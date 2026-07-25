// =============================================================================
// autostream_repeat.cpp
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Impure implementation of the "repeat" feature: RepeatEncoder
// implementations (Mp2Encoder via libtwolame, PcmS16Encoder), RepeatRecorder
// (SPSC ring + low-priority encode worker), RepeatController (the
// IDLE/RECORDING/HOLD/ARMED/REPLAYING/FADING_OUT state machine), ReplayEngine,
// and the /proc/meminfo file-I/O wrapper around autostream_repeat_buffer.h's
// pure parser.
// =============================================================================

#include "autostream_monitor.h"

#include <twolame.h>
#include <mpg123.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

#include <fcntl.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>


// =============================================================================
// /proc/meminfo file I/O wrapper ("read_meminfo()")
//
// The pure parser (parse_meminfo_text) lives in autostream_repeat_buffer.h and
// is unit-tested on canned text (unit test U8). This wrapper does the actual
// file read and is intentionally not unit-testable in isolation.
// =============================================================================

static MemInfo read_meminfo()
{
#ifdef AUTOSTREAM_REPEAT_TEST_HOOKS
    // Test-only: if /tmp/.autostream_repeat_test_force_meminfo_mib exists, its
    // content (a decimal MiB value) overrides the real /proc/meminfo read.
    // This lets memory floor / sliding window behaviour be exercised
    // deterministically and safely, without physically ballooning a test
    // device's RAM down near actual exhaustion (which risks OOM-killing
    // unrelated processes on a shared, page-cache-heavy system where
    // MemAvailable's reclaimable-cache estimate makes genuine exhaustion
    // impractical to induce from a test harness). A file (rather than an
    // environment variable fixed at process start) lets a test toggle
    // simulated pressure on and off mid-recording without restarting the
    // daemon. Only compiled into AUTOSTREAM_REPEAT_TEST_HOOKS builds --
    // never present in the production binary.
    {
        std::ifstream override_f("/tmp/.autostream_repeat_test_force_meminfo_mib");
        if (override_f)
        {
            std::string line;
            std::getline(override_f, line);
            if (!line.empty())
            {
                MemInfo mi;
                mi.available_mib = std::strtol(line.c_str(), nullptr, 10);
                return mi;
            }
        }
    }
#endif
    std::ifstream f("/proc/meminfo");
    if (!f)
        return MemInfo{};

    std::ostringstream ss;
    ss << f.rdbuf();
    return parse_meminfo_text(ss.str());
}


// =============================================================================
// Codec <-> config-string mapping
// =============================================================================

static CodecChoice codec_choice_from_config(const std::string& codec_cfg, long available_mib)
{
    if (codec_cfg == "auto")     return pick_codec(available_mib);
    if (codec_cfg == "mp2_160")  return CodecChoice::Mp2_160;
    if (codec_cfg == "mp2_192")  return CodecChoice::Mp2_192;
    if (codec_cfg == "mp2_224")  return CodecChoice::Mp2_224;
    if (codec_cfg == "pcm")      return CodecChoice::PcmS16;
    return CodecChoice::Unavailable;
}

static bool is_valid_codec_config_string(const std::string& s)
{
    return s == "auto" || s == "mp2_160" || s == "mp2_192" || s == "mp2_224" || s == "pcm";
}

static const char* codec_choice_to_string(CodecChoice c)
{
    switch (c)
    {
        case CodecChoice::Mp2_160: return "mp2_160";
        case CodecChoice::Mp2_192: return "mp2_192";
        case CodecChoice::Mp2_224: return "mp2_224";
        case CodecChoice::PcmS16:  return "pcm";
        case CodecChoice::Unavailable:
        default:                   return "unavailable";
    }
}

static int bitrate_kbps_for(CodecChoice c)
{
    switch (c)
    {
        case CodecChoice::Mp2_160: return 160;
        case CodecChoice::Mp2_192: return 192;
        case CodecChoice::Mp2_224: return 224;
        default:                   return 0;
    }
}


// =============================================================================
// Mp2Encoder — libtwolame float-input MP2 encoder
// =============================================================================

namespace
{

class Mp2Encoder : public RepeatEncoder
{
public:
    Mp2Encoder(int sample_rate_hz, int bitrate_kbps)
    {
        _gfp = twolame_init();
        if (_gfp)
        {
            twolame_set_num_channels(_gfp, 2);
            twolame_set_in_samplerate(_gfp, sample_rate_hz);
            twolame_set_out_samplerate(_gfp, sample_rate_hz);
            twolame_set_bitrate(_gfp, bitrate_kbps);
            twolame_set_mode(_gfp, TWOLAME_STEREO);
            if (twolame_init_params(_gfp) != 0)
            {
                LOG_WARN("[repeat] twolame_init_params failed; MP2 encoding disabled for this session");
                twolame_close(&_gfp);
                _gfp = nullptr;
            }
        }
    }

    ~Mp2Encoder() override
    {
        if (_gfp)
            twolame_close(&_gfp);
    }

    size_t encode(const float* interleaved, int frames, std::vector<uint8_t>& out) override
    {
        if (!_gfp || frames <= 0)
        {
            out.clear();
            return 0;
        }

        // twolame's documented worst case is 1.25 * num_samples + 7200 bytes.
        size_t cap = static_cast<size_t>(frames) * 5u / 4u + 7200u;
        if (out.size() < cap)
            out.resize(cap);

        int n = twolame_encode_buffer_float32_interleaved(
            _gfp, interleaved, frames, out.data(), static_cast<int>(out.size()));

        if (n <= 0)
        {
            out.clear();
            return 0;
        }
        out.resize(static_cast<size_t>(n));
        return static_cast<size_t>(n);
    }

    size_t flush(std::vector<uint8_t>& out) override
    {
        if (!_gfp)
        {
            out.clear();
            return 0;
        }

        size_t cap = 16384;
        out.resize(cap);
        int n = twolame_encode_flush(_gfp, out.data(), static_cast<int>(out.size()));
        if (n <= 0)
        {
            out.clear();
            return 0;
        }
        out.resize(static_cast<size_t>(n));
        return static_cast<size_t>(n);
    }

    // Each encode()/flush() call already returns a whole number of
    // self-contained MP2 frames (twolame buffers any residual PCM
    // internally), so RepeatController's per-append-call granularity is
    // already frame-aligned; no additional rounding is required here.
    int frame_bytes() const override { return 1; }

private:
    twolame_options* _gfp = nullptr;
};


// =============================================================================
// PcmS16Encoder — s16 quantisation identical to the FIFO edge. The PCM tier
// stores s16 regardless of the pipe's actual bit depth.
// =============================================================================

class PcmS16Encoder : public RepeatEncoder
{
public:
    size_t encode(const float* interleaved, int frames, std::vector<uint8_t>& out) override
    {
        if (frames <= 0)
        {
            out.clear();
            return 0;
        }

        size_t n_samples = static_cast<size_t>(frames) * 2u;
        out.resize(n_samples * sizeof(int16_t));

        // Identical quantisation to the FIFO edge (autostream_monitor_io.cpp's
        // src_float_to_short_array() call, immediately after this tap point).
        src_float_to_short_array(interleaved,
                                  reinterpret_cast<short*>(out.data()),
                                  static_cast<long>(n_samples));
        return out.size();
    }

    size_t flush(std::vector<uint8_t>& out) override
    {
        // Nothing is buffered internally between encode() calls.
        out.clear();
        return 0;
    }

    int frame_bytes() const override { return 4; }   // stereo s16 = 2 ch * 2 bytes
};

}   // namespace

std::unique_ptr<RepeatEncoder> make_repeat_encoder(CodecChoice codec, int sample_rate_hz)
{
    switch (codec)
    {
        case CodecChoice::Mp2_160:
        case CodecChoice::Mp2_192:
        case CodecChoice::Mp2_224:
            return std::make_unique<Mp2Encoder>(sample_rate_hz, bitrate_kbps_for(codec));
        case CodecChoice::PcmS16:
            return std::make_unique<PcmS16Encoder>();
        case CodecChoice::Unavailable:
        default:
            return nullptr;
    }
}


// =============================================================================
// Mp2Decoder — libmpg123 wrapper for the replay path
//
// Not part of the RepeatEncoder hierarchy (decode, not encode); private to
// this translation unit like Mp2Encoder/PcmS16Encoder, keeping <mpg123.h> out
// of the shared header. Forces s16/output_rate/stereo output regardless of
// what mpg123 auto-detects from the MP2 frame headers, since the recording is
// always made at the monitor's own output rate: the decoder forces the
// s16/output_rate/stereo output format.
// =============================================================================

namespace
{

class Mp2Decoder
{
public:
    explicit Mp2Decoder(int sample_rate_hz)
    {
        static std::once_flag once;
        std::call_once(once, []() { mpg123_init(); });   // process-wide; safe to call once ever

        int err = 0;
        _mh = mpg123_new(nullptr, &err);
        if (!_mh)
            return;

        mpg123_param(_mh, MPG123_FLAGS, MPG123_QUIET, 0);
        // Force a single fixed output format; reject anything else so a
        // format surprise never silently changes the pipe's byte layout.
        mpg123_format_none(_mh);
        if (mpg123_format(_mh, sample_rate_hz, MPG123_STEREO, MPG123_ENC_SIGNED_16) != MPG123_OK)
        {
            mpg123_delete(_mh);
            _mh = nullptr;
            return;
        }
        if (mpg123_open_feed(_mh) != MPG123_OK)
        {
            mpg123_delete(_mh);
            _mh = nullptr;
        }
    }

    ~Mp2Decoder()
    {
        if (_mh)
        {
            mpg123_close(_mh);
            mpg123_delete(_mh);
        }
    }

    bool ok() const { return _mh != nullptr; }

    // Feeds compressed bytes; decodes as many complete output frames as are
    // available into out (appended, not cleared -- caller pre-clears if
    // desired). Returns false only on an unrecoverable decoder error (caller
    // should treat the session as unplayable and abort replay).
    bool feed_and_decode(const uint8_t* data, size_t len, std::vector<int16_t>& out)
    {
        if (!_mh)
            return false;

        if (len > 0 && mpg123_feed(_mh, data, len) != MPG123_OK)
            return false;

        unsigned char buf[16384];
        size_t bytes_decoded = 0;
        for (;;)
        {
            int err = mpg123_read(_mh, buf, sizeof(buf), &bytes_decoded);
            if (err == MPG123_NEW_FORMAT)
                continue;   // format re-announced (harmless; we forced it above)
            if (bytes_decoded > 0)
            {
                size_t n_samples = bytes_decoded / sizeof(int16_t);
                size_t old_size = out.size();
                out.resize(old_size + n_samples);
                std::memcpy(out.data() + old_size, buf, bytes_decoded);
            }
            if (err == MPG123_NEED_MORE)
                return true;    // fed data exhausted; wait for the next feed
            if (err == MPG123_OK)
                continue;       // more output may be pending this feed
            if (err == MPG123_DONE)
                return true;
            return false;       // MPG123_ERR or other unrecoverable condition
        }
    }

private:
    mpg123_handle* _mh = nullptr;
};

}   // namespace


// =============================================================================
// Pipe-format conversion (s16 passthrough today; kept as a single function
// parameterised for a future wider pipe format)
//
// Today the monitor's pipe format is s16le at output_rate_hz(), identical to
// what both the MP2 decoder (forced) and the PCM tier already produce, so
// this is a passthrough. If the pipe format ever widens beyond s16, this is
// the single place that grows the container-expansion logic; every other
// part of ReplayEngine stays s16 internally so the change stays localised
// here.
// =============================================================================

namespace
{

void convert_to_pipe_format(const int16_t* in_s16, size_t n_samples, std::vector<uint8_t>& out)
{
    out.resize(n_samples * sizeof(int16_t));
    std::memcpy(out.data(), in_s16, n_samples * sizeof(int16_t));
}

}   // namespace


// =============================================================================
// RepeatRecorder
// =============================================================================

RepeatRecorder::RepeatRecorder(RepeatController& owner)
    : _owner(owner)
    , _ring(RING_FLOATS, 0.0f)
    , _meta_ring(META_RING_SIZE)
{
}

RepeatRecorder::~RepeatRecorder()
{
    stop();
}

void RepeatRecorder::start()
{
    if (_running.exchange(true))
        return;
    _stop_requested.store(false, std::memory_order_relaxed);
    _worker_thread = std::thread(&RepeatRecorder::worker_thread_func, this);
}

void RepeatRecorder::stop()
{
    if (!_running.exchange(false))
        return;

    _stop_requested.store(true, std::memory_order_release);
    _cv.notify_all();
    if (_worker_thread.joinable())
        _worker_thread.join();
}

void RepeatRecorder::submit_block(const float* interleaved, int frames, bool above_threshold)
{
    if (frames <= 0)
        return;

    uint32_t n_floats = static_cast<uint32_t>(frames) * 2u;

    uint32_t sample_write = _ring_write_pos.load(std::memory_order_relaxed);
    uint32_t sample_read  = _ring_read_pos.load(std::memory_order_acquire);
    uint32_t sample_used  = sample_write - sample_read;
    uint32_t sample_free  = RING_FLOATS - sample_used;

    uint32_t meta_write = _meta_write_pos.load(std::memory_order_relaxed);
    uint32_t meta_read  = _meta_read_pos.load(std::memory_order_acquire);
    uint32_t meta_used  = meta_write - meta_read;

    if (n_floats > sample_free || meta_used >= META_RING_SIZE)
    {
        _dropped_frames.fetch_add(static_cast<uint64_t>(frames), std::memory_order_relaxed);
        return;
    }

    uint32_t write_idx   = sample_write & RING_MASK;
    uint32_t to_end      = RING_FLOATS - write_idx;
    uint32_t first_chunk = std::min(n_floats, to_end);
    uint32_t second_chunk = n_floats - first_chunk;

    std::memcpy(_ring.data() + write_idx, interleaved, first_chunk * sizeof(float));
    if (second_chunk > 0)
        std::memcpy(_ring.data(), interleaved + first_chunk, second_chunk * sizeof(float));

    _ring_write_pos.fetch_add(n_floats, std::memory_order_release);

    BlockMeta meta;
    meta.frames          = static_cast<uint32_t>(frames);
    meta.above_threshold = above_threshold;
    _meta_ring[meta_write & META_RING_MASK] = meta;
    _meta_write_pos.fetch_add(1, std::memory_order_release);

    _cv.notify_one();
}

void RepeatRecorder::worker_thread_func()
{
    // Per-thread niceness: yields to the audio path, OwnTone, and Vibra.
    // setpriority() with PRIO_PROCESS + the Linux TID (not the process PID)
    // applies to this thread only.
    setpriority(PRIO_PROCESS, static_cast<id_t>(syscall(SYS_gettid)), 10);

    std::vector<float> scratch;

    while (true)
    {
        {
            std::unique_lock<std::mutex> lk(_cv_mutex);
            _cv.wait_for(lk, std::chrono::milliseconds(50),
                [this]()
                {
                    uint32_t mw = _meta_write_pos.load(std::memory_order_acquire);
                    uint32_t mr = _meta_read_pos.load(std::memory_order_relaxed);
                    return (mw - mr) > 0u || _stop_requested.load(std::memory_order_relaxed)
                        || _pending_start_requested.load(std::memory_order_acquire);
                });
        }

        // Keep the idle-status meminfo cache fresh every loop
        // iteration (~50 ms cadence via the wait_for timeout above,
        // regardless of ring activity); internally throttled to a real
        // /proc read at most every kMemCheckIntervalSeconds and a no-op
        // while disabled or Recording.
        _owner.maybe_refresh_idle_meminfo_cache();

        // Handle a deferred session start BEFORE draining the ring
        // below -- any blocks the audio thread buffered while _state was
        // Pending (recording_wanted() admits Pending like Recording) need
        // the encoder to already exist by the time this same iteration's
        // drain loop hands them to RepeatController::process_recorder_
        // samples(), or they are silently dropped (that function requires
        // _state == Recording). perform_pending_start() itself flips the
        // state to Recording (or back to Idle on refusal) before returning.
        if (_pending_start_requested.exchange(false, std::memory_order_acq_rel))
            _owner.perform_pending_start();

        for (;;)
        {
            uint32_t meta_write = _meta_write_pos.load(std::memory_order_acquire);
            uint32_t meta_read  = _meta_read_pos.load(std::memory_order_relaxed);
            if (meta_write - meta_read == 0u)
                break;

            BlockMeta meta = _meta_ring[meta_read & META_RING_MASK];
            uint32_t n_floats = meta.frames * 2u;

            if (scratch.size() < n_floats)
                scratch.resize(n_floats);

            uint32_t read_idx = _ring_read_pos.load(std::memory_order_relaxed) & RING_MASK;
            uint32_t to_end   = RING_FLOATS - read_idx;
            uint32_t first    = std::min(n_floats, to_end);
            uint32_t second   = n_floats - first;

            std::memcpy(scratch.data(), _ring.data() + read_idx, first * sizeof(float));
            if (second > 0)
                std::memcpy(scratch.data() + first, _ring.data(), second * sizeof(float));

            _ring_read_pos.fetch_add(n_floats, std::memory_order_release);
            _meta_read_pos.fetch_add(1, std::memory_order_release);

            _owner.process_recorder_samples(scratch.data(),
                                             static_cast<int>(meta.frames),
                                             meta.above_threshold);
        }

        // The ring is now empty (or was already) -- wake anyone in
        // wait_for_drain() so notify_capture_stopped()'s bounded drain wait
        // does not have to sit out its full timeout when the drain actually
        // finishes promptly.
        _drain_cv.notify_all();

        if (_stop_requested.load(std::memory_order_relaxed))
        {
            uint32_t mw = _meta_write_pos.load(std::memory_order_acquire);
            uint32_t mr = _meta_read_pos.load(std::memory_order_relaxed);
            if (mw - mr == 0u)
                break;
        }
    }
}


// =============================================================================
// RepeatController
// =============================================================================

RepeatController::RepeatController(int sample_rate_hz, std::mutex& fifo_mutex,
                                    OutputProcessor& output_processor)
    : _sample_rate_hz(sample_rate_hz)
    , _fifo_mutex(fifo_mutex)
    , _output_processor(output_processor)
    , _recorder(*this)
    , _replay(*this)
{
}

RepeatController::~RepeatController()
{
    stop();
}

void RepeatController::start()
{
    _recorder.start();
    _replay.start_thread();
}

void RepeatController::stop()
{
    // Hard-abort any active replay first (no fade -- daemon is shutting
    // down) so the replay thread is idle before we join it, then join, then
    // free the buffer: a daemon restart leaves the buffer gone by
    // construction -- nothing here needs to survive shutdown.
    _replay.request_abort();
    _replay.stop_thread();
    _recorder.stop();

    // Declared BEFORE the lock_guard so it destructs (freeing the
    // actual chunk storage) AFTER the lock_guard unlocks -- see
    // RepeatBuffer::steal_chunks()'s comment for the declaration-order
    // pattern this and every other free_recording_locked() call site uses.
    std::deque<RepeatBuffer::Chunk> freed_chunks;
    {
        std::lock_guard<std::mutex> lock(_repeat_mutex);
        freed_chunks = free_recording_locked();
        set_fifo_owner(FifoOwner::Live);
    }
}

std::deque<RepeatBuffer::Chunk> RepeatController::free_recording_locked()
{
    _encoder.reset();
    std::deque<RepeatBuffer::Chunk> stolen = _buffer.steal_chunks();
    _trim.reset();
    _state        = RepeatState::Idle;
    _origin_input = 0;
    _active_codec = CodecChoice::Unavailable;
    _unavailable_reason.clear();

    _state_fast.store(0, std::memory_order_relaxed);
    _origin_input_fast.store(0, std::memory_order_relaxed);

    return stolen;
}

void RepeatController::set_fifo_owner(FifoOwner owner)
{
    // Guarded by _fifo_mutex: the live process threads already
    // hold _fifo_mutex around their write section, so flipping the fast
    // mirror under the same mutex ensures no live writer is mid-critical-
    // section when ownership changes, and the very next live writer to
    // acquire the mutex observes the new owner before it decides whether to
    // write. Never held across a blocking write on either side.
    std::lock_guard<std::mutex> fifo_lock(_fifo_mutex);
    _fifo_owner_fast.store(static_cast<int>(owner), std::memory_order_relaxed);
}

void RepeatController::set_fifo_path(const std::string& path)
{
    std::lock_guard<std::mutex> lock(_repeat_mutex);
    _fifo_path = path;
}

std::string RepeatController::set_enabled(bool enabled, const std::string& codec_text)
{
    std::string codec = codec_text.empty() ? "auto" : codec_text;
    if (!is_valid_codec_config_string(codec))
        return "codec must be one of auto|mp2_160|mp2_192|mp2_224|pcm";

    // Declared BEFORE the lock_guard below so it destructs (freeing
    // any actual chunk storage) AFTER the lock unlocks.
    std::deque<RepeatBuffer::Chunk> freed_chunks;
    std::lock_guard<std::mutex> lock(_repeat_mutex);

    bool was_enabled = _enabled_cfg;
    _codec_cfg   = codec;
    _enabled_cfg = enabled;
    _enabled_fast.store(enabled, std::memory_order_relaxed);

    // "Global enable turned OFF mid-stream: Recording stops; buffer
    // freed immediately." Applies whether a session is actively RECORDING or
    // a finished recording is sitting in HOLD. Turning enable ON is handled
    // implicitly: notify_capture_started() only begins a session at a
    // should_capture edge, so setting the flag mid-session cannot retroactively
    // start recording the session already in progress -- "takes effect at the
    // next capture session" falls out of that call-site discipline for free.
    if (was_enabled && !enabled && _state != RepeatState::Idle)
    {
        LOG_INFO("[repeat] Disabled mid-%s; recording discarded",
                 _state == RepeatState::Recording ? "recording"
                     : (_state == RepeatState::Hold ? "hold" : "replay"));

        // "If replay active: replay fades out and stops, buffer freed" --
        // a disable during replay is a hard abort (no fade) rather than the
        // 1.5 s disarm fade: the feature itself is going away, there is
        // nothing to fade gracefully into.
        //
        // The buffer itself is NOT freed here when a replay is active: the
        // free is deferred to on_replay_session_ended_locked_entry() (see
        // PendingAction's declaration comment) because ReplayEngine's Reader
        // may still be mid-read against _buffer, without holding
        // _repeat_mutex, at this exact instant -- request_abort() only sets
        // an atomic the replay thread notices within ~kPollTimeoutMs.
        if (_state == RepeatState::Replaying || _state == RepeatState::FadingOut)
        {
            // If a live-interrupt fade is currently in flight,
            // remember that fact BEFORE clobbering to Discard (which always
            // wins here) -- a re-enable arriving before the terminal
            // handler runs can then restore it (see the block below).
            _pending_interrupt_restorable = (_pending_action == PendingAction::LiveInterrupt);
            _pending_action = PendingAction::Discard;
            _replay.request_abort();
        }
        else
        {
            freed_chunks = free_recording_locked();
        }
        _armed = false;
    }
    else if (!was_enabled && enabled)
    {
        // Force the next recorder-worker tick (within its ~50 ms poll
        // cadence, not up to kMemCheckIntervalSeconds later) to take a fresh
        // /proc/meminfo reading for the idle-status
        // cache, so get_status()'s max_recording_seconds has a plausible
        // value promptly after enabling rather than staying at whatever
        // (possibly stale, possibly never-set) reading was cached before.
        // Only resets the timestamp -- the actual read still happens on the
        // worker thread, never here under _repeat_mutex.
        _last_idle_mem_check_time = 0.0;

        // A re-enable arriving before a pending Discard's terminal
        // handler has run, where that Discard overwrote what was originally
        // a live-interrupt fade -- restore LiveInterrupt semantics so the
        // terminal handler starts a new recording for the interrupting
        // input after freeing the old buffer, instead of silently just
        // discarding it despite the feature being enabled again. A no-op in
        // every other case: nothing pending, the fade already reached its terminal
        // handler, or the pending Discard came from notify_input_stopped()
        // (never restorable -- _pending_interrupt_restorable is only ever
        // set by the branch above).
        if ((_state == RepeatState::Replaying || _state == RepeatState::FadingOut) &&
            _pending_action == PendingAction::Discard && _pending_interrupt_restorable)
        {
            _pending_action = PendingAction::LiveInterrupt;
            _pending_interrupt_restorable = false;
            LOG_INFO("[repeat] Re-enabled while a pending discard was overwriting a "
                     "live-interrupt fade (input %d): restoring live-interrupt semantics",
                     _pending_interrupt_input);
        }
    }

    return "";
}

bool RepeatController::recording_wanted(int input_index) const
{
    if (!_enabled_fast.load(std::memory_order_relaxed))
        return false;

    // Pending is admitted alongside Recording -- audio arriving while
    // the recorder worker is still doing the deferred meminfo read/encoder
    // construction (RepeatController::perform_pending_start()) is buffered
    // into RepeatRecorder's SPSC ring rather than dropped; the worker itself
    // will not actually hand blocks to the encoder
    // (process_recorder_samples()) until it has flipped the state to
    // Recording, so nothing is encoded before the encoder exists -- it is
    // only buffered a little earlier than before.
    int state = _state_fast.load(std::memory_order_relaxed);
    if (state != static_cast<int>(RepeatState::Recording) &&
        state != static_cast<int>(RepeatState::Pending))
        return false;

    return _origin_input_fast.load(std::memory_order_relaxed) == input_index;
}

void RepeatController::notify_capture_started(int input_index)
{
    // This runs on the audio process thread (InputChannel::
    // process_thread_func, autostream_monitor_io.cpp), so everything below
    // must stay cheap -- no /proc reads, no encoder construction. The heavy
    // lifting is deferred to perform_pending_start(), run by
    // RepeatRecorder's own (niced +10) worker thread.
    std::lock_guard<std::mutex> lock(_repeat_mutex);

    if (!_enabled_cfg)
        return;
    if (_state == RepeatState::Recording || _state == RepeatState::Pending)
        return;   // should not happen (single origin input); guard defensively

    // Live-interrupt crossfade trigger. A should_capture edge on ANY input
    // while REPLAYING/FADING_OUT -- the origin input resuming, or the other
    // input going live -- is the interrupt signal ("a permitted input
    // detects audio (first above-threshold block)"). This deliberately does
    // NOT distinguish "genuine interrupt" from the kind of brief
    // above-threshold blip that a false edge could produce:
    // is_above_threshold's own silence_seconds hysteresis
    // (autostream_monitor_io.cpp) is what decides an edge is real, so this
    // handler can trust every edge it sees as a genuine live-interrupt
    // trigger.
    if (_state == RepeatState::Replaying || _state == RepeatState::FadingOut)
    {
        if (_pending_action == PendingAction::LiveInterrupt)
        {
            // An interrupt fade is already in flight (from this or the other
            // input); first trigger wins, additional retriggers before it
            // completes are no-ops.
            LOG_DEBUG("[repeat] Ignoring capture-start on input %d; a live-interrupt "
                      "fade is already in progress (input %d)",
                      input_index, _pending_interrupt_input);
            return;
        }
        if (_pending_action == PendingAction::Discard)
        {
            // A disable/stop_input teardown has already committed
            // Discard for this fade (only set_enabled(true) arriving before
            // the terminal handler can undo that -- see set_enabled()); a
            // fresh capture-start edge on top of an already-committed
            // Discard does not itself resurrect live-interrupt semantics.
            LOG_DEBUG("[repeat] Ignoring capture-start on input %d; a discard is already "
                      "pending for this fade", input_index);
            return;
        }

        _pending_interrupt_input      = input_index;
        _pending_action               = PendingAction::LiveInterrupt;
        _pending_interrupt_restorable = false;

        if (_state == RepeatState::Replaying)
        {
            _state = RepeatState::FadingOut;
            _state_fast.store(static_cast<int>(RepeatState::FadingOut), std::memory_order_relaxed);
            _replay.request_fade_out();
            LOG_INFO("[repeat] Live interrupt on input %d: fading out replay (input %d)",
                     input_index, _origin_input);
        }
        else
        {
            // _state == FadingOut already: a Disarm fade (set_armed(false))
            // is already running. A live interrupt arriving during that fade
            // UPGRADES it -- the fade itself (timing/gain shape) is
            // unaffected (it is already running on the replay thread; no
            // need to re-issue request_fade_out()), but the controller's
            // POST-fade action changes from "-> Hold" to "-> free old,
            // begin new recording for input_index", because a live source
            // taking over always wins.
            LOG_INFO("[repeat] Live interrupt on input %d during an in-progress disarm "
                     "fade-out (input %d): upgrading to live-interrupt semantics",
                     input_index, _origin_input);
        }
        return;
    }

    // New capture session with an existing finished recording: the old
    // buffer is freed and a new recording starts. This particular free
    // happens on the audio thread itself; the deferred-heavy-work path
    // below only covers the METER READ + ENCODER INIT, not the
    // (comparatively rare) discard of a finished HOLD recording. The
    // detached chunks still destruct as soon as this statement ends, i.e.
    // slightly before the rest of this function runs, which is fine since
    // nothing here depends on the old buffer.
    if (_state == RepeatState::Hold)
        free_recording_locked();

    // Record a cheap pending-start marker and hand the heavy lifting
    // to the recorder worker thread instead of doing it inline here.
    // recording_wanted() (audio-thread, lock-free) already treats Pending
    // like Recording for this exact input, so blocks arriving before the
    // worker finishes are buffered in RepeatRecorder's ring, not dropped.
    _origin_input = input_index;
    _state = RepeatState::Pending;
    _state_fast.store(static_cast<int>(RepeatState::Pending), std::memory_order_relaxed);
    _origin_input_fast.store(input_index, std::memory_order_relaxed);

    _recorder.request_pending_start();
}

void RepeatController::perform_pending_start()
{
    // Called by RepeatRecorder's worker thread (niced +10), never the audio
    // thread. _origin_input was already set by notify_capture_started()
    // under the lock; read it back under the lock too (cheap) before doing
    // the actual heavy work unlocked, since nothing else can change
    // _origin_input while _state == Pending (only this function and a
    // superseding stop/disable transition out of Pending do).
    int input_index;
    {
        std::lock_guard<std::mutex> lock(_repeat_mutex);
        if (_state != RepeatState::Pending)
            return;   // superseded already (e.g. notify_capture_stopped() raced in first)
        input_index = _origin_input;
    }

    // ── Everything below runs WITHOUT _repeat_mutex ─────────────────────────
    MemInfo mem = read_meminfo();
    CodecChoice codec = CodecChoice::Unavailable;
    if (mem.ok() && mem.available_mib >= kMinAvailableMibForStart)
        codec = codec_choice_from_config(_codec_cfg, mem.available_mib);

    std::unique_ptr<RepeatEncoder> encoder;
    if (codec != CodecChoice::Unavailable)
        encoder = make_repeat_encoder(codec, _sample_rate_hz);

    InputParams params;
    bool have_params = false;
    if (_input_params_query)
    {
        params = _input_params_query(input_index);
        have_params = true;
    }

    // ── Re-acquire the lock and commit (re-validate after reacquire) ───────
    std::lock_guard<std::mutex> lock(_repeat_mutex);
    if (_state != RepeatState::Pending || _origin_input != input_index)
        return;   // superseded while we were computing above; drop this attempt

    if (codec == CodecChoice::Unavailable || !encoder)
    {
        _unavailable_reason = !encoder && codec != CodecChoice::Unavailable
            ? "encoder_init_failed" : "insufficient_memory";
        LOG_WARN("[repeat] begin_session refused (input %d): %s (available=%ld MiB)",
                  input_index, _unavailable_reason.c_str(), mem.ok() ? mem.available_mib : -1);
        _state = RepeatState::Idle;
        _origin_input = 0;
        _state_fast.store(static_cast<int>(RepeatState::Idle), std::memory_order_relaxed);
        _origin_input_fast.store(0, std::memory_order_relaxed);
        return;   // back to Idle
    }

    if (have_params)
    {
        _origin_silence_threshold_sample     = params.silence_threshold_sample;
        _origin_track_change_silence_seconds = params.track_change_silence_seconds;
    }

    _unavailable_reason.clear();
    _active_codec = codec;
    _max_recording_seconds = max_recording_seconds(codec, mem.available_mib, 0, _sample_rate_hz);
    _buffer.clear();
    _trim.reset();
    _encoder = std::move(encoder);
    _dropped_frames_baseline = _recorder.dropped_frames();
    _last_mem_check_time = get_monotonic_time();
    // This session start already did a fresh /proc/meminfo read (mem, above)
    // -- fold it into the idle-status cache too so a status poll landing
    // right after this transition (before the next worker tick) still sees
    // an up-to-date reading rather than a possibly-stale idle value.
    _cached_available_mib   = mem.ok() ? mem.available_mib : -1;
    _last_idle_mem_check_time = _last_mem_check_time;
    _state = RepeatState::Recording;

    _state_fast.store(static_cast<int>(RepeatState::Recording), std::memory_order_relaxed);
    // _origin_input_fast is already correct (set at Pending-entry) and
    // unchanged by this transition.

    LOG_INFO("[repeat] Recording started (input %d, codec=%s, max=%lds)",
             input_index, codec_choice_to_string(_active_codec), _max_recording_seconds);
}

void RepeatController::maybe_refresh_idle_meminfo_cache()
{
    // Called every ~50 ms by RepeatRecorder's worker thread loop (never the
    // audio thread), regardless of whether the feature is enabled or a
    // session is active -- so this function must stay cheap in the common
    // case and must NEVER do file I/O while _repeat_mutex is held (same
    // lock-hygiene rule as process_recorder_samples()).
    //
    // While Recording, the in-session memory-guard tick
    // (process_recorder_samples()/apply_memory_guard_locked()) already keeps
    // a fresh meminfo reading flowing through _last_mem_check_time; this
    // function only needs to cover the idle/hold gap so that
    // get_status()'s max_recording_seconds has something current to report
    // even when no recording is in progress, instead of showing "-" at idle.
    if (!_enabled_fast.load(std::memory_order_relaxed))
        return;
    if (_state_fast.load(std::memory_order_relaxed) == static_cast<int>(RepeatState::Recording))
        return;

    double now = get_monotonic_time();
    {
        std::lock_guard<std::mutex> lock(_repeat_mutex);
        if (_state == RepeatState::Recording)
            return;   // re-check under the lock: a session may have just started
        bool due = (now - _last_idle_mem_check_time) >= kMemCheckIntervalSeconds
                   || _cached_available_mib < 0;
        if (!due)
            return;
    }

    // ── Outside _repeat_mutex: the actual /proc/meminfo read ───────────────
    MemInfo mem = read_meminfo();

    std::lock_guard<std::mutex> lock(_repeat_mutex);
    if (_state == RepeatState::Recording)
        return;   // a session started while the read was in flight; that
                  // path now owns _max_recording_seconds/the fresh reading
    _last_idle_mem_check_time = now;
    _cached_available_mib     = mem.ok() ? mem.available_mib : -1;
}

void RepeatController::notify_capture_stopped(int input_index)
{
    std::unique_lock<std::mutex> lock(_repeat_mutex);

    if (_origin_input != input_index)
        return;

    if (_state == RepeatState::Pending)
    {
        // should_capture flipped back off again before the recorder
        // worker even reached perform_pending_start() (a very short blip).
        // Nothing was ever recorded -- return to Idle directly. If
        // perform_pending_start() is concurrently mid-flight right now (it
        // does its heavy work WITHOUT the lock), its own re-validation after
        // reacquiring the lock (_state != Pending / _origin_input mismatch)
        // will see this change and cleanly back out without starting a
        // session nobody wants anymore.
        _state = RepeatState::Idle;
        _origin_input = 0;
        _state_fast.store(static_cast<int>(RepeatState::Idle), std::memory_order_relaxed);
        _origin_input_fast.store(0, std::memory_order_relaxed);
        LOG_INFO("[repeat] Capture stopped (input %d) before the pending session start "
                 "completed; cancelled", input_index);
        return;
    }

    if (_state != RepeatState::Recording)
        return;

    // Give the recorder worker a bounded chance to drain whatever is
    // still sitting in its SPSC ring before finalizing -- otherwise a
    // handful of trailing blocks that already passed recording_wanted()'s
    // gate (i.e. were legitimately part of this session) could be silently
    // lost the instant _state stops being Recording (process_recorder_
    // samples() drops any block it drains once that is true). Lock order:
    // release _repeat_mutex for the wait itself, since the worker thread
    // needs to acquire it once per drained block
    // (process_recorder_samples()) to make any progress at all -- waiting
    // here while still holding it would deadlock the worker against this
    // very call.
    lock.unlock();
    bool drained = _recorder.wait_for_drain(std::chrono::milliseconds(kDrainTimeoutMs));
    lock.lock();

    // Re-validate: something else could have ended this session while the
    // lock was released (e.g. a racing disable/stop_input on the same
    // instant -- vanishingly unlikely in practice since this all happens on
    // the audio thread's own should_capture edge, but cheap to guard).
    if (_state != RepeatState::Recording || _origin_input != input_index)
        return;

    if (!drained)
    {
        uint64_t still_queued = _recorder.queued_frames();
        if (still_queued > 0)
        {
            // Folded into the SAME counter submit_block() uses for ring-full
            // drops, so status.recording.dropped_frames stays an honest
            // total regardless of which path lost the audio.
            _recorder.add_dropped_frames(still_queued);
            LOG_WARN("[repeat] notify_capture_stopped (input %d): drain timed out after "
                     "%dms; %llu queued frame(s) counted as dropped",
                     input_index, kDrainTimeoutMs,
                     static_cast<unsigned long long>(still_queued));
        }
    }

    // Flush any residual buffered output (MP2's internal frame accumulator).
    if (_encoder)
    {
        std::vector<uint8_t> tail;
        size_t n = _encoder->flush(tail);
        if (n > 0)
        {
            if (!_buffer.append(tail.data(), n))
            {
                _buffer.drop_oldest_chunk();
                _buffer.append(tail.data(), n);
            }
            // The flush tail is trailing data, never "loud" by definition --
            // account it the same way as a silent block for trim purposes.
            _trim.on_block_appended(false, n);
        }
    }

    // Silence trim: remove the silence-timeout tail plus a 1 s pad.
    long byte_rate = byte_rate_for(_active_codec, _sample_rate_hz);
    size_t pad_bytes = (byte_rate > 0)
        ? static_cast<size_t>(static_cast<double>(byte_rate) * kSilenceTrimPadSeconds)
        : 0;
    int frame_bytes = _encoder ? _encoder->frame_bytes() : 1;
    size_t trim_bytes = SilenceTrimAccountant::compute_trim_bytes(
        _trim.bytes_since_last_loud(), pad_bytes, static_cast<size_t>(frame_bytes),
        _buffer.total_bytes());
    _buffer.truncate_tail(trim_bytes);

    _encoder.reset();
    _state = RepeatState::Hold;
    _state_fast.store(static_cast<int>(RepeatState::Hold), std::memory_order_relaxed);
    // _origin_input / _origin_input_fast are left as-is: the HOLD recording's
    // origin_input is still meaningful for status reporting. The
    // fast mirror no longer matters once _state_fast != Recording, since
    // recording_wanted() short-circuits on the state check first.

    LOG_INFO("[repeat] Recording stopped (input %d): %zu bytes held, trimmed %zu bytes",
             input_index, _buffer.total_bytes(), trim_bytes);

    // Capture-stop -> replay-start transition: if session arm is set,
    // replay begins immediately, inside this SAME _repeat_mutex
    // critical section that just updated _state to Hold -- so a concurrent
    // get_status() can never observe is_capturing=false (already true by the
    // time this runs) with armed=true and bytes>0 but replay.active=false.
    if (_armed)
        begin_replay_locked();
}

void RepeatController::begin_replay_locked()
{
    if (_state != RepeatState::Hold || _buffer.total_bytes() == 0)
        return;   // nothing to replay (e.g. armed with an empty/never-started recording)

    long rate = byte_rate_for(_active_codec, _sample_rate_hz);
    double duration = (rate > 0)
        ? static_cast<double>(_buffer.total_bytes()) / static_cast<double>(rate) : 0.0;

    _state = RepeatState::Replaying;
    _state_fast.store(static_cast<int>(RepeatState::Replaying), std::memory_order_relaxed);

    // FifoOwner flips to Replay BEFORE the engine's thread is told to start,
    // so the very next live-path FIFO write (should one somehow race in)
    // already observes Replay and discards -- ownership only ever flips at
    // replay start, never mid-write.
    set_fifo_owner(FifoOwner::Replay);

    _replay.request_start(_active_codec, _sample_rate_hz, &_buffer, _origin_input,
                           _origin_silence_threshold_sample,
                           _origin_track_change_silence_seconds);

    LOG_INFO("[repeat] Replay starting (input %d, %.1f s, codec=%s)",
             _origin_input, duration,
             _active_codec == CodecChoice::PcmS16 ? "pcm" : "mp2");
}

std::string RepeatController::set_armed(bool armed)
{
    std::lock_guard<std::mutex> lock(_repeat_mutex);

    bool was_armed = _armed;
    _armed = armed;

    if (armed && !was_armed)
    {
        // Arming while idle with a HOLD recording -> replay starts
        // immediately (the primary "press repeat after the record ended"
        // use case). If currently Recording, nothing happens until the
        // next capture-stop (handled above in notify_capture_stopped()).
        if (_state == RepeatState::Hold)
            begin_replay_locked();
    }
    else if (!armed && was_armed)
    {
        // Disarm during replay -> 1.5 s fade then stop, buffer retained as
        // HOLD (D5). Disarm during an interrupt's FADING_OUT is a
        // no-op here too: FadingOut is not RepeatState::Replaying, so the
        // condition below simply does not match and the fade already in
        // progress continues untouched -- matching "No-op; fade completes".
        if (_state == RepeatState::Replaying)
        {
            _state = RepeatState::FadingOut;
            _state_fast.store(static_cast<int>(RepeatState::FadingOut), std::memory_order_relaxed);
            _replay.request_fade_out();
            LOG_INFO("[repeat] Disarm during replay (input %d): fading out", _origin_input);
        }
        // If Idle/Recording/Hold, disarm is just a flag clear -- no session
        // to interrupt.
    }

    return "";
}

void RepeatController::notify_input_stopped(int input_index)
{
    // Declared BEFORE the lock below so it destructs (freeing any
    // actual chunk storage) AFTER the lock unlocks.
    std::deque<RepeatBuffer::Chunk> freed_chunks;
    std::unique_lock<std::mutex> lock(_repeat_mutex);

    if (_origin_input != input_index)
        return;

    // D12 "reload teardown": stop_input on the origin input
    // discards the buffer and cancels any active replay unconditionally,
    // regardless of state (Recording/Hold/Replaying/FadingOut) -- belt and
    // braces alongside Python's own pre-stop_input disarm+discard.
    // As in set_enabled(false) above, the free is deferred when a replay
    // session is active (see PendingAction's declaration comment). This is
    // NEVER restorable by a later re-enable (unlike set_enabled(false)'s
    // Discard) -- the origin input itself is being torn down, so there
    // is no "new recording for the interrupting input" to honour even if
    // repeat stays enabled; _pending_interrupt_restorable is deliberately
    // left false here.
    if (_state == RepeatState::Replaying || _state == RepeatState::FadingOut)
    {
        _pending_action = PendingAction::Discard;
        _replay.request_abort();
    }
    else if (_state == RepeatState::Recording)
    {
        // This branch gives the recorder worker a BOUNDED chance
        // (wait_for_drain()) to hand its still-queued ring blocks to
        // process_recorder_samples() before the encoder is torn down --
        // otherwise process_recorder_samples()'s own re-validation
        // (`_state != Recording || !_encoder`) would silently drop that
        // trailing audio the instant _encoder is reset here. A stop_input on
        // the origin input mid-recording (exactly the D12/reload-teardown
        // case this function exists for) gets the same courtesy as
        // notify_capture_stopped()'s Recording path (above): the recording
        // is still discarded either way (this is a teardown, not a normal
        // stop), but the worker gets a last bounded chance to finish
        // encoding blocks that already passed recording_wanted()'s gate
        // before they are thrown away anyway.
        //
        // Lock order note (same as notify_capture_stopped()): release
        // _repeat_mutex for the wait itself -- the worker thread needs to
        // acquire it once per drained block (process_recorder_samples()) to
        // make any progress, so waiting here while still holding it would
        // deadlock the worker against this very call.
        lock.unlock();
        _recorder.wait_for_drain(std::chrono::milliseconds(kDrainTimeoutMs));
        lock.lock();

        // Re-validate: something else (a racing notify_capture_stopped()/
        // set_enabled(false)/another notify_input_stopped()) could have ended
        // this session while the lock was released.
        if (_origin_input == input_index && _state == RepeatState::Recording)
            freed_chunks = free_recording_locked();
    }
    else
    {
        freed_chunks = free_recording_locked();
    }
    _armed = false;
}

bool RepeatController::is_replay_sourcing_input(int input_index) const
{
    std::lock_guard<std::mutex> lock(_repeat_mutex);
    return (_state == RepeatState::Replaying || _state == RepeatState::FadingOut)
        && _origin_input == input_index;
}

void RepeatController::on_replay_session_ended_locked_entry()
{
    // Called by ReplayEngine's OWN thread once it has stopped writing (fade
    // completed or a hard write error abort). Takes _repeat_mutex itself
    // (hence "_locked_entry" -- this function acquires the lock, unlike the
    // *_locked() helpers above which assume the caller already holds it).
    //
    // Declared BEFORE the lock_guard below so it destructs (freeing
    // any actual chunk storage) AFTER the lock unlocks.
    std::deque<RepeatBuffer::Chunk> freed_chunks;
    std::lock_guard<std::mutex> lock(_repeat_mutex);

    if (_state != RepeatState::Replaying && _state != RepeatState::FadingOut)
        return;   // already handled by a racing notify_input_stopped()/set_enabled(false)

    set_fifo_owner(FifoOwner::Live);

    // Single pending action, consulted (and cleared) exactly once here.
    // See PendingAction's declaration comment for the full set/clear matrix.
    PendingAction action = _pending_action;
    int interrupting_input = _pending_interrupt_input;
    _pending_action = PendingAction::None;
    _pending_interrupt_restorable = false;

    if (action == PendingAction::Discard)
    {
        // The replay thread has now fully stopped touching _buffer (it is
        // about to return from run_one_session() right after this call
        // returns), so this is the first safe point to free it -- see
        // PendingAction's declaration comment. This wins over a pending live
        // interrupt (feature going away/input being torn down trumps
        // starting a fresh recording) because Discard always overwrites
        // LiveInterrupt in _pending_action (set_enabled()/notify_input_
        // stopped()).
        freed_chunks = free_recording_locked();
        LOG_INFO("[repeat] Replay session ended (input %d); buffer discarded (disable/stop_input)",
                 _origin_input);
    }
    else if (action == PendingAction::LiveInterrupt)
    {
        // Fade complete (or the write path hit a hard error mid-fade,
        // either way the crossfade's outcome is the same: hand
        // the FIFO to the interrupting input). free_recording_
        // locked() is safe here for the same reason as the discard branch
        // above -- the replay thread has fully stopped touching _buffer.
        freed_chunks = free_recording_locked();
        LOG_INFO("[repeat] Live-interrupt fade complete; old recording (input %d) freed",
                 _origin_input);

        // A new recording starts for the new session (global enable
        // permitting), using the same deferred pending-start mechanism as
        // notify_capture_started()'s normal path: this callback runs on
        // ReplayEngine's OWN thread, which should hand the FIFO back to the
        // live path promptly rather than blocking on meminfo+encoder init
        // itself. perform_pending_start() (recorder worker thread) refuses
        // (falls back to Idle) if disabled/insufficient memory. The
        // interrupting input's own live audio during the fade was discarded
        // (is_fifo_owned_by_replay() gate, autostream_monitor_io.cpp), so
        // this recording starts from the handoff point, not from the
        // interrupt's first detected block -- the discarded fade overlap is
        // never recovered, by design.
        if (_enabled_cfg)
        {
            _origin_input = interrupting_input;
            _state = RepeatState::Pending;
            _state_fast.store(static_cast<int>(RepeatState::Pending), std::memory_order_relaxed);
            _origin_input_fast.store(interrupting_input, std::memory_order_relaxed);
            _recorder.request_pending_start();
        }
    }
    else   // PendingAction::None
    {
        _state = RepeatState::Hold;
        _state_fast.store(static_cast<int>(RepeatState::Hold), std::memory_order_relaxed);
        LOG_INFO("[repeat] Replay session ended (input %d); buffer retained as HOLD", _origin_input);

        // The only way to land in this branch is a plain Disarm fade
        // completing (LiveInterrupt/Discard always set an explicit
        // _pending_action, so None here means neither was in flight). If a
        // re-arm (set_armed(true)) arrived WHILE the fade was still running,
        // it was a no-op there (set_armed() only auto-restarts replay from
        // Hold, and state was Replaying/FadingOut at that moment, not Hold
        // yet) -- leaving the session stuck at "_armed == true but nothing
        // playing" until the user toggled armed off/on again. Restarting
        // replay here, immediately, closes that dead end. Not an infinite
        // fade/replay loop: this branch runs at most once per fade-
        // completion event (itself only ever triggered by a user-initiated
        // disarm), and begin_replay_locked() starts a plain (non-fading)
        // replay -- there is no path from a plain replay back into another
        // automatic fade without a further user action.
        if (_armed && _enabled_cfg && _buffer.total_bytes() > 0)
            begin_replay_locked();
    }
}

void RepeatController::process_recorder_samples(const float* interleaved, int frames, bool above_threshold)
{
    // encode() is fast, purely CPU-bound work against the one encoder
    // object this worker thread owns exclusively while Recording, so it
    // stays under the lock like before -- but read_meminfo() (a /proc file
    // read) and the chunk allocation a predicted new-chunk append needs must
    // NOT happen while _repeat_mutex is held, or every other caller
    // (get_status(), set_enabled(), notify_capture_stopped(), ...) stalls
    // for the duration. unique_lock (not lock_guard) so this function can
    // unlock/relock around that work.
    std::unique_lock<std::mutex> lock(_repeat_mutex);

    if (_state != RepeatState::Recording || !_encoder)
        return;

    size_t n = _encoder->encode(interleaved, frames, _encode_scratch);
    if (n == 0)
        return;

    // "Before every chunk allocation" means before an append that
    // will actually need a new chunk, i.e. this call's n bytes would overflow
    // the space remaining in the current last chunk -- not merely "total
    // bytes happens to already sit exactly on a chunk boundary", which for a
    // streaming encoder essentially never coincides with an arbitrary block
    // size and would make this check almost never fire in practice.
    size_t used_in_last_chunk = (_buffer.chunk_bytes() > 0)
        ? (_buffer.total_bytes() % _buffer.chunk_bytes()) : 0;
    bool will_allocate = (_buffer.chunk_count() == 0)
        || (used_in_last_chunk + n > _buffer.chunk_bytes());

    double now = get_monotonic_time();
    bool tick_due = (now - _last_mem_check_time) >= kMemCheckIntervalSeconds;

    if (will_allocate || tick_due)
    {
        size_t chunk_bytes = _buffer.chunk_bytes();
        lock.unlock();

        // ── Outside _repeat_mutex ────────────────────────────────────────
        std::unique_ptr<uint8_t[]> preallocated;
        if (will_allocate)
            preallocated = RepeatBuffer::allocate_chunk_storage(chunk_bytes);

        MemInfo mem;
        if (tick_due)
            mem = read_meminfo();

        lock.lock();
        // Re-validate: a disable/stop/teardown may have superseded this
        // session entirely while the lock was released.
        if (_state != RepeatState::Recording || !_encoder)
            return;   // session ended meanwhile; drop this block

        if (tick_due)
        {
            _last_mem_check_time = now;
            apply_memory_guard_locked(mem);
        }

        if (!_buffer.append_with_preallocated(std::move(preallocated), _encode_scratch.data(), n))
        {
            // Hard allocation failure even after the guard's proactive
            // drops above: shed one more chunk and retry once
            // (RepeatBuffer::append() never frees the last remaining
            // chunk, so this always terminates).
            _buffer.drop_oldest_chunk();
            _buffer.append(_encode_scratch.data(), n);
        }
        _trim.on_block_appended(above_threshold, n);
        return;
    }

    if (!_buffer.append(_encode_scratch.data(), n))
    {
        _buffer.drop_oldest_chunk();
        _buffer.append(_encode_scratch.data(), n);
    }
    _trim.on_block_appended(above_threshold, n);
}

void RepeatController::apply_memory_guard_locked(const MemInfo& mem)
{
    // This function never calls read_meminfo() itself -- the caller
    // (process_recorder_samples()) always fetches mem OUTSIDE _repeat_mutex
    // and hands it in already-read, so this is safe to call while holding
    // the lock.
    if (!mem.ok())
        return;

    // Drop oldest chunks until back above the floor. Re-reading
    // /proc/meminfo after every single drop would be the precise approach but
    // is unnecessary I/O under sustained pressure; approximate the RAM
    // released by each 16 MiB chunk instead and re-verify for real on the
    // next tick/allocation.
    long chunk_mib = static_cast<long>(_buffer.chunk_bytes() / (1024 * 1024));
    long available = mem.available_mib;
    while (available < kFreeRamFloorMib && _buffer.chunk_count() > 1)
    {
        _buffer.drop_oldest_chunk();
        available += chunk_mib;
    }
}

#ifdef AUTOSTREAM_REPEAT_TEST_HOOKS
std::string RepeatController::debug_dump_buffer(const std::string& path) const
{
    std::lock_guard<std::mutex> lock(_repeat_mutex);

    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f)
        return "failed to open " + path + " for writing";

    RepeatBuffer::Reader reader(_buffer);
    std::vector<uint8_t> chunk(65536);
    size_t total = 0;
    for (;;)
    {
        size_t n = reader.next(chunk.data(), chunk.size());
        if (n == 0)
            break;
        f.write(reinterpret_cast<const char*>(chunk.data()), static_cast<std::streamsize>(n));
        total += n;
    }
    if (!f)
        return "write error while dumping repeat buffer";

    LOG_INFO("[repeat] debug_dump_buffer: wrote %zu bytes to '%s'", total, path.c_str());
    return "";
}
#endif

RepeatStatus RepeatController::get_status() const
{
    std::lock_guard<std::mutex> lock(_repeat_mutex);

    RepeatStatus s;
    s.enabled = _enabled_cfg;
    s.armed   = _armed;
    s.codec   = _codec_cfg;

    if (_state == RepeatState::Recording)
    {
        // Frozen at the value computed when this session started
        // (perform_pending_start()) -- unchanged pre-existing behaviour.
        s.max_recording_seconds = _max_recording_seconds;
    }
    else if (_enabled_cfg && _cached_available_mib >= 0)
    {
        // Idle/Hold/Replaying/FadingOut: report what a session started right
        // now would get, from the cache maintained by
        // maybe_refresh_idle_meminfo_cache() on the recorder worker thread --
        // this call must never itself touch /proc/meminfo (it can be called
        // under long-held locks elsewhere / on a hot poll path).
        CodecChoice idle_codec = CodecChoice::Unavailable;
        if (_cached_available_mib >= kMinAvailableMibForStart)
            idle_codec = codec_choice_from_config(_codec_cfg, _cached_available_mib);
        s.max_recording_seconds = (idle_codec != CodecChoice::Unavailable)
            ? max_recording_seconds(idle_codec, _cached_available_mib, 0, _sample_rate_hz)
            : 0;
    }
    else
    {
        // Disabled, or enabled but no meminfo reading has landed yet (a
        // brief window right after startup/re-enable, before the first
        // worker tick completes): 0 is the "genuinely unavailable" value the
        // setup-page note treats as "no number yet" (core/
        // autostream_webui_page_setup.py's refreshRepeatSetupNote()).
        s.max_recording_seconds = 0;
    }

    s.recording.active         = (_state == RepeatState::Recording);
    s.recording.bytes          = _buffer.total_bytes();
    s.recording.truncated_head = _buffer.truncated_head();
    s.recording.origin_input   = _origin_input;
    s.recording.unavailable_reason = _unavailable_reason;

    uint64_t dropped_total = _recorder.dropped_frames();
    s.recording.dropped_frames = (dropped_total >= _dropped_frames_baseline)
        ? (dropped_total - _dropped_frames_baseline) : 0;

    long rate = (_active_codec != CodecChoice::Unavailable)
        ? byte_rate_for(_active_codec, _sample_rate_hz) : 0;
    s.recording.seconds = (rate > 0)
        ? static_cast<double>(s.recording.bytes) / static_cast<double>(rate) : 0.0;

    // Replay block reflects reality (ReplayEngine's own snapshot) rather than
    // being derived purely from _state, so that D9's atomicity property holds
    // even in the single-poll window right after begin_replay_locked() sets
    // _state = Replaying but before the replay thread has actually opened its
    // fd: get_status() reports replay.active=true from the moment the state
    // transition happens (this function itself holds _repeat_mutex, so it can
    // never observe the pre-transition Hold state once notify_capture_stopped()
    // has returned) -- ReplayEngine::get_snapshot() below is consulted only
    // for position/duration/loop_count, not for the active flag itself.
    ReplayEngine::Snapshot rsnap = _replay.get_snapshot();
    s.replay.active           = (_state == RepeatState::Replaying || _state == RepeatState::FadingOut);
    s.replay.position_seconds = rsnap.position_seconds;
    s.replay.duration_seconds = rsnap.duration_seconds;
    s.replay.loop_count       = rsnap.loop_count;

    return s;
}


// =============================================================================
// ReplayEngine
// =============================================================================

ReplayEngine::ReplayEngine(RepeatController& owner)
    : _owner(owner)
{
}

ReplayEngine::~ReplayEngine()
{
    stop_thread();
}

void ReplayEngine::start_thread()
{
    if (_running.exchange(true))
        return;
    _stop_requested.store(false, std::memory_order_relaxed);
    _thread = std::thread(&ReplayEngine::thread_func, this);
}

void ReplayEngine::stop_thread()
{
    if (!_running.exchange(false))
        return;

    _stop_requested.store(true, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lk(_cmd_mutex);
        _pending_cmd = Cmd::Abort;
    }
    _cmd_cv.notify_all();
    if (_thread.joinable())
        _thread.join();
}

void ReplayEngine::request_start(CodecChoice codec, int sample_rate_hz,
                                  const RepeatBuffer* buffer,
                                  int origin_input,
                                  int origin_silence_threshold_sample,
                                  float origin_track_change_silence_seconds)
{
    _session_codec                        = codec;
    _session_rate_hz                      = sample_rate_hz;
    _session_buffer                       = buffer;
    _session_origin_input                 = origin_input;
    _session_silence_threshold_sample     = origin_silence_threshold_sample;
    _session_track_change_silence_seconds = origin_track_change_silence_seconds;

    std::lock_guard<std::mutex> lk(_cmd_mutex);
    _pending_cmd = Cmd::Start;
    _cmd_cv.notify_all();
}

void ReplayEngine::request_fade_out()
{
    std::lock_guard<std::mutex> lk(_cmd_mutex);
    // Must never downgrade a pending Start OR a pending Abort.
    // Start: should not happen given the controller's own state gating,
    // but defensive (a fade-out with no session to fade would be a no-op
    // anyway -- see run_one_session()'s pre-fd-open loop -- but clobbering
    // a not-yet-picked-up Start here would silently cancel a session that
    // was about to begin). Abort: request_abort() is the hard-stop path
    // (disable/reload/stop_input); a fade_out arriving after an abort
    // has already been queued (e.g. set_enabled(false) racing a live-
    // interrupt trigger) must not soften that into a graceful fade -- the
    // controller has already committed to tearing the session down.
    if (_pending_cmd != Cmd::Start && _pending_cmd != Cmd::Abort)
        _pending_cmd = Cmd::FadeOut;
    _cmd_cv.notify_all();
}

void ReplayEngine::request_abort()
{
    std::lock_guard<std::mutex> lk(_cmd_mutex);
    _pending_cmd = Cmd::Abort;
    _cmd_cv.notify_all();
}

ReplayEngine::Snapshot ReplayEngine::get_snapshot() const
{
    Snapshot s;
    s.active           = _active.load(std::memory_order_relaxed);
    s.position_seconds  = _position_seconds.load(std::memory_order_relaxed);
    s.duration_seconds  = _duration_seconds.load(std::memory_order_relaxed);
    s.loop_count        = _loop_count.load(std::memory_order_relaxed);
    return s;
}

unsigned ReplayEngine::get_id_snapshot(int16_t* out, unsigned max_frames) const
{
    std::lock_guard<std::mutex> lock(_id_mutex);

    if (_id_buf.empty())
        return 0;

    unsigned avail = std::min(_id_frames_avail, max_frames);
    if (avail == 0)
        return 0;

    unsigned start  = (_id_write_pos - avail) & ID_BUF_MASK;
    unsigned to_end = ID_BUF_FRAMES - start;

    if (avail <= to_end)
    {
        std::memcpy(out, _id_buf.data() + start, avail * sizeof(int16_t));
    }
    else
    {
        std::memcpy(out,          _id_buf.data() + start, to_end            * sizeof(int16_t));
        std::memcpy(out + to_end, _id_buf.data(),          (avail - to_end) * sizeof(int16_t));
    }
    return avail;
}

void ReplayEngine::thread_func()
{
    for (;;)
    {
        Cmd cmd;
        {
            std::unique_lock<std::mutex> lk(_cmd_mutex);
            _cmd_cv.wait(lk, [this]()
            {
                return _pending_cmd != Cmd::None || _stop_requested.load(std::memory_order_relaxed);
            });

            if (_pending_cmd == Cmd::None)
            {
                // Woken only by stop_thread() with nothing queued.
                break;
            }
            cmd = _pending_cmd;
            _pending_cmd = Cmd::None;
        }

        if (cmd == Cmd::Start)
            run_one_session();
        // FadeOut/Abort with no session running: nothing to do (the
        // controller only issues them while REPLAYING/FADING_OUT, i.e. while
        // a session is active and this thread is inside run_one_session(),
        // not waiting here -- this branch is defensive only).

        if (_stop_requested.load(std::memory_order_relaxed))
            break;
    }
}

namespace
{

// Peak absolute s16 sample across an interleaved stereo block -- mirrors
// InputChannel::compute_peak_sample()'s integer-only discipline, used by
// ReplayEngine to feed its own TrackGapDetector from decoded blocks.
int replay_peak_sample(const int16_t* samples, size_t n_samples)
{
    int peak = 0;
    for (size_t i = 0; i < n_samples; ++i)
    {
        int v = samples[i];
        int abs_v = (v < 0) ? -v : v;
        if (abs_v > peak)
            peak = abs_v;
    }
    return peak;
}

}   // namespace

void ReplayEngine::run_one_session()
{
    CodecChoice codec               = _session_codec;
    int         rate_hz             = _session_rate_hz;
    const RepeatBuffer* buffer      = _session_buffer;
    int         origin              = _session_origin_input;
    int         silence_threshold   = _session_silence_threshold_sample;
    double      track_gap_seconds   = static_cast<double>(_session_track_change_silence_seconds);

    std::string path;
    {
        std::lock_guard<std::mutex> lock(_owner._repeat_mutex);
        path = _owner._fifo_path;
    }

    // ── Open our own fd on the FIFO ──────────────────────────────────────
    // O_NONBLOCK (not a literal blocking open) so a missing reader (ENXIO)
    // or a full pipe never hangs this thread without an abort check; a
    // poll(POLLOUT)-gated write loop below still lets the reader's drain
    // rate pace replay exactly as a blocking fd would.
    _fd = -1;
    for (;;)
    {
        // Treat FadeOut the same as Abort here: there is no audio in flight
        // yet to fade (no reader has ever been attached to write to), so a
        // disarm arriving before the fd is even open has nothing to wait
        // out -- end the session immediately rather than spinning forever
        // ignoring the request. Both commands must unblock this loop: a
        // disarm sent while no reader is attached to the FIFO must still
        // end replay promptly (D5/D6 verification).
        Cmd cmd = _pending_cmd.load();
        if (cmd == Cmd::Abort || cmd == Cmd::FadeOut || _stop_requested.load(std::memory_order_relaxed))
        {
            _pending_cmd.store(Cmd::None);
            _owner.on_replay_session_ended_locked_entry();
            return;
        }
        int fd = ::open(path.c_str(), O_WRONLY | O_NONBLOCK);
        if (fd >= 0)
        {
            _fd = fd;
            break;
        }
        if (errno != ENXIO)
        {
            LOG_WARN("[repeat] ReplayEngine: open('%s') failed: %s", path.c_str(), strerror(errno));
            _owner.on_replay_session_ended_locked_entry();
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(kPollTimeoutMs));
    }

    std::unique_ptr<Mp2Decoder> decoder;
    if (codec != CodecChoice::PcmS16)
    {
        decoder = std::make_unique<Mp2Decoder>(rate_hz);
        if (!decoder->ok())
        {
            LOG_WARN("[repeat] ReplayEngine: mpg123 init failed; aborting replay");
            ::close(_fd);
            _fd = -1;
            _owner.on_replay_session_ended_locked_entry();
            return;
        }
    }

    long byte_rate = byte_rate_for(codec, rate_hz);
    double duration = (byte_rate > 0)
        ? static_cast<double>(buffer->total_bytes()) / static_cast<double>(byte_rate) : 0.0;

    RepeatBuffer::Reader reader(*buffer);
    TrackGapDetector gap_detector;

    // Fresh session, fresh stall streak -- never carry a stall
    // reading from a PRIOR replay session into this one's get_status()
    // reporting (see _stall_since's doc comment).
    _stall_since.store(0.0, std::memory_order_relaxed);

    // ── Replay-owned DSP chain state ─────────────────────────────────────
    // Origin input's gain/EQ are pulled live (not baked into the
    // recording) and applied here, in the same order the live InputChannel
    // path applies them (gain, then EQ, then the shared OutputProcessor),
    // before quantising back to s16 for the pipe. _replay_filters holds this
    // session's own BiquadFilter delay-line state, entirely separate from any
    // InputChannel's -- rebuilt only when the pulled EQ band list's shared_ptr
    // address changes (identical change-detection discipline to
    // InputChannel::process_thread_func's _current_eq_bands, autostream_
    // monitor_io.cpp). Reset (cleared) both here (session start) and at each
    // loop wrap: filter state must not carry across the loop seam -- the
    // sample immediately after the wrap is not continuous with the sample
    // immediately before it, so carrying delay-line state across that seam
    // would smear a discontinuity into a filter-tail artefact at every loop
    // boundary.
    std::vector<BiquadFilter> replay_filters;
    std::shared_ptr<const std::vector<EqBand>> replay_eq_bands_cache;

    {
        std::lock_guard<std::mutex> id_lock(_id_mutex);
        _id_buf.assign(ID_BUF_FRAMES, 0);
        _id_write_pos    = 0;
        _id_frames_avail = 0;
    }
    _track_change_seq.store(0, std::memory_order_relaxed);

    int id_err = 0;
    SRC_STATE* id_src = src_new(SRC_LINEAR, 1, &id_err);

    _duration_seconds.store(duration, std::memory_order_relaxed);
    _position_seconds.store(0.0, std::memory_order_relaxed);
    _loop_count.store(0, std::memory_order_relaxed);
    _active.store(true, std::memory_order_relaxed);

    bool   fading            = false;
    double fade_elapsed_secs = 0.0;
    double frames_played     = 0.0;

    std::vector<uint8_t>  raw_buf(65536);
    std::vector<int16_t>  pcm_staging;
    std::vector<uint8_t>  pipe_bytes;
    std::vector<float>    id_float_mono;
    std::vector<float>    id_float_out;
    std::vector<int16_t>  id_tmp;

    // DSP-chain scratch: float stage (gain/EQ/OutputProcessor) and the
    // requantised s16 result, reused across slices/iterations to avoid
    // per-slice heap churn.
    std::vector<float>    dsp_float_buf;
    std::vector<int16_t>  dsp_pcm_buf;

    // Current pulled gain/EQ, refreshed once per staging refill (each
    // outer loop iteration below) -- see RepeatController::LiveDspParams.
    RepeatController::LiveDspParams live_dsp;

    bool session_aborted = false;

    for (;;)
    {
        Cmd cmd = _pending_cmd.exchange(Cmd::None, std::memory_order_acq_rel);
        if (cmd == Cmd::Abort || _stop_requested.load(std::memory_order_relaxed))
        {
            session_aborted = true;
            break;
        }
        if (cmd == Cmd::FadeOut && !fading)
        {
            fading = true;
            fade_elapsed_secs = 0.0;
        }

        size_t n = reader.next(raw_buf.data(), raw_buf.size());
        if (n == 0)
        {
            // End of buffer: loop -- increment loop_count and rewind the
            // reader. Never happens mid-fade in practice (a fade
            // completes in 1.5 s, far short of any recording), but if it did,
            // looping mid-fade is harmless -- the fade gain continues to
            // ramp down against the freshly-rewound stream.
            _loop_count.fetch_add(1, std::memory_order_relaxed);
            reader.rewind();
            frames_played = 0.0;
            _position_seconds.store(0.0, std::memory_order_relaxed);

            // Reset the replay-owned EQ filter state at the loop seam
            // so no delay-line history carries from the end of the
            // recording into its own beginning.
            replay_filters.clear();
            replay_eq_bands_cache.reset();
            continue;
        }

        // Pull the origin input's current gain/EQ once per staging
        // refill (this outer-loop iteration processes one reader.next()
        // batch, typically a few hundred ms to ~1 s of audio depending on
        // codec/bitrate -- ~1 s granularity is fine here, and
        // polling somewhat more often than that costs only a cheap function
        // call + shared_ptr copy). Rebuild replay_filters only when the
        // pulled band list's shared_ptr address has actually changed, mirroring
        // InputChannel::process_thread_func's own _current_eq_bands
        // change-detection (autostream_monitor_io.cpp) -- so an unchanged EQ
        // setting costs nothing beyond the pointer compare.
        live_dsp = _owner.query_live_dsp_params(origin);
        if (live_dsp.eq_bands != replay_eq_bands_cache)
        {
            replay_eq_bands_cache = live_dsp.eq_bands;
            replay_filters.clear();
            if (replay_eq_bands_cache)
            {
                for (const auto& band : *replay_eq_bands_cache)
                {
                    BiquadFilter f;
                    f.configure(band, live_dsp.eq_sample_rate);
                    replay_filters.push_back(f);
                }
            }
        }

        pcm_staging.clear();
        if (codec == CodecChoice::PcmS16)
        {
            size_t n_samples = n / sizeof(int16_t);
            pcm_staging.resize(n_samples);
            std::memcpy(pcm_staging.data(), raw_buf.data(), n_samples * sizeof(int16_t));
        }
        else
        {
            if (!decoder->feed_and_decode(raw_buf.data(), n, pcm_staging))
            {
                LOG_WARN("[repeat] ReplayEngine: mpg123 decode error; aborting replay");
                session_aborted = true;
                break;
            }
        }

        if (pcm_staging.empty())
            continue;   // decoder still accumulating a partial frame

        size_t total_samples = pcm_staging.size() - (pcm_staging.size() % 2);   // stereo-align
        size_t offset = 0;
        bool write_failed = false;

        while (offset < total_samples)
        {
            size_t slice_samples = std::min(kSliceFrames * 2, total_samples - offset);
            slice_samples -= (slice_samples % 2);
            if (slice_samples == 0)
                break;

            int16_t* slice = pcm_staging.data() + offset;
            size_t   slice_frames = slice_samples / 2;

            // ── Replay-side TrackGapDetector + 16 kHz mono ID tap ──────────
            // Fed from the DECODED, PRE-DSP `slice` -- i.e. exactly the
            // stage the recording itself is made at (POST-SRC/PRE-GAIN,
            // see the recorder tap's comment in autostream_monitor_io.cpp),
            // which matches InputChannel's own live ID tap stage
            // ("post-main-SRC, pre-gain/pre-EQ", InputChannel::_id_buf's
            // class comment) -- so track-ID behaves identically whether the
            // audio is coming from live capture or replay. This runs BEFORE
            // the gain/EQ/OutputProcessor chain below: fade is applied at the
            // very end, after quantisation, so this tap always sees the
            // untouched decoded sample regardless of fade state, matching
            // live behaviour where the ID tap is likewise upstream of gain.
            int peak = replay_peak_sample(slice, slice_samples);
            bool raw_above = (peak >= silence_threshold);
            if (gap_detector.update(/*capturing=*/true, raw_above,
                                     get_monotonic_time(), track_gap_seconds))
            {
                _track_change_seq.fetch_add(1, std::memory_order_relaxed);
            }

            if (id_src)
            {
                id_float_mono.resize(slice_frames);
                for (size_t f = 0; f < slice_frames; ++f)
                {
                    float L = slice[f * 2]     / 32768.0f;
                    float R = slice[f * 2 + 1] / 32768.0f;
                    id_float_mono[f] = (L + R) * 0.5f;
                }
                size_t max_out = slice_frames + 16;
                id_float_out.resize(max_out);

                SRC_DATA sd;
                std::memset(&sd, 0, sizeof(sd));
                sd.data_in       = id_float_mono.data();
                sd.input_frames  = static_cast<long>(slice_frames);
                sd.data_out      = id_float_out.data();
                sd.output_frames = static_cast<long>(max_out);
                sd.src_ratio     = static_cast<double>(ID_BUF_RATE) / static_cast<double>(rate_hz);
                sd.end_of_input  = 0;

                if (src_process(id_src, &sd) == 0 && sd.output_frames_gen > 0)
                {
                    size_t id_count = static_cast<size_t>(sd.output_frames_gen);
                    id_tmp.resize(id_count);
                    for (size_t i = 0; i < id_count; ++i)
                    {
                        float s = id_float_out[i];
                        if (s >  1.0f) s =  1.0f;
                        if (s < -1.0f) s = -1.0f;
                        id_tmp[i] = static_cast<int16_t>(s * 32767.0f);
                    }
                    std::lock_guard<std::mutex> id_lock(_id_mutex);
                    unsigned wp = _id_write_pos;
                    for (size_t i = 0; i < id_count; ++i)
                        _id_buf[(wp + static_cast<unsigned>(i)) & ID_BUF_MASK] = id_tmp[i];
                    _id_write_pos    = wp + static_cast<unsigned>(id_count);
                    _id_frames_avail = std::min(_id_frames_avail + static_cast<unsigned>(id_count),
                                                 ID_BUF_FRAMES);
                }
            }

            // ── Live DSP chain -- gain, then EQ, then the shared ──────────
            // OutputProcessor (identical order to InputChannel::process_
            // thread_func's live path: gain+ramp, per-input EQ, then
            // OutputProcessor::apply()) -- EXCEPT the fade-in ramp, which is
            // never re-played (only the settled current gain applies; see
            // InputChannel::gain_linear()'s doc comment).
            dsp_float_buf.resize(slice_samples);
            src_short_to_float_array(slice, dsp_float_buf.data(),
                                      static_cast<int>(slice_samples));

            if (live_dsp.gain_linear != 1.0f)
            {
                for (size_t s = 0; s < slice_samples; ++s)
                    dsp_float_buf[s] *= live_dsp.gain_linear;
            }

            for (auto& filter : replay_filters)
                filter.process(dsp_float_buf.data(), static_cast<int>(slice_frames));

            // OutputProcessor::apply() is shared, mutable state (the same
            // instance the live InputChannel path calls) -- held under
            // _fifo_mutex for exactly the duration of this call, mirroring
            // the live path's own critical section (autostream_monitor_io.cpp),
            // and NEVER across the blocking/poll-gated write below: this
            // mutex is never held across write().
            {
                std::lock_guard<std::mutex> fifo_lock(_owner._fifo_mutex);
                _owner._output_processor.apply(dsp_float_buf.data(), static_cast<int>(slice_frames));
            }

            dsp_pcm_buf.resize(slice_samples);
            src_float_to_short_array(dsp_float_buf.data(), dsp_pcm_buf.data(),
                                      static_cast<int>(slice_samples));

            // ── Fade gain (disarm fade: linear, 1.5 s span) ────────────────
            // Applied AFTER the DSP chain so a live gain
            // change during the fade itself still scales correctly -- the
            // fade is a final multiplicative envelope on top of whatever the
            // DSP chain just produced, not a substitute baked-in level.
            if (fading)
            {
                for (size_t f = 0; f < slice_frames; ++f)
                {
                    double t = fade_elapsed_secs + static_cast<double>(f) / rate_hz;
                    double g = 1.0 - (t / kFadeSeconds);
                    if (g < 0.0) g = 0.0;
                    dsp_pcm_buf[f * 2]     = static_cast<int16_t>(dsp_pcm_buf[f * 2]     * g);
                    dsp_pcm_buf[f * 2 + 1] = static_cast<int16_t>(dsp_pcm_buf[f * 2 + 1] * g);
                }
                fade_elapsed_secs += static_cast<double>(slice_frames) / rate_hz;
            }

            // ── Pipe-format conversion + blocking (poll-gated) write ──────
            convert_to_pipe_format(dsp_pcm_buf.data(), slice_samples, pipe_bytes);
            if (!write_slice_blocking(pipe_bytes))
            {
                write_failed = true;
                break;
            }

            offset         += slice_samples;
            frames_played  += static_cast<double>(slice_frames);
            _position_seconds.store(frames_played / rate_hz, std::memory_order_relaxed);
        }

        if (write_failed)
        {
            session_aborted = true;   // reader absent / pipe error
            break;
        }
        if (fading && fade_elapsed_secs >= kFadeSeconds)
            break;   // disarm fade complete: fall through to normal cleanup
    }

    _active.store(false, std::memory_order_relaxed);
    if (_fd >= 0)
    {
        ::close(_fd);
        _fd = -1;
    }
    if (id_src)
        src_delete(id_src);

    LOG_INFO("[repeat] Replay session ended (input %d)%s", origin,
             session_aborted ? " [aborted]" : " [fade complete]");

    _owner.on_replay_session_ended_locked_entry();
}

bool ReplayEngine::write_slice_blocking(const std::vector<uint8_t>& data)
{
    // track_stall_outcome() below folds every exit of this loop
    // into "fifo.stalled_seconds" the same way FifoWriter::write() does for
    // the live path -- a poll() timeout (reader not draining) counts as a
    // stall tick just like a hard write error, since either way no bytes are
    // moving; a poll timeout alone does not exit the loop (it re-checks the
    // abort flag and continues), so it is recorded inline below rather than
    // via a single wrapped return.
    size_t written = 0;
    while (written < data.size())
    {
        if (_pending_cmd.load(std::memory_order_relaxed) == Cmd::Abort ||
            _stop_requested.load(std::memory_order_relaxed))
            return track_stall_outcome(false);

        pollfd pfd;
        pfd.fd      = _fd;
        pfd.events  = POLLOUT;
        pfd.revents = 0;
        int pr = ::poll(&pfd, 1, kPollTimeoutMs);
        if (pr < 0)
        {
            if (errno == EINTR)
                continue;
            return track_stall_outcome(false);
        }
        if (pr == 0)
        {
            track_stall_outcome(false);   // reader not draining; keep polling
            continue;   // timed out; loop back to re-check the abort flag
        }

        if (pfd.revents & (POLLERR | POLLHUP))
            return track_stall_outcome(false);   // reader gone

        ssize_t n = ::write(_fd, data.data() + written, data.size() - written);
        if (n < 0)
        {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            return track_stall_outcome(false);   // EPIPE/EBADF/etc -- SIGPIPE is
                                                  // globally ignored (autostream_monitor.cpp),
                                                  // so we always see the error return rather
                                                  // than being killed.
        }
        written += static_cast<size_t>(n);
    }
    return track_stall_outcome(true);
}

bool ReplayEngine::track_stall_outcome(bool ok)
{
    if (ok)
        _stall_since.store(0.0, std::memory_order_relaxed);
    else if (_stall_since.load(std::memory_order_relaxed) == 0.0)
        _stall_since.store(get_monotonic_time(), std::memory_order_relaxed);
    return ok;
}
