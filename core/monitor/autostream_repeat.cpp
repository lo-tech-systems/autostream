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
#include <optional>
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
    // This lets arena-build floor-check behaviour (partial/achieved-capacity
    // builds, arena_not_ready) be exercised deterministically and safely,
    // without physically ballooning a test
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

// "auto" maps to CodecChoice::Unavailable -- the sentinel plan_arena()
// (autostream_repeat_buffer.h) documents for "let the ladder decide" (it
// resolves that sentinel internally via pick_codec_for_target(), so this
// function never needs available_mib/target_minutes/sample_rate_hz itself).
// Any other valid config string skips the ladder outright, across all six
// pinned tiers. The only caller is maybe_build_arena(); is_valid_codec_
// config_string() (below) is what actually rejects a malformed config
// string, at set_enabled() time -- this function assumes it has already
// been validated.
static CodecChoice pinned_codec_from_config(const std::string& codec_cfg)
{
    if (codec_cfg == "auto")     return CodecChoice::Unavailable;
    if (codec_cfg == "mp2_160")  return CodecChoice::Mp2_160;
    if (codec_cfg == "mp2_192")  return CodecChoice::Mp2_192;
    if (codec_cfg == "mp2_224")  return CodecChoice::Mp2_224;
    if (codec_cfg == "mp2_256")  return CodecChoice::Mp2_256;
    if (codec_cfg == "mp2_320")  return CodecChoice::Mp2_320;
    if (codec_cfg == "mp2_384")  return CodecChoice::Mp2_384;
    if (codec_cfg == "pcm")      return CodecChoice::PcmS16;
    return CodecChoice::Unavailable;
}

static bool is_valid_codec_config_string(const std::string& s)
{
    return s == "auto" || s == "mp2_160" || s == "mp2_192" || s == "mp2_224"
        || s == "mp2_256" || s == "mp2_320" || s == "mp2_384" || s == "pcm";
}

static const char* codec_choice_to_string(CodecChoice c)
{
    switch (c)
    {
        case CodecChoice::Mp2_160: return "mp2_160";
        case CodecChoice::Mp2_192: return "mp2_192";
        case CodecChoice::Mp2_224: return "mp2_224";
        case CodecChoice::Mp2_256: return "mp2_256";
        case CodecChoice::Mp2_320: return "mp2_320";
        case CodecChoice::Mp2_384: return "mp2_384";
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
        case CodecChoice::Mp2_256: return 256;
        case CodecChoice::Mp2_320: return 320;
        case CodecChoice::Mp2_384: return 384;
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
// PcmS16Encoder — s16 quantisation identical to the FIFO edge (PCM tier
// stores s16 regardless of pipe bit depth)
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
        case CodecChoice::Mp2_256:
        case CodecChoice::Mp2_320:
        case CodecChoice::Mp2_384:
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
// always made at the monitor's own output rate (the decoder forces the
// output format to s16/output_rate/stereo).
// =============================================================================

namespace
{

class Mp2Decoder
{
public:
    explicit Mp2Decoder(int sample_rate_hz)
        : _sample_rate_hz(sample_rate_hz)
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

    // Discards all buffered bitstream state -- any fed-but-undecoded bytes
    // (including a trailing partial frame) and the decoder's own frame
    // history -- and reopens the feed stream, so the next feed_and_decode()
    // starts bit-exact fresh. The accepted-format table is re-forced the
    // same way the constructor forces it. Returns false (decoder unusable,
    // ok() also false from then on) only if the reopen itself fails.
    bool reset()
    {
        if (!_mh)
            return false;

        mpg123_close(_mh);
        mpg123_format_none(_mh);
        if (mpg123_format(_mh, _sample_rate_hz, MPG123_STEREO, MPG123_ENC_SIGNED_16) != MPG123_OK
            || mpg123_open_feed(_mh) != MPG123_OK)
        {
            mpg123_delete(_mh);
            _mh = nullptr;
            return false;
        }
        return true;
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
    int            _sample_rate_hz = 0;
};

}   // namespace


// Pipe-format conversion: convert_to_pipe_format() (autostream_repeat_buffer.h)
// is the replay-side counterpart of the live path's deliver_output() wire
// narrowing (autostream_monitor_io.cpp) -- both edges branch on
// AudioMonitor::output_format_mode() so the wire layout never disagrees
// between the two writers. Every OTHER part of ReplayEngine stays s16
// internally -- dsp_pcm_buf, the decoder output, the replay-side ID tap, and
// replay_peak_sample() all operate in the int16 domain; only this one
// conversion, at the very edge before the bytes go on the wire, changes
// width. See the helper's own doc comment for both wire layouts.


// =============================================================================
// RepeatRecorder
// =============================================================================

RepeatRecorder::RepeatRecorder(RepeatController& owner)
    : _owner(owner)
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

    size_t n_floats = static_cast<size_t>(frames) * 2u;

    // Both rings must have room -- a dropped block must never be recorded as
    // a "used" meta-ring slot with no matching sample data (or vice versa).
    if (n_floats > _ring.write_available() || _meta_ring.write_available() == 0)
    {
        _dropped_frames.fetch_add(static_cast<uint64_t>(frames), std::memory_order_relaxed);
        return;
    }

    _ring.write(interleaved, n_floats);

    BlockMeta meta;
    meta.frames          = static_cast<uint32_t>(frames);
    meta.above_threshold = above_threshold;
    _meta_ring.write(&meta, 1);

    _cv.notify_one();
}

void RepeatRecorder::worker_thread_func()
{
    // Per-thread niceness: yields to the audio path, OwnTone, and
    // Vibra. setpriority() with PRIO_PROCESS + the Linux TID (not the process
    // PID) applies to this thread only.
    setpriority(PRIO_PROCESS, static_cast<id_t>(syscall(SYS_gettid)), 10);

    std::vector<float> scratch;

    while (true)
    {
        {
            std::unique_lock<std::mutex> lk(_cv_mutex);
            _cv.wait_for(lk, std::chrono::milliseconds(50),
                [this]()
                {
                    return _meta_ring.read_available() > 0
                        || _stop_requested.load(std::memory_order_relaxed)
                        || _pending_start_requested.load(std::memory_order_acquire);
                });
        }

        // Drive the incremental arena-build loop every iteration (~50 ms
        // cadence via the wait_for timeout above, regardless of ring
        // activity); a no-op once an arena is ready, and gated by the
        // boot-settle rule (kArenaSettleSeconds) before a build ever starts
        // -- see maybe_build_arena()'s own comment.
        _owner.maybe_build_arena();

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
            if (_meta_ring.read_available() == 0)
                break;

            BlockMeta meta;
            _meta_ring.read(&meta, 1);
            size_t n_floats = meta.frames * 2u;

            if (scratch.size() < n_floats)
                scratch.resize(n_floats);

            _ring.read(scratch.data(), n_floats);

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
            if (_meta_ring.read_available() == 0)
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
    // Boot-settle reference point (kArenaSettleSeconds) --
    // captured once, here, so maybe_build_arena() can measure process uptime
    // without depending on when the daemon happened to construct this
    // object relative to process start (in practice, very early -- but
    // measuring from here rather than assuming that is exact by
    // construction, not by convention).
    _construct_time = get_monotonic_time();
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
    // free the buffer. On daemon restart the buffer is gone by
    // construction -- nothing here needs to survive shutdown.
    _replay.request_abort();
    _replay.stop_thread();
    _recorder.stop();

    // Declared BEFORE the lock_guard so they destruct (freeing the
    // actual chunk storage, live and spare) AFTER the lock_guard unlocks --
    // see RepeatBuffer::steal_chunks()'s comment for the declaration-order
    // pattern every teardown_arena_locked() call site uses.
    std::deque<std::unique_ptr<uint8_t[]>> freed_spare;
    std::deque<RepeatBuffer::Chunk> freed_chunks;
    {
        std::lock_guard<std::mutex> lock(_repeat_mutex);
        discard_recording_locked();
        freed_chunks = teardown_arena_locked(freed_spare);
        set_fifo_owner(FifoOwner::Live);
    }
}

void RepeatController::discard_recording_locked()
{
    // Session-start-without-teardown: reset_cursors()
    // returns every chunk to the spare pool -- as if it had never been
    // drawn out of it -- rather than freeing anything, so the arena's
    // committed footprint is exactly unchanged by a discard. Outside
    // fixed-capacity mode (should not happen once the feature has ever
    // built an arena, but harmless if reached before the first build)
    // reset_cursors() falls back to its own documented behaviour, which is
    // still "no allocation, no free".
    _encoder.reset();
    _buffer.reset_cursors();
    _trim.reset();
    _onset.reset();
    _tail_marker.reset();
    _preroll_ring.clear();
    transition_locked(RepeatState::Idle);
    set_origin_locked(0);
    // _active_codec is deliberately NOT reset here (unlike the pre-arena
    // free_recording_locked() this replaces): from arena-build completion
    // onward it tracks the ARENA's codec, not any one session's, so
    // get_status()'s Hold/Idle recording.seconds stays honest across a
    // discard that leaves the arena intact. Only
    // teardown_arena_locked() resets it, alongside tearing the arena itself
    // down.
    _unavailable_reason.clear();
}

std::deque<RepeatBuffer::Chunk> RepeatController::teardown_arena_locked(
    std::deque<std::unique_ptr<uint8_t[]>>& out_spare)
{
    // Feature-disable teardown: unlike discard_
    // recording_locked(), this actually frees the arena's committed
    // storage -- both the live chunks (the return value) and the spare pool
    // (out_spare) -- for the caller to destroy after releasing
    // _repeat_mutex, same discipline as every other steal_chunks() call
    // site. Called only from set_enabled(false) (after EnabledOff has
    // already discarded any in-flight recording), stop(), and the
    // config-change re-plan in set_enabled().
    std::deque<RepeatBuffer::Chunk> stolen = _buffer.steal_chunks(&out_spare);
    _arena_plan               = ArenaPlan{CodecChoice::Unavailable, 0, 0};
    _arena_build_in_progress  = false;
    _active_codec              = CodecChoice::Unavailable;
    _unavailable_reason.clear();
    return stolen;
}

// =============================================================================
// Single mutation choke points. Every direct write to the _state/_state_fast
// pair or the _origin_input/_origin_input_fast pair in this file goes
// through exactly one of these two functions --
// `grep -n "_state_fast\.\|_origin_input_fast\." core/monitor/autostream_repeat.cpp`
// shows exactly one store site for each atomic, both here.
// =============================================================================

void RepeatController::transition_locked(RepeatState next)
{
    // Precondition: caller holds _repeat_mutex (documented, not asserted --
    // see the declaration comment in autostream_monitor.h).
    if (next != _state)
        LOG_DEBUG("[repeat] state %d -> %d", static_cast<int>(_state), static_cast<int>(next));
    _state = next;
    _state_fast.store(static_cast<int>(next), std::memory_order_relaxed);
}

void RepeatController::set_origin_locked(int input_index)
{
    _origin_input = input_index;
    _origin_input_fast.store(input_index, std::memory_order_relaxed);
}

void RepeatController::set_enabled_locked(bool enabled)
{
    _enabled_cfg = enabled;
    _enabled_fast.store(enabled, std::memory_order_relaxed);
}


// decide_repeat_transition() -- the pure decision core -- and the
// RepeatState x RepeatEvent matrix comment it implements live in
// autostream_monitor.h (as an `inline` free function), not here. That keeps
// it link-independent of libtwolame/libmpg123 (both real deps of the rest of
// this TU), so core/monitor/tests/test_repeat_transitions.cpp can drive it
// with a bare `g++ -I core/monitor test_repeat_transitions.cpp`, matching
// the zero-dependency pattern autostream_repeat_buffer.h/autostream_spsc_
// ring.h already use. See the header for the matrix comment + implementation.

void RepeatController::handle_event_locked(RepeatEvent event, const RepeatEventCtx& ctx)
{
    // void return: discard_recording_locked() (below) frees nothing -- the
    // arena persists across a discard -- so unlike the pre-arena free_
    // recording_locked() this replaces, there is no deque of freed chunks
    // for a caller to keep alive past the lock release.

    // Captured BEFORE any mutation below, so the log_tag switch at the
    // bottom prints the same values the original code's LOG_* calls read
    // (which always ran before -- or independent of -- the mutation).
    RepeatState state_before                  = _state;
    int         origin_before                 = _origin_input;
    int         pending_interrupt_input_before = _pending_interrupt_input;

    RepeatDecision d = decide_repeat_transition(_state, _armed, _enabled_cfg, _pending_action,
                                                 _pending_interrupt_restorable, event, ctx);

    if (d.kind == RepeatDecision::Kind::Impossible)
    {
        LOG_WARN("[repeat] handle_event_locked: impossible cell (state=%d, event=%d)",
                  static_cast<int>(state_before), static_cast<int>(event));
        return;
    }
    if (d.kind == RepeatDecision::Kind::NoOp)
        return;

    // Kind::Ignored cells never set any of the flags below (decide_repeat_
    // transition() returns early for them), so this block is a true no-op
    // for Ignored and only actually mutates anything for Kind::Apply.

    // Snapshot the origin to revert to if this LiveInterrupt promotion's
    // admission ends up refused (PendingStartFailed's has_hold_bytes
    // branch) -- see _pending_interrupt_revert_origin's declaration
    // comment. Must be captured here, from origin_before, because
    // set_origin below (when this cell also requests a new Pending session)
    // overwrites _origin_input with the interrupting input before this
    // function returns.
    if (d.log_tag == RepeatLogTag::ReplaySessionEndedLiveInterruptPending)
        _pending_interrupt_revert_origin = origin_before;

    if (d.set_pending_interrupt_input)
        _pending_interrupt_input = d.pending_interrupt_input;
    if (d.set_pending_action)
    {
        _pending_action = d.pending_action;
        // Single mutation choke point for the probation fast mirrors too
        // (recording_wanted()/is_fifo_owned_by_replay()'s pattern): every
        // write to _pending_action funnels through this one spot, so this
        // is the only place the mirrors can ever go stale relative to it.
        // Ordered AFTER the set_pending_interrupt_input block above so that
        // when a single decision sets both (CaptureStarted's probation-arm
        // cell always does), _pending_interrupt_input already holds this
        // call's value, not the previous probation/interrupt's.
        bool armed_now = (d.pending_action == PendingAction::InterruptProbation);
        // Publish the input BEFORE the armed flag so a concurrent
        // notify_probation_block() that observes armed_now==true can never
        // read a stale (or the -1 sentinel) input value behind it.
        _probation_input_fast.store(armed_now ? _pending_interrupt_input : -1,
                                     std::memory_order_relaxed);
        _probation_armed_fast.store(armed_now, std::memory_order_relaxed);
        if (armed_now)
        {
            // Fresh arm: any accumulation left over from a previous,
            // already-resolved probation attempt must not leak into this
            // one -- see _interrupt_probation's declaration comment.
            _interrupt_probation.reset();
            _probation_armed_time      = get_monotonic_time();
            _probation_last_block_time = 0.0;
        }
    }
    if (d.set_pending_restorable)
        _pending_interrupt_restorable = d.pending_restorable;

    if (d.do_free_recording)
        discard_recording_locked();

    if (d.change_state)
        transition_locked(d.next_state);
    if (d.set_origin)
        set_origin_locked(d.origin_input);

    if (d.do_request_abort)
        _replay.request_abort();
    if (d.do_request_fade_out)
        _replay.request_fade_out();
    if (d.do_begin_replay)
        begin_replay_locked();
    if (d.do_request_pending_start)
        _recorder.request_pending_start();

    switch (d.log_tag)
    {
        case RepeatLogTag::None:
            break;
        case RepeatLogTag::DisabledMidState:
            LOG_INFO("[repeat] Disabled mid-%s; recording discarded",
                     state_before == RepeatState::Recording ? "recording"
                         : (state_before == RepeatState::Hold ? "hold" : "replay"));
            break;
        case RepeatLogTag::ReenabledRestoringLiveInterrupt:
            LOG_INFO("[repeat] Re-enabled while a pending discard was overwriting a "
                     "live-interrupt fade (input %d): restoring live-interrupt semantics",
                     pending_interrupt_input_before);
            break;
        case RepeatLogTag::CaptureStartIgnoredFadeInProgress:
            LOG_DEBUG("[repeat] Ignoring capture-start on input %d; a live-interrupt "
                      "fade is already in progress (input %d)",
                      ctx.input_index, pending_interrupt_input_before);
            break;
        case RepeatLogTag::CaptureStartIgnoredDiscardPending:
            LOG_DEBUG("[repeat] Ignoring capture-start on input %d; a discard is already "
                      "pending for this fade", ctx.input_index);
            break;
        case RepeatLogTag::CaptureStartIgnoredProbationInProgress:
            // Same duplicate-suppression rationale as the two Ignored cells
            // above: an interrupt probation window is at most a few
            // seconds, so this cannot spam the way the hold-active case
            // could, but the same convention keeps all "Ignoring capture-
            // start" lines behaving consistently either way.
            LOG_DEBUG("[repeat] Ignoring capture-start on input %d; a live-interrupt "
                      "probation is already in progress (input %d)",
                      ctx.input_index, pending_interrupt_input_before);
            break;
        case RepeatLogTag::CaptureStartIgnoredReplayHoldActive:
            // DEBUG + identical message text on every repeat (same
            // ctx.input_index each time): relies on logger_log()'s built-in
            // duplicate-suppression (autostream_monitor_utils.cpp,
            // DUPLICATE_LOG_LIMIT) to collapse the ~once/second re-notify
            // stream (see compute_should_renotify_capture_started(),
            // autostream_monitor_utils.h) into a handful of lines plus a
            // "(suppressed N duplicate entries)" summary, rather than one
            // line per second for up to a ~30 s hold. Identical convention
            // to the two Ignored cells immediately above, which already
            // rely on the same mechanism for the same reason (repeated
            // CaptureStarted events on a still-open fade/discard).
            LOG_DEBUG("[repeat] Ignoring capture-start on input %d; minimum playback "
                      "hold active on the current replay", ctx.input_index);
            break;
        case RepeatLogTag::CaptureStartArmsProbation:
            LOG_INFO("[repeat] Capture start on input %d during replay (input %d): "
                     "arming live-interrupt probation (%.2f s to confirm)",
                     ctx.input_index, origin_before, kInterruptSustainSeconds);
            break;
        case RepeatLogTag::LiveInterruptFadingOutReplay:
            LOG_INFO("[repeat] Live interrupt on input %d: fading out replay (input %d)",
                     ctx.input_index, origin_before);
            break;
        case RepeatLogTag::LiveInterruptUpgradingDisarmFade:
            LOG_INFO("[repeat] Live interrupt on input %d during an in-progress disarm "
                     "fade-out (input %d): upgrading to live-interrupt semantics",
                     ctx.input_index, origin_before);
            break;
        case RepeatLogTag::ProbationTimedOutReplayContinues:
            LOG_WARN("[repeat] live-interrupt probation expired unconfirmed (input %d); "
                     "replay continues (input %d)",
                     pending_interrupt_input_before, origin_before);
            break;
        case RepeatLogTag::CaptureStoppedPendingCancelled:
            LOG_INFO("[repeat] Capture stopped (input %d) before the pending session start "
                     "completed; cancelled", ctx.input_index);
            break;
        case RepeatLogTag::DisarmDuringReplayFadingOut:
            LOG_INFO("[repeat] Disarm during replay (input %d): fading out", origin_before);
            break;
        case RepeatLogTag::ReplaySessionEndedDiscarded:
            LOG_INFO("[repeat] Replay session ended (input %d); buffer discarded (disable/stop_input)",
                     origin_before);
            break;
        case RepeatLogTag::ReplaySessionEndedLiveInterruptPending:
            // No longer "freed" here -- see the admit-before-free comment on
            // this cell (decide_repeat_transition()) and on
            // perform_pending_start(). The old recording (input %d) is
            // retained until the new session's admission is actually
            // decided; perform_pending_start()'s own INFO/WARN lines cover
            // what happens to it next.
            LOG_INFO("[repeat] Live-interrupt fade complete (input %d); starting new session "
                     "(input %d), old recording retained pending admission",
                     origin_before, ctx.interrupting_input);
            break;
        case RepeatLogTag::ReplaySessionEndedLiveInterruptDisabledFreed:
            LOG_INFO("[repeat] Live-interrupt fade complete (input %d) but repeat was "
                     "disabled before it finished; old recording freed, no new session",
                     origin_before);
            break;
        case RepeatLogTag::ReplaySessionEndedRetainedHold:
            LOG_INFO("[repeat] Replay session ended (input %d); buffer retained as HOLD",
                     origin_before);
            break;
        case RepeatLogTag::PendingStartFailedRevertedToHold:
            LOG_INFO("[repeat] New session admission refused; reverted to HOLD (input %d), "
                     "recording survives",
                     ctx.revert_origin_input);
            break;
    }
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

std::string RepeatController::set_enabled(bool enabled, const std::string& codec_text,
                                           int target_minutes)
{
    std::string codec = codec_text.empty() ? "auto" : codec_text;
    if (!is_valid_codec_config_string(codec))
        return "codec must be one of auto|mp2_160|mp2_192|mp2_224|mp2_256|mp2_320|mp2_384|pcm";

    // Declared BEFORE the lock_guard below so they destruct (freeing any
    // actual chunk storage, live and spare) AFTER the lock unlocks -- see
    // teardown_arena_locked()'s own comment.
    std::deque<std::unique_ptr<uint8_t[]>> freed_spare;
    std::deque<RepeatBuffer::Chunk> freed_chunks;
    std::lock_guard<std::mutex> lock(_repeat_mutex);

    bool was_enabled = _enabled_cfg;
    std::string old_codec_cfg      = _codec_cfg;
    int         old_target_minutes = _target_minutes_cfg;
    _codec_cfg = codec;

    // target_minutes < 0 is the "field omitted" sentinel (see the socket
    // handler's json_get_int(..., -1) default) -- leave whatever is already
    // stored (kDefaultRepeatTargetMinutes at first construction) unchanged
    // rather than resetting it back to the default on every call that
    // happens not to mention it. A provided value is clamped to
    // [kMinRepeatTargetMinutes, kMaxRepeatTargetMinutes].
    if (target_minutes >= 0)
    {
        int clamped = target_minutes;
        if (clamped < kMinRepeatTargetMinutes) clamped = kMinRepeatTargetMinutes;
        if (clamped > kMaxRepeatTargetMinutes) clamped = kMaxRepeatTargetMinutes;
        _target_minutes_cfg = clamped;
    }

    set_enabled_locked(enabled);   // single mutation choke point

    // Config-change re-plan: staying enabled but
    // actually changing target_minutes or the pinned codec is treated as an
    // internal disable+enable -- there is no separate re-plan event, and no
    // in-place arena resize. The Python target-minutes path already sends a
    // genuine off/on toggle (harmless double with this); the pinned-codec
    // path is switched to the same off/on shape on the Python side (see
    // core/autostream_webui_api.py's _live_repeat_codec()) specifically so a
    // codec pin arriving here as a single set_enabled(true, new_codec) call
    // still re-plans via this branch.
    bool config_changed = was_enabled && enabled &&
        (_codec_cfg != old_codec_cfg || _target_minutes_cfg != old_target_minutes);

    // Global enable turned OFF mid-stream (or a config change re-plans):
    // recording stops, discarded immediately; the arena itself is torn down
    // AFTER the event dispatch, unconditionally -- an arena can exist even
    // at Idle (built but never recorded into, or discarded back to Idle by
    // an earlier session), so teardown must not be gated on _state the way
    // the discard dispatch below is. Turning enable ON is handled implicitly
    // by handle_event_locked()/notify_capture_started(): a session only
    // begins at a should_capture edge, so setting the flag mid-session
    // cannot retroactively start recording the session already in progress.
    //
    // The state-decision logic for the discard half (what happens for each
    // _state -- Idle no-op, Recording/Hold/Pending discard, Replaying/
    // FadingOut hard-abort-with-Discard-pending, and the restorable
    // re-enable) lives in decide_repeat_transition() as the EnabledOff/
    // EnabledOn cells -- see the matrix comment above handle_event_locked().
    if ((was_enabled && !enabled) || config_changed)
    {
        if (_state != RepeatState::Idle)
        {
            handle_event_locked(RepeatEvent::EnabledOff);
            _armed = false;
        }
        freed_chunks = teardown_arena_locked(freed_spare);
    }
    if ((!was_enabled && enabled) || config_changed)
    {
        // Nothing to do here beyond the event dispatch itself: the arena
        // build (maybe_build_arena(), RepeatRecorder's worker thread) picks
        // up the fact that _enabled_fast is true and no arena exists on its
        // very next ~50 ms tick, with no timestamp to reset -- unlike the
        // pre-arena idle-meminfo cache this replaces, there is no separate
        // cache staleness to force-refresh.
        handle_event_locked(RepeatEvent::EnabledOn);
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
    //
    // Live-interrupt trigger. A should_capture edge on ANY input while
    // REPLAYING/FADING_OUT -- the origin input resuming, or the other input
    // going live -- is the interrupt SIGNAL ("a permitted input detects
    // audio (first above-threshold block)"), but while state == Replaying
    // (an ACTIVE replay) it is no longer trusted immediately on its own:
    // this call only ARMS the interrupt-probation gate (decide_repeat_
    // transition()'s CaptureStarted cell), which requires
    // kInterruptSustainSeconds of continued above-threshold audio (fed
    // separately, by notify_probation_block() below, every block regardless
    // of this edge call's cadence) before the fade/free/new-session sequence
    // this comment used to describe actually happens. FadingOut's own edge
    // still applies immediately, unprobated -- see decide_repeat_
    // transition()'s CaptureStarted cell for why.
    //
    // "New capture session with existing finished recording: old buffer
    // freed, new recording starts"; "should not happen (single origin
    // input)" defensive guard while Recording/Pending; both the
    // ignored-retrigger cases (an interrupt fade, a discard, or a probation
    // already pending) -- all of this state-decision logic lives in
    // decide_repeat_transition()'s CaptureStarted cells; see the matrix
    // comment above handle_event_locked(). This wrapper is purely lock +
    // dispatch, matching the "thin wrapper" shape the whole class uses.
    std::lock_guard<std::mutex> lock(_repeat_mutex);

    // Arena-ready kick bookkeeping: updated unconditionally,
    // regardless of _state/_enabled_cfg -- cheap (two plain field writes
    // under a lock this call already takes) and needed even while the
    // arena isn't ready yet, since maybe_build_arena() consults this the
    // instant a build completes, which may be the very next worker tick
    // after this call. See _capture_active's declaration comment
    // (autostream_monitor.h) for the gap this closes.
    _capture_active       = true;
    _capture_active_input = input_index;

    RepeatEventCtx ctx;
    ctx.input_index = input_index;
    // Minimum playback hold: only meaningful while a replay (or its
    // fade-out) is actually in flight, and only while _origin_minimum_
    // playback_seconds (snapshotted from the origin input's config at
    // recording start) is non-zero. 0 must reproduce today's behaviour
    // exactly, so this stays false whenever the hold is disabled.
    if ((_state == RepeatState::Replaying || _state == RepeatState::FadingOut) &&
        _origin_minimum_playback_seconds > 0 && _replay_start_time > 0.0)
    {
        double elapsed = get_monotonic_time() - _replay_start_time;
        ctx.replay_hold_active = elapsed < static_cast<double>(_origin_minimum_playback_seconds);
    }
    handle_event_locked(RepeatEvent::CaptureStarted, ctx);
}

void RepeatController::notify_probation_block(int input_index, bool above_threshold, double now)
{
    // This runs on the audio process thread, once per processed block, for
    // EVERY input, unconditionally -- see the declaration comment
    // (autostream_monitor.h) for the data-path choice this depends on
    // (is_above_threshold from InputChannel::update_silence_state(), which
    // runs regardless of capturing/recording_wanted() state, unlike the
    // recorder's own OnsetGate feed). It therefore MUST cost nothing in the
    // overwhelming common case (no probation in flight): two relaxed atomic
    // loads, same discipline as recording_wanted()/is_fifo_owned_by_replay().
    if (!_probation_armed_fast.load(std::memory_order_relaxed))
        return;
    if (_probation_input_fast.load(std::memory_order_relaxed) != input_index)
        return;

    std::lock_guard<std::mutex> lock(_repeat_mutex);

    // Re-validate under the lock: the fast-path check above can be stale by
    // the time this thread acquires the lock (another thread may have
    // confirmed/timed-out/superseded the same probation in between, or --
    // in the two-input case -- this call itself simply lost a race against
    // the OTHER input's own notify_probation_block() call for the same
    // block-processing tick).
    if (_pending_action != PendingAction::InterruptProbation ||
        _pending_interrupt_input != input_index)
        return;

    RepeatEventCtx ctx;
    ctx.input_index = input_index;

    // Wall-clock timeout bound, independent of the sustain accumulator
    // below (which only advances on above-threshold blocks): armed longer
    // than kPreRollSeconds without confirming and this probation is done,
    // regardless of what today's audio has been doing -- see
    // kInterruptSustainSeconds' declaration comment (autostream_repeat_
    // buffer.h) for why kPreRollSeconds is the natural bound here.
    if (now - _probation_armed_time >= kPreRollSeconds)
    {
        handle_event_locked(RepeatEvent::ProbationTimedOut, ctx);
        return;
    }

    // Elapsed wall-clock time since the previous block fed to this
    // probation attempt, clamped so the very first call after arming (where
    // there is no previous call to measure from) or a scheduling gap (a
    // delayed audio-thread iteration) cannot inject a spuriously large jump
    // into the sustain accumulator -- 0.25 s is comfortably larger than any
    // real block duration this codebase processes, so it only ever clamps
    // genuine gaps, never a normal block-to-block interval.
    double block_seconds = (_probation_last_block_time > 0.0)
        ? std::min(now - _probation_last_block_time, 0.25)
        : 0.0;
    _probation_last_block_time = now;

    bool confirmed = _interrupt_probation.on_block(above_threshold, block_seconds);
    if (confirmed)
        handle_event_locked(RepeatEvent::ProbationConfirmed, ctx);
}

void RepeatController::perform_pending_start()
{
    // Called by RepeatRecorder's worker thread (niced +10), never the audio
    // thread. Collapsed: the arena is built ONCE at
    // enable time (maybe_build_arena()), not re-sized per session, so this
    // function no longer does a meminfo read, credited-MiB admission
    // arithmetic, or a per-session codec re-pick -- it only checks whether
    // the arena is ready and, if so, resets into it.
    //
    // Still two-phase (snapshot under the lock, heavy work unlocked,
    // re-validate on reacquire) even though the meminfo read is gone:
    // _input_params_query calls into InputChannel accessors that take that
    // channel's own _config_mutex, and encoder construction allocates codec
    // state -- neither may run while _repeat_mutex is held (the former would
    // establish a _repeat_mutex -> _config_mutex ordering nothing else in
    // the codebase promises to respect; the latter is the same
    // no-allocation-under-the-lock hygiene every other path here observes).
    //
    // The arena-readiness snapshot cannot go stale in the not-ready ->
    // ready direction between the two phases: the build loop
    // (maybe_build_arena()) runs on this SAME worker thread, strictly
    // before/after this function in the loop body, never concurrently. It
    // can go stale ready -> torn-down (set_enabled() on another thread),
    // but every teardown path also moves _state out of Pending first, so
    // the _state re-validation on reacquire already covers it.
    int  input_index;
    bool arena_ready;
    CodecChoice codec;
    {
        std::lock_guard<std::mutex> lock(_repeat_mutex);
        if (_state != RepeatState::Pending)
            return;   // superseded already (e.g. notify_capture_stopped() raced in first)
        input_index = _origin_input;
        arena_ready = arena_ready_locked();
        codec       = _arena_plan.codec;
    }

    // ── Everything below runs WITHOUT _repeat_mutex ──────────────────────────
    std::unique_ptr<RepeatEncoder> encoder;
    if (arena_ready)
        encoder = make_repeat_encoder(codec, _sample_rate_hz);

    InputParams params;
    bool have_params = false;
    if (arena_ready && encoder && _input_params_query)
    {
        params = _input_params_query(input_index);
        have_params = true;
    }

    // ── Re-acquire the lock and commit (re-validate after reacquire) ──────
    std::lock_guard<std::mutex> lock(_repeat_mutex);
    if (_state != RepeatState::Pending || _origin_input != input_index)
        return;   // superseded while we were computing above; drop this attempt

    if (!arena_ready || !encoder)
    {
        // arena_not_ready while a build is still pending/possible (no
        // finalized plan yet -- see _arena_build_in_progress's own comment);
        // insufficient_memory once maybe_build_arena() has finalized at
        // Unavailable (zero chunks achievable); encoder_init_failed when the
        // arena was fine but codec-state construction itself failed. All
        // three are refused via the same PendingStartFailed path -- see
        // decide_repeat_transition()'s cell for that event.
        _unavailable_reason = (arena_ready && !encoder)
            ? "encoder_init_failed"
            : (_arena_build_in_progress ? "arena_not_ready" : "insufficient_memory");
        LOG_WARN("[repeat] begin_session refused (input %d): %s",
                  input_index, _unavailable_reason.c_str());
        RepeatEventCtx ctx;
        ctx.has_hold_bytes      = _buffer.total_bytes() > 0;
        ctx.revert_origin_input = _pending_interrupt_revert_origin;
        handle_event_locked(RepeatEvent::PendingStartFailed, ctx);
        return;   // back to Hold (old recording survives) or Idle
    }

    if (have_params)
    {
        _origin_silence_threshold_sample     = params.silence_threshold_sample;
        _origin_track_change_silence_seconds = params.track_change_silence_seconds;
        _origin_minimum_playback_seconds     = params.minimum_playback_seconds;
    }

    _unavailable_reason.clear();
    _active_codec = codec;
    _max_recording_seconds = _arena_plan.capacity_seconds;
    // reset_cursors() (NOT steal_chunks()): the arena persists across
    // sessions -- this discards whatever the buffer was holding (an empty
    // buffer for a plain Idle/Hold start, or an old held recording for a
    // LiveInterrupt promotion that deliberately left it in place -- see
    // decide_repeat_transition()'s ReplaySessionEnded x LiveInterrupt cell)
    // by returning every chunk to the spare pool, never freeing anything.
    _buffer.reset_cursors();
    _trim.reset();
    // Onset gate: fresh per session. The ring is sized from this
    // session's own recording-path sample format -- always stereo float at
    // _sample_rate_hz on this (pre-DSP) tap, regardless of which codec was
    // just chosen above for the eventual encoded output.
    _onset.reset();
    // Tail marker pad: the quiet left in place between the last music and
    // the loop point. The byte-rate figure only sizes the pad's TARGET --
    // the recorded cut itself always lands on a committed block boundary
    // (see TailMarker::on_block_committed()), so encoded-frame alignment
    // never depends on this estimate being exact.
    {
        long tail_byte_rate = byte_rate_for(codec, _sample_rate_hz);
        size_t tail_pad_bytes = (tail_byte_rate > 0)
            ? static_cast<size_t>(static_cast<double>(tail_byte_rate) * kSilenceTrimPadSeconds)
            : 0;
        _tail_marker.reset(tail_pad_bytes);
    }
    _preroll_ring.set_capacity_frames(
        static_cast<size_t>(kPreRollSeconds * static_cast<double>(_sample_rate_hz)));
    _encoder = std::move(encoder);
    _dropped_frames_baseline = _recorder.dropped_frames();

    // Pending -> Recording decision (PendingStartSucceeded cell).
    // _origin_input_fast is already correct (set at Pending-entry) and
    // unchanged by this transition.
    handle_event_locked(RepeatEvent::PendingStartSucceeded);

    LOG_INFO("[repeat] Recording started (input %d, codec=%s, max=%lds)",
             input_index, codec_choice_to_string(_active_codec), _max_recording_seconds);
}

void RepeatController::maybe_build_arena()
{
    // Called every ~50 ms by RepeatRecorder's worker thread loop (never the
    // audio thread), the same call site maybe_refresh_idle_meminfo_cache()
    // used to occupy -- so this function must stay cheap when there is
    // nothing to do, and must NEVER do file I/O or allocation while
    // _repeat_mutex is held.
    if (!_enabled_fast.load(std::memory_order_relaxed))
        return;

    bool need_build;
    {
        std::lock_guard<std::mutex> lock(_repeat_mutex);
        double now = get_monotonic_time();
        // An IN-PROGRESS build always continues, unconditionally and first:
        // fixed_capacity() latches on the very first committed chunk, so any
        // "is the arena ready?" test is already true one tick into a
        // multi-tick build -- gating continuation on NOT-ready (as this once
        // did) froze every build at its first tick's chunks, with status
        // reporting the full planned capacity for an arena that mostly
        // did not exist. arena_ready_locked() encodes the corrected
        // definition (finalized, not merely started).
        //
        // _next_build_attempt_time throttles retry after a FAILED build
        // (insufficient memory): without it, a memory-starved appliance
        // would re-read /proc/meminfo and re-derive the plan on every ~50 ms
        // tick, forever. A failed build instead schedules its next attempt
        // kArenaSettleSeconds out -- the retry itself is deliberate (RAM
        // freed later means the arena eventually builds, self-healing), only
        // its cadence is bounded.
        need_build = _arena_build_in_progress
            || (!arena_ready_locked()
                && (now - _construct_time) >= kArenaSettleSeconds
                && now >= _next_build_attempt_time);
    }
    if (!need_build)
        return;

    bool first_tick = false;
    {
        std::lock_guard<std::mutex> lock(_repeat_mutex);
        // Re-validate under the lock: a disable/teardown may have raced in
        // since the check above.
        if (!_enabled_cfg)
            return;
        if (arena_ready_locked())
            return;   // a racing build (should not happen -- one worker thread
                       // drives this -- but defensive) already FINALIZED;
                       // an in-progress build falls through and continues
        first_tick = !_arena_build_in_progress;
        if (first_tick)
            _arena_build_in_progress = true;
    }

    // ── Outside _repeat_mutex: derive the plan (first tick only) ──────────
    // The plan itself does not change once derived -- only how much of it
    // has been COMMITTED changes, tick by tick, below -- so this read only
    // needs to happen once per build, not once per tick.
    if (first_tick)
    {
        MemInfo mem = read_meminfo();
        long effective_mib = mem.ok() ? mem.effective_available_mib() : 0;
        CodecChoice pinned = pinned_codec_from_config(_codec_cfg);
        ArenaPlan plan = plan_arena(effective_mib, _target_minutes_cfg, _sample_rate_hz, pinned,
                                     _buffer.chunk_bytes());

        std::lock_guard<std::mutex> lock(_repeat_mutex);
        if (!_enabled_cfg)
            return;   // disabled while the meminfo read was in flight
        _arena_plan = plan;
        if (plan.codec == CodecChoice::Unavailable)
        {
            // Not even one whole chunk fits: nothing to commit, finalize
            // immediately as refused. Retry throttled -- see
            // _next_build_attempt_time at the top of this function.
            _arena_build_in_progress = false;
            _unavailable_reason      = "insufficient_memory";
            _next_build_attempt_time = get_monotonic_time() + kArenaSettleSeconds;
            LOG_WARN("[repeat] arena build: insufficient memory (available=%ld MiB, "
                      "target=%d min)", effective_mib, _target_minutes_cfg);
            return;
        }
    }

    // ── Incremental commit: up to 2 chunks this tick ───────────────────────
    size_t target_chunks;
    {
        std::lock_guard<std::mutex> lock(_repeat_mutex);
        if (!_enabled_cfg || !_arena_build_in_progress)
            return;   // disabled, or a racing tick already finalized this build
        target_chunks = (_buffer.chunk_bytes() > 0) ? (_arena_plan.arena_bytes / _buffer.chunk_bytes()) : 0;
    }

    bool stopped_early = false;
    int committed_this_tick = 0;
    for (; committed_this_tick < 2; ++committed_this_tick)
    {
        size_t committed_chunks;
        {
            std::lock_guard<std::mutex> lock(_repeat_mutex);
            committed_chunks = _buffer.chunk_count() + _buffer.spare_chunk_count();
        }
        if (committed_chunks >= target_chunks)
            break;   // target reached

        // ── Outside _repeat_mutex: the per-chunk floor check ────────────────
        MemInfo mem = read_meminfo();
        long effective_mib = mem.ok() ? mem.effective_available_mib() : 0;
        long chunk_mib = static_cast<long>(_buffer.chunk_bytes() / (1024 * 1024));
        if (!mem.ok() || (effective_mib - chunk_mib) < kFreeRamFloorMib)
        {
            stopped_early = true;
            break;
        }

        // The memset inside preallocate_one_more_chunk() runs under the
        // lock: ~16 MiB of first-touch writes costs on the order of a
        // millisecond, far below the threshold that would meaningfully
        // stall get_status()/set_enabled()/notify_capture_started() (all of
        // which take this same lock only briefly themselves), and keeping
        // it under the lock is the simplest correct form -- allocating
        // outside and re-validating on re-acquire would need to handle a
        // superseding disable/teardown racing the allocation, for no
        // benefit worth that complexity at this size.
        bool ok;
        {
            std::lock_guard<std::mutex> lock(_repeat_mutex);
            if (!_enabled_cfg || !_arena_build_in_progress)
                return;
            ok = _buffer.preallocate_one_more_chunk();
        }
        if (!ok)
        {
            stopped_early = true;
            break;
        }
    }

    size_t committed_chunks_now;
    {
        std::lock_guard<std::mutex> lock(_repeat_mutex);
        committed_chunks_now = _buffer.chunk_count() + _buffer.spare_chunk_count();
    }
    bool finished = stopped_early || committed_chunks_now >= target_chunks;
    if (!finished)
        return;   // still short of target, no early stop -- continue next tick

    // ── Finalize: recompute capacity_seconds from the ACHIEVED arena_bytes ──
    {
        std::lock_guard<std::mutex> lock(_repeat_mutex);
        if (!_enabled_cfg || !_arena_build_in_progress)
            return;   // disabled/torn-down while finalizing

        size_t achieved_bytes = _buffer.arena_bytes();
        long   rate            = byte_rate_for(_arena_plan.codec, _sample_rate_hz);
        if (achieved_bytes == 0 || rate <= 0)
        {
            // Zero chunks achievable (the very first chunk's floor check
            // failed immediately): the arena cannot exist at all. Retry
            // throttled -- see _next_build_attempt_time at the top of this
            // function.
            _arena_plan          = ArenaPlan{CodecChoice::Unavailable, 0, 0};
            _unavailable_reason  = "insufficient_memory";
            _active_codec        = CodecChoice::Unavailable;
            _next_build_attempt_time = get_monotonic_time() + kArenaSettleSeconds;
        }
        else
        {
            _arena_plan.arena_bytes      = achieved_bytes;
            _arena_plan.capacity_seconds = static_cast<long>(achieved_bytes / static_cast<size_t>(rate));
            _unavailable_reason.clear();
            // Set from build completion onward, not
            // just during a Recording session: a HELD recording's
            // recording.seconds (get_status()) must derive from the codec
            // that actually encoded it, which -- once an arena has ever been
            // built -- is always this arena's codec (fixed per arena, never
            // re-picked per session).
            _active_codec = _arena_plan.codec;
            LOG_INFO("[repeat] arena built: codec=%s, arena=%zu MiB, capacity=%lds "
                     "(requested %d min)",
                     codec_choice_to_string(_arena_plan.codec), achieved_bytes / (1024 * 1024),
                     _arena_plan.capacity_seconds, _target_minutes_cfg);
        }
        _arena_build_in_progress = false;

        // Arena-ready kick (required): a permitted input
        // may already be capturing (audio playing through the settle
        // window, or simply arriving while a large arena's build spans
        // several ticks) with no NEW should_capture edge coming to admit
        // it -- notify_capture_started() only fires once per edge, and a
        // refused Pending never retries on its own. Dispatching a synthetic
        // CaptureStarted here, for the input _capture_active already names,
        // closes that gap: without it, audio already playing when the
        // build finishes would go entirely unrecorded for the rest of the
        // session (see _capture_active's declaration comment for the full
        // rationale). Dispatched inside this same critical section (handle_
        // event_locked() is a *_locked helper, and the guards just tested --
        // _capture_active, _state == Idle -- must not be re-checked under a
        // later, separate lock acquisition where a real edge could have
        // raced in between).
        if (_arena_plan.codec != CodecChoice::Unavailable && _capture_active && _state == RepeatState::Idle)
        {
            RepeatEventCtx ctx;
            ctx.input_index = _capture_active_input;
            handle_event_locked(RepeatEvent::CaptureStarted, ctx);
        }
    }
}

void RepeatController::notify_capture_stopped(int input_index)
{
    std::unique_lock<std::mutex> lock(_repeat_mutex);

    // Arena-ready kick bookkeeping: cleared unconditionally
    // for THIS input, before the origin-input early-return below -- capture
    // stopping on a non-origin input (e.g. the other, not-currently-recorded
    // input) must still clear the flag if it was the one being tracked, or a
    // stale should-capture edge from a device that is no longer capturing
    // could trigger a spurious synthetic session start later. See
    // notify_capture_started()'s matching set for the full comment.
    if (_capture_active && _capture_active_input == input_index)
        _capture_active = false;

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
        RepeatEventCtx ctx;
        ctx.input_index = input_index;
        handle_event_locked(RepeatEvent::CaptureStopped, ctx);   // Pending -> Idle + log (CaptureStoppedPendingCancelled)
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

    // Tail cut.
    size_t trim_bytes;
    if (_tail_marker.has_mark())
    {
        // Normal case: onset confirmed and at least one sustained run was
        // committed. Cut everything past the marker's recorded cut position
        // (the first committed block boundary at least the pad past the last
        // sustained run's end -- see TailMarker) -- this is what excludes
        // lead-out crackle and a tonearm clunk (each a transient that reset
        // the tail's own SustainTracker without ever re-sustaining)
        // regardless of whether the input's own silence test ever actually
        // saw them as "quiet" moment to moment. Because the cut is a
        // committed block boundary, the kept tail always ends on a whole
        // encoded frame; the encoder flush tail appended above lies past
        // the cut and is removed with the rest of the run-out. When no cut
        // was recorded, the session ended within the pad of the last
        // sustained run -- the recording already ends close enough to the
        // music that nothing needs cutting.
        trim_bytes = (_tail_marker.has_cut()
                      && _buffer.total_bytes() >= _tail_marker.cut_bytes())
            ? (_buffer.total_bytes() - _tail_marker.cut_bytes())
            : 0;
    }
    else
    {
        // Fallback: no valid marker, which in practice means onset never
        // confirmed this session -- _buffer is empty (nothing was ever
        // committed) so this trims nothing either way. Kept as the
        // fallback path (rather than skipping the cut outright) so any
        // future edge case that leaves _tail_marker without a mark still
        // gets the pre-existing measured-trailing-silence behaviour instead
        // of silently keeping an untrimmed tail.
        long byte_rate = byte_rate_for(_active_codec, _sample_rate_hz);
        size_t pad_bytes = (byte_rate > 0)
            ? static_cast<size_t>(static_cast<double>(byte_rate) * kSilenceTrimPadSeconds)
            : 0;
        int frame_bytes = _encoder ? _encoder->frame_bytes() : 1;
        trim_bytes = SilenceTrimAccountant::compute_trim_bytes(
            _trim.bytes_since_last_loud(), pad_bytes, static_cast<size_t>(frame_bytes),
            _buffer.total_bytes());
    }
    _buffer.truncate_tail(trim_bytes);

    _encoder.reset();
    // Onset gate / tail marker: the session is over either way -- if onset
    // never confirmed, _buffer is empty by construction (nothing was ever
    // spliced in) and any thump/spin-up audio still sitting in the ring is
    // discarded here rather than lingering in memory into HOLD; if onset did
    // confirm, the ring was already fully drained during the recording (see
    // process_recorder_samples()) and is empty already. Either way, the next
    // session's perform_pending_start() would re-initialise all three anyway
    // -- this is purely prompt cleanup, not a correctness requirement.
    _onset.reset();
    _tail_marker.reset();
    _preroll_ring.clear();
    // Recording -> Hold decision (CaptureStopped cell); _origin_input
    // / _origin_input_fast are left as-is by that cell (not one of the
    // fields it writes) -- the HOLD recording's origin_input is still
    // meaningful for status reporting. The fast mirror no longer
    // matters once _state_fast != Recording, since recording_wanted()
    // short-circuits on the state check first.
    handle_event_locked(RepeatEvent::CaptureStopped);

    LOG_INFO("[repeat] Recording stopped (input %d): %zu bytes held, trimmed %zu bytes",
             input_index, _buffer.total_bytes(), trim_bytes);

    // Capture-stop -> replay-start transition: if session
    // arm is set, replay begins immediately, inside this SAME _repeat_mutex
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

    transition_locked(RepeatState::Replaying);

    // Minimum playback hold: replay owns playback from this instant. See
    // notify_capture_started()'s replay_hold_active computation.
    _replay_start_time = get_monotonic_time();

    // FifoOwner flips to Replay BEFORE the engine's thread is told to start,
    // so the very next live-path FIFO write (should one somehow race in)
    // already observes Replay and discards -- consistent with "flip
    // ownership only at replay start... never mid-write".
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

    // The state-decision logic (arm-while-Hold -> begin_replay_locked();
    // disarm-while-Replaying -> FadingOut + fade-out; every other (state,
    // Armed/Disarmed) cell a deliberate no-op) lives in
    // decide_repeat_transition()'s Armed/Disarmed cells -- see the matrix
    // comment above handle_event_locked().
    if (armed && !was_armed)
        handle_event_locked(RepeatEvent::Armed);
    else if (!armed && was_armed)
        handle_event_locked(RepeatEvent::Disarmed);

    return "";
}

void RepeatController::notify_input_stopped(int input_index)
{
    // No pre-lock chunk-storage local any more: InputStopped's cells all
    // discard (arena persists), never teardown -- see discard_recording_
    // locked()'s own comment for why that no longer frees anything.
    std::unique_lock<std::mutex> lock(_repeat_mutex);

    if (_origin_input != input_index)
        return;

    // Origin-input reload teardown (driver scenario d12): stop_input on the
    // origin input discards the buffer and cancels any active replay
    // unconditionally, regardless of state (Recording/Hold/Replaying/
    // FadingOut) -- belt and braces alongside Python's own pre-stop_input
    // disarm+discard.
    // As in set_enabled(false) above, the free is deferred when a replay
    // session is active (see PendingAction's declaration comment). This is
    // NEVER restorable by a later re-enable (unlike set_enabled(false)'s
    // Discard) -- the origin input itself is being torn down, so there
    // is no "new recording for the interrupting input" to honour even if
    // repeat stays enabled; _pending_interrupt_restorable is deliberately
    // left false here.
    // The state-decision logic below (Replaying/FadingOut -> abort + pending
    // Discard; Recording/Idle/Hold/Pending -> discard_recording_locked())
    // lives in decide_repeat_transition()'s InputStopped cells -- see the matrix
    // comment above handle_event_locked(). This wrapper still owns the
    // drain-wait choreography and the re-validation discipline exactly
    // where they were.
    if (_state == RepeatState::Replaying || _state == RepeatState::FadingOut)
    {
        handle_event_locked(RepeatEvent::InputStopped);
    }
    else if (_state == RepeatState::Recording)
    {
        // This branch gives the recorder worker a BOUNDED chance
        // (wait_for_drain()) to hand its still-queued ring blocks to
        // process_recorder_samples() before the encoder is torn down, the
        // same courtesy notify_capture_stopped()'s Recording path (above)
        // gives it -- otherwise process_recorder_samples()'s own
        // re-validation (`_state != Recording || !_encoder`) would silently
        // drop that trailing audio the instant _encoder is reset here. A
        // stop_input on the origin input mid-recording (exactly the
        // reload-teardown case this function exists for) gets the same
        // treatment: the recording is still discarded either way, but only
        // after giving the worker a last bounded chance to finish encoding
        // blocks that already passed recording_wanted()'s gate before they
        // are thrown away anyway.
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
            handle_event_locked(RepeatEvent::InputStopped);
    }
    else
    {
        handle_event_locked(RepeatEvent::InputStopped);
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
    // No pre-lock chunk-storage local: ReplaySessionEnded's cells all
    // discard (arena persists), never teardown.
    std::lock_guard<std::mutex> lock(_repeat_mutex);

    // The three-way PendingAction dispatch (Discard -> free; Live
    // Interrupt -> free + start a new Pending session for the interrupting
    // input if still enabled; None -> Hold, with the re-arm-during-fade
    // restart) lives in decide_repeat_
    // transition()'s ReplaySessionEnded cells -- see the matrix comment
    // above handle_event_locked(). This wrapper still does the one-time
    // FifoOwner flip (unrelated to the RepeatState machine) and builds the
    // event's ctx from data (interrupting_input, has_hold_bytes) the pure
    // decision core cannot read off a real RepeatController itself.
    if (_state != RepeatState::Replaying && _state != RepeatState::FadingOut)
        return;   // already handled by a racing notify_input_stopped()/set_enabled(false)

    set_fifo_owner(FifoOwner::Live);

    RepeatEventCtx ctx;
    ctx.interrupting_input = _pending_interrupt_input;
    ctx.has_hold_bytes     = (_buffer.total_bytes() > 0);
    handle_event_locked(RepeatEvent::ReplaySessionEnded, ctx);
}

void RepeatController::encode_and_append_locked(const float* interleaved, int frames,
                                                  bool above_threshold)
{
    // Never unlocks: append() in fixed-arena mode
    // draws from the spare pool or recycles the front chunk (allocate_chunk()
    // in autostream_repeat_buffer.h) -- a pointer move, not a new/malloc call
    // -- and there is no more in-session meminfo tick (the arena is sized
    // once, at build time, not re-checked per block), so nothing on this
    // path needs to happen outside _repeat_mutex any more. encode() itself
    // is fast, purely CPU-bound work against the one encoder object this
    // worker thread owns exclusively while Recording.
    size_t n = _encoder->encode(interleaved, frames, _encode_scratch);
    if (n == 0)
        return;

    // Pre-encode block duration, same domain OnsetGate/SustainTracker use
    // elsewhere (frames / sample_rate_hz) -- computed once here since both
    // append paths below feed it to _tail_marker after their own append.
    double block_seconds = static_cast<double>(frames) / static_cast<double>(_sample_rate_hz);

    if (!_buffer.append(_encode_scratch.data(), n))
    {
        // Hard allocation failure: effectively unreachable once an arena is
        // built (append()'s allocate_chunk() then only draws from the spare
        // pool or recycles, never calling new -- see that function's own
        // comment), but kept as a two-line belt-and-braces fallback for the
        // legacy (non-arena) path -- shed one more chunk and retry once
        // (RepeatBuffer::append() never frees the last remaining chunk, so
        // this always terminates).
        _buffer.drop_oldest_chunk();
        _buffer.append(_encode_scratch.data(), n);
    }
    _trim.on_block_appended(above_threshold, n);
    _tail_marker.on_block_committed(above_threshold, block_seconds, _buffer.total_bytes());
}

void RepeatController::process_recorder_samples(const float* interleaved, int frames, bool above_threshold)
{
    // lock_guard (not unique_lock): encode_and_append_locked() never unlocks
    // any more -- see its own comment.
    std::lock_guard<std::mutex> lock(_repeat_mutex);

    if (_state != RepeatState::Recording || !_encoder)
        return;

    // ── Onset gate ─────────────────────────────────────────────────────────
    // The SESSION already started (this function only runs while Recording);
    // the RECORDER additionally waits for sustained above-threshold audio
    // before committing anything. While onset is not yet confirmed, this
    // block goes ONLY into the pre-roll ring -- never into the encoder/
    // buffer -- so a session that ends before onset confirms leaves the
    // buffer untouched (empty), and has_hold_bytes-gated replay naturally
    // has nothing to play.
    //
    // block_in_ring tracks whether THIS call's own block was pushed into the
    // ring below, so the tail of this function knows whether the block still
    // needs writing directly (steady state: onset confirmed AND the ring
    // fully drained) or has already been folded into the ring-drain loop's
    // backlog (onset pending, just confirmed on this very call, or confirmed
    // earlier with backlog still queued -- in every ring case this call's
    // block is the ring's newest entry, and the drain loop below walks the
    // ring oldest-first, so it is written in its correct chronological
    // position, not duplicated). Committed buffer order therefore always
    // equals arrival order: a block is only ever written directly when no
    // older block is still queued ahead of it.
    bool block_in_ring = false;

    if (!_onset.is_confirmed())
    {
        _preroll_ring.push(interleaved, frames, above_threshold);
        block_in_ring = true;

        bool just_confirmed = _onset.on_block(
            above_threshold, static_cast<double>(frames) / static_cast<double>(_sample_rate_hz));
        if (!just_confirmed)
            return;   // still filling the ring; nothing committed yet

        // Onset just confirmed: fall through to drain the ring (amortized
        // below), which now includes this call's own block as its newest
        // entry.
    }
    else if (!_preroll_ring.empty())
    {
        // Onset confirmed on an earlier call but the amortized drain below
        // has not yet emptied the backlog: this block must queue BEHIND the
        // ring's older entries, not bypass them -- writing it directly here
        // would commit it ahead of audio that precedes it chronologically.
        _preroll_ring.push(interleaved, frames, above_threshold);
        block_in_ring = true;
    }

    // ── Amortized pre-roll splice ────────────────────────────────────────
    // Once onset has confirmed (this call or a previous one), drain up to
    // kOnsetRingDrainBlocksPerCall ring blocks (oldest first, i.e.
    // chronological order) through the normal encode/append/trim path
    // before this call's own live block -- see kOnsetRingDrainBlocksPerCall's
    // declaration for why this is amortized rather than one single burst
    // call. A session whose first live block already confirmed onset (ring
    // holds everything back to session start, since kPreRollSeconds >=
    // kOnsetSustainSeconds) drains its entire backlog this way over the next
    // few calls; a session that never buffered a ring beyond a block or two
    // drains trivially, within this same call.
    for (int i = 0; i < kOnsetRingDrainBlocksPerCall && !_preroll_ring.empty(); ++i)
    {
        PreRollRing::Block blk;
        if (!_preroll_ring.pop_front(blk))
            break;
        encode_and_append_locked(blk.samples.data(),
                                  static_cast<int>(blk.samples.size() / 2u), blk.above_threshold);
    }

    if (block_in_ring)
        return;   // this call's block was handled via the ring above (now,
                   // or -- if the drain cap was hit first -- in a future
                   // call's drain, since it is still safely queued)

    // Steady state: onset was already confirmed before this call started,
    // and the ring played no part in this call at all -- write the live
    // block directly, exactly as process_recorder_samples() always did
    // before onset gating existed.
    encode_and_append_locked(interleaved, frames, above_threshold);
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
    s.target_minutes = _target_minutes_cfg;
    // requested_minutes: the honesty-surface companion to
    // max_recording_seconds below -- what was asked for, not
    // what the arena delivers. Only meaningful while the feature is
    // enabled; 0 disabled, matching max_recording_seconds's own
    // enabled-only convention.
    s.requested_minutes = _enabled_cfg ? _target_minutes_cfg : 0;

    if (_state == RepeatState::Recording)
    {
        // Frozen at the value computed when this session started
        // (perform_pending_start(), from the arena's own capacity_seconds
        // at that instant) -- unchanged pre-existing behaviour.
        s.max_recording_seconds = _max_recording_seconds;
        s.effective_codec       = codec_choice_to_string(_active_codec);
    }
    else
    {
        // Idle/Hold/Replaying/FadingOut/Pending: report the ARENA's actual
        // figures -- no hypothetical re-derivation, no
        // poll-to-poll drift, and this call never itself touches
        // /proc/meminfo (it can be called under long-held locks elsewhere /
        // on a hot poll path; the arena's figures are already sitting in
        // _arena_plan, maintained by maybe_build_arena() on the recorder
        // worker thread). Arena ready == _arena_plan.codec != Unavailable
        // && _buffer.fixed_capacity() (same test perform_pending_start()
        // uses); 0 is the "no number yet" value the setup page treats as
        // such, covering both "disabled" and "enabled but the build hasn't
        // finished/started yet" (e.g. the settle window, or a still-running
        // multi-tick build for a large arena).
        if (arena_ready_locked())
        {
            s.max_recording_seconds = _arena_plan.capacity_seconds;
            s.effective_codec       = codec_choice_to_string(_arena_plan.codec);
        }
        else
        {
            s.max_recording_seconds = 0;
        }
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
    // being derived purely from _state, so that a single poll of get_status()
    // never observes a torn, half-transitioned snapshot -- even in the
    // single-poll window right after begin_replay_locked() sets
    // _state = Replaying but before the replay thread has actually opened its
    // fd: get_status() reports replay.active=true from the moment the state
    // transition happens (this function itself holds _repeat_mutex, so it can
    // never observe the pre-transition Hold state once notify_capture_stopped()
    // has returned) -- ReplayEngine::get_snapshot() below is consulted only
    // for position/duration/loop_count, not for the active flag itself.
    ReplayEngine::Snapshot rsnap = _replay.get_snapshot();
    s.replay.active           = (_state == RepeatState::Replaying || _state == RepeatState::FadingOut);
    s.replay.fading_out       = (_state == RepeatState::FadingOut);
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
        {
            // run_one_session() does not call the terminal handler itself --
            // every one of its exit paths (open-abort, open error,
            // decoder-init failure, mid-session abort, decode/write error,
            // fade complete) funnels through its return value instead, and
            // this is the single call site for
            // on_replay_session_ended_locked_entry(). The reason
            // value itself is not consulted here -- the handler is reason-
            // agnostic today, exactly as all four old call sites invoked it
            // identically regardless of why the session ended.
            run_one_session();
            _owner.on_replay_session_ended_locked_entry();
        }
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

// =============================================================================
// ReplayEngine::ReplaySessionCtx
//
// RAII home for every per-session resource: fd, decoder, Reader, ID tap,
// fade state, and the DSP-chain scratch buffers. Constructed once per
// session (a local variable in run_one_session()) and destroyed when that
// function returns via any path -- early or otherwise -- so a future exit
// added to the middle of the session loop cannot leak the fd or the mpg123
// decoder the way a hand-written early `return` could.
// =============================================================================

struct ReplayEngine::ReplaySessionCtx
{
    int fd = -1;   // blocking-paced O_WRONLY fd on the FIFO, owned solely by the replay thread

    std::unique_ptr<Mp2Decoder>          decoder;   // null for the PCM tier
    std::optional<RepeatBuffer::Reader>  reader;    // no default ctor; emplaced by init_session()
    std::optional<IdTapResampler>        id_tap;    // no default ctor; emplaced by init_session()
    TrackGapDetector                     gap_detector;

    // ── Replay-owned DSP chain state -- see init_session()'s comment for
    // the loop-seam reset rule ──────────────────────────────────────────────
    std::vector<BiquadFilter> replay_filters;
    std::shared_ptr<const std::vector<EqBand>> replay_eq_bands_cache;
    RepeatController::LiveDspParams live_dsp;   // current pulled gain/EQ, refreshed once per
                                                 // staging refill -- see decode_next_slice()

    bool   fading            = false;
    double fade_elapsed_secs = 0.0;
    double frames_played     = 0.0;

    // Scratch, sized once per session (never per-slice) to avoid heap churn.
    std::vector<uint8_t>  raw_buf = std::vector<uint8_t>(65536);
    std::vector<int16_t>  pcm_staging;
    std::vector<uint8_t>  pipe_bytes;
    std::vector<float>    id_stereo_float;   // int16 slice -> normalised float, ID-tap input
    std::vector<float>    dsp_float_buf;     // gain/EQ/OutputProcessor float stage
    std::vector<int16_t>  dsp_pcm_buf;       // requantised s16 result

    ~ReplaySessionCtx()
    {
        // decoder/reader/id_tap are RAII themselves; only the fd needs
        // explicit teardown here -- same condition (fd >= 0) the pre-split
        // code closed it under at every one of its exit points.
        if (fd >= 0)
            ::close(fd);
    }
};

// Opens this session's own blocking-paced fd on the FIFO.
// O_NONBLOCK (not a literal blocking open) so a missing reader (ENXIO) or a
// full pipe never hangs this thread without an abort check; the
// poll(POLLOUT)-gated write loop in write_slice_paced() still lets the
// reader's drain rate pace replay exactly as a blocking fd would.
std::optional<ReplayEngine::SessionEndReason>
ReplayEngine::open_fifo_for_session(ReplaySessionCtx& ctx, const std::string& path)
{
    ctx.fd = -1;
    for (;;)
    {
        // Treat FadeOut the same as Abort here: there is no audio in flight
        // yet to fade (no reader has ever been attached to write to), so a
        // disarm arriving before the fd is even open has nothing to wait
        // out -- end the session immediately rather than spinning forever
        // ignoring the request: checking Abort alone here would leave a
        // disarm sent while no reader is attached to the FIFO unable to
        // unblock replay.
        Cmd cmd = _pending_cmd.load();
        if (cmd == Cmd::Abort || cmd == Cmd::FadeOut || _stop_requested.load(std::memory_order_relaxed))
        {
            _pending_cmd.store(Cmd::None);
            return SessionEndReason::AbortedBeforeOpen;
        }
        int fd = ::open(path.c_str(), O_WRONLY | O_NONBLOCK);
        if (fd >= 0)
        {
            ctx.fd = fd;
            return std::nullopt;
        }
        if (errno != ENXIO)
        {
            LOG_WARN("[repeat] ReplayEngine: open('%s') failed: %s", path.c_str(), strerror(errno));
            return SessionEndReason::OpenError;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(kPollTimeoutMs));
    }
}

// Decoder construction, Reader/ID-tap setup, and the ID-buffer/track-change-
// seq reset -- everything that must happen exactly once, after the fd is
// open, before the per-slice loop starts.
bool ReplayEngine::init_session(ReplaySessionCtx& ctx, CodecChoice codec, int rate_hz,
                                 const RepeatBuffer& buffer)
{
    if (codec != CodecChoice::PcmS16)
    {
        ctx.decoder = std::make_unique<Mp2Decoder>(rate_hz);
        if (!ctx.decoder->ok())
        {
            LOG_WARN("[repeat] ReplayEngine: mpg123 init failed; aborting replay");
            return false;
        }
    }

    ctx.reader.emplace(buffer);

    // Fresh session, fresh stall streak -- never carry a stall
    // reading from a PRIOR replay session into this one's get_status()
    // reporting (see _stall_since's doc comment).
    _stall_since.store(0.0, std::memory_order_relaxed);

    // ctx.replay_filters/replay_eq_bands_cache hold this session's own
    // BiquadFilter delay-line state, entirely separate from any
    // InputChannel's -- default-constructed empty here (session start) and
    // cleared again at each loop wrap in decode_next_slice(): filter state
    // must not carry across the loop seam, since the sample immediately
    // after the wrap is not continuous with the sample immediately before
    // it, so carrying delay-line state across that seam would smear a
    // discontinuity into a filter-tail artefact at every loop boundary.

    {
        std::lock_guard<std::mutex> id_lock(_id_mutex);
        _id_buf.assign(ID_BUF_FRAMES, 0);
        _id_write_pos    = 0;
        _id_frames_avail = 0;
    }
    _track_change_seq.store(0, std::memory_order_relaxed);

    // ID-tap resampler (shared, filtered SRC_SINC_FASTEST helper -- see
    // autostream_id_tap.h), constructed fresh per session, matching the
    // per-session src_new()/src_delete() lifetime this replaced. kSliceFrames
    // (4096) is the largest block a single iteration below ever hands it.
    ctx.id_tap.emplace(rate_hz, static_cast<int>(ID_BUF_RATE), static_cast<int>(kSliceFrames));

    return true;
}

// One reader.next() batch: abort/fade-start check, buffer-end loop-wrap
// handling, live gain/EQ pull, and codec decode/copy into ctx.pcm_staging.
ReplayEngine::SliceBatchOutcome
ReplayEngine::decode_next_slice(ReplaySessionCtx& ctx, CodecChoice codec)
{
    Cmd cmd = _pending_cmd.exchange(Cmd::None, std::memory_order_acq_rel);
    if (cmd == Cmd::Abort || _stop_requested.load(std::memory_order_relaxed))
        return SliceBatchOutcome::Aborted;
    if (cmd == Cmd::FadeOut && !ctx.fading)
    {
        ctx.fading = true;
        ctx.fade_elapsed_secs = 0.0;
    }

    size_t n = ctx.reader->next(ctx.raw_buf.data(), ctx.raw_buf.size());
    if (n == 0)
    {
        // End of buffer: loop (loop_count++, reader.rewind()). Never happens
        // mid-fade in practice (a fade
        // completes in kFadeSeconds, far short of any recording), but if it did,
        // looping mid-fade is harmless -- the fade gain continues to
        // ramp down against the freshly-rewound stream.
        _loop_count.fetch_add(1, std::memory_order_relaxed);
        ctx.reader->rewind();
        ctx.frames_played = 0.0;
        // _position_seconds is deliberately left untouched here:
        // it stays frozen at the just-finished loop's duration for the
        // whole inter-loop gap (write_loop_gap(), called by the caller in
        // response to the Wrapped outcome below), then resets to 0 as an
        // ordinary side effect of the first real post-gap slice's own
        // position update in run_one_session()'s write loop.

        // Reset the replay-owned EQ filter state at the loop seam
        // so no delay-line history carries from the end of the
        // recording into its own beginning.
        ctx.replay_filters.clear();
        ctx.replay_eq_bands_cache.reset();

        // The decoder's buffered bitstream state must not carry across the
        // seam either: the recording's final bytes may end mid-frame, and a
        // decoder still holding them would prepend them to the head's first
        // frame after the rewind, desyncing the decode at the very start of
        // every loop. PCM has no decoder (ctx.decoder is null on that tier).
        if (ctx.decoder && !ctx.decoder->reset())
        {
            LOG_WARN("[repeat] ReplayEngine: decoder reset failed at loop wrap; aborting replay");
            return SliceBatchOutcome::DecodeError;
        }
        return SliceBatchOutcome::Wrapped;
    }

    // Pull the origin input's current gain/EQ once per staging refill
    // (this call processes one reader.next() batch, typically a few
    // hundred ms to ~1 s of audio depending on codec/bitrate -- ~1 s
    // granularity is fine, and polling somewhat more often than that costs
    // only a cheap function call + shared_ptr copy).
    // Rebuild ctx.replay_filters only when the pulled band list's shared_ptr
    // address has actually changed, mirroring InputChannel::process_
    // thread_func's own _current_eq_bands change-detection (autostream_
    // monitor_io.cpp) -- so an unchanged EQ setting costs nothing beyond the
    // pointer compare. _session_origin_input is read directly (not passed
    // in) because it is fixed for the whole session -- see its own doc
    // comment: only written by request_start(), only read by this thread
    // once a session is active.
    ctx.live_dsp = _owner.query_live_dsp_params(_session_origin_input);
    if (ctx.live_dsp.eq_bands != ctx.replay_eq_bands_cache)
    {
        ctx.replay_eq_bands_cache = ctx.live_dsp.eq_bands;
        ctx.replay_filters.clear();
        if (ctx.replay_eq_bands_cache)
        {
            for (const auto& band : *ctx.replay_eq_bands_cache)
            {
                BiquadFilter f;
                f.configure(band, ctx.live_dsp.eq_sample_rate);
                ctx.replay_filters.push_back(f);
            }
        }
    }

    ctx.pcm_staging.clear();
    if (codec == CodecChoice::PcmS16)
    {
        size_t n_samples = n / sizeof(int16_t);
        ctx.pcm_staging.resize(n_samples);
        std::memcpy(ctx.pcm_staging.data(), ctx.raw_buf.data(), n_samples * sizeof(int16_t));
    }
    else
    {
        if (!ctx.decoder->feed_and_decode(ctx.raw_buf.data(), n, ctx.pcm_staging))
        {
            LOG_WARN("[repeat] ReplayEngine: mpg123 decode error; aborting replay");
            return SliceBatchOutcome::DecodeError;
        }
    }

    if (ctx.pcm_staging.empty())
        return SliceBatchOutcome::Retry;   // decoder still accumulating a partial frame

    return SliceBatchOutcome::Ready;
}

// One kSliceFrames-sized slice: track-gap detect -> ID tap -> gain -> EQ ->
// OutputProcessor -> fade envelope -> pipe-format conversion, writing the
// result into ctx.pipe_bytes for write_slice_paced() to send.
void ReplayEngine::process_slice(ReplaySessionCtx& ctx, const int16_t* slice, size_t slice_samples,
                                  int rate_hz, int silence_threshold, double track_gap_seconds)
{
    size_t slice_frames = slice_samples / 2;

    // ── Replay-side TrackGapDetector + 16 kHz mono ID tap ─────────────────
    // Fed from the DECODED, PRE-DSP `slice` -- i.e. exactly the stage the
    // recording itself is made at (POST-SRC/PRE-GAIN, see the recorder
    // tap's comment in autostream_monitor_io.cpp), which matches
    // InputChannel's own live ID tap stage ("post-main-SRC, pre-gain/pre-EQ",
    // InputChannel::_id_buf's class comment) -- so track-ID behaves
    // identically whether the audio is coming from live capture or replay.
    // This must run BEFORE the gain/EQ/OutputProcessor chain below: fade is
    // applied at the very end, after quantisation, so this tap sees the
    // untouched decoded sample regardless of fade state, matching live
    // behaviour where the ID tap is likewise upstream of gain.
    int peak = replay_peak_sample(slice, slice_samples);
    bool raw_above = (peak >= silence_threshold);
    if (ctx.gap_detector.update(/*capturing=*/true, raw_above,
                                 get_monotonic_time(), track_gap_seconds))
    {
        _track_change_seq.fetch_add(1, std::memory_order_relaxed);
    }

    if (ctx.id_tap->valid())
    {
        // Normalise the decoded int16 slice to float; id_tap does
        // the downmix, resample, and clamp (autostream_id_tap.h).
        ctx.id_stereo_float.resize(slice_samples);
        for (size_t s = 0; s < slice_samples; ++s)
            ctx.id_stereo_float[s] = slice[s] / 32768.0f;

        int id_count = 0;
        const int16_t* id_out = ctx.id_tap->process(
            ctx.id_stereo_float.data(), static_cast<int>(slice_frames), &id_count);
        if (id_out && id_count > 0)
        {
            std::lock_guard<std::mutex> id_lock(_id_mutex);
            unsigned wp = _id_write_pos;
            for (int i = 0; i < id_count; ++i)
                _id_buf[(wp + static_cast<unsigned>(i)) & ID_BUF_MASK] = id_out[i];
            _id_write_pos    = wp + static_cast<unsigned>(id_count);
            _id_frames_avail = std::min(_id_frames_avail + static_cast<unsigned>(id_count),
                                         ID_BUF_FRAMES);
        }
    }

    // ── Live DSP chain -- gain, then EQ, then the shared OutputProcessor
    // (identical order to InputChannel::process_
    // thread_func's live path: gain+ramp, per-input EQ, then
    // OutputProcessor::apply()) -- EXCEPT the fade-in ramp, which is
    // never re-played (only the settled current gain applies; see
    // InputChannel::gain_linear()'s doc comment).
    ctx.dsp_float_buf.resize(slice_samples);
    src_short_to_float_array(slice, ctx.dsp_float_buf.data(),
                              static_cast<int>(slice_samples));

    if (ctx.live_dsp.gain_linear != 1.0f)
    {
        for (size_t s = 0; s < slice_samples; ++s)
            ctx.dsp_float_buf[s] *= ctx.live_dsp.gain_linear;
    }

    for (auto& filter : ctx.replay_filters)
        filter.process(ctx.dsp_float_buf.data(), static_cast<int>(slice_frames));

    // OutputProcessor::apply() is shared, mutable state (the same
    // instance the live InputChannel path calls) -- held under
    // _fifo_mutex for exactly the duration of this call, mirroring
    // the live path's own critical section (autostream_monitor_io.cpp),
    // and NEVER across the blocking/poll-gated write in write_slice_paced()
    // (this mutex is never held across write()).
    {
        std::lock_guard<std::mutex> fifo_lock(_owner._fifo_mutex);
        _owner._output_processor.apply(ctx.dsp_float_buf.data(), static_cast<int>(slice_frames));
    }

    ctx.dsp_pcm_buf.resize(slice_samples);
    src_float_to_short_array(ctx.dsp_float_buf.data(), ctx.dsp_pcm_buf.data(),
                              static_cast<int>(slice_samples));

    // ── Fade gain (disarm fade, linear, kFadeSeconds span) ──────────────
    // Applied AFTER the DSP chain, by design, so a live gain
    // change during the fade itself still scales correctly -- the
    // fade is a final multiplicative envelope on top of whatever the
    // DSP chain just produced, not a substitute baked-in level.
    if (ctx.fading)
    {
        for (size_t f = 0; f < slice_frames; ++f)
        {
            double t = ctx.fade_elapsed_secs + static_cast<double>(f) / rate_hz;
            double g = 1.0 - (t / kFadeSeconds);
            if (g < 0.0) g = 0.0;
            ctx.dsp_pcm_buf[f * 2]     = static_cast<int16_t>(ctx.dsp_pcm_buf[f * 2]     * g);
            ctx.dsp_pcm_buf[f * 2 + 1] = static_cast<int16_t>(ctx.dsp_pcm_buf[f * 2 + 1] * g);
        }
        ctx.fade_elapsed_secs += static_cast<double>(slice_frames) / rate_hz;
    }

    // ── Pipe-format conversion ─────────────────────────────────────────────
    // widen_to_s32 mirrors deliver_output()'s own mode check so the replay
    // writer and the live writer never disagree about the wire layout.
    bool widen_to_s32 = AudioMonitor::output_format_mode() != OutputFormatMode::Compatible;
    convert_to_pipe_format(ctx.dsp_pcm_buf.data(), slice_samples, ctx.pipe_bytes, widen_to_s32);
}

ReplayEngine::SessionEndReason ReplayEngine::run_one_session()
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

    // ReplaySessionCtx owns the fd, decoder, Reader, ID tap, fade state,
    // and DSP scratch for this session; its destructor closes the fd
    // and tears everything else down when this function returns, via any
    // path below.
    ReplaySessionCtx ctx;

    if (auto open_reason = open_fifo_for_session(ctx, path))
        return *open_reason;

    if (!init_session(ctx, codec, rate_hz, *buffer))
        return SessionEndReason::DecoderInitFailed;

    long byte_rate = byte_rate_for(codec, rate_hz);
    double duration = (byte_rate > 0)
        ? static_cast<double>(buffer->total_bytes()) / static_cast<double>(byte_rate) : 0.0;

    _duration_seconds.store(duration, std::memory_order_relaxed);
    _position_seconds.store(0.0, std::memory_order_relaxed);
    _loop_count.store(0, std::memory_order_relaxed);
    _active.store(true, std::memory_order_relaxed);

    SessionEndReason reason = SessionEndReason::FadeComplete;   // default: only overwritten below
                                                                 // on an abort/error path (mirrors
                                                                 // the pre-split `session_aborted`
                                                                 // bool's default of false)

    for (;;)
    {
        SliceBatchOutcome outcome = decode_next_slice(ctx, codec);
        if (outcome == SliceBatchOutcome::Aborted || outcome == SliceBatchOutcome::DecodeError)
        {
            reason = SessionEndReason::Aborted;
            break;
        }
        if (outcome == SliceBatchOutcome::Wrapped)
        {
            if (!write_loop_gap(ctx, rate_hz))
            {
                reason = SessionEndReason::Aborted;   // reader absent / pipe error mid-gap
                break;
            }
            continue;
        }
        if (outcome == SliceBatchOutcome::Retry)
            continue;

        size_t total_samples = ctx.pcm_staging.size() - (ctx.pcm_staging.size() % 2);   // stereo-align
        size_t offset = 0;
        bool write_failed = false;

        while (offset < total_samples)
        {
            size_t slice_samples = std::min(kSliceFrames * 2, total_samples - offset);
            slice_samples -= (slice_samples % 2);
            if (slice_samples == 0)
                break;

            const int16_t* slice = ctx.pcm_staging.data() + offset;
            process_slice(ctx, slice, slice_samples, rate_hz, silence_threshold, track_gap_seconds);
            if (!write_slice_paced(ctx))
            {
                write_failed = true;
                break;
            }

            size_t slice_frames = slice_samples / 2;
            offset            += slice_samples;
            ctx.frames_played += static_cast<double>(slice_frames);
            _position_seconds.store(ctx.frames_played / rate_hz, std::memory_order_relaxed);
        }

        if (write_failed)
        {
            reason = SessionEndReason::Aborted;   // reader absent / pipe error
            break;
        }
        if (ctx.fading && ctx.fade_elapsed_secs >= kFadeSeconds)
        {
            reason = SessionEndReason::FadeComplete;
            break;   // disarm fade complete: fall through to normal cleanup
        }
    }

    _active.store(false, std::memory_order_relaxed);
    // ctx's destructor closes the fd (and tears down the decoder/reader/ID
    // tap) when this function returns, below -- the same condition (fd >= 0)
    // the pre-split code closed it under at every one of its own exit
    // points, now enforced structurally instead of by hand at each one.

    LOG_INFO("[repeat] Replay session ended (input %d)%s", origin,
             reason == SessionEndReason::FadeComplete ? " [fade complete]" : " [aborted]");

    return reason;
}

bool ReplayEngine::write_slice_paced(ReplaySessionCtx& ctx)
{
    // track_stall_outcome() below folds every exit of this loop
    // into "fifo.stalled_seconds" the same way FifoWriter::write() does for
    // the live path -- a poll() timeout (reader not draining) counts as a
    // stall tick just like a hard write error, since either way no bytes are
    // moving; a poll timeout alone does not exit the loop (it re-checks the
    // abort flag and continues), so it is recorded inline below rather than
    // via a single wrapped return.
    const std::vector<uint8_t>& data = ctx.pipe_bytes;
    size_t written = 0;
    while (written < data.size())
    {
        if (_pending_cmd.load(std::memory_order_relaxed) == Cmd::Abort ||
            _stop_requested.load(std::memory_order_relaxed))
            return track_stall_outcome(false);

        pollfd pfd;
        pfd.fd      = ctx.fd;
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

        ssize_t n = ::write(ctx.fd, data.data() + written, data.size() - written);
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

bool ReplayEngine::write_loop_gap(ReplaySessionCtx& ctx, int rate_hz)
{
    // Silence, generated directly (no decode, no DSP chain, no fade, no ID
    // tap, no TrackGapDetector update -- see this method's declaration
    // comment) -- reuses ctx.pipe_bytes as scratch exactly like
    // process_slice() does, and paces through the same write_slice_paced()
    // so an abort/write-error/stall observed mid-gap behaves identically to
    // one observed mid-content.
    size_t gap_frames  = static_cast<size_t>(kLoopGapSeconds * rate_hz);
    size_t gap_samples = gap_frames * 2u;   // stereo

    std::vector<int16_t> silence(std::min(kSliceFrames * 2, gap_samples), 0);

    // Same mode check as process_slice() -- the gap must land on the wire
    // in the same layout as the content either side of it.
    bool widen_to_s32 = AudioMonitor::output_format_mode() != OutputFormatMode::Compatible;

    size_t written_samples = 0;
    while (written_samples < gap_samples)
    {
        if (_pending_cmd.load(std::memory_order_relaxed) == Cmd::Abort ||
            _stop_requested.load(std::memory_order_relaxed))
            return false;

        size_t slice_samples = std::min(silence.size(), gap_samples - written_samples);
        convert_to_pipe_format(silence.data(), slice_samples, ctx.pipe_bytes, widen_to_s32);
        if (!write_slice_paced(ctx))
            return false;
        written_samples += slice_samples;
    }
    return true;
}

bool ReplayEngine::track_stall_outcome(bool ok)
{
    if (ok)
        _stall_since.store(0.0, std::memory_order_relaxed);
    else if (_stall_since.load(std::memory_order_relaxed) == 0.0)
        _stall_since.store(get_monotonic_time(), std::memory_order_relaxed);
    return ok;
}
