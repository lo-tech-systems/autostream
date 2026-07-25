// =============================================================================
// autostream_monitor_io.cpp
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Implementation of audio I/O classes: list_alsa_capture_devices, AlsaCapture,
// FifoWriter, InputChannel.
// =============================================================================

#include "autostream_monitor.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <system_error>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>


// =============================================================================
// list_alsa_capture_devices
// =============================================================================

std::vector<AlsaDeviceInfo> list_alsa_capture_devices()
{
    std::vector<AlsaDeviceInfo> result;

    void** hints = nullptr;
    if (snd_device_name_hint(-1, "pcm", &hints) < 0)
    {
        LOG_WARN("[monitor] list_alsa_capture_devices: snd_device_name_hint failed");
        return result;
    }

    for (void** hint = hints; *hint != nullptr; ++hint)
    {
        char* name_cstr = snd_device_name_get_hint(*hint, "NAME");
        char* desc_cstr = snd_device_name_get_hint(*hint, "DESC");
        char* ioid_cstr = snd_device_name_get_hint(*hint, "IOID");

        // IOID is "Input", "Output", or nullptr (meaning both directions).
        // We want capture devices only.
        bool is_capture = (ioid_cstr == nullptr || strcmp(ioid_cstr, "Input") == 0);

        if (name_cstr && is_capture)
        {
            std::string hw_name(name_cstr);

            // Only include hw:X,Y devices — plughw, default, etc. are excluded
            // because we want to talk directly to hardware for clock measurement.
            if (hw_name.size() > 3 && hw_name.substr(0, 3) == "hw:")
            {
                AlsaDeviceInfo info;
                info.hw_name = hw_name;

                if (desc_cstr)
                {
                    // ALSA desc format is typically "Card Name\nSubdevice Name"
                    std::string full_desc(desc_cstr);
                    auto newline_pos = full_desc.find('\n');
                    if (newline_pos != std::string::npos)
                    {
                        info.card_name   = full_desc.substr(0, newline_pos);
                        info.device_name = full_desc.substr(newline_pos + 1);
                    }
                    else
                    {
                        info.card_name   = full_desc;
                        info.device_name = full_desc;
                    }
                }

                result.push_back(info);
            }
        }

        free(name_cstr);
        free(desc_cstr);
        free(ioid_cstr);
    }

    snd_device_name_free_hint(hints);
    LOG_DEBUG("[monitor] list_alsa_capture_devices found %zu capture device(s)", result.size());
    return result;
}


// =============================================================================
// AlsaCapture
// =============================================================================

static constexpr unsigned int AUTO_CAPTURE_RATE_MAX_HZ = 48000;

AlsaCapture::AlsaCapture() = default;

AlsaCapture::~AlsaCapture()
{
    close();
}

bool AlsaCapture::open(const std::string& hw_device, int channels)
{
    if (_pcm)
    {
        LOG_WARN("[alsa] open() called while device already open; closing first");
        close();
    }

    int err;

    err = snd_pcm_open(&_pcm, hw_device.c_str(), SND_PCM_STREAM_CAPTURE, 0);
    if (err < 0)
    {
        LOG_WARN("[alsa] Cannot open device '%s': %s",
                 hw_device.c_str(), snd_strerror(err));
        _pcm = nullptr;
        return false;
    }

    // Allocate hardware parameter space on the stack.
    snd_pcm_hw_params_t* hw_params = nullptr;
    snd_pcm_hw_params_alloca(&hw_params);

    int selected_rate_hz = 0;

    err = snd_pcm_hw_params_any(_pcm, hw_params);
    if (err < 0)
    {
        LOG_WARN("[alsa] Cannot initialise hw_params for '%s': %s",
                 hw_device.c_str(), snd_strerror(err));
        goto fail;
    }

    err = snd_pcm_hw_params_set_access(_pcm, hw_params, SND_PCM_ACCESS_RW_INTERLEAVED);
    if (err < 0)
    {
        LOG_WARN("[alsa] Cannot set interleaved access for '%s': %s",
                 hw_device.c_str(), snd_strerror(err));
        goto fail;
    }

    // Request S32_LE first (24-in-32 / full-32-bit-scale
    // container -- see AudioMonitor::OUTPUT_BITS); many current USB ADCs are
    // 16-bit-only, so fall back to S16_LE on rejection rather than failing
    // open() outright. read() hides the distinction from callers by always
    // widening S16 samples up to the same 32-bit scale a native S32 capture
    // already uses.
    err = snd_pcm_hw_params_set_format(_pcm, hw_params, SND_PCM_FORMAT_S32_LE);
    if (err < 0)
    {
        LOG_INFO("[alsa] S32_LE not supported for '%s' (%s); falling back to S16_LE",
                 hw_device.c_str(), snd_strerror(err));

        err = snd_pcm_hw_params_set_format(_pcm, hw_params, SND_PCM_FORMAT_S16_LE);
        if (err < 0)
        {
            LOG_WARN("[alsa] Cannot set S16_LE format for '%s': %s",
                     hw_device.c_str(), snd_strerror(err));
            goto fail;
        }
        _captured_s32 = false;
    }
    else
    {
        _captured_s32 = true;
    }

    err = snd_pcm_hw_params_set_channels(_pcm, hw_params,
                                          static_cast<unsigned int>(channels));
    if (err < 0)
    {
        LOG_WARN("[alsa] Cannot set %d channels for '%s': %s",
                 channels, hw_device.c_str(), snd_strerror(err));
        goto fail;
    }
    _channels = channels;

    {
        unsigned int rate_max = AUTO_CAPTURE_RATE_MAX_HZ;
        int          dir      = 0;

        // Constrain capture to rates at or below the product ceiling, then
        // choose the highest rate ALSA can satisfy within that range.
        err = snd_pcm_hw_params_set_rate_max(_pcm, hw_params, &rate_max, &dir);
        if (err < 0)
        {
            LOG_WARN("[alsa] No supported capture rate <= %u Hz for '%s'",
                     AUTO_CAPTURE_RATE_MAX_HZ, hw_device.c_str());
            goto fail;
        }

        unsigned int selected_rate = rate_max;
        dir = -1;
        err = snd_pcm_hw_params_set_rate_near(_pcm, hw_params, &selected_rate, &dir);
        if (err < 0)
        {
            LOG_WARN("[alsa] Cannot select capture rate <= %u Hz for '%s': %s",
                     AUTO_CAPTURE_RATE_MAX_HZ, hw_device.c_str(), snd_strerror(err));
            goto fail;
        }

        selected_rate_hz = static_cast<int>(selected_rate);
        _actual_rate     = selected_rate_hz;

        if (_actual_rate <= 0 || _actual_rate > static_cast<int>(AUTO_CAPTURE_RATE_MAX_HZ))
        {
            LOG_WARN("[alsa] Invalid selected capture rate %d Hz for '%s'",
                     _actual_rate, hw_device.c_str());
            goto fail;
        }
    }

    {
        // Request a ~1024-frame period.  This gives ~21 ms latency at 48 kHz
        // which is a good balance between CPU overhead and responsiveness.
        snd_pcm_uframes_t period = 1024;
        err = snd_pcm_hw_params_set_period_size_near(_pcm, hw_params, &period, nullptr);
        if (err < 0)
        {
            LOG_WARN("[alsa] Cannot set period size for '%s': %s",
                     hw_device.c_str(), snd_strerror(err));
            goto fail;
        }
        _period_frames = static_cast<int>(period);
    }

    err = snd_pcm_hw_params(_pcm, hw_params);
    if (err < 0)
    {
        LOG_WARN("[alsa] Cannot apply hw_params for '%s': %s",
                 hw_device.c_str(), snd_strerror(err));
        goto fail;
    }

    err = snd_pcm_prepare(_pcm);
    if (err < 0)
    {
        LOG_WARN("[alsa] Cannot prepare '%s': %s",
                 hw_device.c_str(), snd_strerror(err));
        goto fail;
    }

    LOG_INFO("[alsa] Opened '%s': selected=%d Hz, negotiated=%d Hz, %d ch, %s, period=%d frames",
             hw_device.c_str(), selected_rate_hz, _actual_rate, channels,
             _captured_s32 ? "S32_LE" : "S16_LE (fallback)", _period_frames);
    return true;

fail:
    snd_pcm_close(_pcm);
    _pcm = nullptr;
    _period_frames = 0;
    _actual_rate   = 0;
    return false;
}

void AlsaCapture::close()
{
    // Hold _read_mutex so that close() cannot run concurrently with the
    // body of read() (between the _pcm null-check and snd_pcm_readi).
    // If a read is in progress, close() waits for it to finish (at most one
    // hardware period, ~21 ms) before setting _pcm = nullptr.
    std::lock_guard<std::mutex> lock(_read_mutex);
    if (_pcm)
    {
        snd_pcm_close(_pcm);
        _pcm = nullptr;
    }
    _period_frames = 0;
    _actual_rate   = 0;
    _captured_s32  = false;
}

int AlsaCapture::read(int32_t* buf, int n_frames)
{
    // Hold _read_mutex for the duration of the check + snd_pcm_readi call.
    // This prevents close() from setting _pcm = nullptr between the guard
    // and the actual use of _pcm.  The lock is uncontended in normal
    // operation (only the capture thread calls read()), so the overhead
    // is negligible.
    std::lock_guard<std::mutex> lock(_read_mutex);

    if (!_pcm)
        return -1;

    snd_pcm_sframes_t frames_read;

    if (_captured_s32)
    {
        // Hardware negotiated S32_LE: ALSA already presents samples at the
        // full 32-bit dynamic range this monitor's internal representation
        // uses, so read straight into the caller's
        // buffer with no conversion.
        frames_read = snd_pcm_readi(_pcm, buf, n_frames);
    }
    else
    {
        // Fallback path: hardware only supports S16_LE. Read into a
        // pre-grown scratch buffer, then widen each sample up to the common
        // 32-bit scale by left-shifting 16 bits (int16's full range placed
        // at the top of the 32-bit word) -- the same "left-justify the
        // significant bits" convention a native S32 capture already
        // satisfies, so downstream DSP (which only ever sees the widened
        // int32 stream) cannot tell the two apart.
        //
        // _s16_scratch.resize() only reallocates the first time it is
        // called with a larger n_frames than seen before; period_frames()
        // (and hence n_frames here) does not change during an open session,
        // so this is not a steady-state allocation on the capture thread --
        // the same tolerance InputChannel::capture_thread_func() already
        // relies on for its own period buffer.
        size_t needed = static_cast<size_t>(n_frames) * static_cast<size_t>(_channels);
        if (_s16_scratch.size() < needed)
            _s16_scratch.resize(needed);

        frames_read = snd_pcm_readi(_pcm, _s16_scratch.data(), n_frames);

        if (frames_read > 0)
        {
            size_t n = static_cast<size_t>(frames_read) * static_cast<size_t>(_channels);
            for (size_t i = 0; i < n; ++i)
                buf[i] = widen_s16_to_s32(_s16_scratch[i]);
        }
    }

    if (frames_read >= 0)
        return static_cast<int>(frames_read);

    // Handle recoverable errors (xrun, suspended).
    int err = snd_pcm_recover(_pcm, static_cast<int>(frames_read),
                               /*silent=*/1);
    if (err == 0)
    {
        // Recovered from xrun; the caller should retry rather than treating
        // the zero return as silence.
        return 0;
    }

    LOG_WARN("[alsa] Unrecoverable read error: %s", snd_strerror(err));
    return -1;
}

bool AlsaCapture::captured_as_s32() const
{
    std::lock_guard<std::mutex> lock(_read_mutex);
    return _captured_s32;
}

bool AlsaCapture::is_open() const
{
    std::lock_guard<std::mutex> lock(_read_mutex);
    return _pcm != nullptr;
}

int AlsaCapture::period_frames() const
{
    std::lock_guard<std::mutex> lock(_read_mutex);
    return _period_frames;
}

int AlsaCapture::actual_rate() const
{
    std::lock_guard<std::mutex> lock(_read_mutex);
    return _actual_rate;
}


// =============================================================================
// FifoWriter
// =============================================================================

FifoWriter::FifoWriter() = default;

FifoWriter::~FifoWriter()
{
    close();
}

void FifoWriter::set_path(const std::string& path)
{
    close();
    _path = path;
}

bool FifoWriter::try_open()
{
    if (_path.empty())
        return false;

    // O_NONBLOCK is kept permanently on the fd (never cleared).  This means:
    //   - If OwnTone has not opened its read end yet, open() returns ENXIO and
    //     we return false silently; the caller retries on the next block.
    //   - Once open, if the pipe buffer is full, write() returns EAGAIN rather
    //     than blocking the process thread indefinitely.
    int fd = ::open(_path.c_str(), O_WRONLY | O_NONBLOCK);
    if (fd < 0)
    {
        if (errno != ENXIO && errno != ENOENT)
        {
            LOG_WARN("[fifo] Cannot open '%s': %s",
                     _path.c_str(), strerror(errno));
        }
        return false;
    }

    // Verify the path is actually a named pipe.  O_NONBLOCK lets us open a
    // regular file without blocking, so we must reject it here before we
    // start writing raw PCM into it and silently fill the disk.
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISFIFO(st.st_mode))
    {
        LOG_WARN("[fifo] '%s' is not a named pipe; rejecting", _path.c_str());
        ::close(fd);
        return false;
    }

    _fd = fd;
    LOG_INFO("[fifo] Opened '%s' for writing", _path.c_str());
    return true;
}

bool FifoWriter::write(const void* data, size_t len)
{
    bool ok = write_impl(data, len);

    // Cheap stall tracking for get_status()'s top-level
    // "fifo.stalled_seconds" (single relaxed atomic; no new locks on this
    // hot path -- see the member's doc comment). Every call here is already
    // an attempt by an active writer (the caller only calls write() when it
    // actually has data to deliver), so a false return is unambiguously a
    // dropped/failed write, and a true return unambiguously clears any
    // in-progress stall streak.
    if (ok)
    {
        _stall_since.store(0.0, std::memory_order_relaxed);
    }
    else if (_stall_since.load(std::memory_order_relaxed) == 0.0)
    {
        _stall_since.store(get_monotonic_time(), std::memory_order_relaxed);
    }

    return ok;
}

bool FifoWriter::write_impl(const void* data, size_t len)
{
    if (_fd < 0)
    {
        // Not yet open — try to open now.  If this fails (OwnTone not ready),
        // silently discard the data and wait for the next call.
        if (!try_open())
            return false;
    }

    const char* ptr     = static_cast<const char*>(data);
    size_t      written = 0;

    while (written < len)
    {
        ssize_t n = ::write(_fd, ptr + written, len - written);
        if (n > 0)
        {
            written += static_cast<size_t>(n);
        }
        else if (n == 0)
        {
            break;
        }
        else
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                if (written > 0)
                {
                    // A partial block was already written before the pipe
                    // buffer filled.  The PCM frame boundary is now lost.
                    // Close the fd so the next write() call reopens it from
                    // the beginning, giving OwnTone a chance to re-sync.
                    LOG_WARN("[fifo] Partial write on '%s' (%zu/%zu bytes); closing to re-sync stream",
                             _path.c_str(), written, len);
                    close();
                }
                else
                {
                    // Pipe buffer full before any bytes written — safe to
                    // drop the whole block.  Throttle to once per 5 seconds.
                    double now = get_monotonic_time();
                    if (now - _stall_last_log_time >= 5.0)
                    {
                        LOG_WARN("[fifo] Pipe buffer full on '%s'; dropping block",
                                 _path.c_str());
                        _stall_last_log_time = now;
                    }
                }
                return false;
            }
            else if (errno == EPIPE || errno == EBADF)
            {
                // OwnTone has closed its read end.  Close our fd so try_open()
                // will reopen it on the next write attempt.
                LOG_WARN("[fifo] Broken pipe on '%s'; will reopen on next write",
                         _path.c_str());
                close();
            }
            else
            {
                LOG_WARN("[fifo] Write error on '%s': %s",
                         _path.c_str(), strerror(errno));
            }
            return false;
        }
    }

    return written == len;
}

void FifoWriter::close()
{
    if (_fd >= 0)
    {
        ::close(_fd);
        _fd = -1;
    }
}


// =============================================================================
// OutputDumpWriter
// =============================================================================

// Placeholder WAV header written at start(); sizes patched to final values
// at stop() (see patch_u32() there). Built from
// AudioMonitor::OUTPUT_RATE/OUTPUT_BITS/OUTPUT_CHANNELS via the shared
// build_wav_header() helper (autostream_monitor_utils.{h,cpp}) instead of a
// hardcoded 44.1 kHz/16-bit byte array, so it can never drift from the
// format the ring/submit_block()/writer thread above actually move.
//
// Container choice: WAVE_FORMAT_PCM with a 32-bit integer container (not
// IEEE float, not a narrowing 32->16 down-convert). The samples reaching
// submit_block() are already full-scale 32-bit integers (24-in-32, per
// the monitor's capture/FIFO convention) by the time they get here, so a
// 32-bit PCM container is a byte-for-byte tap of the exact wire format with
// zero extra conversion work on the hot path -- matching the "widen the tap
// to match _pcm_out exactly" choice already made for the ring itself.

OutputDumpWriter::OutputDumpWriter()
{
}

OutputDumpWriter::~OutputDumpWriter()
{
    stop();
}

std::string OutputDumpWriter::start(const std::string& path, bool overwrite)
{
    std::lock_guard<std::mutex> lock(_mutex);

    if (_active.load(std::memory_order_relaxed))
        return "dump already active; call stop_output_dump first";

    // Open the output file.  Use POSIX open() so we can pass O_EXCL for
    // non-overwrite mode, then wrap with fdopen() for stdio buffering.
    int flags = O_WRONLY | O_CREAT | (overwrite ? O_TRUNC : O_EXCL);
    int fd = ::open(path.c_str(), flags, 0644);
    if (fd < 0)
        return std::string("failed to open output file: ") + strerror(errno);

    FILE* f = fdopen(fd, "wb");
    if (!f)
    {
        int saved = errno;
        ::close(fd);
        return std::string("fdopen failed: ") + strerror(saved);
    }

    // Write placeholder header (data_bytes=0); sizes are patched in stop().
    // bits is a hardcoded 32, NOT AudioMonitor::output_bits_per_sample()
    // -- the dump is always a 32-bit container regardless of wire mode; see
    // the class comment above.
    std::array<uint8_t, 44> header = build_wav_header(
        AudioMonitor::output_rate_hz(),
        32,
        AudioMonitor::output_channels());
    if (fwrite(header.data(), 1, header.size(), f) != header.size())
    {
        fclose(f);
        return "failed to write WAV header";
    }

    // Initialise ring and counters before setting _active so submit_block()
    // cannot observe a stale read position.
    _file    = f;
    _path    = path;
    _ring.reset();
    _frames_written.store(0, std::memory_order_relaxed);
    _dropped_frames.store(0, std::memory_order_relaxed);
    _stop_requested.store(false, std::memory_order_relaxed);

    // Release store: makes the ring initialisation visible to the writer thread
    // before it observes _active = true via any subsequent acquire load.
    _active.store(true, std::memory_order_release);

    _writer_thread = std::thread(&OutputDumpWriter::writer_thread_func, this);

    LOG_INFO("[dump] Recording started: path='%s'", path.c_str());
    return "";
}

void OutputDumpWriter::stop(bool* was_active_out)
{
    std::lock_guard<std::mutex> lock(_mutex);

    if (!_active.load(std::memory_order_relaxed))
    {
        if (was_active_out) *was_active_out = false;
        return;
    }

    // Clear _active first so the audio thread stops submitting new frames as
    // soon as possible.  _stop_requested then signals the writer thread to
    // drain whatever remains in the ring and exit.
    _active.store(false, std::memory_order_release);
    _stop_requested.store(true, std::memory_order_release);
    _cv.notify_all();

    if (_writer_thread.joinable())
        _writer_thread.join();

    // Patch WAV header with final data sizes.
    if (_file)
    {
        uint64_t frames       = _frames_written.load(std::memory_order_relaxed);
        // frames * bytes/frame. Deliberately a FIXED 8 bytes/frame
        // (AudioMonitor::output_channels() * sizeof(int32_t)), NOT
        // AudioMonitor::output_bytes_per_frame() -- that descriptor varies
        // with wire mode (4 in compatible) and would under-report this
        // always-32-bit dump's data size by half. _frames_written itself
        // already counts frames actually fwritten as int32 (see
        // writer_thread_func()'s "written / 2u" below), so this stays a
        // correct byte count in both output modes.
        uint64_t data_bytes64 = frames * static_cast<uint64_t>(AudioMonitor::output_channels()) * sizeof(int32_t);

        // Clamp to uint32 max — the WAV data chunk is limited to ~4 GB
        // (~6.7 hours at 176400 bytes/s), which is far beyond engineering use.
        uint32_t data_bytes = (data_bytes64 > 0xFFFFFFFFull)
                              ? 0xFFFFFFFFu
                              : static_cast<uint32_t>(data_bytes64);
        uint32_t riff_size  = (data_bytes <= 0xFFFFFFFFu - 36u)
                              ? 36u + data_bytes
                              : 0xFFFFFFFFu;

        auto patch_u32 = [this](long offset, uint32_t val)
        {
            uint8_t b[4] = {
                static_cast<uint8_t>(val),
                static_cast<uint8_t>(val >>  8),
                static_cast<uint8_t>(val >> 16),
                static_cast<uint8_t>(val >> 24)
            };
            fseek(_file, offset, SEEK_SET);
            fwrite(b, 1, 4, _file);
        };

        patch_u32(4,  riff_size);   // RIFF chunk size at offset 4
        patch_u32(40, data_bytes);  // data chunk size at offset 40

        fflush(_file);
        fclose(_file);
        _file = nullptr;
    }

    LOG_INFO("[dump] Recording stopped: path='%s', frames=%llu, dropped=%llu",
             _path.c_str(),
             static_cast<unsigned long long>(_frames_written.load(std::memory_order_relaxed)),
             static_cast<unsigned long long>(_dropped_frames.load(std::memory_order_relaxed)));

    if (was_active_out) *was_active_out = true;
}

void OutputDumpWriter::submit_block(const int32_t* samples, int out_frames)
{
    if (!_active.load(std::memory_order_relaxed))
        return;

    size_t n_samples = static_cast<size_t>(out_frames) * 2u;

    // Check ring space; drop and count the whole block if it doesn't fit
    // rather than partially writing it.
    if (n_samples > _ring.write_available())
    {
        _dropped_frames.fetch_add(static_cast<uint64_t>(out_frames),
                                   std::memory_order_relaxed);
        return;
    }

    _ring.write(samples, n_samples);

    // Wake the writer thread.  notify_one() is safe without holding _cv_mutex
    // (same pattern as InputChannel::capture_thread_func → _ring_cv.notify_one()).
    _cv.notify_one();
}

void OutputDumpWriter::writer_thread_func()
{
    while (true)
    {
        // Sleep until data is available or a stop is requested.
        // The 20 ms timeout catches any notify_one() fired between the
        // predicate check and the wait_for() entry.
        {
            std::unique_lock<std::mutex> lk(_cv_mutex);
            _cv.wait_for(lk, std::chrono::milliseconds(20),
                [this]()
                {
                    return _ring.read_available() > 0
                        || _stop_requested.load(std::memory_order_relaxed);
                });
        }

        // Drain all available samples to disk.
        size_t avail = _ring.read_available();

        if (avail > 0)
        {
            // read() into a pre-sized scratch buffer, then fwrite it. This is
            // one memcpy more than a hand-rolled version that fwrote directly
            // from the two ring segments would need, but that's an acceptable
            // trade to share the SpscRing<T> read(T*, size_t) API -- this
            // thread is a background disk writer, not on the live FIFO/audio
            // hot path.
            _ring.read(_read_scratch.data(), avail);

            bool write_ok = true;
            // sizeof(int32_t) -- see submit_block()'s comment on the
            // dump ring's widened element type.
            size_t written = fwrite(_read_scratch.data(),
                                    sizeof(int32_t), avail, _file);
            if (written < avail)
                write_ok = false;

            // `written` is in samples (int32); stereo frames = samples / 2.
            _frames_written.fetch_add(written / 2u, std::memory_order_relaxed);

            if (!write_ok)
            {
                LOG_WARN("[dump] Write error; aborting dump recording");
                break;
            }
        }

        // Exit only after stop has been requested and the ring is fully drained.
        if (_stop_requested.load(std::memory_order_relaxed))
        {
            if (_ring.read_available() == 0)
                break;
        }
    }
}

OutputDumpWriter::Status OutputDumpWriter::get_status() const
{
    Status s;
    s.active         = _active.load(std::memory_order_relaxed);
    s.frames_written = _frames_written.load(std::memory_order_relaxed);
    s.dropped_frames = _dropped_frames.load(std::memory_order_relaxed);
    {
        std::lock_guard<std::mutex> lock(_mutex);
        s.path = _path;
    }
    return s;
}


// =============================================================================
// InputChannel
// =============================================================================

// dbfs_to_linear_threshold()/linear_to_dbfs(): float-domain dBFS<->linear
// conversions used throughout this file (silence threshold at configure()
// time, and the level/peak dBFS fields in get_status()). Moved to
// autostream_monitor_utils.{h,cpp} so they are linkable from a test binary
// that doesn't pull in ALSA/libsamplerate; this is the float-domain version
// that eliminated the old 32767/32768 int16-scale constants. See
// autostream_monitor_utils.h for the declarations.

InputChannel::InputChannel(int               index,
                           FifoWriter&       shared_fifo,
                           std::mutex&       fifo_mutex,
                           OutputProcessor&  output_processor,
                           OutputDumpWriter& dump_writer,
                           RepeatController& repeat_controller)
    : _index(index)
    , _shared_fifo(shared_fifo)
    , _fifo_mutex(fifo_mutex)
    , _output_processor(output_processor)
    , _dump_writer(dump_writer)
    , _repeat_controller(repeat_controller)
{
    _status.index = index;
}

InputChannel::~InputChannel()
{
    stop();
}

bool InputChannel::configure(const InputConfig& cfg)
{
    std::lock_guard<std::mutex> lock(_config_mutex);

    if (_running.load() && _config_valid)
    {
        // The channel is already running.  Changing alsa_device requires a
        // stop/start cycle because it is used only at open() time.  Reject
        // the call rather than silently ignoring part of it.
        if (cfg.alsa_device != _config.alsa_device)
        {
            LOG_WARN("[input%d] configure() rejected: stop the input before changing device",
                     _index);
            return false;
        }
    }

    _config                   = cfg;
    _config_valid             = true;
    _silence_threshold_sample.store(dbfs_to_linear_threshold(cfg.silence_threshold_dbfs),
                                    std::memory_order_relaxed);
    LOG_INFO("[input%d] Configured device='%s', silence_threshold=%.1f dBFS, silence_seconds=%d",
             _index, cfg.alsa_device.c_str(), cfg.silence_threshold_dbfs, cfg.silence_seconds);
    return true;
}

void InputChannel::set_eq(const std::vector<EqBand>& bands)
{
    // EQ operates on the resampled output, so the sample rate is always the
    // fixed output rate.  The process thread picks up the change lazily.
    _eq_chain.set_bands(bands, static_cast<float>(AudioMonitor::output_rate_hz()));
    LOG_DEBUG("[input%d] Applied %zu EQ band(s)", _index, bands.size());
}

void InputChannel::set_gain(float gain_db)
{
    // Convert once from dB to linear here so the process thread only needs
    // a single multiply per sample; no pow() on the hot path.
    float linear = std::pow(10.0f, gain_db / 20.0f);
    _gain_linear.store(linear, std::memory_order_relaxed);
    LOG_DEBUG("[input%d] Gain set to %.2f dB", _index, gain_db);
}

bool InputChannel::start(std::string* error_out)
{
    if (_running.load())
    {
        LOG_WARN("[input%d] start() called while already running", _index);
        if (error_out)
            *error_out = "input is already running";
        return false;
    }

    // Read and validate configuration under the lock.
    InputConfig cfg;
    {
        std::lock_guard<std::mutex> lock(_config_mutex);
        if (!_config_valid)
        {
            LOG_WARN("[input%d] start() called before configure()", _index);
            if (error_out)
                *error_out = "input is not configured";
            return false;
        }
        cfg = _config;
    }

    // Open the ALSA device.
    if (!_alsa.open(cfg.alsa_device, /*channels=*/2))
    {
        LOG_WARN("[input%d] Failed to open ALSA device '%s'",
                 _index, cfg.alsa_device.c_str());
        if (error_out)
            *error_out = "failed to open ALSA device";
        return false;
    }

    // Create a libsamplerate state for the main stereo output conversion.
    // SRC_SINC_FASTEST provides good quality with moderate CPU usage.
    // On a Pi Zero, SRC_LINEAR can be substituted if CPU becomes a bottleneck.
    int src_error = 0;
    _src_state = src_new(SRC_SINC_FASTEST, /*channels=*/2, &src_error);
    if (!_src_state)
    {
        LOG_WARN("[input%d] src_new failed: %s",
                 _index, src_strerror(src_error));
        _alsa.close();
        if (error_out)
            *error_out = "failed to initialise sample-rate converter";
        return false;
    }

    // Create the 48000 → 16000 Hz ID-tap resampler (shared, filtered
    // SRC_SINC_FASTEST helper -- see autostream_id_tap.h). MAX_SRC_OUTPUT
    // (process_thread_func()'s local constant, 4096) is the largest block
    // the process thread will ever hand it, so that is what pre-sizes its
    // scratch.
    _id_tap = std::make_unique<IdTapResampler>(
        AudioMonitor::output_rate_hz(), static_cast<int>(ID_BUF_RATE), 4096);
    if (!_id_tap->valid())
    {
        LOG_WARN("[input%d] src_new (ID tap) failed", _index);
        src_delete(_src_state);
        _src_state = nullptr;
        _id_tap.reset();
        _alsa.close();
        if (error_out)
            *error_out = "failed to initialise ID sample-rate converter";
        return false;
    }

    // Seed the rate estimator with the rate ALSA actually negotiated rather
    // than the nominal target rate. This keeps the first plausibility check in
    // RateEstimator::feed() anchored to the real device rate.
    _rate_estimator.reset(_alsa.actual_rate(), AudioMonitor::output_rate_hz());

    // Reset silence tracking and capture-thread private state.
    _last_above_threshold_time   = 0.0;
    _ring_overflow_last_log_time = 0.0;

    // Ensure the ramp starts fresh; it will be armed when the first capture
    // session begins inside process_thread_func().
    _ramp_frames_remaining = 0;

    // Reset per-channel EQ state.  Setting _current_eq_bands to nullptr forces
    // process_thread_func() to rebuild _local_filters from scratch on the first
    // block, ensuring the new session starts with zeroed delay-line state.
    _local_filters.clear();
    _current_eq_bands.reset();

    // Reset session peak accumulators so the new session starts from scratch.
    _poll_peak_sample.store(0,            std::memory_order_relaxed);
    _session_raw_peak_sample.store(0,     std::memory_order_relaxed);
    _session_effective_peak_linear.store(0.0f, std::memory_order_relaxed);

    // Clear ring buffer.
    _ring_buf.reset();

    // Allocate and reset the identification snapshot buffer.
    // Done here rather than in the constructor so the ~1 MB allocation only
    // happens if the channel is ever started.
    {
        std::lock_guard<std::mutex> lock(_id_mutex);
        if (_id_buf.empty())
            _id_buf.resize(ID_BUF_FRAMES);
        _id_write_pos    = 0;
        _id_frames_avail = 0;
    }

    // Reset the VU history ring so the new session starts with a clean
    // sequence.  The process-thread-only fields are written here before
    // the thread is spawned, so no lock is required for those.
    {
        std::lock_guard<std::mutex> lk(_vu_history_mutex);
        _vu_history_count     = 0;
        _vu_history_write_idx = 0;
    }
    _vu_bin_seq         = 0;
    _vu_bin_left_peak   = 0.0f;
    _vu_bin_right_peak  = 0.0f;
    _vu_bin_start_time  = 0.0;   // initialised to real time at start of process_thread_func

    // Set _started before spawning threads.  stop() guards on
    // _started.exchange(false), so setting it first ensures that any
    // concurrent stop() call after this point always performs full cleanup —
    // including joining the threads we are about to create.  If stop() wins
    // the exchange before the threads exist, the joinable() checks make the
    // joins harmless no-ops.
    _started.store(true);
    _running.store(true);

    try
    {
        _capture_thr = std::thread(&InputChannel::capture_thread_func, this);
        _process_thr = std::thread(&InputChannel::process_thread_func, this);
    }
    catch (const std::system_error& e)
    {
        // Thread creation failed (e.g. EAGAIN under resource pressure).
        // Signal any thread that did start to exit, join it, then undo the
        // flags so the channel is left in a clean stopped state.
        _running.store(false);
        _alsa.close();              // unblocks a blocked snd_pcm_readi()
        if (_capture_thr.joinable())
            _capture_thr.join();
        // _process_thr is not joinable if its construction was what threw.
        if (_src_state)
        {
            src_delete(_src_state);
            _src_state = nullptr;
        }
        _id_tap.reset();
        _started.store(false);
        LOG_WARN("[input%d] Thread creation failed: %s", _index, e.what());
        if (error_out)
            *error_out = std::string("thread creation failed: ") + e.what();
        return false;
    }

    LOG_INFO("[input%d] Started on device '%s' at %d Hz (auto-selected <= %u Hz)",
             _index, cfg.alsa_device.c_str(), _alsa.actual_rate(), AUTO_CAPTURE_RATE_MAX_HZ);
    return true;
}

void InputChannel::stop()
{
    // Guard on _started, not _running.  The capture thread may have already
    // stored _running = false (after an unrecoverable ALSA error) and exited,
    // leaving _capture_thr and _process_thr joinable and _src_state allocated.
    // Using _started.exchange(false) ensures stop() runs exactly once and
    // always performs the full cleanup regardless of how _running got cleared.
    if (!_started.exchange(false))
        return;

    // Signal the process thread to exit (the capture thread may have already
    // cleared this after an ALSA error, but a redundant store is harmless).
    _running.store(false);

    // Wake the process thread immediately so it does not wait out its condvar
    // timeout after _running is cleared.
    _ring_cv.notify_all();

    // Close the ALSA device to unblock any snd_pcm_readi() in progress.
    // AlsaCapture::close() holds _read_mutex, so it either runs before the
    // next read() call or waits for the current one to finish (at most ~21 ms).
    _alsa.close();

    if (_capture_thr.joinable())
        _capture_thr.join();
    if (_process_thr.joinable())
        _process_thr.join();

    if (_src_state)
    {
        src_delete(_src_state);
        _src_state = nullptr;
    }
    _id_tap.reset();

    _capturing.store(false);
    _current_peak_sample.store(0, std::memory_order_relaxed);
    _poll_peak_sample.store(0, std::memory_order_relaxed);
    _session_raw_peak_sample.store(0, std::memory_order_relaxed);
    _session_effective_peak_linear.store(0.0f, std::memory_order_relaxed);
    _track_change_seq.store(0, std::memory_order_relaxed);
    _track_gap_detector.reset();

    {
        std::lock_guard<std::mutex> lock(_status_mutex);
        _status.is_silent       = true;
        _status.is_capturing    = false;
        _status.detected_hz     = 0.0;
        _status.track_change_seq = 0;
    }

    // Do NOT reset _id_write_pos or _id_frames_avail here.  The snapshot
    // buffer retains the final audio so a get_id_snapshot request issued
    // immediately after stop() still returns valid data.  start() resets
    // both counters to 0 before the next capture session begins.

    LOG_INFO("[input%d] Stopped", _index);
}

void InputChannel::set_allow_capture(bool allow)
{
    _allow_capture.store(allow);
    LOG_DEBUG("[input%d] allow_capture=%s", _index, allow ? "true" : "false");
}

InputChannelStatus InputChannel::get_status() const
{
    // All log10 conversions happen here, not in the hot path.
    // get_status() is called ~10 times/second so the cost is negligible.
    InputChannelStatus s;
    {
        std::lock_guard<std::mutex> lock(_status_mutex);
        s = _status;
    }
    // _current_peak_sample/_poll_peak_sample/_session_raw_peak_sample
    // are now linear amplitudes in [0.0, 1.0] (see compute_peak_sample()'s
    // comment), so linear_to_dbfs() -- already used for effective peak below
    // -- converts them directly; the separate sample_to_dbfs() int16-scale
    // helper is gone.
    s.level_dbfs             = linear_to_dbfs(_current_peak_sample.load(std::memory_order_relaxed));
    s.poll_peak_dbfs         = linear_to_dbfs(_poll_peak_sample.exchange(0.0f, std::memory_order_relaxed));
    s.raw_peak_dbfs          = linear_to_dbfs(_session_raw_peak_sample.load(std::memory_order_relaxed));
    s.effective_peak_dbfs    = linear_to_dbfs(_session_effective_peak_linear.load(std::memory_order_relaxed));
    s.is_started             = _started.load(std::memory_order_relaxed);
    s.is_running             = _running.load(std::memory_order_relaxed);
    return s;
}

float InputChannel::compute_peak_sample(const int32_t* samples,
                                         int            n_frames,
                                         int            n_channels) const
{
    // Integer scan (int64_t accumulator -- abs(INT32_MIN) does not fit in
    // int32_t, unlike an int16 accumulator where abs of the most negative
    // value fits comfortably in an int), one float divide at
    // the very end to normalise against the full 32-bit scale. samples are
    // assumed already in the monitor's common 32-bit internal representation
    // (see AlsaCapture::read()'s comment), so this is correct regardless of
    // whether the hardware actually negotiated S32_LE or S16_LE-widened.
    int64_t peak = 0;
    for (int frame = 0; frame < n_frames; ++frame)
    {
        for (int ch = 0; ch < n_channels; ++ch)
        {
            int64_t sample     = samples[frame * n_channels + ch];
            int64_t abs_sample = (sample < 0) ? -sample : sample;
            if (abs_sample > peak)
                peak = abs_sample;
        }
    }
    return static_cast<float>(peak) / 2147483648.0f;  // 2^31, full int32 scale
}

unsigned InputChannel::get_id_snapshot(int16_t* out, unsigned max_frames) const
{
    std::lock_guard<std::mutex> lock(_id_mutex);

    if (_id_buf.empty())
        return 0;

    unsigned avail = std::min(_id_frames_avail, max_frames);
    if (avail == 0)
        return 0;

    // The most recent `avail` frames end at _id_write_pos.
    // Walking backwards: start = (_id_write_pos - avail), masked.
    unsigned start  = (_id_write_pos - avail) & ID_BUF_MASK;
    unsigned to_end = ID_BUF_FRAMES - start;

    if (avail <= to_end)
    {
        memcpy(out, _id_buf.data() + start, avail * sizeof(int16_t));
    }
    else
    {
        // Copy wraps around the end of the circular buffer.
        memcpy(out,           _id_buf.data() + start, to_end           * sizeof(int16_t));
        memcpy(out + to_end,  _id_buf.data(),          (avail - to_end) * sizeof(int16_t));
    }

    return avail;
}


// ── Capture thread ────────────────────────────────────────────────────────────
//
// Reads hardware periods from ALSA and writes interleaved stereo samples,
// in the monitor's common 32-bit internal representation (widened from
// int16_t; AlsaCapture::read() itself hides whether the hardware
// actually negotiated S32_LE or fell back to S16_LE), into the ring buffer.
// This thread runs at close to real time and should do as little work as
// possible to avoid causing ALSA xruns.
//
void InputChannel::capture_thread_func()
{
    // Size the local read buffer to one hardware period.
    // We re-read the period size after open; it will not change during a session.
    std::vector<int32_t> period_buf;

    while (_running.load(std::memory_order_relaxed))
    {
        if (!_alsa.is_open())
        {
            // The ALSA device was closed (probably by stop()).
            break;
        }

        // Ensure the buffer is sized to the negotiated period.
        int period = _alsa.period_frames();
        if (period <= 0)
            break;

        if (static_cast<int>(period_buf.size()) != period * 2)
            period_buf.resize(period * 2);

        int frames_read = _alsa.read(period_buf.data(), period);

        // Test-only (--test-hooks): debug_inject_capture_failure() arms this
        // flag from the control thread. Consuming it here (check-and-clear,
        // once per iteration) and forcing frames_read negative routes
        // through EXACTLY the same unrecoverable-error exit path below as a
        // genuine ALSA failure -- from this point on there is no difference
        // between an injected and a real failure.
        if (_debug_fail_injected.exchange(false, std::memory_order_relaxed))
        {
            LOG_WARN("[input%d] [test-hooks] injected capture failure", _index);
            frames_read = -1;
        }

        if (frames_read < 0)
        {
            // Unrecoverable ALSA error; stop the capture session.
            LOG_WARN("[input%d] ALSA read error; stopping capture thread", _index);
            _running.store(false);
            break;
        }

        if (frames_read == 0)
        {
            // Recovered from xrun; skip this period to let the hardware re-sync.
            continue;
        }

        size_t samples_to_write = static_cast<size_t>(frames_read) * 2;  // stereo

        // Check that there is space in the ring buffer.  If the process thread
        // is falling behind, we drop this incoming period rather than
        // blocking, which would cause an ALSA xrun.
        if (samples_to_write > _ring_buf.write_available())
        {
            // Ring buffer is full — the process thread is falling behind.
            // Drop this incoming period rather than advancing the read
            // position from the capture thread.  The read position must only
            // be written by the process thread to preserve the SPSC
            // invariant; the capture thread writing it (even atomically) can
            // race with the process thread's store and silently corrupt the
            // read position.
            // Throttle the log to once every 5 seconds to avoid log spam
            // under sustained CPU load.
            {
                double now = get_monotonic_time();
                if (now - _ring_overflow_last_log_time >= 5.0)
                {
                    LOG_WARN("[input%d] Ring buffer full; dropping periods", _index);
                    _ring_overflow_last_log_time = now;
                }
            }
            continue;
        }

        _ring_buf.write(period_buf.data(), samples_to_write);

        // Wake the process thread if it is waiting for data.  notify_one() is
        // called without holding _ring_cv_mutex; this is safe — if the process
        // thread is between its availability check and its wait_for call, the
        // predicate will find enough data on the next evaluation.
        _ring_cv.notify_one();

        // Feed the rate estimator now, while we know exactly how many frames
        // the hardware delivered and at what wall-clock time.
        _rate_estimator.feed(frames_read, get_monotonic_time());
    }
}

// ── Process thread ────────────────────────────────────────────────────────────
//
// Drains the ring buffer, measures the audio level, runs the silence state
// machine, and when capturing is active: resamples via libsamplerate, applies
// the EQ chain, and writes the result to the shared FIFO.
//
void InputChannel::process_thread_func()
{
    // Pre-size processing scratch buffers (promoted from locals to members --
    // see the members' declaration comment in autostream_monitor.h for why
    // this introduces no new allocation). Sized once here, at thread entry,
    // exactly like the local std::vectors they replaced.
    _pcm_in.resize(static_cast<size_t>(MAX_FRAMES) * 2);           // interleaved int32
    _float_in.resize(static_cast<size_t>(MAX_FRAMES) * 2);         // interleaved float
    _float_out.resize(static_cast<size_t>(MAX_SRC_OUTPUT) * 2);    // post-SRC float
    _pcm_out.resize(static_cast<size_t>(MAX_SRC_OUTPUT) * 2);      // final int32
    // ID-tap scratch (downmix, resample, clamp) lives inside _id_tap
    // (IdTapResampler) -- pre-sized in start() from this same MAX_SRC_OUTPUT
    // bound.

    // Duration of the fade-in ramp in output frames (one second at 48000 Hz).
    _ramp_duration_frames = AudioMonitor::output_rate_hz();

    // Number of output frames to accumulate before the first FIFO write.
    // 0.5 s at 48000 Hz = 24000 frames = ~188 KB of int32 stereo data.
    // This gives OwnTone a full initial buffer so it can start streaming
    // without the starvation-induced skips that occur when the pipe is
    // cold and the first few writes are each only a single period (~1024 frames).
    _prefill_duration_frames = AudioMonitor::output_rate_hz() / 2;

    // Anchor the first VU bin to the moment the process thread starts.
    _vu_bin_start_time = get_monotonic_time();

    // Periodic (30 s) buffer/drift diagnostics for the cumulative-dropout hunt.
    // Comparing SRC input vs output frame rates over time reveals whether the
    // drift-compensated FIFO output stays locked to the nominal output rate
    // across long playback, or slowly walks off (the suspected dropout cause).
    _stats_last_log_time = get_monotonic_time();
    _stats_in_frames     = 0;   // SRC input frames consumed since last log
    _stats_out_frames    = 0;   // SRC output frames produced since last log

    while (_running.load(std::memory_order_relaxed))
    {
        // ── Periodic buffer/drift diagnostics (every 30 s) ───────────────────
        // Kept inline here (not extracted into one of the named stage methods
        // below) because it is a housekeeping concern independent of any
        // single stage: it must run unconditionally, every iteration, before
        // the ring-drain wait/continue, exactly like today. Its accumulators
        // (_stats_in_frames/_stats_out_frames) are members because
        // resample_block() -- a separate method -- adds to them on every
        // src_process() call; this block only reads and periodically resets
        // them.
        {
            double stats_now = get_monotonic_time();
            double stats_dt  = stats_now - _stats_last_log_time;
            if (stats_dt >= 30.0)
            {
                double nominal_out = static_cast<double>(AudioMonitor::output_rate_hz());
                double out_rate    = _stats_out_frames / stats_dt;
                double in_rate     = _stats_in_frames  / stats_dt;
                double out_dev     = out_rate - nominal_out;
                if (out_dev < 0.0) out_dev = -out_dev;

                // The drift-compensated output should stay locked to nominal_out.
                // A short source-silence gap is passed through as silence at the
                // nominal rate, so it does NOT trip this; only a real stall/runaway
                // (capture gating on long silence, resampler fault) pushes the
                // window rate >0.5% off nominal. Routine lines stay at DEBUG;
                // a deviation escalates to WARN so it stands out in the log.
                // Guard on stats_out_frames > 0 so an idle/stopped window (nothing
                // playing, out=0) is NOT a fault and stays at DEBUG; a capture-stop
                // that lands mid-window still emits partial output and is caught.
                if (_stats_out_frames > 0 && out_dev > 0.005 * nominal_out)
                    LOG_WARN("[stats] input%d est_in=%.2fHz ratio=%.6f in=%.1ff/s out=%.1ff/s nominal_out=%.0f over %.1fs  <-- OUT RATE OFF NOMINAL",
                             _index, _rate_estimator.estimated_input_rate(), _rate_estimator.src_ratio(),
                             in_rate, out_rate, nominal_out, stats_dt);
                else
                    LOG_DEBUG("[stats] input%d est_in=%.2fHz ratio=%.6f in=%.1ff/s out=%.1ff/s nominal_out=%.0f over %.1fs",
                              _index, _rate_estimator.estimated_input_rate(), _rate_estimator.src_ratio(),
                              in_rate, out_rate, nominal_out, stats_dt);

                _stats_in_frames     = 0;
                _stats_out_frames    = 0;
                _stats_last_log_time = stats_now;
            }
        }

        // Runs unconditionally, every iteration (including idle iterations
        // that are about to `continue` below) -- see close_elapsed_vu_bins().
        close_elapsed_vu_bins();

        // ── Wait for / read a block from the ring buffer ──────────────────────
        int frames_in = 0;
        if (!drain_capture_ring(frames_in))
            continue;

        // ── Peak-level metering for the block just read ───────────────────────
        // Linear amplitude in [0.0, 1.0], not an int16-scale sample
        // count -- see compute_peak_sample()'s comment.
        float peak_sample = update_metering(frames_in);

        // ── Silence state machine ─────────────────────────────────────────────
        double now = get_monotonic_time();
        float silence_threshold_sample = 0.0f;
        bool  is_above_threshold = false;
        float track_change_silence_seconds = 0.0f;
        bool should_capture = update_silence_state(peak_sample, now,
                                                     silence_threshold_sample,
                                                     is_above_threshold,
                                                     track_change_silence_seconds);

        // ── Capture session start/stop transitions + track-gap detection ─────
        handle_session_edges(should_capture, peak_sample, silence_threshold_sample,
                              now, track_change_silence_seconds);

        // ── Feed through SRC → EQ → FIFO when capturing ──────────────────────
        if (_capturing.load() && _src_state)
            resample_block(frames_in, peak_sample, silence_threshold_sample);

        // ── Update the status snapshot ────────────────────────────────────────
        // level_dbfs is intentionally omitted here; get_status() converts
        // _current_peak_sample to dBFS at read time to keep log10 off this path.
        {
            std::lock_guard<std::mutex> lock(_status_mutex);
            _status.is_silent       = !is_above_threshold;
            _status.is_capturing    = _capturing.load();
            _status.detected_hz     = _rate_estimator.estimated_input_rate();
            _status.track_change_seq = _track_change_seq.load(std::memory_order_relaxed);
        }
    }
}


// ── InputChannel::close_elapsed_vu_bins ───────────────────────────────────────
//
// Runs every process_thread_func() iteration (including idle iterations after
// the condition-variable sleep) so silence bins are produced even when the
// channel is not capturing.  A while loop catches up if multiple bins have
// elapsed since the last iteration (e.g. after a long OS sleep).
//
void InputChannel::close_elapsed_vu_bins()
{
    double now = get_monotonic_time();
    while (now - _vu_bin_start_time >= VU_BIN_SECONDS)
    {
        VuBin bin;
        bin.seq        = ++_vu_bin_seq;
        bin.left_dbfs  = linear_to_dbfs(_vu_bin_left_peak);
        bin.right_dbfs = linear_to_dbfs(_vu_bin_right_peak);
        _vu_bin_left_peak  = 0.0f;
        _vu_bin_right_peak = 0.0f;
        _vu_bin_start_time += VU_BIN_SECONDS;

        std::lock_guard<std::mutex> lk(_vu_history_mutex);
        _vu_history[_vu_history_write_idx] = bin;
        _vu_history_write_idx = (_vu_history_write_idx + 1) % VU_HISTORY_BINS;
        if (_vu_history_count < VU_HISTORY_BINS)
            ++_vu_history_count;
    }
}


// ── InputChannel::drain_capture_ring ──────────────────────────────────────────
//
// Waits (bounded, 5 ms) for at least MIN_SAMPLES to become available in
// _ring_buf and, once available, reads one block into _pcm_in. Returns false
// (having already performed the bounded wait) when the caller should
// `continue` its loop without processing a block this iteration; true with
// frames_in set to the number of stereo frames read otherwise.
//
bool InputChannel::drain_capture_ring(int& frames_in)
{
    // ── Wait for data ────────────────────────────────────────────────────
    size_t available = _ring_buf.read_available();

    if (available < MIN_SAMPLES)
    {
        // Sleep until the capture thread signals new data or up to 5 ms
        // (the timeout handles the case where notify_one() was called just
        // before we entered wait_for — at most one missed notification).
        std::unique_lock<std::mutex> lk(_ring_cv_mutex);
        _ring_cv.wait_for(lk, std::chrono::milliseconds(5),
            [this]()
            {
                return !_running.load(std::memory_order_relaxed) ||
                       _ring_buf.read_available() >= MIN_SAMPLES;
            });
        return false;
    }

    // ── Copy a block from the ring buffer ────────────────────────────────
    size_t samples_to_read = std::min(available,
                                       static_cast<size_t>(MAX_FRAMES * 2));
    samples_to_read &= ~static_cast<size_t>(1);  // ensure we read complete stereo frames

    _ring_buf.read(_pcm_in.data(), samples_to_read);

    frames_in = static_cast<int>(samples_to_read / 2);
    return true;
}


// ── InputChannel::update_metering ─────────────────────────────────────────────
//
// Peak-level metering for the block drain_capture_ring() just read into
// _pcm_in: compute_peak_sample(), _current_peak_sample, the
// _poll_peak_sample CAS loop, and _session_raw_peak_sample. Returns the raw
// peak sample so callers (silence state, track-gap detection, the recorder
// tap's above-threshold flag) can use the same value computed exactly once
// per iteration, as today.
//
float InputChannel::update_metering(int frames_in)
{
    // ── Compute peak sample level ─────────────────────────────────────────
    // Linear amplitude in [0.0, 1.0]; see compute_peak_sample()'s
    // comment. Still no log10 here -- that stays deferred to get_status().
    float peak_sample = compute_peak_sample(_pcm_in.data(), frames_in, /*channels=*/2);
    _current_peak_sample.store(peak_sample, std::memory_order_relaxed);

    // Accumulate poll-window peak — reset by get_status() via exchange(0).
    // Use CAS so that a concurrent exchange(0) in get_status() is never lost:
    // if get_status() wins the exchange between our load and store, the CAS
    // fails, prev is updated to 0, and we retry to set peak_sample.
    {
        float prev = _poll_peak_sample.load(std::memory_order_relaxed);
        while (peak_sample > prev &&
               !_poll_peak_sample.compare_exchange_weak(
                   prev, peak_sample, std::memory_order_relaxed))
            ; // prev is updated on failure; retry with latest value
    }

    // Accumulate session raw peak (plain float compare — no log10).
    {
        float prev = _session_raw_peak_sample.load(std::memory_order_relaxed);
        if (peak_sample > prev)
            _session_raw_peak_sample.store(peak_sample, std::memory_order_relaxed);
    }

    return peak_sample;
}


// ── InputChannel::update_silence_state ────────────────────────────────────────
//
// Silence/activity state machine (activity threshold x _allow_capture gate,
// unchanged). Updates _last_above_threshold_time and returns should_capture;
// also hands back the per-iteration config snapshot (silence_threshold_sample,
// track_change_silence_seconds) and is_above_threshold that
// handle_session_edges() and the status-snapshot update need, read exactly
// once per iteration as today.
//
bool InputChannel::update_silence_state(float   peak_sample,
                                         double  now,
                                         float&  silence_threshold_sample,
                                         bool&   is_above_threshold,
                                         float&  track_change_silence_seconds)
{
    // _silence_threshold_sample is published atomically by configure(), so
    // we only need to lock here to read silence_seconds and track_change_silence_seconds.
    int silence_seconds;
    {
        std::lock_guard<std::mutex> lock(_config_mutex);
        silence_seconds              = _config.silence_seconds;
        track_change_silence_seconds = _config.track_change_silence_seconds;
    }
    silence_threshold_sample = _silence_threshold_sample.load(std::memory_order_relaxed);

    // Plain float comparison (still no log10/trig on this hot path).
    if (peak_sample >= silence_threshold_sample)
        _last_above_threshold_time = now;

    is_above_threshold = (_last_above_threshold_time > 0.0)
                       && ((now - _last_above_threshold_time)
                           < static_cast<double>(silence_seconds));

    bool should_capture = is_above_threshold
                       && _allow_capture.load(std::memory_order_relaxed);

    return should_capture;
}


// ── InputChannel::handle_session_edges ────────────────────────────────────────
//
// Capture session start/stop transitions (SRC resets incl. the ID-tap
// reset, RepeatController notifications, ramp/pre-fill arming) and
// track-gap detection.
//
// TrackGapDetector::update() is folded in here -- NOT into
// tap_for_id_and_repeat() -- because it runs once per OUTER
// process_thread_func() loop iteration, before the SRC loop, using the raw
// per-block peak computed once at the top of the iteration. The ID/repeat
// taps in tap_for_id_and_repeat() instead run once per SRC output CHUNK,
// and a single outer iteration's input can produce more than one chunk
// (libsamplerate does not always consume all input in one src_process()
// call). Detecting the gap once per outer iteration here, at the same
// relative position as before, preserves its exact firing cadence.
//
void InputChannel::handle_session_edges(bool   should_capture,
                                         float  peak_sample,
                                         float  silence_threshold_sample,
                                         double now,
                                         float  track_change_silence_seconds)
{
    // ── Start or stop the capture session ────────────────────────────────
    if (should_capture && !_capturing.load())
    {
        if (_src_state)
            src_reset(_src_state);
        // Reset the ID-tap resampler alongside the main SRC state so a
        // fresh capture session gets fresh interpolator state on BOTH
        // paths -- otherwise only the main SRC gets reset here, letting
        // the ID tap carry state across silence gaps.
        if (_id_tap)
            _id_tap->reset();
        _ramp_frames_remaining    = _ramp_duration_frames;
        _prefill_frames_remaining = _prefill_duration_frames;
        _prefill_buf.clear();
        _prefill_buf.reserve(static_cast<size_t>(_prefill_duration_frames) * 2);
        _capturing.store(true);
        _repeat_controller.notify_capture_started(_index);
        LOG_INFO("[input%d] Capture session started (peak=%.4f, threshold=%.4f)",
                 _index, peak_sample, silence_threshold_sample);
    }
    else if (!should_capture && _capturing.load())
    {
        _repeat_controller.notify_capture_stopped(_index);
        _capturing.store(false);
        LOG_INFO("[input%d] Capture session stopped (silence=%.1f s)",
                 _index, now - _last_above_threshold_time);
    }

    // ── Track-gap detection ───────────────────────────────────────────────
    // Uses the raw per-block amplitude flag (not the debounced is_above_threshold)
    // so a gap that starts within silence_seconds is detected precisely.
    // Fires on the first above-threshold block after a qualifying gap.
    {
        // Discard any in-progress gap candidate when the threshold changes so
        // a partial gap measured against the old value does not fire spuriously.
        if (track_change_silence_seconds != _prev_track_change_silence_seconds)
        {
            _track_gap_detector.clear_candidate();
            _prev_track_change_silence_seconds = track_change_silence_seconds;
        }

        bool raw_above = (peak_sample >= silence_threshold_sample);
        if (_track_gap_detector.update(_capturing.load(), raw_above, now,
                                       static_cast<double>(track_change_silence_seconds)))
        {
            uint32_t seq = _track_change_seq.fetch_add(1, std::memory_order_relaxed) + 1;
            LOG_INFO("[input%d] Possible track change detected (gap=%.1f s, seq=%u)",
                     _index, _track_gap_detector.last_gap_seconds(), seq);
        }
    }
}


// ── InputChannel::resample_block ──────────────────────────────────────────────
//
// Owns the main SRC loop (`while (frames_left > 0)`) and the periodic
// drift-diagnostics accumulation (_stats_in_frames/_stats_out_frames read by
// the diagnostics block at the top of process_thread_func()'s loop). For
// each output chunk src_process() produces, calls tap_for_id_and_repeat(),
// apply_output_chain(), and deliver_output() in that order -- identical to
// today's single nested per-chunk block. Only called when _capturing and
// _src_state are both set (checked by the caller), exactly as today.
//
void InputChannel::resample_block(int frames_in, float peak_sample, float silence_threshold_sample)
{
    // Convert int32 (the monitor's common 32-bit internal
    // representation) to float in the range [-1.0, +1.0]. libsamplerate's
    // src_int_to_float_array assumes the full 32-bit dynamic range, matching
    // the widening convention AlsaCapture::read() and convert_to_pipe_format()
    // (autostream_repeat.cpp) both use.
    src_int_to_float_array(_pcm_in.data(), _float_in.data(), frames_in * 2);

    // Resample in a loop.  libsamplerate may not consume all input frames
    // in a single call if the output buffer would overflow (this can happen
    // with high upsampling ratios, e.g. 8 kHz input → 44.1 kHz output).
    // We iterate until all input frames are consumed, writing each chunk
    // to the FIFO as it is produced.  src_ratio is read once per block
    // so it is consistent across all iterations.
    const float* in_ptr      = _float_in.data();
    int          frames_left = frames_in;
    const double ratio       = _rate_estimator.src_ratio();

    while (frames_left > 0)
    {
        SRC_DATA src_data;
        memset(&src_data, 0, sizeof(src_data));
        src_data.data_in       = in_ptr;
        src_data.input_frames  = frames_left;
        src_data.data_out      = _float_out.data();
        src_data.output_frames = MAX_SRC_OUTPUT;
        src_data.src_ratio     = ratio;
        src_data.end_of_input  = 0;

        int src_err = src_process(_src_state, &src_data);
        if (src_err != 0)
        {
            LOG_WARN("[input%d] libsamplerate error: %s",
                     _index, src_strerror(src_err));
            break;
        }

        in_ptr      += src_data.input_frames_used * 2;  // stereo
        frames_left -= static_cast<int>(src_data.input_frames_used);

        // Accumulate for the periodic [stats] diagnostics block at the top of
        // process_thread_func()'s loop.
        _stats_in_frames  += static_cast<uint64_t>(src_data.input_frames_used);
        _stats_out_frames += static_cast<uint64_t>(src_data.output_frames_gen > 0 ? src_data.output_frames_gen : 0);

        if (src_data.output_frames_gen <= 0)
            continue;   // no output this iteration; keep consuming input

        int out_frames = static_cast<int>(src_data.output_frames_gen);

        tap_for_id_and_repeat(out_frames, peak_sample, silence_threshold_sample);
        apply_output_chain(out_frames);
        deliver_output(out_frames);
    }   // while (frames_left > 0)
}


// ── InputChannel::tap_for_id_and_repeat ───────────────────────────────────────
//
// Post-SRC, pre-gain, pre-EQ taps for one produced chunk: the shared
// IdTapResampler snapshot ring and the RepeatController recorder tap.
//
void InputChannel::tap_for_id_and_repeat(int out_frames, float peak_sample, float silence_threshold_sample)
{
    // ── ID snapshot tap (post-SRC, pre-gain, pre-EQ) ─────────
    // Tap here to capture uncolored audio: gain and EQ reflect
    // user preference and would skew Shazam's frequency-domain
    // fingerprints if applied. Downmix, resample (48000 → 16000
    // Hz, filtered SRC_SINC_FASTEST), and clamp are all done by
    // _id_tap (IdTapResampler); this just writes its output into
    // _id_buf under the ring's own lock.
    if (!_id_buf.empty() && _id_tap)
    {
        int id_count = 0;
        const int16_t* id_out = _id_tap->process(_float_out.data(), out_frames, &id_count);
        if (id_out && id_count > 0)
        {
            std::lock_guard<std::mutex> id_lock(_id_mutex);
            unsigned wp = _id_write_pos;
            for (int i = 0; i < id_count; ++i)
                _id_buf[(wp + static_cast<unsigned>(i)) & ID_BUF_MASK] = id_out[i];
            _id_write_pos    = wp + static_cast<unsigned>(id_count);
            _id_frames_avail = std::min(
                _id_frames_avail + static_cast<unsigned>(id_count),
                ID_BUF_FRAMES);
        }
    }

    // ── Repeat-feature recorder tap -- POST-SRC / PRE-GAIN, immediately ────
    // after the libsamplerate conversion to output rate and before the
    // gain+fade-in section in apply_output_chain().
    //
    // The recording must carry NO baked-in gain, fade-in ramp, input EQ,
    // output EQ/gain, or auto-trim, so that replay can apply the ORIGIN
    // INPUT'S CURRENT (live-pulled) gain/EQ plus the shared OutputProcessor
    // at playback time instead of at record time. This tap point is
    // float_out immediately after src_process() in resample_block() and
    // before any of gain/ramp/EQ/OutputProcessor::apply() run on it -- i.e.
    // exactly the same stage as the ID tap just above (both explicitly
    // documented as "post-SRC, pre-gain, pre-EQ" -- see the ID tap's own
    // comment a few lines up and InputChannel::_id_buf's class-level
    // comment, "Tap point: post-main-SRC (48000 Hz stereo float),
    // pre-gain/pre-EQ"), so replay's own TrackGapDetector/ID tap (fed from
    // the decoded recording, autostream_repeat.cpp) observes audio at the
    // identical DSP stage as the live ID tap, without any further change
    // needed on the replay side.
    //
    // The above-threshold flag passed to submit_float_block() is still the
    // RAW per-block peak test computed once per outer process_thread_func()
    // iteration (`peak_sample >= silence_threshold_sample`, passed down from
    // update_metering()/update_silence_state() via resample_block()'s
    // parameters) on the int32 ring-buffer samples (compute_peak_sample():
    // linear float amplitude in [0.0, 1.0], not int16) -- i.e. BEFORE even
    // this SRC step, let alone gain. That flag was already computed upstream
    // of every DSP stage, so it remains the right "was this block loud"
    // signal for SilenceTrimAccountant regardless of where the recorder's
    // audio tap itself sits.
    //
    // Pre-fill gap-free capture: this tap fires for every processed block
    // from the very first block of a capture session, completely
    // independent of the FIFO pre-fill accumulator in deliver_output()
    // (`_prefill_frames_remaining`), which only gates when accumulated int16
    // samples are flushed to the OUTPUT fifo, not whether this call site
    // runs. This call site never sits inside the
    // `if (_prefill_frames_remaining > 0) ... else ...` branch, so the
    // recording is gap-free across the pre-fill window.
    //
    // Gating: recording_wanted() alone is sufficient here (no need to also
    // check _allow_capture/is_fifo_owned_by_replay() as a
    // post-OutputProcessor tap site would need for locality inside the
    // live-write block) -- it already requires _state == Recording|Pending
    // AND origin_input == this input's index, and _origin_input is only
    // ever set to an input whose should_capture (hence _allow_capture) is
    // true (RepeatController::notify_capture_started() is only called from
    // inside `if (_capturing.load() && _src_state)`, itself gated by
    // should_capture). A live-interrupt fade (FadingOut) leaves state
    // neither Recording nor Pending, so the interrupting input's audio is
    // correctly excluded here without any extra check.
    if (_repeat_controller.recording_wanted(_index))
        _repeat_controller.submit_float_block(
            _float_out.data(), out_frames,
            peak_sample >= silence_threshold_sample);
}


// ── InputChannel::apply_output_chain ──────────────────────────────────────────
//
// Per-input gain/fade-in ramp and EQ for one produced chunk (lock-free; runs
// before the _fifo_mutex section in deliver_output()). Also accumulates the
// session effective peak. Operates on _float_out in place.
//
void InputChannel::apply_output_chain(int out_frames)
{
    // ── Apply pre-amp gain and fade-in ramp ──────────────────
    // Read gain once so it is consistent across the block.
    // memory_order_relaxed is fine: a one-block lag is imperceptible.
    float gain = _gain_linear.load(std::memory_order_relaxed);

    if (_ramp_frames_remaining > 0)
    {
        // Ramp is active.  Apply a per-frame multiplier that rises
        // linearly from 0.0 at session start to 1.0 at ramp end,
        // combined with _gain_linear in a single multiply per sample.
        //
        // ramp_pos is the frame index into the full ramp, counting
        // from 0 (session start) to _ramp_duration_frames (ramp end).
        // Frames within this block that fall inside the ramp use the
        // interpolated gain; any frames after the ramp completes
        // within the same block receive the full gain.
        int frames_in_ramp = std::min(out_frames, _ramp_frames_remaining);
        int ramp_pos       = _ramp_duration_frames - _ramp_frames_remaining;

        for (int f = 0; f < frames_in_ramp; ++f)
        {
            float ramp_gain = gain * static_cast<float>(ramp_pos + f)
                                    / static_cast<float>(_ramp_duration_frames);
            _float_out[f * 2]     *= ramp_gain;
            _float_out[f * 2 + 1] *= ramp_gain;
        }

        // Freeze the ramp's progress while ReplayEngine owns the FIFO.
        // This block's write-side
        // section in deliver_output() is skipped entirely whenever
        // is_fifo_owned_by_replay() is true, so these frames are
        // computed but never reach OwnTone -- decrementing the
        // counter anyway would let a ~1.5 s live-interrupt fade
        // silently exhaust the 1 s ramp before the FIFO ever
        // hands over, producing an abrupt full-volume jump the
        // instant ownership actually flips to Live instead of the
        // intended audible fade-in. Freezing here means the ramp
        // (armed fresh at notify_capture_started(), see
        // handle_session_edges()) has not consumed any of its span
        // by the handoff instant, so it plays out cleanly over the
        // first _ramp_duration_frames of frames actually written
        // once is_fifo_owned_by_replay() goes false -- i.e. the
        // ramp is effectively re-armed AT the handoff instant
        // without needing a separate cross-object re-arm call.
        // recording_wanted()/is_fifo_owned_by_replay() are both
        // single relaxed atomic loads (cheap, lock-free), so this
        // extra read outside _fifo_mutex costs nothing measurable
        // and only ever causes a stale-by-one-block read, which is
        // harmless here (worst case: one extra block's worth of
        // ramp progress either frozen or advanced a moment early).
        if (!_repeat_controller.is_fifo_owned_by_replay())
            _ramp_frames_remaining -= frames_in_ramp;

        // Apply uniform gain to any remaining frames in this block
        // (those that fall after the ramp completes).
        if (gain != 1.0f)
        {
            for (int f = frames_in_ramp; f < out_frames; ++f)
            {
                _float_out[f * 2]     *= gain;
                _float_out[f * 2 + 1] *= gain;
            }
        }
    }
    else if (gain != 1.0f)
    {
        // No ramp — apply uniform gain to the whole block.
        int total_samples = out_frames * 2;
        for (int s = 0; s < total_samples; ++s)
            _float_out[s] *= gain;
    }

    // ── Apply per-channel EQ ──────────────────────────────────
    // Check whether _eq_chain has published a new band list since
    // the last block.  If so, rebuild local filters with freshly
    // zeroed delay-line state.  The shared_ptr comparison is a
    // pointer equality check — no allocation.
    auto latest_bands = _eq_chain.get_bands();
    if (latest_bands != _current_eq_bands)
    {
        _current_eq_bands = latest_bands;
        _local_filters.clear();
        if (latest_bands)
        {
            float sr = _eq_chain.sample_rate();
            for (const auto& band : *latest_bands)
            {
                BiquadFilter f;
                f.configure(band, sr);
                _local_filters.push_back(f);
            }
        }
    }
    for (auto& filter : _local_filters)
        filter.process(_float_out.data(), out_frames);

    // ── Accumulate session effective peak ─────────────────────
    // Scan the post-gain, post-input-EQ float samples.  Deferred
    // to get_status() for the dBFS conversion (no log10 here).
    // This measures the per-input signal level before output EQ.
    {
        float eff_peak = 0.0f;
        int total_samples = out_frames * 2;
        for (int s = 0; s < total_samples; ++s)
        {
            float v = std::fabs(_float_out[s]);
            if (v > eff_peak)
                eff_peak = v;
        }
        float prev = _session_effective_peak_linear.load(std::memory_order_relaxed);
        if (eff_peak > prev)
            _session_effective_peak_linear.store(eff_peak, std::memory_order_relaxed);
    }
}


// ── InputChannel::deliver_output ──────────────────────────────────────────────
//
// The _fifo_mutex critical section for one produced chunk: OutputProcessor
// apply() (output EQ/gain/auto-trim) gated by live_write_active, the
// capturing_live-gated VU-bin peak accumulation, the int16 cast, the
// engineering dump tap, and pre-fill buffering / FIFO write.
//
// apply() — which includes the auto-trim CAS update — and the
// FIFO write are both performed while holding _fifo_mutex.  This
// is the key structural invariant that makes auto-trim reset
// race-free:
//
//   Control thread (api_set_allow_capture handoff):
//     1. Stores _allow_capture = false on outgoing input.
//     2. Acquires _fifo_mutex.
//     3. Calls reset_auto_trim() (trim → 0).
//     4. Stores _allow_capture = true on incoming input.
//     5. Releases _fifo_mutex.
//
//   Process thread of outgoing input: either
//     A. Holds _fifo_mutex when the control thread tries step 2.
//        The outgoing thread's apply() and write complete, mutex
//        is released, then the control thread resets trim.  The
//        outgoing thread's NEXT iteration observes
//        _allow_capture = false and skips apply() entirely.
//     B. Does not hold _fifo_mutex when the control thread does
//        step 2.  The control thread acquires first; the outgoing
//        thread waits.  When it finally acquires, it reads
//        _allow_capture = false and skips both apply() and the
//        FIFO write — the trim is never touched.
//
// In both cases the trim is 0 before the incoming input's first
// apply() call, and the outgoing input cannot write a negative
// trim after the reset.
//
// ── Extended for the third writer: ReplayEngine ─────────────────────────────
//
// ReplayEngine writes to the SAME FIFO through its OWN
// blocking-paced fd (not this FifoWriter instance), so the
// two writers never contend for FifoWriter's internal state;
// what they DO need to arbitrate is which one is allowed to
// put bytes on the wire at all, via the FifoOwner flag
// (RepeatController::_fifo_owner_fast):
//
//   Writer                  | Flips FifoOwner under...
//   ------------------------|---------------------------------
//   Live (this file)        | never writes it, only reads it
//                           | (is_fifo_owned_by_replay()) --
//                           | already inside this _fifo_mutex
//                           | critical section.
//   ReplayEngine start/stop | RepeatController::set_fifo_owner()
//                           | (autostream_repeat.cpp), which
//                           | takes _fifo_mutex for exactly the
//                           | duration of the atomic store --
//                           | never across ReplayEngine's own
//                           | blocking/poll-gated write().
//
// Because the flip and this read are both done under
// _fifo_mutex, the same two-case argument as auto-trim above
// applies: either this thread holds _fifo_mutex when
// set_fifo_owner() is called (this iteration's write, if any,
// completes on the OLD owner value; the mutex is released,
// the owner flips, and this thread's NEXT iteration observes
// the new owner before deciding whether to write), or this
// thread is waiting when the owner flips (it then reads the
// NEW owner immediately). Either way, no iteration of this
// loop can observe a stale owner value and no two writers
// (live and replay) are ever both actively producing FIFO
// bytes at the same instant -- "sequential fade-out -> fade-in,
// no sample mixing" holds structurally, not just by convention.
//
// Lock order: RepeatController's
// _repeat_mutex may be taken while holding nothing, and may
// be held while subsequently taking _fifo_mutex (e.g.
// RepeatController::set_fifo_owner() called from inside a
// _repeat_mutex critical section in begin_replay_locked()/
// on_replay_session_ended_locked_entry()/stop()). The REVERSE
// order -- taking _repeat_mutex while already holding
// _fifo_mutex -- never happens anywhere in this codebase; this
// very _fifo_mutex critical section, for instance, only READS
// fast atomics (is_fifo_owned_by_replay(), recording_wanted())
// and never acquires _repeat_mutex. Neither mutex is ever held
// across a blocking/poll-gated write() on either the live path
// (this file) or ReplayEngine's own write loop
// (autostream_repeat.cpp's write_slice_paced()).
//
// This entire critical section is ONE contiguous lock_guard<std::mutex>
// scope, exactly as it was inside process_thread_func() before this method
// was extracted -- see the deviation note at this method's call site in
// resample_block() / the header declaration: the "-> OutputProcessor" step
// conceptually belongs with apply_output_chain()'s gain/EQ chain, but
// OutputProcessor::apply() is kept HERE, as the first step inside the lock,
// so the lock scope is never split across a method boundary (if a clean
// method boundary would split a lock scope, the method boundary loses).
//
void InputChannel::deliver_output(int out_frames)
{
    std::lock_guard<std::mutex> lock(_fifo_mutex);
    // Repeat-feature FIFO arbitration (extended proof comment above): while
    // ReplayEngine owns the pipe, this input's output is discarded here --
    // it still runs everything ABOVE this _fifo_mutex block (silence
    // detection, track-gap detection, level metering) unconditionally,
    // which is what would drive a live-interrupt trigger. Only the
    // write-side work (EQ/gain/recording-tap/dump-tap/FIFO write) is
    // skipped.
    //
    // VU-bin peak accumulation below is intentionally gated on
    // `capturing_live` ALONE, not `!is_fifo_owned_by_replay()` too, so the
    // home-page VU meter for the origin input keeps updating throughout a
    // replay session (level metering runs unconditionally as stated above)
    // while every write-side step (apply()'s output EQ/gain/auto-trim, the
    // recorder tap, the int16 cast, the dump tap, and the actual FIFO
    // write) is still skipped whenever replay owns the pipe.
    bool capturing_live = _allow_capture.load(std::memory_order_relaxed);
    bool live_write_active = capturing_live &&
        !_repeat_controller.is_fifo_owned_by_replay();

    if (live_write_active)
    {
        // Apply output EQ, output gain, and auto-trim in-place.
        // Must precede float→int16 so the clip scan sees the
        // true overshoot before clamping.
        //
        // The repeat-feature recorder tap sits POST-SRC/PRE-GAIN, well above
        // this _fifo_mutex block -- see tap_for_id_and_repeat()'s comment
        // for the full rationale.
        _output_processor.apply(_float_out.data(), out_frames);
    }
    else
    {
        // This input is not the active FIFO writer
        // right now (not the capturing/allow_capture input,
        // or replay owns the pipe) -- FifoWriter::write()
        // below will not be called on its behalf this block,
        // so any stall streak left over from when it WAS
        // active must not linger and be reported as "still
        // stalled" during a period that is actually idle for
        // this writer. Cheap atomic reset, no lock.
        _shared_fifo.reset_stall();
    }

    // ── Accumulate stereo peak for the current VU bin ─────
    // Tap here: post all output processing (when the write
    // path actually ran this block; see live_write_active
    // above), pre int16 cast. Gated on capturing_live alone
    // so the meter keeps reflecting real input levels
    // during replay, not just during ordinary live capture.
    // Existing playback detection logic (_current_peak_sample,
    // _poll_peak_sample) is left completely untouched.
    if (capturing_live)
    {
        for (int f = 0; f < out_frames; ++f)
        {
            float l = std::fabs(_float_out[f * 2]);
            float r = std::fabs(_float_out[f * 2 + 1]);
            if (l > _vu_bin_left_peak)  _vu_bin_left_peak  = l;
            if (r > _vu_bin_right_peak) _vu_bin_right_peak = r;
        }
    }

    if (live_write_active)
    {
        // Convert to the monitor's common 32-bit internal / output
        // container representation. src_float_to_int_array is libsamplerate's
        // full-32-bit-scale counterpart to src_float_to_short_array -- see
        // resample_block()'s matching src_int_to_float_array comment.
        src_float_to_int_array(_float_out.data(), _pcm_out.data(),
                                out_frames * 2);

        // ── Engineering output dump tap ───────────────────────
        // First point where the signal is complete (32-bit container)
        // after all SRC, per-input gain/EQ, output EQ, output gain,
        // and auto-trim.  submit_block() is non-blocking: it
        // copies into a bounded SPSC ring or drops and counts
        // frames if the ring is full — never delays this thread.
        _dump_writer.submit_block(_pcm_out.data(), out_frames);

        if (_prefill_frames_remaining > 0)
        {
            // Accumulation phase: append to the pre-fill buffer.
            // Do not write to the FIFO yet.
            const int32_t* src_ptr = _pcm_out.data();
            int to_add = std::min(out_frames, _prefill_frames_remaining);
            _prefill_buf.insert(_prefill_buf.end(),
                                src_ptr,
                                src_ptr + static_cast<size_t>(to_add) * 2);
            _prefill_frames_remaining -= to_add;

            if (_prefill_frames_remaining == 0)
            {
                // Pre-fill complete: flush the whole buffer in one
                // write, then write any frames from this block that
                // came after the pre-fill threshold.
                // Byte counts derived from
                // AudioMonitor::output_bytes_per_frame() (the shared
                // rate/bits/channels descriptor) instead of a hand-rolled
                // "* 2 * sizeof(int16_t)" literal, so a future OUTPUT_BITS
                // change only has to happen in one place. The "/ 2" below is
                // the channel count (interleaved stereo), matching the same
                // literal already used throughout this file (e.g.
                // compute_peak_sample()'s channels=2, capture_thread_func()'s
                // "stereo" comment) -- AudioMonitor::OUTPUT_CHANNELS itself
                // is private and not reachable from InputChannel.
                size_t prefill_frames = _prefill_buf.size() / 2;
                _shared_fifo.write(_prefill_buf.data(),
                                   prefill_frames * AudioMonitor::output_bytes_per_frame());
                _prefill_buf.clear();
                _prefill_buf.shrink_to_fit();

                int remainder = out_frames - to_add;
                if (remainder > 0)
                    _shared_fifo.write(src_ptr + static_cast<size_t>(to_add) * 2,
                                       static_cast<size_t>(remainder) * AudioMonitor::output_bytes_per_frame());

                LOG_DEBUG("[input%d] Pre-fill complete; first FIFO write done",
                          _index);
            }
        }
        else
        {
            // Normal phase: write directly to the FIFO.
            _shared_fifo.write(_pcm_out.data(),
                               static_cast<size_t>(out_frames) * AudioMonitor::output_bytes_per_frame());
        }
    }
}


// ── InputChannel::get_vu_history ──────────────────────────────────────────────
//
// Returns all retained VU bins, oldest first.  Thread-safe; acquires
// _vu_history_mutex for the duration of the copy.
//
std::vector<VuBin> InputChannel::get_vu_history() const
{
    std::lock_guard<std::mutex> lk(_vu_history_mutex);

    if (_vu_history_count == 0)
        return {};

    std::vector<VuBin> result;
    result.reserve(static_cast<size_t>(_vu_history_count));

    // The oldest valid bin starts at (write_idx - count), wrapping around.
    int start = (_vu_history_write_idx - _vu_history_count + VU_HISTORY_BINS)
                % VU_HISTORY_BINS;
    for (int i = 0; i < _vu_history_count; ++i)
        result.push_back(_vu_history[(start + i) % VU_HISTORY_BINS]);

    return result;
}
