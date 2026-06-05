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

    err = snd_pcm_hw_params_set_format(_pcm, hw_params, SND_PCM_FORMAT_S16_LE);
    if (err < 0)
    {
        LOG_WARN("[alsa] Cannot set S16_LE format for '%s': %s",
                 hw_device.c_str(), snd_strerror(err));
        goto fail;
    }

    err = snd_pcm_hw_params_set_channels(_pcm, hw_params,
                                          static_cast<unsigned int>(channels));
    if (err < 0)
    {
        LOG_WARN("[alsa] Cannot set %d channels for '%s': %s",
                 channels, hw_device.c_str(), snd_strerror(err));
        goto fail;
    }

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

    LOG_INFO("[alsa] Opened '%s': selected=%d Hz, negotiated=%d Hz, %d ch, period=%d frames",
             hw_device.c_str(), selected_rate_hz, _actual_rate, channels, _period_frames);
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
}

int AlsaCapture::read(int16_t* buf, int n_frames)
{
    // Hold _read_mutex for the duration of the check + snd_pcm_readi call.
    // This prevents close() from setting _pcm = nullptr between the guard
    // and the actual use of _pcm.  The lock is uncontended in normal
    // operation (only the capture thread calls read()), so the overhead
    // is negligible.
    std::lock_guard<std::mutex> lock(_read_mutex);

    if (!_pcm)
        return -1;

    snd_pcm_sframes_t frames_read = snd_pcm_readi(_pcm, buf, n_frames);

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

// Placeholder WAV header written at start(); sizes patched to final values at stop().
// Format: PCM 44100 Hz, 2 channels, signed 16-bit little-endian.
// Header layout (44 bytes):
//   Offset  0: "RIFF"
//   Offset  4: RIFF chunk size = 36 + data_bytes  (patched at offset  4)
//   Offset  8: "WAVE"
//   Offset 12: "fmt " + 16 (sub-chunk size)
//   Offset 20: audio_format=1, channels=2, sample_rate=44100
//   Offset 28: byte_rate=176400, block_align=4, bits_per_sample=16
//   Offset 36: "data"
//   Offset 40: data chunk size = frames * 4        (patched at offset 40)
static const uint8_t WAV_PLACEHOLDER_HEADER[44] = {
    // RIFF chunk descriptor
    'R','I','F','F',
    0,0,0,0,           // RIFF chunk size — patched on stop
    'W','A','V','E',
    // "fmt " sub-chunk (16 bytes)
    'f','m','t',' ',
    16,0,0,0,          // sub-chunk size
    1,0,               // audio format = PCM
    2,0,               // channels = 2
    0x44,0xAC,0,0,     // sample rate = 44100 (0x0000AC44)
    0x10,0xB1,2,0,     // byte rate  = 176400 (0x0002B110)
    4,0,               // block align = 4 bytes
    16,0,              // bits per sample = 16
    // "data" sub-chunk header
    'd','a','t','a',
    0,0,0,0            // data chunk size — patched on stop
};

OutputDumpWriter::OutputDumpWriter()
    : _ring(DUMP_RING_SAMPLES, 0)
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

    // Write placeholder header; sizes will be patched in stop().
    if (fwrite(WAV_PLACEHOLDER_HEADER, 1, sizeof(WAV_PLACEHOLDER_HEADER), f)
            != sizeof(WAV_PLACEHOLDER_HEADER))
    {
        fclose(f);
        return "failed to write WAV header";
    }

    // Initialise ring and counters before setting _active so submit_block()
    // cannot observe a stale read position.
    _file    = f;
    _path    = path;
    _ring_write_pos.store(0, std::memory_order_relaxed);
    _ring_read_pos.store(0,  std::memory_order_relaxed);
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
        uint64_t data_bytes64 = frames * 4ull;  // stereo int16 = 4 bytes/frame

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

void OutputDumpWriter::submit_block(const int16_t* samples, int out_frames)
{
    if (!_active.load(std::memory_order_relaxed))
        return;

    uint32_t n_samples = static_cast<uint32_t>(out_frames) * 2u;

    // Check ring space.  _ring_read_pos is written only by the writer thread;
    // acquire ordering synchronises with its release store so we see the most
    // recently freed space.
    uint32_t write_pos  = _ring_write_pos.load(std::memory_order_relaxed);
    uint32_t read_pos   = _ring_read_pos.load(std::memory_order_acquire);
    uint32_t used       = write_pos - read_pos;
    uint32_t free_space = DUMP_RING_SAMPLES - used;

    if (n_samples > free_space)
    {
        _dropped_frames.fetch_add(static_cast<uint64_t>(out_frames),
                                   std::memory_order_relaxed);
        return;
    }

    // Copy samples into the ring, handling the wrap-around boundary.
    uint32_t write_idx    = write_pos & DUMP_RING_MASK;
    uint32_t to_end       = DUMP_RING_SAMPLES - write_idx;
    uint32_t first_chunk  = std::min(n_samples, to_end);
    uint32_t second_chunk = n_samples - first_chunk;

    memcpy(_ring.data() + write_idx, samples,
           first_chunk * sizeof(int16_t));
    if (second_chunk > 0)
        memcpy(_ring.data(), samples + first_chunk,
               second_chunk * sizeof(int16_t));

    // Release store: makes the ring data visible to the writer thread.
    _ring_write_pos.fetch_add(n_samples, std::memory_order_release);

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
                    uint32_t wp = _ring_write_pos.load(std::memory_order_acquire);
                    uint32_t rp = _ring_read_pos.load(std::memory_order_relaxed);
                    return (wp - rp) > 0u
                        || _stop_requested.load(std::memory_order_relaxed);
                });
        }

        // Drain all available samples to disk.
        uint32_t write_pos = _ring_write_pos.load(std::memory_order_acquire);
        uint32_t read_pos  = _ring_read_pos.load(std::memory_order_relaxed);
        uint32_t avail     = write_pos - read_pos;

        if (avail > 0)
        {
            uint32_t read_idx = read_pos & DUMP_RING_MASK;
            uint32_t to_end   = DUMP_RING_SAMPLES - read_idx;
            uint32_t first    = std::min(avail, to_end);
            uint32_t second   = avail - first;

            bool write_ok = true;
            size_t written = fwrite(_ring.data() + read_idx,
                                    sizeof(int16_t), first, _file);
            if (written < first)
            {
                write_ok = false;
            }
            else if (second > 0)
            {
                size_t written2 = fwrite(_ring.data(),
                                          sizeof(int16_t), second, _file);
                written += written2;
                if (written2 < second)
                    write_ok = false;
            }

            // `written` is in int16 samples; stereo frames = samples / 2.
            _frames_written.fetch_add(written / 2u, std::memory_order_relaxed);

            // Always advance the read position to consume the data, even on
            // write error, so the audio thread is never blocked by a full ring.
            _ring_read_pos.fetch_add(avail, std::memory_order_release);

            if (!write_ok)
            {
                LOG_WARN("[dump] Write error; aborting dump recording");
                break;
            }
        }

        // Exit only after stop has been requested and the ring is fully drained.
        if (_stop_requested.load(std::memory_order_relaxed))
        {
            uint32_t wp = _ring_write_pos.load(std::memory_order_acquire);
            uint32_t rp = _ring_read_pos.load(std::memory_order_relaxed);
            if (wp - rp == 0u)
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

// Convert a dBFS threshold to the equivalent integer sample amplitude (0..32767).
// Computed once at configure() time so the hot path can use a plain integer compare.
static int dbfs_to_sample_threshold(float dbfs)
{
    if (dbfs >= 0.0f)
        return 32767;
    float linear    = std::pow(10.0f, dbfs / 20.0f);
    int   threshold = static_cast<int>(linear * 32768.0f);
    return std::max(1, std::min(32767, threshold));
}

// Convert an integer sample amplitude back to dBFS for reporting.
// Only called from get_status() (~10 times/second), not from the hot path.
static float sample_to_dbfs(int peak)
{
    if (peak <= 0)
        return -90.0f;
    float ratio = static_cast<float>(peak) / 32768.0f;
    return std::max(-90.0f, 20.0f * std::log10(ratio));
}

// Convert a linear float peak amplitude to dBFS.
// Used for the effective peak, which lives in float domain after gain and EQ.
static float linear_to_dbfs(float peak_linear)
{
    if (peak_linear <= 0.0f)
        return -90.0f;
    return std::max(-90.0f, 20.0f * std::log10(peak_linear));
}

InputChannel::InputChannel(int               index,
                           FifoWriter&       shared_fifo,
                           std::mutex&       fifo_mutex,
                           OutputProcessor&  output_processor,
                           OutputDumpWriter& dump_writer)
    : _index(index)
    , _shared_fifo(shared_fifo)
    , _fifo_mutex(fifo_mutex)
    , _output_processor(output_processor)
    , _dump_writer(dump_writer)
    , _ring_buf(RING_BUF_SAMPLES, 0)
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
    _silence_threshold_sample.store(dbfs_to_sample_threshold(cfg.silence_threshold_dbfs),
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

    // Create a libsamplerate state for stereo conversion.
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
    _ring_write_pos.store(0, std::memory_order_relaxed);
    _ring_read_pos.store(0,  std::memory_order_relaxed);

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

    _capturing.store(false);
    _current_peak_sample.store(0, std::memory_order_relaxed);
    _poll_peak_sample.store(0, std::memory_order_relaxed);
    _session_raw_peak_sample.store(0, std::memory_order_relaxed);
    _session_effective_peak_linear.store(0.0f, std::memory_order_relaxed);

    {
        std::lock_guard<std::mutex> lock(_status_mutex);
        _status.is_silent    = true;
        _status.is_capturing = false;
        _status.detected_hz  = 0.0;
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
    s.level_dbfs             = sample_to_dbfs(_current_peak_sample.load(std::memory_order_relaxed));
    s.poll_peak_dbfs         = sample_to_dbfs(_poll_peak_sample.exchange(0, std::memory_order_relaxed));
    s.raw_peak_dbfs          = sample_to_dbfs(_session_raw_peak_sample.load(std::memory_order_relaxed));
    s.effective_peak_dbfs    = linear_to_dbfs(_session_effective_peak_linear.load(std::memory_order_relaxed));
    s.is_started             = _started.load(std::memory_order_relaxed);
    s.is_running             = _running.load(std::memory_order_relaxed);
    return s;
}

int InputChannel::compute_peak_sample(const int16_t* samples,
                                       int            n_frames,
                                       int            n_channels) const
{
    // Pure integer scan — no float arithmetic.
    int peak = 0;
    for (int frame = 0; frame < n_frames; ++frame)
    {
        for (int ch = 0; ch < n_channels; ++ch)
        {
            int sample     = samples[frame * n_channels + ch];
            int abs_sample = (sample < 0) ? -sample : sample;
            if (abs_sample > peak)
                peak = abs_sample;
        }
    }
    return peak;
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
// Reads hardware periods from ALSA and writes interleaved int16 stereo samples
// into the ring buffer.  This thread runs at close to real time and should do
// as little work as possible to avoid causing ALSA xruns.
//
void InputChannel::capture_thread_func()
{
    // Size the local read buffer to one hardware period.
    // We re-read the period size after open; it will not change during a session.
    std::vector<int16_t> period_buf;

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

        int samples_to_write = frames_read * 2;  // stereo

        // Check that there is space in the ring buffer.  If the process thread
        // is falling behind, we drop the oldest data (overwrite) rather than
        // blocking, which would cause an ALSA xrun.
        unsigned write_pos = _ring_write_pos.load(std::memory_order_relaxed);
        unsigned read_pos  = _ring_read_pos.load(std::memory_order_acquire);
        unsigned used      = write_pos - read_pos;   // unsigned subtraction wraps correctly
        unsigned free      = RING_BUF_SAMPLES - used;

        if (static_cast<unsigned>(samples_to_write) > free)
        {
            // Ring buffer is full — the process thread is falling behind.
            // Drop this incoming period rather than advancing _ring_read_pos
            // from the capture thread.  _ring_read_pos must only be written
            // by the process thread to preserve the SPSC invariant; the
            // capture thread writing it (even atomically) can race with the
            // process thread's store and silently corrupt the read position.
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

        // Write samples into the ring buffer, handling wrap-around with two copies.
        unsigned write_idx     = write_pos & RING_BUF_MASK;
        unsigned to_end        = RING_BUF_SAMPLES - write_idx;
        unsigned first_chunk   = std::min(static_cast<unsigned>(samples_to_write), to_end);
        unsigned second_chunk  = static_cast<unsigned>(samples_to_write) - first_chunk;

        memcpy(&_ring_buf[write_idx],
               period_buf.data(),
               first_chunk * sizeof(int16_t));

        if (second_chunk > 0)
        {
            memcpy(&_ring_buf[0],
                   period_buf.data() + first_chunk,
                   second_chunk * sizeof(int16_t));
        }

        // Update write position — this is the release point for the process thread.
        _ring_write_pos.fetch_add(static_cast<unsigned>(samples_to_write),
                                   std::memory_order_release);

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
    // Pre-allocate processing buffers.  Avoid heap allocation on the hot path.
    const int MAX_FRAMES          = 2048;   // maximum input frames per loop iteration
    const int MAX_SRC_OUTPUT      = 4096;   // maximum output frames from libsamplerate

    // Duration of the fade-in ramp in output frames (one second at 44100 Hz).
    const int RAMP_DURATION_FRAMES = AudioMonitor::output_rate_hz();

    // Number of output frames to accumulate before the first FIFO write.
    // 0.5 s at 44100 Hz = 22050 frames = ~172 KB of int16 stereo data.
    // This gives OwnTone a full initial buffer so it can start streaming
    // without the starvation-induced skips that occur when the pipe is
    // cold and the first few writes are each only a single period (~1024 frames).
    const int PREFILL_DURATION_FRAMES = AudioMonitor::output_rate_hz() / 2;

    std::vector<int16_t> pcm_in(MAX_FRAMES * 2);          // interleaved int16
    std::vector<float>   float_in(MAX_FRAMES * 2);        // interleaved float
    std::vector<float>   float_out(MAX_SRC_OUTPUT * 2);   // post-SRC float
    std::vector<int16_t> pcm_out(MAX_SRC_OUTPUT * 2);     // final int16
    std::vector<int16_t> id_tmp(MAX_SRC_OUTPUT / 2);      // mono ID frames (pre-gain/EQ tap)

    // Minimum number of samples to accumulate before processing.
    // 512 samples = 256 stereo frames = ~5 ms at 48 kHz.
    const unsigned MIN_SAMPLES = 512;

    // Anchor the first VU bin to the moment the process thread starts.
    _vu_bin_start_time = get_monotonic_time();

    while (_running.load(std::memory_order_relaxed))
    {
        // ── Close any elapsed VU bins ─────────────────────────────────────────
        // Runs every iteration (including idle iterations after the condition-
        // variable sleep) so silence bins are produced even when the channel
        // is not capturing.  A while loop catches up if multiple bins have
        // elapsed since the last iteration (e.g. after a long OS sleep).
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

        // ── Wait for data ────────────────────────────────────────────────────
        unsigned write_pos = _ring_write_pos.load(std::memory_order_acquire);
        unsigned read_pos  = _ring_read_pos.load(std::memory_order_relaxed);
        unsigned available = write_pos - read_pos;

        if (available < MIN_SAMPLES)
        {
            // Sleep until the capture thread signals new data or up to 5 ms
            // (the timeout handles the case where notify_one() was called just
            // before we entered wait_for — at most one missed notification).
            std::unique_lock<std::mutex> lk(_ring_cv_mutex);
            _ring_cv.wait_for(lk, std::chrono::milliseconds(5),
                [this, MIN_SAMPLES]()
                {
                    return !_running.load(std::memory_order_relaxed) ||
                           (_ring_write_pos.load(std::memory_order_acquire) -
                            _ring_read_pos.load(std::memory_order_relaxed)) >= MIN_SAMPLES;
                });
            continue;
        }

        // ── Copy a block from the ring buffer ────────────────────────────────
        unsigned samples_to_read = std::min(available,
                                             static_cast<unsigned>(MAX_FRAMES * 2));
        samples_to_read &= ~1u;  // ensure we read complete stereo frames

        unsigned read_idx   = read_pos & RING_BUF_MASK;
        unsigned to_end     = RING_BUF_SAMPLES - read_idx;
        unsigned first_chunk  = std::min(samples_to_read, to_end);
        unsigned second_chunk = samples_to_read - first_chunk;

        memcpy(pcm_in.data(),
               &_ring_buf[read_idx],
               first_chunk * sizeof(int16_t));

        if (second_chunk > 0)
        {
            memcpy(pcm_in.data() + first_chunk,
                   &_ring_buf[0],
                   second_chunk * sizeof(int16_t));
        }

        // Advance the read position to release space for the capture thread.
        _ring_read_pos.store(read_pos + samples_to_read, std::memory_order_release);

        int frames_in = static_cast<int>(samples_to_read / 2);

        // ── Compute peak sample level (pure integer, no float) ───────────────
        int peak_sample = compute_peak_sample(pcm_in.data(), frames_in, /*channels=*/2);
        _current_peak_sample.store(peak_sample, std::memory_order_relaxed);

        // Accumulate poll-window peak — reset by get_status() via exchange(0).
        // Use CAS so that a concurrent exchange(0) in get_status() is never lost:
        // if get_status() wins the exchange between our load and store, the CAS
        // fails, prev is updated to 0, and we retry to set peak_sample.
        {
            int prev = _poll_peak_sample.load(std::memory_order_relaxed);
            while (peak_sample > prev &&
                   !_poll_peak_sample.compare_exchange_weak(
                       prev, peak_sample, std::memory_order_relaxed))
                ; // prev is updated on failure; retry with latest value
        }

        // Accumulate session raw peak (no float / log10 — integer compare only).
        {
            int prev = _session_raw_peak_sample.load(std::memory_order_relaxed);
            if (peak_sample > prev)
                _session_raw_peak_sample.store(peak_sample, std::memory_order_relaxed);
        }

        // ── Silence state machine ─────────────────────────────────────────────
        double now = get_monotonic_time();

        // _silence_threshold_sample is published atomically by configure(), so
        // we only need to lock here to read silence_seconds.
        int silence_seconds;
        {
            std::lock_guard<std::mutex> lock(_config_mutex);
            silence_seconds = _config.silence_seconds;
        }
        int silence_threshold_sample = _silence_threshold_sample.load(std::memory_order_relaxed);

        // Integer comparison — no float arithmetic on the hot path.
        if (peak_sample >= silence_threshold_sample)
            _last_above_threshold_time = now;

        bool is_above_threshold = (_last_above_threshold_time > 0.0)
                               && ((now - _last_above_threshold_time)
                                   < static_cast<double>(silence_seconds));

        bool should_capture = is_above_threshold
                           && _allow_capture.load(std::memory_order_relaxed);

        // ── Start or stop the capture session ────────────────────────────────
        if (should_capture && !_capturing.load())
        {
            if (_src_state)
                src_reset(_src_state);
            _ramp_frames_remaining    = RAMP_DURATION_FRAMES;
            _prefill_frames_remaining = PREFILL_DURATION_FRAMES;
            _prefill_buf.clear();
            _prefill_buf.reserve(static_cast<size_t>(PREFILL_DURATION_FRAMES) * 2);
            _capturing.store(true);
            LOG_INFO("[input%d] Capture session started (peak=%d, threshold=%d)",
                     _index, peak_sample, silence_threshold_sample);
        }
        else if (!should_capture && _capturing.load())
        {
            _capturing.store(false);
            LOG_INFO("[input%d] Capture session stopped (silence=%.1f s)",
                     _index, now - _last_above_threshold_time);
        }

        // ── Feed through SRC → EQ → FIFO when capturing ──────────────────────
        if (_capturing.load() && _src_state)
        {
            // Convert int16 to float in the range [-1.0, +1.0].
            src_short_to_float_array(pcm_in.data(), float_in.data(), frames_in * 2);

            // Resample in a loop.  libsamplerate may not consume all input frames
            // in a single call if the output buffer would overflow (this can happen
            // with high upsampling ratios, e.g. 8 kHz input → 44.1 kHz output).
            // We iterate until all input frames are consumed, writing each chunk
            // to the FIFO as it is produced.  src_ratio is read once per block
            // so it is consistent across all iterations.
            const float* in_ptr      = float_in.data();
            int          frames_left = frames_in;
            const double ratio       = _rate_estimator.src_ratio();

            while (frames_left > 0)
            {
            SRC_DATA src_data;
            memset(&src_data, 0, sizeof(src_data));
            src_data.data_in       = in_ptr;
            src_data.input_frames  = frames_left;
            src_data.data_out      = float_out.data();
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

            if (src_data.output_frames_gen <= 0)
                continue;   // no output this iteration; keep consuming input

            {
                int out_frames = static_cast<int>(src_data.output_frames_gen);

                // ── ID snapshot tap (post-SRC, pre-gain, pre-EQ) ─────────
                // Tap here to capture uncolored audio: gain and EQ reflect
                // user preference and would skew frequency-domain fingerprints.
                // Downsample 44100 Hz stereo → 22050 Hz mono:
                //   - Take every other frame (2:1 decimation; no anti-aliasing
                //     filter needed — fingerprint content is ≤ 5 kHz, well
                //     below the 11025 Hz Nyquist of the tap output rate).
                //   - Average L+R channels to produce a mono signal.
                // Written under _id_mutex (held for microseconds); the control
                // thread holds _id_mutex only during an explicit snapshot
                // request, so contention is negligible.
                if (!_id_buf.empty())
                {
                    int id_count = out_frames / 2;
                    for (int i = 0; i < id_count; ++i)
                    {
                        float L    = float_out[i * 4];      // frame i*2, left channel
                        float R    = float_out[i * 4 + 1];  // frame i*2, right channel
                        float mono = (L + R) * 0.5f;
                        // Clamp before int16 conversion to guard against any
                        // marginal SRC overshoot.
                        if (mono >  1.0f) mono =  1.0f;
                        if (mono < -1.0f) mono = -1.0f;
                        id_tmp[i] = static_cast<int16_t>(mono * 32767.0f);
                    }
                    if (id_count > 0)
                    {
                        std::lock_guard<std::mutex> id_lock(_id_mutex);
                        unsigned wp = _id_write_pos;
                        for (int i = 0; i < id_count; ++i)
                            _id_buf[(wp + static_cast<unsigned>(i)) & ID_BUF_MASK] = id_tmp[i];
                        _id_write_pos     = wp + static_cast<unsigned>(id_count);
                        _id_frames_avail  = std::min(
                            _id_frames_avail + static_cast<unsigned>(id_count),
                            ID_BUF_FRAMES);
                    }
                }

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
                    // from 0 (session start) to RAMP_DURATION_FRAMES (ramp end).
                    // Frames within this block that fall inside the ramp use the
                    // interpolated gain; any frames after the ramp completes
                    // within the same block receive the full gain.
                    int frames_in_ramp = std::min(out_frames, _ramp_frames_remaining);
                    int ramp_pos       = RAMP_DURATION_FRAMES - _ramp_frames_remaining;

                    for (int f = 0; f < frames_in_ramp; ++f)
                    {
                        float ramp_gain = gain * static_cast<float>(ramp_pos + f)
                                                / static_cast<float>(RAMP_DURATION_FRAMES);
                        float_out[f * 2]     *= ramp_gain;
                        float_out[f * 2 + 1] *= ramp_gain;
                    }
                    _ramp_frames_remaining -= frames_in_ramp;

                    // Apply uniform gain to any remaining frames in this block
                    // (those that fall after the ramp completes).
                    if (gain != 1.0f)
                    {
                        for (int f = frames_in_ramp; f < out_frames; ++f)
                        {
                            float_out[f * 2]     *= gain;
                            float_out[f * 2 + 1] *= gain;
                        }
                    }
                }
                else if (gain != 1.0f)
                {
                    // No ramp — apply uniform gain to the whole block.
                    int total_samples = out_frames * 2;
                    for (int s = 0; s < total_samples; ++s)
                        float_out[s] *= gain;
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
                    filter.process(float_out.data(), out_frames);

                // ── Accumulate session effective peak ─────────────────────
                // Scan the post-gain, post-input-EQ float samples.  Deferred
                // to get_status() for the dBFS conversion (no log10 here).
                // This measures the per-input signal level before output EQ.
                {
                    float eff_peak = 0.0f;
                    int total_samples = out_frames * 2;
                    for (int s = 0; s < total_samples; ++s)
                    {
                        float v = std::fabs(float_out[s]);
                        if (v > eff_peak)
                            eff_peak = v;
                    }
                    float prev = _session_effective_peak_linear.load(std::memory_order_relaxed);
                    if (eff_peak > prev)
                        _session_effective_peak_linear.store(eff_peak, std::memory_order_relaxed);
                }

                // ── Output processing and FIFO write (all under _fifo_mutex) ─
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
                {
                    std::lock_guard<std::mutex> lock(_fifo_mutex);
                    if (_allow_capture.load(std::memory_order_relaxed))
                    {
                        // Apply output EQ, output gain, and auto-trim in-place.
                        // Must precede float→int16 so the clip scan sees the
                        // true overshoot before clamping.
                        _output_processor.apply(float_out.data(), out_frames);

                        // ── Accumulate stereo peak for the current VU bin ─────
                        // Tap here: post all output processing, pre int16 cast.
                        // Existing playback detection logic (_current_peak_sample,
                        // _poll_peak_sample) is left completely untouched.
                        for (int f = 0; f < out_frames; ++f)
                        {
                            float l = std::fabs(float_out[f * 2]);
                            float r = std::fabs(float_out[f * 2 + 1]);
                            if (l > _vu_bin_left_peak)  _vu_bin_left_peak  = l;
                            if (r > _vu_bin_right_peak) _vu_bin_right_peak = r;
                        }

                        // Convert to int16.
                        src_float_to_short_array(float_out.data(), pcm_out.data(),
                                                 out_frames * 2);

                        // ── Engineering output dump tap ───────────────────────
                        // First point where the signal is complete s16le after
                        // all SRC, per-input gain/EQ, output EQ, output gain,
                        // and auto-trim.  submit_block() is non-blocking: it
                        // copies into a bounded SPSC ring or drops and counts
                        // frames if the ring is full — never delays this thread.
                        _dump_writer.submit_block(pcm_out.data(), out_frames);

                        if (_prefill_frames_remaining > 0)
                        {
                            // Accumulation phase: append to the pre-fill buffer.
                            // Do not write to the FIFO yet.
                            const int16_t* src_ptr = pcm_out.data();
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
                                _shared_fifo.write(_prefill_buf.data(),
                                                   _prefill_buf.size() * sizeof(int16_t));
                                _prefill_buf.clear();
                                _prefill_buf.shrink_to_fit();

                                int remainder = out_frames - to_add;
                                if (remainder > 0)
                                    _shared_fifo.write(src_ptr + static_cast<size_t>(to_add) * 2,
                                                       static_cast<size_t>(remainder) * 2 * sizeof(int16_t));

                                LOG_DEBUG("[input%d] Pre-fill complete; first FIFO write done",
                                          _index);
                            }
                        }
                        else
                        {
                            // Normal phase: write directly to the FIFO.
                            _shared_fifo.write(pcm_out.data(),
                                               static_cast<size_t>(out_frames) * 2 * sizeof(int16_t));
                        }
                    }
                }
            }   // gain/EQ/peak/FIFO block

            }   // while (frames_left > 0)
        }       // if (_capturing.load() && _src_state)

        // ── Update the status snapshot ────────────────────────────────────────
        // level_dbfs is intentionally omitted here; get_status() converts
        // _current_peak_sample to dBFS at read time to keep log10 off this path.
        {
            std::lock_guard<std::mutex> lock(_status_mutex);
            _status.is_silent    = !is_above_threshold;
            _status.is_capturing = _capturing.load();
            _status.detected_hz  = _rate_estimator.estimated_input_rate();
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
