// =============================================================================
// autostream_monitor.h
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Header for the autostream audio monitor daemon.
//
// This program replaces the Python AudioMonitor class, sounddevice, and ffmpeg.
// It is designed to run as a long-lived systemd service that starts at boot
// with no audio device connected.  Python (autostream_core.py) configures it
// at runtime via a Unix domain socket using a simple newline-delimited JSON
// protocol.
//
// Responsibilities:
//   - ALSA audio capture from up to two USB devices
//   - Real-time silence detection and level metering
//   - Adaptive sample-rate conversion (libsamplerate) with clock-drift
//     estimation via a rolling-window IIR rate estimator
//   - User-configurable parametric equalisation (biquad IIR filter bank)
//   - Writing the output stream (s16le stereo 44100 Hz) to a named FIFO
//     that OwnTone watches for AirPlay streaming
//
// What this program does NOT do:
//   - Talk to OwnTone directly (Python continues to do that via HTTP)
//   - Manage WiFi, web UI, or authentication
//
// Socket protocol (newline-delimited JSON):
//
//   Commands Python -> monitor:
//     {"type":"list_devices"}
//     {"type":"configure_input","input":1,"device":"hw:1,0",
//      "silence_threshold_dbfs":-66.0,"silence_seconds":30}
//     {"type":"set_fifo","path":"/tmp/autostream-pipes/autostream.fifo"}
//     {"type":"start_input","input":1}
//     {"type":"stop_input","input":1}
//     {"type":"set_allow_capture","input":1,"allow":true}
//     {"type":"set_eq","input":1,"bands":[{"type":"peak","freq_hz":100.0,
//                                          "gain_db":3.0,"q":0.707}]}
//     {"type":"set_gain","input":1,"gain_db":3.0}
//     {"type":"set_log_level","level":"warning"}
//     {"type":"get_status"}
//     {"type":"get_id_snapshot","input":1}               (max_seconds default 20)
//     {"type":"get_id_snapshot","input":1,"max_seconds":10}
//
//   Responses monitor -> Python (one per command):
//     {"type":"ack","command":"...", "ok":true}
//     {"type":"ack","command":"...", "ok":false,"error":"reason"}
//
//   get_status response:
//     {"type":"status","log_level":"warning","inputs":[
//       {"index":1,"level_dbfs":-42.1,"poll_peak_dbfs":-38.2,"silent":false,
//        "capturing":true,"detected_hz":44097.3,
//        "raw_peak_dbfs":-12.3,"effective_peak_dbfs":-9.1,
//        "started":true,"running":true},
//       {"index":2,"level_dbfs":-90.0,"poll_peak_dbfs":-90.0,"silent":true,
//        "capturing":false,"detected_hz":0.0,
//        "raw_peak_dbfs":-90.0,"effective_peak_dbfs":-90.0,
//        "started":false,"running":false}]}
//   poll_peak_dbfs: maximum raw peak dBFS accumulated since the previous
//   get_status() call.  Reset to -90.0 on each get_status() so each poll
//   sees only the peak from the interval since the last poll.
//
//   get_id_snapshot response -- JSON ack line followed immediately by a raw
//   binary payload of (frames * 2) bytes (signed 16-bit little-endian, mono,
//   22050 Hz, no header).  The client must read exactly frames*2 bytes after
//   the newline.  On error ("ok":false) no binary data follows.
//     {"type":"ack","command":"get_id_snapshot","input":1,"ok":true,
//      "format":"s16le","rate":22050,"channels":1,"frames":N}
//     <N*2 bytes of raw PCM>
//
//   Python polls get_status at whatever rate the UI requires.
//   There is no unsolicited output; all communication is request/response.
//
// Build dependencies:
//   apt-get install libasound2-dev libsamplerate0-dev
//   g++ -std=c++17 -O2 -o autostream_monitor autostream_monitor.cpp \
//       -lasound -lsamplerate -lpthread
// =============================================================================

#pragma once

#include <string>
#include <vector>
#include <array>
#include <set>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <memory>
#include <cstdint>
#include <sys/time.h>      // struct timeval for SO_RCVTIMEO

#include <alsa/asoundlib.h>
#include <samplerate.h>


// =============================================================================
// AlsaDeviceInfo
//
// Describes one ALSA capture device as returned by list_alsa_capture_devices().
// =============================================================================

struct AlsaDeviceInfo
{
    std::string hw_name;        // ALSA hw:* address, e.g. "hw:1,0" or "hw:CARD=CODEC,DEV=0"
    std::string card_name;      // Human-readable card name, e.g. "Cubilux"
    std::string device_name;    // Human-readable device name, e.g. "USB Audio"
};

// Returns all ALSA capture devices visible on the system.
// Uses snd_device_name_hint() so it reflects the current hardware state.
std::vector<AlsaDeviceInfo> list_alsa_capture_devices();


// =============================================================================
// InputConfig
//
// Configuration for one capture channel.  Supplied by Python via the socket.
// =============================================================================

struct InputConfig
{
    std::string alsa_device;               // e.g. "hw:1,0" or "hw:CARD=CODEC,DEV=0"
    float       silence_threshold_dbfs = -66.0f; // dBFS level below which is silent
    int         silence_seconds      = 30;      // silence duration before stopping
};


// =============================================================================
// EqBand
//
// Parameters for one band of the parametric equaliser.
// Coefficients are computed from these using the RBJ Audio EQ Cookbook.
// =============================================================================

struct EqBand
{
    enum class Type
    {
        Peak,
        LowShelf,
        HighShelf,
        LowPass,
        HighPass
    };

    Type  type     = Type::Peak;
    float freq_hz  = 1000.0f;
    float gain_db  = 0.0f;       // not used for LowPass / HighPass
    float q        = 0.707f;
};


// =============================================================================
// BiquadFilter
//
// A single second-order IIR filter section implemented as Direct Form I.
// Operates on interleaved stereo float samples (left-right pairs).
// =============================================================================

class BiquadFilter
{
public:
    BiquadFilter();

    // Compute and store normalised coefficients for the given EQ band.
    // sample_rate is the rate at which this filter will be called.
    void configure(const EqBand& band, float sample_rate);

    // Set coefficients directly (b0, b1, b2, a1, a2 -- a0 assumed = 1).
    void set_coefficients(float b0, float b1, float b2, float a1, float a2);

    // Process n_frames of interleaved stereo float samples in-place.
    void process(float* samples, int n_frames);

    // Reset all delay-line state to zero.
    void reset();

private:
    float _b0, _b1, _b2;   // feedforward coefficients
    float _a1, _a2;         // feedback coefficients (a0 normalised out)

    // Per-channel delay-line state (index 0 = left, index 1 = right).
    float _x1[2], _x2[2];  // previous two input samples
    float _y1[2], _y2[2];  // previous two output samples
};


// =============================================================================
// EqChain
//
// A thread-safe store for the current EQ band list.
//
// Design (copy-on-write via shared_ptr):
//   - set_bands() builds a new immutable band list and swaps the shared_ptr
//     under a very brief mutex hold.
//   - get_bands() returns a copy of the shared_ptr (refcount increment, no
//     allocation).  The caller owns a stable reference until it discards it.
//
// Each InputChannel maintains its own vector<BiquadFilter> with independent
// delay-line state, updated lazily whenever get_bands() returns a new pointer.
// This means the mutex is never held during audio processing.
// =============================================================================

class EqChain
{
public:
    EqChain();

    // Replace all bands.  Holds the mutex only long enough to swap the pointer.
    // Safe to call from any thread at any time.
    void set_bands(const std::vector<EqBand>& bands, float sample_rate);

    // Return the current band list.  The returned shared_ptr is immutable;
    // compare its address against a cached copy to detect changes.
    std::shared_ptr<const std::vector<EqBand>> get_bands() const;

    // The sample rate at which the current bands were configured.
    float sample_rate() const;

private:
    mutable std::mutex                          _mutex;
    std::shared_ptr<const std::vector<EqBand>>  _bands;
    float                                        _sample_rate = 0.0f;
};


// =============================================================================
// RateEstimator
//
// Measures the actual sample rate of an ALSA capture device.  Every time the
// capture thread reads a block of frames, it calls feed().  RateEstimator
// accumulates frames over a rolling window and uses an IIR filter to produce a
// smoothed estimate of the true input rate.  This estimate is used to set the
// libsamplerate conversion ratio so that long-term clock drift between the
// source device and the Pi is corrected without audible pitch artefacts.
// =============================================================================

class RateEstimator
{
public:
    RateEstimator();

    // Reset state and set the reference input and output rates.
    // Call this from the capture thread each time capture starts on a device.
    void reset(int input_rate, int output_rate);

    // Call this from the capture thread each time n_frames new frames arrive.
    // wall_time should be the current monotonic clock time in seconds.
    // After each completed measurement window, the published ratio and rate
    // atomics are updated so other threads can read them without contention.
    void feed(int n_frames, double wall_time);

    // Returns the ratio to pass to libsamplerate: output_rate / estimated_input_rate.
    // Safe to call from any thread.  Reads an atomic -- no lock taken.
    double src_ratio() const;

    // Returns the IIR-smoothed estimate of the actual input rate (Hz).
    // Safe to call from any thread.  Reads an atomic -- no lock taken.
    double estimated_input_rate() const;

private:
    // ── Capture-thread-only state ─────────────────────────────────────────────
    // These fields are read and written exclusively by the capture thread via
    // feed() and reset().  No synchronisation is needed for them.
    int    _input_rate;
    int    _output_rate;
    double _smoothed_rate;
    double _window_start_time;
    long   _window_frame_count;
    bool   _initialised;
    int    _adjustment_count;   // number of windows completed; used to ramp window duration

    // ── Published values (written by capture thread, read by any thread) ──────
    // After each completed measurement window, feed() atomically publishes the
    // updated ratio and rate.  All other internal state stays private above.
    // Note: std::atomic<double> may not be lock-free on ARMv6, but is correct
    // regardless; these values are updated at most once every 10 seconds.
    std::atomic<double> _published_ratio;   // output_rate / smoothed_rate
    std::atomic<double> _published_rate;    // smoothed_rate (Hz)

    // Maximum (steady-state) measurement window.  At startup the window is
    // ramped from 1 second up to this value over the first WINDOW_SECONDS
    // completed windows (i.e. windows of 1 s, 2 s, … 10 s).  This lets the
    // SRC ratio converge quickly on the first capture session while avoiding
    // audible artefacts from abrupt ratio changes during steady-state playback.
    static constexpr double WINDOW_SECONDS = 10.0;

    // IIR smoothing factor.  0.15 means each new measurement contributes 15%
    // of the new estimate and 85% carries over from the previous estimate.
    static constexpr double ALPHA = 0.15;
};


// =============================================================================
// AlsaCapture
//
// Wraps a single ALSA PCM capture device.  Configured for:
//   - S16_LE format (signed 16-bit little-endian)
//   - Interleaved stereo (2 channels)
//   - Highest available capture rate not exceeding 48000 Hz
//   - Hardware period of approximately 1024 frames
// =============================================================================

class AlsaCapture
{
public:
    AlsaCapture();
    ~AlsaCapture();

    // Open the device and configure hardware parameters.
    // Automatically selects the highest available capture rate <= 48000 Hz.
    // Returns true on success; logs and returns false on any ALSA error.
    bool open(const std::string& hw_device, int channels = 2);

    // Close the device and release the ALSA handle.
    void close();

    // Read up to n_frames frames into buf (interleaved int16, n_frames * channels values).
    // Returns the number of frames read (may be less than n_frames).
    // Returns 0 if an xrun (overrun) occurred but was successfully recovered.
    // Returns -1 on an unrecoverable error; caller should close and reopen.
    int read(int16_t* buf, int n_frames);

    // The period size that ALSA negotiated with the hardware.
    // Acquires _read_mutex; safe to call from any thread.
    int  period_frames() const;

    // The sample rate selected by the monitor and accepted by ALSA.
    // Valid only while is_open() is true; returns 0 after close().
    // Acquires _read_mutex; safe to call from any thread.
    int  actual_rate()   const;

    // Acquires _read_mutex; safe to call from any thread.
    bool is_open()       const;

private:
    // _read_mutex serialises close() against read(), is_open(), period_frames(),
    // and actual_rate().  All readers of _pcm, _period_frames, and _actual_rate
    // must hold this mutex, because close() (called from the stop/main thread)
    // writes all three fields concurrently with the capture thread reading them.
    // close() blocks for at most one audio period (~21 ms) until any in-progress
    // read completes; that is acceptable for a stop operation.
    mutable std::mutex _read_mutex;

    snd_pcm_t* _pcm           = nullptr;
    int        _period_frames = 0;
    int        _actual_rate   = 0;
};


// =============================================================================
// FifoWriter
//
// Writes raw PCM data to a named FIFO (mkfifo pipe) watched by OwnTone.
// The file descriptor is opened and kept in O_NONBLOCK mode throughout:
//
//   - If no reader has the FIFO open yet (ENXIO), try_open() fails silently;
//     the next write() call will retry.  This prevents blocking the process
//     thread while OwnTone is starting up.
//
//   - If the pipe buffer is full (EAGAIN), the block is dropped and a throttled
//     warning is logged.  A stalled OwnTone will not freeze the process thread.
//
// Thread safety: all public methods must be called under AudioMonitor::_fifo_mutex.
// This is enforced by convention -- FifoWriter has no mutex of its own.
// =============================================================================

class FifoWriter
{
public:
    FifoWriter();
    ~FifoWriter();

    // Store the FIFO path.  Closes any currently open fd.
    // Caller must hold AudioMonitor::_fifo_mutex.
    void set_path(const std::string& path);

    // Write len bytes from data to the FIFO.
    // If not yet open, attempts to open first.
    // Returns true if all bytes were written.
    // Returns false and drops data on ENXIO (no reader) or EAGAIN (buffer full).
    // Caller must hold AudioMonitor::_fifo_mutex.
    bool write(const void* data, size_t len);

    // Close the file descriptor (does not delete the FIFO).
    // Caller must hold AudioMonitor::_fifo_mutex.
    void close();

    bool is_open()             const { return _fd >= 0; }
    const std::string& path()  const { return _path; }

private:
    bool try_open();    // internal: attempt non-blocking open

    int         _fd                  = -1;
    std::string _path;
    double      _stall_last_log_time = 0.0;   // for throttling EAGAIN warnings
};


// =============================================================================
// InputChannelStatus
//
// A thread-safe snapshot of one input channel's current state.
// Returned by get_status() in response to a get_status socket command.
// =============================================================================

struct InputChannelStatus
{
    int    index                  = 0;
    float  level_dbfs             = -90.0f;  // peak dBFS of the most recent block
    float  poll_peak_dbfs         = -90.0f;  // max raw dBFS since the last get_status() call
    bool   is_silent              = true;
    bool   is_capturing           = false;
    double detected_hz            = 0.0;
    float  raw_peak_dbfs          = -90.0f;  // maximum raw dBFS seen this capture session
    float  effective_peak_dbfs    = -90.0f;  // maximum dBFS after pre-amp and EQ this session

    // Thread lifecycle state -- used by the Python controller to detect
    // the degraded case where the capture thread self-stopped after an
    // unrecoverable ALSA error but stop_input has not been called.
    // A controller that sees is_started=true && is_running=false should
    // issue stop_input then start_input to recover.
    bool   is_started             = false;   // start() has been called and stop() not yet completed
    bool   is_running             = false;   // capture thread is actively running
};


// =============================================================================
// InputChannel
//
// Manages one audio input (one ALSA device).  Contains two threads:
//
//   capture thread  -- reads raw PCM from ALSA and pushes it into a ring buffer
//   process thread  -- drains the ring buffer, measures levels, resamples via
//                     libsamplerate, applies the shared EQ chain, and writes
//                     to the shared FIFO when allow_capture is true
//
// Both threads are created only when start() is called; start() requires that
// configure() has been called first with a valid InputConfig.
// =============================================================================

class InputChannel
{
public:
    // index:       1 or 2, used only in log messages
    // shared_fifo: the AudioMonitor's FifoWriter (both inputs write here)
    // fifo_mutex:  a mutex owned by AudioMonitor that serialises FIFO writes
    InputChannel(int         index,
                 FifoWriter& shared_fifo,
                 std::mutex& fifo_mutex);

    ~InputChannel();

    // Store the configuration.
    // If the channel is stopped: stores all fields.
    // If the channel is running: only silence_threshold_dbfs and silence_seconds
    //   are applied immediately; changes to alsa_device are rejected (caller
    //   must stop the channel first).
    // Returns true on success, false if alsa_device was changed while running.
    bool configure(const InputConfig& cfg);

    // Start the capture and processing threads.
    // Returns false if no valid configuration has been set, if already running,
    // or if ALSA/libsamplerate setup fails. If error_out is non-null, it
    // receives a user-facing error string describing the failure.
    bool start(std::string* error_out = nullptr);

    // Stop both threads, close ALSA, and free libsamplerate state.
    void stop();

    // Allow or suppress writing to the FIFO.
    // When false, this channel continues monitoring levels but writes nothing.
    void set_allow_capture(bool allow);

    // Replace the EQ band list for this input.
    // Applied on the resampled output (44100 Hz) in the process thread.
    // Safe to call while running.
    void set_eq(const std::vector<EqBand>& bands);

    // Set the pre-amplifier gain applied to this input before EQ.
    // gain_db is in the range [-24, +24].  Applied in the float domain after SRC.
    // Safe to call while running.
    void set_gain(float gain_db);

    // Returns a snapshot of the channel's current state (thread-safe).
    InputChannelStatus get_status() const;

    bool is_running() const { return _running.load(); }

    // Returns true if start() has been called and stop() has not yet completed
    // (includes the case where the capture thread self-stopped after an ALSA
    // error but stop() has not been called to join the threads).  Use this to
    // detect the crashed-but-not-cleaned-up state in api_start_input().
    bool is_started() const { return _started.load(); }

    // Copy the most recent min(max_frames, ID_BUF_FRAMES) mono s16le 22050 Hz
    // frames into out[0..return_value-1], ordered oldest-first.  Returns the
    // number of frames actually copied (may be less than max_frames if the
    // buffer has not yet accumulated that many frames since the last start()).
    // Thread-safe; acquires _id_mutex.  Safe to call while the channel is
    // running or after it has stopped.
    unsigned get_id_snapshot(int16_t* out, unsigned max_frames) const;

    // Sample rate and capacity of the identification snapshot buffer.
    static constexpr unsigned ID_BUF_RATE   = 22050;
    static constexpr unsigned ID_BUF_FRAMES = 1u << 19;  // 524288 ≈ 23.7 s

private:
    // ── Thread functions ─────────────────────────────────────────────────────
    void capture_thread_func();
    void process_thread_func();

    // ── Helpers ──────────────────────────────────────────────────────────────

    // Returns the peak absolute sample value (0..32768) across all channels.
    // Note: INT16_MIN (-32768) negated as int yields 32768, so the range
    // is 0..32768, not 0..32767.
    // Pure integer arithmetic -- no float.  The dBFS conversion is deferred to
    // get_status() so that log10 stays off the hot path.
    int compute_peak_sample(const int16_t* samples,
                             int            n_frames,
                             int            n_channels) const;

    // ── Identity ─────────────────────────────────────────────────────────────
    int         _index;

    // ── Shared resources (owned by AudioMonitor) ─────────────────────────────
    FifoWriter& _shared_fifo;
    std::mutex& _fifo_mutex;

    // ── Per-input EQ (owned by this channel) ─────────────────────────────────
    // set_eq() publishes new bands via EqChain::set_bands().  The process thread
    // picks them up lazily via get_bands() without ever holding a lock during
    // filter processing (see _local_filters / _current_eq_bands below).
    EqChain   _eq_chain;

    // ── Per-input pre-amp gain ────────────────────────────────────────────────
    // Stored as a linear multiplier so the process thread can apply it with a
    // single multiply loop -- no pow() on the hot path.
    // Written by set_gain() (control thread), read by process_thread_func().
    std::atomic<float> _gain_linear{1.0f};

    // ── Configuration ────────────────────────────────────────────────────────
    mutable std::mutex _config_mutex;
    InputConfig        _config;
    bool               _config_valid            = false;
    std::atomic<int>   _silence_threshold_sample{0};  // pre-computed from config.silence_threshold_dbfs

    // ── ALSA capture ─────────────────────────────────────────────────────────
    AlsaCapture _alsa;

    // ── libsamplerate state (created in start(), freed in stop()) ────────────
    SRC_STATE*    _src_state = nullptr;

    // ── Sample rate estimation ────────────────────────────────────────────────
    RateEstimator _rate_estimator;

    // ── SPSC ring buffer between capture thread and process thread ────────────
    // Stores interleaved stereo int16 samples.  Size is a power of two so that
    // positions can be masked instead of divided.
    // At 48000 Hz stereo, this holds approximately 2.7 seconds of audio.
    static constexpr unsigned RING_BUF_SAMPLES = 1u << 18;  // 262144
    static constexpr unsigned RING_BUF_MASK    = RING_BUF_SAMPLES - 1u;

    std::vector<int16_t>      _ring_buf;         // sized to RING_BUF_SAMPLES
    std::atomic<unsigned int> _ring_write_pos{0}; // written only by capture thread
    std::atomic<unsigned int> _ring_read_pos{0};  // written only by process thread

    // Condition variable used by the process thread to sleep until data is
    // available without busy-waiting.  The capture thread calls notify_one()
    // after each ring-buffer write.  notify_one() is safe to call without
    // holding _ring_cv_mutex; the process thread uses a wait_for with a
    // predicate so any missed notification is recovered within the timeout.
    std::mutex               _ring_cv_mutex;
    std::condition_variable  _ring_cv;

    // ── Capture thread private state ─────────────────────────────────────────
    double _ring_overflow_last_log_time = 0.0;  // throttle for ring-full warning

    // ── Silence tracking (process thread only) ────────────────────────────────
    double _last_above_threshold_time = 0.0;   // monotonic seconds; 0 = never

    // ── Fade-in ramp (process thread only) ───────────────────────────────────
    // When a capture session starts, _ramp_frames_remaining is set to
    // RAMP_DURATION_FRAMES (one second of output frames).  Each processed block
    // decrements the counter until it reaches zero, at which point the ramp is
    // complete and full gain is applied.  The ramp is combined with _gain_linear
    // in a single per-frame multiply so no extra pass over the buffer is needed.
    int _ramp_frames_remaining{0};

    // ── FIFO pre-fill buffer (process thread only) ────────────────────────────
    // At the start of each capture session, PREFILL_DURATION_FRAMES of
    // post-gain/EQ/ramp int16 samples are accumulated here before any data is
    // written to the FIFO.  Once the threshold is reached the buffer is flushed
    // in a single write (giving OwnTone a full pipe buffer to start from) and
    // subsequent blocks are written directly.
    // _prefill_frames_remaining counts down from PREFILL_DURATION_FRAMES to 0;
    // while it is > 0 we are in the accumulation phase.
    int                  _prefill_frames_remaining{0};
    std::vector<int16_t> _prefill_buf;

    // ── Level metering ────────────────────────────────────────────────────────
    // Written by the process thread every block; read by get_status().
    // Stored as integer / linear float so the process thread never calls log10.
    std::atomic<int>   _current_peak_sample{0};        // current-block raw peak (0..32768)
    mutable std::atomic<int> _poll_peak_sample{0};    // max raw peak since last get_status() call; mutable so exchange(0) is callable from const get_status()
    std::atomic<int>   _session_raw_peak_sample{0};     // session max raw peak
    std::atomic<float> _session_effective_peak_linear{0.0f}; // session max effective peak (linear, >=0)

    // ── Per-channel EQ filter state (process thread only) ────────────────────
    // Rebuilt lazily whenever _eq_chain publishes a new band list.
    std::vector<BiquadFilter>                  _local_filters;
    std::shared_ptr<const std::vector<EqBand>> _current_eq_bands;

    // ── Thread control ────────────────────────────────────────────────────────
    std::atomic<bool> _running{false};
    std::atomic<bool> _allow_capture{false};
    std::atomic<bool> _capturing{false};

    // Set true by start() before threads are spawned; cleared by stop() via
    // exchange(false).  Used instead of _running as the guard in stop() so
    // that stop() always runs full cleanup even when the capture thread has
    // already stored _running = false and exited after an unrecoverable error.
    std::atomic<bool> _started{false};

    // ── Status snapshot (mutex-protected fields) ─────────────────────────────
    mutable std::mutex _status_mutex;
    InputChannelStatus _status;

    // ── Identification snapshot buffer ────────────────────────────────────────
    //
    // A separate rolling buffer that accumulates mono s16le audio at 22050 Hz
    // for use by external fingerprinting tools (e.g. Chromaprint/AcoustID).
    //
    // Tap point: post-SRC (44100 Hz stereo float), pre-gain/pre-EQ.
    //   - Post-SRC: uses a stable, device-independent rate, avoiding the need
    //     for a second resampler.
    //   - Pre-gain/pre-EQ: the identification buffer captures uncolored audio
    //     content.  User gain and EQ settings reflect personal preference and
    //     would skew frequency-domain fingerprints if included.
    //   - Gated by _capturing: SRC only runs while _capturing is true, so the
    //     buffer fills only during active audio sessions.  The 20-second window
    //     is sufficient for Chromaprint (which needs ≥ ~3 s) across any normal
    //     song.
    //
    // Downsampling: every other SRC output frame is averaged (L+R)*0.5 and
    // converted to int16.  No anti-aliasing filter is applied; at 22050 Hz
    // the useful fingerprint content (≤ 5 kHz) is well below the Nyquist of
    // 11025 Hz, and the absence of a filter has no practical effect on
    // fingerprint accuracy.
    //
    // Concurrency: _id_mutex is held by the process thread during each chunk
    // write (O(chunk_size) bytes, ~microseconds) and by the control thread for
    // the full snapshot copy (~200 µs worst case).  The process thread is not
    // real-time so this brief contention is acceptable.
    static constexpr unsigned ID_BUF_MASK    = ID_BUF_FRAMES - 1u;

    mutable std::mutex   _id_mutex;
    std::vector<int16_t> _id_buf;              // allocated in start(); ID_BUF_FRAMES entries
    unsigned             _id_write_pos   = 0;  // total frames written; use & ID_BUF_MASK for index
    unsigned             _id_frames_avail = 0; // frames available to read; saturates at ID_BUF_FRAMES

    // ── Thread handles ────────────────────────────────────────────────────────
    std::thread _capture_thr;
    std::thread _process_thr;
};


// =============================================================================
// AudioMonitor (forward declaration for ControlServer)
// =============================================================================

class AudioMonitor;


// =============================================================================
// ControlServer
//
// Listens on a Unix domain socket for newline-delimited JSON commands from
// Python.  Supports multiple concurrent clients; each accepted socket is
// handled on its own worker thread. Each command receives exactly one response
// line. The accept loop runs on a background thread.
// =============================================================================

class ControlServer
{
public:
    explicit ControlServer(AudioMonitor& monitor);
    ~ControlServer();

    // Create the socket file, bind, and begin accepting connections.
    // Returns false if the socket cannot be created.
    bool start(const std::string& socket_path);

    // Signal the accept loop to stop, interrupt all clients, and join threads.
    void stop();

private:
    void accept_loop();

    // Read commands from one connected client until it disconnects.
    void handle_client(int client_fd);

    // Parse and dispatch one JSON command string; returns a JSON response string.
    // For get_id_snapshot commands that succeed, snapshot_out is filled with
    // the binary PCM payload; the caller sends it immediately after the JSON
    // response line.  snapshot_out is always cleared on entry.
    std::string dispatch_command(const std::string& json_command,
                                  std::vector<int16_t>* snapshot_out);

    // Idle clients that send no command within this many seconds are disconnected.
    // Must be long enough to cover the coordinator's OwnTone HTTP callbacks
    // (owntone_disable_all_outputs + output-selection retries, each up to 3 s,
    // potentially chained for ~12 s when OwnTone is slow).  20 s gives adequate
    // headroom while still being short enough that a dead Python client (e.g.
    // mid-restart) is cleaned up well before Python's own 5 s connect timeout
    // would fire on a second reconnect attempt.
    static constexpr int CLIENT_TIMEOUT_SECONDS = 20;

    AudioMonitor&     _monitor;
    int               _server_fd = -1;
    std::string       _socket_path;
    std::atomic<bool> _running{false};
    std::thread       _accept_thread;

    // Tracked so stop() can interrupt all blocked clients and join their
    // worker threads cleanly.
    std::mutex              _clients_mutex;
    std::set<int>           _client_fds;
    std::vector<std::thread> _client_threads;
};


// =============================================================================
// AudioMonitor
//
// The top-level object.  Owns the two InputChannels, the shared FifoWriter,
// and the ControlServer.  Provides the API methods that ControlServer calls
// in response to socket commands.
// =============================================================================

class AudioMonitor
{
public:
    explicit AudioMonitor(const std::string& socket_path);
    ~AudioMonitor();

    static constexpr int output_rate_hz() { return OUTPUT_RATE; }

    // Start the control server, then block until stop() is called or a signal
    // is received.  Python polls status via the get_status socket command.
    void run();

    // Signal the monitor to shut down cleanly.
    void stop();

    // ── Socket API methods (called by ControlServer::dispatch_command) ────────
    // Each method returns a complete JSON response string. handle_client()
    // appends the trailing newline before sending it to the client.

    std::string api_list_devices();

    std::string api_configure_input(int input_index, const InputConfig& cfg);

    std::string api_set_fifo(const std::string& path);

    std::string api_start_input(int input_index);

    std::string api_stop_input(int input_index);

    std::string api_set_allow_capture(int input_index, bool allow);

    // Set EQ bands for one input (1 or 2).  Applied to the resampled output.
    std::string api_set_eq(int input_index, const std::vector<EqBand>& bands);

    // Set pre-amplifier gain for one input (1 or 2).  gain_db in [-24, +24].
    std::string api_set_gain(int input_index, float gain_db);

    // Update the monitor's runtime log level.
    std::string api_set_log_level(const std::string& level_text);

    // Return a status snapshot for all inputs.
    std::string api_get_status();

    // Copy up to max_seconds (1..20) of recent mono 22050 Hz audio for the
    // given input into binary_out (s16le, no header), returning a JSON ack.
    // binary_out is populated only when "ok":true; the caller sends the bytes
    // as a raw binary payload immediately after the JSON response line.
    std::string api_get_id_snapshot(int input_index, int max_seconds,
                                     std::vector<int16_t>* binary_out);

private:
    // Returns a pointer to the InputChannel for the given 1-based index,
    // or nullptr if the index is out of range.
    InputChannel* get_input(int input_index);

    static constexpr int NUM_INPUTS  = 2;
    static constexpr int OUTPUT_RATE = 44100;

    // Back-off interval (seconds) before retrying a failed auto-restart.
    static constexpr double RESTART_BACKOFF_SECONDS = 5.0;

    std::string _socket_path;

    FifoWriter  _fifo_writer;
    std::mutex  _fifo_mutex;

    // _inputs[0] is input 1, _inputs[1] is input 2.
    std::array<std::unique_ptr<InputChannel>, NUM_INPUTS> _inputs;

    ControlServer _control_server;

    // Per-input monotonic timestamp after which an automatic restart may be
    // attempted.  Zero-initialised so the first crash triggers an immediate
    // restart attempt; set to now + RESTART_BACKOFF_SECONDS after each
    // failed attempt to prevent a tight retry loop.
    std::array<double, NUM_INPUTS> _restart_after{};

    std::atomic<bool> _running{false};

    // Condition variable used to wake run() early when stop() is called so
    // that shutdown latency is not bounded by the 100 ms watchdog interval.
    std::mutex              _run_cv_mutex;
    std::condition_variable _run_cv;
};
