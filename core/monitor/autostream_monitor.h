// =============================================================================
// autostream_monitor.h
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Header for the autostream audio monitor daemon.
//
// This native daemon replaces the previous Python AudioMonitor/sounddevice/
// ffmpeg pipeline.  It runs as a long-lived service, captures from up to two
// ALSA USB inputs, performs silence detection, rate correction, EQ/gain
// processing, and writes a 44.1 kHz stereo PCM stream to a named FIFO.
//
// Python remains responsible for higher-level orchestration, UI, settings, and
// playback-backend control.  At runtime it configures and polls the daemon via
// a newline-delimited JSON socket API.
//
// Documentation split:
//   - This header documents the code-facing API, object model, and invariants.
//   - docs/AUTOSTREAM-MONITOR.md is the canonical external protocol/reference
//     document for commands, responses, examples, and integration behavior.
//
// Build dependencies:
//   apt-get install libasound2-dev libsamplerate0-dev
//   g++ -std=c++17 -O2 -o autostream_monitor \
//       autostream_monitor.cpp \
//       autostream_monitor_dsp.cpp \
//       autostream_monitor_io.cpp \
//       autostream_monitor_utils.cpp \
//       -lasound -lsamplerate -lpthread
// =============================================================================

#pragma once

#include "autostream_monitor_utils.h"

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

// Build identifier compiled into the monitor binary and reported via the
// socket API.  This is intentionally maintained in source so an older running
// binary can be detected after an update if the monitor rebuild failed.
inline constexpr char AUTOSTREAM_MONITOR_BUILD[] = "0.2.0";


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
// OutputGainState
//
// A snapshot of the current output-side gain state returned by
// OutputProcessor::get_gain_state() and included in get_status responses.
// =============================================================================

struct OutputGainState
{
    float manual_gain_db;    // configured manual output gain (set_output_gain)
    bool  auto_trim_enabled; // whether auto-trim is currently active
    float auto_trim_db;      // current auto-trim cut in dB (always <= 0)
    float effective_gain_db; // manual_gain_db + auto_trim_db
};


// =============================================================================
// OutputProcessor
//
// Applies a user-configurable parametric EQ to the output stream, applies
// manual and automatic output gain, and tracks clipping.  There is one
// instance owned by AudioMonitor; a reference to it is threaded into every
// InputChannel so each process thread can call apply() from the same location
// in the signal chain.
//
// Design notes:
//
//   Quick-path: _is_flat is true when the output EQ has no audible effect
//   (empty band list, or every Peak/LowShelf/HighShelf band has gain_db == 0).
//   apply() reads _is_flat with a relaxed atomic load before touching any mutex;
//   when flat, no lock is acquired and no filter arithmetic is performed.
//   At most one audio block (~23 ms) may pass without the new EQ taking effect
//   after set_bands() is called — imperceptible in practice.
//
//   Filter state lifetime: _local_filters and _current_bands are protected by
//   _apply_mutex.  Although only one InputChannel has _allow_capture = true at
//   any instant, the brief handoff window during set_allow_capture() means two
//   process threads could call apply() concurrently.  _apply_mutex closes that
//   window without adding overhead on the quick-path (which never acquires it).
//   The filter state persists across input handoffs so the output stream is
//   continuous.
//
//   Output gain: after the EQ step, apply() multiplies every sample by the
//   effective linear gain derived from manual_gain_db + auto_trim_db.  Both
//   values are read as atomics with relaxed ordering; a one-block lag on change
//   is imperceptible.  When both are zero the multiply loop is skipped entirely.
//
//   Auto-trim: when enabled, apply() detects post-gain clipping (peak > 1.0)
//   and cuts auto_trim_db by exactly the overshoot in dB, clamped to
//   AUTO_TRIM_FLOOR_DB.  The trim accumulates downward within a session (it is
//   never boosted back) and is reset to 0 by reset_auto_trim(), which is called
//   by AudioMonitor on input handoff (set_allow_capture(true)) and on stop_input.
//   Enabling auto-trim via set_auto_trim_enabled(true) also resets the trim.
//   The CAS keep-minimum loop in apply() handles the brief concurrent window
//   during handoff safely.
//
//   Clip tracking: the clip scan always runs, after the output gain step, so
//   it reflects the true final level seen before float-to-int16 conversion.
//   _clip_peak_linear is updated via a CAS keep-maximum loop;
//   poll_clip_overshoot_dbfs() exchanges it for 0.0f (matching the
//   poll_peak_dbfs reset pattern on inputs).
// =============================================================================

class OutputProcessor
{
public:
    OutputProcessor();

    // Replace all output EQ bands.
    // Recomputes _is_flat: true iff bands is empty or every band is a
    // Peak/LowShelf/HighShelf type with gain_db == 0.0f.
    // LowPass and HighPass bands always set _is_flat = false.
    // Safe to call from any thread at any time.
    void set_bands(const std::vector<EqBand>& bands, float sample_rate);

    // Apply the output EQ, output gain, and auto-trim to n_frames of
    // interleaved stereo float samples in-place, then scan for clipping.
    // Signal chain within apply():
    //   1. Output EQ (skipped when _is_flat is true)
    //   2. Effective output gain = manual_gain_db + auto_trim_db (skipped at 0)
    //   3. Clip scan (always runs; updates _clip_peak_linear)
    //   4. Auto-trim update (when enabled and clipping detected)
    // Safe to call concurrently from two process threads (EQ step guarded by
    // _apply_mutex; gain/clip/trim steps use only atomics); in practice only
    // one is active at a time.
    void apply(float* samples, int n_frames);

    // Set the manual output gain applied after the output EQ.
    // gain_db must be in [OUTPUT_GAIN_MIN_DB, OUTPUT_GAIN_MAX_DB].
    // Safe to call from any thread at any time; a one-block lag is acceptable.
    void set_manual_gain(float gain_db);

    // Enable or disable automatic output trimming.
    // When enabled, apply() reacts to post-EQ/gain clipping by cutting the
    // trim enough to prevent equivalent future clipping.  The trim only cuts,
    // never boosts, and accumulates within a session (reset by reset_auto_trim).
    // Enabling always resets the current trim to 0.0 dB.
    // Safe to call from any thread at any time.
    void set_auto_trim_enabled(bool enabled);

    // Reset the auto-trim attenuation to 0.0 dB.
    // Called by AudioMonitor on input handoff (set_allow_capture(true)) and on
    // stop_input so each new capture session starts from zero trim.
    // Does not change whether auto-trim is enabled.
    // Safe to call from any thread at any time.
    void reset_auto_trim();

    // Return the maximum absolute sample value (in dB above 0 dBFS) seen
    // since the last call, and atomically reset the accumulator to zero.
    // Returns 0.0f when no sample has exceeded 1.0 in absolute value.
    // Safe to call from any thread; uses a single atomic exchange.
    float poll_clip_overshoot_dbfs();

    // Return a snapshot of the current output gain state.
    // Safe to call from any thread at any time.
    OutputGainState get_gain_state() const;

    // Manual gain range enforced by validate_output_gain_db().
    static constexpr float OUTPUT_GAIN_MIN_DB = -10.0f;
    static constexpr float OUTPUT_GAIN_MAX_DB = +10.0f;

    // Maximum attenuation the auto-trim is allowed to accumulate.
    static constexpr float AUTO_TRIM_FLOOR_DB = -10.0f;

private:
    // ── Band configuration ────────────────────────────────────────────────────
    EqChain _eq_chain;   // COW store; set_bands() publishes, apply() reads lazily

    // ── Quick-path flag ───────────────────────────────────────────────────────
    // Written by set_bands() with relaxed ordering after _eq_chain.set_bands().
    // Read by apply() with relaxed ordering before acquiring _apply_mutex.
    // A one-block lag on transition is acceptable (see class note above).
    std::atomic<bool> _is_flat{true};

    // ── Filter state (access under _apply_mutex) ──────────────────────────────
    std::mutex                                  _apply_mutex;
    std::vector<BiquadFilter>                   _local_filters;
    std::shared_ptr<const std::vector<EqBand>>  _current_bands;

    // ── Manual output gain ────────────────────────────────────────────────────
    // Written by set_manual_gain() (control thread), read by apply() (process
    // thread).  Relaxed ordering is sufficient; a one-block lag is acceptable.
    std::atomic<float> _manual_gain_db{0.0f};

    // ── Auto-trim state ───────────────────────────────────────────────────────
    // _auto_trim_enabled: written by set_auto_trim_enabled() (control thread),
    //   read by apply() (process thread).  Relaxed ordering is sufficient.
    // _auto_trim_db: written by apply() via a CAS keep-minimum loop when
    //   clipping is detected, and reset to 0 by set_auto_trim_enabled(true) and
    //   reset_auto_trim().  The auto-trim only accumulates downward, so the CAS
    //   loop handles concurrent calls during the brief input-handoff window.
    std::atomic<bool>  _auto_trim_enabled{false};
    std::atomic<float> _auto_trim_db{0.0f};

    // ── Clip accumulator ──────────────────────────────────────────────────────
    // Maximum absolute sample value seen since the last poll_clip_overshoot_dbfs()
    // call.  1.0 == 0 dBFS; values above 1.0 indicate clipping.
    // Updated with a CAS keep-maximum loop in apply(); reset via exchange(0)
    // in poll_clip_overshoot_dbfs().
    std::atomic<float> _clip_peak_linear{0.0f};
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
// OutputDumpWriter
//
// Engineering-only tap that records the final processed audio stream to a WAV
// file on demand, without disturbing the normal FIFO delivery path.
//
// Signal tap point: inside InputChannel::process_thread_func(), immediately
// after _output_processor.apply() and src_float_to_short_array() — the first
// point where the signal is complete 44.1 kHz stereo s16le after all SRC,
// per-input gain/EQ, output EQ, output gain, and auto-trim.  The tap is gated
// by the _allow_capture flag, so the WAV reflects only the active FIFO-feeding
// input.  Pre-fill frames (the initial 0.5 s buffer accumulated before the
// first FIFO write) ARE captured; the WAV therefore starts from time zero even
// though OwnTone has not yet received those frames.
//
// Thread model:
//   - submit_block()    called by the audio process thread (inside _fifo_mutex)
//   - writer thread     drains the ring to disk; owned by this object
//   - start() / stop()  called by the control thread (ControlServer worker)
//
// The audio thread only copies frames into a bounded SPSC ring (never blocks).
// If the ring fills, frames are counted in dropped_frames and discarded —
// normal FIFO delivery is never delayed.  The writer thread drains the ring
// to a stdio-buffered FILE* on its own schedule.
//
// Control via the Unix socket API:
//   {"type":"start_output_dump","path":"/tmp/test.wav"}
//   {"type":"start_output_dump","path":"/tmp/test.wav","overwrite":true}
//   {"type":"stop_output_dump"}
// =============================================================================

class OutputDumpWriter
{
public:
    struct Status
    {
        bool        active         = false;
        std::string path;
        uint64_t    frames_written = 0;  // stereo frames written to disk
        uint64_t    dropped_frames = 0;  // stereo frames dropped (ring full)
    };

    OutputDumpWriter();
    ~OutputDumpWriter();

    // Open path and begin recording.  Writes a 44-byte WAV placeholder header
    // (sizes are patched on stop()).  Returns "" on success or a non-empty
    // error string on failure.  Must not be called while a dump is already active.
    // overwrite: if false, rejects the call when a file already exists at path.
    std::string start(const std::string& path, bool overwrite);

    // Flush, patch WAV header, and close.  No-op if no dump is active.
    // was_active_out (if non-null) is set to indicate whether a recording was
    // in progress before this call.  Called automatically by ~OutputDumpWriter().
    void stop(bool* was_active_out = nullptr);

    // Submit out_frames stereo s16le samples for recording.
    // Called from the audio process thread under AudioMonitor::_fifo_mutex.
    // Non-blocking: drops and counts frames when the ring is full.
    void submit_block(const int16_t* samples, int out_frames);

    // True while a dump is in progress.  Safe to call from any thread.
    bool is_active() const { return _active.load(std::memory_order_relaxed); }

    // Thread-safe snapshot of the current recording state.
    Status get_status() const;

private:
    void writer_thread_func();

    // SPSC ring buffer: 2^18 stereo s16le samples ≈ 2.97 s at 44.1 kHz.
    // submit_block() is the single producer; writer_thread_func() is the
    // single consumer.  Both positions are atomic to satisfy the C++ memory
    // model for inter-thread reads.
    static constexpr uint32_t DUMP_RING_SAMPLES = 1u << 18;   // 262144
    static constexpr uint32_t DUMP_RING_MASK    = DUMP_RING_SAMPLES - 1u;

    std::vector<int16_t>    _ring;
    std::atomic<uint32_t>   _ring_write_pos{0};  // written only by audio thread
    std::atomic<uint32_t>   _ring_read_pos{0};   // written only by writer thread

    std::thread             _writer_thread;
    std::mutex              _cv_mutex;
    std::condition_variable _cv;

    // _active is cleared before _stop_requested is set so the audio thread
    // stops submitting new frames as early as possible during stop().
    std::atomic<bool>       _active{false};
    std::atomic<bool>       _stop_requested{false};

    // _file is opened by start(), owned by the writer thread during the
    // recording session, and closed (after WAV header patch) by stop().
    FILE*                   _file{nullptr};

    // _path is written once in start() under _mutex; read in stop() and
    // get_status() — also under _mutex.
    std::string             _path;

    std::atomic<uint64_t>   _frames_written{0};  // updated by writer thread
    std::atomic<uint64_t>   _dropped_frames{0};  // updated by audio thread

    // Serialises start()/stop() against each other and protects _path reads
    // in get_status().  Held for the full duration of stop() (including the
    // writer thread join), which is fast in practice because draining an
    // in-memory ring to the stdio page cache takes microseconds.
    mutable std::mutex      _mutex;
};


// =============================================================================
// VuBin
//
// One 100 ms bin of stereo peak history, produced by the process thread after
// all output processing (gain, EQ, auto-trim) and before the float→int16
// conversion.  Used to drive the home-page delayed VU meter display.
// =============================================================================

struct VuBin
{
    uint32_t seq        = 0;       // monotonically increasing; resets on channel restart
    float    left_dbfs  = -90.0f;  // peak dBFS of the left channel in this bin
    float    right_dbfs = -90.0f;  // peak dBFS of the right channel in this bin
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
    // index:            1 or 2, used only in log messages
    // shared_fifo:      the AudioMonitor's FifoWriter (both inputs write here)
    // fifo_mutex:       a mutex owned by AudioMonitor that serialises FIFO writes
    // output_processor: the AudioMonitor's OutputProcessor; apply() is called
    //                   on each block after per-input EQ, before float→int16
    // dump_writer:      the AudioMonitor's OutputDumpWriter; submit_block() is
    //                   called after int16 conversion, before the FIFO write
    InputChannel(int               index,
                 FifoWriter&       shared_fifo,
                 std::mutex&       fifo_mutex,
                 OutputProcessor&  output_processor,
                 OutputDumpWriter& dump_writer);

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

    // Returns true if this channel is currently allowed to write to the shared
    // FIFO (i.e. set_allow_capture(true) has been called and set_allow_capture(false)
    // has not yet been called).  Used by AudioMonitor to decide whether stopping
    // this input should also reset the output auto-trim.
    bool allow_capture_enabled() const
    {
        return _allow_capture.load(std::memory_order_relaxed);
    }

    // Returns true if start() has been called and stop() has not yet completed
    // (includes the case where the capture thread self-stopped after an ALSA
    // error but stop() has not been called to join the threads).  Use this to
    // detect the crashed-but-not-cleaned-up state in api_start_input().
    bool is_started() const { return _started.load(); }

    // Copy the most recent min(max_frames, ID_BUF_FRAMES) mono s16le 16000 Hz
    // frames into out[0..return_value-1], ordered oldest-first.  Returns the
    // number of frames actually copied (may be less than max_frames if the
    // buffer has not yet accumulated that many frames since the last start()).
    // Thread-safe; acquires _id_mutex.  Safe to call while the channel is
    // running or after it has stopped.
    unsigned get_id_snapshot(int16_t* out, unsigned max_frames) const;

    // Returns all retained VU history bins, oldest first.
    // Thread-safe; acquires _vu_history_mutex.  May return an empty vector
    // if no bins have been produced yet since the last start().
    std::vector<VuBin> get_vu_history() const;

    // Sample rate and capacity of the identification snapshot buffer.
    // ID_BUF_RATE matches Shazam's internal processing rate, eliminating any
    // resampling step inside the Vibra daemon.
    // ID_BUF_FRAMES must remain a power of two (the ring uses bitwise masking).
    // 2^19 = 524288 frames at 16000 Hz ≈ 32.8 s — above the 20 s daemon max.
    static constexpr unsigned ID_BUF_RATE   = 16000;
    static constexpr unsigned ID_BUF_FRAMES = 1u << 19;  // 524288 ≈ 32.8 s

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
    FifoWriter&       _shared_fifo;
    std::mutex&       _fifo_mutex;
    OutputProcessor&  _output_processor;
    OutputDumpWriter& _dump_writer;

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
    SRC_STATE*    _src_state    = nullptr;  // main stereo SRC (ALSA rate → 44100 Hz)
    SRC_STATE*    _id_src_state = nullptr;  // ID-tap SRC (44100 Hz mono → 16000 Hz)

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

    // ── Stereo VU history (100 ms bins, post-output-processing tap) ───────────
    //
    // The process thread accumulates per-channel float peaks across each 100 ms
    // window and pushes a VuBin when the window closes.  Bins are kept in a
    // fixed-size circular buffer; the API thread reads them under _vu_history_mutex.
    //
    // All _vu_bin_* fields are written only by the process thread.
    // _vu_history, _vu_history_write_idx, and _vu_history_count are written by
    // the process thread and read by the API thread, both under _vu_history_mutex.
    //
    static constexpr double VU_BIN_SECONDS   = 0.1;   // one bin = 100 ms
    static constexpr int    VU_HISTORY_BINS  = 40;    // retain 4 s of history

    // Process-thread-only accumulators (no synchronisation needed):
    float    _vu_bin_left_peak  = 0.0f;   // peak left  linear amplitude in current bin
    float    _vu_bin_right_peak = 0.0f;   // peak right linear amplitude in current bin
    double   _vu_bin_start_time = 0.0;    // monotonic time when current bin started
    uint32_t _vu_bin_seq        = 0;      // sequence counter; incremented on each bin close

    // Shared between process thread (writer) and API thread (reader):
    mutable std::mutex _vu_history_mutex;
    VuBin _vu_history[VU_HISTORY_BINS];   // circular buffer, oldest→newest on read
    int   _vu_history_write_idx = 0;      // index of the next write slot
    int   _vu_history_count     = 0;      // number of valid bins (saturates at VU_HISTORY_BINS)

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
    // A separate rolling buffer that accumulates mono s16le audio at 16000 Hz
    // for Shazam-based track identification via the Vibra daemon.
    //
    // Tap point: post-main-SRC (44100 Hz stereo float), pre-gain/pre-EQ.
    //   - Post-SRC: uses a stable, device-independent rate.
    //   - Pre-gain/pre-EQ: captures uncolored audio; user gain and EQ reflect
    //     personal preference and would skew frequency-domain fingerprints.
    //   - Gated by _capturing: fills only during active audio sessions.
    //
    // Downsampling: a dedicated _id_src_state (SRC_LINEAR, 1 channel) converts
    // the downmixed mono float signal from 44100 → 16000 Hz.  SRC_LINEAR is
    // sufficient for Shazam's spectral peak fingerprinting; upgrade to
    // SRC_SINC_FASTEST if profiling shows a measurable quality impact.
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

    // Set the output-side parametric EQ applied to the stream after per-input
    // processing and before the FIFO write.  Bands are shared across all inputs.
    // An empty band list (or all Peak/Shelf bands with 0 dB gain) enables the
    // quick-path so no filter arithmetic is performed on the hot path.
    std::string api_set_output_eq(const std::vector<EqBand>& bands);

    // Set the manual output gain applied after the output EQ.
    // gain_db must be in [OutputProcessor::OUTPUT_GAIN_MIN_DB,
    //                     OutputProcessor::OUTPUT_GAIN_MAX_DB].
    std::string api_set_output_gain(float gain_db);

    // Enable or disable automatic output trimming.
    // Enabling resets the current auto-trim attenuation to 0.0 dB.
    std::string api_set_output_auto_trim(bool enabled);

    // Update the monitor's runtime log level.
    std::string api_set_log_level(const std::string& level_text);

    // Return a status snapshot for all inputs plus top-level daemon metadata
    // such as the compiled-in monitor_build identifier.
    std::string api_get_status();

    // Copy up to max_seconds (1..20) of recent mono 16000 Hz audio for the
    // given input into binary_out (s16le, no header), returning a JSON ack.
    // binary_out is populated only when "ok":true; the caller sends the bytes
    // as a raw binary payload immediately after the JSON response line.
    std::string api_get_id_snapshot(int input_index, int max_seconds,
                                     std::vector<int16_t>* binary_out);

    // Engineering output dump: record the final processed stream to a WAV file.
    // start: opens path and begins recording; rejects if already active.
    // stop:  flushes, patches WAV header, closes; no-op if not active.
    std::string api_start_output_dump(const std::string& path, bool overwrite);
    std::string api_stop_output_dump();

private:
    // Returns a pointer to the InputChannel for the given 1-based index,
    // or nullptr if the index is out of range.
    InputChannel* get_input(int input_index);

    static constexpr int NUM_INPUTS  = 2;
    static constexpr int OUTPUT_RATE = 44100;

    // Back-off interval (seconds) before retrying a failed auto-restart.
    static constexpr double RESTART_BACKOFF_SECONDS = 5.0;

    std::string _socket_path;

    FifoWriter       _fifo_writer;
    OutputDumpWriter _dump_writer;
    std::mutex       _fifo_mutex;
    OutputProcessor  _output_processor;

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
