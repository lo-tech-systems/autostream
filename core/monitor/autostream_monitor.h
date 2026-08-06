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
// processing, and writes a 48 kHz stereo PCM stream to a named FIFO.
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
//   apt-get install libasound2-dev libsamplerate0-dev libtwolame-dev libmpg123-dev
//   g++ -std=c++17 -O2 -o autostream_monitor \
//       autostream_monitor.cpp \
//       autostream_monitor_dsp.cpp \
//       autostream_monitor_io.cpp \
//       autostream_monitor_utils.cpp \
//       autostream_repeat.cpp \
//       -lasound -lsamplerate -lpthread -ltwolame -lmpg123
// =============================================================================

#pragma once

#include "autostream_monitor_utils.h"
#include "autostream_track_gap_detector.h"
#include "autostream_repeat_buffer.h"
#include "autostream_id_tap.h"
#include "autostream_spsc_ring.h"

#include <algorithm>
#include <string>
#include <vector>
#include <array>
#include <deque>
#include <set>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <memory>
#include <cstdint>
#include <functional>
#include <optional>
#include <sys/time.h>      // struct timeval for SO_RCVTIMEO

#include <alsa/asoundlib.h>
#include <samplerate.h>

// Build identifier compiled into the monitor binary and reported via the
// socket API.  This is intentionally maintained in source so an older running
// binary can be detected after an update if the monitor rebuild failed.
inline constexpr char AUTOSTREAM_MONITOR_BUILD[] = "0.5.25";


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
    float       silence_threshold_dbfs       = -66.0f; // dBFS level below which is silent
    int         silence_seconds              = 30;      // silence duration before stopping
    float       track_change_silence_seconds = 1.25f;  // gap duration (s) that marks a track boundary [0.5, 5.0]
    int         minimum_playback_seconds     = 30;      // minimum playback hold, seconds; 0 disables [0, 300]
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

// Test-only (--test-pin-src-ratio, gated behind --test-hooks): pins the SRC
// ratio to the nominal reset() value so golden-reference runs are
// byte-deterministic. Defined in autostream_monitor_dsp.cpp (see the full
// rationale there); written once by main() before any thread starts.
extern bool g_test_pin_src_ratio;

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
    // The monitor only ships on 64-bit OS (32-bit is supported solely for
    // autostream-dial, which has no monitor), and on aarch64
    // std::atomic<double> is is_always_lock_free (verified; the linked
    // binary has no libatomic dependency). This also covers the per-block
    // _stall_since atomics. See docs/AUTOSTREAM-MONITOR.md "Atomics and
    // lock-freedom".
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
//   - S32_LE format (signed 32-bit little-endian) requested first; falls
//     back to S16_LE if the device does not support 32-bit. read() always
//     hands back samples in the monitor's common 32-bit
//     internal representation regardless of which format was negotiated --
//     see read()'s comment for the widening convention.
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
    // Requests SND_PCM_FORMAT_S32_LE first; falls back to SND_PCM_FORMAT_S16_LE
    // if the device rejects 32-bit. captured_as_s32() reports which one won.
    // Returns true on success; logs and returns false on any ALSA error.
    bool open(const std::string& hw_device, int channels = 2);

    // Close the device and release the ALSA handle.
    void close();

    // Read up to n_frames frames into buf (interleaved int32, n_frames * channels
    // values), always in the monitor's common 32-bit internal representation:
    // samples occupy the full 32-bit dynamic range (matches what libsamplerate's
    // src_int_to_float_array/src_float_to_int_array assume, i.e. AV_SAMPLE_FMT_S32-
    // style "24-in-32 left-justified" scaling). If the hardware negotiated
    // SND_PCM_FORMAT_S32_LE, ALSA already presents samples at this scale and
    // they are copied through unchanged. If it fell back to SND_PCM_FORMAT_S16_LE,
    // each 16-bit sample is left-shifted by 16 bits here (on the capture thread,
    // integer-only, no allocation once the internal scratch buffer has grown to
    // its steady-state size) so a downstream consumer never needs to know which
    // format was actually negotiated.
    // Returns the number of frames read (may be less than n_frames).
    // Returns 0 if an xrun (overrun) occurred but was successfully recovered.
    // Returns -1 on an unrecoverable error; caller should close and reopen.
    int read(int32_t* buf, int n_frames);

    // The period size that ALSA negotiated with the hardware.
    // Acquires _read_mutex; safe to call from any thread.
    int  period_frames() const;

    // The sample rate selected by the monitor and accepted by ALSA.
    // Valid only while is_open() is true; returns 0 after close().
    // Acquires _read_mutex; safe to call from any thread.
    int  actual_rate()   const;

    // True if the hardware negotiated SND_PCM_FORMAT_S32_LE; false if capture
    // fell back to SND_PCM_FORMAT_S16_LE. Valid only while is_open() is true.
    // Acquires _read_mutex; safe to call from any thread.
    bool captured_as_s32() const;

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
    int        _channels      = 2;
    bool       _captured_s32  = false;

    // Scratch buffer used only when the device negotiated S16_LE, to hold the
    // raw 16-bit read before widening into the caller's int32 buffer. Grown
    // (never shrunk) by read() itself, on the capture thread -- same
    // resize-if-needed pattern InputChannel::capture_thread_func() already
    // uses for its own period buffer: the size is stable after the first call
    // for the lifetime of an open session, so this is not a steady-state
    // allocation.
    std::vector<int16_t> _s16_scratch;
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

    // Seconds this writer has been CONTINUOUSLY failing/dropping
    // (ENXIO/EAGAIN/EPIPE/etc, see write()) since the last successful write,
    // for get_status()'s top-level "fifo.stalled_seconds" (docs/AUTOSTREAM-
    // MONITOR.md) -- an owntone-hang watchdog signal. 0.0 whenever the last
    // write() succeeded, OR (via reset_stall()) whenever this writer is not
    // currently the active FIFO writer at all (idle input / replay owns the
    // pipe) -- a stall streak must never be reported as still-growing during
    // a period this writer was not even being asked to write.
    // Single relaxed atomic, no lock: called from the audio process thread's
    // hot path (write()/the caller's inactive-branch reset) and read from the
    // control thread (get_status()) -- staleness of a few blocks is fine,
    // never a correctness issue for a monitoring-only signal.
    double stalled_seconds() const
    {
        double since = _stall_since.load(std::memory_order_relaxed);
        return since > 0.0 ? (get_monotonic_time() - since) : 0.0;
    }

    // Cheap: called by InputChannel::process_thread_func() whenever this
    // input is NOT the active FIFO writer this block (see stalled_seconds()'s
    // comment). A no-op once already 0.
    void reset_stall() { _stall_since.store(0.0, std::memory_order_relaxed); }

private:
    bool try_open();    // internal: attempt non-blocking open
    bool write_impl(const void* data, size_t len);   // the actual write logic; write() wraps it with stall tracking

    int         _fd                  = -1;
    std::string _path;
    double      _stall_last_log_time = 0.0;   // for throttling EAGAIN warnings
    std::atomic<double> _stall_since{0.0};    // monotonic start of the current failure streak; 0 = healthy/idle
};


// =============================================================================
// OutputDumpWriter
//
// Engineering-only tap that records the final processed audio stream to a WAV
// file on demand, without disturbing the normal FIFO delivery path.
//
// Signal tap point: inside InputChannel::process_thread_func(), immediately
// after _output_processor.apply() and src_float_to_short_array() — the first
// point where the signal is complete 48 kHz stereo s16le after all SRC,
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

    // Open path and begin recording.  Writes a 44-byte WAV header built from
    // AudioMonitor::output_rate_hz()/output_bits_per_sample()/output_channels()
    // (reads the process-wide g_output_format descriptor) via the shared
    // build_wav_header() helper (sizes are placeholders, patched on
    // stop()).
    // Returns "" on success or a non-empty error string on failure.  Must
    // not be called while a dump is already active.
    // overwrite: if false, rejects the call when a file already exists at path.
    std::string start(const std::string& path, bool overwrite);

    // Flush, patch WAV header, and close.  No-op if no dump is active.
    // was_active_out (if non-null) is set to indicate whether a recording was
    // in progress before this call.  Called automatically by ~OutputDumpWriter().
    void stop(bool* was_active_out = nullptr);

    // Submit out_frames stereo samples for recording, in the monitor's
    // current output container width (int32_t -- see
    // AudioMonitor::OUTPUT_BITS).  The WAV header written by start()
    // describes this same format, so the file is
    // self-describing end to end.
    // Called from the audio process thread under AudioMonitor::_fifo_mutex.
    // Non-blocking: drops and counts frames when the ring is full.
    void submit_block(const int32_t* samples, int out_frames);

    // True while a dump is in progress.  Safe to call from any thread.
    bool is_active() const { return _active.load(std::memory_order_relaxed); }

    // Thread-safe snapshot of the current recording state.
    Status get_status() const;

private:
    void writer_thread_func();

    // SPSC ring buffer: 2^18 stereo int32 samples ≈ 2.73 s at 48 kHz (the
    // ring holds 1 MiB; element COUNT mirrors _pcm_out/FifoWriter's payload
    // width). submit_block() is the single producer; writer_thread_func() is
    // the single consumer. See autostream_spsc_ring.h for the SPSC proof
    // this relies on.
    static constexpr size_t DUMP_RING_SAMPLES = 1u << 18;   // 262144

    SpscRing<int32_t>       _ring{DUMP_RING_SAMPLES};

    // Scratch buffer for writer_thread_func()'s drain: sized once here (never
    // grown on the writer thread) so read()-into-buffer-then-fwrite adds no
    // allocation. Holds at most one drain's worth of samples, which can be up
    // to the full ring.
    std::vector<int32_t>    _read_scratch = std::vector<int32_t>(DUMP_RING_SAMPLES);

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
    bool     is_started             = false;   // start() has been called and stop() not yet completed
    bool     is_running             = false;   // capture thread is actively running
    uint32_t track_change_seq       = 0;       // monotonically increasing; incremented on each detected track gap
};


// =============================================================================
// RepeatEncoder
//
// Pure abstract interface for the "repeat" feature's recording encode step.
// Concrete implementations (Mp2Encoder via
// libtwolame, PcmS16Encoder) are defined entirely inside autostream_repeat.cpp
// so this shared header stays free of the twolame include -- mirroring the
// pure/impure split already used for autostream_repeat_buffer.h. Obtain an
// instance via make_repeat_encoder().
// =============================================================================

class RepeatEncoder
{
public:
    virtual ~RepeatEncoder() = default;

    // Encodes frames stereo interleaved float samples (frames*2 floats).
    // Appends encoded bytes to out (out is cleared and resized by the
    // implementation as needed) and returns the number of bytes appended.
    // May return 0 if the encoder is still accumulating a partial frame
    // internally (MP2 tier).
    virtual size_t encode(const float* interleaved, int frames,
                          std::vector<uint8_t>& out) = 0;

    // Flushes any remaining buffered/partial output (end of recording).
    // Appends to out and returns the number of bytes appended.
    virtual size_t flush(std::vector<uint8_t>& out) = 0;

    // Nominal per-call output granularity used for silence-trim alignment
    // (SilenceTrimAccountant). Returns 1 when every encode() call
    // already returns a whole number of self-contained frames (true for both
    // implementations here), meaning no additional byte-rounding is needed
    // beyond the per-append-call granularity RepeatController already uses.
    virtual int frame_bytes() const = 0;
};

// Constructs the encoder implementation for the given codec tier. Returns
// nullptr for CodecChoice::Unavailable (callers must not reach this case --
// RepeatController::notify_capture_started() refuses to begin a session when
// pick_codec_for_target()/the pinned codec resolves to Unavailable).
std::unique_ptr<RepeatEncoder> make_repeat_encoder(CodecChoice codec, int sample_rate_hz);


// =============================================================================
// RepeatRecorder
//
// Tap + low-priority encode worker for the "repeat" feature's recording path.
// Direct adaptation of OutputDumpWriter's
// producer/consumer pattern (above): the audio process thread calls the
// non-blocking submit_block() to copy a drained float block (plus its
// above-threshold flag) into a bounded SPSC ring; a dedicated worker thread,
// niced to +10, drains the ring and hands each block to
// RepeatController::process_recorder_samples() for encoding and buffer
// append. If the ring fills, the block is dropped and counted -- the audio
// thread is never delayed.
//
// Unlike OutputDumpWriter, RepeatRecorder carries two parallel rings: one for
// the float sample payload and one for small per-block metadata (frame count
// + above-threshold flag), since a single submit_block() call corresponds to
// one whole audio block with one above-threshold flag, not a per-sample flag.
// =============================================================================

class RepeatController;   // forward declaration; RepeatRecorder only stores a reference

class RepeatRecorder
{
public:
    explicit RepeatRecorder(RepeatController& owner);
    ~RepeatRecorder();

    // Starts the worker thread. Called once at daemon init (AudioMonitor
    // construction); the thread runs for the daemon's lifetime, parked on a
    // condition variable while no blocks are submitted (i.e. while the
    // feature is disabled or between sessions).
    void start();

    // Signals the worker thread to exit and joins it. Called at daemon
    // shutdown (AudioMonitor::stop()).
    void stop();

    // Non-blocking; called from the audio process thread (already gated by
    // RepeatController::recording_wanted()). Copies frames*2 interleaved
    // float samples plus above_threshold into the SPSC rings. Drops and
    // counts the block if either ring is full.
    void submit_block(const float* interleaved, int frames, bool above_threshold);

    uint64_t dropped_frames() const { return _dropped_frames.load(std::memory_order_relaxed); }

    // Wakes the worker thread to perform a deferred session start
    // (RepeatController::perform_pending_start(), which does the meminfo
    // read + encoder construction) instead of that work happening inline on
    // the audio thread inside notify_capture_started(). Cheap: sets an
    // atomic and notifies the same condition variable submit_block() already
    // uses, so the worker wakes promptly even with the ring otherwise idle.
    void request_pending_start()
    {
        _pending_start_requested.store(true, std::memory_order_release);
        _cv.notify_one();
    }

    // Waits up to `timeout` for the SPSC ring to fully drain (i.e. the
    // worker thread has consumed every block submitted so far), returning
    // true if it drained within the timeout and false otherwise. Called by
    // RepeatController::notify_capture_stopped() WITHOUT _repeat_mutex held
    // (lock order: the worker thread's own drain loop takes _repeat_mutex
    // per block via RepeatController::process_recorder_samples(), so
    // waiting here while holding _repeat_mutex would deadlock the worker
    // against itself via the caller). Uses a DEDICATED condition variable
    // (_drain_cv), not the worker's own _cv, so a notify here can never
    // steal a wakeup the worker thread's own wait loop was waiting for (or
    // vice versa) -- the worker explicitly notifies _drain_cv only when its
    // drain loop actually empties the ring (worker_thread_func()). Checking
    // the ring position atomics directly (not a stored "drained" flag)
    // means a notify racing just before this function starts waiting is
    // never a lost wakeup -- the predicate is re-evaluated the instant the
    // wait begins.
    bool wait_for_drain(std::chrono::milliseconds timeout)
    {
        auto ring_empty = [this]()
        {
            return _meta_ring.read_available() == 0;
        };
        if (ring_empty())
            return true;
        std::unique_lock<std::mutex> lk(_cv_mutex);
        return _drain_cv.wait_for(lk, timeout, ring_empty);
    }

    // Best-effort count of audio frames still queued in the sample ring
    // (submitted but not yet drained by the worker), used to fold into the
    // dropped-frames counter when wait_for_drain() times out rather than
    // silently losing that tail. Exact regardless of block-size variation
    // (derived from the sample-domain ring position delta, not a per-block
    // frame sum). Never OVER-reports: the worker's own consumption only
    // ever moves the ring's read position forward, so a concurrent drain can
    // only shrink this value between the read here and the caller acting on it.
    uint64_t queued_frames() const
    {
        return static_cast<uint64_t>(_ring.read_available()) / 2u;   // interleaved stereo floats -> frames
    }

    // Folds a drain-timeout's worth of still-queued frames into the
    // same counter submit_block() itself uses for ring-full drops, so
    // status.recording.dropped_frames stays an honest total regardless of
    // which path lost the audio.
    void add_dropped_frames(uint64_t n)
    {
        if (n > 0)
            _dropped_frames.fetch_add(n, std::memory_order_relaxed);
    }

private:
    void worker_thread_func();

    struct BlockMeta
    {
        uint32_t frames          = 0;
        bool     above_threshold = false;
    };

    RepeatController& _owner;

    // Sample ring: interleaved stereo float samples. 1<<19 floats (double
    // the dump ring's seconds to give the nice'd encoder headroom).
    //
    // AUTOSTREAM_REPEAT_TEST_RING_FLOATS (test-only, must be a power of two)
    // overrides this to a tiny value so ring-overrun resilience can be
    // force-tested deterministically -- in practice, MP2/PCM
    // encoding is cheap enough that even heavy CPU contention rarely
    // overflows the production-sized ring before the nice(+10) worker gets a
    // CFS timeslice, so a real overrun needs either a much smaller ring or an
    // actual thread suspension. Never defined by autostream_install.sh's
    // production build.
#ifdef AUTOSTREAM_REPEAT_TEST_RING_FLOATS
    static constexpr size_t RING_FLOATS = AUTOSTREAM_REPEAT_TEST_RING_FLOATS;
#else
    static constexpr size_t RING_FLOATS = 1u << 19;   // 524288
#endif
    // See autostream_spsc_ring.h for the SPSC proof this relies on.
    SpscRing<float> _ring{RING_FLOATS};

    // Metadata ring: one entry per submit_block() call. Sized generously
    // relative to the sample ring's capacity in typical (small) audio blocks.
    static constexpr size_t META_RING_SIZE = 4096;
    SpscRing<BlockMeta> _meta_ring{META_RING_SIZE};

    std::thread             _worker_thread;
    std::mutex               _cv_mutex;
    std::condition_variable  _cv;
    // Separate from _cv (see wait_for_drain()'s comment) so a drain
    // waiter and the worker's own idle wait never steal each other's
    // notifications; shares _cv_mutex since neither wait needs an
    // independent mutex.
    std::condition_variable  _drain_cv;

    std::atomic<bool> _running{false};
    std::atomic<bool> _stop_requested{false};

    // Set by request_pending_start(), consumed once per outer loop
    // iteration by worker_thread_func() BEFORE it drains any ring blocks --
    // so RepeatController::perform_pending_start() (meminfo read + encoder
    // construction) always runs before this thread hands any accumulated
    // blocks to RepeatController::process_recorder_samples(), which drops
    // blocks whenever the encoder is not ready yet.
    std::atomic<bool> _pending_start_requested{false};

    std::atomic<uint64_t> _dropped_frames{0};   // updated by the audio thread
};


// =============================================================================
// ReplayEngine
//
// Dedicated thread that plays a finished RepeatBuffer recording back into the
// shared FIFO, looping until stopped. Owns its
// own BLOCKING O_WRONLY fd on the FIFO, opened at replay start and closed at
// stop -- distinct from FifoWriter's O_NONBLOCK fd, which the live path keeps
// using untouched. Never holds RepeatController::_repeat_mutex or
// AudioMonitor::_fifo_mutex across a write; FifoOwner arbitration is a
// separate, briefly-locked flag flip (see RepeatController).
//
// Pacing: rather than a purely blocking write() (which would hang
// indefinitely if the reader stops draining without closing), each
// slice write is preceded by a bounded poll(POLLOUT) so the abort/state flag
// can be re-checked at least every ~100-200 ms even while nominally "blocked"
// on the pipe. This still yields the LLD's core pacing property (the kernel
// only reports writable once the reader has drained space, so the reader's
// consumption clock still paces replay) while keeping abort latency bounded
// -- a deliberate deviation from a literal blocking write().
//
// Decode: libmpg123 for the MP2 tier (mpg123_open_feed/mpg123_decode, forced
// output format s16/output_rate/stereo); the PCM tier is a raw copy (no
// decoder needed). Both tiers funnel through the same slice/fade/write loop.
//
// Track ID during replay: embeds its own TrackGapDetector and a
// 16 kHz mono ID tap, fed from the decoded s16 blocks -- mirroring
// InputChannel's own members so track-change events and Vibra snapshots work
// identically while replay owns the FIFO.
// =============================================================================

class ReplayEngine
{
public:
    explicit ReplayEngine(RepeatController& owner);
    ~ReplayEngine();

    // Starts the thread, parked until request_start(). Called once at daemon
    // init (mirrors RepeatRecorder::start()).
    void start_thread();

    // Signals the thread to exit and joins it. Called at daemon shutdown.
    void stop_thread();

    // Both the disarm and live-interrupt triggers use the identical 1.5 s
    // linear fade shape in the slice path below -- only RepeatController's
    // POST-fade branching differs (autostream_repeat.cpp's single
    // _pending_action, consulted by on_replay_session_ended_locked_entry()).
    // request_fade_out() therefore no longer takes a reason parameter (
    // a former FadeReason enum was accepted here but never actually read by
    // ReplayEngine -- a phantom API -- since the fade shape itself never
    // varied by reason; the distinction the controller cares about is
    // entirely captured by its own PendingAction, set by the caller BEFORE
    // calling this).
    //
    // All three request_*() calls are called by RepeatController under
    // _repeat_mutex and only set atomics / notify a condition variable --
    // they never block, so the caller's lock hold time stays short.
    void request_start(CodecChoice codec, int sample_rate_hz,
                        const RepeatBuffer* buffer,
                        int origin_input,
                        int origin_silence_threshold_sample,
                        float origin_track_change_silence_seconds);
    void request_fade_out();
    void request_abort();   // hard stop, no fade (disable/reload/stop_input)

    struct Snapshot
    {
        bool     active           = false;
        double   position_seconds = 0.0;
        double   duration_seconds = 0.0;
        uint64_t loop_count       = 0;
    };
    Snapshot get_snapshot() const;

    // Track-ID plumbing during replay, read by AudioMonitor's
    // status/get_id_snapshot dispatch when routing the origin input's
    // entries to the replay tap instead of the (now-silent) InputChannel.
    uint32_t track_change_seq() const { return _track_change_seq.load(std::memory_order_relaxed); }
    unsigned get_id_snapshot(int16_t* out, unsigned max_frames) const;

    // Mirrors FifoWriter::stalled_seconds() (see its doc comment)
    // for the replay path's own fd -- seconds since the last successful
    // write_slice_blocking() call, 0.0 if healthy or no session has run yet.
    // Reset to 0 at the start of every run_one_session() so a stall from a
    // PRIOR session never leaks into this one's reading.
    double stalled_seconds() const
    {
        double since = _stall_since.load(std::memory_order_relaxed);
        return since > 0.0 ? (get_monotonic_time() - since) : 0.0;
    }

    static constexpr unsigned ID_BUF_RATE   = 16000;
    // Matches InputChannel's own ID_BUF_FRAMES (autostream_monitor.h
    // ~1420) rather than a smaller replay-side value -- there is no reason
    // for the replay tap's track-ID lookback window to be shorter than the
    // live tap's; both feed the same Vibra snapshot consumer, and giving
    // replay a shorter history than live capture had is an inconsistency,
    // not a deliberate saving (the added cost is ~1 MiB: (1<<19 - 1<<17) * 2
    // bytes). ~32.8 s of 16 kHz mono s16 lookback.
    static constexpr unsigned ID_BUF_FRAMES = 1u << 19;   // 524288 ~= 32.8 s

private:
    // Per-session resources (fd, decoder, ID tap, fade state, scratch
    // buffers -- everything run_one_session() used to hold as function-local
    // variables) live in this RAII struct instead, so every exit path from a
    // session -- including ones added in the future -- closes the fd and
    // tears down the decoder/ID-tap by construction rather than by each exit
    // point remembering to do so by hand. Defined in autostream_repeat.cpp
    // (opaque here: the private methods below only take it by reference, and
    // it is only ever constructed/destroyed inside that TU).
    struct ReplaySessionCtx;

    // Why the most recent session ended, decided by run_one_session()
    // and consumed by thread_func() to make the single terminal-handler call
    // (see below). Values map 1:1 onto today's four
    // on_replay_session_ended_locked_entry() call sites:
    //   AbortedBeforeOpen -- Abort/FadeOut/stop observed while still waiting
    //                        for a FIFO reader in open_fifo_for_session()'s
    //                        retry loop (no session state was ever set up).
    //   OpenError         -- open() failed with something other than ENXIO.
    //   DecoderInitFailed -- Mp2Decoder construction/format-negotiation failed.
    //   Aborted           -- Abort/stop mid-session, a decode error, or a
    //                        write error (write_slice_paced() returning
    //                        false) -- today's single `session_aborted` bool
    //                        covers exactly these three sub-cases with
    //                        identical log text ("[aborted]"), so they share
    //                        one reason value here too.
    //   FadeComplete      -- the disarm fade envelope ran to completion (the
    //                        only "successful" end of a session).
    enum class SessionEndReason
    {
        AbortedBeforeOpen,
        OpenError,
        DecoderInitFailed,
        Aborted,
        FadeComplete,
    };

    // Outcome of one decode_next_slice() call, driving run_one_session()'s
    // orchestration loop.
    enum class SliceBatchOutcome
    {
        Ready,        // ctx.pcm_staging holds a non-empty decoded batch to slice/write
        Retry,        // nothing to write yet (decoder still accumulating); loop again
        Wrapped,      // buffer-end loop wrap just happened; caller must write the
                      // inter-loop gap (write_loop_gap()) before looping again
        Aborted,      // Abort/stop observed; end the session
        DecodeError,  // codec decode failed; end the session (treated as Aborted)
    };

    void thread_func();

    // Called on the replay thread once request_start() wakes it. Returns the
    // reason the session ended; thread_func() is the sole caller of
    // on_replay_session_ended_locked_entry(): every session-end path
    // collapses to that one call at the caller.
    SessionEndReason run_one_session();

    // ── run_one_session()'s extracted stages ────────────────────────────────
    // Each takes the session ctx explicitly; no per-slice allocation, no new
    // locks, same execution order as the pre-split function.

    // The fd-open retry/abort-poll loop. Returns nullopt (ctx.fd is now a
    // valid, open, O_WRONLY|O_NONBLOCK fd) on success, or the SessionEndReason
    // to return from run_one_session() on failure/abort.
    std::optional<SessionEndReason> open_fifo_for_session(ReplaySessionCtx& ctx,
                                                            const std::string& path);

    // Decoder construction, Reader/ID-tap setup, ID-buffer/track-change-seq
    // reset -- everything that must happen once, after the fd is open, before
    // the per-slice loop starts. Returns false (decoder init failed) or true.
    bool init_session(ReplaySessionCtx& ctx, CodecChoice codec, int rate_hz,
                       const RepeatBuffer& buffer);

    // One reader.next() batch: abort/fade-start check, buffer-end loop-wrap
    // handling, live gain/EQ pull, and codec decode/copy into
    // ctx.pcm_staging.
    SliceBatchOutcome decode_next_slice(ReplaySessionCtx& ctx, CodecChoice codec);

    // One kSliceFrames-sized slice: track-gap detect -> ID tap -> gain -> EQ
    // -> OutputProcessor -> fade envelope -> pipe-format conversion, in that
    // order, writing the result into ctx.pipe_bytes.
    void process_slice(ReplaySessionCtx& ctx, const int16_t* slice, size_t slice_samples,
                        int rate_hz, int silence_threshold, double track_gap_seconds);

    // Writes ctx.pipe_bytes fully, in poll(POLLOUT)-gated chunks (see class
    // comment above for why this is not a literal blocking write()). Returns
    // false on any unrecoverable error (EPIPE/EBADF/POLLERR/POLLHUP) or
    // if an abort/shutdown was observed while waiting.
    bool write_slice_paced(ReplaySessionCtx& ctx);

    // Writes kLoopGapSeconds of silence to the FIFO at a loop wrap
    // paced identically to real content via write_slice_paced()
    // so the gap consumes real time at the reader's actual drain rate. Not
    // run through process_slice() -- no DSP, no fade envelope, no ID tap, no
    // TrackGapDetector update -- it is not recorded content, so none of
    // those must observe it. _position_seconds is left untouched by this
    // call (see decode_next_slice()'s wrap-point comment: it stays frozen at
    // the just-finished loop's duration for the whole gap, then resets to 0
    // as an ordinary side effect of the first real post-gap slice). Returns
    // false if an abort/write error interrupts the gap early (same contract
    // as write_slice_paced()).
    bool write_loop_gap(ReplaySessionCtx& ctx, int rate_hz);

    // Records a write_slice_paced() outcome into _stall_since
    // and returns `ok` unchanged, so call sites can wrap a return statement
    // with it (see the call sites' comment).
    bool track_stall_outcome(bool ok);

    enum class Cmd { None, Start, FadeOut, Abort };

    static constexpr int    kPollTimeoutMs   = 100;    // abort-check granularity (~100 ms)
    static constexpr size_t kSliceFrames     = 4096;   // 4096 stereo s16 frames = 16 KiB (8-16 KiB slices)
    static constexpr double kFadeSeconds     = 1.5;    // disarm fade span
    static constexpr double kLoopGapSeconds  = 1.5;    // inter-loop silence gap

    RepeatController& _owner;
    std::thread       _thread;
    std::atomic<bool> _running{false};        // thread alive
    std::atomic<bool> _stop_requested{false};

    std::mutex               _cmd_mutex;
    std::condition_variable  _cmd_cv;
    // Atomic (not just mutex-guarded) because open_fifo_for_session() and
    // decode_next_slice() (both called from run_one_session()'s per-session
    // loop) poll/clear it directly from the replay thread without
    // taking _cmd_mutex, for low-latency abort/fade-out checks between
    // slices and inside write_slice_paced()'s poll loop; request_*()/
    // thread_func() still take _cmd_mutex around their read-modify-write +
    // condition_variable signalling so the "wake the idle thread" path has
    // no missed-wakeup race.
    std::atomic<Cmd>         _pending_cmd{Cmd::None};

    // Parameters captured by request_start(), read only by the replay thread
    // after it wakes (no concurrent writer while a session is active, since
    // RepeatController only calls request_start() from Hold/Idle).
    CodecChoice          _session_codec = CodecChoice::Unavailable;
    int                  _session_rate_hz = 48000;
    const RepeatBuffer*  _session_buffer = nullptr;
    int                  _session_origin_input = 0;
    int                  _session_silence_threshold_sample = 0;
    float                _session_track_change_silence_seconds = 1.25f;

    // Live session state, updated by the replay thread, read by
    // get_snapshot()/track_change_seq()/get_id_snapshot() from other threads.
    std::atomic<bool>     _active{false};
    std::atomic<double>   _position_seconds{0.0};
    std::atomic<double>   _duration_seconds{0.0};
    std::atomic<uint64_t> _loop_count{0};
    std::atomic<uint32_t> _track_change_seq{0};

    // ── ID tap (16 kHz mono), mirrors InputChannel's _id_buf/_id_mutex ──────
    static constexpr unsigned ID_BUF_MASK = ID_BUF_FRAMES - 1u;
    mutable std::mutex   _id_mutex;
    std::vector<int16_t> _id_buf;
    unsigned              _id_write_pos    = 0;
    unsigned              _id_frames_avail = 0;

    // The O_WRONLY fd on the FIFO used to live here as a bare `int
    // _fd`; it is now owned by the per-session ReplaySessionCtx (RAII-closed
    // on every exit path), constructed/destroyed entirely within
    // run_one_session()'s call graph in autostream_repeat.cpp.

    // Monotonic start of the current write-stall streak (poll
    // timeout / EPIPE / etc, see write_slice_blocking()); 0 = healthy. Only
    // ever written by the replay thread; read from the control thread by
    // stalled_seconds().
    std::atomic<double> _stall_since{0.0};
};


// =============================================================================
// RepeatController
//
// State machine + owner of the "repeat" feature's recording buffer.
// Implements the IDLE/RECORDING/HOLD/REPLAYING/FADING_OUT states plus
// session-arm and the ReplayEngine, including the live-interrupt crossfade
// trigger.
//
// Locking: all mutable state is protected by _repeat_mutex, EXCEPT the fast
// atomic mirrors (_enabled_fast/_state_fast/_origin_input_fast) used by
// recording_wanted(), which the audio thread calls on every processed block
// and which must therefore never take a lock. recording_wanted() short-
// circuits on a single relaxed load of _enabled_fast, so the feature is
// provably inert (one atomic load, no further work) when disabled.
//
// Lock-order note: _repeat_mutex may be taken while holding nothing, and is
// never taken while holding AudioMonitor::_fifo_mutex (the FIFO write path
// only *reads* the fast atomics, so the two never need to nest).
// =============================================================================

// "Armed" (the session-arm concept) is NOT a RepeatState value -- it is the
// orthogonal `_armed` bool tracked separately (a decision made on this flag,
// not a state of its own; see RepeatController::set_armed()).
//
// Pending: a should_capture edge has been observed and _origin_input/
// _origin_input_fast are already set, but the recorder worker thread has not
// yet finished the deferred session-start work (meminfo read + encoder
// construction -- RepeatController::perform_pending_start()). Audio-thread
// blocks for the origin input ARE admitted (RepeatController::
// recording_wanted() treats Pending like Recording) and buffered in
// RepeatRecorder's SPSC ring while this is in flight, so no audio is lost
// waiting for the worker to run; RepeatController::process_recorder_samples()
// still requires _state == Recording before it will actually encode a
// drained block, so anything buffered during Pending is encoded once the
// worker flips the state, not dropped. Appended at the end (not inserted
// between Idle and Recording) so existing numeric _state_fast values for
// Idle/Recording/Hold/Replaying/FadingOut are unchanged.
enum class RepeatState { Idle, Recording, Hold, Replaying, FadingOut, Pending };

// Which writer currently owns the shared FIFO. Guarded by
// AudioMonitor::_fifo_mutex: the live process threads already hold that
// mutex around their write section (autostream_monitor_io.cpp), and
// ReplayEngine's start/stop transitions take it briefly to flip ownership
// (never across a blocking write) -- see RepeatController's lock-order note
// below and the extended _fifo_mutex proof comment in autostream_monitor_io.cpp.
enum class FifoOwner { Live, Replay };

struct RepeatStatus
{
    bool        enabled              = false;
    bool        armed                = false;    // session arm
    std::string codec                = "auto";   // configured policy: auto|mp2_160|mp2_192|mp2_224|mp2_256|mp2_320|mp2_384|pcm
    int         target_minutes       = kDefaultRepeatTargetMinutes;   // target-duration goal
    long        max_recording_seconds = 0;
    // The tier the estimate above actually assumes: the ACTIVE session's
    // codec while Recording, else the tier a session started right now would
    // get (same pick_codec_for_target() the idle estimate ran). Empty when
    // the estimate is unavailable (disabled / no meminfo yet / refused) --
    // the UI shows the number and this label together (setup page "Buffer:
    // 84 mins (256Kbps MP2)").
    std::string effective_codec;

    struct Recording
    {
        bool        active           = false;
        double      seconds          = 0.0;
        uint64_t    bytes            = 0;
        bool        truncated_head   = false;
        int         origin_input     = 0;
        uint64_t    dropped_frames   = 0;
        std::string unavailable_reason;   // empty = none
    } recording;

    struct Replay
    {
        bool     active            = false;
        bool     fading_out        = false;   // true only while _state == FadingOut; active stays true throughout
        double   position_seconds  = 0.0;
        double   duration_seconds  = 0.0;
        uint64_t loop_count        = 0;
    } replay;
};

// =============================================================================
// Event-driven transition table for RepeatController's core state
// machine (RepeatState x _armed x PendingAction x _pending_interrupt_restorable).
// See the full state x event matrix comment above
// RepeatController::handle_event_locked() in autostream_repeat.cpp for the
// derivation. The types below live at namespace scope (rather than nested in
// RepeatController) purely so decide_repeat_transition() -- the pure decision
// core -- can be unit-tested (core/monitor/tests/test_repeat_transitions.cpp)
// without constructing a real RepeatController, which pulls in libtwolame/
// libmpg123 and spins up real worker threads.
// =============================================================================

// Single pending post-fade action for ReplayEngine's terminal handler
// (on_replay_session_ended_locked_entry()), replacing the former
// _pending_live_interrupt/_pending_discard_on_replay_end bool pair: a
// Discard and a live-restart must never both be pending at once with no
// defined precedence -- PendingAction enforces exactly one outcome per fade.
// Moved here (out of RepeatController, unchanged in meaning) so
// decide_repeat_transition() below can take it as a plain parameter.
//
//   None         -- default. Terminal handler falls to "-> Hold" (a plain
//                    disarm fade completing, or a hard write error with
//                    nothing else in flight).
//   LiveInterrupt -- set by notify_capture_started() when a should_capture
//                    edge arrives during Replaying/FadingOut; also
//                    the "upgrade" target when a Disarm fade (_pending_action
//                    == None, state == FadingOut) is hit by a live interrupt.
//   Discard      -- set by set_enabled(false) or notify_input_stopped() while
//                    Replaying/FadingOut. ALWAYS overwrites a pending
//                    LiveInterrupt ("Discard wins" -- see RepeatController's
//                    _pending_action member comment for the full precedence
//                    writeup).
enum class PendingAction { None, Discard, LiveInterrupt };

// One value per real entry point into the six functions that are thin
// wrappers around decide_repeat_transition() (set_enabled()/
// notify_capture_started()/notify_capture_stopped()/set_armed()/
// notify_input_stopped()/on_replay_session_ended_locked_entry()), plus
// perform_pending_start()'s two outcomes (PendingStartSucceeded/Failed).
// perform_pending_start() is not one of those six functions, but it is a
// genuine Pending -> {Recording, Idle} mutation site with exactly the same
// "decide, then commit under the lock" shape as the others -- folding it in
// here is a deliberate scope extension, not a silent addition.
enum class RepeatEvent
{
    EnabledOn,               // set_enabled(true), was disabled
    EnabledOff,               // set_enabled(false), was enabled
    CaptureStarted,           // notify_capture_started(input_index)
    CaptureStopped,           // notify_capture_stopped(input_index), origin matched
    Armed,                    // set_armed(true), was unarmed
    Disarmed,                 // set_armed(false), was armed
    InputStopped,             // notify_input_stopped(input_index), origin matched
    ReplaySessionEnded,       // on_replay_session_ended_locked_entry()
    PendingStartSucceeded,    // perform_pending_start(): codec/encoder construction ok
    PendingStartFailed,       // perform_pending_start(): refused (mem/encoder init)
};

// Read-only, event-specific extra data decide_repeat_transition() needs
// beyond the explicit (state, armed, enabled_cfg, pending_action,
// pending_restorable) parameters. Kept separate from those (rather than
// adding more positional parameters) because these vary per call, not per
// (state, event) cell.
struct RepeatEventCtx
{
    int  input_index         = 0;      // CaptureStarted
    int  interrupting_input  = 0;      // ReplaySessionEnded: snapshot of
                                        // _pending_interrupt_input taken by
                                        // the caller before it clears it
    bool has_hold_bytes      = false;  // ReplaySessionEnded: _buffer.total_bytes() > 0

    // CaptureStarted, minimum playback hold: true when the active replay (or
    // its fade-out) is still within its minimum-playback window, computed by
    // the caller from _replay_start_time and the origin input's configured
    // minimum_playback_seconds. While true, a live-input transient arriving
    // during Replaying/FadingOut is ignored outright -- no state change, no
    // pending-interrupt latch -- instead of starting the usual fade-out/
    // takeover sequence. Meaningless (left false) for any other event or
    // state; decide_repeat_transition() only consults it in the
    // CaptureStarted x {Replaying, FadingOut} cells.
    //
    // This is a per-CALL decision, not a per-session latch: because
    // notify_capture_started() is invoked both on the should_capture
    // false->true edge AND, while capturing persists unrecorded, by
    // InputChannel's bounded re-notify (see compute_should_
    // renotify_capture_started(), autostream_monitor_utils.h), an Ignored
    // outcome here is naturally revisited roughly once a second for as long
    // as the input keeps capturing -- the hold's OWN expiry (or the replay
    // ending by another route) is what changes the outcome on some later
    // call, not anything remembered from this one.
    bool replay_hold_active  = false;
};

// Which specific LOG_* call (if any) a decision corresponds to. Chosen by
// decide_repeat_transition() (so the branching that picks the message lives
// in exactly one place, the decision table) but actually printed by
// RepeatController::handle_event_locked(), since decide_repeat_transition()
// itself must stay pure (no I/O) to remain unit-testable without pulling in
// the logging macros/real member state. Messages that need data only the
// heavy, non-decision work computes (encoded codec, byte counts, trim
// bytes...) are NOT covered here -- those stay exactly where they are today,
// logged by the wrapper after handle_event_locked() returns.
enum class RepeatLogTag
{
    None,
    DisabledMidState,                    // EnabledOff, non-Idle non-fade states
    ReenabledRestoringLiveInterrupt,      // EnabledOn, Discard+restorable
    CaptureStartIgnoredFadeInProgress,    // CaptureStarted, Ignored (LiveInterrupt pending)
    CaptureStartIgnoredDiscardPending,    // CaptureStarted, Ignored (Discard pending)
    CaptureStartIgnoredReplayHoldActive,  // CaptureStarted, Ignored (minimum playback hold)
    LiveInterruptFadingOutReplay,         // CaptureStarted, Replaying -> FadingOut
    LiveInterruptUpgradingDisarmFade,     // CaptureStarted, FadingOut upgrade
    CaptureStoppedPendingCancelled,       // CaptureStopped, Pending -> Idle
    DisarmDuringReplayFadingOut,          // Disarmed, Replaying -> FadingOut
    ReplaySessionEndedDiscarded,          // ReplaySessionEnded, Discard
    ReplaySessionEndedLiveInterruptFreed, // ReplaySessionEnded, LiveInterrupt
    ReplaySessionEndedRetainedHold,       // ReplaySessionEnded, None -> Hold
};

// Pure decision returned by decide_repeat_transition(): describes what
// should change and which of the wrapper's existing side-effect calls
// applies, but performs no mutation and no I/O itself -- the caller (the
// locked wrapper via RepeatController::handle_event_locked(), or a test) is
// responsible for actually writing the mirror fields (via
// RepeatController::transition_locked()/set_origin_locked()) and invoking
// the flagged side effects. Fields are additive flags, not a single variant,
// because some real cells combine more than one (e.g. CaptureStarted while
// Hold both frees the stale recording AND starts a new Pending session).
struct RepeatDecision
{
    enum class Kind
    {
        Apply,        // valid transition/action; apply the fields below
        Ignored,      // valid "nothing to do this time" cell (a fade or
                      // discard is already in flight) -- logged at DEBUG in
                      // the original code; kept distinct from NoOp so the
                      // matrix comment can call it out explicitly
        NoOp,         // valid, deliberately-defensive no-op cell (matches
                      // today's code's silent `return`) -- NOT an error
        Impossible,   // never reached in production (the wrapper's own
                      // re-validation excludes it before the event is ever
                      // raised); caller asserts-and-logs
    };
    Kind kind = Kind::NoOp;

    bool        change_state = false;
    RepeatState next_state    = RepeatState::Idle;

    bool set_origin    = false;
    int  origin_input   = 0;

    bool          set_pending_action           = false;
    PendingAction pending_action                = PendingAction::None;
    bool          set_pending_interrupt_input   = false;
    int           pending_interrupt_input       = 0;
    bool          set_pending_restorable        = false;
    bool          pending_restorable            = false;

    // Which of the wrapper's existing helper calls this cell's original code
    // issues, in addition to the plain field writes above. The wrapper still
    // owns the actual call; this only says which one applies. Applied (by
    // handle_event_locked()) in this fixed order, derived from the order the
    // original code performed them in every cell that combines more than
    // one: pending-bookkeeping fields, then do_free_recording, then
    // change_state/set_origin, then do_request_abort, then
    // do_request_fade_out, then do_begin_replay, then
    // do_request_pending_start.
    bool do_request_fade_out      = false;
    bool do_request_abort         = false;
    bool do_request_pending_start = false;
    bool do_free_recording        = false;   // free_recording_locked()
    bool do_begin_replay          = false;   // begin_replay_locked()

    RepeatLogTag log_tag = RepeatLogTag::None;
};

// =============================================================================
// The pure decision core + the RepeatState x RepeatEvent matrix it
// implements. Reproduces, cell for cell, the behaviour that used to be
// hand-coded across set_enabled()/notify_capture_started()/notify_capture_
// stopped()/set_armed()/notify_input_stopped()/on_replay_session_ended_
// locked_entry()/perform_pending_start(). Free function (not a
// RepeatController member), defined `inline` right here (not in
// autostream_repeat.cpp) so it stays link-independent of libtwolame/
// libmpg123 (real deps of the rest of that TU) -- it takes every input
// explicitly, touches no shared state, allocates nothing, blocks on
// nothing, and does no I/O, so it can be driven directly, cell by cell, by
// core/monitor/tests/test_repeat_transitions.cpp with a bare
// `g++ -I core/monitor`, the same zero-dependency pattern
// autostream_repeat_buffer.h/autostream_spsc_ring.h already use.
// RepeatController::handle_event_locked() (autostream_repeat.cpp) is the
// only production caller: it supplies the current locked state, applies the
// returned RepeatDecision's field writes via the transition_locked()/
// set_origin_locked() choke points, and runs the flagged side effects.
//
// Rows are RepeatState (declaration order: Idle, Recording, Hold, Replaying,
// FadingOut, Pending); columns are RepeatEvent. Each cell is one of:
//   Apply(...)    -- transition/action fires; "..." summarises the effect.
//   NoOp          -- deliberate no-op in today's code (a silent early
//                    `return`, e.g. a defensive "should not happen" guard).
//                    Not an error -- preserved exactly, not tightened.
//   Ignored(...)  -- a valid "nothing to do this time" cell today's code
//                    logs at LOG_DEBUG (a retrigger while a fade is already
//                    in flight); distinct from NoOp only for documentation.
//   IMPOSSIBLE    -- decide_repeat_transition() asserts-and-logs (via
//                    handle_event_locked()) rather than silently no-op'ing.
//                    Only reached here if a caller's own re-validation
//                    guard (which always runs first in production) is
//                    itself buggy -- see PendingStartSucceeded/Failed below.
//
// EnabledOn and EnabledOff do not depend on `state` for their branch choice
// except via the Replaying/FadingOut check baked into the cell text below
// (their original code -- set_enabled() -- guards on _state but the guard's
// *outcome* only really varies between "Idle" / "Replaying-or-FadingOut" /
// "everything else"; written out per-state below for completeness).
//
// ┌────────────┬───────────────────────────────┬──────────────────────────────┐
// │ state      │ EnabledOn                      │ EnabledOff                    │
// ├────────────┼───────────────────────────────┼──────────────────────────────┤
// │ Idle       │ NoOp                            │ NoOp (armed left untouched)   │
// │ Recording  │ NoOp                            │ Apply: FreeRecording, armed=0 │
// │ Hold       │ NoOp                            │ Apply: FreeRecording, armed=0 │
// │ Pending    │ NoOp                            │ Apply: FreeRecording, armed=0 │
// │ Replaying  │ Apply iff Discard+restorable:   │ Apply: pending=Discard        │
// │            │   pending->LiveInterrupt        │   (snapshot restorable),      │
// │            │ else NoOp                       │   RequestAbort, armed=0       │
// │ FadingOut  │ (same as Replaying)             │ (same as Replaying)           │
// └────────────┴───────────────────────────────┴──────────────────────────────┘
//
// ┌────────────┬────────────────────────────────────────────────────────────┐
// │ state      │ CaptureStarted (input_index)                                │
// ├────────────┼────────────────────────────────────────────────────────────┤
// │ (any)      │ !enabled_cfg -> NoOp (checked before state, all rows)       │
// │ Idle       │ Apply: origin=input, state->Pending, RequestPendingStart    │
// │ Recording  │ NoOp ("should not happen"; single origin input, defensive)  │
// │ Hold       │ Apply: FreeRecording, origin=input, state->Pending,         │
// │            │   RequestPendingStart                                       │
// │ Replaying  │ pending==LiveInterrupt -> Ignored (retrigger, already going)│
// │            │ pending==Discard       -> Ignored (discard already pending) │
// │            │ ctx.replay_hold_active -> Ignored (minimum playback hold;   │
// │            │   NO state change, NO pending latch)                        │
// │            │ else -> Apply: pending->LiveInterrupt(input),               │
// │            │   state->FadingOut, RequestFadeOut                          │
// │ FadingOut  │ (same Ignored branches, incl. replay_hold_active); else ->  │
// │            │   Apply: pending->LiveInterrupt(input), NO state change,   │
// │            │   no RequestFadeOut ("upgrade" -- the fade already running │
// │            │   is untouched)                                             │
// │ Pending    │ NoOp ("should not happen")                                  │
// └────────────┴────────────────────────────────────────────────────────────┘
//
// CaptureStarted delivery, minimum playback hold: notify_capture_started()
// (autostream_repeat.cpp) is called by InputChannel both on the should_
// capture false->true EDGE and, while capturing persists and this input is
// not yet the one actually being recorded (RepeatController::recording_
// wanted() false), by a bounded ~1/s RE-NOTIFY (compute_should_renotify_
// capture_started(), autostream_monitor_utils.h). This is what lets an
// Ignored outcome above (replay_hold_active, or a fade/discard already in
// flight) get revisited automatically once the blocking condition clears --
// without it, a session that arrived mid-hold would never start for as
// long as it kept capturing. Every cell this can repeat into is either a
// defensive NoOp (Recording/Pending), an Ignored no-op cell that already
// tolerates repeats by design (fade/discard/hold-active), or an Apply cell
// that flips state_fast in a way that makes recording_wanted() true on its
// very next check (Idle/Hold -> Pending) -- so no cell fires its side
// effects more than once per actual admission.
//
// ┌────────────┬────────────────────────────────────────────────────────────┐
// │ state      │ CaptureStopped (input_index; wrapper already matched origin)│
// ├────────────┼────────────────────────────────────────────────────────────┤
// │ Idle       │ NoOp                                                        │
// │ Recording  │ Apply: state->Hold (wrapper does the drain wait +           │
// │            │   flush/trim/encoder-teardown around this call, unchanged) │
// │ Hold       │ NoOp                                                        │
// │ Replaying  │ NoOp                                                        │
// │ FadingOut  │ NoOp                                                        │
// │ Pending    │ Apply: state->Idle, origin=0 ("cancelled" before the        │
// │            │   recorder worker even reached perform_pending_start())     │
// └────────────┴────────────────────────────────────────────────────────────┘
//
// ┌────────────┬─────────────────────────────┬──────────────────────────────┐
// │ state      │ Armed                        │ Disarmed                      │
// ├────────────┼─────────────────────────────┼──────────────────────────────┤
// │ Idle       │ NoOp                          │ NoOp                          │
// │ Recording  │ NoOp (replay starts at the    │ NoOp                          │
// │            │   next CaptureStopped)        │                                │
// │ Hold       │ Apply: BeginReplay            │ NoOp                          │
// │ Replaying  │ NoOp (already armed)          │ Apply: state->FadingOut,      │
// │            │                                │   RequestFadeOut (D5)         │
// │ FadingOut  │ NoOp                           │ NoOp (fade in flight          │
// │            │                                │   continues untouched)        │
// │ Pending    │ NoOp                           │ NoOp                          │
// └────────────┴─────────────────────────────┴──────────────────────────────┘
//
// ┌────────────┬────────────────────────────────────────────────────────────┐
// │ state      │ InputStopped (input_index; wrapper already matched origin)  │
// ├────────────┼────────────────────────────────────────────────────────────┤
// │ Idle       │ Apply: FreeRecording (matches free_recording_locked()'s own │
// │ Hold       │   no-op-if-already-idle semantics)                          │
// │ Pending    │ Apply: FreeRecording                                        │
// │ Recording  │ Apply: FreeRecording (wrapper does the bounded drain wait   │
// │            │   before calling this, unchanged)                           │
// │ Replaying  │ Apply: pending->Discard, RequestAbort (never restorable --  │
// │ FadingOut  │   _pending_interrupt_restorable deliberately left untouched)│
// └────────────┴────────────────────────────────────────────────────────────┘
//
// ┌────────────┬────────────────────────────────────────────────────────────┐
// │ state      │ ReplaySessionEnded (pending_action / interrupting_input /   │
// │            │ has_hold_bytes come from ctx; see RepeatEventCtx)           │
// ├────────────┼────────────────────────────────────────────────────────────┤
// │ Idle/Hold/ │ NoOp ("already handled by a racing notify_input_stopped()/  │
// │ Pending    │   set_enabled(false)")                                      │
// │ Replaying  │ pending==Discard      -> Apply: FreeRecording               │
// │ FadingOut  │ pending==LiveInterrupt-> Apply: FreeRecording; if enabled_cfg│
// │ (identical)│   also origin=interrupting_input, state->Pending,           │
// │            │   RequestPendingStart                                       │
// │            │ pending==None         -> Apply: state->Hold; if armed &&    │
// │            │   enabled_cfg && has_hold_bytes also BeginReplay            │
// └────────────┴────────────────────────────────────────────────────────────┘
//
// ┌────────────┬───────────────────────────────┬────────────────────────────┐
// │ state      │ PendingStartSucceeded          │ PendingStartFailed          │
// ├────────────┼───────────────────────────────┼────────────────────────────┤
// │ Pending    │ Apply: state->Recording        │ Apply: state->Idle, origin=0│
// │ (other 5)  │ IMPOSSIBLE (wrapper's own       │ IMPOSSIBLE (same guard)     │
// │            │   re-validation excludes this   │                              │
// │            │   before raising the event)     │                              │
// └────────────┴───────────────────────────────┴────────────────────────────┘
//
// No disagreement was found between the six functions' implied outcomes for
// any (state, event) cell: each RepeatEvent maps 1:1 to exactly one of the
// original six functions (plus perform_pending_start(), folded in above --
// see RepeatEvent's declaration comment), so no two functions ever compete
// to define the same cell.
// =============================================================================

inline RepeatDecision decide_repeat_transition(RepeatState state, bool armed, bool enabled_cfg,
                                                PendingAction pending_action, bool pending_restorable,
                                                RepeatEvent event, const RepeatEventCtx& ctx)
{
    RepeatDecision d;

    switch (event)
    {
        case RepeatEvent::EnabledOn:
        {
            if ((state == RepeatState::Replaying || state == RepeatState::FadingOut) &&
                pending_action == PendingAction::Discard && pending_restorable)
            {
                d.kind = RepeatDecision::Kind::Apply;
                d.set_pending_action = true;
                d.pending_action = PendingAction::LiveInterrupt;
                d.set_pending_restorable = true;
                d.pending_restorable = false;
                d.log_tag = RepeatLogTag::ReenabledRestoringLiveInterrupt;
            }
            else
            {
                d.kind = RepeatDecision::Kind::NoOp;
            }
            return d;
        }

        case RepeatEvent::EnabledOff:
        {
            if (state == RepeatState::Idle)
            {
                d.kind = RepeatDecision::Kind::NoOp;
                return d;
            }
            d.kind = RepeatDecision::Kind::Apply;
            d.log_tag = RepeatLogTag::DisabledMidState;
            if (state == RepeatState::Replaying || state == RepeatState::FadingOut)
            {
                d.set_pending_restorable = true;
                d.pending_restorable = (pending_action == PendingAction::LiveInterrupt);
                d.set_pending_action = true;
                d.pending_action = PendingAction::Discard;
                d.do_request_abort = true;
            }
            else   // Recording, Hold, Pending
            {
                d.do_free_recording = true;
            }
            return d;
        }

        case RepeatEvent::CaptureStarted:
        {
            if (!enabled_cfg)
            {
                d.kind = RepeatDecision::Kind::NoOp;
                return d;
            }
            if (state == RepeatState::Recording || state == RepeatState::Pending)
            {
                d.kind = RepeatDecision::Kind::NoOp;   // "should not happen"; defensive
                return d;
            }
            if (state == RepeatState::Replaying || state == RepeatState::FadingOut)
            {
                if (pending_action == PendingAction::LiveInterrupt)
                {
                    d.kind = RepeatDecision::Kind::Ignored;
                    d.log_tag = RepeatLogTag::CaptureStartIgnoredFadeInProgress;
                    return d;
                }
                if (pending_action == PendingAction::Discard)
                {
                    d.kind = RepeatDecision::Kind::Ignored;
                    d.log_tag = RepeatLogTag::CaptureStartIgnoredDiscardPending;
                    return d;
                }
                // Minimum playback hold: the active replay (or its fade-out)
                // still owns playback. Ignore this live transient outright --
                // no state change, no pending-interrupt latch -- rather than
                // starting the usual fade-out/takeover sequence. Nothing is
                // latched here to remember the transient: InputChannel's
                // bounded re-notify (compute_should_renotify_capture_
                // started(), autostream_monitor_utils.h) keeps calling
                // notify_capture_started() roughly once a second for as
                // long as this input keeps capturing unrecorded, so once
                // ctx.replay_hold_active goes false on some later call --
                // the hold expired, or the replay ended by another route --
                // that later call is what actually starts the takeover.
                if (ctx.replay_hold_active)
                {
                    d.kind = RepeatDecision::Kind::Ignored;
                    d.log_tag = RepeatLogTag::CaptureStartIgnoredReplayHoldActive;
                    return d;
                }

                d.kind = RepeatDecision::Kind::Apply;
                d.set_pending_action = true;
                d.pending_action = PendingAction::LiveInterrupt;
                d.set_pending_interrupt_input = true;
                d.pending_interrupt_input = ctx.input_index;
                d.set_pending_restorable = true;
                d.pending_restorable = false;

                if (state == RepeatState::Replaying)
                {
                    d.change_state = true;
                    d.next_state = RepeatState::FadingOut;
                    d.do_request_fade_out = true;
                    d.log_tag = RepeatLogTag::LiveInterruptFadingOutReplay;
                }
                else   // FadingOut: upgrade an in-flight disarm fade in place
                {
                    d.log_tag = RepeatLogTag::LiveInterruptUpgradingDisarmFade;
                }
                return d;
            }

            // Idle or Hold: new capture session.
            d.kind = RepeatDecision::Kind::Apply;
            if (state == RepeatState::Hold)
                d.do_free_recording = true;
            d.change_state = true;
            d.next_state = RepeatState::Pending;
            d.set_origin = true;
            d.origin_input = ctx.input_index;
            d.do_request_pending_start = true;
            return d;
        }

        case RepeatEvent::CaptureStopped:
        {
            if (state == RepeatState::Pending)
            {
                d.kind = RepeatDecision::Kind::Apply;
                d.change_state = true;
                d.next_state = RepeatState::Idle;
                d.set_origin = true;
                d.origin_input = 0;
                d.log_tag = RepeatLogTag::CaptureStoppedPendingCancelled;
                return d;
            }
            if (state != RepeatState::Recording)
            {
                d.kind = RepeatDecision::Kind::NoOp;
                return d;
            }
            d.kind = RepeatDecision::Kind::Apply;
            d.change_state = true;
            d.next_state = RepeatState::Hold;
            return d;
        }

        case RepeatEvent::Armed:
        {
            if (state == RepeatState::Hold)
            {
                d.kind = RepeatDecision::Kind::Apply;
                d.do_begin_replay = true;
            }
            else
            {
                d.kind = RepeatDecision::Kind::NoOp;
            }
            return d;
        }

        case RepeatEvent::Disarmed:
        {
            if (state == RepeatState::Replaying)
            {
                d.kind = RepeatDecision::Kind::Apply;
                d.change_state = true;
                d.next_state = RepeatState::FadingOut;
                d.do_request_fade_out = true;
                d.log_tag = RepeatLogTag::DisarmDuringReplayFadingOut;
            }
            else
            {
                d.kind = RepeatDecision::Kind::NoOp;
            }
            return d;
        }

        case RepeatEvent::InputStopped:
        {
            d.kind = RepeatDecision::Kind::Apply;
            if (state == RepeatState::Replaying || state == RepeatState::FadingOut)
            {
                d.set_pending_action = true;
                d.pending_action = PendingAction::Discard;
                d.do_request_abort = true;
            }
            else   // Idle, Recording, Hold, Pending
            {
                d.do_free_recording = true;
            }
            return d;
        }

        case RepeatEvent::ReplaySessionEnded:
        {
            if (state != RepeatState::Replaying && state != RepeatState::FadingOut)
            {
                d.kind = RepeatDecision::Kind::NoOp;
                return d;
            }
            d.kind = RepeatDecision::Kind::Apply;
            // Single pending action, consulted AND CLEARED exactly once
            // here, unconditionally, regardless of which of the three
            // branches below fires -- matches the original code's snapshot-
            // then-clear-then-branch order (on_replay_session_ended_locked_
            // entry()'s comment above). See PendingAction's declaration
            // comment for the full set/clear matrix.
            d.set_pending_action = true;
            d.pending_action = PendingAction::None;
            d.set_pending_restorable = true;
            d.pending_restorable = false;
            if (pending_action == PendingAction::Discard)
            {
                d.do_free_recording = true;
                d.log_tag = RepeatLogTag::ReplaySessionEndedDiscarded;
            }
            else if (pending_action == PendingAction::LiveInterrupt)
            {
                d.do_free_recording = true;
                d.log_tag = RepeatLogTag::ReplaySessionEndedLiveInterruptFreed;
                if (enabled_cfg)
                {
                    d.change_state = true;
                    d.next_state = RepeatState::Pending;
                    d.set_origin = true;
                    d.origin_input = ctx.interrupting_input;
                    d.do_request_pending_start = true;
                }
            }
            else   // PendingAction::None
            {
                d.change_state = true;
                d.next_state = RepeatState::Hold;
                d.log_tag = RepeatLogTag::ReplaySessionEndedRetainedHold;
                if (armed && enabled_cfg && ctx.has_hold_bytes)
                    d.do_begin_replay = true;
            }
            return d;
        }

        case RepeatEvent::PendingStartSucceeded:
        {
            if (state != RepeatState::Pending)
            {
                d.kind = RepeatDecision::Kind::Impossible;
                return d;
            }
            d.kind = RepeatDecision::Kind::Apply;
            d.change_state = true;
            d.next_state = RepeatState::Recording;
            return d;
        }

        case RepeatEvent::PendingStartFailed:
        {
            if (state != RepeatState::Pending)
            {
                d.kind = RepeatDecision::Kind::Impossible;
                return d;
            }
            d.kind = RepeatDecision::Kind::Apply;
            d.change_state = true;
            d.next_state = RepeatState::Idle;
            d.set_origin = true;
            d.origin_input = 0;
            return d;
        }
    }

    d.kind = RepeatDecision::Kind::Impossible;   // unreachable: all enumerators handled above
    return d;
}

class RepeatController
{
public:
    // fifo_mutex: AudioMonitor's shared FIFO mutex. RepeatController never
    // holds it and _repeat_mutex simultaneously across a blocking call --
    // only brief, non-nested critical sections in either, per the lock-order
    // note above and the extended proof comment in autostream_monitor_io.cpp.
    // output_processor: AudioMonitor's shared OutputProcessor -- replay
    // now runs the live DSP chain, so ReplayEngine calls output_processor.
    // apply() itself, under _fifo_mutex exactly as the live InputChannel path
    // does (never across the blocking write), immediately before quantising
    // to the pipe format.
    RepeatController(int sample_rate_hz, std::mutex& fifo_mutex, OutputProcessor& output_processor);
    ~RepeatController();

    // Starts the recorder and replay worker threads. Called once at daemon init.
    void start();

    // Stops both worker threads and frees any recording. Called at daemon shutdown.
    void stop();

    // Per-origin-input parameters ReplayEngine needs for its own
    // TrackGapDetector: the pre-computed silence-threshold sample
    // and the configured track-change gap duration. Queried once at
    // notify_capture_started() and snapshotted for the recording/replay's
    // lifetime -- replay never reaches back into a (possibly stopped)
    // InputChannel.
    struct InputParams
    {
        int   silence_threshold_sample        = 0;
        float track_change_silence_seconds    = 1.25f;
        // Minimum playback hold in effect for this input at recording start,
        // seconds; 0 disables the hold. Snapshotted the same way as the
        // fields above and used to gate replay-hold takeover suppression
        // (see decide_repeat_transition()'s CaptureStarted cell).
        int   minimum_playback_seconds        = 30;
    };
    void set_input_params_query(std::function<InputParams(int)> query)
    {
        _input_params_query = std::move(query);
    }

    // Live DSP parameters ReplayEngine pulls from the origin
    // InputChannel each staging refill (~1 s cadence) so gain/EQ changes made
    // WHILE replay is active are heard, unlike InputParams above (which is a
    // one-shot snapshot taken at recording start). The origin InputChannel
    // stays alive and queryable throughout a replay session -- capture
    // stopping only clears _capturing/_allow_capture, it never destructs or
    // stop()s the channel -- so reaching back into it here (unlike
    // InputParams' snapshot-and-hold design) is safe for the whole replay
    // lifetime; notify_input_stopped() (the one path that DOES tear the
    // channel down) unconditionally aborts any active replay first.
    struct LiveDspParams
    {
        float gain_linear = 1.0f;
        std::shared_ptr<const std::vector<EqBand>> eq_bands;
        float eq_sample_rate = 48000.0f;
    };
    void set_live_dsp_query(std::function<LiveDspParams(int)> query)
    {
        _live_dsp_query = std::move(query);
    }

    // Called by ReplayEngine (its own thread); never blocks beyond the cost
    // of invoking the stored callback (a couple of atomic loads + a
    // shared_ptr copy on the AudioMonitor side -- see the wiring in
    // AudioMonitor's constructor). Returns flat/unity defaults if no query
    // has been installed (never happens in production; defensive for tests).
    LiveDspParams query_live_dsp_params(int input_index) const
    {
        return _live_dsp_query ? _live_dsp_query(input_index) : LiveDspParams{};
    }

    // Records the current FIFO path so ReplayEngine can open its own
    // blocking fd on it at replay start. Called by AudioMonitor whenever
    // api_set_fifo() changes FifoWriter's path.
    void set_fifo_path(const std::string& path);

    // {"type":"set_repeat_enabled",...} handler. codec_text must be one of
    // auto|mp2_160|mp2_192|mp2_224|mp2_256|mp2_320|mp2_384|pcm ("" is treated
    // as "auto"). target_minutes is the target-duration goal (the socket
    // API's optional "target_minutes" field): pass a negative value (the
    // socket handler's json_get_int(..., -1) default) to mean "field
    // omitted, leave whatever is already configured" -- it does NOT reset to
    // kDefaultRepeatTargetMinutes on every call, only the first time this
    // controller is ever constructed. A non-negative value is clamped to
    // [kMinRepeatTargetMinutes, kMaxRepeatTargetMinutes]. Returns "" on
    // success or a non-empty error string. Enabling takes effect at
    // the next capture session (no special-casing needed -- begin_session
    // only runs at a should_capture edge); disabling frees any recording
    // (RECORDING or HOLD) immediately, and fades+frees an active replay.
    std::string set_enabled(bool enabled, const std::string& codec_text, int target_minutes = -1);

    // {"type":"set_repeat_armed",...} handler. Setting armed=true
    // while HOLD (finished recording, idle) starts replay immediately.
    // Setting armed=false while REPLAYING triggers the 1.5 s disarm fade
    // (D5); the buffer is retained (HOLD) afterwards and remains re-armable.
    // Returns "" always (no rejectable inputs beyond the bool itself).
    std::string set_armed(bool armed);

    // Fast, lock-free check for the audio-thread tap call site. Must stay
    // cheap: a single relaxed atomic load in the common disabled case.
    bool recording_wanted(int input_index) const;

    // Fast, lock-free "is the repeat feature on at all" check -- a single
    // relaxed atomic load, the same mirror recording_wanted() itself
    // consults first. Exposed separately because InputChannel's
    // re-notify decision (see compute_should_renotify_capture_started(),
    // autostream_monitor_utils.h) needs to distinguish "disabled" from
    // "enabled but not recording ME" -- recording_wanted() alone collapses
    // both to false.
    bool enabled() const
    {
        return _enabled_fast.load(std::memory_order_relaxed);
    }

    // Fast, lock-free check for the live FIFO-write gate (autostream_monitor_
    // io.cpp): true while ReplayEngine owns the pipe, meaning the live
    // process threads must discard their output (detection/metering upstream
    // of this check keeps running regardless).
    bool is_fifo_owned_by_replay() const
    {
        return _fifo_owner_fast.load(std::memory_order_relaxed) == static_cast<int>(FifoOwner::Replay);
    }

    // Forwards to ReplayEngine's own stall tracker (see its doc
    // comment) for get_status()'s top-level "fifo.stalled_seconds" -- only
    // meaningful while is_fifo_owned_by_replay() is true; the caller picks
    // between this and FifoWriter::stalled_seconds() based on that flag.
    double replay_stalled_seconds() const { return _replay.stalled_seconds(); }

    // Forwards to the recorder's non-blocking ring submit. Only meaningful
    // immediately after recording_wanted(input_index) returned true (exactly
    // one input is ever the recording's origin at a time).
    void submit_float_block(const float* interleaved, int frames, bool above_threshold)
    {
        _recorder.submit_block(interleaved, frames, above_threshold);
    }

    // Called by InputChannel::process_thread_func at the should_capture
    // false->true / true->false edges -- already gated by _allow_capture via
    // should_capture. notify_capture_stopped() is where the capture-stop ->
    // replay-start transition happens, atomic within one _repeat_mutex
    // critical section.
    // While REPLAYING/FADING_OUT, a should_capture edge on
    // ANY input (the origin input resuming, or the other input going live)
    // is treated as the live-interrupt trigger -- transitions to
    // FADING_OUT(LiveInterrupt) (or upgrades an in-flight Disarm fade to
    // LiveInterrupt) rather than being ignored.
    void notify_capture_started(int input_index);
    void notify_capture_stopped(int input_index);

    // Called by InputChannel on stop_input() of the current origin input
    // (reload/teardown path): discards the buffer and cancels any
    // active replay unconditionally, no fade (D12).
    void notify_input_stopped(int input_index);

    // Called by RepeatRecorder's worker thread for each drained block.
    void process_recorder_samples(const float* interleaved, int frames, bool above_threshold);

    // Called by RepeatRecorder's worker thread once per outer loop iteration
    // (~every 50 ms, regardless of ring activity) so a cached /proc/meminfo
    // reading stays available for get_status()'s max_recording_seconds even
    // while enabled-but-idle. Internally throttled to a real file
    // read at most every kMemCheckIntervalSeconds; a no-op while disabled or
    // while a session is Recording (that path maintains its own reading).
    void maybe_refresh_idle_meminfo_cache();

    // Whether replay is currently serving as the source of truth for
    // input_index's track-ID/snapshot data -- true while REPLAYING
    // or FADING_OUT and input_index == the recording's origin_input. Used by
    // AudioMonitor to route get_status()'s per-input track_change_seq and
    // get_id_snapshot() to the ReplayEngine tap instead of the InputChannel.
    bool is_replay_sourcing_input(int input_index) const;

    // Replay-routed accessors, valid only when is_replay_sourcing_input()
    // is true for the same input_index; harmless (return 0-ish defaults)
    // otherwise since the caller always checks is_replay_sourcing_input() first.
    uint32_t replay_track_change_seq() const { return _replay.track_change_seq(); }
    unsigned replay_get_id_snapshot(int16_t* out, unsigned max_frames) const
    {
        return _replay.get_id_snapshot(out, max_frames);
    }

    RepeatStatus get_status() const;

    // ── Callbacks from ReplayEngine (its own thread); each takes _repeat_mutex ──
    // Fade completed (disarm) or the write path hit a hard error: both
    // land the controller back in HOLD with the buffer retained, flip
    // FifoOwner back to Live, and close ReplayEngine's fd. Called by
    // ReplayEngine's own thread once it has stopped writing.
    void on_replay_session_ended_locked_entry();

#ifdef AUTOSTREAM_REPEAT_TEST_HOOKS
    // Test-only: writes the current recording buffer's raw encoded bytes to
    // path for offline verification (e.g. ffprobe/mpg123 decode of an MP2
    // capture). Compiled only when AUTOSTREAM_REPEAT_TEST_HOOKS is defined at
    // build time; autostream_install.sh's production build line never
    // defines this macro, so it does not exist in the shipped binary
    // Returns "" on success or an error.
    std::string debug_dump_buffer(const std::string& path) const;
#endif

private:
    friend class ReplayEngine;
    friend class RepeatRecorder;   // calls perform_pending_start()

    // Detaches the current recording's chunks (cheap, under
    // _repeat_mutex) and returns them for the CALLER to destroy after
    // releasing the lock -- see RepeatBuffer::steal_chunks()'s comment for
    // the exact declaration-order pattern every call site uses. Caller
    // holds _repeat_mutex; the returned container must be kept alive (by a
    // local variable declared BEFORE the caller's lock_guard) until after
    // the lock is released.
    std::deque<RepeatBuffer::Chunk> free_recording_locked();

    // Single mutation choke points: every direct write to the
    // _state/_state_fast pair or the _origin_input/_origin_input_fast pair
    // funnels through exactly one of these two, so the atomic-mirror
    // invariant is enforced by construction instead of by convention -- see
    // autostream_repeat.cpp for the grep proof (exactly one line writes
    // _state_fast, one writes _origin_input_fast). Caller must already hold
    // _repeat_mutex (same precondition as every other *_locked() helper in
    // this class; this codebase has no "assert mutex held by this thread"
    // idiom elsewhere, so this is documented, not asserted, consistent with
    // free_recording_locked()/begin_replay_locked() above). Also logs the
    // transition at LOG_DEBUG (the finest granularity already used for
    // repeat's non-terminal events, e.g. the CaptureStarted "ignoring"
    // messages below -- this codebase has no separate DIAG level).
    void transition_locked(RepeatState next);
    void set_origin_locked(int input_index);
    void set_enabled_locked(bool enabled);

    // Applies a RepeatDecision from decide_repeat_transition() --
    // writes the mirror fields it flags (via the choke points above) and
    // runs the flagged side-effect calls (free_recording_locked(),
    // begin_replay_locked(), ReplayEngine commands,
    // _recorder.request_pending_start()), plus the transition-specific
    // LOG_INFO/LOG_DEBUG the original branch used to print (see
    // RepeatLogTag). Does NOT touch _armed (no fast mirror; the six
    // wrappers still write it directly, exactly where they do today) and
    // does NOT do the drain-wait / unlock-relock choreography --
    // callers keep doing that exactly where they do today, calling this
    // only once a decision is ready to commit. Returns any chunks freed by
    // a do_free_recording side effect (empty when none), so the caller
    // can keep them alive in its own pre-lock_guard local until after the
    // lock releases, exactly as free_recording_locked()'s direct callers do.
    // See the state x event matrix comment above this function's definition
    // in autostream_repeat.cpp.
    std::deque<RepeatBuffer::Chunk> handle_event_locked(RepeatEvent event,
                                                          const RepeatEventCtx& ctx = RepeatEventCtx{});

    // Begins replay from a HOLD recording. Caller holds _repeat_mutex. Used
    // by notify_capture_stopped() (armed at capture-stop), set_armed()
    // (arm-while-HOLD), and on_replay_session_ended_locked_entry()
    // (re-arm-during-a-disarm-fade restart).
    void begin_replay_locked();

    // The deferred second half of a session start, run by
    // RepeatRecorder's worker thread (never the audio thread) after
    // notify_capture_started() has already moved _state to Pending and
    // recorded _origin_input. Does the meminfo read + encoder construction
    // OUTSIDE _repeat_mutex, then re-validates _state == Pending after
    // reacquiring it before committing (a stop/disable/teardown may have
    // superseded the pending start while this ran). On success, flips
    // _state to Recording; on refusal (insufficient memory / encoder init
    // failure), flips back to Idle and records _unavailable_reason, exactly
    // matching what the old inline begin_session_locked() used to do.
    void perform_pending_start();

    // Flips FifoOwner under _fifo_mutex (briefly, never nested with
    // _repeat_mutex held across the flip's own duration beyond this call).
    void set_fifo_owner(FifoOwner owner);

    // Applies the 64 MiB free-RAM floor using an
    // ALREADY-FETCHED MemInfo -- this function itself never calls
    // read_meminfo(), so it is safe to call while holding _repeat_mutex
    // (the caller is responsible for having done the actual /proc read
    // outside the lock). Sheds oldest chunks until back above the floor.
    void apply_memory_guard_locked(const MemInfo& mem);

    // One raw block's worth of encode()+chunk-alloc+append+trim-accounting,
    // factored out of process_recorder_samples() so the same logic serves
    // both a live recorder block and a block drained from the pre-roll ring
    // after onset confirms. Caller holds `lock` (== _repeat_mutex)
    // and has already verified _state == Recording && _encoder; this
    // function may unlock/relock `lock` internally (chunk preallocation / a
    // periodic meminfo read), exactly as the pre-extraction body did, and
    // re-validates after reacquiring -- becomes a no-op if the session ended
    // while unlocked. Caller must re-check _state/_encoder itself before any
    // further call in the same outer iteration (see process_recorder_
    // samples()'s ring-drain loop).
    void encode_and_append_locked(std::unique_lock<std::mutex>& lock,
                                   const float* interleaved, int frames,
                                   bool above_threshold);

    // Recording is refused below this threshold regardless of pinned
    // codec (the pinned codec "skips the ladder" for quality-tier selection,
    // not for this base availability gate).
    static constexpr long   kMinAvailableMibForStart = 110;
    static constexpr double kMemCheckIntervalSeconds  = 30.0;
    // Trailing pad kept ahead of the tail cut, shared by both close-time
    // trims: the marker-based cut (last-sustained-run end + this pad, the
    // normal case once onset has confirmed) and the silence-timeout
    // fallback cut (measured trailing silence minus this pad). Same value,
    // same purpose either way -- never bite into the last audible moment.
    static constexpr double kSilenceTrimPadSeconds     = 1.0;
    // Bounded drain wait in notify_capture_stopped() before finalizing;
    // on timeout, whatever is still queued is counted into dropped_frames
    // rather than silently lost.
    static constexpr int    kDrainTimeoutMs            = 250;

    // Onset-gated recording: once OnsetGate confirms, the pre-roll
    // ring built up while onset was pending is drained into the normal
    // encode/append path a bounded number of blocks per
    // process_recorder_samples() call, rather than in one single burst. A
    // full 5 s burst is not expensive CPU-wise (twolame/PCM encode is fast
    // relative to real time), but process_recorder_samples() holds
    // _repeat_mutex across each encode()+append() call, and this function is
    // called from the audio-adjacent recorder worker thread while other
    // callers (get_status(), notify_capture_started/stopped() -- the latter
    // on the real audio thread) block on the same mutex; encoding ~5 s of
    // backlog in one uninterrupted critical section would hold the lock far
    // longer than any other call on this path ever does. Amortizing over a
    // handful of blocks per call keeps every single call's lock-hold time in
    // the same ballpark as ordinary live-block processing, while still
    // draining a multi-second ring within a couple of seconds of real time
    // (recorder blocks arrive well under a second apart).
    static constexpr int    kOnsetRingDrainBlocksPerCall = 8;

    int _sample_rate_hz;
    std::mutex& _fifo_mutex;   // AudioMonitor's shared FIFO mutex (reference)
    OutputProcessor& _output_processor;   // AudioMonitor's shared OutputProcessor
    std::function<InputParams(int)> _input_params_query;
    std::function<LiveDspParams(int)> _live_dsp_query;
    std::string _fifo_path;   // guarded by _repeat_mutex

    RepeatRecorder _recorder;
    ReplayEngine   _replay;

    mutable std::mutex _repeat_mutex;
    bool         _enabled_cfg = false;
    bool         _armed       = false;

    // Single pending post-fade action for ReplayEngine's terminal handler
    // (on_replay_session_ended_locked_entry()). A single enum instead of a
    // _pending_live_interrupt/_pending_discard_on_replay_end bool pair gives
    // this a well-defined precedence: two independent booleans can both be
    // true at once with no rule for which wins, whereas one enum can only
    // hold one value. The PendingAction enum itself lives at namespace scope
    // so decide_repeat_transition() can take it as a plain parameter -- see
    // its declaration above class RepeatController for the full set/clear matrix
    // writeup (moved verbatim from here).
    //
    //   _pending_interrupt_input records which input triggered a
    //   LiveInterrupt. It is deliberately left untouched (not zeroed) when
    //   Discard overwrites a pending LiveInterrupt, purely so a
    //   set_enabled(true) arriving before the terminal handler runs can
    //   restore LiveInterrupt -- see _pending_interrupt_restorable
    //   immediately below and set_enabled()'s implementation.
    PendingAction _pending_action = PendingAction::None;
    int           _pending_interrupt_input = 0;

    // True only while _pending_action == Discard AND that Discard
    // was produced by set_enabled(false) (never notify_input_stopped() --
    // that is an unconditional teardown of the origin input itself, so
    // there is nothing sensible to restore) overwriting an in-flight
    // LiveInterrupt. set_enabled(true) checks this flag: if it is still set
    // (the fade has not yet reached the terminal handler), it flips
    // _pending_action back to LiveInterrupt instead of leaving Discard
    // armed, so the terminal handler starts the new recording for
    // _pending_interrupt_input after freeing the old buffer. Decided
    // behaviour: disable alone during a live-interrupt fade means discard +
    // no new session, even though the fade was interrupt-triggered, UNLESS a
    // re-enable arrives before the fade's terminal handler runs, in which
    // case the interrupt is honoured after all.
    bool          _pending_interrupt_restorable = false;

    std::string  _codec_cfg   = "auto";
    // Target-duration goal in minutes for the codec-ladder selection
    // (pick_codec_for_target()); see set_enabled()'s doc comment for the
    // "field omitted" sentinel convention.
    int          _target_minutes_cfg = kDefaultRepeatTargetMinutes;
    RepeatState  _state       = RepeatState::Idle;
    int          _origin_input = 0;
    CodecChoice  _active_codec = CodecChoice::Unavailable;
    long         _max_recording_seconds = 0;
    std::string  _unavailable_reason;
    // Snapshotted at notify_capture_started() via _input_params_query(); held
    // for the recording/replay's lifetime so ReplayEngine's TrackGapDetector
    // seed values never need to reach back into a possibly-stopped
    // InputChannel.
    int          _origin_silence_threshold_sample     = 0;
    float        _origin_track_change_silence_seconds = 1.25f;
    // Minimum playback hold configured for the origin input at recording
    // start, seconds; 0 disables. Used only to gate replay-hold takeover
    // suppression (see _replay_start_time and the CaptureStarted handling
    // in notify_capture_started()) -- it plays no part in the recording
    // side of the hold, which InputChannel enforces on its own.
    int          _origin_minimum_playback_seconds     = 30;
#ifdef AUTOSTREAM_REPEAT_TEST_CHUNK_BYTES
    // Test-only: overrides RepeatBuffer's default 16 MiB chunk size so
    // memory-guard/sliding-window scenarios can be exercised
    // in seconds instead of minutes. Only defined by a hand-invoked test
    // build (never by autostream_install.sh's production g++ line), e.g.
    // -DAUTOSTREAM_REPEAT_TEST_CHUNK_BYTES=1048576.
    RepeatBuffer _buffer{static_cast<size_t>(AUTOSTREAM_REPEAT_TEST_CHUNK_BYTES)};
#else
    RepeatBuffer _buffer;
#endif
    SilenceTrimAccountant           _trim;
    // Onset-gated recording: OnsetGate decides when the recorder
    // may start committing audio; PreRollRing holds the raw backlog while
    // onset is still pending so nothing is lost once it confirms. Both are
    // (re)initialised at session start (perform_pending_start()) and cleared
    // at session end/discard (free_recording_locked(), notify_capture_
    // stopped()) -- see process_recorder_samples()'s implementation comment
    // for the full state machine.
    OnsetGate    _onset;
    PreRollRing  _preroll_ring;
    // Tail offset gate: tracks the committed-buffer position at the end of
    // the last sustained (music) run, fed once per block actually appended
    // to _buffer (encode_and_append_locked()) -- same call site as _trim
    // above. Drives notify_capture_stopped()'s tail cut whenever it has a
    // mark (the normal case once onset has confirmed), taking over from the
    // silence-timeout cut so run-out crackle and a tonearm clunk are
    // excluded from the recording the same way the onset gate already
    // excludes a start thump. (Re)initialised alongside _onset/_preroll_ring
    // at session start and cleared at session end/discard -- see those
    // members' own comment for the exact call sites.
    TailMarker   _tail_marker;
    std::unique_ptr<RepeatEncoder>  _encoder;
    double       _last_mem_check_time    = 0.0;
    // Monotonic timestamp set at begin_replay_locked(); 0.0 when no replay
    // has started this Hold cycle. Used with _origin_minimum_playback_seconds
    // to compute whether an active replay is still within its minimum
    // playback hold (see notify_capture_started()'s replay_hold_active
    // computation, passed to decide_repeat_transition() via RepeatEventCtx).
    double       _replay_start_time      = 0.0;
    uint64_t     _dropped_frames_baseline = 0;
    std::vector<uint8_t> _encode_scratch;

    // Idle-status meminfo cache: maintained ONLY by
    // maybe_refresh_idle_meminfo_cache(), called from RepeatRecorder's
    // worker thread -- never read from /proc/meminfo on get_status()'s own
    // call path. -1 means "no reading yet" (get_status() reports 0/
    // unavailable in that window, e.g. briefly after daemon startup). Stores
    // MemInfo::effective_available_mib() (swap-aware), not raw MemAvailable,
    // since every consumer of this cache feeds it into sizing (get_status()'s
    // idle max_recording_seconds/codec pick).
    long         _cached_available_mib     = -1;
    double       _last_idle_mem_check_time = 0.0;

    // Fast lock-free mirrors of _enabled_cfg/_state/_origin_input, updated
    // under _repeat_mutex whenever those change, read without a lock by
    // recording_wanted() from the audio thread.
    std::atomic<bool> _enabled_fast{false};
    std::atomic<int>  _state_fast{0};          // mirrors RepeatState
    std::atomic<int>  _origin_input_fast{0};

    // Fast mirror of FifoOwner, flipped under _fifo_mutex by set_fifo_owner()
    // and read (relaxed, no lock) by is_fifo_owned_by_replay() from inside
    // the live path's own _fifo_mutex critical section.
    std::atomic<int> _fifo_owner_fast{static_cast<int>(FifoOwner::Live)};
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
    // repeat_controller: the AudioMonitor's RepeatController; recording_wanted()/
    //                   submit_float_block() are called at the float stage,
    //                   after apply() and before float->int16 conversion
    InputChannel(int               index,
                 FifoWriter&       shared_fifo,
                 std::mutex&       fifo_mutex,
                 OutputProcessor&  output_processor,
                 OutputDumpWriter& dump_writer,
                 RepeatController& repeat_controller);

    ~InputChannel();

    // Store the configuration.
    // If the channel is stopped: stores all fields.
    // If the channel is running: every field except alsa_device is applied
    //   immediately (silence_threshold_dbfs, silence_seconds,
    //   track_change_silence_seconds, minimum_playback_seconds); changes to
    //   alsa_device are rejected (caller must stop the channel first).
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
    // Applied on the resampled output (48000 Hz) in the process thread.
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

    // Snapshot of the two configuration values ReplayEngine needs to run its
    // own TrackGapDetector during replay: the
    // pre-computed silence-threshold sample (already an atomic on the hot
    // path) and the configured track-change gap duration. Captured once by
    // RepeatController::notify_capture_started() at the start of a recording
    // session and held for the lifetime of that recording/replay, so replay
    // never needs to reach back into a possibly-stopped InputChannel.
    //
    // Deliberate boundary conversion: the live path's internal threshold
    // is in the float domain (linear amplitude, 0.0..1.0 -- see
    // _silence_threshold_sample / compute_peak_sample()'s comments), but
    // ReplayEngine's own TrackGapDetector (autostream_repeat.cpp,
    // replay_peak_sample()) stays entirely in the legacy int16-scale
    // (0..32768) domain by design: replay stays int16 internally. This
    // accessor is the single seam between the two
    // domains -- it converts the internal linear threshold back to the
    // legacy int16-equivalent scale here, once, so every consumer on the
    // replay side keeps working against the same int scale it always has,
    // unaware that the live path's internal representation changed at all.
    int silence_threshold_sample() const
    {
        float linear = _silence_threshold_sample.load(std::memory_order_relaxed);
        int   scaled = static_cast<int>(linear * 32768.0f);
        return std::max(1, std::min(32767, scaled));
    }

    float track_change_silence_seconds() const
    {
        std::lock_guard<std::mutex> lock(_config_mutex);
        return _config.track_change_silence_seconds;
    }

    // Minimum playback hold configured for this input, seconds. Snapshotted
    // by RepeatController at recording start the same way as
    // track_change_silence_seconds() above, so a replay session uses the
    // hold duration that was in effect when its recording began.
    int minimum_playback_seconds() const
    {
        std::lock_guard<std::mutex> lock(_config_mutex);
        return _config.minimum_playback_seconds;
    }

    // ── Live DSP pull-model accessors ─────────────────────────────────────
    // ReplayEngine polls these (~1 s cadence, once per staging refill) instead
    // of caching gain/EQ at recording time, so a gain/EQ change made WHILE
    // replay is playing is heard during the loop, not just during the next
    // recording. Both are already lock-free/cheap on this input's own hot
    // path (_gain_linear is a relaxed atomic; EqChain::get_bands() is a
    // shared_ptr copy under a brief mutex, no allocation) so polling them from
    // the replay thread costs nothing measurable and never blocks the audio
    // process thread.  NOTE: this deliberately returns the CURRENT gain, not
    // the fade-in ramp multiplier (_ramp_frames_remaining) -- replay never
    // re-plays the live fade-in: only the
    // settled per-input gain applies during replay.
    float gain_linear() const
    {
        return _gain_linear.load(std::memory_order_relaxed);
    }

    std::shared_ptr<const std::vector<EqBand>> eq_bands() const
    {
        return _eq_chain.get_bands();
    }

    float eq_sample_rate() const
    {
        return _eq_chain.sample_rate();
    }

    // Returns true if start() has been called and stop() has not yet completed
    // (includes the case where the capture thread self-stopped after an ALSA
    // error but stop() has not been called to join the threads).  Use this to
    // detect the crashed-but-not-cleaned-up state in api_start_input().
    bool is_started() const { return _started.load(); }

    // Test-only (--test-hooks): arms a one-shot flag that makes the capture
    // thread take the exact same exit path as a genuine unrecoverable ALSA
    // read error on its next loop iteration (see capture_thread_func()).
    // Gated at the command-dispatch level (ControlServer::dispatch_command()/
    // AudioMonitor::api_debug_fail_input()) on AudioMonitor::test_hooks_enabled();
    // this setter itself has no gate of its own, by design -- one gate,
    // checked once, is simpler to audit than two.
    void debug_inject_capture_failure() { _debug_fail_injected.store(true, std::memory_order_relaxed); }

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

    // ── process_thread_func() stage helpers ─────────────────────────────────
    // Extracted from the single ~745-line process_thread_func() loop body,
    // preserving its exact per-iteration execution order. Each is private,
    // defined in the same TU (autostream_monitor_io.cpp), non-virtual, and
    // takes only the per-iteration values it needs as parameters/out-params
    // rather than new members, keeping state ownership where it already was.
    // See each
    // definition for the stage's proof comments (moved with the stage) and
    // process_thread_func()'s own comment for the call-order map.
    //
    // Runs unconditionally at the very top of each loop iteration (including
    // idle iterations), closing any VU bins whose window has elapsed. Kept
    // separate from update_metering() because it must run BEFORE the
    // ring-drain wait/continue below, whereas update_metering()'s peak
    // computation can only run AFTER data has been read -- folding both into
    // one call would either skip VU-bin closing on idle iterations or require
    // computing a peak over data that doesn't exist yet. See definition.
    void close_elapsed_vu_bins();

    // Waits (bounded, 5 ms) for at least MIN_SAMPLES to be available and, once
    // available, reads one block from _ring_buf into _pcm_in. Returns false
    // (having already performed the wait) when the caller should `continue`
    // the loop without processing a block; true with frames_in set otherwise.
    bool drain_capture_ring(int& frames_in);

    // Peak-level metering for the block just read by drain_capture_ring():
    // compute_peak_sample(), _current_peak_sample, the _poll_peak_sample CAS
    // loop, and _session_raw_peak_sample. Returns the raw peak sample as a
    // linear amplitude in [0.0, 1.0] -- see compute_peak_sample()'s comment
    // (the float domain).
    float update_metering(int frames_in);

    // Silence/activity state machine: updates _last_above_threshold_time and
    // derives is_above_threshold / should_capture (activity threshold x
    // _allow_capture gate, unchanged). Also returns the config snapshot
    // (silence_threshold_sample, track_change_silence_seconds) the caller and
    // handle_session_edges() need, read exactly once per iteration as today.
    // peak_sample/silence_threshold_sample are linear amplitudes in
    // [0.0, 1.0], not int16-scale sample counts -- see compute_peak_sample().
    bool update_silence_state(float   peak_sample,
                               double  now,
                               float&  silence_threshold_sample,
                               bool&   is_above_threshold,
                               float&  track_change_silence_seconds);

    // Capture session start/stop transitions (SRC resets incl. the ID-tap
    // reset, RepeatController notifications, ramp/pre-fill arming) and
    // track-gap detection. TrackGapDetector::update() is folded in here
    // (rather than into tap_for_id_and_repeat()) because it runs once per
    // OUTER loop iteration, before the SRC loop -- not once per SRC output
    // chunk like the ID/repeat taps; moving it into the per-chunk stage would
    // change how often it fires whenever a block spans more than one
    // src_process() call.
    void handle_session_edges(bool   should_capture,
                               float  peak_sample,
                               float  silence_threshold_sample,
                               double now,
                               float  track_change_silence_seconds);

    // Owns the main SRC loop (`while (frames_left > 0)`) and the periodic
    // drift-diagnostics accumulation (_stats_in_frames/_stats_out_frames).
    // For each produced output chunk, calls tap_for_id_and_repeat(),
    // apply_output_chain(), and deliver_output() in that order -- identical
    // to today's single nested block. Only called when _capturing and
    // _src_state are both set, exactly as today.
    void resample_block(int frames_in, float peak_sample, float silence_threshold_sample);

    // Post-SRC, pre-gain, pre-EQ taps for one produced chunk: the shared
    // IdTapResampler snapshot ring and the RepeatController recorder tap.
    void tap_for_id_and_repeat(int out_frames, float peak_sample, float silence_threshold_sample);

    // Per-input gain/fade-in ramp and EQ for one produced chunk (lock-free;
    // runs before the _fifo_mutex section in deliver_output()).
    void apply_output_chain(int out_frames);

    // The _fifo_mutex critical section for one produced chunk: OutputProcessor
    // apply() (output EQ/gain/auto-trim) gated by live_write_active, the
    // capturing_live-gated VU-bin peak accumulation, the int16 cast, the
    // engineering dump tap, and pre-fill buffering / FIFO write. This is ONE
    // contiguous lock_guard<std::mutex> scope, unchanged from today -- see
    // the ownership-flip visibility proof at this method's definition.
    void deliver_output(int out_frames);

    // ── Helpers ──────────────────────────────────────────────────────────────

    // Returns the peak absolute sample value across all channels as a linear
    // amplitude in [0.0, 1.0].
    // The float domain: rather than re-parameterising the old int16-scale
    // peak (0..32768) for a bit depth
    // that can now be 16 or 32 depending on what AlsaCapture negotiated, this
    // normalises against the full 32-bit container scale unconditionally --
    // eliminating the 32767/32768 constants entirely instead of replacing
    // them with a second bit-depth-dependent constant. samples must already
    // be in the monitor's common 32-bit internal representation (the same
    // scale AlsaCapture::read() widens 16-bit captures to), so this is
    // correct regardless of which format the hardware actually negotiated.
    // Integer accumulation (int64_t, to avoid INT32_MIN overflow on abs()),
    // one float divide at the end -- the dBFS conversion itself is still
    // deferred to get_status() so log10 stays off the hot path.
    float compute_peak_sample(const int32_t* samples,
                               int            n_frames,
                               int            n_channels) const;

    // ── Identity ─────────────────────────────────────────────────────────────
    int         _index;

    // ── Shared resources (owned by AudioMonitor) ─────────────────────────────
    FifoWriter&       _shared_fifo;
    std::mutex&       _fifo_mutex;
    OutputProcessor&  _output_processor;
    OutputDumpWriter& _dump_writer;
    RepeatController& _repeat_controller;

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
    // Float domain: linear amplitude threshold in [0.0, 1.0],
    // pre-computed from config.silence_threshold_dbfs. See
    // compute_peak_sample()'s comment and the silence_threshold_sample()
    // accessor above for the deliberate boundary conversion back to the
    // legacy int16 scale for replay's own domain.
    std::atomic<float> _silence_threshold_sample{0.0f};

    // ── ALSA capture ─────────────────────────────────────────────────────────
    AlsaCapture _alsa;

    // ── libsamplerate state (created in start(), freed in stop()) ────────────
    SRC_STATE*    _src_state    = nullptr;  // main stereo SRC (ALSA rate → 48000 Hz)

    // ID-tap resampler (48000 Hz mono → 16000 Hz, SRC_SINC_FASTEST).
    // Constructed in start(), destroyed (reset to nullptr) in stop(),
    // exactly the same lifetime _id_src_state had.
    std::unique_ptr<IdTapResampler> _id_tap;

    // ── Sample rate estimation ────────────────────────────────────────────────
    RateEstimator _rate_estimator;

    // ── SPSC ring buffer between capture thread and process thread ────────────
    // Stores interleaved stereo samples in the monitor's common 32-bit
    // internal representation (widened from int16_t -- element COUNT is
    // unchanged, so this ring holds 1 MiB instead of 512 KiB). At 48000 Hz
    // stereo, this holds approximately 2.7 seconds of audio. See
    // autostream_spsc_ring.h for the SPSC proof this relies on.
    static constexpr size_t RING_BUF_SAMPLES = 1u << 18;  // 262144

    SpscRing<int32_t> _ring_buf{RING_BUF_SAMPLES};

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

    // Minimum playback hold (session-end suppression): monotonic
    // timestamp the current capture session started, 0.0 when not capturing.
    // Set by handle_session_edges() on the should-capture false->true edge;
    // read by update_silence_state() via compute_should_capture_with_hold()
    // (autostream_monitor_utils.h) to decide whether an elapsed-silence
    // session-end should be suppressed. Does not affect is_above_threshold,
    // is_silent status, or track-change gap detection -- all three keep
    // using the raw debounced/per-block values, unaffected by the hold.
    double _capture_start_time     = 0.0;

    // Minimum playback hold (replay-takeover re-notify delivery):
    // monotonic timestamp of the most recent notify_capture_started() call
    // for the current capture session (the original start-edge call, or a
    // bounded re-notify -- see compute_should_renotify_capture_started(),
    // autostream_monitor_utils.h). 0.0 when not capturing. Re-notifying
    // recovers a session the repeat controller Ignored while a replay hold
    // was active (or otherwise dropped): once the controller is no longer
    // ignoring it, the very next re-notify is what actually starts it.
    double _last_notify_capture_started_time = 0.0;

    // Minimum spacing between minimum-playback-hold re-notify attempts
    // while a capture session persists unrecorded. 1 s is frequent enough
    // that the worst-case delay after a hold expires or a replay ends by
    // another route is one interval, and infrequent enough to be pure
    // noise against a ~30 s hold.
    static constexpr double MINIMUM_PLAYBACK_RENOTIFY_INTERVAL_SECONDS = 1.0;

    // ── Track-gap detection (process thread only) ─────────────────────────────
    TrackGapDetector       _track_gap_detector;
    std::atomic<uint32_t>  _track_change_seq{0};
    float                  _prev_track_change_silence_seconds{-1.0f};

    // ── Fade-in ramp (process thread only) ───────────────────────────────────
    // When a capture session starts, _ramp_frames_remaining is set to
    // RAMP_DURATION_FRAMES (one second of output frames).  Each processed block
    // decrements the counter until it reaches zero, at which point the ramp is
    // complete and full gain is applied.  The ramp is combined with _gain_linear
    // in a single per-frame multiply so no extra pass over the buffer is needed.
    int _ramp_frames_remaining{0};

    // ── FIFO pre-fill buffer (process thread only) ────────────────────────────
    // At the start of each capture session, PREFILL_DURATION_FRAMES of
    // post-gain/EQ/ramp samples (in the monitor's output container width --
    // int32_t) are accumulated here before any data is
    // written to the FIFO.  Once the threshold is reached the buffer is flushed
    // in a single write (giving OwnTone a full pipe buffer to start from) and
    // subsequent blocks are written directly.
    // _prefill_frames_remaining counts down from PREFILL_DURATION_FRAMES to 0;
    // while it is > 0 we are in the accumulation phase.
    //
    // This buffer STAYS int32_t in BOTH output modes -- it is filled straight from
    // _pcm_out (deliver_output() always produces that conversion, needed for
    // the dump tap regardless of wire mode; see that method's dataflow
    // note), so accumulation itself needs no per-mode branch at all. Only
    // the FLUSH write is mode-conditional: native writes the accumulated
    // int32 bytes as-is; compatible narrows them to int16 first (a plain
    // >>16, the exact inverse of widen_s16_to_s32()) into a small on-stack
    // scratch at the flush call site. This was chosen over the alternative
    // of accumulating wire-format bytes directly because the per-sample
    // float source for each already-buffered block is gone by the time a
    // later block triggers the flush -- narrowing the retained int32 values
    // is the only option there, and reusing that same narrowing for the
    // whole flushed buffer (rather than also branching the accumulation
    // step) is the smaller, safer diff that leaves this member's type and
    // the insert() call in deliver_output() completely untouched.
    int                  _prefill_frames_remaining{0};
    std::vector<int32_t> _prefill_buf;

    // ── process_thread_func() constants and scratch buffers ──────────────────
    // Formerly local to process_thread_func(): a std::vector(size) local is
    // constructed exactly once per thread lifetime (thread start, not per
    // iteration), so promoting these to members sized once at the same point
    // (top of process_thread_func(), before the loop) introduces no new
    // allocation of any kind -- it only lets the stage methods above share
    // them without passing four buffers around as parameters.
    static constexpr int      MAX_FRAMES     = 2048;  // maximum input frames per loop iteration
    static constexpr int      MAX_SRC_OUTPUT = 4096;   // maximum output frames from libsamplerate
    static constexpr unsigned MIN_SAMPLES    = 512;    // minimum samples to accumulate before processing

    // _pcm_in/_pcm_out are int32_t (the monitor's common 32-bit internal
    // representation / OUTPUT_BITS container).
    std::vector<int32_t> _pcm_in;    // interleaved int32, sized MAX_FRAMES*2
    std::vector<float>   _float_in;  // interleaved float, sized MAX_FRAMES*2
    std::vector<float>   _float_out; // post-SRC float, sized MAX_SRC_OUTPUT*2
    std::vector<int32_t> _pcm_out;   // final int32, sized MAX_SRC_OUTPUT*2

    // Compatible-mode wire scratch.
    // _pcm_out (above) is ALWAYS produced every block regardless of output
    // mode -- it feeds the dump tap (OutputDumpWriter::submit_block(), which
    // documents the internal 32-bit representation in both modes, see the
    // dump-tap dataflow note at deliver_output()'s definition) and, in
    // native mode, the wire itself. _pcm_out16 is the ADDITIONAL conversion
    // deliver_output() only performs when g_output_format.mode ==
    // OutputFormatMode::Compatible: float -> int16 via
    // src_float_to_short_array (the pre-48k-migration path resurrected),
    // written to the FIFO instead of _pcm_out in that mode. Sized once at
    // process_thread_func() entry alongside _pcm_out, same MAX_SRC_OUTPUT*2
    // bound, so this introduces no new allocation on the hot path.
    std::vector<int16_t> _pcm_out16; // compatible-mode final int16, sized MAX_SRC_OUTPUT*2

    // Ramp/pre-fill DURATIONS (as opposed to _ramp_frames_remaining /
    // _prefill_frames_remaining above, which count down within a session).
    // Computed once at process_thread_func() entry (same point as today's
    // local RAMP_DURATION_FRAMES / PREFILL_DURATION_FRAMES) because
    // handle_session_edges() (arming) and apply_output_chain() (ramp math)
    // are now separate methods and both need the same value.
    int _ramp_duration_frames    = 0;
    int _prefill_duration_frames = 0;

    // Periodic (30 s) buffer/drift diagnostics accumulators. Formerly locals
    // declared just above the while loop in process_thread_func(); now
    // members because resample_block() (which accumulates into
    // _stats_in_frames/_stats_out_frames on every src_process() call) and the
    // periodic log-and-reset block (still inline at the top of
    // process_thread_func(), see its definition) both need to observe and
    // reset the same running totals across loop iterations.
    double   _stats_last_log_time = 0.0;
    uint64_t _stats_in_frames     = 0;
    uint64_t _stats_out_frames    = 0;

    // ── Level metering ────────────────────────────────────────────────────────
    // Written by the process thread every block; read by get_status().
    // The float domain (linear amplitude, 0.0..1.0) rather than
    // re-parameterising the old int16-scale (0..32768) peak for 32-bit
    // samples -- see compute_peak_sample()'s comment for the full trace of
    // why this is the eliminate-the-32767-constant option rather than a
    // bit-depth-aware rescale. Stored as linear float so the process thread
    // never calls log10 -- that conversion still happens only in get_status().
    std::atomic<float> _current_peak_sample{0.0f};        // current-block raw peak, linear (0..1)
    mutable std::atomic<float> _poll_peak_sample{0.0f};    // max raw peak since last get_status() call, linear (0..1); mutable so exchange(0) is callable from const get_status()
    std::atomic<float> _session_raw_peak_sample{0.0f};     // session max raw peak, linear (0..1)
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

    // Test-only (--test-hooks): set by debug_inject_capture_failure(),
    // consumed (checked-and-cleared) once per capture_thread_func() loop
    // iteration. See that method's comment for the exact semantics.
    std::atomic<bool> _debug_fail_injected{false};

    // ── Status snapshot (mutex-protected fields) ─────────────────────────────
    mutable std::mutex _status_mutex;
    InputChannelStatus _status;

    // ── Identification snapshot buffer ────────────────────────────────────────
    //
    // A separate rolling buffer that accumulates mono s16le audio at 16000 Hz
    // for Shazam-based track identification via the Vibra daemon.
    //
    // Tap point: post-main-SRC (48000 Hz stereo float), pre-gain/pre-EQ.
    //   - Post-SRC: uses a stable, device-independent rate.
    //   - Pre-gain/pre-EQ: captures uncolored audio; user gain and EQ reflect
    //     personal preference and would skew frequency-domain fingerprints.
    //   - Gated by _capturing: fills only during active audio sessions.
    //
    // Downsampling: _id_tap (IdTapResampler, autostream_id_tap.h) downmixes
    // and converts the 48000 Hz stereo float signal to 16000 Hz mono using
    // SRC_SINC_FASTEST, giving the tap an anti-aliasing filter (the prior
    // SRC_LINEAR converter had none, so content above 8 kHz folded back into
    // the fingerprint signal).
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

    // One entry per accepted connection whose worker thread has not yet been
    // joined. `done` is set as the last action of the worker lambda (after
    // handle_client() returns and the fd bookkeeping is done), so accept_loop()
    // can tell which entries have finished and reap them -- see the sweep in
    // accept_loop() and the comment there for why no mutex is needed. The flag
    // is a shared_ptr (rather than a plain atomic<bool> member) so it safely
    // outlives the ClientThread entry if it is ever erased while the lambda
    // still holds a copy of the pointer.
    struct ClientThread
    {
        std::thread                     thread;
        std::shared_ptr<std::atomic<bool>> done;
    };
    std::vector<ClientThread> _client_threads;
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
    // test_hooks_enabled: gates the debug_fail_input socket command (set via
    // the --test-hooks command-line flag; see main()). Defaults to false so
    // every other construction site (there is currently only the production
    // one in main()) keeps today's behaviour without having to name it.
    explicit AudioMonitor(const std::string& socket_path, bool test_hooks_enabled = false);
    ~AudioMonitor();

    // These read the process-wide g_output_format descriptor
    // (autostream_monitor_utils.h), so they cannot be constexpr (the
    // descriptor is a runtime value, set once in main() -- see
    // g_output_format's doc comment for the publication argument). The
    // names and call sites are unchanged: every existing
    // AudioMonitor::output_rate_hz()-style call across the codebase keeps
    // compiling and behaving identically under the default (native) mode.
    static int output_rate_hz() { return g_output_format.rate; }

    // Bits per sample / channel count for the output pipe wire format.
    // Public for the same reason as output_rate_hz()/output_bytes_per_frame()
    // above: OutputDumpWriter's WAV header builder and both FIFO
    // writers need these without becoming AudioMonitor members.
    static int output_bits_per_sample() { return g_output_format.bits; }
    static int output_channels() { return g_output_format.channels; }

    // Bytes per interleaved output frame (all channels), derived from the
    // g_output_format descriptor. Public so both FIFO writers -- the live
    // path's FifoWriter (InputChannel, this file) and the replay path's
    // ReplayEngine (autostream_repeat.cpp), neither of which is a member of
    // AudioMonitor -- share this single source of truth for the wire
    // format's byte width, instead of hand-rolling
    // "* 2 * sizeof(int16_t)"-style literals that silently go stale if the
    // format changes.
    static int output_bytes_per_frame()
    {
        return g_output_format.bytes_per_frame();
    }

    // The active output format's mode tag ("native"/"compatible" via
    // output_format_mode_name()), for status JSON's "output_format" field.
    static OutputFormatMode output_format_mode() { return g_output_format.mode; }

    // Test-only: true when the daemon was launched with --test-hooks.
    bool test_hooks_enabled() const { return _test_hooks_enabled; }

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

    // Copy up to max_seconds (1..32, clamped to [1,32]) of recent mono 16000 Hz
    // audio for the given input into binary_out (s16le, no header), returning a
    // JSON ack.  binary_out is populated only when "ok":true; the caller sends
    // the bytes as a raw binary payload immediately after the JSON response line.
    std::string api_get_id_snapshot(int input_index, int max_seconds,
                                     std::vector<int16_t>* binary_out);

    // Engineering output dump: record the final processed stream to a WAV file.
    // start: opens path and begins recording; rejects if already active.
    // stop:  flushes, patches WAV header, closes; no-op if not active.
    std::string api_start_output_dump(const std::string& path, bool overwrite);
    std::string api_stop_output_dump();

    // Repeat feature: enabled/codec/target_minutes setting; codec
    // must be auto|mp2_160|mp2_192|mp2_224|mp2_256|mp2_320|mp2_384|pcm.
    std::string api_set_repeat_enabled(bool enabled, const std::string& codec, int target_minutes = -1);

    // Repeat feature: session arm/disarm.
    std::string api_set_repeat_armed(bool armed);

    // Test-only socket command ({"type":"debug_fail_input","input":N}),
    // gated at runtime by test_hooks_enabled() (--test-hooks), unlike the
    // AUTOSTREAM_REPEAT_TEST_HOOKS block below which is a compile-time gate.
    // Makes input N's capture thread take the same exit path as a genuine
    // unrecoverable ALSA read error on its next loop iteration, so the
    // watchdog auto-restart loop in run() can be exercised against a
    // real self-stopped capture thread without kernel-level fault injection.
    // Returns an error ack if test hooks are not enabled or input is invalid.
    std::string api_debug_fail_input(int input_index);

#ifdef AUTOSTREAM_REPEAT_TEST_HOOKS
    // Test-only socket command ({"type":"debug_dump_repeat_buffer","path":...});
    // see RepeatController::debug_dump_buffer(). Never compiled into the
    // production build.
    std::string api_debug_dump_repeat_buffer(const std::string& path);
#endif

private:
    // Returns a pointer to the InputChannel for the given 1-based index,
    // or nullptr if the index is out of range.
    InputChannel* get_input(int input_index);

    // Shared teardown sequence for stopping an input, used by both
    // api_stop_input() (control-server thread) and the watchdog auto-restart
    // loop in run() (main thread). `i` is the 0-based _inputs[] index.
    // Caller must have already verified _inputs[i] is non-null. Returns
    // was_active (whether this input was the active FIFO writer before
    // stop()), so callers that need it for logging don't have to re-read it.
    bool stop_input_with_teardown(int i);

    static constexpr int NUM_INPUTS  = 2;

    // Output pipe format descriptor. The process-wide g_output_format
    // runtime descriptor (autostream_monitor_utils.h) is set once in
    // main() before any thread starts, so the same binary can run in either
    // native (default, 48000/32/2) or compatible (--compatible, 44100/16/2)
    // mode. This class no longer holds its own copy of the format --
    // output_rate_hz() and friends above simply read g_output_format
    // directly. It is the FIFO wire format written by both FifoWriter (live
    // path) and ReplayEngine (replay path, see autostream_repeat.cpp);
    // reported at runtime via api_get_status() so the Python layer reads it
    // instead of assuming it -- including "output_format" so the mode
    // itself, not just the numbers, is legible.

    // Back-off interval (seconds) before retrying a failed auto-restart.
    static constexpr double RESTART_BACKOFF_SECONDS = 5.0;

    std::string _socket_path;

    // Test-only: set once at construction from the --test-hooks command-line
    // flag; gates api_debug_fail_input(). Never mutated after construction,
    // so no synchronisation is needed to read it from the control thread.
    bool _test_hooks_enabled = false;

    FifoWriter       _fifo_writer;
    OutputDumpWriter _dump_writer;
    std::mutex       _fifo_mutex;
    OutputProcessor  _output_processor;

    // Repeat feature controller. Declared before _inputs
    // so it is fully constructed before the InputChannels that hold a
    // reference to it (member init order follows declaration order).
    RepeatController _repeat_controller;

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
