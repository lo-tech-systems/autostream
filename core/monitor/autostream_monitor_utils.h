// =============================================================================
// autostream_monitor_utils.h
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Shared timing, logging, and string utilities used by all
// autostream_monitor translation units.
// =============================================================================

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>


// =============================================================================
// Audio format math
//
// Pure, header/format-agnostic helpers extracted so they can be exercised by
// tests that link only autostream_monitor_utils.cpp (no ALSA/libsamplerate,
// no AudioMonitor instance). Kept behaviourally identical to the code they
// were extracted from -- see the .cpp for provenance notes.
// =============================================================================

// Convert a dBFS threshold to the equivalent linear amplitude threshold, in
// [0.0, 1.0]. 0 dBFS and above clamp to 1.0; the result is floored at
// 1/32768 (the smallest representable step for a 16-bit source) so a very
// negative dBFS threshold never collapses to a threshold of exactly 0.0.
float dbfs_to_linear_threshold(float dbfs);

// Convert a linear float peak amplitude (expected range [0.0, 1.0], but not
// clamped on input) to dBFS. Silence (<= 0.0) maps to -90.0 dBFS, which is
// also the floor applied to any quieter-than-that positive result.
float linear_to_dbfs(float peak_linear);

// Build a standard 44-byte canonical PCM WAV header (RIFF/WAVE, one "fmt "
// sub-chunk of 16 bytes, audio_format = 1 i.e. WAVE_FORMAT_PCM) for the
// given format. data_bytes is the size of the eventual "data" sub-chunk;
// pass 0 for a placeholder header whose size fields get patched later (the
// RIFF and data chunk-size fields are the only ones that depend on
// data_bytes -- every other field is a pure function of rate/bits/channels).
//
// byte_rate and block_align are derived from bits/channels, never hardcoded,
// so the header can never drift from the actual wire format it describes.
std::array<std::uint8_t, 44> build_wav_header(int rate,
                                               int bits,
                                               int channels,
                                               std::uint32_t data_bytes = 0);

// The monitor's S16 -> S32 widening convention: left-justify the 16-bit
// sample into the top of a 32-bit word by shifting
// left 16 bits. This places an S16_LE fallback capture's samples at the
// same full-scale dynamic range a native S32_LE capture already occupies,
// so downstream DSP (which only ever sees the widened int32 stream) cannot
// tell the two capture paths apart. Used by AlsaCapture::read()'s S16
// fallback loop (autostream_monitor_io.cpp); extracted here as a pure,
// header-inline function purely so the convention itself is unit-testable
// without an ALSA device.
inline constexpr std::int32_t widen_s16_to_s32(std::int16_t sample)
{
    return static_cast<std::int32_t>(sample) << 16;
}


// =============================================================================
// Output format descriptor
//
// Replaces the compile-time AudioMonitor::OUTPUT_RATE/OUTPUT_BITS/
// OUTPUT_CHANNELS constexprs with a process-wide runtime descriptor, so a
// single binary can serve either wire format:
//
//   - "native"     48000 Hz / 32-bit / 2ch -- the default.
//   - "compatible" 44100 Hz / 16-bit / 2ch -- for stock (upstream) OwnTone and
//                  pre-48k owntone-mini builds, whose named-pipe input is
//                  fixed at 44.1k/16 and cannot be reconfigured.
//
// The wire-edge narrowing happens at both producer edges: deliver_output()
// (autostream_monitor_io.cpp) branches once per block between float -> int32
// (native) and float -> int16 (compatible, src_float_to_short_array), and
// ReplayEngine's convert_to_pipe_format() (autostream_repeat.cpp) branches
// the same way between <<16 widening (native) and s16 passthrough
// (compatible). Both modes are fully functional -- --compatible starts and
// produces a byte-correct 44.1kHz/16-bit wire.
// =============================================================================

enum class OutputFormatMode
{
    Native,      // 48000 Hz / 32-bit / 2ch (default)
    Compatible,  // 44100 Hz / 16-bit / 2ch (--compatible)
};

// Human-readable mode name used both in the "output_format" status JSON
// field and in log lines ("native" / "compatible").
const char* output_format_mode_name(OutputFormatMode mode);

struct OutputFormatDescriptor
{
    int rate     = 48000;
    int bits     = 32;
    int channels = 2;
    OutputFormatMode mode = OutputFormatMode::Native;

    // Bytes per interleaved output frame (all channels). Derived, never
    // hand-rolled, so a future format never drifts from this single source
    // of truth (mirrors the historical AudioMonitor::output_bytes_per_frame()
    // rationale).
    int bytes_per_frame() const { return channels * (bits / 8); }
};

// Process-wide output format descriptor. Default-constructed to native
// (48000/32/2), matching the native compile-time constants exactly so every
// consumer that never calls main() (i.e. every test binary) sees the
// defaults unchanged.
//
// Publication argument (same as g_test_pin_src_ratio in
// autostream_monitor_dsp.cpp): main() writes this exactly once, from
// command-line parsing, strictly before AudioMonitor is constructed and
// therefore strictly before any capture/process/control/repeat thread is
// started. From that point on it is read-only for the remainder of the
// process. A plain global with no atomics/locking is therefore sufficient --
// there is no concurrent writer, and every reader thread's first read
// happens-after main()'s write via the thread-creation calls that precede it
// (the same happens-before argument the C++ standard gives std::thread
// construction). Defined in autostream_monitor_utils.cpp.
extern OutputFormatDescriptor g_output_format;


// =============================================================================
// Timing
// =============================================================================

// Returns the current monotonic clock time in seconds.
// Monotonic time is used throughout so that NTP adjustments or system clock
// changes do not affect silence detection timing.
double get_monotonic_time();

// Minimum playback hold: live-input session-end suppression
// (suppression point (a)). Pure decision function factored out of
// InputChannel::update_silence_state() so it is unit-testable without a
// running capture channel.
//
// Once a source starts playback it owns playback for minimum_playback_seconds;
// during that window an elapsed-silence session-end is suppressed even
// though is_above_threshold has already gone false. This affects ONLY the
// should_capture value used for the session start/stop decision -- callers
// must keep reporting the raw is_above_threshold (unaffected) for is_silent
// status/VU purposes, and must keep feeding TrackGapDetector the raw
// per-block peak independently of this function's result, so the hold never
// touches track-change detection.
//
// is_above_threshold: raw debounced "signal present" state, already
//   accounting for silence_seconds (see update_silence_state()).
// allow_capture: explicit capture gate (set_allow_capture()); the hold never
//   overrides an explicit stop -- if this is false the result is always false.
// capturing: whether a capture session is currently active (pre-edge state).
// capture_start_time: monotonic timestamp the current session started, or
//   0.0 if there is no active session.
// now: current monotonic time.
// minimum_playback_seconds: configured hold duration; 0 disables the hold
//   entirely, in which case this function returns exactly
//   (is_above_threshold && allow_capture), matching pre-hold behaviour.
inline bool compute_should_capture_with_hold(bool is_above_threshold,
                                              bool allow_capture,
                                              bool capturing,
                                              double capture_start_time,
                                              double now,
                                              int minimum_playback_seconds)
{
    bool hold_active = capturing
                     && minimum_playback_seconds > 0
                     && capture_start_time > 0.0
                     && (now - capture_start_time) < static_cast<double>(minimum_playback_seconds);
    return (is_above_threshold || hold_active) && allow_capture;
}

// Minimum playback hold: replay-takeover re-notify (the delivery side of
// suppression point (b)). RepeatController::notify_capture_started()
// is an EDGE notification -- InputChannel calls it exactly once, on the
// should_capture false->true transition. If that single call lands while an
// active replay's minimum-playback hold is still in effect, decide_repeat_
// transition() Ignores it (see RepeatEventCtx::replay_hold_active) with no
// pending state latched, by design -- but that means nothing re-raises
// CaptureStarted once the hold expires, or if the replay ends by some other
// route (disable/re-enable, discard) while this input is still capturing:
// the swallowed session would otherwise never start.
//
// This pure function decides whether InputChannel's capture loop -- the
// same thread that already calls handle_session_edges() once per processed
// audio block -- should call notify_capture_started() AGAIN this iteration,
// while capturing continues, at a bounded cadence, so the controller keeps
// getting a chance to admit the session as soon as it is able to.
//
// capturing: this input's current _capturing state.
// repeat_enabled: RepeatController::enabled() fast mirror. Checked
//   separately from recording_wanted (which folds "disabled" into its own
//   false) so a disabled controller never re-notifies.
// recording_wanted: RepeatController::recording_wanted(this input) fast
//   mirror -- true once the controller is actually Recording/Pending for
//   this input, at which point re-notifying would be pure overhead (every
//   matrix cell it could hit is a defensive/idempotent NoOp -- see the
//   CaptureStarted state x event table comment above decide_repeat_
//   transition() in autostream_monitor.h).
// now: current monotonic time.
// last_notify_time: monotonic timestamp of the most recent
//   notify_capture_started() call for this input's current session (the
//   original edge call, or a previous re-notify), 0.0 if none this session.
// interval_seconds: minimum spacing between re-notify attempts.
//
// Returns true when a re-notify should fire now.
inline bool compute_should_renotify_capture_started(bool capturing,
                                                      bool repeat_enabled,
                                                      bool recording_wanted,
                                                      double now,
                                                      double last_notify_time,
                                                      double interval_seconds)
{
    if (!capturing || !repeat_enabled || recording_wanted)
        return false;
    return (last_notify_time <= 0.0) || ((now - last_notify_time) >= interval_seconds);
}


// =============================================================================
// Logging
// =============================================================================

enum class MonitorLogLevel
{
    Warn = 0,
    Info = 1,
    Debug = 2,
    Spam = 3,
};

// Parse a case-insensitive log level string into the enum.  The platform
// aliases "fatal", "log", "warning", and "warn" all map to MonitorLogLevel::Warn.
// Returns true on success; false if the text is unrecognised.
bool parse_monitor_log_level(const std::string& text, MonitorLogLevel* out_level);

// Initialise the logger to the given level and (idempotently) start the
// dedicated logging thread if it is not already running.  Called once from
// main(), but safe to call again (e.g. from tests) -- it only resets the
// duplicate-suppression bookkeeping and leaves an already-running logging
// thread in place.
void logger_init(MonitorLogLevel level);

// Read the current log level (atomic; no lock taken).
MonitorLogLevel logger_get_level();

// Set the current log level, flushing any pending repeat summary first.
void logger_set_level(MonitorLogLevel level);

// Flush any pending "suppressed N duplicates" summary into the logging
// queue.  This only enqueues the summary line -- it does not itself wait
// for the message to reach the sink.  Called internally by logger_shutdown()
// and logger_set_level(); exposed for tests that want to force the summary
// to be queued without stopping the logging thread.
void logger_flush_repeats();

// Emit one log message at the given level.  Implements duplicate suppression
// and log-level filtering.  Formats the message and hands it to a bounded
// queue (LOGGER_QUEUE_CAPACITY entries) drained by a dedicated logging
// thread; never blocks on file I/O itself.  If the queue is full the message
// is dropped and counted (see logger_test_dropped_count()) rather than
// applying backpressure to the caller.  Safe to call from any thread
// concurrently, including while holding an unrelated lock (e.g.
// RepeatController's _repeat_mutex) -- that was the point of this design:
// no caller-held mutex is ever held across the actual fwrite()/fflush().
void logger_log(MonitorLogLevel level, const char* fmt, ...);

// Convert a MonitorLogLevel to the name used in JSON protocol responses.
const char* protocol_log_level_name(MonitorLogLevel level);

// Number of pending formatted log lines the bounded queue holds before
// logger_log() starts dropping (and counting) messages instead of blocking
// the caller.  Sized to absorb a multi-second sink stall at normal logging
// rates without unbounded memory growth.
inline constexpr std::size_t LOGGER_QUEUE_CAPACITY = 256;

// Stop the dedicated logging thread, flushing the queue (including any
// pending duplicate-suppression summary, via an internal logger_flush_repeats()
// call) within a bounded wait (~1s).  Call once from main() during teardown,
// after the daemon's last logger_log() call.  If the sink is still stalled
// when the wait expires, the logging thread is detached rather than joined
// -- any not-yet-written queued lines are lost and the thread is leaked for
// the remainder of process exit.  That is an accepted best-effort outcome
// for a crash/teardown path; it is not expected in steady-state operation,
// where the thread drains promptly.  Safe to call even if logger_init() was
// never called (the thread is simply not running).  logger_init() can be
// called again afterwards to restart logging (used by tests).
void logger_shutdown();

// ---------------------------------------------------------------------------
// Test-only introspection.
//
// These exist so the logging thread's queueing/dropping/draining behaviour
// can be exercised deterministically in unit tests, without a running
// daemon and without scraping stderr for side effects.
// ---------------------------------------------------------------------------

// Number of messages dropped because the queue was full, since the last
// time the "[logger] dropped N messages" summary was emitted (that summary
// resets the count to 0 as it is written).
std::uint64_t logger_test_dropped_count();

// Number of messages currently queued and not yet handed to the sink.
std::size_t logger_test_queue_depth();

// Block until the queue has fully drained (all queued lines handed to the
// sink) or timeout_ms elapses.  Returns true if the queue drained before the
// timeout.  Note: "handed to the sink" means fwrite() was called; if the
// sink itself is stalled, the drain can still be mid-flight on the one
// in-flight line when this returns false.
bool logger_test_wait_drained(int timeout_ms = 1000);

#define LOG_WARN(...)  logger_log(MonitorLogLevel::Warn,  __VA_ARGS__)
#define LOG_INFO(...)  logger_log(MonitorLogLevel::Info,  __VA_ARGS__)
#define LOG_DEBUG(...) logger_log(MonitorLogLevel::Debug, __VA_ARGS__)
#define LOG_SPAM(...)  logger_log(MonitorLogLevel::Spam,  __VA_ARGS__)
