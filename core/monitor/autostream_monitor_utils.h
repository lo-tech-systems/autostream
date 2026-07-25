// =============================================================================
// autostream_monitor_utils.h
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Shared timing, logging, and string utilities used by all
// autostream_monitor translation units.
// =============================================================================

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>


// =============================================================================
// Timing
// =============================================================================

// Returns the current monotonic clock time in seconds.
// Monotonic time is used throughout so that NTP adjustments or system clock
// changes do not affect silence detection timing.
double get_monotonic_time();


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
