// =============================================================================
// autostream_monitor_utils.h
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Shared timing, logging, and string utilities used by all
// autostream_monitor translation units.
// =============================================================================

#pragma once

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

// Initialise the logger to the given level.  Called once from main().
void logger_init(MonitorLogLevel level);

// Read the current log level (atomic; no lock taken).
MonitorLogLevel logger_get_level();

// Set the current log level, flushing any pending repeat summary first.
void logger_set_level(MonitorLogLevel level);

// Flush any pending "suppressed N duplicates" summary to stderr.
// Call from main() just before exit.
void logger_flush_repeats();

// Emit one log message at the given level.  Implements duplicate suppression.
// Safe to call from any thread concurrently.
void logger_log(MonitorLogLevel level, const char* fmt, ...);

// Convert a MonitorLogLevel to the name used in JSON protocol responses.
const char* protocol_log_level_name(MonitorLogLevel level);

#define LOG_WARN(...)  logger_log(MonitorLogLevel::Warn,  __VA_ARGS__)
#define LOG_INFO(...)  logger_log(MonitorLogLevel::Info,  __VA_ARGS__)
#define LOG_DEBUG(...) logger_log(MonitorLogLevel::Debug, __VA_ARGS__)
#define LOG_SPAM(...)  logger_log(MonitorLogLevel::Spam,  __VA_ARGS__)
