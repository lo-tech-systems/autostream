// =============================================================================
// autostream_monitor_utils.cpp
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Implementation of timing, logging, and string utilities shared by all
// autostream_monitor translation units.
// =============================================================================

#include "autostream_monitor_utils.h"

#include <atomic>
#include <cctype>
#include <cstdarg>
#include <cstdio>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>
#include <time.h>


// =============================================================================
// Timing
// =============================================================================

double get_monotonic_time()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<double>(ts.tv_sec) + static_cast<double>(ts.tv_nsec) / 1.0e9;
}


// =============================================================================
// Logging internals
// =============================================================================

struct MonitorLoggerState
{
    std::mutex      mutex;
    std::atomic<MonitorLogLevel> level{MonitorLogLevel::Warn};
    std::string     last_key;
    unsigned int    last_printed = 0;
    unsigned int    suppressed = 0;
};

static MonitorLoggerState g_logger;
static constexpr unsigned int DUPLICATE_LOG_LIMIT = 5;

static const char* log_level_name(MonitorLogLevel level)
{
    switch (level)
    {
    case MonitorLogLevel::Warn:  return "WARN";
    case MonitorLogLevel::Info:  return "INFO";
    case MonitorLogLevel::Debug: return "DEBUG";
    case MonitorLogLevel::Spam:  return "SPAM";
    }
    return "WARN";
}

static bool log_level_enabled(MonitorLogLevel level)
{
    return static_cast<int>(level)
        <= static_cast<int>(g_logger.level.load(std::memory_order_relaxed));
}

static std::string trim_copy(const std::string& text)
{
    size_t start = 0;
    while (start < text.size() && std::isspace(static_cast<unsigned char>(text[start])))
        ++start;

    size_t end = text.size();
    while (end > start && std::isspace(static_cast<unsigned char>(text[end - 1])))
        --end;

    return text.substr(start, end - start);
}

static std::string lowercase_copy(std::string text)
{
    for (char& ch : text)
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    return text;
}

static std::string make_timestamp()
{
    std::time_t now = ::time(nullptr);
    struct tm tm_now;
    localtime_r(&now, &tm_now);

    char buf[32];
    if (::strftime(buf, sizeof(buf), "%d-%b-%y %H:%M:%S", &tm_now) == 0)
        return "00-Jan-00 00:00:00";
    return buf;
}

static void logger_emit_raw_line(const std::string& key)
{
    std::string line = make_timestamp();
    line += ": ";
    line += key;
    line += '\n';
    std::fwrite(line.data(), 1, line.size(), stderr);
    std::fflush(stderr);
}

// Emit a "(suppressed N duplicates)" summary.  Must be called with
// g_logger.mutex held.
static void logger_emit_repeat_summary_locked()
{
    if (g_logger.suppressed == 0 || g_logger.last_key.empty())
        return;

    std::ostringstream oss;
    oss << g_logger.last_key
        << " (suppressed " << g_logger.suppressed << " duplicate entr"
        << (g_logger.suppressed == 1 ? "y" : "ies") << ")";
    logger_emit_raw_line(oss.str());
    g_logger.suppressed = 0;
}

static void logger_vlog(MonitorLogLevel level, const char* fmt, va_list args)
{
    if (!log_level_enabled(level))
        return;

    char stack_buf[1024];
    va_list args_copy;
    va_copy(args_copy, args);
    int needed = std::vsnprintf(stack_buf, sizeof(stack_buf), fmt, args_copy);
    va_end(args_copy);

    if (needed < 0)
        return;

    std::string message;
    if (static_cast<size_t>(needed) < sizeof(stack_buf))
    {
        message.assign(stack_buf, static_cast<size_t>(needed));
    }
    else
    {
        std::vector<char> dynamic_buf(static_cast<size_t>(needed) + 1);
        std::vsnprintf(dynamic_buf.data(), dynamic_buf.size(), fmt, args);
        message.assign(dynamic_buf.data(), static_cast<size_t>(needed));
    }

    std::string key = "[";
    key += log_level_name(level);
    key += "] ";
    key += message;

    std::lock_guard<std::mutex> lock(g_logger.mutex);
    if (key == g_logger.last_key)
    {
        ++g_logger.last_printed;
        if (g_logger.last_printed <= DUPLICATE_LOG_LIMIT)
        {
            logger_emit_raw_line(key);
            return;
        }

        ++g_logger.suppressed;
        if (g_logger.last_printed == DUPLICATE_LOG_LIMIT + 1)
        {
            std::ostringstream oss;
            oss << key
                << " (suppressing further duplicates after "
                << DUPLICATE_LOG_LIMIT << " identical entries)";
            logger_emit_raw_line(oss.str());
        }
        return;
    }

    logger_emit_repeat_summary_locked();
    g_logger.last_key = key;
    g_logger.last_printed = 1;
    logger_emit_raw_line(key);
}


// =============================================================================
// Logging public API
// =============================================================================

bool parse_monitor_log_level(const std::string& text, MonitorLogLevel* out_level)
{
    const std::string value = lowercase_copy(trim_copy(text));
    if (value.empty())
        return false;

    if (value == "fatal" || value == "log" || value == "warning" || value == "warn")
    {
        *out_level = MonitorLogLevel::Warn;
        return true;
    }
    if (value == "info")
    {
        *out_level = MonitorLogLevel::Info;
        return true;
    }
    if (value == "debug")
    {
        *out_level = MonitorLogLevel::Debug;
        return true;
    }
    if (value == "spam")
    {
        *out_level = MonitorLogLevel::Spam;
        return true;
    }
    return false;
}

void logger_init(MonitorLogLevel level)
{
    std::lock_guard<std::mutex> lock(g_logger.mutex);
    g_logger.level.store(level, std::memory_order_relaxed);
    g_logger.last_key.clear();
    g_logger.last_printed = 0;
    g_logger.suppressed   = 0;
}

MonitorLogLevel logger_get_level()
{
    return g_logger.level.load(std::memory_order_relaxed);
}

MonitorLogLevel logger_set_level(MonitorLogLevel level)
{
    std::lock_guard<std::mutex> lock(g_logger.mutex);
    logger_emit_repeat_summary_locked();
    g_logger.last_key.clear();
    g_logger.last_printed = 0;
    g_logger.level.store(level, std::memory_order_relaxed);
    return level;
}

void logger_flush_repeats()
{
    std::lock_guard<std::mutex> lock(g_logger.mutex);
    logger_emit_repeat_summary_locked();
}

void logger_log(MonitorLogLevel level, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    logger_vlog(level, fmt, args);
    va_end(args);
}

const char* protocol_log_level_name(MonitorLogLevel level)
{
    switch (level)
    {
    case MonitorLogLevel::Warn:  return "warning";
    case MonitorLogLevel::Info:  return "info";
    case MonitorLogLevel::Debug: return "debug";
    case MonitorLogLevel::Spam:  return "spam";
    }
    return "warning";
}
