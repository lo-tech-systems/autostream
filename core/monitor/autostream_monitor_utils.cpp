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
#include <chrono>
#include <condition_variable>
#include <cstdarg>
#include <cstdio>
#include <deque>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
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
    // Decision-state mutex: guards duplicate-suppression bookkeeping only
    // (last_key / last_printed / suppressed) and the enqueue call that
    // follows the decision.  Never held across file I/O -- a blocking
    // fwrite/fflush under this mutex would stall any caller logging while
    // holding another lock (e.g. RepeatController sites holding
    // _repeat_mutex).
    std::mutex      mutex;
    std::atomic<MonitorLogLevel> level{MonitorLogLevel::Warn};
    std::string     last_key;
    unsigned int    last_printed = 0;
    unsigned int    suppressed = 0;

    // Bounded producer/consumer queue feeding a dedicated logging thread.
    // Mirrors the OutputDumpWriter discipline elsewhere in this module:
    // producers (logger_log() callers) only ever touch queue_mutex for a
    // short, I/O-free critical section; the logging thread is the sole
    // owner of the sink and does all fwrite()/fflush() there.
    std::mutex               queue_mutex;
    std::condition_variable  queue_cv;
    std::deque<std::string>  queue;
    std::atomic<uint64_t>    dropped{0};

    // "Drained" bookkeeping for logger_test_wait_drained().  queue.empty()
    // alone is NOT sufficient: the logging thread swaps the whole queue out
    // (emptying it) before it does the actual fwrite() calls, so there is a
    // window where the queue is empty but a batch is still being written.
    // enqueued is bumped when a line is successfully pushed; written is
    // bumped only after logger_write_to_sink() returns for that line.
    // Drained <=> enqueued == written (release/acquire pair below).
    std::atomic<uint64_t>    enqueued{0};
    std::atomic<uint64_t>    written{0};

    // Thread lifecycle.  Guarded by lifecycle_mutex so logger_init() /
    // logger_shutdown() can be called repeatedly (as tests do) without
    // racing each other.  thread_running is also read (without the lock)
    // by the logging thread itself just before it exits, and polled (also
    // without the lock) by logger_shutdown()'s bounded wait.
    std::mutex        lifecycle_mutex;
    std::thread       thread;
    std::atomic<bool> thread_running{false};
    std::atomic<bool> stop_requested{false};
};

static MonitorLoggerState g_logger;
static constexpr unsigned int DUPLICATE_LOG_LIMIT = 5;
static constexpr int LOGGER_SHUTDOWN_TIMEOUT_MS = 1000;

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

// Format a fully rendered log line, timestamped NOW (at decision time, not
// at drain time -- so timestamps reflect when the event actually happened
// even if the queue is backed up).
static std::string format_log_line(const std::string& key)
{
    std::string line = make_timestamp();
    line += ": ";
    line += key;
    line += '\n';
    return line;
}

// Hand a fully formatted line to the bounded queue.  Takes queue_mutex only
// long enough to push_back() or bump the drop counter -- no I/O happens
// here, so this can safely be called while the caller still holds
// g_logger.mutex (or, transitively, any of ITS callers' own locks, e.g.
// RepeatController's _repeat_mutex).
static void logger_enqueue(std::string line)
{
    {
        std::lock_guard<std::mutex> lock(g_logger.queue_mutex);
        if (g_logger.queue.size() >= LOGGER_QUEUE_CAPACITY)
        {
            g_logger.dropped.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        g_logger.queue.push_back(std::move(line));
        g_logger.enqueued.fetch_add(1, std::memory_order_release);
    }
    g_logger.queue_cv.notify_one();
}

static void logger_emit_raw_line(const std::string& key)
{
    logger_enqueue(format_log_line(key));
}

// Directly write one already-formatted line to the sink.  Called only from
// the logging thread itself (logger_thread_func), which is the sole owner
// of the sink -- never from a producer thread.
static void logger_write_to_sink(const std::string& line)
{
    std::fwrite(line.data(), 1, line.size(), stderr);
    std::fflush(stderr);
}

// The dedicated logging thread: drains the queue and does all blocking I/O,
// so no producer (logger_log() caller) is ever blocked on a slow sink.  If
// the sink stalls, the queue simply backs up (bounded) and further messages
// are dropped-and-counted rather than piling every thread up behind a
// single global mutex.
static void logger_thread_func()
{
    for (;;)
    {
        std::deque<std::string> batch;
        {
            std::unique_lock<std::mutex> lock(g_logger.queue_mutex);
            g_logger.queue_cv.wait(lock, []
            {
                return !g_logger.queue.empty()
                    || g_logger.stop_requested.load(std::memory_order_relaxed);
            });
            batch.swap(g_logger.queue);
        }

        for (const std::string& line : batch)
        {
            logger_write_to_sink(line);
            g_logger.written.fetch_add(1, std::memory_order_release);
        }

        // Pressure-clear diagnosis: once we've drained everything we could
        // see this round, report (and reset) any drop count so silence
        // during a stall is diagnosable after the fact.
        uint64_t dropped_now = g_logger.dropped.exchange(0, std::memory_order_relaxed);
        if (dropped_now > 0)
        {
            std::ostringstream oss;
            oss << "[logger] dropped " << dropped_now
                << " message" << (dropped_now == 1 ? "" : "s")
                << " (queue full)";
            logger_write_to_sink(format_log_line(oss.str()));
        }

        if (g_logger.stop_requested.load(std::memory_order_relaxed))
        {
            std::lock_guard<std::mutex> lock(g_logger.queue_mutex);
            if (g_logger.queue.empty())
                break;
        }
    }

    g_logger.thread_running.store(false, std::memory_order_release);
}

// Must be called with lifecycle_mutex held.
static void logger_ensure_thread_started_locked()
{
    if (g_logger.thread_running.load(std::memory_order_relaxed))
        return;

    g_logger.stop_requested.store(false, std::memory_order_relaxed);
    g_logger.thread_running.store(true, std::memory_order_relaxed);
    g_logger.thread = std::thread(logger_thread_func);
}

// Must be called with lifecycle_mutex held.
static void logger_stop_thread_locked(int timeout_ms)
{
    if (!g_logger.thread_running.load(std::memory_order_relaxed))
        return;

    g_logger.stop_requested.store(true, std::memory_order_relaxed);
    g_logger.queue_cv.notify_all();

    // std::thread has no join-with-timeout, so poll the "has the thread
    // signalled it is exiting" flag instead of the thread object itself.
    // That way a sink stuck mid-write() cannot hang teardown.
    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds(timeout_ms);
    while (g_logger.thread_running.load(std::memory_order_acquire)
           && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    if (!g_logger.thread_running.load(std::memory_order_relaxed))
    {
        if (g_logger.thread.joinable())
            g_logger.thread.join();
    }
    else
    {
        // Best-effort only: the sink is still stalled after the bounded
        // wait.  Detach rather than join so process exit is not held
        // hostage by a wedged write(); any lines still queued are lost.
        // Documented tradeoff (see logger_shutdown() in the header) --
        // acceptable for a crash/teardown path, not steady-state operation.
        g_logger.thread.detach();
    }
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
    {
        std::lock_guard<std::mutex> lifecycle_lock(g_logger.lifecycle_mutex);
        logger_ensure_thread_started_locked();
    }

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

void logger_set_level(MonitorLogLevel level)
{
    std::lock_guard<std::mutex> lock(g_logger.mutex);
    logger_emit_repeat_summary_locked();
    g_logger.last_key.clear();
    g_logger.last_printed = 0;
    g_logger.level.store(level, std::memory_order_relaxed);
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

void logger_shutdown()
{
    // Enqueue any pending duplicate-suppression summary before stopping the
    // thread, so it's included in the final drain rather than silently lost.
    logger_flush_repeats();

    std::lock_guard<std::mutex> lifecycle_lock(g_logger.lifecycle_mutex);
    logger_stop_thread_locked(LOGGER_SHUTDOWN_TIMEOUT_MS);
}

uint64_t logger_test_dropped_count()
{
    return g_logger.dropped.load(std::memory_order_relaxed);
}

size_t logger_test_queue_depth()
{
    std::lock_guard<std::mutex> lock(g_logger.queue_mutex);
    return g_logger.queue.size();
}

bool logger_test_wait_drained(int timeout_ms)
{
    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds(timeout_ms);
    for (;;)
    {
        // enqueued == written means every line ever successfully pushed has
        // actually been handed to logger_write_to_sink() and returned --
        // i.e. the fwrite()/fflush() completed, not just that the queue
        // was swapped out.  Dropped messages never increment enqueued, so
        // they are correctly excluded from this check.
        if (g_logger.written.load(std::memory_order_acquire)
                == g_logger.enqueued.load(std::memory_order_acquire))
            return true;
        if (std::chrono::steady_clock::now() >= deadline)
            return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
}
