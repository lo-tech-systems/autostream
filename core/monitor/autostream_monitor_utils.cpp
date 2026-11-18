// =============================================================================
// autostream_monitor_utils.cpp
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Implementation of timing, logging, and string utilities shared by all
// autostream_monitor translation units.
// =============================================================================

#include "autostream_monitor_utils.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <time.h>

#include <fcntl.h>
#include <malloc.h>

#include <cerrno>
#include <pthread.h>
#include <sched.h>


// =============================================================================
// FIFO pipe sizing
// =============================================================================

int resize_fifo_pipe(int fd)
{
    if (fcntl(fd, F_SETPIPE_SZ, kFifoPipeBytes) < 0)
        return -1;
    return fcntl(fd, F_GETPIPE_SZ);
}


// =============================================================================
// Thread scheduling
// =============================================================================

void set_thread_realtime(const char* thread_label, int priority)
{
    struct sched_param sp{};
    sp.sched_priority = priority;

    int rc = pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);
    if (rc != 0)
    {
        // pthread_setschedparam() returns the error code directly; it does
        // not set errno.
        LOG_WARN("[%s] could not set SCHED_FIFO prio %d: %s; continuing at normal priority",
                 thread_label, priority, strerror(rc));
        return;
    }

    LOG_INFO("[%s] real-time scheduling active (SCHED_FIFO prio %d)", thread_label, priority);
}


// =============================================================================
// Audio format math
//
// dbfs_to_linear_threshold()/linear_to_dbfs(): the float-domain level/peak
// conversion that replaced the old 32767/32768 int16-scale constants. They
// live here rather than in autostream_monitor_io.cpp so the dBFS<->linear
// math is reachable from a test binary that links only this translation
// unit (no ALSA/libsamplerate).
// =============================================================================

float dbfs_to_linear_threshold(float dbfs)
{
    if (dbfs >= 0.0f)
        return 1.0f;
    float linear = std::pow(10.0f, dbfs / 20.0f);
    return std::max(1.0f / 32768.0f, std::min(1.0f, linear));
}

float linear_to_dbfs(float peak_linear)
{
    if (peak_linear <= 0.0f)
        return -90.0f;
    return std::max(-90.0f, 20.0f * std::log10(peak_linear));
}

// =============================================================================
// Output format descriptor
//
// See the class/global doc comments in autostream_monitor_utils.h for the
// full design and publication argument. Default-constructed to native
// (48000/32/2), so any translation unit that never calls main() (every test
// binary) observes the native constants unchanged.
// =============================================================================

OutputFormatDescriptor g_output_format;

const char* output_format_mode_name(OutputFormatMode mode)
{
    switch (mode)
    {
        case OutputFormatMode::Native:     return "native";
        case OutputFormatMode::Compatible: return "compatible";
    }
    return "native";   // unreachable; keeps -Wreturn-type happy on all compilers
}

// =============================================================================
// SRC quality tier
//
// See the section comment in autostream_monitor_utils.h for the full design
// (scope, no-runtime-switching rationale, cross-reference to owntone-mini's
// aac_coder_select()).
// =============================================================================

SrcQualityState g_src_quality;

const char* src_quality_tier_name(SrcQualityTier tier)
{
    switch (tier)
    {
        case SrcQualityTier::Fast:   return "fast";
        case SrcQualityTier::Medium: return "medium";
        case SrcQualityTier::Best:   return "best";
    }
    return "medium";   // unreachable; keeps -Wreturn-type happy on all compilers
}

const char* src_quality_source_name(SrcQualitySource source)
{
    switch (source)
    {
        case SrcQualitySource::Auto: return "auto";
        case SrcQualitySource::Flag: return "flag";
    }
    return "auto";   // unreachable; keeps -Wreturn-type happy on all compilers
}

bool parse_src_quality_tier(const std::string& text, SrcQualityTier* out_tier)
{
    if (text == "fast")
    {
        *out_tier = SrcQualityTier::Fast;
        return true;
    }
    if (text == "medium")
    {
        *out_tier = SrcQualityTier::Medium;
        return true;
    }
    if (text == "best")
    {
        *out_tier = SrcQualityTier::Best;
        return true;
    }
    return false;
}

SrcAutoDetectResult classify_src_tier_from_cpuinfo(const std::string& cpuinfo_content)
{
    // Same "CPU part\t: 0x.." line scan as owntone-mini's aac_coder_select()
    // (src/transcode.c) -- sscanf's literal spaces in the format string
    // match any run of whitespace, so both the tab-separated real file and
    // a hand-written test fixture using plain spaces parse identically.
    std::istringstream in(cpuinfo_content);
    std::string line;
    bool saw_high_perf_part = false;
    bool saw_any_part       = false;

    while (std::getline(in, line))
    {
        unsigned int part = 0;
        if (std::sscanf(line.c_str(), "CPU part : %x", &part) != 1)
            continue;

        saw_any_part = true;
        switch (part)
        {
            case 0xd08: // Cortex-A72 (Pi 4)
            case 0xd0b: // Cortex-A76 (Pi 5)
                saw_high_perf_part = true;
                break;
            default:
                // Cortex-A53 (0xd03, Pi 3 / Zero 2 W) and anything else
                // recognised or not -- Medium, per the header comment.
                break;
        }
        if (saw_high_perf_part)
            break;
    }

    if (saw_high_perf_part)
        return { SrcQualityTier::Best, "cortex-a72/a76" };
    if (saw_any_part)
        return { SrcQualityTier::Medium, "cortex-a53" };
    return { SrcQualityTier::Medium, "unknown" };
}

SrcAutoDetectResult detect_src_tier_from_proc_cpuinfo()
{
    std::ifstream in("/proc/cpuinfo");
    if (!in.is_open())
        return { SrcQualityTier::Medium, "unknown" };

    std::ostringstream contents;
    contents << in.rdbuf();
    return classify_src_tier_from_cpuinfo(contents.str());
}

int src_converter_type_for_tier(SrcQualityTier tier)
{
    switch (tier)
    {
        case SrcQualityTier::Fast:   return SRC_SINC_FASTEST;
        case SrcQualityTier::Medium: return SRC_SINC_MEDIUM_QUALITY;
        case SrcQualityTier::Best:   return SRC_SINC_BEST_QUALITY;
    }
    return SRC_SINC_FASTEST;   // unreachable; keeps -Wreturn-type happy
}

// Replaces OutputDumpWriter's hardcoded 44.1 kHz/16-bit WAV_PLACEHOLDER_HEADER
// byte array (autostream_monitor_io.cpp)
// with a header derived from the monitor's actual output format descriptor
// (g_output_format, autostream_monitor_utils.h -- formerly the compile-time
// AudioMonitor::OUTPUT_RATE/OUTPUT_BITS/OUTPUT_CHANNELS). Pure
// function of its arguments so it can be unit-tested without any
// monitor/ALSA state.
std::array<std::uint8_t, 44> build_wav_header(int rate,
                                               int bits,
                                               int channels,
                                               std::uint32_t data_bytes)
{
    std::array<std::uint8_t, 44> header{};

    const std::uint32_t block_align = static_cast<std::uint32_t>(channels)
                                     * static_cast<std::uint32_t>(bits / 8);
    const std::uint32_t byte_rate   = static_cast<std::uint32_t>(rate) * block_align;

    const std::uint32_t riff_size = 36u + data_bytes;  // 36 = 44-byte header minus 8 for "RIFF"+size

    auto put_u32 = [&header](std::size_t offset, std::uint32_t val)
    {
        header[offset + 0] = static_cast<std::uint8_t>(val);
        header[offset + 1] = static_cast<std::uint8_t>(val >> 8);
        header[offset + 2] = static_cast<std::uint8_t>(val >> 16);
        header[offset + 3] = static_cast<std::uint8_t>(val >> 24);
    };
    auto put_u16 = [&header](std::size_t offset, std::uint16_t val)
    {
        header[offset + 0] = static_cast<std::uint8_t>(val);
        header[offset + 1] = static_cast<std::uint8_t>(val >> 8);
    };

    std::memcpy(&header[0], "RIFF", 4);
    put_u32(4, riff_size);
    std::memcpy(&header[8], "WAVE", 4);

    std::memcpy(&header[12], "fmt ", 4);
    put_u32(16, 16);                                          // fmt sub-chunk size
    put_u16(20, 1);                                            // audio_format = PCM
    put_u16(22, static_cast<std::uint16_t>(channels));
    put_u32(24, static_cast<std::uint32_t>(rate));
    put_u32(28, byte_rate);
    put_u16(32, static_cast<std::uint16_t>(block_align));
    put_u16(34, static_cast<std::uint16_t>(bits));

    std::memcpy(&header[36], "data", 4);
    put_u32(40, data_bytes);

    return header;
}


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

    // Set (under queue_mutex) to make the logging thread scan the rate
    // limiter's slots on its next wake.
    std::atomic<bool> rate_wake{false};
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

// =============================================================================
// Keyed rate limit
// =============================================================================

namespace
{
    struct LogRateSlot
    {
        std::atomic<std::int64_t>  next_ns{0};       // window end
        std::atomic<std::int64_t>  last_emit_ns{0};
        std::atomic<std::uint32_t> suppressed{0};
        std::atomic<std::uint8_t>  level{0};         // level of the last line written
    };

    constexpr std::size_t kLogRateSlotCount =
        static_cast<std::size_t>(LogKey::Count) * kLogKeyInstances;

    LogRateSlot g_rate_slots[kLogRateSlotCount];

    static_assert(std::atomic<std::int64_t>::is_always_lock_free,
                  "the rate limiter's decision path must not take a lock");
    static_assert(std::atomic<std::uint32_t>::is_always_lock_free,
                  "the rate limiter's decision path must not take a lock");

    constexpr const char* kLogKeyNames[] = {
        "capture ring full",
        "fifo reader stalled",
        "output live wait timeout",
        "output scheduling gap",
        "capture rate step",
        "capture rate mismatch",
        "sample rate converter error",
        "fifo open failed",
        "fifo path not a pipe",
        "fifo opened",
        "fifo broken pipe",
        "fifo write error",
        "rate window discarded",
        "rate class candidate",
        "input stopped unexpectedly",
        "input restarted",
        "input restart failed",
        "input stopped soon after a restart",
    };
    static_assert(sizeof(kLogKeyNames) / sizeof(kLogKeyNames[0])
                      == static_cast<std::size_t>(LogKey::Count),
                  "every log key needs a name");

    std::atomic<std::int64_t (*)()> g_rate_clock{nullptr};

    std::int64_t rate_now_ns()
    {
        if (auto fn = g_rate_clock.load(std::memory_order_relaxed))
            return fn();
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return static_cast<std::int64_t>(ts.tv_sec) * 1000000000LL + ts.tv_nsec;
    }
}

// One text for the window-end sweep and for logger_flush_repeats().  A summary
// written straight to the sink can carry a later timestamp than a queued line
// written after it, as the "[logger] dropped" line already can.
static std::string format_rate_summary(std::size_t index, std::uint32_t count,
                                       std::int64_t last_emit_ns, std::int64_t now_ns)
{
    const int level = g_rate_slots[index].level.load(std::memory_order_relaxed);
    const std::size_t key = index / kLogKeyInstances;
    const std::size_t instance = index % kLogKeyInstances;
    const long long elapsed_s = std::max<long long>(
        0, std::llround(static_cast<double>(now_ns - last_emit_ns) / 1.0e9));

    std::ostringstream oss;
    oss << '[' << log_level_name(static_cast<MonitorLogLevel>(level)) << "] [log] "
        << kLogKeyNames[key];
    if (instance != 0)
        oss << ", input " << instance;
    oss << ": " << count << " more suppressed in " << elapsed_s << " s";
    return format_log_line(oss.str());
}

// Report the counts of slots whose window has ended (every slot with a count
// if `force`), either straight to the sink (the logging thread) or through the
// queue (any other thread).  Returns the earliest end of a window still open,
// or 0 if none is.  Each count is reported once: by this scan or by the next
// line written for the slot.  A scan racing with a winner may take the count
// the winner would have appended; that is accepted.
static std::int64_t logger_rate_scan(bool force, bool to_sink)
{
    const std::int64_t now = rate_now_ns();
    std::int64_t earliest = 0;

    for (std::size_t i = 0; i < kLogRateSlotCount; ++i)
    {
        LogRateSlot& slot = g_rate_slots[i];
        const std::int64_t next = slot.next_ns.load(std::memory_order_relaxed);
        if (next > now)
        {
            if (earliest == 0 || next < earliest)
                earliest = next;
            if (!force)
                continue;
        }
        if (slot.suppressed.load(std::memory_order_relaxed) == 0)
            continue;
        const std::uint32_t count = slot.suppressed.exchange(0, std::memory_order_relaxed);
        if (count == 0)
            continue;
        if (!log_level_enabled(static_cast<MonitorLogLevel>(
                slot.level.load(std::memory_order_relaxed))))
            continue;
        std::string line = format_rate_summary(
            i, count, slot.last_emit_ns.load(std::memory_order_relaxed), now);
        if (to_sink)
            logger_write_to_sink(line);
        else
            logger_enqueue(std::move(line));
    }
    return earliest;
}

// The dedicated logging thread: drains the queue and does all blocking I/O,
// so no producer (logger_log() caller) is ever blocked on a slow sink.  If
// the sink stalls, the queue simply backs up (bounded) and further messages
// are dropped-and-counted rather than piling every thread up behind a
// single global mutex.
//
// While a rate-limited window is open the thread also wakes when the earliest
// one ends, to report what was suppressed in it.  With none open it keeps the
// untimed wait, so an idle monitor gains no wakeups.
static void logger_thread_func()
{
    std::int64_t earliest_window_end = 0;
    for (;;)
    {
        std::deque<std::string> batch;
        {
            std::unique_lock<std::mutex> lock(g_logger.queue_mutex);
            auto ready = []
            {
                return !g_logger.queue.empty()
                    || g_logger.stop_requested.load(std::memory_order_relaxed)
                    || g_logger.rate_wake.load(std::memory_order_relaxed);
            };
            if (earliest_window_end > 0)
            {
                const std::int64_t wait_ns =
                    std::max<std::int64_t>(earliest_window_end - rate_now_ns(), 1000000);
                g_logger.queue_cv.wait_for(lock, std::chrono::nanoseconds(wait_ns), ready);
            }
            else
            {
                g_logger.queue_cv.wait(lock, ready);
            }
            g_logger.rate_wake.store(false, std::memory_order_relaxed);
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

        earliest_window_end = logger_rate_scan(false, true);

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

// Render "[LEVEL] message".  Returns false if the format failed.
static bool render_log_key(MonitorLogLevel level, const char* fmt, va_list args,
                           std::string& key)
{
    char stack_buf[1024];
    va_list args_copy;
    va_copy(args_copy, args);
    int needed = std::vsnprintf(stack_buf, sizeof(stack_buf), fmt, args_copy);
    va_end(args_copy);

    if (needed < 0)
        return false;

    key = "[";
    key += log_level_name(level);
    key += "] ";
    if (static_cast<size_t>(needed) < sizeof(stack_buf))
    {
        key.append(stack_buf, static_cast<size_t>(needed));
    }
    else
    {
        std::vector<char> dynamic_buf(static_cast<size_t>(needed) + 1);
        std::vsnprintf(dynamic_buf.data(), dynamic_buf.size(), fmt, args);
        key.append(dynamic_buf.data(), static_cast<size_t>(needed));
    }
    return true;
}

static void logger_vlog(MonitorLogLevel level, const char* fmt, va_list args)
{
    if (!log_level_enabled(level))
        return;

    std::string key;
    if (!render_log_key(level, fmt, args, key))
        return;

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

    for (LogRateSlot& slot : g_rate_slots)
    {
        slot.next_ns.store(0, std::memory_order_relaxed);
        slot.last_emit_ns.store(0, std::memory_order_relaxed);
        slot.suppressed.store(0, std::memory_order_relaxed);
        slot.level.store(0, std::memory_order_relaxed);
    }
}

MonitorLogLevel logger_get_level()
{
    return g_logger.level.load(std::memory_order_relaxed);
}

void logger_set_level(MonitorLogLevel level)
{
    std::lock_guard<std::mutex> lock(g_logger.mutex);
    logger_emit_repeat_summary_locked();
    logger_rate_scan(true, false);
    g_logger.last_key.clear();
    g_logger.last_printed = 0;
    g_logger.level.store(level, std::memory_order_relaxed);
}

void logger_flush_repeats()
{
    std::lock_guard<std::mutex> lock(g_logger.mutex);
    logger_emit_repeat_summary_locked();
    logger_rate_scan(true, false);
}

bool logger_rate_admit(MonitorLogLevel level, LogSlot slot, double seconds)
{
    if (!log_level_enabled(level))
        return false;

    // The sites pass strerror(errno) after this returns.
    const int saved_errno = errno;
    const std::int64_t now = rate_now_ns();
    errno = saved_errno;

    LogRateSlot& s = g_rate_slots[slot.index];
    std::int64_t next = s.next_ns.load(std::memory_order_relaxed);
    if (now < next)
    {
        s.suppressed.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    // Strong CAS on purpose: a spurious failure of a weak one would count a
    // genuine first occurrence as suppressed.  Losing means another thread
    // opened this window a moment ago, so the call belongs in its count.
    const std::int64_t window_end = now + static_cast<std::int64_t>(seconds * 1.0e9);
    if (!s.next_ns.compare_exchange_strong(next, window_end, std::memory_order_relaxed))
    {
        s.suppressed.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    return true;
}

bool logger_log_rated(MonitorLogLevel level, LogSlot slot, const char* fmt, ...)
{
    LogRateSlot& s = g_rate_slots[slot.index];
    const std::int64_t now = rate_now_ns();
    const std::uint32_t count = s.suppressed.exchange(0, std::memory_order_relaxed);
    const std::int64_t previous = s.last_emit_ns.exchange(now, std::memory_order_relaxed);
    s.level.store(static_cast<std::uint8_t>(level), std::memory_order_relaxed);

    std::string key;
    va_list args;
    va_start(args, fmt);
    const bool rendered = render_log_key(level, fmt, args, key);
    va_end(args);
    if (!rendered)
        return false;

    if (count > 0)
    {
        const long long ago_s = std::max<long long>(
            0, std::llround(static_cast<double>(now - previous) / 1.0e9));
        key += " (" + std::to_string(count) + " more suppressed since the last, "
             + std::to_string(ago_s) + " s ago)";
    }

    // Enqueuing wakes the logging thread, which then times its wait to the
    // window this call just opened.
    std::lock_guard<std::mutex> lock(g_logger.mutex);
    logger_emit_repeat_summary_locked();
    g_logger.last_key.clear();
    g_logger.last_printed = 0;
    logger_emit_raw_line(key);
    return true;
}

void logger_rate_rearm(LogSlot slot)
{
    LogRateSlot& s = g_rate_slots[slot.index];
    s.next_ns.store(0, std::memory_order_relaxed);
    if (s.suppressed.load(std::memory_order_relaxed) == 0)
        return;

    // The window is over, so its count is reported by the logging thread
    // rather than waiting for the next line.
    {
        std::lock_guard<std::mutex> lock(g_logger.queue_mutex);
        g_logger.rate_wake.store(true, std::memory_order_relaxed);
    }
    g_logger.queue_cv.notify_one();
}

void logger_test_set_clock(std::int64_t (*clock_ns)())
{
    g_rate_clock.store(clock_ns, std::memory_order_relaxed);
}

void logger_test_rate_sweep()
{
    logger_rate_scan(false, false);
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

// =============================================================================
// Memory usage snapshot
// =============================================================================

namespace
{
    // Parses one "<key><whitespace><digits>..." line, same shape as
    // /proc/self/status and /proc/meminfo lines ("VmRSS:\t  1234 kB",
    // "MemAvailable:    123456 kB"). Returns true iff `line` begins with
    // `key`, regardless of whether the digits themselves went on to parse --
    // so the caller can tell "this was the field" from "keep scanning". A
    // malformed match (key present, no digits) leaves out_kib untouched.
    // Deliberately independent of autostream_repeat_buffer.h's
    // try_parse_kib_field() (same shape, kept local so this facility has no
    // dependency on the repeat feature).
    bool try_parse_kib_line(const std::string& line, const char* key, unsigned long& out_kib)
    {
        size_t key_len = std::strlen(key);
        if (line.compare(0, key_len, key) != 0)
            return false;

        size_t pos = key_len;
        while (pos < line.size() && std::isspace(static_cast<unsigned char>(line[pos])))
            ++pos;

        size_t digits_start = pos;
        while (pos < line.size() && std::isdigit(static_cast<unsigned char>(line[pos])))
            ++pos;

        if (pos == digits_start)
            return true;  // key matched but no digits; malformed, leave out_kib as-is

        out_kib = std::strtoul(line.substr(digits_start, pos - digits_start).c_str(), nullptr, 10);
        return true;
    }
}

bool read_memory_snapshot(MemorySnapshot& out)
{
    out = MemorySnapshot{};

    // /proc/self/status: VmRSS/VmHWM/VmLck. This is the only source whose
    // absence fails the whole call -- every other source below is
    // best-effort and simply leaves its fields at 0/-1.
    {
        std::ifstream in("/proc/self/status");
        if (!in.is_open())
            return false;

        std::string line;
        bool have_rss = false, have_hwm = false, have_lck = false;
        while (std::getline(in, line) && !(have_rss && have_hwm && have_lck))
        {
            if (!have_rss && try_parse_kib_line(line, "VmRSS:", out.rss_kib))
                have_rss = true;
            else if (!have_hwm && try_parse_kib_line(line, "VmHWM:", out.hwm_kib))
                have_hwm = true;
            else if (!have_lck && try_parse_kib_line(line, "VmLck:", out.lck_kib))
                have_lck = true;
        }
    }

    // /proc/meminfo: MemAvailable, SwapTotal, SwapFree. Best-effort -- an
    // unreadable file leaves these fields at their zero defaults rather than
    // failing the call.
    {
        std::ifstream in("/proc/meminfo");
        if (in.is_open())
        {
            unsigned long swap_total_kib = 0, swap_free_kib = 0;
            bool have_avail = false, have_total = false, have_free = false;
            std::string line;
            while (std::getline(in, line) && !(have_avail && have_total && have_free))
            {
                if (!have_avail && try_parse_kib_line(line, "MemAvailable:", out.mem_available_kib))
                    have_avail = true;
                else if (!have_total && try_parse_kib_line(line, "SwapTotal:", swap_total_kib))
                    have_total = true;
                else if (!have_free && try_parse_kib_line(line, "SwapFree:", swap_free_kib))
                    have_free = true;
            }
            out.swap_used_kib = (swap_total_kib > swap_free_kib) ? (swap_total_kib - swap_free_kib) : 0;
        }
    }

    // glibc heap accounting. mallinfo2() is the modern (non-overflowing,
    // size_t-based) replacement for the deprecated mallinfo(); "in-use" is
    // the sum of small-bin/allocated space (uordblks) and mmap'd large
    // allocations (hblkhd), "held" adds the brk-arena space glibc has
    // reserved but not yet returned to the OS (arena) to the same mmap'd
    // total.
    {
        struct mallinfo2 mi = mallinfo2();
        out.heap_inuse_bytes = static_cast<unsigned long>(mi.uordblks) + static_cast<unsigned long>(mi.hblkhd);
        out.heap_held_bytes  = static_cast<unsigned long>(mi.arena)    + static_cast<unsigned long>(mi.hblkhd);
    }

    // malloc_info() writes an XML report (one "<heap nr=".. element per
    // arena) to a FILE*; open_memstream() gives it an in-memory sink so no
    // temp file is needed. Freed on every path, including if
    // open_memstream() itself failed (free(nullptr) is a no-op).
    {
        char*  memstream_buf  = nullptr;
        size_t memstream_size = 0;
        FILE*  memstream = ::open_memstream(&memstream_buf, &memstream_size);
        if (memstream)
        {
            if (::malloc_info(0, memstream) == 0)
            {
                std::fflush(memstream);  // updates memstream_buf/memstream_size
                std::string content(memstream_buf, memstream_size);
                int count = 0;
                size_t pos = 0;
                while ((pos = content.find("<heap nr=", pos)) != std::string::npos)
                {
                    ++count;
                    pos += 9;
                }
                out.malloc_arenas = count;
            }
            std::fclose(memstream);
        }
        std::free(memstream_buf);
    }

    return true;
}

std::string format_memory_line(const MemorySnapshot& m,
                                size_t                arena_chunks,
                                size_t                arena_spare,
                                size_t                arena_target,
                                size_t                chunk_bytes,
                                int                   capturing_inputs,
                                const char*           reason)
{
    const unsigned long rss_mib         = m.rss_kib / 1024;
    const unsigned long peak_mib        = m.hwm_kib / 1024;
    const unsigned long locked_mib      = m.lck_kib / 1024;
    const unsigned long heap_inuse_mib  = m.heap_inuse_bytes / (1024UL * 1024UL);
    const unsigned long heap_held_mib   = m.heap_held_bytes / (1024UL * 1024UL);
    const unsigned long arena_mib       = static_cast<unsigned long>(arena_chunks + arena_spare)
                                         * static_cast<unsigned long>(chunk_bytes) / (1024UL * 1024UL);
    const unsigned long available_mib   = m.mem_available_kib / 1024;
    const unsigned long swap_mib        = m.swap_used_kib / 1024;

    std::ostringstream oss;
    oss << "[monitor] memory: rss " << rss_mib << " MiB (peak " << peak_mib
        << ", locked " << locked_mib << "), heap in-use " << heap_inuse_mib
        << " MiB held " << heap_held_mib << " MiB arenas " << m.malloc_arenas
        << ", repeat arena " << arena_chunks << "+" << arena_spare << "/" << arena_target
        << " chunks (" << arena_mib << " MiB), capturing " << capturing_inputs
        << ", system available " << available_mib << " MiB, swap used " << swap_mib << " MiB";
    if (reason != nullptr && reason[0] != '\0')
        oss << " - " << reason;
    return oss.str();
}


// =============================================================================
// CLI --help text
// =============================================================================

std::string monitor_help_text(const std::string& default_socket_path)
{
    std::ostringstream oss;
    oss << "Usage: autostream_monitor [--socket PATH] [--log-level LEVEL] [--test-hooks]\n"
        << "                           [--compatible] [--src LEVEL]\n"
        << "\n"
        << "  --socket PATH   Unix domain socket path (default: " << default_socket_path << ")\n"
        << "  --log-level L   Override log level: warn|warning|info|debug|spam\n"
        << "  --test-hooks    Enable test-only socket commands (debug_fail_input).\n"
        << "                  Never used in production; dev/test harnesses only.\n"
        << "  --test-pin-src-ratio\n"
        << "                  Pin the SRC ratio to nominal (disables rate-drift\n"
        << "                  correction) for deterministic golden-reference runs.\n"
        << "                  Requires --test-hooks. Never used in production.\n"
        << "  --compatible    Output the FIFO as 44.1kHz/16-bit stereo, for stock\n"
        << "                  (upstream) OwnTone or a pre-48k owntone-mini -- both\n"
        << "                  have a named-pipe input fixed at 44.1kHz/16-bit.\n"
        << "                  Default (this flag absent) is native 48kHz/32-bit.\n"
        << "  --src LEVEL     Sample-rate-converter quality for the main FIFO output\n"
        << "                  path: fast|medium|best. Default (this flag absent) is\n"
        << "                  auto-detected from the CPU (Cortex-A72/A76-class ->\n"
        << "                  best, else medium). An invalid LEVEL falls back to\n"
        << "                  auto-detect with a warning instead of exiting.\n"
        << "\n"
        << "The monitor starts with no audio device connected.\n"
        << "Configure it via the socket using JSON commands.\n"
        << "See autostream_monitor.h for the full protocol.\n";
    return oss.str();
}
