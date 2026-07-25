// =============================================================================
// test_monitor_utils.cpp
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Unit tests for autostream_monitor_utils: log level parsing, get_monotonic_time
// resolution, and protocol_log_level_name round-trip.
//
// Build (on Linux, from repo root):
//   g++ -std=c++17 -O2 -I core/monitor \
//       core/monitor/tests/test_monitor_utils.cpp \
//       core/monitor/autostream_monitor_utils.cpp \
//       -lpthread -o /tmp/test_monitor_utils && /tmp/test_monitor_utils
// =============================================================================

#include "autostream_monitor_utils.h"

#include <atomic>
#include <cassert>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

// ---------------------------------------------------------------------------
// Minimal assertion harness
// ---------------------------------------------------------------------------

static int g_tests  = 0;
static int g_failed = 0;

#define CHECK(cond, msg) do { \
    ++g_tests; \
    if (!(cond)) { \
        ++g_failed; \
        std::fprintf(stderr, "FAIL [%s:%d] %s — %s\n", \
                     __FILE__, __LINE__, #cond, (msg)); \
    } \
} while (0)

// ---------------------------------------------------------------------------
// parse_monitor_log_level
// ---------------------------------------------------------------------------

static void test_parse_log_level()
{
    MonitorLogLevel level;

    CHECK(parse_monitor_log_level("warning", &level), "parse 'warning'");
    CHECK(level == MonitorLogLevel::Warn, "warning maps to Warn");

    CHECK(parse_monitor_log_level("info", &level), "parse 'info'");
    CHECK(level == MonitorLogLevel::Info, "info maps to Info");

    CHECK(parse_monitor_log_level("debug", &level), "parse 'debug'");
    CHECK(level == MonitorLogLevel::Debug, "debug maps to Debug");

    CHECK(parse_monitor_log_level("spam", &level), "parse 'spam'");
    CHECK(level == MonitorLogLevel::Spam, "spam maps to Spam");

    CHECK(parse_monitor_log_level(" INFO ", &level), "parse uppercase info with whitespace");
    CHECK(level == MonitorLogLevel::Info, "uppercase INFO maps to Info");

    CHECK(parse_monitor_log_level("FATAL", &level), "parse uppercase fatal alias");
    CHECK(level == MonitorLogLevel::Warn, "fatal alias maps to Warn");

    CHECK(parse_monitor_log_level("log", &level), "parse log alias");
    CHECK(level == MonitorLogLevel::Warn, "log alias maps to Warn");

    CHECK(parse_monitor_log_level("warn", &level), "parse warn alias");
    CHECK(level == MonitorLogLevel::Warn, "warn alias maps to Warn");

    CHECK(!parse_monitor_log_level("unknown", &level), "unknown returns false");
    CHECK(!parse_monitor_log_level("", &level),         "empty returns false");
}

// ---------------------------------------------------------------------------
// protocol_log_level_name: round-trip via parse_monitor_log_level
// ---------------------------------------------------------------------------

static void test_protocol_log_level_name()
{
    // Each level must have a non-empty protocol name that can be parsed back.
    MonitorLogLevel levels[] = {
        MonitorLogLevel::Warn,
        MonitorLogLevel::Info,
        MonitorLogLevel::Debug,
        MonitorLogLevel::Spam,
    };

    for (auto lvl : levels) {
        const char* name = protocol_log_level_name(lvl);
        CHECK(name != nullptr && name[0] != '\0', "protocol name is non-empty");

        MonitorLogLevel parsed;
        bool ok = parse_monitor_log_level(name, &parsed);
        CHECK(ok, "protocol name round-trips through parse_monitor_log_level");
        CHECK(parsed == lvl, "round-tripped level matches original");
    }
}

// ---------------------------------------------------------------------------
// get_monotonic_time: basic sanity checks
// ---------------------------------------------------------------------------

static void test_get_monotonic_time()
{
    double t0 = get_monotonic_time();
    CHECK(t0 > 0.0, "monotonic time is positive");

    double t1 = get_monotonic_time();
    CHECK(t1 >= t0, "second sample is not earlier than first");

    // A nanosecond-resolution clock on any modern system should yield
    // values that differ by at least ~1 µs per call.  We only check for
    // gross anomalies here (values that differ by more than 10 seconds
    // suggest a clock source problem rather than a resolution issue).
    CHECK((t1 - t0) < 10.0, "two consecutive calls within 10 s");
}

// ---------------------------------------------------------------------------
// logger_set_level / logger_get_level
// ---------------------------------------------------------------------------

static void test_logger_set_get_level()
{
    logger_init(MonitorLogLevel::Warn);
    CHECK(logger_get_level() == MonitorLogLevel::Warn, "init sets level");

    logger_set_level(MonitorLogLevel::Debug);
    CHECK(logger_get_level() == MonitorLogLevel::Debug, "set to debug");

    logger_set_level(MonitorLogLevel::Info);
    CHECK(logger_get_level() == MonitorLogLevel::Info, "set to info");
}

// ---------------------------------------------------------------------------
// StderrRedirect: swap fd 2 to an arbitrary fd for the duration of a scope.
//
// The logger writes to the process's `stderr` FILE*, which glibc keeps
// unbuffered -- each fwrite() triggers an immediate write(2) against
// whatever fd 2 currently refers to.  Redirecting fd 2 to a pipe/file we
// control, without touching any production code, is what lets these tests
// exercise the logging thread's real sink-write path (including making it
// block) from a single process.  IMPORTANT: no CHECK()/fprintf(stderr, ...)
// diagnostics may run while a redirect that could block is active -- they
// would themselves block on it.  Restore first, then assert.
// ---------------------------------------------------------------------------

class StderrRedirect
{
public:
    explicit StderrRedirect(int new_fd)
    {
        std::fflush(stderr);
        _saved_fd = ::dup(STDERR_FILENO);
        ::dup2(new_fd, STDERR_FILENO);
    }

    ~StderrRedirect()
    {
        restore();
    }

    void restore()
    {
        if (_saved_fd < 0)
            return;
        std::fflush(stderr);
        ::dup2(_saved_fd, STDERR_FILENO);
        ::close(_saved_fd);
        _saved_fd = -1;
    }

private:
    int _saved_fd = -1;
};

// ---------------------------------------------------------------------------
// PipeDrain: continuously drain a pipe's read end in a background thread.
//
// IMPORTANT: a naive `while (read(fd, ...) > 0) {}` loop deadlocks here --
// read() only returns 0 (EOF) once every write end of the pipe is closed,
// but our write end stays open (dup2'd onto stderr) for the whole test, so
// such a loop blocks forever waiting for data that will never come once the
// logging thread finishes its current backlog. poll() with a short timeout,
// checked against a stop flag, lets the drain run concurrently with
// logger_test_wait_drained() (new messages can keep arriving while we wait)
// and still be stopped deterministically from the test thread.
// ---------------------------------------------------------------------------

static void pipe_drain_loop(int read_fd, std::atomic<bool>* stop_flag)
{
    char buf[4096];
    struct pollfd pfd;
    pfd.fd = read_fd;
    pfd.events = POLLIN;

    while (!stop_flag->load(std::memory_order_relaxed))
    {
        pfd.revents = 0;
        int rc = ::poll(&pfd, 1, 50 /* ms */);
        if (rc > 0 && (pfd.revents & POLLIN))
        {
            ssize_t n = ::read(read_fd, buf, sizeof(buf));
            if (n <= 0)
                break;  // pipe closed or genuine error
        }
    }
}

// ---------------------------------------------------------------------------
// Logger queue: ordering + byte format preserved
// ---------------------------------------------------------------------------

static void test_logger_ordering_and_format()
{
    logger_init(MonitorLogLevel::Spam);

    char tmp_path[] = "/tmp/test_monitor_utils_ordering_XXXXXX";
    int tmp_fd = ::mkstemp(tmp_path);
    CHECK(tmp_fd >= 0, "mkstemp for ordering capture file succeeded");
    if (tmp_fd < 0)
        return;

    {
        StderrRedirect redirect(tmp_fd);
        LOG_WARN("[test] ordering message A");
        LOG_INFO("[test] ordering message B");
        LOG_DEBUG("[test] ordering message C");
        CHECK(logger_test_wait_drained(1000), "queue drained within 1s (ordering test)");
    }
    ::close(tmp_fd);

    std::ifstream in(tmp_path);
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line))
        if (!line.empty())
            lines.push_back(line);
    in.close();
    ::unlink(tmp_path);

    CHECK(lines.size() == 3, "exactly 3 lines captured");
    if (lines.size() == 3)
    {
        // Byte format: "<DD-Mon-YY HH:MM:SS>: [LEVEL] message" -- unchanged
        // from the pre-queue logger.  Check the "[LEVEL] message" suffix and
        // the ": " timestamp separator rather than the timestamp digits
        // themselves (those are inherently non-deterministic).
        CHECK(lines[0].find(": [WARN] [test] ordering message A") != std::string::npos,
              "line 0 is message A with WARN tag");
        CHECK(lines[1].find(": [INFO] [test] ordering message B") != std::string::npos,
              "line 1 is message B with INFO tag");
        CHECK(lines[2].find(": [DEBUG] [test] ordering message C") != std::string::npos,
              "line 2 is message C with DEBUG tag");
    }

    logger_init(MonitorLogLevel::Warn);  // restore quiet default for later tests
}

// ---------------------------------------------------------------------------
// Logger queue: drop counting under sustained pressure
// ---------------------------------------------------------------------------

static void test_logger_drop_counting()
{
    logger_init(MonitorLogLevel::Spam);

    // A pipe whose write end we redirect stderr to, but whose read end we
    // never drain during the flood: once its kernel buffer fills, further
    // writes from the logging thread block, so the queue backs up and
    // logger_log() has to start dropping messages once LOGGER_QUEUE_CAPACITY
    // is exceeded.
    int fds[2];
    CHECK(::pipe(fds) == 0, "pipe() for drop-counting test succeeded");

    // Shrink the pipe buffer so the flood below reliably exceeds the
    // combined pipe + 256-entry queue capacity without needing an
    // unreasonably large loop.
#ifdef F_SETPIPE_SZ
    ::fcntl(fds[1], F_SETPIPE_SZ, 4096);
#endif

    uint64_t dropped_during_flood = 0;

    {
        StderrRedirect redirect(fds[1]);

        // Distinct messages (varying the counter in the text) so duplicate
        // suppression does not collapse them into a single emitted line --
        // we want raw enqueue volume, not post-suppression volume.
        for (int i = 0; i < 2000; ++i)
            LOG_WARN("[test] drop-flood message %d", i);

        dropped_during_flood = logger_test_dropped_count();

        // Start draining the read end (in the background, non-blocking poll
        // loop -- see PipeDrain comment above) so the logging thread can
        // unblock and finish writing whatever made it into the queue, then
        // wait for the drain to complete.
        std::atomic<bool> stop_drain{false};
        std::thread drain_thread(pipe_drain_loop, fds[0], &stop_drain);
        CHECK(logger_test_wait_drained(2000), "queue drained after unblocking sink");
        stop_drain.store(true, std::memory_order_relaxed);
        drain_thread.join();
    }
    ::close(fds[0]);
    ::close(fds[1]);

    CHECK(dropped_during_flood > 0,
          "flood exceeding queue capacity behind a stalled sink actually dropped messages");

    // The flood was 2000 distinct messages into a 256-entry queue behind a
    // stalled sink -- some must have been dropped and counted.  The drop
    // counter resets to 0 once the logging thread emits the "[logger]
    // dropped N messages" summary as part of draining, so by the time
    // logger_test_wait_drained() returned true, logger_test_dropped_count()
    // is back at 0; the observable effect is captured via the assertion
    // above (drain completing implies the summary path ran without
    // deadlocking) -- explicitly re-check it reads 0 post-drain here.
    CHECK(logger_test_dropped_count() == 0,
          "drop counter reset to 0 after summary emitted on drain");

    logger_init(MonitorLogLevel::Warn);
}

// ---------------------------------------------------------------------------
// Logger queue: producer stays responsive while the sink is stalled
// (stall-simulation -- proves no caller-held mutex is ever held across the
// actual sink write, so a stalled sink cannot wedge another thread)
// ---------------------------------------------------------------------------

static void test_logger_stall_does_not_block_producer()
{
    logger_init(MonitorLogLevel::Spam);

    int fds[2];
    CHECK(::pipe(fds) == 0, "pipe() for stall-simulation test succeeded");

    // Shrink the pipe's kernel buffer to the minimum (one page) so it fills
    // -- and the logging thread's fwrite() blocks -- after only a handful of
    // short log lines, rather than needing tens of thousands of messages.
#ifdef F_SETPIPE_SZ
    ::fcntl(fds[1], F_SETPIPE_SZ, 4096);
#endif

    double wall_ms = -1.0;
    uint64_t dropped_before = 0;
    uint64_t dropped_after  = 0;

    {
        StderrRedirect redirect(fds[1]);

        // Fill the pipe (and, once that's full, the 256-entry queue) without
        // ever reading from fds[0] -- this is a stalled sink: a write() that
        // blocks for a long time. If something held a mutex across that
        // write, any other thread wanting the same mutex would wedge behind
        // it. Here, nothing holds a mutex across it -- that's what we're
        // proving.
        for (int i = 0; i < 4000; ++i)
            LOG_WARN("[test] stall-flood message %d", i);

        dropped_before = logger_test_dropped_count();

        // This is the crux of the test: simulate a concurrent thread doing
        // something latency-sensitive (in production, e.g. get_status() /
        // a RepeatController call under _repeat_mutex) by timing further
        // logger_log() calls while the sink is still fully stalled behind
        // the flood above. If a mutex were held across fwrite/fflush, this
        // would block for as long as the stalled write() -- i.e.
        // indefinitely, since nothing is draining fds[0]. Instead it must
        // return almost immediately every time, because logger_log() never
        // touches the sink itself.
        auto t0 = std::chrono::steady_clock::now();
        for (int i = 0; i < 50; ++i)
            LOG_WARN("[test] responsiveness-probe %d", i);
        auto t1 = std::chrono::steady_clock::now();
        wall_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

        dropped_after = logger_test_dropped_count();

        // Now unblock the stalled sink (background drain, see PipeDrain
        // comment above) and let the logging thread finish draining.
        std::atomic<bool> stop_drain{false};
        std::thread drain_thread(pipe_drain_loop, fds[0], &stop_drain);
        CHECK(logger_test_wait_drained(2000), "queue drained after unblocking stalled sink");
        stop_drain.store(true, std::memory_order_relaxed);
        drain_thread.join();
    }
    ::close(fds[0]);
    ::close(fds[1]);

    // The key evidence: 50 logger_log() calls made *while the sink was
    // still fully stalled* completed in well under a second combined --
    // proving the caller (the analogue of get_status()/_repeat_mutex
    // holders in production) was never blocked behind the wedged write().
    CHECK(wall_ms >= 0.0 && wall_ms < 500.0,
          "50 logger_log() calls during a stalled sink returned promptly (producer not blocked)");
    CHECK(dropped_after >= dropped_before,
          "drop counter is monotonic (queue-full path exercised, not a crash)");

    logger_init(MonitorLogLevel::Warn);
}

// ---------------------------------------------------------------------------
// logger_shutdown: bounded flush-on-shutdown
// ---------------------------------------------------------------------------

static void test_logger_shutdown_flushes_and_stops()
{
    logger_init(MonitorLogLevel::Spam);

    char tmp_path[] = "/tmp/test_monitor_utils_shutdown_XXXXXX";
    int tmp_fd = ::mkstemp(tmp_path);
    CHECK(tmp_fd >= 0, "mkstemp for shutdown capture file succeeded");
    if (tmp_fd < 0)
        return;

    {
        StderrRedirect redirect(tmp_fd);
        LOG_WARN("[test] shutdown message 1");
        LOG_WARN("[test] shutdown message 2");
        LOG_WARN("[test] shutdown message 2");  // duplicate: exercises repeat-summary flush too
        logger_shutdown();  // must drain the queue (and any repeat summary) before returning
    }
    ::close(tmp_fd);

    std::ifstream in(tmp_path);
    std::ostringstream contents;
    contents << in.rdbuf();
    in.close();
    ::unlink(tmp_path);

    CHECK(contents.str().find("shutdown message 1") != std::string::npos,
          "shutdown message 1 was flushed by logger_shutdown()");
    CHECK(contents.str().find("shutdown message 2") != std::string::npos,
          "shutdown message 2 was flushed by logger_shutdown()");
    CHECK(logger_test_queue_depth() == 0, "queue is empty after logger_shutdown()");

    // Restart logging for any subsequent tests / harness use in this process.
    logger_init(MonitorLogLevel::Warn);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

int main()
{
    logger_init(MonitorLogLevel::Warn);   // silence log output during tests

    test_parse_log_level();
    test_protocol_log_level_name();
    test_get_monotonic_time();
    test_logger_set_get_level();
    test_logger_ordering_and_format();
    test_logger_drop_counting();
    test_logger_stall_does_not_block_producer();
    test_logger_shutdown_flushes_and_stops();

    // The logging thread is a background std::thread owned by process-wide
    // state (g_logger); it must be stopped (joined) before main() returns,
    // or the std::thread destructor at static-destruction time will find it
    // still joinable and call std::terminate(). Mirrors the real daemon's
    // main() teardown call in autostream_monitor.cpp.
    logger_shutdown();

    if (g_failed == 0) {
        std::printf("OK  %d/%d tests passed\n", g_tests, g_tests);
        return 0;
    }
    std::fprintf(stderr, "FAIL %d/%d tests failed\n", g_failed, g_tests);
    return 1;
}
