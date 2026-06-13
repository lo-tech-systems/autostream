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

#include <cassert>
#include <cmath>
#include <cstdio>
#include <string>

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

    CHECK(!parse_monitor_log_level("unknown", &level), "unknown returns false");
    CHECK(!parse_monitor_log_level("", &level),         "empty returns false");
    CHECK(!parse_monitor_log_level("INFO", &level),     "uppercase INFO returns false (case-sensitive)");
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
        std::string lower(name);
        for (auto& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        bool ok = parse_monitor_log_level(lower, &parsed);
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

    MonitorLogLevel prev = logger_set_level(MonitorLogLevel::Debug);
    CHECK(logger_get_level() == MonitorLogLevel::Debug, "set to debug");
    // prev should be Warn (what we set at init).
    CHECK(prev == MonitorLogLevel::Warn, "set_level returns previous level");

    logger_set_level(MonitorLogLevel::Info);
    CHECK(logger_get_level() == MonitorLogLevel::Info, "set to info");
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

    if (g_failed == 0) {
        std::printf("OK  %d/%d tests passed\n", g_tests, g_tests);
        return 0;
    }
    std::fprintf(stderr, "FAIL %d/%d tests failed\n", g_failed, g_tests);
    return 1;
}
