// =============================================================================
// test_monitor_memory.cpp
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Unit tests for autostream_monitor_utils' memory-usage snapshot facility:
// format_memory_line()'s exact wording, and read_memory_snapshot()'s basic
// success contract on a real Linux host.
//
// Build (on Linux, from repo root):
//   g++ -std=c++17 -O2 -I core/monitor \
//       core/monitor/tests/test_monitor_memory.cpp \
//       core/monitor/autostream_monitor_utils.cpp \
//       -lpthread -o /tmp/test_monitor_memory && /tmp/test_monitor_memory
// =============================================================================

#include "autostream_monitor_utils.h"

#include <cstdio>
#include <string>

// ---------------------------------------------------------------------------
// Minimal assertion harness (same shape as test_monitor_utils.cpp)
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
// format_memory_line: exact wording, with and without a reason
// ---------------------------------------------------------------------------

static MemorySnapshot fixed_snapshot()
{
    MemorySnapshot m;
    m.rss_kib           = 102400;              // 100 MiB
    m.hwm_kib            = 204800;              // 200 MiB
    m.lck_kib            = 51200;               // 50 MiB
    m.mem_available_kib  = 1048576;             // 1024 MiB
    m.swap_used_kib      = 2048;                // 2 MiB
    m.heap_inuse_bytes   = 10ul * 1024 * 1024;  // 10 MiB
    m.heap_held_bytes    = 20ul * 1024 * 1024;  // 20 MiB
    m.malloc_arenas      = 3;
    return m;
}

static void test_format_memory_line_without_reason()
{
    MemorySnapshot m = fixed_snapshot();
    // arena_chunks=5, arena_spare=2, arena_target=10, chunk_bytes=16 MiB ->
    // arena MiB = (5+2)*16 = 112.
    std::string line = format_memory_line(m, /*arena_chunks=*/5, /*arena_spare=*/2,
                                           /*arena_target=*/10, /*chunk_bytes=*/16ul * 1024 * 1024,
                                           /*capturing_inputs=*/1, /*reason=*/nullptr);

    std::string expected =
        "[monitor] memory: rss 100 MiB (peak 200, locked 50), "
        "heap in-use 10 MiB held 20 MiB arenas 3, "
        "repeat arena 5+2/10 chunks (112 MiB), capturing 1, "
        "system available 1024 MiB, swap used 2 MiB";
    CHECK(line == expected, "format_memory_line() matches exact wording with no reason");
}

static void test_format_memory_line_with_reason()
{
    MemorySnapshot m = fixed_snapshot();
    std::string line = format_memory_line(m, 5, 2, 10, 16ul * 1024 * 1024,
                                           1, "capture session ended");

    std::string expected =
        "[monitor] memory: rss 100 MiB (peak 200, locked 50), "
        "heap in-use 10 MiB held 20 MiB arenas 3, "
        "repeat arena 5+2/10 chunks (112 MiB), capturing 1, "
        "system available 1024 MiB, swap used 2 MiB - capture session ended";
    CHECK(line == expected, "format_memory_line() appends ' - <reason>' verbatim");
}

static void test_format_memory_line_empty_reason_same_as_null()
{
    MemorySnapshot m = fixed_snapshot();
    std::string with_null  = format_memory_line(m, 0, 0, 0, 1, 0, nullptr);
    std::string with_empty = format_memory_line(m, 0, 0, 0, 1, 0, "");
    CHECK(with_null == with_empty, "an empty reason string produces the same line as nullptr");
}

// ---------------------------------------------------------------------------
// read_memory_snapshot: basic success contract on a real Linux host
// ---------------------------------------------------------------------------

static void test_read_memory_snapshot_succeeds()
{
    MemorySnapshot m;
    bool ok = read_memory_snapshot(m);
    CHECK(ok, "read_memory_snapshot() succeeds on a Linux host with /proc mounted");
    CHECK(m.rss_kib > 0, "rss_kib is positive for the running test process");
    CHECK(m.malloc_arenas >= 1, "malloc_info() reports at least one arena");
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

int main()
{
    test_format_memory_line_without_reason();
    test_format_memory_line_with_reason();
    test_format_memory_line_empty_reason_same_as_null();

    test_read_memory_snapshot_succeeds();

    if (g_failed == 0) {
        std::printf("OK  %d/%d tests passed\n", g_tests, g_tests);
        return 0;
    }
    std::fprintf(stderr, "FAIL %d/%d tests failed\n", g_failed, g_tests);
    return 1;
}
