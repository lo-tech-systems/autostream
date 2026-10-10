// =============================================================================
// test_input_activity.cpp
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Unit tests for the input-type rules in autostream_input_activity.h.
//
// Build (on Linux, from repo root):
//   g++ -std=c++17 -O2 -I core/monitor \
//       core/monitor/tests/test_input_activity.cpp \
//       -o /tmp/test_input_activity && /tmp/test_input_activity
// =============================================================================

// Header-only, no external dependencies.
#include "autostream_input_activity.h"

#include <cstdio>

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

static const float kBoundary = -55.0f;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

static void test_named_turntable_gets_long_window()
{
    CHECK(!input_type_immediate_interrupt("turntable", -45.0f, kBoundary),
          "turntable at a turntable-level threshold gets the long window");
    CHECK(!input_type_immediate_interrupt("turntable", -60.0f, kBoundary),
          "turntable keeps the long window even at a line-level threshold");
}

static void test_named_cd_and_line_get_short_window()
{
    CHECK(input_type_immediate_interrupt("cd", -60.0f, kBoundary),
          "cd at -60 gets the short window");
    CHECK(input_type_immediate_interrupt("cd", -45.0f, kBoundary),
          "cd at -45 still gets the short window");
    CHECK(input_type_immediate_interrupt("line", -60.0f, kBoundary),
          "line at -60 gets the short window");
    CHECK(input_type_immediate_interrupt("line", -45.0f, kBoundary),
          "line at -45 still gets the short window");
}

static void test_unknown_type_is_short()
{
    CHECK(input_type_immediate_interrupt("tape", -45.0f, kBoundary),
          "an unknown type is treated as not a turntable");
}

static void test_empty_type_follows_boundary()
{
    CHECK(input_type_immediate_interrupt("", -55.0f, kBoundary),
          "no type, threshold on the boundary: short window");
    CHECK(input_type_immediate_interrupt("", -55.1f, kBoundary),
          "no type, threshold just below the boundary: short window");
    CHECK(!input_type_immediate_interrupt("", -54.9f, kBoundary),
          "no type, threshold just above the boundary: long window");
    CHECK(!input_type_immediate_interrupt("", -45.0f, kBoundary),
          "no type, turntable-level threshold: long window");
}

int main()
{
    test_named_turntable_gets_long_window();
    test_named_cd_and_line_get_short_window();
    test_unknown_type_is_short();
    test_empty_type_follows_boundary();

    std::fprintf(stdout, "%s — %d/%d tests passed\n",
                 g_failed ? "FAIL" : "PASS",
                 g_tests - g_failed, g_tests);
    return g_failed ? 1 : 0;
}
