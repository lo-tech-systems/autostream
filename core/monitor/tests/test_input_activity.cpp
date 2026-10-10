// =============================================================================
// test_input_activity.cpp
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Unit tests for the input-type rules and the activity gate in
// autostream_input_activity.h.
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

static void test_one_block_does_not_fire()
{
    ActivityGate gate;
    CHECK(!gate.on_block(1.0, 0.021), "a single block is not enough");
}

static void test_three_consecutive_blocks_fire_on_third()
{
    ActivityGate gate;
    CHECK(!gate.on_block(1.000, 0.021), "first block: 21 ms");
    CHECK(!gate.on_block(1.021, 0.021), "second block: 42 ms");
    CHECK(gate.on_block(1.042, 0.021), "third block: 63 ms completes it");
}

static void test_spread_blocks_within_a_second_fire()
{
    ActivityGate gate;
    CHECK(!gate.on_block(1.0, 0.021), "first block");
    CHECK(!gate.on_block(1.4, 0.021), "second block, not consecutive");
    CHECK(gate.on_block(1.9, 0.021), "third block, still inside one second");
}

static void test_window_restarts_after_a_second()
{
    ActivityGate gate;
    CHECK(!gate.on_block(1.0, 0.021), "opens the window");
    CHECK(!gate.on_block(1.6, 0.021), "second block");
    CHECK(!gate.on_block(2.2, 0.021), "1.2 s after the anchor: window restarts");
    CHECK(!gate.on_block(2.4, 0.021), "second block of the new window");
    CHECK(gate.on_block(2.6, 0.021), "third block of the new window fires");
}

static void test_large_block_then_small_fires_on_second()
{
    ActivityGate gate;
    CHECK(!gate.on_block(1.0, 0.046), "a 46 ms block alone is short");
    CHECK(gate.on_block(1.046, 0.021), "67 ms in total fires");
}

static void test_fires_then_starts_over()
{
    ActivityGate gate;
    gate.on_block(1.000, 0.021);
    gate.on_block(1.021, 0.021);
    CHECK(gate.on_block(1.042, 0.021), "fires on the third block");
    CHECK(!gate.on_block(1.063, 0.021), "a single block after a fire starts over");
}

static void test_reset_discards_partial_total()
{
    ActivityGate gate;
    gate.on_block(1.000, 0.021);
    gate.on_block(1.021, 0.021);
    gate.reset();
    CHECK(!gate.on_block(1.042, 0.021), "total was discarded by reset()");
}

static void test_gating_by_type()
{
    CHECK(!input_type_activity_gated(""), "no type: gate off");
    CHECK(!input_type_activity_gated("cd"), "cd: gate off");
    CHECK(input_type_activity_gated("turntable"), "turntable: gate on");
    CHECK(input_type_activity_gated("line"), "line: gate on");
    CHECK(input_type_activity_gated("tape"), "any other named type: gate on");
}

static void test_slow_click_train_never_fires()
{
    ActivityGate gate;
    for (int i = 0; i < 6; ++i)
        CHECK(!gate.on_block(1.0 + 1.5 * i, 0.021),
              "one block every 1.5 s never fires");
}

static void test_exactly_required_seconds_fires()
{
    ActivityGate gate;
    CHECK(!gate.on_block(1.0, 0.030), "30 ms is short");
    CHECK(gate.on_block(1.1, 0.030), "exactly 60 ms in total fires");
}

static void test_block_exactly_one_second_later_counts()
{
    ActivityGate gate;
    CHECK(!gate.on_block(1.0, 0.030), "opens the window");
    CHECK(gate.on_block(2.0, 0.030), "a block exactly one second on is still counted");
}

static void test_block_just_past_one_second_restarts()
{
    ActivityGate gate;
    CHECK(!gate.on_block(1.0, 0.030), "opens the window");
    CHECK(!gate.on_block(2.0001, 0.030), "a block just past one second restarts the count");
}

static void test_single_long_block_fires_alone()
{
    ActivityGate gate;
    CHECK(gate.on_block(1.0, 0.064), "one block of 60 ms or more fires by itself");
}

int main()
{
    test_named_turntable_gets_long_window();
    test_named_cd_and_line_get_short_window();
    test_unknown_type_is_short();
    test_empty_type_follows_boundary();
    test_one_block_does_not_fire();
    test_three_consecutive_blocks_fire_on_third();
    test_spread_blocks_within_a_second_fire();
    test_window_restarts_after_a_second();
    test_large_block_then_small_fires_on_second();
    test_fires_then_starts_over();
    test_reset_discards_partial_total();
    test_gating_by_type();
    test_slow_click_train_never_fires();
    test_exactly_required_seconds_fires();
    test_block_exactly_one_second_later_counts();
    test_block_just_past_one_second_restarts();
    test_single_long_block_fires_alone();

    std::fprintf(stdout, "%s — %d/%d tests passed\n",
                 g_failed ? "FAIL" : "PASS",
                 g_tests - g_failed, g_tests);
    return g_failed ? 1 : 0;
}
