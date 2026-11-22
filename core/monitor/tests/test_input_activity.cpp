// =============================================================================
// test_input_activity.cpp
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Unit tests for the input-type rules and the activity gate in
// autostream_input_activity.h.
//
// Build (on Linux, from repo root):
//   g++ -std=c++17 -O2 -I core/monitor core/monitor/tests/test_input_activity.cpp
//       -o /tmp/test_input_activity && /tmp/test_input_activity
// =============================================================================

// Header-only, no external dependencies.
#include "autostream_input_activity.h"

#include <cmath>
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

// Feeds one block with a fixed level, all of it signal, for the tests that
// only count time.
static bool feed(ActivityGate& gate, double now, double block_seconds)
{
    ActivityGateReport r;
    return gate.on_block(now, block_seconds, block_seconds, 0.5f, 0.01, r);
}

// Feeds one block of which only signal_seconds counted as signal.
static bool feed_signal(ActivityGate& gate, double now, double block_seconds, double signal_seconds)
{
    ActivityGateReport r;
    return gate.on_block(now, block_seconds, signal_seconds, 0.5f, 0.01, r);
}

static bool near(double a, double b)
{
    return std::fabs(a - b) < 1e-9;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

static void test_named_turntable_gets_long_window()
{
    CHECK(!input_type_immediate_interrupt("turntable"), "turntable gets the long window");
}

static void test_named_cd_and_line_get_short_window()
{
    CHECK(input_type_immediate_interrupt("cd"), "cd gets the short window");
    CHECK(input_type_immediate_interrupt("line"), "line gets the short window");
}

static void test_unknown_type_is_short()
{
    CHECK(input_type_immediate_interrupt("tape"), "an unknown type is treated as not a turntable");
}

static void test_empty_type_is_line()
{
    CHECK(input_type_immediate_interrupt(""), "no type behaves as line: short window");
}

static void test_one_block_does_not_fire()
{
    ActivityGate gate;
    CHECK(!feed(gate,1.0, 0.021), "a single block is not enough");
}

static void test_three_consecutive_blocks_fire_on_third()
{
    ActivityGate gate;
    CHECK(!feed(gate,1.000, 0.021), "first block: 21 ms");
    CHECK(!feed(gate,1.021, 0.021), "second block: 42 ms");
    CHECK(feed(gate,1.042, 0.021), "third block: 63 ms completes it");
}

static void test_spread_blocks_within_a_second_fire()
{
    ActivityGate gate;
    CHECK(!feed(gate,1.0, 0.021), "first block");
    CHECK(!feed(gate,1.4, 0.021), "second block, not consecutive");
    CHECK(feed(gate,1.9, 0.021), "third block, still inside one second");
}

static void test_window_restarts_after_a_second()
{
    ActivityGate gate;
    CHECK(!feed(gate,1.0, 0.021), "opens the window");
    CHECK(!feed(gate,1.6, 0.021), "second block");
    CHECK(!feed(gate,2.2, 0.021), "1.2 s after the anchor: window restarts");
    CHECK(!feed(gate,2.4, 0.021), "second block of the new window");
    CHECK(feed(gate,2.6, 0.021), "third block of the new window fires");
}

static void test_large_block_then_small_fires_on_second()
{
    ActivityGate gate;
    CHECK(!feed(gate,1.0, 0.046), "a 46 ms block alone is short");
    CHECK(feed(gate,1.046, 0.021), "67 ms in total fires");
}

static void test_fires_then_starts_over()
{
    ActivityGate gate;
    feed(gate,1.000, 0.021);
    feed(gate,1.021, 0.021);
    CHECK(feed(gate,1.042, 0.021), "fires on the third block");
    CHECK(!feed(gate,1.063, 0.021), "a single block after a fire starts over");
}

static void test_reset_discards_partial_total()
{
    ActivityGate gate;
    feed(gate,1.000, 0.021);
    feed(gate,1.021, 0.021);
    gate.reset();
    CHECK(!feed(gate,1.042, 0.021), "total was discarded by reset()");
}

static void test_slow_click_train_never_fires()
{
    ActivityGate gate;
    for (int i = 0; i < 6; ++i)
        CHECK(!feed(gate,1.0 + 1.5 * i, 0.021),
              "one block every 1.5 s never fires");
}

static void test_exactly_required_seconds_fires()
{
    ActivityGate gate;
    CHECK(!feed(gate,1.0, 0.030), "30 ms is short");
    CHECK(feed(gate,1.1, 0.030), "exactly 60 ms in total fires");
}

static void test_block_exactly_one_second_later_counts()
{
    ActivityGate gate;
    CHECK(!feed(gate,1.0, 0.030), "opens the window");
    CHECK(feed(gate,2.0, 0.030), "a block exactly one second on is still counted");
}

static void test_block_just_past_one_second_restarts()
{
    ActivityGate gate;
    CHECK(!feed(gate,1.0, 0.030), "opens the window");
    CHECK(!feed(gate,2.0001, 0.030), "a block just past one second restarts the count");
}

static void test_single_long_block_fires_alone()
{
    ActivityGate gate;
    CHECK(feed(gate,1.0, 0.064), "one block of 60 ms or more fires by itself");
}

static void test_start_after_constants()
{
    CHECK(kStartAfterMinMs == 30, "the shortest Start after is 30 ms");
    CHECK(kStartAfterMaxMs == 250, "the longest Start after is 250 ms");
    CHECK(kStartAfterDefaultMs == 60, "the default Start after is 60 ms");
    ActivityGate gate;
    CHECK(near(gate.required_seconds(), 0.060), "a new gate needs the default 60 ms");
}

static void test_shortest_setting_fires_on_second_block()
{
    ActivityGate gate;
    gate.set_required_seconds(0.030);
    CHECK(!feed(gate, 1.000, 0.021), "21 ms is short of 30 ms");
    CHECK(feed(gate, 1.021, 0.021), "42 ms reaches 30 ms");
}

static void test_longest_setting_fires_on_twelfth_block()
{
    ActivityGate gate;
    gate.set_required_seconds(0.250);
    for (int i = 0; i < 11; ++i)
        CHECK(!feed(gate, 1.0 + 0.021 * i, 0.021), "under 250 ms does not fire");
    CHECK(feed(gate, 1.0 + 0.021 * 11, 0.021), "the twelfth block (252 ms) fires");
}

static void test_setting_change_discards_partial_total()
{
    ActivityGate gate;
    feed(gate, 1.000, 0.021);
    feed(gate, 1.021, 0.021);
    gate.set_required_seconds(0.060);
    CHECK(!feed(gate, 1.042, 0.021), "a new requirement starts the count again");
}

static void test_fire_reports_what_it_counted()
{
    ActivityGate gate;
    ActivityGateReport r;
    CHECK(!gate.on_block(1.000, 0.021, 0.021, 0.25f, 0.010, r), "first block");
    CHECK(!gate.on_block(1.021, 0.021, 0.021, 0.50f, 0.040, r), "second block");
    CHECK(gate.on_block(1.100, 0.021, 0.021, 0.10f, 0.004, r), "third block fires");
    CHECK(r.blocks == 3, "three blocks counted");
    CHECK(near(r.above_seconds, 0.063), "63 ms above the threshold");
    CHECK(near(r.block_seconds, 0.063), "in 63 ms of blocks");
    CHECK(near(r.span_seconds, 0.121), "the window spans from the start of its first block");
    CHECK(r.peak == 0.50f, "the highest block peak");
    CHECK(near(r.mean_square, 0.018), "mean power weighted by block time");
}

static void test_expire_waits_for_the_window()
{
    ActivityGate gate;
    ActivityGateReport r;
    CHECK(!gate.expire(1.0, r), "nothing open, nothing to report");
    gate.on_block(1.000, 0.021, 0.021, 0.30f, 0.020, r);
    CHECK(!gate.expire(1.5, r), "the window is still open half a second on");
    CHECK(!gate.expire(2.0, r), "exactly one second on is still inside the window");
}

static void test_expire_reports_an_unfinished_window_once()
{
    ActivityGate gate;
    ActivityGateReport r;
    gate.on_block(1.000, 0.021, 0.021, 0.30f, 0.020, r);
    gate.on_block(1.400, 0.021, 0.021, 0.40f, 0.040, r);
    CHECK(gate.expire(2.01, r), "an unfinished window is reported after a second");
    CHECK(r.blocks == 2, "two blocks counted");
    CHECK(near(r.above_seconds, 0.042), "42 ms above the threshold");
    CHECK(near(r.span_seconds, 0.421), "span to the end of the last counted block");
    CHECK(r.peak == 0.40f, "the highest block peak");
    CHECK(near(r.mean_square, 0.030), "mean power of the counted blocks");
    CHECK(!gate.expire(3.5, r), "it is reported only once");
    CHECK(!feed(gate, 3.6, 0.021), "the next block starts a fresh count");
}

static void test_expire_after_a_fire_or_reset_reports_nothing()
{
    ActivityGate gate;
    ActivityGateReport r;
    feed(gate, 1.000, 0.021);
    feed(gate, 1.021, 0.021);
    CHECK(feed(gate, 1.042, 0.021), "fires");
    CHECK(!gate.expire(5.0, r), "a window that fired is not reported again");
    feed(gate, 6.0, 0.021);
    gate.reset();
    CHECK(!gate.expire(8.0, r), "a reset window is not reported");
}

static void test_counts_signal_time_not_block_time()
{
    ActivityGate gate;
    ActivityGateReport r;
    CHECK(!gate.on_block(1.000, 0.046, 0.012, 0.3f, 0.010, r), "12 ms of signal in a 46 ms block");
    CHECK(gate.expire(2.01, r), "the window runs out");
    CHECK(near(r.above_seconds, 0.012), "only the signal is counted");
    CHECK(near(r.block_seconds, 0.046), "the block length is kept for the mean power");
}

static void test_a_spike_straddling_two_blocks_does_not_fire()
{
    for (double required : {0.060, 0.030})
    {
        ActivityGate gate;
        gate.set_required_seconds(required);
        CHECK(!feed_signal(gate, 1.000, 0.046, 0.012), "the spike's start ends one block");
        CHECK(!feed_signal(gate, 1.046, 0.046, 0.010), "and its tail starts the next: 22 ms");
    }
}

static void test_blocks_full_of_signal_fire_as_before()
{
    ActivityGate gate;
    CHECK(!feed_signal(gate, 1.000, 0.0213, 0.0213), "21 ms");
    CHECK(!feed_signal(gate, 1.0213, 0.0213, 0.0213), "43 ms");
    CHECK(feed_signal(gate, 1.0426, 0.0213, 0.0213), "64 ms fires on the third block");
}

static void test_mean_power_is_weighted_by_block_time()
{
    ActivityGate gate;
    ActivityGateReport r;
    gate.on_block(1.000, 0.010, 0.005, 0.3f, 0.010, r);
    gate.on_block(1.100, 0.030, 0.005, 0.3f, 0.050, r);
    CHECK(gate.expire(2.01, r), "the window runs out");
    CHECK(near(r.mean_square, (0.010 * 0.010 + 0.050 * 0.030) / 0.040), "weighted by block length");
}

static void test_signal_time_converts_frames()
{
    SignalCount c;
    c.frames   = 441;
    c.trailing = 100;
    c.gap      = true;
    SignalTime t = signal_time(c, 44100);
    CHECK(near(t.seconds, 0.010), "441 frames at 44.1 kHz is 10 ms");
    CHECK(near(t.trailing_seconds, 100.0 / 44100.0), "trailing frames converted");
    CHECK(t.gap, "the gap is carried");
    SignalTime none = signal_time(c, 0);
    CHECK(none.seconds == 0.0 && !none.gap, "no rate, no time");
}

// ---------------------------------------------------------------------------
// SignalRunTracker
// ---------------------------------------------------------------------------

static SignalTime run(double seconds, double trailing, bool gap)
{
    SignalTime t;
    t.seconds          = seconds;
    t.trailing_seconds = trailing;
    t.gap              = gap;
    return t;
}

static void test_run_adds_signal_without_a_gap()
{
    SignalRunTracker t(0.25);
    CHECK(!t.on_block(run(0.1, 0.1, false)), "0.1 s");
    CHECK(!t.on_block(run(0.1, 0.1, false)), "0.2 s");
    CHECK(near(t.run_seconds(), 0.2), "the run adds up");
}

static void test_a_gap_restarts_from_the_trailing_signal()
{
    SignalRunTracker t(0.25);
    t.on_block(run(0.2, 0.2, false));
    CHECK(!t.on_block(run(0.03, 0.01, true)), "a gap inside the block");
    CHECK(near(t.run_seconds(), 0.01), "the run restarts from the signal ending the block");
}

static void test_confirms_once_at_the_window()
{
    SignalRunTracker t(0.25);
    CHECK(!t.on_block(run(0.24, 0.24, false)), "0.24 s of 0.25 s");
    CHECK(t.on_block(run(0.01, 0.01, false)), "reaching 0.25 s confirms");
    CHECK(!t.on_block(run(0.02, 0.02, false)), "and does not confirm again");
}

static void test_a_block_after_a_stall_adds_only_its_own_signal()
{
    SignalRunTracker t(0.25);
    // The power-down blip arrives after a long stall: 22 ms, then the hold runs out.
    CHECK(!t.on_block(run(0.022, 0.0, true)), "one blip never confirms");
    CHECK(near(t.run_seconds(), 0.0), "and leaves no run behind");
    CHECK(!t.on_block(run(0.022, 0.022, false)), "a blip at the end of a block");
    CHECK(near(t.run_seconds(), 0.022), "counts only itself");
}

static void test_reset_switches_the_window_and_clears_the_run()
{
    SignalRunTracker t(1.25);
    t.on_block(run(1.0, 1.0, false));
    t.reset(0.25);
    CHECK(near(t.sustain_seconds(), 0.25), "the new window");
    CHECK(near(t.run_seconds(), 0.0), "an empty run");
    CHECK(!t.on_block(run(0.24, 0.24, false)), "the old run does not count");
    CHECK(t.on_block(run(0.01, 0.01, false)), "a fresh 0.25 s confirms");
}

static void test_a_pop_every_other_block_never_confirms()
{
    SignalRunTracker t(0.25);
    bool confirmed = false;
    for (int i = 0; i < 100; ++i)
        confirmed = t.on_block(i % 2 ? run(0.0, 0.0, true) : run(0.022, 0.022, true)) || confirmed;
    CHECK(!confirmed, "pops broken by quiet blocks never make a run");
}

int main()
{
    test_named_turntable_gets_long_window();
    test_named_cd_and_line_get_short_window();
    test_unknown_type_is_short();
    test_empty_type_is_line();
    test_one_block_does_not_fire();
    test_three_consecutive_blocks_fire_on_third();
    test_spread_blocks_within_a_second_fire();
    test_window_restarts_after_a_second();
    test_large_block_then_small_fires_on_second();
    test_fires_then_starts_over();
    test_reset_discards_partial_total();
    test_slow_click_train_never_fires();
    test_exactly_required_seconds_fires();
    test_block_exactly_one_second_later_counts();
    test_block_just_past_one_second_restarts();
    test_single_long_block_fires_alone();
    test_start_after_constants();
    test_shortest_setting_fires_on_second_block();
    test_longest_setting_fires_on_twelfth_block();
    test_setting_change_discards_partial_total();
    test_fire_reports_what_it_counted();
    test_expire_waits_for_the_window();
    test_expire_reports_an_unfinished_window_once();
    test_expire_after_a_fire_or_reset_reports_nothing();
    test_counts_signal_time_not_block_time();
    test_a_spike_straddling_two_blocks_does_not_fire();
    test_blocks_full_of_signal_fire_as_before();
    test_mean_power_is_weighted_by_block_time();
    test_signal_time_converts_frames();
    test_run_adds_signal_without_a_gap();
    test_a_gap_restarts_from_the_trailing_signal();
    test_confirms_once_at_the_window();
    test_a_block_after_a_stall_adds_only_its_own_signal();
    test_reset_switches_the_window_and_clears_the_run();
    test_a_pop_every_other_block_never_confirms();

    std::fprintf(stdout, "%s — %d/%d tests passed\n",
                 g_failed ? "FAIL" : "PASS",
                 g_tests - g_failed, g_tests);
    return g_failed ? 1 : 0;
}
