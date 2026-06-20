// =============================================================================
// test_track_gap_detector.cpp
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Unit tests for TrackGapDetector.
//
// Build (on Linux, from repo root):
//   g++ -std=c++17 -O2 -I core/monitor \
//       core/monitor/tests/test_track_gap_detector.cpp \
//       -o /tmp/test_track_gap_detector && /tmp/test_track_gap_detector
// =============================================================================

// TrackGapDetector is header-only and has no external dependencies.
#include "autostream_track_gap_detector.h"

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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Simulate N blocks of audio at dt seconds per block.
// Returns the number of true (gap detected) returns.
static int feed(TrackGapDetector& d,
                int    n_blocks,
                bool   capturing,
                bool   above,
                double start_time,
                double dt,
                double required_gap)
{
    int fires = 0;
    for (int i = 0; i < n_blocks; ++i)
    {
        double t = start_time + i * dt;
        if (d.update(capturing, above, t, required_gap))
            ++fires;
    }
    return fires;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

static void test_no_fire_when_not_capturing()
{
    TrackGapDetector d;
    // Even a long silence below threshold while not capturing should not fire.
    int fires = feed(d, 100, /*capturing=*/false, /*above=*/false,
                     0.0, 0.1, /*required_gap=*/1.0);
    CHECK(fires == 0, "no fire when not capturing");
}

static void test_no_fire_while_above_threshold()
{
    TrackGapDetector d;
    // Continuous audio above threshold — no gap.
    int fires = feed(d, 100, true, true, 0.0, 0.1, 1.0);
    CHECK(fires == 0, "no fire while above threshold");
}

static void test_no_fire_if_silence_too_short()
{
    TrackGapDetector d;
    // First: establish "above" state.
    feed(d, 5, true, true, 0.0, 0.1, 1.25);
    // Then: 0.5 s of silence (5 × 0.1 s) — below the 1.25 s required gap.
    int fires = feed(d, 5, true, false, 0.5, 0.1, 1.25);
    CHECK(fires == 0, "no fire when silence < required_gap");
}

static void test_fires_once_when_gap_reached()
{
    TrackGapDetector d;
    // 3 s of silence in 0.1 s blocks with required_gap = 1.25 s.
    // First block at t=0.0 starts the silence timer (_timing_started = true, _silence_start = 0.0).
    // Fire should happen on the first block where t - 0.0 >= 1.25, i.e. t=1.3 (block 13).
    int fires = 0;
    bool first_fire_seen = false;
    double t = 0.0;
    for (int i = 0; i < 30; ++i, t += 0.1)
    {
        bool fired = d.update(true, false, t, 1.25);
        if (fired)
        {
            fires++;
            if (!first_fire_seen)
            {
                first_fire_seen = true;
                CHECK(t >= 1.25, "fires at or after required_gap");
            }
        }
    }
    CHECK(fires == 1, "fires exactly once per gap");
}

static void test_fires_again_after_audio_resumes()
{
    TrackGapDetector d;
    // Gap 1: silence for 2 s → fire once.
    int f1 = feed(d, 20, true, false, 0.0, 0.1, 1.25);
    CHECK(f1 == 1, "gap 1 fires once");

    // Audio resumes for 1 s.
    feed(d, 10, true, true, 2.0, 0.1, 1.25);

    // Gap 2: another silence for 2 s → fire once more.
    int f2 = feed(d, 20, true, false, 3.0, 0.1, 1.25);
    CHECK(f2 == 1, "gap 2 fires once");
}

static void test_reset_clears_state()
{
    TrackGapDetector d;
    // Part-way through a silence run (5 × 0.1 s = 0.5 s elapsed, no fire yet).
    feed(d, 5, true, false, 0.0, 0.1, 1.25);
    d.reset();
    // After reset the timer restarts fresh; first block at t=0.5 sets silence_start=0.5.
    // Gap completes at t ≥ 0.5 + 1.25 = 1.75 s.
    int fires = 0;
    double t = 0.5;
    for (int i = 0; i < 30; ++i, t += 0.1)
        if (d.update(true, false, t, 1.25))
            ++fires;
    CHECK(fires == 1, "reset then re-fires after required_gap");
}

static void test_not_capturing_resets_gap_fired()
{
    TrackGapDetector d;
    // Trigger a gap.
    feed(d, 20, true, false, 0.0, 0.1, 1.25);
    // Capture stops — gap_fired is reset internally.
    d.update(false, false, 3.0, 1.25);
    // Capture restarts; start above threshold to clear silence timer.
    feed(d, 5, true, true, 4.0, 0.1, 1.25);
    // Another silence run — should fire again.
    int fires = feed(d, 20, true, false, 5.0, 0.1, 1.25);
    CHECK(fires == 1, "fires again after capture stop/start cycle");
}

static void test_no_double_fire_without_audio_resume()
{
    TrackGapDetector d;
    // Long silence — 10 s in 0.1 s blocks, required_gap 1.25 s.
    int fires = feed(d, 100, true, false, 0.0, 0.1, 1.25);
    CHECK(fires == 1, "no double-fire during extended silence");
}

static void test_boundary_exact_gap_duration()
{
    TrackGapDetector d;
    // Start silence at t=0.
    // Block at t=1.25 should be the first to fire (t - start == 1.25 >= 1.25).
    bool fired_at_boundary = false;
    for (int i = 0; i <= 13; ++i)
    {
        double t = i * 0.1;
        bool f = d.update(true, false, t, 1.25);
        if (i == 13)
            fired_at_boundary = f;  // t == 1.3 ≥ 1.25
    }
    CHECK(fired_at_boundary, "fires at or after exact required_gap boundary");
}

static void test_required_gap_respected_when_changed()
{
    TrackGapDetector d;
    // Silence starts; run 10 blocks at dt=0.1 (1 s total).
    // required_gap initially 2.0 s → should not fire.
    int f1 = feed(d, 10, true, false, 0.0, 0.1, 2.0);
    CHECK(f1 == 0, "no fire with long required_gap");

    // Now pass a smaller required_gap on the next block — fires immediately
    // because elapsed silence (1.0 s) >= 0.5 s.
    bool fired = d.update(true, false, 1.0, 0.5);
    CHECK(fired, "fires when required_gap shrinks to match elapsed silence");
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main()
{
    test_no_fire_when_not_capturing();
    test_no_fire_while_above_threshold();
    test_no_fire_if_silence_too_short();
    test_fires_once_when_gap_reached();
    test_fires_again_after_audio_resumes();
    test_reset_clears_state();
    test_not_capturing_resets_gap_fired();
    test_no_double_fire_without_audio_resume();
    test_boundary_exact_gap_duration();
    test_required_gap_respected_when_changed();

    std::fprintf(stdout, "%s — %d/%d tests passed\n",
                 g_failed ? "FAIL" : "PASS",
                 g_tests - g_failed, g_tests);
    return g_failed ? 1 : 0;
}
