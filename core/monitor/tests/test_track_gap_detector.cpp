// =============================================================================
// test_track_gap_detector.cpp
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Unit tests for TrackGapDetector.
//
// Semantics: update() returns true on the FIRST above-threshold block after a
// qualifying silence gap.  Never fires during silence.  Never fires on initial
// silence before any active audio has been observed.
//
// Build (on Linux, from repo root):
//   g++ -std=c++17 -O2 -I core/monitor \
//       core/monitor/tests/test_track_gap_detector.cpp \
//       -o /tmp/test_track_gap_detector && /tmp/test_track_gap_detector
// =============================================================================

// TrackGapDetector is header-only and has no external dependencies.
#include "autostream_track_gap_detector.h"

#include <cstdio>
#include <cmath>

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

// Feed N above-threshold blocks at dt seconds per block.
static void feed_above(TrackGapDetector& d, int n,
                       double start_time, double dt, double required_gap,
                       int* fires_out = nullptr)
{
    int fires = 0;
    for (int i = 0; i < n; ++i)
        if (d.update(true, true, start_time + i * dt, required_gap))
            ++fires;
    if (fires_out) *fires_out = fires;
}

// Feed N below-threshold blocks at dt seconds per block.
static void feed_below(TrackGapDetector& d, int n,
                       double start_time, double dt, double required_gap,
                       int* fires_out = nullptr)
{
    int fires = 0;
    for (int i = 0; i < n; ++i)
        if (d.update(true, false, start_time + i * dt, required_gap))
            ++fires;
    if (fires_out) *fires_out = fires;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

static void test_no_fire_when_not_capturing()
{
    TrackGapDetector d;
    // Neither above nor below threshold while not capturing should fire.
    for (int i = 0; i < 100; ++i)
        CHECK(!d.update(false, (i % 2 == 0), i * 0.1, 1.0), "no fire when not capturing");
}

static void test_no_fire_for_initial_silence_before_active_audio()
{
    TrackGapDetector d;
    // Silence from the start, never any above-threshold audio.
    // Even after a very long gap, the detector must not fire when audio finally arrives.
    feed_below(d, 50, 0.0, 0.1, 1.25);  // 5 s of silence
    // First above-threshold block: should NOT fire because no prior audio was seen.
    bool fired = d.update(true, true, 5.0, 1.25);
    CHECK(!fired, "no fire on first-ever audio after initial silence");
}

static void test_no_fire_while_above_threshold()
{
    TrackGapDetector d;
    // Continuous audio above threshold — no gap, never fires.
    int fires = 0;
    feed_above(d, 100, 0.0, 0.1, 1.25, &fires);
    CHECK(fires == 0, "no fire while always above threshold");
}

static void test_no_fire_if_silence_too_short()
{
    TrackGapDetector d;
    // Establish active audio.
    feed_above(d, 5, 0.0, 0.1, 1.25);
    // 0.5 s of silence — below the 1.25 s required gap.
    feed_below(d, 5, 0.5, 0.1, 1.25);
    // Audio resumes: gap was only 0.5 s, should not fire.
    bool fired = d.update(true, true, 1.0, 1.25);
    CHECK(!fired, "no fire when silence < required_gap");
}

static void test_fires_on_audio_resumption_after_qualifying_gap()
{
    TrackGapDetector d;
    // Active audio phase.
    feed_above(d, 5, 0.0, 0.1, 1.25);
    // 2 s of silence (qualifies at ≥ 1.25 s).
    feed_below(d, 20, 0.5, 0.1, 1.25);
    // Audio resumes — this block should fire.
    bool fired = d.update(true, true, 2.5, 1.25);
    CHECK(fired, "fires when audio resumes after qualifying gap");
}

static void test_fires_exactly_once_per_gap()
{
    TrackGapDetector d;
    feed_above(d, 5, 0.0, 0.1, 1.25);
    feed_below(d, 20, 0.5, 0.1, 1.25);

    // First above-threshold block after gap — fires.
    int fires = 0;
    for (int i = 0; i < 10; ++i)
        if (d.update(true, true, 2.5 + i * 0.1, 1.25))
            ++fires;
    CHECK(fires == 1, "fires exactly once when audio resumes after gap");
}

static void test_fires_again_after_second_gap()
{
    TrackGapDetector d;
    // Gap 1
    feed_above(d, 5, 0.0, 0.1, 1.25);
    feed_below(d, 20, 0.5, 0.1, 1.25);
    bool f1 = d.update(true, true, 2.5, 1.25);
    CHECK(f1, "gap 1 fires");

    // Audio continues.
    feed_above(d, 5, 2.6, 0.1, 1.25);

    // Gap 2
    feed_below(d, 20, 3.1, 0.1, 1.25);
    bool f2 = d.update(true, true, 5.1, 1.25);
    CHECK(f2, "gap 2 fires");
}

static void test_no_fire_during_silence()
{
    TrackGapDetector d;
    feed_above(d, 5, 0.0, 0.1, 1.25);
    // Feed silence; it qualifies (> 1.25 s) but update() must return false throughout.
    int fires = 0;
    feed_below(d, 50, 0.5, 0.1, 1.25, &fires);
    CHECK(fires == 0, "no fire while audio remains below threshold");
}

static void test_reset_clears_seen_audio_and_candidate()
{
    TrackGapDetector d;
    // Establish active audio and start a gap.
    feed_above(d, 5, 0.0, 0.1, 1.25);
    feed_below(d, 20, 0.5, 0.1, 1.25);  // qualifying gap

    d.reset();

    // After reset: no seen-audio, no candidate.
    // Audio resumes — should NOT fire because seen_audio was cleared.
    bool fired = d.update(true, true, 2.5, 1.25);
    CHECK(!fired, "no fire after reset — seen_audio cleared");
}

static void test_capture_stop_clears_candidate()
{
    TrackGapDetector d;
    feed_above(d, 5, 0.0, 0.1, 1.25);
    feed_below(d, 20, 0.5, 0.1, 1.25);  // qualifying gap

    // Capture stops.
    d.update(false, false, 2.5, 1.25);  // reset() called internally

    // Capture restarts; audio resumes immediately — no fire because state was reset.
    bool fired = d.update(true, true, 3.0, 1.25);
    CHECK(!fired, "no fire on audio after capture stop clears candidate");
}

static void test_last_gap_seconds_populated()
{
    TrackGapDetector d;
    feed_above(d, 5, 0.0, 0.1, 1.25);
    // 2 s silence starting at t=0.5
    feed_below(d, 20, 0.5, 0.1, 1.25);
    // Audio resumes at t=2.5 → gap = 2.5 - 0.5 = 2.0 s
    bool fired = d.update(true, true, 2.5, 1.25);
    CHECK(fired, "fired");
    // Allow up to 10% error for floating-point dt accumulation.
    double gap = d.last_gap_seconds();
    CHECK(gap >= 1.9 && gap <= 2.1, "last_gap_seconds approx 2.0");
}

static void test_required_gap_respected_when_changed()
{
    TrackGapDetector d;
    feed_above(d, 5, 0.0, 0.1, 2.0);
    // 1.5 s of silence, required_gap = 2.0 — candidate active but not qualifying yet.
    feed_below(d, 15, 0.5, 0.1, 2.0);
    // Change required_gap to 1.0 s on the next below-threshold block.
    // Elapsed = 1.5 s ≥ 1.0 s → candidate becomes qualifying this block.
    d.update(true, false, 2.0, 1.0);
    // Audio resumes: should fire (gap is now qualifying under new threshold).
    bool fired = d.update(true, true, 2.1, 1.0);
    CHECK(fired, "fires when required_gap shrinks to meet elapsed silence");
}

static void test_wrap_detection_fires()
{
    // Simulate the capture-stop reset (which resets seq to 0) and verify the
    // detector fires correctly after a fresh start.
    TrackGapDetector d;
    feed_above(d, 5, 0.0, 0.1, 1.25);
    feed_below(d, 20, 0.5, 0.1, 1.25);
    bool fired = d.update(true, true, 2.5, 1.25);
    CHECK(fired, "fired after qualifying gap from fresh start");
}

static void test_clear_candidate_discards_partial_gap()
{
    // Establish audio and start a gap that would qualify under the old threshold.
    TrackGapDetector d;
    feed_above(d, 5, 0.0, 0.1, 1.25);
    // 1.5 s of silence — qualifies under threshold 1.25 s.
    feed_below(d, 15, 0.5, 0.1, 1.25);

    // clear_candidate() discards the gap state without clearing _seen_audio.
    d.clear_candidate();

    // Audio resumes: must NOT fire because the candidate was cleared.
    bool fired = d.update(true, true, 2.0, 1.25);
    CHECK(!fired, "clear_candidate discards qualifying gap — no fire on resume");
}

static void test_clear_candidate_preserves_seen_audio()
{
    // After clear_candidate(), new gaps are still detected (seen_audio preserved).
    TrackGapDetector d;
    feed_above(d, 5, 0.0, 0.1, 1.25);
    feed_below(d, 20, 0.5, 0.1, 1.25);  // qualifying gap
    d.clear_candidate();

    // Audio resumes — no fire (candidate cleared).
    d.update(true, true, 2.5, 1.25);

    // New gap after the resumed audio.
    feed_below(d, 20, 2.6, 0.1, 1.25);
    bool fired = d.update(true, true, 4.6, 1.25);
    CHECK(fired, "clear_candidate preserves seen_audio — new gap fires correctly");
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main()
{
    test_no_fire_when_not_capturing();
    test_no_fire_for_initial_silence_before_active_audio();
    test_no_fire_while_above_threshold();
    test_no_fire_if_silence_too_short();
    test_fires_on_audio_resumption_after_qualifying_gap();
    test_fires_exactly_once_per_gap();
    test_fires_again_after_second_gap();
    test_no_fire_during_silence();
    test_reset_clears_seen_audio_and_candidate();
    test_capture_stop_clears_candidate();
    test_last_gap_seconds_populated();
    test_required_gap_respected_when_changed();
    test_wrap_detection_fires();
    test_clear_candidate_discards_partial_gap();
    test_clear_candidate_preserves_seen_audio();

    std::fprintf(stdout, "%s — %d/%d tests passed\n",
                 g_failed ? "FAIL" : "PASS",
                 g_tests - g_failed, g_tests);
    return g_failed ? 1 : 0;
}
