// =============================================================================
// test_output_stage.cpp
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Header-only unit tests for OutputMixer (autostream_output_stage.h). Does
// not touch OutputStage itself, which links ALSA and libsamplerate -- these
// tests build and run against the mixer alone, with no such dependency.
//
// Build (on Linux, from repo root):
//   g++ -std=c++17 -O2 -Wall -Wextra -I core/monitor
//       core/monitor/tests/test_output_stage.cpp
//       -o /tmp/test_output_stage && /tmp/test_output_stage
// =============================================================================

#include "autostream_output_stage.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <vector>

// ---------------------------------------------------------------------------
// Minimal assertion harness (same shape as test_monitor_memory.cpp)
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

namespace
{
    constexpr int    kRate        = 48000;
    constexpr size_t kBlockFrames = 960;   // 20 ms at 48 kHz
}

// ---------------------------------------------------------------------------
// (1) One active source at gain 1: pass-through is byte-exact.
// ---------------------------------------------------------------------------

static void test_pass_through_gain_one()
{
    OutputMixer mixer(kRate, kBlockFrames);
    mixer.activate(OutputSource::Live1, 1.0f, 0.0);   // ramp 0 -> gain jumps to 1 immediately

    std::vector<float> in(kBlockFrames * 2);
    for (size_t i = 0; i < in.size(); ++i)
        in[i] = static_cast<float>(i % 200) / 400.0f - 0.25f;   // an arbitrary, non-trivial pattern

    size_t accepted = mixer.push(OutputSource::Live1, in.data(), kBlockFrames);
    CHECK(accepted == kBlockFrames, "push() accepts a full block into an empty ring");

    std::vector<float> out(kBlockFrames * 2, -1.0f);
    mixer.mix_block(out.data());

    CHECK(std::memcmp(out.data(), in.data(), in.size() * sizeof(float)) == 0,
          "a single active source at gain 1 passes samples through byte-exact");
}

// ---------------------------------------------------------------------------
// (2) An inactive source: push() is rejected, and it contributes nothing.
// ---------------------------------------------------------------------------

static void test_inactive_source_push_rejected()
{
    OutputMixer mixer(kRate, kBlockFrames);

    std::vector<float> in(kBlockFrames * 2, 0.7f);
    size_t accepted = mixer.push(OutputSource::Live2, in.data(), kBlockFrames);
    CHECK(accepted == 0, "push() returns 0 for a source that has never been activated");
    CHECK(mixer.available(OutputSource::Live2) == 0,
          "a rejected push leaves the inactive source's ring empty");

    // Activate a different source so mix_block() has something to do, and
    // confirm the still-inactive one adds nothing.
    mixer.activate(OutputSource::Live1, 1.0f, 0.0);
    std::vector<float> live1_in(kBlockFrames * 2, 0.3f);
    mixer.push(OutputSource::Live1, live1_in.data(), kBlockFrames);

    std::vector<float> out(kBlockFrames * 2, -1.0f);
    mixer.mix_block(out.data());

    bool all_from_live1 = std::all_of(out.begin(), out.end(),
                                       [](float v) { return v == 0.3f; });
    CHECK(all_from_live1, "an inactive source contributes nothing even if a push into it was attempted");
}

// ---------------------------------------------------------------------------
// (3) A 1.5 s crossfade between two sources.
// ---------------------------------------------------------------------------

static constexpr double kCrossfadeSeconds = 1.5;
static const size_t     kCrossfadeFrames  = static_cast<size_t>(kCrossfadeSeconds * kRate);   // 72000
static const size_t     kCrossfadeBlocks  = kCrossfadeFrames / kBlockFrames;                   // 75
static const size_t     kMiddleBlock      = kCrossfadeBlocks / 2;                              // 37

// A ramping down from full gain to silence, and B ramping up from silence
// to full gain, fed with equal constant input: the sum must stay constant
// on every single frame of every block.
static void test_crossfade_sum_stays_constant_and_final_state()
{
    OutputMixer mixer(kRate, kBlockFrames);

    mixer.activate(OutputSource::Live1, 1.0f, 0.0);                  // A: full gain immediately
    mixer.activate(OutputSource::Live2, 0.0f, kCrossfadeSeconds);    // B: starts at 0, superseded below
    mixer.set_gain(OutputSource::Live2, 1.0f, kCrossfadeSeconds);    // B ramps 0 -> 1
    mixer.set_gain(OutputSource::Live1, 0.0f, kCrossfadeSeconds);    // A ramps 1 -> 0, same window

    std::vector<float> block_in(kBlockFrames * 2, 0.5f);
    std::vector<float> out(kBlockFrames * 2);

    for (size_t b = 0; b < kCrossfadeBlocks; ++b)
    {
        mixer.push(OutputSource::Live1, block_in.data(), kBlockFrames);
        mixer.push(OutputSource::Live2, block_in.data(), kBlockFrames);
        mixer.mix_block(out.data());

        for (float v : out)
            CHECK(std::fabs(v - 0.5f) < 1e-4f, "the crossfade sum stays 0.5 on every frame");
    }

    CHECK(!mixer.is_active(OutputSource::Live1), "A is inactive once its 1.5 s fade-out completes");
    CHECK(mixer.gain_is_zero(OutputSource::Live1), "A reports gain_is_zero once its fade-out completes");
    CHECK(mixer.is_active(OutputSource::Live2), "B is still active at the end of the crossfade");
}

// Isolate A's own ramp (feeding it alone) to check it is linear and that it
// ends inactive with gain_is_zero() true.
static void test_crossfade_gain_a_is_linear()
{
    OutputMixer mixer(kRate, kBlockFrames);
    mixer.activate(OutputSource::Live1, 1.0f, 0.0);
    mixer.set_gain(OutputSource::Live1, 0.0f, kCrossfadeSeconds);

    std::vector<float> in(kBlockFrames * 2, 1.0f);
    std::vector<float> out(kBlockFrames * 2);

    for (size_t b = 0; b < kCrossfadeBlocks; ++b)
    {
        mixer.push(OutputSource::Live1, in.data(), kBlockFrames);
        mixer.mix_block(out.data());

        if (b == kMiddleBlock)
        {
            float expected = 1.0f - static_cast<float>(b * kBlockFrames) / static_cast<float>(kCrossfadeFrames);
            CHECK(std::fabs(out[0] - expected) < 1e-3f, "A's gain is linear at the middle of the crossfade");
        }
    }

    CHECK(!mixer.is_active(OutputSource::Live1), "A is inactive after its fade-out completes");
    CHECK(mixer.gain_is_zero(OutputSource::Live1), "A reports gain_is_zero after its fade-out completes");
}

// Isolate B's own ramp the same way, and confirm it lands exactly on 1.0.
static void test_crossfade_gain_b_is_linear_and_reaches_one()
{
    OutputMixer mixer(kRate, kBlockFrames);
    mixer.activate(OutputSource::Live2, 0.0f, kCrossfadeSeconds);

    std::vector<float> in(kBlockFrames * 2, 1.0f);
    std::vector<float> out(kBlockFrames * 2);

    for (size_t b = 0; b < kCrossfadeBlocks; ++b)
    {
        mixer.push(OutputSource::Live2, in.data(), kBlockFrames);
        mixer.mix_block(out.data());

        if (b == kMiddleBlock)
        {
            float expected = static_cast<float>(b * kBlockFrames) / static_cast<float>(kCrossfadeFrames);
            CHECK(std::fabs(out[0] - expected) < 1e-3f, "B's gain is linear at the middle of the ramp");
        }
    }

    CHECK(mixer.is_active(OutputSource::Live2), "B is still active once it reaches its target gain");

    // The ramp's very last sample is still multiplied by the gain value
    // just short of target (multiply-then-advance, per block); the
    // persisted state only becomes exactly target once that last advance
    // is written back at the end of the block. One further block, now with
    // no ramp in flight, proves the persisted gain landed exactly on 1.0.
    mixer.push(OutputSource::Live2, in.data(), kBlockFrames);
    mixer.mix_block(out.data());
    bool steady_at_one = std::all_of(out.begin(), out.end(), [](float v) { return v == 1.0f; });
    CHECK(steady_at_one, "B's persisted gain reaches exactly 1.0 once the ramp completes");
}

// ---------------------------------------------------------------------------
// (4) Underrun padding and counters, with the two-block grace period.
// ---------------------------------------------------------------------------

static void test_underrun_padding_and_grace_period()
{
    OutputMixer mixer(kRate, kBlockFrames);
    mixer.activate(OutputSource::Live1, 1.0f, 0.0);

    const size_t half = kBlockFrames / 2;
    std::vector<float> half_block(half * 2, 0.4f);
    std::vector<float> out(kBlockFrames * 2);

    // Blocks 0 and 1 are within the grace period: a short ring must not be
    // counted as an underrun, even though it is still padded with silence.
    for (int b = 0; b < 2; ++b)
    {
        mixer.push(OutputSource::Live1, half_block.data(), half);
        mixer.mix_block(out.data());

        bool delivered_half_ok = true;
        for (size_t f = 0; f < half; ++f)
            if (out[f * 2] != 0.4f || out[f * 2 + 1] != 0.4f) delivered_half_ok = false;
        CHECK(delivered_half_ok, "the delivered half of a short block passes through unchanged");

        bool padded_half_ok = true;
        for (size_t f = half; f < kBlockFrames; ++f)
            if (out[f * 2] != 0.0f || out[f * 2 + 1] != 0.0f) padded_half_ok = false;
        CHECK(padded_half_ok, "the missing half of a short block is padded with silence");

        OutputMixer::Counters c = mixer.counters();
        CHECK(c.underrun_frames[static_cast<size_t>(OutputSource::Live1)] == 0,
              "a short ring within the first two blocks after activate() is not counted as an underrun");
    }

    // Block 2 is past the grace period: the same shortfall now counts.
    mixer.push(OutputSource::Live1, half_block.data(), half);
    mixer.mix_block(out.data());

    OutputMixer::Counters c = mixer.counters();
    CHECK(c.underrun_frames[static_cast<size_t>(OutputSource::Live1)] == half,
          "a short ring past the grace period counts the shortfall as an underrun");
}

// ---------------------------------------------------------------------------
// (5) live_clock_source() ordering.
// ---------------------------------------------------------------------------

static void test_live_clock_source_ordering()
{
    OutputMixer mixer(kRate, kBlockFrames);

    mixer.activate(OutputSource::Live2, 1.0f, 0.0);
    CHECK(mixer.live_clock_source() == 1, "Live2 alone clocks the stage as source 1");

    mixer.activate(OutputSource::Live1, 1.0f, 0.0);
    CHECK(mixer.live_clock_source() == 0, "Live1 takes precedence over Live2 when both are active");

    mixer.deactivate(OutputSource::Live1);
    mixer.deactivate(OutputSource::Live2);
    mixer.activate(OutputSource::Replay, 1.0f, 0.0);
    CHECK(mixer.live_clock_source() == -1, "Replay alone never clocks the stage");
}

// ---------------------------------------------------------------------------
// (6) A source at gain 0 / target 0 is drained but not summed.
// ---------------------------------------------------------------------------

static void test_zero_gain_source_drained_not_summed()
{
    OutputMixer mixer(kRate, kBlockFrames);
    mixer.activate(OutputSource::Live1, 0.0f, 0.0);   // jumps straight to gain 1 (ramp 0 = immediate)
    mixer.set_gain(OutputSource::Live1, 0.0f, 0.0);   // then straight back to gain 0, target 0

    CHECK(mixer.is_active(OutputSource::Live1), "a source held at gain 0 / target 0 stays active");
    CHECK(mixer.gain_is_zero(OutputSource::Live1), "gain_is_zero() is true while gain and target are both 0");

    std::vector<float> in(kBlockFrames * 2, 0.9f);
    std::vector<float> out(kBlockFrames * 2);

    for (int b = 0; b < 3; ++b)
    {
        size_t accepted = mixer.push(OutputSource::Live1, in.data(), kBlockFrames);
        CHECK(accepted == kBlockFrames, "an active source at gain 0 still accepts pushes");

        std::fill(out.begin(), out.end(), -1.0f);
        mixer.mix_block(out.data());

        bool silent = std::all_of(out.begin(), out.end(), [](float v) { return v == 0.0f; });
        CHECK(silent, "a source at gain 0 / target 0 contributes nothing to the mix");
        CHECK(mixer.available(OutputSource::Live1) == 0,
              "the source's ring is drained every block rather than left to fill up");
    }

    CHECK(mixer.is_active(OutputSource::Live1), "the source is still active after several silent blocks");
}

// ---------------------------------------------------------------------------
// (7) Pushing beyond ring capacity drops the excess and counts it.
// ---------------------------------------------------------------------------

static void test_push_beyond_capacity_drops_and_counts()
{
    OutputMixer mixer(kRate, kBlockFrames);
    mixer.activate(OutputSource::Live1, 1.0f, 0.0);

    // The ring holds 0.5 s of frames rounded up to a power of two -- well
    // under 40000 frames at 48 kHz. Push more than that in one call,
    // without draining, to force a drop.
    const size_t huge_frames = 40000;
    std::vector<float> in(huge_frames * 2, 0.1f);

    size_t accepted = mixer.push(OutputSource::Live1, in.data(), huge_frames);
    CHECK(accepted > 0 && accepted < huge_frames, "an oversized push accepts only what the ring can hold");

    OutputMixer::Counters c = mixer.counters();
    size_t idx = static_cast<size_t>(OutputSource::Live1);
    CHECK(c.dropped_frames[idx] == huge_frames - accepted,
          "frames a push could not fit into the ring are counted as dropped");
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

int main()
{
    test_pass_through_gain_one();
    test_inactive_source_push_rejected();

    test_crossfade_sum_stays_constant_and_final_state();
    test_crossfade_gain_a_is_linear();
    test_crossfade_gain_b_is_linear_and_reaches_one();

    test_underrun_padding_and_grace_period();
    test_live_clock_source_ordering();
    test_zero_gain_source_drained_not_summed();
    test_push_beyond_capacity_drops_and_counts();

    if (g_failed == 0) {
        std::printf("OK  %d/%d tests passed\n", g_tests, g_tests);
        return 0;
    }
    std::fprintf(stderr, "FAIL %d/%d tests failed\n", g_failed, g_tests);
    return 1;
}
