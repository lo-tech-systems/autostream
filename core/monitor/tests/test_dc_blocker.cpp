// =============================================================================
// test_dc_blocker.cpp
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Unit tests for the detection peak in autostream_dc_blocker.h.
//
// Build (on Linux, from repo root):
//   g++ -std=c++17 -O2 -I core/monitor \
//       core/monitor/tests/test_dc_blocker.cpp \
//       -o /tmp/test_dc_blocker && /tmp/test_dc_blocker
// =============================================================================

// Header-only, no external dependencies.
#include "autostream_dc_blocker.h"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <vector>

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

static const int    kRate      = 48000;
static const int    kBlock     = 1024;
static const double kFullScale = 2147483648.0;  // 2^31
static const double kPi        = 3.14159265358979323846;

static double db(float linear)
{
    return linear > 0.0f ? 20.0 * std::log10(static_cast<double>(linear)) : -999.0;
}

static int32_t to_s32(double x)
{
    return static_cast<int32_t>(std::lround(x * (kFullScale - 1.0)));
}

// Interleaved stereo int32 audio; left and right from the two functions of
// the frame index.
template <typename L, typename R>
static std::vector<int32_t> stereo(int frames, L left, R right)
{
    std::vector<int32_t> v(static_cast<size_t>(frames) * 2);
    for (int f = 0; f < frames; ++f)
    {
        v[f * 2]     = to_s32(left(f));
        v[f * 2 + 1] = to_s32(right(f));
    }
    return v;
}

// Feeds the audio in kBlock-frame blocks and returns the peak of each.
static std::vector<float> feed(DcBlockedPeak& p, const std::vector<int32_t>& audio)
{
    std::vector<float> peaks;
    int frames = static_cast<int>(audio.size() / 2);
    for (int f = 0; f + kBlock <= frames; f += kBlock)
        peaks.push_back(p.block_peak(audio.data() + f * 2, kBlock, 2, kFullScale));
    return peaks;
}

static double sine(int f, double hz, double amp)
{
    return amp * std::sin(2.0 * kPi * hz * f / kRate);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// The case that prompted it: one channel held at about -51 dBFS while paused.
static void test_a_constant_offset_reads_as_silence()
{
    DcBlockedPeak p;
    p.reset(kRate);
    auto audio = stereo(kRate, [](int) { return -0.0029; }, [](int) { return 0.0; });
    auto peaks = feed(p, audio);
    for (float pk : peaks)
        CHECK(db(pk) < -100.0, "an offset that is there from the first sample never reads as sound");
}

static void test_noise_on_an_offset_reads_at_the_noise_level()
{
    DcBlockedPeak p;
    p.reset(kRate);
    // A small 1 kHz tone at -62 dBFS riding on a -51 dBFS offset.
    double amp = std::pow(10.0, -62.0 / 20.0);
    auto audio = stereo(kRate, [&](int f) { return -0.0029 + sine(f, 1000.0, amp); },
                        [](int) { return 0.0; });
    auto peaks = feed(p, audio);
    float last = peaks.back();
    CHECK(std::fabs(db(last) - (-62.0)) < 0.5, "the level is the tone's, not the offset's");
}

static void test_music_passes_unchanged()
{
    for (double hz : {50.0, 100.0, 1000.0, 10000.0})
    {
        DcBlockedPeak p;
        p.reset(kRate);
        double amp = std::pow(10.0, -20.0 / 20.0);
        auto audio = stereo(kRate, [&](int f) { return sine(f, hz, amp); },
                            [&](int f) { return sine(f, hz, amp); });
        auto peaks = feed(p, audio);
        double got = db(peaks.back());
        // A first-order high-pass at 10 Hz is down 0.17 dB at 50 Hz.
        CHECK(std::fabs(got - (-20.0)) < 0.25, "audible frequencies keep their level");
    }
}

static void test_an_offset_that_starts_later_settles_quickly()
{
    DcBlockedPeak p;
    p.reset(kRate);
    auto audio = stereo(kRate, [](int f) { return f < kRate / 4 ? 0.0 : -0.0029; },
                        [](int) { return 0.0; });
    auto peaks = feed(p, audio);
    // The step shows briefly at its own level, then decays (16 ms time
    // constant): well below any threshold within a quarter of a second.
    int step_block = (kRate / 4) / kBlock;
    CHECK(db(peaks[step_block]) > -55.0, "the step itself is seen");
    CHECK(db(peaks[step_block + 12]) < -90.0, "and is gone within about 250 ms");
}

static void test_reprime_hides_a_jump()
{
    DcBlockedPeak p;
    p.reset(kRate);
    auto quiet  = stereo(kBlock * 4, [](int) { return 0.0; }, [](int) { return 0.0; });
    auto offset = stereo(kBlock * 4, [](int) { return 0.01; }, [](int) { return 0.01; });
    feed(p, quiet);
    p.reprime();
    auto peaks = feed(p, offset);
    for (float pk : peaks)
        CHECK(db(pk) < -100.0, "after a reprime the new offset is not a step");
}

static void test_int16_samples_use_their_own_full_scale()
{
    DcBlockedPeak p;
    p.reset(kRate);
    std::vector<int16_t> audio(static_cast<size_t>(kBlock) * 2 * 8);
    for (int f = 0; f < kBlock * 8; ++f)
    {
        int16_t v = static_cast<int16_t>(std::lround(100.0 + sine(f, 1000.0, 3277.0)));
        audio[f * 2] = v;
        audio[f * 2 + 1] = v;
    }
    float last = 0.0f;
    for (int b = 0; b < 8; ++b)
        last = p.block_peak(audio.data() + b * kBlock * 2, kBlock, 2, 32768.0);
    CHECK(std::fabs(db(last) - (-20.0)) < 0.3, "a -20 dBFS tone on an offset reads -20 dBFS");
}

static void test_level_never_exceeds_full_scale()
{
    DcBlockedPeak p;
    p.reset(kRate);
    // Full negative to full positive in one sample after priming.
    auto audio = stereo(kBlock * 2, [](int f) { return f < kBlock ? -1.0 : 1.0; },
                        [](int) { return 0.0; });
    auto peaks = feed(p, audio);
    for (float pk : peaks)
        CHECK(pk <= 1.0f, "the level stays in [0, 1]");
}

static void test_bad_input_reads_as_silence()
{
    DcBlockedPeak p;
    p.reset(0);
    int32_t s[4] = {1000, 1000, 1000, 1000};
    CHECK(p.block_peak(s, 0, 2, kFullScale) == 0.0f, "no frames");
    CHECK(p.block_peak(s, 2, 3, kFullScale) == 0.0f, "more channels than it keeps");
}

int main()
{
    test_a_constant_offset_reads_as_silence();
    test_noise_on_an_offset_reads_at_the_noise_level();
    test_music_passes_unchanged();
    test_an_offset_that_starts_later_settles_quickly();
    test_reprime_hides_a_jump();
    test_int16_samples_use_their_own_full_scale();
    test_level_never_exceeds_full_scale();
    test_bad_input_reads_as_silence();

    std::printf("%d tests, %d failed\n", g_tests, g_failed);
    return g_failed == 0 ? 0 : 1;
}
