// =============================================================================
// test_dc_blocker.cpp
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Unit tests for the detection peak in autostream_dc_blocker.h.
//
// Build (on Linux, from repo root):
//   g++ -std=c++17 -O2 -I core/monitor core/monitor/tests/test_dc_blocker.cpp
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

// ---------------------------------------------------------------------------
// Signal counting
// ---------------------------------------------------------------------------

static const float kThreshold60 = 0.001f;   // -60 dBFS

static double dbfs(double db_value)
{
    return std::pow(10.0, db_value / 20.0);
}

// Feeds the audio in kBlock-frame blocks with counting and returns each
// block's count; the peaks go to `peaks` when it is given.
static std::vector<SignalCount> feed_counting(DcBlockedPeak& p, const std::vector<int32_t>& audio,
                                              float threshold, std::vector<float>* peaks = nullptr,
                                              int block = kBlock)
{
    std::vector<SignalCount> counts;
    int frames = static_cast<int>(audio.size() / 2);
    for (int f = 0; f + block <= frames; f += block)
    {
        SignalCount c;
        float pk = p.block_peak_and_signal(audio.data() + f * 2, block, 2, kFullScale, threshold, c);
        counts.push_back(c);
        if (peaks)
            peaks->push_back(pk);
    }
    return counts;
}

static int total_frames(const std::vector<SignalCount>& counts)
{
    int n = 0;
    for (const SignalCount& c : counts)
        n += c.frames;
    return n;
}

// Frames a step of size `step` stays at or above `threshold` after the
// blocker, as the filter's own decay gives it.
static int decay_frames(double step, double threshold, int rate)
{
    double r = std::exp(-2.0 * kPi * kDcBlockerCornerHz / rate);
    return static_cast<int>(std::ceil(std::log(step / threshold) / -std::log(r)));
}

static void test_counting_leaves_the_peak_unchanged()
{
    double amp = dbfs(-62.0);
    auto audio = stereo(kRate, [&](int f) { return (f < kRate / 2 ? -0.0029 : 0.004) + sine(f, 1000.0, amp); },
                        [&](int f) { return sine(f, 100.0, 0.1); });
    DcBlockedPeak plain;
    DcBlockedPeak counting;
    plain.reset(kRate);
    counting.reset(kRate);
    auto expected = feed(plain, audio);
    std::vector<float> got;
    feed_counting(counting, audio, kThreshold60, &got);
    bool same = expected.size() == got.size();
    for (size_t i = 0; same && i < got.size(); ++i)
        same = (expected[i] == got[i]);
    CHECK(same, "counting does not change a single peak");
}

static void test_a_tone_above_the_threshold_counts_every_frame()
{
    DcBlockedPeak p;
    p.reset(kRate);
    double amp = dbfs(-20.0);
    auto audio = stereo(kRate, [&](int f) { return sine(f, 1000.0, amp); },
                        [&](int f) { return sine(f, 1000.0, amp); });
    auto counts = feed_counting(p, audio, kThreshold60);
    bool all = true;
    for (size_t i = 1; i < counts.size(); ++i)
        all = all && counts[i].frames == kBlock && counts[i].trailing == kBlock && !counts[i].gap;
    CHECK(all, "every frame of a tone well above the threshold counts");
}

static void test_a_low_tone_near_the_threshold_is_bridged()
{
    for (int rate : {44100, 48000})
    {
        DcBlockedPeak p;
        p.reset(rate);
        double amp = dbfs(-58.0);
        auto audio = stereo(rate, [&](int f) { return amp * std::sin(2.0 * kPi * 50.0 * f / rate); },
                            [](int) { return 0.0; });
        auto counts = feed_counting(p, audio, kThreshold60);
        bool all = true;
        for (size_t i = 1; i < counts.size(); ++i)
            all = all && counts[i].frames == kBlock && !counts[i].gap;
        CHECK(all, "the zero crossings of a 50 Hz tone 2 dB over the threshold are bridged");
    }
}

static void test_a_step_counts_its_decay_plus_the_hold()
{
    for (int rate : {44100, 48000})
    {
        for (double step_db : {-53.6, 0.0})
        {
            DcBlockedPeak p;
            p.reset(rate);
            double step = dbfs(step_db) * 0.999;   // stay inside full scale at 0 dBFS
            int frames = kBlock * 16;
            auto audio = stereo(frames, [&](int f) { return f < kBlock ? 0.0 : step; },
                                [](int) { return 0.0; });
            auto counts = feed_counting(p, audio, kThreshold60);
            int hold = static_cast<int>(std::lround(rate * kSignalHoldSeconds));
            int expected = decay_frames(step, kThreshold60, rate) + hold;
            int got = total_frames(counts);
            CHECK(std::abs(got - expected) <= 3, "a step counts its decay above the threshold plus the hold");
            CHECK(counts.back().frames == 0 && counts.back().gap && counts.back().trailing == 0,
                  "and nothing once the hold is spent");
        }
    }
}

static void test_the_observed_blip_counts_about_22_ms()
{
    DcBlockedPeak p;
    p.reset(44100);
    double step = dbfs(-53.6);
    auto audio = stereo(kBlock * 8, [&](int f) { return f < kBlock ? 0.0 : step; },
                        [](int) { return 0.0; });
    double ms = 1000.0 * total_frames(feed_counting(p, audio, kThreshold60)) / 44100.0;
    CHECK(ms > 20.0 && ms < 24.0, "a -53.6 dB power-down blip counts about 22 ms at -60 dB");
}

static void test_an_offset_present_from_the_start_counts_nothing()
{
    DcBlockedPeak p;
    p.reset(kRate);
    auto audio = stereo(kRate, [](int) { return -0.0029; }, [](int) { return 0.0; });
    CHECK(total_frames(feed_counting(p, audio, kThreshold60)) == 0,
          "an offset there from the first sample counts no signal");
}

static void test_trailing_is_the_run_that_ends_the_block()
{
    DcBlockedPeak p;
    p.reset(kRate);
    double amp = dbfs(-20.0);
    // 100 quiet frames then 300 of tone: the run that ends the block is 300.
    std::vector<int32_t> a = stereo(400, [&](int f) { return f < 100 ? 0.0 : sine(f, 1000.0, amp); },
                                    [](int) { return 0.0; });
    SignalCount c;
    p.block_peak_and_signal(a.data(), 400, 2, kFullScale, kThreshold60, c);
    CHECK(c.gap, "the quiet start is a gap");
    CHECK(c.frames == 300 && c.trailing == 300, "the tone is the trailing run");

    // Then a long quiet block: the hold and the decay of the tone's last
    // sample count at its start, and nothing trails it.
    std::vector<int32_t> b(static_cast<size_t>(kRate / 4) * 2, 0);
    p.block_peak_and_signal(b.data(), kRate / 4, 2, kFullScale, kThreshold60, c);
    CHECK(c.frames > 0 && c.gap && c.trailing == 0, "a quiet stretch longer than the hold ends the run");
}

static void test_the_hold_is_ten_milliseconds_at_both_rates()
{
    for (int rate : {44100, 48000})
    {
        DcBlockedPeak p;
        p.reset(rate);
        // Prime on silence, then one loud frame among silence.
        std::vector<int32_t> quiet(static_cast<size_t>(kBlock) * 2, 0);
        SignalCount c;
        p.block_peak_and_signal(quiet.data(), kBlock, 2, kFullScale, kThreshold60, c);
        std::vector<int32_t> click(static_cast<size_t>(kBlock) * 2, 0);
        click[0] = to_s32(0.5);
        p.block_peak_and_signal(click.data(), kBlock, 2, kFullScale, kThreshold60, c);
        int hold = static_cast<int>(std::lround(rate * kSignalHoldSeconds));
        // The click frame, the next frame (the filter's -0.5 swing back), its
        // tiny decaying tail (well under -60 dB within a frame or two) and the hold.
        CHECK(c.frames >= hold + 1 && c.frames <= hold + 3, "one click counts itself plus 10 ms");
    }
}

static void test_reset_and_reprime_clear_the_hold()
{
    DcBlockedPeak p;
    p.reset(kRate);
    std::vector<int32_t> quiet(static_cast<size_t>(kBlock) * 2, 0);
    std::vector<int32_t> loud(static_cast<size_t>(kBlock) * 2, 0);
    for (int f = 0; f < kBlock; ++f)
        loud[f * 2] = to_s32(sine(f, 1000.0, 0.1));
    SignalCount c;
    p.block_peak_and_signal(quiet.data(), kBlock, 2, kFullScale, kThreshold60, c);
    p.block_peak_and_signal(loud.data(), kBlock, 2, kFullScale, kThreshold60, c);
    p.reprime();
    p.block_peak_and_signal(quiet.data(), kBlock, 2, kFullScale, kThreshold60, c);
    CHECK(c.frames == 0, "after a reprime the hold does not carry into the next block");
    p.block_peak_and_signal(loud.data(), kBlock, 2, kFullScale, kThreshold60, c);
    p.reset(kRate);
    p.block_peak_and_signal(quiet.data(), kBlock, 2, kFullScale, kThreshold60, c);
    CHECK(c.frames == 0, "after a reset the hold does not carry into the next block");
}

static void test_bad_input_counts_nothing()
{
    DcBlockedPeak p;
    p.reset(kRate);
    int32_t s[6] = {1000, 1000, 1000, 1000, 1000, 1000};
    SignalCount c;
    c.frames = 7;
    CHECK(p.block_peak_and_signal(s, 0, 2, kFullScale, kThreshold60, c) == 0.0f && c.frames == 0,
          "no frames");
    CHECK(p.block_peak_and_signal(s, 2, 3, kFullScale, kThreshold60, c) == 0.0f && c.frames == 0,
          "more channels than it keeps");
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
    test_counting_leaves_the_peak_unchanged();
    test_a_tone_above_the_threshold_counts_every_frame();
    test_a_low_tone_near_the_threshold_is_bridged();
    test_a_step_counts_its_decay_plus_the_hold();
    test_the_observed_blip_counts_about_22_ms();
    test_an_offset_present_from_the_start_counts_nothing();
    test_trailing_is_the_run_that_ends_the_block();
    test_the_hold_is_ten_milliseconds_at_both_rates();
    test_reset_and_reprime_clear_the_hold();
    test_bad_input_counts_nothing();

    std::printf("%d tests, %d failed\n", g_tests, g_failed);
    return g_failed == 0 ? 0 : 1;
}
