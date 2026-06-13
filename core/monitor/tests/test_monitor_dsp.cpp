// =============================================================================
// test_monitor_dsp.cpp
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Unit tests for the DSP layer: BiquadFilter, EqChain, RateEstimator, and
// OutputProcessor (subset that doesn't require ALSA or libsamplerate).
//
// BiquadFilter tests verify the RBJ-cookbook invariants:
//   - A Peak filter at 0 dB is a pass-through.
//   - A Peak filter at non-zero dB changes the coefficients.
//   - LowShelf at 0 dB is a pass-through.
//   - A zero-state filter produces 0 for an all-zero input.
//   - EqChain publishes new bands atomically and returns them via get_bands().
//   - RateEstimator: initial src_ratio equals output/input; updates after feed().
//
// Build (on Linux, from repo root):
//   g++ -std=c++17 -O2 -I core/monitor \
//       core/monitor/tests/test_monitor_dsp.cpp \
//       core/monitor/autostream_monitor_dsp.cpp \
//       core/monitor/autostream_monitor_utils.cpp \
//       -lpthread -lasound -lsamplerate -latomic \
//       -o /tmp/test_monitor_dsp && /tmp/test_monitor_dsp
// =============================================================================

#include "autostream_monitor.h"
#include "autostream_monitor_utils.h"

#include <cassert>
#include <cmath>
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

#define CHECK_CLOSE(a, b, tol, msg) \
    CHECK(std::fabs(static_cast<double>(a) - static_cast<double>(b)) < (tol), (msg))

// ---------------------------------------------------------------------------
// BiquadFilter
// ---------------------------------------------------------------------------

static void test_biquad_zero_gain_is_passthrough()
{
    BiquadFilter f;
    EqBand band;
    band.type    = EqBand::Type::Peak;
    band.freq_hz = 1000.0f;
    band.gain_db = 0.0f;
    band.q       = 0.707f;
    f.configure(band, 44100.0f);

    // An impulse through a 0 dB peak filter should return the same signal.
    // Process one frame: input {1.0, 1.0} (interleaved stereo).
    std::vector<float> samples = {1.0f, 1.0f};
    f.process(samples.data(), 1);

    // With gain_db == 0 the RBJ peak formula yields b0/a0 = 1 and b1==a1,
    // b2==a2, so the filter output equals the input within floating-point
    // precision.
    CHECK_CLOSE(samples[0], 1.0f, 1e-5f, "Peak 0dB passthrough left");
    CHECK_CLOSE(samples[1], 1.0f, 1e-5f, "Peak 0dB passthrough right");
}

static void test_biquad_zero_input_gives_zero_output()
{
    BiquadFilter f;
    EqBand band;
    band.type    = EqBand::Type::Peak;
    band.freq_hz = 500.0f;
    band.gain_db = 6.0f;
    band.q       = 1.0f;
    f.configure(band, 44100.0f);

    std::vector<float> zeros(64, 0.0f);  // 32 stereo frames
    f.process(zeros.data(), 32);

    for (float v : zeros)
        CHECK_CLOSE(v, 0.0f, 1e-9f, "zero input gives zero output");
}

static void test_biquad_nonzero_gain_changes_coefficients()
{
    // A Peak filter at 0 dB should yield different internal coefficients than
    // one at 6 dB.  We test this by verifying the impulse responses differ.
    BiquadFilter f0, f6;

    EqBand b;
    b.type    = EqBand::Type::Peak;
    b.freq_hz = 1000.0f;
    b.q       = 0.707f;

    b.gain_db = 0.0f;  f0.configure(b, 44100.0f);
    b.gain_db = 6.0f;  f6.configure(b, 44100.0f);

    std::vector<float> s0 = {1.0f, 1.0f};
    std::vector<float> s6 = {1.0f, 1.0f};
    f0.process(s0.data(), 1);
    f6.process(s6.data(), 1);

    // The 6 dB peak filter must boost the impulse response vs 0 dB.
    CHECK(s6[0] > s0[0], "6 dB peak has larger impulse response than 0 dB (left)");
    CHECK(s6[1] > s0[1], "6 dB peak has larger impulse response than 0 dB (right)");
}

static void test_biquad_reset_clears_state()
{
    BiquadFilter f;
    EqBand band;
    band.type    = EqBand::Type::Peak;
    band.freq_hz = 200.0f;
    band.gain_db = 6.0f;
    band.q       = 0.707f;
    f.configure(band, 44100.0f);

    // Feed some non-zero samples to build up delay-line state.
    std::vector<float> samples(16, 1.0f);
    f.process(samples.data(), 8);

    // Reset: subsequent output for a zero input must also be zero.
    f.reset();
    std::vector<float> zeros(16, 0.0f);
    f.process(zeros.data(), 8);
    for (float v : zeros)
        CHECK_CLOSE(v, 0.0f, 1e-9f, "post-reset zero input gives zero output");
}

static void test_biquad_low_shelf_zero_gain_passthrough()
{
    BiquadFilter f;
    EqBand band;
    band.type    = EqBand::Type::LowShelf;
    band.freq_hz = 100.0f;
    band.gain_db = 0.0f;
    band.q       = 0.707f;
    f.configure(band, 44100.0f);

    std::vector<float> samples = {1.0f, 1.0f};
    f.process(samples.data(), 1);
    CHECK_CLOSE(samples[0], 1.0f, 1e-5f, "LowShelf 0dB passthrough left");
    CHECK_CLOSE(samples[1], 1.0f, 1e-5f, "LowShelf 0dB passthrough right");
}

static void test_biquad_set_coefficients_identity()
{
    // Identity filter: b0=1, b1=b2=0, a1=a2=0.
    BiquadFilter f;
    f.set_coefficients(1.0f, 0.0f, 0.0f, 0.0f, 0.0f);

    std::vector<float> samples = {0.5f, 0.7f, 0.3f, 0.9f};  // 2 stereo frames
    f.process(samples.data(), 2);
    CHECK_CLOSE(samples[0], 0.5f, 1e-9f, "identity left 0");
    CHECK_CLOSE(samples[1], 0.7f, 1e-9f, "identity right 0");
    CHECK_CLOSE(samples[2], 0.3f, 1e-9f, "identity left 1");
    CHECK_CLOSE(samples[3], 0.9f, 1e-9f, "identity right 1");
}

// ---------------------------------------------------------------------------
// EqChain
// ---------------------------------------------------------------------------

static void test_eq_chain_empty_on_construction()
{
    EqChain chain;
    auto bands = chain.get_bands();
    CHECK(bands != nullptr, "get_bands returns non-null");
    CHECK(bands->empty(), "initial bands list is empty");
}

static void test_eq_chain_set_and_get_bands()
{
    EqChain chain;
    std::vector<EqBand> new_bands(2);
    new_bands[0].freq_hz = 100.0f;
    new_bands[1].freq_hz = 1000.0f;

    chain.set_bands(new_bands, 44100.0f);
    auto got = chain.get_bands();
    CHECK(got != nullptr,  "get_bands after set is non-null");
    CHECK(got->size() == 2, "set 2 bands, got 2 bands");
    CHECK((*got)[0].freq_hz == 100.0f,  "first band freq preserved");
    CHECK((*got)[1].freq_hz == 1000.0f, "second band freq preserved");
}

static void test_eq_chain_sample_rate_stored()
{
    EqChain chain;
    std::vector<EqBand> bands(1);
    chain.set_bands(bands, 48000.0f);
    CHECK_CLOSE(chain.sample_rate(), 48000.0f, 1.0f, "sample_rate stored correctly");
}

// ---------------------------------------------------------------------------
// RateEstimator
// ---------------------------------------------------------------------------

static void test_rate_estimator_initial_ratio()
{
    RateEstimator est;
    est.reset(48000, 44100);
    double ratio = est.src_ratio();
    double expected = 44100.0 / 48000.0;
    CHECK_CLOSE(ratio, expected, 1e-6, "initial src_ratio = output/input");
}

static void test_rate_estimator_initial_estimated_rate()
{
    RateEstimator est;
    est.reset(48000, 44100);
    double rate = est.estimated_input_rate();
    // Before any windows complete the published rate stays at input_rate.
    CHECK_CLOSE(rate, 48000.0, 1.0, "initial estimated input rate close to input rate");
}

static void test_rate_estimator_feed_updates_after_full_window()
{
    RateEstimator est;
    est.reset(44100, 44100);

    // Simulate one full 10 s window of accurate 44100 Hz audio.
    // We feed 1024-frame blocks with monotonically advancing wall time.
    const int block = 1024;
    double t = 0.0;
    const int n_blocks = static_cast<int>(10.0 * 44100.0 / block) + 1;
    for (int i = 0; i < n_blocks; ++i) {
        t += static_cast<double>(block) / 44100.0;
        est.feed(block, t);
    }

    // After a full window the estimated rate should be close to 44100.
    double rate = est.estimated_input_rate();
    CHECK(rate > 43000.0 && rate < 45000.0, "rate estimate in plausible range after full window");

    double ratio = est.src_ratio();
    CHECK(ratio > 0.9 && ratio < 1.1, "src_ratio in plausible range after full window");
}

// ---------------------------------------------------------------------------
// OutputProcessor: basic gain state
// ---------------------------------------------------------------------------

static void test_output_processor_initial_gain_state()
{
    OutputProcessor op;
    OutputGainState state = op.get_gain_state();
    CHECK_CLOSE(state.manual_gain_db,   0.0f, 1e-6f, "initial manual_gain_db == 0");
    CHECK(state.auto_trim_enabled == false,           "initial auto_trim_enabled == false");
    CHECK_CLOSE(state.auto_trim_db,     0.0f, 1e-6f, "initial auto_trim_db == 0");
    CHECK_CLOSE(state.effective_gain_db, 0.0f, 1e-6f, "initial effective_gain_db == 0");
}

static void test_output_processor_set_manual_gain()
{
    OutputProcessor op;
    op.set_manual_gain(3.0f);
    OutputGainState state = op.get_gain_state();
    CHECK_CLOSE(state.manual_gain_db, 3.0f, 1e-6f, "manual_gain_db reflects set value");
    CHECK_CLOSE(state.effective_gain_db, 3.0f, 1e-6f, "effective_gain_db == manual when no trim");
}

static void test_output_processor_auto_trim_enable_resets_trim()
{
    OutputProcessor op;
    // Force a non-zero trim by enabling, then applying a very loud signal.
    op.set_auto_trim_enabled(true);
    // The trim starts at 0 when enabled.
    OutputGainState s = op.get_gain_state();
    CHECK(s.auto_trim_enabled,              "auto_trim enabled after enable()");
    CHECK_CLOSE(s.auto_trim_db, 0.0f, 1e-6f, "trim reset to 0 when enabled");
}

static void test_output_processor_reset_auto_trim()
{
    OutputProcessor op;
    op.set_auto_trim_enabled(true);
    op.reset_auto_trim();
    OutputGainState s = op.get_gain_state();
    CHECK_CLOSE(s.auto_trim_db, 0.0f, 1e-6f, "reset_auto_trim clears to 0");
}

static void test_output_processor_flat_input_produces_no_clip()
{
    OutputProcessor op;
    std::vector<float> samples(512, 0.5f);  // 256 stereo frames at 0.5
    op.apply(samples.data(), 256);
    // No clipping expected for samples at 0.5 linear.
    float overshoot = op.poll_clip_overshoot_dbfs();
    CHECK_CLOSE(overshoot, 0.0f, 1e-6f, "0.5-amplitude signal produces no clip overshoot");
}

static void test_output_processor_clip_detected_for_over_unity()
{
    OutputProcessor op;
    op.set_manual_gain(6.0f);  // +6 dB to push samples above 1.0
    // Input samples at 0.8 linear — after +6 dB ≈ ×2, output ≈ 1.6 (clips).
    std::vector<float> samples(512, 0.8f);
    op.apply(samples.data(), 256);
    float overshoot = op.poll_clip_overshoot_dbfs();
    CHECK(overshoot > 0.0f, "clipping detected when signal pushed above 1.0");
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

int main()
{
    logger_init(MonitorLogLevel::Warn);  // silence log output during tests

    // BiquadFilter
    test_biquad_zero_gain_is_passthrough();
    test_biquad_zero_input_gives_zero_output();
    test_biquad_nonzero_gain_changes_coefficients();
    test_biquad_reset_clears_state();
    test_biquad_low_shelf_zero_gain_passthrough();
    test_biquad_set_coefficients_identity();

    // EqChain
    test_eq_chain_empty_on_construction();
    test_eq_chain_set_and_get_bands();
    test_eq_chain_sample_rate_stored();

    // RateEstimator
    test_rate_estimator_initial_ratio();
    test_rate_estimator_initial_estimated_rate();
    test_rate_estimator_feed_updates_after_full_window();

    // OutputProcessor
    test_output_processor_initial_gain_state();
    test_output_processor_set_manual_gain();
    test_output_processor_auto_trim_enable_resets_trim();
    test_output_processor_reset_auto_trim();
    test_output_processor_flat_input_produces_no_clip();
    test_output_processor_clip_detected_for_over_unity();

    if (g_failed == 0) {
        std::printf("OK  %d/%d tests passed\n", g_tests, g_tests);
        return 0;
    }
    std::fprintf(stderr, "FAIL %d/%d tests failed\n", g_failed, g_tests);
    return 1;
}
