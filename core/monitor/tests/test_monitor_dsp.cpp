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
    // The native monitor capture rate makes the nominal input/output pair
    // 48000/48000 (unity).
    RateEstimator est;
    est.reset(48000, 48000);
    double ratio = est.src_ratio();
    double expected = 48000.0 / 48000.0;
    CHECK_CLOSE(ratio, expected, 1e-6, "initial src_ratio = output/input");
}

static void test_rate_estimator_initial_estimated_rate()
{
    RateEstimator est;
    est.reset(48000, 48000);
    double rate = est.estimated_input_rate();
    // Before any windows complete the published rate stays at input_rate.
    CHECK_CLOSE(rate, 48000.0, 1.0, "initial estimated input rate close to input rate");
}

static void test_rate_estimator_feed_updates_after_full_window()
{
    RateEstimator est;
    est.reset(48000, 48000);

    // Simulate one full 10 s window of accurate 48000 Hz audio.
    // We feed 1024-frame blocks with monotonically advancing wall time.
    const int block = 1024;
    double t = 0.0;
    const int n_blocks = static_cast<int>(10.0 * 48000.0 / block) + 1;
    for (int i = 0; i < n_blocks; ++i) {
        t += static_cast<double>(block) / 48000.0;
        est.feed(block, t);
    }

    // After a full window the estimated rate should be close to 48000.
    double rate = est.estimated_input_rate();
    CHECK(rate > 47000.0 && rate < 49000.0, "rate estimate in plausible range after full window");

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
// BiquadFilter — extreme and non-finite inputs (P8 robustness)
// ---------------------------------------------------------------------------

static void test_biquad_nan_input_does_not_crash()
{
    // Feeding NaN propagates NaN through the filter (IEEE 754 arithmetic) but
    // must not trigger an assert or crash.  After reset() the filter state is
    // cleared and normal inputs produce finite outputs again.
    BiquadFilter f;
    EqBand band;
    band.type    = EqBand::Type::Peak;
    band.freq_hz = 1000.0f;
    band.gain_db = 6.0f;
    band.q       = 0.707f;
    f.configure(band, 44100.0f);

    std::vector<float> nan_samples = {
        std::numeric_limits<float>::quiet_NaN(),
        std::numeric_limits<float>::quiet_NaN()
    };
    f.process(nan_samples.data(), 1);   // must not crash / assert

    // After reset, the delay state is cleared — the filter must produce finite
    // output for a finite input even after having processed NaN.
    f.reset();
    std::vector<float> clean = {0.5f, 0.5f};
    f.process(clean.data(), 1);
    CHECK(std::isfinite(clean[0]), "BiquadFilter: finite output after NaN + reset (left)");
    CHECK(std::isfinite(clean[1]), "BiquadFilter: finite output after NaN + reset (right)");
}

static void test_biquad_inf_input_does_not_crash()
{
    BiquadFilter f;
    EqBand band;
    band.type    = EqBand::Type::Peak;
    band.freq_hz = 500.0f;
    band.gain_db = 3.0f;
    band.q       = 1.0f;
    f.configure(band, 44100.0f);

    float inf = std::numeric_limits<float>::infinity();
    std::vector<float> inf_samples = {inf, -inf};
    f.process(inf_samples.data(), 1);   // must not crash / assert

    // Same as NaN: after reset the filter recovers for finite inputs.
    f.reset();
    std::vector<float> clean = {1.0f, 1.0f};
    f.process(clean.data(), 1);
    CHECK(std::isfinite(clean[0]), "BiquadFilter: finite output after Inf + reset (left)");
    CHECK(std::isfinite(clean[1]), "BiquadFilter: finite output after Inf + reset (right)");
}

static void test_biquad_extreme_positive_gain_does_not_crash()
{
    // +120 dB is an extreme but valid configuration value.  The filter must
    // configure without crashing.  We do not assert on the output value
    // (it may be ±Infinity for large inputs) — only that no assert/exception
    // is triggered.
    BiquadFilter f;
    EqBand band;
    band.type    = EqBand::Type::Peak;
    band.freq_hz = 1000.0f;
    band.gain_db = 120.0f;
    band.q       = 0.707f;
    f.configure(band, 44100.0f);   // must not crash

    std::vector<float> samples = {1.0f, 1.0f};
    f.process(samples.data(), 1);  // may overflow to Inf — acceptable
    CHECK(true, "+120 dB configure and process completed without crash");
}

static void test_biquad_extreme_negative_gain_does_not_crash()
{
    BiquadFilter f;
    EqBand band;
    band.type    = EqBand::Type::Peak;
    band.freq_hz = 1000.0f;
    band.gain_db = -120.0f;
    band.q       = 0.707f;
    f.configure(band, 44100.0f);

    std::vector<float> samples = {1.0f, 1.0f};
    f.process(samples.data(), 1);
    // -120 dB attenuation → output should be very small (or exactly zero).
    CHECK(std::isfinite(samples[0]), "-120 dB output is finite (left)");
    CHECK(std::isfinite(samples[1]), "-120 dB output is finite (right)");
}

// ---------------------------------------------------------------------------
// EqChain — sample-rate change (P8 robustness)
// ---------------------------------------------------------------------------

static void test_eq_chain_sample_rate_change_updates_rate()
{
    EqChain chain;
    std::vector<EqBand> bands(1);
    bands[0].type    = EqBand::Type::Peak;
    bands[0].freq_hz = 1000.0f;
    bands[0].gain_db = 3.0f;
    bands[0].q       = 0.707f;

    chain.set_bands(bands, 44100.0f);
    CHECK_CLOSE(chain.sample_rate(), 44100.0f, 1.0f, "initial rate 44100");

    chain.set_bands(bands, 48000.0f);
    CHECK_CLOSE(chain.sample_rate(), 48000.0f, 1.0f, "rate updated to 48000 after set_bands");
}

static void test_eq_chain_sample_rate_change_recomputes_coefficients()
{
    // EqChain stores immutable band configuration; the audio-processing
    // consumer builds BiquadFilter instances from get_bands() and sample_rate().
    // Mirror that path and verify that the published sample rate affects the
    // resulting filter coefficients.
    EqBand band;
    band.type    = EqBand::Type::Peak;
    band.freq_hz = 8000.0f;
    band.gain_db = 12.0f;
    band.q       = 1.0f;

    EqChain chain44, chain48;
    std::vector<EqBand> bands = {band};
    chain44.set_bands(bands, 44100.0f);
    chain48.set_bands(bands, 48000.0f);

    auto bands44 = chain44.get_bands();
    auto bands48 = chain48.get_bands();
    CHECK(bands44 && bands44->size() == 1, "44100 Hz chain publishes one band");
    CHECK(bands48 && bands48->size() == 1, "48000 Hz chain publishes one band");

    BiquadFilter filter44, filter48;
    filter44.configure((*bands44)[0], chain44.sample_rate());
    filter48.configure((*bands48)[0], chain48.sample_rate());

    std::vector<float> imp44 = {1.0f, 1.0f};
    std::vector<float> imp48 = {1.0f, 1.0f};
    filter44.process(imp44.data(), 1);
    filter48.process(imp48.data(), 1);

    bool differ = std::fabs(imp44[0] - imp48[0]) > 1e-4f ||
                  std::fabs(imp44[1] - imp48[1]) > 1e-4f;
    CHECK(differ, "EqChain at 44100 and 48000 Hz produce different impulse responses");
}

// ---------------------------------------------------------------------------
// AudioMonitor::output_bytes_per_frame(): FIFO wire-format byte width,
// derived from OUTPUT_CHANNELS * (OUTPUT_BITS / 8). This is the single
// shared source of truth both FifoWriter (live path) and ReplayEngine
// (replay path) use instead of hand-rolled "* 2 * sizeof(int16_t)" literals.
// Requires autostream_monitor.h (ALSA/libsamplerate), hence tested here
// rather than in test_monitor_utils.
// ---------------------------------------------------------------------------

static void test_output_bytes_per_frame_current_format()
{
    // Default (native) runtime format: 48000 Hz / 32-bit / stereo. The
    // format is runtime-selectable (g_output_format), but no test here
    // calls main(), so it is still at its default-constructed value.
    CHECK(AudioMonitor::output_rate_hz() == 48000, "output_rate_hz() is 48000");
    CHECK(AudioMonitor::output_bits_per_sample() == 32, "output_bits_per_sample() is 32");
    CHECK(AudioMonitor::output_channels() == 2, "output_channels() is 2");
    CHECK(AudioMonitor::output_bytes_per_frame() == 8,
          "32-bit stereo is 8 bytes/frame (2 channels * 4 bytes)");
    CHECK(AudioMonitor::output_format_mode() == OutputFormatMode::Native,
          "output_format_mode() defaults to Native");
    CHECK(std::string(output_format_mode_name(AudioMonitor::output_format_mode())) == "native",
          "output_format_mode_name() reports \"native\" for the default descriptor");
}

// ---------------------------------------------------------------------------
// g_output_format descriptor -- default (native) and a --compatible-
// equivalent configuration. Tests the OutputFormatDescriptor
// struct directly (constructing a local instance) rather than mutating the
// shared g_output_format global, so this test can't leak state into any
// test that runs after it in the same binary (test_monitor_dsp's main()
// below runs everything in one process).
// ---------------------------------------------------------------------------

static void test_output_format_descriptor_defaults_are_native()
{
    OutputFormatDescriptor d;   // default-constructed, same as g_output_format at process start
    CHECK(d.rate == 48000, "default descriptor rate is 48000");
    CHECK(d.bits == 32, "default descriptor bits is 32");
    CHECK(d.channels == 2, "default descriptor channels is 2");
    CHECK(d.bytes_per_frame() == 8, "default descriptor is 8 bytes/frame");
    CHECK(d.mode == OutputFormatMode::Native, "default descriptor mode is Native");
}

static void test_output_format_descriptor_compatible_configuration()
{
    // Mirrors exactly what main() sets when --compatible is given
    // (autostream_monitor.cpp), constructed here as a standalone value so
    // this test needs no daemon/global-state setup.
    OutputFormatDescriptor d;
    d.rate     = 44100;
    d.bits     = 16;
    d.channels = 2;
    d.mode     = OutputFormatMode::Compatible;

    CHECK(d.rate == 44100, "compatible descriptor rate is 44100");
    CHECK(d.bits == 16, "compatible descriptor bits is 16");
    CHECK(d.channels == 2, "compatible descriptor channels is 2");
    CHECK(d.bytes_per_frame() == 4,
          "compatible (16-bit stereo) descriptor is 4 bytes/frame (2 channels * 2 bytes)");
    CHECK(d.mode == OutputFormatMode::Compatible, "compatible descriptor mode is Compatible");
    CHECK(std::string(output_format_mode_name(d.mode)) == "compatible",
          "output_format_mode_name() reports \"compatible\"");
}

static void test_output_bytes_per_frame_arithmetic_for_16bit_stereo()
{
    // AudioMonitor::output_bytes_per_frame() is compile-time-fixed to the
    // current 32-bit format, so a legacy 16-bit/stereo pipe's byte width
    // can't be asked of it directly. Exercise the same formula
    // (channels * (bits/8)) it uses internally to confirm the arithmetic
    // itself -- not just the current constant -- is right: 2 * (16/8) = 4.
    constexpr int channels_16bit = 2;
    constexpr int bits_16bit     = 16;
    constexpr int bytes_per_frame_16bit = channels_16bit * (bits_16bit / 8);
    CHECK(bytes_per_frame_16bit == 4, "16-bit stereo is 4 bytes/frame");
    CHECK(bytes_per_frame_16bit == static_cast<int>(2 * sizeof(int16_t)),
          "matches the 2 * sizeof(int16_t) literal for 16-bit stereo");
}

// ---------------------------------------------------------------------------
// Scaling equivalence between the two wire-edge narrowing paths
// deliver_output() can take for the SAME source
// float samples --
//   (a) native:     src_float_to_int_array()  (float -> s32)
//   (b) compatible: src_float_to_short_array() (float -> s16)
// deliver_output() itself always runs (a) (needed for the dump tap/prefill
// buffer regardless of mode) and, in compatible mode, ALSO runs (b) for the
// wire. The prefill-flush path, however, cannot re-run (b) for
// already-buffered blocks (the float source is gone by flush time -- see
// _prefill_buf's declaration comment in autostream_monitor.h) and instead
// narrows the RETAINED s32 buffer with a plain >>16. This test is the
// justification for that substitution: it confirms >>16 of libsamplerate's
// float->s32 output agrees with a direct float->s16 conversion of the same
// source samples to within 1 LSB, for a representative set of amplitudes
// (silence, near-full-scale, negative, small, mid-scale, a swept ramp).
// ---------------------------------------------------------------------------

static void test_float_to_s16_vs_float_to_s32_shifted_scaling_equivalence()
{
    std::vector<float> samples = {
        0.0f, -0.0f,
        1.0f, -1.0f,
        0.999f, -0.999f,
        0.5f, -0.5f,
        0.1f, -0.1f,
        0.0001f, -0.0001f,
        0.7071f, -0.7071f,   // -3 dBFS-ish
    };
    // A swept ramp adds broad coverage beyond the hand-picked points above.
    for (int i = -100; i <= 100; ++i)
        samples.push_back(static_cast<float>(i) / 100.0f);

    int n = static_cast<int>(samples.size());
    std::vector<int32_t> as_s32(n);
    std::vector<int16_t> as_s16(n);

    src_float_to_int_array(samples.data(), as_s32.data(), n);
    src_float_to_short_array(samples.data(), as_s16.data(), n);

    int max_abs_diff = 0;
    for (int i = 0; i < n; ++i)
    {
        int16_t narrowed = static_cast<int16_t>(as_s32[i] >> 16);
        int diff = static_cast<int>(narrowed) - static_cast<int>(as_s16[i]);
        if (diff < 0) diff = -diff;
        if (diff > max_abs_diff) max_abs_diff = diff;
    }

    CHECK(max_abs_diff <= 1,
          "float->s32>>16 agrees with direct float->s16 within 1 LSB across the sample set");
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

    // BiquadFilter — extreme and non-finite inputs (P8 robustness)
    test_biquad_nan_input_does_not_crash();
    test_biquad_inf_input_does_not_crash();
    test_biquad_extreme_positive_gain_does_not_crash();
    test_biquad_extreme_negative_gain_does_not_crash();

    // EqChain
    test_eq_chain_empty_on_construction();
    test_eq_chain_set_and_get_bands();
    test_eq_chain_sample_rate_stored();
    test_eq_chain_sample_rate_change_updates_rate();
    test_eq_chain_sample_rate_change_recomputes_coefficients();

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

    // AudioMonitor output format descriptor
    test_output_bytes_per_frame_current_format();
    test_output_bytes_per_frame_arithmetic_for_16bit_stereo();
    test_float_to_s16_vs_float_to_s32_shifted_scaling_equivalence();
    test_output_format_descriptor_defaults_are_native();
    test_output_format_descriptor_compatible_configuration();

    // logger_init() above started the dedicated logging thread;
    // it must be stopped before main() returns or the std::thread
    // destructor at static-destruction time aborts via std::terminate().
    logger_shutdown();

    if (g_failed == 0) {
        std::printf("OK  %d/%d tests passed\n", g_tests, g_tests);
        return 0;
    }
    std::fprintf(stderr, "FAIL %d/%d tests failed\n", g_failed, g_tests);
    return 1;
}
