// =============================================================================
// test_id_tap.cpp
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Unit tests for autostream_id_tap.h's IdTapResampler -- the shared, filtered
// 16 kHz mono track-ID tap.
//
// Test coverage:
//   - Anti-aliasing: a >8 kHz input tone must be strongly attenuated in the
//     16 kHz output (this is the whole point of using a filtered converter
//     instead of SRC_LINEAR). This test is written to FAIL if the converter
//     type is reverted to SRC_LINEAR; see the comment on
//     test_anti_aliasing_attenuates_above_nyquist() for how that was verified
//     during development.
//   - Passband: an in-band tone passes through near its input amplitude.
//   - Reset semantics: reset() between blocks must leave the resampler
//     equivalent to a fresh instance for a subsequent identical input.
//   - Clamp behaviour: out-of-range input samples are clamped to
//     [-32767, 32767] in the output, matching the pre-existing behaviour at
//     both call sites.
//   - Oversize-block guard: process() must not overrun scratch sized for
//     max_block_frames when handed a larger block.
//
// Build (on Linux/WSL, from repo root):
//   g++ -std=c++17 -Wall -Wextra -O2 -I core/monitor \
//       core/monitor/tests/test_id_tap.cpp \
//       -lsamplerate \
//       -o /tmp/test_id_tap && /tmp/test_id_tap
// =============================================================================

#include "autostream_id_tap.h"

#include <chrono>
#include <cmath>
#include <cstdio>
#include <vector>

// ---------------------------------------------------------------------------
// Minimal assertion harness (matches test_monitor_dsp.cpp / test_repeat_buffer.cpp)
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

static constexpr int kInputRate  = 48000;   // native monitor capture rate
static constexpr int kOutputRate = 16000;
static constexpr int kMaxBlock   = 4096;   // matches both call sites' block cap

// Builds an interleaved stereo float block of a pure sine tone at
// freq_hz, identical on both channels (a mono source panned centre --
// downmix then reproduces the same tone at the same amplitude).
static std::vector<float> make_tone(double freq_hz, double amplitude,
                                     int frames, int sample_rate_hz,
                                     double phase0 = 0.0)
{
    std::vector<float> out(static_cast<size_t>(frames) * 2);
    for (int i = 0; i < frames; ++i)
    {
        double t = static_cast<double>(i) / static_cast<double>(sample_rate_hz);
        float s = static_cast<float>(amplitude * std::sin(2.0 * M_PI * freq_hz * t + phase0));
        out[static_cast<size_t>(i) * 2]     = s;
        out[static_cast<size_t>(i) * 2 + 1] = s;
    }
    return out;
}

static double rms(const int16_t* data, int count)
{
    if (count <= 0)
        return 0.0;
    double sum_sq = 0.0;
    for (int i = 0; i < count; ++i)
    {
        double s = static_cast<double>(data[i]) / 32767.0;
        sum_sq += s * s;
    }
    return std::sqrt(sum_sq / static_cast<double>(count));
}

// Feeds `total_frames` of a stereo tone through `tap` in kMaxBlock-sized
// chunks (so multi-block streaming behaviour is exercised, matching how
// both real call sites drive process()), collecting all produced output
// samples.
static std::vector<int16_t> run_tone(IdTapResampler& tap, double freq_hz,
                                      double amplitude, int total_frames,
                                      int sample_rate_hz)
{
    std::vector<int16_t> collected;
    int remaining = total_frames;
    int frame_offset = 0;
    while (remaining > 0)
    {
        int block = std::min(remaining, kMaxBlock);
        auto tone = make_tone(freq_hz, amplitude, block, sample_rate_hz,
                               2.0 * M_PI * freq_hz *
                                   (static_cast<double>(frame_offset) / sample_rate_hz));
        int out_count = 0;
        const int16_t* out = tap.process(tone.data(), block, &out_count);
        if (out && out_count > 0)
            collected.insert(collected.end(), out, out + out_count);
        remaining     -= block;
        frame_offset  += block;
    }
    return collected;
}

// ---------------------------------------------------------------------------
// Anti-aliasing
// ---------------------------------------------------------------------------
//
// Development-time verification of the claim that this test fails against
// SRC_LINEAR: with SRC_SINC_FASTEST (current code), a 10 kHz tone into a
// 44100 -> 16000 Hz tap (measured pre-flip; the qualitative stopband
// behaviour is unchanged at the post-flip 48000 -> 16000 ratio) measured
// ~235 dB of attenuation relative to a 1 kHz
// in-band reference at the same amplitude (stopband RMS ~0.0 vs. passband
// RMS ~0.566 -- effectively complete rejection), well past this test's 10 dB
// bar. Manually swapping autostream_id_tap.h's src_new() call to SRC_LINEAR
// reduced that to ~1.4 dB (stopband RMS ~0.478 vs. the same ~0.565 passband
// reference -- a 10 kHz tone barely attenuated at all, since SRC_LINEAR is a
// sample-and-hold/linear interpolator with no stopband rejection) --
// confirming this test fails against an unfiltered converter, as a real
// regression guard should.
static void test_anti_aliasing_attenuates_above_nyquist()
{
    IdTapResampler tap(kInputRate, kOutputRate, kMaxBlock);
    CHECK(tap.valid(), "anti-alias: tap constructs");

    const double kAmplitude = 0.8;
    const int    kFrames    = kInputRate;   // 1 second

    // 10 kHz is above the 16 kHz output's 8 kHz Nyquist -- must alias if the
    // converter has no stopband, and must be heavily attenuated if it does.
    auto above_nyquist = run_tone(tap, 10000.0, kAmplitude, kFrames, kInputRate);
    CHECK(!above_nyquist.empty(), "anti-alias: 10 kHz tone produces output");

    // Reference: a 1 kHz in-band tone at the same amplitude, run through a
    // fresh instance so the 10 kHz run's filter history can't influence it.
    IdTapResampler ref_tap(kInputRate, kOutputRate, kMaxBlock);
    auto in_band = run_tone(ref_tap, 1000.0, kAmplitude, kFrames, kInputRate);
    CHECK(!in_band.empty(), "anti-alias: 1 kHz reference tone produces output");

    // Skip the first 10% of each run (filter settling / group delay) before
    // measuring steady-state RMS.
    auto steady = [](const std::vector<int16_t>& v) {
        size_t skip = v.size() / 10;
        return std::make_pair(v.data() + skip, static_cast<int>(v.size() - skip));
    };
    auto [above_data, above_n] = steady(above_nyquist);
    auto [ref_data, ref_n]     = steady(in_band);

    double above_rms = rms(above_data, above_n);
    double ref_rms    = rms(ref_data, ref_n);

    std::fprintf(stderr,
                  "[test_id_tap] 10 kHz stopband RMS=%.6f, 1 kHz passband RMS=%.6f, "
                  "attenuation=%.1f dB\n",
                  above_rms, ref_rms,
                  20.0 * std::log10((ref_rms > 1e-12 ? ref_rms : 1e-12) /
                                     (above_rms > 1e-12 ? above_rms : 1e-12)));

    // kInputRate/kOutputRate is exactly 3:1 (48000/16000), so this exercises
    // the FIR fast path (autostream_id_tap.h's design_fir_filter()), not
    // SRC_SINC_FASTEST. The FIR is designed for >=70 dB stopband attenuation
    // (10 kHz is well past its 8 kHz stopband edge); require at least 60 dB
    // here -- demanding enough that it still fails hard against a
    // no-stopband converter (SRC_LINEAR was ~1.4 dB, per the dev-time
    // measurement above) while leaving headroom under the 70 dB design
    // target for floating-point / windowing slack.
    CHECK(above_rms < ref_rms * std::pow(10.0, -60.0 / 20.0),
          "anti-alias: 10 kHz tone attenuated >= 60 dB relative to 1 kHz passband (FIR path)");
}

// ---------------------------------------------------------------------------
// Passband
// ---------------------------------------------------------------------------

static void test_passband_tone_passes_at_expected_amplitude()
{
    IdTapResampler tap(kInputRate, kOutputRate, kMaxBlock);
    CHECK(tap.valid(), "passband: tap constructs");

    const double kAmplitude = 0.5;
    const int    kFrames    = kInputRate;   // 1 second

    auto out = run_tone(tap, 1000.0, kAmplitude, kFrames, kInputRate);
    CHECK(!out.empty(), "passband: 1 kHz tone produces output");

    // Skip settling, then measure peak amplitude of the steady-state output.
    size_t skip = out.size() / 10;
    double peak = 0.0;
    for (size_t i = skip; i < out.size(); ++i)
    {
        double s = std::fabs(static_cast<double>(out[i]) / 32767.0);
        if (s > peak)
            peak = s;
    }

    // Downmix of identical L/R at amplitude A yields A (L+R)*0.5 = A. Allow
    // generous tolerance for SINC filter ripple / group delay edge effects.
    CHECK(peak > kAmplitude * 0.85 && peak < kAmplitude * 1.15,
          "passband: 1 kHz tone peak amplitude within 15% of input amplitude");
}

// ---------------------------------------------------------------------------
// Reset semantics
// ---------------------------------------------------------------------------

static void test_reset_matches_fresh_instance()
{
    const int kFrames = 2048;

    // Instance A: process a "warm-up" block of unrelated content, then
    // reset(), then process the reference signal.
    IdTapResampler tap_a(kInputRate, kOutputRate, kMaxBlock);
    CHECK(tap_a.valid(), "reset: tap_a constructs");
    auto warmup = make_tone(5000.0, 0.9, kFrames, kInputRate);
    int warmup_count = 0;
    tap_a.process(warmup.data(), kFrames, &warmup_count);
    tap_a.reset();

    auto reference = make_tone(1000.0, 0.5, kFrames, kInputRate);
    int count_a = 0;
    const int16_t* out_a = tap_a.process(reference.data(), kFrames, &count_a);

    // Instance B: fresh, never touched, processes the identical reference.
    IdTapResampler tap_b(kInputRate, kOutputRate, kMaxBlock);
    CHECK(tap_b.valid(), "reset: tap_b constructs");
    int count_b = 0;
    const int16_t* out_b = tap_b.process(reference.data(), kFrames, &count_b);

    CHECK(count_a == count_b, "reset: reset instance and fresh instance produce the same sample count");
    if (count_a == count_b && out_a && out_b)
    {
        bool all_equal = true;
        int max_diff = 0;
        for (int i = 0; i < count_a; ++i)
        {
            int diff = std::abs(static_cast<int>(out_a[i]) - static_cast<int>(out_b[i]));
            if (diff > max_diff)
                max_diff = diff;
            if (diff > 1)   // float rounding tolerance, not a semantic difference
                all_equal = false;
        }
        CHECK(all_equal, "reset: reset instance output matches fresh instance output (within float tolerance)");
        if (!all_equal)
            std::fprintf(stderr, "[test_id_tap] reset mismatch: max_diff=%d\n", max_diff);
    }
}

// ---------------------------------------------------------------------------
// Clamp behaviour
// ---------------------------------------------------------------------------

static void test_clamp_out_of_range_samples()
{
    IdTapResampler tap(kInputRate, kOutputRate, kMaxBlock);
    CHECK(tap.valid(), "clamp: tap constructs");

    const int kFrames = 512;
    std::vector<float> block(static_cast<size_t>(kFrames) * 2);
    for (int i = 0; i < kFrames; ++i)
    {
        // Well beyond +-1.0 on both channels -- downmix of two out-of-range
        // same-sign samples stays out of range too, so the clamp must fire.
        block[static_cast<size_t>(i) * 2]     = 3.5f;
        block[static_cast<size_t>(i) * 2 + 1] = 3.5f;
    }

    int out_count = 0;
    const int16_t* out = tap.process(block.data(), kFrames, &out_count);
    CHECK(out != nullptr && out_count > 0, "clamp: block produces output");
    if (out)
    {
        bool any_clamped = false;
        for (int i = 0; i < out_count; ++i)
        {
            CHECK(out[i] <= 32767 && out[i] >= -32767, "clamp: every output sample within int16 clamp range");
            if (out[i] == 32767)
                any_clamped = true;
        }
        CHECK(any_clamped, "clamp: a constant 3.5 input clamps to full-scale output");
    }
}

// ---------------------------------------------------------------------------
// Allocation-free / oversize guard
// ---------------------------------------------------------------------------

static void test_oversize_block_is_guarded_not_overrun()
{
    const int kSmallMax = 256;
    IdTapResampler tap(kInputRate, kOutputRate, kSmallMax);
    CHECK(tap.valid(), "oversize: tap constructs");

    // Hand it a block larger than max_block_frames. process() must clamp to
    // its pre-sized scratch rather than reading/writing past it (no
    // heap growth, no out-of-bounds access -- this test relies on
    // AddressSanitizer/valgrind-style tooling to catch an actual overrun;
    // absent that, it at least asserts the documented clamp-and-continue
    // contract instead of a crash).
    const int kOversizedFrames = kSmallMax * 4;
    auto tone = make_tone(1000.0, 0.5, kOversizedFrames, kInputRate);

    int out_count = 0;
    const int16_t* out = tap.process(tone.data(), kOversizedFrames, &out_count);

    // Guarded to kSmallMax input frames; output frame count for a
    // 48000->16000 conversion of kSmallMax input frames is at most
    // ceil(kSmallMax * 16000/48000) + a small SINC lookahead margin.
    CHECK(out_count <= kSmallMax, "oversize: output count bounded by the guarded (not oversized) input length");
    (void)out;
}

// ---------------------------------------------------------------------------
// Invalid input handling
// ---------------------------------------------------------------------------

static void test_invalid_arguments_return_no_output()
{
    IdTapResampler tap(kInputRate, kOutputRate, kMaxBlock);
    CHECK(tap.valid(), "invalid: tap constructs");

    int out_count = 99;
    const int16_t* out = tap.process(nullptr, 100, &out_count);
    CHECK(out == nullptr && out_count == 0, "invalid: null input pointer yields no output");

    std::vector<float> block(64, 0.0f);
    out_count = 99;
    out = tap.process(block.data(), 0, &out_count);
    CHECK(out == nullptr && out_count == 0, "invalid: zero frames yields no output");

    out_count = 99;
    out = tap.process(block.data(), -5, &out_count);
    CHECK(out == nullptr && out_count == 0, "invalid: negative frames yields no output");
}

// ---------------------------------------------------------------------------
// FIR fast path: split-block vs. single-block equivalence
// ---------------------------------------------------------------------------
//
// process_fir()'s ring buffer / decimation-phase counter persist across
// process() calls (autostream_id_tap.h's process_fir() comment). This test
// asserts that promise directly: feeding the same signal through in small
// chunks must produce bit-identical output to feeding it in one large chunk,
// with no edge artefact at the chunk boundaries.
static void test_split_block_matches_single_block_fir_path()
{
    const int kTotalFrames = 4000;   // < kMaxBlock, so the "single call" baseline below really is one call
    auto tone = make_tone(1000.0, 0.6, kTotalFrames, kInputRate);

    // Single call, whole block at once (kTotalFrames < kMaxBlock so this is
    // one process() call).
    IdTapResampler tap_single(kInputRate, kOutputRate, kMaxBlock);
    CHECK(tap_single.valid(), "split-block: single-call tap constructs");
    int count_single = 0;
    const int16_t* out_single_ptr = tap_single.process(tone.data(), kTotalFrames, &count_single);
    std::vector<int16_t> out_single(out_single_ptr, out_single_ptr + count_single);

    // Same signal, split into irregular chunks (not multiples of 3, not
    // multiples of each other) across several process() calls.
    IdTapResampler tap_split(kInputRate, kOutputRate, kMaxBlock);
    CHECK(tap_split.valid(), "split-block: split-call tap constructs");
    std::vector<int16_t> out_split;
    const int chunk_sizes[] = {1, 2, 5, 37, 500, 1000, 1000, 1455};   // sums to kTotalFrames
    int consumed = 0;
    for (int chunk : chunk_sizes)
    {
        int out_count = 0;
        const int16_t* out = tap_split.process(tone.data() + consumed * 2, chunk, &out_count);
        if (out && out_count > 0)
            out_split.insert(out_split.end(), out, out + out_count);
        consumed += chunk;
    }
    CHECK(consumed == kTotalFrames, "split-block: chunk sizes sum to the total frame count");

    CHECK(out_single.size() == out_split.size(),
          "split-block: single-call and split-call output sample counts match");
    if (out_single.size() == out_split.size())
    {
        bool all_equal = true;
        for (size_t i = 0; i < out_single.size(); ++i)
        {
            if (out_single[i] != out_split[i])
            {
                all_equal = false;
                break;
            }
        }
        CHECK(all_equal, "split-block: single-call and split-call output samples are bit-identical");
    }
}

// ---------------------------------------------------------------------------
// Non-3:1 rate: compatible mode (44100 -> 16000) still uses the SINC path
// ---------------------------------------------------------------------------
//
// 44100/16000 = 2.75625..., not an integer ratio, so the FIR fast path must
// not engage; this is a behaviour snapshot of the pre-existing
// SRC_SINC_FASTEST path, confirming it is untouched by the 3:1 fast-path
// addition.
static void test_non_3to1_rate_uses_sinc_path()
{
    const int kCompatInputRate = 44100;
    IdTapResampler tap(kCompatInputRate, kOutputRate, kMaxBlock);
    CHECK(tap.valid(), "non-3:1: 44100->16000 tap constructs");

    const double kAmplitude = 0.8;
    const int    kFrames    = kCompatInputRate;   // 1 second

    auto above_nyquist = run_tone(tap, 10000.0, kAmplitude, kFrames, kCompatInputRate);
    CHECK(!above_nyquist.empty(), "non-3:1: 10 kHz tone produces output");

    IdTapResampler ref_tap(kCompatInputRate, kOutputRate, kMaxBlock);
    auto in_band = run_tone(ref_tap, 1000.0, kAmplitude, kFrames, kCompatInputRate);
    CHECK(!in_band.empty(), "non-3:1: 1 kHz reference tone produces output");

    auto steady = [](const std::vector<int16_t>& v) {
        size_t skip = v.size() / 10;
        return std::make_pair(v.data() + skip, static_cast<int>(v.size() - skip));
    };
    auto [above_data, above_n] = steady(above_nyquist);
    auto [ref_data, ref_n]     = steady(in_band);

    double above_rms = rms(above_data, above_n);
    double ref_rms    = rms(ref_data, ref_n);

    std::fprintf(stderr,
                  "[test_id_tap] (non-3:1 SINC path) 10 kHz stopband RMS=%.6f, "
                  "1 kHz passband RMS=%.6f, attenuation=%.1f dB\n",
                  above_rms, ref_rms,
                  20.0 * std::log10((ref_rms > 1e-12 ? ref_rms : 1e-12) /
                                     (above_rms > 1e-12 ? above_rms : 1e-12)));

    // Same 10 dB bar as the original (pre-FIR) anti-aliasing test -- this is
    // the behaviour snapshot for the path this refactor must leave alone.
    CHECK(above_rms < ref_rms * std::pow(10.0, -10.0 / 20.0),
          "non-3:1: 10 kHz tone attenuated >= 10 dB relative to 1 kHz passband (SINC path)");
}

// ---------------------------------------------------------------------------
// 3:1 output-count sanity: N input frames -> ~N/3 outputs cumulative
// ---------------------------------------------------------------------------
//
// The FIR path emits one output every 3rd input sample once its history
// ring is full (taps-1 samples of warm-up latency), so cumulative output
// count trails N/3 by roughly (taps/3) samples and never exceeds N/3. The
// exact tap count is an internal design choice (see design_fir_filter()),
// so this asserts generous, design-agnostic bounds rather than an exact tap
// count.
static void test_3to1_output_count_sanity()
{
    IdTapResampler tap(kInputRate, kOutputRate, kMaxBlock);
    CHECK(tap.valid(), "output-count: 3:1 tap constructs");

    const int kFrames = kInputRate;   // 1 second = 48000 input frames
    // Drive it through run_tone (kMaxBlock-sized chunks, matching how both
    // real call sites feed process()) rather than one raw process() call --
    // kFrames (48000) exceeds kMaxBlock (4096), and a single process() call
    // silently clamps to max_block_frames (the oversize guard), which would
    // undercount here for a reason unrelated to what this test checks.
    auto out_v = run_tone(tap, 1000.0, 0.5, kFrames, kInputRate);
    int out_count = static_cast<int>(out_v.size());

    const int expected = kFrames / 3;   // 16000
    CHECK(out_count <= expected,
          "output-count: FIR cumulative output count never exceeds N/3");
    // Generous warm-up margin: even a very long FIR (hundreds of taps) loses
    // well under 1000 output samples (~3000 input samples) of latency.
    CHECK(out_count >= expected - 1000,
          "output-count: FIR cumulative output count is within warm-up latency of N/3");

    std::fprintf(stderr,
                  "[test_id_tap] 3:1 output-count sanity: %d input frames -> %d output samples "
                  "(N/3 = %d)\n",
                  kFrames, out_count, expected);
}

// ---------------------------------------------------------------------------
// Optional: rough relative timing, FIR fast path vs. general SINC path.
// Not a gated assertion -- just a report, relevant to CPU budget on
// constrained hardware (the process thread's per-block cost).
// ---------------------------------------------------------------------------
static void report_fir_vs_sinc_timing()
{
    const int kFrames = kInputRate;   // 1 second of 48 kHz stereo per iteration
    auto tone = make_tone(1000.0, 0.5, kFrames, kInputRate);
    const int kIterations = 50;

    IdTapResampler fir_tap(kInputRate, kOutputRate, kMaxBlock);          // 48000->16000, 3:1 FIR
    IdTapResampler sinc_tap(44100, kOutputRate, kMaxBlock);              // 44100->16000, SINC
    auto tone_compat = make_tone(1000.0, 0.5, 44100, 44100);

    auto t0 = std::chrono::steady_clock::now();
    for (int it = 0; it < kIterations; ++it)
    {
        int out_count = 0;
        fir_tap.process(tone.data(), kFrames, &out_count);
    }
    auto t1 = std::chrono::steady_clock::now();
    for (int it = 0; it < kIterations; ++it)
    {
        int out_count = 0;
        sinc_tap.process(tone_compat.data(), 44100, &out_count);
    }
    auto t2 = std::chrono::steady_clock::now();

    double fir_ms  = std::chrono::duration<double, std::milli>(t1 - t0).count();
    double sinc_ms = std::chrono::duration<double, std::milli>(t2 - t1).count();

    std::fprintf(stderr,
                  "[test_id_tap] timing (informational, not gated): FIR 48000->16000 "
                  "%.2f ms / %d iters (%.4f ms/iter) vs. SINC 44100->16000 %.2f ms / %d iters "
                  "(%.4f ms/iter) -- ratio (SINC/FIR) = %.2fx\n",
                  fir_ms, kIterations, fir_ms / kIterations,
                  sinc_ms, kIterations, sinc_ms / kIterations,
                  (fir_ms > 0.0) ? (sinc_ms / fir_ms) : 0.0);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

int main()
{
    test_anti_aliasing_attenuates_above_nyquist();
    test_passband_tone_passes_at_expected_amplitude();
    test_reset_matches_fresh_instance();
    test_clamp_out_of_range_samples();
    test_oversize_block_is_guarded_not_overrun();
    test_invalid_arguments_return_no_output();
    test_split_block_matches_single_block_fir_path();
    test_non_3to1_rate_uses_sinc_path();
    test_3to1_output_count_sanity();
    report_fir_vs_sinc_timing();

    if (g_failed == 0) {
        std::printf("OK  %d/%d tests passed\n", g_tests, g_tests);
        return 0;
    }
    std::fprintf(stderr, "FAIL %d/%d tests failed\n", g_failed, g_tests);
    return 1;
}
