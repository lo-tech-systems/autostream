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
//   - RateEstimator rate detector: steps to the standard rate a device really
//     delivers (flag on), reports it (flag off), and ignores jitter, stalls,
//     xruns and gaps.
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
    CHECK_CLOSE(rate, 48000.0, 1.0, "rate estimate matches the true rate after full window");

    double ratio = est.src_ratio();
    CHECK_CLOSE(ratio, 1.0, 1e-4, "src_ratio is unity after full window at the nominal rate");

    CHECK(est.relock_count() == 0, "an honest device never steps");
    CHECK(est.lock_state() == RateLockState::Locked, "an honest device is locked");
    CHECK(est.mismatch_rate() == 0, "an honest device reports no mismatch");
}


// ---------------------------------------------------------------------------
// RateEstimator: rate detector
// ---------------------------------------------------------------------------

// Deterministic jitter source (no shared random state between tests).
static double jitter_ms(uint32_t& s, double max_ms)
{
    s = s * 1664525u + 1013904223u;
    return max_ms * static_cast<double>(s >> 8) / 16777216.0;
}

// Feed `seconds` of audio at `rate_hz` in `period`-frame reads.  `t` is the
// hardware clock (advances exactly period / rate_hz per read); the time given
// to feed() is t plus a non-negative latency of up to `max_jitter_ms`, drawn
// fresh per read, which is how read-return timing behaves.
static void feed_periods(RateEstimator& est, double rate_hz, double seconds, double& t,
                         double max_jitter_ms = 0.0, int period = 1024, uint32_t seed = 1)
{
    const int n = static_cast<int>(std::ceil(seconds * rate_hz / period));
    for (int i = 0; i < n; ++i)
    {
        t += period / rate_hz;
        est.feed(period, t + jitter_ms(seed, max_jitter_ms) / 1000.0);
    }
}

// Feed an exact number of reads.  With 1024-frame reads a detector window is
// six reads, so multiples of six keep a test aligned to window boundaries.
static void feed_reads(RateEstimator& est, double rate_hz, int reads, double& t, int period = 1024)
{
    for (int i = 0; i < reads; ++i)
    {
        t += period / rate_hz;
        est.feed(period, t);
    }
}

// Feed reads until `done()` holds after a read, for at most `max_seconds`.
// Returns the seconds fed when it first held, or -1.0 if it never did.
template <class Done>
static double feed_until(RateEstimator& est, double rate_hz, double max_seconds, double& t,
                         Done done, int period = 1024, double max_jitter_ms = 0.0,
                         uint32_t seed = 1)
{
    const int n = static_cast<int>(std::ceil(max_seconds * rate_hz / period));
    double fed = 0.0;
    for (int i = 0; i < n; ++i)
    {
        t += period / rate_hz;
        fed += period / rate_hz;
        est.feed(period, t + jitter_ms(seed, max_jitter_ms) / 1000.0);
        if (done())
            return fed;
    }
    return -1.0;
}

// The first feed() only starts the windows.
static void prime(RateEstimator& est, double& t, int period = 1024) { est.feed(period, t); }

// 90 reads at 44100 (about 2.1 s, a multiple of six) with matching off: the
// detector has reported the mismatch and its run is saturated at 44100.
static void mismatch_asserted_at_44100(RateEstimator& est, double& t)
{
    est.reset(48000, 48000);
    prime(est, t);
    feed_reads(est, 44100.0, 90, t);
}

static void test_step_to_44100_on_48000_with_matching_on()
{
    RateEstimator est;
    est.reset(48000, 48000);
    est.set_dynamic_rate_matching(true);
    double t = 0.0;
    prime(est, t);

    feed_periods(est, 44100.0, 0.30, t);
    CHECK_CLOSE(est.estimated_input_rate(), 48000.0, 1.0, "no step before three windows agree");
    CHECK(est.relock_count() == 0, "no premature step");

    const double fed = feed_until(est, 44100.0, 0.40, t, [&] { return est.relock_count() == 1; });
    CHECK(fed > 0.0, "the step arrives");
    CHECK(t > 0.417 && t < 0.558, "the step lands between three and four windows of 44.1 kHz");

    CHECK_CLOSE(est.estimated_input_rate(), 44100.0, 1e-6, "nominal moved to 44100 (no servo window yet)");
    CHECK_CLOSE(est.src_ratio(), 48000.0 / 44100.0, 1e-6, "ratio published at the step");
    CHECK(est.lock_state() == RateLockState::Locked, "locked after the step");
    CHECK(est.relock_count() == 1, "one step");
    CHECK(est.mismatch_rate() == 0, "no mismatch with matching on");
    CHECK(est.nominal_rate() == 44100, "nominal is 44100");
    CHECK(est.negotiated_rate() == 48000, "negotiated rate is never stepped");
}

static void test_step_to_44100_with_compatible_output()
{
    RateEstimator est;
    est.reset(48000, 44100);
    est.set_dynamic_rate_matching(true);
    CHECK_CLOSE(est.src_ratio(), 0.91875, 1e-6, "initial ratio is output over negotiated");
    double t = 0.0;
    prime(est, t);
    feed_periods(est, 44100.0, 1.0, t);
    CHECK_CLOSE(est.src_ratio(), 1.0, 1e-3, "ratio is unity once the nominal is 44100");
    CHECK_CLOSE(est.estimated_input_rate(), 44100.0, 0.005 * 44100.0, "rate within 0.5 % of 44100");
    CHECK(est.relock_count() == 1, "one step");
}

static void test_drift_is_tracked_without_a_step()
{
    RateEstimator est;
    est.reset(48000, 48000);
    est.set_dynamic_rate_matching(true);
    double t = 0.0;
    prime(est, t);
    feed_periods(est, 48048.0, 60.0, t);   // 0.1 % high
    CHECK(est.relock_count() == 0, "drift inside the nominal's class is not a step");
    CHECK(est.lock_state() == RateLockState::Locked, "drifting device stays locked");
    const double rate = est.estimated_input_rate();
    CHECK(rate > 48030.0 && rate < 48050.0, "servo converges on the drifting rate");
    CHECK_CLOSE(est.src_ratio(), 48000.0 / rate, 1e-6, "ratio follows the servo rate");
}

static void test_jitter_within_budget_no_false_step_and_true_step_detected()
{
    RateEstimator est;
    est.reset(48000, 48000);
    est.set_dynamic_rate_matching(true);
    double t = 0.0;
    prime(est, t);
    feed_periods(est, 48000.0, 20.0, t, 4.0);
    CHECK(est.relock_count() == 0, "4 ms of read latency never steps an honest device");
    CHECK(est.mismatch_rate() == 0, "matching on never reports a mismatch");
    feed_periods(est, 48000.0, 0.2, t);
    CHECK(est.lock_state() == RateLockState::Locked, "locked after a clean window");
    CHECK_CLOSE(est.estimated_input_rate(), 48000.0, 0.003 * 48000.0, "servo rate within 0.3 %");

    const double fed = feed_until(est, 44100.0, 1.0, t, [&] { return est.relock_count() == 1; },
                                  1024, 4.0);
    CHECK(fed > 0.0 && fed < 0.70, "a real change is still detected through the same jitter");
    CHECK(est.nominal_rate() == 44100, "nominal moved to 44100");
}

static void test_a_late_read_costs_a_window_not_a_step()
{
    RateEstimator est;
    est.reset(48000, 48000);
    est.set_dynamic_rate_matching(true);
    double t = 0.0;
    prime(est, t);
    feed_reads(est, 48000.0, 96, t);
    CHECK(est.lock_state() == RateLockState::Locked, "locked before the late read");

    // The read that ends the next window reports 8 ms late.
    feed_reads(est, 48000.0, 5, t);
    t += 1024 / 48000.0;
    est.feed(1024, t + 0.008);
    CHECK(est.lock_state() == RateLockState::Acquiring, "the window with the late boundary is not confirmation");
    CHECK(est.relock_count() == 0, "no step on a late read");
    CHECK(est.mismatch_rate() == 0, "no mismatch on a late read");

    // The late boundary also shortens the next window, which then measures
    // fast and falls in no class.
    feed_reads(est, 48000.0, 6, t);
    CHECK(est.lock_state() == RateLockState::Acquiring, "the window after the late boundary is inconclusive");
    CHECK(est.relock_count() == 0 && est.mismatch_rate() == 0, "no step or mismatch there either");

    feed_reads(est, 48000.0, 6, t);
    CHECK(est.lock_state() == RateLockState::Locked, "locked again on the next in-class window");
    feed_reads(est, 48000.0, 6, t);
    CHECK(est.lock_state() == RateLockState::Locked, "and stays locked");
    CHECK(est.relock_count() == 0, "still no step");
    CHECK(est.mismatch_rate() == 0, "still no mismatch");
}

// The detector neither steps nor reports a mismatch across a stall.  No servo
// window closes during the two shorter stalls, so the published rate is only
// compared across the suspension, whose overlong servo window is rejected.
static void test_stall_and_suspension_change_nothing()
{
    RateEstimator est;
    est.reset(48000, 48000);
    est.set_dynamic_rate_matching(true);
    double t = 0.0;
    prime(est, t);
    feed_reads(est, 48000.0, 564, t);           // about 12 s
    const double r0     = est.estimated_input_rate();
    const double ratio0 = est.src_ratio();

    // A 0.2 s stall inside a window: 18.7 kHz is plausible but in no class,
    // so that window is inconclusive.
    feed_reads(est, 48000.0, 5, t);
    t += 0.2;
    feed_reads(est, 48000.0, 1, t);
    CHECK(est.lock_state() == RateLockState::Acquiring, "stalled window is inconclusive");
    feed_reads(est, 48000.0, 6, t);
    CHECK(est.lock_state() == RateLockState::Locked, "next in-class window locks again");
    CHECK(est.relock_count() == 0 && est.mismatch_rate() == 0, "stall: no step, no mismatch");

    // A 2 s stall: below the plausibility floor, discarded, state kept.
    feed_reads(est, 48000.0, 5, t);
    t += 2.0;
    feed_reads(est, 48000.0, 1, t);
    CHECK(est.lock_state() == RateLockState::Locked, "discarded window leaves the lock state alone");
    CHECK(est.relock_count() == 0 && est.mismatch_rate() == 0, "long stall: no step, no mismatch");
    CHECK(est.nominal_rate() == 48000, "long stall: nominal unchanged");

    // A 60 s suspension.
    feed_reads(est, 48000.0, 5, t);
    t += 60.0;
    feed_reads(est, 48000.0, 1, t);
    CHECK(est.lock_state() == RateLockState::Locked, "suspension leaves the lock state alone");
    feed_reads(est, 48000.0, 24, t);
    CHECK(est.relock_count() == 0 && est.mismatch_rate() == 0, "suspension: no step, no mismatch");
    CHECK_CLOSE(est.estimated_input_rate(), r0, 1.0, "suspension: the servo rejects the overlong window");
    CHECK_CLOSE(est.src_ratio(), ratio0, 1e-9, "suspension: ratio unchanged");
}

static void test_xrun_taints_the_window()
{
    RateEstimator est;
    est.reset(48000, 48000);
    est.set_dynamic_rate_matching(true);
    double t = 0.0;
    prime(est, t);
    feed_periods(est, 44100.0, 0.1, t);
    est.mark_capture_loss();
    feed_periods(est, 44100.0, 0.1, t);
    CHECK(est.relock_count() == 0, "the tainted window does not count");
    const double fed = feed_until(est, 44100.0, 0.6, t, [&] { return est.relock_count() == 1; });
    CHECK(fed > 0.0 && t < 0.2 + 0.60, "the step still arrives, one window late");

    // At a 512-frame period a window has twelve reads; a lost period inside
    // each window would read as 44308 Hz.  Marking the loss keeps it from
    // counting as evidence.
    RateEstimator small;
    small.reset(48000, 48000);
    small.set_dynamic_rate_matching(true);
    double ts = 0.0;
    prime(small, ts, 512);
    for (int slot = 1; slot < 280; ++slot)
    {
        ts += 512 / 48000.0;
        if (slot % 13 == 0)
            small.mark_capture_loss();
        else
            small.feed(512, ts);
    }
    CHECK(small.relock_count() == 0, "marked losses never step");
    CHECK(small.mismatch_rate() == 0, "matching on never reports a mismatch");
    CHECK(small.nominal_rate() == 48000, "nominal unchanged by marked losses");
}

static void test_midsession_switch_both_ways()
{
    RateEstimator est;
    est.reset(48000, 48000);
    est.set_dynamic_rate_matching(true);
    double t = 0.0;
    prime(est, t);
    feed_periods(est, 44100.0, 120.4, t);
    CHECK(est.relock_count() == 1, "stepped to 44100 once");

    double fed = feed_until(est, 48000.0, 1.0, t, [&] { return est.nominal_rate() == 48000; });
    CHECK(fed > 0.0 && fed <= 0.56, "back to 48000 within 0.56 s");
    CHECK_CLOSE(est.estimated_input_rate(), 48000.0, 1e-6, "published rate is the new standard rate at the step");
    CHECK(est.relock_count() == 2, "second step");

    feed_periods(est, 48000.0, 20.0, t);
    fed = feed_until(est, 44100.0, 1.0, t, [&] { return est.nominal_rate() == 44100; });
    CHECK(fed > 0.0 && fed <= 0.56, "and to 44100 again within 0.56 s");
    CHECK_CLOSE(est.estimated_input_rate(), 44100.0, 1e-6, "published rate is the new standard rate at the step");
    CHECK(est.relock_count() == 3, "third step");
}

// Rates that alternate faster than the lock time never step.  A window whose
// reads are mostly one rate still measures inside that rate's class, with up
// to a third of its reads from the other rate (2 of 6 at a 1024-frame
// period, 44.1 against 48 kHz).  Three consecutive in-class windows therefore
// need about 14 reads of one rate in a row at a 1024-frame period, roughly
// 0.33 s; 9-read segments (0.2 s) cannot supply them.
static void test_rates_alternating_faster_than_the_lock_time_never_step()
{
    RateEstimator est;
    est.reset(48000, 48000);
    est.set_dynamic_rate_matching(true);
    double t = 0.0;
    prime(est, t);
    for (int i = 0; i < 25; ++i)
    {
        feed_periods(est, 44100.0, 0.2, t);
        feed_periods(est, 48000.0, 0.2, t);
    }
    CHECK(est.relock_count() == 0, "rates alternating faster than the lock time never produce a run of three");
    CHECK(est.mismatch_rate() == 0, "matching on never reports a mismatch");
}

// The other side of that boundary is intended: a rate held long enough to
// fill three in-class windows earns a step, even when the same rate came and
// went before.  With 0.33 s segments (15 reads at 44.1 kHz, 16 at 48 kHz, 1024-frame
// period) the nominal follows the rate back and forth about every two
// seconds rather than on every cycle.
static void test_a_rate_held_long_enough_steps_even_when_it_alternates()
{
    RateEstimator est;
    est.reset(48000, 48000);
    est.set_dynamic_rate_matching(true);
    double t = 0.0;
    prime(est, t);
    for (int i = 0; i < 16; ++i)
    {
        feed_periods(est, 44100.0, 0.33, t);
        feed_periods(est, 48000.0, 0.33, t);
    }
    CHECK(est.relock_count() >= 1, "a rate held for three windows earns a step");
    CHECK(est.relock_count() <= 8, "the nominal does not flip on every cycle");
    CHECK(est.nominal_rate() == 44100 || est.nominal_rate() == 48000, "the nominal is always a standard rate");
    CHECK(est.mismatch_rate() == 0, "matching on never reports a mismatch");
}

static void test_rate_near_no_standard_never_steps()
{
    {
        RateEstimator est;
        est.reset(48000, 48000);
        est.set_dynamic_rate_matching(true);
        double t = 0.0;
        prime(est, t);
        feed_periods(est, 46000.0, 3.0, t);
        CHECK(est.relock_count() == 0, "46 kHz is in no class: no step");
        CHECK(est.nominal_rate() == 48000, "nominal unchanged");
        CHECK(est.mismatch_rate() == 0, "matching on never reports a mismatch");
        CHECK(est.lock_state() == RateLockState::Acquiring, "46 kHz is neither the nominal nor a standard rate");
        const double ratio = est.src_ratio();
        CHECK(ratio >= 1.0 && ratio <= 48000.0 / 46000.0 + 1e-9, "servo blends inside its band as before");
    }
    {
        RateEstimator est;
        est.reset(48000, 48000);
        est.set_dynamic_rate_matching(true);
        double t = 0.0;
        prime(est, t);
        feed_periods(est, 40000.0, 3.0, t);
        CHECK(est.relock_count() == 0, "40 kHz is in no class: no step");
        CHECK(est.nominal_rate() == 48000, "nominal unchanged");
        CHECK(est.mismatch_rate() == 0, "matching on never reports a mismatch");
        CHECK(est.lock_state() == RateLockState::Acquiring, "40 kHz stays acquiring");
        CHECK_CLOSE(est.src_ratio(), 1.0, 1e-9, "servo rejects every window");
    }
}

static void test_matching_off_publishes_todays_values_and_reports_mismatch()
{
    RateEstimator est;
    est.reset(48000, 48000);
    double t = 0.0;
    prime(est, t);
    const double seen = feed_until(est, 44100.0, 1.0, t, [&] { return est.mismatch_rate() != 0; });
    CHECK(seen > 0.417 && seen < 0.558, "mismatch appears after three windows");
    feed_periods(est, 44100.0, 6.0, t);
    CHECK_CLOSE(est.src_ratio(), 1.0, 1e-9, "ratio is untouched with matching off");
    CHECK_CLOSE(est.estimated_input_rate(), 48000.0, 1e-9, "rate is untouched with matching off");
    CHECK(est.relock_count() == 0, "matching off never steps");
    CHECK(est.lock_state() == RateLockState::Mismatch, "state is Mismatch");
    CHECK(est.mismatch_rate() == 44100, "mismatch reports the delivered rate");
}

static void test_mismatch_clears_only_after_three_nominal_windows()
{
    RateEstimator est;
    double t = 0.0;
    mismatch_asserted_at_44100(est, t);
    CHECK(est.mismatch_rate() == 44100, "mismatch asserted");

    feed_reads(est, 48000.0, 6, t);   // one window at the nominal
    CHECK(est.mismatch_rate() == 44100, "one window at the nominal does not clear");
    CHECK(est.lock_state() == RateLockState::Mismatch, "and the state stays Mismatch");

    feed_reads(est, 44100.0, 12, t);  // the 44100 run starts again
    CHECK(est.mismatch_rate() == 44100, "still asserted");
    CHECK(est.lock_state() == RateLockState::Mismatch, "still Mismatch");

    double cleared_at = -1.0;
    double since = 0.0;
    for (int i = 0; i < 36 && cleared_at < 0.0; ++i)
    {
        feed_reads(est, 48000.0, 1, t);
        since += 1024 / 48000.0;
        if (est.mismatch_rate() == 0)
            cleared_at = since;
    }
    CHECK(cleared_at > 0.384 - 1e-6 && cleared_at < 0.512 + 1e-6, "clears after three windows at the nominal, not before");
    CHECK(est.lock_state() == RateLockState::Locked, "Locked once cleared");
    CHECK(est.relock_count() == 0, "clearing is not a step");
}

static void test_turning_matching_on_steps_from_existing_evidence()
{
    RateEstimator est;
    double t = 0.0;
    mismatch_asserted_at_44100(est, t);
    est.set_dynamic_rate_matching(true);
    feed_periods(est, 44100.0, 0.15, t);
    CHECK(est.relock_count() == 1, "steps within one window of the toggle");
    CHECK(est.nominal_rate() == 44100, "nominal is 44100");
    CHECK(est.mismatch_rate() == 0, "mismatch cleared by the step");
    CHECK(est.lock_state() == RateLockState::Locked, "locked");
}

static void test_turning_matching_off_reverts_the_nominal()
{
    RateEstimator est;
    est.reset(48000, 48000);
    est.set_dynamic_rate_matching(true);
    double t = 0.0;
    prime(est, t);
    feed_until(est, 44100.0, 1.0, t, [&] { return est.relock_count() == 1; });

    est.set_dynamic_rate_matching(false);
    feed_periods(est, 44100.0, 0.15, t);
    CHECK_CLOSE(est.estimated_input_rate(), 48000.0, 1e-6, "nominal back at the negotiated rate");
    CHECK_CLOSE(est.src_ratio(), 1.0, 1e-9, "ratio back at unity");
    CHECK(est.relock_count() == 1, "the count survives the flag being turned off");
    CHECK(est.mismatch_rate() == 0, "no mismatch yet");
    CHECK(est.lock_state() == RateLockState::Acquiring, "acquiring after the revert");
    CHECK(!est.dynamic_rate_matching(), "flag reads off");

    feed_periods(est, 44100.0, 0.5, t);
    CHECK(est.lock_state() == RateLockState::Mismatch, "mismatch re-asserted after three windows");
    CHECK(est.mismatch_rate() == 44100, "reports 44100");
    CHECK_CLOSE(est.src_ratio(), 1.0, 1e-9, "ratio stays at unity");
    CHECK(est.relock_count() == 1, "count still 1");
}

static void test_turning_matching_on_for_an_honest_device_does_not_step()
{
    RateEstimator est;
    est.reset(48000, 48000);
    double t = 0.0;
    prime(est, t);
    feed_reads(est, 48000.0, 36, t);        // a saturated run in the nominal's class
    const double ratio0 = est.src_ratio();
    est.set_dynamic_rate_matching(true);
    feed_reads(est, 48000.0, 12, t);
    CHECK(est.relock_count() == 0, "the nominal's own run is not a step");
    CHECK(est.nominal_rate() == 48000, "nominal unchanged");
    CHECK_CLOSE(est.src_ratio(), ratio0, 1e-12, "ratio untouched");
    CHECK(est.lock_state() == RateLockState::Locked, "still locked");
}

// With matching off, read-timing jitter within the budget over a long run
// never makes the detector report a mismatch.
static void test_matching_off_jitter_never_reports_a_mismatch()
{
    RateEstimator est;
    est.reset(48000, 48000);
    double t = 0.0;
    prime(est, t);
    uint32_t seed = 1;
    const int n = static_cast<int>(std::ceil(60.0 * 48000.0 / 1024));
    bool ever_mismatch = false;
    for (int i = 0; i < n; ++i)
    {
        t += 1024 / 48000.0;
        est.feed(1024, t + jitter_ms(seed, 4.0) / 1000.0);
        if (est.lock_state() == RateLockState::Mismatch || est.mismatch_rate() != 0)
            ever_mismatch = true;
    }
    CHECK(!ever_mismatch, "4 ms of read latency never reports a mismatch with matching off");
    CHECK(est.relock_count() == 0, "matching off never steps");
    CHECK(est.lock_state() == RateLockState::Locked, "locked at the end of the run");
}

static void test_32khz_source_on_a_48khz_negotiation_steps_with_matching_on()
{
    RateEstimator est;
    est.reset(48000, 48000);
    est.set_dynamic_rate_matching(true);
    double t = 0.0;
    prime(est, t);
    const double fed = feed_until(est, 32000.0, 1.0, t, [&] { return est.relock_count() == 1; });
    CHECK(fed >= 0.57 && fed <= 0.62, "the step lands after three windows of 32 kHz");
    CHECK(est.nominal_rate() == 32000, "nominal is 32000");
    CHECK_CLOSE(est.estimated_input_rate(), 32000.0, 1e-6, "rate published at the step");
    CHECK_CLOSE(est.src_ratio(), 1.5, 1e-9, "ratio is output over 32 kHz");
    CHECK(est.lock_state() == RateLockState::Locked, "locked after the step");
    CHECK(est.mismatch_rate() == 0, "no mismatch with matching on");
}

// With matching off the reported rate follows the device to another standard
// rate: the old report is kept until three windows agree on the new one.
static void test_a_reported_mismatch_follows_the_device_to_another_rate()
{
    RateEstimator est;
    double t = 0.0;
    mismatch_asserted_at_44100(est, t);
    CHECK(est.mismatch_rate() == 44100, "mismatch asserted at 44100");

    feed_reads(est, 32000.0, 12, t);   // two windows at 32 kHz
    CHECK(est.lock_state() == RateLockState::Mismatch, "the state stays Mismatch while the new rate is unconfirmed");
    CHECK(est.mismatch_rate() == 44100, "and the old rate is still reported");

    feed_reads(est, 32000.0, 6, t);    // the third
    CHECK(est.lock_state() == RateLockState::Mismatch, "still Mismatch");
    CHECK(est.mismatch_rate() == 32000, "the reported rate moves to 32000");
    CHECK(est.relock_count() == 0, "matching off never steps");
    CHECK_CLOSE(est.src_ratio(), 1.0, 1e-9, "ratio untouched");
}

// A seed that disagrees with the device is corrected when matching is on.
static void test_a_wrong_seed_is_corrected_with_matching_on()
{
    RateEstimator est;
    est.reset(48000, 48000, 44100);
    est.set_dynamic_rate_matching(true);
    double t = 0.0;
    prime(est, t);
    const double fed = feed_until(est, 48000.0, 1.0, t, [&] { return est.relock_count() == 1; });
    CHECK(fed > 0.0 && fed <= 0.45, "the seed is corrected within the usual lock time");
    CHECK(est.nominal_rate() == 48000, "nominal is 48000");
    CHECK_CLOSE(est.src_ratio(), 1.0, 1e-9, "ratio is unity");
    CHECK(est.lock_state() == RateLockState::Locked, "locked after the correction");
}

// Switching matching off well after a step: the run gathered at the stepped
// rate is not carried over to the negotiated rate, so the mismatch comes back
// only after a fresh run.
static void test_turning_matching_off_later_waits_for_fresh_evidence()
{
    RateEstimator est;
    est.reset(48000, 48000);
    est.set_dynamic_rate_matching(true);
    double t = 0.0;
    prime(est, t);
    feed_until(est, 44100.0, 1.0, t, [&] { return est.relock_count() == 1; });
    feed_reads(est, 44100.0, 60, t);   // ten windows in the stepped rate's own class
    CHECK(est.nominal_rate() == 44100 && est.lock_state() == RateLockState::Locked, "stepped and locked");

    est.set_dynamic_rate_matching(false);
    feed_reads(est, 44100.0, 6, t);    // the window that reverts
    CHECK(est.nominal_rate() == 48000, "nominal back at the negotiated rate");
    CHECK_CLOSE(est.src_ratio(), 1.0, 1e-9, "ratio back at unity");
    CHECK(est.lock_state() == RateLockState::Acquiring, "acquiring on the reverting window");
    CHECK(est.mismatch_rate() == 0, "no mismatch on the reverting window");

    feed_reads(est, 44100.0, 6, t);
    CHECK(est.lock_state() == RateLockState::Acquiring && est.mismatch_rate() == 0,
          "still acquiring after two windows");

    feed_reads(est, 44100.0, 6, t);
    CHECK(est.lock_state() == RateLockState::Mismatch, "mismatch after three agreeing windows");
    CHECK(est.mismatch_rate() == 44100, "reports 44100");
    CHECK(est.nominal_rate() == 48000, "nominal stays at the negotiated rate");
    CHECK(est.relock_count() == 1, "count still 1");
}

// Turning matching on while no run is saturated withdraws a reported
// mismatch at once; the step follows when the evidence has been gathered.
static void test_turning_matching_on_without_evidence_withdraws_the_mismatch()
{
    RateEstimator est;
    double t = 0.0;
    mismatch_asserted_at_44100(est, t);
    est.mark_capture_loss();
    feed_reads(est, 44100.0, 6, t);    // a discarded window empties the run
    CHECK(est.lock_state() == RateLockState::Mismatch && est.mismatch_rate() == 44100,
          "a discarded window leaves the report alone");

    est.set_dynamic_rate_matching(true);
    feed_reads(est, 44100.0, 6, t);
    CHECK(est.lock_state() == RateLockState::Acquiring, "acquiring at once, not mismatch");
    CHECK(est.mismatch_rate() == 0, "no mismatch with matching on");
    CHECK(est.relock_count() == 0, "no step on one window");

    feed_reads(est, 44100.0, 6, t);
    CHECK(est.relock_count() == 0 && est.mismatch_rate() == 0, "still gathering");
    feed_reads(est, 44100.0, 6, t);
    CHECK(est.relock_count() == 1, "the step follows after three windows");
    CHECK(est.nominal_rate() == 44100, "nominal is 44100");
    CHECK(est.lock_state() == RateLockState::Locked, "locked");
}

static void test_flag_accessor_reads_the_stored_value()
{
    RateEstimator est;
    est.reset(48000, 48000);
    CHECK(!est.dynamic_rate_matching(), "off by default");
    est.set_dynamic_rate_matching(true);
    CHECK(est.dynamic_rate_matching(), "reads the stored value before any window closes");
    est.reset(48000, 48000);
    CHECK(est.dynamic_rate_matching(), "reset keeps the stored flag");
}

static void test_seed_rate_is_used_and_negotiated_rate_reported()
{
    RateEstimator est;
    est.reset(48000, 48000, 44100);
    est.set_dynamic_rate_matching(true);
    CHECK_CLOSE(est.src_ratio(), 48000.0 / 44100.0, 1e-6, "ratio from the seed");
    CHECK_CLOSE(est.estimated_input_rate(), 44100.0, 1e-9, "rate is the seed");
    CHECK(est.nominal_rate() == 44100, "nominal is the seed");
    CHECK(est.negotiated_rate() == 48000, "negotiated rate kept");
    CHECK(est.lock_state() == RateLockState::Acquiring, "acquiring before any window");
    double t = 0.0;
    prime(est, t);
    feed_periods(est, 44100.0, 0.3, t);
    CHECK(est.lock_state() == RateLockState::Locked, "locked on the seeded rate");
    CHECK(est.relock_count() == 0, "no step needed");
}

static void test_seed_zero_means_negotiated()
{
    RateEstimator a;
    a.reset(48000, 48000, 0);
    RateEstimator b;
    b.reset(48000, 48000);
    CHECK_CLOSE(a.src_ratio(), 1.0, 1e-9, "explicit zero seed gives unity");
    CHECK_CLOSE(b.src_ratio(), 1.0, 1e-9, "defaulted seed gives unity");
    CHECK(a.nominal_rate() == 48000 && b.nominal_rate() == 48000, "nominal is the negotiated rate");
}

static void test_reset_clears_detector_state()
{
    RateEstimator est;
    est.reset(48000, 48000);
    est.set_dynamic_rate_matching(true);
    double t = 0.0;
    prime(est, t);
    feed_until(est, 44100.0, 1.0, t, [&] { return est.relock_count() == 1; });

    est.reset(48000, 48000);
    CHECK_CLOSE(est.src_ratio(), 1.0, 1e-9, "ratio back at unity");
    CHECK_CLOSE(est.estimated_input_rate(), 48000.0, 1e-9, "rate back at the negotiated rate");
    CHECK(est.lock_state() == RateLockState::Acquiring, "acquiring");
    CHECK(est.relock_count() == 0, "count cleared");
    CHECK(est.mismatch_rate() == 0, "mismatch cleared");
    CHECK(est.nominal_rate() == 48000, "nominal cleared");

    prime(est, t);
    feed_periods(est, 48000.0, 0.2, t);
    CHECK(est.lock_state() == RateLockState::Locked, "locks again from a clean start");
}

static void test_period_size_does_not_change_detection()
{
    const int periods[3] = {512, 2048, 1000};
    for (int period : periods)
    {
        RateEstimator est;
        est.reset(48000, 48000);
        est.set_dynamic_rate_matching(true);
        double t = 0.0;
        prime(est, t, period);
        const double fed = feed_until(est, 44100.0, 1.0, t, [&] { return est.relock_count() == 1; }, period);
        const double limit = 0.56 + (period == 2048 ? 2048 / 44100.0 : 0.0);
        CHECK(fed > 0.0 && fed <= limit, "steps within the same time whatever the period");
        CHECK(est.nominal_rate() == 44100, "nominal is exactly 44100");
    }
}

static void test_acquiring_then_locked_for_an_honest_device()
{
    RateEstimator est;
    est.reset(48000, 48000);
    double t = 0.0;
    prime(est, t);
    feed_periods(est, 48000.0, 0.1, t);
    CHECK(est.lock_state() == RateLockState::Acquiring, "no window yet");
    feed_periods(est, 48000.0, 0.1, t);
    CHECK(est.lock_state() == RateLockState::Locked, "locked after the first window");
    CHECK(est.relock_count() == 0, "no step");
}

static void test_test_pin_disables_measurement_and_reports_locked()
{
    g_test_pin_src_ratio = true;
    RateEstimator est;
    est.reset(48000, 48000);
    est.set_dynamic_rate_matching(true);
    double t = 0.0;
    prime(est, t);
    feed_periods(est, 44100.0, 1.0, t);
    CHECK_CLOSE(est.src_ratio(), 1.0, 1e-12, "pinned ratio");
    CHECK_CLOSE(est.estimated_input_rate(), 48000.0, 1e-12, "pinned rate");
    CHECK(est.relock_count() == 0, "pinned: no step");
    CHECK(est.lock_state() == RateLockState::Locked, "pinned: reported locked");
    CHECK(est.mismatch_rate() == 0, "pinned: no mismatch");
    g_test_pin_src_ratio = false;
}

static void test_uncounted_drops_step_only_at_small_periods()
{
    // 512-frame reads, every thirteenth hardware read missing: each window
    // spans thirteen periods of time for twelve reads of frames, 44308 Hz.
    {
        RateEstimator est;
        est.reset(48000, 48000);
        est.set_dynamic_rate_matching(true);
        double t = 0.0;
        prime(est, t, 512);
        for (int slot = 1; slot < 280; ++slot)
        {
            t += 512 / 48000.0;
            if (slot % 13 != 0)
                est.feed(512, t);
        }
        CHECK(est.relock_count() == 1, "uncounted drops at a small period look like 44.1 kHz");
        CHECK(est.nominal_rate() == 44100, "and step the nominal");
    }
    // 1024-frame reads, every seventh missing: 41143 Hz, in no class.
    for (int flag = 0; flag < 2; ++flag)
    {
        RateEstimator est;
        est.reset(48000, 48000);
        est.set_dynamic_rate_matching(flag == 1);
        double t = 0.0;
        prime(est, t);
        bool ever_mismatch = false;
        for (int slot = 1; slot < 160; ++slot)
        {
            t += 1024 / 48000.0;
            if (slot % 7 != 0)
                est.feed(1024, t);
            if (est.lock_state() == RateLockState::Mismatch)
                ever_mismatch = true;
        }
        CHECK(est.relock_count() == 0, "at the default period a drop reads as no class: no step");
        CHECK(est.nominal_rate() == 48000, "nominal unchanged");
        CHECK(est.mismatch_rate() == 0 && !ever_mismatch, "and no mismatch");
        CHECK(est.lock_state() == RateLockState::Acquiring, "lock only delayed");
    }
}

static void test_low_negotiated_rate_locks()
{
    {
        RateEstimator est;
        est.reset(16000, 48000);
        est.set_dynamic_rate_matching(true);
        double t = 0.0;
        prime(est, t);
        feed_periods(est, 16000.0, 2.0, t, 2.0);
        CHECK(est.lock_state() == RateLockState::Locked, "a 16 kHz device locks");
        CHECK(est.relock_count() == 0 && est.mismatch_rate() == 0, "no step, no mismatch");
        CHECK(est.nominal_rate() == 16000, "nominal unchanged");
    }
    {
        RateEstimator est;
        est.reset(8000, 48000);
        est.set_dynamic_rate_matching(true);
        double t = 0.0;
        prime(est, t);
        feed_periods(est, 8000.0, 3.0, t, 2.0);
        CHECK(est.lock_state() == RateLockState::Locked, "an 8 kHz device locks");
        CHECK(est.relock_count() == 0 && est.mismatch_rate() == 0, "no step, no mismatch");
        CHECK(est.nominal_rate() == 8000, "nominal unchanged");
    }
}

static void test_stale_evidence_is_not_used_after_a_gap()
{
    // The player comes back with a 48 kHz source.
    {
        RateEstimator est;
        double t = 0.0;
        mismatch_asserted_at_44100(est, t);
        feed_reads(est, 44100.0, 3, t);           // part of a window
        t += 3600.0;                              // an hour with nothing delivered
        est.set_dynamic_rate_matching(true);
        feed_reads(est, 44100.0, 3, t);           // closes the overlong window
        CHECK(est.relock_count() == 0, "the overlong window is discarded, not used as evidence");
        CHECK(est.nominal_rate() == 48000, "no step on hour-old evidence");

        // With matching on and nothing to step on, the stale report is
        // withdrawn when the setting takes effect.
        CHECK(est.mismatch_rate() == 0, "the old report is withdrawn");
        CHECK(est.lock_state() == RateLockState::Acquiring, "acquiring until a clean window");
        feed_reads(est, 48000.0, 6, t);
        CHECK(est.relock_count() == 0, "never stepped");
        CHECK(est.mismatch_rate() == 0, "still no mismatch");
        CHECK(est.lock_state() == RateLockState::Locked, "locked after one clean window");
    }
    // The player comes back with the same 44.1 kHz source.
    {
        RateEstimator est;
        double t = 0.0;
        mismatch_asserted_at_44100(est, t);
        feed_reads(est, 44100.0, 3, t);
        t += 3600.0;
        est.set_dynamic_rate_matching(true);
        feed_reads(est, 44100.0, 3, t);
        CHECK(est.relock_count() == 0, "no step at the discarded window");
        double stepped_at = -1.0;
        double since = 0.0;
        for (int i = 0; i < 36 && stepped_at < 0.0; ++i)
        {
            feed_reads(est, 44100.0, 1, t);
            since += 1024 / 44100.0;
            if (est.relock_count() == 1)
                stepped_at = since;
        }
        CHECK(stepped_at > 0.417 && stepped_at < 0.558, "the evidence is gathered again before the step");
        CHECK(est.nominal_rate() == 44100, "nominal is 44100");
    }
}

// The servo as it was before the detector existed, kept here as the
// reference for "matching off changes nothing the servo publishes".
struct ReferenceServo
{
    int    input_rate = 48000;
    int    output_rate = 48000;
    double smoothed = 48000.0;
    double window_start = 0.0;
    long   frames = 0;
    bool   initialised = false;
    int    adjustments = 0;
    double ratio = 1.0;
    double rate = 48000.0;

    void reset(int in, int out)
    {
        input_rate = in;
        output_rate = out;
        smoothed = in;
        window_start = 0.0;
        frames = 0;
        initialised = false;
        adjustments = 0;
        ratio = static_cast<double>(out) / static_cast<double>(in);
        rate = static_cast<double>(in);
    }

    void feed(int n, double now)
    {
        if (!initialised)
        {
            window_start = now;
            frames = 0;
            initialised = true;
            return;
        }
        frames += n;
        double current = std::min(static_cast<double>(adjustments + 1), 10.0);
        double elapsed = now - window_start;
        if (elapsed < current)
            return;
        double measured = static_cast<double>(frames) / elapsed;
        double deviation = std::abs(measured - static_cast<double>(input_rate))
                           / static_cast<double>(input_rate);
        if (deviation < 0.05)
            smoothed = 0.15 * measured + (1.0 - 0.15) * smoothed;
        if (adjustments < 10)
            ++adjustments;
        window_start = now;
        frames = 0;
        ratio = (smoothed > 0.0) ? static_cast<double>(output_rate) / smoothed : 1.0;
        rate = smoothed;
    }
};

static void test_matching_off_published_values_equal_the_servo_alone()
{
    struct Phase { double rate; double seconds; double stall; };
    const Phase phases[] = {
        {48000.0, 30.0, 0.0},     // honest
        {48048.0, 40.0, 0.0},     // drifting
        {48000.0, 5.0, 0.2},      // a stall
        {44100.0, 25.0, 0.0},     // delivering another standard rate
        {46000.0, 15.0, 0.0},     // in no class
        {48000.0, 5.0, 60.0},     // a long suspension
        {47000.0, 20.0, 0.0},
    };
    RateEstimator est;
    ReferenceServo ref;
    est.reset(48000, 48000);
    ref.reset(48000, 48000);
    double t = 0.0;
    uint32_t seed = 7;
    est.feed(1024, t);
    ref.feed(1024, t);
    long differing = 0;
    for (const Phase& p : phases)
    {
        t += p.stall;
        const int n = static_cast<int>(std::ceil(p.seconds * p.rate / 1024));
        for (int i = 0; i < n; ++i)
        {
            t += 1024 / p.rate;
            const double now = t + jitter_ms(seed, 3.0) / 1000.0;
            est.feed(1024, now);
            ref.feed(1024, now);
            if (est.src_ratio() != ref.ratio || est.estimated_input_rate() != ref.rate)
                ++differing;
        }
    }
    CHECK(differing == 0, "with matching off the published ratio and rate are bit-identical to the servo alone");
}

// ---------------------------------------------------------------------------
// Two inputs at different rates.  Each input owns its estimator, so one
// input's rate, flag, lock state and steps never show in the other.  The two
// capture threads read in wall-clock order, so the helper feeds whichever
// device is due next.
// ---------------------------------------------------------------------------

struct SimInput
{
    RateEstimator est;
    double        hw_rate = 48000.0;   // the rate the device really delivers
    double        t       = 0.0;
    int           period  = 1024;
};

static void start_input(SimInput& in, int negotiated, int output, int index,
                        double hw_rate, bool matching)
{
    in.hw_rate = hw_rate;
    in.est.reset(negotiated, output, 0, index);
    in.est.set_dynamic_rate_matching(matching);
    prime(in.est, in.t, in.period);
}

static void run_two(SimInput& a, SimInput& b, double seconds)
{
    const double end = std::max(a.t, b.t) + seconds;
    while (a.t < end || b.t < end)
    {
        SimInput& in = (a.t <= b.t) ? a : b;
        in.t += in.period / in.hw_rate;
        in.est.feed(in.period, in.t);
    }
}

static void test_two_honest_inputs_at_different_native_rates_lock_without_mismatch()
{
    SimInput a, b;
    start_input(a, 44100, 48000, 1, 44100.0, false);
    start_input(b, 48000, 48000, 2, 48000.0, false);
    run_two(a, b, 30.0);
    CHECK(a.est.lock_state() == RateLockState::Locked, "input 1 locks at its own 44100");
    CHECK(b.est.lock_state() == RateLockState::Locked, "input 2 locks at its own 48000");
    CHECK(a.est.mismatch_rate() == 0 && b.est.mismatch_rate() == 0, "neither input reports a mismatch");
    CHECK(a.est.relock_count() == 0 && b.est.relock_count() == 0, "neither input steps");
    CHECK_CLOSE(a.est.src_ratio(), 48000.0 / 44100.0, 1e-3, "input 1 ratio is output over 44100");
    CHECK_CLOSE(b.est.src_ratio(), 1.0, 1e-3, "input 2 ratio is unity");
}

static void test_a_step_on_one_input_leaves_an_honest_input_untouched()
{
    SimInput a, b;
    start_input(a, 48000, 48000, 1, 44100.0, true);
    start_input(b, 48000, 48000, 2, 48000.0, false);
    run_two(a, b, 2.0);
    CHECK(a.est.relock_count() == 1, "input 1 steps exactly once");
    CHECK(a.est.nominal_rate() == 44100, "input 1 nominal is 44100");
    CHECK(a.est.negotiated_rate() == 48000, "input 1 negotiated rate is kept");
    CHECK(b.est.relock_count() == 0, "input 2 does not step");
    CHECK(b.est.nominal_rate() == 48000, "input 2 nominal is untouched");
    CHECK(b.est.lock_state() == RateLockState::Locked && b.est.mismatch_rate() == 0,
          "input 2 stays locked with no mismatch");
    CHECK(a.est.dynamic_rate_matching() && !b.est.dynamic_rate_matching(), "the flag is per input");
    run_two(a, b, 30.0);
    CHECK_CLOSE(a.est.src_ratio(), 48000.0 / 44100.0, 2e-3, "input 1 ratio settles near output over 44100");
    CHECK_CLOSE(b.est.src_ratio(), 1.0, 1e-3, "input 2 ratio stays at unity");
    CHECK(b.est.relock_count() == 0, "input 2 still has not stepped");
}

static void test_enabling_matching_on_one_input_steps_it_on_its_own_evidence()
{
    SimInput a, b;
    start_input(a, 48000, 48000, 1, 44100.0, true);
    start_input(b, 48000, 48000, 2, 32000.0, false);
    run_two(a, b, 3.0);
    CHECK(a.est.relock_count() == 1 && a.est.mismatch_rate() == 0, "input 1 stepped with no mismatch");
    CHECK(b.est.lock_state() == RateLockState::Mismatch, "input 2 reports a mismatch");
    CHECK(b.est.mismatch_rate() == 32000, "input 2 reports 32000");
    CHECK(b.est.relock_count() == 0 && b.est.nominal_rate() == 48000, "input 2 has not stepped");
    CHECK_CLOSE(b.est.src_ratio(), 1.0, 1e-9, "input 2 ratio is untouched");

    const uint32_t relocks_before = a.est.relock_count();
    b.est.set_dynamic_rate_matching(true);
    run_two(a, b, 0.5);
    CHECK(b.est.relock_count() == 1 && b.est.nominal_rate() == 32000, "input 2 steps to 32000 once enabled");
    CHECK_CLOSE(b.est.src_ratio(), 1.5, 2e-2, "input 2 ratio is about output over 32000");
    CHECK(a.est.relock_count() == relocks_before, "input 1 relock count is unchanged by input 2's step");
    CHECK(a.est.nominal_rate() == 44100, "input 1 nominal is unchanged by input 2's step");
}

static void test_both_inputs_step_to_their_own_rates()
{
    SimInput a, b;
    start_input(a, 48000, 48000, 1, 44100.0, true);
    start_input(b, 48000, 48000, 2, 32000.0, true);
    run_two(a, b, 20.0);
    CHECK(a.est.nominal_rate() == 44100 && a.est.relock_count() == 1, "input 1 steps once to 44100");
    CHECK(b.est.nominal_rate() == 32000 && b.est.relock_count() == 1, "input 2 steps once to 32000");
    CHECK_CLOSE(a.est.src_ratio(), 48000.0 / 44100.0, 2e-3, "input 1 ratio is output over 44100");
    CHECK_CLOSE(b.est.src_ratio(), 1.5, 3e-3, "input 2 ratio is output over 32000");
}

// The daemon's compatible mode: the output rate is passed to reset().
static void test_both_inputs_step_to_their_own_rates_with_a_44100_output()
{
    SimInput a, b;
    start_input(a, 48000, 44100, 1, 44100.0, true);
    start_input(b, 48000, 44100, 2, 32000.0, true);
    run_two(a, b, 20.0);
    CHECK(a.est.nominal_rate() == 44100 && a.est.relock_count() == 1, "input 1 steps once to 44100");
    CHECK_CLOSE(a.est.src_ratio(), 1.0, 2e-3, "input 1 converts at unity on a 44100 output");
    CHECK(b.est.nominal_rate() == 32000 && b.est.relock_count() == 1, "input 2 steps once to 32000");
    CHECK_CLOSE(b.est.src_ratio(), 44100.0 / 32000.0, 3e-3, "input 2 ratio is output over 32000");
    CHECK(a.est.mismatch_rate() == 0 && b.est.mismatch_rate() == 0, "no mismatch on either input");
}

// Two converters alternating at the two highest ratios the detector can now
// reach: a 32 kHz nominal at the top of the servo band, on a 48000 and on a
// 44100 output.  Each block is MAX_FRAMES input frames and each call may
// produce at most MAX_SRC_OUTPUT frames, the sizes InputChannel::
// resample_block() uses (private constants, mirrored here).  resample_block()
// needs a running channel, so this makes the same src_process() calls
// directly.
static void test_two_resamplers_at_the_widest_ratios_stay_within_the_output_bound()
{
    constexpr int MAX_FRAMES     = 2048;
    constexpr int MAX_SRC_OUTPUT = 4096;
    constexpr int BLOCKS         = 200;
    const double  band           = 1.0 - 0.05;   // the servo's BAND_FRACTION
    const double  ratios[2]      = {(48000.0 / 32000.0) / band, (44100.0 / 32000.0) / band};

    int err_a = 0, err_b = 0;
    SRC_STATE* state[2] = {src_new(SRC_SINC_FASTEST, 2, &err_a), src_new(SRC_SINC_FASTEST, 2, &err_b)};
    CHECK(state[0] != nullptr && state[1] != nullptr, "both converters are created");
    if (!state[0] || !state[1])
    {
        if (state[0]) src_delete(state[0]);
        if (state[1]) src_delete(state[1]);
        return;
    }

    std::vector<float> in(static_cast<size_t>(MAX_FRAMES) * 2);
    std::vector<float> out(static_cast<size_t>(MAX_SRC_OUTPUT) * 2);
    for (int i = 0; i < MAX_FRAMES; ++i)
    {
        in[2 * i]     = std::sin(i * 0.01f);
        in[2 * i + 1] = std::cos(i * 0.013f);
    }

    long total_out[2]  = {0, 0};
    long calls[2]      = {0, 0};
    long largest_chunk = 0;
    bool errored       = false;
    for (int blk = 0; blk < BLOCKS && !errored; ++blk)
    {
        for (int which = 0; which < 2 && !errored; ++which)
        {
            const float* p = in.data();
            int left       = MAX_FRAMES;
            while (left > 0)
            {
                SRC_DATA d{};
                d.data_in       = p;
                d.input_frames  = left;
                d.data_out      = out.data();
                d.output_frames = MAX_SRC_OUTPUT;
                d.src_ratio     = ratios[which];
                d.end_of_input  = 0;
                if (src_process(state[which], &d) != 0 ||
                    (d.input_frames_used == 0 && d.output_frames_gen == 0))
                {
                    errored = true;
                    break;
                }
                p += d.input_frames_used * 2;
                left -= static_cast<int>(d.input_frames_used);
                largest_chunk = std::max<long>(largest_chunk, d.output_frames_gen);
                total_out[which] += d.output_frames_gen;
                ++calls[which];
            }
        }
    }
    src_delete(state[0]);
    src_delete(state[1]);

    CHECK(!errored, "neither converter errors or stalls");
    CHECK(largest_chunk <= MAX_SRC_OUTPUT, "the largest chunk is within MAX_SRC_OUTPUT");
    CHECK(calls[0] == BLOCKS && calls[1] == BLOCKS, "each block is consumed in a single call");
    for (int i = 0; i < 2; ++i)
    {
        const double expected = static_cast<double>(BLOCKS) * MAX_FRAMES * ratios[i];
        CHECK_CLOSE(total_out[i], expected, 0.01 * expected, "total frames out match the ratio");
    }
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
// the output stage can take for the SAME source
// float samples --
//   (a) native:     src_float_to_int_array()  (float -> s32)
//   (b) compatible: src_float_to_short_array() (float -> s16)
// The output stage always runs (a) for the dump tap and, in compatible
// mode, also runs (b) for the wire, so the two forms of one block must
// agree. This test confirms >>16 of libsamplerate's
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

    // RateEstimator rate detector
    test_step_to_44100_on_48000_with_matching_on();
    test_step_to_44100_with_compatible_output();
    test_drift_is_tracked_without_a_step();
    test_jitter_within_budget_no_false_step_and_true_step_detected();
    test_a_late_read_costs_a_window_not_a_step();
    test_stall_and_suspension_change_nothing();
    test_xrun_taints_the_window();
    test_midsession_switch_both_ways();
    test_rates_alternating_faster_than_the_lock_time_never_step();
    test_a_rate_held_long_enough_steps_even_when_it_alternates();
    test_rate_near_no_standard_never_steps();
    test_matching_off_publishes_todays_values_and_reports_mismatch();
    test_mismatch_clears_only_after_three_nominal_windows();
    test_turning_matching_on_steps_from_existing_evidence();
    test_turning_matching_off_reverts_the_nominal();
    test_turning_matching_on_for_an_honest_device_does_not_step();
    test_matching_off_jitter_never_reports_a_mismatch();
    test_32khz_source_on_a_48khz_negotiation_steps_with_matching_on();
    test_a_reported_mismatch_follows_the_device_to_another_rate();
    test_a_wrong_seed_is_corrected_with_matching_on();
    test_turning_matching_off_later_waits_for_fresh_evidence();
    test_turning_matching_on_without_evidence_withdraws_the_mismatch();
    test_flag_accessor_reads_the_stored_value();
    test_seed_rate_is_used_and_negotiated_rate_reported();
    test_seed_zero_means_negotiated();
    test_reset_clears_detector_state();
    test_period_size_does_not_change_detection();
    test_acquiring_then_locked_for_an_honest_device();
    test_test_pin_disables_measurement_and_reports_locked();
    test_uncounted_drops_step_only_at_small_periods();
    test_low_negotiated_rate_locks();
    test_stale_evidence_is_not_used_after_a_gap();
    test_matching_off_published_values_equal_the_servo_alone();

    // RateEstimator, two inputs at different rates
    test_two_honest_inputs_at_different_native_rates_lock_without_mismatch();
    test_a_step_on_one_input_leaves_an_honest_input_untouched();
    test_enabling_matching_on_one_input_steps_it_on_its_own_evidence();
    test_both_inputs_step_to_their_own_rates();
    test_both_inputs_step_to_their_own_rates_with_a_44100_output();
    test_two_resamplers_at_the_widest_ratios_stay_within_the_output_bound();

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
