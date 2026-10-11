// =============================================================================
// autostream_monitor_dsp.cpp
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Implementation of DSP classes: BiquadFilter, EqChain, OutputProcessor,
// RateEstimator.
// =============================================================================

#include "autostream_monitor.h"

#include <algorithm>
#include <cmath>


// =============================================================================
// BiquadFilter
// =============================================================================

BiquadFilter::BiquadFilter()
    : _b0(1.0f), _b1(0.0f), _b2(0.0f)
    , _a1(0.0f), _a2(0.0f)
{
    reset();
}

void BiquadFilter::set_coefficients(float b0, float b1, float b2, float a1, float a2)
{
    _b0 = b0;
    _b1 = b1;
    _b2 = b2;
    _a1 = a1;
    _a2 = a2;
}

void BiquadFilter::configure(const EqBand& band, float sample_rate)
{
    // All formulae from the RBJ Audio EQ Cookbook by Robert Bristow-Johnson.
    // https://www.w3.org/TR/audio-eq-cookbook/

    const float A       = std::pow(10.0f, band.gain_db / 40.0f);
    const float w0      = 2.0f * static_cast<float>(M_PI) * band.freq_hz / sample_rate;
    const float cos_w0  = std::cos(w0);
    const float sin_w0  = std::sin(w0);
    const float alpha   = sin_w0 / (2.0f * band.q);

    float b0, b1, b2, a0, a1, a2;

    switch (band.type)
    {
    case EqBand::Type::Peak:
        b0 =  1.0f + alpha * A;
        b1 = -2.0f * cos_w0;
        b2 =  1.0f - alpha * A;
        a0 =  1.0f + alpha / A;
        a1 = -2.0f * cos_w0;
        a2 =  1.0f - alpha / A;
        break;

    case EqBand::Type::LowShelf:
    {
        const float two_sqrt_A_alpha = 2.0f * std::sqrt(A) * alpha;
        b0 =      A * ((A + 1.0f) - (A - 1.0f) * cos_w0 + two_sqrt_A_alpha);
        b1 = 2.0f*A * ((A - 1.0f) - (A + 1.0f) * cos_w0                   );
        b2 =      A * ((A + 1.0f) - (A - 1.0f) * cos_w0 - two_sqrt_A_alpha);
        a0 =          ((A + 1.0f) + (A - 1.0f) * cos_w0 + two_sqrt_A_alpha);
        a1 =   -2.0f * ((A - 1.0f) + (A + 1.0f) * cos_w0                  );
        a2 =          ((A + 1.0f) + (A - 1.0f) * cos_w0 - two_sqrt_A_alpha);
        break;
    }

    case EqBand::Type::HighShelf:
    {
        const float two_sqrt_A_alpha = 2.0f * std::sqrt(A) * alpha;
        b0 =      A * ((A + 1.0f) + (A - 1.0f) * cos_w0 + two_sqrt_A_alpha);
        b1 =-2.0f*A * ((A - 1.0f) + (A + 1.0f) * cos_w0                   );
        b2 =      A * ((A + 1.0f) + (A - 1.0f) * cos_w0 - two_sqrt_A_alpha);
        a0 =          ((A + 1.0f) - (A - 1.0f) * cos_w0 + two_sqrt_A_alpha);
        a1 =    2.0f * ((A - 1.0f) - (A + 1.0f) * cos_w0                  );
        a2 =          ((A + 1.0f) - (A - 1.0f) * cos_w0 - two_sqrt_A_alpha);
        break;
    }

    case EqBand::Type::LowPass:
        b0 = (1.0f - cos_w0) / 2.0f;
        b1 =  1.0f - cos_w0;
        b2 = (1.0f - cos_w0) / 2.0f;
        a0 =  1.0f + alpha;
        a1 = -2.0f * cos_w0;
        a2 =  1.0f - alpha;
        break;

    case EqBand::Type::HighPass:
        b0 =  (1.0f + cos_w0) / 2.0f;
        b1 = -(1.0f + cos_w0);
        b2 =  (1.0f + cos_w0) / 2.0f;
        a0 =  1.0f + alpha;
        a1 = -2.0f * cos_w0;
        a2 =  1.0f - alpha;
        break;

    default:
        // Unity gain passthrough if type is unrecognised.
        set_coefficients(1.0f, 0.0f, 0.0f, 0.0f, 0.0f);
        return;
    }

    // Normalise all coefficients by a0 so the feedback path has unity a0.
    set_coefficients(b0 / a0, b1 / a0, b2 / a0, a1 / a0, a2 / a0);
}

void BiquadFilter::process(float* samples, int n_frames)
{
    // Direct Form I.  For each frame, process the left channel (index 0)
    // and the right channel (index 1) independently.
    for (int frame = 0; frame < n_frames; ++frame)
    {
        for (int ch = 0; ch < 2; ++ch)
        {
            float x = samples[frame * 2 + ch];
            float y = _b0 * x
                    + _b1 * _x1[ch]
                    + _b2 * _x2[ch]
                    - _a1 * _y1[ch]
                    - _a2 * _y2[ch];

            _x2[ch] = _x1[ch];
            _x1[ch] = x;
            _y2[ch] = _y1[ch];
            _y1[ch] = y;

            samples[frame * 2 + ch] = y;
        }
    }
}

void BiquadFilter::reset()
{
    _x1[0] = _x1[1] = 0.0f;
    _x2[0] = _x2[1] = 0.0f;
    _y1[0] = _y1[1] = 0.0f;
    _y2[0] = _y2[1] = 0.0f;
}


// =============================================================================
// EqChain
// =============================================================================

EqChain::EqChain()
    : _bands(std::make_shared<const std::vector<EqBand>>())
{
}

void EqChain::set_bands(const std::vector<EqBand>& bands, float sample_rate)
{
    // Build the new immutable band list outside the mutex so the lock hold is
    // as short as possible.
    auto new_bands = std::make_shared<const std::vector<EqBand>>(bands);

    std::lock_guard<std::mutex> lock(_mutex);
    _bands       = std::move(new_bands);
    _sample_rate = sample_rate;
}

std::shared_ptr<const std::vector<EqBand>> EqChain::get_bands() const
{
    // Return a copy of the shared_ptr; the refcount increment is the only
    // work done under the mutex.
    std::lock_guard<std::mutex> lock(_mutex);
    return _bands;
}

float EqChain::sample_rate() const
{
    std::lock_guard<std::mutex> lock(_mutex);
    return _sample_rate;
}


// =============================================================================
// OutputProcessor
// =============================================================================

OutputProcessor::OutputProcessor() = default;

void OutputProcessor::set_bands(const std::vector<EqBand>& bands, float sample_rate)
{
    // Compute the quick-path flag before publishing bands so there is no
    // window where _is_flat=true but the chain already holds non-flat bands.
    // A band is considered "flat" only for Peak/LowShelf/HighShelf with 0 dB
    // gain.  LowPass and HighPass are never flat regardless of parameters.
    bool is_flat = true;
    for (const auto& b : bands)
    {
        if (b.type == EqBand::Type::LowPass || b.type == EqBand::Type::HighPass)
        {
            is_flat = false;
            break;
        }
        if (b.gain_db != 0.0f)
        {
            is_flat = false;
            break;
        }
    }

    _eq_chain.set_bands(bands, sample_rate);

    // Store _is_flat after publishing to _eq_chain.  In the brief window
    // between these two lines, _is_flat may still read true while _eq_chain
    // already holds the new non-flat bands.  apply() would therefore skip
    // filtering for at most one audio block (~23 ms) before seeing _is_flat=false
    // and rebuilding _local_filters from the new bands.  This one-block lag is
    // imperceptible in practice and is the same trade-off used by the per-input
    // EqChain (see InputChannel::process_thread_func).
    _is_flat.store(is_flat, std::memory_order_relaxed);
    LOG_DEBUG("[output] set_bands: %zu band(s), flat=%s",
              bands.size(), is_flat ? "true" : "false");
}

void OutputProcessor::apply(float* samples, int n_frames)
{
    // ── EQ path: skipped entirely when all bands are identity ─────────────────
    if (!_is_flat.load(std::memory_order_relaxed))
    {
        std::lock_guard<std::mutex> lock(_apply_mutex);

        // Lazy rebuild: compare shared_ptr addresses (no allocation).
        // If set_bands() has published new bands since the last call, rebuild
        // _local_filters with freshly zeroed delay-line state.  Filter state
        // persists across input handoffs so the output stream is continuous.
        auto latest = _eq_chain.get_bands();
        if (latest != _current_bands)
        {
            _current_bands = latest;
            _local_filters.clear();
            if (latest)
            {
                float sr = _eq_chain.sample_rate();
                for (const auto& band : *latest)
                {
                    BiquadFilter f;
                    f.configure(band, sr);
                    _local_filters.push_back(f);
                }
            }
        }

        for (auto& filter : _local_filters)
            filter.process(samples, n_frames);
    }

    // ── Output gain (manual + auto-trim) ────────────────────────────────────
    // Compute and apply the effective output gain once per block.
    // Both atomics are read with relaxed ordering; a one-block lag on change
    // is imperceptible (~23 ms).  The multiply loop is skipped at 0 dB to
    // avoid a pow() call and a redundant multiply on the common flat path.
    {
        float eff_db = _manual_gain_db.load(std::memory_order_relaxed)
                     + _auto_trim_db.load(std::memory_order_relaxed);
        if (eff_db != 0.0f)
        {
            float gain  = std::pow(10.0f, eff_db / 20.0f);
            int   total = n_frames * 2;
            for (int i = 0; i < total; ++i)
                samples[i] *= gain;
        }
    }

    // ── Clip scan: always runs (reflects the true final level after gain) ─────
    // Scan the post-EQ, post-gain float data for the maximum absolute value.
    // Values > 1.0 will be clamped to full-scale by the downstream
    // float->int conversion (src_float_to_int_array on the live path,
    // src_float_to_short_array on the replay path), so we measure the true
    // overshoot here, in float, before either conversion.
    int   total_samples = n_frames * 2;   // interleaved stereo
    float peak          = 0.0f;
    for (int i = 0; i < total_samples; ++i)
    {
        float v = std::fabs(samples[i]);
        if (v > peak)
            peak = v;
    }

    // ── Auto-trim update (cut-only, session-hold) ─────────────────────────────
    // When enabled and the post-gain signal clips, add enough attenuation to
    // prevent the same overshoot on the next block.  The trim accumulates
    // downward within a session and is reset by reset_auto_trim() on handoff or
    // stop.  A CAS keep-minimum loop handles the brief concurrent window during
    // input handoff without corrupting the trim value.
    if (peak > 1.0f && _auto_trim_enabled.load(std::memory_order_relaxed))
    {
        float cut_db    = -20.0f * std::log10(peak);  // negative: overshoot to cut
        float prev_trim = _auto_trim_db.load(std::memory_order_relaxed);
        while (true)
        {
            float new_trim = std::max(prev_trim + cut_db, AUTO_TRIM_FLOOR_DB);
            if (new_trim >= prev_trim)
                break;   // already at floor or (shouldn't happen) cut_db >= 0
            if (_auto_trim_db.compare_exchange_weak(prev_trim, new_trim,
                                                     std::memory_order_relaxed))
            {
                LOG_INFO("[output] Auto-trim cut: %.2f dB -> %.2f dB "
                         "(peak=%.4f, overshoot=%.2f dB)",
                         prev_trim, new_trim, peak, -cut_db);
                break;
            }
            // prev_trim refreshed by compare_exchange_weak on failure; retry
        }
    }

    // ── Clip accumulator ──────────────────────────────────────────────────────
    // Atomically update _clip_peak_linear keeping the running maximum.
    // The CAS keep-maximum pattern is safe with relaxed ordering: at worst,
    // a concurrent poll_clip_overshoot_dbfs() exchange() wins the race and
    // resets to 0, whereupon the next CAS iteration stores peak from scratch.
    float prev = _clip_peak_linear.load(std::memory_order_relaxed);
    while (peak > prev &&
           !_clip_peak_linear.compare_exchange_weak(
               prev, peak, std::memory_order_relaxed))
        ;  // prev refreshed on failure; retry
}

float OutputProcessor::poll_clip_overshoot_dbfs()
{
    // Atomically swap the accumulator for zero and convert to dBFS.
    // 0.0f means no sample exceeded 1.0 since the last call.
    float peak = _clip_peak_linear.exchange(0.0f, std::memory_order_relaxed);
    if (peak <= 1.0f)
        return 0.0f;
    return 20.0f * std::log10(peak);
}

void OutputProcessor::set_manual_gain(float gain_db)
{
    _manual_gain_db.store(gain_db, std::memory_order_relaxed);
    LOG_INFO("[output] Manual output gain set to %.2f dB", gain_db);
}

void OutputProcessor::set_auto_trim_enabled(bool enabled)
{
    if (enabled)
    {
        // Reset any accumulated trim before enabling so each newly-enabled
        // auto-trim session starts from zero attenuation.
        float prev = _auto_trim_db.exchange(0.0f, std::memory_order_relaxed);
        LOG_INFO("[output] Auto-trim enabled (trim reset: %.2f dB -> 0.0 dB)", prev);
    }
    else
    {
        LOG_INFO("[output] Auto-trim disabled (trim held at %.2f dB)",
                 _auto_trim_db.load(std::memory_order_relaxed));
    }
    _auto_trim_enabled.store(enabled, std::memory_order_relaxed);
}

void OutputProcessor::reset_auto_trim()
{
    float prev = _auto_trim_db.exchange(0.0f, std::memory_order_relaxed);
    if (prev != 0.0f)
        LOG_INFO("[output] Auto-trim reset to 0.0 dB (was %.2f dB)", prev);
    else
        LOG_DEBUG("[output] Auto-trim reset (was already 0.0 dB)");
}

OutputGainState OutputProcessor::get_gain_state() const
{
    OutputGainState s;
    s.manual_gain_db    = _manual_gain_db.load(std::memory_order_relaxed);
    s.auto_trim_enabled = _auto_trim_enabled.load(std::memory_order_relaxed);
    s.auto_trim_db      = _auto_trim_db.load(std::memory_order_relaxed);
    s.effective_gain_db = s.manual_gain_db + s.auto_trim_db;
    return s;
}


// =============================================================================
// RateEstimator
// =============================================================================

RateEstimator::RateEstimator()
    : _input_rate(48000)
    , _output_rate(48000)
    , _smoothed_rate(48000.0)
    , _window_start_time(0.0)
    , _window_frame_count(0)
    , _initialised(false)
    , _adjustment_count(0)
    , _negotiated_rate(48000)
    , _input_index(0)
    , _detect_start_time(0.0)
    , _detect_frames(0)
    , _detect_tainted(false)
    , _run_class(0)
    , _run_count(0)
    , _rate_matching_applied(false)
    , _last_step_log_time(-1e9)
    , _last_mismatch_log_time(-1e9)
    , _published_ratio(48000.0 / 48000.0)
    , _published_rate(48000.0)
    , _rate_matching_enabled(false)
    , _published_lock_state(static_cast<int>(RateLockState::Acquiring))
    , _published_mismatch_hz(0)
    , _relock_count(0)
{
}

void RateEstimator::reset(int negotiated_rate, int output_rate, int seed_rate, int input_index)
{
    // Called before the capture thread starts — plain writes to capture-only fields.
    _negotiated_rate    = negotiated_rate;
    _input_index        = input_index;
    _input_rate         = (seed_rate > 0) ? seed_rate : negotiated_rate;
    _output_rate        = output_rate;
    _smoothed_rate      = static_cast<double>(_input_rate);
    _window_start_time  = 0.0;
    _window_frame_count = 0;
    _initialised        = false;
    _adjustment_count   = 0;

    _detect_start_time = 0.0;
    _detect_frames     = 0;
    _detect_tainted    = false;
    clear_run();
    _rate_matching_applied  = _rate_matching_enabled.load(std::memory_order_relaxed);
    _last_step_log_time     = -1e9;
    _last_mismatch_log_time = -1e9;

    // Publish safe initial values so any thread that reads before the first
    // measurement window completes gets a sensible initial ratio.
    publish_ratio_and_rate();
    _published_mismatch_hz.store(0, std::memory_order_relaxed);
    _relock_count.store(0, std::memory_order_relaxed);

    // Under the test pin feed() never measures; report the pinned nominal as
    // locked rather than leaving status at "acquiring" for a whole golden run.
    publish_lock(g_test_pin_src_ratio ? RateLockState::Locked : RateLockState::Acquiring);
}

// Test-only (--test-pin-src-ratio, gated behind --test-hooks): when set,
// feed() never publishes a measured rate, so the SRC ratio stays at the
// nominal value reset() published (exactly 1.0 on a loopback where the
// capture rate equals OUTPUT_RATE). This makes the entire audio pipeline a
// pure function of the input samples — the property golden-reference
// byte-compare testing depends on. Written once by main() before any
// thread starts, read-only
// thereafter (plain bool is sufficient; no concurrent writes exist).
// Never set in production: rate-drift correction is a core product function.
bool g_test_pin_src_ratio = false;

void RateEstimator::feed(int n_frames, double wall_time)
{
    // This method is called only from the capture thread.
    // All reads and writes to the plain fields are safe without locks.  Only
    // the atomic stores, and the one atomic load in close_detector_window(),
    // cross thread boundaries.

    // Test-only determinism pin: leave the reset()-published nominal ratio in
    // place and do no measurement at all (see g_test_pin_src_ratio above).
    if (g_test_pin_src_ratio)
        return;

    if (!_initialised)
    {
        _window_start_time  = wall_time;
        _window_frame_count = 0;
        _detect_start_time  = wall_time;
        _detect_frames      = 0;
        _detect_tainted     = false;
        _initialised        = true;
        return;
    }

    _window_frame_count += n_frames;
    _detect_frames      += n_frames;

    // Detector first: a step restarts the servo window, so the servo never
    // blends a measurement that straddles the step.
    if (_detect_frames >= DETECT_WINDOW_FRAMES)
        close_detector_window(wall_time);

    update_servo_window(wall_time);
}

void RateEstimator::update_servo_window(double wall_time)
{
    // Ramp the window duration from 1 s up to WINDOW_SECONDS over the first
    // WINDOW_SECONDS completed windows (i.e. 1 s, 2 s, … 10 s).  This lets
    // the first SRC ratio correction arrive after just one second rather than
    // ten, while the longer steady-state windows keep ratio changes smooth.
    double current_window = std::min(
        static_cast<double>(_adjustment_count + 1),
        WINDOW_SECONDS);

    double elapsed = wall_time - _window_start_time;
    if (elapsed < current_window)
        return;

    // We have a full window of data.  Compute the measured rate and blend
    // it into the running IIR-smoothed estimate.
    double measured_rate = static_cast<double>(_window_frame_count) / elapsed;

    // Sanity-check: reject measurements that are implausibly far from the
    // initial input rate (e.g. if the process was suspended, elapsed could be
    // very large).
    double deviation = std::abs(measured_rate - static_cast<double>(_input_rate))
                       / static_cast<double>(_input_rate);
    if (deviation < BAND_FRACTION)  // within ±5% of nominal
    {
        _smoothed_rate = ALPHA * measured_rate + (1.0 - ALPHA) * _smoothed_rate;
    }

    // Advance the ramp counter (saturates at WINDOW_SECONDS so the cast is safe).
    if (_adjustment_count < static_cast<int>(WINDOW_SECONDS))
        ++_adjustment_count;

    // Reset the window for the next measurement period.
    _window_start_time  = wall_time;
    _window_frame_count = 0;

    // Publish the updated values so other threads can read them safely.
    // memory_order_relaxed is sufficient: there is no ordering dependency
    // between these two stores and any other shared state.
    publish_ratio_and_rate();
}

void RateEstimator::restart_servo(double now)
{
    _adjustment_count   = 0;
    _window_start_time  = now;
    _window_frame_count = 0;
}

void RateEstimator::publish_ratio_and_rate()
{
    double new_ratio = (_smoothed_rate > 0.0)
                       ? static_cast<double>(_output_rate) / _smoothed_rate
                       : 1.0;
    _published_ratio.store(new_ratio,      std::memory_order_relaxed);
    _published_rate.store(_smoothed_rate,  std::memory_order_relaxed);
}

void RateEstimator::set_dynamic_rate_matching(bool on)
{
    _rate_matching_enabled.store(on, std::memory_order_relaxed);
}

void RateEstimator::mark_capture_loss()
{
    _detect_tainted = true;
}

void RateEstimator::close_detector_window(double now)
{
    const double elapsed = now - _detect_start_time;
    const long   frames  = _detect_frames;
    const bool   tainted = _detect_tainted;
    _detect_start_time = now;
    _detect_frames     = 0;
    _detect_tainted    = false;

    // Decide first whether this window is evidence at all, and drop any
    // pending run if it is not, before a mode change is applied.  A read that
    // blocked for a long gap closes an overlong window; a run gathered before
    // the gap must not survive it, or turning matching on during the gap
    // would step on stale evidence.  A discarded window leaves the lock state
    // alone: a stalled device has not changed rate as far as we know, and an
    // xrun lost an unknown number of frames.
    const double measured = (elapsed > 0.0) ? static_cast<double>(frames) / elapsed : 0.0;
    const bool   lost     = tainted || elapsed <= 0.0;
    const bool   slow     = !lost && measured < std::min(DETECT_MIN_PLAUSIBLE_HZ,
                                                         0.5 * static_cast<double>(_input_rate));
    const bool   discard  = lost || slow;
    if (discard)
        clear_run();

    // The flag is read once per window.  After a discard the run is empty, so
    // turning matching on cannot step; turning it off reverts regardless.
    const bool enabled = _rate_matching_enabled.load(std::memory_order_relaxed);
    if (enabled != _rate_matching_applied)
        apply_mode_change(enabled, now);

    if (discard)
    {
        if (lost)
            LOG_DEBUG("[input%d] Rate window discarded: xrun inside window", _input_index);
        else
            LOG_DEBUG("[input%d] Rate window discarded: %.1f Hz over %.3f s",
                      _input_index, measured, elapsed);
        return;
    }

    // Classify.  The nominal's class is tested first and against the nominal
    // itself, not the table, so a non-standard nominal still confirms.  Every
    // plausible window then belongs to exactly one run: the nominal's,
    // another standard rate's, or none.
    const double nominal = static_cast<double>(_input_rate);
    const int cls = (std::fabs(measured - nominal) / nominal <= CLASS_HALF_WIDTH)
                    ? _input_rate
                    : classify(measured);

    if (cls == 0 || cls != _run_class)
    {
        _run_class = cls;
        _run_count = (cls == 0) ? 0 : 1;
        if (cls != 0 && cls != _input_rate)
            LOG_DEBUG("[input%d] Rate class candidate: %d Hz (measured %.1f Hz, nominal %d Hz)",
                      _input_index, cls, measured, _input_rate);
    }
    else if (_run_count < DETECT_AGREE_WINDOWS)
    {
        ++_run_count;
    }

    const bool mismatch_asserted =
        _published_mismatch_hz.load(std::memory_order_relaxed) != 0;

    if (cls == _input_rate)
    {
        if (!mismatch_asserted)
        {
            publish_lock(RateLockState::Locked);   // any other run was a spike or a straddle
            return;
        }
        // A reported mismatch is held until the device has delivered the
        // nominal for a full run, so one early read cannot hide it.
        if (_run_count < DETECT_AGREE_WINDOWS)
            return;
        _published_mismatch_hz.store(0, std::memory_order_relaxed);
        publish_lock(RateLockState::Locked);
        LOG_INFO("[input%d] Capture rate mismatch cleared: delivering %d Hz again",
                 _input_index, _input_rate);
        return;
    }

    if (cls == 0 || _run_count < DETECT_AGREE_WINDOWS)
    {
        // Evidence pending or inconclusive; an asserted mismatch is kept.
        if (!mismatch_asserted)
            publish_lock(RateLockState::Acquiring);
        return;
    }

    // DETECT_AGREE_WINDOWS consecutive windows in one standard class that is
    // not the nominal.
    if (enabled)
        step_to(cls, now);
    else
        report_mismatch(cls, now);
}

int RateEstimator::classify(double measured) const
{
    for (int rate : STANDARD_RATES)
        if (std::fabs(measured - rate) / rate <= CLASS_HALF_WIDTH)
            return rate;
    return 0;
}

void RateEstimator::clear_run()
{
    _run_class = 0;
    _run_count = 0;
}

void RateEstimator::publish_lock(RateLockState s)
{
    _published_lock_state.store(static_cast<int>(s), std::memory_order_relaxed);
}

void RateEstimator::apply_mode_change(bool enabled, double now)
{
    _rate_matching_applied = enabled;
    if (enabled)
    {
        // Act on evidence already gathered while observing, so turning the
        // setting on in answer to a mismatch report fixes the audio at once.
        // The caller has already cleared the run if this window was
        // discarded, and the nominal's own run never qualifies.
        if (_run_class != 0 && _run_count >= DETECT_AGREE_WINDOWS && _run_class != _input_rate)
            step_to(_run_class, now);
        return;
    }

    // Off: the nominal is the negotiated rate again.  The detector reasserts
    // a mismatch after a full run if it is still true.
    _published_mismatch_hz.store(0, std::memory_order_relaxed);
    if (_input_rate != _negotiated_rate)
    {
        LOG_INFO("[input%d] Dynamic Rate Matching off: nominal %d -> %d Hz (negotiated)",
                 _input_index, _input_rate, _negotiated_rate);
        _input_rate    = _negotiated_rate;
        _smoothed_rate = static_cast<double>(_negotiated_rate);
        restart_servo(now);
        publish_ratio_and_rate();
        publish_lock(RateLockState::Acquiring);
    }
}

void RateEstimator::step_to(int new_nominal, double now)
{
    const int old_nominal = _input_rate;
    _input_rate    = new_nominal;
    _smoothed_rate = static_cast<double>(new_nominal);
    restart_servo(now);
    publish_ratio_and_rate();
    clear_run();
    publish_lock(RateLockState::Locked);
    _published_mismatch_hz.store(0, std::memory_order_relaxed);
    _relock_count.fetch_add(1, std::memory_order_relaxed);

    const double ratio = _published_ratio.load(std::memory_order_relaxed);
    if (now - _last_step_log_time >= STEP_LOG_INTERVAL_SECONDS)
    {
        _last_step_log_time = now;
        LOG_INFO("[input%d] Capture rate step: nominal %d -> %d Hz (negotiated %d Hz, ratio %.6f, step #%u)",
                 _input_index, old_nominal, new_nominal, _negotiated_rate, ratio,
                 _relock_count.load(std::memory_order_relaxed));
    }
    else
        LOG_DEBUG("[input%d] Capture rate step: nominal %d -> %d Hz (ratio %.6f)",
                  _input_index, old_nominal, new_nominal, ratio);
}

void RateEstimator::report_mismatch(int delivered, double now)
{
    publish_lock(RateLockState::Mismatch);
    if (_published_mismatch_hz.load(std::memory_order_relaxed) == delivered)
        return;
    _published_mismatch_hz.store(delivered, std::memory_order_relaxed);
    if (now - _last_mismatch_log_time >= MISMATCH_LOG_INTERVAL_SECONDS)
    {
        _last_mismatch_log_time = now;
        LOG_WARN("[input%d] Capture rate mismatch: device delivers %d Hz but was opened at %d Hz; "
                 "dynamic rate matching is off for this input",
                 _input_index, delivered, _negotiated_rate);
    }
}

double RateEstimator::src_ratio() const
{
    return _published_ratio.load(std::memory_order_relaxed);
}

double RateEstimator::estimated_input_rate() const
{
    return _published_rate.load(std::memory_order_relaxed);
}

RateLockState RateEstimator::lock_state() const
{
    return static_cast<RateLockState>(_published_lock_state.load(std::memory_order_relaxed));
}

int RateEstimator::mismatch_rate() const
{
    return _published_mismatch_hz.load(std::memory_order_relaxed);
}

uint32_t RateEstimator::relock_count() const
{
    return _relock_count.load(std::memory_order_relaxed);
}

bool RateEstimator::dynamic_rate_matching() const
{
    return _rate_matching_enabled.load(std::memory_order_relaxed);
}

int RateEstimator::nominal_rate() const
{
    return _input_rate;
}

int RateEstimator::negotiated_rate() const
{
    return _negotiated_rate;
}
