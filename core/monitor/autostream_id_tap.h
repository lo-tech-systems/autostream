// =============================================================================
// autostream_id_tap.h
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// IdTapResampler: the mono downmix + 48000 Hz -> 16000 Hz resample + clamp
// shared by the two track-ID taps (live capture, InputChannel::
// process_thread_func() in autostream_monitor_io.cpp; replay,
// ReplayEngine::init_session()/process_slice() -- called from
// run_one_session() -- in autostream_repeat.cpp).
//
// This header exists because hand-duplicating this logic at both call sites
// creates two failure modes that a single shared, tested component avoids:
// a plain SRC_LINEAR converter has no anti-aliasing filter, so content above
// the 8 kHz Nyquist of the 16 kHz output folds back into the fingerprinting
// signal; and two independent copies have to be kept manually in sync via
// cross-referencing comments, which is exactly how session-reset semantics
// can drift -- one call site resetting its main SRC state at every
// capture-session start while forgetting to reset the ID SRC state
// alongside it. Both failure modes are structural (duplicated hand-written
// DSP), so the fix is a single shared component rather than two
// carefully-synced copies.
//
// Converter, general case: SRC_SINC_FASTEST, matching the main stereo path's
// choice (autostream_monitor_io.cpp's _src_state) -- this is what actually
// adds the missing anti-aliasing filter. CPU cost is small relative to the
// stereo main-path SINC already running on the same thread (mono vs.
// stereo, same quality setting).
//
// Converter, 3:1 fast path (relevant to CPU budget on constrained hardware;
// native-mode 48000 -> 16000 is exactly 3:1): general-purpose arbitrary-ratio
// SINC is the wrong tool for a fixed integer ratio -- it carries
// interpolator bookkeeping (fractional phase tracking, variable filter-tap
// selection per output sample) that a fixed-ratio decimator does not need.
// When input_rate_hz == 3 * output_rate_hz exactly, this class instead uses
// a dedicated windowed-sinc lowpass FIR run only at decimation instants (see
// design_fir_filter() below) -- alias-free by construction (a real
// stopband, not a heuristic), and considerably cheaper per output sample
// than SRC_SINC_FASTEST because it does none of the arbitrary-ratio
// machinery. Compatible mode (44100 -> 16000, ratio 2.75:1, not integer)
// keeps the SRC_SINC_FASTEST path untouched -- this class only special-cases
// the exact 3:1 pattern; it does not attempt to special-case other integer
// ratios (2:1, 4:1, ...) that nothing in this codebase currently produces.
// If a future rate combination needs one, the design_fir_filter() math below
// generalises directly (replace the fixed "3" with the new integer ratio
// and the FIR-processing loop's decimation modulus), but that generalisation
// is deliberately not built ahead of need.
//
// Allocation-free in process(): every scratch buffer -- SINC path's mono/
// output buffers, FIR path's ring-buffer history and coefficient table --
// is sized once, in the constructor, from max_block_frames (the caller's
// largest possible input block) and the filter design. process() never
// grows a buffer and never calls new/malloc -- it runs on the process
// thread (live) and the replay thread, both of which must never block or
// allocate.
//
// NOT thread-safe; each call site owns its own instance (InputChannel has
// one per input, ReplayEngine constructs one per replay session), exactly
// matching the lifetime of the SRC_STATE* each used to own directly. Locking
// around the *output* (the ring-buffer write under each owner's own
// _id_mutex) stays with the call site -- this helper only produces samples,
// it never touches a ring buffer or a lock.
// =============================================================================

#pragma once

#include <samplerate.h>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <vector>

class IdTapResampler
{
public:
    // input_rate_hz / output_rate_hz: e.g. 48000 -> 16000. max_block_frames
    // must be >= the largest `frames` ever passed to process() (the live
    // path's MAX_SRC_OUTPUT, the replay path's kSliceFrames -- both 4096
    // today); output scratch is sized generously at max_block_frames + 16 to
    // match the +16 headroom the original replay-path code used for the
    // resampler's output_frames bound.
    IdTapResampler(int input_rate_hz, int output_rate_hz, int max_block_frames)
        : _src_ratio(static_cast<double>(output_rate_hz) /
                      static_cast<double>(input_rate_hz)),
          _max_block_frames(max_block_frames),
          _use_fir(output_rate_hz > 0 && input_rate_hz == 3 * output_rate_hz),
          _mono_in(static_cast<size_t>(max_block_frames)),
          _mono_out(static_cast<size_t>(max_block_frames) + 16),
          _clamped_out(static_cast<size_t>(max_block_frames) + 16)
    {
        if (_use_fir)
        {
            design_fir_filter(input_rate_hz, output_rate_hz);
            _fir_ring.assign(static_cast<size_t>(_fir_num_taps), 0.0f);
            // FIR path never fails to construct (no external library call
            // that can error out) -- always valid() once the coefficients
            // are computed.
            return;
        }

        int src_error = 0;
        _state = src_new(SRC_SINC_FASTEST, /*channels=*/1, &src_error);
        // Failure is reported via valid(); callers preserve today's call-site
        // behaviour (log + treat the ID tap as unavailable / fail input
        // start, depending on the site -- see each .cpp for its own
        // handling) rather than this header deciding that policy.
    }

    ~IdTapResampler()
    {
        if (_state)
            src_delete(_state);
    }

    IdTapResampler(const IdTapResampler&)            = delete;
    IdTapResampler& operator=(const IdTapResampler&) = delete;

    bool valid() const { return _use_fir || _state != nullptr; }

    // src_reset() on the internal state (SINC path) / zeroes the FIR history
    // ring (FIR path). Call at the start of every capture / replay session
    // so interpolator (or FIR) history never bleeds across a silence gap or
    // session boundary.
    void reset()
    {
        if (_use_fir)
        {
            std::fill(_fir_ring.begin(), _fir_ring.end(), 0.0f);
            _fir_ring_pos   = 0;
            _fir_fill       = 0;
            _fir_decim_count = 0;
            return;
        }
        if (_state)
            src_reset(_state);
    }

    // Downmixes a stereo interleaved float block ((L+R)*0.5), resamples it
    // to the output rate, and clamps the result to [-1, 1] s16-scaled
    // int16_t samples. `frames` is the number of stereo frame pairs in
    // `stereo_in` (i.e. stereo_in has 2*frames floats).
    //
    // Returns a pointer to internal scratch (valid until the next process()
    // or reset() call) and writes the produced sample count to *out_count.
    // Returns nullptr (and *out_count = 0) if the converter failed to
    // construct, frames is out of range, or the resampler reports an error /
    // produces no output for this block -- callers already treat "no output"
    // as a normal, non-fatal case (a resampler does not necessarily emit
    // output on every call, especially the FIR path, which only emits once
    // every 3 input samples).
    const int16_t* process(const float* stereo_in, int frames, int* out_count)
    {
        *out_count = 0;
        if (!valid() || !stereo_in || frames <= 0)
            return nullptr;

        // Guard against a caller passing a block larger than what the
        // constructor pre-sized scratch for -- this must never happen (both
        // call sites cap their block size well under max_block_frames), but
        // a cheap bounds check here is far cheaper than a heap corruption.
        if (frames > _max_block_frames)
            frames = _max_block_frames;

        for (int i = 0; i < frames; ++i)
        {
            float L = stereo_in[i * 2];
            float R = stereo_in[i * 2 + 1];
            _mono_in[static_cast<size_t>(i)] = (L + R) * 0.5f;
        }

        int count = 0;
        if (_use_fir)
        {
            count = process_fir(frames);
        }
        else
        {
            count = process_sinc(frames);
        }

        if (count <= 0)
            return nullptr;

        for (int i = 0; i < count; ++i)
        {
            float s = _mono_out[static_cast<size_t>(i)];
            if (s >  1.0f) s =  1.0f;
            if (s < -1.0f) s = -1.0f;
            _clamped_out[static_cast<size_t>(i)] = static_cast<int16_t>(s * 32767.0f);
        }

        *out_count = count;
        return _clamped_out.data();
    }

private:
    // -------------------------------------------------------------------
    // General-ratio path: libsamplerate SRC_SINC_FASTEST.
    // -------------------------------------------------------------------
    int process_sinc(int frames)
    {
        SRC_DATA sd;
        std::memset(&sd, 0, sizeof(sd));
        sd.data_in       = _mono_in.data();
        sd.input_frames  = frames;
        sd.data_out      = _mono_out.data();
        sd.output_frames = static_cast<long>(_mono_out.size());
        sd.src_ratio     = _src_ratio;
        sd.end_of_input  = 0;

        if (src_process(_state, &sd) != 0 || sd.output_frames_gen <= 0)
            return 0;

        return static_cast<int>(sd.output_frames_gen);
    }

    // -------------------------------------------------------------------
    // 3:1 fast path: fixed decimating FIR.
    //
    // Implementation form: a single circular history buffer holding the
    // most recent _fir_num_taps mono input samples, with the full
    // taps-length convolution evaluated only at decimation instants (every
    // 3rd input sample). This is deliberately NOT written as a textbook
    // 3-phase polyphase filter bank (3 sub-filters of taps/3 coefficients
    // each, one evaluated per input sample) -- the two forms do the same
    // total multiply-accumulate work (taps MACs per output sample either
    // way; a polyphase bank just spreads those same MACs one phase-filter
    // per input sample instead of one full filter per output sample), and
    // "evaluate the full filter only when there is output to produce" is
    // simpler to get right (no phase-to-subfilter bookkeeping) for the same
    // cost. taps is kept a multiple of 3 (see design_fir_filter()) so a
    // polyphase decomposition remains possible later without a coefficient
    // re-derivation, per the header comment above.
    //
    // Block-boundary correctness: _fir_ring / _fir_ring_pos / _fir_fill /
    // _fir_decim_count all persist across process() calls (only reset() or
    // a fresh instance clears them), so splitting one logical block into
    // several process() calls produces bit-identical output to one call
    // with the whole block -- there is no per-call "flush" or edge
    // artefact. Covered by
    // test_split_block_matches_single_block_fir_path().
    // -------------------------------------------------------------------
    int process_fir(int frames)
    {
        int out_count = 0;
        const int taps = _fir_num_taps;
        const float* coeffs = _fir_coeffs.data();
        float* ring = _fir_ring.data();

        for (int i = 0; i < frames; ++i)
        {
            ring[static_cast<size_t>(_fir_ring_pos)] = _mono_in[static_cast<size_t>(i)];
            _fir_ring_pos = (_fir_ring_pos + 1) % taps;
            if (_fir_fill < taps)
                ++_fir_fill;

            bool ready = (_fir_fill == taps) && (_fir_decim_count == 0);
            _fir_decim_count = (_fir_decim_count + 1) % 3;

            if (!ready)
                continue;

            // _fir_ring_pos already points one past the newest sample,
            // i.e. exactly at the oldest sample in the window (standard
            // circular-buffer property once the buffer has wrapped at
            // least once) -- walk forward from there, oldest to newest,
            // split into two contiguous runs to avoid a per-tap modulo.
            int idx        = _fir_ring_pos;
            int first_len  = taps - idx;
            double acc     = 0.0;
            for (int k = 0; k < first_len; ++k)
                acc += static_cast<double>(coeffs[k]) * static_cast<double>(ring[idx + k]);
            for (int k = 0; k < idx; ++k)
                acc += static_cast<double>(coeffs[first_len + k]) * static_cast<double>(ring[k]);

            if (static_cast<size_t>(out_count) < _mono_out.size())
                _mono_out[static_cast<size_t>(out_count)] = static_cast<float>(acc);
            ++out_count;
        }

        return out_count;
    }

    // -------------------------------------------------------------------
    // FIR design (constructor time only -- allocation here is fine; only
    // process() must stay allocation-free).
    //
    // Windowed-sinc lowpass, Kaiser window. Design targets:
    //   - passband edge fp  ~ 6.8-7.0 kHz  (fingerprinting content)
    //   - stopband edge fst = output_rate_hz / 2  (the decimated output's
    //     own Nyquist -- e.g. 8 kHz for the 16 kHz tap; anything at or
    //     above this that isn't rejected pre-decimation aliases straight
    //     into the fingerprinting band, same reasoning as the SINC path)
    //   - stopband attenuation A >= 70 dB
    //
    // fp is derived as fst - 1200 Hz (a 1.2 kHz transition band), which for
    // the concrete 48000 -> 16000 case used today gives fp = 6800 Hz,
    // fst = 8000 Hz, matching the 6.8-7.0 kHz / 8 kHz targets above exactly.
    //
    // Kaiser beta from the stopband attenuation A (Kaiser 1980 approximation,
    // as used by e.g. scipy.signal.kaiser_beta / most DSP textbooks):
    //   beta = 0                                   , A <= 21 dB
    //        = 0.5842*(A-21)^0.4 + 0.07886*(A-21)   , 21 < A <= 50 dB
    //        = 0.1102*(A-8.7)                       , A > 50 dB
    // For A = 70 dB: beta = 0.1102*(70-8.7) = 6.7553.
    //
    // Filter length from the Kaiser length estimate:
    //   N >= (A - 7.95) / (2.285 * 2*pi*delta_f)   where delta_f = (fst-fp)/fs
    // For fs = 48000, delta_f = 1200/48000 = 0.025, A = 70:
    //   N >= (70 - 7.95) / (2.285 * 2*pi*0.025) = 62.05 / 0.3591 ~= 172.8
    // taps (= N+1, the number of coefficients) is then rounded up to the
    // next value that is both odd (Type-I linear-phase FIR -> a single
    // centre tap, symmetric either side) and a multiple of 3 (clean 3-phase
    // polyphase decomposition later, per the class-level comment) --
    // 173 -> 174 -> ... -> 177 is the first value satisfying both, so
    // taps = 177 for the 48000 -> 16000 case (order N = 176), comfortably
    // above the 172.8 minimum for margin.
    //
    // Ideal (unwindowed) lowpass impulse response, cutoff fc = (fp+fst)/2
    // (transition-band centre): h_ideal[n] = 2*fc/fs * sinc(2*fc/fs*(n-M)),
    // M = (taps-1)/2, sinc(u) = sin(pi*u)/(pi*u), sinc(0) = 1. Windowed by
    // the Kaiser window w[n] = I0(beta*sqrt(1-((n-M)/M)^2)) / I0(beta),
    // I0 = the zeroth-order modified Bessel function of the first kind
    // (series-summed below). The coefficient set is then normalised to
    // unity DC gain (sum(h) == 1) so a low-frequency tone passes through
    // the decimator at its input amplitude, compensating the Kaiser
    // window's small deviation from an exact unity-gain passband.
    //
    // Measured results (see test_id_tap.cpp): stopband attenuation and
    // passband ripple are printed by the test suite and reported alongside
    // the implementation; both meet the >=70 dB / tight-ripple design
    // targets above with margin (the class-level design N chosen with a
    // small safety margin over the 172.8-tap minimum).
    // -------------------------------------------------------------------
    static double bessel_i0(double x)
    {
        double sum  = 1.0;
        double term = 1.0;
        double y    = (x * x) / 4.0;
        for (int k = 1; k <= 50; ++k)
        {
            term *= y / (static_cast<double>(k) * static_cast<double>(k));
            sum  += term;
            if (term < 1e-14 * sum)
                break;
        }
        return sum;
    }

    static double kaiser_beta(double A)
    {
        if (A > 50.0)
            return 0.1102 * (A - 8.7);
        if (A >= 21.0)
            return 0.5842 * std::pow(A - 21.0, 0.4) + 0.07886 * (A - 21.0);
        return 0.0;
    }

    void design_fir_filter(int input_rate_hz, int output_rate_hz)
    {
        const double fs  = static_cast<double>(input_rate_hz);
        const double fst = static_cast<double>(output_rate_hz) / 2.0;
        double       fp  = fst - 1200.0;
        if (fp <= 0.0)
            fp = fst * 0.85;   // defensive fallback; not hit by any rate combination in use today

        const double A        = 70.0;
        const double beta     = kaiser_beta(A);
        const double delta_f  = (fst - fp) / fs;
        const int    n_min    = static_cast<int>(std::ceil((A - 7.95) / (2.285 * 2.0 * M_PI * delta_f)));

        int taps = n_min + 1;
        while (!(taps % 3 == 0 && taps % 2 == 1))
            ++taps;

        _fir_num_taps = taps;
        _fir_coeffs.resize(static_cast<size_t>(taps));

        const int    M      = (taps - 1) / 2;
        const double fc     = (fp + fst) / 2.0;
        const double two_fc = 2.0 * fc / fs;

        double sum = 0.0;
        for (int n = 0; n < taps; ++n)
        {
            const double m = static_cast<double>(n - M);
            double ideal;
            if (m == 0.0)
                ideal = two_fc;
            else
                ideal = std::sin(M_PI * two_fc * m) / (M_PI * m);

            const double ratio  = m / static_cast<double>(M);
            const double window = bessel_i0(beta * std::sqrt(std::max(0.0, 1.0 - ratio * ratio))) /
                                   bessel_i0(beta);

            const double h = ideal * window;
            _fir_coeffs[static_cast<size_t>(n)] = static_cast<float>(h);
            sum += h;
        }

        // Normalise to unity DC gain.
        if (sum != 0.0)
        {
            for (auto& c : _fir_coeffs)
                c = static_cast<float>(static_cast<double>(c) / sum);
        }
    }

    SRC_STATE* _state = nullptr;
    double     _src_ratio;
    int        _max_block_frames;
    bool       _use_fir;

    std::vector<float>   _mono_in;
    std::vector<float>   _mono_out;
    std::vector<int16_t> _clamped_out;

    // FIR-path state (unused / empty when _use_fir is false).
    int                 _fir_num_taps    = 0;
    std::vector<float>  _fir_coeffs;
    std::vector<float>  _fir_ring;
    int                 _fir_ring_pos    = 0;
    int                 _fir_fill        = 0;
    int                 _fir_decim_count = 0;
};
