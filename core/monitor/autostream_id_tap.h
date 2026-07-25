// =============================================================================
// autostream_id_tap.h
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// IdTapResampler: the mono downmix + 44100 Hz -> 16000 Hz resample + clamp
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
// Converter: SRC_SINC_FASTEST, matching the main stereo path's choice
// (autostream_monitor_io.cpp's _src_state) -- this is what actually adds the
// missing anti-aliasing filter. CPU cost is small relative to the stereo
// main-path SINC already running on the same thread (mono vs. stereo, same
// quality setting).
//
// Allocation-free in process(): every scratch buffer is sized once, in the
// constructor, from max_block_frames (the caller's largest possible input
// block). process() never grows a buffer and never calls new/malloc -- it
// runs on the process thread (live) and the replay thread, both of which
// must never block or allocate.
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
#include <cstring>
#include <vector>

class IdTapResampler
{
public:
    // input_rate_hz / output_rate_hz: e.g. 44100 -> 16000. max_block_frames
    // must be >= the largest `frames` ever passed to process() (the live
    // path's MAX_SRC_OUTPUT, the replay path's kSliceFrames -- both 4096
    // today); output scratch is sized generously at max_block_frames + 16 to
    // match the +16 headroom the original replay-path code used for the
    // resampler's output_frames bound.
    IdTapResampler(int input_rate_hz, int output_rate_hz, int max_block_frames)
        : _src_ratio(static_cast<double>(output_rate_hz) /
                      static_cast<double>(input_rate_hz)),
          _max_block_frames(max_block_frames),
          _mono_in(static_cast<size_t>(max_block_frames)),
          _mono_out(static_cast<size_t>(max_block_frames) + 16),
          _clamped_out(static_cast<size_t>(max_block_frames) + 16)
    {
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

    bool valid() const { return _state != nullptr; }

    // src_reset() on the internal state. Call at the start of every capture
    // / replay session so interpolator history never bleeds across a
    // silence gap or session boundary.
    void reset()
    {
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
    // construct, frames is out of range, or libsamplerate reports an error
    // for this block -- callers already treat "no output" as a normal,
    // non-fatal case (a resampler does not necessarily emit output on every
    // call).
    const int16_t* process(const float* stereo_in, int frames, int* out_count)
    {
        *out_count = 0;
        if (!_state || !stereo_in || frames <= 0)
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

        SRC_DATA sd;
        std::memset(&sd, 0, sizeof(sd));
        sd.data_in       = _mono_in.data();
        sd.input_frames  = frames;
        sd.data_out      = _mono_out.data();
        sd.output_frames = static_cast<long>(_mono_out.size());
        sd.src_ratio     = _src_ratio;
        sd.end_of_input  = 0;

        if (src_process(_state, &sd) != 0 || sd.output_frames_gen <= 0)
            return nullptr;

        int count = static_cast<int>(sd.output_frames_gen);
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
    SRC_STATE* _state = nullptr;
    double     _src_ratio;
    int        _max_block_frames;

    std::vector<float>   _mono_in;
    std::vector<float>   _mono_out;
    std::vector<int16_t> _clamped_out;
};
