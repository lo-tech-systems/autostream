// =============================================================================
// autostream_dc_blocker.h
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Peak level of a block with any constant offset (DC) removed, for silence
// and track-gap detection. Some sources sit at a fixed offset when they are
// not playing -- a CD player whose Bluetooth path passes through a converter
// paused at about -51 dBFS on one channel -- and a raw peak would read that
// as sound at any threshold below it. The audio itself is never filtered;
// only the level that detection compares with its threshold.
//
// One first-order high-pass per channel, y[n] = x[n] - x[n-1] + R * y[n-1],
// with its corner well below anything audible. The first block after a
// reset primes the filter from its first sample, so a source that is
// already at an offset when it starts reads as silence rather than as a
// decaying step.
//
// The same pass can also count how much of the block is signal, for the
// gates that need sound to last before they act (see block_peak_and_signal).
//
// Included by autostream_monitor.h, autostream_repeat.cpp and by unit tests
// (which cannot depend on ALSA or libsamplerate). No external dependencies.
// =============================================================================

#pragma once

#include <cmath>
#include <cstdint>

inline constexpr double kDcBlockerCornerHz = 10.0;

// How long a frame at the threshold keeps the frames after it counted as
// signal: one half-cycle at 50 Hz, so the zero crossings of a tone never
// read as gaps while a spike counts its own length and no more than this.
inline constexpr double kSignalHoldSeconds = 0.010;

// What one block counted as signal, in frames.
struct SignalCount
{
    int  frames   = 0;      // frames counted as signal, the hold included
    int  trailing = 0;      // counted frames after the block's last uncounted one
    bool gap      = false;  // the block held at least one uncounted frame
};

class DcBlockedPeak
{
public:
    static constexpr int kMaxChannels = 2;

    // Sets the corner and the hold for this sample rate and forgets the
    // filter state.
    void reset(int rate_hz)
    {
        _r = (rate_hz > 0)
            ? std::exp(-2.0 * 3.14159265358979323846 * kDcBlockerCornerHz
                       / static_cast<double>(rate_hz))
            : 0.0;
        _hold_frames = (rate_hz > 0)
            ? static_cast<int>(std::lround(static_cast<double>(rate_hz) * kSignalHoldSeconds))
            : 0;
        _primed    = false;
        _hold_left = 0;
        for (int c = 0; c < kMaxChannels; ++c)
        {
            _x1[c] = 0.0;
            _y1[c] = 0.0;
        }
    }

    // Forgets the filter state but keeps the corner: for a jump in the
    // audio (a replay's loop wrap or seek), where the next sample is not
    // continuous with the last and must not read as a step.
    void reprime()
    {
        _primed    = false;
        _hold_left = 0;
    }

    // Peak of |filtered sample| across an interleaved block, as a fraction
    // of full_scale (2^31 for the monitor's int32 samples, 2^15 for s16).
    template <typename Sample>
    float block_peak(const Sample* samples, int n_frames, int n_channels, double full_scale)
    {
        return scan<false>(samples, n_frames, n_channels, full_scale, 0.0f, nullptr);
    }

    // The same peak, and the frames that count as signal. A frame is signal
    // when either channel's filtered level is at or above threshold_level (a
    // fraction of full scale, as the peak is), or when such a frame came
    // within the last kSignalHoldSeconds. The hold bridges the zero
    // crossings of a tone, so music above the threshold counts for its whole
    // length, while a spike counts its own length plus the hold.
    template <typename Sample>
    float block_peak_and_signal(const Sample* samples, int n_frames, int n_channels,
                                double full_scale, float threshold_level, SignalCount& out)
    {
        out = SignalCount{};
        return scan<true>(samples, n_frames, n_channels, full_scale, threshold_level, &out);
    }

private:
    // One loop for both: without counting, the arithmetic and the result are
    // exactly block_peak's alone. Each frame either is at the threshold
    // (signal, hold reloaded), is inside the hold (signal, hold counts down),
    // or is quiet.
    template <bool kCount, typename Sample>
    float scan(const Sample* samples, int n_frames, int n_channels, double full_scale,
               [[maybe_unused]] float threshold_level, [[maybe_unused]] SignalCount* out)
    {
        if (n_frames <= 0 || n_channels <= 0 || n_channels > kMaxChannels)
            return 0.0f;
        if (!_primed)
        {
            for (int c = 0; c < n_channels; ++c)
            {
                _x1[c] = static_cast<double>(samples[c]);
                _y1[c] = 0.0;
            }
            _primed = true;
        }
        [[maybe_unused]] const double threshold = static_cast<double>(threshold_level) * full_scale;
        double peak = 0.0;
        for (int f = 0; f < n_frames; ++f)
        {
            bool above = false;
            for (int c = 0; c < n_channels; ++c)
            {
                double x = static_cast<double>(samples[f * n_channels + c]);
                double y = x - _x1[c] + _r * _y1[c];
                _x1[c] = x;
                _y1[c] = y;
                double a = std::fabs(y);
                if (a > peak)
                    peak = a;
                if constexpr (kCount)
                    above |= (a >= threshold);
            }
            if constexpr (kCount)
            {
                if (above)
                {
                    _hold_left = _hold_frames;
                    ++out->frames;
                    ++out->trailing;
                }
                else if (_hold_left > 0)
                {
                    --_hold_left;
                    ++out->frames;
                    ++out->trailing;
                }
                else
                {
                    out->trailing = 0;
                    out->gap      = true;
                }
            }
        }
        // A step can overshoot full scale briefly; keep the raw peak's range.
        double level = peak / full_scale;
        return static_cast<float>(level < 1.0 ? level : 1.0);
    }

    double _r = 0.0;
    bool   _primed = false;
    int    _hold_frames = 0;   // kSignalHoldSeconds at the current rate
    int    _hold_left   = 0;   // hold frames left after the last frame at the threshold
    double _x1[kMaxChannels] = {0.0, 0.0};
    double _y1[kMaxChannels] = {0.0, 0.0};
};
