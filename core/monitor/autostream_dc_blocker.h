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
// Included by autostream_monitor.h, autostream_repeat.cpp and by unit tests
// (which cannot depend on ALSA or libsamplerate). No external dependencies.
// =============================================================================

#pragma once

#include <cmath>
#include <cstdint>

inline constexpr double kDcBlockerCornerHz = 10.0;

class DcBlockedPeak
{
public:
    static constexpr int kMaxChannels = 2;

    // Sets the corner for this sample rate and forgets the filter state.
    void reset(int rate_hz)
    {
        _r = (rate_hz > 0)
            ? std::exp(-2.0 * 3.14159265358979323846 * kDcBlockerCornerHz
                       / static_cast<double>(rate_hz))
            : 0.0;
        _primed = false;
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
        _primed = false;
    }

    // Peak of |filtered sample| across an interleaved block, as a fraction
    // of full_scale (2^31 for the monitor's int32 samples, 2^15 for s16).
    template <typename Sample>
    float block_peak(const Sample* samples, int n_frames, int n_channels, double full_scale)
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
        double peak = 0.0;
        for (int f = 0; f < n_frames; ++f)
        {
            for (int c = 0; c < n_channels; ++c)
            {
                double x = static_cast<double>(samples[f * n_channels + c]);
                double y = x - _x1[c] + _r * _y1[c];
                _x1[c] = x;
                _y1[c] = y;
                double a = std::fabs(y);
                if (a > peak)
                    peak = a;
            }
        }
        // A step can overshoot full scale briefly; keep the raw peak's range.
        double level = peak / full_scale;
        return static_cast<float>(level < 1.0 ? level : 1.0);
    }

private:
    double _r = 0.0;
    bool   _primed = false;
    double _x1[kMaxChannels] = {0.0, 0.0};
    double _y1[kMaxChannels] = {0.0, 0.0};
};
