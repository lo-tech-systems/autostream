// =============================================================================
// autostream_track_gap_detector.h
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// TrackGapDetector: detects inter-track silence gaps in a capture stream.
//
// Included by autostream_monitor.h and by unit tests (which cannot depend on
// ALSA or libsamplerate).  Has no external dependencies.
// =============================================================================

#pragma once

// =============================================================================
// TrackGapDetector
//
// Detects inter-track silence gaps by inspecting the raw per-block amplitude
// flag (not the debounced silence state used for session start/stop).  When
// a capture session is active and raw audio stays below the silence threshold
// for at least required_gap_seconds, update() returns true exactly once per
// gap.  It returns false again until audio rises above the threshold and then
// drops below for another required_gap_seconds.
//
// All state is private to the process thread; no locking is needed.
// =============================================================================

class TrackGapDetector
{
public:
    void reset()
    {
        _silence_start   = 0.0;
        _timing_started  = false;
        _gap_fired       = false;
    }

    // Returns true the first time a complete gap is detected in each silence run.
    // capturing:                 whether the channel is in an active capture session
    // raw_block_above_threshold: whether this block's peak is above the silence threshold
    // now_seconds:               current monotonic time
    // required_gap_seconds:      minimum silence duration to count as a track boundary
    bool update(bool capturing, bool raw_block_above_threshold,
                double now_seconds, double required_gap_seconds)
    {
        if (!capturing)
        {
            reset();
            return false;
        }

        if (raw_block_above_threshold)
        {
            _silence_start  = 0.0;
            _timing_started = false;
            _gap_fired      = false;
            return false;
        }

        if (!_timing_started)
        {
            _silence_start  = now_seconds;
            _timing_started = true;
        }

        if (!_gap_fired && (now_seconds - _silence_start) >= required_gap_seconds)
        {
            _gap_fired = true;
            return true;
        }

        return false;
    }

private:
    double _silence_start  = 0.0;
    bool   _timing_started = false;
    bool   _gap_fired      = false;
};
