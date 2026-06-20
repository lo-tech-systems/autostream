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
// Detects inter-track silence gaps and fires on the first above-threshold block
// after a qualifying gap.  Fire semantics match the plan exactly:
//
//   1. Active audio must be observed before any gap candidate is started.
//   2. Below-threshold audio starts a gap candidate timer.
//   3. When the gap reaches required_gap_seconds the candidate becomes qualifying.
//   4. update() returns true on the FIRST above-threshold block after a
//      qualifying gap — i.e. when audio resumes.  The caller increments
//      track_change_seq when update() returns true.
//   5. Exactly one true is returned per gap event.
//   6. Candidate is cleared immediately on resumption.
//
// Rules (from section 5.2 of the scheduling plan):
//   - Do not emit for initial silence before the first active audio.
//   - Do not emit while audio remains below threshold.
//   - Do not emit for a gap shorter than required_gap_seconds.
//   - Emit once when audio resumes after a qualifying gap.
//   - Reset all state when capturing stops.
//
// All state is private to the process thread; no locking is needed.
// =============================================================================

class TrackGapDetector
{
public:
    void reset()
    {
        _state         = State::Idle;
        _silence_start = 0.0;
        _seen_audio    = false;
        _last_gap      = 0.0;
    }

    // Discard any in-progress gap candidate without resetting _seen_audio.
    // Called when track_change_silence_seconds changes mid-capture so that a
    // partial gap measured against the old threshold does not fire spuriously.
    void clear_candidate()
    {
        _state         = State::Idle;
        _silence_start = 0.0;
    }

    // Returns true the moment audio resumes after a qualifying gap.
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
            _seen_audio    = true;
            bool fire      = (_state == State::QualifyingGap);
            if (fire)
                _last_gap = now_seconds - _silence_start;
            _state         = State::Idle;
            return fire;
        }

        // Below threshold from here on.
        if (!_seen_audio)
            return false;  // no active audio yet; ignore initial silence

        if (_state == State::Idle)
        {
            _state         = State::BelowCounting;
            _silence_start = now_seconds;
        }

        if (_state == State::BelowCounting &&
            (now_seconds - _silence_start) >= required_gap_seconds)
        {
            _state = State::QualifyingGap;
        }

        return false;
    }

    // Duration of the most recently detected gap (seconds).
    // Valid after update() returns true; undefined otherwise.
    double last_gap_seconds() const { return _last_gap; }

private:
    enum class State { Idle, BelowCounting, QualifyingGap };

    State  _state         = State::Idle;
    double _silence_start = 0.0;
    bool   _seen_audio    = false;
    double _last_gap      = 0.0;
};
