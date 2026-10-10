// =============================================================================
// autostream_input_activity.h
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Rules that follow from the input type the coordinator names in
// configure_input ("turntable", "cd" or "line"; empty when it sent none).
//
// Included by autostream_monitor.h and by unit tests (which cannot depend on
// ALSA or libsamplerate).  Has no external dependencies beyond <string>.
// =============================================================================

#pragma once

#include <string>

// Whether a live edge on this input gets the short replay-interrupt
// probation window. A named type decides it outright; with no type the
// silence threshold is compared with the boundary older releases used.
inline bool input_type_immediate_interrupt(const std::string& input_type,
                                           float silence_threshold_dbfs,
                                           float boundary_dbfs)
{
    if (input_type.empty())
        return silence_threshold_dbfs <= boundary_dbfs;
    return input_type != "turntable";
}

// Whether the activity gate below applies: every named type except "cd"
// (a CD's silence is digital, so there is nothing to smooth); off when the
// coordinator named no type.
inline bool input_type_activity_gated(const std::string& input_type)
{
    return !input_type.empty() && input_type != "cd";
}

// Accumulates the time an input has spent at or above its silence
// threshold while it is not yet active. Fed only with qualifying blocks:
// blocks below the threshold are not fed and reset nothing, so a quiet
// passage whose peaks straddle the threshold still accumulates. The
// running total restarts when more than kWindowSeconds have passed since
// the block that opened it.
class ActivityGate
{
public:
    static constexpr double kRequiredSeconds = 0.060;
    static constexpr double kWindowSeconds   = 1.0;

    void reset()
    {
        _open          = false;
        _window_start  = 0.0;
        _above_seconds = 0.0;
    }

    // Returns true on the call that completes the requirement, and resets
    // itself on that call.
    bool on_block(double now_seconds, double block_seconds)
    {
        if (!_open || now_seconds - _window_start > kWindowSeconds)
        {
            _open          = true;
            _window_start  = now_seconds;
            _above_seconds = 0.0;
        }
        _above_seconds += block_seconds;
        if (_above_seconds >= kRequiredSeconds)
        {
            reset();
            return true;
        }
        return false;
    }

private:
    bool   _open          = false;
    double _window_start  = 0.0;   // monotonic seconds of the block that opened the window
    double _above_seconds = 0.0;
};
