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

// The input's "Start after" setting: how much time at or above the
// threshold the activity gate needs, in milliseconds.
inline constexpr int kStartAfterDefaultMs = 60;
inline constexpr int kStartAfterMinMs     = 30;
inline constexpr int kStartAfterMaxMs     = 250;

// What one window of the activity gate counted.
struct ActivityGateReport
{
    double above_seconds = 0.0;   // time in the counted blocks
    double span_seconds  = 0.0;   // start of the window's first block to the end of its last counted one
    float  peak          = 0.0f;  // highest counted block peak, linear full scale
    double mean_square   = 0.0;   // time-weighted mean power of the counted blocks, linear full scale
    int    blocks        = 0;
};

// Accumulates the time an input has spent at or above its silence
// threshold while it is not yet active. Fed only with qualifying blocks:
// blocks below the threshold are not fed and reset nothing, so a quiet
// passage whose peaks straddle the threshold still accumulates. The
// running total restarts when more than kWindowSeconds have passed since
// the block that opened it. Block times are taken at the end of each
// block, so a window starts one block length before its first time.
class ActivityGate
{
public:
    static constexpr double kWindowSeconds = 1.0;

    // Sets how much time the gate needs, and discards any running total.
    void set_required_seconds(double seconds)
    {
        _required_seconds = seconds;
        reset();
    }

    double required_seconds() const { return _required_seconds; }

    void reset()
    {
        _open        = false;
        _window_open = 0.0;
        _report      = ActivityGateReport{};
        _power_time  = 0.0;
    }

    // Closes a window that has run past kWindowSeconds without completing
    // the requirement. Returns true, with what it counted, when one was open.
    bool expire(double now_seconds, ActivityGateReport& out)
    {
        if (!_open || now_seconds - _window_open <= kWindowSeconds)
            return false;
        out = finished_report();
        reset();
        return true;
    }

    // Counts one block at or above the threshold. Returns true on the call
    // that completes the requirement, with that window in `out`, and resets.
    bool on_block(double now_seconds, double block_seconds,
                  float peak, double mean_square, ActivityGateReport& out)
    {
        if (!_open || now_seconds - _window_open > kWindowSeconds)
        {
            reset();
            _open        = true;
            _window_open = now_seconds;
            _first_block = block_seconds;
        }
        _report.above_seconds += block_seconds;
        _report.span_seconds   = now_seconds - _window_open + _first_block;
        _report.blocks        += 1;
        if (peak > _report.peak)
            _report.peak = peak;
        _power_time += mean_square * block_seconds;

        if (_report.above_seconds >= _required_seconds)
        {
            out = finished_report();
            reset();
            return true;
        }
        return false;
    }

private:
    ActivityGateReport finished_report() const
    {
        ActivityGateReport r = _report;
        r.mean_square = (r.above_seconds > 0.0) ? _power_time / r.above_seconds : 0.0;
        return r;
    }

    double             _required_seconds = kStartAfterDefaultMs / 1000.0;
    bool               _open             = false;
    double             _window_open      = 0.0;   // monotonic seconds of the block that opened the window
    double             _first_block      = 0.0;   // that block's length
    double             _power_time       = 0.0;   // sum of mean square x block seconds
    ActivityGateReport _report;
};

// Why an input became active on a block, or why a gate window closed
// without it, for the debug log. Ungated carries the one block that made
// an ungated input active. None on every other block.
struct ActivityStartReport
{
    enum class Kind { None, Fired, Expired, Ungated };

    Kind               kind = Kind::None;
    ActivityGateReport gate;
};
