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
