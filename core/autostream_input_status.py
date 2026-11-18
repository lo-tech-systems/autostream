"""autostream_input_status -- each input's level item, its two Setup rate texts
and the sample-rate mismatch banner, published as the inputs part from the
running monitors.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import threading
from typing import Optional

import autostream_runtime as runtime
import autostream_state


SAMPLE_RATE_MISMATCH_BANNER_TEXT = "Sample Rate Mismatch: Please enable Dynamic Rate Matching"


RATE_MATCHING_NOTE_MONITOR_OLD = (
    "The audio monitor on this appliance needs updating before this setting "
    "takes effect."
)


def _rate_matching_note_for(mon: Optional["AudioMonitor"]) -> str:
    if mon is None:
        return autostream_state.RATE_MATCHING_NOTE_DEFAULT
    if mon.dynamic_rate_matching and mon.monitor_dynamic_rate_matching is None:
        return RATE_MATCHING_NOTE_MONITOR_OLD
    if not mon.dynamic_rate_matching and mon.rate_mismatch_hz > 0:
        return (
            f"This input is delivering {autostream_state.format_khz(mon.rate_mismatch_hz)} but the "
            f"device was opened at {autostream_state.format_khz(mon.negotiated_hz)}. Turn this on "
            f"to follow the source."
        )
    return autostream_state.RATE_MATCHING_NOTE_DEFAULT


def _sample_rate_text_for(mon: Optional["AudioMonitor"], connected: bool) -> str:
    if mon is None or not connected or not mon.rate_lock:
        return autostream_state.SAMPLE_RATE_TEXT_NOT_RUNNING
    # A non-breaking space keeps each rate with its unit when the line wraps
    # on a narrow screen; autostream_state.format_khz itself keeps its plain space.
    def keep_unit(text: str) -> str:
        return text.replace(" ", "\u00a0")

    opened = autostream_state.format_khz(mon.negotiated_hz)
    if mon.rate_mismatch_hz > 0 and opened:
        return (
            f"Sample rate: {keep_unit(opened)} (source is sending "
            f"{keep_unit(autostream_state.format_khz(mon.rate_mismatch_hz))})"
        )
    if mon.rate_lock == "acquiring":
        return "Sample rate: checking"
    running = autostream_state.format_khz(mon.detected_hz)
    if not running:
        return autostream_state.SAMPLE_RATE_TEXT_NOT_RUNNING
    # Compared as text so a device that opens at 47999 Hz still reads as
    # 48 kHz and is not taken for a rate step.
    if opened and opened != running:
        return (
            f"Sample rate: {keep_unit(running)} "
            f"(device opened at {keep_unit(opened)})"
        )
    return f"Sample rate: {keep_unit(running)}"


_inputs_writer = autostream_state.store().claim("inputs", "autostream_input_status")
# Held across read-build-publish, so of two concurrent publishers the one that
# publishes last also read last.
_inputs_publish_lock = threading.Lock()


def _build_inputs_part(monitors: list, connected: bool) -> "autostream_state.InputsPart":
    """The inputs part from the running monitors: each input's Web UI level
    item (sourced from the most recent status poll cached in its AudioMonitor,
    so at most one poll interval stale), its two Setup rate texts, and the
    sample-rate mismatch banner."""
    entries = []
    for mon in monitors:
        level = {
            "index": int(mon.input_index),
            "label": f"Input {mon.input_index}",
            "dbfs": round(mon.poll_peak_dbfs, 1),
            "detected_hz": round(mon.detected_hz, 1),
            "detected_khz": autostream_state.format_khz(mon.detected_hz),
            "negotiated_hz": mon.negotiated_hz,
            "rate_lock": mon.rate_lock,
            "relock_count": mon.relock_count,
            "rate_mismatch_hz": mon.rate_mismatch_hz,
            "rate_mismatch_khz": autostream_state.format_khz(mon.rate_mismatch_hz),
            "dynamic_rate_matching": mon.dynamic_rate_matching,
            "monitor_supports_rate_matching": mon.monitor_dynamic_rate_matching is not None,
            "is_above_threshold": not mon.is_silent,
            "vu_history": mon.vu_history,
        }
        entries.append(autostream_state.InputEntry(
            index=int(mon.input_index),
            device=mon.input_device,
            input_type=mon.input_type,
            capturing=bool(mon.is_capturing),
            replay_origin=bool(mon._replay_origin),
            rate_note=_rate_matching_note_for(mon),
            sample_rate_text=_sample_rate_text_for(mon, connected),
            rate_mismatch_hz=int(mon.rate_mismatch_hz),
            level=level,
        ))
    # The lowest-numbered input whose monitor reports a different standard
    # rate than it was opened at, or 0. The daemon reports a mismatch only
    # while its own Dynamic Rate Matching flag is off, so no test of the
    # coordinator's copy of the flag is needed: after a successful push the
    # daemon steps and clears the report within a window, and after a failed
    # push the report (and the banner) correctly stays.
    mismatch = next(
        (m.input_index for m in sorted(monitors, key=lambda m: m.input_index)
         if m.rate_mismatch_hz > 0),
        0,
    )
    return autostream_state.InputsPart(
        entries=tuple(entries),
        sample_rate_mismatch_input=mismatch,
        # The text names neither the input nor the rates; the banner's link
        # identifies the input.
        sample_rate_warning_text=SAMPLE_RATE_MISMATCH_BANNER_TEXT if mismatch else "",
    )


def publish_inputs() -> None:
    """Rebuild the inputs part from the monitors and the monitor part. Both
    are read inside the lock, so of two concurrent publishers the one that
    publishes last also read last (no older 'connected' overwriting a newer
    one). The change is delivered after the lock is released."""
    with _inputs_publish_lock:
        monitors = runtime.monitors_snapshot()
        connected = autostream_state.store().snapshot().monitor.connected
        pending = _inputs_writer.publish(_build_inputs_part(monitors, connected))
    pending.notify()
