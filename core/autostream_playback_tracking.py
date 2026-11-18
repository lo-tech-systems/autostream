"""autostream_playback_tracking -- the playback tracker's glue.

The tracker is built from the configuration, kept in step with each input's
settings, published as the playback part (hours and maintenance flags), and
reset when a part is serviced. Binds the rows for resetting a service counter
and for handing an input's playback settings to the tracker.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
import threading
from typing import Optional

import autostream_runtime as runtime
import autostream_state
from autostream_bluetooth_client import classify_loopback_hw
from autostream_intents.table import Intent, Outcome, bind
from autostream_playback_stats import (
    MaintenanceResetResult,
    PlaybackInputConfig,
    PlaybackSnapshot,
    PlaybackTracker,
)

_OWNER = "autostream_playback_tracking"


def _playback_input_configs_from_config(cfg) -> dict[int, PlaybackInputConfig]:
    return {
        1: PlaybackInputConfig.normalized(
            enabled=cfg.audio1_enabled,
            is_turntable=cfg.audio1.is_turntable,
            is_bluetooth=classify_loopback_hw(cfg.audio1.capture_device) == "capture",
            stylus_life_hours=cfg.audio1.stylus_life_hours,
            belt_life_hours=cfg.audio1.belt_life_hours,
            belt_life_years=cfg.audio1.belt_life_years,
            bearing_life_hours=cfg.audio1.bearing_life_hours,
            bearing_life_years=cfg.audio1.bearing_life_years,
            input_type=cfg.audio1.input_type,
        ),
        2: PlaybackInputConfig.normalized(
            enabled=cfg.audio2_enabled,
            is_turntable=cfg.audio2.is_turntable,
            is_bluetooth=classify_loopback_hw(cfg.audio2.capture_device) == "capture",
            stylus_life_hours=cfg.audio2.stylus_life_hours,
            belt_life_hours=cfg.audio2.belt_life_hours,
            belt_life_years=cfg.audio2.belt_life_years,
            bearing_life_hours=cfg.audio2.bearing_life_hours,
            bearing_life_years=cfg.audio2.bearing_life_years,
            input_type=cfg.audio2.input_type,
        ),
    }


def ensure_playback_tracker(cfg) -> Optional[PlaybackTracker]:
    try:
        if runtime._playback_tracker is None:
            runtime._playback_tracker = PlaybackTracker()
        runtime._playback_tracker.replace_input_configs(_playback_input_configs_from_config(cfg))
    except Exception as e:
        logging.warning("Playback tracker unavailable: %s", e)
        runtime._playback_tracker = None

    publish_playback()
    return runtime._playback_tracker


_playback_writer = autostream_state.store().claim("playback", _OWNER)
# Held across read-and-publish, so of two concurrent publishers the one that
# publishes last also read last.
_playback_publish_lock = threading.Lock()


def _read_playback_snapshot() -> PlaybackSnapshot:
    tracker = runtime._playback_tracker
    if tracker is None:
        return autostream_state.empty_playback_snapshot()
    try:
        return tracker.snapshot()
    except Exception as e:
        logging.warning("Could not read playback snapshot: %s", e)
        return autostream_state.empty_playback_snapshot()


def publish_playback() -> None:
    """Publish the tracker's current hours and maintenance flags as the
    playback part. Readers see the value as of the last publish: the tracker
    accumulates seconds between poll cycles, so it is at most one cycle old."""
    with _playback_publish_lock:
        pending = _playback_writer.publish(_read_playback_snapshot())
    pending.notify()


def _reset_input(input_index: int, method_name: str, item_name: str) -> MaintenanceResetResult:
    tracker = runtime._playback_tracker
    if tracker is None:
        return MaintenanceResetResult(applied=False, persisted=False)
    try:
        result = getattr(tracker, method_name)(int(input_index))
    except Exception as e:
        logging.warning("Could not reset %s for input %s: %s", item_name, input_index, e)
        return MaintenanceResetResult(applied=False, persisted=False)
    publish_playback()
    return result


def reset_input_stylus(input_index: int) -> MaintenanceResetResult:
    return _reset_input(input_index, "reset_stylus", "stylus")


def reset_input_belt(input_index: int) -> MaintenanceResetResult:
    return _reset_input(input_index, "reset_belt", "belt")


def reset_input_bearing(input_index: int) -> MaintenanceResetResult:
    return _reset_input(input_index, "reset_bearing", "bearing")


def update_playback_input_config(
    input_index: int,
    *,
    enabled: bool,
    is_turntable: bool,
    input_type: str,
    is_bluetooth: bool = False,
    stylus_life_hours: int,
    belt_life_hours: int = 0,
    belt_life_years: int = 0,
    bearing_life_hours: int = 0,
    bearing_life_years: int = 0,
) -> bool:
    tracker = runtime._playback_tracker
    if tracker is None:
        return False
    try:
        tracker.update_input_config(
            int(input_index),
            enabled=enabled,
            is_turntable=is_turntable,
            is_bluetooth=is_bluetooth,
            stylus_life_hours=stylus_life_hours,
            belt_life_hours=belt_life_hours,
            belt_life_years=belt_life_years,
            bearing_life_hours=bearing_life_hours,
            bearing_life_years=bearing_life_years,
            input_type=input_type,
        )
        publish_playback()
        return True
    except Exception as e:
        logging.warning(
            "Could not update playback config for input %s: %s",
            input_index,
            e,
        )
        return False


def _counters_reset(intent: Intent, wait: float) -> Outcome:
    fn = {
        "stylus": reset_input_stylus,
        "belt": reset_input_belt,
        "bearing": reset_input_bearing,
    }[intent.args["item"]]
    result = fn(int(intent.args["input"]))
    return Outcome(
        ok=bool(result.applied),
        error=None if result.applied else "not_applied",
        result={"reset": result},
    )


def _playback_config_set(intent: Intent, wait: float) -> Outcome:
    args = dict(intent.args)
    index = int(args.pop("input"))
    updated = update_playback_input_config(index, **args)
    return Outcome(ok=True, result={"updated": bool(updated)})


bind("input.counters.reset", _counters_reset, owner=_OWNER)
bind("input.playback_config.set", _playback_config_set, owner=_OWNER)
