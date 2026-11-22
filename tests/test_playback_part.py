"""tests/test_playback_part.py

Playback hours and maintenance flags as a part of the state snapshot: the
coordinator publishes what the tracker reports at each point where it can
change, and readers see the value as of the last publish.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_core as core
import autostream_runtime as runtime
import autostream_state as state
from autostream_config import parse_config
from autostream_playback_stats import PlaybackInputConfig, PlaybackTracker
import autostream_playback_tracking as playback_tracking


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def make_tracker(tmp_path, clock=None) -> PlaybackTracker:
    tracker = PlaybackTracker(stats_path=tmp_path / "ps.json", time_fn=clock or Clock())
    tracker.replace_input_configs({
        1: PlaybackInputConfig.normalized(
            enabled=True, is_turntable=True, stylus_life_hours=1,
            belt_life_hours=100, belt_life_years=1,
            bearing_life_hours=100, bearing_life_years=1),
    })
    runtime._playback_tracker = tracker
    return tracker


def playback():
    return state.store().snapshot().playback


def collect():
    seen = []
    state.store().subscribe(seen.append)
    return seen


def test_the_part_starts_as_the_empty_snapshot():
    assert playback() == state.empty_playback_snapshot()
    assert playback().inputs == {}


def test_without_a_tracker_the_published_snapshot_is_empty():
    runtime._playback_tracker = None
    playback_tracking.publish_playback()
    assert playback() == state.empty_playback_snapshot()


def test_a_tracker_that_fails_publishes_the_empty_snapshot(tmp_path):
    tracker = make_tracker(tmp_path)
    with patch.object(tracker, "snapshot", side_effect=RuntimeError("boom")):
        playback_tracking.publish_playback()
    assert playback() == state.empty_playback_snapshot()


def test_publishing_reflects_the_tracker(tmp_path):
    make_tracker(tmp_path)
    playback_tracking.publish_playback()
    assert set(playback().inputs) == {1}
    assert playback().inputs[1].enabled is True


def test_ensuring_the_tracker_publishes_its_configuration(tmp_path):
    cfg = parse_config({
        "audio1": {"enabled": True, "capture_device": "hw:0,0", "input_type": "turntable",
                   "stylus_life_hours": 500},
        "audio2": {"enabled": False, "capture_device": "hw:1,0", "input_type": "line"},
        "audio3": {"enabled": True, "input_type": "cd"},
    }, high_perf=False)
    with patch("autostream_playback_tracking.PlaybackTracker",
               lambda: PlaybackTracker(stats_path=tmp_path / "ps.json")):
        playback_tracking.ensure_playback_tracker(cfg)
    assert playback().inputs[1].enabled is True
    assert playback().inputs[2].enabled is False
    assert playback().inputs[3].enabled is True
    assert playback().inputs[3].is_bluetooth is True
    assert playback().inputs[1].is_bluetooth is False


def test_a_counter_reset_publishes_before_it_returns(tmp_path):
    clock = Clock()
    tracker = make_tracker(tmp_path, clock)
    tracker.on_playback_started(1)
    tracker.on_wear_started(1)
    clock.now += 7200
    tracker.on_wear_stopped(1)
    tracker.on_playback_stopped(1)
    playback_tracking.publish_playback()
    assert playback().inputs[1].stylus_overdue is True
    result = playback_tracking.reset_input_stylus(1)
    assert result.applied is True
    assert playback().inputs[1].stylus_overdue is False


def test_a_config_update_publishes_before_it_returns(tmp_path):
    make_tracker(tmp_path)
    playback_tracking.publish_playback()
    assert playback().inputs[1].enabled is True
    assert playback_tracking.update_playback_input_config(
        1, enabled=False, is_turntable=True, input_type="turntable",
        stylus_life_hours=500) is True
    assert playback().inputs[1].enabled is False


def test_the_digest_moves_on_a_flag_or_a_whole_minute_only(tmp_path):
    clock = Clock()
    tracker = make_tracker(tmp_path, clock)
    tracker.on_playback_started(1)
    playback_tracking.publish_playback()
    seen = collect()
    clock.now += 20
    playback_tracking.publish_playback()
    assert seen == []
    assert playback().inputs[1].total_playback_seconds >= 19
    clock.now += 60
    playback_tracking.publish_playback()
    assert [c.parts for c in seen] == [frozenset({"playback"})]


def test_a_failed_config_update_without_a_tracker_publishes_nothing():
    runtime._playback_tracker = None
    seen = collect()
    assert playback_tracking.update_playback_input_config(
        1, enabled=True, is_turntable=False, input_type="line",
        stylus_life_hours=0) is False
    assert seen == []
