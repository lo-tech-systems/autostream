"""tests/test_track_part.py

Track identification as a part of the state snapshot: each monitor publishes
its own entry under its identification lock and the change reaches
subscribers after that lock is released.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_core as core
import autostream_runtime as runtime
import autostream_state as state
from autostream_audio_monitor import AudioMonitor
from track_id.models import (
    STATE_DISABLED,
    STATE_IDENTIFIED,
    STATE_WAITING,
    TrackIdentificationSnapshot,
    disabled_snapshot,
)
import autostream_input_status as input_status
import autostream_audio_monitor as audio_monitor


def make_monitor(index=1, **overrides) -> AudioMonitor:
    defaults = dict(
        input_index=index, input_device="hw:0,0", silence_threshold_dbfs=-50.0,
        silence_seconds=5, fifo_path="/tmp/test.fifo",
        owntone_base_url="http://localhost:3689", owntone_output_name="Speaker A",
        owntone_volume_percent=50, dynamic_rate_matching=False,
    )
    defaults.update(overrides)
    with patch("autostream_audio_monitor.PersistentNowPlayingCache") as cache, \
         patch("autostream_audio_monitor.get_shared_metadata_publisher") as pub:
        cache.return_value.get_manual_hint.return_value = None
        pub.side_effect = lambda path: MagicMock()
        return AudioMonitor(**defaults)


def service():
    svc = MagicMock()
    svc.analysis_lead_in_seconds = 5
    svc.snapshot_seconds = 15
    return svc


def identified(title="Blue in Green"):
    return TrackIdentificationSnapshot(
        enabled=True, state=STATE_IDENTIFIED, status_text="Identified",
        title=title, artist="Miles Davis")


def track():
    return state.store().snapshot().track


def collect():
    seen = []
    state.store().subscribe(seen.append)
    return seen


def test_the_part_starts_with_no_entries_and_no_service():
    assert track() == state.TrackPart()
    assert track().entries == {}
    assert track().service_enabled is False


def test_a_new_monitor_publishes_its_disabled_entry():
    mon = make_monitor(2)
    assert track().entries[2] == disabled_snapshot()
    assert track().entries[2] is mon._ti_snapshot or track().entries[2] == mon._ti_snapshot


def test_entries_are_kept_per_input():
    first = make_monitor(1)
    second = make_monitor(2)
    with first._ti_locked():
        first._set_ti_snapshot(identified("One"))
    with second._ti_locked():
        second._set_ti_snapshot(identified("Two"))
    assert track().entries[1].title == "One"
    assert track().entries[2].title == "Two"
    assert state.track_for_input(state.store().snapshot(), 1).title == "One"
    assert state.track_for_input(state.store().snapshot(), 9).state == STATE_DISABLED


def test_setting_a_snapshot_outside_the_lock_is_refused():
    mon = make_monitor(1)
    with pytest.raises(AssertionError):
        mon._set_ti_snapshot(identified())


def test_the_change_is_delivered_after_the_lock_is_released():
    mon = make_monitor(1)
    held = []
    state.store().subscribe(lambda change: held.append(mon._ti_state_lock.locked()))
    with mon._ti_locked():
        mon._set_ti_snapshot(identified())
        assert held == []
    assert held == [False]


def test_two_assignments_under_one_lock_are_published_in_order_and_delivered_together():
    mon = make_monitor(1)
    seen = collect()
    with mon._ti_locked():
        mon._set_ti_snapshot(identified("First"))
        mon._set_ti_snapshot(identified("Second"))
        assert seen == []
    assert [c.parts for c in seen] == [frozenset({"track"}), frozenset({"track"})]
    assert track().entries[1].title == "Second"


def test_an_exception_in_the_block_still_releases_the_lock_and_delivers():
    mon = make_monitor(1)
    seen = collect()
    with pytest.raises(RuntimeError):
        with mon._ti_locked():
            mon._set_ti_snapshot(identified())
            raise RuntimeError("boom")
    assert not mon._ti_state_lock.locked()
    assert len(seen) == 1
    assert mon._ti_lock_owner is None


def test_applying_a_service_publishes_the_waiting_entry():
    mon = make_monitor(1)
    mon._apply_track_id_service(service())
    assert track().entries[1].state == STATE_WAITING
    mon._apply_track_id_service(None)
    assert track().entries[1].state == STATE_DISABLED


def test_the_service_flag_is_published_when_the_service_is_rebuilt():
    seen = collect()
    audio_monitor.publish_track_service(True)
    assert track().service_enabled is True
    assert [c.parts for c in seen] == [frozenset({"track"})]
    audio_monitor.publish_track_service(True)
    assert len(seen) == 1
    audio_monitor.publish_track_service(False)
    assert track().service_enabled is False


def test_the_active_track_follows_the_part_and_the_inputs():
    mon = make_monitor(1)
    mon.is_capturing = True
    with mon._ti_locked():
        mon._set_ti_snapshot(identified())
    input_status.publish_inputs()
    audio_monitor.publish_track_service(True)
    assert state.active_track(state.store().snapshot()).title == "Blue in Green"
    mon.is_capturing = False
    input_status.publish_inputs()
    assert state.active_track(state.store().snapshot()).state == STATE_WAITING
    audio_monitor.publish_track_service(False)
    assert state.active_track(state.store().snapshot()).state == STATE_DISABLED


def test_a_snapshot_that_moves_nothing_shown_publishes_no_change():
    mon = make_monitor(1)
    with mon._ti_locked():
        mon._set_ti_snapshot(identified())
    seen = collect()
    with mon._ti_locked():
        mon._set_ti_snapshot(identified())
    assert seen == []
