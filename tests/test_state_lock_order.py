"""tests/test_state_lock_order.py

The lock-order rules of the state store, checked with recording locks:

  1. Nothing is acquired while the store lock is held.
  3. No subscriber is called while the calling thread holds the store lock or
     a domain lock.
  5. The function given to update() takes no lock.

and, for each part owner, that the owner's own lock is released before its
change reaches a subscriber.
"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import lockcheck
import autostream_state as state
from autostream_state import SessionPart, SettingsPart
from autostream_state.store import StateStore


@pytest.fixture
def st():
    s = StateStore()
    s.reset_for_tests(track_locks=True)
    lockcheck.install(s)
    yield s
    lockcheck.uninstall()


@pytest.fixture
def tracked_singleton():
    """The process store with a recording lock, put back afterwards."""
    s = state.store()
    s.reset_for_tests(track_locks=True)
    lockcheck.install(s)
    yield s
    lockcheck.uninstall()
    s._lock = threading.Lock()
    s._cond = threading.Condition(s._lock)


def test_publish_update_and_notify_acquire_nothing_under_the_store_lock(st):
    session = st.claim("session", "test_owner")
    settings = st.claim("settings", "test_owner")
    domain = lockcheck.TrackedLock("domain")
    st.subscribe(lambda change: None)
    with domain:
        pending = session.publish(SessionPart(True, "input1"))
        pending2 = settings.update(lambda cur: SettingsPart(cur.generation + 1))
    pending.notify()
    pending2.notify()
    assert lockcheck.ACQUIRED_UNDER_STORE == []
    assert st.lock_violations == []


def test_the_detector_sees_a_lock_taken_inside_update(st):
    settings = st.claim("settings", "test_owner")
    domain = lockcheck.TrackedLock("domain")

    def fn(cur):
        with domain:
            return SettingsPart(cur.generation + 1)

    settings.update(fn).notify()
    assert lockcheck.ACQUIRED_UNDER_STORE == ["domain"]


def test_subscribers_run_with_no_lock_held_after_the_writers_lock_is_released(st):
    session = st.claim("session", "test_owner")
    domain = lockcheck.TrackedLock("domain")
    held_in_call = []
    st.subscribe(lambda change: held_in_call.append(lockcheck.held()))
    with domain:
        pending = session.publish(SessionPart(True, "input1"))
    pending.notify()
    assert held_in_call == [frozenset()]
    assert st.lock_violations == []


def test_notify_inside_a_domain_lock_is_reported(st):
    session = st.claim("session", "test_owner")
    domain = lockcheck.TrackedLock("domain")
    st.subscribe(lambda change: None)
    with domain:
        session.publish(SessionPart(True, "input1")).notify()
    assert st.lock_violations == [("subscriber called holding", ("domain",))]


def test_a_batch_close_calls_the_subscriber_with_no_lock_held(st):
    session = st.claim("session", "test_owner")
    seen = []
    st.subscribe(lambda change: seen.append(lockcheck.held()))
    with st.batch():
        session.publish(SessionPart(True, "input1")).notify()
    assert seen == [frozenset()]
    assert st.lock_violations == []


def test_wait_for_change_wakes_while_publishers_run(st):
    session = st.claim("session", "test_owner")
    result = []
    t = threading.Thread(target=lambda: result.append(st.wait_for_change(0, 5.0)))
    t.start()
    time.sleep(0.05)
    session.publish(SessionPart(True, "input1")).notify()
    t.join(5)
    assert result and result[0].version == 1
    assert st.lock_violations == []


def test_the_repeat_overlay_lock_is_released_before_subscribers_run(tracked_singleton, monkeypatch):
    from unittest.mock import patch

    import autostream_repeat as repeat

    monkeypatch.setattr(repeat, "_overlay_lock", lockcheck.TrackedLock("overlay"))
    seen = []
    tracked_singleton.subscribe(lambda change: seen.append(lockcheck.held()))
    block = {
        "enabled": True, "armed": False,
        "recording": {"active": False, "seconds": 10.0, "origin_input": 1},
        "replay": {"active": False, "fading_out": False,
                   "position_seconds": 0.0, "duration_seconds": 0.0},
    }
    repeat.publish_from_daemon(block)
    with patch("autostream_repeat._rearm_replay_identification"), \
         patch("autostream_repeat._announce_replay_playing"), \
         patch("autostream_repeat.notify_state_changed"):
        repeat.apply_repeat_ack({"ok": True, "command": "set_repeat_armed",
                                 "state": "replaying", "armed": True,
                                 "position_seconds": 0.0})
    assert len(seen) >= 3
    assert all(held == frozenset() for held in seen)
    assert lockcheck.ACQUIRED_UNDER_STORE == []
    assert tracked_singleton.lock_violations == []


def test_the_inputs_publish_lock_is_released_before_subscribers_run(tracked_singleton, monkeypatch):
    import autostream_core as core

    monkeypatch.setattr(core, "_inputs_publish_lock", lockcheck.TrackedLock("inputs"))
    monkeypatch.setattr(core.runtime, "_monitors_lock", lockcheck.TrackedLock("monitors"))
    seen = []
    tracked_singleton.subscribe(lambda change: seen.append(lockcheck.held()))
    core._set_monitor_runtime_info(connected=True)
    core._publish_inputs()
    assert seen and all(held == frozenset() for held in seen)
    assert lockcheck.ACQUIRED_UNDER_STORE == []
    assert tracked_singleton.lock_violations == []


def test_the_playback_publish_lock_is_released_before_subscribers_run(tracked_singleton, monkeypatch):
    import autostream_core as core

    monkeypatch.setattr(core, "_playback_publish_lock", lockcheck.TrackedLock("playback"))
    seen = []
    tracked_singleton.subscribe(lambda change: seen.append(lockcheck.held()))
    monkeypatch.setattr(core, "_read_playback_snapshot", lambda: _playback_with_flag())
    core._publish_playback()
    assert seen == [frozenset()]
    assert lockcheck.ACQUIRED_UNDER_STORE == []
    assert tracked_singleton.lock_violations == []


def _playback_with_flag():
    import dataclasses

    snap = state.empty_playback_snapshot()
    return dataclasses.replace(snap, stylus_banner_text="Stylus due")


def test_a_monitors_identification_lock_is_released_before_subscribers_run(tracked_singleton):
    from unittest.mock import MagicMock, patch

    import autostream_core as core

    with patch("autostream_core.PersistentNowPlayingCache") as cache, \
         patch("autostream_core.get_shared_metadata_publisher") as pub:
        cache.return_value.get_manual_hint.return_value = None
        pub.side_effect = lambda path: MagicMock()
        mon = core.AudioMonitor(
            input_index=1, input_device="hw:0,0", silence_threshold_dbfs=-50.0,
            silence_seconds=5, fifo_path="/tmp/test.fifo",
            owntone_base_url="http://localhost:3689", owntone_output_name="Speaker A",
            owntone_volume_percent=50)
    mon._ti_state_lock = lockcheck.TrackedLock("identification")
    seen = []
    tracked_singleton.subscribe(
        lambda change: seen.append((lockcheck.held(), mon._ti_state_lock.locked())))
    svc = MagicMock()
    svc.analysis_lead_in_seconds = 1
    svc.snapshot_seconds = 1
    mon._apply_track_id_service(svc)
    mon._apply_track_id_service(None)
    assert seen and all(held == frozenset() and not locked for held, locked in seen)
    assert lockcheck.ACQUIRED_UNDER_STORE == []
    assert tracked_singleton.lock_violations == []
