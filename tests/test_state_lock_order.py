"""tests/test_state_lock_order.py

The lock-order rules of the state store, checked with recording locks:

  1. Nothing is acquired while the store lock is held.
  3. No subscriber is called while the calling thread holds the store lock or
     a domain lock.
  5. The function given to update() takes no lock.

and, for each part owner, that the owner's own lock is released before its
change reaches a subscriber.

The output authority adds, with its two locks ranked apply (10) below
authority (20):

  6. The authority lock is never held when the apply lock is requested.
  7. With threads, only the apply thread takes the apply lock.
  8. No call to the player is made while the authority lock is held.
  9. No subscriber is called while either authority lock is held.
 10. submit() holds no lock when it calls a handler.
 11. The authority calls the policy with no authority lock held.
 12. The event source thread takes no authority lock; it only enqueues.
 13. The policy holds no lock across an authority call, a submit or anything
     that reaches the player.
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
from output_fakes import FakeBackend, FakeSource, group_row, row
from autostream_state import SessionPart, SettingsPart
from autostream_state.store import StateStore
import autostream_playback_tracking as playback_tracking
import autostream_input_status as input_status
import autostream_audio_monitor as audio_monitor
import webui.protocol.hub as proto_hub


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
         patch("autostream_repeat._announce_replay_playing"):
        repeat.apply_repeat_ack({"ok": True, "command": "set_repeat_armed",
                                 "state": "replaying", "armed": True,
                                 "position_seconds": 0.0})
    assert len(seen) >= 3
    assert all(held == frozenset() for held in seen)
    assert lockcheck.ACQUIRED_UNDER_STORE == []
    assert tracked_singleton.lock_violations == []


def test_the_inputs_publish_lock_is_released_before_subscribers_run(tracked_singleton, monkeypatch):
    import autostream_core as core

    monkeypatch.setattr(input_status, "_inputs_publish_lock", lockcheck.TrackedLock("inputs"))
    monkeypatch.setattr(core.runtime, "_monitors_lock", lockcheck.TrackedLock("monitors"))
    seen = []
    tracked_singleton.subscribe(lambda change: seen.append(lockcheck.held()))
    core._set_monitor_runtime_info(connected=True)
    input_status.publish_inputs()
    assert seen and all(held == frozenset() for held in seen)
    assert lockcheck.ACQUIRED_UNDER_STORE == []
    assert tracked_singleton.lock_violations == []


def test_the_playback_publish_lock_is_released_before_subscribers_run(tracked_singleton, monkeypatch):
    import autostream_core as core

    monkeypatch.setattr(playback_tracking, "_playback_publish_lock", lockcheck.TrackedLock("playback"))
    seen = []
    tracked_singleton.subscribe(lambda change: seen.append(lockcheck.held()))
    monkeypatch.setattr(playback_tracking, "_read_playback_snapshot", lambda: _playback_with_flag())
    playback_tracking.publish_playback()
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

    with patch("autostream_audio_monitor.PersistentNowPlayingCache") as cache, \
         patch("autostream_audio_monitor.get_shared_metadata_publisher") as pub:
        cache.return_value.get_manual_hint.return_value = None
        pub.side_effect = lambda path: MagicMock()
        mon = audio_monitor.AudioMonitor(
            input_index=1, input_device="hw:0,0", silence_threshold_dbfs=-50.0,
            silence_seconds=5, fifo_path="/tmp/test.fifo",
            owntone_base_url="http://localhost:3689")
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


def test_the_settings_lock_is_released_before_the_generation_reaches_subscribers(tracked_singleton, tmp_path):
    import json

    import autostream_core as core
    from autostream_settings import SettingsStore

    p = tmp_path / "cfg.json"
    p.write_text(json.dumps({}))
    s = SettingsStore(str(p), _save_interval_seconds=60.0, _writer=lambda path, data: None)
    try:
        s._lock = lockcheck.TrackedLock("settings")
        s.add_commit_hook(core._publish_settings_generation)
        seen = []
        tracked_singleton.subscribe(lambda change: seen.append((lockcheck.held(), s._lock.locked())))
        s.update(lambda raw: raw.update(x=1))
        assert seen and all(held == frozenset() and not locked for held, locked in seen)
        assert lockcheck.ACQUIRED_UNDER_STORE == []
        assert tracked_singleton.lock_violations == []
    finally:
        s.close(save=False)


# ---------------------------------------------------------------------------
# The output authority
# ---------------------------------------------------------------------------

@pytest.fixture
def authority(tracked_singleton):
    """The output authority with ranked, recording locks, a backend that checks
    its calls, and a subscriber that records what the notifying thread holds."""
    from autostream_state.outputs import get_authority
    a = get_authority()
    a.install_locks_for_tests(
        apply_lock=lockcheck.TrackedLock("apply", rank=10),
        lock=lockcheck.TrackedLock("authority", rank=20),
    )
    backend = FakeBackend(a)
    a.start(backend)
    held_when_told = []
    tracked_singleton.subscribe(lambda change: held_when_told.append(lockcheck.held()))
    a.backend_for_test = backend
    a.held_when_told = held_when_told
    yield a
    a.backend_for_test = None


def _every_intent(a, merge):
    """All the intents, in an order that lets each do something."""
    from autostream_state import Origin
    merge([row(1, selected=True, volume_percent=40), row(2, selected=True, volume_percent=50), row(3)])
    a.select("3", Origin.USER, volume=20)
    a.set_volume("1", 60, Origin.USER)
    a.step_volume(5, Origin.USER, default_level=50, requester="dial:x")
    a.mute_all(Origin.USER)
    a.unmute_all(Origin.USER, default_level=50)
    a.mute("1", Origin.POLICY)
    a.unmute("1", Origin.POLICY, default_level=50)
    a.mute("1", Origin.DEVICE)
    a.unmute("1", Origin.DEVICE, default_level=0, only_token=1)
    a.reselect("1", Origin.USER)
    a.deselect("3", Origin.USER)
    a.submit_pin("3", "1234")
    a.note_session(True)
    a.deselect_all(Origin.USER)
    a.deselect_all(Origin.SESSION)
    a.note_session(False)


def test_an_intent_takes_the_authority_lock_before_the_store_lock_and_notifies_after(authority):
    a = authority
    _every_intent(a, lambda rows: a.merge_for_tests(rows, boot="b0"))
    assert a.held_when_told, "the subscriber was never told"
    assert all(h == frozenset() for h in a.held_when_told)
    assert lockcheck.ACQUIRED_UNDER_STORE == []
    assert state.store().lock_violations == []
    assert lockcheck.ORDER_VIOLATIONS == []


def test_the_apply_lock_is_never_requested_under_the_authority_lock(authority):
    a = authority
    _every_intent(a, lambda rows: a.merge_for_tests(rows, boot="b0"))
    a.backend_for_test.rows = [row(1, selected=True), row(2)]
    a.on_outputs_changed()
    a.select("2", state.Origin.USER, volume=30)
    for i in range(6):
        a.step(now=2000.0 + 3 * i)
    assert "apply" in lockcheck.ACQUIRED_BY
    assert lockcheck.ORDER_VIOLATIONS == []


def test_the_detector_sees_the_wrong_order(authority):
    a = authority
    with a._lock:
        with a._apply_lock:
            pass
    assert lockcheck.ORDER_VIOLATIONS == [("apply", frozenset({"authority"}))]


def test_only_the_apply_thread_takes_the_apply_lock_when_started(authority, monkeypatch):
    import time
    import autostream_state.outputs as outputs
    from autostream_state import Origin
    a = authority
    monkeypatch.setattr(outputs, "_threads_allowed", True)
    a._source_factory = lambda info, base_url, *, poll_interval: FakeSource()
    a.backend_for_test.rows = [row(1, selected=True, volume_percent=40), row(2)]
    a.start(a.backend_for_test)
    try:
        deadline = time.monotonic() + 5
        while not state.store().snapshot().outputs.connected and time.monotonic() < deadline:
            time.sleep(0.01)
        applied = [
            a.select("2", Origin.USER, volume=30),
            a.set_volume("1", 70, Origin.USER),
            a.deselect("2", Origin.USER),
        ]
        for x in applied:
            x.outcome.result(5)
    finally:
        a.stop(timeout=5.0)
    assert lockcheck.ACQUIRED_BY["apply"] == {"outputs-apply"}
    assert len(lockcheck.ACQUIRED_BY["authority"]) >= 2      # the worker and the callers
    assert lockcheck.ORDER_VIOLATIONS == []


def test_no_backend_call_is_made_under_the_authority_lock(authority):
    """The fake backend asserts it in every method; run every kind of call."""
    a = authority
    backend = a.backend_for_test
    backend.rows = [row(1, selected=True, volume_percent=40), group_row(2, "stopped")]
    a._events_enabled = True
    a._source_factory = lambda info, base_url, *, poll_interval: FakeSource()
    a.on_outputs_changed()
    a.step(now=100.0)                     # a probe and a read
    _every_intent(a, lambda rows: a.merge_for_tests(rows, boot="b0"))
    for i in range(8):
        a.step(now=200.0 + 3 * i)         # timers and a reconcile
    kinds = {c[0] for c in backend.calls}
    assert {"update_output", "set_selected_outputs", "stop_and_disable_all",
            "submit_output_pin"} <= kinds
    assert backend.reads >= 1 and backend.channel_calls >= 1


def test_a_merge_notifies_after_the_authority_lock_is_released(authority):
    a = authority
    a.backend_for_test.rows = [row(1, selected=True)]
    a.on_outputs_changed()
    a.step(now=100.0)
    assert a.held_when_told and all(h == frozenset() for h in a.held_when_told)
    assert state.store().lock_violations == []


def test_the_policy_is_told_with_no_authority_lock_held(authority):
    from autostream_backend_events import DeviceEvent

    a = authority
    held = []

    class Recorder:
        def on_device_event(self, ev, outputs, now):
            held.append(("event", lockcheck.held()))

        def on_timer(self, now, outputs):
            held.append(("timer", lockcheck.held()))

        def next_deadline(self):
            held.append(("deadline", lockcheck.held()))
            return None

        def on_session(self, active):
            held.append(("session", lockcheck.held()))

    a.set_policy(Recorder())
    a.merge_for_tests([row(1, selected=True, volume_percent=40)], boot="b0")
    a.note_session(True)
    a.on_device_event(DeviceEvent("receiver_command", "1", None, "paus", None, 1, 1.0))
    a.note_session(False)
    a.step(now=100.0)
    a._next_wait(100.0)
    assert {kind for kind, _ in held} == {"event", "timer", "deadline", "session"}
    assert [kind for kind, _ in held].count("session") == 2
    assert all(h == frozenset() for _, h in held)
    assert lockcheck.ORDER_VIOLATIONS == []
    assert lockcheck.ACQUIRED_UNDER_STORE == []


def test_the_event_thread_only_enqueues(authority):
    a = authority
    from autostream_backend_events import ConnectInfo, DeviceEvent
    done = threading.Event()
    names = []

    def source_thread():
        names.append(threading.current_thread().name)
        a.on_connected(ConnectInfo("b0", 1, frozenset(), "unix_socket"))
        a.on_outputs_changed()
        a.on_device_event(DeviceEvent("device_volume", "1", None, "x", "1", 1, 1.0))
        a.on_disconnected("eof")
        done.set()

    with a._lock:                          # another thread holds the authority lock
        with a._apply_lock:                # and the apply lock
            t = threading.Thread(target=source_thread, name="events-test")
            t.start()
            assert done.wait(2.0), "a sink method waited for an authority lock"
    t.join(2.0)
    assert "events-test" not in lockcheck.ACQUIRED_BY.get("authority", set())
    assert "events-test" not in lockcheck.ACQUIRED_BY.get("apply", set())


def test_submit_holds_no_lock_while_the_handler_runs(tracked_singleton):
    from autostream_intents import validate as v
    from autostream_intents.table import Intent, Outcome, RateLimit, Row, _Table
    row_ = Row(
        name="thing.set", args={"level": v.integer(0, 10, error="bad")},
        required=frozenset({"level"}), origins=frozenset({state.Origin.USER}),
        limit=RateLimit(min_interval_s=1.0),
    )
    tbl = _Table(rows={"thing.set": row_})
    tbl._limit_lock = lockcheck.TrackedLock("limit")
    seen = []
    tbl.bind("thing.set", lambda intent, wait: (seen.append(lockcheck.held()), Outcome(ok=True))[1],
             owner="test")
    reply = tbl.submit(Intent("thing.set", {"level": 3}, state.Origin.USER, "webui"))
    assert reply.ok and seen == [frozenset()]
    assert "limit" in lockcheck.ACQUIRED_BY            # the limiter was taken, and let go


def test_a_burst_of_intents_from_many_threads_breaks_no_rule(authority):
    from autostream_state import Origin
    a = authority
    a.merge_for_tests([row(1, selected=True, volume_percent=40), row(2, selected=True, volume_percent=50)], boot="b0")
    errors = []

    def hammer(n):
        try:
            for i in range(30):
                a.set_volume("1", (n * 7 + i) % 100, Origin.USER)
                a.step_volume(1 if i % 2 else -1, Origin.USER, default_level=50)
                if i % 5 == 0:
                    a.mute_all(Origin.USER)
                else:
                    a.unmute_all(Origin.USER, default_level=50)
        except Exception as exc:       # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=hammer, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(20)
    assert errors == []
    assert lockcheck.ORDER_VIOLATIONS == []
    assert lockcheck.ACQUIRED_UNDER_STORE == []
    assert state.store().lock_violations == []


def test_the_backend_double_notices_a_call_made_under_the_authority_lock(authority):
    with authority._lock:
        with pytest.raises(AssertionError, match="authority lock"):
            authority.backend_for_test.update_output("1", volume_percent=1)


def test_the_settings_cache_parses_outside_its_lock(tracked_singleton, tmp_path, monkeypatch):
    import json
    import autostream_live_config as lc
    from autostream_settings import SettingsStore

    path = tmp_path / "config.json"
    path.write_text(json.dumps({}))
    settings = SettingsStore(str(path), _save_interval_seconds=9999, _writer=lambda p, d: None)
    cache_lock = lockcheck.TrackedLock("settings_cache")
    store_lock = lockcheck.TrackedLock("settings_store")
    monkeypatch.setattr(lc, "_output_settings_lock", cache_lock)
    settings._lock = store_lock
    held_in_snapshot = []
    real = settings.snapshot

    def watching():
        held_in_snapshot.append(lockcheck.held())
        return real()

    settings.snapshot = watching
    try:
        lc.bind_settings_store(settings)
        lc.include_tv_for("1")
        settings.update(lambda r: r.setdefault("outputs", {}).update({"device_pause_scope": "all"}))
        lc.output_policy_settings()
    finally:
        settings.close(save=False)
    assert held_in_snapshot and all("settings_cache" not in h for h in held_in_snapshot)
    assert lockcheck.ORDER_VIOLATIONS == []
    assert lockcheck.ACQUIRED_UNDER_STORE == []


def _watch_authority_calls(a, monkeypatch, held):
    """Record what the calling thread holds at the entry of each authority
    call the policy makes."""
    for name in ("mute", "mute_all", "unmute", "unmute_joined", "deselect", "deselect_all", "unit_marks"):
        real = getattr(a, name)

        def watched(*args, _real=real, _name=name, **kwargs):
            held.append((_name, lockcheck.held()))
            return _real(*args, **kwargs)

        monkeypatch.setattr(a, name, watched)


@pytest.mark.parametrize("scope", ["output", "all", "off_all"])
def test_a_receiver_pause_and_play_break_no_rule(authority, monkeypatch, scope):
    import autostream_output_policy as op
    import autostream_runtime as runtime
    from autostream_backend_events import DeviceEvent
    from autostream_config import OutputsConfig

    a = authority
    monkeypatch.setattr(runtime, "_metadata_push_lock", lockcheck.TrackedLock("metadata_push"))
    pol = op.get_policy()
    pol.bind_settings(lambda: OutputsConfig(device_pause_scope=scope))
    a.set_policy(pol)
    held = []
    _watch_authority_calls(a, monkeypatch, held)
    a.merge_for_tests([row(1, selected=True, volume_percent=40), row(2, selected=True, volume_percent=30)],
                      boot="b0", now=100.0)
    runtime.note_metadata_push(50.0)
    a.note_session(True)
    a.on_device_event(DeviceEvent("receiver_command", "1", "Speaker 1", "paus", None, 1, 100.0))
    a.step(now=100.0)
    a.on_device_event(DeviceEvent("receiver_command", "1", "Speaker 1", "play", None, 2, 200.0))
    a.step(now=200.0)
    a.note_session(False)
    a.step(now=201.0)
    assert {name for name, _ in held} >= {"mute" if scope == "output" else "mute_all" if scope == "all" else "deselect_all"}
    assert all(h == frozenset() for _, h in held)
    assert lockcheck.ORDER_VIOLATIONS == []
    assert lockcheck.ACQUIRED_UNDER_STORE == []


def test_a_pause_timeout_turn_off_breaks_no_rule(authority, monkeypatch):
    import autostream_output_policy as op
    from autostream_backend_events import DeviceEvent
    from autostream_config import OutputsConfig

    a = authority
    pol = op.get_policy()
    pol.bind_settings(lambda: OutputsConfig(device_pause_scope="all"))
    a.set_policy(pol)
    held = []
    _watch_authority_calls(a, monkeypatch, held)
    a.merge_for_tests([row(1, selected=True, volume_percent=40), row(2, selected=True, volume_percent=30)],
                      boot="b0", now=100.0)
    a.on_device_event(DeviceEvent("receiver_command", "1", "Speaker 1", "paus", None, 1, 100.0))
    a.step(now=100.0)
    a.step(now=500.0)
    assert [name for name, _ in held].count("deselect") == 2
    assert all(h == frozenset() for _, h in held)
    assert a.held_when_told and all(h == frozenset() for h in a.held_when_told)
    assert lockcheck.ORDER_VIOLATIONS == []
    assert lockcheck.ACQUIRED_UNDER_STORE == []


def test_the_include_tv_reader_runs_without_the_authority_lock(authority, tmp_path):
    import json
    import autostream_live_config as lc
    from autostream_settings import SettingsStore
    from autostream_state import Origin

    path = tmp_path / "config.json"
    path.write_text(json.dumps({"owntone": {"include_tv": {"1": False}}}))
    settings = SettingsStore(str(path), _save_interval_seconds=9999, _writer=lambda p, d: None)
    held_in_reader = []

    def reader(unit_id):
        held_in_reader.append(lockcheck.held())
        return lc.include_tv_for(unit_id)

    try:
        lc.bind_settings_store(settings)
        authority.set_include_tv_reader(reader)
        authority.merge_for_tests([row(1, selected=True, volume_percent=40)], boot="b0")
        authority.select("1", Origin.USER, volume=30)
        authority.reselect("1", Origin.USER)
    finally:
        lc.bind_settings_store(None)
        settings.close(save=False)
    assert held_in_reader
    assert all(h <= {"apply"} for h in held_in_reader)
    assert lockcheck.ORDER_VIOLATIONS == []


def test_the_stream_hub_takes_only_its_own_condition_and_is_called_with_no_lock_held(st):

    session = st.claim("session", "test_owner")
    hub = proto_hub.StreamHub(st)
    hub._cond = threading.Condition(lockcheck.TrackedLock("stream_hub"))
    hub.start()
    stop = threading.Event()

    def park():
        gen = 0
        while not stop.is_set():
            gen = hub.wait_past(gen, 0.2) or gen

    waiters = [threading.Thread(target=park, daemon=True) for _ in range(8)]
    for t in waiters:
        t.start()
    time.sleep(0.05)
    for i in range(20):
        session.publish(SessionPart(True, f"input{i}")).notify()
    stop.set()
    for t in waiters:
        t.join(3.0)
    hub.stop()
    assert hub.generation() == 20
    assert lockcheck.ACQUIRED_UNDER_STORE == []
    assert st.lock_violations == []
    assert lockcheck.ORDER_VIOLATIONS == []
