"""Tests for dial/dial_core.py: snapshot, publish and subscribe."""
import dataclasses
import os
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dial"))

import pytest

from dial_core import DialCore, create_dial_core
from dial_core_state import CoreSnapshot, NowPlaying


def _core(clock=None):
    kwargs = {} if clock is None else {"clock": clock}
    return DialCore("dial-1", **kwargs)


def _tick(core, polling=True, now_playing=None):
    """One publish storing *polling* and *now_playing*."""
    def mutate(state):
        state.polling = polling
        state.now_playing = now_playing
    return core._publish(mutate)


class TestSnapshot:
    def test_initial_snapshot(self):
        core = _core(clock=lambda: 12.5)
        snap = core.snapshot()
        assert isinstance(snap, CoreSnapshot)
        assert snap.seq == 0
        assert snap.at == 12.5
        assert snap.polling is False
        assert snap.dial.uuid == "dial-1"

    def test_snapshot_is_immutable(self):
        snap = _core().snapshot()
        with pytest.raises(dataclasses.FrozenInstanceError):
            snap.seq = 5
        with pytest.raises(dataclasses.FrozenInstanceError):
            snap.focus.manual_id = "x"

    def test_publish_bumps_seq_and_replaces_snapshot(self):
        ticks = iter([1.0, 2.0, 3.0])
        core = _core(clock=lambda: next(ticks))
        first = core.snapshot()
        np = NowPlaying("svc", "a", "t", 40)
        second = _tick(core, now_playing=np)
        third = _tick(core, polling=False)
        assert (first.seq, second.seq, third.seq) == (0, 1, 2)
        assert core.snapshot() is third
        assert second.now_playing == np and second.polling is True
        assert third.now_playing is None and third.polling is False
        assert (first.at, second.at, third.at) == (1.0, 2.0, 3.0)
        # an earlier snapshot is not disturbed by later publishes
        assert second.now_playing == np

    def test_create_dial_core_uses_cfg_uuid(self):
        class Cfg:
            uuid = "abc"
        core = create_dial_core(Cfg())
        assert core.snapshot().dial.uuid == "abc"


class TestSubscribe:
    def test_subscriber_called_per_publish(self):
        core = _core()
        calls = []
        core.subscribe(lambda: calls.append(core.snapshot().seq))
        _tick(core)
        _tick(core)
        assert calls == [1, 2]

    def test_unsubscribe_stops_calls(self):
        core = _core()
        calls = []
        handle = core.subscribe(lambda: calls.append(1))
        _tick(core)
        core.unsubscribe(handle)
        core.unsubscribe(handle)  # unknown handle is ignored
        _tick(core)
        assert calls == [1]

    def test_registration_order(self):
        core = _core()
        order = []
        core.subscribe(lambda: order.append("a"))
        core.subscribe(lambda: order.append("b"))
        _tick(core)
        assert order == ["a", "b"]

    def test_handles_are_distinct(self):
        core = _core()
        assert core.subscribe(lambda: None) != core.subscribe(lambda: None)

    def test_callback_runs_outside_the_lock(self):
        core = _core()
        seen = {}

        def cb():
            # the lock is free: another publish from the callback's thread
            # would deadlock otherwise
            seen["locked"] = core._lock.locked()
        core.subscribe(cb)
        _tick(core)
        assert seen["locked"] is False

    def test_raising_subscriber_does_not_break_publish(self):
        core = _core()
        later = []

        def boom():
            raise RuntimeError("bad subscriber")
        core.subscribe(boom)
        core.subscribe(lambda: later.append(1))
        snap = _tick(core)
        assert snap.seq == 1
        assert later == [1]
        assert core.snapshot() is snap

    def test_slow_subscriber_delays_only_its_own_publisher(self):
        core = _core()
        core.subscribe(lambda: time.sleep(0.2))
        results = {}

        def slow_publisher():
            t0 = time.monotonic()
            _tick(core)
            results["slow"] = time.monotonic() - t0

        t = threading.Thread(target=slow_publisher)
        t.start()
        time.sleep(0.05)
        # while the callback sleeps the core lock is free: reads and a
        # waiter are not held up
        t0 = time.monotonic()
        snap = core.snapshot()
        assert core.wait_for_change(snap.seq - 1, 1.0) is not None
        assert time.monotonic() - t0 < 0.15
        t.join()
        assert results["slow"] >= 0.2

    def test_subscribe_from_a_callback(self):
        core = _core()
        late = []
        core.subscribe(lambda: core.subscribe(lambda: late.append(1)))
        _tick(core)
        _tick(core)
        assert late == [1]


class TestWaitForChange:
    def test_returns_none_on_timeout(self):
        core = _core()
        t0 = time.monotonic()
        assert core.wait_for_change(0, 0.05) is None
        assert time.monotonic() - t0 >= 0.04

    def test_returns_immediately_when_already_newer(self):
        core = _core()
        _tick(core)
        snap = core.wait_for_change(0, 0.0)
        assert snap is not None and snap.seq == 1

    def test_returns_on_publish(self):
        core = _core()
        out = {}

        def waiter():
            out["snap"] = core.wait_for_change(0, 5.0)

        t = threading.Thread(target=waiter)
        t.start()
        time.sleep(0.05)
        _tick(core)
        t.join(2.0)
        assert not t.is_alive()
        assert out["snap"].seq == 1

    def test_does_not_return_for_an_old_seq(self):
        core = _core()
        _tick(core)
        assert core.wait_for_change(1, 0.05) is None


class TestThreadSafety:
    def test_concurrent_reads_during_publishes(self):
        core = _core()
        stop = threading.Event()
        errors = []

        def reader():
            last = -1
            while not stop.is_set():
                snap = core.snapshot()
                if snap.seq < last:
                    errors.append("seq went backwards")
                last = snap.seq
                if snap.polling != (snap.seq % 2 == 1) and snap.seq != 0:
                    errors.append("torn snapshot")

        readers = [threading.Thread(target=reader) for _ in range(4)]
        for r in readers:
            r.start()
        for i in range(500):
            _tick(core, polling=((core.snapshot().seq + 1) % 2 == 1))
        stop.set()
        for r in readers:
            r.join(2.0)
        assert errors == []
        assert core.snapshot().seq == 500

    def test_concurrent_publishers_keep_seq_unique(self):
        core = _core()
        seen = []
        lock = threading.Lock()

        def pub():
            for _ in range(100):
                snap = _tick(core)
                with lock:
                    seen.append(snap.seq)

        threads = [threading.Thread(target=pub) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(5.0)
        assert sorted(seen) == list(range(1, 401))
        assert core.snapshot().seq == 400


# ---------------------------------------------------------------------------
# Appliance model: focus, now-playing, accepted replay, roster and rows
# ---------------------------------------------------------------------------

from dial_core_state import AUTH_AUTHORIZED  # noqa: E402
from dial_test_support import RosterEntry  # noqa: E402
from dial_repeat_store import RepeatRecord  # noqa: E402

AID = "a" * 20
BID = "b" * 20


def _entry(appliance_id=AID, name="Kitchen", auth=AUTH_AUTHORIZED, playing=False,
           repeat_capable=False, ip="192.0.2.10", port=80, dial_eq=False, dial_outputs=False):
    return RosterEntry(
        appliance_id=appliance_id, service_name=name, name=name, ip=ip, port=port,
        playing=playing, repeat_capable=repeat_capable, dial_api=True, audio_status=True,
        dial_status=True, dial_outputs=dial_outputs, dial_eq=dial_eq, auth=auth,
    )


def _record(state="hold", seconds=42.0):
    return RepeatRecord(
        available=True, state=state, armed=False, recording_seconds=seconds,
        position_seconds=0.0, duration_seconds=0.0, observed_at=1.0,
    )


class TestFieldWrites:
    def test_focus_fields_round_trip_through_the_snapshot(self):
        core = _core()
        core.set_field_for_tests("manual_id", AID)
        core.set_field_for_tests("bound_id", BID)
        core.set_field_for_tests("reporting_id", AID)
        core.set_field_for_tests("source_service_name", "Kitchen")
        core.set_field_for_tests("pending", (AID, "Kitchen", 9.0))
        core.set_field_for_tests("accepted_replay", (AID, 20.0))
        focus = core.snapshot().focus
        assert (focus.manual_id, focus.bound_id, focus.reporting_id) == (AID, BID, AID)
        assert focus.source_service_name == "Kitchen"
        assert focus.pending == (AID, "Kitchen", 9.0)
        assert focus.accepted_replay == (AID, 20.0)

    def test_plain_fields_round_trip(self):
        core = _core()
        np = NowPlaying("Kitchen", "a", "t", 30)
        core.set_field_for_tests("now_playing", np)
        core.set_field_for_tests("idle_affordance", True)
        core.set_field_for_tests("dots_active", True)
        core.set_field_for_tests("outputs_available", True)
        core.set_field_for_tests("eq_available", True)
        snap = core.snapshot()
        assert snap.now_playing is np
        assert snap.idle_affordance and snap.dots_active
        assert snap.outputs_available and snap.eq_available

    def test_unknown_field_is_refused(self):
        with pytest.raises(KeyError):
            _core().set_field_for_tests("seq", 3)

    def test_writing_the_same_object_does_not_publish(self):
        core = _core()
        core.set_field_for_tests("manual_id", AID)
        seq = core.snapshot().seq
        core.set_field_for_tests("manual_id", AID)
        core.set_field_for_tests("now_playing", None)
        assert core.snapshot().seq == seq

    def test_writes_to_different_focus_fields_keep_each_other(self):
        core = _core()
        core.set_field_for_tests("manual_id", AID)
        core.set_field_for_tests("reporting_id", BID)
        core.set_field_for_tests("manual_id", None)
        focus = core.snapshot().focus
        assert focus.manual_id is None and focus.reporting_id == BID

    def test_concurrent_writers_of_different_fields_do_not_lose_updates(self):
        core = _core()
        n = 300

        def writer(field, prefix):
            for i in range(n):
                core.set_field_for_tests(field, f"{prefix}{i}")

        threads = [
            threading.Thread(target=writer, args=("manual_id", "m")),
            threading.Thread(target=writer, args=("reporting_id", "r")),
            threading.Thread(target=writer, args=("bound_id", "b")),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(5.0)
        focus = core.snapshot().focus
        assert (focus.manual_id, focus.reporting_id, focus.bound_id) == (
            f"m{n - 1}", f"r{n - 1}", f"b{n - 1}",
        )


class TestFocusActions:
    def test_set_focus_and_clear(self):
        core = _core()
        core.set_focus(AID)
        assert core.snapshot().focus.manual_id == AID
        core.set_focus(None)
        assert core.snapshot().focus.manual_id is None

    def test_pending_pins_the_focus_and_marks_the_grace(self):
        core = _core()
        core.set_focus_pending(AID, "Kitchen", 12.5)
        focus = core.snapshot().focus
        assert focus.manual_id == AID
        assert focus.pending == (AID, "Kitchen", 12.5)

    def test_drop_pending_focus_for_the_pending_appliance(self):
        core = _core()
        core.set_focus_pending(AID, "Kitchen", 12.5)
        assert core.drop_pending_focus(BID) is False
        assert core.snapshot().focus.manual_id == AID
        assert core.drop_pending_focus(AID) is True
        focus = core.snapshot().focus
        assert focus.manual_id is None and focus.pending is None

    def test_drop_pending_focus_without_a_pending_focus_is_a_no_op(self):
        core = _core()
        core.set_focus(AID)
        assert core.drop_pending_focus(AID) is False
        assert core.snapshot().focus.manual_id == AID

    def test_accept_replay_needs_the_dial_to_follow_that_appliance(self):
        core = _core()
        assert core.accept_replay(AID, 30.0) is False
        core.set_focus(BID)
        assert core.accept_replay(AID, 30.0) is False
        assert core.snapshot().focus.accepted_replay is None
        core.set_focus(AID)
        assert core.accept_replay(AID, 30.0) is True
        assert core.snapshot().focus.accepted_replay == (AID, 30.0)

    def test_current_source_service_name(self):
        core = _core()
        assert core.current_source_service_name() is None
        core.set_field_for_tests("source_service_name", "Kitchen")
        assert core.current_source_service_name() == "Kitchen"


class TestDisplayDelegates:
    """The display's moved attributes are views of the core's state."""

    def _display(self):
        from dial_test_support import make_display
        display, _fb, _gt = make_display(targets=[])
        return display

    def test_focus_attributes_write_through_to_the_core(self):
        display = self._display()
        display.core.set_field_for_tests("manual_id", AID)
        display.core.set_field_for_tests("bound_id", BID)
        display.core.set_field_for_tests("reporting_id", AID)
        display.core.set_field_for_tests("source_service_name", "Kitchen")
        display.core.set_field_for_tests("pending", (AID, "Kitchen", 9.0))
        display.core.set_field_for_tests("accepted_replay", (AID, 20.0))
        focus = display._core.snapshot().focus
        assert (focus.manual_id, focus.bound_id, focus.reporting_id) == (AID, BID, AID)
        assert focus.source_service_name == "Kitchen"
        assert focus.pending == (AID, "Kitchen", 9.0)
        assert focus.accepted_replay == (AID, 20.0)
        assert display.core.snapshot().focus.manual_id == AID and display.core.current_source_service_name() == "Kitchen"

    def test_core_writes_are_visible_through_the_attributes(self):
        display = self._display()
        display._core.set_focus_pending(AID, "Kitchen", 9.0)
        assert display.core.snapshot().focus.manual_id == AID
        assert display.core.snapshot().focus.pending == (AID, "Kitchen", 9.0)
        assert display.core.snapshot().focus.manual_id == AID

    def test_availability_and_now_playing_attributes(self):
        display = self._display()
        np = NowPlaying("Kitchen", "a", "t", 30)
        display.core.set_field_for_tests("now_playing", np)
        display.core.set_field_for_tests("dots_active", True)
        display.core.set_field_for_tests("outputs_available", True)
        display.core.set_field_for_tests("eq_available", True)
        display.core.set_field_for_tests("idle_affordance", True)
        snap = display._core.snapshot()
        assert snap.now_playing is np
        assert snap.dots_active and snap.outputs_available and snap.eq_available
        assert snap.idle_affordance
        assert display.core.snapshot().now_playing is np

    def test_the_display_still_does_not_subscribe_to_the_core(self):
        display = self._display()
        assert display._core._subscribers == {}
        display.fold_for_tests()
        assert display._core._subscribers == {}


# ---------------------------------------------------------------------------
# Outputs and EQ: interest, state, overrides
# ---------------------------------------------------------------------------


from dial_core_state import ActionResult  # noqa: E402


class _Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


_ROWS = (("1", "Bedroom", True, 40, False, ""), ("2", "Study", False, 0, False, ""))


# ---------------------------------------------------------------------------
# Transport requests and the repeat worker's results
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Warnings, update watch and sources in the core
# ---------------------------------------------------------------------------

from dial_core_state import POWER_IDLE, NOWIFI_PROMPT_STREAK, PowerState  # noqa: E402
from dial_network import LINK_CONNECTED, LINK_DOWN, LINK_IGNORED, LINK_UNKNOWN, NetworkView  # noqa: E402
from dial_sdhealth import STATUS_VALID, SdHealthView  # noqa: E402
from dial_update_watch import UpdateView, UpdateWatcher  # noqa: E402
from dial_warning_text import WARNING_DESCRIPTORS
from dial_warnings import WarningManager  # noqa: E402


def _warning_core(tmp_path=None, wall=None, reboot=None, **kwargs):
    wall = wall or _Clock(1_000_000.0)
    manager = WarningManager(WARNING_DESCRIPTORS, clock=wall)
    core = DialCore(
        "dial-1", warnings=manager,
        update_watcher=UpdateWatcher(str(tmp_path / "update-result.env")) if tmp_path else None,
        update_seen_path=str(tmp_path / "seen") if tmp_path else "/nonexistent/seen",
        reboot=reboot, **kwargs,
    )
    return core, manager, wall


class TestPower:
    @staticmethod
    def _core(accept=True):
        clock = _Clock(500.0)
        asked = []

        def shutdown(on_outcome):
            asked.append(on_outcome)
            return accept
        core = DialCore("dial-1", clock=clock, shutdown=shutdown)
        return core, clock, asked

    def test_it_starts_idle(self):
        core, _, _ = self._core()
        assert core.snapshot().power == POWER_IDLE

    def test_a_request_the_network_module_takes_publishes_requested(self):
        core, clock, asked = self._core()
        seq = core.snapshot().seq
        assert core.request_dial_shutdown() is True
        assert core.snapshot().power == PowerState("requested", 500.0)
        assert core.snapshot().seq == seq + 1
        assert len(asked) == 1

    def test_a_refusal_from_the_network_module_publishes_nothing(self):
        core, _, asked = self._core(accept=False)
        seq = core.snapshot().seq
        assert core.request_dial_shutdown() is False
        assert core.snapshot().power == POWER_IDLE and core.snapshot().seq == seq

    def test_a_success_report_changes_nothing(self):
        core, _, _ = self._core()
        core.request_dial_shutdown()
        seq = core.snapshot().seq
        core._on_shutdown_outcome(True)
        assert core.snapshot().power.state == "requested" and core.snapshot().seq == seq

    def test_a_failure_while_requested_moves_to_failed_at_that_moment(self):
        core, clock, asked = self._core()
        core.request_dial_shutdown()
        clock.t = 520.0
        asked[0](False)
        assert core.snapshot().power == PowerState("failed", 520.0)

    def test_a_failure_while_idle_changes_nothing(self):
        core, _, _ = self._core()
        seq = core.snapshot().seq
        core._on_shutdown_outcome(False)
        assert core.snapshot().power == POWER_IDLE and core.snapshot().seq == seq

    def test_a_request_while_requested_is_refused_without_asking(self):
        core, _, asked = self._core()
        core.request_dial_shutdown()
        assert core.request_dial_shutdown() is False
        assert len(asked) == 1

    def test_a_request_while_failed_moves_to_requested(self):
        core, clock, asked = self._core()
        core.request_dial_shutdown()
        asked[0](False)
        clock.t = 600.0
        assert core.request_dial_shutdown() is True
        assert core.snapshot().power == PowerState("requested", 600.0)
        assert len(asked) == 2

    def test_a_failure_before_the_request_was_published_is_not_lost(self):
        clock = _Clock(500.0)

        def shutdown(on_outcome):
            on_outcome(False)           # the helper failed before the call returned
            return True
        core = DialCore("dial-1", clock=clock, shutdown=shutdown)
        assert core.request_dial_shutdown() is True
        assert core.snapshot().power == PowerState("failed", 500.0)
        assert core.request_dial_shutdown() is True      # and the person can ask again

    def test_the_outcome_is_folded_outside_the_core_lock(self):
        core, _, asked = self._core()
        core.request_dial_shutdown()
        seen = []
        core.subscribe(lambda: seen.append(core._lock.locked()))
        asked[0](False)
        assert seen == [False]


def _net(link):
    return NetworkView(link=link)


def _sd(percent, status=STATUS_VALID):
    return SdHealthView(status=status, percent=percent)


def _progress(phase="packages", percent=45):
    return UpdateView(status="in_progress", percent=percent, phase=phase, tag="0.7.0",
                      previous_tag="0.6.0", last_run_at="2000-01-01T00:00:00+00:00")


def _finished(status="success", **kw):
    fields = dict(status=status, percent=100, phase="done", tag="0.7.0", previous_tag="0.6.0",
                  last_run_at="2000-01-01T01:00:00+00:00")
    fields.update(kw)
    return UpdateView(**fields)


def _row(core, warning_id):
    return next(w for w in core.snapshot().warnings if w.id == warning_id)


class TestWarningSnapshot:
    def test_the_snapshot_lists_every_registered_warning_in_registry_order(self):
        core, manager, _ = _warning_core()
        snap = core.snapshot()
        assert [w.id for w in snap.warnings] == [d.id for d in WARNING_DESCRIPTORS]
        assert all(not w.active for w in snap.warnings)
        assert snap.due_status_id is None

    def test_an_active_warning_shows_its_reading_and_start(self):
        core, manager, wall = _warning_core()
        change = core.warning_active("sdhealth", 40)
        assert change.began is True and change.active is True
        row = _row(core, "sdhealth")
        assert row.active and row.reading == 40 and row.active_since == wall.t

    def test_a_warning_is_never_the_due_status(self):
        core, manager, _ = _warning_core()
        core.warning_active("sdhealth", 40)
        core.warning_active("nowifi")
        assert core.snapshot().due_status_id is None

    def test_a_repeat_refreshes_and_is_not_a_new_incident(self):
        core, manager, wall = _warning_core()
        core.warning_active("sdhealth", 40)
        seq = core.snapshot().seq
        wall.t += 10
        change = core.warning_active("sdhealth", 40)
        assert change.began is False
        assert core.snapshot().seq == seq
        core.warning_active("sdhealth", 30)
        assert _row(core, "sdhealth").reading == 30
        assert _row(core, "sdhealth").active_since == 1_000_000.0

    def test_the_due_status_follows_priority(self):
        core, manager, _ = _warning_core()
        core.warning_active("update_result", _finished())
        assert core.snapshot().due_status_id == "update_result"
        core.warning_active("update", _progress())
        assert core.snapshot().due_status_id == "update"
        core.warning_cleared("update")
        assert core.snapshot().due_status_id == "update_result"
        core.warning_cleared("update_result")
        assert core.snapshot().due_status_id is None

    def test_closing_a_status_ends_it(self):
        core, manager, _ = _warning_core()
        core.warning_active("update_result", _finished())
        assert core.close_status("update_result") == ActionResult(True)
        assert core.snapshot().due_status_id is None
        assert not _row(core, "update_result").active

    def test_close_is_refused_for_a_warning_and_an_unknown_id(self):
        core, manager, _ = _warning_core()
        core.warning_active("nowifi")
        assert core.close_status("nowifi") == ActionResult(False, "wrong_state")
        assert core.close_status("nope") == ActionResult(False, "wrong_state")
        assert _row(core, "nowifi").active


class TestNetworkSource:
    def test_a_connected_reading_sets_the_latch_and_the_view(self):
        core, manager, _ = _warning_core()
        assert core.snapshot().wifi_ever_connected is False
        effects = core.on_network_view(_net(LINK_CONNECTED))
        snap = core.snapshot()
        assert snap.wifi_ever_connected is True and snap.network == _net(LINK_CONNECTED)
        assert [(c.warning_id, c.active) for c in effects.changes] == [("nowifi", False)]
        assert effects.signal is True

    def test_down_never_prompts_until_the_link_has_connected(self):
        core, manager, _ = _warning_core()
        for _ in range(NOWIFI_PROMPT_STREAK + 3):
            effects = core.on_network_view(_net(LINK_DOWN))
            assert effects.changes == ()
        assert core._state.wifi_down_streak == NOWIFI_PROMPT_STREAK + 3
        assert core.snapshot().due_status_id is None

    def test_a_loss_after_connecting_activates_at_the_streak(self):
        core, manager, _ = _warning_core()
        core.on_network_view(_net(LINK_CONNECTED))
        for _ in range(NOWIFI_PROMPT_STREAK - 1):
            assert core.on_network_view(_net(LINK_DOWN)).changes == ()
        effects = core.on_network_view(_net(LINK_DOWN))
        (change,) = effects.changes
        assert (change.warning_id, change.active, change.began) == ("nowifi", True, True)
        assert manager.is_active("nowifi")
        again = core.on_network_view(_net(LINK_DOWN))
        assert again.changes[0].began is False

    def test_ignored_resets_the_streak_only(self):
        core, manager, _ = _warning_core()
        core.on_network_view(_net(LINK_CONNECTED))
        for _ in range(NOWIFI_PROMPT_STREAK):
            core.on_network_view(_net(LINK_DOWN))
        core.on_network_view(_net(LINK_IGNORED))
        assert core._state.wifi_down_streak == 0
        assert core.snapshot().wifi_ever_connected is True
        assert manager.is_active("nowifi")

    def test_an_unknown_reading_changes_only_the_held_view(self):
        core, manager, _ = _warning_core()
        core.on_network_view(_net(LINK_CONNECTED))
        core.on_network_view(_net(LINK_DOWN))
        effects = core.on_network_view(_net(LINK_UNKNOWN))
        assert effects.changes == ()
        assert core._state.wifi_down_streak == 1
        assert core.snapshot().network == _net(LINK_UNKNOWN)
        assert core.snapshot().wifi_ever_connected is True
        core.on_network_view(_net(LINK_DOWN))
        assert core.snapshot().wifi_ever_connected is True

    def test_ignored_and_unknown_readings_leave_the_warning_active(self):
        core, manager, _ = _warning_core()
        core.on_network_view(_net(LINK_CONNECTED))
        for _ in range(NOWIFI_PROMPT_STREAK):
            core.on_network_view(_net(LINK_DOWN))
        core.on_network_view(_net(LINK_IGNORED))
        core.on_network_view(_net(LINK_UNKNOWN))
        assert manager.is_active("nowifi")
        core.on_network_view(_net(LINK_CONNECTED))
        assert not manager.is_active("nowifi")


class TestSdHealthSource:
    def test_low_activates_with_the_percent_and_recovery_clears(self):
        core, manager, _ = _warning_core()
        effects = core.on_sd_health_view(_sd(1))
        (change,) = effects.changes
        assert (change.warning_id, change.active, change.began) == ("sdhealth", True, True)
        assert core._state.sd_level == "failing"
        assert _row(core, "sdhealth").reading == ("failing", 1, None)
        assert core.snapshot().sd_health == _sd(1)
        effects = core.on_sd_health_view(_sd(100))
        assert effects.changes[0].active is False
        assert core._state.sd_level == "ok" and core.snapshot().due_status_id is None

    def test_a_reading_between_the_bands_is_a_warning_not_critical(self):
        core, manager, _ = _warning_core()
        core.on_sd_health_view(_sd(18))
        assert core._state.sd_level == "low"
        assert _row(core, "sdhealth").reading == ("low", 18, None)

    def test_a_reading_without_a_percent_ends_the_incident(self):
        core, manager, _ = _warning_core()
        core.on_sd_health_view(_sd(1))
        core.on_sd_health_view(SdHealthView())
        assert not manager.is_active("sdhealth")


class TestUpdateSource:
    def test_progress_raises_the_card_and_records_the_view(self, tmp_path):
        core, manager, _ = _warning_core(tmp_path)
        effects = core.apply_update_view(_progress())
        (change,) = effects.changes
        assert (change.warning_id, change.active, change.began) == ("update", True, True)
        assert core.snapshot().update == _progress()
        assert core.snapshot().due_status_id == "update"
        assert effects.restarting is False

    def test_the_reboot_phase_clears_the_card_and_asks_for_restarting(self, tmp_path):
        core, manager, _ = _warning_core(tmp_path)
        core.apply_update_view(_progress())
        effects = core.apply_update_view(_progress(phase="reboot", percent=96))
        assert effects.restarting is True
        assert [(c.warning_id, c.active) for c in effects.changes] == [("update", False)]
        assert not manager.is_active("update")

    def test_the_verify_phase_does_nothing(self, tmp_path):
        core, manager, _ = _warning_core(tmp_path)
        effects = core.apply_update_view(_progress(phase="verify", percent=96))
        assert effects.changes == () and effects.restarting is False and effects.signal is True
        assert not manager.is_active("update")

    def test_a_finished_run_raises_its_result_once_and_records_the_marker(self, tmp_path):
        core, manager, _ = _warning_core(tmp_path)
        core.apply_update_view(_progress())
        effects = core.apply_update_view(_finished())
        assert [(c.warning_id, c.active) for c in effects.changes] == [
            ("update", False), ("update_result", True),
        ]
        assert (tmp_path / "seen").read_text().strip() == "2000-01-01T01:00:00+00:00"
        again = core.apply_update_view(_finished())
        assert again.changes == () and again.signal is False

    def test_a_marker_from_an_earlier_run_suppresses_the_card(self, tmp_path):
        (tmp_path / "seen").write_text("2000-01-01T01:00:00+00:00\n")
        core, manager, _ = _warning_core(tmp_path)
        effects = core.apply_update_view(_finished())
        assert effects.changes == () and not manager.is_active("update_result")

    def test_the_marker_falls_back_to_status_and_tag(self, tmp_path):
        core, manager, _ = _warning_core(tmp_path)
        core.apply_update_view(_finished(last_run_at=""))
        assert (tmp_path / "seen").read_text().strip() == "success-0.7.0"

    def test_an_empty_view_signals_but_changes_nothing(self, tmp_path):
        core, manager, _ = _warning_core(tmp_path)
        effects = core.apply_update_view(UpdateView())
        assert effects.changes == () and effects.signal is True

    def test_the_watch_reads_the_file_only_when_it_changes(self, tmp_path):
        core, manager, _ = _warning_core(tmp_path)
        assert core.tick_update_watch(1.0) is None
        (tmp_path / "update-result.env").write_text(
            "STATUS=in_progress\nPERCENT_COMPLETE=30\nPHASE=packages\nTAG=0.7.0\n")
        effects = core.tick_update_watch(2.0)
        assert effects is not None and effects.changes[0].warning_id == "update"
        assert _row(core, "update").reading.percent == 30
        assert core.tick_update_watch(3.0) is None

    def test_the_result_card_clears_itself_after_an_hour(self, tmp_path):
        core, manager, wall = _warning_core(tmp_path)
        core.apply_update_view(_finished())
        wall.t += 3599
        assert core.expire_warnings().changes == ()
        wall.t += 2
        effects = core.expire_warnings()
        assert [(c.warning_id, c.active) for c in effects.changes] == [("update_result", False)]
        assert core.snapshot().due_status_id is None


class TestHousekeepingAndReboot:
    def test_the_tick_folds_the_watch_and_expiry_together(self, tmp_path):
        core, manager, wall = _warning_core(tmp_path)
        (tmp_path / "update-result.env").write_text(
            "STATUS=success\nPERCENT_COMPLETE=100\nTAG=0.7.0\nLAST_RUN_AT=t1\n")
        effects = core.tick_housekeeping(5.0)
        assert [c.warning_id for c in effects.changes] == ["update", "update_result"]
        wall.t += 3601
        effects = core.tick_housekeeping(6.0)
        assert [(c.warning_id, c.active) for c in effects.changes] == [("update_result", False)]

    def test_a_quiet_tick_publishes_nothing(self, tmp_path):
        core, manager, _ = _warning_core(tmp_path)
        seq = core.snapshot().seq
        effects = core.tick_housekeeping(5.0)
        assert effects.changes == () and core.snapshot().seq == seq

    def test_a_reboot_request_goes_to_the_injected_function(self):
        calls = []
        core, manager, _ = _warning_core(reboot=lambda: calls.append(1) or True)
        assert core.request_dial_reboot() is True
        assert calls == [1]

    def test_a_rate_gated_or_raising_request_is_false(self):
        core, manager, _ = _warning_core(reboot=lambda: False)
        assert core.request_dial_reboot() is False

        def boom():
            raise RuntimeError("no")
        core, manager, _ = _warning_core(reboot=boom)
        assert core.request_dial_reboot() is False

    def test_a_shutdown_request_goes_to_the_injected_function(self):
        calls = []
        core, manager, _ = _warning_core(shutdown=lambda on_outcome: calls.append(1) or True)
        assert core.request_dial_shutdown() is True
        assert calls == [1]

    def test_a_refused_or_raising_shutdown_request_is_false(self):
        core, manager, _ = _warning_core(shutdown=lambda on_outcome: False)
        assert core.request_dial_shutdown() is False

        def boom(on_outcome):
            raise RuntimeError("no")
        core, manager, _ = _warning_core(shutdown=boom)
        assert core.request_dial_shutdown() is False

    def test_warning_changes_are_published_outside_the_core_lock(self):
        core, manager, _ = _warning_core()
        seen = []
        core.subscribe(lambda: seen.append(core._lock.locked()))
        core.warning_active("sdhealth", 5)
        core.on_network_view(_net(LINK_CONNECTED))
        assert seen and not any(seen)


