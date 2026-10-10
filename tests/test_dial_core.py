"""Tests for dial/dial_core.py: snapshot, publish and subscribe."""
import dataclasses
import os
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dial"))

import pytest

from dial_core import DialCore, create_dial_core
from dial_core_state import CoreSnapshot, FocusState, NowPlaying


def _core(clock=None):
    kwargs = {} if clock is None else {"clock": clock}
    return DialCore("dial-1", lambda: [], lambda: [], **kwargs)


def _tick(core, polling=True, now_playing=None):
    return core.publish_tick(
        polling=polling,
        focus=FocusState(None, None, None, None, None, None, False),
        now_playing=now_playing,
        idle_affordance=False,
        outputs_available=False,
        eq_available=False,
    )


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
        core = create_dial_core(Cfg(), lambda: [])
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

from dial_auth import AUTH_AUTHORIZED, AUTH_UNAUTHORIZED, AUTH_UNKNOWN  # noqa: E402
from dial_mdns import PlayingTarget, RosterEntry  # noqa: E402
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
        core.set_field("manual_id", AID)
        core.set_field("bound_id", BID)
        core.set_field("reporting_id", AID)
        core.set_field("source_service_name", "Kitchen")
        core.set_field("pending", (AID, "Kitchen", 9.0))
        core.set_field("accepted_replay", (AID, 20.0))
        focus = core.snapshot().focus
        assert (focus.manual_id, focus.bound_id, focus.reporting_id) == (AID, BID, AID)
        assert focus.source_service_name == "Kitchen"
        assert focus.pending == (AID, "Kitchen", 9.0)
        assert focus.accepted_replay == (AID, 20.0)

    def test_plain_fields_round_trip(self):
        core = _core()
        np = NowPlaying("Kitchen", "a", "t", 30)
        core.set_field("now_playing", np)
        core.set_field("idle_affordance", True)
        core.set_field("dots_active", True)
        core.set_field("outputs_available", True)
        core.set_field("eq_available", True)
        snap = core.snapshot()
        assert snap.now_playing is np
        assert snap.idle_affordance and snap.dots_active
        assert snap.outputs_available and snap.eq_available

    def test_unknown_field_is_refused(self):
        with pytest.raises(KeyError):
            _core().set_field("seq", 3)

    def test_writing_the_same_object_does_not_publish(self):
        core = _core()
        core.set_field("manual_id", AID)
        seq = core.snapshot().seq
        core.set_field("manual_id", AID)
        core.set_field("now_playing", None)
        assert core.snapshot().seq == seq

    def test_writes_to_different_focus_fields_keep_each_other(self):
        core = _core()
        core.set_field("manual_id", AID)
        core.set_field("reporting_id", BID)
        core.set_field("manual_id", None)
        focus = core.snapshot().focus
        assert focus.manual_id is None and focus.reporting_id == BID

    def test_concurrent_writers_of_different_fields_do_not_lose_updates(self):
        core = _core()
        n = 300

        def writer(field, prefix):
            for i in range(n):
                core.set_field(field, f"{prefix}{i}")

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
        assert core.manual_focus_id() == AID
        core.set_focus(None)
        assert core.manual_focus_id() is None

    def test_pending_pins_the_focus_and_marks_the_grace(self):
        core = _core()
        core.set_focus_pending(AID, "Kitchen", 12.5)
        focus = core.snapshot().focus
        assert focus.manual_id == AID
        assert focus.pending == (AID, "Kitchen", 12.5)

    def test_clear_focus_drops_manual_and_pending_in_one_publish(self, caplog):
        core = _core()
        core.set_focus_pending(AID, "Kitchen", 12.5)
        seq = core.snapshot().seq
        with caplog.at_level("INFO"):
            core.clear_focus("test reason")
        focus = core.snapshot().focus
        assert focus.manual_id is None and focus.pending is None
        assert core.snapshot().seq == seq + 1
        assert "manual focus cleared (test reason)" in caplog.text

    def test_replace_pending_only_when_unchanged_since_the_read(self):
        core = _core()
        core.set_focus_pending(AID, "Kitchen", 12.5)
        read = core.snapshot().focus.pending
        # The touch thread pins another appliance after the poll's read.
        core.set_focus_pending(BID, "Lounge", 15.0)
        assert core.replace_pending(read, None) is False
        assert core.snapshot().focus.pending == (BID, "Lounge", 15.0)
        newest = core.snapshot().focus.pending
        assert core.replace_pending(newest, None) is True
        assert core.snapshot().focus.pending is None

    def test_replace_pending_with_the_same_value_writes_nothing(self):
        core = _core()
        core.set_focus_pending(AID, "Kitchen", 12.5)
        read = core.snapshot().focus.pending
        seq = core.snapshot().seq
        assert core.replace_pending(read, read) is False
        assert core.snapshot().seq == seq

    def test_drop_pending_focus_for_the_pending_appliance(self):
        core = _core()
        core.set_focus_pending(AID, "Kitchen", 12.5)
        assert core.drop_pending_focus(BID) is False
        assert core.manual_focus_id() == AID
        assert core.drop_pending_focus(AID) is True
        focus = core.snapshot().focus
        assert focus.manual_id is None and focus.pending is None

    def test_drop_pending_focus_without_a_pending_focus_is_a_no_op(self):
        core = _core()
        core.set_focus(AID)
        assert core.drop_pending_focus(AID) is False
        assert core.manual_focus_id() == AID

    def test_accept_replay_needs_the_dial_to_follow_that_appliance(self):
        core = _core()
        assert core.accept_replay(AID, 30.0) is False
        core.set_focus(BID)
        assert core.accept_replay(AID, 30.0) is False
        assert core.snapshot().focus.accepted_replay is None
        core.set_focus(AID)
        assert core.accept_replay(AID, 30.0) is True
        assert core.snapshot().focus.accepted_replay == (AID, 30.0)

    def test_focus_volume_target_follows_the_roster_and_auth(self):
        core = _core()
        assert core.focus_volume_target() is None
        entry = _entry()
        core.set_roster([entry])
        assert core.focus_volume_target() is None
        core.set_focus(AID)
        assert core.focus_volume_target() is entry
        core.set_roster([_entry(auth=AUTH_UNAUTHORIZED)])
        assert core.focus_volume_target() is None
        core.set_roster([])
        assert core.focus_volume_target() is None

    def test_current_source_service_name(self):
        core = _core()
        assert core.current_source_service_name() is None
        core.set_field("source_service_name", "Kitchen")
        assert core.current_source_service_name() == "Kitchen"


class TestAcceptedReplay:
    @pytest.fixture(autouse=True)
    def _store(self):
        from dial_repeat_store import repeat_store
        repeat_store.clear(AID)
        yield repeat_store
        repeat_store.clear(AID)

    def _following(self, store, state="replaying"):
        core = _core()
        core.set_roster([_entry(repeat_capable=True)])
        core.set_focus(AID)
        store.update(AID, _record(state))
        assert core.accept_replay(AID, 20.0)
        return core

    def test_adds_the_accepted_appliance_with_the_clock_as_playing_since(self, _store):
        core = self._following(_store)
        targets = core.with_accepted_replay([], 5.0)
        assert [t.appliance_id for t in targets] == [AID]
        assert targets[0].playing_since == 5.0
        assert core.snapshot().focus.accepted_replay == (AID, 20.0)

    def test_the_window_ends_at_the_deadline_boundary(self, _store):
        core = self._following(_store)
        assert [t.appliance_id for t in core.with_accepted_replay([], 19.99)] == [AID]
        assert core.with_accepted_replay([], 20.01) == []
        assert core.snapshot().focus.accepted_replay is None

    def test_the_real_advertisement_ends_the_window(self, _store):
        core = self._following(_store)
        real = PlayingTarget(
            ip="192.0.2.10", port=80, name="Kitchen", dial_api=True, audio_status=True,
            dial_status=True, service_name="Kitchen", playing_since=1.0, appliance_id=AID,
            auth=AUTH_AUTHORIZED,
        )
        assert core.with_accepted_replay([real], 5.0) == [real]
        assert core.snapshot().focus.accepted_replay is None

    def test_a_record_that_is_not_replaying_ends_the_window(self, _store):
        core = self._following(_store, state="hold")
        assert core.with_accepted_replay([], 5.0) == []
        assert core.snapshot().focus.accepted_replay is None

    def test_leaving_the_focus_ends_the_window(self, _store):
        core = self._following(_store)
        core.set_focus(None)
        assert core.with_accepted_replay([], 5.0) == []
        assert core.snapshot().focus.accepted_replay is None

    def test_a_window_opened_meanwhile_is_not_overwritten_by_the_poll(self, _store):
        core = self._following(_store)
        # The poll read the first window; a new ack opens another before it
        # stores its own "window over" result.
        stale = core.snapshot().focus.accepted_replay
        assert core.accept_replay(AID, 99.0)
        assert core._replace_focus_if("accepted_replay", stale, None) is False
        assert core.snapshot().focus.accepted_replay == (AID, 99.0)

    def test_no_window_leaves_targets_alone(self, _store):
        core = _core()
        targets = [object()]
        assert core.with_accepted_replay(targets, 1.0) is targets


class TestRosterAndAppliances:
    def test_appliances_derive_from_the_roster_in_order(self):
        core = _core()
        core.set_roster([
            _entry(AID, "Kitchen", playing=True, repeat_capable=True, dial_eq=True),
            _entry(BID, "autostream on Lounge", auth=AUTH_UNKNOWN, dial_outputs=True),
        ])
        first, second = core.snapshot().appliances
        assert (first.appliance_id, first.service_name, first.name) == (AID, "Kitchen", "Kitchen")
        assert first.playing and first.repeat_capable and first.dial_eq
        assert first.dial_eq_version == 1 and first.dial_outputs_version == 0
        assert first.auth == AUTH_AUTHORIZED
        assert (second.appliance_id, second.name) == (BID, "Lounge")
        assert second.dial_outputs and second.dial_outputs_version == 1
        assert second.auth == AUTH_UNKNOWN

    def test_roster_getter_returns_what_was_stored(self):
        core = _core()
        roster = [_entry()]
        core.set_roster(roster)
        assert core.roster() is roster

    def test_webui_address_comes_from_the_roster_entry(self):
        core = _core()
        core.set_roster([_entry(ip="192.0.2.77", port=8080)])
        appliance = core.snapshot().appliance(AID)
        assert (appliance.webui_scheme, appliance.webui_host, appliance.webui_port) == (
            "http", "192.0.2.77", 8080,
        )

    def test_webui_address_follows_a_moved_appliance(self):
        core = _core()
        core.set_roster([_entry(ip="192.0.2.10")])
        core.set_roster([_entry(ip="192.0.2.11")])
        assert core.snapshot().appliance(AID).webui_host == "192.0.2.11"

    def test_an_entry_missing_attributes_takes_neutral_values(self):
        class Bare:
            appliance_id = AID
            service_name = "Kitchen"
            ip = "192.0.2.10"
            port = 80
        core = _core()
        core.set_roster([Bare()])
        appliance = core.snapshot().appliance(AID)
        assert appliance.playing is False and appliance.repeat_capable is False
        assert appliance.repeat is None and appliance.master_volume is None
        assert appliance.webui_host == "192.0.2.10"

    def test_publish_tick_repeats_feed_the_appliances(self):
        core = _core()
        core.set_roster([_entry(repeat_capable=True)])
        rec = _record()
        core.publish_tick(polling=True, repeats={AID: rec})
        assert core.snapshot().appliance(AID).repeat is rec
        core.publish_tick(polling=True, repeats={})
        assert core.snapshot().appliance(AID).repeat is None

    def test_a_roster_change_keeps_the_last_repeat_records(self):
        core = _core()
        core.set_roster([_entry(repeat_capable=True)])
        rec = _record()
        core.publish_tick(polling=True, repeats={AID: rec})
        core.set_roster([_entry(repeat_capable=True, ip="192.0.2.99")])
        assert core.snapshot().appliance(AID).repeat is rec

    def test_snapshot_rows_match_the_pure_helpers(self):
        import dial_core_state as cs
        core = _core()
        roster = [
            _entry(AID, "Kitchen", playing=True, repeat_capable=True),
            _entry(BID, "Lounge", auth=AUTH_UNAUTHORIZED),
            _entry("c" * 20, "Study", auth=AUTH_UNKNOWN),
        ]
        core.set_roster(roster)
        core.set_field("reporting_id", AID)
        core.publish_tick(polling=True, repeats={AID: _record("hold", 61.0)})
        snap = core.snapshot()
        assert snap.selector_rows() == cs.selector_rows(roster, None, AID)
        assert snap.picker_rows() == cs.picker_rows(
            roster, lambda appliance_id, now: _record("hold", 61.0) if appliance_id == AID else None, 0.0,
        )
        assert [r.appliance_id for r in snap.picker_rows()] == [AID]

    def test_selector_current_prefers_the_manual_focus(self):
        core = _core()
        core.set_roster([_entry(AID, "Kitchen"), _entry(BID, "Lounge")])
        core.set_field("reporting_id", AID)
        core.set_focus(BID)
        current = [r.appliance_id for r in core.snapshot().selector_rows() if r.current]
        assert current == [BID]


class TestPublishTickKeepsStoredWrites:
    def test_fields_left_out_keep_their_stored_value(self):
        core = _core()
        np = NowPlaying("Kitchen", "a", "t", 30)
        core.set_field("now_playing", np)
        core.set_field("manual_id", AID)
        core.set_field("idle_affordance", True)
        core.set_field("outputs_available", True)
        core.publish_tick(polling=True)
        snap = core.snapshot()
        assert snap.polling is True
        assert snap.now_playing is np and snap.focus.manual_id == AID
        assert snap.idle_affordance and snap.outputs_available

    def test_idle_focus_is_derived_from_the_stored_now_playing(self):
        core = _core()
        core.set_field("now_playing", NowPlaying("Kitchen", "", "", None, playing=False))
        core.publish_tick(polling=True)
        assert core.snapshot().focus.idle_focus is True
        core.set_field("now_playing", NowPlaying("Kitchen", "a", "t", 10))
        core.publish_tick(polling=True)
        assert core.snapshot().focus.idle_focus is False
        core.set_field("now_playing", None)
        core.publish_tick(polling=True)
        assert core.snapshot().focus.idle_focus is False

    def test_a_focus_written_during_the_tick_survives_the_publish(self):
        core = _core()
        core.publish_tick(polling=True)
        core.set_focus_pending(AID, "Kitchen", 9.0)
        core.publish_tick(polling=True)
        assert core.snapshot().focus.pending == (AID, "Kitchen", 9.0)


class TestDisplayDelegates:
    """The display's moved attributes are views of the core's state."""

    def _display(self):
        from dial_test_support import make_display
        display, _fb, _gt = make_display(targets=[])
        return display

    def test_focus_attributes_write_through_to_the_core(self):
        display = self._display()
        display._manual_focus_id = AID
        display._bound_appliance_id = BID
        display._reporting_appliance_id = AID
        display._source_service_name = "Kitchen"
        display._focus_pending = (AID, "Kitchen", 9.0)
        display._accepted_replay = (AID, 20.0)
        focus = display._core.snapshot().focus
        assert (focus.manual_id, focus.bound_id, focus.reporting_id) == (AID, BID, AID)
        assert focus.source_service_name == "Kitchen"
        assert focus.pending == (AID, "Kitchen", 9.0)
        assert focus.accepted_replay == (AID, 20.0)
        assert display._manual_focus_id == AID and display.current_source_service_name() == "Kitchen"

    def test_core_writes_are_visible_through_the_attributes(self):
        display = self._display()
        display._core.set_focus_pending(AID, "Kitchen", 9.0)
        assert display._manual_focus_id == AID
        assert display._focus_pending == (AID, "Kitchen", 9.0)
        assert display.manual_focus_id() == AID

    def test_availability_and_now_playing_attributes(self):
        display = self._display()
        np = NowPlaying("Kitchen", "a", "t", 30)
        display._now_playing = np
        display._dots_active = True
        display._outputs_available = True
        display._eq_available = True
        display._idle_affordance = True
        snap = display._core.snapshot()
        assert snap.now_playing is np
        assert snap.dots_active and snap.outputs_available and snap.eq_available
        assert snap.idle_affordance
        assert display._now_playing is np

    def test_last_roster_derives_the_appliances_and_the_volume_target(self):
        display = self._display()
        entry = _entry(ip="192.0.2.50", port=80)
        display._last_roster = [entry]
        assert display._last_roster == [entry]
        assert display._core.snapshot().appliance(AID).webui_host == "192.0.2.50"
        display.set_manual_focus(AID)
        assert display.focus_volume_target() is entry

    def test_the_display_still_does_not_subscribe_to_the_core(self):
        display = self._display()
        assert display._core._subscribers == {}
        display._poll_once()
        assert display._core._subscribers == {}
