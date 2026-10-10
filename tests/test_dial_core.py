"""Tests for dial/dial_core.py: snapshot, publish and subscribe."""
import dataclasses
import gc
import os
import sys
import threading
import time
import weakref

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dial"))

import pytest

from dial_core import DialCore, create_dial_core
from dial_core_state import CoreSnapshot, FocusState, NowPlaying, artwork_key


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
        display.core.set_field("manual_id", AID)
        display.core.set_field("bound_id", BID)
        display.core.set_field("reporting_id", AID)
        display.core.set_field("source_service_name", "Kitchen")
        display.core.set_field("pending", (AID, "Kitchen", 9.0))
        display.core.set_field("accepted_replay", (AID, 20.0))
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
        assert display.core.manual_focus_id() == AID

    def test_availability_and_now_playing_attributes(self):
        display = self._display()
        np = NowPlaying("Kitchen", "a", "t", 30)
        display.core.set_field("now_playing", np)
        display.core.set_field("dots_active", True)
        display.core.set_field("outputs_available", True)
        display.core.set_field("eq_available", True)
        display.core.set_field("idle_affordance", True)
        snap = display._core.snapshot()
        assert snap.now_playing is np
        assert snap.dots_active and snap.outputs_available and snap.eq_available
        assert snap.idle_affordance
        assert display.core.snapshot().now_playing is np

    def test_last_roster_derives_the_appliances_and_the_volume_target(self):
        display = self._display()
        entry = _entry(ip="192.0.2.50", port=80)
        display.core.set_roster([entry])
        assert display.core.roster() == [entry]
        assert display._core.snapshot().appliance(AID).webui_host == "192.0.2.50"
        display.core.set_focus(AID)
        assert display.core.focus_volume_target() is entry

    def test_the_display_still_does_not_subscribe_to_the_core(self):
        display = self._display()
        assert display._core._subscribers == {}
        display._poll_once()
        assert display._core._subscribers == {}


class _Limiter:
    def __init__(self):
        self.entries = []

    def log(self, level, key, msg, *args):
        self.entries.append((level, key, msg % args))


class TestArtworkBytes:
    URL = "https://provider.example/a.jpg"
    OTHER = "https://provider.example/b.jpg"

    def _fetch(self, core, url, results, calls, errors=None):
        def fetch(u, timeout):
            calls.append(u)
            return results.pop(0)
        return core.fetch_artwork(
            url, fetch=fetch, log_limiter=_Limiter(), eligible=lambda u: u.startswith("https://"),
            timeout=1.0, on_error=None if errors is None else errors.append,
        )

    def test_a_success_is_cached_by_key_and_fetched_once(self):
        core = _core(clock=lambda: 7.0)
        calls = []
        first = self._fetch(core, self.URL, [(b"jpeg", "")], calls)
        again = self._fetch(core, self.URL, [], calls)
        assert calls == [self.URL]
        assert again is first is core.snapshot().artwork
        assert first.data == b"jpeg" and first.fetched_at == 7.0
        assert first.key == artwork_key(self.URL) and len(first.key) == 16

    def test_the_core_never_holds_the_url(self):
        core = _core()
        art = self._fetch(core, self.URL, [(b"jpeg", "")], [])
        assert art.url == ""
        assert self.URL not in repr(core.snapshot().artwork)

    def test_a_failed_fetch_is_retried_on_the_next_call(self):
        core = _core()
        calls, errors = [], []
        assert self._fetch(core, self.URL, [(None, "timeout")], calls, errors) is None
        assert core.snapshot().artwork is None
        art = self._fetch(core, self.URL, [(b"jpeg", "")], calls, errors)
        assert calls == [self.URL, self.URL]
        assert errors == ["artwork_fetch_failed"]
        assert art is core.snapshot().artwork

    def test_an_ineligible_url_is_not_fetched(self):
        core = _core()
        calls = []
        assert self._fetch(core, "http://provider.example/a.jpg", [], calls) is None
        assert calls == []

    def test_the_bytes_are_released_when_the_url_changes(self):
        core = _core()
        first = self._fetch(core, self.URL, [(b"one", "")], [])
        ref = weakref.ref(first)
        del first
        second = self._fetch(core, self.OTHER, [(None, "boom")], [])
        assert second is None
        gc.collect()
        assert ref() is None and core.snapshot().artwork is None

    def test_a_new_track_replaces_the_held_copy(self):
        core = _core()
        self._fetch(core, self.URL, [(b"one", "")], [])
        art = self._fetch(core, self.OTHER, [(b"two", "")], [])
        assert core.snapshot().artwork is art and art.data == b"two"

    def test_clear_by_key_only_drops_that_copy(self):
        core = _core()
        art = self._fetch(core, self.URL, [(b"one", "")], [])
        seq = core.snapshot().seq
        core.clear_artwork(artwork_key(self.OTHER))
        assert core.snapshot().artwork is art and core.snapshot().seq == seq
        core.clear_artwork(art.key)
        assert core.snapshot().artwork is None
        seq = core.snapshot().seq
        core.clear_artwork()
        assert core.snapshot().seq == seq


# ---------------------------------------------------------------------------
# Outputs and EQ: interest, state, overrides
# ---------------------------------------------------------------------------

from unittest.mock import patch  # noqa: E402

from dial_core import RepeatOutcome  # noqa: E402
from dial_core_state import ActionResult, EqBand, OutputRow, TransportRequest  # noqa: E402


class _Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def _outputs_body(*rows):
    return {"ok": True, "outputs": [
        {"id": i, "name": n, "selected": s, "volume": v, "remote_in_use": u,
         **({"remote_owner": o} if o else {})}
        for (i, n, s, v, u, o) in rows
    ]}


_ROWS = (("1", "Bedroom", True, 40, False, ""), ("2", "Study", False, 0, False, ""))


def _io_core(clock=None, *, dial_outputs=True, dial_eq=True, auth=AUTH_AUTHORIZED, focus=True):
    core = _core(clock=clock)
    core.set_roster([_entry(dial_outputs=dial_outputs, dial_eq=dial_eq, auth=auth)])
    if focus:
        core.set_field("reporting_id", AID)
    return core


class TestWatchOutputs:
    def test_first_interest_for_the_focused_appliance_holds_state_and_fetches_once(self):
        core = _io_core()
        with patch("dial_core.enqueue_fetch") as fetch:
            core.watch_outputs(AID, "spi", True)
            core.watch_outputs(AID, "hd", True)
        assert fetch.call_count == 1
        target = fetch.call_args[0][0]
        assert (target.appliance_id, target.ip, target.port) == (AID, "192.0.2.10", 80)
        held = core.snapshot().outputs
        assert held.appliance_id == AID and held.rows == () and held.loaded is False

    def test_registering_without_a_fetch_still_holds_the_state(self):
        core = _io_core()
        with patch("dial_core.enqueue_fetch") as fetch:
            core.watch_outputs(AID, "spi", True, fetch=False)
        fetch.assert_not_called()
        assert core.snapshot().outputs.appliance_id == AID

    def test_interest_in_another_appliance_waits_for_it_to_be_focused(self):
        core = _io_core()
        core.set_roster([_entry(), _entry(appliance_id=BID, name="Study", dial_outputs=True)])
        with patch("dial_core.enqueue_fetch") as fetch:
            core.watch_outputs(BID, "hd", True)
            assert fetch.call_count == 0 and core.snapshot().outputs is None
            core.set_field("manual_id", BID)
            core.refresh_watched(5000.0)
        assert fetch.call_count == 1 and fetch.call_args[0][0].appliance_id == BID
        assert core.snapshot().outputs.appliance_id == BID

    def test_the_state_goes_with_the_last_watcher(self):
        core = _io_core()
        with patch("dial_core.enqueue_fetch"):
            core.watch_outputs(AID, "spi", True)
            core.watch_outputs(AID, "hd", True)
            core.watch_outputs(AID, "spi", False)
            assert core.snapshot().outputs is not None
            core.watch_outputs(AID, "hd", False)
        assert core.snapshot().outputs is None

    def test_dropping_interest_that_was_never_registered_changes_nothing(self):
        core = _io_core()
        seq = core.snapshot().seq
        core.watch_outputs(AID, "spi", False)
        assert core.snapshot().seq == seq

    def test_a_watcher_follows_one_appliance_at_a_time(self):
        core = _io_core()
        core.set_roster([_entry(), _entry(appliance_id=BID, name="Study", dial_outputs=True)])
        with patch("dial_core.enqueue_fetch"):
            core.watch_outputs(AID, "spi", True)
            core.set_field("manual_id", BID)
            core.watch_outputs(BID, "spi", True)
        assert core.snapshot().outputs.appliance_id == BID

    def test_the_list_is_asked_for_again_every_two_seconds(self):
        core = _io_core()
        with patch("dial_core.enqueue_fetch") as fetch:
            core.watch_outputs(AID, "spi", True, fetch=False)
            core.refresh_watched(1000.0)
            assert fetch.call_count == 1                 # the first tick is due at once
            core.refresh_watched(1001.99)
            assert fetch.call_count == 1
            core.refresh_watched(1002.01)
            assert fetch.call_count == 2
            core.refresh_watched(1003.99)
            assert fetch.call_count == 2                 # the window restarts at the fetch

    def test_nothing_is_asked_for_without_a_watcher(self):
        core = _io_core()
        with patch("dial_core.enqueue_fetch") as fetch:
            core.refresh_watched(1000.0)
        fetch.assert_not_called()


class TestOutputsResult:
    def _watching(self, clock=None):
        core = _io_core(clock)
        with patch("dial_core.enqueue_fetch"):
            core.watch_outputs(AID, "spi", True)
        return core

    def test_a_fetch_replaces_the_rows_and_marks_them_loaded(self):
        clock = _Clock(1000.0)
        core = self._watching(clock)
        clock.t = 1001.0
        assert core.on_outputs_result("fetch", AID, 200, _outputs_body(*_ROWS))
        held = core.snapshot().outputs
        assert held.loaded is True and held.fetched_at == 1001.0
        assert held.rows == (
            OutputRow("1", "Bedroom", True, 40), OutputRow("2", "Study", False, 0),
        )

    def test_an_output_in_use_elsewhere_is_kept_and_marked(self):
        core = self._watching()
        core.on_outputs_result("fetch", AID, 200, _outputs_body(
            ("1", "Bedroom", True, 40, False, ""), ("2", "Study", False, 0, True, "Hall"),
        ))
        rows = core.snapshot().outputs.rows
        assert [r.id for r in rows] == ["1", "2"]
        assert (rows[0].remote_in_use, rows[0].remote_owner) == (False, None)
        assert (rows[1].remote_in_use, rows[1].remote_owner) == (True, "Hall")

    def test_a_set_result_is_not_applied(self):
        core = self._watching()
        assert not core.on_outputs_result("set", AID, 200, _outputs_body(*_ROWS))
        assert core.snapshot().outputs.rows == ()

    def test_a_late_result_for_another_appliance_is_dropped(self):
        core = self._watching()
        seq = core.snapshot().seq
        assert not core.on_outputs_result("fetch", BID, 200, _outputs_body(*_ROWS))
        assert core.snapshot().seq == seq and core.snapshot().outputs.rows == ()

    def test_a_result_with_nothing_held_is_dropped(self):
        core = _io_core()
        assert not core.on_outputs_result("fetch", AID, 200, _outputs_body(*_ROWS))
        assert core.snapshot().outputs is None

    def test_a_malformed_or_failed_result_keeps_the_last_rows(self):
        core = self._watching()
        core.on_outputs_result("fetch", AID, 200, _outputs_body(*_ROWS))
        rows = core.snapshot().outputs.rows
        assert not core.on_outputs_result("fetch", AID, 500, None)
        assert not core.on_outputs_result("fetch", AID, 200, {"ok": True, "outputs": [{"id": "1"}]})
        assert core.snapshot().outputs.rows == rows

    def test_a_stale_tap_is_cleared_by_a_later_fetch_and_a_future_one_kept(self):
        clock = _Clock(1000.0)
        core = self._watching(clock)
        core.set_outputs_override(("1", True, 40, 999.0))
        core.on_outputs_result("fetch", AID, 200, _outputs_body(*_ROWS))
        assert core.outputs_override() is None
        core.set_outputs_override(("1", True, 40, 1010.0))
        core.on_outputs_result("fetch", AID, 200, _outputs_body(*_ROWS))
        assert core.outputs_override() == ("1", True, 40, 1010.0)
        assert core.snapshot().outputs.optimistic == ("1", True, 40, 1010.0)


class TestSetOutput:
    def _loaded(self, clock=None, **kw):
        core = _io_core(clock, **kw)
        with patch("dial_core.enqueue_fetch"):
            core.watch_outputs(AID, "spi", True)
        core.on_outputs_result("fetch", AID, 200, _outputs_body(
            *_ROWS, ("3", "Hall", True, 20, True, "Den"),
        ))
        return core

    def test_enabling_shows_at_once_and_sends_with_no_level(self):
        clock = _Clock(1000.0)
        core = self._loaded(clock)
        with patch("dial_core.enqueue_set") as send:
            result = core.set_output(AID, "2", selected=True)
        assert result == ActionResult(True)
        assert core.snapshot().outputs.optimistic == ("2", True, 0, 1000.0)
        target, output_id = send.call_args[0]
        assert (target.appliance_id, target.ip, output_id) == (AID, "192.0.2.10", "2")
        assert send.call_args[1] == {"selected": True, "volume": None}

    def test_a_level_is_sent_and_shown(self):
        core = self._loaded(_Clock(1000.0))
        with patch("dial_core.enqueue_set") as send:
            core.set_output(AID, "1", selected=True, volume=55)
        assert core.outputs_override() == ("1", True, 55, 1000.0)
        assert send.call_args[1] == {"selected": True, "volume": 55}

    def test_the_step_clamps_and_starts_from_the_tap_shown(self):
        core = self._loaded(_Clock(1000.0))
        with patch("dial_core.enqueue_set") as send:
            assert core.step_output_volume(AID, "1", +70).accepted
            assert send.call_args[1]["volume"] == 100
            core.set_outputs_override(("1", True, 42, 1000.0))
            core.step_output_volume(AID, "1", +2)
            assert send.call_args[1]["volume"] == 44
            core.step_output_volume(AID, "1", -99)
            assert send.call_args[1]["volume"] == 0

    def test_a_disabled_output_has_no_level_to_step(self):
        core = self._loaded()
        with patch("dial_core.enqueue_set") as send:
            assert core.step_output_volume(AID, "2", +2) == ActionResult(False, "wrong_state")
        send.assert_not_called()
        assert core.outputs_override() is None

    def test_an_output_taken_elsewhere_is_refused_locally(self):
        core = self._loaded()
        with patch("dial_core.enqueue_set") as send:
            assert core.set_output(AID, "3", selected=False) == ActionResult(False, "wrong_state")
            assert core.step_output_volume(AID, "3", +1) == ActionResult(False, "wrong_state")
        send.assert_not_called()

    def test_refusals_name_their_reason(self):
        with patch("dial_core.enqueue_set") as send:
            core = self._loaded()
            assert core.set_output(BID, "1", selected=False) == ActionResult(False, "unknown_appliance")
            assert core.set_output(AID, "9", selected=False) == ActionResult(False, "wrong_state")
            assert core.set_output(AID, "1") == ActionResult(False, "wrong_state")
            core.set_roster([_entry(dial_outputs=False)])
            assert core.set_output(AID, "1", selected=False) == ActionResult(False, "no_capability")
            core.set_roster([_entry(dial_outputs=True, auth=AUTH_UNAUTHORIZED)])
            assert core.set_output(AID, "1", selected=False) == ActionResult(False, "unauthorized")
        send.assert_not_called()

    def test_the_tap_outlives_the_watchers(self):
        core = self._loaded(_Clock(1000.0))
        with patch("dial_core.enqueue_set"):
            core.set_output(AID, "1", selected=False)
        core.watch_outputs(AID, "spi", False)
        assert core.snapshot().outputs is None
        assert core.outputs_override() == ("1", False, 40, 1000.0)


def _eq_body(bass, treble):
    return {"ok": True, "bass_db": bass, "treble_db": treble}


class TestEq:
    def _watching(self, clock=None, version=0):
        core = _io_core(clock)
        if version:
            core.set_roster([dataclasses.replace(_entry(dial_eq=True), dial_eq_version=version)])
        with patch("dial_core._enqueue_eq_fetch"):
            core.watch_eq(AID, "spi", True)
        return core

    def _six_band_body(self, **gains):
        order = (("peq1", 40), ("peq2", 100), ("peq3", 300), ("peq4", 1000), ("peq5", 4000), ("peq6", 10000))
        return {
            "ok": True, "bass_db": 2, "treble_db": -1,
            "bands": [
                {"id": i, "frequency_hz": f, "type": "peak", "gain_db": gains.get(i, 0.0),
                 "min_db": -12, "max_db": 12}
                for i, f in order
            ],
        }

    def test_a_six_band_fetch_holds_eight_bands(self):
        core = self._watching(version=2)
        assert core.on_eq_result("fetch", AID, 200, self._six_band_body(peq3=1.0))
        held = core.snapshot().eq
        assert [b.id for b in held.bands] == [
            "peq1", "peq2", "peq3", "peq4", "peq5", "peq6", "bass", "treble"]
        assert held.bands[2] == EqBand("peq3", 300, 1, -12, 12)

    def test_a_capability_one_state_reads_only_bass_and_treble(self):
        core = self._watching(version=1)
        assert core.on_eq_result("fetch", AID, 200, self._six_band_body())
        assert [b.id for b in core.snapshot().eq.bands] == ["bass", "treble"]

    def test_a_malformed_six_band_reply_changes_nothing(self):
        core = self._watching(version=2)
        body = self._six_band_body()
        body["bands"] = "x"
        assert not core.on_eq_result("fetch", AID, 200, body)
        assert core.snapshot().eq.loaded is False

    def test_a_band_set_is_accepted_on_a_six_band_state(self):
        core = self._watching(_Clock(1000.0), version=2)
        core.on_eq_result("fetch", AID, 200, self._six_band_body())
        with patch("dial_core._enqueue_eq_set") as send:
            assert core.set_eq(AID, {"peq3": 3}).accepted
        assert send.call_args[0][1] == {"peq3": 3}
        pairs = dict(core.eq_override()[0])
        assert pairs["peq3"] == 3 and pairs["peq1"] == 0 and pairs["bass"] == 2 and pairs["treble"] == -1

    def test_a_band_step_clamps_to_the_band_range(self):
        core = self._watching(_Clock(1000.0), version=2)
        core.on_eq_result("fetch", AID, 200, self._six_band_body(peq3=11.0))
        with patch("dial_core._enqueue_eq_set") as send:
            assert core.step_eq(AID, "peq3", +5).accepted
        assert send.call_args[0][1] == {"peq3": 12}

    def test_a_band_set_is_refused_on_a_capability_one_state(self):
        core = self._watching(_Clock(1000.0), version=1)
        core.on_eq_result("fetch", AID, 200, _eq_body(1, 2))
        with patch("dial_core._enqueue_eq_set") as send:
            assert core.set_eq(AID, {"peq3": 3}) == ActionResult(False, "no_capability")
            assert core.step_eq(AID, "peq3", 1) == ActionResult(False, "no_capability")
        assert not send.called

    def test_an_unknown_band_is_refused_on_a_six_band_state(self):
        core = self._watching(_Clock(1000.0), version=2)
        core.on_eq_result("fetch", AID, 200, self._six_band_body())
        assert core.set_eq(AID, {"peq9": 3}) == ActionResult(False, "no_capability")
        assert core.set_eq(AID, {"peq3": 1, "peq9": 3}) == ActionResult(False, "no_capability")

    def test_a_band_set_before_the_first_reading_is_refused(self):
        core = self._watching(_Clock(1000.0), version=2)
        assert core.set_eq(AID, {"peq3": 3}) == ActionResult(False, "no_capability")

    def test_bass_steps_send_bass_db_on_a_six_band_appliance(self):
        core = self._watching(_Clock(1000.0), version=2)
        core.on_eq_result("fetch", AID, 200, self._six_band_body())
        with patch("dial_core._enqueue_eq_set") as send:
            assert core.step_eq(AID, "bass", +1).accepted
        assert send.call_args[0][1] == {"bass": 3}
        from dial_eq import _set_body
        assert _set_body(send.call_args[0][1]) == {"bass_db": 3}


    def test_first_interest_fetches_once_and_holds_an_empty_state(self):
        core = _io_core()
        with patch("dial_core._enqueue_eq_fetch") as fetch:
            core.watch_eq(AID, "spi", True)
            core.watch_eq(AID, "hd", True)
        assert fetch.call_count == 1 and fetch.call_args[0][0].appliance_id == AID
        held = core.snapshot().eq
        assert (held.appliance_id, held.bands, held.loaded, held.capability_version) == (AID, (), False, 1)

    def test_the_capability_version_comes_from_the_roster(self):
        assert self._watching(version=2).snapshot().eq.capability_version == 2

    def test_the_last_watcher_leaving_drops_the_state(self):
        core = self._watching()
        core.watch_eq(AID, "spi", False)
        assert core.snapshot().eq is None

    def test_a_fetch_maps_bass_and_treble_to_two_bands(self):
        core = self._watching()
        assert core.on_eq_result("fetch", AID, 200, _eq_body(2, -3))
        held = core.snapshot().eq
        assert held.loaded is True
        assert held.bands == (EqBand("bass", None, 2, -6, 6), EqBand("treble", None, -3, -6, 6))

    def test_late_malformed_and_set_results_change_nothing(self):
        core = self._watching()
        seq = core.snapshot().seq
        assert not core.on_eq_result("fetch", BID, 200, _eq_body(1, 1))
        assert not core.on_eq_result("set", AID, 200, _eq_body(1, 1))
        assert not core.on_eq_result("fetch", AID, 500, None)
        assert not core.on_eq_result("fetch", AID, 200, {"ok": False})
        assert not core.on_eq_result("fetch", AID, 200, {"ok": True, "bass_db": "2", "treble_db": 1})
        assert not core.on_eq_result("fetch", AID, 200, {"ok": True, "bass_db": True, "treble_db": 1})
        assert core.snapshot().seq == seq

    def test_a_step_clamps_to_the_band_range_and_keeps_the_other_control(self):
        clock = _Clock(1000.0)
        core = self._watching(clock)
        core.on_eq_result("fetch", AID, 200, _eq_body(1, -3))
        with patch("dial_core._enqueue_eq_set") as send:
            assert core.step_eq(AID, "bass", +9).accepted
        assert core.eq_override() == ((("bass", 6), ("treble", -3)), 1002.0)
        assert core.snapshot().eq.optimistic == (("bass", 6), ("treble", -3))
        assert core.snapshot().eq.optimistic_expires_at == 1002.0
        assert send.call_args[0][1] == {"bass": 6}
        assert send.call_args[0][0].appliance_id == AID

    def test_a_step_before_the_first_reading_starts_from_zero(self):
        core = self._watching(_Clock(1000.0))
        with patch("dial_core._enqueue_eq_set"):
            core.step_eq(AID, "treble", -2)
        assert core.eq_override() == ((("treble", -2),), 1002.0)

    def test_the_tap_window_ends_at_its_boundary(self):
        clock = _Clock(1000.0)
        core = self._watching(clock)
        core.on_eq_result("fetch", AID, 200, _eq_body(0, 0))
        with patch("dial_core._enqueue_eq_set"):
            core.step_eq(AID, "bass", +2)
            assert core.step_eq(AID, "bass", +1).accepted      # steps from the tap shown: 3
        assert dict(core.eq_override()[0])["bass"] == 3
        clock.t = 1001.99
        core.on_eq_result("fetch", AID, 200, _eq_body(0, 0))
        assert core.eq_override()[0] != ()                     # inside the window: kept
        clock.t = 1002.01
        core.on_eq_result("fetch", AID, 200, _eq_body(0, 0))
        assert core.eq_override() == ((), 0.0)

    def test_set_eq_sends_only_the_bands_given_and_shows_all(self):
        core = self._watching(_Clock(1000.0))
        core.on_eq_result("fetch", AID, 200, _eq_body(1, 2))
        with patch("dial_core._enqueue_eq_set") as send:
            core.set_eq(AID, {"treble": -4})
        assert send.call_args[0][1] == {"treble": -4}
        assert dict(core.eq_override()[0]) == {"bass": 1, "treble": -4}

    def test_refusals_name_their_reason(self):
        with patch("dial_core._enqueue_eq_set") as send:
            core = self._watching()
            assert core.set_eq(AID, {"peq1": 1}) == ActionResult(False, "no_capability")
            assert core.set_eq(AID, {}) == ActionResult(False, "no_capability")
            assert core.step_eq(AID, "peq3", 1) == ActionResult(False, "no_capability")
            assert core.set_eq(BID, {"bass": 1}) == ActionResult(False, "unknown_appliance")
            core.watch_eq(AID, "spi", False)
            assert core.set_eq(AID, {"bass": 1}) == ActionResult(False, "not_polling")
            core.set_roster([_entry(dial_eq=False)])
            assert core.set_eq(AID, {"bass": 1}) == ActionResult(False, "no_capability")
            core.set_roster([_entry(dial_eq=True, auth=AUTH_UNAUTHORIZED)])
            assert core.step_eq(AID, "bass", 1) == ActionResult(False, "unauthorized")
        send.assert_not_called()

    def test_reset_sets_every_band_to_zero_on_a_six_band_state(self):
        core = self._watching(_Clock(1000.0), version=2)
        core.on_eq_result("fetch", AID, 200, self._six_band_body(peq3=4.0, peq6=-2.0))
        with patch("dial_core._enqueue_eq_set") as send:
            assert core.reset_eq(AID).accepted
        assert send.call_args[0][1] == {f"peq{n}": 0 for n in range(1, 7)}
        pairs = dict(core.eq_override()[0])
        assert pairs["peq3"] == 0 and pairs["peq6"] == 0

    def test_reset_sets_bass_and_treble_to_zero_on_a_capability_one_state(self):
        core = self._watching(_Clock(1000.0), version=1)
        core.on_eq_result("fetch", AID, 200, _eq_body(3, -2))
        with patch("dial_core._enqueue_eq_set") as send:
            assert core.reset_eq(AID).accepted
        assert send.call_args[0][1] == {"bass": 0, "treble": 0}
        assert dict(core.eq_override()[0]) == {"bass": 0, "treble": 0}

    def test_reset_refusals_name_their_reason(self):
        with patch("dial_core._enqueue_eq_set") as send:
            core = self._watching()
            assert core.reset_eq(BID) == ActionResult(False, "unknown_appliance")
            core.watch_eq(AID, "spi", False)
            assert core.reset_eq(AID) == ActionResult(False, "not_polling")
            core.set_roster([_entry(dial_eq=False)])
            assert core.reset_eq(AID) == ActionResult(False, "no_capability")
            core.set_roster([_entry(dial_eq=True, auth=AUTH_UNAUTHORIZED)])
            assert core.reset_eq(AID) == ActionResult(False, "unauthorized")
        send.assert_not_called()

    def test_fetch_now_asks_whatever_the_interest(self):
        core = _io_core()
        with patch("dial_core._enqueue_eq_fetch") as eq_fetch, patch("dial_core.enqueue_fetch") as out_fetch:
            assert core.fetch_eq(AID) and core.fetch_outputs(AID)
            assert not core.fetch_eq(BID) and not core.fetch_outputs(BID)
        assert eq_fetch.call_count == 1 and out_fetch.call_count == 1


# ---------------------------------------------------------------------------
# Transport requests and the repeat worker's results
# ---------------------------------------------------------------------------

class TestTransport:
    @pytest.fixture(autouse=True)
    def _store(self):
        from dial_repeat_store import repeat_store
        repeat_store.clear(AID)
        yield repeat_store
        repeat_store.clear(AID)

    def _core(self, clock=None):
        core = _core(clock)
        core.set_roster([_entry(repeat_capable=True)])
        return core

    def test_a_request_is_pending_until_the_worker_reports(self):
        clock = _Clock(1000.0)
        core = self._core(clock)
        core.begin_transport(AID, "seek")
        assert core.snapshot().transport == TransportRequest(AID, "seek", 1000.0, "pending", 1000.0, None)

    def test_an_ok_ack_marks_it_accepted(self, _store):
        clock = _Clock(1000.0)
        core = self._core(clock)
        _store.update(AID, _record("hold"))
        core.begin_transport(AID, "seek")
        clock.t = 1001.0
        outcome = core.on_repeat_result("transport", AID, 200, {"ok": True, "state": "replaying"})
        assert outcome == RepeatOutcome(True, False, False)
        assert core.snapshot().transport == TransportRequest(AID, "seek", 1000.0, "accepted", 1001.0, None)

    def test_only_the_ack_of_a_stop_counts_as_its_own(self, _store):
        core = self._core()
        _store.update(AID, _record("replaying"))
        core.begin_transport(AID, "stop")
        first = core.on_repeat_result("transport", AID, 200, {"ok": True, "state": "hold"})
        again = core.on_repeat_result("transport", AID, 200, {"ok": True, "state": "hold"})
        assert first.stop_acked is True and again.stop_acked is False

    def test_a_seek_ack_is_not_a_stop_ack(self, _store):
        core = self._core()
        _store.update(AID, _record("hold"))
        core.begin_transport(AID, "seek")
        assert core.on_repeat_result("transport", AID, 200, {"ok": True, "state": "hold"}).stop_acked is False

    def test_a_rejection_carries_the_daemon_error(self):
        clock = _Clock(1000.0)
        core = self._core(clock)
        core.begin_transport(AID, "seek")
        clock.t = 1002.0
        outcome = core.on_repeat_result("transport", AID, 412, {"ok": False, "error": "fading_out"})
        assert outcome == RepeatOutcome(False, False, False)
        assert core.snapshot().transport == TransportRequest(
            AID, "seek", 1000.0, "rejected", 1002.0, "fading_out",
        )

    def test_a_transient_failure_is_rejected_with_a_generic_error(self):
        core = self._core()
        core.begin_transport(AID, "arm")
        core.on_repeat_result("arm", AID, None, None)
        assert core.snapshot().transport.state == "rejected"
        assert core.snapshot().transport.error == "unreachable"
        core.begin_transport(AID, "arm")
        core.on_repeat_result("arm", AID, 503, None)
        assert core.snapshot().transport.error == "http_503"

    def test_a_result_for_another_appliance_leaves_the_request_alone(self):
        core = self._core()
        core.begin_transport(AID, "seek")
        core.on_repeat_result("transport", BID, 412, {"ok": False, "error": "x"})
        assert core.snapshot().transport.state == "pending"

    def test_the_next_request_replaces_a_settled_one(self):
        clock = _Clock(1000.0)
        core = self._core(clock)
        core.begin_transport(AID, "seek")
        core.on_repeat_result("transport", AID, 412, {"ok": False, "error": "x"})
        clock.t = 1005.0
        core.begin_transport(AID, "stop")
        assert core.snapshot().transport == TransportRequest(AID, "stop", 1005.0, "pending", 1005.0, None)

    def test_an_accepted_replay_of_the_followed_appliance_opens_the_window(self, _store):
        clock = _Clock(1000.0)
        core = self._core(clock)
        core.set_focus(AID)
        _store.update(AID, _record("hold"))
        outcome = core.on_repeat_result("transport", AID, 200, {"ok": True, "state": "replaying"})
        assert outcome.replay_accepted is True
        assert core.snapshot().focus.accepted_replay == (AID, 1020.0)

    def test_an_ack_for_another_appliance_opens_no_window(self, _store):
        core = self._core()
        core.set_focus(BID)
        outcome = core.on_repeat_result("transport", AID, 200, {"ok": True, "state": "replaying"})
        assert outcome.replay_accepted is False
        assert core.snapshot().focus.accepted_replay is None

    def test_a_rejection_drops_a_pending_focus_and_clears_a_gone_buffer(self, _store):
        core = self._core()
        _store.update(AID, _record("hold"))
        core.set_focus_pending(AID, "Kitchen", 1010.0)
        core.on_repeat_result("transport", AID, 412, {"ok": False, "error": "no_recording"})
        assert core.snapshot().focus.pending is None and core.manual_focus_id() is None
        record = _store.get(AID, 1.0)
        assert record is None or not record.available

    def test_a_rejection_nudges_the_auth_map_outside_the_core_lock(self):
        core = self._core()
        seen = []
        with patch("dial_core.auth_map") as amap:
            amap.force_due.side_effect = lambda *a: seen.append(core._lock.locked())
            core.on_repeat_result("transport", AID, 412, {"ok": False, "error": "x"})
        assert seen == [False]


# ---------------------------------------------------------------------------
# Warnings, update watch and sources in the core
# ---------------------------------------------------------------------------

import json  # noqa: E402

from dial_core_state import ApplianceWarning, NOWIFI_PROMPT_STREAK, validate_appliance_warnings  # noqa: E402
from dial_network import LINK_CONNECTED, LINK_DOWN, LINK_IGNORED, LINK_UNKNOWN, NetworkView  # noqa: E402
from dial_sdhealth import STATUS_VALID, SdHealthView  # noqa: E402
from dial_update_watch import UpdateView, UpdateWatcher  # noqa: E402
from dial_warning_text import (  # noqa: E402
    APPLIANCE_WARNING_PRIORITY, WARNING_DESCRIPTORS, appliance_warning_key,
)
from dial_warnings import WarningManager, WarningStore  # noqa: E402


def _warning_core(tmp_path=None, wall=None, store_path=None, reboot=None, **kwargs):
    wall = wall or _Clock(1_000_000.0)
    manager = WarningManager(
        WARNING_DESCRIPTORS, WarningStore(store_path), clock=wall,
    )
    core = DialCore(
        "dial-1", lambda: [], lambda: [], warnings=manager,
        update_watcher=UpdateWatcher(str(tmp_path / "update-result.env")) if tmp_path else None,
        update_seen_path=str(tmp_path / "seen") if tmp_path else "/nonexistent/seen",
        reboot=reboot, **kwargs,
    )
    return core, manager, wall


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
        assert snap.due_warning_id is None

    def test_an_active_warning_shows_its_severity_and_start(self):
        core, manager, wall = _warning_core()
        change = core.warning_active("sdhealth", 40)
        assert change.began is True and change.active is True
        row = _row(core, "sdhealth")
        assert row.active and row.severity == 40 and row.active_since == wall.t
        assert core.snapshot().due_warning_id == "sdhealth"

    def test_a_repeat_refreshes_and_is_not_a_new_incident(self):
        core, manager, wall = _warning_core()
        core.warning_active("sdhealth", 40)
        seq = core.snapshot().seq
        wall.t += 10
        change = core.warning_active("sdhealth", 40)
        assert change.began is False
        assert core.snapshot().seq == seq
        core.warning_active("sdhealth", 30)
        assert _row(core, "sdhealth").severity == 30
        assert _row(core, "sdhealth").active_since == 1_000_000.0

    def test_the_due_id_follows_priority(self):
        core, manager, _ = _warning_core()
        core.warning_active("sdhealth", 40)
        core.warning_active("nowifi")
        assert core.snapshot().due_warning_id == "nowifi"
        core.warning_active("update", _progress())
        assert core.snapshot().due_warning_id == "update"
        core.warning_cleared("update")
        core.warning_cleared("nowifi")
        assert core.snapshot().due_warning_id == "sdhealth"

    def test_a_dismissed_warning_is_not_due_until_the_snooze_runs_out(self):
        core, manager, wall = _warning_core()
        core.warning_active("sdhealth", 40)
        assert core.dismiss_warning("sdhealth") == ActionResult(True)
        assert core.snapshot().due_warning_id is None
        assert _row(core, "sdhealth").snoozed_until is not None
        wall.t += 7 * 86400.0 + 1
        core.expire_warnings()
        assert core.snapshot().due_warning_id == "sdhealth"
        assert _row(core, "sdhealth").snoozed_until is None

    def test_an_incident_scoped_dismissal_is_infinite_until_the_source_clears(self):
        core, manager, wall = _warning_core()
        core.warning_active("nowifi")
        core.dismiss_warning("nowifi")
        assert _row(core, "nowifi").snoozed_until == float("inf")
        core.warning_cleared("nowifi")
        assert _row(core, "nowifi").snoozed_until is None and not _row(core, "nowifi").active

    def test_dismiss_is_refused_for_a_notice_and_an_unknown_id(self):
        core, manager, _ = _warning_core()
        core.warning_active("update", _progress())
        assert core.dismiss_warning("update") == ActionResult(False, "wrong_state")
        assert core.dismiss_warning("nope") == ActionResult(False, "wrong_state")
        assert core.snapshot().due_warning_id == "update"

    def test_dismissing_an_update_result_card_works(self):
        core, manager, _ = _warning_core()
        core.warning_active("update_result", _finished())
        assert core.dismiss_warning("update_result").accepted
        assert core.snapshot().due_warning_id is None

    def test_a_snooze_written_to_the_store_survives_a_new_core(self, tmp_path):
        path = str(tmp_path / "warnings.json")
        wall = _Clock(1_000_000.0)
        core, manager, _ = _warning_core(wall=wall, store_path=path)
        core.warning_active("sdhealth", 40)
        core.dismiss_warning("sdhealth")
        core.flush_warnings()
        wall.t += 3600
        again, manager2, _ = _warning_core(wall=wall, store_path=path)
        again.warning_active("sdhealth", 40)
        assert again.snapshot().due_warning_id is None
        assert _row(again, "sdhealth").snoozed_until is not None


class TestNetworkSource:
    def test_a_connected_reading_sets_the_latch_and_the_view(self):
        core, manager, _ = _warning_core()
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
        assert core.wifi_down_streak() == NOWIFI_PROMPT_STREAK + 3
        assert core.snapshot().due_warning_id is None

    def test_a_loss_after_connecting_activates_at_the_streak(self):
        core, manager, _ = _warning_core()
        core.on_network_view(_net(LINK_CONNECTED))
        for _ in range(NOWIFI_PROMPT_STREAK - 1):
            assert core.on_network_view(_net(LINK_DOWN)).changes == ()
        effects = core.on_network_view(_net(LINK_DOWN))
        (change,) = effects.changes
        assert (change.warning_id, change.active, change.began) == ("nowifi", True, True)
        assert core.snapshot().due_warning_id == "nowifi"
        again = core.on_network_view(_net(LINK_DOWN))
        assert again.changes[0].began is False

    def test_ignored_resets_the_streak_only(self):
        core, manager, _ = _warning_core()
        core.on_network_view(_net(LINK_CONNECTED))
        for _ in range(NOWIFI_PROMPT_STREAK):
            core.on_network_view(_net(LINK_DOWN))
        core.on_network_view(_net(LINK_IGNORED))
        assert core.wifi_down_streak() == 0
        assert core.snapshot().wifi_ever_connected is True
        assert manager.is_active("nowifi")

    def test_an_unknown_reading_changes_only_the_held_view(self):
        core, manager, _ = _warning_core()
        core.on_network_view(_net(LINK_CONNECTED))
        core.on_network_view(_net(LINK_DOWN))
        effects = core.on_network_view(_net(LINK_UNKNOWN))
        assert effects.changes == ()
        assert core.wifi_down_streak() == 1
        assert core.snapshot().network == _net(LINK_UNKNOWN)

    def test_connected_ends_the_incident_and_forgets_the_dismissal(self):
        core, manager, _ = _warning_core()
        core.on_network_view(_net(LINK_CONNECTED))
        for _ in range(NOWIFI_PROMPT_STREAK):
            core.on_network_view(_net(LINK_DOWN))
        core.dismiss_warning("nowifi")
        assert manager.is_snoozed("nowifi")
        core.on_network_view(_net(LINK_CONNECTED))
        assert not manager.is_snoozed("nowifi") and not manager.is_active("nowifi")
        assert core.snapshot().due_warning_id is None


class TestSdHealthSource:
    def test_low_activates_with_the_percent_and_recovery_clears(self):
        core, manager, _ = _warning_core()
        effects = core.on_sd_health_view(_sd(1))
        (change,) = effects.changes
        assert (change.warning_id, change.active, change.began) == ("sdhealth", True, True)
        assert core.sd_low() is True
        assert _row(core, "sdhealth").severity == 1
        assert core.snapshot().sd_health == _sd(1)
        effects = core.on_sd_health_view(_sd(100))
        assert effects.changes[0].active is False
        assert core.sd_low() is False and core.snapshot().due_warning_id is None

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
        assert core.snapshot().due_warning_id == "update"
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
        assert _row(core, "update").severity.percent == 30
        assert core.tick_update_watch(3.0) is None

    def test_the_result_card_clears_itself_after_an_hour(self, tmp_path):
        core, manager, wall = _warning_core(tmp_path)
        core.apply_update_view(_finished())
        wall.t += 3599
        assert core.expire_warnings().changes == ()
        wall.t += 2
        effects = core.expire_warnings()
        assert [(c.warning_id, c.active) for c in effects.changes] == [("update_result", False)]
        assert core.snapshot().due_warning_id is None


class TestHousekeepingAndReboot:
    def test_the_tick_folds_the_watch_expiry_and_flush_together(self, tmp_path):
        path = str(tmp_path / "warnings.json")
        core, manager, wall = _warning_core(tmp_path, store_path=path)
        core.warning_active("sdhealth", 40)
        core.dismiss_warning("sdhealth")
        (tmp_path / "update-result.env").write_text(
            "STATUS=success\nPERCENT_COMPLETE=100\nTAG=0.7.0\nLAST_RUN_AT=t1\n")
        effects = core.tick_housekeeping(5.0)
        assert [c.warning_id for c in effects.changes] == ["update", "update_result"]
        assert "sdhealth" in json.loads((tmp_path / "warnings.json").read_text())
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

    def test_warning_changes_are_published_outside_the_core_lock(self):
        core, manager, _ = _warning_core()
        seen = []
        core.subscribe(lambda: seen.append(core._lock.locked()))
        core.warning_active("sdhealth", 5)
        core.on_network_view(_net(LINK_CONNECTED))
        assert seen and not any(seen)


def _lounge_core(tmp_path=None, **kwargs):
    core, manager, wall = _warning_core(tmp_path, **kwargs)
    core.set_roster([_entry(AID, "Kitchen"), _entry(BID, "autostream on Lounge")])
    return core, manager, wall


def _stylus(**kw):
    base = dict(id="stylus", severity="warning", title="Replace stylus", message="500 h", dismissal="week")
    base.update(kw)
    return ApplianceWarning(**base)


def _slot(core, appliance_id):
    return core.snapshot().appliance(appliance_id)


class TestApplianceWarningsFeed:
    def test_a_validated_set_lands_in_the_appliance_slot_with_its_name(self):
        core, manager, _ = _lounge_core()
        assert core.set_appliance_warnings(BID, (_stylus(),)) == ActionResult(True)
        (w,) = _slot(core, BID).warnings
        assert w.appliance_name == "Lounge" and w.title == "Replace stylus"
        assert _slot(core, AID).warnings == ()

    def test_the_capability_flag_is_false_for_every_appliance_today(self):
        core, manager, _ = _lounge_core()
        assert not any(a.supplies_warnings for a in core.snapshot().appliances)

    def test_the_manager_gets_a_data_driven_row_namespaced_by_appliance(self):
        core, manager, _ = _lounge_core()
        core.set_appliance_warnings(BID, (_stylus(),))
        key = appliance_warning_key(BID, "stylus")
        desc = manager.descriptor(key)
        assert key == f"appliance:{BID}:stylus"
        assert desc is not None and desc.title == "Replace stylus"
        assert desc.message_for(None) == "500 h"
        assert desc.interrupting is False and desc.auto_clear_after_s is None
        assert desc.source_name == "Lounge" and desc.persisted is True
        assert manager.is_active(key)
        assert core.snapshot().due_warning_id == key

    def test_the_dial_sets_priority_below_every_dial_warning_in_a_fixed_band(self):
        core, manager, _ = _lounge_core()
        core.set_appliance_warnings(BID, (
            _stylus(id="a", severity="info"), _stylus(id="b", severity="warning"),
            _stylus(id="c", severity="critical"),
        ))
        priorities = {
            w: manager.descriptor(appliance_warning_key(BID, w)).priority for w in "abc"
        }
        assert priorities == {
            "a": APPLIANCE_WARNING_PRIORITY["info"], "b": APPLIANCE_WARNING_PRIORITY["warning"],
            "c": APPLIANCE_WARNING_PRIORITY["critical"],
        }
        assert max(priorities.values()) < min(d.priority for d in WARNING_DESCRIPTORS)
        assert core.snapshot().due_warning_id == appliance_warning_key(BID, "c")

    def test_a_dial_warning_outranks_an_appliance_warning(self):
        core, manager, _ = _lounge_core()
        core.set_appliance_warnings(BID, (_stylus(severity="critical"),))
        core.warning_active("sdhealth", 40)
        assert core.snapshot().due_warning_id == "sdhealth"
        core.dismiss_warning("sdhealth")
        assert core.snapshot().due_warning_id == appliance_warning_key(BID, "stylus")

    def test_the_same_warning_id_on_two_appliances_is_two_warnings(self):
        core, manager, _ = _lounge_core()
        core.set_appliance_warnings(AID, (_stylus(),))
        core.set_appliance_warnings(BID, (_stylus(),))
        assert manager.is_active(appliance_warning_key(AID, "stylus"))
        assert manager.is_active(appliance_warning_key(BID, "stylus"))
        core.dismiss_warning(appliance_warning_key(AID, "stylus"))
        assert manager.is_snoozed(appliance_warning_key(AID, "stylus"))
        assert not manager.is_snoozed(appliance_warning_key(BID, "stylus"))

    def test_the_dismissal_hint_picks_the_snooze_or_makes_a_notice(self):
        core, manager, wall = _lounge_core()
        core.set_appliance_warnings(BID, (
            _stylus(id="d", dismissal="day"), _stylus(id="w", dismissal="week"),
            _stylus(id="n", dismissal="none"),
        ))
        day, week, none = (appliance_warning_key(BID, w) for w in "dwn")
        assert [b.label for b in manager.descriptor(none).buttons] == ["OK"]
        assert [b.label for b in manager.descriptor(day).buttons] == ["Dismiss"]
        assert core.dismiss_warning(none) == ActionResult(True)
        core.dismiss_warning(day)
        core.dismiss_warning(week)
        wall.t += 86400.0 + 1
        assert manager.is_snoozed(none)
        assert not manager.is_snoozed(day) and manager.is_snoozed(week)
        wall.t += 6 * 86400.0
        assert not manager.is_snoozed(week)
        assert manager.is_snoozed(none)

    def test_a_notice_is_put_away_until_the_appliance_stops_reporting_it(self):
        core, manager, wall = _lounge_core()
        key = appliance_warning_key(BID, "n")
        core.set_appliance_warnings(BID, (_stylus(id="n", dismissal="none"),))
        core.dismiss_warning(key)
        wall.t += 365 * 86400.0
        assert manager.is_snoozed(key) and core.snapshot().due_warning_id is None
        core.set_appliance_warnings(BID, ())
        core.set_appliance_warnings(BID, (_stylus(id="n", dismissal="none"),))
        assert not manager.is_snoozed(key) and core.snapshot().due_warning_id == key

    def test_a_notice_is_never_written_to_the_snooze_file(self, tmp_path):
        path = tmp_path / "warnings.json"
        core, manager, _ = _lounge_core(store_path=str(path))
        core.set_appliance_warnings(BID, (
            _stylus(id="n", dismissal="none"), _stylus(id="w", dismissal="week"),
        ))
        core.dismiss_warning(appliance_warning_key(BID, "n"))
        core.dismiss_warning(appliance_warning_key(BID, "w"))
        core.flush_warnings()
        assert set(json.loads(path.read_text())) == {appliance_warning_key(BID, "w")}

    def test_escalation_keeps_a_snooze_taken_at_the_lower_severity(self):
        core, manager, wall = _lounge_core()
        key = appliance_warning_key(BID, "stylus")
        core.set_appliance_warnings(BID, (_stylus(severity="warning"),))
        core.dismiss_warning(key)
        core.set_appliance_warnings(BID, (_stylus(severity="critical"),))
        assert manager.descriptor(key).priority == APPLIANCE_WARNING_PRIORITY["critical"]
        assert manager.is_snoozed(key) and core.snapshot().due_warning_id is None

    def test_an_appliance_with_no_roster_name_is_still_attributed(self):
        core, manager, _ = _warning_core()
        core.set_roster([_entry(AID, "")])
        core.set_appliance_warnings(AID, (_stylus(),))
        assert manager.descriptor(appliance_warning_key(AID, "stylus")).source_name == "Appliance"

    def test_a_replacement_set_ends_the_incidents_no_longer_present(self):
        core, manager, _ = _lounge_core()
        core.set_appliance_warnings(BID, (_stylus(id="a"), _stylus(id="b")))
        core.dismiss_warning(appliance_warning_key(BID, "a"))
        core.set_appliance_warnings(BID, (_stylus(id="b"),))
        assert manager.descriptor(appliance_warning_key(BID, "a")) is None
        assert [w.id for w in _slot(core, BID).warnings] == ["b"]
        assert appliance_warning_key(BID, "a") not in [w.id for w in core.snapshot().warnings]
        core.set_appliance_warnings(BID, (_stylus(id="a"),))
        assert not manager.is_snoozed(appliance_warning_key(BID, "a"))

    def test_an_empty_set_clears_everything_for_the_appliance(self):
        core, manager, _ = _lounge_core()
        core.set_appliance_warnings(BID, (_stylus(),))
        core.set_appliance_warnings(BID, ())
        assert _slot(core, BID).warnings == ()
        assert core.snapshot().due_warning_id is None
        assert [w.id for w in core.snapshot().warnings] == [d.id for d in WARNING_DESCRIPTORS]

    def test_the_same_set_again_publishes_nothing(self):
        core, manager, _ = _lounge_core()
        core.set_appliance_warnings(BID, (_stylus(),))
        seq = core.snapshot().seq
        assert core.set_appliance_warnings(BID, (_stylus(),)).accepted
        assert core.snapshot().seq == seq

    def test_a_changed_text_replaces_the_row_and_keeps_the_incident(self):
        core, manager, wall = _lounge_core()
        core.set_appliance_warnings(BID, (_stylus(),))
        key = appliance_warning_key(BID, "stylus")
        core.dismiss_warning(key)
        wall.t += 5
        core.set_appliance_warnings(BID, (_stylus(title="Replace the stylus"),))
        assert manager.descriptor(key).title == "Replace the stylus"
        assert manager.is_snoozed(key)

    def test_an_unknown_appliance_is_refused(self):
        core, manager, _ = _lounge_core()
        assert core.set_appliance_warnings("c" * 20, (_stylus(),)) == ActionResult(False, "unknown_appliance")
        assert core.snapshot().due_warning_id is None

    def test_the_core_keeps_at_most_the_cap_of_well_formed_distinct_warnings(self):
        core, manager, _ = _lounge_core()
        many = tuple(_stylus(id=f"w{i}") for i in range(30))
        core.set_appliance_warnings(BID, many)
        assert len(_slot(core, BID).warnings) == 8
        core.set_appliance_warnings(BID, (_stylus(id="Bad Id"), "junk", None, _stylus(id="a"), _stylus(id="a")))
        assert [w.id for w in _slot(core, BID).warnings] == ["a"]

    def test_an_appliance_leaving_the_roster_loses_its_warnings(self):
        core, manager, _ = _lounge_core()
        core.set_appliance_warnings(BID, (_stylus(),))
        core.set_roster([_entry(AID, "Kitchen")])
        assert manager.descriptor(appliance_warning_key(BID, "stylus")) is None
        assert core.snapshot().due_warning_id is None
        assert core.snapshot().appliance(BID) is None

    def test_a_roster_refresh_keeps_warnings_for_appliances_still_present(self):
        core, manager, _ = _lounge_core()
        core.set_appliance_warnings(BID, (_stylus(),))
        core.set_roster([_entry(AID, "Kitchen"), _entry(BID, "autostream on Lounge", playing=True)])
        assert len(_slot(core, BID).warnings) == 1
        assert manager.is_active(appliance_warning_key(BID, "stylus"))

    def test_a_persisted_snooze_survives_a_restart_before_the_appliance_reports(self, tmp_path):
        path = str(tmp_path / "warnings.json")
        wall = _Clock(1_000_000.0)
        core, manager, _ = _lounge_core(wall=wall, store_path=path)
        core.set_appliance_warnings(BID, (_stylus(),))
        key = appliance_warning_key(BID, "stylus")
        core.dismiss_warning(key)
        core.flush_warnings()
        wall.t += 3600

        again, manager2, _ = _lounge_core(wall=wall, store_path=path)
        assert manager2.descriptor(key) is None
        manager2._dirty = True          # something else changed meanwhile
        again.flush_warnings()
        assert key in json.loads((tmp_path / "warnings.json").read_text())
        again.set_appliance_warnings(BID, (_stylus(),))
        assert manager2.is_snoozed(key)
        assert again.snapshot().due_warning_id is None

    def test_a_parked_snooze_that_runs_out_is_dropped_on_the_next_write(self, tmp_path):
        path = str(tmp_path / "warnings.json")
        wall = _Clock(1_000_000.0)
        core, manager, _ = _lounge_core(wall=wall, store_path=path)
        core.set_appliance_warnings(BID, (_stylus(dismissal="day"),))
        core.dismiss_warning(appliance_warning_key(BID, "stylus"))
        core.flush_warnings()
        wall.t += 3600
        again, manager2, _ = _lounge_core(wall=wall, store_path=path)
        wall.t += 86400
        manager2._dirty = True
        again.flush_warnings()
        assert json.loads((tmp_path / "warnings.json").read_text()) == {}

    def test_the_validator_output_feeds_straight_in(self):
        core, manager, _ = _lounge_core()
        body = {"appliance_id": BID, "warnings": [
            {"id": "stylus", "severity": "critical", "title": "Replace stylus‮", "message": "x" * 500},
            {"id": "BAD ID", "title": "dropped"},
        ]}
        core.set_appliance_warnings(BID, validate_appliance_warnings(body, BID))
        (w,) = _slot(core, BID).warnings
        assert w.title == "Replace stylus" and len(w.message) == 120 and w.severity == "critical"

    def test_an_appliance_warning_is_not_a_row_of_the_static_table(self):
        from dial_display import _WARNING_BY_ID
        core, manager, _ = _lounge_core()
        core.set_appliance_warnings(BID, (_stylus(),))
        assert core.snapshot().due_warning_id not in _WARNING_BY_ID


# ---- where an appliance's warnings come from -----------------------------------

import dial_capabilities  # noqa: E402
from dial_auth import auth_map  # noqa: E402
from dial_core import (  # noqa: E402
    WARNINGS_RECONCILE_S, WARNINGS_RECONCILE_SPREAD_S, _warnings_spread,
)

_ID_A = "a" * 20
_ID_B = "b" * 20


def _warn_body(appliance_id, *warnings, ok=True):
    return {
        "ok": ok, "appliance_id": appliance_id,
        "warnings": [
            dict(id=w, severity="warning", title="Replace stylus", message="500 h", dismissal="week")
            for w in warnings
        ],
    }


def _supplier(appliance_id=_ID_A, name="Kitchen", auth=AUTH_AUTHORIZED, proto=3, version="0.8.0"):
    return RosterEntry(
        appliance_id=appliance_id, service_name=name, name=name, ip="192.0.2.10", port=80,
        playing=False, repeat_capable=False, auth=auth, dial_proto_version=proto,
        version=version,
    )


def _learn(appliance_id=_ID_A, version="0.8.0", warnings=1):
    dial_capabilities.record(
        appliance_id, version, {"dial_status": 1, "dial_warnings": warnings}, 0.0,
    )


class TestApplianceWarningsSource:
    @pytest.fixture(autouse=True)
    def _isolate(self):
        dial_capabilities.registry.clear()
        auth_map.reset()
        with patch("dial_core._enqueue_appliance_fetch") as enq:
            self.fetches = enq
            yield
        dial_capabilities.registry.clear()
        auth_map.reset()

    def _core(self, *entries, polling=True):
        core, manager, wall = _warning_core()
        for e in entries:
            if e.dial_proto_version >= 3:
                _learn(e.appliance_id, e.version)
        core.set_roster(list(entries))
        core.set_polling(polling)
        return core

    def _asked(self):
        return [(c.args[0], c.args[1].appliance_id) for c in self.fetches.call_args_list]

    def test_a_first_authorised_sighting_is_fetched_on_the_next_step(self):
        core = self._core(_supplier())
        core._refresh_appliance_warnings(1000.0)
        assert self._asked() == [("warnings", _ID_A)]
        target = self.fetches.call_args.args[1]
        assert (target.ip, target.port) == ("192.0.2.10", 80)

    def test_the_housekeeping_tick_runs_the_step(self):
        core = self._core(_supplier())
        core._housekeeping(1000.0)
        assert ("warnings", _ID_A) in self._asked()

    def test_a_push_fetches_at_once_and_restarts_the_interval(self):
        core = self._core(_supplier())
        core._refresh_appliance_warnings(1000.0)
        self.fetches.reset_mock()
        core._refresh_appliance_warnings(1001.0)
        assert not self.fetches.called
        core.notify_warnings_changed(_ID_A)
        core._refresh_appliance_warnings(1002.0)
        assert self._asked() == [("warnings", _ID_A)]
        self.fetches.reset_mock()
        core._refresh_appliance_warnings(1002.0 + WARNINGS_RECONCILE_S - 1)
        assert not self.fetches.called

    def test_the_interval_boundary_includes_the_appliances_own_spread(self):
        core = self._core(_supplier())
        core._refresh_appliance_warnings(1000.0)
        due = 1000.0 + WARNINGS_RECONCILE_S + _warnings_spread(_ID_A)
        self.fetches.reset_mock()
        core._refresh_appliance_warnings(due - 0.5)
        assert not self.fetches.called
        core._refresh_appliance_warnings(due)
        assert self._asked() == [("warnings", _ID_A)]

    def test_the_spread_differs_between_ids_and_stays_inside_its_window(self):
        spreads = {_warnings_spread(c * 20) for c in "abcdefgh"}
        assert len(spreads) > 1
        assert all(0.0 <= s < WARNINGS_RECONCILE_SPREAD_S for s in spreads)
        assert _warnings_spread(_ID_A) == _warnings_spread(_ID_A)

    def test_a_wake_fetches_every_appliance_again(self):
        core = self._core(_supplier(_ID_A), _supplier(_ID_B, name="Lounge"))
        core._refresh_appliance_warnings(1000.0)
        self.fetches.reset_mock()
        core.request_poll(reconcile=True)
        core._refresh_appliance_warnings(1001.0)
        assert sorted(self._asked()) == [("warnings", _ID_A), ("warnings", _ID_B)]
        self.fetches.reset_mock()
        core._refresh_appliance_warnings(1002.0)
        assert not self.fetches.called

    def test_nothing_is_fetched_for_an_appliance_that_cannot_or_may_not(self):
        core = self._core(
            _supplier(_ID_A, proto=2),
            _supplier(_ID_B, name="Lounge", auth=AUTH_UNAUTHORIZED),
            _supplier("c" * 20, name="Study", auth=AUTH_UNKNOWN),
        )
        core.notify_warnings_changed(_ID_A)
        core.notify_warnings_changed(_ID_B)
        core._refresh_appliance_warnings(1000.0)
        assert not self.fetches.called

    def test_an_appliance_without_the_capability_is_not_fetched(self):
        core, _, _ = _warning_core()
        _learn(_ID_A, warnings=0)
        core.set_roster([_supplier()])
        core.set_polling(True)
        core._refresh_appliance_warnings(1000.0)
        assert not self.fetches.called

    def test_polling_off_fetches_nothing_and_resumes_when_on(self):
        core = self._core(_supplier(), polling=False)
        core.notify_warnings_changed(_ID_A)
        core._refresh_appliance_warnings(1000.0)
        assert not self.fetches.called
        core.set_polling(True)
        core._refresh_appliance_warnings(1001.0)
        assert self._asked() == [("warnings", _ID_A)]

    def test_a_good_reply_lands_in_the_slot_and_logs_a_count(self, caplog):
        core = self._core(_supplier())
        with caplog.at_level("INFO"):
            assert core.on_warnings_result(_ID_A, 200, _warn_body(_ID_A, "stylus"))
        assert [w.id for w in core.snapshot().appliance(_ID_A).warnings] == ["stylus"]
        assert "appliance warnings: Kitchen 1 warning(s)" in caplog.text
        assert "Replace stylus" not in caplog.text
        assert not core.on_warnings_result(_ID_A, 200, _warn_body(_ID_A, "stylus"))

    def test_an_empty_list_clears_the_slot(self):
        core = self._core(_supplier())
        core.on_warnings_result(_ID_A, 200, _warn_body(_ID_A, "stylus"))
        assert core.on_warnings_result(_ID_A, 200, _warn_body(_ID_A))
        assert core.snapshot().appliance(_ID_A).warnings == ()
        assert core.snapshot().due_warning_id is None

    @pytest.mark.parametrize("status,body", [
        (None, None),
        (403, {}),
        (400, {"ok": False, "error": "missing_dial_id"}),
        (200, {"ok": False, "error": "config_error"}),
        (200, {"ok": True, "appliance_id": _ID_A}),
        (200, {"ok": True, "appliance_id": _ID_B, "warnings": []}),
        (200, {"ok": True, "appliance_id": _ID_A, "warnings": "x"}),
        (200, None),
        (500, _warn_body(_ID_A)),
    ])
    def test_anything_else_keeps_what_is_held(self, status, body):
        core = self._core(_supplier())
        core.on_warnings_result(_ID_A, 200, _warn_body(_ID_A, "stylus"))
        seq = core.snapshot().seq
        assert not core.on_warnings_result(_ID_A, status, body)
        assert [w.id for w in core.snapshot().appliance(_ID_A).warnings] == ["stylus"]
        assert core.snapshot().seq == seq

    def test_a_refusal_clears_the_slot_and_demotes_auth(self):
        core = self._core(_supplier())
        core.on_warnings_result(_ID_A, 200, _warn_body(_ID_A, "stylus"))
        refusal = {"ok": False, "error": "dial_not_authorized", "appliance_id": _ID_A}
        assert core.on_warnings_result(_ID_A, 412, refusal)
        assert core.snapshot().appliance(_ID_A).warnings == ()
        assert auth_map.state(_ID_A) == AUTH_UNAUTHORIZED

    def test_a_refusal_naming_another_appliance_changes_nothing(self):
        core = self._core(_supplier())
        core.on_warnings_result(_ID_A, 200, _warn_body(_ID_A, "stylus"))
        refusal = {"ok": False, "error": "dial_not_authorized", "appliance_id": _ID_B}
        assert not core.on_warnings_result(_ID_A, 412, refusal)
        assert len(core.snapshot().appliance(_ID_A).warnings) == 1
        assert auth_map.state(_ID_A) != AUTH_UNAUTHORIZED

    def test_a_roster_that_shows_the_refusal_clears_and_forgets_the_schedule(self):
        core = self._core(_supplier())
        core._refresh_appliance_warnings(1000.0)
        core.on_warnings_result(_ID_A, 200, _warn_body(_ID_A, "stylus"))
        core.set_roster([_supplier(auth=AUTH_UNAUTHORIZED)])
        self.fetches.reset_mock()
        core._refresh_appliance_warnings(1001.0)
        assert core.snapshot().appliance(_ID_A).warnings == ()
        assert not self.fetches.called
        core.set_roster([_supplier()])
        core._refresh_appliance_warnings(1002.0)
        assert self._asked() == [("warnings", _ID_A)]

    def test_an_appliance_that_leaves_loses_its_warnings_and_its_schedule(self):
        core = self._core(_supplier(_ID_A), _supplier(_ID_B, name="Lounge"))
        core._refresh_appliance_warnings(1000.0)
        core.on_warnings_result(_ID_B, 200, _warn_body(_ID_B, "stylus"))
        core.set_roster([_supplier(_ID_A)])
        assert core.snapshot().due_warning_id is None
        core._refresh_appliance_warnings(1001.0)
        assert _ID_B not in core._warnings_next_at
        core.set_roster([_supplier(_ID_A), _supplier(_ID_B, name="Lounge")])
        self.fetches.reset_mock()
        core._refresh_appliance_warnings(1002.0)
        assert self._asked() == [("warnings", _ID_B)]

    def test_losing_the_capability_clears_the_slot(self):
        core = self._core(_supplier())
        core.on_warnings_result(_ID_A, 200, _warn_body(_ID_A, "stylus"))
        _learn(_ID_A, warnings=0)
        core.set_roster([_supplier(name="Kitchen2")])
        core._refresh_appliance_warnings(1000.0)
        assert core.snapshot().appliance(_ID_A).warnings == ()
        assert not self.fetches.called

    def test_a_result_for_an_unknown_appliance_is_ignored(self):
        core = self._core(_supplier())
        assert not core.on_warnings_result(_ID_B, 200, _warn_body(_ID_B, "stylus"))

    def test_the_push_entry_point_only_queues_and_wakes(self):
        core = self._core(_supplier())
        core._poll_wake.clear()
        core.notify_warnings_changed(_ID_A)
        assert core._poll_wake.is_set()
        assert not self.fetches.called
        assert core._warnings_pending == {_ID_A}

    def test_the_step_makes_no_network_call_of_its_own(self):
        core = self._core(_supplier())
        with patch("http.client.HTTPConnection") as conn, patch("socket.create_connection") as sock:
            core._refresh_appliance_warnings(1000.0)
            core.on_warnings_result(_ID_A, 200, _warn_body(_ID_A, "stylus"))
        assert not conn.called and not sock.called
        assert self.fetches.called

    def test_the_step_holds_no_lock_while_it_enqueues(self):
        core = self._core(_supplier())
        held = []
        self.fetches.side_effect = lambda *a: held.append(
            (core._lock.locked(), core._push_lock.locked()))
        core._refresh_appliance_warnings(1000.0)
        assert held == [(False, False)]
