"""Tests for the core's notification API as a second consumer (an adapter on
its own threads) would use it: slow, blocking and re-entrant subscribers,
many waiters, the effects queue, and the rule that no action does I/O or
reaches the view. Ordering is made with events and barriers, not sleeps."""
import dataclasses
import http.client
import os
import socket
import sys
import threading
import urllib.request
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dial"))

import pytest

import dial_core
import dial_core_state
from dial_core import EFFECTS_BACKLOG_MAX, DialCore
from dial_core_state import FocusState

WAIT = 10.0


def _core():
    return DialCore("dial-1", lambda: [], lambda: [])


def _tick(core, polling=True):
    return core.publish_tick(
        polling=polling,
        focus=FocusState(None, None, None, None, None, None, False),
        now_playing=None,
        idle_affordance=False,
        outputs_available=False,
        eq_available=False,
    )


class TestSubscriberReentrancy:
    def test_a_callback_can_unsubscribe_itself(self):
        core = _core()
        calls = []
        handle = []

        def once():
            calls.append(core.snapshot().seq)
            core.unsubscribe(handle[0])
        handle.append(core.subscribe(once))
        _tick(core)
        _tick(core)
        assert calls == [1]

    def test_a_callback_removing_a_later_one_stops_it_in_the_same_publish(self):
        core = _core()
        calls = []
        later = []
        core.subscribe(lambda: (calls.append("first"), core.unsubscribe(later[0])))
        later.append(core.subscribe(lambda: calls.append("later")))
        _tick(core)
        _tick(core)
        assert calls == ["first", "first"]

    def test_a_callback_can_publish_without_deadlock(self):
        core = _core()
        seqs = []

        def cb():
            seqs.append(core.snapshot().seq)
            if len(seqs) == 1:
                _tick(core, polling=False)
        core.subscribe(cb)
        _tick(core)
        assert core.snapshot().seq == 2
        assert seqs == [1, 2]

    def test_a_callback_reading_the_state_does_not_deadlock(self):
        core = _core()
        seen = []
        core.subscribe(lambda: seen.append((core.snapshot().seq, core.take_effects())))
        _tick(core)
        assert seen == [(1, [])]

    def test_unsubscribe_from_another_thread_during_a_callback(self):
        core = _core()
        inside = threading.Event()
        release = threading.Event()
        calls = []

        def blocker():
            calls.append("blocker")
            inside.set()
            release.wait(WAIT)
        handle = core.subscribe(blocker)
        core.subscribe(lambda: calls.append("tail"))
        t = threading.Thread(target=_tick, args=(core,))
        t.start()
        assert inside.wait(WAIT)
        core.unsubscribe(handle)         # must not wait for the running callback
        release.set()
        t.join(WAIT)
        assert not t.is_alive()
        assert calls == ["blocker", "tail"]
        _tick(core)
        assert calls == ["blocker", "tail", "tail"]


class TestBlockedSubscriber:
    def test_a_blocked_callback_holds_up_only_its_publisher(self):
        core = _core()
        inside = threading.Event()
        release = threading.Event()
        first = []

        def blocker():
            if not first:
                first.append(1)
                inside.set()
                release.wait(WAIT)
        core.subscribe(blocker)
        t = threading.Thread(target=_tick, args=(core,))
        t.start()
        assert inside.wait(WAIT)
        try:
            # the publisher is stuck in its callback; everyone else carries on
            assert core.snapshot().seq == 1
            core.subscribe(lambda: None)
            other = _tick(core, polling=False)
            assert other.seq == 2
            assert core.wait_for_change(1, 0.0).seq == 2
            core.take_effects()
        finally:
            release.set()
            t.join(WAIT)
        assert not t.is_alive()

    def test_a_blocked_callback_does_not_hold_back_a_waiter(self):
        core = _core()
        inside = threading.Event()
        release = threading.Event()
        core.subscribe(lambda: (inside.set(), release.wait(WAIT)))
        out = {}
        waiter = threading.Thread(target=lambda: out.update(snap=core.wait_for_change(0, WAIT)))
        waiter.start()
        t = threading.Thread(target=_tick, args=(core,))
        t.start()
        try:
            assert inside.wait(WAIT)
            waiter.join(WAIT)
            assert not waiter.is_alive()     # woken before the callbacks ran
            assert out["snap"].seq == 1
        finally:
            release.set()
            t.join(WAIT)

    def test_a_raising_callback_does_not_stop_later_ones_or_waiters(self):
        core = _core()
        later = []

        def boom():
            raise ValueError("bad subscriber")
        core.subscribe(boom)
        core.subscribe(lambda: later.append(1))
        _tick(core)
        assert later == [1]
        assert core.wait_for_change(0, 0.0).seq == 1


class TestManyWaiters:
    def test_every_waiter_is_woken_by_one_publish(self):
        core = _core()
        n = 8
        outs = [None] * n
        ready = threading.Barrier(n + 1)

        def waiter(i):
            ready.wait(WAIT)
            outs[i] = core.wait_for_change(0, WAIT)

        threads = [threading.Thread(target=waiter, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        ready.wait(WAIT)
        # a waiter that has not reached the wait yet sees the snapshot
        # already newer and returns at once, so no ordering is needed
        _tick(core)
        for t in threads:
            t.join(WAIT)
        assert all(not t.is_alive() for t in threads)
        assert [o.seq for o in outs] == [1] * n
        assert all(o is outs[0] for o in outs)

    def test_a_waiter_gets_the_newest_snapshot_after_several_publishes(self):
        core = _core()
        for i in range(5):
            _tick(core, polling=bool(i % 2))
        snap = core.wait_for_change(0, 0.0)
        assert snap is core.snapshot() and snap.seq == 5

    def test_looping_waiters_always_end_on_the_newest_snapshot(self):
        core = _core()
        n, publishes = 6, 200
        results = [None] * n
        errors = []
        ready = threading.Barrier(n + 1)

        def waiter(i):
            seen = 0
            seqs = []
            ready.wait(WAIT)
            while seen < publishes:
                snap = core.wait_for_change(seen, WAIT)
                if snap is None:
                    errors.append("timed out")
                    return
                if snap.seq <= seen:
                    errors.append("went backwards")
                    return
                seen = snap.seq
                seqs.append(seen)
            results[i] = seqs

        threads = [threading.Thread(target=waiter, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        ready.wait(WAIT)
        for i in range(publishes):
            _tick(core, polling=bool(i % 2))
        for t in threads:
            t.join(WAIT)
        assert errors == []
        for seqs in results:
            assert seqs is not None and seqs[-1] == publishes
            assert seqs == sorted(set(seqs))     # strictly increasing; gaps are coalescing

    def test_a_timeout_in_one_waiter_does_not_disturb_another(self):
        core = _core()
        out = {}
        t = threading.Thread(target=lambda: out.update(snap=core.wait_for_change(0, WAIT)))
        t.start()
        assert core.wait_for_change(5, 0.0) is None
        _tick(core)
        t.join(WAIT)
        assert out["snap"].seq == 1


class TestEffectsQueueIsAViewChannel:
    def test_subscribing_and_waiting_do_not_take_effects(self):
        core = _core()
        core.subscribe(lambda: None)
        core.readout_changed()
        assert core.wait_for_change(0, 0.0) is not None
        assert len(core.take_effects()) == 1

    def test_a_core_with_no_view_stays_bounded_and_keeps_publishing(self):
        core = _core()
        for _ in range(EFFECTS_BACKLOG_MAX * 3):
            core.readout_changed()
        assert len(core._effects) == EFFECTS_BACKLOG_MAX
        assert core.snapshot().seq == EFFECTS_BACKLOG_MAX * 3

    def test_two_takers_split_the_effects_with_none_lost_or_repeated(self):
        core = _core()
        total = EFFECTS_BACKLOG_MAX - 1
        marks = [dial_core.SourceEffects(restarting=bool(i % 2)) for i in range(total)]
        taken = [[], []]
        done = threading.Event()
        ready = threading.Barrier(3)

        def taker(i):
            ready.wait(WAIT)
            while True:
                finished = done.is_set()     # read first: a last take follows it
                taken[i].extend(core.take_effects())
                if finished:
                    return

        threads = [threading.Thread(target=taker, args=(i,)) for i in range(2)]
        for t in threads:
            t.start()
        ready.wait(WAIT)
        for effect in marks:
            core._queue_effects(effect)
        done.set()
        for t in threads:
            t.join(WAIT)
        everything = taken[0] + taken[1]
        assert len(everything) == total
        assert sorted(map(id, everything)) == sorted(map(id, marks))
        for batch in taken:
            ids = [id(e) for e in batch]
            order = [id(e) for e in marks if id(e) in set(ids)]
            assert ids == order


class TestCoreActionsStayInMemory:
    def test_no_action_does_network_io_or_touches_a_display(self):
        core = _core()

        def refuse(*args, **kwargs):
            raise AssertionError("network I/O from a core call")

        with patch.object(socket, "socket", refuse), \
                patch.object(socket, "create_connection", refuse), \
                patch.object(urllib.request, "urlopen", refuse), \
                patch.object(http.client.HTTPConnection, "request", refuse), \
                patch("dial_core.enqueue_delta"), patch("dial_core.enqueue_mute"), \
                patch("dial_core.enqueue_mute_all"), patch("dial_core.enqueue_fetch"), \
                patch("dial_core.enqueue_set"), patch("dial_core._enqueue_eq_fetch"), \
                patch("dial_core._enqueue_eq_set"), patch("dial_core.enqueue_arm"), \
                patch("dial_core.enqueue_transport"):
            core.set_roster([])
            _tick(core)
            core.set_focus(None)
            core.clear_focus("test")
            core.set_field("source_service_name", "Kitchen")
            core.volume_step(1)
            core.mute_toggle()
            core.start_replay("a" * 20)
            core.stop_replay("a" * 20)
            core.set_repeat_armed("a" * 20, True)
            core.step_output_volume("a" * 20, "o", 1)
            core.step_eq("a" * 20, "b", 1)
            core.set_eq("a" * 20, {})
            core.warning_active("nowifi")
            core.warning_cleared("nowifi")
            core.dismiss_warning("nowifi")
            core.expire_warnings()
            core.flush_warnings()
            core.readout_changed()
            core.notify_state_changed("a" * 20, ("mute",))
            core.set_inputs(["encoder"])
            core.take_effects()
            core.snapshot()
            core.wait_for_change(0, 0.0)
        # the core has no way to reach a view's lock: it never imports one
        assert not hasattr(dial_core, "dial_display")
        assert not hasattr(dial_core, "DialDisplay")


_PUBLISHED = {
    "NowPlaying", "SelectorRow", "PickerRow", "OutputRow", "ApplianceState", "FocusState",
    "Artwork", "OutputsState", "EqBand", "EqState", "WarningState", "TransportRequest",
    "ActionResult", "DialInfo", "TickContext", "CoreSnapshot", "ApplianceWarning",
}


class TestSnapshotsAreImmutable:
    def test_every_snapshot_type_is_frozen(self):
        types = {
            name: obj for name, obj in vars(dial_core_state).items()
            if name in _PUBLISHED and dataclasses.is_dataclass(obj)
        }
        assert set(types) == _PUBLISHED
        for name, t in types.items():
            assert t.__dataclass_params__.frozen, name

    def test_a_published_snapshot_rejects_writes(self):
        snap = _core().snapshot()
        for target, name in ((snap, "seq"), (snap.focus, "manual_id"), (snap.dial, "name")):
            with pytest.raises(dataclasses.FrozenInstanceError):
                setattr(target, name, 1)


class TestReaderConsistencyAcrossTicks:
    def test_a_reader_sees_monotonic_consistent_snapshots_while_the_poll_publishes(self):
        core = _core()
        ticks = 200
        stop = threading.Event()
        started = threading.Event()
        errors = []

        def reader():
            last = -1
            started.set()
            while not stop.is_set():
                snap = core.snapshot()
                if snap.seq < last:
                    errors.append("seq went backwards")
                last = snap.seq
                if snap.seq and snap.polling != (snap.seq % 2 == 1):
                    errors.append("torn snapshot")

        t = threading.Thread(target=reader)
        t.start()
        assert started.wait(WAIT)
        for i in range(ticks):
            _tick(core, polling=(i % 2 == 0))
        stop.set()
        t.join(WAIT)
        assert errors == []
        assert core.snapshot().seq == ticks
