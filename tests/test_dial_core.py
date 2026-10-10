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
