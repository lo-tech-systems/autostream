"""Tests for the dial-core thread: when it folds the peer clients, how it
paces the folds it is asked for, and its once-a-second housekeeping."""
import os
import sys
import threading
import time
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dial"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

import pytest

import dial_core
from dial_core import DialCore
from dial_update_watch import STATUS_IN_PROGRESS, UpdateView
from dial_warning_text import WARNING_DESCRIPTORS
from dial_warnings import WarningManager, WarningStore


def _make():
    return DialCore("dial-1", warnings=WarningManager(WARNING_DESCRIPTORS, WarningStore(None)))


@pytest.fixture
def interval(monkeypatch):
    """Set the fold interval for the test."""
    return lambda seconds: monkeypatch.setattr(dial_core, "FOLD_INTERVAL_S", seconds)


def _wait_for(condition, limit=3.0):
    deadline = time.monotonic() + limit
    while not condition() and time.monotonic() < deadline:
        time.sleep(0.005)
    return condition()


class TestCoreThread:
    def test_the_thread_folds_every_interval_and_stops_within_the_bound(self, interval):
        core = _make()
        interval(0.02)
        folds = []
        with patch.object(core, "fold_once", side_effect=lambda: folds.append(1)):
            core.start()
            thread = core._thread
            assert thread.name == "dial-core" and thread.daemon
            assert _wait_for(lambda: len(folds) >= 4)
            started = time.monotonic()
            core.stop()
            assert time.monotonic() - started < 2.0
        assert not thread.is_alive()

    def test_a_second_start_does_not_start_a_second_thread(self):
        core = _make()
        core.start()
        try:
            thread = core._thread
            core.start()
            assert core._thread is thread
            assert [t for t in threading.enumerate() if t.name == "dial-core"] == [thread]
        finally:
            core.stop()

    def test_stop_cuts_a_long_wait_short(self, interval):
        core = _make()
        interval(60)
        with patch.object(core, "fold_once"):
            core.start()
            time.sleep(0.1)
            started = time.monotonic()
            core.stop()
        assert time.monotonic() - started < 1.0
        assert not core._thread.is_alive()

    def test_the_interval_runs_from_the_end_of_a_fold(self, interval):
        core = _make()
        interval(0.1)
        starts = []

        def slow_fold():
            starts.append(time.perf_counter())
            time.sleep(0.15)

        with patch.object(core, "fold_once", side_effect=slow_fold):
            core.start()
            assert _wait_for(lambda: len(starts) >= 3)
            core.stop()
        gaps = [b - a for a, b in zip(starts, starts[1:])]
        # fold (0.15) + interval (0.1), never a backlog of back-to-back folds
        assert all(gap >= 0.24 for gap in gaps)

    def test_a_request_runs_a_fold_at_once(self, interval):
        core = _make()
        interval(60)
        folds = []
        with patch.object(core, "fold_once", side_effect=lambda: folds.append(1)):
            core.start()
            assert _wait_for(lambda: len(folds) == 1)
            core.request_fold()
            assert _wait_for(lambda: len(folds) == 2, limit=1.0)
            core.stop()

    def test_a_burst_of_wakes_gives_one_extra_fold(self, interval):
        core = _make()
        interval(60)
        folds = []

        def fold():
            folds.append(1)
            if len(folds) == 1:
                for _ in range(5):
                    core.request_fold()

        with patch.object(core, "fold_once", side_effect=fold):
            core.start()
            assert _wait_for(lambda: len(folds) == 2, limit=1.0)
            time.sleep(0.3)
            assert len(folds) == 2
            core.stop()

    def test_a_wake_before_start_is_consumed_by_the_first_fold(self, interval):
        core = _make()
        interval(60)
        folds = []
        with patch.object(core, "fold_once", side_effect=lambda: folds.append(1)):
            core.request_fold()
            core.start()
            assert _wait_for(lambda: len(folds) == 1, limit=1.0)
            time.sleep(0.3)
            assert len(folds) == 1
            core.stop()

    def test_a_fold_that_raises_does_not_stop_the_loop(self, interval):
        core = _make()
        interval(0.02)
        calls = []

        def flaky():
            calls.append(1)
            raise RuntimeError("boom")

        with patch.object(core, "fold_once", side_effect=flaky):
            core.start()
            assert _wait_for(lambda: len(calls) >= 3)
            core.stop()

    def test_the_core_folds_whatever_the_view_holds(self, interval):
        # The core knows nothing of a panel: nothing a view does stops it.
        core = _make()
        core.set_idle_hold(lambda focus_cleared: True)
        interval(0.02)
        core.start()
        try:
            assert _wait_for(lambda: core.snapshot().ticks >= 3)
        finally:
            core.stop()

    def test_a_wake_just_after_a_fold_waits_for_the_gap(self, interval):
        core = _make()
        interval(60)
        starts, ends = [], []

        def fold():
            starts.append(time.perf_counter())
            ends.append(time.perf_counter())

        with patch.object(core, "fold_once", side_effect=fold):
            core.start()
            assert _wait_for(lambda: len(starts) == 1)
            time.sleep(0.02)
            core.request_fold()
            assert _wait_for(lambda: len(starts) == 2, limit=3.0)
            core.stop()
        assert starts[1] - ends[0] >= dial_core.FOLD_MIN_GAP_S

    def test_a_stream_of_wakes_costs_one_fold_per_gap(self, interval):
        core = _make()
        interval(60)
        starts = []
        with patch.object(core, "fold_once", side_effect=lambda: starts.append(time.perf_counter())):
            core.start()
            assert _wait_for(lambda: len(starts) == 1)
            began = time.perf_counter()
            while time.perf_counter() - began < 1.0:
                core.request_fold()
                time.sleep(0.01)
            core.stop()
        gaps = [b - a for a, b in zip(starts, starts[1:])]
        assert gaps and all(gap >= dial_core.FOLD_MIN_GAP_S for gap in gaps)
        assert len(starts) <= 4

    def test_the_periodic_fold_is_not_paced(self, interval):
        core = _make()
        interval(0.05)
        starts = []
        with patch.object(core, "fold_once", side_effect=lambda: starts.append(time.perf_counter())):
            core.start()
            assert _wait_for(lambda: len(starts) >= 5)
            core.stop()
        gaps = [b - a for a, b in zip(starts, starts[1:])]
        assert min(gaps) < dial_core.FOLD_MIN_GAP_S

    def test_a_stop_during_the_gap_does_not_wait_it_out(self, interval, monkeypatch):
        monkeypatch.setattr(dial_core, "FOLD_MIN_GAP_S", 30.0)
        core = _make()
        interval(60)
        folds = []
        with patch.object(core, "fold_once", side_effect=lambda: folds.append(1)):
            core.start()
            assert _wait_for(lambda: len(folds) == 1)
            thread = core._thread
            core.request_fold()
            time.sleep(0.1)
            started = time.monotonic()
            core.stop()
            assert time.monotonic() - started < 1.5
        assert not thread.is_alive()
        assert len(folds) == 1


class TestHousekeeping:
    def _core_with_watcher(self, view):
        core = _make()
        watcher = MagicMock()
        watcher.tick.return_value = view
        core.update_watcher = watcher
        return core

    def test_a_quiet_second_queues_nothing_and_publishes_nothing(self):
        core = self._core_with_watcher(None)
        seq = core.snapshot().seq
        for second in range(3):
            core._housekeeping(float(second))
        assert core.take_effects() == []
        assert core.snapshot().seq == seq

    def test_what_the_update_watch_did_is_queued_for_the_view_and_announced(self, tmp_path):
        view = UpdateView(status=STATUS_IN_PROGRESS, percent=10, phase="files", tag="0.7.0")
        core = self._core_with_watcher(view)
        core.update_seen_path = str(tmp_path / "seen")
        calls = []
        core.subscribe(lambda: calls.append(len(core._effects)))
        core._housekeeping(1.0)
        assert calls and calls[-1] == 1            # queued before the last announcement
        effects = core.take_effects()
        assert len(effects) == 1 and [c.warning_id for c in effects[0].changes] == ["update"]
        assert core.take_effects() == []

    def test_the_thread_runs_housekeeping_while_nothing_else_happens(self, interval, monkeypatch):
        monkeypatch.setattr(dial_core, "HOUSEKEEPING_INTERVAL_S", 0.02)
        core = _make()
        interval(60)
        runs = []
        with patch.object(core, "fold_once"), \
             patch.object(core, "_housekeeping", side_effect=lambda now: runs.append(now)):
            core.start()
            assert _wait_for(lambda: len(runs) >= 4)
            core.stop()
        assert len(runs) >= 4

    def test_housekeeping_that_raises_does_not_stop_the_folds(self, interval, monkeypatch):
        monkeypatch.setattr(dial_core, "HOUSEKEEPING_INTERVAL_S", 0.02)
        core = _make()
        interval(0.02)
        folds = []
        with patch.object(core, "fold_once", side_effect=lambda: folds.append(1)), \
             patch.object(core, "_housekeeping", side_effect=RuntimeError("boom")):
            core.start()
            assert _wait_for(lambda: len(folds) >= 3)
            core.stop()
        assert len(folds) >= 3
