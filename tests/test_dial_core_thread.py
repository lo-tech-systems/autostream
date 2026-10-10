"""Tests for the poll the core runs: a tick's publishes, its settings, and
the dial-core thread with its housekeeping."""
import os
import sys
import threading
import time
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dial"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

import pytest

import dial_core
from dial_auth import AUTH_UNAUTHORIZED, auth_map
from dial_core import DEFAULT_POLL_INTERVAL_S, DialCore, PollIO
from dial_core_state import NowPlaying, artwork_key
from dial_test_support import (
    _roster_entry,
    _roster_from_targets,
    _status_result,
    _target,
    _track_id,
)
from dial_update_watch import STATUS_IN_PROGRESS, UpdateView
from dial_warning_text import WARNING_DESCRIPTORS
from dial_warnings import WarningManager, WarningStore


def _quiet_io(fetch=None, **overrides):
    """Poll calls that touch no appliance and no process-wide observation."""
    values = dict(
        fetch_status=fetch or (lambda target, dial_id, timeout_seconds=None: _status_result(
            appliance_id=target.appliance_id,
        )),
        enrich=lambda targets, dial_id: [],
        fetch_artwork=lambda url, timeout: (b"picture", ""),
        artwork_eligible=lambda url: True,
        observe_mute=lambda *a, **k: None,
        observe_volume=lambda *a, **k: None,
        forget_mute=lambda *a, **k: None,
    )
    values.update(overrides)
    return PollIO(**values)


def _make(targets=(), roster=None, fetch=None, polling=True, **io_overrides):
    gt = MagicMock(return_value=list(targets))
    gr = (lambda: roster) if roster is not None else (lambda: _roster_from_targets(gt()))
    core = DialCore(
        "dial-1", gt, gr,
        warnings=WarningManager(WARNING_DESCRIPTORS, WarningStore(None)),
        io=_quiet_io(fetch, **io_overrides),
    )
    if polling:
        core.set_polling(True)
    return core, gt


def _fresh_id(tag: str) -> str:
    """An appliance id of its own: the auth map is shared by every test."""
    return (tag.encode().hex() + "0" * 20)[:20]


class TestTickPublishes:
    def test_a_tick_ends_in_a_snapshot_with_a_new_count(self):
        aid = _fresh_id("t1")
        core, gt = _make([_target(appliance_id=aid, auth="authorized")])
        assert core.snapshot().ticks == 0 and core.snapshot().tick is None
        core.poll_once()
        first = core.snapshot()
        core.poll_once()
        second = core.snapshot()
        assert (first.ticks, second.ticks) == (1, 2)
        assert first.tick.previous_now_playing is None
        assert first.tick.previous_reporting_id is None
        assert second.tick.previous_now_playing == first.now_playing
        assert second.tick.previous_reporting_id == aid
        assert second.tick.focus_cleared is False
        assert first.visible_playing == (aid,)

    def test_a_quiet_tick_publishes_exactly_once(self):
        aid = _fresh_id("t2")
        core, gt = _make([_target(appliance_id=aid, auth="authorized")])
        core.poll_once()
        core.poll_once()       # the second tick settles the binding
        seen = []
        core.subscribe(lambda: seen.append(core.snapshot().ticks))
        for _ in range(3):
            core.poll_once()
        assert seen == [3, 4, 5]

    def test_the_playing_set_is_published_before_the_walks_requests(self):
        aid = _fresh_id("t3")
        at_request = []

        def fetch(target, dial_id, timeout_seconds=None):
            snap = core.snapshot()
            at_request.append((snap.visible_playing, snap.ticks))
            return _status_result(appliance_id=target.appliance_id)

        core, gt = _make([_target(appliance_id=aid, auth="authorized")], fetch=fetch)
        core.poll_once()
        assert at_request == [((aid,), 0)]

    def test_the_set_is_published_again_only_when_it_changes(self):
        aid = _fresh_id("t4")
        core, gt = _make([_target(appliance_id=aid, auth="authorized")])
        core.poll_once()
        core.poll_once()       # the second tick settles the binding
        seen = []
        core.subscribe(lambda: seen.append((core.snapshot().visible_playing, core.snapshot().ticks)))
        core.poll_once()
        assert seen == [((aid,), 3)]       # the tick's own publish only
        del seen[:]
        gt.return_value = []
        core.poll_once()
        # The change comes first, before the tick that found it has ended.
        assert seen[0] == ((), 3)
        assert seen[-1] == ((), 4)

    def test_a_wake_for_a_refused_appliance_neither_announces_nor_paints(self):
        aid = _fresh_id("t5w")
        seen = []

        def fetch(target, dial_id, timeout_seconds=None):
            return _status_result(status_error="unauthorized", appliance_id=target.appliance_id)

        core, gt = _make([_target(appliance_id=aid, auth="unknown")], fetch=fetch)
        core.subscribe(lambda: seen.append(core.snapshot().visible_playing))
        core.request_poll()
        core.poll_once()
        assert core.snapshot().visible_playing == ()
        assert all(ids == () for ids in seen)

    def test_a_replayed_record_set_publishes_nothing_new(self):
        aid = _fresh_id("t5r")
        core, gt = _make([_target(appliance_id=aid, auth="authorized")])
        seen = []
        core.subscribe(lambda: seen.append(core.snapshot().visible_playing))
        core.poll_once()
        core.request_poll()
        core.poll_once()
        # Every publish repeats the set; what must not happen is the set
        # changing again once the replayed tick has settled.
        changes = [ids for i, ids in enumerate(seen) if i == 0 or ids != seen[i - 1]]
        assert [ids for ids in changes if ids] == [(aid,)]

    def test_a_refused_first_check_never_shows_the_appliance_as_visible(self):
        aid = _fresh_id("t5")
        seen = []

        def fetch(target, dial_id, timeout_seconds=None):
            return _status_result(status_error="unauthorized", appliance_id=target.appliance_id)

        core, gt = _make([_target(appliance_id=aid, auth="unknown")], fetch=fetch)
        core.subscribe(lambda: seen.append(core.snapshot().visible_playing))
        core.poll_once()
        assert auth_map.state(aid) == AUTH_UNAUTHORIZED
        assert all(ids == () for ids in seen)
        assert core.snapshot().visible_playing == ()

    def test_polling_off_asks_nobody_and_reports_nothing(self):
        aid = _fresh_id("t6")
        core, gt = _make([_target(appliance_id=aid, auth="authorized")], polling=False)
        core.poll_once()
        gt.assert_not_called()
        snap = core.snapshot()
        assert snap.polling is False and snap.now_playing is None and snap.visible_playing == ()
        assert snap.ticks == 1

    def test_set_polling_is_published(self):
        core, gt = _make(polling=False)
        assert core.snapshot().polling is False
        seq = core.snapshot().seq
        core.set_polling(True)
        assert core.snapshot().polling is True and core.snapshot().seq == seq + 1
        core.set_polling(True)
        assert core.snapshot().seq == seq + 1

    def test_a_tick_that_clears_the_focus_says_so(self):
        core, gt = _make()
        core.set_focus(_fresh_id("t7"))      # not on the roster: the tick clears it
        core.poll_once()
        assert core.snapshot().focus.manual_id is None
        assert core.snapshot().tick.focus_cleared is True
        core.poll_once()
        assert core.snapshot().tick.focus_cleared is False

    def test_the_idle_hold_leaves_what_is_reported_as_it_was(self):
        aid = _fresh_id("t8")
        entry = _roster_entry(appliance_id=aid, auth="authorized", service_name="Hall")
        core, gt = _make(roster=[entry])
        core.set_focus(aid)
        holds = []
        core.set_idle_hold(lambda focus_cleared: holds.append(focus_cleared) or True)
        core.poll_once()
        assert holds == [False]
        assert core.snapshot().now_playing is None
        core.set_idle_hold(lambda focus_cleared: False)
        core.poll_once()
        assert core.snapshot().now_playing == NowPlaying("Hall", "", "", 50, playing=False)
        assert core.snapshot().focus.reporting_id == aid
        assert core.snapshot().tick.idle_focus is True

    def test_the_eq_page_can_be_vetoed_by_the_view(self):
        aid = _fresh_id("t9")
        entry = _roster_entry(appliance_id=aid, auth="authorized", dial_eq=True, playing=True)
        target = _target(appliance_id=aid, auth="authorized")
        core, gt = _make([target], roster=[entry])
        core.poll_once()
        assert core.snapshot().eq_available is True
        core.set_eq_veto(lambda: True)
        core.poll_once()
        assert core.snapshot().eq_available is False

    def test_the_artwork_is_downloaded_once_per_track_and_held_by_the_core(self):
        aid = _fresh_id("t10")
        fetched = []

        def fetch_artwork(url, timeout):
            fetched.append(url)
            return b"picture", ""

        def fetch(target, dial_id, timeout_seconds=None):
            return _status_result(track_id=_track_id(), appliance_id=target.appliance_id)

        core, gt = _make([_target(appliance_id=aid, auth="authorized")], fetch=fetch,
                         fetch_artwork=fetch_artwork)
        core.poll_once()
        core.poll_once()
        url = "https://provider.example/x.jpg"
        assert fetched == [url]
        art = core.snapshot().artwork
        assert art.key == artwork_key(url) and art.data == b"picture" and art.url == ""

    def test_a_failed_download_is_tried_again_on_the_next_tick(self):
        aid = _fresh_id("t11")
        replies = iter([(None, "boom"), (b"picture", "")])
        errors = []

        def fetch(target, dial_id, timeout_seconds=None):
            return _status_result(track_id=_track_id(), appliance_id=target.appliance_id)

        core, gt = _make([_target(appliance_id=aid, auth="authorized")], fetch=fetch,
                         fetch_artwork=lambda url, timeout: next(replies), on_artwork_error=errors.append)
        core.poll_once()
        assert core.snapshot().artwork is None and errors == ["artwork_fetch_failed"]
        core.poll_once()
        assert core.snapshot().artwork is not None

    def test_nothing_playing_releases_the_artwork(self):
        aid = _fresh_id("t12")

        def fetch(target, dial_id, timeout_seconds=None):
            return _status_result(track_id=_track_id(), appliance_id=target.appliance_id)

        core, gt = _make([_target(appliance_id=aid, auth="authorized")], fetch=fetch)
        core.poll_once()
        assert core.snapshot().artwork is not None
        gt.return_value = []
        core.poll_once()
        assert core.snapshot().artwork is None


class TestPollSettings:
    @pytest.mark.parametrize("value", [None, True, False, 0, -2, "6", float("nan")])
    def test_an_unusable_interval_reads_as_the_default(self, value):
        core, gt = _make()
        core.set_poll_interval(3)
        core.set_poll_interval(value)
        assert core._poll_interval == DEFAULT_POLL_INTERVAL_S

    @pytest.mark.parametrize("value", [2, 4, 6, 0.05])
    def test_a_usable_interval_is_kept(self, value):
        core, gt = _make()
        core.set_poll_interval(value)
        assert core._poll_interval == value

    def test_a_changed_interval_wakes_the_loop_and_an_unchanged_one_does_not(self):
        core, gt = _make()
        core._poll_wake.clear()
        core.set_poll_interval(3)
        assert core._poll_wake.is_set()
        core._poll_wake.clear()
        core.set_poll_interval(3)
        assert not core._poll_wake.is_set()

    def test_request_poll_wakes_and_reconcile_forces_the_roster_due(self):
        core, gt = _make()
        core._poll_wake.clear()
        core._reconcile_due = False
        with patch("dial_core.auth_map.force_due") as force_due:
            core.request_poll()
            assert core._poll_wake.is_set() and core._reconcile_due is False
            force_due.assert_not_called()
            core.request_poll(reconcile=True)
            force_due.assert_called_once_with()
        assert core._reconcile_due is True

    def test_a_reconcile_request_leaves_the_auth_timers_alone(self):
        core, gt = _make()
        core._poll_wake.clear()
        core._reconcile_due = False
        with patch("dial_core.auth_map.force_due") as force_due:
            core.request_reconcile()
        force_due.assert_not_called()
        assert core._reconcile_due is True and core._poll_wake.is_set()

    def test_an_auth_push_queues_the_id_and_wakes_the_loop(self):
        core, gt = _make()
        core._poll_wake.clear()
        with patch("dial_core.auth_map.force_due") as force_due:
            core.notify_auth_changed("a" * 20)
            core.notify_auth_changed("a" * 20)
        force_due.assert_called_with("a" * 20)
        assert core._push_pending == {"a" * 20}
        assert core._poll_wake.is_set()

    def test_a_push_probe_that_confirms_an_authorisation_is_published(self):
        aid = _fresh_id("p1")
        core, gt = _make([_target(appliance_id=aid, auth="unknown")])
        before = core.snapshot().auth_promotions
        core.notify_auth_changed(aid)
        assert core._drain_push_probes() == "probed"
        assert core.snapshot().auth_promotions == before + 1
        core.notify_auth_changed(aid)       # already authorised: nothing to announce
        core._drain_push_probes()
        assert core.snapshot().auth_promotions == before + 1

    def test_an_empty_push_queue_probes_nothing(self):
        fetch = MagicMock()
        core, gt = _make(fetch=fetch)
        assert core._drain_push_probes() == ""
        fetch.assert_not_called()


class TestCoreThread:
    def _wait_for(self, condition, limit=3.0):
        deadline = time.monotonic() + limit
        while not condition() and time.monotonic() < deadline:
            time.sleep(0.005)
        return condition()

    def test_the_thread_polls_every_interval_and_stops_within_the_bound(self):
        core, gt = _make()
        core.set_poll_interval(0.02)
        polls = []
        with patch.object(core, "poll_once", side_effect=lambda: polls.append(1)):
            core.start()
            thread = core._thread
            assert thread.name == "dial-core" and thread.daemon
            assert self._wait_for(lambda: len(polls) >= 4)
            started = time.monotonic()
            core.stop()
            assert time.monotonic() - started < 2.0
        assert not thread.is_alive()

    def test_a_second_start_does_not_start_a_second_thread(self):
        core, gt = _make()
        core.start()
        try:
            thread = core._thread
            core.start()
            assert core._thread is thread
            assert [t for t in threading.enumerate() if t.name == "dial-core"] == [thread]
        finally:
            core.stop()

    def test_stop_cuts_a_long_wait_short(self):
        core, gt = _make()
        core.set_poll_interval(60)
        with patch.object(core, "poll_once"):
            core.start()
            time.sleep(0.1)
            started = time.monotonic()
            core.stop()
        assert time.monotonic() - started < 1.0
        assert not core._thread.is_alive()

    def test_the_interval_runs_from_the_end_of_a_tick(self):
        core, gt = _make()
        core.set_poll_interval(0.1)
        starts = []

        def slow_poll():
            starts.append(time.perf_counter())
            time.sleep(0.15)

        with patch.object(core, "poll_once", side_effect=slow_poll):
            core.start()
            assert self._wait_for(lambda: len(starts) >= 3)
            core.stop()
        gaps = [b - a for a, b in zip(starts, starts[1:])]
        # tick (0.15) + interval (0.1), never a backlog of back-to-back ticks
        assert all(gap >= 0.24 for gap in gaps)

    def test_a_request_runs_a_tick_at_once(self):
        core, gt = _make()
        core.set_poll_interval(60)
        polls = []
        with patch.object(core, "poll_once", side_effect=lambda: polls.append(1)):
            core.start()
            assert self._wait_for(lambda: len(polls) == 1)
            core.request_poll()
            assert self._wait_for(lambda: len(polls) == 2, limit=1.0)
            core.stop()

    def test_a_burst_of_wakes_gives_one_extra_tick(self):
        core, gt = _make()
        core.set_poll_interval(60)
        polls = []

        def tick():
            polls.append(1)
            if len(polls) == 1:
                for _ in range(5):
                    core.request_poll()

        with patch.object(core, "poll_once", side_effect=tick):
            core.start()
            assert self._wait_for(lambda: len(polls) == 2, limit=1.0)
            time.sleep(0.3)
            assert len(polls) == 2
            core.stop()

    def test_a_wake_before_start_is_consumed_by_the_first_tick(self):
        core, gt = _make()
        core.set_poll_interval(60)
        polls = []
        with patch.object(core, "poll_once", side_effect=lambda: polls.append(1)):
            core.request_poll()
            core.start()
            assert self._wait_for(lambda: len(polls) == 1, limit=1.0)
            time.sleep(0.3)
            assert len(polls) == 1
            core.stop()

    def test_a_tick_that_raises_does_not_stop_the_loop(self):
        core, gt = _make()
        core.set_poll_interval(0.02)
        calls = []

        def flaky():
            calls.append(1)
            raise RuntimeError("boom")

        with patch.object(core, "poll_once", side_effect=flaky):
            core.start()
            assert self._wait_for(lambda: len(calls) >= 3)
            core.stop()

    def test_the_core_polls_with_no_view_at_all(self):
        aid = _fresh_id("th1")

        def fetch(target, dial_id, timeout_seconds=None):
            return _status_result(track_id=_track_id(title="Headless"), appliance_id=target.appliance_id)

        core, gt = _make([_target(appliance_id=aid, auth="authorized")], fetch=fetch)
        core.set_poll_interval(0.02)
        core.start()
        try:
            snap = core.wait_for_change(0, 3.0)
            assert snap is not None
            assert self._wait_for(lambda: core.snapshot().now_playing is not None)
            assert core.snapshot().now_playing.title == "Headless"
            assert core.snapshot().artwork is not None
        finally:
            core.stop()

    def test_a_poll_asleep_or_not_is_the_same_poll(self):
        # The core knows nothing of a panel: nothing a view does stops it.
        core, gt = _make([_target(appliance_id=_fresh_id("th2"), auth="authorized")])
        core.set_idle_hold(lambda focus_cleared: True)
        core.set_poll_interval(0.02)
        core.start()
        try:
            assert self._wait_for(lambda: core.snapshot().ticks >= 3)
        finally:
            core.stop()


class TestHousekeeping:
    def _core_with_watcher(self, view):
        core, gt = _make()
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

    def test_the_thread_runs_housekeeping_while_nothing_else_happens(self, monkeypatch):
        monkeypatch.setattr(dial_core, "HOUSEKEEPING_INTERVAL_S", 0.02)
        core, gt = _make()
        core.set_poll_interval(60)
        runs = []
        with patch.object(core, "poll_once"), \
             patch.object(core, "_housekeeping", side_effect=lambda now: runs.append(now)):
            core.start()
            deadline = time.monotonic() + 3.0
            while len(runs) < 4 and time.monotonic() < deadline:
                time.sleep(0.01)
            core.stop()
        assert len(runs) >= 4

    def test_housekeeping_that_raises_does_not_stop_the_poll(self, monkeypatch):
        monkeypatch.setattr(dial_core, "HOUSEKEEPING_INTERVAL_S", 0.02)
        core, gt = _make()
        core.set_poll_interval(0.02)
        polls = []
        with patch.object(core, "poll_once", side_effect=lambda: polls.append(1)), \
             patch.object(core, "_housekeeping", side_effect=RuntimeError("boom")):
            core.start()
            deadline = time.monotonic() + 3.0
            while len(polls) < 3 and time.monotonic() < deadline:
                time.sleep(0.01)
            core.stop()
        assert len(polls) >= 3
