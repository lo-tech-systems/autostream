"""Tests for the poll the core runs: a tick's publishes, its settings, and
the dial-core thread with its housekeeping."""
import os
import queue
import sys
import threading
import time
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dial"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

import pytest

import dial_core
import dial_volume as dv
from dial_auth import AUTH_UNAUTHORIZED, auth_map
from dial_core import DEFAULT_POLL_INTERVAL_S, FOCUS_PENDING_GRACE_S, DialCore, PollIO
from dial_core_state import NowPlaying, artwork_key
from dial_test_support import (
    _FakeClock,
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


def _make(targets=(), roster=None, fetch=None, polling=True, clock=None, **io_overrides):
    gt = MagicMock(return_value=list(targets))
    gr = (lambda: roster) if roster is not None else (lambda: _roster_from_targets(gt()))
    core = DialCore(
        "dial-1", gt, gr,
        warnings=WarningManager(WARNING_DESCRIPTORS, WarningStore(None)),
        io=_quiet_io(fetch, **io_overrides), clock=clock,
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


class _Replies:
    """A fetch_status stand-in answering from a dict by service name, read at
    each call so a test can change the answers between ticks, and keeping the
    names it was asked in order."""

    def __init__(self, results):
        self.results = results
        self.asked = []

    def __call__(self, target, dial_id, timeout_seconds=None):
        self.asked.append(target.service_name)
        return self.results[target.service_name]


def _artwork_log():
    """A fetch_artwork stand-in that records the URLs it is asked for."""
    asked = []

    def fetch_artwork(url, timeout):
        asked.append(url)
        return b"picture", ""
    return asked, fetch_artwork


class TestTickSelection:
    """Which appliances a tick asks and what it settles on to show: the order
    of the walk, what counts as usable artwork, the text-only fallback and a
    focus pinning the walk."""

    def test_a_refused_target_is_never_asked_or_shown(self):
        aid = _fresh_id("sel1")
        fetch = MagicMock()
        core, gt = _make([_target(appliance_id=aid, auth="unauthorized")], fetch=fetch)
        core.poll_once()
        fetch.assert_not_called()
        snap = core.snapshot()
        assert snap.visible_playing == () and snap.now_playing is None
        assert snap.focus.reporting_id is None and snap.focus.source_service_name is None
        assert snap.artwork is None

    @pytest.mark.parametrize("track_id, title, source", [
        (None, "", None),
        (_track_id(artwork_url=""), "Song", "Kitchen"),
        (_track_id(state="analysing"), "", None),
    ], ids=["no_track_id", "empty_artwork_url", "not_identified"])
    def test_a_reply_without_usable_artwork_selects_none(self, track_id, title, source):
        aid = _fresh_id("sel3")
        asked, fetch_artwork = _artwork_log()
        core, gt = _make(
            [_target(appliance_id=aid, auth="authorized")],
            fetch=lambda target, dial_id, timeout_seconds=None: _status_result(
                track_id=track_id, appliance_id=aid),
            fetch_artwork=fetch_artwork,
        )
        core.poll_once()
        snap = core.snapshot()
        assert asked == [] and snap.artwork is None
        assert snap.focus.source_service_name == source
        assert snap.now_playing.service_name == "Kitchen" and snap.now_playing.title == title
        assert snap.now_playing.playing is True

    @pytest.mark.parametrize("pinned", [False, True])
    def test_an_identified_track_without_artwork_is_shown_as_text(self, pinned):
        aid = _fresh_id("sel7")
        no_art = _track_id(title="Song", artist="The Artist", album="LP", artwork_url="")
        asked, fetch_artwork = _artwork_log()
        core, gt = _make(
            [_target(appliance_id=aid)],
            fetch=lambda target, dial_id, timeout_seconds=None: _status_result(
                track_id=no_art, appliance_id=aid),
            fetch_artwork=fetch_artwork,
        )
        if pinned:
            core.set_focus(aid)
        core.poll_once()
        snap = core.snapshot()
        assert asked == [] and snap.artwork is None
        assert snap.focus.source_service_name == "Kitchen"
        playing = snap.now_playing
        assert (playing.title, playing.artist, playing.album) == ("Song", "The Artist", "LP")

    def test_a_target_with_artwork_wins_over_an_earlier_text_only_one(self):
        first = _target(name="Kitchen", appliance_id=_fresh_id("sel8a"), playing_since=100.0)
        second = _target(name="Lounge", ip="192.168.1.11", appliance_id=_fresh_id("sel8b"),
                         playing_since=200.0)
        replies = _Replies({
            "Kitchen": _status_result(track_id=_track_id(title="No art", artwork_url="")),
            "Lounge": _status_result(track_id=_track_id(title="With art")),
        })
        core, gt = _make([first, second], fetch=replies)
        core.poll_once()
        snap = core.snapshot()
        assert replies.asked == ["Kitchen", "Lounge"]
        assert snap.focus.source_service_name == "Lounge" and snap.now_playing.title == "With art"
        assert snap.artwork.key == artwork_key("https://provider.example/x.jpg")

    @pytest.mark.parametrize("focus_has_artwork", [False, True])
    def test_a_focused_target_is_asked_first_and_the_walk_never_leaves_it(self, focus_has_artwork):
        aid = _fresh_id("sel9")
        focus_t = _target(name="Focus", appliance_id=aid, playing_since=5.0)
        other_t = _target(name="Other", appliance_id=_fresh_id("sel9o"), playing_since=1.0)
        replies = _Replies({
            "Focus": _status_result(track_id=_track_id() if focus_has_artwork else None, appliance_id=aid),
            "Other": _status_result(track_id=_track_id()),
        })
        core, gt = _make([other_t, focus_t], fetch=replies)
        core.set_focus(aid)
        core.poll_once()
        snap = core.snapshot()
        assert replies.asked == ["Focus"]
        assert snap.focus.source_service_name == "Focus" and snap.now_playing.service_name == "Focus"
        assert (snap.artwork is not None) is focus_has_artwork

    def test_the_selector_marks_the_reported_target_and_a_focus_takes_over(self):
        a = _target(name="A", appliance_id="a" * 20, auth="authorized", playing_since=1.0)
        b = _target(name="B", appliance_id="b" * 20, auth="authorized", playing_since=2.0)
        core, gt = _make(
            [a, b],
            fetch=lambda target, dial_id, timeout_seconds=None: _status_result(
                track_id=None, appliance_id=target.appliance_id),
        )
        core.poll_once()
        # Nothing identified: the oldest playing target is the one reported.
        assert core.snapshot().focus.reporting_id == a.appliance_id
        assert {r.appliance_id for r in core.snapshot().selector_rows() if r.current} == {a.appliance_id}
        core.set_focus(b.appliance_id)
        core.poll_once()
        assert {r.appliance_id for r in core.snapshot().selector_rows() if r.current} == {b.appliance_id}

    def test_the_source_service_is_set_before_the_artwork_fetch(self):
        """A volume press landing during a slow artwork fetch reads the
        source service name; it must already be the selected target."""
        older = _target(name="Older", service_name="older", appliance_id=_fresh_id("sel10a"),
                        playing_since=10.0)
        newer = _target(name="Newer", service_name="newer", appliance_id=_fresh_id("sel10b"),
                        playing_since=20.0)
        replies = _Replies({
            "older": _status_result(track_id=None),
            "newer": _status_result(track_id=_track_id()),
        })
        seen = []

        def fetch_artwork(url, timeout):
            seen.append(core.current_source_service_name())
            return None, "stub"

        core, gt = _make([older, newer], fetch=replies, fetch_artwork=fetch_artwork)
        core.poll_once()
        assert seen == ["newer"]


class TestTickBinding:
    """The binding beneath manual focus: the appliance a tick settled on is
    pinned on the next tick, so one newly identified elsewhere cannot steal
    the screen, and the binding is released when its appliance goes."""

    @staticmethod
    def _two():
        return (
            _target(name="Alpha", service_name="alpha", playing_since=1.0),
            _target(name="Bravo", service_name="bravo", playing_since=2.0),
        )

    def test_it_binds_on_the_first_tick(self):
        a = self._two()[0]
        core, gt = _make([a], fetch=_Replies({"alpha": _status_result(track_id=None)}))
        assert core.snapshot().focus.bound_id is None
        core.poll_once()
        focus = core.snapshot().focus
        assert (focus.bound_id, focus.reporting_id) == (a.appliance_id, a.appliance_id)

    def test_a_second_starter_with_artwork_does_not_steal(self):
        a, b = self._two()
        replies = _Replies({
            "alpha": _status_result(track_id=None),
            "bravo": _status_result(track_id=_track_id()),
        })
        asked, fetch_artwork = _artwork_log()
        core, gt = _make([a], fetch=replies, fetch_artwork=fetch_artwork)
        core.poll_once()
        gt.return_value = [a, b]
        del replies.asked[:]
        core.poll_once()
        focus = core.snapshot().focus
        assert focus.bound_id == a.appliance_id and focus.reporting_id == a.appliance_id
        assert core.current_source_service_name() == "alpha"
        assert replies.asked == ["alpha"]
        assert asked == [] and core.snapshot().artwork is None

    def test_a_bound_target_that_stops_with_a_survivor_rebinds(self):
        a, b = self._two()
        both = _Replies({"alpha": _status_result(track_id=None), "bravo": _status_result(track_id=None)})
        core, gt = _make([a, b], fetch=both)
        core.poll_once()
        assert core.snapshot().focus.bound_id == a.appliance_id
        gt.return_value = [b]
        core.poll_once()
        focus = core.snapshot().focus
        assert focus.bound_id == b.appliance_id and focus.reporting_id == b.appliance_id

    def test_a_bound_target_that_stops_with_nothing_left_releases_to_none(self):
        a = self._two()[0]
        core, gt = _make([a], fetch=_Replies({"alpha": _status_result(track_id=None)}))
        core.poll_once()
        assert core.snapshot().focus.bound_id == a.appliance_id
        gt.return_value = []
        core.poll_once()
        focus = core.snapshot().focus
        assert focus.bound_id is None and focus.reporting_id is None

    def test_a_binding_revoked_mid_tick_is_released_and_the_walk_goes_on(self):
        a, b = self._two()
        replies = _Replies({"alpha": _status_result(track_id=None), "bravo": _status_result(track_id=None)})
        asked, fetch_artwork = _artwork_log()
        core, gt = _make([a, b], fetch=replies, fetch_artwork=fetch_artwork)
        core.poll_once()
        assert core.snapshot().focus.bound_id == a.appliance_id
        replies.results["alpha"] = _status_result(status_error="unauthorized", appliance_id=a.appliance_id)
        replies.results["bravo"] = _status_result(track_id=_track_id())
        del replies.asked[:]
        core.poll_once()
        focus = core.snapshot().focus
        assert replies.asked == ["alpha", "bravo"]
        assert focus.bound_id == b.appliance_id and focus.reporting_id == b.appliance_id
        assert core.current_source_service_name() == "bravo"
        url = "https://provider.example/x.jpg"
        assert asked == [url] and core.snapshot().artwork.key == artwork_key(url)

    def test_a_manual_focus_is_mirrored_into_the_binding(self):
        a, b = self._two()
        both = _Replies({"alpha": _status_result(track_id=None), "bravo": _status_result(track_id=None)})
        core, gt = _make([a, b], fetch=both)
        core.poll_once()
        assert core.snapshot().focus.bound_id == a.appliance_id
        core.set_focus(b.appliance_id)
        core.poll_once()
        focus = core.snapshot().focus
        assert focus.bound_id == b.appliance_id and focus.reporting_id == b.appliance_id
        assert core.manual_focus_id() == b.appliance_id


class TestTickMuteOrdering:
    """The mute flag a tick reads is ordered against presses by when its
    request was sent, through the real observation store."""

    @staticmethod
    def _reset():
        dv.observe_mute_state(None, None)
        while True:
            try:
                dv._queue.get_nowait()
            except queue.Empty:
                break

    @pytest.fixture(autouse=True)
    def _clean_mute_state(self):
        """The observation store and its press queue are process-wide."""
        self._reset()
        yield
        self._reset()

    @staticmethod
    def _core(targets, clock, fetch):
        """A core whose mute and volume observations go to the real store."""
        gt = MagicMock(return_value=list(targets))
        core = DialCore(
            "dial-1", gt, lambda: _roster_from_targets(gt()),
            warnings=WarningManager(WARNING_DESCRIPTORS, WarningStore(None)), clock=clock,
            io=PollIO(
                fetch_status=fetch, enrich=lambda targets, dial_id: [],
                fetch_artwork=lambda url, timeout: (None, "unused"), artwork_eligible=lambda url: False,
            ),
        )
        core.set_polling(True)
        return core, gt

    def test_a_poll_sent_before_a_mute_press_never_reverts_the_shown_mute(self):
        """A press lands while a status request is in flight: the reply to
        that request describes the world from before the press, so it must
        not put the glyph back."""
        t = _target(dial_proto_version=2)
        clock = _FakeClock(5.0)
        answer = {"fn": lambda *a, **k: _status_result(track_id=None, muted=False)}
        core, gt = self._core([t], clock, lambda *a, **k: answer["fn"](*a, **k))
        with patch("dial_volume.time.monotonic", clock):
            core.poll_once()
            assert dv.shown_muted(t.service_name) is False

            def fetch_during_press(target, *a, **k):
                # The request was sent at 9.9; the press happens at 10.0 and
                # its response has since arrived (nothing in flight now).
                clock.t = 10.0
                dv.enqueue_mute(False)
                dv._clear_mute_inflight(t.service_name)
                return _status_result(track_id=None, muted=False)

            answer["fn"] = fetch_during_press
            clock.t = 9.9
            core.poll_once()
        assert dv.shown_muted(t.service_name) is True

    def test_a_poll_sent_after_the_mute_press_applies(self):
        t = _target(dial_proto_version=2)
        clock = _FakeClock(5.0)
        core, gt = self._core(
            [t], clock, lambda *a, **k: _status_result(track_id=None, muted=False))
        with patch("dial_volume.time.monotonic", clock):
            core.poll_once()
            clock.t = 10.0
            dv.enqueue_mute(False)
            dv._clear_mute_inflight(t.service_name)
            assert dv.shown_muted(t.service_name) is True
            clock.t = 10.5
            core.poll_once()
        assert dv.shown_muted(t.service_name) is False

    def test_a_legacy_target_poll_after_the_settle_clears_the_mute(self):
        """An earlier-release appliance never reports the flag: once a mute
        reply has settled, the next poll sent after it clears the highlight."""
        t = _target()       # protocol version 0: its status carries no mute flag
        clock = _FakeClock(5.0)
        core, gt = self._core(
            [t], clock, lambda *a, **k: _status_result(track_id=None, muted=None))
        with patch("dial_volume.time.monotonic", clock):
            dv.observe_mute_state(t.service_name, True)     # a mute reply
            assert dv.shown_muted(t.service_name) is True
            clock.t = 20.0
            core.poll_once()
        assert dv.shown_muted(t.service_name) is False

    def test_every_walked_target_is_observed(self):
        """Neither target is identified, so the walk visits both: each gets
        its own entry in the real observation store, not only the one the
        tick reports from."""
        older = _target(name="Older", service_name="older", playing_since=10.0)
        newer = _target(name="Newer", service_name="newer", playing_since=20.0)
        results = {
            "older": _status_result(track_id=None, muted=False),
            "newer": _status_result(track_id=None, muted=True),
        }
        core, gt = self._core(
            [older, newer], _FakeClock(5.0), lambda target, *a, **k: results[target.service_name])
        core.poll_once()
        assert core.snapshot().focus.reporting_id == older.appliance_id
        assert set(dv._observed_muted) == {"older", "newer"}
        assert dv.shown_muted("older") is False
        assert dv.shown_muted("newer") is True


class TestTickTimers:
    """The windows a tick enforces from the core's own clock."""

    def test_a_pending_focus_lasts_to_just_inside_the_grace_and_clears_just_past_it(self):
        """A pending focus on an appliance that never appears survives to
        just inside the grace and is cleared just past it."""
        aid = _fresh_id("tm1")
        clock = _FakeClock(1000.0)
        core, gt = _make(clock=clock)
        start = clock.t
        core.set_focus_pending(aid, "Kitchen", start + FOCUS_PENDING_GRACE_S)
        core.request_poll()
        clock.t = start + FOCUS_PENDING_GRACE_S - 0.01
        core.poll_once()
        assert core.manual_focus_id() == aid
        assert core.snapshot().focus.pending is not None
        clock.t = start + FOCUS_PENDING_GRACE_S + 0.01
        core.poll_once()
        assert core.manual_focus_id() is None
        assert core.snapshot().focus.pending is None
        assert FOCUS_PENDING_GRACE_S == 10.0

    def test_a_refused_playing_appliance_is_probed_once_per_backoff(self):
        """The appliance has been refused and keeps advertising playback. It
        is never fetched by the walk; only the reconcile pass re-checks it,
        and only once its backoff has run out. The reconcile pass runs every
        RECONCILE_INTERVAL_S, so with the backoff starting at 30 s and
        doubling per refusal the re-checks land at 0, 60, 120, 240 and 480 s
        rather than on a fixed cadence."""
        t = _target(name="Hall", service_name="Hall", appliance_id="9" * 20,
                    auth="unauthorized", dial_status=True)
        clock = _FakeClock(1000.0)
        start = clock.t
        probed_at = []

        def fake_enrich(targets, dial_id):
            probed_at.extend([clock.t - start] * len(targets))
            return [
                {"name": x.service_name, "status_error": "unauthorized",
                 "appliance_id": x.appliance_id}
                for x in targets
            ]

        walk_fetch = MagicMock()
        core, gt = _make([t], fetch=walk_fetch, enrich=fake_enrich, clock=clock)
        with patch("dial_core_poll.time.monotonic", clock):
            for _ in range(61):         # 10 s ticks across 600 s
                core.poll_once()
                clock.t += 10.0
        walk_fetch.assert_not_called()
        assert probed_at == [0.0, 60.0, 120.0, 240.0, 480.0]
        assert core.snapshot().focus.reporting_id is None
        assert auth_map.state(t.appliance_id) == AUTH_UNAUTHORIZED


class TestPollSettings:
    @pytest.mark.parametrize("value", [None, True, False, 0, -2, "6", float("nan"), object()])
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

    def test_a_state_push_queues_the_id_with_its_kinds_and_wakes_the_loop(self):
        core, gt = _make()
        core._poll_wake.clear()
        core.notify_state_changed("a" * 20, ("mute", "volume"))
        assert core._poll_wake.is_set()
        assert core._state_pending == {"a" * 20: {"mute", "volume"}}

    def test_a_state_push_naming_nothing_reads_as_any_change(self):
        core, gt = _make()
        core.notify_state_changed("a" * 20)
        core.notify_state_changed("b" * 20, ())
        assert core._state_pending == {"a" * 20: {"any"}, "b" * 20: {"any"}}

    def test_state_pushes_for_one_appliance_merge_their_kinds(self):
        core, gt = _make()
        core.notify_state_changed("a" * 20, ("mute",))
        core.notify_state_changed("a" * 20, ("volume",))
        assert core._state_pending == {"a" * 20: {"mute", "volume"}}

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

    def test_a_state_push_runs_a_tick_at_once(self):
        core, gt = _make()
        core.set_poll_interval(60)
        polls = []
        with patch.object(core, "poll_once", side_effect=lambda: polls.append(1)):
            core.start()
            assert self._wait_for(lambda: len(polls) == 1)
            core.notify_state_changed("a" * 20, ("mute",))
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
