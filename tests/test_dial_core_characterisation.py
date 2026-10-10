"""Characterisation tests for the dial display's poll ordering and focus
handling, timing windows, warnings and artwork, written against DialDisplay as
it stands so the same behaviour can be re-pointed at a different owner later.

Covers: a mute observation sent before a press never reverting the press,
every walked target's mute being observed, the selected service being set
before the artwork fetch, the accepted-replay window (no title or artist, the
grace boundary, the pending-focus boundary), no playing frame after a replay
stops, a refused first check never waking or painting, the sticky binding
beneath manual focus, the screens a focus clear closes, a refused playing
appliance being re-probed once per backoff, artwork failure logging and the
artwork URL staying out of status and logs, the outputs refresh and EQ
optimistic-window boundaries, and a persisted snooze surviving a restart.

Every clock-driven test patches time.monotonic everywhere it is read.
"""
from __future__ import annotations

import contextlib
import dataclasses
import json
import logging
import queue
import time
from unittest.mock import MagicMock, patch

import pytest

Image = pytest.importorskip("PIL.Image", reason="Pillow not installed")

from dial_test_support import (
    FakeBackend,
    _FakeClock,
    _repeat_obj,
    _roster_entry,
    _status_result,
    _target,
    _track_id,
    make_display,
)

import dial_auth
import dial_display as dd
import dial_repeat_store as drs
import dial_volume as dv
from dial_core_state import artwork_key
from dial_display import PLAYING_ARTIST_TEXT, SCREEN_POLICIES
from dial_touch_layout import TouchZone
from dial_warnings import WarningManager, WarningStore

# Module-level names that read the clock. dial_display and dial_volume both
# reach the one time module, so patching either patches both, but each is
# named so a module move only has to repoint this tuple.
_MONOTONIC_TARGETS = (
    "dial_display.time.monotonic", "dial_core_poll.time.monotonic", "dial_volume.time.monotonic",
)


@contextlib.contextmanager
def _patch_monotonic(clock):
    """Patch every time.monotonic reader with *clock*."""
    with contextlib.ExitStack() as stack:
        for target in _MONOTONIC_TARGETS:
            stack.enter_context(patch(target, clock))
        yield


def _reset_mute_state() -> None:
    dv.observe_mute_state(None, None)
    while True:
        try:
            dv._queue.get_nowait()
        except queue.Empty:
            break


@pytest.fixture(autouse=True)
def _clean_mute_state():
    """The mute observation store and its press queue are process-wide."""
    _reset_mute_state()
    yield
    _reset_mute_state()


def _fetch_by_service(results: dict):
    """A fetch_target_status stand-in answering from *results* by the
    target's service name."""
    return lambda target, *a, **k: results[target.service_name]


# ---------------------------------------------------------------------------
# Mute observations are ordered against presses by when the request was sent
# ---------------------------------------------------------------------------

class TestMuteObservationOrdering:
    def test_poll_sent_before_mute_press_never_reverts_shown_mute(self):
        """A press lands while a status request is in flight: the reply to
        that request describes the world from before the press, so it must
        not put the glyph back."""
        t = _target(dial_proto_version=2)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        clock = _FakeClock(5.0)
        with _patch_monotonic(clock):
            with patch("dial_display.fetch_target_status",
                       return_value=_status_result(track_id=None, muted=False)):
                display._poll_once()
            assert dv.shown_muted(t.service_name) is False

            def fetch_during_press(target, *a, **k):
                # The request was sent at 9.9; the press happens at 10.0 and
                # its response has since arrived (nothing in flight now).
                clock.t = 10.0
                dv.enqueue_mute(False)
                dv._clear_mute_inflight(t.service_name)
                return _status_result(track_id=None, muted=False)

            clock.t = 9.9
            with patch("dial_display.fetch_target_status", side_effect=fetch_during_press):
                display._poll_once()
        assert dv.shown_muted(t.service_name) is True

    def test_poll_sent_after_the_mute_press_applies(self):
        t = _target(dial_proto_version=2)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        clock = _FakeClock(5.0)
        with _patch_monotonic(clock):
            with patch("dial_display.fetch_target_status",
                       return_value=_status_result(track_id=None, muted=False)):
                display._poll_once()
            clock.t = 10.0
            dv.enqueue_mute(False)
            dv._clear_mute_inflight(t.service_name)
            assert dv.shown_muted(t.service_name) is True
            clock.t = 10.5
            with patch("dial_display.fetch_target_status",
                       return_value=_status_result(track_id=None, muted=False)):
                display._poll_once()
        assert dv.shown_muted(t.service_name) is False

    def test_legacy_target_poll_after_settle_clears_mute(self):
        """An earlier-release appliance never reports the flag: once a mute
        reply has settled, the next poll sent after it clears the highlight."""
        t = _target()   # protocol version 0: its status carries no mute flag
        display, fb, gt = make_display(targets=[t])
        display.enable()
        clock = _FakeClock(5.0)
        with _patch_monotonic(clock):
            dv.observe_mute_state(t.service_name, True)     # a mute reply
            assert dv.shown_muted(t.service_name) is True
            clock.t = 20.0
            with patch("dial_display.fetch_target_status",
                       return_value=_status_result(track_id=None, muted=None)):
                display._poll_once()
        assert dv.shown_muted(t.service_name) is False

    def test_every_walked_target_is_observed(self):
        """Neither target is identified, so the walk visits both: each gets
        its own entry in the real observation store, not only the one the
        screen reports from."""
        older = _target(name="Older", service_name="older", playing_since=10.0)
        newer = _target(name="Newer", service_name="newer", playing_since=20.0)
        display, fb, gt = make_display(targets=[older, newer])
        display.enable()
        results = {
            "older": _status_result(track_id=None, muted=False),
            "newer": _status_result(track_id=None, muted=True),
        }
        with patch("dial_display.fetch_target_status", side_effect=_fetch_by_service(results)):
            display._poll_once()
        assert display._reporting_appliance_id == older.appliance_id
        assert set(dv._observed_muted) == {"older", "newer"}
        assert dv.shown_muted("older") is False
        assert dv.shown_muted("newer") is True


# ---------------------------------------------------------------------------
# The selected service is published before the artwork fetch starts
# ---------------------------------------------------------------------------

class TestSourceServiceBeforeArtworkFetch:
    def test_source_service_name_is_set_before_the_artwork_fetch(self):
        """A volume press landing during a slow artwork fetch reads the
        source service name; it must already be the selected target."""
        older = _target(name="Older", service_name="older", playing_since=10.0)
        newer = _target(name="Newer", service_name="newer", playing_since=20.0)
        display, fb, gt = make_display(targets=[older, newer])
        display.enable()
        results = {
            "older": _status_result(track_id=None),
            "newer": _status_result(track_id=_track_id()),
        }
        seen = []

        def fetch_artwork(url, timeout):
            seen.append(display.current_source_service_name())
            return None, "stub"

        with patch("dial_display.fetch_target_status", side_effect=_fetch_by_service(results)), \
             patch("dial_display._fetch_artwork", side_effect=fetch_artwork):
            display._poll_once()
        assert seen == ["newer"]


# ---------------------------------------------------------------------------
# The accepted-replay window and the pending-focus window
# ---------------------------------------------------------------------------

AID = "a" * 20


def _replay_display(state="hold", **display_kwargs):
    """A display following AID, rostered and repeat-capable, with a repeat
    record in *state*. The caller patches the clock before calling this."""
    entry = _roster_entry(appliance_id=AID, auth="authorized", repeat_capable=True)
    display, fb, gt = make_display(targets=[], roster=[entry], **display_kwargs)
    display.enable()
    display._last_roster = [entry]
    display._manual_focus_id = AID
    drs.repeat_store.update(
        AID, drs.parse_repeat_object(_repeat_obj(state=state), dd.time.monotonic()),
    )
    display.request_poll = MagicMock()
    return display, fb, gt


def _accept_replay(display) -> None:
    display.on_repeat_result(
        "transport", AID, 200,
        {"ok": True, "state": "replaying", "armed": False, "position_seconds": 0.0},
    )


class TestAcceptedReplayWindow:
    def test_accepted_replay_frame_has_no_title_or_artist(self):
        """The synthetic playing target has no identified track yet, so the
        first frame is the plain logo, playing, with nothing to name."""
        clock = _FakeClock()
        with _patch_monotonic(clock):
            display, fb, gt = _replay_display()
            _accept_replay(display)
            with patch("dial_display.fetch_target_status",
                       return_value=_status_result(appliance_id=AID)):
                display._poll_once()
        playing = display._now_playing
        assert playing is not None and playing.playing
        assert playing.title == ""
        assert playing.artist == ""
        assert display.get_status()["showing"] == "logo"
        assert display._source_artwork_key == ""

    def test_accepted_replay_window_boundary_under_fake_clock(self):
        """Kept just inside the grace, dropped just past it."""
        clock = _FakeClock()
        with _patch_monotonic(clock):
            display, fb, gt = _replay_display()
            _accept_replay(display)
            accepted_at = clock.t
            clock.t = accepted_at + dd.ACCEPTED_REPLAY_GRACE_S - 0.01
            kept = display._core.with_accepted_replay([], clock.t)
            assert [t.appliance_id for t in kept] == [AID]
            assert display._accepted_replay is not None
            clock.t = accepted_at + dd.ACCEPTED_REPLAY_GRACE_S + 0.01
            assert display._core.with_accepted_replay([], clock.t) == []
            assert display._accepted_replay is None
        assert dd.ACCEPTED_REPLAY_GRACE_S == 20.0

    def test_pending_focus_boundary_under_fake_clock(self):
        """A pending focus on an appliance that never appears survives to
        just inside the grace and is cleared just past it."""
        aid = "b" * 20
        display, fb, gt = make_display(targets=[])
        clock = _FakeClock()
        with _patch_monotonic(clock):
            display.set_manual_focus_pending(aid, "Kitchen")
            start = clock.t
            clock.t = start + dd.FOCUS_PENDING_GRACE_S - 0.01
            display._poll_once()
            assert display.manual_focus_id() == aid
            assert display._focus_pending is not None
            clock.t = start + dd.FOCUS_PENDING_GRACE_S + 0.01
            display._poll_once()
        assert display.manual_focus_id() is None
        assert display._focus_pending is None
        assert dd.FOCUS_PENDING_GRACE_S == 10.0


# ---------------------------------------------------------------------------
# A replay that stops never flashes "Playing" over the logo
# ---------------------------------------------------------------------------

class TestReplayStopFrames:
    def test_replay_stop_never_paints_playing_over_the_logo(self):
        """Accepted replay -> the record fades out -> the target is gone and
        the record holds. From the poll that sees the stop, no composed
        frame carries the playing artist text and the base is the
        replay-available logo."""
        clock = _FakeClock()
        with _patch_monotonic(clock):
            # A tier that draws the artist row, with the controls always shown.
            display, fb, gt = _replay_display(always_show_controls=True)
            base_metrics = display._layout_metrics
            display._layout_metrics = lambda: dataclasses.replace(
                base_metrics(), content_tier=dd.CONTENT_RICH,
            )
            # The playing frame must really carry the text, or this test
            # would pass for the wrong reason.
            frames = []
            real_compose = display._compositor.compose

            def record_compose(base, *a, **k):
                frames.append(("playing", k.get("overlay")))
                return real_compose(base, *a, **k)

            idle_bases = []
            real_idle = display._compositor.compose_idle

            def record_idle(base, *a, **k):
                idle_bases.append(base)
                frames.append(("idle", None))
                return real_idle(base, *a, **k)

            display._compositor.compose = record_compose
            display._compositor.compose_idle = record_idle

            _accept_replay(display)
            with patch("dial_display.fetch_target_status",
                       return_value=_status_result(appliance_id=AID)):
                display._poll_once()
            with display._lock:
                display._repaint_current_locked()
            playing_overlays = [o for kind, o in frames if kind == "playing" and o is not None]
            assert any(o.artist == PLAYING_ARTIST_TEXT for o in playing_overlays)

            # The replay is fading out: still playing, still the synthetic target.
            drs.repeat_store.update(AID, drs.parse_repeat_object(
                _repeat_obj(state="fading_out", held=False,
                            replay={"active": True, "position_seconds": 29.0, "duration_seconds": 30.0}),
                clock.t,
            ))
            clock.t += 1.0
            with patch("dial_display.fetch_target_status",
                       return_value=_status_result(appliance_id=AID)):
                display._poll_once()

            # Stopped: the record holds and the target is gone.
            drs.repeat_store.update(AID, drs.parse_repeat_object(_repeat_obj(state="hold"), clock.t))
            clock.t += 1.0
            mark = len(frames)
            with patch("dial_display.fetch_target_status",
                       return_value=_status_result(appliance_id=AID)), \
                 patch("dial_display.load_logo", side_effect=dd.load_logo) as load_logo:
                display._poll_once()
                with display._lock:
                    display._repaint_current_locked()
            after_stop = frames[mark:]
            assert not any(
                o is not None and o.artist == PLAYING_ARTIST_TEXT for kind, o in after_stop
            )
            assert display._now_playing is None
            assert display._idle_affordance is True
            assert display._idle_chassis_due_locked() is True
            assert any(kind == "idle" for kind, _ in after_stop)
            assert load_logo.call_args_list[-1].args[0] == display._replay_logo_path


# ---------------------------------------------------------------------------
# A refused first check neither wakes nor paints
# ---------------------------------------------------------------------------

class TestFirstCheckOrdering:
    def _asleep(self, targets):
        display, fb, gt = make_display(targets=targets)
        display.enable()
        with display._lock:
            display._sleep_locked()
        assert display._display_sleeping
        return display, fb, gt

    def test_first_check_refusal_never_wakes_or_paints_in_the_same_tick(self):
        t = _target(name="Fresh", auth="unknown")
        display, fb, gt = self._asleep([t])
        wakes, frames = fb.wake_calls, len(fb.displayed)
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(status_error="unauthorized",
                                               appliance_id=t.appliance_id)) as fetch:
            display._poll_once()
        assert fetch.call_count == 1
        assert fb.wake_calls == wakes
        assert len(fb.displayed) == frames
        assert display._display_sleeping

    def test_first_check_acceptance_wakes_with_a_single_request(self):
        t = _target(name="Fresh", auth="unknown")
        display, fb, gt = self._asleep([t])
        wakes = fb.wake_calls
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=None)) as fetch:
            display._poll_once()
        assert fetch.call_count == 1      # the walk reuses the first check's reply
        assert fb.wake_calls == wakes + 1
        assert not display._display_sleeping


# ---------------------------------------------------------------------------
# Sticky binding beneath manual focus
# ---------------------------------------------------------------------------

class TestBinding:
    def _two(self):
        a = _target(name="Alpha", service_name="alpha", playing_since=1.0)
        b = _target(name="Bravo", service_name="bravo", playing_since=2.0)
        display, fb, gt = make_display(targets=[a, b])
        display.enable()
        return display, gt, a, b

    @staticmethod
    def _poll(display, results):
        with patch("dial_display.fetch_target_status", side_effect=_fetch_by_service(results)) as fetch, \
             patch("dial_display._fetch_artwork", return_value=(b"jpegdata", "")), \
             patch.object(display, "_show_artwork") as shown:
            display._poll_once()
        return fetch, shown

    def test_binds_on_first_tick(self):
        a = _target(name="Alpha", service_name="alpha", playing_since=1.0)
        display, fb, gt = make_display(targets=[a])
        display.enable()
        assert display._bound_appliance_id is None
        self._poll(display, {"alpha": _status_result(track_id=None)})
        assert display._bound_appliance_id == a.appliance_id
        assert display._reporting_appliance_id == a.appliance_id

    def test_second_starter_with_artwork_does_not_steal(self):
        a = _target(name="Alpha", service_name="alpha", playing_since=1.0)
        b = _target(name="Bravo", service_name="bravo", playing_since=2.0)
        display, fb, gt = make_display(targets=[a])
        display.enable()
        self._poll(display, {"alpha": _status_result(track_id=None)})
        gt.return_value = [a, b]
        fetch, shown = self._poll(display, {
            "alpha": _status_result(track_id=None),
            "bravo": _status_result(track_id=_track_id()),
        })
        assert display._bound_appliance_id == a.appliance_id
        assert display._reporting_appliance_id == a.appliance_id
        assert display.current_source_service_name() == "alpha"
        assert [c.args[0].service_name for c in fetch.call_args_list] == ["alpha"]
        shown.assert_not_called()

    def test_bound_stops_with_a_survivor_rebinds(self):
        display, gt, a, b = self._two()
        both = {"alpha": _status_result(track_id=None), "bravo": _status_result(track_id=None)}
        self._poll(display, both)
        assert display._bound_appliance_id == a.appliance_id
        gt.return_value = [b]
        self._poll(display, both)
        assert display._bound_appliance_id == b.appliance_id
        assert display._reporting_appliance_id == b.appliance_id

    def test_bound_stops_with_nothing_releases_to_none(self):
        a = _target(name="Alpha", service_name="alpha", playing_since=1.0)
        display, fb, gt = make_display(targets=[a])
        display.enable()
        self._poll(display, {"alpha": _status_result(track_id=None)})
        assert display._bound_appliance_id == a.appliance_id
        gt.return_value = []
        self._poll(display, {})
        assert display._bound_appliance_id is None
        assert display._reporting_appliance_id is None

    def test_revoke_mid_tick_releases_and_continues(self):
        display, gt, a, b = self._two()
        self._poll(display, {"alpha": _status_result(track_id=None), "bravo": _status_result(track_id=None)})
        assert display._bound_appliance_id == a.appliance_id
        fetch, shown = self._poll(display, {
            "alpha": _status_result(status_error="unauthorized", appliance_id=a.appliance_id),
            "bravo": _status_result(track_id=_track_id()),
        })
        assert [c.args[0].service_name for c in fetch.call_args_list] == ["alpha", "bravo"]
        assert display._bound_appliance_id == b.appliance_id
        assert display._reporting_appliance_id == b.appliance_id
        assert display.current_source_service_name() == "bravo"
        shown.assert_called_once()
        assert shown.call_args.args[0].key == artwork_key("https://provider.example/x.jpg")

    def test_manual_focus_mirrors_into_the_binding(self):
        display, gt, a, b = self._two()
        both = {"alpha": _status_result(track_id=None), "bravo": _status_result(track_id=None)}
        self._poll(display, both)
        assert display._bound_appliance_id == a.appliance_id
        display.set_manual_focus(b.appliance_id)
        self._poll(display, both)
        assert display._bound_appliance_id == b.appliance_id
        assert display._reporting_appliance_id == b.appliance_id
        assert display.manual_focus_id() == b.appliance_id


# ---------------------------------------------------------------------------
# A focus clear closes exactly the screens whose policy says so
# ---------------------------------------------------------------------------

_SCREEN_NAMES = sorted(name for name in SCREEN_POLICIES if name != "main")


class TestFocusClearClosesPolicyScreens:
    def test_policy_rows_that_close_on_focus_clear(self):
        assert {n for n in _SCREEN_NAMES if SCREEN_POLICIES[n].closes_on_focus_clear} == {
            "repeat", "eq", "outputs", "output",
        }

    @pytest.mark.parametrize("name", _SCREEN_NAMES)
    def test_focus_clear_closes_only_policy_screens(self, name):
        policy = SCREEN_POLICIES[name]
        display, fb, gt = make_display(targets=[])
        display.enable()
        display._manual_focus_id = AID
        sentinel = object()
        with display._lock:
            display._screen = name
            if policy.state_attr is not None:
                setattr(display, policy.state_attr, sentinel)
        display._core.clear_focus("test")
        display._close_screens_for_cleared_focus()
        assert display.manual_focus_id() is None
        if policy.closes_on_focus_clear:
            assert display._screen == "main"
            if policy.state_attr is not None:
                assert getattr(display, policy.state_attr) is None
        else:
            assert display._screen == name
            if policy.state_attr is not None:
                assert getattr(display, policy.state_attr) is sentinel


    def test_a_tick_that_clears_the_focus_closes_the_screen(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display._manual_focus_id = AID      # not on the roster: the tick clears it
        with display._lock:
            display._screen = "outputs"
        display._poll_once()
        assert display.manual_focus_id() is None
        assert display._screen == "main"


# ---------------------------------------------------------------------------
# A refused appliance that keeps playing is re-probed once per backoff
# ---------------------------------------------------------------------------

class TestRefusedPlayingReprobe:
    def test_refused_playing_appliance_is_probed_once_per_backoff(self):
        """The appliance has been refused and keeps advertising playback. It
        is never fetched by the walk; only the reconcile pass re-checks it,
        and only once its backoff has run out. The reconcile pass runs every
        RECONCILE_INTERVAL_SECONDS, so with the backoff starting at 30 s and
        doubling per refusal the re-checks land at 0, 60, 120, 240 and 480 s
        rather than on a fixed cadence."""
        t = _target(name="Hall", service_name="Hall", appliance_id="9" * 20,
                    auth="unauthorized", dial_status=True)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        clock = _FakeClock(1000.0)
        start = clock.t
        probed_at: list[float] = []

        def fake_enrich(targets, dial_id):
            probed_at.extend([clock.t - start] * len(targets))
            return [
                {"name": x.service_name, "status_error": "unauthorized",
                 "appliance_id": x.appliance_id}
                for x in targets
            ]

        with _patch_monotonic(clock), \
                patch("dial_display.fetch_target_status") as walk_fetch, \
                patch("dial_display.enrich_targets", side_effect=fake_enrich):
            for _ in range(61):         # 10 s ticks across 600 s
                display._poll_once()
                clock.t += 10.0
        walk_fetch.assert_not_called()
        assert probed_at == [0.0, 60.0, 120.0, 240.0, 480.0]
        assert display._reporting_appliance_id is None
        assert dial_auth.auth_map.state(t.appliance_id) == dial_auth.AUTH_UNAUTHORIZED


# ---------------------------------------------------------------------------
# Artwork failure logging and the URL staying out of status and logs
# ---------------------------------------------------------------------------

_SECRET_URL = "https://provider.example/art-token-7731/cover.jpg"


def _artwork_display(url=_SECRET_URL):
    t = _target()
    display, fb, gt = make_display(targets=[t])
    display.enable()
    result = _status_result(track_id=_track_id(artwork_url=url))
    return display, result


class TestArtworkLogging:
    def test_artwork_failures_log_first_and_tenth(self, caplog):
        display, result = _artwork_display()
        with patch("dial_display.fetch_target_status", return_value=result), \
                patch("dial_display._fetch_artwork", return_value=(None, "timeout")) as fetch, \
                caplog.at_level(logging.WARNING):
            for _ in range(11):
                display._poll_once()
        assert fetch.call_count == 11           # every poll retries
        records = [r for r in caplog.records if "artwork fetch failed" in r.getMessage()]
        assert len(records) == 2
        assert display.get_status()["showing"] == "logo"
        assert display.get_status()["last_error"] == "artwork_fetch_failed"

    def test_artwork_decode_failures_log_first_and_tenth(self, caplog):
        display, result = _artwork_display()
        with patch("dial_display.fetch_target_status", return_value=result), \
                patch("dial_display._fetch_artwork", return_value=(b"bad", "")), \
                patch("dial_display.decode_artwork", return_value=None), \
                caplog.at_level(logging.WARNING):
            for _ in range(11):
                display._poll_once()
        records = [r for r in caplog.records if "artwork decode failed" in r.getMessage()]
        assert len(records) == 2

    def test_artwork_url_never_stored_or_logged(self, caplog):
        """Status, every log record and every attribute of the display carry
        only the short artwork key: the URL is never stored on the display
        (the cache-reuse key is a hash), nor held by the core."""
        display, result = _artwork_display()
        fake_image = Image.new("RGB", (128, 160))
        with patch("dial_display.fetch_target_status", return_value=result), \
                caplog.at_level(logging.DEBUG):
            with patch("dial_display._fetch_artwork", return_value=(None, "timeout")):
                for _ in range(3):
                    display._poll_once()
            with patch("dial_display._fetch_artwork", return_value=(b"jpeg", "")), \
                    patch("dial_display.decode_artwork", return_value=fake_image), \
                    patch("dial_display_compositor.transform_artwork_for_panel",
                          return_value=fake_image):
                display._poll_once()
        assert display.get_status()["showing"] == "artwork"
        assert caplog.records
        for record in caplog.records:
            assert "art-token-7731" not in record.getMessage()
            assert all("art-token-7731" not in str(a) for a in (record.args or ()))
        assert "art-token-7731" not in json.dumps(display.get_status())
        holders = [
            k for k, v in vars(display).items()
            if isinstance(v, str) and "art-token-7731" in v
        ]
        assert holders == []
        assert display._source_artwork_key == artwork_key(_SECRET_URL)
        held = display._core.snapshot().artwork
        assert held is not None and held.url == "" and held.key == artwork_key(_SECRET_URL)


# ---------------------------------------------------------------------------
# Timing windows: the outputs refresh tick and the EQ optimistic override
# ---------------------------------------------------------------------------

class TestOutputsRefreshBoundary:
    def _opened(self, screen="outputs"):
        display, fb, gt = make_display(targets=[])
        display._reporting_appliance_id = AID
        display._last_roster = [_roster_entry(appliance_id=AID, dial_outputs=True)]
        assert display._open_outputs_locked() is True
        display._screen = screen
        return display

    def test_outputs_refresh_tick_boundary(self):
        display = self._opened()
        clock = _FakeClock(1000.0)
        with _patch_monotonic(clock), patch("dial_core.enqueue_fetch") as enqueue:
            display._tick_outputs_refresh()
            assert enqueue.call_count == 1          # the first tick is due at once
            clock.t = 1001.99
            display._tick_outputs_refresh()
            assert enqueue.call_count == 1
            clock.t = 1002.01
            display._tick_outputs_refresh()
            assert enqueue.call_count == 2
            clock.t = 1003.99
            display._tick_outputs_refresh()
            assert enqueue.call_count == 2          # the window restarts at the fetch
        assert enqueue.call_args[0][0].appliance_id == AID

    def test_outputs_refresh_runs_for_the_detail_page_and_not_for_main(self):
        clock = _FakeClock(1000.0)
        with _patch_monotonic(clock), patch("dial_core.enqueue_fetch") as enqueue:
            self._opened(screen="output")._tick_outputs_refresh()
            assert enqueue.call_count == 1
            self._opened(screen="main")._tick_outputs_refresh()
            assert enqueue.call_count == 1


def _eq_display():
    display, fb, gt = make_display(targets=[])
    display._reporting_appliance_id = AID
    display._last_roster = [_roster_entry(appliance_id=AID, dial_eq=True)]
    display._core._update_availability(time.monotonic())
    return display


class TestEqOptimisticWindow:
    def test_eq_optimistic_window_boundary(self):
        display = _eq_display()
        clock = _FakeClock(1000.0)
        fetched = {"ok": True, "bass_db": 0, "treble_db": 0}
        with _patch_monotonic(clock), patch("dial_core._enqueue_eq_set"):
            assert display._open_eq_locked() is True
            display.eq_step("bass", +2)
            clock.t = 1001.99
            assert display._shown_eq(display._eq, "bass") == 2
            # A fetch that lands inside the window leaves the override in place.
            display.on_eq_result("fetch", AID, 200, fetched, {})
            assert display._eq_optimistic is not None
            assert display._shown_eq(display._eq, "bass") == 2
            clock.t = 1002.01
            assert display._shown_eq(display._eq, "bass") == 0
            # One that lands after it clears the override.
            display.on_eq_result("fetch", AID, 200, fetched, {})
        assert display._eq_optimistic is None

    def test_eq_step_preserves_the_other_controls_shown_value(self):
        display = _eq_display()
        clock = _FakeClock(1000.0)
        with _patch_monotonic(clock), patch("dial_core._enqueue_eq_set"):
            display._open_eq_locked()
            display.on_eq_result("fetch", AID, 200, {"ok": True, "bass_db": 1, "treble_db": -3}, {})
            display.eq_step("bass", +9)
            assert display._eq_optimistic == (6, -3, 1002.0)   # clamped to the limit
            assert display._shown_eq(display._eq, "treble") == -3


# ---------------------------------------------------------------------------
# A persisted snooze survives a restart through the real warning store
# ---------------------------------------------------------------------------

class TestPersistedSnoozeRestart:
    def _display(self, path, wall):
        manager = WarningManager(dd.WARNING_DESCRIPTORS, WarningStore(path), clock=wall)
        display, fb, gt = make_display(targets=[], warnings=manager)
        return display, manager

    @pytest.mark.parametrize("percent, snooze_s", [
        (50, dd.SDHEALTH_SNOOZE_S),
        (1, dd.SDHEALTH_CRITICAL_SNOOZE_S),
    ])
    def test_persisted_snooze_survives_a_restart(self, tmp_path, percent, snooze_s):
        path = str(tmp_path / "warnings.json")
        wall = _FakeClock(1_000_000.0)
        first, manager = self._display(path, wall)
        first._warning_active("sdhealth", percent)
        first.warning_button_tap(TouchZone.SDHEALTH_DISMISS)
        assert manager.is_snoozed("sdhealth") is True
        manager.flush()
        with open(path, encoding="utf-8") as f:
            assert "sdhealth" in json.load(f)

        # A restart: a fresh manager over the same file, the condition still holding.
        wall.t += 3600.0
        second, manager2 = self._display(path, wall)
        second._warning_active("sdhealth", percent)
        assert manager2.is_snoozed("sdhealth") is True
        assert manager2.due() is None

        # Past the snooze it is due again.
        wall.t += snooze_s
        third, manager3 = self._display(path, wall)
        third._warning_active("sdhealth", percent)
        assert manager3.is_snoozed("sdhealth") is False
        assert manager3.due().id == "sdhealth"

    def test_a_cleared_source_forgets_the_persisted_snooze(self, tmp_path):
        path = str(tmp_path / "warnings.json")
        wall = _FakeClock(1_000_000.0)
        first, manager = self._display(path, wall)
        first._warning_active("sdhealth", 50)
        first.warning_button_tap(TouchZone.SDHEALTH_DISMISS)
        manager.flush()
        first._warning_cleared("sdhealth")
        manager.flush()
        second, manager2 = self._display(path, wall)
        second._warning_active("sdhealth", 50)
        assert manager2.is_snoozed("sdhealth") is False
