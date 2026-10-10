"""Tests for the dial core's focus: the manual focus, the pending focus a
picker-started replay holds while it reaches the playing set, and the accepted
replay window that shows a followed replay as playing before its
advertisement arrives.

Each test drives the core through a display (its only consumer here) and reads
the core's snapshot and methods.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

Image = pytest.importorskip("PIL.Image", reason="Pillow not installed")

from dial_test_support import (
    _FakeClock,
    _repeat_obj,
    _roster_entry,
    _status_result,
    _target,
    _track_id,
    make_display,
    on_repeat_result,
    patch_monotonic,
    set_focus_pending,
)

import dial_auth
import dial_core_poll
from dial_core import FOCUS_PENDING_GRACE_S
from dial_core_state import ACCEPTED_REPLAY_GRACE_S, NowPlaying


# ---------------------------------------------------------------------------
# Sticky manual focus.
# ---------------------------------------------------------------------------

class TestManualFocus:
    def test_set_manual_focus_sets_poll_wake_and_is_readable(self):
        display, fb, gt = make_display(targets=[])
        assert not display._core._poll_wake.is_set()
        display.core.set_focus("a" * 20)
        assert display._core._poll_wake.is_set()
        assert display.core.manual_focus_id() == "a" * 20
    def test_clear_manual_focus(self):
        display, fb, gt = make_display(targets=[])
        display.core.set_focus("a" * 20)
        display.core.set_focus(None)
        assert display.core.manual_focus_id() is None
    def test_never_survives_a_new_display(self):
        display1, fb1, gt1 = make_display(targets=[])
        display1.core.set_focus("d" * 20)
        display2, fb2, gt2 = make_display(targets=[])
        assert display2.core.manual_focus_id() is None
    def test_focus_clears_when_target_leaves_roster(self):
        aid = "b" * 20
        display, fb, gt = make_display(targets=[])
        display.core.set_focus(aid)
        display._poll_once()
        assert display.core.manual_focus_id() is None
    def test_focus_clears_mid_tick_on_confirmed_unauthorized_and_falls_back(self):
        aid = "c" * 20
        focus_t = _target(name="Focus", service_name="Focus", appliance_id=aid, playing_since=1.0)
        other_t = _target(name="Other", service_name="Other", playing_since=5.0)
        display, fb, gt = make_display(targets=[focus_t, other_t])
        display.enable()
        display.core.set_focus(aid)

        def fake_fetch(target, dial_id, timeout_seconds):
            if target is focus_t:
                return _status_result(status_error="unauthorized", appliance_id=aid)
            return _status_result(track_id=_track_id())

        with patch("dial_display.fetch_target_status", side_effect=fake_fetch):
            display._poll_once()

        assert display.core.manual_focus_id() is None
        assert dial_auth.auth_map.state(aid) == dial_auth.AUTH_UNAUTHORIZED
        assert display.core.snapshot().focus.source_service_name == "Other"
    def test_focus_target_album_is_read_on_the_pinned_path(self):
        aid = "8" * 19 + "a"
        focus_t = _target(name="Focus", service_name="Focus", appliance_id=aid, playing_since=1.0)
        display, fb, gt = make_display(targets=[focus_t])
        display.enable()
        display.core.set_focus(aid)
        fake_image = Image.new("RGB", (fb.width, fb.height))
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=_track_id(album="Focused Album"), appliance_id=aid)), \
             patch("dial_display._fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display._poll_once()
        assert display.core.snapshot().now_playing.album == "Focused Album"
    def test_focus_clears_when_appliance_stops_but_stays_idle_on_roster(self):
        aid = "b" * 20
        playing = _target(name="A", service_name="A", appliance_id=aid, auth="authorized")
        idle_entry = _roster_entry(name="A", service_name="A", appliance_id=aid, auth="authorized", playing=False)
        display, fb, gt = make_display(targets=[playing], roster=[idle_entry])
        display.enable()
        display.core.set_focus(aid)
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=None, appliance_id=aid)):
            display._poll_once()
        assert display.core.manual_focus_id() == aid

        gt.return_value = []  # the appliance stopped playing but stays rostered idle
        display._poll_once()
        assert display.core.manual_focus_id() is None
    def test_focus_on_idle_appliance_is_kept_when_another_starts_playing(self):
        aid_idle = "c" * 20
        idle_entry = _roster_entry(name="Idle", service_name="Idle", appliance_id=aid_idle, auth="authorized",
                                    playing=False)
        display, fb, gt = make_display(targets=[], roster=[idle_entry])
        display.enable()
        display.core.set_focus(aid_idle)
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=None, appliance_id=aid_idle)):
            display._poll_once()
        assert display.core.manual_focus_id() == aid_idle

        other = _target(name="Other", service_name="Other", appliance_id="d" * 20, auth="authorized")
        gt.return_value = [other]
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        assert display.core.manual_focus_id() == aid_idle
    def test_picking_an_idle_row_shows_it_with_no_fetch_for_playing_targets(self):
        aid_idle = "e" * 20
        idle_entry = _roster_entry(name="Idle", service_name="Idle", appliance_id=aid_idle, auth="authorized",
                                    playing=False)
        other = _target(name="Other", service_name="Other", appliance_id="f" * 20, auth="authorized")
        display, fb, gt = make_display(targets=[other], roster=[idle_entry])
        display.enable()
        display.core.set_focus(aid_idle)  # simulates selector_pick's effect on an idle row

        calls = []

        def fake_fetch(target, dial_id, timeout_seconds):
            calls.append(target.service_name)
            return _status_result(track_id=None, appliance_id=target.appliance_id)

        with patch("dial_display.fetch_target_status", side_effect=fake_fetch):
            display._poll_once()

        assert calls == ["Idle"]
        assert display.core.snapshot().now_playing == NowPlaying("Idle", "", "", 50, playing=False)
        assert display.core.snapshot().focus.reporting_id == aid_idle
        assert display.core.snapshot().focus.source_service_name == "Idle"
    def test_idle_focus_unauthorized_clears_mid_tick_and_walk_falls_through(self):
        aid_idle = "5" * 20
        idle_entry = _roster_entry(name="Idle", service_name="Idle", appliance_id=aid_idle, auth="authorized",
                                    playing=False)
        other = _target(name="Other", service_name="Other", appliance_id="6" * 20, auth="authorized")
        display, fb, gt = make_display(targets=[other], roster=[idle_entry])
        display.enable()
        display.core.set_focus(aid_idle)

        def fake_fetch(target, dial_id, timeout_seconds):
            if target is idle_entry:
                return _status_result(status_error="unauthorized", appliance_id=aid_idle)
            return _status_result(track_id=None, appliance_id=target.appliance_id)

        with patch("dial_display.fetch_target_status", side_effect=fake_fetch):
            display._poll_once()

        assert display.core.manual_focus_id() is None
        assert display.core.snapshot().now_playing is not None
        assert display.core.snapshot().now_playing.service_name == "Other"
        assert display.core.snapshot().focus.reporting_id == "6" * 20
    def test_focus_volume_target_none_without_a_focus(self):
        display, fb, gt = make_display(targets=[])
        display.core.set_roster([_roster_entry(appliance_id="3" * 20, auth="authorized")])
        assert display.core.focus_volume_target() is None
    def test_focus_volume_target_returns_the_roster_entry_while_focused(self):
        aid = "4" * 20
        entry = _roster_entry(name="Kitchen", service_name="Kitchen", appliance_id=aid, auth="authorized",
                               playing=False)
        display, fb, gt = make_display(targets=[])
        display.core.set_field("manual_id", aid)
        display.core.set_roster([entry])
        assert display.core.focus_volume_target() is entry
    def test_focus_volume_target_none_when_entry_unauthorized(self):
        aid = "2" * 20
        entry = _roster_entry(name="Kitchen", service_name="Kitchen", appliance_id=aid, auth="unauthorized",
                               playing=False)
        display, fb, gt = make_display(targets=[])
        display.core.set_field("manual_id", aid)
        display.core.set_roster([entry])
        assert display.core.focus_volume_target() is None


# ---------------------------------------------------------------------------
# Manual-focus pending grace: a picker-started replay's focus survives
# absence from the roster for FOCUS_PENDING_GRACE_S, converts to a normal
# focus once sighted, and clears on expiry or a failed transport.
# ---------------------------------------------------------------------------

class TestFocusPendingGrace:
    def test_pending_focus_survives_absence_within_grace(self):
        display, fb, gt = make_display(targets=[])
        aid = "b" * 20
        set_focus_pending(display, aid, "Kitchen")
        display._poll_once()
        assert display.core.manual_focus_id() == aid
        assert display.core.snapshot().now_playing is not None
        assert display.core.snapshot().now_playing.service_name == "Kitchen"
    def test_pending_focus_expires_after_grace_without_rostered_appliance(self):
        display, fb, gt = make_display(targets=[])
        aid = "d" * 20
        clock = _FakeClock()
        with patch_monotonic(clock):
            set_focus_pending(display, aid, "Kitchen")
            display._poll_once()
            assert display.core.manual_focus_id() == aid
            clock.t += FOCUS_PENDING_GRACE_S + 1
            display._poll_once()
        assert display.core.manual_focus_id() is None
        assert display.core.snapshot().focus.pending is None
    def test_pending_focus_expires_after_grace_kept_as_idle_focus_when_rostered(self):
        aid = "d" * 19 + "1"
        idle_entry = _roster_entry(name="Kitchen", service_name="Kitchen", appliance_id=aid, auth="authorized",
                                    playing=False)
        display, fb, gt = make_display(targets=[], roster=[idle_entry])
        clock = _FakeClock()
        with patch_monotonic(clock), \
             patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=None, appliance_id=aid)):
            set_focus_pending(display, aid, "Kitchen")
            display._poll_once()
            assert display.core.manual_focus_id() == aid
            clock.t += FOCUS_PENDING_GRACE_S + 1
            display._poll_once()
        # The grace expired, but the appliance is rostered (idle): the
        # pending focus simply becomes an ordinary idle focus, not cleared.
        assert display.core.manual_focus_id() == aid
        assert display.core.snapshot().focus.pending is None
        assert display.core.snapshot().now_playing is not None
        assert display.core.snapshot().now_playing.service_name == "Kitchen"
    def test_pending_focus_converts_to_normal_focus_when_sighted(self):
        aid = "e" * 20
        display, fb, gt = make_display(targets=[])
        set_focus_pending(display, aid, "Kitchen")
        display._poll_once()
        assert display.core.snapshot().focus.pending is not None

        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid, playing_since=1.0)
        gt.return_value = [t]
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=None, appliance_id=aid)):
            display._poll_once()
        assert display.core.manual_focus_id() == aid
        assert display.core.snapshot().focus.pending is None
    def test_on_repeat_result_failure_clears_pending_focus(self):
        aid = "f" * 20
        display, fb, gt = make_display(targets=[])
        set_focus_pending(display, aid, "Kitchen")
        display._poll_once()
        assert display.core.manual_focus_id() == aid

        on_repeat_result(display, "transport", aid, 200, {"ok": False, "error": "source_active"})
        assert display.core.manual_focus_id() is None
        assert display.core.snapshot().focus.pending is None
    def test_on_repeat_result_success_does_not_clear_pending_focus(self):
        aid = "1" * 20 + "a" * 0
        aid = "a" * 19 + "1"
        display, fb, gt = make_display(targets=[])
        set_focus_pending(display, aid, "Kitchen")
        display._poll_once()
        on_repeat_result(display,
            "transport", aid, 200,
            {"ok": True, "state": "replaying", "armed": True, "position_seconds": 0.0},
        )
        assert display.core.manual_focus_id() == aid
        assert display.core.snapshot().focus.pending is not None


class TestAcceptedReplayShowsAsPlaying:
    """A replay the dial is following counts as playing from the moment its
    seek is acknowledged until its mDNS playing advertisement arrives."""

    AID = "a" * 20

    def _display(self, state="replaying", auth="authorized", focus=True, rostered=True, accepted=True):
        import dial_repeat_store as drs
        entry = _roster_entry(appliance_id=self.AID, auth=auth, repeat_capable=True)
        display, fb, gt = make_display(targets=[], roster=[entry] if rostered else [])
        display.enable()
        display.core.set_roster([entry] if rostered else [])
        if focus:
            display.core.set_field("manual_id", self.AID)
        now = time.monotonic()
        drs.repeat_store.update(self.AID, drs.parse_repeat_object(_repeat_obj(state=state), now))
        if accepted:
            display.core.set_field("accepted_replay", (self.AID, now + ACCEPTED_REPLAY_GRACE_S))
        return display

    def test_adds_the_accepted_replaying_appliance(self):
        display = self._display()
        targets = display._core.with_accepted_replay([], time.monotonic())
        assert [t.appliance_id for t in targets] == [self.AID]
        assert targets[0].ip == "192.168.1.10"
        assert targets[0].service_name == "Kitchen"
        assert display.core.snapshot().focus.accepted_replay is not None

    def test_the_real_advertisement_takes_over_and_ends_the_window(self):
        display = self._display()
        real = _target(appliance_id=self.AID)
        assert display._core.with_accepted_replay([real], time.monotonic()) == [real]
        assert display.core.snapshot().focus.accepted_replay is None
        # From then on the playing set alone decides, as before.
        assert display._core.with_accepted_replay([], time.monotonic()) == []

    def test_window_expires(self):
        display = self._display()
        now = time.monotonic()
        assert display._core.with_accepted_replay([], now + ACCEPTED_REPLAY_GRACE_S) == []
        assert display.core.snapshot().focus.accepted_replay is None

    def test_a_replaying_record_alone_is_not_enough(self):
        display = self._display(accepted=False)
        assert display._core.with_accepted_replay([], time.monotonic()) == []

    @pytest.mark.parametrize("kwargs", [
        {"state": "hold"}, {"state": "recording"}, {"focus": False},
        {"auth": "unauthorized"}, {"rostered": False},
    ])
    def test_nothing_added_otherwise(self, kwargs):
        display = self._display(**kwargs)
        assert display._core.with_accepted_replay([], time.monotonic()) == []

    def test_poll_shows_it_as_playing(self):
        display = self._display()
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(appliance_id=self.AID)) as fetch:
            display._poll_once()
        assert fetch.call_args[0][0].appliance_id == self.AID
        assert display.core.snapshot().focus.reporting_id == self.AID
        assert display.core.snapshot().now_playing is not None and display.core.snapshot().now_playing.playing
        assert display.core.snapshot().now_playing.title == ""
        assert display.core.snapshot().now_playing.artist == ""

    def test_replaying_ack_for_the_followed_appliance_polls_at_once(self):
        display = self._display(state="hold", accepted=False)
        display.core.request_poll = MagicMock()
        on_repeat_result(display,
            "transport", self.AID, 200, {"ok": True, "state": "replaying", "armed": False, "position_seconds": 0.0},
        )
        display.core.request_poll.assert_called_once()
        assert display.core.snapshot().focus.accepted_replay[0] == self.AID
        targets = display._core.with_accepted_replay([], time.monotonic())
        assert [t.appliance_id for t in targets] == [self.AID]

    def test_accepted_replay_window_survives_a_consistent_immediate_poll(self):
        import dial_repeat_store as drs
        display = self._display(state="hold", accepted=False)
        display.core.request_poll = MagicMock()
        on_repeat_result(display,
            "transport", self.AID, 200, {"ok": True, "state": "replaying", "armed": False, "position_seconds": 0.0},
        )
        now = time.monotonic()
        replaying = _repeat_obj(
            state="replaying", held=False,
            replay={"active": True, "position_seconds": 0.0, "duration_seconds": 30.0},
        )
        dial_core_poll.apply_status_to_repeat(self.AID, {"repeat": replaying, "status_error": None}, now)
        assert drs.repeat_store.get(self.AID, now).state == "replaying"
        targets = display._core.with_accepted_replay([], now)
        assert [t.appliance_id for t in targets] == [self.AID]
        assert display.core.snapshot().focus.accepted_replay is not None

    def test_ack_for_another_appliance_does_not_poll(self):
        display = self._display(state="hold", focus=False, accepted=False)
        display.core.request_poll = MagicMock()
        on_repeat_result(display,
            "transport", self.AID, 200, {"ok": True, "state": "replaying", "armed": False, "position_seconds": 0.0},
        )
        display.core.request_poll.assert_not_called()
        assert display.core.snapshot().focus.accepted_replay is None


# ---------------------------------------------------------------------------
# on_repeat_result: the worker-thread callback wired to dial_repeat.py.
# ---------------------------------------------------------------------------

class TestOnRepeatResult:
    def test_412_forces_due_and_requests_poll_never_touches_auth(self):
        aid = "2" * 20
        display, fb, gt = make_display(targets=[])
        display._core._poll_wake.clear()
        display._core._reconcile_due = False
        with patch("dial_auth.auth_map.force_due") as mock_force_due, \
             patch("dial_auth.auth_map.apply") as mock_apply:
            on_repeat_result(display, "transport", aid, 412, {"ok": False, "error": "dial_not_authorized"})
        mock_force_due.assert_called_once_with(aid)
        mock_apply.assert_not_called()
        assert display._core._poll_wake.is_set()
        assert display._core._reconcile_due is True
    def test_ok_false_source_active_clears_the_record(self):
        import dial_repeat_store as drs
        aid = "3" * 20
        display, fb, gt = make_display(targets=[])
        now = time.monotonic()
        drs.repeat_store.update(aid, drs.parse_repeat_object(_repeat_obj(state="hold"), now))

        on_repeat_result(display, "transport", aid, 200, {"ok": False, "error": "source_active"})
        assert drs.repeat_store.get(aid, time.monotonic()) is None
    def test_ok_false_no_recording_clears_the_record(self):
        import dial_repeat_store as drs
        aid = "4" * 20
        display, fb, gt = make_display(targets=[])
        now = time.monotonic()
        drs.repeat_store.update(aid, drs.parse_repeat_object(_repeat_obj(state="hold"), now))

        on_repeat_result(display, "transport", aid, 200, {"ok": False, "error": "no_recording"})
        assert drs.repeat_store.get(aid, time.monotonic()) is None
    def test_ok_false_other_error_leaves_the_record(self):
        import dial_repeat_store as drs
        aid = "5" * 20
        display, fb, gt = make_display(targets=[])
        now = time.monotonic()
        rec = drs.parse_repeat_object(_repeat_obj(state="hold"), now)
        drs.repeat_store.update(aid, rec)

        on_repeat_result(display, "transport", aid, 200, {"ok": False, "error": "fading_out"})
        assert drs.repeat_store.get(aid, time.monotonic()) == rec
    def test_transient_status_none_nudges_only_no_store_change(self):
        import dial_repeat_store as drs
        aid = "6" * 20
        display, fb, gt = make_display(targets=[])
        now = time.monotonic()
        rec = drs.parse_repeat_object(_repeat_obj(state="hold"), now)
        drs.repeat_store.update(aid, rec)

        with patch("dial_auth.auth_map.force_due") as mock_force_due:
            on_repeat_result(display, "transport", aid, None, None)
        mock_force_due.assert_called_once_with(aid)
        assert drs.repeat_store.get(aid, time.monotonic()) == rec
    def test_transient_other_http_code_nudges_only(self):
        aid = "7" * 20
        display, fb, gt = make_display(targets=[])
        with patch("dial_auth.auth_map.force_due") as mock_force_due:
            on_repeat_result(display, "transport", aid, 500, None)
        mock_force_due.assert_called_once_with(aid)
