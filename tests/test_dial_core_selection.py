"""Tests for what the dial core publishes from a poll: the mute state it
observes from the status poll, the now-playing line and the artwork source it
picks, and its refusal of an appliance that does not speak the typed dialect.

Each test drives a poll through a display (the core's only consumer here) and
reads the core's snapshot and methods.
"""

from __future__ import annotations

import dataclasses
import logging
from unittest.mock import ANY, call, patch

import pytest

Image = pytest.importorskip("PIL.Image", reason="Pillow not installed")

from dial_test_support import (
    _status_result,
    _target,
    _track_id,
    make_display,
)

import dial_auth
import dial_core_poll
from dial_config import DialDisplayConfig
from dial_core_state import NowPlaying


# ---------------------------------------------------------------------------
# dial mute belief: free reconciliation from the status poll.
# master_volume > 0 seen on ANY target during this poll is definitive proof
# the fleet is audible;
# master_volume == 0 proves nothing about the rest of the fleet and must
# never be used to force the belief to muted.
# ---------------------------------------------------------------------------

class TestMuteObservationFromStatusPoll:
    """The poll observes the reported `muted` flag into dial_volume's
    per-service observation store for every target it actually walked, not
    only the reporting-from one -- it never infers mute from a volume. Each
    target has its own entry, so one target's flag can never leak into
    another's; the glyph itself still reads back only the reporting/bound
    service's entry (see TestEffectiveOverlayMerge), unaffected by what else
    the store now holds (see dial_volume.observe_mute_state/shown_muted)."""

    def test_muted_field_observed_for_the_reporting_target(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with patch("dial_core.fetch_target_status",
                   return_value=_status_result(track_id=None, muted=True)), \
             patch("dial_core.observe_mute_state") as mock_observe:
            display._poll_once()
        mock_observe.assert_called_once_with(t.service_name, True, requested_at=ANY, status_reports_mute=False)

    def test_unmuted_field_observed_as_false(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with patch("dial_core.fetch_target_status",
                   return_value=_status_result(track_id=None, muted=False)), \
             patch("dial_core.observe_mute_state") as mock_observe:
            display._poll_once()
        mock_observe.assert_called_once_with(t.service_name, False, requested_at=ANY, status_reports_mute=False)

    def test_status_error_response_observes_none(self):
        """A status_error response is never stored in the poll's `records`
        map, so the reporting target's muted observation is None (unknown)
        -- never left stale from a previous successful poll's inference,
        and never a guess."""
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with patch("dial_core.fetch_target_status",
                   return_value=_status_result(status_error="timeout")), \
             patch("dial_core.observe_mute_state") as mock_observe:
            display._poll_once()
        mock_observe.assert_called_once_with(t.service_name, None, requested_at=ANY, status_reports_mute=False)

    def test_muted_on_every_walked_target_is_observed(self):
        """Two targets, neither identified: the walk visits both before
        falling back to the oldest-playing (first) one as reporting-from --
        both targets' muted flags reach the (per-service) observation store,
        each in its own entry, not only the reporting one."""
        t_reporting = _target(name="Older", service_name="older", playing_since=10.0)
        t_other = _target(name="Newer", service_name="newer", playing_since=20.0)
        display, fb, gt = make_display(targets=[t_reporting, t_other])
        display.enable()

        def fake_fetch(target, dial_id, timeout_seconds):
            return _status_result(track_id=None, muted=(target.service_name != "older"))

        with patch("dial_core.fetch_target_status", side_effect=fake_fetch), \
             patch("dial_core.observe_mute_state") as mock_observe:
            display._poll_once()
        mock_observe.assert_any_call("older", False, requested_at=ANY, status_reports_mute=False)
        mock_observe.assert_any_call("newer", True, requested_at=ANY, status_reports_mute=False)
        assert mock_observe.call_count == 2

    def test_fallback_reporting_target_is_oldest_when_nothing_identified(self):
        """With nothing identified, the reporting-from target is
        select_volume_target()'s fallback: targets[0], the oldest-playing
        one — not whichever target the loop happens to process last."""
        t_older = _target(name="Older", service_name="older", playing_since=10.0)
        t_newer = _target(name="Newer", service_name="newer", playing_since=20.0)
        display, fb, gt = make_display(targets=[t_older, t_newer])
        display.enable()

        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None)), \
             patch("dial_core.observe_master_volume") as mock_observe:
            display._poll_once()

        assert mock_observe.call_args[0][0] == "older"

    def test_forget_mute_states_except_called_with_current_playing_targets(self):
        """Each poll tick prunes the per-service store down to the targets
        actually playing this tick, so a target that has since stopped does
        not accumulate a stale entry forever."""
        t_a = _target(name="A", service_name="svc-a", playing_since=10.0)
        t_b = _target(name="B", service_name="svc-b", playing_since=20.0)
        display, fb, gt = make_display(targets=[t_a, t_b])
        display.enable()
        with patch("dial_core.fetch_target_status",
                   return_value=_status_result(track_id=None, muted=False)), \
             patch("dial_core.forget_mute_states_except") as mock_forget:
            display._poll_once()
        mock_forget.assert_called_once()
        assert set(mock_forget.call_args[0][0]) == {"svc-a", "svc-b"}

    def test_muted_flag_actually_reaches_the_real_observation_store(self):
        """End-to-end against the real dial_volume module (not a mock of
        observe_mute_state) — proves the two modules are actually wired
        together, not just that dial_display calls a same-named stub."""
        import dial_volume as dv
        dv.observe_mute_state(None, None)
        try:
            t = _target()
            display, fb, gt = make_display(targets=[t])
            display.enable()
            with patch("dial_core.fetch_target_status",
                       return_value=_status_result(track_id=None, muted=True)):
                display._poll_once()
            assert dv.shown_muted(t.service_name) is True
        finally:
            dv.observe_mute_state(None, None)

    def test_failed_status_fetch_does_not_flip_a_known_mute_to_unmuted(self):
        """A poll whose status fetch failed records unknown; against the real
        store that must leave a previously confirmed mute showing."""
        import dial_volume as dv
        dv.observe_mute_state(None, None)
        try:
            t = _target(dial_proto_version=2)
            display, fb, gt = make_display(targets=[t])
            display.enable()
            with patch("dial_core.fetch_target_status",
                       return_value=_status_result(track_id=None, muted=True)):
                display._poll_once()
            assert dv.shown_muted(t.service_name) is True
            with patch("dial_core.fetch_target_status",
                       return_value=_status_result(status_error="timeout")):
                display._poll_once()
            assert dv.shown_muted(t.service_name) is True
        finally:
            dv.observe_mute_state(None, None)

    def test_v2_target_is_observed_as_reporting_mute(self):
        t = _target(dial_proto_version=2)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with patch("dial_core.fetch_target_status",
                   return_value=_status_result(track_id=None, muted=True)), \
             patch("dial_core.observe_mute_state") as mock_observe:
            display._poll_once()
        mock_observe.assert_called_once_with(t.service_name, True, requested_at=ANY, status_reports_mute=True)

    def test_status_without_muted_clears_a_legacy_targets_mute_once_settled(self):
        """An earlier-release appliance never reports the flag, so a mute
        reply must not latch the highlight on past the next poll."""
        import dial_volume as dv
        dv.observe_mute_state(None, None)
        try:
            t = _target()
            display, fb, gt = make_display(targets=[t])
            display.enable()
            dv.observe_mute_state(t.service_name, True)      # a mute reply
            with patch("dial_core.fetch_target_status",
                       return_value=_status_result(track_id=None, muted=None)):
                display._poll_once()
            assert dv.shown_muted(t.service_name) is False
        finally:
            dv.observe_mute_state(None, None)

    def test_status_without_muted_keeps_a_v2_targets_mute(self):
        import dial_volume as dv
        dv.observe_mute_state(None, None)
        try:
            t = _target(dial_proto_version=2)
            display, fb, gt = make_display(targets=[t])
            display.enable()
            dv.observe_mute_state(t.service_name, True)
            with patch("dial_core.fetch_target_status",
                       return_value=_status_result(track_id=None, muted=None)):
                display._poll_once()
            assert dv.shown_muted(t.service_name) is True
        finally:
            dv.observe_mute_state(None, None)

    def test_requested_at_is_the_time_the_status_request_was_sent(self):
        """The observation carries the monotonic time taken just before the
        fetch, not a time taken after it returned."""
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        clock = {"now": 100.0}

        def fake_fetch(target, dial_id, timeout_seconds):
            clock["now"] = 105.0      # the reply arrives later
            return _status_result(track_id=None, muted=True)

        with patch("dial_core.fetch_target_status", side_effect=fake_fetch), \
             patch("dial_display.time.monotonic", side_effect=lambda: clock["now"]), \
             patch("dial_core.observe_mute_state") as mock_observe:
            display._poll_once()
        mock_observe.assert_called_once_with(t.service_name, True, requested_at=100.0, status_reports_mute=False)


# ---------------------------------------------------------------------------
# NowPlaying's album field: defaulted and appended last, so every existing
# positional construction (display code and tests alike) keeps working
# unchanged, and an album-only difference still counts for the `!=` check
# _poll_once uses to decide whether to repaint.
# ---------------------------------------------------------------------------

class TestNowPlayingDataclass:
    def test_positional_construction_without_album_still_works(self):
        now_playing = NowPlaying("svc", "A", "T", 50)
        assert now_playing.album == ""

    def test_album_only_difference_is_unequal(self):
        assert NowPlaying("svc", "A", "T", 50, album="X") != NowPlaying("svc", "A", "T", 50)

    def test_same_album_is_equal(self):
        assert NowPlaying("svc", "A", "T", 50, album="X") == NowPlaying("svc", "A", "T", 50, album="X")

    def test_playing_defaults_to_true(self):
        assert NowPlaying("svc", "A", "T", 50).playing is True

    def test_playing_only_difference_is_unequal(self):
        # What triggers a repaint on a focused appliance starting or
        # stopping, even when every other field stays the same.
        assert NowPlaying("svc", "", "", 50, playing=False) != NowPlaying("svc", "", "", 50, playing=True)


# ---------------------------------------------------------------------------
# Now-playing state and artwork-source exposure: the core keeps the
# title/artist/master_volume of the reporting appliance, and exposes the
# chosen artwork source's service name so the volume worker's resolver can
# address it (see dial_main._build_volume_targets_fn).
# ---------------------------------------------------------------------------

class TestNowPlayingAndSource:
    def test_identified_target_sets_source_and_now_playing(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with patch("dial_core.fetch_target_status",
                   return_value=_status_result(track_id=_track_id(artist="The Artist"))), \
             patch("dial_core.observe_master_volume") as mock_observe:
            display._poll_once()

        assert display.core.current_source_service_name() == t.service_name
        assert display.core.snapshot().now_playing is not None
        assert display.core.snapshot().now_playing.artist == "The Artist"
        assert display.core.snapshot().now_playing.album == "Album"
        assert display.core.snapshot().now_playing.service_name == t.service_name
        # The reporting target's master_volume (from _status_result's
        # default of 50) reaches observe_master_volume.
        mock_observe.assert_called_once_with(t.service_name, 50)
    def test_identified_target_without_album_gives_empty_string(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with patch("dial_core.fetch_target_status",
                   return_value=_status_result(track_id=_track_id(album=""))):
            display._poll_once()
        assert display.core.snapshot().now_playing.album == ""
    def test_non_identified_target_gives_empty_album(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with patch("dial_core.fetch_target_status",
                   return_value=_status_result(track_id=_track_id(state="pending"))):
            display._poll_once()
        assert display.core.snapshot().now_playing.album == ""
    def test_no_targets_clears_source_and_now_playing(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=_track_id())):
            display._poll_once()
        assert display.core.current_source_service_name() is not None

        gt.return_value = []
        with patch("dial_core.observe_master_volume") as mock_observe:
            display._poll_once()

        assert display.core.current_source_service_name() is None
        assert display.core.snapshot().now_playing is None
        mock_observe.assert_called_once_with(None, None)
    def test_not_fitted_clears_source_and_now_playing(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=_track_id())):
            display._poll_once()
        assert display.core.current_source_service_name() is not None

        display.update_config(DialDisplayConfig(fitted=False))
        display._poll_once()

        assert display.core.current_source_service_name() is None
        assert display.core.snapshot().now_playing is None


# ---------------------------------------------------------------------------
# Refusal from an appliance that does not speak the typed dialect
# ---------------------------------------------------------------------------

class TestUntypedRefusal:
    def _refusal(self):
        result = _status_result(status_error="unauthorized", appliance_id=None)
        result["untyped_refusal"] = True
        return result

    def test_refusal_without_body_id_applies_to_the_resolved_id(self):
        aid = "4" * 20
        t = _target(name="Hall", service_name="Hall", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        assert dial_core_poll.apply_status_to_auth(t, self._refusal()) is True
        assert dial_auth.auth_map.state(aid) == dial_auth.AUTH_UNAUTHORIZED

    def test_refusal_for_an_unresolved_target_changes_nothing(self):
        t = _target(name="Hall", service_name="Hall", appliance_id="")
        display, fb, gt = make_display(targets=[t])
        assert dial_core_poll.apply_status_to_auth(t, self._refusal()) is False

    def test_earlier_dialect_success_without_body_id_authorizes_again(self):
        aid = "7" * 20
        t = _target(name="Hall", service_name="Hall", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        dial_core_poll.apply_status_to_auth(t, self._refusal())
        assert dial_auth.auth_map.state(aid) == dial_auth.AUTH_UNAUTHORIZED
        ok = _status_result(track_id=_track_id(), appliance_id=None)
        assert dial_core_poll.apply_status_to_auth(t, ok) is True
        assert dial_auth.auth_map.state(aid) == dial_auth.AUTH_AUTHORIZED

    def test_newer_dialect_success_without_body_id_stays_uncorrelated(self):
        aid = "8" * 20
        t = dataclasses.replace(
            _target(name="Hall", service_name="Hall", appliance_id=aid), dial_proto_version=2,
        )
        display, fb, gt = make_display(targets=[t])
        ok = _status_result(track_id=_track_id(), appliance_id=None)
        assert dial_core_poll.apply_status_to_auth(t, ok) is False
        assert dial_auth.auth_map.state(aid) == dial_auth.AUTH_UNKNOWN

    def test_refused_appliance_starting_to_play_is_rechecked_at_once(self):
        aid = "9" * 20
        refused = _target(name="Hall", service_name="Hall", appliance_id=aid, auth="unauthorized")
        display, fb, gt = make_display(targets=[refused])
        display.enable()
        with patch("dial_auth.auth_map.force_due") as force_due, \
                patch("dial_core.fetch_target_status", return_value=_status_result()):
            display._poll_once()
        force_due.assert_any_call(aid)
        assert display._core._reconcile_due or display._core._last_reconcile_at > 0

    def test_refused_appliance_already_playing_is_not_rechecked_every_tick(self):
        aid = "9" * 20
        refused = _target(name="Hall", service_name="Hall", appliance_id=aid, auth="unauthorized")
        display, fb, gt = make_display(targets=[refused])
        display.enable()
        display._core._prev_playing_ids = {aid}
        with patch("dial_auth.auth_map.force_due") as force_due, \
                patch("dial_core.fetch_target_status", return_value=_status_result()):
            display._poll_once()
        assert call(aid) not in force_due.call_args_list

    def test_unchecked_appliance_that_refuses_is_never_shown_on_first_sight(self):
        aid = "a1" * 10
        t = _target(name="Hall", service_name="Hall", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with patch("dial_core.fetch_target_status", return_value=self._refusal()) as fetch:
            display._poll_once()
        assert fetch.call_count == 1
        assert dial_auth.auth_map.state(aid) == dial_auth.AUTH_UNAUTHORIZED
        assert display.core.snapshot().focus.reporting_id is None
        assert display.core.snapshot().now_playing is None

    def test_unchecked_appliance_that_accepts_is_shown_with_one_request(self):
        aid = "b2" * 10
        t = _target(name="Hall", service_name="Hall", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        ok = _status_result(track_id=_track_id(), appliance_id=None)
        with patch("dial_core.fetch_target_status", return_value=ok) as fetch:
            display._poll_once()
        assert fetch.call_count == 1
        assert display.core.snapshot().focus.reporting_id == aid
        assert display.core.snapshot().now_playing is not None and display.core.snapshot().now_playing.playing

    def test_plain_unauthorized_without_body_id_is_still_uncorrelated(self):
        aid = "4" * 20
        t = _target(name="Hall", service_name="Hall", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        result = _status_result(status_error="unauthorized", appliance_id=None)
        assert dial_core_poll.apply_status_to_auth(t, result) is False
        assert dial_auth.auth_map.state(aid) == dial_auth.AUTH_UNKNOWN

    def test_first_refusal_logs_one_warning_then_silent(self, caplog):
        aid = "5" * 20
        t = _target(name="Hall", service_name="Hall", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        with caplog.at_level(logging.WARNING):
            for _ in range(3):
                dial_core_poll.apply_status_to_auth(t, self._refusal())
        warnings = [r for r in caplog.records if "refused this dial" in r.getMessage()]
        assert len(warnings) == 1
        assert "Hall" in warnings[0].getMessage()
        assert "web UI" in warnings[0].getMessage()

    def test_refusal_after_authorization_logs_again(self, caplog):
        aid = "6" * 20
        t = _target(name="Hall", service_name="Hall", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        ok = _status_result(track_id=_track_id(), appliance_id=aid)
        with caplog.at_level(logging.WARNING):
            dial_core_poll.apply_status_to_auth(t, self._refusal())
            dial_core_poll.apply_status_to_auth(t, ok)
            dial_core_poll.apply_status_to_auth(t, self._refusal())
        warnings = [r for r in caplog.records if "refused this dial" in r.getMessage()]
        assert len(warnings) == 2

    def test_typed_refusal_also_logs_once(self, caplog):
        aid = "7" * 20
        t = _target(name="Hall", service_name="Hall", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        typed = _status_result(status_error="unauthorized", appliance_id=aid)
        with caplog.at_level(logging.WARNING):
            dial_core_poll.apply_status_to_auth(t, typed)
            dial_core_poll.apply_status_to_auth(t, typed)
        assert len([r for r in caplog.records if "refused this dial" in r.getMessage()]) == 1
