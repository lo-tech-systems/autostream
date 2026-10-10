"""Tests for the dial core's poll mechanics: how a poll applies auth, feeds the
repeat store, probes pushed auth changes, reconciles the roster, and decides
the idle affordance and the outputs and EQ availability that the snapshot
carries.

Each test drives the core through a display (its only consumer here) and reads
the core's snapshot and methods.
"""

from __future__ import annotations

import dataclasses
import time
from unittest.mock import patch

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
    patch_monotonic,
)

import dial_auth
import dial_display as dd


def _make_eq_display(dial_eq=True, auth="unknown", appliance_id="a" * 20):
    display, fb, gt = make_display(targets=[])
    display.core.set_field("reporting_id", appliance_id)
    display.core.set_roster([_roster_entry(appliance_id=appliance_id, auth=auth, dial_eq=dial_eq)])
    display._core._update_availability(time.monotonic())
    return display


# ---------------------------------------------------------------------------
# Per-appliance status fields in the snapshot
# ---------------------------------------------------------------------------

class TestApplianceStatusFields:
    def _two(self):
        t1 = _target(name="First", service_name="First", appliance_id="1" * 20, playing_since=1.0)
        t2 = _target(name="Second", service_name="Second", appliance_id="2" * 20, playing_since=2.0)
        return make_display(targets=[t1, t2])

    def _by_id(self, display):
        return {a.appliance_id: a for a in display.core.snapshot().appliances}

    def test_a_good_reply_folds_volume_and_mute_and_no_error(self):
        display, fb, gt = self._two()
        display.enable()
        result = _status_result(track_id=_track_id(), muted=True)
        with patch("dial_display.fetch_target_status", return_value=result):
            display._poll_once()
        first = self._by_id(display)["1" * 20]
        assert (first.status_error, first.master_volume, first.muted) == (None, 50, True)

    def test_a_failed_fetch_records_the_error(self):
        display, fb, gt = self._two()
        display.enable()
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(status_error="timeout")):
            display._poll_once()
        first = self._by_id(display)["1" * 20]
        assert first.status_error == "timeout"
        assert first.master_volume is None and first.muted is None

    def test_an_appliance_not_asked_this_tick_shows_none(self):
        display, fb, gt = self._two()
        display.enable()
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=_track_id())) as fetch:
            display._poll_once()
        # The walk stops at the first target that identifies a track.
        assert fetch.call_count == 1
        asked = [a for a in self._by_id(display).values() if a.master_volume is not None]
        silent = [a for a in self._by_id(display).values() if a.master_volume is None]
        assert len(asked) == 1 and len(silent) == 1
        assert (silent[0].status_error, silent[0].muted) == (None, None)

    def test_the_next_tick_replaces_the_last_ones_readings(self):
        display, fb, gt = self._two()
        display.enable()
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(status_error="timeout")):
            display._poll_once()
        assert any(a.status_error == "timeout" for a in self._by_id(display).values())
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=_track_id())):
            display._poll_once()
        assert all(a.status_error is None for a in self._by_id(display).values())

    def test_the_readings_survive_a_roster_change_between_ticks(self):
        display, fb, gt = self._two()
        display.enable()
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=_track_id(), muted=True)):
            display._poll_once()
        display.core.set_roster(display.core.roster() + [_roster_entry(name="Third", appliance_id="3" * 20)])
        assert any(a.muted is True for a in self._by_id(display).values())

    def test_publish_tick_takes_the_statuses_it_is_given(self):
        display, fb, gt = make_display(targets=[])
        display.core.set_roster([_roster_entry(name="First", appliance_id="1" * 20)])
        display.core.publish_tick(polling=True, statuses={"1" * 20: ("boom", None, None)})
        assert self._by_id(display)["1" * 20].status_error == "boom"
        display.core.publish_tick(polling=True)
        assert self._by_id(display)["1" * 20].status_error == "boom"
        display.core.publish_tick(polling=True, statuses={})
        assert self._by_id(display)["1" * 20].status_error is None


# ---------------------------------------------------------------------------
# Auth application during the sequential poll walk
# ---------------------------------------------------------------------------

class TestAuthApplicationDuringPoll:
    def test_412_matching_id_marks_unauthorized_and_moves_to_next_target_on_next_poll(self):
        aid = "1" * 20
        t1 = _target(name="First", service_name="First", appliance_id=aid, playing_since=1.0)
        t2 = _target(name="Second", service_name="Second", playing_since=2.0)
        display, fb, gt = make_display(targets=[t1, t2])
        display.enable()
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(status_error="unauthorized", appliance_id=aid)):
            display._poll_once()
        assert dial_auth.auth_map.state(aid) == dial_auth.AUTH_UNAUTHORIZED

        # Next poll: as a real get_display_targets() would, the row now
        # comes back stamped unauthorized (this fixture's get_targets is a
        # bare mock, so simulate that re-stamp explicitly) and is skipped
        # outright — no fetch at all; the source moves to the next
        # controllable target.
        gt.return_value = [dataclasses.replace(t1, auth="unauthorized"), t2]
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=_track_id())) as mock_fetch:
            display._poll_once()
        mock_fetch.assert_called_once()
        assert mock_fetch.call_args[0][0] is t2
        assert display.core.snapshot().focus.source_service_name == "Second"

    def test_200_with_mismatched_appliance_id_leaves_map_unchanged(self):
        aid = "2" * 20
        other_id = "3" * 20
        t = _target(appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=_track_id(), appliance_id=other_id)):
            display._poll_once()
        assert dial_auth.auth_map.state(aid) == dial_auth.AUTH_UNKNOWN


# ---------------------------------------------------------------------------
# Reconcile pass: concurrent fan-out over rows the sequential walk skipped.
# ---------------------------------------------------------------------------

class TestReconcilePass:
    def test_runs_first_tick_then_not_again_within_interval_then_again(self):
        aid1, aid2 = "4" * 20, "5" * 20
        t1 = _target(name="One", service_name="One", appliance_id=aid1, playing_since=10.0)
        t2 = _target(name="Two", service_name="Two", appliance_id=aid2, playing_since=20.0)
        display, fb, gt = make_display(targets=[t1, t2])
        display.enable()
        clock = _FakeClock()

        def fake_enrich(targets, dial_id):
            return []

        with patch_monotonic(clock), \
             patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display.enrich_targets", side_effect=fake_enrich) as mock_enrich:
            display._poll_once()  # sequential walk visits t1 only (breaks on its artwork)
        assert mock_enrich.call_count == 1
        pending_arg = mock_enrich.call_args[0][0]
        assert [t.service_name for t in pending_arg] == ["Two"]

        with patch_monotonic(clock), \
             patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display.enrich_targets", side_effect=fake_enrich) as mock_enrich2:
            display._poll_once()  # same instant: within the 60s interval
        mock_enrich2.assert_not_called()

        clock.t += dd.RECONCILE_INTERVAL_SECONDS
        with patch_monotonic(clock), \
             patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display.enrich_targets", side_effect=fake_enrich) as mock_enrich3:
            display._poll_once()
        mock_enrich3.assert_called_once()

    def test_only_probes_rows_not_visited_and_due(self):
        aid1, aid2, aid3 = "6" * 20, "7" * 20, "8" * 20
        t1 = _target(name="One", service_name="One", appliance_id=aid1, playing_since=1.0)
        t2 = _target(name="Two", service_name="Two", appliance_id=aid2, playing_since=2.0)
        t3 = _target(name="Three", service_name="Three", appliance_id=aid3, playing_since=3.0)
        display, fb, gt = make_display(targets=[t1, t2, t3])
        display.enable()
        clock = _FakeClock(start=1000.0)
        # t2 is freshly on backoff (not due again until 1000 + 30s); t3 has
        # no entry yet, which is always due.
        dial_auth.auth_map.apply(aid2, dial_auth.OUTCOME_UNAUTHORIZED, aid2, clock.t)

        with patch_monotonic(clock), \
             patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display.enrich_targets", return_value=[]) as mock_enrich:
            display._poll_once()
        pending_arg = mock_enrich.call_args[0][0]
        assert [t.service_name for t in pending_arg] == ["Three"]

    def test_applies_enrich_records_to_the_auth_map(self):
        aid = "9" * 20
        t1 = _target(name="One", service_name="One", playing_since=1.0)
        t2 = _target(name="Two", service_name="Two", appliance_id=aid, playing_since=2.0)
        display, fb, gt = make_display(targets=[t1, t2])
        display.enable()

        def fake_enrich(targets, dial_id):
            return [
                {"name": "Two", "status_error": "unauthorized", "appliance_id": aid},
            ]

        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display.enrich_targets", side_effect=fake_enrich):
            display._poll_once()
        assert dial_auth.auth_map.state(aid) == dial_auth.AUTH_UNAUTHORIZED


# ---------------------------------------------------------------------------
# dial_repeat_store fed from both poll paths.
# ---------------------------------------------------------------------------

class TestRepeatStoreFeed:
    def _repeat_obj(self, **overrides) -> dict:
        base = {
            "available": True, "state": "hold", "armed": False, "held": True,
            "recording_seconds": 30.0,
            "replay": {"active": False, "position_seconds": 0.0, "duration_seconds": 30.0},
        }
        base.update(overrides)
        return base

    def test_artwork_walk_feeds_the_store_for_the_reporting_target(self):
        import dial_repeat_store as drs
        aid = "1" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        result = _status_result(track_id=None, appliance_id=aid)
        result["repeat"] = self._repeat_obj()

        with patch("dial_display.fetch_target_status", return_value=result):
            display._poll_once()

        rec = drs.repeat_store.get(aid, now=time.monotonic())
        assert rec is not None
        assert rec.state == "hold"
        assert rec.recording_seconds == 30.0

    def test_confirmed_unauthorized_clears_the_stored_record(self):
        import dial_repeat_store as drs
        aid = "2" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        drs.repeat_store.update(aid, drs.parse_repeat_object(self._repeat_obj(), now=time.monotonic()))

        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(status_error="unauthorized", appliance_id=aid)):
            display._poll_once()

        assert drs.repeat_store.get(aid, now=time.monotonic()) is None

    def test_transient_error_leaves_the_stored_record_untouched(self):
        import dial_repeat_store as drs
        aid = "3" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        rec = drs.parse_repeat_object(self._repeat_obj(), now=time.monotonic())
        drs.repeat_store.update(aid, rec)

        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(status_error="timeout")):
            display._poll_once()

        assert drs.repeat_store.get(aid, now=time.monotonic()) == rec

    def test_reconcile_pass_feeds_the_store_for_idle_roster_rows_only(self):
        """An idle (non-playing) roster row is reconciled through
        enrich_targets — feeding the repeat store — but is never walked for
        artwork and never sets _now_playing; that stays exclusively the
        playing target's job."""
        import dial_repeat_store as drs
        from dial_mdns import RosterEntry

        aid_playing = "4" * 20
        aid_idle = "5" * 20
        t1 = _target(name="Playing", service_name="Playing",
                      appliance_id=aid_playing, playing_since=1.0)

        def get_roster():
            return [
                RosterEntry(
                    appliance_id=aid_playing, service_name="Playing", name="Playing",
                    ip=t1.ip, port=t1.port, playing=True, repeat_capable=False,
                    dial_api=True, audio_status=True, dial_status=True, auth="unknown",
                ),
                RosterEntry(
                    appliance_id=aid_idle, service_name="Idle", name="Idle",
                    ip="10.0.0.9", port=9999, playing=False, repeat_capable=True,
                ),
            ]

        display, fb, gt = make_display(targets=[t1], get_roster=get_roster)
        display.enable()

        idle_repeat_obj = self._repeat_obj(state="replaying", armed=True,
                                            replay={"active": True, "position_seconds": 1.0,
                                                    "duration_seconds": 5.0})

        def fake_enrich(targets, dial_id):
            assert [t.service_name for t in targets] == ["Idle"]
            return [{
                "name": "Idle", "status_error": None, "appliance_id": aid_idle,
                "repeat": idle_repeat_obj,
            }]

        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=_track_id(), appliance_id=aid_playing)), \
             patch("dial_display.enrich_targets", side_effect=fake_enrich):
            display._poll_once()

        idle_rec = drs.repeat_store.get(aid_idle, now=time.monotonic())
        assert idle_rec is not None
        assert idle_rec.state == "replaying"
        # The idle row never became the artwork base or the reporting target.
        assert display.core.snapshot().now_playing is not None
        assert display.core.snapshot().now_playing.service_name == "Playing"
        assert display.core.snapshot().focus.source_service_name == "Playing"

    def test_reconcile_pass_stamps_observed_at_after_the_fetch_returns(self):
        """The fan-out blocks for up to its own deadline; a record stamped
        with the time before it started would interpolate ahead of the
        truth by that much."""
        import dial_repeat_store as drs
        from dial_mdns import RosterEntry

        aid_playing = "8" * 20
        aid_idle = "9" * 20
        t1 = _target(name="Playing", service_name="Playing", appliance_id=aid_playing, playing_since=1.0)

        def get_roster():
            return [
                RosterEntry(
                    appliance_id=aid_playing, service_name="Playing", name="Playing",
                    ip=t1.ip, port=t1.port, playing=True, repeat_capable=False,
                    dial_api=True, audio_status=True, dial_status=True, auth="unknown",
                ),
                RosterEntry(
                    appliance_id=aid_idle, service_name="Idle", name="Idle",
                    ip="10.0.0.9", port=9999, playing=False, repeat_capable=True,
                ),
            ]

        display, fb, gt = make_display(targets=[t1], get_roster=get_roster)
        display.enable()
        clock = _FakeClock(1000.0)
        fan_out_s = 1.2

        def fake_enrich(targets, dial_id):
            clock.t += fan_out_s                     # the fetch takes this long
            return [{
                "name": "Idle", "status_error": None, "appliance_id": aid_idle,
                "repeat": self._repeat_obj(
                    state="replaying", armed=True,
                    replay={"active": True, "position_seconds": 10.0, "duration_seconds": 30.0},
                ),
            }]

        with patch_monotonic(clock), \
             patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=_track_id(), appliance_id=aid_playing)), \
             patch("dial_display.enrich_targets", side_effect=fake_enrich):
            display._poll_once()

        rec = drs.repeat_store.get(aid_idle, now=clock.t)
        assert rec is not None
        assert rec.observed_at == pytest.approx(clock.t)              # after the fan-out
        assert rec.observed_at >= 1000.0 + fan_out_s
        # Consequence: the interpolation reads the sampled position, not
        # position plus the fan-out time.
        assert dd._interpolate_repeat_position(rec, clock.t) == pytest.approx(10.0)

    def test_reconcile_pass_prunes_ids_not_in_the_roster(self):
        import dial_repeat_store as drs
        aid_gone = "6" * 20
        drs.repeat_store.update(aid_gone, drs.parse_repeat_object(self._repeat_obj(), now=time.monotonic()))
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id="7" * 20, playing_since=1.0)
        display, fb, gt = make_display(targets=[t])
        display.enable()

        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())):
            display._poll_once()

        assert drs.repeat_store.get(aid_gone, now=time.monotonic()) is None


# ---------------------------------------------------------------------------
# Push probes and the poll loop's sleep gate.
# ---------------------------------------------------------------------------

class TestPushProbes:
    def test_notify_auth_changed_sets_poll_wake(self):
        display, fb, gt = make_display(targets=[])
        assert not display._core._poll_wake.is_set()
        display.notify_auth_changed("a" * 20)
        assert display._core._poll_wake.is_set()
    def test_drain_push_probes_only_probes_rostered_ids(self):
        aid = "c" * 20
        t = _target(appliance_id=aid, service_name="Kit")
        display, fb, gt = make_display(targets=[t])
        display.notify_auth_changed(aid)
        display.notify_auth_changed("d" * 20)  # not rostered: skipped, no fetch
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(appliance_id=aid, track_id=None)) as mock_fetch:
            result = display._core._drain_push_probes()
        mock_fetch.assert_called_once()
        assert mock_fetch.call_args[0][0] is t
        assert result == "probed"
    def test_drain_push_probes_is_noop_with_nothing_pending(self):
        display, fb, gt = make_display(targets=[])
        with patch("dial_display.fetch_target_status") as mock_fetch:
            result = display._core._drain_push_probes()
        mock_fetch.assert_not_called()
        assert result == ""


# ---------------------------------------------------------------------------
# Playing-set shrink: a source that stops playing forces an immediate
# reconcile so its retained recording reaches the idle screen and picker.
# ---------------------------------------------------------------------------

class TestReconcileOnPlayingSetShrink:
    def test_shrinking_playing_set_forces_reconcile(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display._core._prev_playing_ids = {"a" * 20}
        display._core._reconcile_due = False
        display._core._last_reconcile_at = time.monotonic()  # cadence alone would NOT fire
        gt.return_value = []  # the source that was playing has stopped
        with patch("dial_core_poll.reconcile") as rp:
            display._poll_once()
        rp.assert_called_once()

    def test_unchanged_playing_set_respects_cadence(self):
        aid = "a" * 20
        t = _target(appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        display._core._prev_playing_ids = {aid}
        display._core._reconcile_due = False
        display._core._last_reconcile_at = time.monotonic()  # cadence alone would NOT fire
        with patch("dial_core_poll.reconcile") as rp, \
             patch("dial_display.fetch_target_status",
                   return_value=_status_result(appliance_id=aid)):
            display._poll_once()
        rp.assert_not_called()


# ---------------------------------------------------------------------------
# _refresh_idle_affordance: the idle screen's own "should I draw the
# affordance" computation.
# ---------------------------------------------------------------------------

class TestRefreshIdleAffordance:
    def _roster_row(self, aid, auth="authorized", repeat_capable=True):
        from dial_mdns import RosterEntry
        return RosterEntry(
            appliance_id=aid, service_name="Kitchen", name="Kitchen", ip="10.0.0.9", port=8080,
            playing=False, repeat_capable=repeat_capable, auth=auth,
        )
    def test_true_when_a_held_authorized_capable_row_exists(self):
        import dial_repeat_store as drs
        display, fb, gt = make_display(targets=[])
        aid = "1" * 20
        now = time.monotonic()
        drs.repeat_store.update(aid, drs.parse_repeat_object(_repeat_obj(state="hold"), now))
        display._core._refresh_idle_affordance([self._roster_row(aid)], now)
        assert display.core.snapshot().idle_affordance is True
    def test_false_when_unauthorized(self):
        import dial_repeat_store as drs
        display, fb, gt = make_display(targets=[])
        aid = "2" * 20
        now = time.monotonic()
        drs.repeat_store.update(aid, drs.parse_repeat_object(_repeat_obj(state="hold"), now))
        display._core._refresh_idle_affordance([self._roster_row(aid, auth="unknown")], now)
        assert display.core.snapshot().idle_affordance is False
    def test_false_when_not_repeat_capable(self):
        import dial_repeat_store as drs
        display, fb, gt = make_display(targets=[])
        aid = "3" * 20
        now = time.monotonic()
        drs.repeat_store.update(aid, drs.parse_repeat_object(_repeat_obj(state="hold"), now))
        display._core._refresh_idle_affordance([self._roster_row(aid, repeat_capable=False)], now)
        assert display.core.snapshot().idle_affordance is False
    def test_false_when_not_held(self):
        import dial_repeat_store as drs
        display, fb, gt = make_display(targets=[])
        aid = "4" * 20
        now = time.monotonic()
        drs.repeat_store.update(aid, drs.parse_repeat_object(_repeat_obj(state="replaying"), now))
        display._core._refresh_idle_affordance([self._roster_row(aid)], now)
        assert display.core.snapshot().idle_affordance is False


# ---------------------------------------------------------------------------
# _outputs_available: whether the top-right OUTPUTS zone is currently live.
# ---------------------------------------------------------------------------

class TestOutputsAvailable:
    def test_reporting_appliance_advertises_dial_outputs(self):
        aid = "a" * 20
        t = _target(appliance_id=aid)
        roster = [_roster_entry(appliance_id=aid, playing=True, dial_outputs=True)]
        display, fb, gt = make_display(targets=[t], roster=roster)
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(appliance_id=aid)):
            display._poll_once()
        assert display.core.snapshot().focus.reporting_id == aid
        assert display.core.snapshot().outputs_available is True

    def test_reporting_appliance_without_dial_outputs(self):
        aid = "a" * 20
        t = _target(appliance_id=aid)
        roster = [_roster_entry(appliance_id=aid, playing=True, dial_outputs=False)]
        display, fb, gt = make_display(targets=[t], roster=roster)
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(appliance_id=aid)):
            display._poll_once()
        assert display.core.snapshot().focus.reporting_id == aid
        assert display.core.snapshot().outputs_available is False

    def test_manual_focus_on_an_idle_appliance_with_dial_outputs(self):
        aid = "a" * 20
        roster = [_roster_entry(appliance_id=aid, playing=False, dial_outputs=True)]
        display, fb, gt = make_display(targets=[], roster=roster)
        display.enable()
        display.core.set_focus(aid)
        with patch("dial_display.fetch_target_status", return_value=_status_result(appliance_id=aid)):
            display._poll_once()
        assert display.core.snapshot().outputs_available is True

    def test_nothing_playing_no_focus_is_false(self):
        display, fb, gt = make_display(targets=[], roster=[])
        display.enable()
        display._poll_once()
        assert display.core.snapshot().outputs_available is False

    def test_unfitted_display_is_false(self):
        display, fb, gt = make_display(fitted=False)
        display.core.set_field("outputs_available", True)
        display._poll_once()
        assert display.core.snapshot().outputs_available is False

    def test_unauthorized_reporting_entry_is_false(self):
        t = _target(appliance_id="a" * 20, auth="unauthorized")
        roster = [_roster_entry(appliance_id="a" * 20, playing=True, dial_outputs=True,
                                 auth="unauthorized")]
        display, fb, gt = make_display(targets=[t], roster=roster)
        display.enable()
        display._poll_once()
        assert display.core.snapshot().outputs_available is False


class TestEqAvailable:
    def test_reporting_appliance_advertises_dial_eq(self):
        aid = "a" * 20
        t = _target(appliance_id=aid)
        roster = [_roster_entry(appliance_id=aid, playing=True, dial_eq=True)]
        display, fb, gt = make_display(targets=[t], roster=roster)
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(appliance_id=aid)):
            display._poll_once()
        assert display.core.snapshot().focus.reporting_id == aid
        assert display.core.snapshot().eq_available is True

    def test_reporting_appliance_without_dial_eq(self):
        aid = "a" * 20
        t = _target(appliance_id=aid)
        roster = [_roster_entry(appliance_id=aid, playing=True, dial_eq=False)]
        display, fb, gt = make_display(targets=[t], roster=roster)
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(appliance_id=aid)):
            display._poll_once()
        assert display.core.snapshot().eq_available is False

    def test_unauthorized_reporting_entry_is_false(self):
        t = _target(appliance_id="a" * 20, auth="unauthorized")
        roster = [_roster_entry(appliance_id="a" * 20, playing=True, dial_eq=True, auth="unauthorized")]
        display, fb, gt = make_display(targets=[t], roster=roster)
        display.enable()
        display._poll_once()
        assert display.core.snapshot().eq_available is False

    def test_nothing_playing_no_focus_is_false(self):
        display, fb, gt = make_display(targets=[], roster=[])
        display.enable()
        display._poll_once()
        assert display.core.snapshot().eq_available is False

    def test_unfitted_display_is_false(self):
        display, fb, gt = make_display(fitted=False)
        display.core.set_field("eq_available", True)
        display._poll_once()
        assert display.core.snapshot().eq_available is False

    def test_false_on_the_compact_tier_even_when_capable(self):
        aid = "a" * 20
        t = _target(appliance_id=aid)
        roster = [_roster_entry(appliance_id=aid, playing=True, dial_eq=True)]
        display, fb, gt = make_display(
            targets=[t], roster=roster, screen_size_inches=1.3,
        )
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(appliance_id=aid)):
            display._poll_once()
        assert display._compact_tier() is True
        assert display.core.snapshot().eq_available is False

    def test_dots_active_true_with_eq_and_no_repeat_record(self):
        display = _make_eq_display(dial_eq=True)
        display._core._update_availability(time.monotonic())
        assert display.core.snapshot().dots_active is True


class TestWarningsPush:
    def test_notify_warnings_changed_queues_and_wakes_the_core(self):
        display, fb, gt = make_display(targets=[])
        assert not display._core._poll_wake.is_set()
        display.notify_warnings_changed("a" * 20)
        assert display._core._poll_wake.is_set()
        assert display._core._warnings_pending == {"a" * 20}
