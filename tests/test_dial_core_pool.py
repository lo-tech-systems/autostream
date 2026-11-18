"""tests/test_dial_core_pool.py -- the dial core reading the appliances from a
peer pool: one publish per fold, the focus rule, the accepted-replay bridge,
the focused appliance's snapshot, outputs and EQ, warnings from the part and
start failures."""
from __future__ import annotations

import time

import pytest

from dial_pool_support import Rig, aid, peer, track, unit, replay_block

from dial_core_state import AUTH_AUTHORIZED, AUTH_UNAUTHORIZED, AUTH_UNKNOWN, NowPlaying
from dial_warning_text import appliance_warning_key


@pytest.fixture
def rig():
    r = Rig()
    yield r
    r.close()


def reporting_name(rig):
    snap = rig.core.snapshot()
    a = snap.appliance(snap.focus.reporting_id)
    return a.name if a is not None else None


# ---- folding --------------------------------------------------------------------


class TestFold:
    def test_several_clients_moving_give_one_publish(self, rig):
        rig.add("Kitchen")
        rig.add("Lounge")
        rig.fold()
        published = []
        rig.core.subscribe(lambda: published.append(1))
        rig.set("Kitchen", peer("Kitchen", playing=True, seq=2))
        rig.set("Lounge", peer("Lounge", playing=True, seq=2))
        rig.fold()
        assert len(published) == 1
        assert {a.name for a in rig.core.snapshot().appliances if a.playing} == {"Kitchen", "Lounge"}

    def test_a_fold_ends_a_tick(self, rig):
        rig.add("Kitchen", peer("Kitchen", playing=True))
        before = rig.core.snapshot().ticks
        snap = rig.fold()
        assert snap.ticks == before + 1 and snap.tick is not None
        assert snap.polling is True

    def test_the_pool_signal_wakes_the_core(self, rig):
        rig.core._wake.clear()
        rig.pool.signal()
        assert rig.core._wake.is_set()

    def test_an_unchanged_snapshot_keeps_its_mapped_state(self, rig):
        rig.add("Kitchen", peer("Kitchen", playing=True))
        first = rig.fold().appliance(aid("Kitchen"))
        rig.t += 30
        assert rig.fold().appliance(aid("Kitchen")).repeat is first.repeat

    def test_access_none_for_this_dial_is_not_allowed(self, rig):
        rig.add("Kitchen", peer("Kitchen", access="none", access_reason="dial_not_authorized"))
        rig.add("Lounge", peer("Lounge", access="none", access_reason="unconfigured"))
        rig.add("Hall", peer("Hall", access="none", access_reason="auth_unavailable"))
        snap = rig.fold()
        assert snap.appliance(aid("Kitchen")).auth == AUTH_UNAUTHORIZED
        assert snap.appliance(aid("Lounge")).auth == AUTH_UNAUTHORIZED
        assert snap.appliance(aid("Hall")).auth == AUTH_UNKNOWN

    def test_an_appliance_authorising_this_dial_is_counted_as_a_promotion(self, rig):
        rig.add("Kitchen", peer("Kitchen", access="unknown"))
        rig.fold()
        rig.set("Kitchen", peer("Kitchen", access="playback", seq=2))
        assert rig.fold().auth_promotions == 1

    def test_a_sighting_without_a_client_is_listed_unreachable(self, rig):
        rig.add("Kitchen")
        del rig.pool._clients[aid("Kitchen")]
        a = rig.fold().appliance(aid("Kitchen"))
        assert a.status_error == "unreachable" and a.auth == AUTH_UNKNOWN


# ---- the focus rule -----------------------------------------------------------------


class TestFocus:
    def test_oldest_playing_when_nothing_is_identified(self, rig):
        rig.add("Newer")
        rig.add("Older", peer("Older", playing=True))
        rig.fold()
        rig.t += 10
        rig.set("Newer", peer("Newer", playing=True, seq=2))
        rig.fold()
        assert reporting_name(rig) == "Older"

    def test_an_identified_track_wins_over_an_older_appliance(self, rig):
        rig.add("Older", peer("Older", playing=True))
        rig.add("Newer", peer("Newer", playing=True, track_entry=track(url="")))
        # Both already playing, Older first, and nothing bound yet.
        rig.core._state.playing_since = {aid("Older"): rig.t - 20, aid("Newer"): rig.t - 10}
        snap = rig.fold()
        assert reporting_name(rig) == "Newer"
        assert (snap.now_playing.title, snap.now_playing.artist) == ("Song", "Artist")
        assert snap.focus.source_service_name == "autostream on Newer"

    def test_a_restart_with_two_already_playing_breaks_the_tie_by_name(self, rig):
        rig.add("Zed", peer("Zed", playing=True))
        rig.add("Amp", peer("Amp", playing=True))
        rig.fold()
        assert reporting_name(rig) == "Amp"

    def test_an_idle_focus_is_shown_while_another_plays(self, rig):
        rig.add("Idle", peer("Idle", master_volume=33))
        rig.add("Busy", peer("Busy", playing=True, track_entry=track()))
        rig.fold()
        rig.core.set_focus(aid("Idle"))
        snap = rig.fold()
        assert snap.focus.reporting_id == aid("Idle") and snap.focus.idle_focus
        assert snap.now_playing == NowPlaying("autostream on Idle", "", "", 33, playing=False)

    def test_a_bound_appliance_is_not_taken_over(self, rig):
        rig.add("First", peer("First", playing=True))
        rig.fold()
        rig.t += 5
        rig.add("Second", peer("Second", playing=True, track_entry=track()))
        rig.fold()
        assert reporting_name(rig) == "First"

    def test_a_refused_appliance_is_never_shown(self, rig):
        rig.add("Refused", peer("Refused", playing=True, access="none", access_reason="dial_not_authorized",
                                track_entry=track()))
        rig.add("Ok", peer("Ok", playing=True))
        snap = rig.fold()
        assert reporting_name(rig) == "Ok" and snap.visible_playing == (aid("Ok"),)

    def test_a_client_removed_while_focused_clears_the_focus(self, rig):
        rig.add("Kitchen", peer("Kitchen", playing=True))
        rig.add("Lounge", peer("Lounge", playing=True))
        rig.fold()
        rig.core.set_focus(aid("Kitchen"))
        assert rig.fold().focus.reporting_id == aid("Kitchen")
        rig.remove("Kitchen")
        snap = rig.fold()
        assert snap.focus.manual_id is None and snap.tick.focus_cleared
        assert snap.focus.reporting_id == aid("Lounge")
        assert snap.focused_peer is rig.pool.get(aid("Lounge")).snap

    def test_a_focus_on_an_appliance_that_stops_is_cleared(self, rig):
        rig.add("Kitchen", peer("Kitchen", playing=True))
        rig.fold()
        rig.core.set_focus(aid("Kitchen"))
        rig.fold()
        rig.set("Kitchen", peer("Kitchen", seq=2))
        snap = rig.fold()
        assert snap.focus.manual_id is None and snap.now_playing is None

    def test_a_focus_change_is_told_to_the_focus_subscribers(self, rig):
        calls = []
        rig.core.subscribe_focus(lambda: calls.append(1))
        rig.add("Kitchen", peer("Kitchen", playing=True))
        rig.fold()
        rig.fold()
        assert calls == [1]

    def test_the_idle_hold_keeps_what_is_shown(self, rig):
        rig.add("Kitchen", peer("Kitchen", playing=True))
        rig.fold()
        rig.core.set_idle_hold(lambda cleared: True)
        rig.set("Kitchen", peer("Kitchen", seq=2))
        snap = rig.fold()
        assert snap.focus.reporting_id == aid("Kitchen") and snap.now_playing is not None
        assert snap.visible_playing == () and snap.focus.source_service_name is None


class TestReplayBridge:
    def test_an_accepted_replay_shows_as_playing_until_the_session_does(self, rig):
        rig.add("Kitchen", peer("Kitchen", repeat=replay_block("replaying")))
        rig.fold()
        rig.core.set_focus(aid("Kitchen"))
        assert rig.core.accept_replay(aid("Kitchen"), rig.t + 20)
        snap = rig.fold()
        assert snap.visible_playing == (aid("Kitchen"),) and snap.now_playing.playing
        assert snap.focus.accepted_replay is not None
        rig.set("Kitchen", peer("Kitchen", playing=True, source="replay", repeat=replay_block(), seq=2))
        snap = rig.fold()
        assert snap.focus.accepted_replay is None and snap.focus.reporting_id == aid("Kitchen")

    def test_the_bridge_closes_at_its_deadline(self, rig):
        rig.add("Kitchen", peer("Kitchen", repeat=replay_block("replaying")))
        rig.fold()
        rig.core.set_focus(aid("Kitchen"))
        rig.core.accept_replay(aid("Kitchen"), rig.t + 20)
        rig.t += 21
        snap = rig.fold()
        assert snap.focus.accepted_replay is None and snap.visible_playing == ()


# ---- the focused appliance ------------------------------------------------------------


class TestFocused:
    def test_focused_peer_is_the_folded_snapshot(self, rig):
        client = rig.add("Kitchen", peer("Kitchen", playing=True))
        snap = rig.fold()
        assert snap.focused_peer is client.snap
        assert rig.core.focused_client() is client

    def test_no_focus_has_no_focused_peer(self, rig):
        rig.add("Kitchen")
        snap = rig.fold()
        assert snap.focused_peer is None and snap.outputs is None and snap.eq is None

    def test_outputs_and_eq_are_the_focused_appliances(self, rig):
        rig.add("Kitchen", peer("Kitchen", playing=True, units=[unit(selected=True, volume=55)],
                                bands=[1, 2, 3, 4, 5, 6]))
        snap = rig.fold()
        assert snap.outputs.appliance_id == aid("Kitchen") and snap.outputs.loaded
        assert [(r.id, r.selected, r.volume) for r in snap.outputs.rows] == [("u1", True, 55)]
        assert [b.gain_db for b in snap.eq.bands][:6] == [1, 2, 3, 4, 5, 6]
        assert snap.outputs_available and snap.eq_available and snap.dots_active

    def test_the_eq_veto_hides_the_eq_page(self, rig):
        rig.core.set_eq_veto(lambda: True)
        rig.add("Kitchen", peer("Kitchen", playing=True))
        assert not rig.fold().eq_available

    def test_the_outputs_state_is_kept_while_its_rows_do_not_change(self, rig):
        rig.add("Kitchen", peer("Kitchen", playing=True, units=[unit()]))
        held = rig.fold().outputs
        rig.t += 5
        rig.set("Kitchen", peer("Kitchen", playing=True, units=[unit()], seq=2, version=2))
        assert rig.fold().outputs is held

    def test_the_readout_and_mute_are_observed_for_the_reporting_appliance(self, rig):
        rig.add("Kitchen", peer("Kitchen", playing=True, master_volume=61, muted_all=True, heard_at=5.0))
        rig.fold()
        rig.io.observe_volume.assert_called_with("autostream on Kitchen", 61)
        rig.io.observe_mute.assert_called_with("autostream on Kitchen", True, requested_at=5.0,
                                               status_reports_mute=True)

    def test_nothing_playing_clears_the_observations(self, rig):
        rig.add("Kitchen")
        rig.fold()
        rig.io.observe_volume.assert_called_with(None, None)
        rig.io.observe_mute.assert_called_with(None, None)


# ---- warnings and start failures --------------------------------------------------------


def entry(i, **kw):
    base = {"id": f"w{i}", "severity": "warning", "title": f"Warning {i}", "message": "m",
            "incident": ""}
    base.update(kw)
    return base


class TestWarnings:
    def test_sixteen_entries_are_kept(self, rig):
        rig.add("Kitchen", peer("Kitchen", warnings=[entry(i) for i in range(20)]))
        a = rig.fold().appliance(aid("Kitchen"))
        assert [w.id for w in a.warnings] == [f"w{i}" for i in range(16)]

    def test_the_name_is_the_source_and_the_manager_holds_them(self, rig):
        rig.add("Kitchen", peer("Kitchen", warnings=[entry(1)]))
        a = rig.fold().appliance(aid("Kitchen"))
        assert a.warnings[0].appliance_name == "Kitchen"
        assert rig.core.warnings.descriptor(appliance_warning_key(aid("Kitchen"), "w1")) is not None

    def test_a_cleared_list_ends_the_incidents(self, rig):
        rig.add("Kitchen", peer("Kitchen", warnings=[entry(1)]))
        rig.fold()
        rig.set("Kitchen", peer("Kitchen", warnings=[], seq=2))
        assert rig.fold().appliance(aid("Kitchen")).warnings == ()
        assert rig.core.warnings.descriptor(appliance_warning_key(aid("Kitchen"), "w1")) is None

    def test_an_appliance_that_goes_loses_its_warnings(self, rig):
        rig.add("Kitchen", peer("Kitchen", warnings=[entry(1)]))
        rig.fold()
        rig.remove("Kitchen")
        rig.fold()
        assert rig.core.warnings.descriptor(appliance_warning_key(aid("Kitchen"), "w1")) is None

    def test_an_appliance_refusing_this_dial_holds_none(self, rig):
        rig.add("Kitchen", peer("Kitchen", access="none", access_reason="dial_not_authorized",
                                warnings=[entry(1)]))
        assert rig.fold().appliance(aid("Kitchen")).warnings == ()


def failure(seq=1, requester="dial:dial-uuid", reason="unreachable", at=None):
    return {"seq": seq, "unit_id": "u1", "name": "Lounge", "reason": reason, "requester": requester,
            "at": time.time() if at is None else at}


class TestStartFailure:
    def test_a_new_failure_of_this_dials_start_raises_the_notice(self, rig):
        rig.add("Kitchen", peer("Kitchen", playing=True))
        rig.fold()
        rig.set("Kitchen", peer("Kitchen", playing=True, start_failure=failure(), seq=2))
        snap = rig.fold()
        assert snap.start_failure is not None and snap.start_failure.name == "Lounge"

    def test_another_requesters_failure_is_not_shown(self, rig):
        rig.add("Kitchen", peer("Kitchen", playing=True))
        rig.fold()
        rig.set("Kitchen", peer("Kitchen", playing=True, start_failure=failure(requester="webui"), seq=2))
        assert rig.fold().start_failure is None

    def test_an_old_failure_read_first_is_not_news(self, rig):
        rig.add("Kitchen", peer("Kitchen", playing=True, start_failure=failure(at=time.time() - 600)))
        assert rig.fold().start_failure is None

    def test_a_recent_failure_read_first_is_shown(self, rig):
        rig.add("Kitchen", peer("Kitchen", playing=True, start_failure=failure(at=time.time() - 2)))
        assert rig.fold().start_failure is not None


# ---- the volume target and the operator socket ---------------------------------


class TestVolumeTarget:
    def test_a_manual_focus_is_the_volume_target_by_its_appliance_id(self, rig):
        assert rig.core.focus_volume_target() is None
        rig.add("Kitchen", peer("Kitchen"))
        rig.fold()
        assert rig.core.focus_volume_target() is None
        rig.core.set_focus(aid("Kitchen"))
        target = rig.core.focus_volume_target()
        assert target.appliance_id == aid("Kitchen") and rig.pool.get(target.appliance_id) is not None

    def test_a_refused_or_gone_focus_is_no_target(self, rig):
        rig.add("Kitchen", peer("Kitchen"))
        rig.fold()
        rig.core.set_focus(aid("Kitchen"))
        rig.set("Kitchen", peer("Kitchen", access="none", access_reason="dial_not_authorized", seq=2))
        rig.fold()
        assert rig.core.focus_volume_target() is None
        rig.remove("Kitchen")
        rig.fold()
        assert rig.core.focus_volume_target() is None


class TestControlSocketRecords:
    def test_the_records_come_from_the_folded_state(self, rig):
        from dial_control import core_target_records
        from dial_mdns import PlayingTarget
        rig.add("Kitchen", peer("Kitchen", playing=True, master_volume=35,
                                units=(unit("u1", selected=True), unit("u2"))))
        rig.fold()
        target = PlayingTarget(ip="192.0.2.10", port=80, name="autostream on Kitchen",
                               dial_status=True, appliance_id=aid("Kitchen"))
        gone = PlayingTarget(ip="192.0.2.11", port=80, name="autostream on Hall", appliance_id=aid("Hall"))
        records = core_target_records(rig.core)([target, gone], "dial-uuid")
        by_name = {r["name"]: r for r in records}
        kitchen = by_name["autostream on Kitchen"]
        assert (kitchen["master_volume"], kitchen["selected_output_count"], kitchen["status_error"]) == (35, 1, None)
        assert by_name["autostream on Hall"]["status_error"] == "unreachable"
        assert [r["name"] for r in records] == ["autostream on Hall", "autostream on Kitchen"]
        assert rig.pool.get(aid("Kitchen")).sent() == []
