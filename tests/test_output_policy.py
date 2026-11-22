"""tests/test_output_policy.py

What a Pause or Play pressed on a speaker does: the recorded scenarios
replayed through the event parser, the output authority and the policy, then
the cases the scenarios cannot show (the settings read at each event, the
intent log lines, the timer hooks, a client's resume).
"""
from __future__ import annotations

import logging
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_output_intents  # noqa: F401  (binds outputs.resume)
import autostream_output_policy as policy_module
import policy_replay
from autostream_backend_events import DeviceEvent
from autostream_config import OutputsConfig
from autostream_intents.table import Intent, submit
from autostream_output_policy import get_policy
from autostream_state import Origin
from autostream_state.outputs import get_authority
from output_fakes import FakeBackend, group_row, row, snap

T0 = 1000.0


# ---------------------------------------------------------------------------
# The recorded scenarios
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", policy_replay.names())
def test_a_recorded_scenario_gives_the_expected_calls_and_state(name, tmp_path, monkeypatch):
    got = policy_replay.replay(name, tmp_path, monkeypatch)
    expect = got.scenario["expect"]
    assert policy_replay.matches(expect["writes"], got.writes), got.writes
    assert got.units == expect["units"]
    assert got.silence_chosen is expect["silence_chosen"]
    assert got.paused == expect["paused"]
    assert got.log == expect["log"]


@pytest.mark.parametrize("name", policy_replay.names())
def test_no_scenario_stops_the_player(name, tmp_path, monkeypatch):
    got = policy_replay.replay(name, tmp_path, monkeypatch)
    assert "stop_and_disable_all" not in [c[0] for c in got.calls]


def _scenario(name, tmp_path, monkeypatch):
    return policy_replay.replay(name, tmp_path, monkeypatch)


def test_the_pause_timeout_leaves_the_default_speaker_off_when_it_was_the_last(tmp_path, monkeypatch):
    got = _scenario("pause_timeout_only_speaker", tmp_path, monkeypatch)
    assert got.silence_chosen is True


def test_the_pause_timeout_nudges_the_repeat_check_when_it_turns_speakers_off(tmp_path, monkeypatch):
    nudges = []
    monkeypatch.setattr(policy_module.repeat_idle, "nudge", lambda: nudges.append(1))
    _scenario("pause_timeout_only_speaker", tmp_path, monkeypatch)
    assert nudges == [1]


def test_a_cancelled_pause_timeout_does_not_nudge_the_repeat_check(tmp_path, monkeypatch):
    nudges = []
    monkeypatch.setattr(policy_module.repeat_idle, "nudge", lambda: nudges.append(1))
    _scenario("pause_timeout_cancelled_by_play", tmp_path, monkeypatch)
    assert nudges == []


def test_the_pause_timeout_leaves_a_speaker_the_user_changed_alone(tmp_path, monkeypatch):
    got = _scenario("pause_timeout_all", tmp_path, monkeypatch)
    assert got.units["1002"] == {"selected": True, "muted": False, "volume": 50, "held": False}
    assert got.units["1001"]["selected"] is False


def test_a_second_pause_does_not_move_the_deadline(tmp_path, monkeypatch):
    got = _scenario("pause_timeout_second_pause_keeps_deadline", tmp_path, monkeypatch)
    assert ["update_output", "1001", {"enabled": False}] in got.writes


def test_a_pause_is_forgotten_when_the_session_ends(tmp_path, monkeypatch):
    got = _scenario("session_end_forgets_pause", tmp_path, monkeypatch)
    assert got.paused == []
    assert not any(w[2] == {"enabled": False} for w in got.writes if len(w) > 2)


# ---------------------------------------------------------------------------
# Cases built by hand
# ---------------------------------------------------------------------------

@pytest.fixture
def w(monkeypatch):
    a = get_authority()
    fb = FakeBackend(a)
    clock = [T0]
    monkeypatch.setattr(a, "_clock", lambda: clock[0])
    a.start(fb)
    pol = get_policy()
    box = SimpleNamespace(cfg=OutputsConfig(device_pause_scope="all"))
    pol.bind_settings(lambda: box.cfg)
    a.set_policy(pol)
    a.merge_for_tests([row(1, selected=True, volume_percent=40), row(2, selected=True, volume_percent=30)],
                      boot="b0", now=T0)
    return SimpleNamespace(a=a, fb=fb, t=clock, pol=pol, box=box)


def event(verb, id="1", received=T0, member=None, kind="receiver_command"):
    return DeviceEvent(kind, id, f"Speaker {id}", verb, None, 1, received, member)


def deliver(w, ev, at=None):
    at = ev.received if at is None else at
    w.t[0] = at
    w.a.on_device_event(ev)
    w.a.step(now=at)


class TestScopeIsReadAtEachEvent:
    def test_a_changed_setting_applies_to_the_next_pause_and_a_play_still_undoes(self, w):
        w.box.cfg = OutputsConfig(device_pause_scope="output")
        deliver(w, event("paus", received=T0 + 1))
        assert snap().unit("1").muted and not snap().unit("2").muted
        w.box.cfg = OutputsConfig(device_pause_scope="all")
        deliver(w, event("play", received=T0 + 2))
        assert not snap().unit("1").muted
        deliver(w, event("paus", received=T0 + 3))
        assert snap().unit("1").muted and snap().unit("2").muted


class TestRefusals:
    def test_a_pause_for_an_unknown_speaker_is_an_info_line_and_no_write(self, w, caplog):
        with caplog.at_level(logging.INFO, logger="autostream"):
            deliver(w, event("paus", id="77", received=T0 + 1))
        assert w.fb.calls == []
        assert any("no such speaker" in r.getMessage() and r.levelno == logging.INFO for r in caplog.records)
        assert any("receiver.pause" in r.getMessage() and "unknown_output" in r.getMessage()
                   for r in caplog.records)

    def test_a_wake_for_an_unknown_speaker_is_an_info_line_and_no_write(self, w, caplog):
        with caplog.at_level(logging.INFO, logger="autostream"):
            deliver(w, event("wake", id="77", received=T0 + 1))
        assert w.fb.calls == []
        assert any("receiver wake from Speaker 77: no such speaker" in r.getMessage()
                   and r.levelno == logging.INFO for r in caplog.records)
        assert any("receiver.wake" in r.getMessage() and "unknown_output" in r.getMessage()
                   for r in caplog.records)

    def test_a_pause_for_a_speaker_that_is_off_is_refused(self, w, caplog):
        w.a.merge_for_tests([row(1, selected=True, volume_percent=40), row(2)], boot="b0", now=T0)
        w.a.deselect("2", Origin.USER)
        w.fb.calls.clear()
        with caplog.at_level(logging.INFO, logger="autostream"):
            deliver(w, event("paus", id="2", received=T0 + 1))
        assert w.fb.calls == []
        assert any("not_selected" in r.getMessage() for r in caplog.records)

    def test_a_pause_with_nothing_on_is_refused_by_the_authority(self, w, caplog):
        w.a.deselect_all(Origin.USER)
        w.fb.calls.clear()
        deliver(w, event("paus", received=T0 + 1))
        assert w.fb.calls == []
        assert w.pol.paused_units() == ()

    def test_a_play_with_nothing_paused_changes_nothing(self, w):
        deliver(w, event("play", received=T0 + 1))
        assert w.fb.calls == []

    def test_other_verbs_are_logged_and_do_nothing(self, w, caplog):
        with caplog.at_level(logging.INFO, logger="autostream.output_policy"):
            for verb in ("nitm", "pitm", "xyzz"):
                deliver(w, event(verb, member="9", received=T0 + 1))
        assert w.fb.calls == []
        lines = [r.getMessage() for r in caplog.records]
        assert len(lines) == 3 and all("no action" in line and "(9)" in line for line in lines)

    def test_a_device_volume_is_the_authoritys_business_not_the_policys(self, w):
        deliver(w, event("paus", received=T0 + 1))
        called = []
        real = w.pol.on_device_event
        w.a.set_policy(SimpleNamespace(
            on_device_event=lambda ev, outputs, now: called.append(ev.kind) or real(ev, outputs, now),
            on_timer=w.pol.on_timer, next_deadline=w.pol.next_deadline, on_session=w.pol.on_session))
        deliver(w, event("volumeup", kind="device_volume", received=T0 + 2))
        assert called == ["device_volume"]
        assert w.pol.paused_units() == ("1",)


class TestIntentLog:
    def test_each_receiver_row_logs_one_intent_line_with_the_device_requester(self, w, caplog):
        with caplog.at_level(logging.DEBUG, logger="autostream.intents"):
            deliver(w, event("paus", received=T0 + 1))
            deliver(w, event("play", received=T0 + 2))
            deliver(w, event("wake", received=T0 + 3))
        lines = [r.getMessage() for r in caplog.records if r.name == "autostream.intents"]
        receiver = [re.sub(r" version=\d+$", "", line) for line in lines if line.startswith("intent receiver.")]
        assert receiver == [
            "intent receiver.pause origin=device requester=device:1 result=ok",
            "intent receiver.play origin=device requester=device:1 result=ok",
            "intent receiver.wake origin=device requester=device:1 result=ok",
        ]

    def test_the_timeout_logs_one_policy_line_per_speaker_turned_off(self, w, caplog):
        deliver(w, event("paus", received=T0 + 1))
        with caplog.at_level(logging.DEBUG, logger="autostream.intents"):
            w.t[0] = T0 + 400
            w.a.step(now=T0 + 400)
        lines = [r.getMessage() for r in caplog.records if r.getMessage().startswith("intent outputs.pause_off")]
        assert len(lines) == 2 and all("origin=policy requester=policy" in line for line in lines)


class TestTimerHooks:
    def test_there_is_no_deadline_until_a_pause_mutes(self, w):
        assert w.pol.next_deadline() is None
        deliver(w, event("paus", received=T0 + 1))
        assert w.pol.next_deadline() == T0 + 1 + 300

    def test_the_time_comes_from_the_setting(self, w):
        w.box.cfg = OutputsConfig(device_pause_scope="all", pause_off_seconds=45)
        deliver(w, event("paus", received=T0 + 1))
        assert w.pol.next_deadline() == T0 + 1 + 45

    def test_the_timer_does_nothing_just_before_the_deadline(self, w):
        deliver(w, event("paus", received=T0))
        w.fb.calls.clear()
        w.a.step(now=T0 + 299.9)
        assert w.fb.calls == [] and w.pol.paused_units() == ("1",)

    def test_a_session_end_drops_every_entry_and_a_start_leaves_them(self, w):
        deliver(w, event("paus", received=T0 + 1))
        w.pol.on_session(True)
        assert w.pol.paused_units() == ("1",)
        w.pol.on_session(False)
        assert w.pol.paused_units() == () and w.pol.next_deadline() is None

    def test_a_speaker_switched_off_and_on_again_ends_its_entry(self, w):
        deliver(w, event("paus", received=T0 + 1))
        w.a.deselect("1", Origin.USER)
        w.a.select("1", Origin.USER, volume=40)
        w.a.merge_for_tests([row(1, selected=True, volume_percent=40), row(2, selected=True, volume_percent=0)],
                            now=T0 + 5)
        w.a.step(now=T0 + 6)
        assert w.pol.paused_units() == ()

    def test_a_speaker_that_goes_away_ends_its_entry(self, w):
        deliver(w, event("paus", received=T0 + 1))
        w.a.deselect("1", Origin.USER)
        w.a.step(now=T0 + 2)
        assert w.pol.paused_units() == ()


class TestAClientResume:
    """outputs.resume from a client (the dial's tap on a Paused speaker):
    the authority ends the hold, and the policy's timer restores what that
    speaker's Pause muted, as its own Play would."""

    @pytest.fixture
    def held(self, w):
        w.a.merge_for_tests([
            group_row(1, "streaming", selected=True, volume_percent=40, session_holdable=True),
            group_row(2, "streaming", selected=True, volume_percent=30),
        ], boot="b0", now=T0)
        deliver(w, event("paus", received=T0 + 1))
        assert snap().unit("1").held and snap().unit("2").muted
        w.fb.calls.clear()
        return w

    @staticmethod
    def resume(id="1"):
        return submit(Intent("outputs.resume", {"id": id}, Origin.USER, "dial:test"), wait=0.5)

    def test_the_speaker_plays_again_and_the_others_are_unmuted(self, held):
        reply = self.resume()
        assert reply.ok and reply.result == {"ok": True, "id": "1"}
        assert ("set_output_hold", ("1", False)) in [c[:2] for c in held.fb.calls]
        held.a.step(now=T0 + 2)
        p = snap()
        assert not p.unit("1").held and not p.unit("2").muted
        assert held.pol.paused_units() == () and held.pol.next_deadline() is None

    def test_a_speaker_that_is_not_held_is_left_as_it_is(self, held):
        reply = self.resume("2")
        assert reply.ok and held.fb.calls == []
        assert snap().unit("2").muted and held.pol.paused_units() == ("1",)

    def test_an_unknown_speaker_or_one_that_is_off_is_refused(self, held):
        assert self.resume("77").error == "unknown_output"
        held.a.deselect("2", Origin.USER)
        assert self.resume("2").error == "not_selected"


class TestPauseAllHoldsTheOthers:
    """With the setting to pause them all, the other speakers are held too
    (muted when they cannot be held), and a Play on any of them brings back
    everything that Pause paused."""

    @pytest.fixture
    def three(self, w):
        w.a.merge_for_tests([
            group_row(1, "streaming", selected=True, volume_percent=40, session_holdable=True),
            group_row(2, "streaming", selected=True, volume_percent=30, session_holdable=True),
            group_row(3, "streaming", selected=True, volume_percent=20),
        ], boot="b0", now=T0)
        deliver(w, event("paus", received=T0 + 1))
        p = snap()
        assert p.unit("1").held and p.unit("2").held and not p.unit("2").muted
        assert p.unit("3").muted and not p.unit("3").held
        w.fb.calls.clear()
        return w

    @staticmethod
    def all_back(w):
        p = snap()
        return (not p.unit("1").held and not p.unit("2").held and not p.unit("3").muted
                and w.pol.paused_units() == ())

    def test_a_play_on_another_speaker_it_held_brings_them_all_back(self, three):
        deliver(three, event("play", id="2", received=T0 + 2))
        assert self.all_back(three)

    def test_a_play_on_a_speaker_it_muted_brings_them_all_back(self, three):
        deliver(three, event("play", id="3", received=T0 + 2))
        assert self.all_back(three)

    def test_a_wake_on_another_speaker_it_held_brings_them_all_back(self, three):
        deliver(three, event("wake", id="2", received=T0 + 2))
        assert self.all_back(three)

    def test_a_pause_from_a_speaker_it_paused_changes_nothing(self, three, caplog):
        with caplog.at_level(logging.INFO, logger="autostream.output_policy"):
            deliver(three, event("paus", id="2", received=T0 + 2))
        assert three.fb.calls == [] and three.pol.paused_units() == ("1",)
        assert any("already paused" in r.getMessage() for r in caplog.records)

    def test_a_speaker_already_muted_is_left_muted(self, w):
        w.a.merge_for_tests([
            group_row(1, "streaming", selected=True, volume_percent=40, session_holdable=True),
            group_row(2, "streaming", selected=True, volume_percent=30, session_holdable=True),
        ], boot="b0", now=T0)
        w.a.mute("2", Origin.USER)
        deliver(w, event("paus", received=T0 + 1))
        assert not snap().unit("2").held and snap().unit("2").muted
        deliver(w, event("play", received=T0 + 2))
        assert not snap().unit("1").held and snap().unit("2").muted

    def test_switching_the_speaker_it_came_from_off_keeps_the_others_paused(self, three):
        three.a.deselect("1", Origin.USER)
        three.a.step(now=T0 + 2)
        assert three.pol.paused_units() == ("2",)
        assert snap().unit("2").held and snap().unit("3").muted
        deliver(three, event("play", id="2", received=T0 + 3))
        p = snap()
        assert not p.unit("2").held and not p.unit("3").muted and three.pol.paused_units() == ()

    def test_switching_another_speaker_it_held_off_takes_it_out(self, three):
        three.a.deselect("2", Origin.USER)
        three.a.step(now=T0 + 2)
        three.fb.calls.clear()
        deliver(three, event("play", received=T0 + 3))
        assert ("set_output_hold", ("2", False)) not in [c[:2] for c in three.fb.calls]
        assert not snap().unit("1").held and not snap().unit("3").muted

    def test_a_client_resume_of_another_speaker_it_held_brings_them_all_back(self, three):
        reply = submit(Intent("outputs.resume", {"id": "2"}, Origin.USER, "dial:test"), wait=0.5)
        assert reply.ok
        three.a.step(now=T0 + 2)
        assert self.all_back(three)

    def test_the_timeout_turns_off_every_speaker_it_paused(self, three):
        three.t[0] = T0 + 400
        three.a.step(now=T0 + 400)
        assert [u.id for u in snap().units if u.selected] == []


class TestAPauseWhileStartingPausesThatSpeakerAlone:
    """An Apple TV whose TV is off pauses itself as soon as it is started.
    A Pause from a speaker switched on here that is not playing yet, or has
    played for under START_PAUSE_S, holds that speaker and leaves the others
    playing, whatever the device pause setting says."""

    @staticmethod
    def rows(state3, selected3):
        return [
            group_row(1, "streaming", selected=True, volume_percent=40, session_holdable=True),
            group_row(2, "streaming", selected=True, volume_percent=30, session_holdable=True),
            group_row(3, state3, selected=selected3, volume_percent=20, session_holdable=True),
        ]

    def switch_on(self, w, state3, at):
        """Speaker 3 switched on here, then read in *state3* at *at*."""
        w.a.merge_for_tests(self.rows("stopped", False), boot="b0", now=T0)
        w.a.note_session(True)
        w.a.select("3", Origin.USER, volume=20)
        w.a.merge_for_tests(self.rows(state3, True), now=at)

    def test_a_pause_before_it_plays_holds_it_alone(self, w, caplog):
        self.switch_on(w, "connecting", T0 + 1)
        with caplog.at_level(logging.INFO, logger="autostream.output_policy"):
            deliver(w, event("paus", id="3", received=T0 + 2))
        p = snap()
        assert p.unit("3").held and not p.unit("1").held and not p.unit("2").held
        assert any("paused while starting" in r.getMessage() for r in caplog.records)

    def test_a_pause_soon_after_it_starts_playing_holds_it_alone(self, w):
        self.switch_on(w, "streaming", T0 + 1)
        deliver(w, event("paus", id="3", received=T0 + 1 + policy_module.START_PAUSE_S - 1))
        p = snap()
        assert p.unit("3").held and not p.unit("1").held and not p.unit("2").held

    def test_a_pause_once_it_has_played_a_while_pauses_them_all(self, w):
        self.switch_on(w, "streaming", T0 + 1)
        deliver(w, event("paus", id="3", received=T0 + 1 + policy_module.START_PAUSE_S + 1))
        p = snap()
        assert p.unit("3").held and p.unit("1").held and p.unit("2").held

    def test_its_play_starts_it_and_the_others_were_never_touched(self, w):
        self.switch_on(w, "connecting", T0 + 1)
        deliver(w, event("paus", id="3", received=T0 + 2))
        w.fb.calls.clear()
        deliver(w, event("play", id="3", received=T0 + 30))
        p = snap()
        assert not p.unit("3").held and w.pol.paused_units() == ()
        assert w.fb.calls == [("set_output_hold", ("3", False), {"timeout": 3.0})]

    def test_a_speaker_found_playing_is_not_starting(self, w):
        # Rows 1 and 2 were read playing, never switched on here, and cannot
        # be held, so the Pause from 1 mutes 2 too
        deliver(w, event("paus", id="1", received=T0 + 1))
        assert snap().unit("2").muted


class TestReset:
    def test_a_reset_of_an_untouched_policy_does_nothing(self):
        pol = policy_module.OutputPolicy()
        entries = pol._entries
        pol.reset_for_tests()
        assert pol._entries is entries and pol._touched is False

    def test_a_reset_forgets_entries_and_settings(self, w):
        deliver(w, event("paus", received=T0 + 1))
        w.pol.reset_for_tests()
        assert w.pol.paused_units() == ()
        assert w.pol._settings is OutputsConfig
        w.pol.reset_for_tests()

    def test_the_suite_reset_leaves_no_entry_behind(self):
        assert get_policy().paused_units() == ()
