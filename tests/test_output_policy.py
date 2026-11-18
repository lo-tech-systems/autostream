"""tests/test_output_policy.py

What a Pause or Play pressed on a speaker does: the recorded scenarios
replayed through the event parser, the output authority and the policy, then
the cases the scenarios cannot show (the settings read at each event, the
play guard comparing the time the event was received, the intent log lines,
the timer hooks).
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

import autostream_output_policy as policy_module
import autostream_runtime as runtime
import policy_replay
from autostream_backend_events import DeviceEvent
from autostream_config import OutputsConfig
from autostream_output_policy import get_policy
from autostream_state import Origin
from autostream_state.outputs import get_authority
from output_fakes import FakeBackend, row, snap

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


def test_turning_every_speaker_off_chooses_silence_and_writes_one_selection(tmp_path, monkeypatch):
    got = _scenario("pause_off_all", tmp_path, monkeypatch)
    assert got.writes == [["set_selected_outputs", []]]
    assert got.silence_chosen is True
    assert not any(u["selected"] for u in got.units.values())


def test_the_pause_timeout_leaves_the_default_speaker_off_when_it_was_the_last(tmp_path, monkeypatch):
    got = _scenario("pause_timeout_only_speaker", tmp_path, monkeypatch)
    assert got.silence_chosen is True


def test_the_pause_timeout_leaves_a_speaker_the_user_changed_alone(tmp_path, monkeypatch):
    got = _scenario("pause_timeout_all", tmp_path, monkeypatch)
    assert got.units["1002"] == {"selected": True, "muted": False, "volume": 50}
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
        w.box.cfg = OutputsConfig(device_pause_scope="ignore")
        deliver(w, event("play", received=T0 + 2))
        assert not snap().unit("1").muted
        deliver(w, event("paus", received=T0 + 3))
        assert not snap().unit("1").muted

    def test_keep_playing_makes_no_authority_call(self, w, monkeypatch):
        w.box.cfg = OutputsConfig(device_pause_scope="ignore")
        called = []
        for name in ("mute", "mute_all", "deselect", "deselect_all", "unmute", "unmute_joined"):
            monkeypatch.setattr(w.a, name, lambda *a, _n=name, **k: called.append(_n))
        deliver(w, event("paus", received=T0 + 1))
        assert called == [] and w.fb.calls == []
        assert w.pol.paused_units() == () and w.pol.next_deadline() is None


class TestPlayGuard:
    def test_the_guard_compares_the_time_the_event_was_received(self, w):
        deliver(w, event("paus", received=T0 + 1))
        runtime.note_metadata_push(T0 + 100)
        # Received 5 s after the push but handled much later: still inside the window.
        w.t[0] = T0 + 120
        w.a.on_device_event(event("play", received=T0 + 105))
        w.a.step(now=T0 + 120)
        assert snap().unit("1").muted
        # Received outside the window, handled at the same worker time.
        deliver(w, event("play", received=T0 + 111), at=T0 + 120)
        assert not snap().unit("1").muted

    def test_a_play_received_just_before_the_push_was_stamped_is_ignored(self, w):
        deliver(w, event("paus", received=T0 + 1))
        runtime.note_metadata_push(T0 + 100)
        deliver(w, event("play", received=T0 + 99))
        assert snap().unit("1").muted

    def test_no_push_ever_made_means_no_guard(self, w):
        deliver(w, event("paus", received=T0 + 1))
        deliver(w, event("play", received=T0 + 2))
        assert not snap().unit("1").muted

    def test_the_window_comes_from_the_setting(self, w):
        w.box.cfg = OutputsConfig(device_pause_scope="all", play_after_metadata_ignore_seconds=30.0)
        deliver(w, event("paus", received=T0 + 1))
        runtime.note_metadata_push(T0 + 100)
        deliver(w, event("play", received=T0 + 125))
        assert snap().unit("1").muted
        deliver(w, event("play", received=T0 + 131))
        assert not snap().unit("1").muted


class TestRefusals:
    def test_a_pause_for_an_unknown_speaker_is_an_info_line_and_no_write(self, w, caplog):
        with caplog.at_level(logging.INFO, logger="autostream"):
            deliver(w, event("paus", id="77", received=T0 + 1))
        assert w.fb.calls == []
        assert any("no such speaker" in r.getMessage() and r.levelno == logging.INFO for r in caplog.records)
        assert any("receiver.pause" in r.getMessage() and "unknown_output" in r.getMessage()
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
        lines = [r.getMessage() for r in caplog.records if r.name == "autostream.intents"]
        receiver = [re.sub(r" version=\d+$", "", line) for line in lines if line.startswith("intent receiver.")]
        assert receiver == [
            "intent receiver.pause origin=device requester=device:1 result=ok",
            "intent receiver.play origin=device requester=device:1 result=ok",
        ]

    def test_turning_every_speaker_off_logs_the_policy_submit(self, w, caplog):
        w.box.cfg = OutputsConfig(device_pause_scope="off_all")
        with caplog.at_level(logging.DEBUG, logger="autostream.intents"):
            deliver(w, event("paus", received=T0 + 1))
        lines = [r.getMessage() for r in caplog.records]
        assert any(line.startswith("intent outputs.deselect_all origin=policy requester=policy") for line in lines)

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
        assert runtime.last_metadata_push() is None
