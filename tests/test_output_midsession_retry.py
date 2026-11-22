"""tests/test_output_midsession_retry.py

A speaker that fails while it plays (it went away, or closed its session)
stays selected on the player with its session failed. With a player that is
polled, the authority restarts it 10 s and 30 s after the failure, with no
notice, and gives it up after that: it is switched off and the failure is
reported. A speaker the player is already restarting is left to it, and one
that comes back starts afresh. A player that reports events makes the quick
retry itself; see TestByEvents for what follows its give-up.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

from autostream_state import Origin
from autostream_state.outputs import get_authority
from output_fakes import FakeBackend, async_hello, group_row, snap, state_event

T0 = 1000.0


@pytest.fixture
def w(monkeypatch):
    a = get_authority()
    fb = FakeBackend(a)
    clock = [T0]
    monkeypatch.setattr(a, "_clock", lambda: clock[0])
    a.start(fb)
    return SimpleNamespace(a=a, fb=fb, t=clock)


def read(w, state, at):
    w.t[0] = T0 + at
    w.a.merge_for_tests([group_row(1, state, selected=True, volume_percent=40)], boot="b0", now=w.t[0])


def tick(w, at):
    w.t[0] = T0 + at
    w.a.step(now=w.t[0])


def restarts(w):
    """The (off, on) pairs sent to the speaker."""
    calls = [c[2].get("enabled") for c in w.fb.calls if c[0] == "update_output" and "enabled" in c[2]]
    return [calls[i:i + 2] for i in range(0, len(calls), 2)]


@pytest.fixture
def failed(w):
    read(w, "streaming", 0)
    w.a.note_session(True)
    tick(w, 0)
    read(w, "failed", 1)
    return w


class TestTheRetries:
    def test_nothing_is_sent_at_once_and_it_reads_connecting(self, failed):
        assert failed.fb.calls == []
        u = snap().unit("1")
        assert u.selected and u.availability == "failed" and u.connecting
        assert snap().start_failure is None

    def test_it_is_restarted_ten_seconds_after_the_failure(self, failed):
        tick(failed, 10.5)
        assert restarts(failed) == []
        tick(failed, 11)
        assert restarts(failed) == [[False, True]]

    def test_a_second_failure_is_retried_twenty_seconds_later(self, failed):
        tick(failed, 11)
        read(failed, "failed", 12)
        tick(failed, 31.5)
        assert len(restarts(failed)) == 1
        tick(failed, 32)
        assert len(restarts(failed)) == 2
        assert snap().start_failure is None

    def test_after_two_retries_it_is_switched_off_and_reported(self, failed):
        tick(failed, 11)
        read(failed, "failed", 12)
        tick(failed, 32)
        read(failed, "failed", 33)
        u = snap().unit("1")
        assert not u.selected
        assert snap().start_failure is not None and snap().start_failure.unit_id == "1"
        tick(failed, 200)
        assert len(restarts(failed)) == 2

    def test_a_speaker_that_comes_back_is_not_retried_and_starts_afresh(self, failed):
        tick(failed, 11)
        read(failed, "streaming", 12)
        tick(failed, 40)
        assert len(restarts(failed)) == 1
        read(failed, "failed", 50)
        tick(failed, 60)
        assert len(restarts(failed)) == 2


class TestWhatIsLeftAlone:
    def test_a_speaker_the_player_is_restarting_itself_is_not_restarted(self, failed):
        read(failed, "startup", 9)
        tick(failed, 11)
        assert restarts(failed) == []

    def test_outside_a_session_nothing_is_retried(self, w):
        read(w, "streaming", 0)
        read(w, "failed", 1)
        tick(w, 60)
        assert restarts(w) == []

    def test_switching_it_off_ends_the_retries(self, failed):
        failed.a.deselect("1", Origin.USER)
        tick(failed, 11)
        tick(failed, 40)
        sent = [on for pair in restarts(failed) for on in pair]
        assert sent and True not in sent


def selects(w):
    """The selects sent to the speaker, a restart's included."""
    return [c for c in w.fb.calls if c[0] == "update_output" and c[2].get("enabled") is True]


def deselects(w):
    return [c for c in w.fb.calls if c[0] == "update_output" and c[2].get("enabled") is False]


@pytest.fixture
def ev_playing(w):
    """A player that reports events, the speaker playing in a session."""
    async_hello(w.a)
    read(w, "streaming", 0)
    w.a.note_session(True)
    tick(w, 0)
    return w


def event(w, at, *args, **fields):
    w.t[0] = T0 + at
    w.a.on_device_event(state_event("1", *args, **fields))
    tick(w, at)


def make_default(w):
    w.a.set_default_members([("1", "Speaker 1", 40)], 40)


class TestByEvents:
    """A player that reports events retries a lost speaker once itself; the
    authority acts only on its give-up: a default speaker is selected again
    on the retry schedule, any other is switched off and reported."""

    def test_the_player_retries_a_lost_speaker_itself(self, ev_playing):
        w = ev_playing
        # The row reads connecting while the player's retry waits
        event(w, 1, "connecting", member_state="failed", selected=True)
        for at in (11, 31):
            tick(w, at)
        assert selects(w) == [] and deselects(w) == []
        assert snap().unit("1").selected and snap().start_failure is None

    def test_its_give_up_switches_off_a_speaker_that_is_not_a_default(self, ev_playing):
        w = ev_playing
        event(w, 1, "connecting", member_state="failed", selected=True)
        event(w, 7, "failed", "unreachable", selected=False)
        assert not snap().unit("1").selected
        assert snap().start_failure is not None and snap().start_failure.reason == "unreachable"
        for at in (20, 60):
            tick(w, at)
        assert selects(w) == []

    def test_a_give_up_that_still_reads_selected_switches_it_off(self, ev_playing):
        # A group whose leader gave up while its other members wait for it
        w = ev_playing
        event(w, 1, "failed", "unreachable", selected=True)
        assert not snap().unit("1").selected
        assert snap().start_failure is not None
        tick(w, 5)
        assert selects(w) == [] and len(deselects(w)) == 1

    def test_a_default_speaker_is_selected_again_on_the_schedule(self, ev_playing):
        w = ev_playing
        make_default(w)
        event(w, 1, "failed", "unreachable", selected=False)
        assert snap().unit("1").selected and snap().start_failure is None
        tick(w, 10.5)
        assert selects(w) == []
        tick(w, 11.5)
        assert len(selects(w)) == 1
        # That start fails too: the next one comes 20 s later
        event(w, 12, "failed", "unreachable", selected=False)
        tick(w, 31.5)
        assert len(selects(w)) == 1
        tick(w, 32.5)
        assert len(selects(w)) == 2
        assert snap().start_failure is None

    def test_two_give_ups_arm_one_retry(self, ev_playing):
        w = ev_playing
        make_default(w)
        event(w, 1, "failed", "unreachable", selected=False)
        event(w, 2, "failed", "unreachable", selected=False)
        tick(w, 11.5)
        assert len(selects(w)) == 1
        tick(w, 12.5)
        assert len(selects(w)) == 1

    def test_a_default_group_missing_a_speaker_is_selected_again(self, ev_playing):
        w = ev_playing
        make_default(w)
        event(w, 1, "streaming", selected=True, members_missing=1)
        tick(w, 11.5)
        assert len(selects(w)) == 1
        assert snap().unit("1").selected and snap().start_failure is None
        # Still one missing after the select: the next comes 20 s later
        event(w, 12, "streaming", selected=True, members_missing=1)
        tick(w, 31.5)
        assert len(selects(w)) == 1
        tick(w, 32.5)
        assert len(selects(w)) == 2
        # Whole again: nothing more is sent
        event(w, 33, "streaming", selected=True, members_missing=0)
        tick(w, 120)
        assert len(selects(w)) == 2

    def test_a_group_missing_a_speaker_that_is_not_a_default_is_left(self, ev_playing):
        w = ev_playing
        event(w, 1, "streaming", selected=True, members_missing=1)
        for at in (11, 31, 61):
            tick(w, at)
        assert selects(w) == [] and deselects(w) == []
