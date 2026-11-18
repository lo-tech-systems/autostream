"""tests/test_output_midsession_retry.py

A speaker that fails while it plays (it went away, or closed its session)
stays selected on the player with its session failed. The authority restarts
it 10 s and 30 s after the failure, with no notice, and gives it up after
that: it is switched off and the failure is reported. A speaker the player is
already restarting is left to it, and one that comes back starts afresh.
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


class TestByEvents:
    def test_a_lost_event_retries_like_a_failed_row(self, w):
        async_hello(w.a)
        read(w, "streaming", 0)
        w.a.note_session(True)
        tick(w, 0)
        w.t[0] = T0 + 1
        w.a.on_device_event(state_event("1", "failed", "lost", selected=True))
        tick(w, 1)
        u = snap().unit("1")
        assert u.selected and u.availability == "failed" and snap().start_failure is None
        tick(w, 11)
        assert restarts(w) == [[False, True]]
        # The restart fails as it starts: given up after the second retry
        w.a.on_device_event(state_event("1", "failed", "unreachable", selected=False))
        tick(w, 12)
        tick(w, 32)
        assert len(restarts(w)) == 2
        w.a.on_device_event(state_event("1", "failed", "unreachable", selected=False))
        tick(w, 33)
        assert not snap().unit("1").selected
        assert snap().start_failure.reason == "unreachable"
