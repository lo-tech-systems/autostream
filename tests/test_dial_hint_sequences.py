"""tests/test_dial_hint_sequences.py

Recorded sequences of the hints dials are sent as the coordinator cycles.

Each sequence is a list of steps:

    ("tick", {"repeat": <block or None>, "track": <track spec>, "session_event": <str or None>})
    ("ack", {<daemon ack>})
    ("advance", <seconds>)

A tick is one coordinator poll cycle with the daemon's repeat block and the
active track as given; an ack is a transport or arm acknowledgement folded in
on the API thread; advance moves the clock, running any flush the coalescer
scheduled.  The driver records every hint emitted as (kinds, dials left out,
time), and the sequence's emissions are compared with
tests/golden/dial_hint_sequences.json.

Re-record after a deliberate change to what is hinted:

    AUTOSTREAM_GOLDEN_RECORD=1 python -m pytest tests/test_dial_hint_sequences.py
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_core as core
import autostream_dial_push as dp
import autostream_state
from track_id.models import TrackIdentificationSnapshot, state_status_text
import autostream_repeat as repeat
from fake_store import FakeStore

GOLDEN = Path(__file__).parent / "golden" / "dial_hint_sequences.json"
RECORD = os.environ.get("AUTOSTREAM_GOLDEN_RECORD") == "1"


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------

def block(*, armed=False, recording_seconds=0.0, replay_active=False, fading_out=False,
          position=0.0, duration=0.0) -> dict:
    return {
        "enabled": True,
        "armed": armed,
        "recording": {"active": False, "seconds": recording_seconds, "origin_input": 1},
        "replay": {
            "active": replay_active, "fading_out": fading_out,
            "position_seconds": position, "duration_seconds": duration,
        },
    }


def spec(state="disabled", **fields) -> dict:
    return {"state": state, **fields}


def _snapshot(entry: dict) -> TrackIdentificationSnapshot:
    state = entry["state"]
    return TrackIdentificationSnapshot(
        enabled=state != "disabled", state=state, status_text=state_status_text(state),
        title=entry.get("title", ""), artist=entry.get("artist", ""),
        album=entry.get("album", ""), artwork_url=entry.get("artwork_url", ""))


def tick(repeat=None, track=None, session_event=None):
    return ("tick", {
        "repeat": repeat, "track": track or spec(),
        "session_event": session_event})


def ack(**fields):
    return ("ack", fields)


def advance(seconds: float):
    return ("advance", seconds)


IDLE = block()
HOLD = block(armed=True, recording_seconds=1260.0)
REPLAYING = block(armed=True, recording_seconds=1260.0, replay_active=True,
                  position=10.0, duration=1260.0)
TRACK_A = spec("identified", title="Title A", artist="Artist A", album="Album A",
                artwork_url="https://example.invalid/a.jpg")
TRACK_B = spec("identified", title="Title B", artist="Artist B", album="Album B",
                artwork_url="https://example.invalid/b.jpg")
ANALYSING = spec("analysing")


SEQUENCES: dict[str, list] = {
    "first_tick_primes_and_emits_nothing": [
        tick(IDLE, spec()),
        advance(1.0),
        tick(IDLE, spec()),
    ],
    "session_start_with_an_identified_track": [
        tick(IDLE, spec()),
        advance(5.0),
        tick(IDLE, TRACK_A, session_event="session_started"),
        advance(1.0),
        tick(IDLE, TRACK_A),
    ],
    "track_change_mid_session": [
        tick(IDLE, TRACK_A),
        advance(5.0),
        tick(IDLE, TRACK_B),
        advance(1.0),
        tick(IDLE, TRACK_B),
    ],
    "analysing_gap_keeps_the_last_value": [
        tick(IDLE, TRACK_A),
        advance(5.0),
        tick(IDLE, ANALYSING),
        tick(IDLE, TRACK_A),
        advance(5.0),
        tick(IDLE, ANALYSING),
        tick(IDLE, TRACK_B),
        advance(1.0),
    ],
    "seek_ack_hints_repeat": [
        tick(REPLAYING, TRACK_A),
        advance(5.0),
        ack(ok=True, command="repeat_seek", state="replaying", armed=True,
            position_seconds=0.0),
        advance(1.0),
        tick(REPLAYING, TRACK_A),
    ],
    "arm_ack_starts_a_replay_from_hold_then_the_tick_reports_it": [
        tick(HOLD, TRACK_A),
        advance(5.0),
        ack(ok=True, command="set_repeat_armed", state="replaying", armed=True),
        advance(1.0),
        tick(REPLAYING, TRACK_A),
        advance(1.0),
    ],
    "ack_and_tick_inside_one_window": [
        tick(HOLD, TRACK_A),
        advance(5.0),
        ack(ok=True, command="set_repeat_armed", state="replaying", armed=True),
        advance(0.1),
        tick(REPLAYING, TRACK_A),
        advance(1.0),
    ],
    "two_edges_inside_one_window": [
        tick(IDLE, spec()),
        advance(5.0),
        tick(IDLE, TRACK_A, session_event="session_started"),
        advance(0.1),
        tick(HOLD, TRACK_B),
        advance(0.1),
        tick(HOLD, TRACK_B, session_event="session_ended"),
        advance(1.0),
    ],
    "session_end": [
        tick(IDLE, TRACK_A),
        advance(5.0),
        tick(IDLE, TRACK_A, session_event="session_ended"),
        advance(1.0),
    ],
    "daemon_repeat_block_disappears_and_returns": [
        tick(HOLD, spec()),
        advance(5.0),
        tick(None, spec()),
        advance(5.0),
        tick(HOLD, spec()),
        advance(1.0),
    ],
}


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

class Driver:
    """Runs a sequence against a coalescer on a fake clock."""

    def __init__(self, monkeypatch) -> None:
        self.now = 1000.0
        self.scheduled: list = []
        self.emissions: list = []
        self._track = _snapshot(spec())

        def emit(kinds, except_dials):
            self.emissions.append(
                [sorted(kinds), sorted(except_dials), round(self.now - 1000.0, 3)])

        def schedule(delay, fn):
            self.scheduled.append((self.now + delay, fn))

        monkeypatch.setattr(dp, "_coalescer", dp.StateChangeCoalescer(
            emit, clock=lambda: self.now, schedule=schedule))
        monkeypatch.setattr(
            core, "get_active_track_identification_snapshot", lambda: self._track)
        # The ack path reads and rewrites the repeat and session parts.
        FakeStore().repeat(None)
        FakeStore().session(False, None)
        self.watches = (
            dp.ChangeWatch("repeat", lambda: autostream_state.repeat_digest(
                autostream_state.store().snapshot().repeat.block)),
            dp.ChangeWatch("track", lambda: autostream_state.track_digest(
                core.get_active_track_identification_snapshot())),
        )

    def run(self, steps) -> list:
        for kind, arg in steps:
            if kind == "tick":
                self._track = _snapshot(arg["track"])
                repeat.publish_from_daemon(arg["repeat"])
                dp.hint_dials_after_cycle(arg["session_event"], self.watches)
            elif kind == "ack":
                repeat.apply_repeat_ack(dict(arg))
            elif kind == "advance":
                self._advance(arg)
            else:
                raise AssertionError(f"unknown step {kind!r}")
        return self.emissions

    def _advance(self, seconds: float) -> None:
        target = self.now + seconds
        while True:
            due = sorted((t, i) for i, (t, _fn) in enumerate(self.scheduled) if t <= target)
            if not due:
                break
            t, index = due[0]
            _t, fn = self.scheduled.pop(index)
            self.now = max(self.now, t)
            fn()
        self.now = target


def _record(monkeypatch) -> dict:
    out = {}
    for name, steps in SEQUENCES.items():
        with monkeypatch.context() as mp:
            out[name] = Driver(mp).run(steps)
    return out


def test_sequences_match_the_recorded_emissions(monkeypatch):
    actual = _record(monkeypatch)
    if RECORD:
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(json.dumps(actual, indent=1) + "\n", encoding="utf-8")
        return
    assert GOLDEN.exists(), f"missing {GOLDEN}; record it with AUTOSTREAM_GOLDEN_RECORD=1"
    expected = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert sorted(actual) == sorted(expected)
    differing = [name for name in expected if actual[name] != expected[name]]
    assert not differing, f"hint sequences differ from the recorded ones: {differing}"


class TestRecordedBehaviour:
    """The properties the recording is meant to pin, stated directly."""

    def _run(self, monkeypatch, name):
        return Driver(monkeypatch).run(SEQUENCES[name])

    def test_the_first_reading_is_a_baseline_and_emits_nothing(self, monkeypatch):
        assert self._run(monkeypatch, "first_tick_primes_and_emits_nothing") == []

    def test_an_analysing_reading_keeps_the_last_value(self, monkeypatch):
        emitted = self._run(monkeypatch, "analysing_gap_keeps_the_last_value")
        assert [e[0] for e in emitted] == [["track"]]

    def test_a_seek_ack_hints_repeat_at_once(self, monkeypatch):
        emitted = self._run(monkeypatch, "seek_ack_hints_repeat")
        assert emitted == [[["repeat"], [], 5.0]]

    def test_changes_inside_one_window_are_emitted_together_when_it_ends(self, monkeypatch):
        emitted = self._run(monkeypatch, "two_edges_inside_one_window")
        assert emitted[0][0] == ["session"]
        assert emitted[1][0] == ["repeat", "session", "track"]
        assert emitted[1][2] == pytest.approx(5.3)

    def test_a_session_end_hints_session(self, monkeypatch):
        emitted = self._run(monkeypatch, "session_end")
        assert [e[0] for e in emitted] == [["session"]]
