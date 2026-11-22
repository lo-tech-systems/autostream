"""tests/test_player_model.py

The questions the output authority asks of a player's rows, answered for
each combination of what the player reports: session rows or not, outcome
events or not. Events without session rows happen on every connect, between
the event channel's hello and the first read.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core"))

from autostream_state.player_model import PendingStart, PlayerModel, taking_audio
from output_fakes import group_row, row

SELECTION = PlayerModel()
WINDOW = PlayerModel(outcome_events=True)         # hello seen, no session row read yet
POLLED = PlayerModel(session_rows=True)
EVENTS = PlayerModel(session_rows=True, outcome_events=True)
ALL = (SELECTION, WINDOW, POLLED, EVENTS)


class TestDerivedRules:
    def test_who_retries_a_lost_speaker(self):
        assert [m.authority_retries_loss for m in ALL] == [False, False, True, False]

    def test_switches_that_need_session_rows(self):
        for m in ALL:
            assert m.follows_hold is m.session_rows
            assert m.reselects_an_off_row is m.session_rows
            assert m.off_means_between_retries is (not m.session_rows)


class TestAvailability:
    @pytest.mark.parametrize("m", [SELECTION, WINDOW])
    def test_without_session_rows_only_a_pin_shows(self, m):
        assert m.availability(row(1, selected=True), True) == "ok"
        assert m.availability(row(1, pin_pending=True), False) == "password"
        assert m.availability(row(1, needs_auth_key=True), False) == "password"

    @pytest.mark.parametrize("m", [POLLED, EVENTS])
    @pytest.mark.parametrize("state, selected, want", [
        ("streaming", True, "ok"), ("connected", True, "ok"),
        ("startup", True, "starting"), ("connecting", True, "starting"),
        ("stopping", True, "starting"), ("stopping", False, "ok"),
        ("failed", True, "failed"), ("password", False, "password"),
        ("stopped", True, "starting"), ("stopped", False, "ok"),
    ])
    def test_with_session_rows_the_state_says(self, m, state, selected, want):
        assert m.availability(group_row(1, state, selected=selected), selected) == want


class TestRowQuestions:
    @pytest.mark.parametrize("m", [SELECTION, WINDOW])
    def test_without_session_rows_selection_says_it_all(self, m):
        on, off = row(1, selected=True), row(1, selected=False)
        assert (m.connecting(on), m.connecting(off)) == (False, True)
        assert (m.streaming(on), m.streaming(off)) == (True, False)
        assert m.result_shown(on, "ok") and not m.result_shown(off, "ok")
        assert m.result_shown(off, "password")

    @pytest.mark.parametrize("m", [POLLED, EVENTS])
    def test_with_session_rows_the_state_says(self, m):
        def r(state):
            return group_row(1, state, selected=True)
        assert not m.connecting(r("streaming")) and m.connecting(r("connected"))
        assert m.streaming(r("connected")) and not m.streaming(r("failed"))
        assert all(m.result_shown(r(s), "x") for s in ("streaming", "connected", "failed", "password"))
        assert not any(m.result_shown(r(s), "x") for s in ("connecting", "stopped", "stopping"))


class TestPendingStart:
    def test_without_session_rows_an_off_row_did_not_start(self):
        for m in (SELECTION, WINDOW):
            assert m.pending_start(row(1, selected=False)) is PendingStart.FAILED
            assert m.pending_start(row(1, selected=True)) is PendingStart.WAIT

    def test_with_events_a_selected_stopped_row_starts_with_the_playback(self):
        assert EVENTS.pending_start(group_row(1, "stopped", selected=True)) is PendingStart.NO_WAIT
        assert POLLED.pending_start(group_row(1, "stopped", selected=True)) is PendingStart.WAIT

    def test_with_session_rows_anything_else_waits(self):
        for m in (POLLED, EVENTS):
            assert m.pending_start(group_row(1, "connecting", selected=True)) is PendingStart.WAIT
            assert m.pending_start(group_row(1, "stopped", selected=False)) is PendingStart.WAIT


class TestTakingAudio:
    @pytest.mark.parametrize("state, want", [
        ("", True),             # a row without a session (upstream OwnTone), or a state unknown to us
        ("connected", True), ("streaming", True),
        ("connecting", False), ("failed", False), ("stopped", False), ("stopping", False), ("password", False),
    ])
    def test_by_the_row_alone(self, state, want):
        assert taking_audio(group_row(1, state, selected=True)) is want
