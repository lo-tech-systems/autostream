"""tests/test_output_hold.py

The output authority's hold of a speaker that paused itself: the hold and
its end as player calls, the refusals, the held mark and what clears it,
how a row's own held flag is followed, the connecting rule, and Mute all
and switch off that leave the held speaker out.
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
from autostream_state.outputs import DEBOUNCE_S, get_authority
from output_fakes import FakeBackend, error, group_row, snap

T0 = 1000.0


@pytest.fixture
def w(monkeypatch):
    a = get_authority()
    fb = FakeBackend(a)
    clock = [T0]
    monkeypatch.setattr(a, "_clock", lambda: clock[0])
    a.start(fb)
    return SimpleNamespace(a=a, fb=fb, t=clock)


def playing(id, *, held=False, holdable=True, volume=40, state="streaming", **extra):
    return group_row(id, state, selected=True, volume_percent=volume,
                     session_held=held, session_holdable=holdable, **extra)


def merge(w, rows, **kw):
    w.a.merge_for_tests(list(rows), boot=kw.pop("boot", "b0"), now=w.t[0], **kw)


def hold_calls(w):
    return [c for c in w.fb.calls if c[0] == "set_output_hold"]


def later(w, seconds=DEBOUNCE_S + 0.5):
    w.t[0] += seconds


class TestHoldAndResume:
    def test_a_hold_asks_the_player_and_shows_at_once(self, w):
        merge(w, [playing(1), playing(2)])
        applied = w.a.hold("1", Origin.DEVICE)
        assert applied.refused is None
        assert hold_calls(w) == [("set_output_hold", ("1", True), {"timeout": pytest.approx(hold_calls(w)[0][2]["timeout"])})]
        assert snap().unit("1").held and not snap().unit("2").held

    def test_resume_asks_the_player_to_end_the_hold(self, w):
        merge(w, [playing(1)])
        w.a.hold("1", Origin.DEVICE)
        w.a.resume("1", Origin.DEVICE)
        assert [c[1] for c in hold_calls(w)] == [("1", True), ("1", False)]
        assert not snap().unit("1").held

    def test_holding_a_held_speaker_or_resuming_a_playing_one_sends_nothing(self, w):
        merge(w, [playing(1)])
        assert w.a.resume("1", Origin.DEVICE).outcome is None
        w.a.hold("1", Origin.DEVICE)
        assert w.a.hold("1", Origin.DEVICE).outcome is None
        assert len(hold_calls(w)) == 1

    def test_a_speaker_the_player_cannot_hold_is_refused_without_a_call(self, w):
        merge(w, [playing(1, holdable=False)])
        assert w.a.hold("1", Origin.DEVICE).refused == "not_holdable"
        assert hold_calls(w) == [] and not snap().unit("1").held

    def test_an_unknown_or_switched_off_speaker_is_refused(self, w):
        merge(w, [group_row(1, "stopped")])
        assert w.a.hold("9", Origin.DEVICE).refused == "unknown_output"
        assert w.a.hold("1", Origin.DEVICE).refused == "not_selected"

    def test_a_hold_the_player_refuses_after_all_is_dropped(self, w):
        merge(w, [playing(1)])
        w.fb.results = [error("not_holdable")]
        w.a.hold("1", Origin.DEVICE)
        assert not snap().unit("1").held


class TestWhatEndsAHold:
    def test_switching_the_speaker_off_ends_it(self, w):
        merge(w, [playing(1)])
        w.a.hold("1", Origin.DEVICE)
        w.a.deselect("1", Origin.USER)
        assert not snap().unit("1").held

    def test_switching_it_on_again_starts_unheld(self, w):
        merge(w, [playing(1)])
        w.a.hold("1", Origin.DEVICE)
        w.a.deselect("1", Origin.USER)
        w.a.select("1", Origin.USER)
        assert not snap().unit("1").held

    def test_the_session_end_ends_it_on_the_player_too(self, w):
        merge(w, [playing(1)])
        w.a.note_session(True)
        w.a.hold("1", Origin.DEVICE)
        w.a.note_session(False)
        w.a.step(now=w.t[0])
        assert not snap().unit("1").held
        assert [c[1] for c in hold_calls(w)] == [("1", True), ("1", False)]

    def test_a_restart_of_the_speaker_ends_it(self, w):
        merge(w, [playing(1)])
        w.a.hold("1", Origin.DEVICE)
        w.a.reselect("1", Origin.USER)
        assert not snap().unit("1").held

    def test_a_player_restart_ends_it(self, w):
        merge(w, [playing(1)])
        w.a.hold("1", Origin.DEVICE)
        merge(w, [playing(1)], boot="b1")
        assert not snap().unit("1").held


class TestTheRowsHeldFlag:
    def test_a_held_row_is_adopted_after_autostream_restarts(self, w):
        merge(w, [playing(1, held=True)])
        assert snap().unit("1").held

    def test_a_hold_the_player_no_longer_has_is_over(self, w):
        merge(w, [playing(1)])
        w.a.hold("1", Origin.DEVICE)
        later(w)
        merge(w, [playing(1, held=False)])
        assert not snap().unit("1").held

    def test_a_row_read_just_after_the_hold_does_not_undo_it(self, w):
        merge(w, [playing(1)])
        w.a.hold("1", Origin.DEVICE)
        merge(w, [playing(1, held=False)])
        assert snap().unit("1").held

    def test_a_row_read_just_after_the_resume_does_not_bring_the_hold_back(self, w):
        merge(w, [playing(1)])
        w.a.hold("1", Origin.DEVICE)
        later(w)
        merge(w, [playing(1, held=True)])
        w.a.resume("1", Origin.DEVICE)
        merge(w, [playing(1, held=True)])
        assert not snap().unit("1").held

    def test_a_held_speaker_is_not_connecting(self, w):
        merge(w, [playing(1, held=True, state="connected")])
        w.a.note_session(True)
        w.a.step(now=w.t[0])
        assert snap().unit("1").held and not snap().unit("1").connecting


class TestTheOthers:
    def test_mute_all_but_the_held_speaker(self, w):
        merge(w, [playing(1), playing(2), playing(3)])
        w.a.hold("1", Origin.DEVICE)
        w.fb.calls.clear()
        applied = w.a.mute_all(Origin.DEVICE, except_id="1")
        p = snap()
        assert not p.unit("1").muted and p.unit("2").muted and p.unit("3").muted
        assert sorted(u for u, _ in applied.mute_tokens) == ["2", "3"]
        assert not p.muted_all
        assert [(c[0], c[1][:2]) for c in w.fb.calls] == [
            ("set_output_muted", ("2", True)), ("set_output_muted", ("3", True))]

    def test_a_speaker_switched_on_later_does_not_join_a_mute_that_left_one_out(self, w):
        merge(w, [playing(1), playing(2), group_row(3, "stopped", session_holdable=True)])
        w.a.mute_all(Origin.DEVICE, except_id="1")
        w.a.select("3", Origin.USER, volume=30)
        assert not snap().unit("3").muted

    def test_mute_all_with_no_other_speaker_is_refused(self, w):
        merge(w, [playing(1)])
        assert w.a.mute_all(Origin.DEVICE, except_id="1").refused == "no_active_outputs"

    def test_switch_off_all_but_the_held_speaker(self, w):
        merge(w, [playing(1), playing(2), playing(3)])
        w.a.hold("1", Origin.DEVICE)
        w.a.deselect_others("1", Origin.POLICY)
        p = snap()
        assert p.unit("1").selected and p.unit("1").held
        assert not p.unit("2").selected and not p.unit("3").selected
        deselects = [c[1] for c in w.fb.calls if c[0] == "update_output" and c[2].get("enabled") is False]
        assert sorted(d[0] for d in deselects) == ["2", "3"]
        assert not p.silence_chosen

    def test_switch_off_others_with_none_is_refused(self, w):
        merge(w, [playing(1)])
        assert w.a.deselect_others("1", Origin.POLICY).refused == "no_active_outputs"


class TestResumeMeansSound:
    def test_resuming_a_muted_held_speaker_ends_the_hold_then_the_mute(self, w):
        merge(w, [playing(1), playing(2)])
        w.a.hold("1", Origin.DEVICE)
        w.a.mute_all(Origin.USER)
        w.fb.calls.clear()
        applied = w.a.resume("1", Origin.DEVICE)
        assert [(c[0], c[1][:2]) for c in w.fb.calls] == [
            ("set_output_hold", ("1", False)), ("set_output_muted", ("1", False))]
        assert [o.ok for o in applied.outcome.result()] == [True, True]
        p = snap()
        assert not p.unit("1").held and not p.unit("1").muted
        assert p.unit("2").muted and p.muted_all is False

    def test_resuming_a_speaker_that_is_not_muted_writes_the_hold_only(self, w):
        merge(w, [playing(1)])
        w.a.hold("1", Origin.DEVICE)
        w.fb.calls.clear()
        applied = w.a.resume("1", Origin.DEVICE)
        assert [c[0] for c in w.fb.calls] == ["set_output_hold"]
        assert len(applied.outcome.result()) == 1

    def test_unmute_all_leaves_the_hold(self, w):
        merge(w, [playing(1), playing(2)])
        w.a.hold("1", Origin.DEVICE)
        w.a.mute_all(Origin.USER)
        w.a.unmute_all(Origin.USER, default_level=0)
        assert snap().unit("1").held and not snap().unit("1").muted

    def test_a_hold_the_player_no_longer_has_is_adopted_without_touching_the_mute(self, w):
        merge(w, [playing(1)])
        w.a.hold("1", Origin.DEVICE)
        w.a.mute("1", Origin.USER)
        later(w)
        merge(w, [playing(1, held=False, muted=True)])
        u = snap().unit("1")
        assert not u.held and u.muted
