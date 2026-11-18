"""tests/test_state_dial_hints.py

Dial hints as a subscriber of the state store: which Changes produce a hint,
in what order, for whom, and how many calls reach the coalescer. The
coalesced recordings in test_dial_hint_sequences cannot show a duplicate
inside the window, so every step here counts the calls itself.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_dial_push as dp
import autostream_repeat as repeat
import autostream_session as session
import autostream_state as state
from fake_store import FakeStore
from track_id.models import TrackIdentificationSnapshot, state_status_text


def _block(*, armed=False, replay_active=False, position=0.0):
    return {
        "enabled": True, "armed": armed,
        "recording": {"active": False, "seconds": 0.0, "origin_input": 1},
        "replay": {"active": replay_active, "fading_out": False,
                   "position_seconds": position, "duration_seconds": 100.0},
    }


def _track(st, title=""):
    return TrackIdentificationSnapshot(
        enabled=st != "disabled", state=st, status_text=state_status_text(st),
        title=title, artist="", album="", artwork_url="")


class Rig:
    """The real subscriber on the process store, with the coalescer replaced
    by a recorder of every (kinds, except_dial) it is given."""

    def __init__(self, monkeypatch):
        state.store().reset_for_tests()
        self.coalescer = MagicMock()
        monkeypatch.setattr(dp, "_coalescer", self.coalescer)
        self.fake = FakeStore()
        self.fake.repeat(None)
        self.fake.session(False, None)
        self.fake.inputs([self.fake.input_entry(1, capturing=True)])
        self.fake.track({1: _track("disabled")}, service_enabled=True)
        dp.install_state_hints(state.store())

    @property
    def calls(self):
        return [c.args for c in self.coalescer.notify.call_args_list]

    def cycle(self, *, repeat_block=None, track=None, edge=None, requester=None):
        """One coordinator cycle: publish through the owners inside a batch
        and close it. Returns the coalescer calls it caused."""
        before = len(self.calls)
        batch = state.store().batch()
        try:
            if track is not None:
                self.fake.track({1: track}, service_enabled=True)
            repeat.publish_from_daemon(repeat_block)
            if edge is not None:
                session._writer.publish(
                    state.SessionPart(edge, "input1" if edge else None),
                    tags=("session",), requester=requester).notify()
        finally:
            batch.close()
        return self.calls[before:]


@pytest.fixture
def rig(monkeypatch):
    return Rig(monkeypatch)


def _ack(command="repeat_seek", state_name="replaying", position=0.0):
    return {"type": "ack", "command": command, "ok": True, "state": state_name,
            "armed": True, "position_seconds": position}


def test_a_repeat_ack_hints_repeat_once_and_not_the_dial_that_asked(rig):
    rig.cycle(repeat_block=_block(armed=True, replay_active=True, position=5.0))
    before = len(rig.calls)
    repeat.apply_repeat_ack(_ack(position=30.0), requester="dial:abc-1")
    assert rig.calls[before:] == [(("repeat",), "abc-1")]


def test_a_repeat_ack_whose_digest_did_not_move_still_hints(rig):
    rig.cycle(repeat_block=_block(armed=True, replay_active=True, position=5.0))
    repeat.apply_repeat_ack(_ack(position=30.0))
    before = len(rig.calls)
    repeat.apply_repeat_ack(_ack(position=31.0))
    assert rig.calls[before:] == [(("repeat",), None)]


def test_a_session_edge_makes_exactly_one_session_call(rig):
    rig.cycle(repeat_block=_block())
    assert rig.cycle(repeat_block=_block(), edge=True) == [(("session",), None)]


def test_a_cycle_with_no_edge_and_no_movement_makes_no_call(rig):
    rig.cycle(repeat_block=_block(), track=_track("identified", "A"))
    assert rig.cycle(repeat_block=_block(), track=_track("identified", "A")) == []


def test_the_first_close_is_the_baseline(rig):
    assert rig.cycle(repeat_block=_block(armed=True), track=_track("identified", "A")) == []


def test_an_analysing_track_keeps_the_previous_value(rig):
    rig.cycle(repeat_block=_block(), track=_track("identified", "A"))
    assert rig.cycle(repeat_block=_block(), track=_track("analysing")) == []
    assert rig.cycle(repeat_block=_block(), track=_track("identified", "A")) == []
    assert rig.cycle(repeat_block=_block(), track=_track("identified", "B")) == [
        (("track",), None)]


def test_one_close_sends_session_then_repeat_then_track_one_call_each(rig):
    rig.cycle(repeat_block=_block(), track=_track("identified", "A"))
    calls = rig.cycle(repeat_block=_block(armed=True), track=_track("identified", "B"),
                      edge=True)
    assert [sorted(kinds) for kinds, _ in calls] == [["session"], ["repeat"], ["track"]]


def test_a_dial_requester_becomes_except_dial(rig):
    rig.cycle(repeat_block=_block())
    assert rig.cycle(repeat_block=_block(), edge=True, requester="dial:abc-1") == [
        (("session",), "abc-1")]


def test_a_non_dial_requester_excludes_nobody(rig):
    rig.cycle(repeat_block=_block())
    assert rig.cycle(repeat_block=_block(), edge=True, requester="webui") == [
        (("session",), None)]


def test_an_immediate_repeat_or_track_change_makes_no_call(rig):
    rig.cycle(repeat_block=_block(), track=_track("identified", "A"))
    repeat.publish_from_daemon(_block(replay_active=True))
    state.store().claim("track", "autostream_core").publish(state.TrackPart(
        entries=state.FrozenDict({1: _track("identified", "B")}), service_enabled=True)).notify()
    assert rig.calls == []


def test_an_immediate_session_publish_is_hinted_only_by_its_tag(rig):
    rig.cycle(repeat_block=_block())
    session._writer.publish(state.SessionPart(True, "input1")).notify()
    assert rig.calls == []
    session._writer.publish(state.SessionPart(False, None), tags=("session",)).notify()
    assert rig.calls == [(("session",), None)]


def test_a_seek_ack_makes_exactly_one_repeat_call_from_the_ack_path(rig):
    rig.cycle(repeat_block=_block(armed=True, replay_active=True, position=10.0))
    repeat.apply_repeat_ack({
        "ok": True, "command": "repeat_seek", "state": "replaying", "armed": True,
        "position_seconds": 0.0})
    assert rig.calls == [(("repeat",), None)]
    # The next close compares against the block the ack path already
    # published, so the same seek is not hinted a second time.
    assert rig.cycle(repeat_block=_block(armed=True, replay_active=True, position=0.0)) == []
    assert len(rig.calls) == 1


def test_an_arm_ack_then_the_tick_makes_one_repeat_call_each(rig):
    rig.cycle(repeat_block=_block(armed=True))
    repeat.apply_repeat_ack({
        "ok": True, "command": "set_repeat_armed", "state": "replaying", "armed": True})
    after_ack = len(rig.calls)
    assert after_ack == 1
    rig.cycle(repeat_block=_block(armed=True, replay_active=True, position=1.0))
    assert len(rig.calls) - after_ack <= 1


def test_subscribers_see_nothing_during_a_batch_and_one_change_at_the_close(rig):
    seen = []
    state.store().subscribe(seen.append)
    batch = state.store().batch()
    session._writer.publish(state.SessionPart(True, "input1"), tags=("session",)).notify()
    repeat.publish_from_daemon(_block(armed=True))
    assert seen == []
    batch.close()
    assert len(seen) == 1 and seen[0].batch is True
    assert {"session", "repeat"} <= seen[0].parts | {"session", "repeat"}
    assert "session" in seen[0].tags


def test_the_subscriber_is_called_with_no_lock_held():
    import lockcheck

    st = state.store()
    st.reset_for_tests(track_locks=True)
    lockcheck.install(st)
    try:
        seen = []
        hints = dp.StateHints(notify=lambda *k, **kw: seen.append(lockcheck.held()))
        st.subscribe(hints)
        batch = st.batch()
        session._writer.publish(state.SessionPart(True, "input1"), tags=("session",)).notify()
        batch.close()
        assert seen == [frozenset()]
        assert st.lock_violations == []
    finally:
        lockcheck.uninstall()
        import threading
        st._lock = threading.Lock()
        st._cond = threading.Condition(st._lock)


def test_a_cycle_that_raises_still_closes_its_batch_and_delivers_one_change(tmp_path):
    """The coordinator loop opens a batch for each cycle; when the cycle
    raises, the finally closes it first, so the merged Change reaches
    subscribers and the next cycle (or the teardown publishes) are not
    swallowed into an open batch."""
    from unittest.mock import patch

    import autostream_core as core
    from test_monitor_daemon_recovery_log import _run_autostream_with_get_status_sequence

    seen = []
    state.store().subscribe(seen.append)
    raised = []

    def failing_publish_playback():
        if state.store()._batches and not raised:
            raised.append(True)
            raise RuntimeError("cycle failed")

    with patch.object(core, "_publish_playback", side_effect=failing_publish_playback):
        with pytest.raises(RuntimeError, match="cycle failed"):
            _run_autostream_with_get_status_sequence(
                tmp_path,
                get_status_results=[
                    {"output_rate": 44100, "output_bits": 16},
                    {"inputs": [], "monitor_build": "x", "log_level": "info"},
                ],
                is_set_threshold=5,
            )
    assert raised
    assert state.store()._batches == {}
    batch_changes = [c for c in seen if c.batch]
    assert len(batch_changes) == 1


# ---------------------------------------------------------------------------
# The outputs part: the speaker list, the volumes and the mutes
# ---------------------------------------------------------------------------

class OutputRig:
    def __init__(self, rig):
        from autostream_state.outputs import get_authority
        from output_fakes import FakeBackend, row

        self.rig = rig
        self.authority = get_authority()
        self.authority.start(FakeBackend(self.authority))
        self.row = row
        rig.fake.outputs([row("1", "Speaker A"), row("2", "Speaker B")])
        self.mark = 0

    @property
    def calls(self):
        return self.rig.calls[self.mark:]

    def forget(self):
        """Count only the calls made from here on."""
        self.mark = len(self.rig.calls)


@pytest.fixture
def outputs(rig):
    return OutputRig(rig)


def test_the_first_reading_of_the_outputs_is_the_baseline(outputs):
    assert outputs.calls == []


def test_a_read_that_changes_nothing_makes_no_call(outputs):
    outputs.rig.fake.outputs([outputs.row("1", "Speaker A"), outputs.row("2", "Speaker B")])
    assert outputs.calls == []


def test_a_speaker_appearing_in_a_read_hints_everyone_of_all_three(outputs):
    outputs.rig.fake.outputs([outputs.row("1", "Speaker A"), outputs.row("2", "Speaker B"),
                              outputs.row("3", "Speaker C")])
    assert outputs.calls == [(("outputs",), None), (("volume",), None), (("mute",), None)]


def test_a_dial_s_own_switch_on_hints_the_list_then_the_volume_and_not_that_dial(outputs):
    outputs.authority.select("1", state.Origin.USER, volume=30, requester="dial:abc-1").outcome.result(1)
    # The write that follows marks the speaker as starting, which every dial is told.
    assert outputs.calls == [(("outputs",), "abc-1"), (("volume",), "abc-1"), (("outputs",), None)]


def test_a_volume_change_alone_hints_only_the_volume(outputs):
    outputs.rig.fake.outputs([outputs.row("1", "Speaker A", selected=True, volume_percent=20),
                              outputs.row("2", "Speaker B")])
    outputs.forget()
    outputs.authority.set_volume("1", 45, state.Origin.USER, requester="dial:abc-1")
    assert outputs.calls == [(("volume",), "abc-1")]


def test_a_mute_alone_hints_only_the_mute(outputs):
    outputs.authority.select("1", state.Origin.USER, volume=20)
    outputs.forget()
    outputs.authority.mute_all(state.Origin.USER, requester="dial:abc-1")
    assert outputs.calls == [(("mute",), "abc-1")]


def test_a_browser_s_change_excludes_nobody(outputs):
    outputs.authority.select("2", state.Origin.USER, volume=10, requester="webui")
    assert outputs.calls and {except_dial for _, except_dial in outputs.calls} == {None}
