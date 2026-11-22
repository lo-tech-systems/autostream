"""tests/test_repeat_idle.py

Repeat is stopped once a replay, or a live session with repeat armed, has
gone to no speaker for five minutes, or at once after the receiver Pause
timeout leaves no speaker on.
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core"))

import autostream_repeat_idle as repeat_idle
from autostream_state import Origin
from output_fakes import group_row, row


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def w():
    clock = Clock()
    watch = repeat_idle.NoSpeakerRepeatStop(clock)
    return clock, watch


def at(w, t, *, speaker_on=False, playing=True, stop_wanted=True):
    clock, watch = w
    clock.t = 1000.0 + t
    return watch.check(speaker_on=speaker_on, playing=playing, stop_wanted=stop_wanted)


class TestFiveMinutes:
    def test_stops_once_after_five_minutes_with_no_speaker(self, w):
        assert not at(w, 0)
        assert not at(w, 299)
        assert at(w, 300)
        assert not at(w, 302)
        assert not at(w, 600)

    def test_a_speaker_coming_on_starts_the_count_again(self, w):
        at(w, 0)
        at(w, 200, speaker_on=True)
        assert not at(w, 202)              # off again: a new count starts here
        assert not at(w, 300)
        assert not at(w, 501)
        assert at(w, 502)

    def test_nothing_happens_while_a_speaker_is_on(self, w):
        for t in (0, 300, 900):
            assert not at(w, t, speaker_on=True)

    def test_nothing_playing_is_never_stopped(self, w):
        # Repeat armed between sessions, with no record on yet
        for t in (0, 300, 3600):
            assert not at(w, t, playing=False)

    def test_a_live_session_without_repeat_is_left_alone(self, w):
        for t in (0, 300, 900):
            assert not at(w, t, stop_wanted=False)

    def test_arming_repeat_later_gives_it_its_own_five_minutes(self, w):
        at(w, 0, stop_wanted=False)
        assert not at(w, 400, stop_wanted=False)
        assert not at(w, 402)
        assert not at(w, 701)
        assert at(w, 702)

    def test_arming_again_after_a_stop_is_stopped_again(self, w):
        at(w, 0)
        assert at(w, 300)
        at(w, 302, stop_wanted=False)      # the stop disarmed it
        assert not at(w, 400)              # armed again, still no speaker
        assert not at(w, 699)
        assert at(w, 700)

    def test_a_new_replay_after_a_quiet_spell_is_a_new_stretch(self, w):
        at(w, 0)
        assert at(w, 300)
        at(w, 302, playing=False, stop_wanted=False)   # held, nothing playing
        assert not at(w, 400)                          # re-armed: a replay starts
        assert at(w, 700)


class TestNudge:
    def test_a_nudge_stops_at_the_next_check(self, w):
        _, watch = w
        at(w, 0)
        watch.nudge()
        assert at(w, 2)
        assert watch.last_was_nudge
        assert not at(w, 400)

    def test_a_nudge_with_a_speaker_still_on_is_used_up(self, w):
        _, watch = w
        watch.nudge()
        assert not at(w, 0, speaker_on=True)
        assert not at(w, 2)
        assert not at(w, 301)
        assert at(w, 302)
        assert not watch.last_was_nudge

    def test_a_nudge_with_repeat_off_is_used_up(self, w):
        _, watch = w
        watch.nudge()
        assert not at(w, 0, stop_wanted=False)
        assert not at(w, 2)                # armed now: waits the full time
        assert at(w, 302)

    def test_a_nudge_from_another_thread_is_seen(self, w):
        import threading
        _, watch = w
        at(w, 0)
        t = threading.Thread(target=watch.nudge)
        t.start()
        t.join()
        assert at(w, 2)


class TestRunCheck:
    @pytest.fixture
    def watch(self):
        clock = Clock()
        yield clock, repeat_idle.reset_for_tests(clock)
        repeat_idle.reset_for_tests()

    @staticmethod
    def _state(fake_store, *, selected=False, armed=False, replay=False, fading=False, capturing=False):
        fake_store.outputs([row(1, selected=selected)])
        fake_store.repeat({"enabled": True, "armed": armed,
                           "replay": {"active": replay, "fading_out": fading}})
        fake_store.inputs([fake_store.input_entry(1, capturing=capturing)])

    def test_a_replay_to_no_speaker_is_stopped_through_the_policy(self, fake_store, watch, caplog):
        clock, _ = watch
        self._state(fake_store, replay=True)
        with patch.object(repeat_idle, "submit") as sub:
            sub.return_value.ok = True
            repeat_idle.run_check()
            clock.t += 300
            with caplog.at_level(logging.INFO, logger="autostream.repeat_idle"):
                repeat_idle.run_check()
        intent = sub.call_args.args[0]
        assert (intent.name, intent.args, intent.origin) == ("repeat.transport", {"action": "stop"}, Origin.POLICY)
        assert "No speaker on for 5 minutes: repeat stopped" in caplog.text

    def test_a_live_session_with_repeat_armed_is_stopped(self, fake_store, watch):
        clock, _ = watch
        self._state(fake_store, armed=True, capturing=True)
        with patch.object(repeat_idle, "submit") as sub:
            repeat_idle.run_check()
            clock.t += 300
            repeat_idle.run_check()
        assert sub.call_count == 1

    def test_a_fading_replay_counts_as_playing(self, fake_store, watch):
        clock, _ = watch
        self._state(fake_store, fading=True)
        with patch.object(repeat_idle, "submit") as sub:
            repeat_idle.run_check()
            clock.t += 300
            repeat_idle.run_check()
        assert sub.call_count == 1

    def test_a_selected_speaker_without_a_session_keeps_it_playing(self, fake_store, watch):
        # Upstream OwnTone: its rows carry no session, so a selected speaker
        # counts as taking the audio, as before
        clock, _ = watch
        self._state(fake_store, selected=True, replay=True)
        with patch.object(repeat_idle, "submit") as sub:
            repeat_idle.run_check()
            clock.t += 600
            repeat_idle.run_check()
        sub.assert_not_called()

    @staticmethod
    def _replay_to(fake_store, session_state):
        """A replay with one selected speaker whose row has a session."""
        fake_store.outputs([group_row(1, session_state, selected=True)])
        fake_store.repeat({"enabled": True, "armed": False, "replay": {"active": True, "fading_out": False}})
        fake_store.inputs([fake_store.input_entry(1, capturing=False)])

    @pytest.mark.parametrize("state", ["streaming", "connected"])
    def test_a_speaker_taking_the_audio_keeps_it_playing(self, fake_store, watch, state):
        clock, _ = watch
        self._replay_to(fake_store, state)
        with patch.object(repeat_idle, "submit") as sub:
            repeat_idle.run_check()
            clock.t += 600
            repeat_idle.run_check()
        sub.assert_not_called()

    @pytest.mark.parametrize("state", ["failed", "connecting", "stopped", "password"])
    def test_a_selected_speaker_not_taking_the_audio_counts_as_off(self, fake_store, watch, state):
        # A default speaker kept wanted while it is retried, or one that fails
        clock, _ = watch
        self._replay_to(fake_store, state)
        with patch.object(repeat_idle, "submit") as sub:
            repeat_idle.run_check()
            clock.t += 300
            repeat_idle.run_check()
        assert sub.call_count == 1

    def test_retries_that_never_reach_the_speaker_do_not_reset_the_count(self, fake_store, watch):
        # Each retry reads connecting for a few seconds, then failed again
        clock, _ = watch
        start = clock.t
        with patch.object(repeat_idle, "submit") as sub:
            while clock.t - start < 300:
                self._replay_to(fake_store, "connecting" if (clock.t - start) % 30 < 4 else "failed")
                repeat_idle.run_check()
                clock.t += 2
            self._replay_to(fake_store, "failed")
            repeat_idle.run_check()
        assert sub.call_count == 1

    def test_armed_while_idle_is_left_alone(self, fake_store, watch):
        clock, _ = watch
        self._state(fake_store, armed=True)
        with patch.object(repeat_idle, "submit") as sub:
            repeat_idle.run_check()
            clock.t += 3600
            repeat_idle.run_check()
        sub.assert_not_called()

    def test_a_nudge_logs_the_pause_timeout(self, fake_store, watch, caplog):
        self._state(fake_store, replay=True)
        repeat_idle.nudge()
        with patch.object(repeat_idle, "submit"), \
             caplog.at_level(logging.INFO, logger="autostream.repeat_idle"):
            repeat_idle.run_check()
        assert "Pause timeout left no speaker on: repeat stopped" in caplog.text

    def test_a_failure_never_escapes(self, fake_store, watch, caplog):
        self._state(fake_store, replay=True)
        repeat_idle.nudge()
        with patch.object(repeat_idle, "submit", side_effect=RuntimeError("socket")):
            repeat_idle.run_check()
        assert "repeat no-speaker check failed" in caplog.text

    def test_no_repeat_block_is_nothing_playing(self, fake_store, watch):
        clock, _ = watch
        fake_store.outputs([row(1)])
        fake_store.repeat(None)
        fake_store.inputs([])
        with patch.object(repeat_idle, "submit") as sub:
            repeat_idle.run_check()
            clock.t += 600
            repeat_idle.run_check()
        sub.assert_not_called()
