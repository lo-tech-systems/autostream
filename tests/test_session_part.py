"""tests/test_session_part.py

The playback session as a part of the state snapshot: the coordinator's
per-cycle publish, the edge tag, the replay note from the repeat ack and the
now-playing republish request.
"""
from __future__ import annotations

import sys
from pathlib import Path

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_session as session
import autostream_state as state


def snap():
    return state.store().snapshot()


def collect():
    seen = []
    state.store().subscribe(seen.append)
    return seen


def test_the_session_starts_idle():
    assert snap().session == state.SessionPart(False, None)


def test_publish_sets_active_and_source():
    session.publish(True, "input2")
    assert snap().session.as_dict() == {"active": True, "source": "input2"}
    session.publish(False, None)
    assert snap().session.as_dict() == {"active": False, "source": None}


def test_publish_without_an_edge_carries_no_tag_and_a_repeat_publish_is_silent():
    seen = collect()
    session.publish(True, "input1")
    session.publish(True, "input1")
    assert [c.tags for c in seen] == [frozenset()]
    assert [c.parts for c in seen] == [frozenset({"session"})]


def test_publish_on_an_edge_carries_the_session_tag_even_when_the_value_is_unchanged():
    session.publish(True, "input1")
    seen = collect()
    session.publish(True, "input1", edge=True)
    assert len(seen) == 1
    assert seen[0].tags == frozenset({"session"})
    assert seen[0].parts == frozenset()


def test_note_replay_started_makes_the_session_active_as_replay():
    session.note_replay_started()
    assert snap().session.as_dict() == {"active": True, "source": "replay"}


def test_note_replay_started_does_not_overwrite_an_active_session():
    session.publish(True, "input1")
    version = snap().version
    seen = collect()
    session.note_replay_started()
    assert snap().session.source == "input1"
    assert snap().version == version
    assert seen == []


def test_the_next_cycle_overwrites_the_note():
    session.note_replay_started()
    session.publish(False, None)
    assert snap().session.active is False


def test_the_republish_request_is_consumed_once():
    assert session.consume_nowplaying_republish() is False
    session.request_nowplaying_republish()
    session.request_nowplaying_republish()
    assert session.consume_nowplaying_republish() is True
    assert session.consume_nowplaying_republish() is False


def test_reset_for_tests_clears_the_republish_request():
    session.request_nowplaying_republish()
    session.reset_for_tests()
    assert session.consume_nowplaying_republish() is False
