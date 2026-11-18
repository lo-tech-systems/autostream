"""tests/test_repeat_part.py

The repeat block as a part of the state snapshot: the coordinator's per-cycle
publish, the ack overlay from a request thread, their ordering, and the
session note that follows an ack, and the tag and requester the ack's change carries.
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path
from unittest.mock import patch

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_repeat as repeat
import autostream_state as state


def snap():
    return state.store().snapshot()


def collect():
    seen = []
    state.store().subscribe(seen.append)
    return seen


def block(*, armed=False, replay_active=False, position=0.0, origin_input=1):
    return {
        "enabled": True,
        "armed": armed,
        "recording": {"active": False, "seconds": 120.0, "origin_input": origin_input},
        "replay": {
            "active": replay_active, "fading_out": False,
            "position_seconds": position, "duration_seconds": 120.0 if replay_active else 0.0,
        },
    }


def ack(command="repeat_seek", state_name="replaying", *, armed=True, position=0.0):
    return {"type": "ack", "command": command, "ok": True, "state": state_name,
            "armed": armed, "position_seconds": position}


def apply(a, **kw):
    with patch("autostream_repeat._rearm_replay_identification") as rearm, \
         patch("autostream_repeat._announce_replay_playing") as announce:
        result = repeat.apply_repeat_ack(a, **kw)
    return result, rearm, announce


def test_the_part_starts_without_a_block():
    assert snap().repeat.block is None


def test_the_daemon_block_is_published_verbatim_and_frozen():
    b = block(armed=True)
    repeat.publish_from_daemon(b)
    assert snap().repeat.block == b
    assert isinstance(snap().repeat.block, state.FrozenDict)
    assert snap().repeat.block is not b


def test_a_non_dict_block_publishes_none():
    repeat.publish_from_daemon(block())
    repeat.publish_from_daemon("not-a-dict")
    assert snap().repeat.block is None


def test_a_daemon_block_that_changes_nothing_shown_publishes_no_change():
    repeat.publish_from_daemon(block(replay_active=True, position=5.0))
    seen = collect()
    repeat.publish_from_daemon(block(replay_active=True, position=6.0))
    assert seen == []
    assert snap().repeat.block["replay"]["position_seconds"] == 6.0


def test_an_ack_overlay_publishes_one_change_tagged_repeat_with_its_requester():
    repeat.publish_from_daemon(block())
    seen = collect()
    result, rearm, announce = apply(ack("set_repeat_armed", armed=True), requester="dial:abc")
    assert result is not None
    assert [c.parts for c in seen] == [frozenset({"repeat"}), frozenset({"session"})]
    assert seen[0].tags == frozenset({"repeat"}) and seen[0].requester == "dial:abc"
    assert snap().repeat.block["replay"]["active"] is True
    rearm.assert_called_once_with(1, in_session=False)
    announce.assert_called_once_with()


def test_an_ack_with_no_block_published_changes_nothing():
    seen = collect()
    a = ack()
    result, rearm, announce = apply(a)
    assert result is a
    assert seen == []
    assert snap().repeat.block is None
    rearm.assert_not_called()


def test_a_rejected_or_unknown_ack_changes_nothing():
    repeat.publish_from_daemon(block())
    seen = collect()
    for bad in (dict(ack(), ok=False), dict(ack(), state="bogus"),
                dict(ack(), command="set_log_level"), None):
        apply(bad)
    assert seen == []


def test_a_replaying_ack_notes_the_session_as_replay():
    repeat.publish_from_daemon(block())
    apply(ack("set_repeat_armed"))
    assert snap().session.as_dict() == {"active": True, "source": "replay"}


def test_a_hold_ack_leaves_the_session_alone():
    repeat.publish_from_daemon(block(replay_active=True))
    apply(ack("set_repeat_armed", "hold", armed=False))
    assert snap().session.active is False


def test_a_seek_that_moves_nothing_shown_still_publishes_a_change_tagged_repeat():
    repeat.publish_from_daemon(block(armed=True, replay_active=True, position=5.0))
    state.store().publish_for_tests("session", state.SessionPart(True, "replay"))
    seen = collect()
    _, rearm, announce = apply(ack(position=30.0))
    assert [c.tags for c in seen] == [frozenset({"repeat"})]
    assert snap().repeat.block["replay"]["position_seconds"] == 30.0
    rearm.assert_called_once_with(1, in_session=True)
    announce.assert_not_called()


def test_the_overlay_does_not_mutate_the_published_block():
    repeat.publish_from_daemon(block())
    before = snap().repeat.block
    apply(ack())
    assert before["replay"]["active"] is False
    assert snap().repeat.block is not before


def test_a_daemon_publish_waits_for_an_overlay_in_flight_and_lands_last():
    repeat.publish_from_daemon(block())
    entered = threading.Event()
    release = threading.Event()
    real = repeat._overlay_repeat_status_from_ack

    def slow(status, a):
        entered.set()
        release.wait(5)
        return real(status, a)

    daemon_block = block(armed=False)
    with patch("autostream_repeat._overlay_repeat_status_from_ack", slow), \
         patch("autostream_repeat._rearm_replay_identification"), \
         patch("autostream_repeat._announce_replay_playing"):
        t1 = threading.Thread(target=lambda: repeat.apply_repeat_ack(ack("set_repeat_armed")))
        t1.start()
        assert entered.wait(5)
        t2 = threading.Thread(target=lambda: repeat.publish_from_daemon(daemon_block))
        t2.start()
        t2.join(0.1)
        assert t2.is_alive()
        release.set()
        t1.join(5)
        t2.join(5)
    assert snap().repeat.block == daemon_block
