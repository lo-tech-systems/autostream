"""tests/test_repeat_intents.py

The repeat arm, stop and seek intents: the seek limit for every origin, the
ack folded into the published repeat block with the requester, and the
reply the routes build from the result.
"""
from __future__ import annotations

import contextlib
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_intents.table as table
import autostream_monitor_control as control
import autostream_state as state
from autostream_intents import Intent, Origin, submit

ACK = {"type": "ack", "command": "repeat_seek", "ok": True, "state": "replaying",
       "armed": True, "position_seconds": 0.0}


def _seek(requester="dial:abc", origin=Origin.USER, position=0.0):
    return submit(Intent("repeat.seek", {"position": position}, origin, requester))


@pytest.fixture
def transport():
    with patch("autostream_monitor_control.send_live_repeat_transport", return_value=ACK) as mock:
        yield mock


def test_a_second_seek_inside_a_second_is_refused_whoever_asks(transport):
    now = [100.0]
    table.set_clock_for_tests(lambda: now[0])
    assert _seek("dial:abc").ok is True
    refused = _seek("peer:other")
    assert (refused.ok, refused.error) == (False, "rate_limited")
    assert transport.call_count == 1
    now[0] = 101.5
    assert _seek("webui").ok is True
    assert transport.call_count == 2


def test_stop_is_never_limited(transport):
    table.set_clock_for_tests(lambda: 100.0)
    for _ in range(3):
        assert submit(Intent("repeat.transport", {"action": "stop"}, Origin.USER, "dial:abc")).ok
    assert transport.call_count == 3
    transport.assert_called_with("stop", requester="dial:abc")


def test_a_seek_and_a_stop_do_not_share_a_limit(transport):
    table.set_clock_for_tests(lambda: 100.0)
    assert _seek().ok
    assert submit(Intent("repeat.transport", {"action": "stop"}, Origin.USER, "dial:abc")).ok


@pytest.mark.parametrize("position", [-1.0, 1e7 + 1, float("nan"), True, "5"])
def test_a_position_outside_the_range_is_refused_before_the_daemon(transport, position):
    reply = _seek(position=position)
    assert (reply.ok, reply.error) == (False, "invalid_position")
    transport.assert_not_called()


def test_arm_needs_a_real_boolean(transport):
    for bad in (1, "true", None):
        reply = submit(Intent("repeat.arm", {"armed": bad}, Origin.USER, "webui"))
        assert (reply.ok, reply.error) == (False, "invalid_armed")


def test_the_reply_carries_the_ack_and_an_unreachable_daemon_gives_none():
    with patch("autostream_monitor_control.set_live_repeat_armed_ack", return_value=ACK):
        reply = submit(Intent("repeat.arm", {"armed": True}, Origin.USER, "webui"))
    assert reply.ok is True and reply.result["ack"] is ACK
    with patch("autostream_monitor_control.set_live_repeat_armed_ack", return_value=None):
        reply = submit(Intent("repeat.arm", {"armed": True}, Origin.USER, "webui"))
    assert reply.ok is False and reply.error == "backend_unavailable"
    assert reply.result["ack"] is None


def test_a_refusal_by_the_daemon_is_not_ok_and_names_its_error():
    refused = {"ok": False, "error": "no_recording", "state": "idle", "armed": False}
    with patch("autostream_monitor_control.send_live_repeat_transport", return_value=refused):
        reply = submit(Intent("repeat.transport", {"action": "stop"}, Origin.USER, "webui"))
    assert (reply.ok, reply.error) == (False, "no_recording")
    assert reply.result["ack"] is refused


@contextlib.contextmanager
def _daemon(client):
    yield client


def test_the_requester_reaches_the_change_the_ack_publishes():
    from fake_store import FakeStore
    FakeStore().repeat({
        "enabled": True, "armed": True,
        "recording": {"active": False, "seconds": 10.0, "origin_input": 1},
        "replay": {"active": True, "fading_out": False,
                   "position_seconds": 1.0, "duration_seconds": 10.0},
    })
    client = MagicMock()
    client.repeat_seek.return_value = dict(ACK, position_seconds=4.0)
    seen = []
    state.store().subscribe(seen.append)
    with patch("autostream_monitor_client._connected_monitor", lambda path=None: _daemon(client)), \
         patch("autostream_repeat._rearm_replay_identification"):
        reply = _seek("dial:abc", position=4.0)
    assert reply.ok is True
    client.repeat_seek.assert_called_once_with(4.0)
    changes = [c for c in seen if "repeat" in c.tags]
    assert len(changes) == 1
    assert changes[0].requester == "dial:abc"


def test_the_lock_on_the_monitor_connection_is_released_before_the_change_is_published():
    published_while_open = []
    open_ = [False]

    @contextlib.contextmanager
    def connected(path=None):
        open_[0] = True
        try:
            yield MagicMock(repeat_stop=MagicMock(return_value=ACK))
        finally:
            open_[0] = False

    with patch("autostream_monitor_client._connected_monitor", connected), \
         patch("autostream_repeat.apply_repeat_ack",
               side_effect=lambda ack, requester=None: published_while_open.append(open_[0]) or ack):
        control.send_live_repeat_transport("stop", requester="webui")
    assert published_while_open == [False]
