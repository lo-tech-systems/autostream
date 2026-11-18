"""tests/test_protocol_access.py

What a named client (a dial or a peer) may do, and how a stream tells it: the
hub's one rule, its memo, the ?client= validation, and the access event on a
real server.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_dials as dials
import autostream_logging as log_setup
from autostream_intents import Role
from stream_helpers import Publisher, RealServer, wait_for
import webui.protocol.hub as proto_hub

DIAL = "dial:0123456789abcdef0123"
PEER = "peer:aabbccddeeff00112233"


@pytest.fixture
def server(monkeypatch):
    log_setup.reset_for_tests()
    s = RealServer(monkeypatch)
    yield s
    s.close()


@pytest.fixture
def publish(server):
    return Publisher(server.store)


@pytest.fixture
def verdict(monkeypatch):
    """What dials.json says: a one-item list holding the verdict, with a call
    counter."""
    box = {"value": dials.AUTH_AUTHORIZED, "calls": 0}

    def lookup(uuid):
        box["calls"] += 1
        return box["value"]

    monkeypatch.setattr(proto_hub.dials, "dial_authorization", lookup)
    return box


def access_events(client) -> list:
    out = []
    for block in client.buf.split(b"\n\n"):
        lines = block.decode("ascii", "replace").split("\n")
        if "event: access" in lines:
            data = next(line for line in lines if line.startswith("data: "))
            out.append(json.loads(data[len("data: "):]))
    return out


# -----------------------------------------------------------------------------
# hub.access: the table of the rule
# -----------------------------------------------------------------------------

class TestRule:
    def test_an_unconfigured_appliance_gives_nobody_a_role(self, server, verdict):
        for client in (DIAL, PEER):
            assert server.hub.access(client, configured=False) == (Role.NONE, "unconfigured")

    def test_a_dial_in_the_store_is_playback(self, server, verdict):
        assert server.hub.access(DIAL, configured=True) == (Role.PLAYBACK, None)

    def test_a_dial_not_in_the_store_is_not_authorised(self, server, verdict):
        verdict["value"] = dials.AUTH_NOT_AUTHORIZED
        assert server.hub.access(DIAL, configured=True) == (Role.NONE, "dial_not_authorized")

    def test_an_unreadable_store_is_auth_unavailable(self, server, verdict):
        verdict["value"] = dials.AUTH_UNAVAILABLE
        assert server.hub.access(DIAL, configured=True) == (Role.NONE, "auth_unavailable")

    def test_a_peer_is_playback_when_control_is_on(self, server):
        server.hub._peer_control = lambda: True
        assert server.hub.access(PEER, configured=True) == (Role.PLAYBACK, None)

    def test_a_peer_is_refused_when_control_is_off(self, server):
        server.hub._peer_control = lambda: False
        assert server.hub.access(PEER, configured=True) == (Role.NONE, "control_disabled")

    def test_a_peer_is_refused_when_the_setting_is_unreadable_or_absent(self, server):
        assert server.hub.access(PEER, configured=True) == (Role.NONE, "control_disabled")

        def broken():
            raise RuntimeError("no settings")

        server.hub._peer_control = broken
        assert server.hub.access(PEER, configured=True) == (Role.NONE, "control_disabled")

    def test_the_caller_says_whether_the_appliance_is_configured(self, server, verdict, publish):
        # The appliance part still says unconfigured; the caller knows better.
        assert server.store.snapshot().appliance.configured is False
        assert server.hub.access(DIAL, configured=True).role is Role.PLAYBACK

    def test_a_name_that_is_not_a_client_has_no_role(self, server):
        assert server.hub.access("dial:nope", configured=True) == (Role.NONE, "invalid_client")


class TestMemo:
    def test_a_dial_answer_is_asked_once_per_generation(self, server, verdict, publish):
        for _ in range(3):
            server.hub.access(DIAL, configured=True)
        assert verdict["calls"] == 1
        publish("dials")
        server.hub.access(DIAL, configured=True)
        assert verdict["calls"] == 2

    def test_the_answer_follows_a_revoke_at_the_next_generation(self, server, verdict, publish):
        assert server.hub.access(DIAL, configured=True).role is Role.PLAYBACK
        verdict["value"] = dials.AUTH_NOT_AUTHORIZED
        assert server.hub.access(DIAL, configured=True).role is Role.PLAYBACK   # remembered
        publish("dials")
        assert server.hub.access(DIAL, configured=True) == (Role.NONE, "dial_not_authorized")

    def test_auth_unavailable_is_never_remembered(self, server, verdict):
        verdict["value"] = dials.AUTH_UNAVAILABLE
        server.hub.access(DIAL, configured=True)
        verdict["value"] = dials.AUTH_AUTHORIZED
        assert server.hub.access(DIAL, configured=True) == (Role.PLAYBACK, None)
        assert verdict["calls"] == 2

    def test_unconfigured_does_not_reach_the_store(self, server, verdict):
        server.hub.access(DIAL, configured=False)
        assert verdict["calls"] == 0

    def test_the_memo_stays_bounded(self, server, verdict):
        for n in range(proto_hub._MEMO_MAX + 20):
            server.hub.access(f"dial:{n:020x}", configured=True)
        assert len(server.hub._access_memo) <= proto_hub._MEMO_MAX


# -----------------------------------------------------------------------------
# ?client= on the stream
# -----------------------------------------------------------------------------

class TestClientParam:
    @pytest.mark.parametrize("value", [
        "dial", "dial:", "dial:XYZ", "dial:0123", "bob:0123456789abcdef0123",
        "dial:0123456789ABCDEF0123", "dial:0123456789abcdef01234",
    ])
    def test_a_malformed_client_is_refused_before_any_stream(self, server, value):
        status, body = server.get(f"/api/v1/events?client={value}")
        assert status == 400
        assert json.loads(body)["error"] == "invalid_client"
        assert server.hub.client_count() == 0

    def test_no_client_means_no_access_event(self, server, publish):
        publish("appliance")
        c = server.connect()
        try:
            assert c.pull_until(b"retry: 2000")
            c.pull(0.3)
            assert access_events(c) == []
        finally:
            c.close()


# -----------------------------------------------------------------------------
# The access event
# -----------------------------------------------------------------------------

def open_as(server, client):
    c = server.connect(f"/api/v1/events?client={client}")
    assert c.pull_until(b"event: access")
    return c


class TestAccessEvent:
    def test_it_comes_right_after_retry_and_before_the_change_event(self, server, verdict, publish):
        publish("appliance")
        c = open_as(server, DIAL)
        try:
            assert c.pull_until(b"event: change")
            text = c.buf.decode("ascii", "replace")
            assert text.index("retry: 2000") < text.index("event: access") < text.index("event: change")
            assert access_events(c) == [{"client": DIAL, "role": "playback", "reason": None}]
        finally:
            c.close()

    def test_an_unconfigured_appliance_says_so(self, server, verdict):
        c = open_as(server, DIAL)
        try:
            assert access_events(c) == [{"client": DIAL, "role": "none", "reason": "unconfigured"}]
        finally:
            c.close()

    def test_a_dial_that_is_not_authorised_is_told_and_still_gets_the_parts(self, server, verdict, publish):
        verdict["value"] = dials.AUTH_NOT_AUTHORIZED
        publish("appliance")
        publish("session")
        c = open_as(server, DIAL)
        try:
            assert c.pull_until(b"event: change")
            assert access_events(c) == [{"client": DIAL, "role": "none", "reason": "dial_not_authorized"}]
            event = server_events(c)[0]
            assert "session" in event["parts"] and "appliance" in event["parts"]
        finally:
            c.close()

    def test_it_is_sent_again_when_the_dials_generation_moves(self, server, verdict, publish):
        publish("appliance")
        verdict["value"] = dials.AUTH_NOT_AUTHORIZED
        c = open_as(server, DIAL)
        try:
            verdict["value"] = dials.AUTH_AUTHORIZED
            publish("dials")
            assert wait_for(lambda: c.pull(0.1) or len(access_events(c)) == 2)
            assert [e["role"] for e in access_events(c)] == ["none", "playback"]
        finally:
            c.close()

    def test_it_is_sent_again_when_the_appliance_becomes_configured(self, server, verdict, publish):
        publish.set_appliance(configured=False)
        c = open_as(server, DIAL)
        try:
            publish.set_appliance(configured=True)
            assert wait_for(lambda: c.pull(0.1) or len(access_events(c)) == 2)
            assert [e["reason"] for e in access_events(c)] == ["unconfigured", None]
        finally:
            c.close()

    def test_a_transient_auth_unavailable_is_corrected_on_the_next_wake(self, server, verdict, publish):
        publish("appliance")
        verdict["value"] = dials.AUTH_UNAVAILABLE
        c = open_as(server, DIAL)
        try:
            verdict["value"] = dials.AUTH_AUTHORIZED
            publish("session")                      # any change; no authorisation in between
            assert wait_for(lambda: c.pull(0.1) or len(access_events(c)) == 2)
            assert [e["reason"] for e in access_events(c)] == ["auth_unavailable", None]
        finally:
            c.close()

    def test_an_unchanged_answer_is_not_repeated(self, server, verdict, publish):
        publish("appliance")
        c = open_as(server, DIAL)
        try:
            for _ in range(3):
                publish("session")
            c.pull(0.8)
            assert len(access_events(c)) == 1
        finally:
            c.close()

    def test_a_transient_failure_is_corrected_on_the_heartbeat(self, server, verdict, publish, monkeypatch):
        import webui.protocol.stream as proto_stream
        monkeypatch.setattr(proto_stream, "HEARTBEAT_S", 0.3)
        monkeypatch.setattr(proto_stream, "LIVENESS_S", 0.1)
        publish("appliance")
        verdict["value"] = dials.AUTH_UNAVAILABLE
        c = open_as(server, DIAL)
        try:
            verdict["value"] = dials.AUTH_AUTHORIZED
            assert wait_for(lambda: c.pull(0.1) or len(access_events(c)) == 2, 5.0)
        finally:
            c.close()

    def test_a_peer_is_told_playback_or_control_disabled(self, server, publish):
        publish("appliance")
        server.hub._peer_control = lambda: False
        c = open_as(server, PEER)
        try:
            assert access_events(c) == [{"client": PEER, "role": "none", "reason": "control_disabled"}]
        finally:
            c.close()
        server.hub._peer_control = lambda: True
        c = open_as(server, PEER)
        try:
            assert access_events(c) == [{"client": PEER, "role": "playback", "reason": None}]
        finally:
            c.close()


def server_events(client) -> list:
    out = []
    for block in client.buf.split(b"\n\n"):
        lines = block.decode("ascii", "replace").split("\n")
        if "event: change" in lines:
            data = next(line for line in lines if line.startswith("data: "))
            out.append(json.loads(data[len("data: "):]))
    return out
