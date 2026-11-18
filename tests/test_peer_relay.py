"""tests/test_peer_relay.py

The relay of another appliance's state, change stream and intents, through a
real server and a fake appliance: the answer for each thing an appliance id
can name, the state body, the stream (resume, boot change, access, limits, the
shared part cache) and the intents (CSRF, the caller, the local checks).
"""
from __future__ import annotations

import json
import socket
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_logging as log_setup
from autostream_protocol import PROTOCOL
from fake_peer_server import BOOT
from relay_rig import OWN_ID, RelayRig
from stream_helpers import wait_for
import webui.peer.relay as relay
import webui.protocol.hub as proto_hub


@pytest.fixture
def rig(monkeypatch):
    log_setup.reset_for_tests()
    made = []

    def make(**kw):
        r = RelayRig(monkeypatch, **kw)
        made.append(r)
        return r
    yield make
    for r in made:
        r.close()


def ready(r):
    assert r.ready()
    return r


def wait_closed(c, timeout: float = 3.0) -> bool:
    """Whether the server closes the connection within *timeout*."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        c.sock.settimeout(0.2)
        try:
            chunk = c.sock.recv(65536)
        except socket.timeout:
            continue
        except OSError:
            return True
        if not chunk:
            return True
        c.buf += chunk
    return False


class TestResolution:
    def test_this_appliances_own_setting_off_is_control_disabled(self, rig):
        r = ready(rig())
        r.control = False
        status, body = r.get("/state")
        assert (status, body["error"]) == (403, "control_disabled")

    @pytest.mark.parametrize("kind,status,error", [
        ("unknown", 200, "unknown_appliance"),
        ("invalid", 200, "unknown_appliance"),
        ("bound", 200, "bound_appliance"),
        ("control_off", 403, "control_disabled"),
        ("conflict", 409, "appliance_conflict"),
        ("unconfigured", 409, "appliance_unconfigured"),
    ])
    def test_each_resolution_has_its_answer(self, rig, kind, status, error):
        r = ready(rig(kind=kind))
        got, body = r.get("/state")
        assert got == status and body["error"] == error
        if status == 200:           # a 404 reaches the browser as a tunnelled reply
            assert body["error_status"] == 404

    def test_a_malformed_id_is_unknown(self, rig):
        r = ready(rig())
        status, raw = r.server.get("/api/v1/peers/nope/state")
        assert json.loads(raw)["error"] == "unknown_appliance"

    def test_a_peer_on_another_protocol_is_protocol_mismatch(self, rig):
        r = rig(peer_protocol=PROTOCOL + 1)
        assert wait_for(lambda: not r.client.snapshot().protocol_ok)
        status, body = r.get("/state")
        assert (status, body["error"]) == (409, "protocol_mismatch")

    def test_an_unreachable_peer_is_retryable(self, rig):
        r = ready(rig())
        r.peer.stop()
        assert wait_for(lambda: not r.client.snapshot().reachable)
        status, body = r.get("/state")
        assert body["error"] == "peer_unreachable" and body["error_status"] == 503
        assert body["retryable"] is True

    def test_an_unknown_path_under_the_peer_is_not_found(self, rig):
        r = ready(rig())
        status, body = r.get("/elsewhere")
        assert body["error"] == "not_found"


class TestState:
    def test_the_body_is_the_held_state_and_makes_no_request(self, rig):
        r = ready(rig(parts={"outputs": {"units": [1]}}))
        status, body = r.get("/state")
        assert status == 200
        assert set(body) == {"boot", "version", "protocol", "clients", "time", "part_versions", "parts"}
        assert body["boot"] == BOOT and body["version"] == r.peer.version
        assert body["parts"]["outputs"] == {"units": [1]} and body["clients"] is None

        def state_reads():
            return len([p for m, p in r.peer.requests if p.startswith("/api/v1/state")])
        before = state_reads()
        r.get("/state")
        assert state_reads() == before

    def test_the_relayed_time_is_this_appliances_clock(self, rig, monkeypatch):
        r = ready(rig())
        monkeypatch.setattr(relay, "time", SimpleNamespace(time=lambda: 1234.5))
        _, body = r.get("/state")
        assert body["time"] == 1234.5

    def test_parts_are_read_live_from_the_peer(self, rig):
        r = ready(rig(parts={"inputs": {"vu": 1}}))
        r.peer.parts["inputs"] = {"vu": 7}              # changed without an event
        status, body = r.get("/state?parts=inputs")
        assert status == 200 and body["parts"] == {"inputs": {"vu": 7}}
        assert ("GET", "/api/v1/state?parts=inputs") in r.peer.requests

    def test_a_peers_400_passes_through(self, rig):
        r = ready(rig())
        status, body = r.get("/state?parts=nothere")
        assert (status, body["error"]) == (400, "unknown_part")

    def test_a_part_name_that_cannot_be_one_is_refused(self, rig):
        r = ready(rig())
        status, body = r.get("/state?parts=a%2Fb")
        assert (status, body["error"]) == (400, "unknown_part")

    def test_a_peer_that_cannot_be_read_is_unreachable(self, rig):
        r = ready(rig(parts={"inputs": {}}))
        r.peer.stop()
        status, body = r.get("/state?parts=inputs")
        assert body["error"] == "peer_unreachable"


class TestEvents:
    def test_the_stream_is_the_peers_with_its_ids(self, rig):
        r = ready(rig())
        c = r.server.connect(r.base + "/events")
        try:
            assert c.pull_until(b"event: access")
            r.peer.push({"session": {"active": True}})
            assert c.pull_until(b'"active":true')
            assert f"id: {BOOT}-{r.peer.version}" in c.buf.decode("ascii")
        finally:
            c.close()

    def test_a_reconnect_with_last_event_id_resumes_against_the_peers_versions(self, rig):
        r = ready(rig(parts={"outputs": {"units": []}}))
        v0 = r.peer.version
        r.peer.push({"session": {"active": True}})
        assert wait_for(lambda: r.client.snapshot().version == v0 + 1)
        c = r.server.connect(r.base + "/events", headers={"Last-Event-ID": f"{BOOT}-{v0}"})
        try:
            assert c.pull_until(b"event: change")
            (event,) = c.events()
            assert event["resync"] is False and list(event["data"]) == ["session"]
        finally:
            c.close()

    def test_another_boot_is_a_resync_with_no_data(self, rig):
        r = ready(rig())
        c = r.server.connect(r.base + "/events", headers={"Last-Event-ID": "ffffffffffffffff-4"})
        try:
            assert c.pull_until(b"event: change")
            (event,) = c.events()
            assert event["resync"] is True and event["data"] == {}
        finally:
            c.close()

    def test_a_peer_boot_change_ends_the_stream_and_the_reconnect_resyncs(self, rig):
        r = ready(rig())
        c = r.server.connect(r.base + "/events")
        try:
            assert c.pull_until(b"event: change")
            old = c.events()[0]["id"]
            r.peer.new_boot("fedcba9876543210")
            assert wait_for(lambda: r.client.snapshot().boot == "fedcba9876543210")
            assert wait_closed(c)
        finally:
            c.close()
        again = r.server.connect(r.base + "/events", headers={"Last-Event-ID": old})
        try:
            assert again.pull_until(b"event: change")
            (event,) = again.events()
            assert event["resync"] is True and event["boot"] == "fedcba9876543210"
        finally:
            again.close()

    def test_the_stream_ends_when_the_peer_goes_unreachable(self, rig):
        r = ready(rig())
        c = r.server.connect(r.base + "/events")
        try:
            assert c.pull_until(b"event: change")
            r.peer.stop()
            assert wait_for(lambda: not r.client.snapshot().reachable)
            assert wait_closed(c)
        finally:
            c.close()
        status, body = r.get("/events")
        assert body["error"] == "peer_unreachable"

    def test_the_peers_access_event_reaches_the_phone(self, rig):
        r = ready(rig())
        c = r.server.connect(r.base + "/events")
        try:
            assert c.pull_until(b"event: access")
            r.peer.send_access("none", "control_disabled")
            assert c.pull_until(b"control_disabled")
            assert '"role":"none"' in c.buf.decode("ascii")
        finally:
            c.close()

    def test_relayed_streams_count_against_the_per_address_limit(self, rig):
        r = ready(rig())
        held = []
        try:
            for _ in range(proto_hub.MAX_STREAMS_PER_ADDRESS):
                c = r.server.connect(r.base + "/events")
                assert c.pull_until(b"retry: 2000")
                held.append(c)
            assert r.server.hub.client_count() == proto_hub.MAX_STREAMS_PER_ADDRESS
            status, body = r.get("/events")
            assert body["error"] == "too_many_from_address"
        finally:
            for c in held:
                c.close()

    def test_a_cross_origin_stream_is_refused(self, rig):
        r = ready(rig())
        status, body = r.get("/events", headers={"Origin": "http://other.example"})
        assert body["error"] == "cross_origin"

    def test_streams_share_one_json_dump_per_part_version(self, rig, monkeypatch):
        r = ready(rig(parts={"outputs": {"units": [1]}}))
        dumps = []
        real = json.dumps
        monkeypatch.setattr(relay, "json", SimpleNamespace(
            dumps=lambda *a, **k: dumps.append(1) or real(*a, **k)))
        v0 = r.peer.version
        clients = [r.server.connect(r.base + "/events", headers={"Last-Event-ID": f"{BOOT}-{v0}"})
                   for _ in range(3)]
        try:
            for c in clients:
                assert c.pull_until(b"retry: 2000")
            r.peer.push({"session": {"active": True}})
            for c in clients:
                assert c.pull_until(b'"active":true')
        finally:
            for c in clients:
                c.close()
        assert len(dumps) == 1


class TestSource:
    def test_alive_follows_the_client(self, rig):
        r = ready(rig())
        source = relay.PeerSource(r.client)
        assert source.alive() and source.pause_s() == 0.0
        r.client.stop()
        assert not source.alive()

    def test_the_view_maps_access(self, rig):
        r = ready(rig())
        assert relay.PeerSource(r.client).current().access("x").role.name == "PLAYBACK"
        r.peer.send_access("none", "control_disabled")
        assert wait_for(lambda: r.client.snapshot().access == "none")
        answer = relay.PeerSource(r.client).current().access("x")
        assert (answer.role.name, answer.reason) == ("NONE", "control_disabled")


class TestIntents:
    def test_an_intent_is_forwarded_as_this_appliances_request(self, rig):
        r = ready(rig())
        r.peer.intent_reply = lambda name, body: (200, {
            "ok": True, "error": None, "version": 12, "boot": BOOT, "result": {"done": 1}})
        status, body = r.post("volume.set", {"args": {"level": 20}})
        assert status == 200
        assert body == {"ok": True, "error": None, "version": 12, "boot": BOOT, "result": {"done": 1}}
        (name, sent), = r.peer.posts
        assert name == "volume.set"
        assert sent == {"client": f"peer:{OWN_ID}", "protocol": PROTOCOL, "args": {"level": 20}}

    def test_a_refusal_from_the_peer_passes_through(self, rig):
        r = ready(rig())
        r.peer.intent_reply = lambda name, body: (200, {
            "ok": False, "error": "rate_limited", "retry_after_s": 4, "version": 1,
            "boot": BOOT, "result": {}})
        _, body = r.post("output.pin.submit", {"args": {}})
        assert body["error"] == "rate_limited" and body["retry_after_s"] == 4.0

    def test_a_missing_csrf_token_is_refused(self, rig):
        r = ready(rig())
        status, body = r.post("volume.set", headers={})
        assert (status, body["error"]) == (403, "csrf_stale")
        assert r.peer.posts == []

    def test_a_body_that_names_a_client_is_refused(self, rig):
        r = ready(rig())
        status, body = r.post("volume.set", {"client": "dial:" + "0" * 20, "args": {}})
        assert (status, body["error"]) == (400, "invalid_client")
        assert r.peer.posts == []

    def test_a_cross_origin_post_is_refused(self, rig):
        r = ready(rig())
        headers = {**r.browser(), "Origin": "http://other.example"}
        status, body = r.post("volume.set", headers=headers)
        assert (status, body["error"]) == (403, "cross_origin")

    def test_an_unconfigured_appliance_relays_nothing(self, rig):
        r = ready(rig())
        r.server.commissioning_required = True
        status, body = r.post("volume.set")
        assert (status, body["ok"], body["error"]) == (200, False, "unconfigured")
        assert r.peer.posts == []

    def test_args_must_be_an_object(self, rig):
        r = ready(rig())
        _, body = r.post("volume.set", {"args": [1]})
        assert body["error"] == "invalid_args"

    @pytest.mark.parametrize("name", ["Bad%20Name", "a" * 65, "x/y"])
    def test_a_bad_name_is_not_forwarded(self, rig, name):
        r = ready(rig())
        r.post(name)
        assert r.peer.posts == []

    def test_this_appliances_setting_off_refuses(self, rig):
        r = ready(rig())
        r.control = False
        status, body = r.post("volume.set")
        assert (status, body["error"]) == (403, "control_disabled")
        assert r.peer.posts == []

    @pytest.mark.parametrize("kind,error", [
        ("unknown", "unknown_appliance"), ("bound", "bound_appliance"),
        ("control_off", "control_disabled"), ("conflict", "appliance_conflict"),
        ("unconfigured", "appliance_unconfigured")])
    def test_each_resolution_refuses_an_intent(self, rig, kind, error):
        r = ready(rig(kind=kind))
        _, body = r.post("volume.set")
        assert body["error"] == error
        assert r.peer.posts == []

    def test_a_peer_that_refuses_this_appliance_is_reported_by_name(self, rig):
        r = ready(rig())
        r.peer.send_access("none", "control_disabled")
        assert wait_for(lambda: r.client.snapshot().access == "none")
        _, body = r.post("volume.set")
        assert body["ok"] is False and body["error"] == "control_disabled"
        assert r.peer.posts == []

    def test_a_transport_failure_is_named(self, rig):
        r = ready(rig())
        r.peer.stop()
        assert wait_for(lambda: not r.client.snapshot().reachable)
        _, body = r.post("volume.set")
        assert body["error"] == "peer_unreachable"
