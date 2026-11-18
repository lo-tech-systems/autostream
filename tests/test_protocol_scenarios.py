"""tests/test_protocol_scenarios.py

One script of client-protocol scenarios, run against two servers: this
appliance's own routes, and the relay of another appliance (a real server
whose relay follows a fake appliance). A client sees the same behaviour from
either: connect, resume, resync after another boot, an access change, an
intent that returns the version it makes pending, and each refusal name.
"""
from __future__ import annotations

import http.client
import json
import secrets
import sys
import time
from pathlib import Path

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_logging as log_setup
from autostream_auth import SESSION_COOKIE_NAME, Session
from autostream_intents import Reply
from relay_rig import RelayRig
from stream_helpers import Publisher, RealServer, wait_for
import webui.common as webui_common
from types import SimpleNamespace
import webui.protocol.intents as intents_route

REFUSALS = ["unknown_intent", "admin_required", "invalid_args", "rate_limited", "output_in_use"]


class Local:
    """This appliance's own routes."""

    name = "local"
    events = "/api/v1/events"

    def __init__(self, monkeypatch) -> None:
        self.monkeypatch = monkeypatch
        self.server = RealServer(monkeypatch)
        self.publisher = Publisher(self.server.store)
        self.publisher("appliance")
        self.server.hub._peer_control = lambda: True
        monkeypatch.setattr(intents_route, "_configured_memo", None)
        monkeypatch.setattr(webui_common, "_config_snapshot", lambda state: SimpleNamespace(
            owntone=SimpleNamespace(volume_percent=30, output_offsets_ms={}, output_airplay_modes={})))
        self.reply = Reply(True, None, 5, "b", {})
        monkeypatch.setattr(intents_route, "submit", lambda intent, **kw: self.reply)
        self.events_with_access = "/api/v1/events?client=peer:" + "0" * 20

    def ready(self) -> bool:
        return True

    @property
    def state_path(self) -> str:
        return "/api/v1/state"

    @property
    def intents_path(self) -> str:
        return "/api/v1/intents/"

    def change(self) -> None:
        """Move a part, so a stream has something to say."""
        self.publisher("settings")

    def deny(self) -> None:
        self.server.hub._peer_control = lambda: False
        self.change()

    def arm(self, ok: bool, error=None) -> None:
        self.reply = Reply(ok, error, 5, "b", {})

    def close(self) -> None:
        self.server.close()


class Relayed:
    """The relay of a fake appliance."""

    name = "relay"

    def __init__(self, monkeypatch) -> None:
        self.rig = RelayRig(monkeypatch)
        self.server = self.rig.server
        self.events = self.rig.base + "/events"
        self.events_with_access = self.events

    def ready(self) -> bool:
        return self.rig.ready()

    @property
    def state_path(self) -> str:
        return self.rig.base + "/state"

    @property
    def intents_path(self) -> str:
        return self.rig.base + "/intents/"

    def change(self) -> None:
        self.rig.peer.push({"settings": {"generation": self.rig.peer.version}})

    def deny(self) -> None:
        self.rig.peer.send_access("none", "control_disabled")

    def arm(self, ok: bool, error=None) -> None:
        peer = self.rig.peer
        peer.intent_reply = lambda name, body: (200, {
            "ok": ok, "error": error, "version": peer.version, "boot": peer.boot, "result": {}})

    def close(self) -> None:
        self.rig.close()


@pytest.fixture(params=[Local, Relayed], ids=["local", "relay"])
def target(request, monkeypatch):
    log_setup.reset_for_tests()
    t = request.param(monkeypatch)
    assert t.ready()
    yield t
    t.close()


def state_of(target) -> dict:
    status, raw = target.server.get(target.state_path)
    assert status == 200
    return json.loads(raw)


def browser(server) -> dict:
    token, csrf = secrets.token_hex(16), secrets.token_hex(16)
    server.auth._sessions[token] = Session(
        token=token, expires_at=int(time.time()) + 3600, csrf_token=csrf, authenticated=True)
    return {"Cookie": f"{SESSION_COOKIE_NAME}={token}", "X-CSRF-Token": csrf,
            "Content-Type": "application/json"}


def post(target, name: str, args=None):
    conn = http.client.HTTPConnection("127.0.0.1", target.server.port, timeout=10)
    try:
        conn.request("POST", target.intents_path + name, body=json.dumps({"args": args or {}}),
                     headers=browser(target.server))
        resp = conn.getresponse()
        return resp.status, json.loads(resp.read())
    finally:
        conn.close()


def test_a_new_client_is_told_to_resync_then_follows_changes(target):
    c = target.server.connect(target.events)
    try:
        assert c.pull_until(b"event: change")
        (first,) = c.events()
        assert first["resync"] is True and first["data"] == {}
        assert first["boot"] == state_of(target)["boot"]
        target.change()
        assert wait_for(lambda: (c.pull(0.1) or True) and len(c.events()) == 2, 3.0)
        second = c.events()[1]
        assert second["resync"] is False and "settings" in second["data"]
        assert second["version"] > first["version"]
    finally:
        c.close()


def test_a_client_at_the_current_version_is_told_nothing_until_a_change(target):
    snap = state_of(target)
    c = target.server.connect(target.events, headers={"Last-Event-ID": f"{snap['boot']}-{snap['version']}"})
    try:
        assert c.pull_until(b"retry: 2000")
        c.pull(0.3)
        assert c.events() == []
        target.change()
        assert c.pull_until(b"event: change")
        assert c.events()[0]["resync"] is False
    finally:
        c.close()


def test_a_client_behind_is_sent_the_parts_that_moved(target):
    snap = state_of(target)
    target.change()
    assert wait_for(lambda: state_of(target)["version"] > snap["version"])
    c = target.server.connect(target.events, headers={"Last-Event-ID": f"{snap['boot']}-{snap['version']}"})
    try:
        assert c.pull_until(b"event: change")
        (event,) = c.events()
        assert event["resync"] is False and "settings" in event["data"]
    finally:
        c.close()


def test_a_client_from_another_boot_is_told_to_resync(target):
    c = target.server.connect(target.events, headers={"Last-Event-ID": "ffffffffffffffff-1"})
    try:
        assert c.pull_until(b"event: change")
        (event,) = c.events()
        assert event["resync"] is True and event["boot"] == state_of(target)["boot"]
    finally:
        c.close()


def test_an_access_change_is_told_to_a_named_stream(target):
    c = target.server.connect(target.events_with_access)
    try:
        assert c.pull_until(b"event: access")
        assert b'"role":"playback"' in c.buf
        target.deny()
        assert c.pull_until(b"control_disabled")
        assert b'"role":"none"' in c.buf
    finally:
        c.close()


def test_an_intent_returns_the_version_it_made_pending(target):
    target.arm(True)
    status, body = post(target, "volume.set", {"level": 20})
    assert status == 200 and body["ok"] is True and body["error"] is None
    state = state_of(target)
    assert body["boot"] == state["boot"] or target.name == "local"
    assert isinstance(body["version"], int) and body["version"] <= state["version"]
    assert set(body) == {"ok", "error", "version", "boot", "result"}


@pytest.mark.parametrize("name", REFUSALS)
def test_each_refusal_name_reaches_the_client(target, name):
    target.arm(False, name)
    status, body = post(target, "volume.set", {"level": 20})
    assert status == 200 and body["ok"] is False and body["error"] == name
