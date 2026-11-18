"""tests/relay_rig.py

A real web server whose relay follows a fake appliance: the fake peer, a
started PeerClient on it, and the relay's name lookup pointed at the client.
Used by the relay tests and by the protocol scenarios.
"""
from __future__ import annotations

import http.client
import json
import secrets
import sys
import time
from pathlib import Path

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_appliances
from autostream_peer_client import PeerClient
from autostream_peer_registry import Sighting
from autostream_protocol import PROTOCOL
from autostream_auth import SESSION_COOKIE_NAME, Session
from fake_peer_server import FakePeer
from stream_helpers import RealServer, wait_for
import webui.common as webui_common
import webui.browser.home as home_page
import webui.peer.relay as relay
import webui.protocol.intents as intents_route

PEER_ID = "aabbccddeeff00112233"
OWN_ID = "00112233445566778899"


class RelayRig:
    def __init__(self, monkeypatch, *, parts=None, kind: str = "remote",
                 peer_protocol: int = PROTOCOL, handler=None) -> None:
        self.monkeypatch = monkeypatch
        self.server = RealServer(monkeypatch, handler=handler)
        self.server.hub._peer_control = lambda: True
        self.control = True
        self.peer = FakePeer(parts=parts, protocol=peer_protocol).start()
        self.client = PeerClient(PEER_ID, client_id=f"peer:{OWN_ID}")
        self.sighting = Sighting(id=PEER_ID, hostname="Kitchen", ip="127.0.0.1", port=self.peer.port,
                                 version="1.0", control=True, proto=PROTOCOL, service_name="k")
        self.kind = kind
        self.client.set_sighting("127.0.0.1", self.peer.port, PROTOCOL)
        self.client.start()
        monkeypatch.setattr(intents_route, "_configured_memo", None)
        monkeypatch.setattr(webui_common, "_effective_control_other_appliances",
                            lambda state: self.control)
        monkeypatch.setattr(relay, "resolve", self._resolve)
        monkeypatch.setattr(home_page, "resolve", self._resolve)
        monkeypatch.setattr(relay.rpi, "get_appliance_id", lambda: OWN_ID)

    def _resolve(self, appliance_id: str):
        if appliance_id != PEER_ID:
            return autostream_appliances.Resolution("unknown")
        return autostream_appliances.Resolution(self.kind, self.client, self.sighting)

    def ready(self, timeout: float = 5.0) -> bool:
        return wait_for(lambda: self.client.snapshot().reachable
                        and self.client.snapshot().boot is not None, timeout) \
            and wait_for(lambda: self.peer.open_streams() >= 1, timeout)

    def close(self) -> None:
        self.client.stop()
        self.peer.stop()
        self.server.close()

    # -- requests ------------------------------------------------------------

    @property
    def base(self) -> str:
        return f"/api/v1/peers/{PEER_ID}"

    def get(self, tail: str, headers=None):
        """(status, parsed body) of one GET under the peer's path."""
        status, raw = self.server.get(self.base + tail, headers=headers)
        try:
            return status, json.loads(raw)
        except ValueError:
            return status, raw

    def page(self, path: str, headers=None):
        """(status, Location header or None, body text) of one GET, not followed."""
        conn = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=10)
        try:
            conn.request("GET", path, headers=headers or {})
            resp = conn.getresponse()
            return resp.status, resp.getheader("Location"), resp.read().decode("utf-8", "replace")
        finally:
            conn.close()

    def browser(self, *, authenticated: bool = True) -> dict:
        token, csrf = secrets.token_hex(16), secrets.token_hex(16)
        self.server.auth._sessions[token] = Session(
            token=token, expires_at=int(time.time()) + 3600, csrf_token=csrf, authenticated=authenticated)
        return {"Cookie": f"{SESSION_COOKIE_NAME}={token}", "X-CSRF-Token": csrf}

    def post(self, name: str, body=None, *, headers="browser", path=None, raw: bytes = None):
        head = {"Content-Type": "application/json"}
        head.update(self.browser() if headers == "browser" else (headers or {}))
        data = raw if raw is not None else json.dumps({"args": {}} if body is None else body).encode()
        conn = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=10)
        try:
            conn.request("POST", path or f"{self.base}/intents/{name}", body=data, headers=head)
            resp = conn.getresponse()
            payload = resp.read()
            try:
                return resp.status, json.loads(payload)
            except ValueError:
                return resp.status, payload
        finally:
            conn.close()
