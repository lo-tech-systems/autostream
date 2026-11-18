"""tests/stream_helpers.py

Shared helpers for the tests of the state stream: a publisher over a store, a
reader for what a stream writes, and a real web server over the stream
routes.
"""
from __future__ import annotations

import json
import socket
import sys
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

from autostream_state import (
    AppliancePart, DialsPart, OutputsPart, RepeatPart, SessionPart, SettingsPart,
    WarningEntry, WarningsPart)
import webui.protocol.hub as proto_hub


def wait_for(predicate, timeout: float = 3.0, step: float = 0.01) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(step)
    return predicate()


class Publisher:
    """Publishes to some parts of a store, each call moving the part. The
    appliance part is published as configured; ``set_appliance`` sets it."""

    def __init__(self, store) -> None:
        owner = "test_owner"
        self._writers = {
            "settings": store.claim("settings", owner),
            "session": store.claim("session", owner),
            "repeat": store.claim("repeat", owner),
            "outputs": store.claim("outputs", owner),
            "appliance": store.claim("appliance", owner),
            "dials": store.claim("dials", owner),
            "warnings": store.claim("warnings", owner),
        }
        self._n: dict = {}

    def bump(self, part: str):
        """Publish a new value to *part*; return the Pending (not notified)."""
        n = self._n[part] = self._n.get(part, 0) + 1
        w = self._writers[part]
        if part == "settings":
            return w.publish(SettingsPart(generation=n))
        if part == "session":
            return w.publish(SessionPart(True, f"input{n}"))
        if part == "repeat":
            return w.publish(RepeatPart(block={"enabled": n % 2 == 1}))
        if part == "dials":
            return w.publish(DialsPart(generation=n))
        if part == "warnings":
            return w.publish(WarningsPart((WarningEntry(
                f"w{n}", "", "info", "no_input", "", "No input", "Set up an input", None),)))
        if part == "appliance":
            return w.publish(AppliancePart(hostname=f"host{n}", configured=True))
        return w.publish(OutputsPart(muted_all=n % 2 == 1))

    def __call__(self, part: str) -> None:
        self.bump(part).notify()

    def set_appliance(self, **fields) -> None:
        self._writers["appliance"].publish(AppliancePart(**fields)).notify()


class Client:
    """The reading end of a stream: collects what arrives."""

    def __init__(self, sock) -> None:
        self.sock = sock
        self.buf = b""

    def pull(self, seconds: float) -> None:
        """Read whatever arrives within *seconds*."""
        end = time.monotonic() + seconds
        while True:
            left = end - time.monotonic()
            if left <= 0:
                return
            self.sock.settimeout(left)
            try:
                chunk = self.sock.recv(65536)
            except (socket.timeout, OSError):
                return
            if not chunk:
                return
            self.buf += chunk

    def pull_until(self, needle: bytes, timeout: float = 3.0) -> bool:
        end = time.monotonic() + timeout
        while needle not in self.buf and time.monotonic() < end:
            self.pull(0.05)
        return needle in self.buf

    @property
    def head(self) -> str:
        return self.buf.partition(b"\r\n\r\n")[0].decode("latin-1")

    @property
    def body(self) -> bytes:
        _head, sep, rest = self.buf.partition(b"\r\n\r\n")
        return rest if sep else b""

    def events(self) -> list:
        """The change events in the body, as dicts with their ids."""
        out = []
        for block in self.body.split(b"\n\n"):
            lines = block.decode("ascii", "replace").split("\n")
            if "event: change" in lines:
                data = next(line for line in lines if line.startswith("data: "))
                event = json.loads(data[len("data: "):])
                event["id"] = next(line for line in lines if line.startswith("id: "))[4:]
                out.append(event)
        return out

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class RealServer:
    """A ConfigWebHandler server on a free loopback port (or *handler*, a
    subclass of it), with a stream hub over its own store installed."""

    def __init__(self, monkeypatch, *, pin=None, handler=None) -> None:
        import autostream_commissioning as commissioning
        from autostream_auth import AuthManager
        from autostream_state.store import StateStore
        from settings_fixtures import viewed_state
        from webui import session_state
        from webui.server import ConfigWebHandler

        self.store = StateStore()
        self.hub = proto_hub.StreamHub(self.store)
        self.hub.start()
        proto_hub.install(self.hub)
        self.auth = AuthManager(config_path="dummy.ini")
        self.auth._pin_loaded = True
        self.auth._pin_value = pin
        self.auth._pin_status = "ok" if pin else "missing"
        state = viewed_state()
        state.config_path = "dummy.ini"
        state.state_path = "dummy-state.json"
        monkeypatch.setattr(session_state, "STATE", state)
        monkeypatch.setattr(session_state, "AUTH", self.auth)
        self.commissioning_required = False
        monkeypatch.setattr(commissioning, "is_commissioning_required",
                            lambda *a, **k: self.commissioning_required)
        monkeypatch.setattr(commissioning, "required_first_boot_step", lambda *a, **k: "owntone")
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler or ConfigWebHandler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def connect(self, path: str = "/api/v1/events", headers=None, *, rcvbuf=None) -> Client:
        """Open a request and return the client reading its reply."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if rcvbuf is not None:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        sock.connect(("127.0.0.1", self.port))
        lines = [f"GET {path} HTTP/1.1", f"Host: 127.0.0.1:{self.port}"]
        lines += [f"{k}: {v}" for k, v in (headers or {}).items()]
        sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        return Client(sock)

    def get(self, path: str, headers=None, timeout: float = 5.0):
        """One ordinary request: (status, body bytes)."""
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            conn.request("GET", path, headers=headers or {})
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    def close(self) -> None:
        self.hub.stop()
        proto_hub.install(None)
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(5.0)
