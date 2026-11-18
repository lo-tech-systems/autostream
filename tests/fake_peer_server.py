"""tests/fake_peer_server.py

A fake appliance for the peer-client tests: a stdlib server on a free loopback
port that answers the state, event and intent routes from a scripted store of
parts, with hooks to push a change, start a new boot, refuse, stall, close and
answer ``protocol_mismatch``.

    peer = FakePeer(parts={"appliance": {"configured": True}})
    peer.start()
    ...
    peer.push({"session": {"active": True}})
    peer.stop()

``requests`` holds ``(method, path)`` for each request, ``connects`` the query
and ``Last-Event-ID`` of each event stream, and ``posts`` the ``(name, body)``
of each intent.
"""
from __future__ import annotations

import json
import queue
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

from autostream_protocol import PROTOCOL  # noqa: E402

BOOT = "0123456789abcdef"


class FakePeer:
    def __init__(self, *, parts=None, boot: str = BOOT, protocol: int = PROTOCOL) -> None:
        self.parts: dict = {"appliance": {"configured": True}, "session": {"active": False}}
        self.parts.update(parts or {})
        self.boot = boot
        self.version = 10
        self.part_versions = {name: 10 for name in self.parts}
        self.protocol = protocol
        self.lifetime_s: float | None = None     # a stream ends after this long
        self.heartbeat_s: float | None = None    # a stream writes a comment this often
        self.state_delay_s = 0.0                 # state replies wait this long
        self.intent_delay_s = 0.0
        self.refusal: tuple[int, dict] | None = None     # the event route answers this
        self.state_refusal: tuple[int, dict] | None = None
        self.stall_events = False                # the event route opens a stream and says nothing
        self.stall_state = False                 # the state route never answers
        self.access: dict | None = {"role": "playback", "reason": None}
        self.intent_reply = None                 # callable(name, body) -> (status, dict)
        self.requests: list = []
        self.connects: list = []
        self.posts: list = []
        self._lock = threading.Lock()
        self._streams: list = []
        self._stopped = threading.Event()
        self._httpd: ThreadingHTTPServer | None = None

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> "FakePeer":
        peer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args) -> None:
                pass

            def do_GET(self) -> None:
                peer._get(self)

            def do_POST(self) -> None:
                peer._post(self)

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._httpd.daemon_threads = True
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()
        return self

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    def stop(self) -> None:
        self._stopped.set()
        self.close_streams()
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()

    # -- scripting ------------------------------------------------------------

    def push(self, data: dict, *, resync: bool = False) -> None:
        """Change parts: merge *data*, bump the version, and write one change
        event to every open stream."""
        with self._lock:
            self.version += 1
            self.parts.update(data)
            for name in data:
                self.part_versions[name] = self.version
            payload = self._change_bytes(data, resync)
            streams = list(self._streams)
        for q in streams:
            q.put(payload)

    def new_boot(self, boot: str = "fedcba9876543210", *, drop: bool = True) -> None:
        """A restart: a new boot id at a lower version. Open streams are closed,
        as the real appliance's are."""
        with self._lock:
            self.boot = boot
            self.version = 3
            self.part_versions = {name: 3 for name in self.parts}
        if drop:
            self.close_streams()

    def close_streams(self) -> None:
        with self._lock:
            streams = list(self._streams)
        for q in streams:
            q.put(None)

    def write(self, raw: bytes) -> None:
        """Write raw bytes to every open stream."""
        with self._lock:
            streams = list(self._streams)
        for q in streams:
            q.put(raw)

    def heartbeat(self) -> None:
        self.write(b": ka\n\n")

    def send_access(self, role: str, reason=None) -> None:
        self.access = {"role": role, "reason": reason}
        self.write(self._access_bytes())

    def open_streams(self) -> int:
        with self._lock:
            return len(self._streams)

    # -- bodies ---------------------------------------------------------------

    def _state_body(self, names) -> dict:
        with self._lock:
            chosen = list(self.parts) if names is None else (names or ["appliance"])
            return {"boot": self.boot, "version": self.version, "protocol": self.protocol,
                    "time": time.time(), "clients": 0, "part_versions": dict(self.part_versions),
                    "parts": {n: self.parts[n] for n in chosen if n in self.parts}}

    def _change_bytes(self, data: dict, resync: bool) -> bytes:
        body = {"boot": self.boot, "version": self.version, "resync": resync,
                "data": {} if resync else data}
        return (b"id: %s-%d\nevent: change\ndata: %s\n\n"
                % (self.boot.encode(), self.version, json.dumps(body).encode()))

    def _access_bytes(self) -> bytes:
        data = dict(self.access or {})
        data["client"] = "peer:" + "0" * 20
        return b"event: access\ndata: %s\n\n" % json.dumps(data).encode()

    # -- routes -------------------------------------------------------------------

    @staticmethod
    def _json(handler, status: int, body: dict) -> None:
        raw = json.dumps(body).encode()
        try:
            handler.send_response(status)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("Content-Length", str(len(raw)))
            handler.end_headers()
            handler.wfile.write(raw)
        except OSError:
            pass

    def _get(self, handler) -> None:
        url = urlsplit(handler.path)
        self.requests.append(("GET", handler.path))
        query = parse_qs(url.query, keep_blank_values=True)
        if url.path == "/api/v1/state":
            self._state(handler, query)
        elif url.path == "/api/v1/events":
            self._events(handler, query)
        else:
            self._json(handler, 404, {"ok": False, "error": "not_found"})

    def _state(self, handler, query) -> None:
        if self.stall_state:
            self._stopped.wait(30.0)
            return
        if self._stopped.wait(self.state_delay_s):
            return
        if self.state_refusal is not None:
            self._json(handler, *self.state_refusal)
            return
        names = None
        if "parts" in query:
            raw = query["parts"][0]
            names = raw.split(",") if raw else []
            if any(n not in self.parts for n in names):
                self._json(handler, 400, {"ok": False, "error": "unknown_part"})
                return
        self._json(handler, 200, self._state_body(names))

    def _events(self, handler, query) -> None:
        since = (query.get("since") or [""])[0]
        self.connects.append({"query": {k: v[0] for k, v in query.items()},
                              "last_event_id": handler.headers.get("Last-Event-ID"),
                              "since": since})
        if self.refusal is not None:
            self._json(handler, *self.refusal)
            return
        if (query.get("protocol") or [str(PROTOCOL)])[0] != str(self.protocol):
            self._json(handler, 200, {"ok": False, "error": "protocol_mismatch",
                                      "protocol": self.protocol})
            return
        q: queue.Queue = queue.Queue()
        out = b"retry: 2000\n\n"
        if "client" in query and self.access is not None:
            out += self._access_bytes()
        with self._lock:
            boot, _, version = since.partition("-")
            if not since or boot != self.boot or not version.isdigit() or int(version) > self.version:
                out += self._change_bytes({}, True)
            elif int(version) < self.version:
                data = {n: self.parts[n] for n in self.parts
                        if self.part_versions.get(n, 0) > int(version)}
                out += self._change_bytes(data, False)
            self._streams.append(q)
        try:
            handler.send_response(200)
            handler.send_header("Content-Type", "text/event-stream")
            handler.send_header("Cache-Control", "no-store")
            handler.end_headers()
            handler.close_connection = True
            if not self.stall_events:
                handler.wfile.write(out)
                handler.wfile.flush()
            opened = last = time.monotonic()
            while not self._stopped.is_set():
                try:
                    item = q.get(timeout=0.02)
                except queue.Empty:
                    now = time.monotonic()
                    if self.lifetime_s is not None and now - opened >= self.lifetime_s:
                        break
                    if self.heartbeat_s is not None and now - last >= self.heartbeat_s \
                            and not self.stall_events:
                        handler.wfile.write(b": ka\n\n")
                        handler.wfile.flush()
                        last = now
                    continue
                if item is None:
                    break
                if self.stall_events:
                    continue
                handler.wfile.write(item)
                handler.wfile.flush()
                last = time.monotonic()
        except OSError:
            pass
        finally:
            with self._lock:
                if q in self._streams:
                    self._streams.remove(q)

    def _post(self, handler) -> None:
        url = urlsplit(handler.path)
        self.requests.append(("POST", handler.path))
        length = int(handler.headers.get("Content-Length") or 0)
        try:
            body = json.loads(handler.rfile.read(length).decode() or "{}")
        except ValueError:
            body = None
        prefix = "/api/v1/intents/"
        if not url.path.startswith(prefix):
            self._json(handler, 404, {"ok": False, "error": "not_found"})
            return
        name = url.path[len(prefix):]
        self.posts.append((name, body))
        if self._stopped.wait(self.intent_delay_s):
            return
        if self.intent_reply is not None:
            status, reply = self.intent_reply(name, body)
        else:
            status, reply = 200, {"ok": True, "error": None, "version": self.version,
                                  "boot": self.boot, "result": {}}
        self._json(handler, status, reply)
