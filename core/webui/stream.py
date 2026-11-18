#!/usr/bin/env python3
"""webui/stream.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

The state change stream (GET /api/v1/events) and the state snapshot
(GET /api/v1/state). Both are unstable: their shape may change.

One hub subscribes once to the state store and counts the changes that moved a
part. Each stream client runs on its own request thread: it waits on the hub,
reads the snapshot, works out which parts moved since the version it last
sent, and writes one short event. A client holds only its own socket, under a
short write timeout and a small send buffer, so a client that stops reading is
dropped and nothing else waits for it: no lock is held while a socket is
written, and the store's publishers only touch the hub's condition.

Contents:
  - send_events      -- GET /api/v1/events
  - send_state_json  -- GET /api/v1/state
"""

from __future__ import annotations

import dataclasses
import enum
import json
import logging
import math
import random
import re
import select
import socket
import threading
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import parse_qs, urlsplit

import autostream_logging as log_setup
from autostream_state import PART_NAMES
from webui import common

MAX_CLIENTS = 8
HEARTBEAT_S = 10.0          # a comment when nothing was written for this long
LIVENESS_S = 1.0            # how often a quiet stream checks that its client is still there
COALESCE_S = 0.3            # changes within this window after a wake become one event
WRITE_TIMEOUT_S = 2.0
SEND_BUFFER_BYTES = 32 * 1024
RETRY_MS = 2000             # the browser's reconnect delay after a stream ends
MAX_AGE_S = 300.0           # a stream is ended after about this long; the browser resumes it
MAX_AGE_JITTER = 0.1        # each stream's age limit is MAX_AGE_S times 0.9 to 1.1
BODY_MAX_AGE_S = 1.0        # the state body is rebuilt after this long, same version

_SINCE_RE = re.compile(r"[0-9a-f]{16}-[0-9]{1,18}")


@dataclass(frozen=True)
class Since:
    """Where a client says it is: a boot id and a snapshot version."""

    boot: str
    version: int


def _parse_id(text: Optional[str]) -> Optional[Since]:
    if not text or not _SINCE_RE.fullmatch(text):
        return None
    boot, _, version = text.partition("-")
    return Since(boot, int(version))


def parse_since(header: Optional[str], query: str) -> Optional[Since]:
    """The client's position from the Last-Event-ID header, else the ``since``
    query parameter, else None. An id that does not have the shape the server
    writes is no position."""
    if header:
        return _parse_id(header)
    values = parse_qs(query or "").get("since")
    return _parse_id(values[0]) if values else None


def event_id(snap) -> str:
    return f"{snap.boot}-{snap.version}"


def changed_parts(snap, since: Optional[Since]) -> tuple[tuple[str, ...], bool]:
    """(parts, resync): what to tell a client that is at *since*. A client
    whose position is unknown, from another boot or ahead of the store is
    told to refetch everything. One at the current version is told nothing.
    Otherwise the parts whose version is above the client's, in PART_NAMES
    order."""
    if since is None or since.boot != snap.boot or since.version > snap.version:
        return tuple(PART_NAMES), True
    if since.version == snap.version:
        return (), False
    return tuple(p for p in PART_NAMES if snap.part_versions.get(p, 0) > since.version), False


def event_bytes(snap, parts, resync: bool) -> bytes:
    data = json.dumps(
        {"boot": snap.boot, "version": snap.version, "parts": list(parts), "resync": bool(resync)},
        separators=(",", ":"))
    return f"id: {event_id(snap)}\nevent: change\ndata: {data}\n\n".encode("ascii")


# -----------------------------------------------------------------------------
# The hub
# -----------------------------------------------------------------------------

class StreamHub:
    """The store's one subscriber for the streams, and the count of clients."""

    def __init__(self, store, *, clock=time.monotonic) -> None:
        self._source = store
        self._clock = clock
        self._cond = threading.Condition()
        self._generation = 0
        self._stopped = False
        self._stop_event = threading.Event()
        self._handle: Optional[int] = None
        self._count_lock = threading.Lock()
        self._clients = 0
        self._build_lock = threading.Lock()
        self._body: Optional[tuple] = None      # (key, built_at, bytes)

    @property
    def store(self):
        return self._source

    def start(self) -> None:
        """Subscribe to the store. Idempotent."""
        with self._cond:
            if self._handle is not None:
                return
            self._stopped = False
            self._stop_event.clear()
            self._handle = self._source.subscribe(self._on_change)

    def stop(self) -> None:
        """Unsubscribe and wake every client, which then ends its stream."""
        with self._cond:
            handle, self._handle = self._handle, None
            self._stopped = True
            self._stop_event.set()
            self._cond.notify_all()
        if handle is not None:
            self._source.unsubscribe(handle)

    @property
    def stopping(self) -> bool:
        return self._stopped

    def generation(self) -> int:
        return self._generation

    def wait_past(self, generation: int, timeout: float) -> Optional[int]:
        """The generation once it is past *generation*, or None when *timeout*
        seconds pass (or the hub stops) first."""
        with self._cond:
            self._cond.wait_for(lambda: self._generation > generation or self._stopped, timeout)
            if self._generation > generation:
                return self._generation
        return None

    def pause(self, seconds: float) -> bool:
        """Wait *seconds*, or less when the hub stops. True when stopping."""
        return self._stop_event.wait(seconds)

    def enter(self) -> bool:
        """Take a client slot; False when MAX_CLIENTS are taken."""
        with self._count_lock:
            if self._clients >= MAX_CLIENTS:
                return False
            self._clients += 1
            return True

    def exit(self) -> None:
        with self._count_lock:
            if self._clients > 0:
                self._clients -= 1

    def client_count(self) -> int:
        return self._clients

    def _on_change(self, change) -> None:
        if not change.parts:        # a tag-only change, or a cycle that moved nothing
            return
        with self._cond:
            self._generation += 1
            self._cond.notify_all()

    def state_body(self) -> bytes:
        """The state route's body for the current snapshot, shared by every
        caller: built once per version and client count, and again when older
        than BODY_MAX_AGE_S so the fast fields stay current."""
        cached = self._body
        key = self._body_key()
        if cached is not None and cached[0] == key and self._clock() - cached[1] < BODY_MAX_AGE_S:
            return cached[2]
        with self._build_lock:
            cached = self._body
            snap = self._source.snapshot()
            clients = self.client_count()
            key = (snap.boot, snap.version, clients)
            now = self._clock()
            if cached is not None and cached[0] == key and now - cached[1] < BODY_MAX_AGE_S:
                return cached[2]
            body = json.dumps(state_json(snap, clients=clients), allow_nan=False,
                              separators=(",", ":")).encode("utf-8")
            self._body = (key, now, body)
            return body

    def _body_key(self) -> tuple:
        snap = self._source.snapshot()
        return (snap.boot, snap.version, self.client_count())


_HUB: Optional[StreamHub] = None


def install(hub: Optional[StreamHub]) -> None:
    """Make *hub* the one the routes use (None removes it)."""
    global _HUB
    _HUB = hub


# -----------------------------------------------------------------------------
# GET /api/v1/state
# -----------------------------------------------------------------------------

def _jsonable(value):
    """*value* as plain JSON types: dataclasses by field, mappings with string
    keys, sequences and sets as lists, enums by value, non-finite floats as
    None."""
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, enum.Enum):
        return _jsonable(value.value)
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: _jsonable(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (frozenset, set)):
        return sorted((_jsonable(v) for v in value), key=str)
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def state_json(snap, *, clients: int) -> dict:
    """The snapshot's parts as they are, with the boot id, the version, the
    version at which each part last moved, and the number of stream clients."""
    return {
        "boot": snap.boot,
        "version": snap.version,
        "clients": clients,
        "part_versions": {str(k): v for k, v in snap.part_versions.items()},
        "parts": {name: _jsonable(getattr(snap, name)) for name in PART_NAMES},
    }


def send_state_json(handler, state) -> None:
    """GET /api/v1/state."""
    hub = _HUB
    if hub is None:
        common.send_browser_api_error(handler, 404, "not_found")
        return
    body = hub.state_body()
    try:
        handler.send_response(200)
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)
    except (BrokenPipeError, ConnectionResetError):
        return


# -----------------------------------------------------------------------------
# GET /api/v1/events
# -----------------------------------------------------------------------------

def _same_origin(headers) -> bool:
    """True unless the request names an Origin whose host differs from Host."""
    origin = headers.get("Origin")
    if not origin:
        return True
    return urlsplit(origin).netloc.lower() == (headers.get("Host") or "").lower()


def _peer_closed(sock) -> bool:
    """Whether the client has closed (or reset) its end of *sock*. A client
    that is merely quiet is not."""
    try:
        if not select.select([sock], [], [], 0)[0]:
            return False
        return sock.recv(1, socket.MSG_PEEK) == b""
    except (OSError, ValueError):
        return True


def _write(handler, payload: bytes) -> None:
    handler.wfile.write(payload)
    handler.wfile.flush()


def _wait(handler, hub, seen_gen: int, deadline: float) -> Optional[int]:
    """The hub generation once it is past *seen_gen*; None at *deadline*. A
    client that has gone ends the stream within LIVENESS_S (ConnectionResetError)
    instead of at the next write."""
    while True:
        left = deadline - time.monotonic()
        woke = hub.wait_past(seen_gen, max(0.0, min(LIVENESS_S, left)))
        if woke is not None or hub.stopping:
            return woke
        if _peer_closed(handler.connection):
            raise ConnectionResetError("client closed the stream")
        if left <= LIVENESS_S:
            return None


def _stream(handler, hub) -> str:
    sock = handler.connection
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SEND_BUFFER_BYTES)
    except OSError:
        pass
    sock.settimeout(WRITE_TIMEOUT_S)              # this connection only
    since = parse_since(handler.headers.get("Last-Event-ID"), urlsplit(handler.path).query)
    handler.send_response(200)
    handler.send_header("Content-Type", "text/event-stream")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Accel-Buffering", "no")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.end_headers()
    handler.close_connection = True
    seen_gen = hub.generation()                   # before the snapshot: a change after it wakes us
    snap = hub.store.snapshot()
    parts, resync = changed_parts(snap, since)
    out = b"retry: %d\n\n" % RETRY_MS
    if parts:
        out += event_bytes(snap, parts, resync)
    _write(handler, out)
    seen = snap.version if parts or since is None else since.version
    opened = last_write = time.monotonic()
    max_age = MAX_AGE_S * random.uniform(1.0 - MAX_AGE_JITTER, 1.0 + MAX_AGE_JITTER)
    while not hub.stopping:
        woke = _wait(handler, hub, seen_gen, min(last_write + HEARTBEAT_S, opened + max_age))
        if hub.stopping:
            break
        if woke is not None and hub.pause(COALESCE_S):   # fold in what follows within the window
            break
        now = time.monotonic()
        if now - opened >= max_age:               # before every write, busy or quiet
            return "lifetime"
        if woke is None:                          # quiet for HEARTBEAT_S
            _write(handler, b": ka\n\n")
            last_write = now
            continue
        seen_gen = hub.generation()
        snap = hub.store.snapshot()
        parts = tuple(p for p in PART_NAMES if snap.part_versions.get(p, 0) > seen)
        if parts:
            _write(handler, event_bytes(snap, parts, False))
            seen = snap.version
            last_write = time.monotonic()
    return "server stopping"


def serve_events(handler, hub) -> str:
    """Run one stream on the calling thread and return why it ended. The
    caller has already taken a slot with hub.enter()."""
    try:
        return _stream(handler, hub)
    except socket.timeout:                        # a write that did not finish in time
        return "timeout"
    except OSError as exc:                        # reset, broken pipe, client gone
        return type(exc).__name__


def send_events(handler, state) -> None:
    """GET /api/v1/events."""
    hub = _HUB
    if hub is None:
        common.send_browser_api_error(handler, 404, "not_found")
        return
    if not _same_origin(handler.headers):
        common.send_browser_api_error(handler, 403, "cross_origin")
        return
    if not hub.enter():
        if log_setup.log_every(("stream", "refused"), 60.0):
            logging.info("state stream: refused a client, %d already connected", MAX_CLIENTS)
        common.send_browser_api_error(handler, 503, "too_many_clients", retryable=True)
        return
    try:
        reason = serve_events(handler, hub)
    finally:
        hub.exit()
    logging.debug("state stream: ended (%s)", reason)
