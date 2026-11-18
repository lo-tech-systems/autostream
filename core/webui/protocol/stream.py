#!/usr/bin/env python3
"""webui/protocol/stream.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

The state change stream (GET /api/v1/events). It is unstable: its shape may
change.

Each stream client runs on its own request thread: it waits on the hub, reads
the snapshot, works out which parts moved since the version it last sent, and
writes one short event. A client holds only its own socket, under a short
write timeout and a small send buffer, so a client that stops reading is
dropped and nothing else waits for it.

Contents:
  - send_events  -- GET /api/v1/events
"""

from __future__ import annotations

import json
import logging
import random
import re
import select
import socket
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import parse_qs, urlsplit

import autostream_logging as log_setup
from autostream_protocol import PROTOCOL, parse_client
from autostream_state import PART_NAMES
from webui import common
from webui.protocol import hub as hub_module

HEARTBEAT_S = 10.0          # a comment when nothing was written for this long
LIVENESS_S = 1.0            # how often a quiet stream checks that its client is still there
COALESCE_S = 0.3            # changes within this window after a wake become one event
WRITE_TIMEOUT_S = 2.0
SEND_BUFFER_BYTES = 32 * 1024
RETRY_MS = 2000             # the browser's reconnect delay after a stream ends
MAX_AGE_S = 300.0           # a stream is ended after about this long; the browser resumes it
MAX_AGE_JITTER = 0.1        # each stream's age limit is MAX_AGE_S times 0.9 to 1.1

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


def event_bytes(snap, resync: bool, data=None) -> bytes:
    """One change event. *data* maps each changed part's name to its JSON bytes
    as the state route shows it; a resync carries none."""
    head = json.dumps(
        {"boot": snap.boot, "version": snap.version, "resync": bool(resync)},
        separators=(",", ":"))
    blobs = b",".join(json.dumps(name).encode("ascii") + b":" + blob
                      for name, blob in (data or {}).items())
    payload = head[:-1].encode("ascii") + b',"data":{' + blobs + b"}}"
    return b"id: %s\nevent: change\ndata: %s\n\n" % (event_id(snap).encode("ascii"), payload)


def _event(hub, snap, parts, resync: bool) -> bytes:
    """The event for *parts* of *snap*, with their data unless it is a resync."""
    data = {} if resync else {name: hub.part_bytes(snap, name) for name in parts}
    return event_bytes(snap, resync, data)


# -----------------------------------------------------------------------------
# GET /api/v1/events
# -----------------------------------------------------------------------------

def _same_origin(headers) -> bool:
    """True unless the request names an Origin whose host differs from Host."""
    origin = headers.get("Origin")
    if not origin:
        return True
    return urlsplit(origin).netloc.lower() == (headers.get("Host") or "").lower()


def _protocol_param(path: str) -> Optional[str]:
    """The ``protocol`` query parameter, or None when the request has none."""
    values = parse_qs(urlsplit(path).query).get("protocol")
    return values[0] if values else None


def _peer_closed(sock) -> bool:
    """Whether the client has closed (or reset) its end of *sock*. A client
    that is merely quiet is not."""
    try:
        if not select.select([sock], [], [], 0)[0]:
            return False
        return sock.recv(1, socket.MSG_PEEK) == b""
    except (OSError, ValueError):
        return True


def _client_param(path: str) -> Optional[str]:
    """The ``client`` query parameter, or None when the request has none."""
    values = parse_qs(urlsplit(path).query).get("client")
    return values[0] if values else None


def _access_event(hub, snap, client: Optional[str], last) -> tuple[bytes, object]:
    """(bytes, answer): the access event of a named client when its answer
    differs from *last*, else b"". Without a client, never."""
    if client is None:
        return b"", last
    answer = hub.access(client, configured=snap.appliance.configured)
    if answer == last:
        return b"", last
    data = json.dumps(answer.event_data(client), separators=(",", ":"))
    return b"event: access\ndata: %s\n\n" % data.encode("ascii"), answer


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


def _stream(handler, hub, client: Optional[str] = None) -> str:
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
    access_event, last_access = _access_event(hub, snap, client, None)
    out += access_event
    if parts:
        out += _event(hub, snap, parts, resync)
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
            access_event, last_access = _access_event(hub, hub.store.snapshot(), client, last_access)
            _write(handler, access_event + b": ka\n\n")
            last_write = now
            continue
        seen_gen = hub.generation()
        snap = hub.store.snapshot()
        access_event, last_access = _access_event(hub, snap, client, last_access)
        if access_event:
            _write(handler, access_event)
            last_write = time.monotonic()
        parts = tuple(p for p in PART_NAMES if snap.part_versions.get(p, 0) > seen)
        if parts:
            _write(handler, _event(hub, snap, parts, False))
            seen = snap.version
            last_write = time.monotonic()
    return "server stopping"


def serve_events(handler, hub, client: Optional[str] = None) -> str:
    """Run one stream on the calling thread and return why it ended. The
    caller has already taken a slot with hub.enter(). *client* names a dial or
    a peer, which is told what it may do in access events."""
    try:
        return _stream(handler, hub, client)
    except socket.timeout:                        # a write that did not finish in time
        return "timeout"
    except OSError as exc:                        # reset, broken pipe, client gone
        return type(exc).__name__


def send_events(handler, state) -> None:
    """GET /api/v1/events."""
    hub = hub_module.current()
    if hub is None:
        common.send_browser_api_error(handler, 404, "not_found")
        return
    if not _same_origin(handler.headers):
        common.send_browser_api_error(handler, 403, "cross_origin")
        return
    if _protocol_param(handler.path) not in (None, str(PROTOCOL)):
        common.send_json(handler, 200, {"ok": False, "error": "protocol_mismatch", "protocol": PROTOCOL})
        return
    client = _client_param(handler.path)
    if client is not None and parse_client(client) is None:
        common.send_browser_api_error(handler, 400, "invalid_client")
        return
    address = handler._get_client_ip()
    refusal = hub.enter(address)
    if refusal is not None:
        if log_setup.log_every(("stream", "refused", refusal), 60.0):
            logging.info("state stream: refused a client from %s (%s)", address, refusal)
        common.send_browser_api_error(handler, 503, refusal, retryable=True)
        return
    try:
        reason = serve_events(handler, hub, client)
    finally:
        hub.exit(address)
    logging.debug("state stream: ended (%s)", reason)
