#!/usr/bin/env python3
"""webui/peer/relay.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Another appliance's state and controls for a browser on this one. The state,
the change stream and the intents of an appliance this one follows are
served at /api/v1/peers/<id>/state, /events and /intents/<name>, in the shapes
the appliance's own routes use, so a page draws a remote appliance with the
code that draws this one. The stream is the peer's: its events and ids are
passed on as they come, so a browser can resume against the peer's versions.

Contents:
  - PeerSource      -- a followed appliance as a stream source
  - state_body      -- a followed appliance's state, as the state route shows it
  - serve_peer_get  -- GET /api/v1/peers/<id>/state and /events
  - serve_peer_intent -- POST /api/v1/peers/<id>/intents/<name>
"""

from __future__ import annotations

import json
import re
import threading
import time
import weakref
from typing import Optional
from urllib.parse import parse_qs, urlsplit

import autostream_rpi as rpi
from autostream_appliances import resolve
from autostream_intents import Role
from autostream_protocol import PROTOCOL
from autostream_state import PART_NAMES
from webui import common
from webui.protocol import hub as hub_module
from webui.protocol import intents as intents_module
from webui.protocol.caller import Refusal, identify
from webui.protocol.stream import _same_origin, serve_events

_PREFIX = "/api/v1/peers/"
_ID_RE = re.compile(r"[0-9a-f]{20}")
_PART_RE = re.compile(r"[a-z_]{1,32}")
_REFUSALS = {
    "unknown": (404, "unknown_appliance"),
    "invalid": (404, "unknown_appliance"),
    "bound": (404, "bound_appliance"),
    "control_off": (403, "control_disabled"),
    "conflict": (409, "appliance_conflict"),
    "unconfigured": (409, "appliance_unconfigured"),
}


# -----------------------------------------------------------------------------
# A followed appliance as a stream source
# -----------------------------------------------------------------------------

_cache_lock = threading.Lock()
_part_caches: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()


def _part_json(client, snap, name: str) -> bytes:
    """The JSON of part *name* in *snap*, built once per version of the part
    however many streams follow the client."""
    key = (snap.boot, snap.part_versions.get(name, 0))
    with _cache_lock:
        cache = _part_caches.setdefault(client, {})
        cached = cache.get(name)
        if cached is not None and cached[0] == key:
            return cached[1]
    blob = json.dumps(snap.parts.get(name), allow_nan=False, separators=(",", ":")).encode("ascii")
    with _cache_lock:
        cache[name] = (key, blob)
    return blob


class _PeerView:
    """One snapshot of a followed appliance as a SourceView."""

    __slots__ = ("_client", "_snap", "boot", "version", "part_versions")

    def __init__(self, client, snap) -> None:
        self._client = client
        self._snap = snap
        self.boot = snap.boot
        self.version = snap.version
        self.part_versions = snap.part_versions

    def part_bytes(self, name: str) -> bytes:
        return _part_json(self._client, self._snap, name)

    def access(self, client: str) -> hub_module.Access:
        """What the followed appliance lets this one do, as it last said."""
        snap = self._snap
        if snap.access == "none":
            return hub_module.Access(Role.NONE, snap.access_reason)
        return hub_module.Access(Role.PLAYBACK)


class PeerSource:
    """A followed appliance for the write loop. The stream ends when the
    appliance cannot be reached, needs another protocol, starts a new boot (its
    versions begin again, so the browser reconnects and is told to read it
    whole) or is no longer followed."""

    def __init__(self, client) -> None:
        self._client = client
        self._boot = client.snapshot().boot

    def mark(self) -> int:
        return self._client.snapshot().seq

    def wait_past(self, mark: int, timeout: float) -> Optional[int]:
        snap = self._client.wait_for_change(mark, timeout)
        return snap.seq if snap is not None else None

    def current(self) -> _PeerView:
        return _PeerView(self._client, self._client.snapshot())

    def pause_s(self) -> float:
        return 0.0          # the appliance already folded its changes together

    def pause(self, seconds: float) -> bool:
        time.sleep(seconds)
        return not self.alive()

    def alive(self) -> bool:
        snap = self._client.snapshot()
        return (not self._client.stopped and snap.reachable and snap.protocol_ok
                and snap.boot == self._boot)


# -----------------------------------------------------------------------------
# Resolving the appliance
# -----------------------------------------------------------------------------

def _refuse(handler, status: int, error: str, **kwargs) -> None:
    common.send_browser_api_error(handler, status, error, **kwargs)


def _client_for(handler, state, peer_id: str):
    """The PeerClient for *peer_id*, or None after sending the refusal. Reads
    this appliance's own control setting first, then what the id names."""
    if not common._effective_control_other_appliances(state):
        _refuse(handler, 403, "control_disabled")
        return None
    resolution = resolve(peer_id)
    refusal = _REFUSALS.get(resolution.kind)
    if refusal is not None:
        _refuse(handler, *refusal)
        return None
    snap = resolution.client.snapshot()
    if not snap.protocol_ok:
        _refuse(handler, 409, "protocol_mismatch")
        return None
    if not snap.reachable:
        _refuse(handler, 503, "peer_unreachable", retryable=True)
        return None
    return resolution.client


def _split(handler) -> tuple[str, str]:
    """(appliance id, what follows it) from the request path."""
    tail = handler._normalized_path()[len(_PREFIX):]
    peer_id, _, rest = tail.partition("/")
    return peer_id, rest


# -----------------------------------------------------------------------------
# GET /api/v1/peers/<id>/state
# -----------------------------------------------------------------------------

def _requested_parts(path: str) -> Optional[list]:
    """The ``parts`` query as names: None when absent, [] when empty.
    ValueError for a name that cannot be a part."""
    values = parse_qs(urlsplit(path).query, keep_blank_values=True).get("parts")
    if not values:
        return None
    names = values[0].split(",") if values[0] else []
    if any(not _PART_RE.fullmatch(n) for n in names):
        raise ValueError("unknown part")
    return names


def state_body(snap) -> dict:
    return {"boot": snap.boot, "version": snap.version, "protocol": snap.protocol or PROTOCOL,
            "clients": None, "time": time.time(),
            "part_versions": dict(snap.part_versions), "parts": dict(snap.parts)}


def serve_peer_state(handler, state, peer_id: str) -> None:
    """GET /api/v1/peers/<id>/state: the appliance's held parts, or with
    ``?parts=`` those parts read live from it (what carries fast fields)."""
    client = _client_for(handler, state, peer_id)
    if client is None:
        return
    try:
        names = _requested_parts(handler.path)
    except ValueError:
        _refuse(handler, 400, "unknown_part")
        return
    snap = client.snapshot()
    if names is None and snap.boot is not None:
        common.send_json(handler, 200, state_body(snap))
        return
    reply = client.fetch(list(PART_NAMES) if names is None else names)
    if reply is None:
        _refuse(handler, 503, "peer_unreachable", retryable=True)
        return
    status, body = reply
    common.send_json(handler, status, body)


# -----------------------------------------------------------------------------
# GET /api/v1/peers/<id>/events
# -----------------------------------------------------------------------------

def serve_peer_events(handler, state, peer_id: str) -> None:
    """GET /api/v1/peers/<id>/events: the appliance's change stream."""
    client = _client_for(handler, state, peer_id)
    if client is None:
        return
    hub = hub_module.current()
    if hub is None:
        _refuse(handler, 404, "not_found")
        return
    if not _same_origin(handler.headers):
        _refuse(handler, 403, "cross_origin")
        return
    if client.snapshot().boot is None:
        _refuse(handler, 503, "peer_unreachable", retryable=True)
        return
    address = handler._get_client_ip()
    refusal = hub.enter(address)
    if refusal is not None:
        _refuse(handler, 503, refusal, retryable=True)
        return
    try:
        serve_events(handler, PeerSource(client), "peer:" + (rpi.get_appliance_id() or "0" * 20))
    finally:
        hub.exit(address)


def serve_peer_get(handler, state) -> None:
    """GET /api/v1/peers/<id>/state and /events."""
    peer_id, rest = _split(handler)
    if not _ID_RE.fullmatch(peer_id):
        _refuse(handler, 404, "unknown_appliance")
    elif rest == "state":
        serve_peer_state(handler, state, peer_id)
    elif rest == "events":
        serve_peer_events(handler, state, peer_id)
    else:
        _refuse(handler, 404, "not_found")


# -----------------------------------------------------------------------------
# POST /api/v1/peers/<id>/intents/<name>
# -----------------------------------------------------------------------------

def _reply(handler, error: Optional[str], reply=None) -> None:
    body = {"ok": False, "error": error, "version": None, "boot": None, "result": {}}
    if reply is not None:
        body.update({"ok": reply.ok, "error": reply.error, "version": reply.version,
                     "boot": reply.boot, "result": dict(reply.result)})
        if reply.retry_after_s is not None:
            body["retry_after_s"] = reply.retry_after_s
    common.send_json(handler, 200, body)


def serve_peer_intent(handler, state) -> None:
    """POST /api/v1/peers/<id>/intents/<name>: the intent goes to the
    appliance as a request from this one, on behalf of the browser."""
    body = intents_module._read_json(handler)
    if body is None:
        return
    if not _same_origin(handler.headers):
        _refuse(handler, 403, "cross_origin")
        return
    if body.get("client") is not None:
        _refuse(handler, 400, "invalid_client")
        return
    if not intents_module._configured(state):
        _reply(handler, "unconfigured")
        return
    who = identify(handler, body, write=True)
    if isinstance(who, Refusal):
        _refuse(handler, who.status, who.error, extra=who.extra)
        return
    peer_id, rest = _split(handler)
    name = rest[len("intents/"):] if rest.startswith("intents/") else ""
    args = body.get("args", {})
    if not _ID_RE.fullmatch(peer_id) or not intents_module._NAME_RE.fullmatch(name):
        _refuse(handler, 404, "not_found")
        return
    if not isinstance(args, dict):
        _reply(handler, "invalid_args")
        return
    client = _client_for(handler, state, peer_id)
    if client is None:
        return
    _reply(handler, None, client.submit(name, args))
