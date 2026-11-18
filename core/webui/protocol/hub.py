#!/usr/bin/env python3
"""webui/protocol/hub.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

The stream hub: the state store's one subscriber for the streams, the count
of connected clients in total and per address, and the caches that every
stream shares.

The hub counts the changes that moved a part. Each stream client runs on its
own request thread: it waits on the hub, reads the snapshot, works out which
parts moved since the version it last sent, and writes one short event. The
store's publishers only touch the hub's condition, and no lock is held while a
socket is written.

Contents:
  - StreamHub  -- the subscriber, the client limits, the part cache, the
                  state body cache and the answer to what a named client may do
  - Access     -- that answer: a role and the reason when it is none
  - install    -- make a hub the one the routes use
  - current    -- the installed hub, or None
"""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Callable, NamedTuple, Optional

import autostream_dials as dials
from autostream_intents import Role
from autostream_protocol import parse_client

MAX_STREAMS = 64
MAX_STREAMS_PER_ADDRESS = 8
BODY_MAX_AGE_S = 1.0        # the state body is rebuilt after this long, same version

TOO_MANY_CLIENTS = "too_many_clients"
TOO_MANY_FROM_ADDRESS = "too_many_from_address"


class Access(NamedTuple):
    """What a named client may do: its role, and why it has none."""

    role: Role
    reason: Optional[str] = None

    def event_data(self, client: str) -> dict:
        return {"client": client, "role": self.role.name.lower(), "reason": self.reason}


_MEMO_MAX = 256


class _PartCache:
    """The JSON of each part, built once per version of that part however many
    streams list it. A part's cached bytes freeze its fast fields at the
    version they were built for, so the cache serves events only. The caller
    holds the hub's build lock."""

    def __init__(self) -> None:
        self._entries: dict[str, tuple[tuple, bytes]] = {}

    def bytes_for(self, snap, name: str) -> bytes:
        from webui.protocol import state     # state imports this module
        key = (snap.boot, snap.part_versions.get(name, 0))
        cached = self._entries.get(name)
        if cached is not None and cached[0] == key:
            return cached[1]
        blob = state.part_json(snap, name)
        self._entries[name] = (key, blob)
        return blob


class StreamHub:
    """The store's one subscriber for the streams, and the count of clients."""

    def __init__(self, store, *, clock=time.monotonic,
                 peer_control: Optional[Callable[[], bool]] = None) -> None:
        """*peer_control* says whether other appliances may control this one;
        without it, or when it raises, they may not."""
        self._source = store
        self._clock = clock
        self._peer_control = peer_control
        self._access_memo: dict = {}
        self._memo_generation = -1
        self._cond = threading.Condition()
        self._generation = 0
        self._stopped = False
        self._stop_event = threading.Event()
        self._handle: Optional[int] = None
        self._count_lock = threading.Lock()
        self._clients = 0
        self._by_address: dict[str, int] = {}
        self._build_lock = threading.Lock()
        self._parts = _PartCache()
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

    def enter(self, address: str) -> Optional[str]:
        """Take a client slot for *address*. None when the stream is admitted,
        else the name of the refusal: every slot taken, or MAX_STREAMS_PER_ADDRESS
        taken by this address."""
        with self._count_lock:
            if self._clients >= MAX_STREAMS:
                return TOO_MANY_CLIENTS
            if self._by_address.get(address, 0) >= MAX_STREAMS_PER_ADDRESS:
                return TOO_MANY_FROM_ADDRESS
            self._clients += 1
            self._by_address[address] = self._by_address.get(address, 0) + 1
            return None

    def exit(self, address: str) -> None:
        """Free the slot that enter(*address*) took."""
        with self._count_lock:
            held = self._by_address.get(address, 0)
            if held <= 0:
                return
            if held == 1:
                del self._by_address[address]
            else:
                self._by_address[address] = held - 1
            self._clients -= 1

    def client_count(self) -> int:
        return self._clients

    def access(self, client: str, *, configured: bool) -> Access:
        """What the named client (``dial:<id>`` or ``peer:<id>``) may do. The
        caller says whether the appliance is configured: the intents route
        reads it live and a stream reads the appliance part, so the two never
        disagree within one request. A dial answer is remembered per dials
        generation; an unreadable dials store is never remembered."""
        if not configured:
            return Access(Role.NONE, "unconfigured")
        parsed = parse_client(client)
        if parsed is None:
            return Access(Role.NONE, "invalid_client")
        kind = parsed[0]
        if kind == "peer":
            return self._peer_access()
        generation = self._source.snapshot().dials.generation
        key = (client, generation)
        with self._count_lock:
            if generation != self._memo_generation or len(self._access_memo) >= _MEMO_MAX:
                self._access_memo.clear()
                self._memo_generation = generation
            known = self._access_memo.get(key)
        if known is not None:
            return known
        verdict = dials.dial_authorization(parsed[1])
        if verdict == dials.AUTH_UNAVAILABLE:
            return Access(Role.NONE, "auth_unavailable")
        answer = (Access(Role.PLAYBACK) if verdict == dials.AUTH_AUTHORIZED
                  else Access(Role.NONE, "dial_not_authorized"))
        with self._count_lock:
            if generation == self._memo_generation:
                self._access_memo[key] = answer
        return answer

    def _peer_access(self) -> Access:
        try:
            allowed = bool(self._peer_control()) if self._peer_control is not None else False
        except Exception:
            logging.debug("stream hub: peer control setting unreadable", exc_info=True)
            allowed = False
        return Access(Role.PLAYBACK) if allowed else Access(Role.NONE, "control_disabled")

    def _on_change(self, change) -> None:
        if not change.parts:        # a tag-only change, or a cycle that moved nothing
            return
        with self._cond:
            self._generation += 1
            self._cond.notify_all()

    def part_bytes(self, snap, name: str) -> bytes:
        """The JSON of part *name* as of its version in *snap*, for an event."""
        with self._build_lock:
            return self._parts.bytes_for(snap, name)

    def state_body(self, parts: Optional[tuple] = None) -> bytes:
        """The state route's body for the current snapshot. Without *parts* it
        is shared by every caller: built once per version and client count, and
        again when older than BODY_MAX_AGE_S so the fast fields stay current.
        With *parts* (names, possibly none) it is built from the live snapshot
        on each call and holds only those parts."""
        from webui.protocol import state     # state imports this module
        if parts is not None:
            snap = self._source.snapshot()
            return json.dumps(state.state_json(snap, clients=self.client_count(), parts=parts),
                              allow_nan=False, separators=(",", ":")).encode("utf-8")
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
            body = json.dumps(state.state_json(snap, clients=clients), allow_nan=False,
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


def current() -> Optional[StreamHub]:
    """The installed hub, or None."""
    return _HUB
