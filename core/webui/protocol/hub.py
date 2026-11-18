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
  - StreamHub  -- the subscriber, the client limits, the part cache and the
                  state body cache
  - install    -- make a hub the one the routes use
  - current    -- the installed hub, or None
"""

from __future__ import annotations

import json
import threading
import time
from typing import Optional

MAX_STREAMS = 64
MAX_STREAMS_PER_ADDRESS = 8
BODY_MAX_AGE_S = 1.0        # the state body is rebuilt after this long, same version

TOO_MANY_CLIENTS = "too_many_clients"
TOO_MANY_FROM_ADDRESS = "too_many_from_address"


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
