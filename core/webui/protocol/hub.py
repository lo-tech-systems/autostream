#!/usr/bin/env python3
"""webui/protocol/hub.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

The stream hub: the state store's one subscriber for the streams, and the
count of connected clients.

The hub counts the changes that moved a part. Each stream client runs on its
own request thread: it waits on the hub, reads the snapshot, works out which
parts moved since the version it last sent, and writes one short event. The
store's publishers only touch the hub's condition, and no lock is held while a
socket is written.

Contents:
  - StreamHub  -- the subscriber, the client count and the state body cache
  - install    -- make a hub the one the routes use
  - current    -- the installed hub, or None
"""

from __future__ import annotations

import json
import threading
import time
from typing import Optional

MAX_CLIENTS = 8
BODY_MAX_AGE_S = 1.0        # the state body is rebuilt after this long, same version


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
        from webui.protocol import state     # state imports this module
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
