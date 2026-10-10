"""dial_hd_events.py: the change hub and the event stream behind the HD page.

One hub thread turns the core's change signals into a sequence number.
Anything can ask for a change by calling publish() (the core's subscriber
callback does, as do the config listener and the panel): it only records the
request and wakes the hub thread, so a publisher is never delayed, and several
requests before the hub thread runs become one step. The state body for a
sequence is built lazily by the first client that asks and cached, so any
number of clients cost one serialisation per change.

The event stream gives each client its own handler thread. A client holds only
its own socket (under a short write timeout) and the hub's condition while it
waits, so a client that stops reading is dropped after one write timeout and
the core, the hub and every other client carry on.

The hub thread also keeps the focused appliance's outputs and EQ fetched while
at least one client is connected (and only then), so a dial with no page open
asks for neither.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
import socket
import threading
from typing import Callable

SSE_MAX_CLIENTS = 4
SSE_HEARTBEAT_S = 15.0
# Kernel send buffer asked for on a stream socket: a client that stops
# reading fills it after a few events and is dropped at the next write
# timeout, instead of sitting on a large buffer.
SSE_SEND_BUFFER_BYTES = 32 * 1024

# The name the hub watches the core's outputs and EQ under.
WATCHER = "hd"

# The hub thread wakes at least this often, so a client count that changed
# without a publish is noticed.
HUB_POLL_S = 1.0


class ChangeHub:
    def __init__(self, core, *, builder: "Callable[[int], bytes] | None" = None) -> None:
        self._core = core
        self._builder = builder
        self._client_count: Callable[[], int] = lambda: 0
        self._event = threading.Event()
        self._flag_lock = threading.Lock()        # guards _dirty only; never held across a call out
        self._dirty = False
        self._cond = threading.Condition()
        self._seq = 1
        self._stopped = False
        self._build_lock = threading.Lock()
        self._cache: tuple[int, bytes] | None = None
        self._thread: threading.Thread | None = None
        self._handle = None
        self._watched: str | None = None

    # ---- wiring ------------------------------------------------------------

    def set_builder(self, builder: "Callable[[int], bytes]") -> None:
        """The function that turns a sequence into the state body."""
        self._builder = builder

    def set_client_counter(self, counter: "Callable[[], int]") -> None:
        """How many event-stream clients are connected, asked by the hub
        thread to decide whether to follow the focused appliance."""
        self._client_count = counter

    # ---- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None:
            return
        self._handle = self._core.subscribe(self.publish)
        self._thread = threading.Thread(target=self._run, daemon=True, name="hd-events")
        self._thread.start()

    def stop(self) -> None:
        with self._cond:
            self._stopped = True
            self._cond.notify_all()
        self._event.set()
        thread, self._thread = self._thread, None
        if self._handle is not None:
            self._core.unsubscribe(self._handle)
            self._handle = None
        if thread is not None:
            thread.join(2.0)
        self._follow(None)

    @property
    def stopped(self) -> bool:
        return self._stopped

    # ---- the sequence ------------------------------------------------------

    def publish(self, *_args) -> None:
        """Ask for a new sequence. Any thread; returns at once."""
        with self._flag_lock:
            self._dirty = True
        self._event.set()

    def poke(self) -> None:
        """Wake the hub thread without stepping the sequence."""
        self._event.set()

    def seq(self) -> int:
        return self._seq

    def wait_for_change(self, seen_seq: int, timeout: float) -> "int | None":
        """The sequence once it is past *seen_seq*, None on timeout or stop."""
        with self._cond:
            self._cond.wait_for(lambda: self._seq != seen_seq or self._stopped, timeout)
            if self._stopped or self._seq == seen_seq:
                return None
            return self._seq

    def state(self) -> tuple[int, bytes]:
        """(sequence, state body) for the current sequence, built once."""
        seq = self._seq
        with self._build_lock:
            if self._cache is not None and self._cache[0] == seq:
                return self._cache
            if self._builder is None:
                raise RuntimeError("no state builder")
            self._cache = (seq, self._builder(seq))
            return self._cache

    # ---- the hub thread ----------------------------------------------------

    def _run(self) -> None:
        while not self._stopped:
            self._event.wait(HUB_POLL_S)
            if self._stopped:
                break
            self._event.clear()
            with self._flag_lock:
                dirty, self._dirty = self._dirty, False
            if dirty:
                with self._cond:
                    self._seq += 1
                    self._cond.notify_all()
            try:
                self._follow_focus()
            except Exception:
                logging.debug("hd hub: follow failed", exc_info=True)

    def _follow_focus(self) -> None:
        target = None
        if self._client_count() > 0:
            target = self._core.snapshot().focused_id()
        self._follow(target)

    def _follow(self, target: "str | None") -> None:
        """Watch the outputs and EQ of *target* (None drops the watch)."""
        previous = self._watched
        if target == previous:
            return
        self._watched = target
        watched, on = (target, True) if target is not None else (previous, False)
        for watch in (self._core.watch_outputs, self._core.watch_eq):
            try:
                watch(watched, WATCHER, on)
            except Exception:
                logging.debug("hd hub: watch failed", exc_info=True)


def _parse_event_id(value: "str | None") -> "int | None":
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def serve_events(handler, hub: ChangeHub, clients) -> None:
    """Run one event-stream client on *handler*'s thread until it goes away.

    *clients* counts and caps the connected clients (enter() / exit()) and
    says when the server is stopping."""
    if not clients.enter():
        handler.send_json(503, {"ok": False, "error": "too_many_clients"})
        return
    try:
        _stream(handler, hub, clients)
    except (socket.timeout, OSError):
        pass
    finally:
        clients.exit()


def _write(handler, payload: bytes) -> None:
    handler.wfile.write(payload)
    handler.wfile.flush()


def _event_bytes(seq: int, body: bytes) -> bytes:
    return b"id: %d\nevent: state\ndata: %s\n\n" % (seq, body)


def _stream(handler, hub: ChangeHub, clients) -> None:
    try:
        handler.connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SSE_SEND_BUFFER_BYTES)
    except OSError:
        pass
    handler.send_response(200)
    handler.send_header("Content-Type", "text/event-stream")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Accel-Buffering", "no")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.end_headers()
    handler.close_connection = True
    handler.wfile.flush()

    last = _parse_event_id(handler.headers.get("Last-Event-ID"))
    seen = last if last is not None else 0
    # A client that is current waits for the next change; any other (new,
    # behind, or ahead of a restarted hub) is sent the state now.
    if last is None or last != hub.seq():
        seq, body = hub.state()
        _write(handler, _event_bytes(seq, body))
        seen = seq
    while not clients.stopping and not hub.stopped:
        changed = hub.wait_for_change(seen, SSE_HEARTBEAT_S)
        if clients.stopping or hub.stopped:
            break
        if changed is None:
            _write(handler, b": ping\n\n")
            continue
        seq, body = hub.state()
        _write(handler, _event_bytes(seq, body))
        seen = seq
