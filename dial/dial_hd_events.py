"""dial_hd_events.py: the change hub and the event stream behind the HD page.

One hub thread turns the core's change signals into a sequence number.
Anything can ask for a change by calling publish() (the core's subscriber
callback does, as do the config listener and the panel): it only records the
request and wakes the hub thread, so a publisher is never delayed, and several
requests before the hub thread runs become one step. At each step the hub
thread calls its step builder once with the new sequence and holds what it
returns until the next step, so any number of clients cost one build per
change.

The page's state is two parts, `dial` and `focused`. A step builds both and
says which changed since the step before; a change event carries only those.
The hub keeps no history: a client that missed a step is told to fetch the
state again.

The event stream gives each client its own handler thread. A client holds only
its own socket (under a short write timeout) and the hub's condition while it
waits, so a client that stops reading is dropped after one write timeout and
the core, the hub and every other client carry on.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import json
import logging
import re
import select
import socket
import threading
import time
from dataclasses import dataclass
from typing import Callable
from urllib.parse import parse_qs, urlsplit

from dial_values import clamp

SSE_MAX_CLIENTS = 4
SSE_HEARTBEAT_S = 15.0
# How often an idle stream looks at its own socket to see whether the client
# has gone (a reloaded page closes its stream without the server writing).
SSE_LIVENESS_S = 1.0
# Kernel send buffer asked for on a stream socket: a client that stops
# reading fills it after a few events and is dropped at the next write
# timeout, instead of sitting on a large buffer.
SSE_SEND_BUFFER_BYTES = 32 * 1024

# The hub thread wakes at least this often, so a stop is noticed even when
# its wake is lost.
HUB_POLL_S = 1.0


class ChangeHub:
    def __init__(self, core, *, builder: "Callable[[int], object] | None" = None) -> None:
        self._core = core
        self._builder = builder

        self._event = threading.Event()
        self._flag_lock = threading.Lock()        # guards _dirty only; never held across a call out
        self._dirty = False
        self._cond = threading.Condition()
        self._seq = 1
        self._latest: "tuple[int, object]" = (1, None)   # (sequence, what its step built)
        self._stopped = False
        self._thread: threading.Thread | None = None
        self._handle = None

    # ---- wiring ------------------------------------------------------------

    def set_builder(self, builder: "Callable[[int], object]") -> None:
        """The function each step calls, on the hub thread, with the new
        sequence; what it returns is held by latest() until the next step."""
        self._builder = builder

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

    def latest(self) -> "tuple[int, object]":
        """(sequence, what the step builder made of it): None for the first
        sequence, for a step with no builder and for a build that failed."""
        with self._cond:
            return self._latest

    def wait_for_change(self, seen_seq: int, timeout: float) -> "int | None":
        """The sequence once it is past *seen_seq*, None on timeout or stop."""
        with self._cond:
            self._cond.wait_for(lambda: self._seq != seen_seq or self._stopped, timeout)
            if self._stopped or self._seq == seen_seq:
                return None
            return self._seq

    # ---- the hub thread ----------------------------------------------------

    def _build(self, seq: int) -> object:
        if self._builder is None:
            return None
        try:
            return self._builder(seq)
        except Exception:
            logging.debug("hd events: step build failed", exc_info=True)
            return None

    def _run(self) -> None:
        while not self._stopped:
            self._event.wait(HUB_POLL_S)
            if self._stopped:
                break
            self._event.clear()
            with self._flag_lock:
                dirty, self._dirty = self._dirty, False
            if dirty:
                # Built before the step is announced, so a waiter woken for a
                # sequence always finds that sequence's build.
                seq = self._seq + 1
                built = self._build(seq)
                with self._cond:
                    self._seq = seq
                    self._latest = (seq, built)
                    self._cond.notify_all()


def serve_events(handler, hub: ChangeHub, clients, boot: str, clock: "Callable[[], float]") -> None:
    """Run one event-stream client on *handler*'s thread until it goes away.

    *clients* counts and caps the connected clients (enter() / exit()) and
    says when the server is stopping. *boot* is the dial's boot id, which
    every event id starts with, and *clock* the core's clock, for the time a
    resync event carries. The hub's builds are (PartStep or None, time)."""
    if not clients.enter():
        handler.send_json(503, {"ok": False, "error": "too_many_clients"})
        return
    try:
        _stream(handler, hub, clients, boot, clock)
    except (socket.timeout, OSError):
        pass
    finally:
        clients.exit()


def _write(handler, payload: bytes) -> None:
    handler.wfile.write(payload)
    handler.wfile.flush()


def _peer_closed(sock) -> bool:
    """Whether the client has closed (or reset) its end of *sock*. A client
    that is merely quiet is not."""
    try:
        if not select.select([sock], [], [], 0)[0]:
            return False
        return sock.recv(1, socket.MSG_PEEK) == b""
    except (OSError, ValueError):
        return True


def _wait(handler, hub: ChangeHub, clients, seen: int) -> "int | None":
    """The hub's sequence once it is past *seen*; None after one heartbeat
    with no change. A client that went away ends the stream (OSError) within
    SSE_LIVENESS_S instead of at the next write."""
    deadline = time.monotonic() + SSE_HEARTBEAT_S
    while True:
        left = deadline - time.monotonic()
        changed = hub.wait_for_change(seen, clamp(left, 0.0, SSE_LIVENESS_S))
        if changed is not None or clients.stopping or hub.stopped:
            return changed
        if _peer_closed(handler.connection):
            raise ConnectionResetError("client closed the stream")
        if left <= SSE_LIVENESS_S:
            return None


def _since(path: str) -> "str | None":
    values = parse_qs(urlsplit(path).query).get("since")
    return values[0] if values else None


def _next_event(boot: str, seen: int, seq: int, built, clock) -> "bytes | None":
    """What a client at *seen* is sent for sequence *seq*: the parts that
    changed when *seq* is the very next step and it built them, nothing when
    none changed, else a resync."""
    if seq == seen + 1 and built is not None and built[0] is not None:
        step, now = built
        return change_bytes(boot, seq, now, step.changed) if step.changed else None
    return change_bytes(boot, seq, round(clock(), 3), {}, resync=True)


def _stream(handler, hub: ChangeHub, clients, boot: str, clock) -> None:
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

    # A client at this boot and the current sequence waits for the next
    # change; any other (new, behind, or from another boot) fetches the state.
    seen = hub.seq()
    if must_resync(parse_since(_since(handler.path)), boot, seen):
        _write(handler, change_bytes(boot, seen, round(clock(), 3), {}, resync=True))
    while not clients.stopping and not hub.stopped:
        changed = _wait(handler, hub, clients, seen)
        if clients.stopping or hub.stopped:
            break
        if changed is None:
            _write(handler, b": ping\n\n")
            continue
        seq, built = hub.latest()
        payload = _next_event(boot, seen, seq, built, clock)
        if payload is not None:
            _write(handler, payload)
        seen = seq


# ---- the two parts, step by step ---------------------------------------------

PART_NAMES = ("dial", "focused")

_SINCE_RE = re.compile(r"([0-9a-f]{16})-([0-9]{1,18})")


def parse_since(value: "str | None") -> "tuple[str, int] | None":
    """(boot, sequence) from a `since` value of the form the events carry as
    their id, or None when it is absent or not of that form."""
    match = _SINCE_RE.fullmatch(value or "")
    return None if match is None else (match.group(1), int(match.group(2)))


def must_resync(since: "tuple[str, int] | None", boot: str, seq: int) -> bool:
    """Whether a client that says it is at *since* must fetch the state. The
    hub keeps no history, so only a client at this boot and the current
    sequence is current; any other cannot be told what moved."""
    return since is None or since != (boot, seq)


def encode_parts(parts: dict) -> "dict[str, bytes]":
    """Each of the page's parts as its JSON (null for an absent one)."""
    return {
        name: json.dumps(parts.get(name), separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        for name in PART_NAMES
    }


@dataclass(frozen=True)
class PartStep:
    """One hub step's parts. *changed* maps each part whose bytes differ from
    the step before (both, with no step before) to its JSON; *versions* is
    what the body reports for each part: the sequence a part last changed at,
    and for the focused part the appliance's own version (absent with no
    focus)."""

    changed: "dict[str, bytes]"
    versions: "dict[str, int]"


class PartDiffer:
    """Builds the page's parts once per hub step and says which changed.

    *clients* returns how many pages are connected. With none, a step builds
    nothing and drops what it held, so the first step after a page connects
    has no baseline and reports both parts."""

    def __init__(self, clients: "Callable[[], int]") -> None:
        self._clients = clients
        self._bytes: "dict[str, bytes] | None" = None
        self._dial_version = 0

    def step(self, seq: int, build: "Callable[[], dict]") -> "PartStep | None":
        """The step for sequence *seq*, with *build* called once for the
        parts; None, without calling it, while no page is connected."""
        if self._clients() <= 0:
            self._bytes = None
            return None
        parts = build()
        current = encode_parts(parts)
        previous = self._bytes
        changed = {n: b for n, b in current.items() if previous is None or previous[n] != b}
        self._bytes = current
        if "dial" in changed:
            self._dial_version = seq
        versions = {"dial": self._dial_version}
        if parts.get("focused") is not None:
            versions["focused"] = parts["focused"]["version"]
        return PartStep(changed, versions)


def _parts_json(parts: "dict[str, bytes]") -> bytes:
    return b"{" + b",".join(json.dumps(n).encode("ascii") + b":" + b for n, b in parts.items()) + b"}"


def state_bytes(boot: str, seq: int, now: float, step: PartStep, parts: "dict[str, bytes]") -> bytes:
    """The state body: the sequence, the core's clock, the part versions and
    *parts*, each as its JSON."""
    head = json.dumps(
        {"boot": boot, "version": seq, "time": now, "part_versions": step.versions}, separators=(",", ":"))
    return head[:-1].encode("ascii") + b',"parts":' + _parts_json(parts) + b"}"


def change_bytes(boot: str, seq: int, now: float, changed: "dict[str, bytes]", resync: bool = False) -> bytes:
    """One change event: *changed* maps each moved part to its JSON; a resync
    carries none and tells the page to fetch the state."""
    head = json.dumps({"boot": boot, "version": seq, "time": now, "resync": bool(resync)}, separators=(",", ":"))
    data = b"{}" if resync else _parts_json(changed)
    payload = head[:-1].encode("ascii") + b',"data":' + data + b"}"
    return b"id: %s-%d\nevent: change\ndata: %s\n\n" % (boot.encode("ascii"), seq, payload)
