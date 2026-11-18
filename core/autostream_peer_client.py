"""autostream_peer_client.py -- a live copy of another appliance, and its controls.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

A PeerClient holds the state of one appliance: it reads the whole state, then
follows the appliance's event stream, and publishes each change as a new
immutable PeerSnapshot. Writes go out as intents on the caller's own thread.
A PeerPool keeps one client per appliance a PeerRegistry sees, and
roster_view lists them for a selector. The module imports only the standard
library and the program's protocol and registry modules, so a dial can carry
it.

Each client has one thread. Subscribers are signal-only: they are called with
the client, read its snapshot and return quickly.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import socket
import threading
import time
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Mapping, Optional, Sequence
from urllib.parse import quote

import autostream_peer_http
from autostream_peer_registry import PeerRegistry, Sighting
from autostream_protocol import PROTOCOL

BACKOFF_STEPS = (1.0, 2.0, 4.0, 8.0, 15.0, 30.0)   # then the last, for as long as it lasts
PROTOCOL_RECHECK_S = 60.0       # a peer on another protocol is looked at again after this
STREAM_READ_S = 25.0            # the longest the stream may stay silent: two missed heartbeats
STATE_READ_S = 2.0
INTENT_READ_S = 5.0
FETCH_READ_S = 2.0

ACCESS_PLAYBACK = "playback"
ACCESS_NONE = "none"
ACCESS_UNKNOWN = "unknown"

# A refusal the peer gives to the event stream because it is full. The peer
# answered, so it is reachable; the client tries again later.
_BUSY = ("too_many_clients", "too_many_from_address")


def backoff_delay(failures: int) -> float:
    """The wait after the *failures*-th failure in a row (1 or more)."""
    return BACKOFF_STEPS[min(max(failures, 1), len(BACKOFF_STEPS)) - 1]


@dataclass(frozen=True)
class PeerSnapshot:
    peer_id: str
    boot: Optional[str]           # the peer's boot id; None before the first full read
    version: int                  # the peer's store version the parts are at
    part_versions: Mapping[str, int]
    parts: Mapping[str, Any]      # part name -> the part as the state body shows it
    reachable: bool
    access: str                   # "playback" | "none" | "unknown"
    access_reason: Optional[str]
    protocol: Optional[int]       # the peer's protocol number; None until read
    protocol_ok: bool
    configured: Optional[bool]    # parts["appliance"]["configured"]; None until read
    heard_at: float               # clock() of the last line or reply from the peer; 0.0 never
    seq: int                      # local; +1 on every change except heard_at


@dataclass(frozen=True)
class PeerReply:
    ok: bool
    error: Optional[str]          # the peer's refusal name, or unreachable | timeout | bad_reply | backoff | protocol_mismatch
    version: Optional[int]
    boot: Optional[str]
    result: Mapping[str, Any]
    retry_after_s: Optional[float]


def _refused(error: str, retry_after_s: Optional[float] = None) -> PeerReply:
    return PeerReply(False, error, None, None, {}, retry_after_s)


def _parse_reply(reply: dict) -> PeerReply:
    """The peer's intent reply, with a field of the wrong type read as absent."""
    def typed(name, kind):
        value = reply.get(name)
        return value if isinstance(value, kind) else None
    retry = typed("retry_after_s", (int, float))
    return PeerReply(ok=bool(reply.get("ok")), error=typed("error", str), version=typed("version", int),
                     boot=typed("boot", str), result=typed("result", dict) or {},
                     retry_after_s=None if retry is None else float(retry))


_EMPTY: Mapping = MappingProxyType({})


class _SessionEnd(Exception):
    """Ends one pass of the client's loop; *outcome* says how."""

    def __init__(self, outcome: str) -> None:
        super().__init__(outcome)
        self.outcome = outcome


class _Subscribers:
    """Signal-only callbacks, called outside every lock of their owner."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._fns: dict[int, Callable] = {}
        self._next = 1

    def add(self, fn: Callable) -> int:
        with self._lock:
            handle, self._next = self._next, self._next + 1
            self._fns[handle] = fn
        return handle

    def remove(self, handle: int) -> None:
        with self._lock:
            self._fns.pop(handle, None)

    def call(self, *args) -> None:
        with self._lock:
            fns = list(self._fns.values())
        for fn in fns:
            try:
                fn(*args)
            except Exception:
                logging.debug("peer client: a subscriber raised", exc_info=True)


class PeerClient:
    """The state of one appliance, kept current, and a way to send it intents."""

    def __init__(self, peer_id: str, *, client_id: str, extra_body: Optional[Mapping] = None,
                 protocol: int = PROTOCOL, clock: Callable[[], float] = time.monotonic,
                 http=autostream_peer_http) -> None:
        self._peer_id = peer_id
        self._client_id = client_id
        self._extra = dict(extra_body or {})
        self._protocol = protocol
        self._clock = clock
        self._http = http
        self._cond = threading.Condition()
        self._snap = PeerSnapshot(
            peer_id=peer_id, boot=None, version=0, part_versions=_EMPTY, parts=_EMPTY,
            reachable=False, access=ACCESS_UNKNOWN, access_reason=None, protocol=None,
            protocol_ok=True, configured=None, heard_at=0.0, seq=0)
        self._subs = _Subscribers()
        self._sighting: Optional[tuple[str, int, Optional[int]]] = None
        self._gen = 0                       # moves with every change of the sighting
        self._session_gen = 0
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._conn_lock = threading.Lock()
        self._conns: set[socket.socket] = set()
        self._thread: Optional[threading.Thread] = None
        self._wb_lock = threading.Lock()
        self._wb_failures = 0
        self._wb_until = 0.0

    # -- lifecycle ----------------------------------------------------------

    def set_sighting(self, ip: str, port: int, proto: Optional[int]) -> None:
        """Where the peer is and the protocol it advertises. A change moves the
        client at once: the open connection is shut and the loop starts again
        at the new address."""
        value = (ip, int(port), proto)
        with self._conn_lock:
            if value == self._sighting:
                return
            self._sighting = value
            self._gen += 1
            self._shut_locked()
        self._wake.set()

    def start(self) -> None:
        with self._cond:
            if self._thread is not None:
                return
            self._thread = threading.Thread(target=self._run, daemon=True,
                                            name=f"peer-{self._peer_id[:8]}")
        self._thread.start()

    def stop(self) -> None:
        """Ask the thread to end and shut its connection. It does not join, so
        it is safe from a registry callback."""
        self._stop.set()
        self._wake.set()
        with self._conn_lock:
            self._shut_locked()
        with self._cond:
            self._cond.notify_all()

    @property
    def stopped(self) -> bool:
        """Whether stop() has been called."""
        return self._stop.is_set()

    @staticmethod
    def _shut(sock: socket.socket) -> None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def _shut_locked(self) -> None:
        for sock in list(self._conns):
            self._shut(sock)

    def _tracker(self) -> Callable[[Optional[socket.socket]], None]:
        """A tracker for one call: it registers the call's socket so a stop or
        a move can shut it, and drops it when called with None. A socket
        opened after the stop or the move is shut at once."""
        mine: list[socket.socket] = []

        def track(sock: Optional[socket.socket]) -> None:
            with self._conn_lock:
                if sock is None:
                    self._conns.difference_update(mine)
                    mine.clear()
                    return
                mine.append(sock)
                self._conns.add(sock)
                if self._stop.is_set() or self._gen != self._session_gen:
                    self._shut(sock)
        return track

    # -- reading ------------------------------------------------------------

    def snapshot(self) -> PeerSnapshot:
        """The current snapshot. A reference read; callers must not change it."""
        return self._snap

    def subscribe(self, fn: Callable[["PeerClient"], None]) -> int:
        """Call ``fn(client)`` after each change, outside the client's lock. It
        must return quickly and only signal."""
        return self._subs.add(fn)

    def unsubscribe(self, handle: int) -> None:
        self._subs.remove(handle)

    def wait_for_change(self, seen_seq: int, timeout: float) -> Optional[PeerSnapshot]:
        """The snapshot once its seq differs from *seen_seq*; None when
        *timeout* seconds pass (or the client stops) first."""
        with self._cond:
            self._cond.wait_for(lambda: self._snap.seq != seen_seq or self._stop.is_set(), timeout)
            return self._snap if self._snap.seq != seen_seq else None

    def _modify(self, build: Callable[[PeerSnapshot], Optional[dict]]) -> None:
        """Replace the snapshot by one with the changes *build* returns for the
        current one (None or no real change: nothing happens), then wake the
        waiters and call the subscribers."""
        with self._cond:
            old = self._snap
            changes = build(old)
            if not changes:
                return
            if all(not isinstance(v, Mapping) and getattr(old, k) == v for k, v in changes.items()):
                return
            self._snap = dataclasses.replace(old, seq=old.seq + 1, **changes)
            self._cond.notify_all()
        self._subs.call(self)

    def _set(self, **changes) -> None:
        self._modify(lambda old: changes)

    def _heard(self) -> None:
        """Note a line or reply from the peer. It moves heard_at and nothing
        else: the seq is unchanged and nobody is woken."""
        with self._cond:
            self._snap = dataclasses.replace(self._snap, heard_at=self._clock())

    # -- the loop -------------------------------------------------------------

    def _run(self) -> None:
        misses = 0
        resume = False
        while not self._stop.is_set():
            self._wake.clear()
            with self._conn_lock:
                sighting, self._session_gen = self._sighting, self._gen
            if sighting is None:
                self._wake.wait()
                continue
            ip, port, proto = sighting
            if proto is not None and proto != self._protocol:
                self._set(protocol_ok=False, reachable=False)
                self._wake.wait(PROTOCOL_RECHECK_S)
                resume = False
                continue
            try:
                self._session(ip, port, resume)
                outcome = "ended"
            except _SessionEnd as end:
                outcome = end.outcome
            except Exception:
                logging.warning("peer client %s: unexpected failure", self._peer_id[:8], exc_info=True)
                outcome = "miss"
            if self._stop.is_set():
                return
            with self._conn_lock:
                moved = self._gen != self._session_gen
            if moved:
                resume = outcome != "miss" and self._snap.boot is not None
                misses = 0
                continue
            if outcome == "ended":
                misses = 0
                resume = True
                continue
            if outcome == "mismatch":
                self._set(protocol_ok=False, reachable=False)
                self._wake.wait(PROTOCOL_RECHECK_S)
                resume = False
                continue
            if outcome == "miss":
                self._set(reachable=False)
            misses += 1
            resume = outcome == "busy"
            self._wake.wait(backoff_delay(misses))

    def _get(self, ip: str, port: int, path: str) -> dict:
        status, body, err = self._http.request_json(
            ip, port, "GET", path, read_s=STATE_READ_S, track=self._tracker())
        if err or status != 200 or body is None:
            raise _SessionEnd("miss")
        self._heard()
        return body

    def _session(self, ip: str, port: int, resume: bool) -> None:
        """One pass: look at the peer, read it whole unless the position is
        still good, then follow its stream until it ends. Ends by returning
        when the peer's stream ends, or by raising _SessionEnd."""
        if not resume:
            hello = self._get(ip, port, "/api/v1/state?parts=")
            number = hello.get("protocol")
            if isinstance(number, int) and number != self._protocol:
                self._set(protocol=number, protocol_ok=False, reachable=False)
                raise _SessionEnd("mismatch")
            self._set(protocol_ok=True, **self._appliance_facts(hello))
            self._full_read(ip, port)
        self._stream(ip, port)

    @staticmethod
    def _appliance_facts(body: dict) -> dict:
        facts: dict = {}
        if isinstance(body.get("protocol"), int):
            facts["protocol"] = body["protocol"]
        appliance = (body.get("parts") or {}).get("appliance")
        if isinstance(appliance, dict) and isinstance(appliance.get("configured"), bool):
            facts["configured"] = appliance["configured"]
        return facts

    def _full_read(self, ip: str, port: int) -> None:
        body = self._get(ip, port, "/api/v1/state")
        boot, version = body.get("boot"), body.get("version")
        parts, versions = body.get("parts"), body.get("part_versions")
        if not (isinstance(boot, str) and isinstance(version, int)
                and isinstance(parts, dict) and isinstance(versions, dict)):
            raise _SessionEnd("miss")
        self._set(boot=boot, version=version, parts=MappingProxyType(dict(parts)),
                  part_versions=MappingProxyType({str(k): v for k, v in versions.items()}),
                  reachable=True, **self._appliance_facts(body))

    def _stream(self, ip: str, port: int) -> None:
        snap = self._snap
        path = ("/api/v1/events?client=%s&protocol=%d&since=%s-%d"
                % (quote(self._client_id, safe=":"), self._protocol, snap.boot, snap.version))
        track = self._tracker()
        resp, status, refusal, err = self._http.open_events(
            ip, port, path, read_s=STREAM_READ_S, track=track)
        if resp is None:
            name = (refusal or {}).get("error")
            if name == "protocol_mismatch":
                raise _SessionEnd("mismatch")
            if name in _BUSY:
                self._heard()
                raise _SessionEnd("busy")
            raise _SessionEnd("miss")
        self._heard()
        heard_line = False
        try:
            for ev in self._http.read_events(resp):
                heard_line = True
                self._heard()
                if ev.event == "change":
                    self._on_change(ev, ip, port)
                elif ev.event == "access":
                    self._on_access(ev)
        except (OSError, autostream_peer_http.StreamError):
            # A shut socket (a stop or a move) is not the peer's doing.
            if self._stop.is_set():
                return
            with self._conn_lock:
                if self._gen != self._session_gen:
                    return
            raise _SessionEnd("miss")
        finally:
            try:
                resp.close()
            except OSError:
                pass
            track(None)
        if not heard_line:
            raise _SessionEnd("miss")      # a stream that opens and says nothing is no stream

    def _on_access(self, ev) -> None:
        try:
            data = json.loads(ev.data_text)
        except ValueError:
            return
        if isinstance(data, dict) and isinstance(data.get("role"), str):
            reason = data.get("reason")
            self._set(access=data["role"], access_reason=reason if isinstance(reason, str) else None)

    def _on_change(self, ev, ip: str, port: int) -> None:
        try:
            data = json.loads(ev.data_text)
        except ValueError:
            return
        if not isinstance(data, dict):
            return
        snap = self._snap
        boot, version = data.get("boot"), data.get("version")
        if data.get("resync") or boot != snap.boot:
            self._full_read(ip, port)
            return
        if not isinstance(version, int) or version <= snap.version:
            return          # already held: a full read overtook this event
        changed = data.get("data")
        if not isinstance(changed, dict):
            return

        def merge(old: PeerSnapshot) -> dict:
            versions = dict(old.part_versions)
            versions.update({name: version for name in changed})
            return {"version": version, "part_versions": MappingProxyType(versions),
                    "parts": MappingProxyType({**old.parts, **changed}),
                    "configured": self._configured_in(changed, old.configured)}
        self._modify(merge)

    @staticmethod
    def _configured_in(changed: dict, current: Optional[bool]) -> Optional[bool]:
        appliance = changed.get("appliance")
        if isinstance(appliance, dict) and isinstance(appliance.get("configured"), bool):
            return appliance["configured"]
        return current

    # -- writing --------------------------------------------------------------

    def submit(self, name: str, args: Mapping, *, extra_body: Optional[Mapping] = None,
               read_s: Optional[float] = None, backoff: bool = True) -> PeerReply:
        """Send the intent *name* with *args* and return the peer's answer.
        *extra_body* is merged over the client's own extra fields; the client,
        protocol and args fields are always the client's. With *backoff* False
        the call is not refused by the write backoff and its failure does not
        advance it. Never raises."""
        try:
            return self._submit(name, args, extra_body, read_s, backoff)
        except Exception:
            logging.warning("peer client %s: submit failed", self._peer_id[:8], exc_info=True)
            return _refused(autostream_peer_http.BAD_REPLY)

    def _submit(self, name, args, extra_body, read_s, backoff) -> PeerReply:
        snap = self._snap
        if not snap.protocol_ok:
            return _refused("protocol_mismatch")
        if snap.access == ACCESS_NONE:
            return _refused(snap.access_reason or "access_denied")
        with self._conn_lock:
            sighting = self._sighting
        if sighting is None:
            return _refused(autostream_peer_http.UNREACHABLE)
        if backoff:
            with self._wb_lock:
                left = self._wb_until - self._clock()
            if left > 0:
                return _refused("backoff", left)
        body = {**self._extra, **(extra_body or {}), "client": self._client_id,
                "protocol": self._protocol, "args": dict(args)}
        status, reply, err = self._http.request_json(
            sighting[0], sighting[1], "POST", "/api/v1/intents/" + quote(name, safe="._"),
            body=body, read_s=read_s if read_s is not None else INTENT_READ_S)
        if err or reply is None:
            if backoff:
                self._write_backoff(True)
            return _refused(err or autostream_peer_http.BAD_REPLY)
        self._write_backoff(False)
        self._heard()
        return _parse_reply(reply)

    def _write_backoff(self, failed: bool) -> None:
        with self._wb_lock:
            self._wb_failures = self._wb_failures + 1 if failed else 0
            self._wb_until = self._clock() + backoff_delay(self._wb_failures) if failed else 0.0

    def fetch(self, parts: Sequence[str], *, merge: bool = False) -> Optional[tuple[int, dict]]:
        """GET the named parts live from the peer: ``(status, body)`` for any
        reply, None when the peer could not be reached. With *merge*, a 200
        from the boot the snapshot holds replaces those parts in it (and
        wakes the readers); the version is unchanged, since the fast fields it
        is for carry none."""
        with self._conn_lock:
            sighting = self._sighting
        if sighting is None:
            return None
        status, body, err = self._http.request_json(
            sighting[0], sighting[1], "GET",
            "/api/v1/state?parts=" + quote(",".join(parts), safe=","), read_s=FETCH_READ_S)
        if err or body is None:
            return None
        self._heard()
        if merge and status == 200 and isinstance(body.get("parts"), dict):
            fresh = body["parts"]

            def fold(old: PeerSnapshot) -> Optional[dict]:
                if old.boot is None or body.get("boot") != old.boot:
                    return None
                return {"parts": MappingProxyType({**old.parts, **fresh})}
            self._modify(fold)
        return status, body


# -- the pool and the roster -----------------------------------------------------

@dataclass(frozen=True)
class RosterEntry:
    id: str
    hostname: str
    version: str
    control: bool
    reachable: bool
    protocol_ok: bool
    access: str
    configured: Optional[bool]
    playing: bool


def roster_view(sightings: Mapping[str, Sighting],
                snapshots: Mapping[str, PeerSnapshot]) -> tuple[RosterEntry, ...]:
    """One entry per sighting, ordered by hostname without regard to case. An
    appliance with no snapshot yet is unreachable and unknown."""
    entries = []
    for peer_id, s in sightings.items():
        snap = snapshots.get(peer_id)
        session = snap.parts.get("session") if snap is not None else None
        entries.append(RosterEntry(
            id=peer_id, hostname=s.hostname, version=s.version, control=s.control,
            reachable=snap is not None and snap.reachable,
            protocol_ok=snap is None or snap.protocol_ok,
            access=snap.access if snap is not None else ACCESS_UNKNOWN,
            configured=snap.configured if snap is not None else None,
            playing=isinstance(session, Mapping) and session.get("active") is True))
    entries.sort(key=lambda e: (e.hostname.casefold(), e.id))
    return tuple(entries)


class PeerPool:
    """One started PeerClient for each appliance the registry sees."""

    def __init__(self, registry: PeerRegistry, make_client: Callable[[str], PeerClient]) -> None:
        self._registry = registry
        self._make_client = make_client
        self._lock = threading.Lock()
        self._clients: Mapping[str, PeerClient] = {}
        self._subs = _Subscribers()
        self._handle: Optional[int] = None

    def start(self) -> None:
        """Follow the registry: subscribe, then make clients for the sightings
        already there. Idempotent."""
        with self._lock:
            if self._handle is not None:
                return
            self._handle = self._registry.subscribe(self._on_registry)
        for peer_id, sighting in self._registry.sightings().items():
            self._on_registry("add", peer_id, sighting)

    def stop(self) -> None:
        with self._lock:
            handle, self._handle = self._handle, None
            clients, self._clients = self._clients, {}
        if handle is not None:
            self._registry.unsubscribe(handle)
        for client in clients.values():
            client.stop()

    def clients(self) -> Mapping[str, PeerClient]:
        """The clients by appliance id. A reference read; it is never changed."""
        return self._clients

    def get(self, peer_id: str) -> Optional[PeerClient]:
        return self._clients.get(peer_id)

    def subscribe(self, fn: Callable[[], None]) -> int:
        """Call ``fn()`` when a client is added or removed, a sighting changes
        or a client's snapshot changes. Signal-only."""
        return self._subs.add(fn)

    def unsubscribe(self, handle: int) -> None:
        self._subs.remove(handle)

    def _on_registry(self, kind: str, peer_id: str, sighting: Optional[Sighting]) -> None:
        stopped: Optional[PeerClient] = None
        with self._lock:
            if self._handle is None:
                return
            client = self._clients.get(peer_id)
            if kind == "remove":
                if client is None:
                    return
                stopped = client
                self._clients = {k: v for k, v in self._clients.items() if k != peer_id}
            elif sighting is not None:
                if client is None:
                    client = self._make_client(peer_id)
                    client.subscribe(self._on_client)
                    self._clients = {**self._clients, peer_id: client}
                    client.set_sighting(sighting.ip, sighting.port, sighting.proto)
                    client.start()
                else:
                    client.set_sighting(sighting.ip, sighting.port, sighting.proto)
        if stopped is not None:
            stopped.stop()
        self._subs.call()

    def _on_client(self, _client: PeerClient) -> None:
        self._subs.call()
