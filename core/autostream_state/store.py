"""autostream_state.store -- the process's immutable state snapshot.

One writer per part. A writer publishes in two phases: publish() (or
update()) swaps the part into a new Snapshot under the store lock and returns
a Pending; the writer then drops its own lock and calls Pending.notify(),
which tells the subscribers. Subscribers are therefore never called with the
store lock or the writer's lock held.

Readers take snapshot(), a plain reference read with no lock, and use it for
as long as they like: a Snapshot never changes.

Lock order (outermost first): a writer's own lock, then the store lock, which
is a leaf. Nothing is acquired and nothing is logged while the store lock is
held, and the function given to update() must do neither.
"""
from __future__ import annotations

import dataclasses
import itertools
import logging
import secrets
import threading
import traceback
import weakref
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

from .freeze import FrozenDict, deep_freeze
from .origin import Origin
from .parts import DIGESTS, PART_NAMES, Snapshot


@dataclass(frozen=True)
class Change:
    version: int                        # store version after the change(s)
    parts: frozenset                    # parts whose digest moved (may be empty)
    origin: Optional[Origin]
    requester: Optional[str]            # "webui", "dial:<uuid>", "peer:<id>", "coordinator"
    tags: frozenset = frozenset()       # publisher-supplied labels, e.g. {"session"} for a session edge
    batch: bool = False                 # emitted by Batch.close()


class WriterTaken(RuntimeError):
    """A second owner tried to claim a part that already has one."""


class _RecordingLock:
    """A lock that knows which thread holds it. Used by tests only, in place
    of the store lock, to check the lock-order rules."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._holder: Optional[int] = None

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        ok = self._lock.acquire(blocking, timeout)
        if ok:
            self._holder = threading.get_ident()
        return ok

    def release(self) -> None:
        self._holder = None
        self._lock.release()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc) -> None:
        self.release()

    def locked(self) -> bool:
        return self._lock.locked()

    def held_by_current_thread(self) -> bool:
        return self._holder == threading.get_ident()


class Pending:
    """The second half of a publish: the Change waiting to be delivered."""

    def __init__(self, store: "StateStore", version: int, change: Optional[Change]) -> None:
        self._store = store
        self.version = version
        self.changed = change is not None
        self._change = change
        self._done = False

    def notify(self) -> None:
        """Deliver the Change to subscribers on this thread, or hand it to the
        batch this thread has open. Idempotent. Call after releasing the
        writer's own lock."""
        if self._done:
            return
        self._done = True
        change = self._change
        if change is None:
            return
        self._store._notified(self)
        self._store._deliver(change)


class PartWriter:
    """The one writer of a part."""

    def __init__(self, store: "StateStore", part: str, owner: str) -> None:
        self._store = store
        self.part = part
        self.owner = owner

    def publish(self, value, *, origin: Optional[Origin] = None,
                requester: Optional[str] = None, tags: Iterable[str] = ()) -> Pending:
        """Phase 1: freeze value (outside the store lock), then under the
        store lock compare its digest with the part's current digest, swap the
        part, rebuild the top-level Snapshot, bump the version and the part's
        entry in part_versions only when the digest moved. Returns at once.
        A Change is pending when the digest moved or tags were given."""
        frozen = deep_freeze(value)
        digest = DIGESTS[self.part](frozen)
        return self._store._commit(self.part, frozen, digest, None, origin, requester, tags)

    def update(self, fn: Callable, *, origin: Optional[Origin] = None,
               requester: Optional[str] = None, tags: Iterable[str] = ()) -> Pending:
        """As publish, with the new value computed as fn(current) under the
        store lock (read-modify-write for parts with several publishing
        threads). fn must be pure and fast: no I/O, no locks, no logging."""
        return self._store._commit(self.part, None, None, fn, origin, requester, tags)


class Batch:
    """Collects what this thread notifies while it is open and delivers it as
    one Change when it is closed. Returned already open by
    StateStore.batch(); also usable as ``with store().batch():``."""

    def __init__(self, store: "StateStore", thread: int) -> None:
        self._store = store
        self._thread = thread
        self._changes: list[Change] = []
        self._closed = False

    def __enter__(self) -> "Batch":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _add(self, change: Change) -> None:
        self._changes.append(change)

    def close(self) -> None:
        """Idempotent. Emits exactly one Change(batch=True) whose parts and
        tags are the unions of everything notified on this thread while open
        (parts may be empty), version = the latest, origin and requester kept
        only when all merged changes agree, else None."""
        if self._closed:
            return
        self._closed = True
        self._store._close_batch(self)
        changes = self._changes
        if changes:
            origins = {c.origin for c in changes}
            requesters = {c.requester for c in changes}
            merged = Change(
                version=max(c.version for c in changes),
                parts=frozenset().union(*(c.parts for c in changes)),
                origin=origins.pop() if len(origins) == 1 else None,
                requester=requesters.pop() if len(requesters) == 1 else None,
                tags=frozenset().union(*(c.tags for c in changes)),
                batch=True,
            )
        else:
            merged = Change(
                version=self._store.snapshot().version, parts=frozenset(),
                origin=None, requester=None, batch=True,
            )
        self._store._call_subscribers(merged)


class StateStore:
    def __init__(self) -> None:
        self._test_mode = False
        self._held_locks_probe: Callable = lambda: ()
        self.lock_violations: list = []
        self._claims: dict[str, tuple[str, PartWriter]] = {}
        self._reset_state()

    # -- construction --------------------------------------------------

    def _reset_state(self) -> None:
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._digests: dict[str, object] = {}
        snap = Snapshot(boot=secrets.token_hex(8), part_versions=FrozenDict())
        for part in PART_NAMES:
            self._digests[part] = DIGESTS[part](getattr(snap, part))
        self._snapshot = snap
        self._subs: tuple = ()
        self._handles = itertools.count(1)
        self._batches: dict[int, Batch] = {}
        self._live: dict[int, tuple] = {}
        self._leaked: list[str] = []

    # -- reading ---------------------------------------------------------

    def snapshot(self) -> Snapshot:
        """The current snapshot: a reference read, no lock."""
        return self._snapshot

    def wait_for_change(self, seen: int, timeout: float) -> Optional[Snapshot]:
        """The snapshot once its version is above *seen*, or None when
        *timeout* seconds pass first."""
        with self._cond:
            if self._cond.wait_for(lambda: self._snapshot.version > seen, timeout):
                return self._snapshot
        return None

    # -- subscribing -----------------------------------------------------

    def subscribe(self, fn: Callable[[Change], None]) -> int:
        handle = next(self._handles)
        with self._lock:
            self._subs = self._subs + ((handle, fn),)
        return handle

    def unsubscribe(self, handle: int) -> None:
        with self._lock:
            self._subs = tuple(s for s in self._subs if s[0] != handle)

    def batch(self) -> Batch:
        """Open a batch bound to the calling thread and return it. Opening a
        second on one thread raises RuntimeError."""
        ident = threading.get_ident()
        if ident in self._batches:
            raise RuntimeError("a batch is already open on this thread")
        b = Batch(self, ident)
        self._batches[ident] = b
        return b

    # -- writers ---------------------------------------------------------

    def claim(self, part: str, owner: str) -> PartWriter:
        """The one writer of *part*. *owner* is a string literal naming the
        owning module, never __name__. The same owner gets the same handle
        again; another owner raises WriterTaken."""
        if part not in PART_NAMES:
            raise KeyError(f"unknown part: {part}")
        with self._lock:
            held = self._claims.get(part)
            if held is not None:
                if held[0] != owner:
                    raise WriterTaken(f"part {part!r} is owned by {held[0]}, not {owner}")
                return held[1]
            writer = PartWriter(self, part, owner)
            self._claims[part] = (owner, writer)
            return writer

    def _commit(self, part: str, value, digest, fn, origin, requester, tags) -> Pending:
        tag_set = frozenset(tags)
        with self._lock:
            snap = self._snapshot
            if fn is not None:
                value = deep_freeze(fn(getattr(snap, part)))
                digest = DIGESTS[part](value)
            moved = digest != self._digests[part]
            fields = {part: value}
            if moved:
                fields["version"] = snap.version + 1
                fields["part_versions"] = FrozenDict({**snap.part_versions, part: snap.version + 1})
                self._digests[part] = digest
            new = dataclasses.replace(snap, **fields)
            self._snapshot = new
            if moved:
                self._cond.notify_all()
        change = None
        if moved or tag_set:
            change = Change(
                version=new.version,
                parts=frozenset((part,)) if moved else frozenset(),
                origin=origin, requester=requester, tags=tag_set,
            )
        pending = Pending(self, new.version, change)
        if change is not None and self._test_mode:
            self._track(pending)
        return pending

    # -- delivery --------------------------------------------------------

    def _deliver(self, change: Change) -> None:
        batch = self._batches.get(threading.get_ident())
        if batch is not None:
            batch._add(change)
        else:
            self._call_subscribers(change)

    def _close_batch(self, batch: Batch) -> None:
        if self._batches.get(batch._thread) is batch:
            del self._batches[batch._thread]

    def _call_subscribers(self, change: Change) -> None:
        held = self._held_locks_probe()
        if held:
            self.lock_violations.append(("subscriber called holding", tuple(sorted(held))))
        for _handle, fn in self._subs:
            try:
                fn(change)
            except Exception:
                logging.debug("state: subscriber failed", exc_info=True)

    # -- leak detection (test mode) --------------------------------------

    def _track(self, pending: Pending) -> None:
        key = id(pending)
        stack = "".join(traceback.format_stack(limit=12)[:-2])
        ref = weakref.ref(pending, lambda _r, key=key: self._died(key))
        self._live[key] = (ref, stack)

    def _died(self, key: int) -> None:
        # Runs from the garbage collector on any thread: no lock.
        entry = self._live.pop(key, None)
        if entry is not None:
            self._leaked.append(entry[1])

    def _notified(self, pending: Pending) -> None:
        self._live.pop(id(pending), None)

    def take_leaked(self) -> list:
        """Test mode only: the creation stacks of pendings that were never
        notified, whether still alive or already collected. Empties the
        record."""
        out = list(self._leaked)
        out.extend(stack for _ref, stack in list(self._live.values()))
        self._leaked.clear()
        self._live.clear()
        return out

    # -- tests -----------------------------------------------------------

    def reset_for_tests(self, *, track_locks: bool = False) -> None:
        """In place: new boot id, version 0, default parts, no subscribers, no
        open batches, leak record emptied, test mode on. Claims survive, so
        handles held by modules stay valid. With track_locks the store lock
        is replaced by a recording lock and the Condition used by
        wait_for_change is rebuilt on that new lock."""
        self._reset_state()
        self._test_mode = True
        self._held_locks_probe = lambda: ()
        self.lock_violations = []
        if track_locks:
            self._lock = _RecordingLock()
            self._cond = threading.Condition(self._lock)

    def publish_for_tests(self, part: str, value) -> Snapshot:
        """Test mode only: swap *value* into *part* without the owner, without
        a Pending and without telling subscribers."""
        if not self._test_mode:
            raise RuntimeError("publish_for_tests is only available in test mode")
        if part not in PART_NAMES:
            raise KeyError(f"unknown part: {part}")
        frozen = deep_freeze(value)
        digest = DIGESTS[part](frozen)
        with self._lock:
            snap = self._snapshot
            fields = {part: frozen}
            if digest != self._digests[part]:
                fields["version"] = snap.version + 1
                fields["part_versions"] = FrozenDict({**snap.part_versions, part: snap.version + 1})
                self._digests[part] = digest
            self._snapshot = dataclasses.replace(snap, **fields)
            self._cond.notify_all()
            return self._snapshot


_STORE = StateStore()


def store() -> StateStore:
    """The process singleton."""
    return _STORE
