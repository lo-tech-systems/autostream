"""tests/lockcheck.py

A lock that records which thread holds it, for tests of lock order.

TrackedLock stands in for a module's own lock. While any TrackedLock is held
by the calling thread, held() names it; acquiring one while the state store's
lock is held by the calling thread is recorded in ACQUIRED_UNDER_STORE.
Install with install(store) after store.reset_for_tests(track_locks=True);
that also makes the store report any subscriber called while a tracked lock
(or the store lock) is held.
"""
from __future__ import annotations

import threading

_local = threading.local()
ACQUIRED_UNDER_STORE: list[str] = []
_store = None


def _held_set() -> set:
    held = getattr(_local, "held", None)
    if held is None:
        held = _local.held = set()
    return held


def _store_lock_held() -> bool:
    lock = getattr(_store, "_lock", None)
    probe = getattr(lock, "held_by_current_thread", None)
    return bool(probe and probe())


def held() -> frozenset:
    """Names of the tracked locks the calling thread holds, plus "store" when
    it holds the state store's lock."""
    out = set(_held_set())
    if _store_lock_held():
        out.add("store")
    return frozenset(out)


class TrackedLock:
    def __init__(self, name: str) -> None:
        self.name = name
        self._lock = threading.Lock()

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        if _store_lock_held():
            ACQUIRED_UNDER_STORE.append(self.name)
        ok = self._lock.acquire(blocking, timeout)
        if ok:
            _held_set().add(self.name)
        return ok

    def release(self) -> None:
        _held_set().discard(self.name)
        self._lock.release()

    def locked(self) -> bool:
        return self._lock.locked()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc) -> None:
        self.release()


def install(state_store) -> None:
    global _store
    _store = state_store
    ACQUIRED_UNDER_STORE.clear()
    state_store._held_locks_probe = held


def uninstall() -> None:
    global _store
    _store = None
    ACQUIRED_UNDER_STORE.clear()
    _held_set().clear()
