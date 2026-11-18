"""tests/lockcheck.py

A lock that records which thread holds it, for tests of lock order.

TrackedLock stands in for a module's own lock. While any TrackedLock is held
by the calling thread, held() names it; acquiring one while the state store's
lock is held by the calling thread is recorded in ACQUIRED_UNDER_STORE.
Install with install(store) after store.reset_for_tests(track_locks=True);
that also makes the store report any subscriber called while a tracked lock
(or the store lock) is held.

A lock may be given a rank. Taking a ranked lock while the thread already
holds a ranked lock of the same or a higher rank is recorded in
ORDER_VIOLATIONS, so a test asserts the order a design states without having
to make the wrong order happen. ACQUIRED_BY names the threads that took each
tracked lock.
"""
from __future__ import annotations

import threading

_local = threading.local()
ACQUIRED_UNDER_STORE: list[str] = []
ORDER_VIOLATIONS: list[tuple[str, frozenset]] = []
ACQUIRED_BY: dict[str, set] = {}
_store = None


def _held_set() -> set:
    held = getattr(_local, "held", None)
    if held is None:
        held = _local.held = set()
    return held


def _ranks() -> dict:
    ranks = getattr(_local, "ranks", None)
    if ranks is None:
        ranks = _local.ranks = {}
    return ranks


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
    def __init__(self, name: str, rank: int | None = None) -> None:
        self.name = name
        self.rank = rank
        self._lock = threading.Lock()

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        if _store_lock_held():
            ACQUIRED_UNDER_STORE.append(self.name)
        if self.rank is not None:
            higher = {n for n, r in _ranks().items() if r >= self.rank}
            if higher:
                ORDER_VIOLATIONS.append((self.name, frozenset(higher)))
        ok = self._lock.acquire(blocking, timeout)
        if ok:
            _held_set().add(self.name)
            if self.rank is not None:
                _ranks()[self.name] = self.rank
            ACQUIRED_BY.setdefault(self.name, set()).add(threading.current_thread().name)
        return ok

    def release(self) -> None:
        _held_set().discard(self.name)
        _ranks().pop(self.name, None)
        self._lock.release()

    def held_by_current_thread(self) -> bool:
        return self.name in _held_set()

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
    ORDER_VIOLATIONS.clear()
    ACQUIRED_BY.clear()
    state_store._held_locks_probe = held


def uninstall() -> None:
    global _store
    _store = None
    ACQUIRED_UNDER_STORE.clear()
    ORDER_VIOLATIONS.clear()
    ACQUIRED_BY.clear()
    _held_set().clear()
    _ranks().clear()
