"""autostream_runtime.py -- process-wide runtime primitives.

A leaf module (standard library; the playback tracker type is imported for
type checking only): the process stop and reload requests, the shared task
pool for backgrounded single-flight work, the recovery log helper, and the
registry of live monitors and the identification service.  Nothing here
imports another application module at run time, so any module may use it
without creating an import cycle.

Process-wide signals (not tied to any store):

  stop_flag    -- shutdown request; the signal handler sets it and every loop
                  that should end with the process waits on or polls it.
  reload_flag  -- configuration reload request; the coordinator picks it up
                  within one poll interval, tears down and re-initialises its
                  monitors, and clears it.

and the now-playing republish request: set when a speaker has started (or the
backend has been brought back), consumed once by the coordinator.
"""

from __future__ import annotations

import concurrent.futures
import logging
import threading
import time
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from autostream_playback_stats import PlaybackTracker


stop_flag = threading.Event()
reload_flag = threading.Event()


def request_config_reload() -> None:
    """Signal the coordinator loop to tear down and re-initialise all monitors.

    Called by the Web UI after a successful settings save.  The coordinator
    picks this up within one poll interval and re-reads the INI without
    restarting the process.
    """
    reload_flag.set()


class TaskPool:
    """Small bounded thread pool with single-flight-per-key submission.

    A fixed-size `ThreadPoolExecutor` backs the pool; `submit(key, fn, ...)`
    is a no-op (returns False, nothing scheduled) when a task already
    in flight under the same key -- callers that need "at most one
    in-flight task per key" get it for free, rather than each new
    backgrounded operation hand-rolling its own `threading.Thread(...)`
    call and rate-limit/inflight bookkeeping.

    Not itself a queue: a rejected (duplicate-key) submission is dropped,
    not deferred -- matching every current call site's existing shape
    (a rate-limited watchdog restart, a gate-admitted identification
    worker), none of which need a submission to wait its turn.
    """

    def __init__(self, max_workers: int = 2) -> None:
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="taskpool",
        )
        self._inflight: dict[str, "concurrent.futures.Future"] = {}
        self._lock = threading.Lock()

    def submit(self, key: str, fn, *args, **kwargs) -> bool:
        """Submit fn(*args, **kwargs) under single-flight key *key*.

        Returns True if a task was scheduled, False if a task already
        in flight under *key* (submission is then a no-op).
        """
        with self._lock:
            existing = self._inflight.get(key)
            if existing is not None and not existing.done():
                return False

            def _run() -> None:
                try:
                    fn(*args, **kwargs)
                finally:
                    # Single-flight-per-key guarantees no other submission
                    # for this key can be accepted while _run is executing
                    # (the check above only passes once the prior future is
                    # done, which -- for a ThreadPoolExecutor future -- is
                    # only true once _run itself has returned), so it is
                    # always safe to unconditionally drop this key's entry
                    # here rather than compare-and-clear against a future
                    # reference not yet in scope.
                    with self._lock:
                        self._inflight.pop(key, None)

            future = self._executor.submit(_run)
            self._inflight[key] = future
            return True

    def is_inflight(self, key: str) -> bool:
        with self._lock:
            future = self._inflight.get(key)
            return future is not None and not future.done()


# Process-wide task pool: the one place backgrounded, single-flight-per-key
# work is scheduled (currently: the OwnTone hang-watchdog restart, per-input
# track identification, and -- via get_task_pool() below -- autostream_align's
# "align-run" job). See TaskPool.
_task_pool = TaskPool(max_workers=2)


def get_task_pool() -> "TaskPool":
    """Return the process-wide task pool.

    External modules that need to schedule work under this pool's
    single-flight-per-key contract (e.g. autostream_align.AlignRun) call this
    instead of reaching into the private _task_pool global directly.
    """
    return _task_pool


# ── Now-playing republish request ────────────────────────────────────────────
# Set when a speaker has started (the output authority raises it) or the
# player has just been brought back: in both cases the receiver-side backend
# only knows the bare queue defaults until the next natural metadata push, so
# the coordinator poll loop consumes this flag once per request and re-sends
# the active session's current now-playing bundle. The lock is a leaf: it
# guards a bool store and nothing is called under it.

_republish_lock = threading.Lock()
_republish_pending: bool = False


def request_nowplaying_republish() -> None:
    """Ask the coordinator to re-send the current now-playing metadata."""
    global _republish_pending
    with _republish_lock:
        _republish_pending = True


def consume_nowplaying_republish() -> bool:
    """Return-and-clear the pending republish request (coordinator loop)."""
    global _republish_pending
    with _republish_lock:
        pending = _republish_pending
        _republish_pending = False
        return pending


# ── Now-playing metadata push time ───────────────────────────────────────────
# The metadata writer stamps the time a now-playing bundle (title, artwork)
# has been written to the player; the output policy reads it to tell a Play
# that answers new artwork from one the user pressed. The lock is a leaf: it
# guards a float store and nothing is called under it.

_metadata_push_lock = threading.Lock()
_metadata_push_at: Optional[float] = None


def note_metadata_push(at: Optional[float] = None) -> None:
    """A now-playing bundle (title, artwork) has just been written to the
    player; *at* defaults to time.monotonic()."""
    global _metadata_push_at
    stamp = time.monotonic() if at is None else at
    with _metadata_push_lock:
        _metadata_push_at = stamp


def last_metadata_push() -> Optional[float]:
    """When the last now-playing bundle was written, or None."""
    with _metadata_push_lock:
        return _metadata_push_at


class RecoveryLog:
    """Emits one WARNING when a failing condition clears, so an operator
    reading WARN-level logs sees the recovery, not just the failure stream."""

    def __init__(self, subject: str):
        self._subject = subject
        self._failing = False
        self._count = 0
        self._first_failure_at = 0.0

    def fail(self, now: float) -> None:
        if not self._failing:
            self._failing = True
            self._first_failure_at = now
        self._count += 1

    def ok(self, now: float) -> None:
        if self._failing:
            logging.warning(
                "%s recovered after %d failure(s) (down for %.0fs)",
                self._subject, self._count, now - self._first_failure_at)
        self._failing = False
        self._count = 0


# --------------------------------------------------------------------------- #
# Registry: the live monitors and the identification service                   #
# --------------------------------------------------------------------------- #
#
# The names below are rebound by their writers (and cleared by the tests), so
# every reader goes through the module object (``runtime._track_id_service``)
# at the point of use, never ``from autostream_runtime import ...``.

# Track all AudioMonitor instances so coordination logic can inspect them.
# _monitors_lock must be held when reading or mutating all_monitors or when
# taking a snapshot of its elements for use on a different thread (Web UI).
all_monitors: list = []
_monitors_lock = threading.Lock()
_playback_tracker: Optional["PlaybackTracker"] = None

# Track identification service singleton (replaced on each config reload).
# Written only from the coordinator thread; read from worker threads under GIL.
_track_id_service = None  # Optional[TrackIdentificationService]

# Process-wide identification admission gate.  A non-blocking acquire is attempted
# before every worker dispatch; at most one identification request runs globally.
# Semaphore-shaped, not a plain data lock -- do not merge with anything else.
_track_id_request_gate = threading.Lock()


def monitors_snapshot() -> list:
    """Return a copy of all_monitors, taken under the monitors lock."""
    with _monitors_lock:
        return list(all_monitors)


def reset_for_tests() -> None:
    """Return the process-wide state to its start-up values: no monitors, no
    playback tracker, no identification service, a free admission gate, no
    republish request and both events clear.  Called by an autouse fixture after every test."""
    global _playback_tracker, _track_id_service, _track_id_request_gate, _republish_pending
    global _metadata_push_at
    _republish_pending = False
    _metadata_push_at = None
    with _monitors_lock:
        all_monitors.clear()
    _playback_tracker = None
    _track_id_service = None
    if _track_id_request_gate.locked():
        _track_id_request_gate = threading.Lock()
    stop_flag.clear()
    reload_flag.clear()
