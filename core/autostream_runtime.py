"""autostream_runtime.py -- process-wide runtime primitives.

A leaf module (standard library only): the process stop and reload requests,
the shared task pool for backgrounded single-flight work, and the recovery
log helper.  Nothing here imports another application module, so any module
may use it without creating an import cycle.

Process-wide signals (not tied to any store):

  stop_flag    -- shutdown request; the signal handler sets it and every loop
                  that should end with the process waits on or polls it.
  reload_flag  -- configuration reload request; the coordinator picks it up
                  within one poll interval, tears down and re-initialises its
                  monitors, and clears it.
"""

import concurrent.futures
import logging
import threading


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


def reset_for_tests() -> None:
    """Clear both process events.  Called by an autouse fixture after every
    test."""
    stop_flag.clear()
    reload_flag.clear()
