"""tests/test_task_pool.py

Coverage for the bounded task-pool-with-single-flight-keys primitive
introduced in autostream_core: a small fixed-size ThreadPoolExecutor
where submitting a second task under a key already in flight is a no-op
(returns False) rather than queuing a duplicate.
"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_core as core


def _wait_until(predicate, timeout=2.0, interval=0.01):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def test_submit_runs_the_task():
    pool = core.TaskPool(max_workers=2)
    done = threading.Event()
    result = {}

    def work():
        result["ran"] = True
        done.set()

    submitted = pool.submit("k1", work)

    assert submitted is True
    assert done.wait(timeout=2.0)
    assert result.get("ran") is True


def test_submit_passes_args_and_kwargs():
    pool = core.TaskPool(max_workers=2)
    done = threading.Event()
    captured = {}

    def work(a, b, c=None):
        captured["args"] = (a, b, c)
        done.set()

    pool.submit("k1", work, 1, 2, c=3)

    assert done.wait(timeout=2.0)
    assert captured["args"] == (1, 2, 3)


def test_duplicate_key_while_inflight_is_rejected():
    pool = core.TaskPool(max_workers=2)
    release = threading.Event()
    started = threading.Event()

    def slow_work():
        started.set()
        release.wait(timeout=2.0)

    first = pool.submit("dup-key", slow_work)
    assert started.wait(timeout=2.0)

    second = pool.submit("dup-key", lambda: None)

    assert first is True
    assert second is False

    release.set()


def test_key_becomes_available_again_after_task_completes():
    pool = core.TaskPool(max_workers=2)
    done = threading.Event()

    pool.submit("k1", lambda: done.set())
    assert done.wait(timeout=2.0)

    # Give the pool's own cleanup (in TaskPool._run's finally) a moment to
    # drop the completed future from the inflight table.
    assert _wait_until(lambda: not pool.is_inflight("k1"))

    second_ran = threading.Event()
    submitted_again = pool.submit("k1", lambda: second_ran.set())

    assert submitted_again is True
    assert second_ran.wait(timeout=2.0)


def test_different_keys_run_concurrently():
    pool = core.TaskPool(max_workers=2)
    both_started = threading.Event()
    starts = []
    release = threading.Event()
    lock = threading.Lock()

    def work():
        with lock:
            starts.append(1)
            if len(starts) == 2:
                both_started.set()
        release.wait(timeout=2.0)

    pool.submit("a", work)
    pool.submit("b", work)

    assert both_started.wait(timeout=2.0)
    release.set()


def test_is_inflight_reflects_running_task():
    pool = core.TaskPool(max_workers=2)
    release = threading.Event()
    started = threading.Event()

    def slow_work():
        started.set()
        release.wait(timeout=2.0)

    assert pool.is_inflight("k1") is False
    pool.submit("k1", slow_work)
    assert started.wait(timeout=2.0)
    assert pool.is_inflight("k1") is True

    release.set()
    assert _wait_until(lambda: pool.is_inflight("k1") is False)


def test_exception_in_task_does_not_break_the_pool():
    pool = core.TaskPool(max_workers=2)
    done = threading.Event()

    def raises():
        raise RuntimeError("boom")

    pool.submit("bad", raises)
    # No observable crash; a subsequent submission under the same key must
    # eventually be accepted once the pool's cleanup has run.
    assert _wait_until(lambda: not pool.is_inflight("bad"))

    pool.submit("bad", lambda: done.set())
    assert done.wait(timeout=2.0)


def test_process_wide_task_pool_singleton_exists():
    assert isinstance(core._task_pool, core.TaskPool)
