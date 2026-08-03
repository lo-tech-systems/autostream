"""Tests for platform/bluetooth_loop.py's LoopBridge.

A fake ``idle_add`` stands in for GLib: it hands the scheduled callback to a
tiny worker thread so call_soon/call_sync exercise real cross-thread
scheduling and blocking without any real main loop or PyGObject involved.
"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
for _p in (REPO_ROOT / "platform",):
    _s = str(_p)
    if _s not in sys.path:
        sys.path.insert(0, _s)

import bluetooth_loop as loop_mod  # noqa: E402


class FakeLoop:
    """Runs scheduled callbacks on its own thread, one at a time, in
    submission order -- close enough to GLib's idle_add semantics (single
    dispatch thread, FIFO) for these tests without needing a real loop."""

    def __init__(self) -> None:
        self._queue: list = []
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self.thread_id: int = 0
        self._thread = threading.Thread(target=self._run, daemon=True, name="fake-loop")
        self._thread.start()

    def _run(self) -> None:
        self.thread_id = threading.get_ident()
        while not self._stop.is_set():
            self._wake.wait(timeout=0.05)
            self._wake.clear()
            with self._lock:
                pending, self._queue = self._queue, []
            for cb in pending:
                cb()

    def idle_add(self, cb) -> None:
        with self._lock:
            self._queue.append(cb)
        self._wake.set()

    def run_on_loop_thread(self, fn) -> None:
        """Test helper: block until the given fn has executed on the loop
        thread (used to make call-from-loop-thread assertions deterministic)."""
        done = threading.Event()

        def _wrapped():
            fn()
            done.set()

        self.idle_add(_wrapped)
        done.wait(timeout=2.0)

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2.0)


@pytest.fixture()
def fake_loop():
    loop = FakeLoop()
    # Ensure the loop thread has started and recorded its identity before
    # any test uses it.
    deadline = time.monotonic() + 2.0
    while loop.thread_id == 0 and time.monotonic() < deadline:
        time.sleep(0.01)
    yield loop
    loop.stop()


def test_call_soon_executes_with_args(fake_loop):
    bridge = loop_mod.LoopBridge(idle_add=fake_loop.idle_add)
    seen = []
    done = threading.Event()

    def fn(a, b):
        seen.append((a, b))
        done.set()

    bridge.call_soon(fn, 1, 2)
    assert done.wait(timeout=2.0)
    assert seen == [(1, 2)]


def test_call_soon_swallows_exceptions(fake_loop):
    bridge = loop_mod.LoopBridge(idle_add=fake_loop.idle_add)

    def fn():
        raise ValueError("boom")

    # Must not raise here, and must not kill the fake loop thread.
    bridge.call_soon(fn)

    # Loop is still alive and can run further work afterwards.
    marker = threading.Event()
    bridge.call_soon(marker.set)
    assert marker.wait(timeout=2.0)


def test_call_sync_returns_value(fake_loop):
    bridge = loop_mod.LoopBridge(idle_add=fake_loop.idle_add)

    def fn(x):
        return x * 2

    assert bridge.call_sync(fn, 21) == 42


def test_call_sync_reraises_exception(fake_loop):
    bridge = loop_mod.LoopBridge(idle_add=fake_loop.idle_add)

    def fn():
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        bridge.call_sync(fn)


def test_call_sync_timeout(fake_loop):
    # idle_add that never actually schedules anything -> call_sync must
    # time out rather than hang forever.
    def dead_idle_add(cb):
        pass

    bridge = loop_mod.LoopBridge(idle_add=dead_idle_add)

    with pytest.raises(loop_mod.LoopCallTimeout):
        bridge.call_sync(lambda: None, timeout=0.1)


def test_call_sync_from_loop_thread_raises(fake_loop):
    bridge = loop_mod.LoopBridge(idle_add=fake_loop.idle_add)
    bridge.mark_loop_thread()  # pretend the current (test) thread is the loop

    with pytest.raises(RuntimeError):
        bridge.call_sync(lambda: None)


def test_assert_on_loop_before_marking_is_noop():
    bridge = loop_mod.LoopBridge(idle_add=lambda cb: None)
    # No loop thread marked yet -> must not raise from any thread.
    bridge.assert_on_loop()


def test_assert_on_loop_passes_on_loop_thread(fake_loop):
    bridge = loop_mod.LoopBridge(idle_add=fake_loop.idle_add)

    outcome = {}

    def check():
        try:
            bridge.assert_on_loop()
            outcome["ok"] = True
        except Exception as e:
            outcome["ok"] = False
            outcome["error"] = e

    # Mark from the loop thread itself, then assert from the loop thread.
    fake_loop.run_on_loop_thread(bridge.mark_loop_thread)
    fake_loop.run_on_loop_thread(check)
    assert outcome["ok"] is True


def test_assert_on_loop_fails_off_loop_thread(fake_loop):
    bridge = loop_mod.LoopBridge(idle_add=fake_loop.idle_add)
    fake_loop.run_on_loop_thread(bridge.mark_loop_thread)

    with pytest.raises(RuntimeError):
        bridge.assert_on_loop()


# ── RecoveryLog: "first success after failure" recovery WARNING ───────────
#
# Shared by the bluetooth daemon's retry loops (BlueZ adapter attach in
# bluetooth_service.py, loopback playback open in bluetooth_pump.py) so an
# operator reading WARN-level logs sees a failing condition clear, not just
# the failure stream that already logs at WARNING.

def test_recovery_log_silent_when_never_failed(caplog):
    log = loop_mod.RecoveryLog("thing")
    with caplog.at_level("WARNING", logger="root"):
        log.ok(100.0)
    assert caplog.records == []


def test_recovery_log_fail_then_ok_emits_one_warning(caplog):
    log = loop_mod.RecoveryLog("thing")
    log.fail(100.0)
    with caplog.at_level("WARNING", logger="root"):
        log.ok(104.0)
    assert len(caplog.records) == 1
    assert "thing recovered after 1 failure(s) (down for 4s)" in caplog.records[0].getMessage()


def test_recovery_log_counts_failures_since_first(caplog):
    log = loop_mod.RecoveryLog("thing")
    log.fail(100.0)
    log.fail(101.0)
    log.fail(102.0)
    with caplog.at_level("WARNING", logger="root"):
        log.ok(112.0)
    assert len(caplog.records) == 1
    msg = caplog.records[0].getMessage()
    assert "recovered after 3 failure(s) (down for 12s)" in msg


def test_recovery_log_resets_after_recovery(caplog):
    log = loop_mod.RecoveryLog("thing")
    log.fail(100.0)
    with caplog.at_level("WARNING", logger="root"):
        log.ok(101.0)
        log.ok(102.0)
        log.ok(103.0)
    assert len(caplog.records) == 1


def test_recovery_log_independent_incidents(caplog):
    log = loop_mod.RecoveryLog("thing")
    log.fail(100.0)
    with caplog.at_level("WARNING", logger="root"):
        log.ok(101.0)
    assert len(caplog.records) == 1
    caplog.clear()

    log.fail(200.0)
    with caplog.at_level("WARNING", logger="root"):
        log.ok(203.0)
    assert len(caplog.records) == 1
    assert "recovered after 1 failure(s) (down for 3s)" in caplog.records[0].getMessage()
