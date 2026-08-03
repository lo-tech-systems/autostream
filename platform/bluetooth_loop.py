#!/usr/bin/python3
"""bluetooth_loop.py

Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.

The single thread-crossing point between the GLib main loop thread (the only
thread allowed to touch dbus-python) and everything else (the control-socket
thread, callers running in tests). ``LoopBridge`` marshals a callable onto
the loop via ``GLib.idle_add`` and either returns immediately
(``call_soon``) or blocks the calling thread until it has run
(``call_sync``).

``idle_add`` is accepted as a constructor argument (defaulting to
``GLib.idle_add``, imported lazily so this module stays importable without
PyGObject installed) so tests can supply a fake scheduler and exercise the
bridge without a real main loop running anywhere.
"""
from __future__ import annotations

import logging
import threading
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

DEFAULT_CALL_TIMEOUT = 5.0


class RecoveryLog:
    """Emits one WARNING when a failing condition clears, so an operator
    reading WARN-level logs sees the recovery, not just the failure stream.

    Shared by the bluetooth daemon's retry loops (BlueZ adapter attach,
    loopback playback open, ...) -- lives here rather than in each retry
    site's own module since every bluetooth daemon module already imports
    this one, and the daemon must not import from core/.
    """

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
            logger.warning(
                "%s recovered after %d failure(s) (down for %.0fs)",
                self._subject, self._count, now - self._first_failure_at)
        self._failing = False
        self._count = 0


class LoopCallTimeout(Exception):
    """Raised by ``call_sync`` when the loop does not run the scheduled
    call within the timeout -- most commonly a wedged/stalled loop."""


class LoopBridge:
    """Marshals calls onto the GLib loop thread.

    The loop thread identity is not known at construction time (the loop
    hasn't started yet); call ``mark_loop_thread()`` once, from inside the
    loop, as the first thing it does. Before that call, ``assert_on_loop()``
    is a no-op -- this keeps unit tests that never start a real loop free to
    call it without special-casing.
    """

    def __init__(self, idle_add: Optional[Callable[..., Any]] = None) -> None:
        # GLib is imported lazily, on first actual use (not here), so
        # constructing a bridge stays safe on systems without PyGObject
        # (dev machines, the WSL test runner) -- matching every other lazy
        # GLib/dbus import point in this codebase.
        self._idle_add = idle_add
        self._loop_thread_id: Optional[int] = None

    def _get_idle_add(self) -> Callable[..., Any]:
        if self._idle_add is None:
            from gi.repository import GLib
            self._idle_add = GLib.idle_add
        return self._idle_add

    def mark_loop_thread(self) -> None:
        """Record the calling thread as the loop thread. Call this once,
        from inside the loop (e.g. the first line of the timeout/idle
        callback that starts everything else, or just before ``loop.run()``
        on the same thread)."""
        self._loop_thread_id = threading.get_ident()

    def assert_on_loop(self) -> None:
        """Raise if the current thread is not the marked loop thread. A
        no-op if the loop thread has not been marked yet (see class
        docstring)."""
        if self._loop_thread_id is None:
            return
        if threading.get_ident() != self._loop_thread_id:
            raise RuntimeError("bluetooth_loop: expected to be called on the loop thread")

    def call_soon(self, fn: Callable[..., Any], *args: Any) -> None:
        """Schedule ``fn(*args)`` to run on the loop thread and return
        immediately. The return value is discarded; an exception raised by
        ``fn`` is logged and swallowed -- it must never propagate back into
        GLib's dispatch loop, which would abort the process."""

        def _run() -> bool:
            try:
                fn(*args)
            except Exception:
                logger.exception("bluetooth_loop: unhandled error in call_soon callback")
            return False  # one-shot: do not re-arm

        self._get_idle_add()(_run)

    def call_sync(
        self, fn: Callable[..., Any], *args: Any, timeout: float = DEFAULT_CALL_TIMEOUT,
    ) -> Any:
        """Schedule ``fn(*args)`` on the loop thread and block the calling
        thread until it has run, returning its result (or re-raising its
        exception here, in the caller's thread).

        Calling this from the loop thread itself would deadlock -- the loop
        can never service the idle callback while it is blocked waiting for
        it -- so that case raises ``RuntimeError`` immediately instead of
        hanging. A loop that does not get around to running the callback
        within ``timeout`` raises ``LoopCallTimeout``.
        """
        if self._loop_thread_id is not None and threading.get_ident() == self._loop_thread_id:
            raise RuntimeError("bluetooth_loop: call_sync invoked from the loop thread would deadlock")

        done = threading.Event()
        result: list = []
        error: list = []

        def _run() -> bool:
            try:
                result.append(fn(*args))
            except Exception as e:
                error.append(e)
            finally:
                done.set()
            return False  # one-shot

        self._get_idle_add()(_run)
        if not done.wait(timeout=timeout):
            raise LoopCallTimeout(f"bluetooth_loop: call_sync timed out after {timeout}s")
        if error:
            raise error[0]
        return result[0]
