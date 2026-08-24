#!/usr/bin/env python3
"""autostream_debounce.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Shared debounce primitive.

Two independent ad hoc ``threading.Timer`` instances existed in
``autostream_webui_api.py`` (``_debounce_coordinator_reload``,
``_debounce_track_id_rebuild``), each with its own lock and timer-handle
global, for the same underlying need -- "collapse repeated calls arriving
within a short window into one trailing call." This module is the *one*
shared implementation of that need, so a future third debounced field
registers a key against this, rather than inventing a fourth ad hoc
``threading.Timer`` trio.

Only ``_debounce_track_id_rebuild`` migrates onto this -- it is the one
genuine debounce-of-a-live-push case. Migrating
``_debounce_coordinator_reload`` is deliberately deferred: the reload flag
is already an idempotent ``threading.Event``, so that timer may be
deletable outright rather than migrated -- a decision left for whoever
next touches the coordinator's reload path, not made here.
"""
from __future__ import annotations

import threading
from typing import Callable, Dict, Optional


class Debouncer:
    """Coalesces repeated ``trigger(key, delay, callback)`` calls under the
    same *key*: a call arriving before the previous one's *delay* has
    elapsed cancels the pending timer and reschedules with the new
    *callback* -- only the last callback registered inside the window runs,
    exactly once, *delay* seconds after the last ``trigger`` call for that
    key.

    One instance may be shared by any number of independently-keyed
    debounced operations across the process -- see ``default_debouncer()``.
    Each key's pending timer is tracked separately, so debouncing one key
    never affects another's schedule.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._timers: Dict[str, threading.Timer] = {}

    def trigger(self, key: str, delay: float, callback: Callable[[], None]) -> None:
        """Schedule *callback* to run after *delay* seconds, cancelling any
        call already pending under *key*."""
        with self._lock:
            existing = self._timers.get(key)
            if existing is not None:
                existing.cancel()

            def _run() -> None:
                with self._lock:
                    # Only clear this key's own entry -- a newer trigger()
                    # call may already have replaced it by the time we get
                    # the lock (the cancel() above races the timer thread
                    # for exactly this reason, and loses gracefully).
                    if self._timers.get(key) is timer:
                        del self._timers[key]
                callback()

            timer = threading.Timer(delay, _run)
            timer.daemon = True
            self._timers[key] = timer
            timer.start()

    def cancel(self, key: str) -> None:
        """Cancel any call pending under *key*, if one exists. No-op otherwise."""
        with self._lock:
            timer = self._timers.pop(key, None)
        if timer is not None:
            timer.cancel()

    def pending(self, key: str) -> bool:
        """True if a call is currently scheduled under *key* (test/introspection hook)."""
        with self._lock:
            return key in self._timers


_default_debouncer: Optional[Debouncer] = None
_default_debouncer_lock = threading.Lock()


def default_debouncer() -> Debouncer:
    """Process-wide shared ``Debouncer`` instance.

    Lazily constructed so importing this module never spins up a thread or
    any other resource at import time.
    """
    global _default_debouncer
    if _default_debouncer is None:
        with _default_debouncer_lock:
            if _default_debouncer is None:
                _default_debouncer = Debouncer()
    return _default_debouncer
