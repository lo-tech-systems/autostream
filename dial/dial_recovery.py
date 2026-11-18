"""dial_recovery.py -- the PIN recovery window.

When the dial starts with a PIN set, a 10-minute window opens in which the
PIN can be replaced from the appliance, provided a person confirms at the
dial (by turning the volume knob or touching the screen).  The window is
announced over mDNS while it is open, so the appliance can offer the reset.

Three threads touch it: startup opens it, a timer closes it, and the
management handlers read it and complete it.  Its own lock guards its state;
the announce callback always runs outside that lock.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Callable


class RecoveryWindow:
    """10-minute PIN recovery window opened at startup when a PIN is set.

    State machine:
      open()          → _active=True,  _volume_confirmed=False, starts timer
      confirm_volume()→ _volume_confirmed=True (only while active)
      _expire()       → timer fires: _active=False, announce without pin_recovery
      complete()      → PIN replaced: cancel timer, _active=False, announce
    """

    _WINDOW_S = 600

    def __init__(self, on_announce: Callable[[bool], None]) -> None:
        self._on_announce      = on_announce
        self._lock             = threading.Lock()
        self._active           = False
        self._volume_confirmed = False
        self._opened_monotonic: float | None = None
        self._timer: threading.Timer | None = None

    def open(self) -> None:
        with self._lock:
            self._volume_confirmed = False
            self._active = True
            self._opened_monotonic = time.monotonic()
            timer = threading.Timer(self._WINDOW_S, self._expire)
            timer.daemon = True
            self._timer = timer
        timer.start()
        self._on_announce(True)   # outside lock — slow subprocess
        logging.info("PIN recovery window opened (10 min)")

    def _expire(self) -> None:
        with self._lock:
            self._active = False
        self._on_announce(False)  # outside lock
        logging.info("PIN recovery window expired")

    def complete(self) -> None:
        with self._lock:
            timer = self._timer
            self._timer = None
            self._active = False
        if timer:
            timer.cancel()
        self._on_announce(False)  # outside lock
        logging.info("PIN recovery: PIN updated")

    def confirm_volume(self) -> None:
        with self._lock:
            if not (self._active and not self._volume_confirmed):
                return
            self._volume_confirmed = True
        logging.info("PIN recovery: volume confirmed")

    def snapshot(self) -> dict:
        """Return a thread-safe copy of current recovery window state,
        including recovery_remaining_ms — milliseconds left in the 10-minute
        window, clamped at 0 (0 whenever the window is not active)."""
        with self._lock:
            remaining_ms = 0
            if self._active and self._opened_monotonic is not None:
                elapsed_ms = int((time.monotonic() - self._opened_monotonic) * 1000)
                remaining_ms = max(0, self._WINDOW_S * 1000 - elapsed_ms)
            return {
                "active": self._active,
                "volume_confirmed": self._volume_confirmed,
                "recovery_remaining_ms": remaining_ms,
            }
