"""dial_pin_guard.py: the PIN rate limiter for the dial's two servers.

The management API and the HD page's LAN login share one per-IP failure count
with exponential back-off, so a guess costs the same on either. The PIN is
stored in plaintext in the 0600 settings file, which is adequate for a home
LAN appliance; the limiter stops casual brute force from a browser.

State is module-level.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import threading
import time

MAX_ATTEMPTS = 5
BACKOFF_BASE_S = 5
BACKOFF_MAX_S = 300

_attempts: dict[str, tuple[int, float]] = {}
_lock = threading.Lock()


def blocked(ip: str) -> tuple[bool, int]:
    """(True, seconds to wait) while *ip* is backed off, else (False, 0)."""
    with _lock:
        fails, blocked_until = _attempts.get(ip, (0, 0.0))
        if blocked_until and blocked_until > time.time():
            return True, int(blocked_until - time.time()) + 1
        return False, 0


def record_failure(ip: str) -> None:
    """Count a wrong PIN from *ip*; from the fifth on, back it off."""
    with _lock:
        fails, _ = _attempts.get(ip, (0, 0.0))
        fails += 1
        blocked_until = 0.0
        if fails >= MAX_ATTEMPTS:
            exp = min(fails - MAX_ATTEMPTS, 6)
            delay = min(BACKOFF_BASE_S * (2 ** exp), BACKOFF_MAX_S)
            blocked_until = time.time() + delay
        _attempts[ip] = (fails, blocked_until)


def clear(ip: str) -> None:
    """Forget *ip*'s failures after a right PIN."""
    with _lock:
        _attempts.pop(ip, None)


def reset_for_tests() -> None:
    """Forget every address."""
    with _lock:
        _attempts.clear()
