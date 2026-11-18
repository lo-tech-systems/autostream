"""dial_pin_guard.py: the PIN rule for the dial's two servers.

The management API and the HD page's LAN login share one per-IP failure count
with exponential back-off, so a guess costs the same on either, and one
constant-time compare. The PIN is stored in plaintext in the 0600 settings
file, which is adequate for a home LAN appliance; the limiter stops casual
brute force from a browser.

State is module-level.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import hmac
import threading
import time
from typing import NamedTuple

MAX_ATTEMPTS = 5
BACKOFF_BASE_S = 5
BACKOFF_MAX_S = 300
# The longest PIN worth comparing; a longer one cannot be right.
PIN_MAX_LENGTH = 64

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


def pin_matches(supplied, expected) -> bool:
    """True when *supplied* is the PIN *expected*, compared in constant time.
    Anything that is not a string, or is over PIN_MAX_LENGTH, never matches."""
    return (
        isinstance(supplied, str) and isinstance(expected, str)
        and len(supplied) <= PIN_MAX_LENGTH
        and hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))
    )


class Verdict(NamedTuple):
    ok: bool
    wait_s: int     # above 0: refuse with a 429 and this Retry-After


def authorise(ip: str, supplied, expected: str) -> Verdict:
    """Check *supplied* against *expected* for a request from *ip*.

    A backed-off client is refused without being checked. A wrong PIN is
    counted, and refused with a wait when that failure backs the client off.
    A right PIN forgets the client's failures."""
    is_blocked, wait = blocked(ip)
    if is_blocked:
        return Verdict(False, wait)
    if not pin_matches(supplied, expected):
        record_failure(ip)
        is_blocked, wait = blocked(ip)
        return Verdict(False, wait if is_blocked else 0)
    clear(ip)
    return Verdict(True, 0)


def reset_for_tests() -> None:
    """Forget every address."""
    with _lock:
        _attempts.clear()
