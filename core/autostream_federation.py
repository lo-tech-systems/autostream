"""autostream_federation.py — in-memory federation session management.

Provides short-lived source-IP-bound bearer tokens for the target-side
federation API (/api/federation/v1/*).  All sessions are in-memory and
are invalidated on process restart.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import hmac
import secrets
import threading
import time
from collections import deque
from typing import Optional

EXPIRY_SECONDS: int = 600           # 10-minute session lifetime
FEDERATION_VERSION: int = 1

_TOKEN_BYTES: int = 20              # 160 bits → 40 hex chars
_RATE_LIMIT_MAX: int = 5            # successful issuances per window
_RATE_LIMIT_WINDOW: int = 60        # rolling window in seconds

_lock = threading.Lock()
_sessions: dict[str, tuple[str, float]] = {}   # token → (source_ip, expires_monotonic)
_rate: dict[str, deque] = {}                   # source_ip → deque of issuance timestamps


def create_session(source_ip: str) -> tuple[Optional[str], int]:
    """Issue a new bearer token for *source_ip*.

    Returns (token, expires_in) on success, or (None, retry_after_seconds) when
    the per-source rate limit is exceeded.  On success, *token* is never empty.
    A rejected request does not consume an issuance slot.
    """
    now = time.monotonic()
    with _lock:
        q = _rate.setdefault(source_ip, deque())
        while q and q[0] <= now - _RATE_LIMIT_WINDOW:
            q.popleft()
        if len(q) >= _RATE_LIMIT_MAX:
            retry_after = max(1, int(_RATE_LIMIT_WINDOW - (now - q[0])) + 1)
            return None, retry_after

        token = secrets.token_hex(_TOKEN_BYTES)
        expires = now + EXPIRY_SECONDS
        _sessions[token] = (source_ip, expires)
        q.append(now)
    return token, EXPIRY_SECONDS


def validate_session(token: str, source_ip: str) -> bool:
    """Return True iff *token* is valid, unexpired, and bound to *source_ip*.

    Uses constant-time comparison to avoid timing side-channels.
    """
    if not token:
        return False
    now = time.monotonic()
    with _lock:
        entry = _sessions.get(token)
    if entry is None:
        hmac.compare_digest(token, token)   # keep timing uniform
        return False
    bound_ip, expires = entry
    return hmac.compare_digest(bound_ip, source_ip) and now <= expires


def sweep_sessions() -> None:
    """Remove expired sessions and inactive rate-limit queues.

    Should be called once per minute (e.g. from the existing minute sweep).
    """
    now = time.monotonic()
    with _lock:
        expired = [t for t, (_, exp) in _sessions.items() if exp <= now]
        for t in expired:
            del _sessions[t]
        inactive = [
            ip for ip, q in _rate.items()
            if not q or q[-1] <= now - _RATE_LIMIT_WINDOW
        ]
        for ip in inactive:
            del _rate[ip]


def evict_session_for_ip(source_ip: str) -> None:
    """Immediately evict all sessions bound to *source_ip*.

    Called when a peer's final sighting is removed from the discovery registry.
    Must not be called while holding the registry lock.
    """
    with _lock:
        to_remove = [t for t, (ip, _) in _sessions.items() if ip == source_ip]
        for t in to_remove:
            del _sessions[t]
