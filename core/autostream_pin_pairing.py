#!/usr/bin/env python3
"""autostream_pin_pairing.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Appliance-side record of who is pairing a speaker, and the limit on PIN
attempts. Process memory only: nothing is persisted and nothing here does I/O.

A speaker that asks for a PIN shows it on its own screen, so only one viewer
should prompt for it at a time. ``claim`` records the requester that triggered
the prompt (with the time); other viewers see the holder in the output list
and stand down until the claim ends (a good PIN, or CLAIM_S passing).

``note_attempt`` limits PIN submissions per (requester, output). It checks and
answers only: it never sleeps or waits, and a refusal says how many seconds
the caller should wait. Any internal fault answers "allowed" -- the limiter
must never be the reason a pairing cannot proceed.

Thread safety: ``_lock`` is a leaf lock held only over plain dictionary work.
The clock is read before the lock is taken and nothing inside the lock calls
out, so it can be called from any thread while any other lock is held.
"""
from __future__ import annotations

import logging
import math
import re
import threading
import time
from collections import deque
from typing import Callable, Optional

# \Z, not $: "$" would also accept a trailing newline.
PIN_RE = re.compile(r"^[0-9]{4,8}\Z")

PIN_CLAIM_S = 90.0
PIN_ATTEMPTS_MAX = 5
PIN_ATTEMPTS_WINDOW_S = 60.0
PIN_CLAIMS_MAX = 64   # outputs with a claim at once; oldest evicted
PIN_KEYS_MAX = 256    # (requester, output) attempt keys at once; oldest evicted

REQUESTER_WEBUI = "webui"


def dial_requester(dial_id: str) -> str:
    """The requester identity for a dial, from its authenticated id."""
    return "dial:" + str(dial_id)


class PairingState:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._claims: dict[str, tuple[str, float]] = {}
        self._attempts: dict[tuple[str, str], deque] = {}
        self._failed_once = False

    def _note_failure(self) -> None:
        if not self._failed_once:
            self._failed_once = True
            logging.debug("pin pairing: internal fault; failing open", exc_info=True)

    def claim(self, output_id: str, requester: str, now: Optional[float] = None) -> str:
        """Record *requester* as the holder for *output_id* unless a live claim
        by someone else exists; renews the holder's own claim. Returns the holder."""
        try:
            if now is None:
                now = self._clock()
            with self._lock:
                return self._claim_locked(output_id, requester, now)
        except Exception:
            self._note_failure()
            return requester

    def _claim_locked(self, output_id: str, requester: str, now: float) -> str:
        entry = self._claims.get(output_id)
        if entry is not None and (now - entry[1]) < PIN_CLAIM_S and entry[0] != requester:
            return entry[0]
        self._claims[output_id] = (requester, now)
        while len(self._claims) > PIN_CLAIMS_MAX:
            oldest = min(self._claims, key=lambda k: self._claims[k][1])
            del self._claims[oldest]
        return requester

    def release(self, output_id: str) -> None:
        try:
            with self._lock:
                self._claims.pop(output_id, None)
        except Exception:
            self._note_failure()

    def holder(self, output_id: str, now: Optional[float] = None) -> str:
        """The live holder or "" (an expired claim reads as none and is dropped)."""
        try:
            if now is None:
                now = self._clock()
            with self._lock:
                entry = self._claims.get(output_id)
                if entry is None:
                    return ""
                if (now - entry[1]) >= PIN_CLAIM_S:
                    del self._claims[output_id]
                    return ""
                return entry[0]
        except Exception:
            self._note_failure()
            return ""

    def note_attempt(
        self, requester: str, output_id: str, now: Optional[float] = None,
    ) -> tuple[bool, int]:
        """(allowed, retry_after_s). Check and answer only: under the limit the
        attempt is counted and (True, 0) returned; at the limit nothing is
        counted and (False, n) says how many whole seconds until the oldest
        attempt in the window leaves it (at least 1). Renews the requester's own
        claim. Any failure inside answers (True, 0) and logs once at debug."""
        try:
            if now is None:
                now = self._clock()
            with self._lock:
                allowed, wait = self._attempt_locked(requester, output_id, now)
                if allowed:
                    entry = self._claims.get(output_id)
                    if entry is not None and entry[0] == requester:
                        self._claims[output_id] = (requester, now)
                return allowed, wait
        except Exception:
            self._note_failure()
            return True, 0

    def _attempt_locked(self, requester: str, output_id: str, now: float) -> tuple[bool, int]:
        key = (requester, output_id)
        times = self._attempts.get(key)
        if times is not None:
            while times and (now - times[0]) >= PIN_ATTEMPTS_WINDOW_S:
                times.popleft()
            if not times:
                del self._attempts[key]
                times = None
        if times is not None and len(times) >= PIN_ATTEMPTS_MAX:
            wait = max(1, math.ceil(PIN_ATTEMPTS_WINDOW_S - (now - times[0])))
            return False, wait
        if times is None:
            times = deque(maxlen=PIN_ATTEMPTS_MAX)
            self._attempts[key] = times
        times.append(now)
        while len(self._attempts) > PIN_KEYS_MAX:
            oldest = min(self._attempts, key=lambda k: self._attempts[k][-1])
            del self._attempts[oldest]
        return True, 0

    def reset(self) -> None:
        with self._lock:
            self._claims.clear()
            self._attempts.clear()
            self._failed_once = False


STATE = PairingState()


def claim(output_id: str, requester: str, now: Optional[float] = None) -> str:
    return STATE.claim(output_id, requester, now)


def release(output_id: str) -> None:
    STATE.release(output_id)


def holder(output_id: str, now: Optional[float] = None) -> str:
    return STATE.holder(output_id, now)


def note_attempt(requester: str, output_id: str, now: Optional[float] = None) -> tuple[bool, int]:
    return STATE.note_attempt(requester, output_id, now)
