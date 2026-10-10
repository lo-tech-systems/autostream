"""dial_auth.py — pure per-appliance authorization knowledge.

Owns one thing: what this dial currently believes about whether it is
authorized to control each appliance it has ever seen, keyed by
appliance_id. It never performs I/O and never decides what to do with that
knowledge — it is written to by whoever learns something (a sighting, a
status poll result) and read by whoever needs to gate on it (the volume and
mute resolvers, the display's list and focus logic). No imports from the
display, touch or HTTP modules; `threading` is used only for the leaf lock
below.

Lock discipline: `AuthMap._lock` is a leaf lock. It is held only for the
duration of a single dict read or write, is never held across I/O, and is
never nested with any other lock in this codebase.

States, per appliance_id:
  unknown       initial state; also the degrade-to state on any failure to
                read this map, so a display, poll or HTTP problem never
                blocks volume/mute control (which only excludes
                "unauthorized").
  authorized    a 200 status response whose body's appliance_id matched.
  unauthorized  a 412 dial_not_authorized response whose body's
                appliance_id matched. Re-probed on a backoff that doubles
                from 30 s to a 600 s ceiling, reset to "due now" by a wake,
                a push, or the selector being opened.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass

AUTH_UNKNOWN = "unknown"
AUTH_AUTHORIZED = "authorized"
AUTH_UNAUTHORIZED = "unauthorized"

OUTCOME_AUTHORIZED = "authorized"      # 200 with valid, matching body
OUTCOME_UNAUTHORIZED = "unauthorized"  # 412 dial_not_authorized, matching body
OUTCOME_TRANSIENT = "transient"        # everything else: never moves state

REPROBE_BACKOFF_INITIAL_S = 30.0
REPROBE_BACKOFF_MAX_S = 600.0
ENTRY_RETENTION_S = 24 * 3600
MAX_ENTRIES = 64


@dataclass
class AuthEntry:
    state: str = AUTH_UNKNOWN
    ip: str = ""
    port: int = 0
    last_confirmed: float | None = None   # monotonic of the last 200/412 that applied
    last_seen: float = 0.0                # monotonic of the last sighting
    next_probe_at: float = 0.0            # unauthorized only; 0 means "due now"
    backoff_s: float = 0.0


class AuthMap:
    """Thread-safe map of appliance_id -> AuthEntry. One module singleton."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, AuthEntry] = {}
        self._refusal_reported: set[str] = set()

    def note_sighting(self, appliance_id: str, ip: str, port: int, now: float) -> None:
        """Record that appliance_id is currently sighted at (ip, port).

        Creates the entry as unknown if absent. An (ip, port) change on an
        existing entry resets state to unknown (a fresh address is a fresh
        appliance until re-confirmed) but keeps last_confirmed as history.
        Empty appliance_id is ignored: an identity-less appliance is never
        entered into the map.
        """
        if not appliance_id:
            return
        with self._lock:
            entry = self._entries.get(appliance_id)
            if entry is None:
                entry = AuthEntry(ip=ip, port=port, last_seen=now)
                self._entries[appliance_id] = entry
                return
            if entry.ip != ip or entry.port != port:
                entry.state = AUTH_UNKNOWN
                entry.next_probe_at = 0.0
                entry.backoff_s = 0.0
            entry.ip = ip
            entry.port = port
            entry.last_seen = now

    def state(self, appliance_id: str) -> str:
        """Current auth state for appliance_id. Never raises."""
        if not appliance_id:
            return AUTH_UNKNOWN
        with self._lock:
            entry = self._entries.get(appliance_id)
            return entry.state if entry is not None else AUTH_UNKNOWN

    def states(self) -> dict[str, str]:
        """Snapshot of every known appliance_id's state."""
        with self._lock:
            return {aid: entry.state for aid, entry in self._entries.items()}

    def apply(
        self,
        appliance_id: str,
        outcome: str,
        body_appliance_id: str | None,
        now: float,
    ) -> bool:
        """Apply a status-poll outcome. Returns True when the state changed.

        The correlation guard: a body_appliance_id that does not equal
        appliance_id (including a missing/None body id) never moves state —
        this closes the stale-IP window where a status reply arrives for a
        (ip, port) that has since been reassigned to a different appliance.
        """
        if not appliance_id:
            return False
        if body_appliance_id != appliance_id:
            return False
        if outcome == OUTCOME_TRANSIENT:
            return False
        with self._lock:
            entry = self._entries.get(appliance_id)
            if entry is None:
                entry = AuthEntry()
                self._entries[appliance_id] = entry
            # A correlated status reply (body id == appliance id) is itself
            # proof the appliance exists on the network — at least as strong
            # as an mDNS sighting — so stamp last_seen here too. Otherwise an
            # entry that is only ever created by apply() (a push-probe that
            # lands before its sighting) carries last_seen=0.0 and is dropped
            # by the very next prune(), losing the confirmed state.
            entry.last_seen = now
            if outcome == OUTCOME_AUTHORIZED:
                changed = entry.state != AUTH_AUTHORIZED
                entry.state = AUTH_AUTHORIZED
                self._refusal_reported.discard(appliance_id)
                entry.last_confirmed = now
                entry.backoff_s = 0.0
                entry.next_probe_at = 0.0
                return changed
            if outcome == OUTCOME_UNAUTHORIZED:
                changed = entry.state != AUTH_UNAUTHORIZED
                entry.state = AUTH_UNAUTHORIZED
                entry.last_confirmed = now
                entry.backoff_s = (
                    REPROBE_BACKOFF_INITIAL_S if entry.backoff_s == 0.0
                    else min(entry.backoff_s * 2, REPROBE_BACKOFF_MAX_S)
                )
                entry.next_probe_at = now + entry.backoff_s
                return changed
            return False

    def record_refusal(self, appliance_id: str) -> bool:
        """True the first time appliance_id's refusal is reported, and again
        only after it has been authorised in between. Lets a caller log a
        refusal once instead of on every re-probe."""
        if not appliance_id:
            return False
        with self._lock:
            if appliance_id in self._refusal_reported:
                return False
            self._refusal_reported.add(appliance_id)
            return True

    def due_for_probe(self, appliance_id: str, now: float) -> bool:
        """True when appliance_id should be probed now.

        Absent, unknown or authorized rows are always due (authorized rows
        are cheaply re-confirmed on every reconcile — it is how a revoke
        without a push arrives). Unauthorized rows are due only once their
        backoff has elapsed.
        """
        if not appliance_id:
            return True
        with self._lock:
            entry = self._entries.get(appliance_id)
            if entry is None or entry.state != AUTH_UNAUTHORIZED:
                return True
            return now >= entry.next_probe_at

    def force_due(self, appliance_id: str | None = None) -> None:
        """Make appliance_id (or every entry, when None) due for probe now."""
        with self._lock:
            if appliance_id is None:
                for entry in self._entries.values():
                    entry.next_probe_at = 0.0
                return
            entry = self._entries.get(appliance_id)
            if entry is not None:
                entry.next_probe_at = 0.0

    def prune(self, now: float) -> None:
        """Drop entries unseen for ENTRY_RETENTION_S, then trim to
        MAX_ENTRIES by oldest last_seen. Called once per reconcile pass."""
        with self._lock:
            for aid in [
                aid for aid, entry in self._entries.items()
                if now - entry.last_seen > ENTRY_RETENTION_S
            ]:
                del self._entries[aid]
            if len(self._entries) > MAX_ENTRIES:
                overflow = len(self._entries) - MAX_ENTRIES
                oldest = sorted(self._entries.items(), key=lambda kv: kv[1].last_seen)
                for aid, _entry in oldest[:overflow]:
                    del self._entries[aid]

    def reset(self) -> None:
        """Clear all entries. Tests only."""
        with self._lock:
            self._entries.clear()
            self._refusal_reported.clear()


auth_map = AuthMap()   # module singleton, mirrors dial_volume's module state
