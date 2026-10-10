"""dial_repeat_store.py — per-appliance repeat/replay state, pure.

Owns one thing: what this dial currently believes about each rostered
appliance's repeat/replay state, keyed by appliance_id. It never performs
I/O and never decides what to do with that knowledge — it is written to by
whoever learns something (a status poll's repeat object, a transport/arm
ack) and read by whoever needs to draw it (the N2 repeat screen, the N4 idle
affordance, the N5 replay picker). No imports beyond `threading` and
`dataclasses` — no hardware, no HTTP, no display.

Lock discipline: `RepeatStore._lock` is a leaf lock. It is held only for the
duration of a single dict read or write, is never held across I/O, and is
never nested with any other lock in this codebase.

Freshness: a record older than RECORD_MAX_AGE_S (three reconcile intervals)
reads as absent — a stale belief must never be shown as though it were
current. `prune()` additionally drops records for ids no longer in the
current roster, called once per reconcile pass so a fully-departed
appliance's record does not linger forever.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, replace

REPEAT_STATES = frozenset({
    "idle", "recording", "hold", "replaying", "fading_out", "pending",
})

# Three reconcile intervals (dial_display.RECONCILE_INTERVAL_SECONDS is 60s;
# this module does not import it, to stay dependency-free — the multiple is
# restated here as a plain constant).
RECORD_MAX_AGE_S = 180.0


@dataclass(frozen=True)
class RepeatRecord:
    available:         bool
    state:              str
    armed:              bool
    recording_seconds:  float
    position_seconds:   float
    duration_seconds:   float
    observed_at:        float   # monotonic time of the status or ack that produced it


def parse_repeat_object(obj, now: float) -> "RepeatRecord | None":
    """Strict parse of the protocol's `repeat` object (autostream_webui_api.
    _dial_repeat_object()). Any shape violation returns None — treated by
    callers as unavailable, never as a reason to fail the whole status
    fetch. `held` is not stored: it is `state == "hold"` by definition, so a
    reader never needs a second field to ask the same question.
    """
    if not isinstance(obj, dict):
        return None

    available = obj.get("available")
    if not isinstance(available, bool):
        return None

    state = obj.get("state")
    if not isinstance(state, str) or state not in REPEAT_STATES:
        return None

    armed = obj.get("armed")
    if not isinstance(armed, bool):
        return None

    recording_seconds = obj.get("recording_seconds")
    if isinstance(recording_seconds, bool) or not isinstance(recording_seconds, (int, float)):
        return None

    replay = obj.get("replay")
    if not isinstance(replay, dict):
        return None

    active = replay.get("active")
    if not isinstance(active, bool):
        return None

    position_seconds = replay.get("position_seconds")
    if isinstance(position_seconds, bool) or not isinstance(position_seconds, (int, float)):
        return None

    duration_seconds = replay.get("duration_seconds")
    if isinstance(duration_seconds, bool) or not isinstance(duration_seconds, (int, float)):
        return None

    return RepeatRecord(
        available=available,
        state=state,
        armed=armed,
        recording_seconds=float(recording_seconds),
        position_seconds=float(position_seconds),
        duration_seconds=float(duration_seconds),
        observed_at=now,
    )


class RepeatStore:
    """Thread-safe map of appliance_id -> RepeatRecord. One module singleton."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, RepeatRecord] = {}

    def update(self, appliance_id: str, record: "RepeatRecord | None") -> bool:
        """Set (record is not None) or clear (record is None) appliance_id's
        entry. Returns True when the stored value actually changed. A
        no-op (returns False) for an empty appliance_id — an identity-less
        row is never stored, the same discipline dial_auth.note_sighting
        uses."""
        if not appliance_id:
            return False
        with self._lock:
            prev = self._records.get(appliance_id)
            if record is None:
                if prev is None:
                    return False
                del self._records[appliance_id]
                return True
            if prev == record:
                return False
            self._records[appliance_id] = record
            return True

    def clear(self, appliance_id: str) -> None:
        """Drop appliance_id's entry, if any. Used when a confirmed 412
        revokes this dial's authorization for it — any cached repeat state
        is no longer this dial's to show."""
        if not appliance_id:
            return
        with self._lock:
            self._records.pop(appliance_id, None)

    def get(self, appliance_id: str, now: float) -> "RepeatRecord | None":
        """The current record for appliance_id, or None when absent or
        older than RECORD_MAX_AGE_S."""
        if not appliance_id:
            return None
        with self._lock:
            record = self._records.get(appliance_id)
        if record is None:
            return None
        if now - record.observed_at > RECORD_MAX_AGE_S:
            return None
        return record

    def apply_ack(self, appliance_id: str, ack: dict, now: float) -> None:
        """Optimistic update from an ok:true transport/arm ack: replaces
        state/armed/position_seconds and keeps the existing
        recording_seconds/duration_seconds (the ack does not carry them).
        A no-op when no record exists yet, when appliance_id is empty, or
        when the ack's shape is not one this store trusts — there is
        nothing to optimistically refine, and the next poll corrects the
        record either way."""
        if not appliance_id or not isinstance(ack, dict):
            return
        state = ack.get("state")
        armed = ack.get("armed")
        position_seconds = ack.get("position_seconds")
        if not isinstance(state, str) or state not in REPEAT_STATES:
            return
        if not isinstance(armed, bool):
            return
        if isinstance(position_seconds, bool) or not isinstance(position_seconds, (int, float)):
            return
        with self._lock:
            prev = self._records.get(appliance_id)
            if prev is None:
                return
            self._records[appliance_id] = replace(
                prev, state=state, armed=armed,
                position_seconds=float(position_seconds), observed_at=now,
            )

    def held_ids(self, now: float) -> frozenset[str]:
        """appliance_ids currently believed to be in Hold, fresh only."""
        with self._lock:
            items = list(self._records.items())
        return frozenset(
            aid for aid, record in items
            if record.state == "hold" and now - record.observed_at <= RECORD_MAX_AGE_S
        )

    def prune(self, keep: set[str]) -> None:
        """Drop every record whose appliance_id is not in *keep* — called
        once per reconcile pass with the current roster's ids, so an
        appliance that has left the roster entirely does not linger here
        forever."""
        with self._lock:
            for aid in [aid for aid in self._records if aid not in keep]:
                del self._records[aid]


repeat_store = RepeatStore()   # module singleton, mirrors dial_auth's auth_map
