"""dial_repeat_store.py — an appliance's repeat/replay record, pure.

`RepeatRecord` is what the dial knows of one appliance's repeat daemon at a
moment: its state, whether it is armed, the recording held and the replay
position, stamped with the monotonic time it was observed. The core maps it
from the appliance's repeat part (dial_peer_view) through
`parse_repeat_object`; the screens read it from the snapshot and move the
replay position on locally between readings with the position helpers. No
I/O, no threads, no hardware, no display.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

from dataclasses import dataclass

REPEAT_STATES = frozenset({
    "idle", "recording", "hold", "replaying", "fading_out", "pending",
})

# The fixed inter-loop gap the appliance's replay engine inserts between
# the end of a buffer and its restart; used only to wrap a locally
# interpolated position between readings.
REPEAT_LOOP_GAP_S = 1.5

# How far the audio a listener hears trails the position the appliance
# reports, when the appliance does not say (older appliances send no
# latency_ms). The appliance normally supplies its audio start buffer.
DEFAULT_LATENCY_S = 2.0

# The widest latency_ms a record will accept; anything outside 0..this is
# treated as absent and the default applies.
MAX_LATENCY_S = 10.0


@dataclass(frozen=True)
class RepeatRecord:
    available:         bool
    state:              str
    armed:              bool
    recording_seconds:  float
    position_seconds:   float
    duration_seconds:   float
    observed_at:        float   # monotonic time of the status or ack that produced it
    # Seconds the heard audio trails position_seconds (the appliance's audio
    # start buffer). Defaulted so a record built without it keeps the
    # long-standing figure.
    latency_seconds:    float = DEFAULT_LATENCY_S


def interpolated_position(rec: RepeatRecord, now: float) -> float:
    """The appliance-reported position advanced by wall time since *rec*
    was observed, wrapped at the loop boundary (the buffer's duration plus
    the fixed inter-loop gap). Local only: the next reading corrects any
    drift. Never negative."""
    pos = rec.position_seconds + (now - rec.observed_at)
    dur = rec.duration_seconds
    if dur > 0:
        pos = pos % (dur + REPEAT_LOOP_GAP_S)
        pos = min(pos, dur)
    return max(0.0, pos)


def heard_position(rec: RepeatRecord, now: float) -> float:
    """The replay position the listener hears at *now*: the interpolated
    position less the record's latency. Deliberately not clamped, so it
    runs negative for the first moments after a (re)start or loop wrap,
    which lets a repaint deadline aim at the true moment the counter
    reaches a given second."""
    return interpolated_position(rec, now) - rec.latency_seconds


def _parse_latency_seconds(value) -> float:
    """latency_ms from the wire to seconds; the default for anything that is
    not a non-bool number within 0..MAX_LATENCY_S."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return DEFAULT_LATENCY_S
    seconds = value / 1000.0
    if not (0.0 <= seconds <= MAX_LATENCY_S):
        return DEFAULT_LATENCY_S
    return float(seconds)


def parse_repeat_object(obj, now: float) -> "RepeatRecord | None":
    """Strict parse of a repeat object, as dial_peer_view.repeat_record
    builds it from the appliance's repeat part. Any shape violation returns
    None, which callers treat as unavailable. `held` is not stored: it is
    `state == "hold"` by definition, so a reader never needs a second field
    to ask the same question.
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
        latency_seconds=_parse_latency_seconds(obj.get("latency_ms")),
    )


