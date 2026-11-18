"""autostream_state.spread -- a volume change made at one speaker, applied
to the other playing speakers. Pure: no locks, no clock, no player calls.
The output authority calls it under its lock."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

# A burst ends after this long with no spread from its reporter.
SPREAD_QUIET_S = 2.0
# After autostream writes a unit, or it starts playing, it is not a reporter
# for this long (outputs.DEBOUNCE_S + outputs.DEVICE_VOLUME_MARK_S).
SPREAD_HOLD_S = 4.0
# An armed report must be compared within this long
# (SPREAD_HOLD_S + outputs.WRITE_TIMEOUT_S).
SPREAD_REPORT_S = 7.0


def _clamp(value) -> int:
    return max(0, min(100, int(value)))


def spread_levels(base: Mapping[str, int], reporter_old: int, reporter_new: int) -> dict[str, int]:
    """Each target's level after the reporter moved from reporter_old to
    reporter_new, from the levels in base. Keeps base's order.

    From a reporter above zero every target is scaled by new/old, so all
    reach zero together. From zero there is no ratio: the change is applied
    as a master step, the reporter's new level added to the targets' mean."""
    if not base:
        return {}
    if reporter_old > 0:
        return {uid: _clamp(round(level * reporter_new / reporter_old)) for uid, level in base.items()}
    current = round(sum(base.values()) / len(base))
    level = _clamp(current + reporter_new)
    if current == 0:
        return {uid: level for uid in base}
    return {uid: _clamp(round(value * level / current)) for uid, value in base.items()}


@dataclass
class Burst:
    """Consecutive reports from one reporter with no gap of SPREAD_QUIET_S.
    It holds the snapshot every spread in it scales from."""
    reporter: str
    reporter_old: int
    base: dict[str, int]                 # target id -> level at the start, row order
    seqs: dict[str, int]                 # target id -> desired_seq after the last spread
    last_at: float
    reporter_new: int = 0
    after: dict[str, int] = field(default_factory=dict)   # target id -> level after the last spread

    def expired(self, now: float) -> bool:
        return now - self.last_at >= SPREAD_QUIET_S

    def note_spread(self, now: float, reporter_new: int,
                    seen: Mapping[str, tuple[int, int]]) -> None:
        """seen: target id -> (desired_seq, level) after this spread."""
        self.last_at = now
        self.reporter_new = reporter_new
        for uid, (seq, level) in seen.items():
            self.seqs[uid] = seq
            self.after[uid] = level

    def moved(self) -> list[str]:
        """Ids in base order whose level after the last spread differs from base."""
        return [uid for uid, level in self.base.items() if self.after.get(uid, level) != level]
