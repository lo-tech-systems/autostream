"""dial_display_repeat_line.py: the replaying counter and the replay timer line.

Two lines show a replay's position as `m:ss / m:ss`: the repeat screen's own
counter, and the timer line on the main page that a replay started from the
picker shows for a while and then fades. RepeatLine holds the painted-second
reference the counter advances against (with the re-sync hold that keeps it
from stepping back), the timer's arm/show/fade/drop fields, and the position
text both lines share.

It takes no lock and reads no clock: the display (DialDisplay) reads
time.monotonic(), passes `now` in, takes its own lock where the field table
below says "under the display's lock", and does every repaint signal. The
display's LOCK ORDER comment still governs.

Threads: T touch, R repaint, H HTTP (update_config reaches the painters).

    field           writers                                         readers
    painted_second  R/H under the display's lock: frame_painted     R lock-free (counter_due, in the
                    (the main painter); R under the lock:           deadline and the repeat tick);
                    commit_counter, reset_counter (the repeat       painters under the lock
                    page's painter and opener)
    timer_id        T arm (picker_pick, then arm(None) on a         R, H
                    refusal); R lock-free: arm(None) from a repeat
                    outcome, the clear in timer_deadline; R/H
                    under the lock: the clear in timer_line
    timer_armed_at  T, R arm                                        R
    timer_shown_at  T, R arm; R/H under the lock: timer_line        R lock-free (timer_deadline)
    timer_frame_at  T, R arm; R/H under the lock: frame_painted     R lock-free (timer_deadline)
    timer_signal_at R lock-free: timer_fired                        R lock-free (timer_deadline)

arm writes the id last, so a reader never pairs a new id with stale times.
The clears of timer_id are lock-free read-modify-writes: a pick landing
between their read and write is lost, which costs one missing timer line.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import math

from dial_display_controls import DEADLINE_PAD_S
from dial_display_views import format_mmss
from dial_repeat_store import heard_position

# A status re-sync can move the locally interpolated counter back by up to
# the appliance's own status-cache age plus jitter: well under a second.
# A step back smaller than this is a re-sync artefact, and the second
# already painted is held until the clock catches up (which takes under a
# second, since the clock gains at 1 s/s); a step back of at least this
# much is a real position change (restart, loop wrap, a stalled source)
# and is shown at once. See RepeatLine.counter_second().
REPEAT_COUNTER_HOLD_S = 1.0

# The replay position line shown on the main page after a picker start:
# fully shown for REPLAY_TIMER_SHOW_S from the first frame that has a
# position to show, then faded out over REPLAY_TIMER_FADE_S, one frame
# every REPLAY_TIMER_FADE_GAP_S (the line is a small window, so the fade is
# cheap). A pick whose replay has produced nothing to show within
# REPLAY_TIMER_ARM_S is dropped.
REPLAY_TIMER_SHOW_S = 10.0
REPLAY_TIMER_FADE_S = 1.0
REPLAY_TIMER_FADE_GAP_S = 0.04
REPLAY_TIMER_ARM_S = 10.0


class RepeatLine:
    """The replaying counter and the replay timer line: fields and arithmetic
    only. Every method takes `now` from the display."""

    def __init__(self) -> None:
        # The counter second last painted for the replaying counter (on
        # either line), the reference the counter's tick advances against:
        # the repeat screen is due a paint whenever the second the counter
        # should read now differs from it, wherever within the second the
        # wake landed, so a late wake or a status re-sync that moved the
        # interpolated clock can never skip a second. None when no counter
        # is running, so the next replaying frame re-anchors.
        self.painted_second: int | None = None
        # The replay position line shown on the main page after a replay is
        # started from the picker: the appliance it is for (None: no timer),
        # when the pick armed it, when its first line was drawn (0.0: not
        # yet; the REPLAY_TIMER_SHOW_S window counts from then), when the
        # last fade frame left, and when the timer's own tick last asked for
        # a repaint.
        self.timer_id: "str | None" = None
        self.timer_armed_at = 0.0
        self.timer_shown_at = 0.0
        self.timer_frame_at = 0.0
        self.timer_signal_at = 0.0

    # ---- the counter ------------------------------------------------------

    def counter_second(self, value: float) -> int:
        """The integer second the replaying counter should read for the
        unfloored counter value *value* (the heard position, which runs
        negative for the first moments after a (re)start or a loop wrap),
        given the second last painted. Normally floor(value), clamped at
        zero. When a status re-sync has moved the interpolated clock back
        below the painted second by less than REPEAT_COUNTER_HOLD_S, the
        painted second is held instead, so the line never steps back or
        repeats for a re-sync; a larger step back is a real change (a
        restart, the loop wrap, a stalled source) and floor(value) is
        returned so it shows at once. A hold is self-limiting: the clock
        gains on the held value at one second per second, so it lasts
        under REPEAT_COUNTER_HOLD_S. Pure: never writes the painted
        second, which only the painters commit."""
        current = max(0, math.floor(value))
        painted = self.painted_second
        if painted is None or current >= painted:
            return current
        if painted - value < REPEAT_COUNTER_HOLD_S:
            return painted
        return current

    def counter_due(self, rec, now: float) -> "float | None":
        """When the running replay counter for repeat-store record *rec*
        next needs a paint: *now* when one is already owed (nothing painted
        yet, or the second moved under a signal repaint or a re-sync), else
        the moment the counter first passes the painted second, plus the
        small scheduling pad the other deadlines use. While a re-sync hold
        is on (value below painted) that is over a second out; the repaint
        loop's own one-second cap trims it and the tick then simply finds
        itself not due and reschedules. None when *rec* is not replaying.
        Shared by every line that shows the counter."""
        if rec is None or rec.state != "replaying":
            return None
        value = heard_position(rec, now)
        painted = self.painted_second
        if self.counter_second(value) != painted:
            return now
        return now + (painted + 1.0 - value) + DEADLINE_PAD_S

    def position_line(self, rec, now: float) -> "tuple[str, int | None] | None":
        """The replay position line for repeat-store record *rec* and the
        counter second it reads (None unless the replay is running), or
        None when *rec* has no replay to show (absent, unavailable, or a
        live source). hold reads 0:00; replaying reads the interpolated
        counter through counter_second(); fading_out freezes at the last
        observed position. Shared by the repeat screen and the main page's
        replay timer line so the two always read alike."""
        if rec is None or not rec.available:
            return None
        if rec.state == "hold":
            return f"0:00 / {format_mmss(rec.recording_seconds)}", None
        if rec.state == "replaying":
            second = self.counter_second(heard_position(rec, now))
            return f"{format_mmss(second)} / {format_mmss(rec.duration_seconds)}", second
        if rec.state == "fading_out":
            return f"{format_mmss(rec.position_seconds)} / {format_mmss(rec.duration_seconds)}", None
        return None

    def reset_counter(self) -> None:
        """Re-anchor the counter: the next replaying frame paints whatever
        second is current, never held against a value painted before."""
        self.painted_second = None

    def commit_counter(self, second: "int | None") -> None:
        """Record the second the repeat page just painted (None for any
        layout without a running counter)."""
        self.painted_second = second

    # ---- the timer line ---------------------------------------------------

    def arm(self, appliance_id: "str | None", now: float) -> None:
        """Start the replay timer for *appliance_id*, or drop it with None.
        Plain writes, the id last."""
        self.timer_armed_at = now
        self.timer_shown_at = 0.0
        self.timer_frame_at = 0.0
        self.timer_id = appliance_id

    def timer_deadline(self, now: float, record_of) -> "float | None":
        """When the main page's replay timer line next needs a paint (see
        timer_line()), or None when there is no timer. *record_of* maps an
        appliance id to its repeat record. While armed but not yet shown, a
        quarter-second check for its first position; while shown, the
        counter's next second (or at once, when a paint is owed), then the
        fade's frames, then one last paint to clear it. A timer that has run
        out, or whose replay has ended, is dropped here as well as in
        timer_line(), so it ends even while the main page is not painting
        (the idle screen, say). No deadline is ever sooner than
        REPLAY_TIMER_FADE_GAP_S after the last one this timer signalled, so
        a paint that does not advance it can never make the loop spin."""
        appliance_id = self.timer_id
        if appliance_id is None:
            return None
        shown = self.timer_shown_at
        if not shown:
            if now - self.timer_armed_at >= REPLAY_TIMER_ARM_S:
                self.timer_id = None
                return None
            return now + 0.25
        elapsed = now - shown
        rec = record_of(appliance_id)
        if elapsed >= REPLAY_TIMER_SHOW_S + REPLAY_TIMER_FADE_S or self.position_line(rec, now) is None:
            # One last paint, without the line.
            self.timer_id = None
            due = now
        elif elapsed >= REPLAY_TIMER_SHOW_S:
            due = max(now, self.timer_frame_at + REPLAY_TIMER_FADE_GAP_S)
        else:
            due = shown + REPLAY_TIMER_SHOW_S + DEADLINE_PAD_S
            counter_due = self.counter_due(rec, now)
            if counter_due is not None:
                due = min(due, counter_due)
        return max(due, self.timer_signal_at + REPLAY_TIMER_FADE_GAP_S)

    def timer_line(self, now: float, record_of, focused_id: "str | None") -> "tuple[str, float, int | None] | None":
        """The main page's replay timer line right now, as (text, alpha,
        counter second), or None when none is drawn. Only for the appliance
        the pick was for, and only while it is *focused_id*. The show window
        starts at the first frame with a position to show, then the line
        fades. The timer is dropped once it has faded, when its replay ends,
        or when a pick has shown nothing within REPLAY_TIMER_ARM_S."""
        appliance_id = self.timer_id
        if appliance_id is None or appliance_id != focused_id:
            return None
        shown_at = self.timer_shown_at
        position = self.position_line(record_of(appliance_id), now)
        if position is None:
            if shown_at or now - self.timer_armed_at >= REPLAY_TIMER_ARM_S:
                self.timer_id = None
            return None
        if not shown_at:
            shown_at = self.timer_shown_at = now
        elapsed = now - shown_at
        if elapsed >= REPLAY_TIMER_SHOW_S + REPLAY_TIMER_FADE_S:
            self.timer_id = None
            return None
        alpha = 1.0 if elapsed < REPLAY_TIMER_SHOW_S else 1.0 - (elapsed - REPLAY_TIMER_SHOW_S) / REPLAY_TIMER_FADE_S
        return position[0], alpha, position[1]

    def frame_painted(self, second: "int | None", sent_at: "float | None" = None) -> None:
        """Note that the main page just painted its timer line at counter
        *second*; *sent_at* is the moment a fade frame finished being sent
        (None for a fully shown line)."""
        self.painted_second = second
        if sent_at is not None:
            self.timer_frame_at = sent_at

    def timer_fired(self, now: float) -> None:
        """Note that the timer's own tick just asked for a repaint."""
        self.timer_signal_at = now
