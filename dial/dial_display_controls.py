"""dial_display_controls.py: the display's controls windows and the reveal slide.

Two time windows decide whether the controls bands are drawn: an artwork tap
hides them for CONTROLS_HIDE_SECONDS, and on the compact tier a touch opens
them for the same length (they start hidden). Around the first, the rich and
large tiers slide the bands' chrome off the panel and back on over
REVEAL_ANIMATION_S. ControlsReveal holds the fields of both and the
arithmetic on them.

It takes no lock and reads no clock: the display (DialDisplay) reads
time.monotonic(), passes `now` in, takes its own lock where the field table
below says "under the display's lock", and does every repaint signal. The
display's LOCK ORDER comment still governs.

Threads: T touch, R repaint, H HTTP (update_config reaches the painters).

    field         writers                                              readers
    hidden_until  T hide, end_hide; R expire_hidden (no lock); R/H     T, R, H, deadline
                  abandon and end_hide under the display's lock
    shown_until   T show_compact; R show_compact (screen change,       T, R, H
                  under the lock); R expire_shown (no lock)
    started_at    R/H under the lock: advance, abandon, abandon_slide, R lock-free (deadline,
                  clear_slide_if (the reveal timer takes the lock)     the reveal timer's compare);
                                                                       painters under the lock
    sliding_in    R/H under the lock: advance                          under the lock: progress
    frame_at      R/H under the lock: frame_sent                       R lock-free (reveal_deadline;
                                                                       a stale value costs one early
                                                                       frame)
    last          R/H under the lock: advance, abandon, abandon_slide  under the lock: advance

The touch-thread writes (hide, end_hide, show_compact) are blind assignments
of a float, atomic under the GIL. expire_hidden and expire_shown are lock-free
read-modify-writes: a hide or show landing between their read and write is
lost, which costs the user one extra tap and nothing else.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

# How long an artwork tap hides the top/bottom bands for. Long enough to look
# at the artwork without the overlay reappearing underneath, short enough
# that the controls are never truly lost: any tap while hidden restores them
# at once anyway. Also the window a compact screen's own controls stay shown
# after a touch/reveal before fading back to bare artwork; the same "long
# enough to act on, short enough to get out of the way" reasoning applies to
# both.
CONTROLS_HIDE_SECONDS = 6.0

# The artwork reveal: how long the bands' chrome takes to slide off the
# panel (the top band up, the bottom band down) while the inter-band text
# fades, before the bare artwork of the hide window shows on its own, and
# how long it takes to slide back in when the controls return. Long
# enough to read as a smooth movement at the frame rate a windowed transmit
# allows on the shipped panel (a dozen or more frames), short enough that
# the artwork is unobstructed well inside a second of the tap. Rich and
# large tiers only: the base tier keeps its instant hide and show and the
# compact tier has no bands. Between slide frames the repaint loop always
# waits at least REVEAL_FRAME_GAP_S. The gap exists so the loop actually
# sleeps, releasing the display's lock and the GIL, between frames and lets
# the touch and HTTP threads take the lock: CPython locks are not FIFO and
# the interpreter only switches threads every sys.getswitchinterval() (5 ms),
# so a back-to-back release and reacquire would starve them. Any real sleep
# hands over, so the gap only needs to be short. On the shipped panel the
# transmit itself is the pace; on a fast or no-op backend the gap is also
# what stops the loop spinning.
REVEAL_ANIMATION_S = 0.55
REVEAL_FRAME_GAP_S = 0.001

# The small margin added to a wake deadline so the wake lands just past the
# moment it is aiming at, not a hair before it.
DEADLINE_PAD_S = 0.005


def reveal_ease(t: float) -> float:
    """Smoothstep easing for the artwork-tap reveal: the chrome starts
    moving gently, is fastest mid-way and settles as it leaves the panel
    edge, so neither the first nor the last frame jumps at the frame rates
    the panel allows. *t* is the clamped time fraction 0..1; the result is
    monotonic in 0..1 with f(0) = 0 and f(1) = 1 exactly."""
    return t * t * (3.0 - 2.0 * t)


class ControlsReveal:
    """The controls windows and the reveal slide: fields and arithmetic only.
    Every method takes `now` from the display."""

    def __init__(self) -> None:
        # Monotonic deadline until which the controls bands are hidden after
        # an artwork tap (0.0, i.e. never, until something arms it).
        self.hidden_until: float = 0.0
        # Compact tier only: monotonic deadline until which a compact
        # screen's own controls stay drawn, opened by a touch, reveal or
        # screen change. Starts at 0.0 (already in the past), so a freshly
        # shown compact screen reads as hidden until the first touch, by
        # design: compact controls start hidden, never flashed on
        # appearance.
        self.shown_until: float = 0.0
        # Monotonic start of the reveal slide (the bands' chrome sliding off
        # the panel, or back onto it), 0.0 when none is running. Stamped at
        # the compose that first finds the controls' state changed, so the
        # first slide frame is a frame that actually painted rather than a
        # moment on the touch thread. Cleared by every path that abandons the
        # slide (a screen change, the panel going dark, a screen or tier that
        # does not animate) and, once the slide is done, only if it is still
        # the start the clearing thread saw.
        self.started_at: float = 0.0
        # Direction of the slide the start belongs to: False while the chrome
        # leaves, True while it returns.
        self.sliding_in: bool = False
        # Monotonic time the last reveal frame finished being sent, so the
        # repaint loop waits at least REVEAL_FRAME_GAP_S after it.
        self.frame_at: float = 0.0
        # Whether the last frame composed for the current screen had its
        # controls steady in place (True) or away (False), or None when there
        # is no comparable previous frame: nothing composed yet on this
        # screen, or the panel went dark or showed the idle screen since. The
        # slide starts exactly when this flips between True and False on a
        # compose, whatever made it flip. None never starts a slide, so a
        # screen change, a wake or the first track after idle appears as it
        # is.
        self.last: bool | None = None

    # ---- touch-thread writes: blind assignments --------------------------

    def hide(self, now: float) -> None:
        """Open an artwork tap's hide window."""
        self.hidden_until = now + CONTROLS_HIDE_SECONDS

    def end_hide(self) -> None:
        """End the hide window."""
        self.hidden_until = 0.0

    def show_compact(self, now: float) -> None:
        """Open the compact tier's own controls window. A harmless write on
        every other tier, where nothing consults it."""
        self.shown_until = now + CONTROLS_HIDE_SECONDS

    # ---- reads ------------------------------------------------------------

    def hidden(self, now: float) -> bool:
        """True while an artwork tap's hide window is still running."""
        return now < self.hidden_until

    def compact_hidden(self, now: float) -> bool:
        """True once the compact tier's controls window has lapsed, or was
        never opened. The caller applies it on the compact tier only."""
        return now >= self.shown_until

    def animating(self, now: float) -> bool:
        """True while a reveal slide is running: a start is stamped and its
        duration has not run out, in either direction."""
        started = self.started_at
        return started != 0.0 and now < started + REVEAL_ANIMATION_S

    def progress(self, now: float) -> float:
        """How far the reveal has slid the bands off the panel at *now*, 0.0
        (in place) to 1.0 (gone), eased; 0.0 whenever no reveal is running,
        which the compositor draws as the ordinary frame. While the bands
        slide in the same position runs backwards (1.0 down to 0.0).
        Computed from the clock at compose time and never stored, so a
        compose that lands late simply draws the later position and one that
        lands after the end draws none."""
        if not self.animating(now):
            return 0.0
        e = reveal_ease(self._fraction(now))
        return (1.0 - e) if self.sliding_in else e

    def _fraction(self, now: float) -> float:
        """The running slide's clamped time fraction 0..1 at *now*."""
        t = (now - self.started_at) / REVEAL_ANIMATION_S
        return min(1.0, max(0.0, t))

    # ---- under the display's lock -----------------------------------------

    def advance(self, now: float, steady: bool, slide_ok: bool) -> tuple[bool, float]:
        """Decide, for the frame about to be composed at *now*, whether it
        is a slide frame and how far along: (animating, progress). *steady*
        is whether the screen's controls would be drawn in place by this
        frame if no slide were running; *slide_ok* whether this screen and
        tier animate at all right now. A slide starts exactly when the
        previous frame's controls state differs from this one's: the tap
        that hid them (in either controls mode), the touch side's own
        dismiss, and the controls' return (a hide window lapsing, a reveal
        tap, the first touch) all arrive here as that one transition, the
        direction being *steady*. The start is stamped at this compose, so
        the first slide frame is the ordinary frame at progress 0 (identical
        to the last one, so nothing is transmitted) and every later frame is
        measured from a moment a frame actually painted, never from the tap
        on another thread. A change that lands mid-slide turns it around
        from where it has got: the easing is symmetric, so a slide restarted
        at the mirrored fraction continues from exactly the position last
        drawn. With no previous frame to compare (None), or where the screen
        or tier does not animate, the controls simply snap and any slide is
        dropped."""
        if not slide_ok:
            self.started_at = 0.0
            self.last = None
            return False, 0.0
        last = self.last
        if last is not None and last != steady:
            t_cur = self._fraction(now) if self.animating(now) else 1.0
            # Never 0.0, the "no slide" value.
            self.started_at = (now - (1.0 - t_cur) * REVEAL_ANIMATION_S) or 1e-9
            self.sliding_in = steady
        self.last = steady
        animating = self.animating(now)
        return animating, (self.progress(now) if animating else 0.0)

    def abandon_slide(self) -> None:
        """Drop the slide and the comparison frame: the idle screen draws no
        controls, so the next now-playing frame has nothing comparable
        before it."""
        self.started_at = 0.0
        self.last = None

    def abandon(self) -> None:
        """Drop the hide window as well as the slide: a hide window and a
        slide belong to the screen they started on, and nothing is on screen
        for them when the panel goes dark."""
        self.hidden_until = 0.0
        self.abandon_slide()

    def frame_sent(self, now: float) -> None:
        """Note that a slide frame has finished being sent."""
        self.frame_at = now

    def clear_slide_if(self, started: float) -> None:
        """End the slide, only if it is still the one starting at *started*."""
        if self.started_at == started:
            self.started_at = 0.0

    # ---- deadlines: lock-free reads ----------------------------------------

    def hidden_deadline(self, now: float) -> float | None:
        """When the hide window's end must wake the repaint loop, or None."""
        until = self.hidden_until
        return until + DEADLINE_PAD_S if until > now else None

    def shown_deadline(self, now: float, compact: bool) -> float | None:
        """When the compact controls window's end must wake the repaint
        loop, or None."""
        until = self.shown_until
        return until + DEADLINE_PAD_S if until > now and compact else None

    def reveal_deadline(self, now: float) -> float | None:
        """When the next reveal frame is due, or None with no slide stamped.
        A slide not yet settled: the next reveal frame a short gap after the
        last one was sent, or at once if that moment has passed, and never
        later than the end of the slide, so the settled frame paints on
        time. Only the end carries the usual small margin, so the settled
        frame's compose is sure to land past it; a mid-slide frame is due
        exactly when its gap is over, or the margin would add to every gap.
        Keyed on the start rather than on the slide still running: the last
        slide frame routinely finishes sending after the end, and the
        settled frame is then due at once, not at the next unrelated wake."""
        started = self.started_at
        if not started:
            return None
        next_frame = max(now, self.frame_at + REVEAL_FRAME_GAP_S)
        end = started + REVEAL_ANIMATION_S
        return next_frame if next_frame < end else max(now, end + DEADLINE_PAD_S)

    # ---- one-shot expiries: repaint thread, lock-free ----------------------

    def expire_hidden(self, now: float) -> bool:
        """True, once, when the hide window has just ended: resets the
        deadline to 0.0 (its "not hidden" value) so the caller does not keep
        re-signalling every housekeeping tick after expiry."""
        deadline = self.hidden_until
        if deadline and now >= deadline:
            self.hidden_until = 0.0
            return True
        return False

    def expire_shown(self, now: float, compact: bool) -> bool:
        """True, once, when the compact controls window has just lapsed on
        the compact tier: resets the deadline to 0.0, the same "already in
        the past" value that reads as hidden."""
        deadline = self.shown_until
        if deadline and now >= deadline and compact:
            self.shown_until = 0.0
            return True
        return False

    def slide_over(self, started: float, now: float) -> bool:
        """Whether the slide that started at *started* has run its length."""
        return now >= started + REVEAL_ANIMATION_S
