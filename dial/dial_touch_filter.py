"""dial_touch_filter.py — pure touch sample filtering and press-lifecycle
policy.

No hardware, no threads, no wall-clock reads of its own: every call passes
in *now* (typically time.monotonic()) so this module is fully deterministic
under test with a synthetic sample stream and an injected clock. It knows
nothing about SPI/I2C, gpiozero, or any driver — dial_touch_drivers.py hands
it raw (x, y, z) tuples (or None) and it turns those into a small, ordered
stream of press-lifecycle events.

Pipeline per feed() call, in order:
  1. median-of-N smoothing of x/y (over the last MEDIAN_N raw samples) to
     reject single-sample ADC position noise,
  2. Z-pressure threshold rejection, on THIS tick's raw z (not smoothed —
     see TouchFilter.feed()'s comment for why lift-off must not be masked
     by a couple of stale still-touching samples lingering in the window),
  3. settling: the very first accepted-contact tick after IDLE is consumed
     silently (it starts the debounce timer but produces no event) —
     resistive panels commonly report a noisy transient on first contact,
  4. debounce: the contact/no-contact edge must hold for DEBOUNCE_S before
     it is trusted; a bounce back within that window aborts the pending
     transition with no event at all,
  5. press lifecycle: PRESS (zone latched from the confirming sample's
     position) -> REPEAT (first at FIRST_REPEAT_S after PRESS, then every
     REPEAT_INTERVAL_S) -> RELEASE, or CAP if MAX_HOLD_S is reached while
     still held (auto-stops repeating; a fresh contact is required to
     resume — no further REPEAT or RELEASE is emitted for that press after
     CAP fires).

ZONE LATCH: the zone reported on every event of one press (PRESS, REPEAT,
CAP) is decided exactly once, from the position at the moment PRESS fires,
and never re-derived even if the finger slides into a different zone
afterwards. The *position* (x, y) reported on later events is still the
live, current smoothed position — only the zone field is frozen. This lets
a consumer that needs "the current physical position" (e.g. a reveal-then-
arm session that samples the zone later, from wherever the finger currently
is) read event.x/event.y, while a consumer that just wants "which zone was
this press" reads event.zone.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass
from enum import Enum

from dial_touch_layout import TouchZone, zone_at

# Number of raw samples averaged (component-wise median) per accepted
# reading. Odd so there is always a single middle value.
MEDIAN_N = 3

# Nominal Z-pressure threshold below which a sample is "not touching". Kept
# as this module's default so a filter can be constructed with no extra
# wiring; callers that know their controller's calibrated threshold (see
# dial_touch_controllers.TouchController.z_threshold) should pass it in.
DEFAULT_Z_THRESHOLD = 100

# Contact/no-contact transitions must hold steady for this long before being
# trusted, absorbing switch bounce right at the threshold.
DEBOUNCE_S = 0.02

# Repeat cadence: first REPEAT fires this long after PRESS, then every
# REPEAT_INTERVAL_S after that.
FIRST_REPEAT_S = 0.4
REPEAT_INTERVAL_S = 0.15

# Maximum sustained hold: after this long from PRESS, repeating auto-stops
# and a CAP event fires instead of the next REPEAT. A fresh contact (full
# release + new press) is required to resume.
MAX_HOLD_S = 5.0


class TouchEventType(str, Enum):
    PRESS = "press"
    REPEAT = "repeat"
    RELEASE = "release"
    CAP = "cap"


@dataclass(frozen=True)
class TouchEvent:
    type: TouchEventType
    x: int
    y: int
    zone: TouchZone | None  # latched at PRESS; see module docstring


# Internal filter phases.
_IDLE = "idle"
_DEBOUNCE_CONTACT = "debounce_contact"      # settle tick already consumed
_HELD = "held"
_HELD_CAPPED = "held_capped"
_DEBOUNCE_RELEASE = "debounce_release"


class TouchFilter:
    """Stateful, pure press-lifecycle filter. One instance per physical
    press session (construct once, feed() repeatedly for the process
    lifetime — it resets its own internal state at each RELEASE/CAP)."""

    def __init__(
        self,
        width: int,
        height: int,
        *,
        z_threshold: int = DEFAULT_Z_THRESHOLD,
        median_n: int = MEDIAN_N,
    ) -> None:
        self._width = width
        self._height = height
        self._z_threshold = z_threshold
        self._median_n = median_n

        self._window: list[tuple[int, int, int]] = []
        self._phase = _IDLE
        self._edge_since: float | None = None  # when the current pending edge began
        self._press_time: float | None = None
        self._next_repeat_time: float | None = None
        self._zone: TouchZone | None = None
        self._last_xy: tuple[int, int] | None = None
        self._capped = False

    def feed(self, raw_sample: tuple[int, int, int] | None, now: float) -> list[TouchEvent]:
        """Feed one raw (x, y, z) sample (or None for "definitely not
        touching right now", e.g. the caller's IRQ went inactive). Returns
        zero or more TouchEvent in the order they occurred."""
        if raw_sample is None:
            self._window.clear()
            contact = False
            mx = my = None
        else:
            self._window.append(raw_sample)
            if len(self._window) > self._median_n:
                self._window.pop(0)
            mx = int(statistics.median(s[0] for s in self._window))
            my = int(statistics.median(s[1] for s in self._window))
            # The Z/contact decision deliberately uses THIS tick's raw z, not
            # a median over the window: median-of-N exists to smooth x/y
            # position jitter from a still-pressed finger, not to delay
            # noticing a genuine, fast lift-off — smoothing z here would
            # have a real liftoff "hidden" behind a couple of stale
            # still-touching samples lingering in the window.
            contact = raw_sample[2] >= self._z_threshold

        if mx is not None and my is not None:
            self._last_xy = (mx, my)

        events: list[TouchEvent] = []

        if self._phase == _IDLE:
            if contact:
                # First accepted tick after idle: settle only, no event.
                self._phase = _DEBOUNCE_CONTACT
                self._edge_since = now
            return events

        if self._phase == _DEBOUNCE_CONTACT:
            if not contact:
                # Bounced back before debounce elapsed — abort, no event.
                self._phase = _IDLE
                self._edge_since = None
                return events
            if now - self._edge_since >= DEBOUNCE_S:
                x, y = self._last_xy
                zone = zone_at(x, y, self._width, self._height)
                self._zone = zone
                self._press_time = now
                self._next_repeat_time = now + FIRST_REPEAT_S
                self._phase = _HELD
                self._edge_since = None
                events.append(TouchEvent(TouchEventType.PRESS, x, y, zone))
            return events

        if self._phase in (_HELD, _HELD_CAPPED):
            if not contact:
                self._phase = _DEBOUNCE_RELEASE
                self._edge_since = now
                return events
            # Still in contact.
            if self._phase == _HELD_CAPPED:
                return events
            if now - self._press_time >= MAX_HOLD_S:
                x, y = self._last_xy
                self._phase = _HELD_CAPPED
                self._next_repeat_time = None
                self._capped = True
                events.append(TouchEvent(TouchEventType.CAP, x, y, self._zone))
                return events
            if self._next_repeat_time is not None and now >= self._next_repeat_time:
                # Only ever emit one REPEAT per feed() call, even if *now*
                # has jumped far past several would-be repeat instants — a
                # caller feeding samples in a tight poll loop still gets a
                # REPEAT roughly every poll tick once due, without bursting
                # a backlog of "catch-up" repeats from one big clock jump.
                x, y = self._last_xy
                events.append(TouchEvent(TouchEventType.REPEAT, x, y, self._zone))
                self._next_repeat_time += REPEAT_INTERVAL_S
            return events

        if self._phase == _DEBOUNCE_RELEASE:
            if contact:
                # Bounced back — still held (preserving whether it had
                # already capped), no event.
                self._phase = _HELD_CAPPED if self._capped else _HELD
                self._edge_since = None
                return events
            if now - self._edge_since >= DEBOUNCE_S:
                x, y = self._last_xy if self._last_xy is not None else (0, 0)
                zone = self._zone
                was_capped = self._capped
                self._reset()
                # A CAP already told the consumer the press ended; do not
                # also emit a real RELEASE for the same press.
                if not was_capped:
                    events.append(TouchEvent(TouchEventType.RELEASE, x, y, zone))
            return events

        return events

    def _reset(self) -> None:
        self._phase = _IDLE
        self._edge_since = None
        self._press_time = None
        self._next_repeat_time = None
        self._zone = None
        self._window.clear()
        self._capped = False
