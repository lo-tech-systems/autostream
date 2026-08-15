"""Tests for dial_touch_filter.py — pure touch sample filtering and
press-lifecycle policy.

Drives TouchFilter with synthetic (x, y, z) sample streams and an injected
clock (a plain float advanced by the test), so every timing edge (debounce,
settle, repeat cadence, max-hold cap) is deterministic.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
if _DIAL not in sys.path:
    sys.path.insert(0, _DIAL)

from dial_touch_filter import (  # noqa: E402
    DEBOUNCE_S,
    FIRST_REPEAT_S,
    MAX_HOLD_S,
    MEDIAN_N,
    REPEAT_INTERVAL_S,
    TouchEventType,
    TouchFilter,
)
from dial_touch_layout import TouchZone, zones_for  # noqa: E402

WIDTH, HEIGHT = 160, 128  # WIDE layout: MUTE | DOWN | UP thirds
Z_THRESHOLD = 100
Z_HIGH = 500
Z_LOW = 0

# A point safely inside each zone's active rectangle, for feeding samples.
_ZONES = zones_for(WIDTH, HEIGHT)


def _center(zone: TouchZone) -> tuple[int, int]:
    x0, y0, x1, y1 = _ZONES[zone]
    return ((x0 + x1) // 2, (y0 + y1) // 2)


UP_XY = _center(TouchZone.UP)
DOWN_XY = _center(TouchZone.DOWN)
MUTE_XY = _center(TouchZone.MUTE)


def make_filter(**kwargs) -> TouchFilter:
    kwargs.setdefault("z_threshold", Z_THRESHOLD)
    return TouchFilter(WIDTH, HEIGHT, **kwargs)


def press_to_confirmed(f: TouchFilter, xy, start: float) -> tuple[float, list]:
    """Feed enough contact samples at *xy* from *start* to get past settle +
    debounce and receive the PRESS event. Returns (now, all_events)."""
    events = []
    # Settle tick (discarded).
    events += f.feed((*xy, Z_HIGH), start)
    # Debounce-confirming tick, after DEBOUNCE_S has elapsed.
    now = start + DEBOUNCE_S + 0.001
    events += f.feed((*xy, Z_HIGH), now)
    return now, events


# ---------------------------------------------------------------------------
# Median smoothing
# ---------------------------------------------------------------------------

class TestMedianSmoothing:
    def test_median_n_constant(self):
        assert MEDIAN_N == 3

    def test_outlier_is_smoothed_out_of_press_position(self):
        f = make_filter()
        now = 0.0
        x, y = UP_XY
        # Settle tick with an outlier x far from the true position.
        f.feed((x + 1000, y, Z_HIGH), now)
        now += 0.001
        f.feed((x, y, Z_HIGH), now)
        now += 0.001
        now = DEBOUNCE_S + 0.01
        events = f.feed((x, y, Z_HIGH), now)
        assert len(events) == 1
        press = events[0]
        assert press.type == TouchEventType.PRESS
        # Median of [x+1000, x, x] over the 3-sample window is x, not the
        # outlier.
        assert press.x == x


# ---------------------------------------------------------------------------
# Z-threshold rejection
# ---------------------------------------------------------------------------

class TestZThresholdRejection:
    def test_low_z_never_produces_events(self):
        f = make_filter()
        now = 0.0
        for _ in range(10):
            events = f.feed((*UP_XY, Z_LOW), now)
            assert events == []
            now += 0.05

    def test_z_exactly_at_threshold_counts_as_contact(self):
        f = make_filter()
        now = 0.0
        f.feed((*UP_XY, Z_THRESHOLD), now)
        now = DEBOUNCE_S + 0.01
        events = f.feed((*UP_XY, Z_THRESHOLD), now)
        assert len(events) == 1
        assert events[0].type == TouchEventType.PRESS


# ---------------------------------------------------------------------------
# Settling: first accepted reading is discarded
# ---------------------------------------------------------------------------

class TestSettling:
    def test_first_contact_tick_produces_no_event(self):
        f = make_filter()
        events = f.feed((*UP_XY, Z_HIGH), 0.0)
        assert events == []

    def test_immediate_release_after_settle_tick_produces_no_event(self):
        """A touch shorter than one tick (settle, then straight back to no
        contact) never reaches debounce, so no PRESS or RELEASE at all."""
        f = make_filter()
        events = f.feed((*UP_XY, Z_HIGH), 0.0)
        assert events == []
        events = f.feed((*UP_XY, Z_LOW), 0.005)
        assert events == []
        events = f.feed(None, 0.5)
        assert events == []


# ---------------------------------------------------------------------------
# Debounce
# ---------------------------------------------------------------------------

class TestDebounce:
    def test_press_not_confirmed_before_debounce_elapses(self):
        f = make_filter()
        f.feed((*UP_XY, Z_HIGH), 0.0)  # settle
        events = f.feed((*UP_XY, Z_HIGH), DEBOUNCE_S / 2)
        assert events == []

    def test_bounce_back_before_debounce_elapses_aborts_with_no_event(self):
        f = make_filter()
        f.feed((*UP_XY, Z_HIGH), 0.0)  # settle
        events = f.feed((*UP_XY, Z_LOW), DEBOUNCE_S / 2)  # bounce back
        assert events == []
        # A fresh contact afterwards still needs its own settle+debounce.
        events = f.feed((*UP_XY, Z_HIGH), 1.0)
        assert events == []
        events = f.feed((*UP_XY, Z_HIGH), 1.0 + DEBOUNCE_S + 0.001)
        assert len(events) == 1
        assert events[0].type == TouchEventType.PRESS

    def test_release_debounced_symmetrically(self):
        f = make_filter()
        now, events = press_to_confirmed(f, UP_XY, 0.0)
        assert events[-1].type == TouchEventType.PRESS
        # Drop below threshold, then bounce back up before release debounce
        # elapses: press must NOT be released.
        events = f.feed((*UP_XY, Z_LOW), now + 0.001)
        assert events == []
        events = f.feed((*UP_XY, Z_HIGH), now + 0.002)
        assert events == []
        # Genuinely release now, holding low long enough.
        events = f.feed((*UP_XY, Z_LOW), now + 0.003)
        assert events == []
        events = f.feed((*UP_XY, Z_LOW), now + 0.003 + DEBOUNCE_S + 0.001)
        assert len(events) == 1
        assert events[0].type == TouchEventType.RELEASE


# ---------------------------------------------------------------------------
# PRESS / REPEAT / RELEASE ordering and exact cadence
# ---------------------------------------------------------------------------

class TestPressRepeatRelease:
    def test_full_lifecycle_ordering(self):
        f = make_filter()
        now, events = press_to_confirmed(f, UP_XY, 0.0)
        assert [e.type for e in events] == [TouchEventType.PRESS]
        press_time = now

        # No repeat before FIRST_REPEAT_S.
        events = f.feed((*UP_XY, Z_HIGH), press_time + FIRST_REPEAT_S - 0.01)
        assert events == []

        # First repeat at press_time + FIRST_REPEAT_S.
        events = f.feed((*UP_XY, Z_HIGH), press_time + FIRST_REPEAT_S)
        assert [e.type for e in events] == [TouchEventType.REPEAT]

        # Second repeat REPEAT_INTERVAL_S later, not FIRST_REPEAT_S later.
        t2 = press_time + FIRST_REPEAT_S + REPEAT_INTERVAL_S
        events = f.feed((*UP_XY, Z_HIGH), t2 - 0.01)
        assert events == []
        events = f.feed((*UP_XY, Z_HIGH), t2)
        assert [e.type for e in events] == [TouchEventType.REPEAT]

        # Release.
        events = f.feed((*UP_XY, Z_LOW), t2 + 0.001)
        assert events == []
        events = f.feed((*UP_XY, Z_LOW), t2 + 0.001 + DEBOUNCE_S + 0.001)
        assert [e.type for e in events] == [TouchEventType.RELEASE]

    def test_constants(self):
        assert FIRST_REPEAT_S == 0.4
        assert REPEAT_INTERVAL_S == 0.15

    def test_one_repeat_per_feed_call_even_after_a_large_clock_jump(self):
        f = make_filter()
        now, _ = press_to_confirmed(f, UP_XY, 0.0)
        # Jump far past several would-be repeat instants in one tick, but
        # stay well under MAX_HOLD_S so this isn't a CAP instead.
        assert now + 1.0 < MAX_HOLD_S
        events = f.feed((*UP_XY, Z_HIGH), now + 1.0)
        repeats = [e for e in events if e.type == TouchEventType.REPEAT]
        assert len(repeats) == 1


# ---------------------------------------------------------------------------
# Max sustained hold cap
# ---------------------------------------------------------------------------

class TestMaxHoldCap:
    def test_cap_fires_after_max_hold_and_stops_repeats(self):
        f = make_filter()
        press_time, events = press_to_confirmed(f, UP_XY, 0.0)
        events = f.feed((*UP_XY, Z_HIGH), press_time + MAX_HOLD_S)
        assert [e.type for e in events] == [TouchEventType.CAP]

        # Continued holding produces nothing further — no more REPEAT.
        events = f.feed((*UP_XY, Z_HIGH), press_time + MAX_HOLD_S + REPEAT_INTERVAL_S)
        assert events == []

    def test_no_release_emitted_after_cap_when_finger_finally_lifts(self):
        f = make_filter()
        press_time, _ = press_to_confirmed(f, UP_XY, 0.0)
        events = f.feed((*UP_XY, Z_HIGH), press_time + MAX_HOLD_S)
        assert events[0].type == TouchEventType.CAP
        t = press_time + MAX_HOLD_S + 0.01
        events = f.feed((*UP_XY, Z_LOW), t)
        assert events == []
        events = f.feed((*UP_XY, Z_LOW), t + DEBOUNCE_S + 0.001)
        assert events == []  # not RELEASE — CAP already served as the end

    def test_fresh_contact_required_to_resume_after_cap(self):
        f = make_filter()
        press_time, _ = press_to_confirmed(f, UP_XY, 0.0)
        f.feed((*UP_XY, Z_HIGH), press_time + MAX_HOLD_S)  # CAP
        t = press_time + MAX_HOLD_S + 0.01
        f.feed((*UP_XY, Z_LOW), t)
        f.feed((*UP_XY, Z_LOW), t + DEBOUNCE_S + 0.001)  # silent internal reset

        # A brand-new contact goes through settle + debounce again and gets
        # its own PRESS.
        t2 = t + 1.0
        events = f.feed((*UP_XY, Z_HIGH), t2)
        assert events == []
        events = f.feed((*UP_XY, Z_HIGH), t2 + DEBOUNCE_S + 0.001)
        assert [e.type for e in events] == [TouchEventType.PRESS]

    def test_max_hold_constant(self):
        assert MAX_HOLD_S > 1.0  # "a few seconds"


# ---------------------------------------------------------------------------
# Zone latch
# ---------------------------------------------------------------------------

class TestZoneLatch:
    def test_zone_latched_at_press_survives_slide_into_another_zone(self):
        f = make_filter()
        press_time, events = press_to_confirmed(f, UP_XY, 0.0)
        press = events[0]
        assert press.zone == TouchZone.UP

        # Slide across the boundary into DOWN's zone, well before the first
        # repeat fires — feed enough samples at the new position for the
        # median-of-N window to fully converge on it before checking the
        # position reported on the eventual REPEAT.
        slide_x, slide_y = DOWN_XY
        pre_repeat_t = press_time + FIRST_REPEAT_S - 0.02
        for i in range(MEDIAN_N):
            events = f.feed((slide_x, slide_y, Z_HIGH), pre_repeat_t + i * 0.001)
            assert events == []

        t = press_time + FIRST_REPEAT_S
        events = f.feed((slide_x, slide_y, Z_HIGH), t)
        assert len(events) == 1
        repeat = events[0]
        assert repeat.type == TouchEventType.REPEAT
        # Zone stays UP — latched at press, not re-derived.
        assert repeat.zone == TouchZone.UP
        # But position tracks the live, current location.
        assert (repeat.x, repeat.y) == (slide_x, slide_y)

    def test_mute_zone_latch(self):
        f = make_filter()
        _, events = press_to_confirmed(f, MUTE_XY, 0.0)
        assert events[0].zone == TouchZone.MUTE
