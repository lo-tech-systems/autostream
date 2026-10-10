"""Tests for dial_touch.py — TouchStateMachine (pure policy) and
TouchEventSource (thread wrapper driven entirely by fakes: no gpiozero, no
real driver, no real clock is required)."""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
if _DIAL not in sys.path:
    sys.path.insert(0, _DIAL)

from dial_touch import (  # noqa: E402
    ACTION_DISMISS_OVERLAY,
    ACTION_MUTE_TOGGLE,
    ACTION_REVEAL_OVERLAY,
    ACTION_SET_PRESSED_ZONE,
    ACTION_VOLUME_DOWN,
    ACTION_VOLUME_UP,
    ACTION_ZONE_TAP,
    DISMISS_S,
    FIRST_REPEAT_S,
    PRESSED_FLASH_S,
    REPEAT_INTERVAL_S,
    SURFACE_HELD,
    SURFACE_HIDDEN,
    SURFACE_IDLE,
    SURFACE_INFO,
    SURFACE_INFO_VALUE,
    SURFACE_NOWIFI,
    SURFACE_OUTPUT,
    SURFACE_OUTPUTS,
    SURFACE_PICKER,
    SURFACE_REPEAT,
    SURFACE_REPEAT_REPLAY,
    SURFACE_RESTARTING,
    SURFACE_SDHEALTH,
    SURFACE_SELECTOR,
    TouchAction,
    TouchEventSource,
    TouchStateMachine,
    _GEOMETRY_FOR_SURFACE,
    _REPEAT_SURFACES,
    _REPEATING_ZONES,
    _SINGLE_SHOT_ZONES,
    _ZONE_TAP_ZONES,
)
from dial_touch_filter import TouchEvent, TouchEventType, TouchFilter  # noqa: E402
from dial_touch_layout import (  # noqa: E402
    GEOMETRY_INFO,
    GEOMETRY_INFO_VALUE,
    GEOMETRY_MAIN,
    GEOMETRY_NONE,
    GEOMETRY_NOWIFI,
    GEOMETRY_OUTPUT,
    GEOMETRY_REPEAT_REPLAY,
    GEOMETRY_SDHEALTH,
    TouchZone,
    compact_layout_for,
    compact_picker_layout_for,
    hit_test,
    idle_layout_for,
    layout_for,
    list_layout_for,
    list_zone_at,
    metrics_for,
    nowifi_layout_for,
    output_layout_for,
    repeat_layout_for,
    sdhealth_layout_for,
    zones_for,
)

WIDTH, HEIGHT = 160, 128
_ZONES = zones_for(WIDTH, HEIGHT)


def _center(zone: TouchZone) -> tuple[int, int]:
    x0, y0, x1, y1 = _ZONES[zone]
    return ((x0 + x1) // 2, (y0 + y1) // 2)


UP_XY = _center(TouchZone.UP)
DOWN_XY = _center(TouchZone.DOWN)
MUTE_XY = _center(TouchZone.MUTE)


def press_event(xy, zone=None):
    return TouchEvent(TouchEventType.PRESS, xy[0], xy[1], zone)


def repeat_event(xy, zone=None):
    return TouchEvent(TouchEventType.REPEAT, xy[0], xy[1], zone)


def release_event(xy=(0, 0), zone=None):
    return TouchEvent(TouchEventType.RELEASE, xy[0], xy[1], zone)


def cap_event(xy=(0, 0), zone=None):
    return TouchEvent(TouchEventType.CAP, xy[0], xy[1], zone)


def kinds(actions):
    return [a.kind for a in actions]


def clears_pressed(actions):
    """True if any action is the pressed-zone highlight being cleared
    (ACTION_SET_PRESSED_ZONE with zone=None)."""
    return any(a.kind == ACTION_SET_PRESSED_ZONE and a.zone is None for a in actions)


# ---------------------------------------------------------------------------
# Already-visible overlay: arms immediately at touch-down
# ---------------------------------------------------------------------------

class TestTapActuatesOnce:
    """A tap — press and release well inside the repeat delay — must produce
    exactly one volume step. Requiring a 400ms hold before anything happened
    would make the buttons feel broken and would make the ordinary task
    (nudge the volume a few percent) impossible by tapping.
    """

    def _tap(self, xy):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm._overlay_visible = True
        actions = sm.on_filter_event(press_event(xy), now=0.0)
        # Released long before FIRST_REPEAT_S — no auto-repeat can have run.
        actions += sm.on_filter_event(release_event(xy), now=0.05)
        return kinds(actions)

    def test_tap_up_produces_exactly_one_volume_up(self):
        assert self._tap(UP_XY).count(ACTION_VOLUME_UP) == 1

    def test_tap_down_produces_exactly_one_volume_down(self):
        assert self._tap(DOWN_XY).count(ACTION_VOLUME_DOWN) == 1

    def test_tap_mute_produces_exactly_one_toggle(self):
        assert self._tap(MUTE_XY).count(ACTION_MUTE_TOGGLE) == 1


class TestAlreadyVisibleArmsAtTouchDown:
    def test_arms_at_press_when_overlay_already_visible(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm._overlay_visible = True  # simulate overlay already shown
        actions = sm.on_filter_event(press_event(UP_XY), now=0.0)
        # A tap must act: the first volume step lands immediately on arm.
        # Holding then auto-repeats on top of it.
        assert kinds(actions) == [ACTION_SET_PRESSED_ZONE, ACTION_VOLUME_UP]
        assert sm.pressed_zone == TouchZone.UP
        # Nothing more until the first repeat falls due.
        assert kinds(sm.tick(now=FIRST_REPEAT_S - 0.01)) == []
        assert kinds(sm.tick(now=FIRST_REPEAT_S)) == [ACTION_VOLUME_UP]

    def test_mute_zone_toggles_once_no_repeat_action(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm._overlay_visible = True
        actions = sm.on_filter_event(press_event(MUTE_XY), now=0.0)
        assert kinds(actions) == [ACTION_SET_PRESSED_ZONE, ACTION_MUTE_TOGGLE]
        # tick() at the repeat instant does nothing for a MUTE zone.
        actions = sm.tick(now=FIRST_REPEAT_S)
        assert ACTION_MUTE_TOGGLE not in kinds(actions)
        assert ACTION_VOLUME_UP not in kinds(actions)
        assert ACTION_VOLUME_DOWN not in kinds(actions)

    def test_repeat_clock_starts_from_touchdown(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm._overlay_visible = True
        sm.on_filter_event(press_event(DOWN_XY), now=10.0)
        assert sm.tick(now=10.0 + FIRST_REPEAT_S - 0.01) == []
        actions = sm.tick(now=10.0 + FIRST_REPEAT_S)
        assert kinds(actions) == [ACTION_VOLUME_DOWN]


# ---------------------------------------------------------------------------
# Reveal-only first touch
# ---------------------------------------------------------------------------

class TestRevealOnlyFirstTouch:
    def test_touch_down_while_hidden_only_reveals(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        assert sm.overlay_visible is False
        actions = sm.on_filter_event(press_event(UP_XY), now=0.0)
        assert kinds(actions) == [ACTION_REVEAL_OVERLAY]
        assert sm.overlay_visible is True
        # No zone sampled / armed yet.
        assert sm.pressed_zone is None

    def test_lift_before_overlay_live_actuates_nothing(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.on_filter_event(press_event(UP_XY), now=0.0)
        actions = sm.on_filter_event(release_event(UP_XY), now=0.05)
        assert actions == []
        # Overlay-live arrives afterwards: nothing armed, no action.
        actions = sm.overlay_live(now=0.2)
        assert actions == []
        assert sm.pressed_zone is None

    def test_still_down_at_overlay_live_stays_reveal_only(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.on_filter_event(press_event(UP_XY), now=0.0)
        # Finger slides to DOWN's zone before the overlay renders.
        sm.on_filter_event(repeat_event(DOWN_XY), now=0.1)
        actions = sm.overlay_live(now=0.15)
        # Reveal-only: the zones were not on screen when this contact began,
        # so overlay_live() never arms, no matter where the finger currently
        # is. It just returns the session to idle.
        assert actions == []
        assert sm.pressed_zone is None
        assert sm.overlay_visible is True

    def test_reveal_only_contact_never_actuates_however_long_held(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.on_filter_event(press_event(UP_XY), now=0.0)
        sm.overlay_live(now=0.1)
        assert sm.pressed_zone is None

        # Keep the same contact down well past FIRST_REPEAT_S / several
        # REPEAT_INTERVAL_S — nothing must ever actuate from this press.
        t = 0.1
        seen_actuation = False
        for _ in range(30):
            t += REPEAT_INTERVAL_S
            actions = sm.on_filter_event(repeat_event(UP_XY), now=t)
            actions += sm.tick(now=t)
            if any(
                a.kind in (ACTION_VOLUME_UP, ACTION_VOLUME_DOWN, ACTION_MUTE_TOGGLE)
                for a in actions
            ):
                seen_actuation = True
        assert t > 0.1 + FIRST_REPEAT_S + 4 * REPEAT_INTERVAL_S
        assert not seen_actuation
        assert sm.pressed_zone is None

    def test_second_press_after_reveal_only_release_arms_and_actuates(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.on_filter_event(press_event(UP_XY), now=0.0)
        sm.overlay_live(now=0.1)
        sm.on_filter_event(release_event(UP_XY), now=0.2)
        assert sm.overlay_visible is True
        assert sm.pressed_zone is None

        # A second, deliberate press while the overlay is still visible arms
        # and actuates immediately — this is what the first touch could not
        # do because the zones were not yet on screen.
        actions = sm.on_filter_event(press_event(UP_XY), now=0.3)
        assert kinds(actions) == [ACTION_SET_PRESSED_ZONE, ACTION_VOLUME_UP]
        assert sm.pressed_zone == TouchZone.UP


# ---------------------------------------------------------------------------
# Dismiss timing
# ---------------------------------------------------------------------------

class TestDismiss:
    def test_dismiss_fires_dismiss_s_after_release(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm._overlay_visible = True
        sm.on_filter_event(press_event(UP_XY), now=0.0)
        sm.on_filter_event(release_event(UP_XY), now=1.0)
        assert sm.tick(now=1.0 + DISMISS_S - 0.01) == []
        actions = sm.tick(now=1.0 + DISMISS_S)
        assert kinds(actions) == [ACTION_DISMISS_OVERLAY]
        assert sm.overlay_visible is False

    def test_contact_sample_resets_dismiss_even_during_long_hold(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm._overlay_visible = True
        sm.on_filter_event(press_event(UP_XY), now=0.0)
        # Keep feeding REPEAT "heartbeats" well past the naive dismiss
        # deadline — dismiss must never fire while still held.
        t = 0.0
        for _ in range(50):
            t += 0.15
            sm.on_filter_event(repeat_event(UP_XY), now=t)
            actions = sm.tick(now=t)
            assert ACTION_DISMISS_OVERLAY not in kinds(actions)
        assert t > DISMISS_S  # proves the hold really did outlast the timer
        assert sm.overlay_visible is True

    def test_cap_starts_dismiss_clock_as_implicit_release(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm._overlay_visible = True
        sm.on_filter_event(press_event(UP_XY), now=0.0)
        sm.on_filter_event(cap_event(UP_XY), now=5.0)
        assert sm.pressed_zone is None  # no longer armed
        assert sm.tick(now=5.0 + DISMISS_S - 0.01) == []
        actions = sm.tick(now=5.0 + DISMISS_S)
        assert kinds(actions) == [ACTION_DISMISS_OVERLAY]


# ---------------------------------------------------------------------------
# set_held_visible() — the "always show controls" external sync from the
# display. held=True makes the overlay count as visible without a touch
# reveal; held=False forces the session back to hidden and drops the latch,
# mirroring force_reveal_only()'s latch handling exactly.
# ---------------------------------------------------------------------------

class TestHeldVisible:
    def test_press_while_held_arms_immediately_no_reveal(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        assert sm.set_held_visible(True, now=0.0) == []
        assert sm.held_visible is True
        assert sm.overlay_visible is True

        actions = sm.on_filter_event(press_event(UP_XY), now=0.1)
        assert kinds(actions) == [ACTION_SET_PRESSED_ZONE, ACTION_VOLUME_UP]
        assert ACTION_REVEAL_OVERLAY not in kinds(actions)
        assert kinds(actions).count(ACTION_VOLUME_UP) == 1

    def test_tick_never_dismisses_while_held(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_held_visible(True, now=0.0)
        sm.on_filter_event(press_event(UP_XY), now=0.1)
        sm.on_filter_event(release_event(UP_XY), now=0.2)

        actions = sm.tick(now=0.2 + DISMISS_S + 1.0)
        assert ACTION_DISMISS_OVERLAY not in kinds(actions)
        assert sm.overlay_visible is True

    def test_unheld_after_visible_dismisses_and_next_press_only_reveals(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_held_visible(True, now=0.0)

        actions = sm.set_held_visible(False, now=1.0)
        assert kinds(actions) == [ACTION_DISMISS_OVERLAY]
        assert sm.overlay_visible is False
        assert sm.held_visible is False

        actions = sm.on_filter_event(press_event(UP_XY), now=1.1)
        assert kinds(actions) == [ACTION_REVEAL_OVERLAY]
        assert ACTION_VOLUME_UP not in kinds(actions)

    def test_unheld_mid_press_clears_pressed_zone_stops_repeat_and_release_is_silent(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_held_visible(True, now=0.0)
        sm.on_filter_event(press_event(UP_XY), now=0.1)
        assert sm.pressed_zone == TouchZone.UP

        actions = sm.set_held_visible(False, now=0.2)
        assert kinds(actions) == [ACTION_SET_PRESSED_ZONE, ACTION_DISMISS_OVERLAY]
        assert sm.pressed_zone is None

        # No repeat fires even though FIRST_REPEAT_S has elapsed.
        actions = sm.tick(now=0.2 + FIRST_REPEAT_S + 0.01)
        assert ACTION_VOLUME_UP not in kinds(actions)

        # The finger is still down (no RELEASE delivered yet) — a later
        # RELEASE must emit nothing further (already unlit, already hidden).
        actions = sm.on_filter_event(release_event(UP_XY), now=0.5)
        assert actions == []

    def test_held_true_does_not_actuate_a_reveal_only_contact_already_down(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        # A press against a hidden overlay is reveal-only.
        sm.on_filter_event(press_event(UP_XY), now=0.0)
        assert sm.pressed_zone is None

        actions = sm.set_held_visible(True, now=0.1)
        assert actions == []
        assert sm.pressed_zone is None  # still not actuated

        sm.on_filter_event(release_event(UP_XY), now=0.2)
        actions = sm.on_filter_event(press_event(UP_XY), now=0.3)
        assert kinds(actions) == [ACTION_SET_PRESSED_ZONE, ACTION_VOLUME_UP]

    def test_mute_tap_while_held_flashes_and_clears_no_repeat(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_held_visible(True, now=0.0)

        actions = sm.on_filter_event(press_event(MUTE_XY), now=0.1)
        assert kinds(actions) == [ACTION_SET_PRESSED_ZONE, ACTION_MUTE_TOGGLE]
        assert kinds(actions).count(ACTION_MUTE_TOGGLE) == 1

        actions = sm.tick(now=0.1 + PRESSED_FLASH_S)
        assert clears_pressed(actions)

        # No repeat behaviour for MUTE, even well past FIRST_REPEAT_S.
        actions = sm.tick(now=0.1 + FIRST_REPEAT_S + 0.1)
        assert ACTION_MUTE_TOGGLE not in kinds(actions)


# ---------------------------------------------------------------------------
# TouchEventSource — fake IRQ, fake driver, fake clock
# ---------------------------------------------------------------------------

class FakeClock:
    def __init__(self, start=0.0):
        self._t = start

    def __call__(self):
        return self._t

    def advance(self, dt):
        self._t += dt


class FakeIRQ:
    """Fake gpiozero-style DigitalInputDevice: is_active + wait_for_active().

    Starts inactive; a test drives .press()/.release() to control state, and
    wait_for_active(timeout) blocks (briefly) using a real Event so the
    background thread behaves like a real blocking wait without needing
    gpiozero installed.
    """

    def __init__(self):
        self._active = threading.Event()

    @property
    def is_active(self):
        return self._active.is_set()

    def wait_for_active(self, timeout=None):
        self._active.wait(timeout=timeout)

    def press(self):
        self._active.set()

    def release(self):
        self._active.clear()


class FakeDriver:
    def __init__(self):
        self.samples: list = []
        self._i = 0

    def queue(self, *samples):
        self.samples.extend(samples)

    def read_sample(self):
        if self._i < len(self.samples):
            s = self.samples[self._i]
            self._i += 1
            return s
        return self.samples[-1] if self.samples else None


class RecordingCallbacks:
    def __init__(self):
        self.calls: list[tuple] = []

    def make(self):
        return dict(
            on_reveal_overlay=lambda: self.calls.append(("reveal",)),
            on_volume_up=lambda: self.calls.append(("volume-up",)),
            on_volume_down=lambda: self.calls.append(("volume-down",)),
            on_mute_toggle=lambda: self.calls.append(("mute",)),
            on_dismiss_overlay=lambda: self.calls.append(("dismiss",)),
            on_set_pressed_zone=lambda zone, index=None: self.calls.append(("zone", zone)),
            on_cap=lambda: self.calls.append(("cap",)),
        )


class TestTouchEventSource:
    def test_press_and_hold_produces_reveal_then_arm_actions(self):
        from dial_touch_filter import TouchFilter

        clock = FakeClock()
        irq = FakeIRQ()
        driver = FakeDriver()
        driver.queue((*UP_XY, 500))
        touch_filter = TouchFilter(WIDTH, HEIGHT, z_threshold=100)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        cb = RecordingCallbacks()

        source = TouchEventSource(
            driver, touch_filter, sm,
            clock=clock, irq=irq,
            poll_interval_s=0.001,
            idle_tick_interval_s=0.02,
            **cb.make(),
        )
        source.start()
        try:
            irq.press()
            # Give the background thread a moment to run its poll loop and
            # advance the fake clock past settle+debounce so PRESS fires.
            for _ in range(20):
                clock.advance(0.01)
                time.sleep(0.005)
            assert ("reveal",) in cb.calls
            # Reveal-only so far: the press has not armed, so nothing has
            # actuated even though the finger is on the UP zone.
            assert ("volume-up",) not in cb.calls

            # Overlay is now "live" per the display side. Reveal-only means
            # this does NOT arm the still-down press — it stays inert.
            source.overlay_live()
            assert not any(c[0] == "zone" for c in cb.calls)
            assert ("volume-up",) not in cb.calls

            # Finger lifts, then a second, deliberate press lands while the
            # overlay is visible: that one arms and actuates immediately.
            irq.release()
            for _ in range(20):
                clock.advance(0.01)
                time.sleep(0.005)

            irq.press()
            for _ in range(20):
                clock.advance(0.01)
                time.sleep(0.005)

            assert any(c[0] == "zone" for c in cb.calls)
            assert ("volume-up",) in cb.calls
        finally:
            irq.release()
            source.stop()

    def test_unknown_driver_tag_and_no_gpiozero_required(self):
        """Importing/using this module must not require gpiozero or real
        hardware at all when a fake irq/driver is supplied."""
        from dial_touch_filter import TouchFilter

        clock = FakeClock()
        irq = FakeIRQ()
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        source = TouchEventSource(driver, touch_filter, sm, clock=clock, irq=irq)
        source.start()
        source.stop(join_timeout=0.5)  # must not hang / must not import gpiozero


# ---------------------------------------------------------------------------
# force_reveal_only() — the non-composited-state (screen cleared/slept)
# force-reset. Distinct from config_changed()'s synthetic release: a
# still-down finger IS allowed to resume here, via reveal-then-arm, because
# only the on-screen geometry an armed zone was sampled against went stale —
# the physical contact itself is still a real, ongoing fact.
# ---------------------------------------------------------------------------

class TestForceRevealOnly:
    def test_drops_latch_and_stays_reveal_only_when_still_down(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm._overlay_visible = True
        sm.on_filter_event(press_event(UP_XY), now=0.0)  # already visible -> arms immediately
        assert sm.pressed_zone == TouchZone.UP

        actions = sm.force_reveal_only()
        assert actions == []
        assert sm.pressed_zone is None

        # Finger still down: overlay_live() is reveal-only like any other
        # reveal — it does NOT re-arm from the current position anymore.
        actions = sm.overlay_live(now=0.5)
        assert actions == []
        assert sm.pressed_zone is None

        # A fresh, deliberate press (overlay already visible) arms and
        # actuates immediately.
        actions = sm.on_filter_event(press_event(UP_XY), now=0.6)
        assert kinds(actions) == [ACTION_SET_PRESSED_ZONE, ACTION_VOLUME_UP]
        assert sm.pressed_zone == TouchZone.UP

    def test_falls_back_to_idle_when_finger_already_up(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm._overlay_visible = True
        sm.on_filter_event(press_event(UP_XY), now=0.0)
        sm.on_filter_event(release_event(UP_XY), now=0.2)

        sm.force_reveal_only()

        assert sm.pressed_zone is None
        # Not reveal-pending (finger already lifted) — overlay_live() is a
        # no-op, same as any other time it is called outside that phase.
        assert sm.overlay_live(now=0.5) == []


class TestIrqLifecycle:
    """The T_IRQ device must be given back when the thread ends.

    A leaked device holds the GPIO for the life of the process: stop()
    returns, but anything that later re-opens the touch stack finds the pin
    busy. Process exit hides it, which is exactly why it needs a test.
    """

    def _source(self, irq=None, make_default=None):
        src = TouchEventSource(
            driver=FakeDriver(),
            touch_filter=TouchFilter(160, 128),
            state_machine=TouchStateMachine(160, 128),
            on_reveal_overlay=lambda: None,
            on_volume_up=lambda: None,
            on_volume_down=lambda: None,
            on_mute_toggle=lambda: None,
            on_dismiss_overlay=lambda: None,
            on_set_pressed_zone=lambda z, index=None: None,
            irq=irq,
            idle_tick_interval_s=0.01,
            poll_interval_s=0.01,
        )
        if make_default is not None:
            src._make_default_irq = make_default
        return src

    def test_self_created_irq_is_closed_when_the_thread_stops(self):
        created = FakeIRQ()
        created.closed = False
        created.close = lambda: setattr(created, "closed", True)

        src = self._source(irq=None, make_default=lambda: created)
        src.start()
        time.sleep(0.05)
        src.stop()

        assert created.closed is True, "T_IRQ device leaked — GPIO stays claimed"

    def test_injected_irq_is_not_closed(self):
        """An injected device belongs to the caller; closing it here would
        release something the owner still holds."""
        injected = FakeIRQ()
        injected.closed = False
        injected.close = lambda: setattr(injected, "closed", True)

        src = self._source(irq=injected)
        src.start()
        time.sleep(0.05)
        src.stop()

        assert injected.closed is False

    def test_irq_is_closed_even_if_the_loop_raises(self):
        """Driven on this thread, not via start(): a crash in a background
        thread is reported as an unhandled-thread-exception warning rather
        than a failure, so the close must be asserted synchronously."""
        created = FakeIRQ()
        created.closed = False
        created.close = lambda: setattr(created, "closed", True)

        src = self._source(irq=None, make_default=lambda: created)
        src._stop_event = threading.Event()

        def _boom(irq):
            raise RuntimeError("boom")

        src._loop = _boom
        with pytest.raises(RuntimeError):
            src._run()

        assert created.closed is True


class TestTouchEventSourceNoncompositedPolling:
    def test_poll_noncomposited_dispatches_force_reveal_only_on_generation_change(self):
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm._overlay_visible = True
        sm.on_filter_event(press_event(UP_XY), now=0.0)
        assert sm.pressed_zone == TouchZone.UP

        gens = iter([0, 0, 1, 1])
        source = TouchEventSource(
            driver, touch_filter, sm,
            get_noncomposited_generation=lambda: next(gens),
        )

        source._poll_noncomposited()  # first call only records the baseline (0)
        assert sm.pressed_zone == TouchZone.UP

        source._poll_noncomposited()  # unchanged (0 -> 0)
        assert sm.pressed_zone == TouchZone.UP

        source._poll_noncomposited()  # changed (0 -> 1) -> force-reset
        assert sm.pressed_zone is None

    def test_no_getter_injected_is_a_no_op(self):
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm._overlay_visible = True
        sm.on_filter_event(press_event(UP_XY), now=0.0)

        source = TouchEventSource(driver, touch_filter, sm)
        source._poll_noncomposited()  # must not raise, must not change anything
        assert sm.pressed_zone == TouchZone.UP

    def test_generation_change_forces_reveal_only_via_running_thread(self):
        """End-to-end through the real background loop, not just the direct
        _poll_noncomposited() call above."""
        from dial_touch_filter import TouchFilter as _TF

        clock = FakeClock()
        irq = FakeIRQ()
        driver = FakeDriver()
        touch_filter = _TF(WIDTH, HEIGHT, z_threshold=100)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm._overlay_visible = True
        sm.on_filter_event(press_event(UP_XY), now=0.0)
        assert sm.pressed_zone == TouchZone.UP

        gen = {"n": 0}
        source = TouchEventSource(
            driver, touch_filter, sm,
            clock=clock, irq=irq,
            poll_interval_s=0.001, idle_tick_interval_s=0.02,
            get_noncomposited_generation=lambda: gen["n"],
        )
        source.start()
        try:
            gen["n"] += 1  # simulate the display clearing/sleeping
            deadline = time.time() + 1.0
            while time.time() < deadline and sm.pressed_zone is not None:
                time.sleep(0.01)
            assert sm.pressed_zone is None
        finally:
            irq.release()
            source.stop()


class TestTouchEventSourceHeldPolling:
    def test_getter_changes_drive_set_held_visible_on_change_only(self):
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)

        values = iter([False, False, True, True, False])
        source = TouchEventSource(
            driver, touch_filter, sm,
            get_persistent_overlay=lambda: next(values),
        )

        source._poll_held_visible()  # False -> baseline, not held
        assert sm.held_visible is False

        source._poll_held_visible()  # False -> False, no change
        assert sm.held_visible is False

        source._poll_held_visible()  # False -> True
        assert sm.held_visible is True
        assert sm.overlay_visible is True

        source._poll_held_visible()  # True -> True, no change
        assert sm.held_visible is True

        source._poll_held_visible()  # True -> False
        assert sm.held_visible is False
        assert sm.overlay_visible is False

    def test_raising_getter_is_treated_as_false(self):
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_held_visible(True, now=0.0)
        assert sm.held_visible is True

        def boom():
            raise RuntimeError("display gone")

        source = TouchEventSource(
            driver, touch_filter, sm, get_persistent_overlay=boom,
        )
        source._poll_held_visible()
        assert sm.held_visible is False

    def test_no_getter_injected_is_a_no_op(self):
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        source = TouchEventSource(driver, touch_filter, sm)
        source._poll_held_visible()  # must not raise, must not change anything
        assert sm.held_visible is False


# ---------------------------------------------------------------------------
# overlay_hidden() — the display took the touch-revealed overlay down itself
# (an artwork tap hid the controls): the session must count the overlay as
# hidden at once, so a finger never arms against bands that are gone.
# ---------------------------------------------------------------------------


class TestOverlayHidden:
    def _revealed(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_HIDDEN, True, now=0.0)
        sm._overlay_visible = True
        return sm

    def test_visible_and_not_held_dismisses(self):
        sm = self._revealed()
        sm._dismiss_deadline = 5.0
        actions = sm.overlay_hidden(now=1.0)
        assert kinds(actions) == [ACTION_DISMISS_OVERLAY]
        assert sm.overlay_visible is False
        assert sm._dismiss_deadline is None
        assert sm._phase == "idle"

    def test_lit_zone_is_cleared_first(self):
        sm = self._revealed()
        sm.on_filter_event(press_event(ARTWORK_XY), now=0.0)
        assert sm.pressed_zone == TouchZone.ARTWORK
        actions = sm.overlay_hidden(now=0.05)
        assert actions == [
            TouchAction(ACTION_SET_PRESSED_ZONE, None),
            TouchAction(ACTION_DISMISS_OVERLAY),
        ]
        assert sm.pressed_zone is None
        # The flash's own clear no longer fires.
        assert sm.tick(now=PRESSED_FLASH_S) == []

    def test_held_is_a_noop(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_held_visible(True, now=0.0)
        assert sm.overlay_hidden(now=1.0) == []
        assert sm.overlay_visible is True
        assert sm.held_visible is True

    def test_not_visible_is_a_noop(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        assert sm.overlay_hidden(now=1.0) == []

    def test_contact_down_falls_back_to_reveal_pending_and_next_press_reveals(self):
        sm = self._revealed()
        sm.on_filter_event(press_event(ARTWORK_XY), now=0.0)
        sm.overlay_hidden(now=0.05)
        assert sm._phase == "reveal_pending"
        sm.on_filter_event(release_event(ARTWORK_XY), now=0.1)
        actions = sm.on_filter_event(press_event(UP_XY), now=0.2)
        assert kinds(actions) == [ACTION_REVEAL_OVERLAY]
        assert ACTION_VOLUME_UP not in kinds(actions)

    def test_event_source_dispatches_the_actions(self):
        sm = self._revealed()
        sm.on_filter_event(press_event(ARTWORK_XY), now=0.0)
        calls = []
        source = TouchEventSource(
            FakeDriver(), TouchFilter(WIDTH, HEIGHT), sm,
            on_dismiss_overlay=lambda: calls.append("dismiss"),
            on_set_pressed_zone=lambda zone, index: calls.append(("pressed", zone)),
            clock=lambda: 0.05,
        )
        source.overlay_hidden()
        assert calls == [("pressed", None), "dismiss"]


# ---------------------------------------------------------------------------
# config_changed() — a live screen settings change (e.g. screen_type, which
# can move zone boundaries outright). Stricter than force_reveal_only(): a
# still-down finger must NOT be allowed to resume at all, only a fresh
# touch-down (real release-then-recontact through the filter).
# ---------------------------------------------------------------------------

class TestConfigChanged:
    def test_delivers_synthetic_release_and_clears_latch(self):
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm._overlay_visible = True
        sm.on_filter_event(press_event(UP_XY), now=0.0)
        assert sm.pressed_zone == TouchZone.UP

        source = TouchEventSource(driver, touch_filter, sm, clock=lambda: 1.0)
        source.config_changed()

        assert sm.pressed_zone is None

    def test_still_down_finger_cannot_resume_without_fresh_touch_down(self):
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm._overlay_visible = True
        sm.on_filter_event(press_event(UP_XY), now=0.0)

        source = TouchEventSource(driver, touch_filter, sm, clock=lambda: 1.0)
        source.config_changed()
        assert sm.pressed_zone is None

        # Finger still physically down: a real driver/filter would only ever
        # emit REPEAT (not a new PRESS) until an actual release+recontact.
        # Feeding a REPEAT straight to the (now IDLE) state machine must do
        # nothing.
        actions = sm.on_filter_event(repeat_event(UP_XY), now=1.1)
        assert actions == []
        assert sm.pressed_zone is None

        # Only a fresh PRESS (a real release-then-recontact) re-arms.
        actions = sm.on_filter_event(press_event(UP_XY), now=2.0)
        assert kinds(actions) == [ACTION_SET_PRESSED_ZONE, ACTION_VOLUME_UP]
        assert sm.pressed_zone == TouchZone.UP


# ---------------------------------------------------------------------------
# PRESSED HIGHLIGHT — UP/DOWN stay lit until release; MUTE self-clears after
# PRESSED_FLASH_S even with the finger still down.
# ---------------------------------------------------------------------------

class TestPressedHighlight:
    @pytest.mark.parametrize(
        "zone_xy,action_kind",
        [(UP_XY, ACTION_VOLUME_UP), (DOWN_XY, ACTION_VOLUME_DOWN)],
    )
    def test_repeating_zone_stays_lit_while_held_and_clears_only_on_release(
        self, zone_xy, action_kind
    ):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm._overlay_visible = True
        actions = sm.on_filter_event(press_event(zone_xy), now=0.0)
        assert kinds(actions) == [ACTION_SET_PRESSED_ZONE, action_kind]

        # Hold well past PRESSED_FLASH_S (and past a couple of repeats) —
        # a repeating zone must never self-clear while still down.
        t = 0.0
        for _ in range(6):
            t += PRESSED_FLASH_S
            actions = sm.tick(now=t)
            assert not clears_pressed(actions)
        assert t > PRESSED_FLASH_S * 4

        actions = sm.on_filter_event(release_event(zone_xy), now=t)
        assert kinds(actions).count(ACTION_SET_PRESSED_ZONE) == 1
        assert clears_pressed(actions)
        assert sm.pressed_zone is None

    def test_mute_self_clears_after_flash_even_with_finger_still_down(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm._overlay_visible = True
        actions = sm.on_filter_event(press_event(MUTE_XY), now=0.0)
        assert kinds(actions) == [ACTION_SET_PRESSED_ZONE, ACTION_MUTE_TOGGLE]
        assert sm.pressed_zone == TouchZone.MUTE

        # Not due yet just before the flash deadline.
        actions = sm.tick(now=PRESSED_FLASH_S - 0.01)
        assert not clears_pressed(actions)
        assert sm.pressed_zone == TouchZone.MUTE

        # Due at the flash deadline, finger still down.
        actions = sm.tick(now=PRESSED_FLASH_S)
        assert clears_pressed(actions)
        assert sm.pressed_zone is None

        # Later contact/ticks must not re-light it.
        sm.on_filter_event(repeat_event(MUTE_XY), now=PRESSED_FLASH_S + 0.1)
        actions = sm.tick(now=PRESSED_FLASH_S + 1.0)
        assert not clears_pressed(actions)  # nothing left to clear
        assert sm.pressed_zone is None

    def test_short_tap_clears_highlight_exactly_once(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm._overlay_visible = True
        sm.on_filter_event(press_event(MUTE_XY), now=0.0)

        # Released well before PRESSED_FLASH_S.
        actions = sm.on_filter_event(release_event(MUTE_XY), now=0.05)
        assert kinds(actions).count(ACTION_SET_PRESSED_ZONE) == 1
        assert clears_pressed(actions)
        assert sm.pressed_zone is None

        # A later tick at what would have been the flash deadline must not
        # emit a second clear — release already cancelled the flash timer.
        actions = sm.tick(now=PRESSED_FLASH_S)
        assert not clears_pressed(actions)

    def test_force_reveal_only_clears_lit_state(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm._overlay_visible = True
        sm.on_filter_event(press_event(UP_XY), now=0.0)
        assert sm.pressed_zone == TouchZone.UP

        sm.force_reveal_only()
        assert sm.pressed_zone is None
        # And it must not spontaneously reappear on a later tick.
        assert not clears_pressed(sm.tick(now=10.0))


# ---------------------------------------------------------------------------
# display_config_changed() — live rotate toggle re-derives the filter's axis
# transform from the profile's UNROTATED signs, XORing in the rotate flag,
# then delivers the same synthetic release as config_changed().
# ---------------------------------------------------------------------------

class FakeAxisFilter:
    """Spy standing in for TouchFilter: records set_axis_transform() calls
    without needing a real filter/feed() pipeline."""

    def __init__(self):
        self.calls: list[tuple[bool, bool, bool]] = []

    def set_axis_transform(self, *, swap_xy, invert_x, invert_y):
        self.calls.append((swap_xy, invert_x, invert_y))


class TestDisplayConfigChanged:
    def test_rotate_true_xors_invert_signs(self):
        driver = FakeDriver()
        touch_filter = FakeAxisFilter()
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm._overlay_visible = True
        sm.on_filter_event(press_event(UP_XY), now=0.0)
        assert sm.pressed_zone == TouchZone.UP

        source = TouchEventSource(
            driver, touch_filter, sm, clock=lambda: 1.0,
            axis_signs=(True, False, True),  # swap, invert_x, invert_y (unrotated)
        )
        source.display_config_changed(rotate=True)

        # invert_x/invert_y each XORed with rotate=True; swap is untouched.
        assert touch_filter.calls == [(True, True, False)]
        # Synthetic release still delivered.
        assert sm.pressed_zone is None

    def test_rotate_false_keeps_signs_unchanged(self):
        driver = FakeDriver()
        touch_filter = FakeAxisFilter()
        sm = TouchStateMachine(WIDTH, HEIGHT)

        source = TouchEventSource(
            driver, touch_filter, sm, clock=lambda: 1.0,
            axis_signs=(True, False, True),
        )
        source.display_config_changed(rotate=False)

        assert touch_filter.calls == [(True, False, True)]

    def test_no_axis_signs_is_a_safe_noop_on_transform(self):
        driver = FakeDriver()
        touch_filter = FakeAxisFilter()
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm._overlay_visible = True
        sm.on_filter_event(press_event(UP_XY), now=0.0)
        assert sm.pressed_zone == TouchZone.UP

        # axis_signs defaults to None.
        source = TouchEventSource(driver, touch_filter, sm, clock=lambda: 1.0)
        source.display_config_changed(rotate=True)

        assert touch_filter.calls == []  # transform left untouched
        # The synthetic release is still delivered regardless.
        assert sm.pressed_zone is None


# ---------------------------------------------------------------------------
# set_geometry() — a live layout-size change replaces the hit-test size and
# metrics together.
# ---------------------------------------------------------------------------

class TestSetGeometry:
    def test_stale_geometry_press_misses_and_new_geometry_press_hits(self):
        metrics_640 = metrics_for(640, 480, mm_per_px=0.0889, size_chosen=True)
        up_640 = layout_for(640, 480, metrics_640).footer_up
        up_xy_640 = ((up_640[0] + up_640[2]) // 2, (up_640[1] + up_640[3]) // 2)

        sm = TouchStateMachine(640, 480, metrics=metrics_640)
        sm.set_geometry(160, 128, metrics_for(160, 128))
        sm._overlay_visible = True

        # The old (640x480) UP centre no longer means anything against the
        # new 160x128 geometry — it lands outside the panel or in a dead
        # zone, either way nothing arms.
        sm.on_filter_event(press_event(up_xy_640), now=0.0)
        assert sm.pressed_zone is None

        base_metrics = metrics_for(160, 128)
        up_160 = layout_for(160, 128, base_metrics).footer_up
        up_xy_160 = ((up_160[0] + up_160[2]) // 2, (up_160[1] + up_160[3]) // 2)
        sm.on_filter_event(press_event(up_xy_160), now=0.1)
        assert sm.pressed_zone == TouchZone.UP


# ---------------------------------------------------------------------------
# A physical touch reading, scaled from the panel's physical pixel size to
# the logical size a layout-size setting composes/hit-tests in, must land on
# the same logical zone a press expressed directly in logical coordinates
# does — geometry single source, end to end.
# ---------------------------------------------------------------------------

class TestPhysicalToLogicalRoundTrip:
    def test_physical_tap_maps_to_the_same_logical_hit(self):
        from dial_touch_filter import TouchFilter as _RealTouchFilter

        metrics = metrics_for(640, 480, mm_per_px=0.0889, size_chosen=True)
        down = layout_for(640, 480, metrics).down
        cx = (down[0] + down[2]) // 2
        cy = (down[1] + down[3]) // 2

        sm = TouchStateMachine(640, 480, metrics=metrics)
        sm._overlay_visible = True
        sm.on_filter_event(press_event((cx, cy)), now=0.0)
        assert sm.pressed_zone == TouchZone.DOWN

        # The physical panel is half the logical size on each axis (320x240
        # under 640x480 logical) — the physical point (cx // 2, cy // 2)
        # through the capacitive remap must land back in the same logical
        # zone (an odd centre coordinate can round to an adjacent pixel
        # under integer halving, so the zone is what round-trips exactly,
        # not necessarily the single pixel).
        f = _RealTouchFilter(640, 480, physical_size=(320, 240))
        mapped = f._to_panel_xy(cx // 2, cy // 2)
        hit = hit_test(GEOMETRY_MAIN, mapped[0], mapped[1], 640, 480, metrics=metrics)
        assert hit is not None and hit.zone == TouchZone.DOWN


# ---------------------------------------------------------------------------
# display_config_changed(rotate, layout=...) — the live layout-size remap:
# axis transform, then the filter's logical size, then the machine's
# geometry, then the synthetic release, in that order.
# ---------------------------------------------------------------------------

class FakeGeometryFilter:
    """Spy filter exposing both set_axis_transform() and set_logical_size(),
    recording the order display_config_changed() calls them in."""

    def __init__(self):
        self.calls: list[str] = []

    def set_axis_transform(self, *, swap_xy, invert_x, invert_y):
        self.calls.append("axis")

    def set_logical_size(self, width, height, *, physical_size=None):
        self.calls.append("size")


class FakeGeometryMachine:
    """Spy state machine recording set_geometry()/on_filter_event() order —
    stands in for TouchStateMachine so display_config_changed()'s dispatch
    order can be pinned without a real hit-test."""

    def __init__(self):
        self.calls: list[str] = []

    def set_geometry(self, width, height, metrics):
        self.calls.append("geometry")

    def on_filter_event(self, event, now):
        self.calls.append("release")
        return []


class TestDisplayConfigChangedWithLayout:
    def test_order_is_axis_then_size_then_geometry_then_release(self):
        from dial_display_profiles import LayoutContext

        driver = FakeDriver()
        touch_filter = FakeGeometryFilter()
        sm = FakeGeometryMachine()
        source = TouchEventSource(
            driver, touch_filter, sm, clock=lambda: 1.0, axis_signs=(False, False, False),
        )
        ctx = LayoutContext(
            logical_width=640, logical_height=480, physical_width=320, physical_height=240,
            mm_per_px=0.0889, size_chosen=True,
        )
        source.display_config_changed(False, layout=ctx)
        assert touch_filter.calls == ["axis", "size"]
        assert sm.calls == ["geometry", "release"]

    def test_no_layout_keeps_existing_three_tests_unchanged(self):
        """display_config_changed() without layout= must behave exactly as
        it did before this keyword existed (see TestDisplayConfigChanged
        above) — this is a direct pin of that claim against the spy."""
        driver = FakeDriver()
        touch_filter = FakeGeometryFilter()
        sm = FakeGeometryMachine()
        source = TouchEventSource(
            driver, touch_filter, sm, clock=lambda: 1.0, axis_signs=(False, False, False),
        )
        source.display_config_changed(False)
        assert touch_filter.calls == ["axis"]  # set_logical_size never called
        assert sm.calls == ["release"]  # set_geometry never called

    def test_filter_lacking_set_logical_size_is_skipped_silently(self):
        from dial_display_profiles import LayoutContext

        driver = FakeDriver()
        touch_filter = FakeAxisFilter()  # no set_logical_size on this spy
        sm = FakeGeometryMachine()
        source = TouchEventSource(
            driver, touch_filter, sm, clock=lambda: 1.0, axis_signs=(False, False, False),
        )
        ctx = LayoutContext(
            logical_width=320, logical_height=240, physical_width=160, physical_height=128,
            mm_per_px=0.1143, size_chosen=True,
        )
        source.display_config_changed(False, layout=ctx)  # must not raise
        assert touch_filter.calls == [(False, False, False)]
        assert sm.calls == ["geometry", "release"]


# ---------------------------------------------------------------------------
# set_surface() — surface-aware hit-test (the selector screen) and the
# single-shot ACTION_ZONE_TAP zones (NAME, LIST_*).
# ---------------------------------------------------------------------------

_LIST_LAYOUT = list_layout_for(WIDTH, HEIGHT)


def _list_row_center(i: int) -> tuple[int, int]:
    x0, y0, x1, y1 = _LIST_LAYOUT.rows[i]
    return ((x0 + x1) // 2, (y0 + y1) // 2)


def _list_bar_center(rect) -> tuple[int, int]:
    x0, y0, x1, y1 = rect
    return ((x0 + x1) // 2, (y0 + y1) // 2)


LIST_ROW0_XY = _list_row_center(0)
LIST_BACK_XY = _list_bar_center(_LIST_LAYOUT.back)
LIST_DOWN_XY = _list_bar_center(_LIST_LAYOUT.down)
LIST_UP_XY = _list_bar_center(_LIST_LAYOUT.up)
NAME_XY = (lambda r: ((r[0] + r[2]) // 2, (r[1] + r[3]) // 2))(zones_for(WIDTH, HEIGHT)[TouchZone.NAME])
ARTWORK_XY = (lambda r: ((r[0] + r[2]) // 2, (r[1] + r[3]) // 2))(zones_for(WIDTH, HEIGHT)[TouchZone.ARTWORK])


class TestSetSurface:
    def test_same_surface_is_a_noop_but_updates_name_active(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        assert sm.set_surface(SURFACE_HIDDEN, False, now=0.0) == []
        assert sm.surface == SURFACE_HIDDEN
        # A same-surface call updates name_active without touching anything
        # else — provable by then arming NAME successfully.
        sm._overlay_visible = True
        assert sm.set_surface(SURFACE_HIDDEN, True, now=0.0) == []
        actions = sm.on_filter_event(press_event(NAME_XY), now=0.1)
        assert any(a.kind == ACTION_ZONE_TAP for a in actions)

    def test_selector_surface_arms_immediately_without_reveal(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_SELECTOR, False, now=0.0)
        actions = sm.on_filter_event(press_event(LIST_ROW0_XY), now=0.1)
        assert kinds(actions) == [ACTION_SET_PRESSED_ZONE, ACTION_ZONE_TAP]

    def test_list_row_tap_reports_its_index(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_SELECTOR, False, now=0.0)
        actions = sm.on_filter_event(press_event(_list_row_center(2)), now=0.1)
        tap = next(a for a in actions if a.kind == ACTION_ZONE_TAP)
        assert tap.zone == TouchZone.LIST_ROW
        assert tap.index == 2

    def test_list_back_down_up_taps(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_SELECTOR, False, now=0.0)
        for xy, expected_zone in (
            (LIST_BACK_XY, TouchZone.LIST_BACK),
            (LIST_DOWN_XY, TouchZone.LIST_DOWN),
            (LIST_UP_XY, TouchZone.LIST_UP),
        ):
            sm.on_filter_event(release_event(), now=0.0)
            actions = sm.on_filter_event(press_event(xy), now=0.1)
            tap = next(a for a in actions if a.kind == ACTION_ZONE_TAP)
            assert tap.zone == expected_zone
            assert tap.index is None

    def test_list_tap_is_single_shot_no_repeat(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_SELECTOR, False, now=0.0)
        sm.on_filter_event(press_event(LIST_ROW0_XY), now=0.0)
        assert sm.pressed_zone == TouchZone.LIST_ROW
        # The flash clears itself; no ACTION_ZONE_TAP is re-emitted by tick().
        actions = sm.tick(now=PRESSED_FLASH_S)
        assert actions == [TouchAction(ACTION_SET_PRESSED_ZONE, None)]
        actions = sm.tick(now=FIRST_REPEAT_S + 1.0)
        assert actions == []

    def test_name_zone_inactive_when_name_active_false(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_HIDDEN, False, now=0.0)
        sm._overlay_visible = True
        actions = sm.on_filter_event(press_event(NAME_XY), now=0.0)
        assert actions == []  # dead zone: name_active is False

    def test_name_zone_active_emits_zone_tap(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_HIDDEN, True, now=0.0)
        sm._overlay_visible = True
        actions = sm.on_filter_event(press_event(NAME_XY), now=0.0)
        assert kinds(actions) == [ACTION_SET_PRESSED_ZONE, ACTION_ZONE_TAP]
        tap = next(a for a in actions if a.kind == ACTION_ZONE_TAP)
        assert tap.zone == TouchZone.NAME
        assert tap.index is None

    def test_artwork_tap_emits_zone_tap(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_HIDDEN, True, now=0.0)
        sm._overlay_visible = True
        actions = sm.on_filter_event(press_event(ARTWORK_XY), now=0.0)
        assert kinds(actions) == [ACTION_SET_PRESSED_ZONE, ACTION_ZONE_TAP]
        tap = next(a for a in actions if a.kind == ACTION_ZONE_TAP)
        assert tap.zone == TouchZone.ARTWORK
        assert tap.index is None

    def test_artwork_tap_is_single_shot_no_repeat(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_HIDDEN, True, now=0.0)
        sm._overlay_visible = True
        sm.on_filter_event(press_event(ARTWORK_XY), now=0.0)
        assert sm.pressed_zone == TouchZone.ARTWORK
        actions = sm.tick(now=PRESSED_FLASH_S)
        assert actions == [TouchAction(ACTION_SET_PRESSED_ZONE, None)]
        actions = sm.tick(now=FIRST_REPEAT_S + 1.0)
        assert actions == []

    def test_surface_change_with_finger_down_drops_the_latch(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_SELECTOR, False, now=0.0)
        sm.on_filter_event(press_event(LIST_ROW0_XY), now=0.0)
        assert sm.pressed_zone == TouchZone.LIST_ROW

        actions = sm.set_surface(SURFACE_HIDDEN, False, now=0.1)
        assert sm.pressed_zone is None
        assert any(a.kind == ACTION_SET_PRESSED_ZONE and a.zone is None for a in actions)

    def test_change_to_hidden_emits_dismiss(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_HELD, False, now=0.0)
        assert sm.overlay_visible is True
        actions = sm.set_surface(SURFACE_HIDDEN, False, now=0.1)
        assert any(a.kind == ACTION_DISMISS_OVERLAY for a in actions)
        assert sm.overlay_visible is False

    def test_change_to_held_or_selector_counts_as_visible(self):
        for target in (SURFACE_HELD, SURFACE_SELECTOR):
            sm = TouchStateMachine(WIDTH, HEIGHT)
            sm.set_surface(target, False, now=0.0)
            assert sm.overlay_visible is True
            assert sm.held_visible is True

    def test_dismiss_clock_disabled_on_selector(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_SELECTOR, False, now=0.0)
        sm.on_filter_event(press_event(LIST_ROW0_XY), now=0.0)
        sm.on_filter_event(release_event(), now=0.05)
        # Held (selector counts as held) disables the dismiss clock in
        # tick() — far past DISMISS_S, the overlay stays "visible".
        actions = sm.tick(now=DISMISS_S * 10)
        assert not any(a.kind == ACTION_DISMISS_OVERLAY for a in actions)
        assert sm.overlay_visible is True


class TestTouchEventSourceSurfacePolling:
    def test_getter_changes_drive_set_surface_on_change_only(self):
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)

        values = iter([
            (SURFACE_HIDDEN, False),
            (SURFACE_HIDDEN, False),
            (SURFACE_SELECTOR, False),
            (SURFACE_SELECTOR, False),
            (SURFACE_HIDDEN, False),
        ])
        source = TouchEventSource(
            driver, touch_filter, sm,
            get_touch_surface=lambda: next(values),
        )

        source._poll_surface()  # baseline
        assert sm.surface == SURFACE_HIDDEN

        source._poll_surface()  # unchanged
        assert sm.surface == SURFACE_HIDDEN

        source._poll_surface()  # -> selector
        assert sm.surface == SURFACE_SELECTOR

        source._poll_surface()  # unchanged
        assert sm.surface == SURFACE_SELECTOR

        source._poll_surface()  # -> hidden
        assert sm.surface == SURFACE_HIDDEN

    def test_raising_get_touch_surface_is_treated_as_hidden(self):
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_SELECTOR, False, now=0.0)

        def boom():
            raise RuntimeError("display gone")

        source = TouchEventSource(driver, touch_filter, sm, get_touch_surface=boom)
        source._poll_surface()
        assert sm.surface == SURFACE_HIDDEN

    def test_legacy_get_persistent_overlay_only_still_behaves_exactly_as_before(self):
        """get_touch_surface omitted entirely: _poll_surface() must fall
        back to the untouched legacy _poll_held_visible() path, so existing
        held/hidden-only wiring (dial_main.py, pre-selector) keeps working
        byte for byte."""
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)

        values = iter([False, True, False])
        source = TouchEventSource(
            driver, touch_filter, sm,
            get_persistent_overlay=lambda: next(values),
        )
        # The legacy path drives held_visible directly via
        # set_held_visible() — it never touches surface at all, which is
        # exactly the "byte for byte" guarantee: existing wiring that only
        # ever polled get_persistent_overlay must see no new behaviour.
        source._poll_surface()
        assert sm.held_visible is False
        source._poll_surface()
        assert sm.held_visible is True
        source._poll_surface()
        assert sm.held_visible is False

    def test_no_getter_at_all_is_a_no_op(self):
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        source = TouchEventSource(driver, touch_filter, sm)
        source._poll_surface()  # must not raise, must not change anything
        assert sm.surface == SURFACE_HIDDEN
        assert sm.held_visible is False


class TestZoneTapDispatch:
    def test_on_zone_tap_receives_zone_and_index(self):
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_SELECTOR, False, now=0.0)

        calls = []
        source = TouchEventSource(
            driver, touch_filter, sm,
            on_zone_tap=lambda zone, index: calls.append((zone, index)),
        )
        source._dispatch(sm.on_filter_event(press_event(_list_row_center(1)), now=0.0))
        assert calls == [(TouchZone.LIST_ROW, 1)]

    def test_no_callback_injected_is_a_safe_noop(self):
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_SELECTOR, False, now=0.0)
        source = TouchEventSource(driver, touch_filter, sm)
        # Must not raise even though on_zone_tap was never supplied.
        source._dispatch(sm.on_filter_event(press_event(LIST_ROW0_XY), now=0.0))


class TestSetPressedZoneDispatch:
    """on_set_pressed_zone(zone, index) carries the row index on the wire
    for LIST_ROW, exactly like on_zone_tap already does — every other zone,
    and the flash-clear, always pass index=None."""

    def test_arming_a_list_row_dispatches_its_index(self):
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_SELECTOR, False, now=0.0)

        calls = []
        source = TouchEventSource(
            driver, touch_filter, sm,
            on_set_pressed_zone=lambda zone, index=None: calls.append((zone, index)),
        )
        source._dispatch(sm.on_filter_event(press_event(_list_row_center(2)), now=0.0))
        assert (TouchZone.LIST_ROW, 2) in calls

    def test_arming_down_dispatches_no_index(self):
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm._overlay_visible = True

        calls = []
        source = TouchEventSource(
            driver, touch_filter, sm,
            on_set_pressed_zone=lambda zone, index=None: calls.append((zone, index)),
        )
        source._dispatch(sm.on_filter_event(press_event(DOWN_XY), now=0.0))
        assert (TouchZone.DOWN, None) in calls

    def test_the_flash_clear_dispatches_no_index(self):
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_SELECTOR, False, now=0.0)
        sm.on_filter_event(press_event(LIST_ROW0_XY), now=0.0)

        calls = []
        source = TouchEventSource(
            driver, touch_filter, sm,
            on_set_pressed_zone=lambda zone, index=None: calls.append((zone, index)),
        )
        source._dispatch(sm.tick(now=PRESSED_FLASH_S))
        assert (None, None) in calls


# ---------------------------------------------------------------------------
# The REPEAT, IDLE and PICKER surfaces; DOTS/NAME gating; the new zones'
# single-shot/zone-tap behaviour; touch_surface() 2- and 3-tuple polling.
# ---------------------------------------------------------------------------

_REPEAT_LAYOUT = repeat_layout_for(WIDTH, HEIGHT)


def _rect_center(rect) -> tuple[int, int]:
    x0, y0, x1, y1 = rect
    return ((x0 + x1) // 2, (y0 + y1) // 2)


DOTS_XY = _rect_center(zones_for(WIDTH, HEIGHT)[TouchZone.DOTS])
NAME_XY = _rect_center(zones_for(WIDTH, HEIGHT)[TouchZone.NAME])
REPEAT_PLAY_XY = _rect_center(_REPEAT_LAYOUT.row)
REPEAT_START_XY = _rect_center(_REPEAT_LAYOUT.start)
REPEAT_STOP_XY = _rect_center(_REPEAT_LAYOUT.stop)
# The repeat screen's own OUTPUTS zone is the volume_cluster readout
# (top-right, unchanged) — NOT the main surface's MUTE_XY, which lands in
# the main screen's own three-way footer cell; the repeat screen has no
# mute control of its own.
REPEAT_OUTPUTS_XY = _rect_center(_REPEAT_LAYOUT.volume_cluster)
IDLE_XY = (WIDTH // 2, HEIGHT - 1)
IDLE_INFO_XY = _rect_center(idle_layout_for(WIDTH, HEIGHT).info)
IDLE_WIFI_XY = _rect_center(idle_layout_for(WIDTH, HEIGHT).wifi)


class TestNewSurfacesArmImmediately:
    """SURFACE_REPEAT, SURFACE_IDLE and SURFACE_PICKER all behave as
    "held": a press arms immediately, no reveal step, no dismiss clock —
    the same contract SURFACE_SELECTOR already has."""

    @pytest.mark.parametrize("surface", [SURFACE_REPEAT, SURFACE_IDLE, SURFACE_PICKER, SURFACE_INFO])
    def test_surface_counts_as_visible_and_held(self, surface):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(surface, False, now=0.0, dots_active=True)
        assert sm.overlay_visible is True
        assert sm.held_visible is True

    def test_repeat_play_arms_immediately_without_reveal(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_REPEAT, False, now=0.0)
        actions = sm.on_filter_event(press_event(REPEAT_PLAY_XY), now=0.1)
        assert kinds(actions) == [ACTION_SET_PRESSED_ZONE, ACTION_ZONE_TAP]

    def test_outputs_zone_opens_outputs_list_on_the_repeat_surface(self):
        # The repeat screen's own top-right readout opens the outputs list,
        # same as main -- it has no mute control of its own.
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_REPEAT, False, now=0.0, outputs_active=True)
        actions = sm.on_filter_event(press_event(REPEAT_OUTPUTS_XY), now=0.1)
        assert kinds(actions) == [ACTION_SET_PRESSED_ZONE, ACTION_ZONE_TAP]
        tap = next(a for a in actions if a.kind == ACTION_ZONE_TAP)
        assert tap.zone == TouchZone.OUTPUTS

    def test_outputs_zone_dead_on_the_repeat_surface_when_unavailable(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_REPEAT, False, now=0.0, outputs_active=False)
        actions = sm.on_filter_event(press_event(REPEAT_OUTPUTS_XY), now=0.1)
        assert actions == []

    def test_idle_replay_arms_immediately_without_reveal(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_IDLE, False, now=0.0)
        actions = sm.on_filter_event(press_event(IDLE_XY), now=0.1)
        assert kinds(actions) == [ACTION_SET_PRESSED_ZONE, ACTION_ZONE_TAP]

    def test_idle_info_arms_immediately_without_reveal(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_IDLE, False, now=0.0)
        actions = sm.on_filter_event(press_event(IDLE_INFO_XY), now=0.1)
        assert kinds(actions) == [ACTION_SET_PRESSED_ZONE, ACTION_ZONE_TAP]

    def test_idle_wifi_arms_immediately_without_reveal(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_IDLE, False, now=0.0)
        actions = sm.on_filter_event(press_event(IDLE_WIFI_XY), now=0.1)
        assert kinds(actions) == [ACTION_SET_PRESSED_ZONE, ACTION_ZONE_TAP]
        tap = next(a for a in actions if a.kind == ACTION_ZONE_TAP)
        assert tap.zone == TouchZone.IDLE_WIFI

    def test_picker_row_arms_immediately_without_reveal(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_PICKER, False, now=0.0)
        actions = sm.on_filter_event(press_event(LIST_ROW0_XY), now=0.1)
        assert kinds(actions) == [ACTION_SET_PRESSED_ZONE, ACTION_ZONE_TAP]

    def test_picker_list_row_reports_its_index(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_PICKER, False, now=0.0)
        actions = sm.on_filter_event(press_event(_list_row_center(2)), now=0.1)
        tap = next(a for a in actions if a.kind == ACTION_ZONE_TAP)
        assert tap.zone == TouchZone.LIST_ROW
        assert tap.index == 2

    def test_dismiss_clock_disabled_on_repeat_and_idle(self):
        for surface in (SURFACE_REPEAT, SURFACE_IDLE):
            sm = TouchStateMachine(WIDTH, HEIGHT)
            sm.set_surface(surface, False, now=0.0)
            actions = sm.tick(now=DISMISS_S * 10)
            assert not any(a.kind == ACTION_DISMISS_OVERLAY for a in actions)
            assert sm.overlay_visible is True


class TestInfoSurface:
    """SURFACE_INFO: the idle screen's own read-only info page. Held like
    every other list surface (see TestNewSurfacesArmImmediately's own
    SURFACE_INFO cases). Off the compact tier its own geometry (GEOMETRY_
    INFO) carries no LIST_ROW entries at all — a tap in a row cell lands in
    no zone; on the compact tier the rows ARE tappable, opening the compact
    info page's own drill-in (SURFACE_INFO_VALUE, below)."""

    def test_maps_to_geometry_info(self):
        assert _GEOMETRY_FOR_SURFACE[SURFACE_INFO] == GEOMETRY_INFO

    def test_row_press_produces_no_action_off_compact(self):
        # WIDTH/HEIGHT (160x128) is a base-tier fixture, never compact.
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_INFO, False, now=0.0)
        actions = sm.on_filter_event(press_event(LIST_ROW0_XY), now=0.1)
        assert actions == []
        assert sm.pressed_zone is None

    def test_back_and_down_still_resolve(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_INFO, False, now=0.0)
        actions = sm.on_filter_event(press_event(LIST_BACK_XY), now=0.1)
        tap = next(a for a in actions if a.kind == ACTION_ZONE_TAP)
        assert tap.zone == TouchZone.LIST_BACK

        sm2 = TouchStateMachine(WIDTH, HEIGHT)
        sm2.set_surface(SURFACE_INFO, False, now=0.0)
        actions = sm2.on_filter_event(press_event(LIST_DOWN_XY), now=0.1)
        tap = next(a for a in actions if a.kind == ACTION_ZONE_TAP)
        assert tap.zone == TouchZone.LIST_DOWN

    def test_row_press_on_the_compact_info_surface_reports_list_row(self):
        p = compact_picker_layout_for(240, 240, metrics=_COMPACT_METRICS)
        sm = TouchStateMachine(240, 240, metrics=_COMPACT_METRICS)
        sm.set_surface(SURFACE_INFO, False, now=0.0)
        actions = sm.on_filter_event(press_event(_rect_center(p.row1)), now=0.1)
        tap = next(a for a in actions if a.kind == ACTION_ZONE_TAP)
        assert tap.zone == TouchZone.LIST_ROW
        assert tap.index == 1


class TestInfoValueSurface:
    """SURFACE_INFO_VALUE: the compact info page's own drill-in. Held like
    every other list surface; its geometry (GEOMETRY_INFO_VALUE) is a
    single whole-panel LIST_BACK entry, so any press anywhere reports the
    same zone-tap back to the list."""

    def test_maps_to_geometry_info_value(self):
        assert _GEOMETRY_FOR_SURFACE[SURFACE_INFO_VALUE] == GEOMETRY_INFO_VALUE

    def test_arms_immediately_like_every_other_held_surface(self):
        sm = TouchStateMachine(240, 240, metrics=_COMPACT_METRICS)
        sm.set_surface(SURFACE_INFO_VALUE, False, now=0.0)
        assert sm.overlay_visible is True
        assert sm.held_visible is True

    @pytest.mark.parametrize("xy", [(0, 0), (120, 120), (239, 239)])
    def test_a_press_anywhere_reports_list_back(self, xy):
        sm = TouchStateMachine(240, 240, metrics=_COMPACT_METRICS)
        sm.set_surface(SURFACE_INFO_VALUE, False, now=0.0)
        actions = sm.on_filter_event(press_event(xy), now=0.1)
        tap = next(a for a in actions if a.kind == ACTION_ZONE_TAP)
        assert tap.zone == TouchZone.LIST_BACK


class TestDotsGating:
    """DOTS and NAME are each gated by their own "is it currently
    tappable" flag on BOTH the main surface and the repeat surface."""

    def test_dots_inactive_on_main_is_a_dead_zone(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_HIDDEN, False, now=0.0, dots_active=False)
        sm._overlay_visible = True
        actions = sm.on_filter_event(press_event(DOTS_XY), now=0.0)
        assert actions == []

    def test_dots_active_on_main_emits_zone_tap(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_HIDDEN, False, now=0.0, dots_active=True)
        sm._overlay_visible = True
        actions = sm.on_filter_event(press_event(DOTS_XY), now=0.0)
        tap = next(a for a in actions if a.kind == ACTION_ZONE_TAP)
        assert tap.zone == TouchZone.DOTS

    def test_dots_inactive_on_repeat_is_a_dead_zone(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_REPEAT, False, now=0.0, dots_active=False)
        actions = sm.on_filter_event(press_event(DOTS_XY), now=0.0)
        assert actions == []

    def test_dots_active_on_repeat_emits_zone_tap(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_REPEAT, False, now=0.0, dots_active=True)
        actions = sm.on_filter_event(press_event(DOTS_XY), now=0.0)
        tap = next(a for a in actions if a.kind == ACTION_ZONE_TAP)
        assert tap.zone == TouchZone.DOTS

    def test_same_surface_call_updates_dots_active(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_REPEAT, False, now=0.0, dots_active=False)
        assert sm.set_surface(SURFACE_REPEAT, False, now=0.0, dots_active=True) == []
        actions = sm.on_filter_event(press_event(DOTS_XY), now=0.0)
        assert any(a.kind == ACTION_ZONE_TAP for a in actions)

    def test_name_inactive_on_repeat_is_a_dead_zone(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_REPEAT, False, now=0.0)
        actions = sm.on_filter_event(press_event(NAME_XY), now=0.0)
        assert actions == []

    def test_name_active_on_repeat_emits_zone_tap(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_REPEAT, True, now=0.0)
        actions = sm.on_filter_event(press_event(NAME_XY), now=0.0)
        tap = next(a for a in actions if a.kind == ACTION_ZONE_TAP)
        assert tap.zone == TouchZone.NAME


class TestRepeatAndIdleZoneTaps:
    def test_repeat_play_start_stop_taps(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        for xy, expected_zone in (
            (REPEAT_PLAY_XY, TouchZone.REPEAT_PLAY),
            (REPEAT_START_XY, TouchZone.REPEAT_START),
            (REPEAT_STOP_XY, TouchZone.REPEAT_STOP),
        ):
            sm.set_surface(SURFACE_REPEAT, False, now=0.0)
            sm.on_filter_event(release_event(), now=0.0)
            actions = sm.on_filter_event(press_event(xy), now=0.1)
            tap = next(a for a in actions if a.kind == ACTION_ZONE_TAP)
            assert tap.zone == expected_zone
            assert tap.index is None

    def test_idle_replay_tap(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_IDLE, False, now=0.0)
        actions = sm.on_filter_event(press_event(IDLE_XY), now=0.1)
        tap = next(a for a in actions if a.kind == ACTION_ZONE_TAP)
        assert tap.zone == TouchZone.IDLE_REPLAY

    def test_idle_info_tap(self):
        # The "i" affordance's own zone, top-right of the idle screen —
        # reachable regardless of whether IDLE_XY (elsewhere on the idle
        # surface) would resolve to a replay tap.
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_IDLE, False, now=0.0)
        actions = sm.on_filter_event(press_event(IDLE_INFO_XY), now=0.1)
        tap = next(a for a in actions if a.kind == ACTION_ZONE_TAP)
        assert tap.zone == TouchZone.IDLE_INFO
        assert tap.index is None

    def test_repeat_and_idle_taps_are_single_shot_no_repeat(self):
        for surface, xy, zone in (
            (SURFACE_REPEAT, REPEAT_PLAY_XY, TouchZone.REPEAT_PLAY),
            (SURFACE_IDLE, IDLE_XY, TouchZone.IDLE_REPLAY),
        ):
            sm = TouchStateMachine(WIDTH, HEIGHT)
            sm.set_surface(surface, False, now=0.0)
            sm.on_filter_event(press_event(xy), now=0.0)
            assert sm.pressed_zone == zone
            actions = sm.tick(now=PRESSED_FLASH_S)
            assert actions == [TouchAction(ACTION_SET_PRESSED_ZONE, None)]
            actions = sm.tick(now=FIRST_REPEAT_S + 1.0)
            assert actions == []


class TestTouchSurfacePollingTupleContracts:
    """_poll_surface() accepts either the older 2-tuple or a 3-tuple
    that adds dots_active — see dial_touch.py's TouchEventSource._poll_
    surface docstring."""

    def test_two_tuple_still_accepted_dots_active_defaults_false(self):
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        source = TouchEventSource(
            driver, touch_filter, sm,
            get_touch_surface=lambda: (SURFACE_HIDDEN, True),
        )
        source._poll_surface()
        assert sm.surface == SURFACE_HIDDEN
        sm._overlay_visible = True
        actions = sm.on_filter_event(press_event(DOTS_XY), now=0.0)
        assert actions == []  # dots_active defaulted to False

    def test_three_tuple_carries_dots_active_through(self):
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        source = TouchEventSource(
            driver, touch_filter, sm,
            get_touch_surface=lambda: (SURFACE_HIDDEN, True, True),
        )
        source._poll_surface()
        assert sm.surface == SURFACE_HIDDEN
        sm._overlay_visible = True
        actions = sm.on_filter_event(press_event(DOTS_XY), now=0.0)
        assert any(a.kind == ACTION_ZONE_TAP for a in actions)

    def test_dots_only_change_still_triggers_set_surface(self):
        """Same surface, same name_active, only dots_active flips — must
        still be detected and applied (not swallowed by a 2-tuple-shaped
        equality check)."""
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        values = iter([
            (SURFACE_HIDDEN, True, False),
            (SURFACE_HIDDEN, True, True),
        ])
        source = TouchEventSource(
            driver, touch_filter, sm,
            get_touch_surface=lambda: next(values),
        )
        source._poll_surface()
        source._poll_surface()
        sm._overlay_visible = True
        actions = sm.on_filter_event(press_event(DOTS_XY), now=0.0)
        assert any(a.kind == ACTION_ZONE_TAP for a in actions)

    def test_raising_getter_still_treated_as_hidden_with_a_2_or_3_tuple_fallback(self):
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_REPEAT, False, now=0.0)

        def boom():
            raise RuntimeError("display gone")

        source = TouchEventSource(driver, touch_filter, sm, get_touch_surface=boom)
        source._poll_surface()
        assert sm.surface == SURFACE_HIDDEN


class TestExistingPollingSuiteUnaffected:
    """The existing polling tests (TestTouchEventSourceSurfacePolling)
    already cover 2-tuple-only wiring end to end; this class only pins the
    2-tuple contract still works when a bare non-tuple string is somehow
    returned (defensive; not expected from any real caller)."""

    def test_bare_string_result_still_handled(self):
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        source = TouchEventSource(
            driver, touch_filter, sm,
            get_touch_surface=lambda: SURFACE_HIDDEN,
        )
        source._poll_surface()
        assert sm.surface == SURFACE_HIDDEN


# ---------------------------------------------------------------------------
# force_overlay_visible() and the repeat-close reveal-on-return-to-main
# mechanism: closing the repeat screen via a DOTS tap must bring back the
# main screen's volume overlay rather than leaving bare artwork on screen.
# ---------------------------------------------------------------------------

class TestForceOverlayVisible:
    def test_makes_overlay_visible_and_returns_reveal_action(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        actions = sm.force_overlay_visible(now=0.0)
        assert actions == [TouchAction(ACTION_REVEAL_OVERLAY)]
        assert sm.overlay_visible is True

    def test_undoes_a_surface_change_dismiss_within_the_same_tick(self):
        """The exact sequence _poll_surface() drives: the repeat surface's
        set_surface(..., SURFACE_HIDDEN) dismisses the overlay first (the
        repeat screen counted as held); force_overlay_visible() right
        after must bring it straight back."""
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_REPEAT, True, now=0.0, dots_active=True)
        assert sm.overlay_visible is True
        dismiss_actions = sm.set_surface(SURFACE_HIDDEN, False, now=1.0)
        assert any(a.kind == ACTION_DISMISS_OVERLAY for a in dismiss_actions)
        assert sm.overlay_visible is False

        reveal_actions = sm.force_overlay_visible(now=1.0)
        assert reveal_actions == [TouchAction(ACTION_REVEAL_OVERLAY)]
        assert sm.overlay_visible is True

    def test_auto_dismisses_normally_afterwards(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.force_overlay_visible(now=0.0)
        actions = sm.tick(now=DISMISS_S + 1.0)
        assert any(a.kind == ACTION_DISMISS_OVERLAY for a in actions)

    def test_does_not_arm_a_dismiss_clock_while_held(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_held_visible(True, now=0.0)
        sm.force_overlay_visible(now=0.0)
        actions = sm.tick(now=DISMISS_S * 10)
        assert not any(a.kind == ACTION_DISMISS_OVERLAY for a in actions)
        assert sm.overlay_visible is True


class TestRepeatCloseRevealWiring:
    """TouchEventSource._poll_surface(): a transition away from
    SURFACE_REPEAT consumes the display's one-shot repeat-close-reveal
    flag and, when it was set, reveals the overlay on the way back to
    main."""

    def test_reveals_on_transition_away_from_repeat_when_flag_set(self):
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        values = iter([(SURFACE_REPEAT, True, True), (SURFACE_HIDDEN, True, False)])
        reveal_calls = []
        source = TouchEventSource(
            driver, touch_filter, sm,
            get_touch_surface=lambda: next(values),
            consume_repeat_close_reveal=lambda: True,
            on_reveal_overlay=lambda: reveal_calls.append(True),
        )
        source._poll_surface()  # -> SURFACE_REPEAT (held visible, no reveal action)
        source._poll_surface()  # -> SURFACE_HIDDEN: dismissed, then force-revealed
        assert len(reveal_calls) == 1
        assert sm.overlay_visible is True

    def test_no_extra_reveal_when_flag_not_set(self):
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        values = iter([(SURFACE_REPEAT, True, True), (SURFACE_HIDDEN, True, False)])
        reveal_calls = []
        source = TouchEventSource(
            driver, touch_filter, sm,
            get_touch_surface=lambda: next(values),
            consume_repeat_close_reveal=lambda: False,
            on_reveal_overlay=lambda: reveal_calls.append(True),
        )
        source._poll_surface()  # -> SURFACE_REPEAT (held visible, no reveal action)
        source._poll_surface()  # -> SURFACE_HIDDEN, flag clear: dismissed, stays hidden
        assert reveal_calls == []
        assert sm.overlay_visible is False

    def test_not_consulted_for_a_transition_that_is_not_away_from_repeat(self):
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        values = iter([(SURFACE_SELECTOR, False, False), (SURFACE_HIDDEN, True, False)])
        consume = MagicMock(return_value=True)
        source = TouchEventSource(
            driver, touch_filter, sm,
            get_touch_surface=lambda: next(values),
            consume_repeat_close_reveal=consume,
        )
        source._poll_surface()  # -> SURFACE_SELECTOR
        source._poll_surface()  # -> SURFACE_HIDDEN (not away from repeat)
        consume.assert_not_called()

    def test_none_getter_is_a_safe_no_op(self):
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        values = iter([(SURFACE_REPEAT, True, True), (SURFACE_HIDDEN, True, False)])
        source = TouchEventSource(
            driver, touch_filter, sm,
            get_touch_surface=lambda: next(values),
            consume_repeat_close_reveal=None,
        )
        source._poll_surface()
        source._poll_surface()  # must not raise with no getter supplied
        assert sm.surface == SURFACE_HIDDEN


# ---------------------------------------------------------------------------
# SURFACE_REPEAT_REPLAY: the compact tier's own repeat-replaying surface —
# GEOMETRY_REPEAT_REPLAY, held immediately like every other non-hidden
# surface, and the repeat-close reveal rule treats it as one set together
# with SURFACE_REPEAT.
# ---------------------------------------------------------------------------

_COMPACT_METRICS = metrics_for(240, 240, 0.0973)
_COMPACT_LAYOUT = compact_layout_for(240, 240, metrics=_COMPACT_METRICS)


class TestNewSurfaceMapsToGeometryRepeatReplay:
    def test_maps_to_geometry_repeat_replay(self):
        from dial_touch import _GEOMETRY_FOR_SURFACE

        assert _GEOMETRY_FOR_SURFACE[SURFACE_REPEAT_REPLAY] == GEOMETRY_REPEAT_REPLAY

    def test_arms_immediately_like_every_other_held_surface(self):
        sm = TouchStateMachine(240, 240, metrics=_COMPACT_METRICS)
        sm.set_surface(SURFACE_REPEAT_REPLAY, True, now=0.0, dots_active=True)
        assert sm.overlay_visible is True
        assert sm.held_visible is True

    def test_bl_arms_repeat_start(self):
        sm = TouchStateMachine(240, 240, metrics=_COMPACT_METRICS)
        sm.set_surface(SURFACE_REPEAT_REPLAY, True, now=0.0)
        actions = sm.on_filter_event(press_event(_rect_center(_COMPACT_LAYOUT.bl)), now=0.1)
        assert kinds(actions) == [ACTION_SET_PRESSED_ZONE, ACTION_ZONE_TAP]
        tap = next(a for a in actions if a.kind == ACTION_ZONE_TAP)
        assert tap.zone == TouchZone.REPEAT_START

    def test_br_arms_repeat_stop(self):
        sm = TouchStateMachine(240, 240, metrics=_COMPACT_METRICS)
        sm.set_surface(SURFACE_REPEAT_REPLAY, True, now=0.0)
        actions = sm.on_filter_event(press_event(_rect_center(_COMPACT_LAYOUT.br)), now=0.1)
        tap = next(a for a in actions if a.kind == ACTION_ZONE_TAP)
        assert tap.zone == TouchZone.REPEAT_STOP

    def test_tl_back_control_tap_reports_dots_gated_by_dots_active(self):
        # The back control reuses the DOTS zone for "tap = back" — gated by
        # dots_active exactly like the main/repeat surfaces' own DOTS cell.
        sm = TouchStateMachine(240, 240, metrics=_COMPACT_METRICS)
        sm.set_surface(SURFACE_REPEAT_REPLAY, True, now=0.0, dots_active=False)
        assert sm.on_filter_event(press_event(_rect_center(_COMPACT_LAYOUT.tl)), now=0.1) == []
        sm.set_surface(SURFACE_REPEAT_REPLAY, True, now=0.2, dots_active=True)
        actions = sm.on_filter_event(press_event(_rect_center(_COMPACT_LAYOUT.tl)), now=0.3)
        tap = next(a for a in actions if a.kind == ACTION_ZONE_TAP)
        assert tap.zone == TouchZone.DOTS


class TestRepeatSurfacesFormOneSet:
    def test_repeat_and_repeat_replay_are_both_members(self):
        assert SURFACE_REPEAT in _REPEAT_SURFACES
        assert SURFACE_REPEAT_REPLAY in _REPEAT_SURFACES

    def test_repeat_to_repeat_replay_does_not_fire_the_close_reveal(self):
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        values = iter([(SURFACE_REPEAT, True, True), (SURFACE_REPEAT_REPLAY, True, True)])
        reveal_calls = []
        source = TouchEventSource(
            driver, touch_filter, sm,
            get_touch_surface=lambda: next(values),
            consume_repeat_close_reveal=MagicMock(return_value=True),
            on_reveal_overlay=lambda: reveal_calls.append(True),
        )
        source._poll_surface()  # -> SURFACE_REPEAT
        source._poll_surface()  # -> SURFACE_REPEAT_REPLAY: still in the set, no reveal
        assert reveal_calls == []

    def test_repeat_replay_to_repeat_does_not_fire_the_close_reveal(self):
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        values = iter([(SURFACE_REPEAT_REPLAY, True, True), (SURFACE_REPEAT, True, True)])
        reveal_calls = []
        source = TouchEventSource(
            driver, touch_filter, sm,
            get_touch_surface=lambda: next(values),
            consume_repeat_close_reveal=MagicMock(return_value=True),
            on_reveal_overlay=lambda: reveal_calls.append(True),
        )
        source._poll_surface()
        source._poll_surface()
        assert reveal_calls == []

    def test_repeat_replay_to_hidden_does_fire_the_close_reveal(self):
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        values = iter([(SURFACE_REPEAT_REPLAY, True, True), (SURFACE_HIDDEN, True, False)])
        reveal_calls = []
        source = TouchEventSource(
            driver, touch_filter, sm,
            get_touch_surface=lambda: next(values),
            consume_repeat_close_reveal=lambda: True,
            on_reveal_overlay=lambda: reveal_calls.append(True),
        )
        source._poll_surface()  # -> SURFACE_REPEAT_REPLAY
        source._poll_surface()  # -> SURFACE_HIDDEN: leaves the set, reveals
        assert len(reveal_calls) == 1
        assert sm.overlay_visible is True

    def test_repeat_replay_to_held_does_fire_the_close_reveal(self):
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        values = iter([(SURFACE_REPEAT_REPLAY, True, True), (SURFACE_HELD, True, False)])
        reveal_calls = []
        source = TouchEventSource(
            driver, touch_filter, sm,
            get_touch_surface=lambda: next(values),
            consume_repeat_close_reveal=lambda: True,
            on_reveal_overlay=lambda: reveal_calls.append(True),
        )
        source._poll_surface()
        source._poll_surface()
        assert len(reveal_calls) == 1


class TestNoWifiAndRestartingSurfaces:
    def test_surface_map(self):
        assert _GEOMETRY_FOR_SURFACE[SURFACE_NOWIFI] == GEOMETRY_NOWIFI
        assert _GEOMETRY_FOR_SURFACE[SURFACE_RESTARTING] == GEOMETRY_NONE

    def test_nowifi_cells_arm_as_zone_taps(self):
        l = nowifi_layout_for(WIDTH, HEIGHT)
        for rect, zone in ((l.dismiss, TouchZone.NOWIFI_DISMISS), (l.restart, TouchZone.NOWIFI_RESTART)):
            sm = TouchStateMachine(WIDTH, HEIGHT)
            sm.set_surface(SURFACE_NOWIFI, False, now=0.0)
            actions = sm.on_filter_event(press_event(_rect_center(rect)), now=0.1)
            assert kinds(actions) == [ACTION_SET_PRESSED_ZONE, ACTION_ZONE_TAP]
            assert actions[-1].zone == zone

    def test_restarting_surface_is_held_but_inert(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_RESTARTING, False, now=0.0)
        assert sm.held_visible is True
        for xy in (UP_XY, DOWN_XY, MUTE_XY, (WIDTH // 2, HEIGHT // 2)):
            assert sm.on_filter_event(press_event(xy), now=0.1) == []
            sm.on_filter_event(release_event(), now=0.2)

    def test_a_button_less_warning_surface_mapped_to_none_is_held_but_inert(self):
        layout = nowifi_layout_for(WIDTH, HEIGHT)
        with patch.dict(_GEOMETRY_FOR_SURFACE, {"notice": GEOMETRY_NONE}):
            sm = TouchStateMachine(WIDTH, HEIGHT)
            sm.set_surface("notice", False, now=0.0)
            for rect in (layout.message, layout.dismiss, layout.restart):
                assert sm.on_filter_event(press_event(_rect_center(rect)), now=0.1) == []
                sm.on_filter_event(release_event(), now=0.2)

    def test_sdhealth_surface_map(self):
        assert _GEOMETRY_FOR_SURFACE[SURFACE_SDHEALTH] == GEOMETRY_SDHEALTH

    def test_sdhealth_dismiss_cell_arms_as_zone_tap(self):
        l = sdhealth_layout_for(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_SDHEALTH, False, now=0.0)
        actions = sm.on_filter_event(press_event(_rect_center(l.dismiss)), now=0.1)
        assert kinds(actions) == [ACTION_SET_PRESSED_ZONE, ACTION_ZONE_TAP]
        assert actions[-1].zone == TouchZone.SDHEALTH_DISMISS


# ---------------------------------------------------------------------------
# The complement rule: the single-shot and zone-tap sets are derived from
# the zone enum minus the two/three fixed-action zones, not hand-listed —
# stated here explicitly so a reader checking the derivation finds it
# alongside the sets themselves.
# ---------------------------------------------------------------------------

class TestComplementRuleDerivation:
    def test_single_shot_zones_is_every_zone_except_up_and_down(self):
        assert _SINGLE_SHOT_ZONES == frozenset(TouchZone) - {
            TouchZone.UP, TouchZone.DOWN, TouchZone.OUTPUT_UP, TouchZone.OUTPUT_DOWN,
            TouchZone.EQ_BASS_DOWN, TouchZone.EQ_BASS_UP, TouchZone.EQ_TREBLE_DOWN, TouchZone.EQ_TREBLE_UP,
        }

    def test_zone_tap_zones_is_every_zone_except_up_down_and_mute(self):
        assert _ZONE_TAP_ZONES == frozenset(TouchZone) - {
            TouchZone.UP, TouchZone.DOWN, TouchZone.MUTE,
        }


class TestUnknownSurfaceFallsBackToMainGeometry:
    def test_unknown_surface_string_arms_against_main(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface("not-a-real-surface", False, now=0.0)
        actions = sm.on_filter_event(press_event(UP_XY), now=0.1)
        assert kinds(actions) == [ACTION_SET_PRESSED_ZONE, ACTION_VOLUME_UP]


# ---------------------------------------------------------------------------
# The outputs list and per-output detail surfaces: geometry mapping, the
# OUTPUTS gate, OUTPUT_UP/OUTPUT_DOWN repeating as zone taps, and
# OUTPUT_TOGGLE/OUTPUT_BACK as single-shot zone taps.
# ---------------------------------------------------------------------------

_OUTPUT_LAYOUT = output_layout_for(WIDTH, HEIGHT)
OUTPUT_BACK_XY = _rect_center(_OUTPUT_LAYOUT.back)
OUTPUT_TOGGLE_XY = _rect_center(_OUTPUT_LAYOUT.row)
OUTPUT_DOWN_XY = _rect_center(_OUTPUT_LAYOUT.down)
OUTPUT_UP_XY = _rect_center(_OUTPUT_LAYOUT.up)
OUTPUTS_XY = _rect_center(zones_for(WIDTH, HEIGHT)[TouchZone.OUTPUTS])


class TestOutputsSurfaceMapping:
    def test_surface_outputs_maps_to_list_geometry(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_OUTPUTS, False, now=0.0)
        actions = sm.on_filter_event(press_event(LIST_ROW0_XY), now=0.1)
        tap = next(a for a in actions if a.kind == ACTION_ZONE_TAP)
        assert tap.zone == TouchZone.LIST_ROW
        assert tap.index == 0

    def test_surface_outputs_counts_as_visible_and_held(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_OUTPUTS, False, now=0.0)
        assert sm.overlay_visible is True
        assert sm.held_visible is True

    def test_surface_output_maps_to_geometry_output(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_OUTPUT, False, now=0.0)
        actions = sm.on_filter_event(press_event(OUTPUT_TOGGLE_XY), now=0.1)
        tap = next(a for a in actions if a.kind == ACTION_ZONE_TAP)
        assert tap.zone == TouchZone.OUTPUT_TOGGLE

    def test_surface_output_counts_as_visible_and_held(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_OUTPUT, False, now=0.0)
        assert sm.overlay_visible is True
        assert sm.held_visible is True

    def test_name_zone_reused_on_the_output_surface(self):
        """NAME is reused from the main surface on the output detail page —
        gated by the same _name_active flag."""
        name_xy = _rect_center(_OUTPUT_LAYOUT.name)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_OUTPUT, True, now=0.0)
        actions = sm.on_filter_event(press_event(name_xy), now=0.1)
        tap = next(a for a in actions if a.kind == ACTION_ZONE_TAP)
        assert tap.zone == TouchZone.NAME

    def test_name_inactive_on_output_is_a_dead_zone(self):
        name_xy = _rect_center(_OUTPUT_LAYOUT.name)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_OUTPUT, False, now=0.0)
        actions = sm.on_filter_event(press_event(name_xy), now=0.0)
        assert actions == []


class TestOutputZoneTaps:
    def test_output_back_is_single_shot_zone_tap(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_OUTPUT, False, now=0.0)
        actions = sm.on_filter_event(press_event(OUTPUT_BACK_XY), now=0.0)
        tap = next(a for a in actions if a.kind == ACTION_ZONE_TAP)
        assert tap.zone == TouchZone.OUTPUT_BACK
        assert sm.pressed_zone == TouchZone.OUTPUT_BACK
        # Single-shot: the flash clears itself even if held.
        actions = sm.tick(now=PRESSED_FLASH_S)
        assert actions == [TouchAction(ACTION_SET_PRESSED_ZONE, None)]
        actions = sm.tick(now=FIRST_REPEAT_S + 1.0)
        assert actions == []

    def test_output_toggle_is_single_shot_zone_tap(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_OUTPUT, False, now=0.0)
        actions = sm.on_filter_event(press_event(OUTPUT_TOGGLE_XY), now=0.0)
        assert kinds(actions) == [ACTION_SET_PRESSED_ZONE, ACTION_ZONE_TAP]
        tap = next(a for a in actions if a.kind == ACTION_ZONE_TAP)
        assert tap.zone == TouchZone.OUTPUT_TOGGLE
        actions = sm.tick(now=PRESSED_FLASH_S)
        assert actions == [TouchAction(ACTION_SET_PRESSED_ZONE, None)]
        actions = sm.tick(now=FIRST_REPEAT_S + 1.0)
        assert actions == []

    def test_output_up_and_down_are_in_the_repeating_set(self):
        assert TouchZone.OUTPUT_UP in _REPEATING_ZONES
        assert TouchZone.OUTPUT_DOWN in _REPEATING_ZONES

    def test_output_down_repeats_as_zone_taps(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_OUTPUT, False, now=0.0)
        actions = sm.on_filter_event(press_event(OUTPUT_DOWN_XY), now=0.0)
        first_tap = next(a for a in actions if a.kind == ACTION_ZONE_TAP)
        assert first_tap.zone == TouchZone.OUTPUT_DOWN

        # No repeat yet just before FIRST_REPEAT_S.
        assert kinds(sm.tick(now=FIRST_REPEAT_S - 0.01)) == []
        # A zone tap fires at FIRST_REPEAT_S, and again every
        # REPEAT_INTERVAL_S after that, same cadence as UP/DOWN.
        actions = sm.tick(now=FIRST_REPEAT_S)
        tap = next(a for a in actions if a.kind == ACTION_ZONE_TAP)
        assert tap.zone == TouchZone.OUTPUT_DOWN
        actions = sm.tick(now=FIRST_REPEAT_S + REPEAT_INTERVAL_S)
        tap = next(a for a in actions if a.kind == ACTION_ZONE_TAP)
        assert tap.zone == TouchZone.OUTPUT_DOWN

    def test_output_up_repeats_as_zone_taps(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_OUTPUT, False, now=0.0)
        sm.on_filter_event(press_event(OUTPUT_UP_XY), now=0.0)
        actions = sm.tick(now=FIRST_REPEAT_S)
        tap = next(a for a in actions if a.kind == ACTION_ZONE_TAP)
        assert tap.zone == TouchZone.OUTPUT_UP

    def test_output_stepper_stays_lit_while_held_like_up_down(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_OUTPUT, False, now=0.0)
        sm.on_filter_event(press_event(OUTPUT_DOWN_XY), now=0.0)
        assert sm.pressed_zone == TouchZone.OUTPUT_DOWN
        # Not cleared by the single-shot flash timer.
        actions = sm.tick(now=PRESSED_FLASH_S)
        assert sm.pressed_zone == TouchZone.OUTPUT_DOWN
        sm.on_filter_event(release_event(OUTPUT_DOWN_XY), now=0.5)
        assert sm.pressed_zone is None


class TestOutputsGate:
    """The top-right OUTPUTS zone (main surface) is gated by
    _outputs_active, the same discipline _dots_active/_name_active use."""

    def test_outputs_inactive_is_a_dead_zone(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_HIDDEN, False, now=0.0, outputs_active=False)
        sm._overlay_visible = True
        actions = sm.on_filter_event(press_event(OUTPUTS_XY), now=0.0)
        assert actions == []

    def test_outputs_active_emits_zone_tap(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_HIDDEN, False, now=0.0, outputs_active=True)
        sm._overlay_visible = True
        actions = sm.on_filter_event(press_event(OUTPUTS_XY), now=0.0)
        tap = next(a for a in actions if a.kind == ACTION_ZONE_TAP)
        assert tap.zone == TouchZone.OUTPUTS

    def test_same_surface_call_updates_outputs_active(self):
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm.set_surface(SURFACE_HIDDEN, False, now=0.0, outputs_active=False)
        assert sm.set_surface(SURFACE_HIDDEN, False, now=0.0, outputs_active=True) == []
        sm._overlay_visible = True
        actions = sm.on_filter_event(press_event(OUTPUTS_XY), now=0.0)
        assert any(a.kind == ACTION_ZONE_TAP for a in actions)

    def test_mute_is_still_a_fixed_action_zone_not_outputs(self):
        """The footer's own MUTE cell is unaffected by the OUTPUTS gate —
        it still fires the fixed mute-toggle action, never a zone tap."""
        sm = TouchStateMachine(WIDTH, HEIGHT)
        sm._overlay_visible = True
        actions = sm.on_filter_event(press_event(MUTE_XY), now=0.0)
        assert kinds(actions) == [ACTION_SET_PRESSED_ZONE, ACTION_MUTE_TOGGLE]


class TestTouchSurfaceFourTupleContract:
    """_poll_surface() accepts the full 4-tuple (surface, name_active,
    dots_active, outputs_active), on top of the existing 2- and 3-tuple
    forms — see TestTouchSurfacePollingTupleContracts above for those."""

    def test_four_tuple_carries_outputs_active_through(self):
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        source = TouchEventSource(
            driver, touch_filter, sm,
            get_touch_surface=lambda: (SURFACE_HIDDEN, False, False, True),
        )
        source._poll_surface()
        assert sm.surface == SURFACE_HIDDEN
        sm._overlay_visible = True
        actions = sm.on_filter_event(press_event(OUTPUTS_XY), now=0.0)
        assert any(a.kind == ACTION_ZONE_TAP for a in actions)

    def test_three_tuple_defaults_outputs_active_false(self):
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        source = TouchEventSource(
            driver, touch_filter, sm,
            get_touch_surface=lambda: (SURFACE_HIDDEN, False, True),
        )
        source._poll_surface()
        sm._overlay_visible = True
        actions = sm.on_filter_event(press_event(OUTPUTS_XY), now=0.0)
        assert actions == []

    def test_outputs_active_only_change_still_triggers_set_surface(self):
        """A 4-tuple that differs only in its last element (no surface,
        name_active or dots_active change) must still resync the state
        machine — the same "chrome changed with no surface change" case
        dots_active already handles for the main screen."""
        driver = FakeDriver()
        touch_filter = TouchFilter(WIDTH, HEIGHT)
        sm = TouchStateMachine(WIDTH, HEIGHT)
        values = iter([
            (SURFACE_HIDDEN, False, False, False),
            (SURFACE_HIDDEN, False, False, True),
        ])
        source = TouchEventSource(
            driver, touch_filter, sm,
            get_touch_surface=lambda: next(values),
        )
        source._poll_surface()
        source._poll_surface()
        sm._overlay_visible = True
        actions = sm.on_filter_event(press_event(OUTPUTS_XY), now=0.0)
        assert any(a.kind == ACTION_ZONE_TAP for a in actions)
