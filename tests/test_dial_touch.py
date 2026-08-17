"""Tests for dial_touch.py — TouchStateMachine (pure policy) and
TouchEventSource (thread wrapper driven entirely by fakes: no gpiozero, no
real driver, no real clock is required)."""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

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
    DISMISS_S,
    FIRST_REPEAT_S,
    PRESSED_FLASH_S,
    REPEAT_INTERVAL_S,
    TouchEventSource,
    TouchStateMachine,
)
from dial_touch_filter import TouchEvent, TouchEventType, TouchFilter  # noqa: E402
from dial_touch_layout import TouchZone, zones_for  # noqa: E402

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
            on_set_pressed_zone=lambda zone: self.calls.append(("zone", zone)),
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
            on_set_pressed_zone=lambda z: None,
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
