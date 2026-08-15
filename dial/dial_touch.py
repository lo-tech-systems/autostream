"""dial_touch.py — touch session policy and the thread that drives it.

Two classes, deliberately kept separate:

  TouchStateMachine — pure, no thread, no clock of its own (every method
  takes *now*). Consumes dial_touch_filter.TouchEvent objects plus an
  explicit "overlay actually rendered" input and produces a small ordered
  list of ACTIONS for a caller to dispatch. It owns the "is the overlay
  visible" truth — see REVEAL-THEN-ARM below.

  TouchEventSource — a thin thread wrapper with no policy of its own. It
  blocks on T_IRQ via gpiozero, drives a driver + a TouchFilter + a
  TouchStateMachine, and hands the resulting actions to injected callables.
  It does NOT import dial_volume or dial_display — a later change wires
  those in by passing their methods as the callables here. Both gpiozero and
  dial_touch_drivers are imported lazily/defensively so this module stays
  importable on a machine with neither installed.

REVEAL-THEN-ARM: a contact that begins while the overlay is not visible only
reveals it — no zone is sampled at touch-down. Only when the caller later
reports (via overlay_live()) that the overlay has actually rendered does the
session sample the zone, from wherever the finger currently is at that
moment, and arm — starting the 400ms repeat clock then, not at touch-down.
If the finger has already lifted by the time overlay_live() is called,
nothing is actuated; the touch was reveal-only.

When the overlay is already visible at touch-down, none of the above
applies: the press arms immediately, sampling the zone at touch-down and
starting the repeat clock from touch-down — the zones were already visible
before the finger landed.

DISMISS: ~DISMISS_S after the last *contact sample* (not the last
touch-down) the overlay is dismissed. Every accepted sample while
armed/held resets this deadline, so a long hold can never dismiss underneath
a repeating finger. The clock starts at RELEASE, or at a filter CAP (treated
as an implicit release for this purpose — no further repeats, no further
resets, straight to counting down to dismiss).

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from dial_touch_filter import TouchEventType
from dial_touch_layout import TouchZone, zone_at

# Overlay auto-dismisses this long after the last contact sample / release /
# cap-stop, whichever is most recent.
DISMISS_S = 4.0

# Mirrored here from dial_touch_filter so TouchStateMachine can run its own
# repeat clock (needed for the reveal-then-arm case, where arming happens
# later than the filter's own PRESS-anchored clock) with identical cadence
# to the filter's, so the "already visible" case — where the state machine's
# clock and the filter's clock start at the same instant — behaves exactly
# the same either way.
FIRST_REPEAT_S = 0.4
REPEAT_INTERVAL_S = 0.15

# Action kinds produced by TouchStateMachine.
ACTION_REVEAL_OVERLAY = "reveal-overlay"
ACTION_VOLUME_UP = "volume-up"
ACTION_VOLUME_DOWN = "volume-down"
ACTION_MUTE_TOGGLE = "mute-toggle"
ACTION_DISMISS_OVERLAY = "dismiss-overlay"
ACTION_SET_PRESSED_ZONE = "set-pressed-zone"

_PHASE_IDLE = "idle"
_PHASE_REVEAL_PENDING = "reveal_pending"
_PHASE_ARMED = "armed"


@dataclass(frozen=True)
class TouchAction:
    kind: str
    zone: TouchZone | None = None


class TouchStateMachine:
    """Pure press-session policy. No thread, no clock reads — every method
    takes an explicit *now*, so tests drive it deterministically."""

    def __init__(self, width: int, height: int) -> None:
        self._width = width
        self._height = height
        self._phase = _PHASE_IDLE
        self._overlay_visible = False
        self._contact_down = False
        self._pending_xy: tuple[int, int] | None = None
        self._armed_zone: TouchZone | None = None
        self._next_repeat_time: float | None = None
        self._dismiss_deadline: float | None = None

    # -- read-only state, for a compositor/UI to consult -------------------

    @property
    def overlay_visible(self) -> bool:
        return self._overlay_visible

    @property
    def pressed_zone(self) -> TouchZone | None:
        return self._armed_zone if self._phase == _PHASE_ARMED else None

    # -- inputs --------------------------------------------------------

    def on_filter_event(self, event, now: float) -> list[TouchAction]:
        """Feed one dial_touch_filter.TouchEvent. Returns zero or more
        actions."""
        if event.type == TouchEventType.PRESS:
            return self._on_press(event, now)
        if event.type == TouchEventType.REPEAT:
            return self._on_repeat(event, now)
        if event.type == TouchEventType.RELEASE:
            return self._on_release(now)
        if event.type == TouchEventType.CAP:
            return self._on_cap(now)
        return []

    def overlay_live(self, now: float) -> list[TouchAction]:
        """Tell the session the overlay has actually rendered. Only
        meaningful while reveal-pending; a no-op otherwise."""
        if self._phase != _PHASE_REVEAL_PENDING:
            return []
        if not self._contact_down or self._pending_xy is None:
            # Finger already lifted before the overlay rendered — reveal
            # only, nothing actuated.
            self._phase = _PHASE_IDLE
            return []
        x, y = self._pending_xy
        return self._arm(x, y, now)

    def tick(self, now: float) -> list[TouchAction]:
        """Periodic check for repeat-due and dismiss-due, independent of any
        new filter event arriving. Callers should invoke this regularly
        (e.g. once per poll tick and once per idle-wait timeout) so repeats
        and the dismiss timeout fire even between filter events."""
        actions: list[TouchAction] = []
        if self._phase == _PHASE_ARMED and self._next_repeat_time is not None:
            if now >= self._next_repeat_time:
                if self._armed_zone == TouchZone.UP:
                    actions.append(TouchAction(ACTION_VOLUME_UP))
                    self._reset_dismiss(now)
                elif self._armed_zone == TouchZone.DOWN:
                    actions.append(TouchAction(ACTION_VOLUME_DOWN))
                    self._reset_dismiss(now)
                self._next_repeat_time += REPEAT_INTERVAL_S
        if (
            self._dismiss_deadline is not None
            and now >= self._dismiss_deadline
            and self._overlay_visible
        ):
            actions.append(TouchAction(ACTION_DISMISS_OVERLAY))
            self._overlay_visible = False
            self._dismiss_deadline = None
            self._phase = _PHASE_IDLE
        return actions

    # -- internals -------------------------------------------------------

    def _on_press(self, event, now: float) -> list[TouchAction]:
        self._contact_down = True
        self._pending_xy = (event.x, event.y)
        if not self._overlay_visible:
            self._overlay_visible = True
            self._phase = _PHASE_REVEAL_PENDING
            return [TouchAction(ACTION_REVEAL_OVERLAY)]
        return self._arm(event.x, event.y, now)

    def _on_repeat(self, event, now: float) -> list[TouchAction]:
        self._contact_down = True
        self._pending_xy = (event.x, event.y)
        if self._phase == _PHASE_ARMED:
            self._reset_dismiss(now)
        return []

    def _on_release(self, now: float) -> list[TouchAction]:
        self._contact_down = False
        if self._phase in (_PHASE_ARMED, _PHASE_REVEAL_PENDING):
            self._phase = _PHASE_IDLE
            self._armed_zone = None
            self._next_repeat_time = None
            self._reset_dismiss(now)
        return []

    def _on_cap(self, now: float) -> list[TouchAction]:
        # Implicit release: stop repeating, start the dismiss clock, same as
        # a real RELEASE — the filter guarantees no further REPEAT/RELEASE
        # will follow for this press.
        return self._on_release(now)

    def _arm(self, x: int, y: int, now: float) -> list[TouchAction]:
        zone = zone_at(x, y, self._width, self._height)
        if zone is None:
            # Landed/arrived in a dead zone — nothing to actuate; still
            # counts as a contact sample toward dismiss.
            self._phase = _PHASE_IDLE
            self._armed_zone = None
            self._reset_dismiss(now)
            return []
        self._phase = _PHASE_ARMED
        self._armed_zone = zone
        self._next_repeat_time = now + FIRST_REPEAT_S
        self._reset_dismiss(now)
        # Every zone acts once, immediately, on arm — a tap must do something.
        # Holding then adds auto-repeat: the next step lands FIRST_REPEAT_S
        # later and every REPEAT_INTERVAL_S after that (see tick()), the same
        # shape as a keyboard's auto-repeat. MUTE is single-shot and never
        # repeats, since re-toggling a mute at 150ms intervals is meaningless.
        actions = [TouchAction(ACTION_SET_PRESSED_ZONE, zone)]
        if zone == TouchZone.MUTE:
            actions.append(TouchAction(ACTION_MUTE_TOGGLE))
        elif zone == TouchZone.UP:
            actions.append(TouchAction(ACTION_VOLUME_UP))
        elif zone == TouchZone.DOWN:
            actions.append(TouchAction(ACTION_VOLUME_DOWN))
        return actions

    def _reset_dismiss(self, now: float) -> None:
        self._dismiss_deadline = now + DISMISS_S


# ---------------------------------------------------------------------------
# TouchEventSource — thin thread wrapper
# ---------------------------------------------------------------------------

# T_IRQ is active-low; mirrors dial_touch_drivers._TOUCH_IRQ_GPIO (kept as
# its own constant here too so this module has no import-time dependency on
# the drivers module beyond what open_driver() itself needs).
_T_IRQ_GPIO = 26

# How often the sample loop polls the driver while T_IRQ is active.
_POLL_INTERVAL_S = 0.01

# How long wait_for_active() blocks before returning control to the loop so
# tick() gets a chance to fire the dismiss timeout even with no touch at all.
_IDLE_TICK_INTERVAL_S = 0.1


class TouchEventSource:
    """Drives driver -> filter -> state machine and dispatches the resulting
    actions through injected callables. Constructed with an already-open
    driver, filter, and state machine (dial_main.py wiring, once it exists,
    owns creating those); this class adds only the thread and the IRQ wait.
    """

    def __init__(
        self,
        driver,
        touch_filter,
        state_machine: TouchStateMachine,
        *,
        on_reveal_overlay=None,
        on_volume_up=None,
        on_volume_down=None,
        on_mute_toggle=None,
        on_dismiss_overlay=None,
        on_set_pressed_zone=None,
        on_cap=None,
        clock=None,
        irq=None,
        poll_interval_s: float = _POLL_INTERVAL_S,
        idle_tick_interval_s: float = _IDLE_TICK_INTERVAL_S,
    ) -> None:
        self._driver = driver
        self._filter = touch_filter
        self._state_machine = state_machine
        self._on_reveal_overlay = on_reveal_overlay
        self._on_volume_up = on_volume_up
        self._on_volume_down = on_volume_down
        self._on_mute_toggle = on_mute_toggle
        self._on_dismiss_overlay = on_dismiss_overlay
        self._on_set_pressed_zone = on_set_pressed_zone
        self._on_cap = on_cap
        self._clock = clock or time.monotonic
        self._irq = irq
        self._poll_interval_s = poll_interval_s
        self._idle_tick_interval_s = idle_tick_interval_s
        self._thread = None
        self._stop_event = None

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        import threading

        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="touch-event-source", daemon=True
        )
        self._thread.start()

    def stop(self, join_timeout: float = 1.0) -> None:
        if self._stop_event is not None:
            self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=join_timeout)

    def overlay_live(self) -> None:
        """Tell the underlying session the overlay has actually rendered.
        Safe to call from any thread; forwards to the state machine and
        dispatches any resulting actions."""
        self._dispatch(self._state_machine.overlay_live(self._clock()))

    # -- main loop -----------------------------------------------------

    def _make_default_irq(self):
        from gpiozero import DigitalInputDevice

        return DigitalInputDevice(_T_IRQ_GPIO, pull_up=True)

    def _run(self) -> None:
        irq = self._irq if self._irq is not None else self._make_default_irq()
        while not self._stop_event.is_set():
            irq.wait_for_active(timeout=self._idle_tick_interval_s)
            if irq.is_active:
                self._sample_loop(irq)
            else:
                self._dispatch(self._state_machine.tick(self._clock()))

    def _sample_loop(self, irq) -> None:
        while irq.is_active and not self._stop_event.is_set():
            now = self._clock()
            raw = self._driver.read_sample()
            for event in self._filter.feed(raw, now):
                self._handle_filter_event(event, now)
            self._dispatch(self._state_machine.tick(now))
            self._stop_event.wait(self._poll_interval_s)
        # T_IRQ has gone inactive: tell the filter contact has definitely
        # ended, in case debounce/settling hadn't already caught up.
        now = self._clock()
        for event in self._filter.feed(None, now):
            self._handle_filter_event(event, now)
        self._dispatch(self._state_machine.tick(now))

    def _handle_filter_event(self, event, now: float) -> None:
        if event.type == TouchEventType.CAP and self._on_cap is not None:
            self._on_cap()
        self._dispatch(self._state_machine.on_filter_event(event, now))

    def _dispatch(self, actions) -> None:
        for action in actions:
            if action.kind == ACTION_REVEAL_OVERLAY and self._on_reveal_overlay:
                self._on_reveal_overlay()
            elif action.kind == ACTION_VOLUME_UP and self._on_volume_up:
                self._on_volume_up()
            elif action.kind == ACTION_VOLUME_DOWN and self._on_volume_down:
                self._on_volume_down()
            elif action.kind == ACTION_MUTE_TOGGLE and self._on_mute_toggle:
                self._on_mute_toggle()
            elif action.kind == ACTION_DISMISS_OVERLAY and self._on_dismiss_overlay:
                self._on_dismiss_overlay()
            elif action.kind == ACTION_SET_PRESSED_ZONE and self._on_set_pressed_zone:
                self._on_set_pressed_zone(action.zone)
