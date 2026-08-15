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

REVEAL-ONLY FIRST TOUCH: a contact that begins while the overlay is not
visible ONLY reveals it. No zone is sampled, nothing is actuated, however
long the finger stays down — the user gets to see where the buttons are
before committing to one. Actuating on that first contact would mean
pressing a control the user could not yet see.

When the overlay is already visible at touch-down the press arms
immediately, sampling the zone at touch-down and starting the repeat clock
from touch-down — the zones were on screen before the finger landed.

PRESSED HIGHLIGHT: arming lights the pressed zone. How it clears depends on
what the zone does:

  - UP/DOWN repeat while held, so the highlight stays lit for as long as the
    finger is down and clears on release. It is showing a control that is
    genuinely still active.
  - MUTE is single-shot — it fires once and never repeats — so there is no
    ongoing state to show. It flashes for PRESSED_FLASH_S and clears itself,
    even if the finger stays down.

Either way the highlight is cleared explicitly rather than left for the next
unrelated repaint, which made a brief tap look like a stuck button.

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

from dial_touch_filter import TouchEvent, TouchEventType
from dial_touch_layout import TouchZone, zone_at

# Overlay auto-dismisses this long after the last contact sample / release /
# cap-stop, whichever is most recent.
DISMISS_S = 4.0

# How long a single-shot (MUTE) highlight stays lit. Long enough to read as
# deliberate feedback, short enough that it never looks like a latched
# state; each change costs one full-frame push. Repeating zones (UP/DOWN)
# ignore this and stay lit until release — see the module docstring.
PRESSED_FLASH_S = 0.25

# Mirrored here from dial_touch_filter so TouchStateMachine can run its own
# repeat clock with identical cadence to the filter's.
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
        self._pressed_until: float | None = None
        self._pressed_lit = False

    # -- read-only state, for a compositor/UI to consult -------------------

    @property
    def overlay_visible(self) -> bool:
        return self._overlay_visible

    @property
    def pressed_zone(self) -> TouchZone | None:
        return self._armed_zone if self._pressed_lit else None

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
        # Reveal only. The contact that summoned the overlay never actuates,
        # whether or not the finger is still down: until this moment the
        # zones were not on screen, so acting on it would fire a control the
        # user could not see. A second, deliberate press does the work.
        self._phase = _PHASE_IDLE
        self._pending_xy = None
        self._reset_dismiss(now)
        return []

    def force_reveal_only(self) -> list[TouchAction]:
        """External force-reset: drop whatever zone was armed and stop
        repeating, without ending the whole session the way a real RELEASE
        would.

        Used when the display reports (via its non-composited-state
        Event/generation — see dial_display.DialDisplay._mark_noncomposited_
        locked) that the screen went dark (cleared or slept) underneath
        whatever was on it — the geometry an armed zone was sampled against
        may no longer correspond to anything actually drawn.

        If the finger is still down, this falls back to REVEAL_PENDING —
        the same phase a fresh touch-down against a hidden overlay starts
        in. Since a reveal never actuates, the finger resting there will
        not act on the stale geometry; a fresh, deliberate press is needed,
        which is the safe outcome when what was on screen has just been
        torn down underneath it.

        If the finger is already up, this simply returns to idle. Never
        returns any actions of its own; it only clears local state.
        """
        self._armed_zone = None
        self._next_repeat_time = None
        self._pressed_lit = False
        self._pressed_until = None
        if self._contact_down:
            self._phase = _PHASE_REVEAL_PENDING
        else:
            self._phase = _PHASE_IDLE
        return []

    def tick(self, now: float) -> list[TouchAction]:
        """Periodic check for repeat-due and dismiss-due, independent of any
        new filter event arriving. Callers should invoke this regularly
        (e.g. once per poll tick and once per idle-wait timeout) so repeats
        and the dismiss timeout fire even between filter events."""
        actions: list[TouchAction] = []
        if self._pressed_until is not None and now >= self._pressed_until:
            # Single-shot flash over: unlight the zone. Emitted even after a
            # release has already returned the session to idle, so a tap
            # shorter than the flash still gets its highlight cleared.
            self._pressed_until = None
            self._pressed_lit = False
            actions.append(TouchAction(ACTION_SET_PRESSED_ZONE, None))
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
        # Any contact sample holds the overlay open, armed or not — a finger
        # resting after a reveal-only touch must not have the zones vanish
        # from under it.
        self._reset_dismiss(now)
        return []

    def _on_release(self, now: float) -> list[TouchAction]:
        self._contact_down = False
        actions: list[TouchAction] = []
        if self._phase in (_PHASE_ARMED, _PHASE_REVEAL_PENDING):
            self._phase = _PHASE_IDLE
            self._armed_zone = None
            self._next_repeat_time = None
            self._reset_dismiss(now)
        # A held repeating zone stays lit until exactly here; clear it. A
        # single-shot flash may already have cleared itself, in which case
        # there is nothing to emit.
        if self._pressed_lit:
            self._pressed_lit = False
            self._pressed_until = None
            actions.append(TouchAction(ACTION_SET_PRESSED_ZONE, None))
        return actions

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
        self._pressed_lit = True
        # Only the single-shot zone self-clears; a repeating one stays lit
        # while the finger holds it, because it really is still acting.
        self._pressed_until = now + PRESSED_FLASH_S if zone == TouchZone.MUTE else None
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
        get_noncomposited_generation=None,
        axis_signs=None,
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
        # Injected read of dial_display.DialDisplay.noncomposited_generation
        # — kept injected (not an import) for the same reason as the other
        # callbacks: this module must not import dial_display. None disables
        # the check entirely (e.g. in tests that don't care about it).
        self._get_noncomposited_generation = get_noncomposited_generation
        # The profile's UNROTATED axis signs (swap, invert_x, invert_y),
        # kept so a live rotate toggle can re-derive the mapping. None when
        # the caller did not supply them (e.g. tests constructing directly).
        self._axis_signs = axis_signs
        self._last_noncomposited_gen = None
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

    def display_config_changed(self, rotate: bool) -> None:
        """Apply a live screen-settings change that affects touch mapping.

        A 180-degree rotate is applied to the frame in software, so the
        touch axes must invert with it — otherwise every press lands
        diagonally opposite the button the user is looking at. The profile's
        own axis signs describe the UNROTATED panel, so rotate is XOR'd in,
        exactly as dial_main does when first building the filter.

        Also delivers the synthetic release that config_changed() does: the
        finger cannot carry a press across a remap, because the zone it was
        sampled against has just moved.
        """
        setter = getattr(self._filter, "set_axis_transform", None)
        if setter is not None and self._axis_signs is not None:
            swap, base_invert_x, base_invert_y = self._axis_signs
            setter(
                swap_xy=swap,
                invert_x=base_invert_x != rotate,
                invert_y=base_invert_y != rotate,
            )
        self.config_changed()

    def config_changed(self) -> None:
        """Tell the session a live screen settings change (e.g. screen_type,
        which changes the zone geometry a currently-armed press was sampled
        against) just landed.

        Delivers a SYNTHETIC RELEASE to the state machine and drops the zone
        latch — a still-down finger cannot resume where it left off; only a
        fresh touch-down (a real PRESS from the filter, which requires an
        actual release-then-recontact) can arm again. This is deliberately
        stricter than force_reveal_only() (used for the momentary
        clear/sleep case): a screen_type change can move zone boundaries
        outright, so resuming the old arm — or even re-sampling from the
        current position via reveal-then-arm — could land on a zone that
        means something different now. Safe to call from any thread.
        """
        now = self._clock()
        self._dispatch(
            self._state_machine.on_filter_event(TouchEvent(TouchEventType.RELEASE, 0, 0, None), now)
        )

    def _poll_noncomposited(self) -> None:
        """Check whether the display's non-composited-state generation has
        advanced since we last looked (screen cleared or slept). If so,
        force the session back to reveal-only and drop the zone latch — see
        TouchStateMachine.force_reveal_only(). A no-op when no getter was
        injected. Cheap (one int read/compare) — safe to call every loop
        iteration.
        """
        if self._get_noncomposited_generation is None:
            return
        gen = self._get_noncomposited_generation()
        if self._last_noncomposited_gen is None:
            self._last_noncomposited_gen = gen
            return
        if gen != self._last_noncomposited_gen:
            self._last_noncomposited_gen = gen
            self._dispatch(self._state_machine.force_reveal_only())

    # -- main loop -----------------------------------------------------

    def _make_default_irq(self):
        from gpiozero import DigitalInputDevice

        return DigitalInputDevice(_T_IRQ_GPIO, pull_up=True)

    def _run(self) -> None:
        irq = self._irq if self._irq is not None else self._make_default_irq()
        while not self._stop_event.is_set():
            self._poll_noncomposited()
            irq.wait_for_active(timeout=self._idle_tick_interval_s)
            if irq.is_active:
                self._sample_loop(irq)
            else:
                # Keep feeding the filter "definitely not touching" while
                # idle, not just once as the sample loop exits. The release
                # debounce needs a no-contact sample AFTER DEBOUNCE_S has
                # elapsed to complete; the single feed(None) on the way out
                # of _sample_loop only starts that timer. Without a second
                # one the filter stays mid-debounce forever, and the next
                # contact is read as the same press resuming — so no PRESS
                # is emitted, the overlay never reveals again, and once the
                # original press is older than MAX_HOLD_S every later touch
                # collapses straight to a CAP. One touch works, none after.
                now = self._clock()
                for event in self._filter.feed(None, now):
                    self._handle_filter_event(event, now)
                self._dispatch(self._state_machine.tick(now))

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
