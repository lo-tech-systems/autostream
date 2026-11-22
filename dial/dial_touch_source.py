"""dial_touch_source.py -- the thread that drives the touch session.

TouchEventSource is a thin thread wrapper with no policy of its own. It
blocks on T_IRQ via gpiozero, drives a driver + a TouchFilter + a
dial_touch.TouchStateMachine, and hands the resulting actions to injected
callables. It does NOT import dial_volume or dial_display: dial_touch_wiring wires
those in by passing their methods as the callables here. gpiozero and
dial_touch_drivers are imported lazily so this module stays importable on a
machine with neither installed.

The display is read only through injected getters, never imported. Once per
loop iteration the source polls the display's non-composited generation (the
screen was cleared or slept: the session goes back to reveal-only) and its
touch_surface() (the surface plus its flags, so a transition is noticed
within one tick either way): the 5-tuple (surface, name_active, dots_active,
outputs_active, bell_active). Closing the repeat screen via a DOTS tap also
reveals the main screen's volume overlay on return (the display's one-shot
repeat-close-reveal flag, consumed in _poll_surface()). A live settings
change delivers a synthetic release, because a finger cannot carry a press
across a remap.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import time

from dial_layout_metrics import metrics_for
from dial_touch import (
    ACTION_DISMISS_OVERLAY, ACTION_MUTE_TOGGLE, ACTION_REVEAL_OVERLAY, ACTION_SET_PRESSED_ZONE,
    ACTION_VOLUME_DOWN, ACTION_VOLUME_UP, ACTION_WAKE, ACTION_ZONE_TAP, TouchStateMachine,
)
from dial_touch_filter import TouchEvent, TouchEventType
from dial_touch_surfaces import (
    SURFACE_HIDDEN, SURFACE_REPEAT, SURFACE_REPEAT_REPLAY, SurfaceState,
)

# The repeat screen's two surfaces, treated as one set by the repeat-close
# reveal rule below: a flip between them (the enable <-> replaying
# transition) is not a close, so it must not fire the reveal — only leaving
# the set entirely (to "hidden"/"held", a genuine DOTS-tap close) does.
_REPEAT_SURFACES = frozenset((SURFACE_REPEAT, SURFACE_REPEAT_REPLAY))


# How often the sample loop polls the driver while T_IRQ is active.
_POLL_INTERVAL_S = 0.01

# How long wait_for_active() blocks before returning control to the loop so
# tick() gets a chance to fire the dismiss timeout even with no touch at all.
_IDLE_TICK_INTERVAL_S = 0.1


class TouchEventSource:
    """Drives driver -> filter -> state machine and dispatches the resulting
    actions through injected callables. Constructed with an already-open
    driver, filter, and state machine (dial_touch_wiring.py, once it exists,
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
        on_zone_tap=None,
        on_wake=None,
        on_cap=None,
        clock=None,
        irq=None,
        poll_interval_s: float = _POLL_INTERVAL_S,
        idle_tick_interval_s: float = _IDLE_TICK_INTERVAL_S,
        get_noncomposited_generation=None,
        get_touch_surface=None,
        consume_repeat_close_reveal=None,
        axis_signs=None,
    ) -> None:
        self._driver = driver
        self._filter = touch_filter
        self._state_machine = state_machine
        self._on_reveal_overlay = on_reveal_overlay
        self._on_wake = on_wake
        self._on_volume_up = on_volume_up
        self._on_volume_down = on_volume_down
        self._on_mute_toggle = on_mute_toggle
        self._on_dismiss_overlay = on_dismiss_overlay
        # ACTION_SET_PRESSED_ZONE callback: on_set_pressed_zone(zone, index)
        # — index only ever carries a value for LIST_ROW (the row it was
        # sampled against); every other zone, and the flash-clear
        # (zone=None), pass index=None.
        self._on_set_pressed_zone = on_set_pressed_zone
        # ACTION_ZONE_TAP callback: on_zone_tap(zone, index) — NAME (opens
        # the selector) and the LIST_* zones (act on it). See dial_touch_wiring.py's
        # wiring for what each zone does; this module knows nothing about
        # the display beyond dispatching the action.
        self._on_zone_tap = on_zone_tap
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
        # Injected read of dial_display.DialDisplay.touch_surface — the
        # surface and its five flags in one call; None disables the sync
        # entirely — see _poll_surface(). Kept injected, never imported,
        # for the same reason as every other display-facing callback here.
        self._get_touch_surface = get_touch_surface
        # Injected read-and-clear of dial_display.DialDisplay.
        # consume_repeat_close_reveal — a one-shot flag set only when the
        # repeat screen closes via a DOTS tap (never any other way it can
        # close), consumed here right after the resulting surface change is
        # applied to reveal the main screen's volume overlay instead of
        # leaving bare artwork on screen — see _poll_surface() and
        # TouchStateMachine.force_overlay_visible(). None disables it
        # entirely (e.g. tests that don't care, or a display stand-in that
        # predates this feature).
        self._consume_repeat_close_reveal = consume_repeat_close_reveal
        self._last_surface: SurfaceState | None = None
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

    def overlay_hidden(self) -> None:
        """Tell the underlying session the display has hidden the overlay
        itself. Safe to call from any thread; forwards to the state machine
        and dispatches any resulting actions."""
        self._dispatch(self._state_machine.overlay_hidden(self._clock()))

    def display_config_changed(self, rotate: bool, *, layout=None) -> None:
        """Apply a live screen-settings change that affects touch mapping.

        A 180-degree rotate is applied to the frame in software, so the
        touch axes must invert with it — otherwise every press lands
        diagonally opposite the button the user is looking at. The profile's
        own axis signs describe the UNROTATED panel, so rotate is XOR'd in,
        exactly as dial_touch_wiring does when first building the filter.

        *layout*, when given, is a dial_display_profiles.LayoutContext: the
        filter is re-scaled to its logical size and the state machine
        re-geometried to it (with metrics for that size) before the
        synthetic release below, so a press straddling the change is
        dropped exactly as a rotate drops it.

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
        if layout is not None:
            resize = getattr(self._filter, "set_logical_size", None)
            if resize is not None:
                resize(layout.logical_width, layout.logical_height, physical_size=layout.physical_size)
            self._state_machine.set_geometry(
                layout.logical_width, layout.logical_height,
                metrics_for(
                    layout.logical_width, layout.logical_height,
                    mm_per_px=layout.mm_per_px, size_chosen=layout.size_chosen,
                ),
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
            self._state_machine.on_filter_event(TouchEvent(TouchEventType.RELEASE, 0, 0), now)
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

    def _poll_surface(self) -> None:
        """Sync the state machine's surface from the display each loop
        iteration — see TouchStateMachine.set_surface() and dial_touch's
        SURFACES paragraph.

        get_touch_surface returns (surface, name_active, dots_active,
        outputs_active, bell_active); a raising getter is treated as
        SURFACE_HIDDEN with every flag False. self._last_surface keeps the
        full tuple so a flag-only change — main screen chrome
        appearing/disappearing with no surface or name_active change —
        still triggers a set_surface() call. A no-op when no getter was
        injected.

        A transition AWAY from SURFACE_REPEAT additionally consumes the
        display's one-shot repeat-close-reveal flag (see
        consume_repeat_close_reveal in __init__): when it is set — which
        only happens when the repeat screen just closed via a DOTS tap,
        never any other way — this brings the main screen's volume
        overlay straight back up after set_surface()'s own DISMISS, via
        TouchStateMachine.force_overlay_visible().
        """
        if self._get_touch_surface is None:
            return
        try:
            result = self._get_touch_surface()
        except Exception:
            result = SurfaceState(SURFACE_HIDDEN, False, False, False, False)
        surface, name_active, dots_active, outputs_active, bell_active = result
        current = SurfaceState(surface, bool(name_active), bool(dots_active), bool(outputs_active), bool(bell_active))
        if current != self._last_surface:
            previous_surface = self._last_surface[0] if self._last_surface is not None else None
            self._last_surface = current
            self._dispatch(self._state_machine.set_surface(
                surface, bool(name_active), self._clock(),
                dots_active=bool(dots_active), outputs_active=bool(outputs_active),
                bell_active=bool(bell_active),
            ))
            if (
                previous_surface in _REPEAT_SURFACES and surface not in _REPEAT_SURFACES
                and self._consume_repeat_close_reveal is not None
                and self._consume_repeat_close_reveal()
            ):
                self._dispatch(self._state_machine.force_overlay_visible(self._clock()))

    # -- main loop -----------------------------------------------------

    def _make_default_irq(self):
        from gpiozero import DigitalInputDevice

        # Imported here so this module keeps no import-time dependency on
        # the drivers. T_IRQ is active-low.
        from dial_touch_drivers import TOUCH_IRQ_GPIO

        return DigitalInputDevice(TOUCH_IRQ_GPIO, pull_up=True)

    def _run(self) -> None:
        # Close only what this thread created. An injected irq belongs to
        # whoever passed it in (tests, mostly) and closing it here would
        # release a device the owner still holds a reference to.
        owned_irq = None
        if self._irq is not None:
            irq = self._irq
        else:
            irq = owned_irq = self._make_default_irq()
        try:
            self._loop(irq)
        finally:
            if owned_irq is not None:
                # Without this the T_IRQ GPIO stays claimed for the life of
                # the process: stop() ends the thread but the pin is never
                # given back, so anything that later re-opens the touch
                # stack (a restart-free reconfigure, a test, an orderly
                # shutdown) finds it busy.
                try:
                    owned_irq.close()
                except Exception:
                    pass

    def _loop(self, irq) -> None:
        while not self._stop_event.is_set():
            self._poll_noncomposited()
            self._poll_surface()
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
            self._poll_surface()
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
            elif action.kind == ACTION_WAKE and self._on_wake:
                self._on_wake()
            elif action.kind == ACTION_VOLUME_UP and self._on_volume_up:
                self._on_volume_up()
            elif action.kind == ACTION_VOLUME_DOWN and self._on_volume_down:
                self._on_volume_down()
            elif action.kind == ACTION_MUTE_TOGGLE and self._on_mute_toggle:
                self._on_mute_toggle()
            elif action.kind == ACTION_DISMISS_OVERLAY and self._on_dismiss_overlay:
                self._on_dismiss_overlay()
            elif action.kind == ACTION_SET_PRESSED_ZONE and self._on_set_pressed_zone:
                self._on_set_pressed_zone(action.zone, action.index)
            elif action.kind == ACTION_ZONE_TAP and self._on_zone_tap:
                self._on_zone_tap(action.zone, action.index)
