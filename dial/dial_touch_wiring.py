"""dial_touch_wiring.py -- what a touch does at the dial.

The touch source (dial_touch_source) turns raw contacts into a few
callbacks: a first touch reveals the overlay or wakes a sleeping panel, a
press arms a zone, a tap acts on it, and the volume and mute zones nudge or
toggle the core.  TouchWiring holds those callbacks, so each reads the
display and core it was built with, and build_touch_source() builds the
hardware side (driver, filter, state machine, axis mapping) and hands the
callbacks to the source.

Any deliberate contact proves physical presence for PIN recovery, so every
callback that follows a contact confirms it first.  The reveal-then-arm
scheme (see dial_touch.py) means a first touch may only ever reveal the
overlay and never arm or actuate anything, so confirmation cannot wait for
an armed zone.

The 180-degree screen rotation is applied to the frame in software, so the
touch sheet is turned the same way; that composes with the profile's own
axis mapping.

Every callback runs on the touch source's thread and none blocks: the
display and core entry points they call are lock-free or take their own
locks, and none does network I/O.

Only dial_touch_layout is imported at module level.  The builder imports
the rest when it runs, like dial_display.create_dial_display() inside
main(), so a missing display stack or touch library degrades to no touch
instead of taking the service down, and importing this module needs no
Pillow.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
from typing import Callable

from dial_touch_layout import BELL_ZONES, CARD_BUTTON_ZONES, TouchZone


class TouchWiring:
    """The touch source's callbacks, bound to one display and one core."""

    def __init__(
        self,
        display,
        core,
        *,
        step: Callable[[], int],
        confirm_presence: Callable[[], None],
        overlay_state: type,
    ) -> None:
        self._display = display
        self._core = core
        self._step = step
        self._confirm = confirm_presence
        self._overlay_state = overlay_state
        self._source = None

    def attach(self, source) -> None:
        """Give the wiring the touch source it reports back to. Called before
        the source starts, so before any callback can run."""
        self._source = source

    def on_wake(self) -> None:
        # A touch on a sleeping panel only wakes it (see
        # TouchStateMachine._on_press). It is still a human touch, so it
        # confirms presence; the repaint thread applies the wake.
        self._confirm()
        self._display.notify_touch_activity()

    def on_reveal_overlay(self) -> None:
        self._confirm()
        self._display.notify_touch_activity()
        # muted is left at the OverlayState default -- the display's own
        # compose-time merge (_effective_overlay_locked) fills it in from
        # the observation store (dial_volume.shown_muted()) for whichever
        # appliance is actually reporting, which is the dial's only source
        # of truth for mute; there is nothing to publish here.
        self._display.set_overlay(self._overlay_state(visible=True))
        # The repaint thread services the overlay signal well ahead of any
        # human-perceptible delay; treating "signaled" as "rendered" here
        # (rather than blocking on the repaint thread's actual SPI push)
        # keeps touch dispatch decoupled from frame latency, matching the
        # rest of this feature's lock-order discipline.
        self._source.overlay_live()

    def on_dismiss_overlay(self) -> None:
        self._display.set_overlay(self._overlay_state(visible=False))

    def on_set_pressed_zone(self, zone, index=None) -> None:
        # Every zone on every screen reports through one channel; the
        # display resolves it against the screen actually showing, so a
        # zone that does not exist there draws nothing. zone=None is the
        # flash-clear.
        self._confirm()
        self._display.notify_touch_activity()
        self._display.set_pressed(zone, index)

    def on_volume_up(self) -> None:
        # The volume step first, THEN notify_touch_activity():
        # notify_touch_activity() sets the repaint signal, and the repaint
        # must see the nudged pending readout value (see
        # dial_volume.enqueue_delta()), not the pre-press one.
        self._core.volume_step(self._step())
        self._display.notify_touch_activity()

    def on_volume_down(self) -> None:
        self._core.volume_step(-self._step())
        self._display.notify_touch_activity()

    def on_mute_toggle(self) -> None:
        self._display.notify_touch_activity()
        # core.mute_toggle() is the same decision the physical button
        # makes: under scope "current" it flips whatever the
        # reporting appliance last reported (read from the observation
        # store, never inferred or persisted here) and echoes the request
        # into that same store so the glyph updates on this frame; under
        # scope "all" it enqueues a fleet toggle the volume worker decides at
        # dispatch instead. Either way this does no network I/O and takes no
        # DialDisplay lock, so this stays as cheap as the volume callbacks
        # above. on_set_pressed_zone() always runs immediately before this
        # for the MUTE zone (see TouchStateMachine._arm) and already
        # recorded the press on the pressed channel.
        self._core.mute_toggle()
        self._display.set_overlay(self._overlay_state(visible=True))

    def on_zone_tap(self, zone, index) -> None:
        # NAME opens the appliance selector (from either the main, repeat
        # or EQ screen); the LIST_* zones act on whichever list-chassis
        # screen (selector, picker or outputs) is open; DOTS cycles the
        # pages (main -> repeat -> eq -> main, skipping one with nothing to
        # show — closing back to main also reveals the main screen's volume
        # overlay on return — see display.cycle_pages()); REPEAT_* act on
        # the repeat screen; EQ_BASS_*/EQ_TREBLE_* act on the EQ page's own
        # bars; IDLE_REPLAY opens the replay picker; any bell (BELL_ZONES) opens the
        # warnings card; IDLE_WIFI opens the idle screen's read-only info
        # page; any card button (CARD_BUTTON_ZONES) goes to the display's
        # card dispatch; OUTPUTS
        # opens the outputs list; OUTPUT_* act on the per-output detail
        # page; ARTWORK hides the main screen's own bands for a few
        # seconds — see dial_touch.py's SURFACES paragraph for how a press
        # ever reaches one of these zones in the first place.
        self._confirm()
        display = self._display
        display.notify_touch_activity()
        if zone == TouchZone.NAME:
            display.open_selector()
        elif zone == TouchZone.LIST_BACK:
            display.close_list()
        elif zone == TouchZone.LIST_DOWN:
            display.list_page(+1)
        elif zone == TouchZone.LIST_UP:
            display.list_page(-1)
        elif zone == TouchZone.LIST_ROW:
            display.list_row_tap(index)
        elif zone == TouchZone.DOTS:
            display.cycle_pages()
        elif zone == TouchZone.EQ_BASS_DOWN:
            display.eq_step("bass", -1)
        elif zone == TouchZone.EQ_BASS_UP:
            display.eq_step("bass", +1)
        elif zone == TouchZone.EQ_TREBLE_DOWN:
            display.eq_step("treble", -1)
        elif zone == TouchZone.EQ_TREBLE_UP:
            display.eq_step("treble", +1)
        elif zone == TouchZone.REPEAT_PLAY:
            display.repeat_toggle_tap()
        elif zone == TouchZone.REPEAT_START:
            display.repeat_start_tap()
        elif zone == TouchZone.REPEAT_STOP:
            display.repeat_stop_tap()
        elif zone == TouchZone.IDLE_REPLAY:
            display.open_picker()
        elif zone in BELL_ZONES:
            display.open_warnings()
        elif zone == TouchZone.IDLE_WIFI:
            display.open_info()
        elif zone in CARD_BUTTON_ZONES:
            display.card_button_tap(zone)
        elif zone == TouchZone.OUTPUTS:
            display.open_outputs()
        elif zone == TouchZone.OUTPUT_BACK:
            display.close_list()
        elif zone == TouchZone.OUTPUT_TOGGLE:
            display.output_toggle_tap()
        elif zone == TouchZone.OUTPUT_UP:
            display.output_volume_tap(+self._step())
        elif zone == TouchZone.OUTPUT_DOWN:
            display.output_volume_tap(-self._step())
        elif zone == TouchZone.ARTWORK:
            display.hide_controls()
            # The session must know the controls are gone: with the
            # controls revealed by touch nothing else would tell it, and a
            # finger must never arm against bands that are no longer drawn.
            self._source.overlay_hidden()


def build_touch_source(cfg, display, core, confirm_presence=None, step_percent=None):
    """Construct and wire a TouchEventSource for cfg.display against the
    already-built *display* manager and *core* (volume and mute go to the
    core).

    The caller wraps this whole call in its own try/except so a missing
    gpiozero/SPI/I2C library, or any other construction failure, degrades to
    no-touch without taking the display or volume control down with it.

    step_percent, when supplied, is a zero-arg callable returning the
    CURRENT step size — main() passes `lambda: http_server.step_percent` so
    a live /configure change is honoured by touch immediately, matching the
    encoder's nudge_up/nudge_down (which already read http_server.step_percent
    rather than the startup cfg). When omitted, the callbacks fall back to
    the startup cfg.step_percent.

    confirm_presence is optional so callers/tests that don't care about
    recovery can omit it.

    The MUTE zone calls core.mute_toggle(), the same call the physical
    button makes, so a touch tap and a button press make identical scope
    decisions.
    """
    from dial_display_views import OverlayState
    from dial_display_profiles import get_profile, layout_context_for
    from dial_touch import TouchStateMachine
    from dial_touch_source import TouchEventSource
    from dial_layout_metrics import metrics_for
    from dial_touch_controllers import get_controller
    from dial_touch_drivers import open_driver
    from dial_touch_filter import DEFAULT_Z_THRESHOLD, TouchFilter

    controller = get_controller(cfg.display.touch_type)
    profile = get_profile(cfg.display.screen_type)
    layout = layout_context_for(cfg.display)
    driver = open_driver(controller.driver_tag)
    # ft6206 (capacitive) leaves z_threshold unset — it reports already-
    # "touching" samples with no meaningful analog pressure, so the
    # threshold check is effectively a no-op for it (see
    # dial_touch_drivers.FT6206Driver). TouchFilter still needs *some* int
    # threshold to compare against, so fall back to its own default.
    z_threshold = (
        controller.z_threshold if controller.z_threshold is not None else DEFAULT_Z_THRESHOLD
    )
    # A 180-degree screen rotation is applied to the frame in software, so
    # the touch sheet has to be turned the same way or presses land
    # diagonally opposite what the user sees. Inverting BOTH axes is what
    # 180 degrees means; it composes with the profile's own axis mapping.
    rotated = bool(cfg.display.rotate)
    touch_filter = TouchFilter(
        layout.logical_width,
        layout.logical_height,
        z_threshold=z_threshold,
        raw_x_min=controller.raw_x_min,
        raw_x_max=controller.raw_x_max,
        raw_y_min=controller.raw_y_min,
        raw_y_max=controller.raw_y_max,
        swap_xy=profile.touch_swap_xy,
        invert_x=profile.touch_invert_x != rotated,
        invert_y=profile.touch_invert_y != rotated,
        physical_size=layout.physical_size,
    )
    touch_metrics = metrics_for(
        layout.logical_width, layout.logical_height,
        mm_per_px=layout.mm_per_px, size_chosen=layout.size_chosen,
    )
    state_machine = TouchStateMachine(
        layout.logical_width, layout.logical_height, metrics=touch_metrics,
        is_asleep=getattr(display, "is_sleeping", None),
    )

    wiring = TouchWiring(
        display, core,
        step=step_percent if step_percent is not None else (lambda: cfg.step_percent),
        confirm_presence=confirm_presence or (lambda: None),
        overlay_state=OverlayState,
    )
    source = TouchEventSource(
        driver, touch_filter, state_machine,
        on_reveal_overlay=wiring.on_reveal_overlay,
        on_wake=wiring.on_wake,
        on_volume_up=wiring.on_volume_up,
        on_volume_down=wiring.on_volume_down,
        on_mute_toggle=wiring.on_mute_toggle,
        on_dismiss_overlay=wiring.on_dismiss_overlay,
        on_set_pressed_zone=wiring.on_set_pressed_zone,
        on_zone_tap=wiring.on_zone_tap,
        get_noncomposited_generation=display.noncomposited_generation,
        # get_touch_surface carries the surface and its flags — see
        # dial_touch_source.TouchEventSource._poll_surface.
        get_touch_surface=getattr(display, "touch_surface", None),
        consume_repeat_close_reveal=getattr(display, "consume_repeat_close_reveal", None),
        axis_signs=(
            profile.touch_swap_xy, profile.touch_invert_x, profile.touch_invert_y
        ),
    )
    wiring.attach(source)
    # Logged on success, not just on failure: without this there is no way
    # to tell from the journal whether the touch stack came up at all, and
    # the axis mapping is the first thing to check when presses land in the
    # wrong place.
    logging.info(
        "dial touch: %s ready on %dx%d logical on %dx%d (raw x %s-%s y %s-%s, swap_xy=%s, "
        "invert x=%s y=%s, rotate=%s)",
        controller.key, layout.logical_width, layout.logical_height,
        profile.width, profile.height,
        controller.raw_x_min, controller.raw_x_max,
        controller.raw_y_min, controller.raw_y_max,
        profile.touch_swap_xy,
        profile.touch_invert_x != rotated, profile.touch_invert_y != rotated,
        rotated,
    )
    return source
