#!/usr/bin/env python3
"""dial_main.py — autostream dial service entry point.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
import threading
import time

from dial_config import load_config
from dial_control import DialControlServer
from dial_http_server import (
    ADMIN_CMD,
    VERSION,
    DialHTTPServer,
    NoOpDisplayStatusProvider,
    _announce_self,
)
from dial_led import DialLED
from dial_mdns import (
    get_display_targets,
    get_playing_targets,
    mark_display_target_unauthorized,
    start_playing_browser,
    stop_playing_browser,
)
from dial_target_status import enrich_targets
from dial_volume import enqueue_delta, enqueue_mute, is_muted, start_volume_worker


def _configure_logging() -> None:
    level_name = os.environ.get('APP_LOG_LEVEL', 'INFO').strip().upper()
    level = getattr(logging, level_name, logging.INFO)
    if not isinstance(level, int):
        level = logging.INFO
    log_file = "/var/log/autostream/autostream-dial.log"
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    logging.basicConfig(
        level=level,
        format="%(asctime)s: %(message)s",
        datefmt="%d-%b-%y %H:%M:%S",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout),
        ],
    )
    # Suppress library noise at INFO; still visible at DEBUG.
    logging.getLogger('gpiozero').setLevel(logging.WARNING)
    logging.getLogger('lgpio').setLevel(logging.WARNING)


def _reconcile_update_timer(auto_update: bool) -> None:
    """Ensure the systemd timer matches the persisted auto_update value.

    Called at every startup to recover from crashes between config save and
    timer activation (POST /configure step 3→5) where rollback never ran.
    Non-fatal — a failure must never prevent the service from starting.
    """
    verb = "enable" if auto_update else "disable"
    try:
        r = subprocess.run(
            ["sudo", ADMIN_CMD, "toggle-dial-update-timer", verb],
            timeout=10,
        )
        if r.returncode != 0:
            logging.warning(
                "startup: timer reconciliation failed (rc=%d, verb=%s) — timer state may be stale",
                r.returncode, verb,
            )
    except Exception as e:
        logging.warning(
            "startup: timer reconciliation raised %s: %s — continuing",
            type(e).__name__, e,
        )


def _build_touch_source(cfg, display, confirm_presence=None):
    """Construct and wire a TouchEventSource for cfg.display against the
    already-built *display* manager.

    Every import here is deferred to inside this function, exactly like
    dial_display.create_dial_display() is deferred inside main() — in
    particular, dial_display_compositor (needed here for OverlayState) pulls
    in Pillow at module import time, so hoisting any of these imports to
    module level would defeat the same ImportError isolation the display
    stack already gets. The caller wraps this whole call in its own
    try/except so a missing gpiozero/SPI/I2C library, or any other
    construction failure, degrades to no-touch without taking the display
    or volume control down with it.
    """
    from dial_display_compositor import OverlayState
    from dial_display_profiles import get_profile
    from dial_touch import TouchEventSource, TouchStateMachine
    from dial_touch_controllers import get_controller
    from dial_touch_drivers import open_driver
    from dial_touch_filter import DEFAULT_Z_THRESHOLD, TouchFilter
    from dial_touch_layout import TouchZone

    # Any deliberate contact with the screen proves physical presence — the
    # reveal-then-arm scheme (see dial_touch.py) means a first touch may only
    # ever reveal the overlay and never arm/actuate anything, so confirmation
    # must not wait for an armed zone. on_reveal_overlay fires on that very
    # first touch-down; on_set_pressed_zone fires whenever a press arms
    # (either immediately, if the overlay was already visible, or later via
    # overlay_live()). Together they cover every contact. confirm_presence is
    # optional so callers/tests that don't care about recovery can omit it.
    _confirm_presence = confirm_presence or (lambda: None)

    controller = get_controller(cfg.display.touch_type)
    profile = get_profile(cfg.display.screen_type)
    driver = open_driver(controller.driver_tag)
    # ft6206 (capacitive) leaves z_threshold unset — it reports already-
    # "touching" samples with no meaningful analog pressure, so the
    # threshold check is effectively a no-op for it (see
    # dial_touch_drivers.FT6206Driver). TouchFilter still needs *some* int
    # threshold to compare against, so fall back to its own default.
    z_threshold = (
        controller.z_threshold if controller.z_threshold is not None else DEFAULT_Z_THRESHOLD
    )
    touch_filter = TouchFilter(profile.width, profile.height, z_threshold=z_threshold)
    state_machine = TouchStateMachine(profile.width, profile.height)

    def on_reveal_overlay() -> None:
        _confirm_presence()
        display.notify_touch_activity()
        # muted is read from the belief (dial_volume.is_muted()) rather than
        # left at the tri-state default so a reveal that follows a prior
        # mute (from the physical button, or an earlier touch session)
        # shows the correct glyph on its very first frame.
        display.set_overlay(OverlayState(visible=True, muted=is_muted()))
        # The repaint thread services the overlay signal well ahead of any
        # human-perceptible delay; treating "signaled" as "rendered" here
        # (rather than blocking on the repaint thread's actual SPI push)
        # keeps touch dispatch decoupled from frame latency, matching the
        # rest of this feature's lock-order discipline.
        touch_source.overlay_live()

    def on_dismiss_overlay() -> None:
        display.set_overlay(OverlayState(visible=False))

    def on_set_pressed_zone(zone) -> None:
        _confirm_presence()
        display.notify_touch_activity()
        display.set_overlay(OverlayState(visible=True, pressed=zone, muted=is_muted()))

    def on_volume_up() -> None:
        display.notify_touch_activity()
        enqueue_delta(cfg.step_percent)

    def on_volume_down() -> None:
        display.notify_touch_activity()
        enqueue_delta(-cfg.step_percent)

    def on_mute_toggle() -> None:
        display.notify_touch_activity()
        # Flip the belief and repaint the glyph immediately, on the same
        # frame as the press — enqueue_mute() does no network I/O and takes
        # no DialDisplay lock (see its docstring), so this stays as cheap as
        # the volume callbacks above. on_set_pressed_zone() always runs
        # immediately before this for the MUTE zone (see
        # TouchStateMachine._arm), so the overlay is already visible with
        # pressed=TouchZone.MUTE; this call only needs to update muted.
        muted = enqueue_mute()
        display.set_overlay(OverlayState(visible=True, pressed=TouchZone.MUTE, muted=muted))

    touch_source = TouchEventSource(
        driver, touch_filter, state_machine,
        on_reveal_overlay=on_reveal_overlay,
        on_volume_up=on_volume_up,
        on_volume_down=on_volume_down,
        on_mute_toggle=on_mute_toggle,
        on_dismiss_overlay=on_dismiss_overlay,
        on_set_pressed_zone=on_set_pressed_zone,
        get_noncomposited_generation=display.noncomposited_generation,
    )
    return touch_source


def main() -> None:
    _configure_logging()

    shutdown_event = threading.Event()

    def _on_sigterm(sig, frame):
        logging.info("autostream-dial stopping")
        shutdown_event.set()

    def _on_sigint(sig, frame):
        logging.info("autostream-dial stopping")
        shutdown_event.set()

    signal.signal(signal.SIGTERM, _on_sigterm)
    signal.signal(signal.SIGINT, _on_sigint)

    cfg = load_config()
    logging.info("autostream-dial starting (version %s, uuid %s)", VERSION, cfg.uuid)

    _reconcile_update_timer(cfg.auto_update)
    _announce_self(cfg)

    led = DialLED(cfg.led_gpio)

    # Imported lazily so a Pillow/display-stack import failure (e.g. an
    # incomplete apt install) degrades to a no-op display rather than taking
    # down the whole service — volume control must not depend on Pillow.
    try:
        from dial_display import create_dial_display
        display = create_dial_display(cfg, get_display_targets, mark_display_target_unauthorized)
    except ImportError as e:
        logging.warning("dial display: display stack unavailable (%s) — display disabled", e)
        display = NoOpDisplayStatusProvider()

    http_server = DialHTTPServer(cfg, display_status_provider=display)
    http_server.start()

    if cfg.pin:
        http_server.begin_recovery_window()

    start_playing_browser(shutdown_event=shutdown_event)
    display.start()
    start_volume_worker(cfg, get_playing_targets, led)

    # Touch requires a screen (a product decision) — built AFTER the display
    # and only when the config says both a screen is fitted and a touch
    # controller is selected. `hasattr(display, "set_overlay")` excludes the
    # NoOpDisplayStatusProvider fallback above: if the display stack itself
    # failed to import, there is nothing for touch to draw an overlay onto,
    # so touch must not start either, regardless of what cfg.display says.
    # Construction failures here (missing gpiozero, no SPI/I2C, an unknown
    # driver tag, ...) degrade to no-touch and log it — touch must never
    # prevent the dial from starting or affect volume control, exactly like
    # the display stack's own isolation above.
    touch_source = None
    if (
        cfg.display.fitted
        and cfg.display.touch_type != "none"
        and hasattr(display, "set_overlay")
    ):
        try:
            touch_source = _build_touch_source(
                cfg, display, confirm_presence=http_server.confirm_volume
            )
            touch_source.start()
        except Exception as e:
            logging.warning("dial touch: touch stack unavailable (%s) — touch disabled", e)
            touch_source = None

    # ---- Shared nudge callbacks (passed to both encoder and control socket) ----

    def nudge_up() -> int:
        http_server.confirm_volume()
        delta = http_server.step_percent
        enqueue_delta(delta)
        return delta

    def nudge_down() -> int:
        http_server.confirm_volume()
        delta = -http_server.step_percent
        enqueue_delta(delta)
        return delta

    def nudge_delta(delta: int) -> int:
        if delta != 0:
            http_server.confirm_volume()
        enqueue_delta(delta)
        return delta

    # ---- Local control socket ----

    control_server = DialControlServer(
        get_runtime_status=http_server.get_runtime_status,
        get_targets=get_playing_targets,
        enrich_targets=enrich_targets,
        nudge_up=nudge_up,
        nudge_down=nudge_down,
        nudge_delta=nudge_delta,
        software_version=VERSION,
    )

    # Import GPIO helpers lazily — non-Pi hosts can still run the HTTP service.
    try:
        from autostream_rpi import setup_rotary_encoder, setup_button  # type: ignore[import]
    except ImportError:
        setup_rotary_encoder = None  # type: ignore[assignment]
        setup_button = None  # type: ignore[assignment]

    # Socket startup failures are fatal — let them escape so systemd can retry.
    # The finally block stops the control server and HTTP server on any exit.
    try:
        control_server.start()

        # Store encoder and button in long-lived locals — prevents GC from
        # finalising the underlying lgpio device handle and silently stopping
        # interrupts.
        encoder = None
        if cfg.clk_gpio is None or cfg.dt_gpio is None:
            # A screen-only build has no rotary encoder wired up — this is a
            # deliberate config choice, not a hardware fault, so it gets an
            # INFO line rather than the GPIO-init warning below.
            logging.info("rotary encoder not configured; skipping")
        elif setup_rotary_encoder is not None:
            encoder = setup_rotary_encoder(cfg.clk_gpio, cfg.dt_gpio, nudge_up, nudge_down)

        def on_press() -> None:
            http_server.confirm_volume()
            enqueue_mute()

        button = None
        if cfg.sw_gpio is None:
            logging.info("button not configured; skipping")
        elif setup_button is not None:
            button = setup_button(cfg.sw_gpio, on_press)

        # Runtime-derived, not config-derived: a dial with clk/dt/sw_gpio set
        # but whose GPIO init failed (setup_rotary_encoder/setup_button
        # returning None) must not claim it can confirm presence, and
        # neither must a dial whose touch stack raised above (touch_source
        # stays None on that path). See DialHTTPServer.set_can_confirm_presence.
        http_server.set_can_confirm_presence(
            encoder is not None or button is not None or touch_source is not None
        )

        while not shutdown_event.wait(5):
            led.set_playing() if get_playing_targets() else led.set_idle()
    finally:
        stop_playing_browser()
        if touch_source is not None:
            touch_source.stop()
        display.stop()
        control_server.stop()
        http_server._server.shutdown()


if __name__ == '__main__':
    main()
