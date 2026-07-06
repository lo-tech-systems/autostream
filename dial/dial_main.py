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
from dial_volume import enqueue_delta, enqueue_mute_toggle, start_volume_worker


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

    # ---- Shared nudge callbacks (passed to both encoder and control socket) ----

    def nudge_up() -> int:
        http_server.confirm_volume()
        delta = http_server.step_percent
        enqueue_delta(delta)
        return delta

    def nudge_down() -> int:
        delta = -http_server.step_percent
        enqueue_delta(delta)
        return delta

    def nudge_delta(delta: int) -> int:
        if delta > 0:
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
        button = None
        if setup_rotary_encoder is not None:
            encoder = setup_rotary_encoder(cfg.clk_gpio, cfg.dt_gpio, nudge_up, nudge_down)

        def on_press() -> None:
            enqueue_mute_toggle()

        if setup_button is not None and cfg.sw_gpio is not None:
            button = setup_button(cfg.sw_gpio, on_press)

        while not shutdown_event.wait(5):
            led.set_playing() if get_playing_targets() else led.set_idle()
    finally:
        stop_playing_browser()
        display.stop()
        control_server.stop()
        http_server._server.shutdown()


if __name__ == '__main__':
    main()
