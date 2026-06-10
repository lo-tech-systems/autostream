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
import time

from dial_config import load_config
from dial_encoder import RotaryEncoderHandler
from dial_http_server import ADMIN_CMD, VERSION, DialHTTPServer, _announce_self
from dial_led import DialLED
from dial_mdns import get_playing_targets, start_playing_browser
from dial_volume import enqueue_delta, start_volume_worker


def _configure_logging() -> None:
    level = os.environ.get('APP_LOG_LEVEL', 'INFO').upper()
    logging.basicConfig(
        level=level,
        format='%(levelname)s %(name)s %(message)s',
        stream=sys.stderr,
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

    def _on_sigterm(sig, frame):
        logging.info("autostream-dial stopping")
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _on_sigterm)

    cfg = load_config()
    logging.info("autostream-dial starting (version %s, uuid %s)", VERSION, cfg.uuid)

    _reconcile_update_timer(cfg.auto_update)
    _announce_self(cfg)

    led = DialLED(cfg.led_gpio)

    http_server = DialHTTPServer(cfg)
    http_server.start()

    if cfg.pin:
        http_server.begin_recovery_window()

    start_playing_browser()
    start_volume_worker(cfg, get_playing_targets, led)

    def on_cw() -> None:
        http_server.confirm_volume()
        enqueue_delta(http_server.step_percent)

    def on_ccw() -> None:
        enqueue_delta(-http_server.step_percent)

    # Store encoder handler — prevents GC of the lgpio device handle.
    encoder = RotaryEncoderHandler(cfg.clk_gpio, cfg.dt_gpio, on_cw, on_ccw)

    while True:
        led.set_playing() if get_playing_targets() else led.set_idle()
        time.sleep(5)


if __name__ == '__main__':
    main()
