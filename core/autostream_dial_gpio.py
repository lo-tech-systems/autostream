"""autostream_dial_gpio.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

GPIO helpers for dial hardware: rotary encoder and button setup via
gpiozero.

Split out of ``core/autostream_rpi.py``, which re-exports these names for
existing importers. Dial-hardware GPIO wiring belongs with a dial adapter,
not system/CPU facts. Pure code motion -- no logic changed from the
original module.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def setup_rotary_encoder(clk: int, dt: int, on_cw, on_ccw):
    """Attach interrupt-driven callbacks to a rotary encoder.

    Returns the gpiozero.RotaryEncoder instance (caller must retain a
    reference to prevent garbage collection).  Returns None if gpiozero is
    unavailable or the GPIO cannot be initialised.
    """
    try:
        from gpiozero import RotaryEncoder
        enc = RotaryEncoder(clk, dt, wrap=False, max_steps=0)
        enc.when_rotated_clockwise = on_cw
        enc.when_rotated_counter_clockwise = on_ccw
        return enc
    except Exception as e:
        logger.warning("setup_rotary_encoder: GPIO init failed: %s", e)
        return None


def setup_button(gpio: int, on_press, bounce_time: float = 0.1):
    """Attach an interrupt-driven press callback to a GPIO button.

    Returns the gpiozero.Button instance (caller must retain a reference to
    prevent garbage collection).  Returns None if gpiozero is unavailable or
    the GPIO cannot be initialised.
    """
    try:
        from gpiozero import Button
        btn = Button(gpio, pull_up=True, bounce_time=bounce_time)
        btn.when_pressed = on_press
        return btn
    except Exception as e:
        logger.warning("setup_button: GPIO init failed: %s", e)
        return None
