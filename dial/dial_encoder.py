"""dial_encoder.py — Rotary encoder handler using gpiozero.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Uses gpiozero.RotaryEncoder for interrupt-driven quadrature decoding (no
polling).  The instance is kept alive in self._encoder to prevent CPython's
GC from finalising the underlying lgpio device handle and silently stopping
interrupts.  Callers must store the returned RotaryEncoderHandler in a
long-lived variable.
"""
from __future__ import annotations

import logging


class RotaryEncoderHandler:
    """Owns the gpiozero RotaryEncoder device for its lifetime.

    Storing the instance (rather than discarding it) prevents CPython's garbage
    collector from finalising the underlying lgpio device handle and silently
    stopping interrupts.
    """

    def __init__(
        self,
        clk_gpio: int,
        dt_gpio:  int,
        on_cw:    callable,
        on_ccw:   callable,
    ) -> None:
        self._encoder = None
        try:
            from gpiozero import RotaryEncoder  # type: ignore[import]
            enc = RotaryEncoder(
                a=clk_gpio,
                b=dt_gpio,
                wrap=False,
                max_steps=0,
            )
            enc.when_rotated_clockwise         = on_cw
            enc.when_rotated_counter_clockwise = on_ccw
            self._encoder = enc
            logging.debug("encoder: GPIO CLK=%d DT=%d initialised", clk_gpio, dt_gpio)
        except Exception as e:
            # GPIO unavailable: running on a non-Pi host, hardware absent, or
            # lgpio not installed.  Log and continue — HTTP server still works.
            logging.warning("encoder: GPIO init failed (%s) — encoder disabled", e)
