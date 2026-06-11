"""dial_led.py — Single LED driver (DR-6).

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

LED is optional; pass gpio=None (or leave led_gpio blank in config) for
a fully no-op instance.
"""
from __future__ import annotations

import logging
import threading


class DialLED:
    def __init__(self, gpio: int | None = None) -> None:
        self._led = None
        if gpio is None:
            return
        try:
            from gpiozero import LED  # type: ignore[import]
            self._led = LED(gpio)
        except Exception as e:
            logging.debug("LED init skipped (gpio=%s): %s", gpio, e)

    def set_playing(self) -> None:
        if self._led:
            self._led.on()

    def set_idle(self) -> None:
        if self._led:
            self._led.off()

    def flash_clamped(self) -> None:
        """Two-cycle blink to indicate boundary volume (DR-6)."""
        if not self._led:
            return
        threading.Thread(target=self._blink, daemon=True).start()

    def _blink(self) -> None:
        self._led.blink(on_time=0.15, off_time=0.15, n=2, background=False)
        # Main loop's set_playing/set_idle call (every 5 s) restores correct state.
