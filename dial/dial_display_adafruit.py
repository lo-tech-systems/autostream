"""dial_display_adafruit.py — ST7735S SPI backend behind the display manager interface.

Fixed v1 hardware profile only: Raspberry Pi SPI0, no offsets, no BGR/invert,
no alternate wiring. Hardware imports (board, busio, digitalio,
adafruit_rgb_display) happen only inside open(), never at module import time,
so a display-disabled dial never touches SPI/GPIO and starts normally even
when the Adafruit package is not installed.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging

from dial_display import DisplayBackend

_SPI_CLOCK_HZ = 16_000_000

# Fixed v1 wiring profile (Raspberry Pi SPI0). This target's Blinka board
# module exposes SPI0/GPIO pins as board.GPIOxx rather than board.Dxx —
# confirmed against the physical hardware import check ("board SPI: 11 10").
_DC_GPIO = 25
_RESET_GPIO = 24
_CS_GPIO = 8
_BACKLIGHT_GPIO = 18


class AdafruitST7735SBackend(DisplayBackend):
    name = "adafruit_st7735s"
    width = 128
    height = 160

    def __init__(self) -> None:
        self._display = None
        self._backlight = None

    def open(self) -> None:
        import board
        import busio
        import digitalio
        from adafruit_rgb_display.st7735 import ST7735S
        from gpiozero import LED

        spi = busio.SPI(clock=board.GPIO11, MOSI=board.GPIO10, MISO=board.GPIO9)
        cs = digitalio.DigitalInOut(board.GPIO8)
        dc = digitalio.DigitalInOut(board.GPIO25)
        reset = digitalio.DigitalInOut(board.GPIO24)

        self._display = ST7735S(
            spi, dc, cs,
            rst=reset,
            width=self.width,
            height=self.height,
            baudrate=_SPI_CLOCK_HZ,
            polarity=0,
            phase=0,
            rotation=0,
        )

        # Backlight is owned here, separate from the Adafruit constructor —
        # on after a successful open, off on close/disable.
        try:
            self._backlight = LED(_BACKLIGHT_GPIO)
            self._backlight.on()
        except Exception as e:
            logging.warning("dial display: backlight setup failed (GPIO%d): %s", _BACKLIGHT_GPIO, e)
            self._backlight = None

    def close(self) -> None:
        if self._backlight is not None:
            try:
                self._backlight.off()
            except Exception:
                pass
            try:
                self._backlight.close()
            except Exception:
                pass
            self._backlight = None
        self._display = None

    def clear(self) -> None:
        if self._display is None:
            return
        self._display.fill(0)

    def display(self, image) -> None:
        if self._display is None:
            return
        self._display.image(image)
