"""dial_display_adafruit.py — ST7735S SPI backend behind the display manager interface.

Fixed v1 hardware profile only: Raspberry Pi SPI0, no GRAM offsets, no
BGR/invert, no alternate wiring. Hardware imports (board, busio, digitalio,
adafruit_rgb_display) happen only inside open(), never at module import time,
so a display-disabled dial never touches SPI/GPIO and starts normally even
when the Adafruit package is not installed.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging

from dial_display import DisplayBackend

_SPI_CLOCK_HZ = 16_000_000

# Fixed v1 wiring profile (Raspberry Pi SPI0). Blinka exposes Raspberry Pi pins
# with different aliases across releases/boards, so resolve each BCM pin through
# the common names instead of assuming one board module shape.
_DC_GPIO = 25
_RESET_GPIO = 24
_CS_GPIO = 8
_BACKLIGHT_GPIO = 18

# The ST7735S driver's hardcoded init sets MADCTL=0x60 (MV|MX), so the
# controller itself scans in LANDSCAPE: after the axis exchange the CASET
# "column" register addresses the physical 160-px axis (162 GRAM addresses)
# and RASET the 128-px axis (132 addresses). The driver must therefore be
# constructed with landscape dimensions (width=160, height=128) and rotation=0,
# and each pre-rendered 160x128 frame is sent as-is in a single full-screen
# write — every pixel, background included, is overwritten on every update.
#
# (Configuring the common-sense-looking portrait 128x160 + rotation=90 instead
# writes only 128 of the 160 physical columns — leaving an unfilled stripe —
# and overflows the 132-address row register, mangling the image.)
#
# This panel's visible area starts at GRAM 0,0 — no green-tab-style offsets
# (confirmed on hardware: non-zero offsets shift the image). Set _ROTATION=180
# if the image is upside down for the chosen mounting (the driver rotates the
# frame in software; dimensions are unchanged).
_PANEL_WIDTH = 160
_PANEL_HEIGHT = 128
_X_OFFSET = 0
_Y_OFFSET = 0
_ROTATION = 0
_BACKGROUND_RGB = (14, 40, 65)


def _board_pin(board_module, gpio: int, *aliases: str):
    names = (f"GPIO{gpio}", f"D{gpio}", *aliases)
    for name in names:
        if hasattr(board_module, name):
            return getattr(board_module, name)
    raise AttributeError(
        f"board module has no supported alias for GPIO{gpio} "
        f"(tried {', '.join(names)})"
    )


def _claim_digital_out(digitalio_module, pin, label: str):
    try:
        return digitalio_module.DigitalInOut(pin)
    except Exception as e:
        raise RuntimeError(f"claim {label} failed: {e}") from e


def _claim_chip_select_or_none(digitalio_module, pin):
    try:
        return digitalio_module.DigitalInOut(pin)
    except Exception as e:
        if "busy" in str(e).lower():
            logging.info(
                "dial display: GPIO8/CE0 chip-select busy; using SPI hardware chip-select"
            )
            return None
        raise RuntimeError(f"claim GPIO8/CE0 chip-select failed: {e}") from e


def _fit_image_to_panel(image, width: int, height: int):
    if getattr(image, "size", None) == (width, height):
        return image

    try:
        from PIL import Image

        img = image.convert("RGB")
        try:
            resample = Image.Resampling.LANCZOS
        except AttributeError:
            resample = Image.LANCZOS
        img.thumbnail((width, height), resample)
        canvas = Image.new("RGB", (width, height), _BACKGROUND_RGB)
        canvas.paste(img, ((width - img.width) // 2, (height - img.height) // 2))
        logging.warning(
            "dial display: adapted image from %s to panel size %dx%d",
            getattr(image, "size", "unknown"), width, height,
        )
        return canvas
    except Exception:
        return image


def _solid_background_image():
    from PIL import Image

    return Image.new("RGB", (_PANEL_WIDTH, _PANEL_HEIGHT), _BACKGROUND_RGB)


class AdafruitST7735SBackend(DisplayBackend):
    name = "adafruit_st7735s"
    width = _PANEL_WIDTH
    height = _PANEL_HEIGHT

    def __init__(self) -> None:
        self._display = None
        self._backlight = None

    def open(self) -> None:
        import board
        import busio
        import digitalio
        from adafruit_rgb_display.st7735 import ST7735S

        try:
            spi = busio.SPI(
                clock=_board_pin(board, 11, "SCLK"),
                MOSI=_board_pin(board, 10, "MOSI"),
                MISO=_board_pin(board, 9, "MISO"),
            )
        except Exception as e:
            raise RuntimeError(f"open SPI0 failed: {e}") from e

        cs = _claim_chip_select_or_none(digitalio, _board_pin(board, _CS_GPIO, "CE0"))
        dc = _claim_digital_out(digitalio, _board_pin(board, _DC_GPIO), "GPIO25 data-command")
        reset = _claim_digital_out(digitalio, _board_pin(board, _RESET_GPIO), "GPIO24 reset")
        backlight = _claim_digital_out(digitalio, _board_pin(board, _BACKLIGHT_GPIO), "GPIO18 backlight")

        self._display = ST7735S(
            spi, dc, cs,
            rst=reset,
            width=_PANEL_WIDTH,
            height=_PANEL_HEIGHT,
            baudrate=_SPI_CLOCK_HZ,
            polarity=0,
            phase=0,
            rotation=_ROTATION,
            bl=backlight,
            x_offset=_X_OFFSET,
            y_offset=_Y_OFFSET,
        )

        self._backlight = backlight

    def close(self) -> None:
        if self._backlight is not None:
            try:
                self._backlight.value = False
            except Exception:
                pass
            try:
                self._backlight.deinit()
            except Exception:
                pass
            self._backlight = None
        self._display = None

    def clear(self) -> None:
        if self._display is None:
            return
        self._display.image(_fit_image_to_panel(_solid_background_image(), self.width, self.height))

    def display(self, image) -> None:
        if self._display is None:
            return
        self._display.image(_fit_image_to_panel(image, self.width, self.height))

    def sleep(self) -> None:
        if self._display is None:
            return
        # Backlight off first: the panel goes dark even if the SPI frame
        # write below fails.
        if self._backlight is not None:
            try:
                self._backlight.value = False
            except Exception:
                pass
        from PIL import Image

        black = Image.new("RGB", (_PANEL_WIDTH, _PANEL_HEIGHT), (0, 0, 0))
        self._display.image(_fit_image_to_panel(black, self.width, self.height))

    def wake(self) -> None:
        if self._display is None:
            return
        if self._backlight is not None:
            try:
                self._backlight.value = True
            except Exception:
                pass
