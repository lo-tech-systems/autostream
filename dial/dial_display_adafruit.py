"""dial_display_adafruit.py — profile-driven Adafruit SPI display backend.

Panel geometry (dimensions, offsets, rotation, baudrate) comes from a
DisplayProfile (see dial_display_profiles.py); wiring (which BCM pins carry
DC/reset/CS/backlight) is fixed across all profiles and stays in this
module. Hardware imports (board, digitalio, adafruit_rgb_display) happen
only inside open(), never at module import time, so a display-disabled dial
never touches SPI/GPIO and starts normally even when the Adafruit package is
not installed.

The SPI0 bus itself is NOT constructed here: it is process-lifetime and
shared with a future touch controller, so dial_spi_bus.py owns constructing
it (lazily, on first use) and this backend only ever borrows it via
dial_spi_bus.get_bus(). close() never deinits it — see close() below.
dial_spi_bus is pure Python with no hardware imports at module scope, so
importing it here at module level is safe under the same discipline as
dial_display_profiles.py.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging

import dial_spi_bus
from dial_display import DisplayBackend
from dial_display_profiles import DEFAULT_PROFILE_KEY, DisplayProfile, backend_name_for, get_profile

# Fixed wiring (Raspberry Pi SPI0), shared across every profile — this is
# board wiring, not panel geometry, so it is not part of the profile table.
# Blinka exposes Raspberry Pi pins with different aliases across
# releases/boards, so resolve each BCM pin through the common names instead
# of assuming one board module shape.
_DC_GPIO = 25
_RESET_GPIO = 24
_CS_GPIO = 8
_BACKLIGHT_GPIO = 18

_BACKGROUND_RGB = (14, 40, 65)

# Driver tag -> (module path, class name) for lazy import inside open().
_DRIVER_MODULES = {
    "st7735s": ("adafruit_rgb_display.st7735", "ST7735S"),
    "st7789": ("adafruit_rgb_display.st7789", "ST7789"),
    "ili9341": ("adafruit_rgb_display.ili9341", "ILI9341"),
}

# Only ST7735S's constructor in the pinned adafruit-circuitpython-rgb-display
# accepts bl= and drives the backlight pin itself; ST7789 and ILI9341 do not
# take a backlight kwarg at all. For those tags this backend claims the
# backlight pin directly and drives it high on open()/wake() and low on
# close()/sleep(), matching what ST7735S's bl= does internally.
_DRIVER_OWNS_BACKLIGHT = {"st7735s"}

# ILI9341's constructor in the pinned library takes no GRAM offset arguments
# at all (its init table fixes the window), unlike ST7735S and ST7789 which
# both accept x_offset/y_offset. Passing them anyway is a TypeError at open(),
# so the offsets are only supplied to the drivers that declare them. Profiles
# for offset-less drivers must therefore leave x_offset/y_offset at 0.
_DRIVER_TAKES_OFFSETS = {"st7735s", "st7789"}


def _board_pin(board_module, gpio: int, *aliases: str):
    """Delegates to dial_spi_bus.board_pin — one definition, shared by
    every module that has to resolve a BCM number to a board alias."""
    return dial_spi_bus.board_pin(board_module, gpio, *aliases)


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


def _resolve_driver_class(driver_tag: str):
    try:
        module_path, class_name = _DRIVER_MODULES[driver_tag]
    except KeyError:
        raise RuntimeError(f"unknown display driver tag {driver_tag!r}") from None
    import importlib

    module = importlib.import_module(module_path)
    return getattr(module, class_name)


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


def _solid_background_image(width: int, height: int):
    from PIL import Image

    return Image.new("RGB", (width, height), _BACKGROUND_RGB)


# Logged at most once per process: a missing numpy is a one-time
# misconfiguration, not something worth a warning on every frame.
_numpy_missing_logged = False


def _pack_rgb565(image) -> bytes | None:
    """Pack a PIL RGB image straight to big-endian RGB565 bytes ourselves.

    The pinned adafruit_rgb_display driver's own image_to_data() helper does
    this with numpy too, but then finishes with
    ``numpy.dstack(...).flatten().tolist()`` followed by ``bytes(...)``,
    materialising a 153,600-element Python list at 320x240. Packing straight
    to bytes with ``.astype(">u2").tobytes()`` skips that list entirely and
    measures ~6x faster (2.5ms/9.4ms vs 16.2ms/57.8ms at 160x128/320x240 on a
    Pi 2B), producing byte-identical output.

    numpy is imported lazily, here inside the function, not because it is
    hardware but to match this module's lazy-import discipline (see the
    module docstring) so the module still imports cleanly on a machine
    without numpy.

    Returns None if numpy is unavailable, or if packing fails for any other
    reason (e.g. *image* is not actually image-like), so the caller can fall
    back to the driver's own image() path — slower, but always correct.
    """
    global _numpy_missing_logged
    try:
        import numpy
    except ImportError:
        if not _numpy_missing_logged:
            logging.warning(
                "dial display: python3-numpy is not installed; falling back to "
                "the driver's per-pixel frame conversion, which is hundreds of "
                "milliseconds to seconds slower per frame. Install "
                "python3-numpy to fix this."
            )
            _numpy_missing_logged = True
        return None

    try:
        data = numpy.asarray(image.convert("RGB"), dtype=numpy.uint16)
        color = ((data[:, :, 0] & 0xF8) << 8) | ((data[:, :, 1] & 0xFC) << 3) | (data[:, :, 2] >> 3)
        return color.astype(">u2").tobytes()
    except Exception:
        return None


class AdafruitDisplayBackend(DisplayBackend):
    def __init__(self, profile: DisplayProfile) -> None:
        self._profile = profile
        self.name = backend_name_for(profile)
        self.width = profile.width
        self.height = profile.height
        self._display = None
        self._backlight = None
        self._spi = None

    def open(self) -> None:
        profile = self._profile
        # Resolve the driver class before touching any hardware module, so
        # an unknown/misconfigured driver tag fails fast with a clear error
        # instead of a confusing missing-hardware-module traceback.
        driver_class = _resolve_driver_class(profile.driver_tag)

        import board
        import digitalio

        # The bus is process-lifetime and shared with a future touch
        # controller — dial_spi_bus owns constructing (and only
        # constructing) it exactly once; this backend never tears it down.
        try:
            spi = dial_spi_bus.get_bus()
        except Exception as e:
            raise RuntimeError(f"open SPI0 failed: {e}") from e
        self._spi = spi

        cs = _claim_chip_select_or_none(digitalio, _board_pin(board, _CS_GPIO, "CE0"))
        dc = _claim_digital_out(digitalio, _board_pin(board, _DC_GPIO), "GPIO25 data-command")
        reset = _claim_digital_out(digitalio, _board_pin(board, _RESET_GPIO), "GPIO24 reset")

        driver_owns_backlight = profile.driver_tag in _DRIVER_OWNS_BACKLIGHT
        backlight = _claim_digital_out(digitalio, _board_pin(board, _BACKLIGHT_GPIO), "GPIO18 backlight")

        kwargs = dict(
            rst=reset,
            width=profile.width,
            height=profile.height,
            baudrate=profile.baudrate,
            polarity=0,
            phase=0,
            rotation=profile.rotation,
        )
        if profile.driver_tag in _DRIVER_TAKES_OFFSETS:
            kwargs["x_offset"] = profile.x_offset
            kwargs["y_offset"] = profile.y_offset
        if driver_owns_backlight:
            kwargs["bl"] = backlight

        self._display = driver_class(spi, dc, cs, **kwargs)

        if not driver_owns_backlight:
            # The driver has no bl= kwarg (ST7789/ILI9341 in the pinned
            # library) — drive the shared backlight pin ourselves so the
            # panel lights up on open(), matching ST7735S's bl= behaviour.
            backlight.switch_to_output(value=True)

        self._backlight = backlight

    def close(self) -> None:
        # Deliberately does NOT deinit or release self._spi: the bus is
        # owned by dial_spi_bus for the lifetime of the process, not by this
        # backend. A screen_type swap (close() on the old profile's backend
        # followed by open() on the new one) must not tear the bus out from
        # under a touch controller sharing it — close() only releases what
        # this backend uniquely owns (the backlight pin and the driver
        # object).
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
        self._spi = None

    def _push_frame(self, image) -> None:
        """Push one full-panel frame, packing RGB565 ourselves when possible.

        The driver's own image() does the same 565 conversion internally,
        but — without numpy — via a per-pixel Python loop, and — with numpy
        — via a helper that still materialises a large intermediate Python
        list (see _pack_rgb565's docstring). Packing here and writing
        straight to the driver's _block() window-write primitive skips both.

        _block is a private attribute of a third-party class, so its
        absence (a future library version renaming/removing it) is guarded
        with getattr rather than assumed: that degrades to the slow-but-
        correct self._display.image() path instead of crashing.
        """
        fitted = _fit_image_to_panel(image, self.width, self.height)
        packed = _pack_rgb565(fitted)
        block = getattr(self._display, "_block", None)
        if packed is not None and block is not None:
            block(0, 0, self.width - 1, self.height - 1, packed)
        else:
            self._display.image(fitted)

    def clear(self) -> None:
        if self._display is None:
            return
        image = _solid_background_image(self.width, self.height)
        self._push_frame(image)

    def display(self, image) -> None:
        if self._display is None:
            return
        self._push_frame(image)

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

        black = Image.new("RGB", (self.width, self.height), (0, 0, 0))
        self._push_frame(black)

    def wake(self) -> None:
        if self._display is None:
            return
        if self._backlight is not None:
            try:
                self._backlight.value = True
            except Exception:
                pass


class AdafruitST7735SBackend(AdafruitDisplayBackend):
    """Zero-arg backend bound to the default (today's shipped) profile.

    Kept as its own class, rather than a bare alias, so every existing
    zero-arg call site (create_dial_display(), the test suite) keeps working
    unchanged.
    """

    def __init__(self) -> None:
        super().__init__(get_profile(DEFAULT_PROFILE_KEY))
