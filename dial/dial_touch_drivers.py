"""dial_touch_drivers.py — lazy hardware touch controller drivers.

Mirrors dial_display_adafruit.py's discipline: hardware imports (board,
digitalio, an SPI/I2C library) happen only inside a driver's open(), never
at module import time, so a machine with no touch hardware/library
installed can still import this module without error. Driver-tag ->
(module, class) resolution happens lazily inside open_driver(), exactly
like dial_display_adafruit._resolve_driver_class().

Two driver tags:
  - "xpt2046" — resistive touch (also covers HR2046/ADS7846 clones), an
    in-repo SPI implementation with no new pip dependency, on its own SPI1
    bus via dial_spi_bus (separate from the display's SPI0).
  - "ft6206" — capacitive touch (FT6206/FT6236) over I2C, using whichever
    adafruit_ft6206 library happens to be installed; imported lazily and
    reported cleanly (RuntimeError, not a bare ImportError traceback) if
    absent. No such dependency is currently pinned in dial/requirements —
    see FT6206Driver.open() for what would need adding.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import dial_spi_bus

# Fixed touch wiring (Raspberry Pi), independent of controller choice.
#
# The controller sits on SPI1 (see dial_spi_bus.TOUCH_BUS), physically
# separate from the display's SPI0 — so no header pin has to carry two
# wires and a frame push can never delay a sample.
#
# Chip select is a PLAIN GPIO driven by this driver, not a hardware CE
# line. Both controllers' CE pins are claimed by the kernel the moment
# their bus is enabled (spi0 CS0/CS1 on GPIO8/GPIO7), so a hardware CE
# cannot be claimed here — and unlike the display, this driver has no
# fallback to hardware chip-select available, because busio.SPI does not
# drive CS at all. It must therefore be a GPIO nothing else owns.
#
# GPIO16 is free for this because the installer parks the SPI1 overlay's
# own chip select on GPIO12 (see installer/dial/helpers.sh enable_spi1).
# That keeps the whole touch harness on physical pins 35-40, one
# contiguous block at the end of the header, which ordinary jumper leads
# can reach without doubling wires onto shared pins.
#
# T_IRQ is the controller's active-low interrupt line, polled/waited-on by
# dial_touch.TouchEventSource.
_TOUCH_CS_GPIO = 16   # plain GPIO, driven by this driver (physical pin 36)
_TOUCH_IRQ_GPIO = 26  # T_IRQ, active-low

# XPT2046 control-byte command set (12-bit mode, single-ended, power-down
# between conversions so T_IRQ stays usable). Byte layout: S=1, A2-A0
# channel select, MODE=0 (12-bit), SER/DFR=1 (single-ended), PD1/PD0=00.
_CMD_X = 0xD0  # channel 5 (X position)
_CMD_Y = 0x90  # channel 1 (Y position)
_CMD_Z1 = 0xB0  # channel 3 (Z1, pressure)
_CMD_Z2 = 0xC0  # channel 4 (Z2, pressure)

# XPT2046 must be clocked slowly and reliably (datasheet max ~2MHz; this is
# a deliberately conservative value, well under the display's much higher
# baudrate) — configured fresh on every acquisition per dial_spi_bus's
# baudrate contract, never assumed left over from the display's transaction.
_XPT2046_BAUDRATE = 1_000_000


class UnknownTouchDriverError(RuntimeError):
    """Raised by open_driver() for a driver_tag with no known implementation."""


def _board_pin(board_module, gpio: int, *aliases: str):
    """Delegates to dial_spi_bus.board_pin — one definition, shared by
    every module that has to resolve a BCM number to a board alias."""
    return dial_spi_bus.board_pin(board_module, gpio, *aliases)


class XPT2046Driver:
    """In-repo resistive touch driver for XPT2046 and its HR2046/ADS7846
    pin-compatible clones. Uses the SPI1 bus constructed by
    dial_spi_bus.get_bus(TOUCH_BUS) — separate from the display's SPI0 —
    and owns nothing but its own chip select.
    """

    def __init__(self) -> None:
        self._spi = None
        self._cs = None

    def open(self) -> None:
        import board
        import digitalio

        try:
            self._spi = dial_spi_bus.get_bus(dial_spi_bus.TOUCH_BUS)
        except Exception as e:
            raise RuntimeError(f"open SPI1 failed: {e}") from e

        cs = digitalio.DigitalInOut(_board_pin(board, _TOUCH_CS_GPIO))
        cs.switch_to_output(value=True)
        self._cs = cs

    def close(self) -> None:
        if self._cs is not None:
            try:
                self._cs.deinit()
            except Exception:
                pass
            self._cs = None
        self._spi = None

    def read_sample(self) -> tuple[int, int, int] | None:
        """Read one raw (x, y, z) touch sample, or None if the panel is not
        currently registering a valid conversion (e.g. released between the
        caller's IRQ check and this read).

        Per dial_spi_bus's baudrate contract, the whole acquire-configure-
        transfer-release sequence happens inside a single transaction-lock
        hold, and the baudrate is (re)configured every time — never assumed
        left over from a previous read.
        """
        if self._spi is None:
            return None
        with dial_spi_bus.spi_transaction(dial_spi_bus.TOUCH_BUS):
            while not self._spi.try_lock():
                pass
            try:
                self._spi.configure(baudrate=_XPT2046_BAUDRATE, polarity=0, phase=0)
                x = self._read_channel(_CMD_X)
                y = self._read_channel(_CMD_Y)
                z1 = self._read_channel(_CMD_Z1)
                z2 = self._read_channel(_CMD_Z2)
            finally:
                self._spi.unlock()
        if x is None or y is None or z1 is None or z2 is None:
            return None
        # Standard XPT2046 pressure estimate: larger z1/smaller z2 gap means
        # firmer contact. z2 - z1 with z1 as the divisor is the textbook
        # Touch-Screen-Controller pressure formula; clamp to non-negative so
        # noise never reports a spurious negative pressure.
        z = max(0, (4096 - (z2 - z1)))
        return (x, y, z)

    def _read_channel(self, command: int) -> int | None:
        """Issue one 3-byte command/read cycle and return the 12-bit result.

        XPT2046 returns the 12-bit conversion across the low 12 bits of the
        two bytes clocked out after the command byte (7 dummy/settling bits,
        then 12 data bits, then 5 trailing zero bits) — the standard
        command-byte-then-two-read-bytes framing used by every XPT2046
        datasheet example.
        """
        if self._cs is None:
            return None
        write_buf = bytes([command, 0x00, 0x00])
        read_buf = bytearray(3)
        self._cs.value = False
        try:
            self._spi.write_readinto(write_buf, read_buf)
        finally:
            self._cs.value = True
        raw = ((read_buf[1] << 8) | read_buf[2]) >> 3
        return raw & 0x0FFF


class FT6206Driver:
    """I2C capacitive touch driver for FT6206/FT6236.

    No calibration is needed — the FT6206's own firmware already reports
    scaled panel coordinates, so z is reported as a fixed "touching" value
    (dial_touch_controllers.TouchController leaves z_threshold=None for this
    controller — the filter's threshold check is effectively a no-op here).

    The underlying I2C library is imported lazily inside open() and is NOT
    currently pinned in dial/requirements.txt or dial/requirements.lock —
    Adafruit publishes one as `adafruit-circuitpython-ft6206` (module
    `adafruit_ft6206`). If/when this driver is wired up for real hardware,
    that package needs adding to the dial requirements; until then, a
    machine without it degrades cleanly with a clear RuntimeError from
    open() rather than a bare ModuleNotFoundError traceback.
    """

    # A touch is "present" once FT6206 reports it; there is no meaningful
    # analog pressure value, so a constant well above any sane threshold is
    # reported for z.
    _PRESENT_Z = 4095

    def __init__(self) -> None:
        self._ft = None

    def open(self) -> None:
        import board

        try:
            import adafruit_ft6206
        except ImportError as e:
            raise RuntimeError(
                "FT6206 driver requires the adafruit-circuitpython-ft6206 "
                "package (module adafruit_ft6206), which is not installed "
                "and not currently pinned in dial/requirements.txt"
            ) from e

        try:
            i2c = board.I2C()
        except Exception as e:
            raise RuntimeError(f"open I2C bus failed: {e}") from e

        self._ft = adafruit_ft6206.Adafruit_FT6206(i2c)

    def close(self) -> None:
        self._ft = None

    def read_sample(self) -> tuple[int, int, int] | None:
        if self._ft is None:
            return None
        if not self._ft.touched:
            return None
        points = self._ft.touches
        if not points:
            return None
        point = points[0]
        return (point["x"], point["y"], self._PRESENT_Z)


# Driver tag -> zero-arg constructor, resolved lazily inside open_driver().
_DRIVERS = {
    "xpt2046": XPT2046Driver,
    "ft6206": FT6206Driver,
}


def open_driver(driver_tag: str):
    """Construct and open() the driver for *driver_tag*, returning it ready
    for read_sample() calls. Raises UnknownTouchDriverError for a tag with
    no known implementation, mirroring
    dial_display_adafruit._resolve_driver_class()'s unknown-tag error.
    """
    try:
        driver_class = _DRIVERS[driver_tag]
    except KeyError:
        raise UnknownTouchDriverError(f"unknown touch driver tag {driver_tag!r}") from None
    driver = driver_class()
    driver.open()
    return driver
