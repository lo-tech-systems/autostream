"""dial_hd_ddc.py: an HDMI panel's backlight over DDC/CI.

Most HDMI panels have no sysfs backlight, but many answer the monitor control
channel on the connector's DDC bus. This speaks that protocol straight through
i2c-dev (stdlib only): VCP 0x10 sets the brightness and VCP 0xD6 switches the
backlight off (standby) and on. The class has the interface HdPanel already
uses for a sysfs backlight, so the panel needs no per-kind code.

A DDC write takes tens of milliseconds plus the pauses the protocol demands,
and a brightness drag sends many values, so nothing here blocks its caller:
set_percent() only records the wanted level and one worker thread applies the
latest one (a newer level replaces an older one that has not started yet).

Locking: one condition guards the wanted level and the stop flag and is never
held while talking to the bus; the bus is touched only by the worker thread
(and by detect(), before the worker exists). The panel's own locks are never
taken here.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import errno
import fcntl
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from dial_hd_panel import BACKLIGHT_ROOT, Backlight, BacklightBase, scaled_level

DRM_ROOT = Path("/sys/class/drm")
DEV_ROOT = Path("/dev")

I2C_SLAVE = 0x0703          # ioctl: choose the device address for read/write
DDC_ADDRESS = 0x37          # the display's 7-bit DDC/CI address

# Framing. The host speaks as source 0x51; a reply is sent by the display
# (0x6E) to the virtual host address 0x50, which seeds the reply's checksum
# the way the display address 0x6E seeds a request's.
HOST_SOURCE = 0x51
DISPLAY_SOURCE = 0x6E
HOST_DEST = 0x50
LENGTH_FLAG = 0x80
OP_GET, OP_GET_REPLY, OP_SET = 0x01, 0x02, 0x03
GET_REPLY_SIZE = 11
NULL_LENGTH = 0x80
RESULT_UNSUPPORTED = 1

# VCP feature codes, and the power-mode values this uses.
VCP_BRIGHTNESS = 0x10
VCP_POWER = 0xD6
POWER_ON = 1
POWER_OFF = 4               # off: the panel reads back 2 (standby) afterwards

# Pauses the protocol asks for: between a request and reading its reply, and
# between commands. 50 ms covers both with margin.
DDC_PAUSE_S = 0.05

# A panel woken from power-off shows its own banner before it takes commands;
# give it a moment, then check the brightness by reading it back.
WAKE_SETTLE_S = 1.0
WAKE_ATTEMPTS = 5
WAKE_RETRY_S = 0.5

PROBE_ATTEMPTS = 2          # the first read after idle is sometimes a null reply
DETECT_BUDGET_S = 2.0       # no further bus is tried once this has passed
CLOSE_JOIN_S = 8.0


class DdcError(Exception):
    """A DDC exchange that did not give a usable answer."""


class DdcUnsupported(DdcError):
    """The display answered, but does not implement that feature."""


def _checksum(seed: int, body: bytes) -> int:
    value = seed
    for byte in body:
        value ^= byte
    return value


def set_request(code: int, value: int) -> bytes:
    """The set-VCP packet for feature *code*."""
    body = bytes([HOST_SOURCE, LENGTH_FLAG | 4, OP_SET, code, (value >> 8) & 0xFF, value & 0xFF])
    return body + bytes([_checksum(DISPLAY_SOURCE, body)])


def get_request(code: int) -> bytes:
    """The get-VCP packet for feature *code*."""
    body = bytes([HOST_SOURCE, LENGTH_FLAG | 2, OP_GET, code])
    return body + bytes([_checksum(DISPLAY_SOURCE, body)])


def parse_get_reply(data: bytes, code: int) -> "tuple[int, int]":
    """(current, maximum) from a get-VCP reply for *code*. Anything short of a
    complete, correctly checksummed, matching reply raises DdcError."""
    if len(data) != GET_REPLY_SIZE:
        raise DdcError(f"reply is {len(data)} bytes, not {GET_REPLY_SIZE}")
    if data[0] == DISPLAY_SOURCE and data[1] == NULL_LENGTH:
        raise DdcError("null reply (display not ready)")
    if data[0] != DISPLAY_SOURCE:
        raise DdcError(f"reply from {data[0]:#04x}")
    if data[1] != LENGTH_FLAG | 8:
        raise DdcError(f"reply length byte {data[1]:#04x}")
    if _checksum(HOST_DEST, data[:-1]) != data[-1]:
        raise DdcError("reply checksum mismatch")
    if data[2] != OP_GET_REPLY:
        raise DdcError(f"reply opcode {data[2]:#04x}")
    if data[3] == RESULT_UNSUPPORTED:
        raise DdcUnsupported(f"feature {code:#04x} not supported")
    if data[3] != 0:
        raise DdcError(f"result code {data[3]}")
    if data[4] != code:
        raise DdcError(f"reply is for feature {data[4]:#04x}, not {code:#04x}")
    return (data[8] << 8) | data[9], (data[6] << 8) | data[7]


class I2cBus:
    """One i2c-dev node addressed at the display's DDC address."""

    def __init__(self, path: "Path | str", address: int = DDC_ADDRESS) -> None:
        self._fd = os.open(path, os.O_RDWR)
        try:
            fcntl.ioctl(self._fd, I2C_SLAVE, address)
        except OSError:
            os.close(self._fd)
            raise

    def write(self, data: bytes) -> None:
        if os.write(self._fd, data) != len(data):
            raise OSError(errno.EIO, "short i2c write")

    def read(self, size: int) -> bytes:
        return os.read(self._fd, size)

    def close(self) -> None:
        try:
            os.close(self._fd)
        except OSError:
            pass


class DdcLink:
    """get-VCP and set-VCP over a bus from *open_bus* (opened when first
    needed and again after a bus error). Every failure is a DdcError."""

    def __init__(self, open_bus: Callable[[], object], sleep: Callable[[float], None] = time.sleep) -> None:
        self._open_bus = open_bus
        self._sleep = sleep
        self._bus = None

    def close(self) -> None:
        bus, self._bus = self._bus, None
        if bus is not None:
            bus.close()

    def _exchange(self, request: bytes, reply_size: int = 0) -> bytes:
        try:
            if self._bus is None:
                self._bus = self._open_bus()
            self._bus.write(request)
            self._sleep(DDC_PAUSE_S)
            data = self._bus.read(reply_size) if reply_size else b""
            self._sleep(DDC_PAUSE_S)
            return bytes(data)
        except OSError as e:
            self.close()
            raise DdcError(str(e)) from e

    def get_vcp(self, code: int) -> "tuple[int, int]":
        return parse_get_reply(self._exchange(get_request(code), GET_REPLY_SIZE), code)

    def set_vcp(self, code: int, value: int) -> None:
        self._exchange(set_request(code, value))


def connected_ddc_buses(drm_root: Path = DRM_ROOT, dev_root: Path = DEV_ROOT) -> "list[Path]":
    """The i2c-dev nodes behind each connected HDMI connector's ddc link."""
    buses = []
    try:
        connectors = sorted(Path(drm_root).glob("card*-HDMI-A-*"))
    except OSError:
        return buses
    for connector in connectors:
        try:
            if (connector / "status").read_text().strip() != "connected":
                continue
            name = Path(os.path.realpath(connector / "ddc")).name
        except OSError:
            continue
        node = Path(dev_root) / name
        if re.fullmatch(r"i2c-\d+", name) and node.exists():
            buses.append(node)
    return buses


class DdcBacklight(BacklightBase):
    """A panel's brightness and power over DDC/CI. *maximum* is the panel's
    own brightness maximum and *power* says whether it has power control."""

    kind = "ddc"

    def __init__(
        self, link: DdcLink, maximum: int, power: bool, *,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        super().__init__()
        self._link = link
        self._max = maximum
        self._power = power
        self._sleep = sleep
        self._cond = threading.Condition()
        self._target: "int | None" = None
        self._last_awake = 100
        self._asleep = False
        self._stopping = False
        self._thread: "threading.Thread | None" = None
        # Worker thread only: whether the panel is known to be powered on.
        self._on: "bool | None" = None

    # ---- detection ---------------------------------------------------------

    @classmethod
    def detect(
        cls, drm_root: Path = DRM_ROOT, dev_root: Path = DEV_ROOT, *,
        open_bus: "Callable[[Path], object]" = I2cBus,
        sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic,
    ) -> "DdcBacklight | None":
        """A backlight on the first connected HDMI panel that reports a
        brightness maximum, else None. Bounded by DETECT_BUDGET_S between
        buses; never raises."""
        try:
            started = clock()
            for path in connected_ddc_buses(drm_root, dev_root):
                if clock() - started > DETECT_BUDGET_S:
                    break
                found = cls._probe(path, open_bus, sleep)
                if found is not None:
                    return found
        except Exception:
            logging.debug("HD panel: DDC detection failed", exc_info=True)
        return None

    @classmethod
    def _probe(cls, path: Path, open_bus, sleep) -> "DdcBacklight | None":
        link = DdcLink(lambda: open_bus(path), sleep)
        maximum = cls._read_feature(link, VCP_BRIGHTNESS)
        if maximum is None or maximum[1] <= 0:
            link.close()
            return None
        power = cls._read_feature(link, VCP_POWER) is not None
        logging.info(
            "HD panel: DDC backlight on %s (max %d, power control %s)",
            path, maximum[1], "yes" if power else "no",
        )
        return cls(link, maximum[1], power, sleep=sleep)

    @staticmethod
    def _read_feature(link: DdcLink, code: int) -> "tuple[int, int] | None":
        for _ in range(PROBE_ATTEMPTS):
            try:
                return link.get_vcp(code)
            except DdcUnsupported:
                return None
            except DdcError:
                continue
        return None

    # ---- the interface HdPanel uses ----------------------------------------

    def set_percent(self, percent: int) -> None:
        """Record the wanted level (0 powers the panel down); returns at once.
        Never raises."""
        percent = max(0, min(100, int(percent)))
        with self._cond:
            if self._stopping:
                return
            self._target = percent
            self._asleep = percent == 0
            if percent:
                self._last_awake = percent
            if self._thread is None:
                self._thread = threading.Thread(target=self._run, daemon=True, name="hd-ddc")
                self._thread.start()
            self._cond.notify()

    def close(self) -> None:
        """Leave the panel on at its last awake level, then stop the worker."""
        with self._cond:
            thread = self._thread
            if thread is not None and not self._stopping and self._asleep:
                self._target = self._last_awake
            self._stopping = True
            self._cond.notify()
        if thread is not None:
            thread.join(CLOSE_JOIN_S)
        self._link.close()

    # ---- the worker --------------------------------------------------------

    def _run(self) -> None:
        while True:
            with self._cond:
                while self._target is None and not self._stopping:
                    self._cond.wait()
                target, self._target = self._target, None
            if target is None:
                return
            try:
                self._apply(target)
            except DdcError as e:
                self._on = None
                self._warn_once("backlight DDC write", e)
            except Exception as e:
                self._on = None
                self._warn_once("backlight DDC write", repr(e))

    def _superseded(self) -> bool:
        with self._cond:
            return self._target is not None

    def _apply(self, percent: int) -> None:
        link = self._link
        if percent == 0:
            if self._power:
                link.set_vcp(VCP_POWER, POWER_OFF)
                self._on = False
            else:
                link.set_vcp(VCP_BRIGHTNESS, 0)
            return
        woke = self._power and self._ensure_on()
        value = scaled_level(percent, self._max)
        if woke:
            self._set_verified(value)
        else:
            link.set_vcp(VCP_BRIGHTNESS, value)

    def _ensure_on(self) -> bool:
        """Power the panel on if it is not known to be; True when this
        woke it (so the next command may not be accepted yet)."""
        if self._on:
            return False
        try:
            current, _ = self._link.get_vcp(VCP_POWER)
        except DdcError:
            current = None
        if current != POWER_ON:
            self._link.set_vcp(VCP_POWER, POWER_ON)
        self._on = True
        if current == POWER_ON:
            return False
        self._sleep(WAKE_SETTLE_S)
        return True

    def _set_verified(self, value: int) -> None:
        """Set the brightness and read it back, a few times if the panel is
        still coming up; a newer request ends the retries early."""
        error: "DdcError | None" = None
        for attempt in range(WAKE_ATTEMPTS):
            if attempt:
                if self._superseded():
                    return
                self._sleep(WAKE_RETRY_S)
            try:
                self._link.set_vcp(VCP_BRIGHTNESS, value)
                current, _ = self._link.get_vcp(VCP_BRIGHTNESS)
            except DdcError as e:
                error = e
                continue
            if current == value:
                return
            error = DdcError(f"brightness reads {current}, wanted {value}")
        raise error


def detect_backlight(
    sysfs_root: Path = BACKLIGHT_ROOT, drm_root: Path = DRM_ROOT, dev_root: Path = DEV_ROOT,
) -> "BacklightBase | None":
    """A writable sysfs backlight if there is one, else a DDC panel, else None."""
    return Backlight.detect(sysfs_root) or DdcBacklight.detect(drm_root, dev_root)
