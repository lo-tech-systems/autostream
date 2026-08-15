"""Tests for dial_touch_drivers.py — lazy hardware touch drivers.

XPT2046 is exercised with a mocked SPI bus/board/digitalio stack (no real
hardware); FT6206 is exercised only for its degrade-clean-without-the-
library path, since inventing a fake adafruit_ft6206 API would test nothing
real. Unknown driver tags must raise a clear error, mirroring
dial_display_adafruit's unknown-driver-tag behaviour.
"""
from __future__ import annotations

import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
if _DIAL not in sys.path:
    sys.path.insert(0, _DIAL)

import dial_spi_bus  # noqa: E402
import dial_touch_drivers as dtd  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_spi_bus():
    dial_spi_bus._reset_for_tests()
    yield
    dial_spi_bus._reset_for_tests()


def _install_fake_board_and_digitalio(monkeypatch, fake_spi):
    """Install fake `board` and `digitalio` modules into sys.modules so the
    driver's lazy `import board` / `import digitalio` inside open() resolve
    to test doubles, and monkeypatch dial_spi_bus.get_bus() to hand back a
    controllable fake SPI object."""
    fake_board = types.SimpleNamespace(GPIO7="GPIO7-pin", CE1="CE1-pin")
    fake_digitalio = types.ModuleType("digitalio")

    created_cs = MagicMock(name="cs_digitalinout")

    class _DigitalInOut:
        def __init__(self, pin):
            self.pin = pin
            self.value = None
            self._direction = None

        def switch_to_output(self, value=False):
            self.value = value

        def deinit(self):
            pass

    fake_digitalio.DigitalInOut = _DigitalInOut

    monkeypatch.setitem(sys.modules, "board", fake_board)
    monkeypatch.setitem(sys.modules, "digitalio", fake_digitalio)
    monkeypatch.setattr(dial_spi_bus, "get_bus", lambda: fake_spi)
    return fake_board, fake_digitalio


class FakeSPI:
    """Stand-in for busio.SPI: try_lock/unlock/configure/write_readinto."""

    def __init__(self, response_bytes_for_command=None):
        self.locked = False
        self.configure_calls = []
        self.transfers = []
        self._response_for_command = response_bytes_for_command or {}

    def try_lock(self):
        self.locked = True
        return True

    def unlock(self):
        self.locked = False

    def configure(self, *, baudrate, polarity, phase):
        self.configure_calls.append((baudrate, polarity, phase))

    def write_readinto(self, write_buf, read_buf):
        assert self.locked, "write_readinto called without holding try_lock()"
        self.transfers.append(bytes(write_buf))
        command = write_buf[0]
        response = self._response_for_command.get(command, b"\x00\x00\x00")
        for i, b in enumerate(response):
            read_buf[i] = b


class TestXPT2046Driver:
    def test_read_sample_issues_expected_command_bytes(self, monkeypatch):
        fake_spi = FakeSPI()
        _install_fake_board_and_digitalio(monkeypatch, fake_spi)

        driver = dtd.XPT2046Driver()
        driver.open()
        driver.read_sample()

        commands_sent = [t[0] for t in fake_spi.transfers]
        assert commands_sent == [
            dtd._CMD_X, dtd._CMD_Y, dtd._CMD_Z1, dtd._CMD_Z2,
        ]
        # Every transfer is 3 bytes: command + 2 dummy bytes.
        for t in fake_spi.transfers:
            assert len(t) == 3
            assert t[1] == 0x00 and t[2] == 0x00

    def test_read_sample_configures_its_own_baudrate_inside_transaction(self, monkeypatch):
        fake_spi = FakeSPI()
        _install_fake_board_and_digitalio(monkeypatch, fake_spi)

        driver = dtd.XPT2046Driver()
        driver.open()
        driver.read_sample()

        assert len(fake_spi.configure_calls) == 1
        baudrate, polarity, phase = fake_spi.configure_calls[0]
        assert baudrate == dtd._XPT2046_BAUDRATE
        assert polarity == 0
        assert phase == 0

    def test_read_sample_returns_plausible_sample(self, monkeypatch):
        # 12-bit ADC value 0x0800 (2048) placed in the standard framing:
        # byte1 holds the high bits, byte2 the low bits + 3 trailing zeros.
        def encode(value_12bit: int) -> bytes:
            shifted = (value_12bit & 0x0FFF) << 3
            return bytes([0x00, (shifted >> 8) & 0xFF, shifted & 0xFF])

        response_map = {
            dtd._CMD_X: encode(1234),
            dtd._CMD_Y: encode(2345),
            dtd._CMD_Z1: encode(200),
            dtd._CMD_Z2: encode(100),
        }
        fake_spi = FakeSPI(response_bytes_for_command=response_map)
        _install_fake_board_and_digitalio(monkeypatch, fake_spi)

        driver = dtd.XPT2046Driver()
        driver.open()
        sample = driver.read_sample()

        assert sample is not None
        x, y, z = sample
        assert x == 1234
        assert y == 2345
        assert isinstance(z, int)
        assert z >= 0

    def test_read_sample_before_open_returns_none(self):
        driver = dtd.XPT2046Driver()
        assert driver.read_sample() is None

    def test_close_is_safe_before_open(self):
        driver = dtd.XPT2046Driver()
        driver.close()  # must not raise


class TestFT6206Driver:
    def test_open_without_library_raises_clean_runtime_error(self, monkeypatch):
        fake_board = types.SimpleNamespace()
        monkeypatch.setitem(sys.modules, "board", fake_board)
        monkeypatch.delitem(sys.modules, "adafruit_ft6206", raising=False)

        # Force `import adafruit_ft6206` to fail even if it happens to be
        # installed in this environment, so the degrade path is exercised
        # deterministically everywhere.
        real_import = __import__

        def _blocking_import(name, *args, **kwargs):
            if name == "adafruit_ft6206":
                raise ImportError("no module named adafruit_ft6206")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr("builtins.__import__", _blocking_import)

        driver = dtd.FT6206Driver()
        with pytest.raises(RuntimeError, match="adafruit_ft6206"):
            driver.open()

    def test_read_sample_before_open_returns_none(self):
        driver = dtd.FT6206Driver()
        assert driver.read_sample() is None


class TestUnknownDriverTag:
    def test_open_driver_unknown_tag_raises(self):
        with pytest.raises(dtd.UnknownTouchDriverError):
            dtd.open_driver("does-not-exist")

    def test_open_driver_known_tags_present(self):
        assert "xpt2046" in dtd._DRIVERS
        assert "ft6206" in dtd._DRIVERS
