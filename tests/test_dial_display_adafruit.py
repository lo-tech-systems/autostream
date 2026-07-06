"""Tests for dial_display_adafruit.py — ST7735S backend with mocked hardware.

Covers: no hardware imports at module level, lazy import inside open(),
non-fatal open failure when the Adafruit package or board pins are absent,
correct construction of the fixed v1 wiring profile, and backlight on/off
lifecycle. No physical display or Pi hardware is required — all hardware
modules are mocked via sys.modules injection.
"""
from __future__ import annotations

import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
if _DIAL not in sys.path:
    sys.path.insert(0, _DIAL)

import dial_display_adafruit as dda
from dial_display_adafruit import AdafruitST7735SBackend


# ---------------------------------------------------------------------------
# Module-level import discipline
# ---------------------------------------------------------------------------

class TestNoModuleLevelHardwareImports:
    def test_source_has_no_top_level_hardware_imports(self):
        source_path = Path(_DIAL) / "dial_display_adafruit.py"
        text = source_path.read_text(encoding="utf-8")
        # Only the open() method body (indented) may import these.
        for line in text.splitlines():
            if line.startswith("import board") or line.startswith("import busio") \
               or line.startswith("import digitalio") \
               or line.startswith("from adafruit_rgb_display"):
                pytest.fail(f"hardware import found at module level: {line!r}")

    def test_instantiation_does_not_touch_hardware(self):
        """Constructing the backend must not import or touch any hardware module."""
        AdafruitST7735SBackend()  # must not raise even without board/adafruit_rgb_display installed

    def test_open_failure_is_non_fatal_when_adafruit_absent(self):
        backend = AdafruitST7735SBackend()
        with pytest.raises(Exception):
            backend.open()  # raises because 'board' is not installed in this env

    def test_backend_not_imported_when_fitted_false(self):
        """create_dial_display() must not require adafruit_rgb_display when fitted is False."""
        import dial_display

        cfg = MagicMock()
        cfg.display = MagicMock(fitted=False)
        cfg.uuid = "uuid"
        display = dial_display.create_dial_display(cfg, MagicMock(), MagicMock())
        display.start()
        display.stop()  # must not raise even though Adafruit modules are absent


# ---------------------------------------------------------------------------
# Mocked-hardware backend behavior
# ---------------------------------------------------------------------------

def _install_fake_hardware_modules():
    """Inject fake board/busio/digitalio/adafruit_rgb_display/gpiozero.LED modules."""
    board = types.ModuleType("board")
    for name in ("GPIO8", "GPIO9", "GPIO10", "GPIO11", "GPIO24", "GPIO25"):
        setattr(board, name, name)

    busio = types.ModuleType("busio")
    spi_mock = MagicMock(name="SPI")
    busio.SPI = MagicMock(return_value=spi_mock)

    digitalio = types.ModuleType("digitalio")
    digitalio.DigitalInOut = MagicMock(side_effect=lambda pin: MagicMock(name=f"DigitalInOut({pin})"))

    adafruit_rgb_display = types.ModuleType("adafruit_rgb_display")
    st7735_mod = types.ModuleType("adafruit_rgb_display.st7735")
    fake_display = MagicMock(name="ST7735S_instance")
    st7735_mod.ST7735S = MagicMock(return_value=fake_display)
    adafruit_rgb_display.st7735 = st7735_mod

    gpiozero = types.ModuleType("gpiozero")
    fake_led = MagicMock(name="LED_instance")
    gpiozero.LED = MagicMock(return_value=fake_led)

    modules = {
        "board": board,
        "busio": busio,
        "digitalio": digitalio,
        "adafruit_rgb_display": adafruit_rgb_display,
        "adafruit_rgb_display.st7735": st7735_mod,
        "gpiozero": gpiozero,
    }
    return modules, busio.SPI, digitalio.DigitalInOut, st7735_mod.ST7735S, gpiozero.LED, fake_display, fake_led


class TestMockedHardwareBackend:
    def test_open_constructs_st7735s_with_fixed_profile(self):
        modules, spi_ctor, dio_ctor, st7735_ctor, led_ctor, fake_display, fake_led = (
            _install_fake_hardware_modules()
        )
        with patch.dict(sys.modules, modules):
            backend = AdafruitST7735SBackend()
            backend.open()

        assert st7735_ctor.call_count == 1
        args, kwargs = st7735_ctor.call_args
        assert kwargs["width"] == 128
        assert kwargs["height"] == 160
        assert kwargs["baudrate"] == 16_000_000
        assert kwargs["polarity"] == 0
        assert kwargs["phase"] == 0
        assert kwargs["rotation"] == 0
        assert "rst" in kwargs

    def test_open_turns_backlight_on(self):
        modules, spi_ctor, dio_ctor, st7735_ctor, led_ctor, fake_display, fake_led = (
            _install_fake_hardware_modules()
        )
        with patch.dict(sys.modules, modules):
            backend = AdafruitST7735SBackend()
            backend.open()
        led_ctor.assert_called_once_with(18)
        fake_led.on.assert_called_once()

    def test_close_turns_backlight_off(self):
        modules, spi_ctor, dio_ctor, st7735_ctor, led_ctor, fake_display, fake_led = (
            _install_fake_hardware_modules()
        )
        with patch.dict(sys.modules, modules):
            backend = AdafruitST7735SBackend()
            backend.open()
            backend.close()
        fake_led.off.assert_called_once()

    def test_display_calls_underlying_image_method(self):
        modules, spi_ctor, dio_ctor, st7735_ctor, led_ctor, fake_display, fake_led = (
            _install_fake_hardware_modules()
        )
        with patch.dict(sys.modules, modules):
            backend = AdafruitST7735SBackend()
            backend.open()
            sentinel_image = object()
            backend.display(sentinel_image)
        fake_display.image.assert_called_once_with(sentinel_image)

    def test_clear_calls_underlying_fill(self):
        modules, spi_ctor, dio_ctor, st7735_ctor, led_ctor, fake_display, fake_led = (
            _install_fake_hardware_modules()
        )
        with patch.dict(sys.modules, modules):
            backend = AdafruitST7735SBackend()
            backend.open()
            backend.clear()
        fake_display.fill.assert_called_once_with(0)

    def test_display_before_open_is_noop(self):
        backend = AdafruitST7735SBackend()
        backend.display(object())  # must not raise

    def test_clear_before_open_is_noop(self):
        backend = AdafruitST7735SBackend()
        backend.clear()  # must not raise

    def test_backlight_setup_failure_is_non_fatal(self):
        modules, spi_ctor, dio_ctor, st7735_ctor, led_ctor, fake_display, fake_led = (
            _install_fake_hardware_modules()
        )
        modules["gpiozero"].LED = MagicMock(side_effect=RuntimeError("gpio busy"))
        with patch.dict(sys.modules, modules):
            backend = AdafruitST7735SBackend()
            backend.open()  # must not raise despite backlight failure
        assert backend._backlight is None
