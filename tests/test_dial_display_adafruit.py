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
from PIL import Image

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
    """Inject fake board/busio/digitalio/adafruit_rgb_display modules."""
    board = types.ModuleType("board")
    for name in ("GPIO8", "GPIO9", "GPIO10", "GPIO11", "GPIO18", "GPIO24", "GPIO25"):
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

    modules = {
        "board": board,
        "busio": busio,
        "digitalio": digitalio,
        "adafruit_rgb_display": adafruit_rgb_display,
        "adafruit_rgb_display.st7735": st7735_mod,
    }
    return modules, busio.SPI, digitalio.DigitalInOut, st7735_mod.ST7735S, fake_display


def _install_fake_hardware_modules_with_alt_board_names():
    modules, spi_ctor, dio_ctor, st7735_ctor, fake_display = (
        _install_fake_hardware_modules()
    )
    board = types.ModuleType("board")
    board.SCLK = "SCLK"
    board.MOSI = "MOSI"
    board.MISO = "MISO"
    board.CE0 = "CE0"
    board.D18 = "D18"
    board.D24 = "D24"
    board.D25 = "D25"
    modules["board"] = board
    return modules, spi_ctor, dio_ctor, st7735_ctor, fake_display


class TestMockedHardwareBackend:
    def test_open_constructs_st7735s_with_fixed_profile(self):
        modules, spi_ctor, dio_ctor, st7735_ctor, fake_display = (
            _install_fake_hardware_modules()
        )
        with patch.dict(sys.modules, modules):
            backend = AdafruitST7735SBackend()
            backend.open()

        assert st7735_ctor.call_count == 1
        args, kwargs = st7735_ctor.call_args
        # Landscape dimensions with rotation=0 — the ST7735S driver's MADCTL
        # init already scans landscape, so frames are sent unrotated as one
        # full-screen write. This panel has no GRAM offsets (confirmed on
        # hardware).
        assert kwargs["width"] == 160
        assert kwargs["height"] == 128
        assert kwargs["baudrate"] == 16_000_000
        assert kwargs["polarity"] == 0
        assert kwargs["phase"] == 0
        assert kwargs["rotation"] == 0
        assert kwargs["bl"] is not None
        assert kwargs["x_offset"] == 0
        assert kwargs["y_offset"] == 0
        assert "rst" in kwargs

    def test_open_accepts_blinka_alt_board_pin_names(self):
        modules, spi_ctor, dio_ctor, st7735_ctor, fake_display = (
            _install_fake_hardware_modules_with_alt_board_names()
        )
        with patch.dict(sys.modules, modules):
            backend = AdafruitST7735SBackend()
            backend.open()

        spi_ctor.assert_called_once_with(clock="SCLK", MOSI="MOSI", MISO="MISO")
        dio_ctor.assert_any_call("CE0")
        dio_ctor.assert_any_call("D25")
        dio_ctor.assert_any_call("D24")
        assert st7735_ctor.call_count == 1

    def test_open_passes_backlight_to_display_driver(self):
        modules, spi_ctor, dio_ctor, st7735_ctor, fake_display = (
            _install_fake_hardware_modules()
        )
        with patch.dict(sys.modules, modules):
            backend = AdafruitST7735SBackend()
            backend.open()
        dio_ctor.assert_any_call("GPIO18")
        args, kwargs = st7735_ctor.call_args
        assert kwargs["bl"] is backend._backlight

    def test_close_turns_backlight_off_and_deinits(self):
        modules, spi_ctor, dio_ctor, st7735_ctor, fake_display = (
            _install_fake_hardware_modules()
        )
        with patch.dict(sys.modules, modules):
            backend = AdafruitST7735SBackend()
            backend.open()
            backlight = backend._backlight
            backend.close()
        assert backlight.value is False
        backlight.deinit.assert_called_once()

    def test_display_calls_underlying_image_method(self):
        modules, spi_ctor, dio_ctor, st7735_ctor, fake_display = (
            _install_fake_hardware_modules()
        )
        with patch.dict(sys.modules, modules):
            backend = AdafruitST7735SBackend()
            backend.open()
            sentinel_image = object()
            backend.display(sentinel_image)
        fake_display.image.assert_called_once_with(sentinel_image)

    def test_clear_calls_underlying_fill(self):
        modules, spi_ctor, dio_ctor, st7735_ctor, fake_display = (
            _install_fake_hardware_modules()
        )
        with patch.dict(sys.modules, modules):
            backend = AdafruitST7735SBackend()
            backend.open()
            backend.clear()
        args, kwargs = fake_display.image.call_args
        assert args[0].size == (160, 128)
        assert args[0].getpixel((0, 0)) == (14, 40, 65)

    def test_display_adapts_portrait_image_to_landscape_panel(self):
        modules, spi_ctor, dio_ctor, st7735_ctor, fake_display = (
            _install_fake_hardware_modules()
        )
        source = Image.new("RGB", (128, 160), (255, 0, 0))
        with patch.dict(sys.modules, modules):
            backend = AdafruitST7735SBackend()
            backend.open()
            backend.display(source)

        args, kwargs = fake_display.image.call_args
        out = args[0]
        assert out.size == (160, 128)
        assert out.getpixel((0, 0)) == (14, 40, 65)

    def test_display_before_open_is_noop(self):
        backend = AdafruitST7735SBackend()
        backend.display(object())  # must not raise

    def test_clear_before_open_is_noop(self):
        backend = AdafruitST7735SBackend()
        backend.clear()  # must not raise

    def test_backlight_setup_failure_names_pin(self):
        modules, spi_ctor, dio_ctor, st7735_ctor, fake_display = (
            _install_fake_hardware_modules()
        )

        def fake_digital_in_out(pin):
            if pin == "GPIO18":
                raise RuntimeError("GPIO busy")
            return MagicMock(name=f"DigitalInOut({pin})")

        modules["digitalio"].DigitalInOut = MagicMock(side_effect=fake_digital_in_out)
        with patch.dict(sys.modules, modules):
            backend = AdafruitST7735SBackend()
            with pytest.raises(RuntimeError, match="GPIO18 backlight"):
                backend.open()

    def test_busy_display_pin_error_names_pin(self):
        modules, spi_ctor, dio_ctor, st7735_ctor, fake_display = (
            _install_fake_hardware_modules()
        )

        def fake_digital_in_out(pin):
            if pin == "GPIO24":
                raise RuntimeError("GPIO busy")
            return MagicMock(name=f"DigitalInOut({pin})")

        modules["digitalio"].DigitalInOut = MagicMock(side_effect=fake_digital_in_out)
        with patch.dict(sys.modules, modules):
            backend = AdafruitST7735SBackend()
            with pytest.raises(RuntimeError, match="GPIO24 reset"):
                backend.open()

    def test_sleep_turns_backlight_off_and_writes_true_black_frame(self):
        modules, spi_ctor, dio_ctor, st7735_ctor, fake_display = (
            _install_fake_hardware_modules()
        )
        with patch.dict(sys.modules, modules):
            backend = AdafruitST7735SBackend()
            backend.open()
            backlight = backend._backlight
            backend.sleep()

        assert backlight.value is False
        args, kwargs = fake_display.image.call_args
        frame = args[0]
        assert frame.size == (160, 128)
        assert frame.getpixel((0, 0)) == (0, 0, 0)
        assert frame.getpixel((0, 0)) != dda._BACKGROUND_RGB

    def test_wake_turns_backlight_on_and_renders_nothing(self):
        modules, spi_ctor, dio_ctor, st7735_ctor, fake_display = (
            _install_fake_hardware_modules()
        )
        with patch.dict(sys.modules, modules):
            backend = AdafruitST7735SBackend()
            backend.open()
            backlight = backend._backlight
            backlight.value = False
            fake_display.image.reset_mock()
            backend.wake()

        assert backlight.value is True
        fake_display.image.assert_not_called()

    def test_sleep_before_open_is_noop(self):
        backend = AdafruitST7735SBackend()
        backend.sleep()  # must not raise

    def test_wake_before_open_is_noop(self):
        backend = AdafruitST7735SBackend()
        backend.wake()  # must not raise

    def test_busy_ce0_uses_hardware_chip_select(self):
        modules, spi_ctor, dio_ctor, st7735_ctor, fake_display = (
            _install_fake_hardware_modules()
        )

        def fake_digital_in_out(pin):
            if pin == "GPIO8":
                raise RuntimeError("GPIO busy")
            return MagicMock(name=f"DigitalInOut({pin})")

        modules["digitalio"].DigitalInOut = MagicMock(side_effect=fake_digital_in_out)
        with patch.dict(sys.modules, modules):
            backend = AdafruitST7735SBackend()
            backend.open()

        args, kwargs = st7735_ctor.call_args
        assert args[2] is None
