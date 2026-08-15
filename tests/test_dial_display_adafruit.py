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

Image = pytest.importorskip("PIL.Image", reason="Pillow not installed")

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
if _DIAL not in sys.path:
    sys.path.insert(0, _DIAL)

import dial_display_adafruit as dda
import dial_spi_bus
from dial_display_adafruit import AdafruitDisplayBackend, AdafruitST7735SBackend
from dial_display_profiles import DISPLAY_PROFILES, get_profile


@pytest.fixture(autouse=True)
def _reset_shared_spi_bus():
    """dial_spi_bus.get_bus() is a process-wide singleton — reset it around
    every test in this module so one test's fake bus doesn't leak into the
    next (mirrors _install_fake_hardware_modules()'s per-test module fakes)."""
    dial_spi_bus._reset_for_tests()
    yield
    dial_spi_bus._reset_for_tests()


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


# ---------------------------------------------------------------------------
# Shared SPI bus ownership: the backend borrows the bus from dial_spi_bus
# and must never construct or dispose of it itself.
# ---------------------------------------------------------------------------

class TestSharedSpiBus:
    def test_open_obtains_bus_from_shared_owner_not_directly(self):
        modules, spi_ctor, dio_ctor, st7735_ctor, fake_display = (
            _install_fake_hardware_modules()
        )
        with patch.dict(sys.modules, modules):
            backend = AdafruitST7735SBackend()
            backend.open()

        # busio.SPI() is called exactly once — by dial_spi_bus.get_bus(),
        # not a second time directly by the backend.
        spi_ctor.assert_called_once_with(clock="GPIO11", MOSI="GPIO10", MISO="GPIO9")
        args, kwargs = st7735_ctor.call_args
        assert args[0] is spi_ctor.return_value

    def test_two_open_close_cycles_reuse_the_same_bus_object(self):
        modules, spi_ctor, dio_ctor, st7735_ctor, fake_display = (
            _install_fake_hardware_modules()
        )
        with patch.dict(sys.modules, modules):
            backend = AdafruitST7735SBackend()
            backend.open()
            first_spi = backend._spi
            backend.close()

            backend.open()
            second_spi = backend._spi
            backend.close()

        assert first_spi is second_spi
        # Only ever constructed once across both cycles.
        spi_ctor.assert_called_once()

    def test_close_leaves_the_shared_bus_usable_not_deinitted(self):
        modules, spi_ctor, dio_ctor, st7735_ctor, fake_display = (
            _install_fake_hardware_modules()
        )
        with patch.dict(sys.modules, modules):
            backend = AdafruitST7735SBackend()
            backend.open()
            bus = dial_spi_bus.get_bus()
            backend.close()

        # close() must not touch the shared bus at all.
        bus.deinit.assert_not_called()
        assert dial_spi_bus.get_bus() is bus

    def test_screen_type_swap_keeps_same_bus(self):
        """close() on one profile's backend followed by open() on a
        different profile's backend (a screen_type swap) must not tear the
        shared bus out from under it — the same bus object comes back."""
        modules, spi_ctor, dio_ctor, st7735_ctor, fake_display = (
            _install_fake_hardware_modules()
        )
        modules2, dio_ctor2, st7789_ctor, fake_display2 = (
            _install_fake_hardware_modules_for("st7789", "st7789", "ST7789")
        )
        # Keep the same fake busio module (and therefore the same SPI
        # constructor mock) across both fake-hardware installs so the two
        # backends observe the identical shared bus.
        modules2["busio"] = modules["busio"]

        with patch.dict(sys.modules, modules):
            old_backend = AdafruitST7735SBackend()
            old_backend.open()
            old_spi = old_backend._spi
            old_backend.close()

        with patch.dict(sys.modules, modules2):
            new_backend = AdafruitDisplayBackend(get_profile("st7789_320x240"))
            new_backend.open()
            new_spi = new_backend._spi

        assert new_spi is old_spi
        spi_ctor.assert_called_once()


# ---------------------------------------------------------------------------
# Profile table integrity (also exercised standalone in
# test_dial_display_profiles.py — kept here too since the backend consumes it)
# ---------------------------------------------------------------------------

class TestProfileTableIntegrity:
    def test_keys_unique_and_default_present(self):
        assert len(DISPLAY_PROFILES) == len(set(DISPLAY_PROFILES.keys()))
        assert "st7735s_160x128" in DISPLAY_PROFILES

    def test_default_profile_reproduces_todays_constants(self):
        profile = get_profile("st7735s_160x128")
        assert (profile.width, profile.height) == (160, 128)
        assert (profile.x_offset, profile.y_offset) == (0, 0)
        assert profile.rotation == 0
        assert profile.baudrate == 16_000_000


class TestZeroArgBackwardCompat:
    def test_zero_arg_backend_reports_default_dims_and_name(self):
        backend = AdafruitST7735SBackend()
        assert backend.width == 160
        assert backend.height == 128
        assert backend.name == "adafruit_st7735s"


# ---------------------------------------------------------------------------
# Profile-driven driver dispatch (ST7789 / ILI9341)
# ---------------------------------------------------------------------------

def _install_fake_hardware_modules_for(driver_tag: str, module_name: str, class_name: str):
    """Inject fake board/busio/digitalio plus a fake driver module for
    *driver_tag*, without an st7735 module — dispatch must import only the
    module the profile names."""
    board = types.ModuleType("board")
    for name in ("GPIO8", "GPIO9", "GPIO10", "GPIO11", "GPIO18", "GPIO24", "GPIO25"):
        setattr(board, name, name)

    busio = types.ModuleType("busio")
    spi_mock = MagicMock(name="SPI")
    busio.SPI = MagicMock(return_value=spi_mock)

    digitalio = types.ModuleType("digitalio")
    digitalio.DigitalInOut = MagicMock(side_effect=lambda pin: MagicMock(name=f"DigitalInOut({pin})"))

    adafruit_rgb_display = types.ModuleType("adafruit_rgb_display")
    driver_mod = types.ModuleType(f"adafruit_rgb_display.{module_name}")
    fake_display = MagicMock(name=f"{class_name}_instance")
    setattr(driver_mod, class_name, MagicMock(return_value=fake_display))
    setattr(adafruit_rgb_display, module_name, driver_mod)

    modules = {
        "board": board,
        "busio": busio,
        "digitalio": digitalio,
        "adafruit_rgb_display": adafruit_rgb_display,
        f"adafruit_rgb_display.{module_name}": driver_mod,
    }
    return modules, digitalio.DigitalInOut, getattr(driver_mod, class_name), fake_display


class TestProfileDrivenDriverDispatch:
    def test_st7789_profile_constructs_st7789_with_profile_dims(self):
        profile = get_profile("st7789_320x240")
        modules, dio_ctor, st7789_ctor, fake_display = (
            _install_fake_hardware_modules_for("st7789", "st7789", "ST7789")
        )
        with patch.dict(sys.modules, modules):
            backend = AdafruitDisplayBackend(profile)
            backend.open()

        assert st7789_ctor.call_count == 1
        args, kwargs = st7789_ctor.call_args
        assert kwargs["width"] == profile.width
        assert kwargs["height"] == profile.height
        assert kwargs["x_offset"] == profile.x_offset
        assert kwargs["y_offset"] == profile.y_offset
        assert kwargs["rotation"] == profile.rotation
        assert kwargs["baudrate"] == profile.baudrate
        # ST7789 does not accept bl= in the pinned library — the backend
        # must not pass it.
        assert "bl" not in kwargs
        assert backend.name == "adafruit_st7789"

    def test_st7789_backend_drives_backlight_itself(self):
        profile = get_profile("st7789_320x240")
        modules, dio_ctor, st7789_ctor, fake_display = (
            _install_fake_hardware_modules_for("st7789", "st7789", "ST7789")
        )
        with patch.dict(sys.modules, modules):
            backend = AdafruitDisplayBackend(profile)
            backend.open()

        backend._backlight.switch_to_output.assert_called_once_with(value=True)

    def test_ili9341_profile_constructs_ili9341_with_profile_dims(self):
        profile = get_profile("ili9341_320x240")
        modules, dio_ctor, ili9341_ctor, fake_display = (
            _install_fake_hardware_modules_for("ili9341", "ili9341", "ILI9341")
        )
        with patch.dict(sys.modules, modules):
            backend = AdafruitDisplayBackend(profile)
            backend.open()

        assert ili9341_ctor.call_count == 1
        args, kwargs = ili9341_ctor.call_args
        assert kwargs["width"] == profile.width
        assert kwargs["height"] == profile.height
        assert kwargs["rotation"] == profile.rotation
        assert kwargs["baudrate"] == profile.baudrate
        assert "bl" not in kwargs
        # ILI9341's constructor in the pinned library declares neither offset
        # argument; passing them is a TypeError on real hardware. The mocked
        # driver would accept them silently, so assert their absence.
        assert "x_offset" not in kwargs
        assert "y_offset" not in kwargs
        assert backend.name == "adafruit_ili9341"

    def test_offset_less_driver_profiles_declare_zero_offsets(self):
        """Offsets are dropped for drivers that take none — so a non-zero
        offset in such a profile would be silently unenforceable."""
        from dial_display_adafruit import _DRIVER_TAKES_OFFSETS
        from dial_display_profiles import DISPLAY_PROFILES

        for profile in DISPLAY_PROFILES.values():
            if profile.driver_tag not in _DRIVER_TAKES_OFFSETS:
                assert profile.x_offset == 0 and profile.y_offset == 0, (
                    f"{profile.key} sets offsets its driver cannot accept"
                )

    def test_unknown_driver_tag_raises_runtime_error(self):
        from dial_display_profiles import DisplayProfile

        bogus = DisplayProfile(
            key="bogus", label="Bogus", driver_tag="not-a-real-driver",
            width=100, height=100,
        )
        backend = AdafruitDisplayBackend(bogus)
        with pytest.raises(RuntimeError, match="not-a-real-driver"):
            backend.open()
