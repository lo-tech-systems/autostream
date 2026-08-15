"""Tests for dial_touch_controllers.py — the touch controller profile table.

Covers table integrity (unique keys, catalogue coverage, known bus values,
default presence) and that the module never pulls in a hardware library —
dial_config.py will import this module for enum validation, before the
display stack's ImportError isolation runs (see dial_touch_controllers.py's
module docstring), so a hardware import here would defeat the
degrade-to-noop invariant.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
if _DIAL not in sys.path:
    sys.path.insert(0, _DIAL)

import dial_touch_controllers as dtc

_KNOWN_BUS_VALUES = {"spi", "i2c"}


class TestControllerTableIntegrity:
    def test_keys_match_dict_keys(self):
        for key, controller in dtc.TOUCH_CONTROLLERS.items():
            assert controller.key == key

    def test_catalogue_covers_every_key(self):
        catalogue_keys = {entry["key"] for entry in dtc.list_controllers()}
        assert catalogue_keys == set(dtc.TOUCH_CONTROLLERS.keys())

    def test_labels_non_empty(self):
        for controller in dtc.TOUCH_CONTROLLERS.values():
            assert controller.label

    def test_bus_values_known(self):
        for controller in dtc.TOUCH_CONTROLLERS.values():
            assert controller.bus in _KNOWN_BUS_VALUES

    def test_default_key_present(self):
        assert dtc.DEFAULT_TOUCH_KEY in dtc.TOUCH_CONTROLLERS

    def test_default_is_none_and_has_no_driver(self):
        default = dtc.get_controller(dtc.DEFAULT_TOUCH_KEY)
        assert default.driver_tag is None

    def test_get_controller_returns_table_entry(self):
        for key, controller in dtc.TOUCH_CONTROLLERS.items():
            assert dtc.get_controller(key) is controller

    def test_get_controller_unknown_key_raises(self):
        with pytest.raises(dtc.UnknownTouchControllerError):
            dtc.get_controller("does-not-exist")

    def test_catalogue_shape(self):
        for entry in dtc.list_controllers():
            assert set(entry.keys()) == {"key", "text"}
            assert isinstance(entry["key"], str)
            assert isinstance(entry["text"], str)

    def test_expected_entries_present(self):
        assert set(dtc.TOUCH_CONTROLLERS.keys()) == {"none", "xpt2046", "ft6206"}


class TestResistiveCalibration:
    def test_xpt2046_has_calibration_constants(self):
        c = dtc.get_controller("xpt2046")
        assert c.bus == "spi"
        assert c.raw_x_min is not None
        assert c.raw_x_max is not None
        assert c.raw_y_min is not None
        assert c.raw_y_max is not None
        assert c.z_threshold is not None
        assert c.raw_x_min < c.raw_x_max
        assert c.raw_y_min < c.raw_y_max

    def test_capacitive_controllers_have_no_calibration(self):
        for key in ("none", "ft6206"):
            c = dtc.get_controller(key)
            assert c.raw_x_min is None
            assert c.raw_x_max is None
            assert c.raw_y_min is None
            assert c.raw_y_max is None
            assert c.z_threshold is None


class TestNoHardwareImport:
    def test_importing_controllers_does_not_pull_in_hardware_modules(self):
        """Stronger than a source-text check: actually import the module in
        a fresh subprocess and inspect sys.modules afterwards."""
        script = (
            "import sys; "
            f"sys.path.insert(0, {_DIAL!r}); "
            "import dial_touch_controllers; "
            "hw = {'board', 'busio', 'digitalio', 'adafruit_rgb_display', "
            "'adafruit_ft6206', 'gpiozero'}; "
            "hit = hw & set(sys.modules); "
            "print(','.join(sorted(hit)))"
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == ""

    def test_source_has_no_hardware_import_statements(self):
        source_path = Path(_DIAL) / "dial_touch_controllers.py"
        for line in source_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            assert not stripped.startswith("import board")
            assert not stripped.startswith("import busio")
            assert not stripped.startswith("import digitalio")
            assert not stripped.startswith("import gpiozero")
            assert not stripped.startswith("from gpiozero")
            assert not stripped.startswith("from adafruit_rgb_display")
            assert not stripped.startswith("import adafruit_rgb_display")
            assert not stripped.startswith("import adafruit_ft6206")
            assert not stripped.startswith("from adafruit_ft6206")
