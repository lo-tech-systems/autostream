"""Tests for dial_display_profiles.py — the display profile table.

Covers: table integrity (unique keys, catalogue coverage, key/dims naming
convention), the default profile reproducing today's shipped panel exactly,
and that the module never pulls in a hardware library — dial_config.py will
import this module unconditionally at process start, before the display
stack's ImportError isolation, so a hardware import here would defeat the
degrade-to-noop invariant (see dial_display_adafruit.py and dial_display.py).
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

import dial_display_profiles as ddp

_KNOWN_DRIVER_TAGS = {"st7735s", "st7789", "ili9341"}


# ---------------------------------------------------------------------------
# Table integrity
# ---------------------------------------------------------------------------

class TestProfileTableIntegrity:
    def test_keys_match_dict_keys(self):
        for key, profile in ddp.DISPLAY_PROFILES.items():
            assert profile.key == key

    def test_catalogue_covers_every_key(self):
        catalogue_keys = {entry["key"] for entry in ddp.list_profiles()}
        assert catalogue_keys == set(ddp.DISPLAY_PROFILES.keys())

    def test_labels_non_empty(self):
        for profile in ddp.DISPLAY_PROFILES.values():
            assert profile.label

    def test_dims_positive(self):
        for profile in ddp.DISPLAY_PROFILES.values():
            assert profile.width > 0
            assert profile.height > 0

    def test_driver_tag_known(self):
        for profile in ddp.DISPLAY_PROFILES.values():
            assert profile.driver_tag in _KNOWN_DRIVER_TAGS

    def test_default_profile_key_present(self):
        assert ddp.DEFAULT_PROFILE_KEY in ddp.DISPLAY_PROFILES

    def test_key_naming_convention_matches_logical_dims(self):
        """Key must end with "<width>x<height>" in landscape WIDTHxHEIGHT
        order — the logical/compose dims, not necessarily the datasheet
        label's orientation."""
        for profile in ddp.DISPLAY_PROFILES.values():
            assert profile.key.endswith(f"{profile.width}x{profile.height}")

    def test_get_profile_returns_the_table_entry(self):
        for key, profile in ddp.DISPLAY_PROFILES.items():
            assert ddp.get_profile(key) is profile

    def test_get_profile_unknown_key_raises(self):
        with pytest.raises(ddp.UnknownDisplayProfileError):
            ddp.get_profile("does-not-exist")


# ---------------------------------------------------------------------------
# Default profile reproduces today's shipped panel exactly
# ---------------------------------------------------------------------------

class TestDefaultProfile:
    def test_default_profile_matches_current_shipped_panel(self):
        profile = ddp.get_profile(ddp.DEFAULT_PROFILE_KEY)
        assert profile.width == 160
        assert profile.height == 128
        assert profile.x_offset == 0
        assert profile.y_offset == 0
        assert profile.rotation == 0
        assert profile.baudrate == 16_000_000
        assert profile.driver_tag == "st7735s"
        assert profile.rotation_mechanism == "init_table"

    def test_default_profile_backend_name(self):
        profile = ddp.get_profile(ddp.DEFAULT_PROFILE_KEY)
        assert ddp.backend_name_for(profile) == "adafruit_st7735s"

    def test_default_profile_key(self):
        assert ddp.DEFAULT_PROFILE_KEY == "st7735s_160x128"


# ---------------------------------------------------------------------------
# No hardware import, ever
# ---------------------------------------------------------------------------

class TestNoHardwareImport:
    def test_importing_profiles_does_not_pull_in_hardware_modules(self):
        """Stronger than a source-text check: actually import the module in
        a fresh subprocess and inspect sys.modules afterwards."""
        script = (
            "import sys; "
            f"sys.path.insert(0, {_DIAL!r}); "
            "import dial_display_profiles; "
            "hw = {'board', 'busio', 'digitalio', 'adafruit_rgb_display'}; "
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
        """The docstring is allowed to mention these names in prose; only
        actual import statements are disallowed."""
        source_path = Path(_DIAL) / "dial_display_profiles.py"
        for line in source_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            assert not stripped.startswith("import board")
            assert not stripped.startswith("import busio")
            assert not stripped.startswith("import digitalio")
            assert not stripped.startswith("from adafruit_rgb_display")
            assert not stripped.startswith("import adafruit_rgb_display")
