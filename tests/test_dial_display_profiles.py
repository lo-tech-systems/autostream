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

    def test_init_table_profiles_only_use_supported_rotations(self):
        """An init_table panel scans in a fixed orientation, so only 0 and 180
        are meaningful — 90/270 would address the row register beyond its
        range and mangle the image rather than rotating it. Nothing enforces
        this at construction, so guard the table itself.
        """
        for profile in ddp.DISPLAY_PROFILES.values():
            if profile.rotation_mechanism == "init_table":
                assert profile.rotation in (0, 180), (
                    f"{profile.key}: rotation {profile.rotation} is not "
                    "addressable on an init_table panel"
                )

    def test_default_profile_backend_name(self):
        profile = ddp.get_profile(ddp.DEFAULT_PROFILE_KEY)
        assert ddp.backend_name_for(profile) == "adafruit_st7735s"

    def test_default_profile_key(self):
        assert ddp.DEFAULT_PROFILE_KEY == "st7735s_160x128"


# ---------------------------------------------------------------------------
# Physical-size defaults and derivation
# ---------------------------------------------------------------------------

_EXPECTED_DEFAULT_INCHES = {
    "st7735s_160x128": 1.8,
    "st7735s_128x128": 1.44,
    "st7789_240x240": 1.3,
    "st7789_320x240": 2.8,
    "ili9341_320x240": 2.8,
}

# mm_per_px_for(profile, profile.default_diagonal_inches), computed by hand
# from diagonal_mm / hypot(width, height).
_EXPECTED_MM_PER_PX = {
    "st7735s_160x128": 0.2231,
    "st7735s_128x128": 0.2021,
    "st7789_240x240": 0.0973,
    "st7789_320x240": 0.1778,
    "ili9341_320x240": 0.1778,
}


class TestPhysicalSizeDefaults:
    def test_every_profile_sets_a_positive_default(self):
        for profile in ddp.DISPLAY_PROFILES.values():
            assert profile.default_diagonal_inches > 0

    def test_confirmed_default_diagonals(self):
        for key, inches in _EXPECTED_DEFAULT_INCHES.items():
            assert ddp.DISPLAY_PROFILES[key].default_diagonal_inches == inches

    def test_mm_per_px_for_matches_confirmed_table(self):
        for key, expected in _EXPECTED_MM_PER_PX.items():
            profile = ddp.DISPLAY_PROFILES[key]
            actual = ddp.mm_per_px_for(profile, profile.default_diagonal_inches)
            assert actual == pytest.approx(expected, abs=1e-4)

    def test_mm_per_px_for_scales_with_diagonal(self):
        profile = ddp.get_profile(ddp.DEFAULT_PROFILE_KEY)
        small = ddp.mm_per_px_for(profile, 1.0)
        large = ddp.mm_per_px_for(profile, 2.0)
        assert large == pytest.approx(small * 2, rel=1e-9)

    def test_effective_diagonal_inches_without_override_uses_profile_default(self):
        profile = ddp.get_profile(ddp.DEFAULT_PROFILE_KEY)
        assert ddp.effective_diagonal_inches(profile, None) == profile.default_diagonal_inches

    def test_effective_diagonal_inches_with_override_uses_override(self):
        profile = ddp.get_profile(ddp.DEFAULT_PROFILE_KEY)
        assert ddp.effective_diagonal_inches(profile, 3.5) == 3.5

    def test_list_profiles_entries_carry_default_inches(self):
        by_key = {entry["key"]: entry for entry in ddp.list_profiles()}
        for key, inches in _EXPECTED_DEFAULT_INCHES.items():
            assert by_key[key]["default_inches"] == inches

    def test_list_profiles_entry_shape(self):
        for entry in ddp.list_profiles():
            assert set(entry.keys()) == {"key", "text", "default_inches"}


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


# ---------------------------------------------------------------------------
# Layout size: which named sizes each profile offers, and the LayoutContext
# every configuration resolves to.
# ---------------------------------------------------------------------------

from dial_touch_layout import metrics_for  # noqa: E402


class _FakeDisplayCfg:
    """A DialDisplayConfig-shaped stand-in — layout_context_for() reads its
    argument by attribute only, so a plain namespace exercises it without
    importing dial_config (which itself imports this module)."""

    def __init__(self, screen_type, screen_size_inches=None, layout_size=None):
        self.screen_type = screen_type
        self.screen_size_inches = screen_size_inches
        self.layout_size = layout_size


class TestLayoutSizesFor:
    def test_5x4_panel_offers_every_size(self):
        profile = ddp.get_profile("st7735s_160x128")
        assert ddp.layout_sizes_for(profile) == ["small", "medium", "large"]

    def test_square_panels_offer_nothing(self):
        for key in ("st7735s_128x128", "st7789_240x240"):
            assert ddp.layout_sizes_for(ddp.get_profile(key)) == []

    def test_4x3_panels_offer_every_size(self):
        for key in ("st7789_320x240", "ili9341_320x240"):
            assert ddp.layout_sizes_for(ddp.get_profile(key)) == ["small", "medium", "large"]

    def test_layout_size_options_texts(self):
        profile = ddp.get_profile("ili9341_320x240")
        options = ddp.layout_size_options(profile)
        assert options == [
            {"key": "small", "text": "Small (160x128)"},
            {"key": "medium", "text": "Medium (320x240)"},
            {"key": "large", "text": "Large (640x480)"},
        ]

    def test_layout_size_options_empty_for_square_panel(self):
        profile = ddp.get_profile("st7789_240x240")
        assert ddp.layout_size_options(profile) == []


class TestLogicalSizeFor:
    def test_none_is_the_profiles_own_size(self):
        profile = ddp.get_profile("ili9341_320x240")
        assert ddp.logical_size_for(profile, None) == (320, 240)

    def test_named_size_is_the_table_entry(self):
        profile = ddp.get_profile("ili9341_320x240")
        assert ddp.logical_size_for(profile, "large") == (640, 480)


class TestMmPerPxForSizeDelegate:
    def test_mm_per_px_for_matches_mm_per_px_for_size_on_every_profile(self):
        """mm_per_px_for() must stay a byte-identical delegate to
        mm_per_px_for_size() applied to the profile's own dims — the None-path
        invariant this whole feature is built to preserve."""
        for profile in ddp.DISPLAY_PROFILES.values():
            expected = ddp.mm_per_px_for_size(
                profile.default_diagonal_inches, profile.width, profile.height
            )
            assert ddp.mm_per_px_for(profile, profile.default_diagonal_inches) == expected


class TestLayoutContextFor:
    def test_none_layout_is_the_profiles_own_size(self):
        cfg = _FakeDisplayCfg("ili9341_320x240", screen_size_inches=2.8, layout_size=None)
        ctx = ddp.layout_context_for(cfg)
        assert ctx.logical_size == (320, 240)
        assert ctx.physical_size == (320, 240)
        assert ctx.mm_per_px == pytest.approx(0.1778, abs=1e-4)
        assert ctx.size_chosen is False
        assert ctx.resamples is False

    def test_small_on_320x240_panel(self):
        cfg = _FakeDisplayCfg("ili9341_320x240", screen_size_inches=2.8, layout_size="small")
        ctx = ddp.layout_context_for(cfg)
        assert ctx.logical_size == (160, 128)
        assert ctx.physical_size == (320, 240)
        assert ctx.mm_per_px == pytest.approx(0.3471, abs=1e-4)
        assert ctx.size_chosen is True
        assert ctx.resamples is True

    def test_large_on_320x240_panel(self):
        cfg = _FakeDisplayCfg("ili9341_320x240", screen_size_inches=2.8, layout_size="large")
        ctx = ddp.layout_context_for(cfg)
        assert ctx.logical_size == (640, 480)
        assert ctx.physical_size == (320, 240)
        assert ctx.mm_per_px == pytest.approx(0.0889, abs=1e-4)
        assert ctx.size_chosen is True

    def test_medium_on_160x128_panel(self):
        cfg = _FakeDisplayCfg("st7735s_160x128", screen_size_inches=1.8, layout_size="medium")
        ctx = ddp.layout_context_for(cfg)
        assert ctx.logical_size == (320, 240)
        assert ctx.physical_size == (160, 128)
        assert ctx.mm_per_px == pytest.approx(0.1143, abs=1e-4)
        assert ctx.size_chosen is True

    def test_unknown_screen_type_falls_back_to_default_profile(self):
        cfg = _FakeDisplayCfg("does-not-exist")
        ctx = ddp.layout_context_for(cfg)
        default = ddp.get_profile(ddp.DEFAULT_PROFILE_KEY)
        assert ctx.logical_size == (default.width, default.height)
        assert ctx.physical_size == (default.width, default.height)

    def test_stale_layout_size_resolves_as_none(self):
        cfg = _FakeDisplayCfg("ili9341_320x240", screen_size_inches=2.8, layout_size="huge")
        ctx = ddp.layout_context_for(cfg)
        assert ctx.logical_size == (320, 240)
        assert ctx.size_chosen is False

    def test_missing_layout_size_attribute_behaves_as_none(self):
        """layout_context_for() reads layout_size with getattr(default=None)
        so a bare object without the attribute at all (an old caller's
        config-shaped stand-in) still resolves to the native size."""

        class _NoLayoutAttr:
            screen_type = "ili9341_320x240"
            screen_size_inches = 2.8

        ctx = ddp.layout_context_for(_NoLayoutAttr())
        assert ctx.logical_size == (320, 240)
        assert ctx.size_chosen is False


# Metrics at the offered layout contexts, per the confirmed table: tier,
# band_h, rows_per_page, row_h, touch_min_px, touch_short.
_LAYOUT_METRICS_TABLE = [
    # (screen_type, inches, layout_size, tier, band_h, rows, row_h, touch_min_px, touch_short)
    ("ili9341_320x240", 2.8, None, "rich", 48, 5, 48, 45, False),
    ("ili9341_320x240", 2.8, "small", "base", 32, 3, 32, 24, False),
    ("ili9341_320x240", 2.8, "large", "large", 96, 5, 96, 90, False),
    ("st7735s_160x128", 1.8, None, "base", 32, 3, 32, 36, False),
    ("st7735s_160x128", 1.8, "medium", "rich", 48, 5, 48, 70, False),
    ("st7735s_160x128", 1.8, "large", "large", 96, 5, 96, 140, False),
]


class TestMetricsAtOfferedLayoutContexts:
    @pytest.mark.parametrize(
        "screen_type,inches,layout_size,tier,band_h,rows,row_h,touch_min_px,touch_short",
        _LAYOUT_METRICS_TABLE,
    )
    def test_pinned_metrics(
        self, screen_type, inches, layout_size, tier, band_h, rows, row_h, touch_min_px, touch_short,
    ):
        cfg = _FakeDisplayCfg(screen_type, screen_size_inches=inches, layout_size=layout_size)
        ctx = ddp.layout_context_for(cfg)
        metrics = metrics_for(
            *ctx.logical_size, mm_per_px=ctx.mm_per_px, size_chosen=ctx.size_chosen,
        )
        assert metrics.content_tier == tier
        assert metrics.band_h == band_h
        assert metrics.rows_per_page == rows
        assert metrics.row_h == row_h
        assert metrics.touch_min_px == touch_min_px
        assert metrics.touch_short == touch_short
