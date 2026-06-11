"""Regression tests for maintenance-interval normalization.

WP1: bearing_life_hours was normalized using normalize_maintenance_life_hours
(valid values: 0, 1000, 2000, 3000) instead of normalize_bearing_life_hours
(valid values: 0, 200, 500, 1000, 2000).  Values of 200 and 500 were silently
discarded.  These tests cover every supported value for each maintenance item and
verify the regression at the INI-parse and PlaybackInputConfig.normalized() call
sites.
"""
import configparser
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

from autostream_config import (
    DEFAULT_STYLUS_LIFE_HOURS,
    VALID_STYLUS_LIFE_HOURS,
    VALID_MAINTENANCE_LIFE_HOURS,
    VALID_BEARING_LIFE_HOURS,
    VALID_MAINTENANCE_LIFE_YEARS,
    normalize_stylus_life_hours,
    normalize_maintenance_life_hours,
    normalize_bearing_life_hours,
    normalize_maintenance_life_years,
    _parse_audio_input_config,
)
from autostream_playback_stats import PlaybackInputConfig


# ---------------------------------------------------------------------------
# normalize_stylus_life_hours
# ---------------------------------------------------------------------------

class TestNormalizeStylusLifeHours:
    @pytest.mark.parametrize("value", VALID_STYLUS_LIFE_HOURS)
    def test_valid_values_pass_through(self, value):
        assert normalize_stylus_life_hours(value) == value

    def test_zero_disables_tracking(self):
        assert normalize_stylus_life_hours(0) == 0

    @pytest.mark.parametrize("value", VALID_STYLUS_LIFE_HOURS)
    def test_string_form_accepted(self, value):
        assert normalize_stylus_life_hours(str(value)) == value

    def test_negative_falls_back_to_default(self):
        assert normalize_stylus_life_hours(-1) == DEFAULT_STYLUS_LIFE_HOURS

    def test_garbage_falls_back_to_default(self):
        assert normalize_stylus_life_hours("bad") == DEFAULT_STYLUS_LIFE_HOURS


# ---------------------------------------------------------------------------
# normalize_maintenance_life_hours  (belt)
# ---------------------------------------------------------------------------

class TestNormalizeBeltLifeHours:
    @pytest.mark.parametrize("value", VALID_MAINTENANCE_LIFE_HOURS)
    def test_valid_belt_values_pass_through(self, value):
        assert normalize_maintenance_life_hours(value) == value

    @pytest.mark.parametrize("value", VALID_MAINTENANCE_LIFE_HOURS)
    def test_string_form_accepted(self, value):
        assert normalize_maintenance_life_hours(str(value)) == value

    @pytest.mark.parametrize("value", [200, 500])
    def test_bearing_hours_not_accepted_for_belt(self, value):
        # 200 and 500 are valid bearing intervals but must be rejected for belt
        assert normalize_maintenance_life_hours(value) == 0

    def test_invalid_value_falls_back_to_zero(self):
        assert normalize_maintenance_life_hours(9999) == 0

    def test_garbage_falls_back_to_zero(self):
        assert normalize_maintenance_life_hours("bad") == 0


# ---------------------------------------------------------------------------
# normalize_bearing_life_hours
# ---------------------------------------------------------------------------

class TestNormalizeBearingLifeHours:
    @pytest.mark.parametrize("value", VALID_BEARING_LIFE_HOURS)
    def test_valid_bearing_values_pass_through(self, value):
        # Regression: 200 and 500 were silently discarded before WP1.
        assert normalize_bearing_life_hours(value) == value

    @pytest.mark.parametrize("value", VALID_BEARING_LIFE_HOURS)
    def test_string_form_accepted(self, value):
        assert normalize_bearing_life_hours(str(value)) == value

    def test_belt_3000_not_accepted_for_bearing(self):
        # 3000 is a valid belt interval but must be rejected for bearing
        assert normalize_bearing_life_hours(3000) == 0

    def test_invalid_value_falls_back_to_zero(self):
        assert normalize_bearing_life_hours(9999) == 0

    def test_garbage_falls_back_to_zero(self):
        assert normalize_bearing_life_hours("bad") == 0


# ---------------------------------------------------------------------------
# normalize_maintenance_life_years
# ---------------------------------------------------------------------------

class TestNormalizeMaintenanceLifeYears:
    @pytest.mark.parametrize("value", VALID_MAINTENANCE_LIFE_YEARS)
    def test_valid_years_pass_through(self, value):
        assert normalize_maintenance_life_years(value) == value

    def test_invalid_value_falls_back_to_zero(self):
        assert normalize_maintenance_life_years(99) == 0


# ---------------------------------------------------------------------------
# INI config parsing — bearing_life_hours regression
# ---------------------------------------------------------------------------

def _ini_cfg(bearing_life_hours: str = "0", belt_life_hours: str = "0") -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.add_section("audio1")
    cfg.set("audio1", "bearing_life_hours", bearing_life_hours)
    cfg.set("audio1", "belt_life_hours", belt_life_hours)
    return cfg


class TestConfigParseBearingLifeHours:
    @pytest.mark.parametrize("value", VALID_BEARING_LIFE_HOURS)
    def test_all_bearing_values_survive_parse(self, value):
        result = _parse_audio_input_config(_ini_cfg(bearing_life_hours=str(value)), "audio1")
        assert result.bearing_life_hours == value

    @pytest.mark.parametrize("value", VALID_MAINTENANCE_LIFE_HOURS)
    def test_all_belt_values_survive_parse(self, value):
        result = _parse_audio_input_config(_ini_cfg(belt_life_hours=str(value)), "audio1")
        assert result.belt_life_hours == value

    def test_belt_200_rejected_in_belt_field(self):
        # 200 is a valid bearing value but not a valid belt value
        result = _parse_audio_input_config(_ini_cfg(belt_life_hours="200"), "audio1")
        assert result.belt_life_hours == 0

    def test_bearing_fields_independent_of_belt_fields(self):
        result = _parse_audio_input_config(
            _ini_cfg(bearing_life_hours="500", belt_life_hours="1000"), "audio1"
        )
        assert result.bearing_life_hours == 500
        assert result.belt_life_hours == 1000


# ---------------------------------------------------------------------------
# PlaybackInputConfig.normalized() — bearing_life_hours regression
# ---------------------------------------------------------------------------

class TestPlaybackInputConfigNormalized:
    @pytest.mark.parametrize("value", VALID_BEARING_LIFE_HOURS)
    def test_all_bearing_values_survive_normalized(self, value):
        # Regression: 200 and 500 were silently discarded before WP1.
        cfg = PlaybackInputConfig.normalized(bearing_life_hours=value)
        assert cfg.bearing_life_hours == value

    @pytest.mark.parametrize("value", VALID_MAINTENANCE_LIFE_HOURS)
    def test_all_belt_values_survive_normalized(self, value):
        cfg = PlaybackInputConfig.normalized(belt_life_hours=value)
        assert cfg.belt_life_hours == value

    def test_belt_200_rejected_in_normalized(self):
        cfg = PlaybackInputConfig.normalized(belt_life_hours=200)
        assert cfg.belt_life_hours == 0

    def test_bearing_fields_independent_of_belt_fields(self):
        cfg = PlaybackInputConfig.normalized(bearing_life_hours=500, belt_life_hours=1000)
        assert cfg.bearing_life_hours == 500
        assert cfg.belt_life_hours == 1000
