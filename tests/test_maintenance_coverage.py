"""Maintenance documentation and focused coverage tests.

Adds missing boundary and compatibility tests that the existing suites do not
cover:
  - Custom (non-menu) stylus lifetime is accepted by normalize_stylus_life_hours.
  - Belt/bearing hours warning boundary (just inside and just outside the zone).
  - Belt/bearing time warning/overdue boundary (days-based).
  - Disabled hours dimension: belt_life_hours=0 keeps hours flags False.
  - Disabled time dimension: belt_life_years=0 keeps time flags False.
  - Malformed or missing service timestamps are treated as "no date recorded".
  - Public snapshot keys (to_public_dict) are a stable contract.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

from autostream_config import (
    VALID_STYLUS_LIFE_HOURS,
    normalize_stylus_life_hours,
)
from autostream_playback_stats import (
    PlaybackTracker,
    PlaybackInputConfig,
    InputPlaybackSnapshot,
    MAINTENANCE_HOURS_WARNING_SECONDS,
    MAINTENANCE_TIME_WARNING_DAYS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class FakeClock:
    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _iso_ago(clk: FakeClock, days: int) -> str:
    """Return an ISO-8601 UTC timestamp for *days* days before clk.now."""
    dt = datetime.fromtimestamp(clk.now, tz=timezone.utc) - timedelta(days=days)
    return dt.isoformat()


def _turntable(
    *,
    stylus_life_hours: int = 0,
    belt_life_hours: int = 1000,
    belt_life_years: int = 2,
    bearing_life_hours: int = 500,
    bearing_life_years: int = 1,
) -> PlaybackInputConfig:
    return PlaybackInputConfig.normalized(
        enabled=True,
        is_turntable=True,
        stylus_life_hours=stylus_life_hours,
        belt_life_hours=belt_life_hours,
        belt_life_years=belt_life_years,
        bearing_life_hours=bearing_life_hours,
        bearing_life_years=bearing_life_years,
    )


def _tracker(tmp_path, *, clock=None):
    clk = clock or FakeClock()
    return PlaybackTracker(stats_path=tmp_path / "ps.json", time_fn=clk)


# ---------------------------------------------------------------------------
# normalize_stylus_life_hours — custom positive integer
# ---------------------------------------------------------------------------

class TestStylusCustomLifetime:
    def test_custom_positive_integer_is_accepted(self):
        assert normalize_stylus_life_hours(123) == 123

    def test_custom_value_not_in_menu_is_not_clamped(self):
        for v in (1, 99, 333, 999, 1001, 5000):
            assert normalize_stylus_life_hours(v) == v, f"value {v} should be accepted"

    def test_valid_menu_values_still_pass_through(self):
        for v in VALID_STYLUS_LIFE_HOURS:
            assert normalize_stylus_life_hours(v) == v

    def test_custom_value_survives_round_trip_through_config(self, tmp_path):
        """A custom stylus lifetime set directly in config survives parse."""
        from autostream_config import _parse_audio_input_config
        raw = {"stylus_life_hours": 123}
        result = _parse_audio_input_config(raw)
        assert result.stylus_life_hours == 123


# ---------------------------------------------------------------------------
# Belt hours — warning and overdue boundaries
# ---------------------------------------------------------------------------

class TestBeltHoursWarningBoundary:
    """Belt hours warning triggers when remaining < MAINTENANCE_HOURS_WARNING_SECONDS."""

    def _belt_snap(self, tmp_path, clk, belt_life_hours, used_seconds):
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _turntable(belt_life_hours=belt_life_hours)})
        tr.on_playback_started(1)
        tr.on_wear_started(1)
        clk.advance(used_seconds)
        tr.on_playback_stopped(1)
        tr.on_wear_stopped(1)
        return tr.snapshot().inputs[1]

    def test_well_below_warning_threshold_no_warning(self, tmp_path):
        clk = FakeClock()
        life_secs = 1000 * 3600
        # Leave 2× the warning threshold remaining → no warning
        used = life_secs - MAINTENANCE_HOURS_WARNING_SECONDS * 2
        snap = self._belt_snap(tmp_path, clk, 1000, used)
        assert snap.belt_hours_warning is False
        assert snap.belt_hours_overdue is False

    def test_just_inside_warning_zone(self, tmp_path):
        clk = FakeClock()
        life_secs = 1000 * 3600
        # remaining = MAINTENANCE_HOURS_WARNING_SECONDS - 1 → inside warning zone
        used = life_secs - MAINTENANCE_HOURS_WARNING_SECONDS + 1
        snap = self._belt_snap(tmp_path, clk, 1000, used)
        assert snap.belt_hours_warning is True
        assert snap.belt_hours_overdue is False

    def test_just_outside_warning_zone(self, tmp_path):
        clk = FakeClock()
        life_secs = 1000 * 3600
        # remaining = MAINTENANCE_HOURS_WARNING_SECONDS → NOT in warning zone (strict <)
        used = life_secs - MAINTENANCE_HOURS_WARNING_SECONDS
        snap = self._belt_snap(tmp_path, clk, 1000, used)
        assert snap.belt_hours_warning is False
        assert snap.belt_hours_overdue is False

    def test_overdue_when_hours_exceeded(self, tmp_path):
        clk = FakeClock()
        life_secs = 1000 * 3600
        used = life_secs + 1
        snap = self._belt_snap(tmp_path, clk, 1000, used)
        assert snap.belt_hours_overdue is True
        assert snap.belt_hours_warning is False  # overdue takes precedence

    def test_disabled_hours_dimension_stays_false(self, tmp_path):
        clk = FakeClock()
        # belt_life_hours=0 disables the hours dimension entirely
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _turntable(belt_life_hours=0, belt_life_years=0)})
        tr.on_playback_started(1)
        tr.on_wear_started(1)
        clk.advance(99999 * 3600)  # far beyond any threshold
        tr.on_playback_stopped(1)
        tr.on_wear_stopped(1)
        snap = tr.snapshot().inputs[1]
        assert snap.belt_hours_overdue is False
        assert snap.belt_hours_warning is False
        assert snap.belt_hours_remaining is None


# ---------------------------------------------------------------------------
# Belt time — warning and overdue boundaries
# ---------------------------------------------------------------------------

class TestBeltTimeWarningBoundary:
    """Belt time warning triggers when elapsed_days >= threshold - 30."""

    def _belt_time_snap(self, tmp_path, clk, belt_life_years, days_ago):
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _turntable(
            belt_life_hours=0,         # hours dimension off
            belt_life_years=belt_life_years,
        )})
        # Write the service timestamp directly into persisted state
        state_data = {
            "schema_version": 2,
            "updated_at": _iso_ago(clk, 0),
            "inputs": {
                "1": {
                    "last_belt_service_at": _iso_ago(clk, days_ago),
                }
            },
        }
        (tmp_path / "ps.json").write_text(json.dumps(state_data))
        tr2 = PlaybackTracker(stats_path=tmp_path / "ps.json", time_fn=clk)
        tr2.replace_input_configs({1: _turntable(
            belt_life_hours=0,
            belt_life_years=belt_life_years,
        )})
        return tr2.snapshot().inputs[1]

    def test_well_before_threshold_no_warning(self, tmp_path):
        clk = FakeClock()
        # 2 years = 730 days; service 60 days ago = 670 days remaining
        snap = self._belt_time_snap(tmp_path, clk, 2, 60)
        assert snap.belt_time_warning is False
        assert snap.belt_time_overdue is False

    def test_just_inside_time_warning_zone(self, tmp_path):
        clk = FakeClock()
        # threshold = 730; warning at >= 730 - 30 = 700 days elapsed
        snap = self._belt_time_snap(tmp_path, clk, 2, 700)
        assert snap.belt_time_warning is True
        assert snap.belt_time_overdue is False

    def test_just_outside_time_warning_zone(self, tmp_path):
        clk = FakeClock()
        # elapsed = 699 → just below warning zone
        snap = self._belt_time_snap(tmp_path, clk, 2, 699)
        assert snap.belt_time_warning is False
        assert snap.belt_time_overdue is False

    def test_overdue_when_time_exceeded(self, tmp_path):
        clk = FakeClock()
        # 2 years = 730 days; service 731 days ago
        snap = self._belt_time_snap(tmp_path, clk, 2, 731)
        assert snap.belt_time_overdue is True
        assert snap.belt_time_warning is False

    def test_disabled_time_dimension_stays_false_even_years_later(self, tmp_path):
        clk = FakeClock()
        # belt_life_years=0 disables the time dimension
        snap = self._belt_time_snap(tmp_path, clk, 0, 3000)
        assert snap.belt_time_overdue is False
        assert snap.belt_time_warning is False

    def test_malformed_service_date_treated_as_no_date(self, tmp_path):
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _turntable(belt_life_hours=0, belt_life_years=1)})
        state_data = {
            "schema_version": 2,
            "updated_at": _iso_ago(clk, 0),
            "inputs": {"1": {"last_belt_service_at": "not-a-date"}},
        }
        (tmp_path / "ps.json").write_text(json.dumps(state_data))
        tr2 = PlaybackTracker(stats_path=tmp_path / "ps.json", time_fn=clk)
        tr2.replace_input_configs({1: _turntable(belt_life_hours=0, belt_life_years=1)})
        snap = tr2.snapshot().inputs[1]
        assert snap.belt_elapsed_days is None
        assert snap.belt_time_overdue is False
        assert snap.belt_time_warning is False

    def test_null_service_date_treated_as_no_date(self, tmp_path):
        clk = FakeClock()
        state_data = {
            "schema_version": 2,
            "inputs": {"1": {"last_belt_service_at": None}},
        }
        (tmp_path / "ps.json").write_text(json.dumps(state_data))
        tr = PlaybackTracker(stats_path=tmp_path / "ps.json", time_fn=clk)
        tr.replace_input_configs({1: _turntable(belt_life_hours=0, belt_life_years=1)})
        snap = tr.snapshot().inputs[1]
        assert snap.belt_elapsed_days is None
        assert snap.belt_time_overdue is False


# ---------------------------------------------------------------------------
# Bearing — mirror the belt tests for completeness
# ---------------------------------------------------------------------------

class TestBearingHoursWarningBoundary:
    def _bearing_snap(self, tmp_path, clk, bearing_life_hours, used_seconds):
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _turntable(
            belt_life_hours=0, belt_life_years=0,
            bearing_life_hours=bearing_life_hours, bearing_life_years=0,
        )})
        tr.on_playback_started(1)
        tr.on_wear_started(1)
        clk.advance(used_seconds)
        tr.on_playback_stopped(1)
        tr.on_wear_stopped(1)
        return tr.snapshot().inputs[1]

    def test_just_inside_bearing_warning_zone(self, tmp_path):
        clk = FakeClock()
        life_secs = 500 * 3600
        used = life_secs - MAINTENANCE_HOURS_WARNING_SECONDS + 1
        snap = self._bearing_snap(tmp_path, clk, 500, used)
        assert snap.bearing_hours_warning is True
        assert snap.bearing_hours_overdue is False

    def test_bearing_overdue_when_hours_exceeded(self, tmp_path):
        clk = FakeClock()
        life_secs = 500 * 3600
        snap = self._bearing_snap(tmp_path, clk, 500, life_secs + 1)
        assert snap.bearing_hours_overdue is True
        assert snap.bearing_hours_warning is False

    def test_disabled_bearing_hours_stays_false(self, tmp_path):
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _turntable(
            belt_life_hours=0, belt_life_years=0,
            bearing_life_hours=0, bearing_life_years=0,
        )})
        tr.on_playback_started(1)
        tr.on_wear_started(1)
        clk.advance(99999 * 3600)
        tr.on_playback_stopped(1)
        tr.on_wear_stopped(1)
        snap = tr.snapshot().inputs[1]
        assert snap.bearing_hours_overdue is False
        assert snap.bearing_hours_warning is False
        assert snap.bearing_hours_remaining is None


# ---------------------------------------------------------------------------
# Public snapshot key compatibility
# ---------------------------------------------------------------------------

_EXPECTED_PUBLIC_KEYS = frozenset({
    "input_index", "label", "active", "enabled", "is_turntable", "is_bluetooth",
    "total_playback_seconds", "total_playback_hours",
    # stylus
    "stylus_playback_seconds", "stylus_playback_hours",
    "stylus_life_hours", "stylus_remaining_seconds", "stylus_remaining_hours",
    "stylus_warning", "stylus_overdue", "last_stylus_reset_at",
    # belt hours
    "belt_life_hours", "belt_playback_seconds", "belt_playback_hours",
    "belt_hours_remaining", "belt_hours_overdue", "belt_hours_warning",
    # belt time
    "belt_life_years", "belt_elapsed_days", "belt_time_overdue", "belt_time_warning",
    # belt combined
    "belt_overdue", "belt_warning", "last_belt_service_at",
    # bearing hours
    "bearing_life_hours", "bearing_playback_seconds", "bearing_playback_hours",
    "bearing_hours_remaining", "bearing_hours_overdue", "bearing_hours_warning",
    # bearing time
    "bearing_life_years", "bearing_elapsed_days",
    "bearing_time_overdue", "bearing_time_warning",
    # bearing combined
    "bearing_overdue", "bearing_warning", "last_bearing_service_at",
})


class TestPublicSnapshotCompatibility:
    """to_public_dict() must expose a stable set of keys for the JSON API."""

    def test_all_expected_keys_present(self, tmp_path):
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _turntable(
            stylus_life_hours=500,
            belt_life_hours=1000, belt_life_years=2,
            bearing_life_hours=500, bearing_life_years=1,
        )})
        snap = tr.snapshot().inputs[1]
        public = snap.to_public_dict()
        missing = _EXPECTED_PUBLIC_KEYS - public.keys()
        assert not missing, f"Missing public snapshot keys: {missing}"

    def test_no_unexpected_keys_added(self, tmp_path):
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _turntable()})
        snap = tr.snapshot().inputs[1]
        public = snap.to_public_dict()
        extra = public.keys() - _EXPECTED_PUBLIC_KEYS
        assert not extra, f"Unexpected new public snapshot keys: {extra}"
