"""Regression tests for Service-page display helpers.

Covers the warning-vs-overdue distinction: when a maintenance item is overdue
the tracker sets overdue=True and warning=False (see autostream_playback_stats
_compute_hours_remaining).  The display functions must still surface a warn
flag so the card and text styling are applied.
"""
import sys
from dataclasses import replace
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

from autostream_playback_stats import make_fallback_input_snapshot
from autostream_webui_service_schema import (
    _card_display,
    _hours_display,
    _time_display,
)

_STYLUS_LIFE = 500
_BELT_LIFE_H = 1000
_BELT_LIFE_Y = 3
_BELT_TOTAL_DAYS = _BELT_LIFE_Y * 365


def _base_snap(is_turntable=True):
    return make_fallback_input_snapshot(
        1, "TT",
        is_turntable=is_turntable,
        stylus_life_hours=_STYLUS_LIFE,
        belt_life_hours=_BELT_LIFE_H,
        belt_life_years=_BELT_LIFE_Y,
        bearing_life_hours=200,
        bearing_life_years=3,
    )


# ---------------------------------------------------------------------------
# _hours_display
# ---------------------------------------------------------------------------

class TestHoursDisplay:
    def test_healthy_bar_status(self):
        hd = _hours_display("stylus", _STYLUS_LIFE, _base_snap())
        assert hd["hours_bar_status"] == "healthy"
        assert hd["hours_remaining_warn"] is False

    def test_warning_sets_bar_and_flag(self):
        snap = replace(_base_snap(), stylus_warning=True)
        hd = _hours_display("stylus", _STYLUS_LIFE, snap)
        assert hd["hours_bar_status"] == "warning"
        assert hd["hours_remaining_warn"] is True

    def test_overdue_sets_critical_bar(self):
        snap = replace(_base_snap(), stylus_overdue=True)
        hd = _hours_display("stylus", _STYLUS_LIFE, snap)
        assert hd["hours_bar_status"] == "critical"

    def test_overdue_sets_remaining_warn(self):
        """hours_remaining_warn must be True when overdue even though warning=False."""
        snap = replace(_base_snap(), stylus_overdue=True)
        hd = _hours_display("stylus", _STYLUS_LIFE, snap)
        assert hd["hours_remaining_warn"] is True

    def test_warning_flag_false_overdue_flag_true_gives_warn(self):
        """Mirrors the real tracker invariant: warning=False when overdue=True."""
        snap = replace(_base_snap(), stylus_warning=False, stylus_overdue=True)
        hd = _hours_display("stylus", _STYLUS_LIFE, snap)
        assert hd["hours_remaining_warn"] is True

    def test_belt_hours_overdue(self):
        snap = replace(_base_snap(), belt_hours_overdue=True)
        hd = _hours_display("belt", _BELT_LIFE_H, snap)
        assert hd["hours_bar_status"] == "critical"
        assert hd["hours_remaining_warn"] is True

    def test_belt_hours_warning(self):
        snap = replace(_base_snap(), belt_hours_warning=True)
        hd = _hours_display("belt", _BELT_LIFE_H, snap)
        assert hd["hours_bar_status"] == "warning"
        assert hd["hours_remaining_warn"] is True

    def test_tracking_off_returns_live_false(self):
        hd = _hours_display("stylus", 0, _base_snap())
        assert hd["hours_live"] is False
        assert hd["hours_bar_status"] == "healthy"
        assert hd["hours_remaining_warn"] is False

    def test_bar_pct_is_string(self):
        hd = _hours_display("stylus", _STYLUS_LIFE, _base_snap())
        assert isinstance(hd["hours_bar_pct"], str)


# ---------------------------------------------------------------------------
# _time_display — provide belt_elapsed_days so tests enter the active branch
# ---------------------------------------------------------------------------

class TestTimeDisplay:
    def _snap_with_days(self, elapsed_days, *, belt_time_warning=False,
                        belt_time_overdue=False):
        base = _base_snap()
        return replace(
            base,
            belt_elapsed_days=elapsed_days,
            belt_time_warning=belt_time_warning,
            belt_time_overdue=belt_time_overdue,
        )

    def test_no_service_date_returns_healthy(self):
        # elapsed_days=None → else branch → healthy, no warn
        td = _time_display("belt", _BELT_LIFE_Y, _base_snap())
        assert td["time_live"] is True
        assert td["time_bar_status"] == "healthy"
        assert td["remaining_warn"] is False

    def test_time_warning_sets_flag(self):
        snap = self._snap_with_days(
            _BELT_TOTAL_DAYS - 30,       # 30 days remaining — may or may not trigger
            belt_time_warning=True,
        )
        td = _time_display("belt", _BELT_LIFE_Y, snap)
        assert td["time_live"] is True
        assert td["remaining_warn"] is True

    def test_time_overdue_sets_critical(self):
        snap = self._snap_with_days(_BELT_TOTAL_DAYS + 5, belt_time_overdue=True)
        td = _time_display("belt", _BELT_LIFE_Y, snap)
        assert td["time_bar_status"] == "critical"

    def test_time_overdue_sets_remaining_warn(self):
        """remaining_warn must be True when overdue even though t_warn=False."""
        snap = self._snap_with_days(
            _BELT_TOTAL_DAYS + 5,
            belt_time_warning=False,
            belt_time_overdue=True,
        )
        td = _time_display("belt", _BELT_LIFE_Y, snap)
        assert td["remaining_warn"] is True

    def test_stylus_has_no_time_dimension(self):
        td = _time_display("stylus", _BELT_LIFE_Y, _base_snap())
        assert td["time_live"] is False

    def test_life_years_zero_returns_live_false(self):
        td = _time_display("belt", 0, _base_snap())
        assert td["time_live"] is False


# ---------------------------------------------------------------------------
# _card_display — use consistent playback hours so hours_remaining is correct
# ---------------------------------------------------------------------------

class TestCardDisplay:
    def _card_stylus(self, *, playback_seconds=0, warning=False, overdue=False):
        base = _base_snap()
        snap = replace(
            base,
            stylus_playback_seconds=playback_seconds,
            stylus_warning=warning,
            stylus_overdue=overdue,
        )
        hd = _hours_display("stylus", _STYLUS_LIFE, snap)
        td = _time_display("stylus", 0, snap)
        return _card_display("stylus", hd, td, is_turntable=True), hd

    def test_healthy_card_no_warn(self):
        cd, _ = self._card_stylus()
        assert cd["card_warn"] is False
        assert cd["card_sub"] == "Tracking on"

    def test_warning_card_has_warn(self):
        cd, _ = self._card_stylus(warning=True)
        assert cd["card_warn"] is True
        assert "due soon" in cd["card_sub"]

    def test_overdue_card_has_warn(self):
        """card_warn must be True when stylus is overdue."""
        # With consistent data: playback_seconds >= life_hours*3600
        overdue_seconds = _STYLUS_LIFE * 3600 + 1
        cd, hd = self._card_stylus(playback_seconds=overdue_seconds, overdue=True)
        assert hd["hours_remaining"] == "Due now"
        assert cd["card_warn"] is True
        assert cd["card_sub"] == "Stylus due now"

    def test_overdue_flag_only_card_warn(self):
        """Even with inconsistent snap data, overdue flag makes card_warn True
        because hours_remaining_warn propagates the overdue flag through."""
        cd, hd = self._card_stylus(overdue=True)
        assert cd["card_warn"] is True

    def test_not_turntable_returns_no_warn(self):
        snap = replace(_base_snap(is_turntable=False), stylus_overdue=True)
        hd = _hours_display("stylus", _STYLUS_LIFE, snap)
        td = _time_display("stylus", 0, snap)
        cd = _card_display("stylus", hd, td, is_turntable=False)
        assert cd["card_warn"] is False

    def test_tracking_off_returns_no_warn(self):
        snap = _base_snap()
        hd = _hours_display("stylus", 0, snap)
        td = _time_display("stylus", 0, snap)
        cd = _card_display("stylus", hd, td, is_turntable=True)
        assert cd["card_warn"] is False
        assert cd["card_sub"] == "Tracking off"
