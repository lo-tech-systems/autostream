"""Tests for the appliance's dial warnings (core/autostream_dial_warnings.py).

Covers:
1.  Each maintenance condition (stylus, belt, bearing; overdue and due soon)
    from a synthetic playback snapshot: id, severity, title, message, dismissal.
2.  Which inputs and items report at all (disabled inputs, untracked stylus).
3.  Ordering (overdue first, then due soon, then the power supply), the cap
    of eight and unique ids.
4.  Label cleaning and truncation to the title limit.
5.  Power supply: undervoltage now, since boot, none, unreadable.
6.  A provider that raises contributes nothing.
7.  The digest: stable, and moved by any change to the set.
8.  Cross-check against the dial's own validator: nothing a provider produces,
    at its worst-case text, is dropped, truncated or altered.
"""
from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
for _sub in ("core", "dial"):
    _p = str(REPO_ROOT / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)

import autostream_dial_warnings as dw
from autostream_playback_stats import make_fallback_input_snapshot
import dial_core_state


def _snap(index=1, label=None, **overrides):
    base = make_fallback_input_snapshot(
        index, label if label is not None else f"Input {index}",
        is_turntable=True, stylus_life_hours=500, belt_life_hours=500, bearing_life_hours=500,
    )
    return replace(base, **overrides)


def _playback(*snaps):
    return SimpleNamespace(inputs={s.input_index: s for s in snaps})


def _maintenance(*snaps):
    with patch("autostream_core.get_playback_snapshot", return_value=_playback(*snaps)):
        return dw._maintenance_warnings()


class TestMaintenanceRows:
    def test_nothing_due_reports_nothing(self):
        assert _maintenance(_snap(1), _snap(2)) == []

    def test_stylus_overdue(self):
        (w,) = _maintenance(_snap(1, stylus_overdue=True, stylus_warning=True))
        assert w == dw.DialWarning(
            "stylus_in1", "critical", "Input 1 stylus",
            "Needs changing now. Reset the counter in Service.", "day")

    def test_stylus_due_soon_states_hours(self):
        (w,) = _maintenance(_snap(2, stylus_warning=True, stylus_remaining_hours=7.5))
        assert w == dw.DialWarning(
            "stylus_in2", "warning", "Input 2 stylus",
            "Needs changing soon (7.5 h remaining).", "week")

    def test_stylus_due_soon_without_hours(self):
        (w,) = _maintenance(_snap(1, stylus_warning=True, stylus_remaining_hours=None))
        assert w.message == "Needs changing soon."

    @pytest.mark.parametrize("item,suffix", [("belt", "drive belt"), ("bearing", "main bearing")])
    def test_belt_and_bearing_overdue(self, item, suffix):
        (w,) = _maintenance(_snap(1, **{f"{item}_overdue": True}))
        assert w == dw.DialWarning(
            f"{item}_in1", "critical", f"Input 1 {suffix}",
            "Needs attention now. Reset the counter in Service.", "day")

    @pytest.mark.parametrize("item,suffix", [("belt", "drive belt"), ("bearing", "main bearing")])
    def test_belt_and_bearing_due_soon(self, item, suffix):
        (w,) = _maintenance(_snap(2, **{f"{item}_warning": True}))
        assert w == dw.DialWarning(
            f"{item}_in2", "warning", f"Input 2 {suffix}", "Service due soon.", "week")

    def test_overdue_wins_over_warning_for_the_same_item(self):
        (w,) = _maintenance(_snap(1, belt_overdue=True, belt_warning=True))
        assert w.severity == "critical"

    def test_disabled_input_reports_nothing(self):
        assert _maintenance(_snap(1, enabled=False, stylus_overdue=True, belt_overdue=True)) == []

    def test_stylus_without_life_tracking_reports_nothing(self):
        assert _maintenance(_snap(1, stylus_life_hours=0, stylus_overdue=True)) == []

    def test_ids_match_the_dial_pattern(self):
        everything = dict(stylus_overdue=True, belt_overdue=True, bearing_overdue=True)
        out = _maintenance(_snap(1, **everything), _snap(2, **everything))
        assert len(out) == 6
        for w in out:
            assert dial_core_state.APPLIANCE_WARNING_ID_RE.fullmatch(w.id)


class TestOrderingAndCap:
    def test_overdue_before_due_soon_across_inputs(self):
        out = _maintenance(
            _snap(1, stylus_warning=True, stylus_remaining_hours=3.0),
            _snap(2, belt_overdue=True),
        )
        assert [w.id for w in out] == ["belt_in2", "stylus_in1"]

    def test_psu_follows_maintenance(self):
        with patch("autostream_core.get_playback_snapshot",
                   return_value=_playback(_snap(1, stylus_warning=True, stylus_remaining_hours=1.0))), \
             patch("autostream_system_stats._read_get_throttled_value", return_value=0x1):
            out = dw.current_warnings()
        assert [w.id for w in out] == ["stylus_in1", "psu"]

    def test_cap_is_eight_and_keeps_the_front(self):
        many = [dw.DialWarning(f"w{i}", "warning", "T", "m", "day") for i in range(12)]
        with patch.object(dw, "WARNING_PROVIDERS", (lambda: many,)):
            out = dw.current_warnings()
        assert [w.id for w in out] == [f"w{i}" for i in range(8)]

    def test_duplicate_ids_are_dropped(self):
        a = dw.DialWarning("x", "warning", "First", "m", "day")
        b = dw.DialWarning("x", "critical", "Second", "m", "day")
        with patch.object(dw, "WARNING_PROVIDERS", (lambda: [a, b],)):
            assert dw.current_warnings() == [a]

    def test_a_raising_provider_contributes_nothing(self):
        good = dw.DialWarning("ok", "warning", "T", "m", "day")

        def boom():
            raise RuntimeError("provider failed")

        with patch.object(dw, "WARNING_PROVIDERS", (boom, lambda: [good])):
            assert dw.current_warnings() == [good]

    def test_empty_title_is_dropped(self):
        blank = dw.DialWarning("x", "warning", " ​ ", "m", "day")
        with patch.object(dw, "WARNING_PROVIDERS", (lambda: [blank],)):
            assert dw.current_warnings() == []


class TestTextCleaning:
    def test_clean_matches_the_dials_own_cleaning(self):
        samples = [
            "plain", "  spaced   out  ", "tab\tand\nnewline", "a‮b​c",
            "x" * 300, "é", "\ud800broken", "\x00nul",
        ]
        for text in samples:
            for limit in (5, 40, 120):
                assert dw.clean_display_text(text, limit) == dial_core_state._clean_text(text, limit)

    def test_non_string_is_empty(self):
        assert dw.clean_display_text(None, 10) == ""

    def test_fit_adds_an_ellipsis_when_shortened(self):
        out = dw.fit_display_text("x" * 50, 10)
        assert len(out) == 10 and out.endswith("…")

    def test_fit_leaves_short_text_alone(self):
        assert dw.fit_display_text("short", 10) == "short"

    def test_long_label_shortens_only_the_label(self):
        (w,) = _maintenance(_snap(1, label="L" * 100, bearing_overdue=True))
        assert len(w.title) == dw.TITLE_MAX
        assert w.title.endswith(" main bearing")
        assert "…" in w.title

    def test_label_control_characters_are_cleaned(self):
        (w,) = _maintenance(_snap(1, label="Deck‮\n  one", belt_overdue=True))
        assert w.title == "Deck one drive belt"


class TestPsu:
    @staticmethod
    def _psu(value):
        with patch("autostream_system_stats._read_get_throttled_value", return_value=value):
            return dw._psu_warnings()

    def test_undervoltage_now(self):
        (w,) = self._psu(0x1)
        assert w == dw.DialWarning(
            "psu", "critical", "Power supply",
            "Undervoltage detected. Replace the PSU or cable.", "day")

    def test_undervoltage_now_wins_over_history(self):
        (w,) = self._psu(0x10001)
        assert w.severity == "critical"

    def test_undervoltage_since_boot(self):
        (w,) = self._psu(0x10000)
        assert w == dw.DialWarning(
            "psu", "warning", "Power supply",
            "Undervoltage was detected earlier. Check the PSU and cable.", "week")

    def test_history_is_reported_every_time(self):
        assert self._psu(0x10000) == self._psu(0x10000) != []

    def test_other_throttle_bits_are_not_undervoltage(self):
        assert self._psu(0x20002) == []

    def test_clean_and_unreadable(self):
        assert self._psu(0) == []
        assert self._psu(None) == []


class TestDigest:
    def test_stable_for_equal_sets(self):
        a = [dw.DialWarning("x", "warning", "T", "m", "day")]
        b = [dw.DialWarning("x", "warning", "T", "m", "day")]
        assert dw.warnings_digest(a) == dw.warnings_digest(b)

    @pytest.mark.parametrize("field,value", [
        ("severity", "critical"), ("title", "Other"), ("message", "n"),
        ("dismissal", "week"), ("id", "y"),
    ])
    def test_any_field_change_moves_it(self, field, value):
        base = dw.DialWarning("x", "warning", "T", "m", "day")
        assert dw.warnings_digest([base]) != dw.warnings_digest([replace(base, **{field: value})])

    def test_empty_set_differs_from_one_warning(self):
        assert dw.warnings_digest([]) != dw.warnings_digest(
            [dw.DialWarning("x", "warning", "T", "m", "day")])


class TestDialValidatorCrossCheck:
    APPLIANCE_ID = "a1b2c3d4e5f6a7b8c9d0"

    def _through_the_dial(self, warnings):
        body = {"ok": True, "appliance_id": self.APPLIANCE_ID,
                "warnings": dw.warnings_payload(warnings)}
        return dial_core_state.validate_appliance_warnings(json.dumps(body), self.APPLIANCE_ID)

    @staticmethod
    def _fields(w):
        return (w.id, w.severity, w.title, w.message, w.dismissal)

    def _assert_unchanged(self, produced):
        got = self._through_the_dial(produced)
        assert [self._fields(w) for w in got] == [self._fields(w) for w in produced]

    def test_every_provider_at_worst_case_text(self):
        everything = dict(stylus_overdue=True, belt_overdue=True, bearing_overdue=True)
        worst_label = "W" * 200
        with patch("autostream_core.get_playback_snapshot", return_value=_playback(
                _snap(1, label=worst_label, **everything),
                _snap(2, label=worst_label, **everything))), \
             patch("autostream_system_stats._read_get_throttled_value", return_value=0x10001):
            produced = dw.current_warnings()
        assert len(produced) == 7
        self._assert_unchanged(produced)
        assert max(len(w.title) for w in produced) == dw.TITLE_MAX

    def test_due_soon_variants_at_worst_case_text(self):
        with patch("autostream_core.get_playback_snapshot", return_value=_playback(
                _snap(1, label="W" * 200, stylus_warning=True, stylus_remaining_hours=99999.9,
                      belt_warning=True, bearing_warning=True),
                _snap(2, label="é" * 200, stylus_warning=True, stylus_remaining_hours=0.0))), \
             patch("autostream_system_stats._read_get_throttled_value", return_value=0x10000):
            produced = dw.current_warnings()
        assert len(produced) == 5
        self._assert_unchanged(produced)

    def test_limits_agree_with_the_dial(self):
        assert dw.TITLE_MAX == dial_core_state.APPLIANCE_WARNING_TITLE_MAX
        assert dw.MESSAGE_MAX == dial_core_state.APPLIANCE_WARNING_MESSAGE_MAX
        assert dw.WARNINGS_MAX == dial_core_state.APPLIANCE_WARNINGS_MAX

    def test_empty_set_is_a_clean_empty_reply(self):
        assert self._through_the_dial([]) == ()
