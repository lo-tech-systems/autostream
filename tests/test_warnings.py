"""tests/test_warnings.py

The warnings text table: one case per row, the order, the cap, the lengths,
which rows are critical, and the microSD hysteresis.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_state as state
import autostream_warnings as w

LONG_LABEL = "A very long turntable label that cannot possibly fit"


def snap(label="Turntable", *, enabled=True, stylus="", belt="", bearing="",
         life=1000, remaining=None):
    """One input's playback view; each item is "", "due" or "overdue"."""
    return SimpleNamespace(
        label=label, enabled=enabled, stylus_life_hours=life,
        stylus_remaining_hours=remaining,
        stylus_warning=stylus == "due", stylus_overdue=stylus == "overdue",
        belt_warning=belt == "due", belt_overdue=belt == "overdue",
        bearing_warning=bearing == "due", bearing_overdue=bearing == "overdue",
    )


def make(inputs=None, *, entries=(), **kw):
    values = dict(
        playback=SimpleNamespace(inputs=inputs if inputs is not None else {1: snap()}),
        inputs=state.InputsPart(entries=tuple(entries)),
        throttled=0, cpu_temp_c=None, cpu_status="ok", sd_percent=None,
        sd_level="ok", dials_needing_update=0, unlicensed=False,
    )
    values.update(kw)
    return w.Inputs(**values)


def mismatch(index):
    return state.InputEntry(
        index=index, device="d", input_type="line", capturing=True, replay_origin=False,
        rate_note="", sample_rate_text="", rate_mismatch_hz=44100, level=state.FrozenDict())


def only(entries):
    assert len(entries) == 1
    return entries[0]


class TestRows:
    def test_nothing_to_say(self):
        assert w.derive(make()) == ()

    def test_psu_now(self):
        e = only(w.derive(make(throttled=0x1)))
        assert (e.id, e.severity, e.kind, e.title, e.message, e.link) == (
            "psu", "critical", "psu", "Power supply", "Low voltage now", None)

    def test_psu_since_boot_only(self):
        e = only(w.derive(make(throttled=0x10000)))
        assert (e.severity, e.message) == ("warning", "Low voltage seen earlier")

    def test_now_wins_over_earlier(self):
        assert only(w.derive(make(throttled=0x10001))).message == "Low voltage now"

    @pytest.mark.parametrize("bits", [1 << 18, 1 << 19, 1 << 3, 1 << 2])
    def test_other_throttle_bits_say_nothing(self, bits):
        assert w.derive(make(throttled=bits)) == ()

    def test_cpu_hot_and_too_hot(self):
        hot = only(w.derive(make(cpu_status="high", cpu_temp_c=71.6)))
        assert (hot.id, hot.severity, hot.message) == (
            "cpu_temp", "warning", "Running hot, 72 °C")
        crit = only(w.derive(make(cpu_status="critical", cpu_temp_c=81.2)))
        assert (crit.severity, crit.message) == ("critical", "Too hot, 81 °C")

    def test_sd_failing_and_low(self):
        bad = only(w.derive(make(sd_percent=8, sd_level="failing")))
        assert (bad.severity, bad.message, bad.link, bad.title) == (
            "critical", "8% life left, replace now", "/about", "microSD card")
        low = only(w.derive(make(sd_percent=18, sd_level="low")))
        assert (low.severity, low.message) == (
            "warning", "18% life left, replace soon")

    def test_sd_unknown_says_nothing(self):
        assert w.derive(make(sd_percent=None, sd_level="low")) == ()

    def test_stylus_overdue_and_due(self):
        over = only(w.derive(make({1: snap(stylus="overdue")})))
        assert (over.id, over.severity, over.kind, over.subject, over.title, over.message,
                over.link) == (
            "stylus_in1", "warning", "stylus", "Turntable", "Turntable stylus",
            "Change now", "/service")
        due = only(w.derive(make({1: snap(stylus="due", remaining=4.46)})))
        assert (due.severity, due.message) == (
            "info", "Change soon, 4.5 h left")
        assert only(w.derive(make({1: snap(stylus="due")}))).message == "Change soon"

    def test_a_stylus_with_no_life_set_says_nothing(self):
        assert w.derive(make({1: snap(stylus="overdue", life=0)})) == ()

    def test_a_disabled_input_says_nothing_of_its_wear(self):
        assert w.derive(make({1: snap(enabled=False, belt="overdue"), 2: snap(enabled=True)})) == ()

    @pytest.mark.parametrize("item,title", [("belt", "drive belt"), ("bearing", "main bearing")])
    def test_belt_and_bearing(self, item, title):
        over = only(w.derive(make({2: snap("CD", **{item: "overdue"})})))
        assert (over.id, over.kind, over.title, over.message, over.severity) == (
            f"{item}_in2", item, f"CD {title}", "Service now", "warning")
        due = only(w.derive(make({2: snap("CD", **{item: "due"})})))
        assert (due.message, due.severity) == ("Service soon", "info")

    def test_sample_rate(self):
        e = only(w.derive(make({1: snap(), 2: snap("CD")}, entries=[mismatch(2)])))
        assert (e.id, e.severity, e.kind, e.subject, e.title, e.message, e.link) == (
            "sample_rate_in2", "warning", "sample_rate", "CD", "CD sample rate",
            "Turn on rate matching", "/setup#input2")

    def test_dial_update_wording(self):
        one = only(w.derive(make(dials_needing_update=1)))
        assert (one.id, one.title, one.message, one.link) == (
            "dial_update", "Dials", "1 needs updating", "/setup#dials")
        assert only(w.derive(make(dials_needing_update=3))).message == "3 need updating"

    def test_licence(self):
        e = only(w.derive(make(unlicensed=True)))
        assert (e.id, e.severity, e.message, e.link) == (
            "licence", "warning", "This system is unlicensed", None)

    def test_no_input(self):
        e = only(w.derive(make({1: snap(enabled=False), 2: snap(enabled=False)})))
        assert (e.id, e.severity, e.title, e.message, e.link) == (
            "no_input", "info", "No input", "Set up an input in the web UI", "/setup")

    def test_no_inputs_known_yet_is_not_no_input(self):
        assert w.derive(make({})) == ()


class TestOrderAndCap:
    def test_severity_then_kind_then_input(self):
        out = w.derive(make(
            {1: snap(stylus="due"), 2: snap("CD", stylus="overdue", belt="overdue")},
            throttled=0x1, cpu_status="high", cpu_temp_c=71,
            sd_percent=18, sd_level="low", dials_needing_update=2))
        assert [e.id for e in out] == [
            "psu", "cpu_temp", "sd_health", "stylus_in2", "belt_in2", "dial_update",
            "stylus_in1"]

    def test_the_cap_drops_the_lowest(self):
        many = {i: snap(f"In {i}", stylus="due") for i in range(1, 21)}
        out = w.derive(make(many, throttled=0x1))
        assert len(out) == w.MAX_ENTRIES
        assert out[0].id == "psu"
        assert out[-1].id == "stylus_in15"


class TestShape:
    def test_only_the_appliance_faults_are_critical(self):
        everything = make(
            {1: snap(stylus="overdue", belt="overdue", bearing="overdue")},
            entries=[mismatch(1)], throttled=0x1, cpu_status="critical", cpu_temp_c=85,
            sd_percent=5, sd_level="failing", dials_needing_update=1, unlicensed=True)
        out = w.derive(everything)
        assert {e.id for e in out if e.severity == "critical"} == {"psu", "cpu_temp", "sd_health"}
        for e in out:
            assert e.incident == ""

    def test_titles_and_messages_fit_at_the_longest_label(self):
        everything = make(
            {1: snap(LONG_LABEL, stylus="due", remaining=99.9, belt="overdue", bearing="due")},
            entries=[mismatch(1)], throttled=0x1, cpu_status="critical", cpu_temp_c=100,
            sd_percent=15, sd_level="failing", dials_needing_update=99, unlicensed=True)
        out = w.derive(everything)
        assert len(out) >= 8
        for e in out:
            assert 0 < len(e.title) <= w.TITLE_MAX, e
            assert 0 < len(e.message) <= w.MESSAGE_MAX, e

    def test_the_other_messages_fit(self):
        for kw in (dict(sd_percent=25, sd_level="low"), dict(cpu_status="high", cpu_temp_c=99),
                   dict(throttled=0x10000)):
            for e in w.derive(make(**kw)):
                assert len(e.message) <= w.MESSAGE_MAX

    def test_a_long_label_is_shortened_not_the_suffix(self):
        e = only(w.derive(make({1: snap(LONG_LABEL, belt="due")})))
        assert e.title.endswith(" drive belt") and e.title.count("…") == 1

    def test_ids_are_kind_ids(self):
        out = w.derive(make({1: snap(stylus="due"), 2: snap(belt="due")}, entries=[mismatch(1)],
                            throttled=1, dials_needing_update=1))
        assert all(re.fullmatch(r"[a-z0-9_-]{1,32}", e.id) for e in out)


class TestSdLevel:
    @pytest.mark.parametrize("percent,previous,expected", [
        (None, "failing", "ok"),
        (9, "ok", "failing"),
        (10, "ok", "low"),
        (15, "failing", "failing"),
        (16, "failing", "low"),
        (25, "failing", "low"),
        (26, "failing", "ok"),
        (19, "ok", "low"),
        (20, "ok", "ok"),
        (25, "low", "low"),
        (26, "low", "ok"),
        (12, "ok", "low"),
        (15, "low", "low"),
    ])
    def test_thresholds_both_ways(self, percent, previous, expected):
        assert w.sd_level(percent, previous) == expected
