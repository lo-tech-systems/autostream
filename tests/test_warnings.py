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
         life=1000, remaining=None, stylus_used=450, stylus_reset="2026-03-03T10:00:00+00:00",
         belt_why=("hours",), service_at="2025-06-01T09:30:00+00:00", used=800, left=50):
    """One input's playback view; each item is "", "due" or "overdue". The
    hours are given as hours and held as seconds, as the tracker holds them.
    belt_why says which dimensions of a belt or bearing are due."""
    fields = dict(
        label=label, enabled=enabled, stylus_life_hours=life,
        stylus_playback_seconds=stylus_used * 3600,
        stylus_remaining_seconds=None if remaining is None else round(remaining * 3600),
        stylus_warning=stylus == "due", stylus_overdue=stylus == "overdue",
        last_stylus_reset_at=stylus_reset,
    )
    for item, state in (("belt", belt), ("bearing", bearing)):
        fields.update({
            f"{item}_warning": state == "due", f"{item}_overdue": state == "overdue",
            f"{item}_life_hours": 1000, f"{item}_life_years": 2,
            f"{item}_playback_seconds": used * 3600, f"{item}_hours_remaining": left * 3600,
            f"{item}_hours_overdue": state == "overdue" and "hours" in belt_why,
            f"{item}_hours_warning": state == "due" and "hours" in belt_why,
            f"{item}_time_overdue": state == "overdue" and "time" in belt_why,
            f"{item}_time_warning": state == "due" and "time" in belt_why,
            f"last_{item}_service_at": service_at,
        })
    return SimpleNamespace(**fields)


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
        assert (e.severity, e.message, e.detail) == (
            "warning", "Low voltage seen", "Low voltage was seen since the last restart.")

    def test_now_wins_over_earlier(self):
        assert only(w.derive(make(throttled=0x10001))).message == "Low voltage now"

    @pytest.mark.parametrize("bits", [1 << 18, 1 << 19, 1 << 3, 1 << 2])
    def test_other_throttle_bits_say_nothing(self, bits):
        assert w.derive(make(throttled=bits)) == ()

    def test_cpu_hot_and_too_hot(self):
        hot = only(w.derive(make(cpu_status="high", cpu_temp_c=71.6)))
        assert (hot.id, hot.severity, hot.message, hot.detail) == (
            "cpu_temp", "warning", "Running hot", "CPU at 72 °C.")
        crit = only(w.derive(make(cpu_status="critical", cpu_temp_c=81.2)))
        assert (crit.severity, crit.message, crit.detail) == ("critical", "Too hot", "CPU at 81 °C.")
        assert only(w.derive(make(cpu_status="high", cpu_temp_c=None))).detail == ""
        assert hot.link == crit.link == "/about#system"

    def test_sd_failing_and_low(self):
        bad = only(w.derive(make(sd_percent=8, sd_level="failing")))
        assert (bad.severity, bad.message, bad.link, bad.title) == (
            "critical", "Replace now", "/about#system", "microSD card")
        assert bad.detail == "8% of its life left."
        low = only(w.derive(make(sd_percent=18, sd_level="low", sd_read_at="2026-03-03T10:00:00+00:00")))
        assert (low.severity, low.message, low.link) == ("warning", "Replace soon", "/about#system")
        assert low.detail == "18% of its life left. Read 3 Mar 2026."

    def test_licence_and_no_input_have_no_detail(self):
        assert only(w.derive(make(unlicensed=True))).detail == ""
        assert only(w.derive(make({1: snap(enabled=False)}))).detail == ""

    def test_the_entry_helper_fits_a_detail(self):
        entry = w._entry("x", "info", "k", "t", "m", None, detail="word " * 60)
        assert len(entry.detail) == w.DETAIL_MAX and entry.detail.endswith("…")
        assert w._entry("x", "info", "k", "t", "m", None).detail == ""

    def test_sd_unknown_says_nothing(self):
        assert w.derive(make(sd_percent=None, sd_level="low")) == ()

    def test_stylus_overdue_and_due(self):
        over = only(w.derive(make({1: snap(stylus="overdue")})))
        assert (over.id, over.severity, over.kind, over.subject, over.title, over.message,
                over.link) == (
            "stylus_in1", "warning", "stylus", "Turntable", "Turntable stylus",
            "Change now", "/service")
        due = only(w.derive(make({1: snap(stylus="due", remaining=4.46)})))
        assert (due.severity, due.message) == ("info", "Change soon")
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

    def test_the_stylus_detail_gives_the_hours_and_the_date(self):
        over = only(w.derive(make({1: snap(stylus="overdue", life=500)})))
        assert over.detail == "Played 450.0 h of its 500 h life. Last changed 3 Mar 2026."
        due = only(w.derive(make({1: snap(stylus="due", life=500, remaining=50)})))
        assert due.detail == "50.0 h left of its 500 h life. Last changed 3 Mar 2026."

    def test_a_missing_date_drops_its_sentence_not_the_detail(self):
        over = only(w.derive(make({1: snap(stylus="overdue", life=500, stylus_reset=None)})))
        assert over.detail == "Played 450.0 h of its 500 h life."
        assert only(w.derive(make({1: snap(stylus="overdue", stylus_reset="garbage")}))).detail.startswith("Played")

    @pytest.mark.parametrize("item", ["belt", "bearing"])
    def test_belt_and_bearing_details_name_the_cause(self, item):
        hours = only(w.derive(make({1: snap(**{item: "overdue"})})))
        assert hours.detail == "Played 800.0 h of its 1000 h service interval."
        soon = only(w.derive(make({1: snap(**{item: "due"})})))
        assert soon.detail == "50.0 h left of its 1000 h service interval."
        time_only = only(w.derive(make({1: snap(belt_why=("time",), **{item: "overdue"})})))
        assert time_only.detail == "Last serviced 1 Jun 2025, due every 2 years."
        both = only(w.derive(make({1: snap(belt_why=("hours", "time"), **{item: "overdue"})})))
        assert both.detail == ("Played 800.0 h of its 1000 h service interval. "
                               "Last serviced 1 Jun 2025, due every 2 years.")

    def test_sample_rate_detail_gives_the_rate(self):
        assert only(w.derive(make({1: snap(), 2: snap("CD")}, entries=[mismatch(2)]))).detail == (
            "CD is running at 44.1 kHz.")

    def test_sample_rate(self):
        e = only(w.derive(make({1: snap(), 2: snap("CD")}, entries=[mismatch(2)])))
        assert (e.id, e.severity, e.kind, e.subject, e.title, e.message, e.link) == (
            "sample_rate_in2", "warning", "sample_rate", "CD", "CD sample rate",
            "Turn on rate matching", "/setup#input2")

    def test_dial_update_wording(self):
        one = only(w.derive(make(dials_needing_update=1)))
        assert (one.id, one.title, one.message, one.link) == (
            "dial_update", "Dials", "1 needs updating", "/setup#dials")
        assert one.detail == "Update it from Setup, Dials."
        three = only(w.derive(make(dials_needing_update=3)))
        assert (three.message, three.detail) == ("3 need updating", "Update them from Setup, Dials.")

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
