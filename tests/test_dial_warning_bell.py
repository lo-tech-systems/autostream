"""Tests for dial_warning_bell.py: what a bell holds, its order, its count and
severity, which appliances a whole bell counts, and where the dial's own
update warning sits."""
from __future__ import annotations

import dataclasses
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
for _sub in ("dial", "tests"):
    _p = str(REPO_ROOT / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)

import hd_scenarios as hs
from dial_appliance_warnings import ApplianceWarning
from dial_core_state import AUTH_AUTHORIZED, AUTH_UNAUTHORIZED, AUTH_UNKNOWN, WarningState
from dial_warning_bell import (
    DIAL_SOURCE, Bell, BellEntry, appliance_bell, dial_bell, rostered, whole_bell,
)
from dial_warning_text import WARNING_DESCRIPTORS, appliance_warning_descriptor, appliance_warning_key
from dial_warnings import ACTION_RESTART

KITCHEN = "b" * 20


def _snapshot(active=None, appliances=None, extra=()):
    base = hs.SCENARIOS["nothing_playing"].snapshot
    changes = {"warnings": hs.warning_states(active or {}, extra=extra)}
    if appliances is not None:
        changes["appliances"] = tuple(appliances)
    return dataclasses.replace(base, **changes)


def _appliance(aid, name, *warnings, auth=AUTH_AUTHORIZED):
    return dataclasses.replace(
        hs.appliance(aid, name), auth=auth,
        warnings=tuple(ApplianceWarning(*w, appliance_name=name) for w in warnings),
    )


class TestBell:
    def test_an_empty_bell_has_no_count_and_no_severity(self):
        bell = Bell(())
        assert bell.count == 0 and bell.severity is None

    def test_the_severity_is_the_worst_entry(self):
        def entry(severity):
            return BellEntry("k", "s", severity, "t", "m", ())
        assert Bell((entry("info"), entry("warning"))).severity == "warning"
        assert Bell((entry("info"), entry("critical"), entry("warning"))).severity == "critical"
        assert Bell((entry("info"),)).severity == "info"
        assert Bell((entry("info"), entry("info"))).count == 2


class TestDialBell:
    def test_nothing_active_is_an_empty_bell(self):
        assert dial_bell(_snapshot(), WARNING_DESCRIPTORS) == Bell(())

    def test_the_sd_card_entry_reads_its_text_and_attribution(self):
        bell = dial_bell(_snapshot({"sdhealth": ("low", 18)}), WARNING_DESCRIPTORS)
        assert bell.entries == (BellEntry(
            "sdhealth", DIAL_SOURCE, "warning", "microSD card", "18% life left, replace soon", ()),)

    def test_the_failing_sd_card_is_critical(self):
        assert dial_bell(_snapshot({"sdhealth": ("failing", 2)}), WARNING_DESCRIPTORS).severity == "critical"

    def test_no_wifi_carries_restart_beside_close(self):
        (entry,) = dial_bell(_snapshot({"nowifi": None}), WARNING_DESCRIPTORS).entries
        assert (entry.key, entry.title, entry.severity) == ("nowifi", "No WiFi", "warning")
        assert entry.actions == (ACTION_RESTART,)

    def test_the_protocol_warning_is_one_dial_entry_naming_the_appliances(self):
        bell = dial_bell(
            _snapshot({"update_dial": ("Lounge", "Kitchen")}), WARNING_DESCRIPTORS)
        (entry,) = bell.entries
        assert entry.key == "update_dial" and entry.source == DIAL_SOURCE
        assert entry.title == "Update this dial"
        assert entry.message == "Lounge, Kitchen need a newer dial"
        assert entry.severity == "warning" and entry.actions == ()

    def test_a_status_is_not_in_the_bell(self):
        snap = _snapshot({"update": hs.SCENARIOS["warning_update"].snapshot.update,
                          "update_result": hs.SCENARIOS["warning_update_result"].snapshot.update})
        assert dial_bell(snap, WARNING_DESCRIPTORS) == Bell(())

    def test_an_appliances_warning_is_not_in_the_dial_bell(self):
        warning = ApplianceWarning("stylus", "warning", "Stylus", "Soon", appliance_name="Lounge")
        key = appliance_warning_key(hs.LOUNGE, "stylus")
        snap = _snapshot({key: "warning"}, extra=(key,))
        descriptors = WARNING_DESCRIPTORS + (appliance_warning_descriptor(hs.LOUNGE, warning),)
        assert dial_bell(snap, descriptors) == Bell(())

    def test_worst_first_then_registry_order(self):
        snap = _snapshot({"update_dial": ("Lounge",), "nowifi": None, "sdhealth": ("failing", 2)})
        bell = dial_bell(snap, WARNING_DESCRIPTORS)
        assert [e.key for e in bell.entries] == ["sdhealth", "nowifi", "update_dial"]
        assert [e.severity for e in bell.entries] == ["critical", "warning", "warning"]

    def test_an_active_state_without_a_descriptor_is_skipped(self):
        assert dial_bell(_snapshot({"sdhealth": ("low", 18)}), ()) == Bell(())

    def test_descriptors_may_be_given_as_a_mapping(self):
        mapping = {d.id: d for d in WARNING_DESCRIPTORS}
        assert dial_bell(_snapshot({"sdhealth": ("low", 18)}), mapping).count == 1

    def test_an_inactive_state_is_skipped(self):
        snap = dataclasses.replace(_snapshot({"sdhealth": ("low", 18)}), warnings=tuple(
            WarningState(w.id, False, None, None) for w in _snapshot({"sdhealth": ("low", 18)}).warnings))
        assert dial_bell(snap, WARNING_DESCRIPTORS).count == 0


class TestApplianceBell:
    def test_an_appliance_with_none_has_an_empty_bell(self):
        assert appliance_bell(_appliance(hs.LOUNGE, "Lounge")) == Bell(())

    def test_each_warning_is_an_entry_attributed_to_the_appliance(self):
        a = _appliance(hs.LOUNGE, "Lounge", ("stylus_in1", "warning", "Stylus", "Soon"))
        (entry,) = appliance_bell(a).entries
        assert entry == BellEntry(
            f"appliance:{hs.LOUNGE}:stylus_in1", "Lounge", "warning", "Stylus", "Soon", ())

    def test_worst_first_and_ties_keep_the_reported_order(self):
        a = _appliance(
            hs.LOUNGE, "Lounge",
            ("a", "info", "A", ""), ("b", "critical", "B", ""), ("c", "warning", "C", ""),
            ("d", "critical", "D", ""),
        )
        bell = appliance_bell(a)
        assert [e.title for e in bell.entries] == ["B", "D", "C", "A"]
        assert bell.severity == "critical" and bell.count == 4

    def test_the_older_appliance_warning_is_on_its_row(self):
        scenario = hs.SCENARIOS["appliance_needs_update"]
        (entry,) = appliance_bell(scenario.snapshot.appliances[0]).entries
        assert entry.title == "Update Lounge" and entry.source == "Lounge"


class TestWholeBell:
    def _snap(self):
        lounge = _appliance(hs.LOUNGE, "Lounge", ("a", "info", "Lounge info", ""))
        kitchen = _appliance(KITCHEN, "Kitchen", ("b", "critical", "Kitchen critical", ""))
        return _snapshot({"nowifi": None}, appliances=(lounge, kitchen))

    def test_it_counts_the_dial_and_every_appliance(self):
        bell = whole_bell(self._snap(), WARNING_DESCRIPTORS)
        assert bell.count == 3 and bell.severity == "critical"

    def test_order_is_worst_first_dial_before_appliances_among_equals(self):
        bell = whole_bell(self._snap(), WARNING_DESCRIPTORS)
        assert [e.title for e in bell.entries] == ["Kitchen critical", "No WiFi", "Lounge info"]
        assert [e.source for e in bell.entries] == ["Kitchen", DIAL_SOURCE, "Lounge"]

    def test_it_holds_nothing_when_nothing_is_wrong(self):
        assert whole_bell(_snapshot(), WARNING_DESCRIPTORS) == Bell(())

    def test_the_dials_update_warning_is_counted_once_however_many_appliances(self):
        snap = _snapshot({"update_dial": ("Lounge", "Kitchen")}, appliances=(
            _appliance(hs.LOUNGE, "Lounge"), _appliance(KITCHEN, "Kitchen")))
        assert whole_bell(snap, WARNING_DESCRIPTORS).count == 1

    @pytest.mark.parametrize("auth, counted", [
        (AUTH_AUTHORIZED, True), (AUTH_UNAUTHORIZED, True), (AUTH_UNKNOWN, False),
    ])
    def test_only_the_appliances_the_dial_shows_are_counted(self, auth, counted):
        a = _appliance(KITCHEN, "Kitchen", ("w", "warning", "W", ""), auth=auth)
        snap = _snapshot(appliances=(a,))
        assert whole_bell(snap, WARNING_DESCRIPTORS).count == (1 if counted else 0)
        assert (a in rostered(snap)) is counted

    def test_an_appliance_without_an_identity_is_not_counted(self):
        a = dataclasses.replace(
            _appliance(KITCHEN, "Kitchen", ("w", "warning", "W", "")), appliance_id="")
        assert whole_bell(_snapshot(appliances=(a,)), WARNING_DESCRIPTORS).count == 0

    def test_the_rostered_set_is_the_hd_list(self):
        from dial_hd_state import build_parts
        scenario = hs.SCENARIOS["appliance_warning"]
        shown = [a["id"] for a in build_parts(
            scenario.snapshot, descriptors=scenario.descriptors)["dial"]["appliances"]]
        assert [a.appliance_id for a in rostered(scenario.snapshot)] == shown
