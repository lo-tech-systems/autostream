"""Tests for the HD page's two-part state: build_parts (the `dial` and
`focused` parts from one core snapshot), the per-step diff, and the `since`
and resync rule. All pure functions; no server."""
from __future__ import annotations

import dataclasses
from types import MappingProxyType
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dial"))

import hd_scenarios as hs
from dial_hd_events import (
    PartDiffer, change_bytes, encode_parts, must_resync, parse_since, state_bytes,
)
from dial_hd_state import FOCUSED_PART_NAMES, build_parts, build_state
from dial_pool_support import Rig, peer, replay_block, unit

BOOT = "0123456789abcdef"
LOUNGE = hs.LOUNGE


def parts_of(scenario, **overrides):
    scenario = dataclasses.replace(scenario, **overrides)
    return build_parts(
        scenario.snapshot, descriptors=scenario.descriptors, panel=scenario.panel,
        settings=scenario.settings, recovery=scenario.recovery, now=scenario.now,
        wall_now=scenario.wall_now,
    )


def with_peer(name, **kwargs):
    base = hs.SCENARIOS[name]
    return base.with_snapshot(focused_peer=peer("Lounge", **kwargs))


class TestDialPart:
    def test_it_carries_no_envelope_reading_and_none_of_the_appliances_own_parts(self):
        part = parts_of(hs.SCENARIOS["playing_artwork"])["dial"]
        for key in ("seq", "now", "core_seq", "now_playing", "volume", "outputs", "outputs_available",
                    "eq", "eq_available"):
            assert key not in part
        assert part["v"] == 2

    def test_it_keeps_what_the_page_draws_from_the_dial(self):
        part = parts_of(hs.SCENARIOS["playing_artwork"])["dial"]
        for key in ("started", "polling", "dial", "focus", "appliances", "artwork", "transport",
                    "outputs_request", "start_failure", "warnings", "network", "sd_health", "update",
                    "panel", "recovery", "power"):
            assert key in part
        assert part["artwork"]["url"].startswith("/api/v1/artwork/")

    def test_focus_names_the_reporting_appliance(self):
        part = parts_of(hs.SCENARIOS["playing_artwork"])["dial"]
        assert part["focus"]["reporting_id"] == LOUNGE

    def test_an_appliance_block_has_update_needed_and_no_volume_or_capabilities(self):
        for row in parts_of(hs.SCENARIOS["appliance_needs_update"])["dial"]["appliances"]:
            assert "update_needed" in row and "webui" in row
            for key in ("volume", "muted", "capabilities"):
                assert key not in row

    def test_the_panel_loses_the_older_page_key(self):
        assert "always_show_controls" not in parts_of(hs.SCENARIOS["playing_artwork"])["dial"]["panel"]

    @pytest.mark.parametrize("name", hs.SCENARIO_NAMES)
    def test_it_does_not_change_when_only_the_clock_does(self, name):
        scenario = hs.SCENARIOS[name]
        first = parts_of(scenario)["dial"]
        later = parts_of(scenario, now=scenario.now + 37.5)["dial"]
        assert json.dumps(first, sort_keys=True) == json.dumps(later, sort_keys=True)

    def test_a_replaying_position_is_the_reported_one_with_its_observed_at(self):
        scenario = hs.SCENARIOS["replaying"]
        part = parts_of(scenario)["dial"]
        old = build_state(scenario.snapshot, now=scenario.now, wall_now=scenario.wall_now)
        row = next(a for a in part["appliances"] if a["repeat"] is not None)
        old_row = next(a for a in old["appliances"] if a["repeat"] is not None)
        assert row["repeat"]["observed_at"] == old_row["repeat"]["observed_at"]
        # The full body carries the position on to now; the part does not.
        assert row["repeat"]["position_s"] <= old_row["repeat"]["position_s"]
        later = parts_of(scenario, now=scenario.now + 10)["dial"]
        assert next(a for a in later["appliances"] if a["repeat"] is not None)["repeat"] == row["repeat"]

    def test_it_changes_when_something_in_it_does(self):
        base = hs.SCENARIOS["playing_artwork"]
        other = base.with_snapshot(power=dataclasses.replace(base.snapshot.power, state="requested"))
        assert parts_of(base)["dial"] != parts_of(other)["dial"]


class TestFocusedPart:
    def test_it_is_null_with_no_focus(self):
        assert parts_of(hs.SCENARIOS["nothing_playing"])["focused"] is None

    def test_it_carries_the_folded_appliance_snapshot(self):
        scenario = with_peer(
            "playing_artwork", playing=True, boot="bb", version=77, access="playback",
            units=[unit("u1", selected=True)], bands=[0, 1, 2, 3, 4, 5],
            repeat=replay_block(), warnings=[{"id": "stylus"}])
        focused = parts_of(scenario)["focused"]
        assert focused["id"] == scenario.snapshot.focused_peer.peer_id
        assert (focused["boot"], focused["version"], focused["reachable"], focused["access"]) == (
            "bb", 77, True, "playback")

    def test_parts_are_limited_to_the_six_the_page_reads_and_passed_through(self):
        scenario = with_peer(
            "playing_artwork", playing=True, units=[unit()], bands=[0] * 6, repeat=replay_block(),
            warnings=[{"id": "stylus"}], track_entry={"state": "identified", "title": "T"})
        peer_now = scenario.snapshot.focused_peer
        held_parts = dict(peer_now.parts, inputs={"entries": [{"index": 1, "input_type": "cd"}]})
        scenario = scenario.with_snapshot(
            focused_peer=dataclasses.replace(peer_now, parts=MappingProxyType(held_parts)))
        focused = parts_of(scenario)["focused"]
        held = scenario.snapshot.focused_peer.parts
        assert set(focused["parts"]) == set(FOCUSED_PART_NAMES)
        assert "warnings" not in focused["parts"] and "appliance" not in focused["parts"]
        for name in FOCUSED_PART_NAMES:
            assert focused["parts"][name] == held[name]

    def test_an_absent_part_is_left_out_not_nulled(self):
        focused = parts_of(with_peer("playing_artwork", outputs=False))["focused"]
        assert "outputs" not in focused["parts"] and "eq" not in focused["parts"]

    def test_it_is_json_serialisable(self):
        scenario = with_peer("playing_artwork", playing=True, units=[unit()], bands=[0] * 6)
        assert json.loads(encode_parts(parts_of(scenario))["focused"])["parts"]["outputs"]["units"]


class TestOnePublish:
    def test_both_parts_come_from_the_one_snapshot_not_a_live_read(self):
        rig = Rig()
        try:
            client = rig.add("Lounge", peer("Lounge", playing=True, version=5, units=[unit(selected=True)]))
            snapshot = rig.fold()
            assert snapshot.focused_peer is not None
            # The appliance moves on after the publish; the parts still show the fold.
            rig.set("Lounge", peer("Lounge", playing=True, version=6, units=[unit(selected=False)]))
            parts = build_parts(snapshot, now=1.0)
            assert parts["focused"]["version"] == 5
            assert parts["focused"]["parts"]["outputs"]["units"][0]["selected"] is True
            roster = {a["id"]: a for a in parts["dial"]["appliances"]}
            assert parts["focused"]["id"] in roster
            assert parts["dial"]["focus"]["reporting_id"] == parts["focused"]["id"]
            assert client.fetches() == []
        finally:
            rig.close()

    def test_building_reads_only_the_snapshot_it_is_given(self):
        scenario = with_peer("playing_artwork", playing=True)
        first = parts_of(scenario)
        again = parts_of(scenario)
        assert encode_parts(first) == encode_parts(again)


class Builder:
    def __init__(self, parts):
        self.parts = parts
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return self.parts


class TestPartDiffer:
    def make(self, count):
        self.count = [count]
        return PartDiffer(lambda: self.count[0])

    def test_with_no_client_nothing_is_built_and_no_step_is_made(self):
        differ = self.make(0)
        build = Builder({"dial": {"a": 1}, "focused": None})
        for seq in range(2, 12):
            assert differ.step(seq, build) is None
        assert build.calls == 0

    def test_the_first_step_after_a_client_connects_has_both_parts(self):
        differ = self.make(0)
        build = Builder({"dial": {"a": 1}, "focused": {"id": "x", "version": 9}})
        for seq in range(2, 6):
            differ.step(seq, build)
        self.count[0] = 1
        step = differ.step(6, build)
        assert build.calls == 1
        assert set(step.changed) == {"dial", "focused"}
        assert step.versions == {"dial": 6, "focused": 9}

    def test_a_following_step_with_no_change_carries_nothing(self):
        differ = self.make(1)
        build = Builder({"dial": {"a": 1}, "focused": None})
        differ.step(2, build)
        step = differ.step(3, build)
        assert step.changed == {}
        assert build.calls == 2

    def test_only_the_part_whose_bytes_changed_is_carried(self):
        differ = self.make(1)
        differ.step(2, Builder({"dial": {"a": 1}, "focused": {"id": "x", "version": 4}}))
        step = differ.step(3, Builder({"dial": {"a": 2}, "focused": {"id": "x", "version": 4}}))
        assert list(step.changed) == ["dial"]
        step = differ.step(4, Builder({"dial": {"a": 2}, "focused": {"id": "x", "version": 5}}))
        assert list(step.changed) == ["focused"]
        assert step.versions == {"dial": 3, "focused": 5}

    def test_a_change_of_focus_to_none_is_a_change_and_drops_the_version(self):
        differ = self.make(1)
        differ.step(2, Builder({"dial": {}, "focused": {"id": "x", "version": 4}}))
        step = differ.step(3, Builder({"dial": {}, "focused": None}))
        assert step.changed == {"focused": b"null"}
        assert "focused" not in step.versions

    def test_a_client_leaving_drops_the_baseline(self):
        differ = self.make(1)
        build = Builder({"dial": {"a": 1}, "focused": None})
        differ.step(2, build)
        self.count[0] = 0
        assert differ.step(3, build) is None
        self.count[0] = 1
        assert set(differ.step(4, build).changed) == {"dial", "focused"}

    def test_each_step_builds_once_whatever_the_part_count(self):
        differ = self.make(2)
        build = Builder({"dial": {"a": 1}, "focused": None})
        differ.step(2, build)
        differ.step(3, build)
        assert build.calls == 2

    def test_a_dial_part_that_only_the_clock_moves_is_not_a_change(self):
        differ = self.make(1)
        scenario = hs.SCENARIOS["replaying"]
        differ.step(2, lambda: parts_of(scenario, now=scenario.now))
        step = differ.step(3, lambda: parts_of(scenario, now=scenario.now + 20))
        assert step.changed == {}


class TestSince:
    @pytest.mark.parametrize("value, expected", [
        (BOOT + "-812", (BOOT, 812)),
        (BOOT + "-0", (BOOT, 0)),
    ])
    def test_a_well_formed_id_is_read(self, value, expected):
        assert parse_since(value) == expected

    @pytest.mark.parametrize("value", [
        None, "", "812", BOOT, BOOT + "-", BOOT + "-x", "short-5", BOOT.upper() + "-5",
        BOOT + "-5 ", BOOT + "-1234567890123456789", "-" + BOOT + "-5",
    ])
    def test_anything_else_is_no_position(self, value):
        assert parse_since(value) is None

    def test_a_client_at_this_boot_and_sequence_is_current(self):
        assert not must_resync((BOOT, 812), BOOT, 812)

    @pytest.mark.parametrize("since", [
        None, (BOOT, 811), (BOOT, 813), ("fedcba9876543210", 812),
    ])
    def test_any_other_must_resync(self, since):
        assert must_resync(since, BOOT, 812)


class TestWire:
    def parts(self):
        return encode_parts({"dial": {"v": 2, "x": "é"}, "focused": None})

    def test_the_state_body_has_the_sequence_time_versions_and_parts(self):
        differ = PartDiffer(lambda: 1)
        built = {"dial": {"v": 2}, "focused": {"id": "a", "version": 4}}
        step = differ.step(812, lambda: built)
        body = json.loads(state_bytes(BOOT, 812, 41873.512, step, encode_parts(built)))
        assert body == {
            "boot": BOOT, "version": 812, "time": 41873.512,
            "part_versions": {"dial": 812, "focused": 4},
            "parts": built,
        }

    def test_a_state_body_with_no_focus_has_a_null_part_and_no_focused_version(self):
        differ = PartDiffer(lambda: 1)
        built = {"dial": {"v": 2}, "focused": None}
        step = differ.step(5, lambda: built)
        body = json.loads(state_bytes(BOOT, 5, 1.0, step, encode_parts(built)))
        assert body["parts"]["focused"] is None and "focused" not in body["part_versions"]

    def test_a_change_event_carries_only_the_changed_parts_under_the_boot_and_sequence_id(self):
        raw = change_bytes(BOOT, 813, 2.5, {"dial": b'{"v":2}'})
        lines = raw.decode("utf-8").split("\n")
        assert lines[0] == f"id: {BOOT}-813" and lines[1] == "event: change"
        assert raw.endswith(b"\n\n")
        data = json.loads(lines[2][len("data: "):])
        assert data == {"boot": BOOT, "version": 813, "time": 2.5, "resync": False, "data": {"dial": {"v": 2}}}

    def test_a_resync_event_carries_no_data(self):
        raw = change_bytes(BOOT, 813, 2.5, {"dial": b"{}"}, resync=True)
        data = json.loads(raw.decode("utf-8").split("\n")[2][len("data: "):])
        assert data["resync"] is True and data["data"] == {}

    def test_non_ascii_text_stays_valid_json(self):
        raw = change_bytes(BOOT, 1, 0.0, self.parts())
        data = json.loads(raw.decode("utf-8").split("\n")[2][len("data: "):])
        assert data["data"]["dial"]["x"] == "é"
