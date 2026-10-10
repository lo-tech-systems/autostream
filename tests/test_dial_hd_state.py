"""Tests for the HD dial's state body (dial_hd_state.build_state), the
scenario corpus it is built from and the FakeCore the later layers drive.

Each scenario has a golden JSON file in tests/golden/hd_state/. To
regenerate them after a deliberate change, run with HD_GOLDEN_UPDATE=1: the
new output must still carry every key the committed file has (the body only
ever grows), and the files are then rewritten.
"""
from __future__ import annotations

import dataclasses
import json
import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dial"))

import hd_scenarios as hs
from hd_fake_core import FakeCore
from dial_core_state import (
    ActionResult, validate_appliance_warnings,
)
from dial_hd_state import STATE_VERSION, STRING_MAX, build_state, dumps

GOLDEN_DIR = Path(__file__).parent / "golden" / "hd_state"
UPDATE = bool(os.environ.get("HD_GOLDEN_UPDATE"))


def _paths(value, prefix=""):
    """Every key path in a JSON value; list items are walked as '[]'."""
    out = set()
    if isinstance(value, dict):
        for k, v in value.items():
            out.add(f"{prefix}.{k}")
            out |= _paths(v, f"{prefix}.{k}")
    elif isinstance(value, list):
        for v in value:
            out |= _paths(v, f"{prefix}[]")
    return out


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield k
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


def _drop_key(value, name):
    if isinstance(value, dict):
        return {k: _drop_key(v, name) for k, v in value.items() if k != name}
    if isinstance(value, list):
        return [_drop_key(v, name) for v in value]
    return value


def _state(name, **overrides):
    return dataclasses.replace(hs.SCENARIOS[name], **overrides).state()


class TestCorpus:
    def test_every_named_scenario_exists(self):
        assert set(hs.SCENARIO_NAMES) == {
            "starting", "nothing_playing", "playing_artwork", "playing_no_artwork",
            "replay_hold", "replaying", "fading_out", "replay_elsewhere", "in_use_speaker",
            "unreachable", "unauthorized", "recovery_pending", "eq_none", "eq_two", "eq_six",
            "warning_sdhealth", "warning_update", "warning_update_result", "warning_nowifi",
            "appliance_warning", "appliance_warning_notice", "disconnected",
        }

    def test_a_build_is_repeatable(self):
        for scenario in hs.SCENARIOS.values():
            assert scenario.state() == scenario.state()


class TestGolden:
    @pytest.mark.parametrize("name", hs.SCENARIO_NAMES)
    def test_matches_the_committed_json(self, name):
        state = hs.SCENARIOS[name].state()
        path = GOLDEN_DIR / f"{name}.json"
        if UPDATE:
            if path.exists():
                old = json.loads(path.read_text(encoding="utf-8"))
                missing = _paths(old) - _paths(state)
                assert not missing, f"{name}: keys removed: {sorted(missing)}"
            GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(state, indent=2, ensure_ascii=False, sort_keys=False) + "\n",
                encoding="utf-8",
            )
            pytest.skip("golden regenerated")
        assert path.exists(), f"{path} is missing; run with HD_GOLDEN_UPDATE=1 to create it"
        assert state == json.loads(path.read_text(encoding="utf-8"))

    def test_the_additive_check_catches_a_removed_key(self):
        old = {"a": {"b": 1}, "c": [{"d": 1}]}
        assert _paths(old) - _paths({"a": {}, "c": [{"d": 1}]}) == {".a.b"}
        assert not _paths(old) - _paths({"a": {"b": 1, "x": 2}, "c": [{"d": 1, "e": 2}], "z": 1})

    def test_every_golden_file_has_a_scenario(self):
        files = {p.stem for p in GOLDEN_DIR.glob("*.json")}
        assert files <= set(hs.SCENARIO_NAMES)


class TestShape:
    def test_every_body_is_versioned_and_json(self):
        for scenario in hs.SCENARIOS.values():
            state = scenario.state(hub_seq=7)
            assert state["v"] == STATE_VERSION == 1
            assert state["seq"] == 7 and state["core_seq"] == scenario.snapshot.seq
            assert json.loads(dumps(state)) == state

    def test_the_wire_form_is_compact_and_keeps_unicode(self):
        wire = dumps({"a": [1, 2], "t": "café"})
        assert wire == '{"a":[1,2],"t":"café"}'

    def test_started_follows_the_tick_count(self):
        assert _state("starting")["started"] is False
        assert _state("nothing_playing")["started"] is True

    def test_focus_block(self):
        state = _state("replay_hold")
        assert state["focus"] == {
            "appliance_id": hs.LOUNGE, "manual": True, "pending": False, "idle": True}

    def test_now_playing_names_the_reporting_appliance(self):
        state = _state("playing_artwork")
        assert state["now_playing"] == {
            "appliance_id": hs.LOUNGE, "title": "Tunnel of Love", "artist": "Dire Straits",
            "album": "Making Movies", "playing": True}
        assert _state("nothing_playing")["now_playing"] is None

    def test_volume_carries_the_readout_and_the_mute_flag_handed_in(self):
        assert _state("playing_artwork", muted=True)["volume"] == {
            "appliance_id": hs.LOUNGE, "level": 42, "muted": True}
        assert _state("nothing_playing")["volume"]["level"] is None
        assert _state("nothing_playing")["volume"]["muted"] is None

    def test_only_listed_appliances_appear(self):
        scenario = hs.SCENARIOS["nothing_playing"]
        unknown = hs.appliance(hs.KITCHEN, "Kitchen", auth="unknown")
        nameless = hs.appliance("", "Ghost")
        snapshot = dataclasses.replace(
            scenario.snapshot, appliances=scenario.snapshot.appliances + (unknown, nameless))
        ids = [a["id"] for a in dataclasses.replace(scenario, snapshot=snapshot).state()["appliances"]]
        assert ids == [hs.LOUNGE]

    def test_capability_versions_and_webui_text(self):
        a = _state("playing_artwork")["appliances"][0]
        assert a["capabilities"] == {
            "outputs": 1, "eq": 2, "repeat": True, "warnings": True, "proto": 3}
        assert a["webui"] == "http://192.0.2.20:80/"
        assert a["volume"] == 42 and a["muted"] is False

    def test_the_panel_falls_back_to_the_settings(self):
        state = _state("nothing_playing", panel={"asleep": True, "backlight": "none"},
                       settings={"brightness": 55, "sleep_after_s": 900, "always_show_controls": True})
        assert state["panel"] == {
            "asleep": True, "brightness": 55, "sleep_after_s": 900, "backlight": "none",
            "always_show_controls": True, "kiosk": False}
        assert build_state(hs.SCENARIOS["nothing_playing"].snapshot)["panel"]["brightness"] == 80

    def test_the_kiosk_flag_is_false_unless_the_panel_says_so(self):
        assert _state("playing_artwork")["panel"]["kiosk"] is False
        assert _state("playing_artwork", panel={"kiosk": True})["panel"]["kiosk"] is True

    def test_recovery_takes_a_tuple_or_a_mapping(self):
        assert _state("recovery_pending")["recovery"] == {"active": True, "confirmed": False}
        assert _state("nothing_playing", recovery={"active": True, "confirmed": True})["recovery"] == {
            "active": True, "confirmed": True}

    def test_network_sd_health_and_update_blocks(self):
        state = _state("warning_update")
        assert state["update"]["phase"] == "python" and state["update"]["percent"] == 40
        assert _state("nothing_playing")["update"] is None
        assert _state("nothing_playing")["network"] == {
            "link": "connected", "ssid": "HomeNet", "signal": "Strong", "bars": 3}
        assert _state("nothing_playing")["sd_health"] == {"status": "valid", "percent": 84}
        assert _state("starting")["network"] is None


class TestRepeat:
    def test_a_replay_position_runs_on_between_readings(self):
        repeat = _state("replaying")["appliances"][0]["repeat"]
        assert repeat["position_s"] == 119.0 and repeat["duration_s"] == 1100.0
        assert repeat["armed"] is True

    def test_the_position_stops_at_the_duration(self):
        scenario = hs.SCENARIOS["replaying"]
        assert dataclasses.replace(scenario, now=hs.NOW + 5000).state()[
            "appliances"][0]["repeat"]["position_s"] == 1098.0

    def test_a_fading_replay_is_not_extrapolated(self):
        assert _state("fading_out")["appliances"][0]["repeat"]["position_s"] == 1097.0

    @staticmethod
    def _with_latency(name, latency, **scenario_kw):
        scenario = hs.SCENARIOS[name]
        appliance = scenario.snapshot.appliances[0]
        repeat = dataclasses.replace(appliance.repeat, latency_seconds=latency)
        snapshot = dataclasses.replace(
            scenario.snapshot, appliances=(dataclasses.replace(appliance, repeat=repeat),)
            + scenario.snapshot.appliances[1:])
        return dataclasses.replace(scenario, snapshot=snapshot, **scenario_kw).state()[
            "appliances"][0]["repeat"]

    def test_the_block_carries_the_latency(self):
        assert _state("replaying")["appliances"][0]["repeat"]["latency_s"] == 2.0
        assert self._with_latency("replaying", 0.3)["latency_s"] == 0.3

    def test_the_position_is_the_heard_position(self):
        # Reported 120.0 s at the reading, one second old: 121.0 on, less latency.
        assert self._with_latency("replaying", 0.3)["position_s"] == 120.7
        assert self._with_latency("replaying", 3.5)["position_s"] == 117.5

    def test_the_heard_position_is_never_negative(self):
        scenario = hs.SCENARIOS["replaying"]
        appliance = scenario.snapshot.appliances[0]
        record = dataclasses.replace(
            appliance.repeat, position_seconds=0.0, observed_at=hs.NOW, latency_seconds=3.5)
        snapshot = dataclasses.replace(
            scenario.snapshot, appliances=(dataclasses.replace(appliance, repeat=record),)
            + scenario.snapshot.appliances[1:])
        out = dataclasses.replace(scenario, snapshot=snapshot).state()
        assert out["appliances"][0]["repeat"]["position_s"] == 0.0

    def test_replaying_covers_replay_and_fade(self):
        assert _state("replaying")["appliances"][0]["replaying"] is True
        assert _state("fading_out")["appliances"][0]["replaying"] is True
        assert _state("replay_hold")["appliances"][0]["replaying"] is False
        assert _state("nothing_playing")["appliances"][0]["repeat"] is None

    def test_replay_elsewhere_marks_the_other_appliance(self):
        by_id = {a["id"]: a for a in _state("replay_elsewhere")["appliances"]}
        assert by_id[hs.LOUNGE]["replaying"] is True and by_id[hs.KITCHEN]["replaying"] is False
        assert _state("replay_elsewhere")["focus"]["appliance_id"] == hs.KITCHEN


class TestReachable:
    def test_a_failed_fetch_is_unreachable(self):
        assert _state("unreachable")["appliances"][0]["reachable"] is False

    def test_an_appliance_not_asked_is_reachable(self):
        assert _state("nothing_playing")["appliances"][0]["reachable"] is True

    def test_a_refusal_is_not_unreachable(self):
        scenario = hs.SCENARIOS["nothing_playing"]
        refused = dataclasses.replace(scenario.snapshot.appliances[0], status_error="unauthorized")
        state = dataclasses.replace(
            scenario, snapshot=dataclasses.replace(scenario.snapshot, appliances=(refused,))).state()
        assert state["appliances"][0]["reachable"] is True

    def test_an_unauthorized_appliance_is_listed_as_such(self):
        by_id = {a["id"]: a for a in _state("unauthorized")["appliances"]}
        assert by_id[hs.KITCHEN]["auth"] == "unauthorized"


class TestOutputs:
    def test_rows_are_renamed_and_in_use_shows_the_owner(self):
        rows = _state("in_use_speaker")["outputs"]["rows"]
        assert rows[2] == {
            "id": "o3", "name": "Bedroom", "selected": False, "volume": 20,
            "in_use": True, "owner": "Kitchen", "default": False}
        assert _state("playing_artwork")["outputs"]["rows"][2]["owner"] == ""

    def test_the_default_output_is_flagged(self):
        rows = _state("playing_artwork")["outputs"]["rows"]
        assert [r["default"] for r in rows] == [True, False, False]

    def test_the_optimistic_tap_overrides_the_row(self):
        scenario = hs.SCENARIOS["playing_artwork"]
        held = scenario.snapshot.outputs
        snapshot = dataclasses.replace(scenario.snapshot, outputs=dataclasses.replace(
            held, optimistic=("o2", True, 60, hs.NOW)))
        rows = dataclasses.replace(scenario, snapshot=snapshot).state()["outputs"]["rows"]
        assert rows[1]["selected"] is True and rows[1]["volume"] == 60
        assert rows[0]["selected"] is True and rows[0]["volume"] == 45

    def test_an_optimistic_selection_keeps_the_row_volume(self):
        scenario = hs.SCENARIOS["playing_artwork"]
        held = dataclasses.replace(scenario.snapshot.outputs, optimistic=("o1", False, None, hs.NOW))
        rows = dataclasses.replace(
            scenario, snapshot=dataclasses.replace(scenario.snapshot, outputs=held)
        ).state()["outputs"]["rows"]
        assert rows[0]["selected"] is False and rows[0]["volume"] == 45

    def test_nothing_held_is_null(self):
        assert _state("nothing_playing")["outputs"] is None
        assert _state("nothing_playing")["outputs_available"] is False
        assert _state("playing_artwork")["outputs_available"] is True


class TestEq:
    def test_a_six_band_state_leaves_out_the_derived_bands(self):
        eq = _state("eq_six")["eq"]
        assert eq["version"] == 2
        assert [b["id"] for b in eq["bands"]] == [f"peq{n}" for n in range(1, 7)]
        assert eq["bands"][0] == {
            "id": "peq1", "frequency_hz": 40, "gain_db": 2, "min_db": -12, "max_db": 12}

    def test_a_capability_one_state_has_the_two_derived_bands(self):
        eq = _state("eq_two")["eq"]
        assert eq["version"] == 1
        assert [b["id"] for b in eq["bands"]] == ["bass", "treble"]
        assert eq["bands"][0]["frequency_hz"] is None

    def test_a_tap_inside_its_window_shows_ahead_of_the_reading(self):
        bands = {b["id"]: b["gain_db"] for b in _state("eq_two")["eq"]["bands"]}
        assert bands == {"bass": 4, "treble": 1}

    def test_a_tap_past_its_window_is_dropped(self):
        scenario = hs.SCENARIOS["eq_two"]
        bands = {b["id"]: b["gain_db"] for b in dataclasses.replace(
            scenario, now=hs.NOW + 10).state()["eq"]["bands"]}
        assert bands == {"bass": 2, "treble": 1}

    def test_a_six_band_tap_applies_to_its_band(self):
        scenario = hs.SCENARIOS["eq_six"]
        held = dataclasses.replace(scenario.snapshot.eq, optimistic=(("peq3", 5),),
                                   optimistic_expires_at=hs.NOW + 1)
        bands = {b["id"]: b["gain_db"] for b in dataclasses.replace(
            scenario, snapshot=dataclasses.replace(scenario.snapshot, eq=held)).state()["eq"]["bands"]}
        assert bands["peq3"] == 5 and bands["peq1"] == 2

    def test_no_eq_is_null(self):
        state = _state("eq_none")
        assert state["eq"] is None and state["eq_available"] is False
        assert state["appliances"][0]["capabilities"]["eq"] == 0


class TestArtwork:
    def test_artwork_is_a_key_and_a_local_url(self):
        art = _state("playing_artwork")["artwork"]
        assert art["url"] == "/api/v1/artwork/" + art["key"]
        assert art["backdrop_url"] == art["url"] + "/backdrop"
        assert len(art["key"]) == 16
        assert _state("playing_no_artwork")["artwork"] is None


class TestWarnings:
    def test_a_dial_warning_is_one_card(self):
        warnings = _state("warning_sdhealth")["warnings"]
        assert warnings["due"] == "sdhealth"
        assert warnings["cards"] == [{
            "id": "sdhealth", "severity": "warning", "title": "microSD Health",
            "message": "6%: Replace Soon", "progress": None, "source": "",
            "buttons": [{"label": "Dismiss", "action": "dismiss"}],
            "interrupting": False, "snoozed": False}]

    def test_the_update_card_has_progress_and_no_buttons(self):
        card = _state("warning_update")["warnings"]["cards"][0]
        assert card["title"] == "Updating..." and card["progress"] == 40
        assert card["buttons"] == [] and card["interrupting"] is True

    def test_the_update_result_names_the_version(self):
        card = _state("warning_update_result")["warnings"]["cards"][0]
        assert card["title"] == "Updated" and card["message"] == "Version 0.8.0"

    def test_no_wifi_offers_dismiss_and_restart(self):
        card = _state("warning_nowifi")["warnings"]["cards"][0]
        assert [b["action"] for b in card["buttons"]] == ["dismiss", "restart"]

    def test_an_appliance_warning_is_a_card_and_a_badge(self):
        state = _state("appliance_warning")
        key = f"appliance:{hs.LOUNGE}:stylus_in1"
        card = state["warnings"]["cards"][0]
        assert card["id"] == key and card["source"] == "Lounge" and card["severity"] == "warning"
        assert card["title"] == "Technics stylus" and card["message"] == "Needs changing soon."
        assert state["appliances"][0]["warnings"] == [{
            "key": key, "id": "stylus_in1", "severity": "warning", "title": "Technics stylus",
            "message": "Needs changing soon.", "dismissal": "week", "snoozed": False}]

    def test_a_notice_reads_ok(self):
        card = _state("appliance_warning_notice")["warnings"]["cards"][0]
        assert card["buttons"] == [{"label": "OK", "action": "dismiss"}]
        assert card["severity"] == "info"

    def test_a_snooze_runs_to_a_wall_clock_time(self):
        scenario = hs.SCENARIOS["appliance_warning"]
        key = f"appliance:{hs.LOUNGE}:stylus_in1"
        snoozed = hs._appliance_warning_scenario("x", hs._stylus_warning(), snoozed=True)
        state = snoozed.state()
        assert state["warnings"]["cards"][0]["snoozed"] is True
        assert state["appliances"][0]["warnings"][0]["snoozed"] is True
        later = dataclasses.replace(snoozed, wall_now=hs.WALL_NOW + 7200).state()
        assert later["warnings"]["cards"][0]["snoozed"] is False
        assert scenario.state()["warnings"]["cards"][0]["snoozed"] is False
        assert key in {w["key"] for w in state["appliances"][0]["warnings"]}

    def test_an_inactive_or_unknown_warning_makes_no_card(self):
        scenario = hs.SCENARIOS["warning_sdhealth"]
        state = dataclasses.replace(scenario, descriptors=()).state()
        assert state["warnings"]["cards"] == []
        assert _state("nothing_playing")["warnings"] == {"due": None, "cards": []}

    def test_a_card_text_function_that_raises_gives_the_plain_title(self):
        scenario = hs.SCENARIOS["warning_sdhealth"]
        boom = dataclasses.replace(
            scenario.descriptors[1], title_for=lambda _s: 1 / 0, message_for=lambda _s: 1 / 0)
        state = dataclasses.replace(scenario, descriptors=(boom,)).state()
        card = state["warnings"]["cards"][0]
        assert card["title"] == "microSD Health" and card["message"] == ""

    def test_descriptors_may_be_a_mapping(self):
        scenario = hs.SCENARIOS["warning_sdhealth"]
        mapping = {d.id: d for d in scenario.descriptors}
        assert dataclasses.replace(scenario, descriptors=mapping).state() == scenario.state()


class TestNothingLeaks:
    @pytest.mark.parametrize("name", hs.SCENARIO_NAMES)
    def test_no_appliance_url_service_name_or_address(self, name):
        state = hs.SCENARIOS[name].state()
        text = dumps(_drop_key(state, "webui"))
        for secret in (
            hs.ARTWORK_URL, "provider.example", hs.SERVICE_NAME, "_autostream._tcp", "192.0.2.20",
        ):
            assert secret not in text

    def test_the_appliance_address_appears_only_in_webui(self):
        state = _state("playing_artwork")
        assert "192.0.2.20" in dumps(state)
        assert "192.0.2.20" not in dumps(_drop_key(state, "webui"))

    @pytest.mark.parametrize("name", hs.SCENARIO_NAMES)
    def test_every_string_is_short(self, name):
        for text in _strings(hs.SCENARIOS[name].state()):
            assert len(text) <= STRING_MAX

    def test_a_long_string_is_cut(self):
        scenario = hs.SCENARIOS["playing_artwork"]
        long = "x" * 5000
        snapshot = dataclasses.replace(scenario.snapshot, now_playing=dataclasses.replace(
            scenario.snapshot.now_playing, title=long, artist=long))
        state = dataclasses.replace(scenario, snapshot=snapshot).state()
        assert state["now_playing"]["title"] == "x" * STRING_MAX
        assert all(len(t) <= STRING_MAX for t in _strings(state))

    def test_hostile_warning_text_round_trips_unchanged_after_cleaning(self):
        hostile = "<img src=x onerror=alert(1)>"
        body = {"appliance_id": hs.LOUNGE, "warnings": [{
            "id": "evil", "severity": "critical", "title": hostile,
            "message": "a‮b\x00c  d</script>", "dismissal": "day"}]}
        cleaned = validate_appliance_warnings(body, hs.LOUNGE)
        assert cleaned[0].title == hostile
        scenario = hs.SCENARIOS["appliance_warning"]
        appliance = dataclasses.replace(scenario.snapshot.appliances[0], warnings=cleaned)
        state = dataclasses.replace(
            scenario, snapshot=dataclasses.replace(scenario.snapshot, appliances=(appliance,))).state()
        badge = state["appliances"][0]["warnings"][0]
        assert badge["title"] == hostile
        assert badge["message"] == cleaned[0].message == "abc d</script>"
        assert badge["severity"] == "critical"


class TestPure:
    def test_building_does_not_change_the_snapshot(self):
        scenario = hs.SCENARIOS["playing_artwork"]
        before = dataclasses.asdict(scenario.snapshot)
        scenario.state()
        assert dataclasses.asdict(scenario.snapshot) == before

    def test_the_body_shares_nothing_with_the_snapshot(self):
        scenario = hs.SCENARIOS["playing_artwork"]
        state = scenario.state()
        state["appliances"].clear()
        state["dial"]["inputs"].append("x")
        assert scenario.state()["appliances"] and scenario.state()["dial"]["inputs"] == ["touch:hd"]


class TestFakeCore:
    def _core(self):
        return FakeCore(hs.SCENARIOS["playing_artwork"].snapshot)

    def test_publish_advances_the_sequence_and_wakes_waiters(self):
        core = self._core()
        seen = core.snapshot().seq
        got = []
        thread = threading.Thread(target=lambda: got.append(core.wait_for_change(seen, 5)))
        thread.start()
        time.sleep(0.05)
        core.publish(polling=False)
        thread.join(2)
        assert got and got[0].seq == seen + 1 and got[0].polling is False
        assert core.wait_for_change(seen + 1, 0.01) is None

    def test_subscribers_are_called_until_they_unsubscribe(self):
        core = self._core()
        hits = []
        handle = core.subscribe(lambda: hits.append(1))
        core.publish()
        core.unsubscribe(handle)
        core.publish()
        assert hits == [1]

    def test_actions_are_recorded_and_answered(self):
        core = self._core()
        assert core.volume_set(50, hs.LOUNGE) == ActionResult(True)
        core.set_result("set_focus", ActionResult(False, "unknown_appliance"))
        assert core.set_focus("zzz") == ActionResult(False, "unknown_appliance")
        core.set_output(hs.LOUNGE, "o1", selected=True, volume=40)
        assert core.calls_to("volume_set") == [((50, hs.LOUNGE), {})]
        assert core.calls_to("set_output") == [((hs.LOUNGE, "o1"), {"selected": True, "volume": 40})]
        assert [m for m, _a, _k in core.calls] == ["volume_set", "set_focus", "set_output"]

    def test_reboot_and_watches(self):
        core = self._core()
        assert core.request_dial_reboot() is True
        core.watch_outputs(hs.LOUNGE, "hd", True)
        core.watch_eq(hs.LOUNGE, "hd", False)
        assert core.watches == [("outputs", hs.LOUNGE, "hd", True), ("eq", hs.LOUNGE, "hd", False)]
        assert core.warnings.descriptor("sdhealth") is not None
