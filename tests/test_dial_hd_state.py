"""Tests for the HD dial's state body (dial_hd_state.build_parts), the
scenario corpus it is built from and the FakeCore the later layers drive.

Each scenario has a golden JSON file in tests/golden/hd_state/: the `dial`
part the page is sent for it. To regenerate them after a deliberate change,
run with HD_GOLDEN_UPDATE=1 and review the difference.
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
from dial_appliance_warnings import APPLIANCE_WARNINGS_MAX, appliance_warning_entries
from dial_core_state import PIN_WINDOW_S, ActionResult, TransportRequest
from dial_hd_state import STRING_MAX, build_parts

GOLDEN_DIR = Path(__file__).parent / "golden" / "hd_state"
UPDATE = bool(os.environ.get("HD_GOLDEN_UPDATE"))


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


def dumps(state):
    return json.dumps(state, separators=(",", ":"), ensure_ascii=False)


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
            "playing_untitled", "playing_untitled_input", "replay_hold", "replaying", "fading_out", "replay_elsewhere", "in_use_speaker",
            "unreachable", "unauthorized", "recovery_pending", "eq_none", "eq_six",
            "warning_sdhealth", "warning_update", "warning_update_result", "warning_nowifi",
            "appliance_warning", "appliance_warning_info", "disconnected",
            "pin_required", "pin_invalid", "pin_busy", "pin_rate_limited",
            "pin_expired", "power_requested", "power_failed",
            "start_failure_refused", "start_failure_elsewhere", "start_failure_late_pin",
            "appliance_needs_update",
        }

    def test_a_build_is_repeatable(self):
        for scenario in hs.SCENARIOS.values():
            assert scenario.state() == scenario.state()


class TestGolden:
    @pytest.mark.parametrize("name", hs.SCENARIO_NAMES)
    def test_matches_the_committed_json(self, name):
        state = hs.SCENARIOS[name].parts()["dial"]
        path = GOLDEN_DIR / f"{name}.json"
        if UPDATE:
            GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(state, indent=2, ensure_ascii=False, sort_keys=False) + "\n",
                encoding="utf-8",
            )
            pytest.skip("golden regenerated")
        assert path.exists(), f"{path} is missing; run with HD_GOLDEN_UPDATE=1 to create it"
        assert state == json.loads(path.read_text(encoding="utf-8"))

    def test_every_golden_file_has_a_scenario(self):
        files = {p.stem for p in GOLDEN_DIR.glob("*.json")}
        assert files <= set(hs.SCENARIO_NAMES)


class TestShape:
    def test_every_part_is_json(self):
        for scenario in hs.SCENARIOS.values():
            state = scenario.state()
            assert json.loads(dumps(state)) == state

    def test_it_carries_neither_an_envelope_nor_the_appliances_own_readings(self):
        for scenario in hs.SCENARIOS.values():
            assert not {"seq", "now", "core_seq", "now_playing", "volume", "outputs", "eq"} & set(scenario.state())

    def test_started_follows_the_tick_count(self):
        assert _state("starting")["started"] is False
        assert _state("nothing_playing")["started"] is True

    def test_focus_block(self):
        state = _state("replay_hold")
        assert state["focus"] == {
            "appliance_id": hs.LOUNGE, "manual": True, "pending": False, "idle": True,
            "reporting_id": hs.LOUNGE}

    def test_only_listed_appliances_appear(self):
        scenario = hs.SCENARIOS["nothing_playing"]
        unknown = hs.appliance(hs.KITCHEN, "Kitchen", auth="unknown")
        nameless = hs.appliance("", "Ghost")
        snapshot = dataclasses.replace(
            scenario.snapshot, appliances=scenario.snapshot.appliances + (unknown, nameless))
        ids = [a["id"] for a in dataclasses.replace(scenario, snapshot=snapshot).state()["appliances"]]
        assert ids == [hs.LOUNGE]

    def test_the_state_list_and_the_screen_selector_show_the_same_order(self):
        from dial_pool_support import Rig, peer

        rig = Rig(start_lane=False)
        rig.add("Alpha", peer("Alpha", playing=True, access="none", access_reason="dial_not_authorized"))
        rig.add("Mid", peer("Mid", access=None))
        rig.add("Zulu", peer("Zulu"))
        rig.add("Beta", peer("Beta", playing=True))
        snapshot = rig.fold()
        scenario = hs.SCENARIOS["nothing_playing"]
        state = dataclasses.replace(scenario, snapshot=dataclasses.replace(
            scenario.snapshot, appliances=snapshot.appliances)).state()
        # The state and the screen leave the appliance not yet known off
        # their lists; the rest sit in one order.
        assert [a["name"] for a in state["appliances"]] == ["Beta", "Zulu", "Alpha"]
        assert [r.label for r in snapshot.selector_rows()] == ["Beta", "Zulu", "Alpha"]

    def test_the_webui_text_and_update_flag(self):
        a = _state("playing_artwork")["appliances"][0]
        assert a["webui"] == "http://192.0.2.20:80/" and a["update_needed"] is False
        assert "volume" not in a and "muted" not in a and "capabilities" not in a

    def test_the_panel_falls_back_to_the_settings(self):
        state = _state("nothing_playing", panel={"asleep": True, "backlight": "none"},
                       settings={"brightness": 55, "sleep_after_s": 900})
        assert state["panel"] == {
            "asleep": True, "brightness": 55, "brightness_max": 100, "sleep_after_s": 900,
            "sleep_choices": [0, 60, 300, 900], "backlight": "none", "kiosk": False}
        assert build_parts(hs.SCENARIOS["nothing_playing"].snapshot)["dial"]["panel"]["brightness"] == 80

    @pytest.mark.parametrize("kind", ["none", "sysfs", "ddc"])
    def test_the_backlight_kind_is_reported_as_given(self, kind):
        assert _state("nothing_playing", panel={"backlight": kind})["panel"]["backlight"] == kind

    def test_the_kiosk_flag_is_false_unless_the_panel_says_so(self):
        assert _state("playing_artwork")["panel"]["kiosk"] is False
        assert _state("playing_artwork", panel={"kiosk": True})["panel"]["kiosk"] is True

    def test_the_power_block_carries_the_state_and_its_moment(self):
        assert _state("nothing_playing")["power"] == {"state": "idle", "changed_at": 0.0}
        assert _state("power_requested")["power"] == {"state": "requested", "changed_at": hs.NOW - 1}
        assert _state("power_failed")["power"] == {"state": "failed", "changed_at": hs.NOW - 1}

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
    def test_a_replay_position_is_the_reported_one_less_the_latency(self):
        repeat = _state("replaying")["appliances"][0]["repeat"]
        assert repeat["position_s"] == 118.0 and repeat["duration_s"] == 1100.0
        assert repeat["armed"] is True

    def test_the_position_does_not_run_on_with_the_clock(self):
        scenario = hs.SCENARIOS["replaying"]
        assert dataclasses.replace(scenario, now=hs.NOW + 5000).state()["appliances"][0]["repeat"] == (
            scenario.state()["appliances"][0]["repeat"])

    def test_a_fading_replay_reads_as_reported(self):
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

    def test_the_block_says_when_the_appliance_last_reported(self):
        assert _state("replaying")["appliances"][0]["repeat"]["observed_at"] == hs.NOW - 1.0

    def test_the_block_carries_the_latency(self):
        assert _state("replaying")["appliances"][0]["repeat"]["latency_s"] == 2.0
        assert self._with_latency("replaying", 0.3)["latency_s"] == 0.3

    def test_the_position_is_the_heard_position(self):
        # Reported 120.0 s at the reading, less latency.
        assert self._with_latency("replaying", 0.3)["position_s"] == 119.7
        assert self._with_latency("replaying", 3.5)["position_s"] == 116.5

    def test_a_replaying_position_may_be_below_zero_and_another_state_is_held_at_zero(self):
        scenario = hs.SCENARIOS["replaying"]
        appliance = scenario.snapshot.appliances[0]

        def position(state):
            record = dataclasses.replace(
                appliance.repeat, state=state, position_seconds=0.0, observed_at=hs.NOW, latency_seconds=3.5)
            snapshot = dataclasses.replace(
                scenario.snapshot, appliances=(dataclasses.replace(appliance, repeat=record),)
                + scenario.snapshot.appliances[1:])
            return dataclasses.replace(scenario, snapshot=snapshot).state()["appliances"][0]["repeat"]["position_s"]
        assert position("replaying") == -3.5
        assert position("fading_out") == 0.0

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


class TestOutputsRequest:
    def test_the_block_names_the_output_the_wait_and_whether_a_pin_may_be_entered(self):
        def block(name):
            return _state(name)["outputs_request"]
        assert block("pin_required") == {
            "appliance_id": hs.LOUNGE, "kind": "output_set", "state": "rejected",
            "error": "pin_required", "output_id": "o2", "retry_after_s": 0,
            "requested_at": hs.NOW - 1, "changed_at": hs.NOW - 1, "awaiting_pin": True,
            "retry_until": hs.NOW - 1, "awaiting_until": hs.NOW - 1 + PIN_WINDOW_S}
        assert (block("pin_rate_limited")["awaiting_pin"], block("pin_rate_limited")["retry_after_s"]) == (True, 7)
        assert block("pin_expired")["awaiting_pin"] is False
        assert block("pin_busy")["awaiting_pin"] is True and block("pin_busy")["state"] == "pending"
        assert block("pin_invalid")["awaiting_pin"] is True

    def test_the_deadlines_are_absolute_on_the_bodys_clock(self):
        block = _state("pin_rate_limited")["outputs_request"]
        assert block["retry_until"] == hs.NOW - 1 + 7
        assert block["awaiting_until"] == hs.NOW - 1 + PIN_WINDOW_S
        pending = _state("pin_busy")["outputs_request"]
        assert pending["retry_until"] == pending["changed_at"]
        assert pending["awaiting_until"] == pending["changed_at"] + PIN_WINDOW_S
        # A lapsed outcome keeps its deadline, in the past.
        expired = _state("pin_expired")
        assert expired["outputs_request"]["awaiting_pin"] is False
        assert expired["outputs_request"]["awaiting_until"] <= hs.NOW

    def test_the_transport_block_has_no_pin_window(self):
        transport = _state("replaying")["transport"]
        assert transport["awaiting_until"] is None
        assert transport["retry_until"] == transport["changed_at"]

    def test_the_transport_block_gained_the_same_keys(self):
        transport = _state("replaying")["transport"]
        assert transport["kind"] == "seek" and transport["awaiting_pin"] is False
        assert set(transport) == set(_state("pin_required")["outputs_request"])
        assert transport["output_id"] is None and transport["retry_after_s"] == 0

    def test_the_request_says_when_it_reached_its_state(self):
        transport = _state("replaying")["transport"]
        assert transport["changed_at"] == hs.NOW - 1 and transport["requested_at"] == hs.NOW - 2
        # Both are on the clock the repeat block's observed_at uses.
        assert _state("replaying")["appliances"][0]["repeat"]["observed_at"] >= transport["changed_at"]

    def test_no_request_is_null(self):
        state = _state("playing_artwork")
        assert state["outputs_request"] is None and state["transport"] is None

    def test_the_body_never_carries_a_pin_field(self):
        text = json.dumps(_state("pin_busy"))
        assert '"pin"' not in text and "pin_value" not in text


class TestStartFailure:
    def test_the_block_names_the_notice(self):
        block = _state("start_failure_refused")["start_failure"]
        assert block == {
            "appliance_id": hs.LOUNGE, "key": hs.LOUNGE + ":boot-a:3", "unit_id": "o2",
            "name": "Patio", "reason": "refused", "raised_at": hs.NOW - 1}

    def test_the_block_is_none_without_a_notice(self):
        assert _state("playing_artwork")["start_failure"] is None
        assert _state("start_failure_late_pin")["start_failure"] is None

    def test_a_long_name_is_capped(self):
        scenario = hs.SCENARIOS["start_failure_refused"]
        notice = dataclasses.replace(scenario.snapshot.start_failure, name="y" * 5000)
        state = dataclasses.replace(
            scenario, snapshot=dataclasses.replace(scenario.snapshot, start_failure=notice)).state()
        assert state["start_failure"]["name"] == "y" * STRING_MAX

    def test_a_reopened_request_is_a_pin_request_with_its_window_from_the_reopening(self):
        block = _state("start_failure_late_pin")["outputs_request"]
        assert block["awaiting_pin"] is True and block["requested_at"] < block["changed_at"]
        assert block["awaiting_until"] == block["changed_at"] + PIN_WINDOW_S


class TestArtwork:
    def test_artwork_is_a_key_and_a_local_url(self):
        art = _state("playing_artwork")["artwork"]
        assert art["url"] == "/api/v1/artwork/" + art["key"]
        assert art["backdrop_url"] == art["url"] + "/backdrop"
        assert len(art["key"]) == 16
        assert _state("playing_no_artwork")["artwork"] is None


class TestWarnings:
    def test_a_dial_warning_is_one_bell_entry(self):
        bell = _state("warning_sdhealth")["bell"]
        assert bell == {"severity": "warning", "entries": [{
            "key": "sdhealth", "source": "This dial", "severity": "warning",
            "title": "microSD Health", "message": "6%: Replace Soon", "actions": []}]}
        assert _state("warning_sdhealth")["status"] is None

    def test_the_sd_card_is_critical_below_three_percent(self):
        scenario = hs.SCENARIOS["warning_sdhealth"]
        snapshot = dataclasses.replace(scenario.snapshot, warnings=hs.warning_states({"sdhealth": 2}))
        bell = dataclasses.replace(scenario, snapshot=snapshot).state()["bell"]
        assert bell["severity"] == "critical" and bell["entries"][0]["severity"] == "critical"

    def test_the_update_status_has_progress_and_no_buttons(self):
        state = _state("warning_update")
        status = state["status"]
        assert status["id"] == "update" and status["title"] == "Updating..." and status["progress"] == 40
        assert status["buttons"] == [] and status["severity"] == "info"
        assert state["bell"] == {"severity": None, "entries": []}

    def test_the_update_result_names_the_version_and_closes_through_the_core(self):
        status = _state("warning_update_result")["status"]
        assert status["title"] == "Updated" and status["message"] == "Version 0.8.0"
        assert status["buttons"] == [{"label": "Close", "action": "status_close"}]

    def test_no_wifi_is_a_bell_entry_with_restart(self):
        state = _state("warning_nowifi")
        assert state["bell"]["entries"][0]["actions"] == ["restart"]
        assert state["status"] is None

    def test_an_appliance_warning_is_on_its_row_and_not_in_the_dial_bell(self):
        state = _state("appliance_warning")
        key = f"appliance:{hs.LOUNGE}:stylus_in1"
        assert state["appliances"][0]["warnings"] == [{
            "key": key, "source": "Lounge", "severity": "warning", "title": "Technics stylus",
            "message": "Needs changing soon.", "actions": []}]
        assert state["bell"] == {"severity": None, "entries": []}

    def test_an_info_warning_is_an_info_entry(self):
        entry = _state("appliance_warning_info")["appliances"][0]["warnings"][0]
        assert entry["severity"] == "info"

    def test_an_appliance_on_an_older_protocol_lists_the_update_warning_on_its_row(self):
        state = _state("appliance_needs_update")
        block = state["appliances"][0]
        assert block["update_needed"] is True
        assert block["warnings"] == [{
            "key": f"appliance:{hs.LOUNGE}:update_appliance", "source": "Lounge", "severity": "warning",
            "title": "Update Lounge",
            "message": "Its software is older than this dial's. Update it from its web UI.", "actions": []}]

    def test_the_bell_lists_the_worst_severity_first(self):
        scenario = hs.SCENARIOS["nothing_playing"]
        snapshot = dataclasses.replace(
            scenario.snapshot, warnings=hs.warning_states({"sdhealth": 2, "nowifi": None}))
        bell = dataclasses.replace(scenario, snapshot=snapshot).state()["bell"]
        assert [e["key"] for e in bell["entries"]] == ["sdhealth", "nowifi"]
        assert bell["severity"] == "critical"

    def test_the_dial_update_warning_is_a_dial_entry_naming_the_appliances(self):
        scenario = hs.SCENARIOS["nothing_playing"]
        snapshot = dataclasses.replace(
            scenario.snapshot, warnings=hs.warning_states({"update_dial": ("Lounge", "Kitchen")}))
        (entry,) = dataclasses.replace(scenario, snapshot=snapshot).state()["bell"]["entries"]
        assert (entry["key"], entry["source"]) == ("update_dial", "This dial")
        assert entry["title"] == "Update this dial" and entry["message"] == "Lounge, Kitchen need a newer dial"

    def test_an_inactive_or_unknown_warning_makes_no_entry(self):
        scenario = hs.SCENARIOS["warning_sdhealth"]
        state = dataclasses.replace(scenario, descriptors=()).state()
        assert state["bell"] == {"severity": None, "entries": []}
        assert _state("nothing_playing")["bell"] == {"severity": None, "entries": []}
        assert _state("nothing_playing")["status"] is None

    def test_a_status_text_function_that_raises_gives_the_plain_title(self):
        scenario = hs.SCENARIOS["warning_update"]
        (update,) = [d for d in scenario.descriptors if d.id == "update"]
        boom = dataclasses.replace(
            update, title_for=lambda _s: 1 / 0, message_for=lambda _s: 1 / 0, progress_for=lambda _s: 1 / 0)
        status = dataclasses.replace(scenario, descriptors=(boom,)).state()["status"]
        assert status["title"] == "Updating..." and status["message"] == "" and status["progress"] is None

    def test_descriptors_may_be_a_mapping(self):
        scenario = hs.SCENARIOS["warning_sdhealth"]
        mapping = {d.id: d for d in scenario.descriptors}
        assert dataclasses.replace(scenario, descriptors=mapping).state() == scenario.state()


class TestNothingLeaks:
    def test_no_appliance_url_service_name_or_address(self):
        leaks = []
        for name in hs.SCENARIO_NAMES:
            state = hs.SCENARIOS[name].state()
            text = dumps(_drop_key(state, "webui"))
            for secret in (
                hs.ARTWORK_URL, "provider.example", hs.SERVICE_NAME, "_autostream._tcp", "192.0.2.20",
            ):
                if secret in text:
                    leaks.append((name, secret))
        assert not leaks, f"(scenario, text that leaked): {leaks}"

    def test_the_appliance_address_appears_only_in_webui(self):
        state = _state("playing_artwork")
        assert "192.0.2.20" in dumps(state)
        assert "192.0.2.20" not in dumps(_drop_key(state, "webui"))

    def test_every_string_is_short(self):
        long = [
            (name, text[:40]) for name in hs.SCENARIO_NAMES
            for text in _strings(hs.SCENARIOS[name].state()) if len(text) > STRING_MAX
        ]
        assert not long, f"(scenario, start of a string over {STRING_MAX}): {long}"

    def test_a_long_string_is_cut(self):
        scenario = hs.SCENARIOS["appliance_warning"]
        long = "x" * 5000
        appliance = scenario.snapshot.appliances[0]
        warning = dataclasses.replace(appliance.warnings[0], title=long, message=long)
        snapshot = dataclasses.replace(
            scenario.snapshot, appliances=(dataclasses.replace(appliance, warnings=(warning,)),))
        state = dataclasses.replace(scenario, snapshot=snapshot).state()
        assert state["appliances"][0]["warnings"][0]["title"] == "x" * STRING_MAX
        assert all(len(t) <= STRING_MAX for t in _strings(state))

    def test_hostile_warning_text_round_trips_unchanged_after_cleaning(self):
        hostile = "<img src=x onerror=alert(1)>"
        body = {"appliance_id": hs.LOUNGE, "warnings": [{
            "id": "evil", "severity": "critical", "title": hostile,
            "message": "a‮b\x00c  d</script>"}]}
        cleaned = appliance_warning_entries(body["warnings"], APPLIANCE_WARNINGS_MAX)
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
        plain = lambda: dataclasses.asdict(dataclasses.replace(scenario.snapshot, focused_peer=None))
        before, peer = plain(), dict(scenario.snapshot.focused_peer.parts)
        scenario.state()
        scenario.parts()
        assert plain() == before and dict(scenario.snapshot.focused_peer.parts) == peer

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
        core.mute_toggle(hs.LOUNGE)
        assert core.calls_to("volume_set") == [((50, hs.LOUNGE), {})]
        assert core.calls_to("mute_toggle") == [((hs.LOUNGE,), {})]
        assert [m for m, _a, _k in core.calls] == ["volume_set", "set_focus", "mute_toggle"]

    def test_reboot_and_watches(self):
        core = self._core()
        assert core.request_dial_reboot() is True
        core.watch_outputs(hs.LOUNGE, "hd", True)
        core.watch_eq(hs.LOUNGE, "hd", False)
        assert core.watches == [("outputs", hs.LOUNGE, "hd", True), ("eq", hs.LOUNGE, "hd", False)]
        assert core.warnings.descriptor("sdhealth") is not None
