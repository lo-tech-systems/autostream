"""tests/test_state_parts.py

The part types: defaults, digests, freezing and the pure helpers that read
one snapshot.
"""
from __future__ import annotations

import copy
import dataclasses
import json
import math
import pickle
import sys
from pathlib import Path

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_state as state
from autostream_playback_stats import PlaybackSnapshot
from autostream_state import FrozenDict, thaw
from autostream_state.freeze import deep_freeze
from autostream_state.parts import DIGESTS, PART_NAMES
from track_id.models import (
    STATE_IDENTIFIED,
    TrackIdentificationSnapshot,
    disabled_snapshot,
    state_status_text,
    waiting_snapshot,
)


def identified(index: int, title: str = "Title") -> TrackIdentificationSnapshot:
    return TrackIdentificationSnapshot(
        enabled=True, state=STATE_IDENTIFIED, status_text=state_status_text(STATE_IDENTIFIED),
        input_index=index, title=title, artist="Artist", album="Album",
    )


def entry(index, **kw):
    base = dict(
        device="hw:0", input_type="line", capturing=False, replay_origin=False,
        rate_note="note", sample_rate_text="text", rate_mismatch_hz=0,
        level=FrozenDict({"index": index, "dbfs": -40.0, "vu_history": FrozenDict()}),
    )
    base.update(kw)
    return state.InputEntry(index=index, **base)


def snap(**parts):
    return dataclasses.replace(state.Snapshot(), **parts)


class TestDefaults:
    @pytest.mark.parametrize("cls", [
        state.SessionPart, state.RepeatPart, state.TrackPart, state.InputsPart,
        state.MonitorRuntimeInfo, state.HealthPart, state.SettingsPart, state.Snapshot,
    ])
    def test_each_part_constructs_with_no_arguments(self, cls):
        assert cls() == cls()

    def test_defaults_equal_the_initial_values_of_the_state_they_replace(self):
        assert state.SessionPart().as_dict() == {"active": False, "source": None}
        assert state.RepeatPart().block is None
        assert state.TrackPart().entries == {} and state.TrackPart().service_enabled is False
        assert state.InputsPart() == state.InputsPart((), 0, "")
        mon = state.MonitorRuntimeInfo()
        assert (mon.monitor_build, mon.log_level, mon.connected, mon.last_seen_at) == (
            "unknown", "unknown", False, 0.0)
        assert state.HealthPart().as_json() == {
            "reconcile_fired_count": 0, "reconcile_last_fired_at": 0.0,
            "watchdog_armed": False, "watchdog_restart_count": 0,
            "watchdog_last_restart_at": 0.0,
        }
        assert state.SettingsPart().generation == 0

    def test_the_playback_default_is_an_empty_snapshot(self):
        empty = state.empty_playback_snapshot()
        assert isinstance(empty, PlaybackSnapshot)
        assert empty.inputs == {} and empty.stylus_banner_text is None
        assert empty.stylus_warning_indices == () and empty.has_warning is False

    def test_the_rate_texts_are_the_setup_page_texts(self):
        assert state.RATE_MATCHING_NOTE_DEFAULT.startswith("Follows the sample rate of the source.")
        assert state.SAMPLE_RATE_TEXT_NOT_RUNNING == "Sample rate: not running"
        assert state.MISSING_RATE_TEXTS == (
            state.RATE_MATCHING_NOTE_DEFAULT, state.SAMPLE_RATE_TEXT_NOT_RUNNING)

    def test_the_outputs_part_starts_without_a_master(self):
        p = state.OutputsPart()
        assert (p.master_volume, p.selected_count) == (None, 0)

    def test_every_part_has_a_digest(self):
        assert set(DIGESTS) == set(PART_NAMES)


class TestDigests:
    def test_monitor_digest_ignores_last_seen_at(self):
        a = DIGESTS["monitor"](state.MonitorRuntimeInfo("b", "info", True, 1.0))
        b = DIGESTS["monitor"](state.MonitorRuntimeInfo("b", "info", True, 2.0))
        c = DIGESTS["monitor"](state.MonitorRuntimeInfo("b", "debug", True, 1.0))
        t = DIGESTS["monitor"](state.MonitorRuntimeInfo("b", "info", True, 1.0, -2.5))
        assert t == a and state.MonitorRuntimeInfo().output_trim_db is None
        assert a == b and a != c

    def test_monitor_digest_ignores_output_health(self):
        a = DIGESTS["monitor"](state.MonitorRuntimeInfo("b", "info", True))
        b = DIGESTS["monitor"](state.MonitorRuntimeInfo(
            "b", "info", True, output_health=FrozenDict({"fifo": FrozenDict({"stranded_bytes": 7})})))
        assert state.MonitorRuntimeInfo().output_health is None
        assert a == b

    def test_output_health_renders_as_plain_json(self):
        from types import SimpleNamespace

        from webui.protocol import state as protocol_state
        health = FrozenDict({"fifo": FrozenDict({"stalled_seconds": 0.0, "pipe_bytes": -1})})
        snap = SimpleNamespace(monitor=state.MonitorRuntimeInfo("b", "info", True, output_health=health))
        body = json.loads(protocol_state.part_json(snap, "monitor"))
        assert body["output_health"] == {"fifo": {"stalled_seconds": 0.0, "pipe_bytes": -1}}

    def test_inputs_digest_ignores_the_level_but_not_the_texts(self):
        a = state.InputsPart((entry(1),))
        b = state.InputsPart((entry(1, level=FrozenDict({"index": 1, "dbfs": -10.0})),))
        c = state.InputsPart((entry(1, sample_rate_text="other"),))
        d = state.InputsPart((entry(1),), sample_rate_mismatch_input=1)
        assert DIGESTS["inputs"](a) == DIGESTS["inputs"](b)
        assert DIGESTS["inputs"](a) != DIGESTS["inputs"](c)
        assert DIGESTS["inputs"](a) != DIGESTS["inputs"](d)

    def test_repeat_digest_ignores_positions(self):
        a = state.RepeatPart(FrozenDict({"enabled": True, "recording": {"active": True, "seconds": 3.0}}))
        b = state.RepeatPart(FrozenDict({"enabled": True, "recording": {"active": True, "seconds": 9.0}}))
        assert DIGESTS["repeat"](a) == DIGESTS["repeat"](b)

    def test_track_digest_ignores_timestamps_and_keys_on_the_input(self):
        t1 = identified(1)
        t2 = dataclasses.replace(t1, updated_at=5.0, last_attempt_at=4.0)
        a = state.TrackPart(FrozenDict({1: t1}), True)
        b = state.TrackPart(FrozenDict({1: t2}), True)
        c = state.TrackPart(FrozenDict({2: t1}), True)
        d = state.TrackPart(FrozenDict({1: t1}), False)
        assert DIGESTS["track"](a) == DIGESTS["track"](b)
        assert len({DIGESTS["track"](a), DIGESTS["track"](c), DIGESTS["track"](d)}) == 3

    def test_playback_digest_moves_on_a_banner(self):
        empty = state.empty_playback_snapshot()
        assert DIGESTS["playback"](empty) == DIGESTS["playback"](state.empty_playback_snapshot())
        banner = dataclasses.replace(empty, stylus_banner_text="Stylus due")
        assert DIGESTS["playback"](empty) != DIGESTS["playback"](banner)

    def test_appliance_digest_is_every_field(self):
        base = state.AppliancePart()
        for name, value in [("id", "a"), ("hostname", "h"), ("version", "v"),
                            ("configured", True), ("pin_set", True)]:
            assert DIGESTS["appliance"](dataclasses.replace(base, **{name: value})) != DIGESTS["appliance"](base)

    def test_dials_digest_is_the_generation(self):
        assert DIGESTS["dials"](state.DialsPart(1)) != DIGESTS["dials"](state.DialsPart(0))

    def test_health_digest_is_all_five_fields(self):
        base = state.HealthPart()
        for name, value in [
            ("reconcile_fired_count", 1), ("reconcile_last_fired_at", 2.0),
            ("watchdog_armed", True), ("watchdog_restart_count", 3),
            ("watchdog_last_restart_at", -math.inf),
        ]:
            assert DIGESTS["health"](dataclasses.replace(base, **{name: value})) != DIGESTS["health"](base)

    def test_health_json_maps_non_finite_to_none(self):
        part = state.HealthPart(watchdog_last_restart_at=-math.inf)
        assert part.as_json()["watchdog_last_restart_at"] is None
        json.dumps(part.as_json(), allow_nan=False)

    def test_settings_and_session_digests(self):
        assert DIGESTS["settings"](state.SettingsPart(3)) == 3
        assert DIGESTS["session"](state.SessionPart(True, "replay")) == (True, "replay")


class TestFrozenDict:
    def test_json_bytes_equal_a_plain_dicts(self):
        plain = {"a": 1, "b": [1, 2, {"c": None}], "d": {"e": 1.5}}
        frozen = deep_freeze(plain)
        assert isinstance(frozen, dict)
        assert json.dumps(frozen) == json.dumps(plain)
        assert json.dumps(frozen, indent=2, sort_keys=True) == json.dumps(plain, indent=2, sort_keys=True)

    @pytest.mark.parametrize("call", [
        lambda d: d.__setitem__("x", 1),
        lambda d: d.__delitem__("a"),
        lambda d: d.clear(),
        lambda d: d.pop("a"),
        lambda d: d.popitem(),
        lambda d: d.setdefault("x", 1),
        lambda d: d.update({"x": 1}),
        lambda d: d.__ior__({"x": 1}),
    ])
    def test_every_mutating_method_raises(self, call):
        with pytest.raises(TypeError):
            call(FrozenDict({"a": 1}))

    def test_hash_works_and_equal_dicts_hash_equal(self):
        a = FrozenDict({"a": 1, "b": (1, 2)})
        b = FrozenDict({"b": (1, 2), "a": 1})
        assert hash(a) == hash(b)
        assert {a, b} == {a}

    def test_pickle_round_trip_gives_a_frozen_dict(self):
        a = FrozenDict({"a": 1})
        back = pickle.loads(pickle.dumps(a))
        assert type(back) is FrozenDict and back == a

    def test_copies_are_plain_mutable_dicts(self):
        a = deep_freeze({"a": {"b": [1, 2]}})
        for dup in (copy.copy(a), copy.deepcopy(a), a.copy()):
            assert type(dup) is dict
            dup["z"] = 1
        deep = copy.deepcopy(a)
        assert type(deep["a"]) is dict
        deep["a"]["b2"] = 1

    def test_thaw_gives_a_plain_mutable_deep_copy(self):
        a = deep_freeze({"a": {"b": [1, 2]}})
        t = thaw(a)
        assert t == {"a": {"b": [1, 2]}}
        assert type(t) is dict and type(t["a"]) is dict and type(t["a"]["b"]) is list


class TestDeepFreeze:
    def test_containers_become_their_immutable_forms(self):
        out = deep_freeze({"l": [1, [2]], "s": {1, 2}})
        assert type(out) is FrozenDict
        assert out["l"] == (1, (2,))
        assert out["s"] == frozenset({1, 2})

    def test_an_already_frozen_value_is_returned_as_it_is(self):
        value = deep_freeze({"a": (1, 2)})
        assert deep_freeze(value) is value
        part = state.SessionPart(True, "input1")
        assert deep_freeze(part) is part

    def test_a_frozen_dataclass_is_rebuilt_with_frozen_fields(self):
        part = state.RepeatPart({"a": [1]})
        out = deep_freeze(part)
        assert type(out.block) is FrozenDict and out.block["a"] == (1,)

    def test_a_mutable_dataclass_and_other_objects_are_refused(self):
        @dataclasses.dataclass
        class Loose:
            x: int = 0

        with pytest.raises(TypeError):
            deep_freeze(Loose())
        with pytest.raises(TypeError):
            deep_freeze(object())

    def test_enums_and_scalars_pass(self):
        assert deep_freeze(state.Origin.USER) is state.Origin.USER
        assert deep_freeze(None) is None and deep_freeze("x") == "x" and deep_freeze(1.5) == 1.5


class TestFormatKhz:
    @pytest.mark.parametrize("hz,text", [
        (44100, "44.1 kHz"), (48000, "48 kHz"), (96000.0, "96 kHz"),
        (0, ""), (-1, ""), (float("nan"), ""), (float("inf"), ""), ("x", ""), (None, ""),
    ])
    def test_rates_are_formatted_or_empty(self, hz, text):
        assert state.format_khz(hz) == text


class TestHelpers:
    def test_replay_origin_input(self):
        block = {"replay": {"active": True}, "recording": {"origin_input": 2}}
        assert state.replay_origin_input(block) == 2
        assert state.replay_origin_input({"replay": {"active": False}, "recording": {"origin_input": 2}}) is None
        assert state.replay_origin_input(None) is None
        assert state.replay_origin_input({"replay": {"active": True}}) is None

    def test_repeat_recording_origin_does_not_need_replay(self):
        assert state.repeat_recording_origin({"recording": {"origin_input": 1}}) == 1
        assert state.repeat_recording_origin({"recording": {"origin_input": True}}) is None
        assert state.repeat_recording_origin("x") is None

    def test_session_source_input_index(self):
        assert state.session_source_input_index(snap()) is None
        assert state.session_source_input_index(snap(session=state.SessionPart(True, "input2"))) == 2
        block = FrozenDict({"replay": {"active": True}, "recording": {"origin_input": 1}})
        assert state.session_source_input_index(snap(
            session=state.SessionPart(True, "replay"), repeat=state.RepeatPart(block))) == 1
        assert state.session_source_input_index(snap(session=state.SessionPart(True, "bogus"))) is None

    def test_track_for_input_falls_back_to_disabled(self):
        t = identified(1)
        s = snap(track=state.TrackPart(FrozenDict({1: t}), True))
        assert state.track_for_input(s, 1) is t
        assert state.track_for_input(s, 2) == disabled_snapshot()

    def test_the_inputs_part_readers(self):
        part = state.InputsPart((entry(1), entry(2, rate_note="n2", sample_rate_text="t2")))
        assert part.entry(2).index == 2 and part.entry(3) is None
        assert part.rate_texts(2) == ("n2", "t2")
        assert part.rate_texts(3) == state.MISSING_RATE_TEXTS
        levels = part.levels()
        assert [lv["index"] for lv in levels] == [1, 2]
        levels[0]["dbfs"] = 0
        assert part.levels()[0]["dbfs"] == -40.0


class TestActiveTrack:
    """Each branch of the choice of the track shown."""

    T1, T2 = identified(1, "one"), identified(2, "two")

    def build(self, *, source=None, entries, service=True, repeat=None):
        return snap(
            session=state.SessionPart(source is not None, source),
            repeat=state.RepeatPart(repeat),
            inputs=state.InputsPart(tuple(entries)),
            track=state.TrackPart(FrozenDict({1: self.T1, 2: self.T2}), service),
        )

    def test_the_session_source_wins_over_a_capture_flicker_on_another_input(self):
        s = self.build(source="input1", entries=[entry(1), entry(2, capturing=True)])
        assert state.active_track(s) is self.T1

    def test_a_replay_session_uses_the_replay_origin_input(self):
        s = self.build(source="replay", entries=[entry(1), entry(2, replay_origin=True)])
        assert state.active_track(s) is self.T2

    def test_a_replay_session_with_no_origin_falls_through_to_capturing(self):
        s = self.build(source="replay", entries=[entry(1, capturing=True), entry(2)])
        assert state.active_track(s) is self.T1

    def test_a_session_source_naming_no_input_falls_through(self):
        s = self.build(source="input9", entries=[entry(1), entry(2, capturing=True)])
        assert state.active_track(s) is self.T2

    def test_a_malformed_session_source_falls_through(self):
        s = self.build(source="weird", entries=[entry(1), entry(2, capturing=True)])
        assert state.active_track(s) is self.T2

    def test_without_a_session_the_first_capturing_input_is_used(self):
        s = self.build(entries=[entry(1), entry(2, capturing=True)])
        assert state.active_track(s) is self.T2

    def test_then_the_first_replay_origin_input(self):
        s = self.build(entries=[entry(1), entry(2, replay_origin=True)])
        assert state.active_track(s) is self.T2

    def test_nothing_sourcing_with_a_service_is_waiting(self):
        s = self.build(entries=[entry(1), entry(2)], service=True)
        assert state.active_track(s) == waiting_snapshot()

    def test_nothing_sourcing_without_a_service_is_disabled(self):
        s = self.build(entries=[entry(1), entry(2)], service=False)
        assert state.active_track(s) == disabled_snapshot()


class TestOutputsPart:
    @staticmethod
    def unit(id="a", **kw):
        from autostream_players import OutputInfo
        base = dict(
            id=id, name="Speaker " + id, selected=False, volume=0, muted=False,
            availability="ok", cause=state.Origin.ADOPTED,
            reported=OutputInfo(id=id, name="Speaker " + id),
        )
        base.update(kw)
        return state.OutputUnitView(**base)

    def test_the_defaults_describe_a_player_that_has_not_answered(self):
        p = state.OutputsPart()
        assert p.units == () and p.connected is False and p.muted_all is False
        assert p.silence_chosen is False and p.start_failure is None
        assert p.event_source == "poll" and p.backend_boot == ""

    def test_lookups_and_the_desired_selection(self):
        a, b = self.unit("a", selected=True), self.unit("b")
        p = state.OutputsPart(units=(a, b))
        assert p.unit("b") is b and p.unit("zz") is None
        assert p.unit_by_name("Speaker a") is a and p.unit_by_name("nope") is None
        assert p.selected_units() == (a,)

    def test_a_unit_with_no_row_is_offline_and_the_lookups_skip_it(self):
        away = self.unit("a", selected=True, reported=None, availability="gone")
        here = self.unit("b", selected=True)
        p = state.OutputsPart(units=(away, here))
        assert away.offline is True and here.offline is False
        assert p.unit("a") is away
        assert p.unit_by_name("Speaker a") is None and p.unit_by_name("Speaker b") is here
        assert p.selected_units() == (here,)

    def test_the_list_volume_and_mute_digests_leave_offline_units_out(self):
        base = state.OutputsPart(units=(self.unit("a"),), connected=True)
        card = self.unit("d", reported=None, availability="gone", volume=30)
        withcard = dataclasses.replace(base, units=(self.unit("a"), card))
        for digest in (state.outputs_list_digest, state.outputs_volume_digest, state.outputs_mute_digest):
            assert digest(withcard) == digest(base)
        assert DIGESTS["outputs"](withcard) != DIGESTS["outputs"](base)

    def test_a_unit_waiting_for_a_pin_shows_as_off(self):
        assert self.unit(selected=True).shown_selected is True
        assert self.unit(selected=True, availability="password").shown_selected is False
        assert self.unit(selected=False).shown_selected is False

    def test_the_digest_moves_on_what_a_client_shows(self):
        base = state.OutputsPart(units=(self.unit("a"),), connected=True)
        d = DIGESTS["outputs"]
        assert d(base) == d(state.OutputsPart(units=(self.unit("a"),), connected=True))
        member = state.DefaultMemberView("k", "", "Kitchen", 30, "default:Kitchen", True, False)
        for changed in (
            state.OutputsPart(units=(self.unit("a", selected=True),), connected=True),
            state.OutputsPart(units=(self.unit("a", volume=5),), connected=True),
            state.OutputsPart(units=(self.unit("a", muted=True),), connected=True),
            state.OutputsPart(units=(self.unit("a", availability="starting"),), connected=True),
            state.OutputsPart(units=(self.unit("a", connecting=True),), connected=True),
            state.OutputsPart(units=(self.unit("a", name="Other"),), connected=True),
            state.OutputsPart(units=(self.unit("a"),), connected=False),
            state.OutputsPart(units=(self.unit("a"),), connected=True, muted_all=True),
            state.OutputsPart(units=(self.unit("a"),), connected=True, silence_chosen=True),
            state.OutputsPart(units=(self.unit("a", auto_start=True),), connected=True),
            state.OutputsPart(units=(self.unit("a", hidden=True),), connected=True),
            state.OutputsPart(units=(self.unit("a", pin_claim="webui"),), connected=True),
            state.OutputsPart(units=(self.unit("a", in_use_by="hall"),), connected=True),
            state.OutputsPart(units=(self.unit("a"),), connected=True, default_matches=True),
            state.OutputsPart(units=(self.unit("a"),), connected=True, default_members=(member,)),
            state.OutputsPart(units=(self.unit("a"),), connected=True,
                              default_members=(dataclasses.replace(member, pending=True),)),
        ):
            assert d(changed) != d(base)

    def test_a_placeholder_member_is_found_by_its_card_id(self):
        card = state.DefaultMemberView("k", "", "Kitchen", 30, "default:Kitchen", True, False)
        live = state.DefaultMemberView("l", "l", "Lounge", 30, "l", False, False)
        p = state.OutputsPart(default_members=(live, card))
        assert p.placeholder_member("default:Kitchen") is card
        assert p.placeholder_member("l") is None and p.placeholder_member("x") is None

    def test_the_digest_follows_the_pin_fields_and_the_failure_sequence(self):
        from autostream_players import OutputInfo
        d = DIGESTS["outputs"]
        base = state.OutputsPart(units=(self.unit("a"),))
        pin = self.unit("a", reported=OutputInfo(id="a", name="Speaker a", pin_pending=True))
        assert d(state.OutputsPart(units=(pin,))) != d(base)
        one = state.StartFailure(seq=1, unit_id="a", name="n", reason="refused", at=1.0)
        later = dataclasses.replace(one, at=99.0)
        two = dataclasses.replace(one, seq=2)
        with_one = dataclasses.replace(base, start_failure=one)
        assert d(with_one) != d(base)
        assert d(with_one) == d(dataclasses.replace(base, start_failure=later))
        assert d(with_one) != d(dataclasses.replace(base, start_failure=two))

    def test_the_digest_ignores_what_no_list_shows(self):
        from autostream_players import OutputInfo
        d = DIGESTS["outputs"]
        a = self.unit("a", reported=OutputInfo(id="a", name="Speaker a", offset_ms=10))
        b = self.unit("a", reported=OutputInfo(id="a", name="Speaker a", offset_ms=40, current_mode="airplay1"))
        c = self.unit("a", cause=state.Origin.USER)
        assert d(state.OutputsPart(units=(a,), backend_boot="x", event_source="poll")) == d(
            state.OutputsPart(units=(b,), backend_boot="y", event_source="unix_socket"))
        assert d(state.OutputsPart(units=(a,))) == d(state.OutputsPart(units=(c,)))

    def test_the_hint_digests_split_list_volume_and_mute(self):
        base = state.OutputsPart(units=(self.unit("a", selected=True, volume=20),), connected=True)
        louder = dataclasses.replace(base, units=(self.unit("a", selected=True, volume=30),))
        muted = dataclasses.replace(base, units=(self.unit("a", selected=True, volume=20, muted=True),),
                                    muted_all=True)
        off = dataclasses.replace(base, units=(self.unit("a", selected=False, volume=20),))
        assert state.outputs_volume_digest(louder) != state.outputs_volume_digest(base)
        assert state.outputs_list_digest(louder) == state.outputs_list_digest(base)
        assert state.outputs_mute_digest(louder) == state.outputs_mute_digest(base)
        assert state.outputs_mute_digest(muted) != state.outputs_mute_digest(base)
        assert state.outputs_list_digest(muted) == state.outputs_list_digest(base)
        assert state.outputs_list_digest(off) != state.outputs_list_digest(base)
        assert state.outputs_volume_digest(off) == state.outputs_volume_digest(base)
        # a speaker that is connecting is not a change to the dial lists
        connecting = dataclasses.replace(base, units=(self.unit("a", selected=True, volume=20, connecting=True),))
        assert state.outputs_list_digest(connecting) == state.outputs_list_digest(base)

    def test_a_part_with_a_reported_row_is_frozen_and_publishable(self):
        from autostream_players import OutputInfo
        row = OutputInfo(
            id="a", name="A", extra=(("k", [1, 2]),), has_homepods=True,
        )
        part = state.OutputsPart(units=(self.unit("a", reported=row),))
        frozen = deep_freeze(part)
        assert frozen.units[0].reported.extra == (("k", (1, 2)),)
        assert frozen.units[0].reported.has_homepods is True


class TestOutputsCapabilityFlags:
    def test_both_default_off(self):
        p = state.OutputsPart()
        assert p.device_events is False and p.include_tv_supported is False

    def test_the_digest_moves_on_each_flag_but_the_sub_digests_do_not(self):
        from autostream_state.parts import (
            outputs_list_digest, outputs_mute_digest, outputs_volume_digest)
        d = DIGESTS["outputs"]
        base = state.OutputsPart()
        for flag in ("device_events", "include_tv_supported"):
            other = state.OutputsPart(**{flag: True})
            assert d(other) != d(base)
            for sub in (outputs_list_digest, outputs_mute_digest, outputs_volume_digest):
                assert sub(other) == sub(base)


class TestDevicesPart:
    def test_defaults_are_an_empty_list_and_no_status(self):
        p = state.DevicesPart()
        assert p.monitor_devices == ()
        assert p.bluetooth_status is None
        assert state.Snapshot().devices == p

    def test_the_digest_moves_with_either_field(self):
        base = DIGESTS["devices"](state.DevicesPart())
        with_device = DIGESTS["devices"](state.DevicesPart(
            monitor_devices=(FrozenDict({"hw": "hw:1,0"}),)))
        with_status = DIGESTS["devices"](state.DevicesPart(
            bluetooth_status=FrozenDict({"ok": True})))
        assert len({base, with_device, with_status}) == 3
        assert DIGESTS["devices"](state.DevicesPart()) == base

    def test_a_status_is_deep_frozen(self):
        status = deep_freeze({"ok": True, "paired": {"mac": "AA", "name": "N"}})
        assert isinstance(status, FrozenDict)
        assert isinstance(status["paired"], FrozenDict)


class TestWarningsPart:
    @staticmethod
    def entry(**fields):
        base = dict(id="psu", incident="", severity="warning", kind="psu", subject="",
                    title="Power supply", message="m", link=None)
        base.update(fields)
        return state.WarningEntry(**base)

    def test_the_digest_covers_every_field_of_every_entry(self):
        base = state.WarningsPart((self.entry(),))
        for name, value in [("id", "x"), ("incident", "i"), ("severity", "info"), ("kind", "k"),
                            ("subject", "s"), ("title", "t"), ("message", "n"),
                            ("link", "/about")]:
            other = state.WarningsPart((self.entry(**{name: value}),))
            assert DIGESTS["warnings"](other) != DIGESTS["warnings"](base), name
        assert DIGESTS["warnings"](base) == DIGESTS["warnings"](state.WarningsPart((self.entry(),)))

    def test_an_empty_part_differs_from_one_entry(self):
        assert DIGESTS["warnings"](state.WarningsPart()) != DIGESTS["warnings"](
            state.WarningsPart((self.entry(),)))
