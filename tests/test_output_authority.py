"""tests/test_output_authority.py

The output authority: adoption, reads and retries, every intent with the
exact calls it makes on the player, how each answer of the player is taken,
the start-failure field, the event source choice, and the behaviour that only
real threads show (a wait that expires, writes that coalesce, a late outcome
that must not undo a newer request, stop() while a write is in flight).

Without threads the authority writes inline, so most tests run one thread and
read the result straight away. The real-thread tests use the
started_authority fixture and a backend whose calls wait on an Event.
"""
from __future__ import annotations

import dataclasses
import logging
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_runtime as runtime
import autostream_state as state
import autostream_state.outputs as outputs
from autostream_backend_events import DEGRADED, ConnectInfo, DeviceEvent
from autostream_players import ActionResult, EventChannelInfo, ListOutputsResult
from autostream_state import Origin
from output_fakes import FakeBackend, FakeSource, error, group_row, homepods_row, row, snap
from autostream_state.outputs import (
    START_PENDING_S,
    PlayerServiceBackend,
    WriteOutcome,
    get_authority,
    wait_outcome,
)

T0 = 1000.0


@pytest.fixture
def w(monkeypatch):
    a = get_authority()
    fb = FakeBackend(a)
    clock = [T0]
    monkeypatch.setattr(a, "_clock", lambda: clock[0])
    a.start(fb)
    return SimpleNamespace(a=a, fb=fb, t=clock)


def merge(w, rows, **kw):
    w.a.merge_for_tests(list(rows), boot=kw.pop("boot", "b0"), now=w.t[0], **kw)


# ---------------------------------------------------------------------------
# Reads, adoption and the reachable flag
# ---------------------------------------------------------------------------

class TestAdoption:
    def test_the_first_read_adopts_selection_and_volume_without_a_command(self, w):
        merge(w, [row(1, selected=True, volume_percent=40), row(2)])
        p = snap()
        one, two = p.unit("1"), p.unit("2")
        assert one.selected and one.volume == 40 and one.cause is Origin.ADOPTED
        assert not two.selected
        assert p.connected is True
        assert w.fb.calls == []

    def test_a_unit_that_appears_later_is_adopted_on_first_sight(self, w):
        merge(w, [row(1, selected=True, volume_percent=40)])
        w.a.select("1", Origin.USER, volume=25)
        merge(w, [row(1, selected=True, volume_percent=25), row(2, volume_percent=30)])
        p = snap()
        assert p.unit("2").cause is Origin.ADOPTED and p.unit("2").volume == 30
        assert p.unit("1").cause is Origin.USER

    def test_units_keep_the_order_of_the_rows(self, w):
        merge(w, [row(3), row(1), row(2)])
        assert [u.id for u in snap().units] == ["3", "1", "2"]
        merge(w, [row(2), row(3), row(1)])
        assert [u.id for u in snap().units] == ["2", "3", "1"]

    def test_a_pin_wait_shows_as_off_but_is_not_a_command(self, w):
        merge(w, [row(1, needs_auth_key=True)])
        u = snap().unit("1")
        assert u.availability == "password" and u.shown_selected is False

    def test_availability_follows_the_session_when_rows_carry_one(self, w):
        merge(w, [
            group_row(1, "streaming", selected=True),
            group_row(2, "startup", selected=True),
            group_row(3, "failed"),
            group_row(4, "password"),
            group_row(5, "stopped", selected=True),
            group_row(6, "stopped"),
        ])
        got = {u.id: u.availability for u in snap().units}
        assert got == {"1": "ok", "2": "starting", "3": "failed", "4": "password",
                       "5": "starting", "6": "ok"}

    def test_a_homepods_only_row_follows_its_own_session(self, w):
        merge(w, [
            homepods_row(1, "streaming", selected=True),
            homepods_row(2, "startup", selected=True),
            homepods_row(3, "password", selected=True),
            homepods_row(4, "failed", selected=True),
        ])
        got = {u.id: u.availability for u in snap().units}
        assert got == {"1": "ok", "2": "starting", "3": "password", "4": "failed"}

    def test_a_pin_pending_flag_counts_only_for_a_player_without_sessions(self, w):
        merge(w, [row(1, pin_pending=True)])
        assert snap().unit("1").availability == "password"

    def test_a_unit_was_streaming_when_its_own_session_is(self, w):
        merge(w, [homepods_row(1, "streaming", selected=True), homepods_row(2, "stopped", selected=True)])
        assert w.a._units["1"].was_streaming is True
        assert w.a._units["2"].was_streaming is False


class TestReading:
    def test_a_change_during_a_read_causes_exactly_one_more_read(self, w):
        w.fb.rows = [row(1)]
        w.fb.on_list = w.a.on_outputs_changed       # arrives mid-read, once
        w.a.on_outputs_changed()
        w.a.step(now=T0)
        assert w.fb.reads == 1
        w.a.step(now=T0 + 0.1)
        assert w.fb.reads == 2
        w.a.step(now=T0 + 0.2)
        assert w.fb.reads == 2

    def test_a_failed_read_keeps_dirty_and_retries_with_back_off(self, w):
        w.fb.list_result = ListOutputsResult(ok=False, error="x", error_code="request_failed")
        w.a.on_outputs_changed()
        reads_at = []
        for t in (0, 0.4, 0.5, 1.4, 1.5, 3.4, 3.5, 8.4, 8.5, 13.0, 13.5):
            before = w.fb.reads
            w.a.step(now=T0 + t)
            if w.fb.reads > before:
                reads_at.append(t)
        # 0.5, 1, 2, 5, then 5 again
        assert reads_at == [0, 0.5, 1.5, 3.5, 8.5, 13.5]

    def test_a_read_that_succeeds_clears_the_retry(self, w):
        w.fb.list_result = ListOutputsResult(ok=False, error="x", error_code="request_failed")
        w.a.on_outputs_changed()
        w.a.step(now=T0)
        w.fb.list_result = None
        w.fb.rows = [row(1)]
        w.a.step(now=T0 + 0.5)
        assert snap().connected is True
        before = w.fb.reads
        w.a.step(now=T0 + 0.6)
        assert w.fb.reads == before

    def test_connected_goes_false_only_after_three_failures(self, w):
        merge(w, [row(1)])
        w.fb.list_result = ListOutputsResult(ok=False, error="x", error_code="request_failed")
        w.a.on_outputs_changed()
        w.a.step(now=T0)
        w.a.step(now=T0 + 0.5)
        assert snap().connected is True
        w.a.step(now=T0 + 1.5)
        assert snap().connected is False
        # and the unit is kept as it was
        assert snap().unit("1") is not None

    def test_the_part_is_connected_again_after_a_good_read(self, w):
        merge(w, [row(1)])
        w.a.mark_unreachable_for_tests()
        assert snap().connected is False
        merge(w, [row(1)])
        assert snap().connected is True

    def test_timeouts_during_a_pending_start_do_not_count(self, w):
        merge(w, [row(1), row(2)])
        w.fb.results = [error("timeout")]
        w.a.select("1", Origin.USER, volume=30)
        assert snap().connected is True
        w.fb.list_result = ListOutputsResult(ok=False, error="slow", error_code="timeout")
        w.a.on_outputs_changed()
        for i in range(8):
            w.a.step(now=T0 + 10 * i)
        assert snap().connected is True
        # A refused connection is down, whatever is pending.
        w.fb.list_result = ListOutputsResult(ok=False, error="refused", error_code="request_failed")
        w.a.on_outputs_changed()
        for i in range(8, 12):
            w.a.step(now=T0 + 10 * i)
        assert snap().connected is False

    def test_timeouts_while_a_write_is_in_flight_do_not_count(self, w):
        merge(w, [row(1)])
        w.fb.list_result = ListOutputsResult(ok=False, error="slow", error_code="timeout")

        def read_during_the_write(output_id, fields):
            for i in range(5):
                w.a.on_outputs_changed()
                w.a.step(now=T0 + 10 * i)

        w.fb.on_update = read_during_the_write
        w.a.select("1", Origin.USER, volume=30)
        assert snap().connected is True
        # With nothing in flight the same timeouts count.
        w.fb.on_update = None
        for i in range(5, 9):
            w.a.on_outputs_changed()
            w.a.step(now=T0 + 10 * i)
        assert snap().connected is False

    def test_the_safety_read_comes_every_sixty_seconds(self, w):
        w.fb.rows = [row(1)]
        w.a.on_outputs_changed()
        w.a.step(now=T0)
        assert w.fb.reads == 1
        w.a.step(now=T0 + 59)
        assert w.fb.reads == 1
        w.a.step(now=T0 + 60)
        assert w.fb.reads == 2
        w.a.step(now=T0 + 119)
        assert w.fb.reads == 2
        w.a.step(now=T0 + 120)
        assert w.fb.reads == 3

    def test_start_makes_no_call_to_the_player(self, w):
        assert w.fb.calls == [] and w.fb.reads == 0 and w.fb.channel_calls == 0


class TestBootChange:
    def test_a_new_boot_keeps_desired_and_units_without_a_row(self, w):
        merge(w, [row(1, selected=True, volume_percent=40), row(2)], boot="b0")
        merge(w, [], boot="b1")
        p = snap()
        one = p.unit("1")
        assert one is not None and one.selected and one.volume == 40
        assert one.reported is None and one.availability == "gone"
        assert p.backend_boot == "b1"

    def test_units_without_a_row_are_dropped_after_sixty_seconds(self, w):
        merge(w, [row(1), row(2)], boot="b0")
        merge(w, [row(2)], boot="b1")
        w.fb.rows = [row(2)]
        assert snap().unit("1") is not None
        w.a.step(now=T0 + 59)
        assert snap().unit("1") is not None
        w.a.step(now=T0 + 61)
        assert snap().unit("1") is None and snap().unit("2") is not None

    def test_a_unit_that_vanishes_without_a_restart_goes_at_once(self, w):
        merge(w, [row(1), row(2)])
        merge(w, [row(2)])
        assert snap().unit("1") is None

    def test_a_unit_removed_while_streaming_keeps_silence_chosen_and_comes_back(self, w):
        merge(w, [group_row(1, "streaming", selected=True), group_row(2, "stopped")])
        w.a.deselect("1", Origin.USER)
        assert snap().silence_chosen is True
        merge(w, [group_row(2, "stopped")])             # its row leaves for a while
        assert snap().silence_chosen is True
        assert snap().unit("1") is not None
        merge(w, [group_row(1, "stopped"), group_row(2, "stopped")])
        assert snap().unit("1").reported is not None
        assert snap().silence_chosen is True

    def test_a_backend_without_a_boot_counts_its_restarts_in_epochs(self, w):
        w.a.merge_for_tests([row(1)], now=T0)
        assert snap().backend_boot == "epoch:1"
        w.a.mark_unreachable_for_tests()
        w.a.merge_for_tests([row(1)], now=T0)
        assert snap().backend_boot == "epoch:2"

    def test_connect_info_with_a_new_boot_is_a_boot_change(self, w):
        w.fb.rows = [row(1)]
        w.a.on_connected(ConnectInfo("b0", 5, frozenset(), "unix_socket"))
        w.a.step(now=T0)
        assert snap().backend_boot == "b0"
        w.fb.rows = []
        w.a.on_connected(ConnectInfo("b1", 5, frozenset(), "unix_socket"))
        w.a.step(now=T0 + 1)
        assert snap().backend_boot == "b1"
        assert snap().unit("1").availability == "gone"


class TestUnitForDevice:
    def test_ids_resolve_by_the_unit_id_only(self, w):
        merge(w, [homepods_row(20), group_row(10)])
        a = w.a
        assert a.unit_for_device("10") == "10"
        assert a.unit_for_device("20") == "20"
        assert a.unit_for_device("22") is None
        assert a.unit_for_device("99") is None

    def test_a_device_volume_under_a_row_id_reaches_that_row_whatever_the_member(self, w):
        merge(w, [homepods_row(20, "streaming", selected=True, volume_percent=40)])
        w.a.mute("20", Origin.USER)
        w.a.on_device_event(DeviceEvent(
            "device_volume", "20", "Speaker 20", "volumeup", "45", 1, 1.0, member_id="22"))
        w.a.step(now=T0)
        assert snap().unit("20").muted is False

    def test_a_level_a_speaker_reports_over_upnp_is_a_device_volume(self, w):
        # owntone-mini reports a level set on the speaker itself, read from
        # its UPnP renderer, with its own verb and the level in percent
        merge(w, [row(1, selected=True, volume_percent=40)])
        w.a.mute("1", Origin.USER)
        w.a.on_device_event(DeviceEvent("device_volume", "1", "Speaker 1", "upnp.volume", "31", 1, 1.0))
        w.a.step(now=T0)
        assert snap().unit("1").muted is False

    def test_a_device_volume_for_zero_reaches_every_selected_unit(self, w, caplog):
        merge(w, [row(1, selected=True, volume_percent=40), row(2, selected=True, volume_percent=50), row(3)])
        w.a.mute_all(Origin.USER)
        assert snap().muted_all is True
        w.a.on_device_event(DeviceEvent("device_volume", "0", None, "dmcp.volume", "60", 1, 1.0))
        w.a.step(now=T0)
        assert snap().muted_all is False and not any(u.muted for u in snap().units)

    def test_events_that_map_to_no_unit_or_have_no_policy_are_logged_and_dropped(self, w, caplog):
        merge(w, [row(1, selected=True, volume_percent=40)])
        with caplog.at_level(logging.INFO, logger="autostream.outputs"):
            w.a.on_device_event(DeviceEvent("device_volume", "77", "Ghost", "volumeup", "10", 1, 1.0))
            w.a.on_device_event(DeviceEvent("receiver_command", "1", "Speaker 1", "paus", None, 2, 2.0))
            w.a.step(now=T0)
        text = "\n".join(r.getMessage() for r in caplog.records)
        assert "Ghost" in text and "dropped" in text
        assert "receiver command paus from Speaker 1: no policy, ignored" in text
        assert w.fb.calls == []
        assert snap().unit("1").selected is True


# ---------------------------------------------------------------------------
# Intents
# ---------------------------------------------------------------------------

class TestSelect:
    def test_it_selects_and_writes_the_exact_call(self, w):
        merge(w, [row(1), row(2)])
        before = state.store().snapshot().version
        applied = w.a.select("2", Origin.USER, volume=30, offset_ms=-20, mode="airplay2")
        assert w.fb.calls == [("update_output", ("2",), dict(
            enabled=True, volume_percent=30, offset_ms=-20, mode="airplay2", timeout=3.0))]
        u = snap().unit("2")
        assert u.selected and u.volume == 30 and u.cause is Origin.USER
        assert applied.version > before and applied.refused is None
        assert applied.outcome.result() == (WriteOutcome(ok=True),)

    def test_an_unknown_unit_is_refused_and_nothing_is_written(self, w):
        merge(w, [row(1)])
        applied = w.a.select("9", Origin.USER, volume=30)
        assert applied.refused == "unknown_output" and applied.outcome is None
        assert w.fb.calls == []

    def test_a_successful_select_is_starting_until_a_read_shows_otherwise(self, w):
        merge(w, [group_row(1)])
        w.a.select("1", Origin.USER, volume=30)
        assert snap().unit("1").availability == "starting"
        merge(w, [group_row(1, "streaming", selected=True, volume_percent=30)])
        assert snap().unit("1").availability == "ok"

    def test_joining_a_muted_session_is_silent_and_remembers_the_level(self, w):
        merge(w, [row(1, selected=True, volume_percent=40), row(2)])
        w.a.mute_all(Origin.USER)
        w.fb.calls.clear()
        w.a.select("2", Origin.SESSION, volume=35)
        assert w.fb.updates() == [("2", dict(
            enabled=True, volume_percent=0, offset_ms=None, mode=None, timeout=3.0))]
        u = snap().unit("2")
        assert u.muted is True and u.volume == 35

    def test_a_user_select_ends_the_silence_choice_on_success_only(self, w):
        merge(w, [row(1, selected=True), row(2)])
        w.a.deselect("1", Origin.USER)
        assert snap().silence_chosen is True
        w.fb.results = [error("http_error")]
        w.a.select("2", Origin.USER, volume=10)
        assert snap().silence_chosen is True
        w.a.select("2", Origin.USER, volume=10)
        assert snap().silence_chosen is False

    def test_a_select_with_no_level_carries_the_units_desired_level(self, w):
        merge(w, [row(1, volume_percent=44)])
        w.a.select("1", Origin.SESSION)
        assert w.fb.updates()[0][1]["volume_percent"] == 44
        assert snap().unit("1").volume == 44

    def test_a_select_made_with_a_level_carries_it(self, w):
        merge(w, [row(1, volume_percent=44)])
        w.a.select("1", Origin.USER, volume=25)
        assert w.fb.updates() == [("1", dict(enabled=True, volume_percent=25, offset_ms=None, mode=None, timeout=3.0))]

    def test_a_speaker_joining_a_muted_session_starts_silent(self, w):
        merge(w, [row(1, selected=True, volume_percent=40), row(2, volume_percent=30)])
        w.a.mute_all(Origin.USER)
        w.fb.calls.clear()
        w.a.select("2", Origin.USER, volume=30)
        assert [f["volume_percent"] for _u, f in w.fb.updates()] == [0]

    def test_a_player_that_starts_at_the_enabled_level_gets_one_request_with_both(self, w):
        w.a.assume_start_volume_for_tests(True)
        merge(w, [row(1, volume_percent=44)])
        w.a.select("1", Origin.USER, volume=25)
        assert len(w.fb.updates()) == 1

    def test_a_player_that_does_not_gets_the_level_first_and_then_the_select(self, w):
        w.a.assume_start_volume_for_tests(False)
        merge(w, [row(1, volume_percent=44)])
        w.a.select("1", Origin.USER, volume=25)
        assert w.fb.updates() == [
            ("1", dict(volume_percent=25, timeout=3.0)),
            ("1", dict(enabled=True, volume_percent=25, offset_ms=None, mode=None, timeout=3.0)),
        ]

    def test_a_player_that_does_not_gets_a_muted_speaker_started_silent_by_both_requests(self, w):
        w.a.assume_start_volume_for_tests(False)
        merge(w, [row(1, selected=True, volume_percent=40), row(2, volume_percent=30)])
        w.a.mute_all(Origin.USER)
        w.fb.calls.clear()
        w.a.select("2", Origin.USER, volume=30)
        assert [f["volume_percent"] for _u, f in w.fb.updates()] == [0, 0]

    def test_a_failed_level_request_does_not_stop_the_select(self, w):
        w.a.assume_start_volume_for_tests(False)
        merge(w, [row(1, volume_percent=44)])
        w.fb.results = [error("request_failed")]
        out = w.a.select("1", Origin.USER, volume=25).outcome.result()[0]
        assert out.ok is True
        assert len(w.fb.updates()) == 2

    def test_the_start_volume_is_the_configured_default_level(self, w):
        w.a.set_default_output("Speaker 1", 37)
        assert w.a.start_volume() == 37


class TestStartVolumeCapability:
    def hello(self, w, caps, boot="b0"):
        w.a._handle_connected(ConnectInfo(boot, 1, frozenset(caps), "unix_socket"))

    def poll_connected(self, w):
        w.a._handle_connected(ConnectInfo(None, None, frozenset(), "poll"))

    def level_first(self, w):
        merge(w, [row(1, volume_percent=44)])
        w.fb.calls.clear()
        w.a.select("1", Origin.USER, volume=25)
        return len(w.fb.updates()) == 2

    def test_no_hello_ever_seen_sends_the_level_first(self, w):
        w.a.assume_start_volume_for_tests(False)
        assert self.level_first(w) is True

    def test_a_hello_that_lists_the_capability_sends_one_request(self, w):
        w.a.assume_start_volume_for_tests(False)
        self.hello(w, {"changed", "start_volume"})
        assert self.level_first(w) is False

    def test_a_hello_that_does_not_list_it_sends_the_level_first(self, w):
        self.hello(w, {"changed"})
        assert self.level_first(w) is True

    def test_the_capability_is_kept_while_polling_between_sockets_of_one_boot(self, w):
        self.hello(w, {"start_volume"})
        merge(w, [row(1, volume_percent=44)])
        self.poll_connected(w)
        w.a.mark_unreachable_for_tests()
        merge(w, [row(1, volume_percent=44)])
        self.hello(w, {"start_volume"})
        assert self.level_first(w) is False

    def test_the_capability_is_kept_by_a_poll_source_connecting(self, w):
        self.hello(w, {"start_volume"})
        self.poll_connected(w)
        assert self.level_first(w) is False

    def test_a_restart_seen_without_a_hello_forgets_it(self, w):
        w.a.merge_for_tests([row(1, volume_percent=44)], now=T0)
        w.a.mark_unreachable_for_tests()
        w.a.merge_for_tests([row(1, volume_percent=44)], now=T0)
        assert self.level_first(w) is True

    def test_a_new_hello_after_a_restart_sets_it_again(self, w):
        w.a.merge_for_tests([row(1, volume_percent=44)], now=T0)
        w.a.mark_unreachable_for_tests()
        w.a.merge_for_tests([row(1, volume_percent=44)], now=T0)
        self.hello(w, {"start_volume"}, boot="b5")
        assert self.level_first(w) is False


class TestDeselect:
    def test_it_deselects_and_forgets_the_mute(self, w):
        merge(w, [row(1, selected=True, volume_percent=40), row(2, selected=True, volume_percent=20)])
        w.a.mute_all(Origin.USER)
        w.fb.calls.clear()
        w.a.deselect("1", Origin.USER)
        assert w.fb.updates() == [("1", dict(enabled=False, timeout=3.0))]
        u = snap().unit("1")
        assert not u.selected and not u.muted
        assert snap().unit("2").muted is True

    @pytest.mark.parametrize("cause,expected", [
        (Origin.USER, True), (Origin.POLICY, True), (Origin.DEVICE, True),
        (Origin.SESSION, False), (Origin.SYSTEM, False),
    ])
    def test_the_silence_choice_depends_on_the_cause(self, w, cause, expected):
        merge(w, [row(1, selected=True)])
        w.a.deselect("1", cause)
        assert snap().silence_chosen is expected

    def test_the_silence_choice_needs_the_last_unit_to_go(self, w):
        merge(w, [row(1, selected=True), row(2, selected=True)])
        w.a.deselect("1", Origin.USER)
        assert snap().silence_chosen is False
        w.a.deselect("2", Origin.USER)
        assert snap().silence_chosen is True

    def test_a_session_end_clears_the_choice(self, w):
        merge(w, [row(1, selected=True)])
        w.a.deselect("1", Origin.USER)
        w.a.note_session(False)
        assert snap().silence_chosen is False


class TestDeselectAll:
    def test_a_session_edge_stops_and_disables(self, w):
        merge(w, [row(1, selected=True), row(2, selected=True)])
        w.a.deselect_all(Origin.SESSION)
        assert w.fb.calls == [("stop_and_disable_all", (), dict(timeout=3.0))]
        assert not snap().selected_units()

    @pytest.mark.parametrize("cause", [Origin.USER, Origin.POLICY, Origin.DEVICE, Origin.SYSTEM])
    def test_any_other_cause_only_deselects(self, w, cause):
        merge(w, [row(1, selected=True)])
        w.a.deselect_all(cause)
        assert w.fb.calls == [("set_selected_outputs", ([],), dict(timeout=3.0))]

    def test_a_session_edge_ends_every_mute_and_the_held_mute(self, w):
        merge(w, [row(1, selected=True, volume_percent=40)])
        w.a.mute_all(Origin.USER)
        w.a.deselect(  "1", Origin.USER)
        assert snap().muted_all is True               # held with nothing selected
        w.a.deselect_all(Origin.SESSION)
        assert snap().muted_all is False and not any(u.muted for u in snap().units)

    def test_the_choice_of_silence_follows_the_cause(self, w):
        merge(w, [row(1, selected=True)])
        w.a.deselect_all(Origin.SESSION)
        assert snap().silence_chosen is False
        merge(w, [row(1, selected=True)])
        w.a.deselect_all(Origin.USER)
        assert snap().silence_chosen is True


class TestSetVolume:
    def test_it_sets_and_writes(self, w):
        merge(w, [row(1, selected=True, volume_percent=40)])
        w.a.set_volume("1", 65, Origin.USER)
        assert w.fb.updates() == [("1", dict(volume_percent=65, timeout=3.0))]
        assert snap().unit("1").volume == 65

    def test_the_level_is_clamped(self, w):
        merge(w, [row(1, selected=True)])
        w.a.set_volume("1", 400, Origin.USER)
        assert snap().unit("1").volume == 100

    def test_a_user_change_on_a_muted_unit_unmutes_that_unit_only(self, w):
        merge(w, [row(1, selected=True, volume_percent=40), row(2, selected=True, volume_percent=50)])
        w.a.mute_all(Origin.USER)
        w.fb.calls.clear()
        w.a.set_volume("1", 70, Origin.USER)
        assert w.fb.updates() == [("1", dict(volume_percent=70, timeout=3.0))]
        p = snap()
        assert p.unit("1").muted is False and p.unit("1").volume == 70
        assert p.unit("2").muted is True and p.unit("2").volume == 50
        assert p.muted_all is False

    def test_another_cause_on_a_muted_unit_only_moves_the_level_it_returns_to(self, w):
        merge(w, [row(1, selected=True, volume_percent=40)])
        w.a.mute_all(Origin.USER)
        w.fb.calls.clear()
        applied = w.a.set_volume("1", 30, Origin.SESSION)
        assert w.fb.calls == [] and applied.outcome is None
        u = snap().unit("1")
        assert u.muted is True and u.volume == 30

    def test_an_unknown_unit_is_refused(self, w):
        assert w.a.set_volume("9", 10, Origin.USER).refused == "unknown_output"


class TestStepVolume:
    def start(self, w, *levels):
        merge(w, [row(i + 1, selected=True, volume_percent=v) for i, v in enumerate(levels)])
        w.a.merge_for_tests(list(snap().units[i].reported for i in range(len(levels))), now=T0, boot="b0")
        w.fb.calls.clear()

    @pytest.mark.parametrize("levels,delta,expected", [
        ((40,), 10, {"1": 50}),
        ((40, 60), 10, {"1": 48, "2": 72}),      # 50 -> 60: each scaled by 60/50
        ((40, 60), -10, {"1": 32, "2": 48}),     # 50 -> 40
        ((0, 0), 10, {"1": 10, "2": 10}),        # from silence every speaker takes the master
        ((90, 100), 20, {"1": 95, "2": 100}),    # master capped at 100
        ((10, 20), -50, {"1": 0, "2": 0}),
    ])
    def test_the_arithmetic(self, w, levels, delta, expected):
        self.start(w, *levels)
        w.a.step_volume(delta, Origin.USER, default_level=50)
        got = {uid: f["volume_percent"] for uid, f in w.fb.updates()}
        assert got == {k: v for k, v in expected.items() if levels[int(k) - 1] != v}
        assert {u.id: u.volume for u in snap().units} == expected

    def test_a_unit_that_does_not_move_is_not_written(self, w):
        self.start(w, 100, 100)
        w.a.step_volume(10, Origin.USER, default_level=50)
        assert w.fb.updates() == []

    def test_writes_are_one_per_unit_in_unit_order_and_report_each_outcome(self, w):
        self.start(w, 40, 60, 20)
        w.fb.results = [ActionResult(ok=True), error("http_error"), ActionResult(ok=True)]
        applied = w.a.step_volume(10, Origin.USER, default_level=50, requester="dial:abc")
        assert [uid for uid, _ in w.fb.updates()] == ["1", "2", "3"]
        outcomes = applied.outcome.result()
        assert [o.ok for o in outcomes] == [True, False, True]

    def test_no_selected_unit_and_no_player_are_refused(self, w):
        merge(w, [row(1)])
        assert w.a.step_volume(5, Origin.USER, default_level=50).refused == "no_active_outputs"
        w.a.mark_unreachable_for_tests()
        assert w.a.step_volume(5, Origin.USER, default_level=50).refused == "not_connected"

    def test_down_while_muted_changes_nothing(self, w):
        self.start(w, 40, 60)
        w.a.mute_all(Origin.USER)
        w.fb.calls.clear()
        applied = w.a.step_volume(-10, Origin.USER, default_level=50)
        assert w.fb.calls == [] and applied.outcome is None
        assert snap().muted_all is True and [u.volume for u in snap().units] == [40, 60]

    def test_up_while_muted_is_a_plain_restore_with_no_step_on_top(self, w):
        self.start(w, 40, 60)
        w.a.mute_all(Origin.USER)
        w.fb.calls.clear()
        w.a.step_volume(10, Origin.USER, default_level=50)
        assert dict(w.fb.updates()) == {"1": dict(volume_percent=40, timeout=3.0),
                                        "2": dict(volume_percent=60, timeout=3.0)}
        assert snap().muted_all is False

    def test_the_requester_is_on_the_change(self, w):
        self.start(w, 40)
        changes = []
        state.store().subscribe(changes.append)
        w.a.step_volume(10, Origin.USER, default_level=50, requester="dial:abc")
        mine = [c for c in changes if "outputs" in c.parts]
        assert mine and all(c.requester == "dial:abc" for c in mine[:1])


class TestSetMaster:
    def start(self, w, *levels):
        merge(w, [row(i + 1, selected=True, volume_percent=v) for i, v in enumerate(levels)])
        w.fb.calls.clear()

    def levels(self):
        return [u.volume for u in snap().units]

    def test_it_scales_the_group_in_proportion(self, w):
        self.start(w, 40, 60)
        applied = w.a.set_master(75, Origin.USER, default_level=50)
        assert self.levels() == [60, 90]
        assert applied.master == 75 and applied.muted is False and applied.restored is False
        assert dict(w.fb.updates()) == {"1": dict(volume_percent=60, timeout=3.0),
                                        "2": dict(volume_percent=90, timeout=3.0)}

    def test_the_reply_master_is_the_published_master(self, w):
        self.start(w, 33, 50, 71)
        applied = w.a.set_master(64, Origin.USER, default_level=50)
        assert applied.master == snap().master_volume
        assert abs(snap().master_volume - 64) <= 1

    def test_a_group_clamped_at_the_top_ends_further_from_the_level(self, w):
        self.start(w, 100, 50)
        w.a.set_master(90, Origin.USER, default_level=50)
        assert self.levels() == [100, 60]
        assert snap().master_volume == 80

    def test_a_zero_base_puts_every_unit_at_the_level(self, w):
        self.start(w, 0, 0)
        w.a.set_master(30, Origin.USER, default_level=50)
        assert self.levels() == [30, 30]

    def test_a_unit_that_does_not_move_is_not_written(self, w):
        self.start(w, 40, 60)
        w.a.set_master(50, Origin.USER, default_level=50)
        assert w.fb.updates() == []

    def test_level_zero_while_muted_changes_nothing(self, w):
        self.start(w, 40, 60)
        w.a.mute_all(Origin.USER)
        w.fb.calls.clear()
        applied = w.a.set_master(0, Origin.USER, default_level=50)
        assert w.fb.calls == [] and applied.outcome is None and applied.muted is True
        assert snap().muted_all is True

    def test_a_level_while_muted_restores_then_scales(self, w):
        self.start(w, 40, 60)
        w.a.mute_all(Origin.USER)
        w.fb.calls.clear()
        applied = w.a.set_master(25, Origin.USER, default_level=50)
        assert applied.restored is True and snap().muted_all is False
        assert self.levels() == [20, 30]
        assert dict(w.fb.updates()) == {"1": dict(volume_percent=20, timeout=3.0),
                                        "2": dict(volume_percent=30, timeout=3.0)}

    def test_a_unit_muted_on_its_own_is_left_alone(self, w):
        self.start(w, 40, 60)
        w.a.mute("1", Origin.USER)
        w.a.set_master(30, Origin.USER, default_level=50)
        p = snap()
        assert p.unit("1").muted is True and p.unit("1").volume == 40
        assert p.unit("2").volume == 30

    def test_an_offline_selected_unit_is_left_alone_and_not_counted(self, w):
        merge(w, [row(1, selected=True, volume_percent=40), row(2, selected=True, volume_percent=80)])
        merge(w, [row(2, selected=True, volume_percent=80)], boot="b1")
        p = snap()
        assert p.unit("1").offline and p.selected_count == 1 and p.master_volume == 80
        w.fb.calls.clear()
        applied = w.a.set_master(40, Origin.USER, default_level=50)
        assert snap().unit("1").volume == 40 and snap().unit("2").volume == 40
        assert [uid for uid, _ in w.fb.updates()] == ["2"]
        assert applied.master == 40 and snap().master_volume == 40

    def test_only_offline_units_selected_is_no_active_outputs(self, w):
        merge(w, [row(1, selected=True, volume_percent=40)])
        merge(w, [], boot="b1")
        assert w.a.set_master(10, Origin.USER, default_level=50).refused == "no_active_outputs"

    def test_no_selection_and_no_player_are_refused(self, w):
        merge(w, [row(1)])
        assert w.a.set_master(5, Origin.USER, default_level=50).refused == "no_active_outputs"
        w.a.mark_unreachable_for_tests()
        assert w.a.set_master(5, Origin.USER, default_level=50).refused == "not_connected"

    def test_the_requester_is_on_the_change(self, w):
        self.start(w, 40)
        changes = []
        state.store().subscribe(changes.append)
        w.a.set_master(60, Origin.USER, default_level=50, requester="dial:abc")
        mine = [c for c in changes if "outputs" in c.parts]
        assert mine and mine[0].requester == "dial:abc"


class TestMasterFields:
    def test_none_and_zero_with_nothing_selected(self, w):
        merge(w, [row(1)])
        assert (snap().master_volume, snap().selected_count) == (None, 0)

    def test_the_mean_rounded_up_and_the_count(self, w):
        merge(w, [row(1, selected=True, volume_percent=40), row(2, selected=True, volume_percent=51),
                  row(3)])
        assert (snap().master_volume, snap().selected_count) == (46, 2)

    def test_a_muted_unit_counts_at_its_remembered_level(self, w):
        merge(w, [row(1, selected=True, volume_percent=40), row(2, selected=True, volume_percent=60)])
        w.a.mute_all(Origin.USER)
        assert snap().master_volume == 50

    def test_both_move_the_outputs_digest(self, w):
        from autostream_state.parts import DIGESTS
        merge(w, [row(1, selected=True, volume_percent=40)])
        before = DIGESTS["outputs"](snap())
        merge(w, [row(1, selected=True, volume_percent=40), row(2, selected=True, volume_percent=40)])
        assert DIGESTS["outputs"](snap()) != before


class TestMute:
    def test_mute_all_remembers_levels_and_silences_each_audible_unit(self, w):
        merge(w, [row(1, selected=True, volume_percent=40), row(2, selected=True, volume_percent=0), row(3)])
        applied = w.a.mute_all(Origin.USER)
        assert w.fb.updates() == [("1", dict(volume_percent=0, timeout=3.0))]
        p = snap()
        assert p.muted_all is True
        assert p.unit("1").muted and p.unit("1").volume == 40     # the level it returns to
        assert p.unit("2").muted and p.unit("2").volume == 0
        assert not p.unit("3").muted
        assert [o.ok for o in applied.outcome.result()] == [True]

    def test_a_second_mute_does_not_overwrite_what_the_first_remembered(self, w):
        merge(w, [row(1, selected=True, volume_percent=40)])
        w.a.mute_all(Origin.USER)
        merge(w, [row(1, selected=True, volume_percent=0)])
        applied = w.a.mute_all(Origin.USER)
        assert applied.outcome is None
        assert snap().unit("1").volume == 40

    def test_unmute_all_returns_each_unit_to_its_level_or_the_default(self, w):
        merge(w, [row(1, selected=True, volume_percent=40), row(2, selected=True, volume_percent=0)])
        w.a.mute_all(Origin.USER)
        w.fb.calls.clear()
        w.a.unmute_all(Origin.USER, default_level=55)
        assert dict(w.fb.updates()) == {"1": dict(volume_percent=40, timeout=3.0),
                                        "2": dict(volume_percent=55, timeout=3.0)}
        assert snap().muted_all is False

    def test_unmute_all_lifts_a_silent_unit_that_was_never_muted(self, w):
        merge(w, [row(1, selected=True, volume_percent=0), row(2, selected=True, volume_percent=30)])
        w.a.unmute_all(Origin.USER, default_level=55)
        assert dict(w.fb.updates()) == {"1": dict(volume_percent=55, timeout=3.0)}

    def test_muted_all_needs_a_selected_unit_or_a_held_mute(self, w):
        merge(w, [row(1, selected=True, volume_percent=40), row(2)])
        assert snap().muted_all is False
        w.a.mute_all(Origin.USER)
        assert snap().muted_all is True
        w.a.deselect("1", Origin.USER)
        assert snap().muted_all is True               # held
        w.a.deselect_all(Origin.SESSION)
        assert snap().muted_all is False

    def test_a_partly_muted_selection_reads_unmuted(self, w):
        merge(w, [row(1, selected=True, volume_percent=40), row(2, selected=True, volume_percent=50)])
        w.a.mute_all(Origin.USER)
        w.a.set_volume("1", 20, Origin.USER)
        assert snap().muted_all is False

    def test_per_unit_mute_and_unmute(self, w):
        merge(w, [row(1, selected=True, volume_percent=40)])
        w.a.mute("1", Origin.POLICY)
        assert snap().unit("1").muted and w.fb.updates() == [("1", dict(volume_percent=0, timeout=3.0))]
        w.fb.calls.clear()
        w.a.unmute("1", Origin.POLICY, default_level=50)
        assert not snap().unit("1").muted
        assert w.fb.updates() == [("1", dict(volume_percent=40, timeout=3.0))]

    def test_a_device_volume_ends_the_mute_at_once(self, w):
        merge(w, [row(1, selected=True, volume_percent=40)])
        w.a.mute_all(Origin.USER)
        merge(w, [row(1, selected=True, volume_percent=0)])
        w.a.device_volume_seen("1")
        u = snap().unit("1")
        assert not u.muted and u.cause is Origin.DEVICE


class TestPin:
    def test_a_pin_is_a_write_only(self, w):
        merge(w, [row(1)])
        version = state.store().snapshot().version
        applied = w.a.submit_pin("1", "1234")
        assert w.fb.calls == [("submit_output_pin", ("1", "1234"), dict(timeout=3.0))]
        assert state.store().snapshot().version == version
        assert applied.outcome.result() == (WriteOutcome(ok=True),)

    def test_a_pin_the_player_refuses_comes_back_with_its_code(self, w):
        w.fb.results = [error("pin_invalid", "wrong")]
        out = w.a.submit_pin("1", "0000").outcome.result()[0]
        assert out.ok is False and out.error_code == "pin_invalid" and out.error == "wrong"


# ---------------------------------------------------------------------------
# How the player's answers are taken
# ---------------------------------------------------------------------------

class TestOutcomes:
    @pytest.mark.parametrize("cause", [Origin.USER, Origin.SESSION, Origin.SYSTEM])
    @pytest.mark.parametrize("code,reason", [
        ("pin_required", "pin_required"), ("encoder_capacity", "encoder_capacity"),
        ("pin_invalid", "pin_invalid"),
    ])
    def test_a_refusal_by_the_device_reverts_for_every_cause(self, w, cause, code, reason):
        merge(w, [row(1)])
        w.fb.results = [error(code)]
        applied = w.a.select("1", cause, volume=30)
        u = snap().unit("1")
        assert u.selected is False and u.cause is cause
        assert (u.availability == "password") == (code == "pin_required")
        sf = snap().start_failure
        assert (sf.unit_id, sf.name, sf.reason, sf.seq) == ("1", "Speaker 1", reason, 1)
        out = applied.outcome.result()[0]
        assert out.ok is False and out.error_code == code and out.pending is False

    def test_a_wrong_pin_on_a_user_select_is_its_own_reason_with_the_requester(self, w):
        merge(w, [row(1, selected=False)])
        before = snap().unit("1")
        w.fb.results = [error("pin_invalid", "wrong")]
        w.a.select("1", Origin.USER, volume=30, requester="webui").outcome.result()
        u = snap().unit("1")
        assert u.selected is False
        assert u.availability == before.availability
        sf = snap().start_failure
        assert (sf.reason, sf.requester, sf.unit_id) == ("pin_invalid", "webui", "1")

    def test_a_refusal_by_any_other_code_is_still_refused(self, w):
        merge(w, [row(1)])
        w.fb.results = [error("unsupported", "no")]
        w.a.select("1", Origin.USER, volume=30, requester="webui").outcome.result()
        assert snap().start_failure.reason == "refused"

    def test_a_user_select_reverts_on_any_other_failure(self, w):
        merge(w, [row(1)])
        w.fb.results = [error("http_error", "bad request")]
        out = w.a.select("1", Origin.USER, volume=30).outcome.result()[0]
        assert snap().unit("1").selected is False
        assert out.ok is False and out.error == "bad request"
        assert snap().start_failure.reason == "refused"

    def test_a_request_failed_is_not_pending(self, w):
        merge(w, [row(1)])
        w.fb.results = [error("request_failed")]
        out = w.a.select("1", Origin.USER, volume=30).outcome.result()[0]
        assert out.pending is False and out.ok is False
        assert snap().unit("1").selected is False

    def test_a_timeout_is_a_start_pending(self, w):
        merge(w, [row(1)])
        w.fb.results = [error("timeout", "slow")]
        out = w.a.select("1", Origin.USER, volume=30).outcome.result()[0]
        assert out.ok is True and out.pending is True
        u = snap().unit("1")
        assert u.selected is True and u.availability == "starting"
        assert snap().connected is True and snap().start_failure is None

    def test_a_pending_start_ends_with_the_first_read_that_shows_a_result(self, w):
        merge(w, [group_row(1)])
        w.fb.results = [error("timeout")]
        w.a.select("1", Origin.USER, volume=30)
        merge(w, [group_row(1, "stopped", selected=True)])
        assert snap().unit("1").availability == "starting"
        merge(w, [group_row(1, "streaming", selected=True)])
        assert snap().unit("1").availability == "ok"
        w.t[0] += START_PENDING_S + 5
        w.a.step(now=w.t[0])
        assert snap().start_failure is None

    def test_a_pending_coordinator_start_that_never_shows_a_result_is_retried_at_120_seconds_without_a_notice(self, w):
        merge(w, [group_row(1)])
        w.fb.rows = [group_row(1)]
        w.fb.results = [error("timeout")]
        w.a.select("1", Origin.SESSION, volume=30)
        w.a.note_session(True)
        w.a.step(now=w.t[0] + START_PENDING_S - 1)
        assert snap().start_failure is None
        w.a.step(now=w.t[0] + START_PENDING_S + 1)
        assert snap().start_failure is None
        # a coordinator-made select is kept and retried
        u = snap().unit("1")
        assert u.selected is True and u.availability == "failed"
        assert w.a._units["1"].retry_at is not None

    def test_a_pending_user_start_that_never_shows_a_result_is_reverted_with_a_notice_at_120_seconds(self, w):
        merge(w, [group_row(1)])
        w.fb.rows = [group_row(1)]
        w.fb.results = [error("timeout")]
        w.a.select("1", Origin.USER, volume=30)
        w.a.note_session(True)
        w.a.step(now=w.t[0] + START_PENDING_S - 1)
        assert snap().start_failure is None and snap().unit("1").selected is True
        w.a.step(now=w.t[0] + START_PENDING_S + 1)
        sf = snap().start_failure
        assert sf is not None and sf.reason == "timed_out" and sf.seq == 1
        assert snap().unit("1").selected is False

    def test_a_user_select_that_timed_out_is_not_taken_for_the_players_own_change(self, w):
        merge(w, [group_row(1, "stopped")])
        w.fb.results = [error("timeout")]
        w.a.select("1", Origin.USER, volume=30)
        assert w.a._units["1"].own_write_at == w.t[0]

    def test_a_user_select_that_timed_out_and_then_reads_failed_is_reverted_with_a_notice(self, w):
        merge(w, [group_row(1, "stopped")])
        w.a.note_session(True)
        w.fb.results = [error("timeout")]
        w.a.select("1", Origin.USER, volume=30)
        assert snap().unit("1").selected is True and snap().start_failure is None
        merge(w, [group_row(1, "failed", selected=False)])
        assert snap().unit("1").selected is False
        assert snap().start_failure.reason == "failed"

    def test_a_user_select_that_timed_out_and_then_streams_is_not_reported(self, w):
        merge(w, [group_row(1, "stopped")])
        w.a.note_session(True)
        w.fb.results = [error("timeout")]
        w.a.select("1", Origin.USER, volume=30)
        merge(w, [group_row(1, "streaming", selected=True)])
        assert snap().unit("1").selected is True and snap().start_failure is None

    def test_a_disconnect_ends_every_pending_start(self, w):
        merge(w, [row(1)])
        w.fb.results = [error("timeout")]
        w.a.select("1", Origin.USER, volume=30)
        w.a.on_disconnected("eof")
        w.a.step(now=T0 + 1)
        w.fb.list_result = ListOutputsResult(ok=False, error="slow", error_code="timeout")
        w.a.on_outputs_changed()
        for i in range(2, 8):
            w.a.step(now=T0 + 10 * i)
        # no pending start exempts the timeouts any more
        assert snap().connected is False

    def test_a_coordinator_select_that_fails_is_kept_and_retried_during_a_session(self, w):
        merge(w, [group_row(1)])
        w.a.note_session(True)
        w.fb.results = [error("http_error")]
        out = w.a.select("1", Origin.SESSION, volume=30).outcome.result()[0]
        assert out.ok is False
        u = snap().unit("1")
        assert u.selected is True and u.availability == "failed"
        assert snap().start_failure is None
        assert w.a._units["1"].retry_at is not None

    def test_a_coordinator_start_that_fails_is_retried_and_is_not_a_pin_request(self, w):
        merge(w, [group_row(1)])
        w.a.note_session(True)
        w.fb.results = [error("start_failed", "Output failed to start")]
        out = w.a.select("1", Origin.SESSION, volume=30).outcome.result()[0]
        assert out.ok is False and out.error_code == "start_failed"
        u = snap().unit("1")
        assert u.selected is True and u.availability == "failed"
        assert w.a._units["1"].retry_at is not None

    def test_a_user_start_that_fails_is_reverted_with_the_refused_notice(self, w):
        merge(w, [group_row(1)])
        w.a.note_session(True)
        w.fb.results = [error("start_failed", "Output failed to start")]
        w.a.select("1", Origin.USER, volume=30, requester="webui").outcome.result()
        u = snap().unit("1")
        assert u.selected is False and u.availability != "password"
        sf = snap().start_failure
        assert (sf.reason, sf.requester, sf.unit_id) == ("refused", "webui", "1")

    def test_a_coordinator_select_that_fails_reverts_outside_a_session(self, w):
        merge(w, [group_row(1)])
        w.fb.results = [error("http_error")]
        w.a.select("1", Origin.SESSION, volume=30)
        assert snap().unit("1").selected is False
        assert snap().start_failure is None

    def test_a_coordinator_select_that_fails_is_retried_on_a_player_without_group_fields(self, w):
        merge(w, [row(1)])
        w.a.note_session(True)
        w.fb.results = [error("http_error")]
        w.a.select("1", Origin.SESSION, volume=30)
        u = snap().unit("1")
        assert u.selected is True and u.availability == "failed"
        assert w.a._units["1"].retry_at is not None

    def test_a_user_select_that_fails_reverts_on_a_player_without_group_fields(self, w):
        merge(w, [row(1)])
        w.a.note_session(True)
        w.fb.results = [error("http_error")]
        w.a.select("1", Origin.USER, volume=30)
        assert snap().unit("1").selected is False

    def test_a_later_read_showing_failed_reverts_a_user_select_and_publishes_it(self, w):
        merge(w, [group_row(1)])
        w.a.select("1", Origin.USER, volume=30)
        assert snap().unit("1").selected is True
        merge(w, [group_row(1, "failed", selected=True)])
        assert snap().unit("1").selected is False
        sf = snap().start_failure
        assert sf.reason == "failed" and sf.seq == 1
        merge(w, [group_row(1, "failed", selected=False)])
        assert snap().start_failure.seq == 1

    def test_a_later_failed_read_of_a_coordinator_select_is_not_published(self, w):
        merge(w, [group_row(1)])
        w.a.note_session(True)
        w.a.select("1", Origin.SESSION, volume=30)
        for _ in range(3):
            merge(w, [group_row(1, "failed", selected=True)])
        u = snap().unit("1")
        assert u.selected is True and u.availability == "failed"
        assert snap().start_failure is None

    def test_reselect_required_is_logged_and_not_retried(self, w, caplog):
        merge(w, [group_row(1, "streaming", selected=True)])
        w.fb.results = [error("reselect_required")]
        with caplog.at_level(logging.WARNING, logger="autostream.outputs"):
            out = w.a.select("1", Origin.USER, volume=30).outcome.result()[0]
        assert out.ok is False
        assert any("include_tv change refused" in r.getMessage() for r in caplog.records)
        assert len(w.fb.calls) == 1

    def test_group_not_present_keeps_the_unit_wanted_and_pending(self, w):
        merge(w, [group_row(1)])
        w.fb.results = [error("group_not_present")]
        out = w.a.select("1", Origin.USER, volume=30).outcome.result()[0]
        assert out.ok is True and out.pending is True
        u = snap().unit("1")
        assert u.selected is True and u.availability == "starting"

    def test_a_failed_volume_write_keeps_desired(self, w):
        merge(w, [row(1, selected=True, volume_percent=40)])
        w.fb.results = [error("http_error")]
        out = w.a.set_volume("1", 70, Origin.USER).outcome.result()[0]
        assert out.ok is False
        assert snap().unit("1").volume == 70

    def test_a_failed_deselect_keeps_desired(self, w):
        merge(w, [row(1, selected=True)])
        w.fb.results = [error("http_error")]
        w.a.deselect("1", Origin.USER)
        assert snap().unit("1").selected is False


class TestStartFailureField:
    def test_each_failure_takes_the_next_sequence_number(self, w):
        merge(w, [row(1), row(2)])
        w.fb.results = [error("pin_required"), error("encoder_capacity")]
        w.a.select("1", Origin.USER)
        first = snap().start_failure
        w.a.select("2", Origin.USER)
        second = snap().start_failure
        assert (first.seq, first.unit_id) == (1, "1")
        assert (second.seq, second.unit_id) == (2, "2")

    def test_the_sequence_moves_the_digest_and_the_version(self, w):
        merge(w, [row(1)])
        w.fb.results = [error("encoder_capacity"), error("encoder_capacity")]
        w.a.select("1", Origin.USER)
        v1 = state.store().snapshot().part_versions["outputs"]
        w.a.select("1", Origin.USER)
        v2 = state.store().snapshot().part_versions["outputs"]
        assert v2 > v1

    def test_the_timestamp_is_wall_clock_and_not_in_the_digest(self, w, monkeypatch):
        monkeypatch.setattr(w.a, "_wall", lambda: 1_700_000_000.0)
        merge(w, [row(1)])
        w.fb.results = [error("pin_required")]
        w.a.select("1", Origin.USER)
        assert snap().start_failure.at == 1_700_000_000.0

    def test_boot_and_sequence_name_a_failure_for_ever(self, w):
        merge(w, [row(1)])
        w.fb.results = [error("pin_required")]
        w.a.select("1", Origin.USER)
        first = (state.store().snapshot().boot, snap().start_failure.seq)
        state.store().reset_for_tests()
        w.a.reset_for_tests()
        w.a.assume_start_volume_for_tests()
        w.a.start(w.fb)
        merge(w, [row(1)])
        w.fb.results = [error("pin_required")]
        w.a.select("1", Origin.USER)
        second = (state.store().snapshot().boot, snap().start_failure.seq)
        assert first != second

    def test_a_success_publishes_no_failure(self, w):
        merge(w, [row(1)])
        w.a.select("1", Origin.USER)
        assert snap().start_failure is None


class TestRepublishRequest:
    def test_an_ok_select_raises_it(self, w):
        merge(w, [row(1)])
        runtime.consume_nowplaying_republish()
        w.a.select("1", Origin.USER)
        assert runtime.consume_nowplaying_republish() is True

    def test_a_failure_never_raises_it(self, w):
        merge(w, [row(1), row(2), row(3)])
        runtime.consume_nowplaying_republish()
        for code in ("pin_required", "encoder_capacity", "http_error", "request_failed"):
            w.fb.results = [error(code)]
            w.a.select("1", Origin.USER)
        w.fb.results = [error("timeout")]
        w.a.select("2", Origin.USER)
        assert runtime.consume_nowplaying_republish() is False

    def test_a_unit_that_goes_from_starting_to_ok_raises_it(self, w):
        merge(w, [group_row(1)])
        w.fb.results = [error("timeout")]
        w.a.select("1", Origin.USER)
        runtime.consume_nowplaying_republish()
        merge(w, [group_row(1, "startup", selected=True)])
        assert runtime.consume_nowplaying_republish() is False
        merge(w, [group_row(1, "streaming", selected=True)])
        assert runtime.consume_nowplaying_republish() is True

    def test_a_volume_or_a_deselect_does_not_raise_it(self, w):
        merge(w, [row(1, selected=True, volume_percent=30)])
        runtime.consume_nowplaying_republish()
        w.a.set_volume("1", 50, Origin.USER)
        w.a.deselect("1", Origin.USER)
        assert runtime.consume_nowplaying_republish() is False


class TestIncludeTv:
    def tv_rows(self, has_homepods=True, **fields):
        return [group_row(1, "stopped", has_homepods=has_homepods, **fields)]

    def test_the_field_is_never_sent_when_the_reader_has_no_value(self, w):
        merge(w, self.tv_rows())
        w.a.select("1", Origin.USER, volume=30)
        assert "include_tv" not in w.fb.updates()[0][1]

    def test_false_is_sent_only_once_the_row_shows_has_homepods(self, w):
        w.a.set_include_tv_reader(lambda uid: False)
        merge(w, self.tv_rows(has_homepods=False))
        out = w.a.select("1", Origin.USER, volume=30).outcome.result()[0]
        assert w.fb.calls == [] and out.pending is True
        assert snap().unit("1").selected is True and snap().unit("1").availability == "starting"
        merge(w, self.tv_rows())
        w.a.select("1", Origin.USER, volume=30)
        assert w.fb.updates()[0][1]["include_tv"] is False

    def test_true_is_sent_to_a_row_with_homepods_and_nothing_to_another_row(self, w):
        w.a.set_include_tv_reader(lambda uid: True)
        merge(w, self.tv_rows() + [group_row(2, "stopped", has_homepods=False)])
        w.a.select("1", Origin.USER)
        w.a.select("2", Origin.USER)
        calls = dict(w.fb.updates())
        assert calls["1"]["include_tv"] is True
        assert "include_tv" not in calls["2"]

    def test_a_player_whose_rows_lack_has_homepods_is_never_sent_the_field(self, w):
        w.a.set_include_tv_reader(lambda uid: False)
        merge(w, [row(1)])
        w.a.select("1", Origin.USER)
        assert "include_tv" not in w.fb.updates()[0][1]
        w.fb.calls.clear()
        merge(w, [group_row(2, "stopped")])
        w.a.select("2", Origin.USER)
        assert "include_tv" not in dict(w.fb.updates())["2"]

    def test_the_reader_is_not_called_when_rows_are_read(self, w):
        calls = []
        w.a.set_include_tv_reader(lambda uid: calls.append(uid))
        merge(w, [homepods_row(1, "streaming", selected=True)])
        assert calls == []
        assert snap().unit("1").selected is True and w.fb.calls == []

    def test_a_held_select_is_tried_again_on_the_back_off_without_publishing(self, w):
        w.a.set_include_tv_reader(lambda uid: False)
        rows = self.tv_rows(has_homepods=False)
        merge(w, rows)
        w.a.select("1", Origin.USER, volume=30)
        assert w.fb.calls == []
        version = state.store().snapshot().version
        tries = []
        for t in range(1, 80):
            w.t[0] = T0 + t
            before = w.a._units["1"].held_until
            merge(w, rows)
            w.a.step(now=T0 + t)
            if w.a._units["1"].held_until != before:
                tries.append(t)
        assert tries == [10, 30, 70]
        assert w.fb.calls == []
        assert state.store().snapshot().version == version
        assert snap().unit("1").selected is True and snap().unit("1").availability == "starting"

    def test_a_held_select_is_sent_at_once_when_the_homepods_appear(self, w):
        w.a.set_include_tv_reader(lambda uid: False)
        merge(w, self.tv_rows(has_homepods=False))
        w.a.select("1", Origin.USER, volume=30)
        w.t[0] = T0 + 3
        merge(w, self.tv_rows(has_homepods=True))
        assert w.fb.updates()[0][1]["include_tv"] is False
        assert w.fb.updates()[0][1]["enabled"] is True

    def test_group_not_present_is_not_held_by_the_back_off(self, w):
        w.a.set_include_tv_reader(lambda uid: False)
        merge(w, self.tv_rows())
        w.fb.results = [error("group_not_present")]
        out = w.a.select("1", Origin.USER, volume=30).outcome.result()[0]
        assert out.pending is True and w.a._units["1"].held_until == 0.0


class TestReselect:
    def tv(self, **fields):
        return [homepods_row(1, "streaming", selected=True, volume_percent=40, **fields)]

    def test_it_switches_the_unit_off_and_on_with_the_current_choice(self, w):
        choice = {"1": True}
        w.a.set_include_tv_reader(lambda uid: choice[uid])
        merge(w, self.tv())
        choice["1"] = False
        applied = w.a.reselect("1", Origin.USER, requester="webui")
        assert applied.refused is None
        first, second = w.fb.updates()
        assert first[1]["enabled"] is False
        assert second[1]["enabled"] is True and second[1]["include_tv"] is False
        assert snap().unit("1").selected is True and snap().unit("1").volume == 40

    def test_it_keeps_the_mute_and_does_not_touch_the_silence_choice(self, w):
        w.a.set_include_tv_reader(lambda uid: True)
        merge(w, self.tv())
        w.a.mute_all(Origin.USER)
        w.fb.calls.clear()
        silence = snap().silence_chosen
        w.a.reselect("1", Origin.USER)
        select = w.fb.updates()[-1][1]
        assert select["volume_percent"] == 0
        assert snap().unit("1").muted is True
        assert snap().silence_chosen == silence

    def test_it_carries_the_units_level(self, w):
        w.a.set_include_tv_reader(lambda uid: True)
        merge(w, self.tv())
        w.a.reselect("1", Origin.USER)
        assert w.fb.updates()[-1][1]["volume_percent"] == 40

    def test_it_is_refused_for_an_unknown_or_an_unselected_unit(self, w):
        merge(w, [homepods_row(2)])
        assert w.a.reselect("9", Origin.USER).refused == "unknown_output"
        assert w.a.reselect("2", Origin.USER).refused == "not_selected"
        assert w.fb.calls == []

    def test_reconcile_stays_quiet_between_the_two_writes(self, w):
        w.a.set_include_tv_reader(lambda uid: True)
        merge(w, self.tv())
        seen = []

        def between(output_id, fields):
            if fields.get("enabled") is False:
                unit = w.a._units["1"]
                unit.reported = dataclasses.replace(unit.reported, selected=False)
                with w.a._lock:
                    queued = len(w.a._wq)
                    w.a._reconcile_locked(T0 + 30, outputs._Effects())
                    seen.append((queued, len(w.a._wq)))

        w.fb.on_update = between
        w.a.reselect("1", Origin.USER)
        enables = [f for _, f in w.fb.updates() if f.get("enabled") is True]
        assert seen == [(1, 1)]
        assert len(enables) == 1

    def test_a_refused_switch_off_gets_one_more_select_once_the_unit_reads_off(self, w):
        w.a.set_include_tv_reader(lambda uid: False)
        merge(w, self.tv())
        w.fb.results = [error("http_error"), error("reselect_required")]
        w.a.reselect("1", Origin.USER)
        assert len(w.fb.updates()) == 2
        merge(w, self.tv())
        assert len(w.fb.updates()) == 2
        merge(w, [homepods_row(1, "stopped", selected=False)])
        assert len(w.fb.updates()) == 3
        assert w.fb.updates()[2][1]["include_tv"] is False

    def test_a_second_reselect_required_is_only_logged(self, w, caplog):
        w.a.set_include_tv_reader(lambda uid: False)
        merge(w, self.tv())
        w.fb.results = [error("http_error"), error("reselect_required"), error("reselect_required")]
        w.a.reselect("1", Origin.USER)
        with caplog.at_level(logging.WARNING, logger="autostream.outputs"):
            merge(w, [homepods_row(1, "stopped", selected=False)])
        assert len(w.fb.updates()) == 3
        assert any("include_tv change refused" in r.getMessage() for r in caplog.records)
        merge(w, [homepods_row(1, "stopped", selected=False)])
        assert len(w.fb.updates()) == 3

    def test_a_refused_switch_on_of_a_user_selection_reverts_and_says_why(self, w):
        w.a.set_include_tv_reader(lambda uid: False)
        merge(w, self.tv())
        w.fb.results = [ActionResult(ok=True), error("http_error")]
        w.a.reselect("1", Origin.USER)
        assert snap().unit("1").selected is False
        assert snap().start_failure.reason == "refused" and snap().start_failure.unit_id == "1"

    def test_a_new_boot_resends_the_stored_choice(self, w):
        w.a.set_include_tv_reader(lambda uid: False)
        merge(w, self.tv(), boot="b0")
        w.a.select("1", Origin.USER, volume=40)
        w.fb.calls.clear()
        merge(w, [homepods_row(1, "stopped", selected=False)], boot="b1")
        for t in (3, 6):
            w.t[0] = T0 + t
            w.a.step(now=T0 + t)
            merge(w, [homepods_row(1, "stopped", selected=False)], boot="b1")
        assert any(f.get("include_tv") is False for _, f in w.fb.updates())


class TestWaitOutcome:
    def test_a_finished_write_answers_at_once(self, w):
        merge(w, [row(1)])
        applied = w.a.select("1", Origin.USER)
        assert wait_outcome(applied, 0.0) == (WriteOutcome(ok=True),)

    def test_no_write_has_no_outcome(self, w):
        merge(w, [row(1, selected=True, volume_percent=10)])
        w.a.mute_all(Origin.USER)
        assert wait_outcome(w.a.set_volume("1", 20, Origin.SESSION), 1.0) == ()

    def test_an_unfinished_write_answers_pending_for_each_expected_write(self, w):
        future = __import__("concurrent.futures").futures.Future()
        future.expected = 3
        got = wait_outcome(outputs.Applied(version=1, outcome=future), 0.01)
        assert got == (WriteOutcome(ok=True, pending=True),) * 3


# ---------------------------------------------------------------------------
# Event source choice
# ---------------------------------------------------------------------------

class TestEventSource:
    def make(self, w, monkeypatch, *kinds):
        made = []
        sources = iter(kinds)

        def factory(info, base_url, *, poll_interval):
            kind, connected, path = next(sources)
            src = FakeSource(kind, connected, path)
            made.append(src)
            return src

        w.a._source_factory = factory
        w.a._events_enabled = True
        return made

    def test_the_first_iteration_probes_and_creates_the_source(self, w, monkeypatch):
        made = self.make(w, monkeypatch, ("unix_socket", False, "/run/x.sock"))
        assert w.fb.channel_calls == 0
        w.a.step(now=T0)
        assert w.fb.channel_calls == 1
        assert made[0].started == 1 and snap().event_source == "unix_socket"

    def test_a_connected_unix_socket_is_not_probed_again(self, w, monkeypatch):
        made = self.make(w, monkeypatch, ("unix_socket", True, "/run/x.sock"))
        w.a.step(now=T0)
        for t in (60, 120, 600):
            w.a.step(now=T0 + t)
        assert w.fb.channel_calls == 1

    def test_anything_else_is_probed_every_sixty_seconds(self, w, monkeypatch):
        made = self.make(w, monkeypatch, ("poll", False, None), ("poll", False, None), ("poll", False, None))
        w.a.step(now=T0)
        w.a.step(now=T0 + 30)
        assert w.fb.channel_calls == 1
        w.a.step(now=T0 + 60)
        w.a.step(now=T0 + 119)
        assert w.fb.channel_calls == 2
        w.a.step(now=T0 + 120)
        assert w.fb.channel_calls == 3
        # the same kind keeps the running source
        assert made[0].stopped == 0 and made[0].started == 1

    def test_a_change_of_kind_stops_the_old_source_and_starts_the_new(self, w, monkeypatch):
        made = self.make(w, monkeypatch, ("poll", False, None), ("unix_socket", True, "/run/x.sock"))
        w.a.step(now=T0)
        w.a.step(now=T0 + 60)
        assert made[0].stopped == 1 and made[1].started == 1
        assert snap().event_source == "unix_socket"

    def test_a_degraded_websocket_is_replaced_by_polling(self, w, monkeypatch):
        made = self.make(w, monkeypatch, ("websocket", False, None))
        polls = []

        class Poll(FakeSource):
            def __init__(self, interval):
                super().__init__("poll")
                polls.append(self)

        monkeypatch.setattr(outputs, "PollEventSource", Poll)
        w.a.step(now=T0)
        w.a.on_disconnected(DEGRADED)
        w.a.step(now=T0 + 1)
        assert made[0].stopped == 1 and polls and polls[0].started == 1
        assert snap().event_source == "poll"

    def test_a_failed_probe_means_polling(self, w, monkeypatch):
        seen = []
        w.a._source_factory = lambda info, base_url, *, poll_interval: (seen.append(info), FakeSource())[1]
        w.a._events_enabled = True
        w.fb.event_channel_info = lambda: (_ for _ in ()).throw(RuntimeError("down"))
        w.a.step(now=T0)
        assert seen[0].kind == "poll"

    def by_info(self, w):
        """A factory that builds what the probe describes."""
        made = []

        def factory(info, base_url, *, poll_interval):
            src = FakeSource(info.kind, info.kind == "unix_socket", info.socket_path)
            made.append(src)
            return src

        w.a._source_factory = factory
        w.a._events_enabled = True
        return made

    def test_a_failed_probe_keeps_the_unix_source_and_waits_for_the_next_regular_probe(self, w):
        made = self.by_info(w)
        w.fb.channel = EventChannelInfo(kind="unix_socket", protocol=1, socket_path="/run/x.sock", reachable=True)
        w.a.step(now=T0)
        made[0]._connected = False
        w.a.mark_unreachable_for_tests()
        w.fb.event_channel_info = lambda: (_ for _ in ()).throw(RuntimeError("down"))
        w.a.step(now=T0 + 61)
        assert len(made) == 1 and made[0].stopped == 0 and snap().event_source == "unix_socket"
        calls = w.fb.channel_calls
        w.fb.event_channel_info = lambda: EventChannelInfo(kind="poll", reachable=False)
        for t in (62, 63, 64):
            w.a.step(now=T0 + t)
        assert w.fb.channel_calls == calls
        w.a.step(now=T0 + 122)
        assert len(made) == 1 and made[0].stopped == 0

    def test_a_good_read_after_unreachable_swaps_polling_back_to_the_socket_in_one_step(self, w):
        made = self.by_info(w)
        w.fb.channel = EventChannelInfo(kind="poll", reachable=True)
        w.fb.rows = [row(1)]
        w.a.step(now=T0)
        assert snap().event_source == "poll"
        w.a.mark_unreachable_for_tests()
        w.fb.channel = EventChannelInfo(kind="unix_socket", protocol=1, socket_path="/run/x.sock", reachable=True)
        w.a.step(now=T0 + 5)
        assert snap().event_source == "poll"
        w.a.step(now=T0 + 6)
        assert snap().event_source == "unix_socket" and made[0].stopped == 1

    def test_a_degraded_websocket_is_not_built_again_for_an_hour(self, w, monkeypatch):
        made = self.by_info(w)
        monkeypatch.setattr(outputs, "PollEventSource", lambda interval: FakeSource("poll"))
        w.fb.channel = EventChannelInfo(kind="websocket", websocket_port=8, reachable=True)
        w.a.step(now=T0)
        w.a.on_disconnected(DEGRADED)
        w.a.step(now=T0 + 1)
        assert snap().event_source == "poll"
        started = sum(m.started for m in made)
        for t in (61, 121, 3000, 3599):
            w.a.step(now=T0 + t)
        assert snap().event_source == "poll" and sum(m.started for m in made) == started
        w.a.step(now=T0 + 3660)
        assert snap().event_source == "websocket"

    def test_a_counted_restart_clears_the_degraded_websocket_memory(self, w, monkeypatch):
        made = self.by_info(w)
        monkeypatch.setattr(outputs, "PollEventSource", lambda interval: FakeSource("poll"))
        w.fb.channel = EventChannelInfo(kind="websocket", websocket_port=8, reachable=True)
        w.fb.rows = [row(1)]
        w.a.step(now=T0)
        w.a.on_disconnected(DEGRADED)
        w.a.step(now=T0 + 1)
        w.a._handle_connected(ConnectInfo("b0", 1, frozenset(), "unix_socket"))
        w.a._handle_connected(ConnectInfo("b1", 1, frozenset(), "unix_socket"))
        w.a.step(now=T0 + 2)
        w.a.step(now=T0 + 62)
        assert snap().event_source == "websocket"

    def test_set_backend_asks_for_a_fresh_probe(self, w, monkeypatch):
        made = self.make(w, monkeypatch, ("unix_socket", True, "/run/a.sock"), ("unix_socket", True, "/run/b.sock"))
        w.a.step(now=T0)
        other = FakeBackend(w.a)
        other.base_url = "http://elsewhere:3689"
        w.a.set_backend(other)
        w.a.step(now=T0 + 1)
        assert other.channel_calls == 1 and made[0].stopped == 1
        assert w.a.base_url == "http://elsewhere:3689"

    def test_the_sink_methods_only_enqueue(self, w):
        w.a.on_outputs_changed()
        w.a.on_connected(ConnectInfo("b9", 1, frozenset({"device_volume", "receiver_command"}), "unix_socket"))
        w.a.on_disconnected("eof")
        w.a.on_device_event(DeviceEvent("device_volume", "1", None, "x", "1", 1, 1.0))
        assert w.fb.reads == 0 and w.fb.calls == []
        assert w.a._items.qsize() == 4


# ---------------------------------------------------------------------------
# Resetting and the production backend
# ---------------------------------------------------------------------------

class TestReset:
    def test_a_clean_reset_costs_nothing(self):
        a = get_authority()
        a.reset_for_tests()
        before = threading.active_count()
        for _ in range(1000):
            a.reset_for_tests()
        assert threading.active_count() == before
        assert a._touched is False

    def test_a_reset_returns_to_the_default_backend_and_no_units(self, w):
        merge(w, [row(1, selected=True)])
        w.a.set_policy(object())
        w.a.reset_for_tests()
        assert w.a._units == {} and w.a._policy is None
        assert isinstance(w.a._backend, PlayerServiceBackend)
        assert w.a.base_url == "http://localhost:3689"

    def test_no_thread_runs_without_the_fixture(self, w):
        assert w.a._started is False and w.a._threads == []


class TestPlayerServiceBackend:
    def test_each_method_calls_the_player_service_looked_up_at_call_time(self, monkeypatch):
        import autostream_player_service as ps
        seen = []
        for name in ("list_outputs", "update_output", "set_selected_outputs", "stop_and_disable_all",
                     "submit_output_pin", "refresh_runtime_state", "get_capabilities", "event_channel_info"):
            monkeypatch.setattr(ps, name, lambda *a, _n=name, **k: seen.append((_n, a, k)) or "r")
        b = PlayerServiceBackend("http://p:1")
        assert b.list_outputs(10.0) == "r"
        b.update_output("5", volume_percent=7, timeout=3.0)
        b.set_selected_outputs(["1"], 3.0)
        b.stop_and_disable_all(3.0)
        b.submit_output_pin("5", "1234", 3.0)
        b.refresh_runtime_state(3.0)
        b.capabilities()
        b.event_channel_info()
        assert seen == [
            ("list_outputs", ("http://p:1",), {"timeout": 10.0}),
            ("update_output", ("http://p:1", "5"), {"volume_percent": 7, "timeout": 3.0}),
            ("set_selected_outputs", ("http://p:1", ["1"]), {"timeout": 3.0}),
            ("stop_and_disable_all", ("http://p:1",), {"timeout": 3.0}),
            ("submit_output_pin", ("http://p:1", "5", "1234"), {"timeout": 3.0}),
            ("refresh_runtime_state", ("http://p:1",), {"timeout": 3.0}),
            ("get_capabilities", ("http://p:1",), {}),
            ("event_channel_info", ("http://p:1",), {}),
        ]


# ---------------------------------------------------------------------------
# Reconcile: reported against desired
# ---------------------------------------------------------------------------

def put(w, rows, **kw):
    """A read that returns *rows* now, and keeps returning them to the safety read."""
    w.fb.rows = list(rows)
    merge(w, rows, **kw)


def at(w, seconds):
    """Run the worker's timers *seconds* after the start."""
    w.t[0] = T0 + seconds
    w.a.step(now=w.t[0])


def selects(w):
    return [(uid, f) for uid, f in w.fb.updates() if f.get("enabled") is True]


class TestReconcile:
    def test_after_a_player_restart_a_selected_unit_is_selected_again_after_two_seconds(self, w, caplog):
        put(w, [group_row(1, "streaming", selected=True, volume_percent=40)], boot="b0")
        put(w, [group_row(1, "stopped", selected=False)], boot="b1")
        at(w, 0.1)
        assert selects(w) == []
        with caplog.at_level(logging.WARNING, logger="autostream.outputs"):
            at(w, 2.5)
        (uid, kw), = selects(w)
        assert uid == "1" and kw["volume_percent"] == 40
        assert "restored after the player restarted: 1 output(s)" in caplog.text

    def test_the_restart_select_carries_the_desired_level_and_the_players_default_is_not_adopted(self, w):
        put(w, [group_row(1, "streaming", selected=True, volume_percent=31)], boot="b0")
        put(w, [group_row(1, "stopped", selected=False, volume_percent=50)], boot="b1")
        at(w, 0.1)
        assert snap().unit("1").volume == 31
        at(w, 2.5)
        (uid, kw), = selects(w)
        assert uid == "1" and kw["volume_percent"] == 31
        assert snap().unit("1").volume == 31

    def test_a_restart_selects_each_unit_once_with_its_own_level(self, w):
        put(w, [group_row(1, "streaming", selected=True, volume_percent=31),
                group_row(2, "streaming", selected=True, volume_percent=64)], boot="b0")
        put(w, [group_row(1, "stopped", selected=False), group_row(2, "stopped", selected=False)], boot="b1")
        at(w, 0.1)
        at(w, 2.5)
        assert sorted((uid, kw["volume_percent"]) for uid, kw in selects(w)) == [("1", 31), ("2", 64)]
        assert [c for c in w.fb.calls if c[0] == "set_selected_outputs"] == []
        w.fb.calls.clear()
        at(w, 2.6)
        assert selects(w) == []

    def test_a_restart_is_counted_once_per_boot_change(self, w):
        put(w, [group_row(1, "streaming", selected=True)], boot="b0")
        assert snap().backend_restarts == 0
        put(w, [group_row(1, "stopped", selected=False)], boot="b1")
        put(w, [group_row(1, "stopped", selected=False)], boot="b1")
        assert snap().backend_restarts == 1
        put(w, [group_row(1, "stopped", selected=False)], boot="b2")
        assert snap().backend_restarts == 2

    def test_a_player_without_a_boot_id_is_restarted_by_an_unreachable_spell(self, w):
        w.a.merge_for_tests([row(1)], now=T0)
        assert snap().backend_restarts == 0
        w.a.mark_unreachable_for_tests()
        w.a.merge_for_tests([row(1)], now=T0)
        assert snap().backend_restarts == 1

    def test_a_websocket_close_then_a_good_read_is_a_restart(self, w):
        w.a.merge_for_tests([row(1)], now=T0)
        assert snap().backend_restarts == 0
        w.a.on_disconnected("closed")
        w.a.step(now=T0 + 1)
        w.a.merge_for_tests([row(1)], now=T0 + 1)
        assert snap().backend_restarts == 1
        w.a.merge_for_tests([row(1)], now=T0 + 2)
        assert snap().backend_restarts == 1

    def test_a_socket_close_is_not_a_restart_while_the_boot_is_known(self, w):
        w.a._handle_connected(ConnectInfo("b0", 1, frozenset(), "unix_socket"))
        w.a.merge_for_tests([row(1)], now=T0)
        w.a.on_disconnected("closed")
        w.a.step(now=T0 + 1)
        w.a.merge_for_tests([row(1)], now=T0 + 1)
        assert snap().backend_restarts == 0

    def test_a_poll_source_keeps_the_boot_a_socket_gave(self, w):
        w.a._handle_connected(ConnectInfo("b0", 1, frozenset(), "unix_socket"))
        w.a._source = FakeSource("poll")
        w.a._handle_connected(ConnectInfo(None, None, frozenset(), "poll"))
        w.a.merge_for_tests([row(1)], now=T0)
        assert snap().backend_boot == "b0"

    def test_a_player_that_is_unreachable_is_left_alone(self, w):
        put(w, [group_row(1, "streaming", selected=True)], boot="b0")
        put(w, [group_row(1, "stopped", selected=False)], boot="b1")
        w.a.mark_unreachable_for_tests()
        at(w, 0.1)
        at(w, 5)
        assert w.fb.calls == []

    def test_a_user_deselect_is_never_undone(self, w):
        put(w, [group_row(1, "streaming", selected=True)])
        w.a.deselect("1", Origin.USER)
        w.fb.calls.clear()
        put(w, [group_row(1, "stopped", selected=False)])
        for s in (0.1, 3, 6):
            at(w, s)
        assert w.fb.calls == []

    def test_a_unit_waiting_for_a_pin_is_not_selected_again(self, w):
        put(w, [group_row(1, "streaming", selected=True)], boot="b0")
        put(w, [group_row(1, "password", selected=False)], boot="b1")
        for s in (0.1, 3, 6):
            at(w, s)
        assert selects(w) == []
        assert snap().unit("1").availability == "password"

    def test_a_unit_that_is_starting_is_waited_for(self, w):
        put(w, [group_row(1, "streaming", selected=True)], boot="b0")
        put(w, [group_row(1, "startup", selected=False)], boot="b1")
        for s in (0.1, 3, 6):
            at(w, s)
        assert selects(w) == []

    def test_a_lost_select_is_sent_again_after_two_seconds(self, w):
        put(w, [group_row(1, "stopped")])
        w.a.select("1", Origin.USER, volume=30)
        w.fb.calls.clear()
        w.t[0] += 3                                   # past the debounce after the write
        put(w, [group_row(1, "stopped", selected=False)])
        at(w, 3.1)
        assert selects(w) == []
        at(w, 6)
        assert len(selects(w)) == 1

    def test_a_write_still_in_flight_is_not_second_guessed(self, w):
        put(w, [group_row(1, "stopped")])
        w.a.select("1", Origin.USER, volume=30)
        w.fb.calls.clear()
        w.a._inflight = 1                              # the apply thread is on a write
        put(w, [group_row(1, "stopped", selected=False)])
        for s in (0.1, 3, 6):
            at(w, s)
        w.a._inflight = 0
        assert selects(w) == []
        assert snap().unit("1").selected is True

    def test_a_deselected_unit_that_the_player_still_shows_selected_is_deselected_again(self, w):
        put(w, [group_row(1, "streaming", selected=True)])
        w.a.deselect("1", Origin.USER)
        w.fb.calls.clear()
        w.t[0] += 3
        put(w, [group_row(1, "streaming", selected=True)])
        at(w, 3.1)
        assert w.fb.updates() == []
        at(w, 6)
        assert w.fb.updates() == [("1", dict(enabled=False, timeout=3.0))]

    def test_a_failed_start_is_retried_after_ten_then_twenty_then_thirty_seconds_and_then_every_thirty(self, w):
        put(w, [group_row(1, "stopped")])
        w.a.note_session(True)
        w.fb.default = error("http_error")
        w.a.select("1", Origin.SESSION, volume=30)
        put(w, [group_row(1, "failed", selected=False)])
        u = w.a._units["1"]
        seen = []
        for _ in range(5):
            seen.append(u.retry_at - T0)
            before = len(selects(w))
            at(w, seen[-1] - 0.5)
            assert len(selects(w)) == before
            at(w, seen[-1] + 0.01)
            assert len(selects(w)) == before + 1
        assert [round(x) for x in seen] == [10, 30, 60, 90, 120]
        assert snap().start_failure is None                     # a retry is not a notice

    def test_a_session_end_clears_the_back_off(self, w):
        put(w, [group_row(1, "stopped")])
        w.a.note_session(True)
        w.fb.default = error("http_error")
        w.a.select("1", Origin.SESSION, volume=30)
        assert w.a._units["1"].retry_at is not None
        w.a.note_session(False)
        u = w.a._units["1"]
        assert u.retry_at is None and u.retry_n == 0 and u.group_hold_backoff == 10.0

    def test_a_player_without_session_state_retries_at_ten_thirty_and_sixty_seconds_with_reads_between(self, w):
        put(w, [row(1)])
        w.a.note_session(True)
        w.fb.default = error("http_error")
        w.a.select("1", Origin.SESSION, volume=30)
        assert snap().unit("1").availability == "failed"
        seen = []
        for _ in range(3):
            u = w.a._units["1"]
            seen.append(u.retry_at - T0)
            before = len(selects(w))
            for step in (1, 3, 5):
                at(w, seen[-1] - 10 + step)
                put(w, [row(1)])                # a read between retries keeps the wait
                assert u.retry_at - T0 == seen[-1]
                assert snap().unit("1").availability == "failed"
            at(w, seen[-1] + 0.01)
            assert len(selects(w)) == before + 1
            put(w, [row(1)])
        assert [round(x) for x in seen] == [10, 30, 60]
        assert snap().unit("1").selected is True
        assert snap().start_failure is None

    def test_a_retried_select_on_a_player_without_session_state_that_starts_ends_the_retries(self, w):
        put(w, [row(1)])
        w.a.note_session(True)
        w.fb.results = [error("http_error")]
        w.a.select("1", Origin.SESSION, volume=30)
        at(w, 10.01)
        assert len(selects(w)) == 2
        put(w, [row(1, selected=True, volume_percent=30)])
        u = w.a._units["1"]
        assert u.attempt is False and u.retry_at is None and u.retry_n == 0
        assert snap().unit("1").availability == "ok"

    def test_retries_stop_when_the_session_ends(self, w):
        put(w, [row(1)])
        w.a.note_session(True)
        w.fb.default = error("http_error")
        w.a.select("1", Origin.SESSION, volume=30)
        w.a.note_session(False)
        before = len(selects(w))
        at(w, 15)
        assert len(selects(w)) == before

    def test_a_timed_out_select_that_reads_off_on_a_player_without_session_state_is_retried(self, w):
        put(w, [row(1)])
        w.a.note_session(True)
        w.fb.results = [error("timeout")]
        w.a.select("1", Origin.SESSION, volume=30)
        assert w.a._units["1"].start_pending_until > 0
        put(w, [row(1, selected=False)])
        u = w.a._units["1"]
        assert u.start_pending_until == 0.0 and u.retry_at is not None
        assert snap().unit("1").selected is True and snap().unit("1").availability == "failed"

    def test_a_player_without_session_state_still_follows_a_device_pause_while_no_start_is_running(self, w):
        put(w, [row(1)])
        w.a.note_session(True)
        w.fb.default = ActionResult(ok=True)
        w.a.select("1", Origin.SESSION, volume=30)
        put(w, [row(1, selected=True, volume_percent=30)])
        assert w.a._units["1"].attempt is False
        w.t[0] += 5
        put(w, [row(1, selected=False, volume_percent=30)])
        at(w, 5.1)
        assert snap().unit("1").selected is False

    def test_a_coordinator_select_that_timed_out_and_never_started_is_retried_without_a_notice(self, w):
        put(w, [group_row(1, "stopped")])
        w.a.note_session(True)
        w.fb.results = [error("timeout")]
        w.a.select("1", Origin.SESSION, volume=30)
        put(w, [group_row(1, "stopped", selected=False)])
        at(w, 121)
        u = snap().unit("1")
        assert u.selected is True and u.availability == "failed"
        assert snap().start_failure is None
        assert w.a._units["1"].retry_at is not None

    def test_a_user_select_that_timed_out_and_never_started_is_reverted_with_a_notice(self, w):
        put(w, [group_row(1, "stopped")])
        w.a.note_session(True)
        w.fb.results = [error("timeout")]
        w.a.select("1", Origin.USER, volume=30)
        put(w, [group_row(1, "stopped", selected=False)])
        at(w, 121)
        assert snap().unit("1").selected is False
        assert snap().start_failure.reason == "timed_out"

    def test_a_player_without_sessions_adopts_its_own_deselect(self, w):
        put(w, [row(1, selected=True, volume_percent=40)])
        w.t[0] += 5
        put(w, [row(1, selected=False, volume_percent=40)])
        at(w, 5.1)
        u = snap().unit("1")
        assert u.selected is False and u.cause is Origin.BACKEND
        assert w.fb.calls == []

    def test_a_player_without_sessions_reselects_only_after_a_restart(self, w):
        put(w, [row(1, selected=True, volume_percent=40)], boot="b0")
        put(w, [row(1, selected=False)], boot="b1")
        at(w, 0.1)
        at(w, 2.5)
        assert len(selects(w)) == 1

    def test_a_muted_unit_that_reads_louder_is_silenced_again_when_the_player_reports_device_events(self, w):
        put(w, [row(1, selected=True, volume_percent=40)])
        w.a.mute_all(Origin.USER)
        w.a._delivers_device_events = True
        w.fb.calls.clear()
        w.t[0] += 5
        put(w, [row(1, selected=True, volume_percent=40)])
        at(w, 5.1)
        assert w.fb.updates() == []
        at(w, 8)
        assert w.fb.updates() == [("1", dict(volume_percent=0, timeout=3.0))]
        assert snap().unit("1").muted is True

    def test_without_device_events_a_louder_read_on_a_muted_unit_ends_the_mute(self, w):
        put(w, [row(1, selected=True, volume_percent=40)])
        w.a.mute_all(Origin.USER)
        w.fb.calls.clear()
        w.t[0] += 5
        put(w, [row(1, selected=True, volume_percent=40)])
        at(w, 5.1)
        u = snap().unit("1")
        assert u.muted is False and u.volume == 40 and u.cause is Origin.BACKEND
        assert w.fb.calls == []

    def test_a_level_changed_on_the_player_is_adopted_without_a_write(self, w):
        put(w, [row(1, selected=True, volume_percent=40)])
        w.t[0] += 5
        put(w, [row(1, selected=True, volume_percent=55)])
        at(w, 5.1)
        assert snap().unit("1").volume == 55
        assert w.fb.calls == []

    def test_a_level_written_a_moment_ago_is_not_overwritten_by_a_stale_read(self, w):
        put(w, [row(1, selected=True, volume_percent=40)])
        w.a.set_volume("1", 70, Origin.USER)
        put(w, [row(1, selected=True, volume_percent=40)])
        at(w, 0.5)
        assert snap().unit("1").volume == 70

    def test_a_level_whose_write_is_still_queued_is_not_overwritten_by_a_stale_read(self, w, monkeypatch):
        put(w, [row(1, selected=True, volume_percent=40)])
        # Leave the write in the queue, as when the apply thread has not got to it.
        monkeypatch.setattr(w.a, "_after_intent", lambda: None)
        w.a.set_volume("1", 70, Origin.USER)
        assert w.a._wq
        at(w, 5.0)
        assert snap().unit("1").volume == 70


# ---------------------------------------------------------------------------
# Real threads
# ---------------------------------------------------------------------------

def wait_for(predicate, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.005)
    return False


@pytest.fixture
def live(started_authority):
    a = started_authority
    fb = FakeBackend(a)
    fb.rows = [row(1, selected=True, volume_percent=40), row(2)]
    a._source_factory = lambda info, base_url, *, poll_interval: FakeSource()
    a.start(fb)
    assert wait_for(lambda: snap().connected), "the worker never read the player"
    fb.calls.clear()
    return SimpleNamespace(a=a, fb=fb)


class TestRealThreads:
    def test_the_worker_and_the_apply_thread_are_running(self, live):
        names = {t.name for t in threading.enumerate()}
        assert {"outputs-authority", "outputs-apply"} <= names

    def test_a_wait_that_expires_replies_pending_and_the_real_outcome_arrives_later(self, live):
        live.fb.gate = threading.Event()
        live.fb.results = [error("pin_required", "needs pin")]
        applied = live.a.select("2", Origin.USER, volume=30)
        assert live.fb.entered.wait(5)
        t0 = time.monotonic()
        got = wait_outcome(applied, 0.05)
        assert time.monotonic() - t0 < 2.0
        assert got == (WriteOutcome(ok=True, pending=True),)
        assert not applied.outcome.done()
        live.fb.gate.set()
        real = applied.outcome.result(5)
        assert real[0].ok is False and real[0].error_code == "pin_required"
        assert snap().unit("2").availability == "password"

    def test_a_select_to_a_player_that_needs_the_level_first_sends_both_in_order_on_the_apply_thread(self, live):
        live.a.assume_start_volume_for_tests(False)
        applied = live.a.select("2", Origin.USER, volume=30)
        assert applied.outcome.result(5)[0].ok is True
        assert live.fb.updates() == [
            ("2", dict(volume_percent=30, timeout=3.0)),
            ("2", dict(enabled=True, volume_percent=30, offset_ms=None, mode=None, timeout=3.0)),
        ]

    def test_volume_writes_queued_behind_a_stalled_write_coalesce_to_the_last_level(self, live):
        live.fb.gate = threading.Event()
        first = live.a.set_volume("1", 10, Origin.USER)
        assert live.fb.entered.wait(5)
        later = [live.a.set_volume("1", 11 + i, Origin.USER) for i in range(10)]
        live.fb.gate.set()
        for applied in [first] + later:
            assert applied.outcome.result(5)[0].ok is True
        sent = [f["volume_percent"] for uid, f in live.fb.updates() if uid == "1"]
        assert sent == [10, 20]

    def test_each_unit_keeps_its_own_queued_write(self, live):
        live.fb.rows = [row(1, selected=True, volume_percent=40), row(2, selected=True, volume_percent=40)]
        live.a.select("2", Origin.USER, volume=40).outcome.result(5)
        assert wait_for(lambda: snap().unit("2").selected)
        live.fb.calls.clear()
        live.fb.gate = threading.Event()
        first = live.a.set_volume("1", 10, Origin.USER)
        assert live.fb.entered.wait(5)
        a1 = live.a.set_volume("1", 11, Origin.USER)
        a2 = live.a.set_volume("2", 12, Origin.USER)
        a3 = live.a.set_volume("2", 13, Origin.USER)
        live.fb.gate.set()
        for applied in (first, a1, a2, a3):
            applied.outcome.result(5)
        sent = sorted((uid, f["volume_percent"]) for uid, f in live.fb.updates())
        assert sent == [("1", 10), ("1", 11), ("2", 13)]

    def test_a_late_outcome_cannot_undo_a_newer_request(self, live):
        live.fb.gate = threading.Event()
        live.fb.results = [error("pin_required"), ActionResult(ok=True), ActionResult(ok=True)]
        first = live.a.select("2", Origin.USER, volume=30)
        assert live.fb.entered.wait(5)
        gone = live.a.deselect("2", Origin.USER)
        again = live.a.select("2", Origin.USER, volume=30)
        live.fb.gate.set()
        assert first.outcome.result(5)[0].error_code == "pin_required"
        gone.outcome.result(5)
        assert again.outcome.result(5)[0].ok is True
        assert snap().unit("2").selected is True
        # the late refusal is still shown to the user
        assert snap().start_failure.reason == "pin_required"

    def test_stop_returns_within_its_timeout_while_a_write_is_in_flight(self, live):
        live.fb.gate = threading.Event()
        applied = live.a.select("2", Origin.USER, volume=30)
        assert live.fb.entered.wait(5)
        queued = live.a.set_volume("1", 5, Origin.USER)
        t0 = time.monotonic()
        live.a.stop(timeout=0.5)
        assert time.monotonic() - t0 < 2.0
        # a write still queued is answered, not left waiting for ever
        assert queued.outcome.result(2)[0].ok is False
        live.fb.gate.set()
        assert wait_for(lambda: not any(
            t.name in ("outputs-authority", "outputs-apply") and t.is_alive() for t in threading.enumerate()))

    def test_a_reselect_sends_its_two_writes_back_to_back_with_other_writes_around_it(self, live):
        live.fb.rows = [row(1, selected=True, volume_percent=40), row(2, selected=True, volume_percent=40)]
        live.a.set_include_tv_reader(lambda uid: True)
        live.a.on_outputs_changed()
        assert wait_for(lambda: snap().unit("2") is not None)
        live.fb.calls.clear()
        live.fb.gate = threading.Event()
        first = live.a.set_volume("2", 10, Origin.USER)
        assert live.fb.entered.wait(5)
        again = live.a.reselect("1", Origin.USER)
        other = live.a.set_volume("2", 12, Origin.USER)
        live.fb.gate.set()
        for applied in (first, again, other):
            applied.outcome.result(5)
        order = [(uid, f.get("enabled")) for uid, f in live.fb.updates() if uid == "1"]
        assert order == [("1", False), ("1", True)]
        assert snap().unit("1").selected is True

    def test_a_change_pushed_by_the_source_is_read_and_merged(self, live):
        live.fb.rows = [row(1, selected=True, volume_percent=55), row(2)]
        live.a.on_outputs_changed()
        assert wait_for(lambda: snap().unit("1").volume == 55)


# ---------------------------------------------------------------------------
# Who asked and a request that outlives its wait
# ---------------------------------------------------------------------------

class TestRequesterOnFailure:
    def test_a_failed_start_names_who_asked(self, w):
        merge(w, [row(1)])
        w.fb.results = [error("pin_required")]
        w.a.select("1", Origin.USER, requester="dial:abc")
        assert snap().start_failure.requester == "dial:abc"

    def test_a_refusal_the_player_gives_later_still_names_who_asked(self, w):
        merge(w, [row(1)])
        w.fb.results = [error("http_error")]
        w.a.select("1", Origin.USER, requester="webui")
        assert snap().start_failure.reason == "refused"
        assert snap().start_failure.requester == "webui"

    def test_a_start_the_coordinator_retries_has_no_asker(self, w):
        merge(w, [row(1)])
        w.fb.results = [error("encoder_capacity")]
        w.a.select("1", Origin.SESSION)
        assert snap().start_failure.requester is None

    def test_a_pin_request_answered_inside_the_wait_is_not_claimed_by_the_authority(self, w, monkeypatch):
        claims = []
        monkeypatch.setattr(outputs, "_pin_claim_handler", lambda uid, who: claims.append((uid, who)))
        merge(w, [row(1)])
        w.fb.results = [error("pin_required")]
        applied = w.a.select("1", Origin.USER, requester="dial:abc", claimant="dial:abc")
        # The caller answered inside its wait: the reply carries the prompt, nothing is claimed here.
        assert wait_outcome(applied, 1.0)[0].error_code == "pin_required"
        assert claims == []

    def test_no_handler_installed_is_not_an_error(self, w, monkeypatch):
        monkeypatch.setattr(outputs, "_pin_claim_handler", None)
        merge(w, [row(1)])
        w.fb.results = [error("pin_required")]
        w.a.select("1", Origin.USER, requester="dial:abc", claimant="dial:abc")
        assert snap().start_failure.reason == "pin_required"


class TestVolumeStepResult:
    def test_the_applied_result_carries_the_master_and_the_mute(self, w):
        merge(w, [row(1, selected=True, volume_percent=40), row(2, selected=True, volume_percent=60)])
        stepped = w.a.step_volume(10, Origin.USER, default_level=50)
        assert (stepped.master, stepped.muted, stepped.restored) == (60, False, False)
        muted = w.a.mute_all(Origin.USER)
        assert (muted.master, muted.muted) == (60, True)
        down = w.a.step_volume(-5, Origin.USER, default_level=50)
        assert down.outcome is None and (down.master, down.muted) == (60, True)
        up = w.a.step_volume(5, Origin.USER, default_level=50)
        assert (up.restored, up.muted, up.master) == (True, False, 60)


# ---------------------------------------------------------------------------
# Mute tokens, per-unit restores and the marks a policy reads
# ---------------------------------------------------------------------------

def _marks(w, uid):
    m = w.a.unit_marks(uid)
    return (m.mute_token, m.mute_joined)


class TestMuteTokens:
    def test_mute_all_returns_the_tokens_of_only_the_units_it_muted(self, w):
        merge(w, [row(1, selected=True, volume_percent=40), row(2, selected=True, volume_percent=50), row(3)])
        w.a.mute("1", Origin.DEVICE)
        applied = w.a.mute_all(Origin.DEVICE)
        assert [uid for uid, _ in applied.mute_tokens] == ["2"]
        assert applied.token_at == applied.mute_tokens[0][1] > _marks(w, "1")[0] > 0
        assert w.a.unit_marks("3").mute_token == 0

    def test_tokens_increase_with_each_mute(self, w):
        merge(w, [row(1, selected=True, volume_percent=40), row(2, selected=True, volume_percent=50)])
        first = w.a.mute("1", Origin.DEVICE)
        second = w.a.mute("2", Origin.DEVICE)
        assert first.mute_tokens[0][1] < second.mute_tokens[0][1] == second.token_at

    def test_a_user_mute_all_restamps_a_unit_that_is_already_muted_with_no_write(self, w):
        merge(w, [row(1, selected=True, volume_percent=40)])
        old = w.a.mute("1", Origin.DEVICE).mute_tokens[0][1]
        w.fb.calls.clear()
        applied = w.a.mute_all(Origin.USER)
        assert w.fb.calls == []
        assert applied.mute_tokens == (("1", old + 1),) and _marks(w, "1") == (old + 1, False)

    def test_a_user_mute_restamps_but_a_device_mute_does_not(self, w):
        merge(w, [row(1, selected=True, volume_percent=40)])
        old = w.a.mute("1", Origin.DEVICE).mute_tokens[0][1]
        w.fb.calls.clear()
        again = w.a.mute("1", Origin.DEVICE)
        assert again.mute_tokens == () and _marks(w, "1")[0] == old
        user = w.a.mute("1", Origin.USER)
        assert user.mute_tokens == (("1", old + 1),) and w.fb.calls == []

    def test_a_unit_joining_a_muted_selection_gets_a_joined_token(self, w):
        merge(w, [row(1, selected=True, volume_percent=40), row(2)])
        w.a.mute_all(Origin.DEVICE)
        w.a.select("2", Origin.USER, volume=30)
        assert _marks(w, "2")[1] is True and _marks(w, "2")[0] > _marks(w, "1")[0]
        assert _marks(w, "1")[1] is False

    @pytest.mark.parametrize("clear", [
        lambda a: a.set_volume("1", 20, Origin.USER),
        lambda a: a.unmute_all(Origin.USER, default_level=50),
        lambda a: a.step_volume(5, Origin.USER, default_level=50),
        lambda a: a.unmute("1", Origin.DEVICE, default_level=50),
        lambda a: a.device_volume_seen("1"),
        lambda a: a.deselect("1", Origin.USER),
        lambda a: a.deselect_all(Origin.USER),
    ])
    def test_every_way_a_mute_ends_clears_its_token_and_flag(self, w, clear):
        merge(w, [row(1, selected=True, volume_percent=40), row(2)])
        w.a.mute_all(Origin.DEVICE)
        assert _marks(w, "1")[0] > 0
        clear(w.a)
        assert _marks(w, "1") == (0, False)

    def test_a_louder_read_adopted_on_a_muted_unit_clears_its_token(self, w):
        put(w, [row(1, selected=True, volume_percent=40)])
        w.a.mute_all(Origin.USER)
        w.t[0] += 5
        put(w, [row(1, selected=True, volume_percent=40)])
        at(w, 5.1)
        assert _marks(w, "1") == (0, False)

    def test_a_failed_start_that_is_reverted_clears_the_token(self, w):
        merge(w, [row(1, selected=True, volume_percent=40), row(2)])
        w.a.mute_all(Origin.DEVICE)
        w.fb.results = [error("boom")]
        w.a.select("2", Origin.USER, volume=30)
        assert snap().unit("2").selected is False
        assert _marks(w, "2") == (0, False)

    def test_unmute_with_a_token_restores_only_while_that_mute_stands(self, w):
        merge(w, [row(1, selected=True, volume_percent=40)])
        token = w.a.mute("1", Origin.DEVICE).mute_tokens[0][1]
        w.fb.calls.clear()
        w.a.unmute("1", Origin.DEVICE, default_level=0, only_token=token)
        assert snap().unit("1").muted is False
        assert w.fb.updates() == [("1", dict(volume_percent=40, timeout=3.0))]

    @pytest.mark.parametrize("how", ["moved", "unmuted", "restamped"])
    def test_a_token_mismatch_changes_nothing_and_tells_nobody(self, w, how):
        merge(w, [row(1, selected=True, volume_percent=40)])
        token = w.a.mute("1", Origin.DEVICE).mute_tokens[0][1]
        if how == "moved":
            token -= 1
        elif how == "unmuted":
            w.a.unmute_all(Origin.USER, default_level=50)
        else:
            w.a.mute_all(Origin.USER)
        w.fb.calls.clear()
        changes = []
        state.store().subscribe(changes.append)
        before = state.store().snapshot().version
        applied = w.a.unmute("1", Origin.DEVICE, default_level=0, only_token=token)
        assert applied.outcome is None and applied.refused is None
        assert w.fb.calls == [] and changes == []
        assert state.store().snapshot().version == before
        assert snap().unit("1").muted is (how != "unmuted")

    def test_unmuting_a_unit_that_is_not_muted_publishes_nothing(self, w):
        merge(w, [row(1, selected=True, volume_percent=40)])
        changes = []
        state.store().subscribe(changes.append)
        applied = w.a.unmute("1", Origin.DEVICE, default_level=50)
        assert applied.outcome is None and changes == [] and w.fb.calls == []

    def test_unmuting_an_unknown_unit_is_refused(self, w):
        assert w.a.unmute("9", Origin.DEVICE, default_level=0).refused == "unknown_output"

    def test_a_unit_muted_at_zero_comes_back_at_zero_with_no_write(self, w):
        merge(w, [row(1, selected=True, volume_percent=0)])
        token = w.a.mute("1", Origin.DEVICE).mute_tokens[0][1]
        assert w.fb.calls == []
        w.a.unmute("1", Origin.DEVICE, default_level=0, only_token=token)
        assert snap().unit("1").muted is False and snap().unit("1").volume == 0
        assert w.fb.calls == []

    def test_unmute_joined_restores_only_joined_mutes_after_the_token(self, w):
        merge(w, [row(1, selected=True, volume_percent=40), row(2), row(3), row(4)])
        w.a.mute_all(Origin.DEVICE)
        since = w.a.mute_all(Origin.DEVICE).token_at       # nothing new; the counter as it stands
        w.a.select("2", Origin.USER, volume=30)            # joins muted
        w.a.select("3", Origin.USER, volume=35)            # joins muted
        w.fb.calls.clear()
        w.a.unmute_joined(since, Origin.DEVICE, default_level=0)
        p = snap()
        assert not p.unit("2").muted and not p.unit("3").muted
        assert p.unit("1").muted
        assert dict(w.fb.updates()) == {"2": dict(volume_percent=30, timeout=3.0),
                                        "3": dict(volume_percent=35, timeout=3.0)}

    def test_unmute_joined_leaves_a_join_from_before_the_token(self, w):
        merge(w, [row(1, selected=True, volume_percent=40), row(2)])
        w.a.mute_all(Origin.DEVICE)
        w.a.select("2", Origin.USER, volume=30)
        since = w.a.unit_marks("2").mute_token
        w.a.unmute_joined(since, Origin.DEVICE, default_level=0)
        assert snap().unit("2").muted is True

    def test_unmute_joined_with_nothing_to_restore_publishes_nothing(self, w):
        merge(w, [row(1, selected=True, volume_percent=40)])
        w.a.mute_all(Origin.DEVICE)
        changes = []
        state.store().subscribe(changes.append)
        applied = w.a.unmute_joined(0, Origin.DEVICE, default_level=0)
        assert applied.outcome is None and changes == []

    def test_the_mute_hold_ends_with_the_last_per_unit_restore(self, w):
        merge(w, [row(1, selected=True, volume_percent=40), row(2, selected=True, volume_percent=50)])
        applied = w.a.mute_all(Origin.DEVICE)
        tokens = dict(applied.mute_tokens)
        w.a.unmute("1", Origin.DEVICE, default_level=0, only_token=tokens["1"])
        assert w.a._mute_held is True
        w.a.unmute("2", Origin.DEVICE, default_level=0, only_token=tokens["2"])
        assert w.a._mute_held is False and snap().muted_all is False


class TestSelectSeq:
    def test_it_moves_when_the_selection_goes_from_off_to_on(self, w):
        merge(w, [row(1), row(2, selected=True, volume_percent=30)])
        assert w.a.unit_marks("1").select_seq == 0 and w.a.unit_marks("2").select_seq == 1
        w.a.select("1", Origin.USER, volume=20)
        assert w.a.unit_marks("1").select_seq == 1
        w.a.select("1", Origin.USER, volume=25)
        assert w.a.unit_marks("1").select_seq == 1
        w.a.deselect("1", Origin.USER)
        w.a.select("1", Origin.USER, volume=25)
        assert w.a.unit_marks("1").select_seq == 2

    def test_a_volume_does_not_move_it(self, w):
        merge(w, [row(1, selected=True, volume_percent=30)])
        w.a.set_volume("1", 50, Origin.USER)
        w.a.mute_all(Origin.USER)
        assert w.a.unit_marks("1").select_seq == 1

    def test_an_unknown_unit_has_no_marks(self, w):
        assert w.a.unit_marks("nope") is None


# ---------------------------------------------------------------------------
# What the player can report, and the policy hooks
# ---------------------------------------------------------------------------

class RecordingPolicy:
    def __init__(self):
        self.calls = []
        self.deadline = None
        self.fail = False

    def on_device_event(self, ev, outputs, now):
        self.calls.append(("event", ev.verb, now, outputs.unit("1").muted if outputs.unit("1") else None))
        if self.fail:
            raise RuntimeError("policy broke")

    def on_timer(self, now, outputs):
        self.calls.append(("timer", now))
        if self.fail:
            raise RuntimeError("policy broke")

    def next_deadline(self):
        return self.deadline

    def on_session(self, active):
        self.calls.append(("session", active))
        if self.fail:
            raise RuntimeError("policy broke")


class TestCapabilityFlags:
    def test_device_events_follow_the_hello_capabilities(self, w):
        assert snap().device_events is False
        w.a.on_connected(ConnectInfo("b0", 1, frozenset({"device_volume", "receiver_command"}), "unix_socket"))
        w.a.step(now=T0)
        assert snap().device_events is True
        w.a.on_connected(ConnectInfo("b0", 1, frozenset({"changed"}), "unix_socket"))
        w.a.step(now=T0)
        assert snap().device_events is False

    def test_a_connect_that_changes_nothing_publishes_nothing(self, w):
        info = ConnectInfo("b0", 1, frozenset({"device_volume", "receiver_command"}), "unix_socket")
        w.a.on_connected(info)
        w.a.step(now=T0)
        version = state.store().snapshot().version
        w.a.on_connected(info)
        w.a.step(now=T0)
        assert state.store().snapshot().version == version

    def test_a_degraded_channel_clears_device_events(self, w):
        w.a.on_connected(ConnectInfo("b0", 1, frozenset({"device_volume", "receiver_command"}), "unix_socket"))
        w.a.step(now=T0)
        w.a._source_factory = lambda info, base_url, *, poll_interval: FakeSource()
        w.a.on_disconnected(DEGRADED)
        w.a.step(now=T0)
        assert snap().device_events is False and snap().event_source == "poll"

    def test_include_tv_supported_comes_from_the_first_row_with_has_homepods(self, w):
        merge(w, [row(1)])
        assert snap().include_tv_supported is False
        merge(w, [row(1), homepods_row(2, "streaming")])
        assert snap().include_tv_supported is True


class TestPolicyHooks:
    @pytest.fixture
    def pol(self, w):
        p = RecordingPolicy()
        w.a.set_policy(p)
        return p

    def test_a_device_event_reaches_the_policy_with_the_state_after_its_own_handling(self, w, pol):
        merge(w, [row(1, selected=True, volume_percent=40)])
        w.a.mute("1", Origin.USER)
        w.a.on_device_event(DeviceEvent("device_volume", "1", None, "volumeup", "45", 1, 1.0))
        w.a.step(now=T0 + 3)
        assert ("event", "volumeup", T0 + 3, False) in pol.calls

    def test_the_policy_is_told_the_clock_read_after_the_wait(self, w, pol):
        merge(w, [row(1, selected=True, volume_percent=40)])
        w.t[0] = T0 + 1.5
        w.a.on_device_event(DeviceEvent("receiver_command", "1", None, "paus", None, 1, 1.0))
        w.a.step(block=0.5)
        assert [c for c in pol.calls if c[0] == "event"] == [("event", "paus", T0 + 1.5, False)]

    def test_on_timer_runs_every_step_with_the_step_time(self, w, pol):
        w.a.step(now=T0 + 1)
        w.a.step(now=T0 + 2)
        assert pol.calls == [("timer", T0 + 1), ("timer", T0 + 2)]

    def test_next_deadline_shortens_the_wait(self, w, pol):
        merge(w, [row(1)])
        assert w.a._next_wait(T0) == 1.0
        pol.deadline = T0 + 0.4
        assert w.a._next_wait(T0) == pytest.approx(0.4)
        pol.deadline = T0 - 5
        assert w.a._next_wait(T0) == 0.05

    def test_both_session_edges_reach_the_policy_in_queue_order_with_events(self, w, pol):
        merge(w, [row(1, selected=True, volume_percent=40)])
        w.a.note_session(True)
        w.a.on_device_event(DeviceEvent("receiver_command", "1", None, "paus", None, 1, 1.0))
        w.a.note_session(False)
        w.a.step(now=T0)
        order = [c[:2] if c[0] == "event" else c for c in pol.calls if c[0] != "timer"]
        assert order == [("session", True), ("event", "paus"), ("session", False)]

    def test_a_raising_hook_is_logged_and_the_next_step_runs(self, w, pol, caplog):
        pol.fail = True
        merge(w, [row(1, selected=True, volume_percent=40)])
        w.a.note_session(True)
        w.a.on_device_event(DeviceEvent("receiver_command", "1", None, "paus", None, 1, 1.0))
        with caplog.at_level(logging.ERROR, logger="autostream.outputs"):
            w.a.step(now=T0)
            w.a.step(now=T0 + 1)
        text = "\n".join(r.getMessage() for r in caplog.records)
        assert "device event" in text and "session edge" in text and "timer" in text
        assert pol.calls[-1] == ("timer", T0 + 1)

    def test_a_bound_policy_suppresses_the_no_policy_line(self, w, pol, caplog):
        merge(w, [row(1, selected=True, volume_percent=40)])
        with caplog.at_level(logging.INFO, logger="autostream.outputs"):
            w.a.on_device_event(DeviceEvent("receiver_command", "1", "Speaker 1", "paus", None, 2, 2.0))
            w.a.step(now=T0)
        assert "no policy" not in "\n".join(r.getMessage() for r in caplog.records)


class TestConnecting:
    def connecting(self, uid="1"):
        return snap().unit(uid).connecting

    @pytest.mark.parametrize("session_state,expected", [
        ("startup", True), ("connected", True), ("stopped", True),
        ("streaming", False), ("password", False),
    ])
    def test_a_wanted_speaker_on_a_row_with_a_session_connects_until_it_streams(self, w, session_state, expected):
        w.a.note_session(True)
        merge(w, [group_row(1, session_state, selected=True)])
        assert self.connecting() is expected

    def test_a_failed_speaker_the_coordinator_keeps_retrying_is_connecting(self, w):
        merge(w, [group_row(1)])
        w.a.note_session(True)
        w.fb.results = [error("http_error")]
        w.a.select("1", Origin.SESSION, volume=30).outcome.result()
        merge(w, [group_row(1, "failed", selected=False)])
        assert snap().unit("1").availability == "failed" and self.connecting()

    def test_a_failed_start_being_reverted_is_not_connecting(self, w):
        merge(w, [group_row(1)])
        w.a.note_session(True)
        w.fb.results = [error("http_error")]
        w.a.select("1", Origin.USER, volume=30).outcome.result()
        merge(w, [group_row(1, "failed", selected=False)])
        assert snap().unit("1").selected is False and not self.connecting()

    def test_a_speaker_that_is_not_wanted_is_not_connecting(self, w):
        w.a.note_session(True)
        merge(w, [group_row(1, "startup", selected=False)])
        assert not self.connecting()

    def test_nothing_connects_outside_a_session(self, w):
        merge(w, [group_row(1, "startup", selected=True)])
        assert not self.connecting()

    def test_the_session_edges_move_it(self, w):
        merge(w, [group_row(1, "startup", selected=True)])
        assert not self.connecting()
        w.a.note_session(True)
        assert self.connecting()
        w.a.note_session(False)
        assert not self.connecting()

    def test_a_unit_whose_row_is_away_is_not_connecting(self, w):
        w.a.note_session(True)
        merge(w, [group_row(1, "streaming", selected=True)], boot="b0")
        merge(w, [], boot="b1")
        assert snap().unit("1").reported is None and not self.connecting()

    def test_a_row_without_a_session_connects_until_the_player_reports_it_selected(self, w):
        w.a.note_session(True)
        merge(w, [row(1)])
        w.fb.results = [ActionResult(ok=True)]
        w.a.select("1", Origin.SESSION, volume=30).outcome.result()
        merge(w, [row(1, selected=False)])
        assert self.connecting()
        merge(w, [row(1, selected=True)])
        assert not self.connecting()

    def test_a_speaker_waiting_for_a_pin_is_not_connecting(self, w):
        w.a.note_session(True)
        merge(w, [row(1, selected=True, needs_auth_key=True)])
        assert snap().unit("1").availability == "password" and not self.connecting()


class TestDefaultCard:
    NAME = "Speaker 9"

    @pytest.fixture(autouse=True)
    def configured(self, w):
        w.a.set_default_output(self.NAME, 35)

    def test_a_default_the_player_does_not_have_is_listed_offline(self, w):
        merge(w, [row(1)])
        p = snap()
        card = p.units[-1]
        assert (card.id, card.name, card.offline) == ("default:" + self.NAME, self.NAME, True)
        assert (card.volume, card.muted, card.availability, card.cause) == (35, False, "gone", Origin.SESSION)
        assert card.reported is None and card.connecting is False
        assert p.placeholder_id == card.id

    def test_nothing_is_listed_while_the_player_is_unreachable_or_no_default_is_set(self, w):
        merge(w, [row(1)])
        w.a.mark_unreachable_for_tests()
        assert all(u.name != self.NAME for u in snap().units) and snap().placeholder_id == ""
        merge(w, [row(1)])
        w.a.set_default_output("", 35)
        assert [u.id for u in snap().units] == ["1"]

    def test_it_is_selected_in_a_session_until_the_user_chooses_silence(self, w):
        merge(w, [row(1)])
        card = lambda: snap().units[-1]  # noqa: E731
        assert card().selected is False
        w.a.note_session(True)
        assert card().selected is True
        w.a.want_default(False)
        assert card().selected is False and snap().silence_chosen is True
        w.a.want_default(True)
        assert card().selected is True and snap().silence_chosen is False
        w.a.want_default(False)
        w.a.note_session(False)
        assert card().selected is False and snap().silence_chosen is False

    def test_the_tap_writes_nothing_to_the_player(self, w):
        merge(w, [row(1)])
        w.a.note_session(True)
        w.a.want_default(False)
        w.a.want_default(True)
        assert w.fb.calls == []

    def test_it_is_not_a_unit_for_the_authority(self, w):
        merge(w, [row(1)])
        w.a.note_session(True)
        assert w.a.select("default:" + self.NAME, Origin.USER, volume=30).refused == "unknown_output"
        assert w.a.deselect("default:" + self.NAME, Origin.USER).refused == "unknown_output"
        assert w.a.set_volume("default:" + self.NAME, 30, Origin.USER).refused == "unknown_output"
        assert w.a.step_volume(5, Origin.USER, default_level=50).refused == "no_active_outputs"

    def test_offline_views_are_skipped_by_the_lookups(self, w):
        merge(w, [row(1)])
        w.a.note_session(True)
        p = snap()
        assert p.units[-1].selected is True
        assert p.unit_by_name(self.NAME) is None
        assert p.selected_units() == ()

    def test_the_row_appearing_replaces_the_placeholder(self, w):
        merge(w, [row(1)])
        merge(w, [row(1), row(9, self.NAME)])
        p = snap()
        assert [u.id for u in p.units] == ["1", "9"] and p.placeholder_id == ""
        assert p.unit_by_name(self.NAME).id == "9" and not p.unit("9").offline

    def test_a_default_whose_row_goes_away_is_kept_past_the_usual_wait(self, w):
        merge(w, [row(1), row(9, self.NAME, selected=True, volume_percent=35)])
        merge(w, [row(1)])
        p = snap()
        gone = p.unit("9")
        assert gone.offline and gone.selected is True and p.placeholder_id == ""
        w.t[0] += outputs.ABSENT_KEEP_S + 5
        merge(w, [row(1)])
        assert snap().unit("9") is not None and snap().unit("9").offline
        assert snap().unit_by_name(self.NAME) is None and snap().selected_units() == ()

    def test_another_speaker_that_goes_away_is_still_dropped(self, w):
        merge(w, [row(1), row(2)])
        merge(w, [row(1)])
        assert snap().unit("2") is None

    def test_no_write_reaches_the_player_for_a_default_it_does_not_have(self, w):
        merge(w, [row(1), row(9, self.NAME, selected=True)])
        merge(w, [row(1)])
        w.fb.calls.clear()
        w.a.deselect("9", Origin.USER).outcome.result(5)
        w.a.select("9", Origin.USER, volume=30).outcome.result(5)
        assert w.fb.calls == []
        assert snap().unit("9").selected is True

    def test_the_dial_lists_do_not_move_when_it_comes_and_goes(self, w):
        merge(w, [row(1)])
        base = snap()
        w.a.note_session(True)
        w.a.want_default(False)
        merge(w, [row(1), row(9, self.NAME)])
        merge(w, [row(1)])
        for digest in (state.outputs_list_digest, state.outputs_volume_digest, state.outputs_mute_digest):
            assert digest(snap()) == digest(base)
