"""Tests for the dial core's request methods that need no screen: manual
focus, the replay and repeat requests, and master volume and mute. Each is
called on a bare core with a roster and nothing else, taking an accept and
every refusal. (Outputs, EQ, warning dismissal and the reboot request are
exercised the same way in test_dial_core.py.)"""
import os
import sys
import threading
import time
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dial"))

import pytest

import dial_repeat_store as drs
from dial_auth import AUTH_AUTHORIZED, AUTH_UNAUTHORIZED
from dial_core import FOCUS_PENDING_GRACE_S, DialCore
from dial_core_state import ActionResult
from dial_mdns import RosterEntry

AID = "a" * 20
BID = "b" * 20


class _Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def _entry(appliance_id=AID, auth=AUTH_AUTHORIZED, repeat_capable=True, ip="192.0.2.10", port=80,
           service_name="Kitchen"):
    return RosterEntry(
        appliance_id=appliance_id, service_name=service_name, name=service_name, ip=ip, port=port,
        playing=False, repeat_capable=repeat_capable, auth=auth,
    )


def _core(*entries, clock=None):
    core = DialCore("dial-1", lambda: [], lambda: [], clock=clock or time.monotonic)
    core.set_roster(list(entries) if entries else [_entry()])
    return core


def _record(state, appliance_id=AID, armed=False, available=True):
    drs.repeat_store.update(appliance_id, drs.parse_repeat_object({
        "available": available, "state": state, "armed": armed, "held": state == "hold",
        "recording_seconds": 30.0,
        "replay": {"active": state == "replaying", "position_seconds": 1.0, "duration_seconds": 30.0},
    }, time.monotonic()))


@pytest.fixture(autouse=True)
def _clean_store():
    drs.repeat_store.clear(AID)
    drs.repeat_store.clear(BID)
    yield
    drs.repeat_store.clear(AID)
    drs.repeat_store.clear(BID)


class TestSetFocus:
    def test_pins_the_focus_and_wakes_the_poll(self):
        core = _core()
        assert core.set_focus(AID) == ActionResult(True)
        assert core.snapshot().focus.manual_id == AID
        assert core._poll_wake.is_set()

    def test_none_clears_it_back_to_auto_pick(self):
        core = _core()
        core.set_focus(AID)
        assert core.set_focus(None) == ActionResult(True)
        assert core.snapshot().focus.manual_id is None

    def test_an_appliance_that_refused_this_dial_is_refused(self):
        core = _core(_entry(auth=AUTH_UNAUTHORIZED))
        assert core.set_focus(AID) == ActionResult(False, "unauthorized")
        assert core.snapshot().focus.manual_id is None

    def test_an_id_off_the_roster_is_taken_and_left_for_the_tick_to_drop(self):
        core = _core()
        assert core.set_focus(BID) == ActionResult(True)
        assert core.snapshot().focus.manual_id == BID

    def test_callable_from_another_thread(self):
        core = _core()
        results = []
        thread = threading.Thread(target=lambda: results.append(core.set_focus(AID)))
        thread.start()
        thread.join()
        assert results == [ActionResult(True)]


class TestStartReplay:
    def test_pins_a_pending_focus_records_and_sends_a_seek_to_zero(self):
        clock = _Clock(1000.0)
        core = _core(clock=clock)
        _record("hold")
        with patch("dial_core.enqueue_transport") as send:
            assert core.start_replay(AID) == ActionResult(True, token=1000.0)
        snap = core.snapshot()
        assert snap.focus.manual_id == AID
        assert snap.focus.pending == (AID, "Kitchen", 1000.0 + FOCUS_PENDING_GRACE_S)
        assert (snap.transport.appliance_id, snap.transport.kind, snap.transport.state) == (
            AID, "seek", "pending",
        )
        target, action, position, token = send.call_args[0]
        assert (target.appliance_id, target.ip, target.port) == (AID, "192.0.2.10", 80)
        assert (action, position, token) == ("seek", 0.0, 1000.0)
        assert snap.transport.requested_at == token
        assert core._poll_wake.is_set()

    def test_a_running_replay_restarts(self):
        core = _core()
        _record("replaying")
        with patch("dial_core.enqueue_transport") as send:
            assert core.start_replay(AID).accepted
        assert send.call_args[0][1] == "seek"

    def test_a_rejection_from_the_worker_drops_the_pending_focus(self):
        core = _core()
        _record("hold")
        with patch("dial_core.enqueue_transport"):
            token = core.start_replay(AID).token
        core.on_repeat_result(
            "transport", AID, 200, {"ok": False, "error": "source_active"}, {"token": token},
        )
        snap = core.snapshot()
        assert snap.focus.manual_id is None and snap.focus.pending is None
        assert snap.transport.state == "rejected"

    @pytest.mark.parametrize("entry, reason", [
        (_entry(auth=AUTH_UNAUTHORIZED), "unauthorized"),
        (_entry(repeat_capable=False), "no_capability"),
    ])
    def test_refused_for_the_appliance(self, entry, reason):
        core = _core(entry)
        _record("hold")
        with patch("dial_core.enqueue_transport") as send:
            assert core.start_replay(AID) == ActionResult(False, reason)
        send.assert_not_called()
        assert core.snapshot().focus.manual_id is None
        assert core.snapshot().transport is None

    def test_refused_for_an_unknown_appliance(self):
        core = _core()
        with patch("dial_core.enqueue_transport") as send:
            assert core.start_replay(BID) == ActionResult(False, "unknown_appliance")
        send.assert_not_called()

    def test_refused_without_a_usable_record(self):
        core = _core()
        with patch("dial_core.enqueue_transport") as send:
            assert core.start_replay(AID) == ActionResult(False, "no_record")
            _record("hold", available=False)
            assert core.start_replay(AID) == ActionResult(False, "no_record")
        send.assert_not_called()
        assert core.snapshot().focus.manual_id is None

    @pytest.mark.parametrize("state", ["recording", "pending", "idle"])
    def test_refused_when_the_record_is_not_a_replay_or_a_hold(self, state):
        core = _core()
        _record(state)
        with patch("dial_core.enqueue_transport") as send:
            assert core.start_replay(AID) == ActionResult(False, "wrong_state")
        send.assert_not_called()
        assert core.snapshot().focus.pending is None


class TestRestartReplay:
    @pytest.mark.parametrize("state", ["replaying", "hold"])
    def test_seeks_to_zero_without_touching_the_focus(self, state):
        core = _core()
        _record(state)
        with patch("dial_core.enqueue_transport") as send:
            result = core.restart_replay(AID)
        target, action, position, token = send.call_args[0]
        assert (target.appliance_id, action, position) == (AID, "seek", 0.0)
        assert result == ActionResult(True, token=token)
        snap = core.snapshot()
        assert snap.transport.requested_at == token
        assert snap.transport.kind == "seek" and snap.transport.state == "pending"
        assert snap.focus.manual_id is None and snap.focus.pending is None

    def test_refusals(self):
        with patch("dial_core.enqueue_transport") as send:
            core = _core()
            assert core.restart_replay(BID) == ActionResult(False, "unknown_appliance")
            assert core.restart_replay(AID) == ActionResult(False, "no_record")
            _record("recording")
            assert core.restart_replay(AID) == ActionResult(False, "wrong_state")
            assert _core(_entry(repeat_capable=False)).restart_replay(AID) == ActionResult(
                False, "no_capability")
            assert _core(_entry(auth=AUTH_UNAUTHORIZED)).restart_replay(AID) == ActionResult(
                False, "unauthorized")
        send.assert_not_called()


class TestStopReplay:
    def test_records_a_stop_and_sends_it(self):
        core = _core()
        _record("replaying")
        with patch("dial_core.enqueue_transport") as send:
            result = core.stop_replay(AID)
        target, action, position, token = send.call_args[0]
        assert (target.appliance_id, action, position) == (AID, "stop", 0.0)
        assert result == ActionResult(True, token=token)
        assert core.snapshot().transport.kind == "stop"
        # its own ok ack settles it and is told apart from a seek's
        outcome = core.on_repeat_result(
            "transport", AID, 200, {"ok": True, "state": "hold"}, {"token": token},
        )
        assert outcome.stop_acked is True
        assert core.snapshot().transport.state == "accepted"

    @pytest.mark.parametrize("state", ["hold", "recording", "idle"])
    def test_refused_outside_a_running_replay(self, state):
        core = _core()
        _record(state)
        with patch("dial_core.enqueue_transport") as send:
            assert core.stop_replay(AID) == ActionResult(False, "wrong_state")
        send.assert_not_called()

    def test_refusals(self):
        with patch("dial_core.enqueue_transport") as send:
            core = _core()
            assert core.stop_replay(BID) == ActionResult(False, "unknown_appliance")
            assert core.stop_replay(AID) == ActionResult(False, "no_record")
            assert _core(_entry(repeat_capable=False)).stop_replay(AID) == ActionResult(
                False, "no_capability")
            assert _core(_entry(auth=AUTH_UNAUTHORIZED)).stop_replay(AID) == ActionResult(
                False, "unauthorized")
        send.assert_not_called()


class TestSetRepeatArmed:
    @pytest.mark.parametrize("state", ["recording", "pending", "idle"])
    @pytest.mark.parametrize("armed", [True, False])
    def test_records_and_sends_the_arm(self, state, armed):
        core = _core()
        _record(state)
        with patch("dial_core.enqueue_arm") as send:
            result = core.set_repeat_armed(AID, armed)
        target, sent, token = send.call_args[0]
        assert (target.appliance_id, target.ip, target.port, sent) == (AID, "192.0.2.10", 80, armed)
        assert result == ActionResult(True, token=token)
        assert core.snapshot().transport.requested_at == token
        assert core.snapshot().transport.kind == "arm"
        assert core.snapshot().transport.state == "pending"

    @pytest.mark.parametrize("state", ["replaying", "hold"])
    def test_refused_in_the_replay_layout(self, state):
        core = _core()
        _record(state)
        with patch("dial_core.enqueue_arm") as send:
            assert core.set_repeat_armed(AID, True) == ActionResult(False, "wrong_state")
        send.assert_not_called()
        assert core.snapshot().transport is None

    def test_refusals(self):
        with patch("dial_core.enqueue_arm") as send:
            core = _core()
            assert core.set_repeat_armed(BID, True) == ActionResult(False, "unknown_appliance")
            assert core.set_repeat_armed(AID, True) == ActionResult(False, "no_record")
            assert _core(_entry(repeat_capable=False)).set_repeat_armed(AID, True) == ActionResult(
                False, "no_capability")
            assert _core(_entry(auth=AUTH_UNAUTHORIZED)).set_repeat_armed(AID, True) == ActionResult(
                False, "unauthorized")
        send.assert_not_called()


class TestVolumeStep:
    def test_queues_the_delta_for_the_worker(self):
        core = _core()
        with patch("dial_core.enqueue_delta") as send:
            assert core.volume_step(3) == ActionResult(True)
            assert core.volume_step(-2) == ActionResult(True)
        assert [c[0] for c in send.call_args_list] == [(3,), (-2,)]

    def test_an_id_must_be_the_focused_appliance(self):
        core = _core(_entry(), _entry(BID))
        core.set_focus(AID)
        with patch("dial_core.enqueue_delta") as send:
            assert core.volume_step(1, BID) == ActionResult(False, "not_focused")
            send.assert_not_called()
            assert core.volume_step(1, AID) == ActionResult(True)
        send.assert_called_once_with(1)

    def test_the_reporting_appliance_counts_as_focused(self):
        core = _core()
        core.set_field("reporting_id", AID)
        with patch("dial_core.enqueue_delta") as send:
            assert core.volume_step(1, AID).accepted
        send.assert_called_once_with(1)

    def test_an_id_with_nothing_focused_is_refused(self):
        core = _core()
        with patch("dial_core.enqueue_delta") as send:
            assert core.volume_step(1, AID) == ActionResult(False, "not_focused")
        send.assert_not_called()


class TestVolumeSet:
    def test_queues_the_difference_from_what_is_shown(self):
        core = _core()
        core.set_field("source_service_name", "Kitchen")
        with patch("dial_core.shown_volume", return_value=40) as shown, \
                patch("dial_core.enqueue_delta") as send:
            assert core.volume_set(55) == ActionResult(True)
            assert core.volume_set(10) == ActionResult(True)
        shown.assert_called_with("Kitchen")
        assert [c[0] for c in send.call_args_list] == [(15,), (-30,)]

    def test_the_level_shown_already_queues_nothing(self):
        core = _core()
        with patch("dial_core.shown_volume", return_value=40), patch("dial_core.enqueue_delta") as send:
            assert core.volume_set(40) == ActionResult(True)
        send.assert_not_called()

    def test_nothing_observed_yet_is_refused(self):
        core = _core()
        with patch("dial_core.shown_volume", return_value=None), patch("dial_core.enqueue_delta") as send:
            assert core.volume_set(30) == ActionResult(False, "wrong_state")
        send.assert_not_called()

    @pytest.mark.parametrize("level", [-1, 101, 5.5, "9", True, None])
    def test_a_level_outside_zero_to_one_hundred_is_refused(self, level):
        core = _core()
        with patch("dial_core.shown_volume", return_value=40), patch("dial_core.enqueue_delta") as send:
            assert core.volume_set(level) == ActionResult(False, "wrong_state")
        send.assert_not_called()

    def test_an_id_must_be_the_focused_appliance(self):
        core = _core(_entry(), _entry(BID))
        core.set_focus(AID)
        with patch("dial_core.shown_volume", return_value=40), patch("dial_core.enqueue_delta") as send:
            assert core.volume_set(50, BID) == ActionResult(False, "not_focused")
            send.assert_not_called()
            assert core.volume_set(50, AID) == ActionResult(True)
        send.assert_called_once_with(10)

    def test_an_id_with_nothing_focused_is_refused(self):
        core = _core()
        with patch("dial_core.shown_volume", return_value=40), patch("dial_core.enqueue_delta") as send:
            assert core.volume_set(50, AID) == ActionResult(False, "not_focused")
        send.assert_not_called()


class TestMuteToggle:
    def test_scope_current_flips_what_the_followed_appliance_reported(self):
        core = _core()
        core.set_mute_scope(lambda: "current")
        core.set_field("source_service_name", "Kitchen")
        with patch("dial_core.shown_muted", return_value=False) as shown, \
                patch("dial_core.enqueue_mute") as mute, \
                patch("dial_core.enqueue_mute_all") as mute_all:
            assert core.mute_toggle() == ActionResult(True)
        shown.assert_called_once_with("Kitchen")
        mute.assert_called_once_with(False)
        mute_all.assert_not_called()

    def test_scope_all_queues_one_fleet_toggle(self):
        core = _core()
        core.set_mute_scope(lambda: "all")
        with patch("dial_core.enqueue_mute") as mute, \
                patch("dial_core.enqueue_mute_all") as mute_all:
            assert core.mute_toggle() == ActionResult(True)
        mute.assert_not_called()
        mute_all.assert_called_once_with()

    def test_the_scope_is_read_on_every_press(self):
        core = _core()
        scope = ["current"]
        core.set_mute_scope(lambda: scope[0])
        with patch("dial_core.enqueue_mute") as mute, patch("dial_core.enqueue_mute_all") as mute_all:
            core.mute_toggle()
            scope[0] = "all"
            core.mute_toggle()
        assert mute.call_count == 1 and mute_all.call_count == 1

    def test_without_a_scope_it_acts_on_the_followed_appliance(self):
        core = _core()
        with patch("dial_core.enqueue_mute") as mute, patch("dial_core.enqueue_mute_all") as mute_all:
            core.mute_toggle()
        assert mute.call_count == 1
        mute_all.assert_not_called()

    def test_an_id_must_be_the_focused_appliance(self):
        core = _core(_entry(), _entry(BID))
        core.set_focus(AID)
        with patch("dial_core.enqueue_mute") as mute, patch("dial_core.enqueue_mute_all") as mute_all:
            assert core.mute_toggle(BID) == ActionResult(False, "not_focused")
            mute.assert_not_called()
            mute_all.assert_not_called()
            assert core.mute_toggle(AID) == ActionResult(True)
        assert mute.call_count == 1
