"""The failed start in a status reply, read by the dial core: a notice for a
start this dial asked for, a reopened PIN request, and the rules that keep
anything else (or anything old) off the screens."""
import dataclasses
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dial"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

from unittest.mock import MagicMock

import pytest

import dial_core_state as cs
from dial_core import DialCore, OutputsEffect, PollIO, StartFailureEffect
from dial_test_support import _FakeClock, _roster_entry, _status_result, _target
from dial_warning_text import WARNING_DESCRIPTORS
from dial_warnings import WarningManager, WarningStore


def _id(tag: str) -> str:
    """An appliance id of its own: the auth map is shared by every test."""
    return (tag.encode().hex() + "0" * 20)[:20]


class Appliances:
    """A dial core over one or two appliances whose status replies the test
    sets, with a clock the test moves."""

    def __init__(self, tag: str, *, idle: bool = False, second: str | None = None):
        self.clock = _FakeClock(1000.0)
        self.failures: dict = {}
        self.fetch_error = None
        self.aid = _id(tag)
        self.other = _id(second) if second else None
        ids = [self.aid] + ([self.other] if self.other else [])
        targets = [] if idle else [_target(appliance_id=self.aid, auth="authorized", name="Hall")]
        if self.other:
            targets.append(_target(name="Den", appliance_id=self.other, auth="authorized",
                                   ip="192.0.2.11", service_name="Den"))
        roster = [_roster_entry(appliance_id=i, auth="authorized", service_name=n, name=n,
                                playing=not idle) for i, n in zip(ids, ("Hall", "Den"))]
        gt = MagicMock(return_value=targets)
        io = PollIO(
            fetch_status=self._fetch, enrich=lambda targets, dial_id: [],
            fetch_artwork=lambda url, timeout: (b"x", ""), artwork_eligible=lambda url: True,
            observe_mute=lambda *a, **k: None, observe_volume=lambda *a, **k: None,
            forget_mute=lambda *a, **k: None,
        )
        self.core = DialCore(
            "dial-1", gt, lambda: roster,
            warnings=WarningManager(WARNING_DESCRIPTORS, WarningStore(None)),
            io=io, clock=self.clock,
        )
        self.core.set_polling(True)
        if idle:
            self.core.set_focus(self.aid)
            self.core.set_idle_hold(lambda focus_cleared: False)

    def _fetch(self, target, dial_id, timeout_seconds=None):
        result = _status_result(status_error=self.fetch_error, appliance_id=target.appliance_id)
        result["start_failure"] = self.failures.get(target.appliance_id)
        return result

    def fail(self, aid=None, **fields):
        body = {"seq": 1, "boot": "boot-a", "unit_id": "1002", "name": "Speaker B",
                "reason": "refused", "mine": True, "age_s": 2}
        body.update(fields)
        self.failures[aid or self.aid] = body

    def tick(self):
        self.core.poll_once()
        return self.core.snapshot()

    def request(self, state, output_id="1002", aid=None, error=None):
        """Put this dial's output request into the core, as a set would."""
        request = cs.TransportRequest(
            aid or self.aid, "output_set", self.clock.t, state, self.clock.t, error, output_id, 0,
            (True, 40) if state == "pending" else None)
        self.core._state.outputs_request = request
        return request


def test_a_failure_of_the_dials_own_raises_one_notice_once():
    a = Appliances("sf1")
    a.fail()
    snap = a.tick()
    notice = snap.start_failure
    assert notice == cs.StartFailureNotice(
        a.aid, f"{a.aid}:boot-a:1", "1002", "Speaker B", "refused", 1000.0)
    assert a.core.take_effects() == [StartFailureEffect(a.aid, notice.key, "Speaker B", "refused")]
    a.tick()
    assert a.core.take_effects() == []
    assert a.core.snapshot().start_failure == notice


def test_a_failure_another_client_asked_for_raises_nothing():
    a = Appliances("sf2")
    a.fail(mine=False)
    assert a.tick().start_failure is None
    assert a.core.take_effects() == []
    a.failures[a.aid]["mine"] = True
    assert a.tick().start_failure is None       # already handled: seen


def test_a_failure_already_old_on_the_first_reading_raises_nothing():
    a = Appliances("sf3")
    a.fail(age_s=31)
    assert a.tick().start_failure is None
    assert a.core.take_effects() == []


def test_an_idle_focused_appliances_failure_raises_the_notice():
    a = Appliances("sf4", idle=True)
    a.fail()
    snap = a.tick()
    assert snap.tick.idle_focus is True
    assert snap.start_failure is not None and snap.start_failure.appliance_id == a.aid


def test_a_wrong_pin_raises_nothing():
    a = Appliances("sf5")
    a.request("accepted")
    a.fail(reason="pin_invalid")
    assert a.tick().start_failure is None
    assert a.core.take_effects() == []
    assert a.core.snapshot().outputs_request.state == "accepted"


@pytest.mark.parametrize("output_id", ["1002", "tv-group-9"])
def test_a_late_pin_request_reopens_the_request(output_id):
    a = Appliances("sf6")
    request = a.request("accepted", output_id=output_id)
    a.clock.t += 5.0
    a.fail(reason="pin_required", unit_id=output_id)
    snap = a.tick()
    held = snap.outputs_request
    assert (held.state, held.error, held.changed_at) == ("rejected", "pin_required", 1005.0)
    assert (held.requested_at, held.output_id) == (request.requested_at, output_id)
    assert cs.awaiting_pin(held, 1005.0)
    assert snap.start_failure is None
    assert a.core.take_effects() == [
        OutputsEffect(a.aid, output_id, "output_set", "rejected", "pin_required",
                      request.requested_at, True)]


def test_a_pin_request_waits_for_the_pending_reply_then_reopens():
    a = Appliances("sf7")
    a.request("pending")
    a.fail(reason="pin_required")
    snap = a.tick()
    assert snap.outputs_request.state == "pending"
    assert a.core.take_effects() == []
    a.request("accepted")
    snap = a.tick()
    assert snap.outputs_request.state == "rejected" and snap.outputs_request.error == "pin_required"
    assert len(a.core.take_effects()) == 1


def test_a_pin_request_for_another_speaker_does_nothing():
    a = Appliances("sf8")
    a.request("accepted", output_id="9")
    a.fail(reason="pin_required")
    assert a.tick().outputs_request.state == "accepted"
    assert a.core.take_effects() == []


def test_a_pin_request_the_reply_already_asked_does_nothing():
    a = Appliances("sf8b")
    before = a.request("rejected", error="pin_required")
    a.fail(reason="pin_required")
    assert a.tick().outputs_request == before
    assert a.core.take_effects() == []


def test_a_pin_request_nobody_here_asked_for_does_nothing():
    a = Appliances("sf9")
    a.request("accepted")
    a.fail(reason="pin_required", mine=False)
    assert a.tick().outputs_request.state == "accepted"
    assert a.core.take_effects() == []


def test_a_pin_request_read_from_an_appliance_the_dial_is_not_focused_on():
    a = Appliances("sf10", second="sf10b")
    a.request("accepted", aid=a.other)
    a.fail(a.other, reason="pin_required")
    snap = a.tick()
    assert snap.focus.manual_id is None and snap.focus.reporting_id == a.aid
    assert snap.outputs_request.state == "rejected" and snap.outputs_request.error == "pin_required"
    assert snap.start_failure is None


def test_dismissing_clears_the_notice_and_a_wrong_key_leaves_it():
    a = Appliances("sf11")
    a.fail()
    notice = a.tick().start_failure
    assert a.core.dismiss_start_failure("other").accepted
    assert a.core.snapshot().start_failure == notice
    assert a.core.dismiss_start_failure(notice.key).accepted
    assert a.core.snapshot().start_failure is None
    assert a.core.dismiss_start_failure(notice.key).accepted


def test_housekeeping_drops_a_notice_after_the_hold():
    a = Appliances("sf12")
    a.fail()
    a.tick()
    a.clock.t += cs.START_FAILURE_HOLD_S - 1
    a.core._expire_start_failure(a.clock.t)
    assert a.core.snapshot().start_failure is not None
    a.clock.t += 1
    a.core._expire_start_failure(a.clock.t)
    assert a.core.snapshot().start_failure is None


def test_a_new_boot_with_seq_one_raises_again():
    a = Appliances("sf13")
    a.fail(seq=7)
    assert a.tick().start_failure.key.endswith(":boot-a:7")
    a.fail(seq=1, boot="boot-b")
    assert a.tick().start_failure.key.endswith(":boot-b:1")


def test_a_later_failure_replaces_the_notice():
    a = Appliances("sf14")
    a.fail(seq=1)
    a.tick()
    a.fail(seq=2, name="Speaker C")
    assert a.tick().start_failure.name == "Speaker C"


def test_the_notice_is_logged_once(caplog):
    a = Appliances("sf15")
    a.fail()
    with caplog.at_level(logging.INFO):
        a.tick()
        a.tick()
    lines = [r.getMessage() for r in caplog.records if "could not start" in r.getMessage()]
    assert lines == ["dial core: Hall could not start Speaker B (refused)"]


def test_a_failed_status_read_changes_nothing():
    a = Appliances("sf16")
    a.fail()
    a.fetch_error = "timeout"
    assert a.tick().start_failure is None
    assert a.core._state.start_failure_seen == {}


def test_the_private_field_is_not_published():
    names = {f.name for f in dataclasses.fields(cs.CoreSnapshot)}
    assert "start_failure" in names and "start_failure_seen" not in names


def test_an_outputs_effect_built_positionally_is_not_late():
    assert OutputsEffect("a", "1", "output_set", "accepted", None, 1.0).late is False
