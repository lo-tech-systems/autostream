"""Ordering rules of the dial's mute observation store.

A status poll must never overwrite a mute state a press or a reply has
already established: an unknown poll value never replaces a known bool, a
poll requested before a reply was received is ignored, and poll observations
for a service are ignored while a mute request for it is outstanding (with a
bounded expiry). Replies and the optimistic echo always apply.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
if _DIAL not in sys.path:
    sys.path.insert(0, _DIAL)

import dial_volume as dv
from dial_mdns import PlayingTarget


@pytest.fixture
def clock(monkeypatch):
    """A controllable monotonic clock for dial_volume."""
    now = [1000.0]
    monkeypatch.setattr(dv, "time", SimpleNamespace(monotonic=lambda: now[0]))
    dv.observe_mute_state(None, None)
    return now


def _target(service_name: str, ip: str = "10.0.0.1") -> PlayingTarget:
    return PlayingTarget(ip=ip, port=80, name="test", dial_api=True, service_name=service_name)


def _urlopen_mute(muted: bool):
    resp = MagicMock()
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    resp.read.return_value = json.dumps({"ok": True, "muted": muted}).encode()
    return resp


class TestUnknownNeverOverwritesKnown:
    def test_unknown_poll_keeps_a_known_true(self, clock):
        dv.observe_mute_state("svc", True, requested_at=1.0)
        dv.observe_mute_state("svc", None, requested_at=2.0)
        assert dv.shown_muted("svc") is True

    def test_unknown_poll_keeps_a_known_false(self, clock):
        dv.observe_mute_state("svc", False, requested_at=1.0)
        dv.observe_mute_state("svc", None, requested_at=2.0)
        assert dv._observed_muted["svc"] is False

    def test_first_unknown_poll_creates_an_unknown_entry(self, clock):
        dv.observe_mute_state("svc", None, requested_at=1.0)
        assert "svc" in dv._observed_muted
        assert dv._observed_muted["svc"] is None
        assert dv.shown_muted("svc") is False

    def test_known_bool_poll_still_replaces_a_known_bool(self, clock):
        dv.observe_mute_state("svc", True, requested_at=1.0)
        dv.observe_mute_state("svc", False, requested_at=2.0)
        assert dv.shown_muted("svc") is False

    def test_none_service_clears_everything(self, clock):
        dv.observe_mute_state("a", True)
        dv.observe_mute_state("b", False, requested_at=1.0)
        dv._mark_mute_inflight("a")
        dv.observe_mute_state(None, None, requested_at=5.0)
        assert dv._observed_muted == {}
        assert dv._mute_settled_at == {}
        assert dv._mute_inflight == {}
        assert dv._last_observed_mute_service is None


class TestSettledTime:
    def test_poll_sent_before_a_reply_was_received_is_ignored(self, clock):
        clock[0] = 1000.0
        dv.observe_mute_state("svc", True)          # reply received at 1000
        dv.observe_mute_state("svc", False, requested_at=999.9)
        assert dv.shown_muted("svc") is True

    def test_poll_sent_after_the_reply_was_received_applies(self, clock):
        clock[0] = 1000.0
        dv.observe_mute_state("svc", True)
        dv.observe_mute_state("svc", False, requested_at=1000.0)
        assert dv.shown_muted("svc") is False

    def test_settled_time_is_the_receive_time_not_the_request_time(self, clock):
        clock[0] = 1002.5
        dv.observe_mute_state("svc", True)
        assert dv._mute_settled_at["svc"] == 1002.5

    def test_settled_time_is_per_service(self, clock):
        dv.observe_mute_state("a", True)
        dv.observe_mute_state("b", True, requested_at=1.0)
        assert dv.shown_muted("b") is True

    def test_unknown_reply_does_not_settle(self, clock):
        dv.observe_mute_state("svc", None)
        assert "svc" not in dv._mute_settled_at

    def test_reply_always_applies_over_a_newer_settled_time(self, clock):
        clock[0] = 1000.0
        dv.observe_mute_state("svc", True)
        clock[0] = 1001.0
        dv.observe_mute_state("svc", False)
        assert dv.shown_muted("svc") is False
        assert dv._mute_settled_at["svc"] == 1001.0

    def test_volume_reply_settles_through_the_same_path(self, clock):
        clock[0] = 1000.0
        resp = MagicMock()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        resp.read.return_value = json.dumps({"ok": True, "volume": 40, "muted": True}).encode()
        with patch("urllib.request.urlopen", return_value=resp):
            dv._send_one(_target("svc"), "uuid", 1, [])
        dv.observe_mute_state("svc", False, requested_at=999.0)
        assert dv.shown_muted("svc") is True


class TestEnqueueMuteEcho:
    def test_pre_press_poll_is_ignored_after_the_echo(self, clock):
        dv.observe_mute_state("svc", False)
        clock[0] = 1010.0
        dv.enqueue_mute(False)                      # press at 1010
        assert dv.shown_muted("svc") is True
        dv.observe_mute_state("svc", False, requested_at=1009.0)
        assert dv.shown_muted("svc") is True

    def test_echo_marks_the_last_observed_service_in_flight(self, clock):
        dv.observe_mute_state("svc", False)
        dv.enqueue_mute(False)
        assert "svc" in dv._mute_inflight

    def test_post_press_poll_is_ignored_while_in_flight(self, clock):
        dv.observe_mute_state("svc", False)
        clock[0] = 1010.0
        dv.enqueue_mute(False)
        clock[0] = 1010.5
        dv.observe_mute_state("svc", False, requested_at=1010.4)
        assert dv.shown_muted("svc") is True

    def test_poll_applies_once_the_reply_has_landed(self, clock):
        dv.observe_mute_state("svc", False)
        clock[0] = 1010.0
        dv.enqueue_mute(False)
        clock[0] = 1010.4
        with patch("urllib.request.urlopen", return_value=_urlopen_mute(True)):
            dv._send_one_mute(_target("svc"), "uuid", True)
        assert "svc" not in dv._mute_inflight
        clock[0] = 1011.0
        dv.observe_mute_state("svc", True, requested_at=1010.9)
        assert dv.shown_muted("svc") is True
        # A request sent before the reply was received still cannot undo it.
        dv.observe_mute_state("svc", False, requested_at=1010.3)
        assert dv.shown_muted("svc") is True

    def test_no_observed_service_marks_nothing(self, clock):
        dv.enqueue_mute(False)
        assert dv._mute_inflight == {}


class TestInflight:
    def test_poll_ignored_while_inflight(self, clock):
        dv.observe_mute_state("svc", True)
        dv._mark_mute_inflight("svc")
        clock[0] += 1.0
        dv.observe_mute_state("svc", False, requested_at=clock[0])
        assert dv.shown_muted("svc") is True

    def test_inflight_is_per_service(self, clock):
        dv.observe_mute_state("b", True)
        dv._mark_mute_inflight("a")
        dv.observe_mute_state("b", False, requested_at=clock[0])
        assert dv.shown_muted("b") is False

    def test_inflight_expires(self, clock):
        dv.observe_mute_state("svc", True)
        dv._mark_mute_inflight("svc")
        clock[0] += dv.MUTE_INFLIGHT_EXPIRY_SECONDS + 0.1
        dv.observe_mute_state("svc", False, requested_at=clock[0])
        assert dv.shown_muted("svc") is False
        assert "svc" not in dv._mute_inflight

    def test_expiry_is_above_the_send_timeout(self):
        assert dv.MUTE_INFLIGHT_EXPIRY_SECONDS > 0.6

    def test_failed_send_clears_inflight(self, clock):
        dv._mark_mute_inflight("svc")
        with patch("urllib.request.urlopen", side_effect=OSError("down")):
            dv._send_one_mute(_target("svc"), "uuid", True)
        assert "svc" not in dv._mute_inflight

    def test_ok_false_clears_inflight(self, clock):
        dv._mark_mute_inflight("svc")
        resp = _urlopen_mute(True)
        resp.read.return_value = json.dumps({"ok": False}).encode()
        with patch("urllib.request.urlopen", return_value=resp):
            dv._send_one_mute(_target("svc"), "uuid", True)
        assert "svc" not in dv._mute_inflight

    def test_reply_applies_while_inflight(self, clock):
        dv._mark_mute_inflight("svc")
        with patch("urllib.request.urlopen", return_value=_urlopen_mute(True)):
            dv._send_one_mute(_target("svc"), "uuid", True)
        assert dv.shown_muted("svc") is True

    def test_forget_prunes_the_new_stores(self, clock):
        dv.observe_mute_state("keep", True)
        dv.observe_mute_state("gone", True)
        dv._mark_mute_inflight("gone")
        dv.forget_mute_states_except({"keep"})
        assert "gone" not in dv._mute_settled_at
        assert "gone" not in dv._mute_inflight
        assert "keep" in dv._mute_settled_at


class TestMuteAll:
    def test_marks_every_target_and_clears_each_as_its_reply_lands(self, clock):
        t1, t2 = _target("d1", "10.0.0.1"), _target("d2", "10.0.0.2")
        seen = {}

        def fake_fan_out_mute(targets, uuid, muted):
            seen["inflight"] = set(dv._mute_inflight)
            seen["echo"] = {t.service_name: dv.shown_muted(t.service_name) for t in targets}
            dv._send_one_mute(t1, uuid, muted)      # d1 answers, d2 never does

        with patch.object(dv, "_fan_out_status", return_value=[False, False]), \
             patch.object(dv, "_fan_out_mute", side_effect=fake_fan_out_mute), \
             patch("urllib.request.urlopen", return_value=_urlopen_mute(True)):
            dv._dispatch_mute_all([t1, t2], "uuid")
        assert seen["inflight"] == {"d1", "d2"}
        assert seen["echo"] == {"d1": True, "d2": True}
        assert "d1" not in dv._mute_inflight
        assert "d2" in dv._mute_inflight

    def test_a_poll_for_a_marked_target_is_ignored_until_it_answers(self, clock):
        t1 = _target("d1")
        with patch.object(dv, "_fan_out_status", return_value=[False]), \
             patch.object(dv, "_fan_out_mute"):
            dv._dispatch_mute_all([t1], "uuid")
        dv.observe_mute_state("d1", False, requested_at=clock[0] + 0.1)
        assert dv.shown_muted("d1") is True

    def test_fan_out_clears_each_target_on_failure(self, clock):
        t1, t2 = _target("d1", "10.0.0.1"), _target("d2", "10.0.0.2")
        with patch.object(dv, "_fan_out_status", return_value=[False, False]), \
             patch("urllib.request.urlopen", side_effect=OSError("down")):
            dv._dispatch_mute_all([t1, t2], "uuid")
        assert dv._mute_inflight == {}


class TestStatusWithoutMuteFlag:
    """An appliance whose status never carries the flag (an earlier release)
    must not latch the highlight on from a mute reply."""

    def test_legacy_poll_after_mute_reply_clears_known_state(self, clock):
        clock[0] = 1000.0
        dv.observe_mute_state("svc", True)              # mute reply received
        clock[0] = 1001.0
        dv.observe_mute_state("svc", None, requested_at=1000.5, status_reports_mute=False)
        assert dv.shown_muted("svc") is False
        assert dv._observed_muted["svc"] is None

    def test_legacy_poll_sent_before_the_reply_is_still_ignored(self, clock):
        clock[0] = 1000.0
        dv.observe_mute_state("svc", True)
        dv.observe_mute_state("svc", None, requested_at=999.0, status_reports_mute=False)
        assert dv.shown_muted("svc") is True

    def test_legacy_poll_during_inflight_mute_is_ignored(self, clock):
        dv.observe_mute_state("svc", True)
        dv._mark_mute_inflight("svc")
        clock[0] += 1.0
        dv.observe_mute_state("svc", None, requested_at=clock[0], status_reports_mute=False)
        assert dv.shown_muted("svc") is True

    def test_legacy_poll_after_press_echo_clears_once_the_reply_landed(self, clock):
        dv.observe_mute_state("svc", False)
        clock[0] = 1010.0
        dv.enqueue_mute(False)
        clock[0] = 1010.4
        with patch("urllib.request.urlopen", return_value=_urlopen_mute(True)):
            dv._send_one_mute(_target("svc"), "uuid", True)
        assert dv.shown_muted("svc") is True
        clock[0] = 1016.0
        dv.observe_mute_state("svc", None, requested_at=1015.9, status_reports_mute=False)
        assert dv.shown_muted("svc") is False

    def test_v2_poll_without_muted_keeps_known_state(self, clock):
        clock[0] = 1000.0
        dv.observe_mute_state("svc", True)
        clock[0] = 1001.0
        dv.observe_mute_state("svc", None, requested_at=1000.5, status_reports_mute=True)
        assert dv.shown_muted("svc") is True

    def test_status_reports_mute_defaults_to_protected(self, clock):
        dv.observe_mute_state("svc", True)
        dv.observe_mute_state("svc", None, requested_at=clock[0])
        assert dv.shown_muted("svc") is True
