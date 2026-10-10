"""Priority 5 — dial_volume sender tests.

Covers: _send_one() URL/body/timeout, ok=false application failure,
403 debug-only, clamp detection, fail-count reset; _log_volume_failure()
warning on 1st and every 10th, debug in between; _fan_out() concurrent
dispatch and clamped aggregate; queue coalescing and LED flash.

Also covers the deterministic mute fan-out (_fan_out_mute/_send_one_mute) —
new coverage, not an update: the exact wire contract dial_main.py sends
against ({"dial_id", "action": "mute"|"restore"}), the "muted" field folded
back into the belief from an authoritative response, 403 debug-only, no
targets, all-targets-403, and partial fan-out failure.
"""
from __future__ import annotations

import json
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
if _DIAL not in sys.path:
    sys.path.insert(0, _DIAL)

import dial_volume as dv
from dial_mdns import PlayingTarget


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _target(ip: str = "192.168.1.10", port: int = 80, service_name: str = "") -> PlayingTarget:
    return PlayingTarget(ip=ip, port=port, name="test", dial_api=True, service_name=service_name)


def _mock_urlopen_success(volume: int = 50, ok: bool = True):
    """Return a context manager mock suitable for urllib.request.urlopen."""
    resp = MagicMock()
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    resp.read.return_value = json.dumps({"ok": ok, "volume": volume}).encode()
    return resp


def _clear_state():
    dv._fail_counts.clear()
    # Also reset the module state introduced for single-targeting/
    # optimistic-readout and the mute observation store, so a test that
    # doesn't explicitly reset them never inherits state left behind by an
    # earlier test.
    dv.observe_master_volume(None, None)
    dv.observe_mute_state(None, None)
    dv._on_readout_changed = None
    dv._mute_targets_fn = None


def _seed_mute_observation(service_name: str, muted: bool) -> None:
    """Seed the mute observation store as if an earlier response/poll had
    already reported *muted* for *service_name* — the dial keeps no belief
    of its own, only what it was last told."""
    dv.observe_mute_state(service_name, muted)


def _mock_urlopen_mute_success(muted: bool = True, ok: bool = True, extra: dict | None = None):
    body = {"ok": ok, "muted": muted}
    if extra:
        body.update(extra)
    resp = MagicMock()
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    resp.read.return_value = json.dumps(body).encode()
    return resp


# ---------------------------------------------------------------------------
# _send_one: URL, body, timeout
# ---------------------------------------------------------------------------

class TestSendOneRequestFormat:
    def setup_method(self):
        _clear_state()

    def test_sends_to_correct_url(self):
        target = _target(ip="10.0.0.5", port=7842)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append((req.full_url, timeout))
            return _mock_urlopen_success()

        clamped = []
        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            dv._send_one(target, "my-uuid", 5, clamped)

        assert captured[0][0] == "http://10.0.0.5:7842/api/dial/volume"

    def test_request_timeout_is_04(self):
        target = _target()
        captured_timeouts = []

        def fake_urlopen(req, timeout=None):
            captured_timeouts.append(timeout)
            return _mock_urlopen_success()

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            dv._send_one(target, "uuid", 3, [])

        assert captured_timeouts[0] == pytest.approx(0.4, abs=0.01)

    def test_body_contains_dial_id_and_delta(self):
        target = _target()
        captured_bodies = []

        def fake_urlopen(req, timeout=None):
            captured_bodies.append(json.loads(req.data))
            return _mock_urlopen_success()

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            dv._send_one(target, "dial-uuid-42", 7, [])

        assert captured_bodies[0]["dial_id"] == "dial-uuid-42"
        assert captured_bodies[0]["delta"] == 7

    def test_content_type_header_is_json(self):
        target = _target()
        captured_headers = []

        def fake_urlopen(req, timeout=None):
            captured_headers.append(req.get_header("Content-type"))
            return _mock_urlopen_success()

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            dv._send_one(target, "uuid", 1, [])

        assert captured_headers[0] == "application/json"

    def test_method_is_post(self):
        target = _target()
        captured_methods = []

        def fake_urlopen(req, timeout=None):
            captured_methods.append(req.get_method())
            return _mock_urlopen_success()

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            dv._send_one(target, "uuid", 1, [])

        assert captured_methods[0] == "POST"


# ---------------------------------------------------------------------------
# _send_one: application failure (ok=False)
# ---------------------------------------------------------------------------

class TestSendOneApplicationFailure:
    def setup_method(self):
        _clear_state()

    def test_ok_false_increments_fail_count(self):
        target = _target(ip="1.2.3.4")
        with patch("urllib.request.urlopen", return_value=_mock_urlopen_success(ok=False)):
            dv._send_one(target, "uuid", 1, [])

        assert dv._fail_counts.get("1.2.3.4", 0) == 1

    def test_ok_false_does_not_set_clamped(self):
        target = _target()
        clamped = []
        with patch("urllib.request.urlopen", return_value=_mock_urlopen_success(ok=False, volume=100)):
            dv._send_one(target, "uuid", 5, clamped)

        assert clamped == []


# ---------------------------------------------------------------------------
# _send_one: 403 unauthorized — debug only
# ---------------------------------------------------------------------------

class TestSendOne403:
    def setup_method(self):
        _clear_state()

    def test_403_does_not_increment_fail_count(self, caplog):
        import logging
        target = _target(ip="9.9.9.9")
        err = urllib.error.HTTPError(url="", code=403, msg="Forbidden", hdrs=None, fp=None)
        with patch("urllib.request.urlopen", side_effect=err):
            with caplog.at_level(logging.DEBUG):
                dv._send_one(target, "uuid", 1, [])

        assert dv._fail_counts.get("9.9.9.9", 0) == 0

    def test_403_logs_at_debug_not_warning(self, caplog):
        import logging
        target = _target(ip="9.9.9.9")
        err = urllib.error.HTTPError(url="", code=403, msg="Forbidden", hdrs=None, fp=None)
        with patch("urllib.request.urlopen", side_effect=err):
            with caplog.at_level(logging.DEBUG):
                dv._send_one(target, "uuid", 1, [])

        warning_msgs = [r for r in caplog.records
                        if r.levelno >= logging.WARNING and "9.9.9.9" in r.getMessage()]
        debug_msgs   = [r for r in caplog.records
                        if r.levelno == logging.DEBUG and "9.9.9.9" in r.getMessage()]
        assert not warning_msgs, "403 should not log at WARNING"
        assert debug_msgs, "403 should log at DEBUG"

    def test_412_does_not_increment_fail_count(self, caplog):
        import logging
        target = _target(ip="9.9.9.9")
        err = urllib.error.HTTPError(url="", code=412, msg="Precondition Failed", hdrs=None, fp=None)
        with patch("urllib.request.urlopen", side_effect=err):
            with caplog.at_level(logging.DEBUG):
                dv._send_one(target, "uuid", 1, [])

        assert dv._fail_counts.get("9.9.9.9", 0) == 0

    def test_412_logs_at_debug_not_warning(self, caplog):
        import logging
        target = _target(ip="9.9.9.9")
        err = urllib.error.HTTPError(url="", code=412, msg="Precondition Failed", hdrs=None, fp=None)
        with patch("urllib.request.urlopen", side_effect=err):
            with caplog.at_level(logging.DEBUG):
                dv._send_one(target, "uuid", 1, [])

        warning_msgs = [r for r in caplog.records
                        if r.levelno >= logging.WARNING and "9.9.9.9" in r.getMessage()]
        debug_msgs   = [r for r in caplog.records
                        if r.levelno == logging.DEBUG and "9.9.9.9" in r.getMessage()]
        assert not warning_msgs, "412 should not log at WARNING"
        assert debug_msgs, "412 should log at DEBUG"


# ---------------------------------------------------------------------------
# _send_one: clamp detection
# ---------------------------------------------------------------------------

class TestSendOneClamp:
    def setup_method(self):
        _clear_state()

    def test_positive_delta_at_100_sets_clamped(self):
        clamped = []
        with patch("urllib.request.urlopen", return_value=_mock_urlopen_success(volume=100)):
            dv._send_one(_target(), "uuid", 5, clamped)
        assert clamped

    def test_negative_delta_at_0_sets_clamped(self):
        clamped = []
        with patch("urllib.request.urlopen", return_value=_mock_urlopen_success(volume=0)):
            dv._send_one(_target(), "uuid", -5, clamped)
        assert clamped

    def test_positive_delta_not_at_100_does_not_set_clamped(self):
        clamped = []
        with patch("urllib.request.urlopen", return_value=_mock_urlopen_success(volume=95)):
            dv._send_one(_target(), "uuid", 5, clamped)
        assert not clamped

    def test_negative_delta_not_at_0_does_not_set_clamped(self):
        clamped = []
        with patch("urllib.request.urlopen", return_value=_mock_urlopen_success(volume=5)):
            dv._send_one(_target(), "uuid", -5, clamped)
        assert not clamped

    def test_success_clears_fail_count(self):
        ip = "5.5.5.5"
        dv._fail_counts[ip] = 3
        target = _target(ip=ip)
        with patch("urllib.request.urlopen", return_value=_mock_urlopen_success(volume=50)):
            dv._send_one(target, "uuid", 1, [])
        assert ip not in dv._fail_counts


# ---------------------------------------------------------------------------
# _log_volume_failure: rate limiting
# ---------------------------------------------------------------------------

class TestLogVolumeFailureRateLimit:
    def setup_method(self):
        _clear_state()

    def test_first_failure_logs_warning(self, caplog):
        import logging
        with caplog.at_level(logging.DEBUG):
            dv._log_volume_failure("1.1.1.1", "test error %s", "detail")
        warnings = [r for r in caplog.records
                    if r.levelno >= logging.WARNING and "1.1.1.1" in r.getMessage()]
        assert warnings, "First failure must log at WARNING"

    def test_second_failure_logs_debug(self, caplog):
        import logging
        dv._log_volume_failure("2.2.2.2", "err")  # 1st → WARNING
        caplog.clear()
        with caplog.at_level(logging.DEBUG):
            dv._log_volume_failure("2.2.2.2", "err")  # 2nd → DEBUG
        warnings = [r for r in caplog.records
                    if r.levelno >= logging.WARNING and "2.2.2.2" in r.getMessage()]
        debugs   = [r for r in caplog.records
                    if r.levelno == logging.DEBUG and "2.2.2.2" in r.getMessage()]
        assert not warnings, "2nd failure must not log at WARNING"
        assert debugs, "2nd failure must log at DEBUG"

    def test_tenth_failure_logs_warning(self, caplog):
        import logging
        ip = "3.3.3.3"
        for _ in range(9):
            dv._log_volume_failure(ip, "err")
        caplog.clear()
        with caplog.at_level(logging.DEBUG):
            dv._log_volume_failure(ip, "err")  # 10th → WARNING
        warnings = [r for r in caplog.records
                    if r.levelno >= logging.WARNING and ip in r.getMessage()]
        assert warnings, "Every 10th failure must log at WARNING"


# ---------------------------------------------------------------------------
# _fan_out: concurrent dispatch
# ---------------------------------------------------------------------------

class TestFanOut:
    def setup_method(self):
        _clear_state()

    def test_sends_to_all_targets(self):
        targets = [_target("1.0.0.1"), _target("1.0.0.2"), _target("1.0.0.3")]
        sent_to = []

        def fake_send_one(target, uuid, delta, clamped):
            sent_to.append(target.ip)

        with patch.object(dv, "_send_one", side_effect=fake_send_one):
            dv._fan_out(targets, "uuid", 2)

        assert sorted(sent_to) == ["1.0.0.1", "1.0.0.2", "1.0.0.3"]

    def test_returns_true_when_any_clamped(self):
        targets = [_target("1.0.0.1"), _target("1.0.0.2")]

        def fake_send_one(target, uuid, delta, clamped):
            if target.ip == "1.0.0.1":
                clamped.append(True)

        with patch.object(dv, "_send_one", side_effect=fake_send_one):
            result = dv._fan_out(targets, "uuid", 5)

        assert result is True

    def test_returns_false_when_no_target_clamped(self):
        targets = [_target()]

        def fake_send_one(target, uuid, delta, clamped):
            pass

        with patch.object(dv, "_send_one", side_effect=fake_send_one):
            result = dv._fan_out(targets, "uuid", 2)

        assert result is False


# ---------------------------------------------------------------------------
# Queue coalescing: one summed delta per burst, LED flash on clamp
# ---------------------------------------------------------------------------

class TestQueueCoalescing:
    def setup_method(self):
        _clear_state()
        dv._cfg = MagicMock(uuid="test-uuid")

    def test_burst_coalesced_to_one_fan_out_call(self):
        """Multiple enqueue_delta calls before the worker runs should produce
        one _fan_out call with the summed delta."""
        fan_out_calls = []

        def fake_fan_out(targets, uuid, delta):
            fan_out_calls.append(delta)
            return False

        target = _target()
        done = threading.Event()

        def fake_targets():
            return [target]

        dv._targets_fn = fake_targets
        dv._led_ref    = None

        import queue as _q
        # Pre-load three deltas into a fresh queue
        fresh_queue: _q.SimpleQueue = _q.SimpleQueue()
        fresh_queue.put(2)
        fresh_queue.put(3)
        fresh_queue.put(1)

        with patch.object(dv, "_fan_out", side_effect=fake_fan_out), \
             patch.object(dv, "_queue", fresh_queue):
            # Simulate one worker iteration
            delta = dv._queue.get()
            while True:
                try:
                    delta += dv._queue.get_nowait()
                except _q.Empty:
                    break
            dv._fan_out(fake_targets(), dv._cfg.uuid, delta)

        assert fan_out_calls == [6], f"Expected [6], got {fan_out_calls}"

    def test_led_flashed_when_clamped(self):
        """LED.flash_clamped() must be called when fan_out returns True."""
        mock_led = MagicMock()
        dv._led_ref = mock_led
        dv._targets_fn = lambda: [_target()]

        import queue as _q
        fresh_queue: _q.SimpleQueue = _q.SimpleQueue()
        fresh_queue.put(5)

        with patch.object(dv, "_fan_out", return_value=True), \
             patch.object(dv, "_queue", fresh_queue):
            delta = dv._queue.get()
            while True:
                try:
                    delta += dv._queue.get_nowait()
                except _q.Empty:
                    break
            targets = dv._targets_fn()
            clamped = dv._fan_out(targets, dv._cfg.uuid, delta)
            if clamped and dv._led_ref:
                dv._led_ref.flash_clamped()


# ---------------------------------------------------------------------------
# _send_one_mute: exact wire contract
#
# This is the one place the exact body dial_volume sends is checked against
# the exact shape the appliance-side handler parses: POST /api/dial/mute
# takes {"dial_id": ..., "action": "mute"|"restore"}. Nothing else in the
# suite exercises both sides of this protocol together.
# ---------------------------------------------------------------------------

class TestSendOneMuteRequestFormat:
    def setup_method(self):
        _clear_state()

    def test_body_matches_the_exact_wire_contract_for_mute(self):
        target = _target()
        captured_bodies = []

        def fake_urlopen(req, timeout=None):
            captured_bodies.append(json.loads(req.data))
            return _mock_urlopen_mute_success(muted=True)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            dv._send_one_mute(target, "dial-uuid-42", True)

        assert captured_bodies[0] == {"dial_id": "dial-uuid-42", "action": "mute"}

    def test_body_matches_the_exact_wire_contract_for_restore(self):
        target = _target()
        captured_bodies = []

        def fake_urlopen(req, timeout=None):
            captured_bodies.append(json.loads(req.data))
            return _mock_urlopen_mute_success(muted=False)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            dv._send_one_mute(target, "dial-uuid-42", False)

        assert captured_bodies[0] == {"dial_id": "dial-uuid-42", "action": "restore"}

    def test_sends_to_correct_url(self):
        target = _target(ip="10.0.0.6", port=7842)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req.full_url)
            return _mock_urlopen_mute_success()

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            dv._send_one_mute(target, "uuid", True)

        assert captured[0] == "http://10.0.0.6:7842/api/dial/mute"

    def test_request_timeout_is_04(self):
        target = _target()
        captured_timeouts = []

        def fake_urlopen(req, timeout=None):
            captured_timeouts.append(timeout)
            return _mock_urlopen_mute_success()

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            dv._send_one_mute(target, "uuid", True)

        assert captured_timeouts[0] == pytest.approx(0.4, abs=0.01)

    def test_content_type_header_is_json(self):
        target = _target()
        captured_headers = []

        def fake_urlopen(req, timeout=None):
            captured_headers.append(req.get_header("Content-type"))
            return _mock_urlopen_mute_success()

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            dv._send_one_mute(target, "uuid", True)

        assert captured_headers[0] == "application/json"

    def test_method_is_post(self):
        target = _target()
        captured_methods = []

        def fake_urlopen(req, timeout=None):
            captured_methods.append(req.get_method())
            return _mock_urlopen_mute_success()

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            dv._send_one_mute(target, "uuid", True)

        assert captured_methods[0] == "POST"


# ---------------------------------------------------------------------------
# _send_one_mute: free observation — the "muted" field is folded into the
# per-service observation store (dial_volume.observe_mute_state/
# shown_muted), not any dial-side belief -- the dial keeps none.
# ---------------------------------------------------------------------------

class TestSendOneMuteReconciliation:
    def setup_method(self):
        _clear_state()

    def test_authoritative_muted_true_is_observed(self):
        target = _target(service_name="svc")
        with patch("urllib.request.urlopen", return_value=_mock_urlopen_mute_success(muted=True)):
            dv._send_one_mute(target, "uuid", True)
        assert dv.shown_muted("svc") is True

    def test_authoritative_muted_false_is_observed_even_if_we_asked_to_mute(self):
        # Mute responses are authoritative and may report either state,
        # regardless of which action this dial actually sent.
        target = _target(service_name="svc")
        _seed_mute_observation("svc", True)
        with patch("urllib.request.urlopen", return_value=_mock_urlopen_mute_success(muted=False)):
            dv._send_one_mute(target, "uuid", True)
        assert dv.shown_muted("svc") is False

    def test_missing_muted_field_leaves_the_store_unchanged(self):
        target = _target(service_name="svc")
        _seed_mute_observation("svc", True)
        resp = MagicMock()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        resp.read.return_value = json.dumps({"ok": True}).encode()
        with patch("urllib.request.urlopen", return_value=resp):
            dv._send_one_mute(target, "uuid", False)
        assert dv.shown_muted("svc") is True

    def test_non_bool_muted_field_leaves_the_store_unchanged(self):
        target = _target(service_name="svc")
        _seed_mute_observation("svc", True)
        resp = MagicMock()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        resp.read.return_value = json.dumps({"ok": True, "muted": "yes"}).encode()
        with patch("urllib.request.urlopen", return_value=resp):
            dv._send_one_mute(target, "uuid", False)
        assert dv.shown_muted("svc") is True

    def test_ok_false_does_not_observe(self):
        target = _target(service_name="svc")
        _seed_mute_observation("svc", True)
        with patch("urllib.request.urlopen",
                   return_value=_mock_urlopen_mute_success(muted=False, ok=False)):
            dv._send_one_mute(target, "uuid", False)
        assert dv.shown_muted("svc") is True

    def test_partial_true_response_still_observes(self):
        """A response may carry "partial": true alongside ok/muted — that is
        purely informational and must not block the observation."""
        target = _target(service_name="svc")
        resp = _mock_urlopen_mute_success(muted=True, extra={"partial": True})
        with patch("urllib.request.urlopen", return_value=resp):
            dv._send_one_mute(target, "uuid", True)
        assert dv.shown_muted("svc") is True

    def test_a_later_observation_for_a_different_service_makes_the_earlier_one_unknown(self):
        """The store holds one reporting service at a time (see
        shown_muted()'s service-equality gate) -- a later observation for a
        different service means reading the earlier one back reports
        unknown (False), never a stale value from the wrong appliance."""
        target_a = _target(ip="6.0.0.1", service_name="svc-a")
        target_b = _target(ip="6.0.0.2", service_name="svc-b")
        with patch("urllib.request.urlopen", return_value=_mock_urlopen_mute_success(muted=True)):
            dv._send_one_mute(target_a, "uuid", True)
        with patch("urllib.request.urlopen", return_value=_mock_urlopen_mute_success(muted=False)):
            dv._send_one_mute(target_b, "uuid", False)
        assert dv.shown_muted("svc-a") is False  # unknown, not the stale True
        assert dv.shown_muted("svc-b") is False  # the actual last-reported value


# ---------------------------------------------------------------------------
# _send_one_mute: application failure and 403 (mirrors _send_one's rules)
# ---------------------------------------------------------------------------

class TestSendOneMuteFailureHandling:
    def setup_method(self):
        _clear_state()

    def test_ok_false_increments_fail_count(self):
        target = _target(ip="1.2.3.9")
        with patch("urllib.request.urlopen",
                   return_value=_mock_urlopen_mute_success(muted=True, ok=False)):
            dv._send_one_mute(target, "uuid", True)
        assert dv._fail_counts.get("1.2.3.9", 0) == 1

    def test_success_clears_fail_count(self):
        ip = "5.5.5.9"
        dv._fail_counts[ip] = 3
        target = _target(ip=ip)
        with patch("urllib.request.urlopen", return_value=_mock_urlopen_mute_success(muted=True)):
            dv._send_one_mute(target, "uuid", True)
        assert ip not in dv._fail_counts

    def test_403_does_not_increment_fail_count(self, caplog):
        import logging
        target = _target(ip="9.9.9.8")
        err = urllib.error.HTTPError(url="", code=403, msg="Forbidden", hdrs=None, fp=None)
        with patch("urllib.request.urlopen", side_effect=err):
            with caplog.at_level(logging.DEBUG):
                dv._send_one_mute(target, "uuid", True)
        assert dv._fail_counts.get("9.9.9.8", 0) == 0

    def test_403_logs_at_debug_not_warning(self, caplog):
        import logging
        target = _target(ip="9.9.9.8")
        err = urllib.error.HTTPError(url="", code=403, msg="Forbidden", hdrs=None, fp=None)
        with patch("urllib.request.urlopen", side_effect=err):
            with caplog.at_level(logging.DEBUG):
                dv._send_one_mute(target, "uuid", True)
        warning_msgs = [r for r in caplog.records
                        if r.levelno >= logging.WARNING and "9.9.9.8" in r.getMessage()]
        debug_msgs = [r for r in caplog.records
                      if r.levelno == logging.DEBUG and "9.9.9.8" in r.getMessage()]
        assert not warning_msgs, "403 should not log at WARNING"
        assert debug_msgs, "403 should log at DEBUG"

    def test_403_does_not_observe(self):
        """A 403 carries no body to fold in — the store must be untouched."""
        target = _target(service_name="svc")
        _seed_mute_observation("svc", True)
        err = urllib.error.HTTPError(url="", code=403, msg="Forbidden", hdrs=None, fp=None)
        with patch("urllib.request.urlopen", side_effect=err):
            dv._send_one_mute(target, "uuid", False)
        assert dv.shown_muted("svc") is True

    def test_412_does_not_increment_fail_count(self, caplog):
        import logging
        target = _target(ip="9.9.9.7")
        err = urllib.error.HTTPError(url="", code=412, msg="Precondition Failed", hdrs=None, fp=None)
        with patch("urllib.request.urlopen", side_effect=err):
            with caplog.at_level(logging.DEBUG):
                dv._send_one_mute(target, "uuid", True)
        assert dv._fail_counts.get("9.9.9.7", 0) == 0

    def test_412_logs_at_debug_not_warning(self, caplog):
        import logging
        target = _target(ip="9.9.9.7")
        err = urllib.error.HTTPError(url="", code=412, msg="Precondition Failed", hdrs=None, fp=None)
        with patch("urllib.request.urlopen", side_effect=err):
            with caplog.at_level(logging.DEBUG):
                dv._send_one_mute(target, "uuid", True)
        warning_msgs = [r for r in caplog.records
                        if r.levelno >= logging.WARNING and "9.9.9.7" in r.getMessage()]
        debug_msgs = [r for r in caplog.records
                      if r.levelno == logging.DEBUG and "9.9.9.7" in r.getMessage()]
        assert not warning_msgs, "412 should not log at WARNING"
        assert debug_msgs, "412 should log at DEBUG"

    def test_412_does_not_observe(self):
        """A 412 carries no body to fold in — the store must be untouched."""
        target = _target(service_name="svc")
        _seed_mute_observation("svc", True)
        err = urllib.error.HTTPError(url="", code=412, msg="Precondition Failed", hdrs=None, fp=None)
        with patch("urllib.request.urlopen", side_effect=err):
            dv._send_one_mute(target, "uuid", False)
        assert dv.shown_muted("svc") is True


# ---------------------------------------------------------------------------
# _fan_out_mute: concurrent dispatch, no targets, all-403, partial failure
# ---------------------------------------------------------------------------

class TestFanOutMute:
    def setup_method(self):
        _clear_state()

    def test_sends_to_all_targets_with_the_same_absolute_action(self):
        targets = [_target("2.0.0.1"), _target("2.0.0.2"), _target("2.0.0.3")]
        sent = []

        def fake_send_one_mute(target, uuid, muted):
            sent.append((target.ip, muted))

        with patch.object(dv, "_send_one_mute", side_effect=fake_send_one_mute):
            dv._fan_out_mute(targets, "uuid", True)

        assert sorted(sent) == [
            ("2.0.0.1", True), ("2.0.0.2", True), ("2.0.0.3", True),
        ]

    def test_no_targets_sends_nothing(self):
        """An empty target list (the no-targets case) must not attempt any
        request — mirrors _worker()'s `if not targets: continue` guard."""
        sent = []

        def fake_send_one_mute(target, uuid, muted):
            sent.append(target)

        with patch.object(dv, "_send_one_mute", side_effect=fake_send_one_mute):
            dv._fan_out_mute([], "uuid", True)

        assert sent == []

    def test_all_targets_403_leaves_the_store_unobserved(self):
        """All targets unauthorized: no target returns a body to fold in, so
        whatever the store already held survives untouched — a mixed-LAN
        403 must never look like a correction."""
        targets = [_target("3.0.0.1", service_name="svc"), _target("3.0.0.2", service_name="svc")]
        _seed_mute_observation("svc", True)
        err = urllib.error.HTTPError(url="", code=403, msg="Forbidden", hdrs=None, fp=None)

        with patch("urllib.request.urlopen", side_effect=err):
            dv._fan_out_mute(targets, "uuid", True)

        assert dv.shown_muted("svc") is True
        assert dv._fail_counts.get("3.0.0.1", 0) == 0
        assert dv._fail_counts.get("3.0.0.2", 0) == 0

    def test_partial_fan_out_failure_observes_from_the_surviving_target(self):
        """One target succeeds (and reports muted=True back), the other is
        unreachable — the store still gets the free observation from the
        one that answered, and the failing one's fail count is bumped."""
        good = _target(ip="4.0.0.1", service_name="good-svc")
        bad = _target(ip="4.0.0.2", service_name="bad-svc")

        def fake_urlopen(req, timeout=None):
            if req.full_url.startswith(f"http://{bad.ip}"):
                raise OSError("connection refused")
            return _mock_urlopen_mute_success(muted=True)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            dv._fan_out_mute([good, bad], "uuid", True)

        assert dv.shown_muted("good-svc") is True
        assert dv._fail_counts.get(bad.ip, 0) == 1
        assert dv._fail_counts.get(good.ip, 0) == 0


# ---------------------------------------------------------------------------
# enqueue_mute(): flips the caller-supplied reported state, no network I/O,
# no DialDisplay lock, no belief of its own kept anywhere in this module.
# ---------------------------------------------------------------------------

class TestEnqueueMuteAbsoluteAction:
    def setup_method(self):
        _clear_state()
        # Drain any leftover queue items from a previous test.
        while True:
            try:
                dv._queue.get_nowait()
            except Exception:
                break

    def test_reported_unmuted_flips_to_mute(self):
        new_state = dv.enqueue_mute(False)
        assert new_state is True
        assert dv._queue.get_nowait() == ("mute", True)

    def test_reported_muted_flips_to_restore(self):
        new_state = dv.enqueue_mute(True)
        assert new_state is False
        assert dv._queue.get_nowait() == ("mute", False)

    def test_enqueue_mute_performs_no_network_io(self):
        def boom(*a, **kw):
            raise AssertionError("enqueue_mute() must never touch the network")

        with patch("urllib.request.urlopen", side_effect=boom):
            dv.enqueue_mute(False)  # must not raise

    def test_enqueue_mute_echoes_into_the_observation_store(self):
        """The dial persists nothing, but a press must still repaint the
        glyph on the same frame -- the echo lives in the mute observation
        store (dial_volume._readout_muted), not any belief."""
        dv.observe_mute_state("svc", False)
        dv.enqueue_mute(False)
        assert dv.shown_muted("svc") is True

    def test_enqueue_mute_does_not_touch_which_service_the_store_reports_for(self):
        """The echo updates only the value, never the tracked service -- it
        applies to whichever service the store already associates with the
        reporting appliance."""
        dv.observe_mute_state("svc", False)
        dv.enqueue_mute(False)
        assert dv.shown_muted("other-svc") is False


# ---------------------------------------------------------------------------
# _worker(): dispatches a mute batch item through _fan_out_mute with the
# belief carried in the queue event (mirrors TestQueueCoalescing's style of
# simulating a single worker iteration rather than driving the real
# infinite-loop thread).
# ---------------------------------------------------------------------------

class TestWorkerMuteDispatch:
    def setup_method(self):
        _clear_state()
        dv._cfg = MagicMock(uuid="test-uuid")

    def test_mute_batch_item_dispatches_via_fan_out_mute(self):
        fan_out_mute_calls = []

        def fake_fan_out_mute(targets, uuid, muted):
            fan_out_mute_calls.append((uuid, muted))

        target = _target()
        dv._targets_fn = lambda: [target]

        with patch.object(dv, "_fan_out_mute", side_effect=fake_fan_out_mute):
            batch = dv._coalesce(("mute", True))
            targets = dv._targets_fn()
            for event in batch:
                if event[0] == "delta":
                    dv._fan_out(targets, dv._cfg.uuid, event[1])
                else:
                    dv._fan_out_mute(targets, dv._cfg.uuid, event[1])

        assert fan_out_mute_calls == [("test-uuid", True)]


# ---------------------------------------------------------------------------
# select_volume_target(): pure single-target selection — no I/O, no lock,
# no module state. Both dial_display's poll and the worker's resolvers call
# this so they can never disagree about who the reporting-from target is.
# ---------------------------------------------------------------------------

class TestSelectVolumeTarget:
    def test_preferred_present_is_returned_even_when_not_first(self):
        older = _target(ip="7.0.0.1", service_name="older")
        newer = _target(ip="7.0.0.2", service_name="newer")
        assert dv.select_volume_target([older, newer], "newer") is newer

    def test_preferred_absent_falls_back_to_first(self):
        older = _target(ip="7.0.0.1", service_name="older")
        newer = _target(ip="7.0.0.2", service_name="newer")
        assert dv.select_volume_target([older, newer], "vanished") is older

    def test_none_preferred_falls_back_to_first(self):
        older = _target(ip="7.0.0.1", service_name="older")
        newer = _target(ip="7.0.0.2", service_name="newer")
        assert dv.select_volume_target([older, newer], None) is older

    def test_empty_list_with_preferred_returns_none(self):
        assert dv.select_volume_target([], "anything") is None

    def test_empty_list_with_no_preferred_returns_none(self):
        assert dv.select_volume_target([], None) is None


# ---------------------------------------------------------------------------
# _worker(): per-event target resolution — a delta event resolves via
# _targets_fn(), a mute event resolves via _mute_targets_fn() (falling back
# to _targets_fn() when unset). Mirrors TestWorkerMuteDispatch's style of
# simulating a single worker iteration (see that class's docstring) rather
# than driving the real infinite-loop thread, now extended to also resolve
# per event rather than once per batch — see dial_volume._worker().
# ---------------------------------------------------------------------------

class TestWorkerTargetResolution:
    def setup_method(self):
        _clear_state()
        dv._cfg = MagicMock(uuid="test-uuid")

    def _dispatch(self, batch):
        """Reproduce _worker()'s per-event resolution branch for *batch*
        without the blocking queue.get() loop, recording which resolver's
        result reached which fan-out call."""
        fan_out_calls = []
        fan_out_mute_calls = []
        for event in batch:
            if event[0] == "delta":
                targets = dv._targets_fn()
                if not targets:
                    continue
                fan_out_calls.append((targets, event[1]))
            else:
                resolver = dv._mute_targets_fn or dv._targets_fn
                targets = resolver()
                if not targets:
                    continue
                fan_out_mute_calls.append((targets, event[1]))
        return fan_out_calls, fan_out_mute_calls

    def test_delta_event_uses_targets_fn(self):
        vol_target = _target(ip="8.0.0.1", service_name="volume-target")
        mute_target = _target(ip="8.0.0.2", service_name="mute-target")
        dv._targets_fn = lambda: [vol_target]
        dv._mute_targets_fn = lambda: [mute_target]

        fan_out_calls, fan_out_mute_calls = self._dispatch([("delta", 5)])

        assert fan_out_calls == [([vol_target], 5)]
        assert fan_out_mute_calls == []

    def test_mute_event_uses_mute_targets_fn_when_set(self):
        vol_target = _target(ip="8.0.0.1", service_name="volume-target")
        mute_target = _target(ip="8.0.0.2", service_name="mute-target")
        dv._targets_fn = lambda: [vol_target]
        dv._mute_targets_fn = lambda: [mute_target]

        fan_out_calls, fan_out_mute_calls = self._dispatch([("mute", True)])

        assert fan_out_calls == []
        assert fan_out_mute_calls == [([mute_target], True)]

    def test_mute_event_falls_back_to_targets_fn_when_mute_targets_fn_unset(self):
        vol_target = _target(ip="8.0.0.1", service_name="volume-target")
        dv._targets_fn = lambda: [vol_target]
        dv._mute_targets_fn = None

        _, fan_out_mute_calls = self._dispatch([("mute", True)])

        assert fan_out_mute_calls == [([vol_target], True)]

    def test_empty_targets_fn_result_skips_only_the_delta_event(self):
        mute_target = _target(ip="8.0.0.2", service_name="mute-target")
        dv._targets_fn = lambda: []
        dv._mute_targets_fn = lambda: [mute_target]

        fan_out_calls, fan_out_mute_calls = self._dispatch([("delta", 5), ("mute", True)])

        assert fan_out_calls == []
        assert fan_out_mute_calls == [([mute_target], True)]

    def test_empty_mute_targets_fn_result_skips_only_the_mute_event(self):
        vol_target = _target(ip="8.0.0.1", service_name="volume-target")
        dv._targets_fn = lambda: [vol_target]
        dv._mute_targets_fn = lambda: []

        fan_out_calls, fan_out_mute_calls = self._dispatch([("delta", 5), ("mute", True)])

        assert fan_out_calls == [([vol_target], 5)]
        assert fan_out_mute_calls == []


# ---------------------------------------------------------------------------
# Optimistic volume readout: observe_master_volume()/shown_volume()/
# enqueue_delta()'s pending-offset nudge.
# ---------------------------------------------------------------------------

class TestVolumeReadout:
    def setup_method(self):
        dv.observe_master_volume(None, None)
        # Drain any leftover queue items so enqueue_delta() below doesn't
        # leave the shared module queue non-empty for a later test.
        while True:
            try:
                dv._queue.get_nowait()
            except Exception:
                break

    def test_shown_volume_none_before_any_observation(self):
        assert dv.shown_volume("a") is None

    def test_shown_volume_none_for_none_service_name(self):
        dv.observe_master_volume("a", 50)
        assert dv.shown_volume(None) is None

    def test_enqueued_delta_after_observation_shows_optimistic_total(self):
        dv.observe_master_volume("a", 50)
        dv.enqueue_delta(2)
        assert dv.shown_volume("a") == 52

    def test_pending_clamps_at_100(self):
        dv.observe_master_volume("a", 95)
        dv.enqueue_delta(50)
        assert dv.shown_volume("a") == 100

    def test_pending_clamps_at_0(self):
        dv.observe_master_volume("a", 5)
        dv.enqueue_delta(-50)
        assert dv.shown_volume("a") == 0

    def test_new_observation_resets_pending(self):
        dv.observe_master_volume("a", 50)
        dv.enqueue_delta(10)
        assert dv.shown_volume("a") == 60
        dv.observe_master_volume("a", 40)  # supersedes the +10 pending above
        assert dv.shown_volume("a") == 40

    def test_shown_volume_for_a_different_target_is_none(self):
        """A stale number from another appliance must never be shown."""
        dv.observe_master_volume("a", 50)
        assert dv.shown_volume("b") is None

    def test_observation_of_none_volume_shows_none(self):
        """volume=None means the target has no selected outputs."""
        dv.observe_master_volume("a", 50)
        dv.observe_master_volume("a", None)
        assert dv.shown_volume("a") is None

    def test_observation_of_none_service_clears_the_readout_entirely(self):
        dv.observe_master_volume("a", 50)
        dv.observe_master_volume(None, None)
        assert dv.shown_volume("a") is None


# ---------------------------------------------------------------------------
# _send_one(): fast-path readout reconciliation from the volume response,
# and the on_readout_changed callback it drives.
# ---------------------------------------------------------------------------

class TestSendOneReadoutObservation:
    def setup_method(self):
        _clear_state()

    def teardown_method(self):
        dv._on_readout_changed = None

    def test_successful_response_observes_master_volume_for_the_target(self):
        target = _target(ip="9.0.0.1", service_name="svc-a")
        with patch("urllib.request.urlopen", return_value=_mock_urlopen_success(volume=42)):
            dv._send_one(target, "uuid", 2, [])
        assert dv.shown_volume("svc-a") == 42

    def test_on_readout_changed_called_after_a_successful_response(self):
        target = _target(ip="9.0.0.2", service_name="svc-b")
        called = []
        dv._on_readout_changed = lambda: called.append(True)
        with patch("urllib.request.urlopen", return_value=_mock_urlopen_success(volume=10)):
            dv._send_one(target, "uuid", 2, [])
        assert called == [True]

    def test_on_readout_changed_not_called_when_unset(self):
        target = _target(ip="9.0.0.3", service_name="svc-c")
        dv._on_readout_changed = None
        with patch("urllib.request.urlopen", return_value=_mock_urlopen_success(volume=10)):
            dv._send_one(target, "uuid", 2, [])  # must not raise

    def test_raising_on_readout_changed_does_not_break_the_send_or_the_clamp_result(self):
        """A repaint request must never break a volume send — see the
        module and _send_one() docstrings."""
        target = _target(ip="9.0.0.4", service_name="svc-d")

        def boom():
            raise RuntimeError("repaint blew up")

        dv._on_readout_changed = boom
        clamped: list = []
        with patch("urllib.request.urlopen", return_value=_mock_urlopen_success(volume=100)):
            dv._send_one(target, "uuid", 5, clamped)  # must not raise
        assert clamped == [True]
        assert dv.shown_volume("svc-d") == 100

    def test_ok_false_does_not_observe_the_readout(self):
        target = _target(ip="9.0.0.5", service_name="svc-e")
        with patch("urllib.request.urlopen", return_value=_mock_urlopen_success(volume=88, ok=False)):
            dv._send_one(target, "uuid", 2, [])
        assert dv.shown_volume("svc-e") is None
