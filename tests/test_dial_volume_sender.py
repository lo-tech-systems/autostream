"""Priority 5 — dial_volume sender tests.

Covers: _send_one() URL/body/timeout, ok=false application failure,
403 debug-only, clamp detection, fail-count reset; _log_volume_failure()
warning on 1st and every 10th, debug in between; _fan_out() concurrent
dispatch and clamped aggregate; queue coalescing and LED flash.
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

def _target(ip: str = "192.168.1.10", port: int = 80) -> PlayingTarget:
    return PlayingTarget(ip=ip, port=port, name="test", dial_api=True)


def _mock_urlopen_success(volume: int = 50, ok: bool = True):
    """Return a context manager mock suitable for urllib.request.urlopen."""
    resp = MagicMock()
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    resp.read.return_value = json.dumps({"ok": ok, "volume": volume}).encode()
    return resp


def _clear_state():
    dv._fail_counts.clear()


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

        mock_led.flash_clamped.assert_called_once()
