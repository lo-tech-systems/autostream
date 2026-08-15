"""Priority 5 — dial_http_server handler tests.

Covers: malformed body, field boundaries, PIN rate-limiting, recovery window,
save failure, timer rollback, name re-announce, update check/apply endpoints,
RecoveryWindow state machine, and startup timer reconciliation.
"""
from __future__ import annotations

import copy
import io
import json
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
if _DIAL not in sys.path:
    sys.path.insert(0, _DIAL)

import dial_http_server as dhs
from dial_config import DEFAULT_PROFILE_KEY, DEFAULT_TOUCH_KEY, DialConfig, DialDisplayConfig
from dial_http_server import DialHTTPServer, NoOpDisplayStatusProvider, RecoveryWindow


# ---------------------------------------------------------------------------
# Handler factory
# ---------------------------------------------------------------------------

class FakeDialServer:
    """Minimal stand-in for DialHTTPServer used to build and exercise the handler."""

    def __init__(self, cfg: DialConfig) -> None:
        self._cfg           = cfg
        self._cfg_lock      = threading.Lock()
        self._display_status = NoOpDisplayStatusProvider()
        self._display_status.update_config(cfg.display)
        self._recovery_window = MagicMock(spec=RecoveryWindow)
        self._recovery_window._active           = False
        self._recovery_window._volume_confirmed = False
        self._recovery_window._recovery_remaining_ms = 0
        rw = self._recovery_window
        rw.snapshot.side_effect = lambda: {
            "active": rw._active,
            "volume_confirmed": rw._volume_confirmed,
            "recovery_remaining_ms": rw._recovery_remaining_ms,
        }
        self._can_confirm_presence = False
        self._announce_calls: list = []

    def update_cfg(self, new_cfg: DialConfig) -> None:
        self._cfg = new_cfg

    def _on_announce(self, add: bool) -> None:
        self._announce_calls.append(add)

    @property
    def step_percent(self) -> int:
        return self._cfg.step_percent

    def _make_handler(self):
        return dhs.DialHTTPServer._make_handler(self)


def _make_handler_cls(cfg: DialConfig | None = None) -> tuple:
    """Return (handler_class, fake_server)."""
    if cfg is None:
        cfg = DialConfig(uuid="test-uuid")
    server = FakeDialServer(cfg)
    dhs._pin_attempts.clear()
    return server._make_handler(), server


def _call_handler(
    path: str,
    method: str = "POST",
    body: dict | bytes | None = None,
    cfg: DialConfig | None = None,
    setup_server: "FakeDialServer | None" = None,
) -> dict:
    """Build a handler instance, invoke it, and return status/data/server."""
    handler_cls, server = (_make_handler_cls(cfg)
                           if setup_server is None else
                           (setup_server._make_handler(), setup_server))

    if isinstance(body, dict):
        body_bytes = json.dumps(body).encode()
    elif body is None:
        body_bytes = b"{}"
    else:
        body_bytes = body

    h = object.__new__(handler_cls)
    h.path           = path
    h.rfile          = io.BytesIO(body_bytes)
    h.client_address = ("127.0.0.1", 1234)
    h.headers        = {"Content-Length": str(len(body_bytes))}

    result: dict = {}
    save_calls:  list = []

    def _send_json(status, data):
        result["status"] = status
        result["data"]   = data

    def _send_429(wait_secs):
        result["status"] = 429
        result["data"]   = {"ok": False, "error": "too_many_attempts"}

    def _send_error(code, *_a):
        result["status"] = code
        result["data"]   = {"ok": False, "error": f"http_{code}"}

    h._send_json  = _send_json
    h._send_429   = _send_429
    h.send_error  = _send_error

    with patch("dial_config.save_config",
               side_effect=lambda c: save_calls.append(copy.copy(c))):
        if method == "GET":
            h.do_GET()
        elif method == "POST":
            h.do_POST()
        else:
            h._handle_configure()

    result["save_calls"] = save_calls
    result["server"]     = server
    return result


# ---------------------------------------------------------------------------
# Malformed body
# ---------------------------------------------------------------------------

class TestMalformedBody:
    def test_invalid_content_length_returns_400(self):
        handler_cls, _ = _make_handler_cls()
        h = object.__new__(handler_cls)
        h.path           = "/configure"
        h.rfile          = io.BytesIO(b"{}")
        h.client_address = ("127.0.0.1", 1)
        h.headers        = {"Content-Length": "not-a-number"}
        result = {}

        def _capture(code, *_):
            result["status"] = code
        h.send_error = _capture
        h._send_json = lambda s, d: result.update(status=s, data=d)
        h._handle_configure()
        assert result["status"] == 400

    def test_oversized_body_returns_413(self):
        handler_cls, _ = _make_handler_cls()
        h = object.__new__(handler_cls)
        h.path           = "/configure"
        h.rfile          = io.BytesIO(b"x")
        h.client_address = ("127.0.0.1", 1)
        h.headers        = {"Content-Length": str(dhs.MAX_BODY + 1)}
        result = {}
        h.send_error = lambda code, *_: result.update(status=code)
        h._send_json = lambda s, d: result.update(status=s, data=d)
        h._handle_configure()
        assert result["status"] == 413

    def test_invalid_json_returns_400_invalid_json(self):
        r = _call_handler("/configure", body=b"not-json")
        assert r["status"] == 400
        assert r["data"]["error"] == "invalid_json"

    def test_non_object_json_returns_400(self):
        r = _call_handler("/configure", body=b"[1,2,3]")
        assert r["status"] == 400
        assert r["data"]["error"] == "body_must_be_object"


# ---------------------------------------------------------------------------
# Field validation: boundaries
# ---------------------------------------------------------------------------

class TestFieldBoundaries:
    def test_name_too_long_rejected(self):
        r = _call_handler("/configure", body={"name": "x" * 65})
        assert r["status"] == 400
        assert r["data"]["error"] == "invalid_name"

    def test_name_max_length_accepted(self):
        r = _call_handler("/configure", body={"name": "x" * 64})
        assert r["status"] == 200

    def test_name_with_pipe_char_rejected(self):
        r = _call_handler("/configure", body={"name": "bad|name"})
        assert r["status"] == 400

    def test_name_with_semicolon_rejected(self):
        r = _call_handler("/configure", body={"name": "a;b"})
        assert r["status"] == 400

    def test_step_percent_zero_rejected(self):
        r = _call_handler("/configure", body={"step_percent": 0})
        assert r["status"] == 400
        assert r["data"]["error"] == "invalid_step_percent"

    def test_step_percent_11_rejected(self):
        r = _call_handler("/configure", body={"step_percent": 11})
        assert r["status"] == 400

    def test_step_percent_10_accepted(self):
        r = _call_handler("/configure", body={"step_percent": 10})
        assert r["status"] == 200

    def test_step_percent_1_accepted(self):
        r = _call_handler("/configure", body={"step_percent": 1})
        assert r["status"] == 200

    def test_step_percent_bool_rejected(self):
        # True is a bool, not an int for this field (bool is subclass of int — explicit trap)
        r = _call_handler("/configure", body={"step_percent": True})
        assert r["status"] == 400
        assert r["data"]["error"] == "invalid_step_percent"

    def test_auto_update_non_bool_rejected(self):
        r = _call_handler("/configure", body={"auto_update": 1})
        assert r["status"] == 400
        assert r["data"]["error"] == "invalid_auto_update"

    def test_auto_update_true_accepted(self):
        with patch("subprocess.run", return_value=MagicMock(returncode=0)):
            r = _call_handler("/configure", body={"auto_update": True})
        assert r["status"] == 200

    def test_new_pin_too_short_rejected(self):
        r = _call_handler("/configure", body={"new_pin": "123"})
        assert r["status"] == 400
        assert r["data"]["error"] == "invalid_new_pin"

    def test_new_pin_non_digits_rejected(self):
        r = _call_handler("/configure", body={"new_pin": "abcd"})
        assert r["status"] == 400

    def test_new_pin_4_digits_accepted(self):
        r = _call_handler("/configure", body={"new_pin": "1234"})
        assert r["status"] == 200
        assert r["save_calls"][0].pin == "1234"

    def test_new_pin_empty_string_clears_pin(self):
        cfg = DialConfig(uuid="x", pin="old")
        # No current_pin needed to clear when using recovery_window
        # Clear without PIN protection (no current PIN guarding empty_pin)
        cfg2 = DialConfig(uuid="x", pin="")  # no existing PIN
        r = _call_handler("/configure", body={"new_pin": ""}, cfg=cfg2)
        assert r["status"] == 200
        assert r["save_calls"][0].pin == ""

    def test_update_channel_unknown_rejected(self):
        r = _call_handler("/configure", body={"update_channel": "beta"})
        assert r["status"] == 400
        assert r["data"]["error"] == "invalid_update_channel"

    def test_update_channel_stable_accepted(self):
        r = _call_handler("/configure", body={"update_channel": "stable"})
        assert r["status"] == 200

    def test_update_channel_dev_accepted(self):
        r = _call_handler("/configure", body={"update_channel": "dev"})
        assert r["status"] == 200

    def test_update_channel_integer_rejected(self):
        r = _call_handler("/configure", body={"update_channel": 1})
        assert r["status"] == 400


# ---------------------------------------------------------------------------
# PIN auth and rate limiting
# ---------------------------------------------------------------------------

class TestPINAuth:
    def setup_method(self):
        dhs._pin_attempts.clear()

    def test_protected_field_no_pin_sent_returns_403(self):
        cfg = DialConfig(uuid="x", pin="9999")
        r = _call_handler("/configure", body={"name": "New Name"}, cfg=cfg)
        assert r["status"] == 403
        assert r["data"]["error"] == "wrong_pin"

    def test_wrong_pin_returns_403(self):
        cfg = DialConfig(uuid="x", pin="9999")
        r = _call_handler("/configure",
                          body={"name": "New", "current_pin": "0000"}, cfg=cfg)
        assert r["status"] == 403
        assert r["data"]["error"] == "wrong_pin"

    def test_correct_pin_allows_change(self):
        cfg = DialConfig(uuid="x", pin="9999")
        r = _call_handler("/configure",
                          body={"name": "New", "current_pin": "9999"}, cfg=cfg)
        assert r["status"] == 200

    def test_correct_pin_clears_fail_count(self):
        cfg = DialConfig(uuid="x", pin="1234")
        # Record some failures first
        dhs._pin_attempts["127.0.0.1"] = (3, 0.0)
        r = _call_handler("/configure",
                          body={"name": "X", "current_pin": "1234"}, cfg=cfg)
        assert r["status"] == 200
        assert "127.0.0.1" not in dhs._pin_attempts

    def test_five_failures_trigger_rate_limit(self):
        cfg = DialConfig(uuid="x", pin="1234")
        # Re-use the same server so _pin_attempts accumulate across calls
        server = FakeDialServer(cfg)
        for _ in range(dhs._PIN_MAX_ATTEMPTS):
            _call_handler("/configure",
                          body={"name": "X", "current_pin": "wrong"},
                          setup_server=server)
        # After PIN_MAX_ATTEMPTS failures the next call should be rate-limited
        r = _call_handler("/configure",
                          body={"name": "X", "current_pin": "wrong"},
                          setup_server=server)
        assert r["status"] == 429
        assert r["data"]["error"] == "too_many_attempts"

    def test_no_pin_set_does_not_require_auth(self):
        cfg = DialConfig(uuid="x", pin="")
        r = _call_handler("/configure", body={"name": "Freely"}, cfg=cfg)
        assert r["status"] == 200


# ---------------------------------------------------------------------------
# PIN recovery via recovery window
# ---------------------------------------------------------------------------

class TestPINRecovery:
    def setup_method(self):
        dhs._pin_attempts.clear()

    def test_recovery_not_confirmed_returns_403(self):
        cfg = DialConfig(uuid="x", pin="9999")
        server = FakeDialServer(cfg)
        server._recovery_window._active           = True
        server._recovery_window._volume_confirmed = False
        r = _call_handler(
            "/configure",
            body={"pin_recovery": True, "new_pin": "1234", "name": "X"},
            setup_server=server,
        )
        assert r["status"] == 403
        assert r["data"]["error"] == "recovery_not_confirmed"

    def test_recovery_window_not_active_returns_403(self):
        cfg = DialConfig(uuid="x", pin="9999")
        server = FakeDialServer(cfg)
        server._recovery_window._active           = False
        server._recovery_window._volume_confirmed = True
        r = _call_handler(
            "/configure",
            body={"pin_recovery": True, "new_pin": "1234", "name": "X"},
            setup_server=server,
        )
        assert r["status"] == 403

    def test_recovery_no_new_pin_returns_400(self):
        cfg = DialConfig(uuid="x", pin="9999")
        server = FakeDialServer(cfg)
        server._recovery_window._active           = True
        server._recovery_window._volume_confirmed = True
        r = _call_handler(
            "/configure",
            body={"pin_recovery": True, "name": "X"},  # missing new_pin
            setup_server=server,
        )
        assert r["status"] == 400
        assert r["data"]["error"] == "new_pin_required_for_recovery"

    def test_recovery_invalid_new_pin_returns_400(self):
        cfg = DialConfig(uuid="x", pin="9999")
        server = FakeDialServer(cfg)
        server._recovery_window._active           = True
        server._recovery_window._volume_confirmed = True
        r = _call_handler(
            "/configure",
            body={"pin_recovery": True, "new_pin": "abc"},
            setup_server=server,
        )
        assert r["status"] == 400

    def test_successful_recovery_calls_window_complete(self):
        cfg = DialConfig(uuid="x", pin="9999")
        server = FakeDialServer(cfg)
        server._recovery_window._active           = True
        server._recovery_window._volume_confirmed = True
        r = _call_handler(
            "/configure",
            body={"pin_recovery": True, "new_pin": "5678"},
            setup_server=server,
        )
        assert r["status"] == 200
        server._recovery_window.complete.assert_called_once()


# ---------------------------------------------------------------------------
# Save failure and timer rollback
# ---------------------------------------------------------------------------

class TestSaveAndRollback:
    def test_save_failure_leaves_live_config_unchanged(self):
        cfg = DialConfig(uuid="x", name="Original", step_percent=2)
        server = FakeDialServer(cfg)

        result: dict = {}
        handler_cls = server._make_handler()
        body_bytes = json.dumps({"name": "Changed"}).encode()
        h = object.__new__(handler_cls)
        h.path           = "/configure"
        h.rfile          = io.BytesIO(body_bytes)
        h.client_address = ("127.0.0.1", 1)
        h.headers        = {"Content-Length": str(len(body_bytes))}
        h._send_json  = lambda s, d: result.update(status=s, data=d)
        h.send_error  = lambda c, *_: result.update(status=c)
        h._send_429   = lambda w: result.update(status=429)

        with patch("dial_config.save_config", side_effect=OSError("disk full")):
            h._handle_configure()

        assert result["status"] == 500
        assert server._cfg.name == "Original"

    def test_timer_failure_rolls_back_auto_update(self):
        """If toggle-dial-update-timer fails, the live and saved config must be rolled back."""
        cfg = DialConfig(uuid="x", auto_update=False)
        result: dict = {}
        rollback_saves: list = []
        server = FakeDialServer(cfg)
        handler_cls = server._make_handler()
        body_bytes = json.dumps({"auto_update": True}).encode()
        h = object.__new__(handler_cls)
        h.path           = "/configure"
        h.rfile          = io.BytesIO(body_bytes)
        h.client_address = ("127.0.0.1", 1)
        h.headers        = {"Content-Length": str(len(body_bytes))}
        h._send_json  = lambda s, d: result.update(status=s, data=d)
        h.send_error  = lambda c, *_: result.update(status=c)
        h._send_429   = lambda w: result.update(status=429)

        real_save_calls = []

        def fake_save(c):
            real_save_calls.append(copy.copy(c))

        mock_run = MagicMock(returncode=1, stderr=b"")
        with patch("dial_config.save_config", side_effect=fake_save), \
             patch("subprocess.run", return_value=mock_run):
            h._handle_configure()

        # Final live config must have auto_update rolled back to original value
        assert server._cfg.auto_update is False
        # The rollback must have called save_config with the original value
        assert any(not s.auto_update for s in real_save_calls), \
            "Expected a rollback save with auto_update=False"

    def test_timer_failure_response_is_ok_false(self):
        cfg = DialConfig(uuid="x", auto_update=False)
        result: dict = {}
        server = FakeDialServer(cfg)
        handler_cls = server._make_handler()
        body_bytes = json.dumps({"auto_update": True}).encode()
        h = object.__new__(handler_cls)
        h.path           = "/configure"
        h.rfile          = io.BytesIO(body_bytes)
        h.client_address = ("127.0.0.1", 1)
        h.headers        = {"Content-Length": str(len(body_bytes))}
        h._send_json  = lambda s, d: result.update(status=s, data=d)
        h.send_error  = lambda c, *_: result.update(status=c)
        h._send_429   = lambda w: result.update(status=429)

        mock_run = MagicMock(returncode=1, stderr=b"")
        with patch("dial_config.save_config"), \
             patch("subprocess.run", return_value=mock_run):
            h._handle_configure()

        assert result["data"]["ok"] is False
        assert result["data"]["error"] == "timer_command_failed"


# ---------------------------------------------------------------------------
# Name re-announce only after successful save
# ---------------------------------------------------------------------------

class TestNameReannounce:
    def test_name_change_triggers_announce(self):
        cfg = DialConfig(uuid="x", name="Old")
        server = FakeDialServer(cfg)
        with patch("dial_config.save_config"):
            r = _call_handler("/configure",
                              body={"name": "New"},
                              setup_server=server)
        assert r["status"] == 200
        assert server._announce_calls, "Expected _on_announce call after name change"

    def test_no_name_change_no_announce(self):
        cfg = DialConfig(uuid="x", name="Same")
        server = FakeDialServer(cfg)
        with patch("dial_config.save_config"):
            r = _call_handler("/configure",
                              body={"step_percent": 4},
                              setup_server=server)
        assert r["status"] == 200
        assert not server._announce_calls, "Expected no _on_announce without name change"

    def test_save_failure_prevents_announce(self):
        cfg = DialConfig(uuid="x", name="Old")
        server = FakeDialServer(cfg)
        result: dict = {}
        handler_cls = server._make_handler()
        body_bytes = json.dumps({"name": "New"}).encode()
        h = object.__new__(handler_cls)
        h.path           = "/configure"
        h.rfile          = io.BytesIO(body_bytes)
        h.client_address = ("127.0.0.1", 1)
        h.headers        = {"Content-Length": str(len(body_bytes))}
        h._send_json  = lambda s, d: result.update(status=s, data=d)
        h.send_error  = lambda c, *_: result.update(status=c)
        h._send_429   = lambda w: result.update(status=429)

        with patch("dial_config.save_config", side_effect=OSError("disk full")):
            h._handle_configure()

        assert not server._announce_calls, "Must not announce when save fails"


# ---------------------------------------------------------------------------
# Update check and apply endpoints
# ---------------------------------------------------------------------------

class TestUpdateEndpoints:
    def test_update_check_returns_subprocess_stdout(self):
        result = {}
        handler_cls, _ = _make_handler_cls()
        h = object.__new__(handler_cls)
        h.path           = "/update/check"
        h.client_address = ("127.0.0.1", 1)
        h._send_json     = lambda s, d: result.update(status=s, data=d)

        mock_run = MagicMock(returncode=0,
                             stdout=json.dumps({"ok": True, "tag": "v1.2.3"}))
        with patch("subprocess.run", return_value=mock_run):
            h._handle_update_check()

        assert result["status"] == 200
        assert result["data"]["ok"] is True
        assert result["data"]["tag"] == "v1.2.3"

    def test_update_check_nonzero_returns_ok_false(self):
        result = {}
        handler_cls, _ = _make_handler_cls()
        h = object.__new__(handler_cls)
        h.path           = "/update/check"
        h.client_address = ("127.0.0.1", 1)
        h._send_json     = lambda s, d: result.update(status=s, data=d)

        mock_run = MagicMock(returncode=1, stdout="")
        with patch("subprocess.run", return_value=mock_run):
            h._handle_update_check()

        assert result["data"]["ok"] is False

    def test_update_check_exception_returns_ok_false(self):
        result = {}
        handler_cls, _ = _make_handler_cls()
        h = object.__new__(handler_cls)
        h.path           = "/update/check"
        h.client_address = ("127.0.0.1", 1)
        h._send_json     = lambda s, d: result.update(status=s, data=d)

        with patch("subprocess.run", side_effect=OSError("timeout")):
            h._handle_update_check()

        assert result["data"]["ok"] is False

    def test_update_check_malformed_stdout_returns_ok_false(self):
        result = {}
        handler_cls, _ = _make_handler_cls()
        h = object.__new__(handler_cls)
        h.path           = "/update/check"
        h.client_address = ("127.0.0.1", 1)
        h._send_json     = lambda s, d: result.update(status=s, data=d)

        mock_run = MagicMock(returncode=0, stdout="not-json")
        with patch("subprocess.run", return_value=mock_run):
            h._handle_update_check()

        assert result["data"]["ok"] is False

    def test_update_apply_scheduler_failure_returns_ok_false(self):
        mock_run = MagicMock(returncode=1)
        result = {}
        handler_cls, _ = _make_handler_cls()
        h = object.__new__(handler_cls)
        h.path           = "/update"
        h.rfile          = io.BytesIO(b"")
        h.client_address = ("127.0.0.1", 1)
        h.headers        = {"Content-Length": "0"}
        h._send_json  = lambda s, d: result.update(status=s, data=d)
        h.send_error  = lambda c, *_: result.update(status=c)

        with patch("subprocess.run", return_value=mock_run):
            h._handle_update()

        assert result["data"]["ok"] is False
        assert result["data"]["error"] == "scheduler_failed"

    def test_update_apply_success_returns_ok_true(self):
        result = {}
        handler_cls, _ = _make_handler_cls()
        h = object.__new__(handler_cls)
        h.path           = "/update"
        h.rfile          = io.BytesIO(b"")
        h.client_address = ("127.0.0.1", 1)
        h.headers        = {"Content-Length": "0"}
        h._send_json  = lambda s, d: result.update(status=s, data=d)
        h.send_error  = lambda c, *_: result.update(status=c)

        with patch("subprocess.run", return_value=MagicMock(returncode=0)):
            h._handle_update()

        assert result["data"]["ok"] is True


# ---------------------------------------------------------------------------
# RecoveryWindow state machine
# ---------------------------------------------------------------------------

class TestRecoveryWindowStateMachine:
    def _make(self):
        announce_calls = []
        rw = RecoveryWindow(on_announce=lambda add: announce_calls.append(add))
        return rw, announce_calls

    def test_open_sets_active_and_announces_true(self):
        rw, calls = self._make()
        with patch("threading.Timer") as mock_timer_cls:
            mock_timer_cls.return_value = MagicMock()
            rw.open()
        assert rw._active is True
        assert calls == [True]

    def test_expire_clears_active_and_announces_false(self):
        rw, calls = self._make()
        with patch("threading.Timer") as mock_timer_cls:
            mock_timer_cls.return_value = MagicMock()
            rw.open()
        calls.clear()
        rw._expire()
        assert rw._active is False
        assert calls == [False]

    def test_complete_cancels_timer_and_announces_false(self):
        rw, calls = self._make()
        mock_timer = MagicMock()
        with patch("threading.Timer", return_value=mock_timer):
            rw.open()
        calls.clear()
        rw.complete()
        mock_timer.cancel.assert_called_once()
        assert rw._active is False
        assert calls == [False]

    def test_confirm_volume_sets_flag_only_when_active(self):
        rw, _ = self._make()
        rw.confirm_volume()  # not active — should be noop
        assert rw._volume_confirmed is False

        with patch("threading.Timer") as mock_timer_cls:
            mock_timer_cls.return_value = MagicMock()
            rw.open()
        rw.confirm_volume()
        assert rw._volume_confirmed is True

    def test_confirm_volume_noop_if_already_confirmed(self):
        rw, _ = self._make()
        with patch("threading.Timer") as mock_timer_cls:
            mock_timer_cls.return_value = MagicMock()
            rw.open()
        rw.confirm_volume()
        rw.confirm_volume()
        assert rw._volume_confirmed is True

    def test_open_replaces_running_timer(self):
        rw, _ = self._make()
        timer1 = MagicMock()
        timer2 = MagicMock()
        with patch("threading.Timer", side_effect=[timer1, timer2]):
            rw.open()
            rw.open()
        timer1.cancel.assert_not_called()  # open() doesn't cancel previous timer explicitly
        assert rw._timer is timer2

    def test_snapshot_remaining_ms_zero_when_inactive(self):
        rw, _ = self._make()
        snap = rw.snapshot()
        assert snap["recovery_remaining_ms"] == 0

    def test_snapshot_remaining_ms_near_full_window_just_after_open(self):
        rw, _ = self._make()
        with patch("threading.Timer") as mock_timer_cls:
            mock_timer_cls.return_value = MagicMock()
            rw.open()
        snap = rw.snapshot()
        assert 0 < snap["recovery_remaining_ms"] <= 600_000

    def test_snapshot_remaining_ms_decreases_over_time(self):
        rw, _ = self._make()
        with patch("threading.Timer") as mock_timer_cls, \
             patch("time.monotonic", return_value=1000.0):
            mock_timer_cls.return_value = MagicMock()
            rw.open()
        with patch("time.monotonic", return_value=1005.0):  # 5s later
            snap = rw.snapshot()
        assert snap["recovery_remaining_ms"] == 595_000

    def test_snapshot_remaining_ms_clamps_at_zero_past_the_window(self):
        rw, _ = self._make()
        with patch("threading.Timer") as mock_timer_cls, \
             patch("time.monotonic", return_value=1000.0):
            mock_timer_cls.return_value = MagicMock()
            rw.open()
        with patch("time.monotonic", return_value=1000.0 + 3600):  # 1hr later
            snap = rw.snapshot()
        assert snap["recovery_remaining_ms"] == 0

    def test_snapshot_remaining_ms_zero_after_complete(self):
        rw, _ = self._make()
        with patch("threading.Timer") as mock_timer_cls:
            mock_timer_cls.return_value = MagicMock()
            rw.open()
        rw.complete()
        assert rw.snapshot()["recovery_remaining_ms"] == 0


# ---------------------------------------------------------------------------
# Startup timer reconciliation (_reconcile_update_timer)
# ---------------------------------------------------------------------------

class TestReconcileUpdateTimer:
    def test_auto_update_true_sends_enable_verb(self):
        import dial_main
        run_cmds = []
        with patch("subprocess.run",
                   side_effect=lambda cmd, **_: run_cmds.append(cmd) or MagicMock(returncode=0)):
            dial_main._reconcile_update_timer(True)
        assert any("enable" in cmd for cmd in run_cmds), f"Expected 'enable' in {run_cmds}"

    def test_auto_update_false_sends_disable_verb(self):
        import dial_main
        run_cmds = []
        with patch("subprocess.run",
                   side_effect=lambda cmd, **_: run_cmds.append(cmd) or MagicMock(returncode=0)):
            dial_main._reconcile_update_timer(False)
        assert any("disable" in cmd for cmd in run_cmds), f"Expected 'disable' in {run_cmds}"

    def test_nonzero_return_code_does_not_raise(self):
        import dial_main
        with patch("subprocess.run", return_value=MagicMock(returncode=1)):
            dial_main._reconcile_update_timer(True)  # must not raise

    def test_exception_does_not_raise(self):
        import dial_main
        with patch("subprocess.run", side_effect=OSError("broken")):
            dial_main._reconcile_update_timer(False)  # must not raise

    def test_correct_admin_command_used(self):
        import dial_main
        run_cmds = []
        with patch("subprocess.run",
                   side_effect=lambda cmd, **_: run_cmds.append(list(cmd)) or MagicMock(returncode=0)):
            dial_main._reconcile_update_timer(True)
        flat = " ".join(run_cmds[0])
        assert "toggle-dial-update-timer" in flat


# ---------------------------------------------------------------------------
# GET/POST /screen/settings
# ---------------------------------------------------------------------------

_RUNTIME_KEYS = {"fitted", "rotate", "screen_type", "bgr", "touch_type", "active", "backend",
                  "backend_loaded", "showing", "last_error", "last_error_at",
                  "display_sleeping", "display_idle_seconds"}


class TestScreenSettingsGet:
    def test_get_returns_effective_fitted_and_runtime_shape(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(fitted=False))
        result = {}
        handler_cls, _ = _make_handler_cls(cfg)
        h = object.__new__(handler_cls)
        h.path           = "/screen/settings"
        h.client_address = ("127.0.0.1", 1234)
        h._send_json     = lambda s, d: result.update(status=s, data=d)
        h.do_GET()
        assert result["status"] == 200
        assert result["data"]["ok"] is True
        assert result["data"]["screen"] == {
            "fitted": False, "rotate": False,
            "screen_type": DEFAULT_PROFILE_KEY, "bgr": False,
            "touch_type": DEFAULT_TOUCH_KEY,
        }
        assert set(result["data"]["runtime"].keys()) == _RUNTIME_KEYS
        assert result["data"]["runtime"]["fitted"] is False
        assert result["data"]["runtime"]["backend"] == "noop"
        assert result["data"]["runtime"]["touch_type"] == ""
        assert "artwork_url" not in json.dumps(result["data"])
        supported = result["data"]["supported"]
        assert supported, "supported profile list must not be empty"
        assert all(set(p.keys()) == {"key", "text"} for p in supported)
        supported_touch = result["data"]["supported_touch"]
        assert supported_touch, "supported_touch controller list must not be empty"
        assert all(set(c.keys()) == {"key", "text"} for c in supported_touch)
        # supported_touch is a separate capability list from supported (display
        # profiles) — a dial on a previous release publishes supported but has
        # no supported_touch key at all, so a client must not infer touch
        # support from the presence/contents of supported.
        assert {p["key"] for p in supported_touch} != {p["key"] for p in supported}

    def test_get_reflects_fitted_true(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(fitted=True))
        result = {}
        handler_cls, _ = _make_handler_cls(cfg)
        h = object.__new__(handler_cls)
        h.path           = "/screen/settings"
        h.client_address = ("127.0.0.1", 1234)
        h._send_json     = lambda s, d: result.update(status=s, data=d)
        h.do_GET()
        assert result["data"]["screen"] == {
            "fitted": True, "rotate": False,
            "screen_type": DEFAULT_PROFILE_KEY, "bgr": False,
            "touch_type": DEFAULT_TOUCH_KEY,
        }
        assert result["data"]["runtime"]["fitted"] is True

    def test_get_reflects_rotate_true(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(fitted=True, rotate=True))
        result = {}
        handler_cls, _ = _make_handler_cls(cfg)
        h = object.__new__(handler_cls)
        h.path           = "/screen/settings"
        h.client_address = ("127.0.0.1", 1234)
        h._send_json     = lambda s, d: result.update(status=s, data=d)
        h.do_GET()
        assert result["data"]["screen"] == {
            "fitted": True, "rotate": True,
            "screen_type": DEFAULT_PROFILE_KEY, "bgr": False,
            "touch_type": DEFAULT_TOUCH_KEY,
        }

    def test_get_reflects_screen_type_and_bgr(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(
            fitted=True, screen_type="st7789_240x240", bgr=True,
        ))
        result = {}
        handler_cls, _ = _make_handler_cls(cfg)
        h = object.__new__(handler_cls)
        h.path           = "/screen/settings"
        h.client_address = ("127.0.0.1", 1234)
        h._send_json     = lambda s, d: result.update(status=s, data=d)
        h.do_GET()
        assert result["data"]["screen"] == {
            "fitted": True, "rotate": False,
            "screen_type": "st7789_240x240", "bgr": True,
            "touch_type": DEFAULT_TOUCH_KEY,
        }

    def test_get_reflects_touch_type(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(
            fitted=True, touch_type="xpt2046",
        ))
        result = {}
        handler_cls, _ = _make_handler_cls(cfg)
        h = object.__new__(handler_cls)
        h.path           = "/screen/settings"
        h.client_address = ("127.0.0.1", 1234)
        h._send_json     = lambda s, d: result.update(status=s, data=d)
        h.do_GET()
        assert result["data"]["screen"] == {
            "fitted": True, "rotate": False,
            "screen_type": DEFAULT_PROFILE_KEY, "bgr": False,
            "touch_type": "xpt2046",
        }


class TestScreenSettingsPost:
    def setup_method(self):
        dhs._pin_attempts.clear()

    def test_post_complete_settings_replaces_config(self):
        r = _call_handler("/screen/settings", body={"screen": {"fitted": True}})
        assert r["status"] == 200
        assert r["data"]["ok"] is True
        assert r["data"]["screen"] == {
            "fitted": True, "rotate": False,
            "screen_type": DEFAULT_PROFILE_KEY, "bgr": False,
            "touch_type": DEFAULT_TOUCH_KEY,
        }
        assert set(r["data"]["runtime"].keys()) == _RUNTIME_KEYS
        assert r["data"]["restart_required"] is False
        assert r["save_calls"][0].display.fitted is True

    def test_post_rotate_true_persists_and_appears_in_response(self):
        r = _call_handler("/screen/settings", body={"screen": {"fitted": True, "rotate": True}})
        assert r["status"] == 200
        assert r["data"]["screen"] == {
            "fitted": True, "rotate": True,
            "screen_type": DEFAULT_PROFILE_KEY, "bgr": False,
            "touch_type": DEFAULT_TOUCH_KEY,
        }
        assert r["save_calls"][0].display.rotate is True

    def test_post_screen_type_and_bgr_persist_and_appear_in_response(self):
        r = _call_handler(
            "/screen/settings",
            body={"screen": {"fitted": True, "screen_type": "st7789_240x240", "bgr": True}},
        )
        assert r["status"] == 200
        assert r["data"]["screen"] == {
            "fitted": True, "rotate": False,
            "screen_type": "st7789_240x240", "bgr": True,
            "touch_type": DEFAULT_TOUCH_KEY,
        }
        assert r["save_calls"][0].display.screen_type == "st7789_240x240"
        assert r["save_calls"][0].display.bgr is True

    def test_post_touch_type_persists_and_appears_in_response(self):
        r = _call_handler(
            "/screen/settings",
            body={"screen": {"fitted": True, "touch_type": "ft6206"}},
        )
        assert r["status"] == 200
        assert r["data"]["screen"] == {
            "fitted": True, "rotate": False,
            "screen_type": DEFAULT_PROFILE_KEY, "bgr": False,
            "touch_type": "ft6206",
        }
        assert r["save_calls"][0].display.touch_type == "ft6206"

    def test_post_unknown_touch_type_returns_invalid_screen_settings(self):
        r = _call_handler(
            "/screen/settings",
            body={"screen": {"fitted": True, "touch_type": "no_such_controller"}},
        )
        assert r["status"] == 400
        assert r["data"]["error"] == "invalid_screen_settings"
        assert r["save_calls"] == []

    def test_post_unknown_screen_type_returns_invalid_screen_settings(self):
        r = _call_handler(
            "/screen/settings",
            body={"screen": {"fitted": True, "screen_type": "no_such_panel"}},
        )
        assert r["status"] == 400
        assert r["data"]["error"] == "invalid_screen_settings"
        assert r["save_calls"] == []

    def test_post_rotate_omitted_defaults_false_and_still_200(self):
        r = _call_handler("/screen/settings", body={"screen": {"fitted": True}})
        assert r["status"] == 200
        assert r["data"]["screen"]["rotate"] is False
        assert r["save_calls"][0].display.rotate is False

    def test_post_non_bool_rotate_returns_invalid_screen_settings(self):
        r = _call_handler("/screen/settings", body={"screen": {"fitted": True, "rotate": 1}})
        assert r["status"] == 400
        assert r["data"]["error"] == "invalid_screen_settings"

    def test_post_missing_fitted_returns_invalid_screen_settings(self):
        r = _call_handler("/screen/settings", body={"screen": {}})
        assert r["status"] == 400
        assert r["data"]["error"] == "invalid_screen_settings"

    def test_post_non_bool_fitted_returns_invalid_screen_settings(self):
        r = _call_handler("/screen/settings", body={"screen": {"fitted": 1}})
        assert r["status"] == 400
        assert r["data"]["error"] == "invalid_screen_settings"

    def test_post_unknown_field_returns_invalid_screen_settings(self):
        r = _call_handler("/screen/settings",
                          body={"screen": {"fitted": True, "rotation": 90}})
        assert r["status"] == 400
        assert r["data"]["error"] == "invalid_screen_settings"

    def test_post_missing_screen_object_returns_invalid_screen_settings(self):
        r = _call_handler("/screen/settings", body={})
        assert r["status"] == 400
        assert r["data"]["error"] == "invalid_screen_settings"

    def test_post_requires_pin_when_set(self):
        cfg = DialConfig(uuid="x", pin="9999")
        r = _call_handler("/screen/settings", body={"screen": {"fitted": True}}, cfg=cfg)
        assert r["status"] == 403
        assert r["data"]["error"] == "wrong_pin"

    def test_post_correct_pin_allows_change(self):
        cfg = DialConfig(uuid="x", pin="9999")
        r = _call_handler(
            "/screen/settings",
            body={"screen": {"fitted": True}, "current_pin": "9999"},
            cfg=cfg,
        )
        assert r["status"] == 200

    def test_post_save_failure_returns_500(self):
        cfg = DialConfig(uuid="x")
        server = FakeDialServer(cfg)
        result: dict = {}
        handler_cls = server._make_handler()
        body_bytes = json.dumps({"screen": {"fitted": True}}).encode()
        h = object.__new__(handler_cls)
        h.path           = "/screen/settings"
        h.rfile          = io.BytesIO(body_bytes)
        h.client_address = ("127.0.0.1", 1)
        h.headers        = {"Content-Length": str(len(body_bytes))}
        h._send_json  = lambda s, d: result.update(status=s, data=d)
        h.send_error  = lambda c, *_: result.update(status=c)
        h._send_429   = lambda w: result.update(status=429)

        with patch("dial_config.save_config", side_effect=OSError("disk full")):
            h._handle_screen_settings()

        assert result["status"] == 500
        assert result["data"]["error"] == "save_failed"

    def test_post_does_not_expose_secrets_or_artwork(self):
        r = _call_handler("/screen/settings", body={"screen": {"fitted": True}})
        dumped = json.dumps(r["data"])
        assert "artwork_url" not in dumped
        assert "pin" not in r["data"]["screen"]

    def test_post_live_applies_to_display_status_provider(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(fitted=False))
        server = FakeDialServer(cfg)
        r = _call_handler("/screen/settings",
                          body={"screen": {"fitted": True}},
                          setup_server=server)
        assert r["status"] == 200
        assert server._display_status.get_status()["fitted"] is True


# ---------------------------------------------------------------------------
# Apply-then-persist: a failed live apply must not reach save_config(), and
# the response must surface the failure with the on-disk config unchanged.
# ---------------------------------------------------------------------------

class _FailingDisplayStatusProvider:
    """Stand-in whose update_config() reports a failed backend open — the
    same last_error a real DialDisplay sets when a screen_type's backend
    fails to open (see dial_display.py _enable_locked degrade-to-noop path).
    """

    def update_config(self, config) -> dict:
        return {
            "fitted": config.fitted, "rotate": config.rotate,
            # runtime.screen_type reports the ACTIVE profile, and nothing is
            # open after a failed enable — mirroring DialDisplay, which clears
            # it on teardown and only sets it on a successful open.
            "screen_type": "", "bgr": config.bgr,
            "active": False, "backend": "noop", "backend_loaded": False,
            "showing": "noop", "last_error": "backend_open_failed",
            "last_error_at": 12345.0,
            "display_sleeping": False, "display_idle_seconds": 0,
        }

    def get_status(self) -> dict:
        return self.update_config(DialDisplayConfig())


class TestTouchTypeRestartRequired:
    """touch_type is read once at startup, so changing it cannot apply live
    — the response must say so instead of claiming a live apply."""

    def _post(self, cfg, screen):
        return _call_handler("/screen/settings", body={"screen": screen}, cfg=cfg)

    def test_touch_type_change_sets_restart_required(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(
            fitted=True, touch_type=DEFAULT_TOUCH_KEY,
        ))
        r = self._post(cfg, {"fitted": True, "touch_type": "xpt2046"})
        assert r["status"] == 200
        assert r["data"]["ok"] is True
        assert r["data"]["restart_required"] is True

    def test_unchanged_touch_type_does_not_set_restart_required(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(
            fitted=True, touch_type="xpt2046",
        ))
        r = self._post(cfg, {"fitted": True, "touch_type": "xpt2046"})
        assert r["data"]["restart_required"] is False

    def test_other_screen_changes_still_apply_live(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(
            fitted=True, rotate=False, touch_type="xpt2046",
        ))
        r = self._post(cfg, {"fitted": True, "rotate": True, "touch_type": "xpt2046"})
        assert r["data"]["restart_required"] is False


class TestScreenSettingsApplyThenPersist:
    def test_failed_apply_does_not_persist_and_reports_error(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(
            fitted=False, screen_type="st7735s_160x128",
        ))
        server = FakeDialServer(cfg)
        server._display_status = _FailingDisplayStatusProvider()
        r = _call_handler(
            "/screen/settings",
            body={"screen": {"fitted": True, "screen_type": "st7789_240x240"}},
            setup_server=server,
        )
        assert r["status"] == 200
        assert r["data"]["ok"] is False
        assert r["data"]["error"] == "screen_apply_failed"
        assert r["save_calls"] == [], "a failed apply must never reach save_config()"
        # On-disk config unchanged: the response's screen echoes the OLD
        # (still-effective) settings, not the rejected screen_type.
        assert r["data"]["screen"]["screen_type"] == "st7735s_160x128"

    def test_rotate_change_still_persists_when_backend_cannot_open(self):
        """Only a screen_type change withholds persistence.

        A dial whose panel is absent or faulty fails every open, but its
        rotate/bgr/fitted settings must stay changeable — withholding those
        too would make an unopenable display unconfigurable.
        """
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(
            fitted=True, rotate=False, screen_type="st7735s_160x128",
        ))
        server = FakeDialServer(cfg)
        server._display_status = _FailingDisplayStatusProvider()
        r = _call_handler(
            "/screen/settings",
            body={"screen": {
                "fitted": True, "rotate": True,
                "screen_type": "st7735s_160x128",
            }},
            setup_server=server,
        )
        assert r["status"] == 200
        assert r["data"]["ok"] is True
        assert len(r["save_calls"]) == 1
        assert r["save_calls"][0].display.rotate is True
        assert server._cfg.display.screen_type == "st7735s_160x128"
        assert r["data"]["runtime"]["last_error"] == "backend_open_failed"

    def test_failed_apply_does_not_call_update_cfg(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(fitted=False))
        server = FakeDialServer(cfg)
        server._display_status = _FailingDisplayStatusProvider()
        original_update_cfg = server.update_cfg
        calls = []
        server.update_cfg = lambda c: (calls.append(c), original_update_cfg(c))
        _call_handler(
            "/screen/settings",
            body={"screen": {"fitted": True, "screen_type": "st7789_240x240"}},
            setup_server=server,
        )
        assert calls == [], "a failed apply must never update the live server config"

    def test_disabling_display_never_treated_as_apply_failure(self):
        """fitted=False can never fail to apply — even if the display status
        provider is (unrealistically) reporting a stale backend_open_failed,
        disabling must still succeed and persist normally."""
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(fitted=True))
        server = FakeDialServer(cfg)
        server._display_status = _FailingDisplayStatusProvider()
        r = _call_handler(
            "/screen/settings",
            body={"screen": {"fitted": False}},
            setup_server=server,
        )
        assert r["status"] == 200
        assert r["data"]["ok"] is True
        assert len(r["save_calls"]) == 1


# ---------------------------------------------------------------------------
# NoOpDisplayStatusProvider — placeholder runtime status shape
# ---------------------------------------------------------------------------

class TestNoOpDisplayStatusProvider:
    def test_get_status_includes_sleep_fields(self):
        provider = NoOpDisplayStatusProvider()
        status = provider.get_status()
        assert status["display_sleeping"] is False
        assert status["display_idle_seconds"] == 0

    def test_get_status_includes_screen_type_and_bgr(self):
        provider = NoOpDisplayStatusProvider()
        status = provider.get_status()
        assert status["screen_type"] == DEFAULT_PROFILE_KEY
        assert status["bgr"] is False


# ---------------------------------------------------------------------------
# Dial root route removed — setup UI no longer served
# ---------------------------------------------------------------------------

class TestDialRootRouteRemoved:
    def test_get_root_returns_404(self):
        """GET / must return 404 — the dial no longer serves a standalone setup UI."""
        result = {}
        handler_cls, _ = _make_handler_cls()
        h = object.__new__(handler_cls)
        h.path           = "/"
        h.client_address = ("127.0.0.1", 1234)
        h._send_json     = lambda s, d: result.update(status=s, data=d)
        h.send_error     = lambda code, *_: result.update(status=code)
        h.do_GET()
        assert result.get("status") == 404, (
            "GET / must return 404 now that the standalone dial setup UI has been removed"
        )

    def test_get_index_html_returns_404(self):
        """GET /index.html must return 404."""
        result = {}
        handler_cls, _ = _make_handler_cls()
        h = object.__new__(handler_cls)
        h.path           = "/index.html"
        h.client_address = ("127.0.0.1", 1234)
        h._send_json     = lambda s, d: result.update(status=s, data=d)
        h.send_error     = lambda code, *_: result.update(status=code)
        h.do_GET()
        assert result.get("status") == 404, (
            "GET /index.html must return 404 — setup page no longer served"
        )

    def test_setup_page_html_not_imported_at_module_level(self):
        """SETUP_PAGE_HTML must not be imported at module level in dial_http_server."""
        import dial_http_server
        assert not hasattr(dial_http_server, "SETUP_PAGE_HTML"), (
            "SETUP_PAGE_HTML must not be a module-level name in dial_http_server "
            "after the setup UI was removed"
        )

    def test_docstring_describes_management_api(self):
        """dial_http_server module docstring must say 'management API', not 'setup page'."""
        import dial_http_server
        doc = dial_http_server.__doc__ or ""
        assert "management" in doc.lower() or "management API" in doc, (
            "dial_http_server docstring must describe this as a management API"
        )
        assert "setup page" not in doc.lower(), (
            "dial_http_server docstring must not refer to a 'setup page' "
            "after the UI was removed"
        )


# ---------------------------------------------------------------------------
# Management API still works after setup UI removal
# ---------------------------------------------------------------------------

class TestManagementApiRetained:
    def test_get_configure_still_200(self):
        """GET /configure must still return 200 — appliance proxy depends on this."""
        result = {}
        handler_cls, _ = _make_handler_cls()
        h = object.__new__(handler_cls)
        h.path           = "/configure"
        h.client_address = ("127.0.0.1", 1234)
        h._send_json     = lambda s, d: result.update(status=s, data=d)
        h.send_error     = lambda code, *_: result.update(status=code)
        h.do_GET()
        assert result.get("status") == 200, (
            "GET /configure must still return 200 after setup UI removal"
        )

    def test_get_recovery_status_still_reachable(self):
        """GET /recovery_status must still respond — recovery flow is retained."""
        result = {}
        handler_cls, _ = _make_handler_cls()
        h = object.__new__(handler_cls)
        h.path           = "/recovery_status"
        h.client_address = ("127.0.0.1", 1234)
        h._send_json     = lambda s, d: result.update(status=s, data=d)
        h.send_error     = lambda code, *_: result.update(status=code)
        h.do_GET()
        # Returns 200 (active) or 404 (inactive) — both are valid; must not be 500
        assert result.get("status") in (200, 404), (
            "GET /recovery_status must still return 200 or 404 after setup UI removal"
        )


# ---------------------------------------------------------------------------
# can_confirm_presence + recovery_remaining_ms — lost-PIN recovery on
# dials without a rotary encoder.
# ---------------------------------------------------------------------------

class TestCanConfirmPresenceAndRemainingMs:
    def _get(self, path: str, server) -> dict:
        result = {}
        handler_cls = server._make_handler()
        h = object.__new__(handler_cls)
        h.path           = path
        h.client_address = ("127.0.0.1", 1234)
        h._send_json     = lambda s, d: result.update(status=s, data=d)
        h.send_error     = lambda code, *_: result.update(status=code)
        h.do_GET()
        return result

    def test_configure_includes_can_confirm_presence_false_by_default(self):
        cfg = DialConfig(uuid="x")
        server = FakeDialServer(cfg)
        r = self._get("/configure", server)
        assert r["status"] == 200
        assert r["data"]["can_confirm_presence"] is False

    def test_configure_includes_can_confirm_presence_true_when_set(self):
        cfg = DialConfig(uuid="x")
        server = FakeDialServer(cfg)
        server._can_confirm_presence = True
        r = self._get("/configure", server)
        assert r["data"]["can_confirm_presence"] is True

    def test_recovery_status_inactive_includes_can_confirm_presence(self):
        cfg = DialConfig(uuid="x")
        server = FakeDialServer(cfg)
        server._can_confirm_presence = True
        server._recovery_window._active = False
        r = self._get("/recovery_status", server)
        assert r["status"] == 404
        assert r["data"]["can_confirm_presence"] is True

    def test_recovery_status_active_includes_can_confirm_presence_and_remaining_ms(self):
        cfg = DialConfig(uuid="x")
        server = FakeDialServer(cfg)
        server._can_confirm_presence = True
        server._recovery_window._active = True
        server._recovery_window._volume_confirmed = False
        server._recovery_window._recovery_remaining_ms = 543_000
        r = self._get("/recovery_status", server)
        assert r["status"] == 200
        assert r["data"]["active"] is True
        assert r["data"]["volume_confirmed"] is False
        assert r["data"]["can_confirm_presence"] is True
        assert r["data"]["recovery_remaining_ms"] == 543_000

    def test_recovery_status_remaining_ms_decreases_and_clamps_at_zero(self):
        """End-to-end against a REAL RecoveryWindow (not a mocked snapshot):
        the value reported over /recovery_status must actually count down and
        never go negative once the 10-minute window has elapsed."""
        cfg = DialConfig(uuid="x", pin="1234")
        server = DialHTTPServer.__new__(DialHTTPServer)
        server._cfg            = cfg
        server._cfg_lock       = threading.Lock()
        server._recovery_window = RecoveryWindow(on_announce=lambda add: None)
        server._can_confirm_presence = False
        server._display_status = NoOpDisplayStatusProvider()

        with patch("threading.Timer") as mock_timer_cls, \
             patch("time.monotonic", return_value=2000.0):
            mock_timer_cls.return_value = MagicMock()
            server._recovery_window.open()

        with patch("time.monotonic", return_value=2000.0 + 60):  # 60s later
            r1 = self._get("/recovery_status", server)
        with patch("time.monotonic", return_value=2000.0 + 120):  # 120s later
            r2 = self._get("/recovery_status", server)

        assert r1["data"]["recovery_remaining_ms"] == 540_000
        assert r2["data"]["recovery_remaining_ms"] == 480_000
        assert r2["data"]["recovery_remaining_ms"] < r1["data"]["recovery_remaining_ms"]

        with patch("time.monotonic", return_value=2000.0 + 3600):  # 1hr later
            r3 = self._get("/recovery_status", server)
        assert r3["data"]["recovery_remaining_ms"] == 0

    def test_set_can_confirm_presence_updates_real_server(self):
        cfg = DialConfig(uuid="x")
        server = DialHTTPServer.__new__(DialHTTPServer)
        server._can_confirm_presence = False
        assert server._can_confirm_presence is False
        server.set_can_confirm_presence(True)
        assert server._can_confirm_presence is True
        server.set_can_confirm_presence(False)
        assert server._can_confirm_presence is False

    def test_recovery_not_confirmed_403_unchanged_by_new_fields(self):
        """Sanity check: the existing 403 recovery_not_confirmed behaviour is
        unaffected by the new can_confirm_presence/recovery_remaining_ms
        fields on the GET side."""
        cfg = DialConfig(uuid="x", pin="9999")
        server = FakeDialServer(cfg)
        server._recovery_window._active           = True
        server._recovery_window._volume_confirmed = False
        r = _call_handler(
            "/configure",
            body={"pin_recovery": True, "new_pin": "1234", "name": "X"},
            setup_server=server,
        )
        assert r["status"] == 403
        assert r["data"]["error"] == "recovery_not_confirmed"

    def test_get_update_status_still_reachable(self):
        """GET /update/status must still respond — update flow is retained."""
        result = {}
        handler_cls, _ = _make_handler_cls()
        h = object.__new__(handler_cls)
        h.path           = "/update/status"
        h.client_address = ("127.0.0.1", 1234)
        h._send_json     = lambda s, d: result.update(status=s, data=d)
        h.send_error     = lambda code, *_: result.update(status=code)

        fake_env = {"STATUS": "success", "MESSAGE": "ok", "PERCENT_COMPLETE": "100",
                    "LAST_RUN_AT": "2026-01-01T00:00:00+00:00"}
        with patch("dial_http_server._read_update_state", return_value="complete"):
            h.do_GET()
        assert result.get("status") == 200, (
            "GET /update/status must still return 200 after setup UI removal"
        )

    def test_post_configure_still_works(self):
        """POST /configure must still process name changes — appliance proxy depends on it."""
        r = _call_handler("/configure", body={"name": "MyDial"})
        assert r["status"] == 200, (
            "POST /configure must still return 200 after setup UI removal"
        )
        assert r["data"].get("ok") is True

    def test_configure_name_pin_step_fields_accepted(self):
        """POST /configure must still accept name, step_percent, and new_pin."""
        r = _call_handler("/configure", body={"name": "Test", "step_percent": 3, "new_pin": "4321"})
        assert r["status"] == 200
        assert r["save_calls"][0].name == "Test"
        assert r["save_calls"][0].step_percent == 3
        assert r["save_calls"][0].pin == "4321"
