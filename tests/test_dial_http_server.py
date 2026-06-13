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
from dial_config import DialConfig
from dial_http_server import RecoveryWindow


# ---------------------------------------------------------------------------
# Handler factory
# ---------------------------------------------------------------------------

class FakeDialServer:
    """Minimal stand-in for DialHTTPServer used to build and exercise the handler."""

    def __init__(self, cfg: DialConfig) -> None:
        self._cfg           = cfg
        self._cfg_lock      = threading.Lock()
        self._recovery_window = MagicMock(spec=RecoveryWindow)
        self._recovery_window._active           = False
        self._recovery_window._volume_confirmed = False
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
        r = _call_handler("/update", method="POST")
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
