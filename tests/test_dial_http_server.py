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
        self._touch_source = None
        self._touch_runtime = ''
        self._touch_restart_lock = threading.Lock()
        self._last_touch_restart_monotonic: float | None = None
        self._announce_calls: list = []
        self._auth_push_limiter = dhs._PushLimiter()
        self._get_rostered_ips = None

    def _rostered_ips(self) -> dict:
        return dhs.DialHTTPServer._rostered_ips(self)

    def update_cfg(self, new_cfg: DialConfig) -> None:
        self._cfg = new_cfg

    def _on_announce(self, add: bool) -> None:
        self._announce_calls.append(add)

    @property
    def step_percent(self) -> int:
        return self._cfg.step_percent

    @property
    def effective_volume_scope(self) -> str:
        return dhs.effective_scope(self._cfg.display, self._cfg.display.volume_scope)

    @property
    def effective_mute_scope(self) -> str:
        return dhs.effective_scope(self._cfg.display, self._cfg.display.mute_scope)

    def _make_handler(self):
        return dhs.DialHTTPServer._make_handler(self)

    # The cooldown gate and the actual restart trigger reuse the real
    # DialHTTPServer implementation rather than reinventing it here — this
    # fake exists to exercise dial_http_server.py's handler logic, not to
    # duplicate it.
    def _touch_restart_allowed(self) -> bool:
        return dhs.DialHTTPServer._touch_restart_allowed(self)

    def fire_touch_restart(self) -> None:
        dhs.DialHTTPServer.fire_touch_restart(self)


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
    client_ip: str = "127.0.0.1",
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
    h.client_address = (client_ip, 1234)
    h.headers        = {"Content-Length": str(len(body_bytes))}

    result: dict = {}
    save_calls:  list = []
    call_order:  list = []

    def _send_json(status, data):
        call_order.append("send_json")
        result["status"] = status
        result["data"]   = data

    def _send_429(wait_secs):
        result["status"] = 429
        result["data"]   = {"ok": False, "error": "too_many_attempts"}

    def _send_error(code, *_a):
        result["status"] = code
        result["data"]   = {"ok": False, "error": f"http_{code}"}

    def _send_bytes(status, content_type, body):
        call_order.append("send_bytes")
        result["status"]       = status
        result["content_type"] = content_type
        result["body"]         = body

    h._send_json  = _send_json
    h._send_429   = _send_429
    h.send_error  = _send_error
    h._send_bytes = _send_bytes

    def _popen(*args, **kwargs):
        call_order.append("popen")
        return MagicMock()

    with patch("dial_config.save_config",
               side_effect=lambda c: save_calls.append(copy.copy(c))), \
         patch("subprocess.Popen", side_effect=_popen) as mock_popen:
        if method == "GET":
            h.do_GET()
        elif method == "POST":
            h.do_POST()
        else:
            h._handle_configure()

    result["save_calls"] = save_calls
    result["server"]     = server
    result["call_order"] = call_order
    result["popen_mock"] = mock_popen
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

    def test_configure_ignores_unknown_mute_all_playing_field(self):
        """mute_all_playing is retired from /configure: an old appliance
        still posting it must still succeed, with no effect (unknown keys
        are ignored, matching every other unrecognised field)."""
        r = _call_handler("/configure", body={"mute_all_playing": True})
        assert r["status"] == 200
        assert not hasattr(r["save_calls"][0], "mute_all_playing")


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
# PIN-recovery arm/disarm endpoints — write/delete the request file that
# dial_main.py evaluates at the next startup. Deliberately unauthenticated:
# a PIN cannot gate the endpoint that exists to recover a forgotten PIN.
# ---------------------------------------------------------------------------

class TestRecoveryArmDisarmEndpoints:
    def test_arm_writes_request_file(self, tmp_path):
        cfg = DialConfig(uuid="x", pin="9999")
        request_path = tmp_path / "pin_reset.txt"
        assert not request_path.exists()
        with patch("dial_http_server.PIN_RESET_PATH", request_path):
            r = _call_handler("/recovery/arm", cfg=cfg)
        assert r["status"] == 200
        assert r["data"] == {"ok": True}
        assert request_path.exists()

    def test_disarm_deletes_request_file(self, tmp_path):
        cfg = DialConfig(uuid="x", pin="9999")
        request_path = tmp_path / "pin_reset.txt"
        request_path.write_text("")
        with patch("dial_http_server.PIN_RESET_PATH", request_path):
            r = _call_handler("/recovery/disarm", cfg=cfg)
        assert r["status"] == 200
        assert r["data"] == {"ok": True}
        assert not request_path.exists()

    def test_disarm_is_idempotent_when_no_request_file(self, tmp_path):
        cfg = DialConfig(uuid="x", pin="9999")
        request_path = tmp_path / "pin_reset.txt"
        assert not request_path.exists()
        with patch("dial_http_server.PIN_RESET_PATH", request_path):
            r = _call_handler("/recovery/disarm", cfg=cfg)
        assert r["status"] == 200
        assert r["data"] == {"ok": True}

    def test_arm_requires_no_pin_even_when_one_is_set(self, tmp_path):
        """No current_pin/pin_recovery field is supplied at all — a PIN check
        here would be circular, since the PIN is the thing being recovered."""
        cfg = DialConfig(uuid="x", pin="9999")
        request_path = tmp_path / "pin_reset.txt"
        with patch("dial_http_server.PIN_RESET_PATH", request_path):
            r = _call_handler("/recovery/arm", cfg=cfg, body={})
        assert r["status"] == 200
        assert r["data"]["ok"] is True

    def test_disarm_requires_no_pin_even_when_one_is_set(self, tmp_path):
        cfg = DialConfig(uuid="x", pin="9999")
        request_path = tmp_path / "pin_reset.txt"
        request_path.write_text("")
        with patch("dial_http_server.PIN_RESET_PATH", request_path):
            r = _call_handler("/recovery/disarm", cfg=cfg, body={})
        assert r["status"] == 200
        assert r["data"]["ok"] is True

    def test_arm_write_failure_does_not_raise_and_still_responds_ok(self, tmp_path, caplog):
        """Best-effort like the running-marker helpers: a broken state
        directory must not take the endpoint down."""
        cfg = DialConfig(uuid="x", pin="9999")
        request_path = tmp_path / "pin_reset.txt"
        with patch("dial_http_server.PIN_RESET_PATH", request_path), \
             patch.object(type(request_path), "touch", side_effect=OSError("read-only")), \
             caplog.at_level("WARNING"):
            r = _call_handler("/recovery/arm", cfg=cfg)
        assert r["status"] == 200
        assert r["data"] == {"ok": True}
        assert "could not write" in caplog.text


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

_RUNTIME_KEYS = {"fitted", "rotate", "screen_type", "bgr", "touch_type",
                  "always_show_controls", "active", "backend",
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
            "always_show_controls": False,
            "screen_size_inches": None,
            "layout_size": None,
            "volume_scope": "current",
            "mute_scope": "current",
        }
        assert set(result["data"]["runtime"].keys()) == _RUNTIME_KEYS
        assert result["data"]["runtime"]["fitted"] is False
        assert result["data"]["runtime"]["backend"] == "noop"
        assert result["data"]["runtime"]["touch_type"] == ""
        assert "artwork_url" not in json.dumps(result["data"])
        supported = result["data"]["supported"]
        assert supported, "supported profile list must not be empty"
        assert all(set(p.keys()) == {"key", "text", "default_inches"} for p in supported)
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
            "always_show_controls": False,
            "screen_size_inches": None,
            "layout_size": None,
            "volume_scope": "current",
            "mute_scope": "current",
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
            "always_show_controls": False,
            "screen_size_inches": None,
            "layout_size": None,
            "volume_scope": "current",
            "mute_scope": "current",
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
            "always_show_controls": False,
            "screen_size_inches": None,
            "layout_size": None,
            "volume_scope": "current",
            "mute_scope": "current",
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
            "always_show_controls": False,
            "screen_size_inches": None,
            "layout_size": None,
            "volume_scope": "current",
            "mute_scope": "current",
        }

    def test_runtime_touch_type_reports_running_controller(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(fitted=True))
        handler_cls, server = _make_handler_cls(cfg)
        server._touch_runtime = "xpt2046"
        result = {}
        h = object.__new__(handler_cls)
        h.path           = "/screen/settings"
        h.client_address = ("127.0.0.1", 1234)
        h._send_json     = lambda s, d: result.update(status=s, data=d)
        h.do_GET()
        assert result["data"]["runtime"]["touch_type"] == "xpt2046"

    def test_runtime_touch_type_none_when_disabled(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(fitted=True, touch_type="none"))
        handler_cls, server = _make_handler_cls(cfg)
        server._touch_runtime = "none"
        result = {}
        h = object.__new__(handler_cls)
        h.path           = "/screen/settings"
        h.client_address = ("127.0.0.1", 1234)
        h._send_json     = lambda s, d: result.update(status=s, data=d)
        h.do_GET()
        assert result["data"]["runtime"]["touch_type"] == "none"

    def test_runtime_touch_type_failed_when_construction_raised(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(fitted=True, touch_type="xpt2046"))
        handler_cls, server = _make_handler_cls(cfg)
        server._touch_runtime = "failed"
        result = {}
        h = object.__new__(handler_cls)
        h.path           = "/screen/settings"
        h.client_address = ("127.0.0.1", 1234)
        h._send_json     = lambda s, d: result.update(status=s, data=d)
        h.do_GET()
        assert result["data"]["runtime"]["touch_type"] == "failed"

    def test_runtime_touch_type_independent_of_persisted_config(self):
        """The whole point of runtime.touch_type: it must reflect what is
        actually RUNNING, not what was just persisted. A dial whose config
        says X but whose running process is still on Y (pre-restart) must
        report screen.touch_type == X (persisted) and runtime.touch_type
        == Y (running) simultaneously."""
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(
            fitted=True, touch_type="xpt2046",
        ))
        handler_cls, server = _make_handler_cls(cfg)
        server._touch_runtime = "ft6206"
        result = {}
        h = object.__new__(handler_cls)
        h.path           = "/screen/settings"
        h.client_address = ("127.0.0.1", 1234)
        h._send_json     = lambda s, d: result.update(status=s, data=d)
        h.do_GET()
        assert result["data"]["screen"]["touch_type"] == "xpt2046"
        assert result["data"]["runtime"]["touch_type"] == "ft6206"

    def test_get_reflects_always_show_controls(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(
            fitted=True, always_show_controls=True,
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
            "touch_type": DEFAULT_TOUCH_KEY,
            "always_show_controls": True,
            "screen_size_inches": None,
            "layout_size": None,
            "volume_scope": "current",
            "mute_scope": "current",
        }

    def test_get_layout_sizes_matches_the_active_profiles_options(self):
        from dial_display_profiles import get_profile, layout_size_options

        cfg = DialConfig(uuid="x", display=DialDisplayConfig(fitted=False))
        result = {}
        handler_cls, _ = _make_handler_cls(cfg)
        h = object.__new__(handler_cls)
        h.path           = "/screen/settings"
        h.client_address = ("127.0.0.1", 1234)
        h._send_json     = lambda s, d: result.update(status=s, data=d)
        h.do_GET()
        assert result["data"]["layout_sizes"] == layout_size_options(get_profile(DEFAULT_PROFILE_KEY))

    def test_get_layout_sizes_follows_the_configured_screen_type(self):
        from dial_display_profiles import get_profile, layout_size_options

        cfg = DialConfig(uuid="x", display=DialDisplayConfig(
            fitted=False, screen_type="st7789_240x240",
        ))
        result = {}
        handler_cls, _ = _make_handler_cls(cfg)
        h = object.__new__(handler_cls)
        h.path           = "/screen/settings"
        h.client_address = ("127.0.0.1", 1234)
        h._send_json     = lambda s, d: result.update(status=s, data=d)
        h.do_GET()
        # A square panel offers no named size at all.
        assert result["data"]["layout_sizes"] == layout_size_options(get_profile("st7789_240x240"))
        assert result["data"]["layout_sizes"] == []

    def test_get_reflects_volume_and_mute_scope(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(
            fitted=True, volume_scope="all", mute_scope="current",
        ))
        result = {}
        handler_cls, _ = _make_handler_cls(cfg)
        h = object.__new__(handler_cls)
        h.path           = "/screen/settings"
        h.client_address = ("127.0.0.1", 1234)
        h._send_json     = lambda s, d: result.update(status=s, data=d)
        h.do_GET()
        assert result["data"]["screen"]["volume_scope"] == "all"
        assert result["data"]["screen"]["mute_scope"] == "current"

    def test_get_scope_block_reflects_effective_values_when_fitted(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(
            fitted=True, volume_scope="all", mute_scope="current",
        ))
        result = {}
        handler_cls, _ = _make_handler_cls(cfg)
        h = object.__new__(handler_cls)
        h.path           = "/screen/settings"
        h.client_address = ("127.0.0.1", 1234)
        h._send_json     = lambda s, d: result.update(status=s, data=d)
        h.do_GET()
        assert result["data"]["scope"] == {"volume": "all", "mute": "current"}

    def test_get_scope_block_forces_all_when_not_fitted(self):
        """A screenless dial cannot choose which appliance to address, so
        BOTH effective values report "all" regardless of the stored choice
        -- the informational block must reflect what the dial is actually
        doing, not merely what is saved."""
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(
            fitted=False, volume_scope="current", mute_scope="current",
        ))
        result = {}
        handler_cls, _ = _make_handler_cls(cfg)
        h = object.__new__(handler_cls)
        h.path           = "/screen/settings"
        h.client_address = ("127.0.0.1", 1234)
        h._send_json     = lambda s, d: result.update(status=s, data=d)
        h.do_GET()
        assert result["data"]["scope"] == {"volume": "all", "mute": "all"}


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
            "always_show_controls": False,
            "screen_size_inches": None,
            "layout_size": None,
            "volume_scope": "current",
            "mute_scope": "current",
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
            "always_show_controls": False,
            "screen_size_inches": None,
            "layout_size": None,
            "volume_scope": "current",
            "mute_scope": "current",
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
            "always_show_controls": False,
            "screen_size_inches": None,
            "layout_size": None,
            "volume_scope": "current",
            "mute_scope": "current",
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
            "always_show_controls": False,
            "screen_size_inches": None,
            "layout_size": None,
            "volume_scope": "current",
            "mute_scope": "current",
        }
        assert r["save_calls"][0].display.touch_type == "ft6206"

    def test_post_always_show_controls_true_persists_and_appears_in_response(self):
        r = _call_handler(
            "/screen/settings",
            body={"screen": {"fitted": True, "always_show_controls": True}},
        )
        assert r["status"] == 200
        assert r["data"]["screen"] == {
            "fitted": True, "rotate": False,
            "screen_type": DEFAULT_PROFILE_KEY, "bgr": False,
            "touch_type": DEFAULT_TOUCH_KEY,
            "always_show_controls": True,
            "screen_size_inches": None,
            "layout_size": None,
            "volume_scope": "current",
            "mute_scope": "current",
        }
        assert r["save_calls"][0].display.always_show_controls is True

    def test_post_always_show_controls_omitted_defaults_false(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(
            fitted=True, always_show_controls=True,
        ))
        # A whole-object POST that omits the field resets it, same as an old
        # appliance omitting bgr/screen_type today (see B.6 in the design
        # notes) — this is the accepted cost of whole-object semantics.
        r = _call_handler(
            "/screen/settings", body={"screen": {"fitted": True}}, cfg=cfg,
        )
        assert r["status"] == 200
        assert r["data"]["screen"]["always_show_controls"] is False
        assert r["save_calls"][0].display.always_show_controls is False

    def test_post_non_bool_always_show_controls_returns_invalid_screen_settings(self):
        r = _call_handler(
            "/screen/settings",
            body={"screen": {"fitted": True, "always_show_controls": 1}},
        )
        assert r["status"] == 400
        assert r["data"]["error"] == "invalid_screen_settings"
        assert r["save_calls"] == []

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

    def test_post_with_both_scopes_persists_and_echoes(self):
        r = _call_handler(
            "/screen/settings",
            body={"screen": {"fitted": True, "volume_scope": "all", "mute_scope": "all"}},
        )
        assert r["status"] == 200
        assert r["data"]["screen"]["volume_scope"] == "all"
        assert r["data"]["screen"]["mute_scope"] == "all"
        assert r["data"]["scope"] == {"volume": "all", "mute": "all"}
        assert r["save_calls"][0].display.volume_scope == "all"
        assert r["save_calls"][0].display.mute_scope == "all"

    def test_post_omitting_scopes_saves_current(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(
            fitted=True, volume_scope="all", mute_scope="all",
        ))
        r = _call_handler(
            "/screen/settings", body={"screen": {"fitted": True}}, cfg=cfg,
        )
        assert r["status"] == 200
        assert r["data"]["screen"]["volume_scope"] == "current"
        assert r["data"]["screen"]["mute_scope"] == "current"

    def test_post_non_string_volume_scope_returns_invalid_screen_settings(self):
        r = _call_handler(
            "/screen/settings",
            body={"screen": {"fitted": True, "volume_scope": True}},
        )
        assert r["status"] == 400
        assert r["data"]["error"] == "invalid_screen_settings"
        assert r["save_calls"] == []

    def test_post_unknown_mute_scope_value_returns_invalid_screen_settings(self):
        r = _call_handler(
            "/screen/settings",
            body={"screen": {"fitted": True, "mute_scope": "everything"}},
        )
        assert r["status"] == 400
        assert r["data"]["error"] == "invalid_screen_settings"
        assert r["save_calls"] == []

    def test_screen_apply_failed_body_carries_previous_scopes(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(
            fitted=False, screen_type="st7735s_160x128",
            volume_scope="all", mute_scope="current",
        ))
        server = FakeDialServer(cfg)
        server._display_status = _FailingDisplayStatusProvider()
        r = _call_handler(
            "/screen/settings",
            body={"screen": {
                "fitted": True, "screen_type": "st7789_240x240",
                "volume_scope": "current", "mute_scope": "current",
            }},
            setup_server=server,
        )
        assert r["status"] == 200
        assert r["data"]["error"] == "screen_apply_failed"
        assert r["data"]["screen"]["volume_scope"] == "all"
        assert r["data"]["scope"] == {"volume": "all", "mute": "all"}


# ---------------------------------------------------------------------------
# GET /screen/image — one-shot screenshot of the panel
# ---------------------------------------------------------------------------

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


class _FrameStatusProvider:
    """Minimal display-status stand-in exposing only latest_frame_png(),
    used to drive the endpoint without a real DialDisplay."""

    def __init__(self, frame_png: bytes | None = None, raises: Exception | None = None) -> None:
        self._frame_png = frame_png
        self._raises = raises

    def latest_frame_png(self):
        if self._raises is not None:
            raise self._raises
        return self._frame_png


class TestScreenImageGet:
    def test_returns_png_with_headers_when_frame_available(self):
        png_bytes = _PNG_SIGNATURE + b"rest-of-a-fake-encoded-frame"
        server = FakeDialServer(DialConfig(uuid="test-uuid"))
        server._display_status = _FrameStatusProvider(frame_png=png_bytes)
        r = _call_handler("/screen/image", method="GET", setup_server=server)
        assert r["status"] == 200
        assert r["content_type"] == "image/png"
        assert r["body"] == png_bytes
        assert r["body"].startswith(_PNG_SIGNATURE)

    def test_none_frame_returns_404_no_frame(self):
        server = FakeDialServer(DialConfig(uuid="test-uuid"))
        server._display_status = _FrameStatusProvider(frame_png=None)
        r = _call_handler("/screen/image", method="GET", setup_server=server)
        assert r["status"] == 404
        assert r["data"] == {"ok": False, "error": "no_frame"}

    def test_raising_accessor_returns_404_not_500(self):
        server = FakeDialServer(DialConfig(uuid="test-uuid"))
        server._display_status = _FrameStatusProvider(raises=RuntimeError("boom"))
        r = _call_handler("/screen/image", method="GET", setup_server=server)
        assert r["status"] == 404
        assert r["data"] == {"ok": False, "error": "no_frame"}

    def test_noop_provider_returns_404_no_frame(self):
        r = _call_handler("/screen/image", method="GET")
        assert r["status"] == 404
        assert r["data"] == {"ok": False, "error": "no_frame"}

    def test_documented_in_dial_protocol(self):
        doc = REPO_ROOT / "docs" / "dial" / "DIAL_PROTOCOL.md"
        text = doc.read_text(encoding="utf-8")
        assert "GET /screen/image" in text
        assert "no_frame" in text


class TestSendBytesHeaders:
    """Exercises the real _send_bytes() implementation directly (not the
    result-capturing stub _call_handler() installs for the branch tests
    above), to pin down the actual header values it writes."""

    def test_headers_and_body(self):
        handler_cls, _ = _make_handler_cls()
        h = object.__new__(handler_cls)
        sent_status = []
        sent_headers = []

        def _send_response(status):
            sent_status.append(status)

        def _send_header(name, value):
            sent_headers.append((name, value))

        h.send_response = _send_response
        h.send_header = _send_header
        h.end_headers = lambda: None
        h.wfile = io.BytesIO()

        body = _PNG_SIGNATURE + b"payload"
        h._send_bytes(200, "image/png", body)

        assert sent_status == [200]
        headers = dict(sent_headers)
        assert headers["Content-Type"] == "image/png"
        assert headers["Content-Length"] == str(len(body))
        assert headers["Cache-Control"] == "no-store"
        assert h.wfile.getvalue() == body


# ---------------------------------------------------------------------------
# Layout-size setting — same save/echo path as the other screen fields;
# applies live via the display manager AND remaps the touch stack, so it
# never sets restart_required.
# ---------------------------------------------------------------------------

class TestLayoutSizeSetting:
    def test_post_offered_size_persists_appears_and_remaps_touch(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(fitted=True))
        server = FakeDialServer(cfg)
        orig_update_config = server._display_status.update_config
        mock_update_config = MagicMock(side_effect=orig_update_config)
        server._display_status.update_config = mock_update_config
        server._touch_source = MagicMock()

        r = _call_handler(
            "/screen/settings",
            body={"screen": {"fitted": True, "layout_size": "large"}},
            setup_server=server,
        )

        assert r["status"] == 200
        assert r["data"]["ok"] is True
        assert r["data"]["screen"]["layout_size"] == "large"
        assert isinstance(r["data"]["layout_sizes"], list) and r["data"]["layout_sizes"]
        assert r["data"]["restart_required"] is False
        assert r["save_calls"][0].display.layout_size == "large"

        mock_update_config.assert_called_once()
        applied_display = mock_update_config.call_args[0][0]
        assert applied_display.layout_size == "large"

        server._touch_source.display_config_changed.assert_called_once()
        args, kwargs = server._touch_source.display_config_changed.call_args
        assert args == (False,)
        assert kwargs["layout"].logical_size == (640, 480)

    def test_post_size_not_offered_for_screen_type_is_rejected(self):
        r = _call_handler(
            "/screen/settings",
            body={"screen": {"fitted": True, "screen_type": "st7789_240x240", "layout_size": "medium"}},
        )
        assert r["status"] == 400
        assert r["data"]["error"] == "invalid_screen_settings"

    def test_post_without_layout_size_key_persists_none(self):
        """An older card's whole-object POST (no knowledge of this field at
        all) keeps working — the field defaults to None."""
        r = _call_handler("/screen/settings", body={"screen": {"fitted": True}})
        assert r["status"] == 200
        assert r["data"]["screen"]["layout_size"] is None
        assert r["save_calls"][0].display.layout_size is None

    def test_get_and_post_layout_sizes_shape(self):
        from dial_display_profiles import LAYOUT_SIZES

        r = _call_handler("/screen/settings", body={"screen": {"fitted": True}})
        for entry in r["data"]["layout_sizes"]:
            assert set(entry.keys()) == {"key", "text"}
            assert entry["key"] in LAYOUT_SIZES


# ---------------------------------------------------------------------------
# Layout report — what the persisted screen settings resolve to. Computed
# from the configured (not active) display, the same layout_context_for()/
# metrics_for() pair the display manager itself composes and hit-tests
# with, so the pinned rows below are a characterisation of that shared
# arithmetic, not a second derivation of it.
# ---------------------------------------------------------------------------

class TestLayoutReportHelper:
    """Pins _layout_report_for() for every confirmed profile/size combination."""

    @pytest.mark.parametrize(
        "screen_type, screen_size_inches, layout_size, expected",
        [
            ("st7735s_160x128", None, None, {
                "logical_width": 160, "logical_height": 128,
                "physical_width": 160, "physical_height": 128,
                "resampled": False, "size_chosen": False,
                "content_tier": "base", "touch_short": False,
            }),
            ("st7735s_160x128", None, "medium", {
                "logical_width": 320, "logical_height": 240,
                "physical_width": 160, "physical_height": 128,
                "resampled": True, "size_chosen": True,
                "content_tier": "rich", "touch_short": False,
            }),
            ("st7735s_160x128", None, "large", {
                "logical_width": 640, "logical_height": 480,
                "physical_width": 160, "physical_height": 128,
                "resampled": True, "size_chosen": True,
                "content_tier": "large", "touch_short": False,
            }),
            ("st7735s_128x128", None, None, {
                "logical_width": 128, "logical_height": 128,
                "physical_width": 128, "physical_height": 128,
                "resampled": False, "size_chosen": False,
                "content_tier": "base", "touch_short": False,
            }),
            ("st7789_240x240", None, None, {
                "logical_width": 240, "logical_height": 240,
                "physical_width": 240, "physical_height": 240,
                "resampled": False, "size_chosen": False,
                # Vetoed back to base: the quarter-height band on this glass
                # is short of the touch floor, and no size was chosen.
                "content_tier": "base", "touch_short": True,
            }),
            ("st7789_320x240", None, None, {
                "logical_width": 320, "logical_height": 240,
                "physical_width": 320, "physical_height": 240,
                "resampled": False, "size_chosen": False,
                "content_tier": "rich", "touch_short": False,
            }),
            ("ili9341_320x240", None, None, {
                "logical_width": 320, "logical_height": 240,
                "physical_width": 320, "physical_height": 240,
                "resampled": False, "size_chosen": False,
                "content_tier": "rich", "touch_short": False,
            }),
            ("st7789_320x240", None, "medium", {
                "logical_width": 320, "logical_height": 240,
                "physical_width": 320, "physical_height": 240,
                "resampled": False, "size_chosen": True,
                "content_tier": "rich", "touch_short": False,
            }),
            ("st7789_320x240", 2.8, "small", {
                "logical_width": 160, "logical_height": 128,
                "physical_width": 320, "physical_height": 240,
                "resampled": True, "size_chosen": True,
                "content_tier": "base", "touch_short": False,
            }),
            ("st7789_320x240", 2.8, "large", {
                "logical_width": 640, "logical_height": 480,
                "physical_width": 320, "physical_height": 240,
                "resampled": True, "size_chosen": True,
                "content_tier": "large", "touch_short": False,
            }),
            # touch_short is True at 240x240's default size...
            ("st7789_240x240", 1.3, None, {
                "logical_width": 240, "logical_height": 240,
                "physical_width": 240, "physical_height": 240,
                "resampled": False, "size_chosen": False,
                "content_tier": "base", "touch_short": True,
            }),
            # ...and moves with the glass: the same 320x240 panel, set to a
            # smaller physical size than its 2.8in default, also reports
            # touch_short True (this is the case the setup-card warning
            # exists for).
            ("st7789_320x240", 1.5, None, {
                "logical_width": 320, "logical_height": 240,
                "physical_width": 320, "physical_height": 240,
                "resampled": False, "size_chosen": False,
                "content_tier": "base", "touch_short": True,
            }),
            # An unknown screen_type falls back to the default profile.
            ("no-such-profile", None, None, {
                "logical_width": 160, "logical_height": 128,
                "physical_width": 160, "physical_height": 128,
                "resampled": False, "size_chosen": False,
                "content_tier": "base", "touch_short": False,
            }),
        ],
    )
    def test_pinned_rows(self, screen_type, screen_size_inches, layout_size, expected):
        cfg = DialDisplayConfig(
            screen_type=screen_type,
            screen_size_inches=screen_size_inches,
            layout_size=layout_size,
        )
        assert dhs._layout_report_for(cfg) == expected

    def test_every_value_is_int_bool_or_str_never_none(self):
        for screen_type in ("st7735s_160x128", "st7789_240x240", "no-such-profile"):
            report = dhs._layout_report_for(DialDisplayConfig(screen_type=screen_type))
            for key, value in report.items():
                assert value is not None, f"{key} is None for {screen_type}"
                assert isinstance(value, (int, bool, str)), (
                    f"{key}={value!r} for {screen_type} is {type(value)}, not int/bool/str"
                )


class TestLayoutReportWiring:
    def test_get_layout_matches_helper_for_default_config(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(fitted=False))
        r = _call_handler("/screen/settings", method="GET", cfg=cfg)
        assert r["data"]["layout"] == dhs._layout_report_for(cfg.display)

    def test_get_layout_matches_helper_for_large_configured_display(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(
            fitted=False, screen_type="st7789_320x240", layout_size="large",
        ))
        r = _call_handler("/screen/settings", method="GET", cfg=cfg)
        assert r["data"]["layout"] == dhs._layout_report_for(cfg.display)

    def test_get_layout_present_alongside_unchanged_runtime_keys(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(fitted=False))
        r = _call_handler("/screen/settings", method="GET", cfg=cfg)
        assert set(r["data"]["runtime"].keys()) == _RUNTIME_KEYS
        assert "layout" not in r["data"]["runtime"]

    def test_post_success_layout_reflects_new_config(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(
            fitted=True, screen_type="st7789_320x240",
        ))
        r = _call_handler(
            "/screen/settings",
            body={"screen": {"fitted": True, "screen_type": "st7789_320x240", "layout_size": "large"}},
            cfg=cfg,
        )
        assert r["status"] == 200
        assert r["data"]["ok"] is True
        assert r["data"]["layout"] == {
            "logical_width": 640, "logical_height": 480,
            "physical_width": 320, "physical_height": 240,
            "resampled": True, "size_chosen": True,
            "content_tier": "large", "touch_short": False,
        }

    def test_post_body_without_layout_size_reports_size_chosen_false(self):
        r = _call_handler("/screen/settings", body={"screen": {"fitted": True}})
        assert r["data"]["layout"]["size_chosen"] is False

    def test_post_apply_failed_layout_reflects_persisted_config(self):
        """On a failed screen_type apply, the response echoes the persisted
        (previous) screen — layout must match, not the rejected request."""
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
        assert r["data"]["error"] == "screen_apply_failed"
        assert r["data"]["layout"] == dhs._layout_report_for(cfg.display)
        # The rejected request's screen_type report differs — proves this
        # isn't accidentally matching both.
        assert r["data"]["layout"] != dhs._layout_report_for(
            DialDisplayConfig(fitted=True, screen_type="st7789_240x240")
        )


# ---------------------------------------------------------------------------
# Screen-size setting (physical diagonal, inches) — same save/echo path as
# the other screen fields; applies live (no restart), so it never sets
# restart_required.
# ---------------------------------------------------------------------------

class TestScreenSizeInchesSetting:
    def test_get_default_inches_present_per_supported_entry(self):
        result = {}
        handler_cls, _ = _make_handler_cls()
        h = object.__new__(handler_cls)
        h.path           = "/screen/settings"
        h.client_address = ("127.0.0.1", 1234)
        h._send_json     = lambda s, d: result.update(status=s, data=d)
        h.do_GET()
        supported = result["data"]["supported"]
        for entry in supported:
            assert isinstance(entry["default_inches"], (int, float))
            assert entry["default_inches"] > 0

    def test_get_reflects_override_when_set(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(fitted=True, screen_size_inches=3.5))
        result = {}
        handler_cls, _ = _make_handler_cls(cfg)
        h = object.__new__(handler_cls)
        h.path           = "/screen/settings"
        h.client_address = ("127.0.0.1", 1234)
        h._send_json     = lambda s, d: result.update(status=s, data=d)
        h.do_GET()
        assert result["data"]["screen"]["screen_size_inches"] == 3.5

    def test_post_persists_and_echoes_size(self):
        r = _call_handler(
            "/screen/settings",
            body={"screen": {"fitted": True, "screen_size_inches": 2.8}},
        )
        assert r["status"] == 200
        assert r["data"]["screen"]["screen_size_inches"] == 2.8
        assert r["save_calls"][0].display.screen_size_inches == 2.8

    def test_post_null_persists_and_echoes_none(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(fitted=True, screen_size_inches=2.8))
        r = _call_handler(
            "/screen/settings",
            body={"screen": {"fitted": True, "screen_size_inches": None}},
            cfg=cfg,
        )
        assert r["status"] == 200
        assert r["data"]["screen"]["screen_size_inches"] is None
        assert r["save_calls"][0].display.screen_size_inches is None

    def test_size_only_change_returns_restart_required_false(self):
        r = _call_handler(
            "/screen/settings",
            body={"screen": {"fitted": True, "screen_size_inches": 3.5}},
        )
        assert r["status"] == 200
        assert r["data"]["restart_required"] is False
        assert "restarting" not in r["data"]

    def test_post_out_of_range_size_returns_invalid_screen_settings(self):
        r = _call_handler(
            "/screen/settings",
            body={"screen": {"fitted": True, "screen_size_inches": 25}},
        )
        assert r["status"] == 400
        assert r["data"]["error"] == "invalid_screen_settings"
        assert r["save_calls"] == []


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
            "always_show_controls": config.always_show_controls,
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

    def test_apply_failure_response_reports_runtime_touch_type_not_dead_default(self):
        """runtime.touch_type must report the running touch stack on every
        response that carries it, not a placeholder. This one covers the
        apply-failure branch."""
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(
            fitted=False, screen_type="st7735s_160x128",
        ))
        server = FakeDialServer(cfg)
        server._display_status = _FailingDisplayStatusProvider()
        server._touch_runtime = "ft6206"
        r = _call_handler(
            "/screen/settings",
            body={"screen": {"fitted": True, "screen_type": "st7789_240x240"}},
            setup_server=server,
        )
        assert r["data"]["error"] == "screen_apply_failed"
        assert r["data"]["runtime"]["touch_type"] == "ft6206"

    def test_success_response_reports_runtime_touch_type_not_dead_default(self):
        """Same dead pattern, success branch."""
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(fitted=True))
        server = FakeDialServer(cfg)
        server._touch_runtime = "ft6206"
        r = _call_handler(
            "/screen/settings",
            body={"screen": {"fitted": True}},
            setup_server=server,
        )
        assert r["data"]["runtime"]["touch_type"] == "ft6206"


# ---------------------------------------------------------------------------
# Self-restart on touch_type change (POST /screen/settings)
# ---------------------------------------------------------------------------

class TestTouchTypeSelfRestart:
    """The dial restarts itself via `sudo -n autostream_admin
    restart-dial-service` when touch_type actually changes, fired
    fire-and-forget (Popen, never waited on) strictly after the HTTP
    response has been sent, and rate-limited to at most once per
    dhs._TOUCH_RESTART_COOLDOWN_SECONDS since POST /screen/settings is
    unauthenticated on a PIN-less dial."""

    def _post_touch_change(self, server, touch_type):
        return _call_handler(
            "/screen/settings",
            body={"screen": {"fitted": True, "touch_type": touch_type}},
            setup_server=server,
        )

    def test_restart_triggered_on_touch_type_change(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(
            fitted=True, touch_type=DEFAULT_TOUCH_KEY,
        ))
        server = FakeDialServer(cfg)
        r = self._post_touch_change(server, "xpt2046")
        assert r["status"] == 200
        assert r["data"]["ok"] is True
        assert r["data"]["restarting"] is True
        r["popen_mock"].assert_called_once_with(
            ["sudo", "-n", dhs.ADMIN_CMD, "restart-dial-service"]
        )

    def test_restart_not_triggered_when_touch_type_unchanged(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(fitted=True, touch_type="xpt2046"))
        server = FakeDialServer(cfg)
        r = self._post_touch_change(server, "xpt2046")
        assert r["data"]["restart_required"] is False
        assert "restarting" not in r["data"]
        r["popen_mock"].assert_not_called()

    def test_restart_not_triggered_on_validation_failure(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(
            fitted=True, touch_type=DEFAULT_TOUCH_KEY,
        ))
        server = FakeDialServer(cfg)
        r = self._post_touch_change(server, "no_such_controller")
        assert r["status"] == 400
        r["popen_mock"].assert_not_called()

    def test_restart_not_triggered_on_wrong_pin(self):
        cfg = DialConfig(uuid="x", pin="9999", display=DialDisplayConfig(
            fitted=True, touch_type=DEFAULT_TOUCH_KEY,
        ))
        r = _call_handler(
            "/screen/settings",
            body={"screen": {"fitted": True, "touch_type": "xpt2046"}, "current_pin": "0000"},
            cfg=cfg,
        )
        assert r["status"] == 403
        r["popen_mock"].assert_not_called()

    def test_restart_fires_strictly_after_response_is_sent(self):
        """_send_json writes synchronously to wfile on the handler thread;
        firing the restart before it returns would risk truncating the
        response. Recording call order (not just that both happened) is
        the only way to prove this."""
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(
            fitted=True, touch_type=DEFAULT_TOUCH_KEY,
        ))
        server = FakeDialServer(cfg)
        r = self._post_touch_change(server, "xpt2046")
        assert r["call_order"] == ["send_json", "popen"]

    def test_popen_raising_does_not_fail_the_request(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(
            fitted=True, touch_type=DEFAULT_TOUCH_KEY,
        ))
        handler_cls, server = _make_handler_cls(cfg)
        body_bytes = json.dumps({"screen": {"fitted": True, "touch_type": "xpt2046"}}).encode()
        h = object.__new__(handler_cls)
        h.path           = "/screen/settings"
        h.rfile          = io.BytesIO(body_bytes)
        h.client_address = ("127.0.0.1", 1)
        h.headers        = {"Content-Length": str(len(body_bytes))}
        result: dict = {}
        h._send_json  = lambda s, d: result.update(status=s, data=d)
        h.send_error  = lambda c, *_: result.update(status=c)
        h._send_429   = lambda w: result.update(status=429)

        with patch("dial_config.save_config", side_effect=lambda c: None), \
             patch("subprocess.Popen", side_effect=OSError("no sudo")):
            h._handle_screen_settings()

        assert result["status"] == 200
        assert result["data"]["ok"] is True
        assert result["data"]["restarting"] is True

    def test_cooldown_refuses_second_trigger_within_window(self, caplog):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(
            fitted=True, touch_type=DEFAULT_TOUCH_KEY,
        ))
        server = FakeDialServer(cfg)
        with patch("dial_http_server.time.monotonic", return_value=1000.0):
            r1 = self._post_touch_change(server, "xpt2046")
        assert r1["data"]["restarting"] is True
        assert r1["popen_mock"].call_count == 1

        with patch("dial_http_server.time.monotonic", return_value=1010.0), \
             caplog.at_level("WARNING"):
            r2 = self._post_touch_change(server, "ft6206")
        assert r2["data"]["restart_required"] is True
        assert "restarting" not in r2["data"]
        assert r2["popen_mock"].call_count == 0
        assert any("cooldown" in rec.message for rec in caplog.records)

    def test_cooldown_allows_trigger_after_window_elapses(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(
            fitted=True, touch_type=DEFAULT_TOUCH_KEY,
        ))
        server = FakeDialServer(cfg)
        with patch("dial_http_server.time.monotonic", return_value=1000.0):
            self._post_touch_change(server, "xpt2046")
        with patch(
            "dial_http_server.time.monotonic",
            return_value=1000.0 + dhs._TOUCH_RESTART_COOLDOWN_SECONDS + 1,
        ):
            r2 = self._post_touch_change(server, "ft6206")
        assert r2["data"]["restarting"] is True
        assert r2["popen_mock"].call_count == 1


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
# DialHTTPServer.effective_volume_scope / effective_mute_scope
# ---------------------------------------------------------------------------

class TestEffectiveScopeProperties:
    def test_fitted_dial_reports_stored_values(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(
            fitted=True, volume_scope="all", mute_scope="current",
        ))
        server = DialHTTPServer.__new__(DialHTTPServer)
        server._cfg = cfg
        server._cfg_lock = threading.Lock()
        assert server.effective_volume_scope == "all"
        assert server.effective_mute_scope == "current"

    def test_unfitted_dial_forces_all_for_both(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(
            fitted=False, volume_scope="current", mute_scope="current",
        ))
        server = DialHTTPServer.__new__(DialHTTPServer)
        server._cfg = cfg
        server._cfg_lock = threading.Lock()
        assert server.effective_volume_scope == "all"
        assert server.effective_mute_scope == "all"

    def test_reads_live_cfg_after_update_cfg(self):
        cfg = DialConfig(uuid="x", display=DialDisplayConfig(fitted=True, mute_scope="current"))
        server = DialHTTPServer.__new__(DialHTTPServer)
        server._cfg = cfg
        server._cfg_lock = threading.Lock()
        assert server.effective_mute_scope == "current"
        new_cfg = copy.copy(cfg)
        new_cfg.display = DialDisplayConfig(fitted=True, mute_scope="all")
        server.update_cfg(new_cfg)
        assert server.effective_mute_scope == "all"


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

    def test_get_status_includes_always_show_controls(self):
        provider = NoOpDisplayStatusProvider()
        status = provider.get_status()
        assert status["always_show_controls"] is False

    def test_latest_frame_png_returns_none(self):
        provider = NoOpDisplayStatusProvider()
        assert provider.latest_frame_png() is None


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

    def test_get_configure_does_not_echo_mute_all_playing(self):
        """mute_all_playing is retired — GET /configure never reports it,
        even for a dial that has never saved settings since the field was
        removed (DialConfig no longer has the attribute at all)."""
        result = {}
        cfg = DialConfig(uuid="test-uuid")
        handler_cls, _ = _make_handler_cls(cfg)
        h = object.__new__(handler_cls)
        h.path           = "/configure"
        h.client_address = ("127.0.0.1", 1234)
        h._send_json     = lambda s, d: result.update(status=s, data=d)
        h.send_error     = lambda code, *_: result.update(status=code)
        h.do_GET()
        assert result["status"] == 200
        assert "mute_all_playing" not in result["data"]

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

    def test_set_touch_runtime_updates_real_server(self):
        server = DialHTTPServer.__new__(DialHTTPServer)
        server._touch_runtime = ''
        server.set_touch_runtime("xpt2046")
        assert server._touch_runtime == "xpt2046"
        server.set_touch_runtime("none")
        assert server._touch_runtime == "none"
        server.set_touch_runtime("failed")
        assert server._touch_runtime == "failed"

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


# ---------------------------------------------------------------------------
# POST /auth-changed
# ---------------------------------------------------------------------------

_AID = "a" * 20


class _NotifyingDisplayStatusProvider(NoOpDisplayStatusProvider):
    """Stand-in with a real notify_auth_changed hook to assert on."""

    def __init__(self) -> None:
        super().__init__()
        self.notified: list = []

    def notify_auth_changed(self, appliance_id: str) -> None:
        self.notified.append(appliance_id)


class _RaisingNotifyDisplayStatusProvider(NoOpDisplayStatusProvider):
    def notify_auth_changed(self, appliance_id: str) -> None:
        raise RuntimeError("boom")


class TestAuthChangedRoute:
    def test_invalid_json_returns_400(self):
        r = _call_handler("/auth-changed", body=b"not json")
        assert r["status"] == 400
        assert r["data"]["error"] == "invalid_json"

    def test_non_object_body_returns_400(self):
        r = _call_handler("/auth-changed", body=b"[1,2,3]")
        assert r["status"] == 400
        assert r["data"]["error"] == "body_must_be_object"

    def test_missing_appliance_id_returns_400(self):
        r = _call_handler("/auth-changed", body={})
        assert r["status"] == 400
        assert r["data"]["error"] == "invalid_appliance_id"

    def test_non_string_appliance_id_returns_400(self):
        r = _call_handler("/auth-changed", body={"appliance_id": 12345})
        assert r["status"] == 400
        assert r["data"]["error"] == "invalid_appliance_id"

    def test_malformed_appliance_id_returns_400(self):
        r = _call_handler("/auth-changed", body={"appliance_id": "not-hex-not-20-chars"})
        assert r["status"] == 400
        assert r["data"]["error"] == "invalid_appliance_id"

    def test_well_formed_body_returns_202_even_when_id_unknown(self):
        r = _call_handler("/auth-changed", body={"appliance_id": _AID})
        assert r["status"] == 202
        assert r["data"]["ok"] is True

    def test_enqueues_on_display_when_ip_matches_rostered_sighting(self):
        server = FakeDialServer(DialConfig(uuid="test-uuid"))
        display = _NotifyingDisplayStatusProvider()
        server._display_status = display
        server._get_rostered_ips = lambda: {_AID: "127.0.0.1"}
        r = _call_handler("/auth-changed", body={"appliance_id": _AID},
                          setup_server=server, client_ip="127.0.0.1")
        assert r["status"] == 202
        assert display.notified == [_AID]

    def test_does_not_enqueue_when_ip_does_not_match_rostered_sighting(self):
        server = FakeDialServer(DialConfig(uuid="test-uuid"))
        display = _NotifyingDisplayStatusProvider()
        server._display_status = display
        server._get_rostered_ips = lambda: {_AID: "192.168.1.5"}
        r = _call_handler("/auth-changed", body={"appliance_id": _AID},
                          setup_server=server, client_ip="192.168.1.99")
        assert r["status"] == 202
        assert display.notified == []

    def test_does_not_enqueue_when_id_not_rostered_at_all(self):
        server = FakeDialServer(DialConfig(uuid="test-uuid"))
        display = _NotifyingDisplayStatusProvider()
        server._display_status = display
        server._get_rostered_ips = lambda: {}
        r = _call_handler("/auth-changed", body={"appliance_id": _AID},
                          setup_server=server, client_ip="127.0.0.1")
        assert r["status"] == 202
        assert display.notified == []

    def test_get_rostered_ips_none_never_enqueues(self):
        server = FakeDialServer(DialConfig(uuid="test-uuid"))
        display = _NotifyingDisplayStatusProvider()
        server._display_status = display
        server._get_rostered_ips = None
        r = _call_handler("/auth-changed", body={"appliance_id": _AID},
                          setup_server=server, client_ip="127.0.0.1")
        assert r["status"] == 202
        assert display.notified == []

    def test_get_rostered_ips_raising_degrades_to_no_enqueue(self):
        server = FakeDialServer(DialConfig(uuid="test-uuid"))
        display = _NotifyingDisplayStatusProvider()
        server._display_status = display

        def _raise():
            raise RuntimeError("mdns browser broke")
        server._get_rostered_ips = _raise
        r = _call_handler("/auth-changed", body={"appliance_id": _AID},
                          setup_server=server, client_ip="127.0.0.1")
        assert r["status"] == 202
        assert display.notified == []

    def test_noop_display_provider_accepts_without_error(self):
        server = FakeDialServer(DialConfig(uuid="test-uuid"))
        server._display_status = NoOpDisplayStatusProvider()
        server._get_rostered_ips = lambda: {_AID: "127.0.0.1"}
        r = _call_handler("/auth-changed", body={"appliance_id": _AID},
                          setup_server=server, client_ip="127.0.0.1")
        assert r["status"] == 202

    def test_notify_raising_does_not_break_the_response(self):
        server = FakeDialServer(DialConfig(uuid="test-uuid"))
        server._display_status = _RaisingNotifyDisplayStatusProvider()
        server._get_rostered_ips = lambda: {_AID: "127.0.0.1"}
        r = _call_handler("/auth-changed", body={"appliance_id": _AID},
                          setup_server=server, client_ip="127.0.0.1")
        assert r["status"] == 202
        assert r["data"]["ok"] is True

    def test_ip_rate_limit_refuses_second_push_within_window_but_still_202(self):
        server = FakeDialServer(DialConfig(uuid="test-uuid"))
        display = _NotifyingDisplayStatusProvider()
        server._display_status = display
        aid2 = "b" * 20
        server._get_rostered_ips = lambda: {_AID: "127.0.0.1", aid2: "127.0.0.1"}
        r1 = _call_handler("/auth-changed", body={"appliance_id": _AID},
                           setup_server=server, client_ip="127.0.0.1")
        r2 = _call_handler("/auth-changed", body={"appliance_id": aid2},
                           setup_server=server, client_ip="127.0.0.1")
        assert r1["status"] == 202
        assert r2["status"] == 202
        # Same source IP, second push within the 2s window: refused
        # (not enqueued) despite being individually well-formed and rostered.
        assert display.notified == [_AID]

    def test_id_rate_limit_refuses_second_push_within_window_but_still_202(self):
        server = FakeDialServer(DialConfig(uuid="test-uuid"))
        display = _NotifyingDisplayStatusProvider()
        server._display_status = display
        server._get_rostered_ips = lambda: {_AID: "10.0.0.1"}
        r1 = _call_handler("/auth-changed", body={"appliance_id": _AID},
                           setup_server=server, client_ip="10.0.0.1")
        server._get_rostered_ips = lambda: {_AID: "10.0.0.2"}
        r2 = _call_handler("/auth-changed", body={"appliance_id": _AID},
                           setup_server=server, client_ip="10.0.0.2")
        assert r1["status"] == 202
        assert r2["status"] == 202
        # Same appliance_id, second push within the 5s window (from a
        # different source IP this time): refused despite matching its roster.
        assert display.notified == [_AID]

    def test_oversized_body_returns_413(self):
        handler_cls, server = _make_handler_cls()
        h = object.__new__(handler_cls)
        h.path = "/auth-changed"
        h.client_address = ("127.0.0.1", 1234)
        h.headers = {"Content-Length": str(dhs.MAX_BODY + 1)}
        h.rfile = io.BytesIO(b"x" * (dhs.MAX_BODY + 1))
        result = {}
        h._send_json = lambda s, d: result.update(status=s, data=d)
        h.send_error = lambda code, *_: result.update(status=code)
        h.do_POST()
        assert result["status"] == 413
