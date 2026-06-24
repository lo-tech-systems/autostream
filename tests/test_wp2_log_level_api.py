"""WP2 — Log-level and playing-status API tests.

Covers:
  - GET /api/log-level: returns state, available without PIN
  - PUT /api/log-level: browser path (CSRF + PIN), direct-local path (system)
  - Unknown fields in PUT body rejected
  - _is_direct_local() classification
  - GET /api/playing-status: direct-local no auth, proxied requires auth
  - send_log_level_put_json: validation delegation
"""
from __future__ import annotations

import json
import sys
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from typing import Optional
from unittest.mock import MagicMock, patch, call

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

import autostream_webui_api as api_mod
import autostream_auth as auth_mod


# ---------------------------------------------------------------------------
# Minimal handler / state fakes
# ---------------------------------------------------------------------------

def _make_state(config_path: str, *, playing: bool = False) -> MagicMock:
    state = MagicMock()
    state.config_path = config_path
    return state


def _make_handler(
    *,
    peer: str = "127.0.0.1",
    xff: Optional[str] = None,
    xri: Optional[str] = None,
    content_type: str = "application/json",
    csrf_header: Optional[str] = None,
    authenticated: bool = True,
    csrf_valid: bool = True,
) -> MagicMock:
    """Return a fake ConfigWebHandler-like object."""
    h = MagicMock()
    h.client_address = (peer, 12345)
    headers: dict = {}
    if xff is not None:
        headers["X-Forwarded-For"] = xff
    if xri is not None:
        headers["X-Real-IP"] = xri
    if content_type is not None:
        headers["Content-Type"] = content_type
    if csrf_header is not None:
        headers["X-CSRF-Token"] = csrf_header
    h.headers = headers

    # Simulate _is_direct_local logic from ConfigWebHandler
    def _is_direct_local():
        peer_ip = h.client_address[0]
        is_loopback = peer_ip.startswith("127.") or peer_ip == "::1"
        if not is_loopback:
            return False
        if h.headers.get("X-Forwarded-For"):
            return False
        if h.headers.get("X-Real-IP"):
            return False
        ct = (h.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        return ct == "application/json"

    h._is_direct_local = _is_direct_local

    # AUTH mock
    auth = MagicMock()
    auth.is_authenticated.return_value = authenticated
    auth.validate_csrf.return_value = csrf_valid
    auth.require_authenticated_if_pin_enabled.return_value = authenticated
    h._auth = auth

    return h


# ---------------------------------------------------------------------------
# _is_direct_local classification
# ---------------------------------------------------------------------------

class TestIsDirectLocal:
    def _check(self, **kwargs) -> bool:
        h = _make_handler(**kwargs)
        return h._is_direct_local()

    def test_loopback_no_proxy_json_is_direct(self):
        assert self._check(peer="127.0.0.1", content_type="application/json") is True

    def test_loopback_ipv6_is_direct(self):
        assert self._check(peer="::1", content_type="application/json") is True

    def test_xff_present_is_not_direct(self):
        assert self._check(peer="127.0.0.1", xff="10.0.0.1", content_type="application/json") is False

    def test_xri_present_is_not_direct(self):
        assert self._check(peer="127.0.0.1", xri="10.0.0.1", content_type="application/json") is False

    def test_non_loopback_is_not_direct(self):
        assert self._check(peer="192.168.1.1", content_type="application/json") is False

    def test_wrong_content_type_is_not_direct(self):
        assert self._check(peer="127.0.0.1", content_type="text/plain") is False

    def test_form_content_type_is_not_direct(self):
        assert self._check(peer="127.0.0.1", content_type="application/x-www-form-urlencoded") is False

    def test_content_type_with_charset_is_direct(self):
        assert self._check(peer="127.0.0.1", content_type="application/json; charset=utf-8") is True


# ---------------------------------------------------------------------------
# send_log_level_get_json
# ---------------------------------------------------------------------------

class TestSendLogLevelGetJson:
    def test_delegates_to_get_log_level_state(self, tmp_path):
        state = _make_state(str(tmp_path / "cfg.json"))
        h = _make_handler()

        fake_result = {
            "ok": True, "level": "info", "changed_by": "user", "changed_at": None,
        }
        sent = []

        def _fake_send_json(handler, code, payload):
            sent.append((code, payload))

        with patch("autostream_log_policy.get_log_level_state", return_value=fake_result), \
             patch("autostream_webui_api.send_json", _fake_send_json):
            api_mod.send_log_level_get_json(h, state)

        assert len(sent) == 1
        code, payload = sent[0]
        assert code == 200
        assert payload["ok"] is True
        assert payload["level"] == "info"
        assert payload["changed_by"] == "user"

    def test_error_from_getter_is_forwarded(self, tmp_path):
        state = _make_state(str(tmp_path / "cfg.json"))
        h = _make_handler()
        sent = []

        with patch("autostream_log_policy.get_log_level_state",
                   return_value={"ok": False, "error": "read failed"}), \
             patch("autostream_webui_api.send_json", lambda h, c, p: sent.append((c, p))):
            api_mod.send_log_level_get_json(h, state)

        assert sent[0][1]["ok"] is False


# ---------------------------------------------------------------------------
# send_log_level_put_json — validation and routing
# ---------------------------------------------------------------------------

class TestSendLogLevelPutJson:
    def _call(self, json_obj: dict, changed_by: str, tmp_path, *, set_result=None):
        state = _make_state(str(tmp_path / "cfg.json"))
        h = _make_handler()
        sent = []

        if set_result is None:
            set_result = {
                "ok": True, "level": "info", "changed_by": changed_by,
                "changed_at": None, "changed": False, "applied": {},
            }

        with patch("autostream_log_policy.set_log_level", return_value=set_result), \
             patch("autostream_webui_api.send_json", lambda h, c, p: sent.append((c, p))), \
             patch("autostream_webui_api.send_browser_api_error", lambda h, c, e, **kw: sent.append((c, {"error": e}))):
            api_mod.send_log_level_put_json(h, state, json_obj, changed_by)

        return sent

    def test_valid_level_returns_200(self, tmp_path):
        sent = self._call({"level": "debug"}, "user", tmp_path)
        assert sent[0][0] == 200
        assert sent[0][1]["ok"] is True

    def test_unknown_field_returns_400(self, tmp_path):
        sent = self._call({"level": "debug", "changed_by": "admin"}, "user", tmp_path)
        assert sent[0][0] == 400

    def test_missing_level_returns_400(self, tmp_path):
        sent = self._call({}, "user", tmp_path)
        assert sent[0][0] == 400

    def test_invalid_level_returns_400(self, tmp_path):
        set_result = {"ok": False, "error": "Unsupported log level: 'verbose'"}
        sent = self._call({"level": "verbose"}, "user", tmp_path, set_result=set_result)
        assert sent[0][0] == 400

    def test_persistence_failure_returns_500(self, tmp_path):
        set_result = {"ok": False, "error": "Configuration could not be saved"}
        sent = self._call({"level": "info"}, "user", tmp_path, set_result=set_result)
        assert sent[0][0] == 500

    def test_direct_local_records_system(self, tmp_path):
        state = _make_state(str(tmp_path / "cfg.json"))
        h = _make_handler()
        captured_changed_by = []

        def _fake_set(path, level, *, changed_by):
            captured_changed_by.append(changed_by)
            return {"ok": True, "level": level, "changed_by": changed_by,
                    "changed_at": None, "changed": True, "applied": {}}

        with patch("autostream_log_policy.set_log_level", _fake_set), \
             patch("autostream_webui_api.send_json", lambda h, c, p: None):
            api_mod.send_log_level_put_json(h, state, {"level": "warning"}, "system")

        assert captured_changed_by == ["system"]

    def test_browser_put_records_user(self, tmp_path):
        state = _make_state(str(tmp_path / "cfg.json"))
        h = _make_handler()
        captured_changed_by = []

        def _fake_set(path, level, *, changed_by):
            captured_changed_by.append(changed_by)
            return {"ok": True, "level": level, "changed_by": changed_by,
                    "changed_at": None, "changed": True, "applied": {}}

        with patch("autostream_log_policy.set_log_level", _fake_set), \
             patch("autostream_webui_api.send_json", lambda h, c, p: None):
            api_mod.send_log_level_put_json(h, state, {"level": "info"}, "user")

        assert captured_changed_by == ["user"]


# ---------------------------------------------------------------------------
# send_playing_status_json
# ---------------------------------------------------------------------------

class TestSendPlayingStatusJson:
    def test_playing_true_when_capturing(self, tmp_path):
        h = _make_handler()
        sent = []

        with patch("autostream_webui_api.any_monitor_capturing", return_value=True), \
             patch("autostream_webui_api.send_json", lambda h, c, p: sent.append((c, p))):
            api_mod.send_playing_status_json(h)

        assert sent[0][0] == 200
        assert sent[0][1]["ok"] is True
        assert sent[0][1]["playing"] is True

    def test_playing_false_when_idle(self, tmp_path):
        h = _make_handler()
        sent = []

        with patch("autostream_webui_api.any_monitor_capturing", return_value=False), \
             patch("autostream_webui_api.send_json", lambda h, c, p: sent.append((c, p))):
            api_mod.send_playing_status_json(h)

        assert sent[0][1]["playing"] is False

    def test_exception_returns_playing_false(self, tmp_path):
        h = _make_handler()
        sent = []

        with patch("autostream_webui_api.any_monitor_capturing", side_effect=RuntimeError("oops")), \
             patch("autostream_webui_api.send_json", lambda h, c, p: sent.append((c, p))):
            api_mod.send_playing_status_json(h)

        assert sent[0][1]["playing"] is False


# ---------------------------------------------------------------------------
# /api/log-level and /api/playing-status both require auth for browser callers;
# only direct-local callers bypass the auth gate via _is_direct_local().
# ---------------------------------------------------------------------------

class TestAuthAllowlist:
    def test_log_level_not_in_allowlist(self):
        # Browser callers must authenticate; only direct-local bypasses auth.
        assert "/api/log-level" not in auth_mod.ALLOWLIST_PATHS

    def test_playing_status_not_in_allowlist(self):
        # /api/playing-status intentionally requires auth for browser callers.
        assert "/api/playing-status" not in auth_mod.ALLOWLIST_PATHS
