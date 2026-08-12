"""test_appliance_routing.py — end-to-end routing tests for gateway endpoints.

Verifies that do_GET and do_POST in ConfigWebHandler route /api/appliances*
correctly through the gateway module, that auth is NOT required for these
routes (even when a PIN is configured), and that POST mutations require a
valid CSRF token.
"""
from __future__ import annotations

import io
import json
import secrets
import sys
import time
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

try:
    from autostream_webui import ConfigWebHandler
    import autostream_webui as _webui
    _HAS_WEBUI = True
except ImportError:
    _HAS_WEBUI = False

from autostream_auth import AuthManager, Session, SESSION_COOKIE_NAME, PIN_STATUS_MISSING

_skip = pytest.mark.skipif(
    not _HAS_WEBUI, reason="autostream_webui import chain unavailable"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_auth(pin: Optional[str] = "testpin") -> AuthManager:
    mgr = AuthManager(config_path="dummy.ini")
    mgr._pin_loaded = True
    if pin is not None:
        mgr._pin_value = pin
        mgr._pin_status = "ok"
    else:
        mgr._pin_value = None
        mgr._pin_status = PIN_STATUS_MISSING
    return mgr


def _csrf_session(mgr: AuthManager) -> tuple[str, str]:
    sess_token = secrets.token_hex(32)
    csrf_token = secrets.token_hex(32)
    mgr._sessions[sess_token] = Session(
        token=sess_token,
        expires_at=int(time.time()) + 3600,
        csrf_token=csrf_token,
        authenticated=False,
    )
    return sess_token, csrf_token


def _make_get_handler(path: str) -> ConfigWebHandler:
    h = ConfigWebHandler.__new__(ConfigWebHandler)
    h.path = path
    h.command = "GET"
    h.request_version = "HTTP/1.1"
    h.headers = {
        "Cookie": "",
        "X-Forwarded-For": "",
        "X-Real-IP": "",
    }
    h.client_address = ("127.0.0.1", 0)
    h.rfile = io.BytesIO(b"")
    h.wfile = io.BytesIO()
    h.send_response = MagicMock()
    h.send_header = MagicMock()
    h.end_headers = MagicMock()
    h.send_error = MagicMock()
    h._pending_auth_cookie = None
    h._pending_set_cookies = []
    return h


def _make_post_handler(
    path: str,
    sess_token: str = "",
    csrf_token: str = "",
    body: bytes = b"{}",
) -> ConfigWebHandler:
    h = ConfigWebHandler.__new__(ConfigWebHandler)
    h.path = path
    h.command = "POST"
    h.request_version = "HTTP/1.1"
    h.headers = {
        "Cookie": f"{SESSION_COOKIE_NAME}={sess_token}" if sess_token else "",
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
        "X-CSRF-Token": csrf_token,
        "X-Forwarded-For": "",
        "X-Real-IP": "",
    }
    h.client_address = ("127.0.0.1", 0)
    h.rfile = io.BytesIO(body)
    h.wfile = io.BytesIO()
    h.send_response = MagicMock()
    h.send_header = MagicMock()
    h.end_headers = MagicMock()
    h.send_error = MagicMock()
    h._pending_auth_cookie = None
    h._pending_set_cookies = []
    return h


# ---------------------------------------------------------------------------
# GET /api/appliances — list endpoint
# ---------------------------------------------------------------------------

@_skip
class TestGetAppliances:
    def test_routes_to_send_appliances_json(self):
        mgr = _make_auth(pin="secret")
        handler = _make_get_handler("/api/appliances")

        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.send_appliances_json") as stub:
            handler.do_GET()

        stub.assert_called_once()

    def test_no_auth_redirect_with_pin_enabled(self):
        """GET /api/appliances must not redirect to /auth even when PIN is configured."""
        mgr = _make_auth(pin="secret")
        handler = _make_get_handler("/api/appliances")
        send_response_codes = []

        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.send_appliances_json"):
            handler.send_response = lambda c, *a: send_response_codes.append(c)
            handler.do_GET()

        assert 302 not in send_response_codes, "Should not redirect to /auth"


# ---------------------------------------------------------------------------
# GET /api/appliances/<id>/home
# ---------------------------------------------------------------------------

@_skip
class TestGetGatewayHome:
    def _call(self, aid: str):
        mgr = _make_auth(pin="secret")
        handler = _make_get_handler(f"/api/appliances/{aid}/home")
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.send_gateway_home_json") as stub:
            handler.do_GET()
        return stub

    def test_routes_to_send_gateway_home_json(self):
        stub = self._call("aabbccdd1122334455aa")
        stub.assert_called_once()

    def test_appliance_id_passed_correctly(self):
        aid = "1234567890abcdef1234"
        mgr = _make_auth(pin="secret")
        handler = _make_get_handler(f"/api/appliances/{aid}/home")
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.send_gateway_home_json") as stub:
            handler.do_GET()
        _, call_aid = stub.call_args[0][2], stub.call_args[0][2] if stub.call_args[0] else stub.call_args[1].get("appliance_id")
        assert aid in str(stub.call_args)

    def test_no_auth_required(self):
        """GET gateway home must not redirect unauthenticated requests."""
        mgr = _make_auth(pin="secret")
        handler = _make_get_handler("/api/appliances/aabbccdd1122334455aa/home")
        redirect_codes = []
        handler.send_response = lambda c, *a: redirect_codes.append(c)
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.send_gateway_home_json"):
            handler.do_GET()
        assert 302 not in redirect_codes


# ---------------------------------------------------------------------------
# GET /api/appliances/<id>/equaliser and /equaliser/status
# ---------------------------------------------------------------------------

@_skip
class TestGetGatewayEqualiser:
    def test_equaliser_routes_to_stub(self):
        aid = "aabbccdd1122334455aa"
        mgr = _make_auth(pin=None)
        handler = _make_get_handler(f"/api/appliances/{aid}/equaliser")
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.send_gateway_equaliser_json") as stub:
            handler.do_GET()
        stub.assert_called_once()

    def test_eq_status_routes_to_stub(self):
        aid = "aabbccdd1122334455aa"
        mgr = _make_auth(pin=None)
        handler = _make_get_handler(f"/api/appliances/{aid}/equaliser/status")
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.send_gateway_eq_status_json") as stub:
            handler.do_GET()
        stub.assert_called_once()

    def test_unknown_sub_path_returns_404(self):
        aid = "aabbccdd1122334455aa"
        mgr = _make_auth(pin=None)
        handler = _make_get_handler(f"/api/appliances/{aid}/unknown")
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False):
            handler.do_GET()
        handler.send_error.assert_called()


# ---------------------------------------------------------------------------
# POST mutations require CSRF
# ---------------------------------------------------------------------------

@_skip
class TestPostGatewayRequiresCsrf:
    def test_output_post_without_csrf_returns_403(self):
        aid = "aabbccdd1122334455aa"
        mgr = _make_auth(pin=None)  # no PIN, but CSRF still required
        # No session → CSRF fails
        body = json.dumps({"id": "out1", "selected": True, "volume": 50}).encode()
        handler = _make_post_handler(
            f"/api/appliances/{aid}/output",
            sess_token="",
            csrf_token="",
            body=body,
        )
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.send_gateway_output_json") as stub:
            handler.do_POST()
        stub.assert_not_called()

    def test_output_post_with_csrf_reaches_handler(self):
        aid = "aabbccdd1122334455aa"
        mgr = _make_auth(pin=None)
        sess_token, csrf_token = _csrf_session(mgr)
        body = json.dumps({"id": "out1", "selected": True, "volume": 50}).encode()
        handler = _make_post_handler(
            f"/api/appliances/{aid}/output",
            sess_token=sess_token,
            csrf_token=csrf_token,
            body=body,
        )
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.send_gateway_output_json") as stub:
            handler.do_POST()
        stub.assert_called_once()

    def test_eq_config_post_with_csrf_reaches_handler(self):
        aid = "aabbccdd1122334455aa"
        mgr = _make_auth(pin=None)
        sess_token, csrf_token = _csrf_session(mgr)
        body = json.dumps({"field": "gain_db", "value": "1.0"}).encode()
        handler = _make_post_handler(
            f"/api/appliances/{aid}/equaliser/config",
            sess_token=sess_token,
            csrf_token=csrf_token,
            body=body,
        )
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.send_gateway_eq_config_json") as stub:
            handler.do_POST()
        stub.assert_called_once()

    def test_eq_reset_post_with_csrf_reaches_handler(self):
        aid = "aabbccdd1122334455aa"
        mgr = _make_auth(pin=None)
        sess_token, csrf_token = _csrf_session(mgr)
        handler = _make_post_handler(
            f"/api/appliances/{aid}/equaliser/reset",
            sess_token=sess_token,
            csrf_token=csrf_token,
        )
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.send_gateway_eq_reset_json") as stub:
            handler.do_POST()
        stub.assert_called_once()

    def test_post_does_not_require_pin_auth(self):
        """Mutations must pass through with a valid CSRF but without PIN auth."""
        aid = "aabbccdd1122334455aa"
        mgr = _make_auth(pin="secret")  # PIN enabled
        sess_token, csrf_token = _csrf_session(mgr)  # session NOT authenticated
        body = json.dumps({"id": "out1", "selected": True, "volume": 50}).encode()
        handler = _make_post_handler(
            f"/api/appliances/{aid}/output",
            sess_token=sess_token,
            csrf_token=csrf_token,
            body=body,
        )
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.send_gateway_output_json") as stub:
            handler.do_POST()
        # Handler must be reached even without authenticated session
        stub.assert_called_once()


# ---------------------------------------------------------------------------
# Stale-session CSRF recovery on API posts
# ---------------------------------------------------------------------------

@_skip
class TestStaleCsrfRecovery:
    """A restart wipes the in-memory session table, so an already-open tab's
    first API POST fails CSRF validation. That 403 must carry a freshly
    minted session (cookie) and CSRF token so the page's fetch shim can
    transparently retry, instead of the click silently doing nothing."""

    def _post_output_with_stale_session(self):
        mgr = _make_auth(pin=None)
        # Cookie references a session the manager has never seen (restart).
        body = json.dumps({"id": "out1", "selected": True, "volume": 50}).encode()
        handler = _make_post_handler(
            "/api/output",
            sess_token="stale-token-from-before-the-restart",
            csrf_token="stale-csrf-from-the-old-page",
            body=body,
        )
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False):
            handler.do_POST()
        return mgr, handler

    def test_stale_session_gets_json_403_with_fresh_token(self):
        mgr, handler = self._post_output_with_stale_session()
        handler.send_response.assert_called_once_with(403)
        payload = json.loads(handler.wfile.getvalue().decode("utf-8"))
        assert payload["ok"] is False
        assert payload["error"] == "csrf_stale"
        # The token in the body must belong to a real, fresh session.
        fresh = [s for s in mgr._sessions.values()
                 if s.csrf_token == payload["csrf_token"]]
        assert len(fresh) == 1

    def test_stale_session_response_sets_fresh_cookie(self):
        mgr, handler = self._post_output_with_stale_session()
        cookie = handler._pending_auth_cookie
        assert cookie and SESSION_COOKIE_NAME in cookie
        token = cookie.split(f"{SESSION_COOKIE_NAME}=", 1)[1].split(";", 1)[0]
        assert token in mgr._sessions

    def test_non_api_post_keeps_plain_403(self):
        mgr = _make_auth(pin=None)
        handler = _make_post_handler(
            "/some-page", sess_token="stale", csrf_token="stale", body=b"{}",
        )
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False):
            handler.do_POST()
        handler.send_error.assert_called_once()
        assert handler.send_error.call_args[0][0] == 403
