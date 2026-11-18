"""test_appliance_routing.py — end-to-end routing tests for the remote page
path and the stale-session CSRF recovery of API posts.
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
    from webui.server import ConfigWebHandler
    import webui.server as _webui
    _HAS_WEBUI = True
except ImportError:
    _HAS_WEBUI = False

from autostream_auth import AuthManager, Session, SESSION_COOKIE_NAME, PIN_STATUS_MISSING
from settings_fixtures import CONTROLS_OTHER_APPLIANCES, viewed_state

_skip = pytest.mark.skipif(
    not _HAS_WEBUI, reason="web server import chain unavailable"
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
# GET /a/<id>/ with control of other appliances off
# ---------------------------------------------------------------------------

@_skip
class TestRemotePageWithControlOff:
    def test_another_appliances_page_answers_a_plain_redirect_home(self):
        other = "aabbccdd1122334455aa"
        mgr = _make_auth(pin=None)
        handler = _make_get_handler(f"/a/{other}/")
        codes, headers = [], []
        handler.send_response = lambda c, *a: codes.append(c)
        handler.send_header = lambda k, v: headers.append((k, v))
        with patch("webui.session_state.AUTH", mgr), \
             patch("webui.session_state.STATE", viewed_state()), \
             patch("autostream_appliance_identity.get_appliance_id", return_value="0" * 20), \
             patch("autostream_commissioning.is_commissioning_required", return_value=False), \
             patch("webui.browser.home.send_airplay_page") as remote_page:
            handler.do_GET()
        assert codes == [302]
        assert ("Location", "/") in headers
        assert not [h for h in headers if h[0] == "Set-Cookie"]
        assert handler._pending_set_cookies == []
        remote_page.assert_not_called()


# ---------------------------------------------------------------------------
# Stale-session CSRF recovery on API posts
# ---------------------------------------------------------------------------

@_skip
class TestStaleCsrfRecovery:
    """A restart wipes the in-memory session table, so an already-open tab's
    first API POST fails CSRF validation. That 403 must carry a freshly
    minted session (cookie) and CSRF token so the page's fetch shim can
    transparently retry, instead of the click silently doing nothing."""

    def _post_with_stale_session(self):
        mgr = _make_auth(pin=None)
        # Cookie references a session the manager has never seen (restart).
        body = json.dumps({"id": "out1", "selected": True, "volume": 50}).encode()
        handler = _make_post_handler(
            "/api/service/config",
            sess_token="stale-token-from-before-the-restart",
            csrf_token="stale-csrf-from-the-old-page",
            body=body,
        )
        with patch("webui.session_state.AUTH", mgr), \
             patch("webui.session_state.STATE", viewed_state(CONTROLS_OTHER_APPLIANCES)), \
             patch("autostream_commissioning.is_commissioning_required", return_value=False):
            handler.do_POST()
        return mgr, handler

    def test_stale_session_gets_json_403_with_fresh_token(self):
        mgr, handler = self._post_with_stale_session()
        handler.send_response.assert_called_once_with(403)
        payload = json.loads(handler.wfile.getvalue().decode("utf-8"))
        assert payload["ok"] is False
        assert payload["error"] == "csrf_stale"
        # The token in the body must belong to a real, fresh session.
        fresh = [s for s in mgr._sessions.values()
                 if s.csrf_token == payload["csrf_token"]]
        assert len(fresh) == 1

    def test_stale_session_response_sets_fresh_cookie(self):
        mgr, handler = self._post_with_stale_session()
        cookie = handler._pending_auth_cookie
        assert cookie and SESSION_COOKIE_NAME in cookie
        token = cookie.split(f"{SESSION_COOKIE_NAME}=", 1)[1].split(";", 1)[0]
        assert token in mgr._sessions

    def test_non_api_post_keeps_plain_403(self):
        mgr = _make_auth(pin=None)
        handler = _make_post_handler(
            "/some-page", sess_token="stale", csrf_token="stale", body=b"{}",
        )
        with patch("webui.session_state.AUTH", mgr), \
             patch("webui.session_state.STATE", viewed_state(CONTROLS_OTHER_APPLIANCES)), \
             patch("autostream_commissioning.is_commissioning_required", return_value=False):
            handler.do_POST()
        handler.send_error.assert_called_once()
        assert handler.send_error.call_args[0][0] == 403
