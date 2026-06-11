"""Router-level POST auth tests for ConfigWebHandler (WP15 review findings).

Exercises do_POST directly to verify that the protected/public route
classification is enforced at the router boundary, not just by the
require_authenticated_if_pin_enabled helper in isolation.

An unauthenticated request that carries a valid CSRF token is the key threat
model: public pages issue CSRF sessions to any visitor, so CSRF alone cannot
be used as an authentication signal.

Stubs 'requests' (via sys.modules) before importing the webui chain, using
the same pattern as test_updater_foundations.py uses for 'fcntl'.
"""
import io
import secrets
import sys
import time
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

try:
    from autostream_webui import ConfigWebHandler
    import autostream_webui as _webui
    _HAS_WEBUI = True
except ImportError:
    _HAS_WEBUI = False

from autostream_auth import AuthManager, Session, SESSION_COOKIE_NAME, PIN_STATUS_MISSING

_skip_no_webui = pytest.mark.skipif(
    not _HAS_WEBUI, reason="autostream_webui import chain unavailable"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_manager(pin: Optional[str] = "testpin1") -> AuthManager:
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
    """Add an unauthenticated CSRF session; return (session_token, csrf_token)."""
    sess_token = secrets.token_hex(32)
    csrf_token = secrets.token_hex(32)
    mgr._sessions[sess_token] = Session(
        token=sess_token,
        expires_at=int(time.time()) + 3600,
        csrf_token=csrf_token,
        authenticated=False,
    )
    return sess_token, csrf_token


def _make_handler(path: str, sess_token: str, csrf_token: str) -> "ConfigWebHandler":
    """Instantiate ConfigWebHandler without a real socket."""
    body = b'{"data": 1}'
    h = ConfigWebHandler.__new__(ConfigWebHandler)
    h.path = path
    h.command = "POST"
    h.request_version = "HTTP/1.1"
    h.headers = {
        "Cookie": f"{SESSION_COOKIE_NAME}={sess_token}",
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
# Route manifest
# ---------------------------------------------------------------------------

# Protected: an unauthenticated request with a valid CSRF token must NOT reach
# the stub.  The stub is the first downstream call that would be made if the
# auth guard were absent, so assert_not_called() proves the guard fired.
_PROTECTED = [
    ("/setup",              "autostream_webui.handle_setup_post"),
    ("/owntone-setup",      "autostream_webui.handle_owntone_setup_post"),
    ("/logs",               "autostream_webui.handle_logs_post"),
    ("/api/input_eq",       "autostream_webui.handle_live_input_eq_update"),
    ("/api/input_gain",     "autostream_webui.handle_live_input_gain_update"),
    ("/api/update/apply",   "autostream_webui.run_updater"),
    ("/api/reboot",         "autostream_webui.reboot_system"),
    ("/api/factory-reset",  "autostream_webui.handle_factory_reset_post"),
    ("/api/dial/authorize", "autostream_webui.dispatch_dial_management_post"),
]

# Public: an unauthenticated request with a valid CSRF token MUST reach the
# stub.  These routes are intentionally accessible to any trusted-LAN user
# and must not be gated by a PIN session.
_PUBLIC = [
    ("/api/output",          "autostream_webui.handle_output_update"),
    ("/api/output_eq/reset", "autostream_webui.send_output_eq_reset_json"),
    ("/api/service/reset",   "autostream_webui.send_service_reset_json"),
]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@_skip_no_webui
class TestPostRouterAuthEnforcement:
    """do_POST enforces the protected/public route classification."""

    @pytest.mark.parametrize(
        "path,stub_target", _PROTECTED, ids=[p for p, _ in _PROTECTED]
    )
    def test_protected_route_blocks_unauthenticated(self, path, stub_target):
        """Unauthenticated request with valid CSRF must not reach the handler."""
        mgr = _make_manager()
        sess_token, csrf_token = _csrf_session(mgr)
        handler = _make_handler(path, sess_token, csrf_token)

        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch(stub_target) as stub:
            handler.do_POST()

        stub.assert_not_called()

    @pytest.mark.parametrize(
        "path,stub_target", _PUBLIC, ids=[p for p, _ in _PUBLIC]
    )
    def test_public_route_allows_unauthenticated(self, path, stub_target):
        """Unauthenticated request with valid CSRF must reach the handler."""
        mgr = _make_manager()
        sess_token, csrf_token = _csrf_session(mgr)
        handler = _make_handler(path, sess_token, csrf_token)

        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch(stub_target) as stub:
            handler.do_POST()

        stub.assert_called_once()
