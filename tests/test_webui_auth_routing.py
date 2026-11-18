"""Router-level POST authentication tests for ConfigWebHandler.

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
    from webui.server import ConfigWebHandler
    import webui.server as _webui
    _HAS_WEBUI = True
except ImportError:
    _HAS_WEBUI = False

from autostream_auth import AuthManager, Session, SESSION_COOKIE_NAME, PIN_STATUS_MISSING
from settings_fixtures import CONTROLS_OTHER_APPLIANCES, viewed_state

_skip_no_webui = pytest.mark.skipif(
    not _HAS_WEBUI, reason="web server import chain unavailable"
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
    ("/api/update/apply",   "webui.system.updates.run_updater"),
    ("/api/reboot",         "webui.system.power.reboot_system"),
    ("/api/factory-reset",  "webui.system.power.handle_factory_reset_post"),
    ("/api/settings/mdns-grace-period", "webui.browser.api_owntone.send_settings_mdns_grace_period_json"),
    ("/api/dial/authorize", "webui.dial.management.dispatch_dial_management_post"),
    ("/api/dial/recovery/arm", "webui.dial.management.dispatch_dial_management_post"),
    ("/api/dial/recovery/disarm", "webui.dial.management.dispatch_dial_management_post"),
]

# Public: an unauthenticated request with a valid CSRF token MUST reach the
# stub.  These routes are intentionally accessible to any trusted-LAN user
# and must not be gated by a PIN session.
_PUBLIC = [
    ("/api/service/reset",   "webui.browser.api_service.send_service_reset_json"),
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

        with patch("webui.session_state.AUTH", mgr), \
             patch("webui.session_state.STATE", viewed_state(CONTROLS_OTHER_APPLIANCES)), \
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

        with patch("webui.session_state.AUTH", mgr), \
             patch("webui.session_state.STATE", viewed_state(CONTROLS_OTHER_APPLIANCES)), \
             patch("autostream_commissioning.is_commissioning_required",
                   return_value=False), \
             patch(stub_target) as stub:
            handler.do_POST()

        stub.assert_called_once()


@_skip_no_webui
class TestRetiredFormRoutes:
    """Routes whose form POST was retired must no longer reach mutation handlers."""

    @pytest.mark.parametrize("path", ["/setup", "/owntone-setup"])
    def test_form_post_is_not_routed(self, path):
        """POST /setup and POST /owntone-setup are gone; settings autosave."""
        mgr = _make_manager()
        sess_token, csrf_token = _csrf_session(mgr)
        handler = _make_handler(path, sess_token, csrf_token)

        with patch("webui.session_state.AUTH", mgr),              patch("webui.session_state.STATE", viewed_state(CONTROLS_OTHER_APPLIANCES)),              patch("autostream_commissioning.is_commissioning_required", return_value=False):
            handler.do_POST()

        handler.send_error.assert_called_once_with(404, "Not found")

    def test_logs_post_returns_404(self):
        """POST /logs has been removed; log-level changes use PUT /api/log-level."""
        mgr = _make_manager()
        sess_token, csrf_token = _csrf_session(mgr)
        handler = _make_handler("/logs", sess_token, csrf_token)

        with patch("webui.session_state.AUTH", mgr), \
             patch("webui.session_state.STATE", viewed_state(CONTROLS_OTHER_APPLIANCES)), \
             patch("autostream_commissioning.is_commissioning_required", return_value=False):
            handler.do_POST()

        handler.send_error.assert_called_once_with(404, "Not found")


@_skip_no_webui
class TestFederationRoutesSkipBrowserAuth:
    """Federation routes must bypass browser auth/CSRF before reaching the handler."""

    def _make_post_handler(self, path: str, body: bytes = b"") -> "ConfigWebHandler":
        h = ConfigWebHandler.__new__(ConfigWebHandler)
        h.path = path
        h.command = "POST"
        h.request_version = "HTTP/1.1"
        h.headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "Authorization": "",
            "X-CSRF-Token": "",
            "Cookie": "",
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

    def test_federation_post_skips_csrf_with_pin_enabled(self):
        """A POST to a federation route must not trigger CSRF rejection."""
        import autostream_federation as fed
        with fed._lock:
            fed._sessions.clear()
            fed._rate.clear()
        mgr = _make_manager(pin="secret")
        handler = self._make_post_handler("/api/federation/v1/session")
        sent = []
        fake_cfg = MagicMock()
        fake_cfg.webui.advertise_appliance = True
        with patch("webui.session_state.AUTH", mgr), \
             patch("webui.session_state.STATE", viewed_state(CONTROLS_OTHER_APPLIANCES)), \
             patch("autostream_commissioning.is_commissioning_required", return_value=False), \
             patch("autostream_rpi.get_appliance_id", return_value="aabbccdd1122"), \
             patch("webui.common._config_snapshot", return_value=fake_cfg), \
             patch("webui.common.send_json", side_effect=lambda h, c, d: sent.append((c, d))):
            handler.do_POST()
        codes = [c for c, _ in sent]
        assert 403 not in codes, "Federation route must not return 403 CSRF error"

    def test_federation_post_does_not_call_validate_csrf(self):
        """validate_csrf must not be called for federation POST routes."""
        import autostream_federation as fed
        with fed._lock:
            fed._sessions.clear()
            fed._rate.clear()
        mgr = _make_manager(pin="secret")
        handler = self._make_post_handler("/api/federation/v1/session")
        with patch("webui.session_state.AUTH", mgr), \
             patch("webui.session_state.STATE", viewed_state(CONTROLS_OTHER_APPLIANCES)), \
             patch("autostream_commissioning.is_commissioning_required", return_value=False), \
             patch("autostream_rpi.get_appliance_id", return_value="aabbccdd1122"), \
             patch("webui.common.send_json"), \
             patch.object(mgr, "validate_csrf") as mock_csrf:
            handler.do_POST()
        mock_csrf.assert_not_called()


@_skip_no_webui
class TestGatewayRoutesAuth:
    """Gateway GET routes must bypass PIN auth; POST routes require CSRF only."""

    def _make_get(self, path: str) -> "ConfigWebHandler":
        import io
        h = ConfigWebHandler.__new__(ConfigWebHandler)
        h.path = path
        h.command = "GET"
        h.request_version = "HTTP/1.1"
        h.headers = {"Cookie": "", "X-Forwarded-For": "", "X-Real-IP": ""}
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

    def test_appliances_list_accessible_without_auth(self):
        """GET /api/appliances must not redirect even with PIN enabled."""
        mgr = _make_manager(pin="secret")
        handler = self._make_get("/api/appliances")
        redirect_codes = []
        handler.send_response = lambda c, *a: redirect_codes.append(c)
        with patch("webui.session_state.AUTH", mgr), \
             patch("webui.session_state.STATE", viewed_state(CONTROLS_OTHER_APPLIANCES)), \
             patch("autostream_commissioning.is_commissioning_required", return_value=False), \
             patch("webui.peer.gateway.send_appliances_json"):
            handler.do_GET()
        assert 302 not in redirect_codes, "Gateway list must not redirect to /auth"

    def test_gateway_home_accessible_without_auth(self):
        """GET /api/appliances/<id>/home must not redirect with PIN enabled."""
        mgr = _make_manager(pin="secret")
        handler = self._make_get("/api/appliances/aabbccdd1122334455aa/home")
        redirect_codes = []
        handler.send_response = lambda c, *a: redirect_codes.append(c)
        with patch("webui.session_state.AUTH", mgr), \
             patch("webui.session_state.STATE", viewed_state(CONTROLS_OTHER_APPLIANCES)), \
             patch("autostream_commissioning.is_commissioning_required", return_value=False), \
             patch("webui.peer.gateway.send_gateway_home_json"):
            handler.do_GET()
        assert 302 not in redirect_codes

    def test_requires_auth_returns_false_for_appliances(self):
        """AuthManager.requires_auth must return False for /api/appliances."""
        from autostream_auth import AuthManager
        mgr = AuthManager(config_path="dummy.ini")
        mgr._pin_loaded = True
        mgr._pin_value = "secret"
        mgr._pin_status = "ok"
        assert mgr.requires_auth("/api/appliances") is False

    def test_requires_auth_returns_false_for_appliances_id_home(self):
        """AuthManager.requires_auth must return False for /api/appliances/<id>/home."""
        from autostream_auth import AuthManager
        mgr = AuthManager(config_path="dummy.ini")
        mgr._pin_loaded = True
        mgr._pin_value = "secret"
        mgr._pin_status = "ok"
        assert mgr.requires_auth("/api/appliances/aabbccdd1122334455aa/home") is False

    def test_requires_auth_returns_false_for_appliances_id_equaliser(self):
        from autostream_auth import AuthManager
        mgr = AuthManager(config_path="dummy.ini")
        mgr._pin_loaded = True
        mgr._pin_value = "secret"
        mgr._pin_status = "ok"
        assert mgr.requires_auth("/api/appliances/aabbccdd1122334455aa/equaliser") is False

    @pytest.mark.parametrize("tail", ["state", "events", "intents/outputs.set"])
    def test_requires_auth_returns_false_for_the_peer_relay(self, tail):
        from autostream_auth import AuthManager
        mgr = AuthManager(config_path="dummy.ini")
        mgr._pin_loaded = True
        mgr._pin_value = "secret"
        mgr._pin_status = "ok"
        assert mgr.requires_auth(f"/api/v1/peers/aabbccdd1122334455aa/{tail}") is False


# ---------------------------------------------------------------------------
# /api/about/system — GET allowlist coverage (Test 18)
# ---------------------------------------------------------------------------

class TestAboutSystemAllowlist:
    """Unauthenticated GET to /api/about/system is allowed even with PIN enabled."""

    def test_requires_auth_returns_false_for_api_about_system(self):
        from autostream_auth import AuthManager
        mgr = AuthManager(config_path="dummy.ini")
        mgr._pin_loaded = True
        mgr._pin_value = "testpin"
        mgr._pin_status = "ok"
        assert mgr.requires_auth("/api/about/system") is False, (
            "/api/about/system must be in the allowlist so unauthenticated "
            "browsers can fetch system info on PIN-protected appliances"
        )
