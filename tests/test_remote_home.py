"""test_remote_home.py — tests for the remote Home route and page (/a/<id>/).

Covers:
  - Route dispatch: valid remote ID → send_remote_home_page
  - Canonical redirect: bound appliance ID → 302 to /
  - Format guard: invalid ID → 404
  - Auth: accessible without PIN session
  - Page content: appliance ID bootstrap, poll URL, output URL, selector widget
"""
from __future__ import annotations

import io
import sys
from pathlib import Path
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

from autostream_auth import AuthManager, PIN_STATUS_MISSING

_skip = pytest.mark.skipif(
    not _HAS_WEBUI, reason="autostream_webui import chain unavailable"
)

_REMOTE_ID = "aabbccdd1122334455aa"
_LOCAL_ID  = "00000000000000000000"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_auth(pin=None):
    mgr = AuthManager(config_path="dummy.ini")
    mgr._pin_loaded = True
    if pin is not None:
        mgr._pin_value = pin
        mgr._pin_status = "ok"
    else:
        mgr._pin_value = None
        mgr._pin_status = PIN_STATUS_MISSING
    return mgr


def _make_get(path: str) -> "ConfigWebHandler":
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


# ---------------------------------------------------------------------------
# Route dispatch
# ---------------------------------------------------------------------------

@_skip
class TestRemoteHomeRouting:
    """do_GET routes /a/<id>/ correctly."""

    def test_valid_remote_id_calls_send_remote_home_page(self):
        mgr = _make_auth(pin=None)
        handler = _make_get(f"/a/{_REMOTE_ID}/")
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.get_appliance_id", return_value=_LOCAL_ID), \
             patch("autostream_webui.send_remote_home_page") as stub:
            handler.do_GET()
        stub.assert_called_once()

    def test_valid_remote_id_no_trailing_slash(self):
        """Path /a/<id> (no trailing slash) should also route correctly."""
        mgr = _make_auth(pin=None)
        handler = _make_get(f"/a/{_REMOTE_ID}")
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.get_appliance_id", return_value=_LOCAL_ID), \
             patch("autostream_webui.send_remote_home_page") as stub:
            handler.do_GET()
        stub.assert_called_once()

    def test_bound_id_redirects_to_home(self):
        """GET /a/<local-id>/ must return 302 to /."""
        mgr = _make_auth(pin=None)
        handler = _make_get(f"/a/{_LOCAL_ID}/")
        redirect_locations = []
        handler.send_header = MagicMock(side_effect=lambda k, v: redirect_locations.append((k, v)))
        handler.send_response = MagicMock()
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.get_appliance_id", return_value=_LOCAL_ID):
            handler.do_GET()
        codes = [c for c, in [handler.send_response.call_args_list[i][0] for i in range(len(handler.send_response.call_args_list))]]
        assert 302 in codes
        locations = [v for k, v in redirect_locations if k == "Location"]
        assert "/" in locations

    def test_invalid_format_returns_404(self):
        """GET /a/invalid/ must return 404 — format guard."""
        mgr = _make_auth(pin=None)
        handler = _make_get("/a/invalid/")
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.get_appliance_id", return_value=_LOCAL_ID):
            handler.do_GET()
        handler.send_error.assert_called()

    def test_short_id_returns_404(self):
        """A valid-hex-but-short ID (< 20 chars) must 404."""
        mgr = _make_auth(pin=None)
        handler = _make_get("/a/aabb/")
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.get_appliance_id", return_value=_LOCAL_ID):
            handler.do_GET()
        handler.send_error.assert_called()

    def test_no_auth_redirect_with_pin_enabled(self):
        """GET /a/<remote-id>/ must not redirect even with PIN configured."""
        mgr = _make_auth(pin="secret")
        handler = _make_get(f"/a/{_REMOTE_ID}/")
        redirect_codes = []
        handler.send_response = MagicMock(side_effect=lambda c, *a: redirect_codes.append(c))
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.get_appliance_id", return_value=_LOCAL_ID), \
             patch("autostream_webui.send_remote_home_page"):
            handler.do_GET()
        assert 302 not in redirect_codes

    def test_remote_id_passed_to_handler(self):
        """The appliance_id argument passed to send_remote_home_page must match the URL."""
        mgr = _make_auth(pin=None)
        handler = _make_get(f"/a/{_REMOTE_ID}/")
        called_with = {}
        def _stub(h, s, aid):
            called_with["aid"] = aid
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.get_appliance_id", return_value=_LOCAL_ID), \
             patch("autostream_webui.send_remote_home_page", side_effect=_stub):
            handler.do_GET()
        assert called_with.get("aid") == _REMOTE_ID


# ---------------------------------------------------------------------------
# Auth allowlist
# ---------------------------------------------------------------------------

class TestRemoteHomeAuth:
    def test_requires_auth_returns_false_for_remote_page_path(self):
        from autostream_auth import AuthManager
        mgr = AuthManager(config_path="dummy.ini")
        mgr._pin_loaded = True
        mgr._pin_value = "secret"
        mgr._pin_status = "ok"
        assert mgr.requires_auth(f"/a/{_REMOTE_ID}/") is False

    def test_requires_auth_returns_false_for_bound_page_path(self):
        from autostream_auth import AuthManager
        mgr = AuthManager(config_path="dummy.ini")
        mgr._pin_loaded = True
        mgr._pin_value = "secret"
        mgr._pin_status = "ok"
        assert mgr.requires_auth(f"/a/{_LOCAL_ID}/") is False


# ---------------------------------------------------------------------------
# Page content (direct call to send_remote_home_page)
# ---------------------------------------------------------------------------

@_skip
class TestRemoteHomePageContent:
    """Verify that send_remote_home_page embeds required bootstrap variables."""

    def _render(self, aid: str = _REMOTE_ID) -> str:
        from autostream_webui_page_airplay import send_remote_home_page

        state = MagicMock()
        state.config_path = "dummy.ini"

        handler = MagicMock()
        buf = io.BytesIO()
        written_chunks = []

        def _write(data):
            written_chunks.append(data)

        handler.wfile.write = _write
        handler._csrf_token = "testcsrf"
        handler._pending_set_cookies = []

        parsed = MagicMock()
        parsed.owntone.volume_percent = 20
        parsed.webui.dark_mode = False
        parsed.webui.show_hostname_on_home = False
        parsed.webui.control_other_appliances = False
        with patch("autostream_webui_page_airplay._config_snapshot", return_value=parsed), \
             patch("autostream_webui_page_airplay.get_appliance_id", return_value=_LOCAL_ID), \
             patch("autostream_webui_page_airplay.get_all_appliances", return_value=[]), \
             patch("autostream_webui_page_airplay.get_system_hostname", return_value="bound-host"):
            send_remote_home_page(handler, state, aid)

        return b"".join(written_chunks).decode("utf-8", errors="replace")

    def test_page_returns_html(self):
        html = self._render()
        assert "<!DOCTYPE html>" in html or "<html" in html

    def test_page_contains_appliance_id_bootstrap(self):
        html = self._render()
        assert _REMOTE_ID in html

    def test_page_contains_poll_url(self):
        html = self._render()
        assert f"/api/appliances/{_REMOTE_ID}/home" in html

    def test_page_contains_output_url(self):
        html = self._render()
        assert f"/api/appliances/{_REMOTE_ID}/output" in html

    def test_page_contains_selector_widget(self):
        html = self._render()
        assert "appliance-selector" in html

    def test_page_contains_remote_polling_js(self):
        html = self._render()
        assert "pollHomeState" in html

    def test_page_has_remote_nav(self):
        """Remote Home page nav should have disabled Service/Setup/Info tabs."""
        html = self._render()
        assert "nav-tab-disabled" in html

    def test_page_has_outputs_list_placeholder(self):
        html = self._render()
        assert "outputs-list" in html

    def test_page_contains_navigate_to_remote_script(self):
        """navigateToRemoteAppliance must be present (via _NAVIGATE_SCRIPT)."""
        html = self._render()
        assert "navigateToRemoteAppliance" in html

    def test_page_contains_control_other_appliances_flag(self):
        """__CONTROL_OTHER_APPLIANCES JS global must be emitted in the page head."""
        html = self._render()
        assert "__CONTROL_OTHER_APPLIANCES" in html
