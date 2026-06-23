"""test_remote_equaliser.py — tests for the remote Equaliser route (/a/<id>/equaliser).

Covers:
  - Route dispatch: valid remote ID → send_remote_equaliser_page
  - Canonical redirect: bound appliance ID → 302 to /equaliser
  - Format guard: invalid ID → 404
  - Auth: accessible without PIN session
  - Page content: poll/save/reset/status URLs, selector widget, EQ curve, JS
"""
from __future__ import annotations

import ast
import io
import sys
from pathlib import Path
from types import SimpleNamespace
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
class TestRemoteEqualiserRouting:
    """do_GET routes /a/<id>/equaliser correctly."""

    def test_valid_remote_id_calls_send_remote_equaliser_page(self):
        mgr = _make_auth(pin=None)
        handler = _make_get(f"/a/{_REMOTE_ID}/equaliser")
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.get_appliance_id", return_value=_LOCAL_ID), \
             patch("autostream_webui.send_remote_equaliser_page") as stub:
            handler.do_GET()
        stub.assert_called_once()

    def test_remote_id_passed_correctly(self):
        mgr = _make_auth(pin=None)
        handler = _make_get(f"/a/{_REMOTE_ID}/equaliser")
        called_with = {}
        def _stub(h, s, aid):
            called_with["aid"] = aid
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.get_appliance_id", return_value=_LOCAL_ID), \
             patch("autostream_webui.send_remote_equaliser_page", side_effect=_stub):
            handler.do_GET()
        assert called_with.get("aid") == _REMOTE_ID

    def test_bound_id_redirects_to_equaliser(self):
        mgr = _make_auth(pin=None)
        handler = _make_get(f"/a/{_LOCAL_ID}/equaliser")
        redirect_locations = []
        handler.send_header = MagicMock(side_effect=lambda k, v: redirect_locations.append((k, v)))
        handler.send_response = MagicMock()
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.get_appliance_id", return_value=_LOCAL_ID):
            handler.do_GET()
        codes = [c for (c,) in [handler.send_response.call_args_list[i][0]
                                 for i in range(len(handler.send_response.call_args_list))]]
        assert 302 in codes
        locations = [v for k, v in redirect_locations if k == "Location"]
        assert "/equaliser" in locations

    def test_invalid_format_returns_404(self):
        mgr = _make_auth(pin=None)
        handler = _make_get("/a/invalid/equaliser")
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.get_appliance_id", return_value=_LOCAL_ID):
            handler.do_GET()
        handler.send_error.assert_called()

    def test_no_auth_redirect_with_pin_enabled(self):
        """GET /a/<remote-id>/equaliser must not redirect even with PIN configured."""
        mgr = _make_auth(pin="secret")
        handler = _make_get(f"/a/{_REMOTE_ID}/equaliser")
        redirect_codes = []
        handler.send_response = MagicMock(side_effect=lambda c, *a: redirect_codes.append(c))
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.get_appliance_id", return_value=_LOCAL_ID), \
             patch("autostream_webui.send_remote_equaliser_page"):
            handler.do_GET()
        assert 302 not in redirect_codes

    def test_home_route_still_dispatches_correctly(self):
        """The existing /a/<id>/ home routing must be unaffected."""
        mgr = _make_auth(pin=None)
        handler = _make_get(f"/a/{_REMOTE_ID}/")
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.get_appliance_id", return_value=_LOCAL_ID), \
             patch("autostream_webui.send_remote_home_page") as stub:
            handler.do_GET()
        stub.assert_called_once()


# ---------------------------------------------------------------------------
# Auth allowlist
# ---------------------------------------------------------------------------

class TestRemoteEqualiserAuth:
    def test_requires_auth_false_for_equaliser_path(self):
        from autostream_auth import AuthManager
        mgr = AuthManager(config_path="dummy.ini")
        mgr._pin_loaded = True
        mgr._pin_value = "secret"
        mgr._pin_status = "ok"
        assert mgr.requires_auth(f"/a/{_REMOTE_ID}/equaliser") is False


# ---------------------------------------------------------------------------
# Page content (direct call to send_remote_equaliser_page)
# ---------------------------------------------------------------------------

@_skip
class TestRemoteEqualiserPageContent:
    """Verify that send_remote_equaliser_page embeds required bootstrap variables."""

    def _render(self, aid: str = _REMOTE_ID) -> str:
        from autostream_webui_page_equaliser import send_remote_equaliser_page

        state = MagicMock()
        state.config_path = "dummy.ini"

        handler = MagicMock()
        written_chunks = []

        def _write(data):
            written_chunks.append(data)

        handler.wfile.write = _write
        handler._csrf_token = "testcsrf"
        handler._pending_set_cookies = []

        parsed = MagicMock()
        parsed.webui.dark_mode = False
        with patch("autostream_webui_page_equaliser._config_snapshot", return_value=parsed), \
             patch("autostream_webui_page_equaliser.get_appliance_id", return_value=_LOCAL_ID), \
             patch("autostream_webui_page_equaliser.get_all_appliances", return_value=[]), \
             patch("autostream_webui_page_equaliser.get_system_hostname", return_value="bound-host"):
            send_remote_equaliser_page(handler, state, aid)

        return b"".join(written_chunks).decode("utf-8", errors="replace")

    def test_page_returns_html(self):
        html = self._render()
        assert "<!DOCTYPE html>" in html or "<html" in html

    def test_page_contains_appliance_id(self):
        html = self._render()
        assert _REMOTE_ID in html

    def test_page_contains_poll_url(self):
        html = self._render()
        assert f"/api/appliances/{_REMOTE_ID}/equaliser" in html

    def test_page_contains_save_url(self):
        html = self._render()
        assert f"/api/appliances/{_REMOTE_ID}/equaliser/config" in html

    def test_page_contains_reset_url(self):
        html = self._render()
        assert f"/api/appliances/{_REMOTE_ID}/equaliser/reset" in html

    def test_page_contains_status_url(self):
        html = self._render()
        assert f"/api/appliances/{_REMOTE_ID}/equaliser/status" in html

    def test_page_contains_selector_widget(self):
        html = self._render()
        assert "appliance-selector" in html

    def test_page_header_contains_selector_without_flat_button(self):
        html = self._render()
        header_start = html.index("<div class='eq-page-header'>")
        header_end = html.index("<div class='eq-section'>", header_start)
        header = html[header_start:header_end]

        assert "appliance-selector" in header
        assert "eq-flat-btn" not in header
        assert ">Reset<" not in header

    def test_flat_button_is_inside_eq_card(self):
        html = self._render()
        flat_idx = html.index("id='eq-flat-btn'")
        section_idx = html.rindex("<div class='eq-section'>", 0, flat_idx)
        curve_idx = html.index("eq-curve-wrap", flat_idx)

        assert section_idx < flat_idx < curve_idx
        assert ">Flat</button>" in html
        assert "eq-reset-btn" not in html

    def test_page_has_remote_nav(self):
        html = self._render()
        assert "nav-tab-disabled" in html

    def test_page_has_eq_curve(self):
        html = self._render()
        assert "eq-curve" in html

    def test_page_has_bands_container(self):
        html = self._render()
        assert "eq-bands-container" in html

    def test_page_has_gain_section(self):
        html = self._render()
        assert "eq-gain-section" in html

    def test_remote_gain_card_has_no_gain_title(self):
        html = self._render()
        assert '<div class="eq-section-title">Gain</div>' not in html

    def test_page_has_loading_message(self):
        html = self._render()
        assert "eq-loading-msg" in html

    def test_page_has_render_eq_from_state_js(self):
        html = self._render()
        assert "renderEqFromState" in html

    def test_page_has_poll_trim_status_js(self):
        html = self._render()
        assert "_pollTrimStatus" in html

    def test_page_has_selector_js(self):
        html = self._render()
        assert "initApplianceSelector" in html

    def test_page_has_eq_band_config_js(self):
        """_EQ_BANDS must be defined so renderEqFromState can build sliders."""
        html = self._render()
        assert "_EQ_BANDS" in html

    def test_remote_eq_band_slider_handler_survives_python_string_escaping(self):
        """The browser-facing script must contain escaped quotes in generated slider handlers."""
        source = (REPO_ROOT / "core" / "autostream_webui_page_equaliser.py").read_text()
        module = ast.parse(source)
        script = None
        for node in module.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "_REMOTE_EQUALISER_SCRIPT":
                        script = ast.literal_eval(node.value)
                        break
            if script is not None:
                break

        assert script is not None
        assert "syncOutputPeq(\\''+key+'\\',this.value)" in script
        assert "syncOutputPeq(''+key+'',this.value)" not in script

    def test_remote_script_enables_flat_button(self):
        source = (REPO_ROOT / "core" / "autostream_webui_page_equaliser.py").read_text()
        module = ast.parse(source)
        script = None
        for node in module.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "_REMOTE_EQUALISER_SCRIPT":
                        script = ast.literal_eval(node.value)
                        break
            if script is not None:
                break

        assert script is not None
        assert "getElementById('eq-flat-btn')" in script
        assert "getElementById('eq-reset-btn')" not in script

    def test_local_equaliser_cards_match_flat_button_layout(self):
        from autostream_core import OUTPUT_PEQ_BANDS
        from autostream_webui_page_equaliser import _eq_cards_html

        values = {band["key"]: 0.0 for band in OUTPUT_PEQ_BANDS}
        output_eq = SimpleNamespace(
            gain_db=0.0,
            auto_trim_enabled=False,
            **values,
        )
        html = _eq_cards_html(output_eq, selector_html="<div id='appliance-selector'></div>")
        header_start = html.index("<div class='eq-page-header'>")
        header_end = html.index("<div class='eq-section'>", header_start)
        header = html[header_start:header_end]

        assert "appliance-selector" in header
        assert "eq-flat-btn" not in header
        assert "id='eq-flat-btn'" in html
        assert ">Flat</button>" in html
        assert ">Reset</button>" not in html
        assert "<div class='eq-section-title'>Gain</div>" not in html

    def test_page_active_tab_is_equaliser(self):
        html = self._render()
        assert "nav-tab-active" in html
        assert "nav-tab-disabled" in html
