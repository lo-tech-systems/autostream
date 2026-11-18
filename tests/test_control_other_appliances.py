"""test_control_other_appliances.py — tests for the control_other_appliances feature.

Covers:
  - Config: parse_config defaults and explicit values for control_other_appliances
  - Selector: build_appliance_selector_html display_only mode
  - Setup POST: sentinel-controlled persistence and hostname-off enforcement
  - Remote page guard: GET /a/<id>/ redirects when control disabled
  - Local Home: the page tells its script whether other appliances may be controlled
"""
from __future__ import annotations

import io
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from _source_text import page_data, page_with_static

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_config as c
from webui.common import build_appliance_selector_html

try:
    from webui.server import ConfigWebHandler
    import webui.server as _webui
    _HAS_WEBUI = True
except ImportError:
    _HAS_WEBUI = False

from autostream_auth import AuthManager, PIN_STATUS_MISSING

_skip_webui = pytest.mark.skipif(
    not _HAS_WEBUI, reason="web server import chain unavailable"
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


def _make_post(path: str, body: bytes = b"") -> "ConfigWebHandler":
    h = ConfigWebHandler.__new__(ConfigWebHandler)
    h.path = path
    h.command = "POST"
    h.request_version = "HTTP/1.1"
    content_length = str(len(body))
    h.headers = {
        "Cookie": "",
        "X-Forwarded-For": "",
        "X-Real-IP": "",
        "Content-Length": content_length,
        "Content-Type": "application/x-www-form-urlencoded",
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
    h._csrf_token = "testcsrf"
    return h


# ---------------------------------------------------------------------------
# 1. Config parsing
# ---------------------------------------------------------------------------

class TestControlOtherAppliancesConfig:
    def test_defaults_to_true_when_absent(self):
        parsed = c.parse_config({})
        assert parsed.webui.control_other_appliances is True

    def test_explicit_false_parsed(self):
        parsed = c.parse_config({"webui": {"control_other_appliances": False}})
        assert parsed.webui.control_other_appliances is False

    def test_explicit_true_parsed(self):
        parsed = c.parse_config({"webui": {"control_other_appliances": True}})
        assert parsed.webui.control_other_appliances is True

    def test_truthy_string_coerced_to_true(self):
        parsed = c.parse_config({"webui": {"control_other_appliances": 1}})
        assert parsed.webui.control_other_appliances is True

    def test_falsy_zero_coerced_to_false(self):
        parsed = c.parse_config({"webui": {"control_other_appliances": 0}})
        assert parsed.webui.control_other_appliances is False


# ---------------------------------------------------------------------------
# 2. Selector display_only mode
# ---------------------------------------------------------------------------

_BOUND_ID = "a" * 20
_PEER_ID  = "b" * 20

_APPLIANCES = [
    {
        "id": _BOUND_ID,
        "hostname": "my-device",
        "is_bound": True,
        "home_path": "/",
        "equaliser_path": "/equaliser",
    },
    {
        "id": _PEER_ID,
        "hostname": "peer-device",
        "is_bound": False,
        "home_path": f"/a/{_PEER_ID}/",
        "equaliser_path": f"/a/{_PEER_ID}/equaliser",
    },
]


class TestSelectorDisplayOnly:
    def test_display_only_returns_span_not_dropdown(self):
        out = build_appliance_selector_html(
            _APPLIANCES, _BOUND_ID, "home", display_only=True
        )
        assert "<span" in out
        assert "appliance-selector-btn" in out
        # No interactive dropdown markup
        assert "appliance-selector-option" not in out
        assert "<a " not in out

    def test_display_only_shows_matching_hostname(self):
        out = build_appliance_selector_html(
            _APPLIANCES, _BOUND_ID, "home", display_only=True
        )
        assert "my-device" in out

    def test_display_only_shows_peer_hostname_when_peer_is_current(self):
        out = build_appliance_selector_html(
            _APPLIANCES, _PEER_ID, "home", display_only=True
        )
        assert "peer-device" in out

    def test_display_only_shows_autostream_when_id_unmatched(self):
        out = build_appliance_selector_html(
            _APPLIANCES, "z" * 20, "home", display_only=True
        )
        assert "autostream" in out

    def test_display_only_has_pointer_events_none(self):
        out = build_appliance_selector_html(
            _APPLIANCES, _BOUND_ID, "home", display_only=True
        )
        assert "pointer-events:none" in out

    def test_display_only_false_renders_interactive_selector(self):
        out = build_appliance_selector_html(
            _APPLIANCES, _BOUND_ID, "home", display_only=False
        )
        # Should contain the full dropdown structure
        assert "appliance-selector-option" in out

    def test_display_only_escapes_hostname(self):
        appliances = [{"id": _BOUND_ID, "hostname": "<script>", "is_bound": True,
                       "home_path": "/", "equaliser_path": "/equaliser"}]
        out = build_appliance_selector_html(appliances, _BOUND_ID, "home", display_only=True)
        assert "<script>" not in out
        assert "&lt;script&gt;" in out


# ---------------------------------------------------------------------------
# Remote page guard: /a/<id>/ redirects when control disabled
# ---------------------------------------------------------------------------

@_skip_webui
class TestRemotePageGuard:
    def test_disabled_control_redirects_with_302(self):
        mgr = _make_auth(pin=None)
        handler = _make_get(f"/a/{_REMOTE_ID}/")
        with patch("webui.session_state.AUTH", mgr), \
             patch("webui.session_state.STATE", MagicMock()), \
             patch("autostream_commissioning.is_commissioning_required", return_value=False), \
             patch("autostream_rpi.get_appliance_id", return_value=_LOCAL_ID), \
             patch("webui.common._effective_control_other_appliances", return_value=False):
            handler.do_GET()
        codes = [c for (c,) in [handler.send_response.call_args_list[i][0]
                                 for i in range(len(handler.send_response.call_args_list))]]
        assert 302 in codes

    def test_disabled_control_does_not_render_the_home_shell(self):
        mgr = _make_auth(pin=None)
        handler = _make_get(f"/a/{_REMOTE_ID}/")
        with patch("webui.session_state.AUTH", mgr), \
             patch("webui.session_state.STATE", MagicMock()), \
             patch("autostream_commissioning.is_commissioning_required", return_value=False), \
             patch("autostream_rpi.get_appliance_id", return_value=_LOCAL_ID), \
             patch("webui.common._effective_control_other_appliances", return_value=False), \
             patch("webui.browser.home.send_airplay_page") as stub:
            handler.do_GET()
        stub.assert_not_called()

    def test_enabled_control_serves_the_home_shell_for_the_appliance(self):
        from autostream_appliances import Resolution
        mgr = _make_auth(pin=None)
        handler = _make_get(f"/a/{_REMOTE_ID}/")
        peer = Resolution("remote", MagicMock(), MagicMock())
        with patch("webui.session_state.AUTH", mgr), \
             patch("webui.session_state.STATE", MagicMock()), \
             patch("autostream_commissioning.is_commissioning_required", return_value=False), \
             patch("autostream_rpi.get_appliance_id", return_value=_LOCAL_ID), \
             patch("webui.common._effective_control_other_appliances", return_value=True), \
             patch("webui.browser.home.resolve", return_value=peer), \
             patch("webui.browser.home.send_airplay_page") as stub:
            handler.do_GET()
        stub.assert_called_once()
        assert stub.call_args.kwargs["peer"] is peer

    def test_disabled_control_equaliser_also_redirects(self):
        mgr = _make_auth(pin=None)
        handler = _make_get(f"/a/{_REMOTE_ID}/equaliser")
        with patch("webui.session_state.AUTH", mgr), \
             patch("webui.session_state.STATE", MagicMock()), \
             patch("autostream_commissioning.is_commissioning_required", return_value=False), \
             patch("autostream_rpi.get_appliance_id", return_value=_LOCAL_ID), \
             patch("webui.common._effective_control_other_appliances", return_value=False), \
             patch("webui.browser.equaliser.send_equaliser_page") as stub:
            handler.do_GET()
        stub.assert_not_called()
        codes = [c for (c,) in [handler.send_response.call_args_list[i][0]
                                 for i in range(len(handler.send_response.call_args_list))]]
        assert 302 in codes

    def test_local_id_bypasses_guard(self):
        """GET /a/<local-id>/ always redirects to / — the guard must not block this path."""
        mgr = _make_auth(pin=None)
        handler = _make_get(f"/a/{_LOCAL_ID}/")
        with patch("webui.session_state.AUTH", mgr), \
             patch("webui.session_state.STATE", MagicMock()), \
             patch("autostream_commissioning.is_commissioning_required", return_value=False), \
             patch("autostream_rpi.get_appliance_id", return_value=_LOCAL_ID), \
             patch("webui.common._effective_control_other_appliances", return_value=False):
            handler.do_GET()
        # Should get a redirect (302 to /) regardless of the guard
        codes = [c for (c,) in [handler.send_response.call_args_list[i][0]
                                 for i in range(len(handler.send_response.call_args_list))]]
        assert 302 in codes


# ---------------------------------------------------------------------------
# Local Home: in-use output card HTML and navigation script
# ---------------------------------------------------------------------------

try:
    from webui.browser.home import send_airplay_page as _send_airplay_page
    _HAS_AIRPLAY = True
except ImportError:
    _HAS_AIRPLAY = False

_skip_airplay = pytest.mark.skipif(
    not (_HAS_WEBUI and _HAS_AIRPLAY),
    reason="webui.browser.home import chain unavailable",
)


@_skip_airplay
class TestLocalHomeControlFlag:
    """The local Home page tells its script whether other appliances may be controlled
    (the in-use card tap goes to the other appliance only then)."""

    def _render(self, effective_control: bool = True) -> str:
        handler = MagicMock()
        chunks: list[bytes] = []
        handler.wfile.write = lambda d: chunks.append(d)
        handler._csrf_token = "testcsrf"
        handler._pending_set_cookies = []

        auth = MagicMock()
        auth.get_csrf_token.return_value = "testcsrf"

        state = MagicMock()
        state.config_path = "dummy.ini"

        parsed = MagicMock()
        parsed.owntone.base_url = "http://localhost:3689"
        parsed.owntone.volume_percent = 20
        parsed.webui.show_master_volume = False
        parsed.webui.show_input_detail = False
        parsed.webui.show_hostname_on_home = effective_control
        parsed.webui.control_other_appliances = effective_control
        parsed.webui.hidden_outputs = []
        parsed.webui.dark_mode = False

        with patch("webui.common._config_snapshot", return_value=parsed),              patch("autostream_rpi.get_appliance_id", return_value=_LOCAL_ID),              patch("webui.browser.home.get_system_hostname", return_value="autostream"),              patch("webui.browser.home.get_setting", return_value=MagicMock(ok=True, value="2250")),              patch("webui.browser.home.build_top_banner_html", return_value=("", "")):
            _send_airplay_page(handler, state, auth)

        return page_with_static(b"".join(chunks).decode("utf-8", errors="replace"))

    def test_control_flag_true_when_enabled(self):
        html = self._render(effective_control=True)
        assert page_data(html)["prefs"]["control_other_appliances"] is True

    def test_control_flag_false_when_disabled(self):
        html = self._render(effective_control=False)
        assert page_data(html)["prefs"]["control_other_appliances"] is False

    def test_the_page_loads_its_module_and_no_script_of_the_old_page(self):
        html = self._render()
        assert "/static/page/home/home_main.js" in html
        assert "home_cards.js" not in html and "render_fragments.js" not in html
