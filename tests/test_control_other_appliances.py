"""test_control_other_appliances.py — tests for the control_other_appliances feature.

Covers:
  - Config: parse_config defaults and explicit values for control_other_appliances
  - Selector: build_appliance_selector_html display_only mode
  - Equaliser: .local suffix stripped from peer hostnames in selector list
  - Setup POST: sentinel-controlled persistence and hostname-off enforcement
  - Remote page guard: GET /a/<id>/ redirects when control disabled
  - Gateway guard: GET+POST /api/appliances/<id>/... returns 403 when disabled
  - Remote Home: Master Volume label includes remote hostname
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

from fake_store import FakeStore, fake_levels, fake_outputs_result, fake_playback
import autostream_config as c
from webui.common import build_appliance_selector_html

try:
    from autostream_webui import ConfigWebHandler
    import autostream_webui as _webui
    _HAS_WEBUI = True
except ImportError:
    _HAS_WEBUI = False

from autostream_auth import AuthManager, PIN_STATUS_MISSING

_skip_webui = pytest.mark.skipif(
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
# 3. Equaliser peer hostname .local stripping
# ---------------------------------------------------------------------------

class TestEquiliserLocalStripping:
    def _build(self, peers):
        """Call _build_eq_appliances_for_selector with mocked dependencies."""
        from autostream_webui_page_equaliser import _build_eq_appliances_for_selector

        peer_objs = []
        for (pid, phostname) in peers:
            s = MagicMock()
            s.id = pid
            s.hostname = phostname
            peer_objs.append(s)

        with patch("autostream_rpi.get_appliance_id", return_value=_BOUND_ID), \
             patch("autostream_webui_page_equaliser.get_system_hostname", return_value="my-device"), \
             patch("autostream_webui_page_equaliser.get_all_appliances", return_value=peer_objs):
            return _build_eq_appliances_for_selector()

    def test_peer_local_suffix_stripped(self):
        result = self._build([(_PEER_ID, "peer.local")])
        peer = next(r for r in result if r["id"] == _PEER_ID)
        assert peer["hostname"] == "peer"

    def test_peer_local_suffix_case_insensitive(self):
        result = self._build([(_PEER_ID, "Peer.LOCAL")])
        peer = next(r for r in result if r["id"] == _PEER_ID)
        assert peer["hostname"] == "Peer"

    def test_peer_without_local_suffix_unchanged(self):
        result = self._build([(_PEER_ID, "peer-device")])
        peer = next(r for r in result if r["id"] == _PEER_ID)
        assert peer["hostname"] == "peer-device"

    def test_bound_local_suffix_also_stripped(self):
        from autostream_webui_page_equaliser import _build_eq_appliances_for_selector
        with patch("autostream_rpi.get_appliance_id", return_value=_BOUND_ID), \
             patch("autostream_webui_page_equaliser.get_system_hostname",
                   return_value="my-device.local"), \
             patch("autostream_webui_page_equaliser.get_all_appliances", return_value=[]):
            result = _build_eq_appliances_for_selector()
        bound = result[0]
        assert bound["hostname"] == "my-device"

    def test_empty_peer_hostname_falls_back_to_autostream(self):
        result = self._build([(_PEER_ID, "")])
        peer = next(r for r in result if r["id"] == _PEER_ID)
        assert peer["hostname"] == "autostream"


# ---------------------------------------------------------------------------
# 5. Remote page guard: /a/<id>/ redirects when control disabled
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

    def test_disabled_control_does_not_call_send_remote_home_page(self):
        mgr = _make_auth(pin=None)
        handler = _make_get(f"/a/{_REMOTE_ID}/")
        with patch("webui.session_state.AUTH", mgr), \
             patch("webui.session_state.STATE", MagicMock()), \
             patch("autostream_commissioning.is_commissioning_required", return_value=False), \
             patch("autostream_rpi.get_appliance_id", return_value=_LOCAL_ID), \
             patch("webui.common._effective_control_other_appliances", return_value=False), \
             patch("autostream_webui.send_remote_home_page") as stub:
            handler.do_GET()
        stub.assert_not_called()

    def test_enabled_control_calls_send_remote_home_page(self):
        mgr = _make_auth(pin=None)
        handler = _make_get(f"/a/{_REMOTE_ID}/")
        with patch("webui.session_state.AUTH", mgr), \
             patch("webui.session_state.STATE", MagicMock()), \
             patch("autostream_commissioning.is_commissioning_required", return_value=False), \
             patch("autostream_rpi.get_appliance_id", return_value=_LOCAL_ID), \
             patch("webui.common._effective_control_other_appliances", return_value=True), \
             patch("autostream_webui.send_remote_home_page") as stub:
            handler.do_GET()
        stub.assert_called_once()

    def test_disabled_control_equaliser_also_redirects(self):
        mgr = _make_auth(pin=None)
        handler = _make_get(f"/a/{_REMOTE_ID}/equaliser")
        with patch("webui.session_state.AUTH", mgr), \
             patch("webui.session_state.STATE", MagicMock()), \
             patch("autostream_commissioning.is_commissioning_required", return_value=False), \
             patch("autostream_rpi.get_appliance_id", return_value=_LOCAL_ID), \
             patch("webui.common._effective_control_other_appliances", return_value=False), \
             patch("autostream_webui.send_remote_equaliser_page") as stub:
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
# 6. Gateway API guard: GET /api/appliances/<id>/... returns 403 when disabled
# ---------------------------------------------------------------------------

@_skip_webui
class TestGatewayGetGuard:
    def test_disabled_returns_403_for_remote_home(self):
        mgr = _make_auth(pin=None)
        handler = _make_get(f"/api/appliances/{_REMOTE_ID}/home")
        sent_json_calls = []

        def fake_send_json(h, code, data):
            sent_json_calls.append((code, data))

        with patch("webui.session_state.AUTH", mgr), \
             patch("webui.session_state.STATE", MagicMock()), \
             patch("autostream_commissioning.is_commissioning_required", return_value=False), \
             patch("autostream_rpi.get_appliance_id", return_value=_LOCAL_ID), \
             patch("webui.common._effective_control_other_appliances", return_value=False), \
             patch("webui.common.send_json", side_effect=fake_send_json):
            handler.do_GET()

        assert any(code == 403 for code, _ in sent_json_calls)

    def test_disabled_returns_control_disabled_error(self):
        mgr = _make_auth(pin=None)
        handler = _make_get(f"/api/appliances/{_REMOTE_ID}/equaliser")
        sent_json_calls = []

        def fake_send_json(h, code, data):
            sent_json_calls.append((code, data))

        with patch("webui.session_state.AUTH", mgr), \
             patch("webui.session_state.STATE", MagicMock()), \
             patch("autostream_commissioning.is_commissioning_required", return_value=False), \
             patch("autostream_rpi.get_appliance_id", return_value=_LOCAL_ID), \
             patch("webui.common._effective_control_other_appliances", return_value=False), \
             patch("webui.common.send_json", side_effect=fake_send_json):
            handler.do_GET()

        errors = [d.get("error") for _, d in sent_json_calls if _ == 403]
        assert "control_disabled" in errors

    def test_enabled_does_not_block_remote_home(self):
        mgr = _make_auth(pin=None)
        handler = _make_get(f"/api/appliances/{_REMOTE_ID}/home")
        sent_json_calls = []

        def fake_send_json(h, code, data):
            sent_json_calls.append((code, data))

        with patch("webui.session_state.AUTH", mgr), \
             patch("webui.session_state.STATE", MagicMock()), \
             patch("autostream_commissioning.is_commissioning_required", return_value=False), \
             patch("autostream_rpi.get_appliance_id", return_value=_LOCAL_ID), \
             patch("webui.common._effective_control_other_appliances", return_value=True), \
             patch("autostream_webui.send_gateway_home_json", side_effect=fake_send_json), \
             patch("webui.common.send_json", side_effect=fake_send_json):
            handler.do_GET()

        assert not any(code == 403 for code, _ in sent_json_calls)

    def test_local_id_bypasses_gateway_guard(self):
        """Requests for the local appliance's own gateway must always succeed."""
        mgr = _make_auth(pin=None)
        handler = _make_get(f"/api/appliances/{_LOCAL_ID}/home")
        sent_json_calls = []

        def fake_send_json(h, code, data):
            sent_json_calls.append((code, data))

        with patch("webui.session_state.AUTH", mgr), \
             patch("webui.session_state.STATE", MagicMock()), \
             patch("autostream_commissioning.is_commissioning_required", return_value=False), \
             patch("autostream_rpi.get_appliance_id", return_value=_LOCAL_ID), \
             patch("webui.common._effective_control_other_appliances", return_value=False), \
             patch("autostream_webui.send_gateway_home_json", side_effect=fake_send_json), \
             patch("webui.common.send_json", side_effect=fake_send_json):
            handler.do_GET()

        assert not any(code == 403 for code, _ in sent_json_calls)


@_skip_webui
class TestGatewayPostGuard:
    def test_disabled_post_returns_403(self):
        mgr = _make_auth(pin=None)
        body = b"csrf_token=testcsrf&volume=50"
        handler = _make_post(f"/api/appliances/{_REMOTE_ID}/output", body)
        sent_json_calls = []

        def fake_send_json(h, code, data):
            sent_json_calls.append((code, data))

        with patch("webui.session_state.AUTH", mgr), \
             patch("webui.session_state.STATE", MagicMock()), \
             patch("autostream_commissioning.is_commissioning_required", return_value=False), \
             patch("autostream_rpi.get_appliance_id", return_value=_LOCAL_ID), \
             patch("webui.common._effective_control_other_appliances", return_value=False), \
             patch("webui.common.send_json", side_effect=fake_send_json):
            # Patch CSRF to pass so routing reaches the guard
            mgr.validate_csrf = MagicMock(return_value=True)
            handler.do_POST()

        assert any(code == 403 for code, _ in sent_json_calls)

    def test_disabled_post_returns_403_for_repeat(self):
        mgr = _make_auth(pin=None)
        body = b'{"armed": true}'
        handler = _make_post(f"/api/appliances/{_REMOTE_ID}/repeat", body)
        handler.headers["Content-Type"] = "application/json"
        sent_json_calls = []

        def fake_send_json(h, code, data):
            sent_json_calls.append((code, data))

        with patch("webui.session_state.AUTH", mgr), \
             patch("webui.session_state.STATE", MagicMock()), \
             patch("autostream_commissioning.is_commissioning_required", return_value=False), \
             patch("autostream_rpi.get_appliance_id", return_value=_LOCAL_ID), \
             patch("webui.common._effective_control_other_appliances", return_value=False), \
             patch("webui.common.send_json", side_effect=fake_send_json):
            mgr.validate_csrf = MagicMock(return_value=True)
            handler.do_POST()

        assert any(code == 403 for code, _ in sent_json_calls)


# ---------------------------------------------------------------------------
# 7. Remote Home: Master Volume label includes remote hostname
# ---------------------------------------------------------------------------

@_skip_webui
class TestRemoteHomeMasterVolumeLabel:
    def _render(self, remote_hostname: str = "music-room") -> str:
        from autostream_webui_page_airplay import send_remote_home_page

        state = MagicMock()
        state.config_path = "dummy.ini"
        handler = MagicMock()
        written_chunks = []
        handler.wfile.write = lambda data: written_chunks.append(data)
        handler._csrf_token = "testcsrf"
        handler._pending_set_cookies = []

        remote_appliance = {
            "id": _REMOTE_ID,
            "hostname": remote_hostname,
            "is_bound": False,
            "home_path": f"/a/{_REMOTE_ID}/",
            "equaliser_path": f"/a/{_REMOTE_ID}/equaliser",
        }
        local_appliance = {
            "id": _LOCAL_ID,
            "hostname": "local-host",
            "is_bound": True,
            "home_path": "/",
            "equaliser_path": "/equaliser",
        }

        parsed = MagicMock()
        parsed.owntone.volume_percent = 20
        parsed.webui.dark_mode = False
        parsed.webui.show_hostname_on_home = False
        parsed.webui.control_other_appliances = False
        with patch("webui.common._config_snapshot", return_value=parsed), \
             patch("autostream_rpi.get_appliance_id", return_value=_LOCAL_ID), \
             patch("autostream_webui_page_airplay._build_appliances_for_selector",
                   return_value=[local_appliance, remote_appliance]), \
             patch("autostream_webui_page_airplay.get_system_hostname", return_value="local-host"):
            send_remote_home_page(handler, state, _REMOTE_ID)

        return page_with_static(b"".join(written_chunks).decode("utf-8", errors="replace"))

    def test_master_volume_label_is_plain(self):
        html = self._render("music-room")
        assert "Master Volume" in html
        assert "Master Volume (music-room)" not in html

    def test_hostname_appears_in_now_playing_header(self):
        html = self._render("music-room")
        assert "music-room" in html
        assert "now-playing-hdr" in html or "np-hdr" in html

    def test_hostname_escaped_in_now_playing_header(self):
        html = self._render("<script>")
        assert "&lt;script&gt;" in html


# ---------------------------------------------------------------------------
# 8. Local Home: in-use output card HTML and navigation script
# ---------------------------------------------------------------------------

try:
    from autostream_webui_page_airplay import send_airplay_page as _send_airplay_page
    _HAS_AIRPLAY = True
except ImportError:
    _HAS_AIRPLAY = False

_skip_airplay = pytest.mark.skipif(
    not (_HAS_WEBUI and _HAS_AIRPLAY),
    reason="autostream_webui_page_airplay import chain unavailable",
)


@_skip_airplay
class TestLocalHomeInUseCardHTML:
    """Local Home page HTML when an output is occupied by a remote appliance."""

    _IN_USE_OUTPUT = {
        "id": "output-abc",
        "name": "Dining Room",
        "selected": False,
        "volume": 50,
        "is_default": False,
        "remote_in_use": True,
        "remote_owner": "Pi5",
    }

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
        parsed.owntone.output_name = "autostream"
        parsed.owntone.volume_percent = 20
        parsed.webui.show_master_volume = False
        parsed.webui.show_input_detail = False
        parsed.webui.show_hostname_on_home = effective_control
        parsed.webui.control_other_appliances = effective_control
        parsed.webui.hidden_outputs = []
        parsed.webui.dark_mode = False
        parsed.track_identification = MagicMock(enabled=False)

        playback = MagicMock()
        playback.inputs = {}
        playback.stylus_banner_text = ""
        playback.belt_banner_text = ""
        playback.bearing_banner_text = ""
        playback.has_warning = False
        playback.to_public_dict.return_value = {}

        list_result = MagicMock(ok=True, outputs=[FakeStore.output_row("1", "Kitchen")])
        buf_result = MagicMock(ok=True, value="2250")

        with patch("webui.common._config_snapshot", return_value=parsed), \
             patch("autostream_rpi.get_appliance_id", return_value=_LOCAL_ID), \
             patch("autostream_webui_page_airplay.get_all_appliances", return_value=[]), \
             patch("autostream_webui_page_airplay.get_system_hostname", return_value="autostream"), \
             fake_levels([]), \
             fake_playback(playback), \
             fake_outputs_result(list_result), \
             patch("autostream_webui_page_airplay.build_output_list",
                   return_value=[self._IN_USE_OUTPUT]), \
             patch("autostream_output_usage.annotate_outputs", side_effect=lambda x: x), \
             patch("autostream_webui_page_airplay.get_setting", return_value=buf_result), \
             patch("autostream_webui_page_airplay.build_top_banner_html",
                   return_value=("", "")):
            _send_airplay_page(handler, state, auth)

        return page_with_static(b"".join(chunks).decode("utf-8", errors="replace"))

    def test_in_use_card_has_data_remote_in_use_attribute(self):
        html = self._render()
        assert 'data-remote-in-use="1"' in html

    def test_in_use_card_has_data_remote_owner_attribute(self):
        html = self._render()
        assert 'data-remote-owner="Pi5"' in html

    def test_in_use_chip_has_in_use_class(self):
        html = self._render()
        assert "output-state-chip in-use" in html

    def test_in_use_chip_shows_owner_hostname(self):
        html = self._render()
        assert "In Use by Pi5" in html

    def test_page_contains_navigate_script(self):
        """navigateToRemoteAppliance must be present (via _NAVIGATE_SCRIPT)."""
        html = self._render()
        assert "navigateToRemoteAppliance" in html

    def test_control_flag_true_when_enabled(self):
        html = self._render(effective_control=True)
        assert page_data(html)["control_other_appliances"] is True

    def test_control_flag_false_when_disabled(self):
        html = self._render(effective_control=False)
        assert page_data(html)["control_other_appliances"] is False
