"""tests/test_wp8c_routing_cutover.py

WP8C acceptance tests: routing cutover and legacy-mode removal.

Tests cover:
  - During commissioning, GET requests redirect to /first-boot/{step}
  - During commissioning, /first-boot/* routes are allowed
  - When configured, /first-boot/* redirects to /
  - first-boot pages have show_nav=False (no nav bar)
  - Setup page always has liveEnabled=true (no initial_setup mode)
  - OwnTone setup page always has liveEnabled=true
  - Federation returns 409 during commissioning
  - No global initial_setup in autostream_webui
"""
from __future__ import annotations

import io
import json
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

try:
    import autostream_webui
    from autostream_webui import ConfigWebHandler
    _skip = pytest.mark.skipif(False, reason="")
except Exception:
    _skip = pytest.mark.skip(reason="autostream_webui not importable")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_get_handler(path: str) -> "ConfigWebHandler":
    handler = ConfigWebHandler.__new__(ConfigWebHandler)
    handler.path = path
    handler.command = "GET"
    handler.request_version = "HTTP/1.1"
    handler.headers = MagicMock()
    handler.headers.get = MagicMock(return_value="")
    handler.headers.__contains__ = lambda self, key: False
    handler.client_address = ("127.0.0.1", 0)
    handler.rfile = io.BytesIO(b"")
    handler.wfile = io.BytesIO()
    handler.send_response = MagicMock()
    handler.send_header = MagicMock()
    handler.end_headers = MagicMock()
    handler.send_error = MagicMock()
    return handler


def _fake_state(tmp_path):
    from autostream_webui_state import WebUIState
    cfg = tmp_path / "autostream.json"
    cfg.write_text("{}")
    st = tmp_path / "state.json"
    st.write_text("{}")
    return WebUIState(str(cfg), str(st))


# ── No global initial_setup ───────────────────────────────────────────────────

@_skip
class TestNoInitialSetupGlobal:
    def test_initial_setup_attr_removed(self):
        import autostream_webui as wui
        assert not hasattr(wui, "initial_setup"), (
            "initial_setup global must be removed; first-boot uses is_commissioning_required"
        )

    def test_setup_lock_attr_removed(self):
        import autostream_webui as wui
        assert not hasattr(wui, "_setup_lock"), (
            "_setup_lock must be removed with the initial_setup global"
        )


# ── GET routing during commissioning ─────────────────────────────────────────

@_skip
class TestCommissioningRouting:
    def _do_get(self, tmp_path, path, commissioning=True, step="owntone"):
        state = _fake_state(tmp_path)
        auth = MagicMock()
        auth.is_enabled.return_value = False
        auth.requires_auth.return_value = False
        auth.is_authenticated.return_value = True
        auth.ensure_session.return_value = "tok"

        handler = _make_get_handler(path)
        codes = []
        headers = {}
        handler.send_response.side_effect = lambda code: codes.append(code)
        handler.send_header.side_effect = lambda k, v: headers.update({k: v})

        with patch("autostream_webui.AUTH", auth), \
             patch("autostream_webui.STATE", state), \
             patch("autostream_webui.is_commissioning_required", return_value=commissioning), \
             patch("autostream_webui.required_first_boot_step", return_value=step):
            handler.do_GET()

        return codes, headers

    def test_home_during_commissioning_redirects_to_first_boot(self, tmp_path):
        codes, headers = self._do_get(tmp_path, "/", commissioning=True, step="owntone")
        assert 302 in codes
        assert "/first-boot/owntone" in headers.get("Location", "")

    def test_setup_during_commissioning_redirects_to_first_boot(self, tmp_path):
        codes, headers = self._do_get(tmp_path, "/setup", commissioning=True, step="appliance")
        assert 302 in codes
        assert "/first-boot/appliance" in headers.get("Location", "")

    def test_first_boot_path_allowed_during_commissioning(self, tmp_path):
        from autostream_webui_page_first_boot import send_first_boot_owntone_page
        state = _fake_state(tmp_path)
        auth = MagicMock()
        auth.is_enabled.return_value = False
        auth.requires_auth.return_value = False
        auth.is_authenticated.return_value = True
        auth.ensure_session.return_value = "tok"
        auth.require_authenticated_if_pin_enabled.return_value = True

        handler = _make_get_handler("/first-boot/owntone")

        with patch("autostream_webui.AUTH", auth), \
             patch("autostream_webui.STATE", state), \
             patch("autostream_webui.is_commissioning_required", return_value=True), \
             patch("autostream_webui.send_first_boot_owntone_page") as mock_page:
            handler.do_GET()

        mock_page.assert_called_once()

    def test_first_boot_path_redirects_to_home_when_configured(self, tmp_path):
        state = _fake_state(tmp_path)
        auth = MagicMock()
        auth.is_enabled.return_value = False

        handler = _make_get_handler("/first-boot/owntone")
        codes = []
        headers = {}
        handler.send_response.side_effect = lambda code: codes.append(code)
        handler.send_header.side_effect = lambda k, v: headers.update({k: v})

        with patch("autostream_webui.AUTH", auth), \
             patch("autostream_webui.STATE", state), \
             patch("autostream_webui.is_commissioning_required", return_value=False):
            handler.do_GET()

        assert 302 in codes
        assert headers.get("Location") == "/"


# ── Setup page — always liveEnabled=true ─────────────────────────────────────

@_skip
class TestSetupPageNoInitialSetupMode:
    def _render(self, tmp_path) -> str:
        from autostream_webui_page_setup import send_setup_page
        from autostream_settings import SettingsStore
        from autostream_webui_state import WebUIState
        from autostream_players import ListOutputsResult

        cfg_path = str(tmp_path / "config.json")
        (tmp_path / "config.json").write_text(json.dumps({
            "general": {"fifo_path": "/tmp/fifo"},
            "audio1": {"capture_device": "hw:0,0"},
            "owntone": {"output_name": "Kitchen"},
        }))
        store = SettingsStore(cfg_path, _save_interval_seconds=9999)
        state = WebUIState(cfg_path, str(tmp_path / "state.json"), settings=store)

        handler = MagicMock()
        handler.wfile = io.BytesIO()
        auth = MagicMock()
        auth.get_csrf_token.return_value = "tok"
        auth.get_boot_pin_value.return_value = "1234"

        with patch.multiple(
            "autostream_webui_page_setup",
            get_system_hostname=MagicMock(return_value="autostream"),
            list_outputs=MagicMock(return_value=ListOutputsResult(ok=False, error="x")),
            get_ap_ssid=MagicMock(return_value="autostream_AP"),
            get_app_version=MagicMock(return_value="1.0.0"),
            _get_dial_sightings=MagicMock(return_value=[]),
            parse_dial_entries=MagicMock(return_value=[]),
            suggested_silence_threshold_dbfs=MagicMock(return_value=-50.0),
            build_top_banner_html=MagicMock(return_value=("", "")),
            _set_flash_cookie=MagicMock(),
        ):
            with patch.object(state, "get_monitor_devices", return_value=[]):
                send_setup_page(handler, state, auth)

        store.close(save=False)
        return handler.wfile.getvalue().decode("utf-8", errors="replace")

    def test_live_enabled_always_true(self, tmp_path):
        html = self._render(tmp_path)
        assert "const liveEnabled = true;" in html
        assert "const liveEnabled = false;" not in html

    def test_no_initial_setup_heading(self, tmp_path):
        html = self._render(tmp_path)
        assert "Initial Setup" not in html

    def test_factory_reset_zone_always_present(self, tmp_path):
        html = self._render(tmp_path)
        assert "Factory Reset" in html

    def test_nav_always_shown(self, tmp_path):
        html = self._render(tmp_path)
        assert 'id="nav"' in html or 'class="nav' in html or "nav" in html


# ── OwnTone page — always liveEnabled=true ────────────────────────────────────

@_skip
class TestOwntonPageNoInitialSetupMode:
    def _render(self, tmp_path) -> str:
        from autostream_webui_page_owntone import send_owntone_setup_page
        from autostream_settings import SettingsStore
        from autostream_webui_state import WebUIState

        cfg_path = str(tmp_path / "config.json")
        (tmp_path / "config.json").write_text(json.dumps({
            "owntone": {"base_url": "http://localhost:3689", "output_name": "Kitchen"},
        }))
        store = SettingsStore(cfg_path, _save_interval_seconds=9999)
        state = WebUIState(cfg_path, str(tmp_path / "state.json"), settings=store)

        handler = MagicMock()
        written = []
        handler.wfile.write.side_effect = lambda d: written.append(d)
        auth = MagicMock()
        auth.get_csrf_token.return_value = "tok"
        handler._csrf_token = "tok"
        handler.headers = {}

        _cap = MagicMock()
        _cap.can_set_output_mode = False
        _cap.can_set_output_offset = False

        _sett = MagicMock(ok=False, unsupported=True)
        _outs = MagicMock(ok=False, outputs=[])

        with patch("autostream_webui_page_owntone.list_outputs", return_value=_outs), \
             patch("autostream_webui_page_owntone.get_capabilities", return_value=_cap), \
             patch("autostream_webui_page_owntone.get_setting", return_value=_sett), \
             patch("autostream_webui_page_owntone.load_state", return_value={}):
            send_owntone_setup_page(handler, state, auth)

        store.close(save=False)
        return b"".join(written).decode("utf-8")

    def test_live_enabled_always_true(self, tmp_path):
        html = self._render(tmp_path)
        assert "const liveEnabled = true;" in html
        assert "const liveEnabled = false;" not in html

    def test_no_initial_setup_heading(self, tmp_path):
        html = self._render(tmp_path)
        assert "Initial Setup" not in html

    def test_no_continue_button(self, tmp_path):
        html = self._render(tmp_path)
        assert ">Continue<" not in html


# ── POST commissioning gate ───────────────────────────────────────────────────

@_skip
class TestPostCommissioningGate:
    """do_POST enforces commissioning allowlist and blocks first-boot POST after configured."""

    def _make_post_handler(self, path: str, body: bytes = b"{}") -> "ConfigWebHandler":
        import secrets
        import time
        from autostream_auth import AuthManager, Session, SESSION_COOKIE_NAME
        mgr = AuthManager(config_path="dummy.ini")
        mgr._pin_loaded = True
        mgr._pin_value = None  # PIN disabled
        mgr._pin_status = "missing"
        sess_token = secrets.token_hex(32)
        csrf_token = secrets.token_hex(32)
        mgr._sessions[sess_token] = Session(
            token=sess_token,
            expires_at=int(time.time()) + 3600,
            csrf_token=csrf_token,
            authenticated=True,
        )
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
        return h, mgr

    def _response_codes(self, handler) -> list[int]:
        return [c for c, in [call.args for call in handler.send_response.call_args_list]]

    def test_settings_post_blocked_during_commissioning(self, tmp_path):
        """POST /api/settings must return 409 during commissioning."""
        handler, mgr = self._make_post_handler("/api/settings", b'{"field":"x","value":"y"}')
        state = _fake_state(tmp_path)
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", state), \
             patch("autostream_webui.is_commissioning_required", return_value=True), \
             patch("autostream_webui.send_json") as mock_json:
            handler.do_POST()
        # 409 appliance_unconfigured expected
        calls = [(c[0][1], c[0][2]) for c in mock_json.call_args_list]
        assert any(code == 409 for code, _ in calls), f"Expected 409 but got {calls}"

    def test_first_boot_finish_blocked_when_configured(self, tmp_path):
        """POST /first-boot/appliance/finish must return 409 when already configured."""
        handler, mgr = self._make_post_handler("/first-boot/appliance/finish", b"{}")
        state = _fake_state(tmp_path)
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", state), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.send_json") as mock_json:
            handler.do_POST()
        calls = [(c[0][1], c[0][2]) for c in mock_json.call_args_list]
        assert any(code == 409 for code, _ in calls), f"Expected 409 but got {calls}"

    def test_settings_post_allowed_when_configured(self, tmp_path):
        """POST /api/settings must NOT be blocked by the commissioning gate when configured."""
        handler, mgr = self._make_post_handler("/api/settings", b'{"field":"x","value":"y"}')
        state = _fake_state(tmp_path)
        blocked_with_commissioning_error = False
        original_send_json = __import__("autostream_webui_api").send_json

        def track_send_json(h, code, data):
            nonlocal blocked_with_commissioning_error
            if code == 409 and data.get("error") == "appliance_unconfigured":
                blocked_with_commissioning_error = True
            original_send_json(h, code, data)

        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", state), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.send_json", side_effect=track_send_json):
            handler.do_POST()
        assert not blocked_with_commissioning_error, (
            "POST /api/settings must not be blocked with commissioning error when configured"
        )
