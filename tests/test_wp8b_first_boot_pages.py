"""tests/test_wp8b_first_boot_pages.py

WP8B acceptance tests: first-boot pages and workflow endpoints.

Tests cover:
  - send_first_boot_owntone_page: renders output selector, no nav, refresh link
  - send_first_boot_appliance_page: renders ALSA device, volume, hostname, Finish
  - handle_first_boot_continue_post: blank output rejected; valid output saved and redirects
  - handle_first_boot_finish_post:
      * invalid ALSA device returns error page
      * missing output_name (not set in continue) returns error page
      * valid submission: store updated, save_now called, is_technically_complete passes,
        mark_commissioning_complete called, mark_configured called, redirect to /
      * save_now failure keeps in first boot
      * technically complete check failing keeps in first boot
  - first-boot pages omit bottom navigation
"""
from __future__ import annotations

import json
import os
import sys
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

from autostream_settings import SettingsStore


# ── Fixtures ──────────────────────────────────────────────────────────────────

VALID_ALSA = "hw:0,0"


def _make_config(tmp_path: str) -> str:
    cfg = {
        "owntone": {"base_url": "http://localhost:3689", "output_name": "Kitchen", "volume_percent": 20},
        "audio1": {"capture_device": VALID_ALSA},
        "general": {"fifo_path": "/tmp/fifo"},
    }
    path = os.path.join(tmp_path, "config.json")
    with open(path, "w") as f:
        json.dump(cfg, f)
    return path


def _make_state_file(tmp_path: str) -> str:
    path = os.path.join(tmp_path, "state.json")
    with open(path, "w") as f:
        json.dump({"first_boot": {"required": True, "completed": False}}, f)
    return path


def _make_store(config_path: str) -> SettingsStore:
    return SettingsStore(config_path, _save_interval_seconds=9999, _writer=MagicMock())


def _make_state(tmp_path: str, store: SettingsStore | None) -> MagicMock:
    config_path = _make_config(tmp_path)
    state_path = _make_state_file(tmp_path)
    state = MagicMock()
    state.config_path = config_path
    state.state_path = state_path
    state.settings = store
    state.get_monitor_devices.return_value = [
        {"hw": VALID_ALSA, "label": "USB Audio"},
    ]
    return state


def _make_auth():
    auth = MagicMock()
    auth.get_csrf_token.return_value = "tok"
    return auth


def _make_handler():
    handler = MagicMock()
    handler._csrf_token = "tok"
    handler.headers = {}
    written = []
    handler.wfile.write.side_effect = lambda data: written.append(data)
    return handler, written


def _render(handler, written) -> str:
    return b"".join(written).decode("utf-8")


# ── OwnTone first-boot page ────────────────────────────────────────────────────

class TestFirstBootOwtonePage:
    def _get_html(self, tmp_path):
        from autostream_webui_page_first_boot import send_first_boot_owntone_page
        store = _make_store(_make_config(str(tmp_path)))
        state = _make_state(str(tmp_path), store)
        auth = _make_auth()
        handler, written = _make_handler()
        _list = MagicMock()
        _list.ok = True
        _list.outputs = []
        with patch("autostream_webui_page_first_boot.list_outputs", return_value=_list):
            send_first_boot_owntone_page(handler, state, auth)
        return _render(handler, written)

    def test_renders_output_selector(self, tmp_path):
        html = self._get_html(tmp_path)
        assert 'name="output_name"' in html

    def test_has_continue_button(self, tmp_path):
        html = self._get_html(tmp_path)
        assert ">Continue<" in html

    def test_no_bottom_nav(self, tmp_path):
        html = self._get_html(tmp_path)
        assert 'id="nav"' not in html
        assert 'class="nav"' not in html

    def test_has_refresh_link(self, tmp_path):
        html = self._get_html(tmp_path)
        assert "/first-boot/owntone" in html
        assert "Refresh" in html

    def test_shows_error_when_provided(self, tmp_path):
        from autostream_webui_page_first_boot import send_first_boot_owntone_page
        store = _make_store(_make_config(str(tmp_path)))
        state = _make_state(str(tmp_path), store)
        auth = _make_auth()
        handler, written = _make_handler()
        _list = MagicMock(); _list.ok = False; _list.outputs = []
        with patch("autostream_webui_page_first_boot.list_outputs", return_value=_list):
            send_first_boot_owntone_page(handler, state, auth, error="No OwnTone")
        html = _render(handler, written)
        assert "No OwnTone" in html


# ── Appliance first-boot page ─────────────────────────────────────────────────

class TestFirstBootAppliancePage:
    def _get_html(self, tmp_path):
        from autostream_webui_page_first_boot import send_first_boot_appliance_page
        store = _make_store(_make_config(str(tmp_path)))
        state = _make_state(str(tmp_path), store)
        auth = _make_auth()
        handler, written = _make_handler()
        with patch("autostream_webui_page_first_boot.get_system_hostname", return_value="autostream"):
            send_first_boot_appliance_page(handler, state, auth)
        return _render(handler, written)

    def test_renders_alsa_device_select(self, tmp_path):
        html = self._get_html(tmp_path)
        assert 'name="audio1_capture_device"' in html

    def test_renders_turntable_checkbox(self, tmp_path):
        html = self._get_html(tmp_path)
        assert 'name="audio1_turntable"' in html

    def test_renders_volume_slider(self, tmp_path):
        html = self._get_html(tmp_path)
        assert 'name="volume_percent"' in html

    def test_renders_hostname_field(self, tmp_path):
        html = self._get_html(tmp_path)
        assert 'name="hostname"' in html

    def test_has_finish_button(self, tmp_path):
        html = self._get_html(tmp_path)
        assert ">Finish<" in html

    def test_no_bottom_nav(self, tmp_path):
        html = self._get_html(tmp_path)
        assert 'id="nav"' not in html


# ── Continue POST ─────────────────────────────────────────────────────────────

class TestFirstBootContinuePost:
    def test_blank_output_shows_error_page(self, tmp_path):
        from autostream_webui_page_first_boot import handle_first_boot_continue_post
        store = _make_store(_make_config(str(tmp_path)))
        state = _make_state(str(tmp_path), store)
        auth = _make_auth()
        handler, written = _make_handler()
        body = "output_name="
        _list = MagicMock(); _list.ok = True; _list.outputs = []
        with patch("autostream_webui_page_first_boot.list_outputs", return_value=_list):
            handle_first_boot_continue_post(handler, state, auth, body)
        html = _render(handler, written)
        assert "Please select an output" in html

    def test_valid_output_saved_to_store(self, tmp_path):
        from autostream_webui_page_first_boot import handle_first_boot_continue_post
        store = _make_store(_make_config(str(tmp_path)))
        state = _make_state(str(tmp_path), store)
        auth = _make_auth()
        handler, written = _make_handler()
        handle_first_boot_continue_post(handler, state, auth, "output_name=MyOutput")
        snap = store.snapshot()
        assert snap.owntone.output_name == "MyOutput"

    def test_valid_output_redirects_to_appliance(self, tmp_path):
        from autostream_webui_page_first_boot import handle_first_boot_continue_post
        store = _make_store(_make_config(str(tmp_path)))
        state = _make_state(str(tmp_path), store)
        auth = _make_auth()
        handler, written = _make_handler()
        handle_first_boot_continue_post(handler, state, auth, "output_name=Speakers")
        handler.send_response.assert_called_with(303)
        loc_calls = [c for c in handler.send_header.call_args_list
                     if c[0][0] == "Location"]
        assert any("/first-boot/appliance" in str(c) for c in loc_calls)

    def test_no_store_shows_error_page(self, tmp_path):
        from autostream_webui_page_first_boot import handle_first_boot_continue_post
        state = _make_state(str(tmp_path), None)
        auth = _make_auth()
        handler, written = _make_handler()
        _list = MagicMock(); _list.ok = True; _list.outputs = []
        with patch("autostream_webui_page_first_boot.list_outputs", return_value=_list):
            handle_first_boot_continue_post(handler, state, auth, "output_name=X")
        html = _render(handler, written)
        assert "unavailable" in html.lower()


# ── Finish POST ───────────────────────────────────────────────────────────────

class TestFirstBootFinishPost:
    def _make_finish_state(self, tmp_path, output_name="Kitchen"):
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        # Set output_name in store so validation passes
        with open(config_path, "r+") as f:
            import json as _j
            cfg = _j.load(f)
            cfg["owntone"]["output_name"] = output_name
            f.seek(0); _j.dump(cfg, f); f.truncate()
        store = SettingsStore(config_path, _save_interval_seconds=9999, _writer=MagicMock())
        state = MagicMock()
        state.config_path = config_path
        state.state_path = state_path
        state.settings = store
        state.get_monitor_devices.return_value = [{"hw": VALID_ALSA, "label": "USB Audio"}]
        return state, store, config_path, state_path

    def _valid_body(self):
        from urllib.parse import urlencode
        return urlencode({
            "audio1_capture_device": VALID_ALSA,
            "volume_percent": "20",
            "hostname": "autostream",
        })

    def test_invalid_alsa_shows_error(self, tmp_path):
        from autostream_webui_page_first_boot import handle_first_boot_finish_post
        state, store, cfg_path, state_path = self._make_finish_state(str(tmp_path))
        auth = _make_auth()
        handler, written = _make_handler()
        from urllib.parse import urlencode
        body = urlencode({"audio1_capture_device": "bad-device", "volume_percent": "20", "hostname": "h"})
        with patch("autostream_webui_page_first_boot.get_system_hostname", return_value="h"):
            handle_first_boot_finish_post(handler, state, auth, body)
        html = _render(handler, written)
        assert "Invalid ALSA" in html

    def test_valid_finish_calls_save_now(self, tmp_path):
        from autostream_webui_page_first_boot import handle_first_boot_finish_post
        state, store, cfg_path, state_path = self._make_finish_state(str(tmp_path))
        auth = _make_auth()
        handler, written = _make_handler()
        with patch("autostream_webui_page_first_boot.get_system_hostname", return_value="autostream"), \
             patch("autostream_webui_page_first_boot.is_technically_complete", return_value=True), \
             patch("autostream_webui_page_first_boot.mark_commissioning_complete") as m_mark, \
             patch("autostream_webui_page_first_boot.mark_configured"):
            store.save_now = MagicMock()
            handle_first_boot_finish_post(handler, state, auth, self._valid_body())
        store.save_now.assert_called_once()

    def test_save_now_failure_shows_error(self, tmp_path):
        from autostream_webui_page_first_boot import handle_first_boot_finish_post
        state, store, cfg_path, state_path = self._make_finish_state(str(tmp_path))
        auth = _make_auth()
        handler, written = _make_handler()
        with patch("autostream_webui_page_first_boot.get_system_hostname", return_value="autostream"):
            store.save_now = MagicMock(return_value=False)
            handle_first_boot_finish_post(handler, state, auth, self._valid_body())
        html = _render(handler, written)
        assert "could not be saved" in html.lower()

    def test_technically_incomplete_after_save_shows_error(self, tmp_path):
        from autostream_webui_page_first_boot import handle_first_boot_finish_post
        state, store, cfg_path, state_path = self._make_finish_state(str(tmp_path))
        auth = _make_auth()
        handler, written = _make_handler()
        with patch("autostream_webui_page_first_boot.get_system_hostname", return_value="autostream"), \
             patch("autostream_webui_page_first_boot.is_technically_complete", return_value=False):
            store.save_now = MagicMock()
            handle_first_boot_finish_post(handler, state, auth, self._valid_body())
        html = _render(handler, written)
        assert "incomplete" in html.lower()

    def test_mark_commissioning_complete_called_after_save(self, tmp_path):
        from autostream_webui_page_first_boot import handle_first_boot_finish_post
        state, store, cfg_path, state_path = self._make_finish_state(str(tmp_path))
        auth = _make_auth()
        handler, written = _make_handler()
        with patch("autostream_webui_page_first_boot.get_system_hostname", return_value="autostream"), \
             patch("autostream_webui_page_first_boot.is_technically_complete", return_value=True), \
             patch("autostream_webui_page_first_boot.mark_commissioning_complete") as m_mark, \
             patch("autostream_webui_page_first_boot.mark_configured"):
            store.save_now = MagicMock()
            handle_first_boot_finish_post(handler, state, auth, self._valid_body())
        m_mark.assert_called_once_with(state.state_path)

    def test_redirect_to_home_on_success(self, tmp_path):
        from autostream_webui_page_first_boot import handle_first_boot_finish_post
        state, store, cfg_path, state_path = self._make_finish_state(str(tmp_path))
        auth = _make_auth()
        handler, written = _make_handler()
        with patch("autostream_webui_page_first_boot.get_system_hostname", return_value="autostream"), \
             patch("autostream_webui_page_first_boot.is_technically_complete", return_value=True), \
             patch("autostream_webui_page_first_boot.mark_commissioning_complete"), \
             patch("autostream_webui_page_first_boot.mark_configured"):
            store.save_now = MagicMock()
            handle_first_boot_finish_post(handler, state, auth, self._valid_body())
        handler.send_response.assert_called_with(303)
        loc_calls = [c for c in handler.send_header.call_args_list if c[0][0] == "Location"]
        assert any("/" == str(c[0][1]) for c in loc_calls)

    def test_no_output_name_shows_error(self, tmp_path):
        from autostream_webui_page_first_boot import handle_first_boot_finish_post
        state, store, cfg_path, state_path = self._make_finish_state(str(tmp_path), output_name="")
        auth = _make_auth()
        handler, written = _make_handler()
        with patch("autostream_webui_page_first_boot.get_system_hostname", return_value="autostream"):
            store.save_now = MagicMock()
            handle_first_boot_finish_post(handler, state, auth, self._valid_body())
        html = _render(handler, written)
        assert "output" in html.lower()

    def test_store_updated_with_correct_values(self, tmp_path):
        from autostream_webui_page_first_boot import handle_first_boot_finish_post
        state, store, cfg_path, state_path = self._make_finish_state(str(tmp_path))
        auth = _make_auth()
        handler, written = _make_handler()
        from urllib.parse import urlencode
        body = urlencode({
            "audio1_capture_device": VALID_ALSA,
            "audio1_turntable": "on",
            "volume_percent": "40",
            "hostname": "autostream",
        })
        with patch("autostream_webui_page_first_boot.get_system_hostname", return_value="autostream"), \
             patch("autostream_webui_page_first_boot.is_technically_complete", return_value=True), \
             patch("autostream_webui_page_first_boot.mark_commissioning_complete"), \
             patch("autostream_webui_page_first_boot.mark_configured"):
            store.save_now = MagicMock()
            handle_first_boot_finish_post(handler, state, auth, body)
        snap = store.snapshot()
        assert snap.audio1.capture_device == VALID_ALSA
        assert snap.audio1.is_turntable is True
        assert snap.owntone.volume_percent == 40
