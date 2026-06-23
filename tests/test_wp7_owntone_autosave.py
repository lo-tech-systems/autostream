"""tests/test_wp7_owntone_autosave.py

WP7 acceptance tests: OwnTone Setup per-field autosave endpoints.

Tests cover:
  - send_owntone_output_visibility_json: show/hide, validation, known_outputs update
  - send_owntone_output_mode_json: mode set, validation, live runtime update
  - send_owntone_output_offset_json: offset clamped, validation, live runtime update
  - send_owntone_uncompressed_json: delegates to save_setting, restart on result
  - send_owntone_start_buffer_json: value clamped, delegates to save_setting
  - send_owntone_grace_period_json: minutes→seconds conversion, delegates
  - No store → 200 with error (no 500), except native settings
  - Setup page: no Save button in configured mode; liveEnabled=false in initial setup
  - Setup page: autosave JS wired on visibility/mode/offset/uncompressed/buffer/grace
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
from unittest.mock import MagicMock, call, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

from autostream_settings import SettingsStore


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_config(tmp_path: str, extra: dict | None = None) -> str:
    cfg: dict = {
        "owntone": {"base_url": "http://localhost:3689", "output_name": "", "volume_percent": 20},
        "webui": {"hidden_outputs": []},
        "general": {},
    }
    if extra:
        for k, v in extra.items():
            cfg.setdefault(k, {}).update(v)
    path = os.path.join(tmp_path, "config.json")
    with open(path, "w") as f:
        json.dump(cfg, f)
    return path


def _make_state_file(tmp_path: str) -> str:
    path = os.path.join(tmp_path, "state.json")
    with open(path, "w") as f:
        json.dump({"owntone": {"known_outputs": {}}}, f)
    return path


def _make_store(config_path: str) -> SettingsStore:
    return SettingsStore(config_path, _save_interval_seconds=9999, _writer=MagicMock())


def _make_state(config_path: str, state_path: str, store: SettingsStore | None) -> MagicMock:
    state = MagicMock()
    state.config_path = config_path
    state.state_path = state_path
    state.settings = store
    return state


def _make_handler():
    handler = MagicMock()
    sent: dict = {}
    handler.send_response.side_effect = lambda code: sent.update({"code": code})
    handler.wfile = MagicMock()
    handler.wfile.write.side_effect = lambda data: sent.update({"body": json.loads(data)})
    handler.end_headers = MagicMock()
    handler.send_header = MagicMock()
    return handler, sent


# ── Output visibility ─────────────────────────────────────────────────────────

class TestOutputVisibility:
    def test_hide_output_adds_to_hidden(self, tmp_path):
        from autostream_webui_api import send_owntone_output_visibility_json
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, state_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"output_name": "Kitchen", "visible": False})
        send_owntone_output_visibility_json(handler, state, body)
        assert sent["body"]["ok"] is True
        snap = store.snapshot()
        assert "Kitchen" in (snap.webui.hidden_outputs or [])

    def test_show_output_removes_from_hidden(self, tmp_path):
        from autostream_webui_api import send_owntone_output_visibility_json
        config_path = _make_config(str(tmp_path), extra={"webui": {"hidden_outputs": ["Kitchen"]}})
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, state_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"output_name": "Kitchen", "visible": True})
        send_owntone_output_visibility_json(handler, state, body)
        assert sent["body"]["ok"] is True
        snap = store.snapshot()
        assert "Kitchen" not in (snap.webui.hidden_outputs or [])

    def test_known_output_updated_when_id_provided(self, tmp_path):
        from autostream_webui_api import send_owntone_output_visibility_json
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, state_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"output_name": "Kitchen", "output_id": "42", "visible": True})
        with patch("autostream_webui_api.load_state") as m_load, \
             patch("autostream_webui_api.save_state") as m_save:
            m_load.return_value = {"owntone": {"known_outputs": {}}}
            send_owntone_output_visibility_json(handler, state, body)
        m_save.assert_called_once()
        saved_state = m_save.call_args[0][1]
        assert saved_state["owntone"]["known_outputs"].get("42") == "Kitchen"

    def test_missing_output_name_returns_400(self, tmp_path):
        from autostream_webui_api import send_owntone_output_visibility_json
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, state_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"visible": True})
        send_owntone_output_visibility_json(handler, state, body)
        assert sent["code"] == 400

    def test_non_bool_visible_returns_400(self, tmp_path):
        from autostream_webui_api import send_owntone_output_visibility_json
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, state_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"output_name": "Kitchen", "visible": "yes"})
        send_owntone_output_visibility_json(handler, state, body)
        assert sent["code"] == 400

    def test_no_store_returns_error_not_500(self, tmp_path):
        from autostream_webui_api import send_owntone_output_visibility_json
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        state = _make_state(config_path, state_path, None)
        handler, sent = _make_handler()
        body = json.dumps({"output_name": "Kitchen", "visible": False})
        send_owntone_output_visibility_json(handler, state, body)
        assert sent["code"] == 200
        assert sent["body"]["ok"] is False


# ── Output mode ───────────────────────────────────────────────────────────────

class TestOutputMode:
    def test_valid_mode_stored(self, tmp_path):
        from autostream_webui_api import send_owntone_output_mode_json
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, state_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"output_id": "42", "mode": "raop"})
        with patch("autostream_webui_api.update_live_owntone_runtime"):
            send_owntone_output_mode_json(handler, state, body)
        assert sent["body"]["ok"] is True
        snap = store.snapshot()
        assert snap.owntone.output_airplay_modes.get("42") == "raop"

    def test_invalid_mode_returns_400(self, tmp_path):
        from autostream_webui_api import send_owntone_output_mode_json
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, state_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"output_id": "42", "mode": "invalid"})
        send_owntone_output_mode_json(handler, state, body)
        assert sent["code"] == 400

    def test_missing_output_id_returns_400(self, tmp_path):
        from autostream_webui_api import send_owntone_output_mode_json
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, state_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"mode": "raop"})
        send_owntone_output_mode_json(handler, state, body)
        assert sent["code"] == 400

    def test_live_runtime_updated(self, tmp_path):
        from autostream_webui_api import send_owntone_output_mode_json
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, state_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"output_id": "42", "mode": "raop"})
        with patch("autostream_webui_api.update_live_owntone_runtime") as m_live:
            send_owntone_output_mode_json(handler, state, body)
        m_live.assert_called_once()


# ── Output offset ─────────────────────────────────────────────────────────────

class TestOutputOffset:
    def test_offset_stored(self, tmp_path):
        from autostream_webui_api import send_owntone_output_offset_json
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, state_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"output_id": "42", "offset_ms": 250})
        with patch("autostream_webui_api.update_live_owntone_runtime"):
            send_owntone_output_offset_json(handler, state, body)
        assert sent["body"]["ok"] is True
        snap = store.snapshot()
        assert snap.owntone.output_offsets_ms.get("42") == 250

    def test_offset_clamped_to_range(self, tmp_path):
        from autostream_webui_api import send_owntone_output_offset_json
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, state_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"output_id": "42", "offset_ms": 9999})
        with patch("autostream_webui_api.update_live_owntone_runtime"):
            send_owntone_output_offset_json(handler, state, body)
        assert sent["body"]["offset_ms"] == 2000

    def test_non_numeric_offset_returns_400(self, tmp_path):
        from autostream_webui_api import send_owntone_output_offset_json
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, state_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"output_id": "42", "offset_ms": "lots"})
        send_owntone_output_offset_json(handler, state, body)
        assert sent["code"] == 400


# ── Native OwnTone settings ───────────────────────────────────────────────────

class TestNativeOwntoneSettings:
    def _make_save_result(self, ok=True, restart_required=False, unsupported=False):
        from autostream_players import SaveSettingResult
        return SaveSettingResult(
            ok=ok,
            restart_required=restart_required,
            unsupported=unsupported,
            error="" if ok else "owntone_error",
        )

    def test_uncompressed_calls_save_setting(self, tmp_path):
        from autostream_webui_api import send_owntone_uncompressed_json
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, state_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"value": True})
        with patch("autostream_webui_api.save_setting") as m_save, \
             patch("autostream_webui_api._config_snapshot") as m_snap:
            m_snap.return_value = MagicMock(owntone=MagicMock(base_url="http://localhost:3689"))
            m_save.return_value = self._make_save_result()
            send_owntone_uncompressed_json(handler, state, body)
        m_save.assert_called_once()
        assert sent["body"]["ok"] is True

    def test_uncompressed_restart_required_triggers_restart(self, tmp_path):
        from autostream_webui_api import send_owntone_uncompressed_json
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, state_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"value": False})
        with patch("autostream_webui_api.save_setting") as m_save, \
             patch("autostream_webui_api._config_snapshot") as m_snap, \
             patch("autostream_webui_page_owntone.start_owntone_restart_async") as m_restart:
            m_snap.return_value = MagicMock(owntone=MagicMock(base_url="http://localhost:3689"))
            m_save.return_value = self._make_save_result(restart_required=True)
            send_owntone_uncompressed_json(handler, state, body)
        m_restart.assert_called_once()
        assert sent["body"]["restart_required"] is True

    def test_uncompressed_failure_no_restart(self, tmp_path):
        from autostream_webui_api import send_owntone_uncompressed_json
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, state_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"value": True})
        with patch("autostream_webui_api.save_setting") as m_save, \
             patch("autostream_webui_api._config_snapshot") as m_snap, \
             patch("autostream_webui_page_owntone.start_owntone_restart_async") as m_restart:
            m_snap.return_value = MagicMock(owntone=MagicMock(base_url="http://localhost:3689"))
            m_save.return_value = self._make_save_result(ok=False)
            send_owntone_uncompressed_json(handler, state, body)
        m_restart.assert_not_called()
        assert sent["body"]["ok"] is False

    def test_non_bool_uncompressed_returns_400(self, tmp_path):
        from autostream_webui_api import send_owntone_uncompressed_json
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, state_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"value": "yes"})
        send_owntone_uncompressed_json(handler, state, body)
        assert sent["code"] == 400

    def test_start_buffer_clamped(self, tmp_path):
        from autostream_webui_api import send_owntone_start_buffer_json
        from autostream_players import SETTING_START_BUFFER_MS_MAX
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, state_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"value": 999999})
        with patch("autostream_webui_api.save_setting") as m_save, \
             patch("autostream_webui_api._config_snapshot") as m_snap:
            m_snap.return_value = MagicMock(owntone=MagicMock(base_url="http://localhost:3689"))
            m_save.return_value = self._make_save_result()
            send_owntone_start_buffer_json(handler, state, body)
        call_value = m_save.call_args[0][2]
        assert call_value <= SETTING_START_BUFFER_MS_MAX

    def test_grace_period_converts_minutes_to_seconds(self, tmp_path):
        from autostream_webui_api import send_owntone_grace_period_json
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, state_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"value": 5})
        with patch("autostream_webui_api.save_setting") as m_save, \
             patch("autostream_webui_api._config_snapshot") as m_snap:
            m_snap.return_value = MagicMock(owntone=MagicMock(base_url="http://localhost:3689"))
            m_save.return_value = self._make_save_result()
            send_owntone_grace_period_json(handler, state, body)
        call_value = m_save.call_args[0][2]
        assert call_value == 300  # 5 minutes * 60

    def test_unsupported_setting_succeeds_without_restart(self, tmp_path):
        from autostream_webui_api import send_owntone_uncompressed_json
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, state_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"value": True})
        with patch("autostream_webui_api.save_setting") as m_save, \
             patch("autostream_webui_api._config_snapshot") as m_snap, \
             patch("autostream_webui_page_owntone.start_owntone_restart_async") as m_restart:
            m_snap.return_value = MagicMock(owntone=MagicMock(base_url="http://localhost:3689"))
            m_save.return_value = self._make_save_result(ok=False, unsupported=True)
            send_owntone_uncompressed_json(handler, state, body)
        m_restart.assert_not_called()
        assert sent["body"]["ok"] is True


# ── Setup page rendering ──────────────────────────────────────────────────────

class TestOwntoneSetupPage:
    def _render_page(self, tmp_path, initial_setup=False):
        from autostream_webui_page_owntone import send_owntone_setup_page
        from autostream_players import SaveSettingResult, SettingValueResult
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, state_path, store)
        handler = MagicMock()
        auth = MagicMock()
        auth.get_csrf_token.return_value = "tok"
        handler._csrf_token = "tok"
        handler.headers = {}
        written = []
        handler.wfile.write.side_effect = lambda data: written.append(data)

        _list_result = MagicMock()
        _list_result.ok = True
        _list_result.outputs = []

        _cap = MagicMock()
        _cap.can_set_output_mode = False
        _cap.can_set_output_offset = False

        _sett_result = MagicMock()
        _sett_result.ok = False
        _sett_result.unsupported = True

        with patch("autostream_webui_page_owntone.list_outputs", return_value=_list_result), \
             patch("autostream_webui_page_owntone.get_capabilities", return_value=_cap), \
             patch("autostream_webui_page_owntone.get_setting", return_value=_sett_result), \
             patch("autostream_webui_page_owntone.unconfigured", return_value=initial_setup), \
             patch("autostream_webui_page_owntone.load_state", return_value={}):
            send_owntone_setup_page(handler, state, auth)

        return b"".join(written).decode("utf-8")

    def test_configured_mode_no_save_button(self, tmp_path):
        html = self._render_page(str(tmp_path), initial_setup=False)
        assert ">Save<" not in html

    def test_initial_setup_has_continue_button(self, tmp_path):
        html = self._render_page(str(tmp_path), initial_setup=True)
        assert ">Continue<" in html

    def test_live_enabled_true_in_configured_mode(self, tmp_path):
        html = self._render_page(str(tmp_path), initial_setup=False)
        assert "const liveEnabled = true" in html

    def test_live_enabled_false_in_initial_setup(self, tmp_path):
        html = self._render_page(str(tmp_path), initial_setup=True)
        assert "const liveEnabled = false" in html

    def test_autosave_functions_present(self, tmp_path):
        html = self._render_page(str(tmp_path), initial_setup=False)
        assert "_owntoneOffsetDebounced" in html
        assert "_owntoneNativeDebounced" in html

    def test_settings_transact_available(self, tmp_path):
        html = self._render_page(str(tmp_path), initial_setup=False)
        assert "settingsTransact" in html

    def test_refresh_link_present(self, tmp_path):
        html = self._render_page(str(tmp_path), initial_setup=False)
        assert "Refresh" in html
        assert "/owntone-setup" in html
