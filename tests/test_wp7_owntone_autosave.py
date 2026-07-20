"""tests/test_wp7_owntone_autosave.py

WP7 acceptance tests: OwnTone Setup per-field autosave endpoints.

Tests cover:
  - send_owntone_output_visibility_json: show/hide, validation, known_outputs update
  - send_owntone_output_mode_json: mode set, validation, live runtime update
  - send_owntone_output_offset_json: offset clamped, validation, live runtime update
  - send_owntone_uncompressed_json: delegates to save_setting, restart on result
  - send_owntone_start_buffer_json: value clamped, delegates to save_setting
  - send_owntone_grace_period_json: compatibility wrapper for grace period
  - No store → 200 with error (no 500), except native settings
  - Setup page: no Save button in configured mode; liveEnabled=false in initial setup
  - Setup page: autosave JS wired on visibility/mode/offset/uncompressed/buffer
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


# ── Output mode: buffered-audio guard ─────────────────────────────────────────

class TestBufferedModeGuard:
    """A buffered/surround mode can only be set while the backend's buffered-audio
    preference is on; a stale page (rendered while it was on) that still posts a
    buffered selection must be refused, not silently written."""

    _BUFFERED_MODES = ("airplay2_buffered", "airplay2_surround_stereo", "airplay2_surround_upmix")
    _NON_BUFFERED_MODES = ("default", "raop", "airplay2")

    def test_buffered_modes_rejected_when_buffered_audio_off(self, tmp_path):
        from autostream_webui_api import send_owntone_output_mode_json
        for mode in self._BUFFERED_MODES:
            config_path = _make_config(str(tmp_path))
            state_path = _make_state_file(str(tmp_path))
            store = _make_store(config_path)
            state = _make_state(config_path, state_path, store)
            handler, sent = _make_handler()
            body = json.dumps({"output_id": "42", "mode": mode})
            with patch("autostream_webui_api._buffered_audio_is_enabled", return_value=False), \
                 patch("autostream_webui_api.update_live_owntone_runtime") as m_live:
                send_owntone_output_mode_json(handler, state, body)
            assert sent["code"] == 200
            assert sent["body"]["ok"] is False
            assert "Buffered audio is disabled" in sent["body"]["error"]
            m_live.assert_not_called()
            snap = store.snapshot()
            assert "42" not in (snap.owntone.output_airplay_modes or {})

    def test_buffered_modes_succeed_when_buffered_audio_on(self, tmp_path):
        from autostream_webui_api import send_owntone_output_mode_json
        for mode in self._BUFFERED_MODES:
            config_path = _make_config(str(tmp_path))
            state_path = _make_state_file(str(tmp_path))
            store = _make_store(config_path)
            state = _make_state(config_path, state_path, store)
            handler, sent = _make_handler()
            body = json.dumps({"output_id": "42", "mode": mode})
            with patch("autostream_webui_api._buffered_audio_is_enabled", return_value=True), \
                 patch("autostream_webui_api.update_live_owntone_runtime"):
                send_owntone_output_mode_json(handler, state, body)
            assert sent["body"]["ok"] is True
            snap = store.snapshot()
            assert snap.owntone.output_airplay_modes.get("42") == mode

    def test_non_buffered_modes_unaffected_regardless_of_buffered_audio_state(self, tmp_path):
        from autostream_webui_api import send_owntone_output_mode_json
        for mode in self._NON_BUFFERED_MODES:
            for buffered_state in (False, True):
                config_path = _make_config(str(tmp_path))
                state_path = _make_state_file(str(tmp_path))
                store = _make_store(config_path)
                state = _make_state(config_path, state_path, store)
                handler, sent = _make_handler()
                body = json.dumps({"output_id": "42", "mode": mode})
                with patch("autostream_webui_api._buffered_audio_is_enabled", return_value=buffered_state) as m_guard, \
                     patch("autostream_webui_api.update_live_owntone_runtime"):
                    send_owntone_output_mode_json(handler, state, body)
                assert sent["body"]["ok"] is True
                m_guard.assert_not_called()  # `mode in BUFFERED_AIRPLAY_MODES` short-circuits before the probe

    def test_non_buffered_mode_does_not_probe_buffered_audio(self, tmp_path):
        """The guard checks `mode in BUFFERED_AIRPLAY_MODES` first, so a non-buffered
        mode must never trigger the (network-bound) buffered-audio probe."""
        from autostream_webui_api import send_owntone_output_mode_json
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, state_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"output_id": "42", "mode": "raop"})
        with patch("autostream_player_service.get_setting") as m_get, \
             patch("autostream_webui_api.update_live_owntone_runtime"):
            send_owntone_output_mode_json(handler, state, body)
        assert sent["body"]["ok"] is True
        m_get.assert_not_called()


# ── _buffered_audio_is_enabled helper ─────────────────────────────────────────

class TestBufferedAudioIsEnabledHelper:
    """_buffered_audio_is_enabled must be conservative: only True when the probe
    both succeeds and reports a truthy value; anything else (exception, ok=False,
    falsey value) counts as off."""

    def _state(self, tmp_path):
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        return _make_state(config_path, state_path, _make_store(config_path))

    def test_false_on_exception(self, tmp_path):
        from autostream_webui_api import _buffered_audio_is_enabled
        state = self._state(tmp_path)
        with patch("autostream_webui_api._config_snapshot", side_effect=RuntimeError("boom")):
            assert _buffered_audio_is_enabled(state) is False

    def test_false_when_result_not_ok(self, tmp_path):
        from autostream_webui_api import _buffered_audio_is_enabled
        state = self._state(tmp_path)
        with patch("autostream_webui_api._config_snapshot") as m_snap, \
             patch("autostream_player_service.get_setting") as m_get:
            m_snap.return_value = MagicMock(owntone=MagicMock(base_url="http://localhost:3689"))
            m_get.return_value = MagicMock(ok=False, value=True)
            assert _buffered_audio_is_enabled(state) is False

    def test_false_when_value_falsey(self, tmp_path):
        from autostream_webui_api import _buffered_audio_is_enabled
        state = self._state(tmp_path)
        with patch("autostream_webui_api._config_snapshot") as m_snap, \
             patch("autostream_player_service.get_setting") as m_get:
            m_snap.return_value = MagicMock(owntone=MagicMock(base_url="http://localhost:3689"))
            m_get.return_value = MagicMock(ok=True, value=False)
            assert _buffered_audio_is_enabled(state) is False

    def test_true_when_ok_and_value(self, tmp_path):
        from autostream_webui_api import _buffered_audio_is_enabled
        state = self._state(tmp_path)
        with patch("autostream_webui_api._config_snapshot") as m_snap, \
             patch("autostream_player_service.get_setting") as m_get:
            m_snap.return_value = MagicMock(owntone=MagicMock(base_url="http://localhost:3689"))
            m_get.return_value = MagicMock(ok=True, value=True)
            assert _buffered_audio_is_enabled(state) is True


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

    def test_grace_period_compat_endpoint_converts_minutes_to_seconds(self, tmp_path):
        from autostream_webui_api import send_owntone_grace_period_json
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, state_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"value": 5})
        with patch("autostream_webui_api.save_setting") as m_save, \
             patch("autostream_appliances.set_grace_period") as m_browser, \
             patch("autostream_webui_api._config_snapshot") as m_snap:
            m_snap.return_value = MagicMock(owntone=MagicMock(base_url="http://localhost:3689"))
            m_save.return_value = self._make_save_result()
            send_owntone_grace_period_json(handler, state, body)
        call_value = m_save.call_args[0][2]
        assert call_value == 300  # 5 minutes * 60
        m_browser.assert_called_once_with(300)
        assert store.raw_snapshot()["general"]["mdns_grace_period_seconds"] == 300

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

    def test_buffered_audio_unsupported_returns_ok_false(self, tmp_path):
        """reject_unsupported=True: a write against an unsupported backend must fail,
        not report the fake success that the uncompressed-setting path tolerates."""
        from autostream_webui_api import send_owntone_buffered_audio_json
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
            send_owntone_buffered_audio_json(handler, state, body)
        m_restart.assert_not_called()
        assert sent["body"]["ok"] is False

    def test_buffered_audio_succeeds_when_supported(self, tmp_path):
        from autostream_webui_api import send_owntone_buffered_audio_json
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, state_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"value": True})
        with patch("autostream_webui_api.save_setting") as m_save, \
             patch("autostream_webui_api._config_snapshot") as m_snap:
            m_snap.return_value = MagicMock(owntone=MagicMock(base_url="http://localhost:3689"))
            m_save.return_value = self._make_save_result(ok=True)
            send_owntone_buffered_audio_json(handler, state, body)
        assert sent["body"]["ok"] is True


# ── Buffered-audio toggle: resetting stored buffered/surround modes ─────────

class TestBufferedAudioResetOutputs:
    """Turning buffered audio off must fall any output saved as a buffered or
    surround-over-buffered mode back to the default mode, and report the
    changed output ids; turning it on must never touch stored modes."""

    def _make_save_result(self, ok=True, restart_required=False, unsupported=False):
        from autostream_players import SaveSettingResult
        return SaveSettingResult(
            ok=ok,
            restart_required=restart_required,
            unsupported=unsupported,
            error="" if ok else "owntone_error",
        )

    def test_turning_off_resets_buffered_and_surround_modes(self, tmp_path):
        from autostream_webui_api import send_owntone_buffered_audio_json
        config_path = _make_config(str(tmp_path), extra={"owntone": {"airplay_modes": {
            "1": "airplay2_buffered",
            "2": "airplay2_surround_stereo",
            "3": "airplay2_surround_upmix",
            "4": "raop",
            "5": "airplay2",
            "6": "default",
        }}})
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, state_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"value": False})
        with patch("autostream_webui_api.save_setting") as m_save, \
             patch("autostream_webui_api._config_snapshot") as m_snap, \
             patch("autostream_webui_api.update_live_owntone_runtime"):
            m_snap.return_value = MagicMock(owntone=MagicMock(base_url="http://localhost:3689"))
            m_save.return_value = self._make_save_result(ok=True)
            send_owntone_buffered_audio_json(handler, state, body)
        assert sent["body"]["ok"] is True
        assert set(sent["body"]["reset_outputs"]) == {"1", "2", "3"}
        snap = store.snapshot()
        assert snap.owntone.output_airplay_modes["1"] == "default"
        assert snap.owntone.output_airplay_modes["2"] == "default"
        assert snap.owntone.output_airplay_modes["3"] == "default"
        # Untouched: not a buffered-transport mode.
        assert snap.owntone.output_airplay_modes["4"] == "raop"
        assert snap.owntone.output_airplay_modes["5"] == "airplay2"
        assert snap.owntone.output_airplay_modes["6"] == "default"

    def test_turning_on_does_not_reset_stored_modes(self, tmp_path):
        from autostream_webui_api import send_owntone_buffered_audio_json
        config_path = _make_config(str(tmp_path), extra={"owntone": {"airplay_modes": {
            "1": "airplay2_buffered",
        }}})
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, state_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"value": True})
        with patch("autostream_webui_api.save_setting") as m_save, \
             patch("autostream_webui_api._config_snapshot") as m_snap, \
             patch("autostream_webui_api.update_live_owntone_runtime") as m_live:
            m_snap.return_value = MagicMock(owntone=MagicMock(base_url="http://localhost:3689"))
            m_save.return_value = self._make_save_result(ok=True)
            send_owntone_buffered_audio_json(handler, state, body)
        assert sent["body"]["ok"] is True
        assert sent["body"]["reset_outputs"] == []
        m_live.assert_not_called()
        snap = store.snapshot()
        assert snap.owntone.output_airplay_modes["1"] == "airplay2_buffered"

    def test_reset_skipped_gracefully_when_store_unavailable(self, tmp_path):
        from autostream_webui_api import send_owntone_buffered_audio_json
        config_path = _make_config(str(tmp_path), extra={"owntone": {"airplay_modes": {
            "1": "airplay2_buffered",
        }}})
        state_path = _make_state_file(str(tmp_path))
        state = _make_state(config_path, state_path, None)  # no settings store
        handler, sent = _make_handler()
        body = json.dumps({"value": False})
        with patch("autostream_webui_api.save_setting") as m_save, \
             patch("autostream_webui_api._config_snapshot") as m_snap:
            m_snap.return_value = MagicMock(owntone=MagicMock(base_url="http://localhost:3689"))
            m_save.return_value = self._make_save_result(ok=True)
            send_owntone_buffered_audio_json(handler, state, body)
        assert sent["code"] == 200
        assert sent["body"]["ok"] is True
        assert sent["body"]["reset_outputs"] == []


# ── Setup page rendering ──────────────────────────────────────────────────────

class TestOwntoneSetupPage:
    def _render_page(
        self,
        tmp_path,
        setting_results: dict | None = None,
        outputs: list | None = None,
        can_set_output_mode: bool = False,
        config_extra: dict | None = None,
    ):
        """Render the OwnTone setup page with get_setting mocked per setting key.

        `setting_results` maps a setting key (e.g. SETTING_BUFFERED_AUDIO_ENABLED)
        to the object get_setting() should return for that key. Keys not present
        default to the "genuinely unsupported" result (ok=False, unsupported=True)
        that existing callers of this helper relied on.

        `outputs` is a list of OutputInfo instances returned as discovered speakers;
        `can_set_output_mode` toggles capabilities.can_set_output_mode so the mode
        <select> is rendered instead of a hidden input; `config_extra` is passed
        through to `_make_config` (e.g. to pre-seed `owntone.airplay_modes`).
        """
        from autostream_webui_page_owntone import send_owntone_setup_page
        from autostream_players import SaveSettingResult, SettingValueResult
        config_path = _make_config(str(tmp_path), extra=config_extra)
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
        _list_result.outputs = outputs or []

        _cap = MagicMock()
        _cap.can_set_output_mode = can_set_output_mode
        _cap.can_set_output_offset = False

        _default_result = MagicMock()
        _default_result.ok = False
        _default_result.unsupported = True

        _results_by_key = dict(setting_results or {})

        def _fake_get_setting(base_url, setting_key, timeout=3):
            return _results_by_key.get(setting_key, _default_result)

        with patch("autostream_webui_page_owntone.list_outputs", return_value=_list_result), \
             patch("autostream_webui_page_owntone.get_capabilities", return_value=_cap), \
             patch("autostream_webui_page_owntone.get_setting", side_effect=_fake_get_setting), \
             patch("autostream_webui_page_owntone.load_state", return_value={}):
            send_owntone_setup_page(handler, state, auth)

        return b"".join(written).decode("utf-8")

    def test_no_save_button(self, tmp_path):
        html = self._render_page(str(tmp_path))
        assert ">Save<" not in html

    def test_no_continue_button(self, tmp_path):
        html = self._render_page(str(tmp_path))
        assert ">Continue<" not in html

    def test_live_enabled_always_true(self, tmp_path):
        html = self._render_page(str(tmp_path))
        assert "const liveEnabled = true" in html

    def test_autosave_functions_present(self, tmp_path):
        html = self._render_page(str(tmp_path))
        assert "_owntoneOffsetDebounced" in html
        assert "_owntoneNativeDebounced" in html

    def test_settings_transact_available(self, tmp_path):
        html = self._render_page(str(tmp_path))
        assert "settingsTransact" in html

    def test_refresh_link_present(self, tmp_path):
        html = self._render_page(str(tmp_path))
        assert "Refresh" in html
        assert "/owntone-setup" in html

    def test_grace_period_not_rendered_on_owntone_page(self, tmp_path):
        html = self._render_page(str(tmp_path))
        assert 'name="device_removal_grace_period_minutes"' not in html
        assert "mDNS Grace Period" not in html
        assert "/api/owntone/grace-period" not in html

    def test_audio_fieldset_rendered_before_speaker_cards(self, tmp_path):
        """The Audio fieldset (buffered audio / uncompressed / start buffer) must
        render above the per-speaker cards, not below them."""
        from autostream_players import OutputInfo
        output = OutputInfo(id="42", name="Kitchen", supported_modes=("default",))
        html = self._render_page(str(tmp_path), outputs=[output])
        audio_idx = html.index("<legend>Audio</legend>")
        speaker_idx = html.index('id="spk_settings_0"')
        assert audio_idx < speaker_idx


# ── Buffered-audio toggle rendering ────────────────────────────────────────────

class TestBufferedAudioToggle:
    """Buffered-audio control has three render states driven by get_setting():

    - genuinely unsupported (ok=False, unsupported=True): control omitted entirely
    - transient read failure (ok=False, unsupported=False): disabled control + note
    - supported (ok=True): enabled control, checked state mirrors the value
    """

    def _result(self, ok, value=None, unsupported=False):
        r = MagicMock()
        r.ok = ok
        r.value = value
        r.unsupported = unsupported
        return r

    _NAME_ATTR = "name='buffered_audio_enabled'"

    def _input_attrs(self, html: str) -> str:
        """Return the buffered-audio <input>'s attribute list, excluding its
        onchange JS body (which contains the literal substring "checked" as
        part of "this.checked" and would otherwise produce false positives)."""
        idx = html.index(self._NAME_ATTR)
        tag_start = html.rindex("<input", 0, idx)
        tag_end = html.index(">", idx)
        tag = html[tag_start:tag_end + 1]
        return tag.split("onchange=")[0]

    def test_toggle_absent_when_genuinely_unsupported(self, tmp_path):
        from autostream_players import SETTING_BUFFERED_AUDIO_ENABLED
        html = TestOwntoneSetupPage()._render_page(
            str(tmp_path),
            {SETTING_BUFFERED_AUDIO_ENABLED: self._result(ok=False, unsupported=True)},
        )
        assert self._NAME_ATTR not in html
        assert "Enable AirPlay 2 Buffered Audio" not in html
        assert "Could not read the buffered-audio setting" not in html

    def test_toggle_present_but_disabled_on_read_failure(self, tmp_path):
        from autostream_players import SETTING_BUFFERED_AUDIO_ENABLED
        html = TestOwntoneSetupPage()._render_page(
            str(tmp_path),
            {SETTING_BUFFERED_AUDIO_ENABLED: self._result(ok=False, unsupported=False)},
        )
        assert self._NAME_ATTR in html
        assert "Enable AirPlay 2 Buffered Audio" in html
        assert "Could not read the buffered-audio setting" in html
        # Isolate the buffered-audio input tag's attributes and confirm disabled.
        attrs = self._input_attrs(html)
        assert "disabled" in attrs

    def test_toggle_enabled_and_checked_when_value_true(self, tmp_path):
        from autostream_players import SETTING_BUFFERED_AUDIO_ENABLED
        html = TestOwntoneSetupPage()._render_page(
            str(tmp_path),
            {SETTING_BUFFERED_AUDIO_ENABLED: self._result(ok=True, value=True)},
        )
        assert self._NAME_ATTR in html
        assert "Could not read the buffered-audio setting" not in html
        attrs = self._input_attrs(html)
        assert "disabled" not in attrs
        assert "checked" in attrs

    def test_toggle_enabled_and_unchecked_when_value_false(self, tmp_path):
        from autostream_players import SETTING_BUFFERED_AUDIO_ENABLED
        html = TestOwntoneSetupPage()._render_page(
            str(tmp_path),
            {SETTING_BUFFERED_AUDIO_ENABLED: self._result(ok=True, value=False)},
        )
        assert self._NAME_ATTR in html
        assert "Could not read the buffered-audio setting" not in html
        attrs = self._input_attrs(html)
        assert "disabled" not in attrs
        assert "checked" not in attrs

    def test_toggle_onchange_reloads_page_on_success(self, tmp_path):
        """Flipping buffered audio changes which modes the per-output <select>
        should offer, so a successful toggle must reload the page rather than
        just patching the checkbox in place."""
        from autostream_players import SETTING_BUFFERED_AUDIO_ENABLED
        html = TestOwntoneSetupPage()._render_page(
            str(tmp_path),
            {SETTING_BUFFERED_AUDIO_ENABLED: self._result(ok=True, value=True)},
        )
        idx = html.index(self._NAME_ATTR)
        tag_start = html.rindex("<input", 0, idx)
        tag_end = html.index(">", idx)
        tag = html[tag_start:tag_end + 1]
        assert "/api/owntone/buffered-audio" in tag
        assert "onSuccess" in tag
        assert "window.location.reload()" in tag


# ── Buffered-mode filtering in the per-speaker mode <select> ─────────────────

class TestBufferedModeFiltering:
    """BUFFERED_AIRPLAY_MODES are only offered in the mode <select> while the
    backend's buffered-audio preference is on; otherwise they're filtered out
    and a saved buffered/surround selection displays as Auto."""

    def _output(self, out_id="42", modes=None):
        from autostream_players import (
            OUTPUT_MODE_AIRPLAY2,
            OUTPUT_MODE_AIRPLAY2_BUFFERED,
            OUTPUT_MODE_AUTO,
            OutputInfo,
        )
        return OutputInfo(
            id=out_id,
            name="Kitchen",
            supported_modes=modes or (OUTPUT_MODE_AUTO, OUTPUT_MODE_AIRPLAY2, OUTPUT_MODE_AIRPLAY2_BUFFERED),
        )

    def _select_html(self, html: str, index: int = 0) -> str:
        marker = f'name="mode_{index}"'
        start = html.index(marker)
        tag_open_start = html.rindex("<select", 0, start)
        end = html.index("</select>", start) + len("</select>")
        return html[tag_open_start:end]

    def test_buffered_off_hides_buffered_options_and_selects_auto(self, tmp_path):
        from autostream_players import SETTING_BUFFERED_AUDIO_ENABLED
        result = TestBufferedAudioToggle()._result(ok=True, value=False)
        html = TestOwntoneSetupPage()._render_page(
            str(tmp_path),
            {SETTING_BUFFERED_AUDIO_ENABLED: result},
            outputs=[self._output()],
            can_set_output_mode=True,
            config_extra={"owntone": {"airplay_modes": {"42": "airplay2_buffered"}}},
        )
        select_html = self._select_html(html)
        assert "airplay2_buffered" not in select_html
        assert "airplay2_surround_stereo" not in select_html
        assert "airplay2_surround_upmix" not in select_html
        assert '<option value="default" selected>Auto</option>' in select_html

    def test_buffered_on_shows_buffered_options_and_selects_saved_mode(self, tmp_path):
        from autostream_players import SETTING_BUFFERED_AUDIO_ENABLED
        result = TestBufferedAudioToggle()._result(ok=True, value=True)
        html = TestOwntoneSetupPage()._render_page(
            str(tmp_path),
            {SETTING_BUFFERED_AUDIO_ENABLED: result},
            outputs=[self._output()],
            can_set_output_mode=True,
            config_extra={"owntone": {"airplay_modes": {"42": "airplay2_buffered"}}},
        )
        select_html = self._select_html(html)
        assert '<option value="airplay2_buffered" selected>' in select_html
        assert '<option value="default" selected>' not in select_html

    def test_filtering_to_empty_falls_back_to_default_only(self, tmp_path):
        from autostream_players import OUTPUT_MODE_AIRPLAY2_BUFFERED, SETTING_BUFFERED_AUDIO_ENABLED
        result = TestBufferedAudioToggle()._result(ok=True, value=False)
        html = TestOwntoneSetupPage()._render_page(
            str(tmp_path),
            {SETTING_BUFFERED_AUDIO_ENABLED: result},
            outputs=[self._output(modes=(OUTPUT_MODE_AIRPLAY2_BUFFERED,))],
            can_set_output_mode=True,
        )
        select_html = self._select_html(html)
        assert select_html.count("<option") == 1
        assert '<option value="default" selected>Auto</option>' in select_html


# ---------------------------------------------------------------------------
# Restart debounce
# ---------------------------------------------------------------------------

class TestOwntoneRestartDebounce:
    """start_owntone_restart_async coalesces rapid calls into a single restart."""

    def setup_method(self):
        import autostream_webui_page_owntone as _mod
        # Reset module-level timer state between tests
        with _mod._restart_timer_lock:
            if _mod._restart_timer is not None:
                _mod._restart_timer.cancel()
                _mod._restart_timer = None

    def test_rapid_calls_fire_once(self):
        """Two calls within the debounce window must trigger exactly one restart."""
        import autostream_webui_page_owntone as _mod
        state = MagicMock()
        state.begin_owntone_restart = MagicMock(return_value=1)

        with patch("autostream_webui_page_owntone._restart_owntone_worker"):
            _mod.start_owntone_restart_async(state, delay_s=0.05)
            _mod.start_owntone_restart_async(state, delay_s=0.05)
            import time; time.sleep(0.15)

        state.begin_owntone_restart.assert_called_once()

    def test_single_call_fires(self):
        """A single call must eventually trigger the restart."""
        import autostream_webui_page_owntone as _mod
        state = MagicMock()
        state.begin_owntone_restart = MagicMock(return_value=1)

        with patch("autostream_webui_page_owntone._restart_owntone_worker"):
            _mod.start_owntone_restart_async(state, delay_s=0.05)
            import time; time.sleep(0.15)

        state.begin_owntone_restart.assert_called_once()
