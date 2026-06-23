"""tests/test_wp6_field_writer_migration.py

WP6 acceptance tests: existing field-level writers routed through SettingsStore.

Tests cover:
  - apply_eq_field: bool field via store, bool field fallback (no store)
  - apply_eq_field: dB field via store (uses pre-write snapshot), dB fallback
  - apply_eq_reset: zeroes all bands via store, fallback path
  - send_service_config_json: persistence via store, fallback when no store
  - handle_logs_post: log_level persisted via store, fallback when no store
  - Callers in webui_api and gateway pass settings= to apply_eq_field/reset
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
        "output_eq": {
            "auto_trim": False,
            "gain_db": 0.0,
            "peq1_db": 0.0, "peq2_db": 0.0, "peq3_db": 0.0,
            "peq4_db": 0.0, "peq5_db": 0.0, "peq6_db": 0.0,
        },
        "audio1": {"gain_db": 0.0, "eq_bass_db": 0.0, "eq_mid_db": 0.0, "eq_treble_db": 0.0,
                   "is_turntable": True, "stylus_life_hours": 1000,
                   "belt_life_hours": 2000, "belt_life_years": 3,
                   "bearing_life_hours": 5000, "bearing_life_years": 7},
        "general": {"log_level": "INFO"},
    }
    if extra:
        for k, v in extra.items():
            cfg.setdefault(k, {}).update(v)
    path = os.path.join(tmp_path, "config.json")
    with open(path, "w") as f:
        json.dump(cfg, f)
    return path


def _make_store(config_path: str) -> SettingsStore:
    return SettingsStore(config_path, _save_interval_seconds=9999, _writer=MagicMock())


def _make_state(config_path: str, store: SettingsStore | None) -> MagicMock:
    state = MagicMock()
    state.config_path = config_path
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


# ── apply_eq_field — bool field ───────────────────────────────────────────────

class TestApplyEqFieldBoolViaStore:
    def test_store_updated_not_save_config(self, tmp_path):
        from autostream_appliance_models import apply_eq_field
        config_path = _make_config(str(tmp_path))
        store = _make_store(config_path)
        with patch("autostream_appliance_models.set_live_output_auto_trim") as m_trim, \
             patch("autostream_appliance_models.save_config") as m_save:
            ok, norm, err = apply_eq_field(config_path, "auto_trim_enabled", "true", settings=store)
        assert ok is True
        assert norm == "true"
        assert err == ""
        m_save.assert_not_called()
        m_trim.assert_called_once_with(True)
        snap = store.snapshot()
        assert snap.output_eq.auto_trim_enabled is True

    def test_fallback_uses_save_config(self, tmp_path):
        from autostream_appliance_models import apply_eq_field
        config_path = _make_config(str(tmp_path))
        with patch("autostream_appliance_models.set_live_output_auto_trim"), \
             patch("autostream_appliance_models.save_config") as m_save, \
             patch("autostream_appliance_models.load_config") as m_load:
            m_load.return_value = {"output_eq": {"auto_trim_enabled": False}}
            ok, norm, err = apply_eq_field(config_path, "auto_trim_enabled", "false", settings=None)
        assert ok is True
        m_save.assert_called_once()

    def test_unknown_field_raises(self, tmp_path):
        from autostream_appliance_models import apply_eq_field
        config_path = _make_config(str(tmp_path))
        store = _make_store(config_path)
        with pytest.raises(ValueError, match="Unknown field"):
            apply_eq_field(config_path, "nonexistent", "true", settings=store)


# ── apply_eq_field — dB field ─────────────────────────────────────────────────

class TestApplyEqFieldDbViaStore:
    def test_gain_db_via_store(self, tmp_path):
        from autostream_appliance_models import apply_eq_field
        config_path = _make_config(str(tmp_path))
        store = _make_store(config_path)
        with patch("autostream_appliance_models.set_live_output_gain") as m_gain, \
             patch("autostream_appliance_models.save_config") as m_save:
            ok, norm, err = apply_eq_field(config_path, "gain_db", "3.5", settings=store)
        assert ok is True
        assert norm == "3.5"
        m_save.assert_not_called()
        m_gain.assert_called_once_with(3.5)
        snap = store.snapshot()
        assert snap.output_eq.gain_db == pytest.approx(3.5)

    def test_peq_band_via_store_calls_set_live_eq(self, tmp_path):
        from autostream_appliance_models import apply_eq_field
        config_path = _make_config(str(tmp_path))
        store = _make_store(config_path)
        with patch("autostream_appliance_models.set_live_output_eq") as m_eq, \
             patch("autostream_appliance_models.save_config"):
            ok, norm, err = apply_eq_field(config_path, "peq1_db", "2.0", settings=store)
        assert ok is True
        m_eq.assert_called_once()
        args = m_eq.call_args[0]
        assert args[0] == pytest.approx(2.0)  # peq1
        snap = store.snapshot()
        assert snap.output_eq.peq1_db == pytest.approx(2.0)

    def test_clamping_applied(self, tmp_path):
        from autostream_appliance_models import apply_eq_field, _OUTPUT_EQ_DB_MAX
        config_path = _make_config(str(tmp_path))
        store = _make_store(config_path)
        with patch("autostream_appliance_models.set_live_output_gain"):
            ok, norm, err = apply_eq_field(config_path, "gain_db", "9999", settings=store)
        assert ok is True
        assert float(norm) == pytest.approx(_OUTPUT_EQ_DB_MAX)

    def test_non_numeric_raises(self, tmp_path):
        from autostream_appliance_models import apply_eq_field
        config_path = _make_config(str(tmp_path))
        store = _make_store(config_path)
        with pytest.raises(ValueError, match="numeric"):
            apply_eq_field(config_path, "gain_db", "abc", settings=store)

    def test_fallback_uses_save_config(self, tmp_path):
        from autostream_appliance_models import apply_eq_field
        config_path = _make_config(str(tmp_path))
        with patch("autostream_appliance_models.set_live_output_gain"), \
             patch("autostream_appliance_models.save_config") as m_save, \
             patch("autostream_appliance_models.load_config") as m_load, \
             patch("autostream_appliance_models.parse_config") as m_parse:
            m_parse.return_value = MagicMock(output_eq=MagicMock(gain_db=0.0))
            m_load.return_value = {"output_eq": {}}
            ok, norm, err = apply_eq_field(config_path, "gain_db", "1.0", settings=None)
        assert ok is True
        m_save.assert_called_once()


# ── apply_eq_reset ────────────────────────────────────────────────────────────

class TestApplyEqResetViaStore:
    def test_zeroes_all_bands_via_store(self, tmp_path):
        from autostream_appliance_models import apply_eq_reset, _OUTPUT_EQ_BAND_FIELDS
        config_path = _make_config(str(tmp_path), extra={"output_eq": {"peq1_db": 5.0, "peq2_db": 3.0}})
        store = _make_store(config_path)
        with patch("autostream_appliance_models.set_live_output_eq") as m_eq, \
             patch("autostream_appliance_models.save_config") as m_save:
            ok, err = apply_eq_reset(config_path, settings=store)
        assert ok is True
        assert err == ""
        m_save.assert_not_called()
        m_eq.assert_called_once_with(0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
        snap = store.snapshot()
        for band in _OUTPUT_EQ_BAND_FIELDS:
            assert getattr(snap.output_eq, band) == pytest.approx(0.0), band

    def test_fallback_uses_save_config(self, tmp_path):
        from autostream_appliance_models import apply_eq_reset
        config_path = _make_config(str(tmp_path))
        with patch("autostream_appliance_models.set_live_output_eq"), \
             patch("autostream_appliance_models.save_config") as m_save, \
             patch("autostream_appliance_models.load_config") as m_load:
            m_load.return_value = {"output_eq": {}}
            ok, err = apply_eq_reset(config_path, settings=None)
        assert ok is True
        m_save.assert_called_once()


# ── send_service_config_json ──────────────────────────────────────────────────

class TestServiceConfigJsonViaStore:
    def test_store_updated_not_save_config(self, tmp_path):
        from autostream_webui_api import send_service_config_json
        config_path = _make_config(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"field": "service_stylus_life_hours_input1", "value": "500"})
        with patch("autostream_webui_api.save_config") as m_save, \
             patch("autostream_webui_api.update_playback_input_config"), \
             patch("autostream_webui_api.get_playback_snapshot") as m_snap:
            m_snap.return_value = MagicMock(inputs={})
            send_service_config_json(handler, state, body)
        m_save.assert_not_called()
        assert sent.get("body", {}).get("ok") is True
        snap = store.snapshot()
        assert snap.audio1.stylus_life_hours == 500

    def test_fallback_uses_save_config(self, tmp_path):
        from autostream_webui_api import send_service_config_json
        config_path = _make_config(str(tmp_path))
        state = _make_state(config_path, None)
        handler, sent = _make_handler()
        body = json.dumps({"field": "service_stylus_life_hours_input1", "value": "750"})
        with patch("autostream_webui_api.save_config") as m_save, \
             patch("autostream_webui_api.load_config") as m_load, \
             patch("autostream_webui_api.parse_config") as m_parse, \
             patch("autostream_webui_api.update_playback_input_config"), \
             patch("autostream_webui_api.get_playback_snapshot") as m_snap:
            m_snap.return_value = MagicMock(inputs={})
            m_load.return_value = {
                "audio1": {"is_turntable": True, "stylus_life_hours": 1000,
                           "belt_life_hours": 2000, "belt_life_years": 3,
                           "bearing_life_hours": 5000, "bearing_life_years": 7}
            }
            mock_audio = MagicMock()
            mock_audio.is_turntable = True
            mock_audio.stylus_life_hours = 1000
            mock_audio.belt_life_hours = 2000
            mock_audio.belt_life_years = 3
            mock_audio.bearing_life_hours = 5000
            mock_audio.bearing_life_years = 7
            mock_parsed = MagicMock()
            mock_parsed.audio1 = mock_audio
            m_parse.return_value = mock_parsed
            send_service_config_json(handler, state, body)
        m_save.assert_called_once()

    def test_unknown_field_returns_400(self, tmp_path):
        from autostream_webui_api import send_service_config_json
        config_path = _make_config(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"field": "bogus.field", "value": "1"})
        send_service_config_json(handler, state, body)
        assert sent["code"] == 400
        assert sent["body"]["ok"] is False


# ── handle_logs_post ──────────────────────────────────────────────────────────

class TestLogsPostViaStore:
    def _make_logs_state(self, config_path, store):
        state = MagicMock()
        state.config_path = config_path
        state.settings = store
        state.request_path = "/logs"
        return state

    def test_store_updated_not_save_config(self, tmp_path):
        from autostream_webui_page_logs import handle_logs_post
        config_path = _make_config(str(tmp_path))
        store = _make_store(config_path)
        state = self._make_logs_state(config_path, store)
        handler = MagicMock()
        handler.headers = {}
        with patch("autostream_webui_page_logs.save_config") as m_save, \
             patch("autostream_webui_page_logs.update_live_platform_log_level") as m_live, \
             patch("autostream_webui_page_logs.save_log_level"), \
             patch("autostream_webui_page_logs._set_flash_cookie"), \
             patch("autostream_webui_page_logs.build_page_html", return_value=""):
            m_live.return_value = ("DEBUG", True)
            handle_logs_post(handler, state, "log_level=DEBUG")
        m_save.assert_not_called()
        snap = store.snapshot()
        assert snap.general.log_level == "debug"

    def test_fallback_uses_save_config(self, tmp_path):
        from autostream_webui_page_logs import handle_logs_post
        config_path = _make_config(str(tmp_path))
        state = self._make_logs_state(config_path, None)
        handler = MagicMock()
        handler.headers = {}
        with patch("autostream_webui_page_logs.save_config") as m_save, \
             patch("autostream_webui_page_logs.load_config") as m_load, \
             patch("autostream_webui_page_logs.parse_config") as m_parse, \
             patch("autostream_webui_page_logs.update_live_platform_log_level") as m_live, \
             patch("autostream_webui_page_logs.save_log_level"), \
             patch("autostream_webui_page_logs._set_flash_cookie"), \
             patch("autostream_webui_page_logs.build_page_html", return_value=""):
            m_live.return_value = ("DEBUG", True)
            m_load.return_value = {"general": {"log_level": "INFO"}}
            m_parse.return_value = MagicMock(owntone=MagicMock(base_url=None))
            handle_logs_post(handler, state, "log_level=DEBUG")
        m_save.assert_called_once()


# ── Callers pass settings= ────────────────────────────────────────────────────

class TestCallerPassSettings:
    """Verify that webui_api callers forward settings= to apply_eq_field/reset."""

    def test_send_output_eq_config_passes_settings(self, tmp_path):
        """send_output_eq_config_json passes settings=getattr(state,'settings',None)."""
        from autostream_webui_api import send_output_eq_config_json
        config_path = _make_config(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"field": "gain_db", "value": "1.5"})
        with patch("autostream_webui_api.apply_eq_field", return_value=(True, "1.5", "")) as m_apply:
            send_output_eq_config_json(handler, state, body)
        m_apply.assert_called_once()
        _, kwargs = m_apply.call_args
        assert kwargs.get("settings") is store

    def test_send_output_eq_reset_passes_settings(self, tmp_path):
        """send_output_eq_reset_json passes settings=getattr(state,'settings',None)."""
        from autostream_webui_api import send_output_eq_reset_json
        config_path = _make_config(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, store)
        handler, sent = _make_handler()
        with patch("autostream_webui_api.apply_eq_reset", return_value=(True, "")) as m_reset:
            send_output_eq_reset_json(handler, state)
        m_reset.assert_called_once()
        _, kwargs = m_reset.call_args
        assert kwargs.get("settings") is store

    def test_send_federation_eq_config_passes_settings(self, tmp_path):
        """send_federation_eq_config_json passes settings=getattr(state,'settings',None)."""
        from autostream_webui_api import send_federation_eq_config_json
        config_path = _make_config(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"field": "gain_db", "value": "2.0"})
        with patch("autostream_webui_api.apply_eq_field", return_value=(True, "2.0", "")) as m_apply:
            send_federation_eq_config_json(handler, state, body)
        m_apply.assert_called_once()
        _, kwargs = m_apply.call_args
        assert kwargs.get("settings") is store

    def test_send_federation_eq_reset_passes_settings(self, tmp_path):
        """send_federation_eq_reset_json passes settings=getattr(state,'settings',None)."""
        from autostream_webui_api import send_federation_eq_reset_json
        config_path = _make_config(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, store)
        handler, sent = _make_handler()
        with patch("autostream_webui_api.apply_eq_reset", return_value=(True, "")) as m_reset:
            send_federation_eq_reset_json(handler, state)
        m_reset.assert_called_once()
        _, kwargs = m_reset.call_args
        assert kwargs.get("settings") is store

    def test_gateway_eq_field_passes_settings(self, tmp_path):
        """send_gateway_eq_config_json passes settings=getattr(state,'settings',None)."""
        from autostream_appliance_gateway import send_gateway_eq_config_json
        config_path = _make_config(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"field": "gain_db", "value": "1.0"})
        with patch("autostream_appliance_gateway.resolve_appliance", return_value=("bound", None)), \
             patch("autostream_appliance_gateway.apply_eq_field", return_value=(True, "1.0", "")) as m_apply:
            send_gateway_eq_config_json(handler, state, "self", body)
        m_apply.assert_called_once()
        _, kwargs = m_apply.call_args
        assert kwargs.get("settings") is store

    def test_gateway_eq_reset_passes_settings(self, tmp_path):
        """send_gateway_eq_reset_json passes settings=getattr(state,'settings',None)."""
        from autostream_appliance_gateway import send_gateway_eq_reset_json
        config_path = _make_config(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, store)
        handler, sent = _make_handler()
        with patch("autostream_appliance_gateway.resolve_appliance", return_value=("bound", None)), \
             patch("autostream_appliance_gateway.apply_eq_reset", return_value=(True, "")) as m_reset:
            send_gateway_eq_reset_json(handler, state, "self")
        m_reset.assert_called_once()
        _, kwargs = m_reset.call_args
        assert kwargs.get("settings") is store
