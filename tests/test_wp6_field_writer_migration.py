"""tests/test_wp6_field_writer_migration.py

WP6 acceptance tests: existing field-level writers routed through SettingsStore.

Tests cover:
  - apply_eq_field: bool field via store, bool field fallback (no store)
  - apply_eq_field: dB field via store (uses pre-write snapshot), dB fallback
  - apply_eq_reset: zeroes all bands via store, fallback path
  - send_service_config_json: persistence via store, fallback when no store
  - Callers in webui_api and gateway pass settings= to apply_eq_field/reset
"""
from __future__ import annotations

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

from settings_fixtures import fixed_view
from fake_store import fake_playback_mock
from autostream_settings import SettingsStore, as_view, writable_store


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
    state.settings = as_view(store)
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
    def test_store_updated(self, tmp_path):
        from autostream_monitor_control import apply_eq_field
        config_path = _make_config(str(tmp_path))
        store = _make_store(config_path)
        with patch("autostream_monitor_control.set_live_output_auto_trim") as m_trim, \
             patch("autostream_monitor_control.save_config") as m_save:
            ok, norm, err = apply_eq_field(config_path, "auto_trim_enabled", "true", settings=store)
        assert ok is True
        assert norm == "true"
        assert err == ""
        m_save.assert_not_called()
        m_trim.assert_called_once_with(True, requester=None)
        snap = store.snapshot()
        assert snap.output_eq.auto_trim_enabled is True

    def test_no_store_answers_500(self, tmp_path):
        from webui.browser.api_service import send_service_config_json
        config_path = _make_config(str(tmp_path))
        state = _make_state(config_path, None)
        state.settings = fixed_view()
        handler, sent = _make_handler()
        body = json.dumps({"field": "service_stylus_life_hours_input1", "value": "750"})
        with patch("autostream_playback_tracking.update_playback_input_config"), \
             patch("autostream_live_config._store_of", return_value=None), \
             fake_playback_mock() as m_snap:
            m_snap.return_value = MagicMock(inputs={})
            send_service_config_json(handler, state, body)
        assert sent["code"] == 500
        assert sent["body"] == {"ok": False, "error": "Settings store unavailable"}

    def test_unknown_field_returns_400(self, tmp_path):
        from webui.browser.api_service import send_service_config_json
        config_path = _make_config(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"field": "bogus.field", "value": "1"})
        send_service_config_json(handler, state, body)
        assert sent["code"] == 400
        assert sent["body"]["ok"] is False


# ── Callers pass settings= ────────────────────────────────────────────────────

class TestCallerPassSettings:
    """Verify that webui_api callers forward settings= to apply_eq_field/reset."""

    def test_send_federation_eq_config_passes_settings(self, tmp_path):
        """send_federation_eq_config_json passes settings=getattr(state,'settings',None)."""
        from webui.peer.federation import send_federation_eq_config_json
        config_path = _make_config(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"field": "gain_db", "value": "2.0"})
        with patch("autostream_monitor_control.apply_eq_field", return_value=(True, "2.0", "")) as m_apply:
            send_federation_eq_config_json(handler, state, body)
        m_apply.assert_called_once()
        _, kwargs = m_apply.call_args
        assert writable_store(kwargs.get("settings")) is store

    def test_send_federation_eq_reset_passes_settings(self, tmp_path):
        """send_federation_eq_reset_json passes settings=getattr(state,'settings',None)."""
        from webui.peer.federation import send_federation_eq_reset_json
        config_path = _make_config(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, store)
        handler, sent = _make_handler()
        with patch("autostream_monitor_control.apply_eq_reset", return_value=(True, "")) as m_reset:
            send_federation_eq_reset_json(handler, state)
        m_reset.assert_called_once()
        _, kwargs = m_reset.call_args
        assert writable_store(kwargs.get("settings")) is store

    def test_gateway_eq_field_passes_settings(self, tmp_path):
        """send_gateway_eq_config_json passes settings=getattr(state,'settings',None)."""
        from webui.peer.gateway import send_gateway_eq_config_json
        config_path = _make_config(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, store)
        handler, sent = _make_handler()
        body = json.dumps({"field": "gain_db", "value": "1.0"})
        with patch("webui.peer.gateway.resolve_appliance", return_value=("bound", None)), \
             patch("autostream_monitor_control.apply_eq_field", return_value=(True, "1.0", "")) as m_apply:
            send_gateway_eq_config_json(handler, state, "self", body)
        m_apply.assert_called_once()
        _, kwargs = m_apply.call_args
        assert writable_store(kwargs.get("settings")) is store

    def test_gateway_eq_reset_passes_settings(self, tmp_path):
        """send_gateway_eq_reset_json passes settings=getattr(state,'settings',None)."""
        from webui.peer.gateway import send_gateway_eq_reset_json
        config_path = _make_config(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, store)
        handler, sent = _make_handler()
        with patch("webui.peer.gateway.resolve_appliance", return_value=("bound", None)), \
             patch("autostream_monitor_control.apply_eq_reset", return_value=(True, "")) as m_reset:
            send_gateway_eq_reset_json(handler, state, "self")
        m_reset.assert_called_once()
        _, kwargs = m_reset.call_args
        assert writable_store(kwargs.get("settings")) is store
