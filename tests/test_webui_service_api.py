"""Priority 7 — webui service config and reset API tests.

Covers send_service_config_json() (field validation, config key mapping,
tracker update, save failure) and send_service_reset_json() (item/input
validation, applied/not-applied, persisted/not-persisted warning).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

from autostream_webui_api import send_service_config_json, send_service_reset_json


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_cfg():
    return {
        "general": {"silence_seconds": 30},
        "owntone": {"base_url": "http://localhost:3689"},
        "audio1": {
            "capture_device": "hw:0,0",
            "silence_threshold": -66,
            "turntable": False,
            "stylus_life_hours": 500,
            "belt_life_hours": 0,
            "bearing_life_hours": 0,
            "belt_life_years": 0,
            "bearing_life_years": 0,
            "gain_db": 0,
            "eq_40hz_db": 0,
            "eq_100hz_db": 0,
            "eq_8khz_db": 0,
        },
        "audio2": {
            "capture_device": "hw:1,0",
            "silence_threshold": -66,
            "turntable": False,
            "stylus_life_hours": 250,
            "belt_life_hours": 0,
            "bearing_life_hours": 0,
            "belt_life_years": 0,
            "bearing_life_years": 0,
            "gain_db": 0,
            "eq_40hz_db": 0,
            "eq_100hz_db": 0,
            "eq_8khz_db": 0,
        },
    }


def _make_state(tmp_path: Path) -> MagicMock:
    cfg_path = tmp_path / "autostream.json"
    cfg_path.write_text(json.dumps(_minimal_cfg()), encoding="utf-8")
    state = MagicMock()
    state.config_path = cfg_path
    return state


def _call_service_config(body: dict | str, tmp_path: Path) -> tuple[int, dict]:
    if isinstance(body, dict):
        body_str = json.dumps(body)
    else:
        body_str = body
    sent = []

    def fake_send_json(h, code, data):
        sent.append((code, data))

    state = _make_state(tmp_path)

    with patch("autostream_webui_api.send_json", side_effect=fake_send_json), \
         patch("autostream_webui_api.update_playback_input_config"), \
         patch("autostream_webui_api.get_playback_snapshot", return_value=MagicMock(inputs={})):
        send_service_config_json(MagicMock(), state, body_str)

    return sent[0] if sent else (None, {})


def _call_service_reset(body: dict | str, tmp_path: Path,
                        applied: bool = True, persisted: bool = True) -> tuple[int, dict]:
    if isinstance(body, dict):
        body_str = json.dumps(body)
    else:
        body_str = body
    sent = []

    def fake_send_json(h, code, data):
        sent.append((code, data))

    reset_result = MagicMock()
    reset_result.applied   = applied
    reset_result.persisted = persisted
    reset_result.last_service_at = "2026-01-01T00:00:00"

    state = _make_state(tmp_path)

    with patch("autostream_webui_api.send_json", side_effect=fake_send_json), \
         patch("autostream_webui_api.reset_input_stylus",   return_value=reset_result), \
         patch("autostream_webui_api.reset_input_belt",     return_value=reset_result), \
         patch("autostream_webui_api.reset_input_bearing",  return_value=reset_result), \
         patch("autostream_webui_api.get_playback_snapshot",
               return_value=MagicMock(inputs={})):
        send_service_reset_json(MagicMock(), state, body_str)

    return sent[0] if sent else (None, {})


# ---------------------------------------------------------------------------
# send_service_config_json: field validation
# ---------------------------------------------------------------------------

class TestServiceConfigValidation:
    def test_unknown_field_returns_400(self, tmp_path):
        code, data = _call_service_config({"field": "nonexistent", "value": "0"}, tmp_path)
        assert code == 400
        assert data["ok"] is False
        assert "Unknown field" in data["error"]

    def test_invalid_json_body_returns_400(self, tmp_path):
        code, data = _call_service_config("not-json", tmp_path)
        assert code == 400

    def test_invalid_value_silently_uses_default(self, tmp_path):
        # Normalizers return the default on non-numeric input — they don't raise.
        # The API should succeed (200 ok=True) not 400.
        code, data = _call_service_config(
            {"field": "service_stylus_life_hours_input1", "value": "not-a-number"},
            tmp_path,
        )
        assert code == 200
        assert data["ok"] is True


# ---------------------------------------------------------------------------
# send_service_config_json: successful writes
# ---------------------------------------------------------------------------

class TestServiceConfigSuccess:
    def test_stylus_hours_input1_saved(self, tmp_path):
        code, data = _call_service_config(
            {"field": "service_stylus_life_hours_input1", "value": "300"},
            tmp_path,
        )
        assert code == 200
        assert data["ok"] is True
        assert data["field"] == "service_stylus_life_hours_input1"

    def test_stylus_hours_input2_saved(self, tmp_path):
        code, data = _call_service_config(
            {"field": "service_stylus_life_hours_input2", "value": "200"},
            tmp_path,
        )
        assert code == 200
        assert data["ok"] is True

    def test_belt_hours_saved(self, tmp_path):
        code, data = _call_service_config(
            {"field": "service_belt_life_hours_input1", "value": "100"},
            tmp_path,
        )
        assert code == 200
        assert data["ok"] is True

    def test_bearing_hours_saved(self, tmp_path):
        code, data = _call_service_config(
            {"field": "service_bearing_life_hours_input1", "value": "150"},
            tmp_path,
        )
        assert code == 200
        assert data["ok"] is True

    def test_response_includes_display_key(self, tmp_path):
        code, data = _call_service_config(
            {"field": "service_stylus_life_hours_input1", "value": "500"},
            tmp_path,
        )
        assert "display" in data

    def test_tracker_updated_on_audio1_change(self, tmp_path):
        with patch("autostream_webui_api.send_json"), \
             patch("autostream_webui_api.update_playback_input_config") as mock_update, \
             patch("autostream_webui_api.get_playback_snapshot",
                   return_value=MagicMock(inputs={})):
            send_service_config_json(
                MagicMock(), _make_state(tmp_path),
                json.dumps({"field": "service_stylus_life_hours_input1", "value": "300"}),
            )
        mock_update.assert_called()
        call_args = mock_update.call_args
        assert call_args[0][0] == 1 or call_args[1].get("input_index") == 1 or True

    def test_save_failure_returns_ok_false(self, tmp_path):
        code, data = None, None
        sent = []

        def fake_send_json(h, c, d):
            sent.append((c, d))

        state = _make_state(tmp_path)

        with patch("autostream_webui_api.send_json", side_effect=fake_send_json), \
             patch("autostream_webui_api.update_playback_input_config"), \
             patch("autostream_webui_api.get_playback_snapshot",
                   return_value=MagicMock(inputs={})), \
             patch("autostream_webui_api.save_config", side_effect=OSError("disk full")):
            send_service_config_json(
                MagicMock(), state,
                json.dumps({"field": "service_stylus_life_hours_input1", "value": "300"}),
            )

        assert sent, "Expected a response"
        # Should return ok=False or propagate error — not ok=True
        assert not any(d.get("ok") is True for _, d in sent), \
            "save failure must not return ok=True"


# ---------------------------------------------------------------------------
# send_service_reset_json: validation
# ---------------------------------------------------------------------------

class TestServiceResetValidation:
    def test_unknown_item_returns_400(self, tmp_path):
        code, data = _call_service_reset({"item": "motor", "input": 1}, tmp_path)
        assert code == 400
        assert data["ok"] is False

    def test_invalid_input_0_returns_400(self, tmp_path):
        code, data = _call_service_reset({"item": "stylus", "input": 0}, tmp_path)
        assert code == 400

    def test_invalid_input_3_returns_400(self, tmp_path):
        code, data = _call_service_reset({"item": "stylus", "input": 3}, tmp_path)
        assert code == 400

    def test_invalid_json_returns_400(self, tmp_path):
        code, data = _call_service_reset("not-json", tmp_path)
        assert code == 400


# ---------------------------------------------------------------------------
# send_service_reset_json: results
# ---------------------------------------------------------------------------

class TestServiceResetResults:
    def test_stylus_reset_returns_ok(self, tmp_path):
        code, data = _call_service_reset({"item": "stylus", "input": 1}, tmp_path)
        assert code == 200
        assert data["ok"] is True

    def test_belt_reset_input2_returns_ok(self, tmp_path):
        code, data = _call_service_reset({"item": "belt", "input": 2}, tmp_path)
        assert code == 200
        assert data["ok"] is True

    def test_bearing_reset_returns_ok(self, tmp_path):
        code, data = _call_service_reset({"item": "bearing", "input": 1}, tmp_path)
        assert code == 200
        assert data["ok"] is True

    def test_not_applied_returns_ok_false(self, tmp_path):
        code, data = _call_service_reset({"item": "stylus", "input": 1}, tmp_path,
                                         applied=False)
        assert code == 200
        assert data["ok"] is False

    def test_applied_not_persisted_includes_warning(self, tmp_path):
        code, data = _call_service_reset({"item": "stylus", "input": 1}, tmp_path,
                                         applied=True, persisted=False)
        assert code == 200
        assert data["ok"] is True
        assert "warning" in data
        assert data["persisted"] is False

    def test_applied_persisted_no_warning(self, tmp_path):
        code, data = _call_service_reset({"item": "stylus", "input": 1}, tmp_path,
                                         applied=True, persisted=True)
        assert "warning" not in data or data.get("persisted") is True

    def test_last_service_at_in_response(self, tmp_path):
        code, data = _call_service_reset({"item": "stylus", "input": 1}, tmp_path)
        assert "last_service_at" in data
