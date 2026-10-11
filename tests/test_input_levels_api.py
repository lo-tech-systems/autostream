"""Tests for GET /api/inputs/levels, the Setup page's level readout.

The handler reads only cached values: the coordinator's last-poll levels,
the saved config's enabled flags and the monitor's connected flag.
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

from autostream_webui_api import send_input_levels_json
from autostream_webui_state import WebUIState


def _make_handler() -> MagicMock:
    h = MagicMock()
    h.wfile = io.BytesIO()
    return h


def _response(handler: MagicMock) -> tuple[int, dict]:
    code = handler.send_response.call_args[0][0]
    body = json.loads(handler.wfile.getvalue())
    return code, body


def _level(index: int, dbfs: float) -> dict:
    return {
        "index": index,
        "label": f"Input {index}",
        "dbfs": dbfs,
        "detected_hz": 0.0,
        "is_above_threshold": False,
        "vu_history": [],
        "dynamic_rate_matching": False,
        "rate_mismatch_hz": 0,
        "negotiated_hz": 48000,
        "monitor_supports_rate_matching": True,
    }


def _call(levels=None, connected=True, config=None, levels_error=None, config_error=None,
          note=lambda index: f"note {index}", rate=lambda index: f"rate {index}"):
    if config is None:
        config = MagicMock(audio1_enabled=True, audio2_enabled=False)
    state = WebUIState(config_path="dummy.json", state_path="dummy-state.json")
    handler = _make_handler()
    levels_patch = (
        patch("autostream_webui_api.get_monitor_levels_dbfs", side_effect=levels_error)
        if levels_error is not None
        else patch("autostream_webui_api.get_monitor_levels_dbfs", return_value=levels or [])
    )
    config_patch = (
        patch("autostream_webui_api._config_snapshot", side_effect=config_error)
        if config_error is not None
        else patch("autostream_webui_api._config_snapshot", return_value=config)
    )
    with levels_patch, config_patch, patch(
        "autostream_webui_api.input_rate_texts",
        side_effect=lambda index: (note(index), rate(index)),
    ), patch(
        "autostream_webui_api.get_monitor_runtime_info",
        return_value=MagicMock(connected=connected),
    ):
        send_input_levels_json(handler, state)
    return _response(handler)


def test_two_running_inputs():
    config = MagicMock(audio1_enabled=True, audio2_enabled=True)
    code, body = _call(levels=[_level(1, -52.34), _level(2, -61.0)], config=config)
    assert code == 200
    assert body["ok"] is True
    assert body["connected"] is True
    rate_fields = {
        "dynamic_rate_matching": False,
        "rate_mismatch_hz": 0,
        "negotiated_hz": 48000,
        "monitor_supports_rate_matching": True,
    }
    assert body["inputs"] == [
        {"index": 1, "enabled": True, "running": True, "dbfs": -52.34,
         "sample_rate_text": "rate 1", "rate_matching_note": "note 1", **rate_fields},
        {"index": 2, "enabled": True, "running": True, "dbfs": -61.0,
         "sample_rate_text": "rate 2", "rate_matching_note": "note 2", **rate_fields},
    ]


def test_rate_fields_are_the_monitors_reported_values():
    level = _level(1, -40.0)
    level.update(dynamic_rate_matching=True, rate_mismatch_hz=44100,
                 negotiated_hz=48000, monitor_supports_rate_matching=False)
    code, body = _call(levels=[level])
    first = body["inputs"][0]
    assert first["dynamic_rate_matching"] is True
    assert first["rate_mismatch_hz"] == 44100
    assert first["negotiated_hz"] == 48000
    assert first["monitor_supports_rate_matching"] is False


def test_input_without_a_running_monitor_gets_empty_rate_fields_and_the_note():
    code, body = _call(levels=[_level(1, -40.0)])
    second = body["inputs"][1]
    assert second["running"] is False
    assert second["dynamic_rate_matching"] is False
    assert second["rate_mismatch_hz"] == 0
    assert second["negotiated_hz"] == 0
    assert second["monitor_supports_rate_matching"] is False
    assert second["rate_matching_note"] == "note 2"
    assert second["sample_rate_text"] == "rate 2"


def test_a_non_breaking_space_in_the_text_survives_the_json_reply():
    handler = _make_handler()
    state = WebUIState(config_path="dummy.json", state_path="dummy-state.json")
    with patch("autostream_webui_api.get_monitor_levels_dbfs", return_value=[_level(1, -40.0)]), \
         patch("autostream_webui_api._config_snapshot",
               return_value=MagicMock(audio1_enabled=True, audio2_enabled=False)), \
         patch("autostream_webui_api.input_rate_texts",
               side_effect=lambda index: ("note", "Sample rate: 48 kHz")), \
         patch("autostream_webui_api.get_monitor_runtime_info",
               return_value=MagicMock(connected=True)):
        send_input_levels_json(handler, state)
    raw = handler.wfile.getvalue().decode("ascii")
    assert "&nbsp;" not in raw
    assert "48\\u00a0kHz" in raw
    assert json.loads(raw)["inputs"][0]["sample_rate_text"] == "Sample rate: 48 kHz"


def test_the_rate_texts_are_asked_for_once_per_input():
    asked = []
    def note(index):
        asked.append(index)
        return "x"
    _call(levels=[_level(1, -40.0)], note=note)
    assert asked == [1, 2]


def test_levels_failure_still_carries_the_notes():
    code, body = _call(levels_error=RuntimeError("monitors unavailable"))
    assert [item["sample_rate_text"] for item in body["inputs"]] == ["rate 1", "rate 2"]
    assert [item["rate_matching_note"] for item in body["inputs"]] == ["note 1", "note 2"]


def test_disabled_input_reports_no_level():
    code, body = _call(levels=[_level(1, -40.0)])
    assert code == 200
    first, second = body["inputs"]
    assert first["running"] is True and first["dbfs"] == -40.0
    assert second["index"] == 2
    assert second["running"] is False
    assert second["dbfs"] is None
    assert second["enabled"] is False


def test_disconnected_daemon_blanks_levels():
    code, body = _call(
        levels=[_level(1, -40.0), _level(2, -50.0)],
        connected=False,
        config=MagicMock(audio1_enabled=True, audio2_enabled=True),
    )
    assert code == 200
    assert body["connected"] is False
    assert all(item["dbfs"] is None for item in body["inputs"])
    assert all(item["running"] is True for item in body["inputs"])


def test_config_error_still_answers():
    code, body = _call(levels=[_level(1, -40.0)], config_error=RuntimeError("no config"))
    assert code == 200
    assert [item["enabled"] for item in body["inputs"]] == [False, False]
    assert body["inputs"][0]["dbfs"] == -40.0


def test_levels_failure_still_answers():
    code, body = _call(levels_error=RuntimeError("monitors unavailable"))
    assert code == 200
    assert [item["running"] for item in body["inputs"]] == [False, False]
    assert [item["dbfs"] for item in body["inputs"]] == [None, None]
