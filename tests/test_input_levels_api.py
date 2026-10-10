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
    }


def _call(levels=None, connected=True, config=None, levels_error=None, config_error=None):
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
    assert body["inputs"] == [
        {"index": 1, "enabled": True, "running": True, "dbfs": -52.34},
        {"index": 2, "enabled": True, "running": True, "dbfs": -61.0},
    ]


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
