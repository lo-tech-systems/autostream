"""Tests for dial volume fan-out and partial target failures (WP18).

Covers send_dial_volume_post_json in autostream_webui_api:
1. Authorization guards (missing/empty/unauthorized dial_id).
2. Delta validation (None, float, bool, str).
3. Config load failure → config_error.
4. Backend unavailable → backend_unavailable.
5. No active outputs → no_active_outputs.
6. Fan-out proportional volume scaling across multiple outputs.
7. Zero-master case: delta applied directly (no division by zero).
8. Partial failure: some updates fail → partial=True.
9. All-fail: every update fails → all_outputs_failed.
"""
import io
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

# Stub requests before triggering the import chain:
#   autostream_webui_api → autostream_player_service → autostream_players → requests
sys.modules.setdefault("requests", MagicMock())

from autostream_players import ActionResult, ListOutputsResult, OutputInfo
from autostream_webui_api import send_dial_volume_post_json
from autostream_webui_state import WebUIState

DIAL_ID = "test-dial-uuid-1234"
BASE_URL = "http://localhost:3689"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_handler() -> MagicMock:
    h = MagicMock()
    h.wfile = io.BytesIO()
    return h


def _response(handler: MagicMock) -> tuple[int, dict]:
    """Return (http_status_code, parsed_json_body) from a mock handler."""
    code = handler.send_response.call_args[0][0]
    body = json.loads(handler.wfile.getvalue())
    return code, body


def _output(id: str, volume: int, selected: bool = True) -> OutputInfo:
    return OutputInfo(id=id, name=id, selected=selected, volume_percent=volume)


def _ok_list(*outputs: OutputInfo) -> ListOutputsResult:
    return ListOutputsResult(ok=True, outputs=tuple(outputs))


def _fail_list() -> ListOutputsResult:
    return ListOutputsResult(ok=False, error="connection refused")


def _invoke(
    json_obj: dict,
    *,
    authorized: bool = True,
    list_result: ListOutputsResult | None = None,
    update_results: list[ActionResult] | None = None,
    config_error: bool = False,
) -> tuple[int, dict, MagicMock]:
    """Call send_dial_volume_post_json and return (status, body, update_mock)."""
    state = WebUIState(config_path="dummy.ini")
    handler = _make_handler()
    if list_result is None:
        list_result = _ok_list()
    if update_results is None:
        update_results = [ActionResult(ok=True)] * len(
            [o for o in list_result.outputs if o.selected]
        )
    update_iter = iter(update_results)
    update_mock = MagicMock(side_effect=lambda *a, **kw: next(update_iter, ActionResult(ok=True)))

    parsed = MagicMock()
    parsed.owntone.base_url = BASE_URL

    def _cfg_load(path):
        if config_error:
            raise OSError("disk full")
        return ""

    with patch("autostream_webui_api.is_dial_authorized", return_value=authorized), \
         patch("autostream_webui_api.locked_load_config", side_effect=_cfg_load), \
         patch("autostream_webui_api.parse_config", return_value=parsed), \
         patch("autostream_webui_api.list_outputs", return_value=list_result), \
         patch("autostream_webui_api.update_output", update_mock):
        send_dial_volume_post_json(handler, state, json_obj)

    code, body = _response(handler)
    return code, body, update_mock


# ---------------------------------------------------------------------------
# Authorization guards
# ---------------------------------------------------------------------------

class TestDialVolumeAuth:
    def test_missing_dial_id_returns_403(self):
        code, body, _ = _invoke({"delta": 5})
        assert code == 403
        assert body == {}

    def test_empty_dial_id_returns_403(self):
        code, body, _ = _invoke({"dial_id": "", "delta": 5})
        assert code == 403
        assert body == {}

    def test_unauthorized_dial_id_returns_403(self):
        code, body, _ = _invoke({"dial_id": DIAL_ID, "delta": 5}, authorized=False)
        assert code == 403
        assert body == {}


# ---------------------------------------------------------------------------
# Delta validation
# ---------------------------------------------------------------------------

class TestDialVolumeDeltaValidation:
    def test_missing_delta_returns_invalid_delta(self):
        code, body, _ = _invoke({"dial_id": DIAL_ID})
        assert code == 200
        assert body == {"ok": False, "error": "invalid_delta"}

    def test_float_delta_returns_invalid_delta(self):
        code, body, _ = _invoke({"dial_id": DIAL_ID, "delta": 5.5})
        assert code == 200
        assert body == {"ok": False, "error": "invalid_delta"}

    def test_bool_delta_returns_invalid_delta(self):
        # Python bool is a subclass of int; the code explicitly rejects it
        code, body, _ = _invoke({"dial_id": DIAL_ID, "delta": True})
        assert code == 200
        assert body == {"ok": False, "error": "invalid_delta"}

    def test_string_delta_returns_invalid_delta(self):
        code, body, _ = _invoke({"dial_id": DIAL_ID, "delta": "+5"})
        assert code == 200
        assert body == {"ok": False, "error": "invalid_delta"}


# ---------------------------------------------------------------------------
# Backend / config failures
# ---------------------------------------------------------------------------

class TestDialVolumeBackendErrors:
    def test_config_error_returns_config_error(self):
        code, body, _ = _invoke(
            {"dial_id": DIAL_ID, "delta": 5}, config_error=True
        )
        assert code == 200
        assert body == {"ok": False, "error": "config_error"}

    def test_backend_unavailable_returns_error(self):
        code, body, _ = _invoke(
            {"dial_id": DIAL_ID, "delta": 5}, list_result=_fail_list()
        )
        assert code == 200
        assert body == {"ok": False, "error": "backend_unavailable"}

    def test_no_active_outputs_returns_error(self):
        inactive = _output("spk", 50, selected=False)
        code, body, _ = _invoke(
            {"dial_id": DIAL_ID, "delta": 5},
            list_result=_ok_list(inactive),
        )
        assert code == 200
        assert body == {"ok": False, "error": "no_active_outputs"}


# ---------------------------------------------------------------------------
# Fan-out and proportional volume distribution
# ---------------------------------------------------------------------------

class TestDialVolumeFanOut:
    def test_single_output_success(self):
        out = _output("spk", 50)
        code, body, update_mock = _invoke(
            {"dial_id": DIAL_ID, "delta": 10},
            list_result=_ok_list(out),
        )
        assert code == 200
        assert body == {"ok": True, "volume": 60}
        update_mock.assert_called_once_with(
            BASE_URL, "spk", volume_percent=60, timeout=3
        )

    def test_two_outputs_proportional_scaling(self):
        """Outputs at 60% and 40% (master=50). Delta +10 → new_master=60.
        Proportional: 60*60/50=72, 40*60/50=48."""
        out_a = _output("spk_a", 60)
        out_b = _output("spk_b", 40)
        code, body, update_mock = _invoke(
            {"dial_id": DIAL_ID, "delta": 10},
            list_result=_ok_list(out_a, out_b),
        )
        assert code == 200
        assert body == {"ok": True, "volume": 60}
        calls = update_mock.call_args_list
        assert len(calls) == 2
        assert call(BASE_URL, "spk_a", volume_percent=72, timeout=3) in calls
        assert call(BASE_URL, "spk_b", volume_percent=48, timeout=3) in calls

    def test_zero_master_applies_delta_directly(self):
        """When all outputs are at 0%, new_master is applied directly to avoid
        division by zero in proportional scaling."""
        out_a = _output("spk_a", 0)
        out_b = _output("spk_b", 0)
        code, body, update_mock = _invoke(
            {"dial_id": DIAL_ID, "delta": 30},
            list_result=_ok_list(out_a, out_b),
        )
        assert code == 200
        assert body == {"ok": True, "volume": 30}
        calls = update_mock.call_args_list
        assert call(BASE_URL, "spk_a", volume_percent=30, timeout=3) in calls
        assert call(BASE_URL, "spk_b", volume_percent=30, timeout=3) in calls

    def test_delta_clamped_to_100(self):
        """An oversized delta must be clamped; output at 50 + 200 → master stays 100."""
        out = _output("spk", 50)
        code, body, _ = _invoke(
            {"dial_id": DIAL_ID, "delta": 200},
            list_result=_ok_list(out),
        )
        assert code == 200
        assert body == {"ok": True, "volume": 100}

    def test_delta_clamped_to_minus_100(self):
        out = _output("spk", 50)
        code, body, _ = _invoke(
            {"dial_id": DIAL_ID, "delta": -200},
            list_result=_ok_list(out),
        )
        assert code == 200
        assert body == {"ok": True, "volume": 0}

    def test_new_master_clamped_to_100(self):
        out = _output("spk", 95)
        code, body, _ = _invoke(
            {"dial_id": DIAL_ID, "delta": 10},
            list_result=_ok_list(out),
        )
        assert code == 200
        assert body == {"ok": True, "volume": 100}

    def test_new_master_clamped_to_0(self):
        out = _output("spk", 5)
        code, body, _ = _invoke(
            {"dial_id": DIAL_ID, "delta": -20},
            list_result=_ok_list(out),
        )
        assert code == 200
        assert body == {"ok": True, "volume": 0}

    def test_unselected_output_excluded_from_fan_out(self):
        active = _output("active", 50, selected=True)
        inactive = _output("inactive", 80, selected=False)
        code, body, update_mock = _invoke(
            {"dial_id": DIAL_ID, "delta": 10},
            list_result=_ok_list(active, inactive),
        )
        assert code == 200
        assert body == {"ok": True, "volume": 60}
        ids_updated = {c.args[1] for c in update_mock.call_args_list}
        assert ids_updated == {"active"}


# ---------------------------------------------------------------------------
# Partial and total update failures
# ---------------------------------------------------------------------------

class TestDialVolumeUpdateFailures:
    def test_partial_failure_returns_partial_true(self):
        """One of two updates fails: response is ok=True with partial=True."""
        out_a = _output("spk_a", 50)
        out_b = _output("spk_b", 50)
        code, body, _ = _invoke(
            {"dial_id": DIAL_ID, "delta": 10},
            list_result=_ok_list(out_a, out_b),
            update_results=[ActionResult(ok=True), ActionResult(ok=False, error="timeout")],
        )
        assert code == 200
        assert body.get("ok") is True
        assert body.get("partial") is True
        assert body.get("volume") == 60

    def test_all_outputs_failed_returns_error(self):
        out_a = _output("spk_a", 50)
        out_b = _output("spk_b", 50)
        code, body, _ = _invoke(
            {"dial_id": DIAL_ID, "delta": 10},
            list_result=_ok_list(out_a, out_b),
            update_results=[
                ActionResult(ok=False, error="timeout"),
                ActionResult(ok=False, error="timeout"),
            ],
        )
        assert code == 200
        assert body == {"ok": False, "error": "all_outputs_failed"}

    def test_single_output_failure_returns_all_outputs_failed(self):
        out = _output("spk", 50)
        code, body, _ = _invoke(
            {"dial_id": DIAL_ID, "delta": 10},
            list_result=_ok_list(out),
            update_results=[ActionResult(ok=False, error="unreachable")],
        )
        assert code == 200
        assert body == {"ok": False, "error": "all_outputs_failed"}
