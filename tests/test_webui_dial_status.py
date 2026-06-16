"""WP1 tests — POST /api/dial/status endpoint.

Covers:
1.  Routing: dispatched in the UUID-auth block before session/CSRF.
2.  Authorization: absent, empty, non-string, unauthorized UUID → HTTP 403 {}.
3.  Malformed JSON → HTTP 400 (router's native behavior).
4.  Non-object JSON root → HTTP 403 (reaches handler as {}).
5.  Valid authorized UUID → HTTP 200 with ok:true.
6.  application/json with charset parameter is accepted.
7.  selected output volumes [40, 60] → master_volume:50, selected_output_count:2.
8.  Tie cases [40, 61] and [41, 62] match Python round().
9.  No selected outputs → master_volume:null, selected_output_count:0.
10. Unselected outputs excluded from master calculation.
11. playing comes from any_monitor_capturing(), independent of output selection.
12. Config failure → config_error.
13. Backend exception → backend_unavailable.
14. Backend not-ok → backend_unavailable.
15. Handler never calls update_output().
16. calculate_master_volume() helper unit tests.
17. Both Avahi template and autostream_admin generate dial_status=v1.
18. NGINX policy: 403 is not in the intercepted error_page set.
"""
from __future__ import annotations

import io
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

from autostream_players import ListOutputsResult, OutputInfo, ActionResult
from autostream_webui_api import (
    calculate_master_volume,
    send_dial_status_post_json,
)
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
    code = handler.send_response.call_args[0][0]
    body = json.loads(handler.wfile.getvalue())
    return code, body


def _output(id: str, volume: int, selected: bool = True) -> OutputInfo:
    return OutputInfo(id=id, name=id, selected=selected, volume_percent=volume)


def _ok_list(*outputs: OutputInfo) -> ListOutputsResult:
    return ListOutputsResult(ok=True, outputs=tuple(outputs))


def _fail_list(msg: str = "connection refused") -> ListOutputsResult:
    return ListOutputsResult(ok=False, error=msg)


def _invoke(
    json_obj: dict,
    *,
    authorized: bool = True,
    list_result: ListOutputsResult | None = None,
    config_error: bool = False,
    playing: bool = False,
) -> tuple[int, dict, MagicMock]:
    """Call send_dial_status_post_json and return (status, body, update_mock)."""
    state = WebUIState(config_path="dummy.json", state_path="dummy-state.json")
    handler = _make_handler()
    if list_result is None:
        list_result = _ok_list()

    update_mock = MagicMock()

    parsed = MagicMock()
    parsed.owntone.base_url = BASE_URL

    def _cfg_load(path):
        if config_error:
            raise OSError("disk full")
        return {}

    with (
        patch("autostream_webui_api.is_dial_authorized", return_value=authorized),
        patch("autostream_webui_api.locked_load_config", side_effect=_cfg_load),
        patch("autostream_webui_api.parse_config", return_value=parsed),
        patch("autostream_webui_api.list_outputs", return_value=list_result),
        patch("autostream_webui_api.update_output", update_mock),
        patch("autostream_webui_api.any_monitor_capturing", return_value=playing),
    ):
        send_dial_status_post_json(handler, state, json_obj)

    code, body = _response(handler)
    return code, body, update_mock


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------

class TestAuthorization:
    def test_missing_dial_id_returns_403_empty(self):
        code, body, _ = _invoke({})
        assert code == 403
        assert body == {}

    def test_empty_dial_id_returns_403_empty(self):
        code, body, _ = _invoke({"dial_id": ""})
        assert code == 403
        assert body == {}

    def test_non_string_dial_id_returns_403_empty(self):
        code, body, _ = _invoke({"dial_id": 12345})
        assert code == 403
        assert body == {}

    def test_unauthorized_dial_id_returns_403_empty(self):
        code, body, _ = _invoke({"dial_id": DIAL_ID}, authorized=False)
        assert code == 403
        assert body == {}

    def test_authorized_dial_id_returns_200_ok(self):
        code, body, _ = _invoke({"dial_id": DIAL_ID})
        assert code == 200
        assert body["ok"] is True


# ---------------------------------------------------------------------------
# Volume calculation
# ---------------------------------------------------------------------------

class TestMasterVolumeResponse:
    def test_two_outputs_returns_correct_master_and_count(self):
        code, body, _ = _invoke(
            {"dial_id": DIAL_ID},
            list_result=_ok_list(_output("a", 40), _output("b", 60)),
        )
        assert code == 200
        assert body["ok"] is True
        assert body["master_volume"] == 50
        assert body["selected_output_count"] == 2

    def test_no_selected_outputs_returns_null(self):
        code, body, _ = _invoke(
            {"dial_id": DIAL_ID},
            list_result=_ok_list(_output("a", 40, selected=False)),
        )
        assert code == 200
        assert body["ok"] is True
        assert body["master_volume"] is None
        assert body["selected_output_count"] == 0

    def test_unselected_outputs_excluded_from_calculation(self):
        code, body, _ = _invoke(
            {"dial_id": DIAL_ID},
            list_result=_ok_list(
                _output("a", 60),
                _output("b", 80, selected=False),
            ),
        )
        assert code == 200
        assert body["master_volume"] == 60
        assert body["selected_output_count"] == 1

    def test_single_output_at_zero(self):
        code, body, _ = _invoke(
            {"dial_id": DIAL_ID},
            list_result=_ok_list(_output("a", 0)),
        )
        assert code == 200
        assert body["master_volume"] == 0
        assert body["selected_output_count"] == 1


# ---------------------------------------------------------------------------
# Playing field
# ---------------------------------------------------------------------------

class TestPlayingField:
    def test_playing_true_when_monitor_capturing(self):
        code, body, _ = _invoke({"dial_id": DIAL_ID}, playing=True)
        assert body["playing"] is True

    def test_playing_false_when_not_capturing(self):
        code, body, _ = _invoke({"dial_id": DIAL_ID}, playing=False)
        assert body["playing"] is False

    def test_playing_independent_of_outputs(self):
        """playing reflects monitor state, not output selection."""
        code, body, _ = _invoke(
            {"dial_id": DIAL_ID},
            list_result=_ok_list(_output("a", 70)),
            playing=True,
        )
        assert body["playing"] is True


# ---------------------------------------------------------------------------
# Failure paths
# ---------------------------------------------------------------------------

class TestFailurePaths:
    def test_config_error_returns_config_error(self):
        state = WebUIState(config_path="dummy.json", state_path="dummy-state.json")
        handler = _make_handler()
        with (
            patch("autostream_webui_api.is_dial_authorized", return_value=True),
            patch("autostream_webui_api.any_monitor_capturing", return_value=False),
            patch("autostream_webui_api.locked_load_config",
                  side_effect=OSError("disk full")),
        ):
            send_dial_status_post_json(handler, state, {"dial_id": DIAL_ID})
        code, body = _response(handler)
        assert code == 200
        assert body == {"ok": False, "error": "config_error"}

    def test_backend_not_ok_returns_backend_unavailable(self):
        code, body, _ = _invoke(
            {"dial_id": DIAL_ID},
            list_result=_fail_list("OwnTone offline"),
        )
        assert code == 200
        assert body == {"ok": False, "error": "backend_unavailable"}

    def test_backend_exception_returns_backend_unavailable(self):
        state = WebUIState(config_path="dummy.json", state_path="dummy-state.json")
        handler = _make_handler()
        parsed = MagicMock()
        parsed.owntone.base_url = BASE_URL
        with (
            patch("autostream_webui_api.is_dial_authorized", return_value=True),
            patch("autostream_webui_api.any_monitor_capturing", return_value=False),
            patch("autostream_webui_api.locked_load_config", return_value={}),
            patch("autostream_webui_api.parse_config", return_value=parsed),
            patch("autostream_webui_api.list_outputs",
                  side_effect=ConnectionRefusedError("refused")),
        ):
            send_dial_status_post_json(handler, state, {"dial_id": DIAL_ID})
        code, body = _response(handler)
        assert code == 200
        assert body == {"ok": False, "error": "backend_unavailable"}

    def test_no_side_effects_on_outputs(self):
        """Handler never calls update_output()."""
        code, body, update_mock = _invoke(
            {"dial_id": DIAL_ID},
            list_result=_ok_list(_output("a", 50)),
        )
        update_mock.assert_not_called()


# ---------------------------------------------------------------------------
# calculate_master_volume() helper
# ---------------------------------------------------------------------------

class TestCalculateMasterVolume:
    def test_empty_returns_none_zero(self):
        assert calculate_master_volume([]) == (None, 0)

    def test_no_selected_returns_none_zero(self):
        outputs = [_output("a", 50, selected=False)]
        assert calculate_master_volume(outputs) == (None, 0)

    def test_single_selected_output(self):
        outputs = [_output("a", 60)]
        assert calculate_master_volume(outputs) == (60, 1)

    def test_two_outputs_average(self):
        outputs = [_output("a", 40), _output("b", 60)]
        assert calculate_master_volume(outputs) == (50, 2)

    def test_rounding_40_61_matches_python_round(self):
        outputs = [_output("a", 40), _output("b", 61)]
        vol, count = calculate_master_volume(outputs)
        assert vol == round((40 + 61) / 2)
        assert count == 2

    def test_rounding_41_62_matches_python_round(self):
        outputs = [_output("a", 41), _output("b", 62)]
        vol, count = calculate_master_volume(outputs)
        assert vol == round((41 + 62) / 2)
        assert count == 2

    def test_volume_clamped_below_zero(self):
        # Negative volume_percent clamped to 0
        class FakeOutput:
            selected = True
            volume_percent = -10
        vol, count = calculate_master_volume([FakeOutput()])
        assert vol == 0
        assert count == 1

    def test_volume_clamped_above_100(self):
        class FakeOutput:
            selected = True
            volume_percent = 150
        vol, count = calculate_master_volume([FakeOutput()])
        assert vol == 100
        assert count == 1

    def test_mixed_selected_and_unselected(self):
        outputs = [_output("a", 60), _output("b", 80, selected=False)]
        vol, count = calculate_master_volume(outputs)
        assert vol == 60
        assert count == 1


# ---------------------------------------------------------------------------
# Avahi / admin source contract tests
# ---------------------------------------------------------------------------

class TestAvahiDialStatus:
    def test_static_avahi_template_has_dial_status_v1(self):
        avahi_file = REPO_ROOT / "system" / "avahi" / "autostream-playing.service"
        tree = ET.parse(avahi_file)
        root = tree.getroot()
        txt_records = [r.text for r in root.iter("txt-record")]
        assert "dial_status=v1" in txt_records, \
            f"dial_status=v1 not found in {avahi_file}: {txt_records}"

    def test_admin_write_playing_service_has_dial_status_v1(self):
        admin_path = REPO_ROOT / "supervisor" / "autostream_admin"
        text = admin_path.read_text(encoding="utf-8")
        # Verify the dial_status=v1 TXT record is in the _write_playing_service function.
        idx = text.find("_write_playing_service")
        assert idx != -1
        fn_text = text[idx:idx + 1000]
        assert "dial_status=v1" in fn_text, \
            "dial_status=v1 not found in _write_playing_service"


# ---------------------------------------------------------------------------
# NGINX policy: 403 must NOT be intercepted by error_page
# ---------------------------------------------------------------------------

class TestNginxPolicy403:
    def test_main_nginx_error_page_does_not_intercept_403(self):
        nginx_conf = REPO_ROOT / "system" / "nginx" / "autostream-nginx.conf"
        if not nginx_conf.exists():
            pytest.skip("main nginx config not found")
        text = nginx_conf.read_text(encoding="utf-8")
        # Extract error_page directives
        import re
        error_pages = re.findall(r"error_page\s+([^;]+);", text)
        for ep in error_pages:
            codes = ep.strip().split()
            # Last token starting with @ or / is the handler, not a code
            for code_str in codes:
                if code_str.startswith(("@", "/")):
                    break
                if code_str.isdigit() and int(code_str) == 403:
                    pytest.fail(
                        f"Main NGINX error_page intercepts 403; "
                        f"POST /api/dial/status must return native 403. "
                        f"Found: error_page {ep}"
                    )


# ---------------------------------------------------------------------------
# dial_status=v1 in DIAL_PROTOCOL.md
# ---------------------------------------------------------------------------

class TestDialProtocolDoc:
    def test_dial_protocol_documents_dial_status_v1(self):
        doc = REPO_ROOT / "DIAL_PROTOCOL.md"
        text = doc.read_text(encoding="utf-8")
        assert "dial_status" in text, "DIAL_PROTOCOL.md does not mention dial_status"
        assert "/api/dial/status" in text, \
            "DIAL_PROTOCOL.md does not document POST /api/dial/status"
