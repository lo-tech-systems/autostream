"""Tests for POST /api/dial/warnings.

Covers: the shared dial gate in its usual order (400 missing_dial_id, 200
auth_unavailable, 412 dial_not_authorized, 403 for a dial that does not speak
the typed-refusal dialect), the reply shape, an empty list, config_error when
the list cannot be built, and the route registration and documentation.
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

import autostream_dial_warnings as dw
import autostream_webui_routes as routes_mod
from autostream_dials import AUTH_AUTHORIZED, AUTH_NOT_AUTHORIZED, AUTH_UNAVAILABLE, DIAL_CAPABILITIES
from autostream_webui_api import send_dial_warnings_post_json
from autostream_webui_state import WebUIState

DIAL_ID = "test-dial-uuid-1234"
APPLIANCE_ID = "aaaaaaaaaaaaaaaaaaaa"

STYLUS = dw.DialWarning("stylus_in1", "warning", "Input 1 stylus",
                        "Needs changing soon (7.5 h remaining).", "week")


def _invoke(json_obj, *, auth_state=AUTH_AUTHORIZED, speaks_v2=True, warnings=(STYLUS,),
            build_error=None, appliance_id=APPLIANCE_ID):
    state = WebUIState(config_path="dummy.json", state_path="dummy-state.json")
    handler = MagicMock()
    handler.wfile = io.BytesIO()
    build = MagicMock(return_value=list(warnings), side_effect=build_error)
    with (
        patch("autostream_webui_api.dial_authorization", return_value=auth_state),
        patch("autostream_webui_api.dial_speaks_v2", return_value=speaks_v2),
        patch("autostream_webui_api.get_appliance_id", return_value=appliance_id),
        patch("autostream_webui_api.current_warnings", build),
    ):
        send_dial_warnings_post_json(handler, state, json_obj)
    code = handler.send_response.call_args[0][0]
    return code, json.loads(handler.wfile.getvalue()), build


class TestGate:
    def test_missing_dial_id_is_400_and_builds_nothing(self):
        code, body, build = _invoke({})
        assert (code, body) == (400, {"ok": False, "error": "missing_dial_id"})
        build.assert_not_called()

    def test_auth_unavailable_is_200_ok_false(self):
        code, body, build = _invoke({"dial_id": DIAL_ID}, auth_state=AUTH_UNAVAILABLE)
        assert (code, body) == (200, {"ok": False, "error": "auth_unavailable"})
        build.assert_not_called()

    def test_unauthorized_v2_dial_is_412(self):
        code, body, build = _invoke({"dial_id": DIAL_ID}, auth_state=AUTH_NOT_AUTHORIZED)
        assert code == 412
        assert body == {"ok": False, "error": "dial_not_authorized", "appliance_id": APPLIANCE_ID}
        build.assert_not_called()

    def test_unauthorized_legacy_dial_is_403_empty(self):
        code, body, build = _invoke(
            {"dial_id": DIAL_ID}, auth_state=AUTH_NOT_AUTHORIZED, speaks_v2=False)
        assert (code, body) == (403, {})
        build.assert_not_called()


class TestReply:
    def test_shape(self):
        code, body, _ = _invoke({"dial_id": DIAL_ID})
        assert code == 200
        assert body == {
            "ok": True,
            "appliance_id": APPLIANCE_ID,
            "warnings": [{
                "id": "stylus_in1", "severity": "warning", "title": "Input 1 stylus",
                "message": "Needs changing soon (7.5 h remaining).", "dismissal": "week",
            }],
        }

    def test_empty_list_is_ok_true(self):
        code, body, _ = _invoke({"dial_id": DIAL_ID}, warnings=())
        assert (code, body) == (200, {"ok": True, "appliance_id": APPLIANCE_ID, "warnings": []})

    def test_identity_less_appliance_reports_null(self):
        _, body, _ = _invoke({"dial_id": DIAL_ID}, appliance_id=None)
        assert body["appliance_id"] is None

    def test_build_failure_is_config_error(self):
        code, body, _ = _invoke({"dial_id": DIAL_ID}, build_error=OSError("gone"))
        assert (code, body) == (200, {"ok": False, "error": "config_error"})

    def test_no_other_body_field_is_read(self):
        _, body, build = _invoke({"dial_id": DIAL_ID, "anything": "else"})
        assert body["ok"] is True
        build.assert_called_once_with()


class TestRegistration:
    def test_route_is_a_dial_scheme_post(self):
        matches = [r for r in routes_mod.ROUTES if r.path == "/api/dial/warnings"]
        assert len(matches) == 1
        assert matches[0].scheme == "dial"
        assert matches[0].methods == ("POST",)

    def test_capability_is_announced_in_the_json_table(self):
        assert DIAL_CAPABILITIES["dial_warnings"] == 1

    def test_documented_in_dial_protocol(self):
        text = (REPO_ROOT / "docs" / "dial" / "DIAL_PROTOCOL.md").read_text(encoding="utf-8")
        assert "POST /api/dial/warnings" in text
