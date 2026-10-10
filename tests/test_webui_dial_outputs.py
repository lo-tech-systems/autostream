"""Tests for POST /api/dial/outputs and POST /api/dial/outputs/set.

Covers:
1.  Auth gate order (shared _dial_auth_gate with POST /api/dial/status and
    POST /api/dial/repeat): 400 missing_dial_id, 200 auth_unavailable,
    412 dial_not_authorized, for both routes.
2.  POST /api/dial/outputs: the list is built from list_outputs ->
    build_output_list -> annotate_outputs, exactly as the setup page's
    output list is; hidden outputs excluded, default first, remote_in_use
    True only for an output not locally selected and reported in use
    elsewhere; backend_unavailable when list_outputs fails; config_error
    when the config cannot be loaded.
3.  POST /api/dial/outputs/set: body shape (only id/selected/volume ever
    reach sanitize_output_body -- the dial never sends op/pin); enabling
    without a volume applies the configured default; enabling with a
    volume passes it through (clamped by the sanitiser); disabling passes
    selected False untouched; missing id -> 400 missing_output_id; a body
    lacking selected -> 400 invalid_request_body; per-output offset/mode
    derivation; initiated_by is always "user"; the mutation's own result
    dict is returned as-is with appliance_id attached.
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

from autostream_config import DEFAULT_AIRPLAY_MODE
from autostream_dials import AUTH_AUTHORIZED, AUTH_NOT_AUTHORIZED, AUTH_UNAVAILABLE
from autostream_players import ListOutputsResult, OutputInfo
from autostream_webui_api import (
    send_dial_outputs_post_json,
    send_dial_outputs_set_post_json,
)
from autostream_webui_state import WebUIState

DIAL_ID = "test-dial-uuid-1234"
BASE_URL = "http://localhost:3689"
TEST_APPLIANCE_ID = "aaaaaaaaaaaaaaaaaaaa"  # 20 lowercase hex-shaped chars


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


def _output(id_: str, name: str, volume: int, selected: bool = True) -> OutputInfo:
    return OutputInfo(id=id_, name=name, selected=selected, volume_percent=volume)


def _ok_list(*outputs: OutputInfo) -> ListOutputsResult:
    return ListOutputsResult(ok=True, outputs=tuple(outputs))


def _fail_list(msg: str = "connection refused") -> ListOutputsResult:
    return ListOutputsResult(ok=False, error=msg)


def _parsed(
    *,
    output_name: str = "",
    hidden_outputs: list | None = None,
    volume_percent: int = 20,
    output_offsets_ms: dict | None = None,
    output_airplay_modes: dict | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        owntone=SimpleNamespace(
            base_url=BASE_URL,
            output_name=output_name,
            volume_percent=volume_percent,
            output_offsets_ms=output_offsets_ms or {},
            output_airplay_modes=output_airplay_modes or {},
        ),
        webui=SimpleNamespace(hidden_outputs=hidden_outputs or []),
    )


def _invoke_list(
    json_obj: dict,
    *,
    auth_state: str = AUTH_AUTHORIZED,
    appliance_id: str | None = TEST_APPLIANCE_ID,
    list_result: ListOutputsResult | None = None,
    parsed: SimpleNamespace | None = None,
    config_error: bool = False,
    usage_snapshot: dict | None = None,
) -> tuple[int, dict]:
    state = WebUIState(config_path="dummy.json", state_path="dummy-state.json")
    handler = _make_handler()
    if list_result is None:
        list_result = _ok_list()
    if parsed is None:
        parsed = _parsed()

    def _cfg_snapshot(_state):
        if config_error:
            raise OSError("disk full")
        return parsed

    with (
        patch("autostream_webui_api.dial_authorization", return_value=auth_state),
        patch("autostream_webui_api.dial_speaks_v2", return_value=True),
        patch("autostream_webui_api.get_appliance_id", return_value=appliance_id),
        patch("autostream_webui_api._config_snapshot", side_effect=_cfg_snapshot),
        patch("autostream_webui_api.list_outputs", return_value=list_result),
        patch("autostream_output_usage.get_usage_snapshot", return_value=usage_snapshot or {}),
    ):
        send_dial_outputs_post_json(handler, state, json_obj)
    return _response(handler)


def _invoke_set(
    json_obj: dict,
    *,
    auth_state: str = AUTH_AUTHORIZED,
    appliance_id: str | None = TEST_APPLIANCE_ID,
    parsed: SimpleNamespace | None = None,
    config_error: bool = False,
    mutation_result: dict | None = None,
) -> tuple[int, dict, MagicMock, MagicMock]:
    state = WebUIState(config_path="dummy.json", state_path="dummy-state.json")
    handler = _make_handler()
    if parsed is None:
        parsed = _parsed()
    mutation_mock = MagicMock(
        return_value=dict(mutation_result) if mutation_result is not None else {"ok": True, "id": "1"}
    )

    def _cfg_snapshot(_state):
        if config_error:
            raise OSError("disk full")
        return parsed

    mode_mock = MagicMock(side_effect=lambda mode: f"backend:{mode}")
    with (
        patch("autostream_webui_api.dial_authorization", return_value=auth_state),
        patch("autostream_webui_api.dial_speaks_v2", return_value=True),
        patch("autostream_webui_api.get_appliance_id", return_value=appliance_id),
        patch("autostream_webui_api._config_snapshot", side_effect=_cfg_snapshot),
        patch("autostream_webui_api.apply_output_mutation", mutation_mock),
        patch("autostream_player_service.config_airplay_mode_to_backend", mode_mock),
    ):
        send_dial_outputs_set_post_json(handler, state, json_obj)
    code, body = _response(handler)
    return code, body, mutation_mock, mode_mock


# ---------------------------------------------------------------------------
# Auth gate: POST /api/dial/outputs
# ---------------------------------------------------------------------------

class TestOutputsListAuth:
    def test_missing_dial_id_is_400(self):
        code, body = _invoke_list({})
        assert code == 400
        assert body == {"ok": False, "error": "missing_dial_id"}

    def test_auth_unavailable_is_200_ok_false(self):
        code, body = _invoke_list({"dial_id": DIAL_ID}, auth_state=AUTH_UNAVAILABLE)
        assert code == 200
        assert body == {"ok": False, "error": "auth_unavailable"}

    def test_unauthorized_is_412(self):
        code, body = _invoke_list({"dial_id": DIAL_ID}, auth_state=AUTH_NOT_AUTHORIZED)
        assert code == 412
        assert body == {
            "ok": False, "error": "dial_not_authorized", "appliance_id": TEST_APPLIANCE_ID,
        }


# ---------------------------------------------------------------------------
# Auth gate: POST /api/dial/outputs/set
# ---------------------------------------------------------------------------

class TestOutputsSetAuth:
    def test_missing_dial_id_is_400(self):
        code, body, mutation, mode_mock = _invoke_set({"id": "1", "selected": True})
        assert code == 400
        assert body == {"ok": False, "error": "missing_dial_id"}
        mutation.assert_not_called()

    def test_auth_unavailable_is_200_ok_false(self):
        code, body, mutation, mode_mock = _invoke_set(
            {"dial_id": DIAL_ID, "id": "1", "selected": True}, auth_state=AUTH_UNAVAILABLE,
        )
        assert code == 200
        assert body == {"ok": False, "error": "auth_unavailable"}
        mutation.assert_not_called()

    def test_unauthorized_is_412(self):
        code, body, mutation, mode_mock = _invoke_set(
            {"dial_id": DIAL_ID, "id": "1", "selected": True}, auth_state=AUTH_NOT_AUTHORIZED,
        )
        assert code == 412
        assert body == {
            "ok": False, "error": "dial_not_authorized", "appliance_id": TEST_APPLIANCE_ID,
        }
        mutation.assert_not_called()


# ---------------------------------------------------------------------------
# POST /api/dial/outputs: list shape
# ---------------------------------------------------------------------------

class TestOutputsList:
    def test_authorized_returns_outputs_and_appliance_id(self):
        code, body = _invoke_list(
            {"dial_id": DIAL_ID},
            list_result=_ok_list(_output("1", "Bedroom", 40)),
        )
        assert code == 200
        assert body["ok"] is True
        assert body["appliance_id"] == TEST_APPLIANCE_ID
        assert body["outputs"] == [
            {"id": "1", "name": "Bedroom", "selected": True, "volume": 40,
             "remote_in_use": False, "remote_owner": ""},
        ]

    def test_hidden_unselected_output_excluded(self):
        code, body = _invoke_list(
            {"dial_id": DIAL_ID},
            list_result=_ok_list(
                _output("1", "Bedroom", 40, selected=False), _output("2", "Kitchen", 60),
            ),
            parsed=_parsed(hidden_outputs=["Bedroom"]),
        )
        names = [o["name"] for o in body["outputs"]]
        assert names == ["Kitchen"]

    def test_default_output_listed_first(self):
        code, body = _invoke_list(
            {"dial_id": DIAL_ID},
            list_result=_ok_list(_output("2", "Zulu", 10), _output("1", "Alpha", 10)),
            parsed=_parsed(output_name="Zulu"),
        )
        assert body["outputs"][0]["name"] == "Zulu"

    def test_remote_in_use_true_when_used_elsewhere_and_not_locally_selected(self):
        from autostream_output_usage import OutputUsage
        usage = OutputUsage(
            output_name="bedroom", owner_name="other-box", owner_ip="192.168.1.50",
            owner_port=80, service_name="autostream on other-box", observed_at=0.0,
            expires_at=1e18,
        )
        code, body = _invoke_list(
            {"dial_id": DIAL_ID},
            list_result=_ok_list(_output("1", "Bedroom", 0, selected=False)),
            usage_snapshot={"bedroom": usage},
        )
        assert body["outputs"][0]["remote_in_use"] is True

    def test_remote_in_use_false_when_locally_selected(self):
        from autostream_output_usage import OutputUsage
        usage = OutputUsage(
            output_name="bedroom", owner_name="other-box", owner_ip="192.168.1.50",
            owner_port=80, service_name="autostream on other-box", observed_at=0.0,
            expires_at=1e18,
        )
        code, body = _invoke_list(
            {"dial_id": DIAL_ID},
            list_result=_ok_list(_output("1", "Bedroom", 40, selected=True)),
            usage_snapshot={"bedroom": usage},
        )
        assert body["outputs"][0]["remote_in_use"] is False

    def test_reply_carries_remote_owner_for_in_use_rows_and_empty_otherwise(self):
        from autostream_output_usage import OutputUsage
        usage = OutputUsage(
            output_name="bedroom", owner_name="other-box", owner_ip="192.168.1.50",
            owner_port=80, service_name="autostream on other-box", observed_at=0.0,
            expires_at=1e18,
        )
        code, body = _invoke_list(
            {"dial_id": DIAL_ID},
            list_result=_ok_list(
                _output("1", "Bedroom", 0, selected=False),
                _output("2", "Kitchen", 30, selected=True),
            ),
            usage_snapshot={"bedroom": usage, "kitchen": usage},
        )
        rows = {o["name"]: o for o in body["outputs"]}
        assert rows["Bedroom"]["remote_in_use"] is True
        assert rows["Bedroom"]["remote_owner"] == "other-box"
        assert rows["Kitchen"]["remote_in_use"] is False
        assert rows["Kitchen"]["remote_owner"] == ""
        assert "remote_owner_service" not in rows["Bedroom"]

    def test_backend_unavailable_when_list_outputs_not_ok(self):
        code, body = _invoke_list({"dial_id": DIAL_ID}, list_result=_fail_list())
        assert code == 200
        assert body == {"ok": False, "error": "backend_unavailable"}

    def test_config_error_returns_config_error(self):
        code, body = _invoke_list({"dial_id": DIAL_ID}, config_error=True)
        assert code == 200
        assert body == {"ok": False, "error": "config_error"}


# ---------------------------------------------------------------------------
# POST /api/dial/outputs/set: body validation
# ---------------------------------------------------------------------------

class TestOutputsSetValidation:
    def test_missing_id_is_400_missing_output_id(self):
        code, body, mutation, mode_mock = _invoke_set({"dial_id": DIAL_ID, "selected": True})
        assert code == 400
        assert body == {"ok": False, "error": "missing_output_id"}
        mutation.assert_not_called()

    def test_missing_selected_is_400_invalid_request_body(self):
        code, body, mutation, mode_mock = _invoke_set({"dial_id": DIAL_ID, "id": "1"})
        assert code == 400
        assert body == {"ok": False, "error": "invalid_request_body"}
        mutation.assert_not_called()

    def test_op_pin_is_rejected_as_invalid_request_body(self):
        """The dial never sends op/pin; only id/selected/volume reach the
        sanitiser, so a pin submission body is left with no `selected` and
        is rejected the same as any other malformed body."""
        code, body, mutation, mode_mock = _invoke_set(
            {"dial_id": DIAL_ID, "id": "1", "op": "pin", "pin": "1234"},
        )
        assert code == 400
        assert body == {"ok": False, "error": "invalid_request_body"}
        mutation.assert_not_called()

    def test_non_bool_selected_is_400(self):
        code, body, mutation, mode_mock = _invoke_set(
            {"dial_id": DIAL_ID, "id": "1", "selected": "true"},
        )
        assert code == 400
        assert body == {"ok": False, "error": "invalid_request_body"}
        mutation.assert_not_called()


# ---------------------------------------------------------------------------
# POST /api/dial/outputs/set: mutation delegation
# ---------------------------------------------------------------------------

class TestOutputsSetMutation:
    def test_enable_without_volume_fills_configured_default(self):
        code, body, mutation, mode_mock = _invoke_set(
            {"dial_id": DIAL_ID, "id": "1", "selected": True},
            parsed=_parsed(volume_percent=77),
        )
        assert code == 200
        mutation.assert_called_once()
        args, kwargs = mutation.call_args
        assert args[2]["volume"] == 77
        assert args[2]["selected"] is True

    def test_enable_with_volume_passes_through_clamped(self):
        code, body, mutation, mode_mock = _invoke_set(
            {"dial_id": DIAL_ID, "id": "1", "selected": True, "volume": 500},
            parsed=_parsed(volume_percent=77),
        )
        args, kwargs = mutation.call_args
        assert args[2]["volume"] == 100  # sanitize_output_body clamps to [0, 100]

    def test_disable_does_not_apply_the_configured_default(self):
        """The sender's own default-volume fill only applies to an enable
        with no volume in the raw body; a disable is untouched by it (the
        sanitiser's own unconditional volume default is harmless here since
        apply_output_mutation never reads volume for a disable)."""
        code, body, mutation, mode_mock = _invoke_set(
            {"dial_id": DIAL_ID, "id": "1", "selected": False},
            parsed=_parsed(volume_percent=77),
        )
        args, kwargs = mutation.call_args
        assert args[2]["selected"] is False
        assert args[2].get("volume") != 77

    def test_offset_and_mode_derived_per_output_id(self):
        code, body, mutation, mode_mock = _invoke_set(
            {"dial_id": DIAL_ID, "id": "42", "selected": True},
            parsed=_parsed(output_offsets_ms={"42": 15}, output_airplay_modes={"42": "raop"}),
        )
        args, kwargs = mutation.call_args
        assert kwargs["offset_ms"] == 15
        mode_mock.assert_called_once_with("raop")
        assert kwargs["mode"] == "backend:raop"

    def test_missing_offset_and_mode_use_defaults(self):
        code, body, mutation, mode_mock = _invoke_set({"dial_id": DIAL_ID, "id": "1", "selected": True})
        args, kwargs = mutation.call_args
        assert kwargs["offset_ms"] is None
        mode_mock.assert_called_once_with(DEFAULT_AIRPLAY_MODE)

    def test_initiated_by_is_always_user(self):
        code, body, mutation, mode_mock = _invoke_set({"dial_id": DIAL_ID, "id": "1", "selected": False})
        args, kwargs = mutation.call_args
        assert kwargs["initiated_by"] == "user"

    def test_ok_result_returned_as_is_with_appliance_id(self):
        code, body, mutation, mode_mock = _invoke_set(
            {"dial_id": DIAL_ID, "id": "1", "selected": True},
            mutation_result={"ok": True, "id": "1"},
        )
        assert code == 200
        assert body == {"ok": True, "id": "1", "appliance_id": TEST_APPLIANCE_ID}

    def test_rejection_result_returned_as_is_with_appliance_id(self):
        code, body, mutation, mode_mock = _invoke_set(
            {"dial_id": DIAL_ID, "id": "1", "selected": True},
            mutation_result={"ok": False, "id": "1", "error": "output_in_use", "owner": "other-box"},
        )
        assert code == 200
        assert body == {
            "ok": False, "id": "1", "error": "output_in_use", "owner": "other-box",
            "appliance_id": TEST_APPLIANCE_ID,
        }

    def test_pin_required_result_returned_as_is(self):
        code, body, mutation, mode_mock = _invoke_set(
            {"dial_id": DIAL_ID, "id": "1", "selected": True},
            mutation_result={"ok": False, "pin_required": True, "id": "1", "output_name": "Bedroom"},
        )
        assert code == 200
        assert body["pin_required"] is True
        assert body["appliance_id"] == TEST_APPLIANCE_ID

    def test_config_error_returns_config_error(self):
        code, body, mutation, mode_mock = _invoke_set(
            {"dial_id": DIAL_ID, "id": "1", "selected": True}, config_error=True,
        )
        assert code == 200
        assert body == {"ok": False, "error": "config_error"}
        mutation.assert_not_called()


# ---------------------------------------------------------------------------
# Avahi / admin source contract: dial_outputs=v1
# ---------------------------------------------------------------------------

class TestAvahiDialOutputs:
    def test_static_avahi_template_has_dial_outputs_v1(self):
        import xml.etree.ElementTree as ET
        avahi_file = REPO_ROOT / "system" / "avahi" / "autostream-playing.service"
        tree = ET.parse(avahi_file)
        root = tree.getroot()
        txt_records = [r.text for r in root.iter("txt-record")]
        assert "dial_outputs=v1" in txt_records

    def test_admin_write_playing_service_has_dial_outputs_v1(self):
        admin_path = REPO_ROOT / "supervisor" / "autostream_admin"
        text = admin_path.read_text(encoding="utf-8")
        idx = text.find("_write_playing_service")
        assert idx != -1
        fn_text = text[idx:idx + 1000]
        assert "dial_outputs=v1" in fn_text

    def test_admin_write_appliance_service_has_dial_outputs_v1(self):
        admin_path = REPO_ROOT / "supervisor" / "autostream_admin"
        text = admin_path.read_text(encoding="utf-8")
        idx = text.find("_write_appliance_service")
        assert idx != -1
        fn_text = text[idx:idx + 1000]
        assert "dial_outputs=v1" in fn_text


# ---------------------------------------------------------------------------
# dial_outputs=v1 documented in DIAL_PROTOCOL.md
# ---------------------------------------------------------------------------

class TestDialProtocolDoc:
    def test_dial_protocol_documents_dial_outputs_v1(self):
        doc = REPO_ROOT / "docs" / "dial" / "DIAL_PROTOCOL.md"
        text = doc.read_text(encoding="utf-8")
        assert "dial_outputs=v1" in text
        assert "/api/dial/outputs" in text
        assert "/api/dial/outputs/set" in text
