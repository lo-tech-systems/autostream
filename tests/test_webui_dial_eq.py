"""Tests for the dial's bass/treble EQ page: the bass/treble <-> output_eq
band mapping helpers, POST /api/dial/eq and POST /api/dial/eq/set, and the
dial_eq=v1 capability advertisement.

Covers:
1.  Mapping helpers (autostream_appliance_models): eq_fields_for_bass/
    eq_fields_for_treble build the {peq: value} dicts a dial step writes
    (bass moves peq1/peq2 together; treble moves peq6 at full value and
    peq5 at half of it, as a float); bass_treble_from_eq rounds and clamps
    peq1/peq6 to +/-6 for display; apply_eq_fields writes the given fields
    in one store update and calls set_live_output_eq once with the merged
    six bands, leaving peq3/peq4 untouched.
2.  Auth gate order (shared _dial_auth_gate with the other dial routes):
    400 missing_dial_id, 200 auth_unavailable, 412 dial_not_authorized, for
    both POST /api/dial/eq and POST /api/dial/eq/set.
3.  POST /api/dial/eq: returns the rounded/clamped bass_db/treble_db pair
    read from the stored output_eq bands; config_error when the config
    cannot be loaded.
4.  POST /api/dial/eq/set: only bass_db/treble_db ever reach apply_eq_fields;
    a value outside +/-6 is clamped before mapping; a non-int or bool value
    is rejected; an empty body is rejected; a failed apply reports
    eq_apply_failed while the store update still happened.
5.  Capability: dial_eq=v1 in the avahi template, both admin writers and
    the protocol doc.
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

import autostream_appliance_models as models
from autostream_dials import AUTH_AUTHORIZED, AUTH_NOT_AUTHORIZED, AUTH_UNAVAILABLE
from autostream_webui_api import send_dial_eq_post_json, send_dial_eq_set_post_json
from autostream_webui_state import WebUIState

DIAL_ID = "test-dial-uuid-1234"
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


def _oeq(peq1=0.0, peq2=0.0, peq3=0.0, peq4=0.0, peq5=0.0, peq6=0.0) -> SimpleNamespace:
    return SimpleNamespace(peq1_db=peq1, peq2_db=peq2, peq3_db=peq3, peq4_db=peq4, peq5_db=peq5, peq6_db=peq6)


def _parsed(oeq: SimpleNamespace | None = None) -> SimpleNamespace:
    return SimpleNamespace(output_eq=oeq if oeq is not None else _oeq())


def _invoke_read(
    json_obj: dict,
    *,
    auth_state: str = AUTH_AUTHORIZED,
    appliance_id: str | None = TEST_APPLIANCE_ID,
    parsed: SimpleNamespace | None = None,
    config_error: bool = False,
) -> tuple[int, dict]:
    state = WebUIState(config_path="dummy.json", state_path="dummy-state.json")
    handler = _make_handler()
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
    ):
        send_dial_eq_post_json(handler, state, json_obj)
    return _response(handler)


def _invoke_set(
    json_obj: dict,
    *,
    auth_state: str = AUTH_AUTHORIZED,
    appliance_id: str | None = TEST_APPLIANCE_ID,
    parsed: SimpleNamespace | None = None,
    apply_result: tuple = (True, ""),
) -> tuple[int, dict, MagicMock]:
    state = WebUIState(config_path="dummy.json", state_path="dummy-state.json")
    handler = _make_handler()
    if parsed is None:
        parsed = _parsed()
    apply_mock = MagicMock(return_value=apply_result)

    with (
        patch("autostream_webui_api.dial_authorization", return_value=auth_state),
        patch("autostream_webui_api.dial_speaks_v2", return_value=True),
        patch("autostream_webui_api.get_appliance_id", return_value=appliance_id),
        patch("autostream_webui_api._config_snapshot", return_value=parsed),
        patch("autostream_webui_api.apply_eq_fields", apply_mock),
    ):
        send_dial_eq_set_post_json(handler, state, json_obj)
    code, body = _response(handler)
    return code, body, apply_mock


# ---------------------------------------------------------------------------
# Mapping helpers
# ---------------------------------------------------------------------------

class TestEqMappingHelpers:
    def test_eq_fields_for_bass_sets_peq1_and_peq2_equally(self):
        assert models.eq_fields_for_bass(3) == {"peq1_db": 3.0, "peq2_db": 3.0}

    def test_eq_fields_for_bass_negative(self):
        assert models.eq_fields_for_bass(-6) == {"peq1_db": -6.0, "peq2_db": -6.0}

    def test_eq_fields_for_treble_sets_peq6_full_and_peq5_half(self):
        assert models.eq_fields_for_treble(4) == {"peq6_db": 4.0, "peq5_db": 2.0}

    def test_eq_fields_for_treble_odd_value_is_half_db_on_peq5(self):
        fields = models.eq_fields_for_treble(3)
        assert fields["peq6_db"] == 3.0
        assert fields["peq5_db"] == 1.5

    def test_bass_treble_from_eq_rounds(self):
        bass, treble = models.bass_treble_from_eq(_oeq(peq1=2.6, peq6=1.4))
        assert (bass, treble) == (3, 1)

    def test_bass_treble_from_eq_clamps_high(self):
        bass, treble = models.bass_treble_from_eq(_oeq(peq1=9.0, peq6=9.0))
        assert (bass, treble) == (6, 6)

    def test_bass_treble_from_eq_clamps_low(self):
        bass, treble = models.bass_treble_from_eq(_oeq(peq1=-8.0, peq6=-8.0))
        assert (bass, treble) == (-6, -6)


# ---------------------------------------------------------------------------
# apply_eq_fields
# ---------------------------------------------------------------------------

class TestApplyEqFields:
    def test_leaves_peq3_and_peq4_at_stored_values(self, tmp_path):
        cfg_path = tmp_path / "autostream.json"
        cfg_path.write_text(json.dumps({
            "output_eq": {"peq1_db": 0.0, "peq2_db": 0.0, "peq3_db": 5.0, "peq4_db": -5.0,
                           "peq5_db": 0.0, "peq6_db": 0.0},
        }), encoding="utf-8")
        eq_calls = []
        with patch("autostream_appliance_models.set_live_output_eq",
                   side_effect=lambda *a: eq_calls.append(a)):
            ok, err = models.apply_eq_fields(str(cfg_path), models.eq_fields_for_bass(3))
        assert ok is True
        assert eq_calls, "set_live_output_eq must be called"
        peq1, peq2, peq3, peq4, peq5, peq6 = eq_calls[0]
        assert (peq1, peq2) == (3.0, 3.0)
        assert (peq3, peq4) == (5.0, -5.0)

    def test_calls_set_live_output_eq_once_with_merged_six(self, tmp_path):
        cfg_path = tmp_path / "autostream.json"
        cfg_path.write_text(json.dumps({"output_eq": {}}), encoding="utf-8")
        eq_calls = []
        with patch("autostream_appliance_models.set_live_output_eq",
                   side_effect=lambda *a: eq_calls.append(a)):
            values = {**models.eq_fields_for_bass(2), **models.eq_fields_for_treble(4)}
            ok, err = models.apply_eq_fields(str(cfg_path), values)
        assert ok is True
        assert len(eq_calls) == 1
        assert len(eq_calls[0]) == 6

    def test_set_with_both_keys_writes_four_fields_in_one_store_update(self, tmp_path):
        cfg_path = tmp_path / "autostream.json"
        cfg_path.write_text(json.dumps({"output_eq": {}}), encoding="utf-8")
        with patch("autostream_appliance_models.set_live_output_eq"):
            values = {**models.eq_fields_for_bass(2), **models.eq_fields_for_treble(4)}
            ok, err = models.apply_eq_fields(str(cfg_path), values)
        assert ok is True
        saved = json.loads(cfg_path.read_text(encoding="utf-8"))
        eq = saved["output_eq"]
        assert (eq["peq1_db"], eq["peq2_db"], eq["peq6_db"], eq["peq5_db"]) == (2.0, 2.0, 4.0, 2.0)

    def test_save_failure_returns_ok_false(self, tmp_path):
        cfg_path = tmp_path / "autostream.json"
        cfg_path.write_text(json.dumps({"output_eq": {}}), encoding="utf-8")
        with patch("autostream_appliance_models.save_config", side_effect=OSError("disk full")):
            ok, err = models.apply_eq_fields(str(cfg_path), models.eq_fields_for_bass(1))
        assert ok is False
        assert err


# ---------------------------------------------------------------------------
# Auth gate: POST /api/dial/eq and POST /api/dial/eq/set
# ---------------------------------------------------------------------------

class TestEqAuth:
    def test_read_missing_dial_id_is_400(self):
        code, body = _invoke_read({})
        assert code == 400
        assert body == {"ok": False, "error": "missing_dial_id"}

    def test_read_auth_unavailable_is_200_ok_false(self):
        code, body = _invoke_read({"dial_id": DIAL_ID}, auth_state=AUTH_UNAVAILABLE)
        assert code == 200
        assert body == {"ok": False, "error": "auth_unavailable"}

    def test_read_unauthorized_is_412(self):
        code, body = _invoke_read({"dial_id": DIAL_ID}, auth_state=AUTH_NOT_AUTHORIZED)
        assert code == 412
        assert body == {"ok": False, "error": "dial_not_authorized", "appliance_id": TEST_APPLIANCE_ID}

    def test_set_missing_dial_id_is_400(self):
        code, body, apply_mock = _invoke_set({"bass_db": 1})
        assert code == 400
        assert body == {"ok": False, "error": "missing_dial_id"}
        apply_mock.assert_not_called()

    def test_set_auth_unavailable_is_200_ok_false(self):
        code, body, apply_mock = _invoke_set(
            {"dial_id": DIAL_ID, "bass_db": 1}, auth_state=AUTH_UNAVAILABLE,
        )
        assert code == 200
        assert body == {"ok": False, "error": "auth_unavailable"}
        apply_mock.assert_not_called()

    def test_set_unauthorized_is_412(self):
        code, body, apply_mock = _invoke_set(
            {"dial_id": DIAL_ID, "bass_db": 1}, auth_state=AUTH_NOT_AUTHORIZED,
        )
        assert code == 412
        assert body == {"ok": False, "error": "dial_not_authorized", "appliance_id": TEST_APPLIANCE_ID}
        apply_mock.assert_not_called()


# ---------------------------------------------------------------------------
# POST /api/dial/eq: read shape
# ---------------------------------------------------------------------------

class TestEqRead:
    def test_returns_rounded_clamped_pair_and_appliance_id(self):
        code, body = _invoke_read(
            {"dial_id": DIAL_ID}, parsed=_parsed(_oeq(peq1=2.6, peq6=-8.0)),
        )
        assert code == 200
        assert body == {"ok": True, "appliance_id": TEST_APPLIANCE_ID, "bass_db": 3, "treble_db": -6}

    def test_config_error_returns_config_error(self):
        code, body = _invoke_read({"dial_id": DIAL_ID}, config_error=True)
        assert code == 200
        assert body == {"ok": False, "error": "config_error"}


# ---------------------------------------------------------------------------
# POST /api/dial/eq/set: body validation and mutation delegation
# ---------------------------------------------------------------------------

class TestEqSetValidation:
    def test_empty_body_is_400_invalid_request_body(self):
        code, body, apply_mock = _invoke_set({"dial_id": DIAL_ID})
        assert code == 400
        assert body == {"ok": False, "error": "invalid_request_body"}
        apply_mock.assert_not_called()

    def test_non_int_bass_db_is_400(self):
        code, body, apply_mock = _invoke_set({"dial_id": DIAL_ID, "bass_db": "3"})
        assert code == 400
        assert body == {"ok": False, "error": "invalid_request_body"}
        apply_mock.assert_not_called()

    def test_bool_bass_db_is_400(self):
        code, body, apply_mock = _invoke_set({"dial_id": DIAL_ID, "bass_db": True})
        assert code == 400
        assert body == {"ok": False, "error": "invalid_request_body"}
        apply_mock.assert_not_called()

    def test_bass_db_clamped_before_mapping(self):
        code, body, apply_mock = _invoke_set({"dial_id": DIAL_ID, "bass_db": 9})
        assert code == 200
        apply_mock.assert_called_once()
        values = apply_mock.call_args[0][1]
        assert values == {"peq1_db": 6.0, "peq2_db": 6.0}

    def test_treble_db_mapped_with_half_db_secondary(self):
        code, body, apply_mock = _invoke_set({"dial_id": DIAL_ID, "treble_db": 4})
        values = apply_mock.call_args[0][1]
        assert values == {"peq6_db": 4.0, "peq5_db": 2.0}

    def test_both_fields_merge_into_one_call(self):
        code, body, apply_mock = _invoke_set({"dial_id": DIAL_ID, "bass_db": 2, "treble_db": -3})
        apply_mock.assert_called_once()
        values = apply_mock.call_args[0][1]
        assert values == {"peq1_db": 2.0, "peq2_db": 2.0, "peq6_db": -3.0, "peq5_db": -1.5}


class TestEqSetMutation:
    def test_ok_result_returns_readback_pair(self):
        code, body, apply_mock = _invoke_set(
            {"dial_id": DIAL_ID, "bass_db": 2},
            parsed=_parsed(_oeq(peq1=2.0, peq6=0.0)),
        )
        assert code == 200
        assert body == {"ok": True, "appliance_id": TEST_APPLIANCE_ID, "bass_db": 2, "treble_db": 0}

    def test_apply_failure_returns_eq_apply_failed(self):
        code, body, apply_mock = _invoke_set(
            {"dial_id": DIAL_ID, "bass_db": 2}, apply_result=(False, "monitor unreachable"),
        )
        assert code == 200
        assert body == {"ok": False, "error": "eq_apply_failed", "appliance_id": TEST_APPLIANCE_ID}


# ---------------------------------------------------------------------------
# Avahi / admin source contract: dial_eq=v1
# ---------------------------------------------------------------------------

class TestAvahiDialEq:
    def test_static_avahi_template_has_dial_eq_v1(self):
        import xml.etree.ElementTree as ET
        avahi_file = REPO_ROOT / "system" / "avahi" / "autostream-playing.service"
        tree = ET.parse(avahi_file)
        root = tree.getroot()
        txt_records = [r.text for r in root.iter("txt-record")]
        assert "dial_eq=v1" in txt_records

    def test_admin_write_playing_service_has_dial_eq_v1(self):
        admin_path = REPO_ROOT / "supervisor" / "autostream_admin"
        text = admin_path.read_text(encoding="utf-8")
        idx = text.find("_write_playing_service")
        assert idx != -1
        fn_text = text[idx:idx + 1000]
        assert "dial_eq=v1" in fn_text

    def test_admin_write_appliance_service_has_dial_eq_v1(self):
        admin_path = REPO_ROOT / "supervisor" / "autostream_admin"
        text = admin_path.read_text(encoding="utf-8")
        idx = text.find("_write_appliance_service")
        assert idx != -1
        fn_text = text[idx:idx + 1600]
        assert "dial_eq=v1" in fn_text


# ---------------------------------------------------------------------------
# dial_eq=v1 documented in DIAL_PROTOCOL.md
# ---------------------------------------------------------------------------

class TestDialProtocolDoc:
    def test_dial_protocol_documents_dial_eq_v1(self):
        doc = REPO_ROOT / "docs" / "dial" / "DIAL_PROTOCOL.md"
        text = doc.read_text(encoding="utf-8")
        assert "dial_eq=v1" in text
        assert "/api/dial/eq" in text
        assert "/api/dial/eq/set" in text
