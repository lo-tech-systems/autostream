"""Refusal style on the dial protocol routes.

A dial advertising dial_proto=v2 gets the typed refusal (412
dial_not_authorized with appliance_id) on every dial route, volume and mute
included. Every other dial -- one advertising nothing, an unknown dialect, or
one that is not currently sighted -- gets the bare legacy refusal: HTTP 403
with the body ``{}``, byte-for-byte what send_json produces. Authorized
dials see identical success replies whichever dialect they speak.
"""
from __future__ import annotations

import io
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

from autostream_dials import (
    AUTH_AUTHORIZED,
    AUTH_NOT_AUTHORIZED,
    AUTH_UNAVAILABLE,
    DialSighting,
)
from autostream_players import ActionResult, ListOutputsResult, OutputInfo
import autostream_webui_api as api
from autostream_webui_state import WebUIState
from track_id.models import disabled_snapshot

DIAL_ID = "test-dial-uuid-1234"
BASE_URL = "http://localhost:3689"
TEST_APPLIANCE_ID = "aaaaaaaaaaaaaaaaaaaa"  # 20 lowercase hex-shaped chars


class _Capture:
    """Handler stand-in recording the status code, headers and body bytes."""

    def __init__(self):
        self.code = None
        self.headers: list[tuple[str, str]] = []
        self.wfile = io.BytesIO()

    def send_response(self, code):
        self.code = code

    def send_header(self, k, v):
        self.headers.append((k, v))

    def end_headers(self):
        pass

    def result(self):
        return self.code, self.headers, self.wfile.getvalue()


def _sighting(dial_proto: str | None):
    """None means the dial is not currently sighted."""
    if dial_proto is None:
        return None
    return DialSighting(uuid=DIAL_ID, name="D", version="x", ip="10.0.0.9",
                        port=7842, pin_recovery=False, dial_proto=dial_proto)


def _reference(code: int, payload: dict):
    ref = _Capture()
    api.send_json(ref, code, payload)
    return ref.result()


# Every dial route, with a body that passes its own shape checks.
_ROUTES = [
    ("status", api.send_dial_status_post_json, {"dial_id": DIAL_ID}),
    ("repeat", api.send_dial_repeat_post_json, {"dial_id": DIAL_ID, "action": "stop"}),
    ("repeat_arm", api.send_dial_repeat_arm_post_json, {"dial_id": DIAL_ID, "armed": True}),
    ("outputs", api.send_dial_outputs_post_json, {"dial_id": DIAL_ID}),
    ("outputs_set", api.send_dial_outputs_set_post_json,
     {"dial_id": DIAL_ID, "id": "1", "selected": True}),
    ("eq", api.send_dial_eq_post_json, {"dial_id": DIAL_ID}),
    ("eq_set", api.send_dial_eq_set_post_json, {"dial_id": DIAL_ID, "bass_db": 1}),
    ("volume", api.send_dial_volume_post_json, {"dial_id": DIAL_ID, "delta": 5}),
    ("mute", api.send_dial_mute_post_json, {"dial_id": DIAL_ID, "action": "mute"}),
]


def _state() -> WebUIState:
    return WebUIState(config_path="dummy.json", state_path="dummy-state.json")


def _call_refused(fn, body, dial_proto, auth=AUTH_NOT_AUTHORIZED):
    handler = _Capture()
    with (
        patch("autostream_webui_api.dial_authorization", return_value=auth),
        patch("autostream_webui_api.get_appliance_id", return_value=TEST_APPLIANCE_ID),
        patch("autostream_dials.get_dial_sighting", return_value=_sighting(dial_proto)),
    ):
        fn(handler, _state(), body)
    return handler.result()


@pytest.mark.parametrize("name,fn,body", _ROUTES, ids=[r[0] for r in _ROUTES])
class TestRefusalStyle:
    @pytest.mark.parametrize("dial_proto", [None, "", "v3"],
                             ids=["unsighted", "legacy", "unknown_dialect"])
    def test_non_v2_dial_gets_403_empty_body_byte_for_byte(self, name, fn, body, dial_proto):
        result = _call_refused(fn, body, dial_proto)
        assert result == _reference(403, {})
        assert result[2] == b"{}"

    def test_v2_dial_gets_typed_412(self, name, fn, body):
        assert _call_refused(fn, body, "v2") == _reference(412, {
            "ok": False, "error": "dial_not_authorized", "appliance_id": TEST_APPLIANCE_ID,
        })

    @pytest.mark.parametrize("dial_proto", [None, "", "v2"], ids=["unsighted", "legacy", "v2"])
    def test_auth_unavailable_is_200_for_every_dial(self, name, fn, body, dial_proto):
        assert _call_refused(fn, body, dial_proto, auth=AUTH_UNAVAILABLE) == _reference(
            200, {"ok": False, "error": "auth_unavailable"})


class TestVolumeAndMuteGate:
    def test_volume_unauthorized_v2_is_412_typed(self):
        code, _, raw = _call_refused(api.send_dial_volume_post_json,
                                     {"dial_id": DIAL_ID, "delta": 5}, "v2")
        assert code == 412
        assert b"dial_not_authorized" in raw and TEST_APPLIANCE_ID.encode() in raw

    def test_volume_unauthorized_legacy_is_403(self):
        code, _, raw = _call_refused(api.send_dial_volume_post_json,
                                     {"dial_id": DIAL_ID, "delta": 5}, "")
        assert (code, raw) == (403, b"{}")

    def test_mute_unauthorized_legacy_is_403(self):
        code, _, raw = _call_refused(api.send_dial_mute_post_json,
                                     {"dial_id": DIAL_ID, "action": "mute"}, "")
        assert (code, raw) == (403, b"{}")

    def test_missing_dial_id_stays_403_empty_body(self):
        for fn, body in ((api.send_dial_volume_post_json, {"delta": 5}),
                         (api.send_dial_mute_post_json, {"action": "mute"})):
            assert _call_refused(fn, body, "v2") == _reference(403, {})

    def test_authorization_is_checked_before_validation(self):
        code, _, raw = _call_refused(api.send_dial_volume_post_json,
                                     {"dial_id": DIAL_ID, "delta": "x"}, "")
        assert (code, raw) == (403, b"{}")
        code, _, _ = _call_refused(api.send_dial_mute_post_json,
                                   {"dial_id": DIAL_ID, "action": "bogus"}, "v2")
        assert code == 412


def _success(fn, body, dial_proto):
    handler = _Capture()
    outputs = ListOutputsResult(ok=True, outputs=(
        OutputInfo(id="1", name="a", selected=True, volume_percent=40),
        OutputInfo(id="2", name="b", selected=True, volume_percent=60),
    ))
    parsed = MagicMock()
    parsed.owntone.base_url = BASE_URL
    with (
        patch("autostream_webui_api.dial_authorization", return_value=AUTH_AUTHORIZED),
        patch("autostream_webui_api.get_appliance_id", return_value=TEST_APPLIANCE_ID),
        patch("autostream_dials.get_dial_sighting", return_value=_sighting(dial_proto)),
        patch("autostream_webui_api._config_snapshot", return_value=parsed),
        patch("autostream_webui_api.list_outputs", return_value=outputs),
        patch("autostream_webui_api.update_output", return_value=ActionResult(ok=True)),
        patch("autostream_webui_api.apply_mute_action",
              return_value=(200, {"ok": True, "muted": True})),
        patch("autostream_webui_api.get_session_state",
              return_value={"active": True, "source": "input1"}),
        patch("autostream_webui_api.get_repeat_status", return_value=None),
        patch("autostream_core.get_active_track_identification_snapshot",
              return_value=disabled_snapshot()),
    ):
        fn(handler, _state(), body)
    return handler.result()


_SUCCESS_ROUTES = [r for r in _ROUTES if r[0] in ("status", "volume", "mute")]


@pytest.mark.parametrize("name,fn,body", _SUCCESS_ROUTES, ids=[r[0] for r in _SUCCESS_ROUTES])
def test_authorized_dials_get_identical_success_replies(name, fn, body):
    v2 = _success(fn, body, "v2")
    assert v2[0] == 200
    assert v2 == _success(fn, body, "") == _success(fn, body, None)
