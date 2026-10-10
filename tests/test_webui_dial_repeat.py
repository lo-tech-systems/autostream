"""Tests for POST /api/dial/repeat and POST /api/dial/repeat/arm.

Covers:
1.  Auth gate order (shared _dial_auth_gate with POST /api/dial/status):
    400 missing_dial_id, 200 auth_unavailable, 412 dial_not_authorized.
2.  POST /api/dial/repeat: invalid_action 400; invalid_position 400 for a
    bool, a string, NaN, and a negative number; seek rate limiting (one per
    second, appliance-wide); stop is idempotent and never rate-limited; ack
    mapping for every known daemon error token, for an unrecognised/"unknown
    command" daemon error, and for a None ack (daemon unreachable); an ok
    response carries state, armed, position_seconds, appliance_id; the
    route never reads get_repeat_status().
3.  POST /api/dial/repeat/arm: invalid_armed 400 for a non-bool; calls
    set_live_repeat_armed_ack() with the bool; never calls
    apply_repeat_arm_request() (that string-body API is a different route's
    contract).
"""
from __future__ import annotations

import json
import math
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

from autostream_dials import AUTH_AUTHORIZED, AUTH_NOT_AUTHORIZED, AUTH_UNAVAILABLE
from autostream_webui_api import (
    send_dial_repeat_arm_post_json,
    send_dial_repeat_post_json,
)

DIAL_ID = "test-dial-uuid-1234"
TEST_APPLIANCE_ID = "aaaaaaaaaaaaaaaaaaaa"  # 20 lowercase hex-shaped chars


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _handler() -> MagicMock:
    handler = MagicMock()
    handler.wfile = MagicMock()
    sent: dict = {}

    def _send_response(code):
        sent["code"] = code

    def _wfile_write(data):
        sent["body"] = json.loads(data)

    handler.send_response.side_effect = _send_response
    handler.wfile.write.side_effect = _wfile_write
    handler._sent = sent
    return handler


def _response(handler: MagicMock) -> tuple[int, dict]:
    return handler._sent.get("code"), handler._sent.get("body", {})


def _invoke_transport(
    json_obj: dict,
    *,
    auth_state: str = AUTH_AUTHORIZED,
    appliance_id: str | None = TEST_APPLIANCE_ID,
    transport_ack=None,
    transport_side_effect=None,
) -> tuple[int, dict, MagicMock]:
    handler = _handler()
    transport_mock = MagicMock(return_value=transport_ack, side_effect=transport_side_effect)
    with (
        patch("autostream_webui_api.dial_authorization", return_value=auth_state),
        patch("autostream_webui_api.get_appliance_id", return_value=appliance_id),
        patch("autostream_webui_api.send_live_repeat_transport", transport_mock),
        patch("autostream_webui_api.get_repeat_status",
              side_effect=AssertionError("route must not read get_repeat_status")),
    ):
        send_dial_repeat_post_json(handler, MagicMock(), json_obj)
    code, body = _response(handler)
    return code, body, transport_mock


def _invoke_arm(
    json_obj: dict,
    *,
    auth_state: str = AUTH_AUTHORIZED,
    appliance_id: str | None = TEST_APPLIANCE_ID,
    arm_ack=None,
) -> tuple[int, dict, MagicMock, MagicMock]:
    handler = _handler()
    arm_mock = MagicMock(return_value=arm_ack)
    legacy_mock = MagicMock(side_effect=AssertionError("must not call apply_repeat_arm_request"))
    with (
        patch("autostream_webui_api.dial_authorization", return_value=auth_state),
        patch("autostream_webui_api.get_appliance_id", return_value=appliance_id),
        patch("autostream_webui_api.set_live_repeat_armed_ack", arm_mock),
        patch("autostream_webui_api.apply_repeat_arm_request", legacy_mock),
    ):
        send_dial_repeat_arm_post_json(handler, MagicMock(), json_obj)
    code, body = _response(handler)
    return code, body, arm_mock, legacy_mock


# _dial_seek_last (the rate-limit clock) is reset after every test by
# tests/conftest.py's autouse _reset_dial_seek_rate_limit fixture.


# ---------------------------------------------------------------------------
# Auth gate order (shared _dial_auth_gate)
# ---------------------------------------------------------------------------

class TestAuthGateOrder:
    def test_missing_dial_id_is_400(self):
        code, body, transport = _invoke_transport({"action": "stop"})
        assert code == 400
        assert body == {"ok": False, "error": "missing_dial_id"}
        transport.assert_not_called()

    def test_auth_unavailable_is_200_ok_false(self):
        code, body, transport = _invoke_transport(
            {"dial_id": DIAL_ID, "action": "stop"}, auth_state=AUTH_UNAVAILABLE,
        )
        assert code == 200
        assert body == {"ok": False, "error": "auth_unavailable"}
        transport.assert_not_called()

    def test_unauthorized_is_412(self):
        code, body, transport = _invoke_transport(
            {"dial_id": DIAL_ID, "action": "stop"}, auth_state=AUTH_NOT_AUTHORIZED,
        )
        assert code == 412
        assert body == {
            "ok": False,
            "error": "dial_not_authorized",
            "appliance_id": TEST_APPLIANCE_ID,
        }
        transport.assert_not_called()

    def test_arm_route_missing_dial_id_is_400(self):
        code, body, arm_mock, _ = _invoke_arm({"armed": True})
        assert code == 400
        assert body == {"ok": False, "error": "missing_dial_id"}
        arm_mock.assert_not_called()

    def test_arm_route_auth_unavailable_is_200_ok_false(self):
        code, body, arm_mock, _ = _invoke_arm(
            {"dial_id": DIAL_ID, "armed": True}, auth_state=AUTH_UNAVAILABLE,
        )
        assert code == 200
        assert body == {"ok": False, "error": "auth_unavailable"}
        arm_mock.assert_not_called()

    def test_arm_route_unauthorized_is_412(self):
        code, body, arm_mock, _ = _invoke_arm(
            {"dial_id": DIAL_ID, "armed": True}, auth_state=AUTH_NOT_AUTHORIZED,
        )
        assert code == 412
        assert body["error"] == "dial_not_authorized"
        arm_mock.assert_not_called()


# ---------------------------------------------------------------------------
# POST /api/dial/repeat: action validation
# ---------------------------------------------------------------------------

class TestInvalidAction:
    @pytest.mark.parametrize("action", [None, "", "start", "play", 1, True, [], {}])
    def test_invalid_action_is_400(self, action):
        code, body, transport = _invoke_transport({"dial_id": DIAL_ID, "action": action})
        assert code == 400
        assert body == {"ok": False, "error": "invalid_action"}
        transport.assert_not_called()

    @pytest.mark.parametrize("action", ["stop", "seek"])
    def test_valid_actions_reach_transport(self, action):
        code, body, transport = _invoke_transport(
            {"dial_id": DIAL_ID, "action": action},
            transport_ack={"ok": True, "state": "idle", "armed": False, "position_seconds": 0.0},
        )
        assert code == 200
        transport.assert_called_once()


# ---------------------------------------------------------------------------
# POST /api/dial/repeat: position validation
# ---------------------------------------------------------------------------

class TestInvalidPosition:
    @pytest.mark.parametrize("raw", [True, False, "5", float("nan"), -1, -0.5])
    def test_invalid_position_is_400(self, raw):
        code, body, transport = _invoke_transport(
            {"dial_id": DIAL_ID, "action": "seek", "position_seconds": raw},
        )
        assert code == 400
        assert body == {"ok": False, "error": "invalid_position"}
        transport.assert_not_called()

    def test_missing_position_defaults_to_zero_and_is_valid(self):
        """Start is expressed as seek 0 -- an absent position_seconds must
        not be rejected."""
        code, body, transport = _invoke_transport(
            {"dial_id": DIAL_ID, "action": "seek"},
            transport_ack={"ok": True, "state": "replaying", "armed": True,
                           "position_seconds": 0.0},
        )
        assert code == 200
        transport.assert_called_once_with("seek", 0.0)

    def test_valid_positive_position_forwarded(self):
        code, body, transport = _invoke_transport(
            {"dial_id": DIAL_ID, "action": "seek", "position_seconds": 12.5},
            transport_ack={"ok": True, "state": "replaying", "armed": True,
                           "position_seconds": 12.5},
        )
        assert code == 200
        transport.assert_called_once_with("seek", 12.5)

    def test_stop_ignores_position_seconds_field(self):
        code, body, transport = _invoke_transport(
            {"dial_id": DIAL_ID, "action": "stop", "position_seconds": "garbage"},
            transport_ack={"ok": True, "state": "hold", "armed": False, "position_seconds": 0.0},
        )
        assert code == 200
        transport.assert_called_once_with("stop", 0.0)


# ---------------------------------------------------------------------------
# POST /api/dial/repeat: rate limiting
# ---------------------------------------------------------------------------

class TestRateLimit:
    def test_second_seek_within_one_second_is_rate_limited(self):
        ack = {"ok": True, "state": "replaying", "armed": True, "position_seconds": 0.0}
        code1, body1, transport = _invoke_transport(
            {"dial_id": DIAL_ID, "action": "seek", "position_seconds": 0},
            transport_ack=ack,
        )
        assert code1 == 200
        assert body1["ok"] is True
        transport.assert_called_once()

        # Second call reuses the same rate-limit clock (module-level state).
        code2, body2, transport2 = _invoke_transport(
            {"dial_id": DIAL_ID, "action": "seek", "position_seconds": 0},
            transport_ack=ack,
        )
        assert code2 == 200
        assert body2 == {"ok": False, "error": "rate_limited", "appliance_id": TEST_APPLIANCE_ID}
        transport2.assert_not_called()

    def test_stop_is_never_rate_limited(self):
        ack = {"ok": True, "state": "hold", "armed": False, "position_seconds": 0.0}
        for _ in range(3):
            code, body, transport = _invoke_transport(
                {"dial_id": DIAL_ID, "action": "stop"}, transport_ack=ack,
            )
            assert code == 200
            assert body["ok"] is True
            transport.assert_called_once()

    def test_seek_after_the_interval_elapses_is_not_rate_limited(self):
        import autostream_webui_api as api
        ack = {"ok": True, "state": "replaying", "armed": True, "position_seconds": 0.0}
        api._dial_seek_last = 0.0
        with patch("time.monotonic", return_value=100.0):
            code1, body1, _ = _invoke_transport(
                {"dial_id": DIAL_ID, "action": "seek"}, transport_ack=ack,
            )
        assert body1["ok"] is True
        with patch("time.monotonic", return_value=101.5):
            code2, body2, transport2 = _invoke_transport(
                {"dial_id": DIAL_ID, "action": "seek"}, transport_ack=ack,
            )
        assert body2["ok"] is True
        transport2.assert_called_once()


# ---------------------------------------------------------------------------
# POST /api/dial/repeat: ack mapping
# ---------------------------------------------------------------------------

KNOWN_DAEMON_ERRORS = [
    "repeat_unavailable", "source_active", "no_recording", "fading_out",
    "invalid_position",
]


class TestAckMapping:
    @pytest.mark.parametrize("error", KNOWN_DAEMON_ERRORS)
    def test_known_daemon_error_passes_through(self, error):
        ack = {"ok": False, "error": error, "state": "recording", "armed": False}
        code, body, _ = _invoke_transport(
            {"dial_id": DIAL_ID, "action": "stop"}, transport_ack=ack,
        )
        assert code == 200
        assert body == {
            "ok": False, "error": error, "state": "recording", "armed": False,
            "appliance_id": TEST_APPLIANCE_ID,
        }

    def test_unrecognised_daemon_error_maps_to_backend_unavailable(self):
        ack = {"ok": False, "error": "unknown command: repeat_seek"}
        code, body, _ = _invoke_transport(
            {"dial_id": DIAL_ID, "action": "stop"}, transport_ack=ack,
        )
        assert code == 200
        assert body["ok"] is False
        assert body["error"] == "backend_unavailable"
        assert body["appliance_id"] == TEST_APPLIANCE_ID
        # Defaults applied since the ack (an old daemon's) carried none.
        assert body["state"] == "idle"
        assert body["armed"] is False

    def test_none_ack_maps_to_backend_unavailable(self):
        code, body, _ = _invoke_transport(
            {"dial_id": DIAL_ID, "action": "stop"}, transport_ack=None,
        )
        assert code == 200
        assert body == {
            "ok": False, "error": "backend_unavailable",
            "state": "idle", "armed": False, "appliance_id": TEST_APPLIANCE_ID,
        }

    def test_ok_response_carries_state_armed_position_appliance_id(self):
        ack = {"ok": True, "state": "replaying", "armed": True, "position_seconds": 7.5}
        code, body, _ = _invoke_transport(
            {"dial_id": DIAL_ID, "action": "seek", "position_seconds": 7.5},
            transport_ack=ack,
        )
        assert code == 200
        assert body == {
            "ok": True, "state": "replaying", "armed": True,
            "position_seconds": 7.5, "appliance_id": TEST_APPLIANCE_ID,
        }

    def test_ok_ack_missing_fields_defaults_applied(self):
        """An old daemon's ok:true ack (pre-A4, no state/armed/position_seconds)."""
        code, body, _ = _invoke_transport(
            {"dial_id": DIAL_ID, "action": "stop"}, transport_ack={"ok": True},
        )
        assert code == 200
        assert body == {
            "ok": True, "state": "idle", "armed": False,
            "position_seconds": 0.0, "appliance_id": TEST_APPLIANCE_ID,
        }

    def test_route_never_reads_get_repeat_status(self):
        """get_repeat_status is monkeypatched to raise in _invoke_transport;
        a successful call proves the route never touches it."""
        ack = {"ok": True, "state": "hold", "armed": False, "position_seconds": 0.0}
        code, body, _ = _invoke_transport(
            {"dial_id": DIAL_ID, "action": "stop"}, transport_ack=ack,
        )
        assert code == 200
        assert body["ok"] is True


# ---------------------------------------------------------------------------
# POST /api/dial/repeat/arm
# ---------------------------------------------------------------------------

class TestArmRoute:
    @pytest.mark.parametrize("armed", [None, "true", 1, 0, [], {}, "yes"])
    def test_invalid_armed_is_400(self, armed):
        code, body, arm_mock, legacy_mock = _invoke_arm({"dial_id": DIAL_ID, "armed": armed})
        assert code == 400
        assert body == {"ok": False, "error": "invalid_armed"}
        arm_mock.assert_not_called()
        legacy_mock.assert_not_called()

    def test_missing_armed_is_400(self):
        code, body, arm_mock, _ = _invoke_arm({"dial_id": DIAL_ID})
        assert code == 400
        assert body == {"ok": False, "error": "invalid_armed"}
        arm_mock.assert_not_called()

    @pytest.mark.parametrize("armed", [True, False])
    def test_calls_set_live_repeat_armed_ack_with_bool(self, armed):
        ack = {"ok": True, "state": "hold", "armed": armed, "position_seconds": 0.0}
        code, body, arm_mock, legacy_mock = _invoke_arm(
            {"dial_id": DIAL_ID, "armed": armed}, arm_ack=ack,
        )
        assert code == 200
        arm_mock.assert_called_once_with(armed)
        legacy_mock.assert_not_called()

    def test_arm_allowed_while_playing(self):
        """The route places no daemon-state precondition on arming -- the
        daemon's own Armed/Disarmed cells decide what it means."""
        ack = {"ok": True, "state": "recording", "armed": True, "position_seconds": 0.0}
        code, body, arm_mock, _ = _invoke_arm({"dial_id": DIAL_ID, "armed": True}, arm_ack=ack)
        assert code == 200
        assert body["ok"] is True
        arm_mock.assert_called_once_with(True)

    def test_ack_mapping_shared_with_transport_route(self):
        ack = {"ok": False, "error": "repeat_unavailable", "state": "idle", "armed": False}
        code, body, _, _ = _invoke_arm({"dial_id": DIAL_ID, "armed": True}, arm_ack=ack)
        assert code == 200
        assert body == {
            "ok": False, "error": "repeat_unavailable", "state": "idle",
            "armed": False, "appliance_id": TEST_APPLIANCE_ID,
        }

    def test_none_ack_maps_to_backend_unavailable(self):
        code, body, _, _ = _invoke_arm({"dial_id": DIAL_ID, "armed": True}, arm_ack=None)
        assert code == 200
        assert body == {
            "ok": False, "error": "backend_unavailable",
            "state": "idle", "armed": False, "appliance_id": TEST_APPLIANCE_ID,
        }
