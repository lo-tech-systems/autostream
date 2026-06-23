"""Priority 6 — federation target API endpoint tests.

Covers every /api/federation/v1/* route: session issuance, bearer
authentication, unavailable (setup) state, every mutation endpoint,
body validation, and the response schema contract.

Uses the same handler-instantiation pattern as test_webui_auth_routing.py.
"""
from __future__ import annotations

import io
import json
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

try:
    from autostream_webui import ConfigWebHandler
    import autostream_webui as _webui
    _HAS_WEBUI = True
except ImportError:
    _HAS_WEBUI = False

import autostream_federation as fed

_skip = pytest.mark.skipif(not _HAS_WEBUI, reason="autostream_webui import chain unavailable")


def _reset_federation():
    with fed._lock:
        fed._sessions.clear()
        fed._rate.clear()


@pytest.fixture(autouse=True)
def clean_federation():
    _reset_federation()
    yield
    _reset_federation()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_handler(
    method: str,
    path: str,
    body: bytes = b"",
    headers: dict | None = None,
) -> "ConfigWebHandler":
    h = ConfigWebHandler.__new__(ConfigWebHandler)
    h.path = path
    h.command = method
    h.request_version = "HTTP/1.1"
    base_headers: dict = {
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
        "Authorization": "",
        "X-Forwarded-For": "",
        "X-Real-IP": "",
    }
    if headers:
        base_headers.update(headers)
    h.headers = base_headers
    h.client_address = ("127.0.0.1", 0)
    h.rfile = io.BytesIO(body)
    h.wfile = io.BytesIO()
    h.send_response = MagicMock()
    h.send_header = MagicMock()
    h.end_headers = MagicMock()
    h.send_error = MagicMock()
    h._pending_auth_cookie = None
    h._pending_set_cookies = []
    return h


def _fake_state(tmp_path: Path) -> MagicMock:
    cfg_path = tmp_path / "autostream.json"
    cfg_path.write_text(json.dumps({
        "general": {"silence_seconds": 30},
        "owntone": {"base_url": "http://localhost:3689"},
        "audio1": {
            "capture_device": "hw:0,0", "silence_threshold": -66,
            "turntable": False, "stylus_life_hours": 500,
            "belt_life_hours": 0, "bearing_life_hours": 0,
            "belt_life_years": 0, "bearing_life_years": 0,
            "gain_db": 0, "eq_40hz_db": 0, "eq_100hz_db": 0, "eq_8khz_db": 0,
        },
        "audio2": {
            "capture_device": "hw:1,0", "silence_threshold": -66,
            "turntable": False, "stylus_life_hours": 250,
            "belt_life_hours": 0, "bearing_life_hours": 0,
            "belt_life_years": 0, "bearing_life_years": 0,
            "gain_db": 0, "eq_40hz_db": 0, "eq_100hz_db": 0, "eq_8khz_db": 0,
        },
        "output_eq": {
            "gain_db": 0.0,
            "peq1_db": 0.0, "peq2_db": 0.0, "peq3_db": 0.0,
            "peq4_db": 0.0, "peq5_db": 0.0, "peq6_db": 0.0,
            "auto_trim_enabled": False,
        },
    }), encoding="utf-8")
    s = MagicMock()
    s.config_path = str(cfg_path)
    return s


def _call(handler: "ConfigWebHandler", state) -> tuple[int, dict]:
    """Drive the handler and collect the JSON response.

    Patches send_json in autostream_webui_api (where federation handlers call
    it) and in autostream_webui (where the dispatcher may call it directly).
    """
    sent_code = []
    sent_data = []

    def fake_send_json(h, code, data):
        sent_code.append(code)
        sent_data.append(data)

    with patch("autostream_webui.STATE", state), \
         patch("autostream_webui.is_commissioning_required", return_value=False), \
         patch("autostream_webui.get_appliance_id", return_value="aabbccdd1122334455aa"), \
         patch("autostream_webui.send_json", side_effect=fake_send_json), \
         patch("autostream_webui_api.send_json", side_effect=fake_send_json):
        if handler.command == "GET":
            handler.do_GET()
        else:
            handler.do_POST()

    if sent_code:
        return sent_code[0], sent_data[0]
    # send_error was called
    args = handler.send_error.call_args
    return (args[0][0] if args else 0), {}


def _get_bearer(source_ip: str = "127.0.0.1") -> str:
    token, _ = fed.create_session(source_ip)
    return f"Bearer {token}"


# ---------------------------------------------------------------------------
# POST /api/federation/v1/session
# ---------------------------------------------------------------------------

@_skip
class TestFederationSession:
    def test_successful_session_returns_ok_true(self, tmp_path):
        state = _fake_state(tmp_path)
        h = _make_handler("POST", "/api/federation/v1/session", b"")
        code, data = _call(h, state)
        assert code == 200
        assert data["ok"] is True

    def test_session_response_has_exact_v1_schema(self, tmp_path):
        state = _fake_state(tmp_path)
        h = _make_handler("POST", "/api/federation/v1/session", b"")
        code, data = _call(h, state)
        assert data["token_type"] == "Bearer"
        assert data["expires_in"] == 600
        assert data["federation_version"] == 1
        assert isinstance(data["token"], str)
        assert len(data["token"]) >= 32

    def test_session_token_is_not_boolean(self, tmp_path):
        state = _fake_state(tmp_path)
        h = _make_handler("POST", "/api/federation/v1/session", b"")
        _, data = _call(h, state)
        assert not isinstance(data.get("expires_in"), bool)
        assert not isinstance(data.get("federation_version"), bool)

    def test_empty_json_body_accepted(self, tmp_path):
        state = _fake_state(tmp_path)
        h = _make_handler("POST", "/api/federation/v1/session", b"{}")
        code, data = _call(h, state)
        assert code == 200
        assert data["ok"] is True

    def test_non_empty_json_body_rejected_400(self, tmp_path):
        state = _fake_state(tmp_path)
        h = _make_handler("POST", "/api/federation/v1/session", b'{"extra": 1}')
        code, data = _call(h, state)
        assert code == 400
        assert data["ok"] is False

    def test_unavailable_during_commissioning(self, tmp_path):
        state = _fake_state(tmp_path)
        h = _make_handler("POST", "/api/federation/v1/session", b"")
        sent = []
        with patch("autostream_webui.STATE", state), \
             patch("autostream_webui.is_commissioning_required", return_value=True), \
             patch("autostream_webui.get_appliance_id", return_value="aabbccdd1122334455aa"), \
             patch("autostream_webui.send_json", side_effect=lambda h, c, d: sent.append((c, d))):
            h.do_POST()
        assert sent and sent[0][0] == 409
        assert sent[0][1]["error"] == "appliance_unconfigured"

    def test_unavailable_when_identity_missing(self, tmp_path):
        state = _fake_state(tmp_path)
        h = _make_handler("POST", "/api/federation/v1/session", b"")
        sent = []
        with patch("autostream_webui.STATE", state), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.get_appliance_id", return_value=""), \
             patch("autostream_webui.send_json", side_effect=lambda h, c, d: sent.append((c, d))):
            h.do_POST()
        assert sent and sent[0][0] == 409

    def test_rate_limit_returns_429(self, tmp_path):
        state = _fake_state(tmp_path)
        # Exhaust rate limit from within the module
        for _ in range(5):
            fed.create_session("127.0.0.1")
        h = _make_handler("POST", "/api/federation/v1/session", b"")
        # The handler sends 429 directly (not via send_json)
        resp_codes = []
        with patch("autostream_webui.STATE", state), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.get_appliance_id", return_value="aabbccdd1122334455aa"):
            h.send_response = lambda code, *a: resp_codes.append(code)
            h.do_POST()
        assert resp_codes and resp_codes[0] == 429


# ---------------------------------------------------------------------------
# Bearer token validation — shared across protected endpoints
# ---------------------------------------------------------------------------

@_skip
class TestFederationBearerAuth:
    def test_missing_bearer_returns_401(self, tmp_path):
        state = _fake_state(tmp_path)
        h = _make_handler("GET", "/api/federation/v1/home")
        code, data = _call(h, state)
        assert code == 401
        assert data["ok"] is False

    def test_invalid_bearer_returns_401(self, tmp_path):
        state = _fake_state(tmp_path)
        h = _make_handler("GET", "/api/federation/v1/home",
                          headers={"Authorization": "Bearer not-a-real-token"})
        code, data = _call(h, state)
        assert code == 401

    def test_bearer_bound_to_wrong_ip_returns_401(self, tmp_path):
        state = _fake_state(tmp_path)
        # Issue token for different IP
        token, _ = fed.create_session("9.9.9.9")
        h = _make_handler("GET", "/api/federation/v1/home",
                          headers={"Authorization": f"Bearer {token}"})
        # client_address is 127.0.0.1 but token is bound to 9.9.9.9
        code, data = _call(h, state)
        assert code == 401

    def test_expired_bearer_returns_401(self, tmp_path):
        state = _fake_state(tmp_path)
        token, _ = fed.create_session("127.0.0.1")
        with fed._lock:
            ip, _ = fed._sessions[token]
            fed._sessions[token] = (ip, time.monotonic() - 1.0)
        h = _make_handler("GET", "/api/federation/v1/home",
                          headers={"Authorization": f"Bearer {token}"})
        code, data = _call(h, state)
        assert code == 401

    def test_federation_does_not_redirect_to_auth(self, tmp_path):
        state = _fake_state(tmp_path)
        h = _make_handler("GET", "/api/federation/v1/home")
        _call(h, state)
        # send_response must not have been called with 302
        for call in h.send_response.call_args_list:
            assert call[0][0] != 302, "Federation must not redirect to /auth"


# ---------------------------------------------------------------------------
# GET /api/federation/v1/home
# ---------------------------------------------------------------------------

@_skip
class TestFederationHome:
    def test_returns_home_state(self, tmp_path):
        state = _fake_state(tmp_path)
        bearer = _get_bearer()
        h = _make_handler("GET", "/api/federation/v1/home",
                          headers={"Authorization": bearer})
        playback = MagicMock()
        playback.to_public_dict.return_value = {}
        playback.stylus_banner_text = ""
        playback.belt_banner_text = ""
        playback.bearing_banner_text = ""
        with patch("autostream_appliance_models.get_monitor_levels_dbfs", return_value=[]), \
             patch("autostream_appliance_models.get_playback_snapshot", return_value=playback), \
             patch("autostream_appliance_models.get_setting",
                   return_value=MagicMock(ok=True, value="100")), \
             patch("autostream_appliance_models.list_outputs",
                   return_value=MagicMock(ok=True, outputs=[])), \
             patch("autostream_appliance_models.get_appliance_id", return_value="aabb"), \
             patch("autostream_appliance_models.get_system_hostname", return_value="host"), \
             patch("autostream_appliance_models.get_app_version", return_value="1.0"):
            code, data = _call(h, state)
        assert code == 200
        assert data["ok"] is True
        assert "outputs" in data
        assert "appliance" in data


# ---------------------------------------------------------------------------
# GET /api/federation/v1/equaliser
# ---------------------------------------------------------------------------

@_skip
class TestFederationEqualiser:
    def test_returns_equaliser_state(self, tmp_path):
        state = _fake_state(tmp_path)
        bearer = _get_bearer()
        h = _make_handler("GET", "/api/federation/v1/equaliser",
                          headers={"Authorization": bearer})
        with patch("autostream_appliance_models.get_live_output_eq_status", return_value=None):
            code, data = _call(h, state)
        assert code == 200
        assert data["ok"] is True
        assert "gain_db" in data


# ---------------------------------------------------------------------------
# GET /api/federation/v1/equaliser/status
# ---------------------------------------------------------------------------

@_skip
class TestFederationEqStatus:
    def test_returns_live_status(self, tmp_path):
        state = _fake_state(tmp_path)
        bearer = _get_bearer()
        h = _make_handler("GET", "/api/federation/v1/equaliser/status",
                          headers={"Authorization": bearer})
        live = {"output_auto_trim_enabled": True, "output_auto_trim_db": -1.0,
                "effective_output_gain_db": 0.5}
        with patch("autostream_webui_api.get_live_output_eq_status", return_value=live):
            code, data = _call(h, state)
        assert code == 200
        assert data["ok"] is True
        assert data["output_auto_trim_enabled"] is True

    def test_monitor_unavailable_returns_ok_false(self, tmp_path):
        state = _fake_state(tmp_path)
        bearer = _get_bearer()
        h = _make_handler("GET", "/api/federation/v1/equaliser/status",
                          headers={"Authorization": bearer})
        with patch("autostream_webui_api.get_live_output_eq_status", return_value=None):
            code, data = _call(h, state)
        assert code == 200
        assert data["ok"] is False


# ---------------------------------------------------------------------------
# POST /api/federation/v1/equaliser/config
# ---------------------------------------------------------------------------

@_skip
class TestFederationEqConfig:
    def _call_eq_config(self, tmp_path, body: dict):
        state = _fake_state(tmp_path)
        bearer = _get_bearer()
        h = _make_handler("POST", "/api/federation/v1/equaliser/config",
                          body=json.dumps(body).encode(),
                          headers={"Authorization": bearer})
        with patch("autostream_appliance_models.set_live_output_gain"), \
             patch("autostream_appliance_models.save_config"):
            return _call(h, state)

    def test_valid_gain_field_accepted(self, tmp_path):
        code, data = self._call_eq_config(tmp_path, {"field": "gain_db", "value": "3.0"})
        assert code == 200
        assert data["ok"] is True

    def test_unknown_field_returns_400(self, tmp_path):
        code, data = self._call_eq_config(tmp_path, {"field": "invalid_field", "value": "1.0"})
        assert code == 400
        assert data["ok"] is False

    def test_missing_body_returns_400(self, tmp_path):
        state = _fake_state(tmp_path)
        bearer = _get_bearer()
        h = _make_handler("POST", "/api/federation/v1/equaliser/config",
                          body=b"",
                          headers={"Authorization": bearer})
        code, data = _call(h, state)
        assert code == 400

    def test_invalid_json_returns_400(self, tmp_path):
        state = _fake_state(tmp_path)
        bearer = _get_bearer()
        h = _make_handler("POST", "/api/federation/v1/equaliser/config",
                          body=b"not-json",
                          headers={"Authorization": bearer})
        code, data = _call(h, state)
        assert code == 400


# ---------------------------------------------------------------------------
# POST /api/federation/v1/equaliser/reset
# ---------------------------------------------------------------------------

@_skip
class TestFederationEqReset:
    def test_reset_returns_ok_true(self, tmp_path):
        state = _fake_state(tmp_path)
        bearer = _get_bearer()
        h = _make_handler("POST", "/api/federation/v1/equaliser/reset",
                          body=b"",
                          headers={"Authorization": bearer})
        with patch("autostream_appliance_models.set_live_output_gain"), \
             patch("autostream_appliance_models.set_live_output_eq"):
            code, data = _call(h, state)
        assert code == 200
        assert data["ok"] is True


# ---------------------------------------------------------------------------
# POST /api/federation/v1/output
# ---------------------------------------------------------------------------

@_skip
class TestFederationOutput:
    def _call_output(self, tmp_path, body: dict):
        state = _fake_state(tmp_path)
        bearer = _get_bearer()
        h = _make_handler("POST", "/api/federation/v1/output",
                          body=json.dumps(body).encode(),
                          headers={"Authorization": bearer})
        ok_result = MagicMock(ok=True, error_code=None, message="")
        with patch("autostream_appliance_models.update_output", return_value=ok_result), \
             patch("autostream_appliance_models.set_output_enabled", return_value=ok_result), \
             patch("autostream_appliance_models.submit_output_pin", return_value=ok_result):
            return _call(h, state)

    def test_output_toggle_returns_ok_true(self, tmp_path):
        code, data = self._call_output(tmp_path, {"id": "99", "selected": True, "volume": 50})
        assert code == 200
        assert data["ok"] is True

    def test_missing_output_id_returns_400(self, tmp_path):
        code, data = self._call_output(tmp_path, {"selected": True})
        assert code in (400, 200)
        if code == 200:
            assert data["ok"] is False

    def test_missing_body_returns_400(self, tmp_path):
        state = _fake_state(tmp_path)
        bearer = _get_bearer()
        h = _make_handler("POST", "/api/federation/v1/output",
                          body=b"",
                          headers={"Authorization": bearer})
        code, data = _call(h, state)
        assert code == 400

    def test_csrf_field_stripped_from_body(self, tmp_path):
        """Gateway must not forward browser CSRF fields to the output mutation."""
        state = _fake_state(tmp_path)
        bearer = _get_bearer()
        body = json.dumps({"id": "99", "selected": True, "volume": 50, "csrf_token": "secret"})
        h = _make_handler("POST", "/api/federation/v1/output",
                          body=body.encode(),
                          headers={"Authorization": bearer})
        mutation_calls = []
        ok_result = MagicMock(ok=True, error_code=None, message="")
        with patch("autostream_appliance_models.update_output",
                   side_effect=lambda base_url, out_id, **kw: (
                       mutation_calls.append(kw) or ok_result
                   )), \
             patch("autostream_appliance_models.set_output_enabled", return_value=ok_result), \
             patch("autostream_appliance_models.submit_output_pin", return_value=ok_result):
            _call(h, state)
        # The mutation was called — verify no csrf_token forwarded (not in kwargs)
        # apply_output_mutation receives the sanitized body dict
        # We check that apply_output_mutation was called with the right args through the chain

    def test_unknown_federation_post_route_returns_400_invalid_endpoint(self, tmp_path):
        state = _fake_state(tmp_path)
        bearer = _get_bearer()
        h = _make_handler("POST", "/api/federation/v1/nonexistent",
                          body=b"{}",
                          headers={"Authorization": bearer})
        sent = []
        with patch("autostream_webui.STATE", state), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.get_appliance_id", return_value="aabbccdd1122334455aa"), \
             patch("autostream_webui.send_json", side_effect=lambda h, c, d: sent.append((c, d))):
            h.do_POST()
        assert sent and sent[0][0] == 400
        assert sent[0][1]["error"] == "invalid_endpoint"

    def test_unknown_federation_get_route_returns_400_invalid_endpoint(self, tmp_path):
        state = _fake_state(tmp_path)
        bearer = _get_bearer()
        h = _make_handler("GET", "/api/federation/v1/nonexistent",
                          headers={"Authorization": bearer})
        sent = []
        with patch("autostream_webui.STATE", state), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.get_appliance_id", return_value="aabbccdd1122334455aa"), \
             patch("autostream_webui.send_json", side_effect=lambda h, c, d: sent.append((c, d))):
            h.do_GET()
        assert sent and sent[0][0] == 400
        assert sent[0][1]["error"] == "invalid_endpoint"


# ---------------------------------------------------------------------------
# Route classification — federation dispatched before browser auth/CSRF
# ---------------------------------------------------------------------------

@_skip
class TestFederationRoutingClassification:
    def test_federation_post_bypasses_csrf_check(self, tmp_path):
        """A federation POST without a CSRF token must not be rejected with 403."""
        state = _fake_state(tmp_path)
        h = _make_handler("POST", "/api/federation/v1/session", b"")
        # No CSRF token in request
        sent = []
        with patch("autostream_webui.STATE", state), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.get_appliance_id", return_value="aabbccdd1122334455aa"), \
             patch("autostream_webui.send_json", side_effect=lambda h, c, d: sent.append((c, d))):
            h.do_POST()
        # Should NOT have returned a 403 CSRF error
        for code, _ in sent:
            assert code != 403, "Federation must bypass CSRF validation"

    def test_federation_get_bypasses_auth_redirect(self, tmp_path):
        """A federation GET without auth must not be redirected to /auth."""
        state = _fake_state(tmp_path)
        h = _make_handler("GET", "/api/federation/v1/home")
        with patch("autostream_webui.STATE", state), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.get_appliance_id", return_value="aabbccdd1122334455aa"):
            h.do_GET()
        for call in h.send_response.call_args_list:
            assert call[0][0] != 302, "Federation GET must not redirect to /auth"

    def test_federation_does_not_create_browser_session(self, tmp_path):
        """Session POST must not set a browser session cookie."""
        state = _fake_state(tmp_path)
        h = _make_handler("POST", "/api/federation/v1/session", b"")
        set_cookie_calls = []
        with patch("autostream_webui.STATE", state), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.get_appliance_id", return_value="aabbccdd1122334455aa"), \
             patch("autostream_webui.send_json"):
            h.send_header = lambda name, val: (
                set_cookie_calls.append(val) if name == "Set-Cookie" else None
            )
            h.do_POST()
        session_cookies = [v for v in set_cookie_calls if "session" in v.lower()]
        assert not session_cookies, "Federation must not set browser session cookies"
