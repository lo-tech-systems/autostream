"""Dial proxy and handler tests.

Covers: _proxy_call() connection closure and bounded read, dial-offline tunneling,
502 on OSError / invalid JSON / oversized body / 3xx target, target-status
normalization, non-intercepted pass-through, authorize / revoke / management
dispatcher, and the complete GET + POST proxy contract.
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

from autostream_webui_dials import (
    _proxy_call,
    _BadTargetResponse,
    dispatch_dial_management_post,
    handle_dial_authorize_post,
    handle_dial_revoke_post,
    handle_dial_configure_get,
    _proxy_get,
    _proxy_post,
    _MAX_PROXY_RESPONSE_BYTES,
)


# ---------------------------------------------------------------------------
# Mock builder helpers
# ---------------------------------------------------------------------------

def _make_conn_mock(resp_status=200, resp_body=b'{"ok":true}',
                    request_exc=None, getresponse_exc=None, read_exc=None):
    """Build a mock HTTPConnection with configurable failure points."""
    conn = MagicMock()
    if request_exc:
        conn.request.side_effect = request_exc
    else:
        resp = MagicMock()
        resp.status = resp_status
        if read_exc:
            resp.read.side_effect = read_exc
        else:
            resp.read.return_value = resp_body
        if getresponse_exc:
            conn.getresponse.side_effect = getresponse_exc
        else:
            conn.getresponse.return_value = resp
    return conn


def _conn_success(body: bytes = b'{"ok":true}', status: int = 200):
    conn = MagicMock()
    resp = MagicMock()
    resp.status = status
    resp.read.return_value = body
    conn.getresponse.return_value = resp
    return conn


def _capture_sent(fn, *args, **kwargs) -> list[tuple[int, dict]]:
    """Call fn(*args, **kwargs), capturing every send_json / send_browser_api_error call."""
    sent = []

    def fake_send_json(handler, code, data):
        sent.append((code, dict(data)))

    with patch("autostream_webui_dials.send_json", side_effect=fake_send_json), \
         patch("autostream_webui_api.send_json", side_effect=fake_send_json):
        fn(*args, **kwargs)

    return sent


# ---------------------------------------------------------------------------
# _proxy_call: connection closure
# ---------------------------------------------------------------------------

class TestProxyCallConnectionClosure:
    def _call(self, conn_mock, **kwargs):
        with patch("autostream_webui_dials.http.client.HTTPConnection",
                   return_value=conn_mock):
            try:
                return _proxy_call("GET", "10.0.0.1", 7000, "/configure", **kwargs)
            except Exception:
                pass
        return None

    def test_success_closes_connection(self):
        conn = _make_conn_mock(resp_status=200, resp_body=b'{"ok":true}')
        result = self._call(conn)
        assert result == (200, {"ok": True})
        conn.close.assert_called_once()

    def test_non_200_status_closes_connection(self):
        conn = _make_conn_mock(resp_status=403, resp_body=b'{"ok":false}')
        result = self._call(conn)
        assert result == (403, {"ok": False})
        conn.close.assert_called_once()

    def test_request_oserror_closes_connection(self):
        conn = _make_conn_mock(request_exc=OSError("refused"))
        with pytest.raises(OSError):
            with patch("autostream_webui_dials.http.client.HTTPConnection",
                       return_value=conn):
                _proxy_call("GET", "10.0.0.1", 7000, "/configure")
        conn.close.assert_called_once()

    def test_getresponse_oserror_closes_connection(self):
        conn = _make_conn_mock(getresponse_exc=OSError("timeout"))
        with pytest.raises(OSError):
            with patch("autostream_webui_dials.http.client.HTTPConnection",
                       return_value=conn):
                _proxy_call("GET", "10.0.0.1", 7000, "/configure")
        conn.close.assert_called_once()

    def test_read_oserror_closes_connection(self):
        conn = _make_conn_mock(read_exc=OSError("broken pipe"))
        with pytest.raises(OSError):
            with patch("autostream_webui_dials.http.client.HTTPConnection",
                       return_value=conn):
                _proxy_call("GET", "10.0.0.1", 7000, "/configure")
        conn.close.assert_called_once()

    def test_invalid_json_raises_bad_target_response_and_closes_connection(self):
        conn = _make_conn_mock(resp_body=b"not-json")
        with pytest.raises(_BadTargetResponse):
            with patch("autostream_webui_dials.http.client.HTTPConnection",
                       return_value=conn):
                _proxy_call("GET", "10.0.0.1", 7000, "/configure")
        conn.close.assert_called_once()

    def test_post_with_body_closes_connection(self):
        conn = _make_conn_mock(resp_status=200, resp_body=b'{"ok":true}')
        result = self._call(conn, body=b'{"foo":1}')
        assert result == (200, {"ok": True})
        conn.close.assert_called_once()
        _, call_kwargs = conn.request.call_args
        assert call_kwargs.get("headers", {}).get("Content-Type") == "application/json"


# ---------------------------------------------------------------------------
# _proxy_call: bounded read and 3xx rejection
# ---------------------------------------------------------------------------

class TestProxyCallBoundedRead:
    def _call_raw(self, conn_mock):
        with patch("autostream_webui_dials.http.client.HTTPConnection",
                   return_value=conn_mock):
            return _proxy_call("GET", "10.0.0.1", 7000, "/configure")

    def test_exactly_max_bytes_is_accepted(self):
        # Build a 65,536-byte valid JSON object
        # Use a string value padded to hit exactly 65,536 bytes total.
        key = "x"
        # '{"x":"' + padding + '"}' — calculate exact padding
        prefix = b'{"x":"'
        suffix = b'"}'
        pad_len = _MAX_PROXY_RESPONSE_BYTES - len(prefix) - len(suffix)
        body = prefix + (b"a" * pad_len) + suffix
        assert len(body) == _MAX_PROXY_RESPONSE_BYTES
        conn = _make_conn_mock(resp_status=200, resp_body=body)
        status, data = self._call_raw(conn)
        assert status == 200
        assert "x" in data

    def test_one_over_max_bytes_raises_bad_target_response(self):
        body = b'{"x":"' + b"a" * (_MAX_PROXY_RESPONSE_BYTES + 10) + b'"}'
        conn = _make_conn_mock(resp_status=200, resp_body=body)
        with pytest.raises(_BadTargetResponse):
            with patch("autostream_webui_dials.http.client.HTTPConnection",
                       return_value=conn):
                _proxy_call("GET", "10.0.0.1", 7000, "/configure")

    def test_3xx_with_html_body_raises_bad_target_response(self):
        conn = _make_conn_mock(resp_status=301, resp_body=b"<html>redirect</html>")
        with pytest.raises(_BadTargetResponse):
            with patch("autostream_webui_dials.http.client.HTTPConnection",
                       return_value=conn):
                _proxy_call("GET", "10.0.0.1", 7000, "/configure")

    def test_3xx_with_valid_json_body_raises_bad_target_response(self):
        # Even a valid JSON body in a redirect must be rejected before parsing.
        conn = _make_conn_mock(resp_status=302, resp_body=b'{"ok":true}')
        with pytest.raises(_BadTargetResponse):
            with patch("autostream_webui_dials.http.client.HTTPConnection",
                       return_value=conn):
                _proxy_call("GET", "10.0.0.1", 7000, "/configure")

    def test_non_object_json_root_raises_bad_target_response(self):
        conn = _make_conn_mock(resp_status=200, resp_body=b'[1,2,3]')
        with pytest.raises(_BadTargetResponse):
            with patch("autostream_webui_dials.http.client.HTTPConnection",
                       return_value=conn):
                _proxy_call("GET", "10.0.0.1", 7000, "/configure")

    def test_json_string_root_raises_bad_target_response(self):
        conn = _make_conn_mock(resp_status=200, resp_body=b'"hello"')
        with pytest.raises(_BadTargetResponse):
            with patch("autostream_webui_dials.http.client.HTTPConnection",
                       return_value=conn):
                _proxy_call("GET", "10.0.0.1", 7000, "/configure")


# ---------------------------------------------------------------------------
# _proxy_get: full browser-facing contract
# ---------------------------------------------------------------------------

class TestProxyGetContracts:
    def _call_proxy_get(self, uuid: str, conn_mock=None, dial_path="/configure") -> list:
        def run():
            if conn_mock is not None:
                with patch("autostream_webui_dials.http.client.HTTPConnection",
                           return_value=conn_mock):
                    _proxy_get(MagicMock(), uuid, dial_path)
            else:
                _proxy_get(MagicMock(), uuid, dial_path)

        return _capture_sent(run)

    # 1. unknown registry UUID → transport 200, dial_offline, error_status 404, retryable
    def test_dial_offline_tunneled_200(self):
        with patch("autostream_webui_dials.get_dial_sighting", return_value=None):
            sent = self._call_proxy_get("unknown-uuid")
        code, data = sent[0]
        assert code == 200
        assert data["error"] == "dial_offline"
        assert data["error_status"] == 404
        assert data["retryable"] is True

    # 2. connection refusal → transport 200, dial_unreachable, error_status 502
    def test_oserror_tunneled_502_unreachable(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = MagicMock()
        conn.request.side_effect = OSError("refused")
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting):
            sent = self._call_proxy_get("uuid", conn_mock=conn)
        code, data = sent[0]
        assert code == 200
        assert data["error"] == "dial_unreachable"
        assert data["error_status"] == 502

    # 3. socket timeout follows same contract
    def test_timeout_tunneled_502_unreachable(self):
        import socket
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = MagicMock()
        conn.request.side_effect = socket.timeout("timed out")
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting):
            sent = self._call_proxy_get("uuid", conn_mock=conn)
        code, data = sent[0]
        assert code == 200
        assert data["error"] == "dial_unreachable"
        assert data["error_status"] == 502

    # 4. malformed JSON → transport 200, dial_bad_response, error_status 502
    def test_invalid_json_tunneled_502_bad_response(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = _conn_success(body=b"not-json")
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting):
            sent = self._call_proxy_get("uuid", conn_mock=conn)
        code, data = sent[0]
        assert code == 200
        assert data["error"] == "dial_bad_response"
        assert data["error_status"] == 502

    # 5. non-object JSON is rejected as dial_bad_response
    def test_non_object_json_tunneled_502_bad_response(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = _conn_success(body=b'[1,2,3]')
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting):
            sent = self._call_proxy_get("uuid", conn_mock=conn)
        code, data = sent[0]
        assert code == 200
        assert data["error"] == "dial_bad_response"
        assert data["error_status"] == 502

    # 6a. exactly 65,536 byte body accepted if otherwise valid
    def test_max_body_size_accepted(self):
        prefix = b'{"x":"'
        suffix = b'"}'
        pad = _MAX_PROXY_RESPONSE_BYTES - len(prefix) - len(suffix)
        body = prefix + b"a" * pad + suffix
        assert len(body) == _MAX_PROXY_RESPONSE_BYTES
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = _conn_success(body=body)
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting):
            sent = self._call_proxy_get("uuid", conn_mock=conn)
        code, data = sent[0]
        assert code == 200
        assert data.get("ok") is not False or "error_status" not in data  # success path

    # 6b. 65,537 byte body rejected as dial_bad_response
    def test_overflow_body_tunneled_502_bad_response(self):
        body = b'{"x":"' + b"a" * (_MAX_PROXY_RESPONSE_BYTES + 10) + b'"}'
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = _conn_success(body=body)
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting):
            sent = self._call_proxy_get("uuid", conn_mock=conn)
        code, data = sent[0]
        assert code == 200
        assert data["error"] == "dial_bad_response"
        assert data["error_status"] == 502

    # 7. target 400 passes through as native 400
    def test_target_400_passes_through_natively(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = _conn_success(body=b'{"ok":false,"error":"bad_input"}', status=400)
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting):
            sent = self._call_proxy_get("uuid", conn_mock=conn)
        code, data = sent[0]
        assert code == 400
        assert "error_status" not in data

    # 8. target 403 passes through as native 403
    def test_target_403_passes_through_natively(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = _conn_success(body=b'{"ok":false,"error":"wrong_pin"}', status=403)
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting):
            sent = self._call_proxy_get("uuid", conn_mock=conn)
        code, data = sent[0]
        assert code == 403
        assert "error_status" not in data

    # 9. target 404 {"active": false} → transport 200, error_status 404, error: not_found, active retained
    def test_target_404_with_active_false_tunneled_with_field_preserved(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = _conn_success(body=b'{"active":false}', status=404)
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting):
            sent = self._call_proxy_get("uuid", conn_mock=conn, dial_path="/recovery_status")
        code, data = sent[0]
        assert code == 200
        assert data["error_status"] == 404
        assert data["error"] == "not_found"
        assert data["active"] is False
        assert data["ok"] is False

    # 10. target 429 passes through as native 429
    def test_target_429_passes_through_natively(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = _conn_success(body=b'{"ok":false,"error":"too_many_attempts"}', status=429)
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting):
            sent = self._call_proxy_get("uuid", conn_mock=conn)
        code, data = sent[0]
        assert code == 429
        assert "error_status" not in data

    # 11. target 500 passes through as native 500
    def test_target_500_passes_through_natively(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = _conn_success(body=b'{"ok":false,"error":"save_failed"}', status=500)
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting):
            sent = self._call_proxy_get("uuid", conn_mock=conn)
        code, data = sent[0]
        assert code == 500
        assert "error_status" not in data

    # 12a. GET target 502 → transport 200, error_status 502
    def test_get_target_502_tunneled(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = _conn_success(body=b'{"ok":false,"error":"upstream_error"}', status=502)
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting):
            sent = self._call_proxy_get("uuid", conn_mock=conn)
        code, data = sent[0]
        assert code == 200
        assert data["error_status"] == 502

    # 12b. GET target 503 → transport 200, error_status 503
    def test_get_target_503_tunneled(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = _conn_success(body=b'{"ok":false}', status=503)
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting):
            sent = self._call_proxy_get("uuid", conn_mock=conn)
        code, data = sent[0]
        assert code == 200
        assert data["error_status"] == 503
        assert data["error"] == "dial_unavailable"

    # 12c. GET target 504 → transport 200, error_status 504
    def test_get_target_504_tunneled(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = _conn_success(body=b'{"ok":false}', status=504)
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting):
            sent = self._call_proxy_get("uuid", conn_mock=conn)
        code, data = sent[0]
        assert code == 200
        assert data["error_status"] == 504
        assert data["error"] == "dial_timeout"

    # 13. target-provided error_status cannot spoof the normalized value
    def test_target_error_status_cannot_spoof(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = _conn_success(body=b'{"ok":false,"error_status":200}', status=502)
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting):
            sent = self._call_proxy_get("uuid", conn_mock=conn)
        code, data = sent[0]
        assert code == 200
        assert data["error_status"] == 502  # must be actual target status, not spoofed 200

    # 14a. target 3xx with HTML body rejected as dial_bad_response
    def test_3xx_html_body_tunneled_502_bad_response(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = _conn_success(body=b"<html>redirect</html>", status=302)
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting):
            sent = self._call_proxy_get("uuid", conn_mock=conn)
        code, data = sent[0]
        assert code == 200
        assert data["error"] == "dial_bad_response"
        assert data["error_status"] == 502

    # 14b. target 3xx with valid JSON body rejected before pass-through
    def test_3xx_json_body_still_tunneled_502_bad_response(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = _conn_success(body=b'{"ok":true}', status=301)
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting):
            sent = self._call_proxy_get("uuid", conn_mock=conn)
        code, data = sent[0]
        assert code == 200
        assert data["error"] == "dial_bad_response"
        assert data["error_status"] == 502

    # 15. success passes through transport 200 with original JSON object
    def test_success_passes_response_body(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = _conn_success(body=b'{"ok":true,"name":"Test","step_percent":3}')
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting):
            sent = self._call_proxy_get("uuid", conn_mock=conn)
        code, data = sent[0]
        assert code == 200
        assert data["name"] == "Test"
        assert data["step_percent"] == 3

    # 16. connection closes on success and every failure path (tested in TestProxyCallConnectionClosure)

    def test_correct_path_forwarded(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = _conn_success()
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting), \
             patch("autostream_webui_dials.send_json"), \
             patch("autostream_webui_api.send_json"), \
             patch("autostream_webui_dials.http.client.HTTPConnection", return_value=conn):
            _proxy_get(MagicMock(), "uuid", "/recovery_status")
        called_path = conn.request.call_args[0][1]
        assert called_path == "/recovery_status"


# ---------------------------------------------------------------------------
# _proxy_post: full browser-facing contract (GET/POST symmetry)
# ---------------------------------------------------------------------------

class TestProxyPostContracts:
    def _call_proxy_post(self, uuid: str, body_dict=None, conn_mock=None,
                         dial_path="/configure") -> list:
        def run():
            if conn_mock is not None:
                with patch("autostream_webui_dials.http.client.HTTPConnection",
                           return_value=conn_mock):
                    _proxy_post(MagicMock(), uuid, dial_path, body_dict)
            else:
                _proxy_post(MagicMock(), uuid, dial_path, body_dict)

        return _capture_sent(run)

    # 1. unknown UUID → tunneled 404 dial_offline
    def test_dial_offline_tunneled(self):
        with patch("autostream_webui_dials.get_dial_sighting", return_value=None):
            sent = self._call_proxy_post("unknown")
        code, data = sent[0]
        assert code == 200
        assert data["error"] == "dial_offline"
        assert data["error_status"] == 404

    # connection refusal → transport 200, dial_unreachable, error_status 502
    def test_oserror_tunneled_502(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = MagicMock()
        conn.request.side_effect = OSError("timeout")
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting):
            sent = self._call_proxy_post("uuid", body_dict={"x": 1}, conn_mock=conn)
        code, data = sent[0]
        assert code == 200
        assert data["error"] == "dial_unreachable"
        assert data["error_status"] == 502

    # 17a. POST target 502 → transport 200, error_status 502
    def test_post_target_502_tunneled(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = _conn_success(body=b'{"ok":false}', status=502)
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting):
            sent = self._call_proxy_post("uuid", conn_mock=conn)
        code, data = sent[0]
        assert code == 200
        assert data["error_status"] == 502

    # 17b. POST target 503 → transport 200, error_status 503
    def test_post_target_503_tunneled(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = _conn_success(body=b'{"ok":false}', status=503)
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting):
            sent = self._call_proxy_post("uuid", conn_mock=conn)
        code, data = sent[0]
        assert code == 200
        assert data["error_status"] == 503

    # 17c. POST target 504 → transport 200, error_status 504
    def test_post_target_504_tunneled(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = _conn_success(body=b'{"ok":false}', status=504)
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting):
            sent = self._call_proxy_post("uuid", conn_mock=conn)
        code, data = sent[0]
        assert code == 200
        assert data["error_status"] == 504

    # 18. POST target error body: endpoint-specific fields retained, reserved fields not spoofable
    def test_post_target_502_endpoint_fields_retained(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = _conn_success(
            body=b'{"ok":false,"error":"upstream_error","detail":"some context","error_status":999}',
            status=502,
        )
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting):
            sent = self._call_proxy_post("uuid", conn_mock=conn)
        code, data = sent[0]
        assert code == 200
        assert data["error_status"] == 502       # spoofed 999 must not win
        assert data["ok"] is False               # ok must remain false
        assert data.get("detail") == "some context"  # endpoint field retained

    # 19. GET and POST obey the same contract
    def test_get_and_post_same_contract_for_offline(self):
        """Offline UUID produces the same tunneled error for GET and POST."""
        from autostream_webui_dials import _proxy_get
        sent_get = _capture_sent(
            lambda: _proxy_get(MagicMock(), "unknown", "/configure"),
        )
        sent_post = _capture_sent(
            lambda: _proxy_post(MagicMock(), "unknown", "/configure", None),
        )
        # Both captured via the patched send_json
        # They both go through get_dial_sighting → None path, but
        # the patches need to be active. Let's test with patches.
        def run_get():
            with patch("autostream_webui_dials.get_dial_sighting", return_value=None):
                _proxy_get(MagicMock(), "unknown", "/configure")

        def run_post():
            with patch("autostream_webui_dials.get_dial_sighting", return_value=None):
                _proxy_post(MagicMock(), "unknown", "/configure", None)

        sg = _capture_sent(run_get)
        sp = _capture_sent(run_post)
        assert sg[0] == sp[0]  # same transport code and body

    def test_body_forwarded_to_dial(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = _conn_success()
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting), \
             patch("autostream_webui_dials.send_json"), \
             patch("autostream_webui_api.send_json"), \
             patch("autostream_webui_dials.http.client.HTTPConnection", return_value=conn):
            _proxy_post(MagicMock(), "uuid", "/configure", {"name": "Test"})

        _, call_kwargs = conn.request.call_args
        sent_body = json.loads(call_kwargs["body"])
        assert sent_body["name"] == "Test"

    def test_none_body_sends_no_body(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = _conn_success()
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting), \
             patch("autostream_webui_dials.send_json"), \
             patch("autostream_webui_api.send_json"), \
             patch("autostream_webui_dials.http.client.HTTPConnection", return_value=conn):
            _proxy_post(MagicMock(), "uuid", "/update", None)

        _, call_kwargs = conn.request.call_args
        assert call_kwargs["body"] is None


# ---------------------------------------------------------------------------
# Authorize / revoke handler validation
# ---------------------------------------------------------------------------

class TestHandleDialAuthorize:
    def _call(self, body: dict) -> tuple:
        sent = []

        def fake_send_json(handler, status, data):
            sent.append((status, data))

        with patch("autostream_webui_dials.send_json", side_effect=fake_send_json), \
             patch("autostream_webui_dials.write_dial_entry"):
            handle_dial_authorize_post(MagicMock(), body)

        return sent[0] if sent else (None, {})

    def test_missing_uuid_returns_400(self):
        status, data = self._call({"name": "Test"})
        assert status == 400
        assert data["error"] == "missing_uuid"

    def test_empty_uuid_returns_400(self):
        status, data = self._call({"uuid": "", "name": "Test"})
        assert status == 400
        assert data["error"] == "missing_uuid"

    def test_missing_name_returns_400(self):
        status, data = self._call({"uuid": "abc"})
        assert status == 400
        assert data["error"] == "missing_name"

    def test_invalid_name_pipe_returns_400(self):
        status, data = self._call({"uuid": "abc", "name": "bad|name"})
        assert status == 400
        assert data["error"] == "invalid_name"

    def test_invalid_name_semicolon_returns_400(self):
        status, data = self._call({"uuid": "abc", "name": "a;b"})
        assert status == 400
        assert data["error"] == "invalid_name"

    def test_non_string_uuid_returns_400(self):
        status, data = self._call({"uuid": 42, "name": "Test"})
        assert status == 400
        assert data["error"] == "missing_uuid"

    def test_valid_authorize_returns_200(self):
        status, data = self._call({"uuid": "abc", "name": "Valid Name"})
        assert status == 200
        assert data["ok"] is True

    def test_valid_authorize_calls_write_dial_entry(self):
        with patch("autostream_webui_dials.send_json"), \
             patch("autostream_webui_dials.write_dial_entry") as mock_write:
            handle_dial_authorize_post(MagicMock(), {"uuid": "x", "name": "Test"})
        mock_write.assert_called_once_with("x", "Test")


class TestHandleDialRevoke:
    def _call(self, body: dict) -> tuple:
        sent = []

        def fake_send_json(handler, status, data):
            sent.append((status, data))

        with patch("autostream_webui_dials.send_json", side_effect=fake_send_json), \
             patch("autostream_webui_dials.remove_dial_entry"):
            handle_dial_revoke_post(MagicMock(), body)

        return sent[0] if sent else (None, {})

    def test_missing_uuid_returns_400(self):
        status, data = self._call({})
        assert status == 400
        assert data["error"] == "missing_uuid"

    def test_empty_uuid_returns_400(self):
        status, data = self._call({"uuid": ""})
        assert status == 400
        assert data["error"] == "missing_uuid"

    def test_valid_revoke_returns_200(self):
        status, data = self._call({"uuid": "valid-uuid"})
        assert status == 200
        assert data["ok"] is True

    def test_revoke_calls_remove_dial_entry(self):
        with patch("autostream_webui_dials.send_json"), \
             patch("autostream_webui_dials.remove_dial_entry") as mock_remove:
            handle_dial_revoke_post(MagicMock(), {"uuid": "my-uuid"})
        mock_remove.assert_called_once_with("my-uuid")


# ---------------------------------------------------------------------------
# Management dispatcher fallback
# ---------------------------------------------------------------------------

class TestManagementDispatcherFallback:
    def _call_dispatch(self, path: str) -> tuple:
        sent = []

        def fake_send_json(h, code, data):
            sent.append((code, data))

        with patch("autostream_webui_dials.send_json", side_effect=fake_send_json), \
             patch("autostream_webui_api.send_json", side_effect=fake_send_json):
            dispatch_dial_management_post(MagicMock(), path, {})

        return sent[0] if sent else (None, {})

    def test_unknown_management_path_tunneled_404(self):
        code, data = self._call_dispatch("/api/dial/nonexistent")
        assert code == 200
        assert data["error"] == "not_found"
        assert data["error_status"] == 404

    def test_unknown_management_path_ok_is_false(self):
        _, data = self._call_dispatch("/api/dial/mystery")
        assert data["ok"] is False

    def test_known_paths_do_not_fall_to_dispatcher_fallback(self):
        """Known paths route to handlers, not the fallback."""
        sent = []

        def fake_send_json(h, code, data):
            sent.append((code, data))

        with patch("autostream_webui_dials.send_json", side_effect=fake_send_json), \
             patch("autostream_webui_api.send_json", side_effect=fake_send_json), \
             patch("autostream_webui_dials.write_dial_entry"):
            dispatch_dial_management_post(
                MagicMock(), "/api/dial/authorize", {"uuid": "x", "name": "Y"}
            )

        code, data = sent[0]
        assert code == 200
        assert data.get("ok") is True  # success, not not_found
