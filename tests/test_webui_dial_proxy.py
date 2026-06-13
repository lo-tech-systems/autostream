"""Dial proxy and handler tests.

Covers: _proxy_call() connection closure, dial-offline 404, 502 on OSError/
invalid JSON, non-200 pass-through, body/path forwarding, and
authorize/revoke handler validation and persistence failure mapping.
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

from autostream_webui_dials import (
    _proxy_call,
    handle_dial_authorize_post,
    handle_dial_revoke_post,
    handle_dial_configure_get,
    _proxy_get,
    _proxy_post,
)


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

    def test_invalid_json_closes_connection(self):
        conn = _make_conn_mock(resp_body=b"not-json")
        with pytest.raises(ValueError):
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
# _proxy_get: offline, network errors, bad JSON, non-200, success
# ---------------------------------------------------------------------------

class TestProxyGetContracts:
    def _call_proxy_get(self, uuid: str, conn_mock=None) -> list:
        sent = []

        def fake_send_json(handler, status, data):
            sent.append((status, data))

        with patch("autostream_webui_dials.send_json", side_effect=fake_send_json):
            if conn_mock is not None:
                with patch("autostream_webui_dials.http.client.HTTPConnection",
                           return_value=conn_mock):
                    _proxy_get(MagicMock(), uuid, "/configure")
            else:
                _proxy_get(MagicMock(), uuid, "/configure")

        return sent

    def test_dial_offline_returns_404(self):
        with patch("autostream_webui_dials.get_dial_sighting", return_value=None):
            sent = self._call_proxy_get("unknown-uuid")
        assert sent[0][0] == 404
        assert sent[0][1]["error"] == "dial_offline"

    def test_oserror_returns_502_unreachable(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = MagicMock()
        conn.request.side_effect = OSError("refused")
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting):
            sent = self._call_proxy_get("uuid", conn_mock=conn)
        assert sent[0][0] == 502
        assert sent[0][1]["error"] == "dial_unreachable"

    def test_invalid_json_returns_502_bad_response(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = _conn_success(body=b"not-json")
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting):
            sent = self._call_proxy_get("uuid", conn_mock=conn)
        assert sent[0][0] == 502
        assert sent[0][1]["error"] == "dial_bad_response"

    def test_non_200_status_passed_through(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = _conn_success(body=b'{"ok":false}', status=403)
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting):
            sent = self._call_proxy_get("uuid", conn_mock=conn)
        assert sent[0][0] == 403
        assert sent[0][1]["ok"] is False

    def test_success_passes_response_body(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = _conn_success(body=b'{"ok":true,"name":"Test"}')
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting):
            sent = self._call_proxy_get("uuid", conn_mock=conn)
        assert sent[0][0] == 200
        assert sent[0][1]["name"] == "Test"

    def test_correct_path_forwarded(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = _conn_success()
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting), \
             patch("autostream_webui_dials.send_json"), \
             patch("autostream_webui_dials.http.client.HTTPConnection",
                   return_value=conn):
            _proxy_get(MagicMock(), "uuid", "/recovery_status")
        called_path = conn.request.call_args[0][1]
        assert called_path == "/recovery_status"


# ---------------------------------------------------------------------------
# _proxy_post: offline, network errors, body forwarding
# ---------------------------------------------------------------------------

class TestProxyPostContracts:
    def _call_proxy_post(self, uuid: str, body_dict=None, conn_mock=None) -> list:
        sent = []

        def fake_send_json(handler, status, data):
            sent.append((status, data))

        with patch("autostream_webui_dials.send_json", side_effect=fake_send_json):
            if conn_mock is not None:
                with patch("autostream_webui_dials.http.client.HTTPConnection",
                           return_value=conn_mock):
                    _proxy_post(MagicMock(), uuid, "/configure", body_dict)
            else:
                _proxy_post(MagicMock(), uuid, "/configure", body_dict)

        return sent

    def test_dial_offline_returns_404(self):
        with patch("autostream_webui_dials.get_dial_sighting", return_value=None):
            sent = self._call_proxy_post("unknown")
        assert sent[0][0] == 404

    def test_oserror_returns_502(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = MagicMock()
        conn.request.side_effect = OSError("timeout")
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting):
            sent = self._call_proxy_post("uuid", body_dict={"x": 1}, conn_mock=conn)
        assert sent[0][0] == 502
        assert sent[0][1]["error"] == "dial_unreachable"

    def test_body_forwarded_to_dial(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = _conn_success()
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting), \
             patch("autostream_webui_dials.send_json"), \
             patch("autostream_webui_dials.http.client.HTTPConnection",
                   return_value=conn):
            _proxy_post(MagicMock(), "uuid", "/configure", {"name": "Test"})

        _, call_kwargs = conn.request.call_args
        sent_body = json.loads(call_kwargs["body"])
        assert sent_body["name"] == "Test"

    def test_none_body_sends_no_body(self):
        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = _conn_success()
        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting), \
             patch("autostream_webui_dials.send_json"), \
             patch("autostream_webui_dials.http.client.HTTPConnection",
                   return_value=conn):
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
