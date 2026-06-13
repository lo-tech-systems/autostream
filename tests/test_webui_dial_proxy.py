"""Regression tests for dial proxy connection cleanup.

Verifies that _proxy_call() always closes its HTTPConnection regardless of
whether the request, response, or JSON decode step raises an exception.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

from autostream_webui_dials import _proxy_call


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
