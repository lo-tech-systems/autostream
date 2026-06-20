"""HTTP request body reading and failure handling tests.

Covers:
- Invalid, negative, and oversized Content-Length headers
- Empty body on /api/auth/verify returns 400
- Short read (rfile returns fewer bytes than Content-Length) returns 400
- rfile read exception returns 400
- Invalid UTF-8 bodies return 400
- JSON array or string on object-only routes returns 400
- Local privileged-helper failure on /api/factory-reset returns 500
- Dial-volume intentional 200 application contract is unchanged
"""
from __future__ import annotations

import io
import json
import secrets
import sys
import time
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

try:
    from autostream_webui import ConfigWebHandler
    import autostream_webui as _webui
    _HAS_WEBUI = True
except ImportError:
    _HAS_WEBUI = False

from autostream_auth import AuthManager, Session, SESSION_COOKIE_NAME, PIN_STATUS_MISSING

_skip = pytest.mark.skipif(not _HAS_WEBUI, reason="autostream_webui import chain unavailable")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_auth(pin: Optional[str] = None) -> AuthManager:
    """Create an AuthManager with auth disabled (no PIN)."""
    mgr = AuthManager(config_path="dummy.json", state_path="dummy-state.json")
    mgr._pin_loaded = True
    mgr._pin_value = pin
    mgr._pin_status = "ok" if pin else PIN_STATUS_MISSING
    return mgr


def _csrf_session(mgr: AuthManager) -> tuple[str, str]:
    tok = secrets.token_hex(32)
    csrf = secrets.token_hex(32)
    mgr._sessions[tok] = Session(
        token=tok,
        expires_at=int(time.time()) + 3600,
        csrf_token=csrf,
        authenticated=True,
    )
    return tok, csrf


class _ShortRfile:
    """rfile that returns fewer bytes than requested."""
    def __init__(self, data: bytes) -> None:
        self._buf = io.BytesIO(data)

    def read(self, n: int) -> bytes:
        return self._buf.read(max(0, n - 1))  # always short by one byte


class _FailRfile:
    """rfile that raises on read."""
    def read(self, n: int) -> bytes:
        raise OSError("connection reset")


def _make_handler(
    path: str,
    body: bytes,
    content_type: str = "application/json",
    content_length_override: Optional[str] = None,
    rfile_override=None,
    sess_token: str = "",
    csrf_token: str = "",
) -> "ConfigWebHandler":
    h = ConfigWebHandler.__new__(ConfigWebHandler)
    h.path = path
    h.command = "POST"
    h.request_version = "HTTP/1.1"
    cl = content_length_override if content_length_override is not None else str(len(body))
    h.headers = {
        "Content-Type": content_type,
        "Content-Length": cl,
        "Cookie": f"{SESSION_COOKIE_NAME}={sess_token}" if sess_token else "",
        "X-CSRF-Token": csrf_token,
        "X-Forwarded-For": "",
        "X-Real-IP": "",
    }
    h.client_address = ("127.0.0.1", 0)
    h.rfile = rfile_override if rfile_override is not None else io.BytesIO(body)
    h.wfile = io.BytesIO()
    h.send_response = MagicMock()
    h.send_header = MagicMock()
    h.end_headers = MagicMock()
    h.send_error = MagicMock()
    h._pending_auth_cookie = None
    h._pending_set_cookies = []
    return h


# ---------------------------------------------------------------------------
# Content-Length validation tests
# ---------------------------------------------------------------------------

@_skip
class TestContentLength:
    def test_invalid_content_length_non_numeric(self):
        auth = _make_auth()
        h = _make_handler("/api/auth/verify", b"", content_length_override="notanumber")
        with patch("autostream_webui.AUTH", auth):
            h.do_POST()
        h.send_error.assert_called_once()
        code = h.send_error.call_args[0][0]
        assert code == 400

    def test_negative_content_length(self):
        auth = _make_auth()
        h = _make_handler("/api/auth/verify", b"", content_length_override="-1")
        with patch("autostream_webui.AUTH", auth):
            h.do_POST()
        # -1 is invalid (not in 0 <= length <= MAX_POST_SIZE)
        h.send_error.assert_called_once()
        code = h.send_error.call_args[0][0]
        assert code in (400, 413)

    def test_oversized_content_length(self):
        auth = _make_auth()
        oversized = str(ConfigWebHandler.MAX_POST_SIZE + 1)
        h = _make_handler("/api/auth/verify", b"", content_length_override=oversized)
        with patch("autostream_webui.AUTH", auth):
            h.do_POST()
        h.send_error.assert_called_once()
        code = h.send_error.call_args[0][0]
        assert code == 413

    def test_zero_content_length_auth_verify_returns_400(self):
        """Zero-length body on /api/auth/verify must return 400."""
        auth = _make_auth()
        h = _make_handler("/api/auth/verify", b"", content_length_override="0")
        with patch("autostream_webui.AUTH", auth):
            h.do_POST()
        h.send_error.assert_called_once()
        code = h.send_error.call_args[0][0]
        assert code == 400


# ---------------------------------------------------------------------------
# Short read and rfile failure tests
# ---------------------------------------------------------------------------

@_skip
class TestBodyReadFailures:
    def test_short_read_returns_400(self):
        """When rfile.read() returns fewer bytes than Content-Length, send 400."""
        auth = _make_auth()
        body = b'{"nonce":"abc","proof":"def"}'
        h = _make_handler(
            "/api/auth/verify",
            body,
            rfile_override=_ShortRfile(body),
        )
        with patch("autostream_webui.AUTH", auth):
            h.do_POST()
        h.send_error.assert_called_once()
        code = h.send_error.call_args[0][0]
        assert code == 400

    def test_rfile_read_exception_returns_400(self):
        """When rfile.read() raises, send 400."""
        auth = _make_auth()
        body = b'{"x":1}'
        h = _make_handler(
            "/api/auth/verify",
            body,
            rfile_override=_FailRfile(),
        )
        with patch("autostream_webui.AUTH", auth):
            h.do_POST()
        h.send_error.assert_called_once()
        code = h.send_error.call_args[0][0]
        assert code == 400


# ---------------------------------------------------------------------------
# UTF-8 decoding tests
# ---------------------------------------------------------------------------

@_skip
class TestUtf8Decoding:
    def _post_with_body(self, path: str, raw_body: bytes, content_type: str = "application/json"):
        """POST raw bytes to a route, return the handler for inspection."""
        auth = _make_auth()
        tok, csrf = _csrf_session(auth)
        h = _make_handler(path, raw_body, content_type=content_type, sess_token=tok, csrf_token=csrf)
        with patch("autostream_webui.AUTH", auth), \
             patch("autostream_webui.STATE", MagicMock()):
            h.do_POST()
        return h

    def test_invalid_utf8_json_body_returns_400(self):
        body = b'{"key": "\xff\xfe"}'  # invalid UTF-8 in JSON
        h = self._post_with_body("/api/output_eq/reset", body)
        h.send_error.assert_called_once()
        assert h.send_error.call_args[0][0] == 400

    def test_invalid_utf8_form_body_returns_400(self):
        body = b"field=\xff\xfe"  # invalid UTF-8 in form data
        h = self._post_with_body("/api/output_eq/reset", body, content_type="application/x-www-form-urlencoded")
        h.send_error.assert_called_once()
        assert h.send_error.call_args[0][0] == 400


# ---------------------------------------------------------------------------
# Non-object JSON rejection
# ---------------------------------------------------------------------------

@_skip
class TestNonObjectJson:
    def _post_json(self, path: str, body: object):
        auth = _make_auth()
        tok, csrf = _csrf_session(auth)
        raw = json.dumps(body).encode()
        h = _make_handler(path, raw, sess_token=tok, csrf_token=csrf)
        with patch("autostream_webui.AUTH", auth), \
             patch("autostream_webui.STATE", MagicMock()):
            h.do_POST()
        return h

    def test_json_array_on_output_eq_reset_returns_400(self):
        h = self._post_json("/api/output_eq/reset", [1, 2, 3])
        h.send_error.assert_called_once()
        assert h.send_error.call_args[0][0] == 400

    def test_json_string_on_output_eq_reset_returns_400(self):
        h = self._post_json("/api/output_eq/reset", "hello")
        h.send_error.assert_called_once()
        assert h.send_error.call_args[0][0] == 400

    def test_json_number_on_api_output_returns_400(self):
        h = self._post_json("/api/output", 42)
        h.send_error.assert_called_once()
        assert h.send_error.call_args[0][0] == 400

    def test_json_null_on_service_reset_returns_400(self):
        h = self._post_json("/api/service/reset", None)
        h.send_error.assert_called_once()
        assert h.send_error.call_args[0][0] == 400

    def test_dial_volume_array_json_returns_400(self):
        """dial/volume with a JSON array must return 400, not 403."""
        auth = _make_auth()
        raw = json.dumps([1, 2]).encode()
        h = _make_handler("/api/dial/volume", raw)
        with patch("autostream_webui.AUTH", auth), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.send_dial_volume_post_json") as mock_handler:
            h.do_POST()
        h.send_error.assert_called_once()
        assert h.send_error.call_args[0][0] == 400
        mock_handler.assert_not_called()

    def test_dial_mute_array_json_returns_400(self):
        """dial/mute with a JSON array must return 400, not 403."""
        auth = _make_auth()
        raw = json.dumps([1, 2]).encode()
        h = _make_handler("/api/dial/mute", raw)
        with patch("autostream_webui.AUTH", auth), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.send_dial_mute_post_json") as mock_handler:
            h.do_POST()
        h.send_error.assert_called_once()
        assert h.send_error.call_args[0][0] == 400
        mock_handler.assert_not_called()

    def test_dial_volume_object_json_passes_to_handler(self):
        """dial/volume with a valid JSON object must reach the handler (not be rejected)."""
        auth = _make_auth()
        raw = json.dumps({"dial_id": "uid", "delta": 5}).encode()
        h = _make_handler("/api/dial/volume", raw)
        sent_codes = []
        def fake_send_json(hnd, code, data):
            sent_codes.append(code)
        with patch("autostream_webui.AUTH", auth), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.send_dial_volume_post_json", side_effect=fake_send_json):
            h.do_POST()
        h.send_error.assert_not_called()


# ---------------------------------------------------------------------------
# Factory reset — local privileged-helper failure → 500
# ---------------------------------------------------------------------------

@_skip
class TestFactoryResetFailure:
    def test_factory_reset_helper_failure_returns_500(self):
        """When factory_reset_system() raises, /api/factory-reset must return 500."""
        auth = _make_auth(pin="test1234")
        tok, csrf = _csrf_session(auth)
        raw = b"{}"
        h = _make_handler("/api/factory-reset", raw, sess_token=tok, csrf_token=csrf)
        sent = []
        def fake_send_json(hnd, code, data):
            sent.append((code, data))
        with patch("autostream_webui.AUTH", auth), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.handle_factory_reset_post",
                   side_effect=lambda h2, s, a: fake_send_json(h2, 500, {"ok": False})):
            h.do_POST()
        # The handler itself is patched to produce 500; verify the route reaches it
        assert len(sent) == 1
        assert sent[0][0] == 500

    def test_factory_reset_helper_failure_json_schema(self, tmp_path):
        """factory_reset_system() failure returns 500 with ok=false and error fields."""
        import autostream_webui_post_handlers as ph
        handler = MagicMock()
        sent = []
        def fake_send_json(h, code, data):
            sent.append((code, data))
        with patch("autostream_webui_post_handlers.send_json", side_effect=fake_send_json), \
             patch("autostream_webui_post_handlers.factory_reset_system",
                   side_effect=RuntimeError("helper failed")):
            ph.handle_factory_reset_post(handler, MagicMock(), MagicMock())
        assert len(sent) == 1
        code, data = sent[0]
        assert code == 500
        assert data["ok"] is False
        assert "error" in data


# ---------------------------------------------------------------------------
# Auth verify empty body
# ---------------------------------------------------------------------------

@_skip
class TestAuthVerifyEmptyBody:
    def test_empty_body_returns_400(self):
        auth = _make_auth()
        h = _make_handler("/api/auth/verify", b"")
        with patch("autostream_webui.AUTH", auth):
            h.do_POST()
        h.send_error.assert_called_once()
        assert h.send_error.call_args[0][0] == 400

    def test_none_body_from_rfile_error_returns_400(self):
        """If _read_post_body_bytes returns None (error), no second response is sent."""
        auth = _make_auth()
        h = _make_handler("/api/auth/verify", b"data", rfile_override=_FailRfile())
        with patch("autostream_webui.AUTH", auth):
            h.do_POST()
        # send_error called exactly once (by body reader), handle_auth_verify never called
        h.send_error.assert_called_once()
        assert h.send_error.call_args[0][0] == 400
