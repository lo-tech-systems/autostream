"""test_appliance_failure_recovery.py — the bound appliance's own id on a
remote page path redirects to the page it names here:
/a/<bound-id>/equaliser → /equaliser and /a/<bound-id>/ → /.
"""
from __future__ import annotations

import io
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

try:
    from webui.server import ConfigWebHandler
    _HAS_WEBUI = True
except ImportError:
    _HAS_WEBUI = False

from autostream_auth import AuthManager, PIN_STATUS_MISSING

_skip = pytest.mark.skipif(
    not _HAS_WEBUI, reason="web server import chain unavailable"
)

_REMOTE_ID = "aabbccdd1122334455aa"
_LOCAL_ID  = "00000000000000000000"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_auth(pin=None):
    mgr = AuthManager(config_path="dummy.ini")
    mgr._pin_loaded = True
    if pin is not None:
        mgr._pin_value = pin
        mgr._pin_status = "ok"
    else:
        mgr._pin_value = None
        mgr._pin_status = PIN_STATUS_MISSING
    return mgr


def _make_get(path: str) -> "ConfigWebHandler":
    h = ConfigWebHandler.__new__(ConfigWebHandler)
    h.path = path
    h.command = "GET"
    h.request_version = "HTTP/1.1"
    h.headers = {"Cookie": "", "X-Forwarded-For": "", "X-Real-IP": ""}
    h.client_address = ("127.0.0.1", 0)
    h.rfile = io.BytesIO(b"")
    h.wfile = io.BytesIO()
    h.send_response = MagicMock()
    h.send_header = MagicMock()
    h.end_headers = MagicMock()
    h.send_error = MagicMock()
    h._pending_auth_cookie = None
    h._pending_set_cookies = []
    return h


# ---------------------------------------------------------------------------
# Canonical equaliser redirect
# ---------------------------------------------------------------------------

@_skip
class TestCanonicalEqualiserRedirect:
    """Bound appliance ID on /a/<id>/equaliser must redirect to /equaliser."""

    def test_bound_id_on_equaliser_redirects_to_equaliser(self):
        mgr = _make_auth(pin=None)
        handler = _make_get(f"/a/{_LOCAL_ID}/equaliser")
        locations = []
        handler.send_header = MagicMock(side_effect=lambda k, v: locations.append((k, v)))
        handler.send_response = MagicMock()
        with patch("webui.session_state.AUTH", mgr), \
             patch("webui.session_state.STATE", MagicMock()), \
             patch("autostream_commissioning.is_commissioning_required", return_value=False), \
             patch("autostream_appliance_identity.get_appliance_id", return_value=_LOCAL_ID):
            handler.do_GET()
        assert any(v == "/equaliser" for k, v in locations if k == "Location")

    def test_bound_id_on_home_redirects_to_root(self):
        mgr = _make_auth(pin=None)
        handler = _make_get(f"/a/{_LOCAL_ID}/")
        locations = []
        handler.send_header = MagicMock(side_effect=lambda k, v: locations.append((k, v)))
        handler.send_response = MagicMock()
        with patch("webui.session_state.AUTH", mgr), \
             patch("webui.session_state.STATE", MagicMock()), \
             patch("autostream_commissioning.is_commissioning_required", return_value=False), \
             patch("autostream_appliance_identity.get_appliance_id", return_value=_LOCAL_ID):
            handler.do_GET()
        assert any(v == "/" for k, v in locations if k == "Location")
