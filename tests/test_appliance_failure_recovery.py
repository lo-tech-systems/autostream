"""test_appliance_failure_recovery.py — tests for appliance failure recovery.

Covers:
  - Flash message strings embedded in remote Home and Equaliser pages
  - Definitive error codes handled in JS (not_found, unconfigured, etc.)
  - Transport failure threshold (3 strikes → redirect)
  - backoff excluded from failure count
  - Independent Home and Equaliser counters
  - ?msg= parsing supports error: prefix on the landing page
  - Canonical redirect from /a/<bound-id>/equaliser → /equaliser
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
    from autostream_webui import ConfigWebHandler
    import autostream_webui as _webui
    _HAS_WEBUI = True
except ImportError:
    _HAS_WEBUI = False

from autostream_auth import AuthManager, PIN_STATUS_MISSING

_skip = pytest.mark.skipif(
    not _HAS_WEBUI, reason="autostream_webui import chain unavailable"
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


def _render_remote_home(aid: str = _REMOTE_ID) -> str:
    from autostream_webui_page_airplay import send_remote_home_page
    state = MagicMock()
    state.config_path = "dummy.ini"
    handler = MagicMock()
    chunks = []
    handler.wfile.write = lambda d: chunks.append(d)
    handler._csrf_token = "csrf"
    handler._pending_set_cookies = []
    parsed = MagicMock()
    parsed.owntone.volume_percent = 20
    parsed.webui.dark_mode = False
    with patch("autostream_webui_page_airplay._config_snapshot", return_value=parsed), \
         patch("autostream_webui_page_airplay.get_appliance_id", return_value=_LOCAL_ID), \
         patch("autostream_webui_page_airplay.get_all_appliances", return_value=[]), \
         patch("autostream_webui_page_airplay.get_system_hostname", return_value="bound"):
        send_remote_home_page(handler, state, aid)
    return b"".join(chunks).decode("utf-8", errors="replace")


def _render_remote_equaliser(aid: str = _REMOTE_ID) -> str:
    from autostream_webui_page_equaliser import send_remote_equaliser_page
    state = MagicMock()
    state.config_path = "dummy.ini"
    handler = MagicMock()
    chunks = []
    handler.wfile.write = lambda d: chunks.append(d)
    handler._csrf_token = "csrf"
    handler._pending_set_cookies = []
    parsed = MagicMock()
    parsed.webui.dark_mode = False
    with patch("autostream_webui_page_equaliser._config_snapshot", return_value=parsed), \
         patch("autostream_webui_page_equaliser.get_appliance_id", return_value=_LOCAL_ID), \
         patch("autostream_webui_page_equaliser.get_all_appliances", return_value=[]), \
         patch("autostream_webui_page_equaliser.get_system_hostname", return_value="bound"):
        send_remote_equaliser_page(handler, state, aid)
    return b"".join(chunks).decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Flash message strings — remote Home
# ---------------------------------------------------------------------------

@_skip
class TestRemoteHomeFlashMessages:
    """Exact failure flash message strings must appear in the remote Home page JS."""

    def test_transport_failure_redirect_message(self):
        html = _render_remote_home()
        assert "is unavailable. Returned to this appliance." in html

    def test_not_found_message(self):
        html = _render_remote_home()
        assert "The selected appliance address is invalid. Returned to this appliance." in html

    def test_unconfigured_message(self):
        html = _render_remote_home()
        assert "is not ready for remote control. Returned to this appliance." in html

    def test_conflicted_message(self):
        html = _render_remote_home()
        assert "has a network identity conflict and cannot be selected safely. Returned to this appliance." in html

    def test_identity_unavailable_message(self):
        html = _render_remote_home()
        assert "cannot currently provide multi-appliance access. Returned to this appliance." in html

    def test_definitive_errors_list_in_js(self):
        html = _render_remote_home()
        for code in ("not_found", "appliance_unconfigured", "appliance_conflicted",
                     "appliance_identity_unavailable"):
            assert code in html, f"Expected definitive error code {code!r} in remote Home JS"

    def test_transport_errors_list_in_js(self):
        html = _render_remote_home()
        for code in ("remote_timeout", "remote_bad_response", "appliance_offline"):
            assert code in html, f"Expected transport error code {code!r} in remote Home JS"

    def test_backoff_not_in_transport_errors(self):
        """remote_backoff must NOT trigger the failure counter."""
        html = _render_remote_home()
        # remote_backoff is only referenced in the backoff check (not in __TRANSPORT_ERRORS)
        assert "remote_backoff" not in html or "__TRANSPORT_ERRORS" not in html.split("remote_backoff")[0][-200:]


# ---------------------------------------------------------------------------
# Flash message strings — remote Equaliser
# ---------------------------------------------------------------------------

@_skip
class TestRemoteEqualiserFlashMessages:
    """Exact failure flash message strings must appear in the remote Equaliser page JS."""

    def test_transport_failure_redirect_message(self):
        html = _render_remote_equaliser()
        assert "is unavailable. Returned to this appliance." in html

    def test_not_found_message(self):
        html = _render_remote_equaliser()
        assert "The selected appliance address is invalid. Returned to this appliance." in html

    def test_unconfigured_message(self):
        html = _render_remote_equaliser()
        assert "is not ready for remote control. Returned to this appliance." in html

    def test_conflicted_message(self):
        html = _render_remote_equaliser()
        assert "has a network identity conflict and cannot be selected safely. Returned to this appliance." in html

    def test_identity_unavailable_message(self):
        html = _render_remote_equaliser()
        assert "cannot currently provide multi-appliance access. Returned to this appliance." in html

    def test_definitive_errors_list_in_js(self):
        html = _render_remote_equaliser()
        for code in ("not_found", "appliance_unconfigured", "appliance_conflicted",
                     "appliance_identity_unavailable"):
            assert code in html, f"Expected definitive error code {code!r} in remote Equaliser JS"

    def test_degraded_mode_replaces_three_strike_redirect(self):
        html = _render_remote_equaliser()
        assert "_eqDegraded" in html
        assert "_EQ_DEGRADED_POLL_MS" in html
        assert "_eqFailCount>=3" not in html and "_eqFailCount >= 3" not in html

    def test_save_url_referenced_in_js(self):
        html = _render_remote_equaliser()
        assert "__SAVE_URL" in html

    def test_reset_url_referenced_in_js(self):
        html = _render_remote_equaliser()
        assert "__RESET_URL" in html

    def test_write_seq_for_field_supersession(self):
        """Per-field sequence counter must be present for write ordering."""
        html = _render_remote_equaliser()
        assert "_eqWriteSeq" in html


# ---------------------------------------------------------------------------
# Independent failure counters
# ---------------------------------------------------------------------------

@_skip
class TestIndependentFailureCounters:
    """Home and Equaliser pages have independent failure state variables."""

    def test_home_uses_remote_fail_count(self):
        html = _render_remote_home()
        assert "__remoteFailCount" in html

    def test_equaliser_uses_degraded_flag(self):
        html = _render_remote_equaliser()
        assert "_eqDegraded" in html

    def test_home_counter_not_in_equaliser(self):
        """The Equaliser page must not reference the Home page counter."""
        html = _render_remote_equaliser()
        assert "__remoteFailCount" not in html

    def test_home_page_no_eq_degraded(self):
        """The Home page must not reference the Equaliser degraded flag."""
        html = _render_remote_home()
        assert "_eqDegraded" not in html


# ---------------------------------------------------------------------------
# ?msg= prefix parsing on the landing page
# ---------------------------------------------------------------------------

@_skip
class TestMsgPrefixParsing:
    """?msg=error:<text> on / must render an error-type banner, not success."""

    def _get_home_with_msg(self, msg: str) -> str:
        mgr = _make_auth(pin=None)
        handler = _make_get(f"/?msg={msg}")
        chunks = []
        handler.wfile.write = lambda d: chunks.append(d)

        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.unconfigured", return_value=False), \
             patch("autostream_webui.send_airplay_page") as stub:
            handler.do_GET()
        if not stub.called:
            return ""
        kwargs = stub.call_args
        return kwargs[1].get("flash_type", kwargs[0][3] if len(kwargs[0]) > 3 else "")

    def test_error_prefix_yields_error_flash_type(self):
        import urllib.parse
        msg = urllib.parse.quote("error:Something went wrong")
        flash_type = self._get_home_with_msg(msg)
        assert flash_type == "error"

    def test_plain_msg_yields_success_flash_type(self):
        import urllib.parse
        msg = urllib.parse.quote("Settings saved")
        flash_type = self._get_home_with_msg(msg)
        assert flash_type == "success"

    def test_warning_prefix_yields_warning_flash_type(self):
        import urllib.parse
        msg = urllib.parse.quote("warning:Check your settings")
        flash_type = self._get_home_with_msg(msg)
        assert flash_type == "warning"


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
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.unconfigured", return_value=False), \
             patch("autostream_webui.get_appliance_id", return_value=_LOCAL_ID):
            handler.do_GET()
        assert any(v == "/equaliser" for k, v in locations if k == "Location")

    def test_bound_id_on_home_redirects_to_root(self):
        mgr = _make_auth(pin=None)
        handler = _make_get(f"/a/{_LOCAL_ID}/")
        locations = []
        handler.send_header = MagicMock(side_effect=lambda k, v: locations.append((k, v)))
        handler.send_response = MagicMock()
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.unconfigured", return_value=False), \
             patch("autostream_webui.get_appliance_id", return_value=_LOCAL_ID):
            handler.do_GET()
        assert any(v == "/" for k, v in locations if k == "Location")
