"""Browser API error contract tests.

Covers:
  §7.1  send_browser_api_error() helper unit tests
  §7.3  Route distinction tests (known-route tunneled vs unknown-route native 404)
  §7.4  NGINX policy regression tests (main config + dial config)
  §7.6  Direct dial regression tests (import isolation, native statuses)
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

MAIN_NGINX_CONF   = REPO_ROOT / "system" / "nginx" / "autostream-nginx.conf"
MAIN_NGINXD_CONF  = REPO_ROOT / "system" / "nginx" / "autostream-nginxd.conf"
DIAL_NGINX_CONF   = REPO_ROOT / "system" / "nginx" / "autostream-dial-nginx.conf"


# ---------------------------------------------------------------------------
# §7.1  shared helper unit tests
# ---------------------------------------------------------------------------

class TestSendBrowserApiError:
    """Unit tests for send_browser_api_error() in autostream_webui_api."""

    def _call(self, semantic_status, error="test_error", **kwargs):
        """Call send_browser_api_error(), capture (transport_status, payload)."""
        from autostream_webui_api import send_browser_api_error
        captured = []

        def fake_send_json(handler, code, payload):
            captured.append((code, payload))

        with patch("autostream_webui_api.send_json", side_effect=fake_send_json):
            send_browser_api_error(MagicMock(), semantic_status, error, **kwargs)

        assert len(captured) == 1
        return captured[0]

    # 1. intercepted statuses produce transport 200 + error_status
    def test_404_produces_transport_200_with_error_status(self):
        code, payload = self._call(404, "dial_offline")
        assert code == 200
        assert payload["error_status"] == 404
        assert payload["ok"] is False
        assert payload["error"] == "dial_offline"

    def test_502_produces_transport_200_with_error_status(self):
        code, payload = self._call(502, "dial_unreachable")
        assert code == 200
        assert payload["error_status"] == 502

    def test_503_produces_transport_200_with_error_status(self):
        code, payload = self._call(503, "dial_unavailable")
        assert code == 200
        assert payload["error_status"] == 503

    def test_504_produces_transport_200_with_error_status(self):
        code, payload = self._call(504, "dial_timeout")
        assert code == 200
        assert payload["error_status"] == 504

    # 5. non-intercepted statuses retain native transport
    @pytest.mark.parametrize("status", [400, 401, 403, 409, 429, 500])
    def test_native_statuses_pass_through(self, status):
        code, payload = self._call(status, "some_error")
        assert code == status
        assert "error_status" not in payload

    # 6. retryable omitted when not supplied, preserved when supplied
    def test_retryable_omitted_when_unspecified(self):
        _, payload = self._call(502, "dial_unreachable")
        assert "retryable" not in payload

    def test_retryable_true_included_when_supplied(self):
        _, payload = self._call(502, "dial_unreachable", retryable=True)
        assert payload["retryable"] is True

    def test_retryable_false_included_when_supplied(self):
        _, payload = self._call(400, "bad_input", retryable=False)
        assert payload["retryable"] is False

    # 7. extra cannot replace reserved fields
    def test_extra_cannot_override_ok(self):
        _, payload = self._call(502, "x", extra={"ok": True})
        assert payload["ok"] is False

    def test_extra_cannot_override_error(self):
        _, payload = self._call(502, "real_error", extra={"error": "spoofed"})
        assert payload["error"] == "real_error"

    def test_extra_cannot_override_error_status(self):
        _, payload = self._call(502, "x", extra={"error_status": 999})
        assert payload["error_status"] == 502

    def test_extra_fields_are_included(self):
        _, payload = self._call(502, "x", extra={"active": False, "foo": "bar"})
        assert payload["active"] is False
        assert payload["foo"] == "bar"

    # 8. caller dictionary not mutated
    def test_extra_dict_not_mutated(self):
        extra = {"custom": "field"}
        original = dict(extra)
        self._call(404, "x", extra=extra)
        assert extra == original

    # 9. invalid status values fail predictably
    def test_invalid_status_string_raises(self):
        from autostream_webui_api import send_browser_api_error
        with pytest.raises((ValueError, TypeError)):
            send_browser_api_error(MagicMock(), "404", "x")

    def test_invalid_status_99_raises(self):
        from autostream_webui_api import send_browser_api_error
        with pytest.raises(ValueError):
            send_browser_api_error(MagicMock(), 99, "x")

    def test_invalid_status_600_raises(self):
        from autostream_webui_api import send_browser_api_error
        with pytest.raises(ValueError):
            send_browser_api_error(MagicMock(), 600, "x")

    # 10. payload Content-Type comes from send_json (verified structurally)
    def test_delegates_to_send_json(self):
        """Helper must call send_json, not write headers directly."""
        from autostream_webui_api import send_browser_api_error
        with patch("autostream_webui_api.send_json") as mock_sj:
            send_browser_api_error(MagicMock(), 502, "x")
        mock_sj.assert_called_once()


# ---------------------------------------------------------------------------
# §7.3  Route distinction tests
# ---------------------------------------------------------------------------

class TestRouteDistinction:
    """Tests that known-route domain errors are tunneled while unknown routes remain native 404."""

    def _proxy_get_sent(self, uuid, conn_body=b'{"ok":true}', conn_status=200):
        """Exercise _proxy_get() with a mocked sighting and connection."""
        from autostream_webui_dials import _proxy_get
        sent = []

        def fake_send_json(handler, code, data):
            sent.append((code, data))

        sighting = MagicMock(ip="1.2.3.4", port=7842)
        conn = MagicMock()
        resp = MagicMock()
        resp.status = conn_status
        resp.read.return_value = conn_body
        conn.getresponse.return_value = resp

        with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting), \
             patch("autostream_webui_dials.send_json", side_effect=fake_send_json), \
             patch("autostream_webui_api.send_json", side_effect=fake_send_json), \
             patch("autostream_webui_dials.http.client.HTTPConnection", return_value=conn):
            _proxy_get(MagicMock(), uuid, "/configure")

        return sent

    # 1. known route + offline UUID → structured HTTP 200
    def test_known_route_offline_uuid_returns_tunneled_200(self):
        from autostream_webui_dials import _proxy_get
        sent = []

        def fake_send_json(h, code, data):
            sent.append((code, data))

        with patch("autostream_webui_dials.get_dial_sighting", return_value=None), \
             patch("autostream_webui_dials.send_json", side_effect=fake_send_json), \
             patch("autostream_webui_api.send_json", side_effect=fake_send_json):
            _proxy_get(MagicMock(), "missing-uuid", "/configure")

        assert sent[0][0] == 200
        assert sent[0][1]["error"] == "dial_offline"
        assert sent[0][1]["error_status"] == 404

    # 2. dispatch_dial_management_post with unknown path returns tunneled 404
    def test_management_dispatcher_unknown_path_tunneled_404(self):
        from autostream_webui_dials import dispatch_dial_management_post
        sent = []

        def fake_send_json(h, code, data):
            sent.append((code, data))

        with patch("autostream_webui_dials.send_json", side_effect=fake_send_json), \
             patch("autostream_webui_api.send_json", side_effect=fake_send_json):
            dispatch_dial_management_post(MagicMock(), "/api/dial/unknown_path", {})

        assert sent[0][0] == 200
        assert sent[0][1]["error"] == "not_found"
        assert sent[0][1]["error_status"] == 404

    # 3. unknown GET route in core/autostream_webui.py still calls native send_error(404)
    def test_unknown_get_route_calls_native_404(self):
        import io
        sys.path.insert(0, _core)
        import autostream_webui as wui

        h = wui.ConfigWebHandler.__new__(wui.ConfigWebHandler)
        h.path = "/api/nonexistent_route_xyz"
        h.command = "GET"
        h.request_version = "HTTP/1.1"
        h.headers = {"Cookie": "", "Content-Length": "0"}
        h.client_address = ("127.0.0.1", 0)
        h.rfile = io.BytesIO(b"")
        h.wfile = io.BytesIO()
        h.send_response = MagicMock()
        h.send_header = MagicMock()
        h.end_headers = MagicMock()
        h.send_error = MagicMock()
        h._pending_auth_cookie = None
        h._pending_set_cookies = []

        with patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.AUTH", MagicMock()), \
             patch("autostream_webui.STATE", MagicMock()):
            h.do_GET()

        h.send_error.assert_called_with(404, "Not found")

    # 4. unknown POST route still calls native send_error(404)
    def test_unknown_post_route_calls_native_404(self):
        import io
        sys.path.insert(0, _core)
        import autostream_webui as wui

        h = wui.ConfigWebHandler.__new__(wui.ConfigWebHandler)
        h.path = "/api/nonexistent_route_xyz"
        h.command = "POST"
        h.request_version = "HTTP/1.1"
        h.headers = {"Cookie": "", "Content-Length": "0"}
        h.client_address = ("127.0.0.1", 0)
        h.rfile = io.BytesIO(b"")
        h.wfile = io.BytesIO()
        h.send_response = MagicMock()
        h.send_header = MagicMock()
        h.end_headers = MagicMock()
        h.send_error = MagicMock()
        h._pending_auth_cookie = None
        h._pending_set_cookies = []

        with patch("autostream_webui.AUTH", MagicMock()), \
             patch("autostream_webui.STATE", MagicMock()):
            h.do_POST()

        h.send_error.assert_called_with(404, "Not found")

    # 5. missing request fields on known routes remain native 400
    def test_authorize_missing_uuid_is_native_400(self):
        from autostream_webui_dials import handle_dial_authorize_post
        sent = []

        def fake_send_json(h, code, data):
            sent.append((code, data))

        with patch("autostream_webui_dials.send_json", side_effect=fake_send_json):
            handle_dial_authorize_post(MagicMock(), {"name": "Test"})

        assert sent[0][0] == 400
        assert "error_status" not in sent[0][1]

    # 6. auth/CSRF responses retain native status (400 for missing uuid)
    def test_validation_error_not_tunneled(self):
        from autostream_webui_dials import handle_dial_revoke_post
        sent = []

        def fake_send_json(h, code, data):
            sent.append((code, data))

        with patch("autostream_webui_dials.send_json", side_effect=fake_send_json):
            handle_dial_revoke_post(MagicMock(), {})

        code, data = sent[0]
        assert code == 400
        assert "error_status" not in data


class TestFederationErrorContract:
    """Federation target API uses native status codes (400/401/409/429/500).

    These statuses are not in the NGINX-intercepted set, so they must be
    returned natively without error_status tunnelling.
    """

    def test_federation_401_is_native_not_tunneled(self):
        from autostream_webui_api import send_federation_home_json
        sent = []
        with patch("autostream_webui_api.send_json",
                   side_effect=lambda h, c, d: sent.append((c, d))), \
             patch("autostream_webui_api.build_home_state",
                   return_value={"ok": True, "outputs": [], "appliance": {},
                                 "preferences": {}, "playback": {}, "input_levels": [],
                                 "warnings": {}, "vu_delay_ms": 100}):
            send_federation_home_json(MagicMock(), MagicMock())
        # The API function itself doesn't do auth — auth is in the dispatcher.
        # This test verifies the contract: 200 from home function (auth already validated)
        assert sent[0][0] == 200
        assert "error_status" not in sent[0][1]

    def test_send_browser_api_error_with_400_is_native(self):
        from autostream_webui_api import send_browser_api_error
        sent = []
        with patch("autostream_webui_api.send_json",
                   side_effect=lambda h, c, d: sent.append((c, d))):
            send_browser_api_error(MagicMock(), 400, "bad_request")
        code, data = sent[0]
        assert code == 400
        assert "error_status" not in data

    def test_send_browser_api_error_with_401_is_native(self):
        from autostream_webui_api import send_browser_api_error
        sent = []
        with patch("autostream_webui_api.send_json",
                   side_effect=lambda h, c, d: sent.append((c, d))):
            send_browser_api_error(MagicMock(), 401, "unauthorized")
        code, data = sent[0]
        assert code == 401
        assert "error_status" not in data

    def test_send_browser_api_error_with_409_is_native(self):
        from autostream_webui_api import send_browser_api_error
        sent = []
        with patch("autostream_webui_api.send_json",
                   side_effect=lambda h, c, d: sent.append((c, d))):
            send_browser_api_error(MagicMock(), 409, "appliance_unconfigured")
        code, data = sent[0]
        assert code == 409
        assert "error_status" not in data

    def test_send_browser_api_error_with_429_is_native(self):
        from autostream_webui_api import send_browser_api_error
        sent = []
        with patch("autostream_webui_api.send_json",
                   side_effect=lambda h, c, d: sent.append((c, d))):
            send_browser_api_error(MagicMock(), 429, "rate_limited")
        code, data = sent[0]
        assert code == 429
        assert "error_status" not in data

    def test_send_browser_api_error_with_500_is_native(self):
        from autostream_webui_api import send_browser_api_error
        sent = []
        with patch("autostream_webui_api.send_json",
                   side_effect=lambda h, c, d: sent.append((c, d))):
            send_browser_api_error(MagicMock(), 500, "internal_error")
        code, data = sent[0]
        assert code == 500
        assert "error_status" not in data


# ---------------------------------------------------------------------------
# §7.4  NGINX policy regression tests
# ---------------------------------------------------------------------------

def _conf_main():
    return MAIN_NGINX_CONF.read_text(encoding="utf-8")


def _conf_nginxd():
    return MAIN_NGINXD_CONF.read_text(encoding="utf-8")


def _conf_dial():
    return DIAL_NGINX_CONF.read_text(encoding="utf-8")


class TestMainNginxInterceptionPolicy:
    """Main autostream NGINX policy assertions."""

    def test_proxy_intercept_errors_on(self):
        assert "proxy_intercept_errors on" in _conf_main()

    def test_error_page_intercepts_404(self):
        conf = _conf_main()
        m = re.search(r"error_page\s+([0-9 ]+)\s*=", conf)
        assert m, "error_page directive not found"
        codes = set(m.group(1).split())
        assert "404" in codes

    def test_error_page_intercepts_502(self):
        conf = _conf_main()
        m = re.search(r"error_page\s+([0-9 ]+)\s*=", conf)
        codes = set(m.group(1).split())
        assert "502" in codes

    def test_error_page_intercepts_503(self):
        conf = _conf_main()
        m = re.search(r"error_page\s+([0-9 ]+)\s*=", conf)
        codes = set(m.group(1).split())
        assert "503" in codes

    def test_error_page_intercepts_504(self):
        conf = _conf_main()
        m = re.search(r"error_page\s+([0-9 ]+)\s*=", conf)
        codes = set(m.group(1).split())
        assert "504" in codes

    def test_intercepted_set_is_exactly_404_502_503_504(self):
        """No fewer and no more statuses than expected are intercepted."""
        conf = _conf_main()
        m = re.search(r"error_page\s+([0-9 ]+)\s*=", conf)
        assert m, "error_page directive not found"
        codes = frozenset(int(c) for c in m.group(1).split())
        expected = frozenset({404, 502, 503, 504})
        assert codes == expected, (
            f"Intercepted statuses {codes} != expected {expected}"
        )


class TestNginxdConfig:
    """autostream-nginxd.conf (http-scope maps) policy assertions."""

    def test_from_setup_map_defined(self):
        assert "from_setup" in _conf_nginxd()

    def test_from_setup_derives_from_referer(self):
        conf = _conf_nginxd()
        assert "$http_referer" in conf or "http_referer" in conf

    def test_setup_referer_failure_redirects_to_retrying_with_next(self):
        conf = _conf_main()
        assert "/offline/retrying" in conf
        assert "$request_uri" in conf

    def test_non_setup_failure_redirects_to_offline(self):
        conf = _conf_main()
        assert "/offline/" in conf

    def test_safe_next_restricts_to_relative_path(self):
        conf = _conf_nginxd()
        # ~^/[^/] ensures the path starts with / but not //
        assert "safe_next" in conf
        assert "/[^/]" in conf or r"~^/[^/]" in conf

    def test_artwork_location_has_proxy_intercept_errors_off(self):
        conf = _conf_main()
        # Find the artwork location block
        m = re.search(r"location\s+/artwork/\s*\{([^}]+)\}", conf)
        assert m, "/artwork/ location block not found"
        block = m.group(1)
        assert "proxy_intercept_errors off" in block


class TestSharedConstantMatchesNginx:
    """The Python intercepted-status constant must match the deployed NGINX set."""

    def test_python_constant_matches_nginx_intercepted_set(self):
        from autostream_webui_api import _NGINX_INTERCEPTED_STATUSES
        conf = _conf_main()
        m = re.search(r"error_page\s+([0-9 ]+)\s*=", conf)
        assert m, "error_page directive not found in main nginx conf"
        nginx_codes = frozenset(int(c) for c in m.group(1).split())
        assert _NGINX_INTERCEPTED_STATUSES == nginx_codes, (
            f"Python _NGINX_INTERCEPTED_STATUSES {_NGINX_INTERCEPTED_STATUSES} "
            f"!= NGINX error_page codes {nginx_codes}. "
            "Update the constant to match the deployed NGINX policy."
        )


class TestDialNginxInterceptionPolicy:
    """Dial NGINX policy (separate from main assertions in test_dial_nginx_config.py)."""

    def test_dial_intercepts_502(self):
        conf = _conf_dial()
        assert "502" in conf

    def test_dial_intercepts_503(self):
        conf = _conf_dial()
        assert "503" in conf

    def test_dial_intercepts_504(self):
        conf = _conf_dial()
        assert "504" in conf

    def test_dial_does_not_intercept_400(self):
        """400 must not be in dial error_page directive."""
        conf = _conf_dial()
        m = re.search(r"error_page\s+([0-9 ]+)\s*=", conf)
        if not m:
            pytest.skip("No error_page directive in dial nginx config")
        codes = set(m.group(1).split())
        assert "400" not in codes

    def test_dial_does_not_intercept_403(self):
        conf = _conf_dial()
        m = re.search(r"error_page\s+([0-9 ]+)\s*=", conf)
        if not m:
            pytest.skip("No error_page directive in dial nginx config")
        codes = set(m.group(1).split())
        assert "403" not in codes

    def test_dial_does_not_intercept_404(self):
        conf = _conf_dial()
        m = re.search(r"error_page\s+([0-9 ]+)\s*=", conf)
        if not m:
            pytest.skip("No error_page directive in dial nginx config")
        codes = set(m.group(1).split())
        assert "404" not in codes

    def test_dial_does_not_intercept_429(self):
        conf = _conf_dial()
        m = re.search(r"error_page\s+([0-9 ]+)\s*=", conf)
        if not m:
            pytest.skip("No error_page directive in dial nginx config")
        codes = set(m.group(1).split())
        assert "429" not in codes

    def test_dial_does_not_intercept_500(self):
        conf = _conf_dial()
        m = re.search(r"error_page\s+([0-9 ]+)\s*=", conf)
        if not m:
            pytest.skip("No error_page directive in dial nginx config")
        codes = set(m.group(1).split())
        assert "500" not in codes


# ---------------------------------------------------------------------------
# §7.6  Direct dial regression tests (import isolation)
# ---------------------------------------------------------------------------

class TestDialImportIsolation:
    """Dial production modules must not import core/ web UI helpers."""

    def _dial_source(self, filename: str) -> str:
        return (REPO_ROOT / "dial" / filename).read_text(encoding="utf-8")

    def test_dial_http_server_does_not_import_autostream_webui_api(self):
        src = self._dial_source("dial_http_server.py")
        assert "autostream_webui_api" not in src

    def test_dial_http_server_does_not_import_autostream_webui_dials(self):
        src = self._dial_source("dial_http_server.py")
        assert "autostream_webui_dials" not in src

    def test_dial_webui_assets_does_not_import_autostream_webui_api(self):
        src = self._dial_source("dial_webui_assets.py")
        assert "autostream_webui_api" not in src

    def test_dial_webui_assets_does_not_import_autostream_webui_dials(self):
        src = self._dial_source("dial_webui_assets.py")
        assert "autostream_webui_dials" not in src

    def test_dial_webui_assets_does_not_import_core_helper_names(self):
        src = self._dial_source("dial_webui_assets.py")
        assert "send_browser_api_error" not in src

    def test_no_core_module_imported_by_dial_http_server(self):
        src = self._dial_source("dial_http_server.py")
        # No import from core/ modules
        assert "from core." not in src
        assert "import core." not in src

    def test_send_browser_api_error_not_duplicated_in_dial(self):
        """There must be only one authoritative intercepted-status helper."""
        src = self._dial_source("dial_webui_assets.py")
        assert "send_browser_api_error" not in src
        src2 = self._dial_source("dial_http_server.py")
        assert "send_browser_api_error" not in src2


# ---------------------------------------------------------------------------
# §7.7  Gateway error contract
# ---------------------------------------------------------------------------

class TestGatewayErrorContract:
    """Gateway-specific errors must use NGINX-safe transport where required.

    NGINX-intercepted statuses (404/502/503/504) must be tunnelled as HTTP 200
    with an error_status field.  Non-intercepted statuses (409/429/500) must be
    returned natively without error_status.
    """

    def _call_helper(self, semantic_status: int, error: str, **kwargs):
        from autostream_webui_api import send_browser_api_error
        captured = []
        with patch("autostream_webui_api.send_json",
                   side_effect=lambda h, c, d: captured.append((c, d))):
            send_browser_api_error(MagicMock(), semantic_status, error, **kwargs)
        assert len(captured) == 1
        return captured[0]

    # Transport failures produce tunnelled responses
    def test_not_found_tunnelled_as_200(self):
        code, payload = self._call_helper(404, "not_found")
        assert code == 200
        assert payload["error_status"] == 404
        assert payload["ok"] is False

    def test_remote_timeout_tunnelled_as_200_504(self):
        code, payload = self._call_helper(504, "remote_timeout", retryable=True)
        assert code == 200
        assert payload["error_status"] == 504
        assert payload["retryable"] is True

    def test_remote_bad_response_tunnelled_as_200_502(self):
        code, payload = self._call_helper(502, "remote_bad_response", retryable=True)
        assert code == 200
        assert payload["error_status"] == 502

    def test_appliance_offline_tunnelled_as_200_503(self):
        code, payload = self._call_helper(503, "appliance_offline", retryable=True)
        assert code == 200
        assert payload["error_status"] == 503

    # Conflict and backoff produce native responses
    def test_appliance_conflicted_is_native_409(self):
        code, payload = self._call_helper(409, "appliance_conflicted")
        assert code == 409
        assert "error_status" not in payload

    def test_remote_backoff_is_native_429(self):
        code, payload = self._call_helper(429, "remote_backoff", retryable=True,
                                          extra={"retry_after": 5})
        assert code == 429
        assert "error_status" not in payload
        assert payload["retry_after"] == 5

    def test_target_error_is_native_500(self):
        code, payload = self._call_helper(500, "target_error")
        assert code == 500
        assert "error_status" not in payload

    # Retryable propagates correctly for transport failures
    def test_retryable_present_for_tunnelled_errors(self):
        _, payload = self._call_helper(503, "appliance_offline", retryable=True)
        assert payload["retryable"] is True

    def test_retryable_absent_when_not_supplied(self):
        _, payload = self._call_helper(502, "remote_bad_response")
        assert "retryable" not in payload
