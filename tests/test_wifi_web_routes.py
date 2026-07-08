"""Flask captive-portal, status, and network-control routes, including the
control-token auth mechanism."""
from __future__ import annotations

import contextlib
import json
import os
import sys
import threading
import time
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch, call
import ipaddress

import pytest

from _wifi_fixtures import (
    _get_watcher,
    _isolate_reboot_guard,
    _reset_activation_worker,
    _restore_root_log_level,
    flask_client,
    watcher,
)


class TestCaptivePortalRoutes:
    """All captive probe endpoints must return the landing HTML (captive=True behaviour)."""

    PROBE_PATHS = [
        "/hotspot-detect.html",             # Apple iOS
        "/library/test/success.html",       # Apple macOS
        "/generate_204",                    # Android / Chrome
        "/gen_204",                         # Android variant
        "/ncsi.txt",                        # Windows NCSI
        "/connecttest.txt",                 # Windows alternate
    ]

    @pytest.mark.parametrize("path", PROBE_PATHS)
    def test_probe_returns_200_with_redirect_meta(self, flask_client, path):
        client, mod = flask_client
        rv = client.get(path)
        assert rv.status_code == 200
        assert b"setup" in rv.data.lower() or b"redirect" in rv.data.lower(), (
            f"{path} response did not contain setup redirect content"
        )

    @pytest.mark.parametrize("path", PROBE_PATHS)
    def test_probe_response_is_no_cache(self, flask_client, path):
        client, mod = flask_client
        rv = client.get(path)
        cc = rv.headers.get("Cache-Control", "")
        assert "no-store" in cc or "no-cache" in cc, (
            f"{path} missing no-cache header"
        )

    def test_captive_portal_api_returns_captive_json(self, flask_client):
        """RFC 8910 endpoint returns application/captive+json with captive=true."""
        client, mod = flask_client
        rv = client.get("/.well-known/captive-portal")
        assert rv.status_code == 200
        assert "captive+json" in rv.content_type
        data = json.loads(rv.data)
        assert data["captive"] is True
        assert "user-portal-url" in data

    def test_captive_portal_api_user_portal_url_points_to_setup(self, flask_client):
        client, mod = flask_client
        rv = client.get("/.well-known/captive-portal")
        data = json.loads(rv.data)
        assert data["user-portal-url"].endswith("/setup")

    def test_root_redirects_to_setup(self, flask_client):
        client, mod = flask_client
        rv = client.get("/")
        # Either a redirect or the landing page should lead to /setup.
        assert rv.status_code in (301, 302) or b"/setup" in rv.data

    def test_404_returns_captive_landing(self, flask_client):
        client, mod = flask_client
        rv = client.get("/some/unknown/path")
        assert rv.status_code == 200
        assert b"setup" in rv.data.lower()

    def test_factory_builds_app_with_named_endpoints(self, flask_client):
        """wifi_web.build_app(watcher) registers the captive routes by name
        (endpoint names preserved so url_for keeps resolving)."""
        client, mod = flask_client
        app2 = mod.wifi_web.build_app(mod)
        endpoints = {r.endpoint for r in app2.url_map.iter_rules()}
        for name in ("index", "setup", "networks", "reconnect_saved", "status",
                     "apple_captive_probe", "android_probe", "windows_probe",
                     "captive_portal_api"):
            assert name in endpoints, f"missing endpoint {name!r}"
        # A freshly built app serves the captive landing on 404 too.
        assert app2.test_client().get("/no/such/path").status_code == 200

    def test_networks_returns_merged_shape(self, flask_client):
        client, mod = flask_client
        with patch.object(mod, "scan_all_networks",
                          return_value=([{"ssid": "Net", "signal": 50}], True)):
            rv = client.get("/networks")
        assert rv.status_code == 200
        data = json.loads(rv.data)
        assert data["builtin_scan_known"] is True
        assert data["networks"][0]["ssid"] == "Net"


class TestStatusRoute:
    def test_status_returns_json_with_required_keys(self, flask_client):
        client, mod = flask_client
        rv = client.get("/status")
        assert rv.status_code == 200
        data = json.loads(rv.data)
        for key in ("wifistate", "wiredstate", "SetupMode", "gateway_reachable"):
            assert key in data, f"Missing key {key!r} in /status response"

    def test_status_setup_mode_false_by_default(self, flask_client):
        client, mod = flask_client
        rv = client.get("/status")
        data = json.loads(rv.data)
        assert data["SetupMode"] is False

    def test_status_exposes_saved_ssid_visible(self, flask_client):
        client, mod = flask_client
        mod.STATE.saved_ssid_visible = True
        mod.STATE.saved_ssid_name = "MyHomeWiFi"
        data = json.loads(client.get("/status").data)
        assert data["saved_ssid_visible"] is True
        assert data["saved_ssid"] == "MyHomeWiFi"

    def test_dismiss_rejoin_sets_session_flag(self, flask_client):
        client, mod = flask_client
        mod.STATE.saved_ssid_visible = True
        mod.STATE.rejoin_dismissed = False
        rv = client.post("/dismiss_rejoin")
        assert rv.status_code == 200
        assert json.loads(rv.data)["ok"] is True
        assert mod.STATE.rejoin_dismissed is True
        assert mod.STATE.saved_ssid_visible is False

    def test_dismiss_rejoin_is_captive_accessible_no_token(self, flask_client):
        # Reachable from an AP client with no control token (like /reconnect_saved).
        client, mod = flask_client
        mod.wifi_web._control_token = "tok"
        rv = client.post("/dismiss_rejoin", environ_base={"REMOTE_ADDR": "10.0.0.9"})
        assert rv.status_code == 200

    def test_request_ap_mode_rejected_from_non_localhost(self, flask_client):
        client, mod = flask_client
        mod.wifi_web._control_token = "tok"
        rv = client.post(
            "/request_ap_mode",
            json={"reason": "test"},
            headers={mod.wifi_web.CONTROL_TOKEN_HEADER: "tok"},
            environ_base={"REMOTE_ADDR": "10.0.0.5"},
        )
        assert rv.status_code == 403

    def test_request_ap_mode_rejected_without_token(self, flask_client):
        client, mod = flask_client
        mod.wifi_web._control_token = "tok"
        rv = client.post(
            "/request_ap_mode",
            json={"reason": "test"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        # No token header -> forbidden even from loopback (no unauthenticated
        # privileged route remains behind nginx).
        assert rv.status_code == 403

    def test_request_ap_mode_accepted_with_token(self, flask_client):
        client, mod = flask_client
        mod.wifi_web._control_token = "tok"
        rv = client.post(
            "/request_ap_mode",
            json={"reason": "test"},
            headers={mod.wifi_web.CONTROL_TOKEN_HEADER: "tok"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        # If AP exhausted or other condition, might return 409; accept that too.
        assert rv.status_code in (200, 409)

    def test_request_ap_mode_queues_manual_ap_control_action(self, flask_client):
        client, mod = flask_client
        mod.wifi_web._control_token = "tok"
        mod.STATE.pending_control_action = ""
        mod.STATE.control_in_progress = False
        rv = client.post(
            "/request_ap_mode",
            json={"reason": "test"},
            headers={mod.wifi_web.CONTROL_TOKEN_HEADER: "tok"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        assert rv.status_code == 200
        assert rv.get_json()["action"] == "manual_ap"
        # Queued on the shared control channel, not a legacy dedicated event.
        assert mod.STATE.pending_control_action == "manual_ap"
        assert mod.STATE.pending_control_params == {"reason": "test"}
        assert mod.control_action_event.is_set()

    def test_request_ap_mode_busy_returns_409(self, flask_client):
        client, mod = flask_client
        mod.wifi_web._control_token = "tok"
        # Another control action already pending -> busy.
        mod.STATE.pending_control_action = "reconnect_saved"
        mod.STATE.control_in_progress = False
        rv = client.post(
            "/request_ap_mode",
            json={"reason": "test"},
            headers={mod.wifi_web.CONTROL_TOKEN_HEADER: "tok"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        assert rv.status_code == 409
        assert rv.get_json()["error"] == "busy"
        # The in-flight action is untouched.
        assert mod.STATE.pending_control_action == "reconnect_saved"


class TestNetworkControlRoutes:
    """WP6: per-boot-token-protected control surface."""

    def test_network_status_requires_token(self, flask_client):
        client, mod = flask_client
        mod.wifi_web._control_token = "tok"
        rv = client.get("/network_status", environ_base={"REMOTE_ADDR": "127.0.0.1"})
        assert rv.status_code == 403

    def test_network_status_ok_with_token(self, flask_client):
        client, mod = flask_client
        mod.wifi_web._control_token = "tok"
        rv = client.get(
            "/network_status",
            headers={mod.wifi_web.CONTROL_TOKEN_HEADER: "tok"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        assert rv.status_code == 200
        data = json.loads(rv.data)
        assert data["ok"] is True
        assert data["device"]["state"] == "unknown"
        assert data["stale"] is True

    def test_version_requires_token(self, flask_client):
        client, mod = flask_client
        mod.wifi_web._control_token = "tok"
        rv = client.get("/version", environ_base={"REMOTE_ADDR": "127.0.0.1"})
        assert rv.status_code == 403

    def test_version_ok_with_token(self, flask_client):
        client, mod = flask_client
        mod.wifi_web._control_token = "tok"
        rv = client.get(
            "/version",
            headers={mod.wifi_web.CONTROL_TOKEN_HEADER: "tok"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        assert rv.status_code == 200
        data = json.loads(rv.data)
        assert data == {
            "ok": True,
            "component": "wifi_watcher",
            "version": mod.WIFI_WATCHER_VERSION,
        }

    def test_network_control_rejects_non_loopback(self, flask_client):
        client, mod = flask_client
        mod.wifi_web._control_token = "tok"
        rv = client.post(
            "/network_control",
            json={"action": "start_setup"},
            headers={mod.wifi_web.CONTROL_TOKEN_HEADER: "tok"},
            environ_base={"REMOTE_ADDR": "10.0.0.5"},
        )
        assert rv.status_code == 403

    def test_network_control_rejects_unknown_action(self, flask_client):
        client, mod = flask_client
        mod.wifi_web._control_token = "tok"
        rv = client.post(
            "/network_control",
            json={"action": "wipe_everything"},
            headers={mod.wifi_web.CONTROL_TOKEN_HEADER: "tok"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        assert rv.status_code == 400

    def test_network_control_rejects_extra_fields(self, flask_client):
        client, mod = flask_client
        mod.wifi_web._control_token = "tok"
        rv = client.post(
            "/network_control",
            json={"action": "start_setup", "evil": 1},
            headers={mod.wifi_web.CONTROL_TOKEN_HEADER: "tok"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        assert rv.status_code == 400

    def test_network_control_queues_before_disconnect(self, flask_client):
        client, mod = flask_client
        mod.wifi_web._control_token = "tok"
        # Reset pending state.
        mod.STATE.pending_control_action = ""
        mod.STATE.control_in_progress = False
        rv = client.post(
            "/network_control",
            json={"action": "start_setup"},
            headers={mod.wifi_web.CONTROL_TOKEN_HEADER: "tok"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        assert rv.status_code == 200
        assert json.loads(rv.data).get("queued") is True
        assert mod.STATE.pending_control_action == "start_setup"
        # Clean up the queued action so other tests are unaffected.
        mod.STATE.pending_control_action = ""
        mod.control_action_event.clear()

    def test_network_control_queues_disable_adapter(self, flask_client):
        client, mod = flask_client
        mod.wifi_web._control_token = "tok"
        mod.STATE.pending_control_action = ""
        mod.STATE.control_in_progress = False
        rv = client.post(
            "/network_control",
            json={"action": "disable_adapter", "adapter": "usb-abc"},
            headers={mod.wifi_web.CONTROL_TOKEN_HEADER: "tok"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        assert rv.status_code == 200
        assert mod.STATE.pending_control_action == "disable_adapter"
        assert mod.STATE.pending_control_params == {"adapter": "usb-abc"}
        mod.STATE.pending_control_action = ""
        mod.control_action_event.clear()

    def test_network_control_adapter_action_requires_adapter(self, flask_client):
        client, mod = flask_client
        mod.wifi_web._control_token = "tok"
        rv = client.post(
            "/network_control",
            json={"action": "clear_adapter"},   # missing "adapter"
            headers={mod.wifi_web.CONTROL_TOKEN_HEADER: "tok"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        assert rv.status_code == 400

    def test_network_control_adapter_action_rejects_empty_adapter(self, flask_client):
        client, mod = flask_client
        mod.wifi_web._control_token = "tok"
        rv = client.post(
            "/network_control",
            json={"action": "enable_adapter", "adapter": "   "},
            headers={mod.wifi_web.CONTROL_TOKEN_HEADER: "tok"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        assert rv.status_code == 400

    def test_second_conflicting_action_rejected(self, flask_client):
        client, mod = flask_client
        mod.wifi_web._control_token = "tok"
        mod.STATE.pending_control_action = "start_setup"
        rv = client.post(
            "/network_control",
            json={"action": "reconnect_saved"},
            headers={mod.wifi_web.CONTROL_TOKEN_HEADER: "tok"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        assert rv.status_code == 409
        mod.STATE.pending_control_action = ""
        mod.control_action_event.clear()


class TestControlToken:
    def test_token_file_written_with_mode(self, watcher, tmp_path):
        token_path = tmp_path / "run" / "wifi-control.token"
        watcher.wifi_web.CONTROL_TOKEN_DIR = str(tmp_path / "run")
        watcher.wifi_web.CONTROL_TOKEN_PATH = str(token_path)
        tok = watcher.wifi_web.init_control_token(watcher)
        assert tok and token_path.exists()
        # Token never empty; file content matches.
        assert token_path.read_text(encoding="utf-8").strip() == tok
        import stat
        mode = stat.S_IMODE(token_path.stat().st_mode)
        # On POSIX should be 0o640; on Windows chmod is approximate, so only
        # assert it is not world-writable.
        assert not (mode & 0o007) or sys.platform == "win32"

    def test_remove_token_best_effort(self, watcher, tmp_path):
        token_path = tmp_path / "wifi-control.token"
        token_path.write_text("x", encoding="utf-8")
        watcher.wifi_web.CONTROL_TOKEN_PATH = str(token_path)
        watcher.wifi_web.remove_control_token()
        assert not token_path.exists()
        watcher.wifi_web.remove_control_token()  # no error when absent


class TestSavedNetworkGating:
    def test_has_saved_network_committed(self, watcher):
        with patch.object(watcher, "get_configured_network_state",
                          return_value=watcher.wifi_net.NetworkState("Home", "u")):
            assert watcher.wifi_web._has_saved_network(watcher) is True

    def test_has_saved_network_rollback_only(self, watcher):
        watcher.STATE.hotspot = watcher.HotspotSession(
            purpose=watcher.HotspotPurpose.EXPLICIT_RECONFIGURE,
            entered_at=0.0,
            rollback=watcher.RollbackSnapshot("Old", "", ""),
        )
        with patch.object(watcher, "get_configured_network_state",
                          return_value=watcher.wifi_net.NetworkState("", "")):
            assert watcher.wifi_web._has_saved_network(watcher) is True

    def test_no_saved_network_first_run(self, watcher):
        with patch.object(watcher, "get_configured_network_state",
                          return_value=watcher.wifi_net.NetworkState("", "")):
            assert watcher.wifi_web._has_saved_network(watcher) is False


class TestControlAuthLogic:
    def test_authorised_requires_token_match(self, watcher):
        watcher.wifi_web._control_token = "secret"
        # Simulate request object with header + remote.
        req = MagicMock()
        req.remote_addr = "127.0.0.1"
        req.headers = {watcher.wifi_web.CONTROL_TOKEN_HEADER: "secret"}
        with patch.object(watcher.wifi_web, "request", req):
            assert watcher.wifi_web._control_authorised() is True

    def test_authorised_rejects_wrong_token(self, watcher):
        watcher.wifi_web._control_token = "secret"
        req = MagicMock()
        req.remote_addr = "127.0.0.1"
        req.headers = {watcher.wifi_web.CONTROL_TOKEN_HEADER: "wrong"}
        with patch.object(watcher.wifi_web, "request", req):
            assert watcher.wifi_web._control_authorised() is False

    def test_authorised_rejects_non_loopback(self, watcher):
        watcher.wifi_web._control_token = "secret"
        req = MagicMock()
        req.remote_addr = "10.0.0.5"
        req.headers = {watcher.wifi_web.CONTROL_TOKEN_HEADER: "secret"}
        with patch.object(watcher.wifi_web, "request", req):
            assert watcher.wifi_web._control_authorised() is False

    def test_process_control_action_start_setup(self, watcher):
        with patch.object(watcher, "start_explicit_setup") as ss:
            watcher.process_control_action("start_setup")
        ss.assert_called_once()
        assert watcher.STATE.last_control_action == "start_setup"
        assert watcher.STATE.last_control_result == "ok"
        assert watcher.STATE.control_in_progress is False


class TestNetworkStatusRoute:
    def test_forbidden_without_auth(self, flask_client):
        client, mod = flask_client
        with patch.object(mod.wifi_web, "_control_authorised", return_value=False):
            resp = client.get("/network_status")
        assert resp.status_code == 403

    def test_returns_in_memory_snapshot_when_present(self, flask_client):
        client, mod = flask_client
        mod.STATE.network_status_snapshot = {
            "ok": True,
            "schema_version": 1,
            "device": {"state": "online"},
            "connectivity": {"active_path_ok": True, "wired_ok": True},
        }
        with patch.object(mod.wifi_web, "_control_authorised", return_value=True):
            resp = client.get("/network_status")
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True
        assert resp.get_json()["device"]["state"] == "online"
        assert resp.get_json()["connectivity"]["active_path_ok"] is True

    def test_unknown_stale_before_first_snapshot(self, flask_client):
        client, mod = flask_client
        mod.STATE.network_status_snapshot = None
        with patch.object(mod.wifi_web, "_control_authorised", return_value=True):
            resp = client.get("/network_status")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ok"] is True
        assert body["device"]["state"] == "unknown"
        assert body["stale"] is True

    def test_network_status_v2_removed(self, flask_client):
        client, mod = flask_client
        rules = {rule.rule for rule in mod.app.url_map.iter_rules()}
        assert "/network_status_v2" not in rules


class TestSetLogLevelControlRoute:
    def test_accepts_debug_with_ttl(self, flask_client):
        client, mod = flask_client
        mod.wifi_web._control_token = "tok"
        mod.STATE.pending_control_action = ""
        mod.STATE.control_in_progress = False
        rv = client.post(
            "/network_control",
            json={"action": "set_log_level", "level": "debug", "ttl_seconds": 900},
            headers={mod.wifi_web.CONTROL_TOKEN_HEADER: "tok"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        assert rv.status_code == 200
        assert mod.STATE.pending_control_action == "set_log_level"
        assert mod.STATE.pending_control_params == {"level": "debug", "ttl_seconds": 900}
        mod.STATE.pending_control_action = ""
        mod.STATE.pending_control_params = {}
        mod.control_action_event.clear()

    def test_rejects_invalid_level(self, flask_client):
        client, mod = flask_client
        mod.wifi_web._control_token = "tok"
        mod.STATE.pending_control_action = ""
        rv = client.post(
            "/network_control",
            json={"action": "set_log_level", "level": "trace"},
            headers={mod.wifi_web.CONTROL_TOKEN_HEADER: "tok"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        assert rv.status_code == 400

    def test_rejects_debug_without_ttl(self, flask_client):
        client, mod = flask_client
        mod.wifi_web._control_token = "tok"
        mod.STATE.pending_control_action = ""
        rv = client.post(
            "/network_control",
            json={"action": "set_log_level", "level": "debug"},
            headers={mod.wifi_web.CONTROL_TOKEN_HEADER: "tok"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        assert rv.status_code == 400

    def test_rejects_unknown_field(self, flask_client):
        client, mod = flask_client
        mod.wifi_web._control_token = "tok"
        mod.STATE.pending_control_action = ""
        rv = client.post(
            "/network_control",
            json={"action": "set_log_level", "level": "info", "evil": 1},
            headers={mod.wifi_web.CONTROL_TOKEN_HEADER: "tok"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        assert rv.status_code == 400

    def test_rejects_non_loopback(self, flask_client):
        client, mod = flask_client
        mod.wifi_web._control_token = "tok"
        rv = client.post(
            "/network_control",
            json={"action": "set_log_level", "level": "debug", "ttl_seconds": 900},
            headers={mod.wifi_web.CONTROL_TOKEN_HEADER: "tok"},
            environ_base={"REMOTE_ADDR": "10.0.0.5"},
        )
        assert rv.status_code == 403

    def test_start_setup_still_only_action(self, flask_client):
        client, mod = flask_client
        mod.wifi_web._control_token = "tok"
        mod.STATE.pending_control_action = ""
        rv = client.post(
            "/network_control",
            json={"action": "start_setup", "ttl_seconds": 900},
            headers={mod.wifi_web.CONTROL_TOKEN_HEADER: "tok"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        assert rv.status_code == 400
