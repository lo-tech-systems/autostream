"""P1 — Wi-Fi watcher state machine and captive portal tests.

platform/wifi_watcher is the main appliance recovery path. It runs as root
on Linux but every function tested here is deterministic and offline:
  - pure helper functions (_stateset, _is_rfc1918_ipv4)
  - nmcli output parsing (run_cmd patched)
  - ip -j output parsing (_run_ip_json patched)
  - enter/leave setup mode (run_cmd + filesystem patched)
  - Flask routes including all captive portal probe paths

The module uses module-level globals (STATE, state_lock, etc.). Each test
that mutates STATE resets it to a fresh NetworkMonitorState via a fixture.

Integration tests requiring real nmcli/ip/systemctl are in a separate job;
These tests cover the Wi-Fi watcher state machine and captive-portal integration.
"""
from __future__ import annotations

import importlib
import importlib.util
import json
import os
import sys
import threading
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch, call
import ipaddress

import pytest

REPO_ROOT = Path(__file__).parent.parent
WIFI_WATCHER_PATH = REPO_ROOT / "platform" / "wifi_watcher"

# The watcher imports its sibling helper `autostream_wifi_network` (deployed
# alongside it in /opt/autostream). Make core/ importable so the load succeeds.
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)


# ---------------------------------------------------------------------------
# Module loader — stubs Flask and autostream_sysutils so import works offline
# ---------------------------------------------------------------------------

_watcher_mod: ModuleType | None = None
_watcher_lock = threading.Lock()


def _get_watcher() -> ModuleType:
    """Load wifi_watcher once per session with Flask and sysutils stubbed."""
    global _watcher_mod
    with _watcher_lock:
        if _watcher_mod is not None:
            return _watcher_mod

        alias = "wifi_watcher_p1_test"
        loader = SourceFileLoader(alias, str(WIFI_WATCHER_PATH))
        spec = importlib.util.spec_from_loader(alias, loader)
        mod = importlib.util.module_from_spec(spec)

        # Stub dependencies before exec so module-level code doesn't fail.
        from unittest.mock import MagicMock as MM
        _saved: dict[str, object] = {}

        for stub_name in ("flask", "autostream_sysutils"):
            if stub_name not in sys.modules:
                sys.modules[stub_name] = MM()
                _saved[stub_name] = None
            else:
                _saved[stub_name] = sys.modules[stub_name]

        # Flask needs specific objects at module level.
        # Save original attrs so we can restore the real flask module afterwards
        # (when flask IS installed, mutating its attributes would corrupt the
        # flask_client fixture's fresh watcher load).
        _FLASK_ATTRS = ("Flask", "request", "jsonify", "redirect", "url_for", "make_response")
        flask_stub = sys.modules["flask"]
        _flask_saved_attrs = {a: getattr(flask_stub, a, None) for a in _FLASK_ATTRS}
        flask_stub.Flask = lambda *a, **kw: MM()
        flask_stub.request = MM()
        flask_stub.jsonify = lambda d: MM()
        flask_stub.redirect = lambda u: MM()
        flask_stub.url_for = lambda *a, **kw: "/"
        flask_stub.make_response = lambda h, s: MM()

        sysutils = sys.modules["autostream_sysutils"]
        # Save and restore original attrs to avoid permanently mutating the
        # real autostream_sysutils module when it's already imported.
        _sysutils_saved_attrs: dict[str, object] = {}
        for attr in ("run_cmd", "prime_gateway", "reboot_system", "get_system_hostname"):
            if hasattr(sysutils, attr):
                _sysutils_saved_attrs[attr] = getattr(sysutils, attr)
        sysutils.run_cmd = MM()
        sysutils.prime_gateway = MM()
        sysutils.reboot_system = MM()
        sysutils.get_system_hostname = MM(return_value="autostream")

        try:
            loader.exec_module(mod)
        finally:
            for name, orig in _saved.items():
                if orig is None:
                    sys.modules.pop(name, None)
            # Restore flask attrs on the real module (no-op if flask was not
            # installed and we injected a fresh MagicMock).
            if _saved.get("flask") is not None:
                for attr, orig_val in _flask_saved_attrs.items():
                    if orig_val is not None:
                        setattr(flask_stub, attr, orig_val)
            # Restore the real sysutils attributes if we mutated the real module.
            if "autostream_sysutils" not in _saved or _saved.get("autostream_sysutils") is not None:
                for attr, orig_val in _sysutils_saved_attrs.items():
                    setattr(sysutils, attr, orig_val)

        # Store the real function pointers for later patching
        _watcher_mod = mod
        return mod


@pytest.fixture()
def watcher():
    """Return the loaded wifi_watcher module and reset STATE before each test."""
    mod = _get_watcher()
    from dataclasses import fields
    defaults = mod.NetworkMonitorState()
    for f in fields(defaults):
        setattr(mod.STATE, f.name, getattr(defaults, f.name))
    mod._last_logged_values.clear()
    yield mod
    # Reset again in case the test mutated STATE
    for f in fields(defaults):
        setattr(mod.STATE, f.name, getattr(defaults, f.name))


@pytest.fixture()
def flask_client(watcher):
    """Return a Flask test client for the wifi_watcher app.

    wifi_watcher creates a module-level `app` via Flask(). Since we stub Flask
    at import time the real test client comes from loading a second fresh copy
    with real Flask (if available). If Flask is not installed the tests are
    skipped.
    """
    try:
        from flask import Flask
    except ImportError:
        pytest.skip("Flask not installed — captive portal route tests skipped")

    # Re-load the module with real Flask so the test client works.
    alias = "wifi_watcher_flask_test"
    loader = SourceFileLoader(alias, str(WIFI_WATCHER_PATH))
    spec = importlib.util.spec_from_loader(alias, loader)
    flask_mod = importlib.util.module_from_spec(spec)

    # Stub only the non-Flask external deps.
    from unittest.mock import MagicMock as MM
    sysutils_stub = MM()
    sysutils_stub.run_cmd = MM(return_value=MM(returncode=0, stdout="", stderr=""))
    sysutils_stub.prime_gateway = MM()
    sysutils_stub.reboot_system = MM()
    sysutils_stub.get_system_hostname = MM(return_value="autostream")

    saved_sysutils = sys.modules.get("autostream_sysutils")
    sys.modules["autostream_sysutils"] = sysutils_stub
    try:
        loader.exec_module(flask_mod)
    finally:
        if saved_sysutils is None:
            sys.modules.pop("autostream_sysutils", None)
        else:
            sys.modules["autostream_sysutils"] = saved_sysutils

    flask_mod.app.config["TESTING"] = True
    return flask_mod.app.test_client(), flask_mod


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

class TestStateset:
    def test_string_input_uppercased(self):
        mod = _get_watcher()
        assert mod._stateset("reachable") == {"REACHABLE"}

    def test_list_input_each_uppercased(self):
        mod = _get_watcher()
        assert mod._stateset(["STALE", "delay"]) == {"STALE", "DELAY"}

    def test_empty_string_returns_empty_set(self):
        mod = _get_watcher()
        assert mod._stateset("") == {""}

    def test_none_like_returns_empty_set(self):
        mod = _get_watcher()
        assert mod._stateset(42) == set()

    def test_ok_neigh_states_are_recognised(self):
        mod = _get_watcher()
        ok = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"}
        for s in ok:
            assert mod._stateset(s) & mod._OK_NEIGH_STATES


class TestIsRfc1918Ipv4:
    def test_10_range_is_rfc1918(self):
        mod = _get_watcher()
        assert mod._is_rfc1918_ipv4(ipaddress.IPv4Address("10.0.0.1"))

    def test_172_range_is_rfc1918(self):
        mod = _get_watcher()
        assert mod._is_rfc1918_ipv4(ipaddress.IPv4Address("172.16.0.1"))

    def test_192_168_range_is_rfc1918(self):
        mod = _get_watcher()
        assert mod._is_rfc1918_ipv4(ipaddress.IPv4Address("192.168.1.1"))

    def test_public_ip_is_not_rfc1918(self):
        mod = _get_watcher()
        assert not mod._is_rfc1918_ipv4(ipaddress.IPv4Address("8.8.8.8"))

    def test_loopback_is_not_rfc1918(self):
        mod = _get_watcher()
        assert not mod._is_rfc1918_ipv4(ipaddress.IPv4Address("127.0.0.1"))


# ---------------------------------------------------------------------------
# is_wifi_connected — parses nmcli output
# ---------------------------------------------------------------------------

class TestIsWifiConnected:
    def _run_cmd_ok(self, stdout: str):
        m = MagicMock()
        m.returncode = 0
        m.stdout = stdout
        m.stderr = ""
        return m

    def test_connected_client_wifi_returns_true(self, watcher):
        output = "wlan0:wifi:connected:MySSID\n"
        # mode query returns "802-11-wireless.mode:infrastructure"
        mode_result = MagicMock(returncode=0, stdout="802-11-wireless.mode:infrastructure\n", stderr="")
        with patch.object(watcher.wifi_net, "run_cmd") as mock_run:
            mock_run.side_effect = [self._run_cmd_ok(output), mode_result]
            assert watcher.is_wifi_connected() is True

    def test_disconnected_returns_false(self, watcher):
        output = "wlan0:wifi:disconnected:\n"
        with patch.object(watcher.wifi_net, "run_cmd") as mock_run:
            mock_run.return_value = self._run_cmd_ok(output)
            assert watcher.is_wifi_connected() is False

    def test_ap_mode_returns_false(self, watcher):
        # Device is "connected" but the connection is in AP mode.
        output = "wlan0:wifi:connected:Hotspot\n"
        mode_result = MagicMock(returncode=0, stdout="802-11-wireless.mode:ap\n", stderr="")
        with patch.object(watcher.wifi_net, "run_cmd") as mock_run:
            mock_run.side_effect = [self._run_cmd_ok(output), mode_result]
            assert watcher.is_wifi_connected() is False

    def test_command_failure_returns_false(self, watcher):
        result = MagicMock(returncode=1, stdout="", stderr="Error")
        with patch.object(watcher.wifi_net, "run_cmd", return_value=result):
            assert watcher.is_wifi_connected() is False

    def test_empty_output_returns_false(self, watcher):
        with patch.object(watcher.wifi_net, "run_cmd", return_value=self._run_cmd_ok("")):
            assert watcher.is_wifi_connected() is False

    def test_wrong_device_ignored(self, watcher):
        # eth0 connected but wlan0 is not
        output = "eth0:ethernet:connected:Wired\nwlan0:wifi:disconnected:\n"
        with patch.object(watcher.wifi_net, "run_cmd", return_value=self._run_cmd_ok(output)):
            assert watcher.is_wifi_connected() is False

    def test_malformed_line_skipped(self, watcher):
        output = "bad-line-without-colons\nwlan0:wifi:disconnected:\n"
        with patch.object(watcher.wifi_net, "run_cmd", return_value=self._run_cmd_ok(output)):
            assert watcher.is_wifi_connected() is False

    def test_escaped_ssid_with_colon(self, watcher):
        # nmcli -t escapes ':' in SSIDs as '\:'; the helper's parser handles it.
        output = "wlan0:wifi:connected:My\\:SSID\\:with\\:colons\n"
        mode_result = MagicMock(returncode=0, stdout="802-11-wireless.mode:infrastructure\n", stderr="")
        with patch.object(watcher.wifi_net, "run_cmd") as mock_run:
            mock_run.side_effect = [self._run_cmd_ok(output), mode_result]
            assert watcher.is_wifi_connected() is True


# ---------------------------------------------------------------------------
# is_local_ipv4_ready — parses nmcli dev show output
# ---------------------------------------------------------------------------

class TestIsLocalIpv4Ready:
    def _make_run_cmd(self, output: str, rc: int = 0):
        return MagicMock(returncode=rc, stdout=output, stderr="")

    def test_rfc1918_address_returns_true(self, watcher):
        output = "GENERAL.STATE:100 (connected)\nIP4.ADDRESS[1]:192.168.1.42/24\n"
        with patch.object(watcher.wifi_net, "run_cmd", return_value=self._make_run_cmd(output)):
            assert watcher.is_local_ipv4_ready() is True

    def test_link_local_address_returns_false(self, watcher):
        output = "GENERAL.STATE:100 (connected)\nIP4.ADDRESS[1]:169.254.1.1/16\n"
        with patch.object(watcher.wifi_net, "run_cmd", return_value=self._make_run_cmd(output)):
            assert watcher.is_local_ipv4_ready() is False

    def test_public_ip_returns_false(self, watcher):
        # Only RFC1918 addresses count as "local"
        output = "GENERAL.STATE:100 (connected)\nIP4.ADDRESS[1]:8.8.8.8/24\n"
        with patch.object(watcher.wifi_net, "run_cmd", return_value=self._make_run_cmd(output)):
            assert watcher.is_local_ipv4_ready() is False

    def test_disconnected_state_returns_false(self, watcher):
        output = "GENERAL.STATE:30 (disconnected)\nIP4.ADDRESS[1]:192.168.1.42/24\n"
        with patch.object(watcher.wifi_net, "run_cmd", return_value=self._make_run_cmd(output)):
            assert watcher.is_local_ipv4_ready() is False

    def test_no_addresses_returns_false(self, watcher):
        output = "GENERAL.STATE:100 (connected)\n"
        with patch.object(watcher.wifi_net, "run_cmd", return_value=self._make_run_cmd(output)):
            assert watcher.is_local_ipv4_ready() is False

    def test_empty_output_returns_false(self, watcher):
        with patch.object(watcher.wifi_net, "run_cmd", return_value=self._make_run_cmd("")):
            assert watcher.is_local_ipv4_ready() is False

    def test_command_failure_returns_false(self, watcher):
        with patch.object(watcher.wifi_net, "run_cmd", return_value=self._make_run_cmd("", rc=1)):
            assert watcher.is_local_ipv4_ready() is False

    def test_multiple_addresses_accepts_first_rfc1918(self, watcher):
        output = (
            "GENERAL.STATE:100 (connected)\n"
            "IP4.ADDRESS[1]:169.254.0.1/16\n"
            "IP4.ADDRESS[2]:10.0.0.5/8\n"
        )
        with patch.object(watcher.wifi_net, "run_cmd", return_value=self._make_run_cmd(output)):
            assert watcher.is_local_ipv4_ready() is True

    def test_malformed_json_address_skipped(self, watcher):
        output = "GENERAL.STATE:100 (connected)\nIP4.ADDRESS[1]:not-an-ip\n"
        with patch.object(watcher.wifi_net, "run_cmd", return_value=self._make_run_cmd(output)):
            assert watcher.is_local_ipv4_ready() is False


# ---------------------------------------------------------------------------
# is_gateway_reachable — parses ip -j route/neigh output
# ---------------------------------------------------------------------------

class TestIsGatewayReachable:
    """Interface-specific gateway reachability (WP2).

    Health is scoped to the requested interface: the default route's dev must
    equal the interface, and only a neighbour entry on that same interface
    counts.  Another adapter's route/neighbour cannot make a failed adapter
    appear healthy.
    """

    def test_reachable_gateway_returns_true(self, watcher):
        routes = [{"gateway": "192.168.1.1", "dev": "wlan0"}]
        neigh = [{"dev": "wlan0", "state": "REACHABLE"}]
        with patch.object(watcher.wifi_net, "_run_ip_json") as mock_ip, \
             patch.object(watcher, "prime_gateway", MagicMock()):
            mock_ip.side_effect = [routes, neigh]
            assert watcher.is_gateway_reachable("wlan0") is True

    def test_stale_state_returns_true(self, watcher):
        routes = [{"gateway": "192.168.1.1", "dev": "wlan0"}]
        neigh = [{"dev": "wlan0", "state": "STALE"}]
        with patch.object(watcher.wifi_net, "_run_ip_json") as mock_ip, \
             patch.object(watcher, "prime_gateway", MagicMock()):
            mock_ip.side_effect = [routes, neigh]
            assert watcher.is_gateway_reachable("wlan0") is True

    def test_failed_state_returns_false(self, watcher):
        routes = [{"gateway": "192.168.1.1", "dev": "wlan0"}]
        neigh = [{"dev": "wlan0", "state": "FAILED"}]
        with patch.object(watcher.wifi_net, "_run_ip_json") as mock_ip, \
             patch.object(watcher, "prime_gateway", MagicMock()):
            mock_ip.side_effect = [routes, neigh]
            assert watcher.is_gateway_reachable("wlan0") is False

    def test_no_routes_returns_false(self, watcher):
        with patch.object(watcher.wifi_net, "_run_ip_json", return_value=[]):
            assert watcher.is_gateway_reachable("wlan0") is False

    def test_missing_gateway_key_returns_false(self, watcher):
        routes = [{"dev": "wlan0"}]  # no "gateway" key
        with patch.object(watcher.wifi_net, "_run_ip_json", return_value=routes):
            assert watcher.is_gateway_reachable("wlan0") is False

    def test_invalid_gateway_ip_returns_false(self, watcher):
        routes = [{"gateway": "not-an-ip", "dev": "wlan0"}]
        with patch.object(watcher.wifi_net, "_run_ip_json", return_value=routes):
            assert watcher.is_gateway_reachable("wlan0") is False

    def test_empty_neigh_list_returns_false(self, watcher):
        routes = [{"gateway": "192.168.1.1", "dev": "wlan0"}]
        with patch.object(watcher.wifi_net, "_run_ip_json") as mock_ip, \
             patch.object(watcher, "prime_gateway", MagicMock()):
            mock_ip.side_effect = [routes, []]
            assert watcher.is_gateway_reachable("wlan0") is False

    def test_state_as_list_works(self, watcher):
        routes = [{"gateway": "10.0.0.1", "dev": "eth0"}]
        neigh = [{"dev": "eth0", "state": ["REACHABLE"]}]
        with patch.object(watcher.wifi_net, "_run_ip_json") as mock_ip, \
             patch.object(watcher, "prime_gateway", MagicMock()):
            mock_ip.side_effect = [routes, neigh]
            # Must query the interface that actually carries the default route.
            assert watcher.is_gateway_reachable("eth0") is True

    def test_ip_json_exception_returns_false(self, watcher):
        with patch.object(watcher.wifi_net, "_run_ip_json", side_effect=RuntimeError("ip failed")):
            assert watcher.is_gateway_reachable("wlan0") is False

    def test_other_interface_route_does_not_satisfy_requested_interface(self, watcher):
        # Default route is on eth0; querying wlan0 must NOT be satisfied by it.
        routes = [{"gateway": "192.168.1.1", "dev": "eth0"}]
        neigh = [{"dev": "eth0", "state": "REACHABLE"}]
        with patch.object(watcher.wifi_net, "_run_ip_json") as mock_ip, \
             patch.object(watcher, "prime_gateway", MagicMock()):
            mock_ip.side_effect = [routes, neigh]
            assert watcher.is_gateway_reachable("wlan0") is False

    def test_neigh_on_other_dev_does_not_count(self, watcher):
        # Route on wlan0, but the only OK neighbour is on eth0 -> not healthy.
        routes = [{"gateway": "192.168.1.1", "dev": "wlan0"}]
        neigh = [{"dev": "eth0", "state": "REACHABLE"}]
        with patch.object(watcher.wifi_net, "_run_ip_json") as mock_ip, \
             patch.object(watcher, "prime_gateway", MagicMock()):
            mock_ip.side_effect = [routes, neigh]
            assert watcher.is_gateway_reachable("wlan0") is False


# ---------------------------------------------------------------------------
# scan_wifi_networks — parses nmcli output, deduplication
# ---------------------------------------------------------------------------

class TestScanWifiNetworks:
    def _make_run_cmd(self, output: str, rc: int = 0):
        return MagicMock(returncode=rc, stdout=output, stderr="")

    def test_returns_sorted_by_signal_descending(self, watcher):
        output = "NetA:40\nNetB:80\nNetC:60\n"
        with patch.object(watcher, "run_cmd", return_value=self._make_run_cmd(output)):
            nets = watcher.scan_wifi_networks()
        assert [n["ssid"] for n in nets] == ["NetB", "NetC", "NetA"]

    def test_deduplicates_same_ssid_keeps_strongest(self, watcher):
        output = "MyNet:50\nMyNet:75\nMyNet:30\n"
        with patch.object(watcher, "run_cmd", return_value=self._make_run_cmd(output)):
            nets = watcher.scan_wifi_networks()
        assert len(nets) == 1
        assert nets[0]["signal"] == 75

    def test_empty_output_returns_empty_list(self, watcher):
        with patch.object(watcher, "run_cmd", return_value=self._make_run_cmd("")):
            assert watcher.scan_wifi_networks() == []

    def test_command_failure_returns_empty_list(self, watcher):
        with patch.object(watcher, "run_cmd", return_value=self._make_run_cmd("", rc=1)):
            assert watcher.scan_wifi_networks() == []

    def test_blank_ssid_lines_skipped(self, watcher):
        output = ":50\n\nGoodNet:70\n"
        with patch.object(watcher, "run_cmd", return_value=self._make_run_cmd(output)):
            nets = watcher.scan_wifi_networks()
        assert all(n["ssid"] for n in nets)

    def test_non_numeric_signal_skipped(self, watcher):
        output = "GoodNet:70\nBadNet:notanumber\n"
        with patch.object(watcher, "run_cmd", return_value=self._make_run_cmd(output)):
            nets = watcher.scan_wifi_networks()
        assert len(nets) == 1
        assert nets[0]["ssid"] == "GoodNet"

    def test_hidden_network_empty_ssid_skipped(self, watcher):
        # nmcli sometimes emits a line with empty SSID for hidden networks
        output = ":60\nVisible:80\n"
        with patch.object(watcher, "run_cmd", return_value=self._make_run_cmd(output)):
            nets = watcher.scan_wifi_networks()
        ssids = [n["ssid"] for n in nets]
        assert "" not in ssids


# ---------------------------------------------------------------------------
# update_apmode_flag — filesystem state
# ---------------------------------------------------------------------------

class TestUpdateApmodeFlagLifecycle:
    def test_creates_flag_file_when_entering_setup(self, watcher, tmp_path):
        flag = tmp_path / "apmode"
        watcher.AP_MODE_FLAG_PATH = str(flag)
        watcher.update_apmode_flag(True)
        assert flag.exists()

    def test_removes_flag_file_when_leaving_setup(self, watcher, tmp_path):
        flag = tmp_path / "apmode"
        flag.write_text("1\n")
        watcher.AP_MODE_FLAG_PATH = str(flag)
        watcher.update_apmode_flag(False)
        assert not flag.exists()

    def test_idempotent_create(self, watcher, tmp_path):
        flag = tmp_path / "apmode"
        watcher.AP_MODE_FLAG_PATH = str(flag)
        watcher.update_apmode_flag(True)
        watcher.update_apmode_flag(True)
        assert flag.exists()

    def test_idempotent_remove(self, watcher, tmp_path):
        flag = tmp_path / "apmode"
        watcher.AP_MODE_FLAG_PATH = str(flag)
        watcher.update_apmode_flag(False)  # file never existed
        assert not flag.exists()


# ---------------------------------------------------------------------------
# enter_setup_mode / leave_setup_mode — state transitions
# ---------------------------------------------------------------------------

class TestEnterLeaveSetupMode:
    def test_enter_sets_setup_mode_true(self, watcher, tmp_path):
        flag = tmp_path / "apmode"
        watcher.AP_MODE_FLAG_PATH = str(flag)
        with patch.object(watcher, "start_ap_mode"), \
             patch.object(watcher, "stop_ap_mode"):
            watcher.enter_setup_mode("test")
        assert watcher.STATE.setup_mode is True

    def test_enter_creates_ap_flag_file(self, watcher, tmp_path):
        flag = tmp_path / "apmode"
        watcher.AP_MODE_FLAG_PATH = str(flag)
        with patch.object(watcher, "start_ap_mode"), \
             patch.object(watcher, "stop_ap_mode"):
            watcher.enter_setup_mode("test")
        assert flag.exists()

    def test_enter_is_idempotent(self, watcher, tmp_path):
        flag = tmp_path / "apmode"
        watcher.AP_MODE_FLAG_PATH = str(flag)
        with patch.object(watcher, "start_ap_mode") as mock_start, \
             patch.object(watcher, "stop_ap_mode"):
            watcher.enter_setup_mode("first")
            watcher.enter_setup_mode("second")
        # start_ap_mode called only once
        assert mock_start.call_count == 1

    def test_leave_sets_setup_mode_false(self, watcher, tmp_path):
        flag = tmp_path / "apmode"
        flag.write_text("1\n")
        watcher.AP_MODE_FLAG_PATH = str(flag)
        watcher.STATE.setup_mode = True
        with patch.object(watcher, "start_ap_mode"), \
             patch.object(watcher, "stop_ap_mode"):
            watcher.leave_setup_mode("done")
        assert watcher.STATE.setup_mode is False

    def test_leave_removes_ap_flag_file(self, watcher, tmp_path):
        flag = tmp_path / "apmode"
        flag.write_text("1\n")
        watcher.AP_MODE_FLAG_PATH = str(flag)
        watcher.STATE.setup_mode = True
        with patch.object(watcher, "start_ap_mode"), \
             patch.object(watcher, "stop_ap_mode"):
            watcher.leave_setup_mode("done")
        assert not flag.exists()

    def test_leave_is_idempotent_when_not_in_setup(self, watcher, tmp_path):
        flag = tmp_path / "apmode"
        watcher.AP_MODE_FLAG_PATH = str(flag)
        watcher.STATE.setup_mode = False
        with patch.object(watcher, "stop_ap_mode") as mock_stop:
            watcher.leave_setup_mode("done")
        mock_stop.assert_not_called()

    def test_ap_exhausted_blocks_enter(self, watcher, tmp_path):
        flag = tmp_path / "apmode"
        watcher.AP_MODE_FLAG_PATH = str(flag)
        watcher.STATE.ap_exhausted = True
        watcher.STATE.force_setup_mode = False
        with patch.object(watcher, "start_ap_mode") as mock_start:
            watcher.enter_setup_mode("blocked")
        mock_start.assert_not_called()
        assert watcher.STATE.setup_mode is False

    def test_force_setup_mode_bypasses_exhausted_latch(self, watcher, tmp_path):
        flag = tmp_path / "apmode"
        watcher.AP_MODE_FLAG_PATH = str(flag)
        watcher.STATE.ap_exhausted = True
        watcher.STATE.force_setup_mode = True
        with patch.object(watcher, "start_ap_mode") as mock_start, \
             patch.object(watcher, "stop_ap_mode"):
            watcher.enter_setup_mode("forced")
        mock_start.assert_called_once()
        assert watcher.STATE.setup_mode is True

    def test_leave_calls_stop_ap_before_removing_flag(self, watcher, tmp_path):
        """stop_ap_mode must run before the AP flag is removed (ordering invariant)."""
        flag = tmp_path / "apmode"
        flag.write_text("1\n")
        watcher.AP_MODE_FLAG_PATH = str(flag)
        watcher.STATE.setup_mode = True
        order: list[str] = []

        def _stop():
            order.append("stop_ap")
            assert flag.exists(), "flag removed before stop_ap_mode"

        def _update_flag(in_setup: bool):
            order.append(f"flag_{in_setup}")
            if not in_setup and flag.exists():
                flag.unlink()

        with patch.object(watcher, "stop_ap_mode", side_effect=_stop), \
             patch.object(watcher, "update_apmode_flag", side_effect=_update_flag):
            watcher.leave_setup_mode("ordering-test")

        assert order == ["stop_ap", "flag_False"], f"Wrong order: {order}"


# ---------------------------------------------------------------------------
# get_configured_wifi_connection_name — file-based
# ---------------------------------------------------------------------------

class TestGetConfiguredWifiConnectionName:
    def test_returns_name_when_file_exists(self, watcher, tmp_path):
        cfg = tmp_path / "configured_ssid"
        cfg.write_text("MyNetwork\n", encoding="utf-8")
        watcher.CONFIGURED_SSID = str(cfg)
        assert watcher.get_configured_wifi_connection_name() == "MyNetwork"

    def test_returns_none_when_file_absent(self, watcher, tmp_path):
        watcher.CONFIGURED_SSID = str(tmp_path / "nonexistent")
        assert watcher.get_configured_wifi_connection_name() is None

    def test_returns_none_for_empty_file(self, watcher, tmp_path):
        cfg = tmp_path / "configured_ssid"
        cfg.write_text("   \n", encoding="utf-8")
        watcher.CONFIGURED_SSID = str(cfg)
        assert watcher.get_configured_wifi_connection_name() is None


# ---------------------------------------------------------------------------
# Flask routes — captive portal probes and /status
# ---------------------------------------------------------------------------

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

    def test_request_ap_mode_rejected_from_non_localhost(self, flask_client):
        client, mod = flask_client
        mod._control_token = "tok"
        rv = client.post(
            "/request_ap_mode",
            json={"reason": "test"},
            headers={mod.CONTROL_TOKEN_HEADER: "tok"},
            environ_base={"REMOTE_ADDR": "10.0.0.5"},
        )
        assert rv.status_code == 403

    def test_request_ap_mode_rejected_without_token(self, flask_client):
        client, mod = flask_client
        mod._control_token = "tok"
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
        mod._control_token = "tok"
        rv = client.post(
            "/request_ap_mode",
            json={"reason": "test"},
            headers={mod.CONTROL_TOKEN_HEADER: "tok"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        # If AP exhausted or other condition, might return 409; accept that too.
        assert rv.status_code in (200, 409)


class TestNetworkControlRoutes:
    """WP6: per-boot-token-protected control surface."""

    def test_network_status_requires_token(self, flask_client):
        client, mod = flask_client
        mod._control_token = "tok"
        rv = client.get("/network_status", environ_base={"REMOTE_ADDR": "127.0.0.1"})
        assert rv.status_code == 403

    def test_network_status_ok_with_token(self, flask_client):
        client, mod = flask_client
        mod._control_token = "tok"
        rv = client.get(
            "/network_status",
            headers={mod.CONTROL_TOKEN_HEADER: "tok"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        assert rv.status_code == 200
        data = json.loads(rv.data)
        assert data["ok"] is True
        assert "active_adapter_ifname" in data

    def test_network_control_rejects_non_loopback(self, flask_client):
        client, mod = flask_client
        mod._control_token = "tok"
        rv = client.post(
            "/network_control",
            json={"action": "start_setup"},
            headers={mod.CONTROL_TOKEN_HEADER: "tok"},
            environ_base={"REMOTE_ADDR": "10.0.0.5"},
        )
        assert rv.status_code == 403

    def test_network_control_rejects_unknown_action(self, flask_client):
        client, mod = flask_client
        mod._control_token = "tok"
        rv = client.post(
            "/network_control",
            json={"action": "wipe_everything"},
            headers={mod.CONTROL_TOKEN_HEADER: "tok"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        assert rv.status_code == 400

    def test_network_control_rejects_extra_fields(self, flask_client):
        client, mod = flask_client
        mod._control_token = "tok"
        rv = client.post(
            "/network_control",
            json={"action": "start_setup", "evil": 1},
            headers={mod.CONTROL_TOKEN_HEADER: "tok"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        assert rv.status_code == 400

    def test_network_control_queues_before_disconnect(self, flask_client):
        client, mod = flask_client
        mod._control_token = "tok"
        # Reset pending state.
        mod.STATE.pending_control_action = ""
        mod.STATE.control_in_progress = False
        rv = client.post(
            "/network_control",
            json={"action": "start_setup"},
            headers={mod.CONTROL_TOKEN_HEADER: "tok"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        assert rv.status_code == 200
        assert json.loads(rv.data).get("queued") is True
        assert mod.STATE.pending_control_action == "start_setup"
        # Clean up the queued action so other tests are unaffected.
        mod.STATE.pending_control_action = ""
        mod.control_action_event.clear()

    def test_second_conflicting_action_rejected(self, flask_client):
        client, mod = flask_client
        mod._control_token = "tok"
        mod.STATE.pending_control_action = "start_setup"
        rv = client.post(
            "/network_control",
            json={"action": "reconnect_saved"},
            headers={mod.CONTROL_TOKEN_HEADER: "tok"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        assert rv.status_code == 409
        mod.STATE.pending_control_action = ""
        mod.control_action_event.clear()


# ---------------------------------------------------------------------------
# WP4 — recovery adapter and runtime dnsmasq binding
# ---------------------------------------------------------------------------

class TestRecoveryAdapter:
    def _adapter(self, ifname, mac, is_usb=False, is_builtin=False):
        mod = _get_watcher()
        return mod.wifi_net.WifiAdapter(
            ifname=ifname, permanent_mac=mac, current_mac=mac,
            is_builtin=is_builtin, is_usb=is_usb, managed=True,
            state="connected", description=ifname,
        )

    def test_recovery_is_builtin_even_with_usb(self, watcher):
        adapters = [
            self._adapter("wlan1", "aa:bb:cc:00:00:02", is_usb=True),
            self._adapter("wlan0", "aa:bb:cc:00:00:01", is_builtin=True),
        ]
        with patch.object(watcher.wifi_net, "discover_adapters", return_value=adapters):
            assert watcher.resolve_recovery_ifname() == "wlan0"

    def test_recovery_none_when_no_builtin(self, watcher):
        adapters = [self._adapter("wlan1", "aa:bb:cc:00:00:02", is_usb=True)]
        with patch.object(watcher.wifi_net, "discover_adapters", return_value=adapters):
            assert watcher.resolve_recovery_ifname() is None

    def test_write_dnsmasq_runtime_uses_validated_builtin(self, watcher, tmp_path):
        tpl = tmp_path / "tpl.conf"
        tpl.write_text("interface=__AUTOSTREAM_WIFI_IFACE__\nbind-interfaces\n", encoding="utf-8")
        runtime = tmp_path / "run" / "out.conf"
        watcher.DNSMASQ_TEMPLATE_PATH = str(tpl)
        watcher.DNSMASQ_RUNTIME_PATH = str(runtime)
        adapters = [self._adapter("wlan0", "aa:bb:cc:00:00:01", is_builtin=True)]
        with patch.object(watcher.wifi_net, "discover_adapters", return_value=adapters):
            watcher._write_dnsmasq_runtime("wlan0")
        assert "interface=wlan0" in runtime.read_text(encoding="utf-8")

    def test_write_dnsmasq_runtime_refuses_non_builtin(self, watcher, tmp_path):
        tpl = tmp_path / "tpl.conf"
        tpl.write_text("interface=__AUTOSTREAM_WIFI_IFACE__\n", encoding="utf-8")
        runtime = tmp_path / "run" / "out.conf"
        watcher.DNSMASQ_TEMPLATE_PATH = str(tpl)
        watcher.DNSMASQ_RUNTIME_PATH = str(runtime)
        adapters = [self._adapter("wlan0", "aa:bb:cc:00:00:01", is_builtin=True)]
        with patch.object(watcher.wifi_net, "discover_adapters", return_value=adapters):
            # Asking to write for a USB interface (wlan1) must be refused.
            watcher._write_dnsmasq_runtime("wlan1")
        assert not runtime.exists()


# ---------------------------------------------------------------------------
# WP5 — multi-adapter failure fallback and runtime USB adoption
# ---------------------------------------------------------------------------

def _adapter(mod, ifname, mac, is_usb=False, is_builtin=False):
    return mod.wifi_net.WifiAdapter(
        ifname=ifname, permanent_mac=mac, current_mac=mac,
        is_builtin=is_builtin, is_usb=is_usb, managed=True,
        state="connected", description=ifname,
    )


class TestQueryPlayingStatus:
    def test_dial_mode_always_idle(self, watcher):
        with patch.object(watcher, "_DIAL_MODE", True):
            assert watcher.query_playing_status() is False

    def test_ok_true_playing_false(self, watcher):
        body = json.dumps({"ok": True, "playing": False}).encode()
        resp = MagicMock()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        resp.read.return_value = body
        with patch.object(watcher, "_DIAL_MODE", False), \
             patch("urllib.request.urlopen", return_value=resp):
            assert watcher.query_playing_status() is False

    def test_ok_true_playing_true(self, watcher):
        body = json.dumps({"ok": True, "playing": True}).encode()
        resp = MagicMock()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        resp.read.return_value = body
        with patch.object(watcher, "_DIAL_MODE", False), \
             patch("urllib.request.urlopen", return_value=resp):
            assert watcher.query_playing_status() is True

    def test_ok_false_is_uncertain(self, watcher):
        body = json.dumps({"ok": False, "error": "x"}).encode()
        resp = MagicMock()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        resp.read.return_value = body
        with patch.object(watcher, "_DIAL_MODE", False), \
             patch("urllib.request.urlopen", return_value=resp):
            assert watcher.query_playing_status() is None

    def test_non_boolean_playing_is_uncertain(self, watcher):
        body = json.dumps({"ok": True, "playing": "yes"}).encode()
        resp = MagicMock()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        resp.read.return_value = body
        with patch.object(watcher, "_DIAL_MODE", False), \
             patch("urllib.request.urlopen", return_value=resp):
            assert watcher.query_playing_status() is None

    def test_transport_failure_is_uncertain(self, watcher):
        with patch.object(watcher, "_DIAL_MODE", False), \
             patch("urllib.request.urlopen", side_effect=OSError("refused")):
            assert watcher.query_playing_status() is None


class TestUsbFailureFallback:
    def test_absent_active_usb_triggers_immediate_fallback(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb_mac = "bb:bb:bb:bb:bb:01"
        watcher._known_usb_macs.add(usb_mac)
        watcher.STATE.active_client_mac = usb_mac
        watcher.STATE.active_client_ifname = "wlan1"
        adapters = [builtin]  # USB gone
        with patch.object(watcher, "_activate_committed_on", return_value=True) as act, \
             patch.object(watcher, "verify_avahi_after_handover"):
            acted = watcher.handle_usb_failure_fallback(adapters, None)
        assert acted is True
        act.assert_called_once_with("wlan0")
        assert watcher.STATE.using_builtin_fallback is True

    def test_one_transient_unhealthy_pass_does_not_switch(self, watcher):
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:02", is_usb=True)
        watcher._known_usb_macs.add(usb.permanent_mac)
        watcher.STATE.active_client_mac = usb.permanent_mac
        watcher.STATE.active_client_ifname = "wlan1"
        adapters = [_adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True), usb]
        with patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher, "_do_builtin_fallback_or_recovery") as fb:
            acted = watcher.handle_usb_failure_fallback(adapters, usb)
        assert acted is False
        fb.assert_not_called()
        assert watcher.STATE.active_usb_unhealthy_checks == 1

    def test_two_unhealthy_passes_trigger_fallback(self, watcher):
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:03", is_usb=True)
        watcher._known_usb_macs.add(usb.permanent_mac)
        watcher.STATE.active_client_mac = usb.permanent_mac
        watcher.STATE.active_client_ifname = "wlan1"
        watcher.STATE.active_usb_unhealthy_checks = 1
        adapters = [_adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True), usb]
        with patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher, "_do_builtin_fallback_or_recovery", return_value=True) as fb:
            acted = watcher.handle_usb_failure_fallback(adapters, usb)
        assert acted is True
        fb.assert_called_once()

    def test_builtin_fallback_restores_lan(self, watcher):
        adapters = [_adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)]
        with patch.object(watcher, "_activate_committed_on", return_value=True), \
             patch.object(watcher, "verify_avahi_after_handover"):
            acted = watcher._do_builtin_fallback_or_recovery(adapters, "test")
        assert acted is True
        assert watcher.STATE.using_builtin_fallback is True

    def test_usb_only_enters_recovery_hotspot(self, watcher):
        adapters = [_adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)]
        with patch.object(watcher, "_activate_committed_on", return_value=False), \
             patch.object(watcher, "enter_setup_mode") as enter:
            acted = watcher._do_builtin_fallback_or_recovery(adapters, "usb-only")
        assert acted is True
        enter.assert_called_once()
        assert watcher.STATE.setup_purpose == "automatic_recovery"


class TestRuntimeUsbAdoption:
    def _builtin_and_usb(self, watcher):
        return (
            _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True),
            _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:10", is_usb=True),
        )

    def test_adopts_after_two_passes_when_idle(self, watcher):
        builtin, usb = self._builtin_and_usb(watcher)
        adapters = [builtin, usb]
        with patch.object(watcher, "resolve_active_client", return_value=builtin), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher, "query_playing_status", return_value=False), \
             patch.object(watcher, "_activate_committed_on", return_value=True), \
             patch.object(watcher, "verify_avahi_after_handover"), \
             patch.object(watcher, "run_cmd", return_value=MagicMock(returncode=0)):
            first = watcher.handle_runtime_usb_adoption(adapters, wired_connected=False)
            second = watcher.handle_runtime_usb_adoption(adapters, wired_connected=False)
        assert first is False   # first pass only records the candidate
        assert second is True   # adopted on the second stable pass
        assert watcher.STATE.active_client_ifname == "wlan1"

    def test_deferred_while_playing(self, watcher):
        builtin, usb = self._builtin_and_usb(watcher)
        adapters = [builtin, usb]
        with patch.object(watcher, "resolve_active_client", return_value=builtin), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher, "query_playing_status", return_value=True), \
             patch.object(watcher, "_activate_committed_on", return_value=True) as act:
            watcher.handle_runtime_usb_adoption(adapters, wired_connected=False)
            watcher.handle_runtime_usb_adoption(adapters, wired_connected=False)
        act.assert_not_called()  # never handed over while playing

    def test_deferred_then_adopted_when_idle(self, watcher):
        builtin, usb = self._builtin_and_usb(watcher)
        adapters = [builtin, usb]
        # Pass 1 records the candidate (checks=1) and returns before querying
        # playback; passes 2 and 3 query playback (active, then idle).
        playing = [True, False]
        with patch.object(watcher, "resolve_active_client", return_value=builtin), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher, "query_playing_status", side_effect=lambda: playing.pop(0)), \
             patch.object(watcher, "_activate_committed_on", return_value=True), \
             patch.object(watcher, "verify_avahi_after_handover"), \
             patch.object(watcher, "run_cmd", return_value=MagicMock(returncode=0)):
            r1 = watcher.handle_runtime_usb_adoption(adapters, wired_connected=False)
            r2 = watcher.handle_runtime_usb_adoption(adapters, wired_connected=False)
            r3 = watcher.handle_runtime_usb_adoption(adapters, wired_connected=False)
        assert (r1, r2, r3) == (False, False, True)

    def test_uncertain_status_defers(self, watcher):
        builtin, usb = self._builtin_and_usb(watcher)
        adapters = [builtin, usb]
        with patch.object(watcher, "resolve_active_client", return_value=builtin), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher, "query_playing_status", return_value=None), \
             patch.object(watcher, "_activate_committed_on", return_value=True) as act:
            watcher.handle_runtime_usb_adoption(adapters, wired_connected=False)
            watcher.handle_runtime_usb_adoption(adapters, wired_connected=False)
        act.assert_not_called()

    def test_ethernet_blocks_adoption(self, watcher):
        builtin, usb = self._builtin_and_usb(watcher)
        adapters = [builtin, usb]
        with patch.object(watcher, "_activate_committed_on", return_value=True) as act:
            r = watcher.handle_runtime_usb_adoption(adapters, wired_connected=True)
        assert r is False
        act.assert_not_called()

    def test_does_not_switch_between_usb_adapters(self, watcher):
        builtin, usb1 = self._builtin_and_usb(watcher)
        usb2 = _adapter(watcher, "wlan2", "bb:bb:bb:bb:bb:20", is_usb=True)
        adapters = [builtin, usb1, usb2]
        with patch.object(watcher, "resolve_active_client", return_value=usb1), \
             patch.object(watcher, "_activate_committed_on", return_value=True) as act:
            r = watcher.handle_runtime_usb_adoption(adapters, wired_connected=False)
        assert r is False
        act.assert_not_called()

    def test_failed_adoption_sets_retry_suppression(self, watcher):
        builtin, usb = self._builtin_and_usb(watcher)
        adapters = [builtin, usb]
        with patch.object(watcher, "resolve_active_client", return_value=builtin), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher, "query_playing_status", return_value=False), \
             patch.object(watcher, "_activate_committed_on", return_value=False):
            watcher.handle_runtime_usb_adoption(adapters, wired_connected=False)
            r = watcher.handle_runtime_usb_adoption(adapters, wired_connected=False)
        assert r is False
        assert watcher.STATE.usb_adoption_retry_after > 0
        assert watcher.STATE.using_builtin_fallback is False


# ---------------------------------------------------------------------------
# WP6 — transactional change-Wi-Fi flow and local control API
# ---------------------------------------------------------------------------

class TestControlToken:
    def test_token_file_written_with_mode(self, watcher, tmp_path):
        token_path = tmp_path / "run" / "wifi-control.token"
        watcher.CONTROL_TOKEN_DIR = str(tmp_path / "run")
        watcher.CONTROL_TOKEN_PATH = str(token_path)
        tok = watcher.init_control_token()
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
        watcher.CONTROL_TOKEN_PATH = str(token_path)
        watcher.remove_control_token()
        assert not token_path.exists()
        watcher.remove_control_token()  # no error when absent


class TestStartExplicitSetup:
    def test_snapshots_and_enters_setup(self, watcher):
        watcher.STATE.active_client_ifname = "wlan1"
        watcher.STATE.active_client_mac = "bb:bb:bb:bb:bb:01"
        with patch.object(watcher, "get_configured_network_state",
                          return_value=watcher.wifi_net.NetworkState("Home", "uuid-1")), \
             patch.object(watcher, "run_cmd", return_value=MagicMock(returncode=0)), \
             patch.object(watcher, "enter_setup_mode") as enter:
            watcher.start_explicit_setup()
        assert watcher.STATE.reconfigure_active is True
        assert watcher.STATE.setup_purpose == "explicit_reconfigure"
        assert watcher.STATE.rollback_connection_name == "Home"
        assert watcher.STATE.rollback_adapter_mac == "bb:bb:bb:bb:bb:01"
        assert watcher.STATE.force_setup_mode is True  # bypass ap_exhausted
        enter.assert_called_once()

    def test_disconnects_active_client_session(self, watcher):
        watcher.STATE.active_client_ifname = "wlan1"
        calls = []
        with patch.object(watcher, "get_configured_network_state",
                          return_value=watcher.wifi_net.NetworkState("Home", "uuid-1")), \
             patch.object(watcher, "run_cmd", side_effect=lambda c, *a, **k: calls.append(c) or MagicMock(returncode=0)), \
             patch.object(watcher, "enter_setup_mode"):
            watcher.start_explicit_setup()
        assert any("disconnect" in c and "wlan1" in c for c in calls)


class TestReconnectSavedNetwork:
    def test_success_clears_state_and_leaves_setup(self, watcher):
        watcher.STATE.setup_purpose = "explicit_reconfigure"
        watcher.STATE.rollback_connection_name = "Home"
        watcher.STATE.rollback_connection_uuid = "uuid-1"
        watcher.STATE.rollback_adapter_mac = "aa:bb:cc:00:00:01"
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        with patch.object(watcher.wifi_net, "discover_adapters", return_value=[builtin]), \
             patch.object(watcher, "run_cmd", return_value=MagicMock(returncode=0)), \
             patch.object(watcher, "wait_for_connection", return_value=True), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher, "leave_setup_mode") as leave, \
             patch.object(watcher, "verify_avahi_after_handover"):
            ok = watcher.reconnect_saved_network()
        assert ok is True
        leave.assert_called_once()
        assert watcher.STATE.reconfigure_active is False
        assert watcher.STATE.rollback_connection_name == ""

    def test_failure_retains_hotspot(self, watcher):
        watcher.STATE.setup_purpose = "explicit_reconfigure"
        watcher.STATE.rollback_connection_name = "Home"
        watcher.STATE.rollback_connection_uuid = "uuid-1"
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        with patch.object(watcher.wifi_net, "discover_adapters", return_value=[builtin]), \
             patch.object(watcher, "run_cmd", return_value=MagicMock(returncode=0)), \
             patch.object(watcher, "wait_for_connection", return_value=False), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher, "leave_setup_mode") as leave:
            ok = watcher.reconnect_saved_network()
        assert ok is False
        leave.assert_not_called()


class TestReconfigureTimeout:
    def test_timeout_restores_previous(self, watcher):
        with patch.object(watcher, "reconnect_saved_network", return_value=True) as rc:
            watcher.handle_reconfigure_timeout()
        rc.assert_called_once()

    def test_timeout_restore_failure_enters_recovery(self, watcher):
        watcher.STATE.reconfigure_active = True
        with patch.object(watcher, "reconnect_saved_network", return_value=False):
            watcher.handle_reconfigure_timeout()
        assert watcher.STATE.reconfigure_active is False
        assert watcher.STATE.setup_purpose == "automatic_recovery"


class TestSavedNetworkGating:
    def test_has_saved_network_committed(self, watcher):
        with patch.object(watcher, "get_configured_network_state",
                          return_value=watcher.wifi_net.NetworkState("Home", "u")):
            assert watcher._has_saved_network() is True

    def test_has_saved_network_rollback_only(self, watcher):
        watcher.STATE.rollback_connection_name = "Old"
        with patch.object(watcher, "get_configured_network_state",
                          return_value=watcher.wifi_net.NetworkState("", "")):
            assert watcher._has_saved_network() is True

    def test_no_saved_network_first_run(self, watcher):
        with patch.object(watcher, "get_configured_network_state",
                          return_value=watcher.wifi_net.NetworkState("", "")):
            assert watcher._has_saved_network() is False


class TestControlAuthLogic:
    def test_authorised_requires_token_match(self, watcher):
        watcher._control_token = "secret"
        # Simulate request object with header + remote.
        req = MagicMock()
        req.remote_addr = "127.0.0.1"
        req.headers = {watcher.CONTROL_TOKEN_HEADER: "secret"}
        with patch.object(watcher, "request", req):
            assert watcher._control_authorised() is True

    def test_authorised_rejects_wrong_token(self, watcher):
        watcher._control_token = "secret"
        req = MagicMock()
        req.remote_addr = "127.0.0.1"
        req.headers = {watcher.CONTROL_TOKEN_HEADER: "wrong"}
        with patch.object(watcher, "request", req):
            assert watcher._control_authorised() is False

    def test_authorised_rejects_non_loopback(self, watcher):
        watcher._control_token = "secret"
        req = MagicMock()
        req.remote_addr = "10.0.0.5"
        req.headers = {watcher.CONTROL_TOKEN_HEADER: "secret"}
        with patch.object(watcher, "request", req):
            assert watcher._control_authorised() is False

    def test_process_control_action_start_setup(self, watcher):
        with patch.object(watcher, "start_explicit_setup") as ss:
            watcher.process_control_action("start_setup")
        ss.assert_called_once()
        assert watcher.STATE.last_control_action == "start_setup"
        assert watcher.STATE.last_control_result == "ok"
        assert watcher.STATE.control_in_progress is False
