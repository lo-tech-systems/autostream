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

import contextlib
import importlib
import importlib.util
import json
import os
import sys
import threading
from contextlib import ExitStack
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import ModuleType, SimpleNamespace
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
        # Register before exec so the module can reference itself for the
        # split-module seam (wifi_status/wifi_recovery take the watcher module).
        sys.modules[alias] = mod

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

        # wifi_web is a sibling that binds Flask symbols at import; drop any
        # cached copy so the watcher's `import wifi_web` re-binds against the
        # flask currently in sys.modules (stubbed here). The watcher keeps its
        # own reference as `mod.wifi_web`.
        sys.modules.pop("wifi_web", None)

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


@pytest.fixture(autouse=True)
def _restore_root_log_level():
    """Save/restore the root logger level so log-level tests don't leak (WP7)."""
    import logging as _logging
    saved = _logging.getLogger().level
    yield
    _logging.getLogger().setLevel(saved)


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
    sys.modules[alias] = flask_mod

    # Stub only the non-Flask external deps.
    from unittest.mock import MagicMock as MM
    sysutils_stub = MM()
    sysutils_stub.run_cmd = MM(return_value=MM(returncode=0, stdout="", stderr=""))
    sysutils_stub.prime_gateway = MM()
    sysutils_stub.reboot_system = MM()
    sysutils_stub.get_system_hostname = MM(return_value="autostream")

    saved_sysutils = sys.modules.get("autostream_sysutils")
    sys.modules["autostream_sysutils"] = sysutils_stub
    # Drop any cached wifi_web so it re-binds against the real flask used here
    # (an earlier unit load may have bound it to the stubbed flask). The fresh
    # watcher keeps its own reference as `flask_mod.wifi_web`.
    sys.modules.pop("wifi_web", None)
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

class TestWiredPathHealth:
    def test_wired_carrier_ifnames_reports_carrier(self, watcher, tmp_path):
        base = tmp_path / "net" / "eth0"
        base.mkdir(parents=True)
        (base / "carrier").write_text("1\n", encoding="utf-8")

        assert watcher.wired_carrier_ifnames(str(tmp_path / "net")) == ["eth0"]

    def test_carrier_without_ipv4_is_not_healthy(self, watcher):
        with patch.object(watcher, "wired_carrier_ifnames", return_value=["eth0"]), \
             patch.object(watcher.wifi_net, "interface_has_usable_ipv4", return_value=False):
            assert watcher.is_wired_connected() is True
            assert watcher.is_wired_path_healthy("eth0") is False
            assert watcher.any_wired_path_healthy() is False

    def test_carrier_with_usable_ipv4_is_healthy(self, watcher):
        with patch.object(watcher, "wired_carrier_ifnames", return_value=["eth0"]), \
             patch.object(watcher.wifi_net, "interface_has_usable_ipv4", return_value=True):
            assert watcher.is_wired_path_healthy("eth0") is True
            assert watcher.any_wired_path_healthy() is True

    def test_first_healthy_wired_ifname_returns_carrier_with_ipv4(self, watcher):
        def has_ipv4(ifname):
            return ifname == "enp1s0"

        with patch.object(watcher, "wired_carrier_ifnames", return_value=["eth0", "enp1s0"]), \
             patch.object(watcher.wifi_net, "interface_has_usable_ipv4", side_effect=has_ipv4):
            assert watcher.first_healthy_wired_ifname() == "enp1s0"

    def test_first_healthy_wired_ifname_none_without_usable_ipv4(self, watcher):
        with patch.object(watcher, "wired_carrier_ifnames", return_value=["eth0"]), \
             patch.object(watcher.wifi_net, "interface_has_usable_ipv4", return_value=False):
            assert watcher.first_healthy_wired_ifname() is None

    def test_first_healthy_wired_ifname_none_without_carrier(self, watcher):
        with patch.object(watcher, "wired_carrier_ifnames", return_value=[]):
            assert watcher.first_healthy_wired_ifname() is None


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
            watcher.enter_setup_mode(watcher.HotspotPurpose.FIRST_RUN, "test")
        assert watcher.STATE.setup_mode is True
        assert watcher.STATE.hotspot.purpose is watcher.HotspotPurpose.FIRST_RUN

    def test_enter_creates_ap_flag_file(self, watcher, tmp_path):
        flag = tmp_path / "apmode"
        watcher.AP_MODE_FLAG_PATH = str(flag)
        with patch.object(watcher, "start_ap_mode"), \
             patch.object(watcher, "stop_ap_mode"):
            watcher.enter_setup_mode(watcher.HotspotPurpose.FIRST_RUN, "test")
        assert flag.exists()

    def test_enter_is_idempotent(self, watcher, tmp_path):
        flag = tmp_path / "apmode"
        watcher.AP_MODE_FLAG_PATH = str(flag)
        with patch.object(watcher, "start_ap_mode") as mock_start, \
             patch.object(watcher, "stop_ap_mode"):
            watcher.enter_setup_mode(watcher.HotspotPurpose.FIRST_RUN, "first")
            watcher.enter_setup_mode(watcher.HotspotPurpose.MANUAL, "second")
        # start_ap_mode called only once; the original session is kept.
        assert mock_start.call_count == 1
        assert watcher.STATE.hotspot.purpose is watcher.HotspotPurpose.FIRST_RUN

    def test_leave_sets_setup_mode_false(self, watcher, tmp_path):
        flag = tmp_path / "apmode"
        flag.write_text("1\n")
        watcher.AP_MODE_FLAG_PATH = str(flag)
        watcher.STATE.setup_mode = True
        with patch.object(watcher, "start_ap_mode"), \
             patch.object(watcher, "stop_ap_mode"):
            watcher.leave_setup_mode("done")
        assert watcher.STATE.setup_mode is False

    def test_leave_rebases_active_path_timer(self, watcher, tmp_path):
        flag = tmp_path / "apmode"
        flag.write_text("1\n")
        watcher.AP_MODE_FLAG_PATH = str(flag)
        watcher.STATE.setup_mode = True
        watcher.STATE.last_active_path_seen = 1.0
        with patch.object(watcher, "start_ap_mode"), \
             patch.object(watcher, "stop_ap_mode"), \
             patch("time.monotonic", return_value=123.0):
            watcher.leave_setup_mode("done")
        assert watcher.STATE.last_active_path_seen == 123.0

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

    def test_recovery_hotspot_always_enterable_no_once_per_boot_budget(self, watcher, tmp_path):
        # Defect 2: there is no ap_exhausted latch any more.  A hotspot that was
        # entered and left earlier this boot can be re-entered immediately.
        flag = tmp_path / "apmode"
        watcher.AP_MODE_FLAG_PATH = str(flag)
        assert not hasattr(watcher.STATE, "ap_exhausted")
        assert not hasattr(watcher.STATE, "force_setup_mode")
        with patch.object(watcher, "start_ap_mode") as mock_start, \
             patch.object(watcher, "stop_ap_mode"):
            watcher.enter_setup_mode(watcher.HotspotPurpose.FIRST_RUN, "first")
            watcher.leave_setup_mode("done")
            watcher.enter_setup_mode(watcher.HotspotPurpose.USB_LOSS_RECOVERY, "later loss")
        assert mock_start.call_count == 2
        assert watcher.STATE.setup_mode is True
        assert watcher.STATE.hotspot.purpose is watcher.HotspotPurpose.USB_LOSS_RECOVERY

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

    def test_recovery_usb_fallback_when_no_builtin(self, watcher):
        """On hardware with no built-in radio (e.g. Pi 2), a single USB adapter
        is used as the hotspot interface."""
        adapters = [self._adapter("wlan1", "aa:bb:cc:00:00:02", is_usb=True)]
        with patch.object(watcher.wifi_net, "discover_adapters", return_value=adapters):
            assert watcher.resolve_recovery_ifname() == "wlan1"

    def test_recovery_uses_non_active_usb_when_multiple_usb_no_builtin(self, watcher):
        """With multiple USB adapters and no built-in, avoid the active client."""
        adapters = [
            self._adapter("wlan1", "aa:bb:cc:00:00:02", is_usb=True),
            self._adapter("wlan2", "aa:bb:cc:00:00:03", is_usb=True),
        ]
        watcher.STATE.active_client_ifname = "wlan1"
        with patch.object(watcher.wifi_net, "discover_adapters", return_value=adapters):
            assert watcher.resolve_recovery_ifname() == "wlan2"

    def test_recovery_uses_first_usb_when_multiple_usb_none_active(self, watcher):
        adapters = [
            self._adapter("wlan2", "aa:bb:cc:00:00:03", is_usb=True),
            self._adapter("wlan1", "aa:bb:cc:00:00:02", is_usb=True),
        ]
        with patch.object(watcher.wifi_net, "discover_adapters", return_value=adapters):
            assert watcher.resolve_recovery_ifname() == "wlan1"

    def test_recovery_none_when_no_adapters(self, watcher):
        with patch.object(watcher.wifi_net, "discover_adapters", return_value=[]):
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

    def test_write_dnsmasq_runtime_accepts_usb_when_no_builtin(self, watcher, tmp_path):
        """On Pi 2 (no built-in), the sole USB adapter is the hotspot adapter
        and its ifname must be accepted by _write_dnsmasq_runtime."""
        tpl = tmp_path / "tpl.conf"
        tpl.write_text("interface=__AUTOSTREAM_WIFI_IFACE__\nbind-interfaces\n", encoding="utf-8")
        runtime = tmp_path / "run" / "out.conf"
        watcher.DNSMASQ_TEMPLATE_PATH = str(tpl)
        watcher.DNSMASQ_RUNTIME_PATH = str(runtime)
        adapters = [self._adapter("wlan1", "aa:bb:cc:00:00:02", is_usb=True)]
        with patch.object(watcher.wifi_net, "discover_adapters", return_value=adapters):
            watcher._write_dnsmasq_runtime("wlan1")
        assert "interface=wlan1" in runtime.read_text(encoding="utf-8")

    def test_write_dnsmasq_runtime_refuses_non_hotspot_adapter(self, watcher, tmp_path):
        tpl = tmp_path / "tpl.conf"
        tpl.write_text("interface=__AUTOSTREAM_WIFI_IFACE__\n", encoding="utf-8")
        runtime = tmp_path / "run" / "out.conf"
        watcher.DNSMASQ_TEMPLATE_PATH = str(tpl)
        watcher.DNSMASQ_RUNTIME_PATH = str(runtime)
        adapters = [self._adapter("wlan0", "aa:bb:cc:00:00:01", is_builtin=True)]
        with patch.object(watcher.wifi_net, "discover_adapters", return_value=adapters):
            # Built-in is wlan0; passing wlan1 must be refused.
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


def _facts_for(mod, adapters, active_client, *, wifi_cfg=True, wired_ok=False,
               wired_connected=False, now=1000.0):
    """Build a per-pass Facts snapshot for handler/apply tests."""
    return mod.Facts(
        wifi_configured=wifi_cfg, adapters=adapters, wired_connected=wired_connected,
        wired_ok=wired_ok, active_client=active_client, addresses={}, taken_at=now,
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


class TestNoIpLedgerAndDiagnosis:
    """WP5b — no-IP/adoption-failure ledger, escalating back-off, defect 3 status."""

    MAC = "bb:bb:bb:bb:bb:21"

    def test_back_off_escalates_and_then_stops(self, watcher):
        wr = watcher.wifi_recovery
        # Each failure escalates the back-off; after NOIP_STOP_AFTER it is
        # suppressed indefinitely (retry_after == inf).
        prev = 0.0
        for i in range(1, wr.NOIP_STOP_AFTER):
            wr.record_noip_failure(watcher, self.MAC, now=0.0)
            led = watcher.STATE.adapter_noip_ledgers[self.MAC]
            assert led["count"] == i
            assert led["retry_after"] >= prev
            prev = led["retry_after"]
        wr.record_noip_failure(watcher, self.MAC, now=0.0)
        assert watcher.STATE.adapter_noip_ledgers[self.MAC]["retry_after"] == float("inf")
        assert wr.noip_retry_suppressed(watcher, self.MAC, now=1e12) is True

    def test_clear_resets_ledger(self, watcher):
        wr = watcher.wifi_recovery
        wr.record_noip_failure(watcher, self.MAC, now=0.0)
        wr.clear_noip_failures(watcher, self.MAC)
        assert wr.noip_failure_count(watcher, self.MAC) == 0

    def test_mac_less_adapter_uses_stable_id_fallback(self, watcher):
        # An adapter with no permanent MAC keys the no-IP ledger by its stable_id
        # (ifname fallback) — it must not silently lose the ledger/back-off/status.
        usb = _adapter(watcher, "wlan7", "", is_usb=True)
        assert usb.permanent_mac == ""
        assert usb.stable_id == "wlan7"
        watcher.wifi_recovery.record_noip_failure(watcher, usb.stable_id, now=100.0)
        addrs = {}
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value=addrs), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher.wifi_net, "read_operstate", return_value="up"), \
             patch.object(watcher.wifi_net, "default_gateway_ipv4", return_value=""), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.build_network_status_snapshot([usb], wired_connected=False, wired_ok=False)
        rec = snap["adapters"][0]
        assert rec["health"]["state"] == "degraded_no_ip"
        assert rec["policy"]["warning"] == "no_ip_address"

    def test_suppressed_spare_published_as_held_back(self, watcher):
        # C-WP3: a no-IP-suppressed spare is a distinct held-back state (not the
        # transient degraded_no_ip), carries the held_back marker, and is
        # surfaced even with carrier down.
        usb = _adapter(watcher, "wlan0", "dc:62:79:91:4d:d6", is_usb=True)
        for _ in range(watcher.wifi_recovery.NOIP_STOP_AFTER):
            watcher.wifi_recovery.record_noip_failure(watcher, usb.permanent_mac, now=100.0)
        assert watcher.wifi_recovery.noip_retry_suppressed(watcher, usb.permanent_mac, 100.0) is True
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value={}), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=True), \
             patch.object(watcher.wifi_net, "read_operstate", return_value="down"), \
             patch.object(watcher.wifi_net, "default_gateway_ipv4", return_value=""), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.build_network_status_snapshot([usb], wired_connected=False, wired_ok=False)
        rec = snap["adapters"][0]
        assert rec["health"]["state"] == "no_ip_held_back"   # not link_down / degraded_no_ip
        assert rec["policy"]["warning"] == "no_ip_held_back"
        assert rec["policy"]["held_back"] is True

    def test_device_publishes_builtin_fallback_marker(self, watcher):
        # C-WP3: the demoted-from-active marker — device reports it is running on
        # the on-board radio as a fallback.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        watcher.STATE.using_builtin_fallback = True
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value={}), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher.wifi_net, "read_operstate", return_value="up"), \
             patch.object(watcher.wifi_net, "default_gateway_ipv4", return_value=""), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.build_network_status_snapshot([builtin], wired_connected=False, wired_ok=False)
        assert snap["device"]["using_builtin_fallback"] is True

    def test_prune_drops_absent_macs(self, watcher):
        wr = watcher.wifi_recovery
        wr.record_noip_failure(watcher, self.MAC, now=0.0)
        wr.prune_noip_ledgers(watcher, set())  # MAC no longer present
        assert wr.noip_failure_count(watcher, self.MAC) == 0

    def test_no_ip_adapter_classified_degraded_no_ip(self, watcher):
        usb = _adapter(watcher, "wlan0", "dc:62:79:91:4d:d6", is_usb=True)
        watcher.wifi_recovery.record_noip_failure(watcher, usb.permanent_mac, now=100.0)
        addrs = {}
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value=addrs), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher.wifi_net, "read_operstate", return_value="up"), \
             patch.object(watcher.wifi_net, "default_gateway_ipv4", return_value=""), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.build_network_status_snapshot([usb], wired_connected=False, wired_ok=False)
        rec = snap["adapters"][0]
        assert rec["health"]["state"] == "degraded_no_ip"
        assert rec["health"]["checks"] >= 1
        assert rec["health"]["reason"] == "associated_no_ip"
        assert rec["policy"]["warning"] == "no_ip_address"

    def test_idle_unusable_usb_does_not_degrade_online_appliance(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:31", is_usb=True)
        watcher.STATE.active_client_ifname = "wlan0"
        watcher.STATE.active_client_mac = builtin.permanent_mac
        addrs = {"wlan0": [{"family": "ipv4", "address": "192.168.1.42",
                            "prefixlen": 24, "scope": "global"}]}

        def _health(ifname, *a, **k):
            return ifname == "wlan0"  # built-in healthy, idle USB not

        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value=addrs), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher.wifi_net, "read_operstate", return_value="up"), \
             patch.object(watcher.wifi_net, "default_gateway_ipv4", return_value="192.168.1.1"), \
             patch.object(watcher, "is_wifi_client_healthy", side_effect=_health), \
             patch.object(watcher, "is_gateway_reachable", return_value=True), \
             patch.object(watcher, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.build_network_status_snapshot(
                [builtin, usb], wired_connected=False, wired_ok=False)
        # The idle, unattributed USB must not flip the device to degraded.
        assert snap["device"]["state"] == "online"


class TestAdapterOverlayEvents:
    """WP5a / C2-WP3 — the overlay is now a pure classifier over the debounced
    connectivity verdict (conn_ok): it fires ClientFailed only once the loop's
    hysteresis has condemned the path, and only when the condemnation is
    attributable to the recorded USB client.  The 2-pass debounce lives in the
    hysteresis (see TestConnectivityHysteresis), not here."""

    def _diagnose(self, watcher, adapters, active_client, *, conn_ok=False,
                  prev_mac="", prev_ifname=""):
        return watcher.wifi_recovery.diagnose_client_failure(
            watcher, adapters, active_client, conn_ok, prev_mac, prev_ifname)

    def test_absent_usb_returns_client_failed_absent(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb_mac = "bb:bb:bb:bb:bb:01"
        watcher._known_usb_macs.add(usb_mac)
        event = self._diagnose(watcher, [builtin], None,
                               conn_ok=False, prev_mac=usb_mac, prev_ifname="wlan1")
        assert isinstance(event, watcher.ClientFailed)
        assert event.reason == "absent"
        assert event.mac == usb_mac
        assert event.ifname == "wlan1"
        assert event.has_alt_path is True  # built-in present

    def test_no_alt_path_when_no_builtin(self, watcher):
        usb_mac = "bb:bb:bb:bb:bb:01"
        watcher._known_usb_macs.add(usb_mac)
        event = self._diagnose(watcher, [], None,  # USB gone, no built-in
                               conn_ok=False, prev_mac=usb_mac, prev_ifname="wlan1")
        assert event.reason == "absent"
        assert event.has_alt_path is False

    def test_conn_ok_true_returns_none(self, watcher):
        # The hysteresis has not (yet) condemned the path (e.g. a single transient
        # unhealthy pass held prior True): the overlay must not fire.
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:02", is_usb=True)
        watcher._known_usb_macs.add(usb.permanent_mac)
        adapters = [_adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True), usb]
        event = self._diagnose(watcher, adapters, usb,
                               conn_ok=True, prev_mac=usb.permanent_mac, prev_ifname="wlan1")
        assert event is None

    def test_condemned_present_usb_returns_no_ip(self, watcher):
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:03", is_usb=True)
        watcher._known_usb_macs.add(usb.permanent_mac)
        adapters = [_adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True), usb]
        event = self._diagnose(watcher, adapters, usb,
                               conn_ok=False, prev_mac=usb.permanent_mac, prev_ifname="wlan1")
        assert isinstance(event, watcher.ClientFailed)
        assert event.reason == "no_ip"
        assert event.ifname == "wlan1"

    def test_condemned_nm_disconnected_usb_uses_prev_ifname(self, watcher):
        # USB present but NM-disconnected: active_client is None, so the event
        # ifname comes from the recorded (prev) identity.
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:07", is_usb=True)
        watcher._known_usb_macs.add(usb.permanent_mac)
        adapters = [_adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True), usb]
        event = self._diagnose(watcher, adapters, None,
                               conn_ok=False, prev_mac=usb.permanent_mac, prev_ifname="wlan1")
        assert event.reason == "no_ip"       # present -> no_ip (not absent)
        assert event.ifname == "wlan1"

    def test_condemned_non_usb_returns_none(self, watcher):
        # The condemned path is a built-in client (prev_mac not a known USB):
        # reconnect / dead-PHY own it, not the USB-failure overlay.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        event = self._diagnose(watcher, [builtin], builtin,
                               conn_ok=False, prev_mac="aa:bb:cc:00:00:01", prev_ifname="wlan0")
        assert event is None

    def test_no_recorded_client_returns_none(self, watcher):
        # Condemned but nothing was ever recorded as active: nothing to attribute.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        event = self._diagnose(watcher, [builtin], None, conn_ok=False, prev_mac="")
        assert event is None

    def test_apply_client_failed_activates_via_ladder(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        facts = _facts_for(watcher, [builtin], None)
        event = watcher.ClientFailed(ifname="wlan1", mac="bb:bb:bb:bb:bb:05",
                                     reason="no_ip", has_alt_path=True)
        action = watcher.RecoveryAction(watcher.RecoveryKind.ACTIVATE_ONBOARD, ifname="wlan0")
        with patch.object(watcher, "gather_recovery_facts"), \
             patch.object(watcher, "next_recovery_action", return_value=action), \
             patch.object(watcher, "_apply_client_activation", return_value=True) as ap:
            acted = watcher.apply_client_failed(event, facts)
        assert acted is True
        ap.assert_called_once()

    def _rf_stub(self, watcher, *, onboard="", hotspot="", active=""):
        return watcher.RecoveryFacts(
            adapters_by_ifname={}, onboard_ifname=onboard, usb_ifnames=(),
            preferred_usb_ifname="", hotspot_ifname=hotspot, active_ifname=active,
            saved_configured=True, wired_ok=False, taken_at=1000.0,
        )

    def test_apply_client_failed_enters_hotspot_when_no_client_path(self, watcher):
        # C2-WP1: ENTER_HOTSPOT with no usable onboard falls to USB_LOSS_RECOVERY.
        facts = _facts_for(watcher, [], None)
        event = watcher.ClientFailed(ifname="wlan1", mac="bb:bb:bb:bb:bb:05",
                                     reason="absent", has_alt_path=False)
        action = watcher.RecoveryAction(watcher.RecoveryKind.ENTER_HOTSPOT,
                                        purpose=watcher.HotspotPurpose.BOOT_RECOVERY)
        with patch.object(watcher, "gather_recovery_facts",
                          return_value=self._rf_stub(watcher, onboard="")), \
             patch.object(watcher, "next_recovery_action", return_value=action), \
             patch.object(watcher, "_apply_client_activation") as ap, \
             patch.object(watcher, "enter_setup_mode") as enter:
            acted = watcher.apply_client_failed(event, facts)
        assert acted is True
        ap.assert_not_called()
        enter.assert_called_once()
        assert enter.call_args[0][0] is watcher.HotspotPurpose.USB_LOSS_RECOVERY

    def test_active_usb_no_ip_falls_back_to_onboard_not_hotspot(self, watcher):
        # Regression fix (C2-WP1 review): an active USB with carrier but no IP
        # yields a ladder HOLD("usb_active_no_ip").  apply_client_failed must
        # still try the usable onboard before the hotspot (real gather+ladder).
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:50", is_usb=True)
        facts = _facts_for(watcher, [builtin, usb], usb)  # USB is the active client
        event = watcher.ClientFailed(ifname="wlan1", mac="bb:bb:bb:bb:bb:50",
                                     reason="no_ip", has_alt_path=True)
        with patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher, "_apply_client_activation", return_value=True) as ap, \
             patch.object(watcher, "enter_setup_mode") as enter:
            acted = watcher.apply_client_failed(event, facts)
        assert acted is True
        enter.assert_not_called()          # onboard fallback, NOT straight to hotspot
        ap.assert_called_once()
        applied = ap.call_args[0][0]
        assert applied.kind is watcher.RecoveryKind.ACTIVATE_ONBOARD
        assert applied.ifname == "wlan0"

    def test_active_usb_no_ip_with_demoted_onboard_enters_hotspot(self, watcher):
        # The named delta under the real ladder: a no-IP-suppressed onboard is
        # gated out, so there is no usable onboard fallback -> hotspot.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:51", is_usb=True)
        watcher.STATE.adapter_noip_ledgers[builtin.stable_id] = {
            "count": watcher.wifi_recovery.NOIP_STOP_AFTER, "retry_after": float("inf")}
        facts = _facts_for(watcher, [builtin, usb], usb)
        event = watcher.ClientFailed(ifname="wlan1", mac="bb:bb:bb:bb:bb:51",
                                     reason="no_ip", has_alt_path=True)
        with patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher, "_apply_client_activation", return_value=False), \
             patch.object(watcher, "enter_setup_mode") as enter:
            acted = watcher.apply_client_failed(event, facts)
        assert acted is True
        enter.assert_called_once()
        assert enter.call_args[0][0] is watcher.HotspotPurpose.USB_LOSS_RECOVERY

    def test_apply_client_failed_onboard_success_sets_fallback(self, watcher):
        # Real _apply_client_activation path (ACTIVATE_ONBOARD with a USB also
        # present) sets using_builtin_fallback, matching the old builtin fallback.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:09", is_usb=True)
        facts = _facts_for(watcher, [builtin, usb], None)
        event = watcher.ClientFailed(ifname="wlan1", mac="bb:bb:bb:bb:bb:09",
                                     reason="no_ip", has_alt_path=True)
        action = watcher.RecoveryAction(watcher.RecoveryKind.ACTIVATE_ONBOARD, ifname="wlan0")
        with patch.object(watcher, "gather_recovery_facts"), \
             patch.object(watcher, "next_recovery_action", return_value=action), \
             patch.object(watcher, "_activate_committed_on", return_value=True), \
             patch.object(watcher.wifi_net, "discover_adapters", return_value=[builtin, usb]), \
             patch.object(watcher, "leave_setup_mode"), \
             patch.object(watcher, "verify_avahi_after_handover"):
            acted = watcher.apply_client_failed(event, facts)
        assert acted is True
        assert watcher.STATE.using_builtin_fallback is True


class TestUsbFailureFallback:
    """C2-WP3 — handle_usb_failure_fallback consumes the debounced verdict from the
    HealthContext (conn_ok + pre-set-active identity) and wires diagnose->apply."""

    def _hctx(self, watcher, facts, *, conn_ok, prev_mac="", prev_ifname=""):
        pre = watcher.PreFactsContext(now=facts.taken_at, boot_time=0.0, avahi_ok=True)
        fctx = watcher.FactsContext(pre, facts, lambda: False)
        return watcher.HealthContext(
            fctx, health_ifname="wlan1", wifi_connected=False, client_ok=False,
            conn_ok=conn_ok, active_path_ok=conn_ok,
            prev_active_mac=prev_mac, prev_active_ifname=prev_ifname)

    def test_absent_active_usb_triggers_immediate_fallback(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb_mac = "bb:bb:bb:bb:bb:01"
        watcher._known_usb_macs.add(usb_mac)
        facts = _facts_for(watcher, [builtin], None)  # USB gone
        hctx = self._hctx(watcher, facts, conn_ok=False, prev_mac=usb_mac, prev_ifname="wlan1")
        action = watcher.RecoveryAction(watcher.RecoveryKind.ACTIVATE_ONBOARD, ifname="wlan0")
        with patch.object(watcher, "gather_recovery_facts"), \
             patch.object(watcher, "next_recovery_action", return_value=action), \
             patch.object(watcher, "_apply_client_activation", return_value=True) as ap:
            acted = watcher.handle_usb_failure_fallback(hctx)
        assert acted is True
        ap.assert_called_once()

    def test_conn_ok_holds_off_fallback(self, watcher):
        # The hysteresis has not condemned the path yet (transient blip held True):
        # no fallback this pass.
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:02", is_usb=True)
        watcher._known_usb_macs.add(usb.permanent_mac)
        facts = _facts_for(watcher, [_adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True), usb], usb)
        hctx = self._hctx(watcher, facts, conn_ok=True,
                          prev_mac=usb.permanent_mac, prev_ifname="wlan1")
        with patch.object(watcher, "apply_client_failed") as ap:
            acted = watcher.handle_usb_failure_fallback(hctx)
        assert acted is False
        ap.assert_not_called()

    def test_condemned_usb_triggers_fallback(self, watcher):
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:03", is_usb=True)
        watcher._known_usb_macs.add(usb.permanent_mac)
        facts = _facts_for(watcher, [_adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True), usb], usb)
        hctx = self._hctx(watcher, facts, conn_ok=False,
                          prev_mac=usb.permanent_mac, prev_ifname="wlan1")
        with patch.object(watcher, "apply_client_failed", return_value=True) as ap:
            acted = watcher.handle_usb_failure_fallback(hctx)
        assert acted is True
        ap.assert_called_once()


class TestActivateClient:
    """Flag-matrix unit tests for the consolidated activate_client() (Phase A A-WP2)."""

    @contextlib.contextmanager
    def _harness(self, watcher, *, core_ok=True, target=None):
        """Patch the activation core and all tail effects.

        Yields a dict of the effect mocks so a test can assert on them.  The
        core (_activate_committed_on / _activate_profile_on) is patched to
        return ``core_ok``; discovery resolves ``target`` for the ifname.
        """
        tgt = target if target is not None else _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:aa", is_usb=True)
        with patch.object(watcher, "_activate_committed_on", return_value=core_ok) as core, \
             patch.object(watcher, "_activate_profile_on", return_value=core_ok) as core2, \
             patch.object(watcher, "_set_active_client") as set_active, \
             patch.object(watcher, "leave_setup_mode") as leave, \
             patch.object(watcher, "verify_avahi_after_handover") as avahi, \
             patch.object(watcher, "stop_ap_mode") as stop_ap, \
             patch.object(watcher, "start_ap_mode") as start_ap, \
             patch.object(watcher, "update_apmode_flag") as apflag, \
             patch.object(watcher, "run_cmd", return_value=MagicMock(returncode=0)) as run_cmd, \
             patch.object(watcher.wifi_recovery, "clear_noip_failures") as clear_noip, \
             patch.object(watcher.wifi_recovery, "record_noip_failure") as record_noip, \
             patch.object(watcher.wifi_net, "discover_adapters", return_value=[tgt]), \
             patch.object(watcher.wifi_net, "find_adapter_by_ifname", return_value=tgt), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=None), \
             patch.object(watcher.wifi_net, "is_wifi_connected", return_value=False):
            yield {
                "core": core, "core2": core2, "set_active": set_active,
                "leave": leave, "avahi": avahi, "stop_ap": stop_ap,
                "start_ap": start_ap, "apflag": apflag, "run_cmd": run_cmd,
                "clear_noip": clear_noip, "record_noip": record_noip, "target": tgt,
            }

    def test_success_minimal_tail(self, watcher):
        with self._harness(watcher) as h:
            ok = watcher.activate_client("wlan1")
        assert ok is True
        h["set_active"].assert_called_once_with(h["target"])
        h["clear_noip"].assert_called_once()
        h["avahi"].assert_called_once()
        h["leave"].assert_not_called()          # no on_success_leaves_setup
        h["record_noip"].assert_not_called()

    def test_success_does_not_touch_builtin_fallback_or_timers_by_default(self, watcher):
        watcher.STATE.using_builtin_fallback = True
        watcher.STATE.conn_down_start = 123.0
        with self._harness(watcher):
            watcher.activate_client("wlan1")
        assert watcher.STATE.using_builtin_fallback is True   # untouched (flag None)
        assert watcher.STATE.conn_down_start == 123.0         # untouched

    def test_sets_builtin_fallback_and_clears_timers(self, watcher):
        watcher.STATE.conn_down_start = 5.0
        watcher.STATE.last_reconnect_attempt = 6.0
        with self._harness(watcher):
            watcher.activate_client("wlan1", sets_builtin_fallback=True,
                                    clears_down_timers=True)
        assert watcher.STATE.using_builtin_fallback is True
        assert watcher.STATE.conn_down_start is None
        assert watcher.STATE.last_reconnect_attempt is None

    def test_on_success_leaves_setup(self, watcher):
        with self._harness(watcher) as h:
            watcher.activate_client("wlan1", on_success_leaves_setup=True,
                                    leave_reason="done")
        h["leave"].assert_called_once_with("done")

    def test_drop_hotspot_when_in_setup_then_success_no_rebuild(self, watcher):
        watcher.STATE.setup_mode = True
        with self._harness(watcher) as h:
            watcher.activate_client("wlan1", drop_hotspot=True)
        h["stop_ap"].assert_called_once()
        h["start_ap"].assert_not_called()       # success -> no rebuild

    def test_drop_hotspot_rebuilds_on_failure(self, watcher):
        watcher.STATE.setup_mode = True
        with self._harness(watcher, core_ok=False) as h:
            ok = watcher.activate_client("wlan1", drop_hotspot=True)
        assert ok is False
        h["stop_ap"].assert_called_once()
        h["start_ap"].assert_called_once()
        h["apflag"].assert_called_once_with(True)
        assert watcher.STATE.setup_mode is True

    def test_drop_hotspot_skipped_when_not_in_setup(self, watcher):
        watcher.STATE.setup_mode = False
        with self._harness(watcher) as h:
            watcher.activate_client("wlan1", drop_hotspot=True)
        h["stop_ap"].assert_not_called()

    def test_records_noip_on_failure(self, watcher):
        with self._harness(watcher, core_ok=False) as h:
            ok = watcher.activate_client("wlan1", records_noip=True,
                                         stable_id="sid-1", noip_at=42.0)
        assert ok is False
        h["record_noip"].assert_called_once()
        args = h["record_noip"].call_args[0]
        assert args[1] == "sid-1" and args[2] == 42.0
        h["set_active"].assert_not_called()      # no success tail on failure
        h["avahi"].assert_not_called()

    def test_deactivates_builtin_when_connected(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        with self._harness(watcher) as h:
            with patch.object(watcher.wifi_net, "resolve_builtin", return_value=builtin), \
                 patch.object(watcher.wifi_net, "is_wifi_connected", return_value=True):
                watcher.activate_client("wlan1", deactivates_builtin=True)
            disconnect = [c for c in h["run_cmd"].call_args_list
                          if "disconnect" in str(c) and "wlan0" in str(c)]
            assert disconnect, "expected nmcli device disconnect wlan0"

    def test_wait_for_validation_false_is_fire_and_forget(self, watcher):
        with self._harness(watcher) as h:
            ok = watcher.activate_client("wlan1", wait_for_validation=False)
        assert ok is True
        h["core2"].assert_called_once()          # routed through _activate_profile_on
        h["core"].assert_not_called()
        h["set_active"].assert_not_called()      # no success tail
        h["clear_noip"].assert_not_called()
        h["avahi"].assert_not_called()

    def test_profile_override_uses_profile_core(self, watcher):
        rollback = watcher.wifi_net.NetworkState(
            connection_name="Old", connection_uuid="old-uuid")
        with self._harness(watcher) as h:
            watcher.activate_client("wlan1", profile=rollback)
        h["core2"].assert_called_once()
        assert h["core2"].call_args[0][1] is rollback
        h["core"].assert_not_called()

    def test_empty_ifname_returns_false(self, watcher):
        with self._harness(watcher) as h:
            assert watcher.activate_client("") is False
        h["core"].assert_not_called()


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
        # The failed adoption records a no-IP failure and arms the escalating
        # back-off (replacing the fixed usb_adoption_retry_after).
        assert watcher.wifi_recovery.noip_failure_count(watcher, usb.permanent_mac) >= 1
        assert watcher.wifi_recovery.noip_retry_suppressed(
            watcher, usb.permanent_mac, 0.0) is True
        assert watcher.STATE.using_builtin_fallback is False


# ---------------------------------------------------------------------------
# WP6 — transactional change-Wi-Fi flow and local control API
# ---------------------------------------------------------------------------

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


class TestStartExplicitSetup:
    def test_snapshots_and_enters_setup(self, watcher):
        watcher.STATE.active_client_ifname = "wlan1"
        watcher.STATE.active_client_mac = "bb:bb:bb:bb:bb:01"
        with patch.object(watcher, "get_configured_network_state",
                          return_value=watcher.wifi_net.NetworkState("Home", "uuid-1")), \
             patch.object(watcher, "run_cmd", return_value=MagicMock(returncode=0)), \
             patch.object(watcher, "enter_setup_mode") as enter:
            watcher.start_explicit_setup()
        enter.assert_called_once()
        # Enters an EXPLICIT_RECONFIGURE hotspot carrying the rollback snapshot.
        assert enter.call_args[0][0] is watcher.HotspotPurpose.EXPLICIT_RECONFIGURE
        rollback = enter.call_args.kwargs["rollback"]
        assert rollback.connection_name == "Home"
        assert rollback.connection_uuid == "uuid-1"
        assert rollback.adapter_mac == "bb:bb:bb:bb:bb:01"

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
        watcher.STATE.setup_mode = True
        watcher.STATE.hotspot = watcher.HotspotSession(
            purpose=watcher.HotspotPurpose.EXPLICIT_RECONFIGURE,
            entered_at=0.0,
            rollback=watcher.RollbackSnapshot("Home", "uuid-1", "aa:bb:cc:00:00:01"),
        )
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

    def test_failure_retains_hotspot(self, watcher):
        watcher.STATE.setup_mode = True
        watcher.STATE.hotspot = watcher.HotspotSession(
            purpose=watcher.HotspotPurpose.EXPLICIT_RECONFIGURE,
            entered_at=0.0,
            rollback=watcher.RollbackSnapshot("Home", "uuid-1", ""),
        )
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        with patch.object(watcher.wifi_net, "discover_adapters", return_value=[builtin]), \
             patch.object(watcher, "run_cmd", return_value=MagicMock(returncode=0)), \
             patch.object(watcher, "wait_for_connection", return_value=False), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher, "leave_setup_mode") as leave:
            ok = watcher.reconnect_saved_network()
        assert ok is False
        leave.assert_not_called()

    def test_usb_only_client_fails_restores_hotspot(self, watcher):
        """Pi 2 (no built-in radio): the sole USB adapter hosts the hotspot.
        When a client attempt on that adapter fails, the hotspot must be
        recreated so the setup portal remains reachable.

        Transition: USB hotspot active → client attempt → hotspot stops →
        connection fails → hotspot recreated → returns False.
        """
        usb = _adapter(watcher, "wlan1", "aa:bb:cc:00:00:02", is_usb=True)
        watcher.STATE.setup_mode = True
        watcher.STATE.setup_purpose = "automatic_recovery"

        with patch.object(watcher.wifi_net, "discover_adapters", return_value=[usb]), \
             patch.object(watcher, "get_configured_network_state",
                          return_value=watcher.wifi_net.NetworkState("Home", "uuid-1")), \
             patch.object(watcher, "run_cmd", return_value=MagicMock(returncode=0)), \
             patch.object(watcher, "wait_for_connection", return_value=False), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher, "stop_ap_mode") as stop_ap, \
             patch.object(watcher, "start_ap_mode") as start_ap, \
             patch.object(watcher, "update_apmode_flag") as apflag, \
             patch.object(watcher, "leave_setup_mode") as leave:
            ok = watcher.reconnect_saved_network()

        assert ok is False
        stop_ap.assert_called_once()     # hotspot torn down before the client attempt
        start_ap.assert_called_once()    # hotspot recreated after the failed attempt
        apflag.assert_called_with(True)  # flag reflects hotspot-active state
        leave.assert_not_called()        # setup mode never exited
        assert watcher.STATE.setup_mode is True

    def test_usb_only_client_succeeds_leaves_setup(self, watcher):
        """Pi 2 (no built-in radio): when the client attempt on the sole USB
        adapter succeeds, setup mode is exited and the hotspot is not recreated.
        """
        usb = _adapter(watcher, "wlan1", "aa:bb:cc:00:00:02", is_usb=True)
        watcher.STATE.setup_mode = True
        watcher.STATE.setup_purpose = "automatic_recovery"

        with patch.object(watcher.wifi_net, "discover_adapters", return_value=[usb]), \
             patch.object(watcher, "get_configured_network_state",
                          return_value=watcher.wifi_net.NetworkState("Home", "uuid-1")), \
             patch.object(watcher, "run_cmd", return_value=MagicMock(returncode=0)), \
             patch.object(watcher, "wait_for_connection", return_value=True), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher, "stop_ap_mode") as stop_ap, \
             patch.object(watcher, "start_ap_mode") as start_ap, \
             patch.object(watcher, "leave_setup_mode") as leave, \
             patch.object(watcher, "verify_avahi_after_handover"):
            ok = watcher.reconnect_saved_network()

        assert ok is True
        stop_ap.assert_called_once()  # hotspot torn down before the client attempt
        start_ap.assert_not_called()  # hotspot not recreated on success
        leave.assert_called_once()

    def test_netabsent_skips_ipv4_wait(self, watcher):
        """A-WP4 inconsistency 1: reconnect_saved_network must short-circuit the
        IPv4 wait when nmcli reports the saved network is not visible."""
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        absent = MagicMock(
            returncode=10,
            stderr="Error: Connection activation failed: The Wi-Fi network could not be found",
        )
        with patch.object(watcher.wifi_net, "discover_adapters", return_value=[builtin]), \
             patch.object(watcher.wifi_net, "client_candidate_order", return_value=[builtin]), \
             patch.object(watcher, "get_configured_network_state",
                          return_value=watcher.wifi_net.NetworkState("Home", "uuid-1")), \
             patch.object(watcher, "run_cmd", return_value=absent), \
             patch.object(watcher, "wait_for_connection") as wait, \
             patch.object(watcher, "leave_setup_mode"):
            ok = watcher.reconnect_saved_network()
        assert ok is False
        wait.assert_not_called()

    def test_clears_restrictions_before_activation_with_empty_uuid(self, watcher):
        """reconnect_saved_network must resolve and clear cross-adapter restrictions
        before the first activation attempt, even when the stored UUID is empty."""
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        calls = []
        with patch.object(watcher.wifi_net, "discover_adapters", return_value=[builtin]), \
             patch.object(watcher.wifi_net, "client_candidate_order", return_value=[builtin]), \
             patch.object(watcher.wifi_net, "resolve_connection_uuid_for_name",
                          return_value="resolved-uuid"), \
             patch.object(watcher.wifi_net, "save_network_state"), \
             patch.object(watcher, "get_configured_network_state",
                          return_value=watcher.wifi_net.NetworkState("Home", "")), \
             patch.object(watcher, "run_cmd",
                          side_effect=lambda c, *a, **k: calls.append(c) or MagicMock(returncode=0)), \
             patch.object(watcher, "wait_for_connection", return_value=True), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher, "leave_setup_mode"), \
             patch.object(watcher, "verify_avahi_after_handover"):
            watcher.reconnect_saved_network()

        str_calls = [str(c) for c in calls]
        modify_before_up = next(
            (i for i, c in enumerate(str_calls) if "modify" in c and "resolved-uuid" in c), None
        )
        up_call = next(
            (i for i, c in enumerate(str_calls) if "connection" in c and "up" in c), None
        )
        assert modify_before_up is not None, (
            "reconnect_saved_network must issue clear_restrictions_cmd with resolved UUID"
        )
        assert up_call is not None, "reconnect_saved_network must issue an activation command"
        assert modify_before_up < up_call, (
            "cross-adapter restrictions must be cleared BEFORE activation"
        )


class TestCandidateValidateTail:
    """A-WP5: _try_candidate_on_adapter validates via the shared tail, so the
    net-absent short-circuit reaches the credential-apply path too."""

    def test_candidate_netabsent_skips_ipv4_wait_and_deletes(self, watcher):
        target = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:aa", is_usb=True)

        def fake_run(cmd, **kw):
            s = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
            if "connection" in s and "up" in s.split():
                return MagicMock(
                    returncode=10,
                    stderr="Error: activation failed: The Wi-Fi network could not be found",
                )
            return MagicMock(returncode=0, stderr="")

        with patch.object(watcher.wifi_net, "configure_candidate_cmds",
                          return_value=([["nmcli", "connection", "add"]], ["nmcli connection add"])), \
             patch.object(watcher.wifi_net, "get_profile_uuid", return_value="cand-uuid"), \
             patch.object(watcher, "run_cmd", side_effect=fake_run) as run_cmd, \
             patch.object(watcher, "wait_for_connection") as wait:
            ok = watcher._try_candidate_on_adapter("SSID", "pw", target)

        assert ok is False
        wait.assert_not_called()   # net-absent short-circuit reached the candidate path
        assert any("delete" in " ".join(c.args[0]) for c in run_cmd.call_args_list
                   if isinstance(c.args[0], (list, tuple))), "failed candidate must be deleted"


class TestWifiPolicyModule:
    """Phase B: the pure policy core lives in a standalone importable module and
    is re-exported by the watcher for backwards compatibility."""

    def test_reexports_are_the_policy_objects(self, watcher):
        import wifi_policy
        assert watcher.Mode is wifi_policy.Mode
        assert watcher.HotspotPurpose is wifi_policy.HotspotPurpose
        assert watcher.PurposePolicy is wifi_policy.PurposePolicy
        assert watcher.PURPOSE_TABLE is wifi_policy.PURPOSE_TABLE
        assert watcher.AP_MAX_DURATION == wifi_policy.AP_MAX_DURATION
        assert watcher.HOTSPOT_PROBE_GRACE == wifi_policy.HOTSPOT_PROBE_GRACE

    def test_policy_module_has_no_watcher_dependency(self):
        # Importable without loading the watcher / flask / sysutils stubs.
        import wifi_policy
        assert set(wifi_policy.PURPOSE_TABLE) == set(wifi_policy.HotspotPurpose)


class TestConnectivityHysteresis:
    """C-WP1: connectivity_ok is slow to condemn (soft N-pass) and quick to
    forgive (any healthy pass), with hard signals bypassing the debounce
    (field log 01-Jul-2026)."""

    def _facts(self, watcher, adapters, active, *, wired_ok=False, wifi_configured=True):
        return watcher.Facts(
            wifi_configured=wifi_configured, adapters=adapters, wired_connected=False,
            wired_ok=wired_ok, active_client=active, addresses={}, taken_at=1000.0,
        )

    def test_single_soft_blip_holds_prior_true(self, watcher):
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:31", is_usb=True)
        watcher.STATE.connectivity_ok = True  # was online this boot
        facts = self._facts(watcher, [usb], usb)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=False):  # carrier up -> soft
            ok = watcher._debounced_connectivity(facts, usb, client_ok=False)
        assert ok is True                       # a single soft blip does NOT flip
        assert watcher.STATE.conn_unhealthy_checks == 1

    def test_two_soft_passes_condemn(self, watcher):
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:32", is_usb=True)
        watcher.STATE.connectivity_ok = True
        facts = self._facts(watcher, [usb], usb)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=False):
            first = watcher._debounced_connectivity(facts, usb, client_ok=False)
            second = watcher._debounced_connectivity(facts, usb, client_ok=False)
        assert (first, second) == (True, False)  # condemned only after N consecutive

    def test_healthy_pass_recovers_immediately_and_resets(self, watcher):
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:33", is_usb=True)
        watcher.STATE.conn_unhealthy_checks = 1
        facts = self._facts(watcher, [usb], usb)
        ok = watcher._debounced_connectivity(facts, usb, client_ok=True)
        assert ok is True
        assert watcher.STATE.conn_unhealthy_checks == 0

    def test_no_active_client_is_hard(self, watcher):
        watcher.STATE.connectivity_ok = True
        facts = self._facts(watcher, [], None)
        ok = watcher._debounced_connectivity(facts, None, client_ok=False)
        assert ok is False                       # hard: condemned immediately
        assert watcher.STATE.conn_unhealthy_checks == 0

    def test_nm_disconnected_present_usb_is_soft(self, watcher):
        # C2-WP3: no active client this pass, but the recorded USB is still present
        # (NM merely disconnected it) -> soft, debounced 2 passes (the behaviour the
        # retired overlay counter used to provide).
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:35", is_usb=True)
        watcher.STATE.connectivity_ok = True
        facts = self._facts(watcher, [usb], None)  # USB present, not the active client
        first = watcher._debounced_connectivity(facts, None, client_ok=False,
                                                prev_mac=usb.permanent_mac)
        second = watcher._debounced_connectivity(facts, None, client_ok=False,
                                                 prev_mac=usb.permanent_mac)
        assert (first, second) == (True, False)   # 2-pass debounce, not immediate
        assert watcher.STATE.conn_unhealthy_checks == 2

    def test_absent_recorded_usb_is_hard(self, watcher):
        # Recorded USB physically gone from adapters -> hard (immediate), no debounce.
        watcher.STATE.connectivity_ok = True
        facts = self._facts(watcher, [], None)     # USB gone
        ok = watcher._debounced_connectivity(facts, None, client_ok=False,
                                             prev_mac="bb:bb:bb:bb:bb:36")
        assert ok is False
        assert watcher.STATE.conn_unhealthy_checks == 0

    def test_carrier_down_is_hard(self, watcher):
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:34", is_usb=True)
        watcher.STATE.connectivity_ok = True
        facts = self._facts(watcher, [usb], usb)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=True):  # NO-CARRIER
            ok = watcher._debounced_connectivity(facts, usb, client_ok=False)
        assert ok is False

    def test_wired_ok_is_online_without_debounce(self, watcher):
        watcher.STATE.conn_unhealthy_checks = 5
        facts = self._facts(watcher, [], None, wired_ok=True)
        ok = watcher._debounced_connectivity(facts, None, client_ok=False)
        assert ok is True
        assert watcher.STATE.conn_unhealthy_checks == 0


class TestHealthMemo:
    """C-WP0: is_wifi_client_healthy is sampled once per (pass, ifname) and the
    recovery classifier and status snapshot see the same verdict in a pass."""

    def test_health_memo_samples_once_per_ifname(self, watcher):
        n = {"c": 0}

        def fake(ifname=watcher.AP_IFNAME, wifi_connected=None):
            n["c"] += 1
            return True

        with patch.object(watcher, "is_wifi_client_healthy", side_effect=fake):
            memo = watcher._make_health_memo()
            assert memo("wlan0") is True
            assert memo("wlan0", wifi_connected=True) is True
            assert memo("wlan1") is True
            assert memo("wlan1") is True
        assert n["c"] == 2  # one sample per distinct ifname, cached thereafter

    def test_within_pass_agreement_between_recovery_and_active_health(self, watcher):
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:07", is_usb=True)
        facts = watcher.Facts(
            wifi_configured=True, adapters=[usb], wired_connected=False,
            wired_ok=False, active_client=usb, addresses={}, taken_at=1000.0,
        )
        # A hostile source: True first, then False.  Without memoisation the two
        # consumers would disagree within the pass.
        seq = iter([True, False, False, False])
        with patch.object(watcher, "is_wifi_client_healthy",
                          side_effect=lambda *a, **k: next(seq)), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=None), \
             patch.object(watcher.wifi_net, "usb_candidates", return_value=[usb]), \
             patch.object(watcher, "resolve_hotspot_adapter", return_value=None):
            rf = watcher.gather_recovery_facts(facts)
            active_healthy = facts.health_memo("wlan1")
        assert rf.adapters_by_ifname["wlan1"].healthy is True
        assert active_healthy is True  # same cached sample, not the later False


class TestConnectToConfiguredWifiUuid:
    """A-WP6: the steady-state reconnect resolves the UUID and clears
    cross-adapter restrictions (inconsistency 4), fire-and-forget (no wait)."""

    def test_reconnect_carries_uuid_and_clears_restrictions_no_wait(self, watcher):
        calls = []
        with patch.object(watcher, "get_configured_network_state",
                          return_value=watcher.wifi_net.NetworkState("Home", "")), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.wifi_net, "resolve_connection_uuid_for_name",
                          return_value="resolved-uuid"), \
             patch.object(watcher.wifi_net, "save_network_state"), \
             patch.object(watcher, "run_cmd",
                          side_effect=lambda c, *a, **k: calls.append(c) or MagicMock(returncode=0, stderr="")), \
             patch.object(watcher, "wait_for_connection") as wait:
            ok = watcher.connect_to_configured_wifi()
        assert ok is True
        wait.assert_not_called()  # fire-and-forget: no blocking IPv4 wait in the loop
        str_calls = [str(c) for c in calls]
        assert any("modify" in c and "resolved-uuid" in c for c in str_calls), (
            "reconnect must clear cross-adapter restrictions with the resolved UUID"
        )
        up = next((c for c in calls if isinstance(c, list) and "up" in c), None)
        assert up is not None and "resolved-uuid" in up, (
            "the activation command must carry the resolved UUID"
        )

    def test_healthy_returns_early_without_activation(self, watcher):
        calls = []
        with patch.object(watcher, "get_configured_network_state",
                          return_value=watcher.wifi_net.NetworkState("Home", "uuid-1")), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher, "run_cmd",
                          side_effect=lambda c, *a, **k: calls.append(c) or MagicMock(returncode=0)):
            ok = watcher.connect_to_configured_wifi()
        assert ok is True
        assert not any(isinstance(c, list) and "up" in c for c in calls), (
            "healthy path must not issue nmcli connection up"
        )


class TestAttemptOnTargets:
    def test_non_hotspot_target_keeps_ap_up_and_success_leaves_setup(self, watcher):
        hotspot = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        target = _adapter(watcher, "wlan1", "aa:bb:cc:00:00:02", is_usb=True)
        watcher.STATE.setup_mode = True

        with patch.object(watcher.wifi_net, "discover_adapters", return_value=[hotspot, target]), \
             patch.object(watcher, "resolve_hotspot_adapter", return_value=hotspot), \
             patch.object(watcher, "stop_ap_mode") as stop_ap, \
             patch.object(watcher, "start_ap_mode") as start_ap, \
             patch.object(watcher, "leave_setup_mode") as leave, \
             patch.object(watcher, "verify_avahi_after_handover"):
            ok = watcher.attempt_on_targets([target], lambda adapter: adapter.ifname == "wlan1")

        assert ok is True
        stop_ap.assert_not_called()
        start_ap.assert_not_called()
        leave.assert_called_once()
        assert watcher.STATE.active_client_ifname == "wlan1"

    def test_hotspot_target_failure_rebuilds_ap(self, watcher):
        hotspot = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        watcher.STATE.setup_mode = True

        with patch.object(watcher.wifi_net, "discover_adapters", return_value=[hotspot]), \
             patch.object(watcher, "resolve_hotspot_adapter", return_value=hotspot), \
             patch.object(watcher, "stop_ap_mode") as stop_ap, \
             patch.object(watcher, "start_ap_mode") as start_ap, \
             patch.object(watcher, "update_apmode_flag") as apflag, \
             patch.object(watcher, "leave_setup_mode") as leave:
            ok = watcher.attempt_on_targets([hotspot], lambda adapter: False)

        assert ok is False
        stop_ap.assert_called_once()
        start_ap.assert_called_once()
        apflag.assert_called_once_with(True)
        leave.assert_not_called()
        assert watcher.STATE.setup_mode is True

    def test_single_radio_failure_stops_tests_and_rebuilds_ap(self, watcher):
        usb = _adapter(watcher, "wlan1", "aa:bb:cc:00:00:02", is_usb=True)
        watcher.STATE.setup_mode = True

        with patch.object(watcher.wifi_net, "discover_adapters", return_value=[usb]), \
             patch.object(watcher, "resolve_hotspot_adapter", return_value=usb), \
             patch.object(watcher, "stop_ap_mode") as stop_ap, \
             patch.object(watcher, "start_ap_mode") as start_ap, \
             patch.object(watcher, "update_apmode_flag") as apflag:
            ok = watcher.attempt_on_targets([usb], lambda adapter: False)

        assert ok is False
        stop_ap.assert_called_once()
        start_ap.assert_called_once()
        apflag.assert_called_once_with(True)


class TestApplyWifiAsync:
    def test_total_failure_retains_setup_mode_and_does_not_leave_first(self, watcher):
        watcher.STATE.setup_mode = True
        watcher.STATE.apply_in_progress = True
        with patch("time.sleep"), \
             patch.object(watcher, "configure_wifi_with_nmcli", return_value=False), \
             patch.object(watcher, "leave_setup_mode") as leave, \
             patch.object(watcher, "enter_setup_mode") as enter:
            watcher.apply_wifi_async("Home", "bad-password")

        leave.assert_not_called()
        enter.assert_called_once()
        assert watcher.STATE.last_apply_result == "failed"
        assert watcher.STATE.apply_in_progress is False


class TestReconfigureTimeout:
    def test_timeout_restores_previous(self, watcher):
        with patch.object(watcher, "reconnect_saved_network", return_value=True) as rc:
            watcher.handle_reconfigure_timeout()
        rc.assert_called_once()

    def test_timeout_restore_failure_enters_recovery(self, watcher):
        watcher.STATE.setup_mode = True
        watcher.STATE.hotspot = watcher.HotspotSession(
            purpose=watcher.HotspotPurpose.EXPLICIT_RECONFIGURE,
            entered_at=0.0,
            rollback=watcher.RollbackSnapshot("Home", "uuid-1", ""),
        )
        with patch.object(watcher, "reconnect_saved_network", return_value=False):
            watcher.handle_reconfigure_timeout()
        # Failed restore downgrades the session to an automatic recovery hotspot.
        assert watcher.STATE.hotspot.purpose is watcher.HotspotPurpose.USB_LOSS_RECOVERY
        assert watcher.STATE.hotspot.rollback is None


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


# ---------------------------------------------------------------------------
# _resolve_committed_uuid — lazy UUID resolution for legacy profiles
# ---------------------------------------------------------------------------

class TestResolveCommittedUuid:
    """_resolve_committed_uuid() resolves and persists missing UUIDs so that
    cross-adapter restriction clearing is not skipped for legacy profiles."""

    def _state(self, watcher, name="HomeNetwork", uuid=""):
        return watcher.wifi_net.NetworkState(connection_name=name, connection_uuid=uuid)

    def test_returns_uuid_when_already_present(self, watcher):
        state = self._state(watcher, uuid="existing-uuid")
        with patch.object(watcher.wifi_net, "resolve_connection_uuid_for_name") as resolve, \
             patch.object(watcher.wifi_net, "save_network_state") as save:
            result = watcher._resolve_committed_uuid(state)
        assert result == "existing-uuid"
        resolve.assert_not_called()
        save.assert_not_called()

    def test_resolves_and_persists_when_uuid_empty(self, watcher):
        state = self._state(watcher, uuid="")
        with patch.object(watcher.wifi_net, "resolve_connection_uuid_for_name",
                          return_value="resolved-uuid") as resolve, \
             patch.object(watcher.wifi_net, "save_network_state") as save:
            result = watcher._resolve_committed_uuid(state)
        assert result == "resolved-uuid"
        resolve.assert_called_once_with("HomeNetwork")
        save.assert_called_once()
        saved_state = save.call_args[0][0]
        assert saved_state.connection_uuid == "resolved-uuid"
        assert saved_state.connection_name == "HomeNetwork"

    def test_returns_empty_when_resolution_fails(self, watcher):
        state = self._state(watcher, uuid="")
        with patch.object(watcher.wifi_net, "resolve_connection_uuid_for_name",
                          return_value="") as resolve, \
             patch.object(watcher.wifi_net, "save_network_state") as save:
            result = watcher._resolve_committed_uuid(state)
        assert result == ""
        resolve.assert_called_once_with("HomeNetwork")
        save.assert_not_called()

    def test_returns_empty_when_name_empty(self, watcher):
        state = self._state(watcher, name="", uuid="")
        with patch.object(watcher.wifi_net, "resolve_connection_uuid_for_name") as resolve:
            result = watcher._resolve_committed_uuid(state)
        assert result == ""
        resolve.assert_not_called()

    def test_still_returns_uuid_when_persist_fails(self, watcher):
        """A persistence failure must not suppress the resolved UUID — the
        restriction clear should still proceed using the in-memory value."""
        state = self._state(watcher, uuid="")
        with patch.object(watcher.wifi_net, "resolve_connection_uuid_for_name",
                          return_value="resolved-uuid"), \
             patch.object(watcher.wifi_net, "save_network_state",
                          side_effect=OSError("disk full")):
            result = watcher._resolve_committed_uuid(state)
        assert result == "resolved-uuid"

    def test_activate_committed_on_resolves_uuid_before_restriction_clear(self, watcher):
        """When the committed state has an empty UUID, _activate_committed_on
        must resolve it and clear restrictions before activating."""
        with patch.object(watcher, "get_configured_network_state") as gcns, \
             patch.object(watcher.wifi_net, "resolve_connection_uuid_for_name",
                          return_value="resolved-uuid"), \
             patch.object(watcher.wifi_net, "save_network_state"), \
             patch.object(watcher, "run_cmd", return_value=MagicMock(returncode=0)) as rc, \
             patch.object(watcher, "wait_for_connection", return_value=True), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=True):
            gcns.return_value = watcher.wifi_net.NetworkState(
                connection_name="HomeNetwork", connection_uuid=""
            )
            watcher._activate_committed_on("wlan1")

        calls = [str(c) for c in rc.call_args_list]
        assert any("resolved-uuid" in c and "modify" in c for c in calls), (
            "_activate_committed_on must call clear_restrictions_cmd with the resolved UUID"
        )


# ---------------------------------------------------------------------------
# Regression: delayed startup USB enumeration re-probe (Section 4.3 / WP4)
# ---------------------------------------------------------------------------

class TestBootClientBringup:
    """C2-WP4 — the BOOT-window client bring-up is a loop rung that runs the single
    recovery ladder (preferred USB, else onboard) each pass while BOOT_AP_GRACE is
    open, replacing the retired pre-loop startup_connect_usb_first() one-shot and
    its tried-MACs re-probe gate.  The apply mechanics (net-absent short-circuit,
    UUID resolution, no-IP ledger) live in activate_client and are covered by
    TestActivateClient; these tests assert the boot rung's routing and gating."""

    def _fctx(self, watcher, adapters, active_client, *, wifi_cfg=True, wired_ok=False,
              now=10.0, boot_time=0.0):
        facts = _facts_for(watcher, adapters, active_client, wifi_cfg=wifi_cfg,
                           wired_ok=wired_ok, now=now)
        pre = watcher.PreFactsContext(now=now, boot_time=boot_time, avahi_ok=True)
        return watcher.FactsContext(pre, facts, lambda: False)

    def test_boot_window_engages_preferred_usb(self, watcher):
        # Offline in the boot window with a usable USB and no active client: the
        # ladder selects ACTIVATE_USB (rung 1) and the rung owns the pass.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "cc:dd:ee:ff:00:03", is_usb=True)
        fctx = self._fctx(watcher, [builtin, usb], None)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher, "_apply_client_activation", return_value=True) as apply:
            v = watcher.step_boot_client_bringup(fctx)
        assert v is watcher.Verdict.OWN_PASS
        apply.assert_called_once()
        action = apply.call_args[0][0]
        assert action.kind is watcher.RecoveryKind.ACTIVATE_USB
        assert action.ifname == "wlan1"    # USB tried before the built-in

    def test_boot_window_falls_to_onboard_when_no_usb(self, watcher):
        # No USB present: the ladder engages the onboard (rung 2) as a client.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        fctx = self._fctx(watcher, [builtin], None)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher, "_apply_client_activation", return_value=True) as apply:
            v = watcher.step_boot_client_bringup(fctx)
        assert v is watcher.Verdict.OWN_PASS
        action = apply.call_args[0][0]
        assert action.kind is watcher.RecoveryKind.ACTIVATE_ONBOARD
        assert action.ifname == "wlan0"

    def test_wired_ok_short_circuits(self, watcher):
        # Usable wired Ethernet: the boot rung does not engage a Wi-Fi client.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "cc:dd:ee:ff:00:04", is_usb=True)
        fctx = self._fctx(watcher, [builtin, usb], None, wired_ok=True)
        with patch.object(watcher, "_apply_client_activation") as apply:
            v = watcher.step_boot_client_bringup(fctx)
        assert v is watcher.Verdict.CONTINUE
        apply.assert_not_called()

    def test_healthy_client_holds_no_reprobe(self, watcher):
        # A client is already up and healthy: the ladder HOLDs (no thrash).
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "cc:dd:ee:ff:00:05", is_usb=True)
        fctx = self._fctx(watcher, [builtin, usb], usb)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher, "_apply_client_activation") as apply:
            v = watcher.step_boot_client_bringup(fctx)
        assert v is watcher.Verdict.CONTINUE
        apply.assert_not_called()

    def test_after_grace_window_defers(self, watcher):
        # Past BOOT_AP_GRACE the boot rung is inactive; step_boot_ap_entry owns the
        # ladder-then-hotspot decision.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "cc:dd:ee:ff:00:06", is_usb=True)
        fctx = self._fctx(watcher, [builtin, usb], None,
                          now=watcher.BOOT_AP_GRACE + 10.0, boot_time=0.0)
        with patch.object(watcher, "_apply_client_activation") as apply:
            v = watcher.step_boot_client_bringup(fctx)
        assert v is watcher.Verdict.CONTINUE
        apply.assert_not_called()

    def test_setup_mode_skips(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "cc:dd:ee:ff:00:07", is_usb=True)
        watcher.STATE.setup_mode = True
        fctx = self._fctx(watcher, [builtin, usb], None)
        with patch.object(watcher, "_apply_client_activation") as apply:
            v = watcher.step_boot_client_bringup(fctx)
        assert v is watcher.Verdict.CONTINUE
        apply.assert_not_called()

    def test_unconfigured_skips(self, watcher):
        # Nothing committed: the boot rung has no client profile to bring up.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "cc:dd:ee:ff:00:08", is_usb=True)
        fctx = self._fctx(watcher, [builtin, usb], None, wifi_cfg=False)
        with patch.object(watcher, "_apply_client_activation") as apply:
            v = watcher.step_boot_client_bringup(fctx)
        assert v is watcher.Verdict.CONTINUE
        apply.assert_not_called()


# ---------------------------------------------------------------------------
# Regression: two-pass NM-disconnected USB debounce (Section 8.5 / WP5)
# ---------------------------------------------------------------------------

class TestNmDisconnectedUsbDebounce:
    """C2-WP3 — a USB physically present but NM-disconnected is now debounced by
    the single connectivity hysteresis (2 passes); _set_active_client preserves
    active_client_mac while that soft debounce is in progress so pass 2 can still
    attribute the adapter."""

    def test_mac_preserved_while_hysteresis_debounce_in_progress(self, watcher):
        usb_mac = "bb:bb:bb:bb:bb:20"
        watcher.STATE.active_client_mac = usb_mac
        watcher.STATE.active_client_ifname = "wlan1"
        watcher.STATE.conn_unhealthy_checks = 1  # soft debounce in progress
        watcher._set_active_client(None)
        assert watcher.STATE.active_client_mac == usb_mac, (
            "_set_active_client(None) cleared active_client_mac while the debounce is in progress"
        )
        assert watcher.STATE.active_client_ifname == ""

    def test_mac_cleared_when_no_debounce(self, watcher):
        watcher.STATE.active_client_mac = "bb:bb:bb:bb:bb:21"
        watcher.STATE.active_client_ifname = "wlan1"
        watcher.STATE.conn_unhealthy_checks = 0
        watcher._set_active_client(None)
        assert watcher.STATE.active_client_mac == ""
        assert watcher.STATE.active_client_ifname == ""

    def test_two_pass_nm_disconnected_triggers_fallback(self, watcher):
        """End-to-end 2-pass debounce through finalize (hysteresis + MAC
        preservation) and then the Phase B-late USB-failure handler.

        Pass 1: USB present, NM-disconnected -> hysteresis holds prior True, MAC
                preserved; the handler does not fire.
        Pass 2: hysteresis condemns the path (conn_ok False) -> the handler fires.
        """
        usb_mac = "bb:bb:bb:bb:bb:22"
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", usb_mac, is_usb=True)
        adapters = [builtin, usb]
        watcher._known_usb_macs.add(usb_mac)
        watcher.STATE.active_client_mac = usb_mac
        watcher.STATE.active_client_ifname = "wlan1"
        watcher.STATE.connectivity_ok = True

        def _one_pass():
            # NM-disconnected: resolve_active_client finds nothing connected.
            facts = _facts_for(watcher, adapters, None)
            pre = watcher.PreFactsContext(now=facts.taken_at, boot_time=0.0, avahi_ok=True)
            fctx = watcher.FactsContext(pre, facts, lambda: False)
            hctx = watcher.finalize_active_client_and_health(fctx)
            return watcher.step_usb_failure_fallback(hctx)

        with patch.object(watcher.wifi_net, "is_wifi_connected", return_value=False), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher, "apply_client_failed", return_value=True) as ap:
            v1 = _one_pass()
            assert v1 is watcher.Verdict.CONTINUE            # pass 1: held, no fallback
            assert ap.call_count == 0
            assert watcher.STATE.active_client_mac == usb_mac  # preserved for pass 2
            v2 = _one_pass()
            assert v2 is watcher.Verdict.OWN_PASS            # pass 2: condemned -> fallback
            ap.assert_called_once()


# ---------------------------------------------------------------------------
# C2-WP2 note: the in-hotspot USB reconnect is now routed through the single
# recovery ladder (next_recovery_action + _apply_client_activation).  The
# retired _try_recovery_reconnect's private mechanics — leave-on-success,
# retain-on-failure, clear-restrictions-before-up — are covered by
# TestActivateClient (drop_hotspot / on_success_leaves_setup / records_noip) and
# the _activate_committed_on clear-restrictions test; the routing itself is
# covered by TestRecoveryExitEdge and TestScanGatedRecovery below.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# WP2 (dead-PHY) — target resolution, dead detection, budgets, reboot guard
# ---------------------------------------------------------------------------

from contextlib import contextmanager


@contextmanager
def _patch_dead_phy_facts(watcher, *, sysfs_names=(), usb_paths_ifaces=(),
                          link_down=True, healthy=False, sysfs_mac=""):
    """Patch the sysfs/NM facts the dead-PHY helpers consult."""
    def _usb_paths(ifname, sys_root="/sys/class/net"):
        if ifname in usb_paths_ifaces:
            return {"interface_id": "1-1.5:1.0", "driver": "rtl8xxxu",
                    "usb_device_path": "/sys/devices/usb1/1-1.5"}
        return None

    def _find_by_mac(mac, sys_root="/sys/class/net"):
        # Resolve the recorded MAC to its sysfs ifname (first faked netdev).
        if mac and sysfs_mac and mac == sysfs_mac and sysfs_names:
            return list(sysfs_names)[0]
        return ""

    with patch.object(watcher.wifi_net, "list_sysfs_netdevs",
                      return_value=list(sysfs_names)), \
         patch.object(watcher.wifi_net, "usb_sysfs_paths", side_effect=_usb_paths), \
         patch.object(watcher.wifi_net, "read_link_down", return_value=link_down), \
         patch.object(watcher.wifi_net, "find_sysfs_netdev_by_mac", side_effect=_find_by_mac), \
         patch.object(watcher.wifi_net, "_sys_read_mac", return_value=sysfs_mac), \
         patch.object(watcher, "is_wifi_client_healthy", return_value=healthy):
        yield


def _ledger(watcher, stable_id):
    return watcher.STATE.adapter_reset_ledgers[stable_id]


def _spend_window_budget(watcher, stable_id, now=0.0):
    watcher.STATE.adapter_reset_ledgers[stable_id] = {
        "recent_resets": [now, now],
        "total_resets": 2,
        "quarantined_until": None,
    }


class TestDeadAdapterTargetResolution:
    def test_resolves_sole_usb_as_startup_target(self, watcher):
        usb = _adapter(watcher, "wlan0", "dc:62:79:91:4d:d6", is_usb=True)
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"]):
            target = watcher._resolve_target_client([usb])
        assert target is not None
        assert target.ifname == "wlan0"
        assert target.is_usb and target.resettable_usb

    def test_resolves_from_active_mac_via_sysfs_when_nm_missing(self, watcher):
        # NM reports no adapters, but the recorded MAC maps to a sysfs netdev.
        watcher.STATE.active_client_mac = "dc:62:79:91:4d:d6"
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   sysfs_mac="dc:62:79:91:4d:d6"):
            target = watcher._resolve_target_client([])
        assert target is not None
        assert target.ifname == "wlan0"
        assert target.present_in_nm is False
        assert target.present_in_sysfs is True
        assert target.resettable_usb is True

    def test_falls_back_to_ap_ifname_literal(self, watcher):
        with _patch_dead_phy_facts(watcher, sysfs_names=[]):
            target = watcher._resolve_target_client([])
        assert target is not None
        assert target.ifname == watcher.AP_IFNAME


class TestDeadAdapterDetection:
    def _usb(self, watcher):
        return _adapter(watcher, "wlan0", "dc:62:79:91:4d:d6", is_usb=True)

    def test_debounce_declares_dead_and_sets_since(self, watcher):
        usb = self._usb(watcher)
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=True, healthy=False):
            target = watcher._resolve_target_client([usb])
            assert watcher._update_dead_adapter_detection([usb], target) is False
            assert watcher.STATE.dead_adapter_checks == 1
            assert watcher.STATE.dead_adapter_ifname == ""
            assert watcher._update_dead_adapter_detection([usb], target) is True
        assert watcher.STATE.dead_adapter_ifname == "wlan0"
        assert watcher.STATE.dead_adapter_since is not None
        assert watcher.STATE.dead_adapter_first_failure is not None

    def test_healthy_pass_clears_active_fields(self, watcher):
        usb = self._usb(watcher)
        watcher.STATE.dead_adapter_ifname = "wlan0"
        watcher.STATE.dead_adapter_checks = 3
        watcher.STATE.dead_adapter_since = 100.0
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=False, healthy=True):
            target = watcher._resolve_target_client([usb])
            assert watcher._update_dead_adapter_detection([usb], target) is False
        assert watcher.STATE.dead_adapter_ifname == ""
        assert watcher.STATE.dead_adapter_checks == 0
        assert watcher.STATE.dead_adapter_since is None

    def test_healthy_decay_does_not_erase_accounting_ledger(self, watcher):
        usb = self._usb(watcher)
        watcher.STATE.dead_adapter_ifname = "wlan0"
        watcher.STATE.dead_adapter_checks = 3
        watcher.STATE.dead_adapter_healthy_since = 100.0
        watcher.STATE.adapter_reset_ledgers[usb.stable_id] = {
            "recent_resets": [100.0],
            "total_resets": 1,
            "quarantined_until": None,
        }
        now = 100.0 + watcher.DEAD_ADAPTER_HEALTHY_DECAY + 1.0
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=False, healthy=True), \
             patch("time.monotonic", return_value=now):
            target = watcher._resolve_target_client([usb])
            assert watcher._update_dead_adapter_detection([usb], target) is False
        assert watcher.STATE.dead_adapter_ifname == ""
        assert _ledger(watcher, usb.stable_id)["recent_resets"] == [100.0]

    def test_identity_change_resets_debounce(self, watcher):
        usb = self._usb(watcher)
        watcher.STATE.dead_adapter_checks = 1
        watcher.STATE.dead_adapter_stable_id = "old:identity:value:00:00:00"
        watcher.STATE.adapter_reset_ledgers["old:identity:value:00:00:00"] = {
            "recent_resets": [10.0],
            "total_resets": 4,
            "quarantined_until": None,
        }
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=True, healthy=False):
            target = watcher._resolve_target_client([usb])
            watcher._update_dead_adapter_detection([usb], target)
        # Active tracking resets on identity change, but the old ledger is isolated.
        assert watcher.STATE.dead_adapter_checks == 1
        assert _ledger(watcher, "old:identity:value:00:00:00")["total_resets"] == 4

    def test_none_target_clears_state(self, watcher):
        watcher.STATE.dead_adapter_ifname = "wlan0"
        watcher.STATE.dead_adapter_checks = 2
        assert watcher._update_dead_adapter_detection([], None) is False
        assert watcher.STATE.dead_adapter_ifname == ""
        assert watcher.STATE.dead_adapter_checks == 0


class TestResetBudget:
    def _target(self, watcher):
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"]):
            return watcher._resolve_target_client(
                [_adapter(watcher, "wlan0", "dc:62:79:91:4d:d6", is_usb=True)])

    def test_exhausted_after_per_window_budget(self, watcher):
        t = self._target(watcher)
        now = 1000.0
        assert watcher._adapter_reset_budget_exhausted(t, now) is False
        watcher._record_adapter_reset(t, now)
        watcher._record_adapter_reset(t, now)
        assert watcher._adapter_reset_budget_exhausted(t, now) is True

    def test_window_prunes_old_resets_but_total_persists(self, watcher):
        t = self._target(watcher)
        watcher._record_adapter_reset(t, 0.0)
        watcher._record_adapter_reset(t, 0.0)
        later = watcher.USB_RESET_WINDOW + 1.0
        # Per-window budget recovered, total still 2 (< total cap) -> not exhausted.
        assert watcher._adapter_reset_budget_exhausted(t, later) is False
        assert _ledger(watcher, t.stable_id)["total_resets"] == 2

    def test_total_cap_exhausts(self, watcher):
        t = self._target(watcher)
        # Spread resets across windows so per-window never trips, but total does.
        for i in range(watcher.USB_MAX_RESETS_TOTAL):
            watcher._record_adapter_reset(t, i * (watcher.USB_RESET_WINDOW + 1.0))
        last = (watcher.USB_MAX_RESETS_TOTAL) * (watcher.USB_RESET_WINDOW + 1.0)
        assert watcher._adapter_reset_budget_exhausted(t, last) is True

    def test_resets_are_per_adapter_identity(self, watcher):
        a = self._target(watcher)
        b = watcher.TargetAdapter(
            ifname="wlan1",
            stable_id="aa:bb:cc:dd:ee:ff",
            kind="usb_wifi",
            is_usb=True,
            is_builtin=False,
            present_in_nm=True,
            present_in_sysfs=True,
            resettable_usb=True,
        )
        watcher._record_adapter_reset(a, 100.0)
        watcher._record_adapter_reset(a, 101.0)
        assert watcher._adapter_reset_budget_exhausted(a, 101.0) is True
        assert watcher._adapter_reset_budget_exhausted(b, 101.0) is False
        assert _ledger(watcher, a.stable_id)["recent_resets"] == [100.0, 101.0]
        assert _ledger(watcher, b.stable_id)["recent_resets"] == []

    def test_replacement_with_different_stable_mac_gets_separate_ledger(self, watcher):
        a = self._target(watcher)
        replacement = watcher.TargetAdapter(
            ifname=a.ifname,
            stable_id="aa:bb:cc:00:00:99",
            kind=a.kind,
            is_usb=a.is_usb,
            is_builtin=a.is_builtin,
            present_in_nm=a.present_in_nm,
            present_in_sysfs=a.present_in_sysfs,
            resettable_usb=a.resettable_usb,
        )
        watcher._record_adapter_reset(a, 100.0)
        watcher._record_adapter_reset(replacement, 200.0)
        assert set(watcher.STATE.adapter_reset_ledgers) == {a.stable_id, replacement.stable_id}
        assert _ledger(watcher, a.stable_id)["recent_resets"] == [100.0]
        assert _ledger(watcher, replacement.stable_id)["recent_resets"] == [200.0]


class TestDeadPhyRebootGuard:
    def test_permits_until_cap_then_suppresses(self, watcher, tmp_path):
        stamp = str(tmp_path / "guard.json")
        with patch.object(watcher, "DEAD_ADAPTER_REBOOT_STAMP", stamp):
            now = 1_000_000.0
            assert watcher._dead_phy_reboot_guard_permits(now) is True
            for _ in range(watcher.DEAD_ADAPTER_MAX_REBOOTS_PER_WINDOW):
                assert watcher._dead_phy_reboot_guard_permits(now) is True
                watcher._record_dead_phy_reboot_request(now, None)
            assert watcher._dead_phy_reboot_guard_permits(now) is False

    def test_old_requests_pruned(self, watcher, tmp_path):
        stamp = str(tmp_path / "guard.json")
        with patch.object(watcher, "DEAD_ADAPTER_REBOOT_STAMP", stamp):
            t0 = 1_000_000.0
            for _ in range(watcher.DEAD_ADAPTER_MAX_REBOOTS_PER_WINDOW):
                watcher._record_dead_phy_reboot_request(t0, None)
            assert watcher._dead_phy_reboot_guard_permits(t0) is False
            later = t0 + watcher.DEAD_ADAPTER_REBOOT_WINDOW + 1.0
            assert watcher._dead_phy_reboot_guard_permits(later) is True

    def test_corrupt_guard_treated_as_empty(self, watcher, tmp_path):
        stamp = tmp_path / "guard.json"
        stamp.write_text("{ not json", encoding="utf-8")
        with patch.object(watcher, "DEAD_ADAPTER_REBOOT_STAMP", str(stamp)):
            assert watcher._dead_phy_reboot_guard_permits(1_000_000.0) is True


# ---------------------------------------------------------------------------
# WP3 (dead-PHY) — escalation ladder
# ---------------------------------------------------------------------------

class TestEscalateDeadAdapterRecovery:
    USB_MAC = "dc:62:79:91:4d:d6"

    def _usb(self, watcher, ifname="wlan0"):
        return _adapter(watcher, ifname, self.USB_MAC, is_usb=True)

    def _mark_dead(self, watcher):
        """Pre-mark the target as dead so the ladder acts immediately."""
        watcher.STATE.dead_adapter_ifname = "wlan0"
        watcher.STATE.dead_adapter_since = 0.0
        watcher.STATE.dead_adapter_first_failure = 0.0
        watcher.STATE.dead_adapter_checks = watcher.DEAD_ADAPTER_DEBOUNCE
        watcher.STATE.dead_adapter_stable_id = self.USB_MAC

    def test_healthy_target_no_action(self, watcher):
        usb = self._usb(watcher)
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=False, healthy=True):
            assert watcher.escalate_dead_adapter_recovery([usb], False) is False

    def test_dead_no_builtin_tries_method_a(self, watcher):
        usb = self._usb(watcher)
        self._mark_dead(watcher)
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=None), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind", return_value=True) as ra, \
             patch.object(watcher.wifi_net, "reset_usb_adapter_reenumerate", return_value=True) as rb, \
             patch.object(watcher, "wait_for_interface_reappears", return_value="wlan0"), \
             patch.object(watcher, "_activate_committed_on", return_value=False), \
             patch.object(watcher, "verify_avahi_after_handover"):
            handled = watcher.escalate_dead_adapter_recovery([usb], False)
        assert handled is True
        ra.assert_called_once_with("wlan0")
        rb.assert_not_called()
        assert watcher.STATE.last_reset_method == "A"

    def test_method_b_after_a(self, watcher):
        usb = self._usb(watcher)
        self._mark_dead(watcher)
        watcher.STATE.last_reset_method = "A"
        watcher.STATE.last_reset_attempt = 0.0
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=None), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind", return_value=True) as ra, \
             patch.object(watcher.wifi_net, "reset_usb_adapter_reenumerate", return_value=True) as rb, \
             patch.object(watcher, "wait_for_interface_reappears", return_value="wlan0"), \
             patch.object(watcher, "_activate_committed_on", return_value=False), \
             patch.object(watcher, "verify_avahi_after_handover"), \
             patch("time.monotonic", return_value=10_000.0):
            watcher.escalate_dead_adapter_recovery([usb], False)
        rb.assert_called_once_with("wlan0")
        ra.assert_not_called()
        assert watcher.STATE.last_reset_method == "B"

    def test_reset_success_clears_dead_state(self, watcher):
        usb = self._usb(watcher)
        self._mark_dead(watcher)
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=None), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind", return_value=True), \
             patch.object(watcher.wifi_net, "discover_adapters", return_value=[usb]), \
             patch.object(watcher, "wait_for_interface_reappears", return_value="wlan0"), \
             patch.object(watcher, "_activate_committed_on", return_value=True), \
             patch.object(watcher, "verify_avahi_after_handover"):
            watcher.escalate_dead_adapter_recovery([usb], False)
        assert watcher.STATE.dead_adapter_ifname == ""

    def test_builtin_fallback_preferred_over_reset(self, watcher):
        usb = self._usb(watcher)
        builtin = _adapter(watcher, "wlan1", "aa:bb:cc:00:00:01", is_builtin=True)
        self._mark_dead(watcher)
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0", "wlan1"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=builtin), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind", return_value=True) as ra, \
             patch.object(watcher, "_activate_committed_on", return_value=True) as act, \
             patch.object(watcher, "_set_active_client"), \
             patch.object(watcher, "verify_avahi_after_handover"):
            handled = watcher.escalate_dead_adapter_recovery([usb, builtin], False)
        assert handled is True
        act.assert_called_once_with("wlan1")
        ra.assert_not_called()
        assert watcher.STATE.using_builtin_fallback is True

    def test_resets_happen_even_when_wired(self, watcher):
        usb = self._usb(watcher)
        self._mark_dead(watcher)
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=None), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind", return_value=True) as ra, \
             patch.object(watcher, "wait_for_interface_reappears", return_value="wlan0"), \
             patch.object(watcher, "_activate_committed_on", return_value=False), \
             patch.object(watcher, "verify_avahi_after_handover"), \
             patch.object(watcher, "reboot_system") as reboot:
            # wired_connected=True -> reset still attempted, reboot never.
            watcher.escalate_dead_adapter_recovery([usb], True)
        ra.assert_called_once()
        reboot.assert_not_called()

    def test_reboot_when_offline_and_dead_long_enough(self, watcher):
        usb = self._usb(watcher)
        self._mark_dead(watcher)
        # Non-resettable target so the ladder falls through to reboot.
        watcher.STATE.last_reset_attempt = 0.0
        now = watcher.DEAD_ADAPTER_REBOOT_AFTER + 100.0
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=[],  # not resettable
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=None), \
             patch("time.monotonic", return_value=now), \
             patch("time.time", return_value=1_000_000.0), \
             patch.object(watcher, "reboot_system", return_value=True) as reboot:
            with patch.object(watcher, "DEAD_ADAPTER_REBOOT_STAMP",
                              str(tmp_guard())):
                handled = watcher.escalate_dead_adapter_recovery([usb], False)
        assert handled is True
        reboot.assert_called_once_with("NetworkDown")
        assert watcher.STATE.conn_reboot_retry_after == float("inf")

    def test_reboot_suppressed_by_persistent_guard(self, watcher):
        usb = self._usb(watcher)
        self._mark_dead(watcher)
        now = watcher.DEAD_ADAPTER_REBOOT_AFTER + 100.0
        guard = tmp_guard()
        with patch.object(watcher, "DEAD_ADAPTER_REBOOT_STAMP", str(guard)):
            # Fill the guard to the cap.
            for _ in range(watcher.DEAD_ADAPTER_MAX_REBOOTS_PER_WINDOW):
                watcher._record_dead_phy_reboot_request(1_000_000.0, None)
            with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                       usb_paths_ifaces=[],
                                       link_down=True, healthy=False), \
                 patch.object(watcher.wifi_net, "resolve_builtin", return_value=None), \
                 patch("time.monotonic", return_value=now), \
                 patch("time.time", return_value=1_000_000.0), \
                 patch.object(watcher, "reboot_system") as reboot:
                handled = watcher.escalate_dead_adapter_recovery([usb], False)
        assert handled is False
        reboot.assert_not_called()

    def test_quarantine_when_budget_spent_and_other_path(self, watcher):
        usb = self._usb(watcher)
        self._mark_dead(watcher)
        # Spend the per-window budget.
        _spend_window_budget(watcher, self.USB_MAC, now=0.0)
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=None), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind", return_value=True) as ra, \
             patch("time.monotonic", return_value=1.0):
            # wired_connected=True provides the alternate path.
            handled = watcher.escalate_dead_adapter_recovery([usb], True)
        assert handled is False
        ra.assert_not_called()
        assert _ledger(watcher, self.USB_MAC)["quarantined_until"] is not None

    def test_usb_only_emergency_attempt_when_no_path(self, watcher):
        usb = self._usb(watcher)
        self._mark_dead(watcher)
        _spend_window_budget(watcher, self.USB_MAC, now=0.0)
        watcher.STATE.last_reset_attempt = 0.0
        emergency_now = watcher.USB_EMERGENCY_BACKOFF + 10.0
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=None), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind", return_value=True) as ra, \
             patch.object(watcher, "wait_for_interface_reappears", return_value="wlan0"), \
             patch.object(watcher, "_activate_committed_on", return_value=False), \
             patch.object(watcher, "verify_avahi_after_handover"), \
             patch("time.monotonic", return_value=emergency_now):
            # No other path (wired False, no healthy adapter) -> emergency reset.
            handled = watcher.escalate_dead_adapter_recovery([usb], False)
        assert handled is True
        ra.assert_called_once()

    def test_quarantine_is_per_adapter(self, watcher):
        usb = self._usb(watcher)
        other = _adapter(watcher, "wlan1", "aa:bb:cc:00:00:02", is_usb=True)
        self._mark_dead(watcher)
        _spend_window_budget(watcher, self.USB_MAC, now=0.0)
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0", "wlan1"],
                                   usb_paths_ifaces=["wlan0", "wlan1"],
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=None), \
             patch("time.monotonic", return_value=1.0):
            watcher.escalate_dead_adapter_recovery([usb, other], True)
        assert _ledger(watcher, self.USB_MAC)["quarantined_until"] is not None
        assert other.stable_id not in watcher.STATE.adapter_reset_ledgers

    def test_single_radio_setup_mode_resets_not_deadlocks(self, watcher):
        usb = self._usb(watcher)
        self._mark_dead(watcher)
        watcher.STATE.setup_mode = True
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=None), \
             patch.object(watcher, "resolve_hotspot_adapter", return_value=usb), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind", return_value=True) as ra, \
             patch.object(watcher, "wait_for_interface_reappears", return_value="wlan0"), \
             patch.object(watcher, "_activate_committed_on", return_value=False), \
             patch.object(watcher, "verify_avahi_after_handover"):
            handled = watcher.escalate_dead_adapter_recovery([usb], False)
        # Sole dead radio is reset rather than left as a dead hotspot.
        assert handled is True
        ra.assert_called_once()

    def test_setup_mode_defers_to_ap_on_other_adapter(self, watcher):
        usb = self._usb(watcher)
        builtin = _adapter(watcher, "wlan1", "aa:bb:cc:00:00:01", is_builtin=True)
        self._mark_dead(watcher)
        watcher.STATE.setup_mode = True
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0", "wlan1"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=builtin), \
             patch.object(watcher, "resolve_hotspot_adapter", return_value=builtin), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind", return_value=True) as ra:
            handled = watcher.escalate_dead_adapter_recovery([usb, builtin], False)
        assert handled is False
        ra.assert_not_called()


def tmp_guard():
    """Return a unique temp path for a dead-PHY reboot guard file."""
    import tempfile
    return Path(tempfile.mkdtemp()) / "dead-phy-reboot.stamp"


# ---------------------------------------------------------------------------
# WP4 (dead-PHY) — reboot-threshold domain: 30 min, not the 12h catch-all
# ---------------------------------------------------------------------------

class TestDeadPhyRebootThreshold:
    USB_MAC = "dc:62:79:91:4d:d6"

    def _wedged_offline(self, watcher, now):
        usb = _adapter(watcher, "wlan0", self.USB_MAC, is_usb=True)
        watcher.STATE.dead_adapter_ifname = "wlan0"
        watcher.STATE.dead_adapter_since = 1.0
        watcher.STATE.dead_adapter_first_failure = 1.0
        watcher.STATE.dead_adapter_checks = watcher.DEAD_ADAPTER_DEBOUNCE
        watcher.STATE.dead_adapter_stable_id = self.USB_MAC
        watcher.STATE.last_reset_attempt = 1.0
        return usb

    def _run(self, watcher, now):
        usb = self._wedged_offline(watcher, now)
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=[],  # non-resettable -> reboot rung
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=None), \
             patch("time.monotonic", return_value=now), \
             patch("time.time", return_value=1_000_000.0), \
             patch.object(watcher, "DEAD_ADAPTER_REBOOT_STAMP", str(tmp_guard())), \
             patch.object(watcher, "reboot_system", return_value=True) as reboot:
            watcher.escalate_dead_adapter_recovery([usb], False)
        return reboot

    def test_no_reboot_before_30_min(self, watcher):
        reboot = self._run(watcher, watcher.DEAD_ADAPTER_REBOOT_AFTER - 60.0)
        reboot.assert_not_called()

    def test_reboot_at_30_min_not_catchall(self, watcher):
        # Far below the 12h no-active-path catch-all, but past the 30-min dead-PHY path.
        now = watcher.DEAD_ADAPTER_REBOOT_AFTER + 60.0
        assert now < watcher.NO_ACTIVE_PATH_REBOOT_AFTER
        reboot = self._run(watcher, now)
        reboot.assert_called_once_with("NetworkDown")

    def test_threshold_is_30_min(self, watcher):
        assert watcher.DEAD_ADAPTER_REBOOT_AFTER == watcher.GW_DOWN_REBOOT_AFTER
        assert watcher.DEAD_ADAPTER_REBOOT_AFTER == 30 * 60


def _run_monitor_once(
    watcher,
    *,
    now: float,
    wifi_cfg: bool = False,
    wired_connected: bool = False,
    wired_ok: bool = False,
    wifi_connected: bool = False,
    client_ok: bool = False,
    adapters: list | None = None,
    active_client=None,
    dead_recovery=None,
):
    """Run one monitor pass with external facts patched to deterministic values."""
    adapters = adapters if adapters is not None else []
    with ExitStack() as stack:
        stack.enter_context(patch("time.monotonic", return_value=now))
        stack.enter_context(patch.object(watcher, "check_and_repair_avahi_hostname"))
        stack.enter_context(patch.object(watcher, "maybe_reannounce_mdns"))
        stack.enter_context(patch.object(watcher, "revert_expired_log_level"))
        stack.enter_context(patch.object(watcher, "is_wifi_configured", return_value=wifi_cfg))
        stack.enter_context(patch.object(watcher, "is_wired_connected", return_value=wired_connected))
        stack.enter_context(patch.object(watcher, "any_wired_path_healthy", return_value=wired_ok))
        stack.enter_context(patch.object(watcher.wifi_net, "discover_adapters", return_value=adapters))
        stack.enter_context(patch.object(watcher.wifi_net, "list_interface_addresses", return_value={}))
        stack.enter_context(patch.object(watcher, "update_known_adapters"))
        stack.enter_context(patch.object(watcher, "resolve_active_client", return_value=active_client))
        stack.enter_context(patch.object(watcher, "handle_usb_failure_fallback", return_value=False))
        stack.enter_context(patch.object(watcher.wifi_net, "is_wifi_connected", return_value=wifi_connected))
        stack.enter_context(patch.object(watcher, "is_wifi_client_healthy", return_value=client_ok))
        stack.enter_context(patch.object(watcher, "handle_runtime_usb_adoption", return_value=False))
        if dead_recovery is None:
            dead_recovery = MagicMock(return_value=False)
        stack.enter_context(patch.object(watcher, "escalate_dead_adapter_recovery", dead_recovery))
        stack.enter_context(patch.object(watcher, "publish_network_status"))
        stack.enter_context(patch.object(watcher, "log_on_change"))
        stack.enter_context(patch.object(watcher, "step_boot_client_bringup",
                                          return_value=watcher.Verdict.CONTINUE))
        connect = stack.enter_context(patch.object(watcher, "connect_to_configured_wifi"))
        watcher.network_monitor_loop(run_once=True)
        return connect


class TestHotspotPurposeMachine:
    """WP3 — hotspot lifetime/probe policy driven by the purpose table; defects 1 & 2."""

    def _session(self, watcher, purpose, entered_at):
        watcher.STATE.setup_mode = True
        watcher.STATE.hotspot = watcher.HotspotSession(purpose=purpose, entered_at=entered_at)

    def test_defect1_boot_recovery_probes_for_return(self, watcher):
        # A configured device offline at boot is BOOT_RECOVERY and probes for the
        # saved network each pass — it does not sit until the 30-min deadline.
        # Built-in hosts the hotspot; the returned USB is the second radio probed
        # without dropping the AP (WP6 second-radio path).
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:01", is_usb=True)
        self._session(watcher, watcher.HotspotPurpose.BOOT_RECOVERY, entered_at=100.0)
        with patch.object(watcher, "_attempt_recovery_reconnect") as probe:
            _run_monitor_once(watcher, now=120.0, wifi_cfg=True, adapters=[builtin, usb])
        probe.assert_called_once()

    def test_first_run_does_not_probe(self, watcher):
        # FIRST_RUN has nothing saved to probe for.
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:01", is_usb=True)
        self._session(watcher, watcher.HotspotPurpose.FIRST_RUN, entered_at=100.0)
        with patch.object(watcher, "_attempt_recovery_reconnect") as probe, \
             patch.object(watcher, "leave_setup_mode") as leave:
            _run_monitor_once(watcher, now=120.0, wifi_cfg=False, adapters=[usb])
        probe.assert_not_called()
        leave.assert_not_called()

    def test_first_run_is_indefinite(self, watcher):
        # Past 30 minutes, an unconfigured FIRST_RUN hotspot is not torn down.
        self._session(watcher, watcher.HotspotPurpose.FIRST_RUN, entered_at=0.0)
        now = watcher.AP_MAX_DURATION + 60.0
        with patch.object(watcher, "leave_setup_mode") as leave:
            _run_monitor_once(watcher, now=now, wifi_cfg=False)
        leave.assert_not_called()

    def test_recovery_purpose_expires_at_deadline(self, watcher):
        self._session(watcher, watcher.HotspotPurpose.USB_LOSS_RECOVERY, entered_at=0.0)
        now = watcher.AP_MAX_DURATION + 60.0
        with patch.object(watcher, "leave_setup_mode") as leave, \
             patch.object(watcher, "_attempt_recovery_reconnect"):
            _run_monitor_once(watcher, now=now, wifi_cfg=True)
        leave.assert_called_once()

    def test_explicit_hotspot_not_torn_down_by_ethernet(self, watcher):
        # EXPLICIT_RECONFIGURE is not eth-suppressible (Section 2.3).
        self._session(watcher, watcher.HotspotPurpose.EXPLICIT_RECONFIGURE, entered_at=100.0)
        with patch.object(watcher, "leave_setup_mode") as leave, \
             patch.object(watcher, "_attempt_recovery_reconnect"):
            _run_monitor_once(watcher, now=120.0, wifi_cfg=False,
                              wired_connected=True, wired_ok=True)
        leave.assert_not_called()

    def test_user_hotspot_does_not_probe_within_grace(self, watcher):
        # A user opened the portal to change networks; within HOTSPOT_PROBE_GRACE
        # the watcher must NOT probe for (and rejoin) the old saved network, or it
        # would tear the hotspot down before the user can pick a new one.
        self._session(watcher, watcher.HotspotPurpose.EXPLICIT_RECONFIGURE, entered_at=100.0)
        within = 100.0 + watcher.HOTSPOT_PROBE_GRACE - 1.0
        with patch.object(watcher, "_attempt_recovery_reconnect") as probe:
            _run_monitor_once(watcher, now=within, wifi_cfg=True)
        probe.assert_not_called()

    def test_user_hotspot_probes_after_grace(self, watcher):
        # Once the grace window elapses, the user-initiated hotspot resumes
        # probing for the saved network (idle-user recovery before the deadline).
        self._session(watcher, watcher.HotspotPurpose.MANUAL, entered_at=0.0)
        after = watcher.HOTSPOT_PROBE_GRACE + 30.0
        with patch.object(watcher, "_attempt_recovery_reconnect") as probe:
            _run_monitor_once(watcher, now=after, wifi_cfg=True)
        probe.assert_called_once()

    def test_recovery_hotspot_probes_immediately_no_grace(self, watcher):
        # Automatic recovery purposes have probe_grace_s == 0: they lost the path
        # involuntarily and must probe from the first pass.
        self._session(watcher, watcher.HotspotPurpose.USB_LOSS_RECOVERY, entered_at=100.0)
        with patch.object(watcher, "_attempt_recovery_reconnect") as probe:
            _run_monitor_once(watcher, now=101.0, wifi_cfg=True)
        probe.assert_called_once()

    def test_defect2_recovery_enterable_after_earlier_session(self, watcher):
        # After a hotspot was used and left earlier this boot, a later USB-loss
        # fallback still raises a recovery hotspot (no once-per-boot suppression).
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        # Simulate an earlier session that has since been left.
        with patch.object(watcher, "start_ap_mode"), patch.object(watcher, "stop_ap_mode"):
            watcher.enter_setup_mode(watcher.HotspotPurpose.FIRST_RUN, "earlier")
            watcher.leave_setup_mode("earlier done")
        facts = _facts_for(watcher, [builtin], None)
        event = watcher.ClientFailed(ifname="wlan1", mac="bb:bb:bb:bb:bb:0a",
                                     reason="later usb loss", has_alt_path=False)
        action = watcher.RecoveryAction(watcher.RecoveryKind.ENTER_HOTSPOT,
                                        purpose=watcher.HotspotPurpose.BOOT_RECOVERY)
        rf = watcher.RecoveryFacts(
            adapters_by_ifname={}, onboard_ifname="", usb_ifnames=(),
            preferred_usb_ifname="", hotspot_ifname="", active_ifname="",
            saved_configured=True, wired_ok=False, taken_at=1000.0)
        with patch.object(watcher, "gather_recovery_facts", return_value=rf), \
             patch.object(watcher, "next_recovery_action", return_value=action), \
             patch.object(watcher, "enter_setup_mode") as enter:
            acted = watcher.apply_client_failed(event, facts)
        assert acted is True
        enter.assert_called_once()
        assert enter.call_args[0][0] is watcher.HotspotPurpose.USB_LOSS_RECOVERY


class TestBootEntryOnboardFirst:
    """Recovery-ladder WP3 — boot-window entry tries a client before the hotspot."""

    def test_wedged_usb_boot_entry_activates_onboard_not_hotspot(self, watcher):
        # Field-log shape: USB active but wedged, onboard idle. Boot-window entry
        # must run the client on the onboard rather than open a hotspot on it.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "dc:62:79:91:4d:d6", is_usb=True)
        watcher.STATE.boot_time = 300.0  # now=1000 -> boot_age 700s, inside window
        with patch.object(watcher, "_activate_committed_on", return_value=True) as act, \
             patch.object(watcher, "enter_setup_mode") as enter, \
             patch.object(watcher, "verify_avahi_after_handover"), \
             patch.object(watcher.wifi_net, "read_link_down",
                          side_effect=lambda ifn: ifn == "wlan1"):
            _run_monitor_once(
                watcher, now=1000.0, wifi_cfg=True, wifi_connected=True,
                client_ok=False, adapters=[builtin, usb], active_client=usb,
            )
        act.assert_called_with("wlan0")
        enter.assert_not_called()
        assert watcher.STATE.active_client_ifname == "wlan0"
        assert watcher.STATE.using_builtin_fallback is True

    def test_onboard_fails_boot_entry_falls_through_to_hotspot(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "dc:62:79:91:4d:d6", is_usb=True)
        watcher.STATE.boot_time = 300.0
        with patch.object(watcher, "_activate_committed_on", return_value=False), \
             patch.object(watcher, "enter_setup_mode") as enter, \
             patch.object(watcher.wifi_net, "read_link_down",
                          side_effect=lambda ifn: ifn == "wlan1"):
            _run_monitor_once(
                watcher, now=1000.0, wifi_cfg=True, wifi_connected=True,
                client_ok=False, adapters=[builtin, usb], active_client=usb,
            )
        enter.assert_called_once()
        assert enter.call_args[0][0] is watcher.HotspotPurpose.BOOT_RECOVERY


class TestRecoveryFacts:
    """Recovery-ladder WP1 — shared per-adapter facts + RecoveryFacts snapshot."""

    def _facts(self, watcher, adapters, *, active_client=None, now=1000.0,
               wifi_cfg=True, wired_ok=False):
        return watcher.Facts(
            wifi_configured=wifi_cfg,
            adapters=adapters,
            wired_connected=False,
            wired_ok=wired_ok,
            active_client=active_client,
            addresses={},
            taken_at=now,
        )

    def test_adapter_recovery_facts_healthy_builtin(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        with patch.object(watcher, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=False):
            rf = watcher._adapter_recovery_facts(builtin, 1000.0)
        assert rf.ifname == "wlan0"
        assert rf.is_builtin and not rf.is_usb
        assert rf.healthy is True and rf.carrier is True
        assert rf.quarantined is False and rf.budget_exhausted is False

    def test_gather_prefers_usable_usb(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "dc:62:79:91:4d:d6", is_usb=True)
        facts = self._facts(watcher, [builtin, usb], active_client=usb)
        with patch.object(watcher, "is_wifi_client_healthy",
                          side_effect=lambda ifn, **k: ifn == "wlan0"), \
             patch.object(watcher.wifi_net, "read_link_down",
                          side_effect=lambda ifn: ifn == "wlan1"):
            rec = watcher.gather_recovery_facts(facts)
        assert rec.onboard_ifname == "wlan0"
        assert rec.usb_ifnames == ("wlan1",)
        assert rec.preferred_usb_ifname == "wlan1"
        assert rec.active_ifname == "wlan1"
        assert rec.hotspot_ifname == ""  # not in setup

    def test_gather_excludes_quarantined_usb(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "dc:62:79:91:4d:d6", is_usb=True)
        watcher.STATE.adapter_reset_ledgers[usb.stable_id] = {
            "recent_resets": [], "total_resets": 5, "quarantined_until": 1000.0 + 3600,
        }
        facts = self._facts(watcher, [builtin, usb])
        with patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=True):
            rec = watcher.gather_recovery_facts(facts)
        assert rec.preferred_usb_ifname == ""  # quarantined USB is not preferred
        assert rec.adapters_by_ifname["wlan1"].quarantined is True

    def test_gather_excludes_noip_suppressed_usb(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "dc:62:79:91:4d:d6", is_usb=True)
        # Past the no-IP stop budget -> suppressed until MAC changes.
        watcher.STATE.adapter_noip_ledgers[usb.stable_id] = {
            "count": watcher.wifi_recovery.NOIP_STOP_AFTER, "retry_after": float("inf"),
        }
        facts = self._facts(watcher, [builtin, usb])
        with patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=True):
            rec = watcher.gather_recovery_facts(facts)
        assert rec.preferred_usb_ifname == ""
        assert rec.adapters_by_ifname["wlan1"].noip_suppressed is True

    def test_gather_excludes_noip_suppressed_onboard(self, watcher):
        # C2-WP1: a no-IP-suppressed onboard is not offered as a client rung, so
        # the single decider won't blindly engage it on a USB failure.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        watcher.STATE.adapter_noip_ledgers[builtin.stable_id] = {
            "count": watcher.wifi_recovery.NOIP_STOP_AFTER, "retry_after": float("inf"),
        }
        facts = self._facts(watcher, [builtin])
        with patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=False):
            rec = watcher.gather_recovery_facts(facts)
        assert rec.onboard_ifname == ""   # gated out
        assert rec.adapters_by_ifname["wlan0"].noip_suppressed is True

    def test_gather_excludes_quarantined_onboard(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        # Quarantine the onboard via the reset ledger.
        watcher.STATE.adapter_reset_ledgers[builtin.stable_id] = {
            "quarantined_until": 1e12, "recent_resets": [], "total_resets": 0,
        }
        facts = self._facts(watcher, [builtin])
        with patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=True):
            rec = watcher.gather_recovery_facts(facts)
        assert rec.onboard_ifname == ""


class TestExplicitModelInvariants:
    """WP8 — the overlay decision is sited in wifi_recovery.

    The pure next_mode / next_recovery_action / PURPOSE_TABLE purity and
    invariant tests moved to tests/test_wifi_policy.py (Phase B-WP4).
    """

    def test_overlay_decision_only_in_wifi_recovery(self, watcher):
        wr = watcher.wifi_recovery
        assert hasattr(wr, "diagnose_client_failure")
        assert hasattr(wr, "is_degraded_no_ip")
        # wifi_status consumes the verdict; it must not define the decision.
        assert not hasattr(watcher.wifi_status, "diagnose_client_failure")
        assert not hasattr(watcher.wifi_status, "is_degraded_no_ip")

    def test_builtin_is_preferred_recovery_path(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:01", is_usb=True)
        assert watcher.resolve_hotspot_adapter([usb, builtin]) is builtin


class TestRecoveryExitEdge:
    """C2-WP2 — the in-hotspot probe routes through the single recovery ladder;
    a dead second radio no longer blocks the onboard climb.

    These drive the real gather_recovery_facts + next_recovery_action and assert
    the ladder's chosen RecoveryAction reaches _apply_client_activation (the apply
    seam is patched to isolate the routing decision).
    """

    def _in_hotspot(self, watcher):
        # The probe only ever runs from within a recovery hotspot on the onboard.
        watcher.STATE.setup_mode = True
        watcher.STATE.hotspot = watcher.HotspotSession(
            purpose=watcher.HotspotPurpose.BOOT_RECOVERY, entered_at=0.0)

    def test_dead_second_radio_falls_through_to_onboard_rejoin(self, watcher):
        # Field-log shape: AP on onboard wlan0, USB wlan1 wedged. The wedged USB
        # (no carrier) must NOT be chosen; the ladder selects the onboard drop-AP
        # rejoin (exit edge) instead of probing the dead USB forever.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "dc:62:79:91:4d:d6", is_usb=True)
        self._in_hotspot(watcher)
        facts = _facts_for(watcher, [builtin, usb], None)
        with patch.object(watcher.wifi_net, "read_link_down",
                          side_effect=lambda ifn: ifn == "wlan1"), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher, "_saved_ssid_visible", return_value=True), \
             patch.object(watcher, "_apply_client_activation", return_value=True) as apply:
            watcher._attempt_recovery_reconnect(facts)
        apply.assert_called_once()
        action = apply.call_args[0][0]
        assert action.kind is watcher.RecoveryKind.ACTIVATE_ONBOARD
        assert action.ifname == "wlan0"
        assert action.drop_hotspot is True

    def test_quarantined_second_radio_falls_through_to_onboard(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "dc:62:79:91:4d:d6", is_usb=True)
        watcher.STATE.adapter_reset_ledgers[usb.stable_id] = {
            "recent_resets": [], "total_resets": 5, "quarantined_until": 1000.0 + 3600,
        }
        self._in_hotspot(watcher)
        facts = _facts_for(watcher, [builtin, usb], None)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher, "_saved_ssid_visible", return_value=True), \
             patch.object(watcher, "_apply_client_activation", return_value=True) as apply:
            watcher._attempt_recovery_reconnect(facts)
        apply.assert_called_once()
        action = apply.call_args[0][0]
        assert action.kind is watcher.RecoveryKind.ACTIVATE_ONBOARD
        assert action.drop_hotspot is True

    def test_healthy_second_radio_still_probes_without_dropping_ap(self, watcher):
        # A genuinely usable second radio keeps the existing behaviour: the ladder
        # selects ACTIVATE_USB without dropping the AP (drop_hotspot False).
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "dc:62:79:91:4d:d6", is_usb=True)
        self._in_hotspot(watcher)
        facts = _facts_for(watcher, [builtin, usb], None)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher, "_saved_ssid_visible") as vis, \
             patch.object(watcher, "_apply_client_activation", return_value=True) as apply:
            watcher._attempt_recovery_reconnect(facts)
        apply.assert_called_once()
        action = apply.call_args[0][0]
        assert action.kind is watcher.RecoveryKind.ACTIVATE_USB
        assert action.ifname == "wlan1"
        assert action.drop_hotspot is False
        vis.assert_not_called()   # no AP drop -> no scan-gate

    def test_ladder_hold_retains_hotspot(self, watcher):
        # Ethernet appearing mid-hotspot -> ladder HOLDs; the probe must not drop
        # the AP or attempt any client activation (no divergence from the ladder).
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "dc:62:79:91:4d:d6", is_usb=True)
        self._in_hotspot(watcher)
        facts = _facts_for(watcher, [builtin, usb], None, wired_ok=True)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher, "_saved_ssid_visible") as vis, \
             patch.object(watcher, "_apply_client_activation") as apply:
            watcher._attempt_recovery_reconnect(facts)
        apply.assert_not_called()
        vis.assert_not_called()


class TestProbePatience:
    """Recovery-ladder WP4 — fail fast when nmcli reports the SSID is not visible."""

    def test_network_absent_detects_hard_failure(self, watcher):
        absent = MagicMock(returncode=4,
                           stderr="Error: activation failed: The Wi-Fi network could not be found")
        assert watcher._activation_network_absent(absent) is True

    def test_network_absent_false_on_success_and_other_errors(self, watcher):
        ok = MagicMock(returncode=0, stderr="")
        other = MagicMock(returncode=1, stderr="Error: something else")
        assert watcher._activation_network_absent(ok) is False
        assert watcher._activation_network_absent(other) is False

    def test_activate_committed_on_skips_wait_when_absent(self, watcher):
        state = watcher.wifi_net.NetworkState(connection_name="Home", connection_uuid="u1")
        absent = MagicMock(returncode=4,
                           stderr="Error: The Wi-Fi network could not be found")
        with patch.object(watcher, "get_configured_network_state", return_value=state), \
             patch.object(watcher, "_resolve_committed_uuid", return_value="u1"), \
             patch.object(watcher, "run_cmd", return_value=absent), \
             patch.object(watcher, "wait_for_connection") as waiter:
            result = watcher._activate_committed_on("wlan1")
        assert result is False
        waiter.assert_not_called()


class TestFieldLogRecoveryRegression:
    """Recovery-ladder — end-to-end regression for the 30-Jun-2026 field log.

    A wedged USB (wlan1) trapped the device in a BOOT_RECOVERY hotspot on the only
    good radio (onboard wlan0) for 30 minutes because the dead USB was probed
    forever and the onboard was never tried as a client.  These pass the full
    monitor loop and assert the onboard client path is taken promptly instead.
    """

    def test_boot_entry_recovers_on_onboard_without_hotspot(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "dc:62:79:91:4d:d6", is_usb=True)
        watcher.STATE.boot_time = 300.0  # boot_age 700s at now=1000 (inside window)
        with patch.object(watcher, "_activate_committed_on", return_value=True), \
             patch.object(watcher, "enter_setup_mode") as enter, \
             patch.object(watcher, "verify_avahi_after_handover"), \
             patch.object(watcher.wifi_net, "read_link_down",
                          side_effect=lambda ifn: ifn == "wlan1"):
            _run_monitor_once(
                watcher, now=1000.0, wifi_cfg=True, wifi_connected=True,
                client_ok=False, adapters=[builtin, usb], active_client=usb,
            )
        enter.assert_not_called()  # no hotspot: ran on the onboard instead
        assert watcher.STATE.active_client_ifname == "wlan0"

    def test_in_hotspot_climbs_to_onboard_not_dead_usb(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "dc:62:79:91:4d:d6", is_usb=True)
        watcher.STATE.setup_mode = True
        watcher.STATE.hotspot = watcher.HotspotSession(
            purpose=watcher.HotspotPurpose.BOOT_RECOVERY, entered_at=0.0)
        with patch.object(watcher.wifi_net, "read_link_down",
                          side_effect=lambda ifn: ifn == "wlan1"), \
             patch.object(watcher, "_saved_ssid_visible", return_value=True), \
             patch.object(watcher, "_apply_client_activation", return_value=True) as apply:
            _run_monitor_once(watcher, now=120.0, wifi_cfg=True,
                              adapters=[builtin, usb], active_client=usb)
        # The ladder selects the onboard drop-AP rejoin, not the dead USB probe.
        apply.assert_called_once()
        action = apply.call_args[0][0]
        assert action.kind is watcher.RecoveryKind.ACTIVATE_ONBOARD
        assert action.ifname == "wlan0"
        assert action.drop_hotspot is True


class TestLoopHandlers:
    """Loop-handlers WP6 — direct per-handler tests over synthetic contexts.

    Isolation: the `watcher` fixture resets STATE (and _last_logged_values); the
    event-setting tests clear the threading.Events they touch so they cannot leak.
    """

    def _pre(self, watcher, *, now=1000.0, boot_time=0.0, avahi_ok=True):
        return watcher.PreFactsContext(now=now, boot_time=boot_time, avahi_ok=avahi_ok)

    def _facts(self, watcher, *, adapters=None, wifi_cfg=False, wired_ok=False,
               wired_connected=False, active_client=None, now=1000.0):
        return watcher.Facts(
            wifi_configured=wifi_cfg, adapters=adapters or [],
            wired_connected=wired_connected, wired_ok=wired_ok,
            active_client=active_client, addresses={}, taken_at=now,
        )

    def _hctx(self, watcher, facts, *, playing=None, health_ifname="wlan0",
              wifi_connected=False, client_ok=False, conn_ok=False, active_path_ok=False):
        pre = self._pre(watcher, now=facts.taken_at)
        fctx = watcher.FactsContext(pre, facts, playing or (lambda: False))
        return watcher.HealthContext(
            fctx, health_ifname=health_ifname, wifi_connected=wifi_connected,
            client_ok=client_ok, conn_ok=conn_ok, active_path_ok=active_path_ok,
        )

    # ---- run_steps driver ----

    def test_run_steps_short_circuits_on_first_own_pass(self, watcher):
        calls = []
        def cont(ctx): calls.append("c1"); return watcher.Verdict.CONTINUE
        def own(ctx): calls.append("own"); return watcher.Verdict.OWN_PASS
        def after(ctx): calls.append("after"); return watcher.Verdict.CONTINUE
        result = watcher.run_steps([cont, own, after], None)
        assert result is watcher.Verdict.OWN_PASS
        assert calls == ["c1", "own"]  # `after` never runs

    def test_run_steps_all_continue(self, watcher):
        result = watcher.run_steps(
            [lambda c: watcher.Verdict.CONTINUE, lambda c: watcher.Verdict.CONTINUE], None)
        assert result is watcher.Verdict.CONTINUE

    def test_late_own_pass_blocks_trailing_handlers(self, watcher):
        # A Phase B-late OWN_PASS (hotspot policy) must prevent the trailing
        # always-CONTINUE handlers from running — the load-bearing short-circuit.
        watcher.STATE.boot_time = 0.0
        with patch.object(watcher, "step_hotspot_policy",
                          return_value=watcher.Verdict.OWN_PASS) as hp, \
             patch.object(watcher, "step_connection_reliability") as cr, \
             patch.object(watcher, "step_catchall_reboot") as co:
            _run_monitor_once(watcher, now=1000.0, wifi_cfg=True)
        hp.assert_called_once()
        cr.assert_not_called()
        co.assert_not_called()

    # ---- C-WP2: boot-recovery-not-after-online gate ----

    def test_boot_entry_skipped_after_online_this_boot(self, watcher):
        watcher.STATE.been_online_this_boot = True
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:41", is_usb=True)
        facts = self._facts(watcher, adapters=[usb], wifi_cfg=True, active_client=usb, now=100.0)
        hctx = self._hctx(watcher, facts, wifi_connected=True, client_ok=False, conn_ok=False)
        with patch.object(watcher, "next_recovery_action") as nra, \
             patch.object(watcher, "enter_setup_mode") as enter:
            v = watcher.step_boot_ap_entry(hctx)
        assert v is watcher.Verdict.CONTINUE
        nra.assert_not_called()   # runtime paths own it, not boot-entry
        enter.assert_not_called()

    def test_boot_entry_runs_when_never_online(self, watcher):
        watcher.STATE.been_online_this_boot = False
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:42", is_usb=True)
        facts = self._facts(watcher, adapters=[usb], wifi_cfg=True, active_client=usb, now=100.0)
        hctx = self._hctx(watcher, facts, wifi_connected=True, client_ok=False, conn_ok=False)
        action = watcher.RecoveryAction(watcher.RecoveryKind.ENTER_HOTSPOT,
                                        purpose=watcher.HotspotPurpose.BOOT_RECOVERY)
        with patch.object(watcher, "gather_recovery_facts"), \
             patch.object(watcher, "next_recovery_action", return_value=action) as nra, \
             patch.object(watcher, "enter_setup_mode") as enter:
            v = watcher.step_boot_ap_entry(hctx)
        assert v is watcher.Verdict.OWN_PASS
        nra.assert_called_once()
        enter.assert_called_once()

    # ---- Phase A ----

    def test_step_avahi_hostname_gated_and_rate_limited(self, watcher):
        ls = watcher.LoopState()
        with patch.object(watcher, "check_and_repair_avahi_hostname") as chk:
            v = watcher.step_avahi_hostname(self._pre(watcher, now=1000.0), ls)
        assert v is watcher.Verdict.CONTINUE
        chk.assert_called_once()
        assert ls.last_avahi_check == 1000.0
        # Within AVAHI_CHECK_INTERVAL -> not called again.
        with patch.object(watcher, "check_and_repair_avahi_hostname") as chk2:
            watcher.step_avahi_hostname(self._pre(watcher, now=1005.0), ls)
        chk2.assert_not_called()
        # avahi_ok False -> skipped regardless of interval.
        with patch.object(watcher, "check_and_repair_avahi_hostname") as chk3:
            watcher.step_avahi_hostname(self._pre(watcher, now=99999.0, avahi_ok=False), ls)
        chk3.assert_not_called()

    def test_step_manual_ap_request_enters_when_not_in_ap(self, watcher):
        watcher.ap_request_event.clear()
        watcher.STATE.ap_request_reason = "user"
        watcher.ap_request_event.set()
        with patch.object(watcher, "enter_setup_mode") as enter:
            v = watcher.step_manual_ap_request(self._pre(watcher))
        assert v is watcher.Verdict.OWN_PASS
        enter.assert_called_once()
        assert enter.call_args[0][0] is watcher.HotspotPurpose.MANUAL
        assert not watcher.ap_request_event.is_set()

    def test_step_manual_ap_request_continue_when_already_in_ap(self, watcher):
        watcher.ap_request_event.clear()
        watcher.STATE.setup_mode = True
        watcher.ap_request_event.set()
        with patch.object(watcher, "enter_setup_mode") as enter:
            v = watcher.step_manual_ap_request(self._pre(watcher))
        assert v is watcher.Verdict.CONTINUE
        enter.assert_not_called()
        assert not watcher.ap_request_event.is_set()  # event still consumed

    # ---- Phase B-late USB-failure fallback (over the debounced verdict) ----

    def test_step_usb_failure_fallback_owns_pass_on_fallback(self, watcher):
        # C2-WP3: the handler is a Phase B-late handler over the HealthContext; it
        # delegates to handle_usb_failure_fallback(hctx) and owns the pass when a
        # transition fires.
        usb = _adapter(watcher, "wlan1", "dc:62:79:91:4d:d6", is_usb=True)
        facts = self._facts(watcher, adapters=[usb], wifi_cfg=True, active_client=usb)
        hctx = self._hctx(watcher, facts, conn_ok=False)
        with patch.object(watcher, "handle_usb_failure_fallback", return_value=True) as h:
            v = watcher.step_usb_failure_fallback(hctx)
        assert v is watcher.Verdict.OWN_PASS
        h.assert_called_once_with(hctx)

    def test_step_usb_failure_fallback_continue_when_no_transition(self, watcher):
        usb = _adapter(watcher, "wlan1", "dc:62:79:91:4d:d6", is_usb=True)
        facts = self._facts(watcher, adapters=[usb], wifi_cfg=True, active_client=usb)
        hctx = self._hctx(watcher, facts, conn_ok=True)
        with patch.object(watcher, "handle_usb_failure_fallback", return_value=False) as h:
            v = watcher.step_usb_failure_fallback(hctx)
        assert v is watcher.Verdict.CONTINUE
        h.assert_called_once_with(hctx)

    def test_step_usb_failure_fallback_skips_in_setup_mode(self, watcher):
        usb = _adapter(watcher, "wlan1", "dc:62:79:91:4d:d6", is_usb=True)
        facts = self._facts(watcher, adapters=[usb], wifi_cfg=True, active_client=usb)
        hctx = self._hctx(watcher, facts, conn_ok=False)
        watcher.STATE.setup_mode = True
        with patch.object(watcher, "handle_usb_failure_fallback") as h:
            v = watcher.step_usb_failure_fallback(hctx)
        assert v is watcher.Verdict.CONTINUE
        h.assert_not_called()

    # ---- Phase B-late (pinned verdicts) ----

    def test_step_ethernet_wins_owns_pass_even_when_nothing_disconnects(self, watcher):
        facts = self._facts(watcher, wired_ok=True)
        hctx = self._hctx(watcher, facts, playing=lambda: False,
                          conn_ok=True, active_path_ok=True)
        with patch.object(watcher, "run_cmd") as run, \
             patch.object(watcher, "leave_setup_mode") as leave:
            v = watcher.step_ethernet_wins(hctx)
        assert v is watcher.Verdict.OWN_PASS  # owns on the predicate
        run.assert_not_called()               # nothing to disconnect
        leave.assert_not_called()

    def test_step_ethernet_wins_continue_when_not_wired(self, watcher):
        hctx = self._hctx(watcher, self._facts(watcher, wired_ok=False))
        assert watcher.step_ethernet_wins(hctx) is watcher.Verdict.CONTINUE

    def test_step_connection_reliability_always_continue(self, watcher):
        facts = self._facts(watcher, wifi_cfg=True, wired_ok=False)
        hctx = self._hctx(watcher, facts, conn_ok=False)
        with patch.object(watcher, "connect_to_configured_wifi") as conn:
            v = watcher.step_connection_reliability(hctx)
        assert v is watcher.Verdict.CONTINUE   # never owns, even when it reconnects
        conn.assert_called_once()              # prompt reconnect on first entry
        assert watcher.STATE.conn_down_start == hctx.now

    def test_step_catchall_reboot_always_continue(self, watcher):
        watcher.STATE.last_active_path_seen = 0.0
        facts = self._facts(watcher, now=watcher.NO_ACTIVE_PATH_REBOOT_AFTER + 100.0)
        hctx = self._hctx(watcher, facts)
        with patch.object(watcher, "_request_network_down_reboot") as reboot:
            v = watcher.step_catchall_reboot(hctx)
        assert v is watcher.Verdict.CONTINUE
        reboot.assert_called_once()


class TestScanGatedRecovery:
    """C2-WP2 — the ladder-routed in-hotspot probe keeps the apply-layer
    mechanics: RECONNECT_ATTEMPT_INTERVAL bounds the join and, before a drop-AP
    rejoin, RECOVERY_SCAN_INTERVAL gates the saved-SSID scan (the AP is torn down
    only once the network is visible again).  The drop-AP mechanics themselves
    (stop/rebuild) live in activate_client and are covered by TestActivateClient.
    """

    def _in_hotspot(self, watcher):
        watcher.STATE.setup_mode = True
        watcher.STATE.hotspot = watcher.HotspotSession(
            purpose=watcher.HotspotPurpose.BOOT_RECOVERY, entered_at=0.0)

    def test_second_radio_probes_without_dropping_ap(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:01", is_usb=True)
        self._in_hotspot(watcher)
        facts = _facts_for(watcher, [builtin, usb], None)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher, "_saved_ssid_visible") as vis, \
             patch.object(watcher, "_apply_client_activation", return_value=True) as apply:
            watcher._attempt_recovery_reconnect(facts)
        apply.assert_called_once()
        assert apply.call_args[0][0].drop_hotspot is False
        vis.assert_not_called()   # no AP drop -> no scan-gate

    def test_join_interval_bounds_second_radio_probe(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:01", is_usb=True)
        self._in_hotspot(watcher)
        watcher.STATE.last_reconnect_attempt = 1000.0
        facts = _facts_for(watcher, [builtin, usb], None, now=1000.0 + 30)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher, "_apply_client_activation") as apply:
            watcher._attempt_recovery_reconnect(facts)
        apply.assert_not_called()

    def test_single_radio_scan_interval_gates_scan(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        self._in_hotspot(watcher)
        watcher.STATE.last_recovery_scan = 1000.0
        facts = _facts_for(watcher, [builtin], None, now=1000.0 + 5)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher, "_saved_ssid_visible") as vis, \
             patch.object(watcher, "_apply_client_activation") as apply:
            # Within RECOVERY_SCAN_INTERVAL of the last scan: do not scan or join.
            watcher._attempt_recovery_reconnect(facts)
        vis.assert_not_called()
        apply.assert_not_called()

    def test_single_radio_ssid_absent_keeps_ap(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        self._in_hotspot(watcher)
        facts = _facts_for(watcher, [builtin], None, now=1000.0)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher, "_saved_ssid_visible", return_value=False), \
             patch.object(watcher, "_apply_client_activation") as apply:
            watcher._attempt_recovery_reconnect(facts)
        apply.assert_not_called()
        assert watcher.STATE.last_recovery_scan == 1000.0

    def test_single_radio_ssid_present_drops_ap_and_joins(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        self._in_hotspot(watcher)
        facts = _facts_for(watcher, [builtin], None, now=1000.0)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher, "_saved_ssid_visible", return_value=True), \
             patch.object(watcher, "_apply_client_activation", return_value=True) as apply:
            watcher._attempt_recovery_reconnect(facts)
        apply.assert_called_once()
        action = apply.call_args[0][0]
        assert action.kind is watcher.RecoveryKind.ACTIVATE_ONBOARD
        assert action.drop_hotspot is True

    def test_saved_ssid_visible_uses_scan(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        with patch.object(watcher, "_saved_network_ssid", return_value="MyHomeWiFi"), \
             patch.object(watcher.wifi_net, "scan_adapter", return_value={"MyHomeWiFi": -50}):
            assert watcher._saved_ssid_visible(builtin) is True
        with patch.object(watcher, "_saved_network_ssid", return_value="MyHomeWiFi"), \
             patch.object(watcher.wifi_net, "scan_adapter", return_value={"Other": -50}):
            assert watcher._saved_ssid_visible(builtin) is False


class TestExplicitModeClassifier:
    """WP2/WP8 — the loop applies the pure next_mode classifier.

    The pure next_mode state->Mode cases moved to tests/test_wifi_policy.py
    (Phase B-WP4); these remaining tests verify the loop *applies* the
    classifier and publishes it as device.mode.
    """

    def test_loop_applies_authoritative_state_mode(self, watcher):
        # The loop applies the classifier by setting STATE.mode each full pass.
        _run_monitor_once(watcher, now=1000.0, wifi_cfg=True,
                          wifi_connected=True, client_ok=True)
        assert watcher.STATE.mode is watcher.Mode.ONLINE

    def test_snapshot_publishes_authoritative_state_mode(self, watcher):
        # device.mode publishes the authoritative STATE.mode the loop applies.
        usb = _adapter(watcher, "wlan0", "AA:BB:CC:DD:EE:09", is_usb=True)
        watcher.STATE.setup_mode = True
        watcher.STATE.mode = watcher.Mode.HOTSPOT
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value={}), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher.wifi_net, "read_operstate", return_value="up"), \
             patch.object(watcher.wifi_net, "default_gateway_ipv4", return_value=""), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher, "resolve_hotspot_adapter", return_value=usb):
            snap = watcher.build_network_status_snapshot([usb], wired_connected=False, wired_ok=False)
        assert snap["device"]["mode"] == "hotspot"


class TestPerTickFactsSnapshot:
    """WP1 — one immutable Facts snapshot gathered per pass (Section 2.5)."""

    def _run_online_idle_pass(self, watcher, *, capture: dict):
        """Run one online/idle monitor pass with all fact helpers wrapped to
        count calls and record the adapter object each decision observes."""
        builtin = _adapter(watcher, "wlan0", "AA:BB:CC:DD:EE:01", is_builtin=True)
        adapters = [builtin]

        discover = MagicMock(return_value=adapters)
        addrs = MagicMock(return_value={})
        wired_conn = MagicMock(return_value=False)
        wired_ok = MagicMock(return_value=False)
        resolve_active = MagicMock(return_value=builtin)

        def _record_publish(a, *args, **kw):
            capture["publish_adapters"] = a

        def _record_dead(a, *args, **kw):
            capture["dead_adapters"] = a
            return False

        with ExitStack() as stack:
            stack.enter_context(patch("time.monotonic", return_value=100.0))
            stack.enter_context(patch.object(watcher, "check_and_repair_avahi_hostname"))
            stack.enter_context(patch.object(watcher, "maybe_reannounce_mdns"))
            stack.enter_context(patch.object(watcher, "revert_expired_log_level"))
            stack.enter_context(patch.object(watcher, "is_wifi_configured", return_value=True))
            stack.enter_context(patch.object(watcher, "is_wired_connected", wired_conn))
            stack.enter_context(patch.object(watcher, "any_wired_path_healthy", wired_ok))
            stack.enter_context(patch.object(watcher.wifi_net, "discover_adapters", discover))
            stack.enter_context(patch.object(watcher.wifi_net, "list_interface_addresses", addrs))
            stack.enter_context(patch.object(watcher, "update_known_adapters"))
            stack.enter_context(patch.object(watcher, "resolve_active_client", resolve_active))
            stack.enter_context(patch.object(watcher, "handle_usb_failure_fallback", return_value=False))
            stack.enter_context(patch.object(watcher.wifi_net, "is_wifi_connected", return_value=True))
            stack.enter_context(patch.object(watcher, "is_wifi_client_healthy", return_value=True))
            stack.enter_context(patch.object(watcher, "handle_runtime_usb_adoption", return_value=False))
            stack.enter_context(patch.object(watcher, "escalate_dead_adapter_recovery", _record_dead))
            stack.enter_context(patch.object(watcher, "publish_network_status", _record_publish))
            stack.enter_context(patch.object(watcher, "log_on_change"))
            watcher.network_monitor_loop(run_once=True)

        return {
            "adapters": adapters,
            "discover": discover,
            "addresses": addrs,
            "wired_connected": wired_conn,
            "wired_ok": wired_ok,
            "resolve_active": resolve_active,
        }

    def test_single_discover_adapters_per_pass(self, watcher):
        m = self._run_online_idle_pass(watcher, capture={})
        assert m["discover"].call_count == 1

    def test_subprocess_fact_ceiling_per_pass(self, watcher):
        # Pi Zero budget guard: each costly fact helper is gathered exactly once
        # per pass (the per-pass subprocess ceiling; a later WP may not raise it).
        m = self._run_online_idle_pass(watcher, capture={})
        assert m["discover"].call_count == 1
        assert m["addresses"].call_count == 1
        assert m["wired_connected"].call_count == 1
        assert m["wired_ok"].call_count == 1
        assert m["resolve_active"].call_count == 1

    def test_two_decisions_observe_identical_adapter_facts(self, watcher):
        capture: dict = {}
        m = self._run_online_idle_pass(watcher, capture=capture)
        # Both the dead-PHY overlay and the status publisher must see the exact
        # adapter list produced by the single discover_adapters call this pass.
        assert capture["dead_adapters"] is m["adapters"]
        assert capture["publish_adapters"] is m["adapters"]

    def test_gather_facts_returns_consistent_snapshot(self, watcher):
        builtin = _adapter(watcher, "wlan0", "AA:BB:CC:DD:EE:01", is_builtin=True)
        adapters = [builtin]
        with patch("time.monotonic", return_value=42.0), \
             patch.object(watcher, "is_wifi_configured", return_value=True), \
             patch.object(watcher, "is_wired_connected", return_value=False), \
             patch.object(watcher, "any_wired_path_healthy", return_value=False), \
             patch.object(watcher.wifi_net, "discover_adapters", return_value=adapters), \
             patch.object(watcher.wifi_net, "list_interface_addresses", return_value={"wlan0": []}), \
             patch.object(watcher, "resolve_active_client", return_value=builtin):
            facts = watcher.gather_facts()
        assert facts.wifi_configured is True
        assert facts.adapters is adapters
        assert facts.active_client is builtin
        assert facts.addresses == {"wlan0": []}
        assert facts.taken_at == 42.0

    def test_playing_status_memo_queries_once(self, watcher):
        calls = {"n": 0}

        def _q():
            calls["n"] += 1
            return False

        with patch.object(watcher, "query_playing_status", _q):
            memo = watcher._make_playing_status_memo()
            assert memo() is False
            assert memo() is False
            assert memo() is False
        assert calls["n"] == 1

class TestAvahiHandoverReannounce:
    def _ok_result(self):
        return MagicMock(returncode=0, stdout="", stderr="")

    def test_verify_after_handover_checks_hostname_then_marks_pending(self, watcher):
        with patch.object(watcher, "check_and_repair_avahi_hostname") as check, \
             patch.object(watcher, "mark_mdns_reannounce_pending") as mark:
            watcher.verify_avahi_after_handover()
        check.assert_called_once()
        mark.assert_called_once()

    def test_mark_pending_arms_debounce(self, watcher):
        with patch("time.monotonic", return_value=100.0):
            watcher.mark_mdns_reannounce_pending("test")
        assert watcher.STATE.mdns_reannounce_pending is True
        assert watcher.STATE.mdns_address_changed_at == 100.0

    def test_first_observation_only_baselines(self, watcher):
        both = frozenset({("eth0", "192.168.1.5"), ("wlan1", "192.168.1.9")})
        with patch.object(watcher, "_current_mdns_address_set", return_value=both), \
             patch.object(watcher, "restart_avahi_daemon") as restart:
            watcher.maybe_reannounce_mdns(now=0.0)
        restart.assert_not_called()
        assert watcher.STATE.mdns_address_set == both

    def test_address_change_debounces_then_restarts(self, watcher):
        both = frozenset({("eth0", "192.168.1.5"), ("wlan1", "192.168.1.9")})
        eth_only = frozenset({("eth0", "192.168.1.5")})
        watcher.STATE.mdns_address_set = both

        # Dongle removed: set changes -> arm debounce, no restart yet.
        with patch.object(watcher, "_current_mdns_address_set", return_value=eth_only), \
             patch.object(watcher, "restart_avahi_daemon") as restart:
            watcher.maybe_reannounce_mdns(now=10.0)
        restart.assert_not_called()
        assert watcher.STATE.mdns_address_changed_at == 10.0

        # Stable but still inside the debounce window: no restart.
        with patch.object(watcher, "_current_mdns_address_set", return_value=eth_only), \
             patch.object(watcher, "restart_avahi_daemon") as restart:
            watcher.maybe_reannounce_mdns(now=13.0)
        restart.assert_not_called()

        # Stable past the debounce window: re-announce fires once.
        with patch.object(watcher, "_current_mdns_address_set", return_value=eth_only), \
             patch.object(watcher, "restart_avahi_daemon") as restart:
            watcher.maybe_reannounce_mdns(now=20.0)
        restart.assert_called_once_with("network-path re-announce")
        assert watcher.STATE.last_avahi_handover_restart == 20.0
        assert watcher.STATE.mdns_address_changed_at is None

    def test_reannounce_is_rate_limited_for_60_seconds(self, watcher):
        eth_only = frozenset({("eth0", "192.168.1.5")})
        watcher.STATE.mdns_address_set = eth_only
        watcher.STATE.mdns_address_changed_at = 100.0
        watcher.STATE.last_avahi_handover_restart = 100.0

        # Debounce satisfied but within the 60s rate-limit window: suppressed,
        # and the trigger stays armed for a later pass.
        with patch.object(watcher, "_current_mdns_address_set", return_value=eth_only), \
             patch.object(watcher, "restart_avahi_daemon") as restart:
            watcher.maybe_reannounce_mdns(now=159.0)
        restart.assert_not_called()
        assert watcher.STATE.mdns_address_changed_at == 100.0

        # Past the rate-limit window: fires.
        with patch.object(watcher, "_current_mdns_address_set", return_value=eth_only), \
             patch.object(watcher, "restart_avahi_daemon") as restart:
            watcher.maybe_reannounce_mdns(now=160.0)
        restart.assert_called_once_with("network-path re-announce")
        assert watcher.STATE.last_avahi_handover_restart == 160.0

    def test_pending_nudge_fires_when_address_set_unchanged(self, watcher):
        eth_only = frozenset({("eth0", "192.168.1.5")})
        watcher.STATE.mdns_address_set = eth_only
        # Orchestrated handover where our observed set looks the same.
        with patch("time.monotonic", return_value=200.0):
            watcher.mark_mdns_reannounce_pending("network handover")
        with patch.object(watcher, "_current_mdns_address_set", return_value=eth_only), \
             patch.object(watcher, "restart_avahi_daemon") as restart:
            watcher.maybe_reannounce_mdns(now=210.0)
        restart.assert_called_once_with("network-path re-announce")
        assert watcher.STATE.mdns_reannounce_pending is False

    def test_stable_address_set_does_not_restart(self, watcher):
        eth_only = frozenset({("eth0", "192.168.1.5")})
        watcher.STATE.mdns_address_set = eth_only
        with patch.object(watcher, "_current_mdns_address_set", return_value=eth_only), \
             patch.object(watcher, "restart_avahi_daemon") as restart:
            watcher.maybe_reannounce_mdns(now=500.0)
        restart.assert_not_called()

    def test_hostname_mismatch_repair_still_uses_conflict_restart_budget(self, watcher):
        watcher.STATE.avahi_mismatch_start = 0.0

        with patch("time.monotonic", return_value=watcher.AVAHI_MISMATCH_GRACE + 1.0), \
             patch.object(watcher, "_DBUS_SEND", "/usr/bin/dbus-send"), \
             patch.object(watcher, "get_avahi_registered_hostname", return_value="autostream-2"), \
             patch.object(watcher, "get_system_hostname", return_value="autostream"), \
             patch.object(watcher, "run_cmd", return_value=self._ok_result()) as run:
            watcher.check_and_repair_avahi_hostname()

        run.assert_called_once_with(["systemctl", "restart", "avahi-daemon.service"])
        assert watcher.STATE.avahi_restart_count == 1
        assert watcher.STATE.last_avahi_restart == watcher.AVAHI_MISMATCH_GRACE + 1.0
        assert watcher.STATE.last_avahi_handover_restart is None


class TestNetworkMonitorCatchAll:
    def test_broken_ethernet_does_not_suppress_catchall_reboot(self, watcher):
        now = watcher.NO_ACTIVE_PATH_REBOOT_AFTER + 100.0
        watcher.STATE.boot_time = 0.0
        watcher.STATE.last_active_path_seen = 0.0
        with patch.object(watcher, "reboot_system", return_value=True) as reboot:
            _run_monitor_once(
                watcher,
                now=now,
                wifi_cfg=False,
                wired_connected=True,
                wired_ok=False,
            )
        reboot.assert_called_once_with("NetworkDown")

    def test_reboot_throttle_suppresses_repeated_catchall_request(self, watcher):
        now = watcher.NO_ACTIVE_PATH_REBOOT_AFTER + 100.0
        watcher.STATE.boot_time = 0.0
        watcher.STATE.last_active_path_seen = 0.0
        watcher.STATE.conn_reboot_retry_after = now + 60.0
        with patch.object(watcher, "reboot_system", return_value=True) as reboot:
            _run_monitor_once(watcher, now=now, wifi_cfg=False)
        reboot.assert_not_called()

    def test_healthy_ethernet_suppresses_automatic_ap(self, watcher):
        now = watcher.NO_ACTIVE_PATH_REBOOT_AFTER + 100.0
        watcher.STATE.boot_time = 0.0
        watcher.STATE.last_active_path_seen = 0.0
        watcher.STATE.setup_mode = True
        watcher.STATE.ap_enter_time = now - 10.0
        with patch.object(watcher, "leave_setup_mode") as leave, \
             patch.object(watcher, "reboot_system", return_value=True) as reboot:
            _run_monitor_once(
                watcher,
                now=now,
                wifi_cfg=False,
                wired_connected=True,
                wired_ok=True,
            )
        leave.assert_called_once()
        reboot.assert_not_called()

    def test_manual_ap_override_not_closed_by_healthy_ethernet(self, watcher):
        now = watcher.NO_ACTIVE_PATH_REBOOT_AFTER + 100.0
        watcher.STATE.boot_time = 0.0
        watcher.STATE.last_active_path_seen = 0.0
        watcher.STATE.setup_mode = True
        watcher.STATE.hotspot = watcher.HotspotSession(
            purpose=watcher.HotspotPurpose.MANUAL, entered_at=now - 10.0)
        with patch.object(watcher, "leave_setup_mode") as leave, \
             patch.object(watcher, "reboot_system", return_value=True) as reboot:
            _run_monitor_once(
                watcher,
                now=now,
                wifi_cfg=False,
                wired_connected=True,
                wired_ok=True,
            )
        leave.assert_not_called()
        reboot.assert_not_called()

    def test_setup_mode_suspends_catchall(self, watcher):
        now = watcher.NO_ACTIVE_PATH_REBOOT_AFTER + 100.0
        watcher.STATE.boot_time = 0.0
        watcher.STATE.last_active_path_seen = 0.0
        watcher.STATE.setup_mode = True
        watcher.STATE.ap_enter_time = now - 10.0
        with patch.object(watcher, "reboot_system", return_value=True) as reboot:
            _run_monitor_once(watcher, now=now, wifi_cfg=False)
        reboot.assert_not_called()

    def test_active_wifi_rebases_catchall_timer_and_clears_retry(self, watcher):
        now = watcher.NO_ACTIVE_PATH_REBOOT_AFTER + 100.0
        watcher.STATE.boot_time = 0.0
        watcher.STATE.last_active_path_seen = 0.0
        watcher.STATE.conn_reboot_retry_after = now + 60.0
        with patch.object(watcher, "reboot_system", return_value=True) as reboot:
            _run_monitor_once(
                watcher,
                now=now,
                wifi_cfg=True,
                wifi_connected=True,
                client_ok=True,
            )
        reboot.assert_not_called()
        assert watcher.STATE.last_active_path_seen == now
        assert watcher.STATE.conn_reboot_retry_after == 0.0


class TestEthernetWinsWifiDisconnectPolicy:
    """WP4 — usable wired Ethernet wins regardless of subnet; one playback gate."""

    def _run_with_active_wifi(self, watcher, *, playing=False, setup=False):
        now = 1000.0
        wifi = _adapter(watcher, "wlan1", "aa:bb:cc:00:00:02", is_usb=True)
        watcher.STATE.setup_mode = setup
        with patch.object(watcher, "query_playing_status", return_value=playing), \
             patch.object(watcher, "run_cmd", return_value=MagicMock(returncode=0)) as run:
            _run_monitor_once(
                watcher,
                now=now,
                wifi_cfg=True,
                wired_connected=True,
                wired_ok=True,
                wifi_connected=True,
                client_ok=True,
                adapters=[wifi],
                active_client=wifi,
            )
        return run

    def test_wired_up_idle_disconnects_wifi_once(self, watcher):
        # Regardless of subnet: usable Ethernet present + idle → drop Wi-Fi once.
        run = self._run_with_active_wifi(watcher, playing=False)
        run.assert_called_once_with(["nmcli", "device", "disconnect", "wlan1"])
        assert watcher.STATE.active_client_ifname == ""
        assert watcher.STATE.active_client_mac == ""

    def test_playback_active_retains_wifi(self, watcher):
        run = self._run_with_active_wifi(watcher, playing=True)
        run.assert_not_called()
        assert watcher.STATE.active_client_ifname == "wlan1"

    def test_playback_uncertain_retains_wifi(self, watcher):
        run = self._run_with_active_wifi(watcher, playing=None)
        run.assert_not_called()
        assert watcher.STATE.active_client_ifname == "wlan1"

    def test_apply_in_progress_skips_disconnect(self, watcher):
        watcher.STATE.apply_in_progress = True
        run = self._run_with_active_wifi(watcher, playing=False)
        run.assert_not_called()
        assert watcher.STATE.active_client_ifname == "wlan1"

    def test_setup_mode_skips_disconnect(self, watcher):
        with patch.object(watcher, "leave_setup_mode"):
            run = self._run_with_active_wifi(watcher, playing=False, setup=True)
        run.assert_not_called()
        assert watcher.STATE.active_client_ifname == "wlan1"

    def test_wired_drop_attempts_prompt_reconnect_on_entry(self, watcher):
        # Entering OFFLINE_RECONNECTING (e.g. Ethernet drops after a wired-wins
        # disconnect) attempts one prompt reconnect immediately — no 5-min wait,
        # no policy flag.
        watcher.STATE.conn_down_start = None
        connect = _run_monitor_once(
            watcher,
            now=1000.0,
            wifi_cfg=True,
            wired_connected=False,
            wired_ok=False,
            client_ok=False,
        )
        connect.assert_called_once()
        assert watcher.STATE.conn_down_start == 1000.0
        assert watcher.STATE.last_reconnect_attempt == 1000.0

    def test_dead_phy_skipped_when_wired_wins_and_no_wifi_client(self, watcher):
        # After a wired-wins disconnect the idle radio is down by design; do not
        # spend reset budget on it while Ethernet carries traffic.
        dead_recovery = MagicMock(return_value=True)
        _run_monitor_once(
            watcher,
            now=1000.0,
            wifi_cfg=True,
            wired_connected=True,
            wired_ok=True,
            active_client=None,
            dead_recovery=dead_recovery,
        )
        dead_recovery.assert_not_called()


# ---------------------------------------------------------------------------
# WP5 (dead-PHY) — end-to-end scripted state-machine sequences
# ---------------------------------------------------------------------------

class _Clock:
    """Monotonic clock stub driven explicitly by the test."""
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


class TestDeadPhyEndToEnd:
    MAC = "dc:62:79:91:4d:d6"

    def _usb(self, watcher):
        return _adapter(watcher, "wlan0", self.MAC, is_usb=True)

    def _mark_dead(self, watcher, first_failure=1.0):
        watcher.STATE.dead_adapter_ifname = "wlan0"
        watcher.STATE.dead_adapter_since = first_failure
        watcher.STATE.dead_adapter_first_failure = first_failure
        watcher.STATE.dead_adapter_checks = watcher.DEAD_ADAPTER_DEBOUNCE
        watcher.STATE.dead_adapter_stable_id = self.MAC

    def test_sequence_wedge_debounce_reset_then_quarantine(self, watcher):
        """healthy->wedged->debounce->A->B->budget exhausted->quarantine (path up)."""
        usb = self._usb(watcher)
        clock = _Clock(1000.0)
        order = []
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=None), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind",
                          side_effect=lambda i: order.append("A") or True), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_reenumerate",
                          side_effect=lambda i: order.append("B") or True), \
             patch.object(watcher, "wait_for_interface_reappears", return_value="wlan0"), \
             patch.object(watcher, "_activate_committed_on", return_value=False), \
             patch.object(watcher, "verify_avahi_after_handover"), \
             patch.object(watcher, "reboot_system") as reboot, \
             patch("time.monotonic", clock), patch("time.time", return_value=1_000_000.0):
            # Debounce: first wedged pass does not reset.
            assert watcher.escalate_dead_adapter_recovery([usb], True) is False
            # Second pass declares dead and runs Method A.
            assert watcher.escalate_dead_adapter_recovery([usb], True) is True
            clock.advance(watcher.RESET_ATTEMPT_INTERVAL + 1)
            # Method B.
            assert watcher.escalate_dead_adapter_recovery([usb], True) is True
            clock.advance(watcher.RESET_ATTEMPT_INTERVAL + 1)
            # Budget exhausted + ethernet path -> quarantine (does not own pass).
            assert watcher.escalate_dead_adapter_recovery([usb], True) is False
        assert order == ["A", "B"]
        assert _ledger(watcher, self.MAC)["quarantined_until"] is not None
        reboot.assert_not_called()

    def test_sequence_ethernet_up_resets_recover_no_reboot(self, watcher):
        """Ethernet up throughout: Method A recovers Wi-Fi; reboot never fires."""
        usb = self._usb(watcher)
        clock = _Clock(1000.0)
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=None), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind", return_value=True) as ra, \
             patch.object(watcher.wifi_net, "discover_adapters", return_value=[usb]), \
             patch.object(watcher, "wait_for_interface_reappears", return_value="wlan0"), \
             patch.object(watcher, "_activate_committed_on", return_value=True), \
             patch.object(watcher, "_set_active_client"), \
             patch.object(watcher, "verify_avahi_after_handover"), \
             patch.object(watcher, "reboot_system") as reboot, \
             patch("time.monotonic", clock), patch("time.time", return_value=1_000_000.0):
            watcher.escalate_dead_adapter_recovery([usb], True)   # debounce
            watcher.escalate_dead_adapter_recovery([usb], True)   # Method A -> recover
        ra.assert_called_once()
        assert watcher.STATE.dead_adapter_ifname == ""
        reboot.assert_not_called()

    def test_sequence_usb_only_emergency_backoff(self, watcher):
        """No alternate path: budget exceeded but USB-only keeps slow attempts."""
        usb = self._usb(watcher)
        clock = _Clock(1000.0)
        self._mark_dead(watcher, first_failure=clock.t)
        _spend_window_budget(watcher, self.MAC, now=clock.t)
        watcher.STATE.last_reset_attempt = clock.t
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=None), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind", return_value=True) as ra, \
             patch.object(watcher, "wait_for_interface_reappears", return_value="wlan0"), \
             patch.object(watcher, "_activate_committed_on", return_value=False), \
             patch.object(watcher, "verify_avahi_after_handover"), \
             patch.object(watcher, "reboot_system") as reboot, \
             patch("time.monotonic", clock), patch("time.time", return_value=1_000_000.0):
            # Before the emergency backoff elapses: no reset.
            clock.advance(watcher.RESET_ATTEMPT_INTERVAL + 1)
            watcher.escalate_dead_adapter_recovery([usb], False)
            assert ra.call_count == 0
            # After the emergency backoff: a slow emergency reset is attempted.
            clock.advance(watcher.USB_EMERGENCY_BACKOFF + 1)
            watcher.escalate_dead_adapter_recovery([usb], False)
            assert ra.call_count == 1
            reboot.assert_not_called()  # dead_for still < 30 min in this window

    def test_recovered_fresh_episode_is_due_and_starts_with_method_a(self, watcher):
        usb = self._usb(watcher)
        clock = _Clock(1000.0)
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=None), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind", return_value=True) as ra, \
             patch.object(watcher.wifi_net, "reset_usb_adapter_reenumerate", return_value=True) as rb, \
             patch.object(watcher, "wait_for_interface_reappears", return_value="wlan0"), \
             patch.object(watcher, "_activate_committed_on", return_value=True), \
             patch.object(watcher, "verify_avahi_after_handover"), \
             patch("time.monotonic", clock):
            watcher.escalate_dead_adapter_recovery([usb], True)
            watcher.escalate_dead_adapter_recovery([usb], True)
        assert watcher.STATE.last_reset_attempt is None
        assert watcher.STATE.last_reset_method == ""

        clock.advance(1.0)
        self._mark_dead(watcher, first_failure=clock.t)
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=None), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind", return_value=True) as ra2, \
             patch.object(watcher.wifi_net, "reset_usb_adapter_reenumerate", return_value=True) as rb2, \
             patch.object(watcher, "wait_for_interface_reappears", return_value="wlan0"), \
             patch.object(watcher, "_activate_committed_on", return_value=False), \
             patch.object(watcher, "verify_avahi_after_handover"), \
             patch("time.monotonic", clock):
            assert watcher.escalate_dead_adapter_recovery([usb], True) is True
        assert ra.call_count == 1
        ra2.assert_called_once_with("wlan0")
        rb.assert_not_called()
        rb2.assert_not_called()
        assert watcher.STATE.last_reset_method == "A"

    def test_sequence_reboot_then_inprocess_and_guard_suppression(self, watcher):
        """Offline + dead>=30min + resets failing: one reboot, then suppressed."""
        usb = self._usb(watcher)
        clock = _Clock(1000.0)
        self._mark_dead(watcher, first_failure=1.0)
        clock.t = watcher.DEAD_ADAPTER_REBOOT_AFTER + 1000.0
        guard = tmp_guard()
        with patch.object(watcher, "DEAD_ADAPTER_REBOOT_STAMP", str(guard)), \
             _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=[],  # non-resettable -> reboot rung
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=None), \
             patch("time.monotonic", clock), patch("time.time", return_value=1_000_000.0), \
             patch.object(watcher, "reboot_system", return_value=True) as reboot:
            # First: reboot accepted.
            assert watcher.escalate_dead_adapter_recovery([usb], False) is True
            assert watcher.STATE.conn_reboot_retry_after == float("inf")
            # Second: in-process rate limit (retry_after == inf) suppresses.
            assert watcher.escalate_dead_adapter_recovery([usb], False) is False
            assert reboot.call_count == 1
            # Simulate a fresh process whose in-process limit is reset, but the
            # persistent guard is now full -> still suppressed.
            watcher.STATE.conn_reboot_retry_after = 0.0
            for _ in range(watcher.DEAD_ADAPTER_MAX_REBOOTS_PER_WINDOW):
                watcher._record_dead_phy_reboot_request(1_000_000.0, None)
            assert watcher.escalate_dead_adapter_recovery([usb], False) is False
            assert reboot.call_count == 1


# ---------------------------------------------------------------------------
# WP6 (dead-PHY) — status snapshot builder + /network_status route
# ---------------------------------------------------------------------------

class TestBuildNetworkStatusSnapshot:
    MAC = "dc:62:79:91:4d:d6"

    def _snapshot_for_usb(self, watcher, usb, *, now=1000.0, healthy=True):
        addrs = {"wlan0": [{"family": "ipv4", "address": "192.168.1.42",
                            "prefixlen": 24, "scope": "global"}]}
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value=addrs), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher.wifi_net, "read_operstate", return_value="up"), \
             patch.object(watcher.wifi_net, "default_gateway_ipv4", return_value="192.168.1.1"), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=healthy), \
             patch.object(watcher, "is_gateway_reachable", return_value=True), \
             patch.object(watcher, "resolve_hotspot_adapter", return_value=None), \
             patch("time.monotonic", return_value=now):
            return watcher.build_network_status_snapshot([usb], wired_connected=False, wired_ok=False)

    def test_healthy_usb_client_online(self, watcher):
        usb = _adapter(watcher, "wlan0", self.MAC, is_usb=True)
        watcher.STATE.active_client_ifname = "wlan0"
        watcher.STATE.active_client_mac = self.MAC
        addrs = {"wlan0": [{"family": "ipv4", "address": "192.168.1.42",
                            "prefixlen": 24, "scope": "global"}]}
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value=addrs), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher.wifi_net, "read_operstate", return_value="up"), \
             patch.object(watcher.wifi_net, "default_gateway_ipv4", return_value="192.168.1.1"), \
             patch.object(watcher.wifi_net, "get_active_wifi_ssid", return_value="MyHomeWiFi"), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher, "is_gateway_reachable", return_value=True), \
             patch.object(watcher, "resolve_hotspot_adapter", return_value=usb):
            snap = watcher.build_network_status_snapshot([usb], wired_connected=False, wired_ok=False)
        assert snap["schema_version"] == 1
        assert snap["device"]["state"] == "online"
        assert snap["device"]["primary_ifname"] == "wlan0"
        assert snap["device"]["primary_ssid"] == "MyHomeWiFi"
        assert snap["device"]["primary_ipv4"] == "192.168.1.42"
        assert snap["device"]["primary_ipv4_info"] == {
            "address": "192.168.1.42",
            "prefixlen": 24,
            "netmask": "255.255.255.0",
            "gateway": "192.168.1.1",
        }
        assert snap["connectivity"]["client_ok"] is True
        assert snap["connectivity"]["active_path_ok"] is True
        assert snap["connectivity"]["wired_carrier"] is False
        assert snap["connectivity"]["wired_ok"] is False
        rec = snap["adapters"][0]
        assert rec["ifname"] == "wlan0"
        assert rec["kind"] == "usb_wifi"
        assert rec["health"]["state"] == "healthy"
        assert rec["role"] == "client"

    def test_dead_usb_adapter_reported(self, watcher):
        usb = _adapter(watcher, "wlan0", self.MAC, is_usb=True)
        watcher.STATE.dead_adapter_ifname = "wlan0"
        watcher.STATE.dead_adapter_since = 5.0
        watcher.STATE.dead_adapter_checks = 4
        watcher.STATE.last_reset_method = "B"
        watcher.STATE.adapter_reset_ledgers[self.MAC] = {
            "recent_resets": [10.0],
            "total_resets": 1,
            "quarantined_until": None,
        }
        # Pin the monotonic clock so the seeded reset at t=10.0 stays inside the
        # 24h reset window (the snapshot prunes recent_resets against now); without
        # this the count is environment-dependent (host uptime > 24h zeroes it).
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value={}), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=True), \
             patch.object(watcher.wifi_net, "read_operstate", return_value="down"), \
             patch.object(watcher.wifi_net, "default_gateway_ipv4", return_value=""), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher, "resolve_hotspot_adapter", return_value=None), \
             patch("time.monotonic", return_value=1000.0):
            snap = watcher.build_network_status_snapshot([usb], wired_connected=False, wired_ok=False)
        rec = snap["adapters"][0]
        assert rec["health"]["state"] == "dead_phy"
        assert rec["health"]["checks"] == 4
        assert rec["policy"]["last_action"] == "usb_reset_method_b"
        assert rec["policy"]["resets_24h"] == 1
        assert rec["policy"]["warning"] == "resetting"
        assert snap["device"]["state"] == "recovering"

    def test_present_adapter_with_recent_resets_reports_policy_warning(self, watcher):
        usb = _adapter(watcher, "wlan0", self.MAC, is_usb=True)
        watcher.STATE.active_client_ifname = "wlan0"
        watcher.STATE.active_client_mac = self.MAC
        watcher.STATE.adapter_reset_ledgers[self.MAC] = {
            "recent_resets": [900.0, 950.0],
            "total_resets": 2,
            "quarantined_until": None,
        }
        snap = self._snapshot_for_usb(watcher, usb, now=1000.0)
        rec = snap["adapters"][0]
        assert rec["policy"]["resets_24h"] == 2
        assert rec["policy"]["warning"] == "reset_budget_exhausted"
        assert "device_disruption" not in snap
        assert "recently_seen_adapters" not in snap

    def test_present_adapter_without_resets_has_empty_warning(self, watcher):
        usb = _adapter(watcher, "wlan0", self.MAC, is_usb=True)
        watcher.STATE.active_client_ifname = "wlan0"
        watcher.STATE.active_client_mac = self.MAC
        snap = self._snapshot_for_usb(watcher, usb, now=1000.0)
        rec = snap["adapters"][0]
        assert rec["policy"]["resets_24h"] == 0
        assert rec["policy"]["warning"] == ""

    def test_quarantine_policy_uses_expiry_not_presence(self, watcher):
        usb = _adapter(watcher, "wlan0", self.MAC, is_usb=True)
        watcher.STATE.adapter_reset_ledgers[self.MAC] = {
            "recent_resets": [],
            "total_resets": watcher.USB_MAX_RESETS_TOTAL,
            "quarantined_until": 900.0,
        }
        snap = self._snapshot_for_usb(watcher, usb, now=1000.0)
        rec = snap["adapters"][0]
        assert rec["policy"]["quarantined"] is False
        assert rec["policy"]["warning"] == "reset_budget_exhausted"
        assert _ledger(watcher, self.MAC)["quarantined_until"] is None

    def test_reconnected_quarantined_stable_id_stays_quarantined_until_deadline(self, watcher):
        usb = _adapter(watcher, "wlan0", self.MAC, is_usb=True)
        watcher.STATE.adapter_reset_ledgers[self.MAC] = {
            "recent_resets": [900.0, 950.0],
            "total_resets": 2,
            "quarantined_until": 1100.0,
        }
        snap = self._snapshot_for_usb(watcher, usb, now=1000.0)
        rec = snap["adapters"][0]
        assert rec["health"]["state"] == "quarantined"
        assert rec["policy"]["quarantined"] is True
        assert rec["policy"]["warning"] == "quarantined"
        assert rec["policy"]["next_action_after"] == 1100.0

    def test_reconnected_stable_id_clears_quarantine_after_deadline(self, watcher):
        usb = _adapter(watcher, "wlan0", self.MAC, is_usb=True)
        watcher.STATE.adapter_reset_ledgers[self.MAC] = {
            "recent_resets": [900.0],
            "total_resets": 1,
            "quarantined_until": 999.0,
        }
        snap = self._snapshot_for_usb(watcher, usb, now=1000.0)
        rec = snap["adapters"][0]
        assert rec["policy"]["quarantined"] is False
        assert rec["policy"]["warning"] == "recent_resets"
        assert _ledger(watcher, self.MAC)["quarantined_until"] is None

    def test_old_reset_history_pruned_from_policy(self, watcher):
        usb = _adapter(watcher, "wlan0", self.MAC, is_usb=True)
        watcher.STATE.adapter_reset_ledgers[self.MAC] = {
            "recent_resets": [100.0],
            "total_resets": 1,
            "quarantined_until": None,
        }
        snap = self._snapshot_for_usb(watcher, usb, now=100.0 + watcher.USB_RESET_WINDOW + 1.0)
        rec = snap["adapters"][0]
        assert rec["policy"]["resets_24h"] == 0
        assert rec["policy"]["warning"] == ""

    def test_ethernet_degraded_when_wifi_dead(self, watcher):
        usb = _adapter(watcher, "wlan0", self.MAC, is_usb=True)
        watcher.STATE.dead_adapter_ifname = "wlan0"
        addrs = {"eth0": [{"family": "ipv4", "address": "10.0.0.5",
                           "prefixlen": 24, "scope": "global"}]}
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value=addrs), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=True), \
             patch.object(watcher.wifi_net, "read_operstate", return_value="down"), \
             patch.object(watcher.wifi_net, "default_gateway_ipv4", return_value="10.0.0.1"), \
             patch.object(watcher.wifi_net, "get_active_wifi_ssid") as get_ssid, \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.build_network_status_snapshot([usb], wired_connected=True, wired_ok=True)
        assert snap["device"]["state"] == "degraded"
        assert snap["device"]["primary_kind"] == "ethernet"
        assert snap["device"]["primary_ssid"] == ""
        get_ssid.assert_not_called()
        assert snap["device"]["primary_ipv4"] == "10.0.0.5"
        assert snap["device"]["primary_ipv4_info"] == {
            "address": "10.0.0.5",
            "prefixlen": 24,
            "netmask": "255.255.255.0",
            "gateway": "10.0.0.1",
        }
        assert snap["connectivity"]["wired_carrier"] is True
        assert snap["connectivity"]["wired_ok"] is True
        assert snap["connectivity"]["active_path_ok"] is True

    def test_primary_uses_wifi_when_only_wifi_has_default_route(self, watcher):
        usb = _adapter(watcher, "wlan0", self.MAC, is_usb=True)
        watcher.STATE.active_client_ifname = "wlan0"
        watcher.STATE.active_client_mac = self.MAC
        addrs = {
            "wlan0": [{"family": "ipv4", "address": "192.168.1.42",
                       "prefixlen": 24, "scope": "global"}],
            "eth0": [{"family": "ipv4", "address": "10.0.0.5",
                      "prefixlen": 24, "scope": "global"}],
        }
        gateways = {"wlan0": "192.168.1.1", "eth0": ""}
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value=addrs), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher.wifi_net, "read_operstate", return_value="up"), \
             patch.object(watcher.wifi_net, "default_gateway_ipv4",
                          side_effect=lambda ifname: gateways.get(ifname, "")), \
             patch.object(watcher.wifi_net, "get_active_wifi_ssid", return_value="MyHomeWiFi"), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher, "is_gateway_reachable", return_value=True), \
             patch.object(watcher, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.build_network_status_snapshot([usb], wired_connected=True, wired_ok=True)
        assert snap["device"]["primary_kind"] == "usb_wifi"
        assert snap["device"]["primary_ifname"] == "wlan0"
        assert snap["device"]["primary_ssid"] == "MyHomeWiFi"

    def test_primary_uses_ethernet_when_only_ethernet_has_default_route(self, watcher):
        usb = _adapter(watcher, "wlan0", self.MAC, is_usb=True)
        watcher.STATE.active_client_ifname = "wlan0"
        watcher.STATE.active_client_mac = self.MAC
        addrs = {
            "wlan0": [{"family": "ipv4", "address": "192.168.1.42",
                       "prefixlen": 24, "scope": "global"}],
            "eth0": [{"family": "ipv4", "address": "10.0.0.5",
                      "prefixlen": 24, "scope": "global"}],
        }
        gateways = {"wlan0": "", "eth0": "10.0.0.1"}
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value=addrs), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher.wifi_net, "read_operstate", return_value="up"), \
             patch.object(watcher.wifi_net, "default_gateway_ipv4",
                          side_effect=lambda ifname: gateways.get(ifname, "")), \
             patch.object(watcher.wifi_net, "get_active_wifi_ssid") as get_ssid, \
             patch.object(watcher, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.build_network_status_snapshot([usb], wired_connected=True, wired_ok=True)
        assert snap["device"]["primary_kind"] == "ethernet"
        assert snap["device"]["primary_ifname"] == "eth0"
        assert snap["device"]["primary_ssid"] == ""
        get_ssid.assert_not_called()

    def test_primary_prefers_ethernet_when_both_have_default_routes(self, watcher):
        usb = _adapter(watcher, "wlan0", self.MAC, is_usb=True)
        watcher.STATE.active_client_ifname = "wlan0"
        watcher.STATE.active_client_mac = self.MAC
        addrs = {
            "wlan0": [{"family": "ipv4", "address": "192.168.1.42",
                       "prefixlen": 24, "scope": "global"}],
            "eth0": [{"family": "ipv4", "address": "10.0.0.5",
                      "prefixlen": 24, "scope": "global"}],
        }
        gateways = {"wlan0": "192.168.1.1", "eth0": "10.0.0.1"}
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value=addrs), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher.wifi_net, "read_operstate", return_value="up"), \
             patch.object(watcher.wifi_net, "default_gateway_ipv4",
                          side_effect=lambda ifname: gateways.get(ifname, "")), \
             patch.object(watcher.wifi_net, "get_active_wifi_ssid") as get_ssid, \
             patch.object(watcher, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher, "is_gateway_reachable", return_value=True), \
             patch.object(watcher, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.build_network_status_snapshot([usb], wired_connected=True, wired_ok=True)
        assert snap["device"]["primary_kind"] == "ethernet"
        assert snap["device"]["primary_ifname"] == "eth0"
        get_ssid.assert_not_called()

    def test_primary_prefers_ethernet_when_neither_has_default_route(self, watcher):
        usb = _adapter(watcher, "wlan0", self.MAC, is_usb=True)
        watcher.STATE.active_client_ifname = "wlan0"
        watcher.STATE.active_client_mac = self.MAC
        addrs = {
            "wlan0": [{"family": "ipv4", "address": "192.168.1.42",
                       "prefixlen": 24, "scope": "global"}],
            "eth0": [{"family": "ipv4", "address": "10.0.0.5",
                      "prefixlen": 24, "scope": "global"}],
        }
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value=addrs), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher.wifi_net, "read_operstate", return_value="up"), \
             patch.object(watcher.wifi_net, "default_gateway_ipv4", return_value=""), \
             patch.object(watcher.wifi_net, "get_active_wifi_ssid") as get_ssid, \
             patch.object(watcher, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.build_network_status_snapshot([usb], wired_connected=True, wired_ok=True)
        assert snap["device"]["primary_kind"] == "ethernet"
        assert snap["device"]["primary_ifname"] == "eth0"
        assert snap["device"]["primary_ipv4_info"]["gateway"] == ""
        get_ssid.assert_not_called()

    def test_carrier_only_ethernet_is_not_online_or_primary(self, watcher):
        addrs = {"eth0": []}
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value=addrs), \
             patch.object(watcher, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.build_network_status_snapshot([], wired_connected=True, wired_ok=False)
        assert snap["device"]["state"] == "offline"
        assert snap["device"]["primary_kind"] == ""
        assert snap["device"]["primary_ifname"] == ""
        assert snap["device"]["primary_ipv4"] == ""
        assert snap["device"]["primary_ipv4_info"] == {
            "address": "",
            "prefixlen": None,
            "netmask": "",
            "gateway": "",
        }
        assert snap["connectivity"]["wired_carrier"] is True
        assert snap["connectivity"]["wired_ok"] is False
        assert snap["connectivity"]["active_path_ok"] is False

    def test_setup_suspends_connectivity_timer_fields(self, watcher):
        watcher.STATE.setup_mode = True
        watcher.STATE.last_active_path_seen = 10.0
        addrs = {"eth0": [{"family": "ipv4", "address": "10.0.0.5",
                           "prefixlen": 24, "scope": "global"}]}
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value=addrs), \
             patch.object(watcher, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.build_network_status_snapshot([], wired_connected=True, wired_ok=True)
        assert snap["device"]["state"] == "setup_mode"
        assert snap["connectivity"]["active_path_ok"] is False
        assert snap["connectivity"]["no_active_path_age_seconds"] is None
        assert snap["connectivity"]["no_active_path_reboot_remaining_seconds"] is None

    def test_connectivity_timer_age_and_remaining(self, watcher):
        watcher.STATE.last_active_path_seen = 1000.0
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value={}), \
             patch.object(watcher, "resolve_hotspot_adapter", return_value=None), \
             patch("time.monotonic", return_value=1030.0):
            snap = watcher.build_network_status_snapshot([], wired_connected=False, wired_ok=False)
        assert snap["connectivity"]["last_active_path_seen_monotonic"] == 1000.0
        assert snap["connectivity"]["no_active_path_age_seconds"] == 30.0
        assert snap["connectivity"]["no_active_path_reboot_after_seconds"] == watcher.NO_ACTIVE_PATH_REBOOT_AFTER
        assert snap["connectivity"]["no_active_path_reboot_remaining_seconds"] == watcher.NO_ACTIVE_PATH_REBOOT_AFTER - 30.0

    def test_logging_block_present(self, watcher):
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value={}), \
             patch.object(watcher, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.build_network_status_snapshot([], wired_connected=False, wired_ok=False)
        assert snap["logging"]["effective_level"] == "info"
        assert snap["logging"]["default_level"] == "info"
        assert snap["logging"]["temporary_level_expires_at"] is None
        assert snap["device"]["state"] == "offline"

    def test_publish_stores_latest_snapshot_in_memory(self, watcher):
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value={}), \
             patch.object(watcher, "resolve_hotspot_adapter", return_value=None):
            watcher.publish_network_status([], wired_connected=False, wired_ok=False)
        assert watcher.STATE.network_status_snapshot["ok"] is True
        assert watcher.STATE.network_status_snapshot["device"]["state"] == "offline"
        assert watcher.STATE.network_status_updated_at == watcher.STATE.network_status_snapshot["updated_at"]


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


# ---------------------------------------------------------------------------
# WP7 (dead-PHY) — runtime log-level control
# ---------------------------------------------------------------------------

class TestLogLevelValidation:
    def test_valid_info_no_ttl(self, watcher):
        assert watcher.wifi_web.validate_log_level_request(watcher,"info", None) == ("", None)

    def test_debug_requires_ttl(self, watcher):
        err, ttl = watcher.wifi_web.validate_log_level_request(watcher,"debug", None)
        assert err == "ttl_required_for_debug"

    def test_debug_with_ttl_ok(self, watcher):
        assert watcher.wifi_web.validate_log_level_request(watcher,"debug", 900) == ("", 900)

    def test_invalid_level_rejected(self, watcher):
        err, _ = watcher.wifi_web.validate_log_level_request(watcher,"trace", None)
        assert err == "invalid_level"

    def test_numeric_level_rejected(self, watcher):
        err, _ = watcher.wifi_web.validate_log_level_request(watcher,10, 900)
        assert err == "invalid_level"

    def test_ttl_clamped(self, watcher):
        assert watcher.wifi_web.validate_log_level_request(watcher,"debug", 5)[1] == watcher.LOG_LEVEL_TTL_MIN
        assert watcher.wifi_web.validate_log_level_request(watcher,"debug", 99999)[1] == watcher.LOG_LEVEL_TTL_MAX

    def test_non_numeric_ttl_rejected(self, watcher):
        err, _ = watcher.wifi_web.validate_log_level_request(watcher,"debug", "soon")
        assert err == "invalid_ttl"
        err2, _ = watcher.wifi_web.validate_log_level_request(watcher,"debug", True)
        assert err2 == "invalid_ttl"


class TestApplyAndRevertLogLevel:
    def test_apply_temporary_sets_state(self, watcher):
        with patch("time.monotonic", return_value=1000.0):
            watcher.apply_log_level("debug", 900)
        assert watcher.STATE.temporary_log_level == "debug"
        assert watcher.STATE.temporary_log_level_until == 1900.0
        import logging
        assert logging.getLogger().level == logging.DEBUG

    def test_apply_permanent_updates_default(self, watcher):
        watcher.apply_log_level("warning", None)
        assert watcher.STATE.temporary_log_level == ""
        assert watcher.STATE.default_log_level_name == "warning"

    def test_revert_after_ttl(self, watcher):
        watcher.STATE.default_log_level_name = "info"
        with patch("time.monotonic", return_value=1000.0):
            watcher.apply_log_level("debug", 900)
        # Before expiry: no revert.
        watcher.revert_expired_log_level(now=1500.0)
        assert watcher.STATE.temporary_log_level == "debug"
        # After expiry: reverts to default.
        watcher.revert_expired_log_level(now=2000.0)
        assert watcher.STATE.temporary_log_level == ""
        import logging
        assert logging.getLogger().level == logging.INFO


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


class TestProcessSetLogLevel:
    def test_process_applies_level(self, watcher):
        with patch("time.monotonic", return_value=1000.0):
            watcher.process_control_action("set_log_level",
                                           {"level": "debug", "ttl_seconds": 900})
        assert watcher.STATE.temporary_log_level == "debug"
        assert watcher.STATE.last_control_result == "ok"


# ---------------------------------------------------------------------------
# WP8 (dead-PHY) — module split: import + delegation
# ---------------------------------------------------------------------------

class TestModuleSplit:
    def test_recovery_and_status_modules_import(self, watcher):
        # The watcher fixture loads the watcher, which puts platform/ on sys.path.
        import wifi_recovery
        import wifi_status
        assert hasattr(wifi_recovery, "escalate_dead_adapter_recovery")
        assert hasattr(wifi_recovery, "TargetAdapter")
        assert hasattr(wifi_status, "build_network_status_snapshot")

    def test_watcher_reexports_target_adapter(self, watcher):
        import wifi_recovery
        assert watcher.TargetAdapter is wifi_recovery.TargetAdapter

    def test_escalate_delegates(self, watcher):
        usb = _adapter(watcher, "wlan0", "dc:62:79:91:4d:d6", is_usb=True)
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=False, healthy=True):
            # Healthy target -> ladder returns False via the delegated impl.
            assert watcher.escalate_dead_adapter_recovery([usb], False) is False

    def test_snapshot_delegates(self, watcher):
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value={}), \
             patch.object(watcher, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.build_network_status_snapshot([], wired_connected=False, wired_ok=False)
        assert snap["schema_version"] == 1
