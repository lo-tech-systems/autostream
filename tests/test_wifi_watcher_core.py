"""Hub-owned watcher behaviour: pure helpers, AP flag lifecycle, setup-mode
transitions, facts gathering, control-action processing, log-level control,
and the unified guarded-reboot path."""
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
from _wifi_fixtures import _adapter, _patch_dead_phy_facts


class TestStateset:
    def test_string_input_uppercased(self):
        mod = _get_watcher()
        assert mod.wifi_net._stateset("reachable") == {"REACHABLE"}

    def test_list_input_each_uppercased(self):
        mod = _get_watcher()
        assert mod.wifi_net._stateset(["STALE", "delay"]) == {"STALE", "DELAY"}

    def test_empty_string_returns_empty_set(self):
        mod = _get_watcher()
        assert mod.wifi_net._stateset("") == {""}

    def test_none_like_returns_empty_set(self):
        mod = _get_watcher()
        assert mod.wifi_net._stateset(42) == set()

    def test_ok_neigh_states_are_recognised(self):
        mod = _get_watcher()
        ok = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"}
        for s in ok:
            assert mod.wifi_net._stateset(s) & mod.wifi_net._OK_NEIGH_STATES


class TestIsRfc1918Ipv4:
    def test_10_range_is_rfc1918(self):
        mod = _get_watcher()
        assert mod.wifi_net._is_rfc1918_ipv4(ipaddress.IPv4Address("10.0.0.1"))

    def test_172_range_is_rfc1918(self):
        mod = _get_watcher()
        assert mod.wifi_net._is_rfc1918_ipv4(ipaddress.IPv4Address("172.16.0.1"))

    def test_192_168_range_is_rfc1918(self):
        mod = _get_watcher()
        assert mod.wifi_net._is_rfc1918_ipv4(ipaddress.IPv4Address("192.168.1.1"))

    def test_public_ip_is_not_rfc1918(self):
        mod = _get_watcher()
        assert not mod.wifi_net._is_rfc1918_ipv4(ipaddress.IPv4Address("8.8.8.8"))

    def test_loopback_is_not_rfc1918(self):
        mod = _get_watcher()
        assert not mod.wifi_net._is_rfc1918_ipv4(ipaddress.IPv4Address("127.0.0.1"))


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


class TestParseScanOutput:
    def test_deduplicates_same_ssid_keeps_strongest(self, watcher):
        out = "MyNet:50\nMyNet:75\nMyNet:30\n"
        assert watcher.wifi_net.parse_scan_output(out) == {"MyNet": 75}

    def test_empty_output_returns_empty(self, watcher):
        assert watcher.wifi_net.parse_scan_output("") == {}

    def test_blank_and_hidden_ssid_lines_skipped(self, watcher):
        out = ":50\n\nGoodNet:70\n"
        assert watcher.wifi_net.parse_scan_output(out) == {"GoodNet": 70}

    def test_non_numeric_signal_skipped(self, watcher):
        out = "GoodNet:70\nBadNet:notanumber\n"
        assert watcher.wifi_net.parse_scan_output(out) == {"GoodNet": 70}


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


class TestEnterLeaveSetupMode:
    def test_enter_sets_setup_mode_true(self, watcher, tmp_path):
        flag = tmp_path / "apmode"
        watcher.AP_MODE_FLAG_PATH = str(flag)
        with patch.object(watcher.HOTSPOT_CTX, "start_ap_mode"), \
             patch.object(watcher.HOTSPOT_CTX, "stop_ap_mode"):
            watcher.enter_setup_mode(watcher.wifi_policy.HotspotPurpose.FIRST_RUN, "test")
        assert watcher.STATE.setup_mode is True
        assert watcher.STATE.hotspot.purpose is watcher.wifi_policy.HotspotPurpose.FIRST_RUN

    def test_enter_creates_ap_flag_file(self, watcher, tmp_path):
        flag = tmp_path / "apmode"
        watcher.AP_MODE_FLAG_PATH = str(flag)
        with patch.object(watcher.HOTSPOT_CTX, "start_ap_mode"), \
             patch.object(watcher.HOTSPOT_CTX, "stop_ap_mode"):
            watcher.enter_setup_mode(watcher.wifi_policy.HotspotPurpose.FIRST_RUN, "test")
        assert flag.exists()

    def test_enter_is_idempotent(self, watcher, tmp_path):
        flag = tmp_path / "apmode"
        watcher.AP_MODE_FLAG_PATH = str(flag)
        with patch.object(watcher.HOTSPOT_CTX, "start_ap_mode") as mock_start, \
             patch.object(watcher.HOTSPOT_CTX, "stop_ap_mode"):
            watcher.enter_setup_mode(watcher.wifi_policy.HotspotPurpose.FIRST_RUN, "first")
            watcher.enter_setup_mode(watcher.wifi_policy.HotspotPurpose.MANUAL, "second")
        # start_ap_mode called only once; the original session is kept.
        assert mock_start.call_count == 1
        assert watcher.STATE.hotspot.purpose is watcher.wifi_policy.HotspotPurpose.FIRST_RUN

    def test_leave_sets_setup_mode_false(self, watcher, tmp_path):
        flag = tmp_path / "apmode"
        flag.write_text("1\n")
        watcher.AP_MODE_FLAG_PATH = str(flag)
        watcher.STATE.setup_mode = True
        with patch.object(watcher.HOTSPOT_CTX, "start_ap_mode"), \
             patch.object(watcher.HOTSPOT_CTX, "stop_ap_mode"):
            watcher.leave_setup_mode("done")
        assert watcher.STATE.setup_mode is False

    def test_leave_rebases_active_path_timer(self, watcher, tmp_path):
        flag = tmp_path / "apmode"
        flag.write_text("1\n")
        watcher.AP_MODE_FLAG_PATH = str(flag)
        watcher.STATE.setup_mode = True
        watcher.STATE.last_active_path_seen = 1.0
        with patch.object(watcher.HOTSPOT_CTX, "start_ap_mode"), \
             patch.object(watcher.HOTSPOT_CTX, "stop_ap_mode"), \
             patch("time.monotonic", return_value=123.0):
            watcher.leave_setup_mode("done")
        assert watcher.STATE.last_active_path_seen == 123.0

    def test_leave_removes_ap_flag_file(self, watcher, tmp_path):
        flag = tmp_path / "apmode"
        flag.write_text("1\n")
        watcher.AP_MODE_FLAG_PATH = str(flag)
        watcher.STATE.setup_mode = True
        with patch.object(watcher.HOTSPOT_CTX, "start_ap_mode"), \
             patch.object(watcher.HOTSPOT_CTX, "stop_ap_mode"):
            watcher.leave_setup_mode("done")
        assert not flag.exists()

    def test_leave_is_idempotent_when_not_in_setup(self, watcher, tmp_path):
        flag = tmp_path / "apmode"
        watcher.AP_MODE_FLAG_PATH = str(flag)
        watcher.STATE.setup_mode = False
        with patch.object(watcher.HOTSPOT_CTX, "stop_ap_mode") as mock_stop:
            watcher.leave_setup_mode("done")
        mock_stop.assert_not_called()

    def test_recovery_hotspot_always_enterable_no_once_per_boot_budget(self, watcher, tmp_path):
        # Defect 2: there is no ap_exhausted latch any more.  A hotspot that was
        # entered and left earlier this boot can be re-entered immediately.
        flag = tmp_path / "apmode"
        watcher.AP_MODE_FLAG_PATH = str(flag)
        assert not hasattr(watcher.STATE, "ap_exhausted")
        assert not hasattr(watcher.STATE, "force_setup_mode")
        with patch.object(watcher.HOTSPOT_CTX, "start_ap_mode") as mock_start, \
             patch.object(watcher.HOTSPOT_CTX, "stop_ap_mode"):
            watcher.enter_setup_mode(watcher.wifi_policy.HotspotPurpose.FIRST_RUN, "first")
            watcher.leave_setup_mode("done")
            watcher.enter_setup_mode(watcher.wifi_policy.HotspotPurpose.USB_LOSS_RECOVERY, "later loss")
        assert mock_start.call_count == 2
        assert watcher.STATE.setup_mode is True
        assert watcher.STATE.hotspot.purpose is watcher.wifi_policy.HotspotPurpose.USB_LOSS_RECOVERY

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

        with patch.object(watcher.HOTSPOT_CTX, "stop_ap_mode", side_effect=_stop), \
             patch.object(watcher.HOTSPOT_CTX, "update_apmode_flag", side_effect=_update_flag):
            watcher.leave_setup_mode("ordering-test")

        assert order == ["stop_ap", "flag_False"], f"Wrong order: {order}"


class TestStartApModeNmcliFailure:
    """A failed nmcli add/activate must not leave setup_mode set (and so must
    not leave HotspotController.start's flag check believing the AP came up)."""

    def _patch_common(self, watcher):
        return [
            patch.object(watcher, "resolve_recovery_ifname", return_value="wlan0"),
            patch.object(watcher, "get_ap_ssid", return_value="autostream_0000"),
        ]

    def test_add_ap_connection_failure_clears_setup_mode(self, watcher):
        watcher.STATE.setup_mode = True
        watcher.STATE.hotspot = watcher.HotspotSession(
            purpose=watcher.wifi_policy.HotspotPurpose.FIRST_RUN, entered_at=0.0)
        with ExitStack() as stack:
            for p in self._patch_common(watcher):
                stack.enter_context(p)
            stack.enter_context(patch.object(watcher.nm, "delete_connection"))
            stack.enter_context(patch.object(
                watcher.nm, "add_ap_connection",
                return_value=MagicMock(returncode=1, stderr="failed")))
            activate = stack.enter_context(patch.object(watcher.nm, "activate_ap"))
            dnsmasq_write = stack.enter_context(
                patch.object(watcher, "_write_dnsmasq_runtime"))
            watcher.start_ap_mode()
        assert watcher.STATE.setup_mode is False
        assert watcher.STATE.hotspot is None
        activate.assert_not_called()
        dnsmasq_write.assert_not_called()

    def test_activate_ap_failure_clears_setup_mode(self, watcher):
        watcher.STATE.setup_mode = True
        watcher.STATE.hotspot = watcher.HotspotSession(
            purpose=watcher.wifi_policy.HotspotPurpose.FIRST_RUN, entered_at=0.0)
        with ExitStack() as stack:
            for p in self._patch_common(watcher):
                stack.enter_context(p)
            stack.enter_context(patch.object(watcher.nm, "delete_connection"))
            stack.enter_context(patch.object(
                watcher.nm, "add_ap_connection", return_value=MagicMock(returncode=0)))
            stack.enter_context(patch.object(watcher, "_write_dnsmasq_runtime", return_value=True))
            stack.enter_context(patch.object(
                watcher.nm, "activate_ap",
                return_value=MagicMock(returncode=1, stderr="failed")))
            systemctl = stack.enter_context(patch.object(watcher, "run_cmd"))
            watcher.start_ap_mode()
        assert watcher.STATE.setup_mode is False
        assert watcher.STATE.hotspot is None
        systemctl.assert_not_called()   # dnsmasq never started for an AP that never came up

    def test_success_leaves_setup_mode_and_starts_dnsmasq(self, watcher):
        watcher.STATE.setup_mode = True
        watcher.STATE.hotspot = watcher.HotspotSession(
            purpose=watcher.wifi_policy.HotspotPurpose.FIRST_RUN, entered_at=0.0)
        with ExitStack() as stack:
            for p in self._patch_common(watcher):
                stack.enter_context(p)
            stack.enter_context(patch.object(watcher.nm, "delete_connection"))
            stack.enter_context(patch.object(
                watcher.nm, "add_ap_connection", return_value=MagicMock(returncode=0)))
            stack.enter_context(patch.object(watcher, "_write_dnsmasq_runtime", return_value=True))
            stack.enter_context(patch.object(
                watcher.nm, "activate_ap", return_value=MagicMock(returncode=0)))
            systemctl = stack.enter_context(patch.object(watcher, "run_cmd"))
            watcher.start_ap_mode()
        assert watcher.STATE.setup_mode is True
        assert watcher.STATE.hotspot is not None
        systemctl.assert_called_once()

    def test_hotspot_controller_flag_not_set_on_nmcli_failure(self, watcher):
        # End-to-end with the real start_ap_mode: HotspotController.start's
        # existing "flag only if still in setup" check now actually reflects
        # nmcli's verdict, not just the pre-existing abort paths.
        watcher.STATE.setup_mode = True
        watcher.STATE.hotspot = watcher.HotspotSession(
            purpose=watcher.wifi_policy.HotspotPurpose.FIRST_RUN, entered_at=0.0)
        with ExitStack() as stack:
            for p in self._patch_common(watcher):
                stack.enter_context(p)
            stack.enter_context(patch.object(watcher.nm, "delete_connection"))
            stack.enter_context(patch.object(
                watcher.nm, "add_ap_connection",
                return_value=MagicMock(returncode=1, stderr="failed")))
            flag = stack.enter_context(patch.object(watcher.HOTSPOT_CTX, "update_apmode_flag"))
            watcher.hotspot_controller.start()
        flag.assert_not_called()


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
        assert enter.call_args[0][0] is watcher.wifi_policy.HotspotPurpose.EXPLICIT_RECONFIGURE
        rollback = enter.call_args.kwargs["rollback"]
        assert rollback.connection_name == "Home"
        assert rollback.connection_uuid == "uuid-1"
        assert rollback.adapter_mac == "bb:bb:bb:bb:bb:01"

    def test_disconnects_active_client_session(self, watcher):
        watcher.STATE.active_client_ifname = "wlan1"
        with patch.object(watcher, "get_configured_network_state",
                          return_value=watcher.wifi_net.NetworkState("Home", "uuid-1")), \
             patch.object(watcher.nm, "disconnect_device") as disc, \
             patch.object(watcher, "enter_setup_mode"):
            watcher.start_explicit_setup()
        disc.assert_called_once_with("wlan1")


class TestWifiPolicyModule:
    """Phase B: the pure policy core lives in a standalone importable module,
    independent of the watcher."""

    def test_policy_module_has_no_watcher_dependency(self):
        # Importable without loading the watcher / flask / sysutils stubs.
        import wifi_policy
        assert set(wifi_policy.PURPOSE_TABLE) == set(wifi_policy.HotspotPurpose)


class TestUnifiedGuardedReboot:
    """C2-WP5 — every reboot domain (gateway-down, 12-hour catch-all, dead-PHY)
    goes through request_guarded_reboot, sharing one persistent cross-boot guard
    and one in-process throttle.  The stamp is isolated per test by the autouse
    _isolate_reboot_guard fixture."""

    def _read_guard(self, watcher, now_wall=1_000_000.0):
        return watcher.wifi_recovery.read_dead_phy_reboot_guard(watcher, now_wall)

    def test_network_down_domain_records_in_persistent_guard(self, watcher):
        # Gap closed: an accepted network-down reboot is now counted in the same
        # cross-boot window as dead-PHY (previously it was not recorded at all).
        now = 5000.0
        with patch("time.time", return_value=1_000_000.0), \
             patch.object(watcher, "reboot_system", return_value=True) as reboot:
            accepted = watcher.request_guarded_reboot(now, "gw down", domain="network_down")
        assert accepted is True
        reboot.assert_called_once_with("NetworkDown")
        assert watcher.STATE.conn_reboot_retry_after == float("inf")
        assert len(self._read_guard(watcher)["requests"]) == 1

    def test_persistent_guard_suppresses_network_down_domain(self, watcher):
        # A network-down reboot is now suppressed once the cross-boot cap is hit.
        now = 5000.0
        with patch("time.time", return_value=1_000_000.0):
            for _ in range(watcher.DEAD_ADAPTER_MAX_REBOOTS_PER_WINDOW):
                watcher.wifi_recovery.record_dead_phy_reboot_request(watcher, 1_000_000.0, None)
            with patch.object(watcher, "reboot_system", return_value=True) as reboot:
                accepted = watcher.request_guarded_reboot(now, "gw down", domain="network_down")
        assert accepted is False
        reboot.assert_not_called()

    def test_in_process_throttle_suppresses(self, watcher):
        now = 5000.0
        watcher.STATE.conn_reboot_retry_after = now + 60.0
        with patch("time.time", return_value=1_000_000.0), \
             patch.object(watcher, "reboot_system", return_value=True) as reboot:
            accepted = watcher.request_guarded_reboot(now, "gw down", domain="network_down")
        assert accepted is False
        reboot.assert_not_called()

    def test_rejected_reboot_sets_finite_retry_and_no_record(self, watcher):
        now = 5000.0
        with patch("time.time", return_value=1_000_000.0), \
             patch.object(watcher, "reboot_system", return_value=False) as reboot:
            accepted = watcher.request_guarded_reboot(now, "gw down", domain="network_down")
        assert accepted is False
        reboot.assert_called_once_with("NetworkDown")
        assert watcher.STATE.conn_reboot_retry_after == now + watcher.REBOOT_RATE_LIMIT_RETRY
        assert self._read_guard(watcher)["requests"] == []  # only accepted reboots are stamped

    def test_dead_phy_domain_records_target_identity(self, watcher):
        target = watcher.wifi_recovery.TargetAdapter(
            ifname="wlan1", stable_id="sid-1", kind="usb_wifi", is_usb=True,
            is_builtin=False, present_in_nm=True, present_in_sysfs=True, resettable_usb=True)
        now = 5000.0
        with patch("time.time", return_value=1_000_000.0), \
             patch.object(watcher, "reboot_system", return_value=True):
            watcher.request_guarded_reboot(now, "dead phy", domain="dead_phy", target=target)
        req = self._read_guard(watcher)["requests"][0]
        assert req["ifname"] == "wlan1"
        assert req["stable_id"] == "sid-1"


class TestNmcliGoesThroughNMClient:
    """The watcher orchestration module issues no direct nmcli itself — every
    nmcli invocation goes through the bounded NMClient (wifi_nm.py).

    Scoped to platform/wifi_watcher.py: wifi_net keeps its
    facts/query helpers and the pure command builders/parsers NMClient calls, so
    this guard covers the imperative watcher code, not the core facts layer.
    """

    def test_watcher_issues_no_raw_nmcli(self):
        import re
        from pathlib import Path
        src = (Path(__file__).parent.parent / "platform" / "wifi_watcher.py").read_text(encoding="utf-8")
        # No literal run_cmd(["nmcli", ...]) (single- or multi-line).
        assert not re.search(r'run_cmd\(\s*\[\s*"nmcli"', src), (
            "watcher must not issue a raw run_cmd(['nmcli', ...]); use the nm client"
        )
        # No run_cmd(wifi_net.<...>_cmd(...)) builder-based nmcli execution either.
        assert not re.search(r'run_cmd\(\s*wifi_net\.\w+_cmd\(', src), (
            "watcher must not run wifi_net nmcli command builders directly; use the nm client"
        )


class TestSubprocessTimeoutBounds:
    """IF-1: every nmcli/systemctl execution site on the loop and worker paths is
    timeout-bounded, so a wedged NetworkManager returns rc 124 instead of hanging
    the monitor loop.  This is the permanent guard the immediate-fix requires: a
    fake nmcli that never completes within its bound.  A call made with no
    ``timeout=`` would hang the loop forever on real hardware, so the fake fails
    the test if it ever sees one.
    """

    @staticmethod
    def _wedged_run_cmd(calls, sleep_s: float = 0.0):
        """A run_cmd stub modelling a wedged NM/systemctl/ip child.

        It records ``(cmd, timeout)`` for every call, asserts a timeout was
        supplied (an unbounded site would hang forever), and returns rc 124 —
        exactly what the real run_cmd hands back after SIGKILLing a hung child.
        """
        def fake(cmd, *a, timeout=None, log_cmd=None, warn_on_failure=True, **k):
            calls.append((tuple(cmd), timeout))
            assert timeout is not None, f"unbounded subprocess call: {list(cmd)}"
            if sleep_s:
                time.sleep(sleep_s)
            return SimpleNamespace(returncode=124, stdout="",
                                   stderr=f"timeout after {timeout}s")
        return fake

    def test_wedged_nmcli_keeps_monitor_pass_bounded(self, watcher):
        # A monitor pass against a fully wedged NetworkManager: every nmcli/ip
        # query returns rc 124 (the fact helpers degrade gracefully to "offline")
        # and the pass completes promptly instead of blocking on a hung child.
        calls: list = []
        fake = self._wedged_run_cmd(calls, sleep_s=0.002)
        cfg = watcher.wifi_net.NetworkState(connection_name="Home", connection_uuid="u")
        with patch.object(watcher, "run_cmd", side_effect=fake), \
             patch.object(watcher.wifi_net, "run_cmd", side_effect=fake), \
             patch.object(watcher.wifi_nm, "run_cmd", side_effect=fake), \
             patch.object(watcher, "is_wifi_configured", return_value=True), \
             patch.object(watcher, "get_configured_network_state", return_value=cfg):
            watcher.STATE.boot_time = None  # the loop stamps it; boot_age starts at 0
            start = time.monotonic()
            watcher.network_monitor_loop(run_once=True)
            elapsed = time.monotonic() - start
        assert calls, "wedged pass should still exercise nmcli/ip subprocesses"
        assert all(t is not None for _, t in calls)
        # The fake sleeps only milliseconds per call, so a bounded pass returns
        # far faster than any single command timeout (the smallest is 2 s).
        assert elapsed < 5.0

    def test_effectful_transition_sites_are_bounded(self, watcher):
        # The AP-mode lifecycle and the other loop-thread transitions reach nmcli
        # sites that a wedged-discovery pass cannot (they need a resolvable
        # adapter).  Drive them directly and confirm each carries a timeout.
        calls: list = []
        fake = self._wedged_run_cmd(calls)
        cfg = watcher.wifi_net.NetworkState(connection_name="Home", connection_uuid="u")
        with patch.object(watcher, "run_cmd", side_effect=fake), \
             patch.object(watcher.wifi_net, "run_cmd", side_effect=fake), \
             patch.object(watcher.wifi_nm, "run_cmd", side_effect=fake), \
             patch.object(watcher, "resolve_recovery_ifname", return_value="wlan0"), \
             patch.object(watcher, "_write_dnsmasq_runtime", return_value=True), \
             patch.object(watcher.wifi_net, "remove_dnsmasq_runtime_config"), \
             patch.object(watcher, "get_configured_network_state", return_value=cfg), \
             patch.object(watcher.CONFIG_CTX, "get_configured_network_state", return_value=cfg), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.wifi_net, "list_wifi_connection_profiles",
                          return_value=[("uuid-1", "Home")]), \
             patch.object(watcher.wifi_net, "wifi_profile_mode", return_value="infrastructure"):
            watcher.STATE.setup_mode = True
            watcher.start_ap_mode()                        # delete / add (fails fast: rc=124)
            watcher.stop_ap_mode()                         # systemctl stop / delete
            watcher.wifi_config.connect_to_configured_wifi(watcher.CONFIG_CTX)  # clear-restrictions / connection up
            watcher.wifi_config.migrate_client_profiles_autoconnect_no(watcher.CONFIG_CTX)  # autoconnect-no modify
            watcher.STATE.active_client_ifname = "wlan0"
            with patch.object(watcher, "enter_setup_mode"):
                watcher.start_explicit_setup()             # device disconnect

        assert any("connection" in c and "up" in c for c, _ in calls)
        assert any("device" in c and "disconnect" in c for c, _ in calls)
        assert any(c and c[0] == "systemctl" for c, _ in calls)
        assert all(t is not None for _, t in calls)


class TestLogThrottled:
    """WS2-WP4 — the shared time-window throttled-log helper and the
    playing-status warning folded onto it."""

    def test_first_call_logs_then_suppresses_within_interval(self, watcher):
        with patch.object(watcher, "logger") as log:
            assert watcher.log_throttled("k", "msg", interval=300, now=0.0) is True
            assert watcher.log_throttled("k", "msg", interval=300, now=299.0) is False
        log.log.assert_called_once()

    def test_logs_again_after_interval(self, watcher):
        with patch.object(watcher, "logger") as log:
            watcher.log_throttled("k", "msg", interval=300, now=0.0)
            assert watcher.log_throttled("k", "msg", interval=300, now=300.0) is True
        assert log.log.call_count == 2

    def test_distinct_keys_are_independent(self, watcher):
        with patch.object(watcher, "logger") as log:
            assert watcher.log_throttled("a", "m", interval=300, now=0.0) is True
            assert watcher.log_throttled("b", "m", interval=300, now=0.0) is True
        assert log.log.call_count == 2

    def test_warn_playing_status_gated_on_pending_and_throttled(self, watcher):
        # No pending adoption -> never warns.
        watcher.ADOPTION_STATE.pending_usb_adoption_mac = None
        with patch.object(watcher, "logger") as log:
            watcher._warn_playing_status_unavailable()
        log.warning.assert_not_called()

        # Pending adoption -> warns once, then throttled within the window.
        watcher.ADOPTION_STATE.pending_usb_adoption_mac = "aa:bb:cc:00:00:01"
        with patch.object(watcher, "logger") as log:
            watcher._warn_playing_status_unavailable()
            watcher._warn_playing_status_unavailable()
        log.log.assert_called_once()   # log_throttled uses logger.log(level, ...)


class TestRepeatSuppressionFilter:
    """Consecutive-repeat log suppression (replaces the windowed dedupe filter,
    which dropped every record while monotonic time was below its window)."""

    @staticmethod
    def _record(msg: str):
        import logging
        return logging.LogRecord(
            name="test", level=logging.INFO, pathname=__file__, lineno=1,
            msg=msg, args=None, exc_info=None,
        )

    def test_fresh_boot_first_record_passes(self, watcher):
        # Regression: a never-seen message must pass even at low monotonic
        # values (e.g. shortly after boot), not just once uptime is high.
        with patch("time.monotonic", return_value=35.0):
            f = watcher.RepeatSuppressionFilter()
            assert f.filter(self._record("hello")) is True

    def test_consecutive_repeats_suppressed_after_free_passes(self, watcher):
        f = watcher.RepeatSuppressionFilter()
        with patch("time.monotonic", return_value=0.0):
            assert f.filter(self._record("m")) is True
            assert f.filter(self._record("m")) is True
            assert f.filter(self._record("m")) is True
            assert f.filter(self._record("m")) is False
            assert f.filter(self._record("m")) is False

    def test_reminder_after_interval_annotates_count(self, watcher):
        f = watcher.RepeatSuppressionFilter()
        with patch("time.monotonic", return_value=0.0):
            for _ in range(3):
                assert f.filter(self._record("m")) is True
            assert f.filter(self._record("m")) is False
        with patch("time.monotonic", return_value=300.0):
            rec = self._record("m")
            assert f.filter(rec) is True
            assert rec.getMessage().endswith("(repeated 5 times)")

    def test_run_reset_on_new_message(self, watcher):
        f = watcher.RepeatSuppressionFilter()
        with patch("time.monotonic", return_value=0.0):
            assert f.filter(self._record("A")) is True
            assert f.filter(self._record("A")) is True
            assert f.filter(self._record("A")) is True
            assert f.filter(self._record("A")) is False
            assert f.filter(self._record("B")) is True
            assert f.filter(self._record("A")) is True

    def test_alternating_messages_never_suppressed(self, watcher):
        f = watcher.RepeatSuppressionFilter()
        with patch("time.monotonic", return_value=0.0):
            for msg in ["A", "B", "A", "B"]:
                assert f.filter(self._record(msg)) is True

    def test_two_handlers_share_record_stream_annotate_once(self, watcher):
        # Both handlers receive the same LogRecord object per log call; the
        # reminder annotation must be applied exactly once and stay in sync
        # across both filter instances' independent run tracking.
        f1 = watcher.RepeatSuppressionFilter()
        f2 = watcher.RepeatSuppressionFilter()
        with patch("time.monotonic", return_value=0.0):
            for _ in range(3):
                r = self._record("m")
                assert f1.filter(r) is True
                assert f2.filter(r) is True
            r = self._record("m")
            assert f1.filter(r) is False
            assert f2.filter(r) is False
        with patch("time.monotonic", return_value=300.0):
            r = self._record("m")
            assert f1.filter(r) is True
            first_rendered = r.getMessage()
            assert first_rendered.endswith("(repeated 5 times)")
            assert f2.filter(r) is True
            assert r.getMessage() == first_rendered


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
        assert watcher.LOG_STATE.temporary_log_level == "debug"
        assert watcher.LOG_STATE.temporary_log_level_until == 1900.0
        import logging
        assert logging.getLogger().level == logging.DEBUG

    def test_apply_permanent_updates_default(self, watcher):
        watcher.apply_log_level("warning", None)
        assert watcher.LOG_STATE.temporary_log_level == ""
        assert watcher.LOG_STATE.default_log_level_name == "warning"

    def test_revert_after_ttl(self, watcher):
        watcher.LOG_STATE.default_log_level_name = "info"
        with patch("time.monotonic", return_value=1000.0):
            watcher.apply_log_level("debug", 900)
        # Before expiry: no revert.
        watcher.revert_expired_log_level(now=1500.0)
        assert watcher.LOG_STATE.temporary_log_level == "debug"
        # After expiry: reverts to default.
        watcher.revert_expired_log_level(now=2000.0)
        assert watcher.LOG_STATE.temporary_log_level == ""
        import logging
        assert logging.getLogger().level == logging.INFO


class TestApplyRuntimeLevelWerkzeugGating:
    """Werkzeug self-configures its logger to INFO, which would otherwise
    bypass the root level for propagated HTTP access-log records.
    _apply_runtime_level pins werkzeug in step with the runtime level so
    access lines only flow at debug; its own warnings/errors always pass."""

    @pytest.fixture(autouse=True)
    def _restore_logger_state(self, watcher):
        import logging as _logging
        werkzeug_logger = _logging.getLogger("werkzeug")
        saved_root_level = _logging.getLogger().level
        saved_werkzeug_level = werkzeug_logger.level
        saved_temp_level = watcher.LOG_STATE.temporary_log_level
        saved_temp_until = watcher.LOG_STATE.temporary_log_level_until
        saved_default_name = watcher.LOG_STATE.default_log_level_name
        yield
        _logging.getLogger().setLevel(saved_root_level)
        werkzeug_logger.setLevel(saved_werkzeug_level)
        watcher.LOG_STATE.temporary_log_level = saved_temp_level
        watcher.LOG_STATE.temporary_log_level_until = saved_temp_until
        watcher.LOG_STATE.default_log_level_name = saved_default_name

    def test_apply_runtime_level_info_sets_werkzeug_warning(self, watcher):
        import logging as _logging
        watcher._apply_runtime_level(_logging.INFO)
        assert _logging.getLogger().level == _logging.INFO
        assert _logging.getLogger("werkzeug").level == _logging.WARNING

    def test_apply_runtime_level_debug_sets_werkzeug_info(self, watcher):
        import logging as _logging
        watcher._apply_runtime_level(_logging.DEBUG)
        assert _logging.getLogger().level == _logging.DEBUG
        assert _logging.getLogger("werkzeug").level == _logging.INFO

    def test_apply_log_level_debug_sets_werkzeug_info(self, watcher):
        import logging as _logging
        with patch("time.monotonic", return_value=1000.0):
            watcher.apply_log_level("debug", 900)
        assert _logging.getLogger("werkzeug").level == _logging.INFO

    def test_revert_expired_log_level_restores_werkzeug_warning(self, watcher):
        import logging as _logging
        watcher.LOG_STATE.default_log_level_name = "info"
        with patch("time.monotonic", return_value=1000.0):
            watcher.apply_log_level("debug", 900)
        assert _logging.getLogger("werkzeug").level == _logging.INFO
        # Before expiry: werkzeug stays gated for debug access logging.
        watcher.revert_expired_log_level(now=1500.0)
        assert _logging.getLogger("werkzeug").level == _logging.INFO
        # After expiry: reverts to the default level's werkzeug gating.
        watcher.revert_expired_log_level(now=2000.0)
        assert _logging.getLogger().level == _logging.INFO
        assert _logging.getLogger("werkzeug").level == _logging.WARNING


class TestLogLevelChangeConfirmationVisibility:
    """apply_log_level / revert_expired_log_level log their confirmation at
    WARNING so the record survives even when the runtime level itself has
    been lowered to warning."""

    @pytest.fixture(autouse=True)
    def _restore_logger_state(self, watcher):
        import logging as _logging
        werkzeug_logger = _logging.getLogger("werkzeug")
        saved_root_level = _logging.getLogger().level
        saved_werkzeug_level = werkzeug_logger.level
        saved_temp_level = watcher.LOG_STATE.temporary_log_level
        saved_temp_until = watcher.LOG_STATE.temporary_log_level_until
        saved_default_name = watcher.LOG_STATE.default_log_level_name
        yield
        _logging.getLogger().setLevel(saved_root_level)
        werkzeug_logger.setLevel(saved_werkzeug_level)
        watcher.LOG_STATE.temporary_log_level = saved_temp_level
        watcher.LOG_STATE.temporary_log_level_until = saved_temp_until
        watcher.LOG_STATE.default_log_level_name = saved_default_name

    def test_apply_log_level_confirmation_survives_warning_runtime_level(self, watcher, caplog):
        import logging as _logging
        watcher._apply_runtime_level(_logging.WARNING)
        with caplog.at_level(_logging.WARNING, logger=watcher.logger.name):
            with patch("time.monotonic", return_value=1000.0):
                watcher.apply_log_level("debug", 900)
        assert any(
            r.levelno == _logging.WARNING
            and "Runtime log level changed to debug for 900s" in r.getMessage()
            for r in caplog.records
        )

    def test_revert_expired_log_level_confirmation_survives_warning_runtime_level(self, watcher, caplog):
        import logging as _logging
        watcher.LOG_STATE.default_log_level_name = "warning"
        with patch("time.monotonic", return_value=1000.0):
            watcher.apply_log_level("debug", 900)
        with caplog.at_level(_logging.WARNING, logger=watcher.logger.name):
            watcher.revert_expired_log_level(now=2000.0)
        assert any(
            r.levelno == _logging.WARNING
            and "Runtime log level reverted to warning" in r.getMessage()
            for r in caplog.records
        )


class TestProcessSetLogLevel:
    def test_process_applies_level(self, watcher):
        with patch("time.monotonic", return_value=1000.0):
            watcher.process_control_action("set_log_level",
                                           {"level": "debug", "ttl_seconds": 900})
        assert watcher.LOG_STATE.temporary_log_level == "debug"
        assert watcher.CONTROL_STATE.last_control_result == "ok"


class TestCommitNetworkStateClearsBssidState:
    """A newly committed SSID invalidates every interface's BSSID observations
    and the pending pin record — stale signal data from the previous network
    must never leak into roam/pin decisions for the new one."""

    def test_commit_clears_all_interface_tables_and_pin(self, watcher):
        watcher.ADOPTION_STATE.bssid_tables["wlan0"] = {"AA:AA:AA:AA:AA:AA": {"ssid": "Old"}}
        watcher.ADOPTION_STATE.bssid_tables["wlan1"] = {"BB:BB:BB:BB:BB:BB": {"ssid": "Old"}}
        watcher.ADOPTION_STATE.last_bssid_pin = {
            "ifname": "wlan1", "bssid": "BB:BB:BB:BB:BB:BB", "signal": 70, "at": 0.0,
        }
        watcher.ADOPTION_STATE.bssid_roam_candidate = {
            "ifname": "wlan1", "bssid": "BB:BB:BB:BB:BB:BB", "count": 2, "last_seen": 0.0,
        }
        with patch.object(watcher.wifi_net, "resolve_connection_uuid_for_name", return_value="uuid-new"), \
             patch.object(watcher.wifi_net, "save_network_state"):
            watcher._commit_network_state("NewHome", "uuid-new")
        assert watcher.ADOPTION_STATE.bssid_tables == {}
        assert watcher.ADOPTION_STATE.last_bssid_pin == {}
        assert watcher.ADOPTION_STATE.bssid_roam_candidate == {}


class TestModuleSplit:
    def test_recovery_and_status_modules_import(self, watcher):
        # The watcher fixture loads the watcher, which puts platform/ on sys.path.
        import wifi_recovery
        import wifi_status
        assert hasattr(wifi_recovery, "escalate_dead_adapter_recovery")
        assert hasattr(wifi_recovery, "TargetAdapter")
        assert hasattr(wifi_status, "build_network_status_snapshot")

    def test_escalate_delegates(self, watcher):
        usb = _adapter(watcher, "wlan0", "dc:62:79:91:4d:d6", is_usb=True)
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=False, healthy=True):
            # Healthy target -> ladder returns False via the delegated impl.
            assert watcher.wifi_recovery.escalate_dead_adapter_recovery(
                watcher.RECOVERY_CTX, [usb], False) is False

    def test_snapshot_delegates(self, watcher):
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value={}), \
             patch.object(watcher.STATUS_CTX, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.wifi_status.build_network_status_snapshot(watcher.STATUS_CTX, [], wired_connected=False, wired_ok=False)
        assert snap["schema_version"] == 1
