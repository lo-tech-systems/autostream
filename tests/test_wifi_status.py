"""Network status snapshot construction and truthfulness."""
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
from _wifi_fixtures import _adapter, _ledger


class TestBuildNetworkStatusSnapshot:
    MAC = "dc:62:79:91:4d:d6"

    def _snapshot_for_usb(self, watcher, usb, *, now=1000.0, healthy=True):
        addrs = {"wlan0": [{"family": "ipv4", "address": "192.168.1.42",
                            "prefixlen": 24, "scope": "global"}]}
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value=addrs), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher.wifi_net, "read_operstate", return_value="up"), \
             patch.object(watcher.wifi_net, "default_gateway_ipv4", return_value="192.168.1.1"), \
             patch.object(watcher.RECOVERY_CTX, "is_wifi_client_healthy", return_value=healthy), \
             patch.object(watcher.STATUS_CTX, "is_gateway_reachable", return_value=True), \
             patch.object(watcher.STATUS_CTX, "resolve_hotspot_adapter", return_value=None), \
             patch("time.monotonic", return_value=now):
            return watcher.wifi_status.build_network_status_snapshot(watcher.STATUS_CTX, [usb], wired_connected=False, wired_ok=False)

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
             patch.object(watcher.RECOVERY_CTX, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher.STATUS_CTX, "is_gateway_reachable", return_value=True), \
             patch.object(watcher.STATUS_CTX, "resolve_hotspot_adapter", return_value=usb):
            snap = watcher.wifi_status.build_network_status_snapshot(watcher.STATUS_CTX, [usb], wired_connected=False, wired_ok=False)
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
        watcher.RECOVERY_STATE.dead_adapter_ifname = "wlan0"
        watcher.RECOVERY_STATE.dead_adapter_since = 5.0
        watcher.RECOVERY_STATE.dead_adapter_checks = 4
        watcher.RECOVERY_STATE.last_reset_method = "B"
        watcher.RECOVERY_STATE.adapter_reset_ledgers[self.MAC] = {
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
             patch.object(watcher.RECOVERY_CTX, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.STATUS_CTX, "resolve_hotspot_adapter", return_value=None), \
             patch("time.monotonic", return_value=1000.0):
            snap = watcher.wifi_status.build_network_status_snapshot(watcher.STATUS_CTX, [usb], wired_connected=False, wired_ok=False)
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
        watcher.RECOVERY_STATE.adapter_reset_ledgers[self.MAC] = {
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
        watcher.RECOVERY_STATE.adapter_reset_ledgers[self.MAC] = {
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
        watcher.RECOVERY_STATE.adapter_reset_ledgers[self.MAC] = {
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
        watcher.RECOVERY_STATE.adapter_reset_ledgers[self.MAC] = {
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
        watcher.RECOVERY_STATE.adapter_reset_ledgers[self.MAC] = {
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
        watcher.RECOVERY_STATE.dead_adapter_ifname = "wlan0"
        addrs = {"eth0": [{"family": "ipv4", "address": "10.0.0.5",
                           "prefixlen": 24, "scope": "global"}]}
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value=addrs), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=True), \
             patch.object(watcher.wifi_net, "read_operstate", return_value="down"), \
             patch.object(watcher.wifi_net, "default_gateway_ipv4", return_value="10.0.0.1"), \
             patch.object(watcher.wifi_net, "get_active_wifi_ssid") as get_ssid, \
             patch.object(watcher.RECOVERY_CTX, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.STATUS_CTX, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.wifi_status.build_network_status_snapshot(watcher.STATUS_CTX, [usb], wired_connected=True, wired_ok=True)
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
             patch.object(watcher.RECOVERY_CTX, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher.STATUS_CTX, "is_gateway_reachable", return_value=True), \
             patch.object(watcher.STATUS_CTX, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.wifi_status.build_network_status_snapshot(watcher.STATUS_CTX, [usb], wired_connected=True, wired_ok=True)
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
             patch.object(watcher.RECOVERY_CTX, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher.STATUS_CTX, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.wifi_status.build_network_status_snapshot(watcher.STATUS_CTX, [usb], wired_connected=True, wired_ok=True)
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
             patch.object(watcher.RECOVERY_CTX, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher.STATUS_CTX, "is_gateway_reachable", return_value=True), \
             patch.object(watcher.STATUS_CTX, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.wifi_status.build_network_status_snapshot(watcher.STATUS_CTX, [usb], wired_connected=True, wired_ok=True)
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
             patch.object(watcher.RECOVERY_CTX, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher.STATUS_CTX, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.wifi_status.build_network_status_snapshot(watcher.STATUS_CTX, [usb], wired_connected=True, wired_ok=True)
        assert snap["device"]["primary_kind"] == "ethernet"
        assert snap["device"]["primary_ifname"] == "eth0"
        assert snap["device"]["primary_ipv4_info"]["gateway"] == ""
        get_ssid.assert_not_called()

    def test_carrier_only_ethernet_is_not_online_or_primary(self, watcher):
        addrs = {"eth0": []}
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value=addrs), \
             patch.object(watcher.STATUS_CTX, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.wifi_status.build_network_status_snapshot(watcher.STATUS_CTX, [], wired_connected=True, wired_ok=False)
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
             patch.object(watcher.STATUS_CTX, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.wifi_status.build_network_status_snapshot(watcher.STATUS_CTX, [], wired_connected=True, wired_ok=True)
        assert snap["device"]["state"] == "setup_mode"
        assert snap["connectivity"]["active_path_ok"] is False
        assert snap["connectivity"]["no_active_path_age_seconds"] is None
        assert snap["connectivity"]["no_active_path_reboot_remaining_seconds"] is None

    def test_connectivity_timer_age_and_remaining(self, watcher):
        watcher.STATE.last_active_path_seen = 1000.0
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value={}), \
             patch.object(watcher.STATUS_CTX, "resolve_hotspot_adapter", return_value=None), \
             patch("time.monotonic", return_value=1030.0):
            snap = watcher.wifi_status.build_network_status_snapshot(watcher.STATUS_CTX, [], wired_connected=False, wired_ok=False)
        assert snap["connectivity"]["last_active_path_seen_monotonic"] == 1000.0
        assert snap["connectivity"]["no_active_path_age_seconds"] == 30.0
        assert snap["connectivity"]["no_active_path_reboot_after_seconds"] == watcher.NO_ACTIVE_PATH_REBOOT_AFTER
        assert snap["connectivity"]["no_active_path_reboot_remaining_seconds"] == watcher.NO_ACTIVE_PATH_REBOOT_AFTER - 30.0

    def test_logging_block_present(self, watcher):
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value={}), \
             patch.object(watcher.STATUS_CTX, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.wifi_status.build_network_status_snapshot(watcher.STATUS_CTX, [], wired_connected=False, wired_ok=False)
        assert snap["logging"]["effective_level"] == "info"
        assert snap["logging"]["default_level"] == "info"
        assert snap["logging"]["temporary_level_expires_at"] is None
        assert snap["device"]["state"] == "offline"

    def test_roaming_block_reflects_unmanaged(self, watcher):
        watcher.ADOPTION_STATE.roaming_managed = False
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value={}), \
             patch.object(watcher.STATUS_CTX, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.wifi_status.build_network_status_snapshot(watcher.STATUS_CTX, [], wired_connected=False, wired_ok=False)
        assert snap["roaming"] == {"managed": False}

    def test_roaming_block_reflects_managed(self, watcher):
        watcher.ADOPTION_STATE.roaming_managed = True
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value={}), \
             patch.object(watcher.STATUS_CTX, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.wifi_status.build_network_status_snapshot(watcher.STATUS_CTX, [], wired_connected=False, wired_ok=False)
        assert snap["roaming"] == {"managed": True}

    def test_publish_stores_latest_snapshot_in_memory(self, watcher):
        # publish_network_status takes the narrowed STATUS_CTX directly — patch
        # the fact helper on the context.
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value={}), \
             patch.object(watcher.STATUS_CTX, "resolve_hotspot_adapter", return_value=None):
            watcher.wifi_status.publish_network_status(
                watcher.STATUS_CTX, [], wired_connected=False, wired_ok=False)
        assert watcher.SNAPSHOT_STATE.network_status_snapshot["ok"] is True
        assert watcher.SNAPSHOT_STATE.network_status_snapshot["device"]["state"] == "offline"
        assert watcher.SNAPSHOT_STATE.network_status_updated_at == watcher.SNAPSHOT_STATE.network_status_snapshot["updated_at"]


class TestIf7StatusTruthfulness:
    """IF-7(a)+(c): the held-back no-IP count/reason reach the snapshot, and the
    primary SSID falls back to the active connection's configured SSID for
    hidden / scan-stale networks."""

    MAC = "dc:62:79:91:4d:d6"

    # ---- (a) held-back no-IP count and reason ----

    def _classify_snapshot(self, watcher, usb, *, link_down, now=1000.0):
        addrs = {}
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value=addrs), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=link_down), \
             patch.object(watcher.wifi_net, "read_operstate",
                          return_value=("down" if link_down else "up")), \
             patch.object(watcher.wifi_net, "default_gateway_ipv4", return_value=""), \
             patch.object(watcher.RECOVERY_CTX, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.STATUS_CTX, "resolve_hotspot_adapter", return_value=None), \
             patch("time.monotonic", return_value=now):
            snap = watcher.wifi_status.build_network_status_snapshot(
                watcher.STATUS_CTX, [usb], wired_connected=False, wired_ok=False)
        return snap["adapters"][0]

    def test_held_back_carrier_down_publishes_count_and_reason(self, watcher):
        # The 04-Jul field case: an idle spare held back after 5 no-IP failures,
        # now carrier-down.  The dead-PHY reset ledger never ticked, so the
        # meaningful number is the no-IP count — publish it in checks/reason and
        # policy.noip_failures.
        usb = _adapter(watcher, "wlan1", self.MAC, is_usb=True)
        watcher.RECOVERY_STATE.adapter_noip_ledgers[self.MAC] = {"count": 5, "retry_after": float("inf")}
        rec = self._classify_snapshot(watcher, usb, link_down=True)
        assert rec["health"]["state"] == "no_ip_held_back"
        assert rec["health"]["checks"] == 5
        assert rec["health"]["reason"] == "no_ip_held_back"
        assert rec["policy"]["warning"] == "no_ip_held_back"
        assert rec["policy"]["held_back"] is True
        assert rec["policy"]["noip_failures"] == 5

    def test_transient_no_ip_still_reports_associated_no_ip(self, watcher):
        # Carrier-up, not yet suppressed: the transient degraded_no_ip verdict is
        # unchanged (regression on the reason ladder).
        usb = _adapter(watcher, "wlan1", self.MAC, is_usb=True)
        watcher.RECOVERY_STATE.adapter_noip_ledgers[self.MAC] = {"count": 2, "retry_after": 0.0}
        rec = self._classify_snapshot(watcher, usb, link_down=False)
        assert rec["health"]["state"] == "degraded_no_ip"
        assert rec["health"]["checks"] == 2
        assert rec["health"]["reason"] == "associated_no_ip"
        assert rec["policy"]["warning"] == "no_ip_address"
        assert rec["policy"]["noip_failures"] == 2

    def test_dead_adapter_still_reports_link_down_unhealthy(self, watcher):
        # A dead-PHY adapter keeps dead_checks / "link_down_unhealthy" — the
        # held-back branch must not shadow it (regression).
        usb = _adapter(watcher, "wlan0", self.MAC, is_usb=True)
        watcher.RECOVERY_STATE.dead_adapter_ifname = "wlan0"
        watcher.RECOVERY_STATE.dead_adapter_since = 5.0
        watcher.RECOVERY_STATE.dead_adapter_checks = 4
        rec = self._classify_snapshot(watcher, usb, link_down=True)
        assert rec["health"]["state"] == "dead_phy"
        assert rec["health"]["checks"] == 4
        assert rec["health"]["reason"] == "link_down_unhealthy"
        assert rec["policy"]["warning"] == "resetting"

    def test_healthy_adapter_has_empty_reason_and_zero_checks(self, watcher):
        # Regression: a plain healthy adapter publishes checks 0 / reason "".
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
             patch.object(watcher.RECOVERY_CTX, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher.STATUS_CTX, "is_gateway_reachable", return_value=True), \
             patch.object(watcher.STATUS_CTX, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.wifi_status.build_network_status_snapshot(
                watcher.STATUS_CTX, [usb], wired_connected=False, wired_ok=False)
        rec = snap["adapters"][0]
        assert rec["health"]["state"] == "healthy"
        assert rec["health"]["checks"] == 0
        assert rec["health"]["reason"] == ""
        assert rec["policy"]["noip_failures"] == 0

    # ---- (c) primary_ssid fallback for hidden / scan-stale networks ----

    def _ssid_snapshot(self, watcher, usb, *, scan_ssid, conn_name, conn_ssid):
        watcher.STATE.active_client_ifname = "wlan0"
        watcher.STATE.active_client_mac = self.MAC
        addrs = {"wlan0": [{"family": "ipv4", "address": "192.168.1.42",
                            "prefixlen": 24, "scope": "global"}]}
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value=addrs), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher.wifi_net, "read_operstate", return_value="up"), \
             patch.object(watcher.wifi_net, "default_gateway_ipv4", return_value="192.168.1.1"), \
             patch.object(watcher.wifi_net, "get_active_wifi_ssid", return_value=scan_ssid) as get_ssid, \
             patch.object(watcher.wifi_net, "get_active_wifi_connection_name",
                          return_value=conn_name) as get_conn, \
             patch.object(watcher.wifi_net, "get_connection_ssid", return_value=conn_ssid) as get_conn_ssid, \
             patch.object(watcher.RECOVERY_CTX, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher.STATUS_CTX, "is_gateway_reachable", return_value=True), \
             patch.object(watcher.STATUS_CTX, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.wifi_status.build_network_status_snapshot(
                watcher.STATUS_CTX, [usb], wired_connected=False, wired_ok=False)
        return snap, get_ssid, get_conn, get_conn_ssid

    def test_hidden_ssid_falls_back_to_profile_ssid(self, watcher):
        usb = _adapter(watcher, "wlan0", self.MAC, is_usb=True)
        snap, get_ssid, get_conn, get_conn_ssid = self._ssid_snapshot(
            watcher, usb, scan_ssid="", conn_name="netplan-wlan0-IoT", conn_ssid="IoT-Hidden")
        assert snap["device"]["primary_ssid"] == "IoT-Hidden"
        get_ssid.assert_called_once()
        get_conn.assert_called_once()
        get_conn_ssid.assert_called_once_with("netplan-wlan0-IoT")

    def test_scan_hit_wins_without_extra_nmcli_calls(self, watcher):
        usb = _adapter(watcher, "wlan0", self.MAC, is_usb=True)
        snap, get_ssid, get_conn, get_conn_ssid = self._ssid_snapshot(
            watcher, usb, scan_ssid="MyHomeWiFi", conn_name="x", conn_ssid="y")
        assert snap["device"]["primary_ssid"] == "MyHomeWiFi"
        get_ssid.assert_called_once()
        get_conn.assert_not_called()
        get_conn_ssid.assert_not_called()

    def test_no_active_connection_name_yields_empty_ssid(self, watcher):
        usb = _adapter(watcher, "wlan0", self.MAC, is_usb=True)
        snap, get_ssid, get_conn, get_conn_ssid = self._ssid_snapshot(
            watcher, usb, scan_ssid="", conn_name="", conn_ssid="unused")
        assert snap["device"]["primary_ssid"] == ""
        get_conn.assert_called_once()
        get_conn_ssid.assert_not_called()

    def test_non_wifi_primary_skips_ssid_lookup(self, watcher):
        usb = _adapter(watcher, "wlan0", self.MAC, is_usb=True)
        watcher.RECOVERY_STATE.dead_adapter_ifname = "wlan0"
        addrs = {"eth0": [{"family": "ipv4", "address": "10.0.0.5",
                           "prefixlen": 24, "scope": "global"}]}
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value=addrs), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=True), \
             patch.object(watcher.wifi_net, "read_operstate", return_value="down"), \
             patch.object(watcher.wifi_net, "default_gateway_ipv4", return_value="10.0.0.1"), \
             patch.object(watcher.wifi_net, "get_active_wifi_ssid") as get_ssid, \
             patch.object(watcher.wifi_net, "get_active_wifi_connection_name") as get_conn, \
             patch.object(watcher.RECOVERY_CTX, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.STATUS_CTX, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.wifi_status.build_network_status_snapshot(
                watcher.STATUS_CTX, [usb], wired_connected=True, wired_ok=True)
        assert snap["device"]["primary_kind"] == "ethernet"
        assert snap["device"]["primary_ssid"] == ""
        get_ssid.assert_not_called()
        get_conn.assert_not_called()
