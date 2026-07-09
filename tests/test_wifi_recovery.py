"""No-IP ledger and diagnosis, adapter overlay events, budgeted
reset/quarantine, fault-state persistence, and the recovery ladder."""
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
from _wifi_fixtures import _adapter, _facts_for


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
            led = watcher.RECOVERY_STATE.adapter_noip_ledgers[self.MAC]
            assert led["count"] == i
            assert led["retry_after"] >= prev
            prev = led["retry_after"]
        wr.record_noip_failure(watcher, self.MAC, now=0.0)
        assert watcher.RECOVERY_STATE.adapter_noip_ledgers[self.MAC]["retry_after"] == float("inf")
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
             patch.object(watcher.RECOVERY_CTX, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.STATUS_CTX, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.wifi_status.build_network_status_snapshot(watcher.STATUS_CTX, [usb], wired_connected=False, wired_ok=False)
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
             patch.object(watcher.RECOVERY_CTX, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.STATUS_CTX, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.wifi_status.build_network_status_snapshot(watcher.STATUS_CTX, [usb], wired_connected=False, wired_ok=False)
        rec = snap["adapters"][0]
        assert rec["health"]["state"] == "no_ip_held_back"   # not link_down / degraded_no_ip
        assert rec["policy"]["warning"] == "no_ip_held_back"
        assert rec["policy"]["held_back"] is True

    def test_device_publishes_builtin_fallback_marker(self, watcher):
        # C-WP3: the demoted-from-active marker — device reports it is running on
        # the on-board radio as a fallback.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        watcher.ADOPTION_STATE.using_builtin_fallback = True
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value={}), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher.wifi_net, "read_operstate", return_value="up"), \
             patch.object(watcher.wifi_net, "default_gateway_ipv4", return_value=""), \
             patch.object(watcher.RECOVERY_CTX, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher.STATUS_CTX, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.wifi_status.build_network_status_snapshot(watcher.STATUS_CTX, [builtin], wired_connected=False, wired_ok=False)
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
             patch.object(watcher.RECOVERY_CTX, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.STATUS_CTX, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.wifi_status.build_network_status_snapshot(watcher.STATUS_CTX, [usb], wired_connected=False, wired_ok=False)
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
             patch.object(watcher.RECOVERY_CTX, "is_wifi_client_healthy", side_effect=_health), \
             patch.object(watcher.STATUS_CTX, "is_gateway_reachable", return_value=True), \
             patch.object(watcher.STATUS_CTX, "resolve_hotspot_adapter", return_value=None):
            snap = watcher.wifi_status.build_network_status_snapshot(watcher.STATUS_CTX,
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
        watcher.ADOPTION_STATE.known_usb_macs.add(usb_mac)
        event = self._diagnose(watcher, [builtin], None,
                               conn_ok=False, prev_mac=usb_mac, prev_ifname="wlan1")
        assert isinstance(event, watcher.wifi_recovery.ClientFailed)
        assert event.reason == "absent"
        assert event.mac == usb_mac
        assert event.ifname == "wlan1"
        assert event.has_alt_path is True  # built-in present

    def test_no_alt_path_when_no_builtin(self, watcher):
        usb_mac = "bb:bb:bb:bb:bb:01"
        watcher.ADOPTION_STATE.known_usb_macs.add(usb_mac)
        event = self._diagnose(watcher, [], None,  # USB gone, no built-in
                               conn_ok=False, prev_mac=usb_mac, prev_ifname="wlan1")
        assert event.reason == "absent"
        assert event.has_alt_path is False

    def test_conn_ok_true_returns_none(self, watcher):
        # The hysteresis has not (yet) condemned the path (e.g. a single transient
        # unhealthy pass held prior True): the overlay must not fire.
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:02", is_usb=True)
        watcher.ADOPTION_STATE.known_usb_macs.add(usb.permanent_mac)
        adapters = [_adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True), usb]
        event = self._diagnose(watcher, adapters, usb,
                               conn_ok=True, prev_mac=usb.permanent_mac, prev_ifname="wlan1")
        assert event is None

    def test_condemned_present_usb_returns_no_ip(self, watcher):
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:03", is_usb=True)
        watcher.ADOPTION_STATE.known_usb_macs.add(usb.permanent_mac)
        adapters = [_adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True), usb]
        event = self._diagnose(watcher, adapters, usb,
                               conn_ok=False, prev_mac=usb.permanent_mac, prev_ifname="wlan1")
        assert isinstance(event, watcher.wifi_recovery.ClientFailed)
        assert event.reason == "no_ip"
        assert event.ifname == "wlan1"

    def test_condemned_nm_disconnected_usb_uses_prev_ifname(self, watcher):
        # USB present but NM-disconnected: active_client is None, so the event
        # ifname comes from the recorded (prev) identity.
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:07", is_usb=True)
        watcher.ADOPTION_STATE.known_usb_macs.add(usb.permanent_mac)
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
        event = watcher.wifi_recovery.ClientFailed(ifname="wlan1", mac="bb:bb:bb:bb:bb:05",
                                     reason="no_ip", has_alt_path=True)
        action = watcher.wifi_policy.RecoveryAction(watcher.wifi_policy.RecoveryKind.ACTIVATE_ONBOARD, ifname="wlan0")
        with patch.object(watcher.ADOPTION_CTX, "gather_recovery_facts"), \
             patch.object(watcher.wifi_policy, "next_recovery_action", return_value=action), \
             patch.object(watcher.wifi_adoption, "_submit_client_activation", return_value=True) as ap:
            acted = watcher.wifi_adoption.apply_client_failed(watcher.ADOPTION_CTX, event, facts)
        assert acted is True
        ap.assert_called_once()

    def _rf_stub(self, watcher, *, onboard="", hotspot="", active=""):
        return watcher.wifi_policy.RecoveryFacts(
            adapters_by_ifname={}, onboard_ifname=onboard, usb_ifnames=(),
            preferred_usb_ifname="", hotspot_ifname=hotspot, active_ifname=active,
            saved_configured=True, wired_ok=False, taken_at=1000.0,
        )

    def test_apply_client_failed_enters_hotspot_when_no_client_path(self, watcher):
        # C2-WP1: ENTER_HOTSPOT with no usable onboard falls to USB_LOSS_RECOVERY.
        facts = _facts_for(watcher, [], None)
        event = watcher.wifi_recovery.ClientFailed(ifname="wlan1", mac="bb:bb:bb:bb:bb:05",
                                     reason="absent", has_alt_path=False)
        action = watcher.wifi_policy.RecoveryAction(watcher.wifi_policy.RecoveryKind.ENTER_HOTSPOT,
                                        purpose=watcher.wifi_policy.HotspotPurpose.BOOT_RECOVERY)
        with patch.object(watcher.ADOPTION_CTX, "gather_recovery_facts",
                          return_value=self._rf_stub(watcher, onboard="")), \
             patch.object(watcher.wifi_policy, "next_recovery_action", return_value=action), \
             patch.object(watcher.wifi_adoption, "_submit_client_activation") as ap, \
             patch.object(watcher.ADOPTION_CTX, "enter_setup_mode") as enter:
            acted = watcher.wifi_adoption.apply_client_failed(watcher.ADOPTION_CTX, event, facts)
        assert acted is True
        ap.assert_not_called()
        enter.assert_called_once()
        assert enter.call_args[0][0] is watcher.wifi_policy.HotspotPurpose.USB_LOSS_RECOVERY

    def test_active_usb_no_ip_falls_back_to_onboard_not_hotspot(self, watcher):
        # Regression fix (C2-WP1 review): an active USB with carrier but no IP
        # yields a ladder HOLD("usb_active_no_ip").  apply_client_failed must
        # still try the usable onboard before the hotspot (real gather+ladder).
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:50", is_usb=True)
        facts = _facts_for(watcher, [builtin, usb], usb)  # USB is the active client
        event = watcher.wifi_recovery.ClientFailed(ifname="wlan1", mac="bb:bb:bb:bb:bb:50",
                                     reason="no_ip", has_alt_path=True)
        with patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher.wifi_adoption, "_submit_client_activation", return_value=True) as ap, \
             patch.object(watcher.ADOPTION_CTX, "enter_setup_mode") as enter:
            acted = watcher.wifi_adoption.apply_client_failed(watcher.ADOPTION_CTX, event, facts)
        assert acted is True
        enter.assert_not_called()          # onboard fallback, NOT straight to hotspot
        ap.assert_called_once()
        applied = ap.call_args[0][1]
        assert applied.kind is watcher.wifi_policy.RecoveryKind.ACTIVATE_ONBOARD
        assert applied.ifname == "wlan0"

    def test_active_usb_no_ip_with_demoted_onboard_enters_hotspot(self, watcher):
        # The named delta under the real ladder: a no-IP-suppressed onboard is
        # gated out, so there is no usable onboard fallback -> hotspot.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:51", is_usb=True)
        watcher.RECOVERY_STATE.adapter_noip_ledgers[builtin.stable_id] = {
            "count": watcher.wifi_recovery.NOIP_STOP_AFTER, "retry_after": float("inf")}
        facts = _facts_for(watcher, [builtin, usb], usb)
        event = watcher.wifi_recovery.ClientFailed(ifname="wlan1", mac="bb:bb:bb:bb:bb:51",
                                     reason="no_ip", has_alt_path=True)
        with patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher.wifi_adoption, "_submit_client_activation", return_value=False), \
             patch.object(watcher.ADOPTION_CTX, "enter_setup_mode") as enter:
            acted = watcher.wifi_adoption.apply_client_failed(watcher.ADOPTION_CTX, event, facts)
        assert acted is True
        enter.assert_called_once()
        assert enter.call_args[0][0] is watcher.wifi_policy.HotspotPurpose.USB_LOSS_RECOVERY

    def test_wedged_usb_submits_reset_before_job_and_marks_episode(self, watcher):
        # RF-2: a debounced-wedged, resettable, budget-ok preferred USB gets
        # its one budgeted reset (RESET_USB) before onboard failover; the
        # episode is marked on submission so a failed job cannot loop the rung.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:70", is_usb=True)
        watcher.RECOVERY_STATE.dead_adapter_ifname = "wlan1"
        facts = _facts_for(watcher, [builtin, usb], None)
        event = watcher.wifi_recovery.ClientFailed(ifname="wlan1", mac=usb.permanent_mac,
                                     reason="dead_phy_quarantined", has_alt_path=True)
        with patch.object(watcher.wifi_net, "usb_sysfs_paths",
                          side_effect=lambda ifname: {"interface_id": "1-1"} if ifname == "wlan1" else None), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=True), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.ADOPTION_CTX, "submit_activation_job", return_value=True) as submit:
            acted = watcher.wifi_adoption.apply_client_failed(watcher.ADOPTION_CTX, event, facts)
        assert acted is True
        submit.assert_called_once()
        job = submit.call_args[0][0]
        assert job.reset_before is True
        assert job.ifname == "wlan1"
        assert usb.stable_id in watcher.RECOVERY_STATE.failover_reset_done

    def test_second_client_failed_same_episode_falls_through_to_onboard(self, watcher):
        # A second ClientFailed within the same offline episode finds the
        # reset already spent and goes straight to onboard.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:71", is_usb=True)
        watcher.RECOVERY_STATE.failover_reset_done.add(usb.stable_id)
        watcher.RECOVERY_STATE.dead_adapter_ifname = "wlan1"
        facts = _facts_for(watcher, [builtin, usb], None)
        event = watcher.wifi_recovery.ClientFailed(ifname="wlan1", mac=usb.permanent_mac,
                                     reason="dead_phy_quarantined", has_alt_path=True)
        with patch.object(watcher.wifi_net, "usb_sysfs_paths",
                          side_effect=lambda ifname: {"interface_id": "1-1"} if ifname == "wlan1" else None), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=True), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.ADOPTION_CTX, "submit_activation_job", return_value=True) as submit:
            acted = watcher.wifi_adoption.apply_client_failed(watcher.ADOPTION_CTX, event, facts)
        assert acted is True
        job = submit.call_args[0][0]
        assert job.reset_before is False
        assert job.ifname == "wlan0"

    def test_unplugged_usb_fails_over_immediately_no_reset_job(self, watcher):
        # An absent (unplugged) USB is not resettable (no sysfs paths) — the
        # ladder falls straight to onboard, no RESET_USB rung.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb_mac = "bb:bb:bb:bb:bb:72"
        watcher.ADOPTION_STATE.known_usb_macs.add(usb_mac)
        facts = _facts_for(watcher, [builtin], None)  # USB physically gone
        event = watcher.wifi_recovery.ClientFailed(ifname="wlan1", mac=usb_mac,
                                     reason="absent", has_alt_path=True)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.ADOPTION_CTX, "submit_activation_job", return_value=True) as submit:
            acted = watcher.wifi_adoption.apply_client_failed(watcher.ADOPTION_CTX, event, facts)
        assert acted is True
        job = submit.call_args[0][0]
        assert job.reset_before is False
        assert job.ifname == "wlan0"

    def test_apply_client_failed_onboard_success_sets_fallback(self, watcher):
        # WS1-WP3 async cycle: apply_client_failed submits an ACTIVATE_ONBOARD job
        # (USB also present); running the worker + applying the result sets
        # using_builtin_fallback, matching the old built-in fallback behaviour.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:09", is_usb=True)
        facts = _facts_for(watcher, [builtin, usb], None)
        event = watcher.wifi_recovery.ClientFailed(ifname="wlan1", mac="bb:bb:bb:bb:bb:09",
                                     reason="no_ip", has_alt_path=True)
        action = watcher.wifi_policy.RecoveryAction(watcher.wifi_policy.RecoveryKind.ACTIVATE_ONBOARD, ifname="wlan0")
        with patch.object(watcher.ADOPTION_CTX, "gather_recovery_facts"), \
             patch.object(watcher.wifi_policy, "next_recovery_action", return_value=action), \
             patch.object(watcher.wifi_activation, "_activate_committed_on", return_value=True), \
             patch.object(watcher.wifi_net, "discover_adapters", return_value=[builtin, usb]), \
             patch.object(watcher.wifi_net, "find_adapter_by_ifname", return_value=builtin), \
             patch.object(watcher.ACTIVATION_CTX, "leave_setup_mode"), \
             patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"):
            acted = watcher.wifi_adoption.apply_client_failed(watcher.ADOPTION_CTX, event, facts)     # submits the job
            assert acted is True
            assert watcher.STATE.transitioning is True
            job = watcher.wifi_activation._activation_job_queue.get_nowait()
            assert job.sets_builtin_fallback is True              # onboard + usb present
            result = watcher.wifi_activation._run_activation_job(watcher.ACTIVATION_CTX, job)             # _activate_committed_on -> True
            watcher.wifi_activation.apply_activation_result(watcher.ACTIVATION_CTX, result)               # loop applies the tail
        assert watcher.ADOPTION_STATE.using_builtin_fallback is True


class TestBudgetedResetRetry:
    """UP-4: one budgeted USB reset + retry when a pinned activation's scan
    implicated the adapter."""

    def _job(self, watcher, **kw):
        defaults = dict(epoch=watcher.wifi_activation._next_activation_epoch(watcher.ACTIVATION_CTX), kind="activate_committed",
                        ifname="wlan1")
        defaults.update(kw)
        return watcher.wifi_activation.ActivationJob(**defaults)

    def _set_pin(self, watcher, ifname="wlan1", bssid="AA:BB:CC:DD:EE:FF", signal=70):
        watcher.ADOPTION_STATE.last_bssid_pin = {"ifname": ifname, "bssid": bssid, "signal": signal, "at": 0.0}

    def _target(self, watcher, resettable=True):
        return watcher.wifi_recovery.TargetAdapter(
            ifname="wlan1", stable_id="m1", kind="usb_wifi", is_usb=True,
            is_builtin=False, present_in_nm=True, present_in_sysfs=True,
            resettable_usb=resettable)

    def test_weak_scan_failure_no_retry(self, watcher):
        # An absent/weak network (signal below the implicate floor) never resets.
        self._set_pin(watcher, signal=watcher.wifi_activation.PIN_IMPLICATE_SIGNAL - 1)
        job = self._job(watcher)
        with patch.object(watcher.wifi_activation, "_activate_committed_on", return_value=False), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind") as reset:
            r = watcher.wifi_activation._run_activation_job(watcher.ACTIVATION_CTX, job)
        assert r.ok is False
        reset.assert_not_called()

    def test_no_pin_no_retry(self, watcher):
        # No pin recorded at all (e.g. onboard target, or unpinned fallback).
        job = self._job(watcher)
        with patch.object(watcher.wifi_activation, "_activate_committed_on", return_value=False), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind") as reset:
            r = watcher.wifi_activation._run_activation_job(watcher.ACTIVATION_CTX, job)
        assert r.ok is False
        reset.assert_not_called()

    def test_budget_exhausted_no_retry(self, watcher):
        self._set_pin(watcher)
        job = self._job(watcher)
        with patch.object(watcher.wifi_activation, "_activate_committed_on", return_value=False), \
             patch.object(watcher.wifi_net, "discover_adapters", return_value=[]), \
             patch.object(watcher.wifi_recovery, "build_target_adapter",
                          return_value=self._target(watcher)), \
             patch.object(watcher.wifi_recovery, "adapter_reset_budget_exhausted", return_value=True), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind") as reset:
            r = watcher.wifi_activation._run_activation_job(watcher.ACTIVATION_CTX, job)
        assert r.ok is False
        reset.assert_not_called()

    def test_non_resettable_target_no_retry(self, watcher):
        self._set_pin(watcher)
        job = self._job(watcher)
        with patch.object(watcher.wifi_activation, "_activate_committed_on", return_value=False), \
             patch.object(watcher.wifi_net, "discover_adapters", return_value=[]), \
             patch.object(watcher.wifi_recovery, "build_target_adapter",
                          return_value=self._target(watcher, resettable=False)), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind") as reset:
            r = watcher.wifi_activation._run_activation_job(watcher.ACTIVATION_CTX, job)
        assert r.ok is False
        reset.assert_not_called()

    def test_reset_accounted_in_ledger(self, watcher):
        self._set_pin(watcher)
        job = self._job(watcher)
        with patch.object(watcher.wifi_activation, "_activate_committed_on", return_value=False), \
             patch.object(watcher.wifi_net, "discover_adapters", return_value=[]), \
             patch.object(watcher.wifi_recovery, "build_target_adapter",
                          return_value=self._target(watcher)), \
             patch.object(watcher.wifi_recovery, "adapter_reset_budget_exhausted", return_value=False), \
             patch.object(watcher.wifi_recovery, "record_adapter_reset") as record, \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind", return_value=True), \
             patch.object(watcher.wifi_recovery, "wait_for_interface_reappears", return_value=""):
            watcher.wifi_activation._run_activation_job(watcher.ACTIVATION_CTX, job)
        record.assert_called_once()

    def test_disappeared_after_reset_is_failure(self, watcher):
        self._set_pin(watcher)
        job = self._job(watcher)
        with patch.object(watcher.wifi_activation, "_activate_committed_on", return_value=False), \
             patch.object(watcher.wifi_net, "discover_adapters", return_value=[]), \
             patch.object(watcher.wifi_recovery, "build_target_adapter",
                          return_value=self._target(watcher)), \
             patch.object(watcher.wifi_recovery, "adapter_reset_budget_exhausted", return_value=False), \
             patch.object(watcher.wifi_recovery, "record_adapter_reset"), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind", return_value=True), \
             patch.object(watcher.wifi_recovery, "wait_for_interface_reappears", return_value=""):
            r = watcher.wifi_activation._run_activation_job(watcher.ACTIVATION_CTX, job)
        assert r.ok is False
        assert r.ifname == "wlan1"

    def test_exactly_one_retry_and_excludes_failed_bssid(self, watcher):
        self._set_pin(watcher, bssid="AA:BB:CC:DD:EE:FF")
        job = self._job(watcher)
        with patch.object(watcher.wifi_activation, "_activate_committed_on", return_value=False), \
             patch.object(watcher.wifi_net, "discover_adapters", return_value=[]), \
             patch.object(watcher.wifi_recovery, "build_target_adapter",
                          return_value=self._target(watcher)), \
             patch.object(watcher.wifi_recovery, "adapter_reset_budget_exhausted", return_value=False), \
             patch.object(watcher.wifi_recovery, "record_adapter_reset"), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind", return_value=True), \
             patch.object(watcher.wifi_recovery, "wait_for_interface_reappears", return_value="wlan1"), \
             patch.object(watcher.wifi_activation, "_activate_profile_on",
                          return_value=True) as retry_activate:
            r = watcher.wifi_activation._run_activation_job(watcher.ACTIVATION_CTX, job)
        retry_activate.assert_called_once()
        _, kwargs = retry_activate.call_args
        assert kwargs.get("exclude_bssid") == "AA:BB:CC:DD:EE:FF"
        assert r.ok is True
        assert r.ifname == "wlan1"


class TestAdapterFaultStatePersistence:
    """The no-IP + reset/quarantine ledgers survive a restart, with wall-clock
    timestamps translated back onto the monotonic clock and pruned by the
    rolling windows."""

    def _target(self, watcher, stable_id="usb-C"):
        return watcher.wifi_recovery.TargetAdapter(
            ifname="wlan1", stable_id=stable_id, kind="usb_wifi", is_usb=True,
            is_builtin=False, present_in_nm=True, present_in_sysfs=True,
            resettable_usb=True)

    def test_record_writes_the_file(self, watcher):
        wr = watcher.wifi_recovery
        wr.record_noip_failure(watcher, "usb-A", now=100.0)
        assert os.path.exists(watcher.ADAPTER_FAULT_STATE_PATH)

    def test_noip_suppression_survives_restart(self, watcher):
        wr = watcher.wifi_recovery
        for _ in range(wr.NOIP_STOP_AFTER):
            wr.record_noip_failure(watcher, "usb-A", now=100.0)
        # Simulate a restart: drop in-memory state, reload from disk.
        watcher.RECOVERY_STATE.adapter_noip_ledgers = {}
        watcher.RECOVERY_STATE.adapter_reset_ledgers = {}
        wr.load_adapter_fault_state(watcher)
        led = watcher.RECOVERY_STATE.adapter_noip_ledgers.get("usb-A")
        assert led is not None
        assert led["count"] == wr.NOIP_STOP_AFTER
        assert led["retry_after"] == float("inf")   # still suppressed after restart

    def test_finite_backoff_elapsed_during_downtime_not_suppressed(self, watcher):
        wr = watcher.wifi_recovery
        # One failure: finite backoff.  Persist happens with monotonic=1000 / wall=5000.
        with patch("time.monotonic", return_value=1000.0), \
             patch("time.time", return_value=5000.0):
            wr.record_noip_failure(watcher, "usb-B", now=1000.0)
        watcher.RECOVERY_STATE.adapter_noip_ledgers = {}
        # Reload far in the future (wall advanced well past the short backoff).
        with patch("time.monotonic", return_value=50.0), \
             patch("time.time", return_value=99999.0):
            wr.load_adapter_fault_state(watcher)
        led = watcher.RECOVERY_STATE.adapter_noip_ledgers.get("usb-B")
        assert led is not None and led["count"] == 1
        assert led["retry_after"] <= 50.0    # deadline is in the past -> not suppressed

    def test_reset_ledger_round_trips_and_prunes_by_window(self, watcher):
        wr = watcher.wifi_recovery
        target = self._target(watcher, "usb-C")
        with patch("time.monotonic", return_value=1000.0), \
             patch("time.time", return_value=5000.0):
            wr.record_adapter_reset(watcher, target, now=1000.0)
        assert watcher.RECOVERY_STATE.adapter_reset_ledgers["usb-C"]["total_resets"] == 1

        # Reload 1 hour later (wall): the reset is inside the 24h window -> kept.
        watcher.RECOVERY_STATE.adapter_reset_ledgers = {}
        with patch("time.monotonic", return_value=100.0), \
             patch("time.time", return_value=5000.0 + 3600):
            wr.load_adapter_fault_state(watcher)
        led = watcher.RECOVERY_STATE.adapter_reset_ledgers.get("usb-C")
        assert led is not None and led["total_resets"] == 1
        assert len(led["recent_resets"]) == 1

        # Reload 25 hours later (wall): the reset ages out of the rolling window,
        # but the total (quarantine accounting) survives.
        watcher.RECOVERY_STATE.adapter_reset_ledgers = {}
        with patch("time.monotonic", return_value=100.0), \
             patch("time.time", return_value=5000.0 + 25 * 3600):
            wr.load_adapter_fault_state(watcher)
        led = watcher.RECOVERY_STATE.adapter_reset_ledgers.get("usb-C")
        assert led is not None and led["total_resets"] == 1
        assert led["recent_resets"] == []

    def test_malformed_file_is_a_noop(self, watcher):
        with open(watcher.ADAPTER_FAULT_STATE_PATH, "w", encoding="utf-8") as f:
            f.write("{ not json")
        watcher.RECOVERY_STATE.adapter_noip_ledgers = {"pre": {"count": 3, "retry_after": 0.0}}
        watcher.wifi_recovery.load_adapter_fault_state(watcher)
        # Untouched: a malformed file must not wipe or corrupt live state.
        assert watcher.RECOVERY_STATE.adapter_noip_ledgers == {"pre": {"count": 3, "retry_after": 0.0}}

    def test_absent_file_is_a_noop(self, watcher):
        # Fresh temp path (never written).
        watcher.RECOVERY_STATE.adapter_noip_ledgers = {}
        watcher.wifi_recovery.load_adapter_fault_state(watcher)
        assert watcher.RECOVERY_STATE.adapter_noip_ledgers == {}

    def test_failover_reset_done_does_not_persist(self, watcher):
        """RF-1: failover_reset_done is a per-episode marker (an offline
        episode never spans a reboot), so it must not round-trip through
        persist/load like the reset/no-IP ledgers do."""
        wr = watcher.wifi_recovery
        target = self._target(watcher, "usb-D")
        wr.record_adapter_reset(watcher, target, now=1000.0)
        watcher.RECOVERY_STATE.failover_reset_done.add("usb-D")
        assert os.path.exists(watcher.ADAPTER_FAULT_STATE_PATH)
        with open(watcher.ADAPTER_FAULT_STATE_PATH, "r", encoding="utf-8") as f:
            on_disk = json.load(f)
        assert "failover_reset_done" not in on_disk

        # Simulate a restart: drop in-memory state (including the episode
        # marker) and reload from disk.
        watcher.RECOVERY_STATE.adapter_noip_ledgers = {}
        watcher.RECOVERY_STATE.adapter_reset_ledgers = {}
        watcher.RECOVERY_STATE.failover_reset_done = set()
        wr.load_adapter_fault_state(watcher)
        # The reset ledger (which the budget check reads) survives restart...
        assert watcher.RECOVERY_STATE.adapter_reset_ledgers.get("usb-D") is not None
        # ...but the episode-scoped spend marker does not: load_adapter_fault_state
        # never touches it, so it stays whatever the caller set it to.
        assert watcher.RECOVERY_STATE.failover_reset_done == set()


class TestManualAdapterControl:
    """Manual clear / disable / enable adapter control actions."""

    def _pre(self, watcher):
        return watcher.wifi_loop.PreFactsContext(now=0.0, boot_time=0.0, avahi_ok=False)

    def test_disable_and_enable_round_trip(self, watcher):
        wr = watcher.wifi_recovery
        wr.disable_adapter(watcher, "usb-X")
        assert "usb-X" in watcher.RECOVERY_STATE.disabled_adapters
        assert wr.adapter_disabled(watcher, "usb-X") is True
        wr.enable_adapter(watcher, "usb-X")
        assert "usb-X" not in watcher.RECOVERY_STATE.disabled_adapters

    def test_disabled_adapters_persist(self, watcher):
        wr = watcher.wifi_recovery
        wr.disable_adapter(watcher, "usb-Y")
        watcher.RECOVERY_STATE.disabled_adapters = set()
        wr.load_adapter_fault_state(watcher)
        assert "usb-Y" in watcher.RECOVERY_STATE.disabled_adapters

    def test_clear_adapter_clears_both_ledgers(self, watcher):
        wr = watcher.wifi_recovery
        wr.record_noip_failure(watcher, "usb-Z", now=100.0)
        watcher.RECOVERY_STATE.adapter_reset_ledgers["usb-Z"] = {
            "recent_resets": [1.0], "total_resets": 3, "quarantined_until": None}
        wr.clear_adapter_fault_state(watcher, "usb-Z")
        assert "usb-Z" not in watcher.RECOVERY_STATE.adapter_noip_ledgers
        assert "usb-Z" not in watcher.RECOVERY_STATE.adapter_reset_ledgers

    def test_disabled_usb_not_offered_as_client(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "dc:62:79:91:4d:d6", is_usb=True)
        watcher.wifi_recovery.disable_adapter(watcher, usb.stable_id)
        facts = _facts_for(watcher, [builtin, usb], None)
        with patch.object(watcher, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=False):
            rf = watcher.gather_recovery_facts(facts)
        assert rf.preferred_usb_ifname == ""   # disabled USB is skipped

    def test_disabled_candidate_not_adopted(self, watcher):
        builtin, usb = self._builtin_and_usb(watcher)
        watcher.wifi_recovery.disable_adapter(watcher, usb.stable_id)
        with patch.object(watcher.wifi_adoption, "resolve_active_client", return_value=builtin), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher.wifi_activation, "_activate_committed_on", return_value=True) as act:
            r = watcher.wifi_adoption.handle_runtime_usb_adoption(watcher.ADOPTION_CTX, [builtin, usb], wired_connected=False)
        assert r is False
        act.assert_not_called()

    def _builtin_and_usb(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "dc:62:79:91:4d:d6", is_usb=True)
        return builtin, usb

    def test_disabled_target_not_reset(self, watcher):
        usb = _adapter(watcher, "wlan0", "dc:62:79:91:4d:d6", is_usb=True)
        watcher.wifi_recovery.disable_adapter(watcher, usb.stable_id)
        with patch.object(watcher.wifi_recovery, "resolve_target_client",
                          return_value=watcher.wifi_recovery.TargetAdapter(
                              ifname="wlan0", stable_id=usb.stable_id, kind="usb_wifi",
                              is_usb=True, is_builtin=False, present_in_nm=True,
                              present_in_sysfs=True, resettable_usb=True)), \
             patch.object(watcher.wifi_recovery, "update_dead_adapter_detection", return_value=True), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind") as reset:
            handled = watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb], False)
        assert handled is False
        reset.assert_not_called()

    def test_process_control_action_disable(self, watcher):
        watcher.process_control_action("disable_adapter", {"adapter": "usb-Q"})
        assert "usb-Q" in watcher.RECOVERY_STATE.disabled_adapters
        assert watcher.CONTROL_STATE.last_control_result == "ok"

    def test_process_control_action_clear(self, watcher):
        watcher.RECOVERY_STATE.adapter_noip_ledgers["usb-R"] = {"count": 2, "retry_after": 0.0}
        watcher.process_control_action("clear_adapter", {"adapter": "usb-R"})
        assert "usb-R" not in watcher.RECOVERY_STATE.adapter_noip_ledgers
        assert watcher.CONTROL_STATE.last_control_result == "ok"

    def test_adapter_actions_are_non_disruptive(self, watcher):
        # A disable action while an activation is in flight is applied immediately
        # (not deferred) and does not own the pass.
        watcher.STATE.transitioning = True
        watcher.CONTROL_STATE.pending_control_action = "disable_adapter"
        watcher.CONTROL_STATE.pending_control_params = {"adapter": "usb-N"}
        watcher.control_action_event.set()
        v = watcher.wifi_loop.step_control_action(watcher.LOOP_CTX, self._pre(watcher))
        assert v is watcher.Verdict.CONTINUE          # never owns the pass
        assert "usb-N" in watcher.RECOVERY_STATE.disabled_adapters   # applied, not deferred
        assert not watcher.control_action_event.is_set()


class TestNoIpHoldbackReset:
    """One budgeted USB reset when an idle no-IP-held spare reaches the final
    hold-back (the dead-PHY ladder only ever resets the active client)."""

    def _held_usb(self, watcher, ifname="wlan1", mac="dc:62:79:91:4d:d6"):
        usb = _adapter(watcher, ifname, mac, is_usb=True)
        wr = watcher.wifi_recovery
        for _ in range(wr.NOIP_STOP_AFTER):
            wr.record_noip_failure(watcher, usb.stable_id, now=100.0)
        return usb

    def _target(self, watcher, usb, resettable=True):
        return watcher.wifi_recovery.TargetAdapter(
            ifname=usb.ifname, stable_id=usb.stable_id, kind="usb_wifi", is_usb=True,
            is_builtin=False, present_in_nm=True, present_in_sysfs=True,
            resettable_usb=resettable)

    def test_spends_one_reset_and_clears_suppression(self, watcher):
        wr = watcher.wifi_recovery
        usb = self._held_usb(watcher)
        with patch.object(wr, "build_target_adapter", return_value=self._target(watcher, usb)), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind") as reset:
            r = wr.maybe_reset_noip_held_usb(watcher, [usb], now=200.0)
        assert r is True
        reset.assert_called_once_with(usb.ifname)
        assert usb.stable_id in watcher.RECOVERY_STATE.noip_holdback_reset_done
        assert usb.stable_id not in watcher.RECOVERY_STATE.adapter_noip_ledgers   # suppression cleared
        assert watcher.RECOVERY_STATE.adapter_reset_ledgers[usb.stable_id]["total_resets"] == 1

    def test_only_one_reset_per_episode(self, watcher):
        wr = watcher.wifi_recovery
        usb = self._held_usb(watcher)
        watcher.RECOVERY_STATE.noip_holdback_reset_done.add(usb.stable_id)
        with patch.object(wr, "build_target_adapter", return_value=self._target(watcher, usb)), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind") as reset:
            r = wr.maybe_reset_noip_held_usb(watcher, [usb], now=200.0)
        assert r is False
        reset.assert_not_called()

    def test_no_reset_before_final_holdback(self, watcher):
        wr = watcher.wifi_recovery
        usb = _adapter(watcher, "wlan1", "dc:62:79:91:4d:d6", is_usb=True)
        wr.record_noip_failure(watcher, usb.stable_id, now=100.0)  # count 1 < NOIP_STOP_AFTER
        with patch.object(wr, "build_target_adapter", return_value=self._target(watcher, usb)), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind") as reset:
            r = wr.maybe_reset_noip_held_usb(watcher, [usb], now=200.0)
        assert r is False
        reset.assert_not_called()

    def test_no_reset_when_budget_exhausted(self, watcher):
        wr = watcher.wifi_recovery
        usb = self._held_usb(watcher)
        with patch.object(wr, "build_target_adapter", return_value=self._target(watcher, usb)), \
             patch.object(wr, "adapter_reset_budget_exhausted", return_value=True), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind") as reset:
            r = wr.maybe_reset_noip_held_usb(watcher, [usb], now=200.0)
        assert r is False
        reset.assert_not_called()

    def test_disabled_adapter_not_reset(self, watcher):
        wr = watcher.wifi_recovery
        usb = self._held_usb(watcher)
        wr.disable_adapter(watcher, usb.stable_id)
        with patch.object(wr, "build_target_adapter", return_value=self._target(watcher, usb)), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind") as reset:
            r = wr.maybe_reset_noip_held_usb(watcher, [usb], now=200.0)
        assert r is False
        reset.assert_not_called()

    def test_success_clears_holdback_flag(self, watcher):
        usb = _adapter(watcher, "wlan1", "dc:62:79:91:4d:d6", is_usb=True)
        watcher.RECOVERY_STATE.noip_holdback_reset_done.add(usb.stable_id)
        watcher.wifi_activation._set_active_client(watcher.ACTIVATION_CTX, usb)
        assert usb.stable_id not in watcher.RECOVERY_STATE.noip_holdback_reset_done


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
        with patch.object(watcher.RECOVERY_CTX, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=False):
            rf = watcher.wifi_recovery.adapter_recovery_facts(watcher.RECOVERY_CTX, builtin, 1000.0)
        assert rf.ifname == "wlan0"
        assert rf.is_builtin and not rf.is_usb
        assert rf.healthy is True and rf.carrier is True
        assert rf.quarantined is False and rf.budget_exhausted is False
        assert rf.wedged is False

    def test_adapter_recovery_facts_wedged_true_iff_declared_dead(self, watcher):
        # wedged is derived from the exact same source as the status
        # snapshot's dead_phy state: RECOVERY_STATE.dead_adapter_ifname.
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:80", is_usb=True)
        watcher.RECOVERY_STATE.dead_adapter_ifname = "wlan1"
        with patch.object(watcher.RECOVERY_CTX, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=True):
            rf = watcher.wifi_recovery.adapter_recovery_facts(watcher.RECOVERY_CTX, usb, 1000.0)
        assert rf.wedged is True

    def test_adapter_recovery_facts_stable_id_alone_is_not_wedged(self, watcher):
        # A populated dead_adapter_stable_id with dead_adapter_ifname still
        # empty means the debounce is merely in progress, not declared dead.
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:81", is_usb=True)
        watcher.RECOVERY_STATE.dead_adapter_stable_id = usb.stable_id
        watcher.RECOVERY_STATE.dead_adapter_ifname = ""
        with patch.object(watcher.RECOVERY_CTX, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=True):
            rf = watcher.wifi_recovery.adapter_recovery_facts(watcher.RECOVERY_CTX, usb, 1000.0)
        assert rf.wedged is False

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
        watcher.RECOVERY_STATE.adapter_reset_ledgers[usb.stable_id] = {
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
        watcher.RECOVERY_STATE.adapter_noip_ledgers[usb.stable_id] = {
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
        watcher.RECOVERY_STATE.adapter_noip_ledgers[builtin.stable_id] = {
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
        watcher.RECOVERY_STATE.adapter_reset_ledgers[builtin.stable_id] = {
            "quarantined_until": 1e12, "recent_resets": [], "total_resets": 0,
        }
        facts = self._facts(watcher, [builtin])
        with patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=True):
            rec = watcher.gather_recovery_facts(facts)
        assert rec.onboard_ifname == ""


class TestResetBudgetStableIdParity:
    """RF-1: the stable-id-keyed budget check
    (``adapter_reset_budget_exhausted_for_stable_id``) must agree exactly
    with the TargetAdapter-taking form it now delegates to, across a matrix
    of ledger states (empty, within budget, per-window exhausted, total
    exhausted, unknown id)."""

    def _target(self, watcher, stable_id="usb-Z"):
        return watcher.wifi_recovery.TargetAdapter(
            ifname="wlan1", stable_id=stable_id, kind="usb_wifi", is_usb=True,
            is_builtin=False, present_in_nm=True, present_in_sysfs=True,
            resettable_usb=True)

    def test_matches_across_ledger_states(self, watcher):
        wr = watcher.wifi_recovery
        now = 1000.0

        # Unknown id: neither budget is exhausted.
        target_unknown = self._target(watcher, "usb-unknown")
        assert (wr.adapter_reset_budget_exhausted(watcher, target_unknown, now)
                == wr.adapter_reset_budget_exhausted_for_stable_id(
                    watcher, target_unknown.stable_id, now))

        # Within budget (one recent reset, well under the per-window cap).
        watcher.RECOVERY_STATE.adapter_reset_ledgers["usb-within"] = {
            "recent_resets": [now - 10], "total_resets": 1, "quarantined_until": None,
        }
        target_within = self._target(watcher, "usb-within")
        assert wr.adapter_reset_budget_exhausted(watcher, target_within, now) is False
        assert (wr.adapter_reset_budget_exhausted(watcher, target_within, now)
                == wr.adapter_reset_budget_exhausted_for_stable_id(
                    watcher, target_within.stable_id, now))

        # Per-window budget exhausted.
        watcher.RECOVERY_STATE.adapter_reset_ledgers["usb-window"] = {
            "recent_resets": [now - 10] * watcher.USB_MAX_RESETS_PER_WINDOW,
            "total_resets": watcher.USB_MAX_RESETS_PER_WINDOW, "quarantined_until": None,
        }
        target_window = self._target(watcher, "usb-window")
        assert wr.adapter_reset_budget_exhausted(watcher, target_window, now) is True
        assert (wr.adapter_reset_budget_exhausted(watcher, target_window, now)
                == wr.adapter_reset_budget_exhausted_for_stable_id(
                    watcher, target_window.stable_id, now))

        # Total budget exhausted (recent resets pruned out of the window).
        watcher.RECOVERY_STATE.adapter_reset_ledgers["usb-total"] = {
            "recent_resets": [], "total_resets": watcher.USB_MAX_RESETS_TOTAL,
            "quarantined_until": None,
        }
        target_total = self._target(watcher, "usb-total")
        assert wr.adapter_reset_budget_exhausted(watcher, target_total, now) is True
        assert (wr.adapter_reset_budget_exhausted(watcher, target_total, now)
                == wr.adapter_reset_budget_exhausted_for_stable_id(
                    watcher, target_total.stable_id, now))

    def test_none_target_and_empty_stable_id_agree(self, watcher):
        wr = watcher.wifi_recovery
        assert (wr.adapter_reset_budget_exhausted(watcher, None, 1000.0)
                == wr.adapter_reset_budget_exhausted_for_stable_id(watcher, None, 1000.0)
                == wr.adapter_reset_budget_exhausted_for_stable_id(watcher, "", 1000.0)
                is False)


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
            purpose=watcher.wifi_policy.HotspotPurpose.BOOT_RECOVERY, entered_at=0.0)

    def test_dead_second_radio_falls_through_to_onboard_rejoin(self, watcher):
        # Field-log shape: AP on onboard wlan0, USB wlan1 declared wedged
        # (debounced dead-PHY verdict). The wedged, non-resettable USB must
        # NOT be chosen; the ladder selects the onboard drop-AP rejoin (exit
        # edge) instead of probing the dead USB forever.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "dc:62:79:91:4d:d6", is_usb=True)
        self._in_hotspot(watcher)
        watcher.RECOVERY_STATE.dead_adapter_ifname = "wlan1"
        facts = _facts_for(watcher, [builtin, usb], None)
        with patch.object(watcher.wifi_net, "read_link_down",
                          side_effect=lambda ifn: ifn == "wlan1"), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.wifi_adoption, "_saved_ssid_visible", return_value=True), \
             patch.object(watcher.ADOPTION_CTX, "hotspot_station_count", return_value=0), \
             patch.object(watcher.wifi_adoption, "_submit_client_activation", return_value=True) as apply:
            watcher.wifi_adoption._attempt_recovery_reconnect(watcher.ADOPTION_CTX, facts)
        apply.assert_called_once()
        action = apply.call_args[0][1]
        assert action.kind is watcher.wifi_policy.RecoveryKind.ACTIVATE_ONBOARD
        assert action.ifname == "wlan0"
        assert action.drop_hotspot is True

    def test_quarantined_second_radio_falls_through_to_onboard(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "dc:62:79:91:4d:d6", is_usb=True)
        watcher.RECOVERY_STATE.adapter_reset_ledgers[usb.stable_id] = {
            "recent_resets": [], "total_resets": 5, "quarantined_until": 1000.0 + 3600,
        }
        self._in_hotspot(watcher)
        facts = _facts_for(watcher, [builtin, usb], None)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.wifi_adoption, "_saved_ssid_visible", return_value=True), \
             patch.object(watcher.ADOPTION_CTX, "hotspot_station_count", return_value=0), \
             patch.object(watcher.wifi_adoption, "_submit_client_activation", return_value=True) as apply:
            watcher.wifi_adoption._attempt_recovery_reconnect(watcher.ADOPTION_CTX, facts)
        apply.assert_called_once()
        action = apply.call_args[0][1]
        assert action.kind is watcher.wifi_policy.RecoveryKind.ACTIVATE_ONBOARD
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
             patch.object(watcher.wifi_adoption, "_saved_ssid_visible") as vis, \
             patch.object(watcher.wifi_adoption, "_submit_client_activation", return_value=True) as apply:
            watcher.wifi_adoption._attempt_recovery_reconnect(watcher.ADOPTION_CTX, facts)
        apply.assert_called_once()
        action = apply.call_args[0][1]
        assert action.kind is watcher.wifi_policy.RecoveryKind.ACTIVATE_USB
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
             patch.object(watcher.wifi_adoption, "_saved_ssid_visible") as vis, \
             patch.object(watcher.wifi_adoption, "_submit_client_activation") as apply:
            watcher.wifi_adoption._attempt_recovery_reconnect(watcher.ADOPTION_CTX, facts)
        apply.assert_not_called()
        vis.assert_not_called()


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
            purpose=watcher.wifi_policy.HotspotPurpose.BOOT_RECOVERY, entered_at=0.0)

    def test_second_radio_probes_without_dropping_ap(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:01", is_usb=True)
        self._in_hotspot(watcher)
        facts = _facts_for(watcher, [builtin, usb], None)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.wifi_adoption, "_saved_ssid_visible") as vis, \
             patch.object(watcher.wifi_adoption, "_submit_client_activation", return_value=True) as apply:
            watcher.wifi_adoption._attempt_recovery_reconnect(watcher.ADOPTION_CTX, facts)
        apply.assert_called_once()
        assert apply.call_args[0][1].drop_hotspot is False
        vis.assert_not_called()   # no AP drop -> no scan-gate

    def test_join_interval_bounds_second_radio_probe(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:01", is_usb=True)
        self._in_hotspot(watcher)
        watcher.STATE.last_reconnect_attempt = 1000.0
        facts = _facts_for(watcher, [builtin, usb], None, now=1000.0 + 30)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.wifi_adoption, "_submit_client_activation") as apply:
            watcher.wifi_adoption._attempt_recovery_reconnect(watcher.ADOPTION_CTX, facts)
        apply.assert_not_called()

    def test_single_radio_scan_interval_gates_scan(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        self._in_hotspot(watcher)
        watcher.STATE.last_recovery_scan = 1000.0
        facts = _facts_for(watcher, [builtin], None, now=1000.0 + 5)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.wifi_adoption, "_saved_ssid_visible") as vis, \
             patch.object(watcher.wifi_adoption, "_submit_client_activation") as apply:
            # Within RECOVERY_SCAN_INTERVAL of the last scan: do not scan or join.
            watcher.wifi_adoption._attempt_recovery_reconnect(watcher.ADOPTION_CTX, facts)
        vis.assert_not_called()
        apply.assert_not_called()

    def test_single_radio_ssid_absent_keeps_ap(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        self._in_hotspot(watcher)
        facts = _facts_for(watcher, [builtin], None, now=1000.0)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.wifi_adoption, "_saved_ssid_visible", return_value=False), \
             patch.object(watcher.wifi_adoption, "_submit_client_activation") as apply:
            watcher.wifi_adoption._attempt_recovery_reconnect(watcher.ADOPTION_CTX, facts)
        apply.assert_not_called()
        assert watcher.STATE.last_recovery_scan == 1000.0

    def test_single_radio_ssid_present_drops_ap_and_joins(self, watcher):
        # Zero stations on the AP (headless recovery): auto-rejoin proceeds.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        self._in_hotspot(watcher)
        facts = _facts_for(watcher, [builtin], None, now=1000.0)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.wifi_adoption, "_saved_ssid_visible", return_value=True), \
             patch.object(watcher.ADOPTION_CTX, "hotspot_station_count", return_value=0), \
             patch.object(watcher.wifi_adoption, "_submit_client_activation", return_value=True) as apply:
            watcher.wifi_adoption._attempt_recovery_reconnect(watcher.ADOPTION_CTX, facts)
        apply.assert_called_once()
        action = apply.call_args[0][1]
        assert action.kind is watcher.wifi_policy.RecoveryKind.ACTIVATE_ONBOARD
        assert action.drop_hotspot is True
        assert watcher.STATE.saved_ssid_visible is False

    def test_single_radio_ssid_present_with_station_offers_modal(self, watcher):
        # A client is on the setup AP: do NOT yank it; record the rejoin prompt.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        self._in_hotspot(watcher)
        facts = _facts_for(watcher, [builtin], None, now=1000.0)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.wifi_adoption, "_saved_ssid_visible", return_value=True), \
             patch.object(watcher.wifi_adoption, "_saved_network_ssid", return_value="MyHomeWiFi"), \
             patch.object(watcher.ADOPTION_CTX, "hotspot_station_count", return_value=1), \
             patch.object(watcher.wifi_adoption, "_submit_client_activation") as apply:
            watcher.wifi_adoption._attempt_recovery_reconnect(watcher.ADOPTION_CTX, facts)
        apply.assert_not_called()          # AP not dropped
        assert watcher.STATE.saved_ssid_visible is True
        assert watcher.STATE.saved_ssid_name == "MyHomeWiFi"

    def test_single_radio_unknown_station_count_offers_modal(self, watcher):
        # Unknown station count (iw absent): behave as if a client is associated.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        self._in_hotspot(watcher)
        facts = _facts_for(watcher, [builtin], None, now=1000.0)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.wifi_adoption, "_saved_ssid_visible", return_value=True), \
             patch.object(watcher.wifi_adoption, "_saved_network_ssid", return_value="MyHomeWiFi"), \
             patch.object(watcher.ADOPTION_CTX, "hotspot_station_count", return_value=None), \
             patch.object(watcher.wifi_adoption, "_submit_client_activation") as apply:
            watcher.wifi_adoption._attempt_recovery_reconnect(watcher.ADOPTION_CTX, facts)
        apply.assert_not_called()
        assert watcher.STATE.saved_ssid_visible is True

    def test_rejoin_dismissed_stops_probing(self, watcher):
        # After the user chooses "continue setup", the probe short-circuits.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        self._in_hotspot(watcher)
        watcher.STATE.rejoin_dismissed = True
        facts = _facts_for(watcher, [builtin], None, now=1000.0)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.wifi_adoption, "_saved_ssid_visible") as vis, \
             patch.object(watcher.ADOPTION_CTX, "hotspot_station_count") as stations, \
             patch.object(watcher.wifi_adoption, "_submit_client_activation") as apply:
            watcher.wifi_adoption._attempt_recovery_reconnect(watcher.ADOPTION_CTX, facts)
        vis.assert_not_called()
        stations.assert_not_called()
        apply.assert_not_called()

    def test_saved_ssid_visible_uses_scan(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        with patch.object(watcher.wifi_adoption, "_saved_network_ssid", return_value="MyHomeWiFi"), \
             patch.object(watcher.wifi_net, "scan_adapter", return_value={"MyHomeWiFi": -50}):
            assert watcher.wifi_adoption._saved_ssid_visible(watcher.ADOPTION_CTX, builtin) is True
        with patch.object(watcher.wifi_adoption, "_saved_network_ssid", return_value="MyHomeWiFi"), \
             patch.object(watcher.wifi_net, "scan_adapter", return_value={"Other": -50}):
            assert watcher.wifi_adoption._saved_ssid_visible(watcher.ADOPTION_CTX, builtin) is False
