"""Dead-PHY detection, target resolution, reset budgets, the reboot guard,
and end-to-end dead-PHY recovery sequences."""
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
from _wifi_fixtures import _adapter, _patch_dead_phy_facts, _ledger, _spend_window_budget, tmp_guard, _run_monitor_once, _Clock


class TestDeadAdapterTargetResolution:
    def test_resolves_sole_usb_as_startup_target(self, watcher):
        usb = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:10", is_usb=True)
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"]):
            target = watcher.wifi_recovery.resolve_target_client(watcher, [usb])
        assert target is not None
        assert target.ifname == "wlan0"
        assert target.is_usb and target.resettable_usb

    def test_resolves_from_active_mac_via_sysfs_when_nm_missing(self, watcher):
        # NM reports no adapters, but the recorded MAC maps to a sysfs netdev.
        watcher.STATE.active_client_mac = "aa:bb:cc:00:00:10"
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   sysfs_mac="aa:bb:cc:00:00:10"):
            target = watcher.wifi_recovery.resolve_target_client(watcher, [])
        assert target is not None
        assert target.ifname == "wlan0"
        assert target.present_in_nm is False
        assert target.present_in_sysfs is True
        assert target.resettable_usb is True

    def test_falls_back_to_ap_ifname_literal(self, watcher):
        with _patch_dead_phy_facts(watcher, sysfs_names=[]):
            target = watcher.wifi_recovery.resolve_target_client(watcher, [])
        assert target is not None
        assert target.ifname == watcher.AP_IFNAME


class TestDeadAdapterDetection:
    def _usb(self, watcher):
        return _adapter(watcher, "wlan0", "aa:bb:cc:00:00:10", is_usb=True)

    def test_debounce_declares_dead_and_sets_since(self, watcher):
        usb = self._usb(watcher)
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=True, healthy=False):
            target = watcher.wifi_recovery.resolve_target_client(watcher, [usb])
            assert watcher.wifi_recovery.update_dead_adapter_detection(watcher, [usb], target) is False
            assert watcher.RECOVERY_STATE.dead_adapter_checks == 1
            assert watcher.RECOVERY_STATE.dead_adapter_ifname == ""
            assert watcher.wifi_recovery.update_dead_adapter_detection(watcher, [usb], target) is True
        assert watcher.RECOVERY_STATE.dead_adapter_ifname == "wlan0"
        assert watcher.RECOVERY_STATE.dead_adapter_since is not None
        assert watcher.RECOVERY_STATE.dead_adapter_first_failure is not None

    def test_healthy_pass_clears_active_fields(self, watcher):
        usb = self._usb(watcher)
        watcher.RECOVERY_STATE.dead_adapter_ifname = "wlan0"
        watcher.RECOVERY_STATE.dead_adapter_checks = 3
        watcher.RECOVERY_STATE.dead_adapter_since = 100.0
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=False, healthy=True):
            target = watcher.wifi_recovery.resolve_target_client(watcher, [usb])
            assert watcher.wifi_recovery.update_dead_adapter_detection(watcher, [usb], target) is False
        assert watcher.RECOVERY_STATE.dead_adapter_ifname == ""
        assert watcher.RECOVERY_STATE.dead_adapter_checks == 0
        assert watcher.RECOVERY_STATE.dead_adapter_since is None

    def test_healthy_decay_does_not_erase_accounting_ledger(self, watcher):
        usb = self._usb(watcher)
        watcher.RECOVERY_STATE.dead_adapter_ifname = "wlan0"
        watcher.RECOVERY_STATE.dead_adapter_checks = 3
        watcher.RECOVERY_STATE.dead_adapter_healthy_since = 100.0
        watcher.RECOVERY_STATE.adapter_reset_ledgers[usb.stable_id] = {
            "recent_resets": [100.0],
            "total_resets": 1,
            "quarantined_until": None,
        }
        now = 100.0 + watcher.DEAD_ADAPTER_HEALTHY_DECAY + 1.0
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=False, healthy=True), \
             patch("time.monotonic", return_value=now):
            target = watcher.wifi_recovery.resolve_target_client(watcher, [usb])
            assert watcher.wifi_recovery.update_dead_adapter_detection(watcher, [usb], target) is False
        assert watcher.RECOVERY_STATE.dead_adapter_ifname == ""
        assert _ledger(watcher, usb.stable_id)["recent_resets"] == [100.0]

    def test_identity_change_resets_debounce(self, watcher):
        usb = self._usb(watcher)
        watcher.RECOVERY_STATE.dead_adapter_checks = 1
        watcher.RECOVERY_STATE.dead_adapter_stable_id = "old:identity:value:00:00:00"
        watcher.RECOVERY_STATE.adapter_reset_ledgers["old:identity:value:00:00:00"] = {
            "recent_resets": [10.0],
            "total_resets": 4,
            "quarantined_until": None,
        }
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=True, healthy=False):
            target = watcher.wifi_recovery.resolve_target_client(watcher, [usb])
            watcher.wifi_recovery.update_dead_adapter_detection(watcher, [usb], target)
        # Active tracking resets on identity change, but the old ledger is isolated.
        assert watcher.RECOVERY_STATE.dead_adapter_checks == 1
        assert _ledger(watcher, "old:identity:value:00:00:00")["total_resets"] == 4

    def test_none_target_clears_state(self, watcher):
        watcher.RECOVERY_STATE.dead_adapter_ifname = "wlan0"
        watcher.RECOVERY_STATE.dead_adapter_checks = 2
        assert watcher.wifi_recovery.update_dead_adapter_detection(watcher, [], None) is False
        assert watcher.RECOVERY_STATE.dead_adapter_ifname == ""
        assert watcher.RECOVERY_STATE.dead_adapter_checks == 0


class TestResetBudget:
    def _target(self, watcher):
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"]):
            return watcher.wifi_recovery.resolve_target_client(watcher, 
                [_adapter(watcher, "wlan0", "aa:bb:cc:00:00:10", is_usb=True)])

    def test_exhausted_after_per_window_budget(self, watcher):
        t = self._target(watcher)
        now = 1000.0
        assert watcher.wifi_recovery.adapter_reset_budget_exhausted(watcher, t, now) is False
        watcher.wifi_recovery.record_adapter_reset(watcher, t, now)
        watcher.wifi_recovery.record_adapter_reset(watcher, t, now)
        assert watcher.wifi_recovery.adapter_reset_budget_exhausted(watcher, t, now) is True

    def test_window_prunes_old_resets_but_total_persists(self, watcher):
        t = self._target(watcher)
        watcher.wifi_recovery.record_adapter_reset(watcher, t, 0.0)
        watcher.wifi_recovery.record_adapter_reset(watcher, t, 0.0)
        later = watcher.USB_RESET_WINDOW + 1.0
        # Per-window budget recovered, total still 2 (< total cap) -> not exhausted.
        assert watcher.wifi_recovery.adapter_reset_budget_exhausted(watcher, t, later) is False
        assert _ledger(watcher, t.stable_id)["total_resets"] == 2

    def test_total_cap_exhausts(self, watcher):
        t = self._target(watcher)
        # Spread resets across windows so per-window never trips, but total does.
        for i in range(watcher.USB_MAX_RESETS_TOTAL):
            watcher.wifi_recovery.record_adapter_reset(watcher, t, i * (watcher.USB_RESET_WINDOW + 1.0))
        last = (watcher.USB_MAX_RESETS_TOTAL) * (watcher.USB_RESET_WINDOW + 1.0)
        assert watcher.wifi_recovery.adapter_reset_budget_exhausted(watcher, t, last) is True

    def test_resets_are_per_adapter_identity(self, watcher):
        a = self._target(watcher)
        b = watcher.wifi_recovery.TargetAdapter(
            ifname="wlan1",
            stable_id="aa:bb:cc:dd:ee:ff",
            kind="usb_wifi",
            is_usb=True,
            is_builtin=False,
            present_in_nm=True,
            present_in_sysfs=True,
            resettable_usb=True,
        )
        watcher.wifi_recovery.record_adapter_reset(watcher, a, 100.0)
        watcher.wifi_recovery.record_adapter_reset(watcher, a, 101.0)
        assert watcher.wifi_recovery.adapter_reset_budget_exhausted(watcher, a, 101.0) is True
        assert watcher.wifi_recovery.adapter_reset_budget_exhausted(watcher, b, 101.0) is False
        assert _ledger(watcher, a.stable_id)["recent_resets"] == [100.0, 101.0]
        assert _ledger(watcher, b.stable_id)["recent_resets"] == []

    def test_replacement_with_different_stable_mac_gets_separate_ledger(self, watcher):
        a = self._target(watcher)
        replacement = watcher.wifi_recovery.TargetAdapter(
            ifname=a.ifname,
            stable_id="aa:bb:cc:00:00:99",
            kind=a.kind,
            is_usb=a.is_usb,
            is_builtin=a.is_builtin,
            present_in_nm=a.present_in_nm,
            present_in_sysfs=a.present_in_sysfs,
            resettable_usb=a.resettable_usb,
        )
        watcher.wifi_recovery.record_adapter_reset(watcher, a, 100.0)
        watcher.wifi_recovery.record_adapter_reset(watcher, replacement, 200.0)
        assert set(watcher.RECOVERY_STATE.adapter_reset_ledgers) == {a.stable_id, replacement.stable_id}
        assert _ledger(watcher, a.stable_id)["recent_resets"] == [100.0]
        assert _ledger(watcher, replacement.stable_id)["recent_resets"] == [200.0]


class TestDeadPhyRebootGuard:
    def test_permits_until_cap_then_suppresses(self, watcher, tmp_path):
        stamp = str(tmp_path / "guard.json")
        with patch.object(watcher, "DEAD_ADAPTER_REBOOT_STAMP", stamp):
            now = 1_000_000.0
            assert watcher.wifi_recovery.dead_phy_reboot_guard_permits(watcher, now) is True
            for _ in range(watcher.DEAD_ADAPTER_MAX_REBOOTS_PER_WINDOW):
                assert watcher.wifi_recovery.dead_phy_reboot_guard_permits(watcher, now) is True
                watcher.wifi_recovery.record_dead_phy_reboot_request(watcher, now, None)
            assert watcher.wifi_recovery.dead_phy_reboot_guard_permits(watcher, now) is False

    def test_old_requests_pruned(self, watcher, tmp_path):
        stamp = str(tmp_path / "guard.json")
        with patch.object(watcher, "DEAD_ADAPTER_REBOOT_STAMP", stamp):
            t0 = 1_000_000.0
            for _ in range(watcher.DEAD_ADAPTER_MAX_REBOOTS_PER_WINDOW):
                watcher.wifi_recovery.record_dead_phy_reboot_request(watcher, t0, None)
            assert watcher.wifi_recovery.dead_phy_reboot_guard_permits(watcher, t0) is False
            later = t0 + watcher.DEAD_ADAPTER_REBOOT_WINDOW + 1.0
            assert watcher.wifi_recovery.dead_phy_reboot_guard_permits(watcher, later) is True

    def test_corrupt_guard_treated_as_empty(self, watcher, tmp_path):
        stamp = tmp_path / "guard.json"
        stamp.write_text("{ not json", encoding="utf-8")
        with patch.object(watcher, "DEAD_ADAPTER_REBOOT_STAMP", str(stamp)):
            assert watcher.wifi_recovery.dead_phy_reboot_guard_permits(watcher, 1_000_000.0) is True


class TestEscalateDeadAdapterRecovery:
    USB_MAC = "aa:bb:cc:00:00:10"

    def _usb(self, watcher, ifname="wlan0"):
        return _adapter(watcher, ifname, self.USB_MAC, is_usb=True)

    def _mark_dead(self, watcher):
        """Pre-mark the target as dead so the ladder acts immediately."""
        watcher.RECOVERY_STATE.dead_adapter_ifname = "wlan0"
        watcher.RECOVERY_STATE.dead_adapter_since = 0.0
        watcher.RECOVERY_STATE.dead_adapter_first_failure = 0.0
        watcher.RECOVERY_STATE.dead_adapter_checks = watcher.DEAD_ADAPTER_DEBOUNCE
        watcher.RECOVERY_STATE.dead_adapter_stable_id = self.USB_MAC

    def test_healthy_target_no_action(self, watcher):
        usb = self._usb(watcher)
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=False, healthy=True):
            assert watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb], False) is False

    def test_dead_no_builtin_tries_method_a(self, watcher):
        usb = self._usb(watcher)
        self._mark_dead(watcher)
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=None), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind", return_value=True) as ra, \
             patch.object(watcher.wifi_net, "reset_usb_adapter_reenumerate", return_value=True) as rb, \
             patch.object(watcher.RECOVERY_CTX, "wait_for_interface_reappears", return_value="wlan0"), \
             patch.object(watcher.RECOVERY_CTX, "_activate_committed_on", return_value=False), \
             patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"):
            handled = watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb], False)
        assert handled is True
        ra.assert_called_once_with("wlan0")
        rb.assert_not_called()
        assert watcher.RECOVERY_STATE.last_reset_method == "A"

    def test_method_b_after_a(self, watcher):
        usb = self._usb(watcher)
        self._mark_dead(watcher)
        watcher.RECOVERY_STATE.last_reset_method = "A"
        watcher.RECOVERY_STATE.last_reset_attempt = 0.0
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=None), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind", return_value=True) as ra, \
             patch.object(watcher.wifi_net, "reset_usb_adapter_reenumerate", return_value=True) as rb, \
             patch.object(watcher.RECOVERY_CTX, "wait_for_interface_reappears", return_value="wlan0"), \
             patch.object(watcher.RECOVERY_CTX, "_activate_committed_on", return_value=False), \
             patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"), \
             patch("time.monotonic", return_value=10_000.0):
            watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb], False)
        rb.assert_called_once_with("wlan0")
        ra.assert_not_called()
        assert watcher.RECOVERY_STATE.last_reset_method == "B"

    def test_reset_success_clears_dead_state(self, watcher):
        usb = self._usb(watcher)
        self._mark_dead(watcher)
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=None), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind", return_value=True), \
             patch.object(watcher.wifi_net, "discover_adapters", return_value=[usb]), \
             patch.object(watcher.RECOVERY_CTX, "wait_for_interface_reappears", return_value="wlan0"), \
             patch.object(watcher.RECOVERY_CTX, "_activate_committed_on", return_value=True), \
             patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"):
            watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb], False)
        assert watcher.RECOVERY_STATE.dead_adapter_ifname == ""

    def test_reset_preferred_over_builtin_fallback(self, watcher):
        """RF-3: a resettable, budget-ok, due USB reset rung runs before the
        built-in fallback rung is even reached (item 10)."""
        usb = self._usb(watcher)
        builtin = _adapter(watcher, "wlan1", "aa:bb:cc:00:00:01", is_builtin=True)
        self._mark_dead(watcher)
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0", "wlan1"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=builtin) as rb, \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind", return_value=True) as ra, \
             patch.object(watcher.RECOVERY_CTX, "wait_for_interface_reappears", return_value="wlan0"), \
             patch.object(watcher.RECOVERY_CTX, "_activate_committed_on", return_value=True) as act, \
             patch.object(watcher.wifi_activation, "_set_active_client"), \
             patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"):
            handled = watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb, builtin], False)
        assert handled is True
        ra.assert_called_once_with("wlan0")
        # The reset recovered the USB target directly on its own ifname; the
        # built-in fallback rung is never even reached this pass.
        act.assert_called_once_with("wlan0")
        rb.assert_not_called()
        assert watcher.ADOPTION_STATE.using_builtin_fallback is False

    def test_non_resettable_still_reaches_builtin_fallback_first(self, watcher):
        """Item 11: a non-resettable target has no reset rung to prefer, so it
        reaches built-in fallback exactly as before the reorder."""
        usb = self._usb(watcher)
        builtin = _adapter(watcher, "wlan1", "aa:bb:cc:00:00:01", is_builtin=True)
        self._mark_dead(watcher)
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0", "wlan1"],
                                   usb_paths_ifaces=[],  # not resettable
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=builtin), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind", return_value=True) as ra, \
             patch.object(watcher.RECOVERY_CTX, "_activate_committed_on", return_value=True) as act, \
             patch.object(watcher.wifi_activation, "_set_active_client"), \
             patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"):
            handled = watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb, builtin], False)
        assert handled is True
        act.assert_called_once_with("wlan1")
        ra.assert_not_called()
        assert watcher.ADOPTION_STATE.using_builtin_fallback is True

    def test_budget_exhausted_still_reaches_builtin_fallback_first(self, watcher):
        """Item 11: a budget-exhausted resettable target (with another path
        available) skips the reset and reaches built-in fallback first."""
        usb = self._usb(watcher)
        builtin = _adapter(watcher, "wlan1", "aa:bb:cc:00:00:01", is_builtin=True)
        self._mark_dead(watcher)
        _spend_window_budget(watcher, self.USB_MAC, now=0.0)
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0", "wlan1"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=builtin), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind", return_value=True) as ra, \
             patch.object(watcher.RECOVERY_CTX, "_activate_committed_on", return_value=True) as act, \
             patch.object(watcher.wifi_activation, "_set_active_client"), \
             patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"), \
             patch("time.monotonic", return_value=1.0):
            # wired_connected=True also provides an alternate path.
            handled = watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb, builtin], True)
        assert handled is True
        act.assert_called_once_with("wlan1")
        ra.assert_not_called()

    def test_disabled_target_never_reaches_reset_or_builtin(self, watcher):
        """The disabled early-return is unchanged by the reorder (item 2)."""
        usb = self._usb(watcher)
        builtin = _adapter(watcher, "wlan1", "aa:bb:cc:00:00:01", is_builtin=True)
        self._mark_dead(watcher)
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0", "wlan1"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_recovery, "adapter_disabled", return_value=True), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=builtin) as rb, \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind", return_value=True) as ra:
            handled = watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb, builtin], False)
        assert handled is False
        ra.assert_not_called()
        rb.assert_not_called()

    def test_between_reset_windows_falls_through_to_builtin_fallback(self, watcher):
        """Item 12: when the reset rung is not yet due (interval not elapsed),
        the ladder falls through to built-in fallback rather than holding the
        device offline until the next reset window."""
        usb = self._usb(watcher)
        builtin = _adapter(watcher, "wlan1", "aa:bb:cc:00:00:01", is_builtin=True)
        self._mark_dead(watcher)
        watcher.RECOVERY_STATE.last_reset_attempt = 1000.0
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0", "wlan1"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=builtin), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind", return_value=True) as ra, \
             patch.object(watcher.RECOVERY_CTX, "_activate_committed_on", return_value=True) as act, \
             patch.object(watcher.wifi_activation, "_set_active_client"), \
             patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"), \
             patch("time.monotonic", return_value=1000.0 + watcher.RESET_ATTEMPT_INTERVAL / 2):
            # Well inside the reset interval: reset rung declines to act.
            handled = watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb, builtin], False)
        assert handled is True
        ra.assert_not_called()
        act.assert_called_once_with("wlan1")
        assert watcher.ADOPTION_STATE.using_builtin_fallback is True

    def test_resets_happen_even_when_wired(self, watcher):
        usb = self._usb(watcher)
        self._mark_dead(watcher)
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=None), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind", return_value=True) as ra, \
             patch.object(watcher.RECOVERY_CTX, "wait_for_interface_reappears", return_value="wlan0"), \
             patch.object(watcher.RECOVERY_CTX, "_activate_committed_on", return_value=False), \
             patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"), \
             patch.object(watcher, "reboot_system") as reboot:
            # wired_connected=True -> reset still attempted, reboot never.
            watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb], True)
        ra.assert_called_once()
        reboot.assert_not_called()

    def test_reboot_when_offline_and_dead_long_enough(self, watcher):
        usb = self._usb(watcher)
        self._mark_dead(watcher)
        # Non-resettable target so the ladder falls through to reboot.
        watcher.RECOVERY_STATE.last_reset_attempt = 0.0
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
                handled = watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb], False)
        assert handled is True
        reboot.assert_called_once_with("NetworkDown")
        assert watcher.STATE.conn_reboot_retry_after == float("inf")

    def test_reboot_suppressed_by_persistent_guard(self, watcher):
        usb = self._usb(watcher)
        self._mark_dead(watcher)
        now = watcher.DEAD_ADAPTER_REBOOT_AFTER + 100.0
        guard = tmp_guard()
        with patch.object(watcher, "DEAD_ADAPTER_REBOOT_STAMP", str(guard)), \
             patch.object(watcher.RECOVERY_CTX, "DEAD_ADAPTER_REBOOT_STAMP", str(guard)):
            # Fill the guard to the cap.
            for _ in range(watcher.DEAD_ADAPTER_MAX_REBOOTS_PER_WINDOW):
                watcher.wifi_recovery.record_dead_phy_reboot_request(watcher, 1_000_000.0, None)
            with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                       usb_paths_ifaces=[],
                                       link_down=True, healthy=False), \
                 patch.object(watcher.wifi_net, "resolve_builtin", return_value=None), \
                 patch("time.monotonic", return_value=now), \
                 patch("time.time", return_value=1_000_000.0), \
                 patch.object(watcher, "reboot_system") as reboot:
                handled = watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb], False)
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
            handled = watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb], True)
        assert handled is False
        ra.assert_not_called()
        assert _ledger(watcher, self.USB_MAC)["quarantined_until"] is not None
        # The fault-state file is now persisted at quarantine time (via the
        # shared quarantine_adapter helper), not left to a later ledger event.
        assert os.path.exists(watcher.ADAPTER_FAULT_STATE_PATH)
        with open(watcher.ADAPTER_FAULT_STATE_PATH, "r", encoding="utf-8") as f:
            on_disk = json.load(f)
        assert on_disk["reset_ledgers"][self.USB_MAC]["quarantined_until"] is not None

    def test_usb_only_emergency_attempt_when_no_path(self, watcher):
        usb = self._usb(watcher)
        self._mark_dead(watcher)
        _spend_window_budget(watcher, self.USB_MAC, now=0.0)
        watcher.RECOVERY_STATE.last_reset_attempt = 0.0
        emergency_now = watcher.USB_EMERGENCY_BACKOFF + 10.0
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=None), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind", return_value=True) as ra, \
             patch.object(watcher.RECOVERY_CTX, "wait_for_interface_reappears", return_value="wlan0"), \
             patch.object(watcher.RECOVERY_CTX, "_activate_committed_on", return_value=False), \
             patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"), \
             patch("time.monotonic", return_value=emergency_now):
            # No other path (wired False, no healthy adapter) -> emergency reset.
            handled = watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb], False)
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
            watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb, other], True)
        assert _ledger(watcher, self.USB_MAC)["quarantined_until"] is not None
        assert other.stable_id not in watcher.RECOVERY_STATE.adapter_reset_ledgers

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
             patch.object(watcher.RECOVERY_CTX, "wait_for_interface_reappears", return_value="wlan0"), \
             patch.object(watcher.RECOVERY_CTX, "_activate_committed_on", return_value=False), \
             patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"):
            handled = watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb], False)
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
            handled = watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb, builtin], False)
        assert handled is False
        ra.assert_not_called()


class TestDeadPhyRebootThreshold:
    USB_MAC = "aa:bb:cc:00:00:10"

    def _wedged_offline(self, watcher, now):
        usb = _adapter(watcher, "wlan0", self.USB_MAC, is_usb=True)
        watcher.RECOVERY_STATE.dead_adapter_ifname = "wlan0"
        watcher.RECOVERY_STATE.dead_adapter_since = 1.0
        watcher.RECOVERY_STATE.dead_adapter_first_failure = 1.0
        watcher.RECOVERY_STATE.dead_adapter_checks = watcher.DEAD_ADAPTER_DEBOUNCE
        watcher.RECOVERY_STATE.dead_adapter_stable_id = self.USB_MAC
        watcher.RECOVERY_STATE.last_reset_attempt = 1.0
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
            watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb], False)
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


class TestFieldLogRecoveryRegression:
    """Recovery-ladder — end-to-end regression for the 30-Jun-2026 field log.

    A wedged USB (wlan1) trapped the device in a BOOT_RECOVERY hotspot on the only
    good radio (onboard wlan0) for 30 minutes because the dead USB was probed
    forever and the onboard was never tried as a client.  These pass the full
    monitor loop and assert the onboard client path is taken promptly instead.
    """

    def test_boot_entry_recovers_on_onboard_without_hotspot(self, watcher):
        # Boot entry submits the onboard client (not a hotspot on it).
        # The wedged USB's reactivate-first attempt is already spent this
        # episode, so the ladder falls through to onboard directly.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "aa:bb:cc:00:00:10", is_usb=True)
        watcher.RECOVERY_STATE.dead_adapter_ifname = "wlan1"  # declared wedged
        watcher.RECOVERY_STATE.wedged_reactivate_done.add(usb.stable_id)
        watcher.STATE.boot_time = 300.0  # boot_age 700s at now=1000 (inside window)
        with patch.object(watcher.LOOP_CTX, "submit_client_activation", return_value=True) as submit, \
             patch.object(watcher.LOOP_CTX, "enter_setup_mode") as enter, \
             patch.object(watcher.wifi_net, "read_link_down",
                          side_effect=lambda ifn: ifn == "wlan1"):
            _run_monitor_once(
                watcher, now=1000.0, wifi_cfg=True, wifi_connected=True,
                client_ok=False, adapters=[builtin, usb], active_client=usb,
            )
        enter.assert_not_called()  # no hotspot: submitted the onboard client instead
        action = submit.call_args[0][0]
        assert action.kind is watcher.wifi_policy.RecoveryKind.ACTIVATE_ONBOARD
        assert action.ifname == "wlan0"

    def test_in_hotspot_climbs_to_onboard_not_dead_usb(self, watcher):
        # The wedged USB's reactivate-first attempt is already spent this
        # episode, so the ladder climbs to onboard rather than re-probing it.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "aa:bb:cc:00:00:10", is_usb=True)
        watcher.RECOVERY_STATE.dead_adapter_ifname = "wlan1"  # declared wedged
        watcher.RECOVERY_STATE.wedged_reactivate_done.add(usb.stable_id)
        watcher.STATE.setup_mode = True
        watcher.STATE.hotspot = watcher.HotspotSession(
            purpose=watcher.wifi_policy.HotspotPurpose.BOOT_RECOVERY, entered_at=0.0)
        with patch.object(watcher.wifi_net, "read_link_down",
                          side_effect=lambda ifn: ifn == "wlan1"), \
             patch.object(watcher.wifi_adoption, "_saved_ssid_visible", return_value=True), \
             patch.object(watcher.ADOPTION_CTX, "hotspot_station_count", return_value=0), \
             patch.object(watcher.wifi_adoption, "_submit_client_activation", return_value=True) as apply:
            _run_monitor_once(watcher, now=120.0, wifi_cfg=True,
                              adapters=[builtin, usb], active_client=usb)
        # Headless recovery (zero stations on the AP): the ladder selects the
        # onboard drop-AP rejoin, not the dead USB probe.
        apply.assert_called_once()
        action = apply.call_args[0][1]
        assert action.kind is watcher.wifi_policy.RecoveryKind.ACTIVATE_ONBOARD
        assert action.ifname == "wlan0"
        assert action.drop_hotspot is True


class TestDeadPhyEndToEnd:
    MAC = "aa:bb:cc:00:00:10"

    def _usb(self, watcher):
        return _adapter(watcher, "wlan0", self.MAC, is_usb=True)

    def _mark_dead(self, watcher, first_failure=1.0):
        watcher.RECOVERY_STATE.dead_adapter_ifname = "wlan0"
        watcher.RECOVERY_STATE.dead_adapter_since = first_failure
        watcher.RECOVERY_STATE.dead_adapter_first_failure = first_failure
        watcher.RECOVERY_STATE.dead_adapter_checks = watcher.DEAD_ADAPTER_DEBOUNCE
        watcher.RECOVERY_STATE.dead_adapter_stable_id = self.MAC

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
             patch.object(watcher.RECOVERY_CTX, "wait_for_interface_reappears", return_value="wlan0"), \
             patch.object(watcher.RECOVERY_CTX, "_activate_committed_on", return_value=False), \
             patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"), \
             patch.object(watcher, "reboot_system") as reboot, \
             patch("time.monotonic", clock), patch("time.time", return_value=1_000_000.0):
            # Debounce: first wedged pass does not reset.
            assert watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb], True) is False
            # Second pass declares dead and runs Method A.
            assert watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb], True) is True
            clock.advance(watcher.RESET_ATTEMPT_INTERVAL + 1)
            # Method B.
            assert watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb], True) is True
            clock.advance(watcher.RESET_ATTEMPT_INTERVAL + 1)
            # Budget exhausted + ethernet path -> quarantine (does not own pass).
            assert watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb], True) is False
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
             patch.object(watcher.RECOVERY_CTX, "wait_for_interface_reappears", return_value="wlan0"), \
             patch.object(watcher.RECOVERY_CTX, "_activate_committed_on", return_value=True), \
             patch.object(watcher.wifi_activation, "_set_active_client"), \
             patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"), \
             patch.object(watcher, "reboot_system") as reboot, \
             patch("time.monotonic", clock), patch("time.time", return_value=1_000_000.0):
            watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb], True)   # debounce
            watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb], True)   # Method A -> recover
        ra.assert_called_once()
        assert watcher.RECOVERY_STATE.dead_adapter_ifname == ""
        reboot.assert_not_called()

    def test_sequence_usb_only_emergency_backoff(self, watcher):
        """No alternate path: budget exceeded but USB-only keeps slow attempts."""
        usb = self._usb(watcher)
        clock = _Clock(1000.0)
        self._mark_dead(watcher, first_failure=clock.t)
        _spend_window_budget(watcher, self.MAC, now=clock.t)
        watcher.RECOVERY_STATE.last_reset_attempt = clock.t
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=None), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind", return_value=True) as ra, \
             patch.object(watcher.RECOVERY_CTX, "wait_for_interface_reappears", return_value="wlan0"), \
             patch.object(watcher.RECOVERY_CTX, "_activate_committed_on", return_value=False), \
             patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"), \
             patch.object(watcher, "reboot_system") as reboot, \
             patch("time.monotonic", clock), patch("time.time", return_value=1_000_000.0):
            # Before the emergency backoff elapses: no reset.
            clock.advance(watcher.RESET_ATTEMPT_INTERVAL + 1)
            watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb], False)
            assert ra.call_count == 0
            # After the emergency backoff: a slow emergency reset is attempted.
            clock.advance(watcher.USB_EMERGENCY_BACKOFF + 1)
            watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb], False)
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
             patch.object(watcher.RECOVERY_CTX, "wait_for_interface_reappears", return_value="wlan0"), \
             patch.object(watcher.RECOVERY_CTX, "_activate_committed_on", return_value=True), \
             patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"), \
             patch("time.monotonic", clock):
            watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb], True)
            watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb], True)
        assert watcher.RECOVERY_STATE.last_reset_attempt is None
        assert watcher.RECOVERY_STATE.last_reset_method == ""

        clock.advance(1.0)
        self._mark_dead(watcher, first_failure=clock.t)
        with _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=["wlan0"],
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=None), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind", return_value=True) as ra2, \
             patch.object(watcher.wifi_net, "reset_usb_adapter_reenumerate", return_value=True) as rb2, \
             patch.object(watcher.RECOVERY_CTX, "wait_for_interface_reappears", return_value="wlan0"), \
             patch.object(watcher.RECOVERY_CTX, "_activate_committed_on", return_value=False), \
             patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"), \
             patch("time.monotonic", clock):
            assert watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb], True) is True
        assert ra.call_count == 1
        ra2.assert_called_once_with("wlan0")
        rb.assert_not_called()
        rb2.assert_not_called()
        assert watcher.RECOVERY_STATE.last_reset_method == "A"

    def test_sequence_reboot_then_inprocess_and_guard_suppression(self, watcher):
        """Offline + dead>=30min + resets failing: one reboot, then suppressed."""
        usb = self._usb(watcher)
        clock = _Clock(1000.0)
        self._mark_dead(watcher, first_failure=1.0)
        clock.t = watcher.DEAD_ADAPTER_REBOOT_AFTER + 1000.0
        guard = tmp_guard()
        with patch.object(watcher, "DEAD_ADAPTER_REBOOT_STAMP", str(guard)), \
             patch.object(watcher.RECOVERY_CTX, "DEAD_ADAPTER_REBOOT_STAMP", str(guard)), \
             _patch_dead_phy_facts(watcher, sysfs_names=["wlan0"],
                                   usb_paths_ifaces=[],  # non-resettable -> reboot rung
                                   link_down=True, healthy=False), \
             patch.object(watcher.wifi_net, "resolve_builtin", return_value=None), \
             patch("time.monotonic", clock), patch("time.time", return_value=1_000_000.0), \
             patch.object(watcher, "reboot_system", return_value=True) as reboot:
            # First: reboot accepted.
            assert watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb], False) is True
            assert watcher.STATE.conn_reboot_retry_after == float("inf")
            # Second: in-process rate limit (retry_after == inf) suppresses.
            assert watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb], False) is False
            assert reboot.call_count == 1
            # Simulate a fresh process whose in-process limit is reset, but the
            # persistent guard is now full -> still suppressed.
            watcher.STATE.conn_reboot_retry_after = 0.0
            for _ in range(watcher.DEAD_ADAPTER_MAX_REBOOTS_PER_WINDOW):
                watcher.wifi_recovery.record_dead_phy_reboot_request(watcher, 1_000_000.0, None)
            assert watcher.wifi_recovery.escalate_dead_adapter_recovery(watcher.RECOVERY_CTX, [usb], False) is False
            assert reboot.call_count == 1
