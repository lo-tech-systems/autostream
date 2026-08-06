"""Monitor-loop step handlers and phase contexts: hysteresis, health memo,
ethernet-wins, boot AP entry, and the catch-all reboot path."""
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
from _wifi_fixtures import _adapter, _facts_for, _run_monitor_once


class TestConnectivityHysteresis:
    """connectivity_ok is slow to condemn (soft N-pass) and quick to
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
            ok = watcher.wifi_loop._debounced_connectivity(watcher.LOOP_CTX, facts, usb, client_ok=False)
        assert ok is True                       # a single soft blip does NOT flip
        assert watcher.STATE.conn_unhealthy_checks == 1

    def test_two_soft_passes_condemn(self, watcher):
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:32", is_usb=True)
        watcher.STATE.connectivity_ok = True
        facts = self._facts(watcher, [usb], usb)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=False):
            first = watcher.wifi_loop._debounced_connectivity(watcher.LOOP_CTX, facts, usb, client_ok=False)
            second = watcher.wifi_loop._debounced_connectivity(watcher.LOOP_CTX, facts, usb, client_ok=False)
        assert (first, second) == (True, False)  # condemned only after N consecutive

    def test_healthy_pass_recovers_immediately_and_resets(self, watcher):
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:33", is_usb=True)
        watcher.STATE.conn_unhealthy_checks = 1
        facts = self._facts(watcher, [usb], usb)
        ok = watcher.wifi_loop._debounced_connectivity(watcher.LOOP_CTX, facts, usb, client_ok=True)
        assert ok is True
        assert watcher.STATE.conn_unhealthy_checks == 0

    def test_no_active_client_is_hard(self, watcher):
        watcher.STATE.connectivity_ok = True
        facts = self._facts(watcher, [], None)
        ok = watcher.wifi_loop._debounced_connectivity(watcher.LOOP_CTX, facts, None, client_ok=False)
        assert ok is False                       # hard: condemned immediately
        assert watcher.STATE.conn_unhealthy_checks == 0

    def test_nm_disconnected_present_usb_is_soft(self, watcher):
        # No active client this pass, but the recorded USB is still present
        # (NM merely disconnected it) -> soft, debounced 2 passes.
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:35", is_usb=True)
        watcher.STATE.connectivity_ok = True
        facts = self._facts(watcher, [usb], None)  # USB present, not the active client
        first = watcher.wifi_loop._debounced_connectivity(watcher.LOOP_CTX, facts, None, client_ok=False,
                                                prev_mac=usb.permanent_mac)
        second = watcher.wifi_loop._debounced_connectivity(watcher.LOOP_CTX, facts, None, client_ok=False,
                                                 prev_mac=usb.permanent_mac)
        assert (first, second) == (True, False)   # 2-pass debounce, not immediate
        assert watcher.STATE.conn_unhealthy_checks == 2

    def test_absent_recorded_usb_is_hard(self, watcher):
        # Recorded USB physically gone from adapters -> hard (immediate), no debounce.
        watcher.STATE.connectivity_ok = True
        facts = self._facts(watcher, [], None)     # USB gone
        ok = watcher.wifi_loop._debounced_connectivity(watcher.LOOP_CTX, facts, None, client_ok=False,
                                             prev_mac="bb:bb:bb:bb:bb:36")
        assert ok is False
        assert watcher.STATE.conn_unhealthy_checks == 0

    def test_carrier_down_is_hard(self, watcher):
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:34", is_usb=True)
        watcher.STATE.connectivity_ok = True
        facts = self._facts(watcher, [usb], usb)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=True):  # NO-CARRIER
            ok = watcher.wifi_loop._debounced_connectivity(watcher.LOOP_CTX, facts, usb, client_ok=False)
        assert ok is False

    def test_wired_ok_is_online_without_debounce(self, watcher):
        watcher.STATE.conn_unhealthy_checks = 5
        facts = self._facts(watcher, [], None, wired_ok=True)
        ok = watcher.wifi_loop._debounced_connectivity(watcher.LOOP_CTX, facts, None, client_ok=False)
        assert ok is True
        assert watcher.STATE.conn_unhealthy_checks == 0


class TestHandoverSettlingGrace:
    """H-2: a HARD connectivity signal within HANDOVER_SETTLE_SECONDS of the
    last active-client identity change is demoted to the soft (debounced)
    class; a genuinely dead handover still condemns via the normal debounce,
    and the grace never touches the already-soft path."""

    def _facts(self, watcher, adapters, active, *, taken_at=1000.0):
        return watcher.Facts(
            wifi_configured=True, adapters=adapters, wired_connected=False,
            wired_ok=False, active_client=active, addresses={}, taken_at=taken_at,
        )

    def test_hard_signal_within_grace_is_soft(self, watcher):
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:40", is_usb=True)
        watcher.STATE.connectivity_ok = True
        watcher.STATE.active_client_changed_at = 1000.0  # just handed over
        facts = self._facts(watcher, [usb], usb, taken_at=1010.0)  # 10s later, within 45s
        with patch.object(watcher.wifi_net, "read_link_down", return_value=True):  # hard: NO-CARRIER
            first = watcher.wifi_loop._debounced_connectivity(watcher.LOOP_CTX, facts, usb, client_ok=False)
            second = watcher.wifi_loop._debounced_connectivity(watcher.LOOP_CTX, facts, usb, client_ok=False)
        assert (first, second) == (True, False)  # demoted to the 2-pass soft debounce

    def test_hard_signal_after_grace_is_immediate(self, watcher):
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:41", is_usb=True)
        watcher.STATE.connectivity_ok = True
        watcher.STATE.active_client_changed_at = 1000.0
        facts = self._facts(watcher, [usb], usb, taken_at=1000.0 + watcher.HANDOVER_SETTLE_SECONDS + 1)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=True):
            ok = watcher.wifi_loop._debounced_connectivity(watcher.LOOP_CTX, facts, usb, client_ok=False)
        assert ok is False  # unchanged: immediate condemnation once the grace has elapsed

    def test_hard_signal_no_recorded_handover_is_immediate(self, watcher):
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:42", is_usb=True)
        watcher.STATE.connectivity_ok = True
        watcher.STATE.active_client_changed_at = None  # unconfigured startup: no grace
        facts = self._facts(watcher, [usb], usb, taken_at=1000.0)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=True):
            ok = watcher.wifi_loop._debounced_connectivity(watcher.LOOP_CTX, facts, usb, client_ok=False)
        assert ok is False

    def test_stamp_not_refreshed_on_same_identity(self, watcher):
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:43", is_usb=True)
        watcher.STATE.active_client_ifname = usb.ifname
        watcher.STATE.active_client_mac = usb.permanent_mac
        watcher.STATE.active_client_changed_at = 500.0
        with patch.object(watcher.wifi_activation.time, "monotonic", return_value=999.0):
            watcher.wifi_activation._set_active_client(watcher.ACTIVATION_CTX, usb)
        assert watcher.STATE.active_client_changed_at == 500.0  # unchanged: same identity

    def test_stamp_refreshed_on_genuine_change(self, watcher):
        usb_old = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:44", is_usb=True)
        usb_new = _adapter(watcher, "wlan2", "bb:bb:bb:bb:bb:45", is_usb=True)
        watcher.STATE.active_client_ifname = usb_old.ifname
        watcher.STATE.active_client_mac = usb_old.permanent_mac
        watcher.STATE.active_client_changed_at = 500.0
        with patch.object(watcher.wifi_activation.time, "monotonic", return_value=999.0):
            watcher.wifi_activation._set_active_client(watcher.ACTIVATION_CTX, usb_new)
        assert watcher.STATE.active_client_changed_at == 999.0  # refreshed on identity change

    def test_soft_failure_within_grace_still_condemns_after_two_passes(self, watcher):
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:46", is_usb=True)
        watcher.STATE.connectivity_ok = True
        watcher.STATE.active_client_changed_at = 1000.0
        facts = self._facts(watcher, [usb], usb, taken_at=1010.0)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=False):  # already soft
            first = watcher.wifi_loop._debounced_connectivity(watcher.LOOP_CTX, facts, usb, client_ok=False)
            second = watcher.wifi_loop._debounced_connectivity(watcher.LOOP_CTX, facts, usb, client_ok=False)
        assert (first, second) == (True, False)  # grace does not weaken the soft path


class TestHealthMemo:
    """is_wifi_client_healthy is sampled once per (pass, ifname) and the
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


class TestBootClientBringup:
    """The BOOT-window client bring-up is a loop rung that runs the single
    recovery ladder (preferred USB, else onboard) each pass while BOOT_AP_GRACE is
    open, replacing the retired pre-loop startup_connect_usb_first() one-shot and
    its tried-MACs re-probe gate.  The apply mechanics (net-absent short-circuit,
    UUID resolution, no-IP ledger) live in activate_client and are covered by
    TestActivateClient; these tests assert the boot rung's routing and gating."""

    def _fctx(self, watcher, adapters, active_client, *, wifi_cfg=True, wired_ok=False,
              now=10.0, boot_time=0.0):
        facts = _facts_for(watcher, adapters, active_client, wifi_cfg=wifi_cfg,
                           wired_ok=wired_ok, now=now)
        pre = watcher.wifi_loop.PreFactsContext(now=now, boot_time=boot_time, avahi_ok=True)
        return watcher.wifi_loop.FactsContext(pre, facts, lambda: False)

    def test_boot_window_engages_preferred_usb(self, watcher):
        # Offline in the boot window with a usable USB and no active client: the
        # ladder selects ACTIVATE_USB (rung 1) and the rung owns the pass.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "cc:dd:ee:ff:00:03", is_usb=True)
        fctx = self._fctx(watcher, [builtin, usb], None)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.LOOP_CTX, "submit_client_activation", return_value=True) as apply:
            v = watcher.wifi_loop.step_boot_client_bringup(watcher.LOOP_CTX, fctx)
        assert v is watcher.Verdict.OWN_PASS
        apply.assert_called_once()
        action = apply.call_args[0][0]
        assert action.kind is watcher.wifi_policy.RecoveryKind.ACTIVATE_USB
        assert action.ifname == "wlan1"    # USB tried before the built-in

    def test_boot_window_idle_link_down_usb_activates_without_reset(self, watcher):
        # Field regression at the boot rung: first pass, configured, no wire,
        # idle link-down (not yet wedged) preferred USB -> the submitted
        # activation job has reset_before=False (rung 1, not RESET_USB).
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "cc:dd:ee:ff:00:11", is_usb=True)
        fctx = self._fctx(watcher, [builtin, usb], None)
        with patch.object(watcher.wifi_net, "usb_sysfs_paths",
                          side_effect=lambda ifname: {"interface_id": "1-1"} if ifname == "wlan1" else None), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=True), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.ADOPTION_CTX, "submit_activation_job", return_value=True) as submit:
            v = watcher.wifi_loop.step_boot_client_bringup(watcher.LOOP_CTX, fctx)
        assert v is watcher.Verdict.OWN_PASS
        submit.assert_called_once()
        job = submit.call_args[0][0]
        assert job.ifname == "wlan1"
        assert job.reset_before is False

    def test_boot_window_falls_to_onboard_when_no_usb(self, watcher):
        # No USB present: the ladder engages the onboard (rung 2) as a client.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        fctx = self._fctx(watcher, [builtin], None)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.LOOP_CTX, "submit_client_activation", return_value=True) as apply:
            v = watcher.wifi_loop.step_boot_client_bringup(watcher.LOOP_CTX, fctx)
        assert v is watcher.Verdict.OWN_PASS
        action = apply.call_args[0][0]
        assert action.kind is watcher.wifi_policy.RecoveryKind.ACTIVATE_ONBOARD
        assert action.ifname == "wlan0"

    def test_wired_ok_short_circuits(self, watcher):
        # Usable wired Ethernet: the boot rung does not engage a Wi-Fi client.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "cc:dd:ee:ff:00:04", is_usb=True)
        fctx = self._fctx(watcher, [builtin, usb], None, wired_ok=True)
        with patch.object(watcher.LOOP_CTX, "submit_client_activation") as apply:
            v = watcher.wifi_loop.step_boot_client_bringup(watcher.LOOP_CTX, fctx)
        assert v is watcher.Verdict.CONTINUE
        apply.assert_not_called()

    def test_healthy_client_holds_no_reprobe(self, watcher):
        # A client is already up and healthy: the ladder HOLDs (no thrash).
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "cc:dd:ee:ff:00:05", is_usb=True)
        fctx = self._fctx(watcher, [builtin, usb], usb)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher.LOOP_CTX, "submit_client_activation") as apply:
            v = watcher.wifi_loop.step_boot_client_bringup(watcher.LOOP_CTX, fctx)
        assert v is watcher.Verdict.CONTINUE
        apply.assert_not_called()

    def test_after_grace_window_defers(self, watcher):
        # Past BOOT_AP_GRACE the boot rung is inactive; step_boot_ap_entry owns the
        # ladder-then-hotspot decision.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "cc:dd:ee:ff:00:06", is_usb=True)
        fctx = self._fctx(watcher, [builtin, usb], None,
                          now=watcher.wifi_policy.BOOT_AP_GRACE + 10.0, boot_time=0.0)
        with patch.object(watcher.LOOP_CTX, "submit_client_activation") as apply:
            v = watcher.wifi_loop.step_boot_client_bringup(watcher.LOOP_CTX, fctx)
        assert v is watcher.Verdict.CONTINUE
        apply.assert_not_called()

    def test_setup_mode_skips(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "cc:dd:ee:ff:00:07", is_usb=True)
        watcher.STATE.setup_mode = True
        fctx = self._fctx(watcher, [builtin, usb], None)
        with patch.object(watcher.LOOP_CTX, "submit_client_activation") as apply:
            v = watcher.wifi_loop.step_boot_client_bringup(watcher.LOOP_CTX, fctx)
        assert v is watcher.Verdict.CONTINUE
        apply.assert_not_called()

    @pytest.mark.parametrize("roaming_managed", [False, True])
    def test_boot_window_resets_wedged_usb_before_onboard(self, watcher, roaming_managed):
        # A dongle already declared dead-PHY-wedged (debounce completed
        # earlier, e.g. across a watcher restart) gets its one budgeted reset
        # before onboard/hotspot (RF-2 boot-window parity with runtime).
        # The RESET_USB rung keys off link state and dead-PHY bookkeeping, not
        # BSSID pins, so it must fire identically whether roaming management
        # is on or off (fault-ladder invariance).
        watcher.ADOPTION_STATE.roaming_managed = roaming_managed
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "cc:dd:ee:ff:00:09", is_usb=True)
        watcher.RECOVERY_STATE.dead_adapter_ifname = "wlan1"
        # Reactivate-first (rung 1a) already spent this episode: exercises the
        # RESET_USB rung (1c) specifically, same as a runtime pass.
        watcher.RECOVERY_STATE.wedged_reactivate_done.add(usb.stable_id)
        fctx = self._fctx(watcher, [builtin, usb], None)
        with patch.object(watcher.wifi_net, "usb_sysfs_paths",
                          side_effect=lambda ifname: {"interface_id": "1-1"} if ifname == "wlan1" else None), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=True), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.LOOP_CTX, "submit_client_activation", return_value=True) as apply:
            v = watcher.wifi_loop.step_boot_client_bringup(watcher.LOOP_CTX, fctx)
        assert v is watcher.Verdict.OWN_PASS
        action = apply.call_args[0][0]
        assert action.kind is watcher.wifi_policy.RecoveryKind.RESET_USB
        assert action.ifname == "wlan1"

    def test_boot_window_episode_spent_falls_through_to_onboard(self, watcher):
        # Once the episode's reactivate-first attempt AND its reset are both
        # already spent, the boot rung falls through to onboard exactly as a
        # runtime pass would.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "cc:dd:ee:ff:00:10", is_usb=True)
        watcher.RECOVERY_STATE.failover_reset_done.add(usb.permanent_mac)
        watcher.RECOVERY_STATE.wedged_reactivate_done.add(usb.permanent_mac)
        watcher.RECOVERY_STATE.dead_adapter_ifname = "wlan1"
        fctx = self._fctx(watcher, [builtin, usb], None)
        with patch.object(watcher.wifi_net, "usb_sysfs_paths",
                          side_effect=lambda ifname: {"interface_id": "1-1"} if ifname == "wlan1" else None), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=True), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.LOOP_CTX, "submit_client_activation", return_value=True) as apply:
            v = watcher.wifi_loop.step_boot_client_bringup(watcher.LOOP_CTX, fctx)
        assert v is watcher.Verdict.OWN_PASS
        action = apply.call_args[0][0]
        assert action.kind is watcher.wifi_policy.RecoveryKind.ACTIVATE_ONBOARD
        assert action.ifname == "wlan0"

    def test_unconfigured_skips(self, watcher):
        # Nothing committed: the boot rung has no client profile to bring up.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "cc:dd:ee:ff:00:08", is_usb=True)
        fctx = self._fctx(watcher, [builtin, usb], None, wifi_cfg=False)
        with patch.object(watcher.LOOP_CTX, "submit_client_activation") as apply:
            v = watcher.wifi_loop.step_boot_client_bringup(watcher.LOOP_CTX, fctx)
        assert v is watcher.Verdict.CONTINUE
        apply.assert_not_called()


class TestHotspotPurposeMachine:
    """Hotspot lifetime/probe policy driven by the purpose table; defects 1 & 2."""

    def _session(self, watcher, purpose, entered_at):
        watcher.STATE.setup_mode = True
        watcher.STATE.hotspot = watcher.HotspotSession(purpose=purpose, entered_at=entered_at)

    def test_defect1_boot_recovery_probes_for_return(self, watcher):
        # A configured device offline at boot is BOOT_RECOVERY and probes for the
        # saved network each pass — it does not sit until the 30-min deadline.
        # Built-in hosts the hotspot; the returned USB is the second radio probed
        # without dropping the AP (second-radio path).
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:01", is_usb=True)
        self._session(watcher, watcher.wifi_policy.HotspotPurpose.BOOT_RECOVERY, entered_at=100.0)
        with patch.object(watcher.LOOP_CTX, "attempt_recovery_reconnect") as probe:
            _run_monitor_once(watcher, now=120.0, wifi_cfg=True, adapters=[builtin, usb])
        probe.assert_called_once()

    def test_first_run_does_not_probe(self, watcher):
        # FIRST_RUN has nothing saved to probe for.
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:01", is_usb=True)
        self._session(watcher, watcher.wifi_policy.HotspotPurpose.FIRST_RUN, entered_at=100.0)
        with patch.object(watcher.LOOP_CTX, "attempt_recovery_reconnect") as probe, \
             patch.object(watcher, "leave_setup_mode") as leave:
            _run_monitor_once(watcher, now=120.0, wifi_cfg=False, adapters=[usb])
        probe.assert_not_called()
        leave.assert_not_called()

    def test_first_run_is_indefinite(self, watcher):
        # Past 30 minutes, an unconfigured FIRST_RUN hotspot is not torn down.
        self._session(watcher, watcher.wifi_policy.HotspotPurpose.FIRST_RUN, entered_at=0.0)
        now = watcher.wifi_policy.AP_MAX_DURATION + 60.0
        with patch.object(watcher, "leave_setup_mode") as leave:
            _run_monitor_once(watcher, now=now, wifi_cfg=False)
        leave.assert_not_called()

    def test_recovery_purpose_expires_at_deadline(self, watcher):
        self._session(watcher, watcher.wifi_policy.HotspotPurpose.USB_LOSS_RECOVERY, entered_at=0.0)
        now = watcher.wifi_policy.AP_MAX_DURATION + 60.0
        with patch.object(watcher.LOOP_CTX, "leave_setup_mode") as leave, \
             patch.object(watcher.LOOP_CTX, "attempt_recovery_reconnect"):
            _run_monitor_once(watcher, now=now, wifi_cfg=True)
        leave.assert_called_once()

    def test_explicit_hotspot_not_torn_down_by_ethernet(self, watcher):
        # EXPLICIT_RECONFIGURE is not eth-suppressible (Section 2.3).
        self._session(watcher, watcher.wifi_policy.HotspotPurpose.EXPLICIT_RECONFIGURE, entered_at=100.0)
        with patch.object(watcher, "leave_setup_mode") as leave, \
             patch.object(watcher.LOOP_CTX, "attempt_recovery_reconnect"):
            _run_monitor_once(watcher, now=120.0, wifi_cfg=False,
                              wired_connected=True, wired_ok=True)
        leave.assert_not_called()

    def test_user_hotspot_does_not_probe_within_grace(self, watcher):
        # A user opened the portal to change networks; within HOTSPOT_PROBE_GRACE
        # the watcher must NOT probe for (and rejoin) the old saved network, or it
        # would tear the hotspot down before the user can pick a new one.
        self._session(watcher, watcher.wifi_policy.HotspotPurpose.EXPLICIT_RECONFIGURE, entered_at=100.0)
        within = 100.0 + watcher.wifi_policy.HOTSPOT_PROBE_GRACE - 1.0
        with patch.object(watcher.LOOP_CTX, "attempt_recovery_reconnect") as probe:
            _run_monitor_once(watcher, now=within, wifi_cfg=True)
        probe.assert_not_called()

    def test_user_hotspot_probes_after_grace(self, watcher):
        # Once the grace window elapses, the user-initiated hotspot resumes
        # probing for the saved network (idle-user recovery before the deadline).
        self._session(watcher, watcher.wifi_policy.HotspotPurpose.MANUAL, entered_at=0.0)
        after = watcher.wifi_policy.HOTSPOT_PROBE_GRACE + 30.0
        with patch.object(watcher.LOOP_CTX, "attempt_recovery_reconnect") as probe:
            _run_monitor_once(watcher, now=after, wifi_cfg=True)
        probe.assert_called_once()

    def test_recovery_hotspot_probes_immediately_no_grace(self, watcher):
        # Automatic recovery purposes have probe_grace_s == 0: they lost the path
        # involuntarily and must probe from the first pass.
        self._session(watcher, watcher.wifi_policy.HotspotPurpose.USB_LOSS_RECOVERY, entered_at=100.0)
        with patch.object(watcher.LOOP_CTX, "attempt_recovery_reconnect") as probe:
            _run_monitor_once(watcher, now=101.0, wifi_cfg=True)
        probe.assert_called_once()

    def test_defect2_recovery_enterable_after_earlier_session(self, watcher):
        # After a hotspot was used and left earlier this boot, a later USB-loss
        # fallback still raises a recovery hotspot (no once-per-boot suppression).
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        # Simulate an earlier session that has since been left.
        with patch.object(watcher.HOTSPOT_CTX, "start_ap_mode"), patch.object(watcher.HOTSPOT_CTX, "stop_ap_mode"):
            watcher.enter_setup_mode(watcher.wifi_policy.HotspotPurpose.FIRST_RUN, "earlier")
            watcher.leave_setup_mode("earlier done")
        facts = _facts_for(watcher, [builtin], None)
        event = watcher.wifi_recovery.ClientFailed(ifname="wlan1", mac="bb:bb:bb:bb:bb:0a",
                                     reason="later usb loss", has_alt_path=False)
        action = watcher.wifi_policy.RecoveryAction(watcher.wifi_policy.RecoveryKind.ENTER_HOTSPOT,
                                        purpose=watcher.wifi_policy.HotspotPurpose.BOOT_RECOVERY)
        rf = watcher.wifi_policy.RecoveryFacts(
            adapters_by_ifname={}, onboard_ifname="", usb_ifnames=(),
            preferred_usb_ifname="", hotspot_ifname="", active_ifname="",
            saved_configured=True, wired_ok=False, taken_at=1000.0)
        with patch.object(watcher.ADOPTION_CTX, "gather_recovery_facts", return_value=rf), \
             patch.object(watcher.wifi_policy, "next_recovery_action", return_value=action), \
             patch.object(watcher.ADOPTION_CTX, "enter_setup_mode") as enter:
            acted = watcher.wifi_adoption.apply_client_failed(watcher.ADOPTION_CTX, event, facts)
        assert acted is True
        enter.assert_called_once()
        assert enter.call_args[0][0] is watcher.wifi_policy.HotspotPurpose.USB_LOSS_RECOVERY


class TestWs1Wp3AsyncRecovery:
    """The recovery handlers submit activations to the worker, the
    onboard-failure bound yields to the hotspot, and the deferred handlers hold
    off while a job is in flight (transitioning)."""

    def _hctx(self, watcher, facts, *, conn_ok=False):
        pre = watcher.wifi_loop.PreFactsContext(now=facts.taken_at, boot_time=0.0, avahi_ok=True)
        fctx = watcher.wifi_loop.FactsContext(pre, facts, lambda: False)
        return watcher.wifi_loop.HealthContext(
            fctx, health_ifname="wlan0", wifi_connected=False, client_ok=False,
            conn_ok=conn_ok, active_path_ok=conn_ok)

    # ---- onboard-failure bound ----

    def test_onboard_activation_failure_increments_bound(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:01", is_usb=True)
        facts = _facts_for(watcher, [builtin, usb], None)
        action = watcher.wifi_policy.RecoveryAction(watcher.wifi_policy.RecoveryKind.ACTIVATE_ONBOARD, ifname="wlan0")
        with patch.object(watcher.ADOPTION_CTX, "submit_activation_job", return_value=True) as submit:
            watcher.wifi_adoption._submit_client_activation(watcher.ADOPTION_CTX, action, facts)
        job = submit.call_args[0][0]
        assert job.records_onboard_failure is True
        # Applying a failed result increments the bound.
        watcher.wifi_activation.apply_activation_result(watcher.ACTIVATION_CTX, watcher.wifi_activation.ActivationResult(job.epoch, False, "wlan0", job))
        assert watcher.STATE.onboard_activation_failures == 1

    def test_gather_drops_onboard_when_budget_spent(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        facts = _facts_for(watcher, [builtin], None)
        with patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=False):
            watcher.STATE.onboard_activation_failures = 0
            rf = watcher.gather_recovery_facts(facts)
            assert rf.onboard_ifname == "wlan0"
            watcher.STATE.onboard_activation_failures = watcher.ONBOARD_ACTIVATION_MAX_FAILURES
            rf2 = watcher.gather_recovery_facts(facts)
            assert rf2.onboard_ifname == ""     # budget spent -> not offered

    def test_healthy_pass_resets_onboard_bound(self, watcher):
        watcher.STATE.onboard_activation_failures = 2
        facts = _facts_for(watcher, [], None)
        hctx = self._hctx(watcher, facts, conn_ok=True)
        with patch.object(watcher.LOOP_CTX, "publish_network_status"), \
             patch.object(watcher.LOOP_CTX, "next_mode", return_value=watcher.wifi_policy.Mode.ONLINE):
            watcher.wifi_loop.step_publish_state(watcher.LOOP_CTX, hctx)
        assert watcher.STATE.onboard_activation_failures == 0

    def test_healthy_pass_clears_failover_reset_episode_alongside_onboard_bound(self, watcher):
        # The RESET_USB per-episode spend clears at the same site as the
        # onboard-failure bound: a fresh offline episode gets its own reset.
        watcher.STATE.onboard_activation_failures = 2
        watcher.RECOVERY_STATE.failover_reset_done.add("bb:bb:bb:bb:bb:99")
        facts = _facts_for(watcher, [], None)
        hctx = self._hctx(watcher, facts, conn_ok=True)
        with patch.object(watcher.LOOP_CTX, "publish_network_status"), \
             patch.object(watcher.LOOP_CTX, "next_mode", return_value=watcher.wifi_policy.Mode.ONLINE):
            watcher.wifi_loop.step_publish_state(watcher.LOOP_CTX, hctx)
        assert watcher.RECOVERY_STATE.failover_reset_done == set()

    # ---- transitioning defer-gates (§2.3) ----

    def test_deferred_handlers_hold_off_while_transitioning(self, watcher):
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:01", is_usb=True)
        facts = _facts_for(watcher, [usb], None, wifi_cfg=True)
        hctx = self._hctx(watcher, facts, conn_ok=True)
        watcher.STATE.transitioning = True
        with patch.object(watcher.LOOP_CTX, "handle_usb_failure_fallback") as usb_fb, \
             patch.object(watcher.LOOP_CTX, "handle_runtime_usb_adoption") as adopt, \
             patch.object(watcher.LOOP_CTX, "escalate_dead_adapter_recovery") as dead, \
             patch.object(watcher.LOOP_CTX, "submit_client_activation") as submit:
            assert watcher.wifi_loop.step_usb_failure_fallback(watcher.LOOP_CTX, hctx) is watcher.Verdict.CONTINUE
            assert watcher.wifi_loop.step_runtime_usb_adoption(watcher.LOOP_CTX, hctx) is watcher.Verdict.CONTINUE
            assert watcher.wifi_loop.step_dead_phy_recovery(watcher.LOOP_CTX, hctx) is watcher.Verdict.CONTINUE
            assert watcher.wifi_loop.step_boot_ap_entry(watcher.LOOP_CTX, hctx) is watcher.Verdict.CONTINUE
        usb_fb.assert_not_called()
        adopt.assert_not_called()
        dead.assert_not_called()
        submit.assert_not_called()

    def test_ethernet_wins_defers_enforcement_while_transitioning(self, watcher):
        facts = _facts_for(watcher, [], None, wired_ok=True)
        hctx = self._hctx(watcher, facts, conn_ok=True)
        watcher.STATE.setup_mode = True
        watcher.STATE.transitioning = True
        with patch.object(watcher, "leave_setup_mode") as leave, \
             patch.object(watcher, "run_cmd") as run:
            v = watcher.wifi_loop.step_ethernet_wins(watcher.LOOP_CTX, hctx)
        assert v is watcher.Verdict.OWN_PASS   # observed (owns pass)
        leave.assert_not_called()              # enforcement deferred
        run.assert_not_called()

    def test_hotspot_deadline_deferred_while_transitioning(self, watcher):
        watcher.STATE.setup_mode = True
        watcher.STATE.hotspot = watcher.HotspotSession(
            purpose=watcher.wifi_policy.HotspotPurpose.USB_LOSS_RECOVERY, entered_at=0.0)
        watcher.STATE.transitioning = True
        facts = _facts_for(watcher, [], None, wifi_cfg=True,
                           now=watcher.wifi_policy.AP_MAX_DURATION + 60.0)
        hctx = self._hctx(watcher, facts)
        with patch.object(watcher, "leave_setup_mode") as leave, \
             patch.object(watcher.LOOP_CTX, "attempt_recovery_reconnect") as probe:
            v = watcher.wifi_loop.step_hotspot_policy(watcher.LOOP_CTX, hctx)
        assert v is watcher.Verdict.OWN_PASS
        leave.assert_not_called()   # deadline observed, not enforced
        probe.assert_not_called()   # probe deferred


class TestBootEntryOnboardFirst:
    """Recovery ladder — boot-window entry tries a client before the hotspot."""

    def test_wedged_usb_boot_entry_submits_onboard_not_hotspot(self, watcher):
        # Field-log shape: USB active but declared wedged (debounced dead-PHY
        # verdict), onboard idle. Boot-window entry must SUBMIT the client on
        # the onboard rather than open a hotspot.  Reactivate-first
        # already spent this episode -> exercises the fall-through to onboard
        # specifically, not the reactivate-first rung ahead of it.
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "dc:62:79:91:4d:d6", is_usb=True)
        watcher.RECOVERY_STATE.dead_adapter_ifname = "wlan1"
        watcher.RECOVERY_STATE.wedged_reactivate_done.add(usb.stable_id)
        watcher.STATE.boot_time = 300.0  # now=1000 -> boot_age 700s, inside window
        with patch.object(watcher.LOOP_CTX, "submit_client_activation", return_value=True) as submit, \
             patch.object(watcher.LOOP_CTX, "enter_setup_mode") as enter, \
             patch.object(watcher.wifi_net, "read_link_down",
                          side_effect=lambda ifn: ifn == "wlan1"):
            _run_monitor_once(
                watcher, now=1000.0, wifi_cfg=True, wifi_connected=True,
                client_ok=False, adapters=[builtin, usb], active_client=usb,
            )
        submit.assert_called_once()
        action = submit.call_args[0][0]
        assert action.kind is watcher.wifi_policy.RecoveryKind.ACTIVATE_ONBOARD
        assert action.ifname == "wlan0"
        enter.assert_not_called()   # onboard submitted -> no hotspot this pass

    def test_onboard_budget_spent_boot_entry_falls_to_hotspot(self, watcher):
        # Once the onboard failure bound is reached the ladder stops
        # offering onboard, so boot entry falls to the recovery hotspot (the async
        # replacement for the old in-pass "onboard failed -> hotspot").
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        usb = _adapter(watcher, "wlan1", "dc:62:79:91:4d:d6", is_usb=True)
        watcher.STATE.boot_time = 300.0
        watcher.STATE.onboard_activation_failures = watcher.ONBOARD_ACTIVATION_MAX_FAILURES
        with patch.object(watcher.LOOP_CTX, "submit_client_activation") as submit, \
             patch.object(watcher.LOOP_CTX, "enter_setup_mode") as enter, \
             patch.object(watcher.wifi_net, "read_link_down",
                          side_effect=lambda ifn: ifn == "wlan1"):
            _run_monitor_once(
                watcher, now=1000.0, wifi_cfg=True, wifi_connected=True,
                client_ok=False, adapters=[builtin, usb], active_client=usb,
            )
        submit.assert_not_called()   # onboard budget spent, USB wedged -> no client path
        enter.assert_called_once()
        assert enter.call_args[0][0] is watcher.wifi_policy.HotspotPurpose.BOOT_RECOVERY


class TestLoopHandlers:
    """Loop handlers — direct per-handler tests over synthetic contexts.

    Isolation: the `watcher` fixture resets STATE (and the log-dedup cache); the
    event-setting tests clear the threading.Events they touch so they cannot leak.
    """

    def _pre(self, watcher, *, now=1000.0, boot_time=0.0, avahi_ok=True):
        return watcher.wifi_loop.PreFactsContext(now=now, boot_time=boot_time, avahi_ok=avahi_ok)

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
        fctx = watcher.wifi_loop.FactsContext(pre, facts, playing or (lambda: False))
        return watcher.wifi_loop.HealthContext(
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
        with patch.object(watcher.wifi_loop, "step_hotspot_policy",
                          return_value=watcher.Verdict.OWN_PASS) as hp, \
             patch.object(watcher.wifi_loop, "step_connection_reliability") as cr, \
             patch.object(watcher.wifi_loop, "step_catchall_reboot") as co:
            _run_monitor_once(watcher, now=1000.0, wifi_cfg=True)
        hp.assert_called_once()
        cr.assert_not_called()
        co.assert_not_called()

    # ---- Boot-recovery-not-after-online gate ----

    def test_boot_entry_skipped_after_online_this_boot(self, watcher):
        watcher.STATE.been_online_this_boot = True
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:41", is_usb=True)
        facts = self._facts(watcher, adapters=[usb], wifi_cfg=True, active_client=usb, now=100.0)
        hctx = self._hctx(watcher, facts, wifi_connected=True, client_ok=False, conn_ok=False)
        with patch.object(watcher.LOOP_CTX, "next_recovery_action") as nra, \
             patch.object(watcher, "enter_setup_mode") as enter:
            v = watcher.wifi_loop.step_boot_ap_entry(watcher.LOOP_CTX, hctx)
        assert v is watcher.Verdict.CONTINUE
        nra.assert_not_called()   # runtime paths own it, not boot-entry
        enter.assert_not_called()

    def test_boot_entry_runs_when_never_online(self, watcher):
        watcher.STATE.been_online_this_boot = False
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:42", is_usb=True)
        facts = self._facts(watcher, adapters=[usb], wifi_cfg=True, active_client=usb, now=100.0)
        hctx = self._hctx(watcher, facts, wifi_connected=True, client_ok=False, conn_ok=False)
        action = watcher.wifi_policy.RecoveryAction(watcher.wifi_policy.RecoveryKind.ENTER_HOTSPOT,
                                        purpose=watcher.wifi_policy.HotspotPurpose.BOOT_RECOVERY)
        with patch.object(watcher.LOOP_CTX, "gather_recovery_facts"), \
             patch.object(watcher.LOOP_CTX, "next_recovery_action", return_value=action) as nra, \
             patch.object(watcher.LOOP_CTX, "enter_setup_mode") as enter:
            v = watcher.wifi_loop.step_boot_ap_entry(watcher.LOOP_CTX, hctx)
        assert v is watcher.Verdict.OWN_PASS
        nra.assert_called_once()
        enter.assert_called_once()

    # ---- Phase A ----

    def test_step_avahi_hostname_gated_and_rate_limited(self, watcher):
        ls = watcher.wifi_loop.LoopState()
        with patch.object(watcher.LOOP_CTX, "check_and_repair_avahi_hostname") as chk:
            v = watcher.wifi_loop.step_avahi_hostname(watcher.LOOP_CTX, self._pre(watcher, now=1000.0), ls)
        assert v is watcher.Verdict.CONTINUE
        chk.assert_called_once()
        assert ls.last_avahi_check == 1000.0
        # Within AVAHI_CHECK_INTERVAL -> not called again.
        with patch.object(watcher.LOOP_CTX, "check_and_repair_avahi_hostname") as chk2:
            watcher.wifi_loop.step_avahi_hostname(watcher.LOOP_CTX, self._pre(watcher, now=1005.0), ls)
        chk2.assert_not_called()
        # avahi_ok False -> skipped regardless of interval.
        with patch.object(watcher.LOOP_CTX, "check_and_repair_avahi_hostname") as chk3:
            watcher.wifi_loop.step_avahi_hostname(watcher.LOOP_CTX, self._pre(watcher, now=99999.0, avahi_ok=False), ls)
        chk3.assert_not_called()

    def test_manual_ap_control_action_enters_when_not_in_ap(self, watcher):
        # A manual_ap control action enters a MANUAL hotspot via the shared
        # control channel.
        watcher.STATE.setup_mode = False
        with patch.object(watcher, "enter_setup_mode") as enter:
            watcher.process_control_action("manual_ap", {"reason": "user"})
        enter.assert_called_once()
        assert enter.call_args[0][0] is watcher.wifi_policy.HotspotPurpose.MANUAL
        assert watcher.CONTROL_STATE.last_control_result == "ok"

    def test_manual_ap_control_action_noop_when_already_in_ap(self, watcher):
        watcher.STATE.setup_mode = True
        with patch.object(watcher, "enter_setup_mode") as enter:
            watcher.process_control_action("manual_ap", {"reason": "user"})
        enter.assert_not_called()
        assert watcher.CONTROL_STATE.last_control_result == "ok"

    def test_manual_ap_control_action_is_disruptive(self, watcher):
        # step_control_action treats manual_ap as disruptive: it owns the pass and
        # is deferred (left queued) while an activation is in flight.
        watcher.STATE.setup_mode = False
        watcher.STATE.transitioning = False
        watcher.CONTROL_STATE.pending_control_action = "manual_ap"
        watcher.CONTROL_STATE.pending_control_params = {"reason": "user"}
        watcher.control_action_event.set()
        with patch.object(watcher, "enter_setup_mode"):
            v = watcher.wifi_loop.step_control_action(watcher.LOOP_CTX, self._pre(watcher))
        assert v is watcher.Verdict.OWN_PASS
        assert not watcher.control_action_event.is_set()

    def test_set_roaming_management_is_non_disruptive(self, watcher):
        # Like set_log_level, set_roaming_management touches no connectivity/AP
        # state: it is applied immediately, never deferred, and never owns the
        # pass, even while an activation is in flight.
        watcher.STATE.transitioning = True
        watcher.CONTROL_STATE.pending_control_action = "set_roaming_management"
        watcher.CONTROL_STATE.pending_control_params = {"managed": True}
        watcher.control_action_event.set()
        with patch.object(watcher, "get_configured_network_state",
                          return_value=watcher.wifi_net.NetworkState()), \
             patch.object(watcher.wifi_net, "save_network_state"):
            v = watcher.wifi_loop.step_control_action(watcher.LOOP_CTX, self._pre(watcher))
        assert v is watcher.Verdict.CONTINUE
        assert not watcher.control_action_event.is_set()
        assert watcher.ADOPTION_STATE.roaming_managed is True
        assert watcher.CONTROL_STATE.last_control_result == "ok"

    def test_manual_ap_control_action_deferred_while_transitioning(self, watcher):
        watcher.STATE.transitioning = True
        watcher.CONTROL_STATE.pending_control_action = "manual_ap"
        watcher.CONTROL_STATE.pending_control_params = {"reason": "user"}
        watcher.control_action_event.set()
        with patch.object(watcher, "enter_setup_mode") as enter:
            v = watcher.wifi_loop.step_control_action(watcher.LOOP_CTX, self._pre(watcher))
        assert v is watcher.Verdict.CONTINUE
        enter.assert_not_called()
        # Left queued for a later pass (never dropped).
        assert watcher.control_action_event.is_set()
        assert watcher.CONTROL_STATE.pending_control_action == "manual_ap"

    # ---- Phase B-late USB-failure fallback (over the debounced verdict) ----

    def test_step_usb_failure_fallback_owns_pass_on_fallback(self, watcher):
        # The handler is a Phase B-late handler over the HealthContext; it
        # delegates to handle_usb_failure_fallback(hctx) and owns the pass when a
        # transition fires.
        usb = _adapter(watcher, "wlan1", "dc:62:79:91:4d:d6", is_usb=True)
        facts = self._facts(watcher, adapters=[usb], wifi_cfg=True, active_client=usb)
        hctx = self._hctx(watcher, facts, conn_ok=False)
        with patch.object(watcher.LOOP_CTX, "handle_usb_failure_fallback", return_value=True) as h:
            v = watcher.wifi_loop.step_usb_failure_fallback(watcher.LOOP_CTX, hctx)
        assert v is watcher.Verdict.OWN_PASS
        h.assert_called_once_with(hctx)

    def test_step_usb_failure_fallback_continue_when_no_transition(self, watcher):
        usb = _adapter(watcher, "wlan1", "dc:62:79:91:4d:d6", is_usb=True)
        facts = self._facts(watcher, adapters=[usb], wifi_cfg=True, active_client=usb)
        hctx = self._hctx(watcher, facts, conn_ok=True)
        with patch.object(watcher.LOOP_CTX, "handle_usb_failure_fallback", return_value=False) as h:
            v = watcher.wifi_loop.step_usb_failure_fallback(watcher.LOOP_CTX, hctx)
        assert v is watcher.Verdict.CONTINUE
        h.assert_called_once_with(hctx)

    def test_step_usb_failure_fallback_skips_in_setup_mode(self, watcher):
        usb = _adapter(watcher, "wlan1", "dc:62:79:91:4d:d6", is_usb=True)
        facts = self._facts(watcher, adapters=[usb], wifi_cfg=True, active_client=usb)
        hctx = self._hctx(watcher, facts, conn_ok=False)
        watcher.STATE.setup_mode = True
        with patch.object(watcher.LOOP_CTX, "handle_usb_failure_fallback") as h:
            v = watcher.wifi_loop.step_usb_failure_fallback(watcher.LOOP_CTX, hctx)
        assert v is watcher.Verdict.CONTINUE
        h.assert_not_called()

    # ---- Phase B-late (pinned verdicts) ----

    def test_step_ethernet_wins_owns_pass_even_when_nothing_disconnects(self, watcher):
        facts = self._facts(watcher, wired_ok=True)
        hctx = self._hctx(watcher, facts, playing=lambda: False,
                          conn_ok=True, active_path_ok=True)
        with patch.object(watcher, "run_cmd") as run, \
             patch.object(watcher, "leave_setup_mode") as leave:
            v = watcher.wifi_loop.step_ethernet_wins(watcher.LOOP_CTX, hctx)
        assert v is watcher.Verdict.OWN_PASS  # owns on the predicate
        run.assert_not_called()               # nothing to disconnect
        leave.assert_not_called()

    def test_step_ethernet_wins_continue_when_not_wired(self, watcher):
        hctx = self._hctx(watcher, self._facts(watcher, wired_ok=False))
        assert watcher.wifi_loop.step_ethernet_wins(watcher.LOOP_CTX, hctx) is watcher.Verdict.CONTINUE

    def test_step_connection_reliability_always_continue(self, watcher):
        facts = self._facts(watcher, wifi_cfg=True, wired_ok=False)
        hctx = self._hctx(watcher, facts, conn_ok=False)
        with patch.object(watcher.LOOP_CTX, "connect_to_configured_wifi") as conn:
            v = watcher.wifi_loop.step_connection_reliability(watcher.LOOP_CTX, hctx)
        assert v is watcher.Verdict.CONTINUE   # never owns, even when it reconnects
        conn.assert_called_once()              # prompt reconnect on first entry
        assert watcher.STATE.conn_down_start == hctx.now

    def test_step_catchall_reboot_always_continue(self, watcher):
        watcher.STATE.last_active_path_seen = 0.0
        facts = self._facts(watcher, now=watcher.NO_ACTIVE_PATH_REBOOT_AFTER + 100.0)
        hctx = self._hctx(watcher, facts)
        with patch.object(watcher.LOOP_CTX, "request_network_down_reboot") as reboot:
            v = watcher.wifi_loop.step_catchall_reboot(watcher.LOOP_CTX, hctx)
        assert v is watcher.Verdict.CONTINUE
        reboot.assert_called_once()


class TestExplicitModeClassifier:
    """The loop applies the pure next_mode classifier.

    The pure next_mode state->Mode cases moved to tests/test_wifi_policy.py;
    these remaining tests verify the loop *applies* the
    classifier and publishes it as device.mode.
    """

    def test_loop_applies_authoritative_state_mode(self, watcher):
        # The loop applies the classifier by setting STATE.mode each full pass.
        _run_monitor_once(watcher, now=1000.0, wifi_cfg=True,
                          wifi_connected=True, client_ok=True)
        assert watcher.STATE.mode is watcher.wifi_policy.Mode.ONLINE

    def test_snapshot_publishes_authoritative_state_mode(self, watcher):
        # device.mode publishes the authoritative STATE.mode the loop applies.
        usb = _adapter(watcher, "wlan0", "AA:BB:CC:DD:EE:09", is_usb=True)
        watcher.STATE.setup_mode = True
        watcher.STATE.mode = watcher.wifi_policy.Mode.HOTSPOT
        with patch.object(watcher.wifi_net, "list_interface_addresses", return_value={}), \
             patch.object(watcher.wifi_net, "read_link_down", return_value=False), \
             patch.object(watcher.wifi_net, "read_operstate", return_value="up"), \
             patch.object(watcher.wifi_net, "default_gateway_ipv4", return_value=""), \
             patch.object(watcher.RECOVERY_CTX, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.STATUS_CTX, "resolve_hotspot_adapter", return_value=usb):
            snap = watcher.wifi_status.build_network_status_snapshot(watcher.STATUS_CTX, [usb], wired_connected=False, wired_ok=False)
        assert snap["device"]["mode"] == "hotspot"


class TestPerTickFactsSnapshot:
    """One immutable Facts snapshot gathered per pass (Section 2.5)."""

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
            stack.enter_context(patch.object(watcher.LOOP_CTX, "check_and_repair_avahi_hostname"))
            stack.enter_context(patch.object(watcher.LOOP_CTX, "maybe_reannounce_mdns"))
            stack.enter_context(patch.object(watcher.LOOP_CTX, "revert_expired_log_level"))
            stack.enter_context(patch.object(watcher, "is_wifi_configured", return_value=True))
            stack.enter_context(patch.object(watcher, "is_wired_connected", wired_conn))
            stack.enter_context(patch.object(watcher, "any_wired_path_healthy", wired_ok))
            stack.enter_context(patch.object(watcher.wifi_net, "discover_adapters", discover))
            stack.enter_context(patch.object(watcher.wifi_net, "list_interface_addresses", addrs))
            stack.enter_context(patch.object(watcher.LOOP_CTX, "update_known_adapters"))
            stack.enter_context(patch.object(watcher.wifi_adoption, "resolve_active_client", resolve_active))
            stack.enter_context(patch.object(watcher.LOOP_CTX, "handle_usb_failure_fallback", return_value=False))
            stack.enter_context(patch.object(watcher.wifi_net, "is_wifi_connected", return_value=True))
            stack.enter_context(patch.object(watcher, "is_wifi_client_healthy", return_value=True))
            stack.enter_context(patch.object(watcher.LOOP_CTX, "handle_runtime_usb_adoption", return_value=False))
            stack.enter_context(patch.object(watcher.LOOP_CTX, "escalate_dead_adapter_recovery", _record_dead))
            stack.enter_context(patch.object(watcher.LOOP_CTX, "publish_network_status", _record_publish))
            stack.enter_context(patch.object(watcher.LOOP_CTX, "log_on_change"))
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
        # per pass (the per-pass subprocess ceiling; a later change may not raise it).
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
             patch.object(watcher.wifi_adoption, "resolve_active_client", return_value=builtin):
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
        with patch.object(watcher.LOOP_CTX, "leave_setup_mode") as leave, \
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
            purpose=watcher.wifi_policy.HotspotPurpose.MANUAL, entered_at=now - 10.0)
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
    """Usable wired Ethernet wins regardless of subnet; one playback gate."""

    def _run_with_active_wifi(self, watcher, *, playing=False, setup=False):
        now = 1000.0
        wifi = _adapter(watcher, "wlan1", "aa:bb:cc:00:00:02", is_usb=True)
        watcher.STATE.setup_mode = setup
        with patch.object(watcher, "query_playing_status", return_value=playing), \
             patch.object(watcher.nm, "disconnect_device") as run:
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
        run.assert_called_once_with("wlan1")
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
        watcher.APPLY_STATE.apply_in_progress = True
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
