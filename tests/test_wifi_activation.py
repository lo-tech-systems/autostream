"""Activation worker, job/result plumbing, client_up_tail, and the
candidate-apply flow."""
from __future__ import annotations

import contextlib
import json
import logging
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


class TestClientUpTail:
    """The single shared 'a client came up' choreography (client_up_tail)."""

    def _adapter(self, ifname="wlan1", mac="AA:BB:CC:DD:EE:01", stable_id="usb0"):
        a = MagicMock()
        a.ifname = ifname
        a.permanent_mac = mac
        a.stable_id = stable_id
        a.kind = "usb_wifi"
        return a

    def test_sets_active_and_verifies_avahi(self, watcher):
        a = self._adapter()
        with patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover") as avahi:
            watcher.wifi_activation.client_up_tail(watcher.ACTIVATION_CTX, a)
        assert watcher.STATE.active_client_ifname == "wlan1"
        avahi.assert_called_once()

    def test_none_adapter_skips_set_active(self, watcher):
        watcher.STATE.active_client_ifname = "wlan0"
        watcher.STATE.active_client_mac = "prev"
        with patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"), \
             patch.object(watcher.wifi_activation, "_set_active_client") as sac:
            watcher.wifi_activation.client_up_tail(watcher.ACTIVATION_CTX, None)
        sac.assert_not_called()

    def test_disconnect_builtin_runs_nmcli(self, watcher):
        a = self._adapter()
        with patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"), \
             patch.object(watcher.nm, "disconnect_device") as disc:
            watcher.wifi_activation.client_up_tail(
                watcher.ACTIVATION_CTX, a,
                watcher.wifi_recovery.TailSpec(disconnect_builtin_ifname="wlan0"))
        disc.assert_called_once_with("wlan0")

    def test_empty_disconnect_ifname_skips_nmcli(self, watcher):
        a = self._adapter()
        with patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"), \
             patch.object(watcher.nm, "disconnect_device") as disc:
            watcher.wifi_activation.client_up_tail(
                watcher.ACTIVATION_CTX, a,
                watcher.wifi_recovery.TailSpec(disconnect_builtin_ifname=""))
        disc.assert_not_called()

    def test_set_builtin_fallback_flags(self, watcher):
        a = self._adapter()
        with patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"):
            watcher.ADOPTION_STATE.using_builtin_fallback = True
            watcher.wifi_activation.client_up_tail(
                watcher.ACTIVATION_CTX, a,
                watcher.wifi_recovery.TailSpec(set_builtin_fallback=None))   # None -> untouched
            assert watcher.ADOPTION_STATE.using_builtin_fallback is True
            watcher.wifi_activation.client_up_tail(
                watcher.ACTIVATION_CTX, a,
                watcher.wifi_recovery.TailSpec(set_builtin_fallback=False))
            assert watcher.ADOPTION_STATE.using_builtin_fallback is False
            watcher.wifi_activation.client_up_tail(
                watcher.ACTIVATION_CTX, a,
                watcher.wifi_recovery.TailSpec(set_builtin_fallback=True))
            assert watcher.ADOPTION_STATE.using_builtin_fallback is True

    def test_clears_timers_and_onboard_bound(self, watcher):
        a = self._adapter()
        watcher.STATE.conn_down_start = 5.0
        watcher.STATE.last_reconnect_attempt = 5.0
        watcher.STATE.onboard_activation_failures = 2
        with patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"):
            watcher.wifi_activation.client_up_tail(
                watcher.ACTIVATION_CTX, a,
                watcher.wifi_recovery.TailSpec(clear_down_timers=True, reset_onboard_bound=True))
        assert watcher.STATE.conn_down_start is None
        assert watcher.STATE.last_reconnect_attempt is None
        assert watcher.STATE.onboard_activation_failures == 0

    def test_clears_noip_ledger_when_stable_id_given(self, watcher):
        a = self._adapter()
        with patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"), \
             patch.object(watcher.wifi_recovery, "clear_noip_failures") as clr:
            watcher.wifi_activation.client_up_tail(
                watcher.ACTIVATION_CTX, a,
                watcher.wifi_recovery.TailSpec(clear_noip_stable_id="usb0"))
            clr.assert_called_once()
            clr.reset_mock()
            watcher.wifi_activation.client_up_tail(
                watcher.ACTIVATION_CTX, a,
                watcher.wifi_recovery.TailSpec(clear_noip_stable_id=None))
            clr.assert_not_called()

    def test_leave_setup_reason_forwarded(self, watcher):
        a = self._adapter()
        with patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"), \
             patch.object(watcher.ACTIVATION_CTX, "leave_setup_mode") as leave:
            watcher.wifi_activation.client_up_tail(
                watcher.ACTIVATION_CTX, a,
                watcher.wifi_recovery.TailSpec(leave_setup_reason="done"))
            leave.assert_called_once_with("done")
            leave.reset_mock()
            watcher.wifi_activation.client_up_tail(
                watcher.ACTIVATION_CTX, a,
                watcher.wifi_recovery.TailSpec(leave_setup_reason=None))
            leave.assert_not_called()

    def test_clear_dead_adapter_and_pending_adoption(self, watcher):
        a = self._adapter()
        with patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"), \
             patch.object(watcher.ACTIVATION_CTX, "clear_pending_adoption") as cpa, \
             patch.object(watcher.wifi_recovery, "clear_dead_adapter_state") as cda:
            watcher.wifi_activation.client_up_tail(
                watcher.ACTIVATION_CTX, a,
                watcher.wifi_recovery.TailSpec(clear_pending_adoption=True, clear_dead_adapter=True))
        cpa.assert_called_once()
        cda.assert_called_once()

    def test_stamps_roam_holdoff_on_every_successful_activation(self, watcher):
        # UP-2's roam holdoff is documented as gating on "the last roam or
        # successful activation"; client_up_tail is the single success tail
        # every activation path (bring-up, reconnect, adoption, dead-PHY
        # recovery) funnels through, so it must stamp the same field the roam
        # submission does.
        a = self._adapter()
        watcher.ADOPTION_STATE.last_roam_or_activation = None
        with patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"):
            watcher.wifi_activation.client_up_tail(watcher.ACTIVATION_CTX, a)
        assert watcher.ADOPTION_STATE.last_roam_or_activation is not None

    def test_fresh_activation_defers_next_roam(self, watcher):
        # End-to-end: a successful activation must hold off the very next
        # survey pass's roam, not just a prior roam submission.
        a = self._adapter()
        with patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"):
            watcher.wifi_activation.client_up_tail(watcher.ACTIVATION_CTX, a)
        now = watcher.ADOPTION_STATE.last_roam_or_activation + 1.0  # well under ROAM_HOLDOFF_SECS
        table = {
            "AA:BB:CC:DD:EE:01": {"ssid": "Home", "signal": 50, "last_seen": now,
                                  "fail_count": 0, "quarantined_until": None},
            "AA:BB:CC:DD:EE:02": {"ssid": "Home", "signal": 90, "last_seen": now,
                                  "fail_count": 0, "quarantined_until": None},
        }
        target = watcher.wifi_policy.next_roam_target(
            table, "AA:BB:CC:DD:EE:01", now, False, watcher.ADOPTION_STATE.last_roam_or_activation)
        assert target == ""


class TestActivationWorker:
    """The off-thread activation worker skeleton: job/result split,
    single-slot queue + transitioning gate, result application at pass top, and
    the peek-then-consume control-action deferral.  No call sites are migrated yet,
    so these drive the skeleton directly."""

    def _job(self, watcher, **kw):
        defaults = dict(epoch=watcher.wifi_activation._next_activation_epoch(watcher.ACTIVATION_CTX), kind="activate_committed",
                        ifname="wlan1")
        defaults.update(kw)
        return watcher.wifi_activation.ActivationJob(**defaults)

    # ---- the split: _run_activation_job (worker half) ----

    def test_run_job_empty_ifname_fails(self, watcher):
        job = self._job(watcher, ifname="")
        r = watcher.wifi_activation._run_activation_job(watcher.ACTIVATION_CTX, job)
        assert r.ok is False and r.error == "no_ifname"

    def test_run_job_success_carries_job_and_epoch(self, watcher):
        job = self._job(watcher)
        with patch.object(watcher.wifi_activation, "_activate_committed_on", return_value=True):
            r = watcher.wifi_activation._run_activation_job(watcher.ACTIVATION_CTX, job)
        assert r.ok is True and r.ifname == "wlan1" and r.job is job and r.epoch == job.epoch

    def test_run_job_drops_and_rebuilds_ap_on_failure(self, watcher):
        # Worker owns symmetric AP drop-for-attempt + rebuild-on-own-failure.
        watcher.STATE.setup_mode = True
        job = self._job(watcher, drop_hotspot=True)
        with patch.object(watcher.wifi_activation, "_activate_committed_on", return_value=False), \
             patch.object(watcher.ACTIVATION_CTX, "stop_ap_mode") as stop_ap, \
             patch.object(watcher.HOTSPOT_CTX, "start_ap_mode") as start_ap, \
             patch.object(watcher.HOTSPOT_CTX, "update_apmode_flag") as apflag:
            r = watcher.wifi_activation._run_activation_job(watcher.ACTIVATION_CTX, job)
        assert r.ok is False
        stop_ap.assert_called_once()
        start_ap.assert_called_once()
        apflag.assert_called_once_with(True)

    def test_command_timeout_yields_failure_result(self, watcher):
        # A hung nmcli killed by run_cmd(timeout=…) returns rc 124 -> validation
        # fails -> the job result is ok=False (the loop then clears the gate).
        state = watcher.wifi_net.NetworkState(connection_name="Home", connection_uuid="u1")
        timed_out = MagicMock(returncode=124, stderr="")
        job = self._job(watcher, kind="activate_profile", profile=state)
        with patch.object(watcher.ACTIVATION_CTX, "_resolve_committed_uuid", return_value="u1"), \
             patch.object(watcher, "run_cmd", return_value=timed_out), \
             patch.object(watcher, "wait_for_connection", return_value=False):
            r = watcher.wifi_activation._run_activation_job(watcher.ACTIVATION_CTX, job)
        assert r.ok is False

    # ---- submit / drain / transitioning gate ----

    def test_submit_sets_transitioning_and_second_submit_deferred(self, watcher):
        job = self._job(watcher)
        assert watcher.wifi_activation.submit_activation_job(watcher.ACTIVATION_CTX, job) is True
        assert watcher.STATE.transitioning is True
        assert watcher.wifi_activation.get_inflight_activation_epoch() == job.epoch
        # A second submit while transitioning is refused (belt-and-braces gate).
        assert watcher.wifi_activation.submit_activation_job(watcher.ACTIVATION_CTX, self._job(watcher)) is False

    def test_worker_thread_processes_job_and_posts_result(self, watcher):
        job = self._job(watcher)
        with patch.object(watcher.wifi_activation, "_activate_committed_on", return_value=True):
            watcher.wifi_activation.submit_activation_job(watcher.ACTIVATION_CTX, job)
            t = watcher.wifi_activation.start_activation_worker(watcher.ACTIVATION_CTX)
            try:
                assert watcher.wifi_activation.activation_result_event.wait(timeout=5.0)
                result = watcher.wifi_activation.drain_activation_result()
            finally:
                watcher.wifi_activation._activation_job_queue.put(None)  # stop sentinel
                t.join(timeout=5.0)
        assert result is not None and result.ok is True and result.epoch == job.epoch

    def test_step_apply_applies_tail_and_clears_gate(self, watcher):
        job = self._job(watcher, on_success_leaves_setup=True, leave_reason="done")
        watcher.wifi_activation.submit_activation_job(watcher.ACTIVATION_CTX, job)          # sets transitioning + inflight epoch
        watcher.wifi_activation._activation_job_queue.get_nowait()  # (don't run the real worker)
        watcher.wifi_activation._post_activation_result(
            watcher.wifi_activation.ActivationResult(job.epoch, True, "wlan1", job))
        with patch.object(watcher.wifi_activation, "apply_activation_result", return_value=True) as apply:
            v = watcher.wifi_activation.step_apply_activation_result(watcher.ACTIVATION_CTX, self._pre(watcher))
        assert v is watcher.Verdict.CONTINUE
        apply.assert_called_once()
        assert watcher.STATE.transitioning is False
        assert watcher.wifi_activation.get_inflight_activation_epoch() is None

    def test_step_apply_no_result_is_noop(self, watcher):
        with patch.object(watcher.wifi_activation, "apply_activation_result") as apply:
            v = watcher.wifi_activation.step_apply_activation_result(watcher.ACTIVATION_CTX, self._pre(watcher))
        assert v is watcher.Verdict.CONTINUE
        apply.assert_not_called()

    def test_step_apply_stale_epoch_discarded_but_gate_cleared(self, watcher):
        job = self._job(watcher)
        watcher.wifi_activation.submit_activation_job(watcher.ACTIVATION_CTX, job)
        watcher.wifi_activation._activation_job_queue.get_nowait()
        # Post a result with a mismatched epoch (defensive path).
        watcher.wifi_activation._post_activation_result(
            watcher.wifi_activation.ActivationResult(job.epoch + 999, True, "wlan1", job))
        with patch.object(watcher.wifi_activation, "apply_activation_result") as apply:
            watcher.wifi_activation.step_apply_activation_result(watcher.ACTIVATION_CTX, self._pre(watcher))
        apply.assert_not_called()                  # stale -> discarded
        assert watcher.STATE.transitioning is False  # but the gate is cleared

    def _pre(self, watcher):
        return watcher.wifi_loop.PreFactsContext(now=1000.0, boot_time=0.0, avahi_ok=True)

    # ---- peek-then-consume control action (§3.6) ----

    def test_disruptive_control_action_deferred_while_transitioning(self, watcher):
        watcher.STATE.transitioning = True
        watcher.CONTROL_STATE.pending_control_action = "start_setup"
        watcher.CONTROL_STATE.pending_control_params = {}
        watcher.control_action_event.set()
        with patch.object(watcher.LOOP_CTX, "process_control_action") as proc:
            v = watcher.wifi_loop.step_control_action(watcher.LOOP_CTX, self._pre(watcher))
        assert v is watcher.Verdict.CONTINUE
        proc.assert_not_called()                       # not consumed
        assert watcher.CONTROL_STATE.pending_control_action == "start_setup"  # left queued
        assert watcher.control_action_event.is_set()

        # Once the transition completes, the queued action is applied exactly once.
        watcher.STATE.transitioning = False
        with patch.object(watcher.LOOP_CTX, "process_control_action") as proc:
            v = watcher.wifi_loop.step_control_action(watcher.LOOP_CTX, self._pre(watcher))
        assert v is watcher.Verdict.OWN_PASS
        proc.assert_called_once()
        assert watcher.CONTROL_STATE.pending_control_action == ""

    def test_set_log_level_applied_even_while_transitioning(self, watcher):
        watcher.STATE.transitioning = True
        watcher.CONTROL_STATE.pending_control_action = "set_log_level"
        watcher.CONTROL_STATE.pending_control_params = {"level": "debug"}
        watcher.control_action_event.set()
        with patch.object(watcher.LOOP_CTX, "process_control_action") as proc:
            v = watcher.wifi_loop.step_control_action(watcher.LOOP_CTX, self._pre(watcher))
        assert v is watcher.Verdict.CONTINUE           # non-disruptive: pass continues
        proc.assert_called_once()                      # applied immediately
        assert watcher.CONTROL_STATE.pending_control_action == ""  # consumed
        assert not watcher.control_action_event.is_set()


class TestResetBeforeFailover:
    """RF-2 — a RESET_USB job (``reset_before=True``) spends one budgeted reset
    before running the normal activation core on the resolved (possibly
    renamed) interface; a failed job never stacks a second reset via the
    in-job implicated-failure retry."""

    def _job(self, watcher, **kw):
        defaults = dict(epoch=watcher.wifi_activation._next_activation_epoch(watcher.ACTIVATION_CTX),
                        kind="activate_committed", ifname="wlan1", reset_before=True)
        defaults.update(kw)
        return watcher.wifi_activation.ActivationJob(**defaults)

    def _target(self, watcher, ifname="wlan1", stable_id="m1", resettable=True):
        return watcher.wifi_recovery.TargetAdapter(
            ifname=ifname, stable_id=stable_id, kind="usb_wifi", is_usb=True,
            is_builtin=False, present_in_nm=True, present_in_sysfs=True,
            resettable_usb=resettable)

    def test_reset_then_activates_on_resolved_ifname(self, watcher):
        job = self._job(watcher)
        with patch.object(watcher.wifi_net, "discover_adapters", return_value=[]), \
             patch.object(watcher.wifi_recovery, "build_target_adapter",
                          return_value=self._target(watcher)), \
             patch.object(watcher.wifi_recovery, "record_adapter_reset") as record, \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind") as rebind, \
             patch.object(watcher.wifi_recovery, "wait_for_interface_reappears",
                          return_value="wlan2") as reappear, \
             patch.object(watcher.wifi_activation, "_activate_committed_on",
                          return_value=True) as core:
            r = watcher.wifi_activation._run_activation_job(watcher.ACTIVATION_CTX, job)
        record.assert_called_once()
        rebind.assert_called_once_with("wlan1")
        reappear.assert_called_once()
        core.assert_called_once_with(watcher.ACTIVATION_CTX, "wlan2")
        assert r.ok is True
        assert r.ifname == "wlan2"

    def test_success_applies_normal_recovery_tail(self, watcher):
        # End-to-end: the worker result, applied on the loop thread, sets the
        # active client exactly like a normal (non-reset) USB recovery job.
        usb = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:60", is_usb=True)
        job = self._job(watcher, stable_id=usb.stable_id, records_noip=True,
                        clears_down_timers=True)
        with patch.object(watcher.wifi_net, "discover_adapters", return_value=[]), \
             patch.object(watcher.wifi_recovery, "build_target_adapter",
                          return_value=self._target(watcher, stable_id=usb.stable_id)), \
             patch.object(watcher.wifi_recovery, "record_adapter_reset"), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind"), \
             patch.object(watcher.wifi_recovery, "wait_for_interface_reappears",
                          return_value="wlan1"), \
             patch.object(watcher.wifi_activation, "_activate_committed_on", return_value=True), \
             patch.object(watcher.wifi_net, "find_adapter_by_ifname", return_value=usb), \
             patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"):
            r = watcher.wifi_activation._run_activation_job(watcher.ACTIVATION_CTX, job)
            watcher.wifi_activation.apply_activation_result(watcher.ACTIVATION_CTX, r)
        assert watcher.STATE.active_client_ifname == "wlan1"
        assert watcher.STATE.active_client_mac == usb.permanent_mac

    def test_no_reappear_fails_cleanly_without_activating(self, watcher):
        job = self._job(watcher)
        with patch.object(watcher.wifi_net, "discover_adapters", return_value=[]), \
             patch.object(watcher.wifi_recovery, "build_target_adapter",
                          return_value=self._target(watcher)), \
             patch.object(watcher.wifi_recovery, "record_adapter_reset") as record, \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind"), \
             patch.object(watcher.wifi_recovery, "wait_for_interface_reappears", return_value=""), \
             patch.object(watcher.wifi_activation, "_activate_committed_on") as core:
            r = watcher.wifi_activation._run_activation_job(watcher.ACTIVATION_CTX, job)
        assert r.ok is False
        assert r.error == "reset_no_reappear"
        assert r.ifname == "wlan1"
        core.assert_not_called()
        record.assert_called_once()   # exactly the one reset, no second attempt

    def test_activation_failure_does_not_stack_a_second_reset(self, watcher):
        # The interface reappears but the join itself fails; even with a scan
        # strong enough to normally implicate the adapter, a reset_before job
        # must not spend a second reset via the implicated-failure retry.
        watcher.ADOPTION_STATE.last_bssid_pin = {
            "ifname": "wlan1", "bssid": "AA:BB:CC:DD:EE:FF",
            "signal": watcher.wifi_activation.PIN_IMPLICATE_SIGNAL, "at": 0.0,
        }
        job = self._job(watcher)
        with patch.object(watcher.wifi_net, "discover_adapters", return_value=[]), \
             patch.object(watcher.wifi_recovery, "build_target_adapter",
                          return_value=self._target(watcher)), \
             patch.object(watcher.wifi_recovery, "record_adapter_reset") as record, \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind") as rebind, \
             patch.object(watcher.wifi_recovery, "wait_for_interface_reappears",
                          return_value="wlan1"), \
             patch.object(watcher.wifi_activation, "_activate_committed_on", return_value=False), \
             patch.object(watcher.wifi_activation, "_retry_after_implicated_failure") as retry:
            r = watcher.wifi_activation._run_activation_job(watcher.ACTIVATION_CTX, job)
        assert r.ok is False
        retry.assert_not_called()
        record.assert_called_once()
        rebind.assert_called_once()

    def test_reset_reflected_in_ledger_snapshot(self, watcher):
        target = self._target(watcher, stable_id="reset-snap-mac")
        job = self._job(watcher, stable_id="reset-snap-mac")
        with patch.object(watcher.wifi_net, "discover_adapters", return_value=[]), \
             patch.object(watcher.wifi_recovery, "build_target_adapter", return_value=target), \
             patch.object(watcher.wifi_net, "reset_usb_adapter_rebind"), \
             patch.object(watcher.wifi_recovery, "wait_for_interface_reappears",
                          return_value="wlan1"), \
             patch.object(watcher.wifi_activation, "_activate_committed_on", return_value=True):
            watcher.wifi_activation._run_activation_job(watcher.ACTIVATION_CTX, job)
        snapshot = watcher.wifi_recovery.adapter_reset_ledger_snapshot(
            watcher.RECOVERY_CTX, target, time.monotonic())
        assert snapshot["total_resets"] == 1


class TestActivateClient:
    """Flag-matrix unit tests for the worker-half + loop-half tail composition.

    These drive the composition directly (_run_activation_job then
    apply_activation_result) so the tail-flag matrix stays covered."""

    def _run(self, watcher, ifname="wlan1", *, profile=None, **flags):
        wait = flags.get("wait_for_validation", True)
        kind = "activate_committed" if (profile is None and wait) else "activate_profile"
        job = watcher.wifi_activation.ActivationJob(
            epoch=watcher.wifi_activation._next_activation_epoch(watcher.ACTIVATION_CTX), kind=kind, ifname=ifname,
            profile=profile, **flags)
        result = watcher.wifi_activation._run_activation_job(watcher.ACTIVATION_CTX, job)
        return watcher.wifi_activation.apply_activation_result(watcher.ACTIVATION_CTX, result)

    @contextlib.contextmanager
    def _harness(self, watcher, *, core_ok=True, target=None):
        """Patch the activation core and all tail effects.

        Yields a dict of the effect mocks so a test can assert on them.  The
        core (_activate_committed_on / _activate_profile_on) is patched to
        return ``core_ok``; discovery resolves ``target`` for the ifname.
        """
        tgt = target if target is not None else _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:aa", is_usb=True)
        with patch.object(watcher.wifi_activation, "_activate_committed_on", return_value=core_ok) as core, \
             patch.object(watcher.wifi_activation, "_activate_profile_on", return_value=core_ok) as core2, \
             patch.object(watcher.wifi_activation, "_set_active_client") as set_active, \
             patch.object(watcher.ACTIVATION_CTX, "leave_setup_mode") as leave, \
             patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover") as avahi, \
             patch.object(watcher.ACTIVATION_CTX, "stop_ap_mode") as stop_ap, \
             patch.object(watcher.HOTSPOT_CTX, "start_ap_mode") as start_ap, \
             patch.object(watcher.HOTSPOT_CTX, "update_apmode_flag") as apflag, \
             patch.object(watcher, "run_cmd", return_value=MagicMock(returncode=0)) as run_cmd, \
             patch.object(watcher.nm, "disconnect_device") as nm_disconnect, \
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
                "nm_disconnect": nm_disconnect,
                "clear_noip": clear_noip, "record_noip": record_noip, "target": tgt,
            }

    def test_success_minimal_tail(self, watcher):
        with self._harness(watcher) as h:
            ok = self._run(watcher, "wlan1")
        assert ok is True
        h["set_active"].assert_called_once_with(watcher.ACTIVATION_CTX, h["target"])
        h["clear_noip"].assert_called_once()
        h["avahi"].assert_called_once()
        h["leave"].assert_not_called()          # no on_success_leaves_setup
        h["record_noip"].assert_not_called()

    def test_success_does_not_touch_builtin_fallback_or_timers_by_default(self, watcher):
        watcher.ADOPTION_STATE.using_builtin_fallback = True
        watcher.STATE.conn_down_start = 123.0
        with self._harness(watcher):
            self._run(watcher, "wlan1")
        assert watcher.ADOPTION_STATE.using_builtin_fallback is True   # untouched (flag None)
        assert watcher.STATE.conn_down_start == 123.0         # untouched

    def test_sets_builtin_fallback_and_clears_timers(self, watcher):
        watcher.STATE.conn_down_start = 5.0
        watcher.STATE.last_reconnect_attempt = 6.0
        with self._harness(watcher):
            self._run(watcher, "wlan1", sets_builtin_fallback=True,
                                    clears_down_timers=True)
        assert watcher.ADOPTION_STATE.using_builtin_fallback is True
        assert watcher.STATE.conn_down_start is None
        assert watcher.STATE.last_reconnect_attempt is None

    def test_on_success_leaves_setup(self, watcher):
        with self._harness(watcher) as h:
            self._run(watcher, "wlan1", on_success_leaves_setup=True,
                                    leave_reason="done")
        h["leave"].assert_called_once_with("done")

    def test_drop_hotspot_when_in_setup_then_success_no_rebuild(self, watcher):
        watcher.STATE.setup_mode = True
        with self._harness(watcher) as h:
            self._run(watcher, "wlan1", drop_hotspot=True)
        h["stop_ap"].assert_called_once()
        h["start_ap"].assert_not_called()       # success -> no rebuild

    def test_drop_hotspot_rebuilds_on_failure(self, watcher):
        watcher.STATE.setup_mode = True
        with self._harness(watcher, core_ok=False) as h:
            ok = self._run(watcher, "wlan1", drop_hotspot=True)
        assert ok is False
        h["stop_ap"].assert_called_once()
        h["start_ap"].assert_called_once()
        h["apflag"].assert_called_once_with(True)
        assert watcher.STATE.setup_mode is True

    def test_drop_hotspot_skipped_when_not_in_setup(self, watcher):
        watcher.STATE.setup_mode = False
        with self._harness(watcher) as h:
            self._run(watcher, "wlan1", drop_hotspot=True)
        h["stop_ap"].assert_not_called()

    def test_records_noip_on_failure(self, watcher):
        with self._harness(watcher, core_ok=False) as h:
            ok = self._run(watcher, "wlan1", records_noip=True,
                                         stable_id="sid-1", noip_at=42.0)
        assert ok is False
        h["record_noip"].assert_called_once()
        args = h["record_noip"].call_args[0]
        assert args[1] == "sid-1" and args[2] == 42.0
        h["set_active"].assert_not_called()      # no success tail on failure
        h["avahi"].assert_not_called()

    def test_disconnects_previous_ifname_on_success(self, watcher):
        # The runtime-adoption handover carries the previous client's ifname; the
        # success tail disconnects it (transactional: only after the new one is up).
        with self._harness(watcher) as h:
            self._run(watcher, "wlan1", disconnects_previous_ifname="wlan0")
        h["nm_disconnect"].assert_called_once_with("wlan0")

    def test_wait_for_validation_false_is_fire_and_forget(self, watcher):
        with self._harness(watcher) as h:
            ok = self._run(watcher, "wlan1", wait_for_validation=False)
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
            self._run(watcher, "wlan1", profile=rollback)
        h["core2"].assert_called_once()
        assert h["core2"].call_args[0][2] is rollback
        h["core"].assert_not_called()

    def test_empty_ifname_returns_false(self, watcher):
        with self._harness(watcher) as h:
            assert self._run(watcher, "") is False
        h["core"].assert_not_called()


class TestCandidateValidateTail:
    """_try_candidate_on_adapter validates via the shared tail, so the
    net-absent short-circuit reaches the credential-apply path too."""

    def test_candidate_netabsent_skips_ipv4_wait_and_deletes(self, watcher):
        target = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:aa", is_usb=True)
        absent = MagicMock(
            returncode=10,
            stderr="Error: activation failed: The Wi-Fi network could not be found")
        with patch.object(watcher.wifi_net, "configure_candidate_cmds",
                          return_value=([["nmcli", "connection", "add"]], ["nmcli connection add"])), \
             patch.object(watcher.wifi_net, "get_profile_uuid", return_value="cand-uuid"), \
             patch.object(watcher.nm, "run_candidate_setup", return_value=MagicMock(returncode=0)), \
             patch.object(watcher.nm, "clear_restrictions"), \
             patch.object(watcher.nm, "activate", return_value=absent), \
             patch.object(watcher.nm, "delete_by_uuid") as delete_uuid, \
             patch.object(watcher, "wait_for_connection") as wait:
            ok = watcher._try_candidate_on_adapter("SSID", "pw", target)

        assert ok is False
        wait.assert_not_called()   # net-absent short-circuit reached the candidate path
        delete_uuid.assert_called_once_with("cand-uuid")   # failed candidate deleted by uuid


class TestAttemptOnTargets:
    def test_non_hotspot_target_returns_target_without_applying_tail(self, watcher):
        # IF-2: attempt_on_targets returns the successful adapter and applies NO
        # session tail itself (it can run on the worker thread); the caller does.
        hotspot = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        target = _adapter(watcher, "wlan1", "aa:bb:cc:00:00:02", is_usb=True)
        watcher.STATE.setup_mode = True

        with patch.object(watcher.wifi_net, "discover_adapters", return_value=[hotspot, target]), \
             patch.object(watcher, "resolve_hotspot_adapter", return_value=hotspot), \
             patch.object(watcher, "stop_ap_mode") as stop_ap, \
             patch.object(watcher, "start_ap_mode") as start_ap, \
             patch.object(watcher.wifi_activation, "_set_active_client") as set_active, \
             patch.object(watcher.ACTIVATION_CTX, "leave_setup_mode") as leave, \
             patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover") as avahi:
            result = watcher.attempt_on_targets([target], lambda adapter: adapter.ifname == "wlan1")

        assert result is target
        stop_ap.assert_not_called()
        start_ap.assert_not_called()
        # The success tail is the caller's responsibility now.
        set_active.assert_not_called()
        leave.assert_not_called()
        avahi.assert_not_called()

    def test_hotspot_target_failure_rebuilds_ap(self, watcher):
        hotspot = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        watcher.STATE.setup_mode = True

        with patch.object(watcher.wifi_net, "discover_adapters", return_value=[hotspot]), \
             patch.object(watcher, "resolve_hotspot_adapter", return_value=hotspot), \
             patch.object(watcher, "stop_ap_mode") as stop_ap, \
             patch.object(watcher.HOTSPOT_CTX, "start_ap_mode") as start_ap, \
             patch.object(watcher.HOTSPOT_CTX, "update_apmode_flag") as apflag, \
             patch.object(watcher.ACTIVATION_CTX, "leave_setup_mode") as leave:
            result = watcher.attempt_on_targets([hotspot], lambda adapter: False)

        assert result is None
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
             patch.object(watcher.HOTSPOT_CTX, "start_ap_mode") as start_ap, \
             patch.object(watcher.HOTSPOT_CTX, "update_apmode_flag") as apflag:
            result = watcher.attempt_on_targets([usb], lambda adapter: False)

        assert result is None
        stop_ap.assert_called_once()
        start_ap.assert_called_once()
        apflag.assert_called_once_with(True)


class TestApplyCredentialsWorker:
    """Credential apply runs on the shared worker (no Flask thread).
    submit_apply_credentials enqueues an apply_credentials job; the worker runs
    configure_wifi_with_nmcli and the loop applies the wait-page status tail."""

    def test_submit_sets_applying_and_enqueues_job(self, watcher):
        with patch.object(watcher.wifi_activation, "submit_activation_job",
                         wraps=watcher.wifi_activation.submit_activation_job):
            assert watcher.submit_apply_credentials("Home", "s3cr3t") is True
        assert watcher.APPLY_STATE.apply_in_progress is True
        assert watcher.APPLY_STATE.last_apply_result == "applying"
        job = watcher.wifi_activation._activation_job_queue.get_nowait()
        assert job.kind == "apply_credentials"
        assert job.ssid == "Home" and job.password == "s3cr3t"

    def test_submit_refused_when_apply_already_in_progress(self, watcher):
        watcher.APPLY_STATE.apply_in_progress = True
        with patch.object(watcher.wifi_activation, "submit_activation_job") as submit:
            assert watcher.submit_apply_credentials("Home", "x") is False
        submit.assert_not_called()

    def test_applying_state_set_before_job_submission(self, watcher):
        # The "applying" marking must be visible before the job can possibly be
        # picked up and completed by the worker/loop, so a fast result can never
        # be applied and then clobbered back to "applying" by this call.
        seen = {}

        def _check(ctx, job):
            seen["apply_in_progress"] = watcher.APPLY_STATE.apply_in_progress
            seen["last_apply_result"] = watcher.APPLY_STATE.last_apply_result
            return True

        with patch.object(watcher.wifi_activation, "submit_activation_job", side_effect=_check):
            assert watcher.submit_apply_credentials("Home", "x") is True
        assert seen == {"apply_in_progress": True, "last_apply_result": "applying"}

    def test_submit_rolls_back_applying_state_when_job_submission_fails(self, watcher):
        watcher.APPLY_STATE.last_apply_result = "ok"
        watcher.APPLY_STATE.last_apply_error = ""
        with patch.object(watcher.wifi_activation, "submit_activation_job", return_value=False):
            assert watcher.submit_apply_credentials("Home", "x") is False
        assert watcher.APPLY_STATE.apply_in_progress is False
        assert watcher.APPLY_STATE.last_apply_result == "ok"
        assert watcher.APPLY_STATE.last_apply_error == ""

    def test_success_result_sets_ok_and_clears_flag(self, watcher):
        # IF-2: configure_wifi_with_nmcli returns the adapter it came up on; the
        # worker carries that ifname on the result, and apply_activation_result
        # applies the session success tail (set-active / leave-setup / avahi) on
        # the loop thread.
        target = _adapter(watcher, "wlan1", "aa:bb:cc:00:00:02", is_usb=True)
        job = watcher.wifi_activation.ActivationJob(epoch=watcher.wifi_activation._next_activation_epoch(watcher.ACTIVATION_CTX),
                                    kind="apply_credentials", ifname="", ssid="Home", password="x",
                                    on_success_leaves_setup=True,
                                    leave_reason="WiFi client connection succeeded")
        watcher.APPLY_STATE.apply_in_progress = True
        with patch.object(watcher.ACTIVATION_CTX, "configure_wifi_with_nmcli", return_value=target), \
             patch.object(watcher.wifi_net, "discover_adapters", return_value=[target]), \
             patch.object(watcher.wifi_activation, "_set_active_client") as set_active, \
             patch.object(watcher.ACTIVATION_CTX, "leave_setup_mode") as leave, \
             patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover") as avahi:
            result = watcher.wifi_activation._run_activation_job(watcher.ACTIVATION_CTX, job)
            watcher.wifi_activation.apply_activation_result(watcher.ACTIVATION_CTX, result)
        assert result.ok is True
        assert result.ifname == "wlan1"
        assert watcher.APPLY_STATE.last_apply_result == "ok"
        assert watcher.APPLY_STATE.apply_in_progress is False
        # The success tail ran on the loop-thread apply, not on the worker.
        set_active.assert_called_once_with(watcher.ACTIVATION_CTX, target)
        leave.assert_called_once_with("WiFi client connection succeeded")
        avahi.assert_called_once()

    def test_failure_retains_setup_and_returns_to_setup_mode(self, watcher):
        watcher.STATE.setup_mode = True
        watcher.APPLY_STATE.apply_in_progress = True
        job = watcher.wifi_activation.ActivationJob(epoch=watcher.wifi_activation._next_activation_epoch(watcher.ACTIVATION_CTX),
                                    kind="apply_credentials", ifname="", ssid="Home", password="bad",
                                    on_success_leaves_setup=True,
                                    leave_reason="WiFi client connection succeeded")
        with patch.object(watcher.ACTIVATION_CTX, "configure_wifi_with_nmcli", return_value=None), \
             patch.object(watcher.ACTIVATION_CTX, "leave_setup_mode") as leave, \
             patch.object(watcher.ACTIVATION_CTX, "enter_setup_mode") as enter:
            result = watcher.wifi_activation._run_activation_job(watcher.ACTIVATION_CTX, job)
            watcher.wifi_activation.apply_activation_result(watcher.ACTIVATION_CTX, result)
        assert result.ok is False
        leave.assert_not_called()
        enter.assert_called_once()
        assert watcher.APPLY_STATE.last_apply_result == "failed"
        assert watcher.APPLY_STATE.apply_in_progress is False


class TestIf2WorkerSessionContract:
    """IF-2 — the worker never applies a session success tail.  The credential
    apply's tail (set-active / leave-setup / avahi) runs only on the loop thread;
    ethernet enforcement stays deferred until the worker result is applied."""

    def _eth_hctx(self, watcher, now):
        facts = _facts_for(watcher, [], None, wired_ok=True, now=now)
        pre = watcher.wifi_loop.PreFactsContext(now=facts.taken_at, boot_time=0.0, avahi_ok=True)
        fctx = watcher.wifi_loop.FactsContext(pre, facts, lambda: False)
        return watcher.wifi_loop.HealthContext(
            fctx, health_ifname="wlan0", wifi_connected=False, client_ok=False,
            conn_ok=True, active_path_ok=True)

    def test_apply_tail_on_loop_thread_and_eth_defers_until_applied(self, watcher):
        loop_ident = threading.get_ident()
        tail_calls: list = []  # (name, thread_ident) recorded by the setter shims

        target = _adapter(watcher, "wlan1", "aa:bb:cc:00:00:02", is_usb=True)
        started = threading.Event()
        release = threading.Event()

        def blocking_configure(ssid, pw):
            # Worker thread: announce we are in flight, then block so the test can
            # observe a mid-job ethernet-appears pass that must defer enforcement.
            started.set()
            assert release.wait(3.0)
            return target

        def rec_set_active(ctx, adapter):
            tail_calls.append(("set_active", threading.get_ident()))
            watcher.STATE.active_client_ifname = adapter.ifname if adapter else ""
            watcher.STATE.active_client_mac = adapter.permanent_mac if adapter else ""

        def rec_leave(reason=""):
            tail_calls.append(("leave", threading.get_ident()))
            watcher.STATE.setup_mode = False
            watcher.STATE.hotspot = None

        watcher.STATE.setup_mode = True
        watcher.STATE.hotspot = watcher.HotspotSession(
            purpose=watcher.wifi_policy.HotspotPurpose.BOOT_RECOVERY, entered_at=0.0)

        with patch.object(watcher.ACTIVATION_CTX, "configure_wifi_with_nmcli", side_effect=blocking_configure), \
             patch.object(watcher.wifi_activation, "_set_active_client", side_effect=rec_set_active), \
             patch.object(watcher.ACTIVATION_CTX, "leave_setup_mode", side_effect=rec_leave), \
             patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"), \
             patch.object(watcher.wifi_net, "discover_adapters", return_value=[target]):
            worker = watcher.wifi_activation.start_activation_worker(watcher.ACTIVATION_CTX)
            try:
                assert watcher.submit_apply_credentials("Home", "s3cr3t") is True
                assert started.wait(3.0)                 # worker picked up the job
                assert watcher.STATE.transitioning is True

                # Mid-job ethernet-appears pass: step_ethernet_wins observes it but
                # DEFERS enforcement (owns the pass; no leave, no disconnect).
                with patch.object(watcher.nm, "disconnect_device") as disc_defer:
                    v = watcher.wifi_loop.step_ethernet_wins(watcher.LOOP_CTX, self._eth_hctx(watcher, now=1000.0))
                assert v is watcher.Verdict.OWN_PASS
                disc_defer.assert_not_called()
                assert tail_calls == []                  # no success tail yet
                assert watcher.STATE.setup_mode is True

                # Release the worker and wait for it to post the result.
                release.set()
                assert watcher.wifi_activation.activation_result_event.wait(3.0)

                # Apply the result at pass top (loop thread): the success tail runs
                # here and transitioning is cleared.
                pre = watcher.wifi_loop.PreFactsContext(now=1001.0, boot_time=0.0, avahi_ok=True)
                watcher.wifi_activation.step_apply_activation_result(watcher.ACTIVATION_CTX, pre)
                assert watcher.STATE.transitioning is False
                assert watcher.APPLY_STATE.last_apply_result == "ok"
                assert ("set_active", loop_ident) in tail_calls
                assert ("leave", loop_ident) in tail_calls

                # The pass AFTER the result is applied now enforces ethernet: the
                # idle Wi-Fi client is disconnected (no longer deferred).
                with patch.object(watcher.nm, "disconnect_device") as disc_enforce:
                    v2 = watcher.wifi_loop.step_ethernet_wins(watcher.LOOP_CTX, self._eth_hctx(watcher, now=1002.0))
                assert v2 is watcher.Verdict.OWN_PASS
                disc_enforce.assert_called_once_with("wlan1")
            finally:
                watcher.wifi_activation._activation_job_queue.put(None)  # stop the worker thread
                worker.join(3.0)

        # Thread-identity invariant: every session-tail setter ran on the loop
        # thread, never on the worker thread.
        assert tail_calls, "the success tail must have run"
        assert all(ident == loop_ident for _, ident in tail_calls)


class TestReconfigureTimeout:
    def test_timeout_starts_reconfigure_episode(self, watcher):
        # The timeout now starts a reconnect episode tagged reconfigure_timeout.
        with patch.object(watcher.wifi_adoption, "start_reconnect_saved_episode", return_value=True) as start:
            watcher.handle_reconfigure_timeout()
        start.assert_called_once_with(watcher.ADOPTION_CTX, failure_tail="reconfigure_timeout")

    def test_timeout_episode_failure_enters_recovery(self, watcher):
        # When the reconfigure-timeout episode exhausts its targets, its failure
        # tail downgrades the session to an automatic recovery hotspot.
        watcher.STATE.setup_mode = True
        watcher.STATE.hotspot = watcher.HotspotSession(
            purpose=watcher.wifi_policy.HotspotPurpose.EXPLICIT_RECONFIGURE,
            entered_at=0.0,
            rollback=watcher.RollbackSnapshot("Home", "uuid-1", ""),
        )
        watcher.STATE.reconnect_episode = watcher.wifi_adoption.ReconnectEpisode(
            target_ifnames=["wlan0"], profile_name="Home", profile_uuid="uuid-1",
            hotspot_ifname="wlan0", failure_tail="reconfigure_timeout", index=1)
        watcher.wifi_adoption._submit_next_reconnect_target(watcher.ADOPTION_CTX)   # index past end -> failure tail
        assert watcher.STATE.hotspot.purpose is watcher.wifi_policy.HotspotPurpose.USB_LOSS_RECOVERY
        assert watcher.STATE.hotspot.rollback is None

    def test_timeout_not_restarted_while_episode_active(self, watcher):
        # step_reconfigure_timeout must not restart the episode every pass while
        # one is already running.
        watcher.STATE.setup_mode = True
        watcher.STATE.hotspot = watcher.HotspotSession(
            purpose=watcher.wifi_policy.HotspotPurpose.EXPLICIT_RECONFIGURE,
            entered_at=0.0, rollback=watcher.RollbackSnapshot("Home", "uuid-1", ""))
        watcher.STATE.reconnect_episode = watcher.wifi_adoption.ReconnectEpisode(
            target_ifnames=["wlan0"], profile_name="Home", profile_uuid="uuid-1",
            hotspot_ifname="wlan0", failure_tail="reconfigure_timeout")
        pre = watcher.wifi_loop.PreFactsContext(now=watcher.wifi_policy.AP_MAX_DURATION + 10, boot_time=0.0, avahi_ok=False)
        with patch.object(watcher, "handle_reconfigure_timeout") as h:
            v = watcher.wifi_loop.step_reconfigure_timeout(watcher.LOOP_CTX, pre)
        h.assert_not_called()
        assert v is watcher.Verdict.CONTINUE


class TestProbePatience:
    """Recovery ladder — fail fast when nmcli reports the SSID is not visible."""

    def test_network_absent_detects_hard_failure(self, watcher):
        absent = MagicMock(returncode=4,
                           stderr="Error: activation failed: The Wi-Fi network could not be found")
        assert watcher.wifi_activation._activation_network_absent(absent) is True

    def test_network_absent_false_on_success_and_other_errors(self, watcher):
        ok = MagicMock(returncode=0, stderr="")
        other = MagicMock(returncode=1, stderr="Error: something else")
        assert watcher.wifi_activation._activation_network_absent(ok) is False
        assert watcher.wifi_activation._activation_network_absent(other) is False

    def test_activate_committed_on_skips_wait_when_absent(self, watcher):
        state = watcher.wifi_net.NetworkState(connection_name="Home", connection_uuid="u1")
        absent = MagicMock(returncode=4,
                           stderr="Error: The Wi-Fi network could not be found")
        with patch.object(watcher, "get_configured_network_state", return_value=state), \
             patch.object(watcher.ACTIVATION_CTX, "_resolve_committed_uuid", return_value="u1"), \
             patch.object(watcher.nm, "clear_restrictions"), \
             patch.object(watcher.nm, "activate", return_value=absent), \
             patch.object(watcher, "wait_for_connection") as waiter:
            result = watcher.wifi_activation._activate_committed_on(watcher.ACTIVATION_CTX, "wlan1")
        assert result is False
        waiter.assert_not_called()


class TestPinAccountingInterfaceScoping:
    """BM-4: _pin_usb_bssid selection and success/failure accounting operate
    only on the activation target interface's own BSSID table."""

    def _rows(self, bssid="AA:BB:CC:DD:EE:FF", ssid="Home", signal=70, in_use=False):
        return [{"in_use": in_use, "bssid": bssid, "ssid": ssid, "signal": signal}]

    def test_pin_selects_only_from_target_interface_table(self, watcher):
        # A stronger candidate seeded in wlan0's table must never be selected
        # when pinning for wlan1 -- wlan1's scan is the only source consulted.
        watcher.ADOPTION_STATE.roaming_managed = True
        watcher.ADOPTION_STATE.bssid_tables.setdefault("wlan0", {})["11:22:33:44:55:66"] = {
            "ssid": "Home", "signal": 95, "last_seen": 100.0,
            "fail_count": 0, "quarantined_until": None,
        }
        with patch.object(watcher.wifi_net, "usb_sysfs_paths", return_value={"driver": "rtl8xxxu"}), \
             patch.object(watcher.wifi_net, "get_connection_ssid", return_value="Home"), \
             patch.object(watcher.nm, "wifi_bssid_scan", return_value=self._rows(signal=70)), \
             patch.object(watcher.nm, "set_bssid") as set_bssid:
            result = watcher.wifi_activation._pin_usb_bssid(watcher.ACTIVATION_CTX, "wlan1", "uuid-1")
        assert result == "AA:BB:CC:DD:EE:FF"
        set_bssid.assert_called_once_with("uuid-1", "AA:BB:CC:DD:EE:FF")
        # wlan0's stronger candidate is untouched and was never selected.
        assert watcher.ADOPTION_STATE.bssid_tables["wlan0"]["11:22:33:44:55:66"]["signal"] == 95
        assert "11:22:33:44:55:66" not in watcher.ADOPTION_STATE.bssid_tables.get("wlan1", {})

    def test_failure_accounting_touches_only_target_interface_table(self, watcher):
        # Seed the SAME bssid in wlan0's table to prove a wlan1 pin failure
        # cannot bleed fail_count into another interface's observations.
        watcher.ADOPTION_STATE.roaming_managed = True
        watcher.ADOPTION_STATE.bssid_tables.setdefault("wlan0", {})["AA:BB:CC:DD:EE:FF"] = {
            "ssid": "Home", "signal": 70, "last_seen": 100.0,
            "fail_count": 0, "quarantined_until": None,
        }
        with patch.object(watcher.wifi_net, "usb_sysfs_paths", return_value={"driver": "rtl8xxxu"}), \
             patch.object(watcher.wifi_net, "resolve_connection_uuid_for_name", return_value="uuid-1"), \
             patch.object(watcher.wifi_net, "get_connection_ssid", return_value="Home"), \
             patch.object(watcher.nm, "clear_restrictions"), \
             patch.object(watcher.nm, "wifi_bssid_scan", return_value=self._rows()), \
             patch.object(watcher.nm, "set_bssid"), \
             patch.object(watcher.nm, "activate", return_value=MagicMock(returncode=1, stderr="failed")), \
             patch.object(watcher.ACTIVATION_CTX, "wait_for_connection", return_value=False), \
             patch.object(watcher.ACTIVATION_CTX, "is_wifi_client_healthy", return_value=False):
            ok = watcher.wifi_activation._activate_profile_on(
                watcher.ACTIVATION_CTX, "wlan1", watcher.wifi_net.NetworkState("Home", ""))
        assert ok is False
        assert watcher.ADOPTION_STATE.bssid_tables["wlan1"]["AA:BB:CC:DD:EE:FF"]["fail_count"] == 1
        assert watcher.ADOPTION_STATE.bssid_tables["wlan0"]["AA:BB:CC:DD:EE:FF"]["fail_count"] == 0

    def test_success_quarantine_touches_only_target_interface_table(self, watcher):
        # Two same-SSID entries with enough failures to quarantine, one in
        # wlan1's table and an identically-shaped one in wlan0's table. A
        # successful pin on wlan1 must quarantine only wlan1's entry.
        seeded_at = time.monotonic()
        watcher.ADOPTION_STATE.roaming_managed = True
        watcher.ADOPTION_STATE.bssid_tables.setdefault("wlan1", {})["11:22:33:44:55:66"] = {
            "ssid": "Home", "signal": 40, "last_seen": seeded_at,
            "fail_count": watcher.wifi_policy.BSSID_QUARANTINE_FAILS, "quarantined_until": None,
        }
        watcher.ADOPTION_STATE.bssid_tables.setdefault("wlan0", {})["11:22:33:44:55:66"] = {
            "ssid": "Home", "signal": 40, "last_seen": seeded_at,
            "fail_count": watcher.wifi_policy.BSSID_QUARANTINE_FAILS, "quarantined_until": None,
        }
        with patch.object(watcher.wifi_net, "usb_sysfs_paths", return_value={"driver": "rtl8xxxu"}), \
             patch.object(watcher.wifi_net, "resolve_connection_uuid_for_name", return_value="uuid-1"), \
             patch.object(watcher.wifi_net, "get_connection_ssid", return_value="Home"), \
             patch.object(watcher.nm, "clear_restrictions"), \
             patch.object(watcher.nm, "wifi_bssid_scan", return_value=self._rows()), \
             patch.object(watcher.nm, "set_bssid"), \
             patch.object(watcher.nm, "activate", return_value=MagicMock(returncode=0, stderr="")), \
             patch.object(watcher.ACTIVATION_CTX, "wait_for_connection", return_value=True), \
             patch.object(watcher.ACTIVATION_CTX, "is_wifi_client_healthy", return_value=True):
            ok = watcher.wifi_activation._activate_profile_on(
                watcher.ACTIVATION_CTX, "wlan1", watcher.wifi_net.NetworkState("Home", ""))
        assert ok is True
        # wlan1's other same-SSID entry with enough failures is quarantined.
        assert watcher.ADOPTION_STATE.bssid_tables["wlan1"]["11:22:33:44:55:66"]["quarantined_until"] is not None
        # wlan0's identically-shaped entry is untouched by the wlan1 success.
        assert watcher.ADOPTION_STATE.bssid_tables["wlan0"]["11:22:33:44:55:66"]["quarantined_until"] is None


class TestPinScanDebugLogging:
    """SL-1: the pin scan in _pin_usb_bssid emits one compact DEBUG line;
    nothing about scans is logged at INFO."""

    def test_pin_scan_logs_one_debug_line(self, watcher, caplog):
        watcher.ADOPTION_STATE.roaming_managed = True
        rows = [{"in_use": False, "bssid": "AA:BB:CC:DD:EE:FF", "ssid": "Home", "signal": 70}]
        with caplog.at_level(logging.DEBUG, logger="wifi_watcher"), \
             patch.object(watcher.wifi_net, "usb_sysfs_paths", return_value={"driver": "rtl8xxxu"}), \
             patch.object(watcher.wifi_net, "get_connection_ssid", return_value="Home"), \
             patch.object(watcher.nm, "wifi_bssid_scan", return_value=rows), \
             patch.object(watcher.nm, "set_bssid"):
            watcher.wifi_activation._pin_usb_bssid(watcher.ACTIVATION_CTX, "wlan1", "uuid-1")
        matches = [r for r in caplog.records if r.levelno == logging.DEBUG
                   and "BSSID scan on wlan1" in r.getMessage()]
        assert len(matches) == 1
        msg = matches[0].getMessage()
        assert "rescan=True" in msg and "pin" in msg
        assert not any(r.levelno >= logging.INFO and "BSSID scan" in r.getMessage()
                       for r in caplog.records)

    def test_pin_scan_failure_logs_failure_form(self, watcher, caplog):
        watcher.ADOPTION_STATE.roaming_managed = True
        with caplog.at_level(logging.DEBUG, logger="wifi_watcher"), \
             patch.object(watcher.wifi_net, "usb_sysfs_paths", return_value={"driver": "rtl8xxxu"}), \
             patch.object(watcher.nm, "wifi_bssid_scan", return_value=None), \
             patch.object(watcher.nm, "set_bssid"):
            watcher.wifi_activation._pin_usb_bssid(watcher.ACTIVATION_CTX, "wlan1", "uuid-1")
        matches = [r for r in caplog.records if "BSSID scan on wlan1" in r.getMessage()]
        assert len(matches) == 1
        assert matches[0].getMessage().endswith("scan failed")


class TestActivationFailureLedger:
    """S-1 — per-stable-id last-activation-failure record: the failure tail
    classifies a failed attempt from the same nmcli-result/wait-outcome
    information _validate_activation already computes, and the success tail
    clears it (mirroring the no-IP ledger's own clear-on-success)."""

    def _run_real(self, watcher, *, ifname="wlan1", stable_id="mac-1", nm_result,
                  wait_result=None, health_result=None, wait_for_validation=True):
        """Run a job through the real activation core (not the
        _activate_committed_on/_activate_profile_on seam) so _validate_activation
        actually classifies the outcome."""
        state = watcher.wifi_net.NetworkState(connection_name="Home", connection_uuid="u1")
        job = watcher.wifi_activation.ActivationJob(
            epoch=watcher.wifi_activation._next_activation_epoch(watcher.ACTIVATION_CTX),
            kind="activate_profile", ifname=ifname, profile=state,
            wait_for_validation=wait_for_validation, stable_id=stable_id)
        with patch.object(watcher.ACTIVATION_CTX, "_resolve_committed_uuid", return_value="u1"), \
             patch.object(watcher.nm, "clear_restrictions"), \
             patch.object(watcher.nm, "activate", return_value=nm_result), \
             patch.object(watcher.wifi_net, "usb_sysfs_paths", return_value=None), \
             patch.object(watcher.ACTIVATION_CTX, "wait_for_connection", return_value=wait_result), \
             patch.object(watcher.ACTIVATION_CTX, "is_wifi_client_healthy", return_value=health_result):
            return watcher.wifi_activation._run_activation_job(watcher.ACTIVATION_CTX, job)

    def test_network_absent_records_network_not_visible(self, watcher):
        absent = MagicMock(returncode=4,
                           stderr="Error: activation failed: The Wi-Fi network could not be found")
        result = self._run_real(watcher, nm_result=absent)
        assert result.ok is False
        watcher.wifi_activation.apply_activation_result(watcher.ACTIVATION_CTX, result)
        led = watcher.RECOVERY_STATE.activation_failure_ledgers["mac-1"]
        assert led["reason"] == "network_not_visible"
        assert led["rc"] == 4
        assert isinstance(led["at"], float)

    def test_no_ip_timeout_records_no_ip_timeout(self, watcher):
        activated = MagicMock(returncode=0, stderr="")
        result = self._run_real(watcher, nm_result=activated, wait_result=False, health_result=False)
        assert result.ok is False
        watcher.wifi_activation.apply_activation_result(watcher.ACTIVATION_CTX, result)
        led = watcher.RECOVERY_STATE.activation_failure_ledgers["mac-1"]
        assert led["reason"] == "no_ip_timeout"
        assert led["rc"] == 0

    def test_other_nonzero_rc_records_activation_failed(self, watcher):
        other = MagicMock(returncode=1, stderr="Error: something else")
        result = self._run_real(watcher, nm_result=other, wait_result=False, health_result=False)
        assert result.ok is False
        watcher.wifi_activation.apply_activation_result(watcher.ACTIVATION_CTX, result)
        led = watcher.RECOVERY_STATE.activation_failure_ledgers["mac-1"]
        assert led["reason"] == "activation_failed"
        assert led["rc"] == 1

    def test_job_level_failure_before_validation_records_activation_failed(self, watcher):
        # A job that never reaches the activation core (no ifname) still gets a
        # ledger entry so the status snapshot has something to show.
        job = watcher.wifi_activation.ActivationJob(
            epoch=watcher.wifi_activation._next_activation_epoch(watcher.ACTIVATION_CTX),
            kind="activate_committed", ifname="", stable_id="mac-empty")
        result = watcher.wifi_activation._run_activation_job(watcher.ACTIVATION_CTX, job)
        assert result.ok is False and result.error == "no_ifname"
        watcher.wifi_activation.apply_activation_result(watcher.ACTIVATION_CTX, result)
        led = watcher.RECOVERY_STATE.activation_failure_ledgers["mac-empty"]
        assert led["reason"] == "activation_failed"
        assert led["rc"] == 0

    def test_success_clears_the_record_other_adapters_survive(self, watcher):
        watcher.RECOVERY_STATE.activation_failure_ledgers["mac-1"] = {
            "reason": "no_ip_timeout", "rc": 0, "at": 1.0,
        }
        watcher.RECOVERY_STATE.activation_failure_ledgers["mac-other"] = {
            "reason": "network_not_visible", "rc": 4, "at": 2.0,
        }
        target = _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:aa", is_usb=True)
        job = watcher.wifi_activation.ActivationJob(
            epoch=watcher.wifi_activation._next_activation_epoch(watcher.ACTIVATION_CTX),
            kind="activate_committed", ifname="wlan1", stable_id="mac-1")
        result = watcher.wifi_activation.ActivationResult(job.epoch, True, "wlan1", job)
        with patch.object(watcher.wifi_net, "find_adapter_by_ifname", return_value=target), \
             patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"):
            watcher.wifi_activation.apply_activation_result(watcher.ACTIVATION_CTX, result)
        assert "mac-1" not in watcher.RECOVERY_STATE.activation_failure_ledgers
        assert "mac-other" in watcher.RECOVERY_STATE.activation_failure_ledgers
