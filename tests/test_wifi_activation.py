"""Activation worker, job/result plumbing, client_up_tail, and the
candidate-apply flow."""
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


class TestClientUpTail:
    """WP-3 — the single shared 'a client came up' choreography (client_up_tail)."""

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
            watcher.client_up_tail(a)
        assert watcher.STATE.active_client_ifname == "wlan1"
        avahi.assert_called_once()

    def test_none_adapter_skips_set_active(self, watcher):
        watcher.STATE.active_client_ifname = "wlan0"
        watcher.STATE.active_client_mac = "prev"
        with patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"), \
             patch.object(watcher, "_set_active_client") as sac:
            watcher.client_up_tail(None)
        sac.assert_not_called()

    def test_disconnect_builtin_runs_nmcli(self, watcher):
        a = self._adapter()
        with patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"), \
             patch.object(watcher.nm, "disconnect_device") as disc:
            watcher.client_up_tail(a, disconnect_builtin_ifname="wlan0")
        disc.assert_called_once_with("wlan0")

    def test_empty_disconnect_ifname_skips_nmcli(self, watcher):
        a = self._adapter()
        with patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"), \
             patch.object(watcher.nm, "disconnect_device") as disc:
            watcher.client_up_tail(a, disconnect_builtin_ifname="")
        disc.assert_not_called()

    def test_set_builtin_fallback_flags(self, watcher):
        a = self._adapter()
        with patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"):
            watcher.STATE.using_builtin_fallback = True
            watcher.client_up_tail(a, set_builtin_fallback=None)   # None -> untouched
            assert watcher.STATE.using_builtin_fallback is True
            watcher.client_up_tail(a, set_builtin_fallback=False)
            assert watcher.STATE.using_builtin_fallback is False
            watcher.client_up_tail(a, set_builtin_fallback=True)
            assert watcher.STATE.using_builtin_fallback is True

    def test_clears_timers_and_onboard_bound(self, watcher):
        a = self._adapter()
        watcher.STATE.conn_down_start = 5.0
        watcher.STATE.last_reconnect_attempt = 5.0
        watcher.STATE.onboard_activation_failures = 2
        with patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"):
            watcher.client_up_tail(a, clear_down_timers=True, reset_onboard_bound=True)
        assert watcher.STATE.conn_down_start is None
        assert watcher.STATE.last_reconnect_attempt is None
        assert watcher.STATE.onboard_activation_failures == 0

    def test_clears_noip_ledger_when_stable_id_given(self, watcher):
        a = self._adapter()
        with patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"), \
             patch.object(watcher.wifi_recovery, "clear_noip_failures") as clr:
            watcher.client_up_tail(a, clear_noip_stable_id="usb0")
            clr.assert_called_once()
            clr.reset_mock()
            watcher.client_up_tail(a, clear_noip_stable_id=None)
            clr.assert_not_called()

    def test_leave_setup_reason_forwarded(self, watcher):
        a = self._adapter()
        with patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"), \
             patch.object(watcher.ACTIVATION_CTX, "leave_setup_mode") as leave:
            watcher.client_up_tail(a, leave_setup_reason="done")
            leave.assert_called_once_with("done")
            leave.reset_mock()
            watcher.client_up_tail(a, leave_setup_reason=None)
            leave.assert_not_called()

    def test_clear_dead_adapter_and_pending_adoption(self, watcher):
        a = self._adapter()
        with patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"), \
             patch.object(watcher, "_clear_pending_adoption") as cpa, \
             patch.object(watcher.wifi_recovery, "clear_dead_adapter_state") as cda:
            watcher.client_up_tail(a, clear_pending_adoption=True, clear_dead_adapter=True)
        cpa.assert_called_once()
        cda.assert_called_once()

    def test_stamps_roam_holdoff_on_every_successful_activation(self, watcher):
        # UP-2's roam holdoff is documented as gating on "the last roam or
        # successful activation"; client_up_tail is the single success tail
        # every activation path (bring-up, reconnect, adoption, dead-PHY
        # recovery) funnels through, so it must stamp the same field the roam
        # submission does.
        a = self._adapter()
        watcher.STATE.last_roam_or_activation = None
        with patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"):
            watcher.client_up_tail(a)
        assert watcher.STATE.last_roam_or_activation is not None

    def test_fresh_activation_defers_next_roam(self, watcher):
        # End-to-end: a successful activation must hold off the very next
        # survey pass's roam, not just a prior roam submission.
        a = self._adapter()
        with patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"):
            watcher.client_up_tail(a)
        now = watcher.STATE.last_roam_or_activation + 1.0  # well under ROAM_HOLDOFF_SECS
        table = {
            "AA:BB:CC:DD:EE:01": {"ssid": "Home", "signal": 50, "last_seen": now,
                                  "fail_count": 0, "quarantined_until": None},
            "AA:BB:CC:DD:EE:02": {"ssid": "Home", "signal": 90, "last_seen": now,
                                  "fail_count": 0, "quarantined_until": None},
        }
        target = watcher.wifi_policy.next_roam_target(
            table, "AA:BB:CC:DD:EE:01", now, False, watcher.STATE.last_roam_or_activation)
        assert target == ""


class TestActivationWorker:
    """WS1-WP2 — the off-thread activation worker skeleton: job/result split,
    single-slot queue + transitioning gate, result application at pass top, and
    the peek-then-consume control-action deferral.  No call sites are migrated yet
    (WS1-WP3/WP4), so these drive the skeleton directly."""

    def _job(self, watcher, **kw):
        defaults = dict(epoch=watcher._next_activation_epoch(), kind="activate_committed",
                        ifname="wlan1")
        defaults.update(kw)
        return watcher.ActivationJob(**defaults)

    # ---- the split: _run_activation_job (worker half) ----

    def test_run_job_empty_ifname_fails(self, watcher):
        job = self._job(watcher, ifname="")
        r = watcher._run_activation_job(job)
        assert r.ok is False and r.error == "no_ifname"

    def test_run_job_success_carries_job_and_epoch(self, watcher):
        job = self._job(watcher)
        with patch.object(watcher.wifi_activation, "_activate_committed_on", return_value=True):
            r = watcher._run_activation_job(job)
        assert r.ok is True and r.ifname == "wlan1" and r.job is job and r.epoch == job.epoch

    def test_run_job_drops_and_rebuilds_ap_on_failure(self, watcher):
        # Worker owns symmetric AP drop-for-attempt + rebuild-on-own-failure.
        watcher.STATE.setup_mode = True
        job = self._job(watcher, drop_hotspot=True)
        with patch.object(watcher.wifi_activation, "_activate_committed_on", return_value=False), \
             patch.object(watcher.ACTIVATION_CTX, "stop_ap_mode") as stop_ap, \
             patch.object(watcher, "start_ap_mode") as start_ap, \
             patch.object(watcher, "update_apmode_flag") as apflag:
            r = watcher._run_activation_job(job)
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
        with patch.object(watcher, "_resolve_committed_uuid", return_value="u1"), \
             patch.object(watcher, "run_cmd", return_value=timed_out), \
             patch.object(watcher, "wait_for_connection", return_value=False):
            r = watcher._run_activation_job(job)
        assert r.ok is False

    # ---- submit / drain / transitioning gate ----

    def test_submit_sets_transitioning_and_second_submit_deferred(self, watcher):
        job = self._job(watcher)
        assert watcher.submit_activation_job(job) is True
        assert watcher.STATE.transitioning is True
        assert watcher.wifi_activation.get_inflight_activation_epoch() == job.epoch
        # A second submit while transitioning is refused (belt-and-braces gate).
        assert watcher.submit_activation_job(self._job(watcher)) is False

    def test_worker_thread_processes_job_and_posts_result(self, watcher):
        job = self._job(watcher)
        with patch.object(watcher.wifi_activation, "_activate_committed_on", return_value=True):
            watcher.submit_activation_job(job)
            t = watcher.start_activation_worker()
            try:
                assert watcher.activation_result_event.wait(timeout=5.0)
                result = watcher.drain_activation_result()
            finally:
                watcher._activation_job_queue.put(None)  # stop sentinel
                t.join(timeout=5.0)
        assert result is not None and result.ok is True and result.epoch == job.epoch

    def test_step_apply_applies_tail_and_clears_gate(self, watcher):
        job = self._job(watcher, on_success_leaves_setup=True, leave_reason="done")
        watcher.submit_activation_job(job)          # sets transitioning + inflight epoch
        watcher._activation_job_queue.get_nowait()  # (don't run the real worker)
        watcher._post_activation_result(
            watcher.ActivationResult(job.epoch, True, "wlan1", job))
        with patch.object(watcher.wifi_activation, "apply_activation_result", return_value=True) as apply:
            v = watcher.step_apply_activation_result(self._pre(watcher))
        assert v is watcher.Verdict.CONTINUE
        apply.assert_called_once()
        assert watcher.STATE.transitioning is False
        assert watcher.wifi_activation.get_inflight_activation_epoch() is None

    def test_step_apply_no_result_is_noop(self, watcher):
        with patch.object(watcher.wifi_activation, "apply_activation_result") as apply:
            v = watcher.step_apply_activation_result(self._pre(watcher))
        assert v is watcher.Verdict.CONTINUE
        apply.assert_not_called()

    def test_step_apply_stale_epoch_discarded_but_gate_cleared(self, watcher):
        job = self._job(watcher)
        watcher.submit_activation_job(job)
        watcher._activation_job_queue.get_nowait()
        # Post a result with a mismatched epoch (defensive path).
        watcher._post_activation_result(
            watcher.ActivationResult(job.epoch + 999, True, "wlan1", job))
        with patch.object(watcher.wifi_activation, "apply_activation_result") as apply:
            watcher.step_apply_activation_result(self._pre(watcher))
        apply.assert_not_called()                  # stale -> discarded
        assert watcher.STATE.transitioning is False  # but the gate is cleared

    def _pre(self, watcher):
        return watcher.PreFactsContext(now=1000.0, boot_time=0.0, avahi_ok=True)

    # ---- peek-then-consume control action (§3.6) ----

    def test_disruptive_control_action_deferred_while_transitioning(self, watcher):
        watcher.STATE.transitioning = True
        watcher.STATE.pending_control_action = "start_setup"
        watcher.STATE.pending_control_params = {}
        watcher.control_action_event.set()
        with patch.object(watcher.LOOP_CTX, "process_control_action") as proc:
            v = watcher.step_control_action(self._pre(watcher))
        assert v is watcher.Verdict.CONTINUE
        proc.assert_not_called()                       # not consumed
        assert watcher.STATE.pending_control_action == "start_setup"  # left queued
        assert watcher.control_action_event.is_set()

        # Once the transition completes, the queued action is applied exactly once.
        watcher.STATE.transitioning = False
        with patch.object(watcher.LOOP_CTX, "process_control_action") as proc:
            v = watcher.step_control_action(self._pre(watcher))
        assert v is watcher.Verdict.OWN_PASS
        proc.assert_called_once()
        assert watcher.STATE.pending_control_action == ""

    def test_set_log_level_applied_even_while_transitioning(self, watcher):
        watcher.STATE.transitioning = True
        watcher.STATE.pending_control_action = "set_log_level"
        watcher.STATE.pending_control_params = {"level": "debug"}
        watcher.control_action_event.set()
        with patch.object(watcher.LOOP_CTX, "process_control_action") as proc:
            v = watcher.step_control_action(self._pre(watcher))
        assert v is watcher.Verdict.CONTINUE           # non-disruptive: pass continues
        proc.assert_called_once()                      # applied immediately
        assert watcher.STATE.pending_control_action == ""  # consumed
        assert not watcher.control_action_event.is_set()


class TestActivateClient:
    """Flag-matrix unit tests for the worker-half + loop-half tail composition.

    WP-10 retired the synchronous activate_client facade; these drive the same
    composition directly (_run_activation_job then apply_activation_result), which
    is exactly what the facade did, so the tail-flag matrix stays covered."""

    def _run(self, watcher, ifname="wlan1", *, profile=None, **flags):
        wait = flags.get("wait_for_validation", True)
        kind = "activate_committed" if (profile is None and wait) else "activate_profile"
        job = watcher.ActivationJob(
            epoch=watcher._next_activation_epoch(), kind=kind, ifname=ifname,
            profile=profile, **flags)
        result = watcher._run_activation_job(job)
        return watcher.apply_activation_result(result)

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
             patch.object(watcher, "start_ap_mode") as start_ap, \
             patch.object(watcher, "update_apmode_flag") as apflag, \
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
        watcher.STATE.using_builtin_fallback = True
        watcher.STATE.conn_down_start = 123.0
        with self._harness(watcher):
            self._run(watcher, "wlan1")
        assert watcher.STATE.using_builtin_fallback is True   # untouched (flag None)
        assert watcher.STATE.conn_down_start == 123.0         # untouched

    def test_sets_builtin_fallback_and_clears_timers(self, watcher):
        watcher.STATE.conn_down_start = 5.0
        watcher.STATE.last_reconnect_attempt = 6.0
        with self._harness(watcher):
            self._run(watcher, "wlan1", sets_builtin_fallback=True,
                                    clears_down_timers=True)
        assert watcher.STATE.using_builtin_fallback is True
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
    """A-WP5: _try_candidate_on_adapter validates via the shared tail, so the
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
             patch.object(watcher, "_set_active_client") as set_active, \
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
             patch.object(watcher, "start_ap_mode") as start_ap, \
             patch.object(watcher, "update_apmode_flag") as apflag, \
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
             patch.object(watcher, "start_ap_mode") as start_ap, \
             patch.object(watcher, "update_apmode_flag") as apflag:
            result = watcher.attempt_on_targets([usb], lambda adapter: False)

        assert result is None
        stop_ap.assert_called_once()
        start_ap.assert_called_once()
        apflag.assert_called_once_with(True)


class TestApplyCredentialsWorker:
    """WS1-WP4 — credential apply runs on the shared worker (no Flask thread).
    submit_apply_credentials enqueues an apply_credentials job; the worker runs
    configure_wifi_with_nmcli and the loop applies the wait-page status tail."""

    def test_submit_sets_applying_and_enqueues_job(self, watcher):
        with patch.object(watcher, "submit_activation_job", wraps=watcher.submit_activation_job):
            assert watcher.submit_apply_credentials("Home", "s3cr3t") is True
        assert watcher.STATE.apply_in_progress is True
        assert watcher.STATE.last_apply_result == "applying"
        job = watcher._activation_job_queue.get_nowait()
        assert job.kind == "apply_credentials"
        assert job.ssid == "Home" and job.password == "s3cr3t"

    def test_submit_refused_when_apply_already_in_progress(self, watcher):
        watcher.STATE.apply_in_progress = True
        with patch.object(watcher, "submit_activation_job") as submit:
            assert watcher.submit_apply_credentials("Home", "x") is False
        submit.assert_not_called()

    def test_applying_state_set_before_job_submission(self, watcher):
        # The "applying" marking must be visible before the job can possibly be
        # picked up and completed by the worker/loop, so a fast result can never
        # be applied and then clobbered back to "applying" by this call.
        seen = {}

        def _check(job):
            seen["apply_in_progress"] = watcher.STATE.apply_in_progress
            seen["last_apply_result"] = watcher.STATE.last_apply_result
            return True

        with patch.object(watcher, "submit_activation_job", side_effect=_check):
            assert watcher.submit_apply_credentials("Home", "x") is True
        assert seen == {"apply_in_progress": True, "last_apply_result": "applying"}

    def test_submit_rolls_back_applying_state_when_job_submission_fails(self, watcher):
        watcher.STATE.last_apply_result = "ok"
        watcher.STATE.last_apply_error = ""
        with patch.object(watcher, "submit_activation_job", return_value=False):
            assert watcher.submit_apply_credentials("Home", "x") is False
        assert watcher.STATE.apply_in_progress is False
        assert watcher.STATE.last_apply_result == "ok"
        assert watcher.STATE.last_apply_error == ""

    def test_success_result_sets_ok_and_clears_flag(self, watcher):
        # IF-2: configure_wifi_with_nmcli returns the adapter it came up on; the
        # worker carries that ifname on the result, and apply_activation_result
        # applies the session success tail (set-active / leave-setup / avahi) on
        # the loop thread.
        target = _adapter(watcher, "wlan1", "aa:bb:cc:00:00:02", is_usb=True)
        job = watcher.ActivationJob(epoch=watcher._next_activation_epoch(),
                                    kind="apply_credentials", ifname="", ssid="Home", password="x",
                                    on_success_leaves_setup=True,
                                    leave_reason="WiFi client connection succeeded")
        watcher.STATE.apply_in_progress = True
        with patch.object(watcher.ACTIVATION_CTX, "configure_wifi_with_nmcli", return_value=target), \
             patch.object(watcher.wifi_net, "discover_adapters", return_value=[target]), \
             patch.object(watcher.wifi_activation, "_set_active_client") as set_active, \
             patch.object(watcher.ACTIVATION_CTX, "leave_setup_mode") as leave, \
             patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover") as avahi:
            result = watcher._run_activation_job(job)
            watcher.apply_activation_result(result)
        assert result.ok is True
        assert result.ifname == "wlan1"
        assert watcher.STATE.last_apply_result == "ok"
        assert watcher.STATE.apply_in_progress is False
        # The success tail ran on the loop-thread apply, not on the worker.
        set_active.assert_called_once_with(watcher.ACTIVATION_CTX, target)
        leave.assert_called_once_with("WiFi client connection succeeded")
        avahi.assert_called_once()

    def test_failure_retains_setup_and_returns_to_setup_mode(self, watcher):
        watcher.STATE.setup_mode = True
        watcher.STATE.apply_in_progress = True
        job = watcher.ActivationJob(epoch=watcher._next_activation_epoch(),
                                    kind="apply_credentials", ifname="", ssid="Home", password="bad",
                                    on_success_leaves_setup=True,
                                    leave_reason="WiFi client connection succeeded")
        with patch.object(watcher.ACTIVATION_CTX, "configure_wifi_with_nmcli", return_value=None), \
             patch.object(watcher.ACTIVATION_CTX, "leave_setup_mode") as leave, \
             patch.object(watcher.ACTIVATION_CTX, "enter_setup_mode") as enter:
            result = watcher._run_activation_job(job)
            watcher.apply_activation_result(result)
        assert result.ok is False
        leave.assert_not_called()
        enter.assert_called_once()
        assert watcher.STATE.last_apply_result == "failed"
        assert watcher.STATE.apply_in_progress is False


class TestIf2WorkerSessionContract:
    """IF-2 — the worker never applies a session success tail.  The credential
    apply's tail (set-active / leave-setup / avahi) runs only on the loop thread;
    ethernet enforcement stays deferred until the worker result is applied."""

    def _eth_hctx(self, watcher, now):
        facts = _facts_for(watcher, [], None, wired_ok=True, now=now)
        pre = watcher.PreFactsContext(now=facts.taken_at, boot_time=0.0, avahi_ok=True)
        fctx = watcher.FactsContext(pre, facts, lambda: False)
        return watcher.HealthContext(
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
            purpose=watcher.HotspotPurpose.BOOT_RECOVERY, entered_at=0.0)

        with patch.object(watcher.ACTIVATION_CTX, "configure_wifi_with_nmcli", side_effect=blocking_configure), \
             patch.object(watcher.wifi_activation, "_set_active_client", side_effect=rec_set_active), \
             patch.object(watcher.ACTIVATION_CTX, "leave_setup_mode", side_effect=rec_leave), \
             patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"), \
             patch.object(watcher.wifi_net, "discover_adapters", return_value=[target]):
            worker = watcher.start_activation_worker()
            try:
                assert watcher.submit_apply_credentials("Home", "s3cr3t") is True
                assert started.wait(3.0)                 # worker picked up the job
                assert watcher.STATE.transitioning is True

                # Mid-job ethernet-appears pass: step_ethernet_wins observes it but
                # DEFERS enforcement (owns the pass; no leave, no disconnect).
                with patch.object(watcher.nm, "disconnect_device") as disc_defer:
                    v = watcher.step_ethernet_wins(self._eth_hctx(watcher, now=1000.0))
                assert v is watcher.Verdict.OWN_PASS
                disc_defer.assert_not_called()
                assert tail_calls == []                  # no success tail yet
                assert watcher.STATE.setup_mode is True

                # Release the worker and wait for it to post the result.
                release.set()
                assert watcher.activation_result_event.wait(3.0)

                # Apply the result at pass top (loop thread): the success tail runs
                # here and transitioning is cleared.
                pre = watcher.PreFactsContext(now=1001.0, boot_time=0.0, avahi_ok=True)
                watcher.step_apply_activation_result(pre)
                assert watcher.STATE.transitioning is False
                assert watcher.STATE.last_apply_result == "ok"
                assert ("set_active", loop_ident) in tail_calls
                assert ("leave", loop_ident) in tail_calls

                # The pass AFTER the result is applied now enforces ethernet: the
                # idle Wi-Fi client is disconnected (no longer deferred).
                with patch.object(watcher.nm, "disconnect_device") as disc_enforce:
                    v2 = watcher.step_ethernet_wins(self._eth_hctx(watcher, now=1002.0))
                assert v2 is watcher.Verdict.OWN_PASS
                disc_enforce.assert_called_once_with("wlan1")
            finally:
                watcher._activation_job_queue.put(None)  # stop the worker thread
                worker.join(3.0)

        # Thread-identity invariant: every session-tail setter ran on the loop
        # thread, never on the worker thread.
        assert tail_calls, "the success tail must have run"
        assert all(ident == loop_ident for _, ident in tail_calls)


class TestReconfigureTimeout:
    def test_timeout_starts_reconfigure_episode(self, watcher):
        # The timeout now starts a reconnect episode tagged reconfigure_timeout.
        with patch.object(watcher, "start_reconnect_saved_episode", return_value=True) as start:
            watcher.handle_reconfigure_timeout()
        start.assert_called_once_with(failure_tail="reconfigure_timeout")

    def test_timeout_episode_failure_enters_recovery(self, watcher):
        # When the reconfigure-timeout episode exhausts its targets, its failure
        # tail downgrades the session to an automatic recovery hotspot.
        watcher.STATE.setup_mode = True
        watcher.STATE.hotspot = watcher.HotspotSession(
            purpose=watcher.HotspotPurpose.EXPLICIT_RECONFIGURE,
            entered_at=0.0,
            rollback=watcher.RollbackSnapshot("Home", "uuid-1", ""),
        )
        watcher.STATE.reconnect_episode = watcher.ReconnectEpisode(
            target_ifnames=["wlan0"], profile_name="Home", profile_uuid="uuid-1",
            hotspot_ifname="wlan0", failure_tail="reconfigure_timeout", index=1)
        watcher._submit_next_reconnect_target()   # index past end -> failure tail
        assert watcher.STATE.hotspot.purpose is watcher.HotspotPurpose.USB_LOSS_RECOVERY
        assert watcher.STATE.hotspot.rollback is None

    def test_timeout_not_restarted_while_episode_active(self, watcher):
        # step_reconfigure_timeout must not restart the episode every pass while
        # one is already running.
        watcher.STATE.setup_mode = True
        watcher.STATE.hotspot = watcher.HotspotSession(
            purpose=watcher.HotspotPurpose.EXPLICIT_RECONFIGURE,
            entered_at=0.0, rollback=watcher.RollbackSnapshot("Home", "uuid-1", ""))
        watcher.STATE.reconnect_episode = watcher.ReconnectEpisode(
            target_ifnames=["wlan0"], profile_name="Home", profile_uuid="uuid-1",
            hotspot_ifname="wlan0", failure_tail="reconfigure_timeout")
        pre = watcher.PreFactsContext(now=watcher.AP_MAX_DURATION + 10, boot_time=0.0, avahi_ok=False)
        with patch.object(watcher, "handle_reconfigure_timeout") as h:
            v = watcher.step_reconfigure_timeout(pre)
        h.assert_not_called()
        assert v is watcher.Verdict.CONTINUE


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
             patch.object(watcher.nm, "clear_restrictions"), \
             patch.object(watcher.nm, "activate", return_value=absent), \
             patch.object(watcher, "wait_for_connection") as waiter:
            result = watcher._activate_committed_on("wlan1")
        assert result is False
        waiter.assert_not_called()
