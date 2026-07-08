"""USB failure fallback, runtime adoption, reconnect episodes, and BSSID
survey/roam handling."""
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
        with patch.object(watcher.ADOPTION_CTX, "gather_recovery_facts"), \
             patch.object(watcher.wifi_policy, "next_recovery_action", return_value=action), \
             patch.object(watcher.wifi_adoption, "_submit_client_activation", return_value=True) as ap:
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
        with patch.object(watcher.wifi_adoption, "apply_client_failed", return_value=True) as ap:
            acted = watcher.handle_usb_failure_fallback(hctx)
        assert acted is True
        ap.assert_called_once()


class TestRuntimeUsbAdoption:
    def _builtin_and_usb(self, watcher):
        return (
            _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True),
            _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:10", is_usb=True),
        )

    def test_adopts_after_two_passes_submits_transactional_job(self, watcher):
        # WP-10: adoption now submits an off-thread job; the built-in disconnect /
        # set-active happens on the loop-half tail a pass later.
        builtin, usb = self._builtin_and_usb(watcher)
        adapters = [builtin, usb]
        with patch.object(watcher.wifi_adoption, "resolve_active_client", return_value=builtin), \
             patch.object(watcher.ADOPTION_CTX, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher.ADOPTION_CTX, "query_playing_status", return_value=False), \
             patch.object(watcher.wifi_adoption, "_saved_ssid_visible", return_value=True), \
             patch.object(watcher.ADOPTION_CTX, "submit_activation_job", return_value=True) as submit:
            first = watcher.handle_runtime_usb_adoption(adapters, wired_connected=False)
            second = watcher.handle_runtime_usb_adoption(adapters, wired_connected=False)
        assert first is False   # first pass only records the candidate
        assert second is True   # second stable pass submits the adoption job
        job = submit.call_args[0][0]
        assert job.ifname == "wlan1"
        assert job.disconnects_previous_ifname == "wlan0"   # transactional handover
        assert job.sets_builtin_fallback is False
        assert job.clears_pending_adoption is True
        assert job.records_noip is True and job.stable_id == usb.stable_id

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
        with patch.object(watcher.wifi_adoption, "resolve_active_client", return_value=builtin), \
             patch.object(watcher.ADOPTION_CTX, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher.ADOPTION_CTX, "query_playing_status", side_effect=lambda: playing.pop(0)), \
             patch.object(watcher.wifi_adoption, "_saved_ssid_visible", return_value=True), \
             patch.object(watcher.wifi_activation, "_activate_committed_on", return_value=True), \
             patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"), \
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

    def test_adoption_job_carries_noip_recording(self, watcher):
        # The submitted job carries records_noip so the loop-half failure tail
        # records the no-IP failure (the tail behaviour is covered by
        # TestActivateClient.test_records_noip_on_failure).
        builtin, usb = self._builtin_and_usb(watcher)
        adapters = [builtin, usb]
        with patch.object(watcher.wifi_adoption, "resolve_active_client", return_value=builtin), \
             patch.object(watcher.ADOPTION_CTX, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher.ADOPTION_CTX, "query_playing_status", return_value=False), \
             patch.object(watcher.wifi_adoption, "_saved_ssid_visible", return_value=True), \
             patch.object(watcher.ADOPTION_CTX, "submit_activation_job", return_value=True) as submit:
            watcher.handle_runtime_usb_adoption(adapters, wired_connected=False)
            r = watcher.handle_runtime_usb_adoption(adapters, wired_connected=False)
        assert r is True
        job = submit.call_args[0][0]
        assert job.records_noip is True and job.stable_id == usb.stable_id


class TestStepBssidSurvey:
    """UP-5: step_bssid_survey's gating — before delegating to the survey/roam
    implementation."""

    def _usb(self, watcher, ifname="wlan1", mac="bb:bb:bb:bb:bb:01"):
        return _adapter(watcher, ifname, mac, is_usb=True)

    def _hctx(self, watcher, facts, *, client_ok=True, playing=False):
        pre = watcher.PreFactsContext(now=facts.taken_at, boot_time=0.0, avahi_ok=True)
        fctx = watcher.FactsContext(pre, facts, lambda: playing)
        return watcher.HealthContext(
            fctx, health_ifname="wlan1", wifi_connected=True, client_ok=client_ok,
            conn_ok=client_ok, active_path_ok=client_ok)

    def test_setup_mode_skips(self, watcher):
        watcher.STATE.setup_mode = True
        usb = self._usb(watcher)
        hctx = self._hctx(watcher, _facts_for(watcher, [usb], usb))
        with patch.object(watcher.LOOP_CTX, "bssid_survey_and_roam") as survey:
            v = watcher.step_bssid_survey(hctx)
        assert v is watcher.Verdict.CONTINUE
        survey.assert_not_called()

    def test_transitioning_skips(self, watcher):
        watcher.STATE.transitioning = True
        usb = self._usb(watcher)
        hctx = self._hctx(watcher, _facts_for(watcher, [usb], usb))
        with patch.object(watcher.LOOP_CTX, "bssid_survey_and_roam") as survey:
            v = watcher.step_bssid_survey(hctx)
        assert v is watcher.Verdict.CONTINUE
        survey.assert_not_called()

    def test_onboard_active_skips(self, watcher):
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        hctx = self._hctx(watcher, _facts_for(watcher, [builtin], builtin))
        with patch.object(watcher.LOOP_CTX, "bssid_survey_and_roam") as survey:
            v = watcher.step_bssid_survey(hctx)
        assert v is watcher.Verdict.CONTINUE
        survey.assert_not_called()

    def test_no_active_client_skips(self, watcher):
        hctx = self._hctx(watcher, _facts_for(watcher, [], None))
        with patch.object(watcher.LOOP_CTX, "bssid_survey_and_roam") as survey:
            v = watcher.step_bssid_survey(hctx)
        assert v is watcher.Verdict.CONTINUE
        survey.assert_not_called()

    def test_unhealthy_client_skips(self, watcher):
        usb = self._usb(watcher)
        hctx = self._hctx(watcher, _facts_for(watcher, [usb], usb), client_ok=False)
        with patch.object(watcher.LOOP_CTX, "bssid_survey_and_roam") as survey:
            v = watcher.step_bssid_survey(hctx)
        assert v is watcher.Verdict.CONTINUE
        survey.assert_not_called()

    def test_healthy_usb_delegates_and_owns_pass_on_roam(self, watcher):
        usb = self._usb(watcher)
        hctx = self._hctx(watcher, _facts_for(watcher, [usb], usb))
        with patch.object(watcher.LOOP_CTX, "bssid_survey_and_roam", return_value=True) as survey:
            v = watcher.step_bssid_survey(hctx)
        assert v is watcher.Verdict.OWN_PASS
        survey.assert_called_once_with(hctx)

    def test_healthy_usb_no_roam_continues(self, watcher):
        usb = self._usb(watcher)
        hctx = self._hctx(watcher, _facts_for(watcher, [usb], usb))
        with patch.object(watcher.LOOP_CTX, "bssid_survey_and_roam", return_value=False):
            v = watcher.step_bssid_survey(hctx)
        assert v is watcher.Verdict.CONTINUE


class TestBssidSurveyAndRoam:
    """UP-5: wifi_adoption.bssid_survey_and_roam — source selection, cadence
    gating, roam submission, and confirm-scan reversal."""

    def _usb(self, watcher, ifname="wlan1", mac="bb:bb:bb:bb:bb:01"):
        return _adapter(watcher, ifname, mac, is_usb=True)

    def _facts(self, watcher, usb, extra_adapters=None, now=1000.0):
        adapters = [usb] + (extra_adapters or [])
        return _facts_for(watcher, adapters, usb, now=now)

    def _hctx(self, watcher, facts, *, playing=False):
        pre = watcher.PreFactsContext(now=facts.taken_at, boot_time=0.0, avahi_ok=True)
        fctx = watcher.FactsContext(pre, facts, lambda: playing)
        return watcher.HealthContext(
            fctx, health_ifname=facts.active_client.ifname, wifi_connected=True,
            client_ok=True, conn_ok=True, active_path_ok=True)

    @contextlib.contextmanager
    def _stub_ssid(self, watcher, ssid="Home"):
        with patch.object(watcher.ADOPTION_CTX, "get_configured_network_state",
                          return_value=watcher.wifi_net.NetworkState(ssid, "uuid-1")), \
             patch.object(watcher.wifi_net, "get_connection_ssid", return_value=ssid):
            yield

    def _row(self, bssid, ssid="Home", signal=70, in_use=False):
        return {"in_use": in_use, "bssid": bssid, "ssid": ssid, "signal": signal}

    def test_cheap_usb_scan_runs(self, watcher):
        usb = self._usb(watcher)
        hctx = self._hctx(watcher, self._facts(watcher, usb))
        with self._stub_ssid(watcher), \
             patch.object(watcher.nm, "wifi_bssid_scan", return_value=[]) as scan:
            watcher.bssid_survey_and_roam(hctx)
        scan.assert_any_call("wlan1", rescan=False)

    def test_cadence_gating_skips_until_interval_elapses(self, watcher):
        usb = self._usb(watcher)
        hctx1 = self._hctx(watcher, self._facts(watcher, usb, now=1000.0))
        with self._stub_ssid(watcher), \
             patch.object(watcher.nm, "wifi_bssid_scan", return_value=[]) as scan:
            watcher.bssid_survey_and_roam(hctx1)
            scan.reset_mock()
            hctx2 = self._hctx(watcher, self._facts(watcher, usb, now=1000.0 + 1.0))
            watcher.bssid_survey_and_roam(hctx2)
        scan.assert_not_called()

        with self._stub_ssid(watcher), \
             patch.object(watcher.nm, "wifi_bssid_scan", return_value=[]) as scan:
            hctx3 = self._hctx(
                watcher, self._facts(watcher, usb, now=1000.0 + watcher.BSSID_SURVEY_INTERVAL))
            watcher.bssid_survey_and_roam(hctx3)
        scan.assert_any_call("wlan1", rescan=False)

    def test_idle_onboard_scanned_alongside(self, watcher):
        usb = self._usb(watcher)
        onboard = _adapter(watcher, "wlan0", "aa:aa:aa:aa:aa:01", is_builtin=True)
        hctx = self._hctx(watcher, self._facts(watcher, usb, extra_adapters=[onboard]))
        with self._stub_ssid(watcher), \
             patch.object(watcher.ADOPTION_CTX, "resolve_hotspot_adapter", return_value=None), \
             patch.object(watcher.wifi_recovery, "adapter_disabled", return_value=False), \
             patch.object(watcher.wifi_recovery, "adapter_quarantined_until", return_value=None), \
             patch.object(watcher.nm, "wifi_bssid_scan", return_value=[]) as scan:
            watcher.bssid_survey_and_roam(hctx)
        scan.assert_any_call("wlan0", rescan=True)

    def test_onboard_busy_as_hotspot_is_skipped(self, watcher):
        usb = self._usb(watcher)
        onboard = _adapter(watcher, "wlan0", "aa:aa:aa:aa:aa:01", is_builtin=True)
        hctx = self._hctx(watcher, self._facts(watcher, usb, extra_adapters=[onboard]))
        with self._stub_ssid(watcher), \
             patch.object(watcher.ADOPTION_CTX, "resolve_hotspot_adapter", return_value=onboard), \
             patch.object(watcher.nm, "wifi_bssid_scan", return_value=[]) as scan:
            watcher.bssid_survey_and_roam(hctx)
        assert all(c.args[0] != "wlan0" for c in scan.call_args_list)

    def test_onboard_disabled_is_skipped(self, watcher):
        usb = self._usb(watcher)
        onboard = _adapter(watcher, "wlan0", "aa:aa:aa:aa:aa:01", is_builtin=True)
        hctx = self._hctx(watcher, self._facts(watcher, usb, extra_adapters=[onboard]))
        with self._stub_ssid(watcher), \
             patch.object(watcher.ADOPTION_CTX, "resolve_hotspot_adapter", return_value=None), \
             patch.object(watcher.wifi_recovery, "adapter_disabled", return_value=True), \
             patch.object(watcher.nm, "wifi_bssid_scan", return_value=[]) as scan:
            watcher.bssid_survey_and_roam(hctx)
        assert all(c.args[0] != "wlan0" for c in scan.call_args_list)

    def test_playing_skips_full_usb_rescan(self, watcher):
        usb = self._usb(watcher)
        # Elapse both cadences so only the playback gate can suppress the full scan.
        now = 1000.0 + watcher.BSSID_USB_SURVEY_INTERVAL
        hctx = self._hctx(watcher, self._facts(watcher, usb, now=now), playing=True)
        with self._stub_ssid(watcher), \
             patch.object(watcher.nm, "wifi_bssid_scan", return_value=[]) as scan:
            watcher.bssid_survey_and_roam(hctx)
        for c in scan.call_args_list:
            assert not (c.args == ("wlan1",) and c.kwargs.get("rescan") is True)

    def test_dial_mode_playback_false_full_scan_and_roam(self, watcher):
        # playback False (dial mode / idle) is exactly the roam-eligible state.
        usb = self._usb(watcher)
        now = 1000.0 + watcher.BSSID_USB_SURVEY_INTERVAL
        hctx = self._hctx(watcher, self._facts(watcher, usb, now=now), playing=False)
        rows = [
            self._row("AA:AA:AA:AA:AA:AA", signal=50, in_use=True),
            self._row("BB:BB:BB:BB:BB:BB", signal=90),
        ]
        with self._stub_ssid(watcher), \
             patch.object(watcher.nm, "wifi_bssid_scan", return_value=rows), \
             patch.object(watcher.ADOPTION_CTX, "submit_activation_job", return_value=True) as submit:
            result = watcher.bssid_survey_and_roam(hctx)
        assert result is True
        job = submit.call_args[0][0]
        assert job.kind == "activate_committed" and job.ifname == "wlan1"
        assert watcher.STATE.last_roam_or_activation == now

    def test_confirm_scan_reversal_no_submission(self, watcher):
        usb = self._usb(watcher)
        now = 1000.0 + watcher.BSSID_USB_SURVEY_INTERVAL
        hctx = self._hctx(watcher, self._facts(watcher, usb, now=now), playing=False)
        survey_rows = [
            self._row("AA:AA:AA:AA:AA:AA", signal=50, in_use=True),
            self._row("BB:BB:BB:BB:BB:BB", signal=90),
        ]
        # The confirm scan reverses the picture: the candidate has faded back down.
        confirm_rows = [
            self._row("AA:AA:AA:AA:AA:AA", signal=50, in_use=True),
            self._row("BB:BB:BB:BB:BB:BB", signal=52),
        ]
        with self._stub_ssid(watcher), \
             patch.object(watcher.nm, "wifi_bssid_scan", side_effect=[survey_rows, confirm_rows]), \
             patch.object(watcher.ADOPTION_CTX, "submit_activation_job") as submit:
            result = watcher.bssid_survey_and_roam(hctx)
        assert result is False
        submit.assert_not_called()

    def test_no_ssid_returns_false(self, watcher):
        usb = self._usb(watcher)
        hctx = self._hctx(watcher, self._facts(watcher, usb))
        with patch.object(watcher.ADOPTION_CTX, "get_configured_network_state",
                          return_value=watcher.wifi_net.NetworkState("", "")), \
             patch.object(watcher.nm, "wifi_bssid_scan") as scan:
            result = watcher.bssid_survey_and_roam(hctx)
        assert result is False
        scan.assert_not_called()


class TestIf6AdoptionScanGate:
    """IF-6: runtime USB adoption scans the candidate for the committed SSID
    before moving the shared profile, so a dongle that cannot see the network
    never takes the healthy built-in offline (04-Jul field outage)."""

    def _builtin_and_usb(self, watcher):
        return (
            _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True),
            _adapter(watcher, "wlan1", "bb:bb:bb:bb:bb:10", is_usb=True),
        )

    def _prime_to_gate(self, watcher, candidate):
        """Arm STATE so the *next* adoption call reaches the scan gate (two-pass
        stability already satisfied)."""
        watcher.STATE.pending_usb_adoption_mac = candidate.permanent_mac
        watcher.STATE.pending_usb_adoption_checks = 1

    @contextlib.contextmanager
    def _gate_ctx(self, watcher, builtin, *, scan):
        with ExitStack() as stack:
            stack.enter_context(patch.object(watcher.wifi_adoption, "resolve_active_client", return_value=builtin))
            stack.enter_context(patch.object(watcher.ADOPTION_CTX, "is_wifi_client_healthy", return_value=True))
            stack.enter_context(patch.object(watcher.ADOPTION_CTX, "query_playing_status", return_value=False))
            stack.enter_context(patch.object(watcher.wifi_adoption, "_saved_network_ssid", return_value="MyHomeWiFi"))
            scan_mock = stack.enter_context(
                patch.object(watcher.wifi_net, "scan_adapter", return_value=scan))
            act = stack.enter_context(patch.object(watcher.wifi_activation, "_activate_committed_on", return_value=True))
            stack.enter_context(patch.object(watcher.ACTIVATION_CTX, "verify_avahi_after_handover"))
            stack.enter_context(patch.object(watcher, "run_cmd", return_value=MagicMock(returncode=0)))
            yield scan_mock, act

    def test_not_visible_skips_without_activation_or_ledger(self, watcher):
        # (a)+(b): SSID absent from the scan -> no activation, pending state and
        # the no-IP ledger both survive the skip.
        builtin, usb = self._builtin_and_usb(watcher)
        adapters = [builtin, usb]
        self._prime_to_gate(watcher, usb)
        with self._gate_ctx(watcher, builtin, scan={"Other": -50}) as (scan_mock, act):
            r = watcher.handle_runtime_usb_adoption(adapters, wired_connected=False)
        assert r is False
        act.assert_not_called()
        scan_mock.assert_called_once()
        # Pending candidate survives so a later due scan can proceed.
        assert watcher.STATE.pending_usb_adoption_mac == usb.permanent_mac
        assert watcher.STATE.pending_usb_adoption_checks == 2
        # No no-IP failure recorded — the dongle never got to fail DHCP.
        assert watcher.wifi_recovery.noip_failure_count(watcher, usb.permanent_mac) == 0

    def test_rate_bounded_second_pass_does_not_scan(self, watcher):
        # (c): a second not-visible pass inside ADOPTION_SCAN_INTERVAL performs
        # no scan and still returns False.
        builtin, usb = self._builtin_and_usb(watcher)
        adapters = [builtin, usb]
        self._prime_to_gate(watcher, usb)
        with self._gate_ctx(watcher, builtin, scan={"Other": -50}) as (scan_mock, act):
            r1 = watcher.handle_runtime_usb_adoption(adapters, wired_connected=False)
            r2 = watcher.handle_runtime_usb_adoption(adapters, wired_connected=False)
        assert (r1, r2) == (False, False)
        act.assert_not_called()
        scan_mock.assert_called_once()  # second pass: not due -> no scan

    def test_failed_scan_treated_as_not_visible(self, watcher):
        # (e): scan_adapter -> None is conservatively treated as not visible.
        builtin, usb = self._builtin_and_usb(watcher)
        adapters = [builtin, usb]
        self._prime_to_gate(watcher, usb)
        with self._gate_ctx(watcher, builtin, scan=None) as (scan_mock, act):
            r = watcher.handle_runtime_usb_adoption(adapters, wired_connected=False)
        assert r is False
        act.assert_not_called()
        scan_mock.assert_called_once()
        assert watcher.wifi_recovery.noip_failure_count(watcher, usb.permanent_mac) == 0

    def test_visible_ssid_submits_transactional_job(self, watcher):
        # (d): committed SSID visible -> the adoption job is submitted (validated
        # off-thread; the built-in disconnect is the loop-half success tail).
        builtin, usb = self._builtin_and_usb(watcher)
        adapters = [builtin, usb]
        self._prime_to_gate(watcher, usb)
        with self._gate_ctx(watcher, builtin, scan={"MyHomeWiFi": -50}) as (scan_mock, _act), \
             patch.object(watcher.ADOPTION_CTX, "submit_activation_job", return_value=True) as submit:
            r = watcher.handle_runtime_usb_adoption(adapters, wired_connected=False)
        assert r is True
        scan_mock.assert_called_once()
        submit.assert_called_once()
        job = submit.call_args[0][0]
        assert job.ifname == "wlan1"
        assert job.disconnects_previous_ifname == "wlan0"
        assert job.records_noip is True

    def test_visible_then_submits_job_with_noip_recording(self, watcher):
        # (d), failure tail: SSID visible -> the submitted job carries records_noip
        # so a failed activation ticks the no-IP ledger on the loop-half tail.
        builtin, usb = self._builtin_and_usb(watcher)
        adapters = [builtin, usb]
        self._prime_to_gate(watcher, usb)
        with ExitStack() as stack:
            stack.enter_context(patch.object(watcher.wifi_adoption, "resolve_active_client", return_value=builtin))
            stack.enter_context(patch.object(watcher.ADOPTION_CTX, "is_wifi_client_healthy", return_value=True))
            stack.enter_context(patch.object(watcher.ADOPTION_CTX, "query_playing_status", return_value=False))
            stack.enter_context(patch.object(watcher.wifi_adoption, "_saved_network_ssid", return_value="MyHomeWiFi"))
            stack.enter_context(patch.object(watcher.wifi_net, "scan_adapter",
                                             return_value={"MyHomeWiFi": -50}))
            submit = stack.enter_context(
                patch.object(watcher.ADOPTION_CTX, "submit_activation_job", return_value=True))
            r = watcher.handle_runtime_usb_adoption(adapters, wired_connected=False)
        assert r is True
        job = submit.call_args[0][0]
        assert job.records_noip is True and job.stable_id == usb.stable_id


class TestReconnectSavedEpisode:
    """WP-4 — reconnect-saved is a single-target-per-pass async episode.

    The old synchronous multi-target join is gone; the per-target join mechanics
    (AP drop/rebuild, restriction clearing, net-absent short-circuit) now run on
    the worker via _run_activation_job / _activate_profile_on and are covered by
    TestActivationWorker and the _activate_profile_on tests below.  These pin the
    episode bookkeeping and the flags on each submitted job.
    """

    def _pre(self, watcher, now=0.0):
        return watcher.PreFactsContext(now=now, boot_time=0.0, avahi_ok=False)

    def test_starts_episode_and_submits_first_target(self, watcher):
        watcher.STATE.setup_mode = True
        watcher.STATE.hotspot = watcher.HotspotSession(
            purpose=watcher.HotspotPurpose.USB_LOSS_RECOVERY, entered_at=0.0)
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        with patch.object(watcher.wifi_net, "discover_adapters", return_value=[builtin]), \
             patch.object(watcher.wifi_net, "client_candidate_order", return_value=[builtin]), \
             patch.object(watcher.ADOPTION_CTX, "get_configured_network_state",
                          return_value=watcher.wifi_net.NetworkState("Home", "uuid-1")), \
             patch.object(watcher.ADOPTION_CTX, "resolve_hotspot_adapter", return_value=builtin), \
             patch.object(watcher.ADOPTION_CTX, "submit_activation_job", return_value=True) as submit:
            started = watcher.start_reconnect_saved_episode("retain_hotspot")
        assert started is True
        ep = watcher.STATE.reconnect_episode
        assert ep is not None
        assert ep.target_ifnames == ["wlan0"]
        assert ep.profile_name == "Home" and ep.profile_uuid == "uuid-1"
        assert ep.hotspot_ifname == "wlan0"
        submit.assert_called_once()
        job = submit.call_args[0][0]
        assert job.ifname == "wlan0"
        assert job.profile.connection_name == "Home"
        assert job.drop_hotspot is True          # target IS the AP-hosting radio
        assert job.on_success_leaves_setup is True
        assert job.leave_reason == "WiFi client connection succeeded"
        assert ep.inflight_epoch == job.epoch

    def test_not_configured_starts_no_episode(self, watcher):
        with patch.object(watcher.wifi_net, "discover_adapters", return_value=[]), \
             patch.object(watcher.wifi_net, "client_candidate_order", return_value=[]), \
             patch.object(watcher, "get_configured_network_state",
                          return_value=watcher.wifi_net.NetworkState("", "")), \
             patch.object(watcher, "submit_activation_job") as submit:
            started = watcher.start_reconnect_saved_episode()
        assert started is False
        assert watcher.STATE.reconnect_episode is None
        submit.assert_not_called()

    def test_explicit_reconfigure_prefers_rollback_adapter_and_profile(self, watcher):
        watcher.STATE.setup_mode = True
        watcher.STATE.hotspot = watcher.HotspotSession(
            purpose=watcher.HotspotPurpose.EXPLICIT_RECONFIGURE, entered_at=0.0,
            rollback=watcher.RollbackSnapshot("Prev", "uuid-prev", "aa:bb:cc:00:00:09"))
        prev = _adapter(watcher, "wlan1", "aa:bb:cc:00:00:09", is_usb=True)
        builtin = _adapter(watcher, "wlan0", "aa:bb:cc:00:00:01", is_builtin=True)
        with patch.object(watcher.wifi_net, "discover_adapters", return_value=[builtin, prev]), \
             patch.object(watcher.wifi_net, "find_adapter_by_mac", return_value=prev), \
             patch.object(watcher.wifi_net, "client_candidate_order", return_value=[builtin, prev]), \
             patch.object(watcher, "resolve_hotspot_adapter", return_value=builtin), \
             patch.object(watcher, "submit_activation_job", return_value=True):
            watcher.start_reconnect_saved_episode()
        ep = watcher.STATE.reconnect_episode
        # rollback adapter (wlan1) first, then client_candidate_order; rollback
        # profile restored (not the committed one).
        assert ep.target_ifnames[0] == "wlan1"
        assert ep.profile_name == "Prev" and ep.profile_uuid == "uuid-prev"

    def test_failure_advances_to_next_target(self, watcher):
        watcher.STATE.reconnect_episode = watcher.ReconnectEpisode(
            target_ifnames=["wlan1", "wlan0"], profile_name="Home", profile_uuid="uuid-1",
            hotspot_ifname="wlan0", failure_tail="retain_hotspot", index=0, inflight_epoch=7)
        job = watcher.ActivationJob(epoch=7, kind="activate_profile", ifname="wlan1")
        watcher._advance_reconnect_episode(watcher.ActivationResult(7, False, "wlan1", job))
        ep = watcher.STATE.reconnect_episode
        assert ep.index == 1 and ep.inflight_epoch is None
        # A subsequent pass submits the next target and owns the pass.
        with patch.object(watcher.ADOPTION_CTX, "submit_activation_job", return_value=True) as submit:
            v = watcher.step_reconnect_episode(self._pre(watcher))
        assert v is watcher.Verdict.OWN_PASS
        assert submit.call_args[0][0].ifname == "wlan0"

    def test_success_ends_episode(self, watcher):
        watcher.STATE.reconnect_episode = watcher.ReconnectEpisode(
            target_ifnames=["wlan0"], profile_name="Home", profile_uuid="uuid-1",
            hotspot_ifname="wlan0", failure_tail="retain_hotspot", index=0, inflight_epoch=3)
        job = watcher.ActivationJob(epoch=3, kind="activate_profile", ifname="wlan0")
        watcher._advance_reconnect_episode(watcher.ActivationResult(3, True, "wlan0", job))
        assert watcher.STATE.reconnect_episode is None

    def test_foreign_result_does_not_advance(self, watcher):
        watcher.STATE.reconnect_episode = watcher.ReconnectEpisode(
            target_ifnames=["wlan0"], profile_name="Home", profile_uuid="uuid-1",
            hotspot_ifname="wlan0", failure_tail="retain_hotspot", index=0, inflight_epoch=5)
        job = watcher.ActivationJob(epoch=99, kind="activate_committed", ifname="wlan0")
        watcher._advance_reconnect_episode(watcher.ActivationResult(99, False, "wlan0", job))
        # A result from a different job (epoch mismatch) leaves the episode intact.
        assert watcher.STATE.reconnect_episode.index == 0

    def test_exhaustion_retain_hotspot_tail(self, watcher):
        watcher.STATE.setup_mode = True
        watcher.STATE.hotspot = watcher.HotspotSession(
            purpose=watcher.HotspotPurpose.USB_LOSS_RECOVERY, entered_at=0.0)
        watcher.STATE.reconnect_episode = watcher.ReconnectEpisode(
            target_ifnames=["wlan0"], profile_name="Home", profile_uuid="uuid-1",
            hotspot_ifname="wlan0", failure_tail="retain_hotspot", index=1)
        assert watcher._submit_next_reconnect_target() is False
        assert watcher.STATE.reconnect_episode is None
        # Hotspot retained, purpose unchanged.
        assert watcher.STATE.hotspot.purpose is watcher.HotspotPurpose.USB_LOSS_RECOVERY

    def test_exhaustion_reconfigure_timeout_converts_to_usb_loss(self, watcher):
        watcher.STATE.setup_mode = True
        watcher.STATE.hotspot = watcher.HotspotSession(
            purpose=watcher.HotspotPurpose.EXPLICIT_RECONFIGURE, entered_at=0.0,
            rollback=watcher.RollbackSnapshot("Home", "uuid-1", ""))
        watcher.STATE.reconnect_episode = watcher.ReconnectEpisode(
            target_ifnames=["wlan0"], profile_name="Home", profile_uuid="uuid-1",
            hotspot_ifname="wlan0", failure_tail="reconfigure_timeout", index=1)
        watcher._submit_next_reconnect_target()
        assert watcher.STATE.reconnect_episode is None
        assert watcher.STATE.hotspot.purpose is watcher.HotspotPurpose.USB_LOSS_RECOVERY
        assert watcher.STATE.hotspot.rollback is None

    def test_episode_deferred_while_transitioning(self, watcher):
        watcher.STATE.reconnect_episode = watcher.ReconnectEpisode(
            target_ifnames=["wlan0"], profile_name="Home", profile_uuid="uuid-1",
            hotspot_ifname="", failure_tail="retain_hotspot")
        watcher.STATE.transitioning = True
        with patch.object(watcher, "submit_activation_job") as submit:
            v = watcher.step_reconnect_episode(self._pre(watcher))
        assert v is watcher.Verdict.CONTINUE
        submit.assert_not_called()

    def test_disruptive_control_action_deferred_during_episode(self, watcher):
        watcher.STATE.reconnect_episode = watcher.ReconnectEpisode(
            target_ifnames=["wlan0"], profile_name="Home", profile_uuid="uuid-1",
            hotspot_ifname="", failure_tail="retain_hotspot")
        watcher.STATE.transitioning = False
        watcher.STATE.pending_control_action = "start_setup"
        watcher.control_action_event.set()
        with patch.object(watcher.LOOP_CTX, "process_control_action") as pca:
            v = watcher.step_control_action(self._pre(watcher))
        assert v is watcher.Verdict.CONTINUE
        pca.assert_not_called()
        assert watcher.control_action_event.is_set()   # left queued until episode ends

    # ---- the per-target join mechanics preserved on _activate_profile_on ----

    def test_activate_profile_on_clears_restrictions_before_activation(self, watcher):
        order = []
        with patch.object(watcher.wifi_net, "resolve_connection_uuid_for_name",
                          return_value="resolved-uuid"), \
             patch.object(watcher.wifi_net, "save_network_state"), \
             patch.object(watcher.wifi_net, "usb_sysfs_paths", return_value=None), \
             patch.object(watcher.nm, "clear_restrictions",
                          side_effect=lambda *a, **k: order.append("clear")), \
             patch.object(watcher.nm, "set_bssid"), \
             patch.object(watcher.nm, "activate",
                          side_effect=lambda *a, **k: order.append("activate") or MagicMock(returncode=0, stderr="")), \
             patch.object(watcher, "wait_for_connection", return_value=True), \
             patch.object(watcher, "is_wifi_client_healthy", return_value=True):
            watcher._activate_profile_on("wlan0", watcher.wifi_net.NetworkState("Home", ""))
        assert order == ["clear", "activate"]   # restrictions cleared BEFORE activation

    def test_activate_profile_on_netabsent_skips_ipv4_wait(self, watcher):
        absent = MagicMock(
            returncode=10,
            stderr="Error: Connection activation failed: The Wi-Fi network could not be found")
        with patch.object(watcher.wifi_net, "usb_sysfs_paths", return_value=None), \
             patch.object(watcher.nm, "clear_restrictions"), \
             patch.object(watcher.nm, "set_bssid"), \
             patch.object(watcher.nm, "activate", return_value=absent), \
             patch.object(watcher, "wait_for_connection") as wait:
            ok = watcher._activate_profile_on(
                "wlan0", watcher.wifi_net.NetworkState("Home", "uuid-1"))
        assert ok is False
        wait.assert_not_called()


class TestPinUsbBssid:
    """UP-3: the USB BSSID pin seam inside _activate_profile_on."""

    def _rows(self, bssid="AA:BB:CC:DD:EE:FF", ssid="Home", signal=70, in_use=False):
        return [{"in_use": in_use, "bssid": bssid, "ssid": ssid, "signal": signal}]

    def test_non_usb_target_clears_bssid(self, watcher):
        with patch.object(watcher.wifi_net, "usb_sysfs_paths", return_value=None), \
             patch.object(watcher.nm, "set_bssid") as set_bssid, \
             patch.object(watcher.nm, "wifi_bssid_scan") as scan:
            result = watcher._pin_usb_bssid("wlan0", "uuid-1")
        assert result == ""
        set_bssid.assert_called_once_with("uuid-1", "")
        scan.assert_not_called()
        assert watcher.STATE.last_bssid_pin == {}

    def test_usb_target_pins_from_scan(self, watcher):
        with patch.object(watcher.wifi_net, "usb_sysfs_paths", return_value={"driver": "rtl8xxxu"}), \
             patch.object(watcher.wifi_net, "get_connection_ssid", return_value="Home"), \
             patch.object(watcher.nm, "wifi_bssid_scan", return_value=self._rows()), \
             patch.object(watcher.nm, "set_bssid") as set_bssid:
            result = watcher._pin_usb_bssid("wlan1", "uuid-1")
        assert result == "AA:BB:CC:DD:EE:FF"
        set_bssid.assert_called_once_with("uuid-1", "AA:BB:CC:DD:EE:FF")
        assert watcher.STATE.last_bssid_pin["ifname"] == "wlan1"
        assert watcher.STATE.last_bssid_pin["bssid"] == "AA:BB:CC:DD:EE:FF"
        assert watcher.STATE.last_bssid_pin["signal"] == 70
        assert watcher.STATE.bssid_table["AA:BB:CC:DD:EE:FF"]["ssid"] == "Home"

    def test_scan_failure_falls_back_to_unpinned(self, watcher):
        with patch.object(watcher.wifi_net, "usb_sysfs_paths", return_value={"driver": "rtl8xxxu"}), \
             patch.object(watcher.wifi_net, "get_connection_ssid", return_value="Home"), \
             patch.object(watcher.nm, "wifi_bssid_scan", return_value=None), \
             patch.object(watcher.nm, "set_bssid") as set_bssid:
            result = watcher._pin_usb_bssid("wlan1", "uuid-1")
        assert result == ""
        set_bssid.assert_called_once_with("uuid-1", "")
        assert watcher.STATE.last_bssid_pin == {}

    def test_no_candidate_falls_back_to_unpinned(self, watcher):
        # Scan succeeds but yields no row for the committed SSID.
        with patch.object(watcher.wifi_net, "usb_sysfs_paths", return_value={"driver": "rtl8xxxu"}), \
             patch.object(watcher.wifi_net, "get_connection_ssid", return_value="Home"), \
             patch.object(watcher.nm, "wifi_bssid_scan", return_value=[]), \
             patch.object(watcher.nm, "set_bssid") as set_bssid:
            result = watcher._pin_usb_bssid("wlan1", "uuid-1")
        assert result == ""
        set_bssid.assert_called_once_with("uuid-1", "")

    def test_success_accounting_reaches_table(self, watcher):
        watcher.STATE.bssid_table["AA:BB:CC:DD:EE:FF"] = {
            "ssid": "Home", "signal": 70, "last_seen": 100.0,
            "fail_count": 2, "quarantined_until": None,
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
            ok = watcher._activate_profile_on(
                "wlan1", watcher.wifi_net.NetworkState("Home", ""))
        assert ok is True
        assert watcher.STATE.bssid_table["AA:BB:CC:DD:EE:FF"]["fail_count"] == 0

    def test_failure_accounting_reaches_table(self, watcher):
        with patch.object(watcher.wifi_net, "usb_sysfs_paths", return_value={"driver": "rtl8xxxu"}), \
             patch.object(watcher.wifi_net, "resolve_connection_uuid_for_name", return_value="uuid-1"), \
             patch.object(watcher.wifi_net, "get_connection_ssid", return_value="Home"), \
             patch.object(watcher.nm, "clear_restrictions"), \
             patch.object(watcher.nm, "wifi_bssid_scan", return_value=self._rows()), \
             patch.object(watcher.nm, "set_bssid"), \
             patch.object(watcher.nm, "activate", return_value=MagicMock(returncode=1, stderr="failed")), \
             patch.object(watcher.ACTIVATION_CTX, "wait_for_connection", return_value=False), \
             patch.object(watcher.ACTIVATION_CTX, "is_wifi_client_healthy", return_value=False):
            ok = watcher._activate_profile_on(
                "wlan1", watcher.wifi_net.NetworkState("Home", ""))
        assert ok is False
        assert watcher.STATE.bssid_table["AA:BB:CC:DD:EE:FF"]["fail_count"] == 1


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
             patch.object(watcher.wifi_adoption, "apply_client_failed", return_value=True) as ap:
            v1 = _one_pass()
            assert v1 is watcher.Verdict.CONTINUE            # pass 1: held, no fallback
            assert ap.call_count == 0
            assert watcher.STATE.active_client_mac == usb_mac  # preserved for pass 2
            v2 = _one_pass()
            assert v2 is watcher.Verdict.OWN_PASS            # pass 2: condemned -> fallback
            ap.assert_called_once()
