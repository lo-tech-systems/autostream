"""Avahi hostname repair and mDNS re-announce on handover."""
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


class TestAvahiHandoverReannounce:
    def _ok_result(self):
        return MagicMock(returncode=0, stdout="", stderr="")

    def test_verify_after_handover_checks_hostname_then_marks_pending(self, watcher):
        with patch.object(watcher.wifi_mdns, "check_and_repair_avahi_hostname") as check, \
             patch.object(watcher.wifi_mdns, "mark_mdns_reannounce_pending") as mark:
            watcher.verify_avahi_after_handover()
        check.assert_called_once()
        mark.assert_called_once()

    def test_mark_pending_arms_debounce(self, watcher):
        with patch("time.monotonic", return_value=100.0):
            watcher.wifi_mdns.mark_mdns_reannounce_pending(watcher.MDNS_CTX, "test")
        assert watcher.STATE.mdns_reannounce_pending is True
        assert watcher.STATE.mdns_address_changed_at == 100.0

    def test_first_observation_only_baselines(self, watcher):
        both = frozenset({("eth0", "192.168.1.5"), ("wlan1", "192.168.1.9")})
        with patch.object(watcher.wifi_mdns, "_current_mdns_address_set", return_value=both), \
             patch.object(watcher.wifi_mdns, "restart_avahi_daemon") as restart:
            watcher.wifi_mdns.maybe_reannounce_mdns(watcher.MDNS_CTX, now=0.0)
        restart.assert_not_called()
        assert watcher.STATE.mdns_address_set == both

    def test_address_change_debounces_then_restarts(self, watcher):
        both = frozenset({("eth0", "192.168.1.5"), ("wlan1", "192.168.1.9")})
        eth_only = frozenset({("eth0", "192.168.1.5")})
        watcher.STATE.mdns_address_set = both

        # Dongle removed: set changes -> arm debounce, no restart yet.
        with patch.object(watcher.wifi_mdns, "_current_mdns_address_set", return_value=eth_only), \
             patch.object(watcher.wifi_mdns, "restart_avahi_daemon") as restart:
            watcher.wifi_mdns.maybe_reannounce_mdns(watcher.MDNS_CTX, now=10.0)
        restart.assert_not_called()
        assert watcher.STATE.mdns_address_changed_at == 10.0

        # Stable but still inside the debounce window: no restart.
        with patch.object(watcher.wifi_mdns, "_current_mdns_address_set", return_value=eth_only), \
             patch.object(watcher.wifi_mdns, "restart_avahi_daemon") as restart:
            watcher.wifi_mdns.maybe_reannounce_mdns(watcher.MDNS_CTX, now=13.0)
        restart.assert_not_called()

        # Stable past the debounce window: re-announce fires once.
        with patch.object(watcher.wifi_mdns, "_current_mdns_address_set", return_value=eth_only), \
             patch.object(watcher.wifi_mdns, "restart_avahi_daemon") as restart:
            watcher.wifi_mdns.maybe_reannounce_mdns(watcher.MDNS_CTX, now=20.0)
        restart.assert_called_once_with(watcher.MDNS_CTX, "network-path re-announce")
        assert watcher.STATE.last_avahi_handover_restart == 20.0
        assert watcher.STATE.mdns_address_changed_at is None

    def test_reannounce_is_rate_limited_for_60_seconds(self, watcher):
        eth_only = frozenset({("eth0", "192.168.1.5")})
        watcher.STATE.mdns_address_set = eth_only
        watcher.STATE.mdns_address_changed_at = 100.0
        watcher.STATE.last_avahi_handover_restart = 100.0

        # Debounce satisfied but within the 60s rate-limit window: suppressed,
        # and the trigger stays armed for a later pass.
        with patch.object(watcher.wifi_mdns, "_current_mdns_address_set", return_value=eth_only), \
             patch.object(watcher.wifi_mdns, "restart_avahi_daemon") as restart:
            watcher.wifi_mdns.maybe_reannounce_mdns(watcher.MDNS_CTX, now=159.0)
        restart.assert_not_called()
        assert watcher.STATE.mdns_address_changed_at == 100.0

        # Past the rate-limit window: fires.
        with patch.object(watcher.wifi_mdns, "_current_mdns_address_set", return_value=eth_only), \
             patch.object(watcher.wifi_mdns, "restart_avahi_daemon") as restart:
            watcher.wifi_mdns.maybe_reannounce_mdns(watcher.MDNS_CTX, now=160.0)
        restart.assert_called_once_with(watcher.MDNS_CTX, "network-path re-announce")
        assert watcher.STATE.last_avahi_handover_restart == 160.0

    def test_pending_nudge_fires_when_address_set_unchanged(self, watcher):
        eth_only = frozenset({("eth0", "192.168.1.5")})
        watcher.STATE.mdns_address_set = eth_only
        # Orchestrated handover where our observed set looks the same.
        with patch("time.monotonic", return_value=200.0):
            watcher.wifi_mdns.mark_mdns_reannounce_pending(watcher.MDNS_CTX, "network handover")
        with patch.object(watcher.wifi_mdns, "_current_mdns_address_set", return_value=eth_only), \
             patch.object(watcher.wifi_mdns, "restart_avahi_daemon") as restart:
            watcher.wifi_mdns.maybe_reannounce_mdns(watcher.MDNS_CTX, now=210.0)
        restart.assert_called_once_with(watcher.MDNS_CTX, "network-path re-announce")
        assert watcher.STATE.mdns_reannounce_pending is False

    def test_stable_address_set_does_not_restart(self, watcher):
        eth_only = frozenset({("eth0", "192.168.1.5")})
        watcher.STATE.mdns_address_set = eth_only
        with patch.object(watcher.wifi_mdns, "_current_mdns_address_set", return_value=eth_only), \
             patch.object(watcher.wifi_mdns, "restart_avahi_daemon") as restart:
            watcher.wifi_mdns.maybe_reannounce_mdns(watcher.MDNS_CTX, now=500.0)
        restart.assert_not_called()

    def test_hostname_mismatch_repair_still_uses_conflict_restart_budget(self, watcher):
        watcher.STATE.avahi_mismatch_start = 0.0

        # The mDNS helpers read the watcher through MDNS_CTX (the narrowed
        # seam), so inject _DBUS_SEND/run_cmd/get_system_hostname on the context and
        # patch the sibling query on wifi_mdns.
        with patch("time.monotonic", return_value=watcher.AVAHI_MISMATCH_GRACE + 1.0), \
             patch.object(watcher.MDNS_CTX, "_DBUS_SEND", "/usr/bin/dbus-send"), \
             patch.object(watcher.wifi_mdns, "get_avahi_registered_hostname", return_value="autostream-2"), \
             patch.object(watcher.MDNS_CTX, "get_system_hostname", return_value="autostream"), \
             patch.object(watcher.MDNS_CTX, "run_cmd", return_value=self._ok_result()) as run:
            watcher.wifi_mdns.check_and_repair_avahi_hostname(watcher.MDNS_CTX)

        run.assert_called_once_with(["systemctl", "restart", "avahi-daemon.service"],
                                    timeout=watcher.NMCLI_QUICK_TIMEOUT)
        assert watcher.STATE.avahi_restart_count == 1
        assert watcher.STATE.last_avahi_restart == watcher.AVAHI_MISMATCH_GRACE + 1.0
        assert watcher.STATE.last_avahi_handover_restart is None
