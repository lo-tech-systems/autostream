"""HotspotController lifecycle and station-count queries."""
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


class TestHotspotController:
    """WP-8 — HotspotController owns the start/stop/rebuild/clear-stale sequencing
    and pins the flag-ordering invariants."""

    def test_start_sets_flag_when_ap_started(self, watcher):
        watcher.STATE.setup_mode = True   # start_ap_mode leaves it set (AP came up)
        with patch.object(watcher, "start_ap_mode") as start, \
             patch.object(watcher, "update_apmode_flag") as flag:
            watcher.hotspot_controller.start()
        start.assert_called_once()
        flag.assert_called_once_with(True)

    def test_start_sets_no_flag_on_abort(self, watcher):
        # start_ap_mode aborted (no adapter) and cleared setup_mode -> no flag.
        def _abort():
            watcher.STATE.setup_mode = False
        watcher.STATE.setup_mode = True
        with patch.object(watcher, "start_ap_mode", side_effect=_abort), \
             patch.object(watcher, "update_apmode_flag") as flag:
            watcher.hotspot_controller.start()
        flag.assert_not_called()

    def test_stop_tears_down_ap_before_removing_flag(self, watcher):
        order: list[str] = []
        with patch.object(watcher, "stop_ap_mode", side_effect=lambda: order.append("stop_ap")), \
             patch.object(watcher, "update_apmode_flag",
                          side_effect=lambda v: order.append(f"flag_{v}")):
            watcher.hotspot_controller.stop()
        assert order == ["stop_ap", "flag_False"]

    def test_rebuild_reasserts_setup_and_rebuilds(self, watcher):
        watcher.STATE.setup_mode = False   # a racing leave cleared it mid-drop
        with patch.object(watcher, "start_ap_mode") as start, \
             patch.object(watcher, "update_apmode_flag") as flag:
            watcher.hotspot_controller.rebuild()
        assert watcher.STATE.setup_mode is True   # re-asserted
        start.assert_called_once()
        flag.assert_called_once_with(True)

    def test_rebuild_sets_no_flag_when_ap_fails_to_come_back(self, watcher):
        # start_ap_mode's own nmcli failure handling clears setup_mode again;
        # rebuild() must not recreate the flag for an AP that never came up.
        def _nmcli_failure():
            watcher.STATE.setup_mode = False
            watcher.STATE.hotspot = None
        watcher.STATE.setup_mode = False
        with patch.object(watcher, "start_ap_mode", side_effect=_nmcli_failure) as start, \
             patch.object(watcher, "update_apmode_flag") as flag:
            watcher.hotspot_controller.rebuild()
        start.assert_called_once()
        flag.assert_not_called()
        assert watcher.STATE.setup_mode is False

    def test_clear_stale_deletes_ap_and_clears_flag(self, watcher):
        with patch.object(watcher.nm, "delete_connection") as delete, \
             patch.object(watcher, "clear_apmode_flag") as clear:
            watcher.hotspot_controller.clear_stale()
        delete.assert_called_once_with(watcher.AP_CONNECTION_NAME)
        clear.assert_called_once()

    def test_worker_self_undo_uses_controller_rebuild(self, watcher):
        # The activation worker's AP self-undo goes through rebuild() (no direct
        # setup_mode write).
        watcher.STATE.setup_mode = True
        job = watcher.ActivationJob(epoch=watcher._next_activation_epoch(),
                                    kind="activate_committed", ifname="wlan1",
                                    drop_hotspot=True)
        with patch.object(watcher, "_activate_committed_on", return_value=False), \
             patch.object(watcher, "stop_ap_mode"), \
             patch.object(watcher.hotspot_controller, "rebuild") as rebuild:
            watcher._run_activation_job(job)
        rebuild.assert_called_once()


class TestHotspotStationCount:
    """WP-6 — the AP station-count primitive (iw dev <ifname> station dump)."""

    _DUMP = (
        "Station dc:62:79:91:4d:d6 (on wlan0)\n"
        "\tinactive time:\t120 ms\n"
        "\trx bytes:\t1234\n"
        "Station aa:bb:cc:dd:ee:ff (on wlan0)\n"
        "\tinactive time:\t50 ms\n"
    )

    def test_counts_associated_stations(self, watcher):
        with patch.object(watcher, "_IW", "/usr/sbin/iw"), \
             patch.object(watcher, "run_cmd",
                          return_value=MagicMock(returncode=0, stdout=self._DUMP)) as rc:
            n = watcher.hotspot_station_count("wlan0")
        assert n == 2
        assert rc.call_args.kwargs.get("timeout") is not None  # bounded

    def test_zero_stations(self, watcher):
        with patch.object(watcher, "_IW", "/usr/sbin/iw"), \
             patch.object(watcher, "run_cmd", return_value=MagicMock(returncode=0, stdout="")):
            assert watcher.hotspot_station_count("wlan0") == 0

    def test_none_when_iw_absent(self, watcher):
        with patch.object(watcher, "_IW", None), \
             patch.object(watcher, "run_cmd") as rc:
            assert watcher.hotspot_station_count("wlan0") is None
        rc.assert_not_called()

    def test_none_on_command_failure(self, watcher):
        with patch.object(watcher, "_IW", "/usr/sbin/iw"), \
             patch.object(watcher, "run_cmd", return_value=MagicMock(returncode=1, stdout="")):
            assert watcher.hotspot_station_count("wlan0") is None

    def test_none_for_empty_ifname(self, watcher):
        with patch.object(watcher, "_IW", "/usr/sbin/iw"), \
             patch.object(watcher, "run_cmd") as rc:
            assert watcher.hotspot_station_count("") is None
        rc.assert_not_called()

    def test_session_reset_clears_rejoin_state(self, watcher):
        watcher.STATE.saved_ssid_visible = True
        watcher.STATE.saved_ssid_name = "Old"
        watcher.STATE.rejoin_dismissed = True
        with patch.object(watcher, "start_ap_mode"), \
             patch.object(watcher, "update_apmode_flag"):
            watcher.enter_setup_mode(watcher.HotspotPurpose.MANUAL, "x")
        assert watcher.STATE.saved_ssid_visible is False
        assert watcher.STATE.saved_ssid_name == ""
        assert watcher.STATE.rejoin_dismissed is False
