"""tests/test_services.py

The background services: what start() brings up and in which order, the
device scan that publishes the devices part, the announcement loop, and the
process-lifetime helper (discovery shutdown).
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_runtime as runtime
import autostream_services as services
import autostream_state as state
from settings_fixtures import fixed_view


class _Stop(Exception):
    """Ends a loop that ends with time.sleep()."""


def _life():
    return runtime.Lifecycle(threading.Event())


# ---------------------------------------------------------------------------
# start
# ---------------------------------------------------------------------------

class TestStart:
    def test_scanners_start_in_order_with_the_stop_event_then_the_threads(self):
        life = _life()
        order = []
        threads = []

        class FakeThread:
            def __init__(self, target=None, args=(), name=None, daemon=None):
                threads.append((target, args, name, daemon))
                order.append("thread:" + str(name))

            def start(self):
                pass

        def record(name):
            def fn(**kwargs):
                assert kwargs["shutdown_event"] is life.stop
                order.append(name)
            return fn

        def record_state(shutdown_event, **kwargs):
            assert shutdown_event is life.stop
            assert kwargs["config_path"] == "c.ini" and kwargs["state_path"] == "s.json"
            assert kwargs["settings"] == "settings" and kwargs["app_version"]() == "v"
            order.append("appliance_state")

        with patch.object(services.dials, "start_dial_scanner", side_effect=record("dials")), \
             patch.object(services.appliance_state, "start", side_effect=record_state), \
             patch.object(services.threading, "Thread", FakeThread):
            services.start(life, "settings", config_path="c.ini", state_path="s.json",
                           app_version=lambda: "v")

        assert order == ["dials", "appliance_state", "thread:device-scan",
                         "thread:announce-reconcile", "thread:vibra-runtime-refresh"]
        scan, announce, _vibra = threads
        assert scan[0] is services._device_scan_loop and scan[1] == (life, "settings")
        assert announce[0] is services._announcement_loop
        assert announce[1] == (life, "settings", announce[1][2])
        assert all(t[3] is True for t in threads)

    def test_start_does_not_start_the_appliance_scanner_or_a_usage_poller(self):
        life = _life()
        with patch.object(services.dials, "start_dial_scanner"), \
             patch.object(services.appliance_state, "start"), \
             patch.object(services.appliances, "start") as appliances_start, \
             patch.object(services.threading, "Thread"):
            services.start(life, "settings", config_path="c.ini", state_path="s.json",
                           app_version=lambda: "v")
        appliances_start.assert_not_called()
        assert not hasattr(services, "start_output_usage_poller")

    def test_a_failing_start_is_logged_and_raised_and_starts_no_thread(self, caplog):
        life = _life()
        with patch.object(services.dials, "start_dial_scanner", side_effect=RuntimeError("boom")), \
             patch.object(services.threading, "Thread") as thread, \
             caplog.at_level("ERROR"):
            with pytest.raises(RuntimeError):
                services.start(life, MagicMock(), config_path="c.ini", state_path="s.json",
                               app_version=lambda: "v")
        thread.assert_not_called()
        assert any("Background services error" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# device scan
# ---------------------------------------------------------------------------

class TestDeviceScan:
    def _run_once(self, settings):
        life = _life()
        with patch.object(services.time, "sleep", side_effect=_Stop):
            with pytest.raises(_Stop):
                services._device_scan_loop(life, settings)

    def test_publishes_the_cleaned_list_and_the_status(self):
        settings = MagicMock()
        devices = [
            {"hw": " hw:1,0 ", "card": "Card", "name": "Dev", "label": "Card - Dev (hw:1,0)"},
            {"hw": "", "card": "x"},
            "not a dict",
            {"hw": "hw:2,0"},
        ]
        status = {"ok": True, "paired": {"mac": "AA", "name": "N"}}
        with patch.object(services, "bluetooth_installed", return_value=True), \
             patch.object(services, "BluetoothClient") as client, \
             patch.object(services, "get_available_monitor_devices", return_value=devices), \
             patch.object(services, "_rate_follow_check", return_value=48000) as rf, \
             patch.object(services, "_lockout_heal_check", return_value=(0, None)) as lh:
            client.return_value.status.return_value = status
            self._run_once(settings)
        part = state.store().snapshot().devices
        assert [dict(d) for d in part.monitor_devices] == [
            {"hw": "hw:1,0", "card": "Card", "name": "Dev", "label": "Card - Dev (hw:1,0)"},
            {"hw": "hw:2,0", "card": "", "name": "", "label": "hw:2,0"},
        ]
        assert state.thaw(part.bluetooth_status) == status
        assert rf.call_args.args[0] is settings and lh.call_args.args[0] is settings

    def test_a_failed_scan_and_status_publish_an_empty_list_and_none(self):
        with patch.object(services, "bluetooth_installed", return_value=True), \
             patch.object(services, "BluetoothClient", side_effect=RuntimeError("x")), \
             patch.object(services, "get_available_monitor_devices", side_effect=RuntimeError("y")):
            self._run_once(MagicMock())
        part = state.store().snapshot().devices
        assert part.monitor_devices == ()
        assert part.bluetooth_status is None

    def test_the_loop_ends_when_stopping(self):
        life = _life()
        life.stop.set()
        with patch.object(services.time, "sleep", side_effect=_Stop) as sleep:
            services._device_scan_loop(life, MagicMock())
        sleep.assert_not_called()


# ---------------------------------------------------------------------------
# announcement loop
# ---------------------------------------------------------------------------

def _settings():
    settings = MagicMock()
    settings.snapshot.return_value.webui.advertise_appliance = True
    return settings


class TestAnnouncementLoop:
    def test_reconciles_once_then_again_after_each_wait(self):
        events = []
        life = MagicMock()
        # stopping(): the loop check, the check after the wait, then the next
        # loop check ends it.
        stops = iter([False, False, True])
        life.stopping.side_effect = lambda: next(stops)
        life.wait.return_value = False

        with patch.object(services.appliances, "reconcile_appliance_announcement",
                   side_effect=lambda v, adv: events.append(("reconcile", v, adv))):
            services._announcement_loop(life, _settings(), lambda: "1.0")
        assert events == [("reconcile", "1.0", True), ("reconcile", "1.0", True)]

    def test_the_loop_stops_when_the_wait_ends_because_of_stopping(self):
        events = []
        life = MagicMock()
        stops = iter([False, True])
        life.stopping.side_effect = lambda: next(stops)
        life.wait.return_value = True
        with patch.object(services.appliances, "reconcile_appliance_announcement",
                   side_effect=lambda v, adv: events.append("reconcile")):
            services._announcement_loop(life, _settings(), lambda: "1.0")
        assert events == ["reconcile"]


# ---------------------------------------------------------------------------
# discovery shutdown
# ---------------------------------------------------------------------------

class TestShutdown:
    def test_shutdown_stops_both_and_continues_after_a_failure(self):
        with patch.object(services.dials, "stop_dial_scanner", side_effect=RuntimeError("x")) as dials_stop, \
             patch.object(services.appliances, "stop") as ap_stop:
            services.stop_discovery()
        dials_stop.assert_called_once()
        ap_stop.assert_called_once()


# ---------------------------------------------------------------------------
# the Web UI reads the part
# ---------------------------------------------------------------------------

class TestWebUIStateReads:
    def test_monitor_devices_are_fresh_copies_of_the_part(self, tmp_path, fake_store):
        from webui.session_state import WebUIState
        wstate = WebUIState(str(tmp_path / "c.json"), str(tmp_path / "s.json"), settings=fixed_view())
        fake_store.devices(monitor_devices=[{"hw": "hw:1,0", "card": "C", "name": "N", "label": "L"}])
        got = wstate.get_monitor_devices()
        assert got == [{"hw": "hw:1,0", "card": "C", "name": "N", "label": "L"}]
        got[0]["label"] = "changed"
        assert wstate.get_monitor_devices()[0]["label"] == "L"

    def test_an_empty_part_reads_as_no_devices_and_no_status(self, tmp_path):
        from webui.session_state import WebUIState
        wstate = WebUIState(str(tmp_path / "c.json"), str(tmp_path / "s.json"), settings=fixed_view())
        assert wstate.get_monitor_devices() == []
        assert wstate.get_bluetooth_status() is None
