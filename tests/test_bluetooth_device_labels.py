"""Tests for the Bluetooth device-list relabel hook in
core/autostream_core.py's normalize_monitor_devices(), and
get_available_monitor_devices() threading the status through.

Regression guard: with Bluetooth mode off (the default / today's
appliances), normalize_monitor_devices() must behave byte-identically to
before this feature existed.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

import autostream_core as core
from autostream_bluetooth_client import BLUETOOTH_CAPTURE_DEVICE, BLUETOOTH_PLAYBACK_DEVICE


_RAW_DEVICES = [
    {"hw": "hw:1,0", "card": "Behringer UCA", "name": "USB Audio"},
    {"hw": BLUETOOTH_PLAYBACK_DEVICE, "card": "Loopback", "name": "Loopback PCM"},
    {"hw": BLUETOOTH_CAPTURE_DEVICE, "card": "Loopback", "name": "Loopback PCM"},
]


# ---------------------------------------------------------------------------
# Bluetooth mode OFF — byte-identical regression guard
# ---------------------------------------------------------------------------

class TestBluetoothOffIsUnchanged:
    def test_playback_side_not_dropped_when_off(self):
        result = core.normalize_monitor_devices(_RAW_DEVICES, bluetooth_enabled=False)
        hws = {d["hw"] for d in result}
        assert BLUETOOTH_PLAYBACK_DEVICE in hws

    def test_capture_side_not_relabelled_when_off(self):
        result = core.normalize_monitor_devices(_RAW_DEVICES, bluetooth_enabled=False)
        capture = next(d for d in result if d["hw"] == BLUETOOTH_CAPTURE_DEVICE)
        assert not capture["label"].startswith("Bluetooth")
        assert capture["label"] == f"Loopback - Loopback PCM ({BLUETOOTH_CAPTURE_DEVICE})"

    def test_matches_legacy_two_arg_call(self):
        """Calling with only the devices arg (today's call shape) must not error
        and must resolve bluetooth_enabled from bluetooth_installed() (defaults
        off in the test environment -- no unit file at the default path)."""
        result = core.normalize_monitor_devices(_RAW_DEVICES)
        hws = {d["hw"] for d in result}
        assert BLUETOOTH_PLAYBACK_DEVICE in hws
        assert BLUETOOTH_CAPTURE_DEVICE in hws

    def test_ordinary_device_untouched(self):
        result = core.normalize_monitor_devices(_RAW_DEVICES, bluetooth_enabled=False)
        usb = next(d for d in result if d["hw"] == "hw:1,0")
        assert usb["label"] == "Behringer UCA - USB Audio (hw:1,0)"

    def test_empty_devices_returns_empty_list(self):
        assert core.normalize_monitor_devices(None, bluetooth_enabled=False) == []
        assert core.normalize_monitor_devices([], bluetooth_enabled=False) == []


# ---------------------------------------------------------------------------
# Bluetooth mode ON — playback side hidden, capture side relabelled
# ---------------------------------------------------------------------------

class TestBluetoothOnHidesPlaybackSide:
    def test_playback_side_dropped(self):
        result = core.normalize_monitor_devices(_RAW_DEVICES, bluetooth_enabled=True)
        hws = {d["hw"] for d in result}
        assert BLUETOOTH_PLAYBACK_DEVICE not in hws

    def test_other_devices_unaffected(self):
        result = core.normalize_monitor_devices(_RAW_DEVICES, bluetooth_enabled=True)
        hws = {d["hw"] for d in result}
        assert "hw:1,0" in hws

    def test_capture_side_still_present(self):
        result = core.normalize_monitor_devices(_RAW_DEVICES, bluetooth_enabled=True)
        hws = {d["hw"] for d in result}
        assert BLUETOOTH_CAPTURE_DEVICE in hws


class TestBluetoothOnRelabelsCaptureSide:
    def _capture_label(self, status):
        result = core.normalize_monitor_devices(
            _RAW_DEVICES, status, bluetooth_enabled=True,
        )
        return next(d for d in result if d["hw"] == BLUETOOTH_CAPTURE_DEVICE)["label"]

    def test_paired_shows_device_name(self):
        status = {"ok": True, "paired": {"mac": "AA:BB:CC:DD:EE:FF", "name": "Technics SL-1200"}}
        assert self._capture_label(status) == "Bluetooth: Technics SL-1200"

    def test_not_paired(self):
        status = {"ok": True, "paired": None}
        assert self._capture_label(status) == "Bluetooth (not paired)"

    def test_status_none_is_service_unavailable(self):
        assert self._capture_label(None) == "Bluetooth (service unavailable)"

    def test_status_ok_false_is_service_unavailable(self):
        status = {"ok": False, "error": "daemon down"}
        assert self._capture_label(status) == "Bluetooth (service unavailable)"


# ---------------------------------------------------------------------------
# get_available_monitor_devices() threads bluetooth_status through
# ---------------------------------------------------------------------------

class TestGetAvailableMonitorDevicesThreadsStatus:
    def test_bluetooth_status_reaches_normalize(self):
        fake_client = type("FakeClient", (), {
            "connect": lambda self: True,
            "close": lambda self: None,
            "list_devices": lambda self: list(_RAW_DEVICES),
        })()

        status = {"ok": True, "paired": {"mac": "AA:BB:CC:DD:EE:FF", "name": "My Deck"}}

        with patch("autostream_core.MonitorClient", return_value=fake_client), \
             patch("autostream_core.bluetooth_installed", return_value=True):
            result = core.get_available_monitor_devices(bluetooth_status=status)

        capture = next(d for d in result if d["hw"] == BLUETOOTH_CAPTURE_DEVICE)
        assert capture["label"] == "Bluetooth: My Deck"
