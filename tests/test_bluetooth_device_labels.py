"""Tests for the capture-device list in core/autostream_services.py:
normalize_monitor_devices() leaves out both sides of the Bluetooth loopback
(the capture side is input 3's fixed device, the playback side is internal)
and labels every other device as before, and get_available_monitor_devices()
hands the daemon's list to it.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

from autostream_bluetooth_client import BLUETOOTH_CAPTURE_DEVICE, BLUETOOTH_PLAYBACK_DEVICE
import autostream_services as services


_RAW_DEVICES = [
    {"hw": "hw:1,0", "card": "Behringer UCA", "name": "USB Audio"},
    {"hw": BLUETOOTH_PLAYBACK_DEVICE, "card": "Loopback", "name": "Loopback PCM"},
    {"hw": BLUETOOTH_CAPTURE_DEVICE, "card": "Loopback", "name": "Loopback PCM"},
]


class TestTheLoopbackIsNotListed:
    def test_both_sides_left_out(self):
        hws = {d["hw"] for d in services.normalize_monitor_devices(_RAW_DEVICES)}
        assert BLUETOOTH_PLAYBACK_DEVICE not in hws
        assert BLUETOOTH_CAPTURE_DEVICE not in hws

    def test_left_out_whatever_its_spelling(self):
        raw = [{"hw": "hw:card=asbt,dev=1", "card": "Loopback", "name": ""}]
        assert services.normalize_monitor_devices(raw) == []

    def test_ordinary_device_untouched(self):
        result = services.normalize_monitor_devices(_RAW_DEVICES)
        assert result == [{
            "hw": "hw:1,0", "card": "Behringer UCA", "name": "USB Audio",
            "label": "Behringer UCA - USB Audio (hw:1,0)",
        }]

    def test_empty_devices_returns_empty_list(self):
        assert services.normalize_monitor_devices([]) == []
        assert services.normalize_monitor_devices(None) == []


class TestGetAvailableMonitorDevices:
    def test_daemon_list_is_normalised(self):
        client = MagicMock()
        client.list_devices.return_value = _RAW_DEVICES
        cm = MagicMock()
        cm.__enter__.return_value = client
        cm.__exit__.return_value = False
        with patch.object(services.monitor_client, "_connected_monitor", return_value=cm):
            result = services.get_available_monitor_devices()
        assert [d["hw"] for d in result] == ["hw:1,0"]

    def test_no_daemon_is_an_empty_list(self):
        cm = MagicMock()
        cm.__enter__.return_value = None
        cm.__exit__.return_value = False
        with patch.object(services.monitor_client, "_connected_monitor", return_value=cm):
            assert services.get_available_monitor_devices() == []
