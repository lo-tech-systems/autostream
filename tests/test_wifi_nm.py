"""Unit tests for the bounded nmcli client (WP-7).

Every NMClient method must pass an explicit run_cmd(timeout=…) so there is no
unbounded NetworkManager code path.  These load wifi_nm standalone (no watcher /
Flask), patch wifi_nm.run_cmd, and assert the timeout is always applied.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_PLATFORM = str(Path(__file__).parent.parent / "platform")
_CORE = str(Path(__file__).parent.parent / "core")
for _p in (_PLATFORM, _CORE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import wifi_nm  # noqa: E402


ACTIVATE_TIMEOUT = 45
QUICK_TIMEOUT = 15


@pytest.fixture()
def nm():
    return wifi_nm.NMClient(ACTIVATE_TIMEOUT, QUICK_TIMEOUT)


def _last(rc):
    """Return (cmd, kwargs) of the most recent run_cmd call."""
    call = rc.call_args
    return call.args[0], call.kwargs


class TestNMClientBounds:
    """Every method issues exactly one bounded nmcli call."""

    def test_activate_uses_activate_timeout(self, nm):
        with patch.object(wifi_nm, "run_cmd", return_value=MagicMock(returncode=0)) as rc:
            nm.activate("uuid-1", "Home", "wlan0")
        cmd, kw = _last(rc)
        assert cmd[:3] == ["nmcli", "connection", "up"]
        assert kw["timeout"] == ACTIVATE_TIMEOUT

    def test_activate_ident_uses_activate_timeout(self, nm):
        with patch.object(wifi_nm, "run_cmd", return_value=MagicMock(returncode=0)) as rc:
            nm.activate_ident(["uuid", "uuid-1"])
        cmd, kw = _last(rc)
        assert cmd == ["nmcli", "connection", "up", "uuid", "uuid-1"]
        assert kw["timeout"] == ACTIVATE_TIMEOUT

    def test_activate_ap_uses_activate_timeout(self, nm):
        with patch.object(wifi_nm, "run_cmd", return_value=MagicMock(returncode=0)) as rc:
            nm.activate_ap("Hotspot", "wlan0")
        cmd, kw = _last(rc)
        assert cmd == ["nmcli", "connection", "up", "Hotspot", "ifname", "wlan0"]
        assert kw["timeout"] == ACTIVATE_TIMEOUT

    def test_clear_restrictions_uses_quick_timeout(self, nm):
        with patch.object(wifi_nm, "run_cmd", return_value=MagicMock(returncode=0)) as rc:
            nm.clear_restrictions("uuid-1", ("connection.interface-name",))
        cmd, kw = _last(rc)
        assert cmd[:3] == ["nmcli", "connection", "modify"]
        assert kw["timeout"] == QUICK_TIMEOUT

    def test_delete_connection_uses_quick_timeout(self, nm):
        with patch.object(wifi_nm, "run_cmd", return_value=MagicMock(returncode=0)) as rc:
            nm.delete_connection("Hotspot")
        cmd, kw = _last(rc)
        assert cmd == ["nmcli", "connection", "delete", "Hotspot"]
        assert kw["timeout"] == QUICK_TIMEOUT

    def test_delete_by_uuid_uses_quick_timeout(self, nm):
        with patch.object(wifi_nm, "run_cmd", return_value=MagicMock(returncode=0)) as rc:
            nm.delete_by_uuid("uuid-1")
        cmd, kw = _last(rc)
        assert cmd[:3] == ["nmcli", "connection", "delete"] and "uuid-1" in cmd
        assert kw["timeout"] == QUICK_TIMEOUT

    def test_run_candidate_setup_uses_quick_timeout(self, nm):
        with patch.object(wifi_nm, "run_cmd", return_value=MagicMock(returncode=0)) as rc:
            nm.run_candidate_setup(["nmcli", "connection", "add"], log_cmd=["nmcli", "..."])
        _, kw = _last(rc)
        assert kw["timeout"] == QUICK_TIMEOUT
        assert kw["log_cmd"] == ["nmcli", "..."]

    def test_disconnect_device_uses_quick_timeout(self, nm):
        with patch.object(wifi_nm, "run_cmd", return_value=MagicMock(returncode=0)) as rc:
            nm.disconnect_device("wlan1")
        cmd, kw = _last(rc)
        assert cmd == ["nmcli", "device", "disconnect", "wlan1"]
        assert kw["timeout"] == QUICK_TIMEOUT

    def test_add_ap_connection_uses_quick_timeout(self, nm):
        with patch.object(wifi_nm, "run_cmd", return_value=MagicMock(returncode=0)) as rc:
            nm.add_ap_connection("wlan0", "autostream-1234", "Hotspot")
        cmd, kw = _last(rc)
        assert cmd[:4] == ["nmcli", "connection", "add", "type"]
        assert "802-11-wireless.mode" in cmd and "ap" in cmd
        assert "autostream-1234" in cmd
        assert kw["timeout"] == QUICK_TIMEOUT

    def test_set_autoconnect_no_uses_quick_timeout(self, nm):
        with patch.object(wifi_nm, "run_cmd", return_value=MagicMock(returncode=0)) as rc:
            nm.set_autoconnect_no("uuid-1", "Home")
        cmd, kw = _last(rc)
        assert cmd[:3] == ["nmcli", "connection", "modify"]
        assert "connection.autoconnect" in cmd and "no" in cmd
        assert kw["timeout"] == QUICK_TIMEOUT

    def test_every_method_passes_a_timeout(self, nm):
        # Belt-and-braces: drive each command method and assert a timeout kwarg
        # is present on every underlying run_cmd call.
        with patch.object(wifi_nm, "run_cmd", return_value=MagicMock(returncode=0)) as rc:
            nm.activate("u", "n", "wlan0")
            nm.activate_ident(["id", "n"])
            nm.activate_ap("Hotspot", "wlan0")
            nm.clear_restrictions("u", ("k",))
            nm.delete_connection("n")
            nm.delete_by_uuid("u")
            nm.run_candidate_setup(["nmcli"])
            nm.disconnect_device("wlan0")
            nm.add_ap_connection("wlan0", "ssid", "Hotspot")
            nm.set_autoconnect_no("u", "n")
        assert rc.call_count == 10
        for call in rc.call_args_list:
            assert call.kwargs.get("timeout") is not None


class TestNMClientBssidPin:
    def test_set_bssid_uses_quick_timeout(self, nm):
        with patch.object(wifi_nm, "run_cmd", return_value=MagicMock(returncode=0)) as rc:
            nm.set_bssid("uuid-1", "AA:BB:CC:DD:EE:FF")
        cmd, kw = _last(rc)
        assert cmd == ["nmcli", "connection", "modify", "uuid", "uuid-1",
                       "802-11-wireless.bssid", "AA:BB:CC:DD:EE:FF"]
        assert kw["timeout"] == QUICK_TIMEOUT

    def test_wifi_bssid_scan_rescan_true_primes_then_lists(self, nm):
        with patch.object(wifi_nm, "run_cmd",
                          return_value=MagicMock(returncode=0, stdout="")) as rc:
            nm.wifi_bssid_scan("wlan1", rescan=True)
        assert rc.call_count == 2
        rescan_cmd, rescan_kw = rc.call_args_list[0].args[0], rc.call_args_list[0].kwargs
        list_cmd, list_kw = rc.call_args_list[1].args[0], rc.call_args_list[1].kwargs
        assert rescan_cmd == ["nmcli", "device", "wifi", "rescan", "ifname", "wlan1"]
        assert list_cmd[-2:] == ["--rescan", "yes"]
        assert rescan_kw["timeout"] == 15
        assert list_kw["timeout"] == 15

    def test_wifi_bssid_scan_rescan_false_skips_priming(self, nm):
        with patch.object(wifi_nm, "run_cmd",
                          return_value=MagicMock(returncode=0, stdout="")) as rc:
            nm.wifi_bssid_scan("wlan1", rescan=False)
        assert rc.call_count == 1
        list_cmd = rc.call_args_list[0].args[0]
        assert list_cmd[-2:] == ["--rescan", "no"]

    def test_wifi_bssid_scan_returns_parsed_rows(self, nm):
        stdout = r"*:AA\:BB\:CC\:DD\:EE\:FF:Home:70" + "\n"
        with patch.object(wifi_nm, "run_cmd",
                          return_value=MagicMock(returncode=0, stdout=stdout)):
            rows = nm.wifi_bssid_scan("wlan1", rescan=False)
        assert rows == [
            {"in_use": True, "bssid": "AA:BB:CC:DD:EE:FF", "ssid": "Home", "signal": 70}
        ]

    def test_wifi_bssid_scan_returns_none_on_failure(self, nm):
        with patch.object(wifi_nm, "run_cmd",
                          return_value=MagicMock(returncode=1, stdout="")):
            assert nm.wifi_bssid_scan("wlan1", rescan=False) is None
