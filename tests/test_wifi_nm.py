"""Unit tests for the bounded nmcli client.

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
            nm.profile_fields("u", "n", ("k",))
            nm.set_bssid("u", "")
        assert rc.call_count == 14
        for call in rc.call_args_list:
            assert call.kwargs.get("timeout") is not None


class TestProfileFields:
    def test_reads_with_timeout_and_without_failure_warning(self, nm):
        r = MagicMock(returncode=0, stdout="connection.autoconnect:no\n")
        with patch.object(wifi_nm, "run_cmd", return_value=r) as rc:
            got = nm.profile_fields("u1", "Home", ("connection.autoconnect",))
        assert got == {"connection.autoconnect": "no"}
        cmd, kw = _last(rc)
        assert cmd == ["nmcli", "-t", "-f", "connection.autoconnect",
                       "connection", "show", "uuid", "u1"]
        assert kw["timeout"] == QUICK_TIMEOUT
        assert kw["warn_on_failure"] is False

    def test_name_used_when_no_uuid(self, nm):
        r = MagicMock(returncode=0, stdout="k:v\n")
        with patch.object(wifi_nm, "run_cmd", return_value=r) as rc:
            nm.profile_fields("", "Home", ("k",))
        assert _last(rc)[0][-2:] == ["id", "Home"]

    def test_failure_is_none(self, nm):
        r = MagicMock(returncode=10, stdout="")
        with patch.object(wifi_nm, "run_cmd", return_value=r):
            assert nm.profile_fields("u1", "", ("k",)) is None


def _answer(*replies):
    """A run_cmd stand-in returning the replies in order (stdout, rc)."""
    it = iter(replies)

    def fake(cmd, **kwargs):
        out, rc = next(it)
        return MagicMock(returncode=rc, stdout=out, stderr="")
    return fake


class TestReadBeforeWrite:
    BSSID = "802-11-wireless.bssid"

    def test_set_bssid_skips_write_when_already_blank(self, nm):
        with patch.object(wifi_nm, "run_cmd", side_effect=_answer((self.BSSID + ":\n", 0))) as rc:
            r = nm.set_bssid("u1", "")
        assert rc.call_count == 1
        assert rc.call_args.args[0][:5] == ["nmcli", "-t", "-f", self.BSSID, "connection"]
        assert r.returncode == 0

    def test_set_bssid_skips_write_when_pin_already_matches(self, nm):
        reply = self.BSSID + r":AA\:BB\:CC\:DD\:EE\:FF" + "\n"
        with patch.object(wifi_nm, "run_cmd", side_effect=_answer((reply, 0))) as rc:
            r = nm.set_bssid("u1", "aa:bb:cc:dd:ee:ff")
        assert rc.call_count == 1 and r.returncode == 0

    def test_set_bssid_writes_when_pinned(self, nm):
        reply = self.BSSID + r":AA\:BB\:CC\:DD\:EE\:FF" + "\n"
        with patch.object(wifi_nm, "run_cmd", side_effect=_answer((reply, 0), ("", 0))) as rc:
            nm.set_bssid("u1", "")
        assert rc.call_count == 2
        assert rc.call_args.args[0] == [
            "nmcli", "connection", "modify", "uuid", "u1", self.BSSID, ""]
        assert rc.call_args.kwargs["timeout"] == QUICK_TIMEOUT

    def test_clear_restrictions_skips_when_all_empty(self, nm):
        keys = ("connection.interface-name", "802-11-wireless.channel")
        reply = "connection.interface-name:\n802-11-wireless.channel:0\n"
        with patch.object(wifi_nm, "run_cmd", side_effect=_answer((reply, 0))) as rc:
            r = nm.clear_restrictions("u1", keys)
        assert rc.call_count == 1 and r.returncode == 0

    def test_clear_restrictions_writes_only_differing_keys(self, nm):
        keys = ("connection.interface-name", "802-11-wireless.band")
        reply = "connection.interface-name:wlan1\n802-11-wireless.band:\n"
        with patch.object(wifi_nm, "run_cmd", side_effect=_answer((reply, 0), ("", 0))) as rc:
            nm.clear_restrictions("u1", keys)
        assert rc.call_args.args[0] == [
            "nmcli", "connection", "modify", "uuid", "u1", "connection.interface-name", ""]

    def test_read_failure_writes_in_full(self, nm):
        keys = ("connection.interface-name", "802-11-wireless.band")
        with patch.object(wifi_nm, "run_cmd", side_effect=_answer(("", 1), ("", 0))) as rc:
            nm.clear_restrictions("u1", keys)
        assert rc.call_args.args[0] == [
            "nmcli", "connection", "modify", "uuid", "u1",
            "connection.interface-name", "", "802-11-wireless.band", ""]


class TestTeardownTolerance:
    """Idempotent teardown commands (delete/disconnect) treat the goal state
    already holding as benign (DEBUG), while real failures keep the WARNING."""

    def test_disconnect_already_inactive_is_debug_not_warning(self, nm, caplog):
        result = MagicMock(
            returncode=6,
            stderr="Error: Device 'wlan0' disconnecting failed: This device is not active\n",
        )
        with patch.object(wifi_nm, "run_cmd", return_value=result) as rc:
            with caplog.at_level("DEBUG", logger=wifi_nm.logger.name):
                r = nm.disconnect_device("wlan0")
        assert r is result
        assert rc.call_args.kwargs["warn_on_failure"] is False
        assert not [rec for rec in caplog.records if rec.levelname == "WARNING"]
        assert any("already satisfied" in rec.getMessage() for rec in caplog.records)

    def test_delete_unknown_connection_is_debug_not_warning(self, nm, caplog):
        result = MagicMock(
            returncode=10,
            stderr="Error: unknown connection 'Hotspot'.\n",
        )
        with patch.object(wifi_nm, "run_cmd", return_value=result):
            with caplog.at_level("DEBUG", logger=wifi_nm.logger.name):
                nm.delete_connection("Hotspot")
        assert not [rec for rec in caplog.records if rec.levelname == "WARNING"]
        assert any("already satisfied" in rec.getMessage() for rec in caplog.records)

    def test_delete_by_uuid_unknown_connection_is_debug_not_warning(self, nm, caplog):
        result = MagicMock(
            returncode=10,
            stderr="Error: unknown connection 'uuid-1'.\n",
        )
        with patch.object(wifi_nm, "run_cmd", return_value=result):
            with caplog.at_level("DEBUG", logger=wifi_nm.logger.name):
                nm.delete_by_uuid("uuid-1")
        assert not [rec for rec in caplog.records if rec.levelname == "WARNING"]
        assert any("already satisfied" in rec.getMessage() for rec in caplog.records)

    def test_other_teardown_failure_still_warns(self, nm, caplog):
        result = MagicMock(
            returncode=1,
            stderr="Error: NetworkManager is not running.\n",
        )
        with patch.object(wifi_nm, "run_cmd", return_value=result):
            with caplog.at_level("DEBUG", logger=wifi_nm.logger.name):
                nm.disconnect_device("wlan0")
        warnings = [rec for rec in caplog.records if rec.levelname == "WARNING"]
        assert len(warnings) == 1
        assert "Command failed" in warnings[0].getMessage()
        assert "NetworkManager is not running" in warnings[0].getMessage()

    def test_teardown_success_logs_nothing(self, nm, caplog):
        with patch.object(wifi_nm, "run_cmd", return_value=MagicMock(returncode=0)):
            with caplog.at_level("DEBUG", logger=wifi_nm.logger.name):
                nm.disconnect_device("wlan0")
                nm.delete_connection("Hotspot")
        assert not caplog.records


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
