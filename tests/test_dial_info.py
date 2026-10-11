"""Tests for dial_info.py — the idle screen's read-only info page data
gatherer. No hardware imports: every source is faked (subprocess.run,
socket, os.statvfs, /proc/net/wireless) so this suite runs anywhere.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
if _DIAL not in sys.path:
    sys.path.insert(0, _DIAL)

from dial_info import (  # noqa: E402
    INFO_LABELS,
    SIGNAL_DISCONNECTED,
    SIGNAL_NORMAL,
    SIGNAL_STRONG,
    SIGNAL_WEAK,
    _BLANK,
    _ipv4,
    _wifi_status,
    configured_ssid,
    gather_dial_info,
    signal_category_from_dbm,
    signal_category_from_percent,
    wifi_status,
)


def _completed(stdout="", returncode=0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


# ---------------------------------------------------------------------------
# gather_dial_info: shape, order, name/version pass-through.
# ---------------------------------------------------------------------------

class TestGatherShape:
    def _patched(self, **overrides):
        defaults = dict(
            ipv4=lambda: "192.168.1.20",
            wifi=lambda: ("HomeNet", SIGNAL_STRONG),
            disk=lambda: "14.2 GB",
        )
        defaults.update(overrides)
        return patch.multiple(
            "dial_info",
            _ipv4=MagicMock(side_effect=defaults["ipv4"]),
            wifi_status=MagicMock(side_effect=defaults["wifi"]),
            _disk_free=MagicMock(side_effect=defaults["disk"]),
        )

    def test_returns_seven_pairs_in_order_with_fixed_labels(self):
        with self._patched():
            rows = gather_dial_info("Kitchen Dial", "1.4.0", sd_health="87% Good")
        assert len(rows) == 7
        assert tuple(label for label, _ in rows) == INFO_LABELS
        assert rows[0] == ("Dial name", "Kitchen Dial")
        assert rows[1] == ("Firmware", "1.4.0")
        assert rows[2] == ("IPv4", "192.168.1.20")
        assert rows[3] == ("WiFi", "HomeNet")
        assert rows[4] == ("Signal", SIGNAL_STRONG)
        assert rows[5] == ("Disk free", "14.2 GB")
        assert rows[6] == ("SD health", "87% Good")

    def test_sd_health_defaults_to_dash_when_none(self):
        with self._patched():
            rows = gather_dial_info("Kitchen Dial", "1.4.0")
        assert dict(rows)["SD health"] == _BLANK

    def test_blank_name_and_version_become_dash(self):
        with self._patched():
            rows = gather_dial_info("   ", "")
        assert dict(rows)["Dial name"] == _BLANK
        assert dict(rows)["Firmware"] == _BLANK

    def test_an_unnamed_dial_shows_its_uuid_in_the_name_row(self):
        for unnamed in ("", "   ", None):
            with self._patched():
                rows = gather_dial_info(unnamed, "1.0", uuid="0123456789abcdef")
            assert dict(rows)["Dial name"] == "0123456789abcdef"

    def test_a_named_dial_shows_its_name_not_its_uuid(self):
        with self._patched():
            rows = gather_dial_info("Kitchen Dial", "1.0", uuid="0123456789abcdef")
        assert dict(rows)["Dial name"] == "Kitchen Dial"

    def test_no_name_and_no_uuid_shows_a_dash(self):
        for uuid in ("", "  ", None):
            with self._patched():
                rows = gather_dial_info("", "1.0", uuid=uuid)
            assert dict(rows)["Dial name"] == _BLANK

    def test_name_is_stripped(self):
        with self._patched():
            rows = gather_dial_info("  Kitchen Dial  ", "1.0")
        assert dict(rows)["Dial name"] == "Kitchen Dial"

    def test_never_raises_when_every_source_blows_up(self):
        with self._patched(
            ipv4=lambda: (_ for _ in ()).throw(RuntimeError("boom")),
            wifi=lambda: (_ for _ in ()).throw(RuntimeError("boom")),
            disk=lambda: (_ for _ in ()).throw(RuntimeError("boom")),
        ):
            rows = gather_dial_info("Kitchen Dial", "1.4.0")
        assert dict(rows)["IPv4"] == _BLANK
        assert dict(rows)["WiFi"] == _BLANK
        assert dict(rows)["Signal"] == _BLANK
        assert dict(rows)["Disk free"] == _BLANK
        # name/version are unaffected by the other sources blowing up.
        assert dict(rows)["Dial name"] == "Kitchen Dial"
        assert dict(rows)["Firmware"] == "1.4.0"


# ---------------------------------------------------------------------------
# IPv4: socket trick, then the `ip` fallback, then "-".
# ---------------------------------------------------------------------------

class TestIPv4:
    def test_socket_path_returns_local_endpoint_address(self):
        fake_sock = MagicMock()
        fake_sock.__enter__ = MagicMock(return_value=fake_sock)
        fake_sock.__exit__ = MagicMock(return_value=False)
        fake_sock.getsockname.return_value = ("192.168.1.20", 54321)
        with patch("dial_info.socket.socket", return_value=fake_sock):
            assert _ipv4() == "192.168.1.20"

    def test_socket_failure_falls_back_to_ip_command(self):
        # Realistic `ip -4 -o addr show scope global` output: only the
        # global-scope interface is listed (loopback is scope host, so the
        # command itself never reports it).
        with patch("dial_info.socket.socket", side_effect=OSError("no route")):
            with patch(
                "dial_info._run",
                return_value=_completed(
                    stdout="2: eth0    inet 192.168.1.20/24 brd 192.168.1.255 scope global eth0\n",
                ),
            ):
                assert _ipv4() == "192.168.1.20"

    def test_both_failing_returns_none(self):
        with patch("dial_info.socket.socket", side_effect=OSError("no route")):
            with patch("dial_info._run", return_value=None):
                assert _ipv4() is None

    def test_gather_reports_dash_when_both_ipv4_sources_fail(self):
        with patch("dial_info.socket.socket", side_effect=OSError("no route")), \
             patch("dial_info._run", return_value=None):
            rows = gather_dial_info("Kitchen Dial", "1.0")
        assert dict(rows)["IPv4"] == _BLANK


# ---------------------------------------------------------------------------
# WiFi: nmcli terse parsing (with escaped colons), then /proc/net/wireless +
# iwgetid, then ("-", "-").
# ---------------------------------------------------------------------------

class TestWifiStatus:
    def test_nmcli_active_row_with_escaped_colon_in_ssid(self):
        # "Office\:Net" is nmcli's own escaping of the literal SSID
        # "Office:Net"; the inactive row above it must be ignored.
        stdout = "no:Neighbour:40\nyes:Office\\:Net:72\n"
        with patch("dial_info._run", return_value=_completed(stdout=stdout)) as run:
            assert _wifi_status() == ("Office:Net", SIGNAL_STRONG)
        run.assert_called_once()

    def test_nmcli_percent_maps_to_category(self):
        stdout = "yes:HomeNet:50\n"
        with patch("dial_info._run", return_value=_completed(stdout=stdout)):
            assert _wifi_status() == ("HomeNet", SIGNAL_NORMAL)

    def test_nmcli_missing_falls_back_to_proc_wireless_and_iwgetid(self):
        wireless_data = (
            "Inter-| sta-|   Link quality        Level    Noise    Nwid  ...\n"
            " face | tus |     link  level  noise    nwid    ...\n"
            " wlan0: 0000   70.  -65.  -256.       0      0      0\n"
        )
        with patch("dial_info._run") as run:
            run.side_effect = [
                None,  # nmcli
                _completed(stdout="wlan0\n"),  # iwgetid
            ]
            with patch("builtins.open", mock_open(read_data=wireless_data)):
                assert _wifi_status() == ("wlan0", SIGNAL_NORMAL)

    def test_both_wifi_sources_missing_returns_dash_pair(self):
        with patch("dial_info._run", return_value=None):
            with patch("builtins.open", side_effect=OSError("no such file")):
                assert _wifi_status() == (_BLANK, _BLANK)

    def test_proc_wireless_present_but_iwgetid_missing_uses_dash_ssid(self):
        wireless_data = (
            "Inter-| sta-|   Link quality        Level    Noise    Nwid  ...\n"
            " face | tus |     link  level  noise    nwid    ...\n"
            " wlan0: 0000   70.  -80.  -256.       0      0      0\n"
        )
        with patch("dial_info._run") as run:
            run.side_effect = [None, None]  # nmcli, then iwgetid
            with patch("builtins.open", mock_open(read_data=wireless_data)):
                assert _wifi_status() == (_BLANK, SIGNAL_WEAK)

    def test_positive_wireless_level_is_treated_as_unknown(self):
        # A driver reporting raw link-quality units (positive) instead of
        # dBm must not be misread as a very strong signal.
        wireless_data = (
            "Inter-| sta-|   Link quality        Level    Noise    Nwid  ...\n"
            " face | tus |     link  level  noise    nwid    ...\n"
            " wlan0: 0000   70.   70.  -256.       0      0      0\n"
        )
        with patch("dial_info._run", return_value=None):
            with patch("builtins.open", mock_open(read_data=wireless_data)):
                assert _wifi_status() == (_BLANK, _BLANK)


# ---------------------------------------------------------------------------
# Signal categorisation: pure functions, pinned exactly at the boundaries.
# ---------------------------------------------------------------------------

class TestSignalCategories:
    @pytest.mark.parametrize("percent,expected", [(0, SIGNAL_WEAK), (34, SIGNAL_WEAK),
                                                   (35, SIGNAL_NORMAL), (64, SIGNAL_NORMAL),
                                                   (65, SIGNAL_STRONG), (100, SIGNAL_STRONG)])
    def test_percent_thresholds(self, percent, expected):
        assert signal_category_from_percent(percent) == expected

    @pytest.mark.parametrize("dbm,expected", [(-90, SIGNAL_WEAK), (-76, SIGNAL_WEAK),
                                               (-75, SIGNAL_NORMAL), (-61, SIGNAL_NORMAL),
                                               (-60, SIGNAL_STRONG), (-30, SIGNAL_STRONG)])
    def test_dbm_thresholds(self, dbm, expected):
        assert signal_category_from_dbm(dbm) == expected


# ---------------------------------------------------------------------------
# Disk free: os.statvfs, GB above 1GB else MB; OSError -> "-".
# ---------------------------------------------------------------------------

class TestDiskFree:
    @staticmethod
    def _statvfs(f_bavail, f_frsize):
        result = MagicMock()
        result.f_bavail = f_bavail
        result.f_frsize = f_frsize
        return result

    def test_gigabytes_formatted_to_one_decimal(self):
        # 14.2 GB = 14.2 * 1024**3 bytes, f_frsize=1 for a clean byte count.
        free_bytes = int(14.2 * 1024 ** 3)
        with patch("dial_info.os.statvfs", return_value=self._statvfs(free_bytes, 1)):
            rows = gather_dial_info("Dial", "1.0")
        assert dict(rows)["Disk free"] == "14.2 GB"

    def test_megabytes_used_below_one_gigabyte(self):
        free_bytes = 512 * 1024 ** 2
        with patch("dial_info.os.statvfs", return_value=self._statvfs(free_bytes, 1)):
            rows = gather_dial_info("Dial", "1.0")
        assert dict(rows)["Disk free"] == "512 MB"

    def test_oserror_becomes_dash(self):
        with patch("dial_info.os.statvfs", side_effect=OSError("no such device")):
            rows = gather_dial_info("Dial", "1.0")
        assert dict(rows)["Disk free"] == _BLANK


# ---------------------------------------------------------------------------
# Subprocess timeouts are caught, never raised.
# ---------------------------------------------------------------------------

class TestSubprocessTimeout:
    def test_nmcli_timeout_falls_back_to_proc_wireless(self):
        with patch(
            "dial_info.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="nmcli", timeout=2.0),
        ):
            with patch("builtins.open", side_effect=OSError("no such file")):
                assert _wifi_status() == (_BLANK, _BLANK)

    def test_ip_command_timeout_never_raises(self):
        with patch("dial_info.socket.socket", side_effect=OSError("no route")):
            with patch(
                "dial_info.subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd="ip", timeout=2.0),
            ):
                assert _ipv4() is None

    def test_gather_dial_info_never_raises_on_timeout(self):
        with patch("dial_info.socket.socket", side_effect=OSError("no route")), \
             patch("dial_info.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="x", timeout=2.0)), \
             patch("builtins.open", side_effect=OSError("no such file")):
            rows = gather_dial_info("Dial", "1.0")
        assert dict(rows)["IPv4"] == _BLANK
        assert dict(rows)["WiFi"] == _BLANK
        assert dict(rows)["Signal"] == SIGNAL_DISCONNECTED


# ---------------------------------------------------------------------------
# The (WiFi, Signal) rows against the network poller's own verdict, and the
# configured-network fallback used while the dial is not joined to anything.
# ---------------------------------------------------------------------------

class _Net:
    def __init__(self, link):
        self.link = link


class TestWifiRowsAgainstTheWatcher:
    def _rows(self, network, wifi=("HomeNet", SIGNAL_STRONG), configured="HomeNet"):
        with patch("dial_info._ipv4", return_value="10.0.0.5"), \
             patch("dial_info._disk_free", return_value="1.0 GB"), \
             patch("dial_info.wifi_status", side_effect=wifi if callable(wifi) else lambda: wifi), \
             patch("dial_info.configured_ssid", return_value=configured):
            return dict(gather_dial_info("Dial", "1.0", network=network))

    def test_connected_shows_joined_network_and_category(self):
        rows = self._rows(_Net("connected"))
        assert (rows["WiFi"], rows["Signal"]) == ("HomeNet", SIGNAL_STRONG)

    def test_down_shows_configured_ssid_and_disconnected(self):
        rows = self._rows(_Net("down"), wifi=(_BLANK, _BLANK), configured="HomeNet")
        assert (rows["WiFi"], rows["Signal"]) == ("HomeNet", SIGNAL_DISCONNECTED)

    def test_down_overrides_a_stale_joined_reading(self):
        rows = self._rows(_Net("down"), wifi=("Elsewhere", SIGNAL_WEAK), configured="HomeNet")
        assert (rows["WiFi"], rows["Signal"]) == ("HomeNet", SIGNAL_DISCONNECTED)

    def test_down_with_nothing_configured_shows_dash_and_disconnected(self):
        rows = self._rows(_Net("down"), wifi=(_BLANK, _BLANK), configured=None)
        assert (rows["WiFi"], rows["Signal"]) == (_BLANK, SIGNAL_DISCONNECTED)

    def test_no_watcher_view_but_no_association_is_disconnected(self):
        rows = self._rows(None, wifi=(_BLANK, _BLANK), configured="HomeNet")
        assert (rows["WiFi"], rows["Signal"]) == ("HomeNet", SIGNAL_DISCONNECTED)

    def test_no_watcher_view_and_joined_is_unchanged(self):
        rows = self._rows(None, wifi=("HomeNet", SIGNAL_NORMAL))
        assert (rows["WiFi"], rows["Signal"]) == ("HomeNet", SIGNAL_NORMAL)

    def test_probe_raising_without_a_verdict_keeps_the_dash_pair(self):
        rows = self._rows(None, wifi=lambda: (_ for _ in ()).throw(RuntimeError("boom")))
        assert (rows["WiFi"], rows["Signal"]) == (_BLANK, _BLANK)

    def test_configured_ssid_raising_degrades_to_dash(self):
        with patch("dial_info._ipv4", return_value="10.0.0.5"), \
             patch("dial_info._disk_free", return_value="1.0 GB"), \
             patch("dial_info.wifi_status", return_value=(_BLANK, _BLANK)), \
             patch("dial_info.configured_ssid", side_effect=RuntimeError("boom")):
            rows = dict(gather_dial_info("Dial", "1.0", network=_Net("down")))
        assert (rows["WiFi"], rows["Signal"]) == (_BLANK, SIGNAL_DISCONNECTED)


# ---------------------------------------------------------------------------
# configured_ssid: the network-state file (uuid preferred, then name), the
# legacy name-only fallback, and every failure mode along the way.
# ---------------------------------------------------------------------------

class TestConfiguredSsid:
    STATE = '{"schema_version": 1, "connection_name": "HomeNet-profile", "connection_uuid": "abc-123"}'

    def test_uuid_preferred_then_nmcli(self):
        with patch("builtins.open", mock_open(read_data=self.STATE)), \
             patch("dial_info._run", return_value=_completed(stdout="HomeNet\n")) as run:
            assert configured_ssid() == "HomeNet"
        assert run.call_args[0][0] == ["nmcli", "-g", "802-11-wireless.ssid", "connection", "show", "abc-123"]

    def test_name_used_when_uuid_blank(self):
        state = '{"schema_version": 1, "connection_name": "HomeNet-profile", "connection_uuid": ""}'
        with patch("builtins.open", mock_open(read_data=state)), \
             patch("dial_info._run", return_value=_completed(stdout="HomeNet\n")) as run:
            assert configured_ssid() == "HomeNet"
        assert run.call_args[0][0][-1] == "HomeNet-profile"

    def test_legacy_name_file_fallback(self):
        handles = {
            "/etc/autostream-network.json": OSError("missing"),
            "/opt/autostream/ssid": "LegacyProfile\n",
        }

        def fake_open(path, *args, **kwargs):
            value = handles[path]
            if isinstance(value, Exception):
                raise value
            return mock_open(read_data=value)()

        with patch("builtins.open", side_effect=fake_open), \
             patch("dial_info._run", return_value=_completed(stdout="LegacyNet\n")) as run:
            assert configured_ssid() == "LegacyNet"
        assert run.call_args[0][0][-1] == "LegacyProfile"

    def test_nothing_configured_is_none_without_a_subprocess(self):
        with patch("builtins.open", side_effect=OSError("missing")), patch("dial_info._run") as run:
            assert configured_ssid() is None
        run.assert_not_called()

    def test_invalid_json_falls_back_to_legacy(self):
        def fake_open(path, *args, **kwargs):
            if path == "/etc/autostream-network.json":
                return mock_open(read_data="{not json")()
            return mock_open(read_data="P\n")()

        with patch("builtins.open", side_effect=fake_open), \
             patch("dial_info._run", return_value=_completed(stdout="Net\n")):
            assert configured_ssid() == "Net"

    def test_nmcli_failure_is_none(self):
        with patch("builtins.open", mock_open(read_data=self.STATE)), \
             patch("dial_info._run", return_value=_completed(stdout="", returncode=10)):
            assert configured_ssid() is None
        with patch("builtins.open", mock_open(read_data=self.STATE)), patch("dial_info._run", return_value=None):
            assert configured_ssid() is None

    def test_public_wifi_status_is_the_old_private_name(self):
        assert wifi_status is _wifi_status
