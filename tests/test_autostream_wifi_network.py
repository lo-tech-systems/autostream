"""Tests for core/autostream_wifi_network.py — the watcher's network helper.

WP1 scope: network-state load/validate/atomic-save, legacy migration and
mirroring, and the structural guarantee that the helper carries no Flask /
threading / systemd-management code.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

HELPER_PATH = REPO_ROOT / "core" / "autostream_wifi_network.py"

import autostream_wifi_network as wifi_net  # noqa: E402


@pytest.fixture()
def paths(tmp_path):
    return {
        "state_path": str(tmp_path / "autostream-network.json"),
        "legacy_path": str(tmp_path / "ssid"),
    }


def _write(path: str, text: str) -> None:
    Path(path).write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# 1. Valid JSON wins over the legacy file
# ---------------------------------------------------------------------------

def test_valid_json_wins_over_legacy(paths):
    _write(paths["state_path"], json.dumps({
        "schema_version": 1,
        "connection_name": "Home",
        "connection_uuid": "abc-123",
    }))
    _write(paths["legacy_path"], "LegacyName\n")
    state = wifi_net.load_network_state(**paths)
    assert state.connection_name == "Home"
    assert state.connection_uuid == "abc-123"


# ---------------------------------------------------------------------------
# 2. Missing JSON imports a non-empty legacy file
# ---------------------------------------------------------------------------

def test_missing_json_falls_back_to_legacy(paths):
    _write(paths["legacy_path"], "LegacyName\n")
    state = wifi_net.load_network_state(**paths)
    assert state.connection_name == "LegacyName"
    assert state.connection_uuid == ""


# ---------------------------------------------------------------------------
# 3. Invalid JSON falls back to legacy without crashing
# ---------------------------------------------------------------------------

def test_invalid_json_falls_back_to_legacy(paths):
    _write(paths["state_path"], "{ this is not valid json ")
    _write(paths["legacy_path"], "LegacyName\n")
    state = wifi_net.load_network_state(**paths)
    assert state.connection_name == "LegacyName"


def test_wrong_schema_version_falls_back(paths):
    _write(paths["state_path"], json.dumps({
        "schema_version": 99, "connection_name": "Future",
    }))
    _write(paths["legacy_path"], "LegacyName\n")
    state = wifi_net.load_network_state(**paths)
    assert state.connection_name == "LegacyName"


# ---------------------------------------------------------------------------
# 4. Empty legacy state remains unconfigured
# ---------------------------------------------------------------------------

def test_empty_everything_is_unconfigured(paths):
    state = wifi_net.load_network_state(**paths)
    assert state.connection_name == ""
    assert state.is_configured is False


def test_empty_json_consults_legacy(paths):
    _write(paths["state_path"], json.dumps({
        "schema_version": 1, "connection_name": "", "connection_uuid": "",
    }))
    _write(paths["legacy_path"], "LegacyName\n")
    state = wifi_net.load_network_state(**paths)
    assert state.connection_name == "LegacyName"


# ---------------------------------------------------------------------------
# 5. Atomic save writes schema version and expected fields
# ---------------------------------------------------------------------------

def test_atomic_save_writes_schema_and_fields(paths):
    wifi_net.save_network_state(
        wifi_net.NetworkState(connection_name="Home", connection_uuid="u-1"),
        **paths,
    )
    data = json.loads(Path(paths["state_path"]).read_text(encoding="utf-8"))
    assert data["schema_version"] == 1
    assert data["connection_name"] == "Home"
    assert data["connection_uuid"] == "u-1"


# ---------------------------------------------------------------------------
# 6. Successful connection updates both files
# ---------------------------------------------------------------------------

def test_save_updates_both_files(paths):
    wifi_net.save_network_state(
        wifi_net.NetworkState(connection_name="Home", connection_uuid="u-1"),
        **paths,
    )
    legacy = Path(paths["legacy_path"]).read_text(encoding="utf-8")
    assert legacy == "Home\n"  # name + newline, never JSON
    assert "{" not in legacy


# ---------------------------------------------------------------------------
# 7. No adapter preference is persisted in either file
# ---------------------------------------------------------------------------

def test_no_adapter_preference_persisted(paths):
    wifi_net.save_network_state(
        wifi_net.NetworkState(connection_name="Home", connection_uuid="u-1"),
        **paths,
    )
    data = json.loads(Path(paths["state_path"]).read_text(encoding="utf-8"))
    forbidden = {"ifname", "adapter", "mac", "bssid", "band", "interface"}
    assert forbidden.isdisjoint(k.lower() for k in data.keys())


# ---------------------------------------------------------------------------
# 8. No password appears in either file
# ---------------------------------------------------------------------------

def test_no_password_fields(paths):
    wifi_net.save_network_state(
        wifi_net.NetworkState(connection_name="Home", connection_uuid="u-1"),
        **paths,
    )
    state_text = Path(paths["state_path"]).read_text(encoding="utf-8").lower()
    for word in ("password", "psk", "secret", "key-mgmt"):
        assert word not in state_text


# ---------------------------------------------------------------------------
# 9. Legacy migration remains valid (used identically in Dial mode)
# ---------------------------------------------------------------------------

def test_migrate_legacy_resolves_single_uuid(paths):
    _write(paths["legacy_path"], "Home\n")
    with patch.object(wifi_net, "resolve_connection_uuid_for_name", return_value="u-9"):
        migrated = wifi_net.migrate_legacy_state(**paths)
    assert migrated is not None
    assert migrated.connection_name == "Home"
    assert migrated.connection_uuid == "u-9"
    data = json.loads(Path(paths["state_path"]).read_text(encoding="utf-8"))
    assert data["connection_uuid"] == "u-9"


def test_migrate_legacy_without_uuid_keeps_name(paths):
    _write(paths["legacy_path"], "Home\n")
    with patch.object(wifi_net, "resolve_connection_uuid_for_name", return_value=""):
        migrated = wifi_net.migrate_legacy_state(**paths)
    assert migrated.connection_name == "Home"
    assert migrated.connection_uuid == ""


def test_migrate_noop_when_json_already_configured(paths):
    _write(paths["state_path"], json.dumps({
        "schema_version": 1, "connection_name": "Home", "connection_uuid": "u",
    }))
    _write(paths["legacy_path"], "Other\n")
    migrated = wifi_net.migrate_legacy_state(**paths)
    assert migrated is None
    data = json.loads(Path(paths["state_path"]).read_text(encoding="utf-8"))
    assert data["connection_name"] == "Home"  # unchanged


def test_migrate_noop_when_no_legacy(paths):
    assert wifi_net.migrate_legacy_state(**paths) is None


def test_legacy_file_left_unchanged_by_migration(paths):
    _write(paths["legacy_path"], "Home\n")
    with patch.object(wifi_net, "resolve_connection_uuid_for_name", return_value="u-9"):
        wifi_net.migrate_legacy_state(**paths)
    assert Path(paths["legacy_path"]).read_text(encoding="utf-8") == "Home\n"


# ---------------------------------------------------------------------------
# 10. The helper imports no Flask, threading, or systemd-management code
# ---------------------------------------------------------------------------

def test_helper_has_no_forbidden_imports():
    src = HELPER_PATH.read_text(encoding="utf-8")
    for forbidden in ("import flask", "from flask", "import threading",
                      "Flask(", "systemctl"):
        assert forbidden not in src, f"helper must not contain {forbidden!r}"


def test_helper_only_depends_on_stdlib_and_sysutils():
    src = HELPER_PATH.read_text(encoding="utf-8")
    # The only non-stdlib import allowed is autostream_sysutils.
    assert "from autostream_sysutils import" in src
    assert "import requests" not in src


# ---------------------------------------------------------------------------
# 12. The persistent root-owned file path is /etc/autostream-network.json
#     (not inside the unprivileged /etc/autostream/ directory)
# ---------------------------------------------------------------------------

def test_network_state_path_is_etc_not_etc_autostream():
    assert wifi_net.NETWORK_STATE_PATH == "/etc/autostream-network.json"
    assert "/etc/autostream/" not in wifi_net.NETWORK_STATE_PATH


def test_legacy_path_unchanged():
    assert wifi_net.LEGACY_SSID_PATH == "/opt/autostream/ssid"


# ---------------------------------------------------------------------------
# nmcli terse parsing — escaped colons/backslashes/unicode/malformed
# ---------------------------------------------------------------------------

class TestSplitNmcliTerse:
    def test_plain(self):
        assert wifi_net.split_nmcli_terse("a:b:c") == ["a", "b", "c"]

    def test_escaped_colon(self):
        assert wifi_net.split_nmcli_terse(r"My\:SSID:80") == ["My:SSID", "80"]

    def test_escaped_backslash(self):
        assert wifi_net.split_nmcli_terse(r"a\\b:c") == ["a\\b", "c"]

    def test_unicode(self):
        assert wifi_net.split_nmcli_terse("café:90") == ["café", "90"]

    def test_empty_fields(self):
        assert wifi_net.split_nmcli_terse(":") == ["", ""]

    def test_maxsplit_keeps_trailing(self):
        assert wifi_net.split_nmcli_terse("a:b:c", maxsplit=1) == ["a", "b:c"]


class TestResolveUuid:
    def test_single_match_returns_uuid(self):
        out = "Home:uuid-1:802-11-wireless\nWired:uuid-2:ethernet\n"
        with patch.object(wifi_net, "run_cmd",
                          return_value=MagicMock(returncode=0, stdout=out, stderr="")):
            assert wifi_net.resolve_connection_uuid_for_name("Home") == "uuid-1"

    def test_multiple_matches_returns_empty(self):
        out = "Home:uuid-1:802-11-wireless\nHome:uuid-2:802-11-wireless\n"
        with patch.object(wifi_net, "run_cmd",
                          return_value=MagicMock(returncode=0, stdout=out, stderr="")):
            assert wifi_net.resolve_connection_uuid_for_name("Home") == ""

    def test_no_match_returns_empty(self):
        out = "Other:uuid-1:802-11-wireless\n"
        with patch.object(wifi_net, "run_cmd",
                          return_value=MagicMock(returncode=0, stdout=out, stderr="")):
            assert wifi_net.resolve_connection_uuid_for_name("Home") == ""

    def test_command_failure_returns_empty(self):
        with patch.object(wifi_net, "run_cmd",
                          return_value=MagicMock(returncode=1, stdout="", stderr="x")):
            assert wifi_net.resolve_connection_uuid_for_name("Home") == ""


# ---------------------------------------------------------------------------
# WP2 — MAC normalisation
# ---------------------------------------------------------------------------

class TestNormaliseMac:
    def test_lowercases_and_keeps_colons(self):
        assert wifi_net.normalise_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"

    def test_converts_dashes(self):
        assert wifi_net.normalise_mac("aa-bb-cc-dd-ee-ff") == "aa:bb:cc:dd:ee:ff"

    def test_pads_single_hex_digits(self):
        assert wifi_net.normalise_mac("a:b:c:d:e:f") == "0a:0b:0c:0d:0e:0f"

    def test_rejects_zero_mac(self):
        assert wifi_net.normalise_mac("00:00:00:00:00:00") == ""

    def test_rejects_empty(self):
        assert wifi_net.normalise_mac("") == ""
        assert wifi_net.normalise_mac(None) == ""

    def test_rejects_malformed(self):
        assert wifi_net.normalise_mac("not-a-mac") == ""
        assert wifi_net.normalise_mac("aa:bb:cc") == ""


# ---------------------------------------------------------------------------
# WP2 — adapter discovery and classification
# ---------------------------------------------------------------------------

def _adapter(ifname, mac, is_usb=False, is_builtin=False, managed=True, state="connected"):
    return wifi_net.WifiAdapter(
        ifname=ifname, permanent_mac=mac, current_mac=mac,
        is_builtin=is_builtin, is_usb=is_usb, managed=managed,
        state=state, description=ifname,
    )


class TestDiscovery:
    def _dev_status(self, lines):
        return MagicMock(returncode=0, stdout="".join(lines), stderr="")

    def test_classifies_builtin_and_usb(self, tmp_path):
        # Build a fake /sys/class/net tree: wlan0 builtin, wlan1 usb.
        sysroot = tmp_path / "net"
        (sysroot / "wlan0").mkdir(parents=True)
        (sysroot / "wlan1").mkdir(parents=True)
        # Device symlink targets distinguishing usb vs platform.
        (tmp_path / "platform_wlan0").mkdir()
        (tmp_path / "usb_wlan1").mkdir()
        # Simulate realpath by writing 'device' dirs we can detect via _sys_path_is_usb.
        # Easier: monkeypatch _sys_path_is_usb.
        (sysroot / "wlan0" / "address").write_text("aa:bb:cc:00:00:01\n")
        (sysroot / "wlan1" / "address").write_text("aa:bb:cc:00:00:02\n")

        status = self._dev_status([
            "wlan0:wifi:connected:Home\n",
            "wlan1:wifi:disconnected:\n",
            "eth0:ethernet:connected:Wired\n",
        ])

        def fake_run_cmd(cmd, *a, **k):
            if "status" in cmd:
                return status
            # device show <ifname>
            ifname = cmd[-1]
            mac = "aa:bb:cc:00:00:01" if ifname == "wlan0" else "aa:bb:cc:00:00:02"
            out = f"GENERAL.HWADDR:{mac.upper()}\nGENERAL.STATE:100 (connected)\n"
            return MagicMock(returncode=0, stdout=out, stderr="")

        def fake_is_usb(ifname, sys_root="/sys/class/net"):
            return ifname == "wlan1"

        with patch.object(wifi_net, "run_cmd", side_effect=fake_run_cmd), \
             patch.object(wifi_net, "_sys_path_is_usb", side_effect=fake_is_usb):
            adapters = wifi_net.discover_adapters(sys_root=str(sysroot))

        by = {a.ifname: a for a in adapters}
        assert set(by) == {"wlan0", "wlan1"}  # ethernet excluded
        assert by["wlan0"].is_builtin and not by["wlan0"].is_usb
        assert by["wlan1"].is_usb and not by["wlan1"].is_builtin

    def test_resolve_builtin_prefers_classified(self):
        adapters = [
            _adapter("wlan1", "aa:bb:cc:00:00:02", is_usb=True),
            _adapter("wlan0", "aa:bb:cc:00:00:01", is_builtin=True),
        ]
        assert wifi_net.resolve_builtin(adapters).ifname == "wlan0"

    def test_resolve_builtin_wlan0_fallback(self):
        # No classified builtin; falls back to literal wlan0.
        adapters = [_adapter("wlan0", "", is_usb=False, is_builtin=False)]
        assert wifi_net.resolve_builtin(adapters).ifname == "wlan0"

    def test_resolve_builtin_none(self):
        adapters = [_adapter("wlan1", "aa:bb:cc:00:00:02", is_usb=True)]
        assert wifi_net.resolve_builtin(adapters) is None

    def test_usb_candidates_sorted_by_permanent_mac(self):
        adapters = [
            _adapter("wlan2", "aa:bb:cc:00:00:09", is_usb=True),
            _adapter("wlan1", "aa:bb:cc:00:00:02", is_usb=True),
            _adapter("wlan0", "aa:bb:cc:00:00:01", is_builtin=True),
        ]
        order = wifi_net.usb_candidates(adapters)
        assert [a.ifname for a in order] == ["wlan1", "wlan2"]

    def test_ifname_change_does_not_affect_identity(self):
        # Same permanent MAC under a different ifname keeps deterministic order.
        a = [
            _adapter("wlanX", "aa:bb:cc:00:00:02", is_usb=True),
            _adapter("wlanY", "aa:bb:cc:00:00:01", is_usb=True),
        ]
        order = wifi_net.usb_candidates(a)
        assert order[0].permanent_mac == "aa:bb:cc:00:00:01"

    def test_client_order_usb_then_builtin(self):
        adapters = [
            _adapter("wlan0", "aa:bb:cc:00:00:01", is_builtin=True),
            _adapter("wlan1", "aa:bb:cc:00:00:02", is_usb=True),
        ]
        order = wifi_net.client_candidate_order(adapters)
        assert [a.ifname for a in order] == ["wlan1", "wlan0"]


# ---------------------------------------------------------------------------
# WP2 — explicit-interface command construction
# ---------------------------------------------------------------------------

class TestCommandConstruction:
    def test_activate_prefers_uuid_with_ifname(self):
        cmd = wifi_net.activate_connection_cmd("uuid-1", "Home", "wlan1")
        assert cmd == ["nmcli", "connection", "up", "uuid", "uuid-1", "ifname", "wlan1"]

    def test_activate_falls_back_to_id(self):
        cmd = wifi_net.activate_connection_cmd("", "Home", "wlan0")
        assert cmd == ["nmcli", "connection", "up", "id", "Home", "ifname", "wlan0"]

    def test_rescan_targets_interface(self):
        assert wifi_net.rescan_cmd("wlan1") == [
            "nmcli", "device", "wifi", "rescan", "ifname", "wlan1"]

    def test_add_profile_targets_interface(self):
        cmd = wifi_net.add_wifi_profile_cmd("autostream-wifi-abcd1234", "wlan1", "My SSID")
        assert "ifname" in cmd and "wlan1" in cmd
        assert cmd[cmd.index("ifname") + 1] == "wlan1"
        assert cmd[cmd.index("ssid") + 1] == "My SSID"

    def test_clear_restrictions_lists_all_keys(self):
        cmd = wifi_net.clear_restrictions_cmd("uuid-1", wifi_net.CROSS_ADAPTER_RESTRICTIONS)
        for key in ("connection.interface-name", "802-11-wireless.mac-address",
                    "802-11-wireless.bssid", "802-11-wireless.band",
                    "802-11-wireless.channel"):
            assert key in cmd
        # SSID and security must never be cleared here.
        assert "802-11-wireless.ssid" not in cmd
        assert "802-11-wireless-security.key-mgmt" not in cmd

    def test_delete_by_uuid(self):
        assert wifi_net.delete_connection_cmd("uuid-1") == [
            "nmcli", "connection", "delete", "uuid", "uuid-1"]

    def test_get_connection_uuid_by_name(self):
        assert wifi_net.get_connection_uuid_by_name_cmd("Home") == [
            "nmcli", "-g", "connection.uuid",
            "connection", "show", "id", "Home",
        ]


# ---------------------------------------------------------------------------
# WP3 — scan parsing and exact-SSID merging
# ---------------------------------------------------------------------------

class TestScanMerge:
    def test_parse_skips_hidden_and_nonnumeric(self):
        out = "Home:80\n:60\nBad:notnum\n"
        assert wifi_net.parse_scan_output(out) == {"Home": 80}

    def test_parse_keeps_strongest(self):
        out = "Home:50\nHome:75\nHome:30\n"
        assert wifi_net.parse_scan_output(out) == {"Home": 75}

    def test_parse_escaped_colon_ssid(self):
        out = r"My\:Net:42" + "\n"
        assert wifi_net.parse_scan_output(out) == {"My:Net": 42}

    def test_same_ssid_across_adapters_appears_once(self):
        merged = wifi_net.merge_scans(
            {"Home": 60}, [{"Home": 81}],
            builtin_mac="aa:aa:aa:aa:aa:aa", usb_macs=["bb:bb:bb:bb:bb:bb"],
        )
        assert len(merged) == 1
        rec = merged[0]
        assert rec["ssid"] == "Home"
        assert rec["signal"] == 81  # strongest wins
        assert rec["builtin_visible"] is True
        assert rec["usb_visible"] is True
        assert set(rec["adapter_macs"]) == {"aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"}

    def test_builtin_only_network(self):
        merged = wifi_net.merge_scans({"OnlyBuiltin": 70}, [{}])
        rec = next(r for r in merged if r["ssid"] == "OnlyBuiltin")
        assert rec["builtin_visible"] is True
        assert rec["usb_visible"] is False

    def test_usb_only_network(self):
        merged = wifi_net.merge_scans({}, [{"OnlyUsb": 70}])
        rec = next(r for r in merged if r["ssid"] == "OnlyUsb")
        assert rec["builtin_visible"] is False
        assert rec["usb_visible"] is True

    def test_failed_builtin_scan_marks_unknown(self):
        # builtin_scan None -> no built-in visibility contributed.
        merged = wifi_net.merge_scans(None, [{"X": 50}])
        rec = next(r for r in merged if r["ssid"] == "X")
        assert rec["builtin_visible"] is False

    def test_failed_usb_scan_isolated(self):
        merged = wifi_net.merge_scans({"X": 50}, [None])
        rec = next(r for r in merged if r["ssid"] == "X")
        assert rec["builtin_visible"] is True
        assert rec["usb_visible"] is False

    def test_sorted_by_signal_descending(self):
        merged = wifi_net.merge_scans({"A": 40, "B": 80, "C": 60}, [])
        assert [r["ssid"] for r in merged] == ["B", "C", "A"]


class TestConnectionTargetOrder:
    def _adapters(self):
        return [
            _adapter("wlan0", "aa:bb:cc:00:00:01", is_builtin=True),
            _adapter("wlan1", "aa:bb:cc:00:00:02", is_usb=True),
        ]

    def test_usb_only_targets_usb(self):
        adapters = self._adapters()
        merged = [{
            "ssid": "UsbNet", "signal": 70, "builtin_visible": False,
            "usb_visible": True, "adapter_macs": ["aa:bb:cc:00:00:02"],
        }]
        order = wifi_net.connection_target_order("UsbNet", adapters, merged, True)
        assert order[0].ifname == "wlan1"

    def test_shared_ssid_usb_first(self):
        adapters = self._adapters()
        merged = [{
            "ssid": "Shared", "signal": 70, "builtin_visible": True,
            "usb_visible": True,
            "adapter_macs": ["aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"],
        }]
        order = wifi_net.connection_target_order("Shared", adapters, merged, True)
        assert [a.ifname for a in order][:2] == ["wlan1", "wlan0"]

    def test_unknown_ssid_falls_back_to_best_effort(self):
        adapters = self._adapters()
        merged = []  # SSID not in any scan
        order = wifi_net.connection_target_order("Mystery", adapters, merged, False)
        # USB best-effort, then built-in best-effort (builtin scan unknown).
        assert "wlan1" in [a.ifname for a in order]
        assert "wlan0" in [a.ifname for a in order]


# ---------------------------------------------------------------------------
# WP4 — runtime dnsmasq interface binding
# ---------------------------------------------------------------------------

class TestDnsmasqRuntime:
    TEMPLATE = (
        "# comment\n"
        "interface=__AUTOSTREAM_WIFI_IFACE__\n"
        "bind-interfaces\n"
        "dhcp-range=192.168.4.50,192.168.4.200,255.255.255.0,12h\n"
    )

    def test_substitutes_token(self):
        out = wifi_net.render_dnsmasq_runtime_config(self.TEMPLATE, "wlan0")
        assert "interface=wlan0" in out
        assert "__AUTOSTREAM_WIFI_IFACE__" not in out

    def test_missing_token_fails(self):
        with pytest.raises(ValueError):
            wifi_net.render_dnsmasq_runtime_config("interface=wlan0\n", "wlan0")

    def test_duplicated_token_fails(self):
        dup = self.TEMPLATE + "interface=__AUTOSTREAM_WIFI_IFACE__\n"
        with pytest.raises(ValueError):
            wifi_net.render_dnsmasq_runtime_config(dup, "wlan0")

    def test_unsafe_ifname_rejected(self):
        for bad in ("wlan0\ninterface=evil", "wlan 0", "", "a;b"):
            with pytest.raises(ValueError):
                wifi_net.render_dnsmasq_runtime_config(self.TEMPLATE, bad)

    def test_write_runtime_atomic(self, tmp_path):
        tpl = tmp_path / "tpl.conf"
        tpl.write_text(self.TEMPLATE, encoding="utf-8")
        runtime = tmp_path / "run" / "out.conf"
        wifi_net.write_dnsmasq_runtime_config(
            str(tpl), str(runtime), "wlan0", runtime_dir=str(tmp_path / "run"),
        )
        text = runtime.read_text(encoding="utf-8")
        assert "interface=wlan0" in text
        # Static DHCP/DNS behaviour preserved verbatim.
        assert "dhcp-range=192.168.4.50,192.168.4.200,255.255.255.0,12h" in text

    def test_remove_runtime_best_effort(self, tmp_path):
        runtime = tmp_path / "out.conf"
        runtime.write_text("x", encoding="utf-8")
        wifi_net.remove_dnsmasq_runtime_config(str(runtime))
        assert not runtime.exists()
        # No error when already absent.
        wifi_net.remove_dnsmasq_runtime_config(str(runtime))


# ---------------------------------------------------------------------------
# WP1 (dead-PHY) — USB sysfs reset primitives
# ---------------------------------------------------------------------------

def _can_symlink(tmp_path) -> bool:
    """Return True if this environment can create directory symlinks."""
    a = tmp_path / "_sl_a"
    a.mkdir()
    try:
        os.symlink(str(a), str(tmp_path / "_sl_b"))
    except OSError:
        return False
    return True


def _build_fake_usb_tree(tmp_path, ifname="wlan0", driver="rtl8xxxu",
                         interface_id="1-1.5:1.0", mac="dc:62:79:91:4d:d6"):
    """Build a symlink-based fake sysfs tree resembling a USB Wi-Fi dongle.

    Returns (sys_root, bus_root) as strings.  The realpath layout mirrors the
    field unit: /sys/class/net/<if> -> .../<usb_dev>/<iface_id>/net/<if> and
    .../<iface_id>/driver -> /sys/bus/usb/drivers/<driver>.
    """
    usb_dev = interface_id.split(":", 1)[0]  # e.g. "1-1.5"

    sys_root = tmp_path / "sys" / "class" / "net"
    sys_root.mkdir(parents=True)

    devices = tmp_path / "sys" / "devices" / "usb1" / usb_dev
    iface_dir = devices / interface_id
    net_dir = iface_dir / "net" / ifname
    net_dir.mkdir(parents=True)
    (net_dir / "address").write_text(mac + "\n", encoding="utf-8")
    (net_dir / "carrier").write_text("0\n", encoding="utf-8")
    (net_dir / "operstate").write_text("down\n", encoding="utf-8")

    bus_root = tmp_path / "sys" / "bus" / "usb"
    driver_dir = bus_root / "drivers" / driver
    driver_dir.mkdir(parents=True)
    (driver_dir / "unbind").write_text("", encoding="utf-8")
    (driver_dir / "bind").write_text("", encoding="utf-8")
    (devices / "authorized").write_text("1\n", encoding="utf-8")

    # /sys/class/net/<if> -> the per-interface net dir
    os.symlink(str(net_dir), str(sys_root / ifname))
    # <if>/device -> the USB interface dir
    os.symlink(str(iface_dir), str(net_dir / "device"))
    # <if>/device/driver -> the driver dir
    os.symlink(str(driver_dir), str(iface_dir / "driver"))
    return str(sys_root), str(bus_root)


class TestUsbResetPrimitives:
    def test_usb_sysfs_paths_resolves(self, tmp_path):
        if not _can_symlink(tmp_path):
            pytest.skip("symlinks unavailable in this environment")
        sys_root, _ = _build_fake_usb_tree(tmp_path)
        paths = wifi_net.usb_sysfs_paths("wlan0", sys_root=sys_root)
        assert paths is not None
        assert paths["interface_id"] == "1-1.5:1.0"
        assert paths["driver"] == "rtl8xxxu"
        assert paths["usb_device_path"].replace("\\", "/").endswith("/1-1.5")

    def test_usb_sysfs_paths_none_for_non_usb(self, tmp_path):
        if not _can_symlink(tmp_path):
            pytest.skip("symlinks unavailable in this environment")
        # Build a platform (non-USB) tree.
        sys_root = tmp_path / "net"
        sys_root.mkdir()
        plat = tmp_path / "platform" / "soc" / "mmc" / "net" / "wlan0"
        plat.mkdir(parents=True)
        os.symlink(str(plat), str(sys_root / "wlan0"))
        os.symlink(str(plat.parent.parent), str(plat / "device"))
        assert wifi_net.usb_sysfs_paths("wlan0", sys_root=str(sys_root)) is None

    def test_usb_sysfs_paths_none_for_missing(self, tmp_path):
        sys_root = tmp_path / "net"
        sys_root.mkdir()
        assert wifi_net.usb_sysfs_paths("wlan9", sys_root=str(sys_root)) is None

    def test_method_a_writes_unbind_then_bind(self, tmp_path):
        if not _can_symlink(tmp_path):
            pytest.skip("symlinks unavailable in this environment")
        sys_root, bus_root = _build_fake_usb_tree(tmp_path)
        assert wifi_net.reset_usb_adapter_rebind(
            "wlan0", sys_root=sys_root, bus_root=bus_root) is True
        driver_dir = Path(bus_root) / "drivers" / "rtl8xxxu"
        assert (driver_dir / "unbind").read_text() == "1-1.5:1.0"
        assert (driver_dir / "bind").read_text() == "1-1.5:1.0"

    def test_method_b_writes_authorized_toggle(self, tmp_path):
        if not _can_symlink(tmp_path):
            pytest.skip("symlinks unavailable in this environment")
        sys_root, bus_root = _build_fake_usb_tree(tmp_path)
        assert wifi_net.reset_usb_adapter_reenumerate(
            "wlan0", sys_root=sys_root, bus_root=bus_root) is True
        authorized = Path(tmp_path) / "sys" / "devices" / "usb1" / "1-1.5" / "authorized"
        # Last write wins on a plain file; assert it ends at "1".
        assert authorized.read_text() == "1"

    def test_method_a_false_for_missing(self, tmp_path):
        sys_root = tmp_path / "net"
        sys_root.mkdir()
        assert wifi_net.reset_usb_adapter_rebind(
            "wlan9", sys_root=str(sys_root)) is False

    def test_method_b_false_for_missing(self, tmp_path):
        sys_root = tmp_path / "net"
        sys_root.mkdir()
        assert wifi_net.reset_usb_adapter_reenumerate(
            "wlan9", sys_root=str(sys_root)) is False


class TestSysfsNetdevEnumeration:
    def test_list_sysfs_netdevs(self, tmp_path):
        if not _can_symlink(tmp_path):
            pytest.skip("symlinks unavailable in this environment")
        sys_root, _ = _build_fake_usb_tree(tmp_path)
        names = wifi_net.list_sysfs_netdevs(sys_root=sys_root)
        assert "wlan0" in names

    def test_find_sysfs_netdev_by_mac(self, tmp_path):
        if not _can_symlink(tmp_path):
            pytest.skip("symlinks unavailable in this environment")
        sys_root, _ = _build_fake_usb_tree(tmp_path, mac="dc:62:79:91:4d:d6")
        assert wifi_net.find_sysfs_netdev_by_mac(
            "DC:62:79:91:4D:D6", sys_root=sys_root) == "wlan0"
        assert wifi_net.find_sysfs_netdev_by_mac(
            "aa:bb:cc:dd:ee:ff", sys_root=sys_root) == ""

    def test_find_sysfs_netdev_by_mac_empty_for_bad_mac(self, tmp_path):
        sys_root = tmp_path / "net"
        sys_root.mkdir()
        assert wifi_net.find_sysfs_netdev_by_mac("", sys_root=str(sys_root)) == ""

    def test_read_link_down_true(self, tmp_path):
        base = tmp_path / "net" / "wlan0"
        base.mkdir(parents=True)
        (base / "carrier").write_text("0\n")
        (base / "operstate").write_text("down\n")
        assert wifi_net.read_link_down("wlan0", sys_root=str(tmp_path / "net")) is True

    def test_read_link_down_false_when_up(self, tmp_path):
        base = tmp_path / "net" / "wlan0"
        base.mkdir(parents=True)
        (base / "carrier").write_text("1\n")
        (base / "operstate").write_text("up\n")
        assert wifi_net.read_link_down("wlan0", sys_root=str(tmp_path / "net")) is False

    def test_read_link_down_operstate_only(self, tmp_path):
        # carrier unreadable (interface down) but operstate present -> down.
        base = tmp_path / "net" / "wlan0"
        base.mkdir(parents=True)
        (base / "operstate").write_text("down\n")
        assert wifi_net.read_link_down("wlan0", sys_root=str(tmp_path / "net")) is True

    def test_read_link_down_none_when_unreadable(self, tmp_path):
        sys_root = tmp_path / "net"
        sys_root.mkdir()
        assert wifi_net.read_link_down("wlan9", sys_root=str(sys_root)) is None


# ---------------------------------------------------------------------------
# Gateway reachability
# ---------------------------------------------------------------------------

class TestGatewayReachable:
    """Tests for is_gateway_reachable().

    ``ip -j neigh show to <gw> dev <ifname>`` filters by device, so ip
    typically omits the "dev" field.  Three cases:
    - "dev" absent: accept (trust the command filter).
    - "dev" matches ifname: accept.
    - "dev" is a different interface: reject (defensive; should not occur in
      normal output but protects against unexpected kernel behaviour).
    """

    _ROUTES = [{"dev": "wlan0", "gateway": "10.240.1.1", "dst": "default"}]

    def _call(self, neigh_rows, ifname="wlan0"):
        with patch.object(wifi_net, "_run_ip_json", side_effect=[
            self._ROUTES,
            neigh_rows,
        ]):
            return wifi_net.is_gateway_reachable(ifname)

    def test_reachable_without_dev_field(self):
        """ip omits 'dev' when the command already filters by device; must still return True."""
        neigh = [{"dst": "10.240.1.1", "lladdr": "14:49:bc:34:0e:c8", "state": ["REACHABLE"]}]
        assert self._call(neigh) is True

    def test_reachable_with_dev_field(self):
        """Entries that do include 'dev' (some kernel versions) continue to work."""
        neigh = [{"dst": "10.240.1.1", "dev": "wlan0", "lladdr": "14:49:bc:34:0e:c8", "state": ["REACHABLE"]}]
        assert self._call(neigh) is True

    def test_failed_neighbour_rejected(self):
        neigh = [{"dst": "10.240.1.1", "lladdr": "14:49:bc:34:0e:c8", "state": ["FAILED"]}]
        assert self._call(neigh) is False

    def test_neighbour_on_other_dev_rejected(self):
        """An entry that explicitly names a different interface must be rejected."""
        neigh = [{"dst": "10.240.1.1", "dev": "eth0", "state": ["REACHABLE"]}]
        assert self._call(neigh) is False

    def test_empty_neigh_returns_false(self):
        assert self._call([]) is False

    def test_no_matching_route_returns_false(self):
        routes = [{"dev": "eth0", "gateway": "10.240.1.1", "dst": "default"}]
        with patch.object(wifi_net, "_run_ip_json", side_effect=[routes, []]):
            assert wifi_net.is_gateway_reachable("wlan0") is False


# ---------------------------------------------------------------------------
# WP6 (dead-PHY) — runtime status snapshot read/write + address facts
# ---------------------------------------------------------------------------

class TestUsableUnicastIpv4:
    @pytest.mark.parametrize("addr", [
        "192.168.1.42",
        "10.0.0.5/24",
        "172.16.0.9",
        "8.8.8.8",
    ])
    def test_accepts_usable_ipv4(self, addr):
        assert wifi_net.is_usable_unicast_ipv4(addr) is True

    @pytest.mark.parametrize("addr", [
        "0.0.0.0",
        "127.0.0.1",
        "169.254.1.2",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::1",
        "not-an-ip",
        "",
    ])
    def test_rejects_unusable_ipv4(self, addr):
        assert wifi_net.is_usable_unicast_ipv4(addr) is False

    def test_interface_has_usable_ipv4_accepts_public_ipv4(self):
        addrs = {"eth0": [{"family": "ipv4", "address": "8.8.8.8", "scope": "global"}]}
        with patch.object(wifi_net, "list_interface_addresses", return_value=addrs):
            assert wifi_net.interface_has_usable_ipv4("eth0") is True

    def test_interface_has_usable_ipv4_rejects_link_local_only(self):
        addrs = {"eth0": [{"family": "ipv4", "address": "169.254.1.2", "scope": "global"}]}
        with patch.object(wifi_net, "list_interface_addresses", return_value=addrs):
            assert wifi_net.interface_has_usable_ipv4("eth0") is False


class TestListInterfaceAddresses:
    def test_parses_ip_json(self):
        sample = [
            {"ifname": "wlan0", "addr_info": [
                {"family": "inet", "local": "192.168.1.42", "prefixlen": 24, "scope": "global"},
                {"family": "inet6", "local": "fe80::1", "prefixlen": 64, "scope": "link"},
            ]},
            {"ifname": "lo", "addr_info": [
                {"family": "inet", "local": "127.0.0.1", "prefixlen": 8, "scope": "host"},
            ]},
        ]
        with patch.object(wifi_net, "_run_ip_json", return_value=sample):
            out = wifi_net.list_interface_addresses()
        assert out["wlan0"][0] == {
            "family": "ipv4", "address": "192.168.1.42", "prefixlen": 24, "scope": "global"}
        assert out["wlan0"][1]["family"] == "ipv6"
        assert out["lo"][0]["family"] == "ipv4"

    def test_failure_returns_empty(self):
        with patch.object(wifi_net, "_run_ip_json", side_effect=RuntimeError("x")):
            assert wifi_net.list_interface_addresses() == {}


class TestDefaultGatewayIpv4:
    def test_returns_ipv4_for_iface(self):
        routes = [
            {"dev": "wlan0", "gateway": "192.168.1.1", "dst": "default"},
            {"dev": "eth0", "gateway": "10.0.0.1", "dst": "default"},
        ]
        with patch.object(wifi_net, "_run_ip_json", return_value=routes):
            assert wifi_net.default_gateway_ipv4("wlan0") == "192.168.1.1"
            assert wifi_net.default_gateway_ipv4("wlan1") == ""
