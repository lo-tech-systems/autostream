"""Tests for core/autostream_wifi_network.py — the watcher's network helper.

WP1 scope: network-state load/validate/atomic-save, legacy migration and
mirroring, and the structural guarantee that the helper carries no Flask /
threading / systemd-management code.
"""
from __future__ import annotations

import json
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
