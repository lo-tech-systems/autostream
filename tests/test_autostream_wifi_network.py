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
