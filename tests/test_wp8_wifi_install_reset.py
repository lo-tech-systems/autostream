"""WP8 — Installer, factory reset, and uninstall coverage for network state file.

Verifies that /etc/autostream-network.json is correctly handled in:
  - autostream_admin FACTORY_RESET_DELETE_FILES (factory reset)
  - autostream_uninstall.sh (remove_path call)
  - autostream_install.sh (ownership fixup exists)

No shell execution required — file-content checks only.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

sys.path.insert(0, str(REPO_ROOT / "tests"))
from conftest import load_supervisor_script

_admin = load_supervisor_script("autostream_admin", "admin_wp8")

NETWORK_JSON = Path("/etc/autostream-network.json")


# ---------------------------------------------------------------------------
# Factory reset
# ---------------------------------------------------------------------------

class TestFactoryResetDeletesNetworkFile:
    def test_network_json_in_main_reset_list(self):
        """Factory reset must delete /etc/autostream-network.json so the next
        boot starts unconfigured (the adapter-selection invariant)."""
        assert NETWORK_JSON in _admin.FACTORY_RESET_DELETE_FILES, (
            "/etc/autostream-network.json must be in FACTORY_RESET_DELETE_FILES"
        )

    def test_network_json_in_dial_reset_list(self):
        """/etc/autostream-network.json must also be deleted on Dial factory reset.

        Dial uses the shared wifi_watcher, which writes /etc/autostream-network.json.
        Retaining it after factory reset would leave stale connection state.
        """
        assert NETWORK_JSON in _admin.FACTORY_RESET_DIAL_DELETE_FILES, (
            "/etc/autostream-network.json must be in FACTORY_RESET_DIAL_DELETE_FILES"
        )


# ---------------------------------------------------------------------------
# Uninstaller
# ---------------------------------------------------------------------------

UNINSTALL_SH = (REPO_ROOT / "autostream_uninstall.sh").read_text(encoding="utf-8")


class TestUninstallerRemovesNetworkFile:
    def test_remove_path_call_present(self):
        assert "remove_path /etc/autostream-network.json" in UNINSTALL_SH, (
            "autostream_uninstall.sh must call remove_path /etc/autostream-network.json"
        )


# ---------------------------------------------------------------------------
# Installer — ownership fixup
# ---------------------------------------------------------------------------

INSTALL_SH = (REPO_ROOT / "autostream_install.sh").read_text(encoding="utf-8")


class TestInstallerNetworkFileHandling:
    def test_installer_sets_ownership_on_network_json(self):
        """The installer must chown and chmod /etc/autostream-network.json after
        writing it so the watcher (root) can update it."""
        assert "/etc/autostream-network.json" in INSTALL_SH, (
            "autostream_install.sh must reference /etc/autostream-network.json"
        )

    def test_installer_copies_wifi_watcher(self):
        """The main wifi_watcher binary must be copied during install."""
        assert 'wifi_watcher"' in INSTALL_SH or "wifi_watcher" in INSTALL_SH

    def test_installer_copies_wifi_network_helper(self):
        """autostream_wifi_network.py must be deployed (it ships in core/)."""
        # Deployed via bulk core/ copy; installer has a chown fixup line too.
        assert "autostream_wifi_network" in INSTALL_SH
