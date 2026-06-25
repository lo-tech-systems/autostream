"""Regression tests for the logind power-key drop-in.

Verifies that:
- the drop-in file contains HandlePowerKey=ignore;
- the installer deploys it to /etc/systemd/logind.conf.d/;
- the uninstaller removes it.
"""
from __future__ import annotations

from pathlib import Path

REPO_ROOT   = Path(__file__).parent.parent
DROP_IN     = REPO_ROOT / "system" / "logind" / "90-autostream-ignore-power-key.conf"
INSTALLER   = REPO_ROOT / "autostream_install.sh"
UNINSTALLER = REPO_ROOT / "autostream_uninstall.sh"

DEST = "/etc/systemd/logind.conf.d/90-autostream-ignore-power-key.conf"


def test_drop_in_contains_handle_power_key_ignore():
    """The drop-in must set HandlePowerKey=ignore."""
    text = DROP_IN.read_text(encoding="utf-8")
    assert "HandlePowerKey=ignore" in text, (
        f"{DROP_IN.relative_to(REPO_ROOT)} does not contain 'HandlePowerKey=ignore'"
    )


def test_installer_deploys_drop_in():
    """The installer must copy the drop-in to /etc/systemd/logind.conf.d/."""
    text = INSTALLER.read_text(encoding="utf-8")
    assert DEST in text, (
        f"autostream_install.sh does not reference '{DEST}'; "
        "the logind power-key drop-in will not be installed"
    )


def test_uninstaller_removes_drop_in():
    """The uninstaller must remove the drop-in from /etc/systemd/logind.conf.d/."""
    text = UNINSTALLER.read_text(encoding="utf-8")
    assert DEST in text, (
        f"autostream_uninstall.sh does not reference '{DEST}'; "
        "the logind power-key drop-in will not be cleaned up on uninstall"
    )
