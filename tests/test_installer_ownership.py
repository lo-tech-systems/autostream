"""Installer file-ownership hardening tests.

Verifies that:
- autostream_install.sh does not contain a recursive chown of /opt/autostream.
- autostream_dial_install.sh does not contain a recursive chown of /opt/autostream.
- /var/lib/autostream and /etc/autostream ownership is preserved (not touched by the removal).
- Shell syntax checks pass on both installers and installer/dial/helpers.sh.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent

MAIN_INSTALLER = REPO_ROOT / "autostream_install.sh"
DIAL_INSTALLER = REPO_ROOT / "autostream_dial_install.sh"
DIAL_HELPERS   = REPO_ROOT / "installer" / "dial" / "helpers.sh"
MAIN_HELPERS   = REPO_ROOT / "installer" / "lib" / "helpers.sh"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _src(path: Path) -> str:
    return path.read_text(encoding="utf-8")

bash_available = bool(subprocess.run(
    ["bash", "--version"], capture_output=True
).returncode == 0) if sys.platform != "win32" else False


# ---------------------------------------------------------------------------
# No recursive chown of /opt/autostream
# ---------------------------------------------------------------------------

class TestNoRecursiveAppDirChown:
    def test_main_installer_no_recursive_chown_install_dir_to_non_root(self):
        """autostream_install.sh must not recursively chown the app dir to a non-root user.

        chown -R root:root "${INSTALL_DIR}" is required for ownership hardening.
        What must NOT exist is a recursive chown to autostream or any other
        unprivileged account, which would let the service account replace code.
        """
        src = _src(MAIN_INSTALLER)
        # Reject chown -R <non-root-user> on INSTALL_DIR.  Allow root:root.
        pattern = re.compile(
            r'chown\s+-R\s+(?!root:root\b)\S+\s+(?:"\$\{INSTALL_DIR\}"|/opt/autostream)',
        )
        matches = pattern.findall(src)
        assert not matches, (
            f"autostream_install.sh recursively chowns the app dir to a non-root user: {matches!r}\n"
            "Only 'chown -R root:root' is permitted on the application directory"
        )

    def test_dial_installer_no_recursive_chown_opt_autostream(self):
        """autostream_dial_install.sh must not chown -R /opt/autostream."""
        src = _src(DIAL_INSTALLER)
        pattern = re.compile(r'chown\s+-R\s+\S+\s+/opt/autostream')
        matches = pattern.findall(src)
        assert not matches, (
            f"autostream_dial_install.sh contains recursive chown of /opt/autostream: {matches!r}"
        )

    def test_dial_helpers_no_recursive_chown_opt_autostream(self):
        """installer/dial/helpers.sh must not chown -R /opt/autostream."""
        src = _src(DIAL_HELPERS)
        pattern = re.compile(r'chown\s+-R\s+\S+\s+/opt/autostream')
        matches = pattern.findall(src)
        assert not matches, (
            f"installer/dial/helpers.sh contains recursive chown of /opt/autostream: {matches!r}"
        )


# ---------------------------------------------------------------------------
# Application directory is set to root:root
# ---------------------------------------------------------------------------

def _permissions_pass_body(src: str) -> str:
    m = re.search(r'permissions_pass\(\)\s*\{(.+?)\n\}', src, re.DOTALL)
    assert m, "permissions_pass function not found in autostream_install.sh"
    return m.group(1)


class TestAppDirOwnedByRoot:
    def test_main_installer_permissions_pass_recursively_sets_root_ownership(self):
        """permissions_pass must recursively chown the entire INSTALL_DIR tree to root:root.

        A non-recursive chown only secures the top-level directory.  Existing installs
        may have subdirectories (nginx/, images/, monitor/, venv/) still owned by the
        service account; a recursive pass is required to reclaim them all.
        """
        src = _src(MAIN_INSTALLER)
        body = _permissions_pass_body(src)
        pattern = re.compile(
            r'chown\s+-R\s+root:root\s+(?:"\$\{INSTALL_DIR\}"|/opt/autostream)[^/]'
        )
        assert pattern.search(body), (
            "permissions_pass in autostream_install.sh must contain "
            "'chown -R root:root \"${INSTALL_DIR}\"' to reclaim the full application tree"
        )

    def test_main_installer_permissions_pass_no_autostream_dir_chown(self):
        """permissions_pass must not chown INSTALL_DIR to autostream:autostream."""
        src = _src(MAIN_INSTALLER)
        body = _permissions_pass_body(src)
        pattern = re.compile(
            r'chown\s+autostream:autostream\s+"\$\{INSTALL_DIR\}"',
        )
        assert not pattern.search(body), (
            "permissions_pass still contains 'chown autostream:autostream \"${INSTALL_DIR}\"'; "
            "The application directory must be root:root"
        )

    def test_main_installer_no_sudo_autostream_pip(self):
        """pip must not be invoked as sudo -u autostream (venv runs as root installer)."""
        src = _src(MAIN_INSTALLER)
        pattern = re.compile(r'sudo\s+-u\s+autostream\s+.*pip')
        assert not pattern.search(src), (
            "autostream_install.sh invokes pip as 'sudo -u autostream'; "
            "The installer (running as root) must own the venv"
        )

    def test_main_installer_no_pre_venv_autostream_chown(self):
        """The temporary 'chown autostream INSTALL_DIR' before venv creation must be gone."""
        src = _src(MAIN_INSTALLER)
        assert "Setting ownership to enable autostream to manage venv" not in src, (
            "autostream_install.sh still contains the pre-venv 'chown autostream' block; "
            "remove it now that pip runs as the root installer"
        )


# ---------------------------------------------------------------------------
# Preserved: /var/lib/autostream and /etc/autostream ownership
# ---------------------------------------------------------------------------

class TestPreservedStateOwnership:
    def test_main_installer_stamps_dir_still_owned_by_autostream(self):
        """/var/lib/autostream (STAMP_DIR) must remain autostream-owned."""
        src = _src(MAIN_INSTALLER)
        assert 'chown autostream:autostream "${STAMP_DIR}"' in src, (
            "autostream_install.sh must still set STAMP_DIR owner to autostream:autostream "
            "(this is /var/lib/autostream — service state, not program code)"
        )

    def test_main_installer_log_dir_still_owned_by_autostream(self):
        """/var/log/autostream (APP_LOG_DIR) must remain autostream-owned."""
        src = _src(MAIN_INSTALLER)
        assert 'chown -R autostream:autostream "${APP_LOG_DIR}"' in src, (
            "autostream_install.sh must still set APP_LOG_DIR owner to autostream:autostream "
            "(this is /var/log/autostream — service log dir)"
        )

    def test_dial_helpers_state_dir_owned_by_autostream(self):
        """/var/lib/autostream must remain autostream-owned in dial helpers."""
        src = _src(DIAL_HELPERS)
        assert "chown autostream:autostream /var/lib/autostream" in src, (
            "installer/dial/helpers.sh must set /var/lib/autostream to autostream:autostream"
        )

    def test_dial_helpers_etc_autostream_owned_by_root(self):
        """/etc/autostream must remain root-owned in dial helpers."""
        src = _src(DIAL_HELPERS)
        assert "chown root:root /etc/autostream" in src, (
            "installer/dial/helpers.sh must keep /etc/autostream as root:root"
        )


# ---------------------------------------------------------------------------
# Shell syntax checks
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not bash_available, reason="bash not available")
class TestShellSyntax:
    def _check(self, path: Path):
        result = subprocess.run(
            ["bash", "-n", str(path)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, (
            f"bash -n {path.name} failed:\n{result.stderr}"
        )

    def test_main_installer_syntax(self):
        self._check(MAIN_INSTALLER)

    def test_dial_installer_syntax(self):
        self._check(DIAL_INSTALLER)

    def test_dial_helpers_syntax(self):
        self._check(DIAL_HELPERS)

    def test_main_helpers_syntax(self):
        self._check(MAIN_HELPERS)
