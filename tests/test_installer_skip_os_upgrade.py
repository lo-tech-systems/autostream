"""The installers' --skip-os-upgrade: an update that leaves the installed
system packages as they are, for test builds where the upgrade costs time
and card wear. The package lists are still refreshed, since later steps
install packages from them.

The real functions are run in bash with the apt and network calls stubbed to
record what they were asked to do.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from conftest import bash_can_run_script_at_windows_path  # noqa: E402
from test_low_power_mode import PRELUDE, _function, _installer_run  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = REPO_ROOT / "autostream_install.sh"
DIAL_HELPERS = REPO_ROOT / "installer" / "dial" / "helpers.sh"

bash_capable = pytest.mark.skipif(
    not bash_can_run_script_at_windows_path(),
    reason="bash cannot execute scripts at this path (MSYS2 limitation on Windows)",
)

STUBS = '''
recover_interrupted_packages() { echo "CALL recover"; }
apt_refresh_lists() { echo "CALL refresh"; }
refresh_package_lists() { echo "CALL refresh"; }
network_step() { local IFS=" "; echo "CALL $*"; }
apt_step() { local IFS=" "; echo "CALL $*"; }
apt-get() { local IFS=" "; echo "CALL apt-get $*"; }
network_wait() { echo "CALL network_wait"; }
write_update_result() { :; }
'''


def _run(body: str):
    return subprocess.run(["bash", "-c", f"{PRELUDE}\n{STUBS}\n{body}"],
                          capture_output=True, text=True, timeout=30)


@bash_capable
class TestTheSwitch:
    def test_it_is_off_unless_given(self, tmp_path):
        r, _ = _installer_run(tmp_path, 'SKIP_OS_UPGRADE=0; parse_args --update; echo "SKIP=$SKIP_OS_UPGRADE"')
        assert "SKIP=0" in r.stdout

    def test_it_may_accompany_an_update(self, tmp_path):
        r, _ = _installer_run(tmp_path, 'SKIP_OS_UPGRADE=0; parse_args --update --skip-os-upgrade; echo "SKIP=$SKIP_OS_UPGRADE"')
        assert r.returncode == 0 and "SKIP=1" in r.stdout and "ERROR" not in r.stdout

    def test_it_is_listed_in_the_help(self, tmp_path):
        r, _ = _installer_run(tmp_path, "usage")
        assert "--skip-os-upgrade" in r.stdout


@bash_capable
class TestTheApplianceUpgradePhase:
    PHASE = _function(INSTALLER.read_text(encoding="utf-8"), "system_upgrade_phase")

    def test_by_default_the_packages_are_upgraded(self):
        r = _run(f"SKIP_OS_UPGRADE=0\n{self.PHASE}\nsystem_upgrade_phase")
        assert "CALL refresh" in r.stdout and "apt-get upgrade -y" in r.stdout

    def test_with_the_switch_the_lists_are_refreshed_and_nothing_is_upgraded(self):
        r = _run(f"SKIP_OS_UPGRADE=1\n{self.PHASE}\nsystem_upgrade_phase")
        assert "CALL recover" in r.stdout and "CALL refresh" in r.stdout
        assert "apt-get upgrade" not in r.stdout
        assert "--skip-os-upgrade" in r.stdout


@bash_capable
class TestTheDialUpgrade:
    FN = _function(DIAL_HELPERS.read_text(encoding="utf-8"), "system_upgrade")

    def test_by_default_the_packages_are_upgraded(self):
        r = _run(f"SKIP_OS_UPGRADE=false\n{self.FN}\nsystem_upgrade")
        assert "apt-get upgrade -y" in r.stdout

    def test_with_the_switch_the_lists_are_refreshed_and_nothing_is_upgraded(self):
        r = _run(f"SKIP_OS_UPGRADE=true\n{self.FN}\nsystem_upgrade")
        assert "CALL refresh" in r.stdout and "apt-get upgrade" not in r.stdout

    def test_the_dial_installer_reads_the_switch(self):
        text = (REPO_ROOT / "autostream_dial_install.sh").read_text(encoding="utf-8")
        assert "--skip-os-upgrade) SKIP_OS_UPGRADE=true ;;" in text
