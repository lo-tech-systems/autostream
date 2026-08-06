"""Unneeded-system-services trim — installer-level tests.

Scope: remove_unneeded_system_services() in autostream_install.sh, which on
every fresh install and update removes modemmanager and udisks2 (no modem
hardware, no removable-storage workflow on this appliance) and disables
cloud-init's per-boot run via the official /etc/cloud/cloud-init.disabled
kill switch, without uninstalling the cloud-init package.
Static/text-level checks plus functional bash round-trips (bash -c sourcing
the real function body against stubbed dpkg/apt-get/install), mirroring
tests/test_memory_tuning.py.

Environment-dependent (not run here): real dpkg package state, real apt-get
removal.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "tests"))

from conftest import bash_can_run_script_at_windows_path

bash_capable = pytest.mark.skipif(
    not bash_can_run_script_at_windows_path(),
    reason="bash cannot execute scripts at this path (MSYS2 limitation on Windows)",
)

INSTALL_SH = REPO_ROOT / "autostream_install.sh"


def _src(path: Path = INSTALL_SH) -> str:
    return path.read_text(encoding="utf-8")


def _extract_function(src: str, name: str) -> str:
    """Pull a single top-level bash function's full text (signature through
    its closing brace) out of installer source, so test harnesses run the
    REAL current function body rather than a hand-maintained duplicate that
    can silently drift out of sync with it."""
    m = re.search(re.escape(name) + r"\(\)\s*\{.*?\n\}\n", src, re.S)
    assert m is not None, f"could not locate function {name}() in source"
    return m.group(0)


def _write_dpkg_stub(bin_dir: Path, *, present_pkgs: set[str]) -> None:
    # dpkg -s <pkg>: exit 0 if the package is in present_pkgs, else exit 1
    # (mirrors real dpkg's behaviour for a not-installed / never-known package).
    present = " ".join(sorted(present_pkgs))
    stub = bin_dir / "dpkg"
    stub.write_text(
        f'''#!/bin/bash
printf '%s\\n' "$*" >> "${{DPKG_CALLS_FILE}}"
if [ "$1" = "-s" ]; then
  for p in {present}; do
    if [ "$2" = "$p" ]; then
      exit 0
    fi
  done
  exit 1
fi
exit 0
''',
        encoding="utf-8",
    )
    stub.chmod(0o755)


def _write_apt_get_stub(bin_dir: Path, *, fail_pkgs: set[str] = frozenset()) -> None:
    fail = " ".join(sorted(fail_pkgs))
    stub = bin_dir / "apt-get"
    stub.write_text(
        f'''#!/bin/bash
printf '%s\\n' "$*" >> "${{APT_GET_CALLS_FILE}}"
if [ "$1" = "remove" ]; then
  pkg="$3"  # remove -y <pkg> (installer removes one package per call)
  for f in {fail}; do
    if [ "$pkg" = "$f" ]; then
      exit 1
    fi
  done
fi
exit 0
''',
        encoding="utf-8",
    )
    stub.chmod(0o755)


def _run_remove_unneeded_system_services(
    tmp_path, *, present_pkgs: set[str], fail_pkgs: set[str] = frozenset(),
):
    """Run the real remove_unneeded_system_services() body with stubbed
    dpkg/apt-get/install on PATH, and a fake root under tmp_path so the
    /etc/cloud flag file never touches the real filesystem.

    Returns (result, flag_path, dpkg_calls, apt_get_calls).
    """
    tmp_path.mkdir(parents=True, exist_ok=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _write_dpkg_stub(bin_dir, present_pkgs=present_pkgs)
    _write_apt_get_stub(bin_dir, fail_pkgs=fail_pkgs)

    fake_etc_cloud = tmp_path / "etc" / "cloud"
    flag_path = fake_etc_cloud / "cloud-init.disabled"

    dpkg_calls_file = tmp_path / "dpkg_calls"
    dpkg_calls_file.write_text("", encoding="utf-8")
    apt_get_calls_file = tmp_path / "apt_get_calls"
    apt_get_calls_file.write_text("", encoding="utf-8")

    func_src = _extract_function(_src(), "remove_unneeded_system_services")
    # Redirect the flag file's directory by shadowing mkdir/install's target
    # via a real fake root: use a wrapper that rewrites the hardcoded
    # /etc/cloud path to our tmp_path equivalent.
    func_src_local = func_src.replace(
        "/etc/cloud/cloud-init.disabled", flag_path.as_posix()
    ).replace(
        "mkdir -p /etc/cloud", f"mkdir -p {fake_etc_cloud.as_posix()}"
    )

    script = f'''
set -uo pipefail
info() {{ echo "INFO: $*"; }}
warn() {{ echo "WARN: $*"; }}
error() {{ echo "ERROR: $*" >&2; }}
{func_src_local}
remove_unneeded_system_services
echo "EXIT:$?"
'''
    env = dict(os.environ)
    env["PATH"] = bin_dir.as_posix() + os.pathsep + env.get("PATH", "")
    env["DPKG_CALLS_FILE"] = dpkg_calls_file.as_posix()
    env["APT_GET_CALLS_FILE"] = apt_get_calls_file.as_posix()

    result = subprocess.run(
        ["bash", "-c", script],
        capture_output=True, text=True, timeout=20, env=env,
    )
    dpkg_calls = dpkg_calls_file.read_text(encoding="utf-8").splitlines()
    apt_get_calls = apt_get_calls_file.read_text(encoding="utf-8").splitlines()
    return result, flag_path, dpkg_calls, apt_get_calls


# ---------------------------------------------------------------------------
# remove_unneeded_system_services() functional behaviour
# ---------------------------------------------------------------------------

class TestRemoveUnneededSystemServices:
    @bash_capable
    def test_removes_modemmanager_and_udisks2_when_present(self, tmp_path):
        result, _flag, _dpkg_calls, apt_get_calls = _run_remove_unneeded_system_services(
            tmp_path, present_pkgs={"modemmanager", "udisks2"},
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "EXIT:0" in result.stdout
        assert any(c == "remove -y modemmanager" for c in apt_get_calls), apt_get_calls
        assert any(c == "remove -y udisks2" for c in apt_get_calls), apt_get_calls

    @bash_capable
    def test_skips_apt_remove_when_packages_already_absent(self, tmp_path):
        result, _flag, dpkg_calls, apt_get_calls = _run_remove_unneeded_system_services(
            tmp_path, present_pkgs=set(),
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "EXIT:0" in result.stdout
        assert any(c == "-s modemmanager" for c in dpkg_calls), dpkg_calls
        assert any(c == "-s udisks2" for c in dpkg_calls), dpkg_calls
        assert not any(c.startswith("remove") for c in apt_get_calls), apt_get_calls

    @bash_capable
    def test_apt_remove_failure_warns_and_still_returns_zero(self, tmp_path):
        result, _flag, _dpkg_calls, _apt_get_calls = _run_remove_unneeded_system_services(
            tmp_path, present_pkgs={"modemmanager", "udisks2"}, fail_pkgs={"modemmanager"},
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "EXIT:0" in result.stdout
        assert "WARN:" in result.stdout

    @bash_capable
    def test_creates_cloud_init_disabled_flag_when_cloud_init_present(self, tmp_path):
        # Functional round-trip: verifies the flag file is created with the
        # right content and location. Ownership/mode verification requires
        # real root privilege (install -o root -g root warns-and-continues
        # rather than aborting under an unprivileged test runner, mirroring
        # tune_memory_behaviour's best-effort drop-in install), so mode/owner
        # is checked at the source level below instead.
        result, flag_path, _dpkg_calls, _apt_get_calls = _run_remove_unneeded_system_services(
            tmp_path, present_pkgs={"cloud-init"},
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "EXIT:0" in result.stdout
        assert flag_path.exists()
        assert flag_path.read_text(encoding="utf-8") == ""

    @bash_capable
    def test_skips_cloud_init_flag_when_cloud_init_absent(self, tmp_path):
        result, flag_path, _dpkg_calls, _apt_get_calls = _run_remove_unneeded_system_services(
            tmp_path, present_pkgs=set(),
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert not flag_path.exists()

    @bash_capable
    def test_idempotent_rerun_on_already_clean_box(self, tmp_path):
        # First run: everything present.
        result1, flag1, _dc1, _ac1 = _run_remove_unneeded_system_services(
            tmp_path / "run1", present_pkgs={"modemmanager", "udisks2", "cloud-init"},
        )
        assert result1.returncode == 0, result1.stdout + result1.stderr
        assert flag1.exists()

        # Second run against an already-clean box (packages gone, flag
        # already present via cloud-init still installed): must still
        # succeed and remain a no-op for the apt removals.
        result2, flag2, _dc2, apt_get_calls2 = _run_remove_unneeded_system_services(
            tmp_path / "run2", present_pkgs={"cloud-init"},
        )
        assert result2.returncode == 0, result2.stdout + result2.stderr
        assert "EXIT:0" in result2.stdout
        assert not any(c.startswith("remove") for c in apt_get_calls2), apt_get_calls2
        assert flag2.exists()


# ---------------------------------------------------------------------------
# Wiring into configure_phase() / run_install() / run_update()
# ---------------------------------------------------------------------------

class TestConfigurePhaseWiring:
    def _src(self) -> str:
        return _src()

    def test_remove_unneeded_system_services_function_present(self):
        assert "remove_unneeded_system_services()" in self._src()

    def test_configure_phase_calls_remove_unneeded_system_services(self):
        src = self._src()
        m = re.search(r"^configure_phase\(\)\s*\{.*?\n\}\n", src, re.S | re.M)
        assert m is not None
        assert "remove_unneeded_system_services" in m.group(0)

    def test_run_install_reaches_it_via_configure_phase(self):
        src = self._src()
        m = re.search(r"^run_install\(\)\s*\{.*?\n\}\n", src, re.S | re.M)
        assert m is not None
        assert "configure_phase" in m.group(0), (
            "run_install must call configure_phase, the shared phase that "
            "carries remove_unneeded_system_services"
        )

    def test_run_update_reaches_it_via_configure_phase(self):
        src = self._src()
        m = re.search(r"^run_update\(\)\s*\{.*?\n\}\n", src, re.S | re.M)
        assert m is not None
        assert "configure_phase" in m.group(0), (
            "run_update must call configure_phase, the shared phase that "
            "carries remove_unneeded_system_services"
        )

    def test_apt_remove_guarded_by_dpkg_presence_check(self):
        func_src = _extract_function(self._src(), "remove_unneeded_system_services")
        assert "dpkg -s" in func_src
        assert "apt-get remove -y" in func_src
        assert "DEBIAN_FRONTEND=noninteractive" in func_src

    def test_cloud_init_flag_path_matches_official_kill_switch(self):
        func_src = _extract_function(self._src(), "remove_unneeded_system_services")
        assert "/etc/cloud/cloud-init.disabled" in func_src

    def test_cloud_init_flag_installed_with_mode_0644_root_owned(self):
        # Functional mode/ownership verification requires real root privilege
        # (install -o root -g root is a no-op-with-warning under an
        # unprivileged test runner), so this is a source-level check that the
        # right install invocation is used, mirroring the mode assertions on
        # tune_memory_behaviour's drop-in.
        func_src = _extract_function(self._src(), "remove_unneeded_system_services")
        assert (
            "install -m 0644 -o root -g root /dev/null /etc/cloud/cloud-init.disabled"
            in func_src
        )

    def test_cloud_init_flag_install_failure_is_non_fatal(self):
        func_src = _extract_function(self._src(), "remove_unneeded_system_services")
        assert (
            "install -m 0644 -o root -g root /dev/null /etc/cloud/cloud-init.disabled || \\"
            in func_src
        )

    def test_no_apt_purge_of_cloud_init_package(self):
        func_src = _extract_function(self._src(), "remove_unneeded_system_services")
        assert "cloud-init" not in re.sub(
            r"/etc/cloud/cloud-init\.disabled", "", func_src
        ).replace("dpkg -s cloud-init", "").replace(
            "cloud-init not installed", ""
        ).replace("Disabling cloud-init per-boot runs", ""), (
            "must not apt-get remove/purge the cloud-init package itself"
        )


# ---------------------------------------------------------------------------
# Uninstaller symmetry (or deliberate lack thereof)
# ---------------------------------------------------------------------------

class TestUninstallerAsymmetry:
    def test_uninstaller_does_not_reverse_swap_tuning(self):
        # Baseline: confirms the project convention this feature follows --
        # tune_memory_behaviour()'s swap/zram tuning is one-way and is not
        # undone by the uninstaller.
        uninstall_src = (REPO_ROOT / "autostream_uninstall.sh").read_text(encoding="utf-8")
        assert "swappiness" not in uninstall_src
        assert "zram" not in uninstall_src

    def test_uninstaller_does_not_reverse_system_services_trim(self):
        # Matching that convention: the uninstaller must not reinstall
        # modemmanager/udisks2 or remove the cloud-init.disabled flag.
        uninstall_src = (REPO_ROOT / "autostream_uninstall.sh").read_text(encoding="utf-8")
        assert "modemmanager" not in uninstall_src
        assert "udisks2" not in uninstall_src
        assert "cloud-init.disabled" not in uninstall_src
