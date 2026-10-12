"""Dial and appliance installer hardening: the Wi-Fi handback on uninstall, the
package-list refresh, sudoers validation, interrupted-package recovery, the
uninstaller's guards, re-running the installer over an install, log
preservation, the HD part of the post-update health check, and the package
cache clean.

Functional bash round-trips against a scratch root with fake commands on PATH
wherever the harness allows; the remaining checks read the script text and say
so in their names.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_dial_staged_install import (  # noqa: E402
    Env, RECORDER, REPO_ROOT, bash_capable, HELPERS, INSTALLER,
)

UNINSTALLER = REPO_ROOT / "autostream_dial_uninstall.sh"
APPLIANCE_UNINSTALLER = REPO_ROOT / "autostream_uninstall.sh"
WIFI_RESTORE = REPO_ROOT / "installer" / "lib" / "wifi_restore.sh"


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


# ---------------------------------------------------------------------------
# Wi-Fi handback on uninstall
# ---------------------------------------------------------------------------

# A fake nmcli over three files: NM_LIST (uuid:type lines), NM_MODES
# (uuid mode lines) and NM_FAIL (a uuid whose modify or delete fails).
FAKE_NMCLI = r"""#!/bin/bash
echo "nmcli $*" >> "$TRACE"
case "$*" in
    "-t -f UUID,TYPE connection show") cat "$NM_LIST" ;;
    "-g 802-11-wireless.mode connection show "*)
        grep "^${!#} " "$NM_MODES" | cut -d' ' -f2 ;;
    "connection modify "*|"connection delete "*)
        [[ -n "${NM_FAIL:-}" && "$*" == *"$NM_FAIL"* ]] && exit 1
        exit 0 ;;
esac
exit 0
"""

PROFILES = (
    "aaaa:802-11-wireless\n"
    "bbbb:802-11-wireless\n"
    "cccc:802-11-wireless\n"
    "dddd:802-3-ethernet\n"
)
MODES = "aaaa infrastructure\nbbbb infrastructure\ncccc ap\n"


def _nm(env: Env, *, profiles: str = PROFILES, modes: str = MODES) -> dict:
    env.fake("nmcli", FAKE_NMCLI)
    (env.tmp / "nm-list").write_text(profiles, encoding="utf-8")
    (env.tmp / "nm-modes").write_text(modes, encoding="utf-8")
    return {"NM_LIST": (env.tmp / "nm-list").as_posix(),
            "NM_MODES": (env.tmp / "nm-modes").as_posix()}


RESTORE = (f'info() {{ echo "[INFO] $*"; }}; warn() {{ echo "[WARN] $*"; }}; '
           f'source "{WIFI_RESTORE.as_posix()}"; restore_wifi_profiles')


@bash_capable
class TestWifiHandback:
    def test_client_profiles_get_autoconnect_back_and_their_pins_cleared(self, env):
        extra = _nm(env)
        r = env.run(RESTORE, **extra)
        assert r.returncode == 0, r.stderr
        calls = env.calls()
        for uuid in ("aaaa", "bbbb"):
            assert (f"nmcli connection modify {uuid} connection.autoconnect yes "
                    "802-11-wireless.bssid  connection.interface-name ") in calls

    def test_a_wired_profile_is_never_touched(self, env):
        extra = _nm(env)
        env.run(RESTORE, **extra)
        assert not [c for c in env.calls() if "dddd" in c]

    def test_a_hotspot_profile_is_deleted_not_restored(self, env):
        extra = _nm(env)
        env.run(RESTORE, **extra)
        calls = env.calls()
        assert "nmcli connection delete cccc" in calls
        assert not [c for c in calls if c.startswith("nmcli connection modify cccc")]

    def test_one_failing_profile_does_not_stop_the_rest(self, env):
        extra = _nm(env)
        r = env.run(RESTORE, NM_FAIL="aaaa", **extra)
        assert r.returncode == 0, r.stderr
        assert "Failed to restore Wi-Fi profile aaaa" in r.stdout
        assert any(c.startswith("nmcli connection modify bbbb") for c in env.calls())

    def test_a_dial_without_networkmanager_carries_on(self, env):
        (env.bin / "bash").symlink_to(shutil.which("bash"))
        r = env.run(RESTORE, PATH=env.bin.as_posix())
        assert r.returncode == 0, r.stderr
        assert "nmcli not found" in r.stdout


def _uninstall_sandbox(env: Env, extra_shims: tuple[str, ...] = ()) -> Path:
    """A copy of the uninstaller and the installer tree it sources, with every
    command that would change the machine replaced by a recorder."""
    deploy = env.tmp / "deploy"
    (deploy / "installer").mkdir(parents=True)
    shutil.copytree(REPO_ROOT / "installer" / "dial", deploy / "installer" / "dial")
    shutil.copytree(REPO_ROOT / "installer" / "lib", deploy / "installer" / "lib")
    shutil.copy(UNINSTALLER, deploy / UNINSTALLER.name)
    for name in ("rm", "systemctl", "nginx", "udevadm", "userdel", "update-initramfs",
                 *extra_shims):
        env.fake(name, RECORDER)
    return deploy / UNINSTALLER.name


def _run_uninstaller(env: Env, script: Path, *args: str, **extra: str):
    return subprocess.run(["bash", str(script), *args], capture_output=True, text=True,
                          timeout=60, env=env.env(**extra))


@bash_capable
class TestUninstallerHandsWifiBack:
    def test_profiles_are_restored_before_anything_is_removed(self, env):
        extra = _nm(env)
        script = _uninstall_sandbox(env)
        r = _run_uninstaller(env, script, **extra)
        assert r.returncode == 0, r.stderr
        calls = env.calls()
        first_modify = next(i for i, c in enumerate(calls)
                            if c.startswith("nmcli connection modify"))
        first_rm = next(i for i, c in enumerate(calls) if c.startswith("rm "))
        assert first_modify < first_rm

    def test_profiles_are_restored_after_the_watcher_is_stopped(self, env):
        extra = _nm(env)
        script = _uninstall_sandbox(env)
        _run_uninstaller(env, script, **extra)
        calls = env.calls()
        stop = next(i for i, c in enumerate(calls)
                    if c.startswith("systemctl disable --now autostream_dial "))
        first_modify = next(i for i, c in enumerate(calls)
                            if c.startswith("nmcli connection modify"))
        assert stop < first_modify


class TestApplianceUninstallerSharesTheHandback:
    def test_appliance_uninstaller_sources_the_shared_function(self):
        text = APPLIANCE_UNINSTALLER.read_text(encoding="utf-8")
        assert 'source "${INSTALLER_LIB_DIR}/wifi_restore.sh"' in text
        assert "nmcli connection modify \"${uuid}\"" not in text

    def test_dial_uninstaller_sources_the_same_file(self):
        text = UNINSTALLER.read_text(encoding="utf-8")
        assert 'source "$SCRIPT_DIR/installer/lib/wifi_restore.sh"' in text


# ---------------------------------------------------------------------------
# Package lists are refreshed before a fresh install installs anything
# ---------------------------------------------------------------------------

def _apt_script(env: Env, *, update_rc: int = 0, update_text: str = "") -> None:
    """A fake apt-get that records its calls and fails 'update' on demand."""
    env.fake("apt-get", (
        '#!/bin/bash\necho "apt-get $*" >> "$TRACE"\n'
        f'if [[ "$1" == update ]]; then echo "{update_text}"; exit {update_rc}; fi\n'
    ))


@bash_capable
class TestRefreshPackageLists:
    def test_runs_apt_get_update_once(self, env):
        _apt_script(env)
        r = env.run("refresh_package_lists", update="false")
        assert r.returncode == 0, r.stderr
        assert env.calls() == ["apt-get update"]

    def test_a_failed_refresh_stops_a_set_e_script_with_a_clear_message(self, env):
        _apt_script(env, update_rc=100, update_text="E: Failed to fetch http://x/Packages  404")
        r = env.run("refresh_package_lists\necho carried-on", update="false")
        assert r.returncode == 1
        assert "carried-on" not in r.stdout
        assert "could not refresh the package lists" in r.stderr

    def test_a_lock_held_by_another_process_is_retried_once(self, env):
        env.fake("apt-get", (
            '#!/bin/bash\necho "apt-get $*" >> "$TRACE"\n'
            'n=$(wc -l < "$TRACE")\n'
            'if (( n == 1 )); then echo "E: Could not get lock /var/lib/dpkg/lock-frontend"; exit 100; fi\n'
        ))
        r = env.run("refresh_package_lists", update="false")
        assert r.returncode == 0, r.stderr
        assert [c for c in env.calls() if c.startswith("apt-get")] == ["apt-get update"] * 2

    def test_an_update_refreshes_the_lists_exactly_once(self, env):
        _apt_script(env)
        r = env.run("system_upgrade")
        assert r.returncode == 0, r.stderr
        assert [c for c in env.calls() if c == "apt-get update"] == ["apt-get update"]


def _dry_names(tmp_path: Path, **kw) -> list[str]:
    from test_dial_installer_hd import _dry_run, _names
    r, calls = _dry_run(tmp_path, **kw)
    assert r.returncode == 0, r.stderr
    return _names(calls)


@bash_capable
class TestInstallerRefreshesListsOnAFreshInstall:
    """The real installer script run with every helper replaced by a recorder."""

    def test_fresh_install_refreshes_the_lists_before_the_first_package_step(self, tmp_path):
        names = _dry_names(tmp_path, update=False)
        assert names.count("refresh_package_lists") == 1
        assert names.index("refresh_package_lists") < names.index("install_os_packages")
        assert names.index("show_info_and_prompt") < names.index("refresh_package_lists")

    def test_update_does_not_refresh_the_lists_a_second_time(self, tmp_path):
        names = _dry_names(tmp_path, update=True)
        assert "refresh_package_lists" not in names
        assert names.count("system_upgrade") == 1
