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

import re
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


# ---------------------------------------------------------------------------
# Sudoers files are validated before they are installed
# ---------------------------------------------------------------------------

SUDOERS_LIB = REPO_ROOT / "installer" / "lib" / "sudoers.sh"
APPLIANCE_INSTALLER = REPO_ROOT / "autostream_install.sh"

# A fake visudo that rejects any file containing the word BROKEN.
FAKE_VISUDO = r"""#!/bin/bash
echo "visudo $*" >> "$TRACE"
if grep -q BROKEN "${@: -1}"; then echo "parse error in ${@: -1} near line 1"; exit 1; fi
exit 0
"""


def _sudoers(env: Env, text: str) -> tuple[Path, Path]:
    src = env.tmp / "sudoers-src"
    src.write_text(text, encoding="utf-8")
    dest = env.tmp / "sudoers-dest"
    return src, dest


@bash_capable
class TestInstallSudoersFile:
    def test_a_valid_file_is_installed_with_its_content_and_mode_0440(self, env):
        env.fake("visudo", FAKE_VISUDO)
        src, dest = _sudoers(env, "autostream ALL=(root) NOPASSWD: /bin/true\n")
        r = env.run(f'install_sudoers_file "{src}" "{dest}"', update="false")
        assert r.returncode == 0, r.stderr
        assert dest.read_text(encoding="utf-8") == src.read_text(encoding="utf-8")
        assert oct(dest.stat().st_mode & 0o777) == "0o440"

    def test_visudo_checks_a_temporary_copy_not_the_source_or_the_destination(self, env):
        env.fake("visudo", FAKE_VISUDO)
        src, dest = _sudoers(env, "fine\n")
        env.run(f'install_sudoers_file "{src}" "{dest}"', update="false")
        checked = [c.split()[-1] for c in env.calls() if c.startswith("visudo")]
        assert len(checked) == 1
        assert checked[0] not in (str(src), str(dest))
        assert env.calls()[0].startswith("visudo -cf ")

    def test_an_invalid_file_is_refused_and_the_installed_one_is_left_alone(self, env):
        env.fake("visudo", FAKE_VISUDO)
        src, dest = _sudoers(env, "BROKEN\n")
        dest.write_text("previous good file\n", encoding="utf-8")
        r = env.run(f'install_sudoers_file "{src}" "{dest}"\necho carried-on', update="false")
        assert r.returncode == 1
        assert "carried-on" not in r.stdout
        assert "is not valid sudoers syntax" in r.stderr
        assert "parse error" in r.stdout
        assert dest.read_text(encoding="utf-8") == "previous good file\n"

    def test_an_invalid_file_is_not_created_on_a_fresh_install(self, env):
        env.fake("visudo", FAKE_VISUDO)
        src, dest = _sudoers(env, "BROKEN\n")
        r = env.run(f'install_sudoers_file "{src}" "{dest}"', update="false")
        assert r.returncode == 1
        assert not dest.exists()

    def test_no_temporary_copy_is_left_behind_after_a_refusal(self, env):
        env.fake("visudo", FAKE_VISUDO)
        src, dest = _sudoers(env, "BROKEN\n")
        env.run(f'install_sudoers_file "{src}" "{dest}"', update="false",
                TMPDIR=env.tmp.as_posix())
        assert not [p for p in env.tmp.glob("tmp.*")]

    def test_a_missing_source_file_is_an_error(self, env):
        env.fake("visudo", FAKE_VISUDO)
        r = env.run(f'install_sudoers_file "{env.tmp}/absent" "{env.tmp}/dest"', update="false")
        assert r.returncode == 1
        assert "is missing" in r.stderr

    def test_without_visudo_the_file_is_installed_with_a_warning(self, env):
        for name in ("bash", "install", "mktemp", "rm", "id"):
            (env.bin / name).symlink_to(shutil.which(name))
        src, dest = _sudoers(env, "fine\n")
        r = env.run(f'install_sudoers_file "{src}" "{dest}"', update="false",
                    PATH=env.bin.as_posix())
        assert r.returncode == 0, r.stderr
        assert "visudo not found" in r.stderr
        assert dest.read_text(encoding="utf-8") == "fine\n"


@bash_capable
class TestInstallersUseTheCheckedInstall:
    def test_dial_fresh_install_installs_its_sudoers_through_the_check(self, tmp_path):
        from test_dial_installer_hd import _dry_run
        r, calls = _dry_run(tmp_path, update=False)
        assert r.returncode == 0, r.stderr
        want = [c for c in calls if c.startswith("install_sudoers_file")]
        assert len(want) == 1
        assert want[0].endswith("system/sudoers/autostream_dial /etc/sudoers.d/autostream_dial")

    def test_dial_update_installs_its_sudoers_through_the_check(self, tmp_path):
        from test_dial_installer_hd import _dry_run
        r, calls = _dry_run(tmp_path, update=True)
        assert r.returncode == 0, r.stderr
        assert len([c for c in calls if c.startswith("install_sudoers_file")]) == 1

    def test_dial_installer_text_has_no_unchecked_install_of_the_sudoers_file(self):
        text = INSTALLER.read_text(encoding="utf-8")
        assert "install -m 0440" not in text

    def test_dial_helpers_source_the_shared_library(self):
        text = HELPERS.read_text(encoding="utf-8")
        assert 'source "${BASH_SOURCE[0]%/*}/../lib/sudoers.sh"' in text

    def test_appliance_installer_text_checks_both_files_before_installing_them(self):
        text = APPLIANCE_INSTALLER.read_text(encoding="utf-8")
        assert 'source "${INSTALLER_LIB}/sudoers.sh"' in text
        for name in ("autostream_updater", "autostream_admin"):
            assert re.search(
                r'install_sudoers_file "\$\{AUTOSTREAM_DIR\}/system/sudoers/' + name
                + r'"\s+/etc/sudoers.d/' + name, text)
        assert "install -m 0440 -o root -g root \"${AUTOSTREAM_DIR}/system/sudoers" not in text
        configure = text[text.index("configure_phase() {"):]
        assert configure.index("\n  install_sudoers_file") < configure.index("\n  validate_sudoers\n")


# ---------------------------------------------------------------------------
# An interrupted package run is finished before apt is used
# ---------------------------------------------------------------------------

APT_LIB = REPO_ROOT / "installer" / "lib" / "apt.sh"

# apt-get that refuses with dpkg's interrupted-run error until dpkg --configure -a
# has run, the state a power cut inside an upgrade leaves behind.
FAKE_INTERRUPTED_APT = r"""#!/bin/bash
echo "apt-get $*" >> "$TRACE"
if [[ "$1" == upgrade && ! -e "$RECOVERED" ]]; then
    echo "E: dpkg was interrupted, you must manually run 'dpkg --configure -a' to correct the problem." >&2
    exit 100
fi
exit 0
"""

FAKE_DPKG = r"""#!/bin/bash
echo "dpkg $* frontend=${DEBIAN_FRONTEND:-}" >> "$TRACE"
[[ "$*" == "--configure -a" ]] && touch "$RECOVERED"
exit ${DPKG_RC:-0}
"""


@bash_capable
class TestRecoverInterruptedPackages:
    def test_runs_dpkg_configure_all_non_interactively(self, env):
        env.fake("dpkg", FAKE_DPKG)
        r = env.run("recover_interrupted_packages", RECOVERED=(env.tmp / "rec").as_posix())
        assert r.returncode == 0, r.stderr
        assert env.calls() == ["dpkg --configure -a frontend=noninteractive"]

    def test_a_failed_recovery_warns_and_does_not_stop_the_install(self, env):
        env.fake("dpkg", FAKE_DPKG)
        r = env.run("recover_interrupted_packages\necho carried-on",
                    RECOVERED=(env.tmp / "rec").as_posix(), DPKG_RC="2")
        assert r.returncode == 0, r.stderr
        assert "carried-on" in r.stdout
        assert "dpkg --configure -a did not complete" in r.stderr

    def test_an_update_interrupted_inside_the_upgrade_succeeds_on_the_retry(self, env):
        env.fake("dpkg", FAKE_DPKG)
        env.fake("apt-get", FAKE_INTERRUPTED_APT)
        r = env.run("system_upgrade", RECOVERED=(env.tmp / "rec").as_posix())
        assert r.returncode == 0, r.stderr
        assert (env.tmp / "rec").exists()

    def test_without_the_recovery_the_same_retry_would_fail(self, env):
        env.fake("dpkg", RECORDER)
        env.fake("apt-get", FAKE_INTERRUPTED_APT)
        r = env.run("system_upgrade", RECOVERED=(env.tmp / "rec").as_posix())
        assert r.returncode == 100
        assert "dpkg was interrupted" in r.stdout + r.stderr

    def test_an_update_recovers_before_its_first_apt_command(self, env):
        env.fake("dpkg", FAKE_DPKG)
        env.fake("apt-get", FAKE_INTERRUPTED_APT)
        env.run("system_upgrade", RECOVERED=(env.tmp / "rec").as_posix())
        calls = [c for c in env.calls() if c.startswith(("dpkg", "apt-get"))]
        assert calls[0].startswith("dpkg --configure -a")
        assert calls[1] == "apt-get update"

    def test_a_fresh_install_recovers_before_the_lists_are_refreshed(self, tmp_path):
        names = _dry_names(tmp_path, update=False)
        at = names.index
        assert at("recover_interrupted_packages") < at("refresh_package_lists") \
            < at("install_os_packages")


def _function_text(path: Path, name: str) -> str:
    text = path.read_text(encoding="utf-8")
    start = text.index(f"{name}() {{")
    return text[start: text.index("\n}\n", start) + 3]


@bash_capable
class TestApplianceRecoversInterruptedPackages:
    def test_update_recovers_before_it_refreshes_and_upgrades(self, env):
        env.fake("dpkg", FAKE_DPKG)
        env.fake("apt-get", FAKE_INTERRUPTED_APT)
        func = _function_text(APPLIANCE_INSTALLER, "system_upgrade_phase")
        body = (f'info() {{ :; }}; write_update_result() {{ :; }}; source "{APT_LIB}"\n'
                f'{func}\nsystem_upgrade_phase')
        r = env.run(body, RECOVERED=(env.tmp / "rec").as_posix())
        assert r.returncode == 0, r.stderr
        calls = [c for c in env.calls() if c.startswith(("dpkg", "apt-get"))]
        assert calls[0].startswith("dpkg --configure -a")
        assert calls[1:] == ["apt-get update", "apt-get upgrade -y"]

    def test_install_text_recovers_before_the_first_apt_command(self):
        func = _function_text(APPLIANCE_INSTALLER, "bootstrap_phase")
        assert func.index("recover_interrupted_packages") < func.index("apt-get update")

    def test_installer_sources_the_shared_library(self):
        text = APPLIANCE_INSTALLER.read_text(encoding="utf-8")
        assert 'source "${INSTALLER_LIB}/apt.sh"' in text
