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

import io
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_dial_staged_install import (  # noqa: E402
    Env, RECORDER, REPO_ROOT, bash_capable, HELPERS, INSTALLER, posix_only,
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


# id -u answers FAKE_UID so the root check can be exercised without root.
FAKE_ID = r"""#!/bin/bash
if [[ "$1" == "-u" ]]; then echo "${FAKE_UID:-0}"; else exec /usr/bin/id "$@"; fi
"""


def _uninstall_sandbox(env: Env, extra_shims: tuple[str, ...] = (),
                       product: str | None = "autostream-dial") -> Path:
    """A copy of the uninstaller and the installer tree it sources, with every
    command that would change the machine replaced by a recorder, and the
    install-state file naming PRODUCT (none when it is None)."""
    deploy = env.tmp / "deploy"
    (deploy / "installer").mkdir(parents=True)
    shutil.copytree(REPO_ROOT / "installer" / "dial", deploy / "installer" / "dial")
    shutil.copytree(REPO_ROOT / "installer" / "lib", deploy / "installer" / "lib")
    shutil.copy(UNINSTALLER, deploy / UNINSTALLER.name)
    for name in ("rm", "systemctl", "nginx", "udevadm", "userdel", "update-initramfs",
                 *extra_shims):
        env.fake(name, RECORDER)
    env.fake("id", FAKE_ID)
    if product is not None:
        env.install_state.write_text(f"AUTOSTREAM_PRODUCT={product}\n", encoding="utf-8")
    return deploy / UNINSTALLER.name


def _run_uninstaller(env: Env, script: Path, *args: str, **extra: str):
    return subprocess.run(["bash", str(script), *args], capture_output=True, text=True,
                          timeout=60, env=env.env(**extra))


@bash_capable
class TestUninstallerHandsWifiBack:
    def test_profiles_are_restored_before_anything_is_removed(self, env):
        extra = _nm(env)
        script = _uninstall_sandbox(env)
        r = _run_uninstaller(env, script, "--yes", **extra)
        assert r.returncode == 0, r.stderr
        calls = env.calls()
        first_modify = next(i for i, c in enumerate(calls)
                            if c.startswith("nmcli connection modify"))
        first_rm = next(i for i, c in enumerate(calls) if c.startswith("rm "))
        assert first_modify < first_rm

    def test_profiles_are_restored_after_the_watcher_is_stopped(self, env):
        extra = _nm(env)
        script = _uninstall_sandbox(env)
        _run_uninstaller(env, script, "--yes", **extra)
        calls = env.calls()
        stop = next(i for i, c in enumerate(calls)
                    if c == "systemctl disable --now autostream_dial")
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


# ---------------------------------------------------------------------------
# The uninstaller checks what it is about to remove
# ---------------------------------------------------------------------------

def _uid(uid: str) -> dict:
    return {"FAKE_UID": uid}


def _id_shim(env: Env) -> None:
    env.fake("id", FAKE_ID)


@bash_capable
class TestUninstallGuardFunctions:
    def test_a_normal_user_is_refused_with_the_appliance_wording(self, env):
        _id_shim(env)
        r = env.run("require_root_user autostream_dial_uninstall.sh\necho carried-on",
                    **_uid("1000"))
        assert r.returncode == 1
        assert "carried-on" not in r.stdout
        assert ("[ERROR] This script must be run as root "
                "(e.g. sudo ./autostream_dial_uninstall.sh).") in r.stderr

    def test_root_passes(self, env):
        _id_shim(env)
        assert env.run("require_root_user x", **_uid("0")).returncode == 0

    def test_a_dial_install_passes(self, env):
        env.install_state.write_text("AUTOSTREAM_PRODUCT=autostream-dial\n", encoding="utf-8")
        assert env.run("require_dial_install").returncode == 0

    def test_an_appliance_install_is_refused_and_pointed_at_its_own_uninstaller(self, env):
        env.install_state.write_text("AUTOSTREAM_PRODUCT=autostream\n", encoding="utf-8")
        r = env.run("require_dial_install\necho carried-on")
        assert r.returncode == 1
        assert "carried-on" not in r.stdout
        assert "not a dial" in r.stderr
        assert "autostream_uninstall.sh" in r.stderr

    def test_a_box_with_no_install_at_all_is_refused(self, env):
        r = env.run("require_dial_install")
        assert r.returncode == 1
        assert "No autostream dial installation found" in r.stderr

    def test_an_install_that_stopped_before_its_state_file_still_counts_as_a_dial(self, env):
        env.put("etc/autostream/autostream-dial.json", "{}")
        assert env.run("require_dial_install").returncode == 0

    def test_a_started_dial_unit_without_a_state_file_still_counts_as_a_dial(self, env):
        env.put("etc/systemd/system/autostream_dial.service", "[Unit]")
        assert env.run("require_dial_install").returncode == 0

    def test_yes_skips_the_question_even_without_a_terminal(self, env):
        r = env.run("has_tty() { return 1; }; confirm_dial_uninstall true")
        assert r.returncode == 0, r.stderr
        assert "continuing without confirmation" in r.stdout

    def test_no_terminal_and_no_yes_refuses(self, env):
        r = env.run("has_tty() { return 1; }; confirm_dial_uninstall false\necho carried-on")
        assert r.returncode == 1
        assert "carried-on" not in r.stdout
        assert "Interactive confirmation requires a TTY" in r.stderr
        assert "--yes" in r.stderr

    @pytest.mark.parametrize("answer,code", [("y", 0), ("Y", 0), ("n", 1), ("", 1),
                                             ("yes please", 1)])
    def test_the_answer_decides_when_there_is_a_terminal(self, env, answer, code):
        r = env.run('has_tty() { return 0; }; '
                    f'tty_read() {{ printf -v "$2" %s "{answer}"; }}; '
                    "confirm_dial_uninstall false")
        assert r.returncode == code, r.stderr
        if code:
            assert "Aborted by user" in r.stderr


def _changes(env: Env) -> list[str]:
    """Calls the uninstaller made to anything that changes the machine."""
    return [c for c in env.calls() if c.split()[0] in
            ("rm", "systemctl", "userdel", "nginx", "udevadm", "nmcli")]


def _run_detached(env: Env, script: Path, *args: str):
    """Run with no controlling terminal, as under a service or over ssh without -t."""
    return subprocess.run(["bash", str(script), *args], capture_output=True, text=True,
                          timeout=60, env=env.env(), start_new_session=True,
                          stdin=subprocess.DEVNULL)


@bash_capable
class TestUninstallerScript:
    """The real uninstaller run in a sandbox; every command that changes the
    machine is a recorder, so a refusal shows as an empty trace."""

    def test_a_normal_user_changes_nothing(self, env):
        script = _uninstall_sandbox(env)
        r = _run_uninstaller(env, script, "--yes", **_uid("1000"))
        assert r.returncode == 1
        assert "must be run as root" in r.stderr
        assert _changes(env) == []

    def test_an_appliance_install_changes_nothing_even_with_yes(self, env):
        script = _uninstall_sandbox(env, product="autostream")
        r = _run_uninstaller(env, script, "--yes")
        assert r.returncode == 1
        assert "not a dial" in r.stderr
        assert _changes(env) == []

    def test_an_unconfigured_box_changes_nothing(self, env):
        script = _uninstall_sandbox(env, product=None)
        r = _run_uninstaller(env, script, "--yes")
        assert r.returncode == 1
        assert "No autostream dial installation found" in r.stderr
        assert _changes(env) == []

    def test_no_terminal_and_no_yes_changes_nothing(self, env):
        script = _uninstall_sandbox(env)
        r = _run_detached(env, script)
        assert r.returncode == 1
        assert "requires a TTY" in r.stderr
        assert _changes(env) == []

    def test_an_unknown_argument_changes_nothing(self, env):
        script = _uninstall_sandbox(env)
        r = _run_uninstaller(env, script, "--yse")
        assert r.returncode == 2
        assert "Usage:" in r.stderr
        assert _changes(env) == []

    @pytest.mark.parametrize("flag", ["--yes", "-y"])
    def test_yes_removes_the_dial_without_a_terminal(self, env, flag):
        script = _uninstall_sandbox(env)
        r = _run_detached(env, script, flag)
        assert r.returncode == 0, r.stderr
        calls = env.calls()
        assert "rm -rf /opt/autostream" in calls
        assert "rm -rf /var/lib/autostream" in calls
        assert "userdel autostream" in calls

    def test_the_guards_come_before_the_first_change_text_check(self):
        text = UNINSTALLER.read_text(encoding="utf-8")
        first_change = text.index("systemctl disable --now")
        for guard in ("require_root_user", "require_dial_install", "confirm_dial_uninstall"):
            assert text.index(guard) < first_change, guard


def _run_on_a_terminal(argv: list[str], env: dict, answer: bytes) -> tuple[int, str]:
    """Run argv with a controlling terminal and send ANSWER at the prompt."""
    import pty
    import select
    import time

    pid, fd = pty.fork()
    if pid == 0:
        os.execvpe(argv[0], argv, env)
    out = b""
    sent = False
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.5)
        if ready:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
            if not sent and b"(Y/N)" in out:
                os.write(fd, answer)
                sent = True
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status), out.decode("utf-8", "replace")


@bash_capable
@pytest.mark.skipif(sys.platform == "win32", reason="needs a pseudo-terminal")
class TestUninstallerOnATerminal:
    def test_a_no_answer_leaves_the_device_alone(self, env):
        script = _uninstall_sandbox(env)
        code, out = _run_on_a_terminal(["bash", str(script)], env.env(), b"n\n")
        assert code == 1
        assert "Aborted by user" in out
        assert _changes(env) == []

    def test_a_yes_answer_removes_the_dial(self, env):
        script = _uninstall_sandbox(env)
        code, out = _run_on_a_terminal(["bash", str(script)], env.env(), b"y\n")
        assert code == 0, out
        assert "rm -rf /opt/autostream" in env.calls()

    def test_has_tty_is_true_on_a_terminal(self, env):
        code, out = _run_on_a_terminal(
            ["bash", "-c", f'source "{HELPERS}"; has_tty && echo TTY-YES || echo TTY-NO'],
            env.env(), b"")
        assert "TTY-YES" in out


@bash_capable
class TestHasTty:
    def test_has_tty_is_false_without_a_controlling_terminal(self, env):
        r = subprocess.run(
            ["bash", "-c", f'source "{HELPERS}"; has_tty && echo TTY-YES || echo TTY-NO'],
            capture_output=True, text=True, timeout=30, env=env.env(),
            start_new_session=True, stdin=subprocess.DEVNULL)
        assert r.stdout.strip() == "TTY-NO", r.stderr
        assert r.stderr == ""


# ---------------------------------------------------------------------------
# The installer run over an existing install keeps the dial's settings
# ---------------------------------------------------------------------------

SPI_HW = {"clk_gpio": 5, "dt_gpio": 6, "sw_gpio": 7, "led_gpio": None, "port": 7842,
          "uuid": "oldoldoldoldoldoldo",
          "display": {"fitted": True, "screen_type": "ili9341", "rotate": True}}
HD_HW = {"clk_gpio": 17, "dt_gpio": 27, "sw_gpio": 22, "led_gpio": None, "port": 7842,
         "uuid": "oldoldoldoldoldoldo",
         "display": {"fitted": True, "screen_type": "hd_kiosk", "touch_type": "none",
                     "brightness": 40}}
OWNER_SETTINGS = {"step_percent": 5, "name": "Lounge", "pin": "4321", "auto_update": True,
                  "update_channel": "dev", "sd_health_monitoring": True}
NEW_UUID = "0123456789abcdef0123"


def _real_python3(env: Env) -> None:
    (env.bin / "python3").unlink()
    for name in ("chown", "chmod"):
        env.fake(name, RECORDER)


def _hw_path(env: Env) -> Path:
    return env.root / "etc" / "autostream" / "autostream-dial.json"


def _settings_path(env: Env) -> Path:
    return env.state / "dial-settings.json"


def _put_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# The fresh-install sequence in the installer, for the part that decides and
# writes the dial's identity, settings and display profile.
REINSTALL_STEPS = (
    "detect_existing_dial_install\n"
    "if $REINSTALL; then detect_hd_install; fi\n"
    "write_dial_hw_config " + NEW_UUID + "\n"
    "write_dial_settings\n"
    'if $HD; then write_hd_display_config; fi\n'
    'echo "HD=$HD REINSTALL=$REINSTALL"\n'
)


def _reinstall(env: Env, *, hd_flag: bool = False):
    return env.run(f"HD={'true' if hd_flag else 'false'}\n" + REINSTALL_STEPS, update="false")


@bash_capable
class TestWriteDialSettings:
    def test_an_existing_settings_file_is_left_exactly_as_it_is(self, env):
        _real_python3(env)
        _put_json(_settings_path(env), OWNER_SETTINGS)
        before = _settings_path(env).read_bytes()
        r = env.run("write_dial_settings", update="false")
        assert r.returncode == 0, r.stderr
        assert _settings_path(env).read_bytes() == before

    def test_a_missing_file_gets_the_defaults(self, env):
        _real_python3(env)
        r = env.run("write_dial_settings", update="false")
        assert r.returncode == 0, r.stderr
        assert _load(_settings_path(env)) == {
            "step_percent": 2, "name": "", "pin": "", "auto_update": False,
            "update_channel": "stable", "sd_health_monitoring": False}

    @posix_only
    def test_a_new_file_is_private_to_its_owner(self, env):
        _real_python3(env)
        env.run("write_dial_settings", update="false")
        assert oct(_settings_path(env).stat().st_mode & 0o777) == "0o600"

    def test_a_damaged_file_is_replaced_with_the_defaults(self, env):
        _real_python3(env)
        _settings_path(env).write_text("{not json", encoding="utf-8")
        r = env.run("write_dial_settings", update="false")
        assert r.returncode == 0, r.stderr
        assert _load(_settings_path(env))["name"] == ""

    def test_ownership_is_still_applied_to_a_kept_file(self, env):
        _real_python3(env)
        _put_json(_settings_path(env), OWNER_SETTINGS)
        env.run("write_dial_settings", update="false")
        assert f"chown autostream:autostream {_settings_path(env)}" in env.calls()


@bash_capable
class TestWriteDialHwConfig:
    def test_pins_and_display_profile_are_kept_and_the_identity_refreshed(self, env):
        _real_python3(env)
        _put_json(_hw_path(env), SPI_HW)
        r = env.run(f"write_dial_hw_config {NEW_UUID}", update="false")
        assert r.returncode == 0, r.stderr
        cfg = _load(_hw_path(env))
        assert cfg["uuid"] == NEW_UUID
        assert {k: v for k, v in cfg.items() if k != "uuid"} == \
            {k: v for k, v in SPI_HW.items() if k != "uuid"}

    def test_a_missing_file_gets_the_production_pins(self, env):
        _real_python3(env)
        _hw_path(env).parent.mkdir(parents=True, exist_ok=True)
        env.run(f"write_dial_hw_config {NEW_UUID}", update="false")
        assert _load(_hw_path(env)) == {"clk_gpio": 17, "dt_gpio": 27, "sw_gpio": 22,
                                        "led_gpio": None, "port": 7842, "uuid": NEW_UUID}

    def test_a_damaged_file_is_replaced(self, env):
        _real_python3(env)
        _hw_path(env).parent.mkdir(parents=True, exist_ok=True)
        _hw_path(env).write_text("[1, 2]", encoding="utf-8")
        env.run(f"write_dial_hw_config {NEW_UUID}", update="false")
        assert _load(_hw_path(env))["sw_gpio"] == 22


@bash_capable
class TestWriteHdDisplayConfig:
    def test_a_settings_display_block_from_an_spi_set_up_is_switched_to_hd(self, env):
        _real_python3(env)
        _put_json(_hw_path(env), SPI_HW)
        _put_json(_settings_path(env), {**OWNER_SETTINGS, "display": {
            "fitted": True, "screen_type": "ili9341", "touch_type": "xpt2046", "brightness": 70}})
        r = env.run("write_hd_display_config", update="false")
        assert r.returncode == 0, r.stderr
        display = _load(_settings_path(env))["display"]
        assert display["screen_type"] == "hd_kiosk" and display["touch_type"] == "none"
        assert display["brightness"] == 70
        assert _load(_settings_path(env))["name"] == "Lounge"

    def test_settings_without_a_display_block_gain_none(self, env):
        _real_python3(env)
        _put_json(_hw_path(env), SPI_HW)
        _put_json(_settings_path(env), OWNER_SETTINGS)
        env.run("write_hd_display_config", update="false")
        assert _load(_settings_path(env)) == OWNER_SETTINGS

    def test_other_display_settings_in_the_hardware_file_survive(self, env):
        _real_python3(env)
        _put_json(_hw_path(env), HD_HW)
        env.run("write_hd_display_config", update="false")
        assert _load(_hw_path(env))["display"]["brightness"] == 40

    def test_a_missing_settings_file_is_not_created(self, env):
        _real_python3(env)
        _put_json(_hw_path(env), {"uuid": "abc"})
        env.run("write_hd_display_config", update="false")
        assert not _settings_path(env).exists()


@bash_capable
class TestDetectExistingDialInstall:
    @pytest.mark.parametrize("what", ["state", "hardware", "settings"])
    def test_any_trace_of_a_dial_install_counts(self, env, what):
        if what == "state":
            env.install_state.write_text("AUTOSTREAM_PRODUCT=autostream-dial\n", encoding="utf-8")
        elif what == "hardware":
            env.put("etc/autostream/autostream-dial.json", "{}")
        else:
            env.put("var/lib/autostream/dial-settings.json", "{}")
        r = env.run("detect_existing_dial_install\necho $REINSTALL", update="false")
        assert r.stdout.strip() == "true"

    def test_a_clean_device_is_not_a_reinstall(self, env):
        r = env.run("detect_existing_dial_install\necho $REINSTALL", update="false")
        assert r.stdout.strip() == "false"

    def test_an_appliance_state_file_is_not_a_dial_install(self, env):
        env.install_state.write_text("AUTOSTREAM_PRODUCT=autostream\n", encoding="utf-8")
        r = env.run("detect_existing_dial_install\necho $REINSTALL", update="false")
        assert r.stdout.strip() == "false"


@bash_capable
class TestReinstallSequence:
    """The identity, settings and display-profile steps of the installer run
    in order over each starting point."""

    def _installed(self, env, hw, settings):
        _real_python3(env)
        env.install_state.write_text("AUTOSTREAM_PRODUCT=autostream-dial\n", encoding="utf-8")
        _put_json(_hw_path(env), hw)
        _put_json(_settings_path(env), settings)

    def test_a_plain_run_over_an_spi_dial_keeps_everything_and_stays_spi(self, env):
        self._installed(env, SPI_HW, OWNER_SETTINGS)
        r = _reinstall(env)
        assert r.returncode == 0, r.stderr
        assert "HD=false REINSTALL=true" in r.stdout
        assert _load(_settings_path(env)) == OWNER_SETTINGS
        cfg = _load(_hw_path(env))
        assert cfg["display"] == SPI_HW["display"] and cfg["clk_gpio"] == 5

    def test_a_plain_run_over_an_hd_dial_keeps_it_hd_with_its_settings(self, env):
        self._installed(env, HD_HW, OWNER_SETTINGS)
        r = _reinstall(env)
        assert r.returncode == 0, r.stderr
        assert "HD=true REINSTALL=true" in r.stdout
        assert _load(_settings_path(env)) == OWNER_SETTINGS
        assert _load(_hw_path(env))["display"]["screen_type"] == "hd_kiosk"
        assert _load(_hw_path(env))["display"]["brightness"] == 40

    def test_a_plain_run_over_an_hd_dial_whose_profile_is_unreadable_follows_the_marker(self, env):
        self._installed(env, {"uuid": "x"}, OWNER_SETTINGS)
        (env.state / "hd-kiosk").write_text("", encoding="utf-8")
        r = _reinstall(env)
        assert "HD=true REINSTALL=true" in r.stdout

    def test_hd_over_an_spi_dial_converts_it_and_keeps_name_pin_and_settings(self, env):
        self._installed(env, SPI_HW, {**OWNER_SETTINGS, "display": {
            "fitted": True, "screen_type": "ili9341", "touch_type": "xpt2046"}})
        r = _reinstall(env, hd_flag=True)
        assert r.returncode == 0, r.stderr
        settings = _load(_settings_path(env))
        assert settings["name"] == "Lounge" and settings["pin"] == "4321"
        assert settings["display"]["screen_type"] == "hd_kiosk"
        assert _load(_hw_path(env))["display"]["screen_type"] == "hd_kiosk"
        assert _load(_hw_path(env))["clk_gpio"] == 5

    def test_a_clean_device_gets_the_defaults_as_before(self, env):
        _real_python3(env)
        _hw_path(env).parent.mkdir(parents=True, exist_ok=True)
        r = _reinstall(env)
        assert r.returncode == 0, r.stderr
        assert "HD=false REINSTALL=false" in r.stdout
        assert _load(_settings_path(env))["name"] == ""
        assert _load(_hw_path(env))["uuid"] == NEW_UUID

    def test_a_clean_device_with_the_hd_flag_is_an_hd_dial(self, env):
        _real_python3(env)
        _hw_path(env).parent.mkdir(parents=True, exist_ok=True)
        r = _reinstall(env, hd_flag=True)
        assert r.returncode == 0, r.stderr
        assert _load(_hw_path(env))["display"] == {
            "fitted": True, "screen_type": "hd_kiosk", "touch_type": "none"}


@bash_capable
class TestInstallerReinstallWiring:
    """The real installer script with every helper replaced by a recorder."""

    def test_an_existing_install_is_detected_before_the_prompt_and_hd_follows_the_profile(self, tmp_path):
        from test_dial_installer_hd import _dry_run, _names
        r, calls = _dry_run(tmp_path, update=False, reinstall=True, detects_hd=True)
        assert r.returncode == 0, r.stderr
        names = _names(calls)
        at = names.index
        assert at("detect_existing_dial_install") < at("detect_hd_install") \
            < at("show_info_and_prompt") < at("install_os_packages")
        # An HD dial found on a plain run gets its HD steps.
        for name in ("install_kiosk_packages", "write_hd_display_config", "deploy_kiosk_unit"):
            assert names.count(name) == 1, name
        assert "retire_hd_kiosk" not in names

    def test_a_clean_device_does_not_look_for_an_hd_profile(self, tmp_path):
        from test_dial_installer_hd import _dry_run, _names
        r, calls = _dry_run(tmp_path, update=False)
        names = _names(calls)
        assert names.count("detect_existing_dial_install") == 1
        assert "detect_hd_install" not in names

    def test_an_update_does_not_run_the_reinstall_detection(self, tmp_path):
        from test_dial_installer_hd import _dry_run, _names
        r, calls = _dry_run(tmp_path, update=True)
        assert "detect_existing_dial_install" not in _names(calls)

    def test_the_banner_says_the_settings_are_kept(self, env):
        r = env.run("has_tty() { return 1; }\nREINSTALL=true\nHD=false\nshow_info_and_prompt",
                    update="false")
        assert "An existing dial installation was found" in r.stdout
        assert "name, PIN and settings are kept" in r.stdout

    def test_the_banner_is_unchanged_on_a_clean_device(self, env):
        r = env.run("has_tty() { return 1; }\nREINSTALL=false\nHD=false\nshow_info_and_prompt",
                    update="false")
        assert "existing dial installation" not in r.stdout

    def test_usage_text_states_the_rule(self):
        head = INSTALLER.read_text(encoding="utf-8").split("set -euo pipefail")[0]
        assert "reinstall" in head
        assert "keeps the dial's name, PIN and settings" in head
        assert "--hd over an SPI dial converts it to HD" in head


# ---------------------------------------------------------------------------
# The install log and the dial's logs survive an update
# ---------------------------------------------------------------------------

LOG_NAMES = ("autostream-dial.log", "dial-install.log", "dial-update.log",
             "autostream_wifi_watcher.log")
LOGROTATE = REPO_ROOT / "system" / "logrotate" / "autostream-dial"
DIAL_CGI = REPO_ROOT / "dial" / "cgi" / "download-logs.cgi"

# install(1) as GNU does it over an existing file: the old file is unlinked and
# a new one created, so a descriptor held on the old one writes into the void.
FAKE_INSTALL_REPLACING = r"""#!/bin/bash
echo "install $*" >> "$TRACE"
dest="${@: -1}"
rm -f "$dest"
: > "$dest"
"""


def _logdir(env: Env) -> Path:
    d = env.root / "var" / "log" / "autostream"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _init_dirs(env: Env, **extra):
    env.fake("install", FAKE_INSTALL_REPLACING)
    for name in ("chown", "chmod"):
        env.fake(name, RECORDER)
    return env.run("init_service_dirs", update="true", **extra)


@bash_capable
class TestInitServiceDirsKeepsLogs:
    def test_existing_logs_keep_their_content_and_identity(self, env):
        logs = _logdir(env)
        before = {}
        for name in LOG_NAMES:
            (logs / name).write_text(f"history of {name}\n", encoding="utf-8")
            before[name] = (logs / name).stat().st_ino
        r = _init_dirs(env)
        assert r.returncode == 0, r.stderr
        for name in LOG_NAMES:
            assert (logs / name).read_text(encoding="utf-8") == f"history of {name}\n"
            assert (logs / name).stat().st_ino == before[name], name
        assert not [c for c in env.calls() if c.startswith("install")]

    def test_a_log_a_running_installer_holds_open_keeps_receiving_output(self, env):
        logs = _logdir(env)
        (logs / "dial-install.log").write_text("earlier lines\n", encoding="utf-8")
        env.fake("install", FAKE_INSTALL_REPLACING)
        for name in ("chown", "chmod"):
            env.fake(name, RECORDER)
        r = env.run(f'exec 3>>"{logs}/dial-install.log"\n'
                    "init_service_dirs\n"
                    'echo "written after the directories were set up" >&3\n', update="true")
        assert r.returncode == 0, r.stderr
        text = (logs / "dial-install.log").read_text(encoding="utf-8")
        assert text == "earlier lines\nwritten after the directories were set up\n"

    def test_missing_logs_are_created_with_the_neighbouring_owner_and_mode(self, env):
        _logdir(env)
        r = _init_dirs(env)
        assert r.returncode == 0, r.stderr
        installs = [c for c in env.calls() if c.startswith("install")]
        assert len(installs) == 4
        assert any(c.startswith("install -m 0640 -o autostream -g adm /dev/null")
                   and c.endswith("autostream-dial.log") for c in installs)
        for name in LOG_NAMES[1:]:
            assert any(c.startswith("install -m 0640 -o root -g adm /dev/null")
                       and c.endswith(name) for c in installs), name

    def test_owner_and_mode_of_existing_logs_are_corrected_in_place(self, env):
        logs = _logdir(env)
        for name in LOG_NAMES:
            (logs / name).write_text("x", encoding="utf-8")
        _init_dirs(env)
        calls = env.calls()
        assert f"chown autostream:adm {logs}/autostream-dial.log" in calls
        for name in LOG_NAMES[1:]:
            assert f"chown root:adm {logs}/{name}" in calls, name
        for name in LOG_NAMES:
            assert f"chmod 0640 {logs}/{name}" in calls, name


@bash_capable
class TestPrepareInstallLog:
    def test_creates_the_directory_and_file_when_absent(self, env):
        env.fake("install", FAKE_INSTALL_REPLACING)
        for name in ("chown", "chmod"):
            env.fake(name, RECORDER)
        target = env.tmp / "newdir" / "dial-install.log"
        r = env.run(f'prepare_install_log "{target}"', update="false")
        assert r.returncode == 0, r.stderr
        assert target.exists()
        assert f"install -m 0640 -o root -g adm /dev/null {target}" in env.calls()

    def test_an_existing_log_is_kept(self, env):
        env.fake("install", FAKE_INSTALL_REPLACING)
        for name in ("chown", "chmod"):
            env.fake(name, RECORDER)
        target = env.tmp / "dial-install.log"
        target.write_text("previous run\n", encoding="utf-8")
        r = env.run(f'prepare_install_log "{target}"', update="false")
        assert r.returncode == 0, r.stderr
        assert target.read_text(encoding="utf-8") == "previous run\n"
        assert not [c for c in env.calls() if c.startswith("install")]

    def test_an_unwritable_place_is_reported_to_the_caller(self, env):
        (env.tmp / "afile").write_text("", encoding="utf-8")
        r = env.run(f'prepare_install_log "{env.tmp}/afile/dial-install.log"; echo "rc=$?"',
                    update="false")
        assert "rc=1" in r.stdout or r.returncode != 0


@bash_capable
class TestInstallerLogging:
    """The real installer script with every helper replaced by a recorder."""

    def _log_text(self, tmp_path):
        return (tmp_path / "install.log").read_text(encoding="utf-8")

    def test_an_update_appends_to_the_install_log_and_keeps_what_was_there(self, tmp_path):
        from test_dial_installer_hd import _dry_run
        (tmp_path / "install.log").write_text("=== earlier attempt ===\nit failed here\n",
                                              encoding="utf-8")
        r, _calls = _dry_run(tmp_path, update=True)
        assert r.returncode == 0, r.stderr
        text = self._log_text(tmp_path)
        assert text.startswith("=== earlier attempt ===\nit failed here\n")
        assert "=== autostream dial install" in text

    def test_a_second_update_adds_a_second_section(self, tmp_path):
        from test_dial_installer_hd import _dry_run
        (tmp_path / "first").mkdir()
        (tmp_path / "second").mkdir()
        _dry_run(tmp_path / "first", update=True)
        first = (tmp_path / "first" / "install.log").read_text(encoding="utf-8")
        (tmp_path / "second" / "install.log").write_text(first, encoding="utf-8")
        _dry_run(tmp_path / "second", update=True)
        text = (tmp_path / "second" / "install.log").read_text(encoding="utf-8")
        assert text.startswith(first)
        assert text.count("=== autostream dial install") == 2

    def test_a_fresh_install_writes_the_whole_run_to_the_persistent_log_and_to_home(self, tmp_path):
        from test_dial_installer_hd import _dry_run
        r, _calls = _dry_run(tmp_path, update=False)
        assert r.returncode == 0, r.stderr
        home_log = (tmp_path / "autostream_dial_install.log").read_text(encoding="utf-8")
        assert "=== autostream dial install" in home_log
        persistent = self._log_text(tmp_path)
        assert "=== autostream dial install" in persistent
        assert "autostream dial installation complete." in persistent
        assert persistent == home_log

    def test_a_fresh_install_prepares_the_persistent_log_before_its_first_output(self, tmp_path):
        from test_dial_installer_hd import _dry_run, _names
        r, calls = _dry_run(tmp_path, update=False)
        names = _names(calls)
        assert names.index("prepare_install_log") < names.index("show_info_and_prompt")

    def test_installer_text_no_longer_redirects_the_log_half_way_through(self):
        text = INSTALLER.read_text(encoding="utf-8")
        assert text.count("exec > >(tee") == 1
        assert "tee -a \"${LOGFILES[@]}\"" in text


@bash_capable
class TestApplianceInstallLogIsNotTruncated:
    def test_a_second_run_appends_to_the_log_of_the_first(self, tmp_path):
        log = tmp_path / "autostream_install.log"
        log.write_text("[INFO] first run\n[ERROR] it failed\n", encoding="utf-8")
        script = (
            f'source "{REPO_ROOT}/installer/lib/state_files.sh"\n'
            f'source "{REPO_ROOT}/installer/lib/helpers.sh"\n'
            f'LOGFILE="{log}" SCRIPT_NAME=autostream_install.sh ORIG_USER=pi ORIG_HOME=/home/pi\n'
            "init_logging\n"
        )
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, r.stderr
        text = log.read_text(encoding="utf-8")
        assert text.startswith("[INFO] first run\n[ERROR] it failed\n")
        assert "autostream_install.sh starting at" in text

    def test_a_missing_log_is_created(self, tmp_path):
        log = tmp_path / "sub" / "autostream_install.log"
        script = (
            f'source "{REPO_ROOT}/installer/lib/state_files.sh"\n'
            f'source "{REPO_ROOT}/installer/lib/helpers.sh"\n'
            f'LOGFILE="{log}" SCRIPT_NAME=autostream_install.sh ORIG_USER=pi ORIG_HOME=/home/pi\n'
            "init_logging\n"
        )
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, r.stderr
        assert "starting at" in log.read_text(encoding="utf-8")


def _bundle_names(log_dir: Path) -> set[str]:
    env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
           "REQUEST_METHOD": "POST", "HTTP_X_REQUESTED_WITH": "XMLHttpRequest",
           "HTTP_HOST": "dial.local", "DIAL_LOG_DIR": str(log_dir)}
    r = subprocess.run(["bash", str(DIAL_CGI)], capture_output=True, env=env, timeout=30)
    assert r.returncode == 0, r.stderr
    body = r.stdout[r.stdout.index(b"\r\n\r\n") + 4:]
    return {n for n in zipfile.ZipFile(io.BytesIO(body)).namelist() if not n.endswith("/")}


@bash_capable
@pytest.mark.skipif(shutil.which("zip") is None, reason="zip is not installed")
class TestSupportBundleCarriesTheInstallLogs:
    def test_the_install_and_update_logs_and_their_rotations_are_in_the_dial_bundle(self, tmp_path):
        for base in ("dial-install.log", "dial-update.log"):
            (tmp_path / base).write_text("current\n", encoding="utf-8")
            (tmp_path / f"{base}.1").write_text("yesterday\n", encoding="utf-8")
            (tmp_path / f"{base}.2.gz").write_bytes(b"\x1f\x8b")
        names = _bundle_names(tmp_path)
        for base in ("dial-install.log", "dial-update.log"):
            for suffix in ("", ".1", ".2.gz"):
                assert f"autostream-dial/{base}{suffix}" in names, (base, suffix, sorted(names))


class TestLogrotateCoversTheInstallLogs:
    def _stanza(self, log: str) -> str:
        text = LOGROTATE.read_text(encoding="utf-8")
        for block in re.findall(r"((?:/\S+\n)+)?(/\S+ \{.*?\n\})", text, re.S):
            body = "".join(block)
            if log in body:
                return body
        raise AssertionError(f"{log} is not rotated")

    @pytest.mark.parametrize("log", ["dial-install.log", "dial-update.log"])
    def test_the_log_is_rotated_daily_with_a_bounded_history_and_matching_ownership(self, log):
        body = self._stanza(log)
        assert re.search(r"^\s*daily\s*$", body, re.M)
        assert re.search(r"^\s*rotate\s+14\s*$", body, re.M)
        assert re.search(r"^\s*compress\s*$", body, re.M)
        assert re.search(r"^\s*create\s+0640\s+root\s+adm\s*$", body, re.M)


# ---------------------------------------------------------------------------
# The package cache is cleaned once an install or update is known good
# ---------------------------------------------------------------------------

@bash_capable
class TestCleanPackageCache:
    def test_runs_apt_get_clean_and_nothing_else(self, env):
        env.fake("apt-get", RECORDER)
        r = env.run("clean_package_cache", update="false")
        assert r.returncode == 0, r.stderr
        assert env.calls() == ["apt-get clean"]

    def test_a_failure_is_a_warning_and_does_not_fail_the_install(self, env):
        env.fake("apt-get", '#!/bin/bash\necho "apt-get $*" >> "$TRACE"\nexit 100\n')
        r = env.run("clean_package_cache\necho carried-on", update="false")
        assert r.returncode == 0, r.stderr
        assert "carried-on" in r.stdout
        assert "apt-get clean failed" in r.stderr

    def test_nothing_is_removed_or_purged(self):
        text = APT_LIB.read_text(encoding="utf-8")
        body = text[text.index("clean_package_cache() {"):]
        body = body[:body.index("\n}\n")]
        assert "autoremove" not in body and "purge" not in body


@bash_capable
class TestDialInstallerCleansTheCache:
    def test_a_fresh_install_cleans_once_after_the_services_are_restarted(self, tmp_path):
        from test_dial_installer_hd import _dry_run
        r, calls = _dry_run(tmp_path, update=False)
        assert r.returncode == 0, r.stderr
        assert calls.count("clean_package_cache ") == 1
        restart = calls.index("systemctl restart autostream_dial autostream_dial_wifi_watcher")
        assert restart < calls.index("clean_package_cache ")
        assert calls.index("write_install_state 0123456789abcdef0123") < restart

    def test_a_failed_fresh_install_does_not_clean(self, tmp_path):
        from test_dial_staged_install import _dry_run
        r, calls = _dry_run(tmp_path, update=False, fail="deploy_admin")
        assert r.returncode != 0
        assert "clean_package_cache " not in calls

    def test_an_update_does_not_clean_in_the_installer(self, tmp_path):
        from test_dial_installer_hd import _dry_run
        r, calls = _dry_run(tmp_path, update=True)
        assert r.returncode == 0, r.stderr
        assert "clean_package_cache " not in calls

    def test_the_update_still_trims_obsolete_packages_during_the_upgrade(self, env):
        env.fake("apt-get", RECORDER)
        env.run("system_upgrade")
        assert "apt-get autoclean -y" in env.calls()
        assert "apt-get clean" not in env.calls()


def _stubbed_appliance_run(env: Env, function: str, names: list[str], fail: str | None = None):
    """Run the appliance installer's FUNCTION with each phase it calls replaced
    by a recorder (one of them failing on request) and the real
    clean_package_cache over a fake apt-get."""
    env.fake("apt-get", RECORDER)
    func = _function_text(APPLIANCE_INSTALLER, function)
    stubs = "\n".join(
        f'{n}() {{ echo "{n}" >> "$TRACE"; ' + ("return 1; " if n == fail else "") + "}"
        for n in names)
    body = (f'source "{APT_LIB}"\nORIG_HOME=/\nINSTALL_MODE=install\nPROMPT_REBOOT_ON_EXIT=0\n'
            f'info() {{ :; }}\n{stubs}\n{func}\n{function}\n')
    return env.run(body)


INSTALL_PHASES = ["stop_watchdog_if_ram_monitored", "check_network_manager",
                  "show_warnings_and_prompt", "require_rpi_os_trixie", "handle_pin",
                  "bootstrap_phase", "fetch_phase", "sdmon_phase", "deploy_phase",
                  "configure_phase", "network_state_phase", "services_phase", "save_state",
                  "sdmon_probe_and_enable"]
UPDATE_PHASES = ["prepare_update_state_dir", "adopt_older_update_state",
                 "write_update_result", "engage_update_page", "retire_older_update_state",
                 "stop_watchdog_if_ram_monitored", "check_network_manager", "require_rpi_os_trixie", "update_progress",
                 "stop_services_for_update",
                 "system_upgrade_phase", "ensure_build_deps", "fetch_phase", "sdmon_phase",
                 "deploy_phase", "configure_phase", "services_phase", "save_state",
                 "sdmon_probe_and_enable"]


@bash_capable
class TestApplianceInstallerCleansTheCache:
    def test_a_fresh_install_cleans_after_every_phase_has_succeeded(self, env):
        r = _stubbed_appliance_run(env, "run_install", INSTALL_PHASES)
        assert r.returncode == 0, r.stderr
        calls = env.calls()
        assert calls[-1] == "apt-get clean"
        assert calls.count("apt-get clean") == 1
        assert calls.index("sdmon_probe_and_enable") < calls.index("apt-get clean")

    def test_a_failed_fresh_install_does_not_clean(self, env):
        r = _stubbed_appliance_run(env, "run_install", INSTALL_PHASES, fail="deploy_phase")
        assert r.returncode != 0
        assert "apt-get clean" not in env.calls()

    def test_an_update_cleans_after_the_last_phase_and_after_success_is_recorded(self, env):
        r = _stubbed_appliance_run(env, "run_update", UPDATE_PHASES)
        assert r.returncode == 0, r.stderr
        calls = env.calls()
        assert calls.count("apt-get clean") == 1
        assert calls.index("sdmon_probe_and_enable") < calls.index("apt-get clean")

    def test_a_failed_update_does_not_clean(self, env):
        r = _stubbed_appliance_run(env, "run_update", UPDATE_PHASES, fail="configure_phase")
        assert r.returncode != 0
        assert "apt-get clean" not in env.calls()

    def test_update_text_cleans_between_the_success_record_and_the_reboot(self):
        func = _function_text(APPLIANCE_INSTALLER, "run_update")
        assert func.index('write_update_result "success"') < func.index("clean_package_cache") \
            < func.index("autostream_admin reboot")

    def test_installer_does_not_remove_packages_for_the_cleanup(self):
        for path in (APPLIANCE_INSTALLER, INSTALLER, HELPERS, APT_LIB):
            text = path.read_text(encoding="utf-8")
            assert "autoremove" not in text, path.name


# ---------------------------------------------------------------------------
# An uninstall that meets something it cannot remove still reaches the end
# ---------------------------------------------------------------------------

# rm that removes what is inside the scratch root, fails for the paths named
# in RM_FAIL, and only records anything else (the real system paths).
WORKING_RM = r"""#!/bin/bash
echo "rm $*" >> "$TRACE"
rc=0
for a in "$@"; do
    case "$a" in -*) continue ;; esac
    for bad in ${RM_FAIL:-}; do
        if [[ "$a" == "$bad" ]]; then rc=1; continue 2; fi
    done
    case "$a" in "$AUTOSTREAM_FS_ROOT"*) /bin/rm -rf -- "$a" || rc=1 ;; esac
done
exit $rc
"""

# systemctl that fails for the units named in SYSTEMCTL_FAIL.
FAILING_SYSTEMCTL = r"""#!/bin/bash
echo "systemctl $*" >> "$TRACE"
for a in "$@"; do
    for bad in ${SYSTEMCTL_FAIL:-}; do [[ "$a" == "$bad" ]] && exit 5; done
done
exit 0
"""

# userdel that exits with the code in USERDEL_RC.
FAKE_USERDEL = r"""#!/bin/bash
echo "userdel $*" >> "$TRACE"
exit "${USERDEL_RC:-0}"
"""

SALT = "00112233445566778899aabbccddeeff"


@bash_capable
@posix_only
class TestUninstallerCarriesOnPastAFailure:
    def _sandbox(self, env: Env) -> Path:
        script = _uninstall_sandbox(env)
        env.fake("rm", WORKING_RM)
        env.fake("systemctl", FAILING_SYSTEMCTL)
        env.fake("userdel", FAKE_USERDEL)
        return script

    def test_a_dial_with_a_salt_keeps_it_and_loses_everything_else_in_the_directory(self, env):
        script = self._sandbox(env)
        env.put("etc/autostream/dial-id-salt", SALT + "\n")
        env.put("etc/autostream/autostream-dial.json", "{}")
        env.put("etc/autostream/sub/deeper/file", "x")
        r = _run_uninstaller(env, script, "--yes")
        assert r.returncode == 0, r.stderr
        assert [p.name for p in (env.root / "etc/autostream").iterdir()] == ["dial-id-salt"]
        assert (env.root / "etc/autostream/dial-id-salt").read_text() == SALT + "\n"

    def test_an_entry_named_like_the_salt_further_down_does_not_stop_the_uninstall(self, env):
        script = self._sandbox(env)
        env.put("etc/autostream/dial-id-salt", SALT + "\n")
        env.put("etc/autostream/sub/dial-id-salt", "not the salt")
        r = _run_uninstaller(env, script, "--yes")
        assert r.returncode == 0, r.stderr
        assert [p.name for p in (env.root / "etc/autostream").iterdir()] == ["dial-id-salt"]
        assert "autostream dial uninstalled." in r.stdout
        assert "userdel autostream" in env.calls()

    def test_an_entry_that_cannot_be_removed_is_reported_and_the_rest_still_goes(self, env):
        script = self._sandbox(env)
        env.put("etc/autostream/dial-id-salt", SALT + "\n")
        stuck = env.put("etc/autostream/stuck", "x")
        env.put("etc/autostream/other", "x")
        r = _run_uninstaller(env, script, "--yes", RM_FAIL=str(stuck))
        assert r.returncode == 1
        assert "Could not complete" in r.stdout
        assert "could not be completed" in r.stdout
        assert not (env.root / "etc/autostream/other").exists()
        calls = env.calls()
        assert "rm -rf /var/lib/autostream" in calls
        assert "userdel autostream" in calls and "userdel autostream-kiosk" in calls
        assert "rm -rf /var/lib/autostream-kiosk" in calls
        assert "autostream dial uninstalled." not in r.stdout

    def test_a_directory_that_cannot_be_removed_does_not_stop_the_later_steps(self, env):
        script = self._sandbox(env)
        r = _run_uninstaller(env, script, "--yes", RM_FAIL="/opt/autostream")
        assert r.returncode == 1
        assert "Could not complete: rm -rf /opt/autostream" in r.stdout
        calls = env.calls()
        assert "rm -rf /var/lib/autostream" in calls
        assert "userdel autostream-kiosk" in calls

    def test_an_account_still_in_use_stays_with_a_message_and_the_rest_goes(self, env):
        script = self._sandbox(env)
        r = _run_uninstaller(env, script, "--yes", USERDEL_RC="8")
        assert r.returncode == 1
        assert "Could not remove the autostream account" in r.stdout
        assert "userdel autostream'" in r.stdout
        calls = env.calls()
        assert "userdel autostream" in calls and "userdel autostream-kiosk" in calls
        assert "rm -rf /var/lib/autostream-kiosk" in calls

    def test_an_account_that_is_not_there_is_not_a_problem(self, env):
        script = self._sandbox(env)
        r = _run_uninstaller(env, script, "--yes", USERDEL_RC="6")
        assert r.returncode == 0, r.stderr
        assert "Could not" not in r.stdout
        assert "autostream dial uninstalled." in r.stdout

    def test_a_unit_that_is_not_installed_does_not_keep_the_others_from_being_stopped(self, env):
        script = self._sandbox(env)
        r = _run_uninstaller(env, script, "--yes", SYSTEMCTL_FAIL="autostream_dial_dnsmasq")
        assert r.returncode == 0, r.stderr
        calls = env.calls()
        for unit in ("autostream_dial", "autostream_dial_wifi_watcher",
                     "autostream_dial_updater.timer", "autostream_dial_update_recover",
                     "autostream_storage_guard.timer", "autostream_sdcardhealth.timer",
                     "autostream_sdcardhealth_boot", "autostream_dial_kiosk"):
            assert f"systemctl disable --now {unit}" in calls, unit

    def test_a_failed_daemon_reload_is_reported_and_the_rest_goes(self, env):
        script = self._sandbox(env)
        r = _run_uninstaller(env, script, "--yes", SYSTEMCTL_FAIL="daemon-reload")
        assert r.returncode == 1
        assert "Could not complete: systemctl daemon-reload" in r.stdout
        assert "userdel autostream" in env.calls()

    def test_every_plain_file_removal_is_allowed_to_fail_without_stopping_the_uninstall(
            self, env):
        script = self._sandbox(env)
        paths = re.findall(r"^(?:best_effort )?rm -f +(/\S+)\s*$",
                           script.read_text(encoding="utf-8"), re.M)
        assert len(paths) > 25
        r = _run_uninstaller(env, script, "--yes", RM_FAIL=" ".join(paths))
        assert r.returncode == 1
        for path in paths:
            assert f"Could not complete: rm -f {path}" in r.stdout, path
        calls = env.calls()
        assert "rm -rf /var/lib/autostream" in calls
        assert "userdel autostream" in calls and "userdel autostream-kiosk" in calls
        assert "autostream dial uninstalled." not in r.stdout

    def test_no_plain_file_removal_is_left_to_abort_the_script(self):
        text = UNINSTALLER.read_text(encoding="utf-8")
        bare = [ln for ln in text.splitlines()
                if re.match(r"rm -f ", ln) and "|| true" not in ln]
        assert bare == []

    def test_a_clean_run_exits_zero_with_no_warning(self, env):
        script = self._sandbox(env)
        r = _run_uninstaller(env, script, "--yes")
        assert r.returncode == 0, r.stderr
        assert "[WARN]" not in r.stdout
