"""The base system tuning the dial installer shares with the appliance
installer: Wi-Fi power saving off, swap behaviour, unneeded packages removed and
the power key ignored; installed on a fresh install and on an update, SPI and
HD alike, and taken back by the dial uninstaller exactly as the appliance
uninstaller takes it back.

Functional bash round-trips against a scratch root with fake commands on PATH,
plus a dry run of the real dial installer with every helper replaced by a
recorder; the checks that read script text say so in their names.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_dial_staged_install import Env, REPO_ROOT, bash_capable, HELPERS, INSTALLER  # noqa: E402

LIB = REPO_ROOT / "installer" / "lib" / "system_tuning.sh"
APT_LIB = REPO_ROOT / "installer" / "lib" / "apt.sh"
SYSTEM = REPO_ROOT / "system"
APPLIANCE_INSTALLER = REPO_ROOT / "autostream_install.sh"
APPLIANCE_UNINSTALLER = REPO_ROOT / "autostream_uninstall.sh"
DIAL_UNINSTALLER = REPO_ROOT / "autostream_dial_uninstall.sh"

TUNING_FILES = [
    "/etc/NetworkManager/dispatcher.d/99-wlan-fix",
    "/etc/NetworkManager/conf.d/wifi-powersave.conf",
    "/etc/systemd/logind.conf.d/90-autostream-ignore-power-key.conf",
]

# dpkg that reports as installed the packages named in PRESENT.
FAKE_DPKG = r"""#!/bin/bash
echo "dpkg $*" >> "$TRACE"
if [[ "$1" == "-s" ]]; then
    for p in ${PRESENT:-}; do [[ "$p" == "$2" ]] && exit 0; done
    exit 1
fi
exit 0
"""

# apt-get that fails to remove the packages named in FAIL.
FAKE_APT = r"""#!/bin/bash
echo "apt-get $*" >> "$TRACE"
for p in ${FAIL:-}; do [[ "$p" == "$3" ]] && exit 1; done
exit 0
"""

SHIM = 'info() { echo "INFO: $*"; }; warn() { echo "WARN: $*" >&2; }\n'


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    e.fake("dpkg", FAKE_DPKG)
    e.fake("apt-get", FAKE_APT)
    e.fake("sysctl", '#!/bin/bash\necho "sysctl $*" >> "$TRACE"\n')
    return e


def _lib(env: Env, body: str, **extra: str):
    return env.run(f'{SHIM}source "{APT_LIB.as_posix()}"\nsource "{LIB.as_posix()}"\n{body}',
                   **extra)


# ---------------------------------------------------------------------------
# Wi-Fi power saving off
# ---------------------------------------------------------------------------

@bash_capable
class TestWifiPowerSaveOff:
    def test_the_dispatcher_and_the_power_save_drop_in_are_installed_with_the_shipped_content(self, env):
        r = _lib(env, f'install_wifi_power_save_off "{SYSTEM.as_posix()}" "{env.root.as_posix()}"')
        assert r.returncode == 0, r.stderr
        nm = env.root / "etc" / "NetworkManager"
        assert (nm / "dispatcher.d" / "99-wlan-fix").read_bytes() == \
            (SYSTEM / "NetworkManager" / "99-wlan-fix").read_bytes()
        assert (nm / "conf.d" / "wifi-powersave.conf").read_bytes() == \
            (SYSTEM / "NetworkManager" / "wifi-powersave.conf").read_bytes()

    @pytest.mark.skipif(sys.platform == "win32", reason="file modes are meaningful on POSIX only")
    def test_the_dispatcher_is_executable_and_the_drop_in_is_not(self, env):
        _lib(env, f'install_wifi_power_save_off "{SYSTEM.as_posix()}" "{env.root.as_posix()}"')
        nm = env.root / "etc" / "NetworkManager"
        assert (nm / "dispatcher.d" / "99-wlan-fix").stat().st_mode & 0o777 == 0o755
        assert (nm / "conf.d" / "wifi-powersave.conf").stat().st_mode & 0o777 == 0o644

    def test_the_mdns_setting_is_not_part_of_it(self, env):
        _lib(env, f'install_wifi_power_save_off "{SYSTEM.as_posix()}" "{env.root.as_posix()}"')
        assert not (env.root / "etc" / "NetworkManager" / "conf.d" / "mdns.conf").exists()

    def test_the_drop_in_turns_power_saving_off_and_the_dispatcher_does_too(self):
        assert "wifi.powersave = 2" in (SYSTEM / "NetworkManager" / "wifi-powersave.conf").read_text(encoding="utf-8")
        assert "power_save off" in (SYSTEM / "NetworkManager" / "99-wlan-fix").read_text(encoding="utf-8")

    def test_running_it_again_replaces_changed_files_and_restarts_nothing(self, env):
        root = env.root.as_posix()
        _lib(env, f'install_wifi_power_save_off "{SYSTEM.as_posix()}" "{root}"')
        conf = env.root / "etc" / "NetworkManager" / "conf.d" / "wifi-powersave.conf"
        conf.write_text("[connection]\nwifi.powersave = 3\n", encoding="utf-8")
        r = _lib(env, f'install_wifi_power_save_off "{SYSTEM.as_posix()}" "{root}"')
        assert r.returncode == 0, r.stderr
        assert "powersave = 2" in conf.read_text(encoding="utf-8")
        assert not [c for c in env.calls() if c.startswith("systemctl")]


# ---------------------------------------------------------------------------
# The power key
# ---------------------------------------------------------------------------

@bash_capable
class TestIgnorePowerKey:
    def _call(self, env: Env):
        return _lib(env, f'ignore_power_key "{SYSTEM.as_posix()}" "{env.root.as_posix()}"')

    def _dest(self, env: Env) -> Path:
        return env.root / "etc/systemd/logind.conf.d/90-autostream-ignore-power-key.conf"

    def test_the_drop_in_is_installed_and_logind_restarted(self, env):
        r = self._call(env)
        assert r.returncode == 0, r.stderr
        assert "HandlePowerKey=ignore" in self._dest(env).read_text(encoding="utf-8")
        assert "systemctl restart systemd-logind" in env.calls()

    def test_an_unchanged_drop_in_does_not_restart_logind_again(self, env):
        self._call(env)
        env.trace.write_text("", encoding="utf-8")
        r = self._call(env)
        assert r.returncode == 0, r.stderr
        assert "systemctl restart systemd-logind" not in env.calls()

    def test_a_changed_drop_in_is_replaced_and_logind_restarted(self, env):
        self._call(env)
        self._dest(env).write_text("[Login]\nHandlePowerKey=poweroff\n", encoding="utf-8")
        env.trace.write_text("", encoding="utf-8")
        self._call(env)
        assert "HandlePowerKey=ignore" in self._dest(env).read_text(encoding="utf-8")
        assert "systemctl restart systemd-logind" in env.calls()

    def test_a_failed_restart_warns_and_carries_on(self, env):
        env.fake("systemctl", '#!/bin/bash\nexit 1\n')
        r = self._call(env)
        assert r.returncode == 0, r.stderr
        assert "systemctl restart systemd-logind failed" in r.stderr
        assert self._dest(env).exists()


# ---------------------------------------------------------------------------
# Unneeded packages and swap behaviour
# ---------------------------------------------------------------------------

@bash_capable
class TestUnneededPackages:
    def test_each_present_package_is_removed_non_interactively(self, env):
        r = _lib(env, "remove_unneeded_packages", PRESENT="modemmanager udisks2")
        assert r.returncode == 0, r.stderr
        calls = env.calls()
        assert "apt-get remove -y modemmanager" in calls
        assert "apt-get remove -y udisks2" in calls

    def test_an_absent_package_is_not_touched(self, env):
        r = _lib(env, "remove_unneeded_packages", PRESENT="udisks2")
        assert r.returncode == 0, r.stderr
        assert "apt-get remove -y modemmanager" not in env.calls()
        assert "apt-get remove -y udisks2" in env.calls()

    def test_a_failed_removal_warns_and_the_next_package_is_still_tried(self, env):
        r = _lib(env, "set -e; remove_unneeded_packages", PRESENT="modemmanager udisks2",
                 FAIL="modemmanager")
        assert r.returncode == 0, r.stderr
        assert "apt-get remove -y udisks2" in env.calls()
        assert "WARN: apt-get remove -y modemmanager failed" in r.stderr


@bash_capable
class TestMemoryTuningOnTheDial:
    def test_without_an_argument_it_uses_the_shared_sysctl_file_and_masks_the_timer(self, env):
        r = _lib(env, 'install() { local a=("$@"); echo "install ${a[*]: -1}" >> "$TRACE"; }\n'
                      "tune_memory_behaviour")
        assert r.returncode == 0, r.stderr
        calls = env.calls()
        assert "systemctl mask --now rpi-zram-writeback.timer" in calls
        assert "install /etc/sysctl.d/90-autostream-swappiness.conf" in calls
        assert "sysctl -p /etc/sysctl.d/90-autostream-swappiness.conf" in calls

    def test_the_file_name_matches_the_one_the_appliance_installer_passes(self):
        text = APPLIANCE_INSTALLER.read_text(encoding="utf-8")
        assert 'SWAPPINESS_SYSCTL_CONF="/etc/sysctl.d/90-autostream-swappiness.conf"' in text
        assert "/etc/sysctl.d/90-autostream-swappiness.conf" in LIB.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# The dial installer calls each step, fresh and update, SPI and HD
# ---------------------------------------------------------------------------

STEPS = ["install_wifi_power_save_off", "tune_memory_behaviour",
         "remove_unneeded_packages", "ignore_power_key"]

CASES = {
    "fresh SPI": dict(update=False),
    "fresh HD": dict(update=False, hd_flag=True),
    "update SPI": dict(update=True),
    "update HD": dict(update=True, detects_hd=True),
}


@bash_capable
class TestDialInstallerAppliesTheTuning:
    @pytest.mark.parametrize("case", list(CASES))
    def test_each_step_runs_exactly_once(self, tmp_path, case):
        from test_dial_installer_hd import _dry_run, _names
        r, calls = _dry_run(tmp_path, **CASES[case])
        assert r.returncode == 0, r.stderr
        names = _names(calls)
        for step in STEPS:
            assert names.count(step) == 1, (case, step)

    @pytest.mark.parametrize("case", list(CASES))
    def test_the_steps_that_take_the_release_directory_get_its_system_folder(self, tmp_path, case):
        from test_dial_installer_hd import _dry_run
        r, calls = _dry_run(tmp_path, **CASES[case])
        assert r.returncode == 0, r.stderr
        system = f"{tmp_path.as_posix()}/deploy/system"
        assert f"install_wifi_power_save_off {system}" in calls
        assert f"ignore_power_key {system}" in calls

    @pytest.mark.parametrize("case", list(CASES))
    def test_the_steps_come_after_the_packages_are_in_place_and_before_the_state_is_saved(self, tmp_path, case):
        from test_dial_installer_hd import _dry_run, _names
        r, calls = _dry_run(tmp_path, **CASES[case])
        names = _names(calls)
        first = min(names.index(s) for s in STEPS)
        last = max(names.index(s) for s in STEPS)
        assert names.index("install_display_hardware_packages") < first
        assert last < names.index("write_install_state")

    @pytest.mark.parametrize("case", list(CASES))
    def test_no_gpu_memory_setting_is_written(self, tmp_path, case):
        from test_dial_installer_hd import _dry_run
        r, calls = _dry_run(tmp_path, **CASES[case])
        assert not [c for c in calls if "gpu_mem=" in c]

    def test_the_installer_defines_the_messages_the_library_uses_before_it_calls_it(self):
        text = INSTALLER.read_text(encoding="utf-8")
        assert text.index("\ninfo() {") < text.index("\ninstall_wifi_power_save_off ")
        assert text.index("\nwarn() {") < text.index("\ninstall_wifi_power_save_off ")

    def test_the_helpers_source_the_shared_library_text_check(self):
        assert 'source "${BASH_SOURCE[0]%/*}/../lib/system_tuning.sh"' in \
            HELPERS.read_text(encoding="utf-8")

    def test_the_update_rollback_covers_every_file_the_tuning_writes(self, env):
        r = env.run("owned_files_list")
        owned = r.stdout.splitlines()
        for path in TUNING_FILES + ["/etc/sysctl.d/90-autostream-swappiness.conf"]:
            assert path in owned, path


# ---------------------------------------------------------------------------
# The dial uninstaller reverts it as the appliance uninstaller does
# ---------------------------------------------------------------------------

@bash_capable
class TestDialUninstallerReverts:
    def _run(self, env: Env):
        from test_dial_installer_hardening import _uninstall_sandbox, _run_uninstaller
        script = _uninstall_sandbox(env)
        r = _run_uninstaller(env, script, "--yes")
        assert r.returncode == 0, r.stderr
        return env.calls()

    def test_the_power_save_files_and_the_power_key_drop_in_are_removed(self, env):
        calls = self._run(env)
        for path in TUNING_FILES:
            assert f"rm -f {path}" in calls, path

    def test_logind_is_restarted_after_its_drop_in_is_removed(self, env):
        calls = self._run(env)
        assert calls.index("rm -f " + TUNING_FILES[2]) < calls.index("systemctl restart systemd-logind")

    def test_the_swap_behaviour_and_the_removed_packages_are_left_alone_as_on_the_appliance(self, env):
        calls = self._run(env)
        assert not [c for c in calls if "swappiness" in c or "zram" in c or c.startswith("apt-get")]
        appliance = APPLIANCE_UNINSTALLER.read_text(encoding="utf-8")
        assert "swappiness" not in appliance and "zram" not in appliance

    def test_the_appliance_uninstaller_removes_the_same_three_files_text_check(self):
        appliance = APPLIANCE_UNINSTALLER.read_text(encoding="utf-8")
        for path in TUNING_FILES:
            assert f"remove_path {path}" in appliance, path
        assert "systemctl restart systemd-logind" in appliance


# ---------------------------------------------------------------------------
# The appliance installer gets the same behaviour through the shared library
# ---------------------------------------------------------------------------

class TestApplianceUsesTheSharedLibrary:
    def _configure(self) -> str:
        text = APPLIANCE_INSTALLER.read_text(encoding="utf-8")
        return text[text.index("configure_phase() {"):]

    def test_text_check_the_appliance_sources_the_library(self):
        assert 'source "${INSTALLER_LIB}/system_tuning.sh"' in \
            APPLIANCE_INSTALLER.read_text(encoding="utf-8")

    def test_text_check_configure_phase_calls_each_shared_step_with_its_release_directory(self):
        configure = self._configure()
        assert 'install_wifi_power_save_off "${AUTOSTREAM_DIR}/system"' in configure
        assert 'ignore_power_key "${AUTOSTREAM_DIR}/system"' in configure
        assert 'tune_memory_behaviour "${SWAPPINESS_SYSCTL_CONF}"' in configure
        assert re.search(r"^remove_unneeded_system_services\(\) \{.*?\n  remove_unneeded_packages\n",
                         APPLIANCE_INSTALLER.read_text(encoding="utf-8"), re.S | re.M)

    def test_text_check_the_appliance_removes_its_old_mdns_setting(self):
        configure = self._configure()
        assert "system/NetworkManager/mdns.conf" not in configure
        assert "rm -f /etc/NetworkManager/conf.d/mdns.conf" in configure
