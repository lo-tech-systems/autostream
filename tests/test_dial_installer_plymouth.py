"""Dial installer boot splash: the table-driven helpers, their idempotence on
fixture boot files, the rebuild-only-on-change rule, and the installer wiring.

Functional bash round-trips against a scratch root (AUTOSTREAM_FS_ROOT) with
fake apt-get, dpkg-query, plymouth-set-default-theme, update-initramfs and
uname on PATH. Nothing here touches the real system.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_dial_installer_hd import HD_ONLY, _dry_run, _names  # noqa: E402
from test_dial_staged_install import (  # noqa: E402
    HELPERS, INSTALLER, RECORDER, REPO_ROOT, Env, _kv, bash_capable, posix_only,
)

KERNEL = "6.18.34+rpt-rpi-v7"
CMDLINE = ("console=serial0,115200 console=tty1 root=PARTUUID=00000000-02 rootfstype=ext4 "
           "fsck.repair=yes rootwait cfg80211.ieee80211_regdom=GB spidev.bufsiz=65536")
TOKENS = ["quiet", "splash", "plymouth.ignore-serial-consoles", "loglevel=3", "logo.nologo",
          "vt.global_cursor_default=0", "consoleblank=0", "systemd.show_status=0",
          "rd.systemd.show_status=0"]
CONFIG = ("# firmware\nauto_initramfs=1\ndtoverlay=vc4-kms-v3d\n[cm4]\notg_mode=1\n"
          "[all]\ndtoverlay=spi1-1cs,cs0_pin=12\n")
MODULES = "# List of modules to load\n# comment\nsnd-bcm2835\n"
THEME_NAME = "autostream-dial"
THEME_FILES = ["autostream-dial.plymouth", "autostream-dial.script", "starting.png",
               "shutting-down.png"]
DROPIN = "[Service]\nExecStart=\nExecStart=-/usr/bin/plymouth quit --retain-splash\n"

FAKE_DPKG = r"""#!/bin/bash
pkg="${@: -1}"
if grep -qx "$pkg" "$DPKG_INSTALLED" 2>/dev/null; then echo -n installed; else echo -n not-installed; exit 1; fi
"""
FAKE_UNAME = '#!/bin/bash\nif [[ "$1" == "-r" ]]; then echo "$FAKE_KERNEL"; else echo Linux; fi\n'
FAKE_SETTHEME = r"""#!/bin/bash
if [[ $# -eq 0 ]]; then cat "$THEME_FILE"; exit 0; fi
echo "plymouth-set-default-theme $*" >> "$TRACE"
echo "$1" > "$THEME_FILE"
"""


class SplashEnv(Env):
    """An Env with a boot partition, theme state and the splash fake commands."""

    def __init__(self, tmp_path: Path, *, cmdline: str = CMDLINE, config: str = CONFIG,
                 modules: str | None = MODULES, default_theme: str = "bgrt"):
        super().__init__(tmp_path)
        self.cmdline = self.put("/boot/firmware/cmdline.txt", cmdline)
        self.config = self.put("/boot/firmware/config.txt", config)
        self.modules = (self.put("/etc/initramfs-tools/modules", modules)
                        if modules is not None else self.root / "etc/initramfs-tools/modules")
        self.conf = self.root / "etc/plymouth/plymouthd.conf"
        self.dropin = self.root / "etc/systemd/system/plymouth-quit.service.d/retain-splash.conf"
        self.theme_dir = self.root / "usr/share/plymouth/themes" / THEME_NAME
        self.plystate = self.state / "plymouth.state"
        self.theme_file = tmp_path / "default-theme"
        self.theme_file.write_text(default_theme + "\n", encoding="utf-8")
        self.dpkg = tmp_path / "dpkg-installed"
        self.dpkg.write_text("", encoding="utf-8")
        self.fake("apt-get", RECORDER)
        self.fake("dpkg-query", FAKE_DPKG)
        self.fake("uname", FAKE_UNAME)
        self.fake("plymouth-set-default-theme", FAKE_SETTHEME)
        self.fake("update-initramfs", RECORDER)

    def env(self, **extra: str) -> dict:
        extra.setdefault("FAKE_KERNEL", KERNEL)
        extra.setdefault("THEME_FILE", self.theme_file.as_posix())
        extra.setdefault("DPKG_INSTALLED", self.dpkg.as_posix())
        return super().env(**extra)

    def step(self, body: str, **extra: str):
        return self.run(body, update="false", **extra)

    def rebuilds(self) -> list[str]:
        return [c for c in self.calls() if c.startswith("update-initramfs")]

    def theme_sets(self) -> list[str]:
        return [c for c in self.calls() if c.startswith("plymouth-set-default-theme")]

    def state_map(self) -> dict:
        return _kv(self.plystate.read_text(encoding="utf-8")) if self.plystate.exists() else {}


def _helpers_text() -> str:
    return HELPERS.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Structure
# ---------------------------------------------------------------------------

class TestStructure:
    def test_package_step_uses_apt_step_with_the_exact_package_set(self):
        text = _helpers_text()
        body = text[text.index("install_plymouth_packages() {"):]
        body = body[:body.index("\n}\n")]
        assert 'apt_step apt-get install -y --no-install-recommends "${PLYMOUTH_PACKAGES[@]}"' in body
        assert "PLYMOUTH_PACKAGES=(plymouth plymouth-themes initramfs-tools)" in text

    def test_tables_match_the_theme_files_and_module_order(self):
        text = _helpers_text()
        files = re.search(r"PLYMOUTH_THEME_FILES=\(([^)]*)\)", text).group(1).split()
        assert files == THEME_FILES
        assert "PLYMOUTH_INITRAMFS_MODULES=(i2c_bcm2835 vc4)" in text
        theme = REPO_ROOT / "system" / "plymouth" / THEME_NAME
        assert all((theme / name).is_file() for name in files)

    def test_owned_files_list_names_no_plymouth_path(self):
        text = _helpers_text()
        body = text[text.index("owned_files_list() {"):]
        body = body[:body.index("\n}\n")]
        code = "\n".join(line for line in body.splitlines()
                         if not line.lstrip().startswith("#"))
        assert "plymouth" not in code.lower()
        assert "initramfs" not in code.lower()


# ---------------------------------------------------------------------------
# Installer wiring, helpers replaced by recorders
# ---------------------------------------------------------------------------

@bash_capable
class TestWiring:
    @pytest.mark.parametrize("update,hd_flag", [(False, False), (False, True), (True, False)],
                             ids=["fresh-spi", "fresh-hd", "update"])
    def test_runs_once_on_every_path_in_order(self, tmp_path, update, hd_flag):
        r, calls = _dry_run(tmp_path, update=update, hd_flag=hd_flag)
        assert r.returncode == 0, r.stderr
        names = _names(calls)
        assert names.count("install_plymouth_packages") == 1
        assert names.count("configure_plymouth") == 1
        at = names.index
        assert (at("install_display_hardware_packages") < at("install_plymouth_packages")
                < at("install_venv_build_packages"))
        assert at("enable_i2c") < at("configure_plymouth") < at("disable_cloud_init")
        if hd_flag:
            assert at("configure_hd_boot") < at("configure_plymouth")

    def test_hd_update_runs_it_once_too(self, tmp_path):
        r, calls = _dry_run(tmp_path, update=True, detects_hd=True)
        assert r.returncode == 0, r.stderr
        names = _names(calls)
        assert names.count("configure_plymouth") == 1
        assert names.index("configure_hd_boot") < names.index("configure_plymouth")

    def test_not_an_hd_only_step(self):
        assert "configure_plymouth" not in HD_ONLY
        assert "install_plymouth_packages" not in HD_ONLY

    def test_installer_calls_each_step_once(self):
        text = INSTALLER.read_text(encoding="utf-8")
        assert len(re.findall(r"^install_plymouth_packages$", text, re.M)) == 1
        assert len(re.findall(r"^configure_plymouth$", text, re.M)) == 1


# ---------------------------------------------------------------------------
# Packages
# ---------------------------------------------------------------------------

@bash_capable
class TestPackages:
    def test_installs_and_records_only_what_was_missing(self, tmp_path):
        env = SplashEnv(tmp_path)
        env.dpkg.write_text("initramfs-tools\n", encoding="utf-8")
        r = env.step("install_plymouth_packages")
        assert r.returncode == 0, r.stderr
        assert env.calls() == [
            "apt-get install -y --no-install-recommends plymouth plymouth-themes initramfs-tools"]
        assert env.state_map()["packages_installed"] == "plymouth plymouth-themes"

    def test_nothing_recorded_when_all_were_present(self, tmp_path):
        env = SplashEnv(tmp_path)
        env.dpkg.write_text("plymouth\nplymouth-themes\ninitramfs-tools\n", encoding="utf-8")
        assert env.step("install_plymouth_packages").returncode == 0
        assert "packages_installed" not in env.state_map()

    def test_a_rerun_keeps_the_earlier_record(self, tmp_path):
        env = SplashEnv(tmp_path)
        env.step("install_plymouth_packages")
        env.dpkg.write_text("plymouth\nplymouth-themes\ninitramfs-tools\n", encoding="utf-8")
        env.step("install_plymouth_packages")
        assert env.state_map()["packages_installed"] == "initramfs-tools plymouth plymouth-themes"


# ---------------------------------------------------------------------------
# initramfs modules
# ---------------------------------------------------------------------------

@bash_capable
class TestModules:
    def _run(self, env):
        return env.step(f'rc=0; ensure_initramfs_modules "{env.modules.as_posix()}" || rc=$?; '
                        'echo "rc=$rc"')

    def test_missing_file_is_created(self, tmp_path):
        env = SplashEnv(tmp_path, modules=None)
        r = self._run(env)
        assert "rc=10" in r.stdout, r.stderr
        assert env.modules.read_text(encoding="utf-8") == "i2c_bcm2835\nvc4\n"
        assert env.state_map()["modules_added"] == "i2c_bcm2835 vc4"

    def test_empty_file(self, tmp_path):
        env = SplashEnv(tmp_path, modules="")
        assert "rc=10" in self._run(env).stdout
        assert env.modules.read_text(encoding="utf-8") == "i2c_bcm2835\nvc4\n"

    def test_vc4_only_gets_i2c_inserted_before_it(self, tmp_path):
        env = SplashEnv(tmp_path, modules="vc4\n")
        assert "rc=10" in self._run(env).stdout
        assert env.modules.read_text(encoding="utf-8") == "i2c_bcm2835\nvc4\n"
        assert env.state_map()["modules_added"] == "i2c_bcm2835"

    def test_wrong_order_is_reordered_without_recording(self, tmp_path):
        env = SplashEnv(tmp_path, modules="vc4\nsnd-bcm2835\ni2c_bcm2835\n")
        assert "rc=10" in self._run(env).stdout
        assert env.modules.read_text(encoding="utf-8") == "snd-bcm2835\ni2c_bcm2835\nvc4\n"
        assert "modules_added" not in env.state_map()

    def test_comments_and_other_modules_are_kept(self, tmp_path):
        env = SplashEnv(tmp_path)
        self._run(env)
        assert env.modules.read_text(encoding="utf-8") == MODULES + "i2c_bcm2835\nvc4\n"

    def test_missing_trailing_newline_is_handled(self, tmp_path):
        env = SplashEnv(tmp_path, modules="snd-bcm2835")
        self._run(env)
        assert env.modules.read_text(encoding="utf-8") == "snd-bcm2835\ni2c_bcm2835\nvc4\n"

    def test_second_run_changes_nothing(self, tmp_path):
        env = SplashEnv(tmp_path)
        self._run(env)
        after = env.modules.read_bytes()
        r = self._run(env)
        assert "rc=0" in r.stdout
        assert env.modules.read_bytes() == after


# ---------------------------------------------------------------------------
# plymouthd.conf
# ---------------------------------------------------------------------------

@bash_capable
class TestDeviceTimeout:
    def _run(self, env):
        return env.step(f'rc=0; set_plymouth_device_timeout "{env.conf.as_posix()}" || rc=$?; '
                        'echo "rc=$rc"')

    def _conf(self, env, text):
        env.conf.parent.mkdir(parents=True, exist_ok=True)
        env.conf.write_text(text, encoding="utf-8")

    def test_no_file_is_created_and_recorded(self, tmp_path):
        env = SplashEnv(tmp_path)
        assert "rc=10" in self._run(env).stdout
        assert env.conf.read_text(encoding="utf-8") == "[Daemon]\nDeviceTimeout=20\n"
        assert env.state_map()["plymouthd_conf"] == "created"

    def test_file_without_daemon_header(self, tmp_path):
        env = SplashEnv(tmp_path)
        self._conf(env, "# defaults\n")
        assert "rc=10" in self._run(env).stdout
        assert env.conf.read_text(encoding="utf-8") == "# defaults\n[Daemon]\nDeviceTimeout=20\n"
        assert env.state_map()["plymouthd_conf"] == "backup"

    def test_line_goes_directly_after_the_header(self, tmp_path):
        env = SplashEnv(tmp_path)
        self._conf(env, "[Daemon]\nTheme=bgrt\nShowDelay=5\n")
        self._run(env)
        assert env.conf.read_text(encoding="utf-8") == (
            "[Daemon]\nDeviceTimeout=20\nTheme=bgrt\nShowDelay=5\n")

    def test_stale_value_is_replaced(self, tmp_path):
        env = SplashEnv(tmp_path)
        self._conf(env, "[Daemon]\nDeviceTimeout=8\nTheme=bgrt\n")
        self._run(env)
        assert env.conf.read_text(encoding="utf-8") == "[Daemon]\nDeviceTimeout=20\nTheme=bgrt\n"

    def test_backup_is_taken_once_and_run_is_idempotent(self, tmp_path):
        env = SplashEnv(tmp_path)
        original = "[Daemon]\nTheme=bgrt\n"
        self._conf(env, original)
        self._run(env)
        backup = env.state / "plymouthd.conf.orig"
        assert backup.read_text(encoding="utf-8") == original
        after = env.conf.read_bytes()
        assert "rc=0" in self._run(env).stdout
        assert env.conf.read_bytes() == after
        assert backup.read_text(encoding="utf-8") == original


# ---------------------------------------------------------------------------
# Kernel command line
# ---------------------------------------------------------------------------

@bash_capable
class TestCmdline:
    def _run(self, env):
        return env.step(f'rc=0; ensure_cmdline_tokens "{env.cmdline.as_posix()}" || rc=$?; '
                        'echo "rc=$rc"')

    @pytest.mark.parametrize("ending", ["", "\n"])
    def test_all_tokens_appended_to_the_single_line(self, tmp_path, ending):
        env = SplashEnv(tmp_path, cmdline=CMDLINE + ending)
        r = self._run(env)
        assert "rc=10" in r.stdout, r.stderr
        assert env.cmdline.read_text(encoding="utf-8") == f"{CMDLINE} {' '.join(TOKENS)}{ending}"
        assert env.state_map()["cmdline_added"].split() == sorted(TOKENS)

    def test_existing_quiet_and_splash_are_not_added_or_recorded(self, tmp_path):
        env = SplashEnv(tmp_path, cmdline=CMDLINE + " quiet splash")
        self._run(env)
        text = env.cmdline.read_text(encoding="utf-8")
        assert text.split().count("quiet") == 1
        assert text.split().count("splash") == 1
        recorded = env.state_map()["cmdline_added"].split()
        assert len(recorded) == 7
        assert "quiet" not in recorded and "splash" not in recorded

    def test_another_value_for_a_key_is_left_alone(self, tmp_path):
        env = SplashEnv(tmp_path, cmdline=CMDLINE + " loglevel=7")
        self._run(env)
        text = env.cmdline.read_text(encoding="utf-8")
        assert "loglevel=7" in text.split()
        assert "loglevel=3" not in text.split()
        assert "loglevel=3" not in env.state_map()["cmdline_added"].split()

    def test_a_longer_token_does_not_count_as_a_bare_one(self, tmp_path):
        env = SplashEnv(tmp_path, cmdline=CMDLINE + " quietly splashing")
        self._run(env)
        assert {"quiet", "splash"} <= set(env.cmdline.read_text(encoding="utf-8").split())

    def test_idempotent(self, tmp_path):
        env = SplashEnv(tmp_path)
        self._run(env)
        after = env.cmdline.read_bytes()
        r = self._run(env)
        assert "rc=0" in r.stdout
        assert env.cmdline.read_bytes() == after
        assert after.count(b"\n") == 0

    def test_missing_file_warns_without_failing(self, tmp_path):
        env = SplashEnv(tmp_path)
        env.cmdline.unlink()
        r = self._run(env)
        assert r.returncode == 0
        assert "rc=0" in r.stdout
        assert "WARNING" in r.stderr


# ---------------------------------------------------------------------------
# config.txt
# ---------------------------------------------------------------------------

@bash_capable
class TestDisableSplash:
    def _run(self, env):
        return env.step(f'rc=0; set_disable_splash "{env.config.as_posix()}" || rc=$?; '
                        'echo "rc=$rc"')

    def test_absent_key_is_appended_under_all_and_recorded(self, tmp_path):
        env = SplashEnv(tmp_path)
        r = self._run(env)
        assert "rc=10" in r.stdout, r.stderr
        assert env.config.read_text(encoding="utf-8") == CONFIG + "disable_splash=1\n"
        assert env.state_map()["config_added"] == "disable_splash=1"

    def test_other_value_in_all_is_rewritten_not_recorded(self, tmp_path):
        env = SplashEnv(tmp_path, config="[all]\ndisable_splash=0\n")
        assert "rc=10" in self._run(env).stdout
        assert env.config.read_text(encoding="utf-8") == "[all]\ndisable_splash=1\n"
        assert "config_added" not in env.state_map()

    def test_a_copy_in_a_conditional_section_does_not_count(self, tmp_path):
        env = SplashEnv(tmp_path, config="[pi4]\ndisable_splash=1\n")
        assert "rc=10" in self._run(env).stdout
        assert env.config.read_text(encoding="utf-8") == (
            "[pi4]\ndisable_splash=1\n[all]\ndisable_splash=1\n")
        assert env.state_map()["config_added"] == "disable_splash=1"

    def test_idempotent(self, tmp_path):
        env = SplashEnv(tmp_path)
        self._run(env)
        after = env.config.read_bytes()
        assert "rc=0" in self._run(env).stdout
        assert env.config.read_bytes() == after


@bash_capable
class TestRemoveBootConfigLine:
    def _run(self, tmp_path, text, key="disable_splash"):
        cfg = tmp_path / "config.txt"
        cfg.write_text(text, encoding="utf-8")
        r = Env(tmp_path).run(f'remove_boot_config_line {key} "{cfg.as_posix()}"')
        assert r.returncode == 0, r.stderr
        return cfg.read_text(encoding="utf-8")

    def test_removes_the_key_from_the_unconditional_part(self, tmp_path):
        assert self._run(tmp_path, "a=1\ndisable_splash=1\nb=2\n") == "a=1\nb=2\n"

    def test_removes_duplicates_and_the_all_section_copy(self, tmp_path):
        text = "disable_splash=0\n[all]\ndisable_splash=1\nx=1\n"
        assert self._run(tmp_path, text) == "[all]\nx=1\n"

    def test_leaves_conditional_sections_alone(self, tmp_path):
        text = "[pi4]\ndisable_splash=1\n"
        assert self._run(tmp_path, text) == text

    def test_missing_file_is_a_no_op(self, tmp_path):
        r = Env(tmp_path).run(f'remove_boot_config_line disable_splash "{tmp_path}/none"')
        assert r.returncode == 0


# ---------------------------------------------------------------------------
# Drop-in and theme files
# ---------------------------------------------------------------------------

@bash_capable
class TestDropin:
    def test_content_exact_and_recorded(self, tmp_path):
        env = SplashEnv(tmp_path)
        r = env.step("rc=0; write_retain_splash_dropin || rc=$?; echo rc=$rc")
        assert "rc=10" in r.stdout, r.stderr
        assert env.dropin.read_text(encoding="utf-8") == DROPIN
        assert env.state_map()["dropin"] == "1"

    def test_idempotent(self, tmp_path):
        env = SplashEnv(tmp_path)
        env.step("write_retain_splash_dropin || true")
        r = env.step("rc=0; write_retain_splash_dropin || rc=$?; echo rc=$rc")
        assert "rc=0" in r.stdout
        assert env.dropin.read_text(encoding="utf-8") == DROPIN

    def test_a_changed_dropin_is_rewritten(self, tmp_path):
        env = SplashEnv(tmp_path)
        env.put("/etc/systemd/system/plymouth-quit.service.d/retain-splash.conf", "old\n")
        r = env.step("rc=0; write_retain_splash_dropin || rc=$?; echo rc=$rc")
        assert "rc=10" in r.stdout
        assert env.dropin.read_text(encoding="utf-8") == DROPIN


@bash_capable
class TestThemeFiles:
    def _install(self, env):
        return env.run("rc=0; install_plymouth_theme || rc=$?; echo rc=$rc", update="false")

    def test_all_four_files_installed_from_the_repository(self, tmp_path):
        env = SplashEnv(tmp_path)
        r = self._install(env)
        assert "rc=10" in r.stdout, r.stderr
        for name in THEME_FILES:
            src = REPO_ROOT / "system/plymouth" / THEME_NAME / name
            assert (env.theme_dir / name).read_bytes() == src.read_bytes()
        assert env.state_map()["theme"] == THEME_NAME

    @posix_only
    def test_files_are_mode_0644(self, tmp_path):
        env = SplashEnv(tmp_path)
        self._install(env)
        for name in THEME_FILES:
            assert (env.theme_dir / name).stat().st_mode & 0o777 == 0o644

    def test_rerun_writes_nothing(self, tmp_path):
        env = SplashEnv(tmp_path)
        self._install(env)
        assert "rc=0" in self._install(env).stdout

    def test_a_changed_script_is_reinstalled(self, tmp_path):
        env = SplashEnv(tmp_path)
        self._install(env)
        script = env.theme_dir / "autostream-dial.script"
        script.write_text("stale\n", encoding="utf-8")
        r = self._install(env)
        assert "rc=10" in r.stdout
        assert script.read_bytes() == (
            REPO_ROOT / "system/plymouth" / THEME_NAME / "autostream-dial.script").read_bytes()


# ---------------------------------------------------------------------------
# Applying the theme
# ---------------------------------------------------------------------------

@bash_capable
class TestApply:
    def test_another_default_runs_both_commands_for_the_running_kernel(self, tmp_path):
        env = SplashEnv(tmp_path, default_theme="bgrt")
        r = env.step("apply_plymouth_theme false")
        assert r.returncode == 0, r.stderr
        assert env.theme_sets() == [f"plymouth-set-default-theme {THEME_NAME}"]
        assert env.rebuilds() == [f"update-initramfs -u -k {KERNEL}"]
        assert env.state_map()["initramfs_kernel"] == KERNEL

    def test_nothing_runs_when_unchanged_and_the_kernel_matches(self, tmp_path):
        env = SplashEnv(tmp_path, default_theme=THEME_NAME)
        env.plystate.write_text(f"initramfs_kernel={KERNEL}\n", encoding="utf-8")
        assert env.step("apply_plymouth_theme false").returncode == 0
        assert env.calls() == []

    def test_changed_flag_alone_rebuilds(self, tmp_path):
        env = SplashEnv(tmp_path, default_theme=THEME_NAME)
        env.plystate.write_text(f"initramfs_kernel={KERNEL}\n", encoding="utf-8")
        env.step("apply_plymouth_theme true")
        assert env.theme_sets() == []
        assert len(env.rebuilds()) == 1

    def test_a_different_recorded_kernel_only_rebuilds(self, tmp_path):
        env = SplashEnv(tmp_path, default_theme=THEME_NAME)
        env.plystate.write_text("initramfs_kernel=6.1.0-old\n", encoding="utf-8")
        env.step("apply_plymouth_theme false")
        assert env.theme_sets() == []
        assert env.rebuilds() == [f"update-initramfs -u -k {KERNEL}"]
        assert env.state_map()["initramfs_kernel"] == KERNEL

    def test_missing_command_warns_and_succeeds(self, tmp_path):
        env = SplashEnv(tmp_path)
        (env.bin / "plymouth-set-default-theme").unlink()
        r = env.step("apply_plymouth_theme true")
        assert r.returncode == 0
        assert "WARNING" in r.stderr
        assert env.rebuilds() == []

    def test_failed_rebuild_warns_and_is_retried_next_time(self, tmp_path):
        env = SplashEnv(tmp_path)
        env.fake("update-initramfs",
                 '#!/bin/bash\necho "update-initramfs $*" >> "$TRACE"\nexit 1\n')
        r = env.step("apply_plymouth_theme true")
        assert r.returncode == 0
        assert "WARNING" in r.stderr
        assert "initramfs_kernel" not in env.state_map()

    def test_the_rebuild_announces_itself(self, tmp_path):
        env = SplashEnv(tmp_path)
        r = env.step('phase() { echo "phase $*"; }; apply_plymouth_theme true')
        assert ("phase configure 82 Configuring the boot splash "
                "(this may take a few minutes)...") in r.stdout


# ---------------------------------------------------------------------------
# The orchestrator
# ---------------------------------------------------------------------------

@bash_capable
class TestConfigure:
    def _configure(self, env):
        return env.run("configure_plymouth", update="false")

    def test_first_run_rebuilds_once_and_second_run_not_at_all(self, tmp_path):
        env = SplashEnv(tmp_path)
        r = self._configure(env)
        assert r.returncode == 0, r.stderr
        assert len(env.rebuilds()) == 1
        assert len(env.theme_sets()) == 1
        env.trace.write_text("", encoding="utf-8")
        files = (env.cmdline, env.config, env.modules, env.conf, env.dropin)
        snapshot = {p: p.read_bytes() for p in files}
        r = self._configure(env)
        assert r.returncode == 0, r.stderr
        assert env.calls() == []
        assert {p: p.read_bytes() for p in files} == snapshot

    def test_the_whole_state_is_written(self, tmp_path):
        env = SplashEnv(tmp_path)
        self._configure(env)
        state = env.state_map()
        assert state["theme"] == THEME_NAME
        assert state["dropin"] == "1"
        assert state["initramfs_kernel"] == KERNEL
        assert state["modules_added"] == "i2c_bcm2835 vc4"
        assert state["config_added"] == "disable_splash=1"
        assert state["plymouthd_conf"] == "created"
        assert len(state["cmdline_added"].split()) == 9

    def test_a_helper_returning_ten_does_not_abort_the_install(self, tmp_path):
        env = SplashEnv(tmp_path)
        r = env.run("set -e; configure_plymouth; echo survived", update="false")
        assert "survived" in r.stdout, r.stderr

    def test_a_later_change_alone_triggers_a_rebuild(self, tmp_path):
        env = SplashEnv(tmp_path)
        self._configure(env)
        env.trace.write_text("", encoding="utf-8")
        env.cmdline.write_text(CMDLINE + "\n", encoding="utf-8")
        self._configure(env)
        assert len(env.rebuilds()) == 1
        assert env.theme_sets() == []

    def test_missing_boot_files_do_not_fail_the_install(self, tmp_path):
        env = SplashEnv(tmp_path)
        env.cmdline.unlink()
        env.config.unlink()
        r = self._configure(env)
        assert r.returncode == 0
        assert "WARNING" in r.stderr
