"""Dial installer, HD (kiosk browser) dial: the --hd option, the kiosk packages,
account, unit and backlight rule, the shared boot-config helpers, the update
path that keeps an HD dial's kiosk, the uninstaller, and the guarantee that an
SPI dial installs and runs none of it.

Structural checks on the installer text and the shipped unit files (platform
independent), plus functional bash round-trips against a scratch root with fake
commands on PATH, and a dry run of the whole installer with every helper
replaced by a recorder.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from conftest import bash_can_run_script_at_windows_path  # noqa: E402
from test_dial_staged_install import Env, RECORDER, _helper_text  # noqa: E402

bash_capable = pytest.mark.skipif(
    not bash_can_run_script_at_windows_path(),
    reason="bash cannot execute scripts at this path (MSYS2 limitation on Windows)",
)

REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = REPO_ROOT / "autostream_dial_install.sh"
UNINSTALLER = REPO_ROOT / "autostream_dial_uninstall.sh"
HELPERS = REPO_ROOT / "installer" / "dial" / "helpers.sh"
KIOSK_UNIT = REPO_ROOT / "system" / "systemd" / "autostream_dial_kiosk.service"
UDEV_RULE = REPO_ROOT / "system" / "udev" / "99-autostream-backlight.rules"
I2C_MODULES = REPO_ROOT / "system" / "modules-load.d" / "autostream-dial-i2c.conf"

# Every helper that exists for an HD dial only.
HD_ONLY = ("install_kiosk_packages", "create_kiosk_user", "configure_hd_boot",
           "write_hd_display_config", "write_hd_marker", "deploy_kiosk_unit")


def _function_body(text: str, name: str) -> str:
    start = text.index(f"{name}() {{")
    return text[start: text.index("\n}\n", start)]


def _unit_value(key: str) -> str:
    for line in KIOSK_UNIT.read_text(encoding="utf-8").splitlines():
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1]
    raise AssertionError(f"{key}= not found in the kiosk unit")


def _hd_blocks(text: str) -> list[str]:
    """The text of every 'if $HD; then ... fi' block in the installer."""
    return re.findall(r"^\s*if \$HD; then\n(?:.*\n)*?\s*fi\n", text, re.M)


# ---------------------------------------------------------------------------
# Installer text
# ---------------------------------------------------------------------------

class TestInstallerFlag:
    def test_hd_flag_sets_hd_and_defaults_off(self):
        text = INSTALLER.read_text(encoding="utf-8")
        assert re.search(r"^HD=false$", text, re.M)
        assert re.search(r"--hd\) HD=true ;;", text)
        assert re.search(r"--update\) UPDATE=true ;;", text)

    def test_an_update_ignores_the_flag_and_detects_the_profile(self):
        text = INSTALLER.read_text(encoding="utf-8")
        assert "if $UPDATE; then HD=false; fi" in text
        prepare = text[text.index("phase prepare"): text.index("# ---- Fresh-install only")]
        assert "detect_hd_install" in prepare
        assert text.index("detect_hd_install") < text.index("backup_owned_files")
        assert text.index("detect_hd_install") < text.index("install_kiosk_packages")

    def test_hd_steps_run_only_inside_the_hd_gate(self):
        text = INSTALLER.read_text(encoding="utf-8")
        gated = "\n".join(_hd_blocks(text))
        for name in HD_ONLY:
            assert text.count(name) == 1, f"{name} must be called exactly once"
            assert name in gated, f"{name} is called outside an 'if $HD' block"

    def test_non_hd_branch_only_retires_a_former_kiosk(self):
        text = INSTALLER.read_text(encoding="utf-8")
        m = re.search(r"if \$HD; then\n    write_hd_marker\n    deploy_kiosk_unit\nelse\n"
                      r"    retire_hd_kiosk\nfi\n", text)
        assert m is not None

    def test_packages_precede_the_python_phase_and_display_config_follows_settings(self):
        text = INSTALLER.read_text(encoding="utf-8")
        assert text.index("install_kiosk_packages") < text.index("phase python")
        assert text.index("create_kiosk_user") < text.index("phase python")
        assert text.index("write_dial_settings") < text.index("write_hd_display_config")
        assert text.index("write_hd_display_config") < text.index('write_install_state "$DIAL_UUID"')

    def test_unit_is_installed_after_the_dial_units(self):
        text = INSTALLER.read_text(encoding="utf-8")
        assert text.index("systemctl enable autostream_dial ") < text.index("deploy_kiosk_unit")
        assert text.index("write_hd_marker") < text.index("deploy_kiosk_unit")

    def test_banner_gains_one_line_under_hd(self):
        body = _function_body(HELPERS.read_text(encoding="utf-8"), "show_info_and_prompt")
        assert '[[ "${HD:-false}" == true ]] && echo' in body
        assert "kiosk" in body

    def test_pi_model_warning_is_skipped_under_hd(self):
        body = _function_body(HELPERS.read_text(encoding="utf-8"), "check_pi_model")
        assert '[[ "${HD:-false}" == true ]] && return 0' in body


class TestKioskPackages:
    def test_packages_and_apt_step(self):
        body = _function_body(HELPERS.read_text(encoding="utf-8"), "install_kiosk_packages")
        assert "apt_step apt-get install -y cog libgles2 fonts-dejavu-core" in body

    def test_the_old_browser_and_compositor_are_not_installed(self):
        body = _function_body(HELPERS.read_text(encoding="utf-8"), "install_kiosk_packages")
        install = body.split("apt_step", 1)[1]
        for pkg in ("chromium", "cage", "seatd"):
            assert not re.search(rf"\b{pkg}\b", install), pkg

    def test_kiosk_packages_are_installed_nowhere_else(self):
        helpers = HELPERS.read_text(encoding="utf-8")
        for name in ("install_os_packages", "install_image_packages",
                     "install_display_hardware_packages", "install_venv_build_packages"):
            body = _function_body(helpers, name)
            assert "chromium" not in body and "cage" not in body and "seatd" not in body, name
            assert "cog" not in body.split(), name


# ---------------------------------------------------------------------------
# The unit and the udev rule
# ---------------------------------------------------------------------------

class TestKioskUnit:
    def test_exec_start_runs_cog_on_the_drm_platform(self):
        cmd = _unit_value("ExecStart")
        assert cmd == ("/usr/bin/cog --platform=drm --platform-params=renderer=gles "
                       "--bg-color=black --webprocess-failure=restart http://127.0.0.1:7843/")

    def test_the_gles_renderer_is_always_selected(self):
        assert "--platform-params=renderer=gles" in _unit_value("ExecStart").split()

    def test_no_compositor_pointer_or_untested_tuning(self):
        text = KIOSK_UNIT.read_text(encoding="utf-8")
        for word in ("chromium", "Chromium", "cage", "--kiosk", "ozone", "wayland", "Wayland"):
            assert word not in text, word
        assert "COG_PLATFORM_DRM_CURSOR" not in text
        assert "MemoryMax" not in text

    def test_the_only_url_is_the_loopback_page(self):
        cmd = _unit_value("ExecStart")
        assert re.findall(r"https?://\S+", cmd) == ["http://127.0.0.1:7843/"]
        assert cmd.endswith(" http://127.0.0.1:7843/")

    def test_marker_condition_and_start_order(self):
        assert _unit_value("ConditionPathExists") == "/var/lib/autostream/hd-kiosk"
        assert "autostream_dial.service" in _unit_value("After").split()
        assert "plymouth-quit-wait.service" in _unit_value("After").split()
        assert _unit_value("Wants") == "autostream_dial.service"

    def test_runs_unprivileged_and_restarts(self):
        assert _unit_value("User") == "autostream-kiosk"
        assert _unit_value("User") not in ("root", "autostream")
        assert _unit_value("Restart") == "always"
        assert _unit_value("TTYPath") == "/dev/tty1"

    def test_waits_for_the_page_server_before_launch(self):
        pre = _unit_value("ExecStartPre")
        assert "http://127.0.0.1:7843/api/v1/state" in pre

    def test_no_profile_directory_is_named(self):
        assert "user-data-dir" not in _unit_value("ExecStart")
        assert "/var/lib/autostream-kiosk" not in KIOSK_UNIT.read_text(encoding="utf-8")

    def test_installed_to_the_systemd_directory_and_enabled_by_multi_user_target(self):
        assert _unit_value("WantedBy") == "multi-user.target"
        body = _function_body(HELPERS.read_text(encoding="utf-8"), "deploy_kiosk_unit")
        assert "/etc/systemd/system/${KIOSK_UNIT}" in body
        assert 'systemctl enable "${KIOSK_UNIT}"' in body
        assert 'systemctl start' not in body


class TestBacklightRule:
    def test_rule_grants_group_video_write_on_brightness(self):
        text = UDEV_RULE.read_text(encoding="utf-8")
        rules = [ln for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
        assert len(rules) == 1
        assert 'SUBSYSTEM=="backlight"' in rules[0]
        assert "chgrp video /sys/class/backlight/%k/brightness" in rules[0]
        assert "chmod g+w /sys/class/backlight/%k/brightness" in rules[0]

    def test_rule_is_installed_by_the_hd_unit_step_only(self):
        helpers = HELPERS.read_text(encoding="utf-8")
        assert "99-autostream-backlight.rules" in _function_body(helpers, "deploy_kiosk_unit")
        assert "99-autostream-backlight" not in INSTALLER.read_text(encoding="utf-8")


class TestDdcAccess:
    def test_the_module_file_loads_i2c_dev_and_nothing_else(self):
        lines = [ln.strip() for ln in I2C_MODULES.read_text(encoding="utf-8").splitlines()
                 if ln.strip() and not ln.startswith("#")]
        assert lines == ["i2c-dev"]

    def test_the_module_file_is_installed_by_the_hd_unit_step_only(self):
        helpers = HELPERS.read_text(encoding="utf-8")
        body = _function_body(helpers, "deploy_kiosk_unit")
        assert "system/modules-load.d/${I2C_MODULES_FILE}" in body
        assert 'I2C_MODULES_FILE="autostream-dial-i2c.conf"' in helpers
        assert "autostream-dial-i2c" not in INSTALLER.read_text(encoding="utf-8")

    def test_the_group_is_joined_by_the_hd_user_step_only(self):
        body = _function_body(HELPERS.read_text(encoding="utf-8"), "create_kiosk_user")
        assert "getent group i2c" in body
        assert "usermod -aG i2c autostream" in body

    def test_no_package_is_added_for_it(self):
        body = _function_body(HELPERS.read_text(encoding="utf-8"), "install_kiosk_packages")
        assert "i2c" not in body


class TestThemeStylesheet:
    def test_theme_css_goes_to_the_hd_directory_on_every_install(self):
        body = _function_body(HELPERS.read_text(encoding="utf-8"), "install_code_tree")
        assert '"$DEPLOY/nginx/static/theme.css" "${dest}/hd/theme.css"' in body


class TestUninstaller:
    def test_removes_the_kiosk_unit_rule_user_and_data(self):
        text = UNINSTALLER.read_text(encoding="utf-8")
        assert "systemctl disable --now autostream_dial_kiosk" in text
        assert "rm -f /etc/systemd/system/autostream_dial_kiosk.service" in text
        assert "rm -f /etc/udev/rules.d/99-autostream-backlight.rules" in text
        assert "rm -f /etc/modules-load.d/autostream-dial-i2c.conf" in text
        assert "remove_account autostream-kiosk" in text
        assert "rm -rf /var/lib/autostream-kiosk" in text
        assert text.index("autostream_dial_kiosk") < text.index("systemctl daemon-reload")

    def test_no_browser_package_is_purged_and_the_profile_goes_with_the_home(self):
        text = UNINSTALLER.read_text(encoding="utf-8")
        assert not re.search(r"apt(-get)? (purge|remove)", text)
        assert "chromium" not in text
        assert "rm -rf /var/lib/autostream-kiosk" in text

    def test_the_marker_goes_with_the_state_directory(self):
        text = UNINSTALLER.read_text(encoding="utf-8")
        assert "rm -rf /var/lib/autostream\n" in text


# ---------------------------------------------------------------------------
# Syntax and shellcheck
# ---------------------------------------------------------------------------

def _shellcheck_ok() -> bool:
    try:
        return subprocess.run(["shellcheck", "--version"], capture_output=True,
                              timeout=5).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


@bash_capable
class TestShellSyntax:
    @pytest.mark.parametrize("script", [INSTALLER, UNINSTALLER, HELPERS], ids=lambda p: p.name)
    def test_bash_n(self, script):
        r = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr

    @pytest.mark.skipif(not _shellcheck_ok(), reason="shellcheck not installed")
    @pytest.mark.parametrize("script", [INSTALLER, UNINSTALLER, HELPERS], ids=lambda p: p.name)
    def test_shellcheck_errors(self, script):
        r = subprocess.run(["shellcheck", "--severity=error", str(script)],
                           capture_output=True, text=True)
        assert r.returncode == 0, r.stdout


# ---------------------------------------------------------------------------
# Functional helpers
# ---------------------------------------------------------------------------

def _run(env: Env, body: str, *, hd: str | None = None, update: str = "true"):
    pre = f'HD={hd}; ' if hd is not None else ""
    return env.run(pre + body, update=update)


def _real_python(env: Env) -> None:
    (env.bin / "python3").unlink()


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _hw(env: Env) -> Path:
    return env.root / "etc" / "autostream" / "autostream-dial.json"


@bash_capable
class TestBootConfig:
    def _cfg(self, tmp_path: Path, text: str) -> Path:
        cfg = tmp_path / "config.txt"
        cfg.write_text(text, encoding="utf-8")
        return cfg

    def test_line_is_appended_when_absent(self, tmp_path):
        env = Env(tmp_path)
        cfg = self._cfg(tmp_path, "dtparam=audio=on\n")
        r = _run(env, f'write_boot_config_line gpu_mem 128 "{cfg.as_posix()}"')
        assert r.returncode == 0, r.stderr
        assert cfg.read_text(encoding="utf-8") == "dtparam=audio=on\ngpu_mem=128\n"

    def test_existing_value_is_rewritten_and_duplicates_dropped(self, tmp_path):
        env = Env(tmp_path)
        cfg = self._cfg(tmp_path, "gpu_mem=16\ndtparam=audio=on\ngpu_mem=64\n")
        r = _run(env, f'write_boot_config_line gpu_mem 128 "{cfg.as_posix()}"')
        assert r.returncode == 0, r.stderr
        lines = cfg.read_text(encoding="utf-8").splitlines()
        assert lines.count("gpu_mem=128") == 1
        assert not [ln for ln in lines if ln.startswith("gpu_mem=") and ln != "gpu_mem=128"]
        assert "dtparam=audio=on" in lines

    def test_a_correct_single_line_is_left_untouched(self, tmp_path):
        env = Env(tmp_path)
        text = "gpu_mem=128\ndtparam=audio=on\n"
        cfg = self._cfg(tmp_path, text)
        r = _run(env, f'write_boot_config_line gpu_mem 128 "{cfg.as_posix()}"')
        assert r.returncode == 0, r.stderr
        assert cfg.read_text(encoding="utf-8") == text

    def test_value_16_is_supported_for_the_headless_path(self, tmp_path):
        env = Env(tmp_path)
        cfg = self._cfg(tmp_path, "gpu_mem=128\n")
        r = _run(env, f'write_boot_config_line gpu_mem 16 "{cfg.as_posix()}"')
        assert r.returncode == 0, r.stderr
        assert cfg.read_text(encoding="utf-8") == "gpu_mem=16\n"

    def test_missing_file_warns_and_succeeds(self, tmp_path):
        env = Env(tmp_path)
        r = _run(env, f'write_boot_config_line gpu_mem 128 "{(tmp_path / "none").as_posix()}"')
        assert r.returncode == 0
        assert "WARNING" in r.stderr

    @pytest.mark.parametrize("existing", ["dtoverlay=vc4-kms-v3d", "dtoverlay=vc4-kms-v3d,cma-512"])
    def test_overlay_already_enabled_is_not_duplicated(self, tmp_path, existing):
        env = Env(tmp_path)
        cfg = self._cfg(tmp_path, existing + "\n")
        r = _run(env, f'ensure_boot_overlay vc4-kms-v3d "{cfg.as_posix()}"')
        assert r.returncode == 0, r.stderr
        assert cfg.read_text(encoding="utf-8") == existing + "\n"

    def test_overlay_is_appended_when_absent(self, tmp_path):
        env = Env(tmp_path)
        cfg = self._cfg(tmp_path, "dtoverlay=spi1-1cs,cs0_pin=12\n")
        r = _run(env, f'ensure_boot_overlay vc4-kms-v3d "{cfg.as_posix()}"')
        assert r.returncode == 0, r.stderr
        assert cfg.read_text(encoding="utf-8").splitlines() == [
            "dtoverlay=spi1-1cs,cs0_pin=12", "dtoverlay=vc4-kms-v3d"]

    def _both(self, env, cfg):
        c = cfg.as_posix()
        r = _run(env, f'write_boot_config_line gpu_mem 128 "{c}"; '
                      f'ensure_boot_overlay vc4-kms-v3d "{c}"')
        assert r.returncode == 0, r.stderr
        return cfg.read_text(encoding="utf-8")

    def _idempotent(self, env, cfg):
        first = cfg.read_text(encoding="utf-8")
        assert self._both(env, cfg) == first

    def test_no_sections_appends_plainly(self, tmp_path):
        env = Env(tmp_path)
        cfg = self._cfg(tmp_path, "dtparam=audio=on")
        assert self._both(env, cfg) == "dtparam=audio=on\ngpu_mem=128\ndtoverlay=vc4-kms-v3d\n"
        self._idempotent(env, cfg)

    def test_trailing_conditional_section_gets_an_all_header_first(self, tmp_path):
        env = Env(tmp_path)
        cfg = self._cfg(tmp_path, "dtparam=audio=on\n[pi4]\narm_boost=1\n")
        out = self._both(env, cfg)
        assert out == ("dtparam=audio=on\n[pi4]\narm_boost=1\n"
                       "[all]\ngpu_mem=128\ndtoverlay=vc4-kms-v3d\n")
        self._idempotent(env, cfg)

    def test_trailing_cm4_section_is_never_the_home_of_an_appended_line(self, tmp_path):
        env = Env(tmp_path)
        cfg = self._cfg(tmp_path, "[cm4]\notg_mode=1\n")
        out = self._both(env, cfg).splitlines()
        assert out.index("[all]") < out.index("gpu_mem=128")
        assert out.index("[all]") < out.index("dtoverlay=vc4-kms-v3d")

    def test_trailing_all_section_appends_without_a_second_header(self, tmp_path):
        env = Env(tmp_path)
        cfg = self._cfg(tmp_path, "[pi4]\narm_boost=1\n[all]\ndtparam=audio=on\n")
        out = self._both(env, cfg)
        assert out == ("[pi4]\narm_boost=1\n[all]\ndtparam=audio=on\n"
                       "gpu_mem=128\ndtoverlay=vc4-kms-v3d\n")
        self._idempotent(env, cfg)

    def test_existing_key_in_all_is_updated_in_place(self, tmp_path):
        env = Env(tmp_path)
        cfg = self._cfg(tmp_path, "[all]\ngpu_mem=16\n[pi4]\narm_boost=1\n")
        out = self._both(env, cfg)
        assert out.startswith("[all]\ngpu_mem=128\n[pi4]\narm_boost=1\n")
        assert out.count("gpu_mem=") == 1
        self._idempotent(env, cfg)

    def test_existing_unconditional_key_before_any_header_is_updated(self, tmp_path):
        env = Env(tmp_path)
        cfg = self._cfg(tmp_path, "gpu_mem=16\n[pi4]\narm_boost=1\n")
        out = self._both(env, cfg)
        assert out.startswith("gpu_mem=128\n[pi4]\narm_boost=1\n")
        assert out.count("gpu_mem=") == 1

    def test_key_only_inside_a_conditional_section_gets_an_all_copy(self, tmp_path):
        env = Env(tmp_path)
        cfg = self._cfg(tmp_path, "[pi4]\ngpu_mem=64\ndtoverlay=vc4-kms-v3d\n")
        out = self._both(env, cfg)
        assert out == ("[pi4]\ngpu_mem=64\ndtoverlay=vc4-kms-v3d\n"
                       "[all]\ngpu_mem=128\ndtoverlay=vc4-kms-v3d\n")
        self._idempotent(env, cfg)

    def test_configure_hd_boot_sets_overlay_and_leaves_gpu_memory_alone(self, tmp_path):
        env = Env(tmp_path)
        cfg = self._cfg(tmp_path, "gpu_mem=16\n")
        for _ in range(2):
            r = _run(env, f'configure_hd_boot "{cfg.as_posix()}"')
            assert r.returncode == 0, r.stderr
        lines = cfg.read_text(encoding="utf-8").splitlines()
        assert sorted(lines) == ["dtoverlay=vc4-kms-v3d", "gpu_mem=16"]

    def test_configure_hd_boot_adds_no_gpu_mem_line(self, tmp_path):
        env = Env(tmp_path)
        cfg = self._cfg(tmp_path, "dtparam=audio=on\n")
        r = _run(env, f'configure_hd_boot "{cfg.as_posix()}"')
        assert r.returncode == 0, r.stderr
        assert "gpu_mem" not in cfg.read_text(encoding="utf-8")

    def test_the_spi_path_never_calls_the_boot_helpers(self):
        text = INSTALLER.read_text(encoding="utf-8")
        for name in ("write_boot_config_line", "ensure_boot_overlay"):
            assert name not in text
        assert "configure_hd_boot" in "\n".join(_hd_blocks(text))


@bash_capable
class TestHdConfigAndAccount:
    def test_display_block_is_added_and_the_rest_kept(self, tmp_path):
        env = Env(tmp_path)
        _real_python(env)
        _write_json(_hw(env), {"clk_gpio": 17, "port": 7842, "uuid": "abc"})
        r = _run(env, "write_hd_display_config")
        assert r.returncode == 0, r.stderr
        cfg = json.loads(_hw(env).read_text(encoding="utf-8"))
        assert cfg["display"] == {"fitted": True, "screen_type": "hd_kiosk", "touch_type": "none"}
        assert cfg["uuid"] == "abc" and cfg["clk_gpio"] == 17 and cfg["port"] == 7842

    def test_the_block_loads_as_the_kiosk_profile(self, tmp_path):
        sys.path.insert(0, str(REPO_ROOT / "dial"))
        import dial_display_profiles as ddp
        env = Env(tmp_path)
        _real_python(env)
        _write_json(_hw(env), {"uuid": "abc"})
        assert _run(env, "write_hd_display_config").returncode == 0
        key = json.loads(_hw(env).read_text(encoding="utf-8"))["display"]["screen_type"]
        assert ddp.get_profile(key).surface == "kiosk"

    def test_marker_is_an_empty_root_owned_file_in_the_state_directory(self, tmp_path):
        env = Env(tmp_path)
        env.fake("install", RECORDER)
        r = _run(env, "write_hd_marker")
        assert r.returncode == 0, r.stderr
        assert env.calls() == [f"install -m 0644 -o root -g root /dev/null {env.state}/hd-kiosk"]

    def test_unit_and_rule_are_installed_then_enabled_not_started(self, tmp_path):
        env = Env(tmp_path)
        for name in ("install", "udevadm", "modprobe"):
            env.fake(name, RECORDER)
        r = _run(env, "deploy_kiosk_unit")
        assert r.returncode == 0, r.stderr
        calls = env.calls()
        assert any(c.startswith("install -D ") and c.endswith("/etc/modules-load.d/autostream-dial-i2c.conf")
                   for c in calls)
        assert "modprobe i2c-dev" in calls
        assert any(c.startswith("install ") and c.endswith("/etc/systemd/system/autostream_dial_kiosk.service")
                   for c in calls)
        assert any(c.startswith("install -D ") and c.endswith("/etc/udev/rules.d/99-autostream-backlight.rules")
                   for c in calls)
        assert calls.index("systemctl daemon-reload") < calls.index(
            "systemctl enable autostream_dial_kiosk.service")
        assert not [c for c in calls if c.startswith("systemctl") and " start " in c + " "]
        assert not [c for c in calls if c.startswith("systemctl") and "--now" in c]

    def test_user_is_created_unprivileged_with_the_device_groups(self, tmp_path):
        env = Env(tmp_path)
        env.fake("id", "#!/bin/bash\nexit 1\n")
        for name in ("useradd", "usermod", "chown", "chmod"):
            env.fake(name, RECORDER)
        r = _run(env, "create_kiosk_user")
        assert r.returncode == 0, r.stderr
        calls = env.calls()
        assert ("useradd --system --create-home --home-dir /var/lib/autostream-kiosk "
                "--shell /usr/sbin/nologin autostream-kiosk") in calls
        for grp in ("video", "input", "render"):
            assert f"usermod -aG {grp} autostream-kiosk" in calls
        assert "usermod -aG video autostream" in calls

    def test_the_service_user_joins_the_i2c_group_when_there_is_one(self, tmp_path):
        env = Env(tmp_path)
        env.fake("id", "#!/bin/bash\nexit 0\n")
        env.fake("getent", "#!/bin/bash\nexit 0\n")
        for name in ("useradd", "usermod", "chown", "chmod"):
            env.fake(name, RECORDER)
        r = _run(env, "create_kiosk_user; create_kiosk_user")
        assert r.returncode == 0, r.stderr
        assert env.calls().count("usermod -aG i2c autostream") == 2     # safe to repeat

    def test_a_system_without_the_i2c_group_is_skipped_with_a_message(self, tmp_path):
        env = Env(tmp_path)
        env.fake("id", "#!/bin/bash\nexit 0\n")
        env.fake("getent", "#!/bin/bash\nexit 2\n")
        for name in ("useradd", "usermod", "chown", "chmod", "groupadd"):
            env.fake(name, RECORDER)
        r = _run(env, "create_kiosk_user")
        assert r.returncode == 0, r.stderr
        calls = env.calls()
        assert "usermod -aG i2c autostream" not in calls
        assert not [c for c in calls if c.startswith("groupadd")]
        assert "No i2c group" in r.stdout

    def test_an_existing_user_is_not_recreated(self, tmp_path):
        env = Env(tmp_path)
        env.fake("id", "#!/bin/bash\nexit 0\n")
        for name in ("useradd", "usermod", "chown", "chmod"):
            env.fake(name, RECORDER)
        r = _run(env, "create_kiosk_user")
        assert r.returncode == 0, r.stderr
        assert not [c for c in env.calls() if c.startswith("useradd")]


@bash_capable
class TestDetectHdInstall:
    def _detect(self, env: Env, hw=None, settings=None, marker=False):
        _real_python(env)
        if hw is not None:
            _write_json(_hw(env), hw)
        if settings is not None:
            _write_json(env.state / "dial-settings.json", settings)
        if marker:
            (env.state / "hd-kiosk").write_text("", encoding="utf-8")
        r = _run(env, "HD=false; detect_hd_install; echo \"HD=$HD\"")
        assert r.returncode == 0, r.stderr
        return r.stdout.strip().splitlines()[-1]

    def test_kiosk_profile_in_the_hardware_file(self, tmp_path):
        assert self._detect(Env(tmp_path), hw={"display": {"screen_type": "hd_kiosk"}}) == "HD=true"

    def test_kiosk_profile_in_the_settings_file(self, tmp_path):
        out = self._detect(Env(tmp_path), hw={"uuid": "a"},
                           settings={"display": {"screen_type": "hd_kiosk"}})
        assert out == "HD=true"

    def test_settings_screen_type_overrides_the_hardware_file(self, tmp_path):
        out = self._detect(Env(tmp_path), hw={"display": {"screen_type": "hd_kiosk"}},
                           settings={"display": {"screen_type": "st7735s_160x128"}}, marker=True)
        assert out == "HD=false"

    def test_spi_profile_is_not_hd(self, tmp_path):
        assert self._detect(Env(tmp_path), hw={"display": {"screen_type": "st7735s_160x128"}}) == "HD=false"

    def test_a_dial_with_no_display_block_is_not_hd(self, tmp_path):
        assert self._detect(Env(tmp_path), hw={"uuid": "a"}, settings={"name": ""}) == "HD=false"

    def test_unreadable_profile_falls_back_to_the_marker(self, tmp_path):
        env = Env(tmp_path)
        (env.state / "dial-settings.json").write_text("{not json", encoding="utf-8")
        assert self._detect(env, hw={"uuid": "a"}, marker=True) == "HD=true"

    def test_unknown_profile_without_a_marker_is_not_hd(self, tmp_path):
        out = self._detect(Env(tmp_path), hw={"display": {"screen_type": "no_such"}})
        assert out == "HD=false"

    def test_detection_never_clears_hd(self, tmp_path):
        env = Env(tmp_path)
        _real_python(env)
        r = _run(env, 'HD=true; detect_hd_install; echo "HD=$HD"')
        assert r.stdout.strip().splitlines()[-1] == "HD=true"


@bash_capable
class TestRetireAndOwnedFiles:
    def test_a_former_hd_dial_has_the_kiosk_switched_off(self, tmp_path):
        env = Env(tmp_path)
        marker = env.put("var/lib/autostream/hd-kiosk", "")
        r = _run(env, "retire_hd_kiosk")
        assert r.returncode == 0, r.stderr
        assert not marker.exists()
        assert "systemctl disable --now autostream_dial_kiosk.service" in env.calls()

    def test_a_dial_that_never_was_hd_is_left_alone(self, tmp_path):
        env = Env(tmp_path)
        r = _run(env, "retire_hd_kiosk")
        assert r.returncode == 0, r.stderr
        assert env.calls() == []

    def test_owned_files_list_names_the_kiosk_files_only_under_hd(self, tmp_path):
        env = Env(tmp_path)
        kiosk = ["/etc/systemd/system/autostream_dial_kiosk.service",
                 "/etc/udev/rules.d/99-autostream-backlight.rules",
                 "/etc/modules-load.d/autostream-dial-i2c.conf",
                 "/var/lib/autostream/hd-kiosk"]
        spi = _run(env, "owned_files_list").stdout.splitlines()
        hd = _run(env, "HD=true; owned_files_list").stdout.splitlines()
        for path in kiosk:
            assert path not in spi
            assert path in hd
        assert hd[:len(spi)] == spi and hd[len(spi):] == kiosk

    def test_owned_files_list_with_hd_unset_matches_hd_false(self, tmp_path):
        env = Env(tmp_path)
        unset = env.run("unset HD; owned_files_list").stdout
        assert unset == _run(env, "HD=false; owned_files_list").stdout

    def test_an_hd_update_backs_up_and_restores_its_kiosk_files(self, tmp_path):
        env = Env(tmp_path)
        unit = env.put("etc/systemd/system/autostream_dial_kiosk.service", "old unit")
        marker = env.put("var/lib/autostream/hd-kiosk", "")
        r = _run(env, "HD=true; backup_owned_files")
        assert r.returncode == 0, r.stderr
        manifest = (env.upd / "update-prev" / "MANIFEST").read_text(encoding="utf-8")
        assert "PRESENT\t/etc/systemd/system/autostream_dial_kiosk.service" in manifest
        assert "PRESENT\t/var/lib/autostream/hd-kiosk" in manifest
        assert "ABSENT\t/etc/udev/rules.d/99-autostream-backlight.rules" in manifest
        unit.write_text("new unit", encoding="utf-8")
        marker.unlink()
        r = _run(env, "HD=true; restore_owned_files")
        assert r.returncode == 0, r.stderr
        assert unit.read_text(encoding="utf-8") == "old unit"
        assert marker.exists()


# ---------------------------------------------------------------------------
# The installer end to end, helpers replaced by recorders
# ---------------------------------------------------------------------------

def _dry_run(tmp_path: Path, *, update: bool, hd_flag: bool = False,
             detects_hd: bool = False, reinstall: bool = False,
             state_text: str = "DIAL_UUID=feedfacefeedfacefeed\n"):
    env = Env(tmp_path)
    deploy = tmp_path / "deploy"
    (deploy / "installer" / "dial").mkdir(parents=True)
    (deploy / "autostream_dial_install.sh").write_bytes(INSTALLER.read_bytes())
    names = re.findall(r"^([a-z][a-z0-9_]*)\(\) \{", _helper_text(), re.M)
    stubs = [f'source "{HELPERS.as_posix()}"']
    for name in names:
        stubs.append(f'{name}() {{ printf "%s %s\\n" {name} "$*" >> "$TRACE"; }}')
    stubs += [
        'phase() { printf "phase %s %s\\n" "$1" "$2" >> "$TRACE"; }',
        "detect_install_version() { echo 1.3.0; }",
        "generate_dial_id() { echo 0123456789abcdef0123; }",
        "has_tty() { return 1; }",
    ]
    if reinstall:
        stubs.append('detect_existing_dial_install() { printf "detect_existing_dial_install\\n" >> "$TRACE"; REINSTALL=true; }')
    if detects_hd:
        stubs.append('detect_hd_install() { printf "detect_hd_install\\n" >> "$TRACE"; HD=true; }')
    (deploy / "installer" / "dial" / "helpers.sh").write_text("\n".join(stubs) + "\n",
                                                               encoding="utf-8")
    for name in ("install", "cp", "mkdir", "rm", "ln", "sed", "chown", "chmod", "reboot",
                 "flock"):
        env.fake(name, RECORDER)
    env.install_state.write_text(state_text, encoding="utf-8")
    args = ["bash", str(deploy / "autostream_dial_install.sh")]
    if update:
        args.append("--update")
    if hd_flag:
        args.append("--hd")
    e = env.env(
        AUTOSTREAM_DIAL_LOCKED="1",
        DIAL_INSTALL_LOGFILE=(tmp_path / "install.log").as_posix(),
        HOME=tmp_path.as_posix(),
        UPDATE_PAINT_DELAY="0",
    )
    r = subprocess.run(args, capture_output=True, text=True, timeout=60, env=e)
    return r, env.calls()


def _names(calls: list[str]) -> list[str]:
    return [c.split()[0] if not c.startswith("phase ") else " ".join(c.split()[:2])
            for c in calls if c.strip()]


@bash_capable
class TestInstallerDryRun:
    def test_fresh_hd_install_runs_every_hd_step_in_order(self, tmp_path):
        r, calls = _dry_run(tmp_path, update=False, hd_flag=True)
        assert r.returncode == 0, r.stderr
        names = _names(calls)
        for name in HD_ONLY:
            assert names.count(name) == 1, name
        assert "retire_hd_kiosk" not in names
        assert "detect_hd_install" not in names
        at = names.index
        assert at("install_kiosk_packages") < at("create_kiosk_user") < at("phase python")
        assert at("install_display_hardware_packages") < at("install_kiosk_packages")
        assert at("enable_i2c") < at("configure_hd_boot")
        assert at("write_dial_settings") < at("write_hd_display_config")
        assert at("write_hd_marker") < at("deploy_kiosk_unit") < at("write_install_state")

    def test_fresh_spi_install_runs_no_hd_step(self, tmp_path):
        r, calls = _dry_run(tmp_path, update=False)
        assert r.returncode == 0, r.stderr
        names = _names(calls)
        for name in HD_ONLY:
            assert name not in names, name
        assert "detect_hd_install" not in names
        assert names.count("retire_hd_kiosk") == 1
        assert not [c for c in calls if re.search(r"kiosk|udev|backlight|vc4|gpu_mem", c)
                    and not c.startswith("retire_hd_kiosk")]

    def test_spi_install_is_the_hd_install_without_the_hd_steps(self, tmp_path):
        (tmp_path / "spi").mkdir()
        (tmp_path / "hd").mkdir()
        _r1, spi = _dry_run(tmp_path / "spi", update=False)
        _r2, hd = _dry_run(tmp_path / "hd", update=False, hd_flag=True)
        assert [n for n in _names(hd) if n not in HD_ONLY] == [
            n for n in _names(spi) if n != "retire_hd_kiosk"]

    def test_spi_update_runs_no_hd_step(self, tmp_path):
        r, calls = _dry_run(tmp_path, update=True)
        assert r.returncode == 0, r.stderr
        names = _names(calls)
        for name in HD_ONLY:
            assert name not in names, name
        assert names.count("detect_hd_install") == 1
        assert names.count("retire_hd_kiosk") == 1

    def test_hd_update_keeps_the_kiosk_without_rewriting_the_profile(self, tmp_path):
        r, calls = _dry_run(tmp_path, update=True, detects_hd=True)
        assert r.returncode == 0, r.stderr
        names = _names(calls)
        for name in ("install_kiosk_packages", "create_kiosk_user", "configure_hd_boot",
                     "write_hd_marker", "deploy_kiosk_unit"):
            assert names.count(name) == 1, name
        assert "write_hd_display_config" not in names
        assert "retire_hd_kiosk" not in names
        at = names.index
        assert at("detect_hd_install") < at("backup_owned_files") < at("stage_code_tree")
        assert at("detect_hd_install") < at("system_upgrade") < at("install_kiosk_packages")
        assert at("deploy_kiosk_unit") < at("write_update_swap")
        assert [n for n in names if n != "rm"][-1] == "schedule_update_reboot"

    def test_the_hd_flag_is_ignored_on_an_update(self, tmp_path):
        r, calls = _dry_run(tmp_path, update=True, hd_flag=True)
        assert r.returncode == 0, r.stderr
        names = _names(calls)
        for name in HD_ONLY:
            assert name not in names, name
