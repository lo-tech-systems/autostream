"""The appliance installer's low power mode (--low-power): the kernel command
line editor, the config.txt lines, how the choice is parsed, recorded and
re-applied, and how the uninstaller takes it back.

The real functions are run in bash against scratch boot files, with the
installer's own IFS in force. The checks that read script text say so in their
names.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from conftest import bash_can_run_script_at_windows_path  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
HARDWARE = REPO_ROOT / "installer" / "lib" / "hardware.sh"
INSTALLER = REPO_ROOT / "autostream_install.sh"
UNINSTALLER = REPO_ROOT / "autostream_uninstall.sh"

bash_capable = pytest.mark.skipif(
    not bash_can_run_script_at_windows_path(),
    reason="bash cannot execute scripts at this path (MSYS2 limitation on Windows)",
)
posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="file modes are meaningful on POSIX only")

LOW_POWER_LINES = ["arm_freq=700", "arm_boost=0", "force_turbo=0"]

# The installer's own word-splitting rules, so a function that depends on the
# default IFS fails here as it would there.
PRELUDE = '''
set -uo pipefail
IFS=$'\\n\\t'
info() { echo "INFO: $*"; }
warn() { echo "WARN: $*"; }
error() { echo "ERROR: $*"; }
'''


def _function(text: str, name: str) -> str:
    m = re.search(r"^" + re.escape(name) + r"\(\) \{.*?\n\}\n", text, re.S | re.M)
    assert m is not None, name
    return m.group(0)


def _bash(body: str, tmp_path: Path, **env: str):
    script = f'{PRELUDE}\nsource "{HARDWARE.as_posix()}"\n{body}'
    import os
    e = dict(os.environ)
    e.update(env)
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                          timeout=30, env=e, cwd=tmp_path)


def _write(path: Path, text: str) -> Path:
    path.write_bytes(text.encode("utf-8"))
    return path


def _text(path: Path) -> str:
    return path.read_bytes().decode("utf-8")


# ---------------------------------------------------------------------------
# The kernel command line editor
# ---------------------------------------------------------------------------

BASE_CMDLINE = ("console=serial0,115200 console=tty1 root=PARTUUID=abcd-02 rootfstype=ext4 "
                "fsck.repair=yes rootwait")


@bash_capable
class TestEnsureCmdlineOption:
    def _ensure(self, tmp_path: Path, content: str | None, value: str = "2"):
        f = tmp_path / "cmdline.txt"
        if content is not None:
            _write(f, content)
        r = _bash(f'ensure_cmdline_option maxcpus {value} "{f.as_posix()}"', tmp_path)
        assert r.returncode == 0, r.stderr
        return r, f

    def test_a_missing_token_is_appended_once_and_the_line_stays_one_line(self, tmp_path):
        r, f = self._ensure(tmp_path, BASE_CMDLINE + "\n")
        assert _text(f) == BASE_CMDLINE + " maxcpus=2\n"

    def test_a_file_without_a_trailing_newline_gets_none(self, tmp_path):
        r, f = self._ensure(tmp_path, BASE_CMDLINE)
        assert _text(f) == BASE_CMDLINE + " maxcpus=2"

    def test_a_token_already_present_leaves_the_file_byte_for_byte_alone(self, tmp_path):
        content = "console=tty1  maxcpus=2   rootwait\n"
        r, f = self._ensure(tmp_path, content)
        assert _text(f) == content
        assert not (tmp_path / "cmdline.txt.autostream-bak").exists()

    def test_a_token_present_with_another_value_is_set_in_place_once(self, tmp_path):
        r, f = self._ensure(tmp_path, "console=tty1 maxcpus=4 rootwait\n")
        assert _text(f) == "console=tty1 maxcpus=2 rootwait\n"

    def test_repeated_tokens_are_collapsed_to_one(self, tmp_path):
        r, f = self._ensure(tmp_path, "maxcpus=1 console=tty1 maxcpus=2 maxcpus=3\n")
        assert _text(f) == "maxcpus=2 console=tty1\n"

    def test_a_longer_key_with_the_same_start_is_not_mistaken_for_it(self, tmp_path):
        r, f = self._ensure(tmp_path, "console=tty1 maxcpus_hint=9 rootwait\n")
        assert _text(f) == "console=tty1 maxcpus_hint=9 rootwait maxcpus=2\n"

    def test_running_it_twice_changes_nothing_the_second_time(self, tmp_path):
        r, f = self._ensure(tmp_path, BASE_CMDLINE + "\n")
        first = _text(f)
        self._ensure(tmp_path, None)
        assert _text(f) == first
        assert first.count("maxcpus=2") == 1

    def test_a_missing_file_warns_and_is_not_created(self, tmp_path):
        r, f = self._ensure(tmp_path, None)
        assert not f.exists()
        assert "not found" in r.stdout

    def test_an_empty_file_gets_just_the_token(self, tmp_path):
        r, f = self._ensure(tmp_path, "")
        assert _text(f) == "maxcpus=2\n"

    def test_a_file_with_several_lines_is_left_alone_with_a_warning(self, tmp_path):
        content = "console=tty1\nrootwait\n"
        r, f = self._ensure(tmp_path, content)
        assert _text(f) == content
        assert "more than one line" in r.stdout

    def test_the_first_change_keeps_a_copy_of_the_original_and_a_later_one_does_not_replace_it(self, tmp_path):
        r, f = self._ensure(tmp_path, BASE_CMDLINE + "\n")
        backup = tmp_path / "cmdline.txt.autostream-bak"
        assert _text(backup) == BASE_CMDLINE + "\n"
        self._ensure(tmp_path, None, value="3")
        assert _text(f).endswith("maxcpus=3\n")
        assert _text(backup) == BASE_CMDLINE + "\n"

    @posix_only
    def test_the_file_keeps_its_mode(self, tmp_path):
        f = _write(tmp_path / "cmdline.txt", "rootwait\n")
        f.chmod(0o755)
        _bash(f'ensure_cmdline_option maxcpus 2 "{f.as_posix()}"', tmp_path)
        assert f.stat().st_mode & 0o777 == 0o755

    @posix_only
    def test_the_default_location_falls_back_to_boot_when_boot_firmware_is_absent(self, tmp_path):
        if Path("/boot/firmware").is_dir():
            pytest.skip("this machine has /boot/firmware")
        r = _bash("boot_file_path cmdline.txt", tmp_path)
        assert r.stdout.strip() == "/boot/cmdline.txt"


@bash_capable
class TestRemoveCmdlineOption:
    def _remove(self, tmp_path: Path, content: str):
        f = _write(tmp_path / "cmdline.txt", content)
        r = _bash(f'remove_cmdline_option maxcpus 2 "{f.as_posix()}"', tmp_path)
        assert r.returncode == 0, r.stderr
        return f

    def test_only_the_exact_token_goes(self, tmp_path):
        f = self._remove(tmp_path, "console=tty1 maxcpus=2 rootwait\n")
        assert _text(f) == "console=tty1 rootwait\n"

    def test_another_value_is_not_ours_and_stays(self, tmp_path):
        content = "console=tty1 maxcpus=4 rootwait\n"
        assert _text(self._remove(tmp_path, content)) == content

    def test_a_file_without_the_token_is_untouched_byte_for_byte(self, tmp_path):
        content = "console=tty1   rootwait"
        assert _text(self._remove(tmp_path, content)) == content


# ---------------------------------------------------------------------------
# config.txt
# ---------------------------------------------------------------------------

STOCK_CONFIG = """# For more options see the docs
dtparam=audio=on
camera_auto_detect=1

[cm4]
otg_mode=1

[all]
enable_uart=1
"""

HAND_SET_CONFIG = """dtparam=audio=on

[pi4]
arm_freq=1800

[all]
arm_freq=700
arm_boost=0
force_turbo=0
over_voltage=-2
enable_uart=1
"""


def _firmware(tmp_path: Path, content: str, *, mode: str = "install", low_power: str = ""):
    cfg = _write(tmp_path / "config.txt", content)
    third = f' "{low_power}"' if low_power != "" else ""
    r = _bash(f'update_pi_firmware_config "{cfg.as_posix()}" {mode}{third}', tmp_path)
    assert r.returncode == 0, r.stderr
    return cfg


def _lines(path: Path) -> list[str]:
    return _text(path).splitlines()


@bash_capable
class TestConfigTxtLines:
    def test_without_the_switch_a_fresh_install_writes_none_of_the_four_settings(self, tmp_path):
        cfg = _firmware(tmp_path, STOCK_CONFIG)
        lines = _lines(cfg)
        for line in LOW_POWER_LINES:
            assert line not in lines
        assert not [l for l in lines if l.startswith("over_voltage")]

    def test_without_the_switch_an_update_keeps_existing_settings_exactly(self, tmp_path):
        cfg = _firmware(tmp_path, HAND_SET_CONFIG, mode="update")
        expected = HAND_SET_CONFIG.replace(
            "[all]\n", "[all]\ndtparam=watchdog=on\ngpu_mem=16\n", 1)
        assert _text(cfg) == expected

    def test_with_the_switch_the_three_lines_follow_the_all_header(self, tmp_path):
        cfg = _firmware(tmp_path, STOCK_CONFIG, low_power="1")
        lines = _lines(cfg)
        i = lines.index("[all]")
        assert lines[i + 1:i + 7] == ["dtparam=watchdog=on", "gpu_mem=16", "dtoverlay=disable-bt",
                                      "arm_freq=700", "arm_boost=0", "force_turbo=0"]

    def test_with_the_switch_each_line_appears_once_and_other_lines_stay(self, tmp_path):
        cfg = _firmware(tmp_path, STOCK_CONFIG, low_power="1")
        lines = _lines(cfg)
        for line in LOW_POWER_LINES:
            assert lines.count(line) == 1
        assert "enable_uart=1" in lines and "otg_mode=1" in lines

    def test_with_the_switch_an_update_applies_them_and_a_second_run_changes_nothing(self, tmp_path):
        cfg = _firmware(tmp_path, STOCK_CONFIG, mode="update", low_power="1")
        first = _text(cfg)
        assert all(first.count(l) == 1 for l in LOW_POWER_LINES)
        _bash(f'update_pi_firmware_config "{cfg.as_posix()}" update 1', tmp_path)
        assert _text(cfg) == first

    def test_a_different_value_already_under_all_is_replaced_and_other_sections_are_not_touched(self, tmp_path):
        content = HAND_SET_CONFIG.replace("arm_freq=700", "arm_freq=900")
        cfg = _firmware(tmp_path, content, mode="update", low_power="1")
        lines = _lines(cfg)
        assert "arm_freq=900" not in lines
        assert lines.count("arm_freq=700") == 1
        assert lines.count("arm_freq=1800") == 1
        assert lines.index("arm_freq=1800") < lines.index("[all]")

    def test_with_the_switch_a_file_without_an_all_header_gets_one(self, tmp_path):
        cfg = _firmware(tmp_path, "dtparam=audio=on\narm_freq=900\n", low_power="1")
        lines = _lines(cfg)
        assert lines[0] == "[all]"
        assert lines.count("arm_freq=700") == 1 and "arm_freq=900" not in lines

    def test_over_voltage_is_never_written(self, tmp_path):
        for content in (STOCK_CONFIG, "dtparam=audio=on\n"):
            cfg = _firmware(tmp_path, content, low_power="1")
            assert "over_voltage" not in _text(cfg)

    def test_an_existing_over_voltage_line_is_not_removed(self, tmp_path):
        for sw in ("", "1"):
            cfg = _firmware(tmp_path, HAND_SET_CONFIG, mode="update", low_power=sw)
            assert "over_voltage=-2" in _lines(cfg)

    def test_the_global_decides_when_no_argument_is_given(self, tmp_path):
        cfg = _write(tmp_path / "config.txt", STOCK_CONFIG)
        r = _bash(f'LOW_POWER=1; update_pi_firmware_config "{cfg.as_posix()}" update', tmp_path)
        assert r.returncode == 0, r.stderr
        assert "arm_freq=700" in _lines(cfg)

    def test_a_missing_file_is_skipped_with_a_warning(self, tmp_path):
        r = _bash(f'update_pi_firmware_config "{(tmp_path / "none.txt").as_posix()}" install 1',
                  tmp_path)
        assert r.returncode == 0 and "not found" in r.stdout


@bash_capable
class TestRemoveLowPowerSettings:
    def test_the_exact_settings_and_the_token_go_and_nothing_else(self, tmp_path):
        cfg = _write(tmp_path / "config.txt", HAND_SET_CONFIG)
        cmd = _write(tmp_path / "cmdline.txt", "console=tty1 maxcpus=2 rootwait\n")
        r = _bash(f'remove_low_power_settings "{cfg.as_posix()}" "{cmd.as_posix()}"', tmp_path)
        assert r.returncode == 0, r.stderr
        lines = _lines(cfg)
        for line in LOW_POWER_LINES[1:] + ["arm_freq=700"]:
            assert line not in lines
        assert "over_voltage=-2" in lines and "arm_freq=1800" in lines and "enable_uart=1" in lines
        assert _text(cmd) == "console=tty1 rootwait\n"

    def test_other_values_of_the_same_keys_stay(self, tmp_path):
        content = "[all]\narm_freq=900\narm_boost=1\nforce_turbo=1\n"
        cfg = _write(tmp_path / "config.txt", content)
        cmd = _write(tmp_path / "cmdline.txt", "maxcpus=4\n")
        _bash(f'remove_low_power_settings "{cfg.as_posix()}" "{cmd.as_posix()}"', tmp_path)
        assert _text(cfg) == content and _text(cmd) == "maxcpus=4\n"

    def test_missing_files_are_not_an_error(self, tmp_path):
        r = _bash(f'remove_low_power_settings "{(tmp_path / "a").as_posix()}" '
                  f'"{(tmp_path / "b").as_posix()}"', tmp_path)
        assert r.returncode == 0, r.stderr


# ---------------------------------------------------------------------------
# The switch: parsing, the saved choice, the unattended update
# ---------------------------------------------------------------------------

def _installer_functions() -> str:
    text = INSTALLER.read_text(encoding="utf-8")
    names = ["is_valid_sdmon_method", "is_valid_owntone_mode", "detect_install_version",
             "usage", "parse_args", "save_state", "load_state"]
    return "\n".join(_function(text, n) for n in names)


def _installer_run(tmp_path: Path, body: str, state: str | None = None):
    """Run the installer's own argument parsing and state functions."""
    state_file = tmp_path / "install-state.env"
    if state is not None:
        _write(state_file, state)
    stubs = tmp_path / "bin"
    stubs.mkdir(exist_ok=True)
    for name in ("chown", "chmod"):
        (stubs / name).write_text("#!/bin/sh\nexit 0\n", encoding="utf-8", newline="\n")
        (stubs / name).chmod(0o755)
    script = f'''
STATE_FILE="{state_file.as_posix()}"
STAMP_DIR="{tmp_path.as_posix()}"
SCRIPT_NAME=autostream_install.sh
AUTOSTREAM_DIR=/x; INSTALL_DIR=/opt/autostream; INSTALL_MODE=install
UNATTENDED=0; PIN_VALUE=""; PIN_REGEX='^[A-Za-z0-9-]{{4,20}}$'
SDMON_METHOD=""; SDMON_CHECK=none; SDMON_CHECK_SERIAL=""; SDMON_CHECK_AT=""; SDMON_CHECK_REASON=""
SDMON_FLAG_THIS_RUN=0; FETCH_AUTOSTREAM=0; OWNTONE_MODE=mini
LOW_POWER=0; LOW_POWER_REQUESTED=0
source "{(REPO_ROOT / "installer" / "lib" / "state_files.sh").as_posix()}"
{_installer_functions()}
{body}
'''
    import os
    e = dict(os.environ)
    e["PATH"] = stubs.as_posix() + os.pathsep + e.get("PATH", "")
    r = subprocess.run(["bash", "-c", f"{PRELUDE}\n{script}"], capture_output=True, text=True,
                       timeout=30, env=e)
    return r, state_file


def _state_value(state_file: Path, key: str) -> str | None:
    for line in _text(state_file).splitlines():
        if line.startswith(key + "="):
            return line.split("=", 1)[1].strip('"')
    return None


@bash_capable
class TestSwitchAndSavedChoice:
    def test_it_is_off_unless_given(self, tmp_path):
        r, _ = _installer_run(tmp_path, 'parse_args --unattended PIN=1234; echo "LP=$LOW_POWER"')
        assert "LP=0" in r.stdout

    def test_the_flag_turns_it_on_beside_the_other_install_options(self, tmp_path):
        r, _ = _installer_run(
            tmp_path, 'parse_args --unattended PIN=1234 --low-power --owntone=full; echo "LP=$LOW_POWER"')
        assert r.returncode == 0, r.stdout
        assert "LP=1" in r.stdout

    def test_a_fresh_install_without_the_flag_records_it_as_off(self, tmp_path):
        r, state = _installer_run(tmp_path, "parse_args; save_state")
        assert _state_value(state, "LOW_POWER") == "0"

    def test_a_fresh_install_with_the_flag_records_it_as_on(self, tmp_path):
        r, state = _installer_run(tmp_path, "parse_args --low-power; save_state")
        assert _state_value(state, "LOW_POWER") == "1"

    def test_an_unattended_update_reasserts_a_recorded_on_choice(self, tmp_path):
        r, state = _installer_run(
            tmp_path, 'parse_args --update; load_state >/dev/null; echo "LP=$LOW_POWER"; save_state',
            state='OWNTONE_MODE="mini"\nLOW_POWER="1"\n')
        assert "LP=1" in r.stdout
        assert _state_value(state, "LOW_POWER") == "1"

    def test_an_update_with_a_recorded_off_choice_stays_off(self, tmp_path):
        r, state = _installer_run(
            tmp_path, 'parse_args --update; load_state >/dev/null; echo "LP=$LOW_POWER"; save_state',
            state='LOW_POWER="0"\n')
        assert "LP=0" in r.stdout and _state_value(state, "LOW_POWER") == "0"

    def test_an_update_from_a_state_file_that_never_had_the_line_stays_off(self, tmp_path):
        r, state = _installer_run(
            tmp_path, 'parse_args --update; load_state >/dev/null; echo "LP=$LOW_POWER"; save_state',
            state='OWNTONE_MODE="mini"\n')
        assert "LP=0" in r.stdout and _state_value(state, "LOW_POWER") == "0"

    def test_the_flag_on_an_update_switches_it_on_and_records_it(self, tmp_path):
        r, state = _installer_run(
            tmp_path,
            'parse_args --update --low-power; load_state >/dev/null; echo "LP=$LOW_POWER"; save_state',
            state='LOW_POWER="0"\n')
        assert r.returncode == 0, r.stdout
        assert "LP=1" in r.stdout and _state_value(state, "LOW_POWER") == "1"

    def test_a_later_run_without_the_flag_keeps_the_record_so_the_uninstaller_still_knows(self, tmp_path):
        r, state = _installer_run(tmp_path, "parse_args; save_state", state='LOW_POWER="1"\n')
        assert _state_value(state, "LOW_POWER") == "1"

    def test_update_still_refuses_the_other_options(self, tmp_path):
        r, _ = _installer_run(tmp_path, "( parse_args --update --sdmon )")
        assert r.returncode == 2
        assert "must be the only flag" in r.stdout

    def test_the_usage_text_lists_the_switch_and_its_effect(self, tmp_path):
        r, _ = _installer_run(tmp_path, "usage")
        assert "[--low-power]" in r.stdout
        assert "--low-power             Limit the appliance to two cores at 700 MHz" in r.stdout
        assert "Takes effect after a reboot" in r.stdout

    def test_the_recorded_choice_reaches_the_boot_files_on_an_unattended_update(self, tmp_path):
        cfg = _write(tmp_path / "config.txt", STOCK_CONFIG)
        r, _ = _installer_run(
            tmp_path,
            f'source "{HARDWARE.as_posix()}"\n'
            f'parse_args --update; load_state >/dev/null\n'
            f'update_pi_firmware_config "{cfg.as_posix()}"',
            state='LOW_POWER="1"\n')
        assert r.returncode == 0, r.stdout
        assert "arm_freq=700" in _lines(cfg)

    def test_with_nothing_recorded_the_unattended_update_leaves_the_boot_lines_as_they_are(self, tmp_path):
        cfg = _write(tmp_path / "config.txt", HAND_SET_CONFIG)
        r, _ = _installer_run(
            tmp_path,
            f'source "{HARDWARE.as_posix()}"\n'
            f'parse_args --update; load_state >/dev/null\n'
            f'update_pi_firmware_config "{cfg.as_posix()}"',
            state='OWNTONE_MODE="mini"\n')
        lines = _lines(cfg)
        for line in LOW_POWER_LINES + ["over_voltage=-2"]:
            assert line in lines


class TestWiring:
    def test_text_check_the_command_line_is_only_edited_when_the_mode_is_on(self):
        text = INSTALLER.read_text(encoding="utf-8")
        configure = _function(text, "configure_phase")
        i = configure.index("apply_low_power_cmdline")
        guard = configure.rindex("if [[", 0, i)
        assert 'LOW_POWER}" == "1"' in configure[guard:i]
        assert configure.count("apply_low_power_cmdline") == 1

    def test_text_check_the_output_says_it_takes_effect_at_the_next_reboot(self):
        configure = _function(INSTALLER.read_text(encoding="utf-8"), "configure_phase")
        assert "takes effect at the next reboot" in configure

    def test_text_check_update_applies_the_mode_through_the_same_configure_phase(self):
        text = INSTALLER.read_text(encoding="utf-8")
        assert "configure_phase" in _function(text, "run_update")
        assert "configure_phase" in _function(text, "run_install")


# ---------------------------------------------------------------------------
# The uninstaller
# ---------------------------------------------------------------------------

def _uninstall_run(tmp_path: Path, state: str | None):
    state_file = tmp_path / "install-state.env"
    if state is not None:
        _write(state_file, state)
    func = _function(UNINSTALLER.read_text(encoding="utf-8"), "revert_low_power_if_used")
    script = f'''
set -u
info() {{ echo "INFO: $*"; }}
warn() {{ echo "WARN: $*"; }}
remove_low_power_settings() {{ echo "REMOVED"; }}
INSTALL_STATE_FILE="{state_file.as_posix()}"
{func}
revert_low_power_if_used
'''
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=20)


@bash_capable
class TestUninstaller:
    def test_it_takes_the_settings_back_when_the_state_says_the_switch_was_used(self, tmp_path):
        r = _uninstall_run(tmp_path, 'OWNTONE_MODE="mini"\nLOW_POWER="1"\n')
        assert "REMOVED" in r.stdout and "next reboot" in r.stdout

    @pytest.mark.parametrize("state", ['LOW_POWER="0"\n', 'OWNTONE_MODE="mini"\n', None])
    def test_it_leaves_the_boot_files_alone_when_the_switch_was_not_used(self, tmp_path, state):
        r = _uninstall_run(tmp_path, state)
        assert "REMOVED" not in r.stdout

    def test_without_the_hardware_library_it_says_what_to_remove_by_hand(self, tmp_path):
        state_file = _write(tmp_path / "install-state.env", 'LOW_POWER="1"\n')
        func = _function(UNINSTALLER.read_text(encoding="utf-8"), "revert_low_power_if_used")
        script = (f'set -u\ninfo() {{ echo "INFO: $*"; }}\nwarn() {{ echo "WARN: $*"; }}\n'
                  f'INSTALL_STATE_FILE="{state_file.as_posix()}"\n{func}\nrevert_low_power_if_used')
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=20)
        assert r.returncode == 0
        assert "by hand" in r.stdout

    def test_text_check_it_runs_before_the_state_directory_is_removed(self):
        text = UNINSTALLER.read_text(encoding="utf-8")
        assert text.index("\n  revert_low_power_if_used\n") < text.index("remove_path /var/lib/autostream\n")


# ---------------------------------------------------------------------------
# What the mode replaced is put back when it is removed
# ---------------------------------------------------------------------------

OS_STOCK_CONFIG = """# For more options and information see
dtparam=audio=on
arm_boost=1
camera_auto_detect=1

[cm4]
otg_mode=1

[all]
"""
STATE_LIB = REPO_ROOT / "installer" / "lib" / "state_files.sh"


def _round_trip(tmp_path: Path, config: str, cmdline: str, *, record_twice_with: str | None = None):
    """Apply low power mode to the files as the installer does, then remove it as
    the uninstaller does. Returns (config as applied, cmdline as applied, config
    after removal, cmdline after removal, the record's text, the record's path)."""
    cfg = _write(tmp_path / "config.txt", config)
    cmd = _write(tmp_path / "cmdline.txt", cmdline)
    rec = tmp_path / "state" / "low-power-restore.env"

    def q(p: Path) -> str:
        return f'"{p.as_posix()}"'

    apply_ = (f'record_low_power_originals {q(cfg)} {q(cmd)} {q(rec)}\n'
              f'update_pi_firmware_config {q(cfg)} install 1\n'
              f'apply_low_power_cmdline {q(cmd)}\n')
    r = _bash(f'source "{STATE_LIB.as_posix()}"\n{apply_}', tmp_path)
    assert r.returncode == 0, r.stderr
    applied = (_text(cfg), _text(cmd))
    record = _text(rec) if rec.exists() else ""
    if record_twice_with is not None:
        # An update: the files now hold the mode's own lines (and the user's later edits).
        _write(cfg, applied[0] + record_twice_with)
        r = _bash(f'source "{STATE_LIB.as_posix()}"\n{apply_}', tmp_path)
        assert r.returncode == 0, r.stderr
        assert _text(rec) == record, "the record must not be rewritten"
    r = _bash(f'source "{STATE_LIB.as_posix()}"\nremove_low_power_settings {q(cfg)} {q(cmd)} {q(rec)}',
              tmp_path)
    assert r.returncode == 0, r.stderr
    return applied[0], applied[1], _text(cfg), _text(cmd), record, rec


def _section_of(text: str, line: str) -> list:
    """The section (None before the first) each copy of LINE sits in."""
    where, section = [], None
    for ln in text.splitlines():
        if ln.strip().startswith("["):
            section = ln.strip()
        elif ln.strip() == line:
            where.append(section)
    return where


@bash_capable
class TestRestoredOnRemoval:
    def test_a_stock_boost_line_outside_any_section_comes_back_where_it_was(self, tmp_path):
        applied, _c, after, _cmd, record, _rec = _round_trip(tmp_path, OS_STOCK_CONFIG, BASE_CMDLINE + "\n")
        assert "arm_boost=1" not in applied.splitlines()         # the mode replaced it
        assert "arm_boost=0" in applied.splitlines()
        assert "CONFIG=top:arm_boost:1" in record
        assert _section_of(after, "arm_boost=1") == [None]
        assert not [ln for ln in after.splitlines() if ln.startswith(("arm_freq", "force_turbo"))]
        assert "arm_boost=0" not in after.splitlines()

    def test_the_key_absent_leaves_none_of_the_three_behind(self, tmp_path):
        config = "dtparam=audio=on\n\n[all]\nenable_uart=1\n"
        _a, _c, after, cmd_after, record, _rec = _round_trip(tmp_path, config, BASE_CMDLINE + "\n")
        assert "CONFIG=" not in record and "MAXCPUS=" not in record
        assert not [ln for ln in after.splitlines() if ln.startswith(("arm_", "force_turbo"))]
        assert cmd_after == BASE_CMDLINE + "\n"

    def test_a_line_in_a_conditional_section_is_never_touched_or_recorded(self, tmp_path):
        config = "[pi5]\narm_boost=1\narm_freq=2400\n\n[all]\n"
        applied, _c, after, _cmd, record, _rec = _round_trip(tmp_path, config, BASE_CMDLINE + "\n")
        assert "CONFIG=" not in record
        assert _section_of(applied, "arm_boost=1") == ["[pi5]"]
        assert _section_of(after, "arm_boost=1") == ["[pi5]"]
        assert _section_of(after, "arm_freq=2400") == ["[pi5]"]

    def test_another_value_under_all_comes_back_under_all(self, tmp_path):
        config = "arm_boost=1\n\n[all]\narm_freq=1000\nforce_turbo=1\n"
        _a, _c, after, _cmd, record, _rec = _round_trip(tmp_path, config, BASE_CMDLINE + "\n")
        assert "CONFIG=all:arm_freq:1000" in record and "CONFIG=all:force_turbo:1" in record
        assert _section_of(after, "arm_freq=1000") == ["[all]"]
        assert _section_of(after, "force_turbo=1") == ["[all]"]
        assert _section_of(after, "arm_boost=1") == [None]

    def test_a_value_equal_to_the_modes_own_but_outside_any_section_is_put_back(self, tmp_path):
        config = "arm_freq=700\n\n[all]\n"
        _a, _c, after, _cmd, record, _rec = _round_trip(tmp_path, config, BASE_CMDLINE + "\n")
        assert "CONFIG=top:arm_freq:700" in record
        assert _section_of(after, "arm_freq=700") == [None]

    def test_a_file_with_no_all_section_gets_its_top_line_back_once(self, tmp_path):
        config = "dtparam=audio=on\narm_boost=1\n"
        _a, _c, after, _cmd, record, _rec = _round_trip(tmp_path, config, BASE_CMDLINE + "\n")
        assert _section_of(after, "arm_boost=1") == [None]
        assert after.count("arm_boost") == 1

    def test_a_maxcpus_value_other_than_two_comes_back(self, tmp_path):
        cmdline = "console=tty1 maxcpus=4 rootwait\n"
        _a, applied_cmd, _after, cmd_after, record, _rec = _round_trip(tmp_path, OS_STOCK_CONFIG, cmdline)
        assert "maxcpus=2" in applied_cmd and "maxcpus=4" not in applied_cmd
        assert "MAXCPUS=4" in record
        assert cmd_after == "console=tty1 maxcpus=4 rootwait\n"

    def test_a_maxcpus_the_mode_added_is_removed(self, tmp_path):
        _a, _c, _after, cmd_after, record, _rec = _round_trip(tmp_path, OS_STOCK_CONFIG, BASE_CMDLINE + "\n")
        assert "MAXCPUS=" not in record
        assert cmd_after == BASE_CMDLINE + "\n"

    def test_a_maxcpus_of_two_already_there_cannot_be_told_from_the_modes_and_goes(self, tmp_path):
        _a, _c, _after, cmd_after, record, _rec = _round_trip(tmp_path, OS_STOCK_CONFIG, "rootwait maxcpus=2\n")
        assert "MAXCPUS=" not in record
        assert cmd_after == "rootwait\n"

    def test_a_later_run_does_not_replace_the_record_with_the_modes_own_lines(self, tmp_path):
        # The second pass finds the mode's own lines under [all]; the record stays as it was.
        _a, _c, after, _cmd, record, _rec = _round_trip(
            tmp_path, OS_STOCK_CONFIG, "console=tty1 maxcpus=4\n", record_twice_with="")
        assert "CONFIG=top:arm_boost:1" in record
        assert _section_of(after, "arm_boost=1") == [None]

    def test_a_record_that_is_there_is_never_made_again_even_when_it_is_empty(self, tmp_path):
        rec = tmp_path / "state" / "low-power-restore.env"
        cfg = _write(tmp_path / "config.txt", "[all]\n")
        cmd = _write(tmp_path / "cmdline.txt", "rootwait\n")
        call = f'record_low_power_originals "{cfg.as_posix()}" "{cmd.as_posix()}" "{rec.as_posix()}"'
        _bash(f'source "{STATE_LIB.as_posix()}"\n{call}', tmp_path)
        assert rec.exists()
        _write(cfg, "arm_boost=1\n[all]\n")
        _bash(f'source "{STATE_LIB.as_posix()}"\n{call}', tmp_path)
        assert "CONFIG=" not in _text(rec)

    @posix_only
    def test_the_record_is_private_to_root(self, tmp_path):
        cfg = _write(tmp_path / "c2.txt", OS_STOCK_CONFIG)
        cmd = _write(tmp_path / "m2.txt", BASE_CMDLINE + "\n")
        rec = tmp_path / "state2" / "r.env"
        _bash(f'source "{STATE_LIB.as_posix()}"\nrecord_low_power_originals '
              f'"{cfg.as_posix()}" "{cmd.as_posix()}" "{rec.as_posix()}"', tmp_path)
        assert rec.stat().st_mode & 0o777 == 0o600

    def test_the_record_is_removed_once_it_has_been_used(self, tmp_path):
        *_x, rec = _round_trip(tmp_path, OS_STOCK_CONFIG, BASE_CMDLINE + "\n")
        assert not rec.exists()


@bash_capable
class TestTheRecordIsOnlyTrustedForWhatTheInstallerWrites:
    def _remove(self, tmp_path: Path, record_text, *, link: bool = False):
        cfg = _write(tmp_path / "config.txt", "[all]\narm_boost=0\n")
        cmd = _write(tmp_path / "cmdline.txt", "rootwait maxcpus=2\n")
        rec = tmp_path / "low-power-restore.env"
        if link:
            target = _write(tmp_path / "target.env", record_text or "")
            rec.symlink_to(target)
        elif record_text is not None:
            _write(rec, record_text)
        r = _bash(f'remove_low_power_settings "{cfg.as_posix()}" "{cmd.as_posix()}" "{rec.as_posix()}"',
                  tmp_path)
        assert r.returncode == 0, r.stderr
        return _text(cfg), _text(cmd)

    @pytest.mark.parametrize("bad", [
        "CONFIG=top:evil_key:1\n",
        "CONFIG=top:arm_boost:1; touch /tmp/x\n",
        "CONFIG=top:arm_boost:\n",
        "CONFIG=top:arm_boost:one\n",
        "CONFIG=other:arm_boost:1\n",
        "CONFIG=all:arm_boost:1 \n",
        "arm_boost=1\n",
        "MAXCPUS=four\n",
        "MAXCPUS=4 root=/dev/sda1\n",
        "MAXCPUS=\n",
    ])
    def test_a_line_that_is_not_one_of_the_forms_it_writes_is_ignored(self, tmp_path, bad):
        cfg, cmd = self._remove(tmp_path, "# note\n" + bad)
        assert "arm_boost=1" not in cfg and "evil" not in cfg and "touch" not in cfg
        assert cmd == "rootwait\n"

    def test_a_good_line_among_bad_ones_is_still_used(self, tmp_path):
        cfg, cmd = self._remove(tmp_path, "CONFIG=top:evil:1\nCONFIG=top:arm_boost:1\nMAXCPUS=3\n")
        assert _section_of(cfg, "arm_boost=1") == [None]
        assert cmd == "rootwait maxcpus=3\n"

    @posix_only
    def test_a_record_that_is_a_link_is_not_followed(self, tmp_path):
        cfg, cmd = self._remove(tmp_path, "CONFIG=top:arm_boost:1\nMAXCPUS=3\n", link=True)
        assert "arm_boost=1" not in cfg
        assert cmd == "rootwait\n"

    def test_without_a_record_only_the_added_lines_go(self, tmp_path):
        cfg, cmd = self._remove(tmp_path, None)
        assert "arm_boost" not in cfg
        assert cmd == "rootwait\n"


class TestInstallerWiring:
    def test_text_check_the_originals_are_noted_before_config_txt_is_changed_and_only_in_the_mode(self):
        text = INSTALLER.read_text(encoding="utf-8")
        i = text.index("    record_low_power_originals\n")
        assert text.rindex('if [[ "${LOW_POWER}" == "1" ]]', 0, i) > i - 200
        assert i < text.index("\n  update_pi_firmware_config\n")
