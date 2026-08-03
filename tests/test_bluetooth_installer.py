"""Bluetooth input — installer / system layer tests.

Scope: OS/kernel config, systemd unit, installer wiring for the Bluetooth
input subsystem. Static/text-level checks mirroring tests/test_p3_installer.py
and tests/test_installer_ownership.py, plus a few functional bash round-trips
(bash -c sourcing the real scripts) for the hardware.sh firmware function.

The subsystem is always installed (apt packages, snd-aloop/BlueZ config, the
systemd unit) but the unit is installed disabled and not started; enabling it
(and, separately, the onboard radio) is a later, privileged runtime action
outside the scope of these installer tests.

Environment-dependent (not run here): actually installing packages, loading
snd-aloop, pairing hardware.
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


def _shellcheck_ok() -> bool:
    try:
        return subprocess.run(
            ["shellcheck", "--version"], capture_output=True, timeout=5
        ).returncode == 0
    except Exception:
        return False


shellcheck_available = pytest.mark.skipif(
    not _shellcheck_ok(),
    reason="shellcheck not installed — run in CI (apt-get install shellcheck)",
)

root_capable = pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="requires root",
)

INSTALL_SH = REPO_ROOT / "autostream_install.sh"
UNINSTALL_SH = REPO_ROOT / "autostream_uninstall.sh"
BLUETOOTH_SH = REPO_ROOT / "installer" / "lib" / "bluetooth.sh"
HARDWARE_SH = REPO_ROOT / "installer" / "lib" / "hardware.sh"
UNIT_FILE = REPO_ROOT / "system" / "systemd" / "autostream_bluetooth.service"
MODULES_LOAD_FILE = REPO_ROOT / "system" / "modules-load.d" / "autostream-bluetooth.conf"
MODPROBE_FILE = REPO_ROOT / "system" / "modprobe.d" / "autostream-bluetooth.conf"
BLUEZ_CONF_FILE = REPO_ROOT / "system" / "bluetooth" / "autostream.conf"

BLUETOOTH_SCRIPTS = [BLUETOOTH_SH]


def _src(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _extract_function(src: str, name: str) -> str:
    """Pull a single top-level bash function's full text (signature through
    its closing brace) out of installer source, so test harnesses can run the
    REAL current function body rather than a hand-maintained duplicate that
    can silently drift out of sync with it."""
    m = re.search(re.escape(name) + r"\(\)\s*\{.*?\n\}\n", src, re.S)
    assert m is not None, f"could not locate function {name}() in source"
    return m.group(0)


# ---------------------------------------------------------------------------
# bash -n syntax + shellcheck (bluetooth.sh is not yet in test_p3_installer's
# static list, so re-assert it here; also re-check the files that library is
# spliced into so a regression is caught locally)
# ---------------------------------------------------------------------------

class TestShellSyntax:
    @bash_capable
    @pytest.mark.parametrize(
        "script",
        [INSTALL_SH, UNINSTALL_SH, BLUETOOTH_SH, HARDWARE_SH],
        ids=lambda p: p.name,
    )
    def test_bash_n_syntax(self, script):
        result = subprocess.run(
            ["bash", "-n", str(script)],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0, (
            f"bash -n failed for {script.name}:\n{result.stderr.strip()}"
        )

    @shellcheck_available
    @pytest.mark.parametrize("script", BLUETOOTH_SCRIPTS, ids=lambda p: p.name)
    def test_shellcheck(self, script):
        result = subprocess.run(
            ["shellcheck", "--severity=error", str(script)],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0, (
            f"shellcheck errors in {script.name}:\n{result.stdout}"
        )


# ---------------------------------------------------------------------------
# --bluetooth flag is retired: it must no longer appear anywhere in the
# installer's argument handling.
# ---------------------------------------------------------------------------

class TestBluetoothFlagRetired:
    def _src(self) -> str:
        return _src(INSTALL_SH)

    def test_no_bluetooth_flag_case_in_parse_args(self):
        src = self._src()
        assert "--bluetooth=*)" not in src
        assert "--bluetooth)" not in src

    def test_no_is_valid_bluetooth_mode(self):
        assert "is_valid_bluetooth_mode" not in self._src()

    def test_no_bluetooth_mode_global(self):
        src = self._src()
        assert "BLUETOOTH_MODE" not in src
        assert "BLUETOOTH_MODE_EXPLICIT" not in src

    def test_no_resolve_or_apply_or_previous_mode_helpers(self):
        src = self._src()
        assert "resolve_bluetooth_mode_default" not in src
        assert "apply_bluetooth_mode" not in src
        assert "_previous_bluetooth_mode" not in src

    def test_usage_does_not_document_bluetooth_flag(self):
        src = self._src()
        assert "--bluetooth=" not in src
        assert "--bluetooth <" not in src


# ---------------------------------------------------------------------------
# hardware.sh — update_pi_firmware_config: fresh installs write disable-bt;
# updates preserve the line's current presence/absence (the line is the
# onboard-radio setting's only store — the Setup toggle edits it in place)
# ---------------------------------------------------------------------------

class TestFirmwareConfigOnboardBtStance:
    # hardware.sh's update_pi_firmware_config() accepts optional path and
    # mode arguments (defaulting to the real /boot/firmware/config.txt and
    # the installer's INSTALL_MODE for all production callsites)
    # specifically so these tests can source and invoke the REAL function
    # against a temp file, rather than maintaining a hand-copied duplicate
    # of its logic that could silently drift out of sync with
    # installer/lib/hardware.sh.
    def _run_firmware_config(self, tmp_path, pre_existing: str = "",
                             mode: str = "install") -> str:
        cfg = tmp_path / "config.txt"
        cfg.write_text(pre_existing, encoding="utf-8")
        script = f'''
set -euo pipefail
info() {{ :; }}
warn() {{ :; }}
error() {{ :; }}
source "{HARDWARE_SH.as_posix()}"
update_pi_firmware_config "{cfg.as_posix()}" "{mode}"
cat "{cfg.as_posix()}"
'''
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=10)
        assert r.returncode == 0, r.stderr
        return r.stdout

    @bash_capable
    def test_install_all_section_present_writes_disable_bt(self, tmp_path):
        out = self._run_firmware_config(tmp_path, "[all]\n", mode="install")
        assert "dtoverlay=disable-bt" in out
        assert "dtparam=watchdog=on" in out

    @bash_capable
    def test_install_all_section_absent_writes_disable_bt(self, tmp_path):
        out = self._run_firmware_config(tmp_path, "", mode="install")
        assert "dtoverlay=disable-bt" in out
        assert "dtparam=watchdog=on" in out
        assert "[all]" in out

    @bash_capable
    def test_pre_existing_disable_bt_line_deduplicated(self, tmp_path):
        out = self._run_firmware_config(
            tmp_path, "[all]\ndtparam=watchdog=on\ndtoverlay=disable-bt\n",
            mode="install",
        )
        assert out.count("dtoverlay=disable-bt") == 1

    @bash_capable
    def test_update_preserves_present_disable_bt(self, tmp_path):
        out = self._run_firmware_config(
            tmp_path, "[all]\ndtoverlay=disable-bt\n", mode="update",
        )
        assert out.count("dtoverlay=disable-bt") == 1
        assert "dtparam=watchdog=on" in out

    @bash_capable
    def test_update_preserves_absent_disable_bt(self, tmp_path):
        # The appliance opted in to the onboard radio (Setup toggle removed
        # the line); an update must not silently revert that choice.
        out = self._run_firmware_config(tmp_path, "[all]\n", mode="update")
        assert "dtoverlay=disable-bt" not in out
        assert "dtparam=watchdog=on" in out

    @bash_capable
    def test_update_preserves_absence_without_all_section(self, tmp_path):
        out = self._run_firmware_config(tmp_path, "arm_64bit=1\n", mode="update")
        assert "dtoverlay=disable-bt" not in out
        assert "dtparam=watchdog=on" in out
        assert "[all]" in out

    @bash_capable
    def test_mode_defaults_to_install_semantics_when_unset(self, tmp_path):
        # Production callsites pass no mode; with INSTALL_MODE unset the
        # function falls back to the fresh-install stance.
        cfg = tmp_path / "config.txt"
        cfg.write_text("[all]\n", encoding="utf-8")
        script = f'''
set -euo pipefail
info() {{ :; }}
warn() {{ :; }}
error() {{ :; }}
source "{HARDWARE_SH.as_posix()}"
update_pi_firmware_config "{cfg.as_posix()}"
cat "{cfg.as_posix()}"
'''
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=10)
        assert r.returncode == 0, r.stderr
        assert "dtoverlay=disable-bt" in r.stdout

    @bash_capable
    def test_install_mode_env_update_preserves_absence(self, tmp_path):
        # Production update callsites pass no arguments: the installer's own
        # INSTALL_MODE global must select the preserving behaviour.
        cfg = tmp_path / "config.txt"
        cfg.write_text("[all]\n", encoding="utf-8")
        script = f'''
set -euo pipefail
info() {{ :; }}
warn() {{ :; }}
error() {{ :; }}
INSTALL_MODE="update"
source "{HARDWARE_SH.as_posix()}"
update_pi_firmware_config "{cfg.as_posix()}"
cat "{cfg.as_posix()}"
'''
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=10)
        assert r.returncode == 0, r.stderr
        assert "dtoverlay=disable-bt" not in r.stdout

    def test_no_bluetooth_mode_conditional_in_source(self):
        src = _src(HARDWARE_SH)
        assert "BLUETOOTH_MODE" not in src

    def test_is_zero_class_board_removed(self):
        # Fully unused now that the installer no longer prints a Zero-class
        # warning at install time; removed along with its tests.
        src = _src(HARDWARE_SH)
        assert "is_zero_class_board" not in src


# ---------------------------------------------------------------------------
# installer/lib/bluetooth.sh — pinned constants + always-install public API
# ---------------------------------------------------------------------------

class TestBluetoothLib:
    def _src(self) -> str:
        return _src(BLUETOOTH_SH)

    def test_pinned_card_id(self):
        assert 'BLUETOOTH_LOOPBACK_CARD_ID="ASBT"' in self._src()

    def test_pinned_unit_name(self):
        assert 'BLUETOOTH_UNIT_NAME="autostream_bluetooth.service"' in self._src()

    def test_install_function_present(self):
        assert "install_bluetooth_stack()" in self._src()

    def test_remove_function_present(self):
        assert "remove_bluetooth_stack()" in self._src()

    def test_install_installs_required_packages(self):
        src = self._src()
        m = re.search(r"^install_bluetooth_stack\(\)\s*\{.*?\n\}\n", src, re.S | re.M)
        assert m is not None
        body = m.group(0)
        for pkg in ["bluez", "bluez-alsa-utils", "python3-dbus", "python3-gi", "python3-alsaaudio"]:
            assert pkg in body, f"install_bluetooth_stack must apt_install {pkg}"

    def test_install_modprobes_snd_aloop_immediately(self):
        src = self._src()
        m = re.search(r"^install_bluetooth_stack\(\)\s*\{.*?\n\}\n", src, re.S | re.M)
        assert "modprobe snd-aloop" in m.group(0)

    def test_install_adds_user_to_bluetooth_group(self):
        src = self._src()
        m = re.search(r"^install_bluetooth_stack\(\)\s*\{.*?\n\}\n", src, re.S | re.M)
        assert "ensure_user_in_group autostream bluetooth" in m.group(0)

    def test_install_does_not_enable_or_start_the_unit(self):
        """The unit is installed disabled and not started at install time --
        enablement is a separate, later, privileged runtime action."""
        src = self._src()
        assert not re.search(r"enable\s+--now\s+.*autostream_bluetooth", src)
        assert "systemctl daemon-reload" in src

    def test_install_does_not_enable_stock_bluetooth_services(self):
        """Enabling the stock bluetooth/bluealsa(d) services also moves to
        the runtime enablement action; the installer must not touch them."""
        src = self._src()
        assert not re.search(r"enable\s+--now\s+bluetooth\b", src)
        assert not re.search(r"enable\s+--now\s+bluealsa", src)
        assert "systemctl unmask bluetooth" not in src

    def test_install_disables_bluealsa_aplay(self):
        src = self._src()
        m = re.search(r"^install_bluetooth_stack\(\)\s*\{.*?\n\}\n", src, re.S | re.M)
        assert m is not None
        assert "bluealsa-aplay.service" in m.group(0)
        assert re.search(r"disable\s+--now\s+bluealsa-aplay\.service", m.group(0))

    def test_remove_does_not_call_firmware_config(self):
        """Firmware disable-bt is now unconditional, so remove_bluetooth_stack
        no longer needs to touch it."""
        src = self._src()
        m = re.search(r"^remove_bluetooth_stack\(\)\s*\{.*?\n\}\n", src, re.S | re.M)
        assert m is not None
        assert "update_pi_firmware_config" not in m.group(0)

    def test_remove_does_not_apt_remove_packages(self):
        src = self._src()
        m = re.search(r"^remove_bluetooth_stack\(\)\s*\{.*?\n\}\n", src, re.S | re.M)
        assert "apt-get remove" not in m.group(0) and "apt_remove" not in m.group(0)

    def test_no_bluetooth_mode_state_helper(self):
        src = self._src()
        assert "_set_bluetooth_mode_in_state" not in src
        assert "BLUETOOTH_MODE" not in src

    def test_daemon_entry_module_pinned(self):
        assert "bluetooth_service.py" in self._src()


# ---------------------------------------------------------------------------
# _copy_bluetooth_daemon_files — module set must be discovered by globbing
# the source checkout, not hand-listed, so a newly added platform/
# bluetooth_*.py module is never silently left undeployed.
# ---------------------------------------------------------------------------

class TestBluetoothDaemonModuleDeployment:
    def _repo_bluetooth_modules(self) -> set:
        platform_dir = REPO_ROOT / "platform"
        return {p.name for p in platform_dir.glob("bluetooth_*.py")}

    @bash_capable
    def test_deploys_every_repo_bluetooth_module(self, tmp_path):
        modules = self._repo_bluetooth_modules()
        assert modules, "expected at least one platform/bluetooth_*.py module in the repo"

        autostream_dir = tmp_path / "src"
        install_dir = tmp_path / "install"
        (autostream_dir / "platform").mkdir(parents=True)
        for name in modules:
            (autostream_dir / "platform" / name).write_text("# stub\n", encoding="utf-8")
        # A non-.py sibling must not be swept up by the glob.
        (autostream_dir / "platform" / "bluetooth_notes.txt").write_text("x", encoding="utf-8")

        script = f'''
set -euo pipefail
info() {{ :; }}
warn() {{ :; }}
error() {{ :; }}
# Unprivileged stand-in for coreutils install(1): copies source to dest,
# ignoring the -m/-o/-g flags this test harness cannot satisfy without root.
install() {{
  local _prev="" _last=""
  local _a
  for _a in "$@"; do _prev=$_last; _last=$_a; done
  cp -- "${{_prev}}" "${{_last}}"
}}
AUTOSTREAM_DIR="{autostream_dir.as_posix()}"
INSTALL_DIR="{install_dir.as_posix()}"
source "{BLUETOOTH_SH.as_posix()}"
_copy_bluetooth_daemon_files
ls "{install_dir.as_posix()}/platform"
'''
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=10)
        assert r.returncode == 0, r.stderr
        deployed = set(r.stdout.split())
        assert deployed == modules, (
            f"deployed set {deployed} does not match repo platform/bluetooth_*.py modules {modules}"
        )

    @bash_capable
    def test_no_matches_warns_and_survives_set_e(self, tmp_path):
        """A source tree with no bluetooth_*.py modules must not trip the
        installer's set -e / ERR trap -- the unmatched glob must expand to
        zero words, never pass a literal '*' pattern through as a filename."""
        autostream_dir = tmp_path / "src"
        install_dir = tmp_path / "install"
        (autostream_dir / "platform").mkdir(parents=True)

        script = f'''
set -euo pipefail
trap 'echo "ERR_TRAP_FIRED" >&2' ERR
info() {{ :; }}
warn() {{ echo "WARN: $*"; }}
error() {{ :; }}
AUTOSTREAM_DIR="{autostream_dir.as_posix()}"
INSTALL_DIR="{install_dir.as_posix()}"
source "{BLUETOOTH_SH.as_posix()}"
_copy_bluetooth_daemon_files
echo "SURVIVED"
'''
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=10)
        assert r.returncode == 0, r.stderr
        assert "ERR_TRAP_FIRED" not in r.stderr
        assert "SURVIVED" in r.stdout
        assert "WARN:" in r.stdout


# ---------------------------------------------------------------------------
# Wiring into autostream_install.sh main flow
# ---------------------------------------------------------------------------

class TestInstallerWiring:
    def _src(self) -> str:
        return _src(INSTALL_SH)

    def test_sources_bluetooth_lib(self):
        assert 'source "${INSTALLER_LIB}/bluetooth.sh"' in self._src()

    def test_configure_phase_calls_install_bluetooth_stack_unconditionally(self):
        src = self._src()
        m = re.search(r"^configure_phase\(\)\s*\{.*?\n\}\n", src, re.S | re.M)
        assert m is not None
        body = m.group(0)
        assert "install_bluetooth_stack" in body
        # No mode/guard function wrapping the call any more.
        assert "apply_bluetooth_mode" not in body

    def test_install_bluetooth_stack_call_is_unguarded(self):
        """Regression guard: the call site inside configure_phase must be a
        bare statement, not gated behind a mode check."""
        src = self._src()
        m = re.search(r"^configure_phase\(\)\s*\{.*?\n\}\n", src, re.S | re.M)
        assert m is not None
        for line in m.group(0).splitlines():
            if "install_bluetooth_stack" in line:
                assert re.match(r"^\s*install_bluetooth_stack\s*$", line), (
                    f"expected a bare unconditional call, got: {line!r}"
                )


# ---------------------------------------------------------------------------
# Uninstaller — always removes the Bluetooth subsystem (it is always present)
# ---------------------------------------------------------------------------

class TestUninstallerBluetooth:
    def _src(self) -> str:
        return _src(UNINSTALL_SH)

    def test_reads_install_state_before_removal(self):
        src = self._src()
        remove_bt_idx = src.find("remove_bluetooth_if_enabled")
        remove_files_idx = src.find('info "Removing autostream application files"')
        assert remove_bt_idx != -1 and remove_files_idx != -1
        assert remove_bt_idx < remove_files_idx, (
            "Bluetooth removal must run before /var/lib/autostream is deleted"
        )

    def test_sources_bluetooth_lib(self):
        assert "bluetooth.sh" in self._src()

    def test_no_bluetooth_mode_state_read(self):
        src = self._src()
        assert "BLUETOOTH_MODE" not in src
        assert "_installed_bluetooth_mode" not in src

    def test_remove_bluetooth_if_enabled_calls_remove_stack_unconditionally(self):
        src = self._src()
        m = re.search(
            r"remove_bluetooth_if_enabled\(\)\s*\{.*?\n\}\n", src, re.S
        )
        assert m is not None
        body = m.group(0)
        assert "remove_bluetooth_stack" in body
        assert "BLUETOOTH_MODE" not in body

    def test_fallback_removes_unit_and_configs(self):
        src = self._src()
        assert "/etc/systemd/system/autostream_bluetooth.service" in src
        assert "/etc/modules-load.d/autostream-bluetooth.conf" in src
        assert "/etc/modprobe.d/autostream-bluetooth.conf" in src
        assert "/etc/bluetooth/main.conf.d/autostream.conf" in src

    def test_stops_and_disables_bluetooth_service(self):
        assert "stop_and_disable_service autostream_bluetooth.service" in self._src()


# ---------------------------------------------------------------------------
# systemd unit
# ---------------------------------------------------------------------------

class TestBluetoothUnit:
    def test_unit_file_exists(self):
        assert UNIT_FILE.exists()

    def _unit(self) -> str:
        return _src(UNIT_FILE)

    def test_exec_start_references_system_python_and_service_module(self):
        unit = self._unit()
        assert "ExecStart=/opt/autostream/venv/bin/python /opt/autostream/platform/bluetooth_service.py" in unit

    def test_unit_clears_rfkill_block_before_start(self):
        """systemd-rfkill restores persisted per-device block state at boot;
        a stale blocked entry would leave a freshly-created adapter powered
        off with nothing to clear it, so the unit unblocks (as root,
        failure-tolerant) before every daemon start."""
        unit = _src(UNIT_FILE)
        assert "ExecStartPre=-+/usr/sbin/rfkill unblock bluetooth" in unit

    def test_runs_as_autostream_user(self):
        unit = self._unit()
        assert "User=autostream" in unit

    def test_supplementary_groups_bluetooth_and_audio(self):
        unit = self._unit()
        m = re.search(r"^SupplementaryGroups=(.+)$", unit, re.M)
        assert m is not None
        groups = m.group(1).split()
        assert "bluetooth" in groups
        assert "audio" in groups

    def test_after_and_wants_bluetooth_bluealsa(self):
        unit = self._unit()
        after = re.search(r"^After=(.+)$", unit, re.M).group(1)
        wants = re.search(r"^Wants=(.+)$", unit, re.M).group(1)
        for target in ("bluetooth.service", "bluealsa.service"):
            assert target in after
            assert target in wants
        assert "sound.target" in after

    def test_no_hard_requires_on_bluetooth_services(self):
        unit = self._unit()
        assert not re.search(r"^Requires=.*bluetooth", unit, re.M)

    def test_restart_on_failure(self):
        unit = self._unit()
        assert "Restart=on-failure" in unit

    def test_working_directory(self):
        unit = self._unit()
        assert "WorkingDirectory=/opt/autostream" in unit

    def test_wanted_by_multi_user_target(self):
        unit = self._unit()
        assert "WantedBy=multi-user.target" in unit

    def test_no_gitignored_doc_references(self):
        unit = self._unit()
        assert "docs/working" not in unit


# ---------------------------------------------------------------------------
# Module config payloads
# ---------------------------------------------------------------------------

class TestModuleConfigFiles:
    def test_modules_load_file_loads_snd_aloop(self):
        assert MODULES_LOAD_FILE.exists()
        text = _src(MODULES_LOAD_FILE)
        lines = [l for l in text.splitlines() if l and not l.startswith("#")]
        assert lines == ["snd-aloop"]

    def test_modprobe_file_pins_card_options(self):
        assert MODPROBE_FILE.exists()
        text = _src(MODPROBE_FILE)
        assert "options snd-aloop enable=1 index=-2 pcm_substreams=1 id=ASBT" in text

    def test_bluez_main_conf_disables_timeouts(self):
        assert BLUEZ_CONF_FILE.exists()
        text = _src(BLUEZ_CONF_FILE)
        assert "DiscoverableTimeout = 0" in text
        assert "PairableTimeout = 0" in text
