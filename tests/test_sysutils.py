"""Priority 8 — autostream_sysutils tests.

Covers atomic_write_file (mode preservation, temp cleanup, fsync, atomic
replace), run_cmd (timeout, exception), run_admin_cmd (sudo args), reboot
helpers, factory_reset_system, set_system_hostname, get_install_state,
and get_sdcard_health_percent/_parse_sdcard_health_percent.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_sysutils as su


# ---------------------------------------------------------------------------
# atomic_write_file
# ---------------------------------------------------------------------------

class TestAtomicWriteFile:
    def test_file_created_with_correct_content(self, tmp_path):
        target = tmp_path / "output.txt"

        def writer(fh):
            fh.write("hello world")

        su.atomic_write_file(target, writer)
        assert target.read_text(encoding="utf-8") == "hello world"

    def test_file_created_without_preexisting(self, tmp_path):
        target = tmp_path / "new.txt"
        su.atomic_write_file(target, lambda fh: fh.write("x"))
        assert target.exists()

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes not enforced on Windows")
    def test_mode_preserved_from_existing_file(self, tmp_path):
        target = tmp_path / "existing.txt"
        target.write_text("old")
        os.chmod(target, 0o600)

        su.atomic_write_file(target, lambda fh: fh.write("new"))

        mode = oct(target.stat().st_mode)[-3:]
        assert mode == "600"

    def test_parent_directory_created(self, tmp_path):
        target = tmp_path / "subdir" / "deeply" / "nested.txt"
        su.atomic_write_file(target, lambda fh: fh.write("content"))
        assert target.exists()

    def test_temp_file_cleaned_up_after_error(self, tmp_path):
        target = tmp_path / "output.txt"

        def failing_writer(fh):
            raise OSError("simulated disk full")

        with pytest.raises(OSError, match="simulated disk full"):
            su.atomic_write_file(target, failing_writer)

        tmp_files = list(tmp_path.glob(f".{target.name}.*.tmp"))
        assert not tmp_files, "temporary file should be removed after write error"

    def test_target_not_replaced_if_write_fails(self, tmp_path):
        target = tmp_path / "output.txt"
        target.write_text("original")

        def failing_writer(fh):
            raise OSError("write error")

        with pytest.raises(OSError):
            su.atomic_write_file(target, failing_writer)

        assert target.read_text() == "original"

    def test_fsync_is_called(self, tmp_path):
        target = tmp_path / "output.txt"
        fsync_calls = []
        real_fsync = os.fsync

        def tracking_fsync(fd):
            fsync_calls.append(fd)
            real_fsync(fd)

        with patch("os.fsync", side_effect=tracking_fsync):
            su.atomic_write_file(target, lambda fh: fh.write("data"))

        assert fsync_calls, "os.fsync must be called"

    def test_replace_is_called(self, tmp_path):
        target = tmp_path / "output.txt"
        replace_calls = []
        real_replace = os.replace

        def tracking_replace(src, dst):
            replace_calls.append((src, dst))
            real_replace(src, dst)

        with patch("os.replace", side_effect=tracking_replace):
            su.atomic_write_file(target, lambda fh: fh.write("data"))

        assert replace_calls, "os.replace must be called for atomic rename"
        # destination must be the target path
        assert Path(replace_calls[0][1]) == target


# ---------------------------------------------------------------------------
# run_cmd: timeout and exception normalization
# ---------------------------------------------------------------------------

class TestRunCmd:
    def test_successful_command_returns_zero(self):
        result = su.run_cmd([sys.executable, "-c", "pass"])
        assert result.returncode == 0

    def test_timeout_returns_rc_124(self):
        import subprocess
        with patch("subprocess.run",
                   side_effect=subprocess.TimeoutExpired(["cmd"], 1)):
            result = su.run_cmd(["sleep", "100"], timeout=0.001)
        assert result.returncode == 124

    def test_exception_returns_rc_1(self):
        with patch("subprocess.run", side_effect=OSError("os error")):
            result = su.run_cmd(["cmd"])
        assert result.returncode == 1

    def test_log_cmd_used_for_display_not_execution(self):
        import subprocess
        ran_cmds = []

        def fake_run(cmd, **kw):
            ran_cmds.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run):
            su.run_cmd(["real", "cmd"], log_cmd=["safe", "log"])

        assert ran_cmds[0] == ["real", "cmd"]


# ---------------------------------------------------------------------------
# startup static system facts
# ---------------------------------------------------------------------------

class TestOsReleaseInfo:
    def test_parses_expected_fields(self, tmp_path):
        f = tmp_path / "os-release"
        f.write_text(
            'PRETTY_NAME="Raspberry Pi OS GNU/Linux 13 (trixie)"\n'
            'VERSION_ID="13"\n'
            "VERSION_CODENAME=trixie\n",
            encoding="utf-8",
        )
        result = su.get_os_release_info(f)
        assert result == {
            "pretty_name": "Raspberry Pi OS GNU/Linux 13 (trixie)",
            "version_id": "13",
            "version_codename": "trixie",
        }

    def test_missing_file_returns_unknowns(self, tmp_path):
        result = su.get_os_release_info(tmp_path / "missing")
        assert result == {
            "pretty_name": "unknown",
            "version_id": "unknown",
            "version_codename": "unknown",
        }


class TestNginxVersion:
    def test_parses_stderr_version(self):
        import subprocess
        cp = subprocess.CompletedProcess(
            ["nginx", "-v"],
            0,
            stdout="",
            stderr="nginx version: nginx/1.22.1\n",
        )
        with patch.object(su, "run_cmd", return_value=cp) as m_run:
            assert su.get_nginx_version() == "nginx/1.22.1"
        m_run.assert_called_once_with(
            ["nginx", "-v"],
            timeout=2.0,
            warn_on_failure=False,
        )

    def test_nonzero_returns_unknown(self):
        import subprocess
        cp = subprocess.CompletedProcess(["nginx", "-v"], 1, stdout="", stderr="nope")
        with patch.object(su, "run_cmd", return_value=cp):
            assert su.get_nginx_version() == "unknown"


class TestStaticSystemFactsAudit:
    def teardown_method(self):
        su._static_system_facts = None

    def test_get_static_system_facts_defaults_to_unknowns(self):
        su._static_system_facts = None
        assert su.get_static_system_facts() == su.StaticSystemFacts()

    def test_audit_collects_stores_and_logs_facts(self):
        with patch.object(su, "get_os_release_info", return_value={
                "pretty_name": "Raspberry Pi OS GNU/Linux 13 (trixie)",
                "version_id": "13",
                "version_codename": "trixie",
             }), \
             patch.object(su, "get_nginx_version", return_value="nginx/1.22.1"), \
             patch("autostream_rpi.get_raspberry_pi_model",
                   return_value="Raspberry Pi 4 Model B Rev 1.5"), \
             patch.object(su.logger, "info") as m_info:
            facts = su.audit_static_system_facts()

        assert facts == su.StaticSystemFacts(
            os_pretty_name="Raspberry Pi OS GNU/Linux 13 (trixie)",
            os_version_id="13",
            os_version_codename="trixie",
            raspberry_pi_model="Raspberry Pi 4 Model B Rev 1.5",
            nginx_version="nginx/1.22.1",
        )
        assert su.get_static_system_facts() == facts
        assert m_info.call_count == 3


# ---------------------------------------------------------------------------
# run_admin_cmd: sudo wrapping
# ---------------------------------------------------------------------------

class TestRunAdminCmd:
    def test_cmd_includes_sudo_n(self):
        import subprocess
        ran_cmds = []

        def fake_run(cmd, **kw):
            ran_cmds.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")

        with patch("subprocess.run", side_effect=fake_run):
            su.run_admin_cmd(["update-status"])

        cmd = ran_cmds[0]
        assert cmd[0] == "sudo"
        assert "-n" in cmd
        assert "update-status" in cmd

    def test_admin_bin_env_override(self):
        import subprocess
        ran_cmds = []

        def fake_run(cmd, **kw):
            ran_cmds.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        with patch.object(su, "AUTOSTREAM_ADMIN_BIN", "/custom/admin"), \
             patch("subprocess.run", side_effect=fake_run):
            su.run_admin_cmd(["status"])

        assert "/custom/admin" in ran_cmds[0]


# ---------------------------------------------------------------------------
# reboot_system
# ---------------------------------------------------------------------------

class TestRebootSystem:
    def test_reboot_calls_run_admin_cmd_with_reboot(self):
        import subprocess
        called_args = []

        def fake_admin(args, timeout=None):
            called_args.append(args)
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

        with patch.object(su, "run_admin_cmd", side_effect=fake_admin):
            su.reboot_system("UserRequestNormal")

        assert called_args, "run_admin_cmd must be called"
        assert "reboot" in called_args[0]
        assert "UserRequestNormal" in called_args[0]

    def test_reboot_with_delay_passes_delay_args(self):
        import subprocess
        called_args = []

        def fake_admin(args, timeout=None):
            called_args.append(args)
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

        with patch.object(su, "run_admin_cmd", side_effect=fake_admin):
            su.reboot_system("UserRequestNormal", delay_s=30)

        flat = called_args[0]
        assert "--delay" in flat
        assert "30" in flat

    def test_empty_reason_defaults_to_UserRequestNormal(self):
        import subprocess
        called_args = []

        def fake_admin(args, timeout=None):
            called_args.append(args)
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

        with patch.object(su, "run_admin_cmd", side_effect=fake_admin):
            su.reboot_system("")

        assert "UserRequestNormal" in called_args[0]


# ---------------------------------------------------------------------------
# factory_reset_system
# ---------------------------------------------------------------------------

class TestFactoryResetSystem:
    def test_success_does_not_raise(self):
        import subprocess

        def fake_admin(args, timeout=None):
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

        with patch.object(su, "run_admin_cmd", side_effect=fake_admin):
            su.factory_reset_system()

    def test_failure_raises_runtime_error(self):
        import subprocess

        def fake_admin(args, timeout=None):
            return subprocess.CompletedProcess(args, 1, stdout="", stderr="failed")

        with patch.object(su, "run_admin_cmd", side_effect=fake_admin):
            with pytest.raises(RuntimeError, match="Factory reset scheduling failed"):
                su.factory_reset_system()


# ---------------------------------------------------------------------------
# set_system_hostname
# ---------------------------------------------------------------------------

class TestSetSystemHostname:
    def test_valid_hostname_calls_admin(self):
        import subprocess
        called_args = []

        def fake_admin(args, timeout=None):
            called_args.append(args)
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

        with patch.object(su, "run_admin_cmd", side_effect=fake_admin):
            su.set_system_hostname("autostream-01")

        assert any("sethostname" in str(a) and "autostream-01" in str(a)
                   for a in called_args)

    def test_invalid_hostname_raises_value_error(self):
        with pytest.raises(ValueError, match="Invalid hostname"):
            su.set_system_hostname("bad..hostname")

    def test_empty_hostname_is_noop(self):
        called = []
        with patch.object(su, "run_admin_cmd",
                          side_effect=lambda *a, **kw: called.append(a)):
            su.set_system_hostname("   ")
        assert not called

    def test_admin_failure_raises_runtime_error(self):
        import subprocess

        def fake_admin(args, timeout=None):
            return subprocess.CompletedProcess(args, 1, stdout="", stderr="err")

        with patch.object(su, "run_admin_cmd", side_effect=fake_admin):
            with pytest.raises(RuntimeError):
                su.set_system_hostname("valid-host")


# ---------------------------------------------------------------------------
# get_install_state: KEY=VALUE parsing
# ---------------------------------------------------------------------------

class TestGetInstallState:
    def test_parses_unquoted_values(self, tmp_path):
        f = tmp_path / "state.env"
        f.write_text("KEY=value\nFOO=bar\n", encoding="utf-8")
        result = su.get_install_state(f)
        assert result == {"KEY": "value", "FOO": "bar"}

    def test_strips_double_quotes(self, tmp_path):
        f = tmp_path / "state.env"
        f.write_text('KEY="quoted value"\n', encoding="utf-8")
        result = su.get_install_state(f)
        assert result["KEY"] == "quoted value"

    def test_strips_single_quotes(self, tmp_path):
        f = tmp_path / "state.env"
        f.write_text("KEY='quoted'\n", encoding="utf-8")
        result = su.get_install_state(f)
        assert result["KEY"] == "quoted"

    def test_skips_comment_lines(self, tmp_path):
        f = tmp_path / "state.env"
        f.write_text("# comment\nKEY=val\n", encoding="utf-8")
        result = su.get_install_state(f)
        assert "#" not in str(result)

    def test_skips_blank_lines(self, tmp_path):
        f = tmp_path / "state.env"
        f.write_text("\nKEY=val\n\n", encoding="utf-8")
        result = su.get_install_state(f)
        assert result == {"KEY": "val"}

    def test_missing_file_returns_empty(self, tmp_path):
        result = su.get_install_state(tmp_path / "nonexistent.env")
        assert result == {}


# ---------------------------------------------------------------------------
# _parse_sdcard_health_percent / get_sdcard_health_percent
# ---------------------------------------------------------------------------

class TestParseSDCardHealthPercent:
    def test_endurance_remaining_parsed(self):
        data = {"success": True, "enduranceRemainLifePercent": 75}
        result = su._parse_sdcard_health_percent(data)
        assert result == 75

    def test_health_status_percent_used_parsed(self):
        data = {"success": True, "healthStatusPercentUsed": 40}
        result = su._parse_sdcard_health_percent(data)
        assert result == 60

    def test_success_false_returns_none(self):
        data = {"success": False, "enduranceRemainLifePercent": 75}
        assert su._parse_sdcard_health_percent(data) is None

    def test_missing_success_key_returns_none(self):
        data = {"enduranceRemainLifePercent": 75}
        assert su._parse_sdcard_health_percent(data) is None

    def test_out_of_range_above_returns_none(self):
        data = {"success": True, "enduranceRemainLifePercent": 150}
        assert su._parse_sdcard_health_percent(data) is None

    def test_out_of_range_below_returns_none(self):
        data = {"success": True, "enduranceRemainLifePercent": -5}
        assert su._parse_sdcard_health_percent(data) is None

    def test_result_clamped_at_zero(self):
        data = {"success": True, "healthStatusPercentUsed": 100.1}
        result = su._parse_sdcard_health_percent(data)
        assert result == 0

    def test_result_clamped_at_100(self):
        data = {"success": True, "healthStatusPercentUsed": -0.1}
        result = su._parse_sdcard_health_percent(data)
        assert result == 100

    def test_non_numeric_endurance_returns_none(self):
        data = {"success": True, "enduranceRemainLifePercent": "n/a"}
        assert su._parse_sdcard_health_percent(data) is None

    def test_get_sdcard_health_percent_no_file_returns_none(self, tmp_path):
        missing = tmp_path / "sdcardhealth.json"
        with patch.object(su, "SDCARD_HEALTH_JSON_FILE", missing):
            result = su.get_sdcard_health_percent()
        assert result is None

    def test_get_sdcard_health_percent_valid_file(self, tmp_path):
        import json
        health_file = tmp_path / "sdcardhealth.json"
        health_file.write_text(
            json.dumps({"success": True, "enduranceRemainLifePercent": 80}),
            encoding="utf-8",
        )
        with patch.object(su, "SDCARD_HEALTH_JSON_FILE", health_file):
            result = su.get_sdcard_health_percent()
        assert result == 80

    def test_get_sdcard_health_percent_malformed_json_returns_none(self, tmp_path):
        health_file = tmp_path / "sdcardhealth.json"
        health_file.write_text("not-json", encoding="utf-8")
        with patch.object(su, "SDCARD_HEALTH_JSON_FILE", health_file):
            result = su.get_sdcard_health_percent()
        assert result is None
