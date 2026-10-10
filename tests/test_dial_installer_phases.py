"""Dial installer update phases: result file writer, phase(), apt_step() and
the system upgrade step.

Functional bash round-trips against a temp result file, following the pattern
in tests/test_dial_installer_spidev_bufsiz.py, plus structural checks on the
installer's phase order.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from conftest import bash_can_run_script_at_windows_path  # noqa: E402

bash_capable = pytest.mark.skipif(
    not bash_can_run_script_at_windows_path(),
    reason="bash cannot execute scripts at this path (MSYS2 limitation on Windows)",
)
posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="file modes are meaningful on POSIX only"
)

REPO_ROOT = Path(__file__).resolve().parents[1]
HELPERS = REPO_ROOT / "installer" / "dial" / "helpers.sh"
INSTALLER = REPO_ROOT / "autostream_dial_install.sh"

LOCK_OUTPUT = "E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 812"


def _bash(tmp_path: Path, body: str, *, bin_dir: Path | None = None,
          update: str = "true", tag: str = "1.3.0"):
    result = tmp_path / "update-result.env"
    state = tmp_path / "install-state.env"
    env = dict(os.environ)
    env["UPDATE_RESULT_FILE"] = result.as_posix()
    env["INSTALL_STATE_FILE"] = state.as_posix()
    env["APT_RETRY_DELAY"] = "0"
    if bin_dir is not None:
        env["PATH"] = bin_dir.as_posix() + os.pathsep + env.get("PATH", "")
    script = (
        f'set -euo pipefail; source "{HELPERS.as_posix()}"; '
        f'UPDATE={update}; AUTOSTREAM_RELEASE_TAG={tag}\n{body}'
    )
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                          timeout=60, env=env)


def _parse(path: Path) -> dict:
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        k, _, v = line.partition("=")
        out[k] = v
    return out


@bash_capable
class TestWriteUpdateResult:
    def test_writes_the_canonical_keys(self, tmp_path):
        r = _bash(tmp_path, 'write_update_result in_progress "Working" 42')
        assert r.returncode == 0, r.stderr
        env = _parse(tmp_path / "update-result.env")
        assert env["STATUS"] == "in_progress"
        assert env["PERCENT_COMPLETE"] == "42"
        assert env["MESSAGE"] == "Working"
        assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00$", env["LAST_RUN_AT"])

    def test_extra_keys_are_written_and_kept_by_the_next_write(self, tmp_path):
        r = _bash(tmp_path, (
            'write_update_result in_progress "a" 5 PHASE=prepare TAG=1.3.0 '
            'PREVIOUS_TAG=1.2.0 ATTEMPT=2 MAX_ATTEMPTS=4 ROLLED_BACK=0\n'
            'write_update_result in_progress "b" 10 PHASE=packages'
        ))
        assert r.returncode == 0, r.stderr
        env = _parse(tmp_path / "update-result.env")
        assert env["PHASE"] == "packages"
        assert env["MESSAGE"] == "b"
        assert (env["TAG"], env["PREVIOUS_TAG"]) == ("1.3.0", "1.2.0")
        assert (env["ATTEMPT"], env["MAX_ATTEMPTS"], env["ROLLED_BACK"]) == ("2", "4", "0")

    def test_empty_value_removes_a_key(self, tmp_path):
        r = _bash(tmp_path, (
            'write_update_result in_progress "a" 5 TRANSIENT_RETRY=1\n'
            'write_update_result in_progress "b" 5 TRANSIENT_RETRY='
        ))
        assert r.returncode == 0, r.stderr
        assert "TRANSIENT_RETRY" not in _parse(tmp_path / "update-result.env")

    def test_unrelated_lines_in_an_old_file_are_dropped(self, tmp_path):
        (tmp_path / "update-result.env").write_text(
            "STATUS=success\nMESSAGE=old\nJUNK=1\nTAG=1.1.0\n", encoding="utf-8")
        r = _bash(tmp_path, 'write_update_result in_progress "new" 0')
        assert r.returncode == 0, r.stderr
        env = _parse(tmp_path / "update-result.env")
        assert "JUNK" not in env
        assert env["TAG"] == "1.1.0"

    def test_newline_in_message_cannot_inject_a_key(self, tmp_path):
        r = _bash(tmp_path, "write_update_result failure $'one\\nPHASE=forged' 0")
        assert r.returncode == 0, r.stderr
        assert "PHASE" not in _parse(tmp_path / "update-result.env")

    @posix_only
    def test_file_is_group_readable_and_no_tmp_left(self, tmp_path):
        r = _bash(tmp_path, 'write_update_result in_progress "x" 0 PHASE=prepare')
        assert r.returncode == 0, r.stderr
        mode = stat.S_IMODE((tmp_path / "update-result.env").stat().st_mode)
        assert mode == 0o644
        assert list(tmp_path.glob("update-result.env.tmp.*")) == []

    @posix_only
    def test_an_existing_file_is_rewritten_as_0644(self, tmp_path):
        target = tmp_path / "update-result.env"
        target.write_text("STATUS=\n", encoding="utf-8")
        target.chmod(0o600)
        r = _bash(tmp_path, 'write_update_result in_progress "x" 0')
        assert r.returncode == 0, r.stderr
        assert stat.S_IMODE(target.stat().st_mode) == 0o644


@bash_capable
class TestPhase:
    def test_writes_phase_tag_percent_and_message(self, tmp_path):
        r = _bash(tmp_path, 'phase packages 10 "Installing packages..."')
        assert r.returncode == 0, r.stderr
        env = _parse(tmp_path / "update-result.env")
        assert env["STATUS"] == "in_progress"
        assert env["PHASE"] == "packages"
        assert env["PERCENT_COMPLETE"] == "10"
        assert env["MESSAGE"] == "Installing packages..."
        assert env["TAG"] == "1.3.0"

    def test_first_write_fills_previous_tag_and_attempt_when_absent(self, tmp_path):
        (tmp_path / "install-state.env").write_text(
            "DIAL_UUID=abc\nAUTOSTREAM_RELEASE_TAG=1.2.0\n", encoding="utf-8")
        r = _bash(tmp_path, 'phase prepare 5 "Preparing..."')
        assert r.returncode == 0, r.stderr
        env = _parse(tmp_path / "update-result.env")
        assert env["PREVIOUS_TAG"] == "1.2.0"
        assert env["ATTEMPT"] == "1"
        assert env["MAX_ATTEMPTS"] == "4"

    def test_does_not_overwrite_values_the_updater_wrote(self, tmp_path):
        (tmp_path / "install-state.env").write_text(
            "AUTOSTREAM_RELEASE_TAG=9.9.9\n", encoding="utf-8")
        (tmp_path / "update-result.env").write_text(
            "STATUS=in_progress\nPREVIOUS_TAG=1.2.0\nATTEMPT=3\nMAX_ATTEMPTS=4\n",
            encoding="utf-8")
        r = _bash(tmp_path, 'phase prepare 5 "Preparing..."')
        assert r.returncode == 0, r.stderr
        env = _parse(tmp_path / "update-result.env")
        assert (env["PREVIOUS_TAG"], env["ATTEMPT"]) == ("1.2.0", "3")

    def test_fresh_install_does_not_touch_the_result_file(self, tmp_path):
        r = _bash(tmp_path, 'phase prepare 5 "Preparing..."; echo "$CURRENT_PHASE"',
                  update="false")
        assert r.returncode == 0, r.stderr
        assert r.stdout.strip() == "prepare"
        assert not (tmp_path / "update-result.env").exists()

    def test_failure_message_names_the_running_phase_and_previous_tag(self, tmp_path):
        (tmp_path / "install-state.env").write_text(
            "AUTOSTREAM_RELEASE_TAG=1.2.0\n", encoding="utf-8")
        r = _bash(tmp_path, 'phase python 45 "Installing Python packages..."\n'
                            'update_failure_message')
        assert r.returncode == 0, r.stderr
        assert r.stdout == "Update to 1.3.0 failed during Python setup - 1.2.0 kept"


def _fake_command(tmp_path: Path, name: str, body: str) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    cmd = bin_dir / name
    cmd.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8", newline="\n")
    cmd.chmod(0o755)
    return bin_dir


def _flaky_apt(tmp_path: Path, outputs: list) -> Path:
    """A fake apt-get that replays *outputs* (status, message) per call and
    records each call, plus the result file as it stood when called."""
    steps = "\n".join(
        f'  {i}) echo "{msg}" >&2; exit {rc};;' for i, (rc, msg) in enumerate(outputs)
    )
    body = (
        f'count_file="{tmp_path.as_posix()}/count"\n'
        'n=$(cat "$count_file" 2>/dev/null || echo 0)\n'
        'echo $((n + 1)) > "$count_file"\n'
        f'cp "$UPDATE_RESULT_FILE" "{tmp_path.as_posix()}/seen.$n" 2>/dev/null || true\n'
        'case "$n" in\n'
        f'{steps}\n'
        '  *) exit 0;;\n'
        'esac\n'
    )
    return _fake_command(tmp_path, "apt-get", body)


def _calls(tmp_path: Path) -> int:
    return int((tmp_path / "count").read_text(encoding="utf-8").strip())


@bash_capable
class TestAptStep:
    @pytest.mark.parametrize("message", [
        LOCK_OUTPUT,
        "E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend)",
        "E: Failed to fetch http://example.invalid/pool/x.deb  Connection failed",
        "W: Temporary failure resolving 'deb.example.invalid'",
        "E: Connection timed out",
    ])
    def test_apt_step_retries_once_on_lock_or_fetch_failure(self, tmp_path, message):
        bin_dir = _flaky_apt(tmp_path, [(100, message), (0, "")])
        r = _bash(tmp_path, 'phase packages 10 "Installing packages..."\n'
                            'apt_step apt-get install -y something',
                  bin_dir=bin_dir)
        assert r.returncode == 0, r.stderr
        assert _calls(tmp_path) == 2
        # While waiting to retry, the result file says so and notes the retry.
        seen = _parse(tmp_path / "seen.1")
        assert seen["MESSAGE"] == "Package step failed, retrying..."
        assert seen["TRANSIENT_RETRY"] == "1"
        assert seen["PHASE"] == "packages"
        # After the retry succeeds the phase message is back.
        env = _parse(tmp_path / "update-result.env")
        assert env["MESSAGE"] == "Installing packages..."

    @pytest.mark.parametrize("status,message", [
        (100, "E: Unable to locate package nonesuch"),
        (100, "E: Sub-process /usr/bin/dpkg returned an error code (1)"),
        (1, LOCK_OUTPUT),
        (2, "E: Failed to fetch http://example.invalid/x.deb"),
    ])
    def test_apt_step_fails_fast_on_other_errors(self, tmp_path, status, message):
        bin_dir = _flaky_apt(tmp_path, [(status, message), (0, "")])
        r = _bash(tmp_path, 'apt_step apt-get install -y something', bin_dir=bin_dir)
        assert r.returncode == status
        assert _calls(tmp_path) == 1

    def test_apt_step_never_retries_twice(self, tmp_path):
        bin_dir = _flaky_apt(tmp_path, [(100, LOCK_OUTPUT)] * 3 + [(0, "")])
        r = _bash(tmp_path, 'apt_step apt-get update', bin_dir=bin_dir)
        assert r.returncode == 100
        assert _calls(tmp_path) == 2

    def test_apt_step_success_runs_once_and_passes_output_through(self, tmp_path):
        bin_dir = _fake_command(tmp_path, "apt-get", 'echo "all good"; exit 0\n')
        r = _bash(tmp_path, 'apt_step apt-get update', bin_dir=bin_dir)
        assert r.returncode == 0
        assert "all good" in r.stdout

    def test_apt_step_failure_stops_a_set_e_script(self, tmp_path):
        bin_dir = _flaky_apt(tmp_path, [(100, "E: Unable to locate package x")])
        r = _bash(tmp_path, 'apt_step apt-get install -y x\necho survived',
                  bin_dir=bin_dir)
        assert r.returncode == 100
        assert "survived" not in r.stdout

    def test_apt_step_does_not_write_the_result_file_on_a_fresh_install(self, tmp_path):
        bin_dir = _flaky_apt(tmp_path, [(100, LOCK_OUTPUT), (0, "")])
        r = _bash(tmp_path, 'apt_step apt-get update', bin_dir=bin_dir, update="false")
        assert r.returncode == 0, r.stderr
        assert not (tmp_path / "update-result.env").exists()


@bash_capable
class TestSystemUpgrade:
    def test_runs_update_then_upgrade_then_autoclean(self, tmp_path):
        log = tmp_path / "log"
        bin_dir = _fake_command(
            tmp_path, "apt-get",
            f'echo "$NEEDRESTART_MODE|$DEBIAN_FRONTEND|$*" >> "{log.as_posix()}"\n',
        )
        r = _bash(tmp_path, "system_upgrade", bin_dir=bin_dir)
        assert r.returncode == 0, r.stderr
        lines = log.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 3
        assert lines[0].endswith("|update")
        assert lines[1] == "l|noninteractive|upgrade -y"
        assert lines[2].endswith("|autoclean -y")

    def test_a_transient_failure_of_the_upgrade_is_retried(self, tmp_path):
        bin_dir = _flaky_apt(tmp_path, [(0, ""), (100, LOCK_OUTPUT), (0, ""), (0, "")])
        r = _bash(tmp_path, "system_upgrade", bin_dir=bin_dir)
        assert r.returncode == 0, r.stderr
        assert _calls(tmp_path) == 4


class TestInstallerPhases:
    @staticmethod
    def _text() -> str:
        return INSTALLER.read_text(encoding="utf-8")

    def test_phases_run_in_order_with_planned_percentages(self):
        text = self._text()
        calls = re.findall(r'^\s*phase (\w+) (\d+) "', text, re.M)
        names = [c[0] for c in calls]
        assert names == ["prepare", "packages", "packages", "python", "files", "configure"]
        percents = [int(c[1]) for c in calls]
        assert percents == sorted(percents)
        assert {n: int(p) for n, p in calls} == {
            "prepare": 5, "packages": 10, "python": 45, "files": 70, "configure": 80,
        }

    def test_phases_bracket_the_work_they_name(self):
        text = self._text()
        pos = {k: text.index(k) for k in (
            "phase prepare", "require_trixie_os\n", "system_upgrade", "phase python",
            "setup_venv   #", "phase files", "deploy_admin\n", "phase configure",
            "enable_spi0", 'write_install_state "$DIAL_UUID"',
        )}
        assert pos["require_trixie_os\n"] < pos["phase prepare"]
        assert pos["system_upgrade"] < pos["phase python"] < pos["setup_venv   #"]
        assert pos["setup_venv   #"] < pos["phase files"] < pos["deploy_admin\n"]
        assert pos["deploy_admin\n"] < pos["phase configure"] < pos["enable_spi0"]
        assert pos["enable_spi0"] < pos['write_install_state "$DIAL_UUID"']

    def test_system_upgrade_runs_on_update_only_and_before_the_installs(self):
        text = self._text()
        m = re.search(r"if \$UPDATE; then\n(?:    .*\n)*?    system_upgrade\n(?:    .*\n)*?fi\n", text)
        assert m is not None, "system_upgrade must sit in an 'if $UPDATE' block"
        assert text.index("system_upgrade") < text.index("install_recovery_packages\n")
        assert text.index("system_upgrade") < text.index("install_sdmon\n")

    def test_every_package_install_precedes_the_python_phase(self):
        text = self._text()
        python_pos = text.index("phase python")
        for call in ("install_recovery_packages\n", "install_image_packages\n",
                     "install_display_hardware_packages\n",
                     "install_venv_build_packages\n", "install_sdmon\n"):
            assert text.index(call) < python_pos, call

    def test_success_is_recorded_as_the_done_phase(self):
        text = self._text()
        m = re.search(r'write_update_result "success"[^\n]*\\\n[^\n]*', text)
        assert m is not None
        assert "PHASE=done" in m.group(0)
        assert "100" in m.group(0)

    def test_exit_trap_records_the_failed_phase(self):
        text = self._text()
        trap = text[text.index("trap '"): text.index("' EXIT")]
        assert "update_failure_message" in trap
        assert "PHASE=failed" in trap

    def test_update_path_user_and_dirs_are_prepared_before_anything_installs(self):
        text = self._text()
        prepare = text.index("phase prepare")
        assert prepare < text.index("create_service_user", prepare)
        assert text.index("create_dirs", prepare) < text.index("system_upgrade")

    def test_every_helper_apt_install_goes_through_apt_step(self):
        helpers = HELPERS.read_text(encoding="utf-8")
        installs = [line for line in helpers.splitlines() if "apt-get install" in line]
        assert installs, "expected apt-get install calls in helpers.sh"
        for line in installs:
            assert line.strip().startswith("apt_step apt-get install"), line
