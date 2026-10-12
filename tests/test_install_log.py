"""The installers' log keeps every run, and keeps all of each.

The appliance installer copies its output into its log through two processes
(tee, then dd opening the file for appending without following a link). Two
faults showed in the log:

- dd holds a part block back until its input ends, so the last line was cut off
  mid-word while the installer was running;
- nothing waited for the two processes at exit, so the final lines were lost
  when the installer ended (and, run as a system service, when the service's
  control group was killed with the installer's own process).

init_logging now writes byte by byte and keeps the processes' ids; the exit
paths call finish_output_log, which gives the terminal back and waits for both.
The dial installer's tee is waited for the same way.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_dial_staged_install import REPO_ROOT, bash_capable  # noqa: E402

LIB = REPO_ROOT / "installer" / "lib"
APPLIANCE = REPO_ROOT / "autostream_install.sh"
DIAL = REPO_ROOT / "autostream_dial_install.sh"


def _run(tmp_path: Path, log: Path, body: str, *, timeout: int = 60):
    script = (
        f'source "{LIB / "state_files.sh"}"\nsource "{LIB / "helpers.sh"}"\n'
        f'LOGFILE="{log.as_posix()}" SCRIPT_NAME=autostream_install.sh ORIG_USER=pi ORIG_HOME=/home/pi\n'
        f"{body}\n"
    )
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                          timeout=timeout, cwd=tmp_path)


@bash_capable
class TestEveryRunIsKept:
    def test_two_consecutive_runs_leave_both_in_order(self, tmp_path):
        log = tmp_path / "autostream_install.log"
        for n in (1, 2):
            r = _run(tmp_path, log, f'init_logging\necho "run {n} first"\necho "run {n} last"\n'
                                    "finish_output_log")
            assert r.returncode == 0, r.stderr
        lines = log.read_text(encoding="utf-8").splitlines()
        picked = [ln for ln in lines if ln.startswith("run ")]
        assert picked == ["run 1 first", "run 1 last", "run 2 first", "run 2 last"]
        assert len([ln for ln in lines if "starting at" in ln]) == 2

    def test_a_second_run_appends_to_a_log_the_first_run_was_killed_in(self, tmp_path):
        log = tmp_path / "autostream_install.log"
        log.write_text("run 1 line\nrun 1 line cut of", encoding="utf-8")
        r = _run(tmp_path, log, 'init_logging\necho "run 2 line"\nfinish_output_log')
        assert r.returncode == 0, r.stderr
        text = log.read_text(encoding="utf-8")
        assert text.startswith("run 1 line\nrun 1 line cut of")
        assert text.rstrip().endswith("run 2 line")


@bash_capable
class TestEveryLineIsInTheLog:
    def test_a_part_line_is_in_the_file_while_the_installer_is_still_running(self, tmp_path):
        # dd used to hold back anything short of a 512-byte block until the end.
        log = tmp_path / "autostream_install.log"
        body = (
            "init_logging\n"
            "printf \"Created symlink '/etc/systemd/system/timer\"\n"
            "for _ in $(seq 1 50); do grep -q 'system/timer' \"$LOGFILE\" && break; sleep 0.1; done\n"
            "grep -q \"system/timer\" \"$LOGFILE\" && echo IN_LOG_WHILE_RUNNING\n"
            "finish_output_log"
        )
        r = _run(tmp_path, log, body)
        assert "IN_LOG_WHILE_RUNNING" in r.stdout, r.stderr

    def test_the_last_line_is_in_the_file_when_the_function_returns(self, tmp_path):
        log = tmp_path / "autostream_install.log"
        r = _run(tmp_path, log, 'init_logging\necho "Installation complete."\nfinish_output_log\n'
                                'grep -q "Installation complete." "$LOGFILE" && echo FOUND')
        assert "FOUND" in r.stdout, r.stderr

    @pytest.mark.parametrize("attempt", range(15))
    def test_the_last_line_survives_the_parent_exiting_immediately(self, tmp_path, attempt):
        log = tmp_path / "autostream_install.log"
        r = _run(tmp_path, log, 'trap finish_output_log EXIT\ninit_logging\n'
                                'echo "first"\nprintf "Installation complete."\nexit 0')
        assert r.returncode == 0, r.stderr
        assert log.read_text(encoding="utf-8").endswith("Installation complete.")

    def test_a_large_output_arrives_whole_and_in_order(self, tmp_path):
        log = tmp_path / "autostream_install.log"
        r = _run(tmp_path, log, 'init_logging\nseq 1 20000\nfinish_output_log')
        assert r.returncode == 0, r.stderr
        numbers = [int(x) for x in log.read_text(encoding="utf-8").splitlines() if x.isdigit()]
        assert numbers == list(range(1, 20001))

    def test_output_is_still_shown_where_it_was_going(self, tmp_path):
        log = tmp_path / "autostream_install.log"
        r = _run(tmp_path, log, 'init_logging\necho shown\necho to-stderr >&2\nfinish_output_log')
        assert "shown" in r.stdout and "to-stderr" in r.stdout

    def test_the_exit_status_survives_an_exit_through_the_trap(self, tmp_path):
        log = tmp_path / "autostream_install.log"
        r = _run(tmp_path, log, 'trap finish_output_log EXIT\ninit_logging\necho failing\nexit 3')
        assert r.returncode == 3
        assert log.read_text(encoding="utf-8").rstrip().endswith("failing")

    def test_finishing_twice_or_without_a_log_is_harmless(self, tmp_path):
        log = tmp_path / "autostream_install.log"
        r = _run(tmp_path, log, 'finish_output_log\ninit_logging\necho x\nfinish_output_log\nfinish_output_log\necho after')
        assert r.returncode == 0, r.stderr
        assert "after" in r.stdout
        assert "after" not in log.read_text(encoding="utf-8")

    def test_a_link_at_the_log_name_is_still_not_followed(self, tmp_path):
        target = tmp_path / "victim"
        target.write_text("secret\n", encoding="utf-8")
        log = tmp_path / "autostream_install.log"
        log.symlink_to(target)
        r = _run(tmp_path, log, 'init_logging\necho written\nfinish_output_log')
        assert r.returncode == 0, r.stderr
        assert target.read_text(encoding="utf-8") == "secret\n"

    def test_a_writer_that_cannot_finish_does_not_hold_the_exit_up_for_good(self, tmp_path):
        log = tmp_path / "autostream_install.log"
        # A child keeps the output open after the installer is done with it.
        body = ('OUTPUT_LOG_WAIT_TENTHS=5\ninit_logging\n(sleep 3 &)\necho last\nfinish_output_log\n'
                'echo RETURNED')
        r = _run(tmp_path, log, body, timeout=15)
        assert "RETURNED" in r.stdout
        assert "may be missing" in r.stderr


# ---------------------------------------------------------------------------
# The exit paths
# ---------------------------------------------------------------------------

def _function(text: str, name: str) -> str:
    m = re.search(r"^" + re.escape(name) + r"\(\) \{.*?\n\}\n", text, re.S | re.M)
    assert m is not None, name
    return m.group(0)


def _on_exit(tmp_path: Path, *, prompt: int, status: int, tty: bool, answer: str = "N"):
    trace = tmp_path / "trace"
    trace.write_text("", encoding="utf-8")
    t = trace.as_posix()
    script = f'''
info() {{ echo "$*"; }}
has_tty() {{ {"true" if tty else "false"}; }}
tty_read() {{ printf -v "$2" '%s' "{answer}"; }}
finish_output_log() {{ echo finish_output_log >> "{t}"; }}
reboot() {{ echo reboot >> "{t}"; }}
UPDATING_FLAG_FILE=/nonexistent/flag PROMPT_REBOOT_ON_EXIT={prompt}
{_function(APPLIANCE.read_text(encoding="utf-8"), "on_exit")}
( exit {status} ); on_exit
'''
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
    return r, trace.read_text(encoding="utf-8").split()


@bash_capable
class TestApplianceExitPaths:
    @pytest.mark.parametrize("prompt, status, tty", [
        (0, 0, False), (0, 1, False), (1, 0, False), (1, 0, True), (1, 1, False),
    ])
    def test_the_log_is_finished_on_every_way_out(self, tmp_path, prompt, status, tty):
        _r, calls = _on_exit(tmp_path, prompt=prompt, status=status, tty=tty)
        assert calls.count("finish_output_log") == 1

    def test_the_log_is_finished_before_the_reboot(self, tmp_path):
        _r, calls = _on_exit(tmp_path, prompt=1, status=0, tty=True, answer="Y")
        assert calls.index("finish_output_log") < calls.index("reboot")

    def test_the_log_is_finished_after_the_last_message(self, tmp_path):
        r, calls = _on_exit(tmp_path, prompt=1, status=0, tty=False)
        assert "Please reboot the device when convenient." in r.stdout
        assert calls == ["finish_output_log"]


@bash_capable
class TestDialInstaller:
    def test_text_check_the_writers_are_waited_for_on_exit_and_before_a_reboot(self):
        text = DIAL.read_text(encoding="utf-8")
        assert 'start_install_log "$DIAL_INSTALL_LOG"' in text
        trap = text[text.index("trap '_exit_rc=$?"):]
        trap = trap[:trap.index("EXIT")]
        assert "finish_output_log" in trap
        assert re.search(r'echo "Rebooting\.\.\."; finish_output_log; reboot', text)

    def test_the_last_line_of_the_dial_log_is_in_the_file(self, tmp_path):
        log = tmp_path / "dial-install.log"
        script = (
            f'source "{LIB / "state_files.sh"}"\nsource "{LIB / "output_log.sh"}"\n'
            f'start_install_log "{log.as_posix()}" 0644\n'
            'trap finish_output_log EXIT\necho "autostream dial installation complete."\nexit 0\n'
        )
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, r.stderr
        assert log.read_text(encoding="utf-8") == "autostream dial installation complete.\n"
