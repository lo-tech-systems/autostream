"""A fresh install must survive the loss of the terminal it was started from.

Two halves, both exercised with stubbed systemd tools:

- No installer, updater or uninstaller restarts systemd-logind (a restart drops
  the login sessions it holds and stops what is left running in them, an
  installer included); the power-key setting is made to take effect by
  signalling it to re-read its settings instead.
- A fresh install started from a login session asks its questions, then runs
  itself again as a transient system service and follows the service's log; an
  --update, and a run that is already that service, are not handed over.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_dial_staged_install import Env, REPO_ROOT, bash_capable  # noqa: E402

LIB = REPO_ROOT / "installer" / "lib" / "handover.sh"
APPLIANCE = REPO_ROOT / "autostream_install.sh"
DIAL = REPO_ROOT / "autostream_dial_install.sh"

# The restart verbs that stop a unit and start it again.
LOGIND_RESTART = re.compile(
    r"^[^#\n]*systemctl[^\n]*\b(?:restart|try-restart|reload-or-restart|try-reload-or-restart)\b"
    r"[^\n]*systemd-logind", re.M)

SYSTEMD_RUN = r"""#!/bin/bash
# Stub: records its arguments, then plays the service that was asked for.
echo "systemd-run $*" >> "$TRACE"
if [[ "${SR_MODE:-ok}" == "refuse" ]]; then
    echo "Failed to start transient service unit: Access denied" >&2
    exit 1
fi
echo "Running as unit: autostream-install.service."
if [[ "${SR_MODE:-ok}" == "hang" ]]; then
    echo $$ > "$HANG_PIDFILE"
    exec /bin/sleep 30
fi
if [[ "${SR_MODE:-ok}" == "silent" ]]; then exit "${SR_RC:-1}"; fi
sleep 0.4
printf 'service line one\n' >> "$HANDOVER_LOG"
sleep 0.4
printf 'service last line' >> "$HANDOVER_LOG"
exit "${SR_RC:-0}"
"""


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    e.fake("systemd-run", SYSTEMD_RUN)
    e.fake("systemctl", '#!/bin/bash\n[[ "$1" == is-active ]] && exit 3\nexit 0\n')
    e.fake("id", '#!/bin/bash\n[[ "$1" == "-u" ]] && { echo "${FAKE_UID:-0}"; exit 0; }\nexec /usr/bin/id "$@"\n')
    return e


def _cgroup(tmp_path: Path, line: str) -> Path:
    path = tmp_path / "cgroup"
    path.write_text(line + "\n", encoding="utf-8")
    return path


SESSION = "0::/user.slice/user-1000.slice/session-4.scope"
SERVICE = "0::/system.slice/autostream-install.service"


def _handover(env: Env, tmp_path: Path, body: str, *, cgroup: str = SESSION, **extra: str):
    systemd_dir = tmp_path / "run-systemd"
    systemd_dir.mkdir(exist_ok=True)
    log = tmp_path / "install.log"
    log.write_text("a run before\n", encoding="utf-8")
    script = (
        "set -Eeuo pipefail\n"
        f'HANDOVER_CGROUP_FILE="{_cgroup(tmp_path, cgroup).as_posix()}"\n'
        f'HANDOVER_SYSTEMD_DIR="{systemd_dir.as_posix()}"\n'
        "HANDOVER_POLL_SECONDS=0.1\n"
        f'source "{LIB.as_posix()}"\n{body}'
    )
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60,
                          cwd=tmp_path,
                          env=env.env(HANDOVER_LOG=log.as_posix(), **extra)), log


CALL = ('hand_over_to_unit autostream-install /opt/x/installer.sh "$HANDOVER_LOG" '
        '--unattended PIN=1234 --owntone=mini && echo "RC=$HANDOVER_RC" || echo "NOT HANDED OVER"')


REFUSE = ('handover_refuse_if_running autostream-install "$HANDOVER_LOG"\n'
          'echo CARRIED-ON')


@bash_capable
class TestInLoginSession:
    @pytest.mark.parametrize("line", [
        "0::/user.slice/user-1000.slice/session-4.scope",
        "0::/user.slice/user-0.slice/session-c2.scope".replace("c2", "12"),
        "0::/user.slice/user-1000.slice/session-31.scope/tmux",
    ])
    def test_a_login_session_scope_counts(self, tmp_path, line):
        r, _ = _handover(Env(tmp_path), tmp_path, "in_login_session && echo yes || echo no", cgroup=line)
        assert r.stdout.strip() == "yes", r.stderr

    @pytest.mark.parametrize("line", [
        "0::/system.slice/autostream-update-1.service",
        "0::/init.scope",
        "0::/user.slice/user-1000.slice/user@1000.service/app.slice/x.service",
        "0::/system.slice/not-a-session-4.scope.service",
    ])
    def test_a_service_or_anything_else_does_not(self, tmp_path, line):
        r, _ = _handover(Env(tmp_path), tmp_path, "in_login_session && echo yes || echo no", cgroup=line)
        assert r.stdout.strip() == "no", r.stderr


@bash_capable
class TestHandOver:
    def test_the_install_runs_again_as_a_service_with_what_it_needs(self, env, tmp_path):
        r, _ = _handover(env, tmp_path, CALL,
                         SUDO_USER="pi", HOME="/home/pi", AUTOSTREAM_RELEASE_TAG="0.7.0",
                         FAKE_UID="0")
        assert r.returncode == 0, r.stderr
        assert "RC=0" in r.stdout
        run = [c for c in env.calls() if c.startswith("systemd-run")]
        assert len(run) == 1
        line = run[0]
        for wanted in ("--collect", "--wait", "--unit=autostream-install",
                       "--working-directory=/opt/x",
                       "--setenv=AUTOSTREAM_HANDED_OVER=1", "--setenv=SUDO_USER=pi",
                       "--setenv=AUTOSTREAM_RELEASE_TAG=0.7.0"):
            assert wanted in line, (wanted, line)
        assert "--setenv=HOME=" not in line
        assert line.endswith("-- bash /opt/x/installer.sh --unattended PIN=1234 --owntone=mini")

    def test_the_service_starts_in_the_scripts_own_directory_not_the_callers(self, env, tmp_path):
        other = tmp_path / "elsewhere"
        other.mkdir()
        r, _ = _handover(env, tmp_path, f'cd "{other.as_posix()}"\n{CALL}')
        assert r.returncode == 0, r.stderr
        line = next(c for c in env.calls() if c.startswith("systemd-run"))
        assert "--working-directory=/opt/x " in line
        assert "elsewhere" not in line

    def test_a_service_that_fails_before_writing_anything_points_to_its_journal(self, env, tmp_path):
        r, _ = _handover(env, tmp_path, CALL, SR_MODE="silent", SR_RC="200")
        assert "RC=200" in r.stdout
        assert "ended with status 200 without writing to" in r.stderr
        assert "journalctl -u autostream-install" in r.stderr

    def test_a_service_that_wrote_to_the_log_before_failing_needs_no_such_hint(self, env, tmp_path):
        r, _ = _handover(env, tmp_path, CALL, SR_RC="3")
        assert "RC=3" in r.stdout
        assert "without writing" not in r.stderr

    def test_a_service_that_succeeds_silently_needs_no_hint(self, env, tmp_path):
        r, _ = _handover(env, tmp_path, CALL, SR_MODE="silent", SR_RC="0")
        assert "RC=0" in r.stdout
        assert "without writing" not in r.stderr

    @pytest.mark.parametrize("sig", [signal.SIGINT, signal.SIGHUP, signal.SIGTERM])
    def test_leaving_the_terminal_early_cleans_up_and_says_the_install_goes_on(self, env, tmp_path, sig):
        if signal.getsignal(sig) == signal.SIG_IGN:
            # A shell started with a signal ignored cannot trap it (under
            # nohup, say), so the hand-over would wait out the service.
            pytest.skip(f"{signal.Signals(sig).name} is ignored by this test run")
        systemd_dir = tmp_path / "run-systemd"
        systemd_dir.mkdir()
        scratch = tmp_path / "scratch"
        scratch.mkdir()
        pidfile = tmp_path / "hang.pid"
        log = tmp_path / "install.log"
        log.write_text("a run before\n", encoding="utf-8")
        script = (
            "set -Eeuo pipefail\n"
            f'HANDOVER_CGROUP_FILE="{_cgroup(tmp_path, SESSION).as_posix()}"\n'
            f'HANDOVER_SYSTEMD_DIR="{systemd_dir.as_posix()}"\n'
            "HANDOVER_POLL_SECONDS=0.1\n"
            f'source "{LIB.as_posix()}"\n{CALL}')
        proc = subprocess.Popen(
            ["bash", "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            cwd=tmp_path, env=env.env(HANDOVER_LOG=log.as_posix(), SR_MODE="hang",
                                      HANG_PIDFILE=pidfile.as_posix(), TMPDIR=scratch.as_posix()))
        for _ in range(100):
            if pidfile.exists() and pidfile.read_text(encoding="utf-8").strip():
                break
            time.sleep(0.1)
        else:
            proc.kill()
            raise AssertionError("the stubbed service never started")
        child = int(pidfile.read_text(encoding="utf-8").strip())
        proc.send_signal(sig)
        _out, err = proc.communicate(timeout=20)
        assert proc.returncode == 1, (proc.returncode, _out, err)
        assert "still running as autostream-install.service" in err
        assert "sudo systemctl stop autostream-install" in err
        assert "tail -f" in err
        assert list(scratch.iterdir()) == []
        for _ in range(50):
            try:
                os.kill(child, 0)
            except ProcessLookupError:
                break
            time.sleep(0.1)
        else:
            os.kill(child, signal.SIGKILL)
            raise AssertionError("the waiting client was left running")

    def test_the_service_output_is_shown_and_what_was_there_before_is_not(self, env, tmp_path):
        r, _ = _handover(env, tmp_path, CALL)
        assert "service line one" in r.stdout
        assert "service last line" in r.stdout
        assert "a run before" not in r.stdout

    def test_the_services_exit_status_is_handed_back(self, env, tmp_path):
        r, _ = _handover(env, tmp_path, CALL, SR_RC="3")
        assert "RC=3" in r.stdout
        assert "service last line" in r.stdout

    @pytest.mark.parametrize("reason, kwargs", [
        ("outside a login session", dict(cgroup=SERVICE)),
        ("already the service", dict(AUTOSTREAM_HANDED_OVER="1")),
        ("not root", dict(FAKE_UID="1000")),
    ])
    def test_it_is_not_made_when_it_is_not_wanted(self, env, tmp_path, reason, kwargs):
        r, _ = _handover(env, tmp_path, CALL, **kwargs)
        assert "NOT HANDED OVER" in r.stdout, reason
        assert not [c for c in env.calls() if c.startswith("systemd-run")], reason

    def test_it_is_not_made_without_systemd_run(self, env, tmp_path):
        (env.bin / "systemd-run").unlink()
        r, _ = _handover(env, tmp_path, CALL, PATH=env.bin.as_posix() + ":/usr/bin:/bin")
        assert "NOT HANDED OVER" in r.stdout

    def test_a_service_that_could_not_be_started_leaves_the_install_to_this_process(self, env, tmp_path):
        r, _ = _handover(env, tmp_path, CALL, SR_MODE="refuse")
        assert "NOT HANDED OVER" in r.stdout
        assert "Could not start autostream-install.service" in r.stderr

    def test_an_install_already_running_as_the_service_is_not_started_twice(self, env, tmp_path):
        env.fake("systemctl", '#!/bin/bash\n[[ "$1" == is-active ]] && exit 0\nexit 0\n')
        r, _ = _handover(env, tmp_path, CALL)
        assert r.returncode == 1
        assert "already running as autostream-install.service" in r.stderr
        assert not [c for c in env.calls() if c.startswith("systemd-run")]

    def test_the_refusal_says_how_to_follow_the_running_install_and_how_to_stop_it(self, env, tmp_path):
        env.fake("systemctl", '#!/bin/bash\n[[ "$1" == is-active ]] && exit 0\nexit 0\n')
        r, log = _handover(env, tmp_path, REFUSE)
        assert r.returncode == 1 and "CARRIED-ON" not in r.stdout
        assert f"tail -f {log.as_posix()}" in r.stderr
        assert "journalctl -fu autostream-install" in r.stderr
        assert "sudo systemctl stop autostream-install" in r.stderr

    def test_nothing_is_refused_when_no_install_is_running(self, env, tmp_path):
        r, _ = _handover(env, tmp_path, REFUSE)
        assert r.returncode == 0 and "CARRIED-ON" in r.stdout

    def test_nothing_is_refused_where_no_hand_over_would_be_made(self, env, tmp_path):
        env.fake("systemctl", '#!/bin/bash\n[[ "$1" == is-active ]] && exit 0\nexit 0\n')
        r, _ = _handover(env, tmp_path, REFUSE, cgroup=SERVICE)
        assert r.returncode == 0 and "CARRIED-ON" in r.stdout


# ---------------------------------------------------------------------------
# The appliance installer: where the questions are asked, and what is not handed over
# ---------------------------------------------------------------------------

def _function(text: str, name: str) -> str:
    m = re.search(r"^" + re.escape(name) + r"\(\) \{.*?\n\}\n", text, re.S | re.M)
    assert m is not None, name
    return m.group(0)


def _appliance_main(tmp_path: Path, *, mode: str, handover_ok: bool, handed_over: str = "0"):
    trace = tmp_path / "trace"
    trace.write_text("", encoding="utf-8")
    main = _function(APPLIANCE.read_text(encoding="utf-8"), "main")
    stubs = "\n".join(
        f'{name}() {{ echo "{name}" >> "{trace.as_posix()}"; }}'
        for name in ("require_sudo", "check_network_manager", "show_warnings_and_prompt",
                     "require_rpi_os_trixie", "handle_pin", "init_logging", "load_state",
                     "run_update", "run_install", "stay_running_after_hangup", "warn", "info"))
    script = f'''
set -uo pipefail
{stubs}
handover_refuse_if_running() {{ echo "handover_refuse_if_running $*" >> "{trace.as_posix()}"; [[ -z "${{FAKE_RUNNING:-}}" ]] || exit 1; }}
parse_args() {{ :; }}
in_login_session() {{ true; }}
hand_over_to_unit() {{ echo "hand_over_to_unit $*" >> "{trace.as_posix()}"; {"HANDOVER_RC=7; return 0" if handover_ok else "return 1"}; }}
INSTALL_MODE={mode}; PROMPTS_DONE={handed_over}; PROMPT_REBOOT_ON_EXIT=0
AUTOSTREAM_DIR=/opt/rel; SCRIPT_NAME=autostream_install.sh; LOGFILE=/var/log/autostream/autostream_install.log
OWNTONE_MODE=mini; SDMON_METHOD=; LOW_POWER=0
{main}
main --unattended PIN=1234
echo "main returned"
'''
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
    return r, trace.read_text(encoding="utf-8").splitlines()


@bash_capable
class TestApplianceInstaller:
    def test_the_questions_are_asked_before_the_hand_over_and_the_service_inherits_the_arguments(self, tmp_path):
        r, calls = _appliance_main(tmp_path, mode="install", handover_ok=True)
        assert r.returncode == 7, r.stderr          # the service's status is the exit status
        names = [c.split()[0] for c in calls]
        assert names.index("show_warnings_and_prompt") < names.index("require_rpi_os_trixie") \
            < names.index("handle_pin") < names.index("hand_over_to_unit")
        assert "init_logging" not in names and "run_install" not in names
        handed = next(c for c in calls if c.startswith("hand_over_to_unit"))
        assert handed == ("hand_over_to_unit autostream-install /opt/rel/autostream_install.sh "
                          "/var/log/autostream/autostream_install.log --unattended")
        assert "PIN=" not in handed

    def test_a_second_run_asks_nothing_and_writes_nothing_while_an_install_is_running(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FAKE_RUNNING", "1")
        r, calls = _appliance_main(tmp_path, mode="install", handover_ok=True)
        assert r.returncode == 1 and "main returned" not in r.stdout
        assert [c.split()[0] for c in calls] == ["require_sudo", "handover_refuse_if_running"]
        assert calls[1] == "handover_refuse_if_running autostream-install /var/log/autostream/autostream_install.log"

    def test_the_service_accepts_the_arguments_it_is_given_without_the_pin(self, tmp_path):
        # The service gets "--unattended" with no PIN=; it must neither complain
        # nor fall over, and the other options must still be read.
        parse = _function(APPLIANCE.read_text(encoding="utf-8"), "parse_args")
        script = f'''
set -uo pipefail
warn() {{ echo "WARN $*"; }}; error() {{ echo "ERROR $*"; }}; usage() {{ :; }}
is_valid_sdmon_method() {{ true; }}; is_valid_owntone_mode() {{ true; }}
INSTALL_MODE=install; UNATTENDED=0; PIN_VALUE=""; OWNTONE_MODE=mini; LOW_POWER=0
{parse}
parse_args --unattended --owntone=full --low-power
echo "rc=$? mode=$OWNTONE_MODE unattended=$UNATTENDED pin=[$PIN_VALUE] low=$LOW_POWER"
'''
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
        assert r.stdout.strip() == "rc=0 mode=full unattended=0 pin=[] low=1", (r.stdout, r.stderr)

    def test_without_a_hand_over_the_install_carries_on_here_without_asking_again(self, tmp_path):
        r, calls = _appliance_main(tmp_path, mode="install", handover_ok=False)
        names = [c.split()[0] for c in calls]
        assert "main returned" in r.stdout
        assert names.count("show_warnings_and_prompt") == 1
        assert names.index("stay_running_after_hangup") < names.index("init_logging") \
            < names.index("run_install")

    def test_an_update_is_not_handed_over_and_asks_nothing(self, tmp_path):
        r, calls = _appliance_main(tmp_path, mode="update", handover_ok=True)
        names = [c.split()[0] for c in calls]
        assert "hand_over_to_unit" not in names
        assert "show_warnings_and_prompt" not in names and "handle_pin" not in names
        assert names.index("init_logging") < names.index("load_state") < names.index("run_update")

    def test_the_service_itself_neither_asks_nor_hands_over_again(self, tmp_path):
        r, calls = _appliance_main(tmp_path, mode="install", handover_ok=True, handed_over="1")
        names = [c.split()[0] for c in calls]
        assert names == ["require_sudo", "init_logging", "run_install"]

    def test_text_check_the_service_leaves_the_reboot_question_to_the_terminal(self):
        run_install = _function(APPLIANCE.read_text(encoding="utf-8"), "run_install")
        assert re.search(r'HANDED_OVER.*?PROMPT_REBOOT_ON_EXIT=0', run_install, re.S)
        assert "PROMPTS_DONE" in run_install


# ---------------------------------------------------------------------------
# The dial installer, end to end over recorders
# ---------------------------------------------------------------------------

HANDOVER_STUBS = (
    "handover_available() { return 0; }",
    'hand_over_to_unit() { printf "hand_over_to_unit %s\\n" "$1" >> "$TRACE"; HANDOVER_RC=${FAKE_RC:-0}; return ${FAKE_HANDOVER:-0}; }',
    "in_login_session() { return 0; }",
    'stay_running_after_hangup() { printf "stay_running_after_hangup\\n" >> "$TRACE"; }',
    'show_info_and_prompt() { printf "show_info_and_prompt\\n" >> "$TRACE"; }',
    'handover_refuse_if_running() { printf "handover_refuse_if_running %s\\n" "$1" >> "$TRACE"; [[ -z "${FAKE_RUNNING:-}" ]] || exit 1; }',
)


@bash_capable
class TestDialInstaller:
    def _run(self, tmp_path, **kw):
        from test_dial_installer_hd import _dry_run, _names
        extra_env = kw.pop("extra_env", None)
        r, calls = _dry_run(tmp_path, extra_stubs=HANDOVER_STUBS, extra_env=extra_env, **kw)
        return r, calls, _names(calls)

    def test_a_fresh_install_asks_first_then_hands_over_and_does_none_of_the_work_itself(self, tmp_path):
        r, calls, names = self._run(tmp_path, update=False, extra_env={"FAKE_RC": "0"})
        assert r.returncode == 0, r.stderr
        assert names.index("show_info_and_prompt") < names.index("hand_over_to_unit")
        assert "autostream-dial-install" in " ".join(calls)
        assert not [n for n in names if n.startswith("phase") or n == "install_os_packages"]
        assert "Non-interactive session; please reboot the device when convenient." in r.stdout

    def test_a_second_run_asks_nothing_and_does_nothing_while_an_install_is_running(self, tmp_path):
        r, calls, names = self._run(tmp_path, update=False, extra_env={"FAKE_RUNNING": "1"})
        assert r.returncode != 0
        assert "handover_refuse_if_running" in names
        assert "show_info_and_prompt" not in names and "hand_over_to_unit" not in names
        assert not [n for n in names if n.startswith("phase") or n == "install_os_packages"]
        assert "handover_refuse_if_running autostream-dial-install" in " ".join(calls)

    def test_the_services_failure_is_this_processs_exit_status_and_no_reboot_is_offered(self, tmp_path):
        r, _calls, _names_ = self._run(tmp_path, update=False, extra_env={"FAKE_RC": "5"})
        assert r.returncode == 5
        assert "reboot" not in r.stdout.lower()

    def test_when_it_cannot_be_handed_over_it_installs_here_and_does_not_ask_again(self, tmp_path):
        r, _calls, names = self._run(tmp_path, update=False, extra_env={"FAKE_HANDOVER": "1"})
        assert r.returncode == 0, r.stderr
        assert names.count("show_info_and_prompt") == 1
        assert names.count("stay_running_after_hangup") == 1
        assert "phase prepare" in names and "write_install_state" in names

    def test_the_service_does_not_ask_or_hand_over_again(self, tmp_path):
        r, _calls, names = self._run(tmp_path, update=False,
                                     extra_env={"AUTOSTREAM_HANDED_OVER": "1"})
        assert r.returncode == 0, r.stderr
        assert "show_info_and_prompt" not in names and "hand_over_to_unit" not in names
        assert "write_install_state" in names
        assert "Reboot the device to complete setup." in r.stdout
        assert "Non-interactive session" not in r.stdout

    def test_an_update_is_not_handed_over(self, tmp_path):
        r, _calls, names = self._run(tmp_path, update=True)
        assert r.returncode == 0, r.stderr
        assert "hand_over_to_unit" not in names and "show_info_and_prompt" not in names
        assert "stay_running_after_hangup" not in names

    @pytest.mark.parametrize("update", [False, True])
    def test_no_dry_run_restarts_logind(self, tmp_path, update):
        _r, calls, _n = self._run(tmp_path, update=update)
        assert not [c for c in calls if LOGIND_RESTART.search(c)]


# ---------------------------------------------------------------------------
# logind is never restarted by anything the user runs
# ---------------------------------------------------------------------------

class TestLogindIsNeverRestarted:
    @pytest.mark.parametrize("path", [
        "autostream_install.sh", "autostream_dial_install.sh",
        "autostream_uninstall.sh", "autostream_dial_uninstall.sh",
        "bootstrap.sh", "dial_bootstrap.sh",
    ])
    def test_text_check_no_script_restarts_it(self, path):
        text = (REPO_ROOT / path).read_text(encoding="utf-8")
        assert not LOGIND_RESTART.search(text), path

    def test_text_check_no_library_restarts_it(self):
        for lib in sorted((REPO_ROOT / "installer").rglob("*.sh")):
            assert not LOGIND_RESTART.search(lib.read_text(encoding="utf-8")), lib.name

    def test_text_check_the_updaters_do_not_either(self):
        for name in ("autostream_updater", "autostream_dial_updater", "autostream_update_retry",
                     "autostream_update_support.py"):
            text = (REPO_ROOT / "supervisor" / name).read_text(encoding="utf-8")
            assert "systemd-logind" not in text, name
