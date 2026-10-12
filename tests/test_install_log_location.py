"""Both installers always write their install log in the one place.

Under /var/log/autostream, whoever starts the installer and however: from a
terminal through sudo, as a system service with no sudo user (the updater, a
hand-over, the boot-time retry). Nothing is written under a home directory, a
log an older release left there is left alone, and a run started from a
terminal says where the log is.

The tests run the installers' own code in a sandbox: the log directory is moved
under a scratch directory, a fake root, and the commands that need root are
recorders.

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
from test_dial_staged_install import Env, REPO_ROOT, bash_capable  # noqa: E402
from test_installer_handover import HANDOVER_STUBS, _function  # noqa: E402

LIB = REPO_ROOT / "installer" / "lib"
APPLIANCE = REPO_ROOT / "autostream_install.sh"
DIAL = REPO_ROOT / "autostream_dial_install.sh"

APPLIANCE_LOG = "/var/log/autostream/autostream_install.log"
DIAL_LOG = "/var/log/autostream/dial-install.log"
OLD_APPLIANCE_HOME_LOG = "autostream_install.log"
OLD_DIAL_HOME_LOG = "autostream_dial_install.log"
OLD_TEXT = "a log an older release left here\n"


def _run(body: str, tmp_path: Path, **env_extra: str) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if k != "SUDO_USER"}
    env.update(env_extra)
    return subprocess.run(["bash", "-c", body], capture_output=True, text=True, timeout=60,
                          cwd=tmp_path, env=env)


def _appliance_globals(logdir: Path, home: Path) -> str:
    """The appliance installer's own lines that decide LOGFILE, with the log
    directory moved into the sandbox and the invoking user's home beside it."""
    text = APPLIANCE.read_text(encoding="utf-8")
    start = text.index("APP_LOG_DIR=")
    block = text[start:text.index("\nSTAMP_DIR=", start)]
    # The sandbox's log directory stands in for the real one.
    block = block.replace("/var/log/autostream", logdir.as_posix())
    return (f'ORIG_HOME="{home.as_posix()}"\n{block}\n'
            'SCRIPT_NAME=autostream_install.sh ORIG_USER=pi\n')


def _appliance_run(tmp_path: Path, *, sudo_user: str | None, extra: str = "", logdir: Path | None = None):
    home = tmp_path / "home" / "pi"
    home.mkdir(parents=True, exist_ok=True)
    logdir = logdir or tmp_path / "var" / "log" / "autostream"
    body = (
        f'source "{LIB / "state_files.sh"}"\nsource "{LIB / "helpers.sh"}"\n'
        f"{_appliance_globals(logdir, home)}{extra}\n"
        "init_logging\necho a-line-of-the-run\nfinish_output_log\n"
    )
    env = {"SUDO_USER": sudo_user} if sudo_user else {}
    r = _run(body, tmp_path, **env)
    return r, logdir / "autostream_install.log", home


def _files_under(root: Path) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())


# ---------------------------------------------------------------------------
# The appliance installer
# ---------------------------------------------------------------------------

@bash_capable
class TestApplianceLogPlace:
    @pytest.mark.parametrize("sudo_user", ["pi", None])
    def test_the_log_is_in_the_log_directory_and_nothing_is_written_in_a_home(self, tmp_path, sudo_user):
        r, log, home = _appliance_run(tmp_path, sudo_user=sudo_user)
        assert r.returncode == 0, r.stderr
        assert "a-line-of-the-run" in log.read_text(encoding="utf-8")
        assert list(home.iterdir()) == []

    def test_the_script_names_the_one_path_without_looking_at_the_user(self):
        text = APPLIANCE.read_text(encoding="utf-8")
        m = re.search(r'^LOGFILE="[^\n]*$', text, re.M)
        assert m.group(0) == 'LOGFILE="${APP_LOG_DIR}/autostream_install.log"'
        assert re.search(r'^APP_LOG_DIR="/var/log/autostream"$', text, re.M)
        assert "~/autostream_install.log" not in text

    def test_the_log_directory_is_made_when_absent(self, tmp_path):
        logdir = tmp_path / "fresh" / "autostream"
        assert not logdir.exists()
        r, log, _home = _appliance_run(tmp_path, sudo_user="pi", logdir=logdir)
        assert r.returncode == 0, r.stderr
        assert stat.S_IMODE(logdir.stat().st_mode) == 0o755
        assert "a-line-of-the-run" in log.read_text(encoding="utf-8")

    def test_an_existing_log_is_appended_to(self, tmp_path):
        logdir = tmp_path / "var" / "log" / "autostream"
        logdir.mkdir(parents=True)
        (logdir / "autostream_install.log").write_text("[INFO] an earlier run\n", encoding="utf-8")
        r, log, _home = _appliance_run(tmp_path, sudo_user=None)
        assert r.returncode == 0, r.stderr
        text = log.read_text(encoding="utf-8")
        assert text.startswith("[INFO] an earlier run\n") and "a-line-of-the-run" in text

    def test_a_link_at_the_log_path_is_still_refused(self, tmp_path):
        logdir = tmp_path / "var" / "log" / "autostream"
        logdir.mkdir(parents=True)
        victim = tmp_path / "victim"
        victim.write_text("secret\n", encoding="utf-8")
        (logdir / "autostream_install.log").symlink_to(victim)
        r, _log, home = _appliance_run(tmp_path, sudo_user="pi")
        assert r.returncode == 0, r.stderr
        assert victim.read_text(encoding="utf-8") == "secret\n"
        assert list(home.iterdir()) == []

    @pytest.mark.parametrize("sudo_user", ["pi", None])
    def test_a_log_an_older_release_left_in_a_home_is_not_touched(self, tmp_path, sudo_user):
        old = tmp_path / "home" / "pi" / OLD_APPLIANCE_HOME_LOG
        old.parent.mkdir(parents=True)
        old.write_text(OLD_TEXT, encoding="utf-8")
        before = old.stat()
        r, log, _home = _appliance_run(tmp_path, sudo_user=sudo_user)
        assert r.returncode == 0, r.stderr
        assert old.read_text(encoding="utf-8") == OLD_TEXT
        assert old.stat().st_mtime_ns == before.st_mtime_ns
        assert "a-line-of-the-run" in log.read_text(encoding="utf-8")

    def test_the_terminal_is_told_where_the_log_is_at_the_start(self, tmp_path):
        r, log, _home = _appliance_run(tmp_path, sudo_user="pi")
        assert f"Log file: {log}" in r.stdout

    def test_the_owner_of_the_directory_can_be_changed_while_the_log_is_open(self, tmp_path):
        # What the permissions step does later: the same file keeps receiving output.
        logdir = tmp_path / "fresh" / "autostream"
        home = tmp_path / "home" / "pi"
        home.mkdir(parents=True)
        body = (
            f'source "{LIB / "state_files.sh"}"\nsource "{LIB / "helpers.sh"}"\n'
            f"{_appliance_globals(logdir, home)}"
            "init_logging\necho before-the-owner-change\n"
            f'/usr/bin/chown -R "$(id -un)" "{logdir.as_posix()}"\n'
            "echo after-the-owner-change\nfinish_output_log\n")
        r = _run(body, tmp_path)
        assert r.returncode == 0, r.stderr
        log = logdir / "autostream_install.log"
        text = log.read_text(encoding="utf-8")
        assert "before-the-owner-change" in text and "after-the-owner-change" in text
        assert text.index("before-the-owner-change") < text.index("after-the-owner-change")


def _on_exit(tmp_path: Path, *, handed_over: str | None, status: int = 0):
    handed = f"HANDED_OVER={handed_over}" if handed_over is not None else ""
    script = f'''
info() {{ echo "$*"; }}
has_tty() {{ false; }}
finish_output_log() {{ :; }}
UPDATING_FLAG_FILE=/nonexistent/flag PROMPT_REBOOT_ON_EXIT=0 {handed}
LOGFILE={APPLIANCE_LOG}
{_function(APPLIANCE.read_text(encoding="utf-8"), "on_exit")}
( exit {status} ); on_exit
'''
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)


@bash_capable
class TestApplianceEndOfRun:
    @pytest.mark.parametrize("status", [0, 1])
    def test_a_run_from_a_terminal_ends_by_naming_the_log(self, tmp_path, status):
        r = _on_exit(tmp_path, handed_over=None, status=status)
        assert f"Install log: {APPLIANCE_LOG}" in r.stdout

    def test_the_service_a_run_was_handed_to_leaves_it_to_the_terminal_side(self, tmp_path):
        r = _on_exit(tmp_path, handed_over="1")
        assert "Install log:" not in r.stdout

    def test_the_failure_message_names_the_one_path(self):
        text = APPLIANCE.read_text(encoding="utf-8")
        assert 'open_log_prompt "Check ${LOGFILE} for details."' in text

    def test_the_banner_names_the_one_path(self):
        text = APPLIANCE.read_text(encoding="utf-8")
        assert f"written to {APPLIANCE_LOG}" in text


# ---------------------------------------------------------------------------
# The dial installer, the real script over recorders
# ---------------------------------------------------------------------------

def _dial_dry_run(tmp_path: Path, *, update: bool, extra_env: dict | None = None,
                  sudo_user: str | None = None, old_home_log: bool = False, handover: bool = False):
    from test_dial_installer_hd import _dry_run
    home = tmp_path  # the sandbox's HOME is the scratch directory itself
    old = home / OLD_DIAL_HOME_LOG
    if old_home_log:
        old.write_text(OLD_TEXT, encoding="utf-8")
    env = dict(extra_env or {})
    if sudo_user:
        env["SUDO_USER"] = sudo_user
    kw = {"extra_stubs": HANDOVER_STUBS} if handover else {}
    r, calls = _dry_run(tmp_path, update=update, extra_env=env, **kw)
    return r, calls, tmp_path / "install.log", old


@bash_capable
class TestDialLogPlace:
    @pytest.mark.parametrize("update, sudo_user, env", [
        (False, "pi", {}),
        (False, None, {}),
        (False, None, {"AUTOSTREAM_HANDED_OVER": "1"}),
        (False, "pi", {"AUTOSTREAM_HANDED_OVER": "1"}),
        (True, None, {}),
        (True, "pi", {}),
    ])
    def test_the_whole_run_is_in_the_one_log_and_no_copy_is_made_in_a_home(self, tmp_path, update,
                                                                           sudo_user, env):
        r, _calls, log, _old = _dial_dry_run(tmp_path, update=update, sudo_user=sudo_user,
                                             extra_env=env)
        assert r.returncode == 0, r.stderr
        assert "=== autostream dial install" in log.read_text(encoding="utf-8")
        assert not list(tmp_path.rglob("autostream_dial_install.log"))

    def test_the_script_names_the_one_path_once(self):
        text = DIAL.read_text(encoding="utf-8")
        assert text.count(DIAL_LOG) == 1
        assert "autostream_dial_install.log" not in text and "DIAL_INSTALL_LOGFILE" not in text
        assert "${HOME" not in text.split("# ---- Logging")[1].split("# ---- Flock")[0]

    @pytest.mark.parametrize("update", [False, True])
    def test_a_log_an_older_release_left_in_a_home_is_not_touched(self, tmp_path, update):
        r, _calls, log, old = _dial_dry_run(tmp_path, update=update, old_home_log=True)
        assert r.returncode == 0, r.stderr
        assert old.read_text(encoding="utf-8") == OLD_TEXT
        assert log.exists()

    def test_an_existing_log_is_appended_to(self, tmp_path):
        (tmp_path / "install.log").write_text("=== an earlier run ===\n", encoding="utf-8")
        r, _calls, log, _old = _dial_dry_run(tmp_path, update=False)
        assert r.returncode == 0, r.stderr
        assert log.read_text(encoding="utf-8").startswith("=== an earlier run ===\n=== autostream dial")

    def test_a_link_at_the_log_path_is_still_refused(self, tmp_path):
        victim = tmp_path / "victim"
        victim.write_text("secret\n", encoding="utf-8")
        (tmp_path / "install.log").symlink_to(victim)
        r, _calls, _log, _old = _dial_dry_run(tmp_path, update=False)
        assert r.returncode == 0, r.stderr
        assert victim.read_text(encoding="utf-8") == "secret\n"
        assert "not writing the install log there" in r.stderr

    def test_a_run_from_a_terminal_names_the_log_at_the_start_and_at_the_end(self, tmp_path):
        r, _calls, log, _old = _dial_dry_run(tmp_path, update=False)
        lines = [ln for ln in r.stdout.splitlines() if ln == f"Install log: {log}"]
        assert len(lines) == 2

    def test_the_service_a_run_was_handed_to_names_it_once(self, tmp_path):
        r, _calls, log, _old = _dial_dry_run(tmp_path, update=False,
                                             extra_env={"AUTOSTREAM_HANDED_OVER": "1"})
        assert [ln for ln in r.stdout.splitlines() if ln.startswith("Install log:")] == \
            [f"Install log: {log}"]

    def test_the_terminal_side_of_a_hand_over_follows_the_file_the_unit_writes(self, tmp_path):
        r, calls, log, _old = _dial_dry_run(tmp_path, update=False, handover=True,
                                            extra_env={"FAKE_RC": "0"})
        assert r.returncode == 0, r.stderr
        assert f"Install log: {log}" in r.stdout
        # The path given to the follower is the one the unit's run opens.
        script = DIAL.read_text(encoding="utf-8")
        assert re.search(r'hand_over_to_unit autostream-dial-install [^\n]*\\\n\s+"\$DIAL_INSTALL_LOG"', script)
        assert re.search(r'start_install_log "\$DIAL_INSTALL_LOG"', script)
        assert not log.exists()  # the terminal side wrote nothing itself

    def test_the_banner_names_the_one_path(self):
        text = (REPO_ROOT / "installer" / "dial" / "helpers.sh").read_text(encoding="utf-8")
        assert f"written to {DIAL_LOG}" in text
        assert "~/autostream_dial_install.log" not in text


# ---------------------------------------------------------------------------
# The writer both installers share, as the dial calls it
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_root(tmp_path):
    env = Env(tmp_path)
    env.fake("chown", '#!/bin/bash\necho "chown $*" >> "$TRACE"\n')
    return env


def _start(env: Env, body: str, logdir: Path):
    script = (f'source "{LIB / "state_files.sh"}"\nsource "{LIB / "output_log.sh"}"\n'
              f'start_install_log "{logdir.as_posix()}/dial-install.log" 0640 root:adm\n'
              f"{body}\nfinish_output_log\n")
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60,
                          env=env.env())


@bash_capable
class TestStartInstallLogForTheDial:
    def test_a_missing_directory_and_log_are_made_with_the_dial_owner_and_mode(self, fake_root, tmp_path):
        logdir = tmp_path / "fresh" / "autostream"
        r = _start(fake_root, "echo from-the-run", logdir)
        assert r.returncode == 0, r.stderr
        log = logdir / "dial-install.log"
        assert "from-the-run" in log.read_text(encoding="utf-8")
        assert stat.S_IMODE(logdir.stat().st_mode) == 0o755
        assert stat.S_IMODE(log.stat().st_mode) == 0o640
        assert any(c.startswith("chown root:adm") for c in fake_root.calls())

    def test_an_existing_log_is_appended_to_and_keeps_its_identity(self, fake_root, tmp_path):
        logdir = tmp_path / "logs"
        logdir.mkdir()
        log = logdir / "dial-install.log"
        log.write_text("earlier\n", encoding="utf-8")
        inode = log.stat().st_ino
        r = _start(fake_root, "echo from-the-run", logdir)
        assert r.returncode == 0, r.stderr
        assert log.read_text(encoding="utf-8").startswith("earlier\n")
        assert "from-the-run" in log.read_text(encoding="utf-8")
        assert log.stat().st_ino == inode

    def test_the_directory_owner_can_change_while_the_log_is_open(self, fake_root, tmp_path):
        logdir = tmp_path / "fresh"
        body = (f'echo before\n/usr/bin/chown -R "$(id -un)" "{logdir.as_posix()}"\n'
                "echo after")
        r = _start(fake_root, body, logdir)
        assert r.returncode == 0, r.stderr
        text = (logdir / "dial-install.log").read_text(encoding="utf-8")
        assert "before" in text and "after" in text

    def test_a_link_at_the_log_path_is_refused_and_the_run_goes_on(self, fake_root, tmp_path):
        logdir = tmp_path / "logs"
        logdir.mkdir()
        victim = tmp_path / "victim"
        victim.write_text("secret\n", encoding="utf-8")
        (logdir / "dial-install.log").symlink_to(victim)
        r = _start(fake_root, "echo still-running", logdir)
        assert r.returncode == 0, r.stderr
        assert "still-running" in r.stdout
        assert victim.read_text(encoding="utf-8") == "secret\n"
        assert "not writing the install log there" in r.stderr


# ---------------------------------------------------------------------------
# The hand-over: the follower reads the file the unit writes
# ---------------------------------------------------------------------------

UNIT = r"""#!/bin/bash
# Stands in for the transient unit: runs the real appliance logging into the path
# the installer's own globals decide, with no sudo user, as a service has none.
echo "systemd-run $*" >> "$TRACE"
echo "Running as unit: autostream-install.service."
env -u SUDO_USER bash -c '
  source "$LIBDIR/state_files.sh"; source "$LIBDIR/helpers.sh"
  ORIG_HOME="$FAKE_HOME"; SCRIPT_NAME=autostream_install.sh ORIG_USER=pi
  eval "$GLOBALS"
  init_logging
  echo "line written by the unit"
  finish_output_log'
"""


@bash_capable
class TestHandOverFollowsTheUnitsLog:
    def test_the_terminal_shows_what_the_unit_wrote_to_the_path_it_was_given(self, tmp_path):
        env = Env(tmp_path)
        env.fake("systemd-run", UNIT)
        env.fake("systemctl", '#!/bin/bash\n[[ "$1" == is-active ]] && exit 3\nexit 0\n')
        env.fake("id", '#!/bin/bash\n[[ "$1" == "-u" ]] && { echo 0; exit 0; }\nexec /usr/bin/id "$@"\n')
        home = tmp_path / "home" / "pi"
        home.mkdir(parents=True)
        logdir = tmp_path / "var" / "log" / "autostream"
        globals_ = _appliance_globals(logdir, home)
        cg = tmp_path / "cgroup"
        cg.write_text("0::/user.slice/user-1000.slice/session-4.scope\n", encoding="utf-8")
        sd = tmp_path / "run-systemd"
        sd.mkdir()
        # LOGFILE as the installer's main() hands it to the follower.
        script = (
            f'HANDOVER_CGROUP_FILE="{cg.as_posix()}"\nHANDOVER_SYSTEMD_DIR="{sd.as_posix()}"\n'
            "HANDOVER_POLL_SECONDS=0.1\n"
            f'source "{LIB / "handover.sh"}"\n{globals_}'
            'hand_over_to_unit autostream-install /opt/x/installer.sh "${LOGFILE}" --unattended\n'
            'echo "RC=$HANDOVER_RC"\n')
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60,
                           cwd=tmp_path,
                           env=env.env(LIBDIR=LIB.as_posix(), FAKE_HOME=home.as_posix(),
                                       GLOBALS=globals_, SUDO_USER="pi"))
        assert r.returncode == 0, r.stderr
        assert "RC=0" in r.stdout
        assert "line written by the unit" in r.stdout
        assert f"Progress is shown from" in r.stdout and str(logdir / "autostream_install.log") in r.stdout
        assert list(home.iterdir()) == []

    def test_the_hand_over_no_longer_passes_a_home_or_a_log_location_on(self, tmp_path):
        text = (LIB / "handover.sh").read_text(encoding="utf-8")
        m = re.search(r"^HANDOVER_ENV_VARS=\((.*)\)$", text, re.M)
        names = m.group(1).split()
        assert "HOME" not in names and "DIAL_INSTALL_LOGFILE" not in names
        assert "SUDO_USER" in names
