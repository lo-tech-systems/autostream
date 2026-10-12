"""The last root writes into directories the service account owns.

The service account can put a link, or any other file, at any name in its own
directories. The back-end version stamps, the dial's saved copies of its state
files and the appliance's install log were still written by name, so a link
there would have been followed by root; the stamps were also trusted on
sight, so one the account wrote could stop a rebuild. Each is exercised with a
link planted at its name, as that account would plant it, and checked for what
the link points at being left alone.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_dial_staged_install import Env, REPO_ROOT, bash_capable, posix_only  # noqa: E402
from test_dial_installer_hardening import _real_python3  # noqa: E402

pytestmark = posix_only

LIB = REPO_ROOT / "installer" / "lib"
SECRET = "root-only-contents\n"


@pytest.fixture
def victim(tmp_path):
    path = tmp_path / "victim"
    path.write_text(SECRET, encoding="utf-8")
    path.chmod(0o600)
    return path


def _stubs(tmp_path: Path, **scripts: str) -> Path:
    bin_dir = tmp_path / "stubs"
    bin_dir.mkdir(exist_ok=True)
    scripts.setdefault("chown", "#!/bin/sh\nexit 0\n")
    for name, text in scripts.items():
        (bin_dir / name).write_text(text, encoding="utf-8")
        (bin_dir / name).chmod(0o755)
    return bin_dir


def _bash(tmp_path: Path, body: str, **scripts: str) -> subprocess.CompletedProcess:
    e = dict(os.environ)
    e["PATH"] = _stubs(tmp_path, **scripts).as_posix() + os.pathsep + e["PATH"]
    return subprocess.run(["bash", "-c", body], capture_output=True, text=True,
                          timeout=30, env=e, cwd=tmp_path)


# ---------------------------------------------------------------------------
# The OwnTone and vibra version stamps
# ---------------------------------------------------------------------------

BACKENDS = [
    pytest.param("owntone.sh", "OWNTONE_MINI_VERSION_STAMP", "OWNTONE_MINI_VERSION", "1.4.3",
                 "OWNTONE_MINI_BINARY", "owntone_mini_stamp_reports_pinned_version",
                 "write_owntone_mini_version_stamp", id="owntone"),
    pytest.param("vibra.sh", "VIBRA_VERSION_STAMP", "VIBRA_VERSION", "v1.0.1",
                 "VIBRA_BINARY", "vibra_mini_stamp_reports_pinned_version",
                 "write_vibra_version_stamp", id="vibra"),
]


def _backend(tmp_path: Path, lib: str, stamp_var: str, version_var: str, binary_var: str,
             body: str, **scripts: str):
    state = tmp_path / "state"
    state.mkdir(exist_ok=True)
    binary = tmp_path / "binary"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    binary.chmod(0o755)
    stamp = state / "stamp"
    # vibra checks ${VIBRA_INSTALL_PREFIX}/bin/vibra-mini.
    prefix = tmp_path / "prefix"
    (prefix / "bin").mkdir(parents=True, exist_ok=True)
    (prefix / "bin" / "vibra-mini").write_text("#!/bin/sh\n", encoding="utf-8")
    (prefix / "bin" / "vibra-mini").chmod(0o755)
    script = (
        "set -euo pipefail\n"
        'info() { :; }; warn() { :; }; update_progress() { :; }\n'
        f'source "{LIB / "state_files.sh"}"\nsource "{LIB / lib}"\n'
        f'{stamp_var}="{stamp}"\n{binary_var}="{binary}"\nVIBRA_INSTALL_PREFIX="{prefix}"\n'
        f"{body}\n")
    return _bash(tmp_path, script, **scripts), stamp


@bash_capable
@pytest.mark.parametrize("lib, stamp_var, version_var, version, binary_var, check, write", BACKENDS)
class TestVersionStamps:
    def test_the_stamp_is_not_written_through_a_link(
            self, tmp_path, victim, lib, stamp_var, version_var, version, binary_var, check, write):
        (tmp_path / "state").mkdir()
        (tmp_path / "state" / "stamp").symlink_to(victim)
        r, stamp = _backend(tmp_path, lib, stamp_var, version_var, binary_var, write)
        assert r.returncode == 0, r.stderr
        assert victim.read_text(encoding="utf-8") == SECRET
        assert not stamp.is_symlink()
        assert stamp.read_text(encoding="utf-8") == version

    def test_a_dangling_link_does_not_create_what_it_points_at(
            self, tmp_path, lib, stamp_var, version_var, version, binary_var, check, write):
        target = tmp_path / "boot-file"
        (tmp_path / "state").mkdir()
        (tmp_path / "state" / "stamp").symlink_to(target)
        r, stamp = _backend(tmp_path, lib, stamp_var, version_var, binary_var, write)
        assert r.returncode == 0, r.stderr
        assert not target.exists()
        assert not stamp.is_symlink()

    def test_a_stamp_written_and_read_back_counts(
            self, tmp_path, lib, stamp_var, version_var, version, binary_var, check, write):
        r, _stamp = _backend(tmp_path, lib, stamp_var, version_var, binary_var,
                             f"{write}\n{check}\necho matched")
        assert r.returncode == 0, r.stderr
        assert "matched" in r.stdout

    def test_a_stamp_the_service_account_owns_does_not_count(
            self, tmp_path, lib, stamp_var, version_var, version, binary_var, check, write):
        # `id -u` answers as if root were running this; the file is the test
        # user's, so it is not root's.
        r, stamp = _backend(
            tmp_path, lib, stamp_var, version_var, binary_var,
            f'printf "%s" "${version_var}" > "{tmp_path / "state" / "stamp"}"\n'
            f"{check} && echo matched || echo rebuild",
            id="#!/bin/sh\necho 4242\n")
        assert r.returncode == 0, r.stderr
        assert "rebuild" in r.stdout

    def test_the_same_stamp_counts_when_root_owns_it(
            self, tmp_path, lib, stamp_var, version_var, version, binary_var, check, write):
        r, stamp = _backend(
            tmp_path, lib, stamp_var, version_var, binary_var,
            f'printf "%s" "${version_var}" > "{tmp_path / "state" / "stamp"}"\n'
            f"{check} && echo matched || echo rebuild")
        assert "matched" in r.stdout

    @pytest.mark.parametrize("text", ["", "0.0.1", "1.4.3\n; touch /tmp/x", "x" * 70,
                                      "1.4.3 extra", "$(id)"])
    def test_a_stamp_that_is_not_the_pinned_version_does_not_count(
            self, tmp_path, text, lib, stamp_var, version_var, version, binary_var, check, write):
        (tmp_path / "state").mkdir()
        (tmp_path / "state" / "stamp").write_text(text, encoding="utf-8")
        r, _ = _backend(tmp_path, lib, stamp_var, version_var, binary_var,
                        f"{check} && echo matched || echo rebuild")
        assert "rebuild" in r.stdout

    def test_a_link_for_a_stamp_does_not_count(
            self, tmp_path, victim, lib, stamp_var, version_var, version, binary_var, check, write):
        victim.write_text(version, encoding="utf-8")
        (tmp_path / "state").mkdir()
        (tmp_path / "state" / "stamp").symlink_to(victim)
        r, _ = _backend(tmp_path, lib, stamp_var, version_var, binary_var,
                        f"{check} && echo matched || echo rebuild")
        assert "rebuild" in r.stdout

    def test_a_pipe_for_a_stamp_does_not_hold_the_installer_up(
            self, tmp_path, lib, stamp_var, version_var, version, binary_var, check, write):
        (tmp_path / "state").mkdir()
        os.mkfifo(tmp_path / "state" / "stamp")
        r, _ = _backend(tmp_path, lib, stamp_var, version_var, binary_var,
                        f"{check} && echo matched || echo rebuild")
        assert "rebuild" in r.stdout

    def test_the_text_uses_the_helpers_and_no_plain_redirect_or_cat(
            self, tmp_path, lib, stamp_var, version_var, version, binary_var, check, write):
        text = (LIB / lib).read_text(encoding="utf-8")
        body = text[text.index(f"{write}() {{"):]
        body = body[:body.index("\n}\n")]
        assert "write_state_file" in body and "> \"${" not in body
        body = text[text.index(f"{check}() {{"):]
        body = body[:body.index("\n}\n")]
        assert "read_state_file_owned" in body and "cat " not in body


# ---------------------------------------------------------------------------
# The dial's restore of the files it saved before an update
# ---------------------------------------------------------------------------

@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def _backup(env: Env, files: dict[str, str]) -> Path:
    backup = env.upd / "update-prev"
    manifest = []
    for path, text in files.items():
        saved = backup / "files" / path.lstrip("/")
        saved.parent.mkdir(parents=True, exist_ok=True)
        saved.write_text(text, encoding="utf-8")
        saved.chmod(0o640)
        manifest.append(f"PRESENT\t{path}")
    (backup / "MANIFEST").write_text("\n".join(manifest) + "\n", encoding="utf-8")
    return backup


@bash_capable
class TestRestoreOwnedFiles:
    STATE_FILE = "/var/lib/autostream/install-state.env"

    def test_a_file_in_the_state_directory_is_not_restored_through_a_link(self, env, victim):
        env.fake("chown", "#!/bin/sh\nexit 0\n")
        backup = _backup(env, {self.STATE_FILE: "DIAL_UUID=saved\n"})
        env.install_state.symlink_to(victim)
        r = env.run(f'restore_owned_files "{backup}"')
        assert r.returncode == 0, r.stderr
        assert victim.read_text(encoding="utf-8") == SECRET
        assert not env.install_state.is_symlink()
        assert env.install_state.read_text(encoding="utf-8") == "DIAL_UUID=saved\n"

    def test_a_dangling_link_does_not_create_what_it_points_at(self, env, tmp_path):
        env.fake("chown", "#!/bin/sh\nexit 0\n")
        target = tmp_path / "somewhere" / "new-file"
        backup = _backup(env, {self.STATE_FILE: "DIAL_UUID=saved\n"})
        env.install_state.symlink_to(target)
        r = env.run(f'restore_owned_files "{backup}"')
        assert r.returncode == 0, r.stderr
        assert not target.exists() and not target.parent.exists()
        assert env.install_state.read_text(encoding="utf-8") == "DIAL_UUID=saved\n"

    def test_nothing_is_copied_to_a_name_in_the_state_directory(self, env, tmp_path):
        # A copy by name can be steered between the removal of the old file and
        # the creation of the new one, so none is made there.
        log = tmp_path / "cp-calls"
        env.fake("chown", "#!/bin/sh\nexit 0\n")
        env.fake("cp", f'#!/bin/bash\necho "$@" >> "{log}"\nexec /bin/cp "$@"\n')
        backup = _backup(env, {self.STATE_FILE: "DIAL_UUID=saved\n",
                               "/var/lib/autostream/hd-kiosk": "",
                               "/etc/systemd/system/autostream_dial.service": "conf\n"})
        r = env.run(f'restore_owned_files "{backup}"')
        assert r.returncode == 0, r.stderr
        calls = log.read_text(encoding="utf-8") if log.exists() else ""
        assert "/var/lib/autostream/" not in calls
        assert "autostream_dial.service" in calls

    def test_the_restored_file_has_the_saved_mode(self, env):
        env.fake("chown", "#!/bin/sh\nexit 0\n")
        backup = _backup(env, {self.STATE_FILE: "DIAL_UUID=saved\n"})
        r = env.run(f'restore_owned_files "{backup}"')
        assert r.returncode == 0, r.stderr
        assert stat.S_IMODE(env.install_state.stat().st_mode) == 0o640

    def test_a_file_outside_the_state_directory_is_still_restored(self, env):
        backup = _backup(env, {"/etc/systemd/system/autostream_dial.service": "old conf\n"})
        r = env.run(f'restore_owned_files "{backup}"')
        assert r.returncode == 0, r.stderr
        assert (env.root / "etc/systemd/system/autostream_dial.service").read_text(
            encoding="utf-8") == "old conf\n"

    def test_the_hd_marker_is_not_written_through_a_link(self, env, victim):
        env.fake("chown", "#!/bin/sh\nexit 0\n")
        _real_python3(env)
        (env.state / "hd-kiosk").symlink_to(victim)
        r = env.run("write_hd_marker")
        assert r.returncode == 0, r.stderr
        assert victim.read_text(encoding="utf-8") == SECRET
        assert not (env.state / "hd-kiosk").is_symlink()
        assert (env.state / "hd-kiosk").exists()


# ---------------------------------------------------------------------------
# The appliance's install log
# ---------------------------------------------------------------------------

def _logging(tmp_path: Path, log: Path, extra: str = ""):
    script = (
        f'source "{LIB / "state_files.sh"}"\nsource "{LIB / "helpers.sh"}"\n'
        f'LOGFILE="{log}" SCRIPT_NAME=autostream_install.sh ORIG_USER=pi ORIG_HOME=/home/pi\n'
        f"init_logging\n{extra}\necho after-logging\n")
    return _bash(tmp_path, script)


def _drain(path: Path, needle: str, tries: int = 50) -> str:
    import time
    for _ in range(tries):
        text = path.read_text(encoding="utf-8") if path.exists() else ""
        if needle in text:
            return text
        time.sleep(0.1)
    return path.read_text(encoding="utf-8") if path.exists() else ""


@bash_capable
class TestInstallLog:
    def test_a_link_at_the_log_is_not_followed_and_the_run_goes_on(self, tmp_path, victim):
        log = tmp_path / "autostream_install.log"
        log.symlink_to(victim)
        r = _logging(tmp_path, log)
        assert r.returncode == 0, r.stderr
        assert victim.read_text(encoding="utf-8") == SECRET
        assert "after-logging" in r.stdout
        assert "not a regular file" in r.stderr or "link" in r.stderr

    def test_a_dangling_link_at_the_log_creates_nothing(self, tmp_path):
        log = tmp_path / "autostream_install.log"
        target = tmp_path / "boot-file"
        log.symlink_to(target)
        r = _logging(tmp_path, log)
        assert r.returncode == 0, r.stderr
        assert not target.exists()
        assert "after-logging" in r.stdout

    def test_a_directory_at_the_log_is_refused(self, tmp_path):
        log = tmp_path / "autostream_install.log"
        log.mkdir()
        r = _logging(tmp_path, log)
        assert r.returncode == 0, r.stderr
        assert "after-logging" in r.stdout

    def test_a_missing_log_is_made_beside_its_name_and_written(self, tmp_path):
        log = tmp_path / "logs" / "autostream_install.log"
        r = _logging(tmp_path, log)
        assert r.returncode == 0, r.stderr
        text = _drain(log, "after-logging")
        assert "starting at" in text and "after-logging" in text
        assert stat.S_IMODE(log.stat().st_mode) == 0o644
        assert not [p for p in log.parent.iterdir() if p.name != log.name]

    def test_an_existing_log_is_appended_to(self, tmp_path):
        log = tmp_path / "autostream_install.log"
        log.write_text("[INFO] first run\n", encoding="utf-8")
        r = _logging(tmp_path, log)
        assert r.returncode == 0, r.stderr
        text = _drain(log, "after-logging")
        assert text.startswith("[INFO] first run\n")
        assert "after-logging" in text

    def test_a_link_put_there_after_the_check_is_refused_by_the_open(self, tmp_path, victim):
        # The sink the output is piped through, run on its own against a link.
        log = tmp_path / "autostream_install.log"
        log.symlink_to(victim)
        r = _bash(tmp_path, f'echo hello | dd of="{log}" oflag=append,nofollow conv=notrunc '
                            "status=none; echo rc=$?")
        assert "rc=0" not in r.stdout
        assert victim.read_text(encoding="utf-8") == SECRET

    def test_the_text_has_no_plain_append_or_truncation_of_the_log(self):
        text = (LIB / "helpers.sh").read_text(encoding="utf-8")
        body = text[text.index("init_logging() {"):]
        body = body[:body.index("\n}\n")]
        assert "tee -a" not in body and ": > " not in body
        assert "nofollow" in body
