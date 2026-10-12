"""The appliance update: what root stages, runs and trusts is out of the service
account's reach.

The service account owns /var/lib/autostream and can replace any name in it.
The release an update runs as root is therefore staged in the root-only
directory instead, the boot-time retry acts only on what root left there, and
the installer no longer takes a path, a flag or a list from the install state
file without checking it. These tests plant what the service account could
plant (a substituted installer in the old staging place, a link at the state
file, a hostile tag, a loose or foreign directory) and check that root's code
neither runs it nor follows it, and that a normal update and a retry after an
interrupted one still work.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "supervisor"))
import autostream_update_support as _asu  # noqa: E402
from test_dial_staged_install import Env, REPO_ROOT, bash_capable, posix_only  # noqa: E402
from test_dial_installer_hardening import _function_text  # noqa: E402
from test_update_recovery import (  # noqa: E402
    _chown_noop, _geteuid_root, _load_retry, _make_installer, _old_timestamp,
    _write_result,
)
from test_updater_staging import (  # noqa: E402
    _copy_tarball_to, _fake_release, _load_host, _make_tarball, _no_installed,
    _unit_inactive,
)

pytestmark = posix_only

APPLIANCE_INSTALLER = REPO_ROOT / "autostream_install.sh"
STATE_FILES = REPO_ROOT / "installer" / "lib" / "state_files.sh"
BOOTSTRAP = REPO_ROOT / "bootstrap.sh"
HOSTILE = "#!/bin/sh\ntouch \"$(dirname \"$0\")/../../../ran-as-root\"\nexit 0\n"


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


# ---------------------------------------------------------------------------
# apply: the release is staged where only root can write, and run from there
# ---------------------------------------------------------------------------

def _apply(mod, tar_path):
    """Run cmd_apply with the network, the lock and the scheduler faked and
    return the result and every command given to the scheduler."""
    commands: list[list[str]] = []

    def fake_run(cmd, timeout=60):
        commands.append(list(cmd))
        return 0, "", ""

    with _unit_inactive(mod), \
         patch.object(mod, "_resolve_release", return_value=_fake_release()), \
         _no_installed(mod), \
         patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
         patch("os.path.isfile", return_value=True), \
         patch("os.access", return_value=True), \
         patch.object(_asu, "_download_file", side_effect=_copy_tarball_to(tar_path)), \
         patch.object(_asu, "_run", side_effect=fake_run), \
         patch.object(mod, "fcntl") as fc:
        fc.LOCK_EX, fc.LOCK_NB, fc.LOCK_UN = 2, 4, 8
        fc.flock.return_value = None
        return mod.cmd_apply(auto=False), commands


def _loaded(tmp_path: Path, make_dir: bool = True):
    mod = _load_host(tmp_path)
    upd = tmp_path / "upd"
    if make_dir:
        upd.mkdir(mode=0o700)
    mod.STAGING_DIR = upd / "staging"
    return mod, upd


class TestApplyStagesInTheRootOnlyDirectory:
    def test_the_installer_that_is_scheduled_is_under_the_root_only_directory(self, tmp_path):
        mod, upd = _loaded(tmp_path)
        result, commands = _apply(mod, _make_tarball(tmp_path))
        assert result["ok"] is True, result
        scheduled = [c for c in commands if any("--update" == a for a in c)]
        assert len(scheduled) == 1
        installer = Path(scheduled[0][scheduled[0].index("--update") - 1])
        assert installer.is_relative_to(upd / "staging")
        assert installer.is_file()

    def test_a_marker_in_the_root_only_directory_records_the_staged_tag(self, tmp_path):
        mod, upd = _loaded(tmp_path)
        result, _ = _apply(mod, _make_tarball(tmp_path))
        assert result["ok"] is True
        assert (upd / "update-in-progress").read_text().strip() == "v1.2.3"
        assert stat.S_IMODE(os.stat(upd / "update-in-progress").st_mode) == 0o600

    def test_the_directory_is_made_private_when_it_is_not_there_yet(self, tmp_path):
        mod, upd = _loaded(tmp_path, make_dir=False)
        result, _ = _apply(mod, _make_tarball(tmp_path))
        assert result["ok"] is True
        assert stat.S_IMODE(os.stat(upd).st_mode) == 0o700

    def test_a_loose_directory_is_refused_and_nothing_is_staged_or_run(self, tmp_path):
        mod, upd = _loaded(tmp_path)
        upd.chmod(0o755)
        result, commands = _apply(mod, _make_tarball(tmp_path))
        assert result["ok"] is False
        assert commands == []
        assert list(upd.iterdir()) == []

    def test_a_directory_owned_by_someone_else_is_refused(self, tmp_path):
        mod, upd = _loaded(tmp_path)
        mod.UPDATE_STATE_UID = os.getuid() + 1
        result, commands = _apply(mod, _make_tarball(tmp_path))
        assert result["ok"] is False
        assert commands == []
        assert list(upd.iterdir()) == []

    def test_a_link_in_place_of_the_directory_is_not_followed(self, tmp_path):
        mod, upd = _loaded(tmp_path, make_dir=False)
        elsewhere = tmp_path / "theirs"
        elsewhere.mkdir(mode=0o700)
        upd.symlink_to(elsewhere)
        result, commands = _apply(mod, _make_tarball(tmp_path))
        assert result["ok"] is False
        assert commands == []
        assert list(elsewhere.iterdir()) == []

    def test_a_failed_download_leaves_no_marker(self, tmp_path):
        mod, upd = _loaded(tmp_path)
        result, _ = _apply(mod, _make_tarball(tmp_path, installer_name="wrong.sh"))
        assert result["ok"] is False
        assert not (upd / "update-in-progress").exists()

    def test_a_final_result_clears_the_marker(self, tmp_path):
        mod, upd = _loaded(tmp_path)
        _apply(mod, _make_tarball(tmp_path))
        assert (upd / "update-in-progress").exists()
        mod._write_update_result("in_progress", 50, "still going")
        assert (upd / "update-in-progress").exists()
        mod._write_update_result("failure", 0, "stopped")
        assert not (upd / "update-in-progress").exists()


# ---------------------------------------------------------------------------
# The boot-time retry acts only on what root left in the root-only directory
# ---------------------------------------------------------------------------

def _retry(mod):
    commands: list[list[str]] = []

    def fake_run(cmd, timeout=60):
        commands.append(list(cmd))
        return 0, "", ""

    with _geteuid_root(), \
         patch.object(mod, "_is_pre_boot", return_value=True), \
         patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
         patch("os.path.isfile", return_value=True), \
         patch("os.access", return_value=True), \
         patch.object(mod, "_run", side_effect=fake_run), \
         _chown_noop():
        rc = mod.main()
    return rc, commands


def _scheduled(commands) -> list[list[str]]:
    return [c for c in commands if "--update" in c]


class TestRetryActsOnlyOnWhatRootStaged:
    def test_an_interrupted_update_is_retried_from_the_root_only_directory(self, tmp_path):
        mod = _load_retry(tmp_path)
        _write_result(tmp_path, "in_progress", _old_timestamp())
        mod.STAGING_DIR.mkdir()
        installer = _make_installer(tmp_path, mod.STAGING_DIR)
        mod.RELEASE_TAG_FILE.write_text("v1.2.3\n")
        rc, commands = _retry(mod)
        assert rc == 0
        (cmd,) = _scheduled(commands)
        assert Path(cmd[cmd.index("--update") - 1]) == installer
        assert installer.is_relative_to(mod.STAGING_DIR.parent)
        assert "--setenv=AUTOSTREAM_RELEASE_TAG=v1.2.3" in cmd
        assert mod.RETRY_COUNT_FILE.read_text().strip() == "1"

    def test_the_count_carries_over_and_stops_at_the_cap(self, tmp_path):
        mod = _load_retry(tmp_path)
        _write_result(tmp_path, "in_progress", _old_timestamp())
        mod.STAGING_DIR.mkdir()
        _make_installer(tmp_path, mod.STAGING_DIR)
        mod.RETRY_COUNT_FILE.write_text(f"{mod.MAX_RETRIES}\n")
        rc, commands = _retry(mod)
        assert rc == 1
        assert _scheduled(commands) == []
        assert "failure" in mod.UPDATE_RESULT_FILE.read_text().lower()

    def test_a_count_that_is_not_a_number_counts_as_none(self, tmp_path):
        mod = _load_retry(tmp_path)
        mod.STAGING_DIR.mkdir()
        mod.RETRY_COUNT_FILE.write_text("-5; reboot\n")
        assert mod._read_retry_count() == 0

    def test_a_substituted_installer_in_the_old_staging_place_is_never_run(self, tmp_path):
        mod = _load_retry(tmp_path)
        _write_result(tmp_path, "in_progress", _old_timestamp())
        old = tmp_path / "update-staging" / "src" / "release-1"
        old.mkdir(parents=True)
        (old / "autostream_install.sh").write_text(HOSTILE)
        (old / "autostream_install.sh").chmod(0o755)
        (tmp_path / "update-staging" / "release_tag").write_text("v9.9.9\n")
        mod.STAGING_DIR.mkdir()          # the root-only directory has nothing staged
        rc, commands = _retry(mod)
        assert rc == 1
        assert _scheduled(commands) == []
        assert not any("update-staging" in " ".join(c) for c in commands)
        assert "failure" in mod.UPDATE_RESULT_FILE.read_text().lower()

    def test_a_status_the_service_account_wrote_does_not_start_a_run_of_old_files(self, tmp_path):
        # An installer is still staged from an earlier update, but root left no
        # record that an update is in flight; only the (replaceable) status says so.
        mod = _load_retry(tmp_path)
        _write_result(tmp_path, "in_progress", _old_timestamp())
        mod.STAGING_DIR.mkdir()
        installer = _make_installer(tmp_path, mod.STAGING_DIR)
        (mod.STAGING_DIR.parent / "update-in-progress").unlink()
        rc, commands = _retry(mod)
        assert rc == 1
        assert _scheduled(commands) == []
        assert installer.exists()

    def test_a_directory_the_service_account_owns_is_not_trusted(self, tmp_path):
        mod = _load_retry(tmp_path)
        _write_result(tmp_path, "in_progress", _old_timestamp())
        mod.STAGING_DIR.mkdir()
        _make_installer(tmp_path, mod.STAGING_DIR)
        mod.UPDATE_STATE_UID = os.getuid() + 1      # the owner is not who root trusts
        rc, commands = _retry(mod)
        assert rc == 1
        assert _scheduled(commands) == []

    def test_a_loose_directory_is_not_trusted(self, tmp_path):
        mod = _load_retry(tmp_path)
        _write_result(tmp_path, "in_progress", _old_timestamp())
        upd = tmp_path / "upd"
        upd.mkdir(mode=0o700)
        mod.STAGING_DIR = upd / "staging"
        mod.RELEASE_TAG_FILE = mod.STAGING_DIR / "release_tag"
        mod.RETRY_COUNT_FILE = mod.STAGING_DIR / "retry_count"
        mod.STAGING_DIR.mkdir()
        _make_installer(tmp_path, mod.STAGING_DIR)
        upd.chmod(0o770)
        rc, commands = _retry(mod)
        assert rc == 1
        assert _scheduled(commands) == []

    def test_a_tag_that_is_not_a_version_is_not_handed_to_the_installer(self, tmp_path):
        mod = _load_retry(tmp_path)
        _write_result(tmp_path, "in_progress", _old_timestamp())
        mod.STAGING_DIR.mkdir()
        _make_installer(tmp_path, mod.STAGING_DIR)
        mod.RELEASE_TAG_FILE.write_text("v1.2.3; touch /tmp/pwned\n")
        rc, commands = _retry(mod)
        assert rc == 0
        (cmd,) = _scheduled(commands)
        tags = [a for a in cmd if a.startswith("--setenv=AUTOSTREAM_RELEASE_TAG=")]
        assert tags == ["--setenv=AUTOSTREAM_RELEASE_TAG=v1.2.3"]

    def test_a_tag_that_is_not_a_version_in_the_marker_too_reads_as_unknown(self, tmp_path):
        mod = _load_retry(tmp_path)
        _write_result(tmp_path, "in_progress", _old_timestamp())
        mod.STAGING_DIR.mkdir()
        _make_installer(tmp_path, mod.STAGING_DIR)
        mod.RELEASE_TAG_FILE.write_text("junk;\n")
        _asu.mark_update_in_progress(mod.STAGING_DIR, "also;junk", os.getuid())
        rc, commands = _retry(mod)
        (cmd,) = _scheduled(commands)
        assert "--setenv=AUTOSTREAM_RELEASE_TAG=unknown" in cmd

    def test_a_retry_that_cannot_proceed_clears_the_marker(self, tmp_path):
        mod = _load_retry(tmp_path)
        _write_result(tmp_path, "in_progress", _old_timestamp())
        mod.STAGING_DIR.mkdir()
        _make_installer(tmp_path, mod.STAGING_DIR)
        mod.RETRY_COUNT_FILE.write_text(f"{mod.MAX_RETRIES}\n")
        _retry(mod)
        assert not (mod.STAGING_DIR.parent / "update-in-progress").exists()


class TestReleaseTagCheck:
    @pytest.mark.parametrize("tag", ["1.3.0", "v1.3.0", "0.7.0-beta.1", "1.2", "v2.0.0-rc.3"])
    def test_versions_pass(self, tag):
        assert _asu.valid_release_tag(tag)

    @pytest.mark.parametrize("tag", [
        "", "latest", "1.3.0; reboot", "$(id)", "../1.0.0", "1.0.0\nSTATUS=x",
        "v1.0.0 extra", "a" * 80,
    ])
    def test_anything_else_does_not(self, tag):
        assert not _asu.valid_release_tag(tag)

    def test_an_installed_tag_that_is_not_a_version_reads_as_unknown(self, tmp_path):
        mod = _load_host(tmp_path)
        mod.INSTALL_STATE_FILE = tmp_path / "install-state.env"
        mod.INSTALL_STATE_FILE.write_text('AUTOSTREAM_RELEASE_TAG="<script>x</script>"\n')
        assert mod._read_installed_release_tag() == "unknown"
        mod.INSTALL_STATE_FILE.write_text('AUTOSTREAM_RELEASE_TAG="0.6.1"\n')
        assert mod._read_installed_release_tag() == "0.6.1"


# ---------------------------------------------------------------------------
# The installer's reads and writes in the directory the service account owns
# ---------------------------------------------------------------------------

PREAMBLE = r"""
set -euo pipefail
IFS=$'\n\t'
info() { :; }; warn() { echo "WARN: $*" >&2; }; error() { echo "ERROR: $*" >&2; }
INSTALL_DIR=/opt/autostream
OWNTONE_MODE=mini; SDMON_METHOD=""; SDMON_CHECK=none; SDMON_CHECK_SERIAL=""
SDMON_CHECK_AT=""; SDMON_CHECK_REASON=""; FETCH_AUTOSTREAM=0
LOW_POWER=0; LOW_POWER_REQUESTED=0
AUTOSTREAM_DIR=/staged
"""


def _installer_run(env: Env, names: list[str], body: str, **extra: str):
    funcs = "\n".join(_function_text(APPLIANCE_INSTALLER, n) for n in names)
    state = (env.root / "var" / "lib" / "autostream")
    script = (
        f'{PREAMBLE}\nsource "{STATE_FILES.as_posix()}"\n'
        f'STATE_FILE="{state.as_posix()}/install-state.env"\n'
        f'UPDATE_RESULT_FILE="{state.as_posix()}/update-result.env"\n'
        f'STAMP_DIR="{state.as_posix()}"\n'
        f'UPDATE_STATE_DIR="{env.root.as_posix()}/var/lib/autostream-update"\n'
        f'UPDATE_IN_PROGRESS_FILE="$UPDATE_STATE_DIR/update-in-progress"\n'
        f'{funcs}\n{body}\n'
    )
    import subprocess
    from test_dial_staged_install import RECORDER
    # Ownership is applied through chown; the test runs as an ordinary user.
    env.fake("chown", RECORDER)
    e = env.env(**extra)
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                          timeout=60, env=e, cwd=env.tmp)


LOAD_FUNCS = ["is_valid_owntone_mode", "is_valid_sdmon_method", "load_state"]
SHOW = ('printf "mode=%s dir=%s fetch=%s method=%s low=%s check=%s\\n" '
        '"$OWNTONE_MODE" "$INSTALL_DIR" "$FETCH_AUTOSTREAM" "$SDMON_METHOD" '
        '"$LOW_POWER" "$SDMON_CHECK"')


@bash_capable
class TestLoadState:
    def test_the_values_the_installer_wrote_are_loaded(self, env):
        env.install_state.write_text(
            'OWNTONE_MODE="full"\nSDMON_METHOD="sandisk"\nSDMON_CHECK="passed"\n'
            'FETCH_AUTOSTREAM="1"\nLOW_POWER="1"\n', encoding="utf-8")
        r = _installer_run(env, LOAD_FUNCS, f"load_state\n{SHOW}")
        assert r.returncode == 0, r.stderr
        assert r.stdout.strip() == ("mode=full dir=/opt/autostream fetch=1 "
                                    "method=sandisk low=1 check=passed")

    def test_an_install_dir_line_is_ignored(self, env):
        env.install_state.write_text('INSTALL_DIR="/etc"\nOWNTONE_MODE="mini"\n', encoding="utf-8")
        r = _installer_run(env, LOAD_FUNCS, f"load_state\n{SHOW}")
        assert r.returncode == 0, r.stderr
        assert "dir=/opt/autostream" in r.stdout

    def test_a_link_at_the_state_file_reads_as_no_state(self, env):
        secret = env.tmp / "elsewhere.env"
        secret.write_text('OWNTONE_MODE="full"\nINSTALL_DIR="/etc"\n', encoding="utf-8")
        env.install_state.symlink_to(secret)
        r = _installer_run(env, LOAD_FUNCS, f"load_state\n{SHOW}")
        assert r.returncode != 0
        assert "No saved install state" in r.stderr
        assert "mode=" not in r.stdout

    def test_a_fifo_at_the_state_file_does_not_hang_or_load(self, env):
        os.mkfifo(env.install_state)
        r = _installer_run(env, LOAD_FUNCS, f"load_state\n{SHOW}")
        assert r.returncode != 0
        assert "No saved install state" in r.stderr

    def test_a_flag_that_would_run_a_command_in_an_arithmetic_test_is_dropped(self, env):
        marker = env.tmp / "ran"
        env.install_state.write_text(
            f'FETCH_AUTOSTREAM="a[$(touch {marker.as_posix()})]"\n', encoding="utf-8")
        r = _installer_run(env, LOAD_FUNCS,
                           f'load_state\n{SHOW}\n[[ ${{FETCH_AUTOSTREAM}} -eq 1 ]] || true')
        assert r.returncode == 0, r.stderr
        assert "fetch=0" in r.stdout
        assert not marker.exists()

    def test_values_that_are_not_what_the_installer_writes_keep_the_defaults(self, env):
        env.install_state.write_text(
            'OWNTONE_MODE="evil"\nSDMON_METHOD="../../bin/sh"\nSDMON_CHECK="Passed; id"\n'
            'LOW_POWER="yes"\n', encoding="utf-8")
        r = _installer_run(env, LOAD_FUNCS, f"load_state\n{SHOW}")
        assert r.returncode == 0, r.stderr
        assert r.stdout.strip() == "mode=mini dir=/opt/autostream fetch=0 method= low=0 check=none"


@bash_capable
class TestInstallerWritesAndReads:
    def test_the_result_is_written_beside_the_old_file_not_through_a_link(self, env):
        victim = env.tmp / "victim"
        victim.write_text("keep me\n", encoding="utf-8")
        env.result.symlink_to(victim)
        r = _installer_run(env, ["write_update_result"],
                           'write_update_result "in_progress" "Starting update" 0')
        assert r.returncode == 0, r.stderr
        assert victim.read_text() == "keep me\n"
        assert not env.result.is_symlink()
        text = env.result.read_text()
        assert 'STATUS="in_progress"' in text
        assert stat.S_IMODE(os.stat(env.result).st_mode) == 0o600

    def test_only_a_final_result_clears_the_in_progress_marker(self, env):
        upd = env.root / "var" / "lib" / "autostream-update"
        upd.mkdir(parents=True, exist_ok=True)
        upd.chmod(0o700)
        marker = upd / "update-in-progress"
        marker.write_text("1.3.0\n")
        r = _installer_run(env, ["write_update_result"],
                           'write_update_result "in_progress" "Working" 50')
        assert r.returncode == 0, r.stderr
        assert marker.exists()
        for status in ("success", "failure"):
            marker.write_text("1.3.0\n")
            r = _installer_run(env, ["write_update_result"],
                               f'write_update_result "{status}" "Done" 100')
            assert r.returncode == 0, r.stderr
            assert not marker.exists()

    def test_stopped_services_are_recorded_where_only_root_can_write(self):
        text = APPLIANCE_INSTALLER.read_text(encoding="utf-8")
        assert 'STOPPED_SERVICES_FILE="${UPDATE_STATE_DIR}/update-stopped-services.env"' in text

    def test_only_units_the_installer_stops_are_started_again(self, env):
        upd = env.root / "var" / "lib" / "autostream-update"
        upd.mkdir(parents=True, exist_ok=True)
        upd.chmod(0o700)
        (upd / "update-stopped-services.env").write_text(
            "owntone\n--now\nsshd\nautostream\nnetworking.service\n", encoding="utf-8")
        env.fake("systemctl", '#!/bin/bash\necho "systemctl $*" >> "$TRACE"\n')
        body = (f'STOPPED_SERVICES_FILE="{upd.as_posix()}/update-stopped-services.env"\n'
                'STOPPABLE_UNITS=(autostream_monitor autostream_bluetooth owntone vibra-mini autostream)\n'
                'restore_stopped_services')
        r = _installer_run(env, ["restore_stopped_services"], body)
        assert r.returncode == 0, r.stderr
        assert env.calls() == ["systemctl start autostream", "systemctl start owntone"]

    def test_the_low_power_record_is_not_taken_through_a_link(self, env):
        elsewhere = env.tmp / "elsewhere.env"
        elsewhere.write_text('LOW_POWER="1"\n', encoding="utf-8")
        env.install_state.symlink_to(elsewhere)
        body = ('saved_state="$(read_state_file "$STATE_FILE" || true)"\n'
                'grep -qE \'^LOW_POWER="?1"?\' <<< "$saved_state" && echo found || echo absent')
        r = _installer_run(env, [], body)
        assert r.stdout.strip() == "absent"


@bash_capable
class TestReadStateFile:
    def _read(self, env, name):
        return _installer_run(env, [], f'read_state_file "{name}" && echo rc=0 || echo rc=1')

    def test_a_regular_file_is_read(self, env):
        env.install_state.write_text("A=1\nB=2\n", encoding="utf-8")
        r = self._read(env, env.install_state.as_posix())
        assert r.stdout == "A=1\nB=2\nrc=0\n"

    def test_a_link_reads_as_absent(self, env):
        target = env.tmp / "t"
        target.write_text("A=1\n")
        env.install_state.symlink_to(target)
        r = self._read(env, env.install_state.as_posix())
        assert r.stdout == "rc=1\n"

    def test_a_directory_reads_as_absent(self, env):
        r = self._read(env, env.state.as_posix())
        assert r.stdout == "rc=1\n"

    def test_only_the_first_64_kib_is_read(self, env):
        env.install_state.write_text("K=" + "x" * 200000 + "\n", encoding="utf-8")
        r = _installer_run(env, [], f'read_state_file "{env.install_state.as_posix()}" | wc -c')
        assert int(r.stdout.strip()) == 65536

    def test_a_value_is_found_by_key(self, env):
        env.install_state.write_text("A=1\nB=two=2\nA=3\n", encoding="utf-8")
        r = _installer_run(env, [], f'read_state_value "{env.install_state.as_posix()}" B; '
                                    f'read_state_value "{env.install_state.as_posix()}" A; '
                                    f'read_state_value "{env.install_state.as_posix()}" C; echo end')
        assert r.stdout == "two=2\n1\nend\n"


# ---------------------------------------------------------------------------
# The first install stages in the root-only directory too
# ---------------------------------------------------------------------------

@bash_capable
class TestBootstrapStaging:
    def test_it_no_longer_stages_in_the_service_account_directory(self):
        text = BOOTSTRAP.read_text(encoding="utf-8")
        assert 'UPDATE_STATE_DIR="/var/lib/autostream-update"' in text
        assert "/var/lib/autostream/update-staging" not in text

    def _prepare(self, env, extra=""):
        import subprocess
        funcs = "\n".join(_function_text(BOOTSTRAP, n)
                          for n in ("prepare_update_dir", "fresh_staging_dir"))
        upd = env.root / "var" / "lib" / "autostream-update"
        script = (f'set -euo pipefail\nUPDATE_STATE_DIR="{upd.as_posix()}"\n'
                  f'STAGING_DIR="$UPDATE_STATE_DIR/staging"\n'
                  f'chown() {{ :; }}\n{funcs}\n{extra}\nfresh_staging_dir')
        return upd, subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                                   timeout=30, env=env.env())

    def test_a_clean_staging_directory_is_made_private(self, env):
        upd, r = self._prepare(env)
        assert r.returncode == 0, r.stderr
        assert stat.S_IMODE(os.stat(upd).st_mode) == 0o700
        assert stat.S_IMODE(os.stat(upd / "staging").st_mode) == 0o700

    def test_a_link_or_a_loose_directory_at_the_name_is_replaced(self, env):
        elsewhere = env.tmp / "theirs"
        elsewhere.mkdir(mode=0o755)
        upd = env.root / "var" / "lib" / "autostream-update"
        upd.rmdir()
        upd.symlink_to(elsewhere)
        _, r = self._prepare(env)
        assert r.returncode == 0, r.stderr
        assert not upd.is_symlink()
        assert list(elsewhere.iterdir()) == []


# ---------------------------------------------------------------------------
# Where the real paths point (nothing redirected)
# ---------------------------------------------------------------------------

class TestRealLocations:
    SERVICE_DIR = Path("/var/lib/autostream")

    def test_the_updater_stages_in_the_root_only_directory(self):
        from conftest import load_supervisor_script
        mod = load_supervisor_script("autostream_updater", "handoff_paths_updater")
        assert mod.STAGING_DIR == Path("/var/lib/autostream-update/staging")
        assert not mod.STAGING_DIR.is_relative_to(self.SERVICE_DIR)

    def test_the_retry_looks_only_in_the_root_only_directory(self):
        from conftest import load_supervisor_script
        mod = load_supervisor_script("autostream_update_retry", "handoff_paths_retry")
        for path in (mod.STAGING_DIR, mod.RELEASE_TAG_FILE, mod.RETRY_COUNT_FILE):
            assert path.is_relative_to(Path("/var/lib/autostream-update")), path
            assert not path.is_relative_to(self.SERVICE_DIR), path
