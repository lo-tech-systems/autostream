"""An older install updates itself onto the system-only directory unattended.

A device on the older layout keeps its staged release, backup and hand-off in
/var/lib/autostream. Its own updater downloads the new release there and runs
the new installer from there with --update; that one run cannot be moved or
protected, and nothing is copied out of it. The new installer makes the
system-only directory and writes the record that an update is under way, and
the old places are removed when the update has an outcome. A run cut short is
reported as failed and the next update stages again in the system-only
directory. These tests build the older layout, run the new installer's side of
it and the new boot step, cut the power at each point and check that no state
is left in which a device cannot update again, including that a rollback to
the older release leaves nothing its boot step could misread.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import importlib.util
import os
import stat
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "supervisor"))
import autostream_update_support as _asu  # noqa: E402
from test_dial_staged_install import (  # noqa: E402
    Env, RECORDER, REPO_ROOT, bash_capable, posix_only,
)
from test_dial_installer_hardening import _function_text  # noqa: E402
from test_dial_update_boot import (  # noqa: E402,F401  (fixtures are used by name)
    NEW_TREE, OLD_TREE, PREV, TAG, World, clock, mod, serve_status, swap_in,
    system, world,
)
from test_update_recovery import (  # noqa: E402
    _chown_noop, _geteuid_root, _load_retry, _old_timestamp, _write_result,
)

pytestmark = posix_only

STATE_LIB = REPO_ROOT / "installer" / "lib" / "state_files.sh"
UPDATE_LIB = REPO_ROOT / "installer" / "lib" / "update_state.sh"
APPLIANCE_INSTALLER = REPO_ROOT / "autostream_install.sh"
HOSTILE = "#!/bin/sh\ntouch /tmp/ran-as-root\nexit 0\n"
GOOD = "#!/bin/sh\nexit 0\n"
UNIT = "etc/systemd/system/autostream_dial_update_recover.service"


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def _legacy_release(env: Env, installer: str = "autostream_install.sh", text: str = GOOD,
                    tag: str = "v0.7.0", count: str | None = None) -> Path:
    """What an older updater left: staging/src/<top>/ with the installer, the
    release tag and (the appliance) the retry count."""
    staging = env.state / "update-staging"
    top = staging / "src" / "lo-tech-systems-autostream-abc1234"
    (top / "system").mkdir(parents=True)
    (top / installer).write_text(text, encoding="utf-8")
    (top / installer).chmod(0o755)
    (top / "system" / "unit").write_text("unit", encoding="utf-8")
    (staging / "release_tag").write_text(tag + "\n", encoding="utf-8")
    if count is not None:
        (staging / "retry_count").write_text(count + "\n", encoding="utf-8")
    return top


def _shell(env: Env, body: str, **extra: str) -> subprocess.CompletedProcess:
    upd = env.upd
    script = (
        "set -euo pipefail\nIFS=$'\\n\\t'\n"
        'info() { :; }; warn() { echo "WARN: $*" >&2; }; error() { echo "ERROR: $*" >&2; }\n'
        f'source "{STATE_LIB.as_posix()}"\nsource "{UPDATE_LIB.as_posix()}"\n'
        f'STAMP_DIR="{env.state.as_posix()}"\nUPDATE_STATE_DIR="{upd.as_posix()}"\n'
        f'UPDATE_IN_PROGRESS_FILE="{upd.as_posix()}/update-in-progress"\n'
        f"{body}\n"
    )
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                          timeout=60, env=env.env(**extra), cwd=env.tmp)


def _adopt(env: Env, release: Path, tag: str = "v0.7.0", **extra: str):
    env.fake("chown", RECORDER)
    funcs = _function_text(APPLIANCE_INSTALLER, "adopt_older_update_state")
    return _shell(env, f'AUTOSTREAM_DIR="{release.as_posix()}"\nAUTOSTREAM_RELEASE_TAG="{tag}"\n'
                       f"{funcs}\nadopt_older_update_state", **extra)


# ---------------------------------------------------------------------------
# Appliance: the first run, from the old place
# ---------------------------------------------------------------------------

@bash_capable
class TestApplianceFirstRun:
    def test_nothing_is_copied_out_of_the_old_place_and_the_record_is_written(self, env):
        release = _legacy_release(env, count="1")
        (env.state / "update-stopped-services.env").write_text("owntone\n")
        r = _adopt(env, release)
        assert r.returncode == 0, r.stderr
        assert not (env.upd / "staging").exists()
        assert not list(env.upd.glob("staging.new"))
        marker = env.upd / "update-in-progress"
        assert marker.read_text().strip() == "v0.7.0"
        assert stat.S_IMODE(os.stat(marker).st_mode) == 0o600
        # The run in progress is still using the old tree, so it is untouched.
        assert (release / "autostream_install.sh").read_text() == GOOD
        assert not (env.state / "update-stopped-services.env").exists()

    def test_a_run_from_the_system_only_directory_leaves_it_as_it_is(self, env):
        new_release = env.upd / "staging" / "src" / "release"
        new_release.mkdir(parents=True)
        (new_release / "autostream_install.sh").write_text(GOOD)
        (env.upd / "staging" / "release_tag").write_text("v0.7.0\n")
        r = _adopt(env, new_release)
        assert r.returncode == 0, r.stderr
        assert (new_release / "autostream_install.sh").read_text() == GOOD
        assert (env.upd / "staging" / "release_tag").read_text().strip() == "v0.7.0"
        assert (env.upd / "update-in-progress").exists()

    @pytest.mark.parametrize("where", ["upd", "state-parent"])
    def test_a_link_planted_at_the_old_name_does_not_touch_the_running_tree(
            self, env, where):
        new_release = env.upd / "staging" / "src" / "release"
        new_release.mkdir(parents=True)
        (new_release / "autostream_install.sh").write_text(GOOD)
        target = env.upd if where == "upd" else env.state.parent
        (env.state / "update-staging").symlink_to(target)
        r = _adopt(env, new_release)
        assert r.returncode == 0, r.stderr
        assert (new_release / "autostream_install.sh").read_text() == GOOD
        assert (env.upd / "update-in-progress").exists()
        # The link is still there; it is unlinked, never followed, when the
        # update has succeeded.
        assert (env.state / "update-staging").is_symlink()

    def test_a_link_planted_at_the_old_name_is_unlinked_not_followed_by_the_clean_up(
            self, env):
        keep = env.upd / "staging" / "src" / "release"
        keep.mkdir(parents=True)
        (keep / "autostream_install.sh").write_text(GOOD)
        (env.state / "update-staging").symlink_to(env.upd / "staging")
        funcs = _function_text(APPLIANCE_INSTALLER, "retire_older_update_state")
        r = _shell(env, f"{funcs}\nretire_older_update_state")
        assert r.returncode == 0, r.stderr
        assert not (env.state / "update-staging").is_symlink()
        assert not (env.state / "update-staging").exists()
        assert (keep / "autostream_install.sh").read_text() == GOOD

    def test_the_clean_up_does_not_descend_through_a_link_inside_the_old_place(self, env):
        _legacy_release(env)
        precious = env.tmp / "precious"
        precious.mkdir()
        (precious / "keep").write_text("keep")
        (env.state / "update-staging" / "src" / "link").symlink_to(precious)
        funcs = _function_text(APPLIANCE_INSTALLER, "retire_older_update_state")
        r = _shell(env, f"{funcs}\nretire_older_update_state")
        assert r.returncode == 0, r.stderr
        assert not (env.state / "update-staging").exists()
        assert (precious / "keep").read_text() == "keep"

    def test_the_old_place_is_removed_once_the_update_has_succeeded(self, env):
        _legacy_release(env)
        link_target = env.tmp / "precious"
        link_target.mkdir()
        (link_target / "keep").write_text("keep")
        funcs = _function_text(APPLIANCE_INSTALLER, "retire_older_update_state")
        r = _shell(env, f"{funcs}\nretire_older_update_state")
        assert r.returncode == 0, r.stderr
        assert not (env.state / "update-staging").exists()
        # A link in its place is unlinked and what it points at is left alone.
        (env.state / "update-staging").symlink_to(link_target)
        r = _shell(env, f"{funcs}\nretire_older_update_state")
        assert r.returncode == 0, r.stderr
        assert not (env.state / "update-staging").is_symlink()
        assert (link_target / "keep").read_text() == "keep"


# ---------------------------------------------------------------------------
# Appliance: an interruption in the first run, with the new retry in place
# ---------------------------------------------------------------------------

def _run_retry(retry_mod):
    commands: list[list[str]] = []

    def fake_run(cmd, timeout=60):
        commands.append(list(cmd))
        return 0, "", ""

    with _geteuid_root(), \
         patch.object(retry_mod, "_is_pre_boot", return_value=True), \
         patch.object(retry_mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
         patch("os.path.isfile", return_value=True), \
         patch("os.access", return_value=True), \
         patch.object(retry_mod, "_run", side_effect=fake_run), \
         _chown_noop():
        rc = retry_mod.main()
    return rc, [c for c in commands if "--update" in c]


@bash_capable
class TestApplianceInterruptedFirstRun:
    def _retry_over(self, env: Env, tmp_path: Path):
        m = _load_retry(tmp_path)
        m.STAMP_DIR = env.state
        m.UPDATE_RESULT_FILE = env.state / "update-result.env"
        m.STAGING_DIR = env.upd / "staging"
        m.RELEASE_TAG_FILE = m.STAGING_DIR / "release_tag"
        m.RETRY_COUNT_FILE = m.STAGING_DIR / "retry_count"
        _write_result(env.state, "in_progress", _old_timestamp())
        return m

    def test_a_cut_after_the_record_is_reported_and_never_runs_the_old_place(
            self, env, tmp_path):
        release = _legacy_release(env, count="1")
        assert _adopt(env, release).returncode == 0
        # The service account swaps the installer in the old place.
        (release / "autostream_install.sh").write_text(HOSTILE)
        m = self._retry_over(env, tmp_path)
        rc, scheduled = _run_retry(m)
        assert rc == 1
        assert scheduled == []
        assert "failure" in (env.state / "update-result.env").read_text().lower()
        assert not (env.upd / "update-in-progress").exists()

    def test_the_device_is_idle_and_clean_after_the_next_boot(self, env, tmp_path):
        release = _legacy_release(env)
        assert _adopt(env, release).returncode == 0
        m = self._retry_over(env, tmp_path)
        assert _run_retry(m)[0] == 1
        with _geteuid_root():
            assert m.main() == 0
        assert not (env.state / "update-staging").exists()
        assert not (env.upd / "update-in-progress").exists()
        assert not (env.upd / "staging").exists()

    def test_a_cut_before_the_record_is_written_does_not_run_anything(
            self, env, tmp_path):
        _legacy_release(env)
        m = self._retry_over(env, tmp_path)
        rc, scheduled = _run_retry(m)
        assert rc == 1
        assert scheduled == []

    def test_an_idle_boot_removes_what_the_old_layout_left(self, env, tmp_path):
        _legacy_release(env)
        (env.state / "update-stopped-services.env").write_text("owntone\n")
        m = self._retry_over(env, tmp_path)
        _write_result(env.state, "success", _old_timestamp())
        with _geteuid_root():
            assert m.main() == 0
        assert not (env.state / "update-staging").exists()
        assert not (env.state / "update-stopped-services.env").exists()

    def test_an_interrupted_boot_leaves_the_old_place_for_the_run_to_finish_with(
            self, env, tmp_path):
        _legacy_release(env)
        m = self._retry_over(env, tmp_path)
        _run_retry(m)
        assert (env.state / "update-staging").exists()


# ---------------------------------------------------------------------------
# Dial: the first run, the boot step, and a rollback to the older release
# ---------------------------------------------------------------------------

def _legacy_dial_leftovers(world) -> None:
    """What the older layout can have left in the service account's directory,
    including a hand-off that a careless reader would act on."""
    state = world.state
    staging = state / "update-staging" / "src" / "autostream-0.7.0"
    staging.mkdir(parents=True)
    (staging / "autostream_dial_install.sh").write_text(HOSTILE, encoding="utf-8")
    (staging / "autostream_dial_install.sh").chmod(0o755)
    (state / "update-staging" / "release_tag").write_text("v9.9.9\n", encoding="utf-8")
    (state / "update-prev" / "files").mkdir(parents=True)
    (state / "update-prev" / "MANIFEST").write_text("PRESENT\t/etc/passwd\n", encoding="utf-8")
    (state / "update-swap.env").write_text(
        "PHASE=staged\nTAG=9.9.9\nPREVIOUS_TAG=0.0.1\nVENV=venv.9.9.9\n"
        "PREVIOUS_VENV=venv.0.0.1\nVENV_MIGRATE=0\n", encoding="utf-8")
    (state / "update-swap.env.tmp.4242").write_text("PHASE=staged\n", encoding="utf-8")


def _legacy_names(world) -> list[str]:
    return sorted(p.name for p in world.state.iterdir() if p.name.startswith("update-s")
                  or p.name.startswith("update-p"))


class TestDialFirstUpdateFromTheOlderLayout:
    def test_the_boot_step_follows_the_new_hand_off_not_the_old_one(self, world, mod, system):
        _legacy_dial_leftovers(world)
        # The older release's own tree: a real `venv` directory and no manifest.
        world.build_staged(first_update=True, migrate=True)
        mod.cmd_boot()
        assert system.verify_scheduled()
        assert world.live_files() == {
            **NEW_TREE, "old_only.py": OLD_TREE["old_only.py"]}
        assert world.venv_target() == f"venv.{TAG}"
        assert (world.opt / f"venv.{PREV}" / "marker").read_text() == "old-venv"
        assert world.swap()["PHASE"] == "swapped"
        # Nothing at the old place was run or replaced.
        assert (world.state / "update-swap.env").read_text().startswith("PHASE=staged")

    def test_a_verified_update_leaves_neither_place_with_anything_in_it(
            self, world, mod, system, clock):
        _legacy_dial_leftovers(world)
        world.build_staged(first_update=True, migrate=True)
        mod.cmd_boot()
        serve_status(mod)
        mod.cmd_verify()
        assert world.result()["STATUS"] == "success"
        assert _legacy_names(world) == []
        assert not [p for p in world.state.iterdir() if "update-swap" in p.name]
        assert sorted(p.name for p in world.upd.iterdir()) == []

    def test_a_link_at_an_old_name_is_unlinked_not_followed(self, world, mod, system, clock,
                                                           tmp_path):
        precious = tmp_path / "precious"
        precious.mkdir()
        (precious / "keep").write_text("keep")
        (world.state / "update-staging").symlink_to(precious)
        world.build_staged(first_update=True, migrate=True)
        mod.cmd_boot()
        serve_status(mod)
        mod.cmd_verify()
        assert not (world.state / "update-staging").exists()
        assert (precious / "keep").read_text() == "keep"

    def test_an_idle_boot_removes_a_hand_off_left_at_the_old_place(self, world, mod, system):
        _legacy_dial_leftovers(world)
        mod.write_update_result("success", "Updated", percent=100)
        mod.cmd_boot()
        assert _legacy_names(world) == []
        assert system.reboots == 0

    @pytest.mark.parametrize("backup", [False, True])
    def test_a_run_cut_short_with_nothing_staged_is_reported_and_the_dial_is_idle_again(
            self, world, mod, system, backup):
        world.build_interrupted(attempt=1, installer=False, backup=backup)
        mod.cmd_boot()
        env = world.result()
        assert env["STATUS"] == "failure"
        assert "recovery files are unavailable" in env["MESSAGE"]
        assert system.retries_scheduled() == []
        assert not (world.upd / "update-in-progress").exists()
        assert not world.backup.exists()
        # The next boot has nothing to do, and a new update can start.
        system.calls.clear()
        assert mod.cmd_boot() == {"ok": True}
        assert system.reboots == 0
        assert system.retries_scheduled() == []


class TestDialRollbackToTheOlderRelease:
    def _backup_with_unit(self, world) -> None:
        world.write_backup()
        unit = world.backup / "files" / "etc" / "systemd" / "system" / "autostream_dial_update_recover.service"
        unit.write_text("older recover unit", encoding="utf-8")
        with (world.backup / "MANIFEST").open("a", encoding="utf-8") as f:
            f.write("PRESENT\t/etc/systemd/system/autostream_dial_update_recover.service\n")
        (world.fs / UNIT).write_text("newer recover unit", encoding="utf-8")

    def test_the_older_boot_unit_comes_back_and_systemd_reads_it(self, world, mod, system):
        world.build_staged(first_update=True, migrate=True, configure_started=False)
        self._backup_with_unit(world)
        mod.cmd_boot()
        mod.cmd_rollback()
        assert (world.fs / UNIT).read_text() == "older recover unit"
        assert ["systemctl", "daemon-reload"] in system.calls
        assert system.reboots == 1

    def test_nothing_is_left_that_the_older_boot_step_could_read(self, world, mod, system):
        _legacy_dial_leftovers(world)
        world.build_staged(first_update=True, migrate=True)
        mod.cmd_boot()
        mod.cmd_rollback()
        # The older step reads the result file and the old staging place only.
        assert _legacy_names(world) == []
        assert not any("update-swap" in p.name for p in world.state.iterdir())
        left = sorted(p.name for p in world.upd.iterdir())
        assert "update-swap.env" not in left
        assert "update-prev" not in left
        assert "update-in-progress" not in left
        env = world.result()
        assert env["STATUS"] == "failure" and env["PHASE"] == "rolled_back"
        assert world.live_files() == OLD_TREE
        assert world.venv_marker() == "old-venv"

    def test_a_boot_after_the_rollback_changes_nothing(self, world, mod, system):
        world.build_staged(first_update=True, migrate=True)
        mod.cmd_boot()
        mod.cmd_rollback()
        system.calls.clear()
        before = world.live_files()
        mod.cmd_boot()
        assert world.live_files() == before
        assert system.calls == [] or all(c[0] != mod.REBOOT_BIN for c in system.calls)
        assert system.reboots == 0


def _old_release_updater(tmp_path: Path):
    """The dial updater as it shipped in the older release, from the repository
    history, loaded under its own name; None when history is not available."""
    git_dir = os.environ.get("GIT_DIR")
    if not (REPO_ROOT / ".git").exists() and not git_dir:
        return None
    for tag in ("0.6.1",):
        r = subprocess.run(["git", "show", f"{tag}:supervisor/autostream_dial_updater"],
                           capture_output=True, text=True, cwd=REPO_ROOT)
        if r.returncode == 0:
            path = tmp_path / "old_autostream_dial_updater.py"
            path.write_text(r.stdout, encoding="utf-8")
            spec = importlib.util.spec_from_file_location("old_dial_updater", path)
            m = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = m
            spec.loader.exec_module(m)
            return m
    return None


class TestOlderBootStepReadsNothingNew:
    def test_it_leaves_the_state_a_rollback_left_alone(self, world, mod, system, tmp_path):
        old = _old_release_updater(tmp_path)
        if old is None:
            pytest.skip("the older release's source is not available from history here")
        world.build_staged(first_update=True, migrate=True)
        mod.cmd_boot()
        mod.cmd_rollback()
        old.STATE_DIR = world.state
        old.LOCK_PATH = tmp_path / "old.lock"
        old.UPDATING_FLAG = tmp_path / "old-updating"
        old.LOG_PATH = tmp_path / "old.log"
        calls = []
        old._run = lambda cmd, timeout=60: calls.append(cmd) or (0, "", "")
        before = (world.state / "update-result.env").read_text(encoding="utf-8")
        assert old.cmd_recover() == {"ok": True}
        assert (world.state / "update-result.env").read_text(encoding="utf-8") == before
        assert calls == []

    def test_it_does_not_look_in_the_system_only_directory(self, world, mod, system, tmp_path):
        old = _old_release_updater(tmp_path)
        if old is None:
            pytest.skip("the older release's source is not available from history here")
        world.build_staged(first_update=True, migrate=True)
        source = Path(old.__file__).read_text(encoding="utf-8")
        assert "var/lib/autostream-update" not in source


@bash_capable
class TestDialFirstRunFromTheOldPlace:
    def _adopt(self, env: Env, release: Path):
        env.fake("chown", RECORDER)
        return env.run(f'DEPLOY="{release.as_posix()}"\nadopt_older_update_staging')

    def test_nothing_is_copied_out_of_the_old_place(self):
        for path in (APPLIANCE_INSTALLER, REPO_ROOT / "autostream_dial_install.sh",
                     REPO_ROOT / "installer" / "dial" / "helpers.sh", UPDATE_LIB):
            text = path.read_text(encoding="utf-8")
            assert "migrate_staged_release" not in text, path.name
            assert "adopt_older_update_staging" not in text, path.name

    def test_the_record_is_written_in_the_prepare_phase_of_an_update(self):
        text = (REPO_ROOT / "autostream_dial_install.sh").read_text(encoding="utf-8")
        block = text[text.index("if $UPDATE; then\n    create_service_user"):]
        block = block[:block.index("\nfi\n")]
        assert "mark_update_in_progress" in block

    def test_the_appliance_record_is_written_before_the_update_runs(self):
        text = APPLIANCE_INSTALLER.read_text(encoding="utf-8")
        body = _function_text(APPLIANCE_INSTALLER, "adopt_older_update_state")
        assert "write_state_file" in body
        run = text[text.index("run_update() {"):]
        assert run.index("adopt_older_update_state") < run.index("write_update_result")
        assert run.index("write_update_result \"success\"") < run.index("retire_older_update_state") \
            < run.index("autostream_admin reboot")
