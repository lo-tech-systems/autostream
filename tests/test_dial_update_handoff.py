"""The dial update hand-off: what root trusts at the next boot is out of the
service account's reach.

The dial stages a release, backs up the files it owns and writes a hand-off
file, then the boot step swaps the staged release in as root. All of that
used to sit in /var/lib/autostream, which the service account owns, so the
account could have steered the boot step: a virtualenv name that climbs out
of the code tree, a backup manifest that names any file on the system, a
staged installer of its own. It now lives in the root-only directory, the
boot step acts only while the marker root wrote there is present, and what it
reads back is checked first. These tests plant each of those as the service
account would and check that the boot step neither follows nor runs them and
leaves the running release as it was; the ordinary swap, verify, rollback and
retry are covered in test_dial_update_boot.py.

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
from test_dial_update_boot import (  # noqa: E402,F401  (fixtures are used by name)
    NEW_TREE, OLD_TREE, PREV, TAG, World, clock, mod, serve_status, swap_in,
    system, world,
)
import autostream_update_support as _asu  # noqa: E402
from conftest import load_supervisor_script  # noqa: E402

pytestmark = posix_only

HELPERS = REPO_ROOT / "installer" / "dial" / "helpers.sh"
INSTALLER = REPO_ROOT / "autostream_dial_install.sh"
BOOTSTRAP = REPO_ROOT / "dial_bootstrap.sh"
SERVICE = "etc/systemd/system/autostream_dial.service"


def _untouched(world, live_before: dict) -> None:
    assert world.live_files() == live_before


def _snapshot(world) -> dict:
    return {
        "files": world.live_files(),
        "venv": sorted(p.name for p in world.opt.iterdir() if p.name.startswith("venv")),
        "next": (world.opt / ".next").exists(),
        "owned": (world.fs / SERVICE).read_text(encoding="utf-8"),
    }


# ---------------------------------------------------------------------------
# Where the hand-off is
# ---------------------------------------------------------------------------

class TestWhereTheHandOffLives:
    def test_the_real_paths_are_in_the_root_only_directory(self):
        m = load_supervisor_script("autostream_dial_updater", "dial_handoff_paths")
        update = Path("/var/lib/autostream-update")
        service = Path("/var/lib/autostream")
        for path in (m.STAGING_DIR, m._swap_file(), m._backup_dir()):
            assert path.is_relative_to(update), path
            assert not path.is_relative_to(service), path

    def test_a_hand_off_in_the_service_account_directory_is_never_read(self, world, mod, system):
        # What the service account could write at the old place: a complete,
        # well-formed hand-off that asks for a swap. The root-only directory
        # has nothing in it.
        world.build_staged(first_update=False, migrate=False)
        (world.state / "update-swap.env").write_text(
            world.swap_file.read_text(encoding="utf-8"), encoding="utf-8")
        world.swap_file.unlink()
        (world.upd / "update-in-progress").unlink()
        before = _snapshot(world)
        mod.cmd_boot()
        after = _snapshot(world)
        # The half-staged tree under /opt is cleaned up; nothing live changes.
        assert {k: v for k, v in after.items() if k != "next"} ==             {k: v for k, v in before.items() if k != "next"}
        assert not system.verify_scheduled()
        assert system.reboots == 0
        assert system.retries_scheduled() == []


# ---------------------------------------------------------------------------
# The marker, and a directory that is not root's
# ---------------------------------------------------------------------------

class TestActsOnlyOnWhatRootLeft:
    def test_a_hand_off_without_the_marker_changes_nothing_and_is_reported(
            self, world, mod, system):
        world.build_staged(first_update=False, migrate=False)
        (world.upd / "update-in-progress").unlink()
        before = _snapshot(world)
        result = mod.cmd_boot()
        assert result["ok"] is True
        assert _snapshot(world) == before
        assert not system.verify_scheduled()
        assert system.reboots == 0
        env = world.result()
        assert env["STATUS"] == "failure"
        assert "not applied" in env["MESSAGE"]
        assert PREV in env["MESSAGE"]
        assert world.swap_file.exists()

    def test_a_directory_owned_by_someone_else_is_not_trusted(self, world, mod, system):
        world.build_staged(first_update=False, migrate=False)
        mod.UPDATE_STATE_UID = os.getuid() + 1
        before = _snapshot(world)
        mod.cmd_boot()
        assert _snapshot(world) == before
        assert not system.verify_scheduled()
        assert world.result()["STATUS"] == "failure"

    @pytest.mark.parametrize("mode", [0o755, 0o770, 0o701])
    def test_a_loose_directory_is_not_trusted(self, world, mod, system, mode):
        world.build_staged(first_update=False, migrate=False)
        world.upd.chmod(mode)
        before = _snapshot(world)
        mod.cmd_boot()
        assert _snapshot(world) == before
        assert not system.verify_scheduled()
        assert world.result()["STATUS"] == "failure"

    def test_a_link_in_place_of_the_directory_is_not_followed(self, world, mod, system, tmp_path):
        world.build_staged(first_update=False, migrate=False)
        real = tmp_path / "real-upd"
        world.upd.rename(real)
        world.upd.symlink_to(real)
        before = _snapshot(world)
        mod.cmd_boot()
        assert _snapshot(world) == before
        assert not system.verify_scheduled()

    def test_a_swap_file_that_is_a_link_is_not_followed(self, world, mod, system, tmp_path):
        world.build_staged(first_update=False, migrate=False)
        elsewhere = tmp_path / "elsewhere.env"
        elsewhere.write_text(world.swap_file.read_text(encoding="utf-8"), encoding="utf-8")
        world.swap_file.unlink()
        world.swap_file.symlink_to(elsewhere)
        before = _snapshot(world)
        mod.cmd_boot()
        assert _snapshot(world) == before
        assert not system.verify_scheduled()

    def test_a_status_the_service_account_wrote_does_not_start_a_retry(
            self, world, mod, system):
        # An installer is staged, but root left no record that an update is in
        # flight; only the (replaceable) result file says one is.
        world.build_interrupted(attempt=1, marker=False)
        result = mod.cmd_boot()
        assert result == {"ok": True}
        assert system.retries_scheduled() == []
        env = world.result()
        assert env["STATUS"] == "failure"
        assert "unavailable" in env["MESSAGE"]

    def test_with_no_update_directory_at_all_nothing_is_retried(self, world, mod, system):
        world.build_interrupted(attempt=1)
        import shutil
        shutil.rmtree(world.upd)
        result = mod.cmd_boot()
        assert result == {"ok": True}
        assert system.retries_scheduled() == []
        assert world.result()["STATUS"] == "failure"

    def test_a_retry_of_a_run_root_staged_still_happens(self, world, mod, system):
        world.build_interrupted(attempt=1)
        assert mod.cmd_boot() == {"ok": True, "retry": 2}
        (cmd,) = system.retries_scheduled()
        assert Path(cmd[-2]).is_relative_to(world.upd)

    def test_a_tag_that_is_not_a_version_is_not_handed_to_the_retry(self, world, mod, system):
        world.build_interrupted(attempt=1)
        (mod.STAGING_DIR / "release_tag").write_text("v1.3.0; reboot\n", encoding="utf-8")
        mod.cmd_boot()
        (cmd,) = system.retries_scheduled()
        tags = [a for a in cmd if a.startswith("--setenv=AUTOSTREAM_RELEASE_TAG=")]
        assert tags == [f"--setenv=AUTOSTREAM_RELEASE_TAG={TAG}"]


# ---------------------------------------------------------------------------
# What is read back from the hand-off file
# ---------------------------------------------------------------------------

BAD_NAMES = [
    "../victim", "venv/../../victim", "/etc", "venv.x/../../victim", "venv..", "venv.tmp",
    "notvenv", "venv.a b", "venv.x;reboot", ".", "venv.",
]


class TestSwapValuesAreChecked:
    @pytest.mark.parametrize("name", BAD_NAMES)
    def test_a_virtualenv_name_that_is_not_a_plain_name_is_refused(
            self, world, mod, system, tmp_path, name):
        world.build_staged(first_update=False, migrate=False)
        victim = tmp_path / "victim"          # beside the code tree
        victim.mkdir()
        (victim / "keep").write_text("mine", encoding="utf-8")
        text = world.swap_file.read_text(encoding="utf-8").replace(f"VENV=venv.{TAG}", f"VENV={name}")
        world.swap_file.write_text(text, encoding="utf-8")
        before = _snapshot(world)
        mod.cmd_boot()
        assert _snapshot(world) == before
        assert (victim / "keep").read_text(encoding="utf-8") == "mine"
        assert not system.verify_scheduled()
        assert world.result()["STATUS"] == "failure"

    @pytest.mark.parametrize("key", ["VENV", "PREVIOUS_VENV"])
    def test_a_name_that_climbs_out_is_not_removed_or_linked_by_a_rollback(
            self, world, mod, system, tmp_path, key):
        swap_in(world, mod, "verifying", first_update=False, migrate=False)
        victim = tmp_path / "victim"          # beside the code tree
        victim.mkdir()
        (victim / "keep").write_text("mine", encoding="utf-8")
        old = f"venv.{TAG}" if key == "VENV" else f"venv.{PREV}"
        text = world.swap_file.read_text(encoding="utf-8").replace(
            f"{key}={old}", f"{key}=../victim")
        world.swap_file.write_text(text, encoding="utf-8")
        system.calls.clear()
        mod.cmd_boot()
        assert (victim / "keep").read_text(encoding="utf-8") == "mine"
        assert system.reboots == 0
        assert os.readlink(world.opt / "venv") == f"venv.{TAG}"

    @pytest.mark.parametrize("line", [
        "TAG=1.3.0; touch /tmp/pwned", "PREVIOUS_TAG=$(id)", "VENV_MIGRATE=yes",
    ])
    def test_a_value_that_is_not_what_the_installer_writes_leaves_the_release_alone(
            self, world, mod, system, line):
        world.build_staged(first_update=False, migrate=False)
        key = line.split("=")[0]
        lines = [ln for ln in world.swap_file.read_text(encoding="utf-8").splitlines()
                 if not ln.startswith(key + "=")]
        world.swap_file.write_text("\n".join(lines + [line]) + "\n", encoding="utf-8")
        before = _snapshot(world)
        mod.cmd_boot()
        assert _snapshot(world) == before
        assert not system.verify_scheduled()
        assert system.reboots == 0
        assert world.result()["STATUS"] == "failure"

    def test_the_backup_directory_named_in_the_file_is_not_used(self, world, mod, system, tmp_path):
        swap_in(world, mod, "verifying", first_update=False, migrate=False)
        decoy = tmp_path / "decoy"
        (decoy / "files" / "etc" / "systemd" / "system").mkdir(parents=True)
        (decoy / "files" / "etc" / "systemd" / "system" / "autostream_dial.service").write_text(
            "from the decoy", encoding="utf-8")
        (decoy / "MANIFEST").write_text(
            "PRESENT\t/etc/systemd/system/autostream_dial.service\n", encoding="utf-8")
        with world.swap_file.open("a", encoding="utf-8") as f:
            f.write(f"BACKUP_DIR={decoy}\n")
        mod.cmd_boot()
        assert (world.fs / SERVICE).read_text(encoding="utf-8") == "old conf"


class TestRestoreIsLimitedToWhatTheInstallerOwns:
    def _manifest(self, world, extra: str) -> None:
        world.write_backup()
        with (world.backup / "MANIFEST").open("a", encoding="utf-8") as f:
            f.write(extra)

    def test_paths_outside_the_owned_files_are_neither_written_nor_removed(
            self, world, mod, system):
        world.build_staged(first_update=False, migrate=False, configure_started=False)
        self._manifest(world, "PRESENT\t/etc/passwd\nABSENT\t/etc/shadow\n"
                              "PRESENT\t/etc/sudoers.d/evil\nABSENT\t/opt/autostream/dial_main.py\n")
        (world.backup / "files" / "etc").mkdir(exist_ok=True, parents=True)
        (world.backup / "files" / "etc" / "passwd").write_text("root::0:0", encoding="utf-8")
        (world.fs / "etc" / "shadow").write_text("keep", encoding="utf-8")
        (world.fs / "etc" / "passwd").write_text("keep", encoding="utf-8")
        mod._restore_owned_files(world.backup)
        assert (world.fs / "etc" / "passwd").read_text(encoding="utf-8") == "keep"
        assert (world.fs / "etc" / "shadow").read_text(encoding="utf-8") == "keep"
        assert not (world.fs / "etc" / "sudoers.d" / "evil").exists()
        # The paths it does own are still put back.
        assert (world.fs / SERVICE).read_text(encoding="utf-8") == "old conf"

    @pytest.mark.parametrize("path", [
        "/etc/systemd/system/../../passwd", "etc/systemd/system/autostream_dial.service",
        "/etc/systemd/system/autostream_dial.service/../../../shadow",
        "/opt/autostream/images/../../etc/passwd", "/opt/autostream/images/.hidden",
        "/opt/autostream/nginx/offline/x.sh", "/opt/autostream/nginx/cgi/sub/x.cgi", "/",
    ])
    def test_these_are_not_owned(self, mod, path):
        assert not mod._owned_path(path)

    @pytest.mark.parametrize("path", [
        "/etc/systemd/system/autostream_dial.service",
        "/usr/local/libexec/autostream/autostream_dial_updater",
        "/opt/autostream/images/autostream-dial-badge.png",
        "/opt/autostream/nginx/offline/updating.html",
        "/opt/autostream/nginx/cgi/reboot.cgi",
        "/var/lib/autostream/install-state.env",
    ])
    def test_these_are_(self, mod, path):
        assert mod._owned_path(path)

    @bash_capable
    @pytest.mark.parametrize("hd", ["true", "false"])
    def test_every_file_the_installer_lists_as_owned_may_be_restored(self, tmp_path, mod, hd):
        env = Env(tmp_path)
        r = env.run("HD=%s\nI2C_MODULES_FILE=${I2C_MODULES_FILE:-x}\nowned_files_list" % hd)
        assert r.returncode == 0, r.stderr
        paths = [p for p in r.stdout.splitlines() if p]
        assert len(paths) > 40
        refused = [p for p in paths if not mod._owned_path(p)]
        assert refused == []


# ---------------------------------------------------------------------------
# Leaving the marker, and what a rollback leaves behind
# ---------------------------------------------------------------------------

class TestMarkerLifecycle:
    def test_a_verified_update_leaves_no_marker_hand_off_or_backup(self, world, mod, system, clock):
        world.build_staged(first_update=False, migrate=False)
        mod.cmd_boot()
        serve_status(mod)
        mod.cmd_verify()
        assert sorted(p.name for p in world.upd.iterdir()) == []

    def test_a_rolled_back_update_leaves_nothing_the_next_boot_could_act_on(
            self, world, mod, system):
        swap_in(world, mod, "verifying", first_update=False, migrate=False)
        mod.cmd_rollback()
        left = sorted(p.name for p in world.upd.iterdir())
        assert "update-swap.env" not in left
        assert "update-prev" not in left
        assert "update-in-progress" not in left
        # A second boot after the rollback finds nothing to do.
        system.calls.clear()
        mod.cmd_boot()
        assert system.reboots == 0
        assert not system.verify_scheduled()
        assert system.retries_scheduled() == []

    def test_an_interrupted_run_that_gives_up_clears_the_marker(self, world, mod, system):
        world.build_interrupted(attempt=4)
        mod.cmd_boot()
        assert not (world.upd / "update-in-progress").exists()

    def test_a_cut_before_the_marker_is_cleared_repeats_the_cleanup(self, world, mod, system, clock):
        world.build_staged(first_update=False, migrate=False)
        mod.cmd_boot()
        serve_status(mod)
        # The verified-update cleanup ran except for its last step.
        swap = mod._read_swap()
        swap["PHASE"] = "done"
        mod._set_swap_phase(swap, "done")
        assert (world.upd / "update-in-progress").exists()
        mod.cmd_boot()
        assert world.result()["STATUS"] == "success"
        assert not (world.upd / "update-in-progress").exists()
        assert not world.swap_file.exists()


# ---------------------------------------------------------------------------
# The installer's side (scratch root, fake commands)
# ---------------------------------------------------------------------------

@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


@bash_capable
class TestInstallerWritesToTheRootOnlyDirectory:
    def _upd(self, env) -> Path:
        d = env.root / "var" / "lib" / "autostream-update"
        d.mkdir(parents=True, exist_ok=True)
        d.chmod(0o700)
        return d

    def test_the_backup_is_taken_into_the_root_only_directory(self, env):
        upd = self._upd(env)
        env.put("usr/local/bin/autostream-dial-control", "ctl")
        r = env.run("backup_owned_files; echo \"$BACKUP_DIR\"")
        assert r.returncode == 0, r.stderr
        assert r.stdout.strip() == (upd / "update-prev").as_posix()
        assert (upd / "update-prev" / "MANIFEST").is_file()
        assert not (env.state / "update-prev").exists()
        assert stat.S_IMODE(os.stat(upd / "update-prev").st_mode) == 0o700

    def test_the_hand_off_is_written_there_without_a_backup_path(self, env):
        upd = self._upd(env)
        r = env.run("NEW_VENV=venv.1.3.0 PREVIOUS_VENV=venv VENV_MIGRATE=1 write_update_swap")
        assert r.returncode == 0, r.stderr
        text = (upd / "update-swap.env").read_text(encoding="utf-8")
        assert "PHASE=staged" in text and "VENV=venv.1.3.0" in text
        assert "BACKUP_DIR" not in text
        assert not (env.state / "update-swap.env").exists()

    def test_the_marker_is_written_private_and_removed_on_a_failed_run(self, env):
        upd = self._upd(env)
        r = env.run("mark_update_in_progress")
        assert r.returncode == 0, r.stderr
        marker = upd / "update-in-progress"
        assert marker.read_text(encoding="utf-8").strip() == "1.3.0"
        assert stat.S_IMODE(os.stat(marker).st_mode) == 0o600
        r = env.run("UPDATE_STAGED=false; BACKUP_TAKEN=false; VENV_BUILT=false\n"
                    "update_failure_message() { echo failed; }\nabort_update")
        assert r.returncode == 0, r.stderr
        assert not marker.exists()

    def test_a_hand_off_already_written_keeps_the_marker_for_the_boot_step(self, env):
        upd = self._upd(env)
        env.run("mark_update_in_progress")
        r = env.run("UPDATE_STAGED=true\nabort_update")
        assert r.returncode == 0, r.stderr
        assert (upd / "update-in-progress").exists()

    def test_the_marker_is_written_after_the_directories_are_prepared(self):
        text = INSTALLER.read_text(encoding="utf-8")
        block = text[text.index("if $UPDATE; then\n    create_service_user"):]
        block = block[:block.index("\nfi\n")]
        assert block.index("create_dirs") < block.index("mark_update_in_progress")

    def test_the_first_install_stages_in_the_root_only_directory(self):
        text = BOOTSTRAP.read_text(encoding="utf-8")
        assert 'UPDATE_STATE_DIR="/var/lib/autostream-update"' in text
        assert "/var/lib/autostream/update-staging" not in text


# ---------------------------------------------------------------------------
# The attempt count and the marker helpers
# ---------------------------------------------------------------------------

class TestRetryCountIsRootsOwn:
    def test_a_result_file_rewritten_to_a_lower_attempt_does_not_reset_the_count(
            self, world, mod, system):
        world.build_interrupted(attempt=1)
        for expected in (2, 3):
            assert mod.cmd_boot() == {"ok": True, "retry": expected}
            # The service account puts the attempt back to 1 each time.
            mod.write_update_result("in_progress", "Installing...", percent=45,
                                    phase="python", attempt=1, max_attempts=4)
        assert mod.cmd_boot() == {"ok": True, "retry": 4}
        mod.write_update_result("in_progress", "Installing...", percent=45,
                                phase="python", attempt=1, max_attempts=4)
        system.calls.clear()
        mod.cmd_boot()
        assert system.retries_scheduled() == []
        assert world.result()["STATUS"] == "failure"
        assert not (world.upd / "update-in-progress").exists()

    def test_the_count_is_kept_in_the_root_only_directory(self, world, mod, system):
        world.build_interrupted(attempt=1)
        mod.cmd_boot()
        count = mod.STAGING_DIR / "retry_count"
        assert count.read_text(encoding="utf-8").strip() == "2"
        assert stat.S_IMODE(os.stat(count).st_mode) == 0o600

    def test_a_count_that_is_not_a_number_counts_as_none(self, world, mod):
        mod.STAGING_DIR.mkdir(parents=True)
        (mod.STAGING_DIR / "retry_count").write_text("9; reboot\n", encoding="utf-8")
        assert mod._root_attempt() == 0


class TestMarkerHelpersUseTheGuardedDirectory:
    def test_nothing_is_written_or_removed_in_a_directory_that_is_not_roots(self, tmp_path):
        d = tmp_path / "upd"
        d.mkdir(mode=0o700)
        (d / "update-in-progress").write_text("x")
        d.chmod(0o755)
        _asu.clear_update_in_progress(d / "staging", os.getuid())
        assert (d / "update-in-progress").exists()
        with pytest.raises(ValueError):
            _asu.mark_update_in_progress(d / "staging", "1.0.0", os.getuid())
        d.chmod(0o700)
        _asu.clear_update_in_progress(d / "staging", os.getuid() + 1)
        assert (d / "update-in-progress").exists()
        _asu.clear_update_in_progress(d / "staging", os.getuid())
        assert not (d / "update-in-progress").exists()

    def test_a_link_in_place_of_the_directory_is_not_followed_when_clearing(self, tmp_path):
        real = tmp_path / "real"
        real.mkdir(mode=0o700)
        (real / "update-in-progress").write_text("x")
        link = tmp_path / "upd"
        link.symlink_to(real)
        _asu.clear_update_in_progress(link / "staging", os.getuid())
        assert (real / "update-in-progress").exists()
