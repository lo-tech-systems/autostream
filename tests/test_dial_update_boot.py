"""Dial updater boot step: swap, verify, rollback and interrupted-run retry.

Drives autostream_dial_updater against a scratch tree.  The installer's
hand-off (the staged code tree and its manifest, the versioned virtualenv, the
owned-file backup and update-swap.env) is built by hand to the documented
on-disk contract; systemctl, systemd-run, the reboot, the status endpoint and
the clock are faked, so nothing here touches the machine.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "tests"))
sys.path.insert(0, str(REPO_ROOT / "supervisor"))

import autostream_update_support as _asu
from conftest import load_supervisor_script

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="symlinks, modes and flock are POSIX behaviour"
)

TAG = "1.3.0"
PREV = "1.2.0"

OLD_TREE = {
    "dial_main.py": "old main",
    "shared.py": "old shared",
    "old_only.py": "old only",
}
NEW_TREE = {
    "dial_main.py": "new main",
    "shared.py": "new shared",
    "new_mod.py": "new mod",
    "sub/inner.py": "new inner",
}


class Crash(BaseException):
    """A simulated power cut: not an Exception, so no handler absorbs it."""


class FakeSystem:
    """Stands in for _run: records every command and answers the few it must."""

    def __init__(self, mod):
        self.mod = mod
        self.calls: list[list[str]] = []
        self.units = {
            mod.DIAL_UNIT: ("active", 0),
            mod.WATCHER_UNIT: ("active", 0),
        }
        self.systemd_run_rc = 0
        self.nginx_rc = 0

    def __call__(self, cmd, timeout=60):
        self.calls.append(list(cmd))
        if cmd[:2] == ["systemctl", "show"]:
            state, restarts = self.units[cmd[-1]]
            return 0, f"ActiveState={state}\nNRestarts={restarts}", ""
        if cmd[0].endswith("systemd-run"):
            return self.systemd_run_rc, "", "scheduling failed" if self.systemd_run_rc else ""
        if cmd[0] == "nginx":
            return self.nginx_rc, "", ""
        return 0, "", ""

    def commands(self, first: str) -> list[list[str]]:
        return [c for c in self.calls if c and c[0] == first]

    def verify_scheduled(self) -> bool:
        return any(c[0].endswith("systemd-run") and c[-1] == "verify" for c in self.calls)

    def retries_scheduled(self) -> list[list[str]]:
        return [c for c in self.calls
                if c[0].endswith("systemd-run") and "--update" in c]

    @property
    def reboots(self) -> int:
        return len([c for c in self.calls if c == [self.mod.REBOOT_BIN]])

    @property
    def stops(self) -> list[list[str]]:
        return [c for c in self.calls if c[:2] == ["systemctl", "stop"]]


class World:
    """A scratch appliance: code tree, venvs, owned files, state files."""

    def __init__(self, tmp_path: Path, mod, system: FakeSystem):
        self.mod = mod
        self.system = system
        self.root = tmp_path
        self.opt = tmp_path / "opt"
        self.state = tmp_path / "state"
        self.fs = tmp_path / "fs"
        for d in (self.opt, self.state, self.fs):
            d.mkdir()

    # -- paths --
    @property
    def swap_file(self) -> Path:
        return self.state / "update-swap.env"

    @property
    def result_file(self) -> Path:
        return self.state / "update-result.env"

    @property
    def backup(self) -> Path:
        return self.state / "update-prev"

    # -- builders --
    def write_tree(self, base: Path, files: dict[str, str]) -> None:
        for rel, text in files.items():
            path = base / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")

    @staticmethod
    def manifest_text(files: dict[str, str]) -> str:
        return "".join(f"0644\troot:root\t{rel}\n" for rel in sorted(files))

    def build_staged(self, first_update: bool = False, migrate: bool = True,
                     configure_started: bool = True) -> None:
        """The state the installer leaves just before it reboots."""
        self.write_tree(self.opt, OLD_TREE)
        if not first_update:
            (self.opt / ".manifest").write_text(self.manifest_text(OLD_TREE), encoding="utf-8")
        next_dir = self.opt / ".next"
        self.write_tree(next_dir, NEW_TREE)
        (next_dir / "MANIFEST").write_text(self.manifest_text(NEW_TREE), encoding="utf-8")
        # virtualenvs
        old_name = f"venv.{PREV}"
        new_name = f"venv.{TAG}"
        if migrate:
            (self.opt / "venv").mkdir()
            (self.opt / "venv" / "marker").write_text("old-venv", encoding="utf-8")
        else:
            (self.opt / old_name).mkdir()
            (self.opt / old_name / "marker").write_text("old-venv", encoding="utf-8")
            os.symlink(old_name, self.opt / "venv")
        (self.opt / new_name).mkdir()
        (self.opt / new_name / "marker").write_text("new-venv", encoding="utf-8")
        # owned files: the update has already replaced them
        self.write_tree(self.fs, {
            "etc/foo.conf": "new conf",
            "etc/added.conf": "added by the update",
            "etc/link.conf": "now a regular file",
        })
        if configure_started:
            self.write_backup()
        self.swap_file.write_text(
            "PHASE=staged\n"
            f"TAG={TAG}\n"
            f"PREVIOUS_TAG={PREV}\n"
            f"VENV={new_name}\n"
            f"PREVIOUS_VENV={old_name}\n"
            f"VENV_MIGRATE={1 if migrate else 0}\n"
            f"BACKUP_DIR={self.backup}\n",
            encoding="utf-8",
        )
        self.mod.write_update_result(
            "in_progress", "Restarting...", percent=96, phase="reboot",
            tag=TAG, previous_tag=PREV, attempt=1, max_attempts=4,
        )

    def write_backup(self) -> None:
        files = self.backup / "files" / "etc"
        files.mkdir(parents=True)
        (files / "foo.conf").write_text("old conf", encoding="utf-8")
        os.symlink("foo.conf", files / "link.conf")
        (self.backup / "MANIFEST").write_text(
            "PRESENT\t/etc/foo.conf\n"
            "PRESENT\t/etc/link.conf\n"
            "ABSENT\t/etc/added.conf\n",
            encoding="utf-8",
        )

    def build_interrupted(self, attempt: int = 1, installer: bool = True,
                          backup: bool = False) -> None:
        """An update run cut short before it staged anything for the swap."""
        self.mod.write_update_result(
            "in_progress", "Installing...", percent=45, phase="python",
            tag=TAG, previous_tag=PREV, attempt=attempt, max_attempts=4,
        )
        staging = self.mod.STAGING_DIR
        (staging / "src" / "autostream-1.3.0").mkdir(parents=True)
        (staging / "release_tag").write_text("v1.3.0\n", encoding="utf-8")
        if installer:
            script = staging / "src" / "autostream-1.3.0" / "autostream_dial_install.sh"
            script.write_text("#!/bin/sh\n", encoding="utf-8")
            os.chmod(script, 0o755)
        self.write_tree(self.fs, {"etc/foo.conf": "half-written conf"})
        if backup:
            self.write_backup()

    # -- inspection --
    def swap(self) -> dict[str, str]:
        out = {}
        for line in self.swap_file.read_text(encoding="utf-8").splitlines():
            k, _, v = line.partition("=")
            out[k] = v
        return out

    def result(self) -> dict[str, str]:
        out = {}
        for line in self.result_file.read_text(encoding="utf-8").splitlines():
            k, _, v = line.partition("=")
            out[k] = v
        return out

    def live_files(self) -> dict[str, str]:
        out = {}
        for path in sorted(self.opt.rglob("*")):
            rel = path.relative_to(self.opt)
            top = rel.parts[0]
            if top.startswith(".") or top.startswith("venv"):
                continue
            if path.is_file():
                out[rel.as_posix()] = path.read_text(encoding="utf-8")
        return out

    def venv_marker(self) -> str:
        return (self.opt / "venv" / "marker").read_text(encoding="utf-8")

    def venv_target(self) -> str:
        return os.readlink(self.opt / "venv")


def swapped_tree(first_update: bool) -> dict[str, str]:
    tree = dict(NEW_TREE)
    if first_update:
        # No manifest was recorded before, so a module the new release dropped
        # cannot be told from any other file and stays.
        tree["old_only.py"] = OLD_TREE["old_only.py"]
    return tree


@pytest.fixture
def mod(tmp_path):
    m = load_supervisor_script("autostream_dial_updater", f"dial_boot_{abs(hash(str(tmp_path)))}")
    m.STATE_DIR = tmp_path / "state"
    m.OPT_DIR = tmp_path / "opt"
    m.FS_ROOT = str(tmp_path / "fs")
    m.STAGING_DIR = m.STATE_DIR / "update-staging"
    m.LOG_PATH = tmp_path / "dial-update.log"
    m.LOCK_PATH = tmp_path / "dial-update.lock"
    m.UPDATING_FLAG = tmp_path / "autostream-dial-updating"
    m.REBOOT_BIN = "/fake/reboot"
    m.FLOCK_BIN = sys.executable
    m._sync = lambda: None
    m._is_pre_boot = lambda ts: True
    m._dial_update_unit_active = lambda: False
    m._find_systemd_run = lambda: "/fake/systemd-run"
    return m


@pytest.fixture
def system(mod, monkeypatch):
    fake = FakeSystem(mod)
    monkeypatch.setattr(mod, "_run", fake)
    monkeypatch.setattr(_asu, "_run", fake)
    return fake


@pytest.fixture
def world(tmp_path, mod, system):
    return World(tmp_path, mod, system)


class Clock:
    """Fake time: sleeping advances it, so a deadline passes instantly."""

    def __init__(self):
        self.now = 0.0
        self.sleeps = 0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps += 1
        self.now += seconds


@pytest.fixture
def clock(mod):
    c = Clock()
    mod._monotonic = c.monotonic
    mod._sleep = c.sleep
    return c


def serve_status(mod, code=200, version=TAG):
    mod._fetch_status = lambda: (code, {"version": version} if code == 200 else {})


def crash_after(n: int):
    """Raise Crash on the n+1th os.replace, as a power cut between renames."""
    real = os.replace
    count = {"n": 0}

    def fake(src, dst, *a, **kw):
        if count["n"] >= n:
            raise Crash()
        count["n"] += 1
        return real(src, dst, *a, **kw)

    return patch("os.replace", fake)


# ---------------------------------------------------------------------------
# Swap at boot
# ---------------------------------------------------------------------------

class TestBootSwap:
    def test_boot_staged_swaps_manifest_and_venv_symlink_then_schedules_verify(
            self, world, mod, system):
        world.build_staged(first_update=False, migrate=False)
        result = mod.cmd_boot()
        assert result["ok"] is True
        assert world.live_files() == swapped_tree(first_update=False)
        assert world.venv_target() == f"venv.{TAG}"
        assert world.venv_marker() == "new-venv"
        assert (world.opt / ".manifest").read_text(encoding="utf-8") == \
            world.manifest_text(NEW_TREE)
        assert not (world.opt / ".next").exists()
        assert world.swap()["PHASE"] == "swapped"
        assert system.verify_scheduled()
        assert system.reboots == 0

    def test_boot_swap_moves_displaced_files_to_prev(self, world, mod):
        world.build_staged(first_update=False)
        mod.cmd_boot()
        prev = world.opt / ".prev"
        assert (prev / "dial_main.py").read_text(encoding="utf-8") == "old main"
        assert (prev / "shared.py").read_text(encoding="utf-8") == "old shared"
        assert (prev / "old_only.py").read_text(encoding="utf-8") == "old only"
        assert (prev / "MANIFEST.prev").read_text(encoding="utf-8") == \
            world.manifest_text(OLD_TREE)

    def test_boot_first_swap_migrates_real_venv_dir_to_versioned_dir(self, world, mod):
        world.build_staged(first_update=True, migrate=True)
        mod.cmd_boot()
        assert (world.opt / "venv").is_symlink()
        assert world.venv_target() == f"venv.{TAG}"
        old = world.opt / f"venv.{PREV}"
        assert old.is_dir() and not old.is_symlink()
        assert (old / "marker").read_text(encoding="utf-8") == "old-venv"
        assert world.live_files() == swapped_tree(first_update=True)

    def test_boot_swap_keeps_a_real_venv_that_is_reused(self, world, mod):
        world.build_staged(migrate=True)
        text = world.swap_file.read_text(encoding="utf-8")
        text = text.replace(f"VENV=venv.{TAG}", "VENV=venv").replace("VENV_MIGRATE=1", "VENV_MIGRATE=0")
        world.swap_file.write_text(text, encoding="utf-8")
        mod.cmd_boot()
        assert not (world.opt / "venv").is_symlink()
        assert world.venv_marker() == "old-venv"

    def test_boot_swap_writes_verify_result_and_updating_flag(self, world, mod):
        world.build_staged()
        mod.cmd_boot()
        env = world.result()
        assert env["STATUS"] == "in_progress"
        assert env["PHASE"] == "verify"
        assert env["PERCENT_COMPLETE"] == "96"
        assert env["MESSAGE"] == f"Starting {TAG}..."
        assert env["TAG"] == TAG and env["PREVIOUS_TAG"] == PREV
        assert env["ATTEMPT"] == "1" and env["MAX_ATTEMPTS"] == "4"
        assert mod.UPDATING_FLAG.exists()

    def test_verify_is_scheduled_under_system_python_after_a_delay(self, world, mod, system):
        world.build_staged()
        mod.cmd_boot()
        cmd = next(c for c in system.calls if c[0].endswith("systemd-run"))
        assert f"--on-active={mod.VERIFY_START_DELAY_S}" in cmd
        assert any(a.startswith("--unit=autostream-dial-verify-") for a in cmd)
        assert cmd[-3] == mod.SYSTEM_PYTHON
        assert cmd[-1] == "verify"

    def test_recover_is_alias_of_boot(self, world, mod, system):
        world.build_staged()
        result = mod.cmd_recover()
        assert result["ok"] is True
        assert world.live_files() == swapped_tree(first_update=False)
        assert system.verify_scheduled()

    def test_main_dispatches_boot_and_recover_to_the_same_step(self, world, mod, capsys):
        world.build_staged()
        with patch("os.geteuid", return_value=0, create=True), \
                patch.object(sys, "argv", ["autostream_dial_updater", "recover"]):
            rc = mod.main()
        assert rc == 0
        assert world.swap()["PHASE"] == "swapped"

    def test_boot_swap_without_a_staged_tree_rolls_back(self, world, mod, system):
        world.build_staged()
        import shutil
        shutil.rmtree(world.opt / ".next")
        mod.cmd_boot()
        assert world.result()["PHASE"] == "rolled_back"
        assert not world.swap_file.exists()
        assert system.reboots == 1
        assert world.live_files() == OLD_TREE

    def test_boot_swap_rolls_back_when_verify_cannot_be_scheduled(self, world, mod, system):
        world.build_staged()
        system.systemd_run_rc = 1
        mod.cmd_boot()
        assert world.result()["ROLLED_BACK"] == "1"
        assert system.reboots == 1
        assert world.live_files() == OLD_TREE
        assert world.venv_marker() == "old-venv"

    @pytest.mark.parametrize("first_update", [False, True])
    @pytest.mark.parametrize("crash_point", range(0, 24))
    def test_swap_interrupted_at_any_point_ends_all_new_or_all_old(
            self, world, mod, system, crash_point, first_update):
        world.build_staged(first_update=first_update, migrate=True)
        with crash_after(crash_point):
            try:
                mod.cmd_boot()
            except Crash:
                pass
        mod.cmd_boot()
        files = world.live_files()
        if files == swapped_tree(first_update):
            assert world.venv_marker() == "new-venv"
            assert world.swap()["PHASE"] == "swapped"
            assert system.verify_scheduled()
        else:
            # The cut came after the swap completed: the next boot finds an
            # unverified swap and reverts it.
            assert files == OLD_TREE
            assert world.venv_marker() == "old-venv"
            assert not world.swap_file.exists()
            assert world.result()["PHASE"] == "rolled_back"
            assert (world.fs / "etc" / "foo.conf").read_text(encoding="utf-8") == "old conf"


# ---------------------------------------------------------------------------
# Boot finding a swap that never reached a verdict
# ---------------------------------------------------------------------------

def swap_in(world, mod, phase: str, **build):
    """Run the boot swap, then pretend a later phase was reached."""
    world.build_staged(**build)
    mod.cmd_boot()
    text = world.swap_file.read_text(encoding="utf-8").replace(
        "PHASE=swapped", f"PHASE={phase}")
    world.swap_file.write_text(text, encoding="utf-8")


class TestBootRollback:
    @pytest.mark.parametrize("phase", ["swapped", "verifying", "rollback"])
    def test_boot_swapped_or_verifying_from_previous_boot_rolls_back(
            self, world, mod, system, phase):
        swap_in(world, mod, phase)
        system.calls.clear()
        mod.cmd_boot()
        assert world.live_files() == OLD_TREE
        assert world.result()["PHASE"] == "rolled_back"
        assert system.reboots == 1
        assert not world.swap_file.exists()

    def test_boot_rollback_does_not_stop_services(self, world, mod, system):
        swap_in(world, mod, "swapped")
        system.calls.clear()
        mod.cmd_boot()
        assert system.stops == []

    def test_boot_with_an_unknown_phase_rolls_back(self, world, mod, system):
        swap_in(world, mod, "mystery")
        mod.cmd_boot()
        assert world.result()["ROLLED_BACK"] == "1"

    def test_rollback_restores_tree_symlink_owned_files_and_writes_rolled_back_result(
            self, world, mod, system):
        swap_in(world, mod, "verifying", first_update=False, migrate=False)
        mod.cmd_rollback()
        assert world.live_files() == OLD_TREE
        assert (world.opt / ".manifest").read_text(encoding="utf-8") == \
            world.manifest_text(OLD_TREE)
        assert world.venv_target() == f"venv.{PREV}"
        assert world.venv_marker() == "old-venv"
        assert not (world.opt / f"venv.{TAG}").exists()
        assert (world.fs / "etc" / "foo.conf").read_text(encoding="utf-8") == "old conf"
        assert not (world.fs / "etc" / "added.conf").exists()
        link = world.fs / "etc" / "link.conf"
        assert link.is_symlink() and os.readlink(link) == "foo.conf"
        env = world.result()
        assert env["STATUS"] == "failure"
        assert env["PHASE"] == "rolled_back"
        assert env["ROLLED_BACK"] == "1"
        assert env["TAG"] == TAG and env["PREVIOUS_TAG"] == PREV
        assert env["MESSAGE"] == f"Update to {TAG} failed - restored {PREV}"
        assert env["ATTEMPT"] == "1"
        assert not world.swap_file.exists()
        assert not mod.UPDATING_FLAG.exists()
        assert not world.backup.exists()
        assert system.reboots == 1

    def test_rollback_after_first_swap_repoints_to_the_migrated_directory(
            self, world, mod):
        swap_in(world, mod, "swapped", first_update=True, migrate=True)
        mod.cmd_rollback()
        assert world.venv_target() == f"venv.{PREV}"
        assert world.venv_marker() == "old-venv"
        assert world.live_files() == OLD_TREE
        assert not (world.opt / ".manifest").exists()

    def test_rollback_reloads_systemd_and_restarts_nginx_without_blocking(
            self, world, mod, system):
        swap_in(world, mod, "swapped")
        system.calls.clear()
        mod.cmd_rollback()
        assert ["systemctl", "daemon-reload"] in system.calls
        assert ["nginx", "-t"] in system.calls
        assert ["systemctl", "restart", "--no-block", "nginx"] in system.calls

    def test_rollback_skips_nginx_restart_when_its_config_is_invalid(
            self, world, mod, system):
        swap_in(world, mod, "swapped")
        system.nginx_rc = 1
        system.calls.clear()
        mod.cmd_rollback()
        assert ["systemctl", "restart", "--no-block", "nginx"] not in system.calls
        assert system.reboots == 1

    def test_rollback_from_a_running_dial_stops_its_services_first(
            self, world, mod, system):
        swap_in(world, mod, "verifying")
        system.calls.clear()
        mod.cmd_rollback()
        assert system.stops == [["systemctl", "stop", mod.DIAL_UNIT, mod.WATCHER_UNIT]]
        assert system.calls.index(system.stops[0]) < system.calls.index([mod.REBOOT_BIN])

    def test_rollback_keeps_the_staging_directory(self, world, mod):
        swap_in(world, mod, "swapped")
        staging = mod.STAGING_DIR
        staging.mkdir(parents=True)
        (staging / "release_tag").write_text("v1.3.0\n", encoding="utf-8")
        mod.cmd_rollback()
        assert (staging / "release_tag").exists()

    def test_rollback_without_a_swap_is_a_noop(self, world, mod, system):
        result = mod.cmd_rollback()
        assert result == {"ok": True, "rolled_back": False}
        assert system.calls == []

    def test_rollback_keeps_reusing_the_unchanged_real_venv(self, world, mod):
        world.build_staged(migrate=True)
        text = world.swap_file.read_text(encoding="utf-8")
        text = text.replace(f"VENV=venv.{TAG}", "VENV=venv").replace(
            f"PREVIOUS_VENV=venv.{PREV}", "PREVIOUS_VENV=venv").replace(
            "VENV_MIGRATE=1", "VENV_MIGRATE=0")
        world.swap_file.write_text(text, encoding="utf-8")
        mod.cmd_boot()
        mod.cmd_rollback()
        assert not (world.opt / "venv").is_symlink()
        assert world.venv_marker() == "old-venv"
        assert (world.opt / f"venv.{TAG}").is_dir()  # not this swap's to remove

    @pytest.mark.parametrize("migrate", [True, False])
    @pytest.mark.parametrize("crash_point", range(0, 26))
    def test_rollback_interrupted_at_any_point_is_completed_by_the_next_boot(
            self, world, mod, system, crash_point, migrate):
        swap_in(world, mod, "verifying", first_update=False, migrate=migrate)
        with crash_after(crash_point):
            try:
                mod.cmd_rollback()
            except Crash:
                pass
        mod.cmd_boot()
        assert world.live_files() == OLD_TREE
        assert world.venv_marker() == "old-venv"
        assert world.venv_target() == f"venv.{PREV}"
        assert (world.fs / "etc" / "foo.conf").read_text(encoding="utf-8") == "old conf"
        assert not (world.fs / "etc" / "added.conf").exists()
        assert world.result()["PHASE"] == "rolled_back"
        assert not world.swap_file.exists()
        assert (world.opt / ".manifest").read_text(encoding="utf-8") == \
            world.manifest_text(OLD_TREE)

    def test_finished_rollback_repeated_changes_nothing(self, world, mod, system):
        swap_in(world, mod, "verifying", first_update=False)
        mod.cmd_rollback()
        # A swap file left behind after the work completed (cut before removal).
        world.swap_file.write_text(
            f"PHASE=rollback\nTAG={TAG}\nPREVIOUS_TAG={PREV}\n"
            f"VENV=venv.{TAG}\nPREVIOUS_VENV=venv.{PREV}\nVENV_MIGRATE=1\n"
            f"BACKUP_DIR={world.backup}\n", encoding="utf-8")
        mod.cmd_boot()
        assert world.live_files() == OLD_TREE
        assert world.venv_marker() == "old-venv"
        assert not world.swap_file.exists()


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------

class TestVerify:
    def swapped(self, world, mod, **build):
        world.build_staged(**build)
        mod.cmd_boot()

    def test_verify_passes_on_active_no_restarts_and_matching_version(
            self, world, mod, system, clock):
        self.swapped(world, mod, first_update=False, migrate=False)
        serve_status(mod)
        (world.opt / "venv.0.9.0").mkdir()
        mod.STAGING_DIR.mkdir(parents=True)
        result = mod.cmd_verify()
        assert result == {"ok": True, "verified": True}
        env = world.result()
        assert env["STATUS"] == "success"
        assert env["PHASE"] == "done"
        assert env["PERCENT_COMPLETE"] == "100"
        assert env["MESSAGE"] == f"Updated to {TAG}"
        assert env["ROLLED_BACK"] == "0"
        assert env["TAG"] == TAG and env["PREVIOUS_TAG"] == PREV
        assert not world.swap_file.exists()
        assert not world.backup.exists()
        assert not mod.UPDATING_FLAG.exists()
        assert not mod.STAGING_DIR.exists()
        assert system.reboots == 0
        # Housekeeping: only the active and the previous environment remain.
        names = sorted(p.name for p in world.opt.glob("venv*"))
        assert names == ["venv", f"venv.{PREV}", f"venv.{TAG}"]

    def test_verify_marks_the_swap_verifying_while_it_checks(self, world, mod, clock):
        self.swapped(world, mod)
        seen = []

        def status():
            seen.append(world.swap()["PHASE"])
            return 200, {"version": TAG}

        mod._fetch_status = status
        mod.cmd_verify()
        assert seen == ["verifying"]

    def test_verify_skips_version_compare_for_unparseable_tag(self, world, mod, clock):
        world.build_staged()
        world.swap_file.write_text(
            world.swap_file.read_text(encoding="utf-8").replace(f"TAG={TAG}", "TAG=unknown"),
            encoding="utf-8")
        mod.cmd_boot()
        serve_status(mod, version="dev-build")
        result = mod.cmd_verify()
        assert result["verified"] is True
        assert world.result()["STATUS"] == "success"

    def test_verify_accepts_a_tag_with_a_v_prefix(self, world, mod, clock):
        world.build_staged()
        world.swap_file.write_text(
            world.swap_file.read_text(encoding="utf-8").replace(f"TAG={TAG}", f"TAG=v{TAG}"),
            encoding="utf-8")
        mod.cmd_boot()
        serve_status(mod, version=TAG)
        assert mod.cmd_verify()["verified"] is True
        assert world.result()["MESSAGE"] == f"Updated to {TAG}"

    def test_verify_fails_on_nrestarts_then_rolls_back(self, world, mod, system, clock):
        self.swapped(world, mod, first_update=False)
        serve_status(mod)
        system.units[mod.DIAL_UNIT] = ("active", 1)
        result = mod.cmd_verify()
        assert result["rolled_back"] is True
        assert clock.sleeps == 0  # a restart is conclusive; no waiting
        assert world.result()["PHASE"] == "rolled_back"
        assert system.reboots == 1
        assert world.live_files() == OLD_TREE
        assert world.venv_marker() == "old-venv"

    def test_verify_fails_on_a_watcher_restart(self, world, mod, system, clock):
        self.swapped(world, mod)
        serve_status(mod)
        system.units[mod.WATCHER_UNIT] = ("active", 2)
        assert mod.cmd_verify()["rolled_back"] is True

    def test_verify_fails_when_the_service_has_failed(self, world, mod, system, clock):
        self.swapped(world, mod)
        serve_status(mod)
        system.units[mod.DIAL_UNIT] = ("failed", 0)
        assert mod.cmd_verify()["rolled_back"] is True
        assert clock.sleeps == 0

    def test_verify_fails_on_the_wrong_version(self, world, mod, system, clock):
        self.swapped(world, mod)
        serve_status(mod, version="1.2.0")
        assert mod.cmd_verify()["rolled_back"] is True
        assert world.result()["ROLLED_BACK"] == "1"

    def test_verify_deadline_rolls_back_when_service_never_becomes_active(
            self, world, mod, system, clock):
        self.swapped(world, mod)
        serve_status(mod)
        system.units[mod.DIAL_UNIT] = ("activating", 0)
        assert mod.cmd_verify()["rolled_back"] is True
        assert clock.now >= mod.VERIFY_DEADLINE_S
        assert system.reboots == 1

    def test_verify_deadline_rolls_back_when_endpoint_never_answers(
            self, world, mod, system, clock):
        self.swapped(world, mod)
        mod._fetch_status = lambda: (0, {})
        assert mod.cmd_verify()["rolled_back"] is True
        assert clock.now >= mod.VERIFY_DEADLINE_S

    def test_verify_waits_for_a_slow_start(self, world, mod, system, clock):
        self.swapped(world, mod)
        answers = iter([(0, {}), (503, {}), (200, {"version": TAG})])
        mod._fetch_status = lambda: next(answers)
        assert mod.cmd_verify()["verified"] is True
        assert clock.sleeps == 2

    def test_verify_without_a_swap_does_nothing(self, world, mod, system, clock):
        assert mod.cmd_verify() == {"ok": True, "verified": False}
        assert system.calls == []

    def test_verify_finishes_cleanup_after_a_cut_between_success_and_removal(
            self, world, mod, system, clock):
        self.swapped(world, mod)
        serve_status(mod)
        world.swap_file.write_text(
            world.swap_file.read_text(encoding="utf-8").replace(
                "PHASE=swapped", "PHASE=done"), encoding="utf-8")
        mod.cmd_boot()  # the next boot must not roll a verified update back
        assert world.result()["STATUS"] == "success"
        assert not world.swap_file.exists()
        assert system.reboots == 0
        assert world.live_files() == swapped_tree(first_update=False)


# ---------------------------------------------------------------------------
# Interrupted run: retry, then fail
# ---------------------------------------------------------------------------

class TestInterruptedRun:
    def test_boot_in_progress_pre_boot_with_staged_installer_retries_and_increments_attempt(
            self, world, mod, system):
        world.build_interrupted(attempt=1)
        result = mod.cmd_boot()
        assert result == {"ok": True, "retry": 2}
        env = world.result()
        assert env["STATUS"] == "in_progress"
        assert env["ATTEMPT"] == "2"
        assert env["MAX_ATTEMPTS"] == "4"
        assert env["PERCENT_COMPLETE"] == "0"
        assert env["MESSAGE"] == "Retrying update (attempt 2 of 4)"
        assert env["TAG"] == TAG and env["PREVIOUS_TAG"] == PREV
        assert mod.UPDATING_FLAG.exists()

    def test_retry_is_scheduled_like_the_appliance_retry(self, world, mod, system):
        world.build_interrupted(attempt=1)
        mod.cmd_boot()
        (cmd,) = system.retries_scheduled()
        assert "--on-active=2" in cmd
        assert "--property=After=NetworkManager.service" in cmd
        assert "--property=Wants=NetworkManager.service" in cmd
        assert "--setenv=AUTOSTREAM_RELEASE_TAG=v1.3.0" in cmd
        assert "--setenv=AUTOSTREAM_DIAL_LOCKED=1" in cmd
        assert any(a.startswith("--unit=autostream-update-dial-retry-") for a in cmd)
        assert cmd[-1] == "--update"
        assert cmd[-2].endswith("autostream_dial_install.sh")
        assert str(mod.LOCK_PATH) in cmd

    def test_retries_continue_up_to_four_attempts_then_fail(self, world, mod, system):
        world.build_interrupted(attempt=1)
        for expected in (2, 3, 4):
            result = mod.cmd_boot()
            assert result == {"ok": True, "retry": expected}
            assert world.result()["MESSAGE"] == f"Retrying update (attempt {expected} of 4)"
        system.calls.clear()
        mod.cmd_boot()
        env = world.result()
        assert env["STATUS"] == "failure"
        assert env["PHASE"] == "failed"
        assert env["MESSAGE"] == f"Update to {TAG} failed after 4 attempts - {PREV} kept"
        assert env["ATTEMPT"] == "4"
        assert system.retries_scheduled() == []
        assert not mod.UPDATING_FLAG.exists()
        assert not mod.STAGING_DIR.exists()

    def test_attempt_count_missing_from_an_old_result_counts_as_the_first(
            self, world, mod, system):
        world.build_interrupted(attempt=1)
        world.result_file.write_text(
            "STATUS=in_progress\nPERCENT_COMPLETE=20\nMESSAGE=Installing...\n"
            "LAST_RUN_AT=2000-01-01T00:00:00+00:00\n", encoding="utf-8")
        assert mod.cmd_boot() == {"ok": True, "retry": 2}

    def test_boot_retry_restores_backup_set_when_configure_had_started(
            self, world, mod, system):
        world.build_interrupted(attempt=1, backup=True)
        (world.fs / "etc" / "added.conf").write_text("added", encoding="utf-8")
        mod.cmd_boot()
        assert (world.fs / "etc" / "foo.conf").read_text(encoding="utf-8") == "old conf"
        assert not (world.fs / "etc" / "added.conf").exists()
        assert not world.backup.exists()
        assert ["systemctl", "daemon-reload"] in system.calls
        assert len(system.retries_scheduled()) == 1

    def test_boot_retry_leaves_owned_files_alone_without_a_backup(self, world, mod):
        world.build_interrupted(attempt=1, backup=False)
        mod.cmd_boot()
        assert (world.fs / "etc" / "foo.conf").read_text(encoding="utf-8") == "half-written conf"

    def test_attempt_cap_marks_failure_and_keeps_previous(self, world, mod, system):
        world.build_interrupted(attempt=4, backup=True)
        mod.cmd_boot()
        env = world.result()
        assert env["STATUS"] == "failure"
        assert env["MESSAGE"] == f"Update to {TAG} failed after 4 attempts - {PREV} kept"
        assert (world.fs / "etc" / "foo.conf").read_text(encoding="utf-8") == "old conf"
        assert system.retries_scheduled() == []

    def test_in_progress_without_staged_installer_marks_failure(self, world, mod, system):
        world.build_interrupted(attempt=1, installer=False, backup=True)
        mod.cmd_boot()
        env = world.result()
        assert env["STATUS"] == "failure"
        assert env["PHASE"] == "failed"
        assert env["MESSAGE"] == (
            f"Update to {TAG} was interrupted and recovery files are unavailable - {PREV} kept")
        assert (world.fs / "etc" / "foo.conf").read_text(encoding="utf-8") == "old conf"
        assert not mod.UPDATING_FLAG.exists()
        assert system.retries_scheduled() == []

    def test_in_progress_with_no_tag_still_reports_failure(self, world, mod):
        world.result_file.write_text("STATUS=in_progress\n", encoding="utf-8")
        mod.cmd_boot()
        env = world.result()
        assert env["STATUS"] == "failure"
        assert env["MESSAGE"].startswith("Update was interrupted")

    def test_in_progress_from_this_boot_is_left_alone(self, world, mod, system):
        world.build_interrupted(attempt=1)
        mod._is_pre_boot = lambda ts: False
        before = world.result_file.read_text(encoding="utf-8")
        assert mod.cmd_boot() == {"ok": True}
        assert world.result_file.read_text(encoding="utf-8") == before
        assert system.calls == []

    def test_active_installer_unit_leaves_in_progress_alone(self, world, mod, system):
        world.build_interrupted(attempt=1)
        mod._dial_update_unit_active = lambda: True
        mod.cmd_boot()
        assert world.result()["STATUS"] == "in_progress"
        assert system.retries_scheduled() == []

    def test_retry_that_cannot_be_scheduled_is_reported_as_failure(self, world, mod, system):
        world.build_interrupted(attempt=1)
        system.systemd_run_rc = 1
        result = mod.cmd_boot()
        assert result["ok"] is False
        assert world.result()["STATUS"] == "failure"
        assert not mod.UPDATING_FLAG.exists()


# ---------------------------------------------------------------------------
# Nothing to do
# ---------------------------------------------------------------------------

class TestIdle:
    def test_no_swap_file_and_no_result_is_a_noop(self, world, mod, system):
        assert mod.cmd_boot() == {"ok": True}
        assert system.calls == []

    @pytest.mark.parametrize("status", ["success", "failure", ""])
    def test_no_swap_file_and_no_in_progress_is_a_noop(self, world, mod, system, status):
        world.result_file.write_text(f"STATUS={status}\n", encoding="utf-8")
        before = world.result_file.read_text(encoding="utf-8")
        assert mod.cmd_boot() == {"ok": True}
        assert world.result_file.read_text(encoding="utf-8") == before
        assert system.calls == []

    def test_boot_idle_is_noop_and_prunes_old_venvs(self, world, mod, system):
        world.write_tree(world.opt, OLD_TREE)
        for name in ("venv.1.0.0", "venv.1.1.0", "venv.1.2.0", "venv.1.3.0"):
            (world.opt / name).mkdir()
        os.utime(world.opt / "venv.1.0.0", (1, 1))
        os.utime(world.opt / "venv.1.1.0", (2, 2))
        os.symlink("venv.1.3.0", world.opt / "venv")
        os.symlink("venv.gone", world.opt / "venv.tmp")
        world.result_file.write_text("STATUS=success\n", encoding="utf-8")
        mod.cmd_boot()
        names = sorted(p.name for p in world.opt.glob("venv*"))
        assert names == ["venv", "venv.1.2.0", "venv.1.3.0"]
        assert world.live_files() == OLD_TREE
        assert system.calls == []

    def test_boot_idle_leaves_a_real_venv_directory_alone(self, world, mod):
        (world.opt / "venv").mkdir()
        (world.opt / "venv.1.0.0").mkdir()
        mod.cmd_boot()
        assert (world.opt / "venv.1.0.0").is_dir()

    def test_boot_idle_removes_a_finished_rollbacks_leftover(self, world, mod):
        (world.opt / ".prev.done").mkdir()
        mod.cmd_boot()
        assert not (world.opt / ".prev.done").exists()


# ---------------------------------------------------------------------------
# Result file and unit
# ---------------------------------------------------------------------------

class TestResultFile:
    def test_result_file_mode_stays_group_readable(self, world, mod, system, clock):
        world.build_staged()
        os.chmod(world.result_file, 0o600)
        mod.cmd_boot()
        assert stat.S_IMODE(world.result_file.stat().st_mode) == 0o644
        serve_status(mod)
        os.chmod(world.result_file, 0o600)
        mod.cmd_verify()
        assert stat.S_IMODE(world.result_file.stat().st_mode) == 0o644

    def test_rollback_result_is_group_readable(self, world, mod):
        swap_in(world, mod, "swapped")
        os.chmod(world.result_file, 0o600)
        mod.cmd_rollback()
        assert stat.S_IMODE(world.result_file.stat().st_mode) == 0o644

    def test_swap_file_is_group_readable(self, world, mod):
        world.build_staged()
        mod.cmd_boot()
        assert stat.S_IMODE(world.swap_file.stat().st_mode) == 0o644

    def test_boot_writes_keep_tag_and_attempt(self, world, mod, clock):
        world.build_staged()
        mod.write_update_result("in_progress", "x", attempt=3, tag=TAG, previous_tag=PREV)
        mod.cmd_boot()
        serve_status(mod)
        mod.cmd_verify()
        env = world.result()
        assert env["ATTEMPT"] == "3"
        assert env["TAG"] == TAG


class TestManifestParsing:
    def test_paths_that_escape_the_tree_are_ignored(self, tmp_path, mod):
        manifest = tmp_path / "MANIFEST"
        manifest.write_text(
            "0644\troot:root\tgood.py\n"
            "0644\troot:root\t/etc/passwd\n"
            "0644\troot:root\t../outside.py\n"
            "garbage line\n"
            "0755\troot:root\tsub/ok.py\n",
            encoding="utf-8")
        assert mod._read_manifest_paths(manifest) == ["good.py", "sub/ok.py"]

    def test_missing_manifest_lists_nothing(self, tmp_path, mod):
        assert mod._read_manifest_paths(tmp_path / "absent") == []


class TestBootUnit:
    UNIT = REPO_ROOT / "system" / "systemd" / "autostream_dial_update_recover.service"

    def _field(self, section: str, key: str) -> str:
        current = ""
        for line in self.UNIT.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                current = line[1:-1]
            elif current == section and line.startswith(key + "="):
                return line.split("=", 1)[1]
        return ""

    def test_recover_unit_runs_under_system_python_and_before_dial_and_nginx(self):
        exec_start = self._field("Service", "ExecStart")
        assert exec_start.startswith("/usr/bin/python3 ")
        assert exec_start.endswith("autostream_dial_updater boot")
        assert "venv" not in exec_start
        before = self._field("Unit", "Before").split()
        for unit in ("autostream_dial.service", "autostream_dial_wifi_watcher.service",
                     "autostream_dial_updater.service", "nginx.service"):
            assert unit in before
        assert "local-fs.target" in self._field("Unit", "After")
        assert self._field("Unit", "DefaultDependencies") == "no"


class TestCrashMatrixCoverage:
    """The interruption tests above step through every rename; make sure the
    ranges they use are not shorter than the real sequences."""

    @staticmethod
    def _count(fn) -> int:
        real = os.replace
        count = {"n": 0}

        def counting(src, dst, *a, **kw):
            count["n"] += 1
            return real(src, dst, *a, **kw)

        with patch("os.replace", counting):
            fn()
        return count["n"]

    def test_swap_sequence_fits_the_interruption_range(self, world, mod):
        world.build_staged(first_update=True, migrate=True)
        assert self._count(mod.cmd_boot) < 24

    def test_rollback_sequence_fits_the_interruption_range(self, world, mod):
        swap_in(world, mod, "verifying", first_update=False, migrate=True)
        assert self._count(mod.cmd_rollback) < 26
