"""The root-only directory an update stages into and hands off through.

The service account owns /var/lib/autostream and can replace anything in it,
so root must not run or trust a file it finds there on a schedule or after a
reboot. Both installers make /var/lib/autostream-update, owned by root alone
with mode 0700, and the updaters open it through one accessor that refuses
anything else. These tests plant the things the service account could plant
(a link at the name, a directory it owns, a loose mode) and check that the
installers' helper puts a proper directory in their place and that the
accessor refuses every one of them.

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
sys.path.insert(0, str(Path(__file__).parent.parent / "supervisor"))
from test_dial_staged_install import (  # noqa: E402
    Env, REPO_ROOT, bash_capable, posix_only,
)

import autostream_update_support as support  # noqa: E402

UPDATE_STATE = REPO_ROOT / "installer" / "lib" / "update_state.sh"
APPLIANCE_INSTALLER = REPO_ROOT / "autostream_install.sh"
DIAL_INSTALLER = REPO_ROOT / "autostream_dial_install.sh"
DIAL_HELPERS = REPO_ROOT / "installer" / "dial" / "helpers.sh"
APPLIANCE_UNINSTALLER = REPO_ROOT / "autostream_uninstall.sh"
DIAL_UNINSTALLER = REPO_ROOT / "autostream_dial_uninstall.sh"

pytestmark = posix_only


def _ensure(tmp_path: Path, target: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c",
         f'set -euo pipefail\nsource "{UPDATE_STATE.as_posix()}"\n'
         f'ensure_update_state_dir "{target.as_posix()}"'],
        capture_output=True, text=True, timeout=30, cwd=tmp_path)


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


# ---------------------------------------------------------------------------
# The installers' helper
# ---------------------------------------------------------------------------

@bash_capable
class TestEnsureUpdateStateDir:
    def test_creates_the_directory_private_to_the_caller(self, tmp_path):
        target = tmp_path / "var" / "lib" / "autostream-update"
        r = _ensure(tmp_path, target)
        assert r.returncode == 0, r.stderr
        st = os.lstat(target)
        assert stat.S_ISDIR(st.st_mode)
        assert st.st_uid == os.getuid()
        assert _mode(target) == 0o700

    def test_a_directory_that_is_already_right_keeps_its_contents(self, tmp_path):
        target = tmp_path / "upd"
        target.mkdir(mode=0o700)
        (target / "staging").mkdir()
        (target / "staging" / "release_tag").write_text("1.0.0\n")
        r = _ensure(tmp_path, target)
        assert r.returncode == 0, r.stderr
        assert (target / "staging" / "release_tag").read_text() == "1.0.0\n"

    def test_a_link_at_the_name_is_replaced_not_followed(self, tmp_path):
        elsewhere = tmp_path / "attacker-dir"
        elsewhere.mkdir(mode=0o755)
        (elsewhere / "marker").write_text("theirs")
        target = tmp_path / "upd"
        target.symlink_to(elsewhere)
        r = _ensure(tmp_path, target)
        assert r.returncode == 0, r.stderr
        assert not target.is_symlink()
        assert stat.S_ISDIR(os.lstat(target).st_mode)
        assert _mode(target) == 0o700
        assert list(target.iterdir()) == []
        # What the link pointed at is untouched, mode included.
        assert (elsewhere / "marker").read_text() == "theirs"
        assert _mode(elsewhere) == 0o755

    def test_a_loose_directory_is_emptied_and_made_again(self, tmp_path):
        target = tmp_path / "upd"
        target.mkdir()
        target.chmod(0o755)
        (target / "src").mkdir()
        (target / "src" / "autostream_install.sh").write_text("#!/bin/sh\nexit 0\n")
        r = _ensure(tmp_path, target)
        assert r.returncode == 0, r.stderr
        assert _mode(target) == 0o700
        assert list(target.iterdir()) == []

    def test_a_plain_file_at_the_name_is_replaced(self, tmp_path):
        target = tmp_path / "upd"
        target.write_text("not a directory")
        r = _ensure(tmp_path, target)
        assert r.returncode == 0, r.stderr
        assert stat.S_ISDIR(os.lstat(target).st_mode)
        assert _mode(target) == 0o700

    def test_it_refuses_an_empty_or_root_name(self, tmp_path):
        for name in ('""', "/"):
            r = subprocess.run(
                ["bash", "-c",
                 f'source "{UPDATE_STATE.as_posix()}"; ensure_update_state_dir {name}'],
                capture_output=True, text=True, timeout=30, cwd=tmp_path)
            assert r.returncode != 0


# ---------------------------------------------------------------------------
# The accessor the updaters open it through
# ---------------------------------------------------------------------------

class TestTrustedStateDir:
    def test_accepts_a_directory_owned_by_the_trusted_user_with_mode_0700(self, tmp_path):
        d = tmp_path / "upd"
        d.mkdir(mode=0o700)
        assert support.trusted_state_dir(d, os.getuid()) == d

    def test_refuses_a_directory_owned_by_someone_else(self, tmp_path):
        d = tmp_path / "upd"
        d.mkdir(mode=0o700)
        with pytest.raises(ValueError, match="owned"):
            support.trusted_state_dir(d, os.getuid() + 1)

    @pytest.mark.parametrize("mode", [0o770, 0o755, 0o750, 0o707, 0o500, 0o777])
    def test_refuses_any_mode_but_0700(self, tmp_path, mode):
        d = tmp_path / "upd"
        d.mkdir()
        d.chmod(mode)
        with pytest.raises(ValueError, match="mode"):
            support.trusted_state_dir(d, os.getuid())

    def test_refuses_a_link_even_to_a_proper_directory(self, tmp_path):
        real = tmp_path / "real"
        real.mkdir(mode=0o700)
        d = tmp_path / "upd"
        d.symlink_to(real)
        with pytest.raises(ValueError, match="link"):
            support.trusted_state_dir(d, os.getuid())

    def test_refuses_a_plain_file(self, tmp_path):
        d = tmp_path / "upd"
        d.write_text("x")
        d.chmod(0o700)
        with pytest.raises(ValueError, match="directory"):
            support.trusted_state_dir(d, os.getuid())

    def test_an_absent_directory_is_reported_as_absent(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            support.trusted_state_dir(tmp_path / "upd", os.getuid())

    def test_create_makes_a_proper_directory(self, tmp_path):
        d = tmp_path / "upd"
        assert support.trusted_state_dir(d, os.getuid(), create=True) == d
        assert _mode(d) == 0o700
        assert os.lstat(d).st_uid == os.getuid()

    def test_create_does_not_repair_a_loose_directory_that_is_there(self, tmp_path):
        d = tmp_path / "upd"
        d.mkdir()
        d.chmod(0o755)
        with pytest.raises(ValueError):
            support.trusted_state_dir(d, os.getuid(), create=True)
        assert _mode(d) == 0o755

    def test_create_does_not_follow_a_link_at_the_name(self, tmp_path):
        real = tmp_path / "real"
        real.mkdir(mode=0o755)
        d = tmp_path / "upd"
        d.symlink_to(real)
        with pytest.raises(ValueError):
            support.trusted_state_dir(d, os.getuid(), create=True)
        assert _mode(real) == 0o755

    def test_the_default_is_the_system_location_and_root(self):
        import inspect
        sig = inspect.signature(support.trusted_state_dir)
        assert support.UPDATE_STATE_DIR == Path("/var/lib/autostream-update")
        assert sig.parameters["path"].default == support.UPDATE_STATE_DIR
        assert sig.parameters["owner_uid"].default == 0


# ---------------------------------------------------------------------------
# Wiring (reads the scripts: the installers need root and a device to run)
# ---------------------------------------------------------------------------

class TestWiring:
    def test_appliance_installer_prepares_it_on_install_and_on_update(self):
        text = APPLIANCE_INSTALLER.read_text(encoding="utf-8")
        assert 'source "${INSTALLER_LIB}/update_state.sh"' in text
        assert text.count("\n  prepare_update_state_dir\n") == 2
        bootstrap = text[text.index("bootstrap_phase() {"):]
        assert bootstrap.index("prepare_update_state_dir") < bootstrap.index("recover_interrupted_packages")
        update = text[text.index("run_update() {"):]
        assert update.index("prepare_update_state_dir") < update.index("write_update_result")

    def test_dial_installer_prepares_it_in_create_dirs_on_both_paths(self):
        helpers = DIAL_HELPERS.read_text(encoding="utf-8")
        body = helpers[helpers.index("create_dirs() {"):helpers.index("create_service_user() {")]
        assert 'ensure_update_state_dir "$(_update_dir)"' in body
        installer = DIAL_INSTALLER.read_text(encoding="utf-8")
        assert installer.count("create_dirs") == 2   # the update path and the fresh path

    @bash_capable
    def test_dial_helper_puts_the_directory_under_the_scratch_root(self, tmp_path):
        env = Env(tmp_path)
        r = env.run('ensure_update_state_dir "$(_update_dir)"; _update_dir')
        assert r.returncode == 0, r.stderr
        target = env.root / "var" / "lib" / "autostream-update"
        assert r.stdout.strip() == target.as_posix()
        assert _mode(target) == 0o700

    def test_both_uninstallers_remove_it(self):
        assert "remove_path /var/lib/autostream-update" in APPLIANCE_UNINSTALLER.read_text(encoding="utf-8")
        assert "rm -rf /var/lib/autostream-update" in DIAL_UNINSTALLER.read_text(encoding="utf-8")
