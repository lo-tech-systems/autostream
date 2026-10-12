"""Two details of how a dial update ends.

A rolled-back update leaves nothing staged behind, and the result file root
writes is owned by root outright: it does not take the owner of whatever file
it replaces, which the service account could have put there.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_dial_staged_install import Env, RECORDER, bash_capable, posix_only  # noqa: E402
from test_dial_update_boot import (  # noqa: E402,F401  (fixtures are used by name)
    clock, mod, system, world,
)

pytestmark = posix_only


class TestARollbackLeavesNothingStaged:
    def _stage_a_release(self, mod) -> Path:
        installer = mod.STAGING_DIR / "src" / "release" / "autostream_dial_install.sh"
        installer.parent.mkdir(parents=True)
        installer.write_text("#!/bin/sh\n", encoding="utf-8")
        return mod.STAGING_DIR

    def test_the_staged_release_is_removed_once_the_rollback_is_done(self, world, mod, system):
        world.build_staged(first_update=False, migrate=False)
        staging = self._stage_a_release(mod)
        mod.cmd_boot()
        assert staging.exists()                     # the swap itself still needs nothing from it
        mod.cmd_rollback()
        assert not staging.exists()
        assert world.result()["PHASE"] == "rolled_back"
        assert system.reboots == 1

    def test_a_rollback_at_boot_removes_it_too(self, world, mod, system):
        world.build_staged(first_update=False, migrate=False)
        staging = self._stage_a_release(mod)
        world.swap_file.write_text(
            world.swap_file.read_text(encoding="utf-8").replace("PHASE=staged", "PHASE=verifying"),
            encoding="utf-8")
        mod.cmd_boot()
        assert not staging.exists()


class TestTheResultFileIsRootsOutright:
    def test_the_owner_is_set_whatever_owned_the_file_before(self, tmp_path, monkeypatch):
        from test_dial_update_result import _load
        mod = _load(tmp_path)
        (tmp_path / "update-result.env").write_text("STATUS=failure\n", encoding="utf-8")
        calls = []
        real_lstat = os.lstat

        def foreign_owner(path, *args, **kwargs):
            st = real_lstat(path, *args, **kwargs)
            if str(path).endswith("update-result.env"):
                return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink,
                                       4242, 4242, st.st_size, 0, 0, 0))
            return st

        monkeypatch.setattr(os, "lstat", foreign_owner)
        monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: calls.append((uid, gid)))
        mod.write_update_result("in_progress", "Working", percent=5)
        assert calls == []

    def test_the_owner_is_set_when_there_was_no_file(self, tmp_path, monkeypatch):
        from test_dial_update_result import _load
        mod = _load(tmp_path)
        calls = []
        monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: calls.append((uid, gid)))
        mod.write_update_result("in_progress", "Working", percent=5)
        assert calls == []

    @bash_capable
    def test_the_installer_does_not_copy_the_owner_of_the_file_it_replaces(self, tmp_path):
        env = Env(tmp_path)
        env.fake("chown", RECORDER)
        # A stat that reports a foreign owner for anything it is asked about.
        env.fake("stat", '#!/bin/bash\necho "stat $*" >> "$TRACE"\necho "4242:4242"\n')
        env.result.write_text("STATUS=failure\n", encoding="utf-8")
        r = env.run('write_update_result in_progress "Working" 5')
        assert r.returncode == 0, r.stderr
        calls = env.calls()
        assert not [c for c in calls if "4242" in c]
        assert not [c for c in calls if c.startswith("stat") and "update-result" in c]
