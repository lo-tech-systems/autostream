"""Priority 4 — Update recovery tests.

Covers autostream_update_retry.main() (host boot-time recovery) and
autostream_dial_updater.cmd_recover() (dial recovery).

Dial recovery: checks STATUS=in_progress (canonical schema); writes
STATUS=failure and removes UPDATING_FLAG when both the unit-active and
lock-free guards pass.

Both modules are loaded via load_supervisor_script() so fcntl is stubbed
on Windows.  Path constants are redirected to tmp_path after load.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "tests"))

_SUPERVISOR_DIR = str(REPO_ROOT / "supervisor")
if _SUPERVISOR_DIR not in sys.path:
    sys.path.insert(0, _SUPERVISOR_DIR)

from conftest import load_supervisor_script


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_retry(tmp_path: Path) -> ModuleType:
    mod = load_supervisor_script("autostream_update_retry", "update_retry_test")
    mod.STAMP_DIR = tmp_path
    mod.UPDATE_RESULT_FILE = tmp_path / "update-result.env"
    mod.STAGING_DIR = tmp_path / "staging"
    mod.RELEASE_TAG_FILE = tmp_path / "staging" / "release_tag"
    mod.RETRY_COUNT_FILE = tmp_path / "staging" / "retry_count"
    mod.UPDATING_FLAG = tmp_path / "autostream-updating"
    mod.LOG_PATH = tmp_path / "update.log"
    mod.UPDATE_LOCK_FILE = tmp_path / "update.lock"
    return mod


def _geteuid_root():
    """Patch os.geteuid to return 0 (simulates root); create=True for Windows."""
    return patch("os.geteuid", return_value=0, create=True)


def _chown_noop():
    """Patch os.chown to no-op; create=True for Windows where it doesn't exist."""
    return patch("os.chown", return_value=None, create=True)


def _load_dial(tmp_path: Path) -> ModuleType:
    mod = load_supervisor_script("autostream_dial_updater", "dial_recover_test")
    mod.STATE_DIR = tmp_path
    mod.LOCK_PATH = tmp_path / "dial.lock"
    mod.LOG_PATH = tmp_path / "dial-update.log"
    mod.UPDATING_FLAG = tmp_path / "autostream-dial-updating"
    return mod


def _write_result(tmp_path: Path, status: str, last_run_at: str = "") -> None:
    (tmp_path / "update-result.env").write_text(
        f'STATUS="{status}"\nLAST_RUN_AT="{last_run_at}"\nMESSAGE="test"\nPERCENT_COMPLETE="0"\n',
        encoding="utf-8",
    )


def _make_installer(tmp_path: Path, staging_dir: Path) -> Path:
    """Create a staged installer under staging_dir/src/myrepo/autostream_install.sh."""
    src = staging_dir / "src" / "myrepo-v1.2.3"
    src.mkdir(parents=True, exist_ok=True)
    installer = src / "autostream_install.sh"
    installer.write_text("#!/bin/sh\nexit 0\n")
    installer.chmod(0o755)
    return installer


def _old_timestamp() -> str:
    """Return an ISO timestamp 120 minutes in the past (safely pre-boot)."""
    ts = datetime.now(tz=timezone.utc) - timedelta(minutes=120)
    return ts.isoformat(timespec="seconds")


def _recent_timestamp() -> str:
    """Return an ISO timestamp 30 seconds in the past (post-boot)."""
    ts = datetime.now(tz=timezone.utc) - timedelta(seconds=30)
    return ts.isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# autostream_update_retry: status-based early exits
# ---------------------------------------------------------------------------

class TestRetryStatusEarlyExit:
    def test_no_result_file_exits_0(self, tmp_path):
        mod = _load_retry(tmp_path)
        with _geteuid_root():
            rc = mod.main()
        assert rc == 0

    def test_status_success_exits_0(self, tmp_path):
        mod = _load_retry(tmp_path)
        _write_result(tmp_path, "success")
        with _geteuid_root():
            rc = mod.main()
        assert rc == 0

    def test_status_failure_exits_0(self, tmp_path):
        mod = _load_retry(tmp_path)
        _write_result(tmp_path, "failure")
        with _geteuid_root():
            rc = mod.main()
        assert rc == 0

    def test_in_progress_but_recent_timestamp_exits_0(self, tmp_path):
        mod = _load_retry(tmp_path)
        _write_result(tmp_path, "in_progress", _recent_timestamp())
        with _geteuid_root(), \
             patch.object(mod, "_is_pre_boot", return_value=False):
            rc = mod.main()
        assert rc == 0


# ---------------------------------------------------------------------------
# autostream_update_retry: in_progress pre-boot with no installer
# ---------------------------------------------------------------------------

class TestRetryNoInstaller:
    def test_missing_installer_writes_failure_and_exits_1(self, tmp_path):
        mod = _load_retry(tmp_path)
        _write_result(tmp_path, "in_progress", _old_timestamp())
        # No staging dir / installer
        with _geteuid_root(), \
             patch.object(mod, "_is_pre_boot", return_value=True), \
             _chown_noop():
            rc = mod.main()
        assert rc == 1
        result_text = mod.UPDATE_RESULT_FILE.read_text()
        assert "failure" in result_text.lower()


# ---------------------------------------------------------------------------
# autostream_update_retry: retry cap
# ---------------------------------------------------------------------------

class TestRetryCapExhausted:
    def test_cap_reached_writes_failure(self, tmp_path):
        mod = _load_retry(tmp_path)
        _write_result(tmp_path, "in_progress", _old_timestamp())
        mod.STAGING_DIR.mkdir(parents=True, exist_ok=True)
        _make_installer(tmp_path, mod.STAGING_DIR)
        mod.RETRY_COUNT_FILE.write_text(str(mod.MAX_RETRIES) + "\n")
        with _geteuid_root(), \
             patch.object(mod, "_is_pre_boot", return_value=True), \
             _chown_noop():
            rc = mod.main()
        assert rc == 1
        result_text = mod.UPDATE_RESULT_FILE.read_text()
        assert "failure" in result_text.lower()

    def test_cap_minus_one_proceeds(self, tmp_path):
        mod = _load_retry(tmp_path)
        _write_result(tmp_path, "in_progress", _old_timestamp())
        mod.STAGING_DIR.mkdir(parents=True, exist_ok=True)
        _make_installer(tmp_path, mod.STAGING_DIR)
        mod.RETRY_COUNT_FILE.write_text(str(mod.MAX_RETRIES - 1) + "\n")
        mod.RELEASE_TAG_FILE.write_text("v1.2.3\n")
        with _geteuid_root(), \
             patch.object(mod, "_is_pre_boot", return_value=True), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(mod, "_run", return_value=(0, "", "")), \
             _chown_noop():
            rc = mod.main()
        assert rc == 0


# ---------------------------------------------------------------------------
# autostream_update_retry: success path increments counter
# ---------------------------------------------------------------------------

class TestRetrySuccessPath:
    def test_increments_retry_count_before_scheduling(self, tmp_path):
        mod = _load_retry(tmp_path)
        _write_result(tmp_path, "in_progress", _old_timestamp())
        mod.STAGING_DIR.mkdir(parents=True, exist_ok=True)
        _make_installer(tmp_path, mod.STAGING_DIR)
        mod.RETRY_COUNT_FILE.write_text("1\n")
        mod.RELEASE_TAG_FILE.write_text("v1.2.3\n")

        with _geteuid_root(), \
             patch.object(mod, "_is_pre_boot", return_value=True), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(mod, "_run", return_value=(0, "", "")), \
             _chown_noop():
            rc = mod.main()

        assert rc == 0
        new_count = int(mod.RETRY_COUNT_FILE.read_text().strip())
        assert new_count == 2   # incremented from 1

    def test_success_writes_in_progress_result(self, tmp_path):
        mod = _load_retry(tmp_path)
        _write_result(tmp_path, "in_progress", _old_timestamp())
        mod.STAGING_DIR.mkdir(parents=True, exist_ok=True)
        _make_installer(tmp_path, mod.STAGING_DIR)
        mod.RETRY_COUNT_FILE.write_text("0\n")
        mod.RELEASE_TAG_FILE.write_text("v1.2.3\n")

        with _geteuid_root(), \
             patch.object(mod, "_is_pre_boot", return_value=True), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(mod, "_run", return_value=(0, "", "")), \
             _chown_noop():
            rc = mod.main()

        assert rc == 0
        result_text = mod.UPDATE_RESULT_FILE.read_text()
        assert "in_progress" in result_text.lower()

    def test_systemd_run_command_includes_release_tag(self, tmp_path):
        mod = _load_retry(tmp_path)
        _write_result(tmp_path, "in_progress", _old_timestamp())
        mod.STAGING_DIR.mkdir(parents=True, exist_ok=True)
        _make_installer(tmp_path, mod.STAGING_DIR)
        mod.RETRY_COUNT_FILE.write_text("0\n")
        mod.RELEASE_TAG_FILE.write_text("v1.2.3\n")
        captured_cmd = []

        def fake_run(cmd, timeout=60):
            captured_cmd.extend(cmd)
            return (0, "", "")

        with _geteuid_root(), \
             patch.object(mod, "_is_pre_boot", return_value=True), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(mod, "_run", side_effect=fake_run), \
             _chown_noop():
            mod.main()

        assert "AUTOSTREAM_RELEASE_TAG=v1.2.3" in " ".join(captured_cmd)
        assert "--update" in captured_cmd


# ---------------------------------------------------------------------------
# autostream_update_retry: scheduling failures
# ---------------------------------------------------------------------------

class TestRetrySchedulingFailure:
    def test_systemd_run_not_found_writes_failure(self, tmp_path):
        mod = _load_retry(tmp_path)
        _write_result(tmp_path, "in_progress", _old_timestamp())
        mod.STAGING_DIR.mkdir(parents=True, exist_ok=True)
        _make_installer(tmp_path, mod.STAGING_DIR)
        mod.RETRY_COUNT_FILE.write_text("0\n")
        with _geteuid_root(), \
             patch.object(mod, "_is_pre_boot", return_value=True), \
             patch.object(mod, "_find_systemd_run", return_value=None), \
             _chown_noop():
            rc = mod.main()
        assert rc == 1
        assert "failure" in mod.UPDATE_RESULT_FILE.read_text().lower()

    def test_flock_not_found_writes_failure(self, tmp_path):
        mod = _load_retry(tmp_path)
        _write_result(tmp_path, "in_progress", _old_timestamp())
        mod.STAGING_DIR.mkdir(parents=True, exist_ok=True)
        _make_installer(tmp_path, mod.STAGING_DIR)
        mod.RETRY_COUNT_FILE.write_text("0\n")
        with _geteuid_root(), \
             patch.object(mod, "_is_pre_boot", return_value=True), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=False), \
             _chown_noop():
            rc = mod.main()
        assert rc == 1
        assert "failure" in mod.UPDATE_RESULT_FILE.read_text().lower()

    def test_subprocess_error_writes_failure(self, tmp_path):
        mod = _load_retry(tmp_path)
        _write_result(tmp_path, "in_progress", _old_timestamp())
        mod.STAGING_DIR.mkdir(parents=True, exist_ok=True)
        _make_installer(tmp_path, mod.STAGING_DIR)
        mod.RETRY_COUNT_FILE.write_text("0\n")
        with _geteuid_root(), \
             patch.object(mod, "_is_pre_boot", return_value=True), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(mod, "_run", side_effect=OSError("spawn failed")), \
             _chown_noop():
            rc = mod.main()
        assert rc == 1
        assert "failure" in mod.UPDATE_RESULT_FILE.read_text().lower()

    def test_systemd_run_nonzero_writes_failure(self, tmp_path):
        mod = _load_retry(tmp_path)
        _write_result(tmp_path, "in_progress", _old_timestamp())
        mod.STAGING_DIR.mkdir(parents=True, exist_ok=True)
        _make_installer(tmp_path, mod.STAGING_DIR)
        mod.RETRY_COUNT_FILE.write_text("0\n")
        with _geteuid_root(), \
             patch.object(mod, "_is_pre_boot", return_value=True), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(mod, "_run", return_value=(1, "", "err")), \
             _chown_noop():
            rc = mod.main()
        assert rc == 1


# ---------------------------------------------------------------------------
# autostream_dial_updater: cmd_recover
# ---------------------------------------------------------------------------

class TestDialRecover:
    def test_no_result_file_returns_ok_noop(self, tmp_path):
        """Missing update-result.env is a no-op (no prior update recorded)."""
        mod = _load_dial(tmp_path)
        result = mod.cmd_recover()
        assert result.get("ok") is True

    def test_status_not_in_progress_is_noop(self, tmp_path):
        """STATUS=success is not an interrupted update — leave unchanged."""
        mod = _load_dial(tmp_path)
        (tmp_path / "update-result.env").write_text("STATUS=success\n")
        result = mod.cmd_recover()
        assert result.get("ok") is True

    def test_active_unit_leaves_unchanged(self, tmp_path):
        """STATUS=in_progress with an active update unit is a live update — leave unchanged."""
        mod = _load_dial(tmp_path)
        (tmp_path / "update-result.env").write_text("STATUS=in_progress\n")
        with patch.object(mod, "_dial_update_unit_active", return_value=True):
            result = mod.cmd_recover()
        assert result.get("ok") is True
        content = (tmp_path / "update-result.env").read_text()
        assert "in_progress" in content

    def test_unit_check_error_returns_ok_false(self, tmp_path):
        """Unit check failure is fail-closed; STATUS is left unchanged."""
        mod = _load_dial(tmp_path)
        (tmp_path / "update-result.env").write_text("STATUS=in_progress\n")
        with patch.object(mod, "_dial_update_unit_active",
                          side_effect=RuntimeError("systemctl broke")):
            result = mod.cmd_recover()
        assert result.get("ok") is False

    def test_lock_held_leaves_unchanged(self, tmp_path):
        """Lock held by a running installer leaves STATUS=in_progress unchanged."""
        mod = _load_dial(tmp_path)
        (tmp_path / "update-result.env").write_text("STATUS=in_progress\n")
        import errno as _errno
        with patch.object(mod, "_dial_update_unit_active", return_value=False):
            mod.fcntl.flock.side_effect = OSError(_errno.EWOULDBLOCK, "held")
            result = mod.cmd_recover()
            mod.fcntl.flock.side_effect = None
        assert result.get("ok") is True
        content = (tmp_path / "update-result.env").read_text()
        assert "in_progress" in content

    def test_both_guards_pass_writes_failure(self, tmp_path):
        """Both guards pass: write STATUS=failure to record the interrupted update."""
        mod = _load_dial(tmp_path)
        (tmp_path / "update-result.env").write_text("STATUS=in_progress\n")
        with patch.object(mod, "_dial_update_unit_active", return_value=False):
            mod.fcntl.flock.side_effect = None
            mod.fcntl.flock.return_value = None
            result = mod.cmd_recover()
        assert result.get("ok") is True
        content = (tmp_path / "update-result.env").read_text()
        assert "STATUS=failure" in content

    def test_both_guards_pass_removes_updating_flag(self, tmp_path):
        """Boot recovery removes the stale UPDATING_FLAG so nginx stops redirecting."""
        mod = _load_dial(tmp_path)
        (tmp_path / "update-result.env").write_text("STATUS=in_progress\n")
        flag = tmp_path / "autostream-dial-updating"
        flag.touch()
        with patch.object(mod, "_dial_update_unit_active", return_value=False):
            mod.fcntl.flock.side_effect = None
            mod.fcntl.flock.return_value = None
            result = mod.cmd_recover()
        assert result.get("ok") is True
        assert not flag.exists(), "UPDATING_FLAG must be removed by boot recovery"
