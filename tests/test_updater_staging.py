"""Priority 4 — Update staging tests.

Covers cmd_apply for both host (autostream_updater) and dial
(autostream_dial_updater): tarball staging/extraction, AP-mode guard,
unit-active guard, lock contention, missing installer, missing system/,
systemd-run and flock guards, scheduling failures, auto-update gates, and
per-product side-effects (host clears result file; dial writes in_progress
status with canonical schema and creates UPDATING_FLAG; scheduling failure
writes STATUS=failure and removes UPDATING_FLAG).

Dial transient unit names match the pattern autostream-update-dial-<ts>-<pid>
which is covered by the shared autostream-update-*.service active-unit glob.

Uses load_supervisor_script() from conftest to stub fcntl on Windows.
All path constants are redirected to tmp_path after module load.
"""
from __future__ import annotations

import errno
import io
import json
import os
import sys
import tarfile
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, call, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "tests"))

# Use conftest helper
from conftest import load_supervisor_script


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_tarball(
    tmp_path: Path,
    installer_name: str = "autostream_install.sh",
    include_system: bool = True,
) -> Path:
    """Build a minimal release tarball at tmp_path/release.tgz."""
    src = tmp_path / "build" / "myrepo-v1.2.3"
    src.mkdir(parents=True)
    script = src / installer_name
    script.write_text("#!/bin/sh\nexit 0\n")
    script.chmod(0o755)
    if include_system:
        (src / "system").mkdir()
    tar_path = tmp_path / "release.tgz"
    with tarfile.open(tar_path, "w:gz") as tf:
        tf.add(str(src), arcname="myrepo-v1.2.3")
    return tar_path


def _copy_tarball_to(src_tar: Path):
    """Return a _download_file replacement that copies src_tar to dst."""
    def _download(url, dst, ua, timeout=120):
        import shutil
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(src_tar), str(dst))
    return _download


def _load_host(tmp_path: Path) -> ModuleType:
    mod = load_supervisor_script("autostream_updater", "updater_staging_host")
    mod.STAGING_DIR = tmp_path / "staging"
    mod.UPDATE_LOCK_FILE = tmp_path / "update.lock"
    mod.UPDATE_RESULT_FILE = tmp_path / "update-result.env"
    mod.LOG_PATH = tmp_path / "update.log"
    mod.APMODE_FLAG = tmp_path / "_apmode_absent"
    mod.PLAYING_SERVICE = tmp_path / "_playing_absent"
    mod.CONFIG_PATH = tmp_path / "autostream.json"
    return mod


def _load_dial(tmp_path: Path) -> ModuleType:
    mod = load_supervisor_script("autostream_dial_updater", "updater_staging_dial")
    mod.STAGING_DIR = tmp_path / "staging"
    mod.LOCK_PATH = tmp_path / "dial.lock"
    mod.STATE_DIR = tmp_path
    mod.LOG_PATH = tmp_path / "dial-update.log"
    mod.APMODE_FLAG = tmp_path / "_dial_apmode_absent"
    mod.UPDATING_FLAG = tmp_path / "autostream-dial-updating"
    return mod


def _fake_release(tag="v1.2.3", tarball_url="http://example.com/r.tgz"):
    return (True, tag, tarball_url, "http://example.com/releases/v1.2.3", None)


def _no_installed(mod):
    return patch.object(mod, "_read_installed_release_tag", return_value="missing")


def _no_installed_dial(mod):
    return patch.object(mod, "_read_installed_tag", return_value="missing")


def _unit_inactive(mod):
    return patch.object(mod, "_update_unit_active", return_value=False)


def _unit_inactive_dial(mod):
    return patch.object(mod, "_dial_update_unit_active", return_value=False)


def _fake_systemd_run(mod, tmp_path: Path):
    fake_path = str(tmp_path / "systemd-run")
    return patch.object(mod, "_find_systemd_run", return_value=fake_path)


def _run_ok(mod):
    return patch.object(mod, "_run", return_value=(0, "", ""))


def _run_fail(mod):
    return patch.object(mod, "_run", return_value=(1, "", "unit failed"))


def _flock_bin_ok(mod, tmp_path: Path):
    flock_path = str(tmp_path / "flock")
    Path(flock_path).write_text("#!/bin/sh\n")
    old_flock = mod.FLOCK_BIN
    mod.FLOCK_BIN = flock_path
    # Ensure isfile+access checks pass
    return patch("os.access", return_value=True), old_flock


# ---------------------------------------------------------------------------
# Host: AP-mode guard
# ---------------------------------------------------------------------------

class TestHostApModeGuard:
    def test_apmode_flag_present_returns_error(self, tmp_path):
        mod = _load_host(tmp_path)
        mod.APMODE_FLAG = tmp_path / "apmode"
        mod.APMODE_FLAG.touch()
        result = mod.cmd_apply(auto=False)
        assert result["ok"] is False
        assert "AP mode" in result.get("error", "")


# ---------------------------------------------------------------------------
# Host: unit-active guard (pre-lock)
# ---------------------------------------------------------------------------

class TestHostUnitActiveGuard:
    def test_pre_lock_unit_active_returns_error(self, tmp_path):
        mod = _load_host(tmp_path)
        with patch.object(mod, "_update_unit_active", return_value=True):
            result = mod.cmd_apply(auto=False)
        assert result["ok"] is False
        assert "progress" in result.get("error", "").lower()

    def test_unit_check_exception_returns_error(self, tmp_path):
        mod = _load_host(tmp_path)
        with patch.object(mod, "_update_unit_active", side_effect=RuntimeError("systemctl failed")):
            result = mod.cmd_apply(auto=False)
        assert result["ok"] is False
        assert "verify" in result.get("error", "").lower()


# ---------------------------------------------------------------------------
# Host: lock contention
# ---------------------------------------------------------------------------

class TestHostLockContention:
    def test_lock_contention_returns_error(self, tmp_path):
        mod = _load_host(tmp_path)
        exc = OSError(errno.EWOULDBLOCK, "would block")
        with _unit_inactive(mod), \
             patch.object(mod, "_resolve_release", return_value=_fake_release()), \
             _no_installed(mod), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True):
            mod.fcntl.flock.side_effect = exc
            result = mod.cmd_apply(auto=False)
            mod.fcntl.flock.side_effect = None
        assert result["ok"] is False
        assert "progress" in result.get("error", "").lower()


# ---------------------------------------------------------------------------
# Host: systemd-run and flock guards
# ---------------------------------------------------------------------------

class TestHostPrerequisiteGuards:
    def test_systemd_run_not_found_returns_error(self, tmp_path):
        mod = _load_host(tmp_path)
        with _unit_inactive(mod), \
             patch.object(mod, "_resolve_release", return_value=_fake_release()), \
             _no_installed(mod), \
             patch.object(mod, "_find_systemd_run", return_value=None):
            result = mod.cmd_apply(auto=False)
        assert result["ok"] is False
        assert "systemd-run" in result.get("error", "")

    def test_flock_not_found_returns_error(self, tmp_path):
        mod = _load_host(tmp_path)
        with _unit_inactive(mod), \
             patch.object(mod, "_resolve_release", return_value=_fake_release()), \
             _no_installed(mod), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=False):
            result = mod.cmd_apply(auto=False)
        assert result["ok"] is False
        assert "flock" in result.get("error", "")


# ---------------------------------------------------------------------------
# Host: staging failures
# ---------------------------------------------------------------------------

class TestHostStagingFailures:
    def test_missing_installer_returns_staging_error(self, tmp_path):
        mod = _load_host(tmp_path)
        # Tarball without autostream_install.sh
        tar = _make_tarball(tmp_path, installer_name="wrong_installer.sh")
        with _unit_inactive(mod), \
             patch.object(mod, "_resolve_release", return_value=_fake_release()), \
             _no_installed(mod), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(mod, "_download_file", side_effect=_copy_tarball_to(tar)), \
             patch.object(mod, "fcntl") as mk_fcntl, \
             patch.object(mod, "_update_unit_active", return_value=False):
            mk_fcntl.LOCK_EX = 2
            mk_fcntl.LOCK_NB = 4
            mk_fcntl.LOCK_UN = 8
            mk_fcntl.flock.return_value = None
            result = mod.cmd_apply(auto=False)
        assert result["ok"] is False
        assert result.get("error") == "Release staging failed"

    def test_missing_system_dir_returns_staging_error(self, tmp_path):
        mod = _load_host(tmp_path)
        tar = _make_tarball(tmp_path, include_system=False)
        with _unit_inactive(mod), \
             patch.object(mod, "_resolve_release", return_value=_fake_release()), \
             _no_installed(mod), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(mod, "_download_file", side_effect=_copy_tarball_to(tar)), \
             patch.object(mod, "fcntl") as mk_fcntl, \
             patch.object(mod, "_update_unit_active", return_value=False):
            mk_fcntl.LOCK_EX = 2
            mk_fcntl.LOCK_NB = 4
            mk_fcntl.LOCK_UN = 8
            mk_fcntl.flock.return_value = None
            result = mod.cmd_apply(auto=False)
        assert result["ok"] is False
        assert result.get("error") == "Release staging failed"

    def test_download_failure_returns_staging_error(self, tmp_path):
        mod = _load_host(tmp_path)
        with _unit_inactive(mod), \
             patch.object(mod, "_resolve_release", return_value=_fake_release()), \
             _no_installed(mod), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(mod, "_download_file", side_effect=OSError("network timeout")), \
             patch.object(mod, "fcntl") as mk_fcntl, \
             patch.object(mod, "_update_unit_active", return_value=False):
            mk_fcntl.LOCK_EX = 2
            mk_fcntl.LOCK_NB = 4
            mk_fcntl.LOCK_UN = 8
            mk_fcntl.flock.return_value = None
            result = mod.cmd_apply(auto=False)
        assert result["ok"] is False
        assert result.get("error") == "Release staging failed"


# ---------------------------------------------------------------------------
# Host: happy path — staging success
# ---------------------------------------------------------------------------

class TestHostApplySuccess:
    def _run_apply(self, tmp_path, tar_path):
        mod = _load_host(tmp_path)
        with _unit_inactive(mod), \
             patch.object(mod, "_resolve_release", return_value=_fake_release()), \
             _no_installed(mod), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(mod, "_download_file", side_effect=_copy_tarball_to(tar_path)), \
             patch.object(mod, "_run", return_value=(0, "", "")) as mock_run, \
             patch.object(mod, "fcntl") as mk_fcntl, \
             patch.object(mod, "_update_unit_active", return_value=False):
            mk_fcntl.LOCK_EX = 2
            mk_fcntl.LOCK_NB = 4
            mk_fcntl.LOCK_UN = 8
            mk_fcntl.flock.return_value = None
            result = mod.cmd_apply(auto=False)
            return result, mod, mock_run

    def test_success_returns_ok_with_staged_tag(self, tmp_path):
        tar = _make_tarball(tmp_path)
        result, mod, _ = self._run_apply(tmp_path, tar)
        assert result["ok"] is True
        assert result.get("staged_tag") == "1.2.3"

    def test_success_clears_stale_update_result(self, tmp_path):
        tar = _make_tarball(tmp_path)
        # Pre-create a stale result file
        result_file = tmp_path / "update-result.env"
        result_file.write_text("STATUS=success\n")
        result, mod, _ = self._run_apply(tmp_path, tar)
        assert result["ok"] is True
        # File should have been removed
        assert not result_file.exists()

    def test_success_writes_release_tag_file(self, tmp_path):
        tar = _make_tarball(tmp_path)
        result, mod, _ = self._run_apply(tmp_path, tar)
        assert result["ok"] is True
        tag_file = mod.STAGING_DIR / "release_tag"
        assert tag_file.exists()
        assert "v1.2.3" in tag_file.read_text()

    def test_scheduling_failure_returns_error(self, tmp_path):
        mod = _load_host(tmp_path)
        tar = _make_tarball(tmp_path)
        with _unit_inactive(mod), \
             patch.object(mod, "_resolve_release", return_value=_fake_release()), \
             _no_installed(mod), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(mod, "_download_file", side_effect=_copy_tarball_to(tar)), \
             patch.object(mod, "_run", return_value=(1, "", "systemd-run failed")), \
             patch.object(mod, "fcntl") as mk_fcntl, \
             patch.object(mod, "_update_unit_active", return_value=False):
            mk_fcntl.LOCK_EX = 2
            mk_fcntl.LOCK_NB = 4
            mk_fcntl.LOCK_UN = 8
            mk_fcntl.flock.return_value = None
            result = mod.cmd_apply(auto=False)
        assert result["ok"] is False
        assert "schedule" in result.get("error", "").lower()

    def test_systemd_run_cmd_includes_required_args(self, tmp_path):
        tar = _make_tarball(tmp_path)
        result, mod, mock_run = self._run_apply(tmp_path, tar)
        assert result["ok"] is True
        cmd_args = mock_run.call_args[0][0]
        cmd_str = " ".join(cmd_args)
        assert "--update" in cmd_str
        assert "AUTOSTREAM_RELEASE_TAG=v1.2.3" in cmd_str
        assert "--exclusive" in cmd_str


# ---------------------------------------------------------------------------
# Host: auto-update gating
# ---------------------------------------------------------------------------

class TestHostAutoUpdateGate:
    def test_auto_disabled_in_config_skips(self, tmp_path):
        mod = _load_host(tmp_path)
        mod.CONFIG_PATH = tmp_path / "autostream.json"
        mod.CONFIG_PATH.write_text(json.dumps({"updates": {"auto_update": False}}))
        result = mod.cmd_apply(auto=True)
        assert result.get("ok") is True
        assert result.get("skipped") is True
        assert result.get("reason") == "auto_update_disabled"

    def test_auto_playback_active_skips(self, tmp_path):
        mod = _load_host(tmp_path)
        mod.CONFIG_PATH = tmp_path / "autostream.json"
        mod.CONFIG_PATH.write_text(json.dumps({"updates": {"auto_update": True}}))
        mod.PLAYING_SERVICE = tmp_path / "playing.service"
        mod.PLAYING_SERVICE.touch()
        result = mod.cmd_apply(auto=True)
        assert result.get("ok") is True
        assert result.get("skipped") is True
        assert result.get("reason") == "playback_active"


# ---------------------------------------------------------------------------
# Host: version guard (already at latest)
# ---------------------------------------------------------------------------

class TestHostVersionGuard:
    def test_already_at_latest_returns_staged_none(self, tmp_path):
        mod = _load_host(tmp_path)
        with _unit_inactive(mod), \
             patch.object(mod, "_resolve_release", return_value=_fake_release(tag="v1.2.3")), \
             patch.object(mod, "_read_installed_release_tag", return_value="1.2.3"):
            result = mod.cmd_apply(auto=False)
        assert result.get("ok") is True
        assert result.get("staged_tag") is None


# ---------------------------------------------------------------------------
# Dial: AP-mode guard
# ---------------------------------------------------------------------------

class TestDialApModeGuard:
    def test_apmode_flag_present_returns_error(self, tmp_path):
        mod = _load_dial(tmp_path)
        mod.APMODE_FLAG = tmp_path / "dial-apmode"
        mod.APMODE_FLAG.touch()
        result = mod.cmd_apply(auto=False)
        assert result["ok"] is False
        assert "AP mode" in result.get("error", "")


# ---------------------------------------------------------------------------
# Dial: auto-update gating
# ---------------------------------------------------------------------------

class TestDialAutoUpdateGate:
    def test_auto_disabled_in_settings_skips(self, tmp_path):
        mod = _load_dial(tmp_path)
        settings = tmp_path / "dial-settings.json"
        settings.write_text(json.dumps({"auto_update": False}))
        result = mod.cmd_apply(auto=True)
        assert result.get("ok") is True
        # Returns {"ok": True} with no staged_tag when auto_update=False
        assert "staged_tag" not in result

    def test_auto_setting_read_failure_returns_ok_skip(self, tmp_path):
        mod = _load_dial(tmp_path)
        # No dial-settings.json → exception reading → fail-closed, returns {"ok": True}
        result = mod.cmd_apply(auto=True)
        assert result.get("ok") is True
        assert "staged_tag" not in result


# ---------------------------------------------------------------------------
# Dial: scheduling failure writes STATUS=failure and removes UPDATING_FLAG
# ---------------------------------------------------------------------------

class TestDialSchedulingFailure:
    def test_scheduling_failure_writes_failure_status(self, tmp_path):
        """systemd-run failure writes STATUS=failure (canonical schema)."""
        mod = _load_dial(tmp_path)
        tar = _make_tarball(tmp_path, installer_name="autostream_dial_install.sh",
                            include_system=False)
        result_file = tmp_path / "update-result.env"
        with _unit_inactive_dial(mod), \
             patch.object(mod, "_resolve_dial_release", return_value=_fake_release()), \
             _no_installed_dial(mod), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(mod, "_download_file", side_effect=_copy_tarball_to(tar)), \
             patch.object(mod, "_run", return_value=(1, "", "unit fail")), \
             patch.object(mod, "fcntl") as mk_fcntl, \
             patch.object(mod, "_dial_update_unit_active", return_value=False):
            mk_fcntl.LOCK_EX = 2
            mk_fcntl.LOCK_NB = 4
            mk_fcntl.LOCK_UN = 8
            mk_fcntl.flock.return_value = None
            result = mod.cmd_apply(auto=False)
        assert result["ok"] is False
        assert result_file.exists()
        content = result_file.read_text()
        assert "STATUS=failure" in content

    def test_scheduling_failure_removes_updating_flag(self, tmp_path):
        """UPDATING_FLAG created before scheduling must be removed on scheduling failure."""
        mod = _load_dial(tmp_path)
        tar = _make_tarball(tmp_path, installer_name="autostream_dial_install.sh",
                            include_system=False)
        with _unit_inactive_dial(mod), \
             patch.object(mod, "_resolve_dial_release", return_value=_fake_release()), \
             _no_installed_dial(mod), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(mod, "_download_file", side_effect=_copy_tarball_to(tar)), \
             patch.object(mod, "_run", return_value=(1, "", "unit fail")), \
             patch.object(mod, "fcntl") as mk_fcntl, \
             patch.object(mod, "_dial_update_unit_active", return_value=False):
            mk_fcntl.LOCK_EX = 2
            mk_fcntl.LOCK_NB = 4
            mk_fcntl.LOCK_UN = 8
            mk_fcntl.flock.return_value = None
            mod.cmd_apply(auto=False)
        assert not mod.UPDATING_FLAG.exists(), \
            "UPDATING_FLAG must be removed after scheduling failure"


# ---------------------------------------------------------------------------
# Dial: happy path
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Host: path traversal rejected; absolute-path members normalized in-place
# ---------------------------------------------------------------------------

def _make_traversal_tarball(tmp_path: Path) -> Path:
    """Build a tarball whose only member has a path-traversal component."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(name="../injected_evil.sh")
        content = b"#!/bin/sh\nexit 0\n"
        info.size = len(content)
        info.mode = 0o755
        tf.addfile(info, io.BytesIO(content))
    buf.seek(0)
    tar_path = tmp_path / "traversal.tgz"
    tar_path.write_bytes(buf.getvalue())
    return tar_path


def _make_tarball_with_absolute_member(
    tmp_path: Path,
    installer_name: str = "autostream_install.sh",
    include_system: bool = True,
) -> Path:
    """Valid release tarball that also contains an absolute-path extra member.

    The absolute member /myrepo-v1.2.3/absolute/injected.sh is normalised by
    data_filter to myrepo-v1.2.3/absolute/injected.sh — staying inside the
    single top-level directory so staging still succeeds.  Without data_filter
    it would attempt to write to /myrepo-v1.2.3/absolute/ on the root filesystem.
    """
    src = tmp_path / "build_abspath" / "myrepo-v1.2.3"
    src.mkdir(parents=True)
    script = src / installer_name
    script.write_text("#!/bin/sh\nexit 0\n")
    script.chmod(0o755)
    if include_system:
        (src / "system").mkdir()
    tar_path = tmp_path / "abspath_valid.tgz"
    with tarfile.open(tar_path, "w:gz") as tf:
        tf.add(str(src), arcname="myrepo-v1.2.3")
        # Absolute-path member: leading '/' would escape to / on a real system.
        # data_filter strips it, landing safely under myrepo-v1.2.3/.
        info = tarfile.TarInfo(name="/myrepo-v1.2.3/absolute/injected.sh")
        content = b"#!/bin/sh\nexit 0\n"
        info.size = len(content)
        info.mode = 0o755
        tf.addfile(info, io.BytesIO(content))
    return tar_path


def _make_symlink_tarball(tmp_path: Path) -> Path:
    """Build a tarball containing a symlink member pointing outside."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(name="evil_link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        info.size = 0
        tf.addfile(info)
    buf.seek(0)
    tar_path = tmp_path / "symlink.tgz"
    tar_path.write_bytes(buf.getvalue())
    return tar_path


def _make_device_tarball(tmp_path: Path) -> Path:
    """Build a tarball containing a block-device member."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(name="evil_dev")
        info.type = tarfile.BLKTYPE
        info.size = 0
        tf.addfile(info)
    buf.seek(0)
    tar_path = tmp_path / "device.tgz"
    tar_path.write_bytes(buf.getvalue())
    return tar_path


def _with_dial_lock(mod):
    """Context manager that sets up the fcntl mock for the dial updater."""
    @contextmanager
    def _ctx():
        with patch.object(mod, "fcntl") as mk:
            mk.LOCK_EX = 2
            mk.LOCK_NB = 4
            mk.LOCK_UN = 8
            mk.flock.return_value = None
            yield mk
    return _ctx()


def _with_host_lock(mod):
    """Context manager that sets up the fcntl mock and tracks flock calls."""
    @contextmanager
    def _ctx():
        with patch.object(mod, "fcntl") as mk:
            mk.LOCK_EX = 2
            mk.LOCK_NB = 4
            mk.LOCK_UN = 8
            mk.flock.return_value = None
            yield mk
    return _ctx()


class TestHostTraversalRejected:
    def test_traversal_tarball_returns_staging_error(self, tmp_path):
        """A tarball with '../' path traversal must not be staged."""
        mod = _load_host(tmp_path)
        tar = _make_traversal_tarball(tmp_path)
        with _unit_inactive(mod), \
             patch.object(mod, "_resolve_release", return_value=_fake_release()), \
             _no_installed(mod), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(mod, "_download_file", side_effect=_copy_tarball_to(tar)), \
             patch.object(mod, "_update_unit_active", return_value=False), \
             _with_host_lock(mod):
            result = mod.cmd_apply(auto=False)
        assert result["ok"] is False
        assert result.get("error") == "Release staging failed"

    def test_absolute_path_member_normalized_inside_staging(self, tmp_path):
        """data_filter strips the leading '/' from /myrepo-v1.2.3/absolute/injected.sh
        and places it at staging/src/myrepo-v1.2.3/absolute/injected.sh. Staging and
        scheduling both succeed, proving the file is contained inside the staging dir."""
        mod = _load_host(tmp_path)
        tar = _make_tarball_with_absolute_member(tmp_path)
        with _unit_inactive(mod), \
             patch.object(mod, "_resolve_release", return_value=_fake_release()), \
             _no_installed(mod), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(mod, "_download_file", side_effect=_copy_tarball_to(tar)), \
             patch.object(mod, "_update_unit_active", return_value=False), \
             patch.object(mod, "_run", return_value=(0, "", "")), \
             _with_host_lock(mod):
            result = mod.cmd_apply(auto=False)
        assert result["ok"] is True
        normalized = mod.STAGING_DIR / "src" / "myrepo-v1.2.3" / "absolute" / "injected.sh"
        assert normalized.exists(), "absolute member must be extracted inside staging, not at /"

    def test_symlink_member_tarball_returns_staging_error(self, tmp_path):
        """A tarball containing a symlink must not be staged."""
        mod = _load_host(tmp_path)
        tar = _make_symlink_tarball(tmp_path)
        with _unit_inactive(mod), \
             patch.object(mod, "_resolve_release", return_value=_fake_release()), \
             _no_installed(mod), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(mod, "_download_file", side_effect=_copy_tarball_to(tar)), \
             patch.object(mod, "_update_unit_active", return_value=False), \
             _with_host_lock(mod):
            result = mod.cmd_apply(auto=False)
        assert result["ok"] is False
        assert result.get("error") == "Release staging failed"

    def test_device_member_tarball_returns_staging_error(self, tmp_path):
        """A tarball containing a block device must not be staged."""
        mod = _load_host(tmp_path)
        tar = _make_device_tarball(tmp_path)
        with _unit_inactive(mod), \
             patch.object(mod, "_resolve_release", return_value=_fake_release()), \
             _no_installed(mod), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(mod, "_download_file", side_effect=_copy_tarball_to(tar)), \
             patch.object(mod, "_update_unit_active", return_value=False), \
             _with_host_lock(mod):
            result = mod.cmd_apply(auto=False)
        assert result["ok"] is False
        assert result.get("error") == "Release staging failed"


# ---------------------------------------------------------------------------
# Host: post-lock unit-active recheck
# ---------------------------------------------------------------------------

class TestHostPostLockUnitActive:
    def test_post_lock_active_returns_error(self, tmp_path):
        """If the unit becomes active *after* the lock is acquired, refuse."""
        mod = _load_host(tmp_path)
        calls = [0]

        def _unit_check():
            calls[0] += 1
            return calls[0] > 1  # False on first (pre-lock), True on second (post-lock)

        with patch.object(mod, "_update_unit_active", side_effect=_unit_check), \
             patch.object(mod, "_resolve_release", return_value=_fake_release()), \
             _no_installed(mod), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             _with_host_lock(mod):
            result = mod.cmd_apply(auto=False)

        assert result["ok"] is False
        assert "progress" in result.get("error", "").lower()


# ---------------------------------------------------------------------------
# Host: lock release (LOCK_UN + close) on success and every error path
# ---------------------------------------------------------------------------

class TestHostLockRelease:
    def _run_with_tracking(self, mod, tar_path, run_rc=0):
        """Run cmd_apply and return (result, flock_call_args_list)."""
        flock_calls = []

        with _unit_inactive(mod), \
             patch.object(mod, "_resolve_release", return_value=_fake_release()), \
             _no_installed(mod), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(mod, "_download_file", side_effect=_copy_tarball_to(tar_path)), \
             patch.object(mod, "_run", return_value=(run_rc, "", "")), \
             patch.object(mod, "_update_unit_active", return_value=False), \
             patch.object(mod, "fcntl") as mk_fcntl:
            mk_fcntl.LOCK_EX = 2
            mk_fcntl.LOCK_NB = 4
            mk_fcntl.LOCK_UN = 8
            mk_fcntl.flock.side_effect = lambda fd, flags: flock_calls.append(flags)
            result = mod.cmd_apply(auto=False)

        return result, flock_calls

    def test_lock_released_with_LOCK_UN_on_success(self, tmp_path):
        mod = _load_host(tmp_path)
        tar = _make_tarball(tmp_path)
        result, flock_calls = self._run_with_tracking(mod, tar, run_rc=0)
        assert result["ok"] is True
        assert 8 in flock_calls, "LOCK_UN (8) must be called on success"

    def test_lock_released_with_LOCK_UN_on_staging_failure(self, tmp_path):
        mod = _load_host(tmp_path)
        tar = _make_tarball(tmp_path, installer_name="wrong.sh")  # staging fails
        result, flock_calls = self._run_with_tracking(mod, tar, run_rc=0)
        assert result["ok"] is False
        assert 8 in flock_calls, "LOCK_UN (8) must be called even on staging failure"

    def test_lock_released_with_LOCK_UN_on_scheduling_failure(self, tmp_path):
        mod = _load_host(tmp_path)
        tar = _make_tarball(tmp_path)
        result, flock_calls = self._run_with_tracking(mod, tar, run_rc=1)
        assert result["ok"] is False
        assert 8 in flock_calls, "LOCK_UN (8) must be called even on scheduling failure"

    def _run_tracking_close(self, mod, tar_path, run_rc=0):
        """Run cmd_apply tracking os.close() calls."""
        FAKE_FD = 777
        close_calls = []

        with _unit_inactive(mod), \
             patch.object(mod, "_resolve_release", return_value=_fake_release()), \
             _no_installed(mod), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(mod, "_download_file", side_effect=_copy_tarball_to(tar_path)), \
             patch.object(mod, "_run", return_value=(run_rc, "", "")), \
             patch.object(mod, "_update_unit_active", return_value=False), \
             patch.object(mod, "fcntl") as mk_fcntl, \
             patch("os.open", return_value=FAKE_FD), \
             patch("os.close", side_effect=lambda fd: close_calls.append(fd)):
            mk_fcntl.LOCK_EX = 2
            mk_fcntl.LOCK_NB = 4
            mk_fcntl.LOCK_UN = 8
            mk_fcntl.flock.return_value = None
            result = mod.cmd_apply(auto=False)

        return result, FAKE_FD, close_calls

    def test_lock_fd_closed_on_success(self, tmp_path):
        mod = _load_host(tmp_path)
        tar = _make_tarball(tmp_path)
        result, fake_fd, close_calls = self._run_tracking_close(mod, tar, run_rc=0)
        assert result["ok"] is True
        assert fake_fd in close_calls, f"os.close({fake_fd}) must be called on success"

    def test_lock_fd_closed_on_staging_failure(self, tmp_path):
        mod = _load_host(tmp_path)
        tar = _make_tarball(tmp_path, installer_name="wrong.sh")
        result, fake_fd, close_calls = self._run_tracking_close(mod, tar, run_rc=0)
        assert result["ok"] is False
        assert fake_fd in close_calls, f"os.close({fake_fd}) must be called on staging failure"

    def test_lock_fd_closed_on_scheduling_failure(self, tmp_path):
        mod = _load_host(tmp_path)
        tar = _make_tarball(tmp_path)
        result, fake_fd, close_calls = self._run_tracking_close(mod, tar, run_rc=1)
        assert result["ok"] is False
        assert fake_fd in close_calls, f"os.close({fake_fd}) must be called on scheduling failure"


# ---------------------------------------------------------------------------
# Dial: happy path
# ---------------------------------------------------------------------------

class TestDialApplySuccess:
    def test_dial_success_returns_ok_staged_tag(self, tmp_path):
        mod = _load_dial(tmp_path)
        tar = _make_tarball(tmp_path, installer_name="autostream_dial_install.sh",
                            include_system=False)
        with _unit_inactive_dial(mod), \
             patch.object(mod, "_resolve_dial_release", return_value=_fake_release()), \
             _no_installed_dial(mod), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(mod, "_download_file", side_effect=_copy_tarball_to(tar)), \
             patch.object(mod, "_run", return_value=(0, "", "")), \
             patch.object(mod, "fcntl") as mk_fcntl, \
             patch.object(mod, "_dial_update_unit_active", return_value=False):
            mk_fcntl.LOCK_EX = 2
            mk_fcntl.LOCK_NB = 4
            mk_fcntl.LOCK_UN = 8
            mk_fcntl.flock.return_value = None
            result = mod.cmd_apply(auto=False)
        assert result["ok"] is True
        assert result.get("staged_tag") == "1.2.3"


# ---------------------------------------------------------------------------
# Dial: path traversal rejected; absolute-path members normalized in-place
# ---------------------------------------------------------------------------

class TestDialTraversalRejected:
    def _run_dial_staging(self, mod, tar):
        with _unit_inactive_dial(mod), \
             patch.object(mod, "_resolve_dial_release", return_value=_fake_release()), \
             _no_installed_dial(mod), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(mod, "_download_file", side_effect=_copy_tarball_to(tar)), \
             patch.object(mod, "_dial_update_unit_active", return_value=False), \
             _with_dial_lock(mod):
            return mod.cmd_apply(auto=False)

    def test_traversal_tarball_returns_staging_error(self, tmp_path):
        mod = _load_dial(tmp_path)
        tar = _make_traversal_tarball(tmp_path)
        result = self._run_dial_staging(mod, tar)
        assert result["ok"] is False

    def test_absolute_path_member_normalized_inside_staging(self, tmp_path):
        """data_filter strips the leading '/' from /myrepo-v1.2.3/absolute/injected.sh
        and places it at staging/src/myrepo-v1.2.3/absolute/injected.sh. Staging and
        scheduling both succeed, proving the file is contained inside the staging dir."""
        mod = _load_dial(tmp_path)
        tar = _make_tarball_with_absolute_member(
            tmp_path, installer_name="autostream_dial_install.sh", include_system=False
        )
        with _unit_inactive_dial(mod), \
             patch.object(mod, "_resolve_dial_release", return_value=_fake_release()), \
             _no_installed_dial(mod), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(mod, "_download_file", side_effect=_copy_tarball_to(tar)), \
             patch.object(mod, "_dial_update_unit_active", return_value=False), \
             patch.object(mod, "_run", return_value=(0, "", "")), \
             _with_dial_lock(mod):
            result = mod.cmd_apply(auto=False)
        assert result["ok"] is True
        normalized = mod.STAGING_DIR / "src" / "myrepo-v1.2.3" / "absolute" / "injected.sh"
        assert normalized.exists(), "absolute member must be extracted inside staging, not at /"

    def test_symlink_member_tarball_returns_staging_error(self, tmp_path):
        mod = _load_dial(tmp_path)
        tar = _make_symlink_tarball(tmp_path)
        result = self._run_dial_staging(mod, tar)
        assert result["ok"] is False

    def test_device_member_tarball_returns_staging_error(self, tmp_path):
        mod = _load_dial(tmp_path)
        tar = _make_device_tarball(tmp_path)
        result = self._run_dial_staging(mod, tar)
        assert result["ok"] is False


# ---------------------------------------------------------------------------
# Dial: lock release (LOCK_UN + os.close) on success and error paths
# ---------------------------------------------------------------------------

class TestDialLockRelease:
    def _run_tracking_close(self, mod, tar_path, run_rc=0):
        FAKE_FD = 888
        close_calls = []
        flock_calls = []

        with _unit_inactive_dial(mod), \
             patch.object(mod, "_resolve_dial_release", return_value=_fake_release()), \
             _no_installed_dial(mod), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(mod, "_download_file", side_effect=_copy_tarball_to(tar_path)), \
             patch.object(mod, "_run", return_value=(run_rc, "", "")), \
             patch.object(mod, "_dial_update_unit_active", return_value=False), \
             patch.object(mod, "fcntl") as mk_fcntl, \
             patch("os.open", return_value=FAKE_FD), \
             patch("os.close", side_effect=lambda fd: close_calls.append(fd)):
            mk_fcntl.LOCK_EX = 2
            mk_fcntl.LOCK_NB = 4
            mk_fcntl.LOCK_UN = 8
            mk_fcntl.flock.side_effect = lambda fd, flags: flock_calls.append(flags)
            result = mod.cmd_apply(auto=False)

        return result, FAKE_FD, flock_calls, close_calls

    def test_lock_released_with_LOCK_UN_on_success(self, tmp_path):
        mod = _load_dial(tmp_path)
        tar = _make_tarball(tmp_path, installer_name="autostream_dial_install.sh",
                            include_system=False)
        result, _, flock_calls, _ = self._run_tracking_close(mod, tar, run_rc=0)
        assert result["ok"] is True
        assert 8 in flock_calls, "LOCK_UN (8) must be called on dial success"

    def test_lock_released_with_LOCK_UN_on_staging_failure(self, tmp_path):
        mod = _load_dial(tmp_path)
        tar = _make_tarball(tmp_path, installer_name="wrong.sh", include_system=False)
        result, _, flock_calls, _ = self._run_tracking_close(mod, tar, run_rc=0)
        assert result["ok"] is False
        assert 8 in flock_calls, "LOCK_UN (8) must be called even on dial staging failure"

    def test_lock_released_with_LOCK_UN_on_scheduling_failure(self, tmp_path):
        mod = _load_dial(tmp_path)
        tar = _make_tarball(tmp_path, installer_name="autostream_dial_install.sh",
                            include_system=False)
        result, _, flock_calls, _ = self._run_tracking_close(mod, tar, run_rc=1)
        assert result["ok"] is False
        assert 8 in flock_calls, "LOCK_UN (8) must be called even on dial scheduling failure"

    def test_lock_fd_closed_on_success(self, tmp_path):
        mod = _load_dial(tmp_path)
        tar = _make_tarball(tmp_path, installer_name="autostream_dial_install.sh",
                            include_system=False)
        result, fake_fd, _, close_calls = self._run_tracking_close(mod, tar, run_rc=0)
        assert result["ok"] is True
        assert fake_fd in close_calls, f"os.close({fake_fd}) must be called on dial success"

    def test_lock_fd_closed_on_staging_failure(self, tmp_path):
        mod = _load_dial(tmp_path)
        tar = _make_tarball(tmp_path, installer_name="wrong.sh", include_system=False)
        result, fake_fd, _, close_calls = self._run_tracking_close(mod, tar, run_rc=0)
        assert result["ok"] is False
        assert fake_fd in close_calls, f"os.close({fake_fd}) must be called on dial staging failure"

    def test_lock_fd_closed_on_scheduling_failure(self, tmp_path):
        mod = _load_dial(tmp_path)
        tar = _make_tarball(tmp_path, installer_name="autostream_dial_install.sh",
                            include_system=False)
        result, fake_fd, _, close_calls = self._run_tracking_close(mod, tar, run_rc=1)
        assert result["ok"] is False
        assert fake_fd in close_calls, f"os.close({fake_fd}) must be called on dial scheduling failure"


# ---------------------------------------------------------------------------
# Dial: post-lock unit-active recheck
# ---------------------------------------------------------------------------

class TestDialPostLockUnitActive:
    def test_post_lock_active_returns_error(self, tmp_path):
        """If the dial unit becomes active *after* the lock is acquired, refuse."""
        mod = _load_dial(tmp_path)
        calls = [0]

        def _unit_check():
            calls[0] += 1
            return calls[0] > 1  # False on first (pre-lock), True on second (post-lock)

        with patch.object(mod, "_dial_update_unit_active", side_effect=_unit_check), \
             patch.object(mod, "_resolve_dial_release", return_value=_fake_release()), \
             _no_installed_dial(mod), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             _with_dial_lock(mod):
            result = mod.cmd_apply(auto=False)

        assert result["ok"] is False
        assert "progress" in result.get("error", "").lower()


# ---------------------------------------------------------------------------
# Dial: UPDATING_FLAG lifecycle and canonical status schema
# ---------------------------------------------------------------------------

class TestDialUpdatingFlag:
    def _run_dial_apply(self, mod, tar, run_rc=0):
        """Run cmd_apply and return the result."""
        with _unit_inactive_dial(mod), \
             patch.object(mod, "_resolve_dial_release", return_value=_fake_release()), \
             _no_installed_dial(mod), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(mod, "_download_file", side_effect=_copy_tarball_to(tar)), \
             patch.object(mod, "_run", return_value=(run_rc, "", "")), \
             patch.object(mod, "fcntl") as mk_fcntl:
            mk_fcntl.LOCK_EX = 2
            mk_fcntl.LOCK_NB = 4
            mk_fcntl.LOCK_UN = 8
            mk_fcntl.flock.return_value = None
            return mod.cmd_apply(auto=False)

    def test_success_creates_updating_flag(self, tmp_path):
        """UPDATING_FLAG is created before scheduling the installer on success."""
        mod = _load_dial(tmp_path)
        tar = _make_tarball(tmp_path, installer_name="autostream_dial_install.sh",
                            include_system=False)
        created_flags = []

        orig_write = mod.write_update_result
        def tracking_write(status, *a, **kw):
            # On in_progress write: flag should already exist
            if status == "in_progress" and mod.UPDATING_FLAG.exists():
                created_flags.append(True)
            return orig_write(status, *a, **kw)

        with patch.object(mod, "write_update_result", side_effect=tracking_write):
            result = self._run_dial_apply(mod, tar, run_rc=0)
        assert result["ok"] is True
        assert created_flags, "UPDATING_FLAG must exist before STATUS=in_progress is written"

    def test_success_writes_in_progress_status(self, tmp_path):
        """Successful scheduling writes STATUS=in_progress (not 'running')."""
        mod = _load_dial(tmp_path)
        tar = _make_tarball(tmp_path, installer_name="autostream_dial_install.sh",
                            include_system=False)
        self._run_dial_apply(mod, tar, run_rc=0)
        result_text = (tmp_path / "update-result.env").read_text()
        assert "STATUS=in_progress" in result_text

    def test_success_writes_percent_complete(self, tmp_path):
        """Successful scheduling writes PERCENT_COMPLETE=0."""
        mod = _load_dial(tmp_path)
        tar = _make_tarball(tmp_path, installer_name="autostream_dial_install.sh",
                            include_system=False)
        self._run_dial_apply(mod, tar, run_rc=0)
        result_text = (tmp_path / "update-result.env").read_text()
        assert "PERCENT_COMPLETE=0" in result_text

    def test_success_writes_last_run_at(self, tmp_path):
        """Successful scheduling writes a LAST_RUN_AT timestamp."""
        mod = _load_dial(tmp_path)
        tar = _make_tarball(tmp_path, installer_name="autostream_dial_install.sh",
                            include_system=False)
        self._run_dial_apply(mod, tar, run_rc=0)
        result_text = (tmp_path / "update-result.env").read_text()
        assert "LAST_RUN_AT=" in result_text

    def test_success_writes_message(self, tmp_path):
        """Successful scheduling writes a non-empty MESSAGE field."""
        mod = _load_dial(tmp_path)
        tar = _make_tarball(tmp_path, installer_name="autostream_dial_install.sh",
                            include_system=False)
        self._run_dial_apply(mod, tar, run_rc=0)
        result_text = (tmp_path / "update-result.env").read_text()
        assert "MESSAGE=" in result_text

    def test_updating_flag_creation_failure_is_fatal(self, tmp_path):
        """cmd_apply must return ok=False if UPDATING_FLAG cannot be created.

        Regression: previously a flag-creation OSError was logged as a warning
        and installation proceeded silently without the updating-redirect
        behaviour.  This test ensures the code now fails closed.
        """
        mod = _load_dial(tmp_path)
        tar = _make_tarball(tmp_path, installer_name="autostream_dial_install.sh",
                            include_system=False)

        def _touch_raises():
            raise OSError("permission denied")

        # Point UPDATING_FLAG at a path whose parent does not exist so the real
        # .touch() raises FileNotFoundError (a subclass of OSError) — avoids
        # patching Path.touch at instance level, which is read-only on Windows.
        mod.UPDATING_FLAG = tmp_path / "nonexistent_subdir" / "updating"

        with _unit_inactive_dial(mod), \
             patch.object(mod, "_resolve_dial_release", return_value=_fake_release()), \
             _no_installed_dial(mod), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(mod, "_download_file", side_effect=_copy_tarball_to(tar)), \
             patch.object(mod, "fcntl") as mk_fcntl:
            mk_fcntl.LOCK_EX = 2
            mk_fcntl.LOCK_NB = 4
            mk_fcntl.LOCK_UN = 8
            mk_fcntl.flock.return_value = None
            result = mod.cmd_apply(auto=False)

        assert result["ok"] is False
        assert "updating marker" in result.get("error", "").lower() or \
               "flag" in result.get("error", "").lower() or \
               "Failed" in result.get("error", ""), (
            f"Expected flag-creation failure error, got: {result}"
        )

    def test_unexpected_exception_after_flag_removes_flag(self, tmp_path):
        """Any unexpected exception after UPDATING_FLAG creation must remove the flag.

        Regression: previously an exception between flag creation and scheduling
        would leave the flag permanently, causing nginx to redirect indefinitely.
        """
        mod = _load_dial(tmp_path)
        tar = _make_tarball(tmp_path, installer_name="autostream_dial_install.sh",
                            include_system=False)

        with _unit_inactive_dial(mod), \
             patch.object(mod, "_resolve_dial_release", return_value=_fake_release()), \
             _no_installed_dial(mod), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(mod, "_download_file", side_effect=_copy_tarball_to(tar)), \
             patch.object(mod, "fcntl") as mk_fcntl:
            mk_fcntl.LOCK_EX = 2
            mk_fcntl.LOCK_NB = 4
            mk_fcntl.LOCK_UN = 8
            mk_fcntl.flock.return_value = None
            # Raise an unexpected exception in write_update_result after the flag
            # has been created (simulates e.g. disk full on the state file)
            with patch.object(mod, "write_update_result",
                               side_effect=OSError("disk full")):
                result = mod.cmd_apply(auto=False)

        assert result["ok"] is False
        assert not mod.UPDATING_FLAG.exists(), (
            "UPDATING_FLAG must be removed after an unexpected exception "
            "(rollback required so nginx does not redirect indefinitely)"
        )


# ---------------------------------------------------------------------------
# Dial: transient unit name matches shared glob
# ---------------------------------------------------------------------------

class TestDialUnitNaming:
    def test_unit_name_matches_shared_glob_prefix(self, tmp_path):
        """Transient unit name starts with 'autostream-update-dial-' (shared glob prefix)."""
        mod = _load_dial(tmp_path)
        tar = _make_tarball(tmp_path, installer_name="autostream_dial_install.sh",
                            include_system=False)
        captured_cmds = []

        def fake_run(cmd, **kw):
            captured_cmds.append(list(cmd))
            return (0, "", "")

        with _unit_inactive_dial(mod), \
             patch.object(mod, "_resolve_dial_release", return_value=_fake_release()), \
             _no_installed_dial(mod), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(mod, "_download_file",
                          side_effect=_copy_tarball_to(tar)), \
             patch.object(mod, "_run", side_effect=fake_run), \
             patch.object(mod, "fcntl") as mk_fcntl:
            mk_fcntl.LOCK_EX = 2
            mk_fcntl.LOCK_NB = 4
            mk_fcntl.LOCK_UN = 8
            mk_fcntl.flock.return_value = None
            mod.cmd_apply(auto=False)

        # Find the systemd-run call (last captured command)
        unit_args = [a for cmd in captured_cmds for a in cmd if a.startswith("--unit=")]
        assert unit_args, "No --unit= argument found in systemd-run call"
        unit_name = unit_args[-1].split("=", 1)[1]
        assert unit_name.startswith("autostream-update-dial-"), (
            f"Unit name {unit_name!r} must start with 'autostream-update-dial-' "
            "to match the shared autostream-update-*.service active-unit glob"
        )

    def test_active_unit_glob_uses_shared_pattern(self, tmp_path):
        """_dial_update_unit_active() uses the shared autostream-update-*.service glob."""
        mod = load_supervisor_script("autostream_dial_updater", "unit_glob_test")
        import inspect
        src = inspect.getsource(mod._dial_update_unit_active)
        assert "autostream-update-*.service" in src, (
            "_dial_update_unit_active must query the shared autostream-update-*.service glob"
        )
