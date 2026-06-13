"""Priority 4 — Update staging tests.

Covers cmd_apply for both host (autostream_updater) and dial
(autostream_dial_updater): tarball staging/extraction, AP-mode guard,
unit-active guard, lock contention, missing installer, missing system/,
systemd-run and flock guards, scheduling failures, auto-update gates, and
per-product side-effects (host clears result file; dial writes running status).

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
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch

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
# Dial: scheduling failure writes STATUS=failed
# ---------------------------------------------------------------------------

class TestDialSchedulingFailure:
    def test_scheduling_failure_writes_failed_status(self, tmp_path):
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
        # Dial writes STATUS=failed to STATE_DIR/update-result.env
        assert result_file.exists()
        content = result_file.read_text()
        assert "failed" in content.lower()


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
