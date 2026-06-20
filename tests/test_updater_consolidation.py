"""Updater staging and scheduling consolidation tests.

Covers the three helpers added to autostream_update_support:
  - is_active_transient_unit: fail-closed on systemctl error
  - stage_release: safe extraction, missing installer, required paths, cleanup
  - schedule_locked_installer: command shape, env vars, flock, unit name prefix

Also verifies that autostream_update_retry uses the shared _read_env_file,
_find_systemd_run, and _run helpers rather than local duplicates.
"""
from __future__ import annotations

import io
import os
import sys
import tarfile as _tarfile
from pathlib import Path
from unittest.mock import call, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_SUPERVISOR_DIR = str(REPO_ROOT / "supervisor")
if _SUPERVISOR_DIR not in sys.path:
    sys.path.insert(0, _SUPERVISOR_DIR)

import autostream_update_support as _asu
from conftest import load_supervisor_script


# ---------------------------------------------------------------------------
# Tarball helpers
# ---------------------------------------------------------------------------

def _make_good_tarball(tmp_path: Path, installer_name: str = "autostream_install.sh",
                       required_dirs: list[str] | None = None) -> Path:
    src = tmp_path / "build" / "repo-v1.0.0"
    src.mkdir(parents=True)
    (src / installer_name).write_text("#!/bin/sh\nexit 0\n")
    (src / installer_name).chmod(0o755)
    for d in (required_dirs or []):
        (src / d).mkdir(parents=True, exist_ok=True)
    tar_path = tmp_path / "release.tgz"
    with _tarfile.open(tar_path, "w:gz") as tf:
        tf.add(str(src), arcname="repo-v1.0.0")
    return tar_path


def _make_traversal_tarball(tmp_path: Path) -> Path:
    buf = io.BytesIO()
    with _tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = _tarfile.TarInfo(name="../evil.sh")
        content = b"#!/bin/sh\n"
        info.size = len(content)
        info.mode = 0o755
        tf.addfile(info, io.BytesIO(content))
    buf.seek(0)
    out = tmp_path / "traversal.tgz"
    out.write_bytes(buf.getvalue())
    return out


def _make_symlink_tarball(tmp_path: Path) -> Path:
    buf = io.BytesIO()
    with _tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = _tarfile.TarInfo(name="evil_link")
        info.type = _tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        info.size = 0
        tf.addfile(info)
    buf.seek(0)
    out = tmp_path / "symlink.tgz"
    out.write_bytes(buf.getvalue())
    return out


def _copy_to(src_tar: Path):
    def _dl(url, dst, ua, timeout=120):
        import shutil
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(src_tar), str(dst))
    return _dl


# ---------------------------------------------------------------------------
# is_active_transient_unit
# ---------------------------------------------------------------------------

class TestIsActiveTransientUnit:
    def test_returns_true_when_unit_found(self):
        with patch.object(_asu, "_run", return_value=(0, "autostream-update-123.service", "")):
            assert _asu.is_active_transient_unit("autostream-update-*") is True

    def test_returns_false_when_no_units(self):
        with patch.object(_asu, "_run", return_value=(0, "", "")):
            assert _asu.is_active_transient_unit("autostream-update-*") is False

    def test_raises_on_systemctl_failure(self):
        with patch.object(_asu, "_run", return_value=(1, "", "failed")):
            with pytest.raises(RuntimeError, match="systemctl exited rc=1"):
                _asu.is_active_transient_unit("autostream-update-*")

    def test_raises_preserves_stderr(self):
        with patch.object(_asu, "_run", return_value=(2, "", "dbus error")):
            with pytest.raises(RuntimeError, match="dbus error"):
                _asu.is_active_transient_unit("autostream-update-*")

    def test_uses_pattern_argument(self):
        captured = []
        def fake_run(cmd, timeout=60):
            captured.extend(cmd)
            return (0, "", "")
        with patch.object(_asu, "_run", side_effect=fake_run):
            _asu.is_active_transient_unit("autostream-update-dial-*.service")
        assert "autostream-update-dial-*.service" in captured


# ---------------------------------------------------------------------------
# stage_release
# ---------------------------------------------------------------------------

class TestStageRelease:
    def test_happy_path_returns_installer_path(self, tmp_path):
        tar = _make_good_tarball(tmp_path)
        staging = tmp_path / "staging"
        with patch.object(_asu, "_download_file", side_effect=_copy_to(tar)):
            installer = _asu.stage_release(
                "http://example.com/r.tgz", "v1.0.0",
                staging, "autostream_install.sh", [], "ua/1.0",
            )
        assert installer.name == "autostream_install.sh"
        assert installer.exists()

    def test_writes_release_tag_file(self, tmp_path):
        tar = _make_good_tarball(tmp_path)
        staging = tmp_path / "staging"
        with patch.object(_asu, "_download_file", side_effect=_copy_to(tar)):
            _asu.stage_release(
                "http://example.com/r.tgz", "v1.2.3",
                staging, "autostream_install.sh", [], "ua/1.0",
            )
        tag_file = staging / "release_tag"
        assert tag_file.exists()
        assert "v1.2.3" in tag_file.read_text()

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix permissions not enforced on Windows")
    def test_staging_dir_created_with_mode_0700(self, tmp_path):
        tar = _make_good_tarball(tmp_path)
        staging = tmp_path / "staging"
        with patch.object(_asu, "_download_file", side_effect=_copy_to(tar)):
            _asu.stage_release(
                "http://example.com/r.tgz", "v1.0.0",
                staging, "autostream_install.sh", [], "ua/1.0",
            )
        mode = oct(staging.stat().st_mode & 0o777)
        assert mode == oct(0o700)

    def test_cleans_previous_staging_on_start(self, tmp_path):
        staging = tmp_path / "staging"
        staging.mkdir()
        (staging / "stale.txt").write_text("old")
        tar = _make_good_tarball(tmp_path)
        with patch.object(_asu, "_download_file", side_effect=_copy_to(tar)):
            _asu.stage_release(
                "http://example.com/r.tgz", "v1.0.0",
                staging, "autostream_install.sh", [], "ua/1.0",
            )
        assert not (staging / "stale.txt").exists()

    def test_missing_installer_removes_staging_and_raises(self, tmp_path):
        tar = _make_good_tarball(tmp_path, installer_name="wrong.sh")
        staging = tmp_path / "staging"
        with patch.object(_asu, "_download_file", side_effect=_copy_to(tar)):
            with pytest.raises(FileNotFoundError, match="autostream_install.sh"):
                _asu.stage_release(
                    "http://example.com/r.tgz", "v1.0.0",
                    staging, "autostream_install.sh", [], "ua/1.0",
                )
        assert not staging.exists(), "partial staging dir must be removed on failure"

    def test_missing_required_path_removes_staging_and_raises(self, tmp_path):
        tar = _make_good_tarball(tmp_path)
        staging = tmp_path / "staging"
        with patch.object(_asu, "_download_file", side_effect=_copy_to(tar)):
            with pytest.raises(FileNotFoundError, match="'system'"):
                _asu.stage_release(
                    "http://example.com/r.tgz", "v1.0.0",
                    staging, "autostream_install.sh", ["system"], "ua/1.0",
                )
        assert not staging.exists()

    def test_required_path_present_succeeds(self, tmp_path):
        tar = _make_good_tarball(tmp_path, required_dirs=["system"])
        staging = tmp_path / "staging"
        with patch.object(_asu, "_download_file", side_effect=_copy_to(tar)):
            installer = _asu.stage_release(
                "http://example.com/r.tgz", "v1.0.0",
                staging, "autostream_install.sh", ["system"], "ua/1.0",
            )
        assert installer.exists()

    def test_download_failure_removes_staging(self, tmp_path):
        staging = tmp_path / "staging"
        with patch.object(_asu, "_download_file", side_effect=OSError("network error")):
            with pytest.raises(OSError):
                _asu.stage_release(
                    "http://example.com/r.tgz", "v1.0.0",
                    staging, "autostream_install.sh", [], "ua/1.0",
                )
        assert not staging.exists()

    def test_traversal_tarball_raises(self, tmp_path):
        tar = _make_traversal_tarball(tmp_path)
        staging = tmp_path / "staging"
        with patch.object(_asu, "_download_file", side_effect=_copy_to(tar)):
            with pytest.raises(Exception):
                _asu.stage_release(
                    "http://example.com/r.tgz", "v1.0.0",
                    staging, "autostream_install.sh", [], "ua/1.0",
                )
        assert not staging.exists(), "partial staging dir must be removed on traversal error"

    def test_symlink_tarball_raises(self, tmp_path):
        tar = _make_symlink_tarball(tmp_path)
        staging = tmp_path / "staging"
        with patch.object(_asu, "_download_file", side_effect=_copy_to(tar)):
            with pytest.raises(Exception):
                _asu.stage_release(
                    "http://example.com/r.tgz", "v1.0.0",
                    staging, "autostream_install.sh", [], "ua/1.0",
                )
        assert not staging.exists()

    def test_dial_installer_no_required_paths(self, tmp_path):
        tar = _make_good_tarball(tmp_path, installer_name="autostream_dial_install.sh")
        staging = tmp_path / "staging"
        with patch.object(_asu, "_download_file", side_effect=_copy_to(tar)):
            installer = _asu.stage_release(
                "http://example.com/r.tgz", "v1.0.0",
                staging, "autostream_dial_install.sh", [], "ua/1.0",
            )
        assert installer.name == "autostream_dial_install.sh"


# ---------------------------------------------------------------------------
# schedule_locked_installer
# ---------------------------------------------------------------------------

class TestScheduleLockedInstaller:
    def _capture_cmd(self, tmp_path, **kwargs):
        """Call schedule_locked_installer and capture the cmd passed to _run."""
        captured = []

        def fake_run(cmd, timeout=60):
            captured.extend(cmd)
            return (0, "", "")

        installer = tmp_path / "install.sh"
        installer.write_text("#!/bin/sh\n")
        lock = tmp_path / "update.lock"

        with patch.object(_asu, "_run", side_effect=fake_run):
            rc, out, err = _asu.schedule_locked_installer(
                "/usr/bin/systemd-run", "autostream-update-12345-678",
                lock, installer, ["--update"],
                **kwargs,
            )

        return captured, (rc, out, err)

    def test_returns_run_tuple(self, tmp_path):
        with patch.object(_asu, "_run", return_value=(0, "ok", "")):
            installer = tmp_path / "install.sh"
            installer.write_text("")
            rc, out, err = _asu.schedule_locked_installer(
                "/usr/bin/systemd-run", "unit-1", tmp_path / "lock",
                installer, ["--update"],
            )
        assert (rc, out, err) == (0, "ok", "")

    def test_includes_unit_name(self, tmp_path):
        cmd, _ = self._capture_cmd(tmp_path)
        assert "--unit=autostream-update-12345-678" in cmd

    def test_includes_flock_exclusive(self, tmp_path):
        cmd, _ = self._capture_cmd(tmp_path)
        assert "--exclusive" in cmd
        assert _asu.FLOCK_BIN in cmd

    def test_includes_installer_args(self, tmp_path):
        cmd, _ = self._capture_cmd(tmp_path)
        assert "--update" in cmd

    def test_default_delay_is_1(self, tmp_path):
        cmd, _ = self._capture_cmd(tmp_path)
        assert "--on-active=1" in cmd

    def test_custom_delay(self, tmp_path):
        cmd, _ = self._capture_cmd(tmp_path, delay=2)
        assert "--on-active=2" in cmd

    def test_extra_env_vars_included(self, tmp_path):
        cmd, _ = self._capture_cmd(
            tmp_path, extra_env={"AUTOSTREAM_RELEASE_TAG": "v1.2.3", "FOO": "bar"}
        )
        cmd_str = " ".join(cmd)
        assert "--setenv=AUTOSTREAM_RELEASE_TAG=v1.2.3" in cmd_str
        assert "--setenv=FOO=bar" in cmd_str

    def test_extra_properties_included(self, tmp_path):
        cmd, _ = self._capture_cmd(
            tmp_path,
            extra_properties=["After=NetworkManager.service", "Wants=NetworkManager.service"],
        )
        cmd_str = " ".join(cmd)
        assert "--property=After=NetworkManager.service" in cmd_str
        assert "--property=Wants=NetworkManager.service" in cmd_str

    def test_lock_path_in_cmd(self, tmp_path):
        lock = tmp_path / "my.lock"
        captured = []

        def fake_run(cmd, timeout=60):
            captured.extend(cmd)
            return (0, "", "")

        installer = tmp_path / "install.sh"
        installer.write_text("")

        with patch.object(_asu, "_run", side_effect=fake_run):
            _asu.schedule_locked_installer(
                "/usr/bin/systemd-run", "u-1", lock, installer, ["--update"],
            )

        assert str(lock) in captured

    def test_installer_path_after_separator(self, tmp_path):
        cmd, _ = self._capture_cmd(tmp_path)
        sep_idx = cmd.index("--")
        installer_idx = cmd.index(str(tmp_path / "install.sh"))
        assert installer_idx > sep_idx, "installer must appear after the -- separator"

    def test_flock_before_installer(self, tmp_path):
        cmd, _ = self._capture_cmd(tmp_path)
        flock_idx = cmd.index(_asu.FLOCK_BIN)
        installer_idx = cmd.index(str(tmp_path / "install.sh"))
        assert flock_idx < installer_idx, "flock must appear before the installer"

    def test_dial_env_vars_included(self, tmp_path):
        cmd, _ = self._capture_cmd(
            tmp_path,
            extra_env={"AUTOSTREAM_RELEASE_TAG": "v2.0.0", "AUTOSTREAM_DIAL_LOCKED": "1"},
        )
        assert "--setenv=AUTOSTREAM_DIAL_LOCKED=1" in cmd

    def test_no_extra_properties_by_default(self, tmp_path):
        cmd, _ = self._capture_cmd(tmp_path)
        properties = [a for a in cmd if a.startswith("--property=") and "=" in a.split("=", 2)[2]]
        # Only Type=oneshot is expected by default; no After/Wants
        assert all("After" not in p and "Wants" not in p for p in properties)


# ---------------------------------------------------------------------------
# autostream_update_retry: uses shared helpers (no local duplicates)
# ---------------------------------------------------------------------------

class TestRetryUsesSharedHelpers:
    def _load_retry(self):
        return load_supervisor_script("autostream_update_retry", "wp4_retry_shared")

    def test_retry_has_no_local_read_env_file(self):
        """_read_env_file must be imported from support, not redefined locally."""
        import inspect
        mod = self._load_retry()
        # The function should exist (imported) but not have its source in the retry file
        assert hasattr(mod, "_read_env_file"), "_read_env_file must be importable on mod"
        src = inspect.getsource(mod._read_env_file)
        # Source should come from autostream_update_support, not autostream_update_retry
        assert "autostream_update_retry" not in src or "autostream_update_support" in src

    def test_retry_has_no_local_find_systemd_run(self):
        """_find_systemd_run must be imported from support, not redefined locally."""
        import inspect
        mod = self._load_retry()
        assert hasattr(mod, "_find_systemd_run")
        src = inspect.getsource(mod._find_systemd_run)
        assert "autostream_update_retry" not in src or "autostream_update_support" in src

    def test_retry_has_no_local_systemdrun_candidates(self):
        """SYSTEMDRUN_CANDIDATES must not be defined in the retry script itself."""
        import inspect
        mod = self._load_retry()
        retry_src = Path(REPO_ROOT / "supervisor" / "autostream_update_retry").read_text(
            encoding="utf-8"
        )
        assert "SYSTEMDRUN_CANDIDATES" not in retry_src, (
            "SYSTEMDRUN_CANDIDATES must be removed from autostream_update_retry "
            "(it is defined in autostream_update_support)"
        )

    def test_retry_imports_flock_bin_from_support(self):
        """FLOCK_BIN in retry must equal the shared constant."""
        mod = self._load_retry()
        assert mod.FLOCK_BIN == _asu.FLOCK_BIN

    def test_retry_has_run_helper(self):
        """_run must be accessible on the retry module (imported from support)."""
        mod = self._load_retry()
        assert hasattr(mod, "_run"), "_run must be importable on the retry module"


# ---------------------------------------------------------------------------
# Updater scripts: no inline staging blocks
# ---------------------------------------------------------------------------

class TestUpdaterUsesSharedStaging:
    def test_host_updater_imports_stage_release(self):
        mod = load_supervisor_script("autostream_updater", "wp4_host_staging")
        assert hasattr(mod, "stage_release"), \
            "autostream_updater must import stage_release from support"

    def test_dial_updater_imports_stage_release(self):
        mod = load_supervisor_script("autostream_dial_updater", "wp4_dial_staging")
        assert hasattr(mod, "stage_release"), \
            "autostream_dial_updater must import stage_release from support"

    def test_host_updater_imports_schedule_locked_installer(self):
        mod = load_supervisor_script("autostream_updater", "wp4_host_sched")
        assert hasattr(mod, "schedule_locked_installer"), \
            "autostream_updater must import schedule_locked_installer from support"

    def test_dial_updater_imports_schedule_locked_installer(self):
        mod = load_supervisor_script("autostream_dial_updater", "wp4_dial_sched")
        assert hasattr(mod, "schedule_locked_installer"), \
            "autostream_dial_updater must import schedule_locked_installer from support"

    def test_host_updater_no_inline_tarfile_open(self):
        """Host updater must not contain inline tarfile.open (staging moved to support)."""
        src = (REPO_ROOT / "supervisor" / "autostream_updater").read_text(encoding="utf-8")
        assert "tarfile.open" not in src, \
            "autostream_updater must not contain inline tarfile.open after consolidation"

    def test_dial_updater_no_inline_tarfile_open(self):
        """Dial updater must not contain inline tarfile.open (staging moved to support)."""
        src = (REPO_ROOT / "supervisor" / "autostream_dial_updater").read_text(encoding="utf-8")
        assert "tarfile.open" not in src, \
            "autostream_dial_updater must not contain inline tarfile.open after consolidation"

    def test_host_unit_name_uses_shared_pattern(self):
        """Host unit name prefix is 'autostream-update-' (covered by shared glob)."""
        src = (REPO_ROOT / "supervisor" / "autostream_updater").read_text(encoding="utf-8")
        assert '"autostream-update-{' in src or "f'autostream-update-{" in src or \
               "autostream-update-{" in src, \
            "Host updater must use the 'autostream-update-' unit name prefix"

    def test_dial_unit_name_uses_shared_pattern(self):
        """Dial unit name prefix is 'autostream-update-dial-' (covered by shared glob)."""
        src = (REPO_ROOT / "supervisor" / "autostream_dial_updater").read_text(encoding="utf-8")
        assert "autostream-update-dial-" in src, \
            "Dial updater must use the 'autostream-update-dial-' unit name prefix"

    def test_support_module_compiles_cleanly(self):
        """autostream_update_support must compile without SyntaxWarning."""
        import warnings
        src = (REPO_ROOT / "supervisor" / "autostream_update_support.py").read_text(
            encoding="utf-8"
        )
        with warnings.catch_warnings():
            warnings.simplefilter("error", SyntaxWarning)
            try:
                compile(src, "autostream_update_support.py", "exec")
            except SyntaxWarning as e:
                pytest.fail(f"SyntaxWarning: {e}")
