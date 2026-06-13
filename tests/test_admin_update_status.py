"""Priority 4 — autostream_admin update-status tests.

Covers read_update_status(): missing file, valid statuses, percent clamping,
in_progress stale detection, and read errors.

read_update_status() prints JSON to stdout; tests capture it via capsys.
UPDATE_RESULT_FILE is redirected to tmp_path after module load.
"""
from __future__ import annotations

import json
import sys
from io import StringIO
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "tests"))

from conftest import load_supervisor_script


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_admin(tmp_path: Path) -> ModuleType:
    mod = load_supervisor_script("autostream_admin", "admin_update_status_test")
    mod.UPDATE_RESULT_FILE = tmp_path / "update-result.env"
    mod.STAMP_DIR = tmp_path
    mod._INSTALL_LOG = tmp_path / "autostream_install.log"
    return mod


def _write_result(tmp_path: Path, *, status: str, message: str = "Test",
                  percent: str = "50", last_run_at: str = "") -> None:
    lines = [
        f'STATUS={status}',
        f'MESSAGE={message}',
        f'PERCENT_COMPLETE={percent}',
    ]
    if last_run_at:
        lines.append(f'LAST_RUN_AT={last_run_at}')
    (tmp_path / "update-result.env").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _run_and_parse(mod, capsys=None) -> dict:
    if capsys is not None:
        mod.read_update_status()
        captured = capsys.readouterr()
        return json.loads(captured.out)
    else:
        buf = StringIO()
        with patch("builtins.print", side_effect=lambda s, **_: buf.write(s + "\n")):
            mod.read_update_status()
        return json.loads(buf.getvalue().strip())


# ---------------------------------------------------------------------------
# Missing result file
# ---------------------------------------------------------------------------

class TestMissingResultFile:
    def test_missing_file_returns_ok_with_defaults(self, tmp_path):
        mod = _load_admin(tmp_path)
        data = _run_and_parse(mod)
        assert data["ok"] is True
        assert data["status"] == "unknown"
        assert "No update status" in data["message"]
        assert data["percent"] == 0

    def test_missing_file_returns_empty_log_tail(self, tmp_path):
        mod = _load_admin(tmp_path)
        data = _run_and_parse(mod)
        assert data["log_tail"] == ""


# ---------------------------------------------------------------------------
# Valid result file
# ---------------------------------------------------------------------------

class TestValidResultFile:
    def test_success_status_returned(self, tmp_path):
        mod = _load_admin(tmp_path)
        _write_result(tmp_path, status="success", message="Update complete", percent="100")
        with patch.object(mod, "_read_log_tail", return_value=""):
            data = _run_and_parse(mod)
        assert data["ok"] is True
        assert data["status"] == "success"
        assert data["message"] == "Update complete"
        assert data["percent"] == 100

    def test_failure_status_returned(self, tmp_path):
        mod = _load_admin(tmp_path)
        _write_result(tmp_path, status="failure", message="Update failed", percent="20")
        with patch.object(mod, "_read_log_tail", return_value=""):
            data = _run_and_parse(mod)
        assert data["status"] == "failure"
        assert data["percent"] == 20

    def test_percent_clamped_below_zero(self, tmp_path):
        mod = _load_admin(tmp_path)
        _write_result(tmp_path, status="success", percent="-10")
        with patch.object(mod, "_read_log_tail", return_value=""):
            data = _run_and_parse(mod)
        assert data["percent"] == 0

    def test_percent_clamped_above_100(self, tmp_path):
        mod = _load_admin(tmp_path)
        _write_result(tmp_path, status="success", percent="150")
        with patch.object(mod, "_read_log_tail", return_value=""):
            data = _run_and_parse(mod)
        assert data["percent"] == 100

    def test_non_numeric_percent_defaults_to_zero(self, tmp_path):
        mod = _load_admin(tmp_path)
        _write_result(tmp_path, status="success", percent="bad")
        with patch.object(mod, "_read_log_tail", return_value=""):
            data = _run_and_parse(mod)
        assert data["percent"] == 0

    def test_log_tail_included_in_output(self, tmp_path):
        mod = _load_admin(tmp_path)
        _write_result(tmp_path, status="success")
        with patch.object(mod, "_read_log_tail", return_value="last log line"):
            data = _run_and_parse(mod)
        assert data["log_tail"] == "last log line"

    def test_last_run_at_included(self, tmp_path):
        mod = _load_admin(tmp_path)
        _write_result(tmp_path, status="success", last_run_at="2026-06-01T10:00:00")
        with patch.object(mod, "_read_log_tail", return_value=""):
            data = _run_and_parse(mod)
        assert data["last_run_at"] == "2026-06-01T10:00:00"


# ---------------------------------------------------------------------------
# in_progress: stale detection
# ---------------------------------------------------------------------------

class TestInProgressStale:
    def test_in_progress_not_stale_stale_false(self, tmp_path):
        mod = _load_admin(tmp_path)
        _write_result(tmp_path, status="in_progress", percent="30")
        with patch.object(mod, "_is_stale_in_progress", return_value=False), \
             patch.object(mod, "_read_log_tail", return_value=""):
            data = _run_and_parse(mod)
        assert data["status"] == "in_progress"
        assert data["stale"] is False

    def test_in_progress_stale_stale_true(self, tmp_path):
        mod = _load_admin(tmp_path)
        _write_result(tmp_path, status="in_progress", percent="30")
        with patch.object(mod, "_is_stale_in_progress", return_value=True), \
             patch.object(mod, "_update_unit_active", return_value=False), \
             patch.object(mod, "_read_log_tail", return_value=""):
            data = _run_and_parse(mod)
        assert data["stale"] is True

    def test_stale_and_unit_active_sets_hung(self, tmp_path):
        mod = _load_admin(tmp_path)
        _write_result(tmp_path, status="in_progress", percent="30")
        with patch.object(mod, "_is_stale_in_progress", return_value=True), \
             patch.object(mod, "_update_unit_active", return_value=True), \
             patch.object(mod, "_read_log_tail", return_value=""):
            data = _run_and_parse(mod)
        assert data.get("hung") is True

    def test_non_in_progress_has_no_stale_key(self, tmp_path):
        mod = _load_admin(tmp_path)
        _write_result(tmp_path, status="success")
        with patch.object(mod, "_read_log_tail", return_value=""):
            data = _run_and_parse(mod)
        # stale key only set for in_progress
        assert data.get("stale") is False


# ---------------------------------------------------------------------------
# Read error
# ---------------------------------------------------------------------------

class TestReadError:
    def test_permission_error_returns_ok_false(self, tmp_path):
        mod = _load_admin(tmp_path)
        # Make the result file exist but raise PermissionError on read
        result_file = tmp_path / "update-result.env"
        result_file.write_text("STATUS=success\n")
        with patch.object(mod, "read_env_file", side_effect=PermissionError("denied")):
            data = _run_and_parse(mod)
        assert data["ok"] is False
        assert data["status"] == "error"


# ---------------------------------------------------------------------------
# _is_pre_boot helper (in autostream_update_retry)
# ---------------------------------------------------------------------------

class TestIsPreBoot:
    def test_old_timestamp_is_pre_boot(self):
        from datetime import datetime, timedelta, timezone
        mod = load_supervisor_script("autostream_update_retry", "retry_is_pre_boot_test")
        ts = (datetime.now(tz=timezone.utc) - timedelta(minutes=120)).isoformat()
        with patch("pathlib.Path.read_text", return_value="10.0 3.5\n"):
            result = mod._is_pre_boot(ts)
        assert result is True

    def test_recent_timestamp_not_pre_boot(self):
        from datetime import datetime, timedelta, timezone
        mod = load_supervisor_script("autostream_update_retry", "retry_is_pre_boot_test2")
        ts = (datetime.now(tz=timezone.utc) - timedelta(seconds=5)).isoformat()
        # uptime = 600s (10 min), so boot was 10 min ago; ts 5s ago is post-boot
        with patch("pathlib.Path.read_text", return_value="600.0 3.5\n"):
            result = mod._is_pre_boot(ts)
        assert result is False

    def test_unparseable_timestamp_treated_as_pre_boot(self):
        mod = load_supervisor_script("autostream_update_retry", "retry_is_pre_boot_test3")
        result = mod._is_pre_boot("not-a-timestamp")
        assert result is True
