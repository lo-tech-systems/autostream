"""Dial updater result file: extended schema, phases and the staging retry.

Covers autostream_dial_updater.write_update_result (read-modify-write of the
optional phase/tag/attempt keys, file mode) and cmd_apply's download phase and
single in-run retry of a transient staging failure, plus the shared
_is_pre_boot helper in autostream_update_support.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import socket
import stat
import sys
import urllib.error
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "tests"))
sys.path.insert(0, str(REPO_ROOT / "supervisor"))

import autostream_update_support as _asu
from conftest import load_supervisor_script

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="file modes are meaningful on POSIX only"
)


def _parse(path: Path) -> dict:
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        k, _, v = line.partition("=")
        out[k] = v
    return out


def _load(tmp_path: Path):
    mod = load_supervisor_script("autostream_dial_updater", "dial_updater_result_test")
    mod.STATE_DIR = tmp_path
    mod.APMODE_FLAG = tmp_path / "_apmode_absent"
    mod.LOG_PATH = tmp_path / "dial-update.log"
    mod.LOCK_PATH = tmp_path / "dial-update.lock"
    mod.STAGING_DIR = tmp_path / "staging"
    mod.UPDATING_FLAG = tmp_path / "autostream-dial-updating"
    mod.FLOCK_BIN = sys.executable
    (tmp_path / "install-state.env").write_text(
        "AUTOSTREAM_RELEASE_TAG=1.2.0\n", encoding="utf-8"
    )
    return mod


class TestWriteUpdateResult:
    def test_extra_keys_are_written(self, tmp_path):
        mod = _load(tmp_path)
        mod.write_update_result(
            "in_progress", "Downloading", percent=0,
            phase="download", tag="1.3.0", previous_tag="1.2.0",
            attempt=1, max_attempts=4, rolled_back=0,
        )
        env = _parse(tmp_path / "update-result.env")
        assert env["PHASE"] == "download"
        assert env["TAG"] == "1.3.0"
        assert env["PREVIOUS_TAG"] == "1.2.0"
        assert env["ATTEMPT"] == "1"
        assert env["MAX_ATTEMPTS"] == "4"
        assert env["ROLLED_BACK"] == "0"

    def test_later_write_keeps_keys_it_does_not_name(self, tmp_path):
        mod = _load(tmp_path)
        mod.write_update_result(
            "in_progress", "Downloading", phase="download", tag="1.3.0",
            previous_tag="1.2.0", attempt=2, max_attempts=4,
        )
        mod.write_update_result("failure", "Gave up", percent=0, phase="failed")
        env = _parse(tmp_path / "update-result.env")
        assert env["STATUS"] == "failure"
        assert env["PHASE"] == "failed"
        assert (env["TAG"], env["PREVIOUS_TAG"]) == ("1.3.0", "1.2.0")
        assert (env["ATTEMPT"], env["MAX_ATTEMPTS"]) == ("2", "4")

    def test_none_removes_a_key(self, tmp_path):
        mod = _load(tmp_path)
        mod.write_update_result("in_progress", "a", transient_retry=1)
        assert "TRANSIENT_RETRY" in _parse(tmp_path / "update-result.env")
        mod.write_update_result("in_progress", "b", transient_retry=None)
        assert "TRANSIENT_RETRY" not in _parse(tmp_path / "update-result.env")

    def test_unknown_key_is_rejected(self, tmp_path):
        mod = _load(tmp_path)
        with pytest.raises(TypeError):
            mod.write_update_result("in_progress", "x", bogus=1)

    def test_newline_in_message_cannot_inject_a_key(self, tmp_path):
        mod = _load(tmp_path)
        mod.write_update_result("failure", "one\nPHASE=forged", percent=0)
        env = _parse(tmp_path / "update-result.env")
        assert "PHASE" not in env
        assert env["STATUS"] == "failure"

    @posix_only
    def test_file_is_group_readable_and_no_tmp_left(self, tmp_path):
        mod = _load(tmp_path)
        mod.write_update_result("in_progress", "x", phase="download")
        mode = stat.S_IMODE((tmp_path / "update-result.env").stat().st_mode)
        assert mode == 0o644
        assert [p.name for p in tmp_path.glob("update-result.env.tmp.*")] == []


def _fake_resolve(tag="v1.3.0"):
    return lambda channel: (True, tag, "https://example.invalid/t.tgz", None, None)


class _Staging:
    """Drives cmd_apply with staging, scheduling and release lookup stubbed."""

    def __init__(self, mod, tmp_path, effects):
        self.mod = mod
        self.tmp_path = tmp_path
        self.effects = list(effects)
        self.calls = 0
        self.seen = []
        self.sleeps = []

    def _stage(self, *args, **kwargs):
        self.calls += 1
        self.seen.append(_parse(self.tmp_path / "update-result.env"))
        effect = self.effects.pop(0)
        if isinstance(effect, BaseException):
            raise effect
        return effect

    def apply(self):
        mod = self.mod
        with patch.object(mod, "_resolve_dial_release", side_effect=_fake_resolve()), \
             patch.object(mod, "_dial_update_unit_active", return_value=False), \
             patch.object(mod, "_find_systemd_run", return_value="/fake/systemd-run"), \
             patch.object(mod, "stage_release", side_effect=self._stage), \
             patch.object(mod, "schedule_locked_installer", return_value=(0, "", "")), \
             patch.object(mod.time, "sleep", side_effect=self.sleeps.append):
            return mod.cmd_apply()


def _installer(tmp_path):
    return tmp_path / "staging" / "src" / "repo" / "autostream_dial_install.sh"


class TestApplyDownloadPhase:
    def test_apply_writes_download_phase_and_previous_tag_before_staging(self, tmp_path):
        mod = _load(tmp_path)
        stage = _Staging(mod, tmp_path, [_installer(tmp_path)])
        result = stage.apply()
        assert result.get("ok") is True
        before_staging = stage.seen[0]
        assert before_staging["STATUS"] == "in_progress"
        assert before_staging["PHASE"] == "download"
        assert before_staging["PERCENT_COMPLETE"] == "0"
        assert before_staging["MESSAGE"] == "Downloading v1.3.0..."
        assert before_staging["TAG"] == "1.3.0"
        assert before_staging["PREVIOUS_TAG"] == "1.2.0"
        assert before_staging["ATTEMPT"] == "1"
        assert before_staging["MAX_ATTEMPTS"] == "4"
        assert before_staging["ROLLED_BACK"] == "0"
        assert mod.UPDATING_FLAG.exists()

    def test_apply_resets_stale_attempt_state_from_a_previous_run(self, tmp_path):
        mod = _load(tmp_path)
        mod.write_update_result(
            "failure", "old", phase="rolled_back", tag="1.1.0",
            previous_tag="1.0.0", attempt=3, max_attempts=4,
            rolled_back=1, transient_retry=1,
        )
        stage = _Staging(mod, tmp_path, [_installer(tmp_path)])
        stage.apply()
        first = stage.seen[0]
        assert (first["ATTEMPT"], first["ROLLED_BACK"]) == ("1", "0")
        assert "TRANSIENT_RETRY" not in first

    def test_installer_message_after_staging_keeps_the_tag_fields(self, tmp_path):
        mod = _load(tmp_path)
        stage = _Staging(mod, tmp_path, [_installer(tmp_path)])
        stage.apply()
        env = _parse(tmp_path / "update-result.env")
        assert env["STATUS"] == "in_progress"
        assert env["TAG"] == "1.3.0"
        assert env["PREVIOUS_TAG"] == "1.2.0"


TRANSIENT = [
    pytest.param(urllib.error.URLError("unreachable"), id="url_error"),
    pytest.param(socket.timeout("timed out"), id="timeout"),
    pytest.param(ConnectionResetError("reset"), id="connection_reset"),
    pytest.param(urllib.error.HTTPError("u", 503, "unavailable", None, None), id="http_503"),
    pytest.param(urllib.error.HTTPError("u", 429, "slow down", None, None), id="http_429"),
]

DETERMINISTIC = [
    pytest.param(FileNotFoundError("installer missing"), id="missing_installer"),
    pytest.param(urllib.error.HTTPError("u", 404, "gone", None, None), id="http_404"),
    pytest.param(ValueError("bad archive"), id="bad_archive"),
]


class TestApplyStagingRetry:
    @pytest.mark.parametrize("error", TRANSIENT)
    def test_apply_retries_staging_once_on_transient_error(self, tmp_path, error):
        mod = _load(tmp_path)
        stage = _Staging(mod, tmp_path, [error, _installer(tmp_path)])
        result = stage.apply()
        assert result.get("ok") is True
        assert stage.calls == 2
        assert stage.sleeps == [mod.TRANSIENT_RETRY_DELAY_S]
        retry_view = stage.seen[1]
        assert retry_view["STATUS"] == "in_progress"
        assert retry_view["MESSAGE"] == "Download failed, retrying..."
        assert retry_view["TRANSIENT_RETRY"] == "1"
        assert retry_view["TAG"] == "1.3.0"

    @pytest.mark.parametrize("error", DETERMINISTIC)
    def test_apply_does_not_retry_staging_on_deterministic_error(self, tmp_path, error):
        mod = _load(tmp_path)
        stage = _Staging(mod, tmp_path, [error])
        result = stage.apply()
        assert result["ok"] is False
        assert result["error"] == "Release staging failed"
        assert stage.calls == 1
        assert stage.sleeps == []
        env = _parse(tmp_path / "update-result.env")
        assert env["STATUS"] == "failure"
        assert env["PHASE"] == "failed"
        assert not mod.UPDATING_FLAG.exists()

    def test_apply_never_retries_staging_twice(self, tmp_path):
        mod = _load(tmp_path)
        stage = _Staging(mod, tmp_path, [
            urllib.error.URLError("one"), urllib.error.URLError("two"),
            urllib.error.URLError("three"),
        ])
        result = stage.apply()
        assert result["ok"] is False
        assert stage.calls == 2
        assert len(stage.sleeps) == 1
        env = _parse(tmp_path / "update-result.env")
        assert env["STATUS"] == "failure"
        assert env["MESSAGE"] == "Update to 1.3.0 failed during download - 1.2.0 kept"
        assert env["TAG"] == "1.3.0"
        assert not mod.UPDATING_FLAG.exists()


class TestIsPreBootShared:
    def test_is_pre_boot_shared_from_support(self):
        assert callable(_asu._is_pre_boot)

    def test_unparseable_timestamp_counts_as_pre_boot(self):
        assert _asu._is_pre_boot("not a time") is True
        assert _asu._is_pre_boot(None) is True

    def test_timestamp_before_boot_is_pre_boot(self, tmp_path):
        uptime = tmp_path / "uptime"
        uptime.write_text("60.0 100.0\n", encoding="utf-8")
        real_path = _asu.Path

        def fake_path(p):
            return uptime if p == "/proc/uptime" else real_path(p)

        with patch.object(_asu, "Path", side_effect=fake_path):
            assert _asu._is_pre_boot("2000-01-01T00:00:00+00:00") is True
            now = _asu.datetime.now(tz=_asu.timezone.utc).isoformat()
            assert _asu._is_pre_boot(now) is False
