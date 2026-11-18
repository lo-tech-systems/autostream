"""tests/test_session_flag.py

The playback-session flag file: an idempotent sync that follows the session,
a start-up clean-up, and the updater skipping an automatic update while the
flag exists.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(_ROOT / "core"), str(_ROOT / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import autostream_session_flag as session_flag
from conftest import load_supervisor_script


@pytest.fixture
def flag(tmp_path):
    path = tmp_path / "pipes" / "session-active"
    path.parent.mkdir()
    with patch.object(session_flag, "SESSION_FLAG_PATH", path):
        session_flag.reset_for_tests()
        yield path
    session_flag.reset_for_tests()


def test_the_flag_follows_the_session(flag):
    assert not flag.exists()
    session_flag.sync(True)
    assert flag.exists()
    session_flag.sync(False)
    assert not flag.exists()


def test_a_repeated_sync_writes_and_removes_once(flag):
    session_flag.sync(True)
    flag.unlink()
    session_flag.sync(True)
    assert not flag.exists()
    session_flag.sync(False)
    session_flag.sync(False)
    assert not flag.exists()


def test_an_idle_sync_with_no_flag_does_nothing(flag):
    with patch.object(Path, "unlink") as unlink:
        session_flag.sync(False)
    unlink.assert_not_called()


def test_a_failed_write_is_retried_by_the_next_sync(flag):
    missing = flag.parent / "gone" / "session-active"
    with patch.object(session_flag, "SESSION_FLAG_PATH", missing):
        session_flag.sync(True)
        assert not missing.exists()
        missing.parent.mkdir()
        session_flag.sync(True)
        assert missing.exists()


def test_the_startup_reset_removes_a_stale_flag(flag):
    flag.touch()
    session_flag.reset_at_startup()
    assert not flag.exists()
    session_flag.sync(True)
    assert flag.exists()


def test_the_startup_reset_with_no_flag_is_quiet(flag):
    session_flag.reset_at_startup()
    assert not flag.exists()


class TestUpdaterReadsTheFlag:
    def _updater(self, tmp_path):
        mod = load_supervisor_script("autostream_updater", f"updater_flag_{abs(hash(str(tmp_path)))}")
        mod.CONFIG_PATH = tmp_path / "autostream.json"
        mod.CONFIG_PATH.write_text('{"updates": {"auto_update": true}}', encoding="utf-8")
        mod.APMODE_FLAG = tmp_path / "_apmode_absent"
        mod.LOG_PATH = tmp_path / "update.log"
        return mod

    def test_an_automatic_update_is_skipped_while_the_flag_exists(self, tmp_path):
        mod = self._updater(tmp_path)
        mod.SESSION_FLAG = tmp_path / "session-active"
        mod.SESSION_FLAG.touch()
        result = mod.cmd_apply(auto=True)
        assert result == {"ok": True, "skipped": True, "reason": "playback_active"}

    def test_the_updater_watches_the_path_the_service_writes(self, tmp_path):
        mod = self._updater(tmp_path)
        written = Path(session_flag.__file__).read_text(encoding="utf-8")
        assert f'Path("{mod.SESSION_FLAG}")' in written


def test_the_installer_removes_the_playing_record_an_earlier_release_left():
    text = (_ROOT / "autostream_install.sh").read_text(encoding="utf-8")
    assert "rm -f /etc/avahi/services/autostream-playing.service" in text
