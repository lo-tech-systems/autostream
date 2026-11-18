"""tests/test_announce.py

The _autostream-playing._tcp announcement: an idempotent sync, a reconciliation
thread started once, and the clean-up at start-up.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_announce as announce

# The suite replaces this with a no-op for every test; the thread test wants the real one.
_REAL_START = announce._start_playing_reconciliation


@pytest.fixture
def avahi():
    """Fake avahi helpers that succeed, and a fixed appliance id."""
    with patch.object(announce, "write_avahi_playing_service", return_value=True) as write, \
         patch.object(announce, "remove_avahi_playing_service", return_value=True) as remove, \
         patch.object(announce, "get_appliance_id", return_value="appliance-a"):
        yield SimpleHelpers(write, remove)


class SimpleHelpers:
    def __init__(self, write, remove):
        self.write = write
        self.remove = remove


def test_a_sync_writes_once_however_often_it_is_repeated(avahi):
    announce.sync_playing_announcement(True, "v1")
    announce.sync_playing_announcement(True, "v1")
    avahi.write.assert_called_once_with("v1", "appliance-a")
    assert announce._playing_announced is True


def test_a_sync_removes_once_after_a_session_ends(avahi):
    announce.sync_playing_announcement(True, "v1")
    announce.sync_playing_announcement(False, "v1")
    announce.sync_playing_announcement(False, "v1")
    avahi.remove.assert_called_once_with()
    assert announce._playing_announced is False


def test_an_idle_sync_with_nothing_announced_does_nothing(avahi):
    announce.sync_playing_announcement(False, "v1")
    avahi.write.assert_not_called()
    avahi.remove.assert_not_called()


def test_a_failed_write_is_retried_by_the_next_sync(avahi):
    avahi.write.return_value = False
    announce.sync_playing_announcement(True, "v1")
    assert announce._playing_announced is False
    avahi.write.return_value = True
    announce.sync_playing_announcement(True, "v1")
    assert announce._playing_announced is True
    assert avahi.write.call_count == 2


def test_the_reconciliation_thread_is_started_once():
    with patch.object(announce, "_start_playing_reconciliation") as start:
        announce.start_reconciliation_once("v1", lambda: False)
        announce.start_reconciliation_once("v1", lambda: False)
    start.assert_called_once()
    assert announce._reconcile_started is True


def test_the_reconciliation_resyncs_from_the_session_it_is_given(avahi):
    ticks = []

    def fake_sleep(seconds):
        ticks.append(seconds)
        if len(ticks) > 1:
            raise SystemExit

    thread = MagicMock()
    with patch.object(announce.threading, "Thread", thread), \
         patch.object(announce.time, "sleep", fake_sleep):
        _REAL_START("v1", lambda: True)
        body = thread.call_args.kwargs["target"]
        with pytest.raises(SystemExit):
            body()
    avahi.write.assert_called_once_with("v1", "appliance-a")
    assert ticks == [60, 60]
    assert thread.call_args.kwargs["daemon"] is True


def test_the_startup_reset_removes_a_stale_announcement_and_follows_the_file(avahi):
    path = MagicMock()
    path.exists.return_value = True
    with patch.object(announce, "_AVAHI_PLAYING_PATH", path):
        announce.reset_at_startup()
    avahi.remove.assert_called_once_with()
    assert announce._playing_announced is True


def test_set_version_and_reset_for_tests(avahi):
    announce.set_version("v9")
    announce.sync_playing_announcement(True, "v9")
    assert announce._playing_version == "v9"
    announce.reset_for_tests()
    assert announce._playing_version is None
    assert announce._playing_announced is False
    assert announce._reconcile_started is False
