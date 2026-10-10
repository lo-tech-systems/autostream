"""Tests for the cached start buffer served as the dial repeat latency_ms."""
from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

import autostream_start_buffer_cache as cache
from autostream_players import (
    SETTING_START_BUFFER_MS_DEFAULT,
    SETTING_START_BUFFER_MS_MAX,
    SETTING_START_BUFFER_MS_MIN,
)

BASE = "http://localhost:3689"


@pytest.fixture(autouse=True)
def _fresh_cache():
    cache.reset()
    yield
    cache.reset()


def _wait_idle(timeout: float = 2.0) -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        with cache._lock:
            if not cache._refreshing:
                return
        time.sleep(0.005)
    raise AssertionError("refresh did not finish")


def test_default_before_first_read():
    fetch = MagicMock(return_value=None)
    assert cache.current_ms(BASE, fetch=fetch) == SETTING_START_BUFFER_MS_DEFAULT
    _wait_idle()


def test_first_call_starts_refresh_and_next_call_sees_value():
    fetch = MagicMock(return_value=1500)
    assert cache.current_ms(BASE, fetch=fetch) == SETTING_START_BUFFER_MS_DEFAULT
    _wait_idle()
    assert cache.current_ms(BASE, fetch=fetch) == 1500
    assert fetch.call_count == 1


def test_fresh_cache_never_calls_owntone():
    cache.note_saved(1800)
    fetch = MagicMock()
    with patch("autostream_player_service.get_setting") as get_setting:
        for _ in range(20):
            assert cache.current_ms(BASE, fetch=fetch) == 1800
    fetch.assert_not_called()
    get_setting.assert_not_called()


def test_stale_cache_triggers_exactly_one_refresh_under_concurrency():
    cache.note_saved(1800)
    with cache._lock:
        cache._checked_at = time.monotonic() - cache.REFRESH_INTERVAL_S - 1
    gate = threading.Event()
    calls = []

    def slow_fetch(base_url):
        calls.append(base_url)
        gate.wait(2.0)
        return 1200

    results = []

    def request():
        results.append(cache.current_ms(BASE, fetch=slow_fetch))

    threads = [threading.Thread(target=request) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(2.0)
    # Requests returned the cached value while the refresh was still running.
    assert results == [1800] * 16
    gate.set()
    _wait_idle()
    assert len(calls) == 1
    assert cache.current_ms(BASE, fetch=slow_fetch) == 1200


def test_save_updates_the_cache_at_once():
    fetch = MagicMock(return_value=2250)
    cache.current_ms(BASE, fetch=fetch)
    _wait_idle()
    cache.note_saved(900)
    assert cache.current_ms(BASE, fetch=fetch) == 900
    assert fetch.call_count == 1


def test_save_clamps_to_valid_range():
    cache.note_saved(10)
    assert cache.current_ms(None) == SETTING_START_BUFFER_MS_MIN
    cache.note_saved(99999)
    assert cache.current_ms(None) == SETTING_START_BUFFER_MS_MAX


def test_failure_keeps_previous_value():
    cache.note_saved(1700)
    with cache._lock:
        cache._checked_at = time.monotonic() - cache.REFRESH_INTERVAL_S - 1
    fetch = MagicMock(side_effect=RuntimeError("down"))
    assert cache.current_ms(BASE, fetch=fetch) == 1700
    _wait_idle()
    assert cache.current_ms(BASE, fetch=fetch) == 1700
    # The failed attempt is not retried until the interval has passed again.
    assert fetch.call_count == 1


def test_fetch_returning_none_keeps_previous_value():
    cache.note_saved(1700)
    with cache._lock:
        cache._checked_at = time.monotonic() - cache.REFRESH_INTERVAL_S - 1
    cache.current_ms(BASE, fetch=MagicMock(return_value=None))
    _wait_idle()
    assert cache.current_ms(BASE, fetch=MagicMock()) == 1700


def test_no_base_url_means_no_refresh():
    fetch = MagicMock()
    assert cache.current_ms(None, fetch=fetch) == SETTING_START_BUFFER_MS_DEFAULT
    assert cache.current_ms("", fetch=fetch) == SETTING_START_BUFFER_MS_DEFAULT
    fetch.assert_not_called()


def test_fetch_parses_and_clamps_owntone_value():
    ok = MagicMock(ok=True, value=99999)
    with patch("autostream_player_service.get_setting", return_value=ok):
        assert cache._fetch(BASE) == SETTING_START_BUFFER_MS_MAX
    bad = MagicMock(ok=False, value=None)
    with patch("autostream_player_service.get_setting", return_value=bad):
        assert cache._fetch(BASE) is None
    junk = MagicMock(ok=True, value="soon")
    with patch("autostream_player_service.get_setting", return_value=junk):
        assert cache._fetch(BASE) is None


# ---- through the dial status object and the WebUI save ----

def _daemon_block():
    return {
        "enabled": True,
        "armed": False,
        "recording": {"active": False, "seconds": 10.0},
        "replay": {"active": False, "position_seconds": 0.0, "duration_seconds": 0.0},
    }


def test_repeat_object_carries_int_latency_ms_from_cache():
    import autostream_webui_api as api

    cache.note_saved(1950)
    with patch.object(api, "get_repeat_status", return_value=_daemon_block()), \
            patch.object(cache, "_fetch") as fetch:
        obj = api._dial_repeat_object(BASE)
    assert obj["latency_ms"] == 1950
    assert type(obj["latency_ms"]) is int
    fetch.assert_not_called()


def test_repeat_object_without_cache_reports_default():
    import autostream_webui_api as api

    with patch.object(api, "get_repeat_status", return_value=_daemon_block()), \
            patch.object(cache, "_fetch", return_value=None):
        obj = api._dial_repeat_object(BASE)
        _wait_idle()
    assert obj["latency_ms"] == SETTING_START_BUFFER_MS_DEFAULT


def test_webui_save_updates_cache_and_failed_save_does_not():
    import autostream_webui_api as api

    handler = MagicMock()
    handler.wfile = __import__("io").BytesIO()
    ok = MagicMock(ok=True, unsupported=False, restart_required=False, message="")
    with patch.object(api, "save_setting", return_value=ok), \
            patch.object(api, "_config_snapshot",
                         return_value=MagicMock(owntone=MagicMock(base_url=BASE))):
        api.send_owntone_start_buffer_json(handler, MagicMock(), json.dumps({"value": 1000}))
    assert json.loads(handler.wfile.getvalue())["ok"] is True
    assert cache.current_ms(None) == 1000

    handler2 = MagicMock()
    handler2.wfile = __import__("io").BytesIO()
    bad = MagicMock(ok=False, unsupported=False, restart_required=False, message="nope")
    with patch.object(api, "save_setting", return_value=bad), \
            patch.object(api, "_config_snapshot",
                         return_value=MagicMock(owntone=MagicMock(base_url=BASE))):
        api.send_owntone_start_buffer_json(handler2, MagicMock(), json.dumps({"value": 3000}))
    assert json.loads(handler2.wfile.getvalue())["ok"] is False
    assert cache.current_ms(None) == 1000
