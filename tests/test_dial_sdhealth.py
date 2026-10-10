"""Tests for dial_sdhealth.py — the dial's own SD card health reader.

Every read goes through a patched autostream_sysutils.sdcard_health_state(),
so this suite runs anywhere; the staleness check uses a real temp file with
a controlled mtime.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
_CORE = str(REPO_ROOT / "core")
for _p in (_DIAL, _CORE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import dial_sdhealth as sh  # noqa: E402


@pytest.fixture(autouse=True)
def _reset():
    sh.reset_for_tests()
    yield
    sh.reset_for_tests()


def _state(**overrides):
    base = {
        "tool_present": True, "timer_enabled": True, "method": "auto",
        "check": "passed", "health_percent": 50,
    }
    base.update(overrides)
    return base


class TestReadHealth:
    def test_off_when_timer_disabled(self):
        with patch.object(sh, "sdcard_health_state", return_value=_state(timer_enabled=False, check="none")):
            view = sh.read_health(now=1.0)
        assert view.status == sh.STATUS_OFF
        assert view.percent is None

    def test_off_when_tool_absent(self):
        with patch.object(sh, "sdcard_health_state", return_value=_state(tool_present=False, timer_enabled=False)):
            view = sh.read_health(now=1.0)
        assert view.status == sh.STATUS_OFF

    def test_unsupported_when_check_failed_and_timer_off(self):
        with patch.object(sh, "sdcard_health_state",
                          return_value=_state(timer_enabled=False, check="failed", health_percent=None)):
            view = sh.read_health(now=1.0)
        assert view.status == sh.STATUS_UNSUPPORTED
        assert view.check == "failed"

    def test_unsupported_when_check_hung_and_timer_on(self):
        with patch.object(sh, "sdcard_health_state",
                          return_value=_state(check="hung", health_percent=None)):
            view = sh.read_health(now=1.0)
        assert view.status == sh.STATUS_UNSUPPORTED
        assert view.check == "hung"

    def test_valid_reading(self):
        with patch.object(sh, "sdcard_health_state", return_value=_state(health_percent=87)), \
             patch.object(sh, "SDCARD_HEALTH_JSON_FILE", Path("/nonexistent/sdcardhealth.json")):
            view = sh.read_health(now=1.0)
        assert view.status == sh.STATUS_VALID
        assert view.percent == 87
        assert view.check == "passed"

    def test_stale_when_file_older_than_threshold(self, tmp_path):
        health_file = tmp_path / "sdcardhealth.json"
        health_file.write_text("{}", encoding="utf-8")
        old = time.time() - (sh.SD_HEALTH_STALE_HOURS + 1) * 3600
        os.utime(health_file, (old, old))
        with patch.object(sh, "sdcard_health_state", return_value=_state(health_percent=40)), \
             patch.object(sh, "SDCARD_HEALTH_JSON_FILE", health_file):
            view = sh.read_health()
        assert view.status == sh.STATUS_STALE
        assert view.percent == 40

    def test_not_stale_when_file_recent(self, tmp_path):
        health_file = tmp_path / "sdcardhealth.json"
        health_file.write_text("{}", encoding="utf-8")
        with patch.object(sh, "sdcard_health_state", return_value=_state(health_percent=40)), \
             patch.object(sh, "SDCARD_HEALTH_JSON_FILE", health_file):
            view = sh.read_health()
        assert view.status == sh.STATUS_VALID

    def test_unavailable_when_check_none(self):
        with patch.object(sh, "sdcard_health_state",
                          return_value=_state(check="none", health_percent=None)):
            view = sh.read_health(now=1.0)
        assert view.status == sh.STATUS_UNAVAILABLE

    def test_unavailable_on_swapped_card(self):
        # sdcard_health_state() itself resets check to "none" for a serial
        # mismatch; this module only sees the result, not the mismatch.
        with patch.object(sh, "sdcard_health_state",
                          return_value=_state(check="none", health_percent=None)):
            view = sh.read_health(now=1.0)
        assert view.status == sh.STATUS_UNAVAILABLE

    def test_never_raises_when_state_read_raises(self):
        with patch.object(sh, "sdcard_health_state", side_effect=RuntimeError("boom")):
            view = sh.read_health(now=5.0)
        assert view == sh.SdHealthView(updated_at=5.0)


class TestIsLow:
    def test_19_raises_from_clean(self):
        view = sh.SdHealthView(status=sh.STATUS_VALID, percent=19)
        assert sh.is_low(view, False) is True

    def test_20_does_not_raise_from_clean(self):
        view = sh.SdHealthView(status=sh.STATUS_VALID, percent=20)
        assert sh.is_low(view, False) is False

    def test_22_holds_when_previously_low(self):
        view = sh.SdHealthView(status=sh.STATUS_VALID, percent=22)
        assert sh.is_low(view, True) is True

    def test_22_does_not_raise_when_not_previously_low(self):
        view = sh.SdHealthView(status=sh.STATUS_VALID, percent=22)
        assert sh.is_low(view, False) is False

    def test_26_clears_even_when_previously_low(self):
        view = sh.SdHealthView(status=sh.STATUS_VALID, percent=26)
        assert sh.is_low(view, True) is False

    def test_stale_keeps_its_percent(self):
        view = sh.SdHealthView(status=sh.STATUS_STALE, percent=15)
        assert sh.is_low(view, False) is True

    def test_off_clears(self):
        view = sh.SdHealthView(status=sh.STATUS_OFF, percent=None)
        assert sh.is_low(view, True) is False

    def test_unsupported_clears(self):
        view = sh.SdHealthView(status=sh.STATUS_UNSUPPORTED, percent=None)
        assert sh.is_low(view, True) is False

    def test_unavailable_clears(self):
        view = sh.SdHealthView(status=sh.STATUS_UNAVAILABLE, percent=None)
        assert sh.is_low(view, True) is False


class TestTick:
    def test_first_call_reads_and_publishes(self):
        with patch.object(sh, "read_health", return_value=sh.SdHealthView(percent=50)) as mock_read:
            sh.tick(now=1.0)
        mock_read.assert_called_once_with(1.0)
        assert sh.latest().percent == 50

    def test_second_call_inside_interval_does_not_read(self):
        with patch.object(sh, "read_health", return_value=sh.SdHealthView(percent=50)) as mock_read:
            sh.tick(now=1.0)
            sh.tick(now=1.0 + sh.SD_HEALTH_POLL_INTERVAL_S / 2)
        mock_read.assert_called_once()

    def test_reads_again_after_the_interval(self):
        with patch.object(sh, "read_health", return_value=sh.SdHealthView(percent=50)) as mock_read:
            sh.tick(now=1.0)
            sh.tick(now=1.0 + sh.SD_HEALTH_POLL_INTERVAL_S)
        assert mock_read.call_count == 2

    def test_raising_callback_is_swallowed(self):
        def bad_callback(view):
            raise RuntimeError("boom")

        sh.start(on_view=bad_callback)
        with patch.object(sh, "read_health", return_value=sh.SdHealthView(percent=50)):
            sh.tick(now=1.0)  # must not raise
        assert sh.latest().percent == 50


class TestRefreshNow:
    def test_publishes_immediately(self):
        with patch.object(sh, "read_health", return_value=sh.SdHealthView(percent=33)):
            sh.refresh_now()
        assert sh.latest().percent == 33

    def test_resets_the_interval_clock(self):
        with patch.object(sh, "read_health", return_value=sh.SdHealthView(percent=1)) as mock_read:
            sh.tick(now=1.0)
            sh.refresh_now()
            sh.tick(now=1.0 + 1.0)  # well inside the interval after refresh
        assert mock_read.call_count == 2  # tick(1.0) + refresh_now(); second tick is a no-op


class TestInfoValue:
    def test_off(self):
        assert sh.info_value(sh.SdHealthView(status=sh.STATUS_OFF)) == "Not monitored"

    def test_unsupported(self):
        assert sh.info_value(sh.SdHealthView(status=sh.STATUS_UNSUPPORTED)) == "Unsupported"

    def test_valid_good(self):
        assert sh.info_value(sh.SdHealthView(status=sh.STATUS_VALID, percent=80)) == "80% Good"

    def test_valid_low(self):
        assert sh.info_value(sh.SdHealthView(status=sh.STATUS_VALID, percent=15)) == "15% Low"

    def test_valid_hysteresis_zone_shows_low(self):
        assert sh.info_value(sh.SdHealthView(status=sh.STATUS_VALID, percent=23)) == "23% Low"

    def test_stale_suffix(self):
        assert sh.info_value(sh.SdHealthView(status=sh.STATUS_STALE, percent=80)) == "80% Good (stale)"

    def test_unavailable_is_dash(self):
        assert sh.info_value(sh.SdHealthView(status=sh.STATUS_UNAVAILABLE)) == "-"
