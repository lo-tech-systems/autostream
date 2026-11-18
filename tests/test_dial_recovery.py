"""The PIN recovery window and the recovery request's age check.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "dial"))

from dial_recovery import RecoveryWindow


class TestRecoveryWindowStateMachine:
    def _make(self):
        announce_calls = []
        rw = RecoveryWindow(on_announce=lambda add: announce_calls.append(add))
        return rw, announce_calls

    def test_open_sets_active_and_announces_true(self):
        rw, calls = self._make()
        with patch("threading.Timer") as mock_timer_cls:
            mock_timer_cls.return_value = MagicMock()
            rw.open()
        assert rw._active is True
        assert calls == [True]

    def test_expire_clears_active_and_announces_false(self):
        rw, calls = self._make()
        with patch("threading.Timer") as mock_timer_cls:
            mock_timer_cls.return_value = MagicMock()
            rw.open()
        calls.clear()
        rw._expire()
        assert rw._active is False
        assert calls == [False]

    def test_complete_cancels_timer_and_announces_false(self):
        rw, calls = self._make()
        mock_timer = MagicMock()
        with patch("threading.Timer", return_value=mock_timer):
            rw.open()
        calls.clear()
        rw.complete()
        mock_timer.cancel.assert_called_once()
        assert rw._active is False
        assert calls == [False]

    def test_confirm_volume_sets_flag_only_when_active(self):
        rw, _ = self._make()
        rw.confirm_volume()  # not active — should be noop
        assert rw._volume_confirmed is False

        with patch("threading.Timer") as mock_timer_cls:
            mock_timer_cls.return_value = MagicMock()
            rw.open()
        rw.confirm_volume()
        assert rw._volume_confirmed is True

    def test_confirm_volume_noop_if_already_confirmed(self):
        rw, _ = self._make()
        with patch("threading.Timer") as mock_timer_cls:
            mock_timer_cls.return_value = MagicMock()
            rw.open()
        rw.confirm_volume()
        rw.confirm_volume()
        assert rw._volume_confirmed is True

    def test_open_replaces_running_timer(self):
        rw, _ = self._make()
        timer1 = MagicMock()
        timer2 = MagicMock()
        with patch("threading.Timer", side_effect=[timer1, timer2]):
            rw.open()
            rw.open()
        timer1.cancel.assert_not_called()  # open() doesn't cancel previous timer explicitly
        assert rw._timer is timer2

    def test_snapshot_remaining_ms_zero_when_inactive(self):
        rw, _ = self._make()
        snap = rw.snapshot()
        assert snap["recovery_remaining_ms"] == 0

    def test_snapshot_remaining_ms_near_full_window_just_after_open(self):
        rw, _ = self._make()
        with patch("threading.Timer") as mock_timer_cls:
            mock_timer_cls.return_value = MagicMock()
            rw.open()
        snap = rw.snapshot()
        assert 0 < snap["recovery_remaining_ms"] <= 600_000

    def test_snapshot_remaining_ms_decreases_over_time(self):
        rw, _ = self._make()
        with patch("threading.Timer") as mock_timer_cls, \
             patch("time.monotonic", return_value=1000.0):
            mock_timer_cls.return_value = MagicMock()
            rw.open()
        with patch("time.monotonic", return_value=1005.0):  # 5s later
            snap = rw.snapshot()
        assert snap["recovery_remaining_ms"] == 595_000

    def test_snapshot_remaining_ms_clamps_at_zero_past_the_window(self):
        rw, _ = self._make()
        with patch("threading.Timer") as mock_timer_cls, \
             patch("time.monotonic", return_value=1000.0):
            mock_timer_cls.return_value = MagicMock()
            rw.open()
        with patch("time.monotonic", return_value=1000.0 + 3600):  # 1hr later
            snap = rw.snapshot()
        assert snap["recovery_remaining_ms"] == 0

    def test_snapshot_remaining_ms_zero_after_complete(self):
        rw, _ = self._make()
        with patch("threading.Timer") as mock_timer_cls:
            mock_timer_cls.return_value = MagicMock()
            rw.open()
        rw.complete()
        assert rw.snapshot()["recovery_remaining_ms"] == 0


class TestRecoveryRequestWithinWindow:
    def test_fresh_request_within_window_when_synced(self, tmp_path):
        import dial_recovery

        request = tmp_path / "pin_reset.txt"
        request.write_text("")
        sync_marker = tmp_path / "synchronized"
        sync_marker.write_text("")

        assert dial_recovery._recovery_request_within_window(
            request, sync_marker_path=sync_marker
        ) is True

    def test_stale_request_not_within_window_when_synced(self, tmp_path):
        import dial_recovery

        request = tmp_path / "pin_reset.txt"
        request.write_text("")
        old = time.time() - dial_recovery._RECOVERY_REQUEST_MAX_AGE_S - 60
        os.utime(request, (old, old))
        sync_marker = tmp_path / "synchronized"
        sync_marker.write_text("")

        assert dial_recovery._recovery_request_within_window(
            request, sync_marker_path=sync_marker
        ) is False

    def test_unsynced_clock_honours_arm_and_logs_skip(self, tmp_path, caplog):
        """No sync marker at all: the function must poll (via the injected
        sleep, never a real one) up to the timeout and then fail open."""
        import dial_recovery

        request = tmp_path / "pin_reset.txt"
        request.write_text("")
        sync_marker = tmp_path / "never_appears"
        sleeps = []

        with caplog.at_level("WARNING"):
            result = dial_recovery._recovery_request_within_window(
                request, sync_marker_path=sync_marker, sleep=sleeps.append,
            )

        assert result is True
        assert "clock not yet synchronised" in caplog.text
        # Polled via the injected callable — never a real time.sleep — for
        # the full timeout, in fixed intervals.
        assert sleeps == [dial_recovery._TIMESYNC_POLL_INTERVAL_S] * (
            dial_recovery._TIMESYNC_POLL_TIMEOUT_S // dial_recovery._TIMESYNC_POLL_INTERVAL_S
        )

    def test_clock_syncs_mid_poll_then_applies_age_rule(self, tmp_path):
        """If the sync marker appears partway through the poll, the age rule
        is applied rather than falling through to the fail-open path."""
        import dial_recovery

        request = tmp_path / "pin_reset.txt"
        request.write_text("")
        sync_marker = tmp_path / "synchronized"
        calls = []

        def fake_sleep(interval):
            calls.append(interval)
            if len(calls) == 2:
                sync_marker.write_text("")

        result = dial_recovery._recovery_request_within_window(
            request, sync_marker_path=sync_marker, sleep=fake_sleep,
        )

        assert result is True
        assert len(calls) == 2
