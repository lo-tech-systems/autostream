"""Priority 3 — AudioMonitor coordination tests.

Tests cover _ingest_status() state transitions, apply_allow_capture() lazy
sync, seconds_since_last_activity, _sync_playback_tracker_state() linkage to
the PlaybackTracker, and stop().

AudioMonitor construction patches PersistentNowPlayingCache and
OwntoneMetadataPipePublisher to avoid filesystem/FIFO side-effects.
VinylRecognizer is already None in this environment (not imported from
autostream_nowplaying), so recognition paths are naturally skipped.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

import autostream_core as core
from autostream_core import AudioMonitor, MonitorClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_monitor(**overrides) -> AudioMonitor:
    """Create an AudioMonitor with patched nowplaying dependencies."""
    defaults = dict(
        input_index=0,
        input_device="hw:0,0",
        silence_threshold_dbfs=-50.0,
        silence_seconds=5,
        fifo_path="/tmp/test.fifo",
        owntone_base_url="http://localhost:3689",
        owntone_output_name="Test Speaker",
        owntone_volume_percent=50,
    )
    defaults.update(overrides)

    with patch("autostream_core.PersistentNowPlayingCache") as mock_cache_cls, \
         patch("autostream_core.OwntoneMetadataPipePublisher") as mock_pub_cls:
        mock_cache_cls.return_value.get_manual_hint.return_value = None
        mock_pub_cls.return_value = MagicMock()
        mon = AudioMonitor(**defaults)

    return mon


def _mock_client() -> MagicMock:
    """Return a mock MonitorClient that records set_allow_capture calls."""
    c = MagicMock(spec=MonitorClient)
    c.set_allow_capture.return_value = True
    return c


def _make_fake_tracker():
    """Return a minimal PlaybackTracker-like mock."""
    t = MagicMock()
    t.on_playback_started.return_value = None
    t.on_playback_stopped.return_value = None
    return t


# ---------------------------------------------------------------------------
# _ingest_status: transition signals
# ---------------------------------------------------------------------------

class TestIngestStatusTransitions:
    def test_silent_inactive_no_transition(self):
        mon = _make_monitor()
        entry = {"level_dbfs": -90.0, "poll_peak_dbfs": -90.0, "silent": True, "capturing": False}
        result = mon._ingest_status(entry)
        assert result == ""

    def test_started_transition(self):
        mon = _make_monitor()
        # Start inactive, then become capturing
        result = mon._ingest_status({"silent": False, "capturing": True})
        assert result == "started"

    def test_stopped_transition(self):
        mon = _make_monitor()
        # Manually set as capturing first
        mon.is_capturing = True
        result = mon._ingest_status({"silent": True, "capturing": False})
        assert result == "stopped"

    def test_no_transition_when_state_unchanged(self):
        mon = _make_monitor()
        mon.is_capturing = True
        result = mon._ingest_status({"silent": False, "capturing": True})
        assert result == ""

    def test_no_transition_idle_to_idle(self):
        mon = _make_monitor()
        mon.is_capturing = False
        result = mon._ingest_status({"silent": True, "capturing": False})
        assert result == ""


# ---------------------------------------------------------------------------
# _ingest_status: field updates
# ---------------------------------------------------------------------------

class TestIngestStatusFields:
    def test_updates_level_dbfs(self):
        mon = _make_monitor()
        mon._ingest_status({"level_dbfs": -12.5})
        assert mon.level_dbfs == -12.5

    def test_updates_poll_peak_dbfs(self):
        mon = _make_monitor()
        mon._ingest_status({"poll_peak_dbfs": -6.0})
        assert mon.poll_peak_dbfs == -6.0

    def test_updates_detected_hz(self):
        mon = _make_monitor()
        mon._ingest_status({"detected_hz": 440.0})
        assert mon.detected_hz == 440.0

    def test_updates_is_silent(self):
        mon = _make_monitor()
        mon._ingest_status({"silent": False})
        assert mon.is_silent is False

    def test_updates_is_capturing(self):
        mon = _make_monitor()
        mon._ingest_status({"capturing": True})
        assert mon.is_capturing is True

    def test_vu_history_dict_stored(self):
        mon = _make_monitor()
        vu = {"rms": [0.1, 0.2, 0.3]}
        mon._ingest_status({"vu_history": vu})
        assert mon.vu_history == vu

    def test_non_dict_vu_history_replaced_with_empty(self):
        mon = _make_monitor()
        mon.vu_history = {"old": "data"}
        mon._ingest_status({"vu_history": [1, 2, 3]})  # list, not dict
        assert mon.vu_history == {}

    def test_missing_fields_use_defaults(self):
        mon = _make_monitor()
        mon._ingest_status({})
        assert mon.level_dbfs == -90.0
        assert mon.poll_peak_dbfs == -90.0
        assert mon.is_silent is True
        assert mon.is_capturing is False


# ---------------------------------------------------------------------------
# _ingest_status: last_active_time tracking
# ---------------------------------------------------------------------------

class TestIngestStatusActivity:
    def test_not_silent_updates_last_active_time(self):
        mon = _make_monitor()
        before = time.time()
        mon._ingest_status({"silent": False})
        assert mon._last_active_time is not None
        assert mon._last_active_time >= before

    def test_silent_does_not_update_last_active_time(self):
        mon = _make_monitor()
        mon._last_active_time = None
        mon._ingest_status({"silent": True})
        assert mon._last_active_time is None


# ---------------------------------------------------------------------------
# seconds_since_last_activity
# ---------------------------------------------------------------------------

class TestSecondsSinceLastActivity:
    def test_returns_inf_before_any_activity(self):
        mon = _make_monitor()
        mon._last_active_time = None
        assert mon.seconds_since_last_activity == float("inf")

    def test_returns_elapsed_after_activity(self):
        mon = _make_monitor()
        mon._last_active_time = time.time() - 5.0
        elapsed = mon.seconds_since_last_activity
        assert 4.5 <= elapsed <= 6.0

    def test_activity_stamp_updated_by_ingest(self):
        mon = _make_monitor()
        assert mon._last_active_time is None
        mon._ingest_status({"silent": False})
        assert mon._last_active_time is not None
        assert mon.seconds_since_last_activity < 1.0


# ---------------------------------------------------------------------------
# apply_allow_capture
# ---------------------------------------------------------------------------

class TestApplyAllowCapture:
    def test_sends_command_when_not_yet_sent(self):
        mon = _make_monitor()
        mon._allow_capture = True
        mon._allow_capture_sent = None
        client = _mock_client()
        mon.apply_allow_capture(client)
        client.set_allow_capture.assert_called_once_with(mon.input_index, True)

    def test_updates_sent_value_on_success(self):
        mon = _make_monitor()
        mon._allow_capture = False
        mon._allow_capture_sent = None
        client = _mock_client()
        mon.apply_allow_capture(client)
        assert mon._allow_capture_sent is False

    def test_no_command_when_value_unchanged(self):
        mon = _make_monitor()
        mon._allow_capture = True
        mon._allow_capture_sent = True
        client = _mock_client()
        mon.apply_allow_capture(client)
        client.set_allow_capture.assert_not_called()

    def test_sends_false_to_disable_capture(self):
        mon = _make_monitor()
        mon._allow_capture = False
        mon._allow_capture_sent = True
        client = _mock_client()
        mon.apply_allow_capture(client)
        client.set_allow_capture.assert_called_once_with(mon.input_index, False)

    def test_does_not_update_sent_when_command_fails(self):
        mon = _make_monitor()
        mon._allow_capture = True
        mon._allow_capture_sent = None
        client = _mock_client()
        client.set_allow_capture.return_value = False
        mon.apply_allow_capture(client)
        # Sent value should still be None because command failed
        assert mon._allow_capture_sent is None

    def test_allow_capture_setter_defers_send(self):
        mon = _make_monitor()
        mon._allow_capture_sent = True
        mon.allow_capture = False   # setter only sets _allow_capture
        assert mon._allow_capture is False
        assert mon._allow_capture_sent is True   # unchanged until apply


# ---------------------------------------------------------------------------
# _sync_playback_tracker_state
# ---------------------------------------------------------------------------

class TestSyncPlaybackTrackerState:
    def _with_tracker(self):
        tracker = _make_fake_tracker()
        # Inject into module-level _playback_tracker
        original = core._playback_tracker
        core._playback_tracker = tracker
        return tracker, original

    def _restore_tracker(self, original):
        core._playback_tracker = original

    def test_no_tracker_sets_inactive(self):
        mon = _make_monitor()
        mon._tracker_playback_active = True
        original = core._playback_tracker
        core._playback_tracker = None
        try:
            mon._sync_playback_tracker_state()
            assert mon._tracker_playback_active is False
        finally:
            core._playback_tracker = original

    def test_starts_tracker_when_capturing_and_audible(self):
        mon = _make_monitor()
        mon.is_capturing = True
        mon.is_silent = False
        mon._tracker_playback_active = False
        tracker, original = self._with_tracker()
        try:
            mon._sync_playback_tracker_state()
            tracker.on_playback_started.assert_called_once_with(mon.input_index)
            assert mon._tracker_playback_active is True
        finally:
            self._restore_tracker(original)

    def test_stops_tracker_when_silent(self):
        mon = _make_monitor()
        mon.is_capturing = True
        mon.is_silent = True
        mon._tracker_playback_active = True
        tracker, original = self._with_tracker()
        try:
            mon._sync_playback_tracker_state()
            tracker.on_playback_stopped.assert_called_once_with(mon.input_index)
            assert mon._tracker_playback_active is False
        finally:
            self._restore_tracker(original)

    def test_no_change_when_state_already_matches(self):
        mon = _make_monitor()
        mon.is_capturing = True
        mon.is_silent = False
        mon._tracker_playback_active = True   # already active
        tracker, original = self._with_tracker()
        try:
            mon._sync_playback_tracker_state()
            tracker.on_playback_started.assert_not_called()
            tracker.on_playback_stopped.assert_not_called()
        finally:
            self._restore_tracker(original)

    def test_stops_tracker_when_not_capturing(self):
        mon = _make_monitor()
        mon.is_capturing = False
        mon.is_silent = False   # audible but not capturing
        mon._tracker_playback_active = True
        tracker, original = self._with_tracker()
        try:
            mon._sync_playback_tracker_state()
            tracker.on_playback_stopped.assert_called_once_with(mon.input_index)
        finally:
            self._restore_tracker(original)


# ---------------------------------------------------------------------------
# stop()
# ---------------------------------------------------------------------------

class TestStop:
    def test_stop_calls_publisher_close(self):
        with patch("autostream_core.PersistentNowPlayingCache") as mock_cache_cls, \
             patch("autostream_core.OwntoneMetadataPipePublisher") as mock_pub_cls:
            mock_cache_cls.return_value.get_manual_hint.return_value = None
            mock_publisher = MagicMock()
            mock_pub_cls.return_value = mock_publisher
            mon = AudioMonitor(
                input_index=1,
                input_device="hw:0,0",
                silence_threshold_dbfs=-50.0,
                silence_seconds=5,
                fifo_path="/tmp/test.fifo",
                owntone_base_url="",
                owntone_output_name="",
                owntone_volume_percent=50,
            )

        mon.stop()
        mock_publisher.close.assert_called_once()

    def test_stop_sets_tracker_inactive(self):
        mon = _make_monitor()
        mon._tracker_playback_active = True
        mon.stop()
        assert mon._tracker_playback_active is False


# ---------------------------------------------------------------------------
# all_monitors registration
# ---------------------------------------------------------------------------

class TestAllMonitors:
    def test_constructor_registers_in_all_monitors(self):
        initial_count = len(core.all_monitors)
        mon = _make_monitor(input_index=7)
        assert mon in core.all_monitors
        assert len(core.all_monitors) == initial_count + 1

    def test_monitors_autouse_fixture_clears_list(self):
        # The conftest autouse fixture clears all_monitors after each test.
        # After registration in test_constructor_registers, the list should be
        # empty at the start of THIS test (fresh test function).
        assert core.all_monitors == []
