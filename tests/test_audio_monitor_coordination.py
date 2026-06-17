"""Priority 3 — AudioMonitor coordination tests.

Tests cover _ingest_status() state transitions, apply_allow_capture() lazy
sync, seconds_since_last_activity, _sync_playback_tracker_state() linkage to
the PlaybackTracker, and stop().

AudioMonitor construction patches PersistentNowPlayingCache and
OwntoneMetadataPipePublisher to avoid filesystem/FIFO side-effects.
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


# ---------------------------------------------------------------------------
# EQ band builders
# ---------------------------------------------------------------------------

class TestBuildMonitorEqBands:
    def test_returns_three_bands(self):
        bands = core.build_monitor_eq_bands(1.0, -2.0, 3.0)
        assert len(bands) == 3

    def test_gain_values_forwarded(self):
        bands = core.build_monitor_eq_bands(1.5, -2.5, 3.5)
        assert bands[0]["gain_db"] == pytest.approx(1.5)
        assert bands[1]["gain_db"] == pytest.approx(-2.5)
        assert bands[2]["gain_db"] == pytest.approx(3.5)

    def test_band_types_correct(self):
        bands = core.build_monitor_eq_bands(0.0, 0.0, 0.0)
        assert bands[0]["type"] == "peak"        # 40 Hz
        assert bands[1]["type"] == "low_shelf"   # 100 Hz
        assert bands[2]["type"] == "high_shelf"  # 8 kHz

    def test_frequencies_correct(self):
        bands = core.build_monitor_eq_bands(0.0, 0.0, 0.0)
        assert bands[0]["freq_hz"] == pytest.approx(40.0)
        assert bands[1]["freq_hz"] == pytest.approx(100.0)
        assert bands[2]["freq_hz"] == pytest.approx(8000.0)

    def test_converts_to_float(self):
        bands = core.build_monitor_eq_bands(1, -2, 3)
        for b in bands:
            assert isinstance(b["gain_db"], float)


class TestBuildOutputEqBands:
    def test_returns_six_bands(self):
        bands = core.build_output_eq_bands(1.0, 2.0, 3.0, 4.0, 5.0, 6.0)
        assert len(bands) == 6

    def test_gain_values_forwarded(self):
        vals = [1.0, -1.0, 2.0, -2.0, 3.0, -3.0]
        bands = core.build_output_eq_bands(*vals)
        for b, v in zip(bands, vals):
            assert b["gain_db"] == pytest.approx(v)

    def test_band_types_from_output_peq_table(self):
        bands = core.build_output_eq_bands(0, 0, 0, 0, 0, 0)
        assert bands[0]["type"] == "low_shelf"   # peq1
        assert bands[-1]["type"] == "high_shelf" # peq6

    def test_freq_hz_matches_output_peq_table(self):
        bands = core.build_output_eq_bands(0, 0, 0, 0, 0, 0)
        expected_freqs = [b["freq_hz"] for b in core.OUTPUT_PEQ_BANDS]
        for b, freq in zip(bands, expected_freqs):
            assert b["freq_hz"] == pytest.approx(freq)


# ---------------------------------------------------------------------------
# set_live_input_eq: cache-update-on-success-only, client closure
# ---------------------------------------------------------------------------

from contextlib import contextmanager as _contextmanager


def _fake_connected(client):
    @_contextmanager
    def _cm(*args, **kwargs):
        yield client
    return _cm


class TestSetLiveInputEq:
    def test_returns_false_when_monitor_unavailable(self):
        with patch.object(core, "_connected_monitor", _fake_connected(None)):
            result = core.set_live_input_eq(1, 0.0, 0.0, 0.0)
        assert result is False

    def test_cache_updated_on_success(self):
        mon = _make_monitor(input_index=1)
        mon.eq_40hz_db = 0.0
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.set_eq.return_value = True
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            core.set_live_input_eq(1, 2.5, -1.0, 3.0)
        assert mon.eq_40hz_db == pytest.approx(2.5)
        assert mon.eq_100hz_db == pytest.approx(-1.0)
        assert mon.eq_8khz_db == pytest.approx(3.0)

    def test_cache_not_updated_on_failure(self):
        mon = _make_monitor(input_index=1)
        mon.eq_40hz_db = 1.0
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.set_eq.return_value = False
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            result = core.set_live_input_eq(1, 9.0, 9.0, 9.0)
        assert result is False
        assert mon.eq_40hz_db == pytest.approx(1.0)  # unchanged

    def test_sends_correct_command_bands(self):
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.set_eq.return_value = True
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            core.set_live_input_eq(2, 1.0, 2.0, 3.0)
        mock_client.set_eq.assert_called_once()
        idx, bands = mock_client.set_eq.call_args[0]
        assert idx == 2
        assert len(bands) == 3
        assert bands[0]["gain_db"] == pytest.approx(1.0)

    def test_client_closed_on_success(self):
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.set_eq.return_value = True
        close_calls = []

        @_contextmanager
        def tracking_cm(*args, **kwargs):
            yield mock_client
            close_calls.append(True)

        with patch.object(core, "_connected_monitor", tracking_cm):
            core.set_live_input_eq(1, 0.0, 0.0, 0.0)
        assert close_calls, "context manager must exit (client closed) on success"

    def test_client_closed_on_failure(self):
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.set_eq.return_value = False
        close_calls = []

        @_contextmanager
        def tracking_cm(*args, **kwargs):
            yield mock_client
            close_calls.append(True)

        with patch.object(core, "_connected_monitor", tracking_cm):
            core.set_live_input_eq(1, 0.0, 0.0, 0.0)
        assert close_calls, "context manager must exit (client closed) on failure"


class TestSetLiveInputGain:
    def test_returns_false_when_monitor_unavailable(self):
        with patch.object(core, "_connected_monitor", _fake_connected(None)):
            assert core.set_live_input_gain(1, 3.0) is False

    def test_cache_updated_on_success(self):
        mon = _make_monitor(input_index=2)
        mon.gain_db = 0.0
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.set_gain.return_value = True
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            core.set_live_input_gain(2, 4.5)
        assert mon.gain_db == pytest.approx(4.5)

    def test_cache_not_updated_on_failure(self):
        mon = _make_monitor(input_index=2)
        mon.gain_db = 1.0
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.set_gain.return_value = False
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            core.set_live_input_gain(2, 9.0)
        assert mon.gain_db == pytest.approx(1.0)  # unchanged

    def test_sends_correct_index_and_gain(self):
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.set_gain.return_value = True
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            core.set_live_input_gain(1, -3.5)
        mock_client.set_gain.assert_called_once_with(1, -3.5)


class TestSetLiveOutputEq:
    def test_returns_false_when_unavailable(self):
        with patch.object(core, "_connected_monitor", _fake_connected(None)):
            assert core.set_live_output_eq(0, 0, 0, 0, 0, 0) is False

    def test_sends_six_bands_to_set_output_eq(self):
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.set_output_eq.return_value = True
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            core.set_live_output_eq(1.0, 2.0, 3.0, 4.0, 5.0, 6.0)
        mock_client.set_output_eq.assert_called_once()
        bands = mock_client.set_output_eq.call_args[0][0]
        assert len(bands) == 6

    def test_returns_command_result(self):
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.set_output_eq.return_value = False
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            result = core.set_live_output_eq(0, 0, 0, 0, 0, 0)
        assert result is False


class TestSetLiveOutputGain:
    def test_returns_false_when_unavailable(self):
        with patch.object(core, "_connected_monitor", _fake_connected(None)):
            assert core.set_live_output_gain(2.0) is False

    def test_sends_gain_to_set_output_gain(self):
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.set_output_gain.return_value = True
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            core.set_live_output_gain(3.5)
        mock_client.set_output_gain.assert_called_once_with(pytest.approx(3.5))


class TestSetLiveOutputAutoTrim:
    def test_returns_false_when_unavailable(self):
        with patch.object(core, "_connected_monitor", _fake_connected(None)):
            assert core.set_live_output_auto_trim(True) is False

    def test_sends_enabled_flag(self):
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.set_output_auto_trim.return_value = True
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            core.set_live_output_auto_trim(True)
        mock_client.set_output_auto_trim.assert_called_once_with(True)


# ---------------------------------------------------------------------------
# update_live_silence_seconds
# ---------------------------------------------------------------------------

class TestUpdateLiveSilenceSeconds:
    def test_returns_true_with_no_monitors(self):
        result = core.update_live_silence_seconds(30)
        assert result is True

    def test_invalid_value_returns_false(self):
        result = core.update_live_silence_seconds("not-a-number")
        assert result is False

    def test_calls_configure_input_for_each_monitor(self):
        mon1 = _make_monitor(input_index=0)
        mon2 = _make_monitor(input_index=1)
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.configure_input.return_value = True
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            result = core.update_live_silence_seconds(45)
        assert result is True
        assert mock_client.configure_input.call_count == 2

    def test_returns_false_when_client_unavailable(self):
        mon = _make_monitor(input_index=0)
        with patch.object(core, "_connected_monitor", _fake_connected(None)):
            result = core.update_live_silence_seconds(30)
        assert result is False

    def test_returns_false_when_configure_input_fails(self):
        mon = _make_monitor(input_index=0)
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.configure_input.return_value = False
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            result = core.update_live_silence_seconds(30)
        assert result is False

    def test_updates_monitor_silence_seconds_on_success(self):
        mon = _make_monitor(input_index=0, silence_seconds=5)
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.configure_input.return_value = True
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            core.update_live_silence_seconds(60)
        assert mon.silence_seconds == 60

    def test_silence_seconds_clamped_to_range(self):
        mon = _make_monitor(input_index=0, silence_seconds=5)
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.configure_input.return_value = True
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            core.update_live_silence_seconds(99999)
        assert mon.silence_seconds == 3600  # clamped to max


# ---------------------------------------------------------------------------
# set_live_monitor_log_level / update_live_platform_log_level
# ---------------------------------------------------------------------------

class TestSetLiveMonitorLogLevel:
    def test_returns_false_when_client_unavailable(self):
        with patch.object(core, "_connected_monitor", _fake_connected(None)):
            result = core.set_live_monitor_log_level("info")
        assert result is False

    def test_calls_set_log_level_with_normalized_level(self):
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.set_log_level.return_value = True
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            result = core.set_live_monitor_log_level("WARNING")
        assert result is True
        mock_client.set_log_level.assert_called_once()
        called_level = mock_client.set_log_level.call_args[0][0]
        assert called_level in ("warning", "WARNING", "warn")  # normalized form

    def test_propagates_client_failure(self):
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.set_log_level.return_value = False
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            result = core.set_live_monitor_log_level("debug")
        assert result is False


class TestUpdateLivePlatformLogLevel:
    @pytest.fixture(autouse=True)
    def _restore_logging_state(self):
        import logging as _logging
        root = _logging.getLogger()
        saved_level = root.level
        saved_handler_levels = [h.level for h in root.handlers]
        saved_platform_level = core._live_platform_log_level
        yield
        root.setLevel(saved_level)
        for h, lvl in zip(root.handlers, saved_handler_levels):
            h.setLevel(lvl)
        core._live_platform_log_level = saved_platform_level

    def test_returns_normalized_level_and_monitor_bool(self):
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.set_log_level.return_value = True
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            normalized, monitor_ok = core.update_live_platform_log_level("DEBUG")
        assert isinstance(normalized, str)
        assert monitor_ok is True

    def test_monitor_fail_still_returns_normalized(self):
        with patch.object(core, "_connected_monitor", _fake_connected(None)):
            normalized, monitor_ok = core.update_live_platform_log_level("info")
        assert isinstance(normalized, str)
        assert monitor_ok is False

    def test_python_log_level_updated(self):
        import logging as _logging
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.set_log_level.return_value = True
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            core.update_live_platform_log_level("DEBUG")
        assert _logging.getLogger().level == _logging.DEBUG


# ---------------------------------------------------------------------------
# _auto_select_default_output: default-output fallback
# ---------------------------------------------------------------------------

def _make_output(name="Test Speaker", out_id="1", selected=False):
    out = MagicMock()
    out.name = name
    out.id = out_id
    out.selected = selected
    return out


class TestAutoSelectDefaultOutput:
    def test_returns_false_when_no_base_url(self):
        mon = _make_monitor(owntone_base_url="")
        result = mon._auto_select_default_output(time.time())
        assert result is False

    def test_returns_true_when_output_already_selected(self):
        mon = _make_monitor()
        selected_out = _make_output(selected=True)
        with patch.object(mon, "_get_owntone_outputs", return_value=[selected_out]), \
             patch.object(mon, "_has_any_selected_outputs", return_value=True):
            result = mon._auto_select_default_output(time.time())
        assert result is True

    def test_returns_false_when_outputs_fetch_fails(self):
        mon = _make_monitor()
        with patch.object(mon, "_get_owntone_outputs", return_value=None):
            result = mon._auto_select_default_output(time.time())
        assert result is False

    def test_returns_false_when_no_default_name_configured(self):
        mon = _make_monitor(owntone_output_name="")
        out = _make_output(selected=False)
        with patch.object(mon, "_get_owntone_outputs", return_value=[out]), \
             patch.object(mon, "_has_any_selected_outputs", return_value=False):
            result = mon._auto_select_default_output(time.time())
        assert result is False

    def test_returns_false_when_named_output_not_found(self):
        mon = _make_monitor(owntone_output_name="Missing Speaker")
        out = _make_output(name="Other Speaker", selected=False)
        with patch.object(mon, "_get_owntone_outputs", return_value=[out]), \
             patch.object(mon, "_has_any_selected_outputs", return_value=False):
            result = mon._auto_select_default_output(time.time())
        assert result is False

    def test_calls_update_output_for_default(self):
        mon = _make_monitor(owntone_output_name="Test Speaker", owntone_volume_percent=42)
        out = _make_output(name="Test Speaker", out_id="77", selected=False)
        ok_result = MagicMock()
        ok_result.ok = True
        ok_result.message = ""
        with patch.object(mon, "_get_owntone_outputs", return_value=[out]), \
             patch.object(mon, "_has_any_selected_outputs", return_value=False), \
             patch.object(core, "update_output", return_value=ok_result) as mock_update:
            result = mon._auto_select_default_output(time.time())
        assert result is True
        mock_update.assert_called_once()
        call_kwargs = mock_update.call_args[1]
        assert call_kwargs["enabled"] is True
        assert call_kwargs["volume_percent"] == 42

    def test_returns_false_when_update_output_fails(self):
        mon = _make_monitor(owntone_output_name="Test Speaker")
        out = _make_output(name="Test Speaker", out_id="77", selected=False)
        fail_result = MagicMock()
        fail_result.ok = False
        fail_result.message = "timeout"
        with patch.object(mon, "_get_owntone_outputs", return_value=[out]), \
             patch.object(mon, "_has_any_selected_outputs", return_value=False), \
             patch.object(core, "update_output", return_value=fail_result):
            result = mon._auto_select_default_output(time.time())
        assert result is False

    def test_skips_auto_select_when_output_occupied(self):
        import autostream_output_usage as _ou
        mon = _make_monitor(owntone_output_name="Test Speaker")
        out = _make_output(name="Test Speaker", out_id="77", selected=False)
        ok_result = MagicMock()
        ok_result.ok = True
        usage = MagicMock()
        usage.owner_name = "living-room"
        with patch.object(mon, "_get_owntone_outputs", return_value=[out]), \
             patch.object(mon, "_has_any_selected_outputs", return_value=False), \
             patch.object(_ou, "refresh_now"), \
             patch.object(_ou, "usage_for_output", return_value=usage), \
             patch.object(core, "update_output", return_value=ok_result) as mock_update:
            result = mon._auto_select_default_output(time.time())
        assert result is False
        mock_update.assert_not_called()

    def test_auto_select_proceeds_when_output_not_occupied(self):
        import autostream_output_usage as _ou
        mon = _make_monitor(owntone_output_name="Test Speaker", owntone_volume_percent=30)
        out = _make_output(name="Test Speaker", out_id="77", selected=False)
        ok_result = MagicMock()
        ok_result.ok = True
        with patch.object(mon, "_get_owntone_outputs", return_value=[out]), \
             patch.object(mon, "_has_any_selected_outputs", return_value=False), \
             patch.object(_ou, "refresh_now"), \
             patch.object(_ou, "usage_for_output", return_value=None), \
             patch.object(core, "update_output", return_value=ok_result) as mock_update:
            result = mon._auto_select_default_output(time.time())
        assert result is True
        mock_update.assert_called_once()

    def test_auto_select_fails_open_when_usage_import_fails(self):
        """If autostream_output_usage cannot be imported, auto-select continues."""
        mon = _make_monitor(owntone_output_name="Test Speaker")
        out = _make_output(name="Test Speaker", out_id="77", selected=False)
        ok_result = MagicMock()
        ok_result.ok = True
        import builtins
        real_import = builtins.__import__
        def _block_ou(name, *args, **kwargs):
            if name == "autostream_output_usage":
                raise ImportError("not available")
            return real_import(name, *args, **kwargs)
        with patch.object(mon, "_get_owntone_outputs", return_value=[out]), \
             patch.object(mon, "_has_any_selected_outputs", return_value=False), \
             patch.object(core, "update_output", return_value=ok_result) as mock_update, \
             patch("builtins.__import__", side_effect=_block_ou):
            result = mon._auto_select_default_output(time.time())
        assert result is True
        mock_update.assert_called_once()

    def test_refresh_now_called_before_occupancy_check(self):
        import autostream_output_usage as _ou
        mon = _make_monitor(owntone_output_name="Test Speaker")
        out = _make_output(name="Test Speaker", out_id="77", selected=False)
        call_order = []
        ok_result = MagicMock()
        ok_result.ok = True
        with patch.object(mon, "_get_owntone_outputs", return_value=[out]), \
             patch.object(mon, "_has_any_selected_outputs", return_value=False), \
             patch.object(_ou, "refresh_now",
                          side_effect=lambda *a, **k: call_order.append("refresh")), \
             patch.object(_ou, "usage_for_output",
                          side_effect=lambda *a, **k: call_order.append("check") or None), \
             patch.object(core, "update_output", return_value=ok_result):
            mon._auto_select_default_output(time.time())
        assert call_order == ["refresh", "check"]


# ---------------------------------------------------------------------------
# _on_capture_started / _on_capture_stopped: side-effect ordering
# ---------------------------------------------------------------------------

class TestCaptureStartOrdering:
    def test_started_from_idle_calls_stop_then_retry(self):
        mon = _make_monitor(owntone_base_url="http://localhost:3689")
        order = []
        mock_client = MagicMock(spec=MonitorClient)

        with patch.object(core, "_stop_and_disable_owntone",
                          side_effect=lambda url, reason: order.append("stop")), \
             patch.object(mon, "_maybe_retry_owntone",
                          side_effect=lambda now: order.append("retry")):
            mon._on_capture_started(was_idle=True)

        assert order.index("stop") < order.index("retry"), \
            "_stop_and_disable_owntone must be called before _maybe_retry_owntone"

    def test_started_not_idle_skips_stop(self):
        mon = _make_monitor(owntone_base_url="http://localhost:3689")
        stop_called = []
        with patch.object(core, "_stop_and_disable_owntone",
                          side_effect=lambda url, reason: stop_called.append(True)), \
             patch.object(mon, "_maybe_retry_owntone"):
            mon._on_capture_started(was_idle=False)
        assert not stop_called

    def test_started_resets_ti_state(self):
        mon = _make_monitor()
        mon._ti_inflight = True
        mon._ti_next_attempt = 999.0
        with patch.object(mon, "_maybe_retry_owntone"):
            mon._on_capture_started(was_idle=False)
        assert mon._ti_inflight is False
        assert mon._ti_next_attempt == 0.0


class TestCaptureStopOrdering:
    def test_stopped_calls_publish_end(self):
        mon = _make_monitor(owntone_base_url="http://localhost:3689")
        mock_client = MagicMock(spec=MonitorClient)

        with patch.object(core, "_stop_and_disable_owntone"), \
             patch.object(core, "any_monitor_capturing", return_value=False):
            mon._on_capture_stopped(mock_client)

        mon._nowplaying_publisher.publish_end.assert_called_once()

    def test_stopped_requests_owntone_stop_when_no_other_capturing(self):
        mon = _make_monitor(owntone_base_url="http://localhost:3689")
        mock_client = MagicMock(spec=MonitorClient)
        stop_calls = []

        with patch.object(core, "any_monitor_capturing", return_value=False), \
             patch.object(core, "_stop_and_disable_owntone",
                          side_effect=lambda url, reason: stop_calls.append(url)):
            mon._on_capture_stopped(mock_client)

        assert stop_calls, "OwnTone stop must be requested when no other monitor is capturing"

    def test_stopped_skips_owntone_stop_when_another_is_capturing(self):
        mon = _make_monitor(owntone_base_url="http://localhost:3689")
        mock_client = MagicMock(spec=MonitorClient)
        stop_calls = []

        with patch.object(core, "any_monitor_capturing", return_value=True), \
             patch.object(core, "_stop_and_disable_owntone",
                          side_effect=lambda url, reason: stop_calls.append(url)):
            mon._on_capture_stopped(mock_client)

        assert not stop_calls, "OwnTone stop must be skipped when another monitor is still capturing"


# ---------------------------------------------------------------------------
# _sync_playing_announcement: mDNS zero-to-one and one-to-zero transitions
# ---------------------------------------------------------------------------

class TestSyncPlayingAnnouncement:
    def setup_method(self):
        core._playing_announced = False

    def teardown_method(self):
        core._playing_announced = False

    def test_zero_to_one_writes_avahi_service(self):
        mon = _make_monitor()
        mon.is_capturing = True
        with patch.object(core, "write_avahi_playing_service", return_value=True) as mock_write:
            core._sync_playing_announcement([mon], "v1")
        mock_write.assert_called_once_with("v1")
        assert core._playing_announced is True

    def test_write_failure_leaves_announced_false(self):
        mon = _make_monitor()
        mon.is_capturing = True
        with patch.object(core, "write_avahi_playing_service", return_value=False):
            core._sync_playing_announcement([mon], "v1")
        assert core._playing_announced is False

    def test_one_to_zero_removes_avahi_service(self):
        core._playing_announced = True
        mon = _make_monitor()
        mon.is_capturing = False
        with patch.object(core, "remove_avahi_playing_service", return_value=True) as mock_remove:
            core._sync_playing_announcement([mon], "v1")
        mock_remove.assert_called_once()
        assert core._playing_announced is False

    def test_remove_failure_leaves_announced_true(self):
        core._playing_announced = True
        mon = _make_monitor()
        mon.is_capturing = False
        with patch.object(core, "remove_avahi_playing_service", return_value=False):
            core._sync_playing_announcement([mon], "v1")
        assert core._playing_announced is True

    def test_already_announced_skips_write(self):
        core._playing_announced = True
        mon = _make_monitor()
        mon.is_capturing = True
        with patch.object(core, "write_avahi_playing_service") as mock_write:
            core._sync_playing_announcement([mon], "v1")
        mock_write.assert_not_called()

    def test_not_announced_and_not_capturing_skips_remove(self):
        core._playing_announced = False
        mon = _make_monitor()
        mon.is_capturing = False
        with patch.object(core, "remove_avahi_playing_service") as mock_remove:
            core._sync_playing_announcement([mon], "v1")
        mock_remove.assert_not_called()
