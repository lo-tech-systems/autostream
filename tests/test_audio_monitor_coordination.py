"""Priority 3 — AudioMonitor coordination tests.

Tests cover _ingest_status() state transitions, apply_allow_capture() lazy
sync, seconds_since_last_activity, _sync_playback_tracker_state() linkage to
the PlaybackTracker, and stop().

AudioMonitor construction patches PersistentNowPlayingCache and
OwntoneMetadataPipePublisher to avoid filesystem/FIFO side-effects.
"""
from __future__ import annotations

import logging
import sys
import time
from dataclasses import replace
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

import autostream_core as core
from autostream_core import AudioMonitor, MonitorClient
from autostream_nowplaying import NowPlayingMetadata


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _no_retry_sleep():
    """Live pushes retry with a pause between attempts; tests do not wait."""
    with patch.object(core, "LIVE_PUSH_RETRY_GAP_SECONDS", 0.0):
        yield


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
         patch("autostream_core.get_shared_metadata_publisher") as mock_get_pub:
        mock_cache_cls.return_value.get_manual_hint.return_value = None
        # Fresh MagicMock per call (not a shared return_value): the real
        # get_shared_metadata_publisher() would hand out the SAME instance
        # for the same fifo_path, but most tests using this
        # helper construct independent monitors and don't want that coupling
        # unless they opt in explicitly.
        mock_get_pub.side_effect = lambda path: MagicMock()
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
    t.on_wear_started.return_value = None
    t.on_wear_stopped.return_value = None
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

    def test_track_change_seq_updated(self):
        mon = _make_monitor()
        mon._ingest_status({"track_change_seq": 3})
        assert mon.track_change_seq == 3

    def test_track_change_seq_missing_keeps_zero(self):
        mon = _make_monitor()
        mon._ingest_status({})
        assert mon.track_change_seq == 0

    def test_track_change_seq_negative_ignored(self):
        mon = _make_monitor()
        mon.track_change_seq = 5
        mon._ingest_status({"track_change_seq": -1})
        assert mon.track_change_seq == 5

    def test_track_change_seq_non_int_ignored(self):
        mon = _make_monitor()
        mon.track_change_seq = 7
        mon._ingest_status({"track_change_seq": "bad"})
        assert mon.track_change_seq == 7


# ---------------------------------------------------------------------------
# _ingest_status: track_change_seq baseline on capture start
# ---------------------------------------------------------------------------

class TestIngestStatusTrackChangeBaseline:

    def test_baseline_set_on_started_transition(self):
        mon = _make_monitor()
        mon._ingest_status({"capturing": True, "track_change_seq": 4})
        assert mon._track_change_seq_baseline == 4

    def test_baseline_updated_on_seq_advance_while_capturing(self):
        """Seq advance while capturing fires a track-change event which updates baseline."""
        mon = _make_monitor()
        mon.is_capturing = True
        mon.track_change_seq = 2
        mon._track_change_seq_baseline = 2
        mon._ingest_status({"capturing": True, "track_change_seq": 6})
        assert mon._track_change_seq_baseline == 6  # updated by track-change event

    def test_baseline_not_set_on_stopped_transition(self):
        mon = _make_monitor()
        mon.is_capturing = True
        mon._track_change_seq_baseline = 3
        mon._ingest_status({"capturing": False, "track_change_seq": 5})
        assert mon._track_change_seq_baseline == 3  # unchanged on stop


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
        mon._tracker_wear_active = True
        original = core._playback_tracker
        core._playback_tracker = None
        try:
            mon._sync_playback_tracker_state()
            assert mon._tracker_playback_active is False
            assert mon._tracker_wear_active is False
        finally:
            core._playback_tracker = original

    def test_starts_tracker_when_capturing_and_audible(self):
        mon = _make_monitor()
        mon.is_capturing = True
        mon.is_silent = False
        mon._tracker_playback_active = False
        mon._tracker_wear_active = False
        tracker, original = self._with_tracker()
        try:
            mon._sync_playback_tracker_state()
            tracker.on_playback_started.assert_called_once_with(mon.input_index)
            assert mon._tracker_playback_active is True
            # Real input capture (audible, not silent) drives wear too.
            tracker.on_wear_started.assert_called_once_with(mon.input_index)
            assert mon._tracker_wear_active is True
        finally:
            self._restore_tracker(original)

    def test_stops_tracker_when_silent(self):
        mon = _make_monitor()
        mon.is_capturing = True
        mon.is_silent = True
        mon._tracker_playback_active = True
        mon._tracker_wear_active = True
        tracker, original = self._with_tracker()
        try:
            mon._sync_playback_tracker_state()
            tracker.on_playback_stopped.assert_called_once_with(mon.input_index)
            assert mon._tracker_playback_active is False
            tracker.on_wear_stopped.assert_called_once_with(mon.input_index)
            assert mon._tracker_wear_active is False
        finally:
            self._restore_tracker(original)

    def test_no_change_when_state_already_matches(self):
        mon = _make_monitor()
        mon.is_capturing = True
        mon.is_silent = False
        mon._tracker_playback_active = True   # already active
        mon._tracker_wear_active = True
        tracker, original = self._with_tracker()
        try:
            mon._sync_playback_tracker_state()
            tracker.on_playback_started.assert_not_called()
            tracker.on_playback_stopped.assert_not_called()
            tracker.on_wear_started.assert_not_called()
            tracker.on_wear_stopped.assert_not_called()
        finally:
            self._restore_tracker(original)

    def test_stops_tracker_when_not_capturing(self):
        mon = _make_monitor()
        mon.is_capturing = False
        mon.is_silent = False   # audible but not capturing
        mon._tracker_playback_active = True
        mon._tracker_wear_active = True
        tracker, original = self._with_tracker()
        try:
            mon._sync_playback_tracker_state()
            tracker.on_playback_stopped.assert_called_once_with(mon.input_index)
            tracker.on_wear_stopped.assert_called_once_with(mon.input_index)
        finally:
            self._restore_tracker(original)


# ---------------------------------------------------------------------------
# stop()
# ---------------------------------------------------------------------------

class TestStop:
    def test_stop_releases_shared_publisher(self):
        """stop() releases this monitor's reference to the shared publisher rather than closing it directly -- another monitor on
        the same fifo_path may still be using it. See
        TestSharedMetadataPublisher for the registry's own refcount/close
        behaviour in autostream_nowplaying.py."""
        with patch("autostream_core.PersistentNowPlayingCache") as mock_cache_cls, \
             patch("autostream_core.get_shared_metadata_publisher") as mock_get_pub, \
             patch("autostream_core.release_shared_metadata_publisher") as mock_release:
            mock_cache_cls.return_value.get_manual_hint.return_value = None
            mock_get_pub.side_effect = lambda path: MagicMock()
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

            # release_shared_metadata_publisher is looked up as a
            # module-level name in autostream_core at call time, so the
            # patch must still be active when stop() runs.
            mon.stop()
        mock_release.assert_called_once_with("/tmp/test.fifo")

    def test_stop_sets_tracker_inactive(self):
        mon = _make_monitor()
        mon._tracker_playback_active = True
        mon._tracker_wear_active = True
        mon.stop()
        assert mon._tracker_playback_active is False
        assert mon._tracker_wear_active is False


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
        assert mock_client.configure_input.call_args.kwargs["input_type"] == "line"

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
# update_live_silence_threshold_dbfs
# ---------------------------------------------------------------------------

class TestUpdateLiveSilenceThresholdDbfs:
    def test_returns_true_with_no_matching_monitor(self):
        result = core.update_live_silence_threshold_dbfs(0, -40.0)
        assert result is True

    def test_invalid_value_returns_false(self):
        _make_monitor(input_index=0)
        result = core.update_live_silence_threshold_dbfs(0, "not-a-number")
        assert result is False

    def test_pushes_configure_input_for_matching_monitor_only(self):
        mon0 = _make_monitor(input_index=0, silence_threshold_dbfs=-50.0)
        mon1 = _make_monitor(input_index=1, silence_threshold_dbfs=-50.0)
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.configure_input.return_value = True
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            result = core.update_live_silence_threshold_dbfs(0, -35.0)
        assert result is True
        assert mock_client.configure_input.call_count == 1
        args, _ = mock_client.configure_input.call_args
        assert args[0] == 0
        assert args[2] == -35.0

    def test_returns_false_when_client_unavailable(self):
        _make_monitor(input_index=0)
        with patch.object(core, "_connected_monitor", _fake_connected(None)):
            result = core.update_live_silence_threshold_dbfs(0, -35.0)
        assert result is False

    def test_failed_push_is_retried_then_reported(self):
        _make_monitor(input_index=0)
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.configure_input.return_value = False
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            result = core.update_live_silence_threshold_dbfs(0, -35.0)
        assert result is False
        assert mock_client.configure_input.call_count == 3

    def test_push_failure_still_updates_monitor_threshold(self):
        mon = _make_monitor(input_index=0, silence_threshold_dbfs=-50.0)
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.configure_input.return_value = False
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            core.update_live_silence_threshold_dbfs(0, -35.0)
        assert mon.silence_threshold_dbfs == -35.0

    def test_first_acknowledged_retry_stops_retrying(self):
        _make_monitor(input_index=0)
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.configure_input.side_effect = [False, True]
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            result = core.update_live_silence_threshold_dbfs(0, -35.0)
        assert result is True
        assert mock_client.configure_input.call_count == 2

    def test_each_attempt_opens_a_fresh_connection(self):
        mon = _make_monitor(input_index=0)
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.configure_input.return_value = False
        entered = []

        @_contextmanager
        def _counting(*args, **kwargs):
            entered.append(1)
            yield mock_client

        with patch.object(core, "_connected_monitor", _counting):
            assert core._push_input_config_with_retry(mon) is False
        assert len(entered) == 3

    def test_an_exception_counts_as_a_failed_attempt(self):
        mon = _make_monitor(input_index=0)
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.configure_input.side_effect = [RuntimeError("boom"), True]
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            assert core._push_input_config_with_retry(mon) is True
        assert mock_client.configure_input.call_count == 2

    def test_push_carries_the_monitor_type(self):
        _make_monitor(input_index=0, input_type="cd")
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.configure_input.return_value = True
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            core.update_live_silence_threshold_dbfs(0, -35.0)
        assert mock_client.configure_input.call_args.kwargs["input_type"] == "cd"

    def test_updates_only_matching_monitor_threshold_on_success(self):
        mon0 = _make_monitor(input_index=0, silence_threshold_dbfs=-50.0)
        mon1 = _make_monitor(input_index=1, silence_threshold_dbfs=-50.0)
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.configure_input.return_value = True
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            core.update_live_silence_threshold_dbfs(0, -35.0)
        assert mon0.silence_threshold_dbfs == -35.0
        assert mon1.silence_threshold_dbfs == -50.0


# ---------------------------------------------------------------------------
# update_live_input_type
# ---------------------------------------------------------------------------

class TestUpdateLiveInputType:
    def _acking_client(self):
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.configure_input.return_value = True
        return mock_client

    def test_returns_true_with_no_matching_monitor(self):
        assert core.update_live_input_type(0, "cd", -60.0) is True

    def test_pushes_type_and_threshold(self):
        _make_monitor(input_index=0)
        mock_client = self._acking_client()
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            result = core.update_live_input_type(0, "cd", -60.0)
        assert result is True
        args, kwargs = mock_client.configure_input.call_args
        assert kwargs["input_type"] == "cd"
        assert args[2] == -60.0

    def test_updates_monitor_attributes(self):
        mon = _make_monitor(input_index=0)
        mock_client = self._acking_client()
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            core.update_live_input_type(0, "cd", -60.0)
            assert mon.input_type == "cd"
            assert mon.is_turntable is False
            assert mon.silence_threshold_dbfs == -60.0
            core.update_live_input_type(0, "turntable", -45.0)
        assert mon.input_type == "turntable"
        assert mon.is_turntable is True
        assert mon.silence_threshold_dbfs == -45.0

    def test_swaps_a_default_bundle_and_requests_republish(self):
        mon = _make_monitor(input_index=0)
        core.consume_nowplaying_republish()
        mon._current_nowplaying = mon._default_nowplaying_metadata()
        with patch.object(core, "_connected_monitor", _fake_connected(self._acking_client())):
            core.update_live_input_type(0, "cd", -60.0)
        assert mon._current_nowplaying.title == "CD"
        assert core.consume_nowplaying_republish() is True

    def test_invalid_threshold_returns_false_and_changes_nothing(self):
        mon = _make_monitor(input_index=0, silence_threshold_dbfs=-50.0)
        mock_client = self._acking_client()
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            result = core.update_live_input_type(0, "cd", "not-a-number")
        assert result is False
        assert mon.input_type == "line"
        assert mon.is_turntable is False
        assert mon.silence_threshold_dbfs == -50.0
        mock_client.configure_input.assert_not_called()

    def test_stored_type_is_normalised(self):
        mon = _make_monitor(input_index=0)
        with patch.object(core, "_connected_monitor", _fake_connected(self._acking_client())):
            core.update_live_input_type(0, "  CD ", -60.0)
        assert mon.input_type == "cd"

    def test_swapped_default_bundle_keeps_its_artwork(self):
        mon = _make_monitor(input_index=0)
        mon._current_nowplaying = replace(
            mon._default_nowplaying_metadata(), artwork=b"art-bytes"
        )
        with patch.object(core, "_connected_monitor", _fake_connected(self._acking_client())):
            core.update_live_input_type(0, "cd", -60.0)
        assert mon._current_nowplaying.title == "CD"
        assert mon._current_nowplaying.artwork == b"art-bytes"

    def test_leaves_an_identified_bundle_alone(self):
        mon = _make_monitor(input_index=0)
        song = NowPlayingMetadata(title="Song", artist="A", album="B")
        mon._current_nowplaying = song
        with patch.object(core, "_connected_monitor", _fake_connected(self._acking_client())):
            core.update_live_input_type(0, "cd", -60.0)
        assert mon._current_nowplaying is song

    def test_failed_push_reports_false_but_keeps_attributes(self):
        mon = _make_monitor(input_index=0)
        with patch.object(core, "_connected_monitor", _fake_connected(None)):
            result = core.update_live_input_type(0, "cd", -60.0)
        assert result is False
        assert mon.input_type == "cd"
        assert mon.silence_threshold_dbfs == -60.0


# ---------------------------------------------------------------------------
# get_session_source_input_index / get_monitor_levels_dbfs
# ---------------------------------------------------------------------------

class TestGetSessionSourceInputIndex:
    def _index(self, state, repeat_status=None):
        with patch.object(core, "get_session_state", return_value=state), \
             patch.object(core, "get_repeat_status", return_value=repeat_status):
            return core.get_session_source_input_index()

    def test_input1(self):
        assert self._index({"active": True, "source": "input1"}) == 1

    def test_input2(self):
        assert self._index({"active": True, "source": "input2"}) == 2

    def test_replay_resolves_to_the_origin_input(self):
        status = {"replay": {"active": True}, "recording": {"origin_input": 2}}
        assert self._index({"active": True, "source": "replay"}, status) == 2

    def test_replay_without_repeat_status_is_none(self):
        assert self._index({"active": True, "source": "replay"}, None) is None

    def test_idle_is_none(self):
        assert self._index({"active": False, "source": None}) is None

    @pytest.mark.parametrize("source", ["input", "inputX", 123])
    def test_unparseable_source_is_none(self, source):
        assert self._index({"active": True, "source": source}) is None


class TestDefaultNowPlayingMetadata:
    def test_raw_capture_device_string_never_appears(self):
        raw_device = "hw:CARD=CODEC,DEV=0"
        for input_type in ("turntable", "cd", "line"):
            meta = _make_monitor(
                input_device=raw_device, input_type=input_type
            )._default_nowplaying_metadata()
            for text in (meta.title, meta.artist, meta.album):
                assert raw_device not in text


class TestGetMonitorLevelsDbfs:
    def test_each_item_carries_its_input_index(self):
        _make_monitor(input_index=2)
        assert core.get_monitor_levels_dbfs()[0]["index"] == 2


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

def _make_output(name="Test Speaker", out_id="1", selected=False, needs_auth_key=False):
    out = MagicMock()
    out.name = name
    out.id = out_id
    out.selected = selected
    out.needs_auth_key = needs_auth_key
    out.pin_pending = False
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
    """_on_capture_started is per-input (track-ID + logging) only;
    the was_idle OwnTone output-enable path lives in the session tracker's
    session_started event (_start_session_owntone), covered in
    tests/test_repeat_api.py's TestSessionTracker classes."""

    def test_started_resets_ti_state(self):
        mon = _make_monitor()
        mon._ti_inflight = True
        mon._ti_next_attempt = 999.0
        mon._on_capture_started()
        assert mon._ti_inflight is False
        assert mon._ti_next_attempt == 0.0

    def test_started_does_not_touch_owntone(self):
        """No OwnTone output action of any kind fires from this per-input callback."""
        mon = _make_monitor(owntone_base_url="http://localhost:3689")
        with patch.object(core, "_stop_and_disable_owntone") as stop_mock, \
             patch.object(mon, "_maybe_retry_owntone") as retry_mock:
            mon._on_capture_started()
        stop_mock.assert_not_called()
        retry_mock.assert_not_called()


class TestCaptureStopOrdering:
    """_on_capture_stopped is per-input (track-ID + logging) only;
    the OwnTone idle-stop and now-playing publish_end live in the session
    tracker's session_ended event, covered in tests/test_repeat_api.py's
    TestSessionTracker classes."""

    def test_stopped_does_not_touch_owntone_or_nowplaying(self):
        mon = _make_monitor(owntone_base_url="http://localhost:3689")
        mock_client = MagicMock(spec=MonitorClient)
        with patch.object(core, "_stop_and_disable_owntone") as stop_mock, \
             patch.object(core, "any_monitor_capturing", return_value=False):
            mon._on_capture_stopped(mock_client)
        stop_mock.assert_not_called()
        mon._nowplaying_publisher.publish_end.assert_not_called()

    def test_stopped_resets_ti_state(self):
        mon = _make_monitor(owntone_base_url="http://localhost:3689")
        mock_client = MagicMock(spec=MonitorClient)
        mon._ti_next_attempt = 999.0
        mon._track_change_seq_baseline = 42
        mon._on_capture_stopped(mock_client)
        assert mon._ti_next_attempt == 0.0
        assert mon._track_change_seq_baseline == 0


# ---------------------------------------------------------------------------
# _sync_playing_announcement: mDNS zero-to-one and one-to-zero transitions.
# The predicate is the unified session-active flag, so a repeat-replay
# session announces exactly like a live-capture one.
# ---------------------------------------------------------------------------

_FIXED_APPLIANCE_ID = "a1b2c3d4e5f6a1b2c3d4"


class TestSyncPlayingAnnouncement:
    def setup_method(self):
        core._playing_announced = False
        self._id_patcher = patch.object(core, "get_appliance_id", return_value=_FIXED_APPLIANCE_ID)
        self._id_patcher.start()

    def teardown_method(self):
        self._id_patcher.stop()
        core._playing_announced = False

    def test_zero_to_one_writes_avahi_service(self):
        with patch.object(core, "write_avahi_playing_service", return_value=True) as mock_write:
            core._sync_playing_announcement(True, "v1")
        mock_write.assert_called_once_with("v1", _FIXED_APPLIANCE_ID)
        assert core._playing_announced is True

    def test_write_failure_leaves_announced_false(self):
        with patch.object(core, "write_avahi_playing_service", return_value=False):
            core._sync_playing_announcement(True, "v1")
        assert core._playing_announced is False

    def test_one_to_zero_removes_avahi_service(self):
        core._playing_announced = True
        with patch.object(core, "remove_avahi_playing_service", return_value=True) as mock_remove:
            core._sync_playing_announcement(False, "v1")
        mock_remove.assert_called_once()
        assert core._playing_announced is False

    def test_remove_failure_leaves_announced_true(self):
        core._playing_announced = True
        with patch.object(core, "remove_avahi_playing_service", return_value=False):
            core._sync_playing_announcement(False, "v1")
        assert core._playing_announced is True

    def test_already_announced_skips_write(self):
        core._playing_announced = True
        with patch.object(core, "write_avahi_playing_service") as mock_write:
            core._sync_playing_announcement(True, "v1")
        mock_write.assert_not_called()

    def test_not_announced_and_not_active_skips_remove(self):
        core._playing_announced = False
        with patch.object(core, "remove_avahi_playing_service") as mock_remove:
            core._sync_playing_announcement(False, "v1")
        mock_remove.assert_not_called()

    def test_reconciliation_reads_session_state_not_capture_flags(self):
        # A replay session (no monitor capturing) must still re-announce:
        # the reconcile tick derives its predicate from get_session_state().
        core._set_session_state(True, "replay")
        try:
            with patch.object(core, "write_avahi_playing_service", return_value=True) as mock_write:
                core._sync_playing_announcement(
                    core.get_session_state()["active"], "v1"
                )
            mock_write.assert_called_once_with("v1", _FIXED_APPLIANCE_ID)
            assert core._playing_announced is True
        finally:
            core._set_session_state(False, None)


# ---------------------------------------------------------------------------
# Replay-start acks advertise "playing" from the API thread, via the task pool.
# ---------------------------------------------------------------------------

def _repeat_block(replaying=False):
    return {
        "enabled": True, "armed": True,
        "recording": {"active": False, "seconds": 342.0, "origin_input": 1},
        "replay": {"active": replaying, "fading_out": False,
                   "position_seconds": 10.0 if replaying else 0.0,
                   "duration_seconds": 342.0},
    }


def _repeat_ack(command, state):
    return {"type": "ack", "command": command, "ok": True, "state": state,
            "armed": True, "position_seconds": 0.0}


class TestReplayAckAnnouncement:
    def setup_method(self):
        core._playing_announced = False
        core._playing_version = "v1"
        core._set_session_state(False, None)

    def teardown_method(self):
        core._playing_announced = False
        core._playing_version = None
        core._set_repeat_status(None)
        core._set_session_state(False, None)

    def _ack_from_hold(self, command="repeat_seek", state="replaying",
                       replaying=False):
        core._set_repeat_status(_repeat_block(replaying=replaying))
        with patch.object(core, "_rearm_replay_identification"), \
             patch.object(core._task_pool, "submit", return_value=True) as submit:
            core.apply_repeat_ack(_repeat_ack(command, state))
        return submit

    def test_replaying_ack_submits_the_announcement_off_thread(self):
        submit = self._ack_from_hold()
        submit.assert_called_once_with(
            "playing-announce", core._announce_playing_if_active, "v1")

    def test_replaying_ack_is_a_noop_when_already_announced(self):
        core._playing_announced = True
        submit = self._ack_from_hold()
        submit.assert_not_called()

    def test_replaying_ack_is_a_noop_without_a_version(self):
        core._playing_version = None
        submit = self._ack_from_hold()
        submit.assert_not_called()

    def test_seek_within_a_replay_does_not_submit(self):
        submit = self._ack_from_hold(replaying=True)
        submit.assert_not_called()

    def test_stop_and_fading_out_acks_never_submit(self):
        assert self._ack_from_hold("repeat_stop", "fading_out",
                                   replaying=True).call_count == 0
        assert self._ack_from_hold("set_repeat_armed", "hold").call_count == 0

    def test_a_submit_failure_never_reaches_the_caller(self):
        core._set_repeat_status(_repeat_block())
        with patch.object(core, "_rearm_replay_identification"), \
             patch.object(core._task_pool, "submit",
                          side_effect=RuntimeError("pool down")):
            core.apply_repeat_ack(_repeat_ack("repeat_seek", "replaying"))

    def test_duplicate_submission_is_dropped_by_single_flight(self):
        import threading
        release = threading.Event()
        started = threading.Event()
        pool = core.TaskPool(max_workers=1)

        def slow(_v):
            started.set()
            release.wait(5)

        try:
            with patch.object(core, "_task_pool", pool), \
                 patch.object(core, "_announce_playing_if_active", slow):
                core._announce_replay_playing()
                assert started.wait(5)
                core._announce_replay_playing()
                assert pool.is_inflight("playing-announce")
        finally:
            release.set()

    def test_worker_reads_the_session_state_when_it_runs(self):
        # A stop that lands before the pooled task runs must not leave the
        # service announced.
        core._set_session_state(False, None)
        with patch.object(core, "write_avahi_playing_service") as write:
            core._announce_playing_if_active("v1")
        write.assert_not_called()
        assert core._playing_announced is False

    def test_worker_announces_while_the_session_is_active(self):
        core._set_session_state(True, "replay")
        with patch.object(core, "get_appliance_id", return_value=_FIXED_APPLIANCE_ID), \
             patch.object(core, "write_avahi_playing_service",
                          return_value=True) as write:
            core._announce_playing_if_active("v1")
            core._sync_playing_announcement(True, "v1")
        write.assert_called_once_with("v1", _FIXED_APPLIANCE_ID)
        assert core._playing_announced is True

    def test_run_autostream_records_the_version(self):
        import inspect
        src = inspect.getsource(core.run_autostream)
        assert "_playing_version = version" in src
        assert "_playing_version" in src.split("global", 1)[1].split("\n", 1)[0]


# ---------------------------------------------------------------------------
# Dynamic Rate Matching: the flag reaching the daemon
# ---------------------------------------------------------------------------

class TestRateMatchingFlagOnEveryPush:
    def _acking_client(self):
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.configure_input.return_value = True
        return mock_client

    def test_silence_seconds_update_carries_the_flag_the_monitor_holds(self):
        _make_monitor(input_index=0, dynamic_rate_matching=True)
        mock_client = self._acking_client()
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            core.update_live_silence_seconds(45)
        assert mock_client.configure_input.call_args.kwargs["dynamic_rate_matching"] is True

    def test_threshold_update_carries_the_flag_the_monitor_holds(self):
        _make_monitor(input_index=0, dynamic_rate_matching=True)
        mock_client = self._acking_client()
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            core.update_live_silence_threshold_dbfs(0, -35.0)
        assert mock_client.configure_input.call_args.kwargs["dynamic_rate_matching"] is True

    def test_input_type_update_carries_the_flag_the_monitor_holds(self):
        _make_monitor(input_index=0, dynamic_rate_matching=True)
        mock_client = self._acking_client()
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            core.update_live_input_type(0, "cd", -60.0)
        assert mock_client.configure_input.call_args.kwargs["dynamic_rate_matching"] is True

    def test_flag_defaults_off_on_a_new_monitor(self):
        assert _make_monitor(input_index=0).dynamic_rate_matching is False

    def test_resync_sends_each_monitors_own_flag(self):
        client = MagicMock(spec=MonitorClient)
        for name in ("set_fifo", "set_log_level", "stop_input", "configure_input",
                     "start_input", "set_allow_capture", "set_repeat_enabled"):
            getattr(client, name).return_value = True
        monitors = [
            _make_monitor(input_index=1, dynamic_rate_matching=True),
            _make_monitor(input_index=2, dynamic_rate_matching=False),
        ]
        with patch("autostream_core.reconcile_fifo_with_backend") as rf, \
             patch("autostream_core.apply_input_gain", return_value=True), \
             patch("autostream_core.apply_input_eq", return_value=True), \
             patch("autostream_core._apply_output_eq_config", return_value=True):
            rf.return_value = MagicMock(ok=True, message="")
            ok = core._resync_monitor_daemon(
                client, monitors, "/tmp/test.fifo", "http://localhost:3689",
                MagicMock(), repeat_enabled=False, repeat_codec="auto",
            )
        assert ok is True
        sent = {c.args[0]: c.kwargs["dynamic_rate_matching"]
                for c in client.configure_input.call_args_list}
        assert sent == {1: True, 2: False}


class TestConfigureInputCallSitesPassTheFlag:
    def test_every_configure_input_call_names_the_keyword(self):
        import ast

        source = (REPO_ROOT / "core" / "autostream_core.py").read_text(encoding="utf-8")
        calls = [
            node for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "configure_input"
        ]
        # Five sites today; fewer would mean this test no longer finds them.
        assert len(calls) >= 5
        missing = [
            node.lineno for node in calls
            if "dynamic_rate_matching" not in {kw.arg for kw in node.keywords}
        ]
        assert missing == [], f"configure_input calls without the flag at lines {missing}"


class TestUpdateLiveDynamicRateMatching:
    def _acking_client(self):
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.configure_input.return_value = True
        return mock_client

    def test_returns_true_with_no_matching_monitor(self):
        assert core.update_live_dynamic_rate_matching(0, True) is True

    def test_pushes_the_new_value_for_the_matching_monitor_only(self):
        _make_monitor(input_index=1)
        _make_monitor(input_index=2)
        mock_client = self._acking_client()
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            result = core.update_live_dynamic_rate_matching(2, True)
        assert result is True
        assert mock_client.configure_input.call_count == 1
        args, kwargs = mock_client.configure_input.call_args
        assert args[0] == 2
        assert kwargs["dynamic_rate_matching"] is True

    def test_other_values_go_out_unchanged(self):
        _make_monitor(input_index=1, input_type="cd", silence_threshold_dbfs=-61.0)
        mock_client = self._acking_client()
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            core.update_live_dynamic_rate_matching(1, True)
        args, kwargs = mock_client.configure_input.call_args
        assert kwargs["input_type"] == "cd"
        assert args[2] == -61.0

    def test_attribute_is_set_before_the_push(self):
        mon = _make_monitor(input_index=1)
        seen = []

        def record(*args, **kwargs):
            seen.append(mon.dynamic_rate_matching)
            return True

        mock_client = MagicMock(spec=MonitorClient)
        mock_client.configure_input.side_effect = record
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            core.update_live_dynamic_rate_matching(1, True)
        assert seen == [True]

    def test_turning_it_off_pushes_false(self):
        mon = _make_monitor(input_index=1, dynamic_rate_matching=True)
        mock_client = self._acking_client()
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            core.update_live_dynamic_rate_matching(1, False)
        assert mon.dynamic_rate_matching is False
        assert mock_client.configure_input.call_args.kwargs["dynamic_rate_matching"] is False

    def test_every_attempt_failing_returns_false_and_keeps_the_value(self):
        mon = _make_monitor(input_index=1)
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.configure_input.return_value = False
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            result = core.update_live_dynamic_rate_matching(1, True)
        assert result is False
        assert mock_client.configure_input.call_count == core.LIVE_PUSH_ATTEMPTS
        assert mon.dynamic_rate_matching is True

    def test_no_daemon_returns_false_and_keeps_the_value(self):
        mon = _make_monitor(input_index=1)
        with patch.object(core, "_connected_monitor", _fake_connected(None)):
            result = core.update_live_dynamic_rate_matching(1, True)
        assert result is False
        assert mon.dynamic_rate_matching is True

    def test_second_attempt_succeeding_returns_true(self):
        _make_monitor(input_index=1)
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.configure_input.side_effect = [False, True]
        with patch.object(core, "_connected_monitor", _fake_connected(mock_client)):
            result = core.update_live_dynamic_rate_matching(1, True)
        assert result is True
        assert mock_client.configure_input.call_count == 2


# ---------------------------------------------------------------------------
# Dynamic Rate Matching: status ingest
# ---------------------------------------------------------------------------

def _rate_records(caplog):
    return [r for r in caplog.records if "delivering" in r.getMessage()]


class TestIngestRateStatus:
    def test_the_five_fields_are_ingested(self):
        mon = _make_monitor(input_index=1)
        mon._ingest_status({
            "started": True, "negotiated_hz": 48000, "rate_lock": "locked",
            "relock_count": 2, "rate_mismatch_hz": 0, "dynamic_rate_matching": True,
        })
        assert mon.negotiated_hz == 48000
        assert mon.rate_lock == "locked"
        assert mon.relock_count == 2
        assert mon.rate_mismatch_hz == 0
        assert mon.monitor_dynamic_rate_matching is True

    def test_an_older_monitor_with_none_of_the_keys_gets_the_defaults(self):
        mon = _make_monitor(input_index=1)
        mon._ingest_status({"level_dbfs": -20.0, "started": True})
        assert mon.negotiated_hz == 0
        assert mon.rate_lock == "locked"
        assert mon.relock_count == 0
        assert mon.rate_mismatch_hz == 0
        assert mon.monitor_dynamic_rate_matching is None

    def test_a_non_bool_support_value_reads_as_unsupported(self):
        mon = _make_monitor(input_index=1)
        mon._ingest_status({"dynamic_rate_matching": "yes"})
        assert mon.monitor_dynamic_rate_matching is None

    def test_support_flag_false_still_counts_as_support(self):
        mon = _make_monitor(input_index=1)
        mon._ingest_status({"dynamic_rate_matching": False})
        assert mon.monitor_dynamic_rate_matching is False

    def test_mismatch_logs_a_warning_naming_input_and_both_rates(self, caplog):
        mon = _make_monitor(input_index=1)
        with caplog.at_level(logging.DEBUG):
            mon._ingest_status({
                "started": True, "negotiated_hz": 48000,
                "rate_lock": "mismatch", "rate_mismatch_hz": 44100,
            })
        recs = _rate_records(caplog)
        assert len(recs) == 1
        assert recs[0].levelno == logging.WARNING
        assert recs[0].getMessage() == (
            "Input 1 is delivering 44100 Hz but was opened at 48000 Hz; "
            "Dynamic Rate Matching is off for this input."
        )
        assert mon.rate_mismatch_hz == 44100

    def test_a_steady_mismatch_logs_once(self, caplog):
        mon = _make_monitor(input_index=1)
        entry = {"started": True, "negotiated_hz": 48000, "rate_mismatch_hz": 44100}
        with caplog.at_level(logging.DEBUG):
            mon._ingest_status(entry)
            mon._ingest_status(entry)
            mon._ingest_status(entry)
        assert len(_rate_records(caplog)) == 1

    def test_clearing_logs_info(self, caplog):
        mon = _make_monitor(input_index=1)
        mon._ingest_status({"started": True, "negotiated_hz": 48000, "rate_mismatch_hz": 44100})
        with caplog.at_level(logging.DEBUG):
            mon._ingest_status({"started": True, "negotiated_hz": 48000, "rate_mismatch_hz": 0})
        cleared = [r for r in caplog.records if "mismatch cleared" in r.getMessage()]
        assert len(cleared) == 1
        assert cleared[0].levelno == logging.INFO
        assert cleared[0].getMessage() == "Input 1 sample rate mismatch cleared."
        assert mon.rate_mismatch_hz == 0

    def test_second_assert_inside_the_throttle_logs_at_info(self, caplog):
        mon = _make_monitor(input_index=1)
        up = {"started": True, "negotiated_hz": 48000, "rate_mismatch_hz": 44100}
        down = {"started": True, "negotiated_hz": 48000, "rate_mismatch_hz": 0}
        window = AudioMonitor.RATE_MISMATCH_LOG_THROTTLE_SECONDS
        with caplog.at_level(logging.DEBUG):
            with patch("autostream_core.time.time", return_value=1000.0):
                mon._ingest_status(up)
                mon._ingest_status(down)
            with patch("autostream_core.time.time", return_value=1000.0 + window - 1):
                mon._ingest_status(up)
        levels = [r.levelno for r in _rate_records(caplog)]
        assert levels == [logging.WARNING, logging.INFO]

    def test_assert_after_the_throttle_warns_again(self, caplog):
        mon = _make_monitor(input_index=1)
        up = {"started": True, "negotiated_hz": 48000, "rate_mismatch_hz": 44100}
        down = {"started": True, "negotiated_hz": 48000, "rate_mismatch_hz": 0}
        window = AudioMonitor.RATE_MISMATCH_LOG_THROTTLE_SECONDS
        with caplog.at_level(logging.DEBUG):
            with patch("autostream_core.time.time", return_value=1000.0):
                mon._ingest_status(up)
                mon._ingest_status(down)
            with patch("autostream_core.time.time", return_value=1000.0 + window):
                mon._ingest_status(up)
        levels = [r.levelno for r in _rate_records(caplog)]
        assert levels == [logging.WARNING, logging.WARNING]

    def test_the_owntone_throttle_timer_does_not_silence_the_warning(self, caplog):
        mon = _make_monitor(input_index=1)
        mon._owntone_last_log = 1000.0
        with caplog.at_level(logging.DEBUG), \
             patch("autostream_core.time.time", return_value=1000.0):
            mon._ingest_status(
                {"started": True, "negotiated_hz": 48000, "rate_mismatch_hz": 44100}
            )
        assert [r.levelno for r in _rate_records(caplog)] == [logging.WARNING]

    def test_each_input_has_its_own_warning_timer(self, caplog):
        first = _make_monitor(input_index=1)
        second = _make_monitor(input_index=2)
        entry = {"started": True, "negotiated_hz": 48000, "rate_mismatch_hz": 44100}
        with caplog.at_level(logging.DEBUG), \
             patch("autostream_core.time.time", return_value=1000.0):
            first._ingest_status(entry)
            second._ingest_status(entry)
        assert [r.levelno for r in _rate_records(caplog)] == [logging.WARNING, logging.WARNING]

    def test_mismatch_follows_the_rate_not_the_lock_string(self, caplog):
        mon = _make_monitor(input_index=1)
        with caplog.at_level(logging.DEBUG):
            mon._ingest_status({
                "started": True, "negotiated_hz": 48000,
                "rate_lock": "mismatch", "rate_mismatch_hz": 0,
            })
        assert mon.rate_mismatch_hz == 0
        assert _rate_records(caplog) == []
        mon._ingest_status({
            "started": True, "negotiated_hz": 48000,
            "rate_lock": "locked", "rate_mismatch_hz": 44100,
        })
        assert mon.rate_mismatch_hz == 44100

    def test_a_mismatch_on_a_stopped_input_is_not_recorded(self):
        mon = _make_monitor(input_index=1)
        mon._ingest_status({"started": False, "negotiated_hz": 0, "rate_mismatch_hz": 44100})
        assert mon.rate_mismatch_hz == 0

    def test_a_rate_step_logs_info(self, caplog):
        mon = _make_monitor(input_index=1)
        with caplog.at_level(logging.DEBUG):
            mon._ingest_status({
                "started": True, "negotiated_hz": 48000, "detected_hz": 44100.0,
                "relock_count": 1, "dynamic_rate_matching": True,
            })
        steps = [r for r in caplog.records if "capture rate step" in r.getMessage()]
        assert len(steps) == 1
        assert steps[0].levelno == logging.INFO
        assert steps[0].getMessage() == (
            "Input 1 capture rate step #1: now 44100.0 Hz (negotiated 48000 Hz)"
        )
        assert mon.relock_count == 1


# ---------------------------------------------------------------------------
# Dynamic Rate Matching: levels, banner text and the Setup note
# ---------------------------------------------------------------------------

class TestRateKeysInMonitorLevels:
    def test_new_keys_carry_the_monitors_values(self):
        mon = _make_monitor(input_index=1, dynamic_rate_matching=True)
        mon._ingest_status({
            "started": True, "negotiated_hz": 48000, "detected_hz": 44100.4,
            "rate_lock": "locked", "relock_count": 1, "rate_mismatch_hz": 0,
            "dynamic_rate_matching": True,
        })
        level = core.get_monitor_levels_dbfs()[0]
        assert level["detected_khz"] == "44.1 kHz"
        assert level["negotiated_hz"] == 48000
        assert level["rate_lock"] == "locked"
        assert level["relock_count"] == 1
        assert level["rate_mismatch_hz"] == 0
        assert level["rate_mismatch_khz"] == ""
        assert level["dynamic_rate_matching"] is True
        assert level["monitor_supports_rate_matching"] is True

    def test_mismatch_rate_is_shown_in_khz(self):
        mon = _make_monitor(input_index=1)
        mon._ingest_status({"started": True, "negotiated_hz": 48000, "rate_mismatch_hz": 44100})
        level = core.get_monitor_levels_dbfs()[0]
        assert level["rate_mismatch_hz"] == 44100
        assert level["rate_mismatch_khz"] == "44.1 kHz"

    def test_an_older_monitor_is_marked_unsupported(self):
        mon = _make_monitor(input_index=1)
        mon._ingest_status({"started": True})
        level = core.get_monitor_levels_dbfs()[0]
        assert level["monitor_supports_rate_matching"] is False
        assert level["rate_lock"] == "locked"

    def test_existing_keys_are_kept(self):
        _make_monitor(input_index=1)
        level = core.get_monitor_levels_dbfs()[0]
        for key in ("index", "label", "dbfs", "detected_hz", "is_above_threshold", "vu_history"):
            assert key in level


class TestFormatKhz:
    @pytest.mark.parametrize("hz, text", [
        (44100, "44.1 kHz"),
        (48000, "48 kHz"),
        (32000, "32 kHz"),
        (88200, "88.2 kHz"),
        (48003.2, "48 kHz"),
        (44097.3, "44.1 kHz"),
        (0, ""),
        (-1, ""),
        (float("nan"), ""),
        (float("inf"), ""),
        (None, ""),
        ("x", ""),
    ])
    def test_formatting(self, hz, text):
        assert core.format_khz(hz) == text


class TestSampleRateBanner:
    _TEXT = "Sample Rate Mismatch: Please enable Dynamic Rate Matching"

    def test_no_monitors_gives_no_text(self):
        assert core.sample_rate_warning_text() == ""
        assert core.sample_rate_mismatch_input() == 0

    def test_a_reported_mismatch_gives_the_fixed_text(self):
        mon = _make_monitor(input_index=1)
        mon.rate_mismatch_hz = 44100
        assert core.sample_rate_warning_text() == self._TEXT
        assert core.sample_rate_warning_text() == core.SAMPLE_RATE_MISMATCH_BANNER_TEXT
        assert core.sample_rate_mismatch_input() == 1

    def test_no_reported_mismatch_gives_no_text_whatever_the_local_flag(self):
        for flag in (False, True):
            _make_monitor(input_index=int(flag) + 1, dynamic_rate_matching=flag)
        assert core.sample_rate_warning_text() == ""

    def test_banner_stays_while_the_monitor_reports_it_after_the_flag_is_set(self):
        # The flag is set locally before the push; a failed push must not
        # hide the banner.
        mon = _make_monitor(input_index=1)
        mon.rate_mismatch_hz = 44100
        mon.dynamic_rate_matching = True
        assert core.sample_rate_warning_text() == self._TEXT

    def test_banner_follows_the_rate_not_the_lock_string(self):
        mon = _make_monitor(input_index=1)
        mon.rate_lock = "mismatch"
        assert core.sample_rate_warning_text() == ""
        mon.rate_lock = "locked"
        mon.rate_mismatch_hz = 44100
        assert core.sample_rate_warning_text() == self._TEXT

    def test_two_mismatched_inputs_give_one_string(self):
        for i in (1, 2):
            _make_monitor(input_index=i).rate_mismatch_hz = 44100
        assert core.sample_rate_warning_text() == self._TEXT

    def test_lowest_numbered_mismatched_input_wins(self):
        _make_monitor(input_index=2).rate_mismatch_hz = 44100
        first = _make_monitor(input_index=1)
        assert core.sample_rate_mismatch_input() == 2
        first.rate_mismatch_hz = 32000
        assert core.sample_rate_mismatch_input() == 1


class TestRateMatchingNoteText:
    def test_no_monitor_for_the_index_gives_the_default(self):
        assert core.rate_matching_note_text(1) == core.RATE_MATCHING_NOTE_DEFAULT

    def test_flag_on_with_an_older_monitor_says_it_needs_updating(self):
        _make_monitor(input_index=1, dynamic_rate_matching=True)
        assert core.rate_matching_note_text(1) == core.RATE_MATCHING_NOTE_MONITOR_OLD

    def test_flag_on_with_a_supporting_monitor_gives_the_default(self):
        mon = _make_monitor(input_index=1, dynamic_rate_matching=True)
        mon.monitor_dynamic_rate_matching = True
        assert core.rate_matching_note_text(1) == core.RATE_MATCHING_NOTE_DEFAULT

    def test_flag_off_with_a_mismatch_describes_it(self):
        mon = _make_monitor(input_index=1)
        mon.rate_mismatch_hz = 44100
        mon.negotiated_hz = 48000
        assert core.rate_matching_note_text(1) == (
            "This input is delivering 44.1 kHz but the device was opened at "
            "48 kHz. Turn this on to follow the source."
        )

    def test_flag_on_with_a_mismatch_still_reported_gives_the_default(self):
        mon = _make_monitor(input_index=1, dynamic_rate_matching=True)
        mon.monitor_dynamic_rate_matching = True
        mon.rate_mismatch_hz = 44100
        mon.negotiated_hz = 48000
        assert core.rate_matching_note_text(1) == core.RATE_MATCHING_NOTE_DEFAULT

    def test_flag_off_with_no_mismatch_gives_the_default(self):
        _make_monitor(input_index=1)
        assert core.rate_matching_note_text(1) == core.RATE_MATCHING_NOTE_DEFAULT

    def test_the_other_inputs_monitor_is_not_consulted(self):
        other = _make_monitor(input_index=2)
        other.rate_mismatch_hz = 44100
        other.negotiated_hz = 48000
        _make_monitor(input_index=1)
        assert core.rate_matching_note_text(1) == core.RATE_MATCHING_NOTE_DEFAULT
