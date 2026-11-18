"""tests/test_inputs_part.py

The inputs part of the state snapshot: one entry per running monitor with its
Web UI level item and its two Setup rate texts, rebuilt at each point where a
value it derives from changes.
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_core as core
import autostream_state as state
from autostream_audio_monitor import AudioMonitor
import autostream_live_config as live_config
import autostream_input_status as input_status

LEVEL_KEYS = {
    "index", "label", "dbfs", "detected_hz", "detected_khz", "negotiated_hz",
    "rate_lock", "relock_count", "rate_mismatch_hz", "rate_mismatch_khz",
    "dynamic_rate_matching", "monitor_supports_rate_matching", "is_above_threshold",
    "vu_history",
}


def make_monitor(index=1, **overrides) -> AudioMonitor:
    defaults = dict(
        input_index=index, input_device="hw:0,0", silence_threshold_dbfs=-50.0,
        silence_seconds=5, fifo_path="/tmp/test.fifo",
        owntone_base_url="http://localhost:3689",
        dynamic_rate_matching=False,
    )
    defaults.update(overrides)
    with patch("autostream_audio_monitor.PersistentNowPlayingCache") as cache, \
         patch("autostream_audio_monitor.get_shared_metadata_publisher") as pub:
        cache.return_value.get_manual_hint.return_value = None
        pub.side_effect = lambda path: MagicMock()
        return AudioMonitor(**defaults)


def locked_status(**fields) -> dict:
    status = {"started": True, "negotiated_hz": 48000, "detected_hz": 48000.0,
              "rate_lock": "locked", "relock_count": 0, "rate_mismatch_hz": 0}
    status.update(fields)
    return status


def inputs():
    return state.store().snapshot().inputs


def test_the_part_starts_empty_with_the_default_texts():
    assert inputs() == state.InputsPart()
    assert inputs().levels() == []
    assert inputs().rate_texts(1) == (
        state.RATE_MATCHING_NOTE_DEFAULT, state.SAMPLE_RATE_TEXT_NOT_RUNNING)


def test_a_publish_builds_one_entry_per_monitor_in_monitor_order():
    make_monitor(2)
    make_monitor(1, input_type="turntable")
    input_status.publish_inputs()
    assert [e.index for e in inputs().entries] == [2, 1]
    assert inputs().entry(1).input_type == "turntable"
    assert inputs().entry(1).device == "hw:0,0"


def test_the_level_item_keeps_the_shape_the_web_ui_reads():
    mon = make_monitor(1)
    mon._ingest_status(locked_status(vu_history={"left": [-60.0, -59.5]}))
    input_status.publish_inputs()
    (level,) = inputs().levels()
    assert set(level) == LEVEL_KEYS
    assert level["index"] == 1 and level["label"] == "Input 1"
    assert level["detected_khz"] == "48 kHz"
    assert level["vu_history"] == {"left": [-60.0, -59.5]}
    level["dbfs"] = 0.0
    assert inputs().levels()[0]["dbfs"] != 0.0


def test_a_mismatch_names_the_lowest_input_and_sets_the_banner():
    make_monitor(2)._ingest_status(locked_status(rate_mismatch_hz=44100))
    make_monitor(1)
    input_status.publish_inputs()
    assert inputs().sample_rate_mismatch_input == 2
    assert inputs().sample_rate_warning_text == input_status.SAMPLE_RATE_MISMATCH_BANNER_TEXT
    make_monitor(3)._ingest_status(locked_status(rate_mismatch_hz=44100))
    input_status.publish_inputs()
    assert inputs().sample_rate_mismatch_input == 2


def test_no_mismatch_clears_the_banner():
    make_monitor(1)._ingest_status(locked_status())
    input_status.publish_inputs()
    assert inputs().sample_rate_mismatch_input == 0
    assert inputs().sample_rate_warning_text == ""


def test_the_readout_follows_the_daemon_connection():
    make_monitor(1)._ingest_status(locked_status())
    core._set_monitor_runtime_info(connected=True)
    assert inputs().rate_texts(1)[1] == "Sample rate: 48 kHz"
    core._set_monitor_runtime_info(connected=False)
    assert inputs().rate_texts(1)[1] == state.SAMPLE_RATE_TEXT_NOT_RUNNING


def test_a_monitor_update_that_leaves_connected_alone_does_not_rebuild_the_inputs():
    core._set_monitor_runtime_info(connected=True)
    with patch.object(input_status, "publish_inputs") as publish:
        core._set_monitor_runtime_info(last_seen_at=5.0)
        core._set_monitor_runtime_info(connected=True)
    publish.assert_not_called()


def test_switching_dynamic_rate_matching_changes_the_note_before_the_push():
    mon = make_monitor(1)
    mon._ingest_status(locked_status(rate_mismatch_hz=44100))
    input_status.publish_inputs()
    assert inputs().rate_texts(1)[0].startswith("This input is delivering")
    seen = []

    def push(target, socket_path=None):
        seen.append(inputs().rate_texts(1)[0])
        return True

    with patch.object(live_config, "_push_input_config_with_retry", push):
        assert live_config.update_live_dynamic_rate_matching(1, True) is True
    assert seen == [input_status.RATE_MATCHING_NOTE_MONITOR_OLD]


def test_changing_the_input_type_updates_the_entry():
    make_monitor(1)
    input_status.publish_inputs()
    with patch.object(live_config, "_push_input_config_with_retry", return_value=True):
        live_config.update_live_input_type(1, "turntable", -50.0)
    assert inputs().entry(1).input_type == "turntable"


def test_an_empty_monitor_list_publishes_an_empty_part():
    make_monitor(1)
    input_status.publish_inputs()
    assert inputs().entries
    with core.runtime._monitors_lock:
        core.runtime.all_monitors.clear()
    input_status.publish_inputs()
    assert inputs() == state.InputsPart()


def test_the_publish_reads_connected_inside_its_lock():
    """Of two concurrent publishers the one that publishes last also read
    last: an older 'connected' cannot overwrite a newer one."""
    make_monitor(1)._ingest_status(locked_status())
    state.store().publish_for_tests("monitor", state.MonitorRuntimeInfo(connected=False))
    entered = threading.Event()
    release = threading.Event()
    real = input_status._build_inputs_part

    def slow(monitors, connected):
        part = real(monitors, connected)
        if not entered.is_set():
            entered.set()
            release.wait(5)
        return part

    with patch.object(input_status, "_build_inputs_part", slow):
        first = threading.Thread(target=input_status.publish_inputs)
        first.start()
        assert entered.wait(5)
        state.store().publish_for_tests("monitor", state.MonitorRuntimeInfo(connected=True))
        second = threading.Thread(target=input_status.publish_inputs)
        second.start()
        second.join(0.1)
        assert second.is_alive()
        release.set()
        first.join(5)
        second.join(5)
    assert inputs().rate_texts(1)[1] == "Sample rate: 48 kHz"
