"""tests/test_runtime.py

The process-wide runtime primitives: stop and reload events, and the helper
that resets them between tests.
"""
import sys
from pathlib import Path

_CORE = str(Path(__file__).parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_runtime as runtime


def test_request_config_reload_sets_the_reload_flag():
    runtime.reload_flag.clear()
    runtime.request_config_reload()
    assert runtime.reload_flag.is_set()
    runtime.reload_flag.clear()


def test_reset_for_tests_clears_both_events():
    runtime.stop_flag.set()
    runtime.reload_flag.set()
    runtime.reset_for_tests()
    assert not runtime.stop_flag.is_set()
    assert not runtime.reload_flag.is_set()


def test_the_task_pool_accessor_returns_the_shared_pool():
    assert runtime.get_task_pool() is runtime._task_pool


def test_monitors_snapshot_is_a_copy_taken_under_the_lock():
    sentinel = object()
    runtime.all_monitors.append(sentinel)
    snap = runtime.monitors_snapshot()
    assert snap == [sentinel]
    snap.clear()
    assert runtime.all_monitors == [sentinel]
    runtime.reset_for_tests()
    assert runtime.all_monitors == []


def test_reset_for_tests_clears_the_registry():
    runtime._playback_tracker = object()
    runtime._track_id_service = object()
    runtime.reset_for_tests()
    assert runtime._playback_tracker is None
    assert runtime._track_id_service is None


def test_reset_for_tests_frees_a_held_admission_gate():
    gate = runtime._track_id_request_gate
    assert gate.acquire(blocking=False)
    runtime.reset_for_tests()
    assert runtime._track_id_request_gate is not gate
    assert runtime._track_id_request_gate.acquire(blocking=False)
    runtime._track_id_request_gate.release()


def test_the_metadata_push_stamp_is_none_until_noted():
    runtime.reset_for_tests()
    assert runtime.last_metadata_push() is None


def test_the_metadata_push_stamp_keeps_the_time_given():
    runtime.note_metadata_push(12.5)
    assert runtime.last_metadata_push() == 12.5
    runtime.note_metadata_push(20.0)
    assert runtime.last_metadata_push() == 20.0


def test_the_metadata_push_stamp_defaults_to_the_monotonic_clock():
    import time
    before = time.monotonic()
    runtime.note_metadata_push()
    assert before <= runtime.last_metadata_push() <= time.monotonic()


def test_reset_for_tests_clears_the_metadata_push_stamp():
    runtime.note_metadata_push(5.0)
    runtime.reset_for_tests()
    assert runtime.last_metadata_push() is None


def test_lifecycle_is_over_the_current_stop_event():
    life = runtime.lifecycle()
    assert life.stop is runtime.stop_flag
    assert not life.stopping()
    runtime.stop_flag.set()
    assert life.stopping()
    runtime.reset_for_tests()


def test_lifecycle_follows_a_replaced_stop_event(monkeypatch):
    import threading
    replacement = threading.Event()
    monkeypatch.setattr(runtime, "stop_flag", replacement)
    assert runtime.lifecycle().stop is replacement


def test_lifecycle_wait_returns_true_once_stopping():
    import threading
    life = runtime.Lifecycle(threading.Event())
    assert life.wait(0.01) is False
    life.stop.set()
    assert life.wait(0.01) is True
