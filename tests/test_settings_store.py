"""WP1 — SettingsStore unit tests.

Tests cover:
- Initial load from missing and existing config
- Unknown raw keys preserved through mutations
- Mutation preserves unrelated fields
- Repeated mutations before the next save cycle create one write
- Save failure preserves in-memory values and dirty state
- The next cycle retries successfully
- Mutation during an in-progress write remains dirty
- Snapshot mutation cannot affect canonical state
- close() with save=True and save=False
- reload_from_disk() clean and dirty behaviour
- save_now() success and failure
"""
from __future__ import annotations

import copy
import json
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

from autostream_settings import SettingsStore, SETTINGS_SAVE_INTERVAL_SECONDS
from autostream_config import AutostreamConfig, parse_config


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_store(tmp_path, *, raw=None, writer=None, stop_event=None, interval=60.0):
    """Create a SettingsStore backed by a temp file with a long save interval."""
    p = tmp_path / "cfg.json"
    if raw is not None:
        p.write_text(json.dumps(raw))
    return SettingsStore(
        str(p),
        _save_interval_seconds=interval,
        _writer=writer,
        _stop_event=stop_event,
    )


def _minimal_valid_raw() -> dict:
    return {
        "general": {"fifo_path": "/tmp/autostream.fifo"},
        "audio1": {"capture_device": "hw:1,0"},
        "owntone": {"output_name": "Living Room"},
    }


# ---------------------------------------------------------------------------
# Initial load
# ---------------------------------------------------------------------------

class TestInitialLoad:
    def test_missing_file_loads_defaults(self, tmp_path):
        p = tmp_path / "absent.json"
        store = SettingsStore(str(p), _save_interval_seconds=60.0)
        cfg = store.snapshot()
        assert isinstance(cfg, AutostreamConfig)
        # Defaults should be applied
        assert cfg.general.silence_seconds == 30
        store.close(save=False)

    def test_existing_config_loaded(self, tmp_path):
        raw = {"general": {"silence_seconds": 45}}
        store = _make_store(tmp_path, raw=raw)
        cfg = store.snapshot()
        assert cfg.general.silence_seconds == 45
        store.close(save=False)

    def test_store_starts_clean(self, tmp_path):
        store = _make_store(tmp_path, raw=_minimal_valid_raw())
        assert not store._dirty
        store.close(save=False)

    def test_interval_constant_default(self):
        assert SETTINGS_SAVE_INTERVAL_SECONDS == 5.0


# ---------------------------------------------------------------------------
# Snapshot isolation
# ---------------------------------------------------------------------------

class TestSnapshotIsolation:
    def test_snapshot_returns_parsed_config(self, tmp_path):
        store = _make_store(tmp_path, raw={"owntone": {"volume_percent": 42}})
        cfg = store.snapshot()
        assert isinstance(cfg, AutostreamConfig)
        assert cfg.owntone.volume_percent == 42
        store.close(save=False)

    def test_snapshot_mutation_does_not_affect_canonical_state(self, tmp_path):
        raw = {"owntone": {"offsets": {"abc123": 10}}}
        store = _make_store(tmp_path, raw=raw)
        cfg = store.snapshot()
        # Mutate the mutable dict inside the returned snapshot
        cfg.owntone.output_offsets_ms["abc123"] = 999
        # Canonical raw must be unchanged
        raw2 = store.raw_snapshot()
        assert raw2["owntone"]["offsets"]["abc123"] == 10
        store.close(save=False)

    def test_raw_snapshot_is_independent_copy(self, tmp_path):
        store = _make_store(tmp_path, raw={"general": {"silence_seconds": 5}})
        snap = store.raw_snapshot()
        snap["general"]["silence_seconds"] = 99
        snap2 = store.raw_snapshot()
        assert snap2["general"]["silence_seconds"] == 5
        store.close(save=False)

    def test_two_snapshots_are_independent(self, tmp_path):
        raw = {"owntone": {"offsets": {"x": 10}}}
        store = _make_store(tmp_path, raw=raw)
        cfg1 = store.snapshot()
        cfg2 = store.snapshot()
        cfg1.owntone.output_offsets_ms["x"] = 777
        assert cfg2.owntone.output_offsets_ms.get("x") == 10
        store.close(save=False)


# ---------------------------------------------------------------------------
# Unknown keys preserved
# ---------------------------------------------------------------------------

class TestUnknownKeysPreserved:
    def test_unknown_top_level_key_preserved(self, tmp_path):
        raw = {"_custom_section": {"foo": "bar"}}
        store = _make_store(tmp_path, raw=raw)
        snap = store.raw_snapshot()
        assert snap.get("_custom_section") == {"foo": "bar"}
        store.close(save=False)

    def test_unknown_key_survives_mutation(self, tmp_path):
        raw = {
            "_extra": "preserved",
            "general": {"silence_seconds": 10},
        }
        store = _make_store(tmp_path, raw=raw)

        def mutate(r):
            r.setdefault("general", {})["silence_seconds"] = 20

        store.update(mutate)
        snap = store.raw_snapshot()
        assert snap.get("_extra") == "preserved"
        assert snap["general"]["silence_seconds"] == 20
        store.close(save=False)


# ---------------------------------------------------------------------------
# Mutation
# ---------------------------------------------------------------------------

class TestMutation:
    def test_mutation_marks_dirty(self, tmp_path):
        store = _make_store(tmp_path)
        store.update(lambda r: r.update({"general": {"silence_seconds": 5}}))
        assert store._dirty
        store.close(save=False)

    def test_mutation_returns_new_snapshot(self, tmp_path):
        store = _make_store(tmp_path)
        cfg = store.update(lambda r: r.update({"general": {"silence_seconds": 7}}))
        assert isinstance(cfg, AutostreamConfig)
        assert cfg.general.silence_seconds == 7
        store.close(save=False)

    def test_mutation_preserves_unrelated_fields(self, tmp_path):
        raw = {
            "general": {"silence_seconds": 10, "log_level": "debug"},
            "audio1": {"capture_device": "hw:1,0"},
        }
        store = _make_store(tmp_path, raw=raw)

        def only_change_silence(r):
            r.setdefault("general", {})["silence_seconds"] = 99

        store.update(only_change_silence)
        cfg = store.snapshot()
        assert cfg.general.silence_seconds == 99
        assert cfg.general.log_level == "debug"
        assert cfg.audio1.capture_device == "hw:1,0"
        store.close(save=False)

    def test_failed_mutator_leaves_canonical_state_unchanged(self, tmp_path):
        raw = {"general": {"silence_seconds": 10}}
        store = _make_store(tmp_path, raw=raw)

        def bad_mutator(r):
            r["general"]["silence_seconds"] = 99
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError):
            store.update(bad_mutator)

        snap = store.raw_snapshot()
        assert snap["general"]["silence_seconds"] == 10
        assert not store._dirty
        store.close(save=False)

    def test_increments_generation(self, tmp_path):
        store = _make_store(tmp_path)
        gen0 = store._generation
        store.update(lambda r: r.update({"a": 1}))
        assert store._generation == gen0 + 1
        store.update(lambda r: r.update({"b": 2}))
        assert store._generation == gen0 + 2
        store.close(save=False)

    def test_concurrent_mutations_both_survive(self, tmp_path):
        """Two threads mutating different fields should both be reflected."""
        store = _make_store(tmp_path, raw={})
        barrier = threading.Barrier(2)

        def set_a():
            barrier.wait()
            store.update(lambda r: r.update({"field_a": 1}))

        def set_b():
            barrier.wait()
            store.update(lambda r: r.update({"field_b": 2}))

        t1 = threading.Thread(target=set_a)
        t2 = threading.Thread(target=set_b)
        t1.start()
        t2.start()
        t1.join(timeout=5)
        t2.join(timeout=5)

        snap = store.raw_snapshot()
        assert snap.get("field_a") == 1
        assert snap.get("field_b") == 2
        store.close(save=False)


# ---------------------------------------------------------------------------
# Periodic save behaviour
# ---------------------------------------------------------------------------

class TestPeriodicSave:
    def test_repeated_mutations_produce_one_write(self, tmp_path):
        """Multiple mutations before a save cycle result in a single write."""
        writes: list[dict] = []

        def writer(path, data):
            writes.append(copy.deepcopy(data))

        store = _make_store(tmp_path, writer=writer)
        for i in range(5):
            store.update(lambda r, i=i: r.update({"count": i}))

        # Trigger a save cycle manually
        store._run_save_cycle()

        assert len(writes) == 1
        assert writes[0]["count"] == 4  # last value wins
        store.close(save=False)

    def test_clean_store_does_not_write(self, tmp_path):
        writes: list[dict] = []
        store = _make_store(tmp_path, writer=lambda p, d: writes.append(d))
        store._run_save_cycle()
        assert writes == []
        store.close(save=False)

    def test_save_failure_preserves_memory_values(self, tmp_path):
        """A failed write must leave in-memory values and dirty state unchanged."""
        raw = {"general": {"silence_seconds": 42}}
        store = _make_store(tmp_path, raw=raw)
        store.update(lambda r: r.update({"general": {"silence_seconds": 99}}))

        def failing_writer(path, data):
            raise OSError("disk full")

        store._writer = failing_writer
        store._run_save_cycle()

        # Dirty flag must remain set
        assert store._dirty
        # In-memory value must be the mutated one
        assert store.snapshot().general.silence_seconds == 99
        store.close(save=False)

    def test_next_cycle_retries_after_failure(self, tmp_path):
        """After a failed write, the next cycle retries and succeeds."""
        writes: list[dict] = []
        fail_first = [True]

        def writer(path, data):
            if fail_first[0]:
                fail_first[0] = False
                raise OSError("transient error")
            writes.append(copy.deepcopy(data))

        store = _make_store(tmp_path, writer=writer)
        store.update(lambda r: r.update({"retried": True}))

        store._run_save_cycle()   # fails
        assert store._dirty        # still dirty
        store._run_save_cycle()   # succeeds
        assert not store._dirty
        assert writes[-1]["retried"] is True
        store.close(save=False)

    def test_mutation_during_write_keeps_dirty(self, tmp_path):
        """When a mutation arrives while a write is in progress, dirty is not cleared."""
        barrier_enter = threading.Event()
        barrier_exit = threading.Event()
        writes: list[dict] = []

        def slow_writer(path, data):
            writes.append(copy.deepcopy(data))
            barrier_enter.set()
            barrier_exit.wait(timeout=5)

        store = _make_store(tmp_path, writer=slow_writer)
        store.update(lambda r: r.update({"initial": True}))

        # Start the save cycle in a background thread
        save_thread = threading.Thread(target=store._run_save_cycle)
        save_thread.start()

        # Wait until the writer is in progress, then mutate
        barrier_enter.wait(timeout=5)
        store.update(lambda r: r.update({"new_field": "arrived_during_write"}))
        barrier_exit.set()
        save_thread.join(timeout=5)

        # The new mutation should keep the store dirty
        assert store._dirty
        store.close(save=False)


# ---------------------------------------------------------------------------
# save_now
# ---------------------------------------------------------------------------

class TestSaveNow:
    def test_save_now_writes_and_clears_dirty(self, tmp_path):
        written: list[dict] = []
        store = _make_store(tmp_path, writer=lambda p, d: written.append(copy.deepcopy(d)))
        store.update(lambda r: r.update({"x": 1}))
        result = store.save_now()
        assert result is True
        assert not store._dirty
        assert written[-1]["x"] == 1
        store.close(save=False)

    def test_save_now_returns_false_on_failure(self, tmp_path):
        store = _make_store(tmp_path, writer=lambda p, d: (_ for _ in ()).throw(OSError("fail")))
        store.update(lambda r: r.update({"y": 2}))
        result = store.save_now()
        assert result is False
        assert store._dirty
        store.close(save=False)

    def test_save_now_does_not_clear_if_mutation_arrives(self, tmp_path):
        barrier_enter = threading.Event()
        barrier_exit = threading.Event()
        writes: list = []

        def slow_writer(path, data):
            writes.append(data)
            barrier_enter.set()
            barrier_exit.wait(timeout=5)

        store = _make_store(tmp_path, writer=slow_writer)
        store.update(lambda r: r.update({"a": 1}))

        t = threading.Thread(target=store.save_now)
        t.start()
        barrier_enter.wait(timeout=5)
        store.update(lambda r: r.update({"b": 2}))  # arrives during write
        barrier_exit.set()
        t.join(timeout=5)

        assert store._dirty  # new mutation kept dirty
        store.close(save=False)

    def test_save_now_on_clean_store_still_returns_true(self, tmp_path):
        written: list = []
        store = _make_store(tmp_path, writer=lambda p, d: written.append(d))
        # No mutations; store is clean
        result = store.save_now()
        assert result is True
        store.close(save=False)

    def test_save_now_returns_false_on_timeout(self, tmp_path):
        """save_now returns False if the writer hangs longer than the timeout."""
        released = threading.Event()

        def hanging_writer(path, data):
            released.wait()  # hangs indefinitely until test releases it

        store = _make_store(tmp_path, writer=hanging_writer)
        store.update(lambda r: r.update({"hang": True}))
        result = store.save_now(timeout=0.05)  # 50 ms timeout
        released.set()  # unblock the background thread
        assert result is False
        assert store._dirty  # dirty flag must remain set
        store.close(save=False)


# ---------------------------------------------------------------------------
# close()
# ---------------------------------------------------------------------------

class TestClose:
    def test_close_save_true_writes_dirty_state(self, tmp_path):
        written: list[dict] = []
        store = _make_store(tmp_path, writer=lambda p, d: written.append(copy.deepcopy(d)))
        store.update(lambda r: r.update({"closing": True}))
        store.close(save=True)
        assert any(d.get("closing") for d in written)

    def test_close_save_false_does_not_write(self, tmp_path):
        written: list[dict] = []
        store = _make_store(tmp_path, writer=lambda p, d: written.append(copy.deepcopy(d)))
        store.update(lambda r: r.update({"closing": True}))
        store.close(save=False)
        assert not any(d.get("closing") for d in written)

    def test_close_stops_background_thread(self, tmp_path):
        store = _make_store(tmp_path, interval=0.05)
        thread = store._thread
        store.close(save=False)
        assert thread is not None
        assert not thread.is_alive()

    def test_close_idempotent(self, tmp_path):
        store = _make_store(tmp_path)
        store.close(save=False)
        store.close(save=False)  # Should not raise


# ---------------------------------------------------------------------------
# reload_from_disk
# ---------------------------------------------------------------------------

class TestReloadFromDisk:
    def test_reload_clean_store_updates_raw(self, tmp_path):
        p = tmp_path / "cfg.json"
        p.write_text(json.dumps({"a": 1}))
        store = SettingsStore(str(p), _save_interval_seconds=60.0)
        assert store.raw_snapshot().get("a") == 1

        p.write_text(json.dumps({"a": 2}))
        store.reload_from_disk()
        assert store.raw_snapshot().get("a") == 2
        store.close(save=False)

    def test_reload_dirty_store_raises_without_discard(self, tmp_path):
        store = _make_store(tmp_path)
        store.update(lambda r: r.update({"x": 1}))
        assert store._dirty
        with pytest.raises(ValueError, match="dirty"):
            store.reload_from_disk()
        store.close(save=False)

    def test_reload_dirty_with_discard_succeeds(self, tmp_path):
        p = tmp_path / "cfg.json"
        p.write_text(json.dumps({"disk_value": True}))
        store = SettingsStore(str(p), _save_interval_seconds=60.0)
        store.update(lambda r: r.update({"memory_value": True}))
        assert store._dirty

        store.reload_from_disk(discard=True)
        assert not store._dirty
        snap = store.raw_snapshot()
        assert snap.get("disk_value") is True
        assert "memory_value" not in snap
        store.close(save=False)

    def test_reload_clears_dirty_flag(self, tmp_path):
        p = tmp_path / "cfg.json"
        p.write_text("{}")
        store = SettingsStore(str(p), _save_interval_seconds=60.0)
        store.update(lambda r: r.update({"z": 9}))
        store.reload_from_disk(discard=True)
        assert not store._dirty
        store.close(save=False)


# ---------------------------------------------------------------------------
# Background thread integration (short interval)
# ---------------------------------------------------------------------------

class TestBackgroundThread:
    def test_background_thread_saves_dirty_state(self, tmp_path):
        """With a short interval, the background thread eventually saves."""
        written: list[dict] = []

        def writer(path, data):
            written.append(copy.deepcopy(data))

        p = tmp_path / "cfg.json"
        store = SettingsStore(
            str(p),
            _save_interval_seconds=0.05,
            _writer=writer,
        )
        store.update(lambda r: r.update({"bg_test": True}))
        # Wait for background thread to fire
        deadline = time.time() + 2.0
        while time.time() < deadline and not written:
            time.sleep(0.02)
        assert written, "background save never fired"
        assert written[-1].get("bg_test") is True
        store.close(save=False)

    def test_background_thread_does_not_write_when_clean(self, tmp_path):
        """Background thread must not write when the store is clean."""
        writes: list = []
        p = tmp_path / "cfg.json"
        store = SettingsStore(
            str(p),
            _save_interval_seconds=0.05,
            _writer=lambda path, data: writes.append(1),
        )
        # No mutations — store is clean
        time.sleep(0.15)
        assert writes == [], "background thread wrote when clean"
        store.close(save=False)
