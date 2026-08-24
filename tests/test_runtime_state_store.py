"""RuntimeStateStore unit tests.

Brings the runtime-state file's fields (PIN override, commissioning
marker, known outputs) under the same schema/dirty-flag/debounce discipline
SettingsStore already has, with one CRITICAL exception: PIN-override writes
must be followed by an explicit flush(sync=True) rather than relying on the
debounced default.

Structured to mirror test_settings_store.py's coverage where the two stores
share the same contract shape (dirty-flag, generation counter, save_now,
close), plus schema-specific tests for the four registered runtime_state
rows.
"""
from __future__ import annotations

import copy
import json
import sys
import threading
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

from autostream_runtime_state import RuntimeStateStore, RUNTIME_STATE_SAVE_INTERVAL_SECONDS
from autostream_settings_schema import SETTINGS_SCHEMA, LiveClass, get_field_spec


def _make_store(tmp_path, *, raw=None, writer=None, stop_event=None, interval=60.0):
    p = tmp_path / "state.json"
    if raw is not None:
        p.write_text(json.dumps(raw))
    return RuntimeStateStore(
        str(p),
        _save_interval_seconds=interval,
        _writer=writer,
        _stop_event=stop_event,
    )


# ---------------------------------------------------------------------------
# Schema rows
# ---------------------------------------------------------------------------

class TestRuntimeStateSchemaRows:
    def test_all_four_rows_registered(self):
        for path in (
            "runtime_state.auth.pin_override",
            "runtime_state.first_boot.required",
            "runtime_state.first_boot.completed",
            "runtime_state.owntone.known_outputs",
        ):
            assert path in SETTINGS_SCHEMA, f"{path} missing"

    def test_all_rows_are_runtime_state_store(self):
        for path in (
            "runtime_state.auth.pin_override",
            "runtime_state.first_boot.required",
            "runtime_state.first_boot.completed",
            "runtime_state.owntone.known_outputs",
        ):
            assert SETTINGS_SCHEMA[path].store == "runtime_state"

    def test_all_rows_are_passive(self):
        """Every runtime_state row must be PASSIVE."""
        for path in (
            "runtime_state.auth.pin_override",
            "runtime_state.first_boot.required",
            "runtime_state.first_boot.completed",
            "runtime_state.owntone.known_outputs",
        ):
            assert SETTINGS_SCHEMA[path].live_class == LiveClass.PASSIVE

    def test_register_field_rejects_non_passive_runtime_state_row(self):
        """register_field() must fail fast (at registration, not in
        production) if a runtime_state row is misclassified LIVE/RELOAD."""
        from autostream_settings_schema import register_field

        with pytest.raises(ValueError, match="PASSIVE"):
            register_field(
                "test.bad_runtime_state_row", "test", "k", lambda v: v,
                store="runtime_state", live_class=LiveClass.LIVE,
            )
        assert "test.bad_runtime_state_row" not in SETTINGS_SCHEMA

    def test_pin_override_section_key(self):
        spec = SETTINGS_SCHEMA["runtime_state.auth.pin_override"]
        assert spec.section == "auth"
        assert spec.key == "pin_override"

    def test_known_outputs_section_key(self):
        spec = SETTINGS_SCHEMA["runtime_state.owntone.known_outputs"]
        assert spec.section == "owntone"
        assert spec.key == "known_outputs"


# ---------------------------------------------------------------------------
# Initial load
# ---------------------------------------------------------------------------

class TestInitialLoad:
    def test_missing_file_loads_empty(self, tmp_path):
        p = tmp_path / "absent.json"
        store = RuntimeStateStore(str(p), _save_interval_seconds=60.0)
        assert store.raw_snapshot() == {}
        store.close(save=False)

    def test_existing_state_loaded(self, tmp_path):
        raw = {"auth": {"pin_override": "1234"}}
        store = _make_store(tmp_path, raw=raw)
        assert store.raw_snapshot()["auth"]["pin_override"] == "1234"
        store.close(save=False)

    def test_store_starts_clean(self, tmp_path):
        store = _make_store(tmp_path, raw={})
        assert not store._dirty
        store.close(save=False)

    def test_interval_constant_default(self):
        assert RUNTIME_STATE_SAVE_INTERVAL_SECONDS == 5.0


# ---------------------------------------------------------------------------
# get/set
# ---------------------------------------------------------------------------

class TestGetSet:
    def test_get_unset_field_is_none(self, tmp_path):
        store = _make_store(tmp_path, raw={})
        assert store.get("runtime_state.auth.pin_override") is None
        store.close(save=False)

    def test_set_then_get_roundtrips(self, tmp_path):
        store = _make_store(tmp_path, raw={})
        store.set("runtime_state.auth.pin_override", "9999")
        assert store.get("runtime_state.auth.pin_override") == "9999"
        store.close(save=False)

    def test_set_marks_dirty(self, tmp_path):
        store = _make_store(tmp_path, raw={})
        store.set("runtime_state.first_boot.required", True)
        assert store._dirty
        store.close(save=False)

    def test_set_unknown_path_raises_keyerror(self, tmp_path):
        store = _make_store(tmp_path, raw={})
        with pytest.raises(KeyError):
            store.set("runtime_state.nonexistent.field", 1)
        store.close(save=False)

    def test_set_settings_store_path_rejected(self, tmp_path):
        """A path registered under store="settings" (not "runtime_state")
        must not be settable through RuntimeStateStore -- the two stores
        are backed by different files and must not silently cross-write."""
        import autostream_webui_api  # noqa: F401 -- registers a "settings" row
        store = _make_store(tmp_path, raw={})
        with pytest.raises(ValueError, match="not a runtime_state"):
            store.set("webui.dark_mode", True)
        store.close(save=False)

    def test_pin_override_validator_strips_whitespace(self, tmp_path):
        store = _make_store(tmp_path, raw={})
        normalized = store.set("runtime_state.auth.pin_override", "  4242  ")
        assert normalized == "4242"
        store.close(save=False)

    def test_known_outputs_set_replaces_whole_dict(self, tmp_path):
        store = _make_store(tmp_path, raw={"owntone": {"known_outputs": {"a": "old"}}})
        store.set("runtime_state.owntone.known_outputs", {"a": "new", "b": "second"})
        assert store.get("runtime_state.owntone.known_outputs") == {"a": "new", "b": "second"}
        store.close(save=False)

    def test_set_preserves_unrelated_sections(self, tmp_path):
        raw = {"auth": {"pin_override": "1111"}, "first_boot": {"required": True, "completed": False}}
        store = _make_store(tmp_path, raw=raw)
        store.set("runtime_state.first_boot.completed", True)
        snap = store.raw_snapshot()
        assert snap["auth"]["pin_override"] == "1111"
        assert snap["first_boot"]["required"] is True
        assert snap["first_boot"]["completed"] is True
        store.close(save=False)


# ---------------------------------------------------------------------------
# update() -- lower-level mutator, mirrors SettingsStore.update()
# ---------------------------------------------------------------------------

class TestUpdate:
    def test_update_applies_mutator(self, tmp_path):
        store = _make_store(tmp_path, raw={})
        store.update(lambda r: r.setdefault("owntone", {}).setdefault("known_outputs", {}).update({"x": "y"}))
        assert store.raw_snapshot()["owntone"]["known_outputs"] == {"x": "y"}
        store.close(save=False)

    def test_failed_mutator_leaves_state_unchanged(self, tmp_path):
        store = _make_store(tmp_path, raw={"a": 1})

        def bad(r):
            r["a"] = 2
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError):
            store.update(bad)
        assert store.raw_snapshot()["a"] == 1
        assert not store._dirty
        store.close(save=False)


# ---------------------------------------------------------------------------
# Periodic save / debounce
# ---------------------------------------------------------------------------

class TestPeriodicSave:
    def test_repeated_sets_produce_one_write(self, tmp_path):
        writes: list[dict] = []
        store = _make_store(tmp_path, writer=lambda p, d: writes.append(copy.deepcopy(d)))
        for i in range(5):
            store.set("runtime_state.first_boot.required", bool(i % 2))
        store._run_save_cycle()
        assert len(writes) == 1
        store.close(save=False)

    def test_clean_store_does_not_write(self, tmp_path):
        writes: list = []
        store = _make_store(tmp_path, writer=lambda p, d: writes.append(1))
        store._run_save_cycle()
        assert writes == []
        store.close(save=False)

    def test_background_thread_eventually_saves(self, tmp_path):
        written: list[dict] = []
        p = tmp_path / "state.json"
        store = RuntimeStateStore(
            str(p), _save_interval_seconds=0.05,
            _writer=lambda path, data: written.append(copy.deepcopy(data)),
        )
        store.set("runtime_state.first_boot.required", True)
        deadline = time.time() + 2.0
        while time.time() < deadline and not written:
            time.sleep(0.02)
        assert written, "background save never fired"
        store.close(save=False)


# ---------------------------------------------------------------------------
# flush() -- the CRITICAL PIN-override synchronous-durability exception
# ---------------------------------------------------------------------------

class TestFlushSyncException:
    def test_flush_default_is_debounced_and_returns_true_without_writing(self, tmp_path):
        writes: list = []
        store = _make_store(tmp_path, writer=lambda p, d: writes.append(1))
        store.set("runtime_state.auth.pin_override", "1234")
        result = store.flush()  # sync=False default
        assert result is True
        assert writes == [], "debounced flush() must not write synchronously"
        assert store._dirty, "debounced flush() must leave the field dirty for the background cycle"
        store.close(save=False)

    def test_flush_sync_true_writes_immediately(self, tmp_path):
        writes: list = []
        store = _make_store(tmp_path, writer=lambda p, d: writes.append(copy.deepcopy(d)))
        store.set("runtime_state.auth.pin_override", "5678")
        result = store.flush(sync=True)
        assert result is True
        assert not store._dirty
        assert writes and writes[-1]["auth"]["pin_override"] == "5678"
        store.close(save=False)

    def test_pin_override_write_then_sync_flush_is_durable_immediately(self, tmp_path):
        """The documented pattern any future PIN-write call site must
        follow: set() (debounced) + flush(sync=True) (CRITICAL exception)."""
        writes: list = []
        store = _make_store(tmp_path, writer=lambda p, d: writes.append(copy.deepcopy(d)))
        store.set("runtime_state.auth.pin_override", "4444")
        ok = store.flush(sync=True)
        assert ok is True
        assert writes[-1]["auth"]["pin_override"] == "4444"
        assert not store._dirty
        store.close(save=False)


# ---------------------------------------------------------------------------
# save_now / close (same contract as SettingsStore)
# ---------------------------------------------------------------------------

class TestSaveNowAndClose:
    def test_save_now_writes_and_clears_dirty(self, tmp_path):
        written: list = []
        store = _make_store(tmp_path, writer=lambda p, d: written.append(copy.deepcopy(d)))
        store.set("runtime_state.first_boot.required", True)
        assert store.save_now() is True
        assert not store._dirty
        store.close(save=False)

    def test_save_now_returns_false_on_failure(self, tmp_path):
        store = _make_store(tmp_path, writer=lambda p, d: (_ for _ in ()).throw(OSError("fail")))
        store.set("runtime_state.first_boot.required", True)
        assert store.save_now() is False
        assert store._dirty
        store.close(save=False)

    def test_close_save_true_writes_dirty_state(self, tmp_path):
        written: list = []
        store = _make_store(tmp_path, writer=lambda p, d: written.append(1))
        store.set("runtime_state.first_boot.required", True)
        store.close(save=True)
        assert written

    def test_close_idempotent(self, tmp_path):
        store = _make_store(tmp_path)
        store.close(save=False)
        store.close(save=False)  # must not raise
