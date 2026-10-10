"""Tests for dial_repeat_store.py — the pure per-appliance repeat/replay
belief store.

Covers: parse_repeat_object() strict field-by-field validation, RepeatStore
freshness (RECORD_MAX_AGE_S), apply_ack()'s optimistic replace-in-place,
held_ids(), and prune().
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
for _p in (_DIAL,):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from dial_repeat_store import (
    RECORD_MAX_AGE_S,
    RepeatRecord,
    RepeatStore,
    parse_repeat_object,
)


# ---------------------------------------------------------------------------
# Purity: no hardware/HTTP/display imports, leaf lock only.
# ---------------------------------------------------------------------------

class TestModulePurity:
    def test_only_threading_and_dataclasses_imported(self):
        import dial_repeat_store as m
        import types
        module_names = {
            name for name, val in vars(m).items()
            if isinstance(val, types.ModuleType)
        }
        assert module_names == {"threading"}


# ---------------------------------------------------------------------------
# parse_repeat_object(): strict field-by-field validation.
# ---------------------------------------------------------------------------

def _valid_obj(**overrides) -> dict:
    base = {
        "available": True,
        "state": "hold",
        "armed": False,
        "held": True,
        "recording_seconds": 12.5,
        "replay": {
            "active": False,
            "position_seconds": 0.0,
            "duration_seconds": 12.5,
        },
    }
    base.update(overrides)
    return base


class TestParseRepeatObject:
    def test_valid_object_parses(self):
        rec = parse_repeat_object(_valid_obj(), now=100.0)
        assert rec == RepeatRecord(
            available=True, state="hold", armed=False,
            recording_seconds=12.5, position_seconds=0.0, duration_seconds=12.5,
            observed_at=100.0,
        )

    def test_not_a_dict_returns_none(self):
        assert parse_repeat_object(None, now=1.0) is None
        assert parse_repeat_object("nope", now=1.0) is None
        assert parse_repeat_object([], now=1.0) is None

    def test_missing_available_is_none(self):
        obj = _valid_obj()
        del obj["available"]
        assert parse_repeat_object(obj, now=1.0) is None

    def test_non_bool_available_is_none(self):
        assert parse_repeat_object(_valid_obj(available="yes"), now=1.0) is None

    def test_unknown_state_is_none(self):
        assert parse_repeat_object(_valid_obj(state="playing"), now=1.0) is None

    def test_non_string_state_is_none(self):
        assert parse_repeat_object(_valid_obj(state=1), now=1.0) is None

    def test_every_known_state_accepted(self):
        for state in ("idle", "recording", "hold", "replaying", "fading_out", "pending"):
            rec = parse_repeat_object(_valid_obj(state=state), now=1.0)
            assert rec is not None and rec.state == state

    def test_non_bool_armed_is_none(self):
        assert parse_repeat_object(_valid_obj(armed=1), now=1.0) is None

    def test_non_numeric_recording_seconds_is_none(self):
        assert parse_repeat_object(_valid_obj(recording_seconds="12"), now=1.0) is None

    def test_bool_recording_seconds_is_none(self):
        """bool is an int subclass in Python — must be explicitly rejected."""
        assert parse_repeat_object(_valid_obj(recording_seconds=True), now=1.0) is None

    def test_int_recording_seconds_accepted_and_coerced_to_float(self):
        rec = parse_repeat_object(_valid_obj(recording_seconds=12), now=1.0)
        assert rec.recording_seconds == 12.0
        assert isinstance(rec.recording_seconds, float)

    def test_replay_not_a_dict_is_none(self):
        assert parse_repeat_object(_valid_obj(replay="nope"), now=1.0) is None

    def test_replay_missing_active_is_none(self):
        obj = _valid_obj()
        del obj["replay"]["active"]
        assert parse_repeat_object(obj, now=1.0) is None

    def test_replay_non_bool_active_is_none(self):
        assert parse_repeat_object(
            _valid_obj(replay={"active": "no", "position_seconds": 0.0, "duration_seconds": 1.0}),
            now=1.0,
        ) is None

    def test_replay_non_numeric_position_is_none(self):
        assert parse_repeat_object(
            _valid_obj(replay={"active": True, "position_seconds": "x", "duration_seconds": 1.0}),
            now=1.0,
        ) is None

    def test_replay_bool_position_is_none(self):
        assert parse_repeat_object(
            _valid_obj(replay={"active": True, "position_seconds": True, "duration_seconds": 1.0}),
            now=1.0,
        ) is None

    def test_replay_non_numeric_duration_is_none(self):
        assert parse_repeat_object(
            _valid_obj(replay={"active": True, "position_seconds": 0.0, "duration_seconds": None}),
            now=1.0,
        ) is None

    def test_held_field_is_not_stored(self):
        """held is derivable (state == 'hold'); the object may carry it or
        not, but RepeatRecord never has a held attribute."""
        obj = _valid_obj()
        del obj["held"]
        rec = parse_repeat_object(obj, now=1.0)
        assert rec is not None
        assert not hasattr(rec, "held")

    def test_observed_at_is_the_supplied_now(self):
        rec = parse_repeat_object(_valid_obj(), now=42.5)
        assert rec.observed_at == 42.5


# ---------------------------------------------------------------------------
# RepeatStore: update/get/clear/freshness.
# ---------------------------------------------------------------------------

class TestRepeatStoreUpdateAndGet:
    def test_update_then_get_returns_the_record(self):
        store = RepeatStore()
        rec = parse_repeat_object(_valid_obj(), now=10.0)
        changed = store.update("aid1", rec)
        assert changed is True
        assert store.get("aid1", now=10.0) == rec

    def test_update_with_none_clears_the_record(self):
        store = RepeatStore()
        rec = parse_repeat_object(_valid_obj(), now=10.0)
        store.update("aid1", rec)
        changed = store.update("aid1", None)
        assert changed is True
        assert store.get("aid1", now=10.0) is None

    def test_update_with_none_when_absent_is_noop(self):
        store = RepeatStore()
        assert store.update("aid1", None) is False

    def test_update_with_identical_record_reports_no_change(self):
        store = RepeatStore()
        rec = parse_repeat_object(_valid_obj(), now=10.0)
        store.update("aid1", rec)
        assert store.update("aid1", rec) is False

    def test_update_ignored_for_empty_appliance_id(self):
        store = RepeatStore()
        rec = parse_repeat_object(_valid_obj(), now=10.0)
        assert store.update("", rec) is False
        assert store.get("", now=10.0) is None

    def test_get_returns_none_for_unknown_id(self):
        store = RepeatStore()
        assert store.get("nope", now=10.0) is None

    def test_get_returns_none_for_empty_id(self):
        store = RepeatStore()
        assert store.get("", now=10.0) is None

    def test_clear_removes_the_entry(self):
        store = RepeatStore()
        rec = parse_repeat_object(_valid_obj(), now=10.0)
        store.update("aid1", rec)
        store.clear("aid1")
        assert store.get("aid1", now=10.0) is None

    def test_clear_on_absent_id_is_noop(self):
        store = RepeatStore()
        store.clear("nope")  # must not raise

    def test_clear_ignored_for_empty_appliance_id(self):
        store = RepeatStore()
        store.clear("")  # must not raise


class TestRepeatStoreFreshness:
    def test_get_within_max_age_returns_record(self):
        store = RepeatStore()
        rec = parse_repeat_object(_valid_obj(), now=1000.0)
        store.update("aid1", rec)
        assert store.get("aid1", now=1000.0 + RECORD_MAX_AGE_S) is not None

    def test_get_past_max_age_returns_none(self):
        store = RepeatStore()
        rec = parse_repeat_object(_valid_obj(), now=1000.0)
        store.update("aid1", rec)
        assert store.get("aid1", now=1000.0 + RECORD_MAX_AGE_S + 0.001) is None


# ---------------------------------------------------------------------------
# apply_ack(): optimistic transport/arm-ack update.
# ---------------------------------------------------------------------------

class TestApplyAck:
    def test_replaces_state_armed_position_keeps_recording_and_duration(self):
        store = RepeatStore()
        rec = parse_repeat_object(_valid_obj(
            state="hold", armed=False,
            replay={"active": False, "position_seconds": 0.0, "duration_seconds": 30.0},
            recording_seconds=30.0,
        ), now=10.0)
        store.update("aid1", rec)

        store.apply_ack("aid1", {"state": "replaying", "armed": True, "position_seconds": 5.0},
                         now=11.0)
        updated = store.get("aid1", now=11.0)
        assert updated.state == "replaying"
        assert updated.armed is True
        assert updated.position_seconds == 5.0
        assert updated.recording_seconds == 30.0
        assert updated.duration_seconds == 30.0
        assert updated.observed_at == 11.0

    def test_noop_when_no_record_exists(self):
        store = RepeatStore()
        store.apply_ack("aid1", {"state": "replaying", "armed": True, "position_seconds": 0.0},
                         now=1.0)
        assert store.get("aid1", now=1.0) is None

    def test_noop_for_empty_appliance_id(self):
        store = RepeatStore()
        rec = parse_repeat_object(_valid_obj(), now=1.0)
        store.update("aid1", rec)
        store.apply_ack("", {"state": "replaying", "armed": True, "position_seconds": 0.0}, now=1.0)
        assert store.get("aid1", now=1.0) == rec

    def test_noop_for_non_dict_ack(self):
        store = RepeatStore()
        rec = parse_repeat_object(_valid_obj(), now=1.0)
        store.update("aid1", rec)
        store.apply_ack("aid1", None, now=1.0)
        assert store.get("aid1", now=1.0) == rec

    def test_noop_for_invalid_state_in_ack(self):
        store = RepeatStore()
        rec = parse_repeat_object(_valid_obj(), now=1.0)
        store.update("aid1", rec)
        store.apply_ack("aid1", {"state": "bogus", "armed": True, "position_seconds": 0.0}, now=2.0)
        assert store.get("aid1", now=2.0) == rec

    def test_noop_for_non_bool_armed_in_ack(self):
        store = RepeatStore()
        rec = parse_repeat_object(_valid_obj(), now=1.0)
        store.update("aid1", rec)
        store.apply_ack("aid1", {"state": "hold", "armed": "yes", "position_seconds": 0.0}, now=2.0)
        assert store.get("aid1", now=2.0) == rec

    def test_noop_for_non_numeric_position_in_ack(self):
        store = RepeatStore()
        rec = parse_repeat_object(_valid_obj(), now=1.0)
        store.update("aid1", rec)
        store.apply_ack("aid1", {"state": "hold", "armed": False, "position_seconds": "x"}, now=2.0)
        assert store.get("aid1", now=2.0) == rec


# ---------------------------------------------------------------------------
# held_ids() and prune().
# ---------------------------------------------------------------------------

class TestHeldIds:
    def test_only_hold_state_ids_returned(self):
        store = RepeatStore()
        store.update("hold-id", parse_repeat_object(_valid_obj(state="hold"), now=10.0))
        store.update("replaying-id", parse_repeat_object(_valid_obj(state="replaying"), now=10.0))
        assert store.held_ids(now=10.0) == frozenset({"hold-id"})

    def test_stale_hold_record_excluded(self):
        store = RepeatStore()
        store.update("hold-id", parse_repeat_object(_valid_obj(state="hold"), now=10.0))
        assert store.held_ids(now=10.0 + RECORD_MAX_AGE_S + 1) == frozenset()

    def test_no_records_returns_empty(self):
        store = RepeatStore()
        assert store.held_ids(now=10.0) == frozenset()


class TestPrune:
    def test_drops_ids_not_in_keep_set(self):
        store = RepeatStore()
        store.update("a", parse_repeat_object(_valid_obj(), now=1.0))
        store.update("b", parse_repeat_object(_valid_obj(), now=1.0))
        store.prune({"a"})
        assert store.get("a", now=1.0) is not None
        assert store.get("b", now=1.0) is None

    def test_empty_keep_set_drops_everything(self):
        store = RepeatStore()
        store.update("a", parse_repeat_object(_valid_obj(), now=1.0))
        store.prune(set())
        assert store.get("a", now=1.0) is None

    def test_prune_is_a_noop_when_nothing_to_drop(self):
        store = RepeatStore()
        store.update("a", parse_repeat_object(_valid_obj(), now=1.0))
        store.prune({"a", "b"})
        assert store.get("a", now=1.0) is not None


# ---------------------------------------------------------------------------
# latency_ms -> latency_seconds, and the shared heard-position functions.
# ---------------------------------------------------------------------------

from dial_repeat_store import (
    DEFAULT_LATENCY_S,
    heard_position,
    heard_position_clamped,
    interpolated_position,
)


class TestLatencyParsing:
    def test_absent_means_the_default(self):
        assert parse_repeat_object(_valid_obj(), now=1.0).latency_seconds == 2.0
        assert DEFAULT_LATENCY_S == 2.0

    def test_valid_value_is_converted_to_seconds(self):
        assert parse_repeat_object(_valid_obj(latency_ms=2250), now=1.0).latency_seconds == 2.25
        assert parse_repeat_object(_valid_obj(latency_ms=300), now=1.0).latency_seconds == 0.3
        assert parse_repeat_object(_valid_obj(latency_ms=1500.0), now=1.0).latency_seconds == 1.5

    def test_the_range_edges_are_accepted(self):
        assert parse_repeat_object(_valid_obj(latency_ms=0), now=1.0).latency_seconds == 0.0
        assert parse_repeat_object(_valid_obj(latency_ms=10000), now=1.0).latency_seconds == 10.0

    @pytest.mark.parametrize("bad", [
        -1, -0.5, 10001, 1e12, float("inf"), float("-inf"), float("nan"),
        True, False, "2250", None, [2250], {"ms": 2250},
    ])
    def test_anything_else_means_the_default(self, bad):
        rec = parse_repeat_object(_valid_obj(latency_ms=bad), now=1.0)
        assert rec is not None and rec.latency_seconds == 2.0

    def test_a_bad_latency_never_rejects_the_object(self):
        assert parse_repeat_object(_valid_obj(latency_ms="x"), now=1.0) is not None

    def test_the_field_is_the_last_one_and_defaulted(self):
        rec = RepeatRecord(True, "hold", False, 1.0, 0.0, 0.0, 5.0)
        assert rec.latency_seconds == 2.0

    def test_an_ack_keeps_the_latency(self):
        store = RepeatStore()
        store.update("a" * 20, parse_repeat_object(_valid_obj(latency_ms=900), now=1.0))
        store.apply_ack("a" * 20, {"state": "replaying", "armed": True,
                                   "position_seconds": 0.0}, now=2.0)
        assert store.get("a" * 20, 2.0).latency_seconds == 0.9


def _rec(position=10.0, duration=100.0, observed_at=50.0, latency=2.0):
    return RepeatRecord(True, "replaying", True, 100.0, position, duration,
                        observed_at, latency_seconds=latency)


class TestHeardPosition:
    def test_interpolation_advances_with_wall_time(self):
        assert interpolated_position(_rec(), 53.0) == pytest.approx(13.0)

    def test_interpolation_wraps_at_the_loop_boundary(self):
        # duration 100 + 1.5 s gap
        assert interpolated_position(_rec(position=99.0), 53.0) == pytest.approx(0.5)

    def test_the_heard_position_trails_by_the_latency(self):
        assert heard_position(_rec(latency=0.3), 53.0) == pytest.approx(12.7)
        assert heard_position(_rec(latency=3.5), 53.0) == pytest.approx(9.5)

    def test_the_heard_position_runs_negative_just_after_a_start(self):
        rec = _rec(position=0.0, latency=3.5)
        assert heard_position(rec, 51.0) == pytest.approx(-2.5)

    def test_the_clamped_variant_never_goes_below_zero(self):
        rec = _rec(position=0.0, latency=3.5)
        assert heard_position_clamped(rec, 51.0) == 0.0
        assert heard_position_clamped(rec, 54.5) == pytest.approx(1.0)
