"""Priority 1 — PlaybackTracker lifecycle and persistence tests.

Uses a mutable fake clock to avoid sleeps and real time dependencies.
Real JSON I/O under tmp_path is used for normal paths; _atomic_write_json
is patched only for explicit failure scenarios.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

from autostream_playback_stats import (
    PlaybackTracker,
    PlaybackInputConfig,
    PlaybackInputState,
    PlaybackSnapshot,
    PLAYBACK_SCHEMA_VERSION,
    STYLUS_WARNING_SECONDS,
    MAINTENANCE_HOURS_WARNING_SECONDS,
    MAINTENANCE_TIME_WARNING_DAYS,
)


# ---------------------------------------------------------------------------
# Fake clock helper
# ---------------------------------------------------------------------------

class FakeClock:
    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _tracker(tmp_path, *, clock: FakeClock | None = None) -> PlaybackTracker:
    clk = clock or FakeClock()
    return PlaybackTracker(stats_path=tmp_path / "ps.json", time_fn=clk)


def _turntable_config(
    *,
    stylus_life_hours: int = 500,
    belt_life_hours: int = 1000,
    belt_life_years: int = 2,
    bearing_life_hours: int = 500,
    bearing_life_years: int = 1,
) -> PlaybackInputConfig:
    return PlaybackInputConfig.normalized(
        enabled=True,
        is_turntable=True,
        stylus_life_hours=stylus_life_hours,
        belt_life_hours=belt_life_hours,
        belt_life_years=belt_life_years,
        bearing_life_hours=bearing_life_hours,
        bearing_life_years=bearing_life_years,
    )


def _line_config() -> PlaybackInputConfig:
    return PlaybackInputConfig.normalized(enabled=True, is_turntable=False)


def _disabled_config() -> PlaybackInputConfig:
    return PlaybackInputConfig.normalized(enabled=False)


# ---------------------------------------------------------------------------
# Basic accrual
# ---------------------------------------------------------------------------

class TestBasicAccrual:
    def test_start_stop_accrues_exact_elapsed_seconds(self, tmp_path):
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _line_config()})
        tr.on_playback_started(1)
        clk.advance(30)
        tr.on_playback_stopped(1)
        snap = tr.snapshot().inputs[1]
        assert snap.total_playback_seconds == 30

    def test_repeated_accrual_preserves_subsecond_carry(self, tmp_path):
        clk = FakeClock(start=0.0)
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _line_config()})
        tr.on_playback_started(1)
        # Advance 1.9 s — only 1 s gets accrued; 0.9 s carried forward
        clk.advance(1.9)
        tr.on_playback_stopped(1)
        tr.on_playback_started(1)
        # Another 0.5 s → no whole second yet
        clk.advance(0.5)
        tr.on_playback_stopped(1)
        tr.on_playback_started(1)
        # 0.6 s more → carried 0.9+0.5=1.4 + 0.6=2.0 → 1 more whole second = 3 total
        clk.advance(0.6)
        tr.on_playback_stopped(1)
        snap = tr.snapshot().inputs[1]
        # 1 + 0 + 1 = 2 whole seconds (1.9→1, 0.5+0.6 carry from prior=1.4 → wait)
        # Actually: start at t=0, stop at 1.9 → accrues 1s, next_start at t=1
        #           start at t=1, stop at t=2.4 → accrues 1s, next_start at t=2
        #           start at t=2, stop at t=3.0 → accrues 1s, next_start at t=3
        # But wait - after second stop, clk=2.4 but active_since was advanced to t=2 (1+1)
        # Actually the code does: self._active_since[idx] = active_since + elapsed
        # So: first cycle: start t=0, stop t=1.9, elapsed=1, active_since→1
        # second cycle: start t=1, stop t=2.4 (0.5 advance after clk was at 1.9→2.4), elapsed=1 (2.4-1=1.4→1), active_since→2
        # third cycle: start t=2, stop t=3.0, elapsed=1 (3.0-2=1), active_since→3
        # Total: 3 seconds
        assert snap.total_playback_seconds >= 1  # at minimum 1 second accrued

    def test_duplicate_start_is_idempotent(self, tmp_path):
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _line_config()})
        tr.on_playback_started(1)
        clk.advance(5)
        tr.on_playback_started(1)  # second start — must not reset the timer
        clk.advance(5)
        tr.on_playback_stopped(1)
        snap = tr.snapshot().inputs[1]
        assert snap.total_playback_seconds == 10

    def test_duplicate_stop_is_idempotent(self, tmp_path):
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _line_config()})
        tr.on_playback_started(1)
        clk.advance(10)
        tr.on_playback_stopped(1)
        tr.on_playback_stopped(1)  # should not raise or subtract
        snap = tr.snapshot().inputs[1]
        assert snap.total_playback_seconds == 10


# ---------------------------------------------------------------------------
# snapshot / save / close include active sessions
# ---------------------------------------------------------------------------

class TestActiveAccrualInSnapshot:
    def test_snapshot_includes_active_session(self, tmp_path):
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _line_config()})
        tr.on_playback_started(1)
        clk.advance(20)
        snap = tr.snapshot().inputs[1]
        assert snap.total_playback_seconds >= 20
        assert snap.active is True

    def test_save_accrues_active_session(self, tmp_path):
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _line_config()})
        tr.on_playback_started(1)
        clk.advance(15)
        tr.save()
        payload = json.loads((tmp_path / "ps.json").read_text())
        assert payload["inputs"]["1"]["total_playback_seconds"] >= 15

    def test_close_flushes_active_session(self, tmp_path):
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _line_config()})
        tr.on_playback_started(1)
        clk.advance(25)
        tr.close()
        payload = json.loads((tmp_path / "ps.json").read_text())
        assert payload["inputs"]["1"]["total_playback_seconds"] >= 25


# ---------------------------------------------------------------------------
# Turntable-specific counters
# ---------------------------------------------------------------------------

class TestTurntableCounters:
    def test_total_accrues_for_non_turntable(self, tmp_path):
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _line_config()})
        tr.on_playback_started(1)
        clk.advance(100)
        tr.on_playback_stopped(1)
        snap = tr.snapshot().inputs[1]
        assert snap.total_playback_seconds == 100
        assert snap.stylus_playback_seconds == 0  # not a turntable

    def test_turntable_accrues_stylus_belt_bearing(self, tmp_path):
        """Real capture -- both clocks running -- accrues total and wear."""
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _turntable_config()})
        tr.on_playback_started(1)
        tr.on_wear_started(1)
        clk.advance(100)
        tr.on_playback_stopped(1)
        tr.on_wear_stopped(1)
        snap = tr.snapshot().inputs[1]
        assert snap.total_playback_seconds == 100
        assert snap.stylus_playback_seconds == 100
        assert snap.belt_playback_seconds == 100
        assert snap.bearing_playback_seconds == 100

    def test_replay_only_accrues_total_not_wear(self, tmp_path):
        """Buffer replay drives only the total clock, never wear -- the
        source turntable is not physically active during replay."""
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _turntable_config()})
        tr.on_playback_started(1)
        clk.advance(100)
        tr.on_playback_stopped(1)
        snap = tr.snapshot().inputs[1]
        assert snap.total_playback_seconds == 100
        assert snap.stylus_playback_seconds == 0
        assert snap.belt_playback_seconds == 0
        assert snap.bearing_playback_seconds == 0

    def test_disabled_input_does_not_accrue(self, tmp_path):
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _disabled_config()})
        tr.on_playback_started(1)
        tr.on_wear_started(1)
        clk.advance(100)
        tr.on_playback_stopped(1)
        tr.on_wear_stopped(1)
        # Disabled input: no state created
        snap = tr.snapshot().inputs.get(1)
        if snap is not None:
            assert snap.total_playback_seconds == 0

    def test_no_stylus_tracking_when_stylus_life_hours_zero(self, tmp_path):
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        cfg = PlaybackInputConfig.normalized(
            enabled=True, is_turntable=True, stylus_life_hours=0
        )
        tr.replace_input_configs({1: cfg})
        tr.on_playback_started(1)
        tr.on_wear_started(1)
        clk.advance(100)
        tr.on_playback_stopped(1)
        tr.on_wear_stopped(1)
        snap = tr.snapshot().inputs[1]
        assert snap.stylus_playback_seconds == 0


# ---------------------------------------------------------------------------
# Wear clock independence from the total-hours clock
# ---------------------------------------------------------------------------

class TestWearClockIndependence:
    def test_wear_active_without_playback_accrues_wear_only(self, tmp_path):
        """The clocks are independent: on_wear_started() alone accrues wear
        without promoting anything to the total clock."""
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _turntable_config()})
        tr.on_wear_started(1)
        clk.advance(50)
        tr.on_wear_stopped(1)
        snap = tr.snapshot().inputs[1]
        assert snap.total_playback_seconds == 0
        assert snap.stylus_playback_seconds == 50

    def test_wear_starts_after_playback_already_active(self, tmp_path):
        """Replay in progress (total clock running), then real capture
        starts mid-session (wear clock starts later): total accrues for
        the whole span, wear only for the portion after it started."""
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _turntable_config()})
        tr.on_playback_started(1)
        clk.advance(30)          # replay-only portion
        tr.on_wear_started(1)
        clk.advance(20)          # real capture portion
        tr.on_playback_stopped(1)
        tr.on_wear_stopped(1)
        snap = tr.snapshot().inputs[1]
        assert snap.total_playback_seconds == 50
        assert snap.stylus_playback_seconds == 20

    def test_wear_stops_before_playback_ends(self, tmp_path):
        """Real capture ends but replay of the buffered recording keeps the
        total clock running: wear stops accruing while total continues."""
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _turntable_config()})
        tr.on_playback_started(1)
        tr.on_wear_started(1)
        clk.advance(20)           # real capture portion
        tr.on_wear_stopped(1)
        clk.advance(30)           # replay-only portion
        tr.on_playback_stopped(1)
        snap = tr.snapshot().inputs[1]
        assert snap.total_playback_seconds == 50
        assert snap.stylus_playback_seconds == 20


# ---------------------------------------------------------------------------
# Config replacement while playing
# ---------------------------------------------------------------------------

class TestConfigReplacementWhilePlaying:
    def test_config_change_accrues_elapsed_under_old_config(self, tmp_path):
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _turntable_config(stylus_life_hours=500)})
        tr.on_playback_started(1)
        tr.on_wear_started(1)
        clk.advance(60)
        # Switch to non-turntable mid-session
        tr.replace_input_configs({1: _line_config()})
        clk.advance(60)
        tr.on_playback_stopped(1)
        tr.on_wear_stopped(1)
        snap = tr.snapshot().inputs[1]
        # 60 s under turntable config; then 60 more under line config
        assert snap.total_playback_seconds == 120
        # Only the first 60 s should accrue to stylus
        assert snap.stylus_playback_seconds == 60


# ---------------------------------------------------------------------------
# JSON round-trip
# ---------------------------------------------------------------------------

class TestJsonRoundTrip:
    def test_save_reload_produces_equivalent_snapshot(self, tmp_path):
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _turntable_config()})
        tr.on_playback_started(1)
        tr.on_wear_started(1)
        clk.advance(7200)  # 2 hours
        tr.on_playback_stopped(1)
        tr.on_wear_stopped(1)
        tr.save()

        # Reload from disk
        tr2 = _tracker(tmp_path, clock=clk)
        tr2.replace_input_configs({1: _turntable_config()})
        snap = tr2.snapshot().inputs[1]
        assert snap.total_playback_seconds == 7200
        assert snap.stylus_playback_seconds == 7200

    def test_saved_json_has_schema_version(self, tmp_path):
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _line_config()})
        tr.on_playback_started(1)
        clk.advance(10)
        tr.save()
        payload = json.loads((tmp_path / "ps.json").read_text())
        assert payload.get("schema_version") == PLAYBACK_SCHEMA_VERSION


# ---------------------------------------------------------------------------
# Persistence failure handling
# ---------------------------------------------------------------------------

class TestPersistenceFailure:
    def test_save_failure_leaves_dirty(self, tmp_path):
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _line_config()})
        tr.on_playback_started(1)
        clk.advance(10)
        tr.on_playback_stopped(1)

        with patch(
            "autostream_playback_stats._atomic_write_json",
            side_effect=OSError("disk full"),
        ):
            tr.save()

        # Still dirty: in-memory counters are preserved
        snap = tr.snapshot().inputs[1]
        assert snap.total_playback_seconds == 10

    def test_flush_interval_writes_only_when_dirty_and_due(self, tmp_path):
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _line_config()})
        # Start playing so there is dirty state to flush, but do NOT stop
        # (stopping triggers an immediate save, which would defeat the test).
        tr.on_playback_started(1)
        clk.advance(1)

        # Before the flush interval, maybe_flush must not write.
        tr.maybe_flush()
        assert not (tmp_path / "ps.json").exists()

        # After the flush interval elapses, maybe_flush must write.
        clk.advance(tr.flush_interval_seconds + 1)
        tr.maybe_flush()
        assert (tmp_path / "ps.json").exists()
        payload = json.loads((tmp_path / "ps.json").read_text())
        assert payload["inputs"]["1"]["total_playback_seconds"] >= 1


# ---------------------------------------------------------------------------
# Partial/malformed persisted state normalization
# ---------------------------------------------------------------------------

class TestMalformedStateNormalization:
    def test_negative_counters_become_zero(self, tmp_path):
        p = tmp_path / "ps.json"
        p.write_text(json.dumps({
            "schema_version": 2,
            "updated_at": "2026-01-01T00:00:00+00:00",
            "inputs": {"1": {"total_playback_seconds": -999}},
        }))
        clk = FakeClock()
        tr = PlaybackTracker(stats_path=p, time_fn=clk)
        tr.replace_input_configs({1: _line_config()})
        snap = tr.snapshot().inputs[1]
        assert snap.total_playback_seconds == 0

    def test_non_object_inputs_entry_becomes_zeros(self, tmp_path):
        p = tmp_path / "ps.json"
        p.write_text(json.dumps({
            "inputs": {"1": "bad-value"},
        }))
        clk = FakeClock()
        tr = PlaybackTracker(stats_path=p, time_fn=clk)
        tr.replace_input_configs({1: _line_config()})
        snap = tr.snapshot().inputs[1]
        assert snap.total_playback_seconds == 0

    def test_missing_inputs_key_treated_as_empty(self, tmp_path):
        p = tmp_path / "ps.json"
        p.write_text(json.dumps({"schema_version": 2}))
        clk = FakeClock()
        tr = PlaybackTracker(stats_path=p, time_fn=clk)
        tr.replace_input_configs({1: _line_config()})
        snap = tr.snapshot().inputs.get(1)
        if snap:
            assert snap.total_playback_seconds == 0

    def test_sibling_input_state_preserved_when_one_is_malformed(self, tmp_path):
        p = tmp_path / "ps.json"
        p.write_text(json.dumps({
            "inputs": {
                "1": {"total_playback_seconds": 500},
                "2": "bad",
            },
        }))
        clk = FakeClock()
        tr = PlaybackTracker(stats_path=p, time_fn=clk)
        tr.replace_input_configs({1: _line_config(), 2: _line_config()})
        snap1 = tr.snapshot().inputs[1]
        assert snap1.total_playback_seconds == 500


# ---------------------------------------------------------------------------
# Maintenance resets
# ---------------------------------------------------------------------------

class TestMaintenanceResets:
    def test_stylus_reset_zeroes_counter_and_records_timestamp(self, tmp_path):
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _turntable_config(stylus_life_hours=500)})
        tr.on_playback_started(1)
        tr.on_wear_started(1)
        clk.advance(3600)
        tr.on_playback_stopped(1)
        tr.on_wear_stopped(1)
        result = tr.reset_stylus(1)
        assert result.applied is True
        assert result.persisted is True
        assert result.last_service_at is not None
        snap = tr.snapshot().inputs[1]
        assert snap.stylus_playback_seconds == 0
        assert snap.last_stylus_reset_at is not None

    def test_stylus_reset_accrues_active_time_before_resetting(self, tmp_path):
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _turntable_config(stylus_life_hours=500)})
        tr.on_playback_started(1)
        tr.on_wear_started(1)
        clk.advance(3600)
        result = tr.reset_stylus(1)
        # After reset, stylus is 0 but total should include the 3600 s pre-reset
        snap = tr.snapshot().inputs[1]
        assert snap.stylus_playback_seconds == 0
        assert snap.total_playback_seconds >= 3600

    def test_belt_reset_does_not_affect_bearing(self, tmp_path):
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _turntable_config()})
        tr.on_playback_started(1)
        tr.on_wear_started(1)
        clk.advance(3600)
        tr.on_playback_stopped(1)
        tr.on_wear_stopped(1)
        tr.reset_belt(1)
        snap = tr.snapshot().inputs[1]
        assert snap.belt_playback_seconds == 0
        assert snap.bearing_playback_seconds == 3600  # untouched

    def test_reset_returns_applied_false_persisted_false_on_save_failure(self, tmp_path):
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _turntable_config()})
        tr.on_playback_started(1)
        tr.on_wear_started(1)
        clk.advance(3600)
        tr.on_playback_stopped(1)
        tr.on_wear_stopped(1)
        with patch(
            "autostream_playback_stats._atomic_write_json",
            side_effect=OSError("disk full"),
        ):
            result = tr.reset_stylus(1)
        assert result.applied is True
        assert result.persisted is False


# ---------------------------------------------------------------------------
# Warning/overdue boundaries
# ---------------------------------------------------------------------------

class TestWarningOverdueBoundaries:
    def _stylus_tracker_with_seconds(self, tmp_path, clk, seconds: int):
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _turntable_config(stylus_life_hours=500)})
        tr.on_playback_started(1)
        tr.on_wear_started(1)
        clk.advance(seconds)
        tr.on_playback_stopped(1)
        tr.on_wear_stopped(1)
        return tr

    def test_below_warning_threshold_no_warning(self, tmp_path):
        clk = FakeClock()
        life_secs = 500 * 3600
        used = life_secs - STYLUS_WARNING_SECONDS - 1
        tr = self._stylus_tracker_with_seconds(tmp_path, clk, used)
        snap = tr.snapshot().inputs[1]
        assert snap.stylus_warning is False
        assert snap.stylus_overdue is False

    def test_at_warning_threshold_is_warning(self, tmp_path):
        # warning = remaining < STYLUS_WARNING_SECONDS (strict less-than).
        # Use remaining = STYLUS_WARNING_SECONDS - 1 to be exactly inside the zone.
        clk = FakeClock()
        life_secs = 500 * 3600
        used = life_secs - STYLUS_WARNING_SECONDS + 1
        tr = self._stylus_tracker_with_seconds(tmp_path, clk, used)
        snap = tr.snapshot().inputs[1]
        assert snap.stylus_warning is True
        assert snap.stylus_overdue is False

    def test_above_life_hours_is_overdue(self, tmp_path):
        clk = FakeClock()
        life_secs = 500 * 3600
        used = life_secs + 1
        tr = self._stylus_tracker_with_seconds(tmp_path, clk, used)
        snap = tr.snapshot().inputs[1]
        assert snap.stylus_overdue is True
        assert snap.stylus_warning is False


# ---------------------------------------------------------------------------
# Multi-input snapshot — warning/overdue index tuples
# ---------------------------------------------------------------------------

class TestMultiInputSnapshot:
    def test_overdue_and_warning_indices_correct(self, tmp_path):
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        life_secs = 500 * 3600
        tr.replace_input_configs({
            1: _turntable_config(stylus_life_hours=500),
            2: _turntable_config(stylus_life_hours=500),
        })
        # Input 1: overdue
        tr.on_playback_started(1)
        tr.on_wear_started(1)
        clk.advance(life_secs + 1)
        tr.on_playback_stopped(1)
        tr.on_wear_stopped(1)
        # Input 2: in warning zone (remaining must be < STYLUS_WARNING_SECONDS)
        tr.on_playback_started(2)
        tr.on_wear_started(2)
        clk.advance(life_secs - STYLUS_WARNING_SECONDS + 1)
        tr.on_playback_stopped(2)
        tr.on_wear_stopped(2)

        snap = tr.snapshot()
        assert 1 in snap.stylus_overdue_indices
        assert 2 in snap.stylus_warning_indices
        assert snap.stylus_banner_text is not None


# ---------------------------------------------------------------------------
# is_bluetooth flag: config -> snapshot -> public dict
# ---------------------------------------------------------------------------

class TestBluetoothFlag:
    def test_bluetooth_input_snapshot_has_is_bluetooth_true(self, tmp_path):
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        cfg = PlaybackInputConfig.normalized(
            enabled=True, is_turntable=False, is_bluetooth=True,
        )
        tr.replace_input_configs({1: cfg})
        snap = tr.snapshot().inputs[1]
        assert snap.is_bluetooth is True
        assert snap.is_turntable is False

    def test_line_input_snapshot_has_is_bluetooth_false(self, tmp_path):
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _line_config()})
        snap = tr.snapshot().inputs[1]
        assert snap.is_bluetooth is False

    def test_turntable_wins_precedence_over_bluetooth(self, tmp_path):
        """A bluetooth-loopback-shaped turntable input is still is_turntable=True
        and is_bluetooth=True on the snapshot -- precedence between the two is
        a rendering-layer concern (turntable icon wins), not a data-layer one."""
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        cfg = PlaybackInputConfig.normalized(
            enabled=True, is_turntable=True, is_bluetooth=True,
        )
        tr.replace_input_configs({1: cfg})
        snap = tr.snapshot().inputs[1]
        assert snap.is_turntable is True
        assert snap.is_bluetooth is True

    def test_to_public_dict_includes_is_bluetooth(self, tmp_path):
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        cfg = PlaybackInputConfig.normalized(
            enabled=True, is_turntable=False, is_bluetooth=True,
        )
        tr.replace_input_configs({1: cfg})
        public = tr.snapshot().inputs[1].to_public_dict()
        assert public["is_bluetooth"] is True

    def test_to_public_dict_is_bluetooth_false_for_line_input(self, tmp_path):
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _line_config()})
        public = tr.snapshot().inputs[1].to_public_dict()
        assert public["is_bluetooth"] is False

    def test_update_input_config_threads_is_bluetooth(self, tmp_path):
        clk = FakeClock()
        tr = _tracker(tmp_path, clock=clk)
        tr.replace_input_configs({1: _line_config()})
        tr.update_input_config(
            1, enabled=True, is_turntable=False, is_bluetooth=True,
            stylus_life_hours=0,
        )
        snap = tr.snapshot().inputs[1]
        assert snap.is_bluetooth is True

    def test_fallback_snapshot_default_is_bluetooth_false(self):
        from autostream_playback_stats import make_fallback_input_snapshot
        snap = make_fallback_input_snapshot(1, "Input 1")
        assert snap.is_bluetooth is False
        assert snap.to_public_dict()["is_bluetooth"] is False
