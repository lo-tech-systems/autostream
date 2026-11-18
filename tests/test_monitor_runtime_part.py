"""tests/test_monitor_runtime_part.py

The coordinator publishes the monitor's runtime metadata and the self-heal
counters as parts of the state snapshot; the status reply reads them there.
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_core as core
import autostream_state as state
import autostream_selfheal as selfheal


def snap():
    return state.store().snapshot()


class TestMonitorPart:
    def test_the_part_starts_unknown_and_disconnected(self):
        m = snap().monitor
        assert (m.monitor_build, m.log_level, m.connected) == ("unknown", "unknown", False)

    def test_a_set_merges_into_what_is_there(self):
        core._set_monitor_runtime_info(monitor_build=" 2.1 ", log_level="info", connected=True,
                                       last_seen_at=5.0)
        core._set_monitor_runtime_info(connected=False)
        m = snap().monitor
        assert (m.monitor_build, m.log_level, m.connected, m.last_seen_at) == (
            "2.1", "info", False, 5.0)

    def test_an_empty_build_reads_unknown(self):
        core._set_monitor_runtime_info(monitor_build="", log_level="  ")
        assert snap().monitor.monitor_build == "unknown"
        assert snap().monitor.log_level == "unknown"

    def test_last_seen_alone_does_not_move_the_version(self):
        core._set_monitor_runtime_info(monitor_build="2.1", connected=True, last_seen_at=1.0)
        version = snap().version
        core._set_monitor_runtime_info(monitor_build="2.1", connected=True, last_seen_at=2.0)
        assert snap().version == version
        assert snap().monitor.last_seen_at == 2.0

    def test_a_connection_change_is_told_to_subscribers(self):
        seen = []
        state.store().subscribe(seen.append)
        core._set_monitor_runtime_info(connected=True)
        assert [c.parts for c in seen] == [frozenset({"monitor"})]


class TestOutputHealth:
    HEALTH = {"fifo": {"stalled_seconds": 0.0, "stranded_bytes": 0}, "underruns": {"live1": 0}}

    def test_it_is_published_frozen(self):
        core._set_monitor_runtime_info(connected=True, output_health=self.HEALTH)
        health = snap().monitor.output_health
        assert isinstance(health, state.FrozenDict)
        assert isinstance(health["fifo"], state.FrozenDict)
        assert health["fifo"]["stranded_bytes"] == 0

    def test_moving_counters_do_not_wake_subscribers(self):
        core._set_monitor_runtime_info(connected=True, output_health=self.HEALTH)
        seen = []
        state.store().subscribe(seen.append)
        core._set_monitor_runtime_info(
            connected=True, output_health={"fifo": {"stalled_seconds": 0.0, "stranded_bytes": 960}})
        assert seen == []
        assert snap().monitor.output_health["fifo"]["stranded_bytes"] == 960

    def test_none_keeps_the_value_and_an_empty_dict_clears_it(self):
        core._set_monitor_runtime_info(connected=True, output_health=self.HEALTH)
        core._set_monitor_runtime_info(last_seen_at=3.0)
        assert snap().monitor.output_health["underruns"]["live1"] == 0
        core._set_monitor_runtime_info(output_health={})
        assert snap().monitor.output_health is None

    def test_a_failed_poll_leaves_no_health_beside_not_connected(self):
        core._set_monitor_runtime_info(connected=True, output_health=self.HEALTH)
        core._set_monitor_runtime_info(connected=False, output_health={})
        m = snap().monitor
        assert (m.connected, m.output_health) == (False, None)

    def test_the_helper_picks_the_four_blocks_only(self):
        status = {
            "fifo": {"a": 1}, "underruns": {"b": 2}, "ring_drops": {"c": 3},
            "output_thread": {"d": 4}, "repeat": {"e": 5}, "inputs": [],
        }
        assert core._output_health_from_status(status) == {
            "fifo": {"a": 1}, "underruns": {"b": 2}, "ring_drops": {"c": 3},
            "output_thread": {"d": 4}}

    def test_the_helper_ignores_values_that_are_not_dicts(self):
        assert core._output_health_from_status({"fifo": 3, "underruns": None, "ring_drops": []}) == {}

    def test_the_helper_gives_an_empty_dict_for_a_status_without_them(self):
        assert core._output_health_from_status({"inputs": []}) == {}


class TestHealthPart:
    def test_a_set_merges_fields(self):
        selfheal._set_owntone_selfheal_state(reconcile_fired_count=2, reconcile_last_fired_at=42.0)
        selfheal._set_owntone_selfheal_state(watchdog_armed=True)
        h = snap().health
        assert (h.reconcile_fired_count, h.reconcile_last_fired_at, h.watchdog_armed) == (
            2, 42.0, True)

    def test_the_never_restarted_sentinel_is_kept_and_reads_null_in_json(self):
        selfheal._set_owntone_selfheal_state(watchdog_last_restart_at=float("-inf"))
        assert snap().health.watchdog_last_restart_at == -math.inf
        assert snap().health.as_json()["watchdog_last_restart_at"] is None
