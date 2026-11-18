"""tests/test_monitor_runtime_part.py

The coordinator publishes the monitor's runtime metadata and the self-heal
counters as parts of the state snapshot; the status reply reads them there.
"""
from __future__ import annotations

import io
import json
import math
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

from fake_store import fake_levels
import autostream_core as core
import autostream_state as state
import autostream_webui_api as api
import autostream_selfheal as selfheal
import webui.common as webui_common


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

    def test_the_status_reply_carries_the_counters(self):
        selfheal._set_owntone_selfheal_state(
            reconcile_fired_count=2, reconcile_last_fired_at=42.0, watchdog_armed=True,
            watchdog_restart_count=1, watchdog_last_restart_at=float("-inf"))
        handler = MagicMock()
        handler.wfile = io.BytesIO()
        with fake_levels([]), \
             patch.object(webui_common, "_session_playing", return_value=False):
            api.send_status_json(handler, None)
        body = json.loads(handler.wfile.getvalue().decode("utf-8"))
        assert body["owntone_selfheal"] == {
            "reconcile_fired_count": 2, "reconcile_last_fired_at": 42.0,
            "watchdog_armed": True, "watchdog_restart_count": 1,
            "watchdog_last_restart_at": None,
        }
