"""tests/test_named_interval_table.py

Coverage for the named-interval table primitive introduced in autostream_core:
a small (name, period, callback) row list, consulted once per coordinator-loop tick
via `_IntervalTable.tick()`. Not a thread of its own -- callers drive `tick()`
synchronously.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_core as core


def test_fresh_row_fires_on_first_tick():
    calls = []
    table = core._IntervalTable()
    table.register("x", 300.0, lambda: calls.append(1))

    table.tick(now=1000.0)

    assert calls == [1]


def test_row_does_not_refire_before_period_elapses():
    calls = []
    table = core._IntervalTable()
    table.register("x", 300.0, lambda: calls.append(1))

    table.tick(now=1000.0)
    table.tick(now=1000.0 + 100.0)  # only 100s elapsed of a 300s period

    assert calls == [1]


def test_row_refires_once_period_elapses():
    calls = []
    table = core._IntervalTable()
    table.register("x", 300.0, lambda: calls.append(1))

    table.tick(now=1000.0)
    table.tick(now=1000.0 + 300.0)

    assert calls == [1, 1]


def test_multiple_rows_are_independent():
    calls = {"fast": 0, "slow": 0}
    table = core._IntervalTable()
    table.register("fast", 5.0, lambda: calls.__setitem__("fast", calls["fast"] + 1))
    table.register("slow", 300.0, lambda: calls.__setitem__("slow", calls["slow"] + 1))

    table.tick(now=1000.0)
    table.tick(now=1006.0)  # fast (5s) elapses again, slow (300s) does not

    assert calls == {"fast": 2, "slow": 1}


def test_tick_defaults_to_wall_clock_when_now_not_given():
    calls = []
    table = core._IntervalTable()
    table.register("x", 300.0, lambda: calls.append(1))

    table.tick()

    assert calls == [1]


def test_named_interval_dataclass_fields():
    def _cb():
        pass

    row = core._NamedInterval(name="stats_flush", period_s=300.0, callback=_cb)

    assert row.name == "stats_flush"
    assert row.period_s == 300.0
    assert row.callback is _cb
    assert row.last_run == 0.0
