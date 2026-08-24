"""tests/test_tick_snapshot.py

Coverage for the per-tick read-only snapshot primitive introduced in
autostream_core: a small frozen dataclass
bundling one poll cycle's status_by_index/repeat_status/replay_origin_idx,
built once per coordinator-loop tick and consulted by the ingest call sites
instead of each one re-deriving the same values from three loose locals.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_core as core


def test_status_for_returns_entry_for_known_index():
    entry = {"silent": False, "capturing": True}
    snap = core._TickSnapshot(
        status_by_index={1: entry, 2: {"silent": True, "capturing": False}},
        repeat_status=None,
        replay_origin_idx=None,
    )

    assert snap.status_for(1) is entry


def test_status_for_returns_none_for_unknown_index():
    snap = core._TickSnapshot(
        status_by_index={1: {"silent": False, "capturing": True}},
        repeat_status=None,
        replay_origin_idx=None,
    )

    assert snap.status_for(2) is None


def test_is_replay_origin_true_for_matching_index():
    snap = core._TickSnapshot(status_by_index={}, repeat_status=None, replay_origin_idx=1)

    assert snap.is_replay_origin(1) is True
    assert snap.is_replay_origin(2) is False


def test_is_replay_origin_false_when_no_origin_this_cycle():
    snap = core._TickSnapshot(status_by_index={}, repeat_status=None, replay_origin_idx=None)

    assert snap.is_replay_origin(1) is False
    assert snap.is_replay_origin(2) is False


def test_repeat_status_field_is_passed_through_unchanged():
    repeat = {"replay": {"active": True}}
    snap = core._TickSnapshot(status_by_index={}, repeat_status=repeat, replay_origin_idx=None)

    assert snap.repeat_status is repeat


def test_snapshot_is_frozen():
    snap = core._TickSnapshot(status_by_index={}, repeat_status=None, replay_origin_idx=None)

    with __import__("pytest").raises(Exception):
        snap.replay_origin_idx = 5
