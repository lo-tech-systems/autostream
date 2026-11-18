"""Tests for dial_core_model.py: the core's mutable record and the snapshot
built from it.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import dataclasses
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "dial"))

import dial_core_model as cm  # noqa: E402
from dial_core_state import (  # noqa: E402
    POWER_IDLE, CoreSnapshot, DialInfo, EqState, FocusState,
)


def _names(cls) -> set:
    return {f.name for f in dataclasses.fields(cls)}


def _default_of(f):
    if f.default is not dataclasses.MISSING:
        return f.default
    if f.default_factory is not dataclasses.MISSING:
        return f.default_factory()
    return dataclasses.MISSING


class TestFieldLists:
    def test_the_published_fields_are_the_snapshots_apart_from_seq_and_at(self):
        assert _names(cm.PublishedState) == _names(CoreSnapshot) - {"seq", "at"}

    def test_the_private_fields_are_not_on_the_snapshot(self):
        private = _names(cm.CoreState) - _names(cm.PublishedState)
        assert private and not private & _names(CoreSnapshot)

    def test_published_fields_lists_the_published_record_only(self):
        assert set(cm.PUBLISHED_FIELDS) == _names(cm.PublishedState)

    def test_a_default_the_snapshot_has_is_the_same_here(self):
        published = {f.name: f for f in dataclasses.fields(cm.PublishedState)}
        for f in dataclasses.fields(CoreSnapshot):
            if f.name in ("seq", "at") or _default_of(f) is dataclasses.MISSING:
                continue
            assert _default_of(published[f.name]) == _default_of(f), f.name


class TestNewState:
    def test_the_first_snapshot_is_what_a_new_core_has_always_published(self):
        dial = DialInfo(
            name="", version="", uuid="d", ip="", port=0, inputs=(),
            volume_scope="current", mute_scope="current",
        )
        expected = CoreSnapshot(
            seq=0, at=0.0, polling=False, appliances=(),
            focus=FocusState(None, None, None, None, None, None, False),
            now_playing=None, artwork=None, idle_affordance=False, outputs=None, eq=None,
            outputs_available=False, eq_available=False, warnings=(), due_status_id=None,
            network=None, wifi_ever_connected=False, sd_health=None, update=None,
            transport=None, volume_readout=(None, None), dial=dial, dots_active=False,
            visible_playing=(), ticks=0, tick=None, auth_promotions=0, outputs_request=None,
            power=POWER_IDLE, start_failure=None, focused_peer=None,
        )
        assert cm.snapshot_of(cm.new_state("d"), 0, 0.0) == expected

    def test_the_private_defaults(self):
        state = cm.new_state("d")
        assert state.roster == [] and state.eq_optimistic == ((), 0.0)
        assert (state.wifi_down_streak, state.sd_low) == (0, False)
        assert state.appliance_warnings == state.protocol_warnings == {}
        assert state.start_failure_seen == state.peers == state.views == state.playing_since == {}

    def test_two_states_share_no_container(self):
        a, b = cm.new_state("d"), cm.new_state("d")
        for name in ("roster", "appliance_warnings", "protocol_warnings", "start_failure_seen",
                     "peers", "views", "playing_since"):
            assert getattr(a, name) is not getattr(b, name), name


class TestSnapshotOf:
    def test_the_optimistic_window_is_merged_into_the_eq_it_carries(self):
        state = cm.new_state("d")
        eq = EqState("a", 1, (), True, (), 0.0)
        state.eq = eq
        state.eq_optimistic = ((("bass", 2),), 9.5)
        snap = cm.snapshot_of(state, 3, 1.5)
        assert (snap.seq, snap.at) == (3, 1.5)
        assert snap.eq.optimistic == (("bass", 2),) and snap.eq.optimistic_expires_at == 9.5
        assert state.eq is eq and eq.optimistic == ()
