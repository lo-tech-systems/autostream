"""dial_core_model.py -- the core's mutable record, split by what leaves it.

`PublishedState` holds exactly `CoreSnapshot`'s fields other than `seq` and
`at`, which a publish stamps. `CoreState` adds what stays inside the core:
the folded peers and the roster, the optimistic EQ window and the sources'
latches. The defaults are the state of a new core.

Values are immutable (tuples and frozen dataclasses) and are replaced, never
edited in place, so a published snapshot can share them. To add a published
field, add it here and on `CoreSnapshot`; a test checks that the two agree.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field, fields

from dial_core_state import (
    POWER_IDLE, CoreSnapshot, DialInfo, FocusState, NowPlaying, TickContext,
)

NO_FOCUS = FocusState(None, None, None, None, None, None, False)


@dataclass
class PublishedState:
    dial: DialInfo                                  # no default: see new_state
    polling: bool = False
    appliances: tuple = ()
    focus: FocusState = NO_FOCUS
    now_playing: NowPlaying | None = None
    artwork: object | None = None
    idle_affordance: bool = False
    outputs: object | None = None
    eq: object | None = None
    outputs_available: bool = False
    eq_available: bool = False
    warnings: tuple = ()
    due_status_id: str | None = None
    network: object | None = None
    wifi_ever_connected: bool = False
    sd_health: object | None = None
    update: object | None = None
    transport: object | None = None
    outputs_request: object | None = None   # the latest output request, as `transport` is the latest replay one
    power: object = POWER_IDLE              # a PowerState
    volume_readout: tuple = (None, None)
    dots_active: bool = False
    visible_playing: tuple = ()     # ids of the playing appliances this dial may use, as of the last fold
    ticks: int = 0                  # folds completed
    tick: TickContext | None = None  # what the last completed fold started from
    auth_promotions: int = 0        # appliances a fold found newly authorised
    start_failure: object | None = None    # the raised StartFailureNotice, published
    focused_peer: object | None = None     # the focused appliance's PeerSnapshot as last folded


@dataclass
class CoreState(PublishedState):
    roster: list = field(default_factory=list)   # the appliance states in roster order as last folded (a read-only list)
    # Kept apart from the EQ state because a tap's value stays shown (until a
    # reading stamped after the window lands) even when nobody is watching the
    # page any more; the snapshot carries it on the state. A slider sends many
    # sets with no outcome to act on, so the EQ has one window, not a request
    # per set; the outputs tap lives on the output request instead.
    eq_optimistic: tuple = ((), 0.0)    # (((band_id, gain_db), ...), expires_at); ((), 0.0) when none
    wifi_down_streak: int = 0           # consecutive down link readings; reset by a connected or ignored one
    sd_low: bool = False                # the SD health incident latch (with hysteresis)
    appliance_warnings: dict = field(default_factory=dict)   # appliance id -> its validated, attributed warnings
    protocol_warnings: dict = field(default_factory=dict)    # appliance id -> the dial's own "Update" warning for it; private
    start_failure_seen: dict = field(default_factory=dict)   # appliance id -> (boot, seq) handled; private
    peers: dict = field(default_factory=dict)          # appliance id -> its last folded PeerSnapshot
    views: dict = field(default_factory=dict)          # appliance id -> ApplianceState mapped from it
    playing_since: dict = field(default_factory=dict)  # appliance id -> core clock its session was first folded


PUBLISHED_FIELDS: tuple[str, ...] = tuple(f.name for f in fields(PublishedState))


def new_state(dial_id: str) -> CoreState:
    """The state of a core that has not yet folded anything."""
    return CoreState(dial=DialInfo(
        name="", version="", uuid=dial_id, ip="", port=0, inputs=(),
        volume_scope="current", mute_scope="current",
    ))


def snapshot_of(state: CoreState, seq: int, at: float) -> CoreSnapshot:
    """The snapshot of *state*, with the optimistic EQ window merged into the
    EQ it carries (the state's own EQ is left as it is)."""
    values = {name: getattr(state, name) for name in PUBLISHED_FIELDS}
    if values["eq"] is not None:
        values["eq"] = dataclasses.replace(
            values["eq"], optimistic=state.eq_optimistic[0],
            optimistic_expires_at=state.eq_optimistic[1],
        )
    return CoreSnapshot(seq=seq, at=at, **values)
