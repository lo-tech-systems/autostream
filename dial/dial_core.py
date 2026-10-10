"""dial_core.py — the dial's appliance model, published as immutable
snapshots.

The core owns one mutable state record guarded by a lock, and a published
`CoreSnapshot` that readers fetch with a plain reference read. Every change
goes through `_publish`: mutate the state under the lock, build and store a
new snapshot with the next sequence number, wake any `wait_for_change`
callers, then (after the lock is released) tell each subscriber.

Locking: the core lock is held only for in-memory work. It is never held
across network or file I/O, a frame push, a subscriber callback, or a call
into `auth_map`, and it is never taken while a display lock is held (nor a
display lock while it is held). Subscriber callbacks run inline on the
publishing thread and must only signal (`Event.set`, `queue.put_nowait`,
`Condition.notify`); a callback that blocks delays that publisher and
nothing else. Consumers coalesce: several publishes before a consumer runs
collapse into one wake, and the consumer reads the newest snapshot.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import dataclasses
import logging
import threading
import time
from dataclasses import dataclass
from typing import Callable

from dial_auth import AUTH_UNAUTHORIZED
from dial_core_state import (
    CoreSnapshot, DialInfo, FocusState, NowPlaying, appliance_states, with_accepted_replay,
)
from dial_mdns import get_roster as _default_get_roster
from dial_repeat_store import repeat_store

_UNSET = object()

# FocusState fields the display's delegating properties write one at a time.
_FOCUS_FIELDS = frozenset((
    "manual_id", "bound_id", "pending", "reporting_id",
    "source_service_name", "accepted_replay",
))

# The remaining single-value fields that can be written the same way.
_PLAIN_FIELDS = frozenset((
    "now_playing", "idle_affordance", "dots_active", "outputs_available", "eq_available",
))


@dataclass
class _CoreState:
    """The core's mutable state: `CoreSnapshot`'s fields other than `seq` and
    `at`, which `_publish` stamps, plus the raw roster and repeat records the
    appliance list is derived from. Values are immutable (tuples and frozen
    dataclasses) and are replaced, never edited in place, so a published
    snapshot can share them."""
    polling: bool
    appliances: tuple
    focus: FocusState
    now_playing: NowPlaying | None
    artwork: object | None
    idle_affordance: bool
    outputs: object | None
    eq: object | None
    outputs_available: bool
    eq_available: bool
    warnings: tuple
    due_warning_id: str | None
    network: object | None
    wifi_ever_connected: bool
    sd_health: object | None
    update: object | None
    transport: object | None
    volume_readout: tuple
    dial: DialInfo
    dots_active: bool
    roster: object          # the merged roster as last published (a read-only list)
    repeats: dict           # appliance id -> repeat record as of the last tick


_SNAPSHOT_FIELDS = tuple(
    f.name for f in dataclasses.fields(_CoreState) if f.name not in ("roster", "repeats")
)


def _initial_state(dial_id: str) -> _CoreState:
    return _CoreState(
        polling=False,
        appliances=(),
        focus=FocusState(None, None, None, None, None, None, False),
        now_playing=None,
        artwork=None,
        idle_affordance=False,
        outputs=None,
        eq=None,
        outputs_available=False,
        eq_available=False,
        warnings=(),
        due_warning_id=None,
        network=None,
        wifi_ever_connected=False,
        sd_health=None,
        update=None,
        transport=None,
        volume_readout=(None, None),
        dial=DialInfo(
            name="", version="", uuid=dial_id, ip="", port=0, inputs=(),
            volume_scope="current", mute_scope="current",
        ),
        dots_active=False,
        roster=[],
        repeats={},
    )


class DialCore:
    def __init__(
        self,
        dial_id: str,
        get_display_targets: Callable,
        get_roster: Callable = _default_get_roster,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._dial_id = dial_id
        self._get_display_targets = get_display_targets
        self._get_roster = get_roster
        self._clock = clock
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._state = _initial_state(dial_id)
        self._seq = 0
        self._subscribers: dict[int, Callable[[], None]] = {}
        self._next_handle = 1
        self._snapshot = self._build_snapshot_locked()

    # ---- reading -----------------------------------------------------------

    def snapshot(self) -> CoreSnapshot:
        """The newest published snapshot: a reference read, no lock."""
        return self._snapshot

    def wait_for_change(self, seen_seq: int, timeout: float | None) -> CoreSnapshot | None:
        """Block until a snapshot newer than *seen_seq* is published, and
        return it; None if *timeout* seconds pass first."""
        with self._cond:
            if not self._cond.wait_for(lambda: self._snapshot.seq > seen_seq, timeout):
                return None
            return self._snapshot

    # ---- subscribing -------------------------------------------------------

    def subscribe(self, callback: Callable[[], None]) -> int:
        """Register a zero-argument signal callback, called after every
        publish on the publishing thread. Returns a handle for
        `unsubscribe`."""
        with self._lock:
            handle = self._next_handle
            self._next_handle += 1
            self._subscribers[handle] = callback
        return handle

    def unsubscribe(self, handle: int) -> None:
        with self._lock:
            self._subscribers.pop(handle, None)

    # ---- publishing --------------------------------------------------------

    def _build_snapshot_locked(self) -> CoreSnapshot:
        return CoreSnapshot(
            seq=self._seq,
            at=self._clock(),
            **{name: getattr(self._state, name) for name in _SNAPSHOT_FIELDS},
        )

    def _publish(self, mutate_fn: Callable[[_CoreState], "bool | None"]) -> CoreSnapshot:
        """Apply *mutate_fn* to the state under the lock (in-memory work
        only), publish the resulting snapshot, then signal the subscribers
        outside the lock. Returns the new snapshot. A mutate function that
        returns False found nothing to change: nothing is published and the
        current snapshot is returned."""
        with self._cond:
            if mutate_fn(self._state) is False:
                return self._snapshot
            self._seq += 1
            snap = self._build_snapshot_locked()
            self._snapshot = snap
            self._cond.notify_all()
            callbacks = list(self._subscribers.values())
        for callback in callbacks:
            try:
                callback()
            except Exception:
                logging.debug("dial core: subscriber callback raised", exc_info=True)
        return snap

    def publish_tick(
        self,
        *,
        polling: bool,
        focus: "FocusState | object" = _UNSET,
        now_playing: "NowPlaying | None | object" = _UNSET,
        idle_affordance: "bool | object" = _UNSET,
        outputs_available: "bool | object" = _UNSET,
        eq_available: "bool | object" = _UNSET,
        repeats: "dict | object" = _UNSET,
    ) -> CoreSnapshot:
        """Publish the end of one poll tick. Fields passed are stored as
        given; fields left out keep the value the writers (the poll's own
        steps and the touch and worker callbacks) have already stored, so a
        concurrent write is never overwritten by a stale copy. When *focus*
        is left out the idle-focus flag is recomputed from the stored
        now-playing. *repeats* (appliance id to repeat record) refreshes
        the per-appliance repeat state."""
        def mutate(state: _CoreState) -> None:
            state.polling = polling
            if focus is not _UNSET:
                state.focus = focus
            if now_playing is not _UNSET:
                state.now_playing = now_playing
            if idle_affordance is not _UNSET:
                state.idle_affordance = idle_affordance
            if outputs_available is not _UNSET:
                state.outputs_available = outputs_available
            if eq_available is not _UNSET:
                state.eq_available = eq_available
            if focus is _UNSET:
                playing = state.now_playing
                idle = playing is not None and not playing.playing
                if idle != state.focus.idle_focus:
                    state.focus = dataclasses.replace(state.focus, idle_focus=idle)
            if repeats is not _UNSET:
                state.repeats = repeats
                state.appliances = appliance_states(state.roster, state.repeats)
        return self._publish(mutate)

    # ---- field writes ------------------------------------------------------

    def roster(self) -> list:
        """The merged roster as last stored: a reference read, no lock. The
        list is shared and must not be edited."""
        return self._state.roster

    def set_roster(self, roster: list) -> CoreSnapshot:
        """Store the merged roster and re-derive the appliance list."""
        def mutate(state: _CoreState) -> None:
            state.roster = roster
            state.appliances = appliance_states(roster, state.repeats)
        return self._publish(mutate)

    def set_field(self, name: str, value) -> CoreSnapshot:
        """Store one value and publish: a focus field (`manual_id`,
        `bound_id`, `pending`, `reporting_id`, `source_service_name`,
        `accepted_replay`), `roster`, or one of the plain fields
        (`now_playing`, `idle_affordance`, `dots_active`,
        `outputs_available`, `eq_available`). Nothing is published when the
        stored value is already that very object. The read-modify-write of a
        focus field happens under the lock, so writers of different focus
        fields never lose each other's update."""
        if name == "roster":
            return self.set_roster(value)
        if name in _FOCUS_FIELDS:
            def mutate(state: _CoreState) -> "bool | None":
                if getattr(state.focus, name) is value:
                    return False
                state.focus = dataclasses.replace(state.focus, **{name: value})
        elif name in _PLAIN_FIELDS:
            def mutate(state: _CoreState) -> "bool | None":
                if getattr(state, name) is value:
                    return False
                setattr(state, name, value)
        else:
            raise KeyError(name)
        return self._publish(mutate)

    # ---- focus -------------------------------------------------------------

    def manual_focus_id(self) -> str | None:
        return self._snapshot.focus.manual_id

    def set_focus(self, appliance_id: str | None) -> None:
        """Pin the display to *appliance_id*, or clear it back to auto-pick
        with None. Never persisted. The caller wakes the poll."""
        self.set_field("manual_id", appliance_id)

    def set_focus_pending(self, appliance_id: str, service_name: str, expires_at: float) -> None:
        """Pin the focus to *appliance_id* and mark it pending until
        *expires_at*: a picker-started replay has not yet reached the
        playing set, so the ordinary "gone from the roster" clear must not
        fire before it has had a chance to appear."""
        def mutate(state: _CoreState) -> None:
            state.focus = dataclasses.replace(
                state.focus, manual_id=appliance_id,
                pending=(appliance_id, service_name, expires_at),
            )
        self._publish(mutate)

    def clear_focus(self, reason: str) -> None:
        """Drop the manual focus and any pending grace."""
        def mutate(state: _CoreState) -> "bool | None":
            if state.focus.manual_id is None and state.focus.pending is None:
                return False
            state.focus = dataclasses.replace(state.focus, manual_id=None, pending=None)
        self._publish(mutate)
        logging.info("dial display: manual focus cleared (%s)", reason)

    def replace_pending(self, expected, new) -> bool:
        """Store the pending focus *new*, only if it is still *expected*:
        the poll resolves the pending grace from a copy it read earlier, and
        must not overwrite a focus the touch thread pinned in between."""
        return self._replace_focus_if("pending", expected, new)

    def drop_pending_focus(self, appliance_id: str) -> bool:
        """Clear the manual and pending focus when the pending focus is for
        *appliance_id* (its replay did not start). True if it was cleared."""
        def mutate(state: _CoreState) -> "bool | None":
            pending = state.focus.pending
            if pending is None or pending[0] != appliance_id:
                return False
            state.focus = dataclasses.replace(state.focus, manual_id=None, pending=None)
        return self._changed(mutate)

    def accept_replay(self, appliance_id: str, until: float) -> bool:
        """Open the accepted-replay window for *appliance_id* until *until*,
        when the dial is following that appliance. True if it was opened."""
        def mutate(state: _CoreState) -> "bool | None":
            if state.focus.manual_id != appliance_id:
                return False
            state.focus = dataclasses.replace(state.focus, accepted_replay=(appliance_id, until))
        return self._changed(mutate)

    def with_accepted_replay(self, targets: list, now: float) -> list:
        """*targets* (the mDNS playing set), plus the appliance whose replay
        the dial has just had accepted, until its own playing advertisement
        arrives. The appliance acknowledges a seek at once, but that
        advertisement only reaches the dial a few seconds later; in
        between, the replay the user just started is shown as playing
        straight away, built from its roster entry, so the ordinary playing
        path fetches its status and artwork. Only that gap is bridged: the
        window ends as soon as the advertisement is seen, when the dial
        stops following the appliance, when its repeat record no longer
        says a replay is running, or at its deadline, after which the
        playing set alone decides again. Poll thread only (the touch and
        worker side only ever open the window); reads the roster published
        by the previous poll (the picker only offers rostered appliances)."""
        focus = self._snapshot.focus
        accepted = focus.accepted_replay
        rec = repeat_store.get(accepted[0], now) if accepted is not None else None
        targets, new_accepted = with_accepted_replay(
            accepted, targets, self._state.roster, focus.manual_id, rec, now,
        )
        if new_accepted is not accepted:
            self._replace_focus_if("accepted_replay", accepted, new_accepted)
        return targets

    def _changed(self, mutate_fn: Callable[[_CoreState], "bool | None"]) -> bool:
        """Publish through *mutate_fn*; True if it changed anything."""
        changed = []

        def wrapped(state: _CoreState) -> "bool | None":
            if mutate_fn(state) is False:
                return False
            changed.append(True)
        self._publish(wrapped)
        return bool(changed)

    def _replace_focus_if(self, name: str, expected, value) -> bool:
        def mutate(state: _CoreState) -> "bool | None":
            if getattr(state.focus, name) is not expected or expected is value:
                return False
            state.focus = dataclasses.replace(state.focus, **{name: value})
        return self._changed(mutate)

    def current_source_service_name(self) -> str | None:
        """mDNS service name of the display's chosen artwork source, or
        None when nothing is identified/playing. Plain reference read, safe
        from any thread; may lag the poll by up to one poll cycle. Used by
        dial_main's volume-target resolver so a touch/encoder press
        addresses whatever this dial is showing, or, with a manual focus,
        the focused appliance, see focus_volume_target()."""
        return self._snapshot.focus.source_service_name

    def focus_volume_target(self):
        """The roster entry the volume/mute worker should address while a
        manual focus is set: that appliance, playing or idle, when it is on
        the last-published roster and not confirmed unauthorized; else None
        (no focus, or the focus is unresolved this tick), meaning "use the
        ordinary playing-set resolution". Plain reference reads of the
        manual focus and the roster, safe from the worker thread; may lag
        the poll by one cycle."""
        focus_id = self._snapshot.focus.manual_id
        if not focus_id:
            return None
        for r in self._state.roster:
            if r.appliance_id == focus_id:
                return r if r.auth != AUTH_UNAUTHORIZED else None
        return None


def create_dial_core(cfg, get_display_targets: Callable, get_roster: Callable = _default_get_roster) -> DialCore:
    """Build the core for dial_main.py wiring."""
    return DialCore(cfg.uuid, get_display_targets, get_roster)
