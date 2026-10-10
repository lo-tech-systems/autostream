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

import dial_core_poll
from dial_auth import AUTH_UNAUTHORIZED, auth_map
from dial_core_state import (
    ACCEPTED_REPLAY_GRACE_S, EQ_LIMIT_DB, EQ_OPTIMISTIC_WINDOW_S, OUTPUTS_REFRESH_S,
    ActionResult, Artwork, CoreSnapshot, DialInfo, EqState, FocusState, NowPlaying,
    OutputsState, TransportRequest, _roster_entry, appliance_states, artwork_key, eq_gain,
    with_accepted_replay,
)
from dial_eq import _EqTarget
from dial_eq import enqueue_fetch as _enqueue_eq_fetch
from dial_eq import enqueue_set as _enqueue_eq_set
from dial_mdns import get_roster as _default_get_roster
from dial_outputs import _OutputsTarget, enqueue_fetch, enqueue_set
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
    # Kept apart from the outputs and EQ states because a tap's value stays
    # shown (until a reading stamped after it lands) even when nobody is
    # watching the page any more; the snapshot carries them on the states.
    outputs_optimistic: tuple | None    # (output_id, selected, volume, stamped_at)
    eq_optimistic: tuple                # (((band_id, gain_db), ...), expires_at); ((), 0.0) when none
    outputs_refresh_at: float           # when the watched list was last asked for
    outputs_watch: dict                 # watcher -> appliance id it follows
    eq_watch: dict


# Held in the state for the core's own use, never published as such.
_PRIVATE_FIELDS = (
    "roster", "repeats", "outputs_optimistic", "eq_optimistic",
    "outputs_refresh_at", "outputs_watch", "eq_watch",
)

_SNAPSHOT_FIELDS = tuple(
    f.name for f in dataclasses.fields(_CoreState) if f.name not in _PRIVATE_FIELDS
)

# The EQ bands the bass/treble capability exposes.
_EQ_BAND_IDS = ("bass", "treble")


@dataclass(frozen=True)
class RepeatOutcome:
    """What a repeat transport result meant, for the caller's own reactions
    (poll wake, screen changes); the state it implies is already folded."""
    ok: bool                # an ok:true ack
    replay_accepted: bool   # an ack for a replay of the appliance the dial follows
    stop_acked: bool        # an ok ack for the Stop this dial sent


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
        outputs_optimistic=None,
        eq_optimistic=((), 0.0),
        outputs_refresh_at=0.0,
        outputs_watch={},
        eq_watch={},
    )


class DialCore:
    def __init__(
        self,
        dial_id: str,
        get_display_targets: Callable,
        get_roster: Callable = _default_get_roster,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._dial_id = dial_id
        self._get_display_targets = get_display_targets
        self._get_roster = get_roster
        # Looked up at each call, so a test that replaces time.monotonic
        # moves the core's clock with everything else.
        self._clock = clock if clock is not None else (lambda: time.monotonic())
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
        fields = {name: getattr(self._state, name) for name in _SNAPSHOT_FIELDS}
        if fields["outputs"] is not None:
            fields["outputs"] = dataclasses.replace(
                fields["outputs"], optimistic=self._state.outputs_optimistic,
            )
        if fields["eq"] is not None:
            fields["eq"] = dataclasses.replace(
                fields["eq"], optimistic=self._state.eq_optimistic[0],
                optimistic_expires_at=self._state.eq_optimistic[1],
            )
        return CoreSnapshot(seq=self._seq, at=self._clock(), **fields)

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

    # ---- artwork -----------------------------------------------------------

    def fetch_artwork(
        self, url: str, *, fetch: Callable, log_limiter, eligible: Callable[[str], bool],
        timeout: float, on_error: Callable[[str], None] | None = None,
    ) -> "Artwork | None":
        """The artwork bytes for *url*, downloaded once per track: the held
        copy when it is already for this URL, else a fresh fetch on the
        calling (poll) thread, outside the lock. Only one buffer is ever
        live: the previous one is released before the next is downloaded.
        The held `Artwork` carries no URL, only its `key`. A URL that is
        not eligible, or a failed fetch, leaves nothing held and returns
        None, so a failed fetch is tried again on the next call."""
        key = artwork_key(url)
        held = self._snapshot.artwork
        if held is not None and held.key == key:
            return held
        self.clear_artwork()
        if not eligible(url):
            logging.debug("dial display: unsupported artwork url candidate")
            return None
        art = dial_core_poll.fetch_artwork_bytes(
            url, log_limiter, fetch=fetch, timeout=timeout, on_error=on_error, now_fn=self._clock,
        )
        if art is None:
            return None
        art = dataclasses.replace(art, url="")

        def mutate(state: _CoreState) -> None:
            state.artwork = art
        self._publish(mutate)
        return art

    def clear_artwork(self, key: str | None = None) -> None:
        """Release the held artwork bytes: always, or only when they are the
        copy named by *key* (so a view dropping an undecodable image cannot
        discard a newer track's)."""
        def mutate(state: _CoreState) -> "bool | None":
            held = state.artwork
            if held is None or (key is not None and held.key != key):
                return False
            state.artwork = None
        self._publish(mutate)

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

    # ---- outputs and EQ ----------------------------------------------------

    def _focused_id(self) -> str | None:
        focus = self._snapshot.focus
        return focus.manual_id or focus.reporting_id

    def _new_eq_state(self, appliance_id: str) -> EqState:
        entry = _roster_entry(self._state.roster, appliance_id)
        version = getattr(entry, "dial_eq_version", 0) or 1
        return EqState(appliance_id, version, (), False, (), 0.0)

    def fetch_outputs(self, appliance_id: str) -> bool:
        """Ask for a fresh outputs list for *appliance_id* now, whoever is
        watching. False when the appliance is not on the roster."""
        entry = _roster_entry(self._state.roster, appliance_id)
        if entry is None:
            return False
        enqueue_fetch(_OutputsTarget(appliance_id, entry.ip, entry.port))
        return True

    def fetch_eq(self, appliance_id: str) -> bool:
        """Ask for a fresh EQ reading for *appliance_id* now. False when the
        appliance is not on the roster."""
        entry = _roster_entry(self._state.roster, appliance_id)
        if entry is None:
            return False
        _enqueue_eq_fetch(_EqTarget(appliance_id, entry.ip, entry.port))
        return True

    def watch_outputs(
        self, appliance_id: str, watcher: str, on: bool, *, fetch: bool = True,
    ) -> None:
        """Register (or drop) *watcher*'s interest in the outputs of
        *appliance_id*. A watcher follows one appliance at a time: a new
        registration replaces its previous one. The core keeps the outputs
        state for the focused or reporting appliance while any watcher is
        registered for it, asks for a list as the first interest arrives
        (unless *fetch* is False, for a caller that has just asked), and
        refetches it every OUTPUTS_REFRESH_S as `refresh_watched` is
        called. The last watcher leaving drops the state. Interest in an
        appliance that is not the focused one is held, and acted on once
        it becomes so."""
        fetch_now = []

        def mutate(state: _CoreState) -> "bool | None":
            watch = state.outputs_watch
            before = set(watch.values())
            if on:
                watch[watcher] = appliance_id
            elif watch.get(watcher) == appliance_id:
                del watch[watcher]
            else:
                return False
            after = set(watch.values())
            changed = False
            held = state.outputs
            if held is not None and held.appliance_id not in after:
                state.outputs = held = None
                changed = True
            if on and appliance_id == self._focused_id():
                if held is None or held.appliance_id != appliance_id:
                    state.outputs = OutputsState(appliance_id, (), False, 0.0, None)
                    changed = True
                if fetch and appliance_id not in before:
                    fetch_now.append(appliance_id)
            return None if changed else False
        self._publish(mutate)
        for target in fetch_now:
            self.fetch_outputs(target)

    def watch_eq(
        self, appliance_id: str, watcher: str, on: bool, *, fetch: bool = True,
    ) -> None:
        """The EQ counterpart of `watch_outputs`, with no periodic refresh:
        a reading is asked for as the first interest arrives and after a
        set."""
        fetch_now = []

        def mutate(state: _CoreState) -> "bool | None":
            watch = state.eq_watch
            before = set(watch.values())
            if on:
                watch[watcher] = appliance_id
            elif watch.get(watcher) == appliance_id:
                del watch[watcher]
            else:
                return False
            after = set(watch.values())
            changed = False
            held = state.eq
            if held is not None and held.appliance_id not in after:
                state.eq = held = None
                changed = True
            if on and appliance_id == self._focused_id():
                if held is None or held.appliance_id != appliance_id:
                    state.eq = self._new_eq_state(appliance_id)
                    changed = True
                if fetch and appliance_id not in before:
                    fetch_now.append(appliance_id)
            return None if changed else False
        self._publish(mutate)
        for target in fetch_now:
            self.fetch_eq(target)

    def refresh_watched(self, now: float) -> None:
        """The housekeeping tick: ask again for the outputs list of the
        focused or reporting appliance when it is watched and was last asked
        for OUTPUTS_REFRESH_S or more ago. *now* is the caller's monotonic
        time."""
        focused = self._focused_id()
        fetch_now = []

        def mutate(state: _CoreState) -> "bool | None":
            if focused is None or focused not in state.outputs_watch.values():
                return False
            held = state.outputs
            if held is None or held.appliance_id != focused:
                state.outputs = OutputsState(focused, (), False, 0.0, None)
                state.outputs_refresh_at = now
                fetch_now.append(focused)
                return None
            if now - state.outputs_refresh_at < OUTPUTS_REFRESH_S:
                return False
            state.outputs_refresh_at = now
            fetch_now.append(focused)
            return False
        self._publish(mutate)
        for target in fetch_now:
            self.fetch_outputs(target)

    def adopt_outputs(
        self, appliance_id: str, rows: tuple, loaded: bool, *, overwrite: bool = False,
    ) -> None:
        """Hold an outputs state for *appliance_id* when there is none: for
        a caller that already has rows on screen. With *overwrite* the rows
        and the loaded flag replace what is held for that appliance."""
        def mutate(state: _CoreState) -> "bool | None":
            held = state.outputs
            if held is not None and held.appliance_id == appliance_id:
                if not overwrite or (held.rows == rows and held.loaded == loaded):
                    return False
                state.outputs = dataclasses.replace(held, rows=rows, loaded=loaded)
                return None
            state.outputs = OutputsState(appliance_id, rows, loaded, 0.0, None)
        self._publish(mutate)

    def adopt_eq(
        self, appliance_id: str, bands: tuple, loaded: bool, *, overwrite: bool = False,
    ) -> None:
        """The EQ counterpart of `adopt_outputs`."""
        def mutate(state: _CoreState) -> "bool | None":
            held = state.eq
            if held is not None and held.appliance_id == appliance_id:
                if not overwrite or (held.bands == bands and held.loaded == loaded):
                    return False
                state.eq = dataclasses.replace(held, bands=bands, loaded=loaded)
                return None
            state.eq = dataclasses.replace(
                self._new_eq_state(appliance_id), bands=bands, loaded=loaded,
            )
        self._publish(mutate)

    # -- optimistic values --

    def outputs_override(self) -> tuple | None:
        """The pending outputs tap, (output_id, selected, volume,
        stamped_at), or None. A reference read."""
        return self._state.outputs_optimistic

    def set_outputs_override(self, value: tuple | None) -> None:
        def mutate(state: _CoreState) -> "bool | None":
            if state.outputs_optimistic == value:
                return False
            state.outputs_optimistic = value
        self._publish(mutate)

    def eq_override(self) -> tuple:
        """The pending EQ tap, (((band_id, gain_db), ...), expires_at); no
        pairs and 0.0 when there is none. A reference read."""
        return self._state.eq_optimistic

    def set_eq_override(self, pairs: tuple, expires_at: float) -> None:
        def mutate(state: _CoreState) -> "bool | None":
            if state.eq_optimistic == (pairs, expires_at):
                return False
            state.eq_optimistic = (pairs, expires_at)
        self._publish(mutate)

    def _eq_shown(self, band_id: str, now: float) -> int | None:
        """The gain *band_id* should show: a live tap's value, else the
        appliance's last reading, else None."""
        eq = self._snapshot.eq
        pairs, expires_at = self.eq_override()
        if pairs and expires_at > now:
            for pair_id, gain in pairs:
                if pair_id == band_id:
                    return gain
        return eq_gain(eq.bands, band_id) if eq is not None else None

    # -- requests --

    def _refusal(self, appliance_id: str, capability: str) -> ActionResult | None:
        entry = _roster_entry(self._state.roster, appliance_id)
        if entry is None:
            return ActionResult(False, "unknown_appliance")
        if not getattr(entry, capability):
            return ActionResult(False, "no_capability")
        if entry.auth == AUTH_UNAUTHORIZED:
            return ActionResult(False, "unauthorized")
        return None

    def _output_row(self, appliance_id: str, output_id: str):
        held = self._snapshot.outputs
        if held is None or held.appliance_id != appliance_id:
            return None
        return next((r for r in held.rows if r.id == output_id), None)

    def set_output(
        self, appliance_id: str, output_id: str, *,
        selected: bool | None = None, volume: int | None = None,
    ) -> ActionResult:
        """Enable or disable an output, or set its level. The change shows
        at once (as the pending tap) and is reconciled by the reading the
        worker asks for after the send. Refused when the appliance is
        unknown, lacks the capability or has refused this dial, when the
        output is not among the rows held, or when another appliance has
        taken it."""
        refusal = self._refusal(appliance_id, "dial_outputs")
        if refusal is not None:
            return refusal
        row = self._output_row(appliance_id, output_id)
        if row is None or row.remote_in_use or (selected is None and volume is None):
            return ActionResult(False, "wrong_state")
        entry = _roster_entry(self._state.roster, appliance_id)
        shown_selected = row.selected if selected is None else selected
        self.set_outputs_override((
            output_id, shown_selected, row.volume if volume is None else volume, self._clock(),
        ))
        enqueue_set(
            _OutputsTarget(appliance_id, entry.ip, entry.port), output_id,
            selected=shown_selected, volume=volume,
        )
        return ActionResult(True)

    def step_output_volume(self, appliance_id: str, output_id: str, delta: int) -> ActionResult:
        """Set an output's level to the level shown plus *delta*, clamped to
        0..100. A disabled output has no level to step from."""
        refusal = self._refusal(appliance_id, "dial_outputs")
        if refusal is not None:
            return refusal
        row = self._output_row(appliance_id, output_id)
        if row is None or row.remote_in_use:
            return ActionResult(False, "wrong_state")
        override = self._state.outputs_optimistic
        if override is not None and override[0] == row.id and override[1]:
            shown = override[2]
        else:
            shown = row.volume if row.selected else None
        if shown is None:
            return ActionResult(False, "wrong_state")
        return self.set_output(
            appliance_id, output_id, selected=True, volume=max(0, min(100, shown + delta)),
        )

    def set_eq(self, appliance_id: str, gains: dict) -> ActionResult:
        """Set EQ bands by id. The values show at once, the other bands
        keeping what they show now, for EQ_OPTIMISTIC_WINDOW_S or until a
        reading stamped after the window lands; only the bands given are
        sent. Refused for an unknown appliance, one without the capability
        or that has refused this dial, when no EQ state is held for it, and
        for a band id the capability does not have."""
        refusal = self._refusal(appliance_id, "dial_eq")
        if refusal is not None:
            return refusal
        if not gains or any(band_id not in _EQ_BAND_IDS for band_id in gains):
            return ActionResult(False, "no_capability")
        held = self._snapshot.eq
        if held is None or held.appliance_id != appliance_id:
            return ActionResult(False, "not_polling")
        entry = _roster_entry(self._state.roster, appliance_id)
        now = self._clock()
        pairs = []
        for band_id in _EQ_BAND_IDS:
            value = gains[band_id] if band_id in gains else self._eq_shown(band_id, now)
            if value is not None:
                pairs.append((band_id, value))
        self.set_eq_override(tuple(pairs), now + EQ_OPTIMISTIC_WINDOW_S)
        _enqueue_eq_set(
            _EqTarget(appliance_id, entry.ip, entry.port),
            **{f"{band_id}_db": gain for band_id, gain in gains.items()},
        )
        return ActionResult(True)

    def step_eq(self, appliance_id: str, band_id: str, delta: int) -> ActionResult:
        """Set a band to the gain shown plus *delta*, clamped to the band's
        range (a band not yet read starts from zero within the standard
        range)."""
        refusal = self._refusal(appliance_id, "dial_eq")
        if refusal is not None:
            return refusal
        if band_id not in _EQ_BAND_IDS:
            return ActionResult(False, "no_capability")
        held = self._snapshot.eq
        if held is None or held.appliance_id != appliance_id:
            return ActionResult(False, "not_polling")
        band = next((b for b in held.bands if b.id == band_id), None)
        low, high = (band.min_db, band.max_db) if band is not None else (-EQ_LIMIT_DB, EQ_LIMIT_DB)
        shown = self._eq_shown(band_id, self._clock())
        return self.set_eq(
            appliance_id, {band_id: max(low, min(high, (0 if shown is None else shown) + delta))},
        )

    # ---- worker results ----------------------------------------------------

    def on_outputs_result(self, kind: str, appliance_id: str, status, body, request=None) -> bool:
        """Fold an outputs worker result: a fetch becomes the held rows (an
        output another appliance has taken among them, marked), and clears
        the pending tap once it was stamped no later than now. A set result
        is not applied: the worker's own reading after it is. A result for
        an appliance other than the one held, or one that is malformed or
        failed, changes nothing. True when the rows were replaced."""
        if kind != "fetch":
            return False
        rows = dial_core_poll.parse_outputs_body(status, body)
        if rows is None:
            return False
        now = self._clock()

        def mutate(state: _CoreState) -> "bool | None":
            held = state.outputs
            if held is None or held.appliance_id != appliance_id:
                return False
            state.outputs = dataclasses.replace(held, rows=rows, loaded=True, fetched_at=now)
            override = state.outputs_optimistic
            if override is not None and override[3] <= now:
                state.outputs_optimistic = None
        return self._changed(mutate)

    def on_eq_result(self, kind: str, appliance_id: str, status, body, request=None) -> bool:
        """Fold an EQ worker result: a fetch becomes the held bands and
        clears the pending tap once its window has passed. Drops a result
        for another appliance and any malformed or failed one. True when the
        bands were replaced."""
        if kind != "fetch":
            return False
        bands = dial_core_poll.parse_eq_body(status, body)
        if bands is None:
            return False
        now = self._clock()

        def mutate(state: _CoreState) -> "bool | None":
            held = state.eq
            if held is None or held.appliance_id != appliance_id:
                return False
            state.eq = dataclasses.replace(held, bands=bands, loaded=True)
            pairs, expires_at = state.eq_optimistic
            if (pairs or expires_at) and expires_at <= now:
                state.eq_optimistic = ((), 0.0)
        return self._changed(mutate)

    # ---- transport -----------------------------------------------------------

    def begin_transport(self, appliance_id: str, kind: str) -> None:
        """Record that a request of *kind* ("seek", "stop" or "arm") has been
        sent to *appliance_id*; it stays pending until the worker reports
        the outcome and is replaced by the next request."""
        now = self._clock()

        def mutate(state: _CoreState) -> None:
            state.transport = TransportRequest(appliance_id, kind, now, "pending", now, None)
        self._publish(mutate)

    def _resolve_transport(
        self, appliance_id: str, outcome: str, error: str | None, now: float,
    ) -> TransportRequest | None:
        """Move the pending request for *appliance_id* to *outcome*; the
        request as it was, or None when there was none pending."""
        pending = []

        def mutate(state: _CoreState) -> "bool | None":
            held = state.transport
            if held is None or held.appliance_id != appliance_id or held.state != "pending":
                return False
            pending.append(held)
            state.transport = dataclasses.replace(
                held, state=outcome, changed_at=now, error=error,
            )
        self._publish(mutate)
        return pending[0] if pending else None

    def on_repeat_result(
        self, kind: str, appliance_id: str, status: int | None, body,
    ) -> RepeatOutcome:
        """Fold a repeat transport result (any request kind). An ok:true ack
        folds into the repeat store, opens the accepted-replay window when
        it says the appliance is replaying and the dial follows it, and
        marks the pending request accepted. Every other outcome (a 412, a
        200 with ok false, or no usable response) marks it rejected with the
        daemon's error string, only nudges the auth map's due-ness, clears
        the stored record when the daemon says the buffer is gone or a live
        source is back, and drops a pending focus on that appliance."""
        now = self._clock()
        if status == 200 and isinstance(body, dict) and body.get("ok"):
            repeat_store.apply_ack(appliance_id, body, now)
            accepted = body.get("state") == "replaying" and self.accept_replay(
                appliance_id, now + ACCEPTED_REPLAY_GRACE_S,
            )
            request = self._resolve_transport(appliance_id, "accepted", None, now)
            return RepeatOutcome(True, accepted, request is not None and request.kind == "stop")
        auth_map.force_due(appliance_id)
        error = body.get("error") if isinstance(body, dict) else None
        if not isinstance(error, str):
            error = "unreachable" if status is None else f"http_{status}"
        self._resolve_transport(appliance_id, "rejected", error, now)
        if status == 412 or (status == 200 and isinstance(body, dict)):
            if error in ("source_active", "no_recording"):
                repeat_store.clear(appliance_id)
        self.drop_pending_focus(appliance_id)
        return RepeatOutcome(False, False, False)

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
