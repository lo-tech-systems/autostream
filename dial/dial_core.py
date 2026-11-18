"""dial_core.py — the dial's appliance model, published as immutable
snapshots.

The core owns one mutable state record guarded by a lock, and a published
`CoreSnapshot` that readers fetch with a plain reference read. Every change
goes through `_publish`: mutate the state under the lock, build and store a
new snapshot with the next sequence number, wake any `wait_for_change`
callers, then (after the lock is released) tell each subscriber.

Locking: the core lock is held only for in-memory work. It is never held
across network or file I/O, a frame push or a subscriber callback, and it is
never taken while a display lock is held (nor a display lock while it is
held). Subscriber callbacks run inline on the publishing thread and must
only signal (`Event.set`, `queue.put_nowait`, `Condition.notify`); a
callback that blocks delays that publisher and nothing else. Consumers
coalesce: several publishes before a consumer runs collapse into one wake,
and the consumer reads the newest snapshot. `wait_for_change` is the same
idea for a consumer that would rather block than be called: any number of
threads may wait at once, each is woken by the publish that makes a newer
snapshot, and each gets whatever is newest when it runs, so a waiter that
loops on the `seq` it last saw never misses the latest state (it may skip
intermediate ones).

Every appliance is held by its own PeerClient in a peer pool
(`attach_pool`). `start()` runs one thread, `dial-core`: it folds the
clients' snapshots into one publish when the pool signals a change (paced to
a few folds a second) and at the fold interval, so a decision bound to time
moves on, and once a second does the housekeeping (the update watch,
expiring warnings, the replay position). The snapshot a
fold publishes carries a new `ticks` count and a `TickContext` saying what
the fold started from, which is how a view tells a finished fold from the
writes in between. What housekeeping does to the warning screens is queued
for the view as `SourceEffects` (`take_effects`), as is what the request
replies, network and SD health readings and volume readouts mean for a
screen. That queue is a channel for one view, not a notification mechanism:
a second consumer should use `subscribe` or `wait_for_change` and read the
snapshot. Taking is atomic, so two takers would split the effects between
them, each effect going to exactly one; a core with no view attached keeps
only the newest `EFFECTS_BACKLOG_MAX`.

The controls' requests go out on one request lane (dial_core_requests), the
HD page's intents on the caller's own thread (`submit_intent`), and artwork
on a short-lived thread of its own.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import dataclasses
import logging
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Callable

from autostream_peer_client import PeerReply, roster_view

import dial_artwork
import dial_core_focus
import dial_core_requests as rq
import dial_peer_view
from dial_config import SCOPE_ALL
from dial_eq_model import DERIVED_EQ_IDS, EQ_BASS_TREBLE_LIMIT_DB
from dial_appliance_warnings import DIAL_WARNING_ID, newer_appliance_names, protocol_warning
from dial_core_artwork import ArtworkFollower
from dial_core_effects import (
    OutputsEffect, RepeatEffect, RepeatOutcome, SourceEffects, StartFailureEffect, WarningChange,
)
from dial_core_model import CoreState, new_state, snapshot_of
from dial_core_state import (
    ACCEPTED_REPLAY_GRACE_S, AUTH_AUTHORIZED, AUTH_UNAUTHORIZED, OUTPUT_KINDS,
    EQ_OPTIMISTIC_WINDOW_S, NOWIFI_PROMPT_STREAK, ActionResult, CoreSnapshot,
    FocusState, FAILURE_DEFER, FAILURE_NOTICE, FAILURE_PIN, FAILURE_SEEN,
    START_FAILURE_HOLD_S, NowPlaying, StartFailureNotice, outputs_tap, PIN_RE,
    pin_capable_outputs, PowerState, TickContext, TransportRequest, WarningState,
    roster_entry, display_order, dots_active, eq_gain,
    reopen_for_pin, six_band, start_failure_action,
)
from dial_mdns import PROTOCOL
from dial_network import LINK_CONNECTED, LINK_DOWN, LINK_IGNORED
from dial_network import request_reboot as _default_reboot
from dial_network import request_shutdown as _default_shutdown
from dial_sdhealth import is_low as _sd_is_low
from dial_update_watch import (
    PHASE_REBOOT, PHASE_VERIFY, STATUS_FAILURE, STATUS_IN_PROGRESS, STATUS_SUCCESS,
    UPDATE_SEEN_PATH, UpdateWatcher, read_seen_marker, write_seen_marker,
)
from dial_values import clamp, clamp_percent, is_int
from dial_volume import (
    enqueue_delta, enqueue_mute, enqueue_mute_all, forget_mute_states_except,
    observe_master_volume, observe_master_volume_if_tracked, observe_mute_state, shown_muted,
    shown_volume,
)
from dial_warning_text import (
    NOWIFI_WARNING_ID, SDHEALTH_WARNING_ID, UPDATE_RESULT_WARNING_ID, UPDATE_WARNING_ID, WARNING_DESCRIPTORS,
    appliance_warning_descriptor, appliance_warning_key,
)
from dial_warnings import KIND_STATUS, WarningManager

# How often the clients are folded when nothing signals: the slowest the
# pending-focus and accepted-replay windows move on.
FOLD_INTERVAL_S = 6
# The housekeeping tick, and so the longest the core thread sleeps.
HOUSEKEEPING_INTERVAL_S = 1.0
# A fold asked for (a client's change, a touch, a focus change) within this
# long of the last fold's end waits for the gap, so a burst of changes costs
# one fold per gap. The periodic fold is not paced; its interval is longer.
FOLD_MIN_GAP_S = 0.4
# How often the dial's own address is read again.
ADDRESS_REFRESH_S = 60.0
# The most effects held for a view that is not draining them (none is
# attached); the oldest are dropped past it.
EFFECTS_BACKLOG_MAX = 256
# While an appliance is replaying, its repeat part is read again this often:
# the position is not part of the change stream.
REPEAT_FETCH_S = 5.0

# The intents submit_intent forwards for the HD page; any other name is
# refused without a request.
SUBMIT_INTENTS = frozenset((
    "outputs.set", "output.pin.submit", "output.eq.set", "output.eq.reset",
    "repeat.arm", "repeat.seek", "repeat.transport", "outputs.save_default",
))
# The core's own refusal names as the page is sent them: the appliance's or the
# library's name where one says the same, else the dial's own.
_REFUSAL_NAMES = {"unauthorized": "dial_not_authorized", "no_capability": "protocol_mismatch",
                  "not_polling": "wrong_state"}
# What each intent needs of the appliance, and the repeat states it acts from.
_INTENT_CAPABILITY = {
    "outputs.set": "dial_outputs", "output.pin.submit": "dial_outputs",
    "outputs.save_default": "dial_outputs", "output.eq.set": "dial_eq", "output.eq.reset": "dial_eq",
    "repeat.arm": "repeat_capable", "repeat.seek": "repeat_capable", "repeat.transport": "repeat_capable",
}
_INTENT_REPEAT_STATES = {
    "repeat.seek": ("replaying", "hold"), "repeat.transport": ("replaying",),
    "repeat.arm": ("recording", "pending", "idle"),
}
_INTENT_KINDS = {"repeat.seek": "seek", "repeat.transport": "stop", "repeat.arm": "arm"}

# FocusState fields that can be written one at a time.
_FOCUS_FIELDS = frozenset((
    "manual_id", "bound_id", "pending", "reporting_id",
    "source_service_name", "accepted_replay",
))

# The remaining single-value fields that can be written the same way.
_PLAIN_FIELDS = frozenset((
    "now_playing", "idle_affordance", "dots_active", "outputs_available", "eq_available",
))


def _eq_band_ids(held) -> tuple:
    """The band ids a set may name given the EQ state held: bass and treble
    always, and the appliance's own bands once a six-band reading has
    landed."""
    if held is None or not six_band(held.capability_version):
        return DERIVED_EQ_IDS
    return DERIVED_EQ_IDS + tuple(b.id for b in held.bands if b.id not in DERIVED_EQ_IDS)


@dataclass
class CoreIO:
    """The calls the core makes out of itself: the artwork download and the
    volume worker's readout store. Each defaults to the real one, looked up
    when it is called; a view or a test supplies stand-ins that do the same,
    so replacing a module attribute still takes effect."""
    fetch_artwork: Callable = lambda url, timeout: dial_artwork.default_fetch_artwork(url, timeout)
    artwork_eligible: Callable = lambda url: dial_artwork.default_artwork_eligible(url)
    observe_mute: Callable = lambda *a, **k: observe_mute_state(*a, **k)
    observe_volume: Callable = lambda *a, **k: observe_master_volume(*a, **k)
    observe_volume_tracked: Callable = lambda *a, **k: observe_master_volume_if_tracked(*a, **k)
    forget_mute: Callable = lambda *a, **k: forget_mute_states_except(*a, **k)
    on_artwork_error: Callable[[str], None] | None = None
    # Starts the short-lived artwork thread: spawn(fn, *args).
    spawn: Callable = lambda fn, *args: threading.Thread(
        target=fn, args=args, daemon=True, name="dial-artwork").start()
    log_limiter: object = dataclasses.field(default_factory=dial_artwork.RateLimitedLogger)


class DialCore:
    def __init__(
        self,
        dial_id: str,
        *,
        clock: Callable[[], float] | None = None,
        warnings: WarningManager | None = None,
        update_watcher: UpdateWatcher | None = None,
        update_seen_path: str = UPDATE_SEEN_PATH,
        reboot: Callable[[], bool] | None = None,
        shutdown: Callable[[Callable[[bool], None]], bool] | None = None,
        io: CoreIO | None = None,
    ) -> None:
        self._dial_id = dial_id
        # Looked up at each call, so a test that replaces time.monotonic
        # moves the core's clock with everything else.
        self._clock = clock if clock is not None else (lambda: time.monotonic())
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._state = new_state(dial_id)
        self._seq = 0
        self._subscribers: dict[int, Callable[[], None]] = {}
        self._next_handle = 1
        # The warning manager owns which warnings are active and which
        # status is due; it has its own leaf lock and is never called while
        # it could call back. The update watcher and the seen
        # marker belong to the update source, driven from one thread.
        self.warnings = warnings if warnings is not None else WarningManager(WARNING_DESCRIPTORS)
        self.update_watcher = update_watcher if update_watcher is not None else UpdateWatcher()
        self.update_seen_path = update_seen_path
        self._update_seen: str | None = None
        self._reboot = reboot if reboot is not None else _default_reboot
        self._shutdown = shutdown if shutdown is not None else _default_shutdown
        self._io = io if io is not None else CoreIO()
        self._artwork = ArtworkFollower(
            lock=lambda: self._lock, publish=lambda fn: self._publish(fn),
            held=lambda: self._state.artwork, io=lambda: self._io, clock=lambda: self._clock())
        self._eq_veto: Callable[[], bool] = lambda: False
        self._mute_scope: Callable[[], str] = lambda: ""
        self._idle_hold: Callable[[bool], bool] = lambda focus_cleared: False
        # Other threads only raise the wake; the fold's bookkeeping belongs
        # to the core thread.
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._prev_playing_ids: set[str] = set()
        self._volume_seen: tuple | None = None         # (service, master volume) last given to the readout
        self._effects: list = []
        # What the dial says about itself: read again on the housekeeping
        # tick, and published only when one of them changed.
        self._name_source: Callable[[], str] | None = None
        self._volume_scope: Callable[[], str] | None = None
        self._address_source: Callable[[], str] | None = None
        self._address_at = 0.0
        # The appliances as the peer pool holds them (see attach_pool); with
        # none attached the core holds no appliance.
        self.pool = None
        self._registry = None
        self._lane: rq.RequestLane | None = None
        self._own_requester = f"dial:{dial_id}"
        self._sightings: dict = {}
        self._waiting: dict[str, rq.Waiting] = {}      # request lane name -> what its shown value waits for
        self._repeat_fetch_at: dict[str, float] = {}
        self._failures_read: set[str] = set()          # appliances whose start failure has been read once
        self._sync_warnings_locked(self._state)
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
        `unsubscribe`. The callback must only signal: it runs on whichever
        thread published (the core thread, a tap, a worker), so one that
        blocks delays that thread. It may subscribe or unsubscribe (itself or
        another) and may publish; an exception it raises is logged and
        ignored."""
        with self._lock:
            handle = self._next_handle
            self._next_handle += 1
            self._subscribers[handle] = callback
        return handle

    def unsubscribe(self, handle: int) -> None:
        """Remove a subscriber; an unknown handle is ignored. Safe from any
        thread, including from inside a callback. A publish already past its
        snapshot of the subscribers skips a callback removed before its turn,
        but one already running is not interrupted."""
        with self._lock:
            self._subscribers.pop(handle, None)

    # ---- publishing --------------------------------------------------------

    def _build_snapshot_locked(self) -> CoreSnapshot:
        return snapshot_of(self._state, self._seq, self._clock())

    def _publish(self, mutate_fn: Callable[[CoreState], "bool | None"]) -> CoreSnapshot:
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
            callbacks = tuple(self._subscribers.items())
        for handle, callback in callbacks:
            if handle not in self._subscribers:
                continue
            try:
                callback()
            except Exception:
                logging.debug("dial core: subscriber callback raised", exc_info=True)
        return snap

    # ---- field writes ------------------------------------------------------

    def roster(self) -> list:
        """The appliance states in roster order as last folded: a reference
        read, no lock. The list is shared and must not be edited."""
        return self._state.roster

    def set_field_for_tests(self, name: str, value) -> CoreSnapshot:
        """Test hook: store one value and publish: a focus field (`manual_id`,
        `bound_id`, `pending`, `reporting_id`, `source_service_name`,
        `accepted_replay`) or one of the plain fields
        (`now_playing`, `idle_affordance`, `dots_active`,
        `outputs_available`, `eq_available`). Nothing is published when the
        stored value is already that object or equal to it. The read-modify-write of a
        focus field happens under the lock, so writers of different focus
        fields never lose each other's update."""
        if name in _FOCUS_FIELDS:
            def mutate(state: CoreState) -> "bool | None":
                held = getattr(state.focus, name)
                if held is value or held == value:
                    return False
                state.focus = dataclasses.replace(state.focus, **{name: value})
        elif name in _PLAIN_FIELDS:
            def mutate(state: CoreState) -> "bool | None":
                held = getattr(state, name)
                if held is value or held == value:
                    return False
                setattr(state, name, value)
        else:
            raise KeyError(name)
        return self._publish(mutate)

    # ---- artwork -----------------------------------------------------------

    def clear_artwork(self, key: str | None = None) -> None:
        """Release the held artwork bytes: always, or only when they are the
        copy named by *key*."""
        self._artwork.clear(key)

    # ---- focus -------------------------------------------------------------

    def set_focus(self, appliance_id: str | None) -> ActionResult:
        """Pin the display to *appliance_id*, or clear it back to auto-pick
        with None, and wake the core so the switch lands at once. Never
        persisted. Refused for an appliance that has refused this dial; an
        id that is not on the roster is taken (the next fold drops a focus
        that has gone)."""
        entry = roster_entry(self._state.roster, appliance_id)
        if entry is not None and entry.auth == AUTH_UNAUTHORIZED:
            return ActionResult(False, "unauthorized")
        def mutate(state: CoreState) -> "bool | None":
            held = state.focus.manual_id
            if held is appliance_id or held == appliance_id:
                return False
            state.focus = dataclasses.replace(state.focus, manual_id=appliance_id)
        self._publish(mutate)
        self._wake.set()
        return ActionResult(True)

    def set_focus_pending(self, appliance_id: str, service_name: str, expires_at: float) -> None:
        """Pin the focus to *appliance_id* and mark it pending until
        *expires_at*: a picker-started replay has not yet reached the
        playing set, so the ordinary "gone from the roster" clear must not
        fire before it has had a chance to appear."""
        def mutate(state: CoreState) -> None:
            state.focus = dial_core_focus.with_pending(state.focus, appliance_id, service_name, expires_at)
        self._publish(mutate)

    def drop_pending_focus(self, appliance_id: str) -> bool:
        """Clear the manual and pending focus when the pending focus is for
        *appliance_id* (its replay did not start). True if it was cleared."""
        def mutate(state: CoreState) -> "bool | None":
            dropped = dial_core_focus.dropped_pending(state.focus, appliance_id)
            if dropped is None:
                return False
            state.focus = dropped
        return self._changed(mutate)

    def accept_replay(self, appliance_id: str, until: float) -> bool:
        """Open the accepted-replay window for *appliance_id* until *until*,
        when the dial is following that appliance. True if it was opened."""
        def mutate(state: CoreState) -> "bool | None":
            accepted = dial_core_focus.with_accepted(state.focus, appliance_id, until)
            if accepted is None:
                return False
            state.focus = accepted
        return self._changed(mutate)

    def _changed(self, mutate_fn: Callable[[CoreState], "bool | None"]) -> bool:
        """Publish through *mutate_fn*; True if it changed anything."""
        changed = []

        def wrapped(state: CoreState) -> "bool | None":
            if mutate_fn(state) is False:
                return False
            changed.append(True)
        self._publish(wrapped)
        return bool(changed)

    # ---- outputs and EQ ----------------------------------------------------

    def _focused_id(self) -> str | None:
        focus = self._snapshot.focus
        return focus.manual_id or focus.reporting_id

    # -- optimistic values --

    def outputs_override(self) -> tuple | None:
        """The outputs tap the latest output request shows, (output_id,
        selected, volume, requested_at), or None. Derived from the current
        snapshot."""
        return outputs_tap(self._snapshot)

    def eq_override(self) -> tuple:
        """The pending EQ tap, (((band_id, gain_db), ...), expires_at); no
        pairs and 0.0 when there is none. A reference read."""
        return self._state.eq_optimistic

    def set_eq_override(self, pairs: tuple, expires_at: float) -> None:
        def mutate(state: CoreState) -> "bool | None":
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
        return self._refusal_in(self._state, appliance_id, capability)

    def _refusal_in(self, state: CoreState, appliance_id: str, capability: str) -> ActionResult | None:
        """Why a request needing *capability* cannot go to *appliance_id*, or
        None. The capability is the appliance's own state, which has every
        capability or none (one protocol)."""
        entry = roster_entry(state.roster, appliance_id)
        if entry is None:
            return ActionResult(False, "unknown_appliance")
        if not getattr(entry, capability, False):
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
        pin: str | None = None, pin_entry: bool = False,
    ) -> ActionResult:
        """Enable or disable an output, or set its level. The change shows
        at once (as the request's shown value) until the appliance's state
        has caught up with the reply. Refused when the appliance is
        unknown, lacks the capability or has refused this dial, when the
        output is not among the rows held, or when another appliance has
        taken it.

        A *pin* (four to eight digits) is sent as a PIN submission that
        enables the output once the speaker is paired; it needs an appliance
        that accepts one (outputs capability 2) and is held only in the
        request body, never in the state or the snapshot. *pin_entry* says
        the caller can show a keypad, so the appliance may ask this dial for
        a PIN.

        The request is recorded on `outputs_request`, carrying the value
        it shows meanwhile. Its outcome is published there when the reply
        lands, and queued as an `OutputsEffect`."""
        refusal = self._refusal(appliance_id, "dial_outputs")
        if refusal is not None:
            return refusal
        if pin is not None and not (isinstance(pin, str) and PIN_RE.match(pin)):
            return ActionResult(False, "wrong_state")
        row = self._output_row(appliance_id, output_id)
        if row is None or row.remote_in_use or (selected is None and volume is None and pin is None):
            return ActionResult(False, "wrong_state")
        entry = roster_entry(self._state.roster, appliance_id)
        if pin is not None and not pin_capable_outputs(entry.dial_outputs_version):
            return ActionResult(False, "no_capability")
        shown_selected = True if pin is not None else (row.selected if selected is None else selected)
        begin, token = self._begin_request(
            "outputs_request", appliance_id, "output_set" if pin is None else "output_pin",
            output_id=output_id, shown=(shown_selected, row.volume if volume is None else volume),
        )
        self._publish(begin)
        intent = (rq.output_pin(output_id, pin) if pin is not None else rq.output_set(
            output_id, selected=shown_selected, volume=volume, pin_entry=pin_entry))
        self._send(appliance_id, intent, token)
        return ActionResult(True, token=token)

    def step_output_volume(self, appliance_id: str, output_id: str, delta: int) -> ActionResult:
        """Set an output's level to the level shown plus *delta*, clamped to
        0..100. A disabled output has no level to step from."""
        refusal = self._refusal(appliance_id, "dial_outputs")
        if refusal is not None:
            return refusal
        row = self._output_row(appliance_id, output_id)
        if row is None or row.remote_in_use:
            return ActionResult(False, "wrong_state")
        override = self.outputs_override()
        if override is not None and override[0] == row.id and override[1]:
            shown = override[2]
        else:
            shown = row.volume if row.selected else None
        if shown is None:
            return ActionResult(False, "wrong_state")
        return self.set_output(
            appliance_id, output_id, selected=True, volume=clamp_percent(shown + delta),
        )

    def step_eq(self, appliance_id: str, band_id: str, delta: int) -> ActionResult:
        """Set a band to the gain shown plus *delta*, clamped to the band's
        range (a band not yet read starts from zero within the standard
        range). The new value shows at once, the other bands keeping what
        they show now, for EQ_OPTIMISTIC_WINDOW_S; only this band is sent.
        Refused for an unknown appliance, one without the capability or that
        has refused this dial, when no EQ state is held for it, and for a
        band id the capability does not have."""
        refusal = self._refusal(appliance_id, "dial_eq")
        if refusal is not None:
            return refusal
        held = self._snapshot.eq
        if held is not None and held.appliance_id != appliance_id:
            held = None
        band_ids = _eq_band_ids(held)
        if band_id not in band_ids:
            return ActionResult(False, "no_capability")
        if held is None:
            return ActionResult(False, "not_polling")
        band = next((b for b in held.bands if b.id == band_id), None)
        low, high = (band.min_db, band.max_db) if band is not None else (-EQ_BASS_TREBLE_LIMIT_DB, EQ_BASS_TREBLE_LIMIT_DB)
        now = self._clock()
        shown = self._eq_shown(band_id, now)
        target = clamp((0 if shown is None else shown) + delta, low, high)
        pairs = []
        for other_id in band_ids:
            value = target if other_id == band_id else self._eq_shown(other_id, now)
            if value is not None:
                pairs.append((other_id, value))
        self.set_eq_override(tuple(pairs), now + EQ_OPTIMISTIC_WINDOW_S)
        self._send(appliance_id, rq.eq_set({band_id: target}), now)
        return ActionResult(True)

    # ---- transport -----------------------------------------------------------

    def begin_transport(self, appliance_id: str, kind: str) -> float:
        """Record that a request of *kind* ("seek", "stop" or "arm") has been
        sent to *appliance_id*; it stays pending until its reply is folded
        and is replaced by the next request. Returns its token."""
        mutate, token = self._begin_request("transport", appliance_id, kind)
        self._publish(mutate)
        return token

    def _begin_request(
        self, lane: str, appliance_id: str, kind: str, *, output_id: str | None = None,
        shown: tuple | None = None,
    ) -> tuple[Callable[[CoreState], None], float]:
        """The mutate function that records a pending request of *kind* on
        *lane* ("transport" or "outputs_request"), so a caller can fold it
        into a publish of its own, and the request's token: the monotonic
        time it began, which the reply is folded against. The next
        request on the lane replaces it. *shown* is what the request shows for
        its output until the appliance's state catches up or a rejection
        takes it."""
        now = self._clock()

        def mutate(state: CoreState) -> None:
            setattr(state, lane, TransportRequest(
                appliance_id, kind, now, "pending", now, None, output_id, 0, shown,
            ))
        return mutate, now

    def _repeat_refusal(self, appliance_id: str, states: tuple) -> ActionResult | None:
        """Why a replay or repeat request cannot go to *appliance_id*, or
        None when it can: the appliance must be known, repeat-capable and
        not have refused this dial, hold a usable record, and have that
        record in one of *states*."""
        return self._repeat_refusal_in(self._state, appliance_id, states)

    def _repeat_refusal_in(self, state: CoreState, appliance_id: str, states: tuple) -> ActionResult | None:
        refusal = self._refusal_in(state, appliance_id, "repeat_capable")
        if refusal is not None:
            return refusal
        record = getattr(roster_entry(state.roster, appliance_id), "repeat", None)
        if record is None or not record.available:
            return ActionResult(False, "no_record")
        if record.state not in states:
            return ActionResult(False, "wrong_state")
        return None

    def _send_transport(self, appliance_id: str, action: str) -> ActionResult:
        """Record the request as pending and queue it on the request lane."""
        token = self.begin_transport(appliance_id, action)
        self._send(appliance_id, rq.replay_stop() if action == "stop" else rq.replay_seek(), token)
        return ActionResult(True, token=token)

    def start_replay(self, appliance_id: str) -> ActionResult:
        """Start the appliance's held recording from the beginning. The
        focus is pinned to it as pending first, so the screen follows it
        through the gap before the replay reaches the playing set; a
        rejected request drops that again when its reply is folded.
        Refused as restart_replay is."""
        refusal = self._repeat_refusal(appliance_id, ("replaying", "hold"))
        if refusal is not None:
            return refusal
        entry = roster_entry(self._state.roster, appliance_id)
        self.set_focus_pending(
            appliance_id, entry.service_name, self._clock() + dial_core_focus.FOCUS_PENDING_GRACE_S)
        self._wake.set()
        return self._send_transport(appliance_id, "seek")

    def restart_replay(self, appliance_id: str) -> ActionResult:
        """Seek a running replay back to its start, or start one from Hold.
        Refused unless the record is replaying or in hold (a live source
        recording, or a replay fading out, is not something to seek)."""
        refusal = self._repeat_refusal(appliance_id, ("replaying", "hold"))
        if refusal is not None:
            return refusal
        return self._send_transport(appliance_id, "seek")

    def stop_replay(self, appliance_id: str) -> ActionResult:
        """Stop a running replay (it fades out and lands in Hold, disarmed).
        Recorded as the pending request so its reply can be told from an
        unrelated seek's. Refused unless the record is replaying."""
        refusal = self._repeat_refusal(appliance_id, ("replaying",))
        if refusal is not None:
            return refusal
        return self._send_transport(appliance_id, "stop")

    def set_repeat_armed(self, appliance_id: str, armed: bool) -> ActionResult:
        """Arm or disarm the appliance's repeat daemon. Refused unless the
        record is recording, pending or idle (the states that have the
        toggle)."""
        refusal = self._repeat_refusal(appliance_id, ("recording", "pending", "idle"))
        if refusal is not None:
            return refusal
        token = self.begin_transport(appliance_id, "arm")
        self._send(appliance_id, rq.repeat_arm(bool(armed)), token)
        return ActionResult(True, token=token)

    # ---- warnings, update watch and sources ----------------------------------

    def _derive_appliances_locked(self, state: CoreState) -> tuple:
        """The appliance list: the appliances' own mapped states, each
        carrying its warnings and the dial's own for it."""
        merged = self._all_warnings(state)
        return tuple(display_order(
            dataclasses.replace(v, warnings=merged.get(aid, ())) for aid, v in state.views.items()
        ))

    @staticmethod
    def _all_warnings(state: CoreState) -> dict:
        """Each appliance's own warnings followed by the dial's protocol
        warning for it, when it has one."""
        merged = dict(state.appliance_warnings)
        for appliance_id, warning in state.protocol_warnings.items():
            merged[appliance_id] = merged.get(appliance_id, ()) + (warning,)
        return merged

    def _sync_warnings_locked(self, state: CoreState) -> bool:
        """Copy the warning manager's runtime state and due status into
        *state*. True when either changed."""
        warnings = tuple(WarningState(*row) for row in self.warnings.runtime())
        due = self.warnings.due_status()
        due_id = due.id if due is not None else None
        changed = warnings != state.warnings or due_id != state.due_status_id
        state.warnings = warnings
        state.due_status_id = due_id
        return changed

    def warning_active(self, warning_id: str, reading=None) -> WarningChange:
        """A source reports its condition present (again); a repeat only
        refreshes the reading. The change says whether this began a new
        incident."""
        began = []

        def mutate(state: CoreState) -> "bool | None":
            began.append(self.warnings.set_active(warning_id, reading))
            return None if self._sync_warnings_locked(state) else False
        self._publish(mutate)
        return WarningChange(warning_id, True, bool(began and began[0]))

    def warning_cleared(self, warning_id: str) -> WarningChange:
        """A source reports its condition gone: the incident ends."""
        def mutate(state: CoreState) -> "bool | None":
            self.warnings.clear(warning_id)
            return None if self._sync_warnings_locked(state) else False
        self._publish(mutate)
        return WarningChange(warning_id, False)

    def close_status(self, status_id: str) -> ActionResult:
        """End a status the person has closed (the update result): the same
        as its source clearing it. Refused with wrong_state for an id that
        is not a registered status. Warnings are closed in the view that
        shows them and never reach the core."""
        desc = self.warnings.descriptor(status_id)
        if desc is None or desc.kind != KIND_STATUS:
            return ActionResult(False, "wrong_state")
        self.warning_cleared(status_id)
        return ActionResult(True)

    def request_dial_reboot(self) -> bool:
        """Ask for a reboot of the dial's own system (rate-gated where the
        request is made). True when a request went out."""
        try:
            return bool(self._reboot())
        except Exception:
            logging.debug("dial core: reboot request raised", exc_info=True)
            return False

    def request_dial_shutdown(self) -> bool:
        """Ask for a graceful power-off of the dial's own system (one
        request at a time). True when a request went out; the outcome of one
        that did not happen is folded into `power` by `_on_shutdown_outcome`."""
        if self._state.power.state == "requested":
            return False
        early: list = []    # an outcome that reached us before the request was published
        try:
            accepted = bool(self._shutdown(lambda ok: self._on_shutdown_outcome(ok, early)))
        except Exception:
            logging.debug("dial core: shutdown request raised", exc_info=True)
            return False
        if not accepted:
            return False

        def mutate(state: CoreState) -> None:
            state.power = PowerState("failed" if early else "requested", self._clock())
        self._publish(mutate)
        return True

    def _on_shutdown_outcome(self, ok: bool, early: "list | None" = None) -> None:
        """Fold the network thread's report of a power-off request. A success
        needs no state (the power goes); a failure ends a request in hand.
        One that arrives before the request was published is left in *early*
        for the publish to read, under the same lock."""
        if ok:
            return

        def mutate(state: CoreState) -> "bool | None":
            if state.power.state != "requested":
                if early is not None:
                    early.append(False)
                return False
            state.power = PowerState("failed", self._clock())
        self._changed(mutate)

    def on_network_view(self, view) -> SourceEffects:
        """Fold a network reading. Connected: the streak resets, the
        ever-connected latch is set and the No-WiFi warning clears. Down:
        the streak grows, and at NOWIFI_PROMPT_STREAK the warning goes
        active unless the link has never been connected since the process
        started. Ignored (setup mode, reboot pending): the streak resets,
        the warning and the latch stay. Any other reading changes nothing
        but the held view. What it did to the warnings is queued for a view
        and returned."""
        changes = []

        def mutate(state: CoreState) -> "bool | None":
            changed = state.network != view
            state.network = view
            if view.link == LINK_CONNECTED:
                changed = changed or not state.wifi_ever_connected
                state.wifi_ever_connected = True
                state.wifi_down_streak = 0
                self.warnings.clear(NOWIFI_WARNING_ID)
                changes.append(WarningChange(NOWIFI_WARNING_ID, False))
            elif view.link == LINK_DOWN:
                state.wifi_down_streak += 1
                if state.wifi_ever_connected and state.wifi_down_streak >= NOWIFI_PROMPT_STREAK:
                    began = self.warnings.set_active(NOWIFI_WARNING_ID)
                    changes.append(WarningChange(NOWIFI_WARNING_ID, True, began))
            elif view.link == LINK_IGNORED:
                state.wifi_down_streak = 0
            if self._sync_warnings_locked(state):
                changed = True
            return None if changed else False
        self._publish(mutate)
        return self._queue_effects(SourceEffects(tuple(changes)))

    def on_sd_health_view(self, view) -> SourceEffects:
        """Fold an SD health reading: low (with hysteresis) starts or
        refreshes the warning with the percent as its severity; not low
        ends the incident. What it did to the warnings is queued for a
        view and returned."""
        changes = []

        def mutate(state: CoreState) -> "bool | None":
            changed = state.sd_health != view
            state.sd_health = view
            low = _sd_is_low(view, state.sd_low)
            state.sd_low = low
            if low:
                began = self.warnings.set_active(SDHEALTH_WARNING_ID, view.percent)
                changes.append(WarningChange(SDHEALTH_WARNING_ID, True, began))
            else:
                self.warnings.clear(SDHEALTH_WARNING_ID)
                changes.append(WarningChange(SDHEALTH_WARNING_ID, False))
            if self._sync_warnings_locked(state):
                changed = True
            return None if changed else False
        self._publish(mutate)
        return self._queue_effects(SourceEffects(tuple(changes)))

    def apply_update_view(self, view) -> SourceEffects:
        """Fold a software update reading. A run in progress raises the
        progress card, except in the reboot phase (the caller shows its
        restarting screen; the updater has already asked for the reboot)
        and the verify phase (nothing until the verdict). A finished run
        raises its result card once, recorded in the seen marker, which
        is file I/O, so call with no lock held."""
        def store(state: CoreState) -> "bool | None":
            if state.update == view:
                return False
            state.update = view
        self._publish(store)
        changes = []
        restarting = False
        if view.status == STATUS_IN_PROGRESS:
            if view.phase == PHASE_REBOOT:
                changes.append(self.warning_cleared(UPDATE_WARNING_ID))
                restarting = True
            elif view.phase != PHASE_VERIFY:
                changes.append(self.warning_active(UPDATE_WARNING_ID, view))
        elif view.status in (STATUS_SUCCESS, STATUS_FAILURE):
            marker = view.last_run_at or f"{view.status}-{view.tag}"
            if self._update_seen is None:
                self._update_seen = read_seen_marker(self.update_seen_path)
            if marker == self._update_seen:
                return SourceEffects(signal=False)
            self._update_seen = marker
            write_seen_marker(marker, self.update_seen_path)
            changes.append(self.warning_cleared(UPDATE_WARNING_ID))
            changes.append(self.warning_active(UPDATE_RESULT_WARNING_ID, view))
        return SourceEffects(tuple(changes), restarting)

    def tick_update_watch(self, now: float) -> SourceEffects | None:
        """Read the update result file when it has changed (a stat() while
        nothing is happening) and fold it; None when it has not changed."""
        view = self.update_watcher.tick(now)
        return None if view is None else self.apply_update_view(view)

    def expire_warnings(self) -> SourceEffects:
        """Clear the warnings that have been active for their
        auto_clear_after_s, as a source's clear would, and refresh the
        published due status."""
        changes = tuple(self.warning_cleared(wid) for wid in self.warnings.expired())

        def mutate(state: CoreState) -> "bool | None":
            return None if self._sync_warnings_locked(state) else False
        self._publish(mutate)
        return SourceEffects(changes, signal=bool(changes))

    def tick_housekeeping(self, now: float) -> SourceEffects:
        """The once-a-second tick: the update watch and expired warnings.
        Does file I/O: call with no lock held."""
        watched = self.tick_update_watch(now)
        expired = self.expire_warnings()
        if watched is None:
            return expired
        return SourceEffects(
            watched.changes + expired.changes, watched.restarting, watched.signal or expired.signal,
        )

    def _store_appliance_warnings_locked(self, state: CoreState, appliance_id: str, new: tuple) -> bool:
        """Replace the appliance's held warnings with *new* (validated and
        attributed): each is registered on the manager and reported active,
        and those no longer present end their incidents. False when *new* is
        what is held."""
        old = state.appliance_warnings.get(appliance_id, ())
        if new == old:
            return False
        kept = {w.id for w in new}
        for warning in old:
            if warning.id not in kept:
                self.warnings.unregister(appliance_warning_key(appliance_id, warning.id))
        for warning in new:
            key = appliance_warning_key(appliance_id, warning.id)
            self.warnings.register(appliance_warning_descriptor(appliance_id, warning))
            self.warnings.set_active(key, warning.severity)
        held = dict(state.appliance_warnings)
        if new:
            held[appliance_id] = new
        else:
            held.pop(appliance_id, None)
        state.appliance_warnings = held
        return True

    def set_mute_scope(self, scope: Callable[[], str]) -> None:
        """Say how far a mute toggle reaches: *scope* returns the dial's
        live effective mute scope on every call, so a settings change
        applies to the next press."""
        self._mute_scope = scope

    def set_volume_scope(self, scope: Callable[[], str]) -> None:
        """Say how far a volume step reaches, for the dial's published
        info: *scope* returns the live effective volume scope on every call.
        The worker resolves its own targets, so this changes nothing a step
        does."""
        self._volume_scope = scope

    def set_identity(self, name: Callable[[], str], version: str, port: int) -> None:
        """Say who this dial is: *name* returns its live name on every call
        (a settings change applies on the next housekeeping tick), *version* and *port*
        are fixed."""
        self._name_source = name
        self._publish(lambda state: self._replace_dial(state, version=version, port=port))
        self._refresh_dial_info(self._clock())

    def set_address_source(self, address: Callable[[], str]) -> None:
        """Say how to read the dial's own address ("" when it has none):
        called on the core thread every `ADDRESS_REFRESH_S`, never from
        any other thread."""
        self._address_source = address
        self._address_at = 0.0

    def set_inputs(self, inputs) -> None:
        """Say which physical inputs are running (`"encoder"`, `"button"`,
        `"touch:<type>"`), in the order given."""
        inputs = tuple(inputs)
        self._publish(lambda state: self._replace_dial(state, inputs=inputs))

    @staticmethod
    def _replace_dial(state: CoreState, **fields) -> "bool | None":
        """Apply *fields* to the published dial info; False when none of
        them differs."""
        dial = dataclasses.replace(state.dial, **fields)
        if dial == state.dial:
            return False
        state.dial = dial

    def _refresh_dial_info(self, now: float) -> None:
        """Re-read the live name, the effective scopes and (every
        `ADDRESS_REFRESH_S`) the address, and publish them when they
        changed. A source that raises keeps the value held."""
        fields = {}
        for field, source in (
            ("name", self._name_source), ("volume_scope", self._volume_scope),
            ("mute_scope", self._mute_scope),
        ):
            if source is None:
                continue
            try:
                value = source()
            except Exception:
                continue
            if isinstance(value, str) and value:
                fields[field] = value
        if self._address_source is not None and now >= self._address_at:
            self._address_at = now + ADDRESS_REFRESH_S
            try:
                address = self._address_source()
            except Exception:
                address = None
            if isinstance(address, str):
                fields["ip"] = address
        if fields:
            self._publish(lambda state: self._replace_dial(state, **fields))

    def _readout_now(self) -> tuple:
        """(service, shown volume) for the appliance the dial reports from,
        as the volume worker's store has it at this moment. The service is
        the one the fold records its volume and mute observations under.
        Plain reads; never called with the core lock held."""
        playing = self._state.now_playing
        service = playing.service_name if playing is not None else None
        return (service, shown_volume(service))

    def readout_changed(self) -> None:
        """The volume worker has a new reading for the readout: publish it
        with the service it belongs to, and queue a repaint for a view. Safe
        from the worker thread; never raises into it."""
        try:
            readout = self._readout_now()

            def mutate(state: CoreState) -> None:
                state.volume_readout = readout
                self._effects.append(SourceEffects())
                del self._effects[:-EFFECTS_BACKLOG_MAX]
            self._publish(mutate)
        except Exception:
            logging.debug("dial core: readout_changed raised", exc_info=True)

    def mute_changed(self) -> None:
        """The mute state the dial shows may have changed (a press was
        echoed, or an appliance answered one): publish, so whoever builds
        from the snapshot reads the mute store again. The mute flag is not
        part of the snapshot, so this always publishes; no repaint is queued
        for a view, which reads the store whenever it paints. Safe from the
        worker thread; never raises into it."""
        try:
            readout = self._readout_now()

            def mutate(state: CoreState) -> None:
                state.volume_readout = readout
            self._publish(mutate)
        except Exception:
            logging.debug("dial core: mute_changed raised", exc_info=True)

    def _not_focused(self, appliance_id: str | None) -> ActionResult | None:
        """The refusal for an id-addressed master volume or mute request:
        the volume worker resolves its own targets, so for now only the
        appliance the dial is following can be addressed by id."""
        if appliance_id is not None and appliance_id != self._focused_id():
            return ActionResult(False, "not_focused")
        return None

    def volume_step(self, delta: int, appliance_id: str | None = None) -> ActionResult:
        """Queue a master volume change of *delta* percent for the volume
        worker, which resolves the target when it sends. With an id, refused
        unless that is the appliance the dial is following."""
        refusal = self._not_focused(appliance_id)
        if refusal is not None:
            return refusal
        enqueue_delta(delta)
        return ActionResult(True)

    def volume_set(self, level: int, appliance_id: str | None = None) -> ActionResult:
        """Move the master volume to *level* (0..100) by queueing the
        difference from what is shown now, which is how the volume worker
        already takes its changes. Refused when nothing has been observed
        yet, or for a level outside the range. With an id, refused unless
        that is the appliance the dial is following."""
        refusal = self._not_focused(appliance_id)
        if refusal is not None:
            return refusal
        if not is_int(level) or not 0 <= level <= 100:
            return ActionResult(False, "wrong_state")
        shown = shown_volume(self.current_source_service_name())
        if shown is None:
            return ActionResult(False, "wrong_state")
        if level != shown:
            enqueue_delta(level - shown)
        return ActionResult(True)

    def mute_toggle(self, appliance_id: str | None = None) -> ActionResult:
        """Toggle mute. Under the broadcast scope "all" a fleet toggle is
        queued, decided when the worker sends; otherwise what the followed
        appliance last reported is flipped, and the flipped state, which
        the mute store shows at once, is published. Plain reads, a queue put
        and a publish: no network. With an id, refused unless that is the
        appliance the dial is following."""
        refusal = self._not_focused(appliance_id)
        if refusal is not None:
            return refusal
        if self._mute_scope() == SCOPE_ALL:
            # Nothing is known yet: the worker decides, echoes and reports
            # the change itself (see mute_changed).
            enqueue_mute_all()
        else:
            enqueue_mute(shown_muted(self.current_source_service_name()))
            self.mute_changed()
        return ActionResult(True)

    def current_source_service_name(self) -> str | None:
        """mDNS service name of the display's chosen artwork source, or
        None when nothing is identified/playing. Plain reference read, safe
        from any thread; may lag the clients by one fold. Used by
        dial_main's volume-target resolver so a touch/encoder press
        addresses whatever this dial is showing, or, with a manual focus,
        the focused appliance, see focus_volume_target()."""
        return self._snapshot.focus.source_service_name

    def focus_volume_target(self):
        """The appliance state the volume/mute worker should address while a
        manual focus is set: that appliance, playing or idle, when it is on
        the last-folded roster and not confirmed unauthorized; else None (no
        focus, or the focus is not on the roster), meaning "use the ordinary
        playing-set resolution". The worker sends through the pool's client
        for its appliance id. Plain reference reads, safe from the worker
        thread; may lag the clients by one fold."""
        focus_id = self._snapshot.focus.manual_id
        if not focus_id:
            return None
        entry = roster_entry(self._state.roster, focus_id)
        if entry is None or entry.auth == AUTH_UNAUTHORIZED:
            return None
        return entry

    # ---- the core thread -----------------------------------------------------

    def set_io(self, io: CoreIO) -> None:
        """Replace the calls the core makes out of itself."""
        self._io = io

    def set_eq_veto(self, veto: Callable[[], bool]) -> None:
        """Say when the EQ page must not be offered whatever the appliance
        advertises (the view's layout has no room for it). Read on the core
        thread, so it must be a plain, lock-free read."""
        self._eq_veto = veto

    def set_idle_hold(self, hold: Callable[[bool], bool]) -> None:
        """Say when a fold that finds nothing playing must leave what is
        reported as it is: the view has a screen up that it will not redraw
        under (a list open, the panel asleep or about to sleep), and what it
        shows then stays what it was until the screen is done. *hold* is
        told whether this fold has cleared the manual focus (which closes
        the screens bound to it). Read on the core thread, so it must be a
        plain, lock-free read."""
        self._idle_hold = hold

    def request_fold(self) -> None:
        """Ask the core thread to fold the clients now instead of at the next
        interval. Lock-free: any thread may call it."""
        self._wake.set()

    def _queue_effects(self, effects):
        """Queue *effects* for a view and publish, so the view is woken to
        take them. A queue nobody drains (no view is attached) keeps the
        newest `EFFECTS_BACKLOG_MAX`. Returns *effects*."""
        def mutate(state: CoreState) -> None:
            self._effects.append(effects)
            del self._effects[:-EFFECTS_BACKLOG_MAX]
        self._publish(mutate)
        return effects

    def take_effects(self) -> list:
        """The effects queued since the last call, oldest first: what the
        warning sources and request replies did that a view turns into
        screens. Single consumer (the view): the queue is emptied, so a
        second caller would take effects the view never sees."""
        with self._lock:
            effects, self._effects = self._effects, []
        return effects

    def start(self) -> None:
        """Start the `dial-core` thread. A second call while it runs does
        nothing."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        if self._lane is not None:
            self._lane.start()
        try:
            self._thread = threading.Thread(target=self._run, daemon=True, name="dial-core")
            self._thread.start()
        except Exception as e:
            # Must never stop the rest of the start-up sequence.
            logging.warning("dial core: failed to start the core thread: %s", e)
            self._thread = None

    def stop(self) -> None:
        """Stop the `dial-core` thread, waiting up to two seconds for it."""
        self._stop.set()
        self._wake.set()
        if self._lane is not None:
            try:
                self._lane.stop()
            except RuntimeError:
                pass    # its thread had not finished starting; it ends on the stop item
        thread = self._thread
        if thread is not None:
            try:
                thread.join(timeout=2)
            except RuntimeError:
                # Thread.start() had not finished registering; the daemon
                # thread still exits on its own once the stop event is set.
                pass

    def _run(self) -> None:
        """The core thread: fold every interval (or when woken), and do the
        housekeeping on every wake, never waiting longer than a second. The
        interval runs from the end of a fold. A wake within `FOLD_MIN_GAP_S`
        of the last fold's end waits for the gap (cut short by a stop), and
        the changes that arrive meanwhile join the fold. The loop keeps its
        own time with a clock nothing replaces."""
        next_fold = 0.0
        last_fold_end = float("-inf")
        while not self._stop.is_set():
            now = time.perf_counter()
            woken = self._wake.is_set()
            if woken or now >= next_fold:
                earliest = last_fold_end + FOLD_MIN_GAP_S
                if woken and now < earliest and self._stop.wait(earliest - now):
                    break
                self._wake.clear()
                try:
                    self.fold_once()
                except Exception:
                    logging.debug("dial core: fold raised", exc_info=True)
                last_fold_end = time.perf_counter()
                next_fold = last_fold_end + FOLD_INTERVAL_S
            try:
                self._housekeeping(self._clock())
            except Exception:
                logging.debug("dial core: housekeeping raised", exc_info=True)
            remaining = next_fold - time.perf_counter()
            self._wake.wait(clamp(remaining, 0.0, HOUSEKEEPING_INTERVAL_S))

    def _housekeeping(self, now: float) -> None:
        """The once-a-second work: the update watch, expiring warnings, the
        start failure notice's hold and the replay
        position. What it did to the warnings is queued for a view and the
        subscribers are told."""
        effects = self.tick_housekeeping(now)
        self._expire_start_failure(now)
        self._fetch_replay_positions(now)
        self._refresh_protocol_warnings()
        self._refresh_dial_info(now)
        if effects.changes or effects.restarting or effects.signal:
            self._queue_effects(effects)

    def _refresh_protocol_warnings(self) -> None:
        """Raise "Update <appliance>" for each rostered appliance whose
        protocol number is lower than this dial's, and the dial's own
        "Update this dial" while any is higher; end each that now agrees or
        has left the roster. One log line per change."""
        lines: list = []

        def mutate(state: CoreState) -> "bool | None":
            wanted = {}
            for r in state.roster:
                warning = protocol_warning(r, PROTOCOL)
                if warning is not None:
                    wanted[r.appliance_id] = warning
            held = state.protocol_warnings
            if wanted != held:
                for appliance_id, warning in held.items():
                    if wanted.get(appliance_id) != warning:
                        self.warnings.unregister(appliance_warning_key(appliance_id, warning.id))
                        if appliance_id not in wanted:
                            lines.append(f"{warning.appliance_name} no longer needs an update")
                for appliance_id, warning in wanted.items():
                    if held.get(appliance_id) != warning:
                        key = appliance_warning_key(appliance_id, warning.id)
                        self.warnings.register(appliance_warning_descriptor(appliance_id, warning))
                        self.warnings.set_active(key, warning.severity)
                        if appliance_id not in held:
                            lines.append(f"{warning.appliance_name} speaks a different dial protocol")
                state.protocol_warnings = wanted
                state.appliances = self._derive_appliances_locked(state)
            names = newer_appliance_names(state.roster, PROTOCOL)
            if names and self.warnings.reading(DIAL_WARNING_ID) != names:
                if not self.warnings.is_active(DIAL_WARNING_ID):
                    lines.append(f"{', '.join(names)} speaks a newer dial protocol")
                self.warnings.set_active(DIAL_WARNING_ID, names)
            elif not names and self.warnings.is_active(DIAL_WARNING_ID):
                self.warnings.clear(DIAL_WARNING_ID)
                lines.append("this dial no longer needs an update")
            changed = self._sync_warnings_locked(state)
            if wanted == held and not changed:
                return False
        self._publish(mutate)
        for line in lines:
            logging.info("dial core: %s", line)

    def _fold_start_failures_locked(self, state: CoreState, failures: dict, effects: list, lines: list) -> None:
        """Decide each appliance's start failure read this fold (see
        `start_failure_action`) and record what it means: remembered, a
        notice raised, or the dial's accepted output request reopened as one
        that asks for a PIN. Effects and log lines are collected for the
        caller to queue once the lock is released."""
        now = self._clock()
        for appliance_id, report in failures.items():
            action = start_failure_action(
                report, state.start_failure_seen.get(appliance_id),
                appliance_id=appliance_id, request=state.outputs_request,
            )
            if action == FAILURE_SEEN or action == FAILURE_DEFER:
                continue
            state.start_failure_seen[appliance_id] = (report.boot, report.seq)
            name = self._appliance_label(state, appliance_id)
            if action == FAILURE_NOTICE:
                key = f"{appliance_id}:{report.boot}:{report.seq}"
                state.start_failure = StartFailureNotice(
                    appliance_id, key, report.unit_id, report.name, report.reason, now,
                )
                effects.append(StartFailureEffect(appliance_id, key, report.name, report.reason))
                lines.append(f"{name} could not start {report.name} ({report.reason})")
            elif action == FAILURE_PIN:
                request = state.outputs_request
                state.outputs_request = reopen_for_pin(request, now)
                effects.append(OutputsEffect(
                    appliance_id, request.output_id or "", "output_set", "rejected",
                    "pin_required", request.requested_at, True,
                ))
                lines.append(f"{name} could not start {report.name} ({report.reason})")

    @staticmethod
    def _appliance_label(state: CoreState, appliance_id: str) -> str:
        """The roster's display name for *appliance_id*, else the id."""
        for r in state.roster:
            if getattr(r, "appliance_id", "") == appliance_id:
                return getattr(r, "name", "") or appliance_id
        return appliance_id

    def dismiss_start_failure(self, key: str) -> ActionResult:
        """Answer the raised notice whose key is *key*: it leaves the snapshot for
        every view. Accepted whether or not it was still raised (a second view, or
        one racing the hold, answers a notice already gone)."""
        def mutate(state: CoreState) -> "bool | None":
            held = state.start_failure
            if held is None or held.key != key:
                return False
            state.start_failure = None
        self._publish(mutate)
        return ActionResult(True)

    def _expire_start_failure(self, now: float) -> None:
        """Drop a notice raised START_FAILURE_HOLD_S or more ago (housekeeping)."""
        held = self._state.start_failure
        if held is None or now - held.raised_at < START_FAILURE_HOLD_S:
            return
        def mutate(state: CoreState) -> "bool | None":
            current = state.start_failure
            if current is None or current.key != held.key:
                return False
            state.start_failure = None
        self._publish(mutate)

    # ---- the pool ------------------------------------------------------------

    def attach_pool(self, pool, registry) -> None:
        """Read every appliance from *pool* (one PeerClient each) and
        *registry* (where each was sighted), and send the controls' requests
        through the pool's clients. The core thread folds the clients'
        snapshots when the pool signals a change, and at the fold interval so
        a decision bound to time moves on: one publish per wake, however many
        clients moved. Call once, before start()."""
        self.pool = pool
        self._registry = registry
        self._lane = rq.RequestLane(pool.get, self._on_lane_done)
        pool.subscribe(self._wake.set)
        if self._thread is not None:
            self._lane.start()

        def mutate(state: CoreState) -> None:
            state.polling = True
        self._publish(mutate)
        self._wake.set()

    def peer_snapshot(self, appliance_id: str):
        """The PeerSnapshot of *appliance_id* as the core last folded it, or
        None. A reference read, no lock."""
        return self._state.peers.get(appliance_id)

    # -- sending --

    def _send(self, appliance_id: str, intent: rq.Intent, token: float) -> None:
        """Queue *intent* for *appliance_id* on the request lane."""
        self._lane.enqueue(rq.LaneItem(
            appliance_id, intent.kind, intent.name, intent.args, intent.extra_body, token,
        ))

    def _on_lane_done(self, item: rq.LaneItem, result) -> None:
        """The request lane's result: a reply is folded into its request; a
        fetch needs nothing, since the merged parts reach the fold through the
        client's own signal."""
        if item.kind != "fetch":
            self._fold_reply(item.appliance_id, item.kind, item.token, result)

    def _fold_reply(self, appliance_id: str, kind: str, token: float, reply) -> None:
        """Fold an appliance's reply into the request carrying *token*. An ok
        reply makes it accepted and keeps its shown value until the
        appliance's folded state has caught up with the reply
        (dial_core_requests.settled); a refusal or a transport outcome makes it
        rejected with that name. What it meant is queued for a view as an
        `OutputsEffect` or a `RepeatEffect`. An accepted replay start opens the
        accepted-replay window, and an accepted seek or stop asks once for the
        replay position; a refused replay request drops a pending focus on
        that appliance. An EQ reply has no request record: the values set show
        for their window whatever it says."""
        if kind in OUTPUT_KINDS:
            lane = "outputs_request"
        elif kind in ("seek", "stop", "arm"):
            lane = "transport"
        else:
            if not reply.ok:
                logging.info("dial core: %s refused (%s)", kind, reply.error)
            return
        now = self._clock()
        resolved = []

        def mutate(state: CoreState) -> "bool | None":
            held = getattr(state, lane)
            if held is None or held.requested_at != token or held.state != "pending":
                return False
            new = rq.fold_reply(held, reply, now)
            self._waiting.pop(lane, None)
            if new.state == "accepted" and new.shown is not None:
                folded = state.peers.get(appliance_id)
                waiting = rq.wait_for(new, reply, folded)
                if waiting is None or rq.settled(waiting, folded):
                    new = dataclasses.replace(new, shown=None)
                else:
                    self._waiting[lane] = waiting
            setattr(state, lane, new)
            resolved.append((held, new))
        self._publish(mutate)

        if lane == "outputs_request":
            if resolved:
                held, new = resolved[0]
                self._queue_effects(OutputsEffect(
                    appliance_id, held.output_id or "", held.kind, new.state, new.error, token,
                ))
            return
        if reply.ok:
            accepted = kind == "seek" and self.accept_replay(appliance_id, now + ACCEPTED_REPLAY_GRACE_S)
            if kind in ("seek", "stop") and self._lane is not None:
                self._lane.enqueue(rq.LaneItem(appliance_id, "fetch", parts=("repeat",)))
            outcome = RepeatOutcome(True, accepted, bool(resolved) and resolved[0][0].kind == "stop")
        else:
            self.drop_pending_focus(appliance_id)
            outcome = RepeatOutcome(False, False, False)
        self._queue_effects(RepeatEffect(appliance_id, outcome, token))

    def submit_intent(self, appliance_id: str, name: str, args, *, pin_entry: bool = False) -> PeerReply:
        """Send the HD page's intent *name* with *args* to *appliance_id* on
        the calling thread, never behind the request lane, and return the
        reply. The local checks the controls make come first, and the request
        is recorded (on `outputs_request` for a speaker or PIN intent, on
        `transport` for a repeat one) under the core lock before anything is
        sent, so the screens see it as they see their own. A local refusal is
        a reply with the dial's name for it: unknown_intent, unknown_appliance,
        wrong_state (not the focused appliance, a speaker row that is not held
        or is in use, a PIN of the wrong shape), no_record, or the
        appliance's or library's name where one says the same
        (dial_not_authorized, protocol_mismatch). *pin_entry* says the caller
        can show a keypad; a PIN submission always says so. Bounded by the
        client's own read."""
        if name not in SUBMIT_INTENTS:
            return _local_refusal("unknown_intent")
        args = dict(args) if isinstance(args, dict) else {}
        now = self._clock()
        begun: dict = {}

        def mutate(state: CoreState) -> "bool | None":
            refusal = self._intent_refusal_locked(state, appliance_id, name, args)
            if refusal is not None:
                begun["refusal"] = refusal
                return False
            record = self._intent_record_locked(state, appliance_id, name, args)
            if record is None:
                return False
            lane, kind, output_id, shown = record
            setattr(state, lane, TransportRequest(
                appliance_id, kind, now, "pending", now, None, output_id, 0, shown,
            ))
            begun["kind"] = kind
        self._publish(mutate)
        if "refusal" in begun:
            return _local_refusal(begun["refusal"])
        client = self.pool.get(appliance_id) if self.pool is not None else None
        if client is None:
            reply = PeerReply(False, "unreachable", None, None, {}, None)
        else:
            pin_capable = pin_entry or name == "output.pin.submit"
            reply = client.submit(name, args, extra_body={"pin_capable": True} if pin_capable else None)
        if "kind" in begun:
            self._fold_reply(appliance_id, begun["kind"], now, reply)
        return reply

    def _intent_refusal_locked(self, state: CoreState, appliance_id: str, name: str, args: dict) -> str | None:
        """The name submit_intent refuses *name* with, or None. Core lock held."""
        refusal = self._refusal_in(state, appliance_id, _INTENT_CAPABILITY[name])
        if refusal is not None:
            return _REFUSAL_NAMES.get(refusal.reason, refusal.reason)
        if appliance_id != (state.focus.manual_id or state.focus.reporting_id):
            return "wrong_state"
        if name in _INTENT_REPEAT_STATES:
            refusal = self._repeat_refusal_in(state, appliance_id, _INTENT_REPEAT_STATES[name])
            return None if refusal is None else _REFUSAL_NAMES.get(refusal.reason, refusal.reason)
        if name in ("outputs.set", "output.pin.submit"):
            row = self._output_row_in(state, appliance_id, args.get("id"))
            if row is None or row.remote_in_use:
                return "wrong_state"
            pin = args.get("pin")
            if name == "output.pin.submit" and not (isinstance(pin, str) and PIN_RE.match(pin)):
                return "wrong_state"
        return None

    def _intent_record_locked(self, state: CoreState, appliance_id: str, name: str, args: dict):
        """(lane, kind, output_id, shown) recording intent *name*, or None for
        an intent with no request record. Core lock held; the checks have
        passed."""
        if name in _INTENT_KINDS:
            return "transport", _INTENT_KINDS[name], None, None
        if name not in ("outputs.set", "output.pin.submit"):
            return None
        row = self._output_row_in(state, appliance_id, args.get("id"))
        if name == "output.pin.submit":
            return "outputs_request", "output_pin", row.id, (True, row.volume)
        selected, volume = args.get("selected"), args.get("volume")
        shown = (
            selected if isinstance(selected, bool) else row.selected,
            volume if is_int(volume) else row.volume,
        )
        return "outputs_request", "output_set", row.id, shown

    @staticmethod
    def _output_row_in(state: CoreState, appliance_id: str, output_id):
        held = state.outputs
        if held is None or held.appliance_id != appliance_id:
            return None
        return next((r for r in held.rows if r.id == output_id), None)

    # -- the fold --

    def fold_once(self) -> CoreSnapshot:
        """Fold every client's snapshot into one publish: the appliance list,
        the focus (dial_core_focus.choose_focus), now playing, the focused
        appliance's outputs and EQ, each appliance's warnings and start
        failure, and the requests its state has overtaken. The publish ends a
        tick. Core thread only (or a test without it)."""
        now = self._clock()
        sightings = dict(self._registry.sightings()) if self._registry is not None else {}
        clients = self.pool.clients() if self.pool is not None else {}
        snaps = {}
        for appliance_id in sightings:
            client = clients.get(appliance_id)
            if client is not None:
                snaps[appliance_id] = client.snapshot()
        order = [e.id for e in roster_view(sightings, snaps)]
        held_views, held_peers, held_since = self._state.views, self._state.peers, self._state.playing_since
        playing_since: dict = {}
        views: dict = {}
        promotions = 0
        for appliance_id in order:
            snap = snaps.get(appliance_id)
            if snap is not None and dial_peer_view.playing(snap.parts):
                playing_since[appliance_id] = held_since.get(appliance_id, now)
            before = held_views.get(appliance_id)
            view = before
            if (view is None or held_peers.get(appliance_id) is not snap
                    or self._sightings.get(appliance_id) != sightings[appliance_id]):
                view = dial_peer_view.appliance_state(
                    sightings[appliance_id], snap, now=now,
                    playing_since=playing_since.get(appliance_id, 0.0),
                )
            if before is not None and before.auth != AUTH_AUTHORIZED and view.auth == AUTH_AUTHORIZED:
                promotions += 1
            views[appliance_id] = view
        self._sightings = sightings
        roster = [views[appliance_id] for appliance_id in order]
        tracks = {appliance_id: dial_peer_view.active_track(s.parts) for appliance_id, s in snaps.items()}
        failures = self._read_start_failures(snaps)
        prev_playing = self._prev_playing_ids

        def decide(focus: FocusState):
            choice = dial_core_focus.choose_focus(
                roster, focus, now, tracks=tracks, prev_playing_ids=prev_playing)
            hold = not choice.visible and self._idle_hold(choice.clear_reason is not None)
            return choice, hold, (None if hold else _now_playing_for(choice, views, snaps))

        focus_read = self._state.focus
        choice, hold, now_playing = decide(focus_read)
        self._observe(choice, snaps, now)
        shown = self._state.now_playing if hold else now_playing
        service = shown.service_name if shown is not None else None
        readout = (service, shown_volume(service))
        effects: list = []
        lines: list = []

        def mutate(state: CoreState) -> None:
            nonlocal choice, hold, now_playing
            if state.focus is not focus_read:
                # A tap moved the focus since it was read: decide again from it.
                choice, hold, now_playing = decide(state.focus)
            tick = TickContext(
                state.focus.reporting_id, state.now_playing, state.idle_affordance,
                choice.clear_reason is not None, choice.idle_focus is not None,
            )
            state.polling = True
            state.peers = snaps
            state.views = views
            state.playing_since = playing_since
            state.roster = roster
            state.auth_promotions += promotions
            self._fold_part_warnings_locked(state, lines)
            self._fold_start_failures_locked(state, failures, effects, lines)
            if hold:
                # The view keeps what is shown until its screen is done.
                state.focus = dataclasses.replace(
                    state.focus, manual_id=choice.manual_id, pending=choice.pending,
                    accepted_replay=choice.accepted_replay, source_service_name=None,
                )
            else:
                state.now_playing = now_playing
                state.focus = dataclasses.replace(
                    choice.apply(state.focus),
                    idle_focus=now_playing is not None and not now_playing.playing,
                )
            self._fold_focused_locked(state, now, availability=not hold)
            state.visible_playing = tuple(sorted(e.appliance_id for e in choice.visible))
            state.idle_affordance = any(
                e.auth == AUTH_AUTHORIZED and e.repeat_capable and e.repeat is not None
                and e.repeat.state == "hold" for e in roster
            )
            self._settle_locked(state)
            state.volume_readout = readout
            state.appliances = self._derive_appliances_locked(state)
            self._sync_warnings_locked(state)
            state.tick = tick
            state.ticks += 1
        snapshot = self._publish(mutate)

        self._prev_playing_ids = (
            {e.appliance_id for e in roster if e.playing} | {e.appliance_id for e in choice.visible})
        if choice.clear_reason is not None:
            logging.info("dial display: manual focus cleared (%s)", choice.clear_reason)
        for line in lines:
            logging.info("dial core: %s", line)
        for effect in effects:
            self._queue_effects(effect)
        if not hold:
            self._artwork.follow(choice.selection.url if choice.visible else None)
        return snapshot

    def _read_start_failures(self, snaps: dict) -> dict:
        """Each appliance's start failure as the report the core acts on. The
        part carries the failure's wall-clock time; on the first reading of an
        appliance's outputs (the dial has just started, or just met it) its
        age is worked out from that, so an old failure is not news, and after
        that a failure that appears is new."""
        failures = {}
        for appliance_id, snap in snaps.items():
            outputs = snap.parts.get("outputs")
            if not isinstance(outputs, Mapping):
                continue
            raw = outputs.get("start_failure")
            age = 0
            if appliance_id not in self._failures_read:
                self._failures_read.add(appliance_id)
                at = raw.get("at") if isinstance(raw, Mapping) else None
                if isinstance(at, (int, float)) and not isinstance(at, bool):
                    age = max(0, int(time.time() - at))
            failures[appliance_id] = dial_peer_view.start_failure(
                raw, snap.boot or "", self._own_requester, age_s=age)
        return failures

    def _fold_part_warnings_locked(self, state: CoreState, lines: list) -> None:
        """Hold each appliance's warnings as its warnings part lists them; an
        appliance that has refused this dial, or has gone, holds none."""
        for appliance_id, view in state.views.items():
            new = view.warnings if view.auth != AUTH_UNAUTHORIZED else ()
            if self._store_appliance_warnings_locked(state, appliance_id, new):
                lines.append(f"appliance warnings: {view.name} {len(new)} warning(s)")
        for appliance_id in [a for a in state.appliance_warnings if a not in state.views]:
            self._store_appliance_warnings_locked(state, appliance_id, ())

    def _fold_focused_locked(self, state: CoreState, now: float, *, availability: bool) -> None:
        """The focused (or reporting) appliance's snapshot, outputs and EQ, as
        folded now, and (with *availability*) what it offers: the EQ page
        (unless the view vetoes it), the page dots and the outputs list. An EQ
        tap whose window has passed goes."""
        focused = state.focus.manual_id or state.focus.reporting_id
        snap = state.peers.get(focused) if focused else None
        state.focused_peer = snap
        if snap is None:
            state.outputs = state.eq = None
        else:
            outputs = dial_peer_view.outputs_state(focused, snap.parts, fetched_at=now)
            held = state.outputs
            if (held is not None and held.appliance_id == focused
                    and (held.rows, held.loaded) == (outputs.rows, outputs.loaded)):
                outputs = held
            state.outputs = outputs
            state.eq = dial_peer_view.eq_state(focused, snap.parts)
        pairs, expires_at = state.eq_optimistic
        if (pairs or expires_at) and expires_at <= now:
            state.eq_optimistic = ((), 0.0)
        if not availability:
            return
        entry = state.views.get(focused) if focused else None
        usable = entry is not None and entry.auth != AUTH_UNAUTHORIZED
        state.eq_available = bool(usable and entry.dial_eq and not self._eq_veto())
        state.outputs_available = bool(usable and entry.dial_outputs)
        state.dots_active = dots_active(entry.repeat if entry is not None else None, state.eq_available)

    def _settle_locked(self, state: CoreState) -> None:
        """Drop the shown value of each accepted request that the appliance's
        folded state has overtaken (or that a newer request has replaced)."""
        for lane, waiting in list(self._waiting.items()):
            request = getattr(state, lane)
            if request is None or request.requested_at != waiting.token or request.shown is None:
                del self._waiting[lane]
            elif rq.settled(waiting, state.peers.get(waiting.appliance_id)):
                setattr(state, lane, dataclasses.replace(request, shown=None))
                del self._waiting[lane]

    def _observe(self, choice, snaps: dict, now: float) -> None:
        """Tell the volume worker's store what the shown appliances report:
        each one's mute flag, and the reporting appliance's master volume
        when that moves (or the reporting appliance changes). With nothing
        playing the store is cleared. Never with the core lock held."""
        io = self._io
        if not choice.visible:
            self._volume_seen = None
            io.observe_volume(None, None)
            io.observe_mute(None, None)
            return
        reporting = choice.reporting
        shown = list(choice.visible)
        if reporting is not None and all(e.appliance_id != reporting.appliance_id for e in shown):
            shown.append(reporting)
        if reporting is not None:
            # The reporting appliance last, so its flag is the one kept.
            shown.sort(key=lambda e: e.appliance_id == reporting.appliance_id)
        for entry in shown:
            snap = snaps.get(entry.appliance_id)
            heard = snap.heard_at if snap is not None and snap.heard_at > 0 else now
            io.observe_mute(entry.service_name, entry.muted, requested_at=heard, status_reports_mute=True)
        io.forget_mute({e.service_name for e in choice.visible})
        if reporting is not None:
            volume = reporting.master_volume
            volume = volume if is_int(volume) else None
            seen = (reporting.service_name, volume)
            if seen != self._volume_seen:
                rekeyed = self._volume_seen is None or self._volume_seen[0] != reporting.service_name
                self._volume_seen = seen
                (io.observe_volume if rekeyed else io.observe_volume_tracked)(*seen)

    # -- replay position --

    def _fetch_replay_positions(self, now: float) -> None:
        """The housekeeping step: every REPEAT_FETCH_S while an appliance's
        repeat record is replaying, ask for its repeat part on the request
        lane, so the position moves on whatever screen is shown, or none."""
        if self._lane is None:
            return
        replaying = {
            a.appliance_id for a in self._snapshot.appliances
            if a.repeat is not None and a.repeat.state == "replaying"
        }
        for appliance_id in [a for a in self._repeat_fetch_at if a not in replaying]:
            del self._repeat_fetch_at[appliance_id]
        for appliance_id in replaying:
            since = self._repeat_fetch_at.setdefault(appliance_id, now)
            if now - since >= REPEAT_FETCH_S:
                self._repeat_fetch_at[appliance_id] = now
                self._lane.enqueue(rq.LaneItem(appliance_id, "fetch", parts=("repeat",)))


def _local_refusal(error: str) -> PeerReply:
    """A refusal made on the dial, in the shape of an appliance's reply."""
    return PeerReply(False, error, None, None, {}, None)


def _now_playing_for(choice, views: dict, snaps: dict) -> NowPlaying | None:
    """What the focus decided is shown: the reporting appliance and the
    selected track (an idle focus shows its name, not playing); with nothing
    playing, an idle focus or a pending focus by name; else nothing."""
    if choice.visible:
        reporting = choice.reporting
        if reporting is None:
            return None
        selection = choice.selection
        view = views.get(reporting.appliance_id)
        snap = snaps.get(reporting.appliance_id)
        return NowPlaying(
            reporting.service_name, selection.artist, selection.title,
            view.master_volume if view is not None else None, album=selection.album,
            input_label=dial_peer_view.now_playing(snap.parts).input_label if snap is not None else "",
            playing=choice.idle_focus is None,
        )
    if choice.idle_focus is not None:
        idle = choice.idle_focus
        return NowPlaying(idle.service_name, "", "", idle.master_volume, playing=False)
    if choice.pending is not None:
        return NowPlaying(choice.pending[1], "", "", None, playing=False)
    return None


def create_dial_core(cfg) -> DialCore:
    """Build the core for dial_main.py wiring."""
    return DialCore(cfg.uuid)
