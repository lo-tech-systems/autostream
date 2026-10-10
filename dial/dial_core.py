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

The core also runs the poll. `start()` runs one thread, `dial-core`: it
polls the appliances every poll interval (or sooner when asked), and once a
second does the housekeeping (the update watch, expiring warnings, the
snooze write, the refresh of watched outputs and EQ). The poll's writes are
published as they are made; the snapshot that ends a tick carries a new
`ticks` count and a `TickContext` saying what the tick started from, which
is how a view tells a finished tick from the writes in between. A view
reacts to the finished tick, never to a half-written one. What housekeeping
does to the warning screens is queued for the view as `SourceEffects`
(`take_effects`).

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
    ACCEPTED_REPLAY_GRACE_S, APPLIANCE_WARNING_ID_RE, APPLIANCE_WARNINGS_MAX, EQ_LIMIT_DB,
    EQ_OPTIMISTIC_WINDOW_S, NOWIFI_PROMPT_STREAK, OUTPUTS_REFRESH_S,
    ActionResult, ApplianceWarning, Artwork, CoreSnapshot, DialInfo, EqState, FocusState,
    NowPlaying, OutputsState, TickContext, TransportRequest, WarningState, _roster_entry,
    appliance_states, artwork_key, attribute_appliance_warnings, choose_pin, dots_active,
    eq_available, eq_gain, idle_affordance, outputs_available, reporting_for, resolve_focus,
    started_refused, visible_targets, walk_order, with_accepted_replay,
)
from dial_eq import _EqTarget
from dial_eq import enqueue_fetch as _enqueue_eq_fetch
from dial_eq import enqueue_set as _enqueue_eq_set
from dial_mdns import get_roster as _default_get_roster
from dial_network import LINK_CONNECTED, LINK_DOWN, LINK_IGNORED
from dial_target_status import enrich_targets, fetch_target_status
from dial_network import request_reboot as _default_reboot
from dial_outputs import _OutputsTarget, enqueue_fetch, enqueue_set
from dial_repeat_store import repeat_store
from dial_sdhealth import is_low as _sd_is_low
from dial_update_watch import (
    PHASE_REBOOT, PHASE_VERIFY, STATUS_FAILURE, STATUS_IN_PROGRESS, STATUS_SUCCESS,
    UPDATE_SEEN_PATH, UpdateWatcher, read_seen_marker, write_seen_marker,
)
from dial_volume import forget_mute_states_except, observe_master_volume, observe_mute_state
from dial_warning_text import WARNING_DESCRIPTORS, appliance_warning_descriptor, appliance_warning_key
from dial_warnings import ACTION_DISMISS, WarningManager, WarningStore

_UNSET = object()

# The poll interval until a view or the wiring sets one, and the slowest
# the pending-focus and accepted-replay windows assume.
DEFAULT_POLL_INTERVAL_S = 6
# How often the whole roster is re-confirmed (or sooner when forced).
RECONCILE_INTERVAL_S = 60
# The housekeeping tick, and so the longest the core thread sleeps.
HOUSEKEEPING_INTERVAL_S = 1.0

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
    visible_playing: tuple      # ids of the playing appliances this dial may use, as of the last poll
    ticks: int                  # poll ticks completed
    tick: "TickContext | None"  # what the last completed tick started from
    auth_promotions: int        # appliances a pushed auth change confirmed as newly authorised
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
    wifi_down_streak: int               # consecutive down link readings; reset by a connected or ignored one
    sd_low: bool                        # the SD health incident latch (with hysteresis)
    appliance_warnings: dict            # appliance id -> its validated, attributed warnings


# Held in the state for the core's own use, never published as such.
_PRIVATE_FIELDS = (
    "roster", "repeats", "outputs_optimistic", "eq_optimistic",
    "outputs_refresh_at", "outputs_watch", "eq_watch",
    "wifi_down_streak", "sd_low", "appliance_warnings",
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


@dataclass(frozen=True)
class WarningChange:
    """What a source did to one warning, for a caller that turns warnings
    into screens: reported present (`active`, and `began` when that started
    a new incident rather than refreshing one) or cleared."""
    warning_id: str
    active: bool
    began: bool = False


@dataclass(frozen=True)
class SourceEffects:
    """The outcome of folding a source's reading: the warning changes in the
    order they were made, whether the update run reached its reboot phase
    (the caller shows its restarting screen), and whether the caller should
    repaint."""
    changes: tuple = ()
    restarting: bool = False
    signal: bool = True


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
        visible_playing=(),
        ticks=0,
        tick=None,
        auth_promotions=0,
        roster=[],
        repeats={},
        outputs_optimistic=None,
        eq_optimistic=((), 0.0),
        outputs_refresh_at=0.0,
        outputs_watch={},
        eq_watch={},
        wifi_down_streak=0,
        sd_low=False,
        appliance_warnings={},
    )


@dataclass
class PollIO:
    """The calls the poll makes out of the core. Each defaults to the real
    one, looked up when it is called; a view or a test supplies stand-ins
    that do the same, so replacing a module attribute still takes effect."""
    fetch_status: Callable = lambda *a, **k: fetch_target_status(*a, **k)
    enrich: Callable = lambda *a, **k: enrich_targets(*a, **k)
    fetch_artwork: Callable = lambda url, timeout: dial_core_poll.default_fetch_artwork(url, timeout)
    artwork_eligible: Callable = lambda url: dial_core_poll.default_artwork_eligible(url)
    observe_mute: Callable = lambda *a, **k: observe_mute_state(*a, **k)
    observe_volume: Callable = lambda *a, **k: observe_master_volume(*a, **k)
    forget_mute: Callable = lambda *a, **k: forget_mute_states_except(*a, **k)
    on_artwork_error: Callable[[str], None] | None = None
    log_limiter: object = dataclasses.field(default_factory=dial_core_poll.RateLimitedLogger)


class DialCore:
    def __init__(
        self,
        dial_id: str,
        get_display_targets: Callable,
        get_roster: Callable = _default_get_roster,
        *,
        clock: Callable[[], float] | None = None,
        warnings: WarningManager | None = None,
        update_watcher: UpdateWatcher | None = None,
        update_seen_path: str = UPDATE_SEEN_PATH,
        reboot: Callable[[], bool] | None = None,
        io: PollIO | None = None,
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
        # The warning manager owns which warnings are active, snoozed or due
        # and persists the snoozes; it has its own leaf lock and is never
        # called while it could call back. The update watcher and the seen
        # marker belong to the update source, driven from one thread.
        self.warnings = warnings if warnings is not None else WarningManager(
            WARNING_DESCRIPTORS, WarningStore(),
        )
        self.update_watcher = update_watcher if update_watcher is not None else UpdateWatcher()
        self.update_seen_path = update_seen_path
        self._update_seen: str | None = None
        self._reboot = reboot if reboot is not None else _default_reboot
        # The poll. Its bookkeeping belongs to the thread running a tick;
        # the flags other threads set (`_poll_wake`, `_reconcile_due`) are
        # plain, lock-free writes.
        self._io = io if io is not None else PollIO()
        self._eq_veto: Callable[[], bool] = lambda: False
        self._idle_hold: Callable[[bool], bool] = lambda focus_cleared: False
        self._polling = False
        self._poll_interval = DEFAULT_POLL_INTERVAL_S
        self._poll_wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._push_lock = threading.Lock()
        self._push_pending: set[str] = set()
        self._last_reconcile_at = 0.0
        self._reconcile_due = True          # the first tick reconciles
        self._prev_playing_ids: set[str] = set()
        self._focus_cleared = False
        self._idle_focus_found = False
        self._effects: list = []
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
        visible_playing: "tuple | object" = _UNSET,
        tick: "TickContext | None | object" = _UNSET,
    ) -> CoreSnapshot:
        """Publish the end of one poll tick. Fields passed are stored as
        given; fields left out keep the value the writers (the poll's own
        steps and the touch and worker callbacks) have already stored, so a
        concurrent write is never overwritten by a stale copy. When *focus*
        is left out the idle-focus flag is recomputed from the stored
        now-playing. *repeats* (appliance id to repeat record) refreshes
        the per-appliance repeat state. A *tick* ends a poll tick: the
        snapshot carries it and a tick count one higher, which is what tells
        a view the tick is over."""
        def mutate(state: _CoreState) -> None:
            state.polling = polling
            if visible_playing is not _UNSET:
                state.visible_playing = visible_playing
            if tick is not _UNSET:
                state.tick = tick
                state.ticks += 1
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
                state.appliances = self._derive_appliances_locked(state)
        return self._publish(mutate)

    # ---- field writes ------------------------------------------------------

    def roster(self) -> list:
        """The merged roster as last stored: a reference read, no lock. The
        list is shared and must not be edited."""
        return self._state.roster

    def set_roster(self, roster: list) -> CoreSnapshot:
        """Store the merged roster and re-derive the appliance list. A
        roster equal to the one held publishes nothing."""
        def mutate(state: _CoreState) -> "bool | None":
            if roster == state.roster:
                return False
            state.roster = roster
            state.appliances = self._derive_appliances_locked(state)
        return self._publish(mutate)

    def set_field(self, name: str, value) -> CoreSnapshot:
        """Store one value and publish: a focus field (`manual_id`,
        `bound_id`, `pending`, `reporting_id`, `source_service_name`,
        `accepted_replay`), `roster`, or one of the plain fields
        (`now_playing`, `idle_affordance`, `dots_active`,
        `outputs_available`, `eq_available`). Nothing is published when the
        stored value is already that object or equal to it. The read-modify-write of a
        focus field happens under the lock, so writers of different focus
        fields never lose each other's update."""
        if name == "roster":
            return self.set_roster(value)
        if name in _FOCUS_FIELDS:
            def mutate(state: _CoreState) -> "bool | None":
                held = getattr(state.focus, name)
                if held is value or held == value:
                    return False
                state.focus = dataclasses.replace(state.focus, **{name: value})
        elif name in _PLAIN_FIELDS:
            def mutate(state: _CoreState) -> "bool | None":
                held = getattr(state, name)
                if held is value or held == value:
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
        held = self._state.artwork
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
        return self._state.focus.manual_id

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
        focus = self._state.focus
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

    # ---- warnings, update watch and sources ----------------------------------

    def _derive_appliances_locked(self, state: _CoreState) -> tuple:
        """The appliance list for the roster and repeat records held. An
        appliance that has left the roster loses its warnings (their
        incidents end with it)."""
        known = {getattr(r, "appliance_id", "") for r in state.roster}
        stale = [aid for aid in state.appliance_warnings if aid not in known]
        if stale:
            held = dict(state.appliance_warnings)
            for appliance_id in stale:
                for warning in held.pop(appliance_id):
                    self.warnings.unregister(appliance_warning_key(appliance_id, warning.id))
            state.appliance_warnings = held
            self._sync_warnings_locked(state)
        return appliance_states(state.roster, state.repeats, state.appliance_warnings)

    def _sync_warnings_locked(self, state: _CoreState) -> bool:
        """Copy the warning manager's runtime state and due warning into
        *state*. True when either changed."""
        warnings = tuple(
            WarningState(wid, active, severity, active_since, snoozed_until)
            for wid, active, severity, active_since, snoozed_until in self.warnings.runtime()
        )
        due = self.warnings.due()
        due_id = due.id if due is not None else None
        changed = warnings != state.warnings or due_id != state.due_warning_id
        state.warnings = warnings
        state.due_warning_id = due_id
        return changed

    def warning_active(self, warning_id: str, severity=None) -> WarningChange:
        """A source reports its condition present (again); a repeat only
        refreshes the severity. The change says whether this began a new
        incident."""
        began = []

        def mutate(state: _CoreState) -> "bool | None":
            began.append(self.warnings.set_active(warning_id, severity))
            return None if self._sync_warnings_locked(state) else False
        self._publish(mutate)
        return WarningChange(warning_id, True, bool(began and began[0]))

    def warning_cleared(self, warning_id: str) -> WarningChange:
        """A source reports its condition gone: the incident ends and any
        dismissal of it, in memory or on disk, is forgotten."""
        def mutate(state: _CoreState) -> "bool | None":
            self.warnings.clear(warning_id)
            return None if self._sync_warnings_locked(state) else False
        self._publish(mutate)
        return WarningChange(warning_id, False)

    def dismiss_warning(self, warning_id: str) -> ActionResult:
        """Apply the warning's dismiss policy (an incident-scoped or timed
        snooze, persisted or not). Refused with wrong_state for a warning
        that is not registered or has no Dismiss button, as a notice has
        none."""
        desc = self.warnings.descriptor(warning_id)
        if desc is None or not any(b.action == ACTION_DISMISS for b in desc.buttons):
            return ActionResult(False, "wrong_state")

        def mutate(state: _CoreState) -> "bool | None":
            self.warnings.dismiss(warning_id)
            return None if self._sync_warnings_locked(state) else False
        self._publish(mutate)
        return ActionResult(True)

    def request_dial_reboot(self) -> bool:
        """Ask for a reboot of the dial's own system (rate-gated where the
        request is made). True when a request went out."""
        try:
            return bool(self._reboot())
        except Exception:
            logging.debug("dial core: reboot request raised", exc_info=True)
            return False

    def flush_warnings(self) -> None:
        """Write any snooze changed since the last write. File I/O: call
        with no lock held."""
        self.warnings.flush()

    def wifi_down_streak(self) -> int:
        return self._state.wifi_down_streak

    def sd_low(self) -> bool:
        return self._state.sd_low

    def on_network_view(self, view) -> SourceEffects:
        """Fold a network reading. Connected: the streak resets, the
        ever-connected latch is set and the No-WiFi warning clears. Down:
        the streak grows, and at NOWIFI_PROMPT_STREAK the warning goes
        active unless the link has never been connected since the process
        started. Ignored (setup mode, reboot pending): the streak resets,
        the warning and the latch stay. Any other reading changes nothing
        but the held view."""
        changes = []

        def mutate(state: _CoreState) -> "bool | None":
            changed = state.network != view
            state.network = view
            if view.link == LINK_CONNECTED:
                changed = changed or not state.wifi_ever_connected
                state.wifi_ever_connected = True
                state.wifi_down_streak = 0
                self.warnings.clear("nowifi")
                changes.append(WarningChange("nowifi", False))
            elif view.link == LINK_DOWN:
                state.wifi_down_streak += 1
                if state.wifi_ever_connected and state.wifi_down_streak >= NOWIFI_PROMPT_STREAK:
                    began = self.warnings.set_active("nowifi")
                    changes.append(WarningChange("nowifi", True, began))
            elif view.link == LINK_IGNORED:
                state.wifi_down_streak = 0
            if self._sync_warnings_locked(state):
                changed = True
            return None if changed else False
        self._publish(mutate)
        return SourceEffects(tuple(changes))

    def on_sd_health_view(self, view) -> SourceEffects:
        """Fold an SD health reading: low (with hysteresis) starts or
        refreshes the warning with the percent as its severity; not low
        ends the incident."""
        changes = []

        def mutate(state: _CoreState) -> "bool | None":
            changed = state.sd_health != view
            state.sd_health = view
            low = _sd_is_low(view, state.sd_low)
            state.sd_low = low
            if low:
                began = self.warnings.set_active("sdhealth", view.percent)
                changes.append(WarningChange("sdhealth", True, began))
            else:
                self.warnings.clear("sdhealth")
                changes.append(WarningChange("sdhealth", False))
            if self._sync_warnings_locked(state):
                changed = True
            return None if changed else False
        self._publish(mutate)
        return SourceEffects(tuple(changes))

    def apply_update_view(self, view) -> SourceEffects:
        """Fold a software update reading. A run in progress raises the
        progress card, except in the reboot phase (the caller shows its
        restarting screen; the updater has already asked for the reboot)
        and the verify phase (nothing until the verdict). A finished run
        raises its result card once, recorded in the seen marker, which
        is file I/O, so call with no lock held."""
        def store(state: _CoreState) -> "bool | None":
            if state.update == view:
                return False
            state.update = view
        self._publish(store)
        changes = []
        restarting = False
        if view.status == STATUS_IN_PROGRESS:
            if view.phase == PHASE_REBOOT:
                changes.append(self.warning_cleared("update"))
                restarting = True
            elif view.phase != PHASE_VERIFY:
                changes.append(self.warning_active("update", view))
        elif view.status in (STATUS_SUCCESS, STATUS_FAILURE):
            marker = view.last_run_at or f"{view.status}-{view.tag}"
            if self._update_seen is None:
                self._update_seen = read_seen_marker(self.update_seen_path)
            if marker == self._update_seen:
                return SourceEffects(signal=False)
            self._update_seen = marker
            write_seen_marker(marker, self.update_seen_path)
            changes.append(self.warning_cleared("update"))
            changes.append(self.warning_active("update_result", view))
        return SourceEffects(tuple(changes), restarting)

    def tick_update_watch(self, now: float) -> SourceEffects | None:
        """Read the update result file when it has changed (a stat() while
        nothing is happening) and fold it; None when it has not changed."""
        view = self.update_watcher.tick(now)
        return None if view is None else self.apply_update_view(view)

    def expire_warnings(self) -> SourceEffects:
        """Clear the warnings that have been active for their
        auto_clear_after_s, as a source's clear would, and refresh the
        published due warning (a snooze may just have run out)."""
        changes = tuple(self.warning_cleared(wid) for wid in self.warnings.expired())

        def mutate(state: _CoreState) -> "bool | None":
            return None if self._sync_warnings_locked(state) else False
        self._publish(mutate)
        return SourceEffects(changes, signal=bool(changes))

    def tick_housekeeping(self, now: float) -> SourceEffects:
        """The once-a-second tick: the update watch, expired warnings, and
        the snooze write. Does file I/O: call with no lock held."""
        watched = self.tick_update_watch(now)
        expired = self.expire_warnings()
        self.flush_warnings()
        if watched is None:
            return expired
        return SourceEffects(
            watched.changes + expired.changes, watched.restarting, watched.signal or expired.signal,
        )

    def set_appliance_warnings(self, appliance_id: str, warnings) -> ActionResult:
        """Accept the validated warnings of *appliance_id* (what
        validate_appliance_warnings returns; an empty set clears them).
        The set replaces the appliance's previous one: each warning is
        registered on the manager as a data-driven row and reported active,
        those no longer present end their incidents, and each carries the
        roster's name for the appliance. Refused with unknown_appliance
        for an id not on the roster. Defensively keeps at most
        APPLIANCE_WARNINGS_MAX well-formed, distinct warnings."""
        outcome = []

        def mutate(state: _CoreState) -> "bool | None":
            current = next((a for a in state.appliances if a.appliance_id == appliance_id), None)
            if current is None:
                outcome.append(ActionResult(False, "unknown_appliance"))
                return False
            outcome.append(ActionResult(True))
            clean, seen = [], set()
            for w in tuple(warnings)[:APPLIANCE_WARNINGS_MAX]:
                if (
                    isinstance(w, ApplianceWarning) and w.id not in seen
                    and APPLIANCE_WARNING_ID_RE.fullmatch(w.id) is not None
                ):
                    seen.add(w.id)
                    clean.append(w)
            new = attribute_appliance_warnings(clean, current.name)
            old = state.appliance_warnings.get(appliance_id, ())
            if new == old:
                return False
            for warning in old:
                if warning.id not in seen:
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
            state.appliances = appliance_states(state.roster, state.repeats, held)
            self._sync_warnings_locked(state)
        self._publish(mutate)
        return outcome[0]

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


    # ---- the poll ------------------------------------------------------------

    def set_io(self, io: PollIO) -> None:
        """Replace the calls the poll makes out of the core."""
        self._io = io

    def set_eq_veto(self, veto: Callable[[], bool]) -> None:
        """Say when the EQ page must not be offered whatever the appliance
        advertises (the view's layout has no room for it). Read on the poll
        thread, so it must be a plain, lock-free read."""
        self._eq_veto = veto

    def set_idle_hold(self, hold: Callable[[bool], bool]) -> None:
        """Say when a poll that finds nothing playing must leave what is
        reported as it is: the view has a screen up that it will not redraw
        under (a list open, the panel asleep or about to sleep), and what it
        shows then stays what it was until the screen is done. *hold* is
        told whether this tick has cleared the manual focus (which closes
        the screens bound to it). Read on the poll thread, so it must be a
        plain, lock-free read."""
        self._idle_hold = hold

    def set_polling(self, enabled: bool) -> None:
        """Turn the poll on or off. Off, a tick only clears what polling
        sets and polls nothing. Turning it on polls at once."""
        enabled = bool(enabled)
        was, self._polling = self._polling, enabled

        def mutate(state: _CoreState) -> "bool | None":
            if state.polling == enabled:
                return False
            state.polling = enabled
        self._publish(mutate)
        if enabled and not was and self._thread is not None:
            self._poll_wake.set()

    def set_poll_interval(self, seconds) -> None:
        """Set how often the poll runs, in seconds. A value that is not a
        positive number reads as the default, so a bad setting never stops
        the poll. A change cuts the current wait short, so the new interval
        applies from the next tick."""
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not seconds > 0:
            seconds = DEFAULT_POLL_INTERVAL_S
        if seconds != self._poll_interval:
            self._poll_interval = seconds
            self._poll_wake.set()

    def request_poll(self, *, reconcile: bool = False) -> None:
        """Ask the poll thread to run a tick now instead of waiting for the
        next one. With *reconcile*, the tick also re-confirms every
        appliance (the auth map is told they are all due). Lock-free: any
        thread may call it."""
        if reconcile:
            auth_map.force_due()
            self.request_reconcile()
        else:
            self._poll_wake.set()

    def request_reconcile(self) -> None:
        """Ask for a poll now that also re-confirms the whole roster, without
        touching the auth map's re-probe timers. Lock-free."""
        self._reconcile_due = True
        self._poll_wake.set()

    def notify_auth_changed(self, appliance_id: str) -> None:
        """Record that *appliance_id* pushed an auth change. Never probes
        here: it only queues the id, makes it due and wakes the poll thread,
        which probes the appliance on its next tick."""
        with self._push_lock:
            self._push_pending.add(appliance_id)
        auth_map.force_due(appliance_id)
        self._poll_wake.set()

    def take_effects(self) -> list:
        """The `SourceEffects` the housekeeping has queued since the last
        call, oldest first: what the warning sources did that a view turns
        into screens."""
        with self._lock:
            effects, self._effects = self._effects, []
        return effects

    def start(self) -> None:
        """Start the `dial-core` thread. A second call while it runs does
        nothing."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        try:
            self._thread = threading.Thread(target=self._run, daemon=True, name="dial-core")
            self._thread.start()
        except Exception as e:
            # Must never stop the rest of the start-up sequence.
            logging.warning("dial core: failed to start the poll thread: %s", e)
            self._thread = None

    def stop(self) -> None:
        """Stop the `dial-core` thread, waiting up to two seconds for it."""
        self._stop.set()
        self._poll_wake.set()
        thread = self._thread
        if thread is not None:
            try:
                thread.join(timeout=2)
            except RuntimeError:
                # Thread.start() had not finished registering; the daemon
                # thread still exits on its own once the stop event is set.
                pass

    def _run(self) -> None:
        """The core thread: poll every interval (or when woken), and do the
        housekeeping on every wake, never waiting longer than a second. The
        interval runs from the end of a tick, so a slow poll never backlogs.
        The loop keeps its own time with a clock nothing replaces."""
        next_poll = 0.0
        while not self._stop.is_set():
            now = time.perf_counter()
            if self._poll_wake.is_set() or now >= next_poll:
                self._poll_wake.clear()
                try:
                    self._drain_push_probes()
                    self.poll_once()
                except Exception:
                    logging.debug("dial core: poll iteration raised", exc_info=True)
                next_poll = time.perf_counter() + self._poll_interval
            try:
                self._housekeeping(self._clock())
            except Exception:
                logging.debug("dial core: housekeeping raised", exc_info=True)
            remaining = next_poll - time.perf_counter()
            self._poll_wake.wait(max(0.0, min(HOUSEKEEPING_INTERVAL_S, remaining)))

    def _housekeeping(self, now: float) -> None:
        """The once-a-second work: the update watch, expiring warnings, the
        snooze write, and the refresh of watched outputs and EQ. What it did
        to the warnings is queued for a view and the subscribers are told."""
        effects = self.tick_housekeeping(now)
        self.refresh_watched(now)
        if effects.changes or effects.restarting or effects.signal:
            with self._lock:
                self._effects.append(effects)
            self._publish(lambda state: None)

    def _drain_push_probes(self) -> str:
        """Probe every appliance the push queue holds. Returns "probed"
        when anything was probed, "" otherwise. A probe that confirms a new
        authorisation is published at once (`auth_promotions`), which is
        what wakes a sleeping view."""
        with self._push_lock:
            ids = set(self._push_pending)
            self._push_pending.clear()
        if not ids:
            return ""
        targets = {t.appliance_id: t for t in self._get_display_targets() if t.appliance_id}
        roster = {r.appliance_id: r for r in self._state.roster if r.appliance_id}
        promoted = dial_core_poll.drain_push_probes(
            ids, targets, roster, self._dial_id, self._probe_auth,
        )
        if promoted:
            def mutate(state: _CoreState) -> None:
                state.auth_promotions += len(promoted)
            self._publish(mutate)
        return "probed"

    def _probe_auth(self, target) -> dict:
        return dial_core_poll.probe_auth(target, self._dial_id, fetch=self._io.fetch_status)

    def poll_once(self) -> None:
        """Run one poll tick on the calling thread and publish its end: the
        loop's step, and what a test calls to poll without the thread. Not
        for two threads at once."""
        state = self._state
        previous_reporting_id = state.focus.reporting_id
        previous_now_playing = state.now_playing
        previous_idle_affordance = state.idle_affordance
        self._focus_cleared = False
        self._idle_focus_found = False
        polling = self._polling
        if polling:
            visible_ids = self._poll_tick()
        else:
            visible_ids = self._clear_polled_fields()
        now = self._clock()
        repeats = {}
        for r in self._state.roster:
            appliance_id = getattr(r, "appliance_id", "")
            if appliance_id:
                repeats[appliance_id] = repeat_store.get(appliance_id, now)
        tick = TickContext(
            previous_reporting_id, previous_now_playing, previous_idle_affordance,
            self._focus_cleared, self._idle_focus_found,
        )
        self.publish_tick(polling=polling, repeats=repeats, visible_playing=visible_ids, tick=tick)

    def _clear_polled_fields(self) -> tuple:
        """What a tick does while polling is off: nothing is reported."""
        self.set_field("source_service_name", None)
        self.set_field("now_playing", None)
        self.set_field("reporting_id", None)
        self.set_field("dots_active", False)
        self.set_field("outputs_available", False)
        self.set_field("eq_available", False)
        return ()

    def _clear_poll_focus(self, reason: str) -> None:
        self.clear_focus(reason)
        self._focus_cleared = True

    def _announce_visible(self, visible_ids: tuple) -> None:
        """Publish the set of playing appliances this dial may use as soon as
        it is known and has changed, before the walk's status requests run,
        so a view can wake for it without waiting for them."""
        def mutate(state: _CoreState) -> "bool | None":
            if state.visible_playing == visible_ids:
                return False
            state.visible_playing = visible_ids
        self._publish(mutate)

    def _update_availability(self, now: float) -> None:
        """Recompute what the focused or reporting appliance offers: the EQ
        page (unless the view vetoes it), the page dots, and the outputs
        list."""
        focus = self._state.focus
        appliance_id = focus.manual_id or focus.reporting_id
        roster = self._state.roster
        rec = repeat_store.get(appliance_id, now) if appliance_id else None
        eq = eq_available(roster, appliance_id, self._eq_veto)
        self.set_field("eq_available", eq)
        self.set_field("dots_active", dots_active(rec, eq))
        self.set_field("outputs_available", outputs_available(roster, appliance_id))

    def _refresh_idle_affordance(self, roster: list, now: float) -> None:
        self.set_field("idle_affordance", idle_affordance(roster, repeat_store.held_ids(now)))

    def _reconcile_if_due(self, roster: list, visited: set, now: float) -> None:
        if self._reconcile_due or now - self._last_reconcile_at >= RECONCILE_INTERVAL_S:
            dial_core_poll.reconcile(
                roster, visited, self._dial_id, enrich=self._io.enrich, now_fn=self._clock,
            )
            self._last_reconcile_at = now
            self._reconcile_due = False

    def _fetch_idle_focus(self, idle_focus):
        """One status request for a focus that has nothing playing under
        it, applied to the auth map and the repeat store."""
        result = self._io.fetch_status(
            idle_focus, self._dial_id, timeout_seconds=dial_core_poll.DIAL_STATUS_TIMEOUT_SECONDS,
        )
        dial_core_poll.apply_status_to_auth(idle_focus, result)
        dial_core_poll.apply_status_to_repeat(idle_focus.appliance_id, result, self._clock())
        return result

    def _poll_tick(self) -> tuple:
        """The tick itself, as far as the core is concerned: everything that
        asks the appliances, reads the roster and decides what is shown.
        Returns the ids of the playing appliances this dial may use. What a
        screen does about it is the view's, from the snapshot this ends in."""
        io = self._io
        dial_id = self._dial_id
        targets = self.with_accepted_replay(self._get_display_targets(), self._clock())
        playing_ids = {t.appliance_id for t in targets if t.appliance_id}
        # The targets this dial may act on: not confirmed unauthorized, and
        # carrying an identity (an unresolved legacy or identity-less
        # appliance cannot be addressed or tracked). Everything below that
        # wakes, binds, reports or offers a volume target works from this
        # list; the raw list still feeds the selector (via the roster) so a
        # refused appliance stays listed.
        visible = visible_targets(targets)
        # A source that was playing and has now stopped drops out of the
        # playing set but stays advertised (idle) in the general roster with
        # a retained recording the appliance now reports as "hold". That
        # transition must reach the idle screen's replay affordance and the
        # replay picker promptly, not up to a full reconcile interval later,
        # so force an immediate reconcile whenever the playing set shrinks.
        stopped_ids = self._prev_playing_ids - playing_ids
        if stopped_ids:
            self._reconcile_due = True
            auth_map.force_due()
        # A refused appliance that starts playing again is re-checked at
        # once rather than at the end of its re-probe backoff: the usual way
        # to fix a refusal is to allow the dial in the appliance's web UI and
        # press play, and an appliance that pushes no auth change gives the
        # dial no other prompt to look again.
        refused_ids = started_refused(targets, self._prev_playing_ids)
        for appliance_id in refused_ids:
            auth_map.force_due(appliance_id)
        if refused_ids:
            self._reconcile_due = True
        # An appliance that has just started playing and has never answered
        # this dial (after a restart, say) is checked before anything below
        # shows it or lets a view wake for it: otherwise one that refuses the
        # dial would be shown as playing until a later poll hid it again.
        # Only for an unpinned poll (a focus or a binding is checked by the
        # walk itself, which releases it on a refusal), and in the walk's
        # own order, stopping at the first appliance that does not refuse:
        # that is the one the walk would have asked first anyway. The
        # replies are kept for the walk, which uses them instead of asking
        # again.
        first_checks: dict[str, tuple[float, dict]] = {}
        focus = self._state.focus
        if focus.manual_id is None and focus.bound_id is None:
            first_checks = dial_core_poll.first_checks(
                visible, self._prev_playing_ids, dial_id,
                fetch=io.fetch_status, now_fn=self._clock,
            )
        if first_checks:
            visible = [
                t for t in visible if auth_map.state(t.appliance_id) != AUTH_UNAUTHORIZED
            ]
        self._prev_playing_ids = playing_ids
        # Any visible playing target counts as activity for a view, including
        # status-erroring ones: the mDNS presence alone means audio is
        # playing on an appliance this dial can talk to. Published now, ahead
        # of the walk's status requests, so a sleeping view wakes without
        # waiting for them. A confirmed-unauthorized appliance, or one with
        # no identity after legacy resolution, does not count. (Unknown auth
        # still counts: it is controllable until a refusal says otherwise.)
        visible_ids = tuple(sorted(t.appliance_id for t in visible))
        self._announce_visible(visible_ids)
        # The merged playing+idle roster: this is where general (idle)
        # sightings get noted into the auth map (dial_mdns.get_roster()'s
        # docstring). Computed unconditionally, whether or not anything is
        # playing, so an idle appliance's presence is tracked at every poll
        # tick, not only while something else happens to be playing.
        roster = self._get_roster()
        self.set_roster(roster)
        now = self._clock()

        # Resolve manual focus before anything else. focus_target is the
        # focused appliance only when it is in the playing set this tick. A
        # focus is cleared when the appliance is no longer rostered at all
        # (or is confirmed unauthorized), or when it was playing last tick
        # and has just stopped: "the show is over". A focus resting on an
        # idle appliance is otherwise kept even while something else plays:
        # that is what lets a pick control an idle device. Unless a picker-
        # started replay is still within its pending grace window, in
        # which case the focus is kept and the empty-targets branch below
        # reports the appliance's name over the logo instead of the ordinary
        # idle screen.
        focus_id = self._state.focus.manual_id
        prev_pending = self._state.focus.pending
        resolution = resolve_focus(
            focus_id, prev_pending, roster, visible, stopped_ids, now, auth_map.state,
        )
        self.replace_pending(prev_pending, resolution.pending)
        if resolution.clear_reason is not None:
            self._clear_poll_focus(resolution.clear_reason)
        focus_target = resolution.focus_target

        # An idle focus: a rostered focus with nothing playing under it.
        # The walk/artwork-selection path below runs only when this is
        # None; when it is set, one pinned status fetch replaces it, and it
        # is what the empty-targets branch reports in place of the idle
        # screen.
        idle_focus = resolution.idle_focus
        self._idle_focus_found = idle_focus is not None

        if not visible:
            # Nothing playing anywhere: there is no reporting-from target any
            # more, and a stale readout for a target that has since stopped
            # must not survive to the next time something starts playing,
            # unless a manual focus (idle, or a not-yet-rostered pending
            # replay) has something of its own to show. The roster reconcile
            # and the idle-affordance refresh still run here on their usual
            # cadence: this is exactly the state the idle screen and the
            # replay picker exist for, and the artwork walk below never runs
            # in this branch to cover it another way.
            self.set_field("source_service_name", None)
            io.observe_volume(None, None)
            io.observe_mute(None, None)
            self._reconcile_if_due(roster, set(), now)
            self._refresh_idle_affordance(roster, now)
            if self._idle_hold(self._focus_cleared):
                return visible_ids

            if idle_focus is not None:
                result = self._fetch_idle_focus(idle_focus)
                if result.get("status_error") == "unauthorized":
                    self._clear_poll_focus("appliance now unauthorized")
                    idle_focus = None   # fall through to the plain idle screen below
                else:
                    master_volume = result.get("master_volume") if not result.get("status_error") else None
                    self.set_field("reporting_id", idle_focus.appliance_id)
                    self.set_field("source_service_name", idle_focus.service_name)
                    self.set_field("now_playing", NowPlaying(
                        idle_focus.service_name, "", "", master_volume, playing=False,
                    ))
                    self._update_availability(now)
            if idle_focus is None:
                pending = self._state.focus.pending
                if pending is not None:
                    # A picker-started replay hasn't reached the playing set
                    # yet, and its appliance is not rostered at all: keep
                    # reporting its name over the logo rather than falling
                    # into the idle screen underneath it (the idle
                    # affordance is suppressed too, now-playing is not None
                    # here).
                    self.set_field("now_playing", NowPlaying(pending[1], "", "", None, playing=False))
                    self.set_field("reporting_id", pending[0])
                else:
                    self.set_field("now_playing", None)
                    self.set_field("reporting_id", None)
                self._update_availability(now)

            # Mirror the binding to whatever is reporting now: a manual
            # focus (idle or pending) always wins and the binding simply
            # tracks it; with none, the binding tracks the (possibly None)
            # reporting id directly, so it releases cleanly to nothing
            # playing/focused and the next tick's walk starts unpinned.
            reporting_id = self._state.focus.reporting_id
            self.set_field("bound_id", focus_id if focus_id is not None else reporting_id)
            self.clear_artwork()
            return visible_ids

        selected_url = None
        selected_service = None
        selected_artist = ""
        selected_title = ""
        selected_album = ""
        records: dict[str, dict] = {}
        visited: set[str] = set(first_checks)  # already asked this tick
        # Monotonic time each mute-feeding status request was sent, so the
        # mute observation below can tell a stale reply from a fresh one. A
        # service never fetched this tick counts as sent at 0.0: still a poll
        # observation, never newer than anything a reply has settled.
        status_sent_at: dict[str, float] = {}

        if idle_focus is not None:
            # One pinned status fetch in place of the whole walk: an idle
            # focus has no artwork of its own, so selected_url/artist/title
            # stay empty, but its auth/repeat state is refreshed and its
            # visited entry stops the reconcile pass below re-probing it.
            status_sent_at[idle_focus.service_name] = self._clock()
            result = self._fetch_idle_focus(idle_focus)
            visited.add(idle_focus.service_name)
            if result.get("status_error") == "unauthorized":
                self._clear_poll_focus("appliance now unauthorized")
                idle_focus = None            # fall through to the ordinary walk this tick
            else:
                selected_service = idle_focus.service_name
                if not result.get("status_error"):
                    records[idle_focus.service_name] = result

        if idle_focus is None:
            # Automatic binding beneath manual focus, only when no manual
            # focus is set: the appliance the screen was already bound to
            # is pinned the same way a manual focus is, so a newly-identified
            # appliance elsewhere cannot steal the screen. Released, and the
            # walk below runs unpinned, the moment the bound appliance stops,
            # leaves the roster, or is confirmed unauthorized; whatever the
            # unpinned walk then reports becomes the new binding at the end
            # of the tick.
            pin_target, bound_id = choose_pin(
                focus_target, self._state.focus.bound_id if focus_id is None else None, visible,
            )
            if focus_id is None and bound_id is None:
                self.set_field("bound_id", None)

            # With a focus (or, absent one, a binding), it is polled first
            # and pinned to unconditionally: the walk never falls through
            # to another appliance's artwork. With neither, the
            # playing_since-ordered walk applies.
            ordered = walk_order(pin_target, visible)

            def on_revoke() -> None:
                # Revoked mid-tick: release whichever pin this was. A
                # manual focus clears it, an automatic binding just
                # releases, and the walk carries on over the remaining
                # targets in this same poll, so the screen shows the
                # auto-pick target immediately.
                nonlocal focus_target
                if focus_target is not None:
                    self._clear_poll_focus("appliance now unauthorized")
                    focus_target = None
                else:
                    self.set_field("bound_id", None)

            walked = dial_core_poll.walk(
                ordered, first_checks, dial_id, pin_target,
                fetch=io.fetch_status, now_fn=self._clock, on_revoke=on_revoke,
            )
            records.update(walked.records)
            status_sent_at.update(walked.status_sent_at)
            visited |= walked.visited
            selection = walked.selection
            selected_url = selection.url
            selected_service = selection.service
            selected_artist = selection.artist
            selected_title = selection.title
            selected_album = selection.album

        # Reporting-from target: the idle focus when one is pinned; else
        # the identified (or focused) source, else the oldest playing
        # CONTROLLABLE target (select_volume_target's fallback). Only
        # auth != unauthorized targets are offered, matching the volume
        # resolver's own filter so the poll and the worker can never
        # disagree about who volume/mute addresses.
        reporting = reporting_for(idle_focus, visible, selected_service)
        reporting_name = reporting.service_name if reporting is not None else None
        reporting_id = reporting.appliance_id if reporting is not None else None
        self.set_field("reporting_id", reporting_id)
        # Mirror the binding to whatever is reporting now (see the
        # empty-targets branch's identical mirror update above).
        # reporting_id can still be None here (e.g. every target
        # unauthorized this tick); the mirror releases to None the same way.
        self.set_field("bound_id", focus_id if focus_id is not None else reporting_id)
        self._update_availability(self._clock())
        record = records.get(reporting_name) if reporting_name else None
        master_volume = record.get("master_volume") if record else None
        dial_core_poll.observe_tick(
            records, reporting_name, status_sent_at, visible, master_volume,
            observe_mute=io.observe_mute, observe_volume=io.observe_volume,
            forget=io.forget_mute,
        )

        # Assigned before the artwork fetch below so a volume press landing
        # during it already goes to the right target.
        self.set_field("source_service_name", selected_service)
        self.set_field("now_playing", (
            NowPlaying(
                reporting_name, selected_artist, selected_title, master_volume, album=selected_album,
                # An idle focus reporting here (targets present elsewhere,
                # but the shown appliance itself has nothing playing) is not
                # playing, same as the empty-targets branch's own idle
                # focus above. Every other path that reaches here (an
                # identified or not-yet-identified playing target) keeps
                # the default True.
                playing=idle_focus is None,
            )
            if reporting_name is not None else None
        ))

        if selected_url:
            self.fetch_artwork(
                selected_url, fetch=io.fetch_artwork, log_limiter=io.log_limiter,
                eligible=io.artwork_eligible,
                timeout=dial_core_poll.ARTWORK_FETCH_TIMEOUT_SECONDS,
                on_error=io.on_artwork_error,
            )
        else:
            self.clear_artwork()

        now = self._clock()
        self._reconcile_if_due(roster, visited, now)
        self._refresh_idle_affordance(roster, now)
        return visible_ids


def create_dial_core(cfg, get_display_targets: Callable, get_roster: Callable = _default_get_roster) -> DialCore:
    """Build the core for dial_main.py wiring."""
    return DialCore(cfg.uuid, get_display_targets, get_roster)
