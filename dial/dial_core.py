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

from dial_core_state import CoreSnapshot, DialInfo, FocusState, NowPlaying
from dial_mdns import get_roster as _default_get_roster


@dataclass
class _CoreState:
    """The core's mutable state: `CoreSnapshot`'s fields other than `seq` and
    `at`, which `_publish` stamps. Values are immutable (tuples and frozen
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


_STATE_FIELDS = tuple(f.name for f in dataclasses.fields(_CoreState))


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
            **{name: getattr(self._state, name) for name in _STATE_FIELDS},
        )

    def _publish(self, mutate_fn: Callable[[_CoreState], None]) -> CoreSnapshot:
        """Apply *mutate_fn* to the state under the lock (in-memory work
        only), publish the resulting snapshot, then signal the subscribers
        outside the lock. Returns the new snapshot."""
        with self._cond:
            mutate_fn(self._state)
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
        focus: FocusState,
        now_playing: NowPlaying | None,
        idle_affordance: bool,
        outputs_available: bool,
        eq_available: bool,
    ) -> CoreSnapshot:
        """Publish the results of one poll tick."""
        def mutate(state: _CoreState) -> None:
            state.polling = polling
            state.focus = focus
            state.now_playing = now_playing
            state.idle_affordance = idle_affordance
            state.outputs_available = outputs_available
            state.eq_available = eq_available
        return self._publish(mutate)


def create_dial_core(cfg, get_display_targets: Callable, get_roster: Callable = _default_get_roster) -> DialCore:
    """Build the core for dial_main.py wiring."""
    return DialCore(cfg.uuid, get_display_targets, get_roster)
