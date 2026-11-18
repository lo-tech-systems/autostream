"""autostream_dial_push.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Tells dials that something they show has changed. notify_state_changed() is
the single entry point: it is called once a change is committed, from any
thread, and returns at once. A dial that is told asks the appliance for its
state itself, so the hint carries only which kinds of thing changed and a
hint that is lost, late or repeated can never leave a dial wrong.

A change is sent at once; further changes inside a short window are sent
together when it ends (StateChangeCoalescer). The send is one fan-out job on
the shared push worker in autostream_webui_dials, which is imported only when
a hint is emitted so that the modules that report changes can import this one
without an import cycle.

Some state is changed only by the coordinator (the daemon's repeat block, the
identified track, a session starting or ending). StateHints, a subscriber to
the state store, notices those once per coordinator cycle. A change to the
outputs part is hinted as what moved in it: the speaker list, the volumes, the
mutes.
"""
from __future__ import annotations

import logging
import threading
import time

from autostream_state import (
    active_track,
    eq_band_digest,
    outputs_list_digest,
    outputs_mute_digest,
    outputs_volume_digest,
    repeat_digest,
    store as _state_store,
    track_digest,
)


STATE_PUSH_PATH = "/state-changed"
# A change is pushed at once; further changes inside this window are pushed
# once, together, when the window ends.
STATE_PUSH_MIN_INTERVAL_S = 0.3
# Oldest dial protocol generation the hint is sent to.
STATE_PUSH_MIN_GENERATION = 3

# What a hint may say changed. A dial treats the list as advisory and an
# unknown token as "something"; the table keeps the senders honest.
CHANGE_KINDS = frozenset({
    "session", "outputs", "volume", "mute", "repeat", "track", "eq", "input",
})


def _timer(delay: float, fn) -> None:
    t = threading.Timer(delay, fn)
    t.daemon = True
    t.start()


class StateChangeCoalescer:
    """A change is emitted at once when none was emitted inside the last
    min_interval_s; otherwise it waits for that window to end and is emitted
    then, together with everything recorded meanwhile. A dial is left out of
    an emitted hint only when every change it merges named that dial.

    The lock covers plain reads and writes only. emit is always called after
    it is released, on the thread of the notify() or flush() that took the
    pending changes."""

    def __init__(self, emit, *, clock=time.monotonic, schedule=None,
                 min_interval_s=STATE_PUSH_MIN_INTERVAL_S) -> None:
        # emit(kinds: frozenset, except_dials: frozenset)
        self._emit = emit
        self._clock = clock
        # schedule(delay_s, fn) runs fn once after delay_s, on another thread
        self._schedule = schedule if schedule is not None else _timer
        self._min_interval_s = min_interval_s
        self._lock = threading.Lock()
        self._last_emit_at: float | None = None
        self._pending_kinds: set = set()
        self._pending_except: set | None = None   # None: nothing pending
        self._scheduled = False

    def notify(self, kinds, except_dial=None) -> None:
        now = self._clock()
        emit = None
        delay = None
        with self._lock:
            self._pending_kinds.update(kinds)
            names = {except_dial} if except_dial else set()
            if self._pending_except is None:
                self._pending_except = names
            else:
                self._pending_except &= names
            inside = (self._last_emit_at is not None
                      and now - self._last_emit_at < self._min_interval_s)
            if not inside:
                emit = self._take_locked(now)
            elif not self._scheduled:
                self._scheduled = True
                delay = self._last_emit_at + self._min_interval_s - now
        if emit is not None:
            self._emit(*emit)
        elif delay is not None:
            try:
                self._schedule(max(0.0, delay), self.flush)
            except Exception:
                # Nothing will flush this window; let the next change
                # schedule again rather than wait for one that never comes.
                with self._lock:
                    self._scheduled = False
                raise

    def flush(self) -> None:
        """Emit what is pending: the end of a window."""
        emit = None
        with self._lock:
            self._scheduled = False
            if self._pending_except is not None:
                emit = self._take_locked(self._clock())
        if emit is not None:
            self._emit(*emit)

    def _take_locked(self, now):
        kinds = frozenset(self._pending_kinds)
        names = frozenset(self._pending_except or ())
        self._pending_kinds.clear()
        self._pending_except = None
        self._last_emit_at = now
        return kinds, names


def _emit_hint(kinds: frozenset, except_dials: frozenset) -> None:
    try:
        from autostream_webui_dials import enqueue_fanout
        enqueue_fanout(
            STATE_PUSH_PATH, {"changed": sorted(kinds)},
            min_generation=STATE_PUSH_MIN_GENERATION, exclude=except_dials,
        )
        logging.debug("dial push: state changed (%s)", ",".join(sorted(kinds)))
    except Exception:
        # Also reached from the timer thread, which has no caller to tell.
        logging.debug("dial push: could not queue the state hint", exc_info=True)


_coalescer = StateChangeCoalescer(_emit_hint)


def notify_state_changed(*kinds: str, except_dial: str | None = None) -> None:
    """Say that something a dial shows has changed. Call once the change is
    committed, with no lock held. Never blocks on the network, never raises.
    *kinds* name what changed (CHANGE_KINDS); *except_dial* is the uuid of
    the dial whose own request made the change, which already has the
    result in its reply and is left out of the hint."""
    try:
        if not kinds or any(k not in CHANGE_KINDS for k in kinds):
            logging.debug("dial push: ignoring state change %r", kinds)
            return
        _coalescer.notify(
            kinds, except_dial if isinstance(except_dial, str) and except_dial else None,
        )
    except Exception:
        logging.debug("dial push: notify failed", exc_info=True)


class StateHints:
    """Turns state changes into dial hints. Session edges come as the
    "session" tag. Repeat and track are compared only on a Change with
    batch=True (the close of a coordinator cycle): the repeat block and the
    active track are compared with their values at the previous close, the
    first close being the baseline and an analysing track keeping the previous
    value. Immediate (non-batch) repeat and track Changes, from the ack path
    and the identification workers, are not compared here: the ack path
    carries the "repeat" tag, which is sent as it is, and comparing them too
    would hint a seek twice. Kinds are
    sent one call each, session first, then repeat, then track, as the
    coordinator did.

    A Change that moved the outputs part, batch or not, is compared in three
    pieces (the speaker list, the volumes, the mutes) with their values at the
    previous comparison, the first being the baseline; each that moved is sent
    as "outputs", "volume" or "mute", in that order, after the session and
    tags and before the repeat and track. A Change that touched the equaliser
    part sends "eq" when the output bands moved, compared the same way; the
    gains, the auto-trim and the input equalisers are not shown on a dial."""

    def __init__(self, notify=None) -> None:
        # None means notify_state_changed, looked up when a hint is sent.
        self._notify = notify
        self._last: dict[str, object] = {}

    def __call__(self, change) -> None:
        try:
            self._hint(change)
        except Exception:
            logging.debug("dial push: state hints failed", exc_info=True)

    def _hint(self, change) -> None:
        except_dial = _dial_of(change.requester)
        if "session" in change.tags:
            self._send("session", except_dial)
        for tag in sorted(change.tags - {"session"}):
            if tag in CHANGE_KINDS:
                self._send(tag, except_dial)
        if "outputs" in change.parts:
            outputs = _state_store().snapshot().outputs
            for kind, digest in (
                ("outputs", outputs_list_digest),
                ("volume", outputs_volume_digest),
                ("mute", outputs_mute_digest),
            ):
                if self._moved(kind, lambda digest=digest: digest(outputs)):
                    self._send(kind, except_dial)
        if "eq" in change.parts:
            eq = _state_store().snapshot().eq
            if self._moved("eq", lambda: eq_band_digest(eq)):
                self._send("eq", except_dial)
        if not change.batch:
            return
        snap = _state_store().snapshot()
        if self._moved("repeat", lambda: repeat_digest(snap.repeat.block)):
            self._send("repeat", except_dial)
        if self._moved("track", lambda: track_digest(active_track(snap))):
            self._send("track", except_dial)

    def _send(self, kind: str, except_dial) -> None:
        (self._notify or notify_state_changed)(kind, except_dial=except_dial)

    def _moved(self, kind: str, digest) -> bool:
        """True when *kind*'s digest differs from the previous reading. The
        first reading is the baseline: a dial fetches the state itself when it
        first meets the appliance. No reading (an attempt is in flight) keeps
        what was there."""
        try:
            value = digest()
        except Exception:
            logging.debug("dial push: %s digest failed", kind, exc_info=True)
            return False
        if value is None:
            return False
        if kind not in self._last:
            self._last[kind] = value
            return False
        if value == self._last[kind]:
            return False
        self._last[kind] = value
        return True


def _dial_of(requester) -> str | None:
    """The uuid in a requester of the form "dial:<uuid>", else None."""
    if isinstance(requester, str) and requester.startswith("dial:") and len(requester) > 5:
        return requester[5:]
    return None


def install_state_hints(store) -> int:
    """Subscribe a StateHints to *store*; returns the subscription handle."""
    return store.subscribe(StateHints())
