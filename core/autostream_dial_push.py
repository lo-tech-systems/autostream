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
identified track, a session starting or ending). ChangeWatch and
hint_dials_after_cycle let its loop notice those once per cycle.
"""
from __future__ import annotations

import logging
import threading
import time

from track_id.models import STATE_ANALYSING, STATE_IDENTIFIED

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


def repeat_digest(rs) -> tuple:
    """The parts of the daemon's repeat block a dial shows: whether the
    feature is on and armed, whether it is recording, holds a recording, is
    replaying or fading out. Positions and durations move every cycle and
    are left out."""
    if not isinstance(rs, dict):
        return ()
    rec = rs.get("recording") if isinstance(rs.get("recording"), dict) else {}
    rep = rs.get("replay") if isinstance(rs.get("replay"), dict) else {}
    return (
        bool(rs.get("enabled")), bool(rs.get("armed")), bool(rec.get("active")),
        (rec.get("seconds") or 0) > 0, bool(rep.get("active")), bool(rep.get("fading_out")),
    )


def track_digest(snap) -> tuple | None:
    """The parts of a track identification snapshot a dial shows: whether a
    track is identified and, if so, its title, artist, album and artwork.
    While an attempt is in flight there is nothing to say (None); the
    timestamps and the attempt states a dial does not tell apart are left
    out."""
    state = getattr(snap, "state", None)
    if state == STATE_ANALYSING:
        return None
    identified = state == STATE_IDENTIFIED
    artwork = (getattr(snap, "artwork_url", "") or "") if identified else ""
    if not artwork.startswith(("http://", "https://")):
        artwork = ""
    text = (
        tuple(getattr(snap, name, "") or "" for name in ("title", "artist", "album"))
        if identified else ("", "", "")
    )
    return (bool(getattr(snap, "enabled", False)), identified) + text + (artwork,)


class ChangeWatch:
    """Notices when *digest* moves between readings and says so as *kind*.
    The first reading is the baseline: a dial fetches the state itself when
    it first meets the appliance."""

    def __init__(self, kind: str, digest) -> None:
        self._kind = kind
        self._digest = digest
        self._last = None
        self._primed = False

    def step(self) -> bool:
        try:
            value = self._digest()
        except Exception:
            logging.debug("dial push: %s digest failed", self._kind, exc_info=True)
            return False
        if value is None:
            # No reading (an attempt is in flight): keep what we had.
            return False
        if not self._primed:
            self._primed = True
            self._last = value
            return False
        if value == self._last:
            return False
        self._last = value
        notify_state_changed(self._kind)
        return True


def hint_dials_after_cycle(session_event, watches) -> None:
    """What one coordinator poll cycle changed that only the coordinator
    sees: a session edge, and whatever the watches notice."""
    if session_event is not None:
        notify_state_changed("session")
    for watch in watches:
        watch.step()
