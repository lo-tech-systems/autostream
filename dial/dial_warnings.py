"""dial_warnings.py: the dial's on-screen warning framework.

A warning is described once (WarningDescriptor: identity, kind, priority,
its text and its buttons) and driven by a source that calls set_active() and
clear() on the manager. The manager keeps the per-warning runtime state
(active, reading, since when) and decides which status screen is due (the
highest-priority active one).

Pure: no hardware, no drawing, no threads of its own. The display manager
owns one WarningManager and is the only caller that turns "due" into a
screen request.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass

# Button actions. Close puts a warning card away in the view that shows it
# (and, for a status card, ends the status); Next steps a warnings card to
# its next entry; Restart shows the restarting screen and asks for the reboot.
ACTION_CLOSE = "close"
ACTION_NEXT = "next"
ACTION_RESTART = "restart"

# The two kinds of descriptor. A warning is a condition a person may want to
# know about and can set aside; a status is what the dial is doing right now
# (an update running or finished) and opens by itself.
KIND_WARNING = "warning"
KIND_STATUS = "status"

# Warnings an appliance supplies are registered at run time under keys that
# start with this prefix (then the appliance id).
APPLIANCE_WARNING_PREFIX = "appliance:"


@dataclass(frozen=True)
class WarningButton:
    """One tappable cell on a card: the label the compositor draws in it and
    the action a tap runs."""
    label: str
    action: str


@dataclass(frozen=True)
class WarningDescriptor:
    """Everything the framework needs to know about one warning.

    id: the key sources and the runtime state use.
    kind: KIND_WARNING or KIND_STATUS.
    priority: higher wins when more than one status is due at once.
    title: the readout-size line. message_for(reading) -> the body-size
      line under it, or None for a single centred line. The reading is
      what the source reported when it set the warning active.
    severity_for(reading) -> "info", "warning" or "critical".
    buttons: left to right.
    title_for(reading) -> the readout-size line, replacing `title` when
      set (a page whose heading depends on its reading).
    progress_for(reading) -> a percent 0..100 drawn as a bar under the
      message, or None for no bar.
    interrupting: the page may open over a secondary screen, and a source
      activating it wakes a sleeping panel. Priority still decides which
      status shows. Always False for a warning.
    auto_clear_after_s: the manager reports the warning expired once it
      has been active this long, and the display clears it like a source
      would. None: only the source clears it.
    source_name: who the warning is attributed to (an appliance warning
      carries its appliance's name); "" for the dial's own.
    screen: the screen-policy row name of a status, which is also its touch
      surface; "" for a warning (a warning shows on the warnings page).
    A descriptor with no buttons has a touch-inert page.
    """
    id: str
    kind: str
    priority: int
    title: str
    message_for: "object | None"
    severity_for: "object"
    buttons: tuple[WarningButton, ...]
    title_for: "object | None" = None
    progress_for: "object | None" = None
    interrupting: bool = False
    auto_clear_after_s: "float | None" = None
    source_name: str = ""
    screen: str = ""


@dataclass
class _WarningRuntime:
    active: bool = False
    reading: object = None
    active_since: "float | None" = None      # when the current incident began; None while inactive


class WarningManager:
    """Runtime state for every registered warning and the due rules.
    Thread-safe through one leaf lock that is never held across a call
    out."""

    def __init__(self, descriptors, clock=time.time) -> None:
        self._by_id: dict[str, WarningDescriptor] = {d.id: d for d in descriptors}
        self._order: tuple[str, ...] = tuple(d.id for d in descriptors)
        self._clock = clock
        self._lock = threading.Lock()
        self._state: dict[str, _WarningRuntime] = {wid: _WarningRuntime() for wid in self._by_id}

    # ---- descriptors ----------------------------------------------------

    def descriptor(self, warning_id: str) -> "WarningDescriptor | None":
        return self._by_id.get(warning_id)

    def descriptors(self) -> tuple[WarningDescriptor, ...]:
        with self._lock:
            return tuple(self._by_id[wid] for wid in self._order)

    # ---- run-time registration ------------------------------------------------

    def register(self, descriptor: WarningDescriptor) -> None:
        """Add a warning at run time, or replace the descriptor of one that
        is registered (its runtime state is kept)."""
        with self._lock:
            wid = descriptor.id
            if wid in self._by_id:
                self._by_id[wid] = descriptor
                return
            self._by_id[wid] = descriptor
            self._order = self._order + (wid,)
            self._state[wid] = _WarningRuntime()

    def unregister(self, warning_id: str) -> None:
        """Remove a run-time warning: its incident ends like a source's
        clear and the descriptor goes."""
        with self._lock:
            self._state.pop(warning_id, None)
            self._by_id.pop(warning_id, None)
            self._order = tuple(wid for wid in self._order if wid != warning_id)

    def runtime(self) -> tuple:
        """Every registered warning's runtime state, in registry order, as
        (id, active, reading, active_since) tuples."""
        with self._lock:
            return tuple(
                (wid, s.active, s.reading, s.active_since)
                for wid in self._order
                for s in (self._state[wid],)
            )

    # ---- source API -------------------------------------------------------

    def set_active(self, warning_id: str, reading=None) -> bool:
        """Report the condition present. A repeat refreshes the reading
        and keeps the incident's start time. Returns True when this call
        began a new incident (it was inactive), False for a refresh or an
        unknown id."""
        with self._lock:
            state = self._state.get(warning_id)
            if state is None:
                return False
            began = not state.active
            if began:
                state.active_since = self._clock()
            state.active = True
            state.reading = reading
            return began

    def clear(self, warning_id: str) -> None:
        """End the incident: inactive, so the next one starts clean."""
        with self._lock:
            state = self._state.get(warning_id)
            if state is None:
                return
            state.active = False
            state.reading = None
            state.active_since = None

    # ---- queries --------------------------------------------------------------

    def is_active(self, warning_id: str) -> bool:
        with self._lock:
            state = self._state.get(warning_id)
            return bool(state and state.active)

    def reading(self, warning_id: str):
        with self._lock:
            state = self._state.get(warning_id)
            return state.reading if state else None

    def expired(self, now: "float | None" = None) -> list[str]:
        """The ids of active warnings whose auto_clear_after_s has run
        out, in registry order. The caller clears them."""
        if now is None:
            now = self._clock()
        out: list[str] = []
        with self._lock:
            for wid in self._order:
                state = self._state[wid]
                limit = self._by_id[wid].auto_clear_after_s
                if limit is None or not state.active or state.active_since is None:
                    continue
                if now - state.active_since >= limit:
                    out.append(wid)
        return out

    def due_status(self) -> "WarningDescriptor | None":
        """The highest-priority active status descriptor, or None. Ties keep
        registry order."""
        best: "WarningDescriptor | None" = None
        with self._lock:
            for wid in self._order:
                desc = self._by_id[wid]
                if desc.kind == KIND_STATUS and self._state[wid].active and (
                        best is None or desc.priority > best.priority):
                    best = desc
        return best
