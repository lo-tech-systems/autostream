"""dial_warnings.py: the dial's on-screen warning framework.

A warning is described once (WarningDescriptor: identity, priority, the
screen and touch geometry it paints with, its text, its buttons and how a
Dismiss is remembered) and driven by a source that calls set_active() and
clear() on the manager. The manager keeps the per-warning runtime state
(active, severity, dismissed_until), decides which warning is due (the
highest-priority one that is active and not snoozed), applies the dismiss
policy, and persists time snoozes through WarningStore so a dismissed
warning stays dismissed across a restart.

Pure: no hardware, no drawing, no threads of its own. The display manager
owns one WarningManager and is the only caller that turns "due" into a
screen request. The store never raises: a missing or unreadable file reads
as nothing dismissed, and a failed write degrades to an in-memory snooze
that resets on restart.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import json
import logging
import math
import os
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from dial_touch_layout import TouchZone

WARNINGS_PATH = "/var/lib/autostream/dial-warnings.json"

# Button actions. Dismiss applies the descriptor's snooze policy and closes
# the page; Restart shows the restarting screen and asks for the reboot.
ACTION_DISMISS = "dismiss"
ACTION_RESTART = "restart"


@dataclass(frozen=True)
class WarningButton:
    """One tappable cell on a warning page: the touch zone the geometry
    reports for it, the label the compositor draws in it, and the action
    the manager runs when it is tapped."""
    zone: TouchZone
    label: str
    action: str


@dataclass(frozen=True)
class WarningDescriptor:
    """Everything the framework needs to know about one warning.

    id: the key sources, the store and the runtime state use.
    priority: higher wins when more than one warning is due at once, and
      a lower-priority page never opens over a higher one.
    screen: the screen-policy row name, which is also the touch surface.
    geometry: the touch geometry the page's cells are laid out with.
    title: the readout-size line. message_for(severity) -> the body-size
      line under it, or None for a single centred line.
    buttons: left to right, in geometry order.
    persisted: whether a finite dismissed_until is written to the store.
    snooze_for(severity) -> seconds, or None for an incident-scoped
      dismiss (suppressed until the source clears the warning).
    title_for(severity) -> the readout-size line, replacing `title` when
      set (a page whose heading depends on its severity).
    progress_for(severity) -> a percent 0..100 drawn as a bar under the
      message, or None for no bar.
    interrupting: the page may open over a secondary screen, and a source
      activating it wakes a sleeping panel. Priority still decides which
      warning shows.
    auto_clear_after_s: the manager reports the warning expired once it
      has been active this long, and the display clears it like a source
      would. None: only the source clears it.
    A warning with no buttons is a notice: it cannot be dismissed and its
    page is touch-inert.
    """
    id: str
    priority: int
    screen: str
    geometry: str
    title: str
    message_for: "object | None"
    buttons: tuple[WarningButton, ...]
    persisted: bool
    snooze_for: "object | None"
    title_for: "object | None" = None
    progress_for: "object | None" = None
    interrupting: bool = False
    auto_clear_after_s: "float | None" = None

    def button_for(self, zone: TouchZone) -> "WarningButton | None":
        for button in self.buttons:
            if button.zone == zone:
                return button
        return None


class WarningStore:
    """The dismissed_until map on disk: {"<id>": <epoch seconds>}.

    path=None keeps everything in memory (tests, or a deliberate opt-out).
    load() and save() never raise. The first save creates the file; the
    directory is the dial's own state directory, owned by the service
    user, so no install step is needed."""

    def __init__(self, path: "str | None" = WARNINGS_PATH) -> None:
        self._path = Path(path) if path else None
        self._save_failed_logged = False

    @property
    def path(self) -> "Path | None":
        return self._path

    def load(self) -> dict[str, float]:
        if self._path is None:
            return {}
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except Exception:
            logging.warning("dial warnings: state file unreadable, treating as empty")
            return {}
        if not isinstance(raw, dict):
            return {}
        out: dict[str, float] = {}
        for key, value in raw.items():
            if isinstance(key, str) and isinstance(value, (int, float)) and math.isfinite(value):
                out[key] = float(value)
        return out

    def save(self, until: dict[str, float]) -> bool:
        if self._path is None:
            return True
        try:
            fd, tmp_path = tempfile.mkstemp(dir=self._path.parent, suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(until, f, indent=2, sort_keys=True)
                    f.flush()
                    os.fsync(f.fileno())
                Path(tmp_path).replace(self._path)
            except BaseException:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
            return True
        except Exception:
            if not self._save_failed_logged:
                self._save_failed_logged = True
                logging.warning("dial warnings: cannot write state file, snoozes will not survive a restart")
            else:
                logging.debug("dial warnings: state write failed", exc_info=True)
            return False


@dataclass
class _WarningRuntime:
    active: bool = False
    severity: object = None
    dismissed_until: "float | None" = None   # None: not dismissed; inf: until the source clears
    active_since: "float | None" = None      # when the current incident began; None while inactive


class WarningManager:
    """Runtime state for every registered warning, the due rule, the
    dismiss policy and the persistence handshake. Thread-safe through one
    leaf lock that is never held across I/O or a call out."""

    def __init__(self, descriptors, store: WarningStore, clock=time.time) -> None:
        self._by_id: dict[str, WarningDescriptor] = {d.id: d for d in descriptors}
        self._order: tuple[str, ...] = tuple(d.id for d in descriptors)
        self._store = store
        self._clock = clock
        self._lock = threading.Lock()
        self._state: dict[str, _WarningRuntime] = {wid: _WarningRuntime() for wid in self._by_id}
        self._dirty = False
        now = clock()
        loaded = store.load()
        for wid, until in loaded.items():
            desc = self._by_id.get(wid)
            if desc is None or not desc.persisted or until <= now:
                # An expired, unknown or non-persisted entry is pruned;
                # the next flush writes the pruned map back.
                self._dirty = True
                continue
            self._state[wid].dismissed_until = until

    # ---- descriptors ----------------------------------------------------

    def descriptor(self, warning_id: str) -> "WarningDescriptor | None":
        return self._by_id.get(warning_id)

    def descriptors(self) -> tuple[WarningDescriptor, ...]:
        return tuple(self._by_id[wid] for wid in self._order)

    def button_owner(self, zone: TouchZone) -> "tuple[WarningDescriptor, WarningButton] | None":
        """The first registered warning with a button on *zone*."""
        for wid in self._order:
            desc = self._by_id[wid]
            button = desc.button_for(zone)
            if button is not None:
                return desc, button
        return None

    # ---- source API -------------------------------------------------------

    def set_active(self, warning_id: str, severity=None) -> bool:
        """Report the condition present. A repeat refreshes the severity
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
            state.severity = severity
            return began

    def clear(self, warning_id: str) -> None:
        """End the incident: inactive, any dismissal forgotten (memory and
        file), so the next incident starts clean."""
        with self._lock:
            state = self._state.get(warning_id)
            if state is None:
                return
            state.active = False
            state.severity = None
            state.active_since = None
            if state.dismissed_until is not None:
                state.dismissed_until = None
                if self._by_id[warning_id].persisted:
                    self._dirty = True

    # ---- dismiss policy -----------------------------------------------------

    def dismiss(self, warning_id: str) -> None:
        desc = self._by_id.get(warning_id)
        if desc is None:
            return
        with self._lock:
            state = self._state[warning_id]
            if desc.snooze_for is None:
                state.dismissed_until = math.inf
            else:
                state.dismissed_until = self._clock() + float(desc.snooze_for(state.severity))
                if desc.persisted:
                    self._dirty = True

    # ---- queries --------------------------------------------------------------

    def is_active(self, warning_id: str) -> bool:
        with self._lock:
            state = self._state.get(warning_id)
            return bool(state and state.active)

    def is_snoozed(self, warning_id: str, now: "float | None" = None) -> bool:
        if now is None:
            now = self._clock()
        with self._lock:
            state = self._state.get(warning_id)
            return bool(state and state.dismissed_until is not None and now < state.dismissed_until)

    def severity(self, warning_id: str):
        with self._lock:
            state = self._state.get(warning_id)
            return state.severity if state else None

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

    def due(self, now: "float | None" = None) -> "WarningDescriptor | None":
        """The highest-priority warning that is active and not snoozed, or
        None. Ties keep registry order."""
        if now is None:
            now = self._clock()
        best: "WarningDescriptor | None" = None
        with self._lock:
            for wid in self._order:
                state = self._state[wid]
                if not state.active:
                    continue
                if state.dismissed_until is not None and now < state.dismissed_until:
                    continue
                desc = self._by_id[wid]
                if best is None or desc.priority > best.priority:
                    best = desc
        return best

    # ---- persistence ------------------------------------------------------------

    def flush(self) -> None:
        """Write the persisted snoozes if anything changed since the last
        write. The snapshot is taken under the lock; the write is not."""
        with self._lock:
            if not self._dirty:
                return
            self._dirty = False
            snapshot = {
                wid: state.dismissed_until
                for wid, state in self._state.items()
                if self._by_id[wid].persisted
                and state.dismissed_until is not None
                and math.isfinite(state.dismissed_until)
            }
        self._store.save(snapshot)
