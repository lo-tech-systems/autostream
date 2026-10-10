"""autostream_dial_warnings.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

The warnings this appliance reports to dials: stylus, drive belt and main
bearing wear per input, and power supply undervoltage. Each provider turns
live state into DialWarning records in exactly the shape a dial accepts, with
text short enough that the dial never has to truncate it. current_warnings()
is the single entry point; the POST /api/dial/warnings handler serves it, and
the watcher below pushes "warnings changed" to dials when its digest moves.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import time
import unicodedata
from dataclasses import asdict, dataclass
from typing import Callable, Optional

from autostream_dials import dial_proto_generation, get_dial_sighting, parse_dial_entries
from autostream_rpi import get_appliance_id

# Limits a dial applies to what it receives; the text here is built to fit.
WARNINGS_MAX = 8
TITLE_MAX = 40
MESSAGE_MAX = 120

SEVERITY_WARNING = "warning"
SEVERITY_CRITICAL = "critical"
DISMISS_DAY = "day"
DISMISS_WEEK = "week"

_ELLIPSIS = "…"

# Oldest dial protocol generation that has the warnings route.
WARNINGS_MIN_GENERATION = 3

WARNINGS_WATCH_INTERVAL_S = 30.0
WARNINGS_PUSH_MIN_INTERVAL_S = 10.0
WARNINGS_PUSH_PATH = "/warnings-changed"


@dataclass(frozen=True)
class DialWarning:
    id: str
    severity: str
    title: str
    message: str
    dismissal: str


# ---------------------------------------------------------------------------
# Text cleaning
# ---------------------------------------------------------------------------

def clean_display_text(value, limit: int) -> str:
    """*value* as plain display text of at most *limit* characters, or ""
    for anything that is not a string. Control, format, surrogate, private-use
    and unassigned characters are removed, except that white-space controls
    and line separators become a space; runs of spaces collapse, the ends are
    trimmed, and the result is Unicode NFC. The same cleaning a dial applies to
    what it receives."""
    if not isinstance(value, str):
        return ""
    value = value[:limit * 4]
    out = []
    for ch in value:
        category = unicodedata.category(ch)
        if category in ("Zl", "Zp") or (category == "Cc" and ch.isspace()):
            out.append(" ")
        elif category in ("Cc", "Cf", "Cs", "Co", "Cn"):
            continue
        else:
            out.append(ch)
    text = unicodedata.normalize("NFC", "".join(out))
    text = re.sub(r" {2,}", " ", text).strip()
    return text[:limit].rstrip()


def fit_display_text(value, limit: int) -> str:
    """*value* cleaned and, when longer than *limit*, shortened to *limit*
    characters ending in an ellipsis."""
    text = clean_display_text(value, limit + 1)
    if len(text) <= limit:
        return text
    return clean_display_text(text, limit - 1) + _ELLIPSIS


def _title(label, suffix: str) -> str:
    """"<label> <suffix>" within TITLE_MAX, shortening only the label."""
    room = TITLE_MAX - len(suffix) - 1
    label_text = fit_display_text(label, room)
    return f"{label_text} {suffix}" if label_text else suffix.capitalize()


# ---------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------

# snapshot item key, title suffix, message when overdue, message when due
# soon (the stylus adds the hours left). Kept short: a dial's warning card
# shows about one line of message.
_MAINTENANCE_ITEMS = (
    ("stylus", "stylus", "Change now", "Change soon"),
    ("belt", "drive belt", "Service now", "Service soon"),
    ("bearing", "main bearing", "Service now", "Service soon"),
)


def _item_state(snap, item: str) -> Optional[str]:
    """"overdue", "warning" or None for one item of one input, under the
    same conditions the WebUI banners use."""
    if not snap.enabled:
        return None
    if item == "stylus" and snap.stylus_life_hours <= 0:
        return None
    if getattr(snap, f"{item}_overdue"):
        return "overdue"
    if getattr(snap, f"{item}_warning"):
        return "warning"
    return None


def _maintenance_warnings() -> list[DialWarning]:
    from autostream_core import get_playback_snapshot

    snapshot = get_playback_snapshot()
    overdue: list[DialWarning] = []
    due: list[DialWarning] = []
    for index, snap in sorted(snapshot.inputs.items()):
        for item, suffix, overdue_text, due_text in _MAINTENANCE_ITEMS:
            state = _item_state(snap, item)
            if state is None:
                continue
            title = _title(snap.label, suffix)
            warning_id = f"{item}_in{int(index)}"
            if state == "overdue":
                overdue.append(DialWarning(
                    warning_id, SEVERITY_CRITICAL, title, overdue_text, DISMISS_DAY))
                continue
            message = due_text
            if item == "stylus" and snap.stylus_remaining_hours is not None:
                message = f"{due_text}, {snap.stylus_remaining_hours:.1f} h left"
            due.append(DialWarning(warning_id, SEVERITY_WARNING, title, message, DISMISS_WEEK))
    return overdue + due


def _psu_warnings() -> list[DialWarning]:
    from autostream_system_stats import _parse_throttled_mask, _read_get_throttled_value

    throttled = _read_get_throttled_value()
    if throttled is None:
        return []
    current, historic = _parse_throttled_mask(throttled)
    if current & 0x1:
        return [DialWarning(
            "psu", SEVERITY_CRITICAL, "Power supply",
            "Low voltage now", DISMISS_DAY)]
    if historic & 0x1:
        return [DialWarning(
            "psu", SEVERITY_WARNING, "Power supply",
            "Low voltage seen earlier", DISMISS_WEEK)]
    return []


WARNING_PROVIDERS: tuple[Callable[[], list[DialWarning]], ...] = (
    _maintenance_warnings,
    _psu_warnings,
)


def current_warnings() -> list[DialWarning]:
    """Every provider's warnings in provider order, at most WARNINGS_MAX, with
    unique ids and display-clean text. A provider that fails contributes
    nothing."""
    out: list[DialWarning] = []
    seen: set[str] = set()
    for provider in WARNING_PROVIDERS:
        try:
            produced = provider()
        except Exception:
            logging.debug("dial warnings: provider %s failed",
                          getattr(provider, "__name__", "?"), exc_info=True)
            continue
        for w in produced:
            if len(out) >= WARNINGS_MAX:
                return out
            if w.id in seen:
                continue
            title = fit_display_text(w.title, TITLE_MAX)
            if not title:
                continue
            seen.add(w.id)
            out.append(DialWarning(
                w.id, w.severity, title, fit_display_text(w.message, MESSAGE_MAX), w.dismissal))
    return out


def warnings_payload(warnings) -> list[dict]:
    return [asdict(w) for w in warnings]


def warnings_digest(warnings) -> str:
    """A stable hash of *warnings*, for noticing that the set changed."""
    blob = json.dumps(warnings_payload(warnings), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Change watcher and push
# ---------------------------------------------------------------------------

def notify_dials_warnings_changed() -> None:
    """Queue one "warnings changed" push to every authorised dial that is
    currently sighted and speaks a protocol generation with the warnings
    route. Never raises; a no-op when this appliance has no identity."""
    try:
        appliance_id = get_appliance_id()
        if not appliance_id:
            return
        from autostream_webui_dials import enqueue_push

        for entry in parse_dial_entries():
            sighting = get_dial_sighting(entry.uuid)
            if sighting is None:
                continue
            if dial_proto_generation(sighting.dial_proto) < WARNINGS_MIN_GENERATION:
                continue
            enqueue_push(WARNINGS_PUSH_PATH, entry.uuid, appliance_id)
    except Exception:
        logging.debug("dial warnings: push enqueue failed", exc_info=True)


class WarningsWatcher:
    """Notices when the warning set changes and pushes at most once per
    min_interval_s. A change inside that window is pushed when it ends,
    carrying whatever the set is by then, so a burst of changes is one push
    and a change that reverts inside the window is none."""

    def __init__(
        self,
        *,
        digest: Callable[[], str],
        notify: Callable[[], None],
        clock: Callable[[], float] = time.monotonic,
        watch_interval_s: float = WARNINGS_WATCH_INTERVAL_S,
        min_interval_s: float = WARNINGS_PUSH_MIN_INTERVAL_S,
    ) -> None:
        self._digest = digest
        self._notify = notify
        self._clock = clock
        self._watch_interval_s = watch_interval_s
        self._min_interval_s = min_interval_s
        self._pushed_digest: Optional[str] = None
        self._last_push_at: Optional[float] = None
        self._pending = False

    def step(self) -> float:
        """One check; returns how long to wait before the next."""
        now = self._clock()
        digest = self._digest()
        if self._pushed_digest is None:
            # The first reading is the baseline: a dial fetches the list
            # itself when it first meets the appliance.
            self._pushed_digest = digest
        self._pending = digest != self._pushed_digest
        if self._pending:
            if self._last_push_at is None or now - self._last_push_at >= self._min_interval_s:
                self._pushed_digest = digest
                self._last_push_at = now
                self._pending = False
                self._notify()
            else:
                return max(0.05, self._last_push_at + self._min_interval_s - now)
        return self._watch_interval_s


_poke_event = threading.Event()
_watcher_lock = threading.Lock()
_watcher_thread: Optional[threading.Thread] = None


def poke() -> None:
    """Ask the watcher to check now, so a change made through the WebUI
    reaches dials within a second rather than a watch interval."""
    _poke_event.set()


def _current_digest() -> str:
    return warnings_digest(current_warnings())


def _watch_loop(watcher: WarningsWatcher, shutdown_event) -> None:
    while shutdown_event is None or not shutdown_event.is_set():
        try:
            wait = watcher.step()
        except Exception:
            logging.debug("dial warnings: watcher step failed", exc_info=True)
            wait = WARNINGS_WATCH_INTERVAL_S
        _poke_event.wait(wait)
        _poke_event.clear()


def start_watcher(shutdown_event: "threading.Event | None" = None) -> None:
    """Start the digest watcher thread. Idempotent."""
    global _watcher_thread
    with _watcher_lock:
        if _watcher_thread is not None and _watcher_thread.is_alive():
            return
        watcher = WarningsWatcher(digest=_current_digest, notify=notify_dials_warnings_changed)
        _watcher_thread = threading.Thread(
            target=_watch_loop, args=(watcher, shutdown_event),
            daemon=True, name="dial-warnings-watch",
        )
        _watcher_thread.start()
