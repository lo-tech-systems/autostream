"""autostream_warnings.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

The text table behind the warnings part: what the appliance wants a person to
know, and the words it uses. derive() is a pure function of the inputs the
appliance-state worker gathers, so every row can be tested without hardware.
The words are short enough to fit a small dial panel: a title of at most 40
characters and a message of at most 32.

Contents:
  - Inputs    -- everything derive() reads
  - derive    -- the ordered warning entries for one set of inputs
  - sd_level  -- the held microSD wear level (hysteresis)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from autostream_state import InputsPart, WarningEntry

if TYPE_CHECKING:
    from autostream_playback_stats import InputPlaybackSnapshot, PlaybackSnapshot

TITLE_MAX = 40
MESSAGE_MAX = 32
MAX_ENTRIES = 16

_ELLIPSIS = "…"

_SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}
_KIND_ORDER = (
    "psu", "cpu_temp", "sd_health", "stylus", "belt", "bearing",
    "sample_rate", "dial_update", "licence", "no_input",
)

# The microSD card's life-left thresholds in percent: a level is entered below
# the first figure and left above the second.
_SD_FAILING = (10, 15)
_SD_LOW = (20, 25)


@dataclass(frozen=True)
class Inputs:
    playback: "PlaybackSnapshot"
    inputs: InputsPart
    throttled: Optional[int]
    cpu_temp_c: Optional[float]
    cpu_status: str                     # "ok" | "high" | "critical"
    sd_percent: Optional[int]
    sd_level: str                       # "ok" | "low" | "failing"
    dials_needing_update: int
    unlicensed: bool


def sd_level(percent: Optional[int], previous: str = "ok") -> str:
    """The microSD wear level for a life-left percentage: "failing" below 10 %
    until above 15 %, "low" below 20 % until above 25 %, else "ok". Unknown is
    "ok". *previous* is the level held from the last reading."""
    if percent is None:
        return "ok"
    if percent < _SD_FAILING[0] or (previous == "failing" and percent <= _SD_FAILING[1]):
        return "failing"
    if percent < _SD_LOW[0] or (previous in ("low", "failing") and percent <= _SD_LOW[1]):
        return "low"
    return "ok"


def _fit(text, limit: int) -> str:
    """*text* on one line, shortened to *limit* characters ending in an
    ellipsis when it is longer."""
    out = " ".join(str(text or "").split())
    return out if len(out) <= limit else out[:limit - 1].rstrip() + _ELLIPSIS


def _title(label: str, suffix: str) -> str:
    """"<label> <suffix>" within TITLE_MAX, shortening only the label."""
    room = TITLE_MAX - len(suffix) - 1
    label_text = _fit(label, room)
    return f"{label_text} {suffix}" if label_text else suffix.capitalize()


def _entry(id, severity, kind, title, message, link, snooze, subject="") -> WarningEntry:
    return WarningEntry(
        id=id, incident="", severity=severity, kind=kind, subject=subject,
        title=_fit(title, TITLE_MAX), message=_fit(message, MESSAGE_MAX),
        link=link, snooze=snooze,
    )


# ---------------------------------------------------------------------------
# One group of rows per source
# ---------------------------------------------------------------------------

# snapshot item key, title suffix, message when overdue, message when due soon
# (the stylus adds the hours left).
_MAINTENANCE_ITEMS = (
    ("stylus", "stylus", "Change now", "Change soon"),
    ("belt", "drive belt", "Service now", "Service soon"),
    ("bearing", "main bearing", "Service now", "Service soon"),
)


def _item_state(snap: "InputPlaybackSnapshot", item: str) -> Optional[str]:
    """"overdue", "due" or None for one item of one input."""
    if not snap.enabled:
        return None
    if item == "stylus" and snap.stylus_life_hours <= 0:
        return None
    if getattr(snap, f"{item}_overdue"):
        return "overdue"
    if getattr(snap, f"{item}_warning"):
        return "due"
    return None


def _maintenance(playback) -> list[tuple[int, WarningEntry]]:
    out = []
    for index, snap in sorted(playback.inputs.items()):
        for item, suffix, overdue_text, due_text in _MAINTENANCE_ITEMS:
            state = _item_state(snap, item)
            if state is None:
                continue
            title = _title(snap.label, suffix)
            entry_id = f"{item}_in{int(index)}"
            if state == "overdue":
                entry = _entry(entry_id, "warning", item, title, overdue_text,
                               "/service", "day", subject=snap.label)
            else:
                message = due_text
                if item == "stylus" and snap.stylus_remaining_hours is not None:
                    message = f"{due_text}, {snap.stylus_remaining_hours:.1f} h left"
                entry = _entry(entry_id, "info", item, title, message,
                               "/service", "week", subject=snap.label)
            out.append((int(index), entry))
    return out


def _sample_rates(i: Inputs) -> list[tuple[int, WarningEntry]]:
    out = []
    for e in i.inputs.entries:
        if e.rate_mismatch_hz <= 0:
            continue
        snap = i.playback.inputs.get(e.index)
        label = snap.label if snap is not None else f"Input {e.index}"
        out.append((e.index, _entry(
            f"sample_rate_in{e.index}", "warning", "sample_rate",
            _title(label, "sample rate"), "Turn on rate matching",
            f"/setup#input{e.index}", "week", subject=label)))
    return out


def _power(throttled: Optional[int]) -> list[WarningEntry]:
    if throttled is None:
        return []
    if throttled & 0x1:
        return [_entry("psu", "critical", "psu", "Power supply",
                       "Low voltage now", None, "day")]
    if (throttled >> 16) & 0x1:
        return [_entry("psu", "warning", "psu", "Power supply",
                       "Low voltage seen earlier", None, "week")]
    return []


def _temperature(status: str, temp_c: Optional[float]) -> list[WarningEntry]:
    if status not in ("high", "critical"):
        return []
    degrees = "" if temp_c is None else f", {round(temp_c)} °C"
    if status == "critical":
        return [_entry("cpu_temp", "critical", "cpu_temp", "CPU temperature",
                       f"Too hot{degrees}", None, "day")]
    return [_entry("cpu_temp", "warning", "cpu_temp", "CPU temperature",
                   f"Running hot{degrees}", None, "day")]


def _card(level: str, percent: Optional[int]) -> list[WarningEntry]:
    if percent is None or level == "ok":
        return []
    if level == "failing":
        return [_entry("sd_health", "critical", "sd_health", "microSD card",
                       f"{percent}% life left, replace now", "/about", "day")]
    return [_entry("sd_health", "warning", "sd_health", "microSD card",
                   f"{percent}% life left, replace soon", "/about", "week")]


def _no_input(playback) -> list[WarningEntry]:
    snaps = list(playback.inputs.values())
    if snaps and not any(s.enabled for s in snaps):
        return [_entry("no_input", "info", "no_input", "No input",
                       "Set up an input in the web UI", "/setup", "week")]
    return []


# ---------------------------------------------------------------------------
# The table
# ---------------------------------------------------------------------------

def derive(i: Inputs) -> tuple[WarningEntry, ...]:
    """Every warning for *i*, most severe first, then in kind order, then by
    input; at most MAX_ENTRIES. Every entry's incident is ""."""
    ranked: list[tuple[int, WarningEntry]] = []
    for entry in (*_power(i.throttled), *_temperature(i.cpu_status, i.cpu_temp_c),
                  *_card(i.sd_level, i.sd_percent)):
        ranked.append((0, entry))
    ranked.extend(_maintenance(i.playback))
    ranked.extend(_sample_rates(i))
    if i.dials_needing_update > 0:
        n = i.dials_needing_update
        ranked.append((0, _entry(
            "dial_update", "warning", "dial_update", "Dials",
            "1 needs updating" if n == 1 else f"{n} need updating",
            "/setup#dials", "week")))
    if i.unlicensed:
        ranked.append((0, _entry(
            "licence", "warning", "licence", "Licence",
            "This system is unlicensed", None, "none")))
    ranked.extend((0, e) for e in _no_input(i.playback))

    ranked.sort(key=lambda r: (
        _SEVERITY_ORDER[r[1].severity], _KIND_ORDER.index(r[1].kind), r[0]))
    return tuple(e for _, e in ranked[:MAX_ENTRIES])
