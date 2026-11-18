"""autostream_warnings.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

The text table behind the warnings part: what the appliance wants a person to
know, and the words it uses. derive() is a pure function of the inputs the
appliance-state worker gathers, so every row can be tested without hardware.
The words are short enough to fit a small dial panel: a title of at most 40
characters and a message of at most 32, with an optional detail of at most
120 that says why, shown where there is room.

Contents:
  - Inputs    -- everything derive() reads
  - derive    -- the ordered warning entries for one set of inputs
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from autostream_playback_stats import format_hours
from autostream_state import InputsPart, WarningEntry, format_khz
from autostream_sysutils import SD_LEVEL_FAILING, SD_LEVEL_OK, format_day, sd_card_text

if TYPE_CHECKING:
    from autostream_playback_stats import InputPlaybackSnapshot, PlaybackSnapshot

TITLE_MAX = 40
MESSAGE_MAX = 32
DETAIL_MAX = 120
MAX_ENTRIES = 16

_ELLIPSIS = "…"

_SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}
_KIND_ORDER = (
    "psu", "cpu_temp", "sd_health", "stylus", "belt", "bearing",
    "sample_rate", "dial_update", "licence", "no_input",
)


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
    sd_read_at: Optional[str] = None    # when the microSD health was read (ISO 8601)



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


def _entry(id, severity, kind, title, message, link, subject="", detail="") -> WarningEntry:
    return WarningEntry(
        id=id, incident="", severity=severity, kind=kind, subject=subject,
        title=_fit(title, TITLE_MAX), message=_fit(message, MESSAGE_MAX),
        link=link, detail=_fit(detail, DETAIL_MAX),
    )


# ---------------------------------------------------------------------------
# One group of rows per source
# ---------------------------------------------------------------------------

# snapshot item key, title suffix, message when overdue, message when due soon.
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


def _maintenance_detail(snap: "InputPlaybackSnapshot", item: str, state: str) -> str:
    """Why *item* is *state* ("overdue" or "due"): the hours used or left and,
    for a belt or bearing, the time since it was last serviced. It reads the
    same flags _item_state does and never decides whether a row exists."""
    if item == "stylus":
        life = f"{snap.stylus_life_hours} h"
        if state == "overdue":
            text = f"Played {format_hours(snap.stylus_playback_seconds)} of its {life} life."
        elif snap.stylus_remaining_seconds is not None:
            text = f"{format_hours(snap.stylus_remaining_seconds)} left of its {life} life."
        else:
            text = ""
        day = format_day(snap.last_stylus_reset_at)
        return f"{text} Last changed {day}.".strip() if day else text
    parts = []
    hours_overdue = getattr(snap, f"{item}_hours_overdue")
    if hours_overdue or getattr(snap, f"{item}_hours_warning"):
        life = f"{getattr(snap, f'{item}_life_hours')} h"
        left = getattr(snap, f"{item}_hours_remaining")   # seconds
        if hours_overdue or left is None:
            used = format_hours(getattr(snap, f"{item}_playback_seconds"))
            parts.append(f"Played {used} of its {life} service interval.")
        else:
            parts.append(f"{format_hours(left)} left of its {life} service interval.")
    if getattr(snap, f"{item}_time_overdue") or getattr(snap, f"{item}_time_warning"):
        day = format_day(getattr(snap, f"last_{item}_service_at"))
        years = getattr(snap, f"{item}_life_years")
        if day and years > 0:
            parts.append(f"Last serviced {day}, due every {years} year{'' if years == 1 else 's'}.")
    return " ".join(parts)


def _maintenance(playback) -> list[tuple[int, WarningEntry]]:
    out = []
    for index, snap in sorted(playback.inputs.items()):
        for item, suffix, overdue_text, due_text in _MAINTENANCE_ITEMS:
            state = _item_state(snap, item)
            if state is None:
                continue
            title = _title(snap.label, suffix)
            entry_id = f"{item}_in{int(index)}"
            detail = _maintenance_detail(snap, item, state)
            if state == "overdue":
                entry = _entry(entry_id, "warning", item, title, overdue_text,
                               "/service", subject=snap.label, detail=detail)
            else:
                entry = _entry(entry_id, "info", item, title, due_text,
                               "/service", subject=snap.label, detail=detail)
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
            f"/setup#input{e.index}", subject=label,
            detail=f"{label} is running at {format_khz(e.rate_mismatch_hz)}.")))
    return out


def _power(throttled: Optional[int]) -> list[WarningEntry]:
    if throttled is None:
        return []
    if throttled & 0x1:
        return [_entry("psu", "critical", "psu", "Power supply", "Low voltage now", None,
                       detail="The power supply cannot hold the voltage up. "
                              "Use a supply rated for this board.")]
    if (throttled >> 16) & 0x1:
        return [_entry("psu", "warning", "psu", "Power supply", "Low voltage seen", None,
                       detail="Low voltage was seen since the last restart.")]
    return []


def _temperature(status: str, temp_c: Optional[float]) -> list[WarningEntry]:
    if status not in ("high", "critical"):
        return []
    detail = "" if temp_c is None else f"CPU at {round(temp_c)} °C."
    if status == "critical":
        return [_entry("cpu_temp", "critical", "cpu_temp", "CPU temperature",
                       "Too hot", "/about#system", detail=detail)]
    return [_entry("cpu_temp", "warning", "cpu_temp", "CPU temperature",
                   "Running hot", "/about#system", detail=detail)]


def _card(level: str, percent: Optional[int], read_at: Optional[str]) -> list[WarningEntry]:
    if percent is None or level == SD_LEVEL_OK:
        return []
    title, message, detail = sd_card_text(level, percent, read_at)
    severity = "critical" if level == SD_LEVEL_FAILING else "warning"
    return [_entry("sd_health", severity, "sd_health", title, message, "/about#system", detail=detail)]


def _no_input(playback) -> list[WarningEntry]:
    snaps = list(playback.inputs.values())
    if snaps and not any(s.enabled for s in snaps):
        return [_entry("no_input", "info", "no_input", "No input",
                       "Set up an input in the web UI", "/setup")]
    return []


# ---------------------------------------------------------------------------
# The table
# ---------------------------------------------------------------------------

def derive(i: Inputs) -> tuple[WarningEntry, ...]:
    """Every warning for *i*, most severe first, then in kind order, then by
    input; at most MAX_ENTRIES. Every entry's incident is ""."""
    ranked: list[tuple[int, WarningEntry]] = []
    for entry in (*_power(i.throttled), *_temperature(i.cpu_status, i.cpu_temp_c),
                  *_card(i.sd_level, i.sd_percent, i.sd_read_at)):
        ranked.append((0, entry))
    ranked.extend(_maintenance(i.playback))
    ranked.extend(_sample_rates(i))
    if i.dials_needing_update > 0:
        n = i.dials_needing_update
        ranked.append((0, _entry(
            "dial_update", "warning", "dial_update", "Dials",
            "1 needs updating" if n == 1 else f"{n} need updating",
            "/setup#dials",
            detail="Update it from Setup, Dials." if n == 1 else "Update them from Setup, Dials.")))
    if i.unlicensed:
        ranked.append((0, _entry(
            "licence", "warning", "licence", "Licence",
            "This system is unlicensed", None)))
    ranked.extend((0, e) for e in _no_input(i.playback))

    ranked.sort(key=lambda r: (
        _SEVERITY_ORDER[r[1].severity], _KIND_ORDER.index(r[1].kind), r[0]))
    return tuple(e for _, e in ranked[:MAX_ENTRIES])
