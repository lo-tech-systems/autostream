#!/usr/bin/env python3
"""autostream_webui_service_schema.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Shared domain logic for the Service page and its JSON API endpoints.

Shared display-computation helpers for the Service page and its live JSON API.
The initial HTML render and the live update payloads call the same functions so
the browser always sees consistent maintenance state regardless of how data arrives.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from autostream_config import (
    VALID_BEARING_LIFE_HOURS,
    VALID_MAINTENANCE_LIFE_HOURS,
    VALID_MAINTENANCE_LIFE_YEARS,
    VALID_STYLUS_LIFE_HOURS,
    normalize_bearing_life_hours,
    normalize_maintenance_life_hours,
    normalize_maintenance_life_years,
    normalize_stylus_life_hours,
)
from autostream_playback_stats import InputPlaybackSnapshot, format_hours


# -----------------------------------------------------------------------------
# Service-item schema
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class _ServiceItem:
    """Metadata for one maintenance tracking dimension.

    Drives both the page selector widgets and the _SERVICE_FIELD_MAP generated
    in autostream_webui_api.  Add a new item here and it appears everywhere
    automatically — no parallel hard-coded strings required.
    """

    key: str                             # "stylus" | "belt" | "bearing"
    card_title: str                      # label shown on the overview list card
    hours_config_key: str                # INI key, e.g. "stylus_life_hours"
    hours_options: tuple                 # allowed hour values for the selector
    hours_normalizer: object             # callable: str -> int
    years_config_key: Optional[str]      # INI key, or None (stylus has no time dim)
    years_normalizer: Optional[object]   # callable: str -> int, or None


_SERVICE_ITEMS: tuple[_ServiceItem, ...] = (
    _ServiceItem(
        key="stylus",
        card_title="Stylus Tracking",
        hours_config_key="stylus_life_hours",
        hours_options=VALID_STYLUS_LIFE_HOURS,
        hours_normalizer=normalize_stylus_life_hours,
        years_config_key=None,
        years_normalizer=None,
    ),
    _ServiceItem(
        key="belt",
        card_title="Belt Tracking",
        hours_config_key="belt_life_hours",
        hours_options=VALID_MAINTENANCE_LIFE_HOURS,
        hours_normalizer=normalize_maintenance_life_hours,
        years_config_key="belt_life_years",
        years_normalizer=normalize_maintenance_life_years,
    ),
    _ServiceItem(
        key="bearing",
        card_title="Bearing Oil Tracking",
        hours_config_key="bearing_life_hours",
        hours_options=VALID_BEARING_LIFE_HOURS,
        hours_normalizer=normalize_bearing_life_hours,
        years_config_key="bearing_life_years",
        years_normalizer=normalize_maintenance_life_years,
    ),
)


# -----------------------------------------------------------------------------
# Snapshot attribute lookup tables
# -----------------------------------------------------------------------------

# item key → snapshot attribute name for playback seconds since last service reset
_SNAP_HOURS_PLAYBACK_ATTR: dict[str, str] = {
    "stylus":  "stylus_playback_seconds",
    "belt":    "belt_playback_seconds",
    "bearing": "bearing_playback_seconds",
}

# item key → (elapsed_days attr, last_service_at attr)
# stylus is absent: it has no time dimension
_SNAP_TIME_ATTRS: dict[str, tuple[str, str]] = {
    "belt":    ("belt_elapsed_days",    "last_belt_service_at"),
    "bearing": ("bearing_elapsed_days", "last_bearing_service_at"),
}


# -----------------------------------------------------------------------------
# Formatting helpers
# -----------------------------------------------------------------------------

def _format_reset_timestamp(raw: Optional[str]) -> str:
    """Format a service ISO timestamp as a locale short date (e.g. 01/23/2025).

    Returns "Never" if raw is absent.  Used by both the initial page render and
    the reset API response so the date string is always consistent.
    """
    if not raw:
        return "Never"
    try:
        dt = datetime.fromisoformat(str(raw))
        try:
            return dt.astimezone().strftime("%x")
        except Exception:
            return dt.strftime("%x")
    except Exception:
        return str(raw)


def _format_elapsed_days(days: Optional[int]) -> str:
    """Return a human-readable elapsed time string from a day count.

    Used for the Remaining label in the time-dimension live section.

    Bands:
      0          → "Today"
      1–29 days  → "<N> day(s)"
      30–730 days → "<N> month(s)"
      > 730 days  → "<N> year(s)"
    """
    if days is None:
        return "Unknown"
    if days == 0:
        return "Today"
    if days < 30:
        return f"{days} day{'s' if days != 1 else ''}"
    if days > 730:
        years = days // 365
        return f"{years} year{'s' if years != 1 else ''}"
    months = days // 30
    return f"{months} month{'s' if months != 1 else ''}"


def _format_age_months(days: Optional[int]) -> str:
    """Return a month count string for the maintenance Age row."""
    if days is None:
        return "Unknown"
    months = days // 30
    return f"{months} month{'s' if months != 1 else ''}"


def _format_due_date(service_at: Optional[str], life_years: int) -> str:
    """Return an approximate due date from a service timestamp and a year threshold."""
    if not service_at or life_years <= 0:
        return "Unknown"
    try:
        dt = datetime.fromisoformat(str(service_at))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        due = dt + timedelta(days=life_years * 365)
        try:
            return due.astimezone().strftime("%x")
        except Exception:
            return due.strftime("%x")
    except Exception:
        return "Unknown"


# -----------------------------------------------------------------------------
# Display-dict helpers
#
# These are the single source of truth for all display calculations.  Both the
# initial HTML render (autostream_webui_page_service) and the live JSON update
# payloads (autostream_webui_api) call these functions so the displayed values
# are always identical, regardless of how the data reaches the browser.
#
# All dicts always contain the full set of keys so callers never need .get()
# fallbacks.  The `hours_live` / `time_live` bool is the discriminator: when
# False the tracker is off and the detail section should be hidden.
# -----------------------------------------------------------------------------

def _hours_display(item: str, life_hours: int, snap: InputPlaybackSnapshot) -> dict:
    """Compute the hours-dimension display dict for one maintenance item / input.

    Keys: hours_live, hours_bar_pct, hours_bar_status, hours_used,
          hours_remaining, hours_remaining_warn.

    Threshold: remaining ≤ 20 % → warning colour; ≤ 10 % → critical bar status.
    When life_hours == 0 (tracking off) returns hours_live: False with neutral
    placeholder values so callers never need to branch on missing keys.
    """
    ps_attr = _SNAP_HOURS_PLAYBACK_ATTR.get(item, "stylus_playback_seconds")
    playback_seconds = int(getattr(snap, ps_attr, 0) or 0)

    if life_hours == 0:
        return {
            "hours_live":           False,
            "hours_bar_pct":        "100.0",
            "hours_bar_status":     "healthy",
            "hours_used":           f"{format_hours(playback_seconds)} / 0 h",
            "hours_remaining":      "",
            "hours_remaining_warn": False,
        }

    rem_secs   = max(0, (life_hours * 3600) - playback_seconds)
    rem_pct    = min(100.0, (rem_secs / max(1, life_hours * 3600)) * 100.0)
    bar_status = "critical" if rem_pct <= 10.0 else ("warning" if rem_pct <= 20.0 else "healthy")

    return {
        "hours_live":           True,
        "hours_bar_pct":        f"{rem_pct:.1f}",
        "hours_bar_status":     bar_status,
        "hours_used":           f"{format_hours(playback_seconds)} / {life_hours} h",
        "hours_remaining":      "Due now" if rem_secs <= 0 else format_hours(rem_secs),
        "hours_remaining_warn": rem_pct <= 20.0,
    }


def _time_display(item: str, life_years: int, snap: InputPlaybackSnapshot) -> dict:
    """Compute the time-dimension display dict for one maintenance item / input.

    Keys: time_live, time_bar_pct, time_bar_status, age, remaining,
          remaining_warn, due.

    Returns time_live: False for items without a time dimension (stylus) or when
    life_years == 0 (tracking off).  Placeholder values are provided for all keys
    so callers never need to branch on missing keys.

    Threshold: remaining ≤ 20 % → warning colour; ≤ 10 % → critical bar status.
    """
    if item not in _SNAP_TIME_ATTRS or life_years == 0:
        return {
            "time_live":      False,
            "time_bar_pct":   "100.0",
            "time_bar_status": "healthy",
            "age":            "N/A",
            "remaining":      "N/A",
            "remaining_warn": False,
            "due":            "N/A",
        }

    ed_attr, svc_attr = _SNAP_TIME_ATTRS[item]
    elapsed_days    = getattr(snap, ed_attr,  None)
    last_service_at = getattr(snap, svc_attr, None)

    if elapsed_days is not None:
        total_days      = life_years * 365
        rem_days        = max(0, total_days - elapsed_days)
        time_rem_pct    = min(100.0, (rem_days / max(1, total_days)) * 100.0)
        time_bar_status = "critical" if time_rem_pct <= 10.0 else ("warning" if time_rem_pct <= 20.0 else "healthy")
        age             = _format_age_months(elapsed_days)
        due             = _format_due_date(last_service_at, life_years)
        remaining       = "Overdue" if rem_days == 0 else _format_elapsed_days(rem_days) + " remaining"
        warn            = time_rem_pct <= 20.0
    else:
        time_rem_pct    = 100.0
        time_bar_status = "healthy"
        age             = "Not recorded"
        due             = "Not set"
        remaining       = f"{life_years} year{'s' if life_years != 1 else ''} remaining"
        warn            = False

    return {
        "time_live":       True,
        "time_bar_pct":    f"{time_rem_pct:.1f}",
        "time_bar_status": time_bar_status,
        "age":             age,
        "remaining":       remaining,
        "remaining_warn":  warn,
        "due":             due,
    }


def _card_display(
    item: str,
    hd: dict,
    td: dict,
    is_turntable: bool,
) -> dict:
    """Compute list-card subtitle and warning flag from pre-computed display dicts.

    Takes the already-computed _hours_display and _time_display results so card
    state is always derived from the same values as the detail panel — no
    separate calculation path.

    Keys: card_sub (str), card_warn (bool).
    """
    if not is_turntable:
        return {"card_sub": "Not a turntable", "card_warn": False}

    hours_live = hd["hours_live"]
    time_live  = td["time_live"]

    if not hours_live and not time_live:
        return {"card_sub": "Tracking off", "card_warn": False}

    hours_overdue = hours_live and hd["hours_remaining"] == "Due now"
    hours_warn    = hours_live and hd["hours_remaining_warn"]
    time_overdue  = time_live  and td["remaining"] == "Overdue"
    time_warn     = time_live  and td["remaining_warn"]

    overdue = hours_overdue or time_overdue
    warn    = hours_warn    or time_warn   # True whenever overdue too

    if overdue:
        sub = "Stylus due now" if item == "stylus" else "Service due now"
    elif warn:
        if item == "stylus":
            rem = hd["hours_remaining"]
            sub = f"Stylus due soon ({rem} left)"
        else:
            sub = "Service due soon"
    else:
        sub = "Tracking on"

    return {"card_sub": sub, "card_warn": warn}
