#!/usr/bin/env python3
"""autostream_webui_common.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Shared helpers for the autostream Web UI.  These are kept separate from
autostream_webui_pages so that other webui modules (e.g. per-page modules)
can import them without pulling in the full page-rendering layer or
creating circular dependencies.

Contents:
  - CONFIG_IO_LOCK / locked_load_config  -- serialise config file I/O across
                                            concurrent HTTP handler threads
  - _set_flash_cookie                    -- write a short-lived status banner
                                            cookie to an HTTP response
  - build_top_banner_html                -- render the top-of-page banner HTML
                                            (flash messages, PSU warnings,
                                            licence state)
  - get_app_version                      -- read the application version string
                                            from the on-disk version file
  - _fallback_input_snapshot             -- construct a zero-valued
                                            InputPlaybackSnapshot from config
                                            when no live snapshot is available
  - _format_reset_date                   -- format a stylus-reset ISO timestamp
                                            as a short "Mon-YY" date string for
                                            compact display (e.g. the About page)
"""

from __future__ import annotations

import html
import threading
from datetime import datetime
from urllib.parse import quote
from typing import Optional

from autostream_auth import FLASH_COOKIE_NAME
from autostream_config import load_config
from autostream_playback import InputPlaybackSnapshot
from autostream_rpi import get_psu_warning_text, cpu_is_licensed, LICENSE_CHECK


# -----------------------------------------------------------------------------
# Thread-safety for ThreadingHTTPServer:
# Protect config file I/O (and coupled owntone.conf edits) from interleaving
# across concurrent requests.
# -----------------------------------------------------------------------------

CONFIG_IO_LOCK = threading.Lock()


def locked_load_config(path: str):
    """Load config under a global lock to avoid reading partial writes."""
    with CONFIG_IO_LOCK:
        return load_config(path)


# -----------------------------------------------------------------------------
# Flash cookie -- short-lived status message passed across a POST/redirect/GET
# cycle (e.g. "Settings saved", "Save failed").
# -----------------------------------------------------------------------------

def _set_flash_cookie(handler, message: str, *, max_age: int = 30) -> None:
    """
    Set a short-lived flash cookie to be consumed (and cleared) on the next GET.
    Stored URL-escaped to keep it cookie-safe.
    """
    val = quote(message, safe="")
    cookie = (
        f"{FLASH_COOKIE_NAME}={val}; Max-Age={max_age}; Path=/; HttpOnly; SameSite=Lax"
    )
    pending = getattr(handler, "_pending_set_cookies", None)
    if pending is None:
        handler._pending_set_cookies = [cookie]
    else:
        pending.append(cookie)


# -----------------------------------------------------------------------------
# Top-of-page banner HTML
# -----------------------------------------------------------------------------

def build_top_banner_html(flash_msg: Optional[str] = None, flash_type: str = "success") -> tuple[str, str]:
    """Returns (banner_html, spacer_html). Handles persistent and flash messages."""

    # Priority 1: User-triggered flash messages (e.g. "Settings saved" / errors)
    if flash_msg:
        banner_id = "green-banner"
        banner_spacer = "green-banner-spacer"
        if flash_type == "error":
            banner_id = "red-banner"
            banner_spacer = "red-banner-spacer"

        return (f"<div id='{banner_id}'>{html.escape(flash_msg)}</div>",
                f"<div id='{banner_spacer}'></div>")

    # Priority 2: System-level PSU warning
    warn = get_psu_warning_text()
    if warn:
        return (f"<div id='red-banner'>{html.escape(warn)}</div>",
                "<div id='red-banner-spacer'></div>")

    # Priority 3: Licensing
    if LICENSE_CHECK and (not cpu_is_licensed()):
        return ("<div id='red-banner'>This system is unlicensed</div>",
                "<div id='red-banner-spacer'></div>")

    return ("", "")


# -----------------------------------------------------------------------------
# Application version
# -----------------------------------------------------------------------------

def get_app_version() -> str:
    """Return the application version string from the on-disk 'version' file.

    The file is expected to be a single line of plain text (e.g. "1.4.2").
    Returns "unknown" if the file is missing or unreadable.
    """
    try:
        with open("version", "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return "unknown"


# -----------------------------------------------------------------------------
# Fallback input snapshot
# -----------------------------------------------------------------------------

def _fallback_input_snapshot(
    parsed_input,
    input_index: int,
    *,
    enabled: bool = True,
) -> InputPlaybackSnapshot:
    """Construct a zero-valued InputPlaybackSnapshot from a parsed config input.

    Used when the live monitor snapshot is unavailable (e.g. the monitor
    process has not yet started, or the input is disabled at config level).
    All playback counters are set to zero; stylus metadata is derived from
    the config so the About page can still render sensible defaults.
    """
    is_turntable = bool(getattr(parsed_input, "is_turntable", False))
    stylus_life_hours = int(getattr(parsed_input, "stylus_life_hours", 500))
    return InputPlaybackSnapshot(
        input_index=input_index,
        label=f"Input {input_index}",
        active=False,
        enabled=bool(enabled),
        is_turntable=is_turntable,
        total_playback_seconds=0,
        total_playback_hours=0.0,
        stylus_playback_seconds=0,
        stylus_playback_hours=0.0,
        stylus_life_hours=stylus_life_hours,
        stylus_remaining_seconds=(stylus_life_hours * 3600 if is_turntable else None),
        stylus_remaining_hours=(float(stylus_life_hours) if is_turntable else None),
        stylus_warning=False,
        stylus_overdue=False,
        last_stylus_reset_at=None,
    )


# -----------------------------------------------------------------------------
# Compact date formatter for the About page stylus panel
# -----------------------------------------------------------------------------

def _format_reset_date(raw: Optional[str]) -> str:
    """Format a stylus-reset ISO timestamp as a compact "Mon-YY" string.

    Used on the About page where horizontal space is limited.  Tries
    ``datetime.fromisoformat`` first (handles the standard ISO 8601 output
    produced by the monitor), then falls back to a manual split-and-map so
    that non-standard or truncated timestamps still render something useful
    rather than exposing a raw exception or the raw string.

    Compare with ``_format_reset_timestamp`` in autostream_webui_pages, which
    produces a locale-aware full date (e.g. "01/23/2024") for use in richer
    playback summary panels.
    """
    if not raw:
        return "Never"
    try:
        dt = datetime.fromisoformat(str(raw))
        try:
            return dt.astimezone().strftime("%b-%y")
        except Exception:
            return dt.strftime("%b-%y")
    except Exception:
        # Manual fallback for non-standard formats (e.g. truncated or
        # space-separated timestamps that fromisoformat cannot parse).
        raw_s = str(raw)
        if "T" in raw_s:
            raw_s = raw_s.split("T", 1)[0]
        parts = raw_s.split("-")
        if len(parts) >= 2:
            year = parts[0][-2:] if len(parts[0]) >= 2 else parts[0]
            month = parts[1]
            month_map = {
                "01": "Jan", "02": "Feb", "03": "Mar", "04": "Apr",
                "05": "May", "06": "Jun", "07": "Jul", "08": "Aug",
                "09": "Sep", "10": "Oct", "11": "Nov", "12": "Dec",
            }
            if month in month_map:
                return f"{month_map[month]}-{year}"
        return raw_s
