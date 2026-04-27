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
  - build_nav_bar_html                   -- render the shared fixed bottom
                                            navigation bar (Home/Setup/Logs/About)
  - build_page_html                      -- render a complete HTML page using the
                                            shared scaffold (head, container, nav)
  - get_app_version                      -- read the installed application
                                            version via the privileged helper
  - _fallback_input_snapshot             -- construct a zero-valued
                                            InputPlaybackSnapshot from config
                                            when no live snapshot is available
  - _format_reset_date                   -- format a stylus-reset ISO timestamp
                                            as a short "Mon-YY" date string for
                                            compact display (e.g. the About page)
  - load_license_text                    -- read the LICENSE / LICENCE file
  - render_license_md                    -- convert LICENSE Markdown to HTML
"""

from __future__ import annotations

import html
import json
import re
import subprocess
from datetime import datetime
from urllib.parse import quote
from typing import Optional

from autostream_auth import FLASH_COOKIE_NAME
from autostream_config import CONFIG_IO_LOCK, DEFAULT_STYLUS_LIFE_HOURS, load_config
from autostream_playback_stats import InputPlaybackSnapshot
from autostream_rpi import get_psu_warning_text, cpu_is_licensed, LICENSE_CHECK
from autostream_webui_assets import (
    BANNER_HTML,
    NAV_ICON_ABOUT,
    NAV_ICON_HOME,
    NAV_ICON_SERVICE,
    NAV_ICON_SETUP,
    STYLE_CSS,
    VIEWPORT_META,
)


def locked_load_config(path: str):
    """Load config under a global lock to avoid reading partial writes."""
    with CONFIG_IO_LOCK:
        return load_config(path)


# -----------------------------------------------------------------------------
# Flash cookie -- short-lived status message passed across a POST/redirect/GET
# cycle (e.g. "Settings saved", "Save failed").
# -----------------------------------------------------------------------------

def _set_flash_cookie(handler, message: str, *, max_age: int = 30, flash_type: str = "success") -> None:
    """
    Set a short-lived flash cookie to be consumed (and cleared) on the next GET.
    Stored URL-escaped to keep it cookie-safe.
    Non-success types are encoded as a '<type>:' prefix so the reader can
    reconstruct the correct banner colour without a separate cookie.
    """
    encoded = (f"{flash_type}:{message}") if flash_type != "success" else message
    val = quote(encoded, safe="")
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

# Cached on first call; immutable for the process lifetime since an update
# always triggers a full process restart.
_app_version_cache: Optional[str] = None


def get_app_version() -> str:
    """Return the installed application version via the privileged helper.

    The result is cached in memory after the first call. Because applying an
    update always restarts the process, the version cannot change while the
    process is running.
    """
    global _app_version_cache
    if _app_version_cache is not None:
        return _app_version_cache

    cmd = [
        "/usr/bin/sudo",
        "-n",
        "/usr/local/libexec/autostream/autostream_admin",
        "version-info",
    ]
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
            check=False,
        )
    except Exception:
        return "unknown"

    if p.returncode != 0:
        return "unknown"

    try:
        payload = json.loads(p.stdout or "{}")
    except Exception:
        return "unknown"

    version = str(payload.get("release_tag") or "").strip()
    _app_version_cache = version or "unknown"
    return _app_version_cache


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
    stylus_life_hours = int(getattr(parsed_input, "stylus_life_hours", DEFAULT_STYLUS_LIFE_HOURS))
    belt_life_hours = int(getattr(parsed_input, "belt_life_hours", 0))
    belt_life_years = int(getattr(parsed_input, "belt_life_years", 0))
    bearing_life_hours = int(getattr(parsed_input, "bearing_life_hours", 0))
    bearing_life_years = int(getattr(parsed_input, "bearing_life_years", 0))
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
        belt_life_hours=belt_life_hours,
        belt_playback_seconds=0,
        belt_playback_hours=0.0,
        belt_hours_remaining=(
            belt_life_hours * 3600 if is_turntable and belt_life_hours > 0 else None
        ),
        belt_hours_overdue=False,
        belt_hours_warning=False,
        belt_life_years=belt_life_years,
        belt_elapsed_days=None,
        belt_time_overdue=False,
        belt_time_warning=False,
        belt_overdue=False,
        belt_warning=False,
        last_belt_service_at=None,
        bearing_life_hours=bearing_life_hours,
        bearing_playback_seconds=0,
        bearing_playback_hours=0.0,
        bearing_hours_remaining=(
            bearing_life_hours * 3600 if is_turntable and bearing_life_hours > 0 else None
        ),
        bearing_hours_overdue=False,
        bearing_hours_warning=False,
        bearing_life_years=bearing_life_years,
        bearing_elapsed_days=None,
        bearing_time_overdue=False,
        bearing_time_warning=False,
        bearing_overdue=False,
        bearing_warning=False,
        last_bearing_service_at=None,
    )


# -----------------------------------------------------------------------------
# Compact date formatter for the About page stylus panel
# -----------------------------------------------------------------------------

def build_nav_bar_html(active: str = "", *, service_warn: bool = False) -> str:
    """Return the fixed bottom navigation bar HTML.

    active:       one of 'home', 'setup', 'service', 'about'
    service_warn: when True the Service tab is styled red (e.g. stylus overdue)
    """
    tabs = [
        ("home",    "/",        "Home",    NAV_ICON_HOME,    ""),
        ("setup",   "/setup",   "Setup",   NAV_ICON_SETUP,   ""),
        ("service", "/service", "Service", NAV_ICON_SERVICE, ' id="service-nav-tab"'),
        ("about",   "/about",   "Info",    NAV_ICON_ABOUT,   ""),
    ]
    items = []
    for key, href, label, icon, extra_attrs in tabs:
        classes = ["nav-tab"]
        if key == active:
            classes.append("nav-tab-active")
        cls = " ".join(classes)
        items.append(
            f'<a href="{href}" class="{cls}"{extra_attrs}>{icon}<span>{label}</span></a>'
        )
    return '<nav class="bottom-nav">' + "".join(items) + "</nav>"


def build_page_html(
    title: str,
    body_html: str,
    *,
    extra_css: str = "",
    head_extra: str = "",
    body_prefix: str = "",
    body_suffix: str = "",
    lic_html: str = "",
    lic_spacer: str = "",
    active_tab: str = "",
    show_nav: bool = True,
    service_warn: bool = False,
    dark_mode: bool = False,
) -> str:
    """Render a complete HTML page using the shared scaffold.

    Parameters
    ----------
    title       : page <title> (plain text, will be HTML-escaped)
    body_html   : content placed inside <div class="container"> after the
                  opening tag; callers are responsible for including BANNER_HTML
                  where needed
    extra_css   : CSS appended to STYLE_CSS inside the <style> block
    head_extra  : raw HTML injected after </style> and before </head>
                  (e.g. csrf_meta, page-specific <script> blocks)
    body_prefix : raw HTML injected after <body> and before <div class="container">
                  (e.g. modal dialogs, overlay divs)
    body_suffix : raw HTML injected after the closing </div> of .container and
                  before the nav bar (e.g. scripts, A2HS_SCRIPT)
    lic_html    : from build_top_banner_html() — the fixed flash/PSU banner
    lic_spacer  : from build_top_banner_html() — the spacer div
    active_tab   : one of 'home', 'setup', 'service', 'about'; selects the
                   active nav bar tab
    show_nav     : when False the nav bar is omitted (e.g. initial-setup wizard)
    service_warn : when True the Service tab is highlighted red
    dark_mode    : when True the dark colour theme is applied via data-theme="dark"
    """
    style = STYLE_CSS + ("\n" + extra_css.strip() if extra_css.strip() else "")
    nav = build_nav_bar_html(active_tab, service_warn=service_warn) if show_nav else ""
    body_cls = ' class="has-bottom-nav"' if show_nav else ""
    theme_attr = ' data-theme="dark"' if dark_mode else ' data-theme="light"'
    return (
        f'<!DOCTYPE html><html{theme_attr}>'
        f'<head><meta charset="utf-8">{VIEWPORT_META}'
        f'<title>{html.escape(title)}</title>'
        f'<style>{style}</style>'
        f'{head_extra}'
        f'</head>'
        f'<body{body_cls}>{lic_html}{lic_spacer}'
        f'{body_prefix}'
        f'<div class="container">'
        f'{body_html}'
        f'</div>'
        f'{body_suffix}'
        f'{nav}'
        f'</body></html>'
    )


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


# -----------------------------------------------------------------------------
# License text helpers (used by the About page)
# -----------------------------------------------------------------------------

_URL_RE = re.compile(r'(https?://[^\s<>"]+)')


def load_license_text() -> str:
    """Read the LICENSE / LICENCE file from the working directory."""
    for fname in ("LICENCE", "LICENSE"):
        try:
            with open(fname, "r", encoding="utf-8") as f:
                text = f.read().strip()
            if text:
                return text
        except (FileNotFoundError, Exception):
            continue
    return ""


def render_license_md(text: str) -> str:
    """Convert the limited Markdown used in the LICENSE file to HTML.

    Handles: # H1 (rendered as h2), ### H3, --- hr, * list items,
    bare URLs, and plain paragraphs.
    """
    def _autolink(s: str) -> str:
        return _URL_RE.sub(
            lambda m: (
                f'<a href="{m.group(1)}" target="_blank" rel="noopener noreferrer">'
                f'{m.group(1)}</a>'
            ), s
        )

    lines = text.splitlines()
    out: list[str] = []
    in_ul = False
    pending: list[str] = []

    def flush_para() -> None:
        nonlocal pending
        if pending:
            out.append(f"<p>{_autolink(' '.join(pending))}</p>")
            pending = []

    def close_ul() -> None:
        nonlocal in_ul
        if in_ul:
            out.append("</ul>")
            in_ul = False

    for line in lines:
        if line.startswith("# "):
            close_ul(); flush_para()
            out.append(f"<h2>{html.escape(line[2:].strip())}</h2>")
        elif line.startswith("### "):
            close_ul(); flush_para()
            out.append(f"<h3>{html.escape(line[4:].strip())}</h3>")
        elif line.strip() == "---":
            close_ul(); flush_para()
            out.append("<hr>")
        elif line.startswith("* "):
            flush_para()
            if not in_ul:
                out.append("<ul>")
                in_ul = True
            out.append(f"<li>{html.escape(line[2:].strip())}</li>")
        elif not line.strip():
            close_ul(); flush_para()
        else:
            close_ul()
            pending.append(html.escape(line.strip()))

    close_ul()
    flush_para()
    return "\n".join(out)
