#!/usr/bin/env python3
"""autostream_webui_common.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Shared helpers for the autostream Web UI, imported by per-page modules and
the main web handler to avoid circular dependencies.

"""

from __future__ import annotations

import html
import json
import re
import subprocess
from datetime import datetime
from urllib.parse import quote, urlparse
from typing import Optional

from autostream_auth import FLASH_COOKIE_NAME
from autostream_bluetooth_client import classify_loopback_hw
from autostream_config import CONFIG_IO_LOCK, DEFAULT_STYLUS_LIFE_HOURS, load_config
from autostream_playback_stats import InputPlaybackSnapshot, make_fallback_input_snapshot
from autostream_rpi import get_psu_warning_text, cpu_is_licensed, LICENSE_CHECK
from autostream_webui_assets import (
    BANNER_HTML,
    NAV_ICON_ABOUT,
    NAV_ICON_EQUALISER,
    NAV_ICON_HOME,
    NAV_ICON_SERVICE,
    NAV_ICON_SETUP,
    VIEWPORT_META,
)
from autostream_webui_components import banner_html

import json as _json


def locked_load_config(path: str):
    """Load config under a global lock to avoid reading partial writes."""
    with CONFIG_IO_LOCK:
        return load_config(path)


def _config_snapshot(state):
    """Return a parsed config snapshot, preferring the in-memory settings store."""
    from autostream_settings import SettingsStore
    settings = getattr(state, "settings", None)
    if isinstance(settings, SettingsStore):
        return settings.snapshot()
    from autostream_config import parse_config
    return parse_config(locked_load_config(state.config_path))


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
# Shared HTML response helper -- matches send_json()'s shape. Lives here
# so page modules and autostream_auth.py can use it without importing
# autostream_webui.py, which already imports this module (a straight import
# the other way would be circular). autostream_webui.py re-exports this name
# for any existing callers that still reach it as autostream_webui.send_html.
# -----------------------------------------------------------------------------

def send_html(handler, code: int, html_str: str, *, extra_headers: Optional[dict] = None) -> None:
    """Write an HTML response, mirroring send_json()'s shape.

    Encodes, sends status/headers, writes the body, and guards the write
    against a client that has already disconnected -- a guard several
    hand-rolled HTML call sites across the codebase previously lacked.
    """
    body = html_str.encode("utf-8")
    try:
        handler.send_response(code)
        handler.send_header("Content-Type", "text/html; charset=utf-8")
        handler.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for name, value in extra_headers.items():
                handler.send_header(name, value)
        handler.end_headers()
        handler.wfile.write(body)
    except (BrokenPipeError, ConnectionResetError):
        # Client navigated away / refreshed / closed the tab mid-response.
        return


def build_hostname_redirect_url(handler, hostname: str, path: str = "/") -> str:
    """Build an absolute .local URL for a hostname change redirect."""
    host_header = handler.headers.get("Host", "")
    port_num = urlparse(f"http://{host_header}").port
    host_p = f"{hostname}.local:{port_num}" if port_num else f"{hostname}.local"
    return f"http://{host_p}{path}"


def send_hostname_changed_page(
    handler,
    hostname: str,
    *,
    path: str = "/",
    show_nav: bool = False,
    active_tab: str = "setup",
    flash_msg: Optional[str] = None,
    flash_type: str = "success",
) -> None:
    """Render a short wait page and redirect the browser to the new .local host."""
    redirect_url = build_hostname_redirect_url(handler, hostname, path)
    safe_host = html.escape(hostname)
    safe_url = html.escape(redirect_url)
    lic_html, lic_spacer = build_top_banner_html(flash_msg=flash_msg, flash_type=flash_type)
    body_html = f"""
{BANNER_HTML}
<h1>Hostname changed</h1>
<div class="card">
  <p>The hostname change is being applied.</p>
  <p>Your appliance will be available at <strong>{safe_host}.local</strong>.</p>
  <p>Redirecting you in 5 seconds.</p>
  <p style="word-break:break-word;">
    <a class="pill-btn" href="{safe_url}">Tap here to continue</a>
  </p>
</div>
"""
    page = build_page_html(
        "Hostname changed",
        body_html,
        head_extra=f'<meta http-equiv="refresh" content="5;url={safe_url}">',
        body_suffix=f'<script>setTimeout(function(){{window.location.href="{safe_url}";}},5000);</script>',
        lic_html=lic_html,
        lic_spacer=lic_spacer,
        active_tab=active_tab,
        show_nav=show_nav,
    )
    send_html(handler, 200, page)
    try:
        handler.wfile.flush()
    except Exception:
        pass


# -----------------------------------------------------------------------------
# Top-of-page banner HTML
# -----------------------------------------------------------------------------

def build_top_banner_html(flash_msg: Optional[str] = None, flash_type: str = "success") -> tuple[str, str]:
    """Returns (banner_html, spacer_html). Handles persistent and flash messages."""

    # Priority 1: User-triggered flash messages (e.g. "Settings saved" / errors)
    if flash_msg:
        banner_id = "red-banner" if flash_type == "error" else "green-banner"
        return banner_html(banner_id, html.escape(flash_msg))

    # Priority 2: System-level PSU warning
    warn = get_psu_warning_text()
    if warn:
        return banner_html("red-banner", html.escape(warn))

    # Priority 3: Licensing
    if LICENSE_CHECK and (not cpu_is_licensed()):
        return banner_html("red-banner", "This system is unlicensed")

    return ("", "")


# -----------------------------------------------------------------------------
# No-input-configured notice — persistent, non-dismissable-required inline
# notice shown on the Home and Setup pages whenever neither audio input is
# enabled. Distinct from the fixed-position top banner above (flash/PSU/
# licensing): this renders inline in the page body, so it can sit alongside
# whatever top banner is already showing rather than competing for the same
# slot.
# -----------------------------------------------------------------------------

def no_input_configured_notice_html(parsed) -> str:
    """Return an inline warning notice when no audio input is enabled.

    ``parsed`` is a parsed config snapshot (as returned by
    ``_config_snapshot()``) or ``None`` when the config could not be loaded,
    in which case no notice is shown -- the caller's own "Configuration
    unavailable" handling already covers that case.
    """
    if parsed is None:
        return ""
    if bool(getattr(parsed, "audio1_enabled", True)) or bool(getattr(parsed, "audio2_enabled", False)):
        return ""
    return (
        "<div style='margin:0 0 1rem;padding:0.75rem 1rem;"
        "border:1.5px solid var(--color-status-warning);border-radius:8px;"
        "font-size:0.9rem;'>"
        "No input device configured &mdash; set one up in "
        "<a href='/setup'>Setup</a>, or enable Bluetooth."
        "</div>"
    )


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
    process is running.  Every failed helper outcome (exception, nonzero exit,
    invalid JSON, blank tag) is cached as "unknown" so repeated calls cannot
    each incur the five-second subprocess timeout.
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
        _app_version_cache = "unknown"
        return _app_version_cache

    if p.returncode != 0:
        _app_version_cache = "unknown"
        return _app_version_cache

    try:
        payload = json.loads(p.stdout or "{}")
    except Exception:
        _app_version_cache = "unknown"
        return _app_version_cache

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
    return make_fallback_input_snapshot(
        input_index,
        f"Input {input_index}",
        enabled=bool(enabled),
        is_turntable=bool(getattr(parsed_input, "is_turntable", False)),
        is_bluetooth=classify_loopback_hw(
            str(getattr(parsed_input, "capture_device", "") or "")
        ) == "capture",
        stylus_life_hours=int(getattr(parsed_input, "stylus_life_hours", DEFAULT_STYLUS_LIFE_HOURS)),
        belt_life_hours=int(getattr(parsed_input, "belt_life_hours", 0)),
        belt_life_years=int(getattr(parsed_input, "belt_life_years", 0)),
        bearing_life_hours=int(getattr(parsed_input, "bearing_life_hours", 0)),
        bearing_life_years=int(getattr(parsed_input, "bearing_life_years", 0)),
    )


# -----------------------------------------------------------------------------
# Shared settings-card helper (used by Setup and Equaliser pages)
# -----------------------------------------------------------------------------

def settings_card_html(inner_html: str, *, margin_top: str = "0.75rem", warn: bool = False) -> str:
    """Render a styled settings card div matching the Setup/Equaliser page presentation.

    Parameters
    ----------
    inner_html  : HTML content placed inside the card
    margin_top  : top margin (CSS value, default "0.75rem")
    warn        : when True the card border is rendered in the danger colour
    """
    border_colour = "var(--color-status-danger)" if warn else "var(--color-border)"
    return (
        f"<div style='margin-top:{margin_top};padding:0.75rem 0.85rem;"
        f"border:1px solid {border_colour};"
        "border-radius:8px;background:var(--color-surface-raised);"
        "font-size:0.95rem;line-height:1.5;'>"
        + inner_html
        + "</div>"
    )


# -----------------------------------------------------------------------------
# Compact date formatter for the About page stylus panel
# -----------------------------------------------------------------------------

def build_nav_bar_html(
    active: str = "",
    *,
    service_warn: bool = False,
    remote_id: str = "",
) -> str:
    """Return the fixed bottom navigation bar HTML.

    active:       one of 'home', 'equaliser', 'setup', 'service', 'about'
    service_warn: when True the Service tab is styled red (e.g. stylus overdue)
    remote_id:    when set, renders remote mode — Home/Equaliser link to the remote
                  appliance; Service, Setup and Info are disabled (non-navigable).
    """
    if remote_id:
        tabs = [
            ("home",      f"/a/{remote_id}/",         "Home",      NAV_ICON_HOME,      ""),
            ("equaliser", f"/a/{remote_id}/equaliser", "Equaliser", NAV_ICON_EQUALISER, ""),
            ("service",   None,                        "Service",   NAV_ICON_SERVICE,   ' id="service-nav-tab"'),
            ("setup",     None,                        "Setup",     NAV_ICON_SETUP,     ""),
            ("about",     None,                        "Info",      NAV_ICON_ABOUT,     ""),
        ]
    else:
        tabs = [
            ("home",      "/",          "Home",      NAV_ICON_HOME,      ""),
            ("equaliser", "/equaliser", "Equaliser", NAV_ICON_EQUALISER, ""),
            ("service",   "/service",   "Service",   NAV_ICON_SERVICE,   ' id="service-nav-tab"'),
            ("setup",     "/setup",     "Setup",     NAV_ICON_SETUP,     ""),
            ("about",     "/about",     "Info",      NAV_ICON_ABOUT,     ""),
        ]
    items = []
    for key, href, label, icon, extra_attrs in tabs:
        classes = ["nav-tab"]
        if key == active:
            classes.append("nav-tab-active")
        if key == "service" and service_warn and not remote_id:
            classes.append("nav-tab-warn")
        if href is None:
            classes.append("nav-tab-disabled")
        cls = " ".join(classes)
        if href is None:
            items.append(
                f'<span class="{cls}" aria-disabled="true"{extra_attrs}>'
                f'{icon}<span>{label}</span></span>'
            )
        else:
            items.append(
                f'<a href="{html.escape(href)}" class="{cls}"{extra_attrs}>'
                f'{icon}<span>{label}</span></a>'
            )
    return '<nav class="bottom-nav">' + "".join(items) + "</nav>"


def build_appliance_selector_html(
    appliances: list,
    current_id: str,
    current_page: str,
    *,
    display_only: bool = False,
) -> str:
    """Build the appliance selector widget HTML.

    appliances:   ordered list of appliance dicts (bound-first, then remote by name).
                  Each dict has: id, hostname, is_bound, home_path, equaliser_path.
    current_id:   the currently selected appliance ID
    current_page: 'home' or 'equaliser' — determines the navigation target for each option.
    display_only: when True, render a non-interactive hostname display instead of a
                  dropdown selector (used when control_other_appliances is disabled).
    """
    if display_only:
        hostname = "autostream"
        for a in appliances:
            if str(a.get("id") or "") == current_id:
                hostname = str(a.get("hostname") or "").strip() or "autostream"
                break
        return (
            f'<span class="appliance-selector-btn"'
            f' style="pointer-events:none;cursor:default"'
            f' aria-label="{html.escape(hostname)}">'
            f'{html.escape(hostname)}</span>'
        )

    if not current_id:
        # Appliance identity unavailable — render a static, non-interactive hostname
        # display so the selector button cannot be activated without a valid bound ID.
        bound_hostname = "autostream"
        for a in appliances:
            if a.get("is_bound"):
                bound_hostname = str(a.get("hostname") or "").strip() or "autostream"
                break
        return (
            f'<span class="appliance-selector-btn"'
            f' style="pointer-events:none;cursor:default"'
            f' aria-label="{html.escape(bound_hostname)}">'
            f'{html.escape(bound_hostname)}</span>'
        )

    # Resolve display name for the trigger button
    current_name = "autostream"
    for a in appliances:
        if str(a.get("id") or "") == current_id:
            current_name = str(a.get("hostname") or "").strip() or "autostream"
            break

    items: list[str] = []
    divider_inserted = False
    for a in appliances:
        is_bound = bool(a.get("is_bound"))
        aid = str(a.get("id") or "")
        hostname = str(a.get("hostname") or "").strip() or "autostream"
        is_selected = (aid == current_id)

        if not is_bound and not divider_inserted:
            items.append(
                '<div class="appliance-selector-divider" role="separator" aria-hidden="true"></div>'
            )
            divider_inserted = True

        if current_page == "equaliser":
            href = str(a.get("equaliser_path") or f"/a/{aid}/equaliser")
        else:
            href = str(a.get("home_path") or ("/" if is_bound else f"/a/{aid}/"))

        cls = "appliance-selector-option"
        if is_selected:
            cls += " appliance-selector-option-active"

        weight = " style=\"font-weight:700;\"" if is_bound else ""
        items.append(
            f'<a href="{html.escape(href)}" role="option"'
            f' aria-selected="{str(is_selected).lower()}"'
            f' class="{cls}"{weight}>'
            f'{html.escape(hostname)}</a>'
        )

    dropdown_inner = (
        "".join(items)
        if items
        else '<span class="appliance-selector-option" style="color:var(--color-text-dim);">'
             'No other appliances</span>'
    )

    safe_current = html.escape(current_name)
    return (
        f'<div class="appliance-selector" id="appliance-selector"'
        f' data-current-id="{html.escape(current_id)}"'
        f' data-current-page="{html.escape(current_page)}">'
        f'<button type="button" class="appliance-selector-btn" id="appliance-selector-btn"'
        f' aria-haspopup="listbox" aria-expanded="false"'
        f' aria-label="Select appliance: {safe_current}">'
        f'<span id="appliance-selector-current">{safe_current}</span>'
        f'<span class="appliance-selector-chevron" aria-hidden="true">&#x25BE;</span>'
        f'</button>'
        f'<div id="appliance-selector-dropdown" role="listbox"'
        f' aria-label="Appliances" class="appliance-selector-dropdown" hidden>'
        f'{dropdown_inner}'
        f'</div>'
        f'</div>'
    )


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
    remote_id: str = "",
) -> str:
    """Render a complete HTML page using the shared scaffold.

    Parameters
    ----------
    title       : page <title> (plain text, will be HTML-escaped)
    body_html   : content placed inside <div class="container"> after the
                  opening tag; callers are responsible for including BANNER_HTML
                  where needed
    extra_css   : CSS appended after the shared theme.css <link> inside a small
                  inline <style> block, for genuinely page-specific rules
    head_extra  : raw HTML injected after </style> and before </head>
                  (e.g. csrf_meta, page-specific <script> blocks)
    body_prefix : raw HTML injected after <body> and before <div class="container">
                  (e.g. modal dialogs, overlay divs)
    body_suffix : raw HTML injected after the closing </div> of .container and
                  before the nav bar (e.g. scripts, A2HS_SCRIPT)
    lic_html    : from build_top_banner_html() — the fixed flash/PSU banner
    lic_spacer  : from build_top_banner_html() — the spacer div
    active_tab   : one of 'home', 'equaliser', 'setup', 'service', 'about'
    show_nav     : when False the nav bar is omitted (e.g. initial-setup wizard)
    service_warn : when True the Service tab is highlighted red
    dark_mode    : when True the dark colour theme is applied via data-theme="dark"
    remote_id    : when set, the nav bar renders in remote mode (pass the remote
                   appliance ID)
    """
    # The shared theme lives only in nginx/static/theme.css, served by nginx as a
    # static file rather than inlined here — see that file and the
    # `location /static/` block in system/nginx/autostream-nginx.conf. The version
    # query string cache-busts on every release without needing a shorter max-age.
    style_link = f'<link rel="stylesheet" href="/static/theme.css?v={html.escape(get_app_version())}">'
    extra_style = f'<style>{extra_css.strip()}</style>' if extra_css.strip() else ""
    nav = build_nav_bar_html(active_tab, service_warn=service_warn, remote_id=remote_id) if show_nav else ""
    body_cls = ' class="has-bottom-nav"' if show_nav else ""
    theme_attr = ' data-theme="dark"' if dark_mode else ' data-theme="light"'
    return (
        f'<!DOCTYPE html><html lang="en"{theme_attr}>'
        f'<head><meta charset="utf-8">{VIEWPORT_META}'
        f'<title>{html.escape(title)}</title>'
        f'{style_link}'
        f'{extra_style}'
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
# Matches an already html.escape()-d "[text](url)" span. The label may
# contain any escaped text except a literal ']'; the URL must be http(s)
# and may not contain whitespace or ')' (so the closing paren is unambiguous).
_MD_LINK_RE = re.compile(r'\[([^\]]+)\]\((https?://[^\s)]+)\)')
# Placeholder used to shield emitted anchors from the bare-URL autolink pass.
_LINK_PLACEHOLDER = "\x00LINK%d\x00"


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

    Handles: # H1 (h2), ## H2 (h3), ### H3 (h4), --- hr, * and - list
    items, > blockquotes (rendered recursively), **bold**, *italic*,
    bare URLs, and plain paragraphs.
    """
    _BOLD_RE = re.compile(r'\*\*(.+?)\*\*')
    _ITALIC_RE = re.compile(r'\*([^*\s][^*]*?)\*')

    def _inline(s: str) -> str:
        s = html.escape(s)
        s = _BOLD_RE.sub(r'<strong>\1</strong>', s)
        s = _ITALIC_RE.sub(r'<em>\1</em>', s)

        # [text](url) markdown links first, each replaced with a placeholder
        # token so the bare-URL autolink pass below cannot re-process the
        # URL already consumed inside the emitted <a> tag.
        emitted_links: list[str] = []

        def _md_link_sub(m: "re.Match[str]") -> str:
            link_text, url = m.group(1), m.group(2)
            emitted_links.append(
                f'<a href="{url}" target="_blank" rel="noopener noreferrer">'
                f'{link_text}</a>'
            )
            return _LINK_PLACEHOLDER % (len(emitted_links) - 1)

        s = _MD_LINK_RE.sub(_md_link_sub, s)
        s = _URL_RE.sub(
            lambda m: (
                f'<a href="{m.group(1)}" target="_blank" rel="noopener noreferrer">'
                f'{m.group(1)}</a>'
            ), s
        )
        for i, link_html in enumerate(emitted_links):
            s = s.replace(_LINK_PLACEHOLDER % i, link_html)
        return s

    lines = text.splitlines()
    out: list[str] = []
    in_ul = False
    in_blockquote = False
    blockquote_lines: list[str] = []
    pending: list[str] = []

    def flush_para() -> None:
        nonlocal pending
        if pending:
            out.append(f"<p>{_inline(' '.join(pending))}</p>")
            pending = []

    def close_ul() -> None:
        nonlocal in_ul
        if in_ul:
            out.append("</ul>")
            in_ul = False

    def flush_blockquote() -> None:
        nonlocal in_blockquote, blockquote_lines
        if in_blockquote:
            inner = render_license_md("\n".join(blockquote_lines))
            out.append(f"<blockquote>{inner}</blockquote>")
            blockquote_lines = []
            in_blockquote = False

    for line in lines:
        if line.startswith("> ") or line.strip() == ">":
            close_ul(); flush_para()
            in_blockquote = True
            blockquote_lines.append(line[2:] if line.startswith("> ") else "")
        elif line.startswith("# "):
            flush_blockquote(); close_ul(); flush_para()
            out.append(f"<h2>{_inline(line[2:].strip())}</h2>")
        elif line.startswith("## "):
            flush_blockquote(); close_ul(); flush_para()
            out.append(f"<h3>{_inline(line[3:].strip())}</h3>")
        elif line.startswith("### "):
            flush_blockquote(); close_ul(); flush_para()
            out.append(f"<h4>{_inline(line[4:].strip())}</h4>")
        elif line.strip() == "---":
            flush_blockquote(); close_ul(); flush_para()
            out.append("<hr>")
        elif line.startswith("* ") or line.startswith("- "):
            flush_blockquote(); flush_para()
            if not in_ul:
                out.append("<ul>")
                in_ul = True
            out.append(f"<li>{_inline(line[2:].strip())}</li>")
        elif not line.strip():
            flush_blockquote(); close_ul(); flush_para()
        else:
            flush_blockquote(); close_ul()
            pending.append(line.strip())

    flush_blockquote()
    close_ul()
    flush_para()
    return "\n".join(out)


# ── Stale-CSRF transparent recovery ──────────────────────────────────────────
#
# Browser sessions live in memory, so an appliance restart invalidates every
# open tab's session cookie and embedded CSRF token. The first state-changing
# API request from such a tab gets HTTP 403 {"error": "csrf_stale"} carrying a
# freshly minted token (see the CSRF branch in autostream_webui.py's POST
# dispatch); this script wraps window.fetch once per page so that exact case
# is retried transparently with the new token instead of the user's click
# silently doing nothing. Any other 403 (or a second consecutive failure)
# passes through untouched. Emit directly after the window.__CSRF assignment
# on every page that makes API calls.
CSRF_RECOVERY_SCRIPT = (
    "<script>(function(){"
    "if(window.__csrfRecoveryInstalled)return;window.__csrfRecoveryInstalled=true;"
    "var _f=window.fetch.bind(window);"
    "function hget(h,k){if(!h)return undefined;return(typeof h.get==='function')?h.get(k):h[k];}"
    "function hcopy(h,k,v){if(typeof h.get==='function'){var n=new Headers(h);n.set(k,v);return n;}"
    "var n={};for(var key in h){n[key]=h[key];}n[k]=v;return n;}"
    "window.fetch=function(input,init){"
    "return _f(input,init).then(function(resp){"
    "if(resp.status!==403||!init||!hget(init.headers,'X-CSRF-Token'))return resp;"
    "return resp.clone().json().then(function(data){"
    "if(!data||data.error!=='csrf_stale'||!data.csrf_token)return resp;"
    "window.__CSRF=data.csrf_token;"
    "var retry=Object.assign({},init);"
    "retry.headers=hcopy(init.headers,'X-CSRF-Token',data.csrf_token);"
    "return _f(input,retry);"
    "},function(){return resp;});"
    "});};"
    "})();</script>"
)
