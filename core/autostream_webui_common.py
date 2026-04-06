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
"""

from __future__ import annotations

import html
import threading
from urllib.parse import quote
from typing import Optional

from autostream_auth import FLASH_COOKIE_NAME
from autostream_config import load_config
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
