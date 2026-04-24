#!/usr/bin/env python3
"""autostream_webui_page_license.py

Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.

The /license route now redirects to /about, where the license text is shown
as a collapsible section within the Copyright & License fieldset.
"""

from __future__ import annotations

from autostream_webui_state import WebUIState


def send_license_page(handler, state: WebUIState) -> None:
    """Redirect to /about where the license is shown as a collapsible section."""
    _ = state
    try:
        handler.send_response(302)
        handler.send_header("Location", "/about")
        handler.end_headers()
    except Exception:
        pass
