#!/usr/bin/env python3
"""webui/browser/home_api.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Home page JSON endpoints.

Contents:
  - send_playing_status_json         -- GET /api/playing-status
"""

from __future__ import annotations

import logging
from webui import common
from webui import session_state
from webui.browser import first_boot


def send_playing_status_json(handler) -> None:
    """GET /api/playing-status -- return whether the appliance is streaming.

    Returns ``{"ok": true, "playing": <bool>}`` when monitor state can be
    determined.  When it cannot (internal error), returns HTTP 200 with an
    explicit *uncertain* body ``{"ok": false, "error": "playing status
    unavailable"}`` rather than falsely reporting stopped playback, so local
    automation conservatively treats the state as unknown.
    """
    try:
        playing = common._session_playing()
    except Exception:
        logging.warning("playing status unavailable (monitor query failed)")
        common.send_json(handler, 200, {"ok": False, "error": "playing status unavailable"})
        return
    common.send_json(handler, 200, {"ok": True, "playing": bool(playing)})


# -----------------------------------------------------------------------------
# Route-table adapters: the calling convention the dispatcher uses (handler,
# state[, body]) in front of the senders above.
# -----------------------------------------------------------------------------


def _route_get_playing_status(handler, state):
    if handler._is_direct_local():
        send_playing_status_json(handler)
        return
    # Proxied caller: reproduce the commissioning gate and the general "gate
    # protected pages" redirect-to-auth check that a proxied request used to
    # fall through to (this path is not in AUTH.ALLOWLIST_PATHS).
    if handler._commissioning_required():
        first_boot._route_commissioning_redirect_get(handler, state)
        return
    if session_state.AUTH.requires_auth("/api/playing-status") and not session_state.AUTH.is_authenticated(handler.headers):
        session_state.AUTH.redirect_to_auth(handler, next_path=handler.path)
        return
    handler._csrf_token = session_state.AUTH.ensure_session(handler)
    send_playing_status_json(handler)
