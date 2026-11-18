#!/usr/bin/env python3
"""webui/browser/home_api.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Home page JSON endpoints.

Contents:
  - send_audio_status_json           -- GET /api/audio/status
  - send_playing_status_json         -- GET /api/playing-status
"""

from __future__ import annotations

import logging
import autostream_logging as log_setup
from autostream_state import store
from webui.session_state import WebUIState
from webui import common
from webui import session_state
from webui.browser import first_boot


# ---------------------------------------------------------------------------
# Dial API handlers
# ---------------------------------------------------------------------------

_audio_status_fail_count = 0


def send_audio_status_json(handler, state: WebUIState) -> None:
    """GET /api/audio/status -- unauthenticated, read-only.

    Returns a fresh snapshot of currently selected OwnTone output names and
    playing state.  Both exceptions and result.ok == False increment the
    failure counter; it only resets on a true success.  WARNING on the 1st
    failure and then at most once a minute; DEBUG between.
    """
    global _audio_status_fail_count
    snap = store().snapshot()
    playing = common._session_playing(snap)
    try:
        parsed = common._config_snapshot(state)
    except Exception as e:
        logging.warning("audio/status: config load failed: %s", e)
        common.send_json(handler, 200, {"playing": playing, "outputs": None,
                                 "error": "backend_unavailable"})
        return
    part = snap.outputs
    if not part.connected:
        _audio_status_fail_count += 1
        n = _audio_status_fail_count
        if log_setup.log_every(("audio_status", "list_outputs"), 60.0):
            logging.warning("audio/status: outputs unavailable (call #%d)", n)
        else:
            logging.debug("audio/status: outputs unavailable")
        common.send_json(handler, 200, {"playing": playing, "outputs": None,
                                 "error": "backend_unavailable"})
        return
    _audio_status_fail_count = 0
    names = [u.name for u in part.units if u.reported is not None and u.shown_selected]
    common.send_json(handler, 200, {"playing": playing, "outputs": names})


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
