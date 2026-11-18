#!/usr/bin/env python3
"""webui/browser/home_api.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Home page JSON endpoints.

Contents:
  - send_owntone_outputs_json        -- GET /api/owntone/outputs
  - send_owntone_outputs_state_json  -- GET /api/owntone/outputs_state
  - send_status_json                 -- GET /api/status
  - send_input_levels_json           -- GET /api/inputs/levels
  - send_audio_status_json           -- GET /api/audio/status
  - send_playing_status_json         -- GET /api/playing-status
"""

from __future__ import annotations

import logging
from typing import Optional
import autostream_logging as log_setup
from autostream_state import store
from webui.browser.home_model import home_outputs_reply, home_status_fields
from webui.session_state import WebUIState
from webui import common
from webui import session_state
from webui.browser import first_boot


# -----------------------------------------------------------------------------
# Home-page status text helper (shared by send_airplay_page and send_status_json)
# -----------------------------------------------------------------------------

def _status_text_for_home(is_playing: bool, input_levels: list[dict]) -> str:
    """Return home-page status text based on the currently active input."""
    if not is_playing:
        return "Waiting"

    active_label = ""
    for lv in input_levels:
        if lv.get("is_above_threshold"):
            active_label = str(lv.get("label") or "").strip()
            break

    if active_label.startswith("In") and active_label[2:].isdigit():
        return f"Playing Input {active_label[2:]}"
    if active_label:
        return f"Playing {active_label}"
    return "Playing"


# -----------------------------------------------------------------------------
# Owntone output JSON endpoints
# -----------------------------------------------------------------------------

def send_owntone_outputs_json(handler, state: WebUIState) -> None:
    """Return available Owntone output names for async refresh on /setup."""
    try:
        parsed = common._config_snapshot(state)
    except Exception as e:
        common.send_json(handler, 500, {"ok": False, "error": str(e), "outputs": []})
        return

    part = store().snapshot().outputs
    if not part.connected:
        logging.error("Owntone outputs request failed: the player is not answering")
    outputs = list(part.reported_rows()) if part.connected else []

    hidden = {str(n).strip().casefold() for n in (parsed.webui.hidden_outputs or ()) if str(n).strip()}

    names = []
    for out in outputs:
        nm = str(out.name or "").strip()
        if not nm:
            continue
        # Mirror existing behavior: hide hidden outputs unless it is the configured default
        if nm.casefold() in hidden and nm != parsed.owntone.output_name:
            continue
        names.append(nm)

    common.send_json(handler, 200, {
        "ok": True,
        "outputs": names,
        "selected": parsed.owntone.output_name,
    })


def send_owntone_outputs_state_json(handler, state: WebUIState) -> None:
    """Return Owntone outputs (id/name/selected/volume) for live refresh on '/'."""
    snap = store().snapshot()
    try:
        parsed = common._config_snapshot(state)
    except Exception as e:
        logging.warning("send_owntone_outputs_state_json: settings unavailable: %s", e)
        common.send_json(handler, 500, {"ok": False, "error": str(e), "outputs": []})
        return
    common.send_json(handler, 200, home_outputs_reply(snap, parsed))


# -----------------------------------------------------------------------------
# Status and update JSON endpoints
# -----------------------------------------------------------------------------

def send_status_json(handler, state: Optional[WebUIState] = None) -> None:
    snap = store().snapshot()
    fields = home_status_fields(snap)
    input_levels = fields["input_levels"]
    playback_dict = fields["playback"]
    warnings = fields["warnings"]
    ti_dict = fields["track_identification"]
    # Unified playback-session state: the authoritative
    # "playing" signal is session.active, not a raw is_capturing check,
    # so replay (daemon-side, no input is "capturing") correctly reports as
    # playing.
    session_state = snap.session.as_dict()
    is_playing = snap.session.active
    response = {
        "playing": is_playing,
        "status_text": _status_text_for_home(is_playing, input_levels),
        "status_class": "playing" if is_playing else "waiting",
        "input_levels": input_levels,
        "playback": playback_dict,
        "playback_banner_text": warnings.get("stylus"),
        "belt_banner_text": warnings.get("belt"),
        "bearing_banner_text": warnings.get("bearing"),
        "dial_update_banner_text": warnings.get("dial_update") or "",
        "sample_rate_banner_text": warnings.get("sample_rate") or "",
        "track_identification": ti_dict,
        # Always present (unlike "repeat" below): the session tracker runs
        # regardless of whether the repeat feature/block exists at all.
        "session": session_state,
        # Appliance-authoritative mute flag: the now-playing header text is
        # the only place the WebUI surfaces a mute, so it needs this on
        # every status poll, not just the outputs poll.
        "muted": snap.outputs.muted_all,
    }
    # Pass the daemon's "repeat" status block through verbatim when present.
    # An old binary that never reports it means the key is
    # omitted entirely -- no KeyError, feature-unsupported by absence.
    repeat_status = snap.repeat.block
    if repeat_status is not None:
        response["repeat"] = repeat_status
    # Reconcile/watchdog counters, always present (coordinator-owned
    # state, not a daemon-optional block like "repeat") -- lets the Web UI or
    # support tooling see that self-healing fired without grepping logs.
    response["owntone_selfheal"] = snap.health.as_json()
    common.send_json(handler, 200, response)


def send_input_levels_json(handler, state: Optional[WebUIState] = None) -> None:
    """GET /api/inputs/levels: the Setup page's live level readout.

    Reads only the coordinator's cache of the last daemon poll, so it
    never waits on OwnTone or the daemon. One entry per input, in index
    order; dbfs is null for an input with no running monitor and for
    every input while the daemon is disconnected. Each entry also carries
    the note shown under the card's Dynamic Rate Matching switch and the
    values that note is worked out from.
    """
    enabled = {1: False, 2: False}
    if state is not None:
        try:
            parsed = common._config_snapshot(state)
            enabled = {1: bool(parsed.audio1_enabled), 2: bool(parsed.audio2_enabled)}
        except Exception:
            logging.debug("input levels: config snapshot unavailable", exc_info=True)
    snap = store().snapshot()
    connected = bool(snap.monitor.connected)
    by_index = {lv.get("index"): lv for lv in snap.inputs.levels()}
    inputs = []
    for index in (1, 2):
        lv = by_index.get(index)
        note_text, rate_text = snap.inputs.rate_texts(index)
        inputs.append({
            "index": index,
            "enabled": enabled[index],
            "running": lv is not None,
            "dbfs": float(lv["dbfs"]) if (lv is not None and connected) else None,
            "sample_rate_text": rate_text,
            "rate_matching_note": note_text,
            "dynamic_rate_matching": bool(lv.get("dynamic_rate_matching", True)) if lv is not None else True,
            "rate_mismatch_hz": int(lv.get("rate_mismatch_hz", 0)) if lv is not None else 0,
            "negotiated_hz": int(lv.get("negotiated_hz", 0)) if lv is not None else 0,
            "monitor_supports_rate_matching": (
                bool(lv.get("monitor_supports_rate_matching", False)) if lv is not None else False
            ),
        })
    common.send_json(handler, 200, {"ok": True, "connected": connected, "inputs": inputs})


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
