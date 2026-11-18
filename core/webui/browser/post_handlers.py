#!/usr/bin/env python3
"""webui/browser/post_handlers.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

POST request handlers for the autostream Web UI.

Contents:
  - handle_output_update          -- POST /api/output
  - handle_live_input_eq_update   -- POST /api/input_eq
  - handle_live_input_gain_update -- POST /api/input_gain
"""

from __future__ import annotations

import json
import logging

from autostream_intents import Intent, Origin, submit
from autostream_pin_pairing import REQUESTER_WEBUI
from autostream_config import DEFAULT_AIRPLAY_MODE
from autostream_player_service import config_airplay_mode_to_backend

from webui.session_state import WebUIState
from autostream_webui_api import send_settings_post_json
from webui import common
from webui.browser import home_model


# -----------------------------------------------------------------------------
# Output toggle / volume handler
# -----------------------------------------------------------------------------

def handle_output_update(handler, state: WebUIState, body: str) -> None:
    try:
        payload = json.loads(body)
        out_id = str(payload.get("id") or "").strip()

        parsed = common._config_snapshot(state)

        offset_ms_raw = parsed.owntone.output_offsets_ms.get(out_id) if out_id else None
        offset_ms = int(offset_ms_raw) if offset_ms_raw is not None else None
        mode_text = parsed.owntone.output_airplay_modes.get(out_id, DEFAULT_AIRPLAY_MODE) if out_id else DEFAULT_AIRPLAY_MODE
        mode = config_airplay_mode_to_backend(mode_text)

        result = home_model.submit_output_change(
            payload, requester="webui", pin_requester=REQUESTER_WEBUI,
            offset_ms=offset_ms, mode=mode,
        )
        common.send_json(handler, 200, result)
    except Exception as e:
        logging.error("Update failed: %s", e)
        common.send_json(handler, 200, {"ok": False, "error": str(e)})


# -----------------------------------------------------------------------------
# Live EQ / gain update handlers
# -----------------------------------------------------------------------------

def handle_live_input_eq_update(handler, state: WebUIState, body: str) -> None:
    """Apply live per-input EQ changes to autostream_monitor and persist to the store."""
    import math
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        common.send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return

    try:
        raw_index = payload.get("input", 0)
        if isinstance(raw_index, bool):
            raise TypeError("bool")
        input_index = int(raw_index)
        eq_fields = ("eq_40hz_db", "eq_100hz_db", "eq_8khz_db")
        for f in eq_fields:
            if isinstance(payload.get(f), bool):
                raise TypeError("bool")
        eq_40hz_db = float(payload.get("eq_40hz_db", 0.0))
        eq_100hz_db = float(payload.get("eq_100hz_db", 0.0))
        eq_8khz_db = float(payload.get("eq_8khz_db", 0.0))
    except Exception:
        common.send_json(handler, 400, {"ok": False, "error": "Invalid EQ payload"})
        return

    if input_index not in (1, 2):
        common.send_json(handler, 400, {"ok": False, "error": "input must be 1 or 2"})
        return

    for val in (eq_40hz_db, eq_100hz_db, eq_8khz_db):
        if not math.isfinite(val) or val < -10.0 or val > 10.0:
            common.send_json(handler, 400, {"ok": False, "error": "EQ gain must be between -10 and 10 dB"})
            return

    reply = submit(Intent(
        "input.eq.set",
        {"input": input_index, "eq_40hz_db": eq_40hz_db, "eq_100hz_db": eq_100hz_db,
         "eq_8khz_db": eq_8khz_db},
        Origin.USER, "webui", context=state))
    if not reply.ok:
        common.send_json(handler, 200, {"ok": False, "error": "Could not update live EQ"})
        return

    common.send_json(handler, 200, {
        "ok": True,
        "input": input_index,
        "eq_40hz_db": eq_40hz_db,
        "eq_100hz_db": eq_100hz_db,
        "eq_8khz_db": eq_8khz_db,
    })


def handle_live_input_gain_update(handler, state: WebUIState, body: str) -> None:
    """Apply live per-input gain changes to autostream_monitor and persist to the store."""
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        common.send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return

    try:
        raw_index = payload.get("input", 0)
        if isinstance(raw_index, bool):
            raise TypeError("bool")
        input_index = int(raw_index)
    except Exception:
        common.send_json(handler, 400, {"ok": False, "error": "Invalid gain payload"})
        return

    if input_index not in (1, 2):
        common.send_json(handler, 400, {"ok": False, "error": "input must be 1 or 2"})
        return

    field = f"audio{input_index}.gain_db"
    send_settings_post_json(handler, state, {"field": field, "value": payload.get("gain_db")})
