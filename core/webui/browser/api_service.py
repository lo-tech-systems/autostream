#!/usr/bin/env python3
"""webui/browser/api_service.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Service life-limit endpoints and their settings fields.

Contents:
  - send_service_config_json         -- POST /api/service/config
  - send_service_reset_json          -- POST /api/service/reset
"""

from __future__ import annotations

import json
import logging
from autostream_bluetooth_client import classify_loopback_hw
from autostream_intents import Intent, submit
from autostream_state import Origin, store
from webui.common import _fallback_input_snapshot
from webui.browser.service_schema import (
    _SERVICE_ITEMS,
    _card_display,
    _format_reset_timestamp,
    _hours_display,
    _time_display,
)
from webui.session_state import WebUIState
from autostream_settings_schema import register_field
from webui import common


# -----------------------------------------------------------------------------
# Service config field map (field name → config section, key, normaliser)
# Generated from _SERVICE_ITEMS so field names and normalisers stay in sync
# with the page schema without needing a parallel hard-coded dict.
#
# Rows are also registered into the shared SETTINGS_SCHEMA table
# (autostream_settings_schema.py), using the exact same section/key/
# normaliser values -- this dict's own shape and values are unchanged, it
# is now just built by the same registration call that populates the
# shared table, rather than a second, separately maintained structure.
# -----------------------------------------------------------------------------

_SERVICE_FIELD_MAP: dict = {}
for _si in _SERVICE_ITEMS:
    for _n in (1, 2):
        _sec = f"audio{_n}"
        _hours_path = f"service_{_si.key}_life_hours_input{_n}"
        register_field(_hours_path, _sec, _si.hours_config_key, normalise=_si.hours_normalizer)
        _SERVICE_FIELD_MAP[_hours_path] = (_sec, _si.hours_config_key, _si.hours_normalizer)
        if _si.years_config_key and _si.years_normalizer:
            _years_path = f"service_{_si.key}_life_years_input{_n}"
            register_field(_years_path, _sec, _si.years_config_key, normalise=_si.years_normalizer)
            _SERVICE_FIELD_MAP[_years_path] = (_sec, _si.years_config_key, _si.years_normalizer)


def _submit_playback_config(input_index: int, **settings) -> None:
    """Hand one input's playback settings to the tracker."""
    reply = submit(Intent("input.playback_config.set", {"input": input_index, **settings},
                          Origin.USER, "webui"))
    if not reply.ok:
        logging.debug("playback settings for input %s not applied: %s", input_index, reply.error)


def send_service_config_json(handler, state: WebUIState, body: str) -> None:
    """POST /api/service/config -- auto-save one maintenance tracking field.

    Request body (JSON):
        { "field": "<field_name>", "value": "<raw_value>" }

    Accepted fields (see _SERVICE_FIELD_MAP):
        service_stylus_life_hours_input1/2
        service_belt_life_hours_input1/2, service_belt_life_years_input1/2
        service_bearing_life_hours_input1/2, service_bearing_life_years_input1/2

    Response (JSON):
        { "ok": true, "field": "<field>", "value": "<normalised>",
          "display": { hours_live, hours_bar_pct, ..., time_live, ... } }
    """
    try:
        payload = json.loads(body or "{}")
        field = str(payload.get("field", "")).strip()
        value = str(payload.get("value", "")).strip()
    except Exception:
        common.send_json(handler, 400, {"ok": False, "error": "Invalid request body"})
        return

    if field not in _SERVICE_FIELD_MAP:
        common.send_json(handler, 400, {"ok": False, "error": "Unknown field"})
        return

    section, key, _normaliser = _SERVICE_FIELD_MAP[field]

    try:
        # The pre-write parse, which the live-update args below start from.
        p = common._config_snapshot(state)
        reply = submit(Intent(
            "settings.service_field.set", {"path": field, "value": value}, Origin.USER, "webui",
            context=state))
        if not reply.ok:
            if "invalid" in reply.result:
                common.send_json(handler, 400, {"ok": False, "error": reply.result["invalid"]})
            elif "unavailable" in reply.result:
                common.send_json(handler, 500, {"ok": False, "error": "Settings store unavailable"})
            else:
                common.send_json(handler, 200, {"ok": False, "error": reply.error})
            return
        normalised = reply.result["value"]

        # Build live-update args from the pre-write parse, substituting the one
        # changed key. This avoids a second parse_config call on the same object.
        if section == "audio1":
            a = p.audio1
            _submit_playback_config(
                1,
                enabled=p.audio1_enabled,
                is_turntable=a.is_turntable,
                input_type=a.input_type,
                is_bluetooth=classify_loopback_hw(a.capture_device) == "capture",
                stylus_life_hours=normalised if key == "stylus_life_hours" else a.stylus_life_hours,
                belt_life_hours=normalised if key == "belt_life_hours" else a.belt_life_hours,
                belt_life_years=normalised if key == "belt_life_years" else a.belt_life_years,
                bearing_life_hours=normalised if key == "bearing_life_hours" else a.bearing_life_hours,
                bearing_life_years=normalised if key == "bearing_life_years" else a.bearing_life_years,
            )
        else:
            a = p.audio2
            _submit_playback_config(
                2,
                enabled=p.audio2_enabled,
                is_turntable=a.is_turntable,
                input_type=a.input_type,
                is_bluetooth=classify_loopback_hw(a.capture_device) == "capture",
                stylus_life_hours=normalised if key == "stylus_life_hours" else a.stylus_life_hours,
                belt_life_hours=normalised if key == "belt_life_hours" else a.belt_life_hours,
                belt_life_years=normalised if key == "belt_life_years" else a.belt_life_years,
                bearing_life_hours=normalised if key == "bearing_life_hours" else a.bearing_life_hours,
                bearing_life_years=normalised if key == "bearing_life_years" else a.bearing_life_years,
            )
    except Exception as e:
        logging.exception("send_service_config_json: save failed")
        common.send_json(handler, 200, {"ok": False, "error": str(e)})
        return

    # Build display dict so the client can update the DOM without recalculation.
    _display: dict = {}
    try:
        _input_idx    = 1 if section == "audio1" else 2
        _item         = key.split("_")[0]       # "stylus" | "belt" | "bearing"
        _dimension    = key.split("_")[-1]      # "hours" | "years"
        _audio        = p.audio1 if _input_idx == 1 else p.audio2
        _is_turntable = bool(getattr(_audio, "is_turntable", False))
        _life_hours   = normalised if _dimension == "hours" else int(getattr(_audio, f"{_item}_life_hours", 0) or 0)
        _life_years   = (normalised if _dimension == "years" else int(getattr(_audio, f"{_item}_life_years", 0) or 0)) if _item != "stylus" else 0
        _playback = store().snapshot().playback
        _snap = _playback.inputs.get(_input_idx)
        if _snap is None:
            _snap = _fallback_input_snapshot(_audio, _input_idx, enabled=True)
        _hd = _hours_display(_item, _life_hours, _snap)
        _td = _time_display(_item, _life_years, _snap)
        _display = {**_hd, **_td, **_card_display(_item, _hd, _td, _is_turntable)}
    except Exception:
        logging.exception("send_service_config_json: display computation failed")

    common.send_json(handler, 200, {"ok": True, "field": field, "value": str(normalised), "display": _display})


def send_service_reset_json(handler, state: WebUIState, body: str) -> None:
    """POST /api/service/reset -- reset one maintenance item counter.

    Request body (JSON):
        { "item": "stylus"|"belt"|"bearing", "input": 1|2 }

    Response (JSON):
        { "ok": true, "persisted": true, "last_service_at": "<ISO>",
          "display": { hours_live, hours_bar_pct, ..., last_service } }
    """
    try:
        payload = json.loads(body or "{}")
        item = str(payload.get("item", "")).strip().lower()
        input_index = int(payload.get("input", 0))
    except Exception:
        common.send_json(handler, 400, {"ok": False, "error": "Invalid request body"})
        return

    if item not in ("stylus", "belt", "bearing"):
        common.send_json(handler, 400, {"ok": False, "error": "Unknown item"})
        return
    if input_index not in (1, 2):
        common.send_json(handler, 400, {"ok": False, "error": "Input must be 1 or 2"})
        return

    # Load config for life thresholds before resetting (used by display computation).
    _life_hours   = 0
    _life_years   = 0
    _is_turntable = False
    _parsed       = None
    _audio_cfg    = None
    try:
        _parsed = common._config_snapshot(state)
        _audio_cfg    = _parsed.audio1 if input_index == 1 else _parsed.audio2
        _life_hours   = int(getattr(_audio_cfg, f"{item}_life_hours", 0) or 0)
        _life_years   = int(getattr(_audio_cfg, f"{item}_life_years", 0) or 0) if item != "stylus" else 0
        _is_turntable = bool(getattr(_audio_cfg, "is_turntable", False))
    except Exception:
        logging.exception("send_service_reset_json: config load for display failed")

    reply = submit(Intent("input.counters.reset", {"input": input_index, "item": item},
                          Origin.USER, "webui"))
    result = reply.result.get("reset")

    if result is None or not result.applied:
        common.send_json(handler, 200, {"ok": False, "error": "Reset could not be applied"})
        return

    response: dict = {
        "ok": True,
        "persisted": bool(result.persisted),
        "last_service_at": result.last_service_at or "",
    }
    if not result.persisted:
        response["warning"] = "Reset applied but could not be saved — may revert on restart"

    # Build display dict from the live snapshot (updated by the reset).
    try:
        _playback = store().snapshot().playback
        _snap = _playback.inputs.get(input_index)
        if _snap is None and _audio_cfg is not None:
            _snap = _fallback_input_snapshot(_audio_cfg, input_index, enabled=True)
        if _snap is not None:
            _hd = _hours_display(item, _life_hours, _snap)
            _td = _time_display(item, _life_years, _snap)
            response["display"] = {
                **_hd,
                **_td,
                **_card_display(item, _hd, _td, _is_turntable),
                "last_service": _format_reset_timestamp(result.last_service_at),
            }
    except Exception:
        logging.exception("send_service_reset_json: display computation failed")

    common.send_json(handler, 200, response)
