#!/usr/bin/env python3
"""webui/browser/api_owntone.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

OwnTone settings endpoints.

Contents:
  - send_owntone_output_*_json       -- POST /api/owntone/output/*
  - send_owntone_uncompressed_json, send_owntone_buffered_audio_json,
  - send_owntone_start_buffer_json, send_owntone_user_agent_json,
  - send_owntone_grace_period_json   -- POST /api/owntone/*
  - send_settings_mdns_grace_period_json -- POST /api/settings/mdns-grace-period
"""

from __future__ import annotations

import json
from autostream_config import DEFAULT_AIRPLAY_MODE, normalize_airplay_mode
from autostream_intents import Intent, submit
from autostream_state import Origin
from webui.session_state import WebUIState
from webui import common


# ---------------------------------------------------------------------------
# OwnTone setup per-field autosave endpoints
#
# Each route parses and checks its request, then submits one backend-setting
# intent; the intent's handler does the work. A backend that asks for a restart
# says so in the result, and the route starts it.
# ---------------------------------------------------------------------------

def _submit_backend_setting(state: WebUIState, setting: str, value: object, output_id: str = ""):
    args = {"setting": setting, "value": value}
    if output_id:
        args["output_id"] = output_id
    return submit(Intent("backend.setting.set", args, Origin.USER, "webui", context=state))


def _start_owntone_restart_if_required(state: WebUIState, reply, restart_threshold_s: float = 0.75) -> bool:
    """Start the OwnTone restart when the intent's result asks for one; returns
    whether it was asked for."""
    required = bool(reply.result.get("restart_required"))
    if required:
        from webui.browser.owntone import start_owntone_restart_async
        start_owntone_restart_async(state, delay_s=restart_threshold_s)
    return required


def send_owntone_output_visibility_json(handler, state: WebUIState, body: str) -> None:
    """POST /api/owntone/output-visibility -- show or hide a named output.

    Body: {"output_name": "<name>", "visible": true|false}
    Optional "output_id" populates known_outputs when provided.
    """
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        common.send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return

    output_name = str(payload.get("output_name") or "").strip()
    if not output_name:
        common.send_json(handler, 400, {"ok": False, "error": "output_name required"})
        return
    visible = payload.get("visible")
    if not isinstance(visible, bool):
        common.send_json(handler, 400, {"ok": False, "error": "visible must be a boolean"})
        return
    output_id = str(payload.get("output_id") or "").strip()

    reply = _submit_backend_setting(
        state, "output_visibility", {"output_name": output_name, "visible": visible}, output_id)
    if not reply.ok:
        common.send_json(handler, 200, {"ok": False, "error": reply.error})
        return

    common.send_json(handler, 200, {"ok": True, "output_name": output_name, "visible": visible})


def send_owntone_output_include_tv_json(handler, state: WebUIState, body: str) -> None:
    """POST /api/owntone/output-include-tv -- play an Apple TV's HomePods with
    or without the Apple TV.

    Body: {"output_id": "<id>", "include_tv": true|false}
    Reply: {"ok": true, "output_id": ..., "include_tv": ..., "reselected": ...}
    """
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        common.send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return

    output_id = str(payload.get("output_id") or "").strip()
    if not output_id:
        common.send_json(handler, 400, {"ok": False, "error": "output_id required"})
        return
    include_tv = payload.get("include_tv")
    if not isinstance(include_tv, bool):
        common.send_json(handler, 400, {"ok": False, "error": "include_tv must be a boolean"})
        return

    reply = _submit_backend_setting(state, "output_include_tv", include_tv, output_id)
    if not reply.ok:
        common.send_json(handler, 200, {"ok": False, "error": reply.error})
        return
    common.send_json(handler, 200, {
        "ok": True,
        "output_id": reply.result["output_id"],
        "include_tv": reply.result["include_tv"],
        "reselected": reply.result["reselected"],
    })


def send_owntone_output_mode_json(handler, state: WebUIState, body: str) -> None:
    """POST /api/owntone/output-mode -- set AirPlay mode for a specific output.

    Body: {"output_id": "<id>", "mode": "default"|"raop"|"airplay2"}
    """
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        common.send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return

    output_id = str(payload.get("output_id") or "").strip()
    if not output_id:
        common.send_json(handler, 400, {"ok": False, "error": "output_id required"})
        return
    mode_raw = str(payload.get("mode") or DEFAULT_AIRPLAY_MODE).strip().lower()
    valid_modes = {
        DEFAULT_AIRPLAY_MODE,
        "raop",
        "airplay2",
        "airplay2_buffered",
        "airplay2_buffered_24",
        "airplay2_surround_stereo",
        "airplay2_surround_upmix",
    }
    if mode_raw not in valid_modes:
        common.send_json(handler, 400, {"ok": False, "error": f"mode must be one of {sorted(valid_modes)}"})
        return
    mode = normalize_airplay_mode(mode_raw)

    reply = _submit_backend_setting(state, "output_mode", mode, output_id)
    if not reply.ok:
        common.send_json(handler, 200, {"ok": False, "error": reply.error})
        return

    common.send_json(handler, 200, {"ok": True, "output_id": output_id, "mode": mode})


def send_owntone_output_offset_json(handler, state: WebUIState, body: str) -> None:
    """POST /api/owntone/output-offset -- set playback offset for a specific output.

    Body: {"output_id": "<id>", "offset_ms": <int>}
    """
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        common.send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return

    output_id = str(payload.get("output_id") or "").strip()
    if not output_id:
        common.send_json(handler, 400, {"ok": False, "error": "output_id required"})
        return
    raw_offset = payload.get("offset_ms")
    if isinstance(raw_offset, bool) or not isinstance(raw_offset, (int, float)):
        common.send_json(handler, 400, {"ok": False, "error": "offset_ms must be a number"})
        return

    reply = _submit_backend_setting(state, "output_offset", raw_offset, output_id)
    if not reply.ok:
        common.send_json(handler, 200, {"ok": False, "error": reply.error})
        return
    common.send_json(handler, 200, {
        "ok": True,
        "output_id": reply.result["output_id"],
        "offset_ms": reply.result["offset_ms"],
        "applied_live": reply.result["applied_live"],
    })


def _send_owntone_native_setting_json(
    handler,
    state: WebUIState,
    setting: str,
    value: object,
) -> None:
    """Shared implementation for native OwnTone settings (uncompressed, user agent).

    Submits the setting and starts the OwnTone restart when asked.
    Returns {"ok": true, "restart_required": true|false}.
    """
    reply = _submit_backend_setting(state, setting, value)
    if not reply.ok:
        common.send_json(handler, 200, {"ok": False, "error": reply.error or "OwnTone API error"})
        return

    common.send_json(handler, 200, {
        "ok": True, "restart_required": _start_owntone_restart_if_required(state, reply)})


def send_owntone_uncompressed_json(handler, state: WebUIState, body: str) -> None:
    """POST /api/owntone/uncompressed-audio — toggle ALAC uncompressed audio.

    Body: {"value": true|false}
    """
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        common.send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return
    value = payload.get("value")
    if not isinstance(value, bool):
        common.send_json(handler, 400, {"ok": False, "error": "value must be a boolean"})
        return
    _send_owntone_native_setting_json(handler, state, "uncompressed_audio", value)


def send_owntone_buffered_audio_json(handler, state: WebUIState, body: str) -> None:
    """POST /api/owntone/buffered-audio — toggle AirPlay 2 buffered audio preference.

    Body: {"value": true|false}
    """
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        common.send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return
    value = payload.get("value")
    if not isinstance(value, bool):
        common.send_json(handler, 400, {"ok": False, "error": "value must be a boolean"})
        return

    reply = _submit_backend_setting(state, "buffered_audio", value)
    if not reply.ok:
        common.send_json(handler, 200, {"ok": False, "error": reply.error or "OwnTone API error"})
        return

    common.send_json(handler, 200, {
        "ok": True,
        "restart_required": _start_owntone_restart_if_required(state, reply),
        "reset_outputs": list(reply.result["reset_outputs"]),
    })


def send_owntone_start_buffer_json(handler, state: WebUIState, body: str) -> None:
    """POST /api/owntone/start-buffer — set start buffer in milliseconds.

    Body: {"value": <int>}
    """
    from autostream_players import (
        SETTING_START_BUFFER_MS_MAX,
        SETTING_START_BUFFER_MS_MIN,
        SETTING_START_BUFFER_MS_STEP,
    )
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        common.send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return
    raw = payload.get("value")
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        common.send_json(handler, 400, {"ok": False, "error": "value must be a number"})
        return
    value = max(
        SETTING_START_BUFFER_MS_MIN,
        min(
            SETTING_START_BUFFER_MS_MAX,
            round(int(raw) / SETTING_START_BUFFER_MS_STEP) * SETTING_START_BUFFER_MS_STEP,
        ),
    )
    reply = _submit_backend_setting(state, "start_buffer_ms", value)
    if not reply.ok:
        common.send_json(handler, 200, {"ok": False, "error": reply.error or "OwnTone API error"})
        return
    common.send_json(handler, 200, {
        "ok": True, "restart_required": _start_owntone_restart_if_required(state, reply)})


def send_owntone_user_agent_json(handler, state: WebUIState, body: str) -> None:
    """POST /api/owntone/user-agent -- set the AirPlay User-Agent header override.

    Body: {"value": <string>}. An empty string (after trimming) resets the
    backend to its derived default.
    """
    from autostream_players import SETTING_USER_AGENT_MAX_LEN
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        common.send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return
    raw = payload.get("value")
    if not isinstance(raw, str):
        common.send_json(handler, 400, {"ok": False, "error": "value must be a string"})
        return
    value = raw.strip()
    if len(value.encode("utf-8")) > SETTING_USER_AGENT_MAX_LEN:
        common.send_json(handler, 400, {"ok": False, "error": "value too long"})
        return
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        common.send_json(handler, 400, {"ok": False, "error": "value contains control characters"})
        return
    _send_owntone_native_setting_json(handler, state, "user_agent", value)


def send_settings_mdns_grace_period_json(handler, state: WebUIState, body: str) -> None:
    """POST /api/settings/mdns-grace-period: set mDNS grace period in minutes.

    Body: {"value": <int>}  (minutes; stored/applied in seconds)
    """
    from autostream_players import (
        SETTING_DEVICE_REMOVAL_GRACE_PERIOD_MAX_MINUTES,
        SETTING_DEVICE_REMOVAL_GRACE_PERIOD_MIN_MINUTES,
    )
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        common.send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return
    raw = payload.get("value")
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        common.send_json(handler, 400, {"ok": False, "error": "value must be a number"})
        return
    minutes = max(
        SETTING_DEVICE_REMOVAL_GRACE_PERIOD_MIN_MINUTES,
        min(SETTING_DEVICE_REMOVAL_GRACE_PERIOD_MAX_MINUTES, int(raw)),
    )
    seconds = minutes * 60

    reply = _submit_backend_setting(state, "mdns_grace_period", seconds)
    if not reply.ok:
        common.send_json(handler, 200, {"ok": False, "error": reply.error})
        return

    response = {
        "ok": True,
        "value": minutes,
        "seconds": seconds,
        "restart_required": _start_owntone_restart_if_required(state, reply),
    }
    if "warning" in reply.result:
        response["warning"] = reply.result["warning"]
    common.send_json(handler, 200, response)


def send_owntone_grace_period_json(handler, state: WebUIState, body: str) -> None:
    """Compatibility wrapper for the former OwnTone-branded endpoint."""
    send_settings_mdns_grace_period_json(handler, state, body)
