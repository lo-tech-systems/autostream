#!/usr/bin/env python3
"""autostream_webui_api.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Lightweight JSON API endpoints and shared send_json helper.

Contents:
  - send_json                    -- write a JSON HTTP response
  - run_updater                  -- invoke the updater script via sudo
  - _status_text_for_home        -- derive home-page status text from playback state
  - send_owntone_outputs_json    -- GET /api/owntone/outputs
  - send_owntone_outputs_state_json -- GET /api/owntone/outputs_state
  - send_status_json             -- GET /api/status
  - send_update_check_json       -- GET /api/update/check
  - send_update_status_json      -- GET /api/update/status
"""

from __future__ import annotations

import json
import logging
import subprocess

from typing import Optional

from autostream_config import parse_config
from autostream_core import (
    any_monitor_capturing,
    get_monitor_levels_dbfs,
    get_playback_snapshot,
)
from autostream_player_service import list_outputs
from autostream_sysutils import run_admin_cmd
from autostream_webui_common import locked_load_config
from autostream_webui_state import WebUIState


# -----------------------------------------------------------------------------
# Core JSON response helper
# -----------------------------------------------------------------------------

def send_json(handler, code: int, payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    try:
        handler.send_response(code)
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)
    except (BrokenPipeError, ConnectionResetError):
        # Client navigated away / refreshed / closed the tab mid-response.
        return


# -----------------------------------------------------------------------------
# Updater subprocess helper
# -----------------------------------------------------------------------------

def run_updater(args: list[str], timeout: int = 30) -> tuple[int, str, str]:
    cmd = ["/usr/bin/sudo", "-n", "/usr/local/libexec/autostream/autostream_updater", *args]
    p = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )
    return p.returncode, p.stdout, p.stderr



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
        cfg = locked_load_config(state.config_path)
        parsed = parse_config(cfg)
    except Exception as e:
        send_json(handler, 500, {"ok": False, "error": str(e), "outputs": []})
        return

    outputs_result = list_outputs(parsed.owntone.base_url, timeout=2)
    if not outputs_result.ok:
        logging.error(
            "Owntone outputs request failed: %s",
            outputs_result.error or outputs_result.detail or outputs_result.error_code,
        )
    outputs = list(outputs_result.outputs) if outputs_result.ok else []

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

    send_json(handler, 200, {
        "ok": True,
        "outputs": names,
        "selected": parsed.owntone.output_name,
    })


def send_owntone_outputs_state_json(handler, state: WebUIState) -> None:
    """Return Owntone outputs (id/name/selected/volume) for live refresh on '/'."""
    try:
        cfg = locked_load_config(state.config_path)
        parsed = parse_config(cfg)
    except Exception as e:
        send_json(handler, 500, {"ok": False, "error": str(e), "outputs": []})
        return

    outputs_result = list_outputs(parsed.owntone.base_url, timeout=2)
    if not outputs_result.ok:
        send_json(
            handler,
            200,
            {
                "ok": False,
                "error": outputs_result.error or outputs_result.detail or outputs_result.error_code,
                "outputs": [],
            },
        )
        return
    outputs = list(outputs_result.outputs)

    default_output_name = parsed.owntone.output_name
    hidden = {str(n).strip().casefold() for n in (parsed.webui.hidden_outputs or ()) if str(n).strip()}

    filtered = []
    for out in outputs:
        out_id = str(out.id or "").strip()
        name = str(out.name or "").strip()
        if not out_id or not name:
            continue

        selected = bool(out.selected)
        # Mirror '/' page behaviour: hide hidden outputs unless selected or default
        if name.casefold() in hidden and not selected and name != default_output_name:
            continue

        vol = max(0, min(100, int(out.volume_percent)))
        filtered.append({
            "id": out_id,
            "name": name,
            "selected": selected,
            "volume": vol,
            "is_default": (name == default_output_name),
        })

    # Sort: default first (matching '/' render)
    if default_output_name:
        filtered.sort(key=lambda o: (0 if o["is_default"] else 1, o["name"].casefold()))

    send_json(handler, 200, {"ok": True, "outputs": filtered})


# -----------------------------------------------------------------------------
# Status and update JSON endpoints
# -----------------------------------------------------------------------------

def send_status_json(handler, state: Optional[WebUIState] = None) -> None:
    is_playing = any_monitor_capturing()
    try:
        input_levels = get_monitor_levels_dbfs()
    except Exception:
        input_levels = []
    playback = get_playback_snapshot()
    send_json(handler, 200, {
        "playing": is_playing,
        "status_text": _status_text_for_home(is_playing, input_levels),
        "status_class": "playing" if is_playing else "waiting",
        "input_levels": input_levels,
        "playback": playback.to_public_dict(),
        "playback_banner_text": playback.banner_text,
    })


def send_update_check_json(handler) -> None:
    rc, out, err = run_updater(["check"], timeout=60)
    if rc != 0:
        send_json(handler, 200, {"ok": False, "error": "check failed"})
        return
    try:
        send_json(handler, 200, json.loads(out))
    except Exception:
        send_json(handler, 200, {"ok": False})


def send_update_status_json(handler) -> None:
    """Return the persisted update status from update-result.env via autostream_admin.

    The response shape matches what autostream_admin update-status emits:
      {ok, status, message, percent, last_run_at}
    where status is one of: in_progress | success | failure | error | unknown
    """
    p = run_admin_cmd(["update-status"], timeout=10.0)
    if p.returncode != 0:
        send_json(handler, 200, {
            "ok": False,
            "status": "error",
            "message": "Could not read update status",
            "percent": 0,
            "last_run_at": "",
        })
        return
    try:
        send_json(handler, 200, json.loads(p.stdout or "{}"))
    except Exception:
        send_json(handler, 200, {
            "ok": False,
            "status": "error",
            "message": "Malformed update status response",
            "percent": 0,
            "last_run_at": "",
        })
