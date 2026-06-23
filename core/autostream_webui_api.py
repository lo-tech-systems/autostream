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
  - send_service_config_json     -- POST /api/service/config
  - send_service_reset_json      -- POST /api/service/reset
  Display/card logic imported from autostream_webui_service_schema (shared with page renderer).
  - send_update_check_json       -- GET /api/update/check
  - send_update_status_json      -- GET /api/update/status
  - send_output_eq_config_json   -- POST /api/output_eq/config
  - send_output_eq_reset_json    -- POST /api/output_eq/reset
  - send_output_eq_status_json   -- GET /api/output_eq/status
"""

from __future__ import annotations

import json
import logging
import subprocess
import threading
import time

from typing import Optional

from autostream_config import (
    CONFIG_IO_LOCK,
    load_config,
    parse_config,
    save_config,
)
from autostream_dials import is_dial_authorized
from autostream_core import (
    any_monitor_capturing,
    get_live_output_eq_status,
    get_monitor_levels_dbfs,
    get_playback_snapshot,
    reset_input_belt,
    reset_input_bearing,
    reset_input_stylus,
    set_live_output_auto_trim,
    set_live_output_eq,
    set_live_output_gain,
    update_playback_input_config,
)
from autostream_appliance_models import (
    _OUTPUT_EQ_ALL_FIELDS,
    _OUTPUT_EQ_BOOL_FIELDS,
    _OUTPUT_EQ_DB_FIELDS,
    apply_eq_field,
    apply_eq_reset,
    apply_output_mutation,
    build_equaliser_state,
    build_home_state,
)
from autostream_player_service import list_outputs, update_output
from autostream_sysutils import run_admin_cmd
from autostream_webui_common import _config_snapshot, _fallback_input_snapshot
from autostream_webui_service_schema import (
    _SERVICE_ITEMS,
    _card_display,
    _format_reset_timestamp,
    _hours_display,
    _time_display,
)
from autostream_webui_state import WebUIState


# -----------------------------------------------------------------------------
# Service config field map (field name → config section, key, normaliser)
# Generated from _SERVICE_ITEMS so field names and normalisers stay in sync
# with the page schema without needing a parallel hard-coded dict.
# -----------------------------------------------------------------------------

_SERVICE_FIELD_MAP: dict = {}
for _si in _SERVICE_ITEMS:
    for _n in (1, 2):
        _sec = f"audio{_n}"
        _SERVICE_FIELD_MAP[f"service_{_si.key}_life_hours_input{_n}"] = (
            _sec, _si.hours_config_key, _si.hours_normalizer,
        )
        if _si.years_config_key and _si.years_normalizer:
            _SERVICE_FIELD_MAP[f"service_{_si.key}_life_years_input{_n}"] = (
                _sec, _si.years_config_key, _si.years_normalizer,
            )


# -----------------------------------------------------------------------------
# Core JSON response helper
# -----------------------------------------------------------------------------

# Statuses intercepted by the main autostream NGINX configuration.
# error_page 404 502 503 504 = @upstream_failed redirects these to an offline
# page, so they cannot be used as browser transport status for structured JSON.
# See system/nginx/autostream-nginx.conf and docs/API-ERROR-CONTRACT.md.
_NGINX_INTERCEPTED_STATUSES: frozenset[int] = frozenset({404, 502, 503, 504})


def send_browser_api_error(
    handler,
    semantic_status: int,
    error: str,
    *,
    retryable: bool | None = None,
    extra: dict | None = None,
) -> None:
    """Send a structured JSON error that survives the main NGINX boundary.

    For statuses in _NGINX_INTERCEPTED_STATUSES (404/502/503/504) the browser
    transport status is 200 and error_status carries the semantic code.
    All other statuses are sent natively.

    Caller-supplied extra fields are merged last; they cannot override ok,
    error, or error_status.  The caller-provided dict is never mutated.
    """
    if not isinstance(semantic_status, int) or not (100 <= semantic_status <= 599):
        raise ValueError(f"Invalid semantic_status: {semantic_status!r}")

    payload: dict = {"ok": False, "error": error}

    tunneled = semantic_status in _NGINX_INTERCEPTED_STATUSES
    if tunneled:
        payload["error_status"] = semantic_status

    if retryable is not None:
        payload["retryable"] = retryable

    if extra:
        for k, v in extra.items():
            if k not in ("ok", "error", "error_status"):
                payload[k] = v

    transport_status = 200 if tunneled else semantic_status
    send_json(handler, transport_status, payload)


def send_json(handler, code: int, payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    try:
        handler.send_response(code)
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        handler.send_header("Cache-Control", "no-store, max-age=0")
        handler.send_header("Pragma", "no-cache")
        handler.send_header("Expires", "0")
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
        parsed = _config_snapshot(state)
    except Exception as e:
        send_json(handler, 500, {"ok": False, "error": str(e), "outputs": []})
        return

    outputs_result = list_outputs(parsed.owntone.base_url, timeout=2)
    if not outputs_result.ok:
        logging.error(
            "Owntone outputs request failed: %s",
            outputs_result.message,
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
    home = build_home_state(state.config_path)
    if not home.get("ok"):
        send_json(handler, 500, {"ok": False, "error": home.get("error", ""), "outputs": []})
        return
    send_json(handler, 200, {"ok": True, "outputs": home["outputs"]})


# -----------------------------------------------------------------------------
# Status and update JSON endpoints
# -----------------------------------------------------------------------------

def send_status_json(handler, state: Optional[WebUIState] = None) -> None:
    if state is not None:
        home = build_home_state(state.config_path)
        input_levels = home.get("input_levels", [])
        playback_dict = home.get("playback", {})
        warnings = home.get("warnings", {})
        ti_dict = home.get("track_identification", {})
    else:
        input_levels = []
        try:
            input_levels = get_monitor_levels_dbfs()
        except Exception:
            pass
        playback = get_playback_snapshot()
        playback_dict = playback.to_public_dict()
        warnings = {
            "stylus": playback.stylus_banner_text or "",
            "belt": playback.belt_banner_text or "",
            "bearing": playback.bearing_banner_text or "",
        }
        try:
            from autostream_core import get_active_track_identification_snapshot
            ti_dict = get_active_track_identification_snapshot().to_public_dict()
        except Exception:
            ti_dict = {}
    is_playing = any_monitor_capturing()
    send_json(handler, 200, {
        "playing": is_playing,
        "status_text": _status_text_for_home(is_playing, input_levels),
        "status_class": "playing" if is_playing else "waiting",
        "input_levels": input_levels,
        "playback": playback_dict,
        "playback_banner_text": warnings.get("stylus"),
        "belt_banner_text": warnings.get("belt"),
        "bearing_banner_text": warnings.get("bearing"),
        "track_identification": ti_dict,
    })


def send_service_config_json(handler, state: WebUIState, body: str) -> None:
    """POST /api/service/config — auto-save one maintenance tracking field.

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
        send_json(handler, 400, {"ok": False, "error": "Invalid request body"})
        return

    if field not in _SERVICE_FIELD_MAP:
        send_json(handler, 400, {"ok": False, "error": "Unknown field"})
        return

    section, key, normaliser = _SERVICE_FIELD_MAP[field]

    try:
        normalised = normaliser(value)
    except Exception as e:
        send_json(handler, 400, {"ok": False, "error": f"Invalid value: {e}"})
        return

    try:
        with CONFIG_IO_LOCK:
            cfg = load_config(state.config_path)
            p = parse_config(cfg)
            cfg.setdefault(section, {})[key] = normalised
            save_config(state.config_path, cfg)

        # Build live-update args from the pre-write parse, substituting the one
        # changed key. This avoids a second parse_config call on the same object.
        if section == "audio1":
            a = p.audio1
            update_playback_input_config(
                1,
                enabled=True,
                is_turntable=a.is_turntable,
                stylus_life_hours=normalised if key == "stylus_life_hours" else a.stylus_life_hours,
                belt_life_hours=normalised if key == "belt_life_hours" else a.belt_life_hours,
                belt_life_years=normalised if key == "belt_life_years" else a.belt_life_years,
                bearing_life_hours=normalised if key == "bearing_life_hours" else a.bearing_life_hours,
                bearing_life_years=normalised if key == "bearing_life_years" else a.bearing_life_years,
            )
        else:
            a = p.audio2
            update_playback_input_config(
                2,
                enabled=p.audio2_enabled,
                is_turntable=a.is_turntable,
                stylus_life_hours=normalised if key == "stylus_life_hours" else a.stylus_life_hours,
                belt_life_hours=normalised if key == "belt_life_hours" else a.belt_life_hours,
                belt_life_years=normalised if key == "belt_life_years" else a.belt_life_years,
                bearing_life_hours=normalised if key == "bearing_life_hours" else a.bearing_life_hours,
                bearing_life_years=normalised if key == "bearing_life_years" else a.bearing_life_years,
            )
    except Exception as e:
        logging.exception("send_service_config_json: save failed")
        send_json(handler, 200, {"ok": False, "error": str(e)})
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
        _playback = get_playback_snapshot()
        _snap = _playback.inputs.get(_input_idx)
        if _snap is None:
            _snap = _fallback_input_snapshot(_audio, _input_idx, enabled=True)
        _hd = _hours_display(_item, _life_hours, _snap)
        _td = _time_display(_item, _life_years, _snap)
        _display = {**_hd, **_td, **_card_display(_item, _hd, _td, _is_turntable)}
    except Exception:
        logging.exception("send_service_config_json: display computation failed")

    send_json(handler, 200, {"ok": True, "field": field, "value": str(normalised), "display": _display})


def send_service_reset_json(handler, state: WebUIState, body: str) -> None:
    """POST /api/service/reset — reset one maintenance item counter.

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
        send_json(handler, 400, {"ok": False, "error": "Invalid request body"})
        return

    if item not in ("stylus", "belt", "bearing"):
        send_json(handler, 400, {"ok": False, "error": "Unknown item"})
        return
    if input_index not in (1, 2):
        send_json(handler, 400, {"ok": False, "error": "Input must be 1 or 2"})
        return

    # Load config for life thresholds before resetting (used by display computation).
    _life_hours   = 0
    _life_years   = 0
    _is_turntable = False
    _parsed       = None
    _audio_cfg    = None
    try:
        _parsed = _config_snapshot(state)
        _audio_cfg    = _parsed.audio1 if input_index == 1 else _parsed.audio2
        _life_hours   = int(getattr(_audio_cfg, f"{item}_life_hours", 0) or 0)
        _life_years   = int(getattr(_audio_cfg, f"{item}_life_years", 0) or 0) if item != "stylus" else 0
        _is_turntable = bool(getattr(_audio_cfg, "is_turntable", False))
    except Exception:
        logging.exception("send_service_reset_json: config load for display failed")

    reset_fn = {"stylus": reset_input_stylus, "belt": reset_input_belt, "bearing": reset_input_bearing}[item]
    result = reset_fn(input_index)

    if not result.applied:
        send_json(handler, 200, {"ok": False, "error": "Reset could not be applied"})
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
        _playback = get_playback_snapshot()
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

    send_json(handler, 200, response)


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


# -----------------------------------------------------------------------------
# Output EQ JSON endpoints
# -----------------------------------------------------------------------------

def send_output_eq_config_json(handler, state, body: str) -> None:
    """POST /api/output_eq/config — auto-save one output EQ field.

    Request body (JSON):
        { "field": "<field_name>", "value": "<raw_value>" }

    Accepted fields:
        gain_db, auto_trim_enabled, peq1_db … peq6_db
    """
    try:
        payload = json.loads(body or "{}")
        field = str(payload.get("field", "")).strip()
        value_raw = str(payload.get("value", "")).strip()
    except Exception:
        send_json(handler, 400, {"ok": False, "error": "Invalid request body"})
        return

    try:
        ok, normalised_str, err = apply_eq_field(state.config_path, field, value_raw)
    except ValueError as e:
        send_json(handler, 400, {"ok": False, "error": str(e)})
        return

    if not ok:
        send_json(handler, 200, {"ok": False, "error": err})
        return

    send_json(handler, 200, {"ok": True, "field": field, "value": normalised_str})


def send_output_eq_reset_json(handler, state) -> None:
    """POST /api/output_eq/reset — zero all EQ bands; does not change output gain or auto-trim."""
    ok, err = apply_eq_reset(state.config_path)
    if not ok:
        send_json(handler, 200, {"ok": False, "error": err})
        return
    send_json(handler, 200, {"ok": True})


def send_output_eq_status_json(handler) -> None:
    """GET /api/output_eq/status — return live output trim state from the monitor.

    Response (JSON):
        { "ok": true,
          "output_auto_trim_enabled": bool,
          "output_auto_trim_db": float,
          "effective_output_gain_db": float }
    or on monitor unavailable:
        { "ok": false, "error": "Monitor unavailable" }
    """
    status = get_live_output_eq_status()
    if status is None:
        send_json(handler, 200, {"ok": False, "error": "Monitor unavailable"})
        return
    send_json(handler, 200, {"ok": True, **status})


# ---------------------------------------------------------------------------
# Dial API handlers
# ---------------------------------------------------------------------------

_audio_status_fail_count = 0


def send_audio_status_json(handler, state: WebUIState) -> None:
    """GET /api/audio/status — unauthenticated, read-only.

    Returns a fresh snapshot of currently selected OwnTone output names and
    playing state.  Both exceptions and result.ok == False increment the
    failure counter; it only resets on a true success.  WARNING on the 1st
    and every 10th failure; DEBUG between.
    """
    global _audio_status_fail_count
    playing = any_monitor_capturing()
    try:
        parsed = _config_snapshot(state)
    except Exception as e:
        logging.warning("audio/status: config load failed: %s", e)
        send_json(handler, 200, {"playing": playing, "outputs": None,
                                 "error": "backend_unavailable"})
        return
    try:
        result = list_outputs(parsed.owntone.base_url, timeout=2)
    except Exception as e:
        _audio_status_fail_count += 1
        n = _audio_status_fail_count
        if n == 1 or n % 10 == 0:
            logging.warning("audio/status: list_outputs failed (call #%d): %s", n, e)
        else:
            logging.debug("audio/status: list_outputs failed: %s", e)
        send_json(handler, 200, {"playing": playing, "outputs": None,
                                 "error": "backend_unavailable"})
        return
    if not result.ok:
        _audio_status_fail_count += 1
        n = _audio_status_fail_count
        if n == 1 or n % 10 == 0:
            logging.warning("audio/status: list_outputs not ok (call #%d): %s",
                            n, result.message)
        else:
            logging.debug("audio/status: list_outputs not ok: %s",
                          result.message)
        send_json(handler, 200, {"playing": playing, "outputs": None,
                                 "error": "backend_unavailable"})
        return
    _audio_status_fail_count = 0
    names = [o.name for o in result.outputs if o.selected]
    send_json(handler, 200, {"playing": playing, "outputs": names})


_volume_lock = threading.Lock()

# Mute state — protected by _volume_lock
_mute_snapshot: dict[str, int] = {}   # output_id → pre-mute volume_percent
_mute_pending: Optional[str] = None   # "mute" | "restore" | None


def send_dial_volume_post_json(handler, state: WebUIState, json_obj: dict) -> None:
    """POST /api/dial/volume — UUID-auth only (no session/CSRF required).

    Applies a volume delta to all selected OwnTone outputs proportionally.
    Returns {"ok": true, "volume": <new_master>} on success.
    """
    dial_id = json_obj.get("dial_id", "")
    delta = json_obj.get("delta")

    if not isinstance(dial_id, str) or not dial_id:
        send_json(handler, 403, {})
        return
    if not is_dial_authorized(dial_id):
        send_json(handler, 403, {})
        return
    if not isinstance(delta, int) or isinstance(delta, bool):
        send_json(handler, 200, {"ok": False, "error": "invalid_delta"})
        return
    delta = max(-100, min(100, delta))

    try:
        parsed = _config_snapshot(state)
        base_url = parsed.owntone.base_url
    except Exception as e:
        logging.warning("dial volume: config load failed: %s", e)
        send_json(handler, 200, {"ok": False, "error": "config_error"})
        return

    with _volume_lock:
        result = list_outputs(base_url, timeout=3)
        if not result.ok:
            send_json(handler, 200, {"ok": False, "error": "backend_unavailable"})
            return
        selected = [o for o in result.outputs if o.selected]
        if not selected:
            send_json(handler, 200, {"ok": False, "error": "no_active_outputs"})
            return
        current_master = round(sum(o.volume_percent for o in selected) / len(selected))
        new_master = max(0, min(100, current_master + delta))
        failed = 0
        for output in selected:
            new_vol = (new_master if current_master == 0
                       else max(0, min(100,
                           round(output.volume_percent * new_master / current_master))))
            r = update_output(base_url, output.id, volume_percent=new_vol, timeout=3)
            if not r.ok:
                logging.warning("update_output %s: %s", output.id, r.error)
                failed += 1

    if failed == len(selected):
        send_json(handler, 200, {"ok": False, "error": "all_outputs_failed"})
        return
    if failed:
        send_json(handler, 200, {"ok": True, "volume": new_master, "partial": True})
        return
    send_json(handler, 200, {"ok": True, "volume": new_master})


def calculate_master_volume(outputs) -> tuple:
    """Return (master_volume, selected_output_count) for selected outputs.

    For each selected output, volume_percent is converted to int and clamped to
    0..100.  Returns (round(sum/count), count), or (None, 0) when none selected.
    """
    volumes = [
        max(0, min(100, int(o.volume_percent)))
        for o in outputs
        if o.selected
    ]
    if not volumes:
        return (None, 0)
    return (round(sum(volumes) / len(volumes)), len(volumes))


def send_dial_status_post_json(handler, state: WebUIState, json_obj: dict) -> None:
    """POST /api/dial/status — UUID-auth only (no session/CSRF required).

    Returns fresh, side-effect-free playing state and master volume.
    """
    dial_id = json_obj.get("dial_id", "")
    if not isinstance(dial_id, str) or not dial_id:
        send_json(handler, 403, {})
        return
    if not is_dial_authorized(dial_id):
        send_json(handler, 403, {})
        return

    playing = any_monitor_capturing()

    try:
        parsed = _config_snapshot(state)
        base_url = parsed.owntone.base_url
    except Exception as e:
        logging.warning("dial status: config load failed: %s", e)
        send_json(handler, 200, {"ok": False, "error": "config_error"})
        return

    try:
        result = list_outputs(base_url, timeout=1.0)
    except Exception as e:
        logging.warning("dial status: list_outputs raised: %s", e)
        send_json(handler, 200, {"ok": False, "error": "backend_unavailable"})
        return

    if not result.ok:
        logging.warning("dial status: list_outputs not ok: %s", result.error)
        send_json(handler, 200, {"ok": False, "error": "backend_unavailable"})
        return

    master_volume, selected_output_count = calculate_master_volume(result.outputs)
    send_json(handler, 200, {
        "ok": True,
        "playing": playing,
        "master_volume": master_volume,
        "selected_output_count": selected_output_count,
    })


def send_dial_mute_post_json(handler, state: WebUIState, json_obj: dict) -> None:
    """POST /api/dial/mute — UUID-auth only (no session/CSRF required).

    Toggles mute state across all selected OwnTone outputs.  A snapshot of
    pre-mute volumes is kept so that the restore action can return each output
    to its original level.  The pending action is retained across partial
    failures so that a retry press completes the interrupted operation rather
    than toggling back too early.
    """
    global _mute_snapshot, _mute_pending

    dial_id = json_obj.get("dial_id", "")
    if not isinstance(dial_id, str) or not dial_id:
        send_json(handler, 403, {})
        return
    if not is_dial_authorized(dial_id):
        send_json(handler, 403, {})
        return

    try:
        parsed = _config_snapshot(state)
        base_url = parsed.owntone.base_url
        default_vol = parsed.owntone.volume_percent
    except Exception as e:
        logging.warning("dial mute: config load failed: %s", e)
        send_json(handler, 200, {"ok": False, "error": "config_error"})
        return

    with _volume_lock:
        result = list_outputs(base_url, timeout=3)
        if not result.ok:
            send_json(handler, 200, {"ok": False, "error": "backend_unavailable"})
            return
        selected = [o for o in result.outputs if o.selected]
        if not selected:
            send_json(handler, 200, {"ok": False, "error": "no_active_outputs"})
            return

        if _mute_pending is not None:
            action = _mute_pending
        elif any(o.volume_percent > 0 for o in selected):
            action = "mute"
        else:
            action = "restore"

        _mute_pending = action

        if action == "mute":
            targets = [o for o in selected if o.volume_percent > 0]
            if not targets:
                _mute_pending = None
                send_json(handler, 200, {"ok": True, "muted": True})
                return

            for o in targets:
                if o.id not in _mute_snapshot:
                    _mute_snapshot[o.id] = o.volume_percent

            succeeded = 0
            failed = 0
            for o in targets:
                r = update_output(base_url, o.id, volume_percent=0, timeout=3)
                if r.ok:
                    succeeded += 1
                else:
                    failed += 1
                    logging.warning("mute: update_output %s: %s", o.id, r.error)

            if not succeeded:
                send_json(handler, 200, {"ok": False, "error": "all_outputs_failed"})
                return

            if failed:
                send_json(handler, 200, {"ok": True, "muted": True, "partial": True})
                return

            _mute_pending = None
            send_json(handler, 200, {"ok": True, "muted": True})

        else:  # restore
            # Per-output decision:
            #  - In snapshot:            restore to the stored pre-mute volume.
            #  - Not in snapshot, vol=0: restore to default (new output selected while
            #                            muted, or state after a process restart where
            #                            the snapshot was lost).
            #  - Not in snapshot, vol>0: already successfully restored in a prior
            #                            partial attempt — skip to avoid overwriting the
            #                            correct volume with the wrong default.
            succeeded = 0
            failed = 0
            any_attempted = False
            for o in selected:
                if o.id in _mute_snapshot:
                    restore_vol = _mute_snapshot[o.id]
                elif o.volume_percent == 0:
                    restore_vol = default_vol
                else:
                    continue  # non-zero, not in snapshot: already restored — skip
                any_attempted = True
                r = update_output(base_url, o.id, volume_percent=restore_vol, timeout=3)
                if r.ok:
                    _mute_snapshot.pop(o.id, None)
                    succeeded += 1
                else:
                    failed += 1
                    logging.warning("restore: update_output %s: %s", o.id, r.error)

            if not any_attempted:
                # All selected outputs are already at non-zero; nothing left to do.
                _mute_pending = None
                _mute_snapshot.clear()
                send_json(handler, 200, {"ok": True, "muted": False})
                return

            if not succeeded:
                send_json(handler, 200, {"ok": False, "error": "all_outputs_failed"})
                return

            if failed:
                send_json(handler, 200, {"ok": True, "muted": False, "partial": True})
                return

            _mute_pending = None
            _mute_snapshot.clear()
            send_json(handler, 200, {"ok": True, "muted": False})


# ---------------------------------------------------------------------------
# Federation target API handlers (called by autostream_webui._dispatch_federation)
# ---------------------------------------------------------------------------

def send_federation_session_json(handler, source_ip: str) -> None:
    """POST /api/federation/v1/session — issue a short-lived bearer token.

    Rate-limited to 5 successful issuances per source IP per 60-second window.
    A rejected request does not consume an issuance slot.
    The token is never logged.
    """
    import autostream_federation
    token, value = autostream_federation.create_session(source_ip)
    if token is None:
        retry_after = value
        handler.send_response(429)
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        handler.send_header("Retry-After", str(retry_after))
        body = json.dumps({
            "ok": False,
            "error": "rate_limited",
            "retryable": True,
            "retry_after": retry_after,
        }).encode("utf-8")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)
        return
    send_json(handler, 200, {
        "ok": True,
        "token": token,
        "token_type": "Bearer",
        "expires_in": autostream_federation.EXPIRY_SECONDS,
        "federation_version": autostream_federation.FEDERATION_VERSION,
    })


def send_federation_home_json(handler, state: WebUIState) -> None:
    """GET /api/federation/v1/home — return aggregate Home state."""
    deadline = time.monotonic() + 1.5
    home = build_home_state(state.config_path, deadline=deadline)
    if not home.get("ok"):
        send_json(handler, 500, {"ok": False, "error": home.get("error", "internal_error")})
        return
    send_json(handler, 200, home)


def send_federation_output_json(handler, state: WebUIState, body_str: str) -> None:
    """POST /api/federation/v1/output — toggle or PIN-submit an AirPlay output."""
    try:
        body = json.loads(body_str)
    except (json.JSONDecodeError, ValueError):
        send_json(handler, 400, {"ok": False, "error": "invalid_json"})
        return
    if not isinstance(body, dict):
        send_json(handler, 400, {"ok": False, "error": "invalid_request_body"})
        return

    out_id = str(body.get("id") or "").strip()
    if not out_id:
        send_json(handler, 400, {"ok": False, "error": "missing_output_id"})
        return

    try:
        parsed = _config_snapshot(state)
        base_url = parsed.owntone.base_url.rstrip("/")
        from autostream_player_service import config_airplay_mode_to_backend
        from autostream_config import DEFAULT_AIRPLAY_MODE
        offset_ms_raw = parsed.owntone.output_offsets_ms.get(out_id)
        offset_ms = int(offset_ms_raw) if offset_ms_raw is not None else None
        mode_text = parsed.owntone.output_airplay_modes.get(out_id, DEFAULT_AIRPLAY_MODE)
        mode = config_airplay_mode_to_backend(mode_text)
    except Exception as e:
        logging.error("federation output: config error: %s", e)
        send_json(handler, 500, {"ok": False, "error": "internal_error"})
        return

    # Sanitize: forward only the documented operation fields, never raw browser body
    sanitized: dict = {"id": out_id}
    op = str(body.get("op") or "").strip().lower()
    if op == "pin":
        pin_val = str(body.get("pin") or "")
        if not pin_val:
            send_json(handler, 400, {"ok": False, "error": "invalid_request_body"})
            return
        sanitized["op"] = "pin"
        sanitized["pin"] = pin_val
    elif op == "":
        selected_raw = body.get("selected")
        if not isinstance(selected_raw, bool):
            send_json(handler, 400, {"ok": False, "error": "invalid_request_body"})
            return
        sanitized["selected"] = selected_raw
        raw_vol = body.get("volume")
        if raw_vol is not None:
            try:
                sanitized["volume"] = max(0, min(100, int(raw_vol)))
            except (ValueError, TypeError):
                sanitized["volume"] = 50
        else:
            sanitized["volume"] = 50
    else:
        send_json(handler, 400, {"ok": False, "error": "invalid_request_body"})
        return

    result = apply_output_mutation(base_url, out_id, sanitized, offset_ms=offset_ms, mode=mode)
    send_json(handler, 200, result)


def send_federation_equaliser_json(handler, state: WebUIState) -> None:
    """GET /api/federation/v1/equaliser — return aggregate Equaliser state."""
    eq = build_equaliser_state(state.config_path)
    if not eq.get("ok"):
        send_json(handler, 500, {"ok": False, "error": eq.get("error", "internal_error")})
        return
    send_json(handler, 200, eq)


def send_federation_eq_config_json(handler, state: WebUIState, body_str: str) -> None:
    """POST /api/federation/v1/equaliser/config — apply one EQ field."""
    try:
        payload = json.loads(body_str)
    except (json.JSONDecodeError, ValueError):
        send_json(handler, 400, {"ok": False, "error": "invalid_json"})
        return
    if not isinstance(payload, dict):
        send_json(handler, 400, {"ok": False, "error": "invalid_request_body"})
        return
    field = str(payload.get("field", "")).strip()
    value_raw = str(payload.get("value", "")).strip()
    try:
        ok, normalised_str, err = apply_eq_field(state.config_path, field, value_raw)
    except ValueError as e:
        send_json(handler, 400, {"ok": False, "error": str(e)})
        return
    if not ok:
        send_json(handler, 500, {"ok": False, "error": err or "internal_error"})
        return
    send_json(handler, 200, {"ok": True, "field": field, "value": normalised_str})


def send_federation_eq_reset_json(handler, state: WebUIState) -> None:
    """POST /api/federation/v1/equaliser/reset — zero all EQ bands; does not change output gain or auto-trim."""
    ok, err = apply_eq_reset(state.config_path)
    if not ok:
        send_json(handler, 500, {"ok": False, "error": err or "internal_error"})
        return
    send_json(handler, 200, {"ok": True})


def send_federation_eq_status_json(handler, state: WebUIState) -> None:  # noqa: ARG001
    """GET /api/federation/v1/equaliser/status — return live trim state."""
    status = get_live_output_eq_status()
    if status is None:
        send_json(handler, 200, {"ok": False, "error": "monitor_unavailable"})
        return
    send_json(handler, 200, {"ok": True, **status})
