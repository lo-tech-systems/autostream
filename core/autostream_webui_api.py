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
import os
import subprocess
import threading
import time

from typing import Optional

from autostream_config import (
    BUFFERED_AIRPLAY_MODES,
    CONFIG_IO_LOCK,
    DEFAULT_AIRPLAY_MODE,
    OUTPUT_USAGE_POLL_INTERVAL_MAX,
    OUTPUT_USAGE_POLL_INTERVAL_MIN,
    REPEAT_CODEC_CHOICES,
    load_config,
    load_state,
    normalize_airplay_mode,
    normalize_output_usage_poll_interval,
    normalize_repeat_codec,
    normalize_track_id_analysis_lead_in_seconds,
    normalize_track_id_refresh_seconds,
    normalize_track_id_track_change_silence_seconds,
    normalize_update_channel,
    parse_config,
    save_config,
    save_state,
    set_input_mode,
)
from autostream_dials import is_dial_authorized
from autostream_core import (
    any_monitor_capturing,
    apply_track_id_config_live_from_parsed,
    get_live_output_eq_status,
    get_monitor_levels_dbfs,
    get_owntone_selfheal_state,
    get_playback_snapshot,
    get_repeat_status,
    get_session_state,
    request_config_reload,
    reset_input_belt,
    reset_input_bearing,
    reset_input_stylus,
    set_live_input_eq,
    set_live_input_gain,
    set_live_output_auto_trim,
    set_live_output_eq,
    set_live_output_gain,
    set_live_repeat_armed,
    set_live_repeat_enabled,
    update_live_owntone_runtime,
    update_live_silence_seconds,
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
from autostream_player_service import list_outputs, save_setting, update_output
from autostream_sysutils import get_system_hostname, run_admin_cmd, set_system_hostname
from urllib.parse import urlparse as _urlparse
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
    # Unified playback-session state: the authoritative
    # "playing" signal is session.active, not a raw is_capturing check,
    # so replay (daemon-side, no input is "capturing") correctly reports as
    # playing. Falls back to any_monitor_capturing() only if the session
    # cache is unavailable for some reason -- keeps this endpoint's existing
    # never-raise contract.
    try:
        session_state = get_session_state()
    except Exception:
        session_state = {"active": any_monitor_capturing(), "source": None}
    is_playing = bool(session_state.get("active"))
    response = {
        "playing": is_playing,
        "status_text": _status_text_for_home(is_playing, input_levels),
        "status_class": "playing" if is_playing else "waiting",
        "input_levels": input_levels,
        "playback": playback_dict,
        "playback_banner_text": warnings.get("stylus"),
        "belt_banner_text": warnings.get("belt"),
        "bearing_banner_text": warnings.get("bearing"),
        "track_identification": ti_dict,
        # Always present (unlike "repeat" below): the session tracker runs
        # regardless of whether the repeat feature/block exists at all.
        "session": session_state,
    }
    # Pass the daemon's "repeat" status block through verbatim when present.
    # An old binary that never reports it means the key is
    # omitted entirely -- no KeyError, feature-unsupported by absence.
    try:
        repeat_status = get_repeat_status()
    except Exception:
        repeat_status = None
    if repeat_status is not None:
        response["repeat"] = repeat_status
    # Reconcile/watchdog counters, always present (coordinator-owned
    # state, not a daemon-optional block like "repeat") -- lets the Web UI or
    # support tooling see that self-healing fired without grepping logs.
    try:
        response["owntone_selfheal"] = get_owntone_selfheal_state()
    except Exception:
        pass
    send_json(handler, 200, response)


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
        from autostream_settings import SettingsStore as _SettingsStore
        _store = getattr(state, "settings", None)
        if isinstance(_store, _SettingsStore):
            p = _store.snapshot()
            _store.update(lambda raw: raw.setdefault(section, {}).update({key: normalised}))
        else:
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
        ok, normalised_str, err = apply_eq_field(
            state.config_path, field, value_raw,
            settings=getattr(state, "settings", None),
        )
    except ValueError as e:
        send_json(handler, 400, {"ok": False, "error": str(e)})
        return

    if not ok:
        send_json(handler, 200, {"ok": False, "error": err})
        return

    send_json(handler, 200, {"ok": True, "field": field, "value": normalised_str})


def send_output_eq_reset_json(handler, state) -> None:
    """POST /api/output_eq/reset — zero all EQ bands; does not change output gain or auto-trim."""
    ok, err = apply_eq_reset(state.config_path, settings=getattr(state, "settings", None))
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


def _dial_track_id_dict() -> dict:
    """Return the grouped track_id object for POST /api/dial/status.

    artwork_url is exposed only for identified results with a validated
    http(s) provider URL — every other state reports an empty string.
    """
    from autostream_core import get_active_track_identification_snapshot
    from track_id.models import STATE_IDENTIFIED

    snap = get_active_track_identification_snapshot()
    artwork_url = snap.artwork_url or ""
    if snap.state != STATE_IDENTIFIED or not artwork_url.startswith(("http://", "https://")):
        artwork_url = ""
    return {
        "enabled": snap.enabled,
        "state": snap.state,
        "title": snap.title,
        "artist": snap.artist,
        "album": snap.album,
        "artwork_url": artwork_url,
        "updated_at": snap.updated_at,
        "last_attempt_at": snap.last_attempt_at,
    }


def send_dial_status_post_json(handler, state: WebUIState, json_obj: dict) -> None:
    """POST /api/dial/status — UUID-auth only (no session/CSRF required).

    Returns fresh, side-effect-free playing state, master volume, and grouped
    track_id now-playing state. Never fetches remote artwork on the request path.
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
        "track_id": _dial_track_id_dict(),
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
        ok, normalised_str, err = apply_eq_field(
            state.config_path, field, value_raw,
            settings=getattr(state, "settings", None),
        )
    except ValueError as e:
        send_json(handler, 400, {"ok": False, "error": str(e)})
        return
    if not ok:
        send_json(handler, 500, {"ok": False, "error": err or "internal_error"})
        return
    send_json(handler, 200, {"ok": True, "field": field, "value": normalised_str})


def send_federation_eq_reset_json(handler, state: WebUIState) -> None:
    """POST /api/federation/v1/equaliser/reset — zero all EQ bands; does not change output gain or auto-trim."""
    ok, err = apply_eq_reset(state.config_path, settings=getattr(state, "settings", None))
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


# ---------------------------------------------------------------------------
# WP3 - Generic settings API
# ---------------------------------------------------------------------------

def _validate_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    raise ValueError("Value must be true or false")


def _validate_poll_interval(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("Value must be a number")
    iv = int(value)
    if iv < OUTPUT_USAGE_POLL_INTERVAL_MIN or iv > OUTPUT_USAGE_POLL_INTERVAL_MAX:
        raise ValueError(
            f"Value must be between {OUTPUT_USAGE_POLL_INTERVAL_MIN}"
            f" and {OUTPUT_USAGE_POLL_INTERVAL_MAX}"
        )
    return iv


def _validate_update_channel(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("Value must be 'stable' or 'dev'")
    if value.strip().lower() not in ("stable", "dev"):
        raise ValueError("Value must be 'stable' or 'dev'")
    return normalize_update_channel(value)


def _validate_gain_db(value: object) -> float:
    import math
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("Value must be a number")
    v = float(value)
    if not math.isfinite(v) or v < -10.0 or v > 10.0:
        raise ValueError("Value must be between -10 and 10")
    return v


def _validate_volume_percent(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("Value must be a number")
    v = int(value)
    if v < 0 or v > 100:
        raise ValueError("Value must be between 0 and 100")
    return v


def _validate_silence_seconds(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("Value must be a number")
    v = int(value)
    if v < 10 or v > 300:
        raise ValueError("Value must be between 10 and 300")
    return v


def _validate_output_name(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("Value must be a string")
    v = value.strip()
    if not v:
        raise ValueError("Value must be a non-empty string")
    return v


def _live_gain_1(state: object, value: object) -> bool:
    return bool(set_live_input_gain(1, float(value)))


def _live_gain_2(state: object, value: object) -> bool:
    return bool(set_live_input_gain(2, float(value)))


def _live_eq_1(state: object, value: object) -> bool:
    from autostream_settings import SettingsStore as _SettingsStore
    settings = getattr(state, "settings", None)
    if not isinstance(settings, _SettingsStore):
        return False
    snap = settings.snapshot()
    return bool(set_live_input_eq(
        1,
        eq_40hz_db=snap.audio1.eq_40hz_db,
        eq_100hz_db=snap.audio1.eq_100hz_db,
        eq_8khz_db=snap.audio1.eq_8khz_db,
    ))


def _live_eq_2(state: object, value: object) -> bool:
    from autostream_settings import SettingsStore as _SettingsStore
    settings = getattr(state, "settings", None)
    if not isinstance(settings, _SettingsStore):
        return False
    snap = settings.snapshot()
    return bool(set_live_input_eq(
        2,
        eq_40hz_db=snap.audio2.eq_40hz_db,
        eq_100hz_db=snap.audio2.eq_100hz_db,
        eq_8khz_db=snap.audio2.eq_8khz_db,
    ))


def _live_owntone_name(state: object, value: object) -> bool:
    from autostream_settings import SettingsStore as _SettingsStore
    settings = getattr(state, "settings", None)
    if not isinstance(settings, _SettingsStore):
        return False
    snap = settings.snapshot()
    return bool(update_live_owntone_runtime(
        output_name=str(value),
        volume_percent=snap.owntone.volume_percent,
        output_offsets_ms=snap.owntone.output_offsets_ms,
        output_airplay_modes=snap.owntone.output_airplay_modes,
    ))


def _live_owntone_volume(state: object, value: object) -> bool:
    from autostream_settings import SettingsStore as _SettingsStore
    settings = getattr(state, "settings", None)
    if not isinstance(settings, _SettingsStore):
        return False
    snap = settings.snapshot()
    return bool(update_live_owntone_runtime(
        output_name=snap.owntone.output_name,
        volume_percent=int(value),
        output_offsets_ms=snap.owntone.output_offsets_ms,
        output_airplay_modes=snap.owntone.output_airplay_modes,
    ))


def _live_silence(state: object, value: object) -> bool:
    return bool(update_live_silence_seconds(int(value)))


def _validate_repeat_codec(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError(f"Value must be one of {', '.join(REPEAT_CODEC_CHOICES)}")
    v = value.strip().lower()
    if v not in REPEAT_CODEC_CHOICES:
        raise ValueError(f"Value must be one of {', '.join(REPEAT_CODEC_CHOICES)}")
    return normalize_repeat_codec(v)


def _live_repeat_enabled(state: object, value: object) -> bool:
    from autostream_settings import SettingsStore as _SettingsStore
    settings = getattr(state, "settings", None)
    if not isinstance(settings, _SettingsStore):
        return False
    snap = settings.snapshot()
    return bool(set_live_repeat_enabled(bool(value), snap.repeat.codec))


def _live_repeat_codec(state: object, value: object) -> bool:
    from autostream_settings import SettingsStore as _SettingsStore
    settings = getattr(state, "settings", None)
    if not isinstance(settings, _SettingsStore):
        return False
    snap = settings.snapshot()
    return bool(set_live_repeat_enabled(snap.repeat.enabled, str(value)))


# ---------------------------------------------------------------------------
# WP4B — validators, debounce helpers, and live functions
# ---------------------------------------------------------------------------

def _validate_capture_device(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("Value must be a string")
    v = value.strip()
    if not v:
        raise ValueError("Value must be a non-empty string")
    return v


def _validate_track_id_lead_in(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("Value must be a number")
    return normalize_track_id_analysis_lead_in_seconds(value)


def _validate_track_id_refresh(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("Value must be a number")
    return normalize_track_id_refresh_seconds(value)


def _validate_track_id_silence(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("Value must be a number")
    return normalize_track_id_track_change_silence_seconds(value)


# Debounce helpers — module-level timer state protected by a threading lock.
# The coordinator reload timer calls save_now() before signalling so the
# coordinator always reads up-to-date settings from disk.

_coordinator_reload_lock = threading.Lock()
_coordinator_reload_timer: Optional[threading.Timer] = None

_track_id_rebuild_lock = threading.Lock()
_track_id_rebuild_timer: Optional[threading.Timer] = None


def _debounce_coordinator_reload(state: object, delay: float = 0.3) -> None:
    global _coordinator_reload_timer
    with _coordinator_reload_lock:
        if _coordinator_reload_timer is not None:
            _coordinator_reload_timer.cancel()

        def _do_reload():
            from autostream_settings import SettingsStore as _SettingsStore
            settings = getattr(state, "settings", None)
            if isinstance(settings, _SettingsStore):
                settings.save_now()
            request_config_reload()

        _coordinator_reload_timer = threading.Timer(delay, _do_reload)
        _coordinator_reload_timer.daemon = True
        _coordinator_reload_timer.start()


def _debounce_track_id_rebuild(state: object, delay: float = 0.3) -> None:
    global _track_id_rebuild_timer
    with _track_id_rebuild_lock:
        if _track_id_rebuild_timer is not None:
            _track_id_rebuild_timer.cancel()

        def _do_rebuild():
            from autostream_settings import SettingsStore as _SettingsStore
            settings = getattr(state, "settings", None)
            if isinstance(settings, _SettingsStore):
                try:
                    snap = settings.snapshot()
                    apply_track_id_config_live_from_parsed(snap)
                except Exception:
                    logging.exception("debounced track-ID rebuild failed")

        _track_id_rebuild_timer = threading.Timer(delay, _do_rebuild)
        _track_id_rebuild_timer.daemon = True
        _track_id_rebuild_timer.start()


def _live_capture_1(state: object, value: object) -> bool:
    _debounce_coordinator_reload(state)
    return True


def _live_capture_2(state: object, value: object) -> bool:
    _debounce_coordinator_reload(state)
    return True


def _live_audio2_enabled(state: object, value: object) -> bool:
    from autostream_settings import SettingsStore as _SettingsStore
    settings = getattr(state, "settings", None)
    if isinstance(settings, _SettingsStore):
        snap = settings.snapshot()
        update_playback_input_config(
            2,
            enabled=bool(value),
            is_turntable=snap.audio2.is_turntable,
            stylus_life_hours=snap.audio2.stylus_life_hours,
            belt_life_hours=snap.audio2.belt_life_hours,
            belt_life_years=snap.audio2.belt_life_years,
            bearing_life_hours=snap.audio2.bearing_life_hours,
            bearing_life_years=snap.audio2.bearing_life_years,
        )
    _debounce_coordinator_reload(state)
    return True


def _live_turntable_1(state: object, value: object) -> bool:
    from autostream_settings import SettingsStore as _SettingsStore
    settings = getattr(state, "settings", None)
    if isinstance(settings, _SettingsStore):
        snap = settings.snapshot()
        update_playback_input_config(
            1,
            enabled=True,
            is_turntable=bool(value),
            stylus_life_hours=snap.audio1.stylus_life_hours,
            belt_life_hours=snap.audio1.belt_life_hours,
            belt_life_years=snap.audio1.belt_life_years,
            bearing_life_hours=snap.audio1.bearing_life_hours,
            bearing_life_years=snap.audio1.bearing_life_years,
        )
    _debounce_coordinator_reload(state)
    return True


def _live_turntable_2(state: object, value: object) -> bool:
    from autostream_settings import SettingsStore as _SettingsStore
    settings = getattr(state, "settings", None)
    if isinstance(settings, _SettingsStore):
        snap = settings.snapshot()
        update_playback_input_config(
            2,
            enabled=snap.audio2_enabled,
            is_turntable=bool(value),
            stylus_life_hours=snap.audio2.stylus_life_hours,
            belt_life_hours=snap.audio2.belt_life_hours,
            belt_life_years=snap.audio2.belt_life_years,
            bearing_life_hours=snap.audio2.bearing_life_hours,
            bearing_life_years=snap.audio2.bearing_life_years,
        )
    _debounce_coordinator_reload(state)
    return True


def _live_track_id(state: object, value: object) -> bool:
    _debounce_track_id_rebuild(state)
    return True


# Maps public dotted field name → (section, key, validator, live_fn_or_None)
_SETTINGS_FIELDS: dict = {
    # WP3 — personalisation (no live effect)
    "webui.dark_mode":                          ("webui",   "dark_mode",                         _validate_bool,            None),
    "webui.show_master_volume":                 ("webui",   "show_master_volume",                 _validate_bool,            None),
    "webui.show_input_detail":                  ("webui",   "show_input_detail",                  _validate_bool,            None),
    "webui.show_hostname_on_home":              ("webui",   "show_hostname_on_home",              _validate_bool,            None),
    "webui.control_other_appliances":           ("webui",   "control_other_appliances",           _validate_bool,            None),
    "webui.output_usage_poll_interval_seconds": ("webui",   "output_usage_poll_interval_seconds", _validate_poll_interval,   None),
    "updates.update_channel":                   ("updates", "update_channel",                     _validate_update_channel,  None),
    # WP4A — audio input gain/EQ (live: monitor)
    "audio1.gain_db":                           ("audio1",  "gain_db",                            _validate_gain_db,         _live_gain_1),
    "audio2.gain_db":                           ("audio2",  "gain_db",                            _validate_gain_db,         _live_gain_2),
    "audio1.eq_40hz_db":                        ("audio1",  "eq_40hz_db",                         _validate_gain_db,         _live_eq_1),
    "audio1.eq_100hz_db":                       ("audio1",  "eq_100hz_db",                        _validate_gain_db,         _live_eq_1),
    "audio1.eq_8khz_db":                        ("audio1",  "eq_8khz_db",                         _validate_gain_db,         _live_eq_1),
    "audio2.eq_40hz_db":                        ("audio2",  "eq_40hz_db",                         _validate_gain_db,         _live_eq_2),
    "audio2.eq_100hz_db":                       ("audio2",  "eq_100hz_db",                        _validate_gain_db,         _live_eq_2),
    "audio2.eq_8khz_db":                        ("audio2",  "eq_8khz_db",                         _validate_gain_db,         _live_eq_2),
    # WP4A — OwnTone playback defaults (live: owntone runtime)
    "owntone.output_name":                      ("owntone", "output_name",                        _validate_output_name,     _live_owntone_name),
    "owntone.volume_percent":                   ("owntone", "volume_percent",                     _validate_volume_percent,  _live_owntone_volume),
    # WP4A — silence detection (live: monitor)
    "general.silence_seconds":                  ("general", "silence_seconds",                    _validate_silence_seconds,        _live_silence),
    # WP4B — audio input capture device (live: coordinator reload debounce)
    "audio1.capture_device":                    ("audio1",  "capture_device",                     _validate_capture_device,         _live_capture_1),
    "audio2.capture_device":                    ("audio2",  "capture_device",                     _validate_capture_device,         _live_capture_2),
    # WP4B — audio2 enabled (live: playback tracker + coordinator reload debounce)
    "audio2.enabled":                           ("audio2",  "enabled",                            _validate_bool,                   _live_audio2_enabled),
    # WP4B — turntable mode (atomic mutation with derived silence_threshold; live: playback tracker + coordinator reload debounce)
    "audio1.turntable":                         ("audio1",  "turntable",                          _validate_bool,                   _live_turntable_1),
    "audio2.turntable":                         ("audio2",  "turntable",                          _validate_bool,                   _live_turntable_2),
    # WP4B — track identification (live: track-ID rebuild debounce)
    "track_identification.enabled":             ("track_identification", "enabled",               _validate_bool,                   _live_track_id),
    "track_identification.analysis_lead_in_seconds": ("track_identification", "analysis_lead_in_seconds", _validate_track_id_lead_in, _live_track_id),
    "track_identification.refresh_seconds":     ("track_identification", "refresh_seconds",        _validate_track_id_refresh,       _live_track_id),
    "track_identification.track_change_silence_seconds": ("track_identification", "track_change_silence_seconds", _validate_track_id_silence, _live_track_id),
    # Repeat recording (live: monitor daemon; NOT _debounce_coordinator_reload
    # -- toggling this must not tear down the playback it governs)
    "repeat.enabled":                           ("repeat",  "enabled",                            _validate_bool,                   _live_repeat_enabled),
    "repeat.codec":                             ("repeat",  "codec",                              _validate_repeat_codec,           _live_repeat_codec),
}


def send_settings_get_json(handler, state) -> None:
    """GET /api/settings — return all browser-editable non-secret settings."""
    try:
        parsed = _config_snapshot(state)
    except Exception as e:
        send_json(handler, 200, {"ok": False, "error": str(e)})
        return
    values = {
        "webui.dark_mode":                         parsed.webui.dark_mode,
        "webui.show_master_volume":                parsed.webui.show_master_volume,
        "webui.show_input_detail":                 parsed.webui.show_input_detail,
        "webui.show_hostname_on_home":             parsed.webui.show_hostname_on_home,
        "webui.control_other_appliances":          parsed.webui.control_other_appliances,
        "webui.output_usage_poll_interval_seconds": parsed.webui.output_usage_poll_interval_seconds,
        "updates.update_channel":                  parsed.updates.update_channel,
        "repeat.enabled":                          parsed.repeat.enabled,
        "repeat.codec":                            parsed.repeat.codec,
    }
    send_json(handler, 200, {"ok": True, "values": values})


def send_settings_post_json(handler, state, json_obj: dict) -> None:
    """POST /api/settings — update one named setting via the SettingsStore.

    Request: {"field": "<dotted.name>", "value": <json_value>}

    Success (HTTP 200):  {"ok": true, "field": "...", "value": <normalised>}
    Validation failure (HTTP 400): {"ok": false, "field": "...", "error": "..."}
    """
    if not isinstance(json_obj, dict):
        send_json(handler, 400, {"ok": False, "error": "JSON object required"})
        return

    field = json_obj.get("field")
    if not isinstance(field, str) or not field.strip():
        send_json(handler, 400, {"ok": False, "field": "", "error": "field must be a non-empty string"})
        return
    field = field.strip()

    if "value" not in json_obj:
        send_json(handler, 400, {"ok": False, "field": field, "error": "value is required"})
        return

    if field not in _SETTINGS_FIELDS:
        send_json(handler, 400, {"ok": False, "field": field, "error": "Unknown field"})
        return

    section, key, validator, live_fn = _SETTINGS_FIELDS[field]
    raw_value = json_obj["value"]

    try:
        normalized = validator(raw_value)
    except ValueError as e:
        send_json(handler, 400, {"ok": False, "field": field, "error": str(e)})
        return

    from autostream_settings import SettingsStore as _SettingsStore
    settings = getattr(state, "settings", None)
    if not isinstance(settings, _SettingsStore):
        send_json(handler, 200, {"ok": False, "field": field, "error": "Settings store unavailable"})
        return

    def _mutator(raw: dict) -> None:
        if field in ("audio1.turntable", "audio2.turntable"):
            set_input_mode(raw, int(section[-1]), bool(normalized))
            return
        raw.setdefault(section, {})[key] = normalized
        # Turning off hostname display also forces control_other_appliances off.
        if field == "webui.show_hostname_on_home" and not normalized:
            raw.setdefault("webui", {})["control_other_appliances"] = False

    try:
        settings.update(_mutator)
    except Exception:
        logging.exception("send_settings_post_json: store update failed")
        send_json(handler, 200, {"ok": False, "field": field, "error": "Internal error"})
        return

    resp: dict = {"ok": True, "field": field, "value": normalized}
    if live_fn is not None:
        try:
            live_ok = bool(live_fn(state, normalized))
        except Exception:
            logging.exception("send_settings_post_json: live effect failed for %s", field)
            live_ok = False
        resp["live"] = live_ok
        if not live_ok:
            resp["live_error"] = "Live effect could not be applied"
    send_json(handler, 200, resp)


def send_repeat_post_json(handler, state, body: str) -> None:
    """POST /api/repeat — arm/disarm repeat-recording replay.

    Request: {"armed": bool}

    Session arm is runtime-only: no settings write accompanies
    this call, and current armed/replay state is read back from /api/status
    (the daemon is the single source of truth -- no WebUIState mirror).

    Success (HTTP 200):  {"ok": true, "armed": <bool>}
    Validation failure (HTTP 400): {"ok": false, "error": "..."}
    Live-apply failure (HTTP 200, ok:false): daemon rejected/unreachable
        (e.g. an older monitor binary that does not support the command).
    """
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return

    if not isinstance(payload, dict):
        send_json(handler, 400, {"ok": False, "error": "JSON object required"})
        return

    if "armed" not in payload:
        send_json(handler, 400, {"ok": False, "error": "armed is required"})
        return

    armed = payload["armed"]
    if not isinstance(armed, bool):
        send_json(handler, 400, {"ok": False, "error": "armed must be true or false"})
        return

    ok = bool(set_live_repeat_armed(armed))
    if not ok:
        send_json(handler, 200, {"ok": False, "armed": armed, "error": "Could not update repeat arm state"})
        return

    send_json(handler, 200, {"ok": True, "armed": armed})


# -----------------------------------------------------------------------------
# WP5 — Dedicated transaction endpoints for privileged/external operations
# -----------------------------------------------------------------------------

# Serializes advertisement preference changes.
# Must not be held while CONFIG_IO_LOCK is held, and vice versa.
_ADVERTISE_LOCK = threading.Lock()


def send_hostname_post_json(handler, state: WebUIState, body: str) -> None:
    """POST /api/settings/hostname — change the system hostname.

    Calls set_system_hostname(); on success, returns a redirect URL so the
    browser can follow the appliance to its new mDNS address.
    """
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return

    new_hn = str(payload.get("value") or "").strip()
    if not new_hn:
        send_json(handler, 400, {"ok": False, "error": "Hostname must not be empty"})
        return

    old_hn = get_system_hostname()
    if new_hn == old_hn:
        send_json(handler, 200, {"ok": True, "changed": False, "value": old_hn})
        return

    try:
        set_system_hostname(new_hn)
    except Exception as exc:
        logging.warning("send_hostname_post_json: hostname change failed: %s", exc)
        send_json(handler, 200, {"ok": False, "error": "Hostname could not be changed"})
        return

    host_header = str(handler.headers.get("Host", "") or "")
    port_num = _urlparse(f"http://{host_header}").port
    port = str(port_num) if port_num else None
    host_p = f"{new_hn}.local:{port}" if port else f"{new_hn}.local"
    redirect_url = f"http://{host_p}/setup"

    send_json(handler, 200, {"ok": True, "changed": True, "value": new_hn, "redirect_url": redirect_url})


def send_advertisement_post_json(handler, state: WebUIState, body: str) -> None:
    """POST /api/settings/advertisement — toggle peer advertisement.

    Calls reconcile_appliance_announcement(); persists to store only on
    success. Uses _ADVERTISE_LOCK to serialize concurrent calls.
    """
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return

    value = payload.get("value")
    if not isinstance(value, bool):
        send_json(handler, 400, {"ok": False, "error": "value must be a boolean"})
        return

    try:
        from autostream_appliances import reconcile_appliance_announcement
        from autostream_webui_common import get_app_version
        with _ADVERTISE_LOCK:
            ok = reconcile_appliance_announcement(get_app_version(), value)
            if not ok:
                logging.warning(
                    "send_advertisement_post_json: admin call failed for advertise=%s", value
                )
                send_json(handler, 200, {"ok": False, "error": "Advertisement preference could not be applied"})
                return
            from autostream_settings import SettingsStore as _SettingsStore
            settings = getattr(state, "settings", None)
            if isinstance(settings, _SettingsStore):
                try:
                    settings.update(lambda raw: raw.setdefault("webui", {}).update({"advertise_appliance": value}))
                except Exception:
                    logging.exception("send_advertisement_post_json: store write failed")
                    send_json(handler, 200, {"ok": True, "value": value,
                                             "warning": "Preference applied but could not be saved — will revert on restart"})
                    return
    except Exception:
        logging.exception("send_advertisement_post_json: unexpected failure")
        send_json(handler, 200, {"ok": False, "error": "Advertisement preference could not be applied"})
        return

    send_json(handler, 200, {"ok": True, "value": value})


def send_auto_update_post_json(handler, state: WebUIState, body: str) -> None:
    """POST /api/settings/auto-update — toggle the automatic update timer.

    Calls the toggle-update-timer admin command; persists to store only on
    success so a failed privileged call cannot commit an incorrect value.
    """
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return

    value = payload.get("value")
    if not isinstance(value, bool):
        send_json(handler, 400, {"ok": False, "error": "value must be a boolean"})
        return

    verb = "enable" if value else "disable"
    result = run_admin_cmd(["toggle-update-timer", verb], timeout=5.0)
    if result.returncode != 0:
        logging.warning(
            "send_auto_update_post_json: toggle-update-timer %s failed (rc=%d): %s",
            verb, result.returncode, (result.stderr or "").strip(),
        )
        send_json(handler, 200, {"ok": False, "error": f"Auto-update timer could not be {verb}d"})
        return

    from autostream_settings import SettingsStore as _SettingsStore
    settings = getattr(state, "settings", None)
    if isinstance(settings, _SettingsStore):
        try:
            settings.update(lambda raw: raw.setdefault("updates", {}).update({"auto_update": value}))
        except Exception:
            logging.exception("send_auto_update_post_json: store write failed")
            send_json(handler, 200, {"ok": True, "value": value,
                                     "warning": "Preference applied but could not be saved — will revert on restart"})
            return

    send_json(handler, 200, {"ok": True, "value": value})


def send_save_now_json(handler, state: WebUIState) -> None:
    """POST /api/settings/save — flush in-memory settings to disk synchronously.

    Called before durability-sensitive actions (reboot, update install) so
    that in-flight autosave changes are not lost when the process restarts.
    Returns an error if the store is unavailable or the save fails; the
    caller should treat a failure as a barrier and not proceed.
    """
    from autostream_settings import SettingsStore as _SettingsStore
    settings = getattr(state, "settings", None)
    if not isinstance(settings, _SettingsStore):
        send_json(handler, 200, {"ok": False, "error": "Settings store not available"})
        return
    if settings.save_now():
        send_json(handler, 200, {"ok": True})
    else:
        send_json(handler, 200, {"ok": False, "error": "Settings could not be saved"})


# ---------------------------------------------------------------------------
# WP7 — OwnTone setup per-field autosave endpoints
# ---------------------------------------------------------------------------

def _owntone_update_live_runtime(state: WebUIState) -> None:
    """Re-apply owntone runtime from the current store or config snapshot."""
    try:
        snap = _config_snapshot(state)
        update_live_owntone_runtime(
            output_name=snap.owntone.output_name,
            volume_percent=snap.owntone.volume_percent,
            output_offsets_ms=snap.owntone.output_offsets_ms,
            output_airplay_modes=snap.owntone.output_airplay_modes,
        )
    except Exception:
        logging.exception("_owntone_update_live_runtime failed")


def _owntone_state_update_known_outputs(state: WebUIState, updates: dict[str, str]) -> None:
    """Race-safe merge of output name updates into the state file.

    Re-reads the state file inside CONFIG_IO_LOCK so that concurrent PIN
    or other state changes made while network calls were in flight are
    preserved.
    """
    if not updates:
        return
    with CONFIG_IO_LOCK:
        live = load_state(state.state_path)
        ko = live.setdefault("owntone", {}).setdefault("known_outputs", {})
        ko.update(updates)
        save_state(state.state_path, live)


def send_owntone_output_visibility_json(handler, state: WebUIState, body: str) -> None:
    """POST /api/owntone/output-visibility — show or hide a named output.

    Body: {"output_name": "<name>", "visible": true|false}
    Optional "output_id" populates known_outputs when provided.
    """
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return

    output_name = str(payload.get("output_name") or "").strip()
    if not output_name:
        send_json(handler, 400, {"ok": False, "error": "output_name required"})
        return
    visible = payload.get("visible")
    if not isinstance(visible, bool):
        send_json(handler, 400, {"ok": False, "error": "visible must be a boolean"})
        return
    output_id = str(payload.get("output_id") or "").strip()

    from autostream_settings import SettingsStore as _SettingsStore
    _store = getattr(state, "settings", None)
    if not isinstance(_store, _SettingsStore):
        send_json(handler, 200, {"ok": False, "error": "Settings store unavailable"})
        return

    def _mutator(raw: dict) -> None:
        hidden = list(raw.setdefault("webui", {}).get("hidden_outputs") or [])
        name_cf = output_name.casefold()
        if visible:
            hidden = [h for h in hidden if str(h).casefold() != name_cf]
        else:
            if not any(str(h).casefold() == name_cf for h in hidden):
                hidden.append(output_name)
        raw["webui"]["hidden_outputs"] = hidden

    try:
        _store.update(_mutator)
    except Exception:
        logging.exception("send_owntone_output_visibility_json: store update failed")
        send_json(handler, 200, {"ok": False, "error": "Internal error"})
        return

    if output_id:
        try:
            _owntone_state_update_known_outputs(state, {output_id: output_name})
        except Exception:
            logging.exception("send_owntone_output_visibility_json: known_outputs update failed")

    send_json(handler, 200, {"ok": True, "output_name": output_name, "visible": visible})


def send_owntone_output_mode_json(handler, state: WebUIState, body: str) -> None:
    """POST /api/owntone/output-mode — set AirPlay mode for a specific output.

    Body: {"output_id": "<id>", "mode": "default"|"raop"|"airplay2"}
    """
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return

    output_id = str(payload.get("output_id") or "").strip()
    if not output_id:
        send_json(handler, 400, {"ok": False, "error": "output_id required"})
        return
    mode_raw = str(payload.get("mode") or DEFAULT_AIRPLAY_MODE).strip().lower()
    valid_modes = {
        DEFAULT_AIRPLAY_MODE,
        "raop",
        "airplay2",
        "airplay2_buffered",
        "airplay2_surround_stereo",
        "airplay2_surround_upmix",
    }
    if mode_raw not in valid_modes:
        send_json(handler, 400, {"ok": False, "error": f"mode must be one of {sorted(valid_modes)}"})
        return
    mode = normalize_airplay_mode(mode_raw)

    # A page rendered while buffered audio was on keeps offering the buffered
    # modes until it is reloaded, so refuse them here rather than trusting the
    # form's option list to still be current.
    if mode in BUFFERED_AIRPLAY_MODES and not _buffered_audio_is_enabled(state):
        send_json(handler, 200, {
            "ok": False,
            "error": "Buffered audio is disabled — enable it before selecting this mode",
        })
        return

    from autostream_settings import SettingsStore as _SettingsStore
    _store = getattr(state, "settings", None)
    if not isinstance(_store, _SettingsStore):
        send_json(handler, 200, {"ok": False, "error": "Settings store unavailable"})
        return

    def _mutator(raw: dict) -> None:
        raw.setdefault("owntone", {}).setdefault("airplay_modes", {})[output_id] = mode

    try:
        _store.update(_mutator)
    except Exception:
        logging.exception("send_owntone_output_mode_json: store update failed")
        send_json(handler, 200, {"ok": False, "error": "Internal error"})
        return

    _owntone_update_live_runtime(state)
    send_json(handler, 200, {"ok": True, "output_id": output_id, "mode": mode})


def send_owntone_output_offset_json(handler, state: WebUIState, body: str) -> None:
    """POST /api/owntone/output-offset — set playback offset for a specific output.

    Body: {"output_id": "<id>", "offset_ms": <int>}
    """
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return

    output_id = str(payload.get("output_id") or "").strip()
    if not output_id:
        send_json(handler, 400, {"ok": False, "error": "output_id required"})
        return
    raw_offset = payload.get("offset_ms")
    if isinstance(raw_offset, bool) or not isinstance(raw_offset, (int, float)):
        send_json(handler, 400, {"ok": False, "error": "offset_ms must be a number"})
        return
    offset_ms = max(-2000, min(2000, int(raw_offset)))

    from autostream_settings import SettingsStore as _SettingsStore
    _store = getattr(state, "settings", None)
    if not isinstance(_store, _SettingsStore):
        send_json(handler, 200, {"ok": False, "error": "Settings store unavailable"})
        return

    def _mutator(raw: dict) -> None:
        raw.setdefault("owntone", {}).setdefault("offsets", {})[output_id] = offset_ms

    try:
        _store.update(_mutator)
    except Exception:
        logging.exception("send_owntone_output_offset_json: store update failed")
        send_json(handler, 200, {"ok": False, "error": "Internal error"})
        return

    _owntone_update_live_runtime(state)
    send_json(handler, 200, {"ok": True, "output_id": output_id, "offset_ms": offset_ms})


def _send_owntone_native_setting_json(
    handler,
    state: WebUIState,
    setting_key: str,
    value: object,
    restart_threshold_s: float = 0.75,
    reject_unsupported: bool = False,
) -> None:
    """Shared implementation for native OwnTone settings (uncompressed, buffer, grace).

    Posts to OwnTone API and optionally triggers an async restart.
    Returns {"ok": true, "restart_required": true|false}.

    Pass reject_unsupported=True for settings whose UI control is hidden on
    backends that lack them: there, a write can only arrive from a stale page or
    a direct call, and reporting success for a no-op would be a lie.
    """
    ok, restart_needed, error = _push_owntone_native_setting(
        state, setting_key, value, restart_threshold_s=restart_threshold_s,
        reject_unsupported=reject_unsupported,
    )
    if not ok:
        send_json(handler, 200, {"ok": False, "error": error or "OwnTone API error"})
        return

    send_json(handler, 200, {"ok": True, "restart_required": restart_needed})


def _push_owntone_native_setting(
    state: WebUIState,
    setting_key: str,
    value: object,
    restart_threshold_s: float = 0.75,
    reject_unsupported: bool = False,
) -> tuple[bool, bool, str]:
    """Push a native setting to the configured OwnTone-compatible backend.

    Unsupported settings are tolerated by default: best-effort pushes such as the
    mDNS grace period fire against whatever backend is configured (including none,
    in dial mode) and must not surface an error. Callers driving a user-visible,
    backend-gated control pass reject_unsupported=True to get a real failure.
    """
    try:
        parsed = _config_snapshot(state)
        base_url = parsed.owntone.base_url
    except Exception as exc:
        return False, False, f"Config unavailable: {exc}"

    result = save_setting(base_url, setting_key, value, timeout=5.0)
    if result.unsupported and reject_unsupported:
        return False, False, (
            result.message or "This backend does not support that setting"
        )
    if not result.ok and not result.unsupported:
        return False, False, result.message or "OwnTone API error"

    restart_needed = bool(result.restart_required)
    if restart_needed:
        from autostream_webui_page_owntone import start_owntone_restart_async
        start_owntone_restart_async(state, delay_s=restart_threshold_s)

    return True, restart_needed, ""


def apply_mdns_grace_period(state: WebUIState, seconds: int) -> tuple[bool, bool, str]:
    """Push configured mDNS grace to appliance discovery and OwnTone Mini.

    Synchronous: configures the in-process appliance browser and then contacts
    the OwnTone backend, returning its result. Used by the interactive settings
    handler, which reports success/restart back to the caller.
    """
    from autostream_appliances import set_grace_period
    from autostream_players import SETTING_DEVICE_REMOVAL_GRACE_PERIOD

    set_grace_period(seconds)
    return _push_owntone_native_setting(
        state, SETTING_DEVICE_REMOVAL_GRACE_PERIOD, seconds
    )


def _forward_mdns_grace_period_to_owntone(
    state: WebUIState,
    seconds: int,
) -> tuple[bool, bool, str]:
    """Best-effort consumer sync for the autostream-owned mDNS grace setting."""
    from autostream_players import SETTING_DEVICE_REMOVAL_GRACE_PERIOD

    return _push_owntone_native_setting(
        state, SETTING_DEVICE_REMOVAL_GRACE_PERIOD, seconds
    )


def apply_mdns_grace_period_startup(state: WebUIState) -> None:
    """Apply the configured mDNS grace at startup without blocking boot.

    Configures the in-process appliance browser synchronously (cheap, always
    safe, and all a dial needs), then pushes the value to the OwnTone backend on
    a background daemon thread. Backgrounding keeps a slow or absent backend
    (e.g. dial mode with no OwnTone) from delaying startup, and isolates the
    network call from the startup thread.
    """
    try:
        cfg = _config_snapshot(state)
        seconds = int(cfg.general.mdns_grace_period_seconds)
    except Exception:
        logging.debug("startup mdns grace: config unavailable", exc_info=True)
        return

    from autostream_appliances import set_grace_period
    set_grace_period(seconds)

    def _push_to_owntone() -> None:
        try:
            from autostream_players import SETTING_DEVICE_REMOVAL_GRACE_PERIOD
            ok, _restart, err = _push_owntone_native_setting(
                state, SETTING_DEVICE_REMOVAL_GRACE_PERIOD, seconds
            )
            if not ok:
                logging.debug("startup mdns grace owntone push failed: %s", err)
        except Exception:
            logging.debug("startup mdns grace owntone push error", exc_info=True)

    threading.Thread(
        target=_push_to_owntone, daemon=True, name="mdns-grace-startup",
    ).start()


def send_owntone_uncompressed_json(handler, state: WebUIState, body: str) -> None:
    """POST /api/owntone/uncompressed-audio — toggle ALAC uncompressed audio.

    Body: {"value": true|false}
    """
    from autostream_players import SETTING_UNCOMPRESSED_ALAC
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return
    value = payload.get("value")
    if not isinstance(value, bool):
        send_json(handler, 400, {"ok": False, "error": "value must be a boolean"})
        return
    _send_owntone_native_setting_json(handler, state, SETTING_UNCOMPRESSED_ALAC, value)


def send_owntone_buffered_audio_json(handler, state: WebUIState, body: str) -> None:
    """POST /api/owntone/buffered-audio — toggle AirPlay 2 buffered audio preference.

    Body: {"value": true|false}
    """
    from autostream_players import SETTING_BUFFERED_AUDIO_ENABLED
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return
    value = payload.get("value")
    if not isinstance(value, bool):
        send_json(handler, 400, {"ok": False, "error": "value must be a boolean"})
        return

    ok, restart_needed, error = _push_owntone_native_setting(
        state, SETTING_BUFFERED_AUDIO_ENABLED, value, reject_unsupported=True,
    )
    if not ok:
        send_json(handler, 200, {"ok": False, "error": error or "OwnTone API error"})
        return

    reset_outputs: list[str] = []
    if not value:
        reset_outputs = _reset_buffered_output_modes(state)

    send_json(handler, 200, {
        "ok": True,
        "restart_required": restart_needed,
        "reset_outputs": reset_outputs,
    })


def _buffered_audio_is_enabled(state: WebUIState) -> bool:
    """Report whether the backend currently has buffered audio switched on.

    Backends that do not expose the setting cannot serve buffered modes either,
    so an unreadable or unsupported result counts as off.
    """
    from autostream_player_service import get_setting
    from autostream_players import SETTING_BUFFERED_AUDIO_ENABLED

    try:
        parsed = _config_snapshot(state)
        result = get_setting(
            parsed.owntone.base_url, SETTING_BUFFERED_AUDIO_ENABLED, timeout=3,
        )
    except Exception:
        logging.debug("buffered-audio probe failed", exc_info=True)
        return False
    return bool(result.ok and result.value)


def _reset_buffered_output_modes(state: WebUIState) -> list[str]:
    """Fall outputs saved as a buffered-transport mode back to the default mode.

    Called when buffered audio is switched off: those modes are no longer
    selectable, so leaving them persisted would silently reapply an unavailable
    mode if the setting were later turned back on, or when an undiscovered
    speaker reappears. Returns the output ids that were changed.
    """
    from autostream_settings import SettingsStore as _SettingsStore

    _store = getattr(state, "settings", None)
    if not isinstance(_store, _SettingsStore):
        logging.warning("buffered-audio off: settings store unavailable, modes not reset")
        return []

    changed: list[str] = []

    def _mutator(raw: dict) -> None:
        changed.clear()  # keep the tally accurate if the store reapplies the mutator
        modes = raw.setdefault("owntone", {}).setdefault("airplay_modes", {})
        for output_id, mode in list(modes.items()):
            if str(mode or "").strip().lower() in BUFFERED_AIRPLAY_MODES:
                modes[output_id] = DEFAULT_AIRPLAY_MODE
                changed.append(str(output_id))

    try:
        _store.update(_mutator)
    except Exception:
        logging.exception("buffered-audio off: failed to reset output modes")
        return []

    if changed:
        _owntone_update_live_runtime(state)
    return changed


def send_owntone_start_buffer_json(handler, state: WebUIState, body: str) -> None:
    """POST /api/owntone/start-buffer — set start buffer in milliseconds.

    Body: {"value": <int>}
    """
    from autostream_players import (
        SETTING_START_BUFFER_MS,
        SETTING_START_BUFFER_MS_DEFAULT,
        SETTING_START_BUFFER_MS_MAX,
        SETTING_START_BUFFER_MS_MIN,
        SETTING_START_BUFFER_MS_STEP,
    )
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return
    raw = payload.get("value")
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        send_json(handler, 400, {"ok": False, "error": "value must be a number"})
        return
    value = max(
        SETTING_START_BUFFER_MS_MIN,
        min(
            SETTING_START_BUFFER_MS_MAX,
            round(int(raw) / SETTING_START_BUFFER_MS_STEP) * SETTING_START_BUFFER_MS_STEP,
        ),
    )
    _send_owntone_native_setting_json(handler, state, SETTING_START_BUFFER_MS, value)


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
        send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return
    raw = payload.get("value")
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        send_json(handler, 400, {"ok": False, "error": "value must be a number"})
        return
    minutes = max(
        SETTING_DEVICE_REMOVAL_GRACE_PERIOD_MIN_MINUTES,
        min(SETTING_DEVICE_REMOVAL_GRACE_PERIOD_MAX_MINUTES, int(raw)),
    )
    seconds = minutes * 60

    from autostream_settings import SettingsStore as _SettingsStore
    _store = getattr(state, "settings", None)
    if not isinstance(_store, _SettingsStore):
        send_json(handler, 200, {"ok": False, "error": "Settings store unavailable"})
        return

    def _mutator(raw_config: dict) -> None:
        raw_config.setdefault("general", {})["mdns_grace_period_seconds"] = seconds

    try:
        _store.update(_mutator)
    except Exception:
        logging.exception("send_settings_mdns_grace_period_json: store update failed")
        send_json(handler, 200, {"ok": False, "error": "Internal error"})
        return

    from autostream_appliances import set_grace_period
    set_grace_period(seconds)

    ok, restart_needed, error = _forward_mdns_grace_period_to_owntone(state, seconds)
    response = {
        "ok": True,
        "value": minutes,
        "seconds": seconds,
        "restart_required": restart_needed,
    }
    if not ok:
        logging.debug("mDNS grace period OwnTone forward failed: %s", error)
        response["warning"] = error or "OwnTone sync failed"
    send_json(handler, 200, response)


def send_owntone_grace_period_json(handler, state: WebUIState, body: str) -> None:
    """Compatibility wrapper for the former OwnTone-branded endpoint."""
    send_settings_mdns_grace_period_json(handler, state, body)


# ---------------------------------------------------------------------------
# Log-level and playing-status APIs
# ---------------------------------------------------------------------------

# Fields the PUT /api/log-level body is allowed to contain.
_LOG_LEVEL_PUT_ALLOWED_FIELDS: frozenset[str] = frozenset({"level"})


def send_log_level_get_json(handler, state: WebUIState) -> None:
    """GET /api/log-level — return current log-level policy state."""
    from autostream_log_policy import get_log_level_state
    result = get_log_level_state(state.config_path)
    send_json(handler, 200, result)


def send_log_level_put_json(
    handler,
    state: WebUIState,
    json_obj: dict,
    changed_by: str,
) -> None:
    """PUT /api/log-level — validate, persist, and apply log level.

    `changed_by` must be "user" or "system"; the caller determines which
    based on the request classification (direct-local vs. browser-proxied).
    Unknown fields in the body produce HTTP 400.
    """
    # Reject any unknown or prohibited fields.
    unknown = set(json_obj.keys()) - _LOG_LEVEL_PUT_ALLOWED_FIELDS
    if unknown:
        send_browser_api_error(
            handler, 400, f"Unknown field(s): {', '.join(sorted(unknown))}"
        )
        return

    requested_level = json_obj.get("level")
    if requested_level is None:
        send_browser_api_error(handler, 400, "Missing required field: level")
        return

    from autostream_log_policy import set_log_level
    result = set_log_level(
        state.config_path,
        requested_level,
        changed_by=changed_by,
    )
    if not result.get("ok"):
        error = result.get("error", "Unknown error")
        if "Unsupported" in error or "Invalid" in error:
            send_browser_api_error(handler, 400, error)
        else:
            send_browser_api_error(handler, 500, "Configuration could not be saved")
        return

    applied_level = result.get("level", requested_level)
    result.setdefault("applied", {})["wifi_watcher"] = forward_log_level_to_watcher(applied_level)

    send_json(handler, 200, result)


# ---------------------------------------------------------------------------
# Network status / setup — bounded proxy to the root watcher
# ---------------------------------------------------------------------------

# The watcher's localhost control interface.  The normal Web UI never executes
# nmcli or reads/writes network.json directly; it proxies bounded JSON requests
# to the root watcher and supplies the per-boot control token from the
# root:autostream-readable token file.
WATCHER_CONTROL_BASE = os.environ.get(
    "APP_WATCHER_CONTROL_BASE", "http://127.0.0.1:9080"
)
WATCHER_CONTROL_TOKEN_PATH = os.environ.get(
    "APP_WIFI_CONTROL_TOKEN", "/run/autostream/wifi-control.token"
)
WATCHER_CONTROL_HEADER = "X-Autostream-Wifi-Control"
_WATCHER_TIMEOUT = 4.0


def _read_watcher_control_token() -> str:
    try:
        with open(WATCHER_CONTROL_TOKEN_PATH, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def _watcher_request(method: str, path: str, body: Optional[dict] = None):
    """Perform a bounded request to a *fixed* watcher control path.

    Only the known fixed paths are permitted; arbitrary paths/commands are never
    forwarded.  Uses the Python standard library only.  Returns (status, data)
    or raises on transport failure.
    """
    import urllib.request as _ur
    import urllib.error as _ue

    if path not in ("/network_status", "/network_control", "/version"):
        raise ValueError("disallowed watcher path")
    token = _read_watcher_control_token()
    url = WATCHER_CONTROL_BASE + path
    data = None
    headers = {WATCHER_CONTROL_HEADER: token}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = _ur.Request(url, data=data, method=method, headers=headers)
    try:
        with _ur.urlopen(req, timeout=_WATCHER_TIMEOUT) as resp:
            raw = resp.read()
            status = resp.status
    except _ue.HTTPError as e:
        raw = e.read()
        status = e.code
    try:
        parsed = json.loads(raw) if raw else {}
    except ValueError:
        parsed = {}
    return status, parsed


_WATCHER_LEVEL_MAP = {
    "spam": "debug", "debug": "debug",
    "info": "info",
    "warning": "warning", "log": "warning", "fatal": "warning",
}
_WATCHER_DEBUG_TTL_SECONDS = 3600


def forward_log_level_to_watcher(app_level: str) -> bool:
    """Best-effort: map and forward *app_level* to the watcher's control API.

    Maps the app's log-level vocabulary to the watcher's runtime vocabulary
    (warning/info/debug) and POSTs a set_log_level action to the watcher's
    /network_control endpoint. A forwarded debug level carries the watcher's
    maximum TTL (1 hour); info/warning are forwarded without a TTL. Never
    raises: any failure (unknown level, missing token, transport error,
    non-success response) is logged and reported as False so a forwarding
    failure never blocks the app-level change that triggered it.
    """
    watcher_level = _WATCHER_LEVEL_MAP.get(str(app_level or "").strip().lower())
    if watcher_level is None:
        logging.warning("forward_log_level_to_watcher: unknown app level %r", app_level)
        return False

    if not _read_watcher_control_token():
        logging.debug("forward_log_level_to_watcher: no watcher control token available")
        return False

    body: dict = {"action": "set_log_level", "level": watcher_level}
    if watcher_level == "debug":
        body["ttl_seconds"] = _WATCHER_DEBUG_TTL_SECONDS

    try:
        status, data = _watcher_request("POST", "/network_control", body)
    except Exception as e:
        logging.warning("forward_log_level_to_watcher: request failed: %s", e)
        return False

    if status != 200 or not isinstance(data, dict) or data.get("ok") is not True:
        logging.warning(
            "forward_log_level_to_watcher: watcher rejected request (status=%s, data=%r)",
            status, data,
        )
        return False

    return True


def get_wifi_watcher_version() -> str:
    """Return the root watcher's code-defined component version, if available."""
    if not _read_watcher_control_token():
        return "unknown"
    try:
        status, data = _watcher_request("GET", "/version")
    except Exception:
        return "unknown"
    if status != 200 or not isinstance(data, dict) or data.get("ok") is not True:
        return "unknown"
    version = str(data.get("version") or "").strip()
    return version or "unknown"


def _network_ip_detail(device: dict) -> str:
    info = device.get("primary_ipv4_info") if isinstance(device.get("primary_ipv4_info"), dict) else {}
    address = str(info.get("address") or "").strip()
    prefixlen = info.get("prefixlen")
    netmask = str(info.get("netmask") or "").strip()
    gateway = str(info.get("gateway") or "").strip()

    if address:
        if prefixlen is not None:
            ip_text = f"{address}/{prefixlen}"
        elif netmask:
            ip_text = f"{address}/{netmask}"
        else:
            ip_text = address
    else:
        ip_text = "Not assigned"

    return f"IP: {ip_text} | Gateway: {gateway or 'Not available'}"


def _network_ipv4_text(info: dict) -> str:
    address = str(info.get("address") or "").strip()
    if not address:
        return ""
    prefixlen = info.get("prefixlen")
    if prefixlen is not None:
        return f"{address}/{prefixlen}"
    netmask = str(info.get("netmask") or "").strip()
    if netmask:
        return f"{address}/{netmask}"
    return address


def _network_adapter_ipv4_text(adapter: dict, device: dict) -> str:
    facts = adapter.get("facts") if isinstance(adapter.get("facts"), dict) else {}
    ipv4 = facts.get("ipv4") if isinstance(facts.get("ipv4"), list) else []
    selected = None
    for addr in ipv4:
        if not isinstance(addr, dict):
            continue
        if addr.get("family") == "ipv4" and str(addr.get("scope") or "") == "global":
            selected = addr
            break
        if selected is None and addr.get("family") == "ipv4":
            selected = addr
    if isinstance(selected, dict):
        text = _network_ipv4_text(selected)
        if text:
            return text

    if str(adapter.get("ifname") or "").strip() == str(device.get("primary_ifname") or "").strip():
        info = device.get("primary_ipv4_info") if isinstance(device.get("primary_ipv4_info"), dict) else {}
        return _network_ipv4_text(info)
    return ""


def _network_adapter_label(adapter: dict) -> str:
    kind = str(adapter.get("kind") or "").strip()
    if kind == "builtin_wifi":
        return "On-board WiFi"
    if kind == "usb_wifi":
        return "USB WiFi"
    return ""


def _network_quarantine_retry_label(next_action_after) -> str:
    """Render the quarantine retry label from the watcher's monotonic deadline.

    The webui and watcher run on the same host, so their CLOCK_MONOTONIC
    values are directly comparable without any timestamp translation.
    """
    remaining_seconds = 0.0
    if isinstance(next_action_after, (int, float)) and not isinstance(next_action_after, bool):
        remaining_seconds = max(0.0, next_action_after - time.monotonic())
    hours = max(1, round(remaining_seconds / 3600))
    return f"Quarantined (auto-retry in {hours}h)"


def _network_activation_failure_label(last_activation_failure: dict) -> Optional[str]:
    """Render the association-failure label, or None when the record is stale."""
    age_seconds = last_activation_failure.get("age_seconds")
    if not isinstance(age_seconds, (int, float)) or isinstance(age_seconds, bool):
        return None
    if age_seconds >= 900:
        return None
    minutes = int(age_seconds // 60)
    reason = str(last_activation_failure.get("reason") or "").strip()
    if reason == "network_not_visible":
        return f"Association failed — network not visible ({minutes}m ago)"
    return f"Association failed ({minutes}m ago)"


def _network_no_ip_status_label(adapter: dict) -> str:
    """Map an adapter with no IP to a truthful status label from health/policy.

    Checked in order of specificity (first match wins): quarantined, reset
    pending, radio-check recovery, a recent association failure, held back,
    reconnect backoff, actively connecting, else disconnected.
    """
    health = adapter.get("health") if isinstance(adapter.get("health"), dict) else {}
    policy = adapter.get("policy") if isinstance(adapter.get("policy"), dict) else {}
    state = str(health.get("state") or "").strip()
    warning = str(policy.get("warning") or "").strip()

    if policy.get("quarantined") is True:
        return _network_quarantine_retry_label(policy.get("next_action_after"))

    if warning == "resetting" or state == "dead_phy":
        return "Recovering (reset pending)"

    empty_scan_streak = policy.get("empty_scan_streak")
    empty_scan_count = empty_scan_streak.get("count") if isinstance(empty_scan_streak, dict) else 0
    if isinstance(empty_scan_count, (int, float)) and not isinstance(empty_scan_count, bool) and empty_scan_count > 0:
        return "Recovering — radio check in progress"

    last_activation_failure = adapter.get("last_activation_failure")
    if isinstance(last_activation_failure, dict):
        failure_label = _network_activation_failure_label(last_activation_failure)
        if failure_label is not None:
            return failure_label

    if state == "no_ip_held_back" or policy.get("held_back") is True:
        return "Held back after repeated failures"

    noip_failures = policy.get("noip_failures")
    has_noip_failures = isinstance(noip_failures, (int, float)) and not isinstance(noip_failures, bool) and noip_failures > 0
    if state == "degraded_no_ip" or has_noip_failures:
        return f"Reconnect backoff (attempt {int(noip_failures or 0)})"

    if state == "connecting":
        return "Connecting…"

    return "Disconnected"


def _network_interface_lines(status: dict) -> list[str]:
    device = status.get("device") if isinstance(status.get("device"), dict) else {}
    lines: list[str] = []

    if str(device.get("primary_kind") or "").strip() == "ethernet":
        eth_text = _network_ipv4_text(
            device.get("primary_ipv4_info") if isinstance(device.get("primary_ipv4_info"), dict) else {}
        )
        if eth_text:
            lines.append(f"Ethernet: {eth_text}")

    adapters = status.get("adapters") if isinstance(status.get("adapters"), list) else []
    wifi_rows = []
    for idx, adapter in enumerate(adapters):
        if not isinstance(adapter, dict):
            continue
        label = _network_adapter_label(adapter)
        if not label:
            continue
        ifname = str(adapter.get("ifname") or "").strip()
        sort_kind = 0 if label == "On-board WiFi" else 1
        wifi_rows.append((sort_kind, ifname, idx, label, adapter))

    for _sort_kind, _ifname, _idx, label, adapter in sorted(wifi_rows):
        ip_text = _network_adapter_ipv4_text(adapter, device)
        if not ip_text:
            lines.append(f"{label}: {_network_no_ip_status_label(adapter)}")
            continue

        ssid_text = ""
        if str(adapter.get("ifname") or "").strip() == str(device.get("primary_ifname") or "").strip():
            ssid_text = str(device.get("primary_ssid") or "").strip()

        if ssid_text:
            lines.append(f"{label}: {ssid_text} - {ip_text}")
        else:
            lines.append(f"{label}: {ip_text}")
    return lines


def _network_warning_rank(adapter: dict) -> int | None:
    policy = adapter.get("policy") if isinstance(adapter.get("policy"), dict) else {}
    warning = str(policy.get("warning") or "").strip()
    if policy.get("quarantined") is True or warning == "quarantined":
        return 0
    # A no-IP-suppressed / demoted adapter is as serious as a reset budget spend
    # (held back out of service) — rank it just below quarantined (C-WP4).
    if warning == "no_ip_held_back" or policy.get("held_back") is True:
        return 1
    if warning == "reset_budget_exhausted":
        return 2
    if warning == "no_ip_address":
        return 3
    if warning == "resetting":
        return 4
    if warning == "recent_resets":
        return 5
    return None


def _network_warning_fields(adapter: dict) -> dict:
    policy = adapter.get("policy") if isinstance(adapter.get("policy"), dict) else {}
    rank = _network_warning_rank(adapter)
    resets = int(policy.get("resets_24h") or 0)
    budget = int(policy.get("reset_budget_24h") or 0)
    # IF-7b: the no-IP failure count published by the watcher (never recomputed
    # here) — the meaningful number for the held-back / no-IP ranks, which the
    # dead-PHY reset ledger ("resets_24h") never ticks.
    noip = int(policy.get("noip_failures") or 0)
    ifname = str(adapter.get("ifname") or "").strip() or "Unknown"

    role = str(adapter.get("role") or "").strip()
    label = _network_adapter_label(adapter) or "WiFi"

    if rank == 0:
        if role == "client":
            warning = f"Warning: the {label} adapter has needed repeated resets and may be faulty."
        else:
            warning = f"{label} adapter held back after repeated failures. Replace the adapter if this keeps happening."
        severity = "danger"
    elif rank == 1:
        # C-WP4: no-IP-suppressed / demoted spare — the "held back" copy now
        # covers no-IP suppression (previously wired only to quarantine), and
        # notes the device fell back to the on-board radio. That fallback
        # framing only fits a non-onboard adapter being held back.
        if label == "On-board WiFi":
            warning = f"{label} adapter held back after repeated failures. Replace the adapter if this keeps happening."
        else:
            warning = (f"{label} adapter held back after repeated failures — running on on-board WiFi. "
                       "Replace the adapter if this keeps happening.")
        severity = "danger"
    elif rank == 2:
        warning = f"Warning: the {label} adapter has needed repeated resets and may be faulty."
        severity = "danger"
    elif rank == 3:
        warning = (f"{label} adapter detected but could not get a network address — "
                   "check the network's DHCP, the adapter's band, or the dongle.")
        severity = "warning"
    elif rank == 4:
        warning = f"{label} adapter is being reset. Network connection may be unstable for a minute."
        severity = "warning"
    elif rank == 5:
        reset_text = "1 reset" if resets == 1 else f"{resets} resets"
        warning = f"Warning: the {label} adapter has needed {reset_text} in the last 24 hours."
        severity = "warning"
    else:
        return {}

    # The no-IP family (rank 1 held-back, rank 3 no-IP) is tracked by the no-IP
    # ledger, not the reset ledger, so show the failed-connection count; the
    # reset-family ranks (0, 2, 4, 5) keep the reset-attempt line (IF-7b).
    if rank in (1, 3):
        support_detail = f"Adapter: {ifname} | Failed connection attempts: {noip}"
    else:
        support_detail = (
            f"Adapter: {ifname} | Reset attempts: {resets} in 24h "
            f"(normal budget: {budget})"
        )

    return {
        "warning": warning,
        "warning_severity": severity,
        "support_detail": support_detail,
    }


def build_network_card_presentation(status: dict) -> dict:
    """Return Network-card presentation fields derived from watcher schema v1."""
    device = status.get("device") if isinstance(status.get("device"), dict) else {}
    primary_kind = str(device.get("primary_kind") or "").strip()
    primary_ifname = str(device.get("primary_ifname") or "").strip()
    primary_ssid = str(device.get("primary_ssid") or "").strip()

    if primary_kind == "ethernet":
        display = "Connected via Ethernet"
    elif primary_kind == "usb_wifi":
        display = "Connected via USB WiFi adapter"
        if primary_ssid:
            display += f" to {primary_ssid}"
    elif primary_kind == "builtin_wifi":
        display = "Connected via on-board WiFi"
        if primary_ssid:
            display += f" to {primary_ssid}"
    else:
        display = "No active network connection"

    result = {
        "title": "Network",
        "display": display,
        "detail": _network_ip_detail(device) if primary_kind else "",
        "interface_lines": _network_interface_lines(status),
        "warning": "",
        "warning_severity": "",
        "support_detail": "",
    }

    adapters = status.get("adapters") if isinstance(status.get("adapters"), list) else []
    wifi_adapters = [
        a for a in adapters
        if isinstance(a, dict) and str(a.get("kind") or "").strip() in ("usb_wifi", "builtin_wifi")
    ]
    active_wifi = [
        a for a in wifi_adapters
        if str(a.get("ifname") or "").strip() == primary_ifname or str(a.get("role") or "").strip() == "client"
    ]
    for adapter in active_wifi:
        if _network_warning_rank(adapter) is not None:
            result.update(_network_warning_fields(adapter))
            return result

    ranked = [
        (rank, adapter) for adapter in wifi_adapters
        for rank in [_network_warning_rank(adapter)]
        if rank is not None
    ]
    if ranked:
        ranked.sort(key=lambda item: item[0])
        result.update(_network_warning_fields(ranked[0][1]))
    return result


def send_network_status_json(handler) -> None:
    """GET /api/network/status — proxy the watcher's non-secret network status."""
    try:
        status, data = _watcher_request("GET", "/network_status")
    except Exception:
        send_browser_api_error(handler, 503, "Network service unavailable")
        return
    if status != 200 or not isinstance(data, dict) or not data.get("ok"):
        send_browser_api_error(handler, 503, "Network service unavailable")
        return
    data.update(build_network_card_presentation(data))
    send_json(handler, 200, data)


_NETWORK_SETUP_ALLOWED_ACTIONS = frozenset({"start_setup", "reconnect_saved"})


def send_network_setup_json(handler, json_obj: dict) -> None:
    """POST /api/network/setup — proxy a bounded setup action to the watcher."""
    if not isinstance(json_obj, dict):
        send_browser_api_error(handler, 400, "JSON object required")
        return
    action = json_obj.get("action")
    extra = set(json_obj.keys()) - {"action", "csrf_token"}
    if action not in _NETWORK_SETUP_ALLOWED_ACTIONS or extra:
        send_browser_api_error(handler, 400, "Invalid action")
        return
    try:
        status, data = _watcher_request("POST", "/network_control", {"action": action})
    except Exception:
        send_browser_api_error(handler, 503, "Network service unavailable")
        return
    if status == 200 and isinstance(data, dict) and data.get("ok"):
        send_json(handler, 200, {"ok": True, "queued": True, "action": action})
        return
    # Surface watcher conflict (busy) without breaking the Setup page.
    if status == 409:
        send_browser_api_error(handler, 409, "A network change is already in progress")
        return
    send_browser_api_error(handler, 503, "Network service unavailable")


def send_network_roaming_json(handler, json_obj: dict) -> None:
    """POST /api/network/roaming — proxy the USB roaming-management preference to the watcher."""
    if not isinstance(json_obj, dict):
        send_browser_api_error(handler, 400, "JSON object required")
        return
    managed = json_obj.get("managed")
    extra = set(json_obj.keys()) - {"managed", "csrf_token"}
    if not isinstance(managed, bool) or extra:
        send_browser_api_error(handler, 400, "Invalid request")
        return
    try:
        status, data = _watcher_request(
            "POST", "/network_control", {"action": "set_roaming_management", "managed": managed}
        )
    except Exception:
        send_browser_api_error(handler, 503, "Network service unavailable")
        return
    if status == 200 and isinstance(data, dict) and data.get("ok"):
        send_json(handler, 200, {"ok": True, "managed": managed})
        return
    send_browser_api_error(handler, 503, "Network service unavailable")


def send_playing_status_json(handler) -> None:
    """GET /api/playing-status — return whether the appliance is streaming.

    Returns ``{"ok": true, "playing": <bool>}`` when monitor state can be
    determined.  When it cannot (internal error), returns HTTP 200 with an
    explicit *uncertain* body ``{"ok": false, "error": "playing status
    unavailable"}`` rather than falsely reporting stopped playback, so local
    automation conservatively treats the state as unknown (Section 8.3).
    """
    try:
        playing = any_monitor_capturing()
    except Exception:
        logging.warning("playing status unavailable (monitor query failed)")
        send_json(handler, 200, {"ok": False, "error": "playing status unavailable"})
        return
    send_json(handler, 200, {"ok": True, "playing": bool(playing)})
