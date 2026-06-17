"""autostream_appliance_models.py — shared Home and Equaliser state models.

Provides build_home_state() and build_equaliser_state() plus shared
output and EQ mutation helpers used by both local API endpoints and
target-side federation APIs (WP6+).

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import concurrent.futures
import logging
import threading
import time
from typing import Optional

from autostream_config import (
    CONFIG_IO_LOCK,
    load_config,
    parse_config,
    save_config,
)
from autostream_core import (
    any_monitor_capturing,
    get_live_output_eq_status,
    get_monitor_levels_dbfs,
    get_playback_snapshot,
    set_live_output_auto_trim,
    set_live_output_eq,
    set_live_output_gain,
)
from autostream_player_service import (
    config_airplay_mode_to_backend,
    get_setting,
    list_outputs,
    set_output_enabled,
    submit_output_pin,
    update_output,
)
from autostream_players import SETTING_START_BUFFER_MS, SETTING_START_BUFFER_MS_DEFAULT
from autostream_rpi import get_appliance_id
from autostream_sysutils import get_system_hostname
from autostream_webui_common import get_app_version, locked_load_config

# ---------------------------------------------------------------------------
# Output ID→name cache (server-side; never populated from browser input)
# ---------------------------------------------------------------------------

_OUTPUT_NAME_CACHE: dict[str, str] = {}   # output id (str) -> display name
_OUTPUT_NAME_CACHE_TIME: float = 0.0
_OUTPUT_NAME_CACHE_TTL: float = 30.0
_output_name_cache_lock = threading.Lock()


def _resolve_output_name(owntone_base_url: str, out_id: str) -> str:
    """Return the display name for *out_id* using a short-lived cache.

    The cache is populated by calling list_outputs from a trusted path
    (this function or the home-state builder).  Browser-supplied names are
    never used here.  Returns an empty string when the name cannot be
    resolved; callers must treat that as fail-open.
    """
    global _OUTPUT_NAME_CACHE, _OUTPUT_NAME_CACHE_TIME
    now = time.monotonic()
    with _output_name_cache_lock:
        if now - _OUTPUT_NAME_CACHE_TIME < _OUTPUT_NAME_CACHE_TTL:
            return _OUTPUT_NAME_CACHE.get(out_id, "")
    try:
        lr = list_outputs(owntone_base_url, timeout=1.0)
    except Exception:
        logging.debug("_resolve_output_name: list_outputs failed for id %s", out_id)
        return ""
    if not lr.ok:
        return ""
    mapping = {str(o.id): str(o.name or "") for o in lr.outputs}
    with _output_name_cache_lock:
        _OUTPUT_NAME_CACHE = mapping
        _OUTPUT_NAME_CACHE_TIME = time.monotonic()
    return mapping.get(out_id, "")


# ---------------------------------------------------------------------------
# Output-list builder (shared between Home page and federation)
# ---------------------------------------------------------------------------

_OUTPUT_EQ_DB_FIELDS = frozenset({
    "gain_db", "peq1_db", "peq2_db", "peq3_db", "peq4_db", "peq5_db", "peq6_db",
})
_OUTPUT_EQ_BAND_FIELDS = frozenset({
    "peq1_db", "peq2_db", "peq3_db", "peq4_db", "peq5_db", "peq6_db",
})
_OUTPUT_EQ_BOOL_FIELDS = frozenset({"auto_trim_enabled"})
_OUTPUT_EQ_ALL_FIELDS = _OUTPUT_EQ_DB_FIELDS | _OUTPUT_EQ_BOOL_FIELDS
_OUTPUT_EQ_DB_MIN = -12.0
_OUTPUT_EQ_DB_MAX = 12.0


def build_output_list(parsed, owntone_outputs: list) -> list[dict]:
    """Filter and sort OwnTone outputs into the standard dict representation.

    Applies hidden-output filtering, puts the configured default first, then
    alphabetical order.  Returns dicts with keys: id, name, selected, volume,
    is_default.
    """
    default_output_name = parsed.owntone.output_name
    hidden = {
        str(n).strip().casefold()
        for n in (parsed.webui.hidden_outputs or ())
        if str(n).strip()
    }

    result: list[dict] = []
    for out in owntone_outputs:
        out_id = str(out.id or "").strip()
        name = str(out.name or "").strip()
        if not out_id or not name:
            continue
        selected = bool(out.selected)
        if name.casefold() in hidden and not selected and name != default_output_name:
            continue
        vol = max(0, min(100, int(out.volume_percent)))
        result.append({
            "id": out_id,
            "name": name,
            "selected": selected,
            "volume": vol,
            "is_default": (name == default_output_name),
        })

    if default_output_name:
        result.sort(key=lambda o: (0 if o["is_default"] else 1, o["name"].casefold()))
    return result


# ---------------------------------------------------------------------------
# build_home_state
# ---------------------------------------------------------------------------

def build_home_state(
    config_path: str,
    *,
    deadline: Optional[float] = None,
) -> dict:
    """Build the aggregate Home state dict.

    When *deadline* is set (a time.monotonic() value), OwnTone calls share the
    remaining budget and run concurrently to fit within the federation 1.5-second
    internal budget.  A sub-call that misses the budget produces the reachable-
    appliance waiting model rather than falsely marking the appliance offline.

    When *deadline* is None (local mode) the existing sequential timeouts are used.

    Returns a dict with keys: ok, appliance, preferences, playback, input_levels,
    warnings, outputs, vu_delay_ms.
    """
    try:
        parsed = parse_config(locked_load_config(config_path))
    except Exception as e:
        logging.warning("build_home_state: config load failed: %s", e)
        return {
            "ok": False,
            "error": str(e),
            "appliance": _local_appliance_info(),
            "preferences": {},
            "playback": {},
            "input_levels": [],
            "warnings": {"stylus": "", "belt": "", "bearing": ""},
            "outputs": [],
            "vu_delay_ms": SETTING_START_BUFFER_MS_DEFAULT,
        }

    try:
        input_levels = get_monitor_levels_dbfs()
    except Exception:
        input_levels = []

    playback = get_playback_snapshot()

    owntone_base_url = parsed.owntone.base_url
    vu_delay_ms = SETTING_START_BUFFER_MS_DEFAULT
    outputs: list[dict] = []

    if deadline is None:
        # Local mode: sequential calls with existing timeouts.
        try:
            buf_result = get_setting(owntone_base_url, SETTING_START_BUFFER_MS, timeout=1)
            vu_delay_ms = int(buf_result.value) if buf_result.ok else SETTING_START_BUFFER_MS_DEFAULT
        except Exception:
            vu_delay_ms = SETTING_START_BUFFER_MS_DEFAULT
        try:
            outputs_result = list_outputs(owntone_base_url, timeout=3)
            if outputs_result.ok:
                outputs = build_output_list(parsed, list(outputs_result.outputs))
        except Exception:
            pass
    else:
        # Federation mode: concurrent calls within deadline budget.
        remaining = max(0.0, deadline - time.monotonic())
        # Reserve a small margin for overhead; cap per-call at remaining / 2.
        per_call = min(remaining / 2, 1.5)
        if per_call > 0.05:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                fut_buf = pool.submit(
                    _safe_get_setting, owntone_base_url, per_call
                )
                fut_out = pool.submit(
                    _safe_list_outputs, owntone_base_url, per_call
                )
                vu_delay_ms = fut_buf.result()
                raw_outputs = fut_out.result()
                if raw_outputs is not None:
                    outputs = build_output_list(parsed, raw_outputs)

    try:
        from autostream_output_usage import annotate_outputs
        outputs = annotate_outputs(outputs)
    except Exception:
        pass

    hostname = _format_hostname(get_system_hostname())
    return {
        "ok": True,
        "appliance": {
            "id": get_appliance_id() or "",
            "hostname": hostname,
            "version": get_app_version(),
        },
        "preferences": {
            "show_master_volume": parsed.webui.show_master_volume,
            "show_input_detail": parsed.webui.show_input_detail,
        },
        "playback": playback.to_public_dict(),
        "input_levels": input_levels,
        "warnings": {
            "stylus": playback.stylus_banner_text or "",
            "belt": playback.belt_banner_text or "",
            "bearing": playback.bearing_banner_text or "",
        },
        "outputs": outputs,
        "vu_delay_ms": int(vu_delay_ms),
    }


def _safe_get_setting(base_url: str, timeout: float) -> int:
    try:
        result = get_setting(base_url, SETTING_START_BUFFER_MS, timeout=timeout)
        return int(result.value) if result.ok else SETTING_START_BUFFER_MS_DEFAULT
    except Exception:
        return SETTING_START_BUFFER_MS_DEFAULT


def _safe_list_outputs(base_url: str, timeout: float) -> Optional[list]:
    try:
        result = list_outputs(base_url, timeout=timeout)
        return list(result.outputs) if result.ok else None
    except Exception:
        return None


def _local_appliance_info() -> dict:
    return {
        "id": get_appliance_id() or "",
        "hostname": _format_hostname(get_system_hostname()),
        "version": get_app_version(),
    }


def _format_hostname(raw: str) -> str:
    hostname = str(raw or "").strip()
    if hostname.lower().endswith(".local"):
        hostname = hostname[:-6]
    return hostname.strip() or "autostream"


# ---------------------------------------------------------------------------
# build_equaliser_state
# ---------------------------------------------------------------------------

def build_equaliser_state(config_path: str) -> dict:
    """Build the aggregate Equaliser state dict.

    Returns a dict with all EQ config fields plus the live auto-trim status
    from the monitor (if available).  Keys: ok, gain_db, auto_trim_enabled,
    peq1_db … peq6_db, output_auto_trim_enabled, output_auto_trim_db,
    effective_output_gain_db.
    """
    try:
        cfg = locked_load_config(config_path)
        parsed = parse_config(cfg)
    except Exception as e:
        logging.warning("build_equaliser_state: config load failed: %s", e)
        return {"ok": False, "error": str(e)}

    oeq = parsed.output_eq
    state: dict = {
        "ok": True,
        "gain_db": float(oeq.gain_db),
        "auto_trim_enabled": bool(oeq.auto_trim_enabled),
        "peq1_db": float(oeq.peq1_db),
        "peq2_db": float(oeq.peq2_db),
        "peq3_db": float(oeq.peq3_db),
        "peq4_db": float(oeq.peq4_db),
        "peq5_db": float(oeq.peq5_db),
        "peq6_db": float(oeq.peq6_db),
    }

    live = get_live_output_eq_status()
    if live is not None:
        state.update(live)

    return state


# ---------------------------------------------------------------------------
# Shared EQ mutations
# ---------------------------------------------------------------------------

def apply_eq_field(config_path: str, field: str, value_raw: str) -> tuple[bool, str, str]:
    """Save and apply one output EQ field.

    Returns (ok, normalised_str, error_message).
    Raises ValueError for unknown fields or non-numeric dB values.
    """
    if field not in _OUTPUT_EQ_ALL_FIELDS:
        raise ValueError(f"Unknown field: {field!r}")

    if field in _OUTPUT_EQ_BOOL_FIELDS:
        normalised_bool = value_raw.lower() in ("true", "1", "yes")
        normalised_str = "true" if normalised_bool else "false"
        try:
            with CONFIG_IO_LOCK:
                cfg = load_config(config_path)
                cfg.setdefault("output_eq", {})[field] = normalised_bool
                save_config(config_path, cfg)
            set_live_output_auto_trim(normalised_bool)
        except Exception as e:
            logging.exception("apply_eq_field: save failed")
            return False, normalised_str, str(e)
        return True, normalised_str, ""

    try:
        value = float(value_raw)
    except ValueError:
        raise ValueError("Value must be numeric")

    value = max(_OUTPUT_EQ_DB_MIN, min(_OUTPUT_EQ_DB_MAX, value))
    normalised_str = f"{value:.1f}"

    try:
        with CONFIG_IO_LOCK:
            cfg = load_config(config_path)
            p = parse_config(cfg)
            cfg.setdefault("output_eq", {})[field] = value
            save_config(config_path, cfg)

        oeq = p.output_eq
        if field == "gain_db":
            set_live_output_gain(value)
        else:
            band_vals = {b: float(getattr(oeq, b)) for b in _OUTPUT_EQ_DB_FIELDS if b != "gain_db"}
            band_vals[field] = value
            set_live_output_eq(
                band_vals["peq1_db"],
                band_vals["peq2_db"],
                band_vals["peq3_db"],
                band_vals["peq4_db"],
                band_vals["peq5_db"],
                band_vals["peq6_db"],
            )
    except Exception as e:
        logging.exception("apply_eq_field: save failed")
        return False, normalised_str, str(e)

    return True, normalised_str, ""


def apply_eq_reset(config_path: str) -> tuple[bool, str]:
    """Zero all EQ band fields (peq1–peq6). Does not change output gain or auto-trim."""
    try:
        with CONFIG_IO_LOCK:
            cfg = load_config(config_path)
            eq = cfg.setdefault("output_eq", {})
            for f in _OUTPUT_EQ_BAND_FIELDS:
                eq[f] = 0.0
            save_config(config_path, cfg)
        set_live_output_eq(0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    except Exception as e:
        logging.exception("apply_eq_reset: reset failed")
        return False, str(e)
    return True, ""


# ---------------------------------------------------------------------------
# Shared output mutation
# ---------------------------------------------------------------------------

def apply_output_mutation(
    owntone_base_url: str,
    out_id: str,
    body: dict,
    *,
    offset_ms: Optional[int] = None,
    mode: Optional[str] = None,
    output_name: str = "",
) -> dict:
    """Apply an output toggle/volume change or PIN submission.

    *body* must contain at least {"id": ..., "op": ...} or {"id": ..., "selected": bool}.
    *offset_ms* and *mode* come from the per-output config (not from the browser body).
    *output_name* is optional; when provided (or resolved internally) the occupancy
    cache is checked before enabling. If the name cannot be resolved the check is
    skipped (fail-open) and a debug message is logged.

    Returns a result dict with keys: ok, id, and optional error/pin_required/pin_invalid.
    """
    op = (body.get("op") or "").strip().lower()
    out_id_text = str(out_id or "").strip()

    if not out_id_text:
        return {"ok": False, "error": "Missing output id"}

    if op == "pin":
        pin_raw = body.get("pin")
        pin = str(pin_raw).strip() if pin_raw is not None else ""
        if not pin:
            return {"ok": False, "error": "Missing PIN", "id": out_id_text}
        pin_result = submit_output_pin(owntone_base_url, out_id_text, pin, timeout=3)
        if not pin_result.ok and pin_result.error_code == "pin_invalid":
            return {
                "ok": False,
                "id": out_id_text,
                "pin_invalid": True,
                "error": pin_result.message,
            }
        if not pin_result.ok:
            return {"ok": False, "id": out_id_text, "error": pin_result.message}
        return {"ok": True, "id": out_id_text}

    selected = bool(body.get("selected", False))
    if selected:
        # Resolve output name from server-side trusted source only.
        # body.get("name") is intentionally ignored to prevent bypass.
        name_to_check = output_name or _resolve_output_name(owntone_base_url, out_id_text)
        if name_to_check:
            try:
                from autostream_output_usage import usage_for_output
                usage = usage_for_output(name_to_check)
                if usage is not None:
                    return {
                        "ok": False,
                        "id": out_id_text,
                        "error": "output_in_use",
                        "owner": usage.owner_name,
                    }
            except Exception:
                logging.debug("apply_output_mutation: usage check failed for %s", name_to_check)

        volume = max(0, min(100, int(body.get("volume", 50))))
        update_result = update_output(
            owntone_base_url,
            out_id_text,
            enabled=True,
            volume_percent=volume,
            offset_ms=offset_ms,
            mode=mode,
            timeout=3,
        )
        if not update_result.ok and update_result.error_code == "pin_required":
            return {
                "ok": False,
                "pin_required": True,
                "id": out_id_text,
                "output_name": str(body.get("name") or ""),
                "error": update_result.message,
            }
        if not update_result.ok:
            return {
                "ok": False,
                "id": out_id_text,
                "error": update_result.message,
                "pin_invalid": False,
            }
        return {"ok": True, "id": out_id_text}

    disable_result = set_output_enabled(owntone_base_url, out_id_text, False, timeout=3)
    if not disable_result.ok:
        return {"ok": False, "id": out_id_text, "error": disable_result.message}
    return {"ok": True, "id": out_id_text}
