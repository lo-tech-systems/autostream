"""autostream_appliance_models.py — shared Home and Equaliser state models.

Provides build_home_state() and build_equaliser_state() plus shared
output and EQ mutation helpers used by both local API endpoints and
target-side federation APIs.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import concurrent.futures
import logging
import math
import threading
import time
from typing import Optional

import autostream_mute_state as mute_state
import autostream_pin_pairing as pairing
from autostream_config import (
    CONFIG_IO_LOCK,
    load_config,
    parse_config,
    save_config,
)
from autostream_core import (
    OUTPUT_PEQ_BANDS,
    any_monitor_capturing,
    clear_user_silence_latch,
    get_active_track_identification_snapshot,
    get_live_output_eq_status,
    get_monitor_levels_dbfs,
    get_playback_snapshot,
    get_repeat_status,
    get_session_state,
    note_user_output_action,
    request_nowplaying_republish,
    set_live_output_auto_trim,
    set_live_output_eq,
    set_live_output_gain,
    set_user_silence_latch,
)
from autostream_dial_push import notify_state_changed
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
from autostream_settings_schema import register_field
from autostream_sysutils import get_system_hostname
from autostream_webui_common import get_app_version, locked_load_config

# ---------------------------------------------------------------------------
# Output info cache (server-side; never populated from browser input)
#
# Keyed by owntone_base_url to avoid cross-appliance contamination.
# Each entry maps output id → (display_name, locally_selected).
# ---------------------------------------------------------------------------

# url -> {out_id -> (name, selected)}
_OUTPUT_INFO_CACHE: dict[str, dict[str, tuple[str, bool]]] = {}
# url -> monotonic timestamp of last successful list_outputs
_OUTPUT_INFO_CACHE_TIME: dict[str, float] = {}
_OUTPUT_INFO_CACHE_TTL: float = 30.0
_output_info_cache_lock = threading.Lock()

# Keep old names as aliases so existing tests that reset these still work.
_OUTPUT_NAME_CACHE: dict[str, str] = {}
_OUTPUT_NAME_CACHE_TIME: float = 0.0


def _refresh_output_info_cache(owntone_base_url: str) -> dict[str, tuple[str, bool]]:
    """Call list_outputs and update the per-URL cache.  Returns the new mapping."""
    try:
        lr = list_outputs(owntone_base_url, timeout=1.0)
    except Exception:
        logging.debug("_refresh_output_info_cache: list_outputs failed for %s", owntone_base_url)
        return {}
    if not lr.ok:
        return {}
    mapping: dict[str, tuple[str, bool]] = {
        str(o.id): (str(o.name or ""), bool(o.selected))
        for o in lr.outputs
    }
    url = owntone_base_url.rstrip("/")
    with _output_info_cache_lock:
        _OUTPUT_INFO_CACHE[url] = mapping
        _OUTPUT_INFO_CACHE_TIME[url] = time.monotonic()
    return mapping


def _update_cached_selected(owntone_base_url: str, out_id: str, selected: bool) -> None:
    """Update the locally_selected flag for one output in the per-URL cache in-place."""
    url = owntone_base_url.rstrip("/")
    with _output_info_cache_lock:
        mapping = _OUTPUT_INFO_CACHE.get(url)
        if mapping and out_id in mapping:
            name, _ = mapping[out_id]
            mapping[out_id] = (name, selected)


def _invalidate_output_info_cache(owntone_base_url: str) -> None:
    """Expire the per-URL cache so the next call refreshes from OwnTone."""
    url = owntone_base_url.rstrip("/")
    with _output_info_cache_lock:
        _OUTPUT_INFO_CACHE_TIME.pop(url, None)


def _resolve_output_info(owntone_base_url: str, out_id: str) -> tuple[str, bool]:
    """Return (display_name, locally_selected) for *out_id* using a per-URL cache.

    Browser-supplied names are never used here. If the cache is fresh but does
    not contain *out_id* (newly appeared output), a single refresh is done before
    failing open so occupancy is enforced for new IDs too. Returns ("", False)
    when resolution fails; callers must treat that as fail-open.
    """
    url = owntone_base_url.rstrip("/")
    now = time.monotonic()
    with _output_info_cache_lock:
        cache_time = _OUTPUT_INFO_CACHE_TIME.get(url, 0.0)
        if now - cache_time < _OUTPUT_INFO_CACHE_TTL:
            mapping = _OUTPUT_INFO_CACHE.get(url, {})
            if out_id in mapping:
                return mapping[out_id]
            # Cache is fresh but ID absent — fall through to refresh once.

    fresh = _refresh_output_info_cache(owntone_base_url)
    return fresh.get(out_id, ("", False))


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


# -----------------------------------------------------------------------------
# Settings schema registration: the third of the four dispatch paths this
# consolidates. apply_eq_field()/apply_eq_reset() below used to clamp/normalise each of
# these seven output_eq fields inline; that clamp/normalise logic now lives
# in one place per field (_clamp_output_eq_db / _normalize_output_eq_bool,
# both verbatim extractions of the previous inline bodies -- same clamp
# bounds, same "Value must be numeric" error message), registered into the
# shared SETTINGS_SCHEMA table so apply_eq_field looks them up by path
# instead of branching on field name inline.
# -----------------------------------------------------------------------------

def _clamp_output_eq_db(value_raw: object) -> float:
    """Coerce+clamp one output_eq dB-valued field. Same body as the inline
    logic apply_eq_field() used before this migration: non-numeric input
    raises "Value must be numeric"; any numeric input is silently clamped to
    [_OUTPUT_EQ_DB_MIN, _OUTPUT_EQ_DB_MAX] rather than rejected.
    """
    try:
        value = float(value_raw)
    except ValueError:
        raise ValueError("Value must be numeric")
    return max(_OUTPUT_EQ_DB_MIN, min(_OUTPUT_EQ_DB_MAX, value))


def _normalize_output_eq_bool(value_raw: object) -> bool:
    """Coerce one output_eq bool-valued field (currently just
    auto_trim_enabled). Same body as apply_eq_field()'s previous inline
    ``value_raw.lower() in ("true", "1", "yes")`` check.
    """
    return value_raw.lower() in ("true", "1", "yes")


for _eq_field in _OUTPUT_EQ_DB_FIELDS:
    register_field(f"output_eq.{_eq_field}", "output_eq", _eq_field, _clamp_output_eq_db)
for _eq_field in _OUTPUT_EQ_BOOL_FIELDS:
    register_field(f"output_eq.{_eq_field}", "output_eq", _eq_field, _normalize_output_eq_bool)


def build_output_list(parsed, owntone_outputs: list) -> list[dict]:
    """Filter and sort OwnTone outputs into the standard dict representation.

    Applies hidden-output filtering, puts the configured default first, then
    alphabetical order.  Returns dicts with keys: id, name, selected, volume,
    is_default, needs_auth_key, requires_auth, pin_pending, pin_claim
    (the requester currently entering a PIN for the output, or "").

    "volume" is the INTENDED level (autostream_mute_state.intended_level):
    while the appliance is muted this is the level the output will return to
    on restore, not its actual (silenced) OwnTone volume -- so every consumer
    of this list (the WebUI's per-output sliders and client-side master
    average, the dial's outputs list and detail page) shows the same number
    regardless of the mute.
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
            "volume": mute_state.intended_level(out_id, vol),
            "is_default": (name == default_output_name),
            "needs_auth_key": bool(out.needs_auth_key),
            "requires_auth": bool(out.requires_auth),
            "pin_pending": bool(out.pin_pending),
            "pin_claim": pairing.holder(out_id),
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
        from track_id.models import disabled_snapshot
        return {
            "ok": False,
            "error": str(e),
            "appliance": _local_appliance_info(),
            "preferences": {},
            "playback": {},
            "input_levels": [],
            "warnings": {"stylus": "", "belt": "", "bearing": "", "dial_update": ""},
            "outputs": [],
            "muted": mute_state.is_muted(),
            "vu_delay_ms": SETTING_START_BUFFER_MS_DEFAULT,
            "track_identification": disabled_snapshot().to_public_dict(),
            **_session_and_repeat_fields(),
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

    try:
        ti_snapshot = get_active_track_identification_snapshot()
        ti_dict = ti_snapshot.to_public_dict()
    except Exception:
        from track_id.models import disabled_snapshot
        ti_dict = disabled_snapshot().to_public_dict()

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
            "dial_update": _dial_update_banner_text(),
        },
        "outputs": outputs,
        "muted": mute_state.is_muted(),
        "vu_delay_ms": int(vu_delay_ms),
        "track_identification": ti_dict,
        **_session_and_repeat_fields(),
    }


def _dial_update_banner_text() -> str:
    """Dial-update banner text, or "" when none is due or the dial scanner
    is unavailable (never raises)."""
    try:
        from autostream_dials import build_dial_update_banner_text
        return build_dial_update_banner_text()
    except Exception:
        return ""


def _session_and_repeat_fields() -> dict:
    """Return the "session" (always present) and "repeat" (present only when
    the daemon has reported one) fields for build_home_state()'s dict.

    Sourced identically to send_status_json (autostream_webui_api.py): the
    session cache falls back to any_monitor_capturing() if unavailable, and
    the repeat block is passed through verbatim when present -- omitted
    entirely (not a KeyError) when the daemon has never reported one, so an
    older backend degrades by absence rather than by error.
    """
    try:
        session_state = get_session_state()
    except Exception:
        session_state = {"active": any_monitor_capturing(), "source": None}
    fields: dict = {"session": session_state}
    try:
        repeat_status = get_repeat_status()
    except Exception:
        repeat_status = None
    if repeat_status is not None:
        fields["repeat"] = repeat_status
    return fields


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

def apply_eq_field(config_path: str, field: str, value_raw: str, *, settings=None) -> tuple[bool, str, str]:
    """Save and apply one output EQ field.

    Returns (ok, normalised_str, error_message).
    Raises ValueError for unknown fields or non-numeric dB values.

    When *settings* is a SettingsStore instance, it is used as the sole
    persistence mechanism (store → background disk write). The config_path
    is only used as a fallback when no store is available.

    Dials are told when a band changes: they show the bands, not the output
    gain or auto-trim.
    """
    from autostream_settings import SettingsStore as _SettingsStore
    _store = settings if isinstance(settings, _SettingsStore) else None

    if field not in _OUTPUT_EQ_ALL_FIELDS:
        raise ValueError(f"Unknown field: {field!r}")

    from autostream_settings_schema import SETTINGS_SCHEMA
    _spec = SETTINGS_SCHEMA[f"output_eq.{field}"]

    if field in _OUTPUT_EQ_BOOL_FIELDS:
        normalised_bool = _spec.validate(value_raw)
        normalised_str = "true" if normalised_bool else "false"
        try:
            if _store is not None:
                _store.update(lambda raw: raw.setdefault("output_eq", {}).update({field: normalised_bool}))
            else:
                with CONFIG_IO_LOCK:
                    cfg = load_config(config_path)
                    cfg.setdefault("output_eq", {})[field] = normalised_bool
                    save_config(config_path, cfg)
            set_live_output_auto_trim(normalised_bool)
        except Exception as e:
            logging.exception("apply_eq_field: save failed")
            return False, normalised_str, str(e)
        return True, normalised_str, ""

    value = _spec.validate(value_raw)
    normalised_str = f"{value:.1f}"
    band_applied = False

    try:
        if _store is not None:
            pre_snap = _store.snapshot()
            _store.update(lambda raw: raw.setdefault("output_eq", {}).update({field: value}))
            oeq = pre_snap.output_eq
        else:
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
            band_applied = True
    except Exception as e:
        logging.exception("apply_eq_field: save failed")
        return False, normalised_str, str(e)

    if band_applied:
        notify_state_changed("eq")
    return True, normalised_str, ""


# ---------------------------------------------------------------------------
# Dial bass/treble mapping onto the six output_eq bands
#
# The dial's Equaliser page shows two controls, bass and treble, each
# +/-6 dB -- narrower than the Equaliser page's own +/-12 dB per-band range.
# Bass moves peq1 (40 Hz low-shelf) and peq2 (100 Hz peak) together, equally;
# treble moves peq6 (10 kHz high-shelf) by the full amount and peq5 (4 kHz
# peak) by half of it, so the high shelf's own edge is not a hard step.
# peq3/peq4 (300 Hz/1 kHz) are never touched by either control.
# ---------------------------------------------------------------------------

EQ_BASS_TREBLE_LIMIT_DB = 6
_EQ_TREBLE_SECONDARY_SCALE = 0.5   # peq5's share of a treble move


def eq_fields_for_bass(bass_db: int) -> dict:
    """The two output_eq band fields a dial bass step writes: peq1 and peq2,
    both set to *bass_db*."""
    return {"peq1_db": float(bass_db), "peq2_db": float(bass_db)}


def eq_fields_for_treble(treble_db: int) -> dict:
    """The two output_eq band fields a dial treble step writes: peq6 at the
    full value, peq5 at half of it (a float -- the schema accepts fractional
    dB)."""
    return {"peq6_db": float(treble_db), "peq5_db": treble_db * _EQ_TREBLE_SECONDARY_SCALE}


def bass_treble_from_eq(oeq) -> tuple:
    """(bass, treble) as the dial shows them: peq1 and peq6, rounded to the
    nearest whole dB and clamped to the dial's own +/-6 dB range. A band the
    Equaliser page set beyond that range simply reads as the limit on the
    dial -- see the field's own read-back note where this is called."""
    clamp = lambda v: max(-EQ_BASS_TREBLE_LIMIT_DB, min(EQ_BASS_TREBLE_LIMIT_DB, int(round(v))))
    return clamp(oeq.peq1_db), clamp(oeq.peq6_db)


def dial_eq_bands(oeq) -> list:
    """Every output EQ band as the dial's band list: id (the stored field
    name without its "_db" suffix), centre frequency, filter type, the stored
    gain and the range a write is clamped to. Driven by OUTPUT_PEQ_BANDS, so a
    band added there appears here without a second table."""
    return [
        {
            "id": b["key"][:-3],
            "frequency_hz": int(b["freq_hz"]),
            "type": b["type"],
            "gain_db": float(getattr(oeq, b["key"])),
            "min_db": int(_OUTPUT_EQ_DB_MIN),
            "max_db": int(_OUTPUT_EQ_DB_MAX),
        }
        for b in OUTPUT_PEQ_BANDS
    ]


def eq_fields_for_bands(bands) -> Optional[dict]:
    """The output_eq band fields a dial "bands" write sets, from an
    {id: gain} object. Gains are ints or finite floats (not bools), clamped to
    the band range; only the named bands are returned. None when the object is
    empty or not a dict, an id is not a band, or a gain is not a finite
    number."""
    if not isinstance(bands, dict) or not bands:
        return None
    known = {b["key"][:-3] for b in OUTPUT_PEQ_BANDS}
    fields: dict = {}
    for band_id, raw in bands.items():
        if band_id not in known:
            return None
        if isinstance(raw, bool) or not isinstance(raw, (int, float)) or not math.isfinite(raw):
            return None
        fields[f"{band_id}_db"] = max(_OUTPUT_EQ_DB_MIN, min(_OUTPUT_EQ_DB_MAX, float(raw)))
    return fields


def apply_eq_fields(config_path: str, values: dict, *, settings=None) -> tuple:
    """Save and apply several output EQ band fields in one update: one store
    write, one live apply of the merged six bands -- unlike calling
    apply_eq_field() once per field, this never re-applies live or re-writes
    the store more than once for a single dial tap that moves two bands at
    once. Each field in *values* is validated through the same schema
    apply_eq_field() uses; a field absent from *values* keeps its currently
    stored value untouched (peq3/peq4 are never in *values* -- the dial never
    writes them).

    When *settings* is a SettingsStore instance, it is used as the sole
    persistence mechanism, same as apply_eq_field().

    Returns (ok, error_message).
    """
    from autostream_settings import SettingsStore as _SettingsStore
    _store = settings if isinstance(settings, _SettingsStore) else None

    from autostream_settings_schema import SETTINGS_SCHEMA
    normalised: dict = {}
    for field, value_raw in values.items():
        if field not in _OUTPUT_EQ_BAND_FIELDS:
            raise ValueError(f"Unknown field: {field!r}")
        normalised[field] = SETTINGS_SCHEMA[f"output_eq.{field}"].validate(value_raw)

    try:
        if _store is not None:
            pre_snap = _store.snapshot()
            _store.update(lambda raw: raw.setdefault("output_eq", {}).update(normalised))
            oeq = pre_snap.output_eq
        else:
            with CONFIG_IO_LOCK:
                cfg = load_config(config_path)
                p = parse_config(cfg)
                cfg.setdefault("output_eq", {}).update(normalised)
                save_config(config_path, cfg)
            oeq = p.output_eq

        band_vals = {b: float(getattr(oeq, b)) for b in _OUTPUT_EQ_BAND_FIELDS}
        band_vals.update(normalised)
        set_live_output_eq(
            band_vals["peq1_db"], band_vals["peq2_db"], band_vals["peq3_db"],
            band_vals["peq4_db"], band_vals["peq5_db"], band_vals["peq6_db"],
        )
    except Exception as e:
        logging.exception("apply_eq_fields: save failed")
        return False, str(e)

    notify_state_changed("eq")
    return True, ""


def apply_eq_reset(config_path: str, *, settings=None) -> tuple[bool, str]:
    """Zero all EQ band fields (peq1–peq6). Does not change output gain or auto-trim.

    When *settings* is a SettingsStore instance, uses it for atomic persistence.
    """
    from autostream_settings import SettingsStore as _SettingsStore
    _store = settings if isinstance(settings, _SettingsStore) else None

    try:
        if _store is not None:
            def _zero(raw: dict) -> None:
                eq = raw.setdefault("output_eq", {})
                for f in _OUTPUT_EQ_BAND_FIELDS:
                    eq[f] = 0.0
            _store.update(_zero)
        else:
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
    notify_state_changed("eq")
    return True, ""


# ---------------------------------------------------------------------------
# Shared output mutation
# ---------------------------------------------------------------------------

def _sanitized_volume(body: dict) -> int:
    """The body's volume clamped to 0-100, or 50 when absent or not a number."""
    raw_vol = body.get("volume")
    if raw_vol is None:
        return 50
    try:
        return max(0, min(100, int(raw_vol)))
    except (ValueError, TypeError):
        return 50


def sanitize_output_body(body: dict) -> tuple[Optional[dict], Optional[str]]:
    """Derive the trusted output-mutation body from a raw browser/peer JSON body.

    Shared by the local federation-server handler
    (``send_federation_output_json`` in autostream_webui_api.py) and the
    gateway client handler (``send_gateway_output_json`` in
    autostream_appliance_gateway.py) so the two write paths that forward a
    browser's POST body across the federation boundary re-derive the exact
    same accepted-field set from the exact same logic, rather than
    hand-duplicating it. Only the documented ``{"id", "op", "pin"}``,
    ``{"id", "op", "pin", "selected", "volume"}`` and
    ``{"id", "selected", "volume"}`` shapes are accepted; every other field
    on the raw body is dropped.

    Returns ``(sanitized, None)`` on success, or ``(None, error_code)`` on
    rejection, where *error_code* is one of "missing_output_id" or
    "invalid_request_body" (matching the wire error codes both call sites
    already emit).
    """
    out_id = str(body.get("id") or "").strip()
    if not out_id:
        return None, "missing_output_id"

    sanitized: dict = {"id": out_id}
    op = str(body.get("op") or "").strip().lower()
    if op == "pin":
        pin_val = body.get("pin")
        if not isinstance(pin_val, str) or not pairing.PIN_RE.match(pin_val):
            return None, "invalid_request_body"
        sanitized["op"] = "pin"
        sanitized["pin"] = pin_val
        if "selected" in body:
            selected_raw = body.get("selected")
            if not isinstance(selected_raw, bool):
                return None, "invalid_request_body"
            sanitized["selected"] = selected_raw
            sanitized["volume"] = _sanitized_volume(body)
    elif op == "":
        selected_raw = body.get("selected")
        if not isinstance(selected_raw, bool):
            return None, "invalid_request_body"
        sanitized["selected"] = selected_raw
        sanitized["volume"] = _sanitized_volume(body)
    else:
        return None, "invalid_request_body"

    return sanitized, None


def apply_output_mutation(
    owntone_base_url: str,
    out_id: str,
    body: dict,
    *,
    offset_ms: Optional[int] = None,
    mode: Optional[str] = None,
    output_name: str = "",
    initiated_by: str,
    requester: Optional[str] = None,
) -> dict:
    """Apply an output toggle/volume change or PIN submission.

    *body* must contain at least {"id": ..., "op": ...} or {"id": ..., "selected": bool}.
    *offset_ms* and *mode* come from the per-output config (not from the browser body).
    *output_name* is optional; when provided (or resolved internally) the occupancy
    cache is checked before enabling. If the name cannot be resolved the check is
    skipped (fail-open) and a debug message is logged.

    initiated_by: "user" or "system". Supplied by trusted internal code only.
        Selects whether the per-user-action bookkeeping below runs:

        - note_user_output_action() is called at function entry whenever
          initiated_by == "user", regardless of the op (including "pin") and
          regardless of whether the mutation goes on to succeed or fail. This
          mirrors the pre-centralisation local handler's behaviour, which
          noted the action unconditionally before attempting the mutation; a
          false-conservative widening of the coordinator's reconcile
          suppression window is harmless, a missed marker is not.
        - The user-chosen-silence latch is only touched for non-pin ops that
          carry a "selected" field, and only once the mutation has
          succeeded: selected=True clears the latch; selected=False re-fetches
          the live output list and sets the latch iff zero outputs remain
          selected. A failed re-fetch leaves the latch untouched (fail open).

        System-initiated calls (initiated_by="system", e.g. the coordinator's
        own auto-select/reconcile paths) perform none of the above.

    requester: the identity that can enter a PIN for this mutation
        (pairing.REQUESTER_WEBUI or pairing.dial_requester(...)); None when
        the caller cannot. Supplied by trusted route code only. A PIN
        attempt without one is counted against the WebUI's budget; an enable
        that needs a PIN records the requester as the one pairing the output.

    A "pin" op that also carries "selected" enables the output (using
    "volume") straight after the PIN is accepted, in the same call.

    Raises ValueError if initiated_by is not "user" or "system".

    Returns a result dict with keys: ok, id, and optional
    error/pin_required/pin_invalid/retry_after_s (error is "invalid_pin" for a
    PIN that is not 4 to 8 digits and "rate_limited" when too many PINs were
    tried, with retry_after_s the seconds to wait; error is "encoder_capacity"
    when the appliance's buffered-encode admission control declines the enable).

    A change that went through is hinted to the dials.
    """
    result = _apply_output_mutation(
        owntone_base_url,
        out_id,
        body,
        offset_ms=offset_ms,
        mode=mode,
        output_name=output_name,
        initiated_by=initiated_by,
        requester=requester,
    )
    if result.get("ok"):
        notify_state_changed("outputs")
    return result


def _apply_output_mutation(
    owntone_base_url: str,
    out_id: str,
    body: dict,
    *,
    offset_ms: Optional[int] = None,
    mode: Optional[str] = None,
    output_name: str = "",
    initiated_by: str,
    requester: Optional[str] = None,
) -> dict:
    """The mutation behind apply_output_mutation, without the hint."""
    initiated_by_text = str(initiated_by or "").strip().lower()
    if initiated_by_text not in ("user", "system"):
        raise ValueError(f"Invalid initiated_by value: {initiated_by!r}")
    is_user_initiated = initiated_by_text == "user"

    op = (body.get("op") or "").strip().lower()
    out_id_text = str(out_id or "").strip()

    if is_user_initiated:
        # Record that a user-initiated output change was attempted, so the
        # coordinator's OwnTone-restart reconcile (autostream_core.py,
        # _OwntoneReconcileTracker) can tell "OwnTone forgot everything" apart
        # from "the user deselected everything on purpose". Recorded
        # unconditionally (including "pin" ops and failed mutations) since a
        # false-conservative widening of the suppression window is harmless;
        # only a missed marker would matter.
        note_user_output_action()

    if not out_id_text:
        return {"ok": False, "error": "Missing output id"}

    if op == "pin":
        pin = body.get("pin")
        if not isinstance(pin, str) or not pairing.PIN_RE.match(pin):
            return {"ok": False, "error": "invalid_pin", "id": out_id_text}
        allowed, wait = pairing.note_attempt(requester or pairing.REQUESTER_WEBUI, out_id_text)
        if not allowed:
            return {
                "ok": False,
                "error": "rate_limited",
                "retry_after_s": wait,
                "id": out_id_text,
            }
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
        pairing.release(out_id_text)
        if not body.get("selected"):
            return {"ok": True, "id": out_id_text}

    selected = bool(body.get("selected", False))
    if selected:
        # Resolve trusted name and local selection state from OwnTone.
        # body.get("name") is intentionally ignored to prevent bypass.
        resolved_name, locally_selected = _resolve_output_info(owntone_base_url, out_id_text)
        name_to_check = output_name or resolved_name
        # Only block enables of outputs not already locally selected.
        # Volume changes on already-on outputs are always allowed.
        if name_to_check and not locally_selected:
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

        if locally_selected and is_user_initiated and mute_state.is_muted():
            # The WebUI has no dedicated unmute control: an explicit,
            # user-initiated volume change on an already-selected output
            # while muted IS the unmute path -- end the mute here and fall
            # through to the normal write below so the output actually
            # sounds at the level the user just chose (not the level that
            # was remembered when the mute began). When the master slider
            # writes several outputs in one gesture, only the first write
            # sees is_muted() True; the rest already see it unmuted and
            # simply write normally, which is fine.
            mute_state.end_mute()
        elif locally_selected and mute_state.remember_level(out_id_text, volume):
            # A volume-only change on an output that is already selected,
            # made by something other than the user (coordinator/reconcile)
            # while the appliance is muted: the level it will return to on
            # restore moves, but the output itself must stay silent, so the
            # OwnTone write is skipped entirely -- muted keeps meaning
            # silent no matter which non-user caller last touched a level.
            return {"ok": True, "id": out_id_text}

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
            # Output was NOT enabled; cache state is unchanged.
            if requester:
                pairing.claim(out_id_text, requester)
            return {
                "ok": False,
                "pin_required": True,
                "id": out_id_text,
                "output_name": str(body.get("name") or ""),
                "error": update_result.message,
            }
        if not update_result.ok and update_result.error_code == "encoder_capacity":
            # Output was NOT enabled; cached selection state is unchanged.
            return {"ok": False, "id": out_id_text, "error": "encoder_capacity"}
        if not update_result.ok:
            # OwnTone rejected; state uncertain — expire cache so next call re-fetches.
            _invalidate_output_info_cache(owntone_base_url)
            return {
                "ok": False,
                "id": out_id_text,
                "error": update_result.message,
                "pin_invalid": False,
            }
        _update_cached_selected(owntone_base_url, out_id_text, True)
        if not locally_selected and mute_state.remember_level(out_id_text, volume):
            # Enabling an output while muted: it just joined the session at
            # its requested volume, but a mute in effect means silent, so it
            # is immediately silenced too. Its requested level is what the
            # restore action brings it to (see autostream_mute_state.py). A
            # failure here is logged and leaves the output audible --
            # fail-open, and this function never raises.
            silence_result = update_output(owntone_base_url, out_id_text, volume_percent=0, timeout=3)
            if not silence_result.ok:
                logging.warning(
                    "apply_output_mutation: could not silence newly-enabled output %s under mute: %s",
                    out_id_text, silence_result.message,
                )
        if is_user_initiated:
            # User enabled an output: any prior "chose silence" latch no
            # longer applies to the current output selection.
            clear_user_silence_latch()
        # A newly enabled output joins the session knowing only the queue
        # defaults -- it never saw the bundle published at session start.
        # Ask the coordinator to re-send the current now-playing metadata so
        # the receiver shows the proper title/artwork immediately rather
        # than at the next natural push (e.g. the next track change).
        request_nowplaying_republish()
        return {"ok": True, "id": out_id_text}

    disable_result = set_output_enabled(owntone_base_url, out_id_text, False, timeout=3)
    if not disable_result.ok:
        _invalidate_output_info_cache(owntone_base_url)
        return {"ok": False, "id": out_id_text, "error": disable_result.message}
    _update_cached_selected(owntone_base_url, out_id_text, False)
    mute_state.forget_output(out_id_text)
    if is_user_initiated:
        # User disabled an output. If that was the last selected output,
        # latch the resulting zero-output state as user-chosen so the
        # coordinator's reconcile/retry don't fight it. Re-fetch outputs
        # rather than trust local state, since other outputs' selection is
        # not known to this call. On fetch failure the state is unknown, so
        # fail open (do not set the latch) rather than risk latching a
        # zero-output state that may not actually be all-zero.
        try:
            list_result = list_outputs(owntone_base_url, timeout=3)
        except Exception:
            list_result = None
        if list_result is not None and getattr(list_result, "ok", False):
            if not any(bool(o.selected) for o in list_result.outputs):
                set_user_silence_latch()
    return {"ok": True, "id": out_id_text}
