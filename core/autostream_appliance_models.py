"""autostream_appliance_models.py -- shared Home and Equaliser state models.

Provides build_home_state() and build_equaliser_state() plus shared
output and EQ mutation helpers used by both local API endpoints and
target-side federation APIs.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
import math
import time
from typing import Optional

import autostream_pin_pairing as pairing
from autostream_config import parse_config
from autostream_core import get_live_output_eq_status
from autostream_eq_bands import OUTPUT_EQ_DB_MAX, OUTPUT_EQ_DB_MIN, OUTPUT_PEQ_BANDS
from autostream_intents import Intent, submit
from autostream_state import Origin, active_track, store
from autostream_player_service import (
    config_airplay_mode_to_backend,
    get_setting,
)
from autostream_players import SETTING_START_BUFFER_MS, SETTING_START_BUFFER_MS_DEFAULT
from autostream_rpi import get_appliance_id
from autostream_sysutils import get_system_hostname
from autostream_webui_common import get_app_version, locked_load_config

# ---------------------------------------------------------------------------
# Output-list builder (shared between Home page and federation)
# ---------------------------------------------------------------------------

def build_output_list(parsed, units) -> list[dict]:
    """Filter and sort the output authority's units into the standard dict
    representation.

    Applies hidden-output filtering, puts the configured default first, then
    alphabetical order.  Returns dicts with keys: id, name, selected, volume,
    is_default, needs_auth_key, requires_auth, pin_pending, pin_claim
    (the requester currently entering a PIN for the output, or "").

    "volume" is the INTENDED level (the unit's own volume in the snapshot):
    while the output is muted this is the level it will return to on
    restore, not its actual (silenced) OwnTone volume -- so every consumer
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
    for unit in units:
        row = unit.reported
        if row is None:
            continue  # the player has no row for it at the moment
        out_id = str(unit.id or "").strip()
        name = str(unit.name or "").strip()
        if not out_id or not name:
            continue
        selected = bool(unit.shown_selected)
        if name.casefold() in hidden and not selected and name != default_output_name:
            continue
        vol = max(0, min(100, int(unit.volume)))
        result.append({
            "id": out_id,
            "name": name,
            "selected": selected,
            "volume": vol,
            "is_default": (name == default_output_name),
            "needs_auth_key": bool(row.needs_auth_key),
            "requires_auth": bool(row.requires_auth),
            "pin_pending": bool(row.pin_pending),
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

    The output list comes from the output authority's snapshot. When *deadline*
    is set (a time.monotonic() value), the one remaining OwnTone call (the
    start-buffer setting) is given what is left of the federation 1.5-second
    internal budget; a call that misses it produces the reachable-appliance
    waiting model rather than falsely marking the appliance offline.

    When *deadline* is None (local mode) the existing timeout is used.

    Returns a dict with keys: ok, appliance, preferences, playback, input_levels,
    warnings, outputs, vu_delay_ms.
    """
    snap = store().snapshot()
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
            "warnings": {
                "stylus": "", "belt": "", "bearing": "", "dial_update": "", "sample_rate": "",
            },
            "outputs": [],
            "muted": snap.outputs.muted_all,
            "vu_delay_ms": SETTING_START_BUFFER_MS_DEFAULT,
            "track_identification": disabled_snapshot().to_public_dict(),
            **_session_and_repeat_fields(snap),
        }

    input_levels = snap.inputs.levels()

    playback = snap.playback

    owntone_base_url = parsed.owntone.base_url
    vu_delay_ms = SETTING_START_BUFFER_MS_DEFAULT
    outputs: list[dict] = []

    if deadline is None:
        try:
            buf_result = get_setting(owntone_base_url, SETTING_START_BUFFER_MS, timeout=1)
            vu_delay_ms = int(buf_result.value) if buf_result.ok else SETTING_START_BUFFER_MS_DEFAULT
        except Exception:
            vu_delay_ms = SETTING_START_BUFFER_MS_DEFAULT
    else:
        # Federation mode: the one call shares what is left of the budget.
        # Reserve a small margin for overhead.
        per_call = min(max(0.0, deadline - time.monotonic()), 1.5)
        if per_call > 0.05:
            vu_delay_ms = _safe_get_setting(owntone_base_url, per_call)

    if snap.outputs.connected:
        outputs = build_output_list(parsed, snap.outputs.units)

    try:
        from autostream_output_usage import annotate_outputs
        outputs = annotate_outputs(outputs)
    except Exception:
        pass

    ti_dict = active_track(snap).to_public_dict()

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
            "sample_rate": snap.inputs.sample_rate_warning_text,
        },
        "outputs": outputs,
        "muted": snap.outputs.muted_all,
        "vu_delay_ms": int(vu_delay_ms),
        "track_identification": ti_dict,
        **_session_and_repeat_fields(snap),
    }


def _dial_update_banner_text() -> str:
    """Dial-update banner text, or "" when none is due or the dial scanner
    is unavailable (never raises)."""
    try:
        from autostream_dials import build_dial_update_banner_text
        return build_dial_update_banner_text()
    except Exception:
        return ""


def _session_and_repeat_fields(snap) -> dict:
    """Return the "session" (always present) and "repeat" (present only when
    the daemon has reported one) fields for build_home_state()'s dict.

    Sourced identically to send_status_json (autostream_webui_api.py): the
    session comes from the caller's snapshot, and the repeat block is passed
    through verbatim when present -- omitted entirely (not a KeyError) when
    the daemon has never reported one, so an older backend degrades by
    absence rather than by error.
    """
    fields: dict = {"session": snap.session.as_dict()}
    repeat_status = snap.repeat.block
    if repeat_status is not None:
        fields["repeat"] = repeat_status
    return fields


def _safe_get_setting(base_url: str, timeout: float) -> int:
    try:
        result = get_setting(base_url, SETTING_START_BUFFER_MS, timeout=timeout)
        return int(result.value) if result.ok else SETTING_START_BUFFER_MS_DEFAULT
    except Exception:
        return SETTING_START_BUFFER_MS_DEFAULT


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
    peq1_db ... peq6_db, output_auto_trim_enabled, output_auto_trim_db,
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
            "min_db": int(OUTPUT_EQ_DB_MIN),
            "max_db": int(OUTPUT_EQ_DB_MAX),
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
        fields[f"{band_id}_db"] = max(OUTPUT_EQ_DB_MIN, min(OUTPUT_EQ_DB_MAX, float(raw)))
    return fields


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


def submit_output_change(
    body: dict,
    *,
    requester: str,
    pin_requester: Optional[str],
    offset_ms: Optional[int] = None,
    mode: Optional[str] = None,
    origin: Origin = Origin.USER,
) -> dict:
    """Switch a speaker on or off, change its volume, or submit its PIN, and
    return the reply body the output routes send.

    *body* is {"id", "selected"[, "volume"]}, or {"id", "op": "pin", "pin"[,
    "selected", "volume"]}; *offset_ms* and *mode* come from the per-output
    configuration, never from the browser. *requester* names the caller for
    the intent path ("webui", "dial:<uuid>", "peer"); *pin_requester* is the
    identity that can enter a PIN for the speaker (None when the caller
    cannot). A pin op that also carries "selected" switches the speaker on
    straight after the PIN is accepted.
    """
    out_id = str(body.get("id") or "").strip()
    if not out_id:
        return {"ok": False, "error": "Missing output id"}
    op = str(body.get("op") or "").strip().lower()
    args: dict = {"id": out_id}
    name = body.get("name")
    if name:
        args["name"] = str(name)[:256]
    if op == "pin":
        args["pin"] = body.get("pin")
        if "selected" in body:
            args["selected"] = bool(body.get("selected"))
        row = "output.pin.submit"
    else:
        args["selected"] = bool(body.get("selected", False))
        row = "outputs.set"
    if args.get("selected"):
        args["volume"] = max(0, min(100, int(body.get("volume", 50))))
        if offset_ms is not None:
            args["offset_ms"] = offset_ms
        if mode:
            args["mode"] = mode
    reply = submit(Intent(row, args, origin, requester, context=pin_requester))
    if reply.result:
        return dict(reply.result)
    return {"ok": False, "error": reply.error, "id": out_id}
