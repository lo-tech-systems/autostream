#!/usr/bin/env python3
"""webui/dial/api.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

The dial protocol endpoints: UUID-authorised JSON posts from the dial.

Contents:
  - send_dial_volume_post_json   -- POST /api/dial/volume
  - send_dial_status_post_json   -- POST /api/dial/status
  - send_dial_mute_post_json     -- POST /api/dial/mute
  - send_dial_repeat_post_json   -- POST /api/dial/repeat
  - send_dial_repeat_arm_post_json -- POST /api/dial/repeat/arm
  - send_dial_outputs_post_json  -- POST /api/dial/outputs
  - send_dial_outputs_set_post_json -- POST /api/dial/outputs/set
  - send_dial_capabilities_json  -- GET /api/dial/capabilities
  - send_dial_eq_post_json       -- POST /api/dial/eq
  - send_dial_eq_set_post_json   -- POST /api/dial/eq/set
  - send_dial_warnings_post_json -- POST /api/dial/warnings
"""

from __future__ import annotations

import json
import logging
import math

from types import SimpleNamespace
from typing import Optional

from autostream_config import DEFAULT_AIRPLAY_MODE, input_type_label, normalize_input_type
import autostream_rpi as rpi
from autostream_dials import (
    AUTH_AUTHORIZED,
    AUTH_UNAVAILABLE,
    DIAL_CAPABILITIES,
    DIAL_PROTO_VERSION,
    dial_authorization,
    dial_speaks_v2,
)
from autostream_intents import Intent, submit
from autostream_state import Origin, active_track, session_source_input_index, store
from autostream_state.live import current_warnings, start_buffer_ms, warnings_payload
from autostream_pin_pairing import dial_requester
from webui.browser import home_model
from webui.browser.home_model import (
    start_failure_reply,
    bass_treble_from_eq,
    build_output_list,
    EQ_BASS_TREBLE_LIMIT_DB,
    dial_eq_bands,
    eq_fields_for_bands,
    eq_fields_for_bass,
    eq_fields_for_treble,
    sanitize_output_body,
)
from webui.session_state import WebUIState
from webui import common
from webui.system import updates


def send_dial_volume_post_json(handler, state: WebUIState, json_obj: dict) -> None:
    """POST /api/dial/volume -- UUID-auth only (no session/CSRF required).

    Applies a volume delta to all selected OwnTone outputs proportionally.
    Returns {"ok": true, "volume": <new_master>, "muted": false} on success.

    This is the only master-volume delta endpoint (the WebUI's master slider
    writes absolute per-output volumes instead), so the mute-aware rule lives
    here for every stepper client: while the selection is muted, a
    non-positive delta is a no-op (there is no lower level than silent to
    step to) that reports the level the outputs will return to and
    muted:true; a positive delta is a plain restore to the remembered levels
    -- no step is added on top of it -- and reports muted:false. The rule
    itself is the output authority's (the volume.step intent).
    """
    dial_id = json_obj.get("dial_id", "")
    delta = json_obj.get("delta")

    if not isinstance(dial_id, str) or not dial_id:
        common.send_json(handler, 403, {})
        return
    if _dial_auth_gate(handler, json_obj) is None:
        return
    if not isinstance(delta, int) or isinstance(delta, bool):
        common.send_json(handler, 200, {"ok": False, "error": "invalid_delta"})
        return
    delta = max(-100, min(100, delta))

    try:
        parsed = common._config_snapshot(state)
        default_vol = parsed.owntone.volume_percent
    except Exception as e:
        logging.warning("dial volume: config load failed: %s", e)
        common.send_json(handler, 200, {"ok": False, "error": "config_error"})
        return

    reply = submit(Intent(
        "volume.step", {"delta": delta, "default_level": default_vol},
        Origin.USER, dial_requester(dial_id),
    ))
    common.send_json(handler, 200, dict(reply.result) if reply.result else {"ok": False, "error": reply.error})


def calculate_master_volume(outputs) -> tuple:
    """Return (master_volume, selected_output_count) for selected outputs.

    For each selected output, volume_percent is converted to int and clamped to
    0..100.  Returns (ceil(sum/count), count), or (None, 0) when none selected.

    Rounds UP, deliberately, so a genuinely mixed but mostly-audible selection
    never displays a hair below its true level. Mute is no longer inferred
    from a reported 0 -- the appliance carries an explicit muted flag instead
    (the output authority holds it) -- but the home page's master control still
    reads this figure directly, so the same rounding-up choice is kept for its
    sake: rounding to nearest could report one output's exact 0 as the whole
    selection's master when the others are only barely above it, which reads
    worse than costing at most one percentage point the other way.

    Note this is NOT the same rounding as send_dial_volume_post_json()'s own
    current_master, which stays round-to-nearest on purpose: it feeds the
    scale-from-zero special case that lifts every output back up when the
    volume is nudged from silence.
    """
    volumes = [
        max(0, min(100, int(o.volume_percent)))
        for o in outputs
        if o.selected
    ]
    if not volumes:
        return (None, 0)
    return (math.ceil(sum(volumes) / len(volumes)), len(volumes))


def _dial_track_id_dict(snap=None) -> dict:
    """Return the grouped track_id object for POST /api/dial/status.

    artwork_url is exposed only for identified results with a validated
    http(s) provider URL -- every other state reports an empty string.
    """
    from track_id.models import STATE_IDENTIFIED

    track = active_track(snap if snap is not None else store().snapshot())
    artwork_url = track.artwork_url or ""
    if track.state != STATE_IDENTIFIED or not artwork_url.startswith(("http://", "https://")):
        artwork_url = ""
    return {
        "enabled": track.enabled,
        "state": track.state,
        "title": track.title,
        "artist": track.artist,
        "album": track.album,
        "artwork_url": artwork_url,
        "updated_at": track.updated_at,
        "last_attempt_at": track.last_attempt_at,
    }


def _derive_repeat_state(rs: dict) -> str:
    """Derive the dial protocol's repeat state from a cached daemon "repeat"
    status block. The daemon's internal "pending" admission window is
    invisible here and reads as "idle"."""
    rec = rs.get("recording") if isinstance(rs.get("recording"), dict) else {}
    rep = rs.get("replay") if isinstance(rs.get("replay"), dict) else {}
    if rep.get("active") and rep.get("fading_out"):
        return "fading_out"
    if rep.get("active"):
        return "replaying"
    if rec.get("active"):
        return "recording"
    if (rec.get("seconds") or 0) > 0:
        return "hold"
    return "idle"


def _dial_repeat_object(base_url: str | None = None, snap=None) -> dict | None:
    """The dial protocol's "repeat" object for POST /api/dial/status, or
    None when the daemon block is unavailable (older monitor binary, or no
    poll yet). Every field but state, available and latency_ms is a
    passthrough of the repeat block of the state snapshot (the caller's
    *snap*, or the current one).
    latency_ms is the audio start buffer, read from a cache so this never
    waits on OwnTone."""
    rs = (snap if snap is not None else store().snapshot()).repeat.block
    if not isinstance(rs, dict):
        return None
    rec = rs.get("recording") if isinstance(rs.get("recording"), dict) else {}
    rep = rs.get("replay") if isinstance(rs.get("replay"), dict) else {}
    enabled = bool(rs.get("enabled"))
    state = _derive_repeat_state(rs) if enabled else "idle"
    return {
        "available": enabled,
        "state": state,
        "armed": bool(rs.get("armed")),
        "held": state == "hold",
        "recording_seconds": float(rec.get("seconds") or 0.0),
        "replay": {
            "active": bool(rep.get("active")),
            "position_seconds": float(rep.get("position_seconds") or 0.0),
            "duration_seconds": float(rep.get("duration_seconds") or 0.0),
        },
        "latency_ms": start_buffer_ms(base_url),
    }


def _dial_input_dict(parsed, snap=None) -> dict | None:
    """The dial protocol's "input" object: the input behind the current
    session, or None when nothing is playing. A replay resolves to the
    input it was recorded from. Reads cached state and the config snapshot
    only."""
    idx = session_source_input_index(
        snap if snap is not None else store().snapshot())
    if idx not in (1, 2):
        return None
    audio = parsed.audio1 if idx == 1 else parsed.audio2
    input_type = normalize_input_type(getattr(audio, "input_type", "line"))
    return {"index": idx, "type": input_type, "label": input_type_label(input_type)}


def _dial_auth_gate(handler, json_obj: dict) -> str | None:
    """Shared dial_id/authorization guard for the dial protocol routes.

    Returns the dial_id when the caller is authorized, else sends the
    protocol response itself and returns None:
      400 {"ok": false, "error": "missing_dial_id"}        dial_id absent, empty or not a string
      200 {"ok": false, "error": "auth_unavailable"}       dials store unreadable (transient to the dial)
      412 {"ok": false, "error": "dial_not_authorized",
           "appliance_id": <id or null>}                   definitive miss, dial speaks v2
      403 {}                                               definitive miss, any other dial
                                                           (legacy or not currently sighted)

    Order matters: the shape check (400) runs before the store is ever read,
    so a malformed request never touches the file; the store-unavailable
    case (200 ok:false) is checked before the definitive-miss case (412).
    """
    dial_id = json_obj.get("dial_id", "")
    if not isinstance(dial_id, str) or not dial_id:
        common.send_json(handler, 400, {"ok": False, "error": "missing_dial_id"})
        return None
    auth = dial_authorization(dial_id)
    if auth == AUTH_UNAVAILABLE:
        common.send_json(handler, 200, {"ok": False, "error": "auth_unavailable"})
        return None
    if auth != AUTH_AUTHORIZED:
        if not dial_speaks_v2(dial_id):
            common.send_json(handler, 403, {})
            return None
        common.send_json(handler, 412, {
            "ok": False,
            "error": "dial_not_authorized",
            "appliance_id": rpi.get_appliance_id(),
        })
        return None
    return dial_id


def _dial_start_failure(snap, dial_id: str) -> dict:
    """The latest failed speaker start as a dial sees it: the Home fields with
    the requester replaced by whether this dial asked."""
    body = start_failure_reply(snap)
    requester = body.pop("requester")
    body["mine"] = requester == dial_requester(dial_id)
    return body


def send_dial_status_post_json(handler, state: WebUIState, json_obj: dict) -> None:
    """POST /api/dial/status -- UUID-auth only (no session/CSRF required).

    Returns fresh, side-effect-free playing state, master volume, and grouped
    track_id now-playing state. Never fetches remote artwork on the request path.
    """
    dial_id = _dial_auth_gate(handler, json_obj)
    if dial_id is None:
        return

    snap = store().snapshot()
    playing = common._session_playing(snap)

    try:
        parsed = common._config_snapshot(state)
        base_url = parsed.owntone.base_url
    except Exception as e:
        logging.warning("dial status: config load failed: %s", e)
        common.send_json(handler, 200, {"ok": False, "error": "config_error"})
        return

    if not snap.outputs.connected:
        logging.warning("dial status: the player is not answering")
        common.send_json(handler, 200, {"ok": False, "error": "backend_unavailable"})
        return

    muted = snap.outputs.muted_all
    reported_outputs = [
        SimpleNamespace(id=u.id, selected=u.shown_selected, volume_percent=u.volume)
        for u in snap.outputs.units if u.reported is not None
    ]
    master_volume, selected_output_count = calculate_master_volume(reported_outputs)
    response = {
        "ok": True,
        "playing": playing,
        "master_volume": master_volume,
        "selected_output_count": selected_output_count,
        "track_id": _dial_track_id_dict(snap),
        "appliance_id": rpi.get_appliance_id(),
        "muted": muted,
        "input": _dial_input_dict(parsed, snap),
    }
    if snap.outputs.start_failure is not None:
        response["start_failure"] = _dial_start_failure(snap, dial_id)
    repeat = _dial_repeat_object(base_url, snap)
    if repeat is not None:
        response["repeat"] = repeat
    common.send_json(handler, 200, response)


# Error tokens the daemon itself can produce for a transport/arm ack, passed
# through as-is rather than mapped to backend_unavailable. Anything else --
# including an older daemon's "unknown command: repeat_seek" -- is backend_unavailable.
_REPEAT_KNOWN_ERRORS = frozenset({
    "repeat_unavailable", "source_active", "no_recording", "fading_out",
    "invalid_position",
})

def _send_dial_repeat_ack(handler, ack: Optional[dict]) -> None:
    """Map a daemon transport/arm ack to the dial protocol's repeat response.

    Shared by POST /api/dial/repeat and POST /api/dial/repeat/arm. ack is
    None (daemon unreachable) or ok:false with an error the daemon minted
    that is not one of _REPEAT_KNOWN_ERRORS (including an older daemon's
    "unknown command: ...") -> backend_unavailable; a known ok:false error
    is passed through as-is; ok:true carries position_seconds too. state
    defaults to "idle" and armed to False when the ack lacks them (an old
    daemon's set_repeat_armed ack has neither field).
    """
    if not isinstance(ack, dict) or not ack.get("ok"):
        error = ack.get("error") if isinstance(ack, dict) else None
        if error not in _REPEAT_KNOWN_ERRORS:
            error = "backend_unavailable"
        common.send_json(handler, 200, {
            "ok": False,
            "error": error,
            "state": (ack or {}).get("state", "idle"),
            "armed": bool((ack or {}).get("armed", False)),
            "appliance_id": rpi.get_appliance_id(),
        })
        return
    common.send_json(handler, 200, {
        "ok": True,
        "state": ack.get("state", "idle"),
        "armed": bool(ack.get("armed", False)),
        "position_seconds": float(ack.get("position_seconds", 0.0)),
        "appliance_id": rpi.get_appliance_id(),
    })


def send_dial_repeat_post_json(handler, state: WebUIState, json_obj: dict) -> None:
    """POST /api/dial/repeat -- repeat-replay transport (stop|seek).

    UUID-in-body auth via _dial_auth_gate, same as POST /api/dial/status.
    Start is expressed as seek 0 -- the dial never sends a nonzero position.
    Seek is rate-limited to one call per second appliance-wide, whoever asks
    (the intent table holds the limit); stop is idempotent (the daemon acks ok:true in every state) and never
    rate-limited. Never reads the repeat block: the response is built
    entirely from the daemon's own transport ack.
    """
    dial_id = _dial_auth_gate(handler, json_obj)
    if dial_id is None:
        return
    action = json_obj.get("action")
    if action not in ("stop", "seek"):
        common.send_json(handler, 400, {"ok": False, "error": "invalid_action"})
        return
    position = 0.0
    if action == "seek":
        raw = json_obj.get("position_seconds", 0)
        if isinstance(raw, bool) or not isinstance(raw, (int, float)) \
                or not math.isfinite(raw) or raw < 0:
            common.send_json(handler, 400, {"ok": False, "error": "invalid_position"})
            return
        position = float(raw)
    requester = f"dial:{dial_id}"
    if action == "seek":
        reply = submit(Intent("repeat.seek", {"position": position}, Origin.USER, requester))
    else:
        reply = submit(Intent("repeat.transport", {"action": "stop"}, Origin.USER, requester))
    if reply.error == "rate_limited":
        common.send_json(handler, 200, {"ok": False, "error": "rate_limited",
                                 "appliance_id": rpi.get_appliance_id()})
        return
    ack = reply.result.get("ack")
    if reply.error == "invalid_position" and "ack" not in reply.result:
        # Past the largest position the intent accepts; the daemon refuses it
        # with the same token.
        ack = {"ok": False, "error": "invalid_position"}
    _send_dial_repeat_ack(handler, ack)


def send_dial_repeat_arm_post_json(handler, state: WebUIState, json_obj: dict) -> None:
    """POST /api/dial/repeat/arm -- arm/disarm repeat-replay from the dial.

    UUID-in-body auth via _dial_auth_gate, same as POST /api/dial/status.
    Submits the arm intent directly, never apply_repeat_arm_request
    (that string-body API stays the contract for POST /api/repeat, federation
    and the gateway). Arm is allowed in every daemon state -- the daemon's
    Armed/Disarmed cells decide what it means.
    """
    dial_id = _dial_auth_gate(handler, json_obj)
    if dial_id is None:
        return
    armed = json_obj.get("armed")
    if not isinstance(armed, bool):
        common.send_json(handler, 400, {"ok": False, "error": "invalid_armed"})
        return
    reply = submit(Intent("repeat.arm", {"armed": armed}, Origin.USER, f"dial:{dial_id}"))
    _send_dial_repeat_ack(handler, reply.result.get("ack"))


def _dial_outputs_list(parsed) -> Optional[list]:
    """The Home page's output list, as the dial sees it: the same three
    functions the Home page itself uses for its output list (hidden-output
    filtering and default-first ordering, then remote-occupancy annotation),
    trimmed to the fields the dial needs, including whether each output is the
    configured default. None when OwnTone is unreachable.
    """
    part = store().snapshot().outputs
    if not part.connected:
        return None
    outputs = build_output_list(parsed, part.units)
    from autostream_state.live import annotate_outputs
    return [
        {
            "id": o["id"], "name": o["name"], "selected": o["selected"],
            "volume": o["volume"], "remote_in_use": bool(o.get("remote_in_use")),
            "remote_owner": str(o.get("remote_owner") or ""),
            "is_default": bool(o.get("is_default")),
            "pin_pending": bool(o.get("pin_pending")),
            "needs_auth_key": bool(o.get("needs_auth_key")),
            "pin_claim": str(o.get("pin_claim") or ""),
        }
        for o in annotate_outputs(outputs)
    ]


def send_dial_outputs_post_json(handler, state: WebUIState, json_obj: dict) -> None:
    """POST /api/dial/outputs -- UUID-auth; the focused appliance's outputs
    for the dial, with outputs in use by another autostream instance hidden.
    """
    if _dial_auth_gate(handler, json_obj) is None:
        return
    try:
        parsed = common._config_snapshot(state)
    except Exception as e:
        logging.warning("dial outputs: config load failed: %s", e)
        common.send_json(handler, 200, {"ok": False, "error": "config_error"})
        return
    outputs = _dial_outputs_list(parsed)
    if outputs is None:
        common.send_json(handler, 200, {"ok": False, "error": "backend_unavailable"})
        return
    common.send_json(handler, 200, {"ok": True, "outputs": outputs, "appliance_id": rpi.get_appliance_id()})


def send_dial_capabilities_json(handler, state: WebUIState) -> None:
    """GET /api/dial/capabilities -- unauthenticated, read-only.

    The capability list a dial reads before it is authorised, so it carries
    only what the mDNS records already broadcast: identity, version, protocol
    generation and the capability table. Static for a given software version.
    """
    common.send_json(handler, 200, {
        "ok": True,
        "appliance_id": rpi.get_appliance_id(),
        "version": updates.get_app_version(),
        "dial_proto": int(DIAL_PROTO_VERSION[1:]),
        "capabilities": dict(DIAL_CAPABILITIES),
    })


def send_dial_warnings_post_json(handler, state: WebUIState, json_obj: dict) -> None:
    """POST /api/dial/warnings -- UUID-auth; the warnings this appliance
    wants a dial to show (maintenance wear, power supply). An empty list is a
    successful "nothing to report"; config_error means the list could not be
    built, which a dial treats as "keep what you have"."""
    if _dial_auth_gate(handler, json_obj) is None:
        return
    try:
        warnings = current_warnings()
    except Exception as e:
        logging.warning("dial warnings: build failed: %s", e)
        common.send_json(handler, 200, {"ok": False, "error": "config_error"})
        return
    common.send_json(handler, 200, {
        "ok": True,
        "appliance_id": rpi.get_appliance_id(),
        "warnings": warnings_payload(warnings),
    })


def send_dial_outputs_set_post_json(handler, state: WebUIState, json_obj: dict) -> None:
    """POST /api/dial/outputs/set -- UUID-auth; enable, disable or set the
    volume of one output through the same mutation the browser uses.

    Enabling without an explicit volume applies the configured default
    volume, exactly as the setup page does; a volume change on an already-
    enabled output and a disable pass through untouched. Rejections
    (output already in use elsewhere, a PIN required or wrong, attempts
    limited with the seconds to wait, encoder capacity) are typed and
    returned as-is. A dial that declares pin_capable, or submits a PIN, is
    the pairing requester for the output; the PIN rule and the attempt limit
    are applied by the mutation.
    """
    dial_id = _dial_auth_gate(handler, json_obj)
    if dial_id is None:
        return
    body = {k: json_obj.get(k) for k in ("id", "selected", "volume", "op", "pin") if k in json_obj}
    sanitized, err = sanitize_output_body(body)
    if err is not None:
        common.send_json(handler, 400, {"ok": False, "error": err})
        return
    pin_capable = json_obj.get("pin_capable") is True or sanitized.get("op") == "pin"
    requester = dial_requester(dial_id) if pin_capable else None
    try:
        parsed = common._config_snapshot(state)
        out_id = sanitized["id"]
        offset_ms_raw = parsed.owntone.output_offsets_ms.get(out_id)
        offset_ms = int(offset_ms_raw) if offset_ms_raw is not None else None
        from autostream_player_service import config_airplay_mode_to_backend
        mode = config_airplay_mode_to_backend(
            parsed.owntone.output_airplay_modes.get(out_id, DEFAULT_AIRPLAY_MODE))
        if sanitized.get("selected") and "volume" not in json_obj:
            sanitized["volume"] = max(0, min(100, int(parsed.owntone.volume_percent)))
    except Exception as e:
        logging.warning("dial outputs: config load failed: %s", e)
        common.send_json(handler, 200, {"ok": False, "error": "config_error"})
        return
    result = home_model.submit_output_change(
        sanitized, requester=dial_requester(dial_id), pin_requester=requester,
        offset_ms=offset_ms, mode=mode,
    )
    result["appliance_id"] = rpi.get_appliance_id()
    common.send_json(handler, 200, result)


def send_dial_eq_post_json(handler, state: WebUIState, json_obj: dict) -> None:
    """POST /api/dial/eq -- UUID-auth; the bass/treble the dial shows,
    read back from the stored output_eq bands (peq1/peq6, rounded and
    clamped to +/-6 dB -- see bass_treble_from_eq), plus every band."""
    if _dial_auth_gate(handler, json_obj) is None:
        return
    try:
        parsed = common._config_snapshot(state)
    except Exception as e:
        logging.warning("dial eq: config load failed: %s", e)
        common.send_json(handler, 200, {"ok": False, "error": "config_error"})
        return
    common.send_json(handler, 200, _dial_eq_reply(parsed))


def _dial_eq_reply(parsed) -> dict:
    """The EQ reply shared by the read and the set: the bass/treble pair
    the two-control Equaliser page shows, and every band with its stored
    gain and range."""
    bass, treble = bass_treble_from_eq(parsed.output_eq)
    return {
        "ok": True, "appliance_id": rpi.get_appliance_id(), "bass_db": bass, "treble_db": treble,
        "bands": dial_eq_bands(parsed.output_eq),
    }


def _legacy_eq_fields(mapper):
    """A body-key validator for the whole-dB bass/treble fields: an int that
    is not a bool, clamped to the dial's +/-6 dB range, then mapped onto the
    band fields. None when the value is not such an int."""
    def validate(raw):
        if isinstance(raw, bool) or not isinstance(raw, int):
            return None
        return mapper(max(-EQ_BASS_TREBLE_LIMIT_DB, min(EQ_BASS_TREBLE_LIMIT_DB, raw)))
    return validate


# Body key -> validator returning the output_eq fields to write, or None when
# the value is invalid. Applied in this order, so on a body that names the same
# band twice the "bands" value wins.
_EQ_SET_FIELDS = (
    ("bass_db", _legacy_eq_fields(eq_fields_for_bass)),
    ("treble_db", _legacy_eq_fields(eq_fields_for_treble)),
    ("bands", eq_fields_for_bands),
)


def send_dial_eq_set_post_json(handler, state: WebUIState, json_obj: dict) -> None:
    """POST /api/dial/eq/set -- UUID-auth; an absolute bass and/or treble
    value (the dial computes its own clamped absolute, same shape as the
    per-output volume steppers) and/or a "bands" object of absolute
    per-band gains, mapped onto the output_eq bands and applied in one write
    (see _EQ_SET_FIELDS and apply_eq_fields). Defensively clamped again here
    regardless of what the dial sent. peq3/peq4 are never touched by the
    bass/treble fields.
    """
    dial_id = _dial_auth_gate(handler, json_obj)
    if dial_id is None:
        return
    values: dict = {}
    for key, validate in _EQ_SET_FIELDS:
        if key not in json_obj:
            continue
        fields = validate(json_obj[key])
        if fields is None:
            common.send_json(handler, 400, {"ok": False, "error": "invalid_request_body"})
            return
        values.update(fields)
    if not values:
        common.send_json(handler, 400, {"ok": False, "error": "invalid_request_body"})
        return
    reply = submit(Intent(
        "output.eq.set", {"fields": tuple(values.items())}, Origin.USER, f"dial:{dial_id}",
        context=state))
    if not reply.ok:
        logging.warning("dial eq set: apply failed: %s", reply.result.get("error", reply.error))
        common.send_json(handler, 200, {"ok": False, "error": "eq_apply_failed", "appliance_id": rpi.get_appliance_id()})
        return
    parsed = common._config_snapshot(state)
    common.send_json(handler, 200, _dial_eq_reply(parsed))


def send_dial_mute_post_json(handler, state: WebUIState, json_obj: dict) -> None:
    """POST /api/dial/mute -- UUID-auth only (no session/CSRF required).

    Validates authorization and the requested action, then submits the
    mute.set intent: "mute" silences every selected output and remembers its
    level, "restore" brings each back to the level it was at (or the
    configured default when it has none). The dial's pushbutton is the only
    client that requests an explicit mute this way; the WebUI ends a mute as
    a side effect of an explicit user volume change. Both actions are
    idempotent: "mute" on an already-silent selection and "restore" on an
    already-audible one succeed as no-ops.
    """
    dial_id = json_obj.get("dial_id", "")
    if not isinstance(dial_id, str) or not dial_id:
        common.send_json(handler, 403, {})
        return
    if _dial_auth_gate(handler, json_obj) is None:
        return

    action = json_obj.get("action")
    if action not in ("mute", "restore"):
        common.send_json(handler, 400, {"ok": False, "error": "invalid_action"})
        return

    try:
        default_vol = common._config_snapshot(state).owntone.volume_percent
    except Exception as e:
        logging.warning("mute: config load failed: %s", e)
        common.send_json(handler, 200, {"ok": False, "error": "config_error"})
        return

    reply = submit(Intent(
        "mute.set", {"action": action, "default_level": default_vol},
        Origin.USER, dial_requester(dial_id),
    ))
    common.send_json(handler, 200, dict(reply.result) if reply.result else {"ok": False, "error": reply.error})


# -----------------------------------------------------------------------------
# Route-table adapters
# -----------------------------------------------------------------------------


def _route_dial_parse_json_obj(handler, *, reject_non_dict: bool):
    """Body read + JSON parse for the UUID-auth dial endpoints, reproducing
    do_POST's former universal body-read (steps 2-3) plus the dial-specific
    guard that used to run just ahead of the volume/mute/status branches.
    Returns a dict (parsed object, or {} if the body wasn't a JSON object
    and rejection wasn't requested), or None if an error response was
    already sent.
    """
    body_bytes = handler._read_post_body_bytes()
    if body_bytes is None:
        return None
    try:
        body_str = body_bytes.decode("utf-8")
    except UnicodeDecodeError:
        handler.send_error(400, "Request body is not valid UTF-8")
        return None
    content_type = (handler.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
    json_obj = None
    if body_str and content_type == "application/json":
        try:
            json_obj = json.loads(body_str)
        except json.JSONDecodeError:
            handler.send_error(400, "Invalid JSON")
            return None
        if reject_non_dict and not isinstance(json_obj, dict):
            handler.send_error(400, "JSON object required")
            return None
    return json_obj if isinstance(json_obj, dict) else {}


def _route_post_dial_volume(handler, state):
    json_obj = _route_dial_parse_json_obj(handler, reject_non_dict=True)
    if json_obj is None:
        return
    send_dial_volume_post_json(handler, state, json_obj)


def _route_post_dial_mute(handler, state):
    json_obj = _route_dial_parse_json_obj(handler, reject_non_dict=True)
    if json_obj is None:
        return
    send_dial_mute_post_json(handler, state, json_obj)


def _route_post_dial_status(handler, state):
    json_obj = _route_dial_parse_json_obj(handler, reject_non_dict=False)
    send_dial_status_post_json(handler, state, json_obj)


def _route_post_dial_repeat(handler, state):
    json_obj = _route_dial_parse_json_obj(handler, reject_non_dict=True)
    if json_obj is None:
        return
    send_dial_repeat_post_json(handler, state, json_obj)


def _route_post_dial_repeat_arm(handler, state):
    json_obj = _route_dial_parse_json_obj(handler, reject_non_dict=True)
    if json_obj is None:
        return
    send_dial_repeat_arm_post_json(handler, state, json_obj)


def _route_post_dial_outputs(handler, state):
    json_obj = _route_dial_parse_json_obj(handler, reject_non_dict=True)
    if json_obj is None:
        return
    send_dial_outputs_post_json(handler, state, json_obj)


def _route_post_dial_outputs_set(handler, state):
    json_obj = _route_dial_parse_json_obj(handler, reject_non_dict=True)
    if json_obj is None:
        return
    send_dial_outputs_set_post_json(handler, state, json_obj)


def _route_post_dial_eq(handler, state):
    json_obj = _route_dial_parse_json_obj(handler, reject_non_dict=True)
    if json_obj is None:
        return
    send_dial_eq_post_json(handler, state, json_obj)


def _route_post_dial_eq_set(handler, state):
    json_obj = _route_dial_parse_json_obj(handler, reject_non_dict=True)
    if json_obj is None:
        return
    send_dial_eq_set_post_json(handler, state, json_obj)


def _route_post_dial_warnings(handler, state):
    json_obj = _route_dial_parse_json_obj(handler, reject_non_dict=True)
    if json_obj is None:
        return
    send_dial_warnings_post_json(handler, state, json_obj)
