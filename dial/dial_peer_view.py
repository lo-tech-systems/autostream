"""dial_peer_view.py -- what the dial shows, worked out from a peer's state.

Pure functions of one PeerSnapshot (or of its parts) and what the caller
passes in: no I/O, no clock reads, no storage. They map the parts an
appliance publishes onto the dial's own snapshot types, so the screens read
the same types whatever the source of the state.

The first group (playing, active_input, speaker_rows, master_volume) mirrors
the browser's shared derivations in nginx/static/shared/state_view.js, and a
test runs both against one table of cases. The second group maps parts onto
the dial's types: ApplianceState, OutputsState, EqState, NowPlaying,
RepeatRecord, the start failure report and the appliance's warnings.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import math
import os
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass

# autostream_eq_bands is deployed flat beside the dial package; in the repo it
# lives in core/.
try:
    import autostream_eq_bands as eq_bands
except ImportError:
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "core")))
    import autostream_eq_bands as eq_bands  # noqa: E402

from dial_core_state import (
    AUTH_AUTHORIZED, AUTH_UNAUTHORIZED, AUTH_UNKNOWN, APPLIANCE_WARNINGS_MAX,
    ApplianceState, ApplianceWarning, EqBand, EqState, NowPlaying, OutputRow, OutputsState,
    StartFailureReport, appliance_warning_entries, attribute_appliance_warnings,
    parse_start_failure, webui_address,
)
from dial_mdns import appliance_display_name
from dial_repeat_store import RepeatRecord, parse_repeat_object
from dial_values import clamp, clamp_percent, is_whole_number

# The EQ range the dial's bass and treble controls move within.
EQ_BASS_TREBLE_LIMIT_DB = 6

# The label of each input type, as the appliance's own pages name it.
_INPUT_TYPE_LABELS = {"turntable": "Turntable", "cd": "CD", "line": "Line"}

# The access refusals that mean this dial is not allowed to control the
# appliance, as opposed to one it has not learned yet.
_NOT_ALLOWED_REASONS = ("dial_not_authorized", "unconfigured")

_INPUT_SOURCE_RE = re.compile(r"input([0-9]+)")


# ---- small readers ------------------------------------------------------------


def _map(value) -> Mapping:
    return value if isinstance(value, Mapping) else {}


def _part(parts, name: str) -> Mapping:
    return _map(_map(parts).get(name))


def _block(parts) -> Mapping:
    return _map(_part(parts, "repeat").get("block"))


def _whole(value) -> int | None:
    """*value* as a whole number, halves rounding up (Math.round), or None
    when it is not a finite number."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    return math.floor(value + 0.5)


# ---- derivations shared with the browser --------------------------------------


def playing(parts) -> bool:
    """A session is active."""
    return bool(_part(parts, "session").get("active"))


def _source_input(parts) -> int | None:
    """The input number the session's own source names (a replay resolves to
    the input it was recorded from), or None."""
    source = _part(parts, "session").get("source") or ""
    if source == "replay":
        block = _block(parts)
        origin = _map(block.get("recording")).get("origin_input")
        if _map(block.get("replay")).get("active") and is_whole_number(origin):
            return int(origin)
        return None
    found = _INPUT_SOURCE_RE.fullmatch(source) if isinstance(source, str) else None
    return int(found.group(1)) if found else None


def active_input(parts) -> int | None:
    """The input number behind the session: the session's own source, else
    the first input above its threshold, else the first input; None with no
    inputs."""
    n = _source_input(parts)
    if n is not None:
        return n
    entries = [e for e in _part(parts, "inputs").get("entries") or () if isinstance(e, Mapping)]
    hot = next((e for e in entries if _map(e.get("level")).get("is_above_threshold")), None)
    first = entries[0] if entries else None
    found = hot if hot is not None else first
    return found.get("index") if found is not None else None


def active_track(parts) -> Mapping | None:
    """The identification entry of the active input, or None."""
    n = active_input(parts)
    if n is None:
        return None
    entry = _map(_part(parts, "track").get("entries")).get(str(n))
    return entry if isinstance(entry, Mapping) else None


def master_volume(parts) -> int | None:
    value = _part(parts, "outputs").get("master_volume")
    return None if value is None else value


@dataclass(frozen=True)
class SpeakerRow:
    id: str
    name: str
    on: bool
    volume: int
    chip: str                 # "in-use" | "on" | "off"
    auto_start: bool
    in_use_by: str
    in_use_id: str
    connecting: bool
    offline: bool
    disabled: bool
    pin_pending: bool
    pin_claim: str
    needs_auth_key: bool = False


def speaker_rows(parts) -> list[SpeakerRow]:
    """The speaker cards in order: Auto-Start first, then by name. A hidden
    speaker stays while it is on or in the Auto-Start set; an offline one
    is left out."""
    in_session = playing(parts)
    rows: list[SpeakerRow] = []
    for u in _part(parts, "outputs").get("units") or ():
        if not isinstance(u, Mapping):
            continue
        on = bool(u.get("selected")) and u.get("availability") != "password"
        auto_start = bool(u.get("auto_start"))
        offline = bool(u.get("offline"))
        if (not u.get("id") or not u.get("name")
                or offline
                or (u.get("hidden") and not on and not auto_start)):
            continue
        by = u.get("in_use_by") or ""
        reported = _map(u.get("reported"))
        level = _whole(u.get("volume")) or 0
        connecting = not by and bool(u.get("connecting"))
        rows.append(SpeakerRow(
            id=u["id"], name=u["name"], on=on, volume=clamp_percent(level),
            chip="in-use" if by else "on" if on else "off",
            auto_start=auto_start, in_use_by=by,
            in_use_id=(u.get("in_use_id") or "") if by else "",
            connecting=connecting,
            offline=not by and not connecting and offline,
            disabled=bool(by) or (offline and not in_session),
            pin_pending=bool(reported.get("pin_pending")),
            pin_claim=u.get("pin_claim") or "",
            needs_auth_key=reported.get("needs_auth_key") is True,
        ))
    rows.sort(key=lambda r: (not r.auto_start, r.name.lower()))
    return rows


# ---- the dial's own types -----------------------------------------------------


def outputs_state(appliance_id: str, parts, *, fetched_at: float = 0.0) -> OutputsState:
    """One row per speaker the page would show. *loaded* is whether the
    appliance has published its outputs."""
    rows = tuple(
        OutputRow(
            id=r.id, name=r.name, selected=r.on, volume=r.volume,
            remote_in_use=bool(r.in_use_by), remote_owner=r.in_use_by or None,
            is_default=r.auto_start, needs_auth_key=r.needs_auth_key,
        )
        for r in speaker_rows(parts)
    )
    return OutputsState(appliance_id, rows, isinstance(_map(parts).get("outputs"), Mapping), fetched_at)


def _bass_treble(bands: list) -> tuple[int, int]:
    """(bass, treble): the 40 Hz and 10 kHz bands rounded to whole dB and
    held to the dial's own range."""
    def clamp(v):
        return max(-EQ_BASS_TREBLE_LIMIT_DB, min(EQ_BASS_TREBLE_LIMIT_DB, int(round(v))))
    return clamp(bands[0]), clamp(bands[-1])


def eq_state(appliance_id: str, parts) -> EqState:
    """The six output bands, then the bass and treble controls the two-control
    page uses. Empty, and not loaded, before the appliance has published its
    bands."""
    raw = _part(parts, "eq").get("output_bands") or ()
    table = eq_bands.OUTPUT_PEQ_BANDS
    gains = [g for g in raw if isinstance(g, (int, float)) and not isinstance(g, bool) and math.isfinite(g)]
    if len(gains) != len(table):
        return EqState(appliance_id, 2, (), False, (), 0.0)
    low, high = int(eq_bands.OUTPUT_EQ_DB_MIN), int(eq_bands.OUTPUT_EQ_DB_MAX)
    bands = [
        EqBand(b["key"][:-3], int(b["freq_hz"]), clamp(_whole(g), low, high), low, high)
        for b, g in zip(table, gains)
    ]
    bass, treble = _bass_treble(gains)
    bands.append(EqBand("bass", None, bass, -EQ_BASS_TREBLE_LIMIT_DB, EQ_BASS_TREBLE_LIMIT_DB))
    bands.append(EqBand("treble", None, treble, -EQ_BASS_TREBLE_LIMIT_DB, EQ_BASS_TREBLE_LIMIT_DB))
    return EqState(appliance_id, 2, tuple(bands), True, (), 0.0)


def now_playing(parts, service_name: str = "") -> NowPlaying:
    """The track on the active input. Title, artist and album are those of an
    identified track only, and the artwork is an identified track's http(s)
    URL; the input label is the session source's input type."""
    track = active_track(parts)
    identified = track is not None and track.get("state") == "identified"
    text = lambda key: track.get(key) if identified and isinstance(track.get(key), str) else ""
    url = text("artwork_url")
    n = _source_input(parts)
    entry = next((e for e in _part(parts, "inputs").get("entries") or ()
                  if isinstance(e, Mapping) and e.get("index") == n), None) if n is not None else None
    label = _INPUT_TYPE_LABELS.get(entry.get("input_type") if entry else None, "Line") if n is not None else ""
    return NowPlaying(
        service_name=service_name, artist=text("artist"), title=text("title"),
        master_volume=master_volume(parts), album=text("album"), playing=playing(parts),
        artwork_url=url if url.startswith(("http://", "https://")) else "", input_label=label,
    )


def start_failure(raw, boot: str, own_requester: str, *, age_s: int = 0) -> StartFailureReport | None:
    """The part's start failure as the report the dial acts on, or None when
    there is none or it is not well formed. *mine* is whether the requester
    is this dial. The part carries the failure's wall-clock time, not an age,
    so the caller supplies *age_s* (0 reads as just now)."""
    if not isinstance(raw, Mapping):
        return None
    return parse_start_failure({
        "seq": raw.get("seq"), "boot": boot, "unit_id": raw.get("unit_id"),
        "name": raw.get("name"), "reason": raw.get("reason"),
        "mine": raw.get("requester") == own_requester, "age_s": age_s,
    })


def repeat_record(block, now: float) -> RepeatRecord | None:
    """The daemon's repeat block as the dial's record, by the rules the
    appliance applied before the dial read the block itself. None when there
    is no block. The part carries no start-buffer figure, so the record keeps
    the dial's default latency."""
    if not isinstance(block, Mapping):
        return None
    rec, rep = _map(block.get("recording")), _map(block.get("replay"))
    enabled = bool(block.get("enabled"))
    if not enabled:
        state = "idle"
    elif rep.get("active") and rep.get("fading_out"):
        state = "fading_out"
    elif rep.get("active"):
        state = "replaying"
    elif rec.get("active"):
        state = "recording"
    elif (rec.get("seconds") or 0) > 0:
        state = "hold"
    else:
        state = "idle"
    return parse_repeat_object({
        "available": enabled, "state": state, "armed": bool(block.get("armed")),
        "recording_seconds": float(rec.get("seconds") or 0.0),
        "replay": {
            "active": bool(rep.get("active")),
            "position_seconds": float(rep.get("position_seconds") or 0.0),
            "duration_seconds": float(rep.get("duration_seconds") or 0.0),
        },
    }, now)


def appliance_warnings(entries, name: str, *, limit: int = APPLIANCE_WARNINGS_MAX) -> tuple[ApplianceWarning, ...]:
    """The part's warnings as the dial keeps them, after the field rules for
    data from another device; every warning carries *name* as its source."""
    return attribute_appliance_warnings(appliance_warning_entries(list(entries or ()), limit), name)


def _auth(snap) -> str:
    if snap.access == "playback":
        return AUTH_AUTHORIZED
    if snap.access == "none" and snap.access_reason in _NOT_ALLOWED_REASONS:
        return AUTH_UNAUTHORIZED
    return AUTH_UNKNOWN


def _status_error(snap) -> str | None:
    if not snap.protocol_ok:
        return "protocol"
    if not snap.reachable:
        return "unreachable"
    if snap.access == "none":
        return "unauthorized"
    if not _part(snap.parts, "outputs").get("connected"):
        return "unavailable"
    return None


def appliance_state(sighting, snap, *, now: float, playing_since: float = 0.0) -> ApplianceState:
    """One appliance as the dial's lists and screens read it. *snap* is the
    appliance's PeerSnapshot, or None before the first one. *now* is the
    clock the repeat record is stamped with; *playing_since* is the core's
    own first sighting of the session (0.0 when idle)."""
    parts = snap.parts if snap is not None else {}
    ok = snap.protocol_ok if snap is not None else True
    outputs = _part(parts, "outputs")
    block = _part(parts, "repeat").get("block")
    scheme, host, port = webui_address(sighting.ip, sighting.port)
    is_playing = playing(parts)
    name = appliance_display_name(sighting.service_name)
    reachable = snap is not None and snap.reachable
    return ApplianceState(
        appliance_id=sighting.id,
        service_name=sighting.service_name,
        name=name,
        ip=sighting.ip,
        port=sighting.port,
        playing=is_playing,
        playing_since=playing_since if is_playing else 0.0,
        auth=_auth(snap) if snap is not None else AUTH_UNKNOWN,
        dial_status=ok,
        dial_outputs=ok,
        dial_eq=ok,
        repeat_capable=ok,
        dial_proto_version=(snap.protocol if snap is not None and snap.protocol is not None
                            else (sighting.proto or 0)),
        dial_eq_version=2 if ok else 0,
        dial_outputs_version=2 if ok else 0,
        status_error=_status_error(snap) if snap is not None else "unreachable",
        master_volume=master_volume(parts),
        muted=bool(outputs.get("muted_all")) if outputs else None,
        repeat=repeat_record(block, now) if reachable else None,
        webui_scheme=scheme,
        webui_host=host,
        webui_port=port,
        supplies_warnings="warnings" in _map(parts),
        warnings=appliance_warnings(_part(parts, "warnings").get("entries"), name),
    )
