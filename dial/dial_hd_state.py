"""dial_hd_state.py: the HD dial's state body, built from a core snapshot.

One pure function, build_state(), turns a CoreSnapshot (plus the dial's own
panel and settings, the warning descriptors and the clock readings it is
handed) into the plain dict that the HD page's state route and event stream
send. No I/O, no locks and no clock reads: everything that varies is an
argument, so the same input is the same output, which is what the golden
tests and the offline mock rely on.

The body is versioned ("v") and only ever grows: a field is added, never
renamed or removed, so a page and a dial of different ages still agree.
It carries nothing the page does not draw. Artwork is a local key and URL
(never the appliance's own URL), appliances are shown by id and display
name, and appliance-supplied text arrives already cleaned by the core and is
capped again here so one pathological reply cannot bloat the stream.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import json
from typing import Any, Iterable, Mapping

from dial_auth import AUTH_AUTHORIZED, AUTH_UNAUTHORIZED
from dial_core_state import (
    DERIVED_EQ_IDS, PLAYING_TEXT, awaiting_pin, awaiting_title, outputs_tap, pin_capable_outputs,
    pin_window_end, six_band,
)
from dial_warning_text import appliance_warning_key

# The body's version. Bumped only for a change an older page could not read;
# an added field never bumps it.
STATE_VERSION = 1

# No string in the body is longer than this many characters.
STRING_MAX = 200

# Where the page fetches the held artwork from, by key.
ARTWORK_PATH = "/api/v1/artwork/"

# The blurred backdrop of the held artwork hangs off the artwork's own path;
# the logo has a fixed one for when nothing is held.
BACKDROP_SUFFIX = "/backdrop"
LOGO_BACKDROP_PATH = "/api/v1/logo/backdrop"

# The panel values shown before the panel service has said anything.
DEFAULT_BRIGHTNESS = 80
DEFAULT_SLEEP_AFTER_S = 300

# Severity of a card whose own severity is not one of the three names (the
# dial's own warnings carry a reading, not a severity).
_CARD_SEVERITIES = ("info", "warning", "critical")
_CARD_SEVERITY_BY_ID = {"update": "info", "update_result": "info"}
_CARD_SEVERITY_DEFAULT = "warning"

_REPLAYING_STATES = ("replaying", "fading_out")


def _text(value: Any) -> str:
    """*value* as a string no longer than STRING_MAX, "" for None."""
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    return value[:STRING_MAX]


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _bool_or_none(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _round(value: Any, places: int = 1) -> float:
    try:
        return round(float(value), places)
    except (TypeError, ValueError, OverflowError):
        return 0.0


def _descriptor_map(descriptors: "Mapping | Iterable | None") -> dict:
    if descriptors is None:
        return {}
    if isinstance(descriptors, Mapping):
        return dict(descriptors)
    return {d.id: d for d in descriptors}


def _call(fn, argument):
    """What a descriptor's text function says for *argument*, None when it
    has none or raises."""
    if fn is None:
        return None
    try:
        return fn(argument)
    except Exception:
        return None


# ---- the parts ---------------------------------------------------------------


def _dial_block(snapshot) -> dict:
    info = snapshot.dial
    return {
        "name": info.name,
        "version": info.version,
        "uuid": info.uuid,
        "address": info.ip,
        "inputs": list(info.inputs),
        "volume_scope": info.volume_scope,
        "mute_scope": info.mute_scope,
    }


def _repeat_block(record, now: float) -> dict | None:
    if record is None:
        return None
    position = record.position_seconds
    if record.state == "replaying":
        # Between two status readings the replay keeps moving.
        position += max(0.0, now - record.observed_at)
        if record.duration_seconds > 0:
            position = min(position, record.duration_seconds)
    # What the listener hears trails the reported position by the
    # appliance's audio start buffer; the page's timer follows this figure.
    heard = max(0.0, position - record.latency_seconds)
    return {
        "available": record.available,
        "state": record.state,
        "armed": record.armed,
        "recording_s": _round(record.recording_seconds),
        "position_s": _round(heard),
        "duration_s": _round(record.duration_seconds),
        "latency_s": _round(record.latency_seconds),
        # When the appliance last reported this record (the core's clock); the
        # page compares it with a request's changed_at to know a report is newer.
        "observed_at": _round(record.observed_at, 3),
    }


def _appliance_warnings(appliance, snoozed_until: dict, wall_now: float) -> list:
    out = []
    for warning in appliance.warnings:
        key = appliance_warning_key(appliance.appliance_id, warning.id)
        until = snoozed_until.get(key)
        out.append({
            "key": key,
            "id": warning.id,
            "severity": warning.severity,
            "title": warning.title,
            "message": warning.message,
            "dismissal": warning.dismissal,
            "snoozed": until is not None and until > wall_now,
        })
    return out


def _appliance_block(a, now: float, wall_now: float, snoozed_until: dict) -> dict:
    return {
        "id": a.appliance_id,
        "name": a.name,
        "auth": a.auth,
        "playing": bool(a.playing),
        "replaying": a.repeat is not None and a.repeat.state in _REPLAYING_STATES,
        # An appliance that answered with a refusal is reachable; its auth
        # says the rest.
        "reachable": a.status_error is None or a.status_error == "unauthorized",
        "volume": _int_or_none(a.master_volume),
        "muted": _bool_or_none(a.muted),
        "capabilities": {
            "outputs": a.dial_outputs_version,
            "eq": a.dial_eq_version,
            "repeat": bool(a.repeat_capable),
            "warnings": bool(a.supplies_warnings),
            "proto": a.dial_proto_version,
        },
        "repeat": _repeat_block(a.repeat, now),
        "warnings": _appliance_warnings(a, snoozed_until, wall_now),
        "webui": f"{a.webui_scheme}://{a.webui_host}:{a.webui_port}/" if a.webui_host else "",
    }


def _focus_block(snapshot) -> dict:
    focus = snapshot.focus
    return {
        "appliance_id": snapshot.focused_id(),
        "manual": focus.manual_id is not None,
        "pending": focus.pending is not None,
        "idle": bool(focus.idle_focus),
    }


def _now_playing_block(snapshot) -> dict | None:
    playing = snapshot.now_playing
    if playing is None:
        return None
    return {
        "appliance_id": snapshot.focus.reporting_id,
        "title": playing.title,
        "artist": playing.artist,
        "album": playing.album,
        "playing": bool(playing.playing),
        # What the page shows as the track while the appliance is playing but
        # has not named it yet; the same word the screen's view uses.
        "title_fallback": PLAYING_TEXT if awaiting_title(playing) else "",
    }


def _artwork_block(snapshot) -> dict | None:
    artwork = snapshot.artwork
    if artwork is None:
        return None
    url = ARTWORK_PATH + artwork.key
    return {"key": artwork.key, "url": url, "backdrop_url": url + BACKDROP_SUFFIX}


def _volume_block(snapshot, muted: bool | None) -> dict:
    return {
        "appliance_id": snapshot.focus.reporting_id,
        "level": _int_or_none(snapshot.volume_readout[1]),
        "muted": _bool_or_none(muted),
    }


def _outputs_block(snapshot) -> dict | None:
    held = snapshot.outputs
    if held is None:
        return None
    pending = outputs_tap(snapshot)
    rows = []
    for row in held.rows:
        selected, volume = row.selected, row.volume
        if pending is not None and pending[0] == row.id:
            selected = pending[1]
            if pending[2] is not None:
                volume = pending[2]
        rows.append({
            "id": row.id,
            "name": row.name,
            "selected": bool(selected),
            "volume": volume,
            "in_use": bool(row.remote_in_use),
            "owner": row.remote_owner or "",
            "default": bool(row.is_default),
        })
    return {"appliance_id": held.appliance_id, "loaded": bool(held.loaded), "rows": rows}


def _eq_block(snapshot, now: float) -> dict | None:
    held = snapshot.eq
    if held is None:
        return None
    pending = dict(held.optimistic) if held.optimistic_expires_at > now else {}
    version = held.capability_version
    bands = []
    for band in held.bands:
        if six_band(version) and band.id in DERIVED_EQ_IDS:
            continue
        bands.append({
            "id": band.id,
            "frequency_hz": band.frequency_hz,
            "gain_db": pending.get(band.id, band.gain_db),
            "min_db": band.min_db,
            "max_db": band.max_db,
        })
    return {
        "appliance_id": held.appliance_id,
        "version": version,
        "loaded": bool(held.loaded),
        "bands": bands,
    }


def _pin_accepted(snapshot, held) -> bool:
    appliance = None if held is None else snapshot.appliance(held.appliance_id)
    return appliance is not None and pin_capable_outputs(appliance.dial_outputs_version)


def _request_block(held, now: float, pin_accepted: bool) -> dict | None:
    if held is None:
        return None
    window_end = pin_window_end(held)
    return {
        "appliance_id": held.appliance_id,
        "kind": held.kind,
        "state": held.state,
        "error": held.error,
        "output_id": held.output_id,
        "retry_after_s": held.retry_after_s,
        # An opaque identity for the page to remember a dismissal by; never drawn.
        "requested_at": held.requested_at,
        # When the request reached its current state, on the same clock.
        "changed_at": _round(held.changed_at, 3),
        "awaiting_pin": awaiting_pin(held, now),
        # Whether the appliance takes a PIN from this dial.
        "pin_accepted": pin_accepted,
        # Absolute times on the body's "now" clock: when a rate-limit wait
        # ends, and when an outcome stops being answered on the screen (null
        # for a request that takes no PIN).
        "retry_until": _round(held.changed_at + held.retry_after_s, 3),
        "awaiting_until": None if window_end is None else _round(window_end, 3),
    }


def _card_severity(state) -> str:
    if isinstance(state.severity, str) and state.severity in _CARD_SEVERITIES:
        return state.severity
    return _CARD_SEVERITY_BY_ID.get(state.id, _CARD_SEVERITY_DEFAULT)


def _card_progress(value) -> int | None:
    value = _int_or_none(value)
    return None if value is None else max(0, min(100, value))


def _warnings_block(snapshot, descriptors: dict, wall_now: float) -> dict:
    cards = []
    for state in snapshot.warnings:
        if not state.active:
            continue
        descriptor = descriptors.get(state.id)
        if descriptor is None:
            continue
        title = _call(descriptor.title_for, state.severity) or descriptor.title
        message = _call(descriptor.message_for, state.severity)
        cards.append({
            "id": state.id,
            "severity": _card_severity(state),
            "title": title,
            "message": message if isinstance(message, str) else "",
            "progress": _card_progress(_call(descriptor.progress_for, state.severity)),
            "source": descriptor.source_name,
            "buttons": [{"label": b.label, "action": b.action} for b in descriptor.buttons],
            "interrupting": bool(descriptor.interrupting),
            "snoozed": state.snoozed_until is not None and state.snoozed_until > wall_now,
        })
    return {"due": snapshot.due_warning_id, "cards": cards}


def _network_block(view) -> dict | None:
    if view is None:
        return None
    return {"link": view.link, "ssid": view.ssid, "signal": view.signal, "bars": view.bars}


def _sd_health_block(view) -> dict | None:
    if view is None:
        return None
    return {"status": view.status, "percent": view.percent}


def _update_block(view) -> dict | None:
    if view is None or not view.status:
        return None
    return {
        "status": view.status,
        "phase": view.phase,
        "percent": view.percent,
        "tag": view.tag,
        "previous_tag": view.previous_tag,
        "rolled_back": bool(view.rolled_back),
    }


def _panel_block(panel: "Mapping | None", settings: "Mapping | None") -> dict:
    panel = panel or {}
    settings = settings or {}

    def pick(key, default):
        if key in panel:
            return panel[key]
        return settings.get(key, default)

    return {
        "asleep": bool(panel.get("asleep", False)),
        "brightness": pick("brightness", DEFAULT_BRIGHTNESS),
        "sleep_after_s": pick("sleep_after_s", DEFAULT_SLEEP_AFTER_S),
        "backlight": _text(panel.get("backlight", "none")),
        # Not read by the page (it always shows its controls); a constant, kept
        # so an older page loaded against this dial still finds the key.
        "always_show_controls": False,
        "kiosk": bool(panel.get("kiosk", False)),
    }


def _recovery_block(recovery) -> dict:
    if isinstance(recovery, Mapping):
        active = recovery.get("active", False)
        confirmed = recovery.get("confirmed", False)
    elif recovery:
        active, confirmed = recovery[0], recovery[1]
    else:
        active = confirmed = False
    return {"active": bool(active), "confirmed": bool(confirmed)}


def _power_block(snapshot) -> dict:
    held = snapshot.power
    return {"state": held.state, "changed_at": _round(held.changed_at, 3)}


def _capped(value):
    """*value* with every string cut to STRING_MAX characters."""
    if isinstance(value, str):
        return value[:STRING_MAX]
    if isinstance(value, dict):
        return {k: _capped(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_capped(v) for v in value]
    return value


# ---- the body ----------------------------------------------------------------


def build_state(
    snapshot, *, descriptors: "Mapping | Iterable | None" = None, panel: "Mapping | None" = None,
    settings: "Mapping | None" = None, recovery=None, hub_seq: int = 0, now: float = 0.0,
    wall_now: float = 0.0, muted: bool | None = None,
) -> dict:
    """The state body for *snapshot*.

    *descriptors* are the warning descriptors by id (or an iterable of
    them), the dial's own and any registered for appliances. *panel* is the
    panel's view (asleep, brightness, sleep_after_s, backlight) and
    *settings* the dial's screen settings, which fill in what the panel does
    not say. *recovery* is (active, confirmed) or a mapping with those keys.
    *hub_seq* is the sequence the change hub has reached. *now* is the
    monotonic time (the repeat position and the EQ tap window are read
    against it) and *wall_now* the wall clock (a snooze runs to a wall-clock
    time). *muted* is the shown mute flag of the reporting appliance, read
    by the caller because it is not part of the snapshot."""
    descriptors = _descriptor_map(descriptors)
    snoozed_until = {s.id: s.snoozed_until for s in snapshot.warnings}
    appliances = [
        _appliance_block(a, now, wall_now, snoozed_until)
        for a in snapshot.appliances
        if a.appliance_id and a.auth in (AUTH_AUTHORIZED, AUTH_UNAUTHORIZED)
    ]
    body = {
        "v": STATE_VERSION,
        "seq": hub_seq,
        # The core's clock when the body was built; the request deadlines and
        # the replay's observed_at are readings on it.
        "now": _round(now, 3),
        "core_seq": snapshot.seq,
        "started": snapshot.ticks > 0,
        "polling": bool(snapshot.polling),
        "dial": _dial_block(snapshot),
        "focus": _focus_block(snapshot),
        "appliances": appliances,
        "now_playing": _now_playing_block(snapshot),
        "artwork": _artwork_block(snapshot),
        "volume": _volume_block(snapshot, muted),
        "outputs": _outputs_block(snapshot),
        "outputs_available": bool(snapshot.outputs_available),
        "eq": _eq_block(snapshot, now),
        "eq_available": bool(snapshot.eq_available),
        "transport": _request_block(snapshot.transport, now, _pin_accepted(snapshot, snapshot.transport)),
        "outputs_request": _request_block(snapshot.outputs_request, now, _pin_accepted(snapshot, snapshot.outputs_request)),
        "warnings": _warnings_block(snapshot, descriptors, wall_now),
        "network": _network_block(snapshot.network),
        "sd_health": _sd_health_block(snapshot.sd_health),
        "update": _update_block(snapshot.update),
        "panel": _panel_block(panel, settings),
        "recovery": _recovery_block(recovery),
        "power": _power_block(snapshot),
    }
    return _capped(body)


def dumps(state: dict) -> str:
    """The wire form of a state body."""
    return json.dumps(state, separators=(",", ":"), ensure_ascii=False)
