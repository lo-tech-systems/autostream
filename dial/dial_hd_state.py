"""dial_hd_state.py: the HD dial's state, built from a core snapshot.

build_parts() turns a CoreSnapshot (plus the dial's own panel and settings,
the warning descriptors and the clock readings it is handed) into the two
parts the HD page's state route and event stream send: `dial`, what the dial
itself knows, and `focused`, the focused appliance's own parts. No I/O, no
locks and no clock reads: everything that varies is an argument, so the same
input is the same output, which is what the golden tests and the offline
preview rely on.

The `dial` part carries nothing the page does not draw. Artwork is a local key and URL
(never the appliance's own URL), appliances are shown by id and display
name, and appliance-supplied text arrives already cleaned by the core and is
capped again here so one pathological reply cannot bloat the stream.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping

from dial_core_state import AUTH_AUTHORIZED, AUTH_UNAUTHORIZED, awaiting_pin, pin_window_end
from dial_values import clamp_percent, int_or_none
from dial_warning_bell import appliance_bell, descriptor_map, dial_bell
from dial_warnings import ACTION_CLOSE

# What the page posts to end a status card (a warning card is put away in the
# page and posts nothing).
STATUS_CLOSE_ACTION = "status_close"

# The version of the `dial` part, bumped for a change in its shape. The page does
# not check it: it is there for whoever reads the stream.
DIAL_PART_VERSION = 3

# The appliance's own parts the `focused` part passes through; the page reads
# nothing else of the appliance's state.
FOCUSED_PART_NAMES = ("session", "repeat", "track", "inputs", "outputs", "eq")

# No string in the body is longer than this many characters.
STRING_MAX = 200

# Where the page fetches the held artwork from, by key.
ARTWORK_PATH = "/api/v1/artwork/"

# The blurred backdrop of the held artwork hangs off the artwork's own path.
BACKDROP_SUFFIX = "/backdrop"

# The panel values shown before the panel service has said anything.
DEFAULT_BRIGHTNESS = 80
DEFAULT_SLEEP_AFTER_S = 300

_REPLAYING_STATES = ("replaying", "fading_out")


def _text(value: Any) -> str:
    """*value* as a string no longer than STRING_MAX, "" for None."""
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    return value[:STRING_MAX]


def _round(value: Any, places: int = 1) -> float:
    try:
        return round(float(value), places)
    except (TypeError, ValueError, OverflowError):
        return 0.0


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


def _repeat_block(record) -> dict | None:
    if record is None:
        return None
    position = record.position_seconds
    # What the listener hears trails the reported position by the
    # appliance's audio start buffer; the page's timer follows this figure.
    # The position is the reported one, as of observed_at, and a replay's can
    # be below zero, so whoever carries it on to a later time stops it at zero
    # only then.
    heard = position - record.latency_seconds
    if record.state != "replaying":
        heard = max(0.0, heard)
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


def _entry_block(entry) -> dict:
    return {
        "key": entry.key, "source": entry.source, "severity": entry.severity,
        "title": entry.title, "message": entry.message, "actions": list(entry.actions),
    }


def _bell_block(bell) -> dict:
    """A bell as the page lists it: its worst severity (None when empty) and
    its entries in order."""
    return {"severity": bell.severity, "entries": [_entry_block(e) for e in bell.entries]}


def _appliance_block(a) -> dict:
    return {
        "id": a.appliance_id,
        "name": a.name,
        "auth": a.auth,
        "playing": bool(a.playing),
        "replaying": a.repeat is not None and a.repeat.state in _REPLAYING_STATES,
        # An appliance that answered with a refusal, or that runs another
        # protocol than this dial's, is reachable; its auth and update_needed
        # say the rest.
        "reachable": a.status_error is None or a.status_error in ("unauthorized", "protocol"),
        "repeat": _repeat_block(a.repeat),
        "warnings": [_entry_block(e) for e in appliance_bell(a).entries],
        "webui": f"{a.webui_scheme}://{a.webui_host}:{a.webui_port}/" if a.webui_host else "",
        "update_needed": a.status_error == "protocol",
    }


def _focus_block(snapshot) -> dict:
    focus = snapshot.focus
    return {
        "appliance_id": snapshot.focused_id(),
        "manual": focus.manual_id is not None,
        "pending": focus.pending is not None,
        "idle": bool(focus.idle_focus),
    }


def _artwork_block(snapshot) -> dict | None:
    artwork = snapshot.artwork
    if artwork is None:
        return None
    url = ARTWORK_PATH + artwork.key
    return {"key": artwork.key, "url": url, "backdrop_url": url + BACKDROP_SUFFIX}


def _request_block(held, now: float) -> dict | None:
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
        # Absolute times on the body's "now" clock: when a rate-limit wait
        # ends, and when an outcome stops being answered on the screen (null
        # for a request that takes no PIN).
        "retry_until": _round(held.changed_at + held.retry_after_s, 3),
        "awaiting_until": None if window_end is None else _round(window_end, 3),
    }


def _card_progress(value) -> int | None:
    value = int_or_none(value)
    return None if value is None else clamp_percent(value)


def _status_block(snapshot, descriptors: dict) -> dict | None:
    """The status the page shows by itself (an update running or finished),
    or None. It closes by asking the core; a warning is put away in the page
    and has no card here."""
    state = next((s for s in snapshot.warnings if s.active and s.id == snapshot.due_status_id), None)
    descriptor = descriptors.get(state.id) if state is not None else None
    if descriptor is None:
        return None
    message = _call(descriptor.message_for, state.reading)
    return {
        "id": state.id,
        "severity": descriptor.severity_for(state.reading),
        "title": _call(descriptor.title_for, state.reading) or descriptor.title,
        "message": message if isinstance(message, str) else "",
        "progress": _card_progress(_call(descriptor.progress_for, state.reading)),
        "buttons": [
            {"label": b.label, "action": STATUS_CLOSE_ACTION if b.action == ACTION_CLOSE else b.action}
            for b in descriptor.buttons
        ],
    }


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


def _start_failure_block(snapshot) -> dict | None:
    """The raised "could not start" notice, or None."""
    held = snapshot.start_failure
    if held is None:
        return None
    return {"appliance_id": held.appliance_id, "key": held.key, "unit_id": held.unit_id,
            "name": held.name, "reason": held.reason, "raised_at": _round(held.raised_at, 3)}


# ---- the two parts ------------------------------------------------------------


def _dial_part(
    snapshot, *, descriptors: "Mapping | Iterable | None" = None, panel: "Mapping | None" = None,
    settings: "Mapping | None" = None, recovery=None, now: float = 0.0,
) -> dict:
    """The part about the dial itself, with none of the appliance's own parts
    and no reading that moves with the clock, so it changes only when
    something in it does. A replaying record's position is the reported one,
    as of its observed_at.

    *descriptors* are the warning descriptors by id (or an iterable of them),
    the dial's own and any registered for appliances. *panel* is the panel's
    view (asleep, brightness, sleep_after_s, backlight) and *settings* the
    dial's screen settings, which fill in what the panel does not say.
    *recovery* is (active, confirmed) or a mapping with those keys. *now* is
    the monotonic time (the request deadlines are readings on it)."""
    descriptors = descriptor_map(descriptors)
    appliances = [
        _appliance_block(a)
        for a in snapshot.appliances
        if a.appliance_id and a.auth in (AUTH_AUTHORIZED, AUTH_UNAUTHORIZED)
    ]
    focus = _focus_block(snapshot)
    focus["reporting_id"] = snapshot.focus.reporting_id
    body = {
        "v": DIAL_PART_VERSION,
        "started": snapshot.ticks > 0,
        "polling": bool(snapshot.polling),
        "dial": _dial_block(snapshot),
        "focus": focus,
        "appliances": appliances,
        "artwork": _artwork_block(snapshot),
        "transport": _request_block(snapshot.transport, now),
        "outputs_request": _request_block(snapshot.outputs_request, now),
        "start_failure": _start_failure_block(snapshot),
        "bell": _bell_block(dial_bell(snapshot, descriptors)),
        "status": _status_block(snapshot, descriptors),
        "network": _network_block(snapshot.network),
        "sd_health": _sd_health_block(snapshot.sd_health),
        "update": _update_block(snapshot.update),
        "panel": _panel_block(panel, settings),
        "recovery": _recovery_block(recovery),
        "power": _power_block(snapshot),
    }
    return _capped(body)


def _focused_part(peer) -> dict | None:
    """The focused appliance's snapshot as the core folded it, limited to the
    parts the page reads and passed through as the appliance sent them."""
    if peer is None:
        return None
    return {
        "id": peer.peer_id,
        "boot": peer.boot,
        "version": peer.version,
        "reachable": bool(peer.reachable),
        "access": peer.access,
        "parts": {name: peer.parts[name] for name in FOCUSED_PART_NAMES if name in peer.parts},
    }


def build_parts(
    snapshot, *, descriptors: "Mapping | Iterable | None" = None, panel: "Mapping | None" = None,
    settings: "Mapping | None" = None, recovery=None, now: float = 0.0,
) -> dict:
    """The two parts of the page's state, {"dial": ..., "focused": ... | None}.
    Both come from the one *snapshot*: the focused part is the appliance
    snapshot the core folded into it, never a live read, so the roster and the
    focus always agree. Arguments as for _dial_part."""
    return {
        "dial": _dial_part(
            snapshot, descriptors=descriptors, panel=panel, settings=settings, recovery=recovery,
            now=now,
        ),
        "focused": _focused_part(snapshot.focused_peer),
    }
