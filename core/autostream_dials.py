"""autostream_dials.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Dial authorization storage and background avahi-browse scanner for
_autostream-dial._tcp services. Maintains an in-memory registry of
currently-visible dial devices keyed by the avahi 5-tuple
(interface, protocol, name, type, domain) and by UUID.

The mDNS transport is provided by the shared autostream_mdns.MdnsBrowser.
Dial-specific behavior (authorization, persistence, transition logging, and
capability filtering) remains in this module.
"""
from __future__ import annotations

import json as _json
import logging
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from autostream_mdns import MdnsBrowser

# ---------------------------------------------------------------------------
# Dial authorization storage
# ---------------------------------------------------------------------------

DIALS_PATH = Path("/var/lib/autostream/dials.json")
_DIALS_LOCK = threading.Lock()
_SIGHTING_THROTTLE_SECS = 60

# Protocol dialect the appliance advertises as dial_proto in its TXT records.
# Kept in step with the value autostream_admin writes. A sighted dial whose
# own dial_proto generation is below this is flagged for updating.
DIAL_PROTO_VERSION = "v3"

# Capabilities this appliance supports, name -> version, served by
# GET /api/dial/capabilities. Only capabilities whose endpoints exist are
# listed. The TXT records keep their original v1 values for older dials; this
# table is where a newer version of a capability is announced. Every
# capability key in the TXT records appears here.
DIAL_CAPABILITIES: dict[str, int] = {
    "dial_status": 1,
    "dial_outputs": 1,
    "dial_eq": 2,
    "repeat": 1,
    "audio_status": 1,
}

# Oldest protocol generation that gets the typed refusal and the other
# current-dialect behaviour. Later generations include everything earlier ones
# mean, so every check is "at least this generation".
_MIN_DIAL_GENERATION = 2


def dial_proto_generation(value) -> int:
    """Parse a dial_proto value of the form v<N> into its generation number.

    Anything absent or malformed (no leading v, no digits, signs, spaces,
    non-ASCII digits) is generation 0, the earliest dialect.
    """
    if not isinstance(value, str):
        return 0
    m = re.fullmatch(r"v([0-9]{1,6})", value)
    return int(m.group(1)) if m else 0

# Printable ASCII only (0x20–0x7e); reject ; | which break TXT parsing.
# Intentional policy duplication of the identical function in autostream_admin
# (an extensionless privileged executable that cannot be imported).
_SAFE_DIAL_NAME = re.compile(r'^[\x20-\x7e]*$')
_BAD_DIAL_CHARS = re.compile(r'[;|]')


def validate_dial_name(name: str) -> bool:
    """Return True if name is printable ASCII without ; or |."""
    return bool(_SAFE_DIAL_NAME.match(name)) and not bool(_BAD_DIAL_CHARS.search(name))


@dataclass
class DialEntry:
    uuid: str
    name: str           # name at authorization time (stable fallback)
    authorized_at: str
    current_name: str = field(default='')   # updated on mDNS sighting
    last_seen: str = field(default='')      # ISO timestamp; blank until first sighting


def _load_dials_locked() -> dict:
    """Read DIALS_PATH; return {} on missing or malformed JSON (fail-closed)."""
    try:
        data = _json.loads(DIALS_PATH.read_text())
        if not isinstance(data, dict):
            logging.warning("dials.json: expected object, got %s — treating as empty",
                            type(data).__name__)
            return {}
        return data
    except FileNotFoundError:
        logging.warning("dials.json missing — treating as empty")
        return {}
    except (_json.JSONDecodeError, OSError) as e:
        logging.warning("dials.json unreadable (%s) — treating as empty", e)
        return {}


class DialsStoreUnavailable(Exception):
    """dials.json exists but cannot be read or parsed."""


_last_store_warning: str | None = None


def _load_dials_locked_strict() -> dict:
    """Like _load_dials_locked but distinguishes 'nobody authorized' from
    'store unreadable'.

    Missing file -> {} (an appliance that has never authorized a dial is not
    "unavailable", it is simply empty). Malformed JSON, a non-object root, or
    an OSError reading the file -> DialsStoreUnavailable, so callers can tell
    a corrupt/unreadable store apart from a definitive "not authorized".
    """
    try:
        raw = DIALS_PATH.read_text()
    except FileNotFoundError:
        return {}
    except OSError as e:
        _warn_store_unavailable_once(f"dials.json unreadable: {e}")
        raise DialsStoreUnavailable(str(e)) from e
    try:
        data = _json.loads(raw)
    except _json.JSONDecodeError as e:
        _warn_store_unavailable_once(f"dials.json malformed: {e}")
        raise DialsStoreUnavailable(str(e)) from e
    if not isinstance(data, dict):
        _warn_store_unavailable_once(
            f"dials.json: expected object, got {type(data).__name__}"
        )
        raise DialsStoreUnavailable("dials.json root is not an object")
    return data


def _warn_store_unavailable_once(message: str) -> None:
    """Log at WARNING once per distinct message, so a persistently corrupt
    file does not warn on every poll from every dial."""
    global _last_store_warning
    if message != _last_store_warning:
        logging.warning(message)
        _last_store_warning = message


AUTH_AUTHORIZED = "authorized"
AUTH_NOT_AUTHORIZED = "not_authorized"
AUTH_UNAVAILABLE = "unavailable"


def dial_authorization(uuid: str) -> str:
    """Three-valued lookup for the dial protocol routes: AUTH_AUTHORIZED,
    AUTH_NOT_AUTHORIZED (definitive miss), or AUTH_UNAVAILABLE (the dials
    store is unreadable, so no definitive answer is possible)."""
    with _DIALS_LOCK:
        try:
            dials = _load_dials_locked_strict()
        except DialsStoreUnavailable:
            return AUTH_UNAVAILABLE
    return AUTH_AUTHORIZED if uuid in dials else AUTH_NOT_AUTHORIZED


def write_dial_entry(uuid: str, name: str) -> None:
    from autostream_sysutils import atomic_write_file
    with _DIALS_LOCK:
        dials = _load_dials_locked()
        dials[uuid] = {"name": name, "authorized_at": datetime.utcnow().isoformat()}
        atomic_write_file(DIALS_PATH, lambda f: _json.dump(dials, f, indent=2),
                          preserve_mode=True)


def remove_dial_entry(uuid: str) -> None:
    from autostream_sysutils import atomic_write_file
    with _DIALS_LOCK:
        dials = _load_dials_locked()
        dials.pop(uuid, None)
        atomic_write_file(DIALS_PATH, lambda f: _json.dump(dials, f, indent=2),
                          preserve_mode=True)


def is_dial_authorized(uuid: str) -> bool:
    """Return True if uuid is present in DIALS_PATH."""
    return dial_authorization(uuid) == AUTH_AUTHORIZED


def parse_dial_entries() -> list:
    """Return all authorized dial entries as DialEntry objects."""
    with _DIALS_LOCK:
        dials = _load_dials_locked()
    entries = []
    for uuid, val in dials.items():
        if not isinstance(val, dict):
            continue
        entries.append(DialEntry(
            uuid=uuid,
            name=val.get("name", ""),
            authorized_at=val.get("authorized_at", ""),
            current_name=val.get("current_name", ""),
            last_seen=val.get("last_seen", ""),
        ))
    return entries


def update_dial_sighting(uuid: str, name: str) -> None:
    """Update last_seen and current_name in dials.json on mDNS sighting.

    Only writes if the existing last_seen is older than _SIGHTING_THROTTLE_SECS.
    Silently no-ops for unknown (unauthorized) UUIDs.
    """
    from autostream_sysutils import atomic_write_file
    with _DIALS_LOCK:
        dials = _load_dials_locked()
        if uuid not in dials:
            return
        entry = dials[uuid]
        last_seen_str = entry.get("last_seen", "")
        if last_seen_str:
            try:
                last_seen = datetime.fromisoformat(last_seen_str)
                if (datetime.utcnow() - last_seen).total_seconds() < _SIGHTING_THROTTLE_SECS:
                    return
            except ValueError:
                pass
        entry["last_seen"] = datetime.utcnow().isoformat()
        entry["current_name"] = name
        atomic_write_file(DIALS_PATH, lambda f: _json.dump(dials, f, indent=2),
                          preserve_mode=True)


# ---------------------------------------------------------------------------
# Scanner state — backed by the shared MdnsBrowser
# ---------------------------------------------------------------------------


@dataclass
class DialSighting:
    uuid: str
    name: str
    version: str
    ip: str
    port: int
    pin_recovery: bool
    sdmon: bool = False   # dial_sdmon=v1 in the TXT record: the dial has the SD health endpoint
    dial_proto: str = ""  # dial_proto value from the TXT record, verbatim; "" when absent


def _parse_dial_event(parts: list, txt: dict) -> tuple | None:
    """Parse a resolved _autostream-dial._tcp Avahi event.

    Returns (uuid, DialSighting) or None if the event should be ignored.
    Dial persistence (last_seen update) is performed here, outside the
    shared registry lock.
    """
    uuid = txt.get("id", "")
    if not uuid:
        return None
    try:
        port = int(parts[8])
    except (ValueError, IndexError):
        port = 7842
    sighting = DialSighting(
        uuid=uuid,
        name=txt.get("name", ""),
        version=txt.get("version", ""),
        ip=parts[7],
        port=port,
        pin_recovery=(txt.get("pin_recovery") == "1"),
        sdmon=(txt.get("dial_sdmon") == "v1"),
        dial_proto=txt.get("dial_proto", ""),
    )
    # Update last_seen / current_name in dials.json (throttled write, outside lock).
    update_dial_sighting(uuid, sighting.name)
    return (uuid, sighting)


_browser: MdnsBrowser = MdnsBrowser(
    service_type="_autostream-dial._tcp",
    parse_fn=_parse_dial_event,
)


def get_dial_sighting(uuid: str) -> DialSighting | None:
    return _browser.get_snapshot().get(uuid)


def get_all_sightings() -> list[DialSighting]:
    return list(_browser.get_snapshot().values())


def dial_speaks_v2(uuid: str) -> bool:
    """True when the dial is currently sighted and advertises at least the
    current protocol dialect.  An unsighted dial is treated as legacy."""
    s = get_dial_sighting(uuid)
    return s is not None and dial_proto_generation(s.dial_proto) >= _MIN_DIAL_GENERATION


def sighting_needs_update(s: DialSighting) -> bool:
    """True when the sighted dial advertises an older protocol generation than
    this appliance does."""
    return dial_proto_generation(s.dial_proto) < dial_proto_generation(DIAL_PROTO_VERSION)


def dials_needing_update() -> list[DialSighting]:
    """Currently sighted dials that do not advertise the current protocol dialect."""
    return [s for s in get_all_sightings() if sighting_needs_update(s)]


def build_dial_update_banner_text() -> str:
    """Home page banner text: non-empty when at least one currently sighted
    dial does not advertise the current protocol dialect.  The wording is the
    same whatever the count; the Setup page's dial card flags each dial."""
    return "Dial updates required" if dials_needing_update() else ""


def start_dial_scanner(
    shutdown_event: "threading.Event | None" = None,
) -> None:
    """Start the background mDNS browser for _autostream-dial._tcp.  Idempotent."""
    _browser.start(shutdown_event=shutdown_event)


def stop_dial_scanner() -> None:
    """Stop the background mDNS browser for _autostream-dial._tcp.  Idempotent."""
    _browser.stop()
