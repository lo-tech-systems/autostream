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
    with _DIALS_LOCK:
        dials = _load_dials_locked()
    return uuid in dials


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


def start_dial_scanner() -> None:
    """Start the background mDNS browser for _autostream-dial._tcp.  Idempotent."""
    _browser.start()
