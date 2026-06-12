"""autostream_dials.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Dial authorization storage and background avahi-browse scanner for
_autostream-dial._tcp services. Maintains an in-memory registry of
currently-visible dial devices keyed by the avahi 5-tuple
(interface, protocol, name, type, domain) and by UUID.
"""
from __future__ import annotations

import json as _json
import logging
import re
import shlex
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

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
# Scanner state
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_by_key: dict[tuple, "DialSighting"] = {}   # key: (iface, proto, name, type, domain)
_by_uuid: dict[str, "DialSighting"] = {}    # key: uuid; for O(1) lookup by callers


@dataclass
class DialSighting:
    uuid: str
    name: str
    version: str
    ip: str
    port: int
    pin_recovery: bool


def get_dial_sighting(uuid: str) -> DialSighting | None:
    with _lock:
        return _by_uuid.get(uuid)


def get_all_sightings() -> list[DialSighting]:
    with _lock:
        return list(_by_uuid.values())


def start_dial_scanner() -> None:
    threading.Thread(target=_browse_loop, daemon=True, name="dial-scanner").start()


def _browse_loop() -> None:
    while True:
        with _lock:
            _by_key.clear()
            _by_uuid.clear()
        try:
            proc = subprocess.Popen(
                ["avahi-browse", "--no-fail", "-p", "-r", "_autostream-dial._tcp"],
                stdout=subprocess.PIPE,
                text=True,
            )
            for line in proc.stdout:
                _handle_line(line.strip())
        except Exception as e:
            logging.warning("dial scanner: %s", e)
        time.sleep(5)


def _parse_avahi_txt(raw: str) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        for token in shlex.split(raw):
            if "=" in token:
                k, _, v = token.partition("=")
                result[k] = v
    except ValueError:
        pass
    return result


def _handle_line(line: str) -> None:
    parts = line.split(";")
    event = parts[0] if parts else ""

    if event == "=" and len(parts) >= 10 and parts[2] == "IPv4":
        key = tuple(parts[1:6])
        txt = _parse_avahi_txt(parts[9])
        uuid = txt.get("id", "")
        if not uuid:
            return
        sighting = DialSighting(
            uuid=uuid,
            name=txt.get("name", ""),
            version=txt.get("version", ""),
            ip=parts[7],
            port=int(parts[8]) if parts[8].isdigit() else 7842,
            pin_recovery=(txt.get("pin_recovery") == "1"),
        )
        with _lock:
            _by_key[key] = sighting
            _by_uuid[uuid] = sighting
        # Update last_seen / current_name in dials.json (throttled write).
        update_dial_sighting(uuid, sighting.name)

    elif event == "-" and len(parts) >= 6 and parts[2] == "IPv4":
        key = tuple(parts[1:6])
        with _lock:
            removed = _by_key.pop(key, None)
            if removed:
                remaining = next(
                    (s for s in _by_key.values() if s.uuid == removed.uuid), None
                )
                if remaining:
                    _by_uuid[removed.uuid] = remaining
                else:
                    _by_uuid.pop(removed.uuid, None)
