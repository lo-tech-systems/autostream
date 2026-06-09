"""autostream_dials.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Background avahi-browse scanner for _autostream-dial._tcp services.
Maintains an in-memory registry of currently-visible dial devices keyed by
the avahi 5-tuple (interface, protocol, name, type, domain) and by UUID.
"""
from __future__ import annotations

import logging
import shlex
import subprocess
import threading
import time
from dataclasses import dataclass

from autostream_config import update_dial_sighting

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
