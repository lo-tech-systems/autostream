"""autostream_appliances.py — appliance announcement and peer discovery.

Maintains the in-memory registry of compatible appliances discovered via
_autostream._tcp mDNS, and manages the local _autostream._tcp Avahi service
file via privileged autostream_admin commands.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
import os
import re
import subprocess
import threading
from dataclasses import dataclass
from typing import Optional

from autostream_federation import evict_session_for_ip
from autostream_mdns import MdnsBrowser
from autostream_rpi import get_appliance_id

_20HEX_RE = re.compile(r'^[0-9a-f]{20}$')

_ADMIN_CMD = [
    "/usr/bin/sudo",
    "-n",
    "/usr/local/libexec/autostream/autostream_admin",
]

# ---------------------------------------------------------------------------
# Appliance sighting model
# ---------------------------------------------------------------------------


@dataclass
class ApplianceSighting:
    id: str
    service_name: str
    hostname: str
    ip: str
    port: int
    version: str


# ---------------------------------------------------------------------------
# Conflict detection state
# ---------------------------------------------------------------------------

_reg_lock = threading.Lock()
# service_name → (appliance_id, hostname, ip)
_svc_info: dict[str, tuple[str, str, str]] = {}
# appliance_id → {(hostname, ip), ...}  — distinct network identities per ID
_id_net_identities: dict[str, set] = {}
# IDs excluded from the registry due to hostname/IP conflict
_conflict_ids: set[str] = set()
# Rate-limit conflict logging to one warning per ID
_conflict_logged: set[str] = set()


def _cap_tokens(raw: str) -> set[str]:
    return {t.strip() for t in raw.split(',') if t.strip()}


def _parse_appliance_event(parts: list, txt: dict) -> tuple | None:
    """Parse a resolved _autostream._tcp Avahi event.

    Returns (appliance_id, ApplianceSighting) or None if the record should
    be excluded (capability mismatch, invalid ID, local ID, or conflict).
    """
    appliance_id = txt.get('id', '')
    if not _20HEX_RE.match(appliance_id):
        return None

    if 'v1' not in _cap_tokens(txt.get('ui', '')):
        return None
    if 'v1' not in _cap_tokens(txt.get('federation', '')):
        return None

    local_id = get_appliance_id()
    if local_id and appliance_id == local_id:
        return None

    try:
        port = int(parts[8])
    except (ValueError, IndexError):
        port = 80

    service_name = parts[3]
    hostname = parts[6]
    ip = parts[7]
    version = txt.get('version', '')
    net_key = (hostname, ip)

    with _reg_lock:
        prev = _svc_info.get(service_name)
        if prev is not None and prev[0] != appliance_id:
            # Service changed its claimed ID — clean up old entry
            old_id, old_h, old_ip = prev
            old_set = _id_net_identities.get(old_id)
            if old_set is not None:
                old_set.discard((old_h, old_ip))
                if not old_set:
                    _id_net_identities.pop(old_id, None)
                    _conflict_ids.discard(old_id)

        _svc_info[service_name] = (appliance_id, hostname, ip)
        id_nets = _id_net_identities.setdefault(appliance_id, set())
        id_nets.add(net_key)

        if len(id_nets) > 1:
            if appliance_id not in _conflict_ids:
                _conflict_ids.add(appliance_id)
                if appliance_id not in _conflict_logged:
                    _conflict_logged.add(appliance_id)
                    hostnames = sorted({h for h, _ in id_nets})
                    logging.warning(
                        "appliance ID conflict: id=%s hostnames=[%s]",
                        appliance_id, ', '.join(hostnames),
                    )
            return None

        if appliance_id in _conflict_ids:
            return None

    sighting = ApplianceSighting(
        id=appliance_id,
        service_name=service_name,
        hostname=hostname,
        ip=ip,
        port=port,
        version=version,
    )
    return (appliance_id, sighting)


def _on_appliance_add(appliance_id: str, sighting: ApplianceSighting) -> None:
    snap = _browser.get_snapshot()
    if len(snap) == 1:
        logging.info("appliance peer found: %s (%s)", sighting.hostname, appliance_id)


def _on_appliance_remove(appliance_id: str, sighting: Optional[ApplianceSighting]) -> None:
    # Called only when the browser's last five-tuple for appliance_id is gone.
    # Clean up ALL _svc_info entries for this id — including any conflict-orphan entries
    # that _parse_appliance_event wrote to _svc_info but returned None for, so they were
    # never registered in the browser and can never be removed any other way.
    with _reg_lock:
        stale = [k for k, v in _svc_info.items() if v[0] == appliance_id]
        for k in stale:
            _svc_info.pop(k, None)
        _id_net_identities.pop(appliance_id, None)
        _conflict_ids.discard(appliance_id)
    if sighting is not None and sighting.ip:
        evict_session_for_ip(sighting.ip)
    snap = _browser.get_snapshot()
    if not snap:
        hostname = sighting.hostname if sighting is not None else appliance_id
        logging.info("no appliance peers — selector disabled (%s gone)", hostname)


_browser: MdnsBrowser = MdnsBrowser(
    service_type="_autostream._tcp",
    parse_fn=_parse_appliance_event,
    on_add=_on_appliance_add,
    on_remove=_on_appliance_remove,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_appliance_sighting(appliance_id: str) -> Optional[ApplianceSighting]:
    """Return the live sighting for *appliance_id* or None if absent/conflicted."""
    return _browser.get_snapshot().get(appliance_id)


def get_all_appliances() -> list[ApplianceSighting]:
    """Return all eligible live appliances sorted by case-insensitive hostname."""
    sightings = list(_browser.get_snapshot().values())
    sightings.sort(key=lambda s: s.hostname.lower())
    return sightings


def get_conflict_ids() -> frozenset[str]:
    """Return the set of appliance IDs currently excluded due to conflict."""
    with _reg_lock:
        return frozenset(_conflict_ids)


def scanner_ready() -> bool:
    """Return True when the appliance scanner has processed at least one browse event
    or the startup grace period has elapsed (>= 8 s)."""
    return _browser.scanner_ready()


def grace_remaining_ms() -> int:
    """Return the remaining startup grace period in milliseconds (0 if expired or ready)."""
    return _browser.grace_remaining_ms()


def start_appliance_scanner() -> None:
    """Start the _autostream._tcp discovery browser if local identity is available.

    Idempotent. Safe to call multiple times. No-op when get_appliance_id() is None
    because self-filtering and bound-ID routing cannot be guaranteed without it.
    """
    if get_appliance_id() is None:
        logging.warning("appliance-scanner: local identity unavailable; not starting")
        return
    _browser.start()


# ---------------------------------------------------------------------------
# Announcement (privileged, via autostream_admin)
# ---------------------------------------------------------------------------

_ANNOUNCE_LOCK = threading.Lock()


def _run_admin(args: list[str]) -> int:
    """Run an autostream_admin subcommand. Returns exit code."""
    cmd = _ADMIN_CMD + args
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=10)
        return r.returncode
    except Exception as e:
        logging.warning("autostream_admin %s: %s", args[0] if args else "?", e)
        return 1


def reconcile_appliance_announcement(version: str, advertise: bool) -> bool:
    """Write or remove the _autostream._tcp Avahi service file.

    Must be called with CONFIG_IO_LOCK not held; acquires _ANNOUNCE_LOCK
    internally to serialize concurrent reconciliation calls.

    Returns True on success, False on admin command failure.
    """
    app_id = get_appliance_id()
    with _ANNOUNCE_LOCK:
        if advertise and app_id is not None:
            rc = _run_admin(["write-appliance-service", version or "unknown", app_id])
        else:
            rc = _run_admin(["remove-appliance-service"])
    if rc != 0:
        logging.warning(
            "reconcile_appliance_announcement: admin command failed (rc=%d) advertise=%s",
            rc, advertise,
        )
    return rc == 0
