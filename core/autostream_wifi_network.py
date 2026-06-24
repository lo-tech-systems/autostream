#!/usr/bin/python3
"""autostream_wifi_network.py

Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

Dedicated, root-owned network-facts and bounded-primitive helper for the
Autostream Wi-Fi recovery watcher (``platform/wifi_watcher``).

Responsibility boundary (see the implementation plan, section 2.7):

  * This module owns *facts* and *bounded primitives*:
      - network-state parsing / atomic writing / legacy migration & mirroring;
      - adapter records and discovery, stable identity;
      - ``nmcli`` query and command-construction primitives;
      - route / neighbour inspection;
      - scan parsing and SSID merging.

  * It MUST NOT contain policy, Flask routes, threads, timers, systemd service
    actions, fallback policy, or another state machine.  Those belong to the
    watcher.

Dependencies are restricted to the Python standard library plus
``autostream_sysutils`` (for ``run_cmd``).  Do not add packages to the recovery
dependency set.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import dataclass
from typing import Optional

from autostream_sysutils import run_cmd

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Paths (parameterised as module constants so tests can redirect them)
# ---------------------------------------------------------------------------

# Root-owned persistent network state.  Deliberately NOT inside
# /etc/autostream/ (which is writable by the unprivileged autostream account).
NETWORK_STATE_PATH = "/etc/autostream-network.json"

# Legacy compatibility mirror.  Despite its name it holds a NetworkManager
# connection *name*, not an SSID.  Retained for upgrade/downgrade compatibility.
LEGACY_SSID_PATH = "/opt/autostream/ssid"

SCHEMA_VERSION = 1


# ---------------------------------------------------------------------------
# Network state model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class NetworkState:
    """Resolved, validated configured-network identity.

    ``connection_name`` empty means the appliance is unconfigured.  The state
    never contains credentials.
    """
    connection_name: str = ""
    connection_uuid: str = ""

    @property
    def is_configured(self) -> bool:
        return bool(self.connection_name)


# ---------------------------------------------------------------------------
# nmcli terse-output parsing
# ---------------------------------------------------------------------------

def split_nmcli_terse(line: str, maxsplit: int = -1) -> list[str]:
    r"""Split an ``nmcli -t`` terse line on unescaped ``:`` separators.

    ``nmcli`` escapes literal ``:`` as ``\:`` and literal ``\`` as ``\\`` in
    terse output, so a naive ``line.split(':')`` corrupts SSIDs and connection
    names that legally contain colons or backslashes.  This parser honours
    those escaping rules and unescapes each returned field.

    ``maxsplit`` limits the number of separator splits; when reached the final
    field keeps any remaining (still unescaped) text verbatim.
    """
    fields: list[str] = []
    current: list[str] = []
    i = 0
    n = len(line)
    splits = 0
    while i < n:
        ch = line[i]
        if ch == "\\" and i + 1 < n:
            # Escaped character — keep the next char literally.
            current.append(line[i + 1])
            i += 2
            continue
        if ch == ":" and (maxsplit < 0 or splits < maxsplit):
            fields.append("".join(current))
            current = []
            splits += 1
            i += 1
            continue
        current.append(ch)
        i += 1
    fields.append("".join(current))
    return fields


# ---------------------------------------------------------------------------
# Atomic file primitives
# ---------------------------------------------------------------------------

def _atomic_write(path: str, data: str, mode: int = 0o644) -> None:
    """Atomically write *data* to *path* with *mode*.

    Creates a temp file in the same directory, flushes, fsyncs, sets mode, then
    ``os.replace`` over the destination.
    """
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Network-state load / save / migration
# ---------------------------------------------------------------------------

def _read_legacy_connection_name(path: Optional[str] = None) -> str:
    """Return the connection name from the legacy SSID file, or "" if absent/empty."""
    p = path or LEGACY_SSID_PATH
    try:
        if not os.path.isfile(p):
            return ""
        with open(p, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError as e:
        logger.warning("Error reading legacy network file %s: %s", p, e)
        return ""


def _parse_network_json(raw: str) -> Optional[NetworkState]:
    """Parse network.json text into a NetworkState, or None if invalid.

    Unknown keys are ignored.  A wrong/missing schema version is treated as
    invalid so the caller falls back to the legacy file rather than guessing.
    """
    try:
        obj = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict):
        return None
    if obj.get("schema_version") != SCHEMA_VERSION:
        return None
    name = obj.get("connection_name", "")
    uuid = obj.get("connection_uuid", "")
    if not isinstance(name, str) or not isinstance(uuid, str):
        return None
    return NetworkState(connection_name=name.strip(), connection_uuid=uuid.strip())


def load_network_state(
    state_path: Optional[str] = None,
    legacy_path: Optional[str] = None,
) -> NetworkState:
    """Resolve the configured network state.

    Resolution order (plan section 3.2):
      1. valid non-empty network.json;
      2. non-empty legacy /opt/autostream/ssid;
      3. unconfigured.

    Invalid/unreadable JSON is logged and falls back to the legacy file rather
    than declaring the appliance unconfigured.
    """
    sp = state_path or NETWORK_STATE_PATH
    lp = legacy_path or LEGACY_SSID_PATH

    if os.path.isfile(sp):
        raw: Optional[str]
        try:
            with open(sp, "r", encoding="utf-8") as f:
                raw = f.read()
        except OSError as e:
            logger.warning("Could not read %s: %s; falling back to legacy file", sp, e)
            raw = None
        if raw is not None:
            parsed = _parse_network_json(raw)
            if parsed is None:
                logger.warning(
                    "Invalid %s; ignoring and falling back to legacy file", sp
                )
            elif parsed.is_configured:
                return parsed
            # An empty-but-valid network.json still means we should consult the
            # legacy file before declaring the appliance unconfigured.

    legacy_name = _read_legacy_connection_name(lp)
    if legacy_name:
        return NetworkState(connection_name=legacy_name, connection_uuid="")

    return NetworkState()


def save_network_state(
    state: NetworkState,
    state_path: Optional[str] = None,
    legacy_path: Optional[str] = None,
    write_legacy: bool = True,
) -> None:
    """Atomically persist *state* to network.json and (optionally) mirror it.

    The legacy mirror receives only ``connection_name`` plus a trailing newline
    — never JSON — so an older watcher can still read it after an upgrade.
    """
    sp = state_path or NETWORK_STATE_PATH
    lp = legacy_path or LEGACY_SSID_PATH

    payload = {
        "schema_version": SCHEMA_VERSION,
        "connection_name": state.connection_name,
        "connection_uuid": state.connection_uuid,
    }
    _atomic_write(sp, json.dumps(payload, indent=2) + "\n", mode=0o644)

    if write_legacy:
        try:
            _atomic_write(lp, f"{state.connection_name}\n", mode=0o644)
        except OSError as e:
            logger.warning("Could not update legacy mirror %s: %s", lp, e)


def resolve_connection_uuid_for_name(name: str) -> str:
    """Resolve a NetworkManager Wi-Fi profile UUID for *name*.

    Returns the UUID only when exactly one matching Wi-Fi profile exists;
    otherwise returns "" and lets the caller log a warning rather than guessing.
    """
    if not name:
        return ""
    r = run_cmd(["nmcli", "-t", "-f", "NAME,UUID,TYPE", "connection", "show"])
    if r.returncode != 0:
        return ""
    matches: list[str] = []
    for line in r.stdout.splitlines():
        if not line:
            continue
        parts = split_nmcli_terse(line)
        if len(parts) < 3:
            continue
        cname, cuuid, ctype = parts[0], parts[1], parts[2]
        if cname == name and "wireless" in ctype:
            matches.append(cuuid)
    if len(matches) == 1:
        return matches[0]
    return ""


def migrate_legacy_state(
    state_path: Optional[str] = None,
    legacy_path: Optional[str] = None,
    resolve_uuid: bool = True,
) -> Optional[NetworkState]:
    """Import legacy /opt/autostream/ssid into network.json when needed.

    Performs migration only when network.json is missing/invalid/unconfigured
    AND the legacy file holds a non-empty name.  The legacy file is left
    unchanged (other than being re-mirrored with the same name).  Returns the
    migrated NetworkState, or None when no migration was required.
    """
    sp = state_path or NETWORK_STATE_PATH
    lp = legacy_path or LEGACY_SSID_PATH

    # If network.json already carries a configured name, nothing to migrate.
    if os.path.isfile(sp):
        try:
            with open(sp, "r", encoding="utf-8") as f:
                parsed = _parse_network_json(f.read())
        except OSError:
            parsed = None
        if parsed is not None and parsed.is_configured:
            return None

    legacy_name = _read_legacy_connection_name(lp)
    if not legacy_name:
        return None

    uuid = ""
    if resolve_uuid:
        uuid = resolve_connection_uuid_for_name(legacy_name)
        if not uuid:
            logger.warning(
                "Legacy network '%s' migrated without a resolved UUID "
                "(no profile or multiple matching profiles)",
                legacy_name,
            )

    migrated = NetworkState(connection_name=legacy_name, connection_uuid=uuid)
    save_network_state(migrated, state_path=sp, legacy_path=lp, write_legacy=True)
    logger.info("Migrated legacy network state for connection '%s'", legacy_name)
    return migrated
