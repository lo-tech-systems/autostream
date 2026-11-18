"""autostream_appliances.py -- the other appliances, and this one's announcement.

Follows every appliance sighted on the network through a PeerClient, publishes
the `peers` part, works out which speakers those appliances are playing, and
resolves an appliance id for the pages that show another appliance. Also
manages the local _autostream._tcp Avahi service file via privileged
autostream_admin commands.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
import re
import subprocess
import threading
from dataclasses import dataclass
from typing import Mapping, Optional

import autostream_rpi as rpi
from autostream_peer_client import PeerClient, PeerPool, PeerSnapshot, roster_view
from autostream_peer_registry import PeerRegistry, Sighting
from autostream_state import Origin, PeersPart, live, store

_OWNER = "autostream_appliances"
_20HEX_RE = re.compile(r'^[0-9a-f]{20}$')

_ADMIN_CMD = [
    "/usr/bin/sudo",
    "-n",
    "/usr/local/libexec/autostream/autostream_admin",
]

_peers_writer = store().claim("peers", _OWNER)

# ---------------------------------------------------------------------------
# The pool and its worker
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_registry: Optional[PeerRegistry] = None
_pool: Optional[PeerPool] = None
_pool_handle: Optional[int] = None
_thread: Optional[threading.Thread] = None
_grace_seconds: Optional[int] = None
_wake = threading.Event()
_stopping = threading.Event()

# casefolded speaker name -> (id, hostname) of the appliance playing it
_usage: dict[str, tuple[str, str]] = {}


def start(life, settings) -> None:
    """Start following the appliances on the network. Idempotent. Does nothing
    when this appliance has no id: without it a peer cannot be told from this
    appliance."""
    global _registry, _pool, _pool_handle, _thread
    own_id = rpi.get_appliance_id()
    if own_id is None:
        logging.warning("appliances: local identity unavailable; not starting")
        return
    with _lock:
        if _thread is not None:
            return
        _stopping.clear()
        _registry = PeerRegistry(local_id=own_id)
        if _grace_seconds is not None:
            _registry.set_grace_period(_grace_seconds)
        _pool = PeerPool(_registry, lambda peer_id: PeerClient(peer_id, client_id=f"peer:{own_id}"))
        _pool_handle = _pool.subscribe(_wake.set)
        _thread = threading.Thread(target=_worker, args=(life,), name="peers", daemon=True)
        registry, pool, thread = _registry, _pool, _thread
    registry.start(shutdown_event=life.stop)
    pool.start()
    _wake.set()
    thread.start()


def stop() -> None:
    """Stop following the appliances. Idempotent."""
    global _registry, _pool, _pool_handle, _thread
    with _lock:
        registry, pool, handle = _registry, _pool, _pool_handle
        thread = _thread
        _registry = _pool = _pool_handle = _thread = None
    _stopping.set()
    _wake.set()
    if pool is not None:
        if handle is not None:
            pool.unsubscribe(handle)
        pool.stop()
    if registry is not None:
        registry.stop()
    if thread is not None and thread is not threading.current_thread():
        thread.join(timeout=2.0)


def set_grace_period(seconds: int) -> None:
    """Set appliance-discovery final-removal grace in seconds."""
    global _grace_seconds
    with _lock:
        _grace_seconds = seconds
        registry = _registry
    if registry is not None:
        registry.set_grace_period(seconds)


def _worker(life) -> None:
    while not life.stopping() and not _stopping.is_set():
        _wake.wait()
        if life.stopping() or _stopping.is_set():
            break
        _wake.clear()
        try:
            _pass()
        except Exception:
            logging.debug("appliances: worker pass failed", exc_info=True)


def _pass() -> None:
    """Read every client once; publish the peers part and the occupancy."""
    global _usage
    with _lock:
        registry, pool = _registry, _pool
    if registry is None or pool is None:
        return
    snapshots = {peer_id: client.snapshot() for peer_id, client in pool.clients().items()}
    entries = roster_view(registry.sightings(), snapshots)
    _peers_writer.publish(PeersPart(entries), origin=Origin.SYSTEM).notify()
    usage = occupancy(entries, snapshots)
    if usage == _usage:
        return
    previous, _usage = _usage, usage
    from autostream_state.outputs import get_authority
    get_authority().set_remote_usage(usage)
    for key, owner in usage.items():
        if previous.get(key) != owner:
            logging.debug("appliances: %s now in use by %s", key, owner[1])
    for key, owner in previous.items():
        if usage.get(key) != owner:
            logging.debug("appliances: %s no longer in use by %s", key, owner[1])


def occupancy(entries, snapshots: Mapping[str, PeerSnapshot]) -> dict[str, tuple[str, str]]:
    """The speakers other appliances are playing: casefolded name -> (id,
    hostname). An appliance counts while it is reachable and has a session;
    each speaker it has switched on, that the player reports and that is not
    waiting for a PIN, is in use. When two appliances report one name, the
    first by hostname wins. *entries* are in hostname order."""
    usage: dict[str, tuple[str, str]] = {}
    for entry in entries:
        snap = snapshots.get(entry.id)
        if snap is None or not snap.reachable:
            continue
        session = snap.parts.get("session")
        if not (isinstance(session, Mapping) and session.get("active") is True):
            continue
        outputs = snap.parts.get("outputs")
        units = outputs.get("units") if isinstance(outputs, Mapping) else None
        for unit in units or ():
            if not isinstance(unit, Mapping):
                continue
            name = str(unit.get("name") or "")
            if (name and unit.get("reported") is not None and unit.get("selected") is True
                    and unit.get("availability") != "password"):
                usage.setdefault(name.strip().casefold(), (entry.id, entry.hostname))
    return usage


def annotate_outputs(outputs: list[dict]) -> list[dict]:
    """The output dicts with remote_in_use and remote_owner added: a speaker is
    in use elsewhere unless it is selected here. Reads the held occupancy and
    makes no request."""
    usage = _usage
    result = []
    for out in outputs:
        out = dict(out)
        owner = usage.get(str(out.get("name") or "").strip().casefold())
        in_use = owner is not None and not out.get("selected")
        out["remote_in_use"] = in_use
        out["remote_owner"] = owner[1] if in_use else ""
        result.append(out)
    return result


def _live_annotate_outputs(outputs: list[dict]) -> list[dict]:
    # Looked up at call time, so a replaced annotate_outputs is the one used.
    return annotate_outputs(outputs)


live.bind("annotate_outputs", _live_annotate_outputs, owner=_OWNER)


# ---------------------------------------------------------------------------
# Resolving an appliance id
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Resolution:
    kind: str     # "invalid" | "bound" | "conflict" | "unknown" | "control_off" | "unconfigured" | "remote"
    client: Optional[PeerClient] = None
    sighting: Optional[Sighting] = None


def resolve(appliance_id: str) -> Resolution:
    """What *appliance_id* names. "remote" carries the client and the sighting;
    "unconfigured" is a reachable appliance that is not set up yet, and
    "control_off" one that does not allow other appliances to control it."""
    if not _20HEX_RE.match(appliance_id):
        return Resolution("invalid")
    own_id = rpi.get_appliance_id()
    if own_id and appliance_id == own_id:
        return Resolution("bound")
    with _lock:
        registry, pool = _registry, _pool
    if registry is None or pool is None:
        return Resolution("unknown")
    if appliance_id in registry.conflicts():
        return Resolution("conflict")
    sighting = registry.sightings().get(appliance_id)
    client = pool.get(appliance_id)
    if sighting is None or client is None:
        return Resolution("unknown")
    if not sighting.control:
        return Resolution("control_off", sighting=sighting)
    snap = client.snapshot()
    if snap.reachable and snap.configured is False:
        return Resolution("unconfigured", client, sighting)
    return Resolution("remote", client, sighting)


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

    The appliance is always advertised when it has a local identity; the
    *advertise* flag selects the control TXT value (on/off), not presence.
    An identity-less appliance still never advertises (no id to key on).

    Must be called with CONFIG_IO_LOCK not held; acquires _ANNOUNCE_LOCK
    internally to serialize concurrent reconciliation calls.

    Returns True on success, False on admin command failure.
    """
    app_id = rpi.get_appliance_id()
    with _ANNOUNCE_LOCK:
        if app_id is not None:
            control = "on" if advertise else "off"
            rc = _run_admin(["write-appliance-service", version or "unknown", app_id, control])
        else:
            rc = _run_admin(["remove-appliance-service"])
    if rc != 0:
        logging.warning(
            "reconcile_appliance_announcement: admin command failed (rc=%d) advertise=%s",
            rc, advertise,
        )
    return rc == 0
