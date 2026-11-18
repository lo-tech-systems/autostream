"""autostream_appliance_state.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Owns the appliance, dials and warnings parts of the state snapshot. The
appliance part says who this appliance is and whether it is set up; the dials
part moves whenever a dial is authorised or revoked, so a stream that tells a
named dial what it may do knows when to ask again; the warnings part is what
the appliance wants a person to know (autostream_warnings holds the words).

A worker thread re-reads the sources once at start (on the calling thread, so
the first snapshot a client sees is complete), then every 30 seconds and
whenever the playback, inputs or dials part moves or something calls
live.state_refresh(). A source that fails to read keeps its last value (the
appliance part) or drops only its own warning. The handlers of the dials.authorize and dials.revoke
rows live here and bind themselves at import.

Contents:
  - start  -- publish once, then run the worker
  - poke   -- ask the worker to look again now (live.state_refresh)
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Callable, Optional

import autostream_appliance_identity as identity
import autostream_licensing
import autostream_system_stats
import autostream_state
from autostream_auth import pin_is_set
from autostream_commissioning import is_commissioning_required
from autostream_dials import (
    get_all_sightings,
    parse_dial_entries,
    remove_dial_entry,
    sighting_needs_update,
    validate_dial_name,
    write_dial_entry,
)
from autostream_intents.table import Intent, Outcome, bind
from autostream_state import AppliancePart, DialsPart, Origin, WarningsPart, live
from autostream_sysutils import format_hostname, get_system_hostname, sd_level, sdcard_health_display
from autostream_system_stats import _read_get_throttled_value
from autostream_warnings import Inputs, derive

_OWNER = "autostream_appliance_state"
_PERIOD_S = 30.0

_appliance_writer = autostream_state.store().claim("appliance", _OWNER)
_dials_writer = autostream_state.store().claim("dials", _OWNER)
_warnings_writer = autostream_state.store().claim("warnings", _OWNER)

_poke_event = threading.Event()


def poke() -> None:
    """Ask the worker to look at its sources now."""
    _poke_event.set()


live.bind("state_refresh", poke, owner=_OWNER)


# ---------------------------------------------------------------------------
# Dials: authorise and revoke
# ---------------------------------------------------------------------------

def _bump_generation(intent: Intent) -> int:
    """Publish the next dials generation, so the reply's version covers it."""
    pending = _dials_writer.update(
        lambda part: DialsPart(part.generation + 1),
        origin=intent.origin, requester=intent.requester,
    )
    pending.notify()
    return pending.version


def _authorize(intent: Intent, wait: float) -> Outcome:
    uuid, name = intent.args["uuid"], intent.args["name"]
    if not validate_dial_name(name):
        return Outcome(ok=False, error="invalid_name")
    write_dial_entry(uuid, name)
    version = _bump_generation(intent)
    return Outcome(ok=True, version=version)


def _revoke(intent: Intent, wait: float) -> Outcome:
    uuid = intent.args["uuid"]
    remove_dial_entry(uuid)
    version = _bump_generation(intent)
    return Outcome(ok=True, version=version)


bind("dials.authorize", _authorize, owner=_OWNER)
bind("dials.revoke", _revoke, owner=_OWNER)


# ---------------------------------------------------------------------------
# The worker
# ---------------------------------------------------------------------------

@dataclass
class _Held:
    """What the worker carries from one pass to the next, for the hysteresis."""

    cpu_status: str = "ok"
    sd_level: str = "ok"


@dataclass(frozen=True)
class _Sources:
    config_path: str
    state_path: str
    app_version: Callable[[], str]
    held: _Held = field(default_factory=_Held)


def _read(read: Callable, keep, what: str):
    """read(), or *keep* when it raises (logged at debug)."""
    try:
        return read()
    except Exception:
        logging.debug("appliance state: %s unreadable; keeping the last value", what, exc_info=True)
        return keep


def _gather(src: _Sources, last: AppliancePart) -> AppliancePart:
    return AppliancePart(
        id=_read(lambda: identity.get_appliance_id() or "", last.id, "appliance id"),
        hostname=_read(lambda: format_hostname(get_system_hostname()), last.hostname, "hostname"),
        version=_read(lambda: str(src.app_version() or ""), last.version, "version"),
        configured=_read(
            lambda: not is_commissioning_required(src.config_path, src.state_path),
            last.configured, "commissioning state"),
        pin_set=_read(lambda: pin_is_set(src.state_path), last.pin_set, "PIN"),
    )


def _dials_needing_update() -> int:
    authorised = {e.uuid for e in parse_dial_entries()}
    return sum(1 for s in get_all_sightings()
               if s.uuid in authorised and sighting_needs_update(s))


def _unlicensed() -> bool:
    return bool(autostream_licensing.LICENSE_CHECK and not autostream_licensing.cpu_is_licensed())


def _gather_warnings(src: _Sources, snap) -> Inputs:
    """The inputs of the warnings table. A source that fails reads as its
    quiet value, so only its own warning goes."""
    held = src.held
    cpu_status, cpu_temp = _read(
        lambda: autostream_system_stats.get_cpu_thermal_status(held.cpu_status), ("ok", None), "CPU temperature")
    held.cpu_status = cpu_status
    sd_percent = _read(sdcard_health_display, None, "microSD health")
    held.sd_level = sd_level(sd_percent, held.sd_level)
    return Inputs(
        playback=snap.playback,
        inputs=snap.inputs,
        throttled=_read(_read_get_throttled_value, None, "throttle flags"),
        cpu_temp_c=cpu_temp,
        cpu_status=cpu_status,
        sd_percent=sd_percent,
        sd_level=held.sd_level,
        dials_needing_update=_read(_dials_needing_update, 0, "dial sightings"),
        unlicensed=_read(_unlicensed, False, "licence"),
    )


def _run_pass(src: _Sources) -> None:
    snap = autostream_state.store().snapshot()
    _appliance_writer.publish(_gather(src, snap.appliance), origin=Origin.SYSTEM).notify()
    entries = derive(_gather_warnings(src, snap))
    _warnings_writer.publish(WarningsPart(entries), origin=Origin.SYSTEM).notify()


_WAKING_PARTS = frozenset({"playback", "inputs", "dials"})


def _wake_on_change(change) -> None:
    """Store subscriber: only sets the event, so no work runs on a publisher's thread."""
    if _WAKING_PARTS & change.parts:
        _poke_event.set()


def _loop(src: _Sources, shutdown_event: threading.Event) -> None:
    logged: set = set()
    while not shutdown_event.is_set():
        _poke_event.wait(_PERIOD_S)
        _poke_event.clear()
        if shutdown_event.is_set():
            break
        try:
            _run_pass(src)
        except Exception as e:
            # Once per distinct message; the parts keep their last values.
            if str(e) not in logged:
                logged.add(str(e))
                logging.exception("appliance state pass failed")


def start(
    shutdown_event: threading.Event,
    *,
    config_path: str,
    state_path: str,
    settings,
    app_version: Callable[[], str],
) -> Optional[threading.Thread]:
    """Publish the parts on this thread, then start the worker that keeps them
    current. Returns the worker thread."""
    src = _Sources(config_path, state_path, app_version)
    try:
        _run_pass(src)
    except Exception:
        logging.exception("appliance state: first pass failed")
    handle = autostream_state.store().subscribe(_wake_on_change)

    def run() -> None:
        try:
            _loop(src, shutdown_event)
        finally:
            autostream_state.store().unsubscribe(handle)

    thread = threading.Thread(target=run, name="appliance-state", daemon=True)
    thread.start()
    return thread
