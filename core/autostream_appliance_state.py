"""autostream_appliance_state.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Owns the appliance and dials parts of the state snapshot. The appliance part
says who this appliance is and whether it is set up; the dials part moves
whenever a dial is authorised or revoked, so a stream that tells a named dial
what it may do knows when to ask again.

A worker thread re-reads the sources once at start (on the calling thread, so
the first snapshot a client sees is complete), then every 30 seconds and
whenever something calls live.state_refresh(). A source that fails to read
keeps its last value. The handlers of the dials.authorize and dials.revoke
rows live here and bind themselves at import.

Contents:
  - start  -- publish once, then run the worker
  - poke   -- ask the worker to look again now (live.state_refresh)
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Callable, Optional

import autostream_rpi as rpi
import autostream_state
from autostream_auth import pin_is_set
from autostream_commissioning import is_commissioning_required
from autostream_dial_push import notify_dial_auth_changed
from autostream_dials import remove_dial_entry, validate_dial_name, write_dial_entry
from autostream_intents.table import Intent, Outcome, bind
from autostream_state import AppliancePart, DialsPart, Origin, live
from autostream_sysutils import format_hostname, get_system_hostname

_OWNER = "autostream_appliance_state"
_PERIOD_S = 30.0

_appliance_writer = autostream_state.store().claim("appliance", _OWNER)
_dials_writer = autostream_state.store().claim("dials", _OWNER)

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


def _push_after_write(uuid: str, verb: str) -> None:
    try:
        notify_dial_auth_changed(uuid)
    except Exception as e:
        logging.debug("dial auth push: enqueue failed after %s: %s", verb, e)


def _authorize(intent: Intent, wait: float) -> Outcome:
    uuid, name = intent.args["uuid"], intent.args["name"]
    if not validate_dial_name(name):
        return Outcome(ok=False, error="invalid_name")
    write_dial_entry(uuid, name)
    version = _bump_generation(intent)
    _push_after_write(uuid, "authorize")
    return Outcome(ok=True, version=version)


def _revoke(intent: Intent, wait: float) -> Outcome:
    uuid = intent.args["uuid"]
    remove_dial_entry(uuid)
    version = _bump_generation(intent)
    _push_after_write(uuid, "revoke")
    return Outcome(ok=True, version=version)


bind("dials.authorize", _authorize, owner=_OWNER)
bind("dials.revoke", _revoke, owner=_OWNER)


# ---------------------------------------------------------------------------
# The worker
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _Sources:
    config_path: str
    state_path: str
    app_version: Callable[[], str]


def _read(read: Callable, keep, what: str):
    """read(), or *keep* when it raises (logged at debug)."""
    try:
        return read()
    except Exception:
        logging.debug("appliance state: %s unreadable; keeping the last value", what, exc_info=True)
        return keep


def _gather(src: _Sources, last: AppliancePart) -> AppliancePart:
    return AppliancePart(
        id=_read(lambda: rpi.get_appliance_id() or "", last.id, "appliance id"),
        hostname=_read(lambda: format_hostname(get_system_hostname()), last.hostname, "hostname"),
        version=_read(lambda: str(src.app_version() or ""), last.version, "version"),
        configured=_read(
            lambda: not is_commissioning_required(src.config_path, src.state_path),
            last.configured, "commissioning state"),
        pin_set=_read(lambda: pin_is_set(src.state_path), last.pin_set, "PIN"),
    )


def _run_pass(src: _Sources) -> None:
    last = autostream_state.store().snapshot().appliance
    _appliance_writer.publish(_gather(src, last), origin=Origin.SYSTEM).notify()


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
    """Publish the appliance part on this thread, then start the worker that
    keeps it current. Returns the worker thread."""
    src = _Sources(config_path, state_path, app_version)
    try:
        _run_pass(src)
    except Exception:
        logging.exception("appliance state: first pass failed")
    thread = threading.Thread(
        target=_loop, args=(src, shutdown_event), name="appliance-state", daemon=True)
    thread.start()
    return thread
