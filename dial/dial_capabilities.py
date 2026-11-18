"""dial_capabilities.py — what an appliance can do for the dial, and where that
is read from.

Two things live here, both pure data with no I/O and no import of the core:

  * the registry of what appliances' capabilities endpoints have said, keyed
    by appliance id and the advertised version the reply was fetched for;
  * `appliance_capabilities()`, the one switch point every caller reads an
    appliance's capabilities through. An appliance of a generation that has a
    capabilities endpoint (CAPABILITIES_ENDPOINT_PROTO or later) is read from
    the registry once the reply for its advertised version has landed; every
    other appliance, and one whose reply has not landed yet, is read from the
    flags its mDNS record advertises and from its protocol generation, exactly
    as before the endpoint existed. A newer appliance is therefore usable from
    its first sighting; the endpoint only adds to what it can do.

The registry has one lock, a leaf: nothing else is taken while it is held and
nothing is called out to. The reply is validated by `parse_capabilities_body`
before it is recorded.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass

# The first protocol generation whose appliances serve a capabilities endpoint.
CAPABILITIES_ENDPOINT_PROTO = 3

# A failed fetch is tried again after this long, doubling to the maximum.
CAPABILITIES_BACKOFF_INITIAL_S = 60.0
CAPABILITIES_BACKOFF_MAX_S = 600.0

# What a reply may hold: its size, the number of capabilities read from it and
# the shape of a capability's name.
CAPABILITIES_MAX_BODY_BYTES = 4096
CAPABILITIES_MAX_ENTRIES = 32
_CAPABILITY_NAME_RE = re.compile(r"[a-z_]{1,32}")


@dataclass(frozen=True)
class Capabilities:
    """What one appliance can do for the dial."""
    status: bool            # serves the dial status endpoint
    outputs: bool           # serves the outputs list and selection
    eq: bool                # serves the EQ page
    repeat: bool            # offers repeat/replay
    typed_refusals: bool    # a refusal carries its own appliance id and a typed error
    reports_mute: bool      # its status carries the mute flag
    warnings: bool = False  # serves the appliance-warnings endpoint
    eq_version: int = 0     # 0 = none, 1 = bass/treble, 2 = six bands
    outputs_version: int = 0  # 0 = none, 1 = the first outputs capability


@dataclass(frozen=True)
class LearnedCapabilities:
    version: str                  # the advertised version the fetch was made for
    capabilities: dict            # name -> version, as validated
    fetched_at: float


class _Registry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._learned: dict[str, LearnedCapabilities] = {}
        # appliance id -> (earliest next attempt, the backoff that produced it)
        self._failures: dict[str, tuple[float, float]] = {}

    def record(self, appliance_id: str, version: str, capabilities: dict, now: float) -> None:
        with self._lock:
            self._learned[appliance_id] = LearnedCapabilities(
                version=version, capabilities=dict(capabilities), fetched_at=now,
            )
            self._failures.pop(appliance_id, None)

    def learned(self, appliance_id: str) -> "LearnedCapabilities | None":
        with self._lock:
            return self._learned.get(appliance_id)

    def forget(self, appliance_id: str) -> None:
        with self._lock:
            self._learned.pop(appliance_id, None)
            self._failures.pop(appliance_id, None)

    def due(self, appliance_id: str, version: str, now: float) -> bool:
        """True when a fetch should be made: nothing is held for the version
        advertised and no failed attempt is still backing off."""
        with self._lock:
            held = self._learned.get(appliance_id)
            if held is not None and held.version == version:
                return False
            failure = self._failures.get(appliance_id)
            return failure is None or now >= failure[0]

    def note_failure(self, appliance_id: str, now: float) -> None:
        with self._lock:
            previous = self._failures.get(appliance_id)
            backoff = (
                CAPABILITIES_BACKOFF_INITIAL_S if previous is None
                else min(previous[1] * 2, CAPABILITIES_BACKOFF_MAX_S)
            )
            self._failures[appliance_id] = (now + backoff, backoff)

    def prune(self, known_ids) -> None:
        """Drop everything held for an appliance not in *known_ids*."""
        keep = set(known_ids)
        with self._lock:
            for table in (self._learned, self._failures):
                for appliance_id in [a for a in table if a not in keep]:
                    del table[appliance_id]

    def clear(self) -> None:
        with self._lock:
            self._learned.clear()
            self._failures.clear()


registry = _Registry()

record = registry.record
learned = registry.learned
forget = registry.forget
due = registry.due
note_failure = registry.note_failure
prune = registry.prune


def parse_capabilities_body(status, body, appliance_id: str) -> "dict[str, int] | None":
    """The capabilities of a GET /api/dial/capabilities reply: name -> version.

    *body* is the reply as received (bytes or text, parsed here under a size
    cap) or an already parsed object. None when the status is not 200, the
    reply is too large, is not JSON, is not an object, is not `ok`, names a
    different appliance than *appliance_id* or has no object of capabilities.
    Within it a name that is not lowercase letters and underscores, or a value
    that is not a non-negative integer, is dropped, and at most
    CAPABILITIES_MAX_ENTRIES are read. Never raises."""
    try:
        if status != 200 or not isinstance(appliance_id, str) or not appliance_id:
            return None
        if isinstance(body, (bytes, bytearray, str)):
            if len(body) > CAPABILITIES_MAX_BODY_BYTES:
                return None
            body = json.loads(body)
        if not isinstance(body, dict) or body.get("ok") is not True:
            return None
        if body.get("appliance_id") != appliance_id:
            return None
        entries = body.get("capabilities")
        if not isinstance(entries, dict):
            return None
        out: dict[str, int] = {}
        for name, value in list(entries.items())[:CAPABILITIES_MAX_ENTRIES]:
            if (
                isinstance(name, str) and _CAPABILITY_NAME_RE.fullmatch(name) is not None
                and isinstance(value, int) and not isinstance(value, bool) and value >= 0
            ):
                out[name] = value
        return out
    except Exception:
        return None


# ---- the switch point -----------------------------------------------------------


def _flag(value) -> int:
    return 1 if value else 0


def _txt_eq_version(target) -> int:
    return getattr(target, "dial_eq_version", 0) or _flag(getattr(target, "dial_eq", False))


def txt_capability_versions(target) -> dict:
    """name -> version for *target* from what its mDNS record advertises."""
    return {
        "dial_status": _flag(getattr(target, "dial_status", False)),
        "dial_outputs": _flag(getattr(target, "dial_outputs", False)),
        "dial_eq": _txt_eq_version(target),
        "repeat": _flag(getattr(target, "repeat_capable", False)),
        "dial_warnings": _flag(getattr(target, "dial_warnings", False)),
    }


def capability_versions(target) -> dict:
    """name -> version for *target*: what its capabilities endpoint said, when
    it is of a generation that has one and the reply for its advertised
    version has landed; else what its mDNS record says. An entry that carries
    no version (a playing record) matches the reply held for its id."""
    if getattr(target, "dial_proto_version", 0) >= CAPABILITIES_ENDPOINT_PROTO:
        held = learned(getattr(target, "appliance_id", ""))
        if held is not None:
            advertised = getattr(target, "version", "")
            if not advertised or advertised == held.version:
                return held.capabilities
    return txt_capability_versions(target)


def _capabilities_from(versions: dict, target) -> Capabilities:
    eq_version = versions.get("dial_eq", 0)
    outputs_version = versions.get("dial_outputs", 0)
    return Capabilities(
        status=versions.get("dial_status", 0) >= 1,
        outputs=outputs_version >= 1,
        eq=eq_version >= 1,
        repeat=versions.get("repeat", 0) >= 1,
        typed_refusals=bool(getattr(target, "typed_refusals", True)),
        reports_mute=bool(getattr(target, "status_reports_mute", True)),
        warnings=versions.get("dial_warnings", 0) >= 1,
        eq_version=eq_version,
        outputs_version=outputs_version,
    )


def txt_capabilities(target) -> Capabilities:
    """*target*'s capabilities from its mDNS record alone: no lock, no
    registry, for a caller that must not take the registry's lock."""
    return _capabilities_from(txt_capability_versions(target), target)


def appliance_capabilities(target) -> Capabilities:
    """The one place an appliance's capabilities are read from a roster or
    playing entry. Missing attributes (an entry type without the flag) read
    as the conservative value the callers always used."""
    return _capabilities_from(capability_versions(target), target)
