"""dial_mdns.py — the appliances sighted on the network, for the volume
control and the operator socket.

The one mDNS browser the dial runs belongs to the peer registry
(autostream_peer_registry); this module is a thin layer over its sightings.
It turns each into a PlayingTarget, with what the core knows of
the appliance (whether it is playing and since when, and whether it takes this
dial's writes) read through the callable `attach` is given. Nothing here
browses, fetches or decides who is authorised.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from typing import Callable, Optional

# The dial deployment copies core modules into /opt/autostream/ at the same
# level as the dial package. In the repo they live in core/, which may or may
# not be on sys.path.
try:
    from autostream_protocol import PROTOCOL
except ImportError:
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "core")))
    from autostream_protocol import PROTOCOL  # noqa: E402

# What the dial believes about its access to an appliance: the same string as
# dial_core_state.AUTH_UNKNOWN, which imports this module.
_AUTH_UNKNOWN = "unknown"

# The mDNS service name prefix stripped by appliance_display_name().
_SERVICE_PREFIX = "autostream on "


@dataclass
class PlayingTarget:
    ip:                 str
    port:               int
    name:               str
    dial_api:           bool  = False
    audio_status:       bool  = False
    dial_status:        bool  = False
    dial_outputs:       bool  = False
    dial_eq:            bool  = False
    service_name:       str   = ""
    playing_since:      float = 0.0
    appliance_id:       str   = ""
    auth:               str   = _AUTH_UNKNOWN
    dial_proto_version: int   = 0
    dial_eq_version:    int   = 0

    @property
    def typed_refusals(self) -> bool:
        return self.dial_proto_version >= 2

    @property
    def status_reports_mute(self) -> bool:
        return self.dial_proto_version >= 2


# One appliance row with the fields the core's state helpers read.
@dataclass(frozen=True)
class RosterEntry:
    appliance_id:   str
    service_name:   str
    name:           str
    ip:             str
    port:           int
    playing:        bool
    repeat_capable: bool
    dial_api:       bool = True
    audio_status:   bool = False
    dial_status:    bool = True
    dial_outputs:   bool = False
    dial_eq:        bool = False
    auth:           str = _AUTH_UNKNOWN
    dial_proto_version: int = 0
    dial_eq_version: int = 0
    version: str = ""      # the advertised software version, "" when none is known

    @property
    def typed_refusals(self) -> bool:
        return self.dial_proto_version >= 2

    @property
    def status_reports_mute(self) -> bool:
        return self.dial_proto_version >= 2


_registry = None
_state_of: Optional[Callable] = None


def attach(registry, state_of: Optional[Callable] = None) -> None:
    """Read sightings from *registry*. *state_of(appliance_id)* returns the
    core's view of that appliance (anything with `playing`, `playing_since`
    and `auth`) or None; without it nothing counts as playing."""
    global _registry, _state_of
    _registry = registry
    _state_of = state_of


def _sightings() -> list:
    registry = _registry
    return list(registry.sightings().values()) if registry is not None else []


def _view(appliance_id: str):
    state_of = _state_of
    if state_of is None:
        return None
    try:
        return state_of(appliance_id)
    except Exception:
        return None


def _target(sighting, view) -> PlayingTarget:
    current = sighting.proto == PROTOCOL
    return PlayingTarget(
        ip=sighting.ip, port=sighting.port, name=sighting.service_name,
        dial_api=True, audio_status=current, dial_status=current, dial_outputs=current,
        dial_eq=current, service_name=sighting.service_name,
        playing_since=float(getattr(view, "playing_since", 0.0) or 0.0),
        appliance_id=sighting.id,
        auth=getattr(view, "auth", _AUTH_UNKNOWN),
        dial_proto_version=sighting.proto or 0,
        dial_eq_version=2 if current else 0,
    )


def get_display_targets() -> list[PlayingTarget]:
    """The playing appliances, ordered for display-source selection: oldest
    playing_since first, with stable name/ip/port tie-breaks."""
    targets = []
    for sighting in _sightings():
        view = _view(sighting.id)
        if view is not None and getattr(view, "playing", False):
            targets.append(_target(sighting, view))
    targets.sort(key=lambda t: (t.playing_since, t.name, t.ip, t.port))
    return targets


def get_playing_targets() -> list[PlayingTarget]:
    """One entry per playing appliance, for the fan-out."""
    return get_display_targets()


def _avahi_unescape(s: str) -> str:
    """Decode avahi-browse parsable-mode escapes. In -p output a byte is
    escaped as a backslash followed by its three-digit DECIMAL value (a
    space becomes \\032), and dot and backslash as \\. and \\\\. The service
    instance name therefore arrives as e.g. autostream\\032on\\032CD_Player."""
    out = re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1))), s)
    return out.replace("\\.", ".").replace("\\\\", "\\")


def appliance_display_name(service_name: str) -> str:
    """Hostname part of the mDNS service name, underscores shown as spaces.

    The name is unescaped first (see _avahi_unescape): avahi hands us the
    instance name with spaces escaped as \\032, so the "autostream on "
    prefix only matches after decoding.
    """
    name = _avahi_unescape(service_name)
    host = (
        name[len(_SERVICE_PREFIX):]
        if name.startswith(_SERVICE_PREFIX)
        else name
    )
    return host.replace("_", " ")
