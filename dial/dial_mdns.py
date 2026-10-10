"""dial_mdns.py — mDNS browser for _autostream-playing._tcp.

Scans for autostream appliances announcing _autostream-playing._tcp.  Only
entries that carry dial_api=v1 in their TXT record are tracked — earlier
appliances without this field are ignored.

IPv4 only.  Deduplication across interfaces is handled by the shared
MdnsBrowser, keyed by mDNS service name.  get_playing_targets() returns one
entry per service name for fan-out.

Transition logging (0→1 and N→0) is preserved here using callbacks, outside
the shared registry lock.

Identity is appliance_id, parsed from the TXT `id` record. Authorization
knowledge for that id lives entirely in dial_auth, and is stamped onto every
target this module returns as `auth` — this module never decides who is
authorized, it only carries the id and reports the current answer.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
import re
import sys
import os
import threading
import time

import dial_auth

# The dial deployment copies core modules into /opt/autostream/ at the same
# level as the dial package, so autostream_mdns is importable directly there.
# In the repo the module lives in core/, which may or may not be on sys.path.
try:
    from autostream_mdns import MdnsBrowser
except ImportError:
    _core = os.path.join(os.path.dirname(__file__), '..', 'core')
    sys.path.insert(0, os.path.abspath(_core))
    from autostream_mdns import MdnsBrowser

import dataclasses
from dataclasses import dataclass

_APPLIANCE_ID_RE = re.compile(r"^[0-9a-f]{20}$")

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
    service_name:       str   = ""
    playing_since:      float = 0.0
    appliance_id:       str   = ""
    auth:               str   = dial_auth.AUTH_UNKNOWN


# Tracks whether we have ever seen a playing target — persists across
# avahi-browse restarts so that restart-cycle re-resolutions do not
# re-emit the 0→1 transition log.
_had_targets: bool = False

# Display-selection bookkeeping, keyed by mDNS service name. playing_since is
# tied to the service identity and survives IP/port refreshes across resolve
# cycles. Authorization knowledge itself is NOT kept here — it lives in
# dial_auth, keyed by appliance_id, so it survives a service-name rename.
_state_lock: threading.Lock = threading.Lock()
_target_state: dict[str, dict] = {}


def _parse_playing_event(parts: list, txt: dict) -> tuple | None:
    """Parse a resolved _autostream-playing._tcp event.

    Returns (service_name, PlayingTarget) or None if the appliance lacks
    dial_api=v1 capability.
    """
    if txt.get('dial_api') != 'v1':
        return None
    try:
        port = int(parts[8])
    except (ValueError, IndexError):
        port = 80
    svc_name = parts[3]
    ip = parts[7]

    raw_id = txt.get('id', '')
    appliance_id = raw_id if _APPLIANCE_ID_RE.match(raw_id) else ""

    with _state_lock:
        prior = _target_state.get(svc_name)
        if prior is None:
            playing_since = time.monotonic()
        else:
            playing_since = prior["playing_since"]
        _target_state[svc_name] = {
            "playing_since":  playing_since,
            "ip":             ip,
            "port":           port,
            "appliance_id":   appliance_id,
        }

    # Outside _state_lock: dial_auth._lock is a leaf lock and must never be
    # nested with another lock.
    if appliance_id:
        dial_auth.auth_map.note_sighting(appliance_id, ip, port, time.monotonic())

    target = PlayingTarget(
        ip=ip,
        port=port,
        name=svc_name,
        dial_api=True,
        audio_status=(txt.get('audio_status') == 'v1'),
        dial_status=(txt.get('dial_status') == 'v1'),
        service_name=svc_name,
        playing_since=playing_since,
        appliance_id=appliance_id,
    )
    return (svc_name, target)


def _on_target_add(svc_name: str, target: PlayingTarget) -> None:
    global _had_targets
    if not _had_targets:
        _had_targets = True
        logging.info("playing target found: %s (%s)", svc_name, target.ip)


def _on_target_change(svc_name: str, old: PlayingTarget, new: PlayingTarget) -> None:
    """Log an address change. The auth reset for it already happened inside
    _parse_playing_event via note_sighting, which is the single place the
    (ip, port) pair is compared — this callback only logs."""
    if (old.ip, old.port) != (new.ip, new.port):
        logging.debug(
            "playing target address changed: %s %s:%s -> %s:%s",
            svc_name, old.ip, old.port, new.ip, new.port,
        )


def _on_target_remove(svc_name: str, target: PlayingTarget | None) -> None:
    with _state_lock:
        _target_state.pop(svc_name, None)
    snap = _browser.get_snapshot()
    if not snap:
        global _had_targets
        _had_targets = False
        logging.info("no playing targets — encoder gated")


_browser: MdnsBrowser = MdnsBrowser(
    service_type="_autostream-playing._tcp",
    parse_fn=_parse_playing_event,
    on_add=_on_target_add,
    on_remove=_on_target_remove,
    on_change=_on_target_change,
)


def _with_auth(target: PlayingTarget) -> PlayingTarget:
    """Stamp the current auth state for target.appliance_id.

    A raising map read must never gate control, so any failure degrades to
    unknown — the same as an appliance never seen before.
    """
    try:
        state = dial_auth.auth_map.state(target.appliance_id)
    except Exception:
        state = dial_auth.AUTH_UNKNOWN
    return dataclasses.replace(target, auth=state)


def get_playing_targets() -> list[PlayingTarget]:
    """Return one entry per mDNS service name — deduplicated across interfaces."""
    return [_with_auth(t) for t in _browser.get_snapshot().values()]


def get_display_targets() -> list[PlayingTarget]:
    """Return currently visible playing targets, ordered for display-source selection.

    Sorted by oldest playing_since first, with stable name/ip/port tie-breaks.
    """
    snapshot = _browser.get_snapshot()
    targets: list[PlayingTarget] = []
    with _state_lock:
        for svc_name, target in snapshot.items():
            state = _target_state.get(svc_name)
            if state is None:
                targets.append(target)
                continue
            targets.append(dataclasses.replace(
                target,
                playing_since=state["playing_since"],
            ))
    targets.sort(key=lambda t: (t.playing_since, t.name, t.ip, t.port))
    return [_with_auth(t) for t in targets]


def appliance_display_name(service_name: str) -> str:
    """Hostname part of the mDNS service name, underscores shown as spaces."""
    host = (
        service_name[len(_SERVICE_PREFIX):]
        if service_name.startswith(_SERVICE_PREFIX)
        else service_name
    )
    return host.replace("_", " ")


def start_playing_browser(
    shutdown_event: "threading.Event | None" = None,
) -> None:
    """Start the background mDNS browser for _autostream-playing._tcp.  Idempotent."""
    _browser.start(shutdown_event=shutdown_event)


def stop_playing_browser() -> None:
    """Stop the background mDNS browser for _autostream-playing._tcp.  Idempotent."""
    _browser.stop()
