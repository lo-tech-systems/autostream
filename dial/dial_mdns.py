"""dial_mdns.py — mDNS browser for _autostream-playing._tcp.

Scans for autostream appliances announcing _autostream-playing._tcp.  Only
entries that carry dial_api=v1 in their TXT record are tracked — earlier
appliances without this field are ignored.

IPv4 only.  Deduplication across interfaces is handled by the shared
MdnsBrowser, keyed by mDNS service name.  get_playing_targets() returns one
entry per service name for fan-out.

Transition logging (0→1 and N→0) is preserved here using callbacks, outside
the shared registry lock.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
import sys
import os
import threading
import time

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
    display_authorized: bool  = True


# Tracks whether we have ever seen a playing target — persists across
# avahi-browse restarts so that restart-cycle re-resolutions do not
# re-emit the 0→1 transition log.
_had_targets: bool = False

# Display-selection bookkeeping, keyed by mDNS service name. playing_since is
# tied to the service identity and survives IP/port refreshes; display_authorized
# is tied to the (service_name, ip, port) row and resets when the address/port
# changes, since that may be a different appliance instance.
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

    with _state_lock:
        prior = _target_state.get(svc_name)
        if prior is None:
            playing_since = time.monotonic()
            display_authorized = True
        else:
            playing_since = prior["playing_since"]
            if prior["ip"] == ip and prior["port"] == port:
                display_authorized = prior["display_authorized"]
            else:
                display_authorized = True
        _target_state[svc_name] = {
            "playing_since":      playing_since,
            "ip":                 ip,
            "port":               port,
            "display_authorized": display_authorized,
        }

    target = PlayingTarget(
        ip=ip,
        port=port,
        name=svc_name,
        dial_api=True,
        audio_status=(txt.get('audio_status') == 'v1'),
        dial_status=(txt.get('dial_status') == 'v1'),
        service_name=svc_name,
        playing_since=playing_since,
        display_authorized=display_authorized,
    )
    return (svc_name, target)


def _on_target_add(svc_name: str, target: PlayingTarget) -> None:
    global _had_targets
    if not _had_targets:
        _had_targets = True
        logging.info("playing target found: %s (%s)", svc_name, target.ip)


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
)


def get_playing_targets() -> list[PlayingTarget]:
    """Return one entry per mDNS service name — deduplicated across interfaces."""
    return list(_browser.get_snapshot().values())


def get_display_targets() -> list[PlayingTarget]:
    """Return currently visible playing targets, ordered for display-source selection.

    Sorted by oldest playing_since first, with stable name/ip/port tie-breaks.
    display_authorized reflects the latest mark_display_target_unauthorized()
    call for each row, even between mDNS resolve cycles.
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
                display_authorized=state["display_authorized"],
            ))
    targets.sort(key=lambda t: (t.playing_since, t.name, t.ip, t.port))
    return targets


def mark_display_target_unauthorized(target: PlayingTarget) -> None:
    """Mark the current (service_name, ip, port) row unauthorized for display polling.

    Ignored if the row has since disappeared or its address/port has changed —
    in that case a fresh instance may be a different appliance and deserves a
    new status attempt.
    """
    with _state_lock:
        state = _target_state.get(target.service_name)
        if state is None:
            return
        if state["ip"] != target.ip or state["port"] != target.port:
            return
        state["display_authorized"] = False


def start_playing_browser(
    shutdown_event: "threading.Event | None" = None,
) -> None:
    """Start the background mDNS browser for _autostream-playing._tcp.  Idempotent."""
    _browser.start(shutdown_event=shutdown_event)


def stop_playing_browser() -> None:
    """Stop the background mDNS browser for _autostream-playing._tcp.  Idempotent."""
    _browser.stop()
