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

# The dial deployment copies core modules into /opt/autostream/ at the same
# level as the dial package, so autostream_mdns is importable directly there.
# In the repo the module lives in core/, which may or may not be on sys.path.
try:
    from autostream_mdns import MdnsBrowser
except ImportError:
    _core = os.path.join(os.path.dirname(__file__), '..', 'core')
    sys.path.insert(0, os.path.abspath(_core))
    from autostream_mdns import MdnsBrowser

from dataclasses import dataclass


@dataclass
class PlayingTarget:
    ip:           str
    port:         int
    name:         str
    dial_api:     bool = False
    audio_status: bool = False
    dial_status:  bool = False


# Tracks whether we have ever seen a playing target — persists across
# avahi-browse restarts so that restart-cycle re-resolutions do not
# re-emit the 0→1 transition log.
_had_targets: bool = False


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
    target = PlayingTarget(
        ip=parts[7],
        port=port,
        name=svc_name,
        dial_api=True,
        audio_status=(txt.get('audio_status') == 'v1'),
        dial_status=(txt.get('dial_status') == 'v1'),
    )
    return (svc_name, target)


def _on_target_add(svc_name: str, target: PlayingTarget) -> None:
    global _had_targets
    if not _had_targets:
        _had_targets = True
        logging.info("playing target found: %s (%s)", svc_name, target.ip)


def _on_target_remove(svc_name: str, target: PlayingTarget | None) -> None:
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


def start_playing_browser() -> None:
    """Start the background mDNS browser for _autostream-playing._tcp.  Idempotent."""
    _browser.start()
