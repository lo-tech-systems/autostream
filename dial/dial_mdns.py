"""dial_mdns.py — mDNS browser for _autostream-playing._tcp.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Stage 5 stub: scanner is not yet implemented.
  get_playing_targets() always returns [].
  start_playing_browser() is a no-op.

Full implementation is in Stage 6 (§8.2).
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PlayingTarget:
    ip:           str
    port:         int
    name:         str
    dial_api:     bool = False
    audio_status: bool = False


def get_playing_targets() -> list[PlayingTarget]:
    """Return currently known playing appliances.

    Stub: always returns an empty list until Stage 6 implementation.
    The dial will not send volume commands until Stage 6 is deployed.
    """
    return []


def start_playing_browser() -> None:
    """Start the background mDNS browser for _autostream-playing._tcp.

    Stub: no-op until Stage 6 implementation.
    """
    pass
