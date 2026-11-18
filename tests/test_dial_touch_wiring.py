"""The touch wiring's zone table: one action per zone, and no zone dropped.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "dial"))

from dial_touch_layout import BELL_ZONES, CARD_BUTTON_ZONES, TouchZone
from dial_touch_wiring import TouchWiring


def _wiring():
    return TouchWiring(
        MagicMock(), MagicMock(), step=lambda: 3, confirm_presence=lambda: None,
        overlay_state=MagicMock(),
    )


def test_zone_table_has_no_duplicate_zone():
    zones = [zone for zone, _action in _wiring()._zone_action_pairs()]
    assert len(zones) == len(set(zones))


def test_zone_table_covers_the_chains_zones():
    explicit = {
        TouchZone.NAME, TouchZone.LIST_BACK, TouchZone.LIST_DOWN, TouchZone.LIST_UP,
        TouchZone.LIST_ROW, TouchZone.DOTS,
        TouchZone.EQ_BASS_DOWN, TouchZone.EQ_BASS_UP,
        TouchZone.EQ_TREBLE_DOWN, TouchZone.EQ_TREBLE_UP,
        TouchZone.REPEAT_PLAY, TouchZone.REPEAT_START, TouchZone.REPEAT_STOP,
        TouchZone.IDLE_REPLAY, TouchZone.IDLE_WIFI,
        TouchZone.OUTPUTS, TouchZone.OUTPUT_BACK, TouchZone.OUTPUT_TOGGLE,
        TouchZone.OUTPUT_UP, TouchZone.OUTPUT_DOWN, TouchZone.ARTWORK,
    }
    assert len(explicit) == 21
    assert set(_wiring()._zone_actions) == explicit | set(BELL_ZONES) | set(CARD_BUTTON_ZONES)
