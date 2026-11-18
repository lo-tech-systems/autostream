"""dial_touch_surfaces.py -- the surfaces the display reports and the touch
source acts on.

The display's touch_surface() names the screen the touch side should hit-test
against, with the four flags that say which chrome is live; the touch side
reads it once per loop. This module holds those names and the five-field
state, so neither side imports the other.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

from typing import NamedTuple

# Surfaces set_surface()/TouchEventSource understand — see the module
# docstring's SURFACES paragraph.
SURFACE_HIDDEN = "hidden"
SURFACE_HELD = "held"
SURFACE_SELECTOR = "selector"
# The repeat, idle and picker surfaces. All three behave as
# "held" exactly like SURFACE_SELECTOR: a press arms immediately, there is
# no reveal step and no dismiss clock — see set_surface() and _arm() below.
SURFACE_REPEAT = "repeat"
SURFACE_IDLE = "idle"
SURFACE_PICKER = "picker"
# The outputs list and per-output detail surfaces. Both behave as "held"
# exactly like SURFACE_SELECTOR/SURFACE_PICKER — see set_surface() below.
SURFACE_OUTPUTS = "outputs"
SURFACE_OUTPUT = "output"
# The compact tier's own repeat-replaying surface — reported by the
# display's touch_surface() in place of SURFACE_REPEAT exactly while that
# tier's replaying layout (time/back, Restart/Stop) is the one actually
# painted; every other tier never reports it (see ScreenPolicy.
# replay_surface). Held like every other non-hidden surface — see
# set_surface() below.
SURFACE_REPEAT_REPLAY = "repeat_replay"
# The idle screen's own read-only info page: held like every other list
# surface (a press arms immediately, no reveal step). Off the compact tier
# its own geometry (GEOMETRY_INFO) carries no LIST_ROW entries at all — a
# tap on a row lands in no zone; on the compact tier the rows ARE tappable,
# opening the field's own value view below.
SURFACE_INFO = "info"
# The compact info page's own drill-in — a tapped field's own full-screen
# value. Held like every other list surface; its geometry (GEOMETRY_INFO_
# VALUE) is a single whole-panel LIST_BACK entry, so any press anywhere
# reports the same zone-tap back to the list.
SURFACE_INFO_VALUE = "info_value"
# The EQ page: rich/large only, reached via the page dots. Held like every
# other secondary surface; hit-tests use the GEOMETRY_EQ table (DOTS/NAME/
# OUTPUTS reused from the main geometry, plus the bass/treble bar steppers).
SURFACE_EQ = "eq"
# A warning or status card: held like every other secondary surface; its
# geometry is the one for its button count (GEOMETRY_CARD1/2/3).
SURFACE_CARD1 = "card1"
SURFACE_CARD2 = "card2"
SURFACE_CARD3 = "card3"
# The "Restarting..." screen: held (so the touch side treats it as a
# visible surface, not a reveal-on-touch one) but with an EMPTY geometry —
# no press anywhere can arm anything until the reboot takes the panel down.
SURFACE_RESTARTING = "restarting"
# The software update progress card has no buttons (empty geometry, so
# touch does nothing); the result card is a one-button card.
SURFACE_UPDATE = "update"


class SurfaceState(NamedTuple):
    """What the display reports each poll: the surface, and whether the
    appliance name, the page dots, the outputs readout and the warning bell
    are live on it."""
    surface: str
    name_active: bool
    dots_active: bool
    outputs_active: bool
    bell_active: bool
