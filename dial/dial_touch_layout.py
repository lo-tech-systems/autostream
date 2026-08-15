"""dial_touch_layout.py — pure touch-zone geometry for the dial display.

This module computes the three touch-zone rectangles (MUTE, DOWN, UP) for a
given panel size, and answers hit-tests against them. It has NO hardware
imports and NO dependency on Pillow, the compositor, or any I/O — it is
arithmetic only, so it can be imported by both:

  - the compositor (dial_display_compositor.py), to know where to draw the
    zone glyphs, and
  - the future touch session, to know which zone a raw touch coordinate
    landed in.

Both consumers MUST share this single source of truth for the geometry —
that is the entire reason this lives in its own module rather than being
duplicated. If the two ever disagreed about where a boundary sits, a user
could see one zone highlighted while a different zone actually responds to
the press.

COORDINATE SPACE: every function here works in COMPOSE-space — the same
(width, height) landscape space the compositor draws in, before the
rotate/BGR transforms in DialDisplayCompositor.compose() are applied. A
caller that receives raw touch coordinates from a rotated physical panel
must map them into compose-space (undo the rotation) before calling
zone_at(). This module knows nothing about rotation, panel drivers, or
physical mounting.

LAYOUT SELECTION: chosen purely from the aspect ratio width/height, with a
threshold just above 16:9:
  - WIDE   (width/height >= 1.8): vertical thirds, left-to-right —
           MUTE | DOWN | UP. Each zone spans the full panel height.
  - SQUARE (width/height <  1.8): top third is MUTE (full width); the
           bottom two-thirds is split left/right into DOWN | UP.
All panels in dial_display_profiles.py are mounted landscape, and these are
the only two shapes that occur across the profile table, so no other layout
is defined.

The threshold sits above 16:9 because the square layout reads better on
real hardware at these sizes — a full-width mute band with the two volume
controls beneath it gives each target more area than three narrow columns
do. Every profile in the current table is between 1.0 and 1.33, so they all
select SQUARE; the WIDE branch is kept for panels wider than 16:9, which
none of the shipped profiles are.

DEAD ZONES: every boundary between two zones carries a small inert band
(the "dead zone") on each side, so an imprecise tap near a boundary hits
neither neighbour rather than the wrong one. The margin is 3px at the
160x128 profile (the shipped panel) and scales with the panel's short side
using the same rule as dial_display_image._blur_radius_for — margin =
round(min(width, height) * 3 / 128) with a floor of 1px. This keeps the
dead-zone band feeling the same physical size across profiles rather than
shrinking to nothing on a big panel or ballooning on a small one.

REMAINDER POLICY: thirds do not divide the panel evenly (160/3, 320/3,
128/3 all leave 1-2px over). Every split below computes each active zone's
size with floor division so all zones in a split are equal (or as equal as
integer division allows), then adds whatever pixels are left over into the
LAST gap between zones. Leftover pixels therefore always land in a dead
zone, never in a tappable rectangle. The union of the returned active zone
rectangles plus the implied dead-zone bands exactly tiles the panel with no
gap and no overlap.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

from enum import Enum

# width/height at or above this ratio selects the WIDE (vertical thirds)
# layout; below it selects the SQUARE (top third + bottom split) layout.
# Set just above 16:9 so everything up to and including a 16:9 panel gets
# the square layout — see LAYOUT SELECTION in the module docstring.
WIDE_ASPECT_THRESHOLD = 1.8

# Dead-zone margin (pixels either side of a boundary) at the reference
# 160x128 profile. See module docstring for the scaling rule applied by
# _dead_zone_margin() for other panel sizes.
_REFERENCE_MARGIN_PX = 3
_REFERENCE_SHORT_SIDE = 128


class TouchZone(str, Enum):
    """The three touch zones. Compares equal to its own string value, so
    callers may use TouchZone.MUTE or the literal "mute" interchangeably."""

    MUTE = "mute"
    DOWN = "down"
    UP = "up"


Rect = tuple[int, int, int, int]  # (x0, y0, x1, y1), x1/y1 exclusive


def _dead_zone_margin(width: int, height: int) -> int:
    """Dead-zone margin in pixels, scaled from the 160x128 reference by the
    panel's short side (min(width, height)) — the same scaling axis used by
    dial_display_image._blur_radius_for, for the same reason: it keeps the
    band's apparent physical size consistent whether the panel is "wide"
    (160x128, 320x240) or "tall-ish" (128x128, 240x240) shaped. Returns
    exactly 3 at 160x128, by construction. Floored at 1px so degenerately
    tiny panels never lose their dead zones entirely.
    """
    return max(1, round(min(width, height) * _REFERENCE_MARGIN_PX / _REFERENCE_SHORT_SIDE))


def _split(total: int, margin: int, weights: list[int]) -> list[tuple[int, int]]:
    """Partition [0, total) into len(weights) active bands separated by
    len(weights)-1 dead-zone gaps of width 2*margin, sized proportionally to
    *weights*, with any leftover pixels (from integer-division remainders)
    folded into the final gap rather than into a band.

    Returns the active band (start, end) pairs in order — the gaps
    themselves are implied by the space between consecutive returned bands
    (and are not returned, since callers only need the tappable rectangles).
    """
    n = len(weights)
    gap_width = 2 * margin
    total_zone_width = total - (n - 1) * gap_width
    weight_sum = sum(weights)

    bases = [total_zone_width * w // weight_sum for w in weights]
    remainder = total_zone_width - sum(bases)

    bands: list[tuple[int, int]] = []
    cursor = 0
    for i, base in enumerate(bases):
        start = cursor
        end = cursor + base
        bands.append((start, end))
        cursor = end
        if i < n - 1:
            gap = gap_width + (remainder if i == n - 2 else 0)
            cursor += gap
    return bands


def zones_for(width: int, height: int) -> dict[TouchZone, Rect]:
    """Return the ACTIVE (tappable) rectangle for each of the three zones,
    already shrunk by the dead-zone margins, in compose-space.

    Rectangles are (x0, y0, x1, y1) with x1/y1 exclusive (Python slice /
    range convention), so a point p is inside iff x0 <= p.x < x1 and
    y0 <= p.y < y1.
    """
    margin = _dead_zone_margin(width, height)
    ratio = width / height

    if ratio >= WIDE_ASPECT_THRESHOLD:
        # WIDE: vertical thirds, full height, left-to-right MUTE|DOWN|UP.
        (mx0, mx1), (dx0, dx1), (ux0, ux1) = _split(width, margin, [1, 1, 1])
        return {
            TouchZone.MUTE: (mx0, 0, mx1, height),
            TouchZone.DOWN: (dx0, 0, dx1, height),
            TouchZone.UP: (ux0, 0, ux1, height),
        }

    # SQUARE: top third (full width) is MUTE; bottom two-thirds splits into
    # DOWN (left) and UP (right). The vertical split uses weights [1, 2] so
    # the top band gets one third of the active height and the bottom band
    # two thirds, matching the layout spec (not two equal halves).
    (ty0, ty1), (by0, by1) = _split(height, margin, [1, 2])
    (dx0, dx1), (ux0, ux1) = _split(width, margin, [1, 1])
    return {
        TouchZone.MUTE: (0, ty0, width, ty1),
        TouchZone.DOWN: (dx0, by0, dx1, by1),
        TouchZone.UP: (ux0, by0, ux1, by1),
    }


def zone_at(x: int, y: int, width: int, height: int) -> TouchZone | None:
    """Return the zone containing compose-space point (x, y), or None if the
    point falls in a dead zone or outside the panel entirely."""
    for zone, (x0, y0, x1, y1) in zones_for(width, height).items():
        if x0 <= x < x1 and y0 <= y < y1:
            return zone
    return None
