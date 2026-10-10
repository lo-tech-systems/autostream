"""dial_touch_layout.py — pure touch-zone geometry for the dial display.

This module computes the touch-zone rectangles (MUTE, DOWN, UP) and the
overlay band geometry for a given panel size, and answers hit-tests against
them. It has NO hardware imports and NO dependency on Pillow, the
compositor, or any I/O — it is arithmetic only, so it can be imported by
both:

  - the compositor (dial_display_compositor.py), to know where to draw the
    overlay bands, the artist text, the volume cluster and the zone glyphs,
    and
  - the touch session (dial_touch.py), to know which zone a raw touch
    coordinate landed in.

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

LAYOUT SELECTION: one band layout, used at every panel size — the layout is
aspect-independent, so there is no ratio threshold and no alternate shape to
select. The top and bottom `height // BAND_DIVISOR` rows are dimmed bands;
everything in between is left untouched. The top band splits into the
artist-name area (left, non-actuating) and the volume cluster (speaker
glyph + master-volume number, right — this is also the MUTE zone). The
bottom band splits into DOWN (left half) and UP (right half). All panels in
dial_display_profiles.py are mounted landscape and this layout does not
depend on their aspect ratio, so no other layout is defined.

DEAD ZONES: every boundary between two adjacent controls carries a small
inert band (the "dead zone") on each side, so an imprecise tap near a
boundary hits neither neighbour rather than the wrong one. Two such
boundaries exist: between the artist text area and the volume cluster (a
gap of 2*margin, the same width used between DOWN and UP), and between DOWN
and UP themselves. The middle half of the panel (the rows strictly between
the top and bottom bands) and the artist text area are dead for a different
reason — they simply carry no control at all; `zone_at` returns None there
exactly as it does in a genuine dead-zone gap. The margin is 3px at the
160x128 profile (the shipped panel) and scales with the panel's short side
using the same rule as dial_display_image._blur_radius_for — margin =
round(min(width, height) * 3 / 128) with a floor of 1px. This keeps the
dead-zone band feeling the same physical size across profiles rather than
shrinking to nothing on a big panel or ballooning on a small one.

REMAINDER POLICY: an active width does not always divide evenly between the
two zones sharing a split (DOWN and UP, after the dead-zone gap between
them is subtracted). _split computes each active zone's size with floor
division so all zones in a split are equal (or as equal as integer division
allows), then adds whatever pixels are left over into the LAST gap between
zones. Leftover pixels therefore always land in a dead zone, never in a
tappable rectangle. The union of the returned active zone rectangles plus
the implied dead-zone bands exactly tiles the panel with no gap and no
overlap.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

# Top and bottom bands each take this fraction of the panel height.
BAND_DIVISOR = 4
# The volume cluster (speaker glyph + number, the MUTE zone) takes this
# fraction of the panel width at the right of the top band.
CLUSTER_WIDTH_NUMERATOR = 2
CLUSTER_WIDTH_DENOMINATOR = 5

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


@dataclass(frozen=True)
class OverlayLayout:
    """Full overlay geometry for one panel size — the single source of truth
    for both where the compositor dims/draws and where the touch zones sit.
    `volume_cluster`, `down` and `up` are exactly the MUTE/DOWN/UP zone
    rectangles zones_for() returns; `artist` and the two band rectangles
    have no corresponding TouchZone because they never actuate."""

    top_band: Rect        # full-width dim region, rows [0, band_h)
    bottom_band: Rect     # full-width dim region, rows [height-band_h, height)
    artist: Rect          # text area, left part of top band (non-actuating)
    volume_cluster: Rect  # glyph + number, right part of top band (== MUTE zone)
    down: Rect            # bottom band, left half (== DOWN zone)
    up: Rect              # bottom band, right half (== UP zone)
    divider_x: int        # x of the vertical divider centre in the bottom band


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


def layout_for(width: int, height: int) -> OverlayLayout:
    """Compute the full overlay geometry for a *width* x *height* panel.

    m = _dead_zone_margin(width, height). Bands are a plain floor-divide of
    the panel height (no dead-zone gap of their own — the artwork above and
    below them is the "gap"); the artist/cluster split and the down/up split
    each carry the usual dead-zone margins. See the module docstring for the
    exact arithmetic and the pinned 160x128 reference numbers.
    """
    m = _dead_zone_margin(width, height)
    band_h = height // BAND_DIVISOR
    top_band: Rect = (0, 0, width, band_h)
    bottom_band: Rect = (0, height - band_h, width, height)

    cluster_w = width * CLUSTER_WIDTH_NUMERATOR // CLUSTER_WIDTH_DENOMINATOR
    # Inset by m on the left and bottom so the pressed wash never touches the
    # band edge or the artist area.
    volume_cluster: Rect = (width - cluster_w + m, 0, width, band_h - m)
    # The gap between artist and cluster is 2m, the same dead-zone width
    # used between DOWN and UP.
    artist: Rect = (m, 0, width - cluster_w - m, band_h)

    (dx0, dx1), (ux0, ux1) = _split(width, m, [1, 1])
    by0 = height - band_h + m
    down: Rect = (dx0, by0, dx1, height)
    up: Rect = (ux0, by0, ux1, height)
    divider_x = (dx1 + ux0) // 2

    return OverlayLayout(
        top_band=top_band,
        bottom_band=bottom_band,
        artist=artist,
        volume_cluster=volume_cluster,
        down=down,
        up=up,
        divider_x=divider_x,
    )


def zones_for(width: int, height: int) -> dict[TouchZone, Rect]:
    """Return the ACTIVE (tappable) rectangle for each of the three zones,
    already shrunk by the dead-zone margins, in compose-space.

    Rectangles are (x0, y0, x1, y1) with x1/y1 exclusive (Python slice /
    range convention), so a point p is inside iff x0 <= p.x < x1 and
    y0 <= p.y < y1. A thin wrapper over layout_for() — see OverlayLayout for
    the full geometry, including the non-actuating artist/band rectangles.
    """
    layout = layout_for(width, height)
    return {
        TouchZone.MUTE: layout.volume_cluster,
        TouchZone.DOWN: layout.down,
        TouchZone.UP: layout.up,
    }


def zone_at(x: int, y: int, width: int, height: int) -> TouchZone | None:
    """Return the zone containing compose-space point (x, y), or None if the
    point falls in a dead zone or outside the panel entirely."""
    for zone, (x0, y0, x1, y1) in zones_for(width, height).items():
        if x0 <= x < x1 and y0 <= y < y1:
            return zone
    return None
