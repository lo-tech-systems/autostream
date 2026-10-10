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
everything in between is left untouched. The top band splits into the NAME
zone (left — the appliance name; tap to open the appliance selector) and
the volume cluster (speaker glyph + master-volume number, right — this is
also the MUTE zone). The bottom band splits into DOWN (left half) and UP
(right half). The artist name, relocated to a centre-low line just above
the bottom band, is a non-actuating label with no touch zone of its own.
All panels in dial_display_profiles.py are mounted landscape and this
layout does not depend on their aspect ratio, so no other layout is
defined.

DEAD ZONES: every boundary between two adjacent controls carries a small
inert band (the "dead zone") on each side, so an imprecise tap near a
boundary hits neither neighbour rather than the wrong one. Two such
boundaries exist: between the NAME zone and the volume cluster (a gap of
2*margin, the same width used between DOWN and UP), and between DOWN and UP
themselves. The middle half of the panel (the rows strictly between the top
and bottom bands, other than the artist label's own rect) is dead for a
different reason — it simply carries no control at all; `zone_at` returns
None there exactly as it does in a genuine dead-zone gap. The margin is 3px
at the 160x128 profile (the shipped panel) and scales with the panel's
short side using the same rule as dial_display_image._blur_radius_for —
margin = round(min(width, height) * 3 / 128) with a floor of 1px. This
keeps the dead-zone band feeling the same physical size across profiles
rather than shrinking to nothing on a big panel or ballooning on a small
one.

SURFACES: this module describes geometry for FOUR hit-test geometries
(GEOMETRY_MAIN, GEOMETRY_LIST, GEOMETRY_REPEAT, GEOMETRY_IDLE), never
mixed. Each geometry's tappable rectangles live in one ordered table —
`zone_rects_for(geometry, width, height)` — that both `hit_test()` below
and the compositor's pressed-zone wash read, so the two can never disagree
about where a boundary sits.

The MAIN geometry (`zone_at`/`zones_for`/`layout_for`) is the now-playing
screen: DOTS, NAME, MUTE, DOWN, UP, plus the non-actuating artist and
title labels. DOTS is carved from the left of the NAME zone (whose x0
therefore starts one band-height plus a 2*margin gap later than before);
it opens the repeat screen. The LIST geometry
(`list_zone_at`/`list_layout_for`) is the appliance list (also reused,
unchanged, for the replay picker): LIST_ROW (one per visible row),
LIST_BACK, LIST_DOWN and LIST_UP. The REPEAT geometry
(`repeat_zone_at`/`repeat_layout_for`) is the repeat screen: DOTS (reused,
pops back to main and reveals the main screen's volume overlay), NAME
(reused, opens the appliance selector), MUTE (the mute/volume readout,
toggles mute like the main screen), REPEAT_PLAY (the enable layout's
arm/disarm row), REPEAT_START, REPEAT_STOP. The IDLE geometry
(`idle_zone_at`/`idle_layout_for`) is the idle screen: IDLE_REPLAY,
covering the whole panel below the top band, expressed as a single rect
(`IdleLayout.replay`) like every other geometry's zones. A caller never
mixes geometries — which one to hit-test against is decided elsewhere
(dial_touch.TouchStateMachine.set_surface, which maps its own surface
strings onto these four geometries many-to-one) — but `hit_test()` and
every per-geometry wrapper are pure functions of (x, y, width, height) and
are the ONLY hit-test functions any state machine calls.

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
    """The touch zones across both surfaces (see the module docstring's
    SURFACES paragraph). Compares equal to its own string value, so callers
    may use TouchZone.MUTE or the literal "mute" interchangeably.

    MUTE, DOWN, UP, NAME, DOTS: the main (now-playing) surface. DOTS opens
    the repeat screen; it is carved from the left of the NAME zone.
    LIST_BACK, LIST_DOWN, LIST_UP, LIST_ROW: the selector/picker surface.
    REPEAT_PLAY, REPEAT_START, REPEAT_STOP: the repeat screen's own
    surface (plus DOTS and NAME, reused there from the main surface).
    IDLE_REPLAY: the idle-screen surface (the whole panel below the top
    band, when the idle affordance is showing).
    """

    MUTE = "mute"
    DOWN = "down"
    UP = "up"
    NAME = "name"
    DOTS = "dots"
    LIST_BACK = "list_back"
    LIST_DOWN = "list_down"
    LIST_UP = "list_up"
    LIST_ROW = "list_row"
    REPEAT_PLAY = "repeat_play"
    REPEAT_START = "repeat_start"
    REPEAT_STOP = "repeat_stop"
    IDLE_REPLAY = "idle_replay"


Rect = tuple[int, int, int, int]  # (x0, y0, x1, y1), x1/y1 exclusive


# Hit-test geometries. These name a geometry, not a screen: the touch layer
# maps its own surfaces onto them many-to-one (two surfaces share MAIN, two
# share LIST — see dial_touch.py's surface-to-geometry map).
GEOMETRY_MAIN = "main"
GEOMETRY_LIST = "list"
GEOMETRY_REPEAT = "repeat"
GEOMETRY_IDLE = "idle"
GEOMETRIES = (GEOMETRY_MAIN, GEOMETRY_LIST, GEOMETRY_REPEAT, GEOMETRY_IDLE)


@dataclass(frozen=True)
class ZoneRect:
    """One tappable rectangle on a geometry: the zone it resolves to, its
    rect in compose-space, and, for LIST_ROW only, the row index. Index is
    carried on the entry rather than encoded in the zone because only
    LIST_ROW ever has one, and the touch layer already reports (zone,
    index) as a pair."""

    zone: TouchZone
    rect: Rect
    index: int | None = None


def zone_rects_for(geometry: str, width: int, height: int) -> tuple[ZoneRect, ...]:
    """The ordered, tappable rectangles of *geometry* at this panel size —
    the single source both the hit-tests below and the compositor's
    pressed-zone wash read, so the two can never disagree about where a
    boundary sits. Order is hit-test order. Every rect here is a field of
    one of the *Layout dataclasses below; this function adds no geometry
    arithmetic of its own, only a view over them. Raises KeyError for an
    unknown geometry (a programming error, never a runtime input)."""
    return _GEOMETRY_BUILDERS[geometry](width, height)


def _main_zone_rects(width: int, height: int) -> tuple[ZoneRect, ...]:
    layout = layout_for(width, height)
    return (
        ZoneRect(TouchZone.DOTS, layout.dots),
        ZoneRect(TouchZone.NAME, layout.name),
        ZoneRect(TouchZone.MUTE, layout.volume_cluster),
        ZoneRect(TouchZone.DOWN, layout.down),
        ZoneRect(TouchZone.UP, layout.up),
    )


def _list_zone_rects(width: int, height: int) -> tuple[ZoneRect, ...]:
    layout = list_layout_for(width, height)
    return tuple(
        ZoneRect(TouchZone.LIST_ROW, rect, i) for i, rect in enumerate(layout.rows)
    ) + (
        ZoneRect(TouchZone.LIST_BACK, layout.back),
        ZoneRect(TouchZone.LIST_DOWN, layout.down),
        ZoneRect(TouchZone.LIST_UP, layout.up),
    )


def _repeat_zone_rects(width: int, height: int) -> tuple[ZoneRect, ...]:
    layout = repeat_layout_for(width, height)
    return (
        ZoneRect(TouchZone.DOTS, layout.dots),
        ZoneRect(TouchZone.NAME, layout.name),
        ZoneRect(TouchZone.MUTE, layout.volume_cluster),
        ZoneRect(TouchZone.REPEAT_PLAY, layout.row),
        ZoneRect(TouchZone.REPEAT_START, layout.start),
        ZoneRect(TouchZone.REPEAT_STOP, layout.stop),
    )


def _idle_zone_rects(width: int, height: int) -> tuple[ZoneRect, ...]:
    layout = idle_layout_for(width, height)
    return (ZoneRect(TouchZone.IDLE_REPLAY, layout.replay),)


_GEOMETRY_BUILDERS = {
    GEOMETRY_MAIN: _main_zone_rects,
    GEOMETRY_LIST: _list_zone_rects,
    GEOMETRY_REPEAT: _repeat_zone_rects,
    GEOMETRY_IDLE: _idle_zone_rects,
}


def hit_test(geometry: str, x: int, y: int, width: int, height: int) -> "ZoneRect | None":
    """The first table entry of *geometry* containing compose-space point
    (x, y), or None in a dead zone or outside the panel. The one hit-test
    loop every per-geometry wrapper below is built from."""
    for entry in zone_rects_for(geometry, width, height):
        x0, y0, x1, y1 = entry.rect
        if x0 <= x < x1 and y0 <= y < y1:
            return entry
    return None


@dataclass(frozen=True)
class OverlayLayout:
    """Full overlay geometry for one panel size — the single source of truth
    for both where the compositor dims/draws and where the touch zones sit.
    `dots`, `name`, `volume_cluster`, `down` and `up` are exactly the
    DOTS/NAME/MUTE/DOWN/UP zone rectangles zones_for() returns; `artist` and
    the two band rectangles have no corresponding TouchZone because they
    never actuate."""

    top_band: Rect        # full-width dim region, rows [0, band_h)
    bottom_band: Rect     # full-width dim region, rows [height-band_h, height)
    dots: Rect            # the two repeat-screen dots, left of the name (== DOTS zone)
    name: Rect            # appliance name, left part of top band (== NAME zone)
    artist: Rect          # centre-low text line, just above the bottom band (non-actuating)
    title: Rect           # track title line, directly above the artist line (non-actuating)
    volume_cluster: Rect  # glyph + number, right part of top band (== MUTE zone)
    down: Rect            # bottom band, left half (== DOWN zone)
    up: Rect              # bottom band, right half (== UP zone)
    divider_x: int        # x of the vertical divider centre in the bottom band


@dataclass(frozen=True)
class RepeatLayout:
    """Full repeat-screen geometry for one panel size. `dots`, `name` and
    `volume_cluster` are the identical rectangles OverlayLayout uses (same
    geometry as the main screen's top band): the dots and the name label
    stay tappable here (== the DOTS/NAME zones); the volume cluster is
    drawn but never hit-tested (the readout is display-only on this
    screen — see repeat_zone_at()). `row` is the full-width middle row
    used by the enable layout's "Repeat Play" toggle (== the REPEAT_PLAY
    zone); `line` shares that same rectangle for the replaying layout's
    centred "m:ss / m:ss" position text — only one of the two layouts is
    ever on screen at a time, so the two never actually compete for it.
    `start`/`stop` are exactly the DOWN/UP zone rectangles, relabelled
    Restart/Stop text glyphs for the replaying layout."""

    dots: Rect
    name: Rect
    volume_cluster: Rect
    row: Rect
    line: Rect
    start: Rect
    stop: Rect
    divider_x: int
    top_band: Rect
    bottom_band: Rect


@dataclass(frozen=True)
class IdleLayout:
    """Idle-screen geometry: a single non-actuating affordance line
    (reusing the same centre-low rect the main surface's artist line
    occupies — `affordance`), plus the actuating rect for the whole panel
    below the top band (`replay`, == the IDLE_REPLAY zone, resolved by
    idle_zone_at())."""

    affordance: Rect
    replay: Rect


@dataclass(frozen=True)
class ListLayout:
    """Full selector-screen geometry for one panel size — the single source
    of truth for both where the compositor draws the appliance list and
    where the selector's touch zones sit. `back`, `down` and `up` are
    exactly the LIST_BACK/LIST_DOWN/LIST_UP zone rectangles list_zone_at()
    resolves to; `rows` are the LIST_ROW rectangles for the CURRENT page,
    top to bottom, full width."""

    rows: tuple[Rect, ...]   # rows_per_page rectangles, full width, top to bottom
    bar: Rect                # bottom band (undivided) — back|down|up live here
    back: Rect               # bar, left third (== LIST_BACK zone)
    down: Rect               # bar, middle third (== LIST_DOWN zone)
    up: Rect                 # bar, right third (== LIST_UP zone)
    row_h: int
    rows_per_page: int


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
    below them is the "gap"); the name/cluster split and the down/up split
    each carry the usual dead-zone margins. The artist line sits centre-low,
    directly above the bottom band, with no dead-zone gap of its own (it
    never actuates, so there is nothing to protect it from). See the module
    docstring for the exact arithmetic and the pinned 160x128 reference
    numbers.
    """
    m = _dead_zone_margin(width, height)
    band_h = height // BAND_DIVISOR
    top_band: Rect = (0, 0, width, band_h)
    bottom_band: Rect = (0, height - band_h, width, height)

    cluster_w = width * CLUSTER_WIDTH_NUMERATOR // CLUSTER_WIDTH_DENOMINATOR
    # Inset by m on the left and bottom so the pressed wash never touches the
    # band edge or the name area.
    volume_cluster: Rect = (width - cluster_w + m, 0, width, band_h - m)
    # DOTS is carved from the left of the name zone, square with the band
    # height, followed by the same 2m dead-zone gap the name/cluster split
    # already used — so this is a pure subdivision of the old name rect,
    # not a size change to the overall top band.
    dots_w = band_h
    dots: Rect = (m, 0, m + dots_w, band_h)
    # The gap between the name zone and cluster is 2m, the same dead-zone
    # width used between DOWN and UP. This is the same rectangle the artist
    # text occupied before it moved centre-low.
    name: Rect = (m + dots_w + 2 * m, 0, width - cluster_w - m, band_h)

    # Centre-low line, just above the bottom band — half the band height,
    # inset by m on each side. Non-actuating: no TouchZone, no dead-zone gap.
    artist_h = band_h // 2
    artist: Rect = (m, height - band_h - artist_h, width - m, height - band_h)
    # Track title sits one line directly above the artist, same height.
    title: Rect = (m, height - band_h - 2 * artist_h, width - m, height - band_h - artist_h)

    (dx0, dx1), (ux0, ux1) = _split(width, m, [1, 1])
    by0 = height - band_h + m
    down: Rect = (dx0, by0, dx1, height)
    up: Rect = (ux0, by0, ux1, height)
    divider_x = (dx1 + ux0) // 2

    return OverlayLayout(
        top_band=top_band,
        bottom_band=bottom_band,
        dots=dots,
        name=name,
        artist=artist,
        title=title,
        volume_cluster=volume_cluster,
        down=down,
        up=up,
        divider_x=divider_x,
    )


def zones_for(width: int, height: int) -> dict[TouchZone, Rect]:
    """Return the ACTIVE (tappable) rectangle for each of the main-surface
    zones, already shrunk by the dead-zone margins, in compose-space.

    Rectangles are (x0, y0, x1, y1) with x1/y1 exclusive (Python slice /
    range convention), so a point p is inside iff x0 <= p.x < x1 and
    y0 <= p.y < y1. A view over the MAIN geometry's zone-rect table (see
    zone_rects_for) — same five keys in the same insertion order as before
    the table existed.
    """
    return {entry.zone: entry.rect for entry in zone_rects_for(GEOMETRY_MAIN, width, height)}


def zone_at(x: int, y: int, width: int, height: int) -> TouchZone | None:
    """Return the main-surface zone containing compose-space point (x, y),
    or None if the point falls in a dead zone or outside the panel
    entirely."""
    hit = hit_test(GEOMETRY_MAIN, x, y, width, height)
    return hit.zone if hit is not None else None


def list_layout_for(width: int, height: int) -> ListLayout:
    """Compute the full selector-screen geometry for a *width* x *height*
    panel: rows_per_page rows tiling [0, height - bar_h), full width, plus a
    bottom bar split three ways (back|down|up) with the usual dead-zone
    margins. Row height equals the bar height (never below 32px on any
    shipped profile), which is what makes rows_per_page exactly 3 on every
    profile listed in dial_display_profiles.py.
    """
    m = _dead_zone_margin(width, height)
    bar_h = height // BAND_DIVISOR
    row_h = bar_h
    rows_per_page = (height - bar_h) // row_h
    rows = tuple((0, i * row_h, width, (i + 1) * row_h) for i in range(rows_per_page))

    (bx0, bx1), (dx0, dx1), (ux0, ux1) = _split(width, m, [1, 1, 1])
    by0 = height - bar_h + m
    return ListLayout(
        rows=rows,
        bar=(0, height - bar_h, width, height),
        back=(bx0, by0, bx1, height),
        down=(dx0, by0, dx1, height),
        up=(ux0, by0, ux1, height),
        row_h=row_h,
        rows_per_page=rows_per_page,
    )


def list_zone_at(x: int, y: int, width: int, height: int) -> tuple[TouchZone, int | None] | None:
    """Return (zone, row_index) for the selector surface at compose-space
    point (x, y): (LIST_ROW, i) inside row i, (LIST_BACK/LIST_DOWN/LIST_UP,
    None) inside the bottom bar, or None in a dead zone or outside the
    panel. row_index is only ever set for LIST_ROW."""
    hit = hit_test(GEOMETRY_LIST, x, y, width, height)
    return (hit.zone, hit.index) if hit is not None else None


def repeat_layout_for(width: int, height: int) -> RepeatLayout:
    """Compute the repeat-screen geometry for a *width* x *height* panel.
    `row` is a full-width strip of height 2*band_h (64px at the reference
    160x128 profile), centred vertically between the top and bottom bands
    — it exactly fills the gap between them, so the enable layout's row
    and the replaying layout's position line always tile the panel with
    no gap against either band.
    """
    layout = layout_for(width, height)
    m = _dead_zone_margin(width, height)
    band_h = height // BAND_DIVISOR
    side = band_h * 2
    cy = height // 2
    row: Rect = (m, cy - side // 2, width - m, cy + side // 2)
    return RepeatLayout(
        dots=layout.dots,
        name=layout.name,
        volume_cluster=layout.volume_cluster,
        row=row,
        line=row,
        start=layout.down,
        stop=layout.up,
        divider_x=layout.divider_x,
        top_band=layout.top_band,
        bottom_band=layout.bottom_band,
    )


def repeat_zone_at(x: int, y: int, width: int, height: int) -> TouchZone | None:
    """Hit-test the repeat screen's surface: DOTS first (pops back to
    main), then NAME (opens the appliance selector), then MUTE (the
    mute/volume readout, toggles mute like the main screen), then the
    middle row (REPEAT_PLAY), then START, then STOP, else None (a dead
    zone). State-agnostic like every other hit-test here — the display
    decides whether a hit means anything in the CURRENT layout (REPEAT_PLAY
    is drawn only in the enable layout, START/STOP only in the replaying
    layout; see dial_display_compositor.compose_repeat)."""
    hit = hit_test(GEOMETRY_REPEAT, x, y, width, height)
    return hit.zone if hit is not None else None


def idle_layout_for(width: int, height: int) -> IdleLayout:
    """Compute the idle-screen geometry: the affordance line is the same
    centre-low rectangle the main surface's (non-actuating) artist line
    occupies; replay is the whole panel below the top band."""
    layout = layout_for(width, height)
    return IdleLayout(affordance=layout.artist, replay=(0, layout.top_band[3], width, height))


def idle_zone_at(x: int, y: int, width: int, height: int) -> TouchZone | None:
    """Return IDLE_REPLAY for any point below the top band, else None. The
    top band is excluded so an accidental brush up there — where the name
    and volume cluster live on the main surface — does nothing on it."""
    hit = hit_test(GEOMETRY_IDLE, x, y, width, height)
    return hit.zone if hit is not None else None
