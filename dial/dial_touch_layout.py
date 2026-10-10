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
from math import ceil

# Top and bottom bands each take this fraction of the panel height.
BAND_DIVISOR = 4
# The volume cluster (speaker glyph + number, the MUTE zone) takes this
# fraction of the panel width at the right of the top band.
CLUSTER_WIDTH_NUMERATOR = 2
CLUSTER_WIDTH_DENOMINATOR = 5

# ---------------------------------------------------------------------------
# Physical-size metrics: one scale rule, and one LayoutMetrics bundle every
# size-dependent number in the dial is read from. Physical size (mm_per_px)
# is optional — every caller that omits it gets exactly today's geometry,
# unaware of density (see metrics_for()'s tier fallback below).
# ---------------------------------------------------------------------------

REFERENCE_SHORT_SIDE = 128  # the 160x128 reference panel's short side


def scale_px(reference_px: int, width: int, height: int, floor: int) -> int:
    """Scale a pixel quantity defined at the 160x128 reference by the
    panel's short side, floored. The one rule every size-dependent pixel
    count in the dial derives from."""
    return max(floor, round(min(width, height) * reference_px / REFERENCE_SHORT_SIDE))


# Content tiers, decided by metrics_for() from the panel's logical pixel
# size (its short side) rather than its physical size: a panel's pixel
# count is what decides whether there is room to lay out more than a dot-
# matrix's worth of chrome, independent of how physically large those
# pixels are. Physical size (mm_per_px) still gates two things: an unknown
# density never guesses a richer layout (falls back to base), and a panel
# whose quarter-height band would be too short to hold a floor-sized touch
# target vetoes a richer tier back to base unless the size was chosen
# deliberately rather than picked automatically (see metrics_for()).
CONTENT_BASE = "base"
CONTENT_RICH = "rich"
CONTENT_LARGE = "large"
_CONTENT_TIERS = (CONTENT_BASE, CONTENT_RICH, CONTENT_LARGE)

RICH_MIN_SHORT_SIDE_PX = 200   # logical short side at/above which the rich tier applies
LARGE_MIN_SHORT_SIDE_PX = 400  # logical short side at/above which the large tier applies

TOUCH_MIN_MM = 8.0                # fingertip floor, resistive and capacitive alike
TOUCH_SHORT_BELOW_BAND_MM = 6.0   # a quarter-height band shorter than this cannot hold a floor-sized control
BAND_MAX_MM = 12.0                # on rich/large panels, chrome stops growing past this physical band height

# Glyph supersample factor fed to _draw_glyph() in dial_display_compositor —
# carried here because it is a property of the content tier, decided
# alongside every other tier-derived quantity. SUPERSAMPLE_DEFAULT is what
# every screen has always used; on the large tier the panel's own pixel
# density means a smaller supersample factor is already antialiased enough.
SUPERSAMPLE_DEFAULT = 4
SUPERSAMPLE_LARGE = 2

# Reference pixel quantities at 160x128 (short side 128) and their floors —
# (reference_px, floor) pairs fed to scale_px() by metrics_for() below.
MARGIN_PX_AT_REFERENCE = (3, 1)
DIVIDER_PX_AT_REFERENCE = (1, 1)
BLUR_RADIUS_AT_REFERENCE = (10, 0)
FONT_BODY_PX_AT_REFERENCE = (13, 8)
FONT_READOUT_PX_AT_REFERENCE = (15, 9)
PAD_PX_AT_REFERENCE = (4, 2)
ICON_GAP_PX_AT_REFERENCE = (3, 2)
HALO_STROKE_PX_AT_REFERENCE = (2, 1)
HALO_BLUR_PX_AT_REFERENCE = (2, 1)

# On the large content tier the scaled text, icon and halo stop growing past
# these pixel sizes: a panel with many times the pixels should carry more
# content, not the same content at a much bigger glyph size. Padding,
# margins, dividers and the artwork blur keep scaling linearly — they are
# about proportion, not legibility.
FONT_BODY_MAX_PX = 36
FONT_READOUT_MAX_PX = 44
HALO_MAX_PX = 3

# Text on the rich and large tiers scales from the large tier's own
# reference (36/44 px on a 480 px short side) rather than from the 160x128
# base, so a rich panel reads with the large tier's own proportions instead
# of base's own numbers scaled up; the large-tier caps above then coincide
# with this reference at short side 480.
FONT_BODY_PX_AT_LARGE_REFERENCE = (36, 480)
FONT_READOUT_PX_AT_LARGE_REFERENCE = (44, 480)
# Header and footer bands on the rich and large tiers take a fifth of the
# height (a quarter on base), still capped physically by BAND_MAX_MM.
BAND_DIVISOR_RICH = 5
# Floor for the rich/large list's right-hand rail column — a computed
# icon-plus-padding width can undercut a safe touch column on a dense rich
# panel; this keeps the rail no thinner than this regardless.
RAIL_W_MIN_PX = 46


@dataclass(frozen=True)
class LayoutMetrics:
    """Every size-dependent number the overlay/list/repeat/idle layouts and
    the compositor need, computed once per compose from a panel size and
    (optionally) its physical density. Passing metrics=None anywhere one of
    these is accepted is exactly equivalent to metrics_for(width, height) —
    today's base-tier, density-unaware geometry."""

    width: int
    height: int
    mm_per_px: float | None      # None: physical size unknown (tests, bare callers)
    content_tier: str            # CONTENT_BASE | CONTENT_RICH | CONTENT_LARGE
    band_mm: float | None        # (height // 4) * mm_per_px, one of the tier inputs
    touch_min_px: int | None     # ceil(TOUCH_MIN_MM / mm_per_px)
    touch_short: bool            # band_mm known and below TOUCH_SHORT_BELOW_BAND_MM
    list_rail: bool              # the list uses the right rail (rich/large) rather than the bottom bar
    has_album_line: bool         # the now-playing body carries an album line above the title (large tier)
    supersample: int             # glyph tile supersample factor (see _draw_glyph in the compositor)
    margin: int                  # dead-zone margin
    band_h: int                  # header/footer height
    row_h: int                   # list row height
    rows_per_page: int
    divider_w: int
    blur_radius: int             # artwork backdrop blur
    font_body: int               # name, artist/title, list rows, repeat row label
    font_readout: int            # volume digits, repeat line, Restart/Stop
    icon: int                    # speaker glyph box (same reference as font_readout)
    pad: int
    icon_gap: int
    halo_stroke: int
    halo_blur: int
    rail_w: int                  # right-rail column width (rich/large only; 0 on base)
    rail_glyph: int              # rail glyph box side, centred within its zone (0 on base)


def metrics_for(
    width: int, height: int, mm_per_px: float | None = None, *, size_chosen: bool = False,
) -> LayoutMetrics:
    """Compute every size-dependent quantity for a *width* x *height* panel.

    The content tier follows the panel's logical pixel size (its short
    side): CONTENT_BASE below RICH_MIN_SHORT_SIDE_PX, CONTENT_RICH from
    there up to LARGE_MIN_SHORT_SIDE_PX, CONTENT_LARGE above that. Physical
    size (mm_per_px) can only ever pull a panel back down to base, never
    push it up: mm_per_px=None ("physical size unknown") always resolves to
    base, and a panel whose quarter-height band is physically too short to
    hold a floor-sized touch target (touch_short) is vetoed back to base
    too — unless *size_chosen* is True, meaning the logical size was picked
    deliberately (a settings override) rather than resolved automatically,
    in which case the veto does not apply but touch_short is still reported
    so the caller can warn about it.

    mm_per_px=None also means every pixel quantity is computed exactly as it
    always was (the base-tier formulas), so every existing caller that never
    passes a density is completely unaffected by any of this.
    """
    short = min(width, height)
    quarter = height // BAND_DIVISOR
    band_mm = quarter * mm_per_px if mm_per_px is not None else None
    touch_short = band_mm is not None and band_mm < TOUCH_SHORT_BELOW_BAND_MM

    if short >= LARGE_MIN_SHORT_SIDE_PX:
        content_tier = CONTENT_LARGE
    elif short >= RICH_MIN_SHORT_SIDE_PX:
        content_tier = CONTENT_RICH
    else:
        content_tier = CONTENT_BASE
    if content_tier != CONTENT_BASE and mm_per_px is None:
        content_tier = CONTENT_BASE           # density unknown: never guess a richer layout
    if content_tier != CONTENT_BASE and touch_short and not size_chosen:
        content_tier = CONTENT_BASE           # the veto: automatic tiering only

    touch_min_px = ceil(TOUCH_MIN_MM / mm_per_px) if mm_per_px else None
    has_album_line = content_tier == CONTENT_LARGE

    if content_tier == CONTENT_BASE:
        band_h = quarter
        row_h = band_h
        rows_per_page = (height - band_h) // row_h    # today's formula, unchanged
        list_rail = False
        supersample = SUPERSAMPLE_DEFAULT
    else:
        # On a wider panel the chrome bands stop growing physically past
        # BAND_MAX_MM — past that point extra height buys nothing but empty
        # chrome — and the list drops its bottom bar for a right-hand rail,
        # so its rows fill the whole panel height instead of leaving room
        # for one. The header/footer bands take a fifth of the height here
        # (a quarter on base), still capped by BAND_MAX_MM.
        band_h = min(height // BAND_DIVISOR_RICH, ceil(BAND_MAX_MM / mm_per_px))
        rows_per_page = height // band_h
        row_h = height // rows_per_page               # rows tile the height exactly
        list_rail = True
        supersample = SUPERSAMPLE_LARGE if content_tier == CONTENT_LARGE else SUPERSAMPLE_DEFAULT

    if content_tier == CONTENT_BASE:
        font_body = scale_px(FONT_BODY_PX_AT_REFERENCE[0], width, height, FONT_BODY_PX_AT_REFERENCE[1])
        font_readout = scale_px(FONT_READOUT_PX_AT_REFERENCE[0], width, height, FONT_READOUT_PX_AT_REFERENCE[1])
    else:
        # The rich and large tiers scale text from the large tier's own
        # reference (36/44px on a 480px short side) instead of the 160x128
        # base scaled up, so a rich panel reads with the large tier's own
        # proportions rather than a blown-up base one — the large tier's
        # own caps below then coincide with this reference at short side
        # 480.
        font_body = round(short * FONT_BODY_PX_AT_LARGE_REFERENCE[0] / FONT_BODY_PX_AT_LARGE_REFERENCE[1])
        font_readout = round(short * FONT_READOUT_PX_AT_LARGE_REFERENCE[0] / FONT_READOUT_PX_AT_LARGE_REFERENCE[1])
    icon = font_readout
    pad = scale_px(PAD_PX_AT_REFERENCE[0], width, height, PAD_PX_AT_REFERENCE[1])
    halo_stroke = scale_px(HALO_STROKE_PX_AT_REFERENCE[0], width, height, HALO_STROKE_PX_AT_REFERENCE[1])
    halo_blur = scale_px(HALO_BLUR_PX_AT_REFERENCE[0], width, height, HALO_BLUR_PX_AT_REFERENCE[1])
    if content_tier != CONTENT_BASE:
        # The halo is a fine screen-space stroke — physical scale keeps it
        # from ballooning into a blur on a bigger panel.
        halo_stroke = min(halo_stroke, HALO_MAX_PX)
        halo_blur = min(halo_blur, HALO_MAX_PX)
    if content_tier == CONTENT_LARGE:
        # More room buys more content, not bigger glyphs past a legible size.
        font_body = min(font_body, FONT_BODY_MAX_PX)
        font_readout = min(font_readout, FONT_READOUT_MAX_PX)
        icon = min(icon, FONT_READOUT_MAX_PX)

    if content_tier == CONTENT_BASE:
        rail_w = 0
        rail_glyph = 0
    else:
        rail_glyph = icon
        # icon plus its own pad on each side, floored at a fixed minimum —
        # a computed value can undercut the touch floor on a dense rich
        # panel (the owner's call: a thinner rail than the header/footer
        # bands, but never thinner than this).
        rail_w = max(icon + 2 * pad, RAIL_W_MIN_PX)

    return LayoutMetrics(
        width=width, height=height, mm_per_px=mm_per_px, content_tier=content_tier,
        band_mm=band_mm, touch_min_px=touch_min_px, touch_short=touch_short,
        list_rail=list_rail, has_album_line=has_album_line, supersample=supersample,
        margin=scale_px(MARGIN_PX_AT_REFERENCE[0], width, height, MARGIN_PX_AT_REFERENCE[1]),
        band_h=band_h, row_h=row_h, rows_per_page=rows_per_page,
        divider_w=scale_px(DIVIDER_PX_AT_REFERENCE[0], width, height, DIVIDER_PX_AT_REFERENCE[1]),
        blur_radius=scale_px(BLUR_RADIUS_AT_REFERENCE[0], width, height, BLUR_RADIUS_AT_REFERENCE[1]),
        font_body=font_body, font_readout=font_readout, icon=icon,
        pad=pad,
        icon_gap=scale_px(ICON_GAP_PX_AT_REFERENCE[0], width, height, ICON_GAP_PX_AT_REFERENCE[1]),
        halo_stroke=halo_stroke, halo_blur=halo_blur,
        rail_w=rail_w, rail_glyph=rail_glyph,
    )


class TouchZone(str, Enum):
    """The touch zones across both surfaces (see the module docstring's
    SURFACES paragraph). Compares equal to its own string value, so callers
    may use TouchZone.MUTE or the literal "mute" interchangeably.

    OUTPUTS, MUTE, DOWN, UP, NAME, DOTS: the main (now-playing) surface.
    DOTS opens the repeat screen; it is carved from the left of the NAME
    zone. OUTPUTS is the top-right volume-cluster readout, opening the
    outputs list; MUTE is the footer's own cell (see FOOTER_VOLUME_MUTE in
    the compositor).
    LIST_BACK, LIST_DOWN, LIST_UP, LIST_ROW: the selector/picker surface,
    also reused by the outputs list.
    REPEAT_PLAY, REPEAT_START, REPEAT_STOP: the repeat screen's own
    surface (plus DOTS and NAME, reused there from the main surface).
    OUTPUT_BACK, OUTPUT_TOGGLE, OUTPUT_UP, OUTPUT_DOWN: the per-output
    detail surface (plus NAME, reused from the main surface).
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
    OUTPUTS = "outputs"
    OUTPUT_BACK = "output_back"
    OUTPUT_TOGGLE = "output_toggle"
    OUTPUT_UP = "output_up"
    OUTPUT_DOWN = "output_down"


Rect = tuple[int, int, int, int]  # (x0, y0, x1, y1), x1/y1 exclusive


# Hit-test geometries. These name a geometry, not a screen: the touch layer
# maps its own surfaces onto them many-to-one (two surfaces share MAIN, two
# share LIST — see dial_touch.py's surface-to-geometry map).
GEOMETRY_MAIN = "main"
GEOMETRY_LIST = "list"
GEOMETRY_REPEAT = "repeat"
GEOMETRY_IDLE = "idle"
GEOMETRY_OUTPUT = "output"
GEOMETRIES = (GEOMETRY_MAIN, GEOMETRY_LIST, GEOMETRY_REPEAT, GEOMETRY_IDLE, GEOMETRY_OUTPUT)


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


def zone_rects_for(
    geometry: str, width: int, height: int, metrics: "LayoutMetrics | None" = None,
) -> tuple[ZoneRect, ...]:
    """The ordered, tappable rectangles of *geometry* at this panel size —
    the single source both the hit-tests below and the compositor's
    pressed-zone wash read, so the two can never disagree about where a
    boundary sits. Order is hit-test order. Every rect here is a field of
    one of the *Layout dataclasses below; this function adds no geometry
    arithmetic of its own, only a view over them. metrics=None means
    metrics_for(width, height) — today's geometry. Raises KeyError for an
    unknown geometry (a programming error, never a runtime input)."""
    return _GEOMETRY_BUILDERS[geometry](width, height, metrics)


def _main_zone_rects(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> tuple[ZoneRect, ...]:
    layout = layout_for(width, height, metrics=metrics)
    return (
        ZoneRect(TouchZone.DOTS, layout.dots),
        ZoneRect(TouchZone.NAME, layout.name),
        ZoneRect(TouchZone.OUTPUTS, layout.volume_cluster),
        ZoneRect(TouchZone.MUTE, layout.footer_mute),
        ZoneRect(TouchZone.DOWN, layout.footer_down),
        ZoneRect(TouchZone.UP, layout.footer_up),
    )


def _list_zone_rects(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> tuple[ZoneRect, ...]:
    layout = list_layout_for(width, height, metrics=metrics)
    rows = tuple(ZoneRect(TouchZone.LIST_ROW, rect, i) for i, rect in enumerate(layout.rows))
    if layout.rail is None:
        return rows + (
            ZoneRect(TouchZone.LIST_BACK, layout.back),
            ZoneRect(TouchZone.LIST_DOWN, layout.down),
            ZoneRect(TouchZone.LIST_UP, layout.up),
        )
    # On the rail, top to bottom: previous page, back/cancel, next page.
    return rows + (
        ZoneRect(TouchZone.LIST_UP, layout.rail_up),
        ZoneRect(TouchZone.LIST_BACK, layout.rail_cancel),
        ZoneRect(TouchZone.LIST_DOWN, layout.rail_down),
    )


def _repeat_zone_rects(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> tuple[ZoneRect, ...]:
    layout = repeat_layout_for(width, height, metrics=metrics)
    return (
        ZoneRect(TouchZone.DOTS, layout.dots),
        ZoneRect(TouchZone.NAME, layout.name),
        ZoneRect(TouchZone.MUTE, layout.volume_cluster),
        ZoneRect(TouchZone.REPEAT_PLAY, layout.row),
        ZoneRect(TouchZone.REPEAT_START, layout.start),
        ZoneRect(TouchZone.REPEAT_STOP, layout.stop),
    )


def _idle_zone_rects(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> tuple[ZoneRect, ...]:
    layout = idle_layout_for(width, height, metrics=metrics)
    return (ZoneRect(TouchZone.IDLE_REPLAY, layout.replay),)


def _output_zone_rects(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> tuple[ZoneRect, ...]:
    layout = output_layout_for(width, height, metrics=metrics)
    return (
        ZoneRect(TouchZone.OUTPUT_BACK, layout.back),
        ZoneRect(TouchZone.NAME, layout.name),
        ZoneRect(TouchZone.OUTPUT_TOGGLE, layout.row),
        ZoneRect(TouchZone.OUTPUT_DOWN, layout.down),
        ZoneRect(TouchZone.OUTPUT_UP, layout.up),
    )


_GEOMETRY_BUILDERS = {
    GEOMETRY_MAIN: _main_zone_rects,
    GEOMETRY_LIST: _list_zone_rects,
    GEOMETRY_REPEAT: _repeat_zone_rects,
    GEOMETRY_IDLE: _idle_zone_rects,
    GEOMETRY_OUTPUT: _output_zone_rects,
}


def hit_test(
    geometry: str, x: int, y: int, width: int, height: int, metrics: "LayoutMetrics | None" = None,
) -> "ZoneRect | None":
    """The first table entry of *geometry* containing compose-space point
    (x, y), or None in a dead zone or outside the panel. The one hit-test
    loop every per-geometry wrapper below is built from."""
    for entry in zone_rects_for(geometry, width, height, metrics=metrics):
        x0, y0, x1, y1 = entry.rect
        if x0 <= x < x1 and y0 <= y < y1:
            return entry
    return None


@dataclass(frozen=True)
class OverlayLayout:
    """Full overlay geometry for one panel size — the single source of truth
    for both where the compositor dims/draws and where the touch zones sit.
    `dots`, `name`, `volume_cluster`, `down` and `up` are exactly the
    DOTS/NAME/MUTE/DOWN/UP zone rectangles zones_for() returns; `artist`,
    `title`, `album` and the two band rectangles have no corresponding
    TouchZone because they never actuate. `album` is only populated on the
    content tier with room for it; elsewhere it is None and the renderer
    draws nothing there."""

    top_band: Rect        # full-width dim region, rows [0, band_h)
    bottom_band: Rect     # full-width dim region, rows [height-band_h, height)
    dots: Rect            # the two repeat-screen dots, left of the name (== DOTS zone)
    name: Rect            # appliance name, left part of top band (== NAME zone)
    artist: Rect          # centre-low text line, just above the bottom band (non-actuating)
    title: Rect           # track title line, directly above the artist line (non-actuating)
    volume_cluster: Rect  # glyph + number, right part of top band (== MUTE zone)
    down: Rect            # bottom band, left half (two-way; kept for the repeat/detail screens)
    up: Rect              # bottom band, right half (two-way; kept for the repeat/detail screens)
    divider_x: int        # x of the vertical divider centre in the bottom band (two-way split)
    album: Rect | None = None  # album line directly above the title (large tier only); None elsewhere, non-actuating
    # Three-way main footer: minus (== DOWN zone), plus (== UP zone), mute
    # (== MUTE zone) — left, middle and right thirds respectively. down/up/
    # divider_x above keep their two-way values for the repeat and output
    # detail screens, which still show only a minus/plus pair.
    footer_down: Rect | None = None      # bottom band, left third (minus, == DOWN zone)
    footer_up: Rect | None = None        # bottom band, middle third (plus, == UP zone)
    footer_mute: Rect | None = None      # bottom band, right third (== MUTE zone)
    footer_dividers: tuple[int, ...] = ()


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
class OutputLayout:
    """Full per-output detail-page geometry for one panel size — the tiered
    repeat layout's own geometry, relabelled: `back` is the header's left
    chevron (== the OUTPUT_BACK zone, reusing the DOTS rect); `name` is the
    appliance name (== the NAME zone, reused from the main surface);
    `volume_cluster` is the header's speaker+digits readout, drawn but
    never hit-tested here (display-only, like the repeat screen's own);
    `row` is the full-width toggle row (== the OUTPUT_TOGGLE zone, the same
    rectangle the repeat screen's enable row uses); `down`/`up` are the
    two-way minus/plus rectangles (== the OUTPUT_DOWN/OUTPUT_UP zones,
    identical to the main surface's own two-way `down`/`up` — no per-output
    footer thirds, this page never mutes)."""

    back: Rect
    name: Rect
    volume_cluster: Rect
    row: Rect
    down: Rect
    up: Rect
    divider_x: int
    top_band: Rect
    bottom_band: Rect


def output_layout_for(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> OutputLayout:
    """Compute the per-output detail-page geometry for a *width* x *height*
    panel — the tiered repeat layout's own toggle row and two-way minus/
    plus, under the detail page's own field names."""
    if metrics is None:
        metrics = metrics_for(width, height)
    layout = layout_for(width, height, metrics=metrics)
    repeat = repeat_layout_for(width, height, metrics=metrics)
    return OutputLayout(
        back=layout.dots,
        name=layout.name,
        volume_cluster=layout.volume_cluster,
        row=repeat.row,
        down=layout.down,
        up=layout.up,
        divider_x=layout.divider_x,
        top_band=layout.top_band,
        bottom_band=layout.bottom_band,
    )


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
    where the selector's touch zones sit. `rows` are the LIST_ROW rectangles
    for the CURRENT page, top to bottom.

    On the base tier the list's navigation lives in a bottom bar, split
    three ways: `back`, `down` and `up` are exactly the LIST_BACK/LIST_DOWN/
    LIST_UP zone rectangles list_zone_at() resolves to, and `bar` is the
    undivided band they live in. On a wider panel the navigation instead
    moves to a right-hand rail running the full height, so the rows can use
    the freed-up width: `bar`/`back`/`down`/`up` are then None, and `rail`/
    `rail_up`/`rail_cancel`/`rail_down` (exactly the LIST_UP/LIST_BACK/
    LIST_DOWN zone rectangles) carry the same three controls stacked
    top to bottom instead of side by side. Exactly one of the two chrome
    groups is populated for a given panel; the other is all None."""

    rows: tuple[Rect, ...]   # rows_per_page rectangles, top to bottom
    row_h: int
    rows_per_page: int
    # bottom-bar chrome (base tier); None when the rail is in use.
    bar: Rect | None                 # undivided band — back|down|up live here
    back: Rect | None                # bar, left third (== LIST_BACK zone)
    down: Rect | None                # bar, middle third (== LIST_DOWN zone)
    up: Rect | None                  # bar, right third (== LIST_UP zone)
    # right-rail chrome (rich/large tiers); None on base.
    rail: Rect | None = None         # the full-height rail column
    rail_up: Rect | None = None      # previous page  (== LIST_UP zone)
    rail_cancel: Rect | None = None  # back / cancel  (== LIST_BACK zone)
    rail_down: Rect | None = None    # next page      (== LIST_DOWN zone)


def _dead_zone_margin(width: int, height: int) -> int:
    """Dead-zone margin in pixels, scaled from the 160x128 reference by the
    panel's short side (min(width, height)) — the same scaling axis used by
    dial_display_image._blur_radius_for, for the same reason: it keeps the
    band's apparent physical size consistent whether the panel is "wide"
    (160x128, 320x240) or "tall-ish" (128x128, 240x240) shaped. Returns
    exactly 3 at 160x128, by construction. Floored at 1px so degenerately
    tiny panels never lose their dead zones entirely.

    A thin test-facing shim over metrics_for(width, height).margin — kept
    under its historical name since tests import it directly.
    """
    return metrics_for(width, height).margin


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


def layout_for(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> OverlayLayout:
    """Compute the full overlay geometry for a *width* x *height* panel.

    m and band_h come from *metrics* (metrics_for(width, height) when None
    is passed — today's geometry). Bands are a plain floor-divide of the
    panel height (no dead-zone gap of their own — the artwork above and
    below them is the "gap"); the name/cluster split and the down/up split
    each carry the usual dead-zone margins. The artist line sits centre-low,
    directly above the bottom band, with no dead-zone gap of its own (it
    never actuates, so there is nothing to protect it from). See the module
    docstring for the exact arithmetic and the pinned 160x128 reference
    numbers.
    """
    if metrics is None:
        metrics = metrics_for(width, height)
    m = metrics.margin
    band_h = metrics.band_h
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
    # One more line above the title, same height, where the tier has room for
    # it: the album name. None elsewhere, so the renderer draws nothing.
    album: Rect | None = (
        (m, height - band_h - 3 * artist_h, width - m, height - band_h - 2 * artist_h)
        if metrics.has_album_line else None
    )

    (dx0, dx1), (ux0, ux1) = _split(width, m, [1, 1])
    by0 = height - band_h + m
    down: Rect = (dx0, by0, dx1, height)
    up: Rect = (ux0, by0, ux1, height)
    divider_x = (dx1 + ux0) // 2

    # Three-way main footer: minus | plus | mute, left to right. Same band
    # row (by0..height) and the same dead-zone margin rule as the two-way
    # split above, just three equal thirds instead of two halves.
    (fdx0, fdx1), (fux0, fux1), (fmx0, fmx1) = _split(width, m, [1, 1, 1])
    footer_down: Rect = (fdx0, by0, fdx1, height)
    footer_up: Rect = (fux0, by0, fux1, height)
    footer_mute: Rect = (fmx0, by0, fmx1, height)
    footer_dividers = ((fdx1 + fux0) // 2, (fux1 + fmx0) // 2)

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
        album=album,
        footer_down=footer_down,
        footer_up=footer_up,
        footer_mute=footer_mute,
        footer_dividers=footer_dividers,
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


def list_layout_for(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> ListLayout:
    """Compute the full selector-screen geometry for a *width* x *height*
    panel.

    On the base tier (metrics.list_rail is False): rows_per_page rows tiling
    [0, height - bar_h), full width, plus a bottom bar split three ways
    (back|down|up) with the usual dead-zone margins. Row height equals the
    bar height (never below 32px on any shipped profile), which is what
    makes rows_per_page exactly 3 on every base-tier profile listed in
    dial_display_profiles.py.

    On the rich/large tiers (metrics.list_rail is True): the navigation
    moves to a right-hand rail (metrics.rail_w wide) so rows tile
    [0, width - rail_w - 2*margin) instead of the full width — the same 2m
    dead gap the header's own name/cluster split and DOWN/UP split use. The
    rail itself is split three ways top to bottom, inset by margin on the
    left the same way the bottom bar is inset by margin at the top; its
    glyphs are drawn into a centred metrics.rail_glyph-side box within each
    third, not the whole zone (see _centred_box in the compositor).
    """
    if metrics is None:
        metrics = metrics_for(width, height)
    m = metrics.margin
    row_h = metrics.row_h
    rows_per_page = metrics.rows_per_page

    if not metrics.list_rail:
        bar_h = metrics.band_h
        rows = tuple((0, i * row_h, width, (i + 1) * row_h) for i in range(rows_per_page))
        (bx0, bx1), (dx0, dx1), (ux0, ux1) = _split(width, m, [1, 1, 1])
        by0 = height - bar_h + m
        return ListLayout(
            rows=rows, row_h=row_h, rows_per_page=rows_per_page,
            bar=(0, height - bar_h, width, height),
            back=(bx0, by0, bx1, height),
            down=(dx0, by0, dx1, height),
            up=(ux0, by0, ux1, height),
        )

    rail_w = metrics.rail_w
    rows_x1 = width - rail_w - 2 * m
    rows = tuple((0, i * row_h, rows_x1, (i + 1) * row_h) for i in range(rows_per_page))
    (uy0, uy1), (cy0, cy1), (dy0, dy1) = _split(height, m, [1, 1, 1])
    rx0 = width - rail_w + m
    return ListLayout(
        rows=rows, row_h=row_h, rows_per_page=rows_per_page,
        bar=None, back=None, down=None, up=None,
        rail=(width - rail_w, 0, width, height),
        rail_up=(rx0, uy0, width, uy1),
        rail_cancel=(rx0, cy0, width, cy1),
        rail_down=(rx0, dy0, width, dy1),
    )


def list_zone_at(x: int, y: int, width: int, height: int) -> tuple[TouchZone, int | None] | None:
    """Return (zone, row_index) for the selector surface at compose-space
    point (x, y): (LIST_ROW, i) inside row i, (LIST_BACK/LIST_DOWN/LIST_UP,
    None) inside the bottom bar, or None in a dead zone or outside the
    panel. row_index is only ever set for LIST_ROW."""
    hit = hit_test(GEOMETRY_LIST, x, y, width, height)
    return (hit.zone, hit.index) if hit is not None else None


def repeat_layout_for(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> RepeatLayout:
    """Compute the repeat-screen geometry for a *width* x *height* panel.
    `row` is a full-width strip of height 2*band_h (64px at the reference
    160x128 profile), centred vertically between the top and bottom bands
    — it exactly fills the gap between them, so the enable layout's row
    and the replaying layout's position line always tile the panel with
    no gap against either band.
    """
    if metrics is None:
        metrics = metrics_for(width, height)
    layout = layout_for(width, height, metrics=metrics)
    m = metrics.margin
    band_h = metrics.band_h
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


def idle_layout_for(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> IdleLayout:
    """Compute the idle-screen geometry: the affordance line is the same
    centre-low rectangle the main surface's (non-actuating) artist line
    occupies; replay is the whole panel below the top band."""
    layout = layout_for(width, height, metrics=metrics)
    return IdleLayout(affordance=layout.artist, replay=(0, layout.top_band[3], width, height))


def idle_zone_at(x: int, y: int, width: int, height: int) -> TouchZone | None:
    """Return IDLE_REPLAY for any point below the top band, else None. The
    top band is excluded so an accidental brush up there — where the name
    and volume cluster live on the main surface — does nothing on it."""
    hit = hit_test(GEOMETRY_IDLE, x, y, width, height)
    return hit.zone if hit is not None else None
