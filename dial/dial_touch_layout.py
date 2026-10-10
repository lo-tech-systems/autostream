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
and bottom bands) is NOT a dead zone: it is the ARTWORK zone, a single tap
target covering the artist/title lines and the artwork around them — a tap
there hides the bands for a few seconds (see dial_display.hide_controls()).
The margin is 3px
at the 160x128 profile (the shipped panel) and scales with the panel's
short side using the same rule as dial_display_image._blur_radius_for —
margin = round(min(width, height) * 3 / 128) with a floor of 1px. This
keeps the dead-zone band feeling the same physical size across profiles
rather than shrinking to nothing on a big panel or ballooning on a small
one.

SURFACES: this module describes geometry for several hit-test geometries
(GEOMETRY_MAIN, GEOMETRY_LIST, GEOMETRY_REPEAT, GEOMETRY_IDLE, and others
below), never mixed. Each geometry's tappable rectangles live in one ordered table —
`zone_rects_for(geometry, width, height)` — that both `hit_test()` below
and the compositor's pressed-zone wash read, so the two can never disagree
about where a boundary sits.

The MAIN geometry (`zone_at`/`zones_for`/`layout_for`) is the now-playing
screen: DOTS, NAME, OUTPUTS, MUTE, DOWN, UP, plus ARTWORK (the inter-band
strip, taps hide the bands) and the non-actuating artist and title labels.
DOTS is carved from the left of the NAME zone (whose x0 therefore starts
one band-height plus a 2*margin gap later than before); it opens the
repeat screen. The LIST geometry
(`list_zone_at`/`list_layout_for`) is the appliance list (also reused,
unchanged, for the replay picker): LIST_ROW (one per visible row),
LIST_BACK, LIST_DOWN and LIST_UP. The REPEAT geometry
(`repeat_zone_at`/`repeat_layout_for`) is the repeat screen: DOTS (reused,
pops back to main and reveals the main screen's volume overlay), NAME
(reused, opens the appliance selector), OUTPUTS (the volume readout, opens
the outputs list like the main screen — the repeat screen has no mute
control of its own), REPEAT_PLAY (the enable layout's arm/disarm row),
REPEAT_START, REPEAT_STOP. The IDLE geometry
(`idle_zone_at`/`idle_layout_for`) is the idle screen: IDLE_WIFI and
IDLE_INFO, two small corner squares listed first so they win the corners
they share with IDLE_REPLAY, which covers the whole panel below the top
band. GEOMETRY_INFO is the info page's own reading of the LIST
table with every LIST_ROW entry removed (its rows are display-only).
GEOMETRY_NOWIFI is the No-WiFi page's own table (Dismiss | Restart);
GEOMETRY_NONE is an empty table (the "Restarting..." screen has nothing
tappable at all). A
caller never mixes geometries — which one to hit-test against is decided
elsewhere
(dial_touch.TouchStateMachine.set_surface, which maps its own surface
strings onto these geometries many-to-one) — but `hit_test()` and
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
#
# CONTENT_COMPACT sits below CONTENT_BASE: a physically tiny panel (a small
# round or square watch-style glass) has no room for bands, a name or a
# volume readout at all, however many logical pixels it reports, so it is
# decided purely from physical size, ahead of the pixel-tier checks below
# (see metrics_for()) rather than being reachable through them.
CONTENT_COMPACT = "compact"
CONTENT_BASE = "base"
CONTENT_RICH = "rich"
CONTENT_LARGE = "large"
_CONTENT_TIERS = (CONTENT_COMPACT, CONTENT_BASE, CONTENT_RICH, CONTENT_LARGE)

RICH_MIN_SHORT_SIDE_PX = 200   # logical short side at/above which the rich tier applies
LARGE_MIN_SHORT_SIDE_PX = 400  # logical short side at/above which the large tier applies

TOUCH_MIN_MM = 8.0                # fingertip floor, resistive and capacitive alike
TOUCH_SHORT_BELOW_BAND_MM = 6.0   # a quarter-height band shorter than this cannot hold a floor-sized control
BAND_MAX_MM = 12.0                # on rich/large panels, chrome stops growing past this physical band height

# Physical short side at or below which the band+body+footer layouts stop
# being usable and the compact (2x2) layouts apply instead. 27mm admits a
# 1.3in 240x240 panel (23.4mm) and a 1.44in 128x128 panel (25.9mm), and
# excludes a 1.8in 160x128 panel (28.6mm) and a 2.8in 320x240 panel
# (42.7mm). Purely physical: unlike the pixel-tier thresholds above, no
# logical pixel count feeds this decision at all (see metrics_for()).
COMPACT_MAX_SHORT_SIDE_MM = 27.0

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

    Ahead of all of that, CONTENT_COMPACT is decided purely from physical
    size: a panel whose short side is at or below COMPACT_MAX_SHORT_SIDE_MM
    of actual glass has no room for the band+body+footer layouts at any
    logical pixel count, so it never enters the pixel-tier ladder above at
    all. mm_per_px=None can never resolve compact (there is no physical size
    to test), and *size_chosen* has no effect on it either way — compact is
    a physical tier down, not a pixel tier the veto below ever tiers back
    up to.

    mm_per_px=None also means every pixel quantity is computed exactly as it
    always was (the base-tier formulas), so every existing caller that never
    passes a density is completely unaffected by any of this.
    """
    short = min(width, height)
    quarter = height // BAND_DIVISOR
    band_mm = quarter * mm_per_px if mm_per_px is not None else None
    touch_short = band_mm is not None and band_mm < TOUCH_SHORT_BELOW_BAND_MM
    short_mm = short * mm_per_px if mm_per_px is not None else None

    if short_mm is not None and short_mm <= COMPACT_MAX_SHORT_SIDE_MM:
        content_tier = CONTENT_COMPACT
    elif short >= LARGE_MIN_SHORT_SIDE_PX:
        content_tier = CONTENT_LARGE
    elif short >= RICH_MIN_SHORT_SIDE_PX:
        content_tier = CONTENT_RICH
    else:
        content_tier = CONTENT_BASE
    if content_tier not in (CONTENT_BASE, CONTENT_COMPACT) and mm_per_px is None:
        content_tier = CONTENT_BASE           # density unknown: never guess a richer layout
    if content_tier not in (CONTENT_BASE, CONTENT_COMPACT) and touch_short and not size_chosen:
        content_tier = CONTENT_BASE           # the veto: automatic tiering only

    touch_min_px = ceil(TOUCH_MIN_MM / mm_per_px) if mm_per_px else None
    has_album_line = content_tier == CONTENT_LARGE

    if content_tier in (CONTENT_BASE, CONTENT_COMPACT):
        band_h = quarter
        row_h = band_h
        # The compact tier's picker shows two rows (its own 2x2 geometry),
        # never the base tier's own row-count formula.
        rows_per_page = 2 if content_tier == CONTENT_COMPACT else (height - band_h) // row_h
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

    if content_tier in (CONTENT_BASE, CONTENT_COMPACT):
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
    if content_tier not in (CONTENT_BASE, CONTENT_COMPACT):
        # The halo is a fine screen-space stroke — physical scale keeps it
        # from ballooning into a blur on a bigger panel.
        halo_stroke = min(halo_stroke, HALO_MAX_PX)
        halo_blur = min(halo_blur, HALO_MAX_PX)
    if content_tier == CONTENT_LARGE:
        # More room buys more content, not bigger glyphs past a legible size.
        font_body = min(font_body, FONT_BODY_MAX_PX)
        font_readout = min(font_readout, FONT_READOUT_MAX_PX)
        icon = min(icon, FONT_READOUT_MAX_PX)

    if content_tier in (CONTENT_BASE, CONTENT_COMPACT):
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
    IDLE_INFO: the idle screen's own small top-right "i" affordance,
    reachable on every idle dial regardless of whether a replay is held —
    opens the read-only info list (see IdleLayout.info/GEOMETRY_INFO).
    IDLE_WIFI: the idle screen's own small top-left Wi-Fi status square,
    the mirror image of IDLE_INFO — a tap opens the No-WiFi page while the
    link is down (inert while connected; see DialDisplay.open_nowifi).
    NOWIFI_DISMISS, NOWIFI_RESTART: the No-WiFi page's two cells.
    SDHEALTH_DISMISS: the SD card warning's one cell.
    ARTWORK: the main surface's inter-band strip (between the top and
    bottom bands); a tap hides the bands for a few seconds.
    EQ_BASS_DOWN, EQ_BASS_UP, EQ_TREBLE_DOWN, EQ_TREBLE_UP: the EQ page's
    own surface (plus DOTS/NAME/OUTPUTS, reused from the main surface) --
    the bass and treble bars' own minus/plus steppers.
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
    IDLE_INFO = "idle_info"
    OUTPUTS = "outputs"
    OUTPUT_BACK = "output_back"
    OUTPUT_TOGGLE = "output_toggle"
    OUTPUT_UP = "output_up"
    OUTPUT_DOWN = "output_down"
    ARTWORK = "artwork"
    EQ_BASS_DOWN = "eq_bass_down"
    EQ_BASS_UP = "eq_bass_up"
    EQ_TREBLE_DOWN = "eq_treble_down"
    EQ_TREBLE_UP = "eq_treble_up"
    IDLE_WIFI = "idle_wifi"
    NOWIFI_DISMISS = "nowifi_dismiss"
    NOWIFI_RESTART = "nowifi_restart"
    SDHEALTH_DISMISS = "sdhealth_dismiss"


Rect = tuple[int, int, int, int]  # (x0, y0, x1, y1), x1/y1 exclusive


# Hit-test geometries. These name a geometry, not a screen: the touch layer
# maps its own surfaces onto them many-to-one (two surfaces share MAIN, two
# share LIST — see dial_touch.py's surface-to-geometry map).
GEOMETRY_MAIN = "main"
GEOMETRY_LIST = "list"
GEOMETRY_REPEAT = "repeat"
# The repeat screen's OWN replaying-layout geometry. Off the compact tier
# this is identical, byte for byte, to GEOMETRY_REPEAT — the large tiers
# share one row/start/stop table between the enable and replaying layouts —
# so the name is valid everywhere; only the compact tier gives the two
# repeat-screen states different rectangles (see _repeat_replay_zone_rects).
GEOMETRY_REPEAT_REPLAY = "repeat_replay"
GEOMETRY_IDLE = "idle"
GEOMETRY_OUTPUT = "output"
# The info page's own table: off the compact tier, the list table with
# every LIST_ROW entry removed, so a row press never arms, flashes or
# dispatches (rows are dead at the geometry level, not just in the
# manager); on compact the rows ARE tappable — this is the list table
# unchanged there, since the compact info page's own rows open a value view
# (see _info_zone_rects/info_row_tap).
GEOMETRY_INFO = "info"
# The compact info page's own drill-in, reached from a GEOMETRY_INFO row on
# that tier only: one entry, the whole panel, LIST_BACK — a tap anywhere
# returns to the list (close_list()'s existing back_to resolution already
# does the rest). Tier-agnostic and pure like every table here.
GEOMETRY_INFO_VALUE = "info_value"
# The EQ page's own table: rich/large only (see eq_layout_for/DialDisplay.
# _eq_available) -- DOTS/NAME/OUTPUTS reused from the main geometry, plus
# the bass/treble bar steppers.
GEOMETRY_EQ = "eq"
# The No-WiFi page's own table: Dismiss and Restart, laid out by
# nowifi_layout_for() (a centred card off compact, the 2x2's bottom row on
# it). The message row is display-only and has no entry.
GEOMETRY_NOWIFI = "nowifi"
# The SD card warning's own table: one Dismiss cell under the message row,
# laid out by sdhealth_layout_for() (the No-WiFi card with its bottom row
# undivided).
GEOMETRY_SDHEALTH = "sdhealth"
# An empty table: the "Restarting..." screen has nothing tappable at all, and
# a surface mapped here can never arm a zone. Kept as a named geometry (not
# an absent one) so the surface map never has to fall back to MAIN.
GEOMETRY_NONE = "none"
GEOMETRIES = (
    GEOMETRY_MAIN, GEOMETRY_LIST, GEOMETRY_REPEAT, GEOMETRY_REPEAT_REPLAY, GEOMETRY_IDLE, GEOMETRY_OUTPUT,
    GEOMETRY_INFO, GEOMETRY_INFO_VALUE, GEOMETRY_EQ, GEOMETRY_NOWIFI, GEOMETRY_SDHEALTH, GEOMETRY_NONE,
)


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
    if metrics is None:
        metrics = metrics_for(width, height)
    if metrics.content_tier == CONTENT_COMPACT:
        # The playing 2x2: pager dots top-left, mute top-right, minus/plus
        # along the bottom — no NAME (appliance selection is unreachable on
        # compact) and no ARTWORK strip (every cell is already a control).
        c = compact_layout_for(width, height, metrics=metrics)
        return (
            ZoneRect(TouchZone.DOTS, c.tl),
            ZoneRect(TouchZone.MUTE, c.tr),
            ZoneRect(TouchZone.DOWN, c.bl),
            ZoneRect(TouchZone.UP, c.br),
        )
    layout = layout_for(width, height, metrics=metrics)
    return (
        ZoneRect(TouchZone.DOTS, layout.dots),
        ZoneRect(TouchZone.NAME, layout.name),
        ZoneRect(TouchZone.OUTPUTS, layout.volume_cluster),
        ZoneRect(TouchZone.MUTE, layout.footer_mute),
        ZoneRect(TouchZone.DOWN, layout.footer_down),
        ZoneRect(TouchZone.UP, layout.footer_up),
        # Last: the bands' own zones above do not overlap this strip at
        # all, so the order only matters for readability, not correctness.
        ZoneRect(TouchZone.ARTWORK, layout.artwork),
    )


def _list_zone_rects(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> tuple[ZoneRect, ...]:
    if metrics is None:
        metrics = metrics_for(width, height)
    if metrics.content_tier == CONTENT_COMPACT:
        # The replay picker: a title band over a 35/65 split — cancel and
        # "more" (next page, wrapping — see the manager's paging) in the
        # left column, the two visible rows in the right column. No LIST_UP:
        # compact never shows a previous-page control of its own — wrapping
        # makes one unnecessary.
        p = compact_picker_layout_for(width, height, metrics=metrics)
        return (
            ZoneRect(TouchZone.LIST_ROW, p.row0, 0),
            ZoneRect(TouchZone.LIST_ROW, p.row1, 1),
            ZoneRect(TouchZone.LIST_BACK, p.cancel),
            ZoneRect(TouchZone.LIST_DOWN, p.more),
        )
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
    if metrics is None:
        metrics = metrics_for(width, height)
    if metrics.content_tier == CONTENT_COMPACT:
        # The repeat screen's enable layout: the back control (the pager
        # dots, same as opening it) top-left, the "Repeat Play" row spanning
        # the full bottom row — no separate cancel. The top-right cell is
        # absent from the table (dead): No NAME/OUTPUTS either — appliance
        # selection and the volume readout are unreachable on compact.
        c = compact_layout_for(width, height, metrics=metrics)
        return (
            ZoneRect(TouchZone.DOTS, c.tl),
            ZoneRect(TouchZone.REPEAT_PLAY, c.bottom_row),
        )
    layout = repeat_layout_for(width, height, metrics=metrics)
    return (
        ZoneRect(TouchZone.DOTS, layout.dots),
        ZoneRect(TouchZone.NAME, layout.name),
        ZoneRect(TouchZone.OUTPUTS, layout.volume_cluster),
        ZoneRect(TouchZone.REPEAT_PLAY, layout.row),
        ZoneRect(TouchZone.REPEAT_START, layout.start),
        ZoneRect(TouchZone.REPEAT_STOP, layout.stop),
    )


def _repeat_replay_zone_rects(
    width: int, height: int, metrics: "LayoutMetrics | None" = None,
) -> tuple[ZoneRect, ...]:
    """GEOMETRY_REPEAT_REPLAY: the repeat screen's OWN replaying-layout
    table. Off the compact tier this is _repeat_zone_rects() itself, byte
    for byte — the large tiers share one row/start/stop table between the
    enable and replaying layouts, so there is nothing of its own to
    describe there; only compact gives the replaying layout different
    rectangles, its own 2x2: back top-left, time top-right (display-only —
    absent from the table), Restart bottom-left, Stop bottom-right."""
    if metrics is None:
        metrics = metrics_for(width, height)
    if metrics.content_tier == CONTENT_COMPACT:
        c = compact_layout_for(width, height, metrics=metrics)
        return (
            ZoneRect(TouchZone.DOTS, c.tl),
            ZoneRect(TouchZone.REPEAT_START, c.bl),
            ZoneRect(TouchZone.REPEAT_STOP, c.br),
        )
    return _repeat_zone_rects(width, height, metrics=metrics)


def _idle_zone_rects(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> tuple[ZoneRect, ...]:
    # The two corner squares first: on rich they dip a few pixels below
    # the top band into IDLE_REPLAY's own rect, and on compact IDLE_REPLAY
    # is the whole panel — either way they overlap it, and hit_test's
    # first-match order is what gives each square its corner while leaving
    # IDLE_REPLAY's own published rect untouched.
    layout = idle_layout_for(width, height, metrics=metrics)
    return (
        ZoneRect(TouchZone.IDLE_WIFI, layout.wifi),
        ZoneRect(TouchZone.IDLE_INFO, layout.info),
        ZoneRect(TouchZone.IDLE_REPLAY, layout.replay),
    )


def _info_zone_rects(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> tuple[ZoneRect, ...]:
    """GEOMETRY_INFO: on the compact tier, the list table unchanged — the
    same picker-shaped rows _list_zone_rects already returns there, now
    tappable (see info_row_tap()); off compact, the list table with every
    LIST_ROW entry removed — the info page's rows are dead at the geometry
    level there, so a press anywhere on one lands in no entry at all (no
    arm, no flash, no dispatch). Either way the controls (rail or
    cancel/more) resolve exactly as they do on the list."""
    if metrics is None:
        metrics = metrics_for(width, height)
    if metrics.content_tier == CONTENT_COMPACT:
        return _list_zone_rects(width, height, metrics=metrics)
    return tuple(e for e in _list_zone_rects(width, height, metrics=metrics) if e.zone != TouchZone.LIST_ROW)


def _info_value_zone_rects(
    width: int, height: int, metrics: "LayoutMetrics | None" = None,
) -> tuple[ZoneRect, ...]:
    """GEOMETRY_INFO_VALUE: one entry, the whole panel, LIST_BACK — a tap
    anywhere on the compact info page's drill-in returns to the list.
    Tier-agnostic and pure; only the compact tier ever requests the screen
    that reads it."""
    return (ZoneRect(TouchZone.LIST_BACK, (0, 0, width, height)),)


def _output_zone_rects(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> tuple[ZoneRect, ...]:
    layout = output_layout_for(width, height, metrics=metrics)
    return (
        ZoneRect(TouchZone.OUTPUT_BACK, layout.back),
        ZoneRect(TouchZone.NAME, layout.name),
        ZoneRect(TouchZone.OUTPUT_TOGGLE, layout.row),
        ZoneRect(TouchZone.OUTPUT_DOWN, layout.down),
        ZoneRect(TouchZone.OUTPUT_UP, layout.up),
    )


def _eq_zone_rects(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> tuple[ZoneRect, ...]:
    """GEOMETRY_EQ: the top band's DOTS/NAME/OUTPUTS (reused from the main
    surface, same rects layout_for() itself gives them) plus the bass and
    treble bars' own minus/plus steppers. The caption/track area between
    each bar's two controls is non-actuating -- there is no zone for it."""
    layout = eq_layout_for(width, height, metrics=metrics)
    return (
        ZoneRect(TouchZone.DOTS, layout.dots),
        ZoneRect(TouchZone.NAME, layout.name),
        ZoneRect(TouchZone.OUTPUTS, layout.volume_cluster),
        ZoneRect(TouchZone.EQ_BASS_DOWN, layout.bass.down),
        ZoneRect(TouchZone.EQ_BASS_UP, layout.bass.up),
        ZoneRect(TouchZone.EQ_TREBLE_DOWN, layout.treble.down),
        ZoneRect(TouchZone.EQ_TREBLE_UP, layout.treble.up),
    )


def _nowifi_zone_rects(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> tuple[ZoneRect, ...]:
    """GEOMETRY_NOWIFI: the page's two cells, Dismiss then Restart. The
    message row is display-only. Tier differences live entirely in
    nowifi_layout_for()."""
    layout = nowifi_layout_for(width, height, metrics=metrics)
    return (
        ZoneRect(TouchZone.NOWIFI_DISMISS, layout.dismiss),
        ZoneRect(TouchZone.NOWIFI_RESTART, layout.restart),
    )


def _sdhealth_zone_rects(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> tuple[ZoneRect, ...]:
    """GEOMETRY_SDHEALTH: the one Dismiss cell. The message row is
    display-only."""
    layout = sdhealth_layout_for(width, height, metrics=metrics)
    return (ZoneRect(TouchZone.SDHEALTH_DISMISS, layout.dismiss),)


def _none_zone_rects(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> tuple[ZoneRect, ...]:
    """GEOMETRY_NONE: nothing is tappable."""
    return ()


_GEOMETRY_BUILDERS = {
    GEOMETRY_MAIN: _main_zone_rects,
    GEOMETRY_LIST: _list_zone_rects,
    GEOMETRY_REPEAT: _repeat_zone_rects,
    GEOMETRY_REPEAT_REPLAY: _repeat_replay_zone_rects,
    GEOMETRY_IDLE: _idle_zone_rects,
    GEOMETRY_OUTPUT: _output_zone_rects,
    GEOMETRY_INFO: _info_zone_rects,
    GEOMETRY_INFO_VALUE: _info_value_zone_rects,
    GEOMETRY_EQ: _eq_zone_rects,
    GEOMETRY_NOWIFI: _nowifi_zone_rects,
    GEOMETRY_SDHEALTH: _sdhealth_zone_rects,
    GEOMETRY_NONE: _none_zone_rects,
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
    artwork: Rect = (0, 0, 0, 0)          # the inter-band strip (== ARTWORK zone)


@dataclass(frozen=True)
class RepeatLayout:
    """Full repeat-screen geometry for one panel size. `dots`, `name` and
    `volume_cluster` are the identical rectangles OverlayLayout uses (same
    geometry as the main screen's top band): the dots and the name label
    stay tappable here (== the DOTS/NAME zones); the volume cluster opens
    the outputs list, same as main (== the OUTPUTS zone — see
    repeat_zone_at()). `row` is the full-width middle row used by the
    enable layout's "Repeat Play" toggle (== the REPEAT_PLAY zone); `line`
    shares that same rectangle for the replaying layout's centred
    "m:ss / m:ss" position text — only one of the two layouts is ever on
    screen at a time, so the two never actually compete for it. `start`/
    `stop` are exactly the DOWN/UP zone rectangles, relabelled Restart/Stop
    text glyphs for the replaying layout."""

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
class InfoValueLayout:
    """The compact info page's drill-in: a small label band across the top
    (the same tight height the picker's own title band uses — font_body +
    pad) and the value rect below it, inset by the usual pad on the left,
    right and bottom."""

    label: Rect    # top band, full width, font_body + pad tall
    value: Rect    # everything below the label band, inset by pad each side


def info_value_layout_for(
    width: int, height: int, metrics: "LayoutMetrics | None" = None,
) -> InfoValueLayout:
    """Compute the compact info page's drill-in geometry for a *width* x
    *height* panel: the label band is exactly as tall as the picker's own
    title band; the value rect is everything below it, inset by pad on
    three sides (the label band already sits flush at the top). Pure and
    tier-agnostic, like every layout function here — only the compact tier
    ever opens the screen that reads it. metrics=None means
    metrics_for(width, height)."""
    if metrics is None:
        metrics = metrics_for(width, height)
    band_h = metrics.font_body + metrics.pad
    pad = metrics.pad
    return InfoValueLayout(label=(0, 0, width, band_h), value=(pad, band_h, width - pad, height))


@dataclass(frozen=True)
class IdleLayout:
    """Idle-screen geometry: a single non-actuating affordance line
    (reusing the same centre-low rect the main surface's artist line
    occupies — `affordance`), the actuating rect for the whole panel
    below the top band (`replay`, == the IDLE_REPLAY zone, resolved by
    idle_zone_at()), the small top-right "i" square (`info`, == the
    IDLE_INFO zone) that opens the read-only info list on every idle dial,
    and its mirror image top-left (`wifi`, == the IDLE_WIFI zone): the
    Wi-Fi status glyph, the same side as `info`, tappable while the link
    is down."""

    affordance: Rect
    replay: Rect
    info: Rect
    wifi: Rect = (0, 0, 0, 0)


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


@dataclass(frozen=True)
class CompactLayout:
    """The 2x2 grid every compact-tier screen is laid out on: four cells
    (tl/tr/bl/br), the two full-width rows those cells tile (top_row/
    bottom_row, used by screens that treat a row as one control rather than
    two), and the two divider-line positions between them. Which cells a
    given screen uses, and as which zones, is each geometry table's own
    business (see the compact branches of _main_zone_rects and friends,
    below) — this dataclass only describes the grid itself."""

    tl: Rect
    tr: Rect
    bl: Rect
    br: Rect
    top_row: Rect
    bottom_row: Rect
    divider_x: int
    divider_y: int


def compact_layout_for(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> CompactLayout:
    """Compute the compact-tier 2x2 grid for a *width* x *height* panel: both
    axes are split independently with the same _split(total, margin, [1, 1])
    two-way rule the base tier's own DOWN/UP footer uses, so the grid is
    built from the one existing split primitive rather than a new rule of
    its own. metrics=None means metrics_for(width, height)."""
    if metrics is None:
        metrics = metrics_for(width, height)
    m = metrics.margin
    (x0, x1), (x2, x3) = _split(width, m, [1, 1])
    (y0, y1), (y2, y3) = _split(height, m, [1, 1])
    return CompactLayout(
        tl=(x0, y0, x1, y1), tr=(x2, y0, x3, y1),
        bl=(x0, y2, x1, y3), br=(x2, y2, x3, y3),
        top_row=(0, y0, width, y1), bottom_row=(0, y2, width, height),
        divider_x=(x1 + x2) // 2, divider_y=(y1 + y2) // 2,
    )


COMPACT_PICKER_LEFT_FRACTION = 0.35  # the controls column's share of the width


@dataclass(frozen=True)
class CompactPickerLayout:
    """The compact replay picker: a title band across the top, then a 2x2
    grid whose left column (COMPACT_PICKER_LEFT_FRACTION of the width) holds
    the cancel and "more" controls and whose right column holds the two
    visible replay targets."""

    title: Rect            # full width, rows [0, title_h)
    title_divider_y: int   # the white line under the title, centred here
    cancel: Rect            # left column, upper cell  (== LIST_BACK)
    more: Rect              # left column, lower cell  (== LIST_DOWN)
    row0: Rect              # right column, upper cell (== LIST_ROW 0)
    row1: Rect              # right column, lower cell (== LIST_ROW 1)
    divider_x: int          # the column line separating the two columns
    divider_y: int          # the line between the two grid rows


def compact_picker_layout_for(
    width: int, height: int, metrics: "LayoutMetrics | None" = None,
) -> CompactPickerLayout:
    """Compute the compact-tier replay picker's geometry: a tight title
    band (the label's own line height plus half a pad above and below) over
    a two-column grid, split left/right at COMPACT_PICKER_LEFT_FRACTION of
    the width with the usual 2*margin dead gap, and top/bottom with the same
    _split(total, margin, [1, 1]) rule the rest of the compact tier uses.
    The grid starts one dead margin below the title's own divider line, so a
    tap on that line hits nothing. metrics=None means metrics_for(width,
    height)."""
    if metrics is None:
        metrics = metrics_for(width, height)
    m = metrics.margin
    title_h = metrics.font_body + metrics.pad
    grid_y0 = title_h + m
    (r0a, r0b), (r1a, r1b) = _split(height - grid_y0, m, [1, 1])
    y0, y1, y2, y3 = grid_y0 + r0a, grid_y0 + r0b, grid_y0 + r1a, grid_y0 + r1b
    divider_x = round(width * COMPACT_PICKER_LEFT_FRACTION)
    lx1, rx0 = divider_x - m, divider_x + m
    return CompactPickerLayout(
        title=(0, 0, width, title_h), title_divider_y=title_h,
        cancel=(0, y0, lx1, y1), more=(0, y2, lx1, y3),
        row0=(rx0, y0, width, y1), row1=(rx0, y2, width, y3),
        divider_x=divider_x, divider_y=(y1 + y2) // 2,
    )


# The No-WiFi card's share of the panel off the compact tier. On compact the
# page is the whole panel (the 2x2 grid), so neither fraction is read there.
NOWIFI_CARD_WIDTH_FRACTION = 0.74
NOWIFI_CARD_HEIGHT_FRACTION = 0.60


@dataclass(frozen=True)
class NoWifiLayout:
    """The No-WiFi page: a card (the whole panel on compact, a centred
    rectangle elsewhere) split into a full-width message row over two
    cells — Dismiss left (== NOWIFI_DISMISS), Restart right (==
    NOWIFI_RESTART) — with the usual 2*margin dead gap between every pair
    of neighbours. divider_y is the horizontal line between the rows;
    divider_x is the vertical line between the two cells, drawn in the
    bottom row only (the message row has no vertical split)."""

    card: Rect
    message: Rect
    dismiss: Rect
    restart: Rect
    divider_x: int
    divider_y: int


def nowifi_layout_for(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> NoWifiLayout:
    """Compute the No-WiFi page geometry for a *width* x *height* panel.

    Compact: exactly the compact 2x2 — message = top_row, dismiss = bl,
    restart = br, dividers = the grid's own. Every other tier: a card
    NOWIFI_CARD_WIDTH_FRACTION x NOWIFI_CARD_HEIGHT_FRACTION of the panel,
    centred, its rows and its bottom-row cells split with the same
    _split(total, margin, [1, 1]) rule the compact grid uses, offset to the
    card's origin. metrics=None means metrics_for(width, height)."""
    if metrics is None:
        metrics = metrics_for(width, height)
    m = metrics.margin
    if metrics.content_tier == CONTENT_COMPACT:
        c = compact_layout_for(width, height, metrics=metrics)
        return NoWifiLayout(
            card=(0, 0, width, height), message=c.top_row, dismiss=c.bl, restart=c.br,
            divider_x=c.divider_x, divider_y=c.divider_y,
        )
    card_w = round(width * NOWIFI_CARD_WIDTH_FRACTION)
    card_h = round(height * NOWIFI_CARD_HEIGHT_FRACTION)
    x0 = (width - card_w) // 2
    y0 = (height - card_h) // 2
    (r0a, r0b), (r1a, r1b) = _split(card_h, m, [1, 1])
    (c0a, c0b), (c1a, c1b) = _split(card_w, m, [1, 1])
    return NoWifiLayout(
        card=(x0, y0, x0 + card_w, y0 + card_h),
        message=(x0, y0 + r0a, x0 + card_w, y0 + r0b),
        dismiss=(x0 + c0a, y0 + r1a, x0 + c0b, y0 + r1b),
        restart=(x0 + c1a, y0 + r1a, x0 + c1b, y0 + r1b),
        divider_x=x0 + (c0b + c1a) // 2,
        divider_y=y0 + (r0b + r1a) // 2,
    )


@dataclass(frozen=True)
class SdHealthLayout:
    """The SD card warning: the No-WiFi card's own rectangle and message
    row, with the bottom row left undivided as one Dismiss cell (there is
    no second action: a worn card cannot be repaired from here)."""

    card: Rect
    message: Rect
    dismiss: Rect
    divider_y: int


def sdhealth_layout_for(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> SdHealthLayout:
    """Derived from nowifi_layout_for(): same card, same message row, same
    horizontal divider; dismiss spans from the No-WiFi Dismiss cell's left
    edge to its Restart cell's right edge."""
    n = nowifi_layout_for(width, height, metrics=metrics)
    dismiss = (n.dismiss[0], n.dismiss[1], n.restart[2], n.restart[3])
    return SdHealthLayout(card=n.card, message=n.message, dismiss=dismiss, divider_y=n.divider_y)


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

    # The inter-band strip: the whole width, rows strictly between the two
    # dimmed bands. A tap here hides them (see the ARTWORK zone) — it never
    # overlaps a real control (the bands own everything else), so it is
    # simply the panel with the bands themselves removed.
    artwork: Rect = (0, band_h, width, height - band_h)

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
        artwork=artwork,
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
    main), then NAME (opens the appliance selector), then OUTPUTS (the
    volume readout, opens the outputs list, same as the main screen), then
    the middle row (REPEAT_PLAY), then START, then STOP, else None (a dead
    zone). State-agnostic like every other hit-test here — the display
    decides whether a hit means anything in the CURRENT layout (REPEAT_PLAY
    is drawn only in the enable layout, START/STOP only in the replaying
    layout; see dial_display_compositor.compose_repeat)."""
    hit = hit_test(GEOMETRY_REPEAT, x, y, width, height)
    return hit.zone if hit is not None else None


@dataclass(frozen=True)
class EqBarLayout:
    """One bar row's geometry on the EQ page (bass or treble) — a
    band-high square stepper at each end, a caption (label left, dB right)
    in the upper half of the space between them, and a track (the dB scale
    line and its marker) in the lower half."""

    row: Rect        # the whole bar row
    down: Rect       # "-" (== EQ_*_DOWN)
    up: Rect         # "+" (== EQ_*_UP)
    caption: Rect    # upper half between the controls: label left, dB right
    track: Rect      # lower half between the controls: the track line and marker
    track_x0: int
    track_x1: int
    track_y: int
    centre_x: int


@dataclass(frozen=True)
class EqLayout:
    """Full EQ-page geometry for one panel size — rich/large only. `dots`,
    `name`, `volume_cluster` and `top_band` are exactly layout_for()'s own
    rectangles (the shared top band this page reuses, unchanged); `bass`
    and `treble` are the two bar rows filling the rest of the panel."""

    dots: Rect
    name: Rect
    volume_cluster: Rect
    top_band: Rect
    bass: EqBarLayout
    treble: EqBarLayout


def eq_layout_for(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> EqLayout:
    """Compute the EQ page's geometry: the shared top band (reused from
    layout_for(), unchanged) over two equal bar rows tiling the rest of the
    panel (_split's own dead-zone gap falls between them). Each bar's own
    controls are a band-high square at each end; the space between them
    splits into an upper caption half and a lower track half."""
    if metrics is None:
        metrics = metrics_for(width, height)
    layout = layout_for(width, height, metrics=metrics)
    m, band_h, pad = metrics.margin, metrics.band_h, metrics.pad
    (a0, a1), (b0, b1) = _split(height - band_h, m, [1, 1])

    def bar(y0: int, y1: int) -> EqBarLayout:
        ctrl = band_h
        down: Rect = (m, y0, m + ctrl, y1)
        up: Rect = (width - m - ctrl, y0, width - m, y1)
        inner_x0, inner_x1 = down[2] + 2 * m, up[0] - 2 * m
        mid = (y0 + y1) // 2
        return EqBarLayout(
            row=(m, y0, width - m, y1), down=down, up=up,
            caption=(inner_x0, y0, inner_x1, mid), track=(inner_x0, mid, inner_x1, y1),
            track_x0=inner_x0 + pad, track_x1=inner_x1 - pad, track_y=(mid + y1) // 2,
            centre_x=(inner_x0 + inner_x1) // 2,
        )

    return EqLayout(
        dots=layout.dots, name=layout.name, volume_cluster=layout.volume_cluster,
        top_band=layout.top_band,
        bass=bar(band_h + a0, band_h + a1), treble=bar(band_h + b0, band_h + b1),
    )


def idle_layout_for(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> IdleLayout:
    """Compute the idle-screen geometry: the affordance line is the same
    centre-low rectangle the main surface's (non-actuating) artist line
    occupies; replay is the whole panel below the top band — or, on the
    compact tier (which has no top band of its own to exclude), the whole
    panel; info is an 8mm-floor square in the top-right corner (the
    fingertip floor wherever density is known, else a band-high square),
    reachable on every idle dial regardless of tier or replay availability;
    wifi is the identical square mirrored into the top-left corner."""
    if metrics is None:
        metrics = metrics_for(width, height)
    layout = layout_for(width, height, metrics=metrics)
    m = metrics.margin
    side = metrics.touch_min_px if metrics.touch_min_px is not None else metrics.band_h
    info: Rect = (width - m - side, m, width - m, m + side)
    wifi: Rect = (m, m, m + side, m + side)
    if metrics.content_tier == CONTENT_COMPACT:
        return IdleLayout(affordance=layout.artist, replay=(0, 0, width, height), info=info, wifi=wifi)
    return IdleLayout(affordance=layout.artist, replay=(0, layout.top_band[3], width, height), info=info, wifi=wifi)


def idle_zone_at(x: int, y: int, width: int, height: int) -> TouchZone | None:
    """Return IDLE_REPLAY for any point below the top band, else None. The
    top band is excluded so an accidental brush up there — where the name
    and volume cluster live on the main surface — does nothing on it."""
    hit = hit_test(GEOMETRY_IDLE, x, y, width, height)
    return hit.zone if hit is not None else None
