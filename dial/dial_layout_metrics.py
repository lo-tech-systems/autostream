"""dial_layout_metrics.py -- the dial's physical scaling: one scale rule and
one LayoutMetrics bundle every size-dependent number is read from.

scale_px is the single rule that turns a pixel quantity defined at the
160x128 reference panel into the same proportion on any other. metrics_for
turns a panel size (and, when known, its physical density) into a
LayoutMetrics: the content tier (compact by physical size, then
base/rich/large by the logical short side, with the density-unknown and
touch-short vetoes) and every number that follows from it. Passing
metrics=None anywhere a LayoutMetrics is accepted is the same as
metrics_for(width, height). Arithmetic only: no hardware, no Pillow.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

from dataclasses import dataclass
from math import ceil, floor

# Top and bottom bands each take this fraction of the panel height.
BAND_DIVISOR = 4

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
    if content_tier == CONTENT_LARGE:
        # More room buys more content, not bigger glyphs past a legible size.
        font_body = min(font_body, FONT_BODY_MAX_PX)
        font_readout = min(font_readout, FONT_READOUT_MAX_PX)
        icon = min(icon, FONT_READOUT_MAX_PX)
    if content_tier not in (CONTENT_BASE, CONTENT_COMPACT):
        # The halo is a fine stroke around the text, so it follows the
        # body font rather than the panel: HALO_MAX_PX at the large tier's
        # FONT_BODY_MAX_PX, proportionally less below it. The stroke rounds
        # down and the blur to nearest, which on a 320x240 panel (18 px
        # text, stroke 1, blur 2) matches the same frame composed at
        # 640x480 and box-averaged down to the panel.
        halo_ratio = font_body / FONT_BODY_MAX_PX
        halo_stroke = max(1, floor(HALO_MAX_PX * halo_ratio))
        halo_blur = max(1, round(HALO_MAX_PX * halo_ratio))

    if content_tier in (CONTENT_BASE, CONTENT_COMPACT):
        rail_w = 0
        rail_glyph = 0
    else:
        rail_glyph = icon
        # icon plus its own pad on each side, floored at a fixed minimum —
        # a computed value can undercut the touch floor on a dense rich
        # panel (by design a thinner rail than the header/footer
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
