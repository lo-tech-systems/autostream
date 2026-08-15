"""dial_display_compositor.py — stateless frame composition for the dial
display.

The manager (dial_display.py) owns all I/O: fetching artwork, decoding it,
loading the logo file, deciding what to show and when. This module owns all
pixel work once a base image is in hand — it is the single place a frame is
actually built. It has no threading, no hardware access, no persistent
state, and no lock of its own; every call is independent of every other.

Two kinds of base image reach compose():
  - Artwork: the manager hands over the RAW DECODED image plus the active
    panel (width, height) and sets is_artwork=True. compose() calls
    transform_artwork_for_panel() itself — a "finished frame" is by
    definition already panel-fitted, so that call belongs here rather than
    in the manager.
  - Logo: the manager calls load_logo(...) itself (file I/O, and the
    failure-to-sentinel branch is manager policy) and passes the resulting
    already-panel-sized image with is_artwork=False — compose() then just
    runs it through the transforms below unchanged.

After the base is panel-sized, compose() applies, in order:
  1. overlay — the touch-zone status overlay (mute/down/up glyphs plus a
     pressed-zone highlight), drawn when OverlayState.visible is true. The
     touch session is what makes it visible; overlay=None (the default) or
     an OverlayState with visible=False are both a strict no-op, pixel for
     pixel, which is what a dial with no touch panel always sees.
  2. rotate (180 degrees, when configured)
  3. BGR channel swap (when configured)

The overlay is drawn BEFORE rotate/bgr so its geometry lives in the same
compose-space coordinates as dial_touch_layout.zones_for() — the same
module a future touch session hit-tests against — rather than in
panel/rotated space.

This is the same rotate-then-BGR logic and ordering that previously lived in
dial_display.py's _apply_frame_transform, moved here unchanged. As before,
this seam is bypassed by the backend-internal clear()/sleep() fills, which
paint directly against the backend rather than going through the manager's
_display_locked()/compose() path. sleep()'s black fill is swap-symmetric so
that is harmless; clear()'s background colour is not — an accepted cosmetic
exception, limited to the fallback background and never artwork.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

from dataclasses import dataclass

from PIL import Image, ImageDraw, ImageEnhance

from dial_display_image import transform_artwork_for_panel
from dial_touch_layout import TouchZone, zones_for

# Overlay dim factor: the whole base frame is multiplied down to this
# fraction of its brightness before the zone glyphs are drawn on top, the
# same ImageEnhance.Brightness idiom dial_display_image.py uses for the
# ambient-blur backdrop (see BACKDROP_DARKEN_PERCENT there). 0.32 reads as a
# ~68% dim — dark enough that the glyphs and the pressed-zone highlight are
# unambiguous against any artwork, while the dimmed art is still faintly
# visible behind it. Set against real hardware: 0.4 left bright album art
# competing with the glyphs.
OVERLAY_DIM_FACTOR = 0.32

# Glyph stroke colour and the pressed-zone highlight fill, chosen for
# contrast against the dimmed backdrop produced by OVERLAY_DIM_FACTOR.
_GLYPH_RGB = (255, 255, 255)
_PRESSED_FILL_RGB = (255, 255, 255)
_PRESSED_FILL_ALPHA = 70  # out of 255 — a translucent highlight wash.

# Divider-line colour: light-grey, near-white — a step down from the pure
# white glyphs/highlight so the boundary lines read as structure rather than
# competing with the glyphs for attention.
_DIVIDER_RGB = (200, 200, 200)

# Divider-line width scales with the panel's short side using the same
# reference axis dial_touch_layout._dead_zone_margin uses (128px short side
# -> 1px line), rounded and floored at 1px. This keeps the line reading as a
# thin hairline at the shipped 160x128 profile while thickening modestly
# (2px) on 320x240/240x240 profiles rather than looking lost against a
# bigger panel.
_DIVIDER_REFERENCE_SHORT_SIDE = 128


@dataclass(frozen=True)
class OverlayState:
    """Immutable snapshot of what the touch-zone overlay should show.

    visible: when False (or when overlay is None entirely), compose() draws
        nothing and behaves exactly as it did before this feature existed —
        this is the regression guard the existing compositor tests pin.
    pressed: the TouchZone currently being pressed, or None if no zone is
        pressed. Only meaningful when visible is True.
    muted: tri-state — True draws the muted glyph variant, False the
        unmuted variant, and None (unknown, e.g. nothing selected/playing)
        also draws the unmuted variant. See _draw_mute_glyph() for the
        rationale: "unknown" defaults to the less alarming of the two
        glyphs rather than guessing a muted state that may not be true.
    """

    visible: bool = False
    pressed: TouchZone | None = None
    muted: bool | None = None


class DialDisplayCompositor:
    """Stateless frame composer — holds no attributes that change between
    calls, so a single instance can safely be shared/reused by the manager.
    """

    def compose(
        self,
        base,
        width: int,
        height: int,
        *,
        rotate: bool,
        bgr: bool,
        is_artwork: bool,
        overlay=None,
    ):
        """Build one display-ready frame from *base*.

        base: either the raw decoded artwork image (is_artwork=True) or an
            already panel-sized base such as the logo or a previously
            fitted/cached artwork frame (is_artwork=False).
        width, height: the active panel dimensions — used to fit artwork;
            ignored when is_artwork=False since the base is assumed already
            sized.
        rotate, bgr: transform toggles applied last, in that order.
        is_artwork: when True, runs transform_artwork_for_panel(base, width,
            height) first so the result is panel-fitted.
        overlay: an OverlayState, or None. None or visible=False is a strict
            no-op (existing behaviour, byte-identical). When visible, drawn
            in compose-space before rotate/bgr — see module docstring.
        """
        if base is None:
            return base

        image = base
        if is_artwork:
            image = transform_artwork_for_panel(image, width, height)

        if overlay is not None and overlay.visible:
            image = _draw_overlay(image, image.width, image.height, overlay)

        if rotate:
            image = image.transpose(Image.ROTATE_180)
        if bgr:
            image = Image.merge("RGB", image.split()[::-1])
        return image


def _draw_overlay(image: Image.Image, width: int, height: int, overlay: OverlayState) -> Image.Image:
    """Return a new frame: *image* dimmed, with the three zone glyphs and an
    optional pressed-zone highlight drawn on top, sized from
    dial_touch_layout.zones_for() so this works at every profile size.
    """
    dimmed = ImageEnhance.Brightness(image.convert("RGB")).enhance(OVERLAY_DIM_FACTOR)
    zones = zones_for(width, height)
    draw = ImageDraw.Draw(dimmed)

    if overlay.pressed is not None and overlay.pressed in zones:
        rect = zones[overlay.pressed]
        _draw_pressed_highlight(dimmed, rect)
        # Re-create the draw handle bound to the (possibly RGBA-composited)
        # image so subsequent glyph strokes land on the highlighted frame.
        draw = ImageDraw.Draw(dimmed)

    _draw_mute_glyph(draw, zones[TouchZone.MUTE], overlay.muted)
    _draw_minus_glyph(draw, zones[TouchZone.DOWN])
    _draw_plus_glyph(draw, zones[TouchZone.UP])

    # Divider lines are drawn last, on top of the glyphs and highlight. They
    # never spatially overlap either (they sit in the dead-zone gaps between
    # zones.zones_for() rects, while glyphs/highlight are confined inside
    # those rects), so draw order can't change what's visible — drawing them
    # last simply keeps this as the smallest possible diff (an addition at
    # the end of the function) and means any future overlay content added
    # above the glyphs still can't bury the boundary lines.
    _draw_dividers(draw, zones, width, height)
    return dimmed


def _divider_line_width(width: int, height: int) -> int:
    """Divider line width in pixels, scaled from a 1px-at-128-short-side
    reference — see _DIVIDER_REFERENCE_SHORT_SIDE. Floored at 1px."""
    return max(1, round(min(width, height) / _DIVIDER_REFERENCE_SHORT_SIDE))


def _draw_dividers(
    draw: ImageDraw.ImageDraw,
    zones: dict[TouchZone, tuple[int, int, int, int]],
    width: int,
    height: int,
) -> None:
    """Draw light-grey dividing lines centred in the dead-zone gap between
    each pair of adjacent zone rectangles from *zones* (as returned by
    dial_touch_layout.zones_for()) — never at a hardcoded fraction of the
    panel, so the lines can't disagree with where taps actually land.

    Which pairs are "adjacent" — and whether the boundary is vertical or
    horizontal — is read off the rects themselves rather than re-deriving
    the WIDE/SQUARE choice zones_for() already made:
      - MUTE and DOWN share the same (y0, y1) span in the WIDE layout
        (vertical thirds: MUTE | DOWN | UP, each full-height) -> two
        vertical dividers, MUTE|DOWN and DOWN|UP.
      - Otherwise (SQUARE layout: full-width MUTE band on top, DOWN|UP
        splitting the area below) -> one horizontal divider between the
        MUTE band and the DOWN/UP band, plus one vertical divider between
        DOWN and UP confined to that lower band's own height.
    """
    mute = zones[TouchZone.MUTE]
    down = zones[TouchZone.DOWN]
    up = zones[TouchZone.UP]
    line_width = _divider_line_width(width, height)

    if (mute[1], mute[3]) == (down[1], down[3]) == (up[1], up[3]):
        # WIDE: vertical thirds, all sharing the same full-height span.
        _draw_vertical_divider(draw, mute, down, line_width)
        _draw_vertical_divider(draw, down, up, line_width)
    else:
        # SQUARE: MUTE band on top; DOWN/UP split the band below it.
        _draw_horizontal_divider(draw, mute, down, line_width)
        _draw_vertical_divider(draw, down, up, line_width)


def _draw_vertical_divider(
    draw: ImageDraw.ImageDraw,
    left_rect: tuple[int, int, int, int],
    right_rect: tuple[int, int, int, int],
    line_width: int,
) -> None:
    """Draw a vertical line centred in the horizontal gap between
    *left_rect* (ends at x1) and *right_rect* (starts at x0), spanning the
    union of their vertical extents."""
    x = (left_rect[2] + right_rect[0]) // 2
    y0 = min(left_rect[1], right_rect[1])
    y1 = max(left_rect[3], right_rect[3])
    draw.line([(x, y0), (x, y1 - 1)], fill=_DIVIDER_RGB, width=line_width)


def _draw_horizontal_divider(
    draw: ImageDraw.ImageDraw,
    top_rect: tuple[int, int, int, int],
    bottom_rect: tuple[int, int, int, int],
    line_width: int,
) -> None:
    """Draw a horizontal line centred in the vertical gap between *top_rect*
    (ends at y1) and *bottom_rect* (starts at y0), spanning the union of
    their horizontal extents."""
    y = (top_rect[3] + bottom_rect[1]) // 2
    x0 = min(top_rect[0], bottom_rect[0])
    x1 = max(top_rect[2], bottom_rect[2])
    draw.line([(x0, y), (x1 - 1, y)], fill=_DIVIDER_RGB, width=line_width)


def _draw_pressed_highlight(image: Image.Image, rect: tuple[int, int, int, int]) -> None:
    """Alpha-composite a translucent highlight wash over *rect* so a press
    is visibly acknowledged. Confined strictly to the pressed zone's own
    rectangle — nothing outside it is touched."""
    x0, y0, x1, y1 = rect
    overlay_layer = Image.new("RGBA", image.size, (0, 0, 0, 0))
    ImageDraw.Draw(overlay_layer).rectangle(
        [x0, y0, x1 - 1, y1 - 1], fill=(*_PRESSED_FILL_RGB, _PRESSED_FILL_ALPHA)
    )
    composited = Image.alpha_composite(image.convert("RGBA"), overlay_layer).convert("RGB")
    image.paste(composited)


def _zone_center_and_span(rect: tuple[int, int, int, int]) -> tuple[int, int, int]:
    """Return (center_x, center_y, glyph_radius) for a zone rectangle — the
    glyph is sized from the smaller of the zone's own width/height so it
    never overflows the (possibly non-square) zone rectangle."""
    x0, y0, x1, y1 = rect
    cx = (x0 + x1) // 2
    cy = (y0 + y1) // 2
    radius = max(2, min(x1 - x0, y1 - y0) // 4)
    return cx, cy, radius


def _draw_minus_glyph(draw: ImageDraw.ImageDraw, rect: tuple[int, int, int, int]) -> None:
    cx, cy, r = _zone_center_and_span(rect)
    width = max(1, r // 3)
    draw.line([(cx - r, cy), (cx + r, cy)], fill=_GLYPH_RGB, width=width)


def _draw_plus_glyph(draw: ImageDraw.ImageDraw, rect: tuple[int, int, int, int]) -> None:
    cx, cy, r = _zone_center_and_span(rect)
    stroke = max(1, r // 3)
    draw.line([(cx - r, cy), (cx + r, cy)], fill=_GLYPH_RGB, width=stroke)
    draw.line([(cx, cy - r), (cx, cy + r)], fill=_GLYPH_RGB, width=stroke)


def _draw_mute_glyph(draw: ImageDraw.ImageDraw, rect: tuple[int, int, int, int], muted: bool | None) -> None:
    """Draw a simple speaker glyph: a body (rectangle + triangle "cone") plus
    sound-wave arcs when unmuted, or a diagonal slash through the body when
    muted.

    muted=True -> muted variant (slash). muted=False -> unmuted variant
    (arcs). muted=None ("unknown" — nothing selected/playing, so there is no
    real mute state to report) also draws the unmuted variant: defaulting to
    "not muted" is the less alarming reading of an unknown state and avoids
    implying a mute the user never set.
    """
    cx, cy, r = _zone_center_and_span(rect)
    stroke = max(1, r // 4)

    # Speaker body: a small rectangle (the driver) plus a triangle (the
    # cone), both left-of-center so the wave/slash has room to the right.
    body_w = max(2, r // 2)
    body_h = max(2, r)
    body_left = cx - r
    rect_box = [body_left, cy - body_h // 2, body_left + body_w, cy + body_h // 2]
    draw.rectangle(rect_box, fill=_GLYPH_RGB)
    cone_tip_x = body_left + body_w + r // 2
    draw.polygon(
        [
            (body_left + body_w, cy - body_h // 2),
            (body_left + body_w, cy + body_h // 2),
            (cone_tip_x, cy - r),
            (cone_tip_x, cy + r),
        ],
        fill=_GLYPH_RGB,
    )

    if muted:
        # Diagonal slash through the whole glyph footprint.
        draw.line(
            [(cx - r, cy - r), (cx + r, cy + r)],
            fill=_GLYPH_RGB,
            width=stroke,
        )
    else:
        # Sound-wave arcs to the right of the cone.
        for i in range(1, 3):
            offset = i * max(1, r // 2)
            box = [
                cone_tip_x - r // 3,
                cy - offset,
                cone_tip_x + offset,
                cy + offset,
            ]
            draw.arc(box, start=-45, end=45, fill=_GLYPH_RGB, width=stroke)
