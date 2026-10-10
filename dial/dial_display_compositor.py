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
  1. overlay — the now-playing controls overlay (dimmed top/bottom bands,
     artist name, speaker glyph + master-volume readout, minus/plus glyphs
     and a divider line), drawn when OverlayState.visible is true. The
     touch session is what makes it visible; overlay=None (the default) or
     an OverlayState with visible=False are both a strict no-op, pixel for
     pixel, which is what a dial with no touch panel always sees.
  2. rotate (180 degrees, when configured)
  3. BGR channel swap (when configured)

The overlay is drawn BEFORE rotate/bgr so its geometry lives in the same
compose-space coordinates as dial_touch_layout.layout_for()/zones_for() —
the same module the touch session hit-tests against — rather than in
panel/rotated space.

This is the same rotate-then-BGR logic and ordering that previously lived in
dial_display.py's _apply_frame_transform, moved here unchanged. As before,
this seam is bypassed by the backend-internal clear()/sleep() fills, which
paint directly against the backend rather than going through the manager's
_display_locked()/compose() path. sleep()'s black fill is swap-symmetric so
that is harmless; clear()'s background colour is not — an accepted cosmetic
exception, limited to the fallback background and never artwork.

Text rendering (artist name, volume number) never raises: every draw or
measure call goes through _draw_text_safe()/_text_size(), which swallow any
Pillow/font exception and report failure to the caller instead. The worst
case for a text failure is an overlay with the glyphs but no text — never an
exception escaping compose(). See _load_font() for the font fallback chain
this same discipline extends to.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import functools
import logging
from dataclasses import dataclass

from PIL import Image, ImageDraw, ImageEnhance, ImageFont

from dial_display_image import transform_artwork_for_panel
from dial_touch_layout import OverlayLayout, TouchZone, layout_for, zones_for

_logger = logging.getLogger(__name__)

# Overlay dim factor: the top and bottom bands are multiplied down to this
# fraction of their brightness before the glyphs/text are drawn on top, the
# same ImageEnhance.Brightness idiom dial_display_image.py uses for the
# ambient-blur backdrop (see BACKDROP_DARKEN_PERCENT there). 0.32 reads as a
# ~68% dim — dark enough that the glyphs and the pressed-zone highlight are
# unambiguous against any artwork, while the dimmed art is still faintly
# visible behind it. Set against real hardware: 0.4 left bright album art
# competing with the glyphs. The middle half of the panel is never dimmed.
OVERLAY_DIM_FACTOR = 0.32

# Glyph stroke colour and the pressed-zone highlight fill, chosen for
# contrast against the dimmed backdrop produced by OVERLAY_DIM_FACTOR. Text
# (artist name, volume number) is drawn in the same colour — see
# _draw_text_safe().
_GLYPH_RGB = (255, 255, 255)
_PRESSED_FILL_RGB = (255, 255, 255)
_PRESSED_FILL_ALPHA = 70  # out of 255 — a translucent highlight wash.

# Divider-line colour: pure white, matching the glyph/text colour, so the
# single boundary line between DOWN and UP reads as clean structure against
# the dimmed backdrop rather than blending into it.
_DIVIDER_RGB = (255, 255, 255)

# Divider-line width scales with the panel's short side using the same
# reference axis dial_touch_layout._dead_zone_margin uses (128px short side
# -> 1px line), rounded and floored at 1px. This keeps the line reading as a
# thin hairline at the shipped 160x128 profile while thickening modestly
# (2px) on 320x240/240x240 profiles rather than looking lost against a
# bigger panel.
_DIVIDER_REFERENCE_SHORT_SIDE = 128

# DejaVu Sans, installed by the dial installer via fonts-dejavu-core (see
# installer/dial/helpers.sh install_image_packages()).
DEJAVU_SANS_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"

# Text/padding sizes at the 160x128 reference, scaled by the panel's short
# side (the same axis dial_touch_layout._dead_zone_margin and
# dial_display_image._blur_radius_for use), floored so a tiny panel still
# gets legible text.
_ARTIST_FONT_PX_AT_REFERENCE = 13
_VOLUME_FONT_PX_AT_REFERENCE = 15
_PAD_PX_AT_REFERENCE = 4
_ICON_GAP_PX_AT_REFERENCE = 3
_FONT_REFERENCE_SHORT_SIDE = 128


@dataclass(frozen=True)
class OverlayState:
    """Immutable snapshot of what the now-playing controls overlay should
    show.

    visible: when False (or when overlay is None entirely), compose() draws
        nothing and behaves exactly as it did before this feature existed —
        this is the regression guard the existing compositor tests pin.
    pressed: the TouchZone currently being pressed, or None if no zone is
        pressed. Only meaningful when visible is True.
    muted: tri-state — True draws the muted glyph variant, False the
        unmuted variant, and None (unknown, e.g. nothing selected/playing)
        also draws the unmuted variant. See _draw_speaker_glyph() for the
        rationale: "unknown" defaults to the less alarming of the two
        glyphs rather than guessing a muted state that may not be true.
    artist: the now-playing artist name, or "" to draw no artist text.
        Always safe: an empty string, a too-long string (truncated with an
        ellipsis) and a font-load failure all degrade to "no artist text",
        never an exception.
    volume: the master-volume readout (0-100), or None to draw the speaker
        glyph alone with no digits — used when nothing has been observed
        yet, or when the observation is for a different target. Appended
        after muted so positional construction in existing tests/call sites
        keeps working.
    """

    visible: bool = False
    pressed: TouchZone | None = None
    muted: bool | None = None
    artist: str = ""
    volume: int | None = None


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


def _scaled_px(reference_px: int, width: int, height: int, floor: int) -> int:
    """Scale *reference_px* (defined at the 160x128 reference, short side
    128) to *width* x *height* by the panel's short side, floored at
    *floor* so a tiny panel never loses legible text/padding entirely."""
    return max(floor, round(min(width, height) * reference_px / _FONT_REFERENCE_SHORT_SIDE))


def _pad_px(width: int, height: int) -> int:
    """Padding (px) between a band's edge and the text/glyph drawn inside
    it, scaled from the 160x128 reference."""
    return _scaled_px(_PAD_PX_AT_REFERENCE, width, height, 2)


@functools.lru_cache(maxsize=16)
def _load_font(size: int):
    """Load DejaVu Sans at *size*, falling back in order: the system TTF,
    Pillow's built-in default font (sized when Pillow supports it, else
    unsized), then None meaning "text disabled". Never raises. Memoised per
    size: a font object is immutable and loading it is file I/O, so loading
    once per process is the right cost.

    Statelessness note: the compositor class itself holds no attributes and
    its output is a pure function of its inputs (see TestStatelessness).
    This cache is a memoised loader of an immutable resource, keyed only by
    size — two processes, two compositor instances, or a cleared cache all
    produce identical frames, so it does not violate that in spirit. Tests
    that need a clean slate call _reset_font_cache().
    """
    try:
        return ImageFont.truetype(DEJAVU_SANS_PATH, size)
    except Exception:
        _logger.warning(
            "dial overlay: DejaVu Sans TTF unavailable at %r, falling back "
            "to Pillow's default font", DEJAVU_SANS_PATH,
        )

    try:
        return ImageFont.load_default(size=size)
    except TypeError:
        # Older Pillow: load_default() takes no size argument at all.
        try:
            return ImageFont.load_default()
        except Exception:
            pass
    except Exception:
        pass

    _logger.warning("dial overlay: Pillow's default font is unavailable; overlay text disabled")
    return None


def _reset_font_cache() -> None:
    """Clear the memoised font cache. Test-only hook: lets a test exercise
    the fallback chain from a clean slate without restarting the process."""
    _load_font.cache_clear()


def _draw_overlay(image: Image.Image, width: int, height: int, overlay: OverlayState) -> Image.Image:
    """Return a new frame: *image* with its top/bottom bands dimmed, the
    artist name, volume readout, minus/plus glyphs and a divider line drawn
    on top, plus an optional pressed-zone highlight. Sized from
    dial_touch_layout.layout_for()/zones_for() so this works at every
    profile size.
    """
    layout = layout_for(width, height)
    zones = zones_for(width, height)

    frame = image.convert("RGB")
    _dim_rect(frame, layout.top_band)
    _dim_rect(frame, layout.bottom_band)

    draw = ImageDraw.Draw(frame)
    if overlay.pressed is not None and overlay.pressed in zones:
        rect = zones[overlay.pressed]
        _draw_pressed_highlight(frame, rect)
        # Re-create the draw handle bound to the (possibly RGBA-composited)
        # image so subsequent glyph/text strokes land on the highlighted
        # frame.
        draw = ImageDraw.Draw(frame)

    volume_px = _scaled_px(_VOLUME_FONT_PX_AT_REFERENCE, width, height, 9)
    artist_px = _scaled_px(_ARTIST_FONT_PX_AT_REFERENCE, width, height, 8)
    volume_font = _load_font(volume_px)
    artist_font = _load_font(artist_px)

    _draw_volume_cluster(draw, layout.volume_cluster, overlay.volume, overlay.muted, volume_font, width, height)
    _draw_artist(draw, layout.artist, overlay.artist, artist_font, width, height)
    _draw_minus_glyph(draw, layout.down)
    _draw_plus_glyph(draw, layout.up)
    _draw_band_divider(draw, layout, width, height)
    return frame


def _dim_rect(frame: Image.Image, rect: tuple[int, int, int, int]) -> None:
    """Dim *rect* of *frame* in place to OVERLAY_DIM_FACTOR of its original
    brightness, leaving every pixel outside the rect untouched. Used for the
    top and bottom bands only — the middle half of the panel keeps full
    artwork brightness."""
    region = frame.crop(rect)
    dimmed_region = ImageEnhance.Brightness(region).enhance(OVERLAY_DIM_FACTOR)
    frame.paste(dimmed_region, rect[:2])


def _divider_line_width(width: int, height: int) -> int:
    """Divider line width in pixels, scaled from a 1px-at-128-short-side
    reference — see _DIVIDER_REFERENCE_SHORT_SIDE. Floored at 1px."""
    return max(1, round(min(width, height) / _DIVIDER_REFERENCE_SHORT_SIDE))


def _draw_band_divider(draw: ImageDraw.ImageDraw, layout: OverlayLayout, width: int, height: int) -> None:
    """Draw a single white vertical divider line at layout.divider_x,
    spanning the bottom band from its top edge to its last visible row —
    the boundary between the DOWN and UP glyphs."""
    line_width = _divider_line_width(width, height)
    x = layout.divider_x
    y0 = layout.bottom_band[1]
    y1 = layout.bottom_band[3] - 1
    draw.line([(x, y0), (x, y1)], fill=_DIVIDER_RGB, width=line_width)


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


def _draw_speaker_glyph(draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], muted: bool | None) -> None:
    """Draw a simple speaker glyph: a body (rectangle + triangle "cone") plus
    sound-wave arcs when unmuted, or a diagonal slash through the body when
    muted. Sized from a square *box* (the glyph's own bounding box, not a
    zone rectangle — see _draw_volume_cluster, which lays the icon box out
    to the left of or in place of the volume digits).

    muted=True -> muted variant (slash). muted=False -> unmuted variant
    (arcs). muted=None ("unknown" — nothing selected/playing, so there is no
    real mute state to report) also draws the unmuted variant: defaulting to
    "not muted" is the less alarming reading of an unknown state and avoids
    implying a mute the user never set.
    """
    x0, y0, x1, y1 = box
    cx = (x0 + x1) // 2
    cy = (y0 + y1) // 2
    r = max(2, min(x1 - x0, y1 - y0) // 2 - 1)
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
            box_arc = [
                cone_tip_x - r // 3,
                cy - offset,
                cone_tip_x + offset,
                cy + offset,
            ]
            draw.arc(box_arc, start=-45, end=45, fill=_GLYPH_RGB, width=stroke)


def _text_size(
    draw: ImageDraw.ImageDraw, text: str, font
) -> tuple[int, int, tuple[int, int, int, int]] | None:
    """Measure *text* rendered in *font*: returns (width, height, bbox)
    where bbox is the raw draw.textbbox((0, 0), ...) result, or None if
    measurement raised. Guarded the same way as _draw_text_safe — a None
    here must make the caller skip that text element only, never propagate
    an exception out of compose()."""
    try:
        bbox = draw.textbbox((0, 0), text, font=font)
    except Exception:
        return None
    left, top, right, bottom = bbox
    return right - left, bottom - top, bbox


def _draw_text_safe(draw: ImageDraw.ImageDraw, xy: tuple[int, int], text: str, font) -> bool:
    """Draw *text* at *xy* in the glyph colour, guarded so a Pillow/font
    failure degrades to "no text drawn" rather than an exception escaping
    compose(). Returns True on success, False if the draw call raised."""
    try:
        draw.text(xy, text, font=font, fill=_GLYPH_RGB)
        return True
    except Exception:
        return False


def _truncate_to_width(draw: ImageDraw.ImageDraw, text: str, font, max_w: int) -> str:
    """Shorten *text* so it (plus an ASCII ellipsis when shortened) fits
    within *max_w* pixels in *font*. Returns the unmodified text when it
    already fits, the longest fitting prefix plus "..." when it needs
    shortening, or "" when nothing fits (not even one character plus the
    ellipsis). Uses the three-dot ASCII string, not U+2026, so the bitmap
    fallback font can render it too. A linear scan is fine here: artist
    strings are short and this runs at most once per repaint."""
    measured = _text_size(draw, text, font)
    if measured is not None and measured[0] <= max_w:
        return text

    for end in range(len(text) - 1, 0, -1):
        candidate = text[:end].rstrip() + "..."
        measured = _text_size(draw, candidate, font)
        if measured is not None and measured[0] <= max_w:
            return candidate
    return ""


def _draw_volume_cluster(
    draw: ImageDraw.ImageDraw,
    rect: tuple[int, int, int, int],
    volume: int | None,
    muted: bool | None,
    font,
    width: int,
    height: int,
) -> None:
    """Draw the volume readout inside *rect* (the top band's volume cluster,
    == the MUTE zone): the speaker glyph, right aligned, and — when both a
    *volume* number and a usable *font* are available — the volume digits to
    its left. *width*/*height* are the panel dimensions (not the rect's own
    size): padding, the icon-to-digits gap and the icon's own size all scale
    from the panel's short side, the same reference axis every other overlay
    dimension uses.

    volume=None or font=None draws the glyph alone, right aligned — always
    safe, since _load_font() never raises and this function never assumes a
    font is present.
    """
    pad = _pad_px(width, height)
    gap = _scaled_px(_ICON_GAP_PX_AT_REFERENCE, width, height, 2)
    icon = _scaled_px(_VOLUME_FONT_PX_AT_REFERENCE, width, height, 9)
    cy = (rect[1] + rect[3]) // 2

    x_icon = rect[2] - pad - icon
    if volume is not None and font is not None:
        text = str(volume)
        measured = _text_size(draw, text, font)
        if measured is not None:
            text_w, text_h, bbox = measured
            left, top, _, _ = bbox
            x_text = rect[2] - pad - text_w
            if _draw_text_safe(draw, (x_text - left, cy - text_h // 2 - top), text, font):
                x_icon = x_text - gap - icon

    icon_box = (x_icon, cy - icon // 2, x_icon + icon, cy - icon // 2 + icon)
    _draw_speaker_glyph(draw, icon_box, muted)


def _draw_artist(
    draw: ImageDraw.ImageDraw,
    rect: tuple[int, int, int, int],
    artist: str,
    font,
    width: int,
    height: int,
) -> None:
    """Draw *artist* left-aligned inside *rect* (the artist text area),
    truncated with an ellipsis so it never reaches the volume cluster. A
    blank *artist* string or a missing *font* draws nothing — always safe.
    *width*/*height* are the panel dimensions, used only to scale the pad
    margin (see _draw_volume_cluster)."""
    if not artist or font is None:
        return

    pad = _pad_px(width, height)
    max_w = rect[2] - rect[0] - pad
    text = _truncate_to_width(draw, artist, font, max_w)
    if not text:
        return

    measured = _text_size(draw, text, font)
    if measured is None:
        return
    text_w, text_h, bbox = measured
    left, top, _, _ = bbox
    cy = (rect[1] + rect[3]) // 2
    x = rect[0] + pad
    _draw_text_safe(draw, (x - left, cy - text_h // 2 - top), text, font)
