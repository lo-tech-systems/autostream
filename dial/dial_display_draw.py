"""dial_display_draw.py -- the drawing primitives under the screen renderers.

Fonts (DejaVu Sans with a fallback chain, memoised), safe text measuring and
drawing, truncating, wrapping and fitting, the per-element soft halo, labels,
the supersampled glyph-tile cache and the painters that fill it, and the
canvas primitives (dimming and wash rectangles, the new-frame background,
the rotate/BGR finish).

Drawing never raises. Every text draw or measure goes through
_draw_text_safe()/_text_size(), so the worst case is a frame with glyphs
but no text; see _load_font() for the font fallback chain. Text over
arbitrary artwork gets a per-element soft dark halo (_draw_text_with_halo()).

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import functools
import logging

from PIL import Image, ImageDraw, ImageEnhance, ImageFilter, ImageFont

from dial_appliance_warnings import SEVERITY_CRITICAL, SEVERITY_WARNING
from dial_display_palette import (
    GLYPH_RGB,
    PRESSED_FILL_RGB,
    PRESSED_FILL_ALPHA,
    ROW_HIGHLIGHT_RGB,
    ROW_HIGHLIGHT_ALPHA,
    HALO_RGBA,
    LIST_BG_RGB,
    DIMMED_GLYPH_RGB,
    BELL_INFO_RGB,
    OVERLAY_DIM_FACTOR,
    BELL_WARNING_RGB,
    BELL_CRITICAL_RGB,
)
from dial_display_views import BG_BASE, BellBadge
from dial_layout_metrics import LayoutMetrics

_LANCZOS = Image.Resampling.LANCZOS
_BOX = Image.Resampling.BOX

_logger = logging.getLogger(__name__)

# DejaVu Sans, installed by the dial installer via fonts-dejavu-core (see
# installer/dial/helpers.sh install_image_packages()).
DEJAVU_SANS_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"

# Small glyphs (the selector's check mark and back/down/up chevrons) are
# drawn at this multiple of their target box size on a transparent layer,
# then downsampled with LANCZOS — antialiasing applied per glyph, not to
# the whole frame. See _draw_glyph().
_GLYPH_SUPERSAMPLE = 4


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


def _dim_rect(frame: Image.Image, rect: tuple[int, int, int, int]) -> None:
    """Dim *rect* of *frame* in place to OVERLAY_DIM_FACTOR of its original
    brightness, leaving every pixel outside the rect untouched. Used for the
    top and bottom bands only — the middle half of the panel keeps full
    artwork brightness."""
    region = frame.crop(rect)
    dimmed_region = ImageEnhance.Brightness(region).enhance(OVERLAY_DIM_FACTOR)
    frame.paste(dimmed_region, rect[:2])


def _draw_wash(image: Image.Image, rect: tuple[int, int, int, int], rgb, alpha: int) -> None:
    """Alpha-composite a translucent *rgb* wash at *alpha* over *rect*.
    Built and applied at *rect*'s own size only — the same crop/composite/
    paste shape _draw_text_with_halo() and _draw_glyph() use — so nothing
    outside the rectangle is even touched by the composite. The pressed
    highlight and the list's current-row wash are both this, at different
    strengths."""
    x0, y0, x1, y1 = rect
    w, h = x1 - x0, y1 - y0
    if w <= 0 or h <= 0:
        return
    wash_layer = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    ImageDraw.Draw(wash_layer).rectangle([0, 0, w - 1, h - 1], fill=(*rgb, alpha))
    region = image.crop(rect).convert("RGBA")
    composited = Image.alpha_composite(region, wash_layer).convert("RGB")
    image.paste(composited, (x0, y0))


def _draw_pressed_highlight(image: Image.Image, rect: tuple[int, int, int, int]) -> None:
    """The pressed-zone wash: _draw_wash at the press strength."""
    _draw_wash(image, rect, PRESSED_FILL_RGB, PRESSED_FILL_ALPHA)


def _draw_row_highlight(image: Image.Image, rect: tuple[int, int, int, int]) -> None:
    """The list's current-row wash: _draw_wash at the fainter row strength."""
    _draw_wash(image, rect, ROW_HIGHLIGHT_RGB, ROW_HIGHLIGHT_ALPHA)


def _zone_center_and_span(rect: tuple[int, int, int, int]) -> tuple[int, int, int]:
    """Return (center_x, center_y, glyph_radius) for a zone rectangle — the
    glyph is sized from the smaller of the zone's own width/height so it
    never overflows the (possibly non-square) zone rectangle."""
    x0, y0, x1, y1 = rect
    cx = (x0 + x1) // 2
    cy = (y0 + y1) // 2
    radius = max(2, min(x1 - x0, y1 - y0) // 4)
    return cx, cy, radius


def _draw_minus_glyph(draw: ImageDraw.ImageDraw, rect: tuple[int, int, int, int], color=GLYPH_RGB) -> None:
    cx, cy, r = _zone_center_and_span(rect)
    width = max(1, r // 3)
    draw.line([(cx - r, cy), (cx + r, cy)], fill=color, width=width)


def _draw_plus_glyph(draw: ImageDraw.ImageDraw, rect: tuple[int, int, int, int], color=GLYPH_RGB) -> None:
    cx, cy, r = _zone_center_and_span(rect)
    stroke = max(1, r // 3)
    draw.line([(cx - r, cy), (cx + r, cy)], fill=color, width=stroke)
    draw.line([(cx, cy - r), (cx, cy + r)], fill=color, width=stroke)


def _draw_speaker_glyph(
    draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], muted: bool | None, color=GLYPH_RGB,
) -> None:
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
    draw.rectangle(rect_box, fill=color)
    cone_tip_x = body_left + body_w + r // 2
    draw.polygon(
        [
            (body_left + body_w, cy - body_h // 2),
            (body_left + body_w, cy + body_h // 2),
            (cone_tip_x, cy - r),
            (cone_tip_x, cy + r),
        ],
        fill=color,
    )

    if muted:
        # Centred over the speaker body, not the glyph box: the body sits
        # left of centre so the sound waves have room, and a slash centred
        # on the box reads as trailing off to the right of it. Same length
        # and angle as a box-centred slash, just shifted left so its own
        # midpoint sits over the body's.
        body_cx = (body_left + cone_tip_x) // 2
        draw.line(
            [(body_cx - r, cy - r), (body_cx + r, cy + r)],
            fill=color,
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
            draw.arc(box_arc, start=-45, end=45, fill=color, width=stroke)


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


def _draw_text_safe(
    draw: ImageDraw.ImageDraw, xy: tuple[int, int], text: str, font, fill=GLYPH_RGB,
) -> bool:
    """Draw *text* at *xy* in *fill* (the glyph colour by default), guarded
    so a Pillow/font failure degrades to "no text drawn" rather than an
    exception escaping compose(). Returns True on success, False if the
    draw call raised. *fill* is overridable so a disabled repeat-screen
    label can be drawn dimmed without a separate code path."""
    try:
        draw.text(xy, text, font=font, fill=fill)
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


def _wrap_words(draw: ImageDraw.ImageDraw, text: str, font, max_w: int) -> "tuple[str, ...]":
    """Greedy word-wrap of *text* into lines no wider than *max_w* pixels in
    *font* (measured by _text_size); a single token wider than *max_w* is
    broken by character. Always returns at least one line (the text itself
    when it has no words)."""
    def fits(s: str) -> bool:
        measured = _text_size(draw, s, font)
        return measured is not None and measured[0] <= max_w

    lines: list[str] = []
    current = ""
    for word in text.split():
        candidate = f"{current} {word}".strip()
        if fits(candidate):
            current = candidate
            continue
        if current:
            lines.append(current)
            current = ""
        if fits(word):
            current = word
            continue
        # word alone is wider than the area: break it by character.
        chunk = ""
        for ch in word:
            piece = chunk + ch
            if fits(piece) or not chunk:
                chunk = piece
            else:
                lines.append(chunk)
                chunk = ch
        current = chunk
    if current:
        lines.append(current)
    return tuple(lines) if lines else (text,)


def _cap_lines(
    draw: ImageDraw.ImageDraw, lines: "tuple[str, ...]", count: int, font, max_w: int,
) -> "tuple[str, ...]":
    """The first *count* of *lines*, the last one ellipsized with
    _truncate_to_width. The dropped remainder (if any) is folded back into
    the last kept line before truncating it, so _truncate_to_width always
    has more than fits and the ellipsis actually appears; a lone kept line
    that already fit on its own would otherwise come back unchanged."""
    kept = list(lines[:count])
    if kept:
        remainder = " ".join(lines[count:])
        tail = f"{kept[-1]} {remainder}".strip() if remainder else kept[-1]
        kept[-1] = _truncate_to_width(draw, tail, font, max_w)
    return tuple(kept)


def _fit_value_lines(
    draw: ImageDraw.ImageDraw, text: str, sizes: "tuple[int, ...]", rect: "tuple[int, int, int, int]",
) -> "tuple[tuple[str, ...], object]":
    """Fit *text* into *rect* (the compact info page's own value area — see
    InfoValueLayout.value) for the drill-in view: try each of *sizes* in
    turn, largest first — greedy word-wrap measured by _text_size, a single
    token wider than the area broken by character — and accept the first
    size whose wrapped block (line count * 1.2 * font size) fits the rect's
    height. When every size still overflows, the last size's lines are kept
    up to however many fit and the final one is ellipsized with
    _truncate_to_width, so something legible is always shown rather than
    spilling past the rect. Returns ((), None) when no size in *sizes* has a
    loadable font — the caller then draws nothing, the same
    degrade-gracefully discipline every text helper in this module follows.
    Pure: no state, no I/O beyond the *draw* measuring calls _text_size
    already makes safely."""
    max_w = rect[2] - rect[0]
    max_h = rect[3] - rect[1]

    last_lines: "tuple[str, ...]" = ()
    last_font = None
    last_size = None
    for size in sizes:
        font = _load_font(size)
        if font is None:
            continue
        lines = _wrap_words(draw, text, font, max_w)
        last_lines, last_font, last_size = lines, font, size
        line_h = size * 1.2
        if line_h > 0 and len(lines) * line_h <= max_h:
            return lines, font
    if last_font is None:
        return (), None
    line_h = last_size * 1.2
    max_lines = max(1, int(max_h // line_h)) if line_h > 0 else 1
    return _cap_lines(draw, last_lines, max_lines, last_font, max_w), last_font


def _draw_text_with_halo(
    frame: Image.Image,
    rect: tuple[int, int, int, int],
    text: str,
    font,
    metrics: LayoutMetrics,
    *,
    align: str = "left",
) -> None:
    """Draw *text* inside *rect* (left-aligned, or centred when
    align="center"), legible over arbitrary album art: a soft,
    Gaussian-blurred dark glow is composited behind the text before the
    text itself is drawn in the glyph colour. Used for the appliance name,
    album, title and artist lines (left-aligned) and the repeat screen's
    replaying-layout position line (centred, over its own artwork/logo base
    image) — see the module docstring's halo paragraph.

    A blank *text*, a missing *font*, truncation-to-nothing, or any Pillow
    failure while building the halo all degrade gracefully: the halo step
    is skipped/caught and the plain text still gets drawn (matching every
    other text helper's discipline of never letting a text failure escape
    compose()). The halo itself is confined strictly to *rect* — it is
    composited on a *rect*-sized layer and pasted back into *rect* only, so
    it can never bleed into a neighbouring zone.
    """
    if not text or font is None:
        return

    draw = ImageDraw.Draw(frame)
    pad = metrics.pad
    max_w = rect[2] - rect[0] - pad
    if max_w <= 0:
        return
    truncated = _truncate_to_width(draw, text, font, max_w)
    if not truncated:
        return

    measured = _text_size(draw, truncated, font)
    if measured is None:
        return
    text_w, text_h, bbox = measured
    left, top, _, _ = bbox
    cy = (rect[1] + rect[3]) // 2
    if align == "center":
        x = rect[0] + max(0, (rect[2] - rect[0] - text_w) // 2)
    else:
        x = rect[0] + pad
    y = cy - text_h // 2
    xy = (x - left, y - top)

    rect_w, rect_h = rect[2] - rect[0], rect[3] - rect[1]
    if rect_w > 0 and rect_h > 0:
        try:
            stroke = metrics.halo_stroke
            radius = metrics.halo_blur
            local_xy = (xy[0] - rect[0], xy[1] - rect[1])
            halo_layer = _halo_layer(truncated, font, local_xy, rect_w, rect_h, stroke, radius)
            region = frame.crop(rect).convert("RGBA")
            composited = Image.alpha_composite(region, halo_layer).convert("RGB")
            frame.paste(composited, (rect[0], rect[1]))
        except Exception:
            pass  # the halo is cosmetic only — fall through to plain text.

    _draw_text_safe(ImageDraw.Draw(frame), xy, truncated, font)


@functools.lru_cache(maxsize=16)
def _halo_layer(text: str, font, local_xy: tuple[int, int], w: int, h: int, stroke: int, radius: int):
    """The blurred, dark-glow layer drawn behind a piece of halo text: a
    pure function of the already-truncated text, the font object, the local
    position the text is drawn at within a (w, h) layer, the stroke width
    and the blur radius — memoised the same way _load_font() memoises a
    loaded font. Keying on the font object itself (rather than, say, its
    point size) means a font reload or a fallback to a different face is
    always a fresh key, never a stale hit.
    """
    layer = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    ImageDraw.Draw(layer).text(
        local_xy, text, font=font, fill=HALO_RGBA, stroke_width=stroke, stroke_fill=HALO_RGBA,
    )
    return layer.filter(ImageFilter.GaussianBlur(radius))


# Kinds for _draw_glyph()'s tile cache — an opaque paint callback cannot be
# hashed as a cache key, so each small glyph identifies itself by one of
# these string constants plus a tuple of hashable parameters. See
# _GLYPH_PAINTERS (below the painter functions) and _glyph_tile().
GLYPH_CHEVRON = "chevron"              # params: (direction, lit)
GLYPH_TWO_DOTS = "two_dots"            # params: (filled,) or (filled, color)
GLYPH_PAGE_DOTS = "page_dots"          # params: (count, filled) or (count, filled, color)
GLYPH_ARM_DOT = "arm_dot"              # params: (armed,)
GLYPH_PLAY = "play"                    # params: () — the selector's "playing" row marker
GLYPH_CROSS = "cross"                  # params: () — the rail's back/cancel control
GLYPH_MUTE = "mute"                    # params: () or (color,) — the main screen's footer mute cell
GLYPH_SPEAKER = "speaker"              # no params — the top band's volume readout icon
GLYPH_RESTART = "restart"              # params: (color,) — the compact tier's Restart control
GLYPH_STOP = "stop"                    # params: (color,) — the compact tier's Stop control
GLYPH_BELL = "bell"                    # params: (severity, count or None) — the warning bell
GLYPH_WIFI = "wifi"                    # params: (lit, color) — the idle screen's Wi-Fi status glyph

# The bell's fill by the worst severity it holds (an informational entry
# uses BELL_INFO_RGB).
_BELL_RGB = {
    SEVERITY_WARNING: BELL_WARNING_RGB,
    SEVERITY_CRITICAL: BELL_CRITICAL_RGB,
}


@functools.lru_cache(maxsize=48)
def _glyph_tile(kind: str, params: tuple, w: int, h: int, supersample: int):
    """The downsampled RGBA tile for one small glyph at one size: a
    transparent canvas at *supersample* times (w, h) is painted by the
    kind's entry in _GLYPH_PAINTERS, then downsampled with LANCZOS. A pure
    function of its arguments, memoised the same way _load_font() memoises a
    loaded font — see that function's statelessness note. Raises on a
    Pillow failure so nothing is cached for a failed paint; the caller
    (_draw_glyph) is responsible for swallowing that.
    """
    big_w, big_h = w * supersample, h * supersample
    big = Image.new("RGBA", (big_w, big_h), (0, 0, 0, 0))
    _GLYPH_PAINTERS[kind](ImageDraw.Draw(big), big_w, big_h, *params)
    return big.resize((w, h), _LANCZOS)


def _draw_glyph(
    frame: Image.Image, rect: tuple[int, int, int, int], kind: str, *params,
    supersample: int = _GLYPH_SUPERSAMPLE,
) -> None:
    """Draw a small glyph antialiased into *rect*: *kind* plus *params*
    identifies a memoised, downsampled tile (see _glyph_tile()), rendered at
    _GLYPH_SUPERSAMPLE times *rect*'s size and downsampled with LANCZOS, then
    alpha-composited over the cropped frame region and pasted back. Used for
    the list's play marker and chevrons and the header's pager dots, whose
    diagonal strokes and curves would otherwise alias visibly at
    these small sizes — the same per-element (never whole-frame)
    antialiasing the halo helper above applies to text. Any Pillow failure,
    including one raised while painting a tile that therefore never gets
    cached, is swallowed here: a glyph that fails to render simply does not
    appear, never an exception.
    """
    x0, y0, x1, y1 = rect
    w, h = x1 - x0, y1 - y0
    if w <= 0 or h <= 0:
        return
    try:
        tile = _glyph_tile(kind, tuple(params), w, h, supersample)
        region = frame.crop(rect).convert("RGBA")
        composited = Image.alpha_composite(region, tile).convert("RGB")
        frame.paste(composited, (x0, y0))
    except Exception:
        pass


def _centred_box(rect: tuple[int, int, int, int], side: int) -> tuple[int, int, int, int]:
    """A *side*-by-*side* box centred within *rect* — used to draw a small
    glyph inside a much larger touch zone (the rail's controls, the header's
    own back control) rather than stretching it across the whole zone, so
    the glyph's own size can shrink independently of the zone's own touch
    floor."""
    x0, y0, x1, y1 = rect
    cx, cy = (x0 + x1) // 2, (y0 + y1) // 2
    half = side // 2
    return (cx - half, cy - half, cx - half + side, cy - half + side)


def _draw_chevron(draw: ImageDraw.ImageDraw, w: int, h: int, direction: str, lit: bool) -> None:
    """A simple two-segment chevron (back/down/up) into a (w, h) canvas —
    see _draw_glyph. *lit*=False dims it to OVERLAY_DIM_FACTOR of the glyph
    colour, matching a disabled/no-more-pages affordance."""
    stroke = max(1, min(w, h) // 7)
    color = GLYPH_RGB if lit else tuple(round(c * OVERLAY_DIM_FACTOR) for c in GLYPH_RGB)
    cx, cy = w / 2, h / 2
    r = min(w, h) * 0.28
    if direction == "left":
        points = [(cx + r, cy - r), (cx - r, cy), (cx + r, cy + r)]
    elif direction == "down":
        points = [(cx - r, cy - r), (cx, cy + r), (cx + r, cy - r)]
    else:  # "up"
        points = [(cx - r, cy + r), (cx, cy - r), (cx + r, cy + r)]
    draw.line(points, fill=color, width=stroke, joint="curve")


def _draw_play_glyph(draw: ImageDraw.ImageDraw, w: int, h: int) -> None:
    """A filled right-pointing triangle — the appliance selector's
    "playing" row marker. Same reach rule as _draw_chevron and
    _draw_cross_glyph (0.28 of the short side) so the list's glyphs read
    as one family; filled rather than stroked because a play mark is
    conventionally solid. Nudged right by a third of its reach so its
    centroid, not its bounding box, sits on the canvas centre — a
    box-centred triangle reads left-heavy. Rendered into a (w, h) canvas —
    see _draw_glyph."""
    r = min(w, h) * 0.28
    cx, cy = w / 2, h / 2
    s = r / 3
    draw.polygon(
        [(cx - r + s, cy - r), (cx - r + s, cy + r), (cx + r + s, cy)],
        fill=GLYPH_RGB,
    )


def _draw_two_dots(draw: ImageDraw.ImageDraw, w: int, h: int, filled: int, color=GLYPH_RGB) -> None:
    """Two small circles side by side, one of them (*filled*: 0 for the
    left one, 1 for the right) drawn solid and the other outlined — the
    main/repeat screen pager dots (also reused, dimmed when inert, as the
    compact tier's own repeat-quadrant glyph). Rendered into a (w, h)
    canvas — see _draw_glyph."""
    r = max(2, round(min(w, h) * 0.12))
    cy = h / 2.0
    gap = r * 3
    cx0 = w / 2.0 - gap / 2.0
    cx1 = w / 2.0 + gap / 2.0
    for i, cx in enumerate((cx0, cx1)):
        box = [cx - r, cy - r, cx + r, cy + r]
        if i == filled:
            draw.ellipse(box, fill=color)
        else:
            draw.ellipse(box, outline=color, width=max(1, r // 3))


def _draw_page_dots(draw: ImageDraw.ImageDraw, w: int, h: int, count: int, filled: int, color=GLYPH_RGB) -> None:
    """*count* small circles evenly spaced, one of them (*filled*) drawn
    solid and the rest outlined — generalises _draw_two_dots for a page
    count other than two (currently only 3, the EQ page's own third dot);
    a smaller radius (0.10 of the short side, against two-dot's 0.12) so
    three dots still fit the same band-high box. Rendered into a (w, h)
    canvas — see _draw_glyph."""
    r = max(2, round(min(w, h) * 0.10))
    cy = h / 2.0
    gap = r * 3
    start = w / 2.0 - gap * (count - 1) / 2.0
    for i in range(count):
        cx = start + gap * i
        box = [cx - r, cy - r, cx + r, cy + r]
        if i == filled:
            draw.ellipse(box, fill=color)
        else:
            draw.ellipse(box, outline=color, width=max(1, r // 3))


def _draw_arm_dot(draw: ImageDraw.ImageDraw, w: int, h: int, armed: bool) -> None:
    """The enable layout's "Repeat Play" row marker: solid white when
    *armed* (the appliance will auto-start a replay on its own), hollow
    (outline only) when disarmed — radius 0.16 of the box. Rendered into a
    (w, h) canvas — see _draw_glyph."""
    r = max(2, round(min(w, h) * 0.16))
    cx, cy = w / 2.0, h / 2.0
    box = [cx - r, cy - r, cx + r, cy + r]
    if armed:
        draw.ellipse(box, fill=GLYPH_RGB)
    else:
        draw.ellipse(box, outline=GLYPH_RGB, width=max(1, r // 3))


def _draw_cross_glyph(draw: ImageDraw.ImageDraw, w: int, h: int) -> None:
    """Two diagonal strokes forming an X — the right-rail's back/cancel
    control. Same stroke width and reach rules as _draw_chevron so the
    three rail glyphs read as one family. Rendered into a (w, h) canvas —
    see _draw_glyph."""
    stroke = max(1, min(w, h) // 7)
    cx, cy = w / 2, h / 2
    r = min(w, h) * 0.28
    draw.line([(cx - r, cy - r), (cx + r, cy + r)], fill=GLYPH_RGB, width=stroke)
    draw.line([(cx - r, cy + r), (cx + r, cy - r)], fill=GLYPH_RGB, width=stroke)


# Fraction of the footer cell's short side the mute glyph's own bounding box
# occupies — generous, since this glyph is the cell's only content (no
# digits beside it, unlike the header's volume_cluster readout).
_MUTE_GLYPH_BOX_FRACTION = 0.56


def _draw_mute_glyph(draw: ImageDraw.ImageDraw, w: int, h: int, color=GLYPH_RGB) -> None:
    """The main screen's own footer mute glyph: the crossed speaker, drawn
    via the same painter the header readout uses (_draw_speaker_glyph),
    always in its muted variant — this cell IS the mute control, so there
    is no unmuted state for it to distinguish. Rendered into a (w, h)
    canvas — see _draw_glyph. Integer box arithmetic throughout: Pillow's
    stroke widths must be ints, and _draw_speaker_glyph derives its own
    stroke width from this box's size. *color* lets the compact tier's
    muted cell invert it to black over its own solid white wash."""
    side = round(min(w, h) * _MUTE_GLYPH_BOX_FRACTION)
    cx, cy = w // 2, h // 2
    half = side // 2
    box = (cx - half, cy - half, cx - half + side, cy - half + side)
    _draw_speaker_glyph(draw, box, muted=True, color=color)


def _draw_speaker_tile(draw: ImageDraw.ImageDraw, w: int, h: int) -> None:
    """The top band's volume readout icon: _draw_speaker_glyph() filling a
    (w, h) canvas — see _draw_glyph."""
    _draw_speaker_glyph(draw, (0, 0, w, h), False)


def _draw_restart_glyph(draw: ImageDraw.ImageDraw, w: int, h: int, color=GLYPH_RGB) -> None:
    """The compact tier's Restart control: the conventional media-player
    "seek to start" icon ("|<<") — a vertical bar near the left edge of the
    glyph's own box, then two filled triangles beside it, both pointing
    left (apex on the left, base on the right), toward the bar. Rendered
    into a (w, h) canvas — see _draw_glyph."""
    short = min(w, h)
    r = short * 0.28
    cx, cy = w / 2, h / 2
    left = cx - r
    right = cx + r

    # The bar: a filled rectangle at the icon's own left edge.
    bar_w = max(2, round(short / 8))
    bar_h = 2 * r * 0.85
    bar_x0, bar_x1 = left, left + bar_w
    bar_y0, bar_y1 = cy - bar_h / 2, cy + bar_h / 2
    draw.rectangle([bar_x0, bar_y0, bar_x1, bar_y1], fill=color)

    # Two left-pointing triangles sharing the remaining width to the
    # icon's right edge, separated from the bar and from each other by the
    # same small gap.
    gap = max(1, bar_w / 2)
    area_x0 = bar_x1 + gap
    tri_w = (right - area_x0 - gap) / 2

    def _triangle(x0: float) -> None:
        draw.polygon(
            [(x0, cy), (x0 + tri_w, cy - bar_h / 2), (x0 + tri_w, cy + bar_h / 2)],
            fill=color,
        )

    _triangle(area_x0)
    _triangle(area_x0 + tri_w + gap)


def _draw_stop_glyph(draw: ImageDraw.ImageDraw, w: int, h: int, color=GLYPH_RGB) -> None:
    """The compact tier's Stop control: a filled square, reach 0.28 of the
    short side (side 0.56 of it), centred — the conventional "stop" glyph.
    Rendered into a (w, h) canvas — see _draw_glyph."""
    side = min(w, h) * 0.56
    cx, cy = w / 2, h / 2
    half = side / 2
    draw.rectangle([cx - half, cy - half, cx + half, cy + half], fill=color)


def _draw_bell_glyph(draw: ImageDraw.ImageDraw, w: int, h: int, severity: str, count: "int | None") -> None:
    """The warning bell: a filled bell (a dome over a flared rim, a knob on
    top, a clapper below) in the severity's colour with the number of
    entries in white across its body (9+ above nine), or no number when
    *count* is None. Drawn from shapes on a
    24-unit grid fitted to the canvas short side, so it reads identically
    across every font fallback. Rendered into a (w, h) canvas — see
    _draw_glyph."""
    u = min(w, h) / 24
    ox, oy = (w - 24 * u) / 2, (h - 24 * u) / 2

    def pt(x, y):
        return (ox + x * u, oy + y * u)

    colour = _BELL_RGB.get(severity, BELL_INFO_RGB)
    draw.ellipse([*pt(10.4, 1.6), *pt(13.6, 4.8)], fill=colour)
    draw.ellipse([*pt(5.2, 3.8), *pt(18.8, 17.4)], fill=colour)
    draw.polygon([pt(5.2, 10.6), pt(18.8, 10.6), pt(18.8, 15.0), pt(21.0, 17.2), pt(21.0, 18.6),
                  pt(3.0, 18.6), pt(3.0, 17.2), pt(5.2, 15.0)], fill=colour)
    draw.pieslice([*pt(9.4, 17.2), *pt(14.6, 22.8)], 0, 180, fill=colour)
    if count is None:
        return
    label = str(count) if count < 10 else "9+"
    box = (*pt(6.0, 6.4), *pt(18.0, 17.0))
    _draw_label_centered(draw, tuple(round(v) for v in box), label, _load_font(max(6, round(u * 9.5))))


def _draw_wifi_glyph(draw: ImageDraw.ImageDraw, w: int, h: int, lit: int, color=GLYPH_RGB) -> None:
    """The idle screen's Wi-Fi status glyph: a dot with three arcs fanning
    upward from it. The innermost *lit* arcs (0..3) and the dot are drawn in
    *color*; the rest in the dimmed glyph shade. lit=0 dims the dot as well,
    so "no link" reads as an entirely grey glyph, and the offline flash's
    red phase passes lit=3 with the alarm colour so every part turns red.

    Sized from the canvas short side S (the whole zone square, not a
    centred sub-box): outer arc radius 0.33 S, arc radii 0.42/0.71/1.00 of
    that, stroke 0.062 S, dot radius 0.78 of the stroke, dot centre at
    0.56 S from the top. The arcs span 222..318 degrees in Pillow's own
    clockwise-from-3-o'clock convention, i.e. a 96 degree fan centred
    straight up. Rendered into a (w, h) canvas — see _draw_glyph."""
    short = min(w, h)
    cx = w / 2
    dot_cy = 0.56 * short
    stroke = max(2, round(short * 0.062))
    outer_r = 0.33 * short
    dot_r = round(stroke * 0.78)
    dim = DIMMED_GLYPH_RGB
    for i, fraction in enumerate((0.42, 0.71, 1.00)):
        r = outer_r * fraction
        arc_color = color if i < lit else dim
        draw.arc([cx - r, dot_cy - r, cx + r, dot_cy + r], start=222, end=318, fill=arc_color, width=stroke)
    dot_color = color if lit > 0 else dim
    draw.ellipse([cx - dot_r, dot_cy - dot_r, cx + dot_r, dot_cy + dot_r], fill=dot_color)


# Dispatch table for _glyph_tile()'s kinded paint step — built here, after
# every painter above is defined, and looked up by name at call time so its
# own position in the module relative to _glyph_tile()/_draw_glyph() (defined
# earlier, alongside the halo-text helper they mirror) does not matter.
_GLYPH_PAINTERS = {
    GLYPH_CHEVRON: _draw_chevron,
    GLYPH_TWO_DOTS: _draw_two_dots,
    GLYPH_PAGE_DOTS: _draw_page_dots,
    GLYPH_ARM_DOT: _draw_arm_dot,
    GLYPH_PLAY: _draw_play_glyph,
    GLYPH_CROSS: _draw_cross_glyph,
    GLYPH_MUTE: _draw_mute_glyph,
    GLYPH_SPEAKER: _draw_speaker_tile,
    GLYPH_RESTART: _draw_restart_glyph,
    GLYPH_STOP: _draw_stop_glyph,
    GLYPH_BELL: _draw_bell_glyph,
    GLYPH_WIFI: _draw_wifi_glyph,
}


def _place_label(draw: ImageDraw.ImageDraw, rect: tuple[int, int, int, int], text: str, font, color, x_for):
    """Draw *text* vertically centred in *rect*, its left edge at
    x_for(rect, text_w), no halo and no truncation. Returns that left edge,
    or None when nothing could be measured (a blank string, a missing font
    or a Pillow failure): the same degrade-gracefully discipline as
    _draw_text_with_halo()."""
    if not text or font is None:
        return None
    measured = _text_size(draw, text, font)
    if measured is None:
        return None
    text_w, text_h, bbox = measured
    left, top, _, _ = bbox
    cy = (rect[1] + rect[3]) // 2
    x = x_for(rect, text_w)
    y = cy - text_h // 2
    _draw_text_safe(draw, (x - left, y - top), text, font, fill=color)
    return x


def _draw_label(
    draw: ImageDraw.ImageDraw, rect: tuple[int, int, int, int], text: str, font, pad: int,
    color=GLYPH_RGB,
) -> None:
    """Draw *text* left-aligned inside *rect*, no halo — used on the flat
    dark repeat-screen background, where (unlike compose()'s overlay over
    arbitrary artwork) there is nothing behind the text to make illegible.
    Degrades to "no text drawn" on a blank string, a missing font,
    truncation-to-nothing, or any Pillow failure — the same discipline as
    _draw_text_with_halo()."""
    if not text or font is None:
        return
    max_w = rect[2] - rect[0] - pad
    if max_w <= 0:
        return
    truncated = _truncate_to_width(draw, text, font, max_w)
    _place_label(draw, rect, truncated, font, color, lambda r, w: r[0] + pad)


def _draw_label_right(
    draw: ImageDraw.ImageDraw, rect: tuple[int, int, int, int], text: str, font, pad: int,
    color=GLYPH_RGB,
) -> None:
    """Draw *text* right-aligned inside *rect*, no halo and no truncation —
    the right-aligned secondary-text path the EQ page's caption row (label
    left, dB right) uses. Same degrade-gracefully discipline as
    _draw_label()."""
    _place_label(draw, rect, text, font, color, lambda r, w: r[2] - pad - w)


def _draw_label_centered(
    draw: ImageDraw.ImageDraw, rect: tuple[int, int, int, int], text: str, font, color=GLYPH_RGB,
) -> None:
    """Draw *text* centred within *rect*, no halo — same degrade-gracefully
    discipline as _draw_label()."""
    _place_label(draw, rect, text, font, color, lambda r, w: (r[0] + r[2]) // 2 - w // 2)


def _tone(on) -> tuple:
    """The glyph colour for a control that is lit (*on*) or dimmed."""
    return GLYPH_RGB if on else DIMMED_GLYPH_RGB


def _new_frame(base, width: int, height: int, background: str) -> Image.Image:
    """Return a fresh (width, height) RGB image to draw a frame into — never
    the caller's own object, so the caller's base image is never mutated by
    what happens next. background == BG_BASE tries to use *base* (a copy of
    it, resized if it is not already panel-sized); anything else, or a base
    that turns out to be unusable, falls back to the flat chassis fill."""
    if background == BG_BASE and base is not None:
        try:
            img = base.convert("RGB")
            if img.size != (width, height):
                img = img.resize((width, height))
            return img
        except Exception:
            pass
    return Image.new("RGB", (width, height), LIST_BG_RGB)


def _finish(img: Image.Image, rotate: bool, bgr: bool) -> Image.Image:
    """Apply the rotate-then-BGR tail every screen shares, in that order.
    Returns *img* itself, unchanged, when neither flag is set."""
    if rotate:
        img = img.transpose(Image.ROTATE_180)
    if bgr:
        img = Image.merge("RGB", img.split()[::-1])
    return img


def _unfinish(img: Image.Image, rotate: bool, bgr: bool) -> Image.Image:
    """Undo _finish: the colour order first, then the rotation, so the
    frame reads as the viewer sees the panel. Returns *img* itself,
    unchanged, when neither flag is set."""
    if bgr:
        img = Image.merge("RGB", img.split()[::-1])
    if rotate:
        img = img.transpose(Image.ROTATE_180)
    return img


def _draw_bell(img: Image.Image, rect, bell: BellBadge, metrics: LayoutMetrics, fraction: float) -> None:
    """The bell glyph centred in *rect* at *fraction* of its short side."""
    side = round(min(rect[2] - rect[0], rect[3] - rect[1]) * fraction)
    _draw_glyph(img, _centred_box(rect, side), GLYPH_BELL, bell.severity, bell.count, supersample=metrics.supersample)
