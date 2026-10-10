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

The appliance name (top-left) and the artist line (centre-low) are both
drawn over arbitrary album art, so both go through _draw_text_with_halo()
rather than a plain draw.text(): a soft, Gaussian-blurred dark glow is
composited behind the text before the text itself is drawn, so it stays
legible whether the artwork behind it is light or dark. The halo is drawn
per element, confined to that element's own rectangle — never as a
whole-frame effect — the same discipline _draw_glyph_supersampled() applies
to the selector chassis's check mark and chevrons (rendered at a higher
resolution and downsampled with LANCZOS, so small diagonal strokes read
smoothly rather than aliasing).

compose_list() is the second top-level entry point this module offers,
alongside compose(): it builds the appliance-selector screen (a dark
chassis with up to three rows and a back|down|up bar) from a ListState
snapshot, sharing dial_touch_layout.list_layout_for()'s geometry with
dial_touch.py's selector-surface hit-test — the same single-source-of-truth
discipline compose()'s overlay geometry already follows. Like compose(), it
applies rotate/BGR last and never raises: a font or glyph failure degrades
to a plainer row, never an exception.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import functools
import logging
from dataclasses import dataclass

from PIL import Image, ImageDraw, ImageEnhance, ImageFilter, ImageFont

from dial_display_image import transform_artwork_for_panel
from dial_touch_layout import (
    OverlayLayout,
    TouchZone,
    layout_for,
    list_layout_for,
    repeat_layout_for,
    zones_for,
)

# Pillow renamed the resample enum in recent versions; fall back for older
# installs, the same guard dial_display_image.py uses for its own resizes.
try:
    _LANCZOS = Image.Resampling.LANCZOS
except AttributeError:
    _LANCZOS = Image.LANCZOS

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

# Halo (soft dark glow behind text drawn over artwork — see the module
# docstring and _draw_text_with_halo()). The stroke gives the glyph outline
# its dark "ink"; the blur then softens that outline into a glow rather than
# a hard silhouette. Both scale with the panel's short side, the same
# reference axis every other overlay dimension uses.
_HALO_STROKE_PX_AT_REFERENCE = 2
_HALO_BLUR_RADIUS_AT_REFERENCE = 2
_HALO_RGBA = (0, 0, 0, 255)

# Selector chassis (compose_list) — a dark background distinct from any
# artwork, so the list unambiguously reads as a different screen.
_LIST_BG_RGB = (16, 16, 16)
_LIST_SEPARATOR_RGB = (48, 48, 48)

# Small glyphs (the selector's check mark and back/down/up chevrons) are
# drawn at this multiple of their target box size on a transparent layer,
# then downsampled with LANCZOS — antialiasing applied per glyph, not to
# the whole frame. See _draw_glyph_supersampled().
_GLYPH_SUPERSAMPLE = 4

# A disabled repeat-screen label (Start/Stop when the daemon state does not
# accept that action right now) is drawn in this dimmed shade of the glyph
# colour — the same OVERLAY_DIM_FACTOR the overlay's chevrons use for their
# own disabled state.
_DIMMED_GLYPH_RGB = tuple(round(c * OVERLAY_DIM_FACTOR) for c in _GLYPH_RGB)

# The selector/picker row "currently replaying" marker (see LOOP_GLYPH
# below) is drawn in this accent colour rather than the plain glyph white,
# so it reads as a status marker distinct from the check mark and chevrons.
_LOOP_GLYPH_RGB = (100, 149, 237)


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
    name: the appliance's display name, or "" to draw nothing and leave the
        NAME tap-zone inert. Always visible whenever a focused/controllable
        appliance is shown — never gated on how many appliances are
        authorized. Drawn top-left with a soft halo (see
        _draw_text_with_halo()), the same as the artist line. Appended last
        so positional construction in existing tests/call sites keeps
        working.
    dots: whether the two repeat-screen pager dots are drawn, left of the
        name. False leaves the NAME text's own rect untouched — the dots
        rect is a separate zone carved out of the top band (see
        dial_touch_layout.layout_for). Appended after name/title so
        existing positional construction keeps working.
    """

    visible: bool = False
    pressed: TouchZone | None = None
    muted: bool | None = None
    artist: str = ""
    volume: int | None = None
    name: str = ""
    title: str = ""
    dots: bool = False


@dataclass(frozen=True)
class ListState:
    """Immutable snapshot of what the appliance-selector screen should show
    — the compose_list() counterpart to OverlayState. Built by the display
    manager from its SelectorState (dial_display.py) on the repaint thread;
    this module has no idea what an "appliance" is, only rows to draw.

    rows: (label, checked) pairs for the CURRENT page only — at most
        ListLayout.rows_per_page entries (3 on every shipped profile).
        checked marks the row that is the current focus. A row may instead
        be a (label, checked, secondary) triple: secondary is drawn right-
        aligned when it is a plain non-empty string (the replay picker's
        buffer length, e.g. "42:10"), or, when it is the LOOP_GLYPH
        sentinel, draws the accent-coloured "currently replaying" marker in
        the row's dot box instead of text (used by the appliance selector).
        A 2-tuple row is byte-identical to before this field existed.
    has_prev: whether a previous page exists — gates whether the LIST_UP
        chevron is drawn lit (see dial_touch_layout.ListLayout.up and the
        LIST_UP -> selector_page(-1) dispatch in dial_main.py).
    has_next: whether a next page exists — gates the LIST_DOWN chevron
        (selector_page(+1)).
    pressed: the (TouchZone, index) currently being pressed, or None. index
        is only meaningful for LIST_ROW; the other zones ignore it. Mirrors
        OverlayState.pressed for the main surface.
    """

    rows: tuple = ()
    has_prev: bool = False
    has_next: bool = False
    pressed: tuple[TouchZone, int | None] | None = None


class _LoopGlyphSentinel:
    """Unique marker for a ListState row's secondary slot — see ListState's
    docstring. A dedicated object (rather than a string like "loop") so it
    can never collide with genuine row text."""

    def __repr__(self) -> str:
        return "LOOP_GLYPH"


LOOP_GLYPH = _LoopGlyphSentinel()


@dataclass(frozen=True)
class RepeatViewState:
    """Immutable snapshot of what the repeat screen should show — the
    compose_repeat() counterpart to OverlayState/ListState. Built by the
    display manager from its repeat-store record (dial_display.py) on the
    repeat-screen compose path; this module has no idea what a daemon state
    is, only a layout name and the fields that layout draws.

    Both layouts share the same top band the main screen's now-playing
    overlay uses (dots, name, mute/volume readout — see _draw_top_band_
    content()); `name`, `muted` and `volume` feed that shared piece, drawn
    without the main screen's halo (there is no arbitrary album art behind
    it in the enable layout, and the replaying layout's own base image is
    already dimmed there — see compose_repeat()'s `base` argument).

    name: the appliance's display name.
    layout: "enable" (a live source is playing or about to; draws the
        "Repeat Play" row) or "replaying" (draws the Restart/Stop row and
        the position line, over the current artwork/logo base image).
    armed: whether the daemon will auto-start a replay on its own — read by
        the enable layout's row marker (a hollow dot when False, solid when
        True). Meaningful in either layout, but only drawn in "enable".
    muted, volume: the top band's mute/volume readout — display-only on
        this screen (no touch zone), mirroring OverlayState.muted/volume.
    line: the centre text for the "replaying" layout ("0:00 / 3:12" style);
        ignored (nothing drawn) in "enable".
    start_enabled, stop_enabled: whether the Restart/Stop label is drawn at
        full brightness (True) or dimmed (False) — "replaying" layout only.
    stop_pressed: whether Stop is drawn with a pressed wash regardless of
        an actual touch — used while a fade-out is already in flight, so
        the button visibly reads as "already actioned, no further tap
        needed" rather than merely dimmed.
    pressed: the TouchZone currently being pressed by a genuine touch, or
        None. Mirrors OverlayState.pressed/ListState.pressed.
    """

    name: str
    layout: str
    armed: bool
    line: str
    start_enabled: bool
    stop_enabled: bool
    stop_pressed: bool
    muted: bool | None = None
    volume: int | None = None
    pressed: "TouchZone | None" = None


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

    def compose_list(self, width: int, height: int, state: ListState, *, rotate: bool, bgr: bool):
        """Build one display-ready frame for the appliance-selector screen.

        Always starts from a flat dark background (_LIST_BG_RGB) — there is
        no artwork on this screen. Draws up to ListLayout.rows_per_page rows
        (label, plus a small selection dot on the row `state` marks selected), a 1px
        separator under each row, and the bottom back|down|up bar (dimmed
        like compose()'s bottom band, with the down/up chevrons drawn at
        OVERLAY_DIM_FACTOR brightness when no next/previous page exists).
        rotate/bgr are applied last, in the same order compose() uses.

        Shares dial_touch_layout.list_layout_for()'s geometry with
        dial_touch.py's selector-surface hit-test — the single source of
        truth for where each row and bar zone sits. Never raises: a font or
        glyph failure degrades to a plainer row, matching compose()'s own
        text-failure discipline.
        """
        frame = _draw_list(width, height, state)

        if rotate:
            frame = frame.transpose(Image.ROTATE_180)
        if bgr:
            frame = Image.merge("RGB", frame.split()[::-1])
        return frame

    def compose_repeat(
        self, width: int, height: int, state: RepeatViewState, *, rotate: bool, bgr: bool, base=None,
    ):
        """Build one display-ready frame for the repeat screen.

        Draws the shared top band (dots, name, mute/volume readout — see
        _draw_top_band_content()) over either a flat dark background
        (_LIST_BG_RGB, the same chassis colour as compose_list()) for the
        enable layout — the "Repeat Play" row, with a hollow or solid dot
        marker depending on `state.armed` — or, for the replaying layout,
        *base* (the current artwork frame or the logo, already panel-sized;
        None falls back to the same flat background), dimmed the same way
        compose()'s overlay dims the main screen's bands, with the
        Restart/Stop labels and the centred position line drawn on top.
        rotate/bgr are applied last, in the same order compose() uses.
        Never raises: a font, glyph or base-image failure degrades to a
        plainer frame, matching compose()'s own discipline.
        """
        frame = _draw_repeat(width, height, state, base)

        if rotate:
            frame = frame.transpose(Image.ROTATE_180)
        if bgr:
            frame = Image.merge("RGB", frame.split()[::-1])
        return frame

    def compose_idle(self, base, width: int, height: int, *, rotate: bool, bgr: bool):
        """Build one display-ready frame for the idle screen: just *base* —
        the logo the manager chose (the plain disc, or the replay-available
        arrows-on-disc logo when a held recording can be replayed) — with no
        volume/mute controls overlay, since nothing is playing and there is
        nothing on this screen to control. *base* is assumed already
        panel-sized (the manager's own logo load). rotate/bgr are applied
        last, in the same order compose() uses. Never raises beyond a None
        passthrough."""
        if base is None:
            return base
        image = base.convert("RGB")
        if rotate:
            image = image.transpose(Image.ROTATE_180)
        if bgr:
            image = Image.merge("RGB", image.split()[::-1])
        return image


def format_mmss(seconds: float) -> str:
    """Format *seconds* as "m:ss" — used by the repeat screen's position
    line and the replay picker's row length. Hours fold into minutes (no
    separate hour field: an hour-plus recording just reads "62:03"); a
    negative input clamps to zero rather than producing a negative string.
    Pure — no I/O, no state.
    """
    total = max(0, int(round(seconds)))
    minutes, secs = divmod(total, 60)
    return f"{minutes}:{secs:02d}"


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


def _draw_top_band_content(
    frame: Image.Image,
    *,
    dots_rect,
    dots_filled: int | None,
    name_rect,
    name_text: str,
    volume_cluster_rect,
    volume: int | None,
    muted: bool | None,
    width: int,
    height: int,
    halo: bool,
) -> None:
    """Draw the top band's pager dots, appliance name and mute/volume
    readout into *frame* in place — the piece of the top band shared
    verbatim by the main screen's now-playing overlay (_draw_overlay,
    halo=True: the name is drawn over arbitrary album art) and the repeat
    screen's own top band (_draw_repeat, halo=False: a flat chassis
    background in the enable layout, or an already band-dimmed artwork/
    logo base in the replaying layout — see the module docstring's halo
    paragraph for why only text drawn directly over undimmed artwork needs
    it).

    Caller is responsible for dimming the band (and drawing any
    pressed-zone highlight) before calling this, same discipline as every
    other draw-onto-frame helper here — text/glyphs always land on top of
    both. dots_rect=None (or dots_filled=None) omits the dots entirely —
    used when the caller's overlay snapshot says they should not be drawn.
    """
    name_px = _scaled_px(_ARTIST_FONT_PX_AT_REFERENCE, width, height, 8)
    volume_px = _scaled_px(_VOLUME_FONT_PX_AT_REFERENCE, width, height, 9)
    name_font = _load_font(name_px)
    volume_font = _load_font(volume_px)

    draw = ImageDraw.Draw(frame)
    _draw_volume_cluster(draw, volume_cluster_rect, volume, muted, volume_font, width, height)
    if halo:
        _draw_text_with_halo(frame, name_rect, name_text, name_font, width, height)
    else:
        pad = _pad_px(width, height)
        _draw_label(ImageDraw.Draw(frame), name_rect, name_text, name_font, pad)
    if dots_rect is not None and dots_filled is not None:
        _draw_glyph_supersampled(
            frame, dots_rect, lambda d, w, h: _draw_two_dots(d, w, h, filled=dots_filled),
        )


def _draw_overlay(image: Image.Image, width: int, height: int, overlay: OverlayState) -> Image.Image:
    """Return a new frame: *image* with its top/bottom bands dimmed, the
    appliance name, artist line, volume readout, minus/plus glyphs and a
    divider line drawn on top, plus an optional pressed-zone highlight.
    Sized from dial_touch_layout.layout_for()/zones_for() so this works at
    every profile size.
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

    # The name (top-left) is drawn plain (no halo), matching the repeat
    # screen's own top band — it sits over the dimmed top band, which already
    # gives it contrast. The dots (also part of the top band) share this
    # same helper with the repeat screen — see _draw_top_band_content().
    _draw_top_band_content(
        frame,
        dots_rect=layout.dots if overlay.dots else None,
        dots_filled=0 if overlay.dots else None,
        name_rect=layout.name, name_text=overlay.name,
        volume_cluster_rect=layout.volume_cluster, volume=overlay.volume, muted=overlay.muted,
        width=width, height=height, halo=False,
    )

    # The artist/title lines are main-screen-only (the repeat screen has no
    # equivalent), so they stay here rather than in the shared helper. Both
    # are drawn over arbitrary album art too, so both get the same halo.
    artist_px = _scaled_px(_ARTIST_FONT_PX_AT_REFERENCE, width, height, 8)
    artist_font = _load_font(artist_px)
    _draw_text_with_halo(frame, layout.title, overlay.title, artist_font, width, height)
    _draw_text_with_halo(frame, layout.artist, overlay.artist, artist_font, width, height)
    draw = ImageDraw.Draw(frame)
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


def _draw_text_safe(
    draw: ImageDraw.ImageDraw, xy: tuple[int, int], text: str, font, fill=_GLYPH_RGB,
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


def _halo_stroke_px(width: int, height: int) -> int:
    return _scaled_px(_HALO_STROKE_PX_AT_REFERENCE, width, height, 1)


def _halo_blur_radius(width: int, height: int) -> int:
    return _scaled_px(_HALO_BLUR_RADIUS_AT_REFERENCE, width, height, 1)


def _draw_text_with_halo(
    frame: Image.Image,
    rect: tuple[int, int, int, int],
    text: str,
    font,
    width: int,
    height: int,
    *,
    align: str = "left",
) -> None:
    """Draw *text* inside *rect* (left-aligned, or centred when
    align="center"), legible over arbitrary album art: a soft,
    Gaussian-blurred dark glow is composited behind the text before the
    text itself is drawn in the glyph colour. Used for the appliance name
    and artist line (left-aligned) and the repeat screen's replaying-layout
    position line (centred, over its own artwork/logo base image) — see the
    module docstring's halo paragraph.

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
    pad = _pad_px(width, height)
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
            stroke = _halo_stroke_px(width, height)
            radius = _halo_blur_radius(width, height)
            local_xy = (xy[0] - rect[0], xy[1] - rect[1])
            halo_layer = Image.new("RGBA", (rect_w, rect_h), (0, 0, 0, 0))
            ImageDraw.Draw(halo_layer).text(
                local_xy, truncated, font=font,
                fill=_HALO_RGBA, stroke_width=stroke, stroke_fill=_HALO_RGBA,
            )
            halo_layer = halo_layer.filter(ImageFilter.GaussianBlur(radius))
            region = frame.crop(rect).convert("RGBA")
            composited = Image.alpha_composite(region, halo_layer).convert("RGB")
            frame.paste(composited, (rect[0], rect[1]))
        except Exception:
            pass  # the halo is cosmetic only — fall through to plain text.

    _draw_text_safe(ImageDraw.Draw(frame), xy, truncated, font)


def _draw_glyph_supersampled(frame: Image.Image, rect: tuple[int, int, int, int], draw_fn) -> None:
    """Draw a small glyph antialiased: *draw_fn(draw, w, h)* renders into a
    transparent (w, h) canvas at _GLYPH_SUPERSAMPLE times *rect*'s size,
    which is then downsampled with LANCZOS and alpha-composited back into
    *rect*. Used for the selector chassis's check mark and chevrons, whose
    diagonal strokes would otherwise alias visibly at these small sizes —
    the same per-element (never whole-frame) antialiasing the halo helper
    above applies to text. Any Pillow failure is swallowed: a glyph that
    fails to render simply does not appear, never an exception.
    """
    x0, y0, x1, y1 = rect
    w, h = x1 - x0, y1 - y0
    if w <= 0 or h <= 0:
        return
    try:
        big_w, big_h = w * _GLYPH_SUPERSAMPLE, h * _GLYPH_SUPERSAMPLE
        big = Image.new("RGBA", (big_w, big_h), (0, 0, 0, 0))
        draw_fn(ImageDraw.Draw(big), big_w, big_h)
        small = big.resize((w, h), _LANCZOS)
        region = frame.crop(rect).convert("RGBA")
        composited = Image.alpha_composite(region, small).convert("RGB")
        frame.paste(composited, (x0, y0))
    except Exception:
        pass


def _draw_selected_dot(draw: ImageDraw.ImageDraw, w: int, h: int) -> None:
    """A small filled white circle marking the selected row, centred in a
    (w, h) canvas — see _draw_glyph_supersampled, which supplies the
    supersampled canvas and downscales it for antialiasing. Deliberately
    small so it marks the selection without competing with the label; only
    the selected row gets one, the rest carry no marker."""
    r = max(2, round(min(w, h) * 0.16))
    cx, cy = w / 2.0, h / 2.0
    draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=_GLYPH_RGB)


def _draw_chevron(draw: ImageDraw.ImageDraw, w: int, h: int, direction: str, lit: bool) -> None:
    """A simple two-segment chevron (back/down/up) into a (w, h) canvas —
    see _draw_glyph_supersampled. *lit*=False dims it to OVERLAY_DIM_FACTOR
    of the glyph colour, matching a disabled/no-more-pages affordance."""
    stroke = max(1, min(w, h) // 7)
    color = _GLYPH_RGB if lit else tuple(round(c * OVERLAY_DIM_FACTOR) for c in _GLYPH_RGB)
    cx, cy = w / 2, h / 2
    r = min(w, h) * 0.28
    if direction == "left":
        points = [(cx + r, cy - r), (cx - r, cy), (cx + r, cy + r)]
    elif direction == "down":
        points = [(cx - r, cy - r), (cx, cy + r), (cx + r, cy - r)]
    else:  # "up"
        points = [(cx - r, cy + r), (cx, cy - r), (cx + r, cy + r)]
    draw.line(points, fill=color, width=stroke, joint="curve")


def _draw_loop_glyph(draw: ImageDraw.ImageDraw, w: int, h: int) -> None:
    """A small looping-arrow glyph — the appliance selector's "currently
    replaying" row marker (see LOOP_GLYPH). Drawn in the accent colour
    (_LOOP_GLYPH_RGB) rather than plain glyph white, into a (w, h) canvas —
    see _draw_glyph_supersampled."""
    cx, cy = w / 2.0, h / 2.0
    r = min(w, h) * 0.28
    stroke = max(1, min(w, h) // 8)
    draw.arc([cx - r, cy - r, cx + r, cy + r], start=30, end=300, fill=_LOOP_GLYPH_RGB, width=stroke)
    ax, ay = cx + r * 0.5, cy - r * 0.87
    draw.polygon(
        [
            (ax, ay - stroke),
            (ax + stroke * 1.6, ay + stroke * 0.4),
            (ax - stroke * 0.4, ay + stroke * 1.6),
        ],
        fill=_LOOP_GLYPH_RGB,
    )


def _draw_two_dots(draw: ImageDraw.ImageDraw, w: int, h: int, filled: int) -> None:
    """Two small circles side by side, one of them (*filled*: 0 for the
    left one, 1 for the right) drawn solid and the other outlined — the
    main/repeat screen pager dots. Rendered into a (w, h) canvas — see
    _draw_glyph_supersampled."""
    r = max(2, round(min(w, h) * 0.12))
    cy = h / 2.0
    gap = r * 3
    cx0 = w / 2.0 - gap / 2.0
    cx1 = w / 2.0 + gap / 2.0
    for i, cx in enumerate((cx0, cx1)):
        box = [cx - r, cy - r, cx + r, cy + r]
        if i == filled:
            draw.ellipse(box, fill=_GLYPH_RGB)
        else:
            draw.ellipse(box, outline=_GLYPH_RGB, width=max(1, r // 3))


def _draw_arm_dot(draw: ImageDraw.ImageDraw, w: int, h: int, armed: bool) -> None:
    """The enable layout's "Repeat Play" row marker: solid white when
    *armed* (the appliance will auto-start a replay on its own), hollow
    (outline only) when disarmed — the same dot size _draw_selected_dot
    uses for the appliance-selector's row marker. Rendered into a (w, h)
    canvas — see _draw_glyph_supersampled."""
    r = max(2, round(min(w, h) * 0.16))
    cx, cy = w / 2.0, h / 2.0
    box = [cx - r, cy - r, cx + r, cy + r]
    if armed:
        draw.ellipse(box, fill=_GLYPH_RGB)
    else:
        draw.ellipse(box, outline=_GLYPH_RGB, width=max(1, r // 3))


def _draw_label(
    draw: ImageDraw.ImageDraw, rect: tuple[int, int, int, int], text: str, font, pad: int,
    color=_GLYPH_RGB,
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
    if not truncated:
        return
    measured = _text_size(draw, truncated, font)
    if measured is None:
        return
    text_w, text_h, bbox = measured
    left, top, _, _ = bbox
    cy = (rect[1] + rect[3]) // 2
    x = rect[0] + pad
    y = cy - text_h // 2
    _draw_text_safe(draw, (x - left, y - top), truncated, font, fill=color)


def _draw_label_centered(
    draw: ImageDraw.ImageDraw, rect: tuple[int, int, int, int], text: str, font, color=_GLYPH_RGB,
) -> None:
    """Draw *text* centred within *rect*, no halo — same degrade-gracefully
    discipline as _draw_label()."""
    if not text or font is None:
        return
    measured = _text_size(draw, text, font)
    if measured is None:
        return
    text_w, text_h, bbox = measured
    left, top, _, _ = bbox
    cx = (rect[0] + rect[2]) // 2
    cy = (rect[1] + rect[3]) // 2
    x = cx - text_w // 2
    y = cy - text_h // 2
    _draw_text_safe(draw, (x - left, y - top), text, font, fill=color)


def _draw_repeat(width: int, height: int, state: RepeatViewState, base=None) -> Image.Image:
    """Render the repeat-screen chassis (compose-space, pre rotate/BGR) —
    see DialDisplayCompositor.compose_repeat()."""
    layout = repeat_layout_for(width, height)

    frame = None
    if state.layout == "replaying" and base is not None:
        try:
            candidate = base.convert("RGB")
            if candidate.size != (width, height):
                candidate = candidate.resize((width, height))
            frame = candidate
        except Exception:
            frame = None  # degrade to the flat chassis background below
    if frame is None:
        frame = Image.new("RGB", (width, height), _LIST_BG_RGB)

    # The top band is dimmed on both layouts — the enable layout's flat
    # chassis background is already dark, so this is cosmetically a no-op
    # there, but it means the shared top-band content (see
    # _draw_top_band_content) never needs to know which layout it is
    # drawn over. The bottom band is only ever occupied in "replaying".
    _dim_rect(frame, layout.top_band)
    if state.layout == "replaying":
        _dim_rect(frame, layout.bottom_band)

    draw = ImageDraw.Draw(frame)
    zones = {
        TouchZone.DOTS: layout.dots,
        TouchZone.NAME: layout.name,
        TouchZone.REPEAT_PLAY: layout.row,
        TouchZone.REPEAT_START: layout.start,
        TouchZone.REPEAT_STOP: layout.stop,
    }
    if state.pressed is not None and state.pressed in zones:
        _draw_pressed_highlight(frame, zones[state.pressed])
        draw = ImageDraw.Draw(frame)
    if state.layout == "replaying" and state.stop_pressed:
        _draw_pressed_highlight(frame, layout.stop)
        draw = ImageDraw.Draw(frame)

    pad = _pad_px(width, height)
    row_px = _scaled_px(_ARTIST_FONT_PX_AT_REFERENCE, width, height, 8)
    line_px = _scaled_px(_VOLUME_FONT_PX_AT_REFERENCE, width, height, 9)
    row_font = _load_font(row_px)
    line_font = _load_font(line_px)

    # The dots draw the RIGHT dot filled (this is the second of the two
    # screens) and are never omitted here — see _draw_top_band_content;
    # halo=False since the enable layout has no arbitrary artwork behind
    # it, and the replaying layout's base image is already band-dimmed.
    _draw_top_band_content(
        frame,
        dots_rect=layout.dots, dots_filled=1,
        name_rect=layout.name, name_text=state.name,
        volume_cluster_rect=layout.volume_cluster, volume=state.volume, muted=state.muted,
        width=width, height=height, halo=False,
    )
    draw = ImageDraw.Draw(frame)

    if state.layout == "enable":
        row = layout.row
        dot_box = row[3] - row[1]
        dot_rect = (row[2] - pad - dot_box, row[1], row[2] - pad, row[3])
        label_rect = (row[0], row[1], dot_rect[0] - pad, row[3])
        _draw_label(draw, label_rect, "Repeat Play", row_font, pad)
        _draw_glyph_supersampled(frame, dot_rect, lambda d, w, h: _draw_arm_dot(d, w, h, state.armed))
    else:
        start_color = _GLYPH_RGB if state.start_enabled else _DIMMED_GLYPH_RGB
        stop_color = _GLYPH_RGB if state.stop_enabled else _DIMMED_GLYPH_RGB
        _draw_label_centered(draw, layout.start, "Restart", line_font, color=start_color)
        _draw_label_centered(draw, layout.stop, "Stop", line_font, color=stop_color)
        _draw_band_divider(draw, layout, width, height)
        _draw_text_with_halo(frame, layout.line, state.line, line_font, width, height, align="center")

    return frame


def _draw_list(width: int, height: int, state: ListState) -> Image.Image:
    """Render the appliance-selector chassis (compose-space, pre rotate/BGR)
    — see DialDisplayCompositor.compose_list()."""
    layout = list_layout_for(width, height)
    frame = Image.new("RGB", (width, height), _LIST_BG_RGB)
    draw = ImageDraw.Draw(frame)

    def _pressed_rect(pressed):
        if pressed is None:
            return None
        zone, index = pressed
        if zone == TouchZone.LIST_ROW:
            if index is not None and 0 <= index < len(layout.rows):
                return layout.rows[index]
            return None
        return {
            TouchZone.LIST_BACK: layout.back,
            TouchZone.LIST_DOWN: layout.down,
            TouchZone.LIST_UP: layout.up,
        }.get(zone)

    pressed_rect = _pressed_rect(state.pressed)
    if pressed_rect is not None:
        _draw_pressed_highlight(frame, pressed_rect)
        draw = ImageDraw.Draw(frame)

    row_px = _scaled_px(_ARTIST_FONT_PX_AT_REFERENCE, width, height, 8)
    row_font = _load_font(row_px)
    pad = _pad_px(width, height)

    for i, (x0, y0, x1, y1) in enumerate(layout.rows):
        draw.line([(x0, y1 - 1), (x1 - 1, y1 - 1)], fill=_LIST_SEPARATOR_RGB, width=1)
        if i >= len(state.rows):
            continue
        row = state.rows[i]
        label, checked = row[0], row[1]
        secondary = row[2] if len(row) > 2 else ""
        is_loop = secondary is LOOP_GLYPH
        check_box = layout.row_h
        cy = (y0 + y1) // 2

        # Right-hand reserved space, built up right to left: the loop
        # glyph (if any), then the selected dot (if any), then free-text
        # secondary (e.g. a buffer length) just left of whatever glyph
        # space is reserved. A plain 2-tuple row (secondary == "") takes
        # exactly the pre-existing "checked reserves one box" path below,
        # byte-identical to before this field existed.
        right_edge = x1 - pad
        if is_loop:
            loop_rect = (right_edge - check_box, y0, right_edge, y1)
            _draw_glyph_supersampled(frame, loop_rect, _draw_loop_glyph)
            draw = ImageDraw.Draw(frame)
            right_edge -= check_box
            if checked:
                check_rect = (right_edge - check_box, y0, right_edge, y1)
                _draw_glyph_supersampled(frame, check_rect, _draw_selected_dot)
                draw = ImageDraw.Draw(frame)
                right_edge -= check_box
        elif checked:
            check_rect = (right_edge - check_box, y0, right_edge, y1)
            _draw_glyph_supersampled(frame, check_rect, _draw_selected_dot)
            draw = ImageDraw.Draw(frame)
            right_edge -= check_box

        if isinstance(secondary, str) and secondary and row_font is not None:
            measured_sec = _text_size(draw, secondary, row_font)
            if measured_sec is not None:
                sec_w, sec_h, sec_bbox = measured_sec
                sec_left, sec_top, _, _ = sec_bbox
                sec_x = right_edge - sec_w
                _draw_text_safe(draw, (sec_x - sec_left, cy - sec_h // 2 - sec_top), secondary, row_font)
                right_edge = sec_x - pad

        if label and row_font is not None and right_edge > x0 + pad:
            text = _truncate_to_width(draw, label, row_font, right_edge - (x0 + pad))
            if text:
                measured = _text_size(draw, text, row_font)
                if measured is not None:
                    text_w, text_h, bbox = measured
                    left, top, _, _ = bbox
                    _draw_text_safe(draw, (x0 + pad - left, cy - text_h // 2 - top), text, row_font)

    _dim_rect(frame, layout.bar)
    draw = ImageDraw.Draw(frame)
    _draw_glyph_supersampled(frame, layout.back, lambda d, w, h: _draw_chevron(d, w, h, "left", True))
    _draw_glyph_supersampled(frame, layout.down, lambda d, w, h: _draw_chevron(d, w, h, "down", state.has_next))
    _draw_glyph_supersampled(frame, layout.up, lambda d, w, h: _draw_chevron(d, w, h, "up", state.has_prev))
    return frame
