"""dial_display_compositor.py — stateless frame composition for the dial
display.

The manager (dial_display.py) owns all I/O: fetching and decoding artwork,
loading the logo file, deciding what to show and when. This module owns all
pixel work once a base image is in hand. It has no threading, no hardware
access, no persistent state and no lock; every call is independent of every
other.

Every screen is drawn by one pipeline, _compose_frame(): background, dims,
row highlights, pressed-zone wash, header, body, footer, then rotate/BGR.
Screens differ only in data: a frozen Frame descriptor made of a background
choice plus a Header/Body/Footer triple, never the drawing order. Each
public entry point turns its own state snapshot into a Frame and hands it
to the pipeline:

  compose()                 the now-playing overlay (OverlayState)
  compose_list()            the appliance selector and outputs list (ListState)
  compose_repeat()          the repeat screen (RepeatViewState)
  compose_eq()              the equaliser page (EqViewState)
  compose_output()          the per-output detail page (OutputViewState)
  compose_info_value()      the compact info page's drill-in value
  compose_idle()            the idle screen
  compose_starting()        the boot splash
  compose_warning()         a warning page
  compose_restarting()      the restarting screen

Geometry comes from dial_touch_layout, the same coordinates the touch side
hit-tests against, in compose-space before rotate/BGR. With no visible
overlay, compose() applies only rotate/BGR to the panel-fitted base, which
is a strict no-op otherwise; a call with neither returns the very object it
was given, which keeps the manager's pre-rotate artwork cache exact.

The artwork-tap reveal is a paint parameter: compose(reveal_progress=p) and
compose_repeat(reveal_progress=p) slide the overlay's chrome off the panel
while the artwork stays put. The chrome is separated from the artwork once
per frame descriptor (see _reveal_layers) and memoised. The manager owns
the clock; this module never knows a frame is part of an animation.

Drawing never raises (see dial_display_draw). An unrecognised Body/Footer
kind is a programming error and is left to raise. The appliance name sits
over the dimmed top band and is drawn plain.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import dataclasses
import functools
import logging
from dataclasses import dataclass, field

import numpy as np
from PIL import Image, ImageChops, ImageDraw, ImageEnhance

from dial_display_image import transform_artwork_for_panel
from dial_display_draw import (
    GLYPH_ARM_DOT,
    GLYPH_BELL,
    GLYPH_CHEVRON,
    GLYPH_CROSS,
    GLYPH_MUTE,
    GLYPH_PAGE_DOTS,
    GLYPH_PLAY,
    GLYPH_RESTART,
    GLYPH_SPEAKER,
    GLYPH_STOP,
    GLYPH_TWO_DOTS,
    GLYPH_WIFI,
    _BOX,
    _LANCZOS,
    _centred_box,
    _cap_lines,
    _dim_rect,
    _draw_bell,
    _draw_glyph,
    _draw_label,
    _draw_label_centered,
    _draw_label_right,
    _draw_minus_glyph,
    _draw_plus_glyph,
    _draw_pressed_highlight,
    _draw_row_highlight,
    _draw_text_safe,
    _draw_text_with_halo,
    _draw_wash,
    _finish,
    _fit_value_lines,
    _glyph_tile,
    _halo_layer,
    _load_font,
    _new_frame,
    _place_label,
    _text_size,
    _tone,
    _truncate_to_width,
    _wrap_words,
)
from dial_display_palette import (
    GLYPH_RGB,
    PRESSED_FILL_RGB,
    MUTE_WASH_ALPHA,
    DIVIDER_RGB,
    LIST_SEPARATOR_RGB,
    DIMMED_GLYPH_RGB,
    INVERTED_GLYPH_RGB,
    ALARM_RGB,
    CARD_FILL_RGB,
    CARD_OUTLINE_RGB,
    CARD_OUTLINE_ALPHA,
    CARD_SHADOW_RGB,
    CARD_SHADOW_ALPHA,
    CORNER_DISC_RGBA,
    OVERLAY_DIM_FACTOR,
)
from dial_display_views import (
    BG_BASE,
    BG_CHASSIS,
    BODY_CENTRED_LABEL,
    BODY_COMPACT_CONTROLS,
    BODY_COMPACT_LIST,
    BODY_COMPACT_REPLAY,
    BODY_COMPACT_TOGGLE,
    BODY_EQ_BARS,
    BODY_IDLE_BADGE,
    BODY_INFO_VALUE,
    BODY_LIST_ROWS,
    BODY_NONE,
    BODY_NOW_PLAYING,
    BODY_REPEAT_LINE,
    BODY_TOGGLE_ROW,
    BODY_WARNING,
    BellBadge,
    Body,
    EqViewState,
    FOOTER_LABELS,
    FOOTER_LIST_BAR,
    FOOTER_LIST_RAIL,
    FOOTER_NONE,
    FOOTER_VOLUME,
    FOOTER_VOLUME_MUTE,
    Footer,
    Frame,
    Header,
    InfoValueView,
    ListState,
    NEEDS_UPDATE_TEXT,
    NOT_AUTHORISED_TEXT,
    OutputViewState,
    OverlayState,
    PLAY_GLYPH,
    RESTARTING_TEXT,
    RepeatViewState,
    STARTING_TEXT,
    WIFI_GREY,
    WIFI_OFF,
    WIFI_RED,
    WIFI_SIGNAL,
    WarningView,
)
from dial_eq_model import EQ_BASS_TREBLE_LIMIT_DB
from dial_values import clamp, clamp_percent
from dial_layout_metrics import CONTENT_COMPACT, LayoutMetrics, metrics_for
from dial_touch_layout import (
    GEOMETRY_EQ,
    GEOMETRY_LIST,
    GEOMETRY_MAIN,
    GEOMETRY_OUTPUT,
    GEOMETRY_REPEAT,
    GEOMETRY_REPEAT_REPLAY,
    CompactLayout,
    CompactPickerLayout,
    Rect,
    TouchZone,
    compact_layout_for,
    compact_picker_layout_for,
    eq_layout_for,
    band_bell_rect,
    dots_bell_rect,
    idle_layout_for,
    info_value_layout_for,
    layout_for,
    list_layout_for,
    repeat_layout_for,
    warning_layout_for,
    zone_rects_for,
)

_logger = logging.getLogger(__name__)

# Fraction of a compact cell's own short side a cell's centred glyph box
# occupies (0.5): 57px at the 240x240 reference, 30px at 128x128. Minus/
# plus are the one exception — they are drawn straight onto the cell rect
# via the existing _draw_minus_glyph/_draw_plus_glyph, which derive their
# own reach from the rect's own size.
_COMPACT_GLYPH_FRACTION = 0.5

# A second, smaller glyph-box fraction for the replay picker's cancel and
# "more" cells only — the whole point of moving them into the picker's own
# narrower left column is that they read as secondary controls next to the
# two visible targets, not as full-size quadrant glyphs. Every other compact
# cell keeps _COMPACT_GLYPH_FRACTION.
_COMPACT_SMALL_GLYPH_FRACTION = 0.4

# The replay picker's own title-bar text.
_COMPACT_PICKER_TITLE = "Replay"

@dataclass(frozen=True)
class RevealLayers:
    """The overlay's own contribution to one screen's frame, separated from
    the artwork it is drawn over, for the artwork-tap reveal: for each of
    the top band, the bottom band and the inter-band strip, the light the
    chrome adds on its own (`*_add`) and how much of whatever is behind it
    shows through (`*_keep`, per channel, 0..255), so that a band's pixels
    are add + keep * base / 255 wherever the band sits. Built by
    _reveal_layers() from two renders of the same frame descriptor, over
    black and over white; a pure function of that descriptor, so it is
    memoised like the glyph tiles and never depends on the base image."""

    top_band: Rect
    bottom_band: Rect
    strip: Rect
    top_add: Image.Image
    top_keep: Image.Image
    bottom_add: Image.Image
    bottom_keep: Image.Image
    strip_add: Image.Image
    strip_keep: Image.Image
    # The same layers as uint16 arrays for the numpy compositing path, plus
    # the strip rows the chrome actually touches; None when building them
    # failed (the Pillow path is used then). Derived from the images
    # above, so excluded from equality and repr.
    arrays: "_RevealArrays | None" = field(default=None, compare=False, repr=False)


@dataclass(frozen=True)
class _RevealArrays:
    """RevealLayers' layers as (rows, cols, 3) uint16 arrays, so a slide
    frame is pure arithmetic. `strip_runs` lists the half-open row ranges
    (relative to the strip) where the chrome changes anything, that is
    where add is not 0 or keep is not 255 in some column; every other
    strip row passes the base through unchanged and is never touched."""

    top_add: object
    top_keep: object
    bottom_add: object
    bottom_keep: object
    strip_add: object
    strip_keep: object
    strip_runs: tuple


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
        metrics: LayoutMetrics | None = None,
        reveal_progress: float = 0.0,
        timer_text: str | None = None,
        timer_alpha: float = 1.0,
        output_size: "tuple[int, int] | None" = None,
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
        metrics: a LayoutMetrics, or None meaning metrics_for(width, height)
            — today's geometry, density-unaware. Feeds the artwork blur
            radius and every overlay scale quantity.
        reveal_progress: how far the artwork-tap reveal has run, 0.0 (the
            bands in place: exactly the frame drawn before this parameter
            existed) to 1.0 (the bands gone: exactly the no-overlay frame).
            In between, the top band's chrome is slid up and the bottom
            band's down by that fraction of their height, the artwork under
            them staying put, and the album/title/artist lines fade with it
            (see _reveal_frame). A paint parameter like the
            idle screen's flash phase: the manager owns the clock. Ignored
            on the compact tier, which has no bands to slide, and whenever
            the overlay is not drawn at all. Values outside 0..1 (or NaN)
            clamp to the nearer endpoint.
        timer_text: the replay position line shown for a short while after
            a replay is started from the idle screen's picker, drawn
            centred in the artwork between the top band and the album/
            title lines, with the same halo the repeat screen's position
            line uses, over whatever else the frame shows. None (the
            default) draws nothing and leaves the frame byte-identical.
            Ignored on the compact tier, whose controls fill the panel.
        timer_alpha: the timer line's opacity, 0.0 to 1.0, for its fade
            out. A paint parameter like reveal_progress: the manager owns
            the clock.
        output_size: the panel's own size, which the caller will resample
            the frame to when it differs from (width, height). A reveal
            slide frame is then returned already at that size when it is a
            reduction (see _reveal_layers()), so a slide composed at a
            larger layout size costs per frame what one at the panel's
            size does. Every other frame, and a slide frame that also
            carries the timer line, is returned at (width, height) as
            before. None (the default) never changes the size.
        """
        if base is None:
            return base

        if metrics is None:
            metrics = metrics_for(width, height)

        image = base
        if is_artwork:
            image = transform_artwork_for_panel(image, width, height, blur_radius=metrics.blur_radius)

        timer = bool(timer_text) and timer_alpha > 0.0 and metrics.content_tier != CONTENT_COMPACT
        # The timer line is drawn in compose space after the main frame, so
        # a frame carrying it stays at the compose size throughout.
        reveal_size = None if timer else _reveal_output_size(image.width, image.height, output_size)
        framed = self._compose_main(image, metrics, overlay, reveal_progress, reveal_size)
        if timer:
            framed = _draw_timer_line(framed, timer_text, timer_alpha, metrics)
        return _finish(framed, rotate, bgr)

    @staticmethod
    def _compose_main(image, metrics: LayoutMetrics, overlay, reveal_progress: float, reveal_size=None):
        """compose()'s own frame, in compose space (before rotate/BGR), or
        at *reveal_size* for a reveal slide frame when that is given (see
        compose()'s output_size). May return *image* itself when nothing is
        drawn over it, so a caller that draws further must not do so in
        place."""
        if overlay is None or not overlay.visible:
            return _with_corner_bell(image, overlay, metrics)

        if metrics.content_tier == CONTENT_COMPACT:
            frame = _compact_controls_frame(overlay, image.width, image.height, metrics)
            return _compose_frame(
                image, image.width, image.height, frame, rotate=False, bgr=False, metrics=metrics,
            )
        if reveal_progress >= 1.0:
            # The bands have left the panel: the same frame a hidden overlay
            # produces, through the same call.
            return _with_corner_bell(image, overlay, metrics)
        frame = _now_playing_frame(overlay, image.width, image.height, metrics)
        if not reveal_progress > 0.0:
            return _compose_frame(
                image, image.width, image.height, frame, rotate=False, bgr=False, metrics=metrics,
            )
        layout = layout_for(image.width, image.height, metrics=metrics)
        layers = _reveal_layers(
            frame, image.width, image.height, metrics,
            layout.top_band, layout.bottom_band, layout.artwork, reveal_size,
        )
        if reveal_size is not None:
            image = _shrunk_base(image, reveal_size)
        return _reveal_frame(image, layers, reveal_progress)

    def compose_list(
        self, width: int, height: int, state: ListState, *, rotate: bool, bgr: bool,
        metrics: LayoutMetrics | None = None, base=None,
    ):
        """Build one display-ready frame for the appliance-selector screen.

        Always starts from a flat dark background (LIST_BG_RGB) — there is
        no artwork on this screen. Draws up to ListLayout.rows_per_page rows
        (label, plus a faint wash on the row `state` marks current, and the
        play marker on rows whose secondary is PLAY_GLYPH), a 1px separator
        under each row, and the bottom back|down|up bar (dimmed like
        compose()'s bottom band, with the down/up chevrons drawn at
        OVERLAY_DIM_FACTOR brightness when no next/previous page exists).
        rotate/bgr are applied last, in the same order compose() uses.

        Shares dial_touch_layout.list_layout_for()'s geometry with
        dial_touch.py's selector-surface hit-test — the single source of
        truth for where each row and bar zone sits. Never raises: a font or
        glyph failure degrades to a plainer row, matching compose()'s own
        text-failure discipline. metrics: see compose().

        *base* is used only on the compact tier — the picker's own 2x2
        screen dims the manager's current base image behind it, same as
        every other compact screen (see _compact_list_frame); every other
        tier ignores it entirely and keeps its flat chassis background,
        byte-identical to before this parameter existed.
        """
        if metrics is None:
            metrics = metrics_for(width, height)
        if metrics.content_tier == CONTENT_COMPACT:
            return _compose_frame(
                base, width, height, _compact_list_frame(state, width, height, metrics),
                rotate=rotate, bgr=bgr, metrics=metrics,
            )
        return _compose_frame(
            None, width, height, _list_frame(state, width, height, metrics),
            rotate=rotate, bgr=bgr, metrics=metrics,
        )

    def compose_repeat(
        self, width: int, height: int, state: RepeatViewState, *, rotate: bool, bgr: bool, base=None,
        metrics: LayoutMetrics | None = None, controls: bool = True, reveal_progress: float = 0.0,
        output_size: "tuple[int, int] | None" = None,
    ):
        """Build one display-ready frame for the repeat screen.

        Draws the shared top band (dots, name, mute/volume readout — see
        _draw_top_band_content()) over either a flat dark background
        (LIST_BG_RGB, the same chassis colour as compose_list()) for the
        enable layout — the "Repeat Play" row, with a hollow or solid dot
        marker depending on `state.armed` — or, for the replaying layout,
        *base* (the current artwork frame or the logo, already panel-sized;
        None falls back to the same flat background), dimmed the same way
        compose()'s overlay dims the main screen's bands, with the
        Restart/Stop labels and the centred position line drawn on top.
        rotate/bgr are applied last, in the same order compose() uses.
        Never raises: a font, glyph or base-image failure degrades to a
        plainer frame, matching compose()'s own discipline. metrics: see
        compose().

        controls=False (only ever passed by the compact tier's own manager
        path, once its controls window has lapsed — see
        DialDisplay._compact_controls_hidden()) skips the whole pipeline and
        returns *base* itself, undimmed, with only rotate/bgr applied — bare
        artwork/logo, no header/body/footer at all. A parameter, not
        attribute state, so the compositor stays stateless either way.

        reveal_progress: the artwork-tap reveal's progress, meaningful only
        for the replaying layout off the compact tier (the enable layout
        has no artwork to reveal and the compact tier no bands): between 0
        and 1 the top and bottom bands' chrome slides off and the position
        line fades, exactly as compose() does for the now-playing overlay;
        0 (the default) is the ordinary frame and 1 the same bare frame
        controls=False gives. Ignored elsewhere.

        output_size: as compose()'s, for this screen's own reveal slide.
        """
        if metrics is None:
            metrics = metrics_for(width, height)
        if not controls:
            return _finish(_new_frame(base, width, height, BG_BASE), rotate, bgr)
        frame = _repeat_frame(state, width, height, metrics)
        if (
            metrics.content_tier != CONTENT_COMPACT
            and state.layout == "replaying"
            and reveal_progress > 0.0
        ):
            if reveal_progress >= 1.0:
                # The chrome has left the panel: the same bare frame
                # controls=False produces, through the same call.
                return _finish(_new_frame(base, width, height, BG_BASE), rotate, bgr)
            layout = repeat_layout_for(width, height, metrics=metrics)
            strip = (0, layout.top_band[3], width, layout.bottom_band[1])
            reveal_size = _reveal_output_size(width, height, output_size)
            layers = _reveal_layers(
                frame, width, height, metrics, layout.top_band, layout.bottom_band, strip, reveal_size,
            )
            if reveal_size is not None:
                base = _shrunk_base(base, reveal_size)
            return _finish(_reveal_frame(base, layers, reveal_progress), rotate, bgr)
        return _compose_frame(
            base, width, height, frame, rotate=rotate, bgr=bgr, metrics=metrics,
        )

    def compose_output(
        self, width: int, height: int, state: OutputViewState, *, rotate: bool, bgr: bool,
        metrics: LayoutMetrics | None = None,
    ):
        """Build one display-ready frame for the per-output detail page.

        A thin adapter like compose_repeat(): a dark chassis background (no
        artwork here either, matching the appliance selector/replay picker
        and the repeat screen's own enable layout), the shared top band
        with a back control (an X) in place of the pager dots (Header.back) and
        this output's own level in the readout in place of the master
        volume, the toggle row (this output's own name plus its enable
        dot, through the same renderer the repeat screen's "Repeat Play"
        row uses), and the two-way minus/plus footer (FOOTER_VOLUME, the
        same one the repeat screen's replaying layout uses) stepping this
        output's own level. rotate/bgr are applied last, in the same order
        every other compose*() call uses. Never raises: a font or glyph
        failure degrades to a plainer frame, matching every other screen's
        discipline. metrics: see compose().
        """
        return _compose_screen(
            None, width, height, lambda w, h, m: _output_frame(state, w, h, m),
            rotate=rotate, bgr=bgr, metrics=metrics,
        )

    def compose_eq(
        self, width: int, height: int, state: "EqViewState", *, rotate: bool, bgr: bool,
        metrics: LayoutMetrics | None = None,
    ):
        """Build one display-ready frame for the EQ page: a dark chassis
        background (no artwork: the bars fill the panel below the top
        band), the shared top band with three pager dots (the third one
        filled) and the master-volume readout (the OUTPUTS zone over it
        opens the outputs list, as on the other two pages), and the
        bass/treble bar rows (see BODY_EQ_BARS/_body_eq_bars). rotate/bgr
        are applied last, in the same order every other compose*() call
        uses. Never raises: a font or glyph failure degrades to a plainer
        frame, matching every other screen's discipline. metrics: see
        compose().
        """
        return _compose_screen(
            None, width, height, lambda w, h, m: _eq_frame(state, w, h, m),
            rotate=rotate, bgr=bgr, metrics=metrics,
        )

    def compose_info_value(
        self, width: int, height: int, view: InfoValueView, *, rotate: bool, bgr: bool,
        metrics: LayoutMetrics | None = None,
    ):
        """Build one display-ready frame for the compact info page's own
        drill-in: a flat chassis background (no artwork here either,
        matching the info list itself), the field name small in the top
        band and its value large and centred below, wrapped or shrunk to
        fit (see _body_info_value/_fit_value_lines). rotate/bgr are applied
        last, in the same order every other compose*() call uses. Never
        raises: a font or measuring failure degrades to nothing drawn for
        that element, matching every other screen's discipline. metrics:
        see compose()."""
        return _compose_screen(
            None, width, height,
            lambda w, h, m: Frame(BG_CHASSIS, body=Body(BODY_INFO_VALUE, label=view.label, line=view.value)),
            rotate=rotate, bgr=bgr, metrics=metrics,
        )

    def compose_idle(
        self, base, width: int, height: int, *, rotate: bool, bgr: bool,
        metrics: LayoutMetrics | None = None, wifi_bars: int = 0, wifi_style: str = WIFI_SIGNAL,
        bell: "BellBadge | None" = None,
    ):
        """Build one display-ready frame for the idle screen: *base* — the
        logo the manager chose (the plain disc, or the replay-available
        arrows-on-disc logo when a held recording can be replayed) — with no
        volume/mute controls overlay, since nothing is playing and there is
        nothing on this screen to control, plus the Wi-Fi status glyph in
        the top-left corner and, when *bell* is given, the warning bell in
        the top-right one (see BODY_IDLE_BADGE) on every idle frame
        regardless of which logo is showing. wifi_style picks the glyph's look: WIFI_SIGNAL
        lights wifi_bars (0..3) arcs, 0 drawing the whole glyph dimmed;
        WIFI_GREY dims every part; WIFI_RED paints every part in alarm red;
        WIFI_OFF draws no glyph at all. The manager passes the current half of
        its offline flash here (red or off against grey), so this module
        stays stateless. *base* is assumed already panel-sized (the manager's
        own logo load). rotate/bgr are applied last, in the same order
        compose() uses. Never raises beyond a None passthrough. metrics: see
        compose()."""
        if base is None:
            return base
        return _compose_frame(
            base, width, height,
            Frame(BG_BASE, body=Body(BODY_IDLE_BADGE, wifi_bars=wifi_bars, wifi_style=wifi_style, bell=bell)),
            rotate=rotate, bgr=bgr, metrics=metrics,
        )

    def compose_warning(
        self, base, width: int, height: int, view: WarningView, *, rotate: bool, bgr: bool,
        metrics: LayoutMetrics | None = None,
    ):
        """Build one display-ready frame for a warning page: the current
        base image (*base*, or a flat chassis when None) dimmed to
        OVERLAY_DIM_FACTOR, then, off the compact tier, a centred card
        (Frame.card: shadow, fill, outline), and on every tier the title
        (and message, if any) over the button cells with a white
        crosshair: a horizontal line under the message row and a vertical
        line between neighbouring cells (see BODY_WARNING). The pressed
        cell, if any, carries the ordinary press wash and nothing else.
        rotate/bgr last, as always. Never raises: a font failure leaves
        the dividers and card without text. metrics: see compose()."""
        return _compose_screen(
            base, width, height, lambda w, h, m: _warning_frame(view, w, h, m),
            rotate=rotate, bgr=bgr, metrics=metrics,
        )

    def compose_restarting(
        self, width: int, height: int, *, rotate: bool, bgr: bool,
        metrics: LayoutMetrics | None = None,
    ):
        """Build the "Restarting..." frame: a flat chassis fill with the
        one string centred, identical on every tier (see
        BODY_CENTRED_LABEL). Shown from a Restart tap until the reboot
        takes the panel down. Never raises: a font failure leaves the flat
        fill alone. metrics: see compose()."""
        return self._compose_centred_label(
            width, height, RESTARTING_TEXT, rotate=rotate, bgr=bgr, metrics=metrics,
        )

    def compose_starting(
        self, width: int, height: int, *, rotate: bool, bgr: bool,
        metrics: LayoutMetrics | None = None,
    ):
        """Build the "Starting..." frame: the same flat chassis and centred
        string as compose_restarting(), with the boot splash's own text.
        The manager pushes it as the very first frame after the backend
        opens at boot, before any of its threads exist, and the first poll
        replaces it with the logo or artwork. Never raises: a font failure
        leaves the flat fill alone. metrics: see compose()."""
        return self._compose_centred_label(
            width, height, STARTING_TEXT, rotate=rotate, bgr=bgr, metrics=metrics,
        )

    def _compose_centred_label(
        self, width: int, height: int, text: str, *, rotate: bool, bgr: bool,
        metrics: LayoutMetrics | None,
    ):
        """One string centred on a flat chassis fill, identical on every
        tier — the shared body of compose_restarting()/compose_starting()
        (see BODY_CENTRED_LABEL and _body_centred_label). rotate/bgr last,
        as always."""
        return _compose_screen(
            None, width, height, lambda w, h, m: Frame(BG_CHASSIS, body=Body(BODY_CENTRED_LABEL, line=text)),
            rotate=rotate, bgr=bgr, metrics=metrics,
        )


def _compose_screen(base, width: int, height: int, build, *, rotate: bool, bgr: bool, metrics):
    """The shared body of the plain compose*() calls: the metrics default,
    then the frame build(width, height, metrics) through the one pipeline,
    with rotate/bgr last."""
    if metrics is None:
        metrics = metrics_for(width, height)
    return _compose_frame(
        base, width, height, build(width, height, metrics), rotate=rotate, bgr=bgr, metrics=metrics,
    )


def _reset_font_cache() -> None:
    """Clear the memoised font cache, and with it the glyph-tile and
    halo-layer caches — a font swap changes the font object identity the
    halo cache keys on, but clearing here too keeps every memo's state
    obviously consistent rather than relying on that alone. Test-only hook:
    lets a test exercise the fallback chain from a clean slate without
    restarting the process."""
    _load_font.cache_clear()
    _reset_render_caches()


def _draw_top_band_content(
    frame: Image.Image,
    *,
    dots_rect,
    dots_filled: int | None,
    name_rect,
    name_text: str,
    volume_cluster_rect,
    volume: int | None,
    metrics: LayoutMetrics,
    dots_count: int = 2,
) -> None:
    """Draw the top band's pager dots, appliance name and mute/volume
    readout into *frame* in place — the piece of the top band shared by the
    main screen's now-playing overlay and the repeat screen's own top band.
    The name is drawn plain: it always sits over the dimmed top band, which
    gives it enough contrast without the soft halo the artist/title lines
    need over undimmed album art.

    Caller is responsible for dimming the band (and drawing any
    pressed-zone highlight) before calling this, same discipline as every
    other draw-onto-frame helper here — text/glyphs always land on top of
    both. dots_rect=None (or dots_filled=None) omits the dots entirely —
    used when the caller's overlay snapshot says they should not be drawn.
    dots_count selects the two-dot glyph (any value other than 3) or the
    three-dot page glyph (exactly 3) — see Header.dots_count.

    The header speaker is never slashed on any screen — mute has one home,
    the main screen's own footer glyph and wash (see FOOTER_VOLUME_MUTE).
    """
    name_font = _load_font(metrics.font_body)
    volume_font = _load_font(metrics.font_readout)

    draw = ImageDraw.Draw(frame)
    _draw_volume_cluster(frame, volume_cluster_rect, volume, volume_font, metrics)
    pad = metrics.pad
    _draw_label(draw, name_rect, name_text, name_font, pad)
    if dots_rect is not None and dots_filled is not None:
        if dots_count == 3:
            _draw_glyph(frame, dots_rect, GLYPH_PAGE_DOTS, 3, dots_filled, supersample=metrics.supersample)
        else:
            _draw_glyph(frame, dots_rect, GLYPH_TWO_DOTS, dots_filled, supersample=metrics.supersample)


def _draw_band_divider(
    draw: ImageDraw.ImageDraw, layout, metrics: LayoutMetrics, xs: "tuple[int, ...]",
) -> None:
    """Draw one or more white vertical divider lines, each spanning the
    bottom band from its top edge to its last visible row — the boundary
    between two adjacent footer controls. A two-way footer (repeat, the
    per-output detail page) passes a single x; the main screen's three-way
    footer passes both of its own."""
    line_width = metrics.divider_w
    y0 = layout.bottom_band[1]
    y1 = layout.bottom_band[3] - 1
    for x in xs:
        draw.line([(x, y0), (x, y1)], fill=DIVIDER_RGB, width=line_width)


def _draw_bottom_band(
    frame: Image.Image, layout, metrics: LayoutMetrics, *,
    left_rect, right_rect, draw_left, draw_right,
) -> None:
    """Draw the bottom band's two controls with the white divider between
    them — the footer shared by the volume screen (minus/plus glyphs) and
    the repeat screen's replaying layout (Restart/Stop labels), the
    counterpart to the shared _draw_top_band_content() header. draw_left and
    draw_right are callables (draw, rect) that render the left and right
    control into their rect — the only part that differs between screens.
    The caller has already dimmed the band and drawn any pressed highlight;
    text/glyphs land on top. *layout* need only carry divider_x and
    bottom_band (both OverlayLayout and RepeatLayout do)."""
    draw = ImageDraw.Draw(frame)
    draw_left(draw, left_rect)
    draw_right(draw, right_rect)
    _draw_band_divider(draw, layout, metrics, (layout.divider_x,))


def _draw_volume_cluster(
    frame: Image.Image,
    rect: tuple[int, int, int, int],
    volume: int | None,
    font,
    metrics: LayoutMetrics,
) -> None:
    """Draw the volume readout inside *rect* (the top band's volume cluster,
    == the OUTPUTS zone on the main screen): the speaker glyph, right aligned, and — when both a
    *volume* number and a usable *font* are available — the volume digits to
    its left. *metrics* carries the panel's scale-derived padding, icon-to-
    digits gap and icon size (not the rect's own size) — all read from the
    same reference axis every other overlay dimension uses.

    volume=None or font=None draws the glyph alone, right aligned — always
    safe, since _load_font() never raises and this function never assumes a
    font is present. The glyph goes through _draw_glyph() at the tier's
    supersample factor, so its cone and arcs are antialiased like every
    other small glyph rather than drawn straight onto the frame.
    """
    draw = ImageDraw.Draw(frame)
    pad = metrics.pad
    gap = metrics.icon_gap
    icon = metrics.icon
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
    _draw_glyph(frame, icon_box, GLYPH_SPEAKER, supersample=metrics.supersample)

# Fraction of the corner bell zone's own short side the bell's box occupies.
# Sized to read as one pair with the Wi-Fi glyph in the opposite corner
# (outer arc radius 0.33 of its zone).
_BELL_GLYPH_FRACTION = 0.80

# The corner bell on resting artwork sits on a dark translucent disc
# (CORNER_DISC_RGBA); this is the bell's share of the disc. The bell's share
# of its zone in the top band and in the compact dots quadrant.
_CORNER_BELL_FRACTION = 0.62
_BAND_BELL_FRACTION = 0.8
_DOTS_BELL_FRACTION = 0.85


def _reset_render_caches() -> None:
    """Clear the memoised glyph-tile, halo-layer, reveal-layer and shrunk
    reveal-base caches. Test-only hook, the same purpose _reset_font_cache()
    serves for the font cache — lets a test exercise any of them from a
    clean slate without restarting the process."""
    global _shrunk_base_memo
    _glyph_tile.cache_clear()
    _halo_layer.cache_clear()
    _timer_fit.cache_clear()
    _reveal_layers.cache_clear()
    _shrunk_base_memo = None


def _active_runs(np, add, keep) -> tuple:
    """Half-open row ranges of a layer where it is not the identity."""
    active = ((add != 0) | (keep != 255)).any(axis=(1, 2))
    padded = np.concatenate(([0], active.astype(np.int8), [0]))
    edges = np.flatnonzero(np.diff(padded))
    return tuple((int(a), int(b)) for a, b in zip(edges[::2], edges[1::2]))


def _build_reveal_arrays(layers: RevealLayers) -> "_RevealArrays | None":
    try:
        def arr(img):
            return np.array(img, dtype=np.uint16)

        strip_add, strip_keep = arr(layers.strip_add), arr(layers.strip_keep)
        return _RevealArrays(
            top_add=arr(layers.top_add), top_keep=arr(layers.top_keep),
            bottom_add=arr(layers.bottom_add), bottom_keep=arr(layers.bottom_keep),
            strip_add=strip_add, strip_keep=strip_keep,
            strip_runs=_active_runs(np, strip_add, strip_keep),
        )
    except Exception:
        _logger.warning("dial display: reveal layer arrays unavailable", exc_info=True)
        return None


def _reveal_output_size(width: int, height: int, output_size) -> "tuple[int, int] | None":
    """The size a reveal slide's frames are built at when it is not the
    compose size: *output_size* when it is strictly smaller on at least one
    axis and no larger on either (a layout size composed bigger than the
    panel), else None. Only a reduction qualifies: the shrink is a box
    average, which is right for that and wrong for growing."""
    if output_size is None:
        return None
    ow, oh = output_size
    if (ow, oh) == (width, height) or ow > width or oh > height or ow < 1 or oh < 1:
        return None
    return ow, oh


def _scale_rect(rect: Rect, sx: float, sy: float) -> Rect:
    return (round(rect[0] * sx), round(rect[1] * sy), round(rect[2] * sx), round(rect[3] * sy))


# The base a resampled reveal slide is drawn over, shrunk once per base
# rather than once per frame: (source image, size, shrunk image). Holding
# the source keeps its identity from being reused while the entry lives.
_shrunk_base_memo: "tuple | None" = None


def _shrunk_base(base, size: tuple[int, int]):
    """*base* box-averaged to *size*, memoised on the base object itself
    for as long as the same base keeps being passed (one slide's frames).
    None stays None, and a base already at *size* is returned as it is."""
    global _shrunk_base_memo
    if base is None or getattr(base, "size", None) == size:
        return base
    memo = _shrunk_base_memo
    if memo is not None and memo[0] is base and memo[1] == size:
        return memo[2]
    shrunk = base.convert("RGB").resize(size, _BOX)
    _shrunk_base_memo = (base, size, shrunk)
    return shrunk


@functools.lru_cache(maxsize=2)
def _reveal_layers(
    frame: Frame, width: int, height: int, metrics: LayoutMetrics,
    top_band: Rect, bottom_band: Rect, strip: Rect,
    output_size: "tuple[int, int] | None" = None,
) -> RevealLayers:
    """Separate *frame*'s chrome from whatever base it will be drawn over,
    for the three regions the artwork-tap reveal moves or fades. Every
    drawing step in the pipeline is linear in the pixel behind it (the
    dim, every wash and glyph, the halo, antialiased text), so rendering
    the same descriptor over black and over white gives, per channel, the
    light the chrome adds on its own and how much of the base shows
    through: black render = add, white render - black render = keep. A
    pure function of its arguments, memoised the same way _glyph_tile()
    is (see _load_font()'s statelessness note): two entries, so the
    now-playing and the repeat screen's layers can both stay warm. The
    numpy forms of the layers are built here too, once per slide.

    *output_size*, from _reveal_output_size(), is the panel size when the
    frame is composed at a larger layout size: the layers are rendered at
    the compose size, so the chrome keeps that size's sharpness, then
    box-averaged to the panel along with their rects, so every frame of
    the slide is built at the panel's own size instead of being built
    large and shrunk each time. The box average is linear, so the shrunk
    layers still separate chrome from base."""
    black = Image.new("RGB", (width, height), (0, 0, 0))
    white = Image.new("RGB", (width, height), (255, 255, 255))
    add = _compose_frame(black, width, height, frame, rotate=False, bgr=False, metrics=metrics)
    lit = _compose_frame(white, width, height, frame, rotate=False, bgr=False, metrics=metrics)
    keep = ImageChops.subtract(lit, add)
    if output_size is not None:
        sx, sy = output_size[0] / width, output_size[1] / height
        add = add.resize(output_size, _BOX)
        keep = keep.resize(output_size, _BOX)
        top_band = _scale_rect(top_band, sx, sy)
        bottom_band = _scale_rect(bottom_band, sx, sy)
        strip = _scale_rect(strip, sx, sy)
    layers = RevealLayers(
        top_band=top_band, bottom_band=bottom_band, strip=strip,
        top_add=add.crop(top_band), top_keep=keep.crop(top_band),
        bottom_add=add.crop(bottom_band), bottom_keep=keep.crop(bottom_band),
        strip_add=add.crop(strip), strip_keep=keep.crop(strip),
    )
    arrays = _build_reveal_arrays(layers)
    if arrays is not None:
        layers = dataclasses.replace(layers, arrays=arrays)
    return layers


def _apply_layer(region: Image.Image, add: Image.Image, keep: Image.Image) -> Image.Image:
    """The chrome laid over *region*: add + keep * region / 255, per
    channel. All three images are the same size."""
    return ImageChops.add(ImageChops.multiply(region, keep), add)


def _apply_layer_np(np, region, add, keep):
    """_apply_layer() on arrays, bit-identical to Pillow's multiply (the
    truncated a * b // 255) then saturating add. *region* is uint8, *add*
    and *keep* uint16 of the same shape; returns uint16 in 0..255."""
    t = region.astype(np.uint16)
    t *= keep
    # (t + 1 + (t >> 8)) >> 8 is exactly t // 255 for every t up to 255 * 255.
    t += (t >> 8) + 1
    t >>= 8
    t += add
    np.minimum(t, 255, out=t)
    return t


def _reveal_frame(base, layers: RevealLayers, progress: float) -> Image.Image:
    """One frame of the artwork-tap reveal, in compose space (before
    rotate/BGR). *progress* is strictly between 0 and 1. A fresh copy of
    *base* (never the caller's object) has the inter-band strip's chrome
    laid over it at opacity 1 - progress, so the text fades; then the top
    band's chrome is laid over the top rows shifted round(progress * band
    height) upwards and the bottom band's the same amount downwards, each
    over the artwork already at those rows, so the chrome leaves the
    panel edge while the artwork underneath never moves and shows bare
    where the chrome has gone. Reproduces the ordinary frame at 0 and the
    bare base at 1 to within rounding; the callers short-circuit both
    endpoints to the exact frames anyway.

    The normal path does the whole frame as arithmetic on one array and
    converts back once, touching only the strip rows the chrome changes;
    that keeps the per-frame cost low and, unlike Pillow's chop and blend
    calls, lets other threads run while it works. The bands are
    bit-identical to the Pillow path; the strip fade is exact too, apart
    from possible one-level float rounding differences. If the array path
    fails for any reason, the same frame is built with Pillow instead; this
    never raises for either."""
    arrays = layers.arrays
    if arrays is not None:
        try:
            return _reveal_frame_np(np, base, layers, arrays, progress)
        except Exception:
            _logger.warning("dial display: numpy reveal failed; using Pillow", exc_info=True)
    return _reveal_frame_pillow(base, layers, progress)


def _reveal_frame_np(np, base, layers: RevealLayers, arrays: _RevealArrays, progress: float):
    width, height = layers.strip[2], layers.bottom_band[3]
    src = _new_frame(base, width, height, BG_BASE)
    out = np.array(src, dtype=np.uint8)
    x0, y0, x1, y1 = layers.strip
    if x1 > x0 and y1 > y0 and arrays.strip_runs:
        alpha = np.float32(1.0 - progress)
        for r0, r1 in arrays.strip_runs:
            region = out[y0 + r0:y0 + r1, x0:x1]
            applied = _apply_layer_np(
                np, region, arrays.strip_add[r0:r1], arrays.strip_keep[r0:r1],
            )
            base_f = region.astype(np.float32)
            applied = applied.astype(np.float32)
            applied -= base_f
            applied *= alpha
            applied += base_f
            region[...] = applied.astype(np.uint8)
    x0, y0, x1, y1 = layers.top_band
    band_h = y1 - y0
    dy = round(progress * band_h)
    if dy < band_h:
        region = out[y0:y1 - dy, x0:x1]
        region[...] = _apply_layer_np(
            np, region, arrays.top_add[dy:band_h], arrays.top_keep[dy:band_h],
        )
    x0, y0, x1, y1 = layers.bottom_band
    band_h = y1 - y0
    dy = round(progress * band_h)
    if dy < band_h:
        region = out[y0 + dy:y1, x0:x1]
        region[...] = _apply_layer_np(
            np, region, arrays.bottom_add[:band_h - dy], arrays.bottom_keep[:band_h - dy],
        )
    return Image.fromarray(out, "RGB")


def _reveal_frame_pillow(base, layers: RevealLayers, progress: float) -> Image.Image:
    """_reveal_frame() with Pillow's own chop and blend operations."""
    width, height = layers.strip[2], layers.bottom_band[3]
    out = _new_frame(base, width, height, BG_BASE)
    x0, y0, x1, y1 = layers.strip
    if x1 > x0 and y1 > y0:
        region = out.crop(layers.strip)
        faded = Image.blend(
            region, _apply_layer(region, layers.strip_add, layers.strip_keep), 1.0 - progress,
        )
        out.paste(faded, (x0, y0))
    x0, y0, x1, y1 = layers.top_band
    band_h = y1 - y0
    dy = round(progress * band_h)
    if dy < band_h:
        region = out.crop((x0, y0, x1, y1 - dy))
        chrome = (0, dy, x1 - x0, band_h)
        out.paste(
            _apply_layer(region, layers.top_add.crop(chrome), layers.top_keep.crop(chrome)),
            (x0, y0),
        )
    x0, y0, x1, y1 = layers.bottom_band
    band_h = y1 - y0
    dy = round(progress * band_h)
    if dy < band_h:
        region = out.crop((x0, y0 + dy, x1, y1))
        chrome = (0, 0, x1 - x0, band_h - dy)
        out.paste(
            _apply_layer(region, layers.bottom_add.crop(chrome), layers.bottom_keep.crop(chrome)),
            (x0, y0 + dy),
        )
    return out


def _draw_header(img: Image.Image, layout, header: Header, metrics: LayoutMetrics) -> None:
    bell_rect = band_bell_rect(layout.name, metrics.band_h)
    # The bell sits over the name's right end, so the name is drawn shorter.
    name_rect = layout.name if header.bell is None else (*layout.name[:2], bell_rect[0], layout.name[3])
    _draw_top_band_content(
        img,
        dots_rect=layout.dots if (header.dots_filled is not None and not header.back) else None,
        dots_filled=None if header.back else header.dots_filled,
        dots_count=header.dots_count,
        name_rect=name_rect, name_text=header.name,
        volume_cluster_rect=layout.volume_cluster,
        volume=header.volume,
        metrics=metrics,
    )
    if header.bell is not None:
        _draw_bell(img, bell_rect, header.bell, metrics, _BAND_BELL_FRACTION)
    if header.back:
        # The per-output detail page's own back control: an X, the same
        # glyph and icon-sized box the rail's own cancel control uses,
        # drawn into the same rect the pager dots would otherwise occupy —
        # the two are mutually exclusive (dots_filled is suppressed above
        # whenever back is set).
        _draw_glyph(img, _centred_box(layout.dots, metrics.icon), GLYPH_CROSS, supersample=metrics.supersample)


def _body_none(img: Image.Image, metrics: LayoutMetrics, body: Body) -> None:
    pass


def _body_idle_badge(img: Image.Image, metrics: LayoutMetrics, body: Body) -> None:
    """The idle screen's own corner glyphs, drawn regardless of which base
    image (the plain logo or the replay-available one) is showing
    underneath — see compose_idle(): the warning bell top-right (only when
    body.bell is set), and the Wi-Fi status glyph top-left as
    body.wifi_style says. WIFI_SIGNAL
    lights body.wifi_bars arcs, WIFI_GREY dims every part, WIFI_RED paints
    every part in alarm red, and WIFI_OFF draws no glyph at all — the base
    shows through untouched, so the flash's blank half really is blank (no
    tile is built or cached for it). An unrecognised style is treated as
    WIFI_SIGNAL."""
    layout = idle_layout_for(metrics.width, metrics.height, metrics=metrics)
    if body.bell is not None:
        x0, y0, x1, y1 = layout.info
        side = round(min(x1 - x0, y1 - y0) * _BELL_GLYPH_FRACTION)
        _draw_glyph(
            img, _centred_box(layout.info, side), GLYPH_BELL, body.bell.severity, body.bell.count,
            supersample=metrics.supersample,
        )
    style = body.wifi_style
    if style == WIFI_OFF:
        return
    if style == WIFI_RED:
        lit, color = 3, ALARM_RGB
    elif style == WIFI_GREY:
        lit, color = 0, GLYPH_RGB
    else:
        lit, color = clamp(int(body.wifi_bars), 0, 3), GLYPH_RGB
    _draw_glyph(img, layout.wifi, GLYPH_WIFI, lit, color, supersample=metrics.supersample)


def _body_now_playing(img: Image.Image, metrics: LayoutMetrics, body: Body) -> None:
    layout = layout_for(metrics.width, metrics.height, metrics=metrics)
    font = _load_font(metrics.font_body)
    if layout.album is not None:
        _draw_text_with_halo(img, layout.album, body.album, font, metrics)
    _draw_text_with_halo(img, layout.title, body.title, font, metrics)
    _draw_text_with_halo(img, layout.artist, body.artist, font, metrics)


def _draw_toggle_row(
    img: Image.Image, metrics: LayoutMetrics, row_rect: tuple[int, int, int, int], label: str, armed: bool,
    *, dot_box: int | None = None,
) -> None:
    """A label plus an on/off dot marker drawn into *row_rect* — shared by
    the repeat screen's "Repeat Play" enable row, the per-output detail
    page's own enable row (both pass repeat_layout_for(...).row) and the
    compact tier's own enable screen (which passes its bottom_row instead).

    *dot_box* sizes the arm-dot's own box, width only — its height still
    always spans the full *row_rect*, so the dot itself (drawn centred
    within that box by _draw_arm_dot) stays vertically centred on the row
    either way. None (every non-compact caller) keeps today's box: the
    row's own height, giving a square box exactly as before. The compact
    tier's own row is far taller relative to its own width than the base
    tier's row ever is, so its own caller (_body_compact_toggle) passes a
    smaller fixed width instead — the row is a single touch zone regardless
    of how big the dot itself is drawn, so shrinking it costs nothing but
    frees the width "Repeat Play" needs to fit without truncating."""
    pad = metrics.pad
    row_font = _load_font(metrics.font_body)
    draw = ImageDraw.Draw(img)
    box_w = dot_box if dot_box is not None else row_rect[3] - row_rect[1]
    dot_rect = (row_rect[2] - pad - box_w, row_rect[1], row_rect[2] - pad, row_rect[3])
    label_rect = (row_rect[0], row_rect[1], dot_rect[0] - pad, row_rect[3])
    _draw_label(draw, label_rect, label, row_font, pad)
    _draw_glyph(img, dot_rect, GLYPH_ARM_DOT, armed, supersample=metrics.supersample)


def _body_toggle_row(img: Image.Image, metrics: LayoutMetrics, body: Body) -> None:
    """A label plus an on/off dot marker on the shared toggle-row rect —
    the repeat screen's "Repeat Play" enable row and the per-output detail
    page's own enable row are the same layout with a different label."""
    layout = repeat_layout_for(metrics.width, metrics.height, metrics=metrics)
    _draw_toggle_row(img, metrics, layout.row, body.label, body.armed)


def _body_repeat_line(img: Image.Image, metrics: LayoutMetrics, body: Body) -> None:
    layout = repeat_layout_for(metrics.width, metrics.height, metrics=metrics)
    font = _load_font(metrics.font_readout)
    _draw_text_with_halo(img, layout.line, body.line, font, metrics, align="center")


# The timer's backing pill: padding as fractions of the digits' height, and
# a fully rounded end (radius is half the pill's height).
_TIMER_PILL_PAD_X = 0.55
_TIMER_PILL_PAD_Y = 0.35


@functools.lru_cache(maxsize=8)
def _pill_mask(w: int, h: int) -> Image.Image:
    """An antialiased capsule mask of (w, h), memoised: the same pill is
    reused every frame of a timer's life."""
    ss = 4
    big = Image.new("L", (w * ss, h * ss), 0)
    ImageDraw.Draw(big).rounded_rectangle((0, 0, w * ss - 1, h * ss - 1), radius=h * ss // 2, fill=255)
    return big.resize((w, h), Image.LANCZOS)


def timer_area(width: int, height: int, metrics: LayoutMetrics) -> "tuple[int, int, int, int] | None":
    """The rect the replay timer's pill lives in, in compose space: from the
    layout's side margin to the header's own right margin (the edge the
    speaker glyph and volume number end at), and from one layout margin
    below the top band to the top of the first album/title line. None when
    the artwork has no room between them."""
    layout = layout_for(width, height, metrics=metrics)
    first_line = layout.album if layout.album is not None else layout.title
    rect = (metrics.margin, layout.top_band[3] + metrics.margin, width - metrics.pad, first_line[1])
    return rect if rect[2] > rect[0] and rect[3] > rect[1] else None


_TIMER_MIN_FONT_PX = 8


@functools.lru_cache(maxsize=32)
def _timer_fit(text: str, font_px: int, area_w: int, area_h: int):
    """How the timer *text* is drawn: (font, text_w, text_h, bbox, pill_w,
    pill_h) for the largest font size at or below *font_px* whose text plus
    the pill's padding fits *area_w*, stepping down a pixel at a time to a
    floor (half the starting size, never below _TIMER_MIN_FONT_PX). At the
    floor the pill is returned at its full width even when that is wider
    than *area_w*: the pill is never clipped. None when the text cannot be
    measured. Memoised, so the common case costs nothing per frame."""
    scratch = ImageDraw.Draw(Image.new("L", (1, 1)))
    floor = min(font_px, max(_TIMER_MIN_FONT_PX, font_px // 2))
    for size in range(font_px, floor - 1, -1):
        font = _load_font(size)
        measured = _text_size(scratch, text, font)
        if measured is None:
            return None
        text_w, text_h, bbox = measured
        pill_w = text_w + 2 * round(text_h * _TIMER_PILL_PAD_X)
        if pill_w <= area_w or size == floor:
            pill_h = min(area_h, text_h + 2 * round(text_h * _TIMER_PILL_PAD_Y))
            return font, text_w, text_h, bbox, pill_w, pill_h
    return None


def _draw_timer_line(img: Image.Image, text: str, alpha: float, metrics: LayoutMetrics) -> Image.Image:
    """The main screen's replay position line (see compose()'s timer_text):
    *text* on a dimmed capsule at the top right of the artwork, just below
    the header band and ending at the header's right margin (see
    timer_area()), blended in at *alpha*. The capsule is always complete:
    the font steps down until it fits the area (see _timer_fit()). It is
    dimmed to OVERLAY_DIM_FACTOR like the top and bottom bands, grows
    leftwards, and costs one small crop, one brightness pass and one masked
    paste per frame. Returns a new image; *img* is never drawn on, since it
    may be the caller's cached base. Never raises: any failure returns *img*
    unchanged."""
    try:
        area = timer_area(img.width, img.height, metrics)
        if area is None:
            return img
        fit = _timer_fit(text, metrics.font_readout, area[2] - area[0], area[3] - area[1])
        if fit is None:
            return img
        font, text_w, text_h, bbox, w, h = fit
        x = max(0, area[2] - w)
        # The paste box: the pill itself, widened left of the area only when
        # even the smallest font's pill is wider than it.
        box = (x, area[1], area[2], area[1] + h)
        out = img.copy()
        region = out.crop(box)
        drawn = region.copy()
        dimmed = ImageEnhance.Brightness(drawn).enhance(OVERLAY_DIM_FACTOR)
        drawn.paste(dimmed, (0, 0), _pill_mask(box[2] - box[0], h))
        draw = ImageDraw.Draw(drawn)
        pw = box[2] - box[0]
        _draw_text_safe(draw, ((pw - text_w) // 2 - bbox[0], (h - text_h) // 2 - bbox[1]), text, font)
        if alpha < 1.0:
            drawn = Image.blend(region, drawn, max(0.0, alpha))
        out.paste(drawn, box[:2])
        return out
    except Exception:
        return img


# The row marker's box side as a fraction of the row height. At 0.75 the
# glyph's reach (0.28 of the box each way) gives a 25 px triangle on a
# 60 px row against a 24 px body font: the marker reads at the text's own
# size rather than taller than it, as a row-height box did.
_MARKER_BOX_FRACTION = 0.75


def _row_text_color(secondary) -> tuple:
    """The text colour of a list row: dimmed when its secondary text is the
    selector's "not authorised" or "needs an update" label, the plain glyph
    colour otherwise."""
    return _tone(secondary not in (NOT_AUTHORISED_TEXT, NEEDS_UPDATE_TEXT))


def _body_list_rows(img: Image.Image, metrics: LayoutMetrics, body: Body) -> None:
    layout = list_layout_for(metrics.width, metrics.height, metrics=metrics)
    draw = ImageDraw.Draw(img)
    row_font = _load_font(metrics.font_body)
    pad = metrics.pad

    for i, (x0, y0, x1, y1) in enumerate(layout.rows):
        draw.line([(x0, y1 - 1), (x1 - 1, y1 - 1)], fill=LIST_SEPARATOR_RGB, width=1)
        if i >= len(body.rows):
            continue
        row = body.rows[i]
        label = row[0]
        secondary = row[2] if len(row) > 2 else ""
        row_color = _row_text_color(secondary)
        cy = (y0 + y1) // 2
        right_edge = x1 - pad

        # One marker box at the row's right, smaller than the row and in
        # the plain glyph white: the play marker when the row carries one,
        # else nothing. "Current" is not a marker: the pipeline washes the
        # current row before any content is drawn (see _list_frame).
        if secondary is PLAY_GLYPH:
            box = max(2, round(layout.row_h * _MARKER_BOX_FRACTION))
            top = y0 + (layout.row_h - box) // 2
            marker_rect = (right_edge - box, top, right_edge, top + box)
            _draw_glyph(img, marker_rect, GLYPH_PLAY, supersample=metrics.supersample)
            draw = ImageDraw.Draw(img)
            right_edge -= box

        if isinstance(secondary, str) and secondary and row_font is not None:
            sec_x = _place_label(
                draw, (x0, y0, x1, y1), secondary, row_font, row_color, lambda r, w, edge=right_edge: edge - w,
            )
            if sec_x is not None:
                right_edge = sec_x - pad

        # A trailing mark keeps its own room: the label is cut to leave it,
        # so the mark is always drawn whole, right after the label.
        mark = row[3] if len(row) > 3 else ""
        measured_mark = None
        mark_w = 0
        if mark and row_font is not None:
            measured_mark = _text_size(draw, mark, row_font)
            if measured_mark is not None:
                mark_w = measured_mark[0] + pad // 2

        if label and row_font is not None and right_edge > x0 + pad + mark_w:
            text = _truncate_to_width(draw, label, row_font, right_edge - (x0 + pad) - mark_w)
            if text:
                measured = _text_size(draw, text, row_font)
                if measured is not None:
                    text_w, text_h, bbox = measured
                    left, top, _, _ = bbox
                    _draw_text_safe(draw, (x0 + pad - left, cy - text_h // 2 - top), text, row_font, fill=row_color)
                    if mark_w:
                        mark_x = x0 + pad + text_w + pad // 2
                        _draw_text_safe(
                            draw,
                            (mark_x - measured_mark[2][0], cy - measured_mark[1] // 2 - measured_mark[2][1]),
                            mark, row_font, fill=row_color,
                        )


# ---------------------------------------------------------------------------
# Compact-tier (2x2) body renderers. Every one of them draws straight onto
# the compact_layout_for() grid — the four cells plus the two divider
# lines, always drawn last so they sit on top of any glyph's own edges —
# rather than layout_for()'s band/body/footer rects, which the compact
# screens never use for drawing (only zone_rects_for() reads them, and only
# off the compact tier).
# ---------------------------------------------------------------------------


def _compact_glyph_box(rect: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    """A glyph box centred within *rect*, sized at _COMPACT_GLYPH_FRACTION
    of its own short side — the compact tier's one glyph-sizing rule,
    shared by every compact cell/row except minus/plus (which are drawn
    straight onto the cell rect by the existing _draw_minus_glyph/_draw_
    plus_glyph, which derive their own reach from the rect's own size)."""
    x0, y0, x1, y1 = rect
    side = round(min(x1 - x0, y1 - y0) * _COMPACT_GLYPH_FRACTION)
    return _centred_box(rect, side)


def _compact_small_glyph_box(rect: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    """A smaller glyph box than _compact_glyph_box's, sized at
    _COMPACT_SMALL_GLYPH_FRACTION of *rect*'s own short side — used only for
    the replay picker's cancel and "more" cells, which sit in a narrower
    column beside the two visible targets and read better at a size smaller
    than every other compact cell's own glyph."""
    x0, y0, x1, y1 = rect
    side = round(min(x1 - x0, y1 - y0) * _COMPACT_SMALL_GLYPH_FRACTION)
    return _centred_box(rect, side)


def _draw_compact_picker_dividers(img: Image.Image, layout: "CompactPickerLayout", metrics: LayoutMetrics) -> None:
    """The replay picker's own white divider lines, drawn last so they sit
    on top of any glyph's own edges: the line under the title band (full
    width), the line between the two grid rows (full width), and the column
    line separating the controls from the two targets — drawn only from the
    title line down to the bottom edge, since it never crosses the title
    band itself."""
    draw = ImageDraw.Draw(img)
    w = metrics.divider_w
    draw.line(
        [(0, layout.title_divider_y), (metrics.width - 1, layout.title_divider_y)], fill=DIVIDER_RGB, width=w,
    )
    draw.line([(0, layout.divider_y), (metrics.width - 1, layout.divider_y)], fill=DIVIDER_RGB, width=w)
    draw.line(
        [(layout.divider_x, layout.title_divider_y), (layout.divider_x, metrics.height - 1)],
        fill=DIVIDER_RGB, width=w,
    )


def _draw_compact_dividers(
    img: Image.Image, layout: "CompactLayout", metrics: LayoutMetrics, *, vertical: str,
) -> None:
    """The compact tier's own white divider lines, drawn last so they sit
    on top of any glyph's own edges. The horizontal line at divider_y,
    spanning the full width, is always drawn; *vertical* selects how much
    of the line at divider_x is drawn: "full" (both rows — the playing 2x2
    and the repeat screen's replaying layout, now its own 2x2), "top" (the
    top row only — the repeat screen's enable layout, whose bottom row is a
    single full-width toggle strip), "bottom" (the bottom row only) or
    "none" (neither row has a vertical divider)."""
    draw = ImageDraw.Draw(img)
    w = metrics.divider_w
    draw.line([(0, layout.divider_y), (metrics.width - 1, layout.divider_y)], fill=DIVIDER_RGB, width=w)
    if vertical == "full":
        draw.line([(layout.divider_x, 0), (layout.divider_x, metrics.height - 1)], fill=DIVIDER_RGB, width=w)
    elif vertical == "top":
        y1 = layout.top_row[3]
        draw.line([(layout.divider_x, 0), (layout.divider_x, y1 - 1)], fill=DIVIDER_RGB, width=w)
    elif vertical == "bottom":
        y0 = layout.bottom_row[1]
        draw.line([(layout.divider_x, y0), (layout.divider_x, metrics.height - 1)], fill=DIVIDER_RGB, width=w)


def _body_compact_controls(img: Image.Image, metrics: LayoutMetrics, body: Body) -> None:
    """The compact tier's playing screen: pager dots (dimmed when there is
    no repeat record to open), mute (inverted over a solid wash while
    muted — the wash itself is a Frame.washes entry, drawn before this body
    runs), minus and plus."""
    c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
    ss = metrics.supersample
    dots_color = _tone(body.dots_lit)
    _draw_glyph(img, _compact_glyph_box(c.tl), GLYPH_TWO_DOTS, 0, dots_color, supersample=ss)
    if body.bell is not None:
        _draw_bell(img, dots_bell_rect(c.tl), body.bell, metrics, _DOTS_BELL_FRACTION)
    mute_color = INVERTED_GLYPH_RGB if body.muted else GLYPH_RGB
    _draw_glyph(img, _compact_glyph_box(c.tr), GLYPH_MUTE, mute_color, supersample=ss)
    draw = ImageDraw.Draw(img)
    _draw_minus_glyph(draw, c.bl)
    _draw_plus_glyph(draw, c.br)
    _draw_compact_dividers(img, c, metrics, vertical="full")


def _draw_compact_list_row(
    img: Image.Image, cell: tuple[int, int, int, int], row: tuple, font, pad: int,
) -> None:
    """One compact-picker row: the label centred in the cell's upper half,
    the secondary "m:ss" string (when it is a plain string — the compact
    picker never carries the appliance-selector's PLAY_GLYPH sentinel)
    centred in the lower half. A row with no secondary (the compact info
    page's own names-only rows) has no lower half to share the cell with, so
    its label is centred on the whole cell instead — the picker's own rows
    always carry "m:ss", so their placement is unchanged. No halo: the whole
    compact frame is already dimmed by Frame.dim_all, unlike the base
    tier's own artwork-backed labels."""
    x0, y0, x1, y1 = cell
    mid = (y0 + y1) // 2
    upper = (x0, y0, x1, mid)
    lower = (x0, mid, x1, y1)
    secondary = row[2] if len(row) > 2 else ""
    has_secondary = isinstance(secondary, str) and bool(secondary)
    label_rect = upper if has_secondary else cell
    draw = ImageDraw.Draw(img)
    max_w = x1 - x0 - 2 * pad
    color = _row_text_color(secondary)
    label = row[0]
    if label and font is not None and max_w > 0:
        text = _truncate_to_width(draw, label, font, max_w)
        _draw_label_centered(draw, label_rect, text, font, color)
    if has_secondary and font is not None and max_w > 0:
        text = _truncate_to_width(draw, secondary, font, max_w)
        _draw_label_centered(draw, lower, text, font, color)


def _body_compact_list(img: Image.Image, metrics: LayoutMetrics, body: Body) -> None:
    """The compact tier's replay picker (or, for the info page, its own
    read-only variant): a tight title bar across the top, horizontally
    centred — the picker's own "Replay" when body.title is unset, else
    body.title (the info page's "Info") — then a 35/65 split — cancel
    top-left and "more" (lit when a second page exists — the compact tier
    wraps rather than clamping, see the manager's own paging) bottom-left,
    both drawn at the picker's own smaller glyph size; the two visible rows
    (current-row highlighting is a Frame.highlights entry, drawn before this
    body runs) fill the right column."""
    p = compact_picker_layout_for(metrics.width, metrics.height, metrics=metrics)
    draw = ImageDraw.Draw(img)
    _draw_label_centered(draw, p.title, body.title or _COMPACT_PICKER_TITLE, _load_font(metrics.font_body))
    row_font = _load_font(metrics.font_body)
    pad = metrics.pad
    for cell, row in zip((p.row0, p.row1), body.rows):
        _draw_compact_list_row(img, cell, row, row_font, pad)
    ss = metrics.supersample
    _draw_glyph(img, _compact_small_glyph_box(p.cancel), GLYPH_CROSS, supersample=ss)
    _draw_glyph(img, _compact_small_glyph_box(p.more), GLYPH_CHEVRON, "down", body.has_more, supersample=ss)
    _draw_compact_picker_dividers(img, p, metrics)


def _body_compact_toggle(img: Image.Image, metrics: LayoutMetrics, body: Body) -> None:
    """The compact tier's repeat-enable screen: the back control (second
    dot lit) top-left, "Repeat Play" plus its arm dot spanning the full
    bottom row — no separate cancel; the top-right cell is left empty. The
    arm dot's own box is capped at metrics.icon (the same reference every
    other compact icon-sized glyph already uses) rather than the row's own
    height: that row is far taller relative to its own width than the base
    tier's row ever is, so the label needs the width back to fit "Repeat
    Play" whole (see _draw_toggle_row's own dot_box paragraph)."""
    c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
    _draw_glyph(img, _compact_glyph_box(c.tl), GLYPH_TWO_DOTS, 1, GLYPH_RGB, supersample=metrics.supersample)
    _draw_toggle_row(img, metrics, c.bottom_row, body.label, body.armed, dot_box=metrics.icon)
    _draw_compact_dividers(img, c, metrics, vertical="top")


def _body_compact_replay(img: Image.Image, metrics: LayoutMetrics, body: Body) -> None:
    """The compact tier's repeat-replaying screen, its own 2x2: the back
    control (second dot lit) top-left, the position-only time (never the
    duration — the manager's own "m:ss / m:ss" line, split before " / ")
    top-right with a halo, like the base tier's own repeat line, Restart
    bottom-left and Stop bottom-right, each dimmed when its own action is
    not currently accepted."""
    c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
    ss = metrics.supersample
    _draw_glyph(img, _compact_glyph_box(c.tl), GLYPH_TWO_DOTS, 1, GLYPH_RGB, supersample=ss)
    font = _load_font(metrics.font_readout)
    position = body.line.split(" / ", 1)[0] if body.line else body.line
    _draw_text_with_halo(img, c.tr, position, font, metrics, align="center")
    start_color = _tone(body.start_enabled)
    stop_color = _tone(body.stop_enabled)
    _draw_glyph(img, _compact_glyph_box(c.bl), GLYPH_RESTART, start_color, supersample=ss)
    _draw_glyph(img, _compact_glyph_box(c.br), GLYPH_STOP, stop_color, supersample=ss)
    _draw_compact_dividers(img, c, metrics, vertical="full")


def _body_info_value(img: Image.Image, metrics: LayoutMetrics, body: Body) -> None:
    """The compact info page's own drill-in: the field's name small in the
    top label band, its value large and centred in the rect below —
    word-wrapped (or, for one over-wide token, character-split) at
    font_readout when it does not fit on one line, shrunk to font_body when
    it still does not, and ellipsized as a last resort — see
    _fit_value_lines(). Never raises: a missing font or a measuring failure
    simply leaves that element undrawn, the same discipline every text
    helper in this module follows."""
    layout = info_value_layout_for(metrics.width, metrics.height, metrics=metrics)
    draw = ImageDraw.Draw(img)
    _draw_label_centered(draw, layout.label, body.label, _load_font(metrics.font_body))
    font_readout = _load_font(metrics.font_readout)
    lines, font = _fit_value_lines(draw, body.line, (metrics.font_readout, metrics.font_body), layout.value)
    if not lines or font is None:
        return
    size = metrics.font_readout if font is font_readout else metrics.font_body
    line_h = size * 1.2
    x0, y0, x1, y1 = layout.value
    top = y0 + (y1 - y0 - len(lines) * line_h) / 2
    for i, line in enumerate(lines):
        row_rect = (x0, int(round(top + i * line_h)), x1, int(round(top + (i + 1) * line_h)))
        _draw_label_centered(draw, row_rect, line, font)


def _eq_caption_text(value: "int | None") -> str:
    """The dB caption a bar's right side shows: "-" while unloaded, else a
    signed whole-dB reading ("+2 dB", "0 dB", "-3 dB")."""
    if value is None:
        return "-"
    return f"{value:+d} dB" if value != 0 else "0 dB"


def _draw_eq_bar(img: Image.Image, bar, label: str, value: "int | None", metrics: LayoutMetrics) -> None:
    """One EQ bar row (bass or treble): the caption (label left, dB right),
    the dimmed track line with a white centre tick, a white fill from
    centre to the marker when the value is known, the marker disc itself,
    and the minus/plus controls — dimmed at the range's own limit or while
    the value has not yet loaded."""
    draw = ImageDraw.Draw(img)
    font = _load_font(metrics.font_body)
    pad = metrics.pad
    _draw_label(draw, bar.caption, label, font, pad)
    _draw_label_right(draw, bar.caption, _eq_caption_text(value), font, pad)

    w = metrics.divider_w
    draw.line([(bar.track_x0, bar.track_y), (bar.track_x1, bar.track_y)], fill=DIMMED_GLYPH_RGB, width=w)
    draw.line(
        [(bar.centre_x, bar.track_y - 2 * w), (bar.centre_x, bar.track_y + 2 * w)], fill=GLYPH_RGB, width=w,
    )
    if value is not None:
        marker_x = bar.centre_x + round(value * (bar.track_x1 - bar.centre_x) / EQ_BASS_TREBLE_LIMIT_DB)
        x0, x1 = sorted((bar.centre_x, marker_x))
        draw.line([(x0, bar.track_y), (x1, bar.track_y)], fill=GLYPH_RGB, width=3 * w)
        r = max(3, pad // 2)
        draw.ellipse([marker_x - r, bar.track_y - r, marker_x + r, bar.track_y + r], fill=GLYPH_RGB)

    at_min = value is not None and value <= -EQ_BASS_TREBLE_LIMIT_DB
    at_max = value is not None and value >= EQ_BASS_TREBLE_LIMIT_DB
    minus_color = _tone(value is not None and not at_min)
    plus_color = _tone(value is not None and not at_max)
    _draw_minus_glyph(draw, bar.down, color=minus_color)
    _draw_plus_glyph(draw, bar.up, color=plus_color)


def _body_eq_bars(img: Image.Image, metrics: LayoutMetrics, body: Body) -> None:
    """The EQ page's own body: the bass bar over the treble bar (see
    eq_layout_for), plus a thin white divider between the two rows at the
    midpoint of the gap between them — the band-divider colour, matching
    every other inter-row boundary in the compositor."""
    layout = eq_layout_for(metrics.width, metrics.height, metrics=metrics)
    _draw_eq_bar(img, layout.bass, "Bass", body.bass_db, metrics)
    _draw_eq_bar(img, layout.treble, "Treble", body.treble_db, metrics)
    divider_y = (layout.bass.row[3] + layout.treble.row[1]) // 2
    ImageDraw.Draw(img).line(
        [(0, divider_y), (metrics.width - 1, divider_y)], fill=DIVIDER_RGB, width=metrics.divider_w,
    )


# The source line of a warning card is drawn at this fraction of the body
# size (never below the floor), in the dimmed glyph colour.
WARNING_SOURCE_FONT_FRACTION = 0.8
WARNING_SOURCE_FONT_FLOOR_PX = 9


def _plan_warning_text(
    draw: ImageDraw.ImageDraw, rect: "tuple[int, int, int, int]", body: Body, metrics: LayoutMetrics,
) -> "list[tuple[str, object, int, tuple]]":
    """Lay out an attributed warning's text in *rect* (the card's message
    row) as (text, font, size, colour) lines, top to bottom. Text arrives
    from outside, so it is fitted rather than assumed short: the source is
    one line (ellipsized when too wide); the title is wrapped at readout
    size, then body size; the message at body size, then at the source's
    small size. The first combination that shows everything wins. When none
    does, the title (body size) keeps as many lines as the row allows, the
    last ellipsized, and the message (small size) gets the height that is
    left, ellipsized, or is dropped when there is none. Returns [] when no
    font loads. Pure: measuring calls only."""
    pad = metrics.pad
    max_w = rect[2] - rect[0] - 2 * pad
    max_h = rect[3] - rect[1]
    small_px = max(WARNING_SOURCE_FONT_FLOOR_PX, round(metrics.font_body * WARNING_SOURCE_FONT_FRACTION))
    body_px = metrics.font_body
    readout_px = metrics.font_readout
    fonts = {px: _load_font(px) for px in (small_px, body_px, readout_px)}
    if any(font is None for font in fonts.values()) or max_w <= 0:
        return []

    out: "list[tuple[str, object, int, tuple]]" = []
    used = 0.0
    source = _truncate_to_width(draw, body.source, fonts[small_px], max_w)
    if source:
        out.append((source, fonts[small_px], small_px, DIMMED_GLYPH_RGB))
        used += small_px * 1.2

    def fitted(title_px: int, message_px: int):
        title = _wrap_words(draw, body.title, fonts[title_px], max_w)
        message = _wrap_words(draw, body.line, fonts[message_px], max_w) if body.line else ()
        if used + (len(title) * title_px + len(message) * message_px) * 1.2 <= max_h:
            return title, message
        return None

    chosen = None
    for title_px, message_px in (
        (readout_px, body_px), (readout_px, small_px), (body_px, body_px), (body_px, small_px),
    ):
        chosen = fitted(title_px, message_px)
        if chosen is not None:
            break
    if chosen is not None:
        title, message = chosen
    else:
        title_px, message_px = body_px, small_px
        title = _wrap_words(draw, body.title, fonts[title_px], max_w)
        message = _wrap_words(draw, body.line, fonts[message_px], max_w) if body.line else ()
        title_n = min(len(title), max(1, int((max_h - used) // (title_px * 1.2))))
        title = _cap_lines(draw, title, title_n, fonts[title_px], max_w)
        message_n = int((max_h - used - title_n * title_px * 1.2) // (message_px * 1.2))
        message = _cap_lines(draw, message, message_n, fonts[message_px], max_w) if message_n > 0 else ()
    out.extend((line, fonts[title_px], title_px, GLYPH_RGB) for line in title)
    out.extend((line, fonts[message_px], message_px, GLYPH_RGB) for line in message)
    return out


def _draw_fitted_warning_text(
    draw: ImageDraw.ImageDraw, rect: "tuple[int, int, int, int]", body: Body, metrics: LayoutMetrics,
) -> None:
    """Draw _plan_warning_text()'s lines, one centred row each, the block
    centred vertically in *rect*."""
    lines = _plan_warning_text(draw, rect, body, metrics)
    x0, y0, x1, y1 = rect
    top = y0 + (y1 - y0 - sum(size * 1.2 for _, _, size, _ in lines)) / 2
    for text, font, size, color in lines:
        row = (x0, int(round(top)), x1, int(round(top + size * 1.2)))
        _draw_label_centered(draw, row, text, font, color)
        top += size * 1.2


def _cell_label_font(draw: ImageDraw.ImageDraw, label: str, width: int, metrics: LayoutMetrics):
    """The body font, stepped down until *label* fits *width* (a three-button
    card on a small panel has cells too narrow for "Restart" at body size)."""
    size = metrics.font_body
    font = _load_font(size)
    while size > 6 and font is not None:
        measured = _text_size(draw, label, font)
        if measured is None or measured[0] <= width:
            break
        size -= 1
        font = _load_font(size)
    return font


def _body_warning(img: Image.Image, metrics: LayoutMetrics, body: Body) -> None:
    """A warning page's content on every tier. With no message the title
    is centred in the whole message row at readout size; with one, the
    title takes the upper three fifths of the row and the message the
    rest at body size. Each button label is centred in its cell at body
    size. Then the crosshair: a horizontal line at divider_y across the
    card's full width, and one vertical line per gap between cells,
    spanning the bottom row only (the message row is never split). On
    the compact tier the card is the whole panel, so a two-button page
    is exactly the 2x2's own bottom-row divider pattern and a one-button
    page has no vertical line at all. A page with no cells has no
    crosshair. With body.percent set, a progress bar takes the bottom
    quarter of the message row (a dimmed track from the card's inner left
    to right edge, a white fill to the percent) and the text is laid out
    in the rest of the row. With body.source set, the row holds the source
    over the title over the message, wrapped and shrunk to fit (see
    _plan_warning_text)."""
    layout = warning_layout_for(metrics.width, metrics.height, buttons=len(body.buttons), metrics=metrics)
    draw = ImageDraw.Draw(img)
    readout_font = _load_font(metrics.font_readout)
    body_font = _load_font(metrics.font_body)
    mx0, my0, mx1, my1 = layout.message
    w = metrics.divider_w
    if body.percent is not None:
        zone = (my1 - my0) // 4
        bar_h = max(3, 2 * w)
        bar_y0 = my1 - zone // 2 - bar_h // 2
        x0, x1 = mx0 + metrics.pad, mx1 - metrics.pad
        fill_x1 = x0 + round((x1 - x0) * clamp_percent(body.percent) / 100)
        draw.rectangle([x0, bar_y0, x1 - 1, bar_y0 + bar_h - 1], fill=DIMMED_GLYPH_RGB)
        if fill_x1 > x0:
            draw.rectangle([x0, bar_y0, fill_x1 - 1, bar_y0 + bar_h - 1], fill=GLYPH_RGB)
        my1 -= zone
    if body.source:
        _draw_fitted_warning_text(draw, (mx0, my0, mx1, my1), body, metrics)
    elif body.line:
        split = my0 + (my1 - my0) * 3 // 5
        _draw_label_centered(draw, (mx0, my0, mx1, split), body.title, readout_font)
        _draw_label_centered(draw, (mx0, split, mx1, my1), body.line, body_font)
    else:
        _draw_label_centered(draw, (mx0, my0, mx1, my1), body.title, readout_font)
    for rect, label in zip(layout.cells, body.buttons):
        _draw_label_centered(draw, rect, label, _cell_label_font(draw, label, rect[2] - rect[0] - 2 * metrics.pad, metrics))
    if not layout.cells:
        return
    cx0, cy0, cx1, cy1 = layout.card
    draw.line([(cx0, layout.divider_y), (cx1 - 1, layout.divider_y)], fill=DIVIDER_RGB, width=w)
    for x in layout.divider_xs:
        draw.line([(x, layout.cells[0][1]), (x, cy1 - 1)], fill=DIVIDER_RGB, width=w)


def _body_centred_label(img: Image.Image, metrics: LayoutMetrics, body: Body) -> None:
    """One string (body.line) centred on the whole panel at the readout
    size — the "Restarting..." and "Starting..." screens."""
    draw = ImageDraw.Draw(img)
    _draw_label_centered(draw, (0, 0, metrics.width, metrics.height), body.line, _load_font(metrics.font_readout))


_BODY_RENDERERS = {
    BODY_NONE: _body_none,
    BODY_NOW_PLAYING: _body_now_playing,
    BODY_TOGGLE_ROW: _body_toggle_row,
    BODY_REPEAT_LINE: _body_repeat_line,
    BODY_LIST_ROWS: _body_list_rows,
    BODY_IDLE_BADGE: _body_idle_badge,
    BODY_COMPACT_CONTROLS: _body_compact_controls,
    BODY_COMPACT_LIST: _body_compact_list,
    BODY_COMPACT_TOGGLE: _body_compact_toggle,
    BODY_COMPACT_REPLAY: _body_compact_replay,
    BODY_INFO_VALUE: _body_info_value,
    BODY_EQ_BARS: _body_eq_bars,
    BODY_WARNING: _body_warning,
    BODY_CENTRED_LABEL: _body_centred_label,
}


def _footer_none(img: Image.Image, layout, metrics: LayoutMetrics, footer: Footer) -> None:
    pass


def _footer_volume(img: Image.Image, layout, metrics: LayoutMetrics, footer: Footer) -> None:
    """The two-way minus/plus footer (the repeat screen's replaying layout,
    the per-output detail page). Each glyph dims to DIMMED_GLYPH_RGB when
    its own side is disabled (Footer.left_enabled/right_enabled) — the
    detail page's own steppers when the output is not selected, matching
    the shade the disabled Restart/Stop labels already use elsewhere."""
    left_color = _tone(footer.left_enabled)
    right_color = _tone(footer.right_enabled)
    _draw_bottom_band(
        img, layout, metrics,
        left_rect=layout.down, right_rect=layout.up,
        draw_left=lambda d, r: _draw_minus_glyph(d, r, color=left_color),
        draw_right=lambda d, r: _draw_plus_glyph(d, r, color=right_color),
    )


def _footer_volume_mute(img: Image.Image, layout, metrics: LayoutMetrics, footer: Footer) -> None:
    """The main screen's own three-way footer: minus | plus | mute, left to
    right (vol-/vol+ stay at today's thumb
    positions, mute moves off the header into its own cell). The mute cell
    always shows the crossed-speaker glyph (GLYPH_MUTE) — this control IS
    the mute toggle, not a state readout — and carries the persistent wash
    while muted (see _now_playing_frame's `highlights`), on top of which a
    genuine press adds the momentary wash."""
    draw = ImageDraw.Draw(img)
    _draw_minus_glyph(draw, layout.footer_down)
    _draw_plus_glyph(draw, layout.footer_up)
    _draw_glyph(img, layout.footer_mute, GLYPH_MUTE, supersample=metrics.supersample)
    draw = ImageDraw.Draw(img)  # _draw_glyph pastes into img; get a fresh Draw handle
    _draw_band_divider(draw, layout, metrics, layout.footer_dividers)


def _footer_labels(img: Image.Image, layout, metrics: LayoutMetrics, footer: Footer) -> None:
    font = _load_font(metrics.font_readout)
    left_color = _tone(footer.left_enabled)
    right_color = _tone(footer.right_enabled)
    _draw_bottom_band(
        img, layout, metrics,
        left_rect=layout.down, right_rect=layout.up,
        draw_left=lambda d, r: _draw_label_centered(d, r, footer.left_text, font, color=left_color),
        draw_right=lambda d, r: _draw_label_centered(d, r, footer.right_text, font, color=right_color),
    )


def _footer_list_bar(img: Image.Image, layout, metrics: LayoutMetrics, footer: Footer) -> None:
    ll = list_layout_for(metrics.width, metrics.height, metrics=metrics)
    ss = metrics.supersample
    _draw_glyph(img, ll.back, GLYPH_CHEVRON, "left", True, supersample=ss)
    _draw_glyph(img, ll.down, GLYPH_CHEVRON, "down", footer.has_next, supersample=ss)
    _draw_glyph(img, ll.up, GLYPH_CHEVRON, "up", footer.has_prev, supersample=ss)


def _footer_list_rail(img: Image.Image, layout, metrics: LayoutMetrics, footer: Footer) -> None:
    """The right-rail counterpart to _footer_list_bar(): the same three
    controls (previous page, back/cancel, next page), stacked top to bottom
    in a dimmed column at the panel's right edge instead of side by side in
    a bottom bar. A 1px separator column marks the boundary between the rows
    and the rail, in the same shade the row separators use. Each glyph is
    drawn into a centred metrics.rail_glyph-side box within its own zone,
    not the whole zone — the rail column stays a full touch target even
    though the glyph inside it is smaller."""
    ll = list_layout_for(metrics.width, metrics.height, metrics=metrics)
    _dim_rect(img, ll.rail)
    ImageDraw.Draw(img).line(
        [(ll.rail[0] - 1, 0), (ll.rail[0] - 1, ll.rail[3] - 1)], fill=LIST_SEPARATOR_RGB, width=1,
    )
    ss = metrics.supersample
    side = metrics.rail_glyph
    _draw_glyph(img, _centred_box(ll.rail_up, side), GLYPH_CHEVRON, "up", footer.has_prev, supersample=ss)
    _draw_glyph(img, _centred_box(ll.rail_cancel, side), GLYPH_CROSS, supersample=ss)
    _draw_glyph(img, _centred_box(ll.rail_down, side), GLYPH_CHEVRON, "down", footer.has_next, supersample=ss)


_FOOTER_RENDERERS = {
    FOOTER_NONE: _footer_none,
    FOOTER_VOLUME: _footer_volume,
    FOOTER_VOLUME_MUTE: _footer_volume_mute,
    FOOTER_LABELS: _footer_labels,
    FOOTER_LIST_BAR: _footer_list_bar,
    FOOTER_LIST_RAIL: _footer_list_rail,
}


def _draw_card(img: Image.Image, rect: Rect, metrics: LayoutMetrics) -> None:
    """A sharp-cornered card: a dark translucent drop shadow offset down
    and right by the panel's pad, a flat fill, then a thin translucent
    white outline. The shadow and outline are each a _draw_wash-style
    alpha composite clipped to the panel, so nothing outside the panel is
    ever touched and the outline reads as a subtle edge rather than a hard
    line."""
    x0, y0, x1, y1 = rect
    offset = max(2, metrics.pad // 2)
    shadow = (
        min(metrics.width, x0 + offset), min(metrics.height, y0 + offset),
        min(metrics.width, x1 + offset), min(metrics.height, y1 + offset),
    )
    _draw_wash(img, shadow, CARD_SHADOW_RGB, CARD_SHADOW_ALPHA)
    draw = ImageDraw.Draw(img)
    draw.rectangle([x0, y0, x1 - 1, y1 - 1], fill=CARD_FILL_RGB)
    _draw_card_outline(img, (x0, y0, x1, y1), metrics.divider_w)


def _draw_card_outline(img: Image.Image, rect: Rect, width: int) -> None:
    """The card's own thin outline, alpha-composited over its fill so it
    reads as a subtle translucent edge rather than a flat, opaque line."""
    x0, y0, x1, y1 = rect
    w, h = x1 - x0, y1 - y0
    if w <= 0 or h <= 0:
        return
    layer = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    ImageDraw.Draw(layer).rectangle(
        [0, 0, w - 1, h - 1], outline=(*CARD_OUTLINE_RGB, CARD_OUTLINE_ALPHA), width=width,
    )
    region = img.crop(rect).convert("RGBA")
    composited = Image.alpha_composite(region, layer).convert("RGB")
    img.paste(composited, (x0, y0))


def _compose_frame(
    base, width: int, height: int, frame: Frame, *, rotate: bool, bgr: bool,
    metrics: LayoutMetrics | None = None,
) -> Image.Image:
    """The one pipeline every screen frame is built from: background, dims,
    then any row highlights, pressed wash, header, body, footer, then
    rotate/BGR. *frame* carries everything screen-specific; the geometry
    itself always comes from layout_for() (plus list_layout_for()/
    repeat_layout_for() inside the renderers that need them) — never
    computed here. *metrics*=None means metrics_for(width, height) —
    today's geometry, density-unaware.

    Dimming happens before the pressed wash so a highlighted zone still
    reads brighter than its dimmed surroundings, matching the dimmed band
    it sits on; the wash happens before any content so text/glyphs always
    land on top of it. The row highlight sits under a persistent state
    wash, which itself sits under the pressed wash — a genuine touch always
    reads as an additional flash over any state already shown. Body and
    footer never overlap, so their relative order does not matter. No
    blanket exception handling here: every draw helper already degrades on
    its own (a missing font or a Pillow failure simply skips that one
    element), and an unrecognised body/footer kind is a programming error
    that should raise rather than be swallowed.
    """
    if metrics is None:
        metrics = metrics_for(width, height)
    img = _new_frame(base, width, height, frame.background)
    layout = layout_for(width, height, metrics=metrics)
    if frame.dim_top:
        _dim_rect(img, layout.top_band)
    if frame.dim_bottom:
        _dim_rect(img, layout.bottom_band)
    if frame.dim_all:
        _dim_rect(img, (0, 0, width, height))
    if frame.card is not None:
        _draw_card(img, frame.card, metrics)
    for rect in frame.highlights:
        _draw_row_highlight(img, rect)
    for rect, alpha in frame.washes:
        _draw_wash(img, rect, PRESSED_FILL_RGB, alpha)
    for rect in frame.pressed:
        _draw_pressed_highlight(img, rect)
    if frame.header is not None:
        _draw_header(img, layout, frame.header, metrics)
    _BODY_RENDERERS[frame.body.kind](img, metrics, frame.body)
    _FOOTER_RENDERERS[frame.footer.kind](img, layout, metrics, frame.footer)
    return _finish(img, rotate, bgr)


def _zone_rect(
    geometry: str, zone: "TouchZone | None", index: "int | None", width: int, height: int,
    metrics: "LayoutMetrics | None" = None,
) -> "Rect | None":
    """The rect the touch layer would report for (zone, index) on
    *geometry*, or None when no such entry exists (a zone from another
    geometry, or a stale LIST_ROW index): nothing is washed. *metrics*
    resolves the same way zone_rects_for() resolves it, so a pressed rect
    is always looked up against the exact geometry a renderer drew — never
    a density-free approximation of it."""
    if zone is None:
        return None
    for entry in zone_rects_for(geometry, width, height, metrics=metrics):
        if entry.zone == zone and entry.index == index:
            return entry.rect
    return None


def _main_pressed_rects(
    pressed: "TouchZone | None", width: int, height: int, metrics: "LayoutMetrics | None" = None,
) -> tuple[Rect, ...]:
    """The now-playing screen's pressed-rect lookup: a stale or unrecognised
    zone (e.g. one that belongs to a different geometry) washes nothing."""
    rect = _zone_rect(GEOMETRY_MAIN, pressed, None, width, height, metrics)
    return (rect,) if rect is not None else ()


def _with_corner_bell(image, overlay, metrics: LayoutMetrics):
    """Resting artwork: *image* itself when there is no bell (the frame is
    the bare base), otherwise a copy with the bell on a dark translucent
    disc in the corner square (IdleLayout.info)."""
    if overlay is None or overlay.bell is None:
        return image
    frame = image.copy()
    x0, y0, x1, y1 = idle_layout_for(image.width, image.height, metrics=metrics).info
    w, h, ss = x1 - x0, y1 - y0, metrics.supersample
    disc = Image.new("RGBA", (w * ss, h * ss), (0, 0, 0, 0))
    ImageDraw.Draw(disc).ellipse([0, 0, w * ss - 1, h * ss - 1], fill=CORNER_DISC_RGBA)
    disc = disc.resize((w, h), _LANCZOS)
    frame.paste(Image.alpha_composite(frame.crop((x0, y0, x1, y1)).convert("RGBA"), disc).convert("RGB"), (x0, y0))
    _draw_bell(frame, (x0, y0, x1, y1), overlay.bell, metrics, _CORNER_BELL_FRACTION)
    return frame


def _compact_controls_frame(overlay: OverlayState, width: int, height: int, metrics: LayoutMetrics) -> Frame:
    """The compact tier's playing screen: dimmed base behind, the mute
    cell's own solid wash when muted (before the body's inverted glyph
    draws over it — see _compose_frame's draw order), pressed resolved
    against the compact MAIN table automatically (GEOMETRY_MAIN itself
    branches on the tier)."""
    c = compact_layout_for(width, height, metrics=metrics)
    return Frame(
        background=BG_BASE,
        dim_all=True,
        pressed=_main_pressed_rects(overlay.pressed, width, height, metrics),
        washes=((c.tr, 255),) if overlay.muted else (),
        header=None,
        body=Body(BODY_COMPACT_CONTROLS, muted=bool(overlay.muted), dots_lit=overlay.dots, bell=overlay.bell),
        footer=Footer(FOOTER_NONE),
    )


def _now_playing_frame(overlay: OverlayState, width: int, height: int, metrics: LayoutMetrics) -> Frame:
    layout = layout_for(width, height, metrics=metrics)
    return Frame(
        background=BG_BASE,
        dim_top=True,
        dim_bottom=True,
        pressed=_main_pressed_rects(overlay.pressed, width, height, metrics),
        # The persistent mute wash: brighter than the dimmed footer band
        # while muted, independent of any genuine touch — a tap still adds
        # its own momentary wash on top (see _compose_frame's draw order).
        # A dedicated (stronger) strength from the row-highlight wash below,
        # which was tuned for the undimmed list chassis and all but
        # disappears over a dimmed footer band under a white glyph.
        washes=((layout.footer_mute, MUTE_WASH_ALPHA),) if overlay.muted else (),
        header=Header(
            name=overlay.name, volume=overlay.volume,
            dots_filled=0 if overlay.dots else None,
            dots_count=3 if overlay.eq_pages else 2, bell=overlay.bell,
        ),
        body=Body(BODY_NOW_PLAYING, title=overlay.title, artist=overlay.artist, album=overlay.album),
        footer=Footer(FOOTER_VOLUME_MUTE),
    )


def _repeat_pressed_rects(
    state: RepeatViewState, width: int, height: int, metrics: "LayoutMetrics | None" = None,
) -> tuple[Rect, ...]:
    """The repeat screen's pressed-rect lookup: a genuine touch first, then
    the fade-out-in-flight Stop wash layered on top of it when replaying —
    same order the two highlights are drawn in today. Resolved against
    GEOMETRY_REPEAT_REPLAY, rather than GEOMETRY_REPEAT, exactly when the
    compact tier's own replaying layout is showing — the only tier/layout
    combination the two geometries actually disagree about (see
    dial_touch_layout.zone_rects_for)."""
    if metrics is None:
        metrics = metrics_for(width, height)
    replaying = state.layout == "replaying"
    geometry = GEOMETRY_REPEAT_REPLAY if (metrics.content_tier == CONTENT_COMPACT and replaying) else GEOMETRY_REPEAT
    rects = []
    rect = _zone_rect(geometry, state.pressed, None, width, height, metrics)
    if rect is not None:
        rects.append(rect)
    if replaying and state.stop_pressed:
        stop_rect = _zone_rect(geometry, TouchZone.REPEAT_STOP, None, width, height, metrics)
        if stop_rect is not None:
            rects.append(stop_rect)
    return tuple(rects)


def _compact_repeat_frame(state: RepeatViewState, width: int, height: int, metrics: LayoutMetrics) -> Frame:
    """The compact tier's repeat screen: dimmed base behind both of its own
    states (enable and replaying alike — the compact tier's own shared
    rendering discipline), no header (no NAME/OUTPUTS on compact), pressed
    resolved against
    whichever of GEOMETRY_REPEAT/GEOMETRY_REPEAT_REPLAY _repeat_pressed_
    rects picks for this state."""
    replaying = state.layout == "replaying"
    body = (
        Body(BODY_COMPACT_REPLAY, line=state.line, start_enabled=state.start_enabled, stop_enabled=state.stop_enabled)
        if replaying
        else Body(BODY_COMPACT_TOGGLE, armed=state.armed, label="Repeat Play")
    )
    return Frame(
        background=BG_BASE,
        dim_all=True,
        pressed=_repeat_pressed_rects(state, width, height, metrics),
        header=None,
        body=body,
        footer=Footer(FOOTER_NONE),
    )


def _repeat_frame(state: RepeatViewState, width: int, height: int, metrics: LayoutMetrics) -> Frame:
    if metrics.content_tier == CONTENT_COMPACT:
        return _compact_repeat_frame(state, width, height, metrics)
    replaying = state.layout == "replaying"
    if replaying:
        body = Body(BODY_REPEAT_LINE, line=state.line)
        footer = Footer(
            FOOTER_LABELS, left_text="Restart", right_text="Stop",
            left_enabled=state.start_enabled, right_enabled=state.stop_enabled,
        )
    else:
        body = Body(BODY_TOGGLE_ROW, armed=state.armed, label="Repeat Play")
        footer = Footer(FOOTER_NONE)
    return Frame(
        background=BG_BASE if replaying else BG_CHASSIS,
        dim_top=True,
        dim_bottom=replaying,
        pressed=_repeat_pressed_rects(state, width, height, metrics),
        header=Header(
            name=state.name, volume=state.volume, dots_filled=1,
            dots_count=3 if state.eq_pages else 2, bell=state.bell,
        ),
        body=body,
        footer=footer,
    )


def _eq_pressed_rects(
    pressed: "TouchZone | None", width: int, height: int, metrics: "LayoutMetrics | None" = None,
) -> tuple[Rect, ...]:
    """The EQ page's pressed-rect lookup: a stale or unrecognised zone (one
    that belongs to a different geometry) washes nothing — the same
    _output_pressed_rects shape, minus the enabled/disabled gate (every EQ
    zone is always tappable once the page is open)."""
    rect = _zone_rect(GEOMETRY_EQ, pressed, None, width, height, metrics)
    return (rect,) if rect is not None else ()


def _eq_frame(state: "EqViewState", width: int, height: int, metrics: LayoutMetrics) -> Frame:
    return Frame(
        background=BG_CHASSIS,
        dim_top=True,
        pressed=_eq_pressed_rects(state.pressed, width, height, metrics),
        header=Header(
            name=state.name, volume=state.volume, dots_filled=2, dots_count=3,
            bell=state.bell,
        ),
        body=Body(BODY_EQ_BARS, bass_db=state.bass_db, treble_db=state.treble_db),
        footer=Footer(FOOTER_NONE),
    )


def _warning_frame(view: WarningView, width: int, height: int, metrics: LayoutMetrics) -> Frame:
    """Dimmed base on every tier; the card only off compact (on compact the
    grid fills the panel and the dimmed base is the whole backdrop, the
    same convention every other compact screen follows)."""
    layout = warning_layout_for(width, height, buttons=len(view.buttons), metrics=metrics)
    compact = metrics.content_tier == CONTENT_COMPACT
    return Frame(
        background=BG_BASE,
        dim_all=True,
        card=None if compact else layout.card,
        pressed=(
            (layout.cells[view.pressed],)
            if view.pressed is not None and 0 <= view.pressed < len(layout.cells) else ()
        ),
        header=None,
        body=Body(
            BODY_WARNING, title=view.title, line=view.message, buttons=view.buttons, percent=view.percent,
            source=view.source,
        ),
        footer=Footer(FOOTER_NONE),
    )


def _output_pressed_rects(
    pressed: "TouchZone | None", enabled: bool, width: int, height: int,
    metrics: "LayoutMetrics | None" = None,
) -> tuple[Rect, ...]:
    """The per-output detail page's pressed-rect lookup: a stale or
    unrecognised zone (e.g. one that belongs to a different geometry)
    washes nothing, and neither does a stepper tap while the output is
    disabled — the steppers are touch-inert then, not just dimmed, so a
    tap on them neither lights nor acts."""
    if pressed in (TouchZone.OUTPUT_UP, TouchZone.OUTPUT_DOWN) and not enabled:
        return ()
    rect = _zone_rect(GEOMETRY_OUTPUT, pressed, None, width, height, metrics)
    return (rect,) if rect is not None else ()


def _output_frame(state: "OutputViewState", width: int, height: int, metrics: LayoutMetrics) -> Frame:
    return Frame(
        background=BG_CHASSIS,
        dim_top=True,
        dim_bottom=True,
        pressed=_output_pressed_rects(state.pressed, state.selected, width, height, metrics),
        header=Header(
            name=state.name, volume=state.level, dots_filled=None, back=True,
        ),
        body=Body(BODY_TOGGLE_ROW, armed=state.selected, label=state.output_name),
        footer=Footer(FOOTER_VOLUME, left_enabled=state.selected, right_enabled=state.selected),
    )


def _list_pressed_rects(
    state: ListState, width: int, height: int, metrics: "LayoutMetrics | None" = None,
) -> tuple[Rect, ...]:
    """The selector screen's pressed-rect lookup: a stale LIST_ROW index
    (the roster shrank between paint and tap) washes nothing rather than
    raising."""
    if state.pressed is None:
        return ()
    zone, index = state.pressed
    rect = _zone_rect(GEOMETRY_LIST, zone, index, width, height, metrics)
    return (rect,) if rect is not None else ()


def _list_highlight_rects(rows: tuple, layout) -> tuple[Rect, ...]:
    """The row rects that get the current-row wash: every visible row
    whose tuple marks it current. Extra rows beyond the page are ignored,
    never indexed (the body renderer skips them from the other side)."""
    return tuple(layout.rows[i] for i, row in enumerate(rows[:len(layout.rows)]) if row[1])


def _compact_list_highlight_rects(rows: tuple, cells: tuple[Rect, Rect]) -> tuple[Rect, ...]:
    """The compact picker's own current-row wash: the same rule
    _list_highlight_rects() applies, over *cells* — the picker layout's own
    (row0, row1) rects — instead of list_layout_for()'s own row rects."""
    return tuple(cells[i] for i, row in enumerate(rows[:len(cells)]) if row[1])


def _compact_list_frame(state: ListState, width: int, height: int, metrics: LayoutMetrics) -> Frame:
    """The compact tier's replay picker (or, with state.plain_background,
    the read-only info page reusing this same layout): dimmed base behind
    (the manager's own current base image, passed through compose_list()'s
    *base*) for the picker, or a flat undimmed chassis for the info page
    (nothing to dim — it has no base image of its own); pressed and the
    current-row wash resolved against the picker's own title-band-plus-grid
    layout."""
    p = compact_picker_layout_for(width, height, metrics=metrics)
    return Frame(
        background=BG_CHASSIS if state.plain_background else BG_BASE,
        dim_all=not state.plain_background,
        pressed=_list_pressed_rects(state, width, height, metrics),
        highlights=_compact_list_highlight_rects(state.rows, (p.row0, p.row1)),
        header=None,
        body=Body(
            BODY_COMPACT_LIST, rows=state.rows, has_more=state.has_prev or state.has_next,
            title=state.title or "",
        ),
        footer=Footer(FOOTER_NONE),
    )


def _list_frame(state: ListState, width: int, height: int, metrics: LayoutMetrics) -> Frame:
    layout = list_layout_for(width, height, metrics=metrics)
    rail = layout.rail is not None
    return Frame(
        background=BG_CHASSIS,
        dim_top=False,
        dim_bottom=not rail,
        pressed=_list_pressed_rects(state, width, height, metrics),
        highlights=_list_highlight_rects(state.rows, layout),
        header=None,
        body=Body(BODY_LIST_ROWS, rows=state.rows),
        footer=Footer(
            FOOTER_LIST_RAIL if rail else FOOTER_LIST_BAR,
            has_prev=state.has_prev, has_next=state.has_next,
        ),
    )
