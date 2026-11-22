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
  compose_warning()         a warning or status card
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

The pipeline sits on four layers, lowest first: dial_display_views (the
view and frame data), dial_display_draw (fonts, text, glyphs and the canvas
primitives), dial_display_reveal (the reveal frames) and dial_display_render
(the body, footer and header renderers).

Drawing never raises (see dial_display_draw). An unrecognised Body/Footer
kind is a programming error and is left to raise. The appliance name sits
over the dimmed top band and is drawn plain.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import dataclasses
import functools

import numpy as np
from PIL import Image, ImageChops

from dial_display_image import transform_artwork_for_panel
from dial_display_draw import (
    _BOX,
    _dim_rect,
    _draw_pressed_highlight,
    _draw_row_highlight,
    _draw_wash,
    _finish,
    _glyph_tile,
    _halo_layer,
    _load_font,
    _new_frame,
)
import dial_display_reveal
from dial_display_reveal import (
    RevealLayers,
    _build_reveal_arrays,
    _reveal_frame,
    _reveal_output_size,
    _scale_rect,
    _shrunk_base,
)
from dial_display_render import (
    _BODY_RENDERERS,
    _FOOTER_RENDERERS,
    _draw_header,
    _draw_timer_line,
    _timer_fit,
    _with_corner_bell,
)
from dial_display_palette import (
    ALERT_ALPHA_HIGH,
    ALERT_ALPHA_LOW,
    ALERT_RGB,
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
    OutputViewState,
    OverlayState,
    RESTARTING_TEXT,
    RepeatViewState,
    STARTING_TEXT,
    WIFI_SIGNAL,
    WarningView,
)
from dial_layout_metrics import CONTENT_COMPACT, LayoutMetrics, metrics_for
from dial_touch_layout import (
    GEOMETRY_EQ,
    GEOMETRY_LIST,
    GEOMETRY_MAIN,
    GEOMETRY_OUTPUT,
    GEOMETRY_REPEAT,
    GEOMETRY_REPEAT_REPLAY,
    Rect,
    TouchZone,
    compact_layout_for,
    compact_picker_layout_for,
    layout_for,
    list_layout_for,
    repeat_layout_for,
    warning_layout_for,
    zone_rects_for,
)


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
        elif reveal_progress >= 1.0:
            # The bands have left the panel: the same frame a hidden overlay
            # produces, through the same call.
            return _with_corner_bell(image, overlay, metrics)
        else:
            frame = _now_playing_frame(overlay, image.width, image.height, metrics)
        if metrics.content_tier == CONTENT_COMPACT or not reveal_progress > 0.0:
            if overlay.alert and overlay.pulse < 1.0:
                return _pulse_frame(image, frame, metrics, overlay.pulse)
            return _compose_frame(
                image, image.width, image.height, frame, rotate=False, bgr=False, metrics=metrics,
            )
        # A slide draws the alert wash solid: its layers are memoised per
        # frame, which a pulse step would change.
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
        self, width: int, height: int, view: WarningView, *, rotate: bool, bgr: bool,
        metrics: LayoutMetrics | None = None,
    ):
        """Build one display-ready frame for a warning or status card: a
        flat, opaque chassis fill on every tier whatever artwork was
        showing, with the card filling the whole panel: the title (and
        message, if any) over the button cells with a white crosshair, a
        horizontal line under the message row and a vertical line between
        neighbouring cells (see BODY_WARNING). The pressed cell, if any,
        carries the ordinary press wash and nothing else. rotate/bgr last,
        as always. Never raises: a font failure leaves the dividers without
        text. metrics: see compose()."""
        return _compose_screen(
            None, width, height, lambda w, h, m: _warning_frame(view, w, h, m),
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


def _reset_render_caches() -> None:
    """Clear the memoised glyph-tile, halo-layer, reveal-layer and shrunk
    reveal-base caches. Test-only hook, the same purpose _reset_font_cache()
    serves for the font cache — lets a test exercise any of them from a
    clean slate without restarting the process."""
    _glyph_tile.cache_clear()
    _halo_layer.cache_clear()
    _timer_fit.cache_clear()
    _reveal_layers.cache_clear()
    dial_display_reveal._reset_shrunk_base()
    global _alert_memo
    _alert_memo = None


# The two ends of the mute cell's alert pulse for one base and frame, so a
# pulse step composes nothing: (base, frame, the solid end, then the cell of
# the see-through end and of the solid end as arrays). Holding the base keeps
# its identity from being reused while the entry lives, as _shrunk_base does.
_alert_memo: "tuple | None" = None


def _alert_washes(cell: Rect, alpha: int) -> tuple:
    return ((cell, ALERT_RGB, alpha),)


def _alert_cell(metrics: LayoutMetrics, width: int, height: int) -> Rect:
    """The mute cell the alert wash covers on the playing screen."""
    if metrics.content_tier == CONTENT_COMPACT:
        return compact_layout_for(width, height, metrics=metrics).tr
    return layout_for(width, height, metrics=metrics).footer_mute


def _pulse_frame(image, frame: Frame, metrics: LayoutMetrics, pulse: float) -> Image.Image:
    """*frame* (which carries the solid alert wash) over *image* with the
    wash at *pulse* of the way from see-through to solid. Every drawing step
    after the wash is linear in the pixel behind it (see _reveal_layers), so
    the cell at any strength is the blend of the two ends; both ends are
    composed once per base and frame and the rest of the panel is the solid
    end's own pixels, so a step changes nothing outside the cell."""
    global _alert_memo
    memo = _alert_memo
    if memo is None or memo[0] is not image or memo[1] != frame:
        cell = _alert_cell(metrics, image.width, image.height)
        low = dataclasses.replace(frame, washes=_alert_washes(cell, ALERT_ALPHA_LOW))
        see = _compose_frame(image, image.width, image.height, low, rotate=False, bgr=False, metrics=metrics)
        solid = _compose_frame(image, image.width, image.height, frame, rotate=False, bgr=False, metrics=metrics)
        memo = (image, frame, solid, cell,
                np.asarray(see.crop(cell), dtype=np.float32), np.asarray(solid.crop(cell), dtype=np.float32))
        _alert_memo = memo
    solid, cell, lo, hi = memo[2:]
    out = solid.copy()
    if pulse < 1.0:
        t = np.float32(max(0.0, pulse))
        blended = (lo + (hi - lo) * t + np.float32(0.5)).astype(np.uint8)
        out.paste(Image.fromarray(blended, "RGB"), cell[:2])
    return out


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
    for rect in frame.highlights:
        _draw_row_highlight(img, rect)
    for rect, rgb, alpha in frame.washes:
        _draw_wash(img, rect, rgb, alpha)
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


def _compact_controls_frame(overlay: OverlayState, width: int, height: int, metrics: LayoutMetrics) -> Frame:
    """The compact tier's playing screen: dimmed base behind, the mute
    cell's solid alert wash when muted or paused (before the body's glyph
    draws over it — see _compose_frame's draw order; _pulse_frame fades
    it), pressed resolved against the compact MAIN table automatically
    (GEOMETRY_MAIN itself branches on the tier)."""
    c = compact_layout_for(width, height, metrics=metrics)
    return Frame(
        background=BG_BASE,
        dim_all=True,
        pressed=_main_pressed_rects(overlay.pressed, width, height, metrics),
        washes=_alert_washes(c.tr, ALERT_ALPHA_HIGH) if overlay.alert else (),
        header=None,
        body=Body(BODY_COMPACT_CONTROLS, paused=overlay.paused, dots_lit=overlay.dots, bell=overlay.bell),
        footer=Footer(FOOTER_NONE),
    )


def _now_playing_frame(overlay: OverlayState, width: int, height: int, metrics: LayoutMetrics) -> Frame:
    layout = layout_for(width, height, metrics=metrics)
    return Frame(
        background=BG_BASE,
        dim_top=True,
        dim_bottom=True,
        pressed=_main_pressed_rects(overlay.pressed, width, height, metrics),
        # The alert wash while muted or paused, independent of any genuine
        # touch — a tap still adds its own momentary wash on top (see
        # _compose_frame's draw order). Solid here; _pulse_frame fades it.
        washes=_alert_washes(layout.footer_mute, ALERT_ALPHA_HIGH) if overlay.alert else (),
        header=Header(
            name=overlay.name, volume=overlay.volume,
            dots_filled=0 if overlay.dots else None,
            dots_count=3 if overlay.eq_pages else 2, bell=overlay.bell,
        ),
        body=Body(BODY_NOW_PLAYING, title=overlay.title, artist=overlay.artist, album=overlay.album),
        footer=Footer(FOOTER_VOLUME_MUTE, paused=overlay.paused),
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
    """The flat chassis fill on every tier: the card is the whole panel, so
    it is opaque whatever the base image."""
    layout = warning_layout_for(width, height, buttons=len(view.buttons), metrics=metrics)
    return Frame(
        background=BG_CHASSIS,
        pressed=(
            (layout.cells[view.pressed],)
            if view.pressed is not None and 0 <= view.pressed < len(layout.cells) else ()
        ),
        header=None,
        body=Body(
            BODY_WARNING, title=view.title, line=view.message, buttons=view.buttons, percent=view.percent,
            source=view.source, severity=view.severity, detail=view.detail,
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
