"""dial_display_render.py -- the screen renderers.

What each body kind and each footer kind draws, the header, the card, the
replay timer line and the corner bell. A body renderer takes
(img, metrics, body) and a footer renderer (img, layout, metrics, footer);
both draw in place onto the frame the compositor's pipeline has prepared.
The two dispatch tables, _BODY_RENDERERS and _FOOTER_RENDERERS, are keyed by
the kind constants in dial_display_views. An unrecognised kind is a
programming error and is left to raise.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import functools

from PIL import Image, ImageDraw, ImageEnhance

from dial_display_draw import (
    GLYPH_BELL,
    GLYPH_CHEVRON,
    GLYPH_CROSS,
    GLYPH_MUTE,
    GLYPH_PAGE_DOTS,
    GLYPH_PAUSE,
    GLYPH_PLAY,
    GLYPH_RESTART,
    GLYPH_SPEAKER,
    GLYPH_STOP,
    GLYPH_SWITCH,
    GLYPH_TWO_DOTS,
    GLYPH_WIFI,
    SWITCH_ASPECT,
    _LANCZOS,
    _centred_box,
    _BELL_RGB,
    _cap_lines,
    _dim_rect,
    _draw_bell,
    _draw_glyph,
    _draw_label,
    _draw_label_centered,
    _draw_label_right,
    _draw_minus_glyph,
    _draw_plus_glyph,
    _draw_text_safe,
    _draw_text_with_halo,
    _fit_value_lines,
    _load_font,
    _place_label,
    _text_size,
    _tone,
    _truncate_to_width,
    _wrap_words,
)
from dial_display_palette import (
    ARMED_LABEL_RGB,
    GLYPH_RGB,
    LOGO_BACKGROUND_RGB,
    DIVIDER_RGB,
    LIST_SEPARATOR_RGB,
    DIMMED_GLYPH_RGB,
    BELL_INFO_RGB,
    ALARM_RGB,
    CORNER_DISC_RGBA,
    OVERLAY_DIM_FACTOR,
)
from dial_display_views import (
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
    Body,
    FOOTER_LABELS,
    FOOTER_LIST_BAR,
    FOOTER_LIST_RAIL,
    FOOTER_NONE,
    FOOTER_TOGGLE,
    FOOTER_VOLUME,
    FOOTER_VOLUME_MUTE,
    Footer,
    Header,
    NEEDS_UPDATE_TEXT,
    NOT_AUTHORISED_TEXT,
    PLAY_GLYPH,
    WIFI_GREY,
    WIFI_OFF,
    WIFI_RED,
)
from dial_eq_model import EQ_BASS_TREBLE_LIMIT_DB
from dial_values import clamp, clamp_percent
from dial_layout_metrics import LayoutMetrics
from dial_touch_layout import (
    CompactLayout,
    CompactPickerLayout,
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
)

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


# An on/off switch's height as a fraction of the bottom band's, wherever it
# is drawn, so the per-output page's switch matches the repeat screen's.
_SWITCH_BAND_FRACTION = 0.62


def _draw_toggle_row(
    img: Image.Image, metrics: LayoutMetrics, row_rect: tuple[int, int, int, int], label: str, on: bool,
) -> None:
    """A label plus its on/off switch drawn into *row_rect*, the switch
    right-aligned and vertically centred — shared by the per-output detail
    page's own enable row (repeat_layout_for(...).row) and the repeat
    screen's enable layout (its bottom band). The switch is the same size
    in either, a fixed fraction of the bottom band's height."""
    pad = metrics.pad
    row_font = _load_font(metrics.font_body)
    draw = ImageDraw.Draw(img)
    band = repeat_layout_for(metrics.width, metrics.height, metrics=metrics).bottom_band
    sh = max(4, round((band[3] - band[1]) * _SWITCH_BAND_FRACTION))
    sw = round(sh * SWITCH_ASPECT)
    top = (row_rect[1] + row_rect[3]) // 2 - sh // 2
    switch_rect = (row_rect[2] - pad - sw, top, row_rect[2] - pad, top + sh)
    label_rect = (row_rect[0], row_rect[1], switch_rect[0] - pad, row_rect[3])
    _draw_label(draw, label_rect, label, row_font, pad)
    _draw_glyph(img, switch_rect, GLYPH_SWITCH, on, supersample=metrics.supersample)


def _body_toggle_row(img: Image.Image, metrics: LayoutMetrics, body: Body) -> None:
    """A label plus its on/off switch on the shared toggle-row rect — the
    per-output detail page's own enable row."""
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
    no repeat record to open), mute (the pause sign while everything
    playing is paused; the alert wash under it is a Frame.washes entry,
    drawn before this body runs), minus and plus."""
    c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
    ss = metrics.supersample
    dots_color = _tone(body.dots_lit)
    _draw_glyph(img, _compact_glyph_box(c.tl), GLYPH_TWO_DOTS, 0, dots_color, supersample=ss)
    if body.bell is not None:
        _draw_bell(img, dots_bell_rect(c.tl), body.bell, metrics, _DOTS_BELL_FRACTION)
    _draw_glyph(img, _compact_glyph_box(c.tr), GLYPH_PAUSE if body.paused else GLYPH_MUTE, supersample=ss)
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
    dot lit) top-left, "Repeat Play" centred on the full bottom row, the
    whole row its control — no separate cancel; the top-right cell is left
    empty. While armed the row is lit (a Frame.washes entry, drawn before
    this body) and the label dark on it; disarmed, the label is white on
    the dimmed artwork."""
    c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
    _draw_glyph(img, _compact_glyph_box(c.tl), GLYPH_TWO_DOTS, 1, GLYPH_RGB, supersample=metrics.supersample)
    color = ARMED_LABEL_RGB if body.armed else GLYPH_RGB
    _draw_label_centered(ImageDraw.Draw(img), c.bottom_row, body.label, _load_font(metrics.font_body), color)
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


# A warning card's small text size, as a fraction of the body size (never
# below the floor): the message when the row is short of room.
WARNING_SMALL_FONT_FRACTION = 0.8
WARNING_SMALL_FONT_FLOOR_PX = 9

# The rule under a warning's source band is this many times the divider width.
WARNING_RULE_WIDTH_FACTOR = 2

# The source band's bell is this share of the band height, but never shorter
# than this multiple of the band text's font size (on compact the band is
# only as tall as its text, and the bell should stand as tall as the text).
WARNING_BAND_BELL_FRACTION = 0.72
WARNING_BAND_BELL_FONT_FACTOR = 1.15


def _warning_band_text_span(rect: "tuple[int, int, int, int]", band_h: int) -> "tuple[int, int]":
    """The band's text span (left, right): the row between a square slot of
    band_h at each end. The bell sits in the right-hand slot and the left is
    left empty, so the source stays centred on the panel."""
    return rect[0] + band_h, rect[2] - band_h


def _plan_warning_band(
    draw: ImageDraw.ImageDraw, rect: "tuple[int, int, int, int]", body: Body, metrics: LayoutMetrics,
    fixed_band_h: "int | None" = None,
) -> "tuple[str, object, int, int] | None":
    """Lay out the source band across the top of *rect* (the card's message
    row) as (text, font, band height, rule height); None when the warning
    has no source, no font loads or the band and rule would not leave the
    row any room. The source is one line at body size, or at the largest
    smaller size (down to the floor) that holds it whole, and is
    ellipsized at the floor when even that is too wide; it is fitted to
    the span between the band's two end slots (see
    _warning_band_text_span), less the usual pad. *fixed_band_h* is
    the layout's source_band_h: off compact the band is the playing
    screen's top bar height, with the text centred in it; None (compact)
    sizes the band from the text. Pure: measuring calls only."""
    if not body.source:
        return None
    floor_px = min(metrics.font_body, WARNING_SMALL_FONT_FLOOR_PX)
    font = None
    max_w = 0
    band_h = fixed_band_h
    for px in range(metrics.font_body, floor_px - 1, -1):
        font = _load_font(px)
        if font is None:
            return None
        if fixed_band_h is None:
            band_h = round(px * 1.2)
        left, right = _warning_band_text_span(rect, band_h)
        max_w = right - left - 2 * metrics.pad
        measured = _text_size(draw, body.source, font)
        if measured is not None and measured[0] <= max_w:
            break
    text = _truncate_to_width(draw, body.source, font, max_w)
    rule_h = WARNING_RULE_WIDTH_FACTOR * metrics.divider_w
    if not text or band_h + rule_h >= rect[3] - rect[1]:
        return None
    return text, font, band_h, rule_h


def _plan_warning_text(
    draw: ImageDraw.ImageDraw, rect: "tuple[int, int, int, int]", body: Body, metrics: LayoutMetrics,
) -> "list[tuple[str, object, int, tuple]]":
    """Lay out a sourced warning's title and message in *rect* (what the
    card's message row has left under the source band) as (text, font,
    size, colour) lines, top to bottom. Text arrives from outside, so it is
    fitted rather than assumed short: the title is wrapped at readout size,
    then body size; the message at body size, then at the small size. The
    first combination that shows everything wins. When none does, the title
    (body size, or the small size in a very short row) keeps as many lines
    as the row allows, the last ellipsized, and the message (small size)
    gets the height that is left, ellipsized, or is dropped when there is
    none. Returns [] when no font loads or the row holds no line at all.
    A detail (body.detail) is tried first: at the small size, under the
    message with a gap of half a small line (an empty entry, so the drawer
    and the fit arithmetic count it like any line), and only if title,
    message and detail all fit whole on one rung of the ladder; it is never
    shortened. When it does not fit it is left out and the plan is what it
    would be without one. Pure: measuring calls only."""
    pad = metrics.pad
    max_w = rect[2] - rect[0] - 2 * pad
    max_h = rect[3] - rect[1]
    small_px = max(WARNING_SMALL_FONT_FLOOR_PX, round(metrics.font_body * WARNING_SMALL_FONT_FRACTION))
    body_px = metrics.font_body
    readout_px = metrics.font_readout
    fonts = {px: _load_font(px) for px in (small_px, body_px, readout_px)}
    if any(font is None for font in fonts.values()) or max_w <= 0:
        return []

    def fitted(title_px: int, message_px: int, extra: int = 0):
        title = _wrap_words(draw, body.title, fonts[title_px], max_w)
        message = _wrap_words(draw, body.line, fonts[message_px], max_w) if body.line else ()
        if (len(title) * title_px + len(message) * message_px + extra) * 1.2 <= max_h:
            return title, message
        return None

    ladder = ((readout_px, body_px), (readout_px, small_px), (body_px, body_px), (body_px, small_px))
    if body.detail:
        detail = _wrap_words(draw, body.detail, fonts[small_px], max_w)
        gap = small_px // 2
        for title_px, message_px in ladder:
            shown = fitted(title_px, message_px, extra=len(detail) * small_px + gap)
            if shown is not None:
                title, message = shown
                out = [(line, fonts[title_px], title_px, GLYPH_RGB) for line in title]
                out.extend((line, fonts[message_px], message_px, GLYPH_RGB) for line in message)
                out.append(("", fonts[small_px], gap, GLYPH_RGB))
                out.extend((line, fonts[small_px], small_px, GLYPH_RGB) for line in detail)
                return out

    chosen = None
    for title_px, message_px in ladder:
        chosen = fitted(title_px, message_px)
        if chosen is not None:
            break
    if chosen is not None:
        title, message = chosen
    else:
        title_px, message_px = body_px, small_px
        if max_h < title_px * 1.2:
            title_px = small_px
        if max_h < title_px * 1.2:
            return []
        title = _wrap_words(draw, body.title, fonts[title_px], max_w)
        message = _wrap_words(draw, body.line, fonts[message_px], max_w) if body.line else ()
        title_n = min(len(title), int(max_h // (title_px * 1.2)))
        title = _cap_lines(draw, title, title_n, fonts[title_px], max_w)
        message_n = int((max_h - title_n * title_px * 1.2) // (message_px * 1.2))
        message = _cap_lines(draw, message, message_n, fonts[message_px], max_w) if message_n > 0 else ()
    out = [(line, fonts[title_px], title_px, GLYPH_RGB) for line in title]
    out.extend((line, fonts[message_px], message_px, GLYPH_RGB) for line in message)
    return out


def _draw_fitted_warning_text(
    draw: ImageDraw.ImageDraw, rect: "tuple[int, int, int, int]", body: Body, metrics: LayoutMetrics,
) -> None:
    """Draw _plan_warning_text()'s lines, one centred row each, the block
    centred vertically in *rect* and never above its top."""
    lines = _plan_warning_text(draw, rect, body, metrics)
    x0, y0, x1, y1 = rect
    top = max(y0, y0 + (y1 - y0 - sum(size * 1.2 for _, _, size, _ in lines)) / 2)
    for text, font, size, color in lines:
        row = (x0, int(round(top)), x1, int(round(top + size * 1.2)))
        if text:
            _draw_label_centered(draw, row, text, font, color)
        top += size * 1.2


def _draw_warning_band(
    img: Image.Image, rect: "tuple[int, int, int, int]", band: "tuple[str, object, int, int]",
    severity: str, metrics: LayoutMetrics,
) -> "tuple[int, int, int, int]":
    """Draw the source band at the top of *rect* (the logo's blue, with the
    source in white between two square end slots) and the dial's warning
    bell, without a number, in the severity's colour centred in the
    right-hand slot. The rule under the band is in the severity's colour,
    across the full width. Returns what is left of *rect* underneath for the
    title and message."""
    text, font, band_h, rule_h = band
    x0, y0, x1, y1 = rect
    draw = ImageDraw.Draw(img)
    draw.rectangle([x0, y0, x1 - 1, y0 + band_h - 1], fill=LOGO_BACKGROUND_RGB)
    side = min(band_h, max(round(band_h * WARNING_BAND_BELL_FRACTION), round(font.size * WARNING_BAND_BELL_FONT_FACTOR)))
    bell_x = x1 - band_h + (band_h - side) // 2
    bell_y = y0 + (band_h - side) // 2
    _draw_glyph(
        img, (bell_x, bell_y, bell_x + side, bell_y + side), GLYPH_BELL, severity, None,
        supersample=metrics.supersample,
    )
    left, right = _warning_band_text_span(rect, band_h)
    _draw_label_centered(draw, (left, y0, right, y0 + band_h), text, font, GLYPH_RGB)
    draw.rectangle(
        [x0, y0 + band_h, x1 - 1, y0 + band_h + rule_h - 1], fill=_BELL_RGB.get(severity, BELL_INFO_RGB),
    )
    return x0, y0 + band_h + rule_h, x1, y1


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
    """A warning or status card's content on every tier. With no message the title
    is centred in the whole message row at readout size; with one, the
    title takes the upper three fifths of the row and the message the
    rest at body size. Each button label is centred in its cell at body
    size. Then the crosshair: a horizontal line at divider_y across the
    card's full width, and one vertical line per gap between cells,
    spanning the bottom row only (the message row is never split). Off
    compact the bottom row is the playing screen's footer row, so the
    buttons match its controls in height; on compact a two-button page
    is exactly the 2x2's own bottom-row divider pattern. A one-button
    page has no vertical line at all. A page with no cells has no
    crosshair. With body.percent set, a progress bar takes the bottom
    quarter of the message row (a dimmed track from the card's inner left
    to right edge, a white fill to the percent) and the text is laid out
    in the rest of the row. With body.source set, the row opens with the
    source in white on a band in the logo's blue across its full width
    (off compact the playing screen's top bar height, on compact sized from
    the text) with a number-less bell at its right-hand end, a rule in the
    severity's colour under it, and the title over the message below that, wrapped
    and shrunk to fit (see _plan_warning_band and _plan_warning_text)."""
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
        rect = (mx0, my0, mx1, my1)
        band = _plan_warning_band(draw, rect, body, metrics, layout.source_band_h)
        if band is not None:
            rect = _draw_warning_band(img, rect, band, body.severity, metrics)
        _draw_fitted_warning_text(draw, rect, body, metrics)
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
    shows the crossed-speaker glyph (GLYPH_MUTE) — this control IS the mute
    toggle, not a state readout — or the pause sign while everything playing
    is paused, when a tap plays them again. It carries the alert wash while
    muted or paused (see _now_playing_frame's `washes`), on top of which a
    genuine press adds the momentary wash."""
    draw = ImageDraw.Draw(img)
    _draw_minus_glyph(draw, layout.footer_down)
    _draw_plus_glyph(draw, layout.footer_up)
    glyph = GLYPH_PAUSE if footer.paused else GLYPH_MUTE
    _draw_glyph(img, layout.footer_mute, glyph, supersample=metrics.supersample)
    draw = ImageDraw.Draw(img)  # _draw_glyph pastes into img; get a fresh Draw handle
    _draw_band_divider(draw, layout, metrics, layout.footer_dividers)


def _footer_toggle(img: Image.Image, layout, metrics: LayoutMetrics, footer: Footer) -> None:
    """The repeat screen's enable layout: its label left and its on/off
    switch right across the whole bottom band, no divider. The switch's half
    of the band is the control (the REPEAT_PLAY zone)."""
    _draw_toggle_row(img, metrics, layout.bottom_band, footer.left_text, footer.armed)


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
    FOOTER_TOGGLE: _footer_toggle,
    FOOTER_LABELS: _footer_labels,
    FOOTER_LIST_BAR: _footer_list_bar,
    FOOTER_LIST_RAIL: _footer_list_rail,
}


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
