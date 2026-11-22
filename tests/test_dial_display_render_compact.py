"""Tests for dial_display_render.py — the compact tier's screens."""
from __future__ import annotations

import sys
from pathlib import Path

from unittest.mock import patch

import pytest

Image = pytest.importorskip("PIL.Image", reason="Pillow not installed")
ImageDraw = pytest.importorskip("PIL.ImageDraw", reason="Pillow not installed")

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
_CORE = str(REPO_ROOT / "core")
for _p in (_DIAL, _CORE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from dial_display_views import (  # noqa: E402
    BODY_INFO_VALUE,
    InfoValueView,
    ListState,
    OverlayState,
)
from dial_display_draw import (  # noqa: E402
    GLYPH_TWO_DOTS,
    _fit_value_lines,
    _glyph_tile,
    _load_font,
    _text_size,
    _truncate_to_width,
)
from dial_display_render import (  # noqa: E402
    _BODY_RENDERERS,
    _COMPACT_PICKER_TITLE,
    _compact_glyph_box,
    _compact_small_glyph_box,
    _draw_compact_list_row,
)
from dial_display_compositor import _reset_font_cache  # noqa: E402
from dial_display_palette import (  # noqa: E402
    ALERT_RGB,
    GLYPH_RGB,
    OVERLAY_DIM_FACTOR,
)
from dial_touch_layout import (  # noqa: E402
    TouchZone,
    compact_layout_for,
    compact_picker_layout_for,
    info_value_layout_for,
)
from dial_compositor_support import (
    _COMPACT_128,
    _COMPACT_240,
    _has_near_white_pixel,
    _repeat_state,
)
from dial_compositor_support import compositor  # noqa: F401

# ---------------------------------------------------------------------------
# The main screen's three-way footer (FOOTER_VOLUME_MUTE): minus | plus |
# mute, left to right, plus the persistent mute wash and GLYPH_MUTE itself.
# ---------------------------------------------------------------------------

def _two_dots_centers(box: tuple[int, int, int, int]) -> tuple[tuple[int, int], tuple[int, int]]:
    """The (left, right) dot centre coordinates _draw_two_dots() paints
    into *box* — mirrors that painter's own geometry so a test can sample
    each dot directly rather than alpha-composite a whole tile."""
    x0, y0, x1, y1 = box
    w, h = x1 - x0, y1 - y0
    r = max(2, round(min(w, h) * 0.12))
    cy = y0 + h / 2.0
    gap = r * 3
    cx0 = x0 + w / 2.0 - gap / 2.0
    cx1 = x0 + w / 2.0 + gap / 2.0
    return (round(cx0), round(cy)), (round(cx1), round(cy))


class TestCompactDividers:
    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_playing_screen_has_a_full_cross(self, compositor, metrics):
        c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
        base = Image.new("RGB", (metrics.width, metrics.height), (10, 10, 10))
        result = compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True), metrics=metrics,
        )
        assert result.getpixel((5, c.divider_y)) == (255, 255, 255)
        assert result.getpixel((metrics.width - 5, c.divider_y)) == (255, 255, 255)
        assert result.getpixel((c.divider_x, 5)) == (255, 255, 255)
        assert result.getpixel((c.divider_x, metrics.height - 5)) == (255, 255, 255)

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_picker_screen_has_a_title_line_a_row_line_and_a_column_line_below_the_title(
        self, compositor, metrics,
    ):
        p = compact_picker_layout_for(metrics.width, metrics.height, metrics=metrics)
        state = ListState(rows=(("Kitchen", False, "1:23"),), has_prev=False, has_next=False)
        result = compositor.compose_list(
            metrics.width, metrics.height, state, rotate=False, bgr=False, metrics=metrics,
        )
        assert result.getpixel((5, p.title_divider_y)) == (255, 255, 255)
        assert result.getpixel((5, p.divider_y)) == (255, 255, 255)
        assert result.getpixel((p.divider_x, p.title_divider_y + 5)) == (255, 255, 255)
        assert result.getpixel((p.divider_x, metrics.height - 5)) == (255, 255, 255)
        # The column line never crosses into the title band itself.
        assert result.getpixel((p.divider_x, 2)) != (255, 255, 255)

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_repeat_enable_screen_has_a_vertical_divider_only_above_the_toggle_row(self, compositor, metrics):
        c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
        result = compositor.compose_repeat(
            metrics.width, metrics.height, _repeat_state(layout="enable", armed=False),
            rotate=False, bgr=False, metrics=metrics,
        )
        assert result.getpixel((5, c.divider_y)) == (255, 255, 255)
        assert result.getpixel((c.divider_x, 5)) == (255, 255, 255)
        assert result.getpixel((c.divider_x, metrics.height - 5)) != (255, 255, 255)

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_repeat_replaying_screen_has_a_full_cross(self, compositor, metrics):
        c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
        base = Image.new("RGB", (metrics.width, metrics.height), (10, 10, 10))
        result = compositor.compose_repeat(
            metrics.width, metrics.height,
            _repeat_state(layout="replaying", line="0:10 / 1:00", start_enabled=True, stop_enabled=True),
            rotate=False, bgr=False, base=base, metrics=metrics,
        )
        assert result.getpixel((5, c.divider_y)) == (255, 255, 255)
        assert result.getpixel((metrics.width - 5, c.divider_y)) == (255, 255, 255)
        assert result.getpixel((c.divider_x, 5)) == (255, 255, 255)
        assert result.getpixel((c.divider_x, metrics.height - 5)) == (255, 255, 255)


class TestCompactPlayingScreen:
    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_minus_and_plus_present_in_bl_and_br(self, compositor, metrics):
        c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
        base = Image.new("RGB", (metrics.width, metrics.height), (10, 10, 10))
        result = compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True), metrics=metrics,
        )
        assert _has_near_white_pixel(result.crop(c.bl))
        assert _has_near_white_pixel(result.crop(c.br))

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_dots_dimmed_when_inert_lit_when_active(self, compositor, metrics):
        base = Image.new("RGB", (metrics.width, metrics.height), (10, 10, 10))
        inert = compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, dots=False), metrics=metrics,
        )
        active = compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, dots=True), metrics=metrics,
        )
        c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
        assert list(inert.crop(c.tl).getdata()) != list(active.crop(c.tl).getdata())

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_dots_light_the_left_one_not_the_right(self, compositor, metrics):
        # The playing screen's own page-indicator state -- the LEFT dot,
        # unlike both repeat surfaces' back control (see
        # TestCompactRepeatEnable/TestCompactRepeatReplaying), which light
        # the right one.
        c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
        base = Image.new("RGB", (metrics.width, metrics.height), (10, 10, 10))
        result = compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, dots=True), metrics=metrics,
        )
        box = _compact_glyph_box(c.tl)
        left_centre, right_centre = _two_dots_centers(box)
        assert min(result.getpixel(left_centre)) > 200
        assert min(result.getpixel(right_centre)) < 200

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_muted_cell_is_a_solid_red_wash_with_a_white_glyph(self, compositor, metrics):
        c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
        base = Image.new("RGB", (metrics.width, metrics.height), (10, 10, 10))
        muted = compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, muted=True), metrics=metrics,
        )
        unmuted = compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, muted=False), metrics=metrics,
        )
        # The wash: every pixel of tr not part of the glyph itself is the
        # solid alert red on the muted frame (the pulse defaults to solid).
        x0, y0, x1, y1 = c.tr
        assert muted.getpixel((x0 + 2, y0 + 2)) == ALERT_RGB
        # The glyph stays white over it.
        pixels = list(muted.crop(c.tr).getdata())
        assert any(p == (255, 255, 255) for p in pixels)
        # Unmuted: no wash.
        assert unmuted.getpixel((x0 + 2, y0 + 2)) != ALERT_RGB

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_everything_paused_shows_the_pause_sign_on_the_red_wash(self, compositor, metrics):
        c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
        base = Image.new("RGB", (metrics.width, metrics.height), (10, 10, 10))
        paused = compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, paused=True), metrics=metrics,
        )
        muted = compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, muted=True), metrics=metrics,
        )
        x0, y0, x1, y1 = c.tr
        assert paused.getpixel((x0 + 2, y0 + 2)) == ALERT_RGB
        # A different glyph in the same cell, and nothing else differs
        assert list(paused.crop(c.tr).getdata()) != list(muted.crop(c.tr).getdata())
        for rect in (c.tl, c.bl, c.br):
            assert list(paused.crop(rect).getdata()) == list(muted.crop(rect).getdata())

    def test_no_text_anywhere_on_the_playing_screen(self, compositor):
        # No name, no volume digits, no artist/title — a plain dimmed frame
        # plus four glyphs and the dividers is everything drawn.
        metrics = _COMPACT_240
        base = Image.new("RGB", (metrics.width, metrics.height), (10, 10, 10))
        with_state = compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, name="Kitchen", volume=42, artist="Artist", title="Title"),
            metrics=metrics,
        )
        without_state = compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, name="", volume=None, artist="", title=""),
            metrics=metrics,
        )
        assert list(with_state.getdata()) == list(without_state.getdata())

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_pressed_up_washes_only_br(self, compositor, metrics):
        c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
        base = Image.new("RGB", (metrics.width, metrics.height), (10, 10, 10))
        unpressed = compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True), metrics=metrics,
        )
        pressed = compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, pressed=TouchZone.UP), metrics=metrics,
        )
        assert list(unpressed.crop(c.br).getdata()) != list(pressed.crop(c.br).getdata())
        assert list(unpressed.crop(c.bl).getdata()) == list(pressed.crop(c.bl).getdata())


class TestCompactPicker:
    def test_title_string_is_replay(self):
        assert _COMPACT_PICKER_TITLE == "Replay"

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_title_text_lands_in_the_title_band(self, compositor, metrics):
        p = compact_picker_layout_for(metrics.width, metrics.height, metrics=metrics)
        state = ListState(rows=(("Kitchen", False, "1:23"),), has_prev=False, has_next=False)
        blank = compositor.compose_list(
            metrics.width, metrics.height, ListState(rows=(("", False, ""),)),
            rotate=False, bgr=False, metrics=metrics,
        )
        result = compositor.compose_list(
            metrics.width, metrics.height, state, rotate=False, bgr=False, metrics=metrics,
        )
        # Blank rows still carry the constant "Replay" title, so both frames
        # already show it — the meaningful check is that some pixel of the
        # title band itself is lit at all (the title is always drawn).
        assert _has_near_white_pixel(result.crop(p.title))
        # Nothing below the title band changes between the two blank rows'
        # frames and this one except the row content itself, so a diff
        # confined to the row cells (not the title band) proves the title
        # is drawn once, from a fixed rect, independent of row content.
        assert list(result.crop(p.title).getdata()) == list(blank.crop(p.title).getdata())

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_title_text_is_horizontally_centered_not_left_aligned(self, compositor, metrics):
        p = compact_picker_layout_for(metrics.width, metrics.height, metrics=metrics)
        state = ListState(rows=(("Kitchen", False, "1:23"),))
        result = compositor.compose_list(
            metrics.width, metrics.height, state, rotate=False, bgr=False, metrics=metrics,
        )
        from PIL import ImageDraw
        font = _load_font(metrics.font_body)
        draw = ImageDraw.Draw(Image.new("RGB", (metrics.width, metrics.height)))
        bbox = draw.textbbox((0, 0), _COMPACT_PICKER_TITLE, font=font)
        text_w = bbox[2] - bbox[0]
        # Mirrors _draw_label_centered's own x arithmetic exactly.
        cx = (p.title[0] + p.title[2]) // 2
        expected_left = cx - text_w // 2

        title_band = result.crop(p.title)
        lit_columns = [
            x for x in range(title_band.width)
            if any(min(title_band.getpixel((x, y))) > 200 for y in range(title_band.height))
        ]
        assert lit_columns, "expected some lit pixel in the title band"
        actual_left = min(lit_columns)
        # The measured left edge sits at the textbbox-derived centred x, not
        # at metrics.pad (where a left-aligned title would start) -- a small
        # tolerance absorbs antialiasing at the "near white" threshold.
        assert abs(actual_left - expected_left) <= 4
        assert actual_left > metrics.pad + 2

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_two_rows_land_in_row0_and_row1(self, compositor, metrics):
        p = compact_picker_layout_for(metrics.width, metrics.height, metrics=metrics)
        state = ListState(rows=(("Kitchen", False, "1:23"), ("Lounge", True, "4:56")), has_prev=False, has_next=False)
        blank = compositor.compose_list(
            metrics.width, metrics.height, ListState(rows=(("", False, ""), ("", False, "")), has_prev=False, has_next=False),
            rotate=False, bgr=False, metrics=metrics,
        )
        result = compositor.compose_list(
            metrics.width, metrics.height, state, rotate=False, bgr=False, metrics=metrics,
        )
        assert list(result.crop(p.row0).getdata()) != list(blank.crop(p.row0).getdata())
        assert list(result.crop(p.row1).getdata()) != list(blank.crop(p.row1).getdata())

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_current_row_gets_the_highlight_wash(self, compositor, metrics):
        p = compact_picker_layout_for(metrics.width, metrics.height, metrics=metrics)
        not_current = ListState(rows=(("Kitchen", False, "1:23"), ("Lounge", False, "4:56")))
        current = ListState(rows=(("Kitchen", True, "1:23"), ("Lounge", False, "4:56")))
        a = compositor.compose_list(metrics.width, metrics.height, not_current, rotate=False, bgr=False, metrics=metrics)
        b = compositor.compose_list(metrics.width, metrics.height, current, rotate=False, bgr=False, metrics=metrics)
        assert list(a.crop(p.row0).getdata()) != list(b.crop(p.row0).getdata())
        assert list(a.crop(p.row1).getdata()) == list(b.crop(p.row1).getdata())

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_more_chevron_lit_iff_more_than_one_page(self, compositor, metrics):
        p = compact_picker_layout_for(metrics.width, metrics.height, metrics=metrics)
        one_page = ListState(rows=(("Kitchen", False, "1:23"),), has_prev=False, has_next=False)
        two_pages = ListState(rows=(("Kitchen", False, "1:23"),), has_prev=False, has_next=True)
        a = compositor.compose_list(metrics.width, metrics.height, one_page, rotate=False, bgr=False, metrics=metrics)
        b = compositor.compose_list(metrics.width, metrics.height, two_pages, rotate=False, bgr=False, metrics=metrics)
        assert list(a.crop(p.more).getdata()) != list(b.crop(p.more).getdata())

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_cancel_and_more_glyph_boxes_are_smaller_than_the_full_cell_box(self, metrics):
        p = compact_picker_layout_for(metrics.width, metrics.height, metrics=metrics)
        small = _compact_small_glyph_box(p.cancel)
        full = _compact_glyph_box(p.cancel)
        small_side = small[2] - small[0]
        full_side = full[2] - full[0]
        assert small_side < full_side

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_placeholder_row_lands_alone_in_row0(self, compositor, metrics):
        p = compact_picker_layout_for(metrics.width, metrics.height, metrics=metrics)
        blank = ListState(rows=(("", False, ""),))
        placeholder = ListState(rows=(("Nothing to replay", False),))
        a = compositor.compose_list(metrics.width, metrics.height, blank, rotate=False, bgr=False, metrics=metrics)
        b = compositor.compose_list(metrics.width, metrics.height, placeholder, rotate=False, bgr=False, metrics=metrics)
        assert list(a.crop(p.row0).getdata()) != list(b.crop(p.row0).getdata())
        assert list(a.crop(p.row1).getdata()) == list(b.crop(p.row1).getdata())

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_pressed_row1_washes_row1_only(self, compositor, metrics):
        p = compact_picker_layout_for(metrics.width, metrics.height, metrics=metrics)
        state = ListState(rows=(("Kitchen", False, "1:23"), ("Lounge", False, "4:56")))
        unpressed = compositor.compose_list(metrics.width, metrics.height, state, rotate=False, bgr=False, metrics=metrics)
        pressed = compositor.compose_list(
            metrics.width, metrics.height,
            ListState(rows=state.rows, pressed=(TouchZone.LIST_ROW, 1)),
            rotate=False, bgr=False, metrics=metrics,
        )
        assert list(unpressed.crop(p.row1).getdata()) != list(pressed.crop(p.row1).getdata())
        assert list(unpressed.crop(p.row0).getdata()) == list(pressed.crop(p.row0).getdata())

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_pressed_back_washes_cancel_only(self, compositor, metrics):
        p = compact_picker_layout_for(metrics.width, metrics.height, metrics=metrics)
        state = ListState(rows=(("Kitchen", False, "1:23"),))
        unpressed = compositor.compose_list(metrics.width, metrics.height, state, rotate=False, bgr=False, metrics=metrics)
        pressed = compositor.compose_list(
            metrics.width, metrics.height,
            ListState(rows=state.rows, pressed=(TouchZone.LIST_BACK, None)),
            rotate=False, bgr=False, metrics=metrics,
        )
        assert list(unpressed.crop(p.cancel).getdata()) != list(pressed.crop(p.cancel).getdata())
        assert list(unpressed.crop(p.more).getdata()) == list(pressed.crop(p.more).getdata())

    def test_base_is_dimmed_behind_when_given(self, compositor):
        metrics = _COMPACT_240
        base = Image.new("RGB", (metrics.width, metrics.height), (200, 150, 100))
        result = compositor.compose_list(
            metrics.width, metrics.height, ListState(rows=(("Kitchen", False, "1:23"),)),
            rotate=False, bgr=False, metrics=metrics, base=base,
        )
        # A corner of the tl cell, clear of any label text, reflects the
        # dimmed base colour rather than the flat chassis fill.
        expected = tuple(round(c * OVERLAY_DIM_FACTOR) for c in (200, 150, 100))
        assert result.getpixel((2, 2)) == expected

    def test_falls_back_to_chassis_when_base_is_none(self, compositor):
        metrics = _COMPACT_240
        result = compositor.compose_list(
            metrics.width, metrics.height, ListState(rows=(("Kitchen", False, "1:23"),)),
            rotate=False, bgr=False, metrics=metrics, base=None,
        )
        from dial_display_palette import LIST_BG_RGB
        expected = tuple(round(c * OVERLAY_DIM_FACTOR) for c in LIST_BG_RGB)
        assert result.getpixel((2, 2)) == expected

    def test_default_fields_are_byte_identical_to_before_they_existed(self, compositor):
        # ListState.title/plain_background default to None/False, which
        # must reproduce exactly the picker's own pre-existing rendering —
        # the byte-identical regression guard for the two new fields.
        metrics = _COMPACT_240
        base = Image.new("RGB", (metrics.width, metrics.height), (200, 150, 100))
        state = ListState(rows=(("Kitchen", False, "1:23"), ("Lounge", True, "4:56")), has_prev=True, has_next=True)
        with_defaults = compositor.compose_list(
            metrics.width, metrics.height, state, rotate=False, bgr=False, metrics=metrics, base=base,
        )
        explicit = ListState(
            rows=state.rows, has_prev=True, has_next=True, title=None, plain_background=False,
        )
        with_explicit_defaults = compositor.compose_list(
            metrics.width, metrics.height, explicit, rotate=False, bgr=False, metrics=metrics, base=base,
        )
        assert list(with_defaults.getdata()) == list(with_explicit_defaults.getdata())


class TestCompactListRowCentering:
    """_draw_compact_list_row: a row with no secondary (the compact info
    page's own names-only rows) has no lower half to share the cell with,
    so its label centres on the whole cell instead; a row that carries one
    (every picker row) keeps today's upper-half placement unchanged."""

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_names_only_row_centres_its_label_on_the_whole_cell(self, metrics):
        cell = (0, 0, metrics.width, 100)
        img = Image.new("RGB", (metrics.width, 100))
        font = _load_font(metrics.font_body)
        _draw_compact_list_row(img, cell, ("Dial name", False), font, metrics.pad)
        lit_rows = [y for y in range(100) if any(min(img.getpixel((x, y))) > 200 for x in range(metrics.width))]
        assert lit_rows
        centre = (min(lit_rows) + max(lit_rows)) / 2
        # Nearer the whole-cell centre (50) than the upper-half centre (25).
        assert abs(centre - 50) < abs(centre - 25)

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_row_with_secondary_still_spans_both_halves(self, metrics):
        # Byte-identical regression guard for the picker's own rows: the
        # label (upper half) and the secondary "m:ss" (lower half) are both
        # still drawn, so lit rows span well past the cell's own centre in
        # both directions — unlike the names-only case above, which only
        # ever lights pixels around the single, shared centre.
        cell = (0, 0, metrics.width, 100)
        img = Image.new("RGB", (metrics.width, 100))
        font = _load_font(metrics.font_body)
        _draw_compact_list_row(img, cell, ("Kitchen", False, "1:23"), font, metrics.pad)
        lit_rows = [y for y in range(100) if any(min(img.getpixel((x, y))) > 200 for x in range(metrics.width))]
        assert lit_rows
        assert min(lit_rows) < 25 and max(lit_rows) > 75

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_empty_secondary_string_is_treated_as_no_secondary(self, metrics):
        # len(row) > 2 alone is not enough — an empty string secondary (as
        # opposed to one simply absent) must still get the whole-cell
        # placement, not the upper half.
        cell = (0, 0, metrics.width, 100)
        whole_cell = Image.new("RGB", (metrics.width, 100))
        empty_secondary = Image.new("RGB", (metrics.width, 100))
        font = _load_font(metrics.font_body)
        _draw_compact_list_row(whole_cell, cell, ("Dial name", False), font, metrics.pad)
        _draw_compact_list_row(empty_secondary, cell, ("Dial name", False, ""), font, metrics.pad)
        assert list(whole_cell.getdata()) == list(empty_secondary.getdata())


class TestInfoListVariant:
    """The read-only info page reuses compose_list()'s compact picker
    format under ListState.title/plain_background, and the rich/large
    chassis unchanged (see test_dial_display_render.TestComposeList's rich five-row test)."""

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_title_replaced_by_info(self, compositor, metrics):
        p = compact_picker_layout_for(metrics.width, metrics.height, metrics=metrics)
        replay = compositor.compose_list(
            metrics.width, metrics.height, ListState(rows=(("", False, ""),)),
            rotate=False, bgr=False, metrics=metrics,
        )
        info = compositor.compose_list(
            metrics.width, metrics.height,
            ListState(rows=(("", False, ""),), title="Info", plain_background=True),
            rotate=False, bgr=False, metrics=metrics,
        )
        assert _has_near_white_pixel(info.crop(p.title))
        assert list(replay.crop(p.title).getdata()) != list(info.crop(p.title).getdata())

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_plain_background_is_flat_chassis_even_with_a_base_given(self, compositor, metrics):
        base = Image.new("RGB", (metrics.width, metrics.height), (200, 150, 100))
        state = ListState(rows=(("Dial name", False, "Kitchen"),), title="Info", plain_background=True)
        result = compositor.compose_list(
            metrics.width, metrics.height, state, rotate=False, bgr=False, metrics=metrics, base=base,
        )
        from dial_display_palette import LIST_BG_RGB
        # Flat chassis, undimmed — not the dimmed base colour a picker frame
        # would show at the same corner (see test_base_is_dimmed_behind_when_given).
        assert result.getpixel((2, 2)) == LIST_BG_RGB

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_labels_upper_half_values_lower_half(self, compositor, metrics):
        p = compact_picker_layout_for(metrics.width, metrics.height, metrics=metrics)
        state = ListState(
            rows=(("Dial name", False, "Kitchen"), ("Firmware", False, "1.2.3")),
            title="Info", plain_background=True,
        )
        blank = ListState(rows=(("", False, ""), ("", False, "")), title="Info", plain_background=True)
        result = compositor.compose_list(metrics.width, metrics.height, state, rotate=False, bgr=False, metrics=metrics)
        empty = compositor.compose_list(metrics.width, metrics.height, blank, rotate=False, bgr=False, metrics=metrics)
        for cell in (p.row0, p.row1):
            assert list(result.crop(cell).getdata()) != list(empty.crop(cell).getdata())

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_compact_rows_are_names_only_and_still_draw(self, compositor, metrics):
        # The real compact info page shape as of the drill-in: (label,
        # False), no value — see _draw_compact_list_row's own whole-cell
        # centring for a row with no secondary.
        p = compact_picker_layout_for(metrics.width, metrics.height, metrics=metrics)
        state = ListState(rows=(("Dial name", False), ("Firmware", False)), title="Info", plain_background=True)
        blank = ListState(rows=(("", False), ("", False)), title="Info", plain_background=True)
        result = compositor.compose_list(metrics.width, metrics.height, state, rotate=False, bgr=False, metrics=metrics)
        empty = compositor.compose_list(metrics.width, metrics.height, blank, rotate=False, bgr=False, metrics=metrics)
        for cell in (p.row0, p.row1):
            assert list(result.crop(cell).getdata()) != list(empty.crop(cell).getdata())

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_no_row_is_ever_highlighted(self, compositor, metrics):
        # The info page never marks a row current — the manager always
        # passes checked=False; even if it somehow did, only the frame
        # actually rendered from real info state matters, which is
        # confined to plain (label, False, value) rows.
        state = ListState(
            rows=(("Dial name", False, "Kitchen"), ("Firmware", False, "1.2.3")),
            title="Info", plain_background=True,
        )
        result = compositor.compose_list(metrics.width, metrics.height, state, rotate=False, bgr=False, metrics=metrics)
        chassis_bg = result.getpixel((1, metrics.height - 1))
        from dial_display_palette import LIST_BG_RGB
        assert chassis_bg == LIST_BG_RGB

    def test_x_in_cancel_and_chevron_lit_iff_more_pages(self, compositor):
        metrics = _COMPACT_240
        p = compact_picker_layout_for(metrics.width, metrics.height, metrics=metrics)
        one_page = ListState(rows=(("Dial name", False, "Kitchen"),), title="Info", plain_background=True)
        two_pages = ListState(
            rows=(("Dial name", False, "Kitchen"),), has_next=True, title="Info", plain_background=True,
        )
        a = compositor.compose_list(metrics.width, metrics.height, one_page, rotate=False, bgr=False, metrics=metrics)
        b = compositor.compose_list(metrics.width, metrics.height, two_pages, rotate=False, bgr=False, metrics=metrics)
        assert _has_near_white_pixel(a.crop(p.cancel))
        assert list(a.crop(p.more).getdata()) != list(b.crop(p.more).getdata())

    def test_never_raises_with_no_font(self, compositor):
        metrics = _COMPACT_240
        state = ListState(
            rows=(("Dial name", False, "Kitchen"),), title="Info", plain_background=True,
        )
        with patch("dial_display_render._load_font", return_value=None):
            result = compositor.compose_list(
                metrics.width, metrics.height, state, rotate=False, bgr=False, metrics=metrics,
            )
        assert result.size == (metrics.width, metrics.height)


class TestInfoValueView:
    """compose_info_value()/_body_info_value(): the compact info page's own
    drill-in — a flat chassis background, the field name small in the top
    band, the value large and centred below, wrapped or shrunk to fit."""

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_background_is_flat_chassis(self, compositor, metrics):
        from dial_display_palette import LIST_BG_RGB
        result = compositor.compose_info_value(
            metrics.width, metrics.height, InfoValueView(label="IPv4", value="10.0.0.5"),
            rotate=False, bgr=False, metrics=metrics,
        )
        assert result.getpixel((1, 1)) == LIST_BG_RGB

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_label_lands_in_the_label_band(self, compositor, metrics):
        layout = info_value_layout_for(metrics.width, metrics.height, metrics=metrics)
        result = compositor.compose_info_value(
            metrics.width, metrics.height, InfoValueView(label="IPv4", value="10.0.0.5"),
            rotate=False, bgr=False, metrics=metrics,
        )
        assert _has_near_white_pixel(result.crop(layout.label))

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_value_lands_in_the_value_rect(self, compositor, metrics):
        layout = info_value_layout_for(metrics.width, metrics.height, metrics=metrics)
        result = compositor.compose_info_value(
            metrics.width, metrics.height, InfoValueView(label="IPv4", value="10.0.0.5"),
            rotate=False, bgr=False, metrics=metrics,
        )
        assert _has_near_white_pixel(result.crop(layout.value))

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_value_is_horizontally_centred(self, compositor, metrics):
        layout = info_value_layout_for(metrics.width, metrics.height, metrics=metrics)
        result = compositor.compose_info_value(
            metrics.width, metrics.height, InfoValueView(label="IPv4", value="14.2 GB"),
            rotate=False, bgr=False, metrics=metrics,
        )
        x0, y0, x1, y1 = layout.value
        region = result.crop(layout.value)
        lit_columns = [
            x for x in range(region.width)
            if any(min(region.getpixel((x, y))) > 200 for y in range(region.height))
        ]
        assert lit_columns
        centre = (min(lit_columns) + max(lit_columns)) / 2
        assert abs(centre - region.width / 2) <= 2

    @pytest.mark.parametrize(
        "metrics,value", [
            (m, v) for m in (_COMPACT_240, _COMPACT_128)
            for v in ("10.0.0.5", "0.6.0-beta.4")
        ],
    )
    def test_shipped_ip_and_version_values_render_on_one_line_no_ellipsis(self, compositor, metrics, value):
        layout = info_value_layout_for(metrics.width, metrics.height, metrics=metrics)
        result = compositor.compose_info_value(
            metrics.width, metrics.height, InfoValueView(label="IPv4", value=value),
            rotate=False, bgr=False, metrics=metrics,
        )
        from PIL import ImageDraw
        draw = ImageDraw.Draw(Image.new("RGB", (metrics.width, metrics.height)))
        font = _load_font(metrics.font_readout)
        lines, used_font = _fit_value_lines(draw, value, (metrics.font_readout, metrics.font_body), layout.value)
        assert lines == (value,)
        assert used_font is font
        assert result.size == (metrics.width, metrics.height)

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_long_ssid_wraps_to_more_than_one_line_with_every_character_present(self, compositor, metrics):
        layout = info_value_layout_for(metrics.width, metrics.height, metrics=metrics)
        ssid = "MyHomeNetworkWithALongNameHere12"
        assert len(ssid) == 32
        from PIL import ImageDraw
        draw = ImageDraw.Draw(Image.new("RGB", (metrics.width, metrics.height)))
        lines, font = _fit_value_lines(draw, ssid, (metrics.font_readout, metrics.font_body), layout.value)
        assert font is not None
        assert len(lines) > 1
        assert "".join(lines) == ssid
        result = compositor.compose_info_value(
            metrics.width, metrics.height, InfoValueView(label="WiFi", value=ssid),
            rotate=False, bgr=False, metrics=metrics,
        )
        assert result.size == (metrics.width, metrics.height)

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_absurd_value_ends_in_ellipsis_and_stays_inside_the_rect(self, compositor, metrics):
        layout = info_value_layout_for(metrics.width, metrics.height, metrics=metrics)
        value = "A" * 200
        from PIL import ImageDraw
        draw = ImageDraw.Draw(Image.new("RGB", (metrics.width, metrics.height)))
        lines, font = _fit_value_lines(draw, value, (metrics.font_readout, metrics.font_body), layout.value)
        assert lines
        assert lines[-1].endswith("...")
        max_w = layout.value[2] - layout.value[0]
        for line in lines:
            measured = _text_size(draw, line, font)
            assert measured is not None and measured[0] <= max_w
        # Never raises when actually composed, and stays panel-sized.
        result = compositor.compose_info_value(
            metrics.width, metrics.height, InfoValueView(label="Long", value=value),
            rotate=False, bgr=False, metrics=metrics,
        )
        assert result.size == (metrics.width, metrics.height)

    def test_never_raises_with_no_font(self, compositor):
        metrics = _COMPACT_240
        with patch("dial_display_render._load_font", return_value=None), \
             patch("dial_display_draw._load_font", return_value=None):
            result = compositor.compose_info_value(
                metrics.width, metrics.height, InfoValueView(label="IPv4", value="10.0.0.5"),
                rotate=False, bgr=False, metrics=metrics,
            )
        assert result.size == (metrics.width, metrics.height)

    def test_body_kind_is_dispatched_through_body_renderers(self):
        assert BODY_INFO_VALUE in _BODY_RENDERERS


class TestCompactRepeatEnable:
    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_label_and_arm_dot_present_on_the_full_width_bottom_row(self, compositor, metrics):
        c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
        disarmed = compositor.compose_repeat(
            metrics.width, metrics.height, _repeat_state(layout="enable", armed=False),
            rotate=False, bgr=False, metrics=metrics,
        )
        armed = compositor.compose_repeat(
            metrics.width, metrics.height, _repeat_state(layout="enable", armed=True),
            rotate=False, bgr=False, metrics=metrics,
        )
        assert list(disarmed.crop(c.bottom_row).getdata()) != list(armed.crop(c.bottom_row).getdata())
        assert _has_near_white_pixel(armed.crop(c.bottom_row))

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_repeat_play_label_fits_the_row_without_truncation(self, metrics):
        # Regression test for a real bug: the label used to be truncated to
        # "Repea..." because the arm-dot box was the row's own (much taller,
        # on compact, than the base tier's row ever is) height, leaving too
        # little width for the label. _draw_toggle_row's compact caller now
        # passes a smaller, fixed-width dot_box (metrics.icon) instead -- see
        # _body_compact_toggle. Mirrors that function's own arithmetic
        # exactly so a regression in the wiring (not just the geometry
        # rule) would be caught.
        c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
        pad = metrics.pad
        row_rect = c.bottom_row
        dot_box = metrics.icon
        dot_x0 = row_rect[2] - pad - dot_box
        label_rect_x1 = dot_x0 - pad
        label_max_w = (label_rect_x1 - row_rect[0]) - pad  # _draw_label's own max_w

        from PIL import ImageDraw
        font = _load_font(metrics.font_body)
        draw = ImageDraw.Draw(Image.new("RGB", (metrics.width, metrics.height)))
        bbox = draw.textbbox((0, 0), "Repeat Play", font=font)
        text_w = bbox[2] - bbox[0]
        assert text_w <= label_max_w, (text_w, label_max_w)
        assert _truncate_to_width(draw, "Repeat Play", font, label_max_w) == "Repeat Play"

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_repeat_play_label_renders_whole_not_ellipsised(self, compositor, metrics):
        # Belt-and-braces integration check alongside the geometry-level
        # test above: render the real frame and confirm the label's own
        # rendered pixels extend into the right-hand portion of where the
        # un-truncated word "Play" must sit -- a truncated "Repea..." would
        # not reach anywhere near there.
        c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
        result = compositor.compose_repeat(
            metrics.width, metrics.height, _repeat_state(layout="enable", armed=False),
            rotate=False, bgr=False, metrics=metrics,
        )
        pad = metrics.pad
        row_rect = c.bottom_row
        dot_box = metrics.icon
        dot_x0 = row_rect[2] - pad - dot_box
        label_rect = (row_rect[0], row_rect[1], dot_x0 - pad, row_rect[3])
        from PIL import ImageDraw
        font = _load_font(metrics.font_body)
        draw = ImageDraw.Draw(Image.new("RGB", (metrics.width, metrics.height)))
        full_w = draw.textbbox((0, 0), "Repeat Play", font=font)[2]
        truncated_w = draw.textbbox((0, 0), "Repea...", font=font)[2]
        # A point past where a truncated "Repea..." would end, but still
        # within the un-truncated label's own drawn width.
        probe_x = label_rect[0] + pad + (truncated_w + full_w) // 2
        assert probe_x < label_rect[2]
        region = result.crop((probe_x, label_rect[1], label_rect[2], label_rect[3]))
        assert _has_near_white_pixel(region)

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_back_control_lights_the_right_dot_not_the_left(self, compositor, metrics):
        # The second dot marks the repeat pages -- distinct from the
        # playing screen's own first-lit dots tile (see TestCompactPlayingScreen).
        c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
        result = compositor.compose_repeat(
            metrics.width, metrics.height, _repeat_state(layout="enable", armed=False),
            rotate=False, bgr=False, metrics=metrics,
        )
        box = _compact_glyph_box(c.tl)
        left_centre, right_centre = _two_dots_centers(box)
        assert min(result.getpixel(right_centre)) > 200
        assert min(result.getpixel(left_centre)) < 200

    def test_right_lit_glyph_tile_differs_from_the_left_lit_one(self):
        right = _glyph_tile(GLYPH_TWO_DOTS, (1, GLYPH_RGB), 32, 32, 4)
        left = _glyph_tile(GLYPH_TWO_DOTS, (0, GLYPH_RGB), 32, 32, 4)
        assert list(right.getdata()) != list(left.getdata())

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_nothing_drawn_in_the_dead_top_right_cell(self, compositor, metrics):
        from dial_display_palette import LIST_BG_RGB
        c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
        armed = compositor.compose_repeat(
            metrics.width, metrics.height, _repeat_state(layout="enable", armed=True),
            rotate=False, bgr=False, metrics=metrics,
        )
        disarmed = compositor.compose_repeat(
            metrics.width, metrics.height, _repeat_state(layout="enable", armed=False),
            rotate=False, bgr=False, metrics=metrics,
        )
        expected = tuple(round(ch * OVERLAY_DIM_FACTOR) for ch in LIST_BG_RGB)
        assert all(px == expected for px in armed.crop(c.tr).getdata())
        assert all(px == expected for px in disarmed.crop(c.tr).getdata())

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_pressed_repeat_play_washes_the_bottom_row_only(self, compositor, metrics):
        c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
        unpressed = compositor.compose_repeat(
            metrics.width, metrics.height, _repeat_state(layout="enable", armed=False),
            rotate=False, bgr=False, metrics=metrics,
        )
        pressed = compositor.compose_repeat(
            metrics.width, metrics.height, _repeat_state(layout="enable", armed=False, pressed=TouchZone.REPEAT_PLAY),
            rotate=False, bgr=False, metrics=metrics,
        )
        assert list(unpressed.crop(c.bottom_row).getdata()) != list(pressed.crop(c.bottom_row).getdata())
        assert list(unpressed.crop(c.tl).getdata()) == list(pressed.crop(c.tl).getdata())

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_pressed_dots_washes_tl_only(self, compositor, metrics):
        c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
        unpressed = compositor.compose_repeat(
            metrics.width, metrics.height, _repeat_state(layout="enable", armed=False),
            rotate=False, bgr=False, metrics=metrics,
        )
        pressed = compositor.compose_repeat(
            metrics.width, metrics.height, _repeat_state(layout="enable", armed=False, pressed=TouchZone.DOTS),
            rotate=False, bgr=False, metrics=metrics,
        )
        assert list(unpressed.crop(c.tl).getdata()) != list(pressed.crop(c.tl).getdata())
        assert list(unpressed.crop(c.bottom_row).getdata()) == list(pressed.crop(c.bottom_row).getdata())


class TestCompactRepeatReplaying:
    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_time_drawn_in_tr(self, compositor, metrics):
        c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
        base = Image.new("RGB", (metrics.width, metrics.height), (10, 10, 10))
        blank = compositor.compose_repeat(
            metrics.width, metrics.height,
            _repeat_state(layout="replaying", line="", start_enabled=True, stop_enabled=True),
            rotate=False, bgr=False, base=base, metrics=metrics,
        )
        with_line = compositor.compose_repeat(
            metrics.width, metrics.height,
            _repeat_state(layout="replaying", line="0:10 / 1:00", start_enabled=True, stop_enabled=True),
            rotate=False, bgr=False, base=base, metrics=metrics,
        )
        assert list(blank.crop(c.tr).getdata()) != list(with_line.crop(c.tr).getdata())

    def test_time_shows_the_position_only_never_the_duration(self, compositor):
        # The manager's own line always carries "position / duration"; the
        # compact replaying cell is a quarter of the panel and its
        # spec names the position alone -- an unconditional split on " / ",
        # not a fit-driven fallback.
        metrics = _COMPACT_240
        base = Image.new("RGB", (metrics.width, metrics.height), (10, 10, 10))
        with_full_line = compositor.compose_repeat(
            metrics.width, metrics.height,
            _repeat_state(layout="replaying", line="72:34 / 80:00", start_enabled=True, stop_enabled=True),
            rotate=False, bgr=False, base=base, metrics=metrics,
        )
        position_only = compositor.compose_repeat(
            metrics.width, metrics.height,
            _repeat_state(layout="replaying", line="72:34", start_enabled=True, stop_enabled=True),
            rotate=False, bgr=False, base=base, metrics=metrics,
        )
        c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
        assert list(with_full_line.crop(c.tr).getdata()) == list(position_only.crop(c.tr).getdata())

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_back_control_lights_the_right_dot_not_the_left(self, compositor, metrics):
        c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
        base = Image.new("RGB", (metrics.width, metrics.height), (10, 10, 10))
        result = compositor.compose_repeat(
            metrics.width, metrics.height,
            _repeat_state(layout="replaying", line="0:10 / 1:00", start_enabled=True, stop_enabled=True),
            rotate=False, bgr=False, base=base, metrics=metrics,
        )
        box = _compact_glyph_box(c.tl)
        left_centre, right_centre = _two_dots_centers(box)
        assert min(result.getpixel(right_centre)) > 200
        assert min(result.getpixel(left_centre)) < 200

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_restart_and_stop_dimmed_when_disabled(self, compositor, metrics):
        c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
        base = Image.new("RGB", (metrics.width, metrics.height), (10, 10, 10))
        enabled = compositor.compose_repeat(
            metrics.width, metrics.height,
            _repeat_state(layout="replaying", line="0:10 / 1:00", start_enabled=True, stop_enabled=True),
            rotate=False, bgr=False, base=base, metrics=metrics,
        )
        disabled = compositor.compose_repeat(
            metrics.width, metrics.height,
            _repeat_state(layout="replaying", line="0:10 / 1:00", start_enabled=False, stop_enabled=False),
            rotate=False, bgr=False, base=base, metrics=metrics,
        )
        assert list(enabled.crop(c.bl).getdata()) != list(disabled.crop(c.bl).getdata())
        assert list(enabled.crop(c.br).getdata()) != list(disabled.crop(c.br).getdata())

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_stop_pressed_washes_br_while_fading_out(self, compositor, metrics):
        c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
        base = Image.new("RGB", (metrics.width, metrics.height), (10, 10, 10))
        not_pressed = compositor.compose_repeat(
            metrics.width, metrics.height,
            _repeat_state(
                layout="replaying", line="0:10 / 1:00", start_enabled=False, stop_enabled=True,
                stop_pressed=False,
            ),
            rotate=False, bgr=False, base=base, metrics=metrics,
        )
        fading_out = compositor.compose_repeat(
            metrics.width, metrics.height,
            _repeat_state(
                layout="replaying", line="0:10 / 1:00", start_enabled=False, stop_enabled=True,
                stop_pressed=True,
            ),
            rotate=False, bgr=False, base=base, metrics=metrics,
        )
        assert list(not_pressed.crop(c.br).getdata()) != list(fading_out.crop(c.br).getdata())

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_pressed_restart_resolves_against_the_replay_table(self, compositor, metrics):
        c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
        base = Image.new("RGB", (metrics.width, metrics.height), (10, 10, 10))
        unpressed = compositor.compose_repeat(
            metrics.width, metrics.height,
            _repeat_state(layout="replaying", line="0:10 / 1:00", start_enabled=True, stop_enabled=True),
            rotate=False, bgr=False, base=base, metrics=metrics,
        )
        pressed = compositor.compose_repeat(
            metrics.width, metrics.height,
            _repeat_state(
                layout="replaying", line="0:10 / 1:00", start_enabled=True, stop_enabled=True,
                pressed=TouchZone.REPEAT_START,
            ),
            rotate=False, bgr=False, base=base, metrics=metrics,
        )
        assert list(unpressed.crop(c.bl).getdata()) != list(pressed.crop(c.bl).getdata())
        assert list(unpressed.crop(c.br).getdata()) == list(pressed.crop(c.br).getdata())


class TestCompactNeverRaises:
    @pytest.fixture(autouse=True)
    def _reset(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    def test_no_font_available_still_composes_every_compact_screen(self, compositor):
        metrics = _COMPACT_240
        base = Image.new("RGB", (metrics.width, metrics.height), (200, 150, 100))
        with patch("dial_display_draw.ImageFont.truetype", side_effect=OSError("no font")), \
             patch("dial_display_draw.ImageFont.load_default", side_effect=OSError("no default")):
            playing = compositor.compose(
                base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
                overlay=OverlayState(visible=True, muted=True), metrics=metrics,
            )
            picker = compositor.compose_list(
                metrics.width, metrics.height, ListState(rows=(("Kitchen", False, "1:23"),)),
                rotate=False, bgr=False, metrics=metrics, base=base,
            )
            enable = compositor.compose_repeat(
                metrics.width, metrics.height, _repeat_state(layout="enable", armed=True),
                rotate=False, bgr=False, metrics=metrics,
            )
            replaying = compositor.compose_repeat(
                metrics.width, metrics.height,
                _repeat_state(layout="replaying", line="0:10 / 1:00", start_enabled=True, stop_enabled=True),
                rotate=False, bgr=False, base=base, metrics=metrics,
            )
        for result in (playing, picker, enable, replaying):
            assert result.size == (metrics.width, metrics.height)
