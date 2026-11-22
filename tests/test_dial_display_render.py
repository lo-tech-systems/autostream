"""Tests for dial_display_render.py — the screens as the body, footer and header renderers draw them."""
from __future__ import annotations

import dataclasses
import sys
from pathlib import Path

from unittest.mock import patch

import pytest

Image = pytest.importorskip("PIL.Image", reason="Pillow not installed")
ImageChops = pytest.importorskip("PIL.ImageChops", reason="Pillow not installed")
ImageDraw = pytest.importorskip("PIL.ImageDraw", reason="Pillow not installed")

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
_CORE = str(REPO_ROOT / "core")
for _p in (_DIAL, _CORE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import dial_display_draw  # noqa: E402
import dial_display_render  # noqa: E402
import dial_eq_model  # noqa: E402
from dial_display_views import (  # noqa: E402
    BODY_EQ_BARS,
    BODY_WARNING,
    DEFAULT_MARK,
    Body,
    EqViewState,
    FOOTER_VOLUME_MUTE,
    Header,
    ListState,
    NOT_AUTHORISED_TEXT,
    OutputViewState,
    PLAY_GLYPH,
    OverlayState,
    RepeatViewState,
    RESTARTING_TEXT,
    STARTING_TEXT,
    WarningView,
    BellBadge,
    WIFI_GREY,
    WIFI_OFF,
    WIFI_RED,
)
from dial_display_draw import (  # noqa: E402
    GLYPH_SPEAKER,
    _BELL_RGB,
    _centred_box,
    _glyph_tile,
    _load_font,
    _text_size,
    _truncate_to_width,
)
from dial_display_render import (  # noqa: E402
    _BODY_RENDERERS,
    _BELL_GLYPH_FRACTION,
    timer_area,
)
from dial_display_compositor import (  # noqa: E402
    _eq_pressed_rects,
    _now_playing_frame,
    _reset_font_cache,
    _reset_render_caches,
)
from dial_display_palette import (  # noqa: E402
    ALERT_RGB,
    BELL_CRITICAL_RGB,
    BELL_INFO_RGB,
    BELL_WARNING_RGB,
    DIMMED_GLYPH_RGB,
    GLYPH_RGB,
    LIST_BG_RGB,
    LOGO_BACKGROUND_RGB,
    OVERLAY_DIM_FACTOR,
)
from dial_layout_metrics import (  # noqa: E402
    CONTENT_BASE,
    CONTENT_COMPACT,
    CONTENT_LARGE,
    FONT_BODY_MAX_PX,
    FONT_BODY_PX_AT_REFERENCE,
    FONT_READOUT_MAX_PX,
    FONT_READOUT_PX_AT_REFERENCE,
    metrics_for,
    scale_px,
)
from dial_touch_layout import (  # noqa: E402
    TouchZone,
    band_bell_rect,
    compact_layout_for,
    dots_bell_rect,
    compact_picker_layout_for,
    eq_layout_for,
    idle_layout_for,
    layout_for,
    list_layout_for,
    repeat_layout_for,
    warning_layout_for,
)
from dial_zone_helpers import zones_for  # noqa: E402
from dial_compositor_support import (
    PROFILE_SIZES,
    _COMPACT_128,
    _COMPACT_240,
    _LARGE_METRICS,
    _RICH_METRICS,
    _diff_bbox,
    _has_near_white_pixel,
    _marked_image,
    _repeat_state,
)
from dial_compositor_support import compositor  # noqa: F401


def _default_profile_metrics():
    """Metrics for the SPI dial's default profile (st7735s_160x128), built
    from its logical size and density the way the showcase panel does."""
    from dial_display_profiles import layout_context_for

    class _Cfg:
        screen_type = "st7735s_160x128"
        screen_size_inches = None
        layout_size = None

    ctx = layout_context_for(_Cfg())
    return metrics_for(*ctx.logical_size, mm_per_px=ctx.mm_per_px, size_chosen=False)


_BASE_METRICS = _default_profile_metrics()


class TestOverlayVisible:
    """Overlay drawing itself — pixel-level checks against the panel-sized
    160x128 profile so zone geometry is deterministic."""

    def _panel_image(self, color=(200, 150, 100)):
        return Image.new("RGB", (160, 128), color)

    def test_visible_overlay_changes_pixels(self, compositor):
        img = self._panel_image()
        result = compositor.compose(
            img, img.width, img.height,
            rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True),
        )
        assert list(result.getdata()) != list(img.getdata())

    def test_title_line_draws_above_artist(self, compositor):
        img = self._panel_image()
        layout = layout_for(img.width, img.height)
        with_title = compositor.compose(
            img, img.width, img.height,
            rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, artist="Artist", title="A Track Title"),
        )
        without_title = compositor.compose(
            img, img.width, img.height,
            rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, artist="Artist"),
        )
        # The title line draws in the title rect (above the artist line).
        assert (
            list(with_title.crop(layout.title).getdata())
            != list(without_title.crop(layout.title).getdata())
        )

    def test_not_visible_is_byte_identical_to_no_overlay(self, compositor):
        img = self._panel_image()
        no_overlay = compositor.compose(
            img, img.width, img.height,
            rotate=False, bgr=False, is_artwork=False,
        )
        not_visible = compositor.compose(
            img, img.width, img.height,
            rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=False),
        )
        assert list(no_overlay.getdata()) == list(not_visible.getdata())

    def test_dim_darkens_bands_leaves_middle_unchanged(self, compositor):
        img = self._panel_image(color=(200, 200, 200))
        result = compositor.compose(
            img, img.width, img.height,
            rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True),
        )
        layout = layout_for(img.width, img.height)

        def mean_brightness(im):
            data = list(im.getdata())
            total = sum(sum(px) for px in data)
            return total / (len(data) * 3)

        assert mean_brightness(result.crop(layout.top_band)) < mean_brightness(img.crop(layout.top_band))
        assert mean_brightness(result.crop(layout.bottom_band)) < mean_brightness(img.crop(layout.bottom_band))

        middle_box = (0, layout.top_band[3], img.width, layout.bottom_band[1])
        assert list(result.crop(middle_box).getdata()) == list(img.crop(middle_box).getdata())

    def test_muted_true_and_false_differ_in_mute_zone(self, compositor):
        img = self._panel_image()
        muted = compositor.compose(
            img, img.width, img.height,
            rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, muted=True),
        )
        unmuted = compositor.compose(
            img, img.width, img.height,
            rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, muted=False),
        )
        x0, y0, x1, y1 = zones_for(img.width, img.height)[TouchZone.MUTE]
        muted_region = muted.crop((x0, y0, x1, y1))
        unmuted_region = unmuted.crop((x0, y0, x1, y1))
        assert list(muted_region.getdata()) != list(unmuted_region.getdata())

    def test_pressed_zone_highlight_confined_to_its_rectangle(self, compositor):
        img = self._panel_image()
        unpressed = compositor.compose(
            img, img.width, img.height,
            rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True),
        )
        pressed = compositor.compose(
            img, img.width, img.height,
            rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, pressed=TouchZone.DOWN),
        )
        zones = zones_for(img.width, img.height)
        assert list(unpressed.getdata()) != list(pressed.getdata())

        # Outside the pressed zone's rectangle, pixels must be unaffected by
        # the press (glyphs themselves are identical either way).
        dx0, dy0, dx1, dy1 = zones[TouchZone.DOWN]
        for zone, (x0, y0, x1, y1) in zones.items():
            if zone == TouchZone.DOWN:
                continue
            region_a = unpressed.crop((x0, y0, x1, y1))
            region_b = pressed.crop((x0, y0, x1, y1))
            assert list(region_a.getdata()) == list(region_b.getdata())

    def test_overlay_composes_before_rotate(self, compositor):
        img = self._panel_image()
        overlay = OverlayState(visible=True, muted=True)
        composed_then_rotated = compositor.compose(
            img, img.width, img.height,
            rotate=True, bgr=False, is_artwork=False,
            overlay=overlay,
        )
        drawn_first = compositor.compose(
            img, img.width, img.height,
            rotate=False, bgr=False, is_artwork=False,
            overlay=overlay,
        )
        expected = drawn_first.transpose(Image.ROTATE_180)
        assert list(composed_then_rotated.getdata()) == list(expected.getdata())

    def test_overlay_composes_before_bgr(self, compositor):
        img = self._panel_image()
        overlay = OverlayState(visible=True, muted=True)
        composed_then_swapped = compositor.compose(
            img, img.width, img.height,
            rotate=False, bgr=True, is_artwork=False,
            overlay=overlay,
        )
        drawn_first = compositor.compose(
            img, img.width, img.height,
            rotate=False, bgr=False, is_artwork=False,
            overlay=overlay,
        )
        expected = Image.merge("RGB", drawn_first.split()[::-1])
        assert list(composed_then_swapped.getdata()) == list(expected.getdata())


class TestBandDivider:
    """The single divider line between DOWN and UP in the bottom band —
    must be derived from layout_for()'s own geometry, must sit outside both
    button rectangles, and must never appear when the overlay is inert."""

    def _panel_image(self, size, color=(200, 150, 100)):
        return Image.new("RGB", size, color)

    @pytest.mark.parametrize("size", [(160, 128), (240, 240)])
    def test_divider_column_differs_between_hidden_and_visible(self, compositor, size):
        img = self._panel_image(size)
        hidden = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=False),
        )
        visible = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True),
        )
        layout = layout_for(*size)
        y0, y1 = layout.bottom_band[1], layout.bottom_band[3]
        differing = any(
            hidden.getpixel((layout.divider_x, y)) != visible.getpixel((layout.divider_x, y))
            for y in range(y0, y1)
        )
        assert differing

    @pytest.mark.parametrize("size", [(160, 128), (240, 240)])
    def test_divider_column_falls_outside_down_and_up(self, size):
        # By construction the divider sits in the dead-zone gap between
        # DOWN and UP, so its column can never overlap either rectangle —
        # confirmed structurally here (the touch-layout test suite already
        # confirms zone_at(divider_x, ...) is None for every y).
        layout = layout_for(*size)
        dx = layout.divider_x
        assert not (layout.down[0] <= dx < layout.down[2])
        assert not (layout.up[0] <= dx < layout.up[2])

    @pytest.mark.parametrize("size", [(160, 128), (240, 240)])
    def test_middle_half_unaffected_by_divider(self, compositor, size):
        img = self._panel_image(size)
        hidden = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=False),
        )
        visible = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True),
        )
        layout = layout_for(*size)
        middle_box = (0, layout.top_band[3], size[0], layout.bottom_band[1])
        assert list(hidden.crop(middle_box).getdata()) == list(visible.crop(middle_box).getdata())


class TestOverlayText:
    """Artist name and volume-readout rendering, including the font
    fallback chain and the guards that keep a text failure from ever raising
    out of compose()."""

    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    def _panel_image(self, size=(160, 128), color=(200, 150, 100)):
        return Image.new("RGB", size, color)

    def test_artist_text_confined_to_artist_rect(self, compositor):
        size = (160, 128)
        img = self._panel_image(size)
        layout = layout_for(*size)
        with_artist = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, artist="Test Artist"),
        )
        without_artist = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, artist=""),
        )
        assert list(with_artist.crop(layout.artist).getdata()) != list(without_artist.crop(layout.artist).getdata())
        assert list(with_artist.crop(layout.volume_cluster).getdata()) == list(
            without_artist.crop(layout.volume_cluster).getdata()
        )

    def test_empty_artist_leaves_artist_rect_dimmed_only(self, compositor):
        size = (160, 128)
        img = self._panel_image(size)
        layout = layout_for(*size)
        no_text = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, artist=""),
        )
        baseline = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True),
        )
        assert list(no_text.crop(layout.artist).getdata()) == list(baseline.crop(layout.artist).getdata())

    def test_long_artist_does_not_bleed_past_its_own_rect(self, compositor):
        # The artist line now sits centre-low, no longer adjacent to the
        # volume cluster — the thing worth pinning is that a very long
        # artist string still gets truncated inside its own rect rather
        # than overflowing into the inset margin to its right.
        size = (160, 128)
        img = self._panel_image(size)
        layout = layout_for(*size)
        baseline = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True),
        )
        long_artist = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, artist="A Very Long Artist Name Indeed" * 3),
        )
        margin_box = (layout.artist[2], layout.artist[1], size[0], layout.artist[3])
        assert list(baseline.crop(margin_box).getdata()) == list(long_artist.crop(margin_box).getdata())

    def test_volume_digits_vs_none_differ(self, compositor):
        size = (160, 128)
        img = self._panel_image(size)
        layout = layout_for(*size)
        with_volume = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, volume=68),
        )
        without_volume = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, volume=None),
        )
        assert list(with_volume.crop(layout.volume_cluster).getdata()) != list(
            without_volume.crop(layout.volume_cluster).getdata()
        )

    def test_volume_none_still_draws_glyph(self, compositor):
        size = (160, 128)
        img = self._panel_image(size)
        layout = layout_for(*size)
        result = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, volume=None),
        )
        # A uniform dimmed rectangle (no glyph) would have exactly one
        # colour; the speaker glyph's white strokes add a second.
        cluster_colors = set(result.crop(layout.volume_cluster).getdata())
        assert len(cluster_colors) > 1

    @pytest.mark.parametrize("volume", [0, 100])
    def test_volume_boundary_values_render(self, compositor, volume):
        size = (160, 128)
        img = self._panel_image(size)
        layout = layout_for(*size)
        result = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, volume=volume),
        )
        none_result = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, volume=None),
        )
        assert list(result.crop(layout.volume_cluster).getdata()) != list(
            none_result.crop(layout.volume_cluster).getdata()
        )

    def test_muted_none_equals_muted_false(self, compositor):
        size = (160, 128)
        img = self._panel_image(size)
        none_result = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, muted=None),
        )
        false_result = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, muted=False),
        )
        assert list(none_result.getdata()) == list(false_result.getdata())

    def test_font_fallback_truetype_unavailable_still_composes(self, compositor):
        size = (160, 128)
        img = self._panel_image(size)
        layout = layout_for(*size)
        with patch("dial_display_draw.ImageFont.truetype", side_effect=OSError("no font")):
            result = compositor.compose(
                img, *size, rotate=False, bgr=False, is_artwork=False,
                overlay=OverlayState(visible=True, artist="Artist", volume=42),
            )
        assert result.size == size
        # The speaker glyph does not depend on the font and still draws.
        cluster_colors = set(result.crop(layout.volume_cluster).getdata())
        assert len(cluster_colors) > 1

    def test_font_fallback_default_font_also_unavailable_disables_text(self, compositor):
        size = (160, 128)
        img = self._panel_image(size)
        layout = layout_for(*size)
        with patch("dial_display_draw.ImageFont.truetype", side_effect=OSError("no font")), \
             patch("dial_display_draw.ImageFont.load_default", side_effect=OSError("no default")):
            result = compositor.compose(
                img, *size, rotate=False, bgr=False, is_artwork=False,
                overlay=OverlayState(visible=True, artist="Artist", volume=42),
            )
        baseline = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True),
        )
        # Text disabled entirely: the artist rect matches the no-text
        # baseline exactly (dimmed background only).
        assert list(result.crop(layout.artist).getdata()) == list(baseline.crop(layout.artist).getdata())
        # The speaker glyph itself never depends on the font and still draws.
        cluster_colors = set(result.crop(layout.volume_cluster).getdata())
        assert len(cluster_colors) > 1

    def test_draw_text_safe_swallows_a_raising_draw_text(self, compositor):
        size = (160, 128)
        img = self._panel_image(size)
        with patch("PIL.ImageDraw.ImageDraw.text", side_effect=RuntimeError("boom")):
            result = compositor.compose(
                img, *size, rotate=False, bgr=False, is_artwork=False,
                overlay=OverlayState(visible=True, artist="Artist", volume=42),
            )
        assert result.size == size

    class _FakeDraw:
        """A fake measurer for _truncate_to_width: 1 width-unit per
        character, fixed height, never raises."""

        def textbbox(self, xy, text, font=None):
            return (0, 0, len(text), 10)

    def test_truncate_to_width_returns_unmodified_text_when_it_fits(self):
        result = _truncate_to_width(self._FakeDraw(), "hello", None, 10)
        assert result == "hello"

    def test_truncate_to_width_shortens_and_adds_ellipsis(self):
        result = _truncate_to_width(self._FakeDraw(), "hello world", None, 8)
        assert result.endswith("...")
        assert len(result) <= 8

    def test_truncate_to_width_returns_empty_when_nothing_fits(self):
        result = _truncate_to_width(self._FakeDraw(), "hello", None, 2)
        assert result == ""

    @pytest.mark.parametrize("size,expected", [
        ((160, 128), (13, 15)),
        ((128, 128), (13, 15)),
        ((240, 240), (24, 28)),
        ((320, 240), (24, 28)),
    ])
    def test_scaled_px_matches_reference_sizes(self, size, expected):
        width, height = size
        expected_artist, expected_volume = expected
        assert scale_px(FONT_BODY_PX_AT_REFERENCE[0], width, height, 8) == expected_artist
        assert scale_px(FONT_READOUT_PX_AT_REFERENCE[0], width, height, 9) == expected_volume


class TestOverlayName:
    """The appliance name (top-left, plain text over the dimmed band, no
    halo — matching the repeat screen) — always drawn whenever a focused/
    controllable appliance is shown (unconditional, never gated on how many
    appliances are authorized)."""

    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    def _panel_image(self, size=(160, 128), color=(200, 150, 100)):
        return Image.new("RGB", size, color)

    def test_default_overlay_state_name_is_empty(self):
        assert OverlayState().name == ""

    def test_empty_name_leaves_name_rect_dimmed_only(self, compositor):
        size = (160, 128)
        img = self._panel_image(size)
        layout = layout_for(*size)
        no_name = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, name=""),
        )
        baseline = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True),
        )
        assert list(no_name.crop(layout.name).getdata()) == list(baseline.crop(layout.name).getdata())

    def test_name_draws_pixels_in_name_rect_and_none_in_cluster(self, compositor):
        size = (160, 128)
        img = self._panel_image(size)
        layout = layout_for(*size)
        with_name = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, name="CD Player"),
        )
        without_name = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, name=""),
        )
        assert list(with_name.crop(layout.name).getdata()) != list(without_name.crop(layout.name).getdata())
        assert list(with_name.crop(layout.volume_cluster).getdata()) == list(
            without_name.crop(layout.volume_cluster).getdata()
        )

    def test_long_name_does_not_bleed_into_the_gap(self, compositor):
        size = (160, 128)
        img = self._panel_image(size)
        layout = layout_for(*size)
        baseline = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True),
        )
        long_name = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, name="A Very Long Appliance Name Indeed" * 3),
        )
        gap_box = (layout.name[2], layout.name[1], layout.volume_cluster[0], layout.name[3])
        assert list(baseline.crop(gap_box).getdata()) == list(long_name.crop(gap_box).getdata())

    def test_name_pressed_highlight_differs(self, compositor):
        size = (160, 128)
        img = self._panel_image(size)
        unpressed = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, name="CD Player"),
        )
        pressed = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, name="CD Player", pressed=TouchZone.NAME),
        )
        assert list(unpressed.getdata()) != list(pressed.getdata())

    def test_font_fallback_unavailable_disables_name_text(self, compositor):
        size = (160, 128)
        img = self._panel_image(size)
        layout = layout_for(*size)
        with patch("dial_display_draw.ImageFont.truetype", side_effect=OSError("no font")), \
             patch("dial_display_draw.ImageFont.load_default", side_effect=OSError("no default")):
            result = compositor.compose(
                img, *size, rotate=False, bgr=False, is_artwork=False,
                overlay=OverlayState(visible=True, name="CD Player"),
            )
        baseline = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True),
        )
        assert list(result.crop(layout.name).getdata()) == list(baseline.crop(layout.name).getdata())

    def test_halo_failure_still_draws_plain_text(self, compositor):
        # If the halo compositing step itself raises, the plain text must
        # still be drawn — the halo is cosmetic, never load-bearing.
        size = (160, 128)
        img = self._panel_image(size)
        layout = layout_for(*size)
        with patch("dial_display_draw.ImageFilter.GaussianBlur", side_effect=RuntimeError("boom")):
            result = compositor.compose(
                img, *size, rotate=False, bgr=False, is_artwork=False,
                overlay=OverlayState(visible=True, name="CD Player"),
            )
        baseline_blank = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, name=""),
        )
        assert list(result.crop(layout.name).getdata()) != list(baseline_blank.crop(layout.name).getdata())


class TestComposeList:
    """The appliance-selector chassis — compose_list(). Pixel checks against
    the 160x128 profile so row/bar geometry is deterministic."""

    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    def test_never_raises_and_returns_panel_sized_frame(self, compositor):
        state = ListState(rows=(("CD Player", True), ("Kitchen", False), ("Study", False)))
        result = compositor.compose_list(160, 128, state, rotate=False, bgr=False)
        assert result.size == (160, 128)

    def test_a_row_without_a_mark_is_byte_identical_to_a_three_tuple_row(self, compositor):
        three = compositor.compose_list(
            160, 128, ListState(rows=(("Bedroom", False, "40"),)), rotate=False, bgr=False)
        four = compositor.compose_list(
            160, 128, ListState(rows=(("Bedroom", False, "40", ""),)), rotate=False, bgr=False)
        assert list(three.getdata()) == list(four.getdata())

    def test_a_marked_row_differs_only_within_its_row(self, compositor):
        layout = list_layout_for(160, 128)
        plain = compositor.compose_list(
            160, 128, ListState(rows=(("Bedroom", False, "40"), ("Study", False, ""))),
            rotate=False, bgr=False)
        marked = compositor.compose_list(
            160, 128, ListState(rows=(("Bedroom", False, "40", DEFAULT_MARK), ("Study", False, ""))),
            rotate=False, bgr=False)
        assert list(plain.crop(layout.rows[0]).getdata()) != list(marked.crop(layout.rows[0]).getdata())
        for rect in layout.rows[1:]:
            assert list(plain.crop(rect).getdata()) == list(marked.crop(rect).getdata())
        for rect in (layout.up, layout.down, layout.back):
            assert list(plain.crop(rect).getdata()) == list(marked.crop(rect).getdata())

    def test_the_mark_survives_a_truncated_label(self, compositor):
        long_name = "A very long speaker name that cannot possibly fit in the row " * 2
        layout = list_layout_for(160, 128)
        x0, y0, x1, y1 = layout.rows[0]
        width, height = x1 - x0, y1 - y0
        pad = metrics_for(160, 128).pad
        blank = compositor.compose_list(
            160, 128, ListState(rows=(("", False),)), rotate=False, bgr=False).crop(layout.rows[0])
        marked = compositor.compose_list(
            160, 128, ListState(rows=((long_name, False, "", DEFAULT_MARK),)),
            rotate=False, bgr=False).crop(layout.rows[0])
        plain = compositor.compose_list(
            160, 128, ListState(rows=((long_name, False, ""),)),
            rotate=False, bgr=False).crop(layout.rows[0])

        def lit_in_centre_band(img):
            # The right-hand end of the label area at the row's vertical middle:
            # where a trailing bullet sits and a cut label's baseline dots do not.
            cy = height // 2
            return sum(
                1 for yy in range(cy - 1, cy + 2) for xx in range(width - pad - 8, width - pad)
                if img.getpixel((xx, yy)) != blank.getpixel((xx, yy)))

        assert lit_in_centre_band(marked) > lit_in_centre_band(plain)

    def test_the_mark_is_placed_after_a_short_label(self, compositor):
        layout = list_layout_for(160, 128)
        x0, y0, x1, y1 = layout.rows[0]
        width, height = x1 - x0, y1 - y0
        blank = compositor.compose_list(
            160, 128, ListState(rows=(("", False),)), rotate=False, bgr=False).crop(layout.rows[0])
        img = compositor.compose_list(
            160, 128, ListState(rows=(("A", False, "", DEFAULT_MARK),)),
            rotate=False, bgr=False).crop(layout.rows[0])

        def lit(x_from, x_to):
            return sum(
                1 for yy in range(height) for xx in range(x_from, x_to)
                if img.getpixel((xx, yy)) != blank.getpixel((xx, yy)))

        assert lit(0, width // 3) > 0
        assert lit(2 * width // 3, width) == 0

    def test_checked_row_differs_from_unchecked_row(self, compositor):
        layout = list_layout_for(160, 128)
        checked = compositor.compose_list(
            160, 128, ListState(rows=(("CD Player", True),)), rotate=False, bgr=False,
        )
        unchecked = compositor.compose_list(
            160, 128, ListState(rows=(("CD Player", False),)), rotate=False, bgr=False,
        )
        assert list(checked.crop(layout.rows[0]).getdata()) != list(unchecked.crop(layout.rows[0]).getdata())

    def test_down_up_dimmed_when_no_prev_next(self, compositor):
        layout = list_layout_for(160, 128)
        lit = compositor.compose_list(
            160, 128, ListState(rows=(("A", False),), has_prev=True, has_next=True),
            rotate=False, bgr=False,
        )
        unlit = compositor.compose_list(
            160, 128, ListState(rows=(("A", False),), has_prev=False, has_next=False),
            rotate=False, bgr=False,
        )
        assert list(lit.crop(layout.down).getdata()) != list(unlit.crop(layout.down).getdata())
        assert list(lit.crop(layout.up).getdata()) != list(unlit.crop(layout.up).getdata())

    def test_back_is_always_lit_regardless_of_paging(self, compositor):
        layout = list_layout_for(160, 128)
        a = compositor.compose_list(
            160, 128, ListState(rows=(("A", False),), has_prev=False, has_next=False),
            rotate=False, bgr=False,
        )
        b = compositor.compose_list(
            160, 128, ListState(rows=(("A", False),), has_prev=True, has_next=True),
            rotate=False, bgr=False,
        )
        assert list(a.crop(layout.back).getdata()) == list(b.crop(layout.back).getdata())

    def test_pressed_row_wash_confined_to_its_rectangle(self, compositor):
        layout = list_layout_for(160, 128)
        state_rows = (("CD Player", True), ("Kitchen", False), ("Study", False))
        unpressed = compositor.compose_list(160, 128, ListState(rows=state_rows), rotate=False, bgr=False)
        pressed = compositor.compose_list(
            160, 128, ListState(rows=state_rows, pressed=(TouchZone.LIST_ROW, 1)),
            rotate=False, bgr=False,
        )
        assert list(unpressed.getdata()) != list(pressed.getdata())
        for i, rect in enumerate(layout.rows):
            if i == 1:
                continue
            assert list(unpressed.crop(rect).getdata()) == list(pressed.crop(rect).getdata())

    def test_pressed_bar_zone_wash(self, compositor):
        layout = list_layout_for(160, 128)
        unpressed = compositor.compose_list(160, 128, ListState(rows=(("A", False),)), rotate=False, bgr=False)
        pressed = compositor.compose_list(
            160, 128, ListState(rows=(("A", False),), pressed=(TouchZone.LIST_BACK, None)),
            rotate=False, bgr=False,
        )
        assert list(unpressed.crop(layout.back).getdata()) != list(pressed.crop(layout.back).getdata())

    def test_stale_pressed_row_index_is_ignored(self, compositor):
        # A row index beyond the current page (e.g. the roster shrank
        # between paint and tap) must never raise.
        result = compositor.compose_list(
            160, 128, ListState(rows=(("A", False),), pressed=(TouchZone.LIST_ROW, 5)),
            rotate=False, bgr=False,
        )
        assert result.size == (160, 128)

    def test_rotate_and_bgr_applied_like_compose(self, compositor):
        state = ListState(rows=(("CD Player", True),))
        plain = compositor.compose_list(160, 128, state, rotate=False, bgr=False)
        rotated = compositor.compose_list(160, 128, state, rotate=True, bgr=False)
        assert list(rotated.getdata()) == list(plain.transpose(Image.ROTATE_180).getdata())

        swapped = compositor.compose_list(160, 128, state, rotate=False, bgr=True)
        assert list(swapped.getdata()) == list(Image.merge("RGB", plain.split()[::-1]).getdata())

    def test_more_rows_than_page_are_ignored_not_raised(self, compositor):
        # compose_list only ever draws rows_per_page rows — the display is
        # responsible for paging state.rows down to one page before calling
        # this. Extra entries must be ignored, never raise or overflow.
        rows = tuple((f"Appliance {i}", False) for i in range(10))
        result = compositor.compose_list(160, 128, ListState(rows=rows), rotate=False, bgr=False)
        assert result.size == (160, 128)

    def test_never_raises_with_font_cache_cleared_and_no_font_available(self, compositor):
        with patch("dial_display_draw.ImageFont.truetype", side_effect=OSError("no font")), \
             patch("dial_display_draw.ImageFont.load_default", side_effect=OSError("no default")):
            result = compositor.compose_list(
                160, 128, ListState(rows=(("CD Player", True),)), rotate=False, bgr=False,
            )
        assert result.size == (160, 128)

    def test_secondary_text_drawn_right_aligned(self, compositor):
        plain = compositor.compose_list(160, 128, ListState(rows=(("Kitchen", False),)), rotate=False, bgr=False)
        with_secondary = compositor.compose_list(
            160, 128, ListState(rows=(("Kitchen", False, "42:10"),)), rotate=False, bgr=False,
        )
        assert list(plain.getdata()) != list(with_secondary.getdata())

    def test_two_tuple_rows_byte_identical_to_before(self, compositor):
        """A 2-tuple row must render identically whether or not the module
        knows about the 3-tuple secondary slot — the regression guard for
        the PLAY_GLYPH/secondary-text feature."""
        state = ListState(rows=(("CD Player", True), ("Kitchen", False)), has_prev=True, has_next=True)
        result = compositor.compose_list(160, 128, state, rotate=False, bgr=False)
        # Re-run with an explicitly empty secondary on each row: must be
        # pixel-identical to the plain 2-tuple form.
        state_explicit = ListState(
            rows=(("CD Player", True, ""), ("Kitchen", False, "")), has_prev=True, has_next=True,
        )
        result_explicit = compositor.compose_list(160, 128, state_explicit, rotate=False, bgr=False)
        assert list(result.getdata()) == list(result_explicit.getdata())

    def test_rich_five_label_value_rows_no_highlight_with_chevrons_lit(self, compositor):
        # The read-only info page's own row shape on rich: no row is ever
        # "current" (no highlight), label left + value right-aligned via
        # the existing secondary-text path, rail chevrons lit per
        # has_prev/has_next.
        metrics = metrics_for(320, 240, 0.1778)
        layout = list_layout_for(320, 240, metrics=metrics)
        rows = (
            ("Dial name", False, "Kitchen"),
            ("Firmware", False, "1.2.3"),
            ("IPv4", False, "192.168.1.20"),
            ("WiFi", False, "HomeNet"),
            ("Signal", False, "Strong"),
        )
        state = ListState(rows=rows, has_prev=False, has_next=True)
        result = compositor.compose_list(320, 240, state, rotate=False, bgr=False, metrics=metrics)
        blank = compositor.compose_list(
            320, 240, ListState(rows=(("", False, ""),) * 5), rotate=False, bgr=False, metrics=metrics,
        )
        for rect in layout.rows:
            assert list(result.crop(rect).getdata()) != list(blank.crop(rect).getdata())
        no_next = compositor.compose_list(
            320, 240, ListState(rows=rows, has_prev=False, has_next=False), rotate=False, bgr=False,
            metrics=metrics,
        )
        assert list(result.crop(layout.rail_down).getdata()) != list(no_next.crop(layout.rail_down).getdata())

    @staticmethod
    def _brightest(img):
        return max(max(px) for px in img.getdata())

    @pytest.mark.parametrize("metrics", [_RICH_METRICS, _COMPACT_240, _COMPACT_128, metrics_for(160, 128)])
    def test_selector_row_secondary_text_dimmed(self, compositor, metrics):
        w, h = metrics.width, metrics.height
        if metrics.content_tier == CONTENT_COMPACT:
            row_rect = compact_picker_layout_for(w, h, metrics=metrics).row0
        else:
            row_rect = list_layout_for(w, h, metrics=metrics).rows[0]

        def render(secondary):
            state = ListState(rows=(("Kitchen", False, secondary),))
            return compositor.compose_list(w, h, state, rotate=False, bgr=False, metrics=metrics).crop(row_rect)

        dimmed = render(NOT_AUTHORISED_TEXT)
        normal = render("Not authorised.")  # a plain secondary string: drawn at full white
        assert self._brightest(normal) > DIMMED_GLYPH_RGB[0]
        # Label and secondary are both drawn, and nothing in the row is brighter than the dim colour.
        blank = render("")
        assert list(dimmed.getdata()) != list(blank.getdata())
        assert self._brightest(dimmed) <= max(DIMMED_GLYPH_RGB)


# ---------------------------------------------------------------------------
# The play marker — a filled white right-pointing triangle drawn in every
# row whose secondary slot is PLAY_GLYPH, on every panel size/density.
# ---------------------------------------------------------------------------

_MARKER_GOLDEN_CASES = [
    (160, 128, metrics_for(160, 128)),
    (128, 128, metrics_for(128, 128)),
    # A 240x240 base-tier case with density left unknown (None): PLAY_GLYPH
    # is an appliance-selector-only marker, never reachable on the compact
    # tier (appliance selection is unreachable there), so this must stay
    # off the compact gate — any real density fine enough to have exercised
    # the old touch_short veto at this pixel size (e.g. 0.0973) now
    # resolves compact instead (COMPACT_MAX_SHORT_SIDE_MM is deliberately
    # looser than that veto's own implied screen size).
    (240, 240, metrics_for(240, 240)),
    (320, 240, _RICH_METRICS),
    (320, 240, metrics_for(320, 240, 0.2778)),
    (640, 480, _LARGE_METRICS),
]


def _marker_rect_for(width, height, metrics):
    """Re-derive the marker rect from the layout and the module's own
    _MARKER_BOX_FRACTION — pins the placement rule, not one literal."""
    from dial_display_render import _MARKER_BOX_FRACTION

    layout = list_layout_for(width, height, metrics=metrics)
    row_h = layout.row_h
    pad = metrics.pad
    x0, y0, x1, y1 = layout.rows[0]
    box = max(2, round(row_h * _MARKER_BOX_FRACTION))
    top = y0 + (row_h - box) // 2
    return (x1 - pad - box, top, x1 - pad, top + box), layout.rows[0], row_h, pad


class TestPlayMarker:
    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    @pytest.mark.parametrize("width,height,metrics", _MARKER_GOLDEN_CASES)
    def test_marker_present_white_and_right_pointing(self, compositor, width, height, metrics):
        marker_rect, row_rect, row_h, pad = _marker_rect_for(width, height, metrics)
        mx0, my0, mx1, my1 = marker_rect
        result = compositor.compose_list(
            width, height, ListState(rows=(("Kitchen", False, PLAY_GLYPH),)),
            rotate=False, bgr=False, metrics=metrics,
        )
        cx, cy = (mx0 + mx1) // 2, (my0 + my1) // 2

        centre = result.getpixel((cx, cy))
        assert min(centre) > 200
        assert centre[0] == centre[1] == centre[2]

        marker_w = mx1 - mx0
        marker_pixels = list(result.crop(marker_rect).getdata())
        assert all(p[0] == p[1] == p[2] for p in marker_pixels)

        half = marker_w // 2
        left_bright = sum(
            1 for i, p in enumerate(marker_pixels) if (i % marker_w) < half and min(p) > 128
        )
        right_bright = sum(
            1 for i, p in enumerate(marker_pixels) if (i % marker_w) >= half and min(p) > 128
        )
        assert left_bright > right_bright

    @pytest.mark.parametrize("width,height,metrics", _MARKER_GOLDEN_CASES)
    def test_marker_confined_and_smaller_than_the_row(self, compositor, width, height, metrics):
        marker_rect, row_rect, row_h, pad = _marker_rect_for(width, height, metrics)
        mx0, my0, mx1, my1 = marker_rect
        x0, y0, x1, y1 = row_rect
        cx, cy = (mx0 + mx1) // 2, (my0 + my1) // 2

        plain = compositor.compose_list(
            width, height, ListState(rows=(("Kitchen", False),)), rotate=False, bgr=False, metrics=metrics,
        )
        marked = compositor.compose_list(
            width, height, ListState(rows=(("Kitchen", False, PLAY_GLYPH),)),
            rotate=False, bgr=False, metrics=metrics,
        )

        region = (x1 - pad - row_h, y0, x1 - pad, y1)
        rx0, ry0, rx1, ry1 = region
        plain_region = list(plain.crop(region).getdata())
        marked_region = list(marked.crop(region).getdata())
        rw = rx1 - rx0
        for i, (p_px, m_px) in enumerate(zip(plain_region, marked_region)):
            if p_px == m_px:
                continue
            rx, ry = rx0 + (i % rw), ry0 + (i // rw)
            assert mx0 <= rx < mx1 and my0 <= ry < my1, (
                f"pixel {(rx, ry)} differs outside the marker rect"
            )

        chassis = plain.getpixel((0, 0))
        assert marked.getpixel((mx0 - 2, cy)) == chassis
        assert marked.getpixel((cx, my0 - 1)) == chassis
        for x in range(mx0, mx1):
            assert min(marked.getpixel((x, y0))) <= 128
            assert min(marked.getpixel((x, y1 - 2))) <= 128

    @pytest.mark.parametrize("width,height,metrics", _MARKER_GOLDEN_CASES)
    def test_marker_absent_when_not_playing(self, compositor, width, height, metrics):
        # A plain row draws no marker at all. A picker row's free-text
        # secondary ("42:10") is right-aligned to the same edge the marker
        # box anchors to and can be wider than the box itself, so pixel
        # equality with a bare row is not a safe probe here — the code-path
        # guarantee ("only a PLAY_GLYPH secondary reaches _draw_glyph with
        # GLYPH_PLAY") is what actually matters, checked directly instead.
        from dial_display_draw import GLYPH_PLAY, _draw_glyph as real_draw_glyph

        calls = []

        def spy(img, rect, kind, *params, **kwargs):
            calls.append(kind)
            return real_draw_glyph(img, rect, kind, *params, **kwargs)

        with patch("dial_display_render._draw_glyph", side_effect=spy):
            compositor.compose_list(
                width, height, ListState(rows=(("Kitchen", False),)), rotate=False, bgr=False, metrics=metrics,
            )
            compositor.compose_list(
                width, height, ListState(rows=(("Kitchen", False, "42:10"),)),
                rotate=False, bgr=False, metrics=metrics,
            )
        assert GLYPH_PLAY not in calls

    def test_marker_never_raises_with_no_font(self, compositor):
        with patch("dial_display_draw.ImageFont.truetype", side_effect=OSError("no font")), \
             patch("dial_display_draw.ImageFont.load_default", side_effect=OSError("no default")):
            result = compositor.compose_list(
                160, 128, ListState(rows=(("Kitchen", True, PLAY_GLYPH),)), rotate=False, bgr=False,
            )
        assert result.size == (160, 128)


class TestRowWash:
    """The current-row wash — a faint, persistent version of the pressed
    wash, drawn under any press, marking the row the pipeline considers
    CURRENT independently of the play marker."""

    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    @pytest.mark.parametrize(
        "width,height,sample_col,sep_row",
        [(160, 128, 158, 31), (320, 240, 246, 47)],
    )
    def test_wash_pixels_match_the_documented_table(self, compositor, width, height, sample_col, sep_row):
        metrics = _RICH_METRICS if width == 320 else None
        cases = [
            (("A", False), None, (16, 16, 16)),
            (("A", False, PLAY_GLYPH), None, (16, 16, 16)),
            (("A", True), None, (36, 36, 36)),
            (("A", True, PLAY_GLYPH), None, (36, 36, 36)),
            (("A", True, PLAY_GLYPH), (TouchZone.LIST_ROW, 0), (96, 96, 96)),
            (("A", False), (TouchZone.LIST_ROW, 0), (82, 82, 82)),
        ]
        for row, pressed, expected in cases:
            result = compositor.compose_list(
                width, height, ListState(rows=(row,), pressed=pressed),
                rotate=False, bgr=False, metrics=metrics,
            )
            assert result.getpixel((sample_col, 1)) == expected, row
            assert result.getpixel((sample_col, sep_row)) == (48, 48, 48)

    def test_wash_confined_to_its_own_row(self, compositor):
        layout = list_layout_for(160, 128)
        unwashed = compositor.compose_list(
            160, 128, ListState(rows=(("A", False), ("B", False), ("C", False))),
            rotate=False, bgr=False,
        )
        washed = compositor.compose_list(
            160, 128, ListState(rows=(("A", True), ("B", False), ("C", False))),
            rotate=False, bgr=False,
        )
        for i in (1, 2):
            assert list(unwashed.crop(layout.rows[i]).getdata()) == list(washed.crop(layout.rows[i]).getdata())

    def test_current_and_playing_marker_matches_playing_only_marker(self, compositor):
        marker_rect, _row_rect, _row_h, _pad = _marker_rect_for(160, 128, metrics_for(160, 128))
        playing_only = compositor.compose_list(
            160, 128, ListState(rows=(("Kitchen", False, PLAY_GLYPH),)), rotate=False, bgr=False,
        )
        current_and_playing = compositor.compose_list(
            160, 128, ListState(rows=(("Kitchen", True, PLAY_GLYPH),)), rotate=False, bgr=False,
        )
        bright = lambda img: {
            (x, y)
            for x in range(marker_rect[0], marker_rect[2])
            for y in range(marker_rect[1], marker_rect[3])
            if min(img.getpixel((x, y))) > 200
        }
        assert bright(playing_only) == bright(current_and_playing)


def _repeat_dot_rect(layout, width=160, height=128):
    """The enable layout's "Repeat Play" row dot marker rect — mirrors the
    geometry _body_repeat_row() itself computes."""
    pad = metrics_for(width, height).pad
    row = layout.row
    dot_box = row[3] - row[1]
    return (row[2] - pad - dot_box, row[1], row[2] - pad, row[3])


class TestComposeRepeatEnableLayout:
    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    def test_never_raises_and_returns_panel_sized_frame(self, compositor):
        result = compositor.compose_repeat(160, 128, _repeat_state(), rotate=False, bgr=False)
        assert result.size == (160, 128)

    def test_row_dot_hollow_when_unarmed(self, compositor):
        layout = repeat_layout_for(160, 128)
        x0, y0, x1, y1 = _repeat_dot_rect(layout)
        cx, cy = (x0 + x1) // 2, (y0 + y1) // 2
        result = compositor.compose_repeat(160, 128, _repeat_state(armed=False), rotate=False, bgr=False)
        # Hollow: the centre stays background, only the outline is drawn.
        assert result.getpixel((cx, cy)) == (16, 16, 16)

    def test_row_dot_solid_when_armed(self, compositor):
        layout = repeat_layout_for(160, 128)
        x0, y0, x1, y1 = _repeat_dot_rect(layout)
        cx, cy = (x0 + x1) // 2, (y0 + y1) // 2
        result = compositor.compose_repeat(160, 128, _repeat_state(armed=True), rotate=False, bgr=False)
        assert result.getpixel((cx, cy)) == (255, 255, 255)

    def test_row_content_differs_between_layouts(self, compositor):
        layout = repeat_layout_for(160, 128)
        enable = compositor.compose_repeat(160, 128, _repeat_state(layout="enable"), rotate=False, bgr=False)
        replaying = compositor.compose_repeat(
            160, 128,
            _repeat_state(layout="replaying", line="0:00 / 1:00", start_enabled=True, stop_enabled=False),
            rotate=False, bgr=False,
        )
        assert list(enable.crop(layout.row).getdata()) != list(replaying.crop(layout.row).getdata())

    def test_name_drawn(self, compositor):
        layout = repeat_layout_for(160, 128)
        blank = compositor.compose_repeat(160, 128, _repeat_state(name=""), rotate=False, bgr=False)
        named = compositor.compose_repeat(160, 128, _repeat_state(name="Kitchen"), rotate=False, bgr=False)
        assert list(blank.crop(layout.name).getdata()) != list(named.crop(layout.name).getdata())

    def test_dots_drawn_right_filled(self, compositor):
        """The repeat screen's dots draw the RIGHT dot filled (screen 2 of
        2) — the mirror image of the main overlay's left-filled dots."""
        layout = repeat_layout_for(160, 128)
        result = compositor.compose_repeat(160, 128, _repeat_state(), rotate=False, bgr=False)
        blank = Image.new("RGB", (160, 128), (16, 16, 16))
        assert list(result.crop(layout.dots).getdata()) != list(blank.crop(layout.dots).getdata())

    def test_pressed_row_highlight(self, compositor):
        layout = repeat_layout_for(160, 128)
        unpressed = compositor.compose_repeat(160, 128, _repeat_state(), rotate=False, bgr=False)
        pressed = compositor.compose_repeat(
            160, 128, _repeat_state(pressed=TouchZone.REPEAT_PLAY), rotate=False, bgr=False,
        )
        assert list(unpressed.crop(layout.row).getdata()) != list(pressed.crop(layout.row).getdata())

    def test_no_volume_buttons_drawn(self, compositor):
        """The enable layout has no bottom +/- volume controls — the top
        band's mute/volume readout is display-only on this screen."""
        layout = repeat_layout_for(160, 128)
        flat_bg = Image.new("RGB", (160, 128), (16, 16, 16))
        result = compositor.compose_repeat(160, 128, _repeat_state(), rotate=False, bgr=False)
        assert list(result.crop(layout.start).getdata()) == list(flat_bg.crop(layout.start).getdata())
        assert list(result.crop(layout.stop).getdata()) == list(flat_bg.crop(layout.stop).getdata())

    def test_never_raises_with_no_font(self, compositor):
        with patch("dial_display_draw.ImageFont.truetype", side_effect=OSError("no font")), \
             patch("dial_display_draw.ImageFont.load_default", side_effect=OSError("no default")):
            result = compositor.compose_repeat(160, 128, _repeat_state(armed=True), rotate=False, bgr=False)
        assert result.size == (160, 128)


class TestComposeRepeatControlsFalse:
    """controls=False (the compact tier's manager path, once its own
    controls window has lapsed) skips the whole pipeline and returns the
    bare base — no header/body/footer, rotate/bgr only."""

    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    def test_returns_the_bare_base_undimmed(self, compositor):
        base = Image.new("RGB", (160, 128), (100, 120, 140))
        result = compositor.compose_repeat(
            160, 128, _repeat_state(name="Kitchen", armed=True), base=base,
            rotate=False, bgr=False, controls=False,
        )
        assert list(result.getdata()) == list(base.getdata())

    def test_no_base_falls_back_to_the_flat_chassis(self, compositor):
        result = compositor.compose_repeat(
            160, 128, _repeat_state(), base=None, rotate=False, bgr=False, controls=False,
        )
        assert result.size == (160, 128)
        assert result.getpixel((0, 0)) == (16, 16, 16)

    def test_defaults_to_true_existing_callers_unaffected(self, compositor):
        base = Image.new("RGB", (160, 128), (100, 120, 140))
        with_controls = compositor.compose_repeat(
            160, 128, _repeat_state(name="Kitchen"), base=base, rotate=False, bgr=False,
        )
        explicit_true = compositor.compose_repeat(
            160, 128, _repeat_state(name="Kitchen"), base=base, rotate=False, bgr=False, controls=True,
        )
        assert list(with_controls.getdata()) == list(explicit_true.getdata())

    def test_rotate_and_bgr_still_applied(self, compositor):
        base = Image.new("RGB", (160, 128), (10, 20, 30))
        base.putpixel((0, 0), (200, 0, 0))
        result = compositor.compose_repeat(
            160, 128, _repeat_state(), base=base, rotate=True, bgr=True, controls=False,
        )
        # rotate 180 puts (0,0) at (159,127); bgr swaps the R/B channels.
        assert result.getpixel((159, 127)) == (0, 0, 200)


class TestComposeRepeatTopBand:
    """The top band (dots, name, mute/volume readout) is shared verbatim by
    both layouts — see _draw_top_band_content(). Exercised once here at the
    default ("enable") layout rather than duplicated in both layout test
    classes."""

    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    def test_volume_number_drawn_when_present(self, compositor):
        layout = repeat_layout_for(160, 128)
        blank = compositor.compose_repeat(160, 128, _repeat_state(volume=None), rotate=False, bgr=False)
        with_volume = compositor.compose_repeat(160, 128, _repeat_state(volume=42), rotate=False, bgr=False)
        assert list(blank.crop(layout.volume_cluster).getdata()) != list(
            with_volume.crop(layout.volume_cluster).getdata()
        )

    def test_name_pressed_highlight(self, compositor):
        layout = repeat_layout_for(160, 128)
        unpressed = compositor.compose_repeat(160, 128, _repeat_state(), rotate=False, bgr=False)
        pressed = compositor.compose_repeat(
            160, 128, _repeat_state(pressed=TouchZone.NAME), rotate=False, bgr=False,
        )
        assert list(unpressed.crop(layout.name).getdata()) != list(pressed.crop(layout.name).getdata())


class TestComposeRepeatReplayingLayout:
    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    def _state(self, **overrides):
        base = dict(layout="replaying", line="1:23 / 4:56", start_enabled=True, stop_enabled=True)
        base.update(overrides)
        return _repeat_state(**base)

    def test_line_text_drawn(self, compositor):
        layout = repeat_layout_for(160, 128)
        blank_line = self._state(line="")
        with_line = self._state(line="1:23 / 4:56")
        blank_result = compositor.compose_repeat(160, 128, blank_line, rotate=False, bgr=False)
        line_result = compositor.compose_repeat(160, 128, with_line, rotate=False, bgr=False)
        assert list(blank_result.crop(layout.line).getdata()) != list(line_result.crop(layout.line).getdata())

    def test_start_and_stop_labels_drawn(self, compositor):
        layout = repeat_layout_for(160, 128)
        empty = Image.new("RGB", (160, 128), (16, 16, 16))
        result = compositor.compose_repeat(160, 128, self._state(), rotate=False, bgr=False)
        # Both button rects differ from an untouched flat-background crop —
        # something (dimmed band plus label) is drawn in each.
        assert list(result.crop(layout.start).getdata()) != list(empty.crop(layout.start).getdata())
        assert list(result.crop(layout.stop).getdata()) != list(empty.crop(layout.stop).getdata())

    def test_disabled_start_dimmer_than_enabled(self, compositor):
        layout = repeat_layout_for(160, 128)
        enabled = compositor.compose_repeat(
            160, 128, self._state(start_enabled=True), rotate=False, bgr=False,
        )
        disabled = compositor.compose_repeat(
            160, 128, self._state(start_enabled=False), rotate=False, bgr=False,
        )
        assert list(enabled.crop(layout.start).getdata()) != list(disabled.crop(layout.start).getdata())

    def test_disabled_stop_dimmer_than_enabled(self, compositor):
        layout = repeat_layout_for(160, 128)
        enabled = compositor.compose_repeat(
            160, 128, self._state(stop_enabled=True), rotate=False, bgr=False,
        )
        disabled = compositor.compose_repeat(
            160, 128, self._state(stop_enabled=False), rotate=False, bgr=False,
        )
        assert list(enabled.crop(layout.stop).getdata()) != list(disabled.crop(layout.stop).getdata())

    def test_stop_pressed_wash_confined_to_stop(self, compositor):
        layout = repeat_layout_for(160, 128)
        unpressed = compositor.compose_repeat(160, 128, self._state(stop_pressed=False), rotate=False, bgr=False)
        pressed = compositor.compose_repeat(160, 128, self._state(stop_pressed=True), rotate=False, bgr=False)
        assert list(unpressed.crop(layout.stop).getdata()) != list(pressed.crop(layout.stop).getdata())
        assert list(unpressed.crop(layout.start).getdata()) == list(pressed.crop(layout.start).getdata())

    def test_divider_drawn_between_start_and_stop(self, compositor):
        layout = repeat_layout_for(160, 128)
        blank_bg = Image.new("RGB", (160, 128), (16, 16, 16))
        result = compositor.compose_repeat(160, 128, self._state(), rotate=False, bgr=False)
        divider_col = [(layout.divider_x, y) for y in range(layout.bottom_band[1], layout.bottom_band[3])]
        assert any(result.getpixel(p) != blank_bg.getpixel(p) for p in divider_col)

    def test_rotate_and_bgr_applied_like_compose(self, compositor):
        state = self._state()
        plain = compositor.compose_repeat(160, 128, state, rotate=False, bgr=False)
        rotated = compositor.compose_repeat(160, 128, state, rotate=True, bgr=False)
        assert list(rotated.getdata()) == list(plain.transpose(Image.ROTATE_180).getdata())
        swapped = compositor.compose_repeat(160, 128, state, rotate=False, bgr=True)
        assert list(swapped.getdata()) == list(Image.merge("RGB", plain.split()[::-1]).getdata())

    def test_start_label_reads_restart_not_start(self, compositor):
        with patch("dial_display_render._draw_label_centered") as mock_label_centered:
            compositor.compose_repeat(160, 128, self._state(), rotate=False, bgr=False)
        texts = [call.args[2] for call in mock_label_centered.call_args_list]
        assert "Restart" in texts
        assert "Start" not in texts

    def test_base_image_drawn_behind_the_position_line(self, compositor):
        layout = repeat_layout_for(160, 128)
        base = Image.new("RGB", (160, 128), (200, 50, 50))
        result = compositor.compose_repeat(160, 128, self._state(), base=base, rotate=False, bgr=False)
        # A point inside the row rect but well clear of the centred text —
        # neither band is dimmed there, so the base colour must survive
        # untouched.
        probe = (layout.row[0] + 2, (layout.row[1] + layout.row[3]) // 2)
        assert result.getpixel(probe) == (200, 50, 50)

    def test_base_image_ignored_in_enable_layout(self, compositor):
        layout = repeat_layout_for(160, 128)
        base = Image.new("RGB", (160, 128), (200, 50, 50))
        state = _repeat_state(layout="enable")
        result = compositor.compose_repeat(160, 128, state, base=base, rotate=False, bgr=False)
        probe = (layout.row[0] + 2, (layout.row[1] + layout.row[3]) // 2)
        assert result.getpixel(probe) == (16, 16, 16)

    def test_top_and_bottom_bands_dim_the_base_image(self, compositor):
        layout = repeat_layout_for(160, 128)
        raw = (200, 50, 50)
        base = Image.new("RGB", (160, 128), raw)
        result = compositor.compose_repeat(160, 128, self._state(), base=base, rotate=False, bgr=False)
        gap_x = (layout.name[2] + layout.volume_cluster[0]) // 2
        gap_y = (layout.top_band[1] + layout.top_band[3]) // 2
        pixel = result.getpixel((gap_x, gap_y))
        # Darkened, not merely different — every channel moves toward
        # black, same discipline test_dim_darkens_bands_leaves_middle_
        # unchanged uses for the main overlay's own bands.
        assert pixel != raw
        assert all(c <= r for c, r in zip(pixel, raw))

    def test_no_base_image_falls_back_to_flat_background(self, compositor):
        result = compositor.compose_repeat(160, 128, self._state(), base=None, rotate=False, bgr=False)
        assert result.size == (160, 128)

    def test_never_raises_with_unusable_base_image(self, compositor):
        result = compositor.compose_repeat(
            160, 128, self._state(), base=object(), rotate=False, bgr=False,
        )
        assert result.size == (160, 128)

    def test_never_raises_with_no_font(self, compositor):
        with patch("dial_display_draw.ImageFont.truetype", side_effect=OSError("no font")), \
             patch("dial_display_draw.ImageFont.load_default", side_effect=OSError("no default")):
            result = compositor.compose_repeat(160, 128, self._state(), rotate=False, bgr=False)
        assert result.size == (160, 128)


class TestRepeatOutputsWash:
    """Reading the shared zone table gives the repeat screen's pressed-rect
    lookup an OUTPUTS entry: a tap there resolves to OUTPUTS and opens the
    outputs list (repeat_zone_at() already does this), so drawing its wash
    the same way every other tappable zone's wash is drawn is the
    consistent behaviour, not a special case. The repeat screen has no MUTE
    zone of its own at all -- a stale MUTE press (e.g. carried over from
    another screen) washes nothing here."""

    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    def test_pressed_outputs_washes_the_volume_cluster_and_nothing_else(self, compositor):
        layout = repeat_layout_for(160, 128)
        unpressed = compositor.compose_repeat(160, 128, _repeat_state(), rotate=False, bgr=False)
        pressed = compositor.compose_repeat(
            160, 128, _repeat_state(pressed=TouchZone.OUTPUTS), rotate=False, bgr=False,
        )
        assert list(unpressed.crop(layout.volume_cluster).getdata()) != list(
            pressed.crop(layout.volume_cluster).getdata()
        )
        for rect in (layout.dots, layout.name, layout.row, layout.start, layout.stop):
            assert list(unpressed.crop(rect).getdata()) == list(pressed.crop(rect).getdata())

    def test_stale_mute_press_washes_nothing_on_the_repeat_surface(self, compositor):
        unpressed = compositor.compose_repeat(160, 128, _repeat_state(), rotate=False, bgr=False)
        pressed = compositor.compose_repeat(
            160, 128, _repeat_state(pressed=TouchZone.MUTE), rotate=False, bgr=False,
        )
        assert list(unpressed.getdata()) == list(pressed.getdata())


# ---------------------------------------------------------------------------
# compose_idle — the idle screen: just the base logo the manager chose
# (plain disc, or the replay-available logo), with no overlay.
# ---------------------------------------------------------------------------

class TestComposeIdle:
    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    def _logo(self, size=(160, 128)):
        return Image.new("RGB", size, (32, 32, 32))

    def test_renders_the_base_plus_the_wifi_glyph_and_the_bell_only(self, compositor):
        # Every idle frame carries the Wi-Fi glyph (on the plain logo too,
        # not only the replay-available one) and, with a bell given, the
        # bell, so the only pixels that ever differ from the plain base are
        # the ones inside one of their two boxes.
        base = self._logo()
        result = compositor.compose_idle(base, 160, 128, rotate=False, bgr=False, bell=BellBadge("warning", 2))
        idle = idle_layout_for(160, 128)
        info, wifi = idle.info, idle.wifi
        for y in range(128):
            for x in range(160):
                if info[0] <= x < info[2] and info[1] <= y < info[3]:
                    continue
                if wifi[0] <= x < wifi[2] and wifi[1] <= y < wifi[3]:
                    continue
                assert result.getpixel((x, y)) == base.getpixel((x, y))

    def test_the_bell_is_drawn_inside_its_own_box_only_when_given(self, compositor):
        base = self._logo()
        info = idle_layout_for(160, 128).info
        plain = compositor.compose_idle(base, 160, 128, rotate=False, bgr=False)
        belled = compositor.compose_idle(base, 160, 128, rotate=False, bgr=False, bell=BellBadge("warning", 2))
        assert list(plain.crop(info).getdata()) == list(base.crop(info).getdata())
        assert list(belled.crop(info).getdata()) != list(base.crop(info).getdata())

    def test_no_bell_is_byte_identical_to_the_frame_without_the_argument(self, compositor):
        base = self._logo()
        a = compositor.compose_idle(base, 160, 128, rotate=False, bgr=False, bell=None)
        b = compositor.compose_idle(base, 160, 128, rotate=False, bgr=False)
        assert a.tobytes() == b.tobytes()

    @pytest.mark.parametrize("severity", sorted(_BELL_RGB))
    def test_the_bell_takes_its_severity_colour(self, compositor, severity):
        metrics = metrics_for(320, 240, 0.1778)
        frame = compositor.compose_idle(
            self._logo((320, 240)), 320, 240, rotate=False, bgr=False, metrics=metrics,
            bell=BellBadge(severity, 1),
        )
        x0, y0, x1, y1 = idle_layout_for(320, 240, metrics=metrics).info
        side = round(min(x1 - x0, y1 - y0) * _BELL_GLYPH_FRACTION)
        bx0, by0, _, _ = _centred_box((x0, y0, x1, y1), side)
        # Inside the bell's body, left of the number, on the dome's straight side.
        px = frame.getpixel((bx0 + round(side * 7.4 / 24), by0 + round(side * 13.5 / 24)))
        assert all(abs(a - b) <= 6 for a, b in zip(px, _BELL_RGB[severity]))

    def test_the_bell_carries_its_number_in_white(self, compositor):
        metrics = metrics_for(320, 240, 0.1778)
        info = idle_layout_for(320, 240, metrics=metrics).info
        base = self._logo((320, 240))
        one = compositor.compose_idle(base, 320, 240, rotate=False, bgr=False, metrics=metrics, bell=BellBadge("warning", 1))
        two = compositor.compose_idle(base, 320, 240, rotate=False, bgr=False, metrics=metrics, bell=BellBadge("warning", 2))
        assert list(one.crop(info).getdata()) != list(two.crop(info).getdata())
        assert any(px[0] > 245 and px[1] > 245 and px[2] > 245 for px in one.crop(info).getdata())

    def test_wifi_glyph_drawn_inside_its_own_box(self, compositor):
        base = self._logo()
        result = compositor.compose_idle(base, 160, 128, rotate=False, bgr=False)
        wifi = idle_layout_for(160, 128).wifi
        assert list(result.crop(wifi).getdata()) != list(base.crop(wifi).getdata())

    def test_none_base_returns_none(self, compositor):
        assert compositor.compose_idle(None, 160, 128, rotate=False, bgr=False) is None

    def test_never_raises_with_a_failing_painter(self, compositor):
        base = self._logo()
        with patch("dial_display_draw._glyph_tile", side_effect=RuntimeError("boom")):
            result = compositor.compose_idle(base, 160, 128, rotate=False, bgr=False)
        assert result.size == (160, 128)

    def test_rotate_and_bgr_applied(self, compositor):
        base = self._logo()
        plain = compositor.compose_idle(base, 160, 128, rotate=False, bgr=False)
        rotated = compositor.compose_idle(base, 160, 128, rotate=True, bgr=False)
        assert list(rotated.getdata()) == list(plain.transpose(Image.ROTATE_180).getdata())
        swapped = compositor.compose_idle(base, 160, 128, rotate=False, bgr=True)
        assert list(swapped.getdata()) == list(Image.merge("RGB", plain.split()[::-1]).getdata())


# ---------------------------------------------------------------------------
# compose_idle — the Wi-Fi status glyph's own bars/alarm parameters.
# ---------------------------------------------------------------------------

class TestComposeIdleWifi:
    def _logo(self, size=(160, 128)):
        return Image.new("RGB", size, (32, 32, 32))

    def test_bars_change_only_the_wifi_box(self, compositor):
        base = self._logo()
        a = compositor.compose_idle(base, 160, 128, rotate=False, bgr=False, wifi_bars=1)
        b = compositor.compose_idle(base, 160, 128, rotate=False, bgr=False, wifi_bars=3)
        wifi = idle_layout_for(160, 128).wifi
        assert list(a.crop(wifi).getdata()) != list(b.crop(wifi).getdata())
        for y in range(128):
            for x in range(160):
                if wifi[0] <= x < wifi[2] and wifi[1] <= y < wifi[3]:
                    continue
                assert a.getpixel((x, y)) == b.getpixel((x, y))

    def test_alarm_paints_red_in_the_wifi_box(self, compositor):
        base = self._logo()
        frame = compositor.compose_idle(base, 160, 128, rotate=False, bgr=False, wifi_style=WIFI_RED)
        wifi = idle_layout_for(160, 128).wifi
        reds = [p for p in frame.crop(wifi).getdata() if p[0] > 150 and p[1] < 130 and p[2] < 130]
        assert reds
        grey_frame = compositor.compose_idle(base, 160, 128, rotate=False, bgr=False, wifi_bars=0)
        assert not [p for p in grey_frame.crop(wifi).getdata() if p[0] > 150 and p[1] < 130]

    def test_bars_clamped_to_zero_three(self, compositor):
        base = self._logo()
        assert list(compositor.compose_idle(base, 160, 128, rotate=False, bgr=False, wifi_bars=9).getdata()) == \
            list(compositor.compose_idle(base, 160, 128, rotate=False, bgr=False, wifi_bars=3).getdata())
        assert list(compositor.compose_idle(base, 160, 128, rotate=False, bgr=False, wifi_bars=-1).getdata()) == \
            list(compositor.compose_idle(base, 160, 128, rotate=False, bgr=False, wifi_bars=0).getdata())

    def test_off_style_draws_no_wifi_glyph_at_all(self, compositor):
        base = self._logo()
        off = compositor.compose_idle(base, 160, 128, rotate=False, bgr=False, wifi_style=WIFI_OFF)
        grey = compositor.compose_idle(base, 160, 128, rotate=False, bgr=False, wifi_style=WIFI_GREY)
        wifi = idle_layout_for(160, 128).wifi
        # Nothing at all in the wifi box: the base shows through untouched.
        assert list(off.crop(wifi).getdata()) == list(base.crop(wifi).getdata())
        assert list(grey.crop(wifi).getdata()) != list(base.crop(wifi).getdata())
        # And the rest of the frame (the bell included) is byte-identical.
        for y in range(128):
            for x in range(160):
                if wifi[0] <= x < wifi[2] and wifi[1] <= y < wifi[3]:
                    continue
                assert off.getpixel((x, y)) == grey.getpixel((x, y))

    def test_grey_style_is_byte_identical_to_signal_with_zero_bars(self, compositor):
        base = self._logo()
        grey = compositor.compose_idle(base, 160, 128, rotate=False, bgr=False, wifi_style=WIFI_GREY)
        zero = compositor.compose_idle(base, 160, 128, rotate=False, bgr=False, wifi_bars=0)
        assert list(grey.getdata()) == list(zero.getdata())

    def test_red_style_ignores_bars(self, compositor):
        base = self._logo()
        a = compositor.compose_idle(base, 160, 128, rotate=False, bgr=False, wifi_style=WIFI_RED, wifi_bars=0)
        b = compositor.compose_idle(base, 160, 128, rotate=False, bgr=False, wifi_style=WIFI_RED, wifi_bars=3)
        assert list(a.getdata()) == list(b.getdata())

    def test_off_style_builds_no_wifi_tile(self, compositor):
        # Off means the painter is never invoked: with no bell either no tile
        # is built at all, and with one only the bell's (one lru miss).
        _reset_render_caches()
        compositor.compose_idle(self._logo(), 160, 128, rotate=False, bgr=False, wifi_style=WIFI_OFF)
        assert _glyph_tile.cache_info().misses == 0
        compositor.compose_idle(
            self._logo(), 160, 128, rotate=False, bgr=False, wifi_style=WIFI_OFF, bell=BellBadge("info", 1))
        assert _glyph_tile.cache_info().misses == 1

    def test_the_bell_fills_most_of_its_zone_and_stays_inside_it(self, compositor):
        metrics = metrics_for(320, 240, 0.1778)
        base = self._logo((320, 240))
        frame = compositor.compose_idle(
            base, 320, 240, rotate=False, bgr=False, metrics=metrics, bell=BellBadge("warning", 1))
        x0, y0, x1, y1 = idle_layout_for(320, 240, metrics=metrics).info
        diff = [
            (x, y) for y in range(y0, y1) for x in range(x0, x1)
            if frame.getpixel((x, y)) != base.getpixel((x, y))
        ]
        xs, ys = [p[0] for p in diff], [p[1] for p in diff]
        side = min(x1 - x0, y1 - y0)
        assert max(ys) - min(ys) >= 0.6 * side and max(xs) - min(xs) >= 0.6 * side


# ---------------------------------------------------------------------------
# A two-button card (the No WiFi shape): a solid chassis fill whatever was
# showing, the card the whole panel on every tier, crosshair, press wash by
# cell index.
# ---------------------------------------------------------------------------

class TestComposeCard:
    """compose_warning() with two buttons: solid chassis, full-panel card,
    crosshair, press wash."""

    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    def _view(self, **kw):
        return WarningView(title="No WiFi", buttons=("Restart", "Close"), **kw)

    def _frame(self, compositor, size, view, mm=None, **kw):
        metrics = metrics_for(*size, mm) if mm is not None else None
        return compositor.compose_warning(
            size[0], size[1], view,
            rotate=kw.get("rotate", False), bgr=kw.get("bgr", False), metrics=metrics)

    @pytest.mark.parametrize("size,mm", [((320, 240), 0.1778), ((160, 128), None), ((240, 240), 0.0973)])
    def test_card_is_the_whole_panel_on_a_solid_chassis_fill(self, compositor, size, mm):
        frame = self._frame(compositor, size, self._view(), mm)
        w, h = size
        for xy in ((1, 1), (w - 2, 1), (1, h - 2), (6, h // 3)):
            assert frame.getpixel(xy) == LIST_BG_RGB
        layout = warning_layout_for(w, h, buttons=2, metrics=metrics_for(w, h, mm) if mm else None)
        assert layout.card == (0, 0, w, h)

    def test_crosshair_horizontal_full_width_vertical_bottom_row_only(self, compositor):
        frame = self._frame(compositor, (320, 240), self._view(), 0.1778)
        l = warning_layout_for(320, 240, buttons=2, metrics=metrics_for(320, 240, 0.1778))
        (divider_x,) = l.divider_xs
        for x in (l.card[0] + 1, divider_x, l.card[2] - 2):
            assert frame.getpixel((x, l.divider_y)) == (255, 255, 255)
        assert frame.getpixel((divider_x, l.cells[0][1] + 5)) == (255, 255, 255)
        assert frame.getpixel((divider_x, l.card[3] - 2)) == (255, 255, 255)
        # No vertical line through the message row (clear of the text:
        # sample near the row's top-left).
        assert frame.getpixel((divider_x, l.message[1] + 4)) == LIST_BG_RGB

    def test_pressed_cell_washes_only_itself(self, compositor):
        plain = self._frame(compositor, (320, 240), self._view(), 0.1778)
        pressed = self._frame(compositor, (320, 240), self._view(pressed=0), 0.1778)
        l = warning_layout_for(320, 240, buttons=2, metrics=metrics_for(320, 240, 0.1778))
        first, second = l.cells
        assert pressed.getpixel((first[0] + 3, first[1] + 3))[0] > LIST_BG_RGB[0]
        assert plain.getpixel((first[0] + 3, first[1] + 3)) == LIST_BG_RGB
        assert pressed.getpixel((second[0] + 3, second[1] + 3)) == LIST_BG_RGB
        assert list(pressed.crop(l.message).getdata()) == list(plain.crop(l.message).getdata())

    @pytest.mark.parametrize("stale", [2, 7, -1])
    def test_a_cell_the_card_does_not_have_washes_nothing(self, compositor, stale):
        a = self._frame(compositor, (160, 128), self._view())
        b = self._frame(compositor, (160, 128), self._view(pressed=stale))
        assert list(a.getdata()) == list(b.getdata())

    def test_compact_is_full_screen_two_by_two(self, compositor):
        frame = self._frame(compositor, (240, 240), self._view(), 0.0973)
        assert frame.getpixel((2, 2)) == LIST_BG_RGB
        l = warning_layout_for(240, 240, buttons=2, metrics=metrics_for(240, 240, 0.0973))
        assert (l.cells, l.divider_xs, l.divider_y) == (((0, 164, 114, 240), (126, 164, 240, 240)), (120,), 158)
        assert frame.getpixel((5, 158)) == (255, 255, 255)              # horizontal, full width
        assert frame.getpixel((120, 200)) == (255, 255, 255)            # vertical, bottom row
        assert frame.getpixel((120, 8)) == LIST_BG_RGB                  # none in the top row

    def test_compact_pressed_second_cell_washes_its_cell(self, compositor):
        plain = self._frame(compositor, (240, 240), self._view(), 0.0973)
        pressed = self._frame(compositor, (240, 240), self._view(pressed=1), 0.0973)
        assert pressed.getpixel((130, 200))[0] > plain.getpixel((130, 200))[0]
        assert pressed.getpixel((5, 200)) == plain.getpixel((5, 200))

    def test_one_cell_spans_the_whole_row_with_no_vertical_line(self, compositor):
        view = WarningView(title="microSD card", message="15% life left, replace soon", buttons=("Close",))
        frame = self._frame(compositor, (320, 240), view, 0.1778)
        l = warning_layout_for(320, 240, buttons=1, metrics=metrics_for(320, 240, 0.1778))
        assert l.divider_xs == ()
        for x in range(l.cells[0][0] + 4, l.cells[0][2] - 4, 7):
            assert frame.getpixel((x, l.cells[0][3] - 6)) == LIST_BG_RGB

    def test_rotate_and_bgr_applied(self, compositor):
        plain = self._frame(compositor, (160, 128), self._view())
        rotated = self._frame(compositor, (160, 128), self._view(), rotate=True)
        assert list(rotated.getdata()) == list(plain.transpose(Image.ROTATE_180).getdata())
        swapped = self._frame(compositor, (160, 128), self._view(), bgr=True)
        assert list(swapped.getdata()) == list(Image.merge("RGB", plain.split()[::-1]).getdata())

    def test_never_raises_without_a_font(self, compositor):
        with patch("dial_display_render._load_font", return_value=None):
            frame = self._frame(compositor, (160, 128), self._view())
        assert frame.size == (160, 128)


# ---------------------------------------------------------------------------
# compose_warning: the generic card: any number of buttons, an optional
# progress bar and source line.
# ---------------------------------------------------------------------------

class TestComposeWarning:
    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    def test_three_buttons_draw_two_vertical_dividers(self, compositor):
        metrics = metrics_for(320, 240, 0.1778)
        frame = compositor.compose_warning(
            320, 240,
            WarningView(title="Three", buttons=("A", "B", "C")),
            rotate=False, bgr=False, metrics=metrics,
        )
        layout = warning_layout_for(320, 240, buttons=3, metrics=metrics)
        for x in layout.divider_xs:
            assert frame.getpixel((x, layout.cells[0][1] + 5)) == (255, 255, 255)
            assert frame.getpixel((x, layout.message[1] + 4)) != (255, 255, 255)

    def test_never_raises_without_a_font(self, compositor):
        with patch("dial_display_render._load_font", return_value=None):
            frame = compositor.compose_warning(
                160, 128,
                WarningView(title="Hi", buttons=("Close",)),
                rotate=False, bgr=False,
            )
        assert frame.size == (160, 128)

    def test_body_buttons_default_is_empty_and_frame_unchanged(self):
        assert Body() == Body(buttons=())


# ---------------------------------------------------------------------------
# The warning bell off the idle screen: in the top band (main, repeat, EQ), in
# the compact dots quadrant, and on a dark disc on resting artwork.
# ---------------------------------------------------------------------------

_BELL = BellBadge("warning", 2)


def _diff_box(a, b):
    return ImageChops.difference(a.convert("RGB"), b.convert("RGB")).getbbox()


class TestBellInTheBand:
    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        _reset_render_caches()
        yield
        _reset_font_cache()

    def _overlay(self, **kw):
        return OverlayState(visible=True, name="Turntable", volume=40, **kw)

    def _frame(self, compositor, overlay, size=(320, 240), mm=0.1778):
        base = Image.new("RGB", size, (90, 120, 140))
        return compositor.compose(
            base, *size, rotate=False, bgr=False, is_artwork=False, overlay=overlay,
            metrics=metrics_for(*size, mm))

    def test_the_bell_is_drawn_in_its_rect_and_the_name_is_drawn_shorter(self, compositor):
        metrics = metrics_for(320, 240, 0.1778)
        layout = layout_for(320, 240, metrics=metrics)
        bell = band_bell_rect(layout.name, metrics.band_h)
        plain = self._frame(compositor, self._overlay())
        belled = self._frame(compositor, self._overlay(bell=_BELL))
        box = _diff_box(plain, belled)
        assert box is not None
        assert box[0] >= layout.name[0] and box[2] <= layout.name[2] and box[3] <= metrics.band_h
        # Nothing outside the name zone moved: the dots, the volume and the bodies are as before.
        for rect in (layout.dots, layout.volume_cluster, (0, metrics.band_h, 320, 240)):
            assert list(plain.crop(rect).getdata()) == list(belled.crop(rect).getdata())
        assert list(belled.crop(bell).getdata()) != list(plain.crop(bell).getdata())

    def test_no_bell_is_byte_identical_to_before(self, compositor):
        a = self._frame(compositor, self._overlay(bell=None))
        b = self._frame(compositor, self._overlay())
        assert a.tobytes() == b.tobytes()

    @pytest.mark.parametrize("size,mm", [((160, 128), None), ((320, 240), 0.1778)])
    def test_the_bell_shows_on_the_repeat_and_eq_screens_too(self, compositor, size, mm):
        metrics = metrics_for(*size, mm) if mm else None
        for compose, state in (
            (compositor.compose_repeat, RepeatViewState(
                name="Turntable", layout="enable", armed=False, line="", start_enabled=False,
                stop_enabled=False, stop_pressed=False, volume=40)),
            (compositor.compose_eq, EqViewState(name="Turntable", bass_db=0, treble_db=0, loaded=True, volume=40)),
        ):
            plain = compose(*size, state, rotate=False, bgr=False, metrics=metrics)
            belled = compose(*size, dataclasses.replace(state, bell=_BELL), rotate=False, bgr=False, metrics=metrics)
            bell = band_bell_rect(layout_for(*size, metrics=metrics_for(*size, mm) if mm else metrics_for(*size)).name,
                                  (metrics or metrics_for(*size)).band_h)
            assert list(plain.crop(bell).getdata()) != list(belled.crop(bell).getdata())

    def test_the_bell_slides_with_the_top_band_during_a_reveal(self, compositor):
        base = Image.new("RGB", (320, 240), (90, 120, 140))
        metrics = metrics_for(320, 240, 0.1778)
        a = compositor.compose(base, 320, 240, rotate=False, bgr=False, is_artwork=False,
                               overlay=self._overlay(bell=_BELL), metrics=metrics, reveal_progress=0.5)
        b = compositor.compose(base, 320, 240, rotate=False, bgr=False, is_artwork=False,
                               overlay=self._overlay(), metrics=metrics, reveal_progress=0.5)
        assert a.tobytes() != b.tobytes()


class TestBellInTheCompactDotsQuadrant:
    def test_the_bell_is_drawn_right_of_the_dots_and_nothing_else_changes(self, compositor):
        metrics = metrics_for(240, 240, 0.0973)
        base = Image.new("RGB", (240, 240), (90, 120, 140))
        c = compact_layout_for(240, 240, metrics=metrics)
        zone = dots_bell_rect(c.tl)

        def frame(bell):
            return compositor.compose(
                base, 240, 240, rotate=False, bgr=False, is_artwork=False, metrics=metrics,
                overlay=OverlayState(visible=True, dots=True, bell=bell))

        plain, belled = frame(None), frame(_BELL)
        box = _diff_box(plain, belled)
        assert box is not None
        assert box[0] >= zone[0] and box[2] <= zone[2] and box[1] >= zone[1] and box[3] <= zone[3]


class TestBellOnRestingArtwork:
    def _compose(self, compositor, overlay, size=(160, 128), mm=None, **kw):
        base = Image.new("RGB", size, (90, 120, 140))
        metrics = metrics_for(*size, mm) if mm else metrics_for(*size)
        return base, compositor.compose(
            base, *size, rotate=False, bgr=False, is_artwork=False, overlay=overlay, metrics=metrics, **kw), metrics

    @pytest.mark.parametrize("overlay", [None, OverlayState(), OverlayState(visible=False)])
    def test_with_no_bell_the_frame_is_the_bare_base_itself(self, compositor, overlay):
        base, frame, _ = self._compose(compositor, overlay)
        assert frame is base

    @pytest.mark.parametrize("size,mm", [((160, 128), None), ((320, 240), 0.1778), ((240, 240), 0.0973)])
    def test_a_bell_adds_a_disc_only_in_the_corner_square(self, compositor, size, mm):
        base, frame, metrics = self._compose(compositor, OverlayState(bell=_BELL), size, mm)
        corner = idle_layout_for(*size, metrics=metrics).info
        box = _diff_box(base, frame)
        assert box is not None
        assert box[0] >= corner[0] and box[1] >= corner[1] and box[2] <= corner[2] and box[3] <= corner[3]

    def test_the_disc_darkens_the_artwork_under_the_bell(self, compositor):
        base, frame, metrics = self._compose(compositor, OverlayState(bell=_BELL), (320, 240), 0.1778)
        x0, y0, x1, y1 = idle_layout_for(320, 240, metrics=metrics).info
        px = frame.getpixel((x0 + 3, (y0 + y1) // 2))        # inside the disc, left of the bell
        assert sum(px) < sum(base.getpixel((x0 + 3, (y0 + y1) // 2)))

    def test_a_finished_reveal_is_the_resting_frame_with_the_bell(self, compositor):
        base, resting, _ = self._compose(compositor, OverlayState(bell=_BELL))
        _, done, _ = self._compose(compositor, OverlayState(visible=True, bell=_BELL), reveal_progress=1.0)
        assert resting.tobytes() == done.tobytes()

    def test_the_input_image_is_never_drawn_on(self, compositor):
        base = Image.new("RGB", (160, 128), (90, 120, 140))
        before = base.tobytes()
        compositor.compose(base, 160, 128, rotate=False, bgr=False, is_artwork=False, overlay=OverlayState(bell=_BELL))
        assert base.tobytes() == before


# ---------------------------------------------------------------------------
# compose_restarting — the "Restarting..." screen: flat chassis, centred text.
# ---------------------------------------------------------------------------

class TestComposeRestarting:
    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_flat_chassis_with_centred_text(self, compositor, width, height):
        frame = compositor.compose_restarting(width, height, rotate=False, bgr=False)
        for xy in ((0, 0), (width - 1, 0), (0, height - 1), (width - 1, height - 1)):
            assert frame.getpixel(xy) == LIST_BG_RGB
        row = [frame.getpixel((x, height // 2)) for x in range(width)]
        ink_x = [x for x, p in enumerate(row) if p != LIST_BG_RGB]
        assert ink_x
        # The ink's own bounding box is centred on the panel — a per-column
        # ink-count comparison would be thrown off by "Restarting..." itself
        # being visually denser at the start (solid letters) than the end
        # (three dots), which is a property of the string, not of centring.
        bbox_mid = (min(ink_x) + max(ink_x)) / 2
        assert abs(bbox_mid - width / 2) <= max(6, width * 0.08)

    def test_font_failure_leaves_the_flat_fill(self, compositor):
        with patch("dial_display_render._load_font", return_value=None):
            frame = compositor.compose_restarting(160, 128, rotate=False, bgr=False)
        assert set(frame.getdata()) == {LIST_BG_RGB}


# ---------------------------------------------------------------------------
# compose_starting — the boot splash: the restart screen's chassis and centred
# label with its own text.
# ---------------------------------------------------------------------------

class TestComposeStarting:
    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_flat_chassis_with_centred_text(self, compositor, width, height):
        frame = compositor.compose_starting(width, height, rotate=False, bgr=False)
        for xy in ((0, 0), (width - 1, 0), (0, height - 1), (width - 1, height - 1)):
            assert frame.getpixel(xy) == LIST_BG_RGB
        row = [frame.getpixel((x, height // 2)) for x in range(width)]
        ink_x = [x for x, p in enumerate(row) if p != LIST_BG_RGB]
        assert ink_x
        bbox_mid = (min(ink_x) + max(ink_x)) / 2
        assert abs(bbox_mid - width / 2) <= max(6, width * 0.08)

    def test_font_failure_leaves_the_flat_fill(self, compositor):
        with patch("dial_display_render._load_font", return_value=None):
            frame = compositor.compose_starting(160, 128, rotate=False, bgr=False)
        assert set(frame.getdata()) == {LIST_BG_RGB}

    def test_differs_from_restarting_only_by_its_text(self, compositor):
        starting = compositor.compose_starting(160, 128, rotate=False, bgr=False)
        restarting = compositor.compose_restarting(160, 128, rotate=False, bgr=False)
        assert list(starting.getdata()) != list(restarting.getdata())
        assert STARTING_TEXT != RESTARTING_TEXT

    def test_restarting_is_byte_identical_to_the_shared_centred_label(self, compositor):
        # The refactor onto one shared helper must not move a pixel of the
        # restart screen.
        via_helper = compositor._compose_centred_label(
            160, 128, RESTARTING_TEXT, rotate=False, bgr=False, metrics=None,
        )
        assert list(via_helper.getdata()) == \
            list(compositor.compose_restarting(160, 128, rotate=False, bgr=False).getdata())

    def test_rotate_and_bgr_apply_like_every_other_screen(self, compositor):
        # Same convention the compose() rotate/bgr tests near lines 211-252
        # pin: rotate is a 180-degree transpose, bgr a channel reversal.
        plain = compositor.compose_starting(160, 128, rotate=False, bgr=False)
        rotated = compositor.compose_starting(160, 128, rotate=True, bgr=False)
        assert list(rotated.getdata()) == list(plain.transpose(Image.ROTATE_180).getdata())
        swapped = compositor.compose_starting(160, 128, rotate=False, bgr=True)
        assert list(swapped.getdata()) == list(Image.merge("RGB", plain.split()[::-1]).getdata())


# ---------------------------------------------------------------------------
# OverlayState.dots — the main overlay's own pager dots.
# ---------------------------------------------------------------------------

class TestOverlayDots:
    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    def test_dots_false_is_default_and_a_no_op(self, compositor):
        assert OverlayState().dots is False
        base = _marked_image(size=(160, 128))
        without = compositor.compose(base, 160, 128, rotate=False, bgr=False, is_artwork=False,
                                      overlay=OverlayState(visible=True, dots=False))
        plain = compositor.compose(base, 160, 128, rotate=False, bgr=False, is_artwork=False,
                                    overlay=OverlayState(visible=True))
        assert list(without.getdata()) == list(plain.getdata())

    def test_dots_true_draws_in_dots_rect_only(self, compositor):
        layout = layout_for(160, 128)
        base = _marked_image(size=(160, 128))
        without = compositor.compose(base, 160, 128, rotate=False, bgr=False, is_artwork=False,
                                      overlay=OverlayState(visible=True, dots=False))
        with_dots = compositor.compose(base, 160, 128, rotate=False, bgr=False, is_artwork=False,
                                        overlay=OverlayState(visible=True, dots=True))
        assert list(without.crop(layout.dots).getdata()) != list(with_dots.crop(layout.dots).getdata())
        # The name rect (immediately to the right) is untouched by the dots
        # flag alone.
        assert list(without.crop(layout.name).getdata()) == list(with_dots.crop(layout.name).getdata())

    def test_dots_not_drawn_when_overlay_invisible(self, compositor):
        base = _marked_image(size=(160, 128))
        result = compositor.compose(base, 160, 128, rotate=False, bgr=False, is_artwork=False,
                                     overlay=OverlayState(visible=False, dots=True))
        assert list(result.getdata()) == list(base.getdata())


class TestRailFooterRendering:
    """The right-rail footer (FOOTER_LIST_RAIL), exercised through
    compose_list() with rich metrics at the shipped 320x240 density."""

    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    @staticmethod
    def _rows():
        return (("CD Player", True), ("Kitchen", False), ("Study", False), ("Lounge", False))

    def test_never_raises_and_returns_panel_sized_frame(self, compositor):
        result = compositor.compose_list(
            320, 240, ListState(rows=self._rows()), rotate=False, bgr=False, metrics=_RICH_METRICS,
        )
        assert result.size == (320, 240)

    def test_separator_column_is_drawn_left_of_the_rail(self, compositor):
        from dial_display_palette import LIST_SEPARATOR_RGB
        layout = list_layout_for(320, 240, metrics=_RICH_METRICS)
        result = compositor.compose_list(
            320, 240, ListState(rows=self._rows()), rotate=False, bgr=False, metrics=_RICH_METRICS,
        )
        assert result.getpixel((layout.rail[0] - 1, 10)) == LIST_SEPARATOR_RGB

    def test_rail_column_is_dimmed_relative_to_the_chassis(self, compositor):
        layout = list_layout_for(320, 240, metrics=_RICH_METRICS)
        result = compositor.compose_list(
            320, 240, ListState(rows=()), rotate=False, bgr=False, metrics=_RICH_METRICS,
        )
        # The rail sits over the same flat chassis fill as the rest of the
        # panel; dimming it must make it read darker than an untouched
        # chassis pixel elsewhere on the frame.
        chassis_pixel = result.getpixel((5, 5))
        rail_pixel = result.getpixel((layout.rail[2] - 2, layout.rail[1] + 2))
        assert sum(rail_pixel) < sum(chassis_pixel)

    def test_paging_state_only_affects_its_own_chevron(self, compositor):
        layout = list_layout_for(320, 240, metrics=_RICH_METRICS)
        neither = compositor.compose_list(
            320, 240, ListState(rows=self._rows(), has_prev=False, has_next=False),
            rotate=False, bgr=False, metrics=_RICH_METRICS,
        )
        both = compositor.compose_list(
            320, 240, ListState(rows=self._rows(), has_prev=True, has_next=True),
            rotate=False, bgr=False, metrics=_RICH_METRICS,
        )
        assert list(neither.crop(layout.rail_up).getdata()) != list(both.crop(layout.rail_up).getdata())
        assert list(neither.crop(layout.rail_down).getdata()) != list(both.crop(layout.rail_down).getdata())
        # The cross (back/cancel) is always lit, regardless of paging state.
        assert list(neither.crop(layout.rail_cancel).getdata()) == list(both.crop(layout.rail_cancel).getdata())

    def test_rail_glyphs_do_not_bleed_past_the_separator(self, compositor):
        # A rail glyph's drawing must be confined to its own rect — the
        # separator column and everything left of it (the row area) must be
        # unaffected by the paging state, which only ever touches the rail.
        layout = list_layout_for(320, 240, metrics=_RICH_METRICS)
        neither = compositor.compose_list(
            320, 240, ListState(rows=self._rows(), has_prev=False, has_next=False),
            rotate=False, bgr=False, metrics=_RICH_METRICS,
        )
        both = compositor.compose_list(
            320, 240, ListState(rows=self._rows(), has_prev=True, has_next=True),
            rotate=False, bgr=False, metrics=_RICH_METRICS,
        )
        rows_region = (0, 0, layout.rail[0] - 1, 240)
        assert list(neither.crop(rows_region).getdata()) == list(both.crop(rows_region).getdata())


class TestRailPressedWash:
    """Pressed-zone wash on the rail follows the zone table exactly — a
    LIST_BACK press washes rail_cancel, not a bottom-bar rect (there is
    none on this tier), and a row index washes its own row only."""

    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    @staticmethod
    def _rows():
        return (("CD Player", True), ("Kitchen", False), ("Study", False), ("Lounge", False))

    def test_list_back_washes_rail_cancel_only(self, compositor):
        layout = list_layout_for(320, 240, metrics=_RICH_METRICS)
        unpressed = compositor.compose_list(
            320, 240, ListState(rows=self._rows()), rotate=False, bgr=False, metrics=_RICH_METRICS,
        )
        pressed = compositor.compose_list(
            320, 240, ListState(rows=self._rows(), pressed=(TouchZone.LIST_BACK, None)),
            rotate=False, bgr=False, metrics=_RICH_METRICS,
        )
        assert list(unpressed.crop(layout.rail_cancel).getdata()) != list(pressed.crop(layout.rail_cancel).getdata())
        for rect in (layout.rail_up, layout.rail_down):
            assert list(unpressed.crop(rect).getdata()) == list(pressed.crop(rect).getdata())

    def test_pressed_row_washes_only_that_row(self, compositor):
        layout = list_layout_for(320, 240, metrics=_RICH_METRICS)
        unpressed = compositor.compose_list(
            320, 240, ListState(rows=self._rows()), rotate=False, bgr=False, metrics=_RICH_METRICS,
        )
        pressed = compositor.compose_list(
            320, 240, ListState(rows=self._rows(), pressed=(TouchZone.LIST_ROW, 3)),
            rotate=False, bgr=False, metrics=_RICH_METRICS,
        )
        assert list(unpressed.crop(layout.rows[3]).getdata()) != list(pressed.crop(layout.rows[3]).getdata())
        for i in range(3):
            assert list(unpressed.crop(layout.rows[i]).getdata()) == list(pressed.crop(layout.rows[i]).getdata())

    def test_stale_row_index_washes_nothing_and_never_raises(self, compositor):
        result = compositor.compose_list(
            320, 240, ListState(rows=self._rows(), pressed=(TouchZone.LIST_ROW, 99)),
            rotate=False, bgr=False, metrics=_RICH_METRICS,
        )
        assert result.size == (320, 240)


# ---------------------------------------------------------------------------
# The large content tier's now-playing body: the album line above the title,
# and the fonts/icon/halo caps that keep a large panel legible rather than
# merely bigger. Base and rich unaffected by construction — proved above
# (test_dial_display_compositor.TestMetricsByteEquivalence's album-ignored
# pins and test_dial_display_draw.TestHaloLayerCacheAccounting's unchanged
# two-miss count at 160x128).
# ---------------------------------------------------------------------------

_LARGE_PREVIEW_METRICS = metrics_for(640, 480, 0.0889, size_chosen=True)


class TestLargeAlbumLine:
    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    def _panel(self, metrics):
        return Image.new("RGB", (metrics.width, metrics.height), (200, 150, 100))

    def _compose(self, compositor, metrics, img, **overlay_kwargs):
        state = dict(visible=True, artist="Artist", title="Title")
        state.update(overlay_kwargs)
        return compositor.compose(
            img, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(**state), metrics=metrics,
        )

    @pytest.mark.parametrize("metrics", [_LARGE_METRICS, _LARGE_PREVIEW_METRICS], ids=["native", "preview"])
    def test_album_pixels_confined_to_its_own_rect(self, compositor, metrics):
        img = self._panel(metrics)
        layout = layout_for(metrics.width, metrics.height, metrics=metrics)
        with_album = self._compose(compositor, metrics, img, album="Album")
        without_album = self._compose(compositor, metrics, img, album="")
        bbox = _diff_bbox(with_album, without_album)
        assert bbox is not None
        ax0, ay0, ax1, ay1 = layout.album
        bx0, by0, bx1, by1 = bbox
        # The halo layer is composited on a rect-sized buffer and pasted
        # back into the rect only, so every changed pixel is contained in
        # it, exactly like the artist and title lines beside it.
        assert ax0 <= bx0 and bx1 <= ax1
        assert ay0 <= by0 and by1 <= ay1

    def test_empty_album_leaves_the_rect_untouched(self, compositor):
        metrics = _LARGE_METRICS
        img = self._panel(metrics)
        layout = layout_for(metrics.width, metrics.height, metrics=metrics)
        no_album = self._compose(compositor, metrics, img, album="")
        baseline = compositor.compose(
            img, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True), metrics=metrics,
        )
        assert list(no_album.crop(layout.album).getdata()) == list(baseline.crop(layout.album).getdata())

    def test_long_album_truncates_with_an_ellipsis(self):
        # The album line shares _truncate_to_width with every other halo-
        # drawn line — check it actually shortens a too-long album string
        # for the album rect's own width at the capped 36px font, the same
        # way it already does for artist/title.
        from PIL import ImageDraw

        metrics = _LARGE_METRICS
        layout = layout_for(metrics.width, metrics.height, metrics=metrics)
        long_album = "A Very Long Album Name Indeed Of Considerable Length" * 3
        img = Image.new("RGB", (metrics.width, metrics.height))
        draw = ImageDraw.Draw(img)
        font = _load_font(metrics.font_body)
        max_w = layout.album[2] - layout.album[0] - metrics.pad
        truncated = _truncate_to_width(draw, long_album, font, max_w)
        assert len(truncated) < len(long_album)
        assert truncated.endswith("...")

    def test_long_album_stays_within_the_rect_on_the_frame(self, compositor):
        metrics = _LARGE_METRICS
        img = self._panel(metrics)
        layout = layout_for(metrics.width, metrics.height, metrics=metrics)
        long_album = "A Very Long Album Name Indeed Of Considerable Length" * 3
        with_album = self._compose(compositor, metrics, img, album=long_album)
        without_album = self._compose(compositor, metrics, img, album="")
        bbox = _diff_bbox(with_album, without_album)
        assert bbox is not None
        assert layout.album[0] <= bbox[0] and bbox[2] <= layout.album[2]


class TestLargeFontCaps:
    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    def test_load_font_called_with_capped_body_and_readout_sizes(self, compositor):
        metrics = _LARGE_METRICS
        img = Image.new("RGB", (metrics.width, metrics.height), (200, 150, 100))
        with patch("dial_display_render._load_font", wraps=_load_font) as spy:
            compositor.compose(
                img, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
                overlay=OverlayState(visible=True, artist="Artist", title="Title", album="Album", volume=42),
                metrics=metrics,
            )
        sizes = {call.args[0] for call in spy.call_args_list}
        assert FONT_BODY_MAX_PX in sizes
        assert FONT_READOUT_MAX_PX in sizes
        # At this panel's own short side the reference formula's uncapped
        # value already equals the cap, so there is no larger uncapped size
        # to rule out here — see test_title_glyph_is_narrower_than_the_
        # uncapped_scaled_size below for a panel where the cap actually bites.

    def test_title_glyph_is_narrower_than_the_uncapped_scaled_size(self, compositor):
        # Compare the real (capped) metrics against what this same panel
        # would have resolved to without the cap — a direct A/B rather than
        # a magic pixel threshold. The title rect is far wider than either
        # rendering of "Title" needs, so — unlike its height, which the
        # halo's rect-sized canvas always fills — glyph WIDTH is a clean
        # measure of the font actually used. A panel bigger than the native
        # large panel is used here (rather than _LARGE_METRICS) because at
        # the native panel's own short side the reference formula's
        # uncapped value already equals the cap — there is nothing left for
        # the cap to do there.
        width, height, mm = 960, 960, 0.06
        metrics = metrics_for(width, height, mm)
        assert metrics.content_tier == CONTENT_LARGE
        with patch("dial_layout_metrics.FONT_BODY_MAX_PX", 999):
            uncapped_metrics = metrics_for(width, height, mm)
        assert uncapped_metrics.font_body == 72  # round(960*36/480), uncapped
        assert metrics.font_body == 36

        img = Image.new("RGB", (width, height), (200, 150, 100))
        layout = layout_for(width, height, metrics=metrics)

        def glyph_width(m):
            with_title = compositor.compose(
                img, m.width, m.height, rotate=False, bgr=False, is_artwork=False,
                overlay=OverlayState(visible=True, title="Title"), metrics=m,
            )
            without_title = compositor.compose(
                img, m.width, m.height, rotate=False, bgr=False, is_artwork=False,
                overlay=OverlayState(visible=True, title=""), metrics=m,
            )
            bbox = _diff_bbox(with_title.crop(layout.title), without_title.crop(layout.title))
            assert bbox is not None
            return bbox[2] - bbox[0]

        assert glyph_width(metrics) < glyph_width(uncapped_metrics)

    def test_speaker_icon_box_is_capped(self, compositor):
        """The header's own readout glyph: the GLYPH_SPEAKER tile's box. The
        footer's mute cell is a separate GLYPH_MUTE tile at that cell's own
        size, which has nothing to do with this cap."""
        metrics = _LARGE_METRICS
        img = Image.new("RGB", (metrics.width, metrics.height), (200, 150, 100))
        with patch("dial_display_render._draw_glyph", wraps=dial_display_draw._draw_glyph) as spy:
            compositor.compose(
                img, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
                overlay=OverlayState(visible=True, volume=42), metrics=metrics,
            )
        speaker = [c for c in spy.call_args_list if c.args[2] == GLYPH_SPEAKER]
        assert len(speaker) == 1
        box = speaker[0].args[1]
        assert box[2] - box[0] == metrics.icon == FONT_READOUT_MAX_PX
        assert speaker[0].kwargs["supersample"] == metrics.supersample

    @pytest.mark.parametrize("metrics", [_RICH_METRICS, _LARGE_METRICS])
    def test_speaker_icon_is_antialiased(self, compositor, metrics):
        """Drawn through the supersampled tile, the icon has intermediate
        levels between the background and the glyph colour, not just the
        two."""
        img = Image.new("RGB", (metrics.width, metrics.height), (0, 0, 0))
        out = compositor.compose(
            img, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True), metrics=metrics,
        )
        rect = layout_for(metrics.width, metrics.height, metrics=metrics).volume_cluster
        levels = {px[0] for px in out.crop(rect).getdata()}
        assert len(levels) > 4


class TestLargeNeverRaises:
    @pytest.fixture(autouse=True)
    def _reset(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    def test_no_font_available_still_composes_a_full_frame(self, compositor):
        metrics = _LARGE_METRICS
        img = Image.new("RGB", (metrics.width, metrics.height), (200, 150, 100))
        with patch("dial_display_draw.ImageFont.truetype", side_effect=OSError("no font")), \
             patch("dial_display_draw.ImageFont.load_default", side_effect=OSError("no default")):
            result = compositor.compose(
                img, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
                overlay=OverlayState(visible=True, artist="Artist", title="Title", album="Album"),
                metrics=metrics,
            )
        assert result.size == (metrics.width, metrics.height)

    def test_halo_failure_still_draws_plain_album_text(self, compositor):
        metrics = _LARGE_METRICS
        img = Image.new("RGB", (metrics.width, metrics.height), (200, 150, 100))
        layout = layout_for(metrics.width, metrics.height, metrics=metrics)
        with patch("dial_display_draw.ImageFilter.GaussianBlur", side_effect=RuntimeError("boom")):
            with_album = compositor.compose(
                img, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
                overlay=OverlayState(visible=True, album="Album"), metrics=metrics,
            )
        baseline_blank = compositor.compose(
            img, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, album=""), metrics=metrics,
        )
        assert list(with_album.crop(layout.album).getdata()) != list(baseline_blank.crop(layout.album).getdata())


class TestFooterVolumeMute:
    @pytest.mark.parametrize(
        "size,metrics",
        [((160, 128), None), ((320, 240), _RICH_METRICS), ((640, 480), _LARGE_METRICS)],
    )
    def test_three_thirds_each_carry_glyph_content(self, compositor, size, metrics):
        img = Image.new("RGB", size, (60, 60, 60))
        result = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True), metrics=metrics,
        )
        layout = layout_for(*size, metrics=metrics)
        for rect in (layout.footer_down, layout.footer_up, layout.footer_mute):
            assert _has_near_white_pixel(result.crop(rect))

    def test_footer_kind_is_volume_mute_on_the_main_screen(self):
        frame = _now_playing_frame(OverlayState(visible=True), 160, 128, metrics_for(160, 128))
        assert frame.footer.kind == FOOTER_VOLUME_MUTE

    @pytest.mark.parametrize(
        "size,metrics",
        [((160, 128), None), ((320, 240), _RICH_METRICS)],
    )
    def test_dividers_drawn_between_the_three_thirds(self, compositor, size, metrics):
        from dial_display_palette import DIVIDER_RGB
        img = Image.new("RGB", size, (60, 60, 60))
        result = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True), metrics=metrics,
        )
        layout = layout_for(*size, metrics=metrics)
        mid_y = (layout.bottom_band[1] + layout.bottom_band[3]) // 2
        for x in layout.footer_dividers:
            assert result.getpixel((x, mid_y)) == DIVIDER_RGB

    def test_thirds_sit_between_the_footer_dividers_in_order(self):
        """The order: minus (DOWN) left, plus (UP) middle, mute
        right — the reverse of a mute-in-the-middle layout."""
        layout = layout_for(320, 240, metrics=_RICH_METRICS)
        assert layout.footer_down[2] <= layout.footer_dividers[0]
        assert layout.footer_up[0] >= layout.footer_dividers[0]
        assert layout.footer_up[2] <= layout.footer_dividers[1]
        assert layout.footer_mute[0] >= layout.footer_dividers[1]


class TestPersistentMuteWash:
    def test_muted_true_washes_the_right_third_brighter_than_dimmed(self, compositor):
        size = (160, 128)
        img = Image.new("RGB", size, (60, 60, 60))
        layout = layout_for(*size)
        unmuted = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, muted=False),
        )
        muted = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, muted=True),
        )
        # Sample a corner of the mute cell, away from the glyph itself, so
        # the comparison isolates the wash rather than the glyph stroke.
        x0, y0, x1, y1 = layout.footer_mute
        corner = (x0 + 1, y1 - 2)
        assert sum(muted.getpixel(corner)) > sum(unmuted.getpixel(corner))

    def test_unmuted_mute_cell_corner_matches_the_plain_dimmed_band(self, compositor):
        size = (160, 128)
        img = Image.new("RGB", size, (60, 60, 60))
        layout = layout_for(*size)
        unmuted = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, muted=False),
        )
        mute_corner = (layout.footer_mute[0] + 1, layout.footer_mute[3] - 2)
        down_corner = (layout.footer_down[0] + 1, layout.footer_down[3] - 2)
        assert unmuted.getpixel(mute_corner) == unmuted.getpixel(down_corner)

    def test_pressed_mute_adds_a_wash_on_top_of_the_persistent_one(self, compositor):
        size = (160, 128)
        img = Image.new("RGB", size, (60, 60, 60))
        layout = layout_for(*size)
        muted_unpressed = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, muted=True),
        )
        muted_pressed = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, muted=True, pressed=TouchZone.MUTE),
        )
        corner = (layout.footer_mute[0] + 1, layout.footer_mute[3] - 2)
        assert sum(muted_pressed.getpixel(corner)) > sum(muted_unpressed.getpixel(corner))

    def test_wash_confined_to_the_mute_third(self, compositor):
        size = (160, 128)
        img = Image.new("RGB", size, (60, 60, 60))
        layout = layout_for(*size)
        unmuted = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, muted=False),
        )
        muted = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, muted=True),
        )
        for rect in (layout.footer_down, layout.footer_up):
            assert list(unmuted.crop(rect).getdata()) == list(muted.crop(rect).getdata())

    def test_wash_is_red_and_clearly_visible_over_a_dimmed_mid_grey_base(self, compositor):
        """The faint grey wash this replaced all but vanished on a dim
        panel. At its see-through end the red still stands well clear of
        the dimmed band, and at its solid end it is the alert red itself."""
        size = (320, 240)
        img = Image.new("RGB", size, (150, 150, 150))
        layout = layout_for(*size, metrics=_RICH_METRICS)
        corner = (layout.footer_mute[0] + 1, layout.footer_mute[3] - 2)

        def frame(**fields):
            return compositor.compose(
                img, *size, rotate=False, bgr=False, is_artwork=False,
                overlay=OverlayState(visible=True, **fields), metrics=_RICH_METRICS,
            )

        plain = frame(muted=False).getpixel(corner)
        faint = frame(muted=True, pulse=0.0).getpixel(corner)
        assert frame(muted=True).getpixel(corner) == ALERT_RGB
        assert faint[0] - plain[0] >= 40 and faint[1] <= plain[1]

    def test_paused_shows_the_pause_sign_in_the_mute_cell_only(self, compositor):
        size = (320, 240)
        img = Image.new("RGB", size, (60, 60, 60))
        layout = layout_for(*size, metrics=_RICH_METRICS)

        def frame(**fields):
            return compositor.compose(
                img, *size, rotate=False, bgr=False, is_artwork=False,
                overlay=OverlayState(visible=True, **fields), metrics=_RICH_METRICS,
            )

        paused, muted = frame(paused=True), frame(muted=True)
        assert list(paused.crop(layout.footer_mute).getdata()) != list(muted.crop(layout.footer_mute).getdata())
        for rect in (layout.footer_down, layout.footer_up, layout.top_band):
            assert list(paused.crop(rect).getdata()) == list(muted.crop(rect).getdata())


class TestAlertPulse:
    """A pulse step blends the cell between its see-through and solid ends;
    nothing outside the cell ever differs, so only the cell is sent."""

    @pytest.fixture(autouse=True)
    def _clean(self):
        _reset_render_caches()
        yield
        _reset_render_caches()

    @pytest.fixture(params=["rich", "compact"])
    def setup(self, request):
        metrics = _RICH_METRICS if request.param == "rich" else _COMPACT_240
        size = (metrics.width, metrics.height)
        img = Image.effect_noise(size, 60).convert("RGB")
        if request.param == "rich":
            cell = layout_for(*size, metrics=metrics).footer_mute
        else:
            cell = compact_layout_for(*size, metrics=metrics).tr
        return metrics, size, img, cell

    def frame(self, compositor, setup, **fields):
        metrics, size, img, _cell = setup
        return compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, **fields), metrics=metrics,
        )

    def outside(self, image, cell):
        x0, y0, x1, y1 = cell
        masked = image.copy()
        masked.paste((0, 0, 0), (x0, y0, x1, y1))
        return masked.tobytes()

    def test_steps_differ_only_inside_the_cell(self, compositor, setup):
        cell = setup[3]
        frames = [self.frame(compositor, setup, muted=True, pulse=p) for p in (0.0, 0.3, 0.7, 1.0)]
        assert len({f.crop(cell).tobytes() for f in frames}) == 4
        assert len({self.outside(f, cell) for f in frames}) == 1

    def test_the_solid_end_is_the_frame_composed_directly(self, compositor, setup):
        stepped = self.frame(compositor, setup, muted=True, pulse=0.999)
        direct = self.frame(compositor, setup, muted=True)
        assert self.outside(stepped, setup[3]) == self.outside(direct, setup[3])
        assert self.frame(compositor, setup, muted=True, pulse=1.0).tobytes() == direct.tobytes()

    def test_the_see_through_end_is_fainter_red(self, compositor, setup):
        x0, y0, x1, y1 = setup[3]
        corner = (x0 + 2, y1 - 3)
        faint = self.frame(compositor, setup, muted=True, pulse=0.0).getpixel(corner)
        solid = self.frame(compositor, setup, muted=True, pulse=1.0).getpixel(corner)
        assert solid == ALERT_RGB and faint != solid

    def test_a_press_still_washes_over_the_pulse(self, compositor, setup):
        x0, y0, x1, y1 = setup[3]
        corner = (x0 + 2, y1 - 3)
        plain = self.frame(compositor, setup, muted=True, pulse=0.5).getpixel(corner)
        pressed = self.frame(compositor, setup, muted=True, pulse=0.5, pressed=TouchZone.MUTE).getpixel(corner)
        assert sum(pressed) > sum(plain)


class TestHeaderNeverSlashedRegardlessOfMuted:
    def test_main_screen_header_unaffected_by_muted(self, compositor):
        size = (160, 128)
        img = Image.new("RGB", size, (60, 60, 60))
        layout = layout_for(*size)
        unmuted = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, volume=42, muted=False),
        )
        muted = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, volume=42, muted=True),
        )
        assert list(unmuted.crop(layout.volume_cluster).getdata()) == list(
            muted.crop(layout.volume_cluster).getdata()
        )


# ---------------------------------------------------------------------------
# compose_output(): the per-output detail page.
# ---------------------------------------------------------------------------

def _output_state(**overrides) -> OutputViewState:
    base = dict(name="Kitchen", output_name="Bedroom", selected=True, level=40, pressed=None)
    base.update(overrides)
    return OutputViewState(**base)


class TestComposeOutput:
    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    @pytest.mark.parametrize(
        "size,metrics",
        [((160, 128), None), ((320, 240), _RICH_METRICS), ((640, 480), _LARGE_METRICS)],
    )
    def test_returns_panel_sized_frame(self, compositor, size, metrics):
        result = compositor.compose_output(
            *size, _output_state(), rotate=False, bgr=False, metrics=metrics,
        )
        assert result.size == size

    def test_back_chevron_drawn_where_the_dots_would_be(self, compositor):
        layout = layout_for(160, 128)
        with_back = compositor.compose_output(160, 128, _output_state(), rotate=False, bgr=False)
        no_dots = compositor.compose(
            Image.new("RGB", (160, 128), (60, 60, 60)), 160, 128,
            rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, dots=False),
        )
        assert list(with_back.crop(layout.dots).getdata()) != list(no_dots.crop(layout.dots).getdata())

    def test_output_name_drawn_in_the_toggle_row(self, compositor):
        layout = repeat_layout_for(160, 128)
        named = compositor.compose_output(
            160, 128, _output_state(output_name="Living Room"), rotate=False, bgr=False,
        )
        blank = compositor.compose_output(
            160, 128, _output_state(output_name=""), rotate=False, bgr=False,
        )
        assert list(named.crop(layout.row).getdata()) != list(blank.crop(layout.row).getdata())

    def test_dot_filled_iff_selected(self, compositor):
        layout = repeat_layout_for(160, 128)
        pad = metrics_for(160, 128).pad
        row = layout.row
        dot_box = row[3] - row[1]
        dot_rect = (row[2] - pad - dot_box, row[1], row[2] - pad, row[3])
        selected = compositor.compose_output(
            160, 128, _output_state(selected=True), rotate=False, bgr=False,
        )
        disabled = compositor.compose_output(
            160, 128, _output_state(selected=False), rotate=False, bgr=False,
        )
        assert list(selected.crop(dot_rect).getdata()) != list(disabled.crop(dot_rect).getdata())

    def test_minus_plus_footer_present_and_two_way(self, compositor):
        layout = layout_for(160, 128)
        unpressed = compositor.compose_output(160, 128, _output_state(), rotate=False, bgr=False)
        pressed_down = compositor.compose_output(
            160, 128, _output_state(pressed=TouchZone.OUTPUT_DOWN), rotate=False, bgr=False,
        )
        assert list(unpressed.crop(layout.down).getdata()) != list(pressed_down.crop(layout.down).getdata())
        assert list(unpressed.crop(layout.up).getdata()) == list(pressed_down.crop(layout.up).getdata())

    def test_readout_digits_present_for_a_level_and_absent_for_none(self, compositor):
        layout = layout_for(160, 128)
        with_level = compositor.compose_output(
            160, 128, _output_state(level=55), rotate=False, bgr=False,
        )
        no_level = compositor.compose_output(
            160, 128, _output_state(level=None), rotate=False, bgr=False,
        )
        assert list(with_level.crop(layout.volume_cluster).getdata()) != list(
            no_level.crop(layout.volume_cluster).getdata()
        )

    def test_pressed_zone_resolves_against_geometry_output(self, compositor):
        """A press reported for OUTPUT_TOGGLE (a zone that exists only on
        GEOMETRY_OUTPUT, never GEOMETRY_MAIN) must wash the toggle row,
        proving the pressed-rect lookup used GEOMETRY_OUTPUT rather than
        falling back to a geometry with no such entry (which would wash
        nothing at all — see _zone_rect degrading gracefully for an
        unrecognised zone)."""
        layout = repeat_layout_for(160, 128)
        unpressed = compositor.compose_output(160, 128, _output_state(), rotate=False, bgr=False)
        pressed = compositor.compose_output(
            160, 128, _output_state(pressed=TouchZone.OUTPUT_TOGGLE), rotate=False, bgr=False,
        )
        assert list(unpressed.crop(layout.row).getdata()) != list(pressed.crop(layout.row).getdata())

    def test_never_raises_with_no_font(self, compositor):
        with patch("dial_display_draw.ImageFont.truetype", side_effect=OSError("no font")), \
             patch("dial_display_draw.ImageFont.load_default", side_effect=OSError("no default")):
            result = compositor.compose_output(160, 128, _output_state(), rotate=False, bgr=False)
        assert result.size == (160, 128)

    def test_disabled_steppers_are_dimmed_not_white(self, compositor):
        """When the output is not selected, the minus/plus glyphs dim to
        the same shade the disabled Restart/Stop labels use, instead of
        staying full white."""
        layout = layout_for(160, 128)
        enabled = compositor.compose_output(160, 128, _output_state(selected=True), rotate=False, bgr=False)
        disabled = compositor.compose_output(160, 128, _output_state(selected=False), rotate=False, bgr=False)
        assert list(enabled.crop(layout.down).getdata()) != list(disabled.crop(layout.down).getdata())
        assert list(enabled.crop(layout.up).getdata()) != list(disabled.crop(layout.up).getdata())
        assert _has_near_white_pixel(enabled.crop(layout.down))
        assert not _has_near_white_pixel(disabled.crop(layout.down))
        assert _has_near_white_pixel(enabled.crop(layout.up))
        assert not _has_near_white_pixel(disabled.crop(layout.up))

    def test_disabled_stepper_press_washes_nothing(self, compositor):
        """A tap on a disabled stepper neither lights nor acts -- the zone
        table still carries OUTPUT_UP/OUTPUT_DOWN (they exist, they just do
        nothing and show nothing while disabled)."""
        unpressed = compositor.compose_output(160, 128, _output_state(selected=False), rotate=False, bgr=False)
        pressed_up = compositor.compose_output(
            160, 128, _output_state(selected=False, pressed=TouchZone.OUTPUT_UP), rotate=False, bgr=False,
        )
        pressed_down = compositor.compose_output(
            160, 128, _output_state(selected=False, pressed=TouchZone.OUTPUT_DOWN), rotate=False, bgr=False,
        )
        assert list(unpressed.getdata()) == list(pressed_up.getdata())
        assert list(unpressed.getdata()) == list(pressed_down.getdata())

    def test_enabled_stepper_press_still_washes(self, compositor):
        # Same press, but the output is selected -- the press wash still
        # applies, proving the previous test's absence is about the
        # disabled state and not a blanket loss of the press wash.
        layout = layout_for(160, 128)
        unpressed = compositor.compose_output(160, 128, _output_state(selected=True), rotate=False, bgr=False)
        pressed_up = compositor.compose_output(
            160, 128, _output_state(selected=True, pressed=TouchZone.OUTPUT_UP), rotate=False, bgr=False,
        )
        assert list(unpressed.crop(layout.up).getdata()) != list(pressed_up.crop(layout.up).getdata())

    def test_back_control_is_confined_to_a_small_centred_box(self, compositor):
        """Item 7b: the back control is an X drawn into a small centred box
        (the same size the rail's own cancel control uses), not a chevron
        stretched across the whole dots zone — a corner of the dots rect,
        outside that box, must be untouched chrome."""
        from dial_display_draw import _centred_box
        from dial_display_palette import OVERLAY_DIM_FACTOR, LIST_BG_RGB
        metrics = metrics_for(160, 128)
        layout = layout_for(160, 128, metrics=metrics)
        box = _centred_box(layout.dots, metrics.icon)
        corner = (layout.dots[0], layout.dots[1])
        assert corner[0] < box[0] and corner[1] < box[1]
        with_back = compositor.compose_output(160, 128, _output_state(), rotate=False, bgr=False)
        # compose_output's own chassis background, dimmed the same way the
        # top band always is — the plain, glyph-free corner colour.
        expected = tuple(round(c * OVERLAY_DIM_FACTOR) for c in LIST_BG_RGB)
        assert with_back.getpixel(corner) == expected


class TestHeaderDotsCount:
    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    def test_default_dots_count_is_two(self):
        assert Header().dots_count == 2

    def test_now_playing_frame_draws_two_dots_when_eq_pages_false(self, compositor):
        layout = layout_for(160, 128)
        two = compositor.compose(
            _marked_image(size=(160, 128)), 160, 128, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, dots=True, eq_pages=False),
        )
        three = compositor.compose(
            _marked_image(size=(160, 128)), 160, 128, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, dots=True, eq_pages=True),
        )
        assert list(two.crop(layout.dots).getdata()) != list(three.crop(layout.dots).getdata())

    def test_now_playing_frame_byte_identical_outside_dots_when_eq_pages_false(self, compositor):
        """eq_pages=False renders byte-identical to before this field
        existed, everywhere outside the dots box."""
        base = _marked_image(size=(160, 128))
        default = compositor.compose(
            base, 160, 128, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, dots=True, artist="X", volume=40),
        )
        explicit_false = compositor.compose(
            base, 160, 128, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, dots=True, artist="X", volume=40, eq_pages=False),
        )
        assert list(default.getdata()) == list(explicit_false.getdata())

    def test_repeat_frame_draws_three_dots_second_solid_when_eq_pages_true(self, compositor):
        layout = repeat_layout_for(320, 240, metrics=_RICH_METRICS)
        two = compositor.compose_repeat(
            320, 240, _repeat_state(eq_pages=False), rotate=False, bgr=False, metrics=_RICH_METRICS,
        )
        three = compositor.compose_repeat(
            320, 240, _repeat_state(eq_pages=True), rotate=False, bgr=False, metrics=_RICH_METRICS,
        )
        assert list(two.crop(layout.dots).getdata()) != list(three.crop(layout.dots).getdata())

    def test_repeat_frame_byte_identical_when_eq_pages_false(self, compositor):
        result_a = compositor.compose_repeat(
            320, 240, _repeat_state(armed=True, eq_pages=False), rotate=False, bgr=False, metrics=_RICH_METRICS,
        )
        result_b = compositor.compose_repeat(
            320, 240, _repeat_state(armed=True), rotate=False, bgr=False, metrics=_RICH_METRICS,
        )
        assert list(result_a.getdata()) == list(result_b.getdata())


# ---------------------------------------------------------------------------
# compose_eq() — the EQ page: chassis background, dimmed top band, three
# pager dots (third filled), bass/treble bars.
# ---------------------------------------------------------------------------

def _eq_state(**overrides) -> "EqViewState":
    base = dict(
        name="Kitchen", bass_db=0, treble_db=0, loaded=True,
        volume=None, pressed=None,
    )
    base.update(overrides)
    return EqViewState(**base)


class TestComposeEq:
    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        _reset_render_caches()
        yield
        _reset_font_cache()
        _reset_render_caches()

    @pytest.mark.parametrize("metrics", [_RICH_METRICS, _LARGE_METRICS])
    def test_returns_panel_sized_frame(self, compositor, metrics):
        result = compositor.compose_eq(
            metrics.width, metrics.height, _eq_state(), rotate=False, bgr=False, metrics=metrics,
        )
        assert result.size == (metrics.width, metrics.height)

    def test_third_dot_solid(self, compositor):
        layout = layout_for(320, 240, metrics=_RICH_METRICS)
        result = compositor.compose_eq(320, 240, _eq_state(), rotate=False, bgr=False, metrics=_RICH_METRICS)
        two_dots_frame = compositor.compose(
            _marked_image(size=(320, 240)), 320, 240, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, dots=True), metrics=_RICH_METRICS,
        )
        assert list(result.crop(layout.dots).getdata()) != list(two_dots_frame.crop(layout.dots).getdata())

    def test_top_band_is_dimmed(self, compositor):
        from dial_display_palette import LIST_BG_RGB
        result = compositor.compose_eq(320, 240, _eq_state(name=""), rotate=False, bgr=False, metrics=_RICH_METRICS)
        layout = layout_for(320, 240, metrics=_RICH_METRICS)
        corner = (layout.top_band[0], layout.top_band[1])
        expected = tuple(round(c * OVERLAY_DIM_FACTOR) for c in LIST_BG_RGB)
        assert result.getpixel(corner) == expected

    def test_labels_and_db_text_drawn_in_captions(self, compositor):
        layout = eq_layout_for(320, 240, metrics=_RICH_METRICS)
        blank = compositor.compose_eq(
            320, 240, _eq_state(bass_db=None, treble_db=None, loaded=False),
            rotate=False, bgr=False, metrics=_RICH_METRICS,
        )
        loaded = compositor.compose_eq(320, 240, _eq_state(bass_db=3, treble_db=-2), rotate=False, bgr=False, metrics=_RICH_METRICS)
        assert list(blank.crop(layout.bass.caption).getdata()) != list(loaded.crop(layout.bass.caption).getdata())
        assert list(blank.crop(layout.treble.caption).getdata()) != list(loaded.crop(layout.treble.caption).getdata())

    @pytest.mark.parametrize("value,expected_side", [(0, "centre"), (6, "right"), (-6, "left")])
    def test_marker_position_at_limits_and_centre(self, compositor, value, expected_side):
        layout = eq_layout_for(320, 240, metrics=_RICH_METRICS)
        bar = layout.bass
        result = compositor.compose_eq(
            320, 240, _eq_state(bass_db=value), rotate=False, bgr=False, metrics=_RICH_METRICS,
        )
        expected_x = {
            "centre": bar.centre_x, "right": bar.track_x1, "left": bar.track_x0,
        }[expected_side]
        # A white pixel should appear at (or immediately around) the expected
        # marker x on the track row.
        found = any(
            result.getpixel((x, bar.track_y)) == GLYPH_RGB
            for x in range(max(0, expected_x - 2), min(320, expected_x + 3))
        )
        assert found

    def test_fill_drawn_on_the_correct_side_of_centre(self, compositor):
        layout = eq_layout_for(320, 240, metrics=_RICH_METRICS)
        bar = layout.bass
        positive = compositor.compose_eq(
            320, 240, _eq_state(bass_db=6), rotate=False, bgr=False, metrics=_RICH_METRICS,
        )
        negative = compositor.compose_eq(
            320, 240, _eq_state(bass_db=-6), rotate=False, bgr=False, metrics=_RICH_METRICS,
        )
        right_of_centre = (bar.centre_x + 10, bar.track_y)
        left_of_centre = (bar.centre_x - 10, bar.track_y)
        assert positive.getpixel(right_of_centre) == GLYPH_RGB
        assert negative.getpixel(left_of_centre) == GLYPH_RGB

    def test_unloaded_shows_dash_and_dimmed_controls(self, compositor):
        layout = eq_layout_for(320, 240, metrics=_RICH_METRICS)
        result = compositor.compose_eq(
            320, 240, _eq_state(bass_db=None, treble_db=None, loaded=False),
            rotate=False, bgr=False, metrics=_RICH_METRICS,
        )
        # Controls dimmed, not white, while unloaded.
        assert not _has_near_white_pixel(result.crop(layout.bass.down))
        assert not _has_near_white_pixel(result.crop(layout.bass.up))
        assert not _has_near_white_pixel(result.crop(layout.treble.down))
        assert not _has_near_white_pixel(result.crop(layout.treble.up))

    def test_loaded_controls_are_white_away_from_the_limits(self, compositor):
        layout = eq_layout_for(320, 240, metrics=_RICH_METRICS)
        result = compositor.compose_eq(
            320, 240, _eq_state(bass_db=0, treble_db=0), rotate=False, bgr=False, metrics=_RICH_METRICS,
        )
        assert _has_near_white_pixel(result.crop(layout.bass.down))
        assert _has_near_white_pixel(result.crop(layout.bass.up))

    def test_minus_dimmed_at_minus_six_plus_dimmed_at_plus_six(self, compositor):
        layout = eq_layout_for(320, 240, metrics=_RICH_METRICS)
        at_min = compositor.compose_eq(
            320, 240, _eq_state(bass_db=-dial_eq_model.EQ_BASS_TREBLE_LIMIT_DB), rotate=False, bgr=False, metrics=_RICH_METRICS,
        )
        at_max = compositor.compose_eq(
            320, 240, _eq_state(bass_db=dial_eq_model.EQ_BASS_TREBLE_LIMIT_DB), rotate=False, bgr=False, metrics=_RICH_METRICS,
        )
        assert not _has_near_white_pixel(at_min.crop(layout.bass.down))
        assert _has_near_white_pixel(at_min.crop(layout.bass.up))
        assert _has_near_white_pixel(at_max.crop(layout.bass.down))
        assert not _has_near_white_pixel(at_max.crop(layout.bass.up))

    def test_pressed_wash_on_tapped_control_only(self, compositor):
        layout = eq_layout_for(320, 240, metrics=_RICH_METRICS)
        unpressed = compositor.compose_eq(320, 240, _eq_state(), rotate=False, bgr=False, metrics=_RICH_METRICS)
        pressed = compositor.compose_eq(
            320, 240, _eq_state(pressed=TouchZone.EQ_BASS_UP), rotate=False, bgr=False, metrics=_RICH_METRICS,
        )
        assert list(unpressed.crop(layout.bass.up).getdata()) != list(pressed.crop(layout.bass.up).getdata())
        assert list(unpressed.crop(layout.bass.down).getdata()) == list(pressed.crop(layout.bass.down).getdata())
        assert list(unpressed.crop(layout.treble.up).getdata()) == list(pressed.crop(layout.treble.up).getdata())

    def test_pressed_zone_from_a_different_geometry_washes_nothing(self, compositor):
        unpressed = compositor.compose_eq(320, 240, _eq_state(), rotate=False, bgr=False, metrics=_RICH_METRICS)
        pressed = compositor.compose_eq(
            320, 240, _eq_state(pressed=TouchZone.OUTPUT_UP), rotate=False, bgr=False, metrics=_RICH_METRICS,
        )
        assert list(unpressed.getdata()) == list(pressed.getdata())

    def test_statelessness(self, compositor):
        before = dict(vars(compositor))
        compositor.compose_eq(320, 240, _eq_state(), rotate=False, bgr=False, metrics=_RICH_METRICS)
        after = dict(vars(compositor))
        assert before == after == {}

    def test_same_inputs_produce_same_output(self, compositor):
        first = compositor.compose_eq(320, 240, _eq_state(bass_db=2), rotate=False, bgr=False, metrics=_RICH_METRICS)
        second = compositor.compose_eq(320, 240, _eq_state(bass_db=2), rotate=False, bgr=False, metrics=_RICH_METRICS)
        assert list(first.getdata()) == list(second.getdata())

    def test_never_raises_with_no_font(self, compositor):
        with patch("dial_display_draw.ImageFont.truetype", side_effect=OSError("no font")), \
             patch("dial_display_draw.ImageFont.load_default", side_effect=OSError("no default")):
            result = compositor.compose_eq(
                320, 240, _eq_state(bass_db=3, treble_db=-2), rotate=False, bgr=False, metrics=_RICH_METRICS,
            )
        assert result.size == (320, 240)

    def test_body_eq_bars_registered_in_body_renderers(self):
        assert BODY_EQ_BARS in _BODY_RENDERERS

    def test_eq_pressed_rects_resolve_against_geometry_eq(self):
        layout = eq_layout_for(320, 240, metrics=_RICH_METRICS)
        assert _eq_pressed_rects(TouchZone.EQ_TREBLE_DOWN, 320, 240, _RICH_METRICS) == (layout.treble.down,)
        assert _eq_pressed_rects(None, 320, 240, _RICH_METRICS) == ()
        assert _eq_pressed_rects(TouchZone.OUTPUT_UP, 320, 240, _RICH_METRICS) == ()


def _artwork_gradient(width, height):
    """A panel-sized base with no flat area, so any pixel the compositor
    draws over or dims is detectable against it."""
    image = Image.new("RGB", (width, height))
    image.putdata([((x * 7) % 256, (y * 5) % 256, 200) for y in range(height) for x in range(width)])
    return image


class TestComposeTimerLine:
    """compose()'s replay timer line: drawn in the artwork between the top
    band and the first album/title line, faded by timer_alpha, absent on
    the compact tier, and a strict no-op when not asked for."""

    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        _reset_render_caches()
        yield
        _reset_font_cache()
        _reset_render_caches()

    def _compose(self, compositor, metrics, **kwargs):
        base = _artwork_gradient(metrics.width, metrics.height)
        overlay = kwargs.pop("overlay", OverlayState(visible=True, dots=True, name="Kitchen", volume=40))
        return base, compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=overlay, metrics=metrics, **kwargs,
        )

    def _timer_rect(self, metrics):
        return timer_area(metrics.width, metrics.height, metrics)

    def test_no_timer_is_byte_identical(self, compositor):
        _, without = self._compose(compositor, _RICH_METRICS)
        _, with_none = self._compose(compositor, _RICH_METRICS, timer_text=None)
        assert with_none.tobytes() == without.tobytes()

    @pytest.mark.parametrize("metrics", [_RICH_METRICS, _LARGE_METRICS])
    def test_draws_only_inside_its_rect(self, compositor, metrics):
        _, plain = self._compose(compositor, metrics)
        _, timed = self._compose(compositor, metrics, timer_text="0:07 / 3:12")
        bbox = _diff_bbox(plain, timed)
        assert bbox is not None
        x0, y0, x1, y1 = self._timer_rect(metrics)
        assert x0 <= bbox[0] and y0 <= bbox[1] and bbox[2] <= x1 and bbox[3] <= y1

    _COVER = (200, 160, 120)
    _LONGEST = "600:59 / 600:59"  # the replay length limit is 600 minutes

    def _on_flat_cover(self, compositor, metrics, text, overlay=None):
        w, h = metrics.width, metrics.height
        base = Image.new("RGB", (w, h), self._COVER)
        out = compositor.compose(
            base, w, h, rotate=False, bgr=False, is_artwork=False, overlay=overlay,
            metrics=metrics, timer_text=text,
        )
        return base, out

    def _pill_bbox(self, metrics, out):
        """Bounding box of the pixels the pill darkened (the cover is flat,
        the overlay absent, so any change is the pill or its digits)."""
        return _diff_bbox(Image.new("RGB", out.size, self._COVER), out)

    def test_the_default_profile_is_the_base_tier(self):
        assert _BASE_METRICS.content_tier == CONTENT_BASE

    @pytest.mark.parametrize("metrics", [_BASE_METRICS, _RICH_METRICS, _LARGE_METRICS])
    @pytest.mark.parametrize("text", ["0:05 / 1:12", "72:04 / 77:30", _LONGEST])
    def test_pill_is_top_right_and_fully_drawn(self, compositor, metrics, text):
        _, out = self._on_flat_cover(compositor, metrics, text)
        layout = layout_for(metrics.width, metrics.height, metrics=metrics)
        first = layout.album if layout.album is not None else layout.title
        x0, y0, x1, y1 = self._pill_bbox(metrics, out)
        # Right edge on the header's own right margin, top one margin below the band.
        assert x1 == metrics.width - metrics.pad
        assert y0 == layout.top_band[3] + metrics.margin
        # The whole pill is inside the area: it never touches the side margin,
        # the header or the lines, so neither end is cut off.
        assert x0 >= metrics.margin
        assert y0 > layout.top_band[3] and y1 <= first[1]
        # Pill ends are dimmed to the band level, the cover beyond is untouched.
        cy = (y0 + y1) // 2
        dim = tuple(round(c * OVERLAY_DIM_FACTOR) for c in self._COVER)
        # Padding on both ends: just inside each end of the pill the cover is
        # dimmed to the band level, with no digit ink there.
        for px in (x0 + 2, x1 - 3):
            assert all(abs(g - e) <= 2 for g, e in zip(out.getpixel((px, cy)), dim))
        assert out.getpixel((x0 - 2, cy)) == self._COVER
        assert out.getpixel((x1 + 1, cy)) == self._COVER

    @pytest.mark.parametrize("metrics", [_BASE_METRICS, _RICH_METRICS, _LARGE_METRICS])
    def test_pill_anchors_right_and_grows_left(self, compositor, metrics):
        _, short = self._on_flat_cover(compositor, metrics, "0:05 / 1:12")
        _, long_ = self._on_flat_cover(compositor, metrics, self._LONGEST)
        s, l = self._pill_bbox(metrics, short), self._pill_bbox(metrics, long_)
        assert s[2] == l[2] and s[1] == l[1] and l[0] < s[0]

    @pytest.mark.parametrize("metrics", [_BASE_METRICS, _RICH_METRICS, _LARGE_METRICS])
    def test_pill_clears_the_header_and_lines_with_the_overlay_up(self, compositor, metrics):
        overlay = OverlayState(visible=True, dots=True, name="Kitchen", volume=40)
        _, with_timer = self._compose(compositor, metrics, overlay=overlay, timer_text=self._LONGEST)
        _, without = self._compose(compositor, metrics, overlay=overlay)
        x0, y0, x1, y1 = _diff_bbox(without, with_timer)
        layout = layout_for(metrics.width, metrics.height, metrics=metrics)
        first = layout.album if layout.album is not None else layout.title
        assert y0 >= layout.top_band[3] and y1 <= first[1]
        assert x0 >= 0 and x1 <= metrics.width - metrics.pad

    def test_drawn_with_no_overlay_too(self, compositor):
        base, timed = self._compose(compositor, _RICH_METRICS, overlay=None, timer_text="0:07 / 3:12")
        assert timed.tobytes() != base.tobytes()

    def test_does_not_draw_on_the_cached_base(self, compositor):
        base, _ = self._compose(compositor, _RICH_METRICS, overlay=None)
        before = base.tobytes()
        compositor.compose(
            base, 320, 240, rotate=False, bgr=False, is_artwork=False, overlay=None,
            metrics=_RICH_METRICS, timer_text="0:07 / 3:12",
        )
        assert base.tobytes() == before

    def test_alpha_fades_between_absent_and_full(self, compositor):
        _, plain = self._compose(compositor, _RICH_METRICS)
        _, full = self._compose(compositor, _RICH_METRICS, timer_text="0:07 / 3:12")
        _, half = self._compose(compositor, _RICH_METRICS, timer_text="0:07 / 3:12", timer_alpha=0.5)
        _, gone = self._compose(compositor, _RICH_METRICS, timer_text="0:07 / 3:12", timer_alpha=0.0)
        assert gone.tobytes() == plain.tobytes()
        assert half.tobytes() not in (plain.tobytes(), full.tobytes())

    def test_the_compact_tier_draws_no_timer_at_any_length(self, compositor):
        for metrics in (_COMPACT_240, _COMPACT_128):
            assert metrics.content_tier == CONTENT_COMPACT
            for text in ("0:05 / 1:12", self._LONGEST):
                base, out = self._on_flat_cover(compositor, metrics, text)
                assert out.tobytes() == base.tobytes()

    def test_the_pill_is_complete_even_when_the_smallest_font_overflows_the_area(self, compositor):
        # An area narrower than the smallest font's pill: the pill is drawn
        # whole, extending left of the area, never clipped.
        from dial_display_render import _timer_fit
        fit = _timer_fit(self._LONGEST, 15, 40, 30)
        assert fit is not None and fit[4] > 40

    def test_ignored_on_the_compact_tier(self, compositor):
        metrics = metrics_for(160, 128, 25.9 / 128)
        assert metrics.content_tier == CONTENT_COMPACT
        _, plain = self._compose(compositor, metrics)
        _, timed = self._compose(compositor, metrics, timer_text="0:07 / 3:12")
        assert timed.tobytes() == plain.tobytes()

    def test_rotate_applies_after_the_line(self, compositor):
        base = _artwork_gradient(320, 240)
        kw = dict(is_artwork=False, overlay=None, metrics=_RICH_METRICS, timer_text="0:07 / 3:12")
        upright = compositor.compose(base, 320, 240, rotate=False, bgr=False, **kw)
        rotated = compositor.compose(base, 320, 240, rotate=True, bgr=False, **kw)
        assert rotated.tobytes() == upright.transpose(Image.ROTATE_180).tobytes()


# ---------------------------------------------------------------------------
# Generic warning body: the optional progress bar and the button-less notice,
# and the guard that the existing No-WiFi and SD frames did not change.
# ---------------------------------------------------------------------------

_WARNING_MM_PER_PX = {(160, 128): None, (128, 128): None, (320, 240): 0.1778, (240, 240): 0.0973}


def _reference_body_warning(img, metrics, body):
    """The warning body as it was drawn before the progress bar and the
    button-less form existed: kept here, independent of the shared
    renderer, as the reference the existing pages must still match."""
    from PIL import ImageDraw
    from dial_display_palette import DIVIDER_RGB
    layout = warning_layout_for(metrics.width, metrics.height, buttons=max(1, len(body.buttons)), metrics=metrics)
    draw = ImageDraw.Draw(img)
    readout_font = dial_display_draw._load_font(metrics.font_readout)
    body_font = dial_display_draw._load_font(metrics.font_body)
    mx0, my0, mx1, my1 = layout.message
    if body.line:
        split = my0 + (my1 - my0) * 3 // 5
        dial_display_draw._draw_label_centered(draw, (mx0, my0, mx1, split), body.title, readout_font)
        dial_display_draw._draw_label_centered(draw, (mx0, split, mx1, my1), body.line, body_font)
    else:
        dial_display_draw._draw_label_centered(draw, layout.message, body.title, readout_font)
    for rect, label in zip(layout.cells, body.buttons):
        # A label too wide for its cell steps down in size (see _cell_label_font).
        font = dial_display_render._cell_label_font(draw, label, rect[2] - rect[0] - 2 * metrics.pad, metrics)
        dial_display_draw._draw_label_centered(draw, rect, label, font)
    w = metrics.divider_w
    cx0, cy0, cx1, cy1 = layout.card
    draw.line([(cx0, layout.divider_y), (cx1 - 1, layout.divider_y)], fill=DIVIDER_RGB, width=w)
    for x in layout.divider_xs:
        draw.line([(x, layout.cells[0][1]), (x, cy1 - 1)], fill=DIVIDER_RGB, width=w)


class TestWarningGenericBody:
    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    def _compose(self, compositor, width, height, view, mm_per_px=None):
        metrics = metrics_for(width, height, mm_per_px) if mm_per_px is not None else None
        return compositor.compose_warning(width, height, view, rotate=False, bgr=False, metrics=metrics)

    @pytest.mark.parametrize("width,height", sorted(_WARNING_MM_PER_PX))
    @pytest.mark.parametrize("pressed", [False, True])
    def test_existing_warning_frames_match_the_reference_renderer(self, compositor, width, height, pressed):
        import dial_display_views
        from dial_display import WARNING_DESCRIPTORS
        mm = _WARNING_MM_PER_PX[(width, height)]
        metrics = metrics_for(width, height, mm) if mm is not None else None
        for desc in (d for d in WARNING_DESCRIPTORS if d.id in ("nowifi", "sdhealth")):
            # Every shipped row leaves the generic fields at their defaults.
            assert desc.title_for is None and desc.progress_for is None
            reading = ("low", 19) if desc.message_for is not None else None
            view = WarningView(
                title=desc.title,
                message=desc.message_for(reading) if desc.message_for is not None else "",
                buttons=tuple(b.label for b in desc.buttons), pressed=len(desc.buttons) - 1 if pressed else None,
            )
            current = compositor.compose_warning(width, height, view, rotate=False, bgr=False, metrics=metrics)
            with patch.dict(dial_display_render._BODY_RENDERERS, {dial_display_views.BODY_WARNING: _reference_body_warning}):
                reference = compositor.compose_warning(
                    width, height, view, rotate=False, bgr=False, metrics=metrics,
                )
            assert current.tobytes() == reference.tobytes(), desc.id

    def test_percent_defaults_to_none_on_view_and_body(self):
        assert WarningView(title="x").percent is None
        assert Body().percent is None

    @pytest.mark.parametrize("width,height,mm_per_px", [
        (320, 240, 0.1778), (240, 240, 0.0973), (160, 128, None), (128, 128, None),
    ])
    def test_progress_bar_is_drawn_to_the_percent_and_absent_without_one(self, compositor, width, height, mm_per_px):
        metrics = metrics_for(width, height, mm_per_px) if mm_per_px is not None else metrics_for(width, height)
        layout = warning_layout_for(width, height, buttons=0, metrics=metrics)
        mx0, my0, mx1, my1 = layout.message
        zone = (my1 - my0) // 4
        bar_cy = my1 - zone // 2
        x0, x1 = mx0 + metrics.pad, mx1 - metrics.pad
        plain = self._compose(compositor, width, height, WarningView(title="Up"), mm_per_px)
        half = self._compose(
            compositor, width, height, WarningView(title="Up", percent=50), mm_per_px,
        )
        full = self._compose(
            compositor, width, height, WarningView(title="Up", percent=100), mm_per_px,
        )
        empty = self._compose(
            compositor, width, height, WarningView(title="Up", percent=0), mm_per_px,
        )
        mid = (x0 + x1) // 2
        left, right = x0 + 2, x1 - 3
        assert half.getpixel((left, bar_cy)) == (255, 255, 255)
        assert half.getpixel((right, bar_cy)) not in ((255, 255, 255), plain.getpixel((right, bar_cy)))
        assert full.getpixel((right, bar_cy)) == (255, 255, 255)
        assert full.getpixel((mid, bar_cy)) == (255, 255, 255)
        assert empty.getpixel((left, bar_cy)) != (255, 255, 255)
        assert empty.getpixel((left, bar_cy)) != plain.getpixel((left, bar_cy))
        # No percent: the row is untouched by any bar.
        assert plain.getpixel((mid, bar_cy)) != (255, 255, 255)
        # The track stays inside the card's inner width.
        assert half.getpixel((x0 - 2, bar_cy)) == plain.getpixel((x0 - 2, bar_cy))

    def test_progress_percent_is_clamped(self, compositor):
        over = self._compose(compositor, 160, 128, WarningView(title="Up", percent=250))
        full = self._compose(compositor, 160, 128, WarningView(title="Up", percent=100))
        under = self._compose(compositor, 160, 128, WarningView(title="Up", percent=-5))
        empty = self._compose(compositor, 160, 128, WarningView(title="Up", percent=0))
        assert list(over.getdata()) == list(full.getdata())
        assert list(under.getdata()) == list(empty.getdata())

    def test_progress_bar_moves_the_message_line_up(self, compositor):
        view = dict(title="Updating...", message="Downloading")
        with_bar = self._compose(compositor, 320, 240, WarningView(percent=40, **view), 0.1778)
        without = self._compose(compositor, 320, 240, WarningView(**view), 0.1778)
        layout = warning_layout_for(320, 240, buttons=0, metrics=metrics_for(320, 240, 0.1778))
        _, my0, _, my1 = layout.message
        split = my0 + (my1 - my0) * 3 // 5

        def lit_rows(img):
            return [
                y for y in range(split, my1)
                if any(img.getpixel((x, y)) == (255, 255, 255) for x in range(layout.message[0], layout.message[2]))
            ]
        assert lit_rows(with_bar) and lit_rows(without)
        assert min(lit_rows(with_bar)) < min(lit_rows(without))

    @pytest.mark.parametrize("width,height,mm_per_px", [
        (320, 240, 0.1778), (160, 128, None), (128, 128, None),
    ])
    def test_no_buttons_draws_no_crosshair(self, compositor, width, height, mm_per_px):
        metrics = metrics_for(width, height, mm_per_px) if mm_per_px is not None else metrics_for(width, height)
        layout = warning_layout_for(width, height, buttons=0, metrics=metrics)
        frame = self._compose(
            compositor, width, height,
            WarningView(title="Updating...", message="", buttons=()), mm_per_px,
        )
        cx0, cy0, cx1, cy1 = layout.card
        # Probe the places a two-button card's divider and cell split would sit.
        two = warning_layout_for(width, height, buttons=2, metrics=metrics)
        for x in list(range(cx0 + 1, cx0 + 8)) + list(range(cx1 - 9, cx1 - 1)):
            assert frame.getpixel((x, two.divider_y)) != (255, 255, 255)
        assert frame.getpixel((two.divider_xs[0], two.cells[0][3] - 4)) != (255, 255, 255)

    def test_no_buttons_with_a_font_failure_still_returns_a_frame(self, compositor):
        with patch("dial_display_render._load_font", return_value=None):
            frame = self._compose(
                compositor, 160, 128, WarningView(title="Hi", percent=30),
            )
        assert frame.size == (160, 128)


# ---------------------------------------------------------------------------
# An attributed warning (an appliance's): the source line over the title over
# the message, fitted to the card's message row on every tier because the
# text is not the dial's own.
# ---------------------------------------------------------------------------

_APPLIANCE_TIERS = {
    "compact_128x128": (128, 128, 0.2021),
    "base_160x128": (160, 128, None),
    "compact_240x240": (240, 240, 0.0973),
    "rich_320x240": (320, 240, 0.1778),
}
# The longest text the protocol allows: a 40-character title and source and a
# 120-character message of ordinary words, and the same lengths with no break
# opportunity at all in the widest letters.
_WORST_SOURCE = "autostream living room hi-fi cabinet left"[:40]
_WORST_TITLE = "Technics SL-1200 MK7 stylus due soon, ok"[:40]
_WORST_MESSAGE = (
    "Needs changing soon (7.5 h remaining). Reset the counter in Service when the new stylus is fitted "
    "and keep going now"
)[:120]
_UNBROKEN = ("S" * 40, "W" * 40, "M" * 120)
_TYPICAL = ("Lounge", "Technics stylus", "Needs changing soon (7.5 h remaining). Reset in Service.")


_TYPICAL_DETAIL = "Played 450 h of its 500 h life. Last changed 3 Mar 2026."
_WORST_DETAIL = (
    "The power supply cannot hold the voltage up when the board is busy. Use a supply rated for this board "
    "and a good cable."
)[:120]


def _fit_plan(tier, source, title, message, severity="warning", detail=""):
    """(draw, message row, metrics, title and message lines, source band) for
    one tier; the lines are laid out in the row left under the band and rule."""
    from PIL import ImageDraw
    from dial_display_render import _plan_warning_band, _plan_warning_text
    width, height, mm = _APPLIANCE_TIERS[tier]
    metrics = metrics_for(width, height, mm)
    layout = warning_layout_for(width, height, buttons=1, metrics=metrics)
    rect = layout.message
    body = Body(
        BODY_WARNING, title=title, line=message, buttons=("Close",), source=source, severity=severity,
        detail=detail,
    )
    draw = ImageDraw.Draw(Image.new("RGB", (width, height)))
    band = _plan_warning_band(draw, rect, body, metrics, layout.source_band_h)
    below = (rect[0], rect[1] + band[2] + band[3], rect[2], rect[3])
    return draw, rect, metrics, _plan_warning_text(draw, below, body, metrics), band


class TestApplianceWarningText:
    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    def test_a_view_has_no_source_or_severity_by_default(self):
        assert WarningView(title="x").source == "" and Body().source == ""
        assert WarningView(title="x").severity == "" and Body().severity == ""

    @pytest.mark.parametrize("tier", sorted(_APPLIANCE_TIERS))
    @pytest.mark.parametrize("texts", [
        (_WORST_SOURCE, _WORST_TITLE, _WORST_MESSAGE), _UNBROKEN, _TYPICAL, ("Lounge", "Power supply", ""),
    ], ids=["worst", "unbroken", "typical", "title_only"])
    def test_every_line_fits_the_message_row_and_the_title_is_never_dropped(self, tier, texts):
        draw, rect, metrics, plan, band = _fit_plan(tier, *texts)
        max_w = rect[2] - rect[0] - 2 * metrics.pad
        assert plan and plan[0][0]
        assert band[2] + band[3] + sum(size * 1.2 for _, _, size, _ in plan) <= rect[3] - rect[1]
        for text, font in [(t, f) for t, f, _, _ in plan] + [(band[0], band[1])]:
            assert _text_size(draw, text, font)[0] <= max_w, text

    @staticmethod
    def _detail_lines(plan, detail):
        """The plan's detail lines (everything after the empty gap entry)."""
        gap = [i for i, (text, *_) in enumerate(plan) if not text]
        assert len(gap) <= 1
        return [text for text, *_ in plan[gap[0] + 1:]] if gap else None

    def test_a_typical_detail_is_planned_whole_at_320x240(self):
        _, _, metrics, plan, _ = _fit_plan(
            "rich_320x240", "Turntable", "Technics stylus", "Change now", detail=_TYPICAL_DETAIL)
        lines = self._detail_lines(plan, _TYPICAL_DETAIL)
        assert lines and " ".join(lines) == _TYPICAL_DETAIL
        small = max(9, round(metrics.font_body * 0.8))
        assert all(size == small for _, _, size, _ in plan[-len(lines):])

    def test_the_gap_is_an_empty_entry_between_the_message_and_the_detail(self):
        _, _, _, plan, _ = _fit_plan(
            "rich_320x240", "Turntable", "Technics stylus", "Change now", detail=_TYPICAL_DETAIL)
        at = [i for i, (text, *_) in enumerate(plan) if not text]
        assert len(at) == 1 and plan[at[0] - 1][0] == "Change now"

    @pytest.mark.parametrize("tier", sorted(_APPLIANCE_TIERS))
    @pytest.mark.parametrize("detail", [_TYPICAL_DETAIL, "18% of its life left.", _WORST_DETAIL])
    @pytest.mark.parametrize("texts", [
        (_WORST_SOURCE, _WORST_TITLE, _WORST_MESSAGE), _UNBROKEN, _TYPICAL, ("Lounge", "Power supply", ""),
    ], ids=["worst", "unbroken", "typical", "title_only"])
    def test_a_detail_is_whole_or_absent_and_the_rest_is_unchanged_when_absent(self, tier, texts, detail):
        draw, rect, metrics, plan, band = _fit_plan(tier, *texts, detail=detail)
        _, _, _, plain, _ = _fit_plan(tier, *texts)
        lines = self._detail_lines(plan, detail)
        if lines is None:
            assert plan == plain
        else:
            assert " ".join(lines) == detail
        max_w = rect[2] - rect[0] - 2 * metrics.pad
        assert band[2] + band[3] + sum(size * 1.2 for _, _, size, _ in plan) <= rect[3] - rect[1]
        for text, font, _, _ in plan:
            assert _text_size(draw, text, font)[0] <= max_w

    def test_a_detail_that_cannot_fit_whole_is_dropped_and_the_card_is_as_without_it(self):
        _, _, _, plan, _ = _fit_plan(
            "base_160x128", _WORST_SOURCE, _WORST_TITLE, _WORST_MESSAGE, detail=_WORST_DETAIL)
        _, _, _, plain, _ = _fit_plan("base_160x128", _WORST_SOURCE, _WORST_TITLE, _WORST_MESSAGE)
        assert self._detail_lines(plan, _WORST_DETAIL) is None and plan == plain

    def test_a_card_with_no_detail_is_planned_as_it_always_was(self):
        _, _, _, plan, _ = _fit_plan("rich_320x240", *_TYPICAL)
        assert self._detail_lines(plan, "") is None

    @pytest.mark.parametrize("tier", ["compact_128x128", "compact_240x240", "rich_320x240"])
    def test_the_longest_title_is_shown_whole_where_the_row_has_room(self, tier):
        draw, rect, metrics, plan, band = _fit_plan(tier, _WORST_SOURCE, _WORST_TITLE, _WORST_MESSAGE)
        assert " ".join(text for text, *_ in plan).startswith(_WORST_TITLE)

    def test_the_base_panel_ellipsizes_the_source_and_the_title_for_the_longest_title(self):
        draw, rect, metrics, plan, band = _fit_plan("base_160x128", _WORST_SOURCE, _WORST_TITLE, _WORST_MESSAGE)
        assert band[0].endswith("...") and plan[-1][0].endswith("...")

    @pytest.mark.parametrize("tier", sorted(_APPLIANCE_TIERS))
    def test_the_typical_title_and_source_show_whole_on_every_tier(self, tier):
        draw, rect, metrics, plan, band = _fit_plan(tier, *_TYPICAL)
        assert band[0] == "Lounge" and plan[0][0] == "Technics stylus"

    @pytest.mark.parametrize("tier", sorted(_APPLIANCE_TIERS))
    def test_a_message_gets_the_row_left_over(self, tier):
        _, _, _, plan, _ = _fit_plan(tier, *_TYPICAL)
        assert len(plan) >= 2 and plan[1][0].startswith("Needs changing")

    @pytest.mark.parametrize("tier", sorted(_APPLIANCE_TIERS))
    def test_the_message_is_never_larger_than_body_size(self, tier):
        _, _, metrics, plan, _ = _fit_plan(tier, *_TYPICAL)
        assert plan[1][2] <= metrics.font_body

    @pytest.mark.parametrize("tier", sorted(_APPLIANCE_TIERS))
    def test_a_short_title_alone_is_drawn_at_readout_size(self, tier):
        _, _, metrics, plan, band = _fit_plan(tier, "Lounge", "Power supply", "")
        assert band[0] == "Lounge"
        assert [text for text, *_ in plan] == ["Power supply"]
        assert plan[0][2] == metrics.font_readout

    @pytest.mark.parametrize("tier", sorted(_APPLIANCE_TIERS))
    def test_a_short_source_is_drawn_at_body_size(self, tier):
        draw, rect, metrics, plan, band = _fit_plan(tier, "Lounge", "Power supply", "")
        assert band[1].size == metrics.font_body

    @pytest.mark.parametrize("tier", sorted(_APPLIANCE_TIERS))
    def test_a_long_source_steps_down_before_it_is_cut(self, tier):
        from dial_display_render import WARNING_SMALL_FONT_FLOOR_PX
        draw, rect, metrics, plan, band = _fit_plan(tier, "Kitchen dial · 12 of 16", "Power supply", "")
        assert not band[0].endswith("...") or band[1].size == WARNING_SMALL_FONT_FLOOR_PX

    @pytest.mark.parametrize("tier", sorted(_APPLIANCE_TIERS))
    @pytest.mark.parametrize("texts", [(_WORST_SOURCE, _WORST_TITLE, _WORST_MESSAGE), _UNBROKEN, _TYPICAL],
                             ids=["worst", "unbroken", "typical"])
    def test_nothing_is_drawn_outside_the_message_row(self, compositor, tier, texts):
        width, height, mm = _APPLIANCE_TIERS[tier]
        metrics = metrics_for(width, height, mm)
        rect = warning_layout_for(width, height, buttons=1, metrics=metrics).message
        view = WarningView(
            title=texts[1], message=texts[2], buttons=("Close",), source=texts[0], severity="critical",
        )
        with_text = compositor.compose_warning(width, height, view, rotate=False, bgr=False, metrics=metrics)
        with patch.object(dial_display_render, "_plan_warning_text", return_value=[]), \
                patch.object(dial_display_render, "_plan_warning_band", return_value=None):
            without = compositor.compose_warning(width, height, view, rotate=False, bgr=False, metrics=metrics)
        box = _diff_bbox(with_text, without)
        assert box is not None
        assert rect[0] <= box[0] and box[2] <= rect[2]
        assert rect[1] <= box[1] and box[3] <= rect[3]

    @pytest.mark.parametrize("tier", sorted(_APPLIANCE_TIERS))
    def test_the_source_band_is_the_top_bar_height_off_compact_and_text_sized_on_compact(self, tier):
        width, height, mm = _APPLIANCE_TIERS[tier]
        metrics = metrics_for(width, height, mm)
        _, _, _, _, band = _fit_plan(tier, "Lounge", "Power supply", "")
        if tier.startswith("compact"):
            assert band[2] == round(metrics.font_body * 1.2)
        else:
            top = layout_for(width, height, metrics=metrics).top_band
            assert band[2] == top[3] - top[1]

    @staticmethod
    def _band_frame(compositor, width, height, metrics, source, severity):
        """(frame, message row, band) for a one-button card with *source*."""
        rect = warning_layout_for(width, height, buttons=1, metrics=metrics).message
        view = WarningView(title="Power supply", buttons=("Close",), source=source, severity=severity)
        frame = compositor.compose_warning(width, height, view, rotate=False, bgr=False, metrics=metrics)
        return frame, rect

    @staticmethod
    def _pixels(frame, x0, y0, x1, y1):
        return {frame.getpixel((x, y)) for x in range(x0, x1) for y in range(y0, y1)}

    @pytest.mark.parametrize("tier", sorted(_APPLIANCE_TIERS))
    @pytest.mark.parametrize("severity,rule_rgb", [
        ("info", BELL_INFO_RGB), ("warning", BELL_WARNING_RGB), ("critical", BELL_CRITICAL_RGB),
    ])
    def test_the_source_band_is_blue_with_white_text_and_a_bell_over_a_severity_rule(
            self, compositor, tier, severity, rule_rgb):
        width, height, mm = _APPLIANCE_TIERS[tier]
        metrics = metrics_for(width, height, mm)
        frame, rect = self._band_frame(compositor, width, height, metrics, "Lounge", severity)
        _, _, _, _, band = _fit_plan(tier, "Lounge", "Power supply", "", severity)
        _, _, band_h, rule_h = band
        assert rule_h == 2 * metrics.divider_w
        x0, y0, x1, _ = rect
        # The band's fill reaches both ends of the row, and the text on it is white.
        assert frame.getpixel((x0, y0)) == frame.getpixel((x1 - 1, y0)) == LOGO_BACKGROUND_RGB
        middle = self._pixels(frame, x0 + band_h, y0, x1 - band_h, y0 + band_h)
        assert GLYPH_RGB in middle and rule_rgb not in middle
        # The left slot is plain band; the right slot holds the bell in the severity's colour.
        assert self._pixels(frame, x0, y0, x0 + band_h, y0 + band_h) == {LOGO_BACKGROUND_RGB}
        slot = self._pixels(frame, x1 - band_h, y0, x1, y0 + band_h)
        assert rule_rgb in slot and GLYPH_RGB not in slot
        for y in range(y0 + band_h, y0 + band_h + rule_h):
            assert frame.getpixel((x0, y)) == frame.getpixel((x1 - 1, y)) == rule_rgb

    @pytest.mark.parametrize("alpha,metrics_args", [
        ("rich", (320, 240, 0.1778)), ("compact", (320, 240, 0.0889)),
    ])
    def test_the_band_bell_is_in_the_right_slot_and_as_tall_as_the_text_on_compact(
            self, compositor, alpha, metrics_args):
        width, height, _ = metrics_args
        metrics = metrics_for(*metrics_args)
        frame, rect = self._band_frame(compositor, width, height, metrics, "Lounge", "warning")
        body = Body(BODY_WARNING, title="Power supply", buttons=("Close",), source="Lounge", severity="warning")
        layout = warning_layout_for(width, height, buttons=1, metrics=metrics)
        _, font, band_h, _ = dial_display_render._plan_warning_band(
            ImageDraw.Draw(frame), rect, body, metrics, layout.source_band_h)
        x0, y0, x1, _ = rect
        rows = [
            y for y in range(y0, y0 + band_h)
            if any(frame.getpixel((x, y)) != LOGO_BACKGROUND_RGB for x in range(x1 - band_h, x1))
        ]
        cols = [
            x for x in range(x1 - band_h, x1)
            if any(frame.getpixel((x, y)) != LOGO_BACKGROUND_RGB for y in range(y0, y0 + band_h))
        ]
        assert rows and cols
        # The bell is centred in its square slot, and (compact) as tall as the text.
        assert abs((rows[0] + rows[-1]) / 2 - (y0 + (band_h - 1) / 2)) <= 1.5
        assert abs((cols[0] + cols[-1]) / 2 - (x1 - (band_h + 1) / 2)) <= 1.5
        if alpha == "compact":
            assert rows[-1] - rows[0] + 1 >= font.size

    @pytest.mark.parametrize("tier", sorted(_APPLIANCE_TIERS))
    def test_a_long_source_is_ellipsized_between_the_slots_and_never_over_the_bell(self, compositor, tier):
        width, height, mm = _APPLIANCE_TIERS[tier]
        metrics = metrics_for(width, height, mm)
        frame, rect = self._band_frame(compositor, width, height, metrics, _UNBROKEN[1], "critical")
        _, _, _, _, band = _fit_plan(tier, _UNBROKEN[1], "Power supply", "", "critical")
        text, _, band_h, _ = band
        x0, y0, x1, _ = rect
        assert text.endswith("...")
        for slot in ((x0, x0 + band_h), (x1 - band_h, x1)):
            assert GLYPH_RGB not in self._pixels(frame, slot[0], y0, slot[1], y0 + band_h)
        assert GLYPH_RGB in self._pixels(frame, x0 + band_h, y0, x1 - band_h, y0 + band_h)

    @pytest.mark.parametrize("tier", sorted(_APPLIANCE_TIERS))
    def test_the_source_changes_the_frame_and_no_source_leaves_it_as_before(self, compositor, tier):
        width, height, mm = _APPLIANCE_TIERS[tier]
        metrics = metrics_for(width, height, mm)
        view = WarningView(title="Power supply", buttons=("Close",))
        plain = compositor.compose_warning(width, height, view, rotate=False, bgr=False, metrics=metrics)
        sourced = compositor.compose_warning(
            width, height, dataclasses.replace(view, source="Lounge"),
            rotate=False, bgr=False, metrics=metrics,
        )
        assert plain.tobytes() != sourced.tobytes()

    def test_a_font_failure_draws_no_text_and_still_returns_a_frame(self, compositor):
        with patch("dial_display_render._load_font", return_value=None):
            frame = compositor.compose_warning(
                160, 128, WarningView(title="Hi", buttons=("Close",), source="Lounge"),
                rotate=False, bgr=False,
            )
        assert frame.size == (160, 128)

    def test_the_wrap_and_cap_helpers_keep_fit_value_lines_as_it_was(self):
        from PIL import ImageDraw
        from dial_display_draw import _cap_lines, _wrap_words
        draw = ImageDraw.Draw(Image.new("RGB", (10, 10)))
        font = _load_font(13)
        lines = _wrap_words(draw, "one two three four five six seven eight", font, 60)
        assert len(lines) > 1 and " ".join(lines) == "one two three four five six seven eight"
        capped = _cap_lines(draw, lines, 1, font, 60)
        assert len(capped) == 1 and capped[0].endswith("...")
        assert _cap_lines(draw, ("fits",), 1, font, 60) == ("fits",)
