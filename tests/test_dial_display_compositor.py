"""Tests for dial_display_compositor.py — stateless frame composition.

Covers rotate/bgr in isolation and combined, identity when neither is set,
the artwork-fit path (transform_artwork_for_panel runs and panel-fits a
non-panel-sized input), the logo path (already-sized base passes through
transforms only), statelessness, the inert overlay parameter, the dimmed
top/bottom bands and single divider line of the now-playing overlay, the
name/artist halo text rendering (including its Pillow-failure fallbacks),
and the appliance-selector chassis (compose_list()).
"""
from __future__ import annotations

import contextlib
import sys
from pathlib import Path

from unittest.mock import patch

import pytest

Image = pytest.importorskip("PIL.Image", reason="Pillow not installed")

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
_CORE = str(REPO_ROOT / "core")
for _p in (_DIAL, _CORE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from dial_display_compositor import (  # noqa: E402
    _ARTIST_FONT_PX_AT_REFERENCE,
    _VOLUME_FONT_PX_AT_REFERENCE,
    BG_BASE,
    BODY_LIST_ROWS,
    BODY_NONE,
    BODY_NOW_PLAYING,
    BODY_REPEAT_LINE,
    BODY_REPEAT_ROW,
    DialDisplayCompositor,
    FOOTER_LABELS,
    FOOTER_LIST_BAR,
    FOOTER_LIST_RAIL,
    FOOTER_NONE,
    FOOTER_VOLUME,
    Frame,
    GLYPH_CHEVRON,
    GLYPH_CROSS,
    GLYPH_TWO_DOTS,
    ListState,
    LOOP_GLYPH,
    OverlayState,
    RepeatViewState,
    _BODY_RENDERERS,
    _FOOTER_RENDERERS,
    _GLYPH_SUPERSAMPLE,
    _compose_frame,
    _glyph_tile,
    _halo_layer,
    _pad_px,
    _reset_font_cache,
    _reset_render_caches,
    _scaled_px,
    _truncate_to_width,
    _zone_rect,
    format_mmss,
)
from dial_touch_layout import (  # noqa: E402
    CONTENT_BASE,
    GEOMETRY_LIST,
    GEOMETRY_MAIN,
    GEOMETRY_REPEAT,
    TouchZone,
    layout_for,
    list_layout_for,
    metrics_for,
    repeat_layout_for,
    zone_rects_for,
    zones_for,
)

# The profile sizes from dial_display_profiles.DISPLAY_PROFILES, and their
# confirmed mm_per_px (see the profiles module's design notes) — mirrors
# test_dial_touch_layout.py's own PROFILE_SIZES/confirmed-density pairing.
PROFILE_SIZES = [
    (160, 128),  # st7735s_160x128
    (128, 128),  # st7735s_128x128
    (240, 240),  # st7789_240x240
    (320, 240),  # st7789_320x240
    (320, 240),  # ili9341_320x240 (duplicate size, both must work)
]
_CONFIRMED_MM_PER_PX = [0.2231, 0.2021, 0.0973, 0.1778, 0.1778]
# Densities chosen to resolve to base at every panel size — proves the
# metrics-threading seam changed no base pixel. A (size, mm) pair that
# resolves to a richer content tier is a deliberate geometry change instead
# (see TestRichTierRendering) rather than a byte-equivalence case.
_OUT_OF_TIER_MM_PER_PX = [0.05, 0.5]
_METRICS_EQUIVALENCE_CASES = [
    (size, mm)
    for size, mm in (
        list(zip(PROFILE_SIZES, _CONFIRMED_MM_PER_PX))
        + [(size, mm) for size in PROFILE_SIZES for mm in _OUT_OF_TIER_MM_PER_PX]
    )
    if metrics_for(size[0], size[1], mm).content_tier == CONTENT_BASE
]

# A confirmed rich panel (the shipped 320x240 density) and a confirmed large
# one (640x480), used by the rail-specific render/pressed-wash tests below.
_RICH_METRICS = metrics_for(320, 240, 0.1778)
_LARGE_METRICS = metrics_for(640, 480, 0.127)


def _marked_image(size=(4, 4)):
    """A small asymmetric image so a 180 degree rotation is detectable."""
    image = Image.new("RGB", size, (0, 0, 0))
    image.putpixel((0, 0), (255, 0, 0))
    return image


@pytest.fixture
def compositor():
    return DialDisplayCompositor()


class TestRotateOnly:
    def test_rotate_true_rotates(self, compositor):
        img = _marked_image()
        result = compositor.compose(
            img, img.width, img.height,
            rotate=True, bgr=False, is_artwork=False,
        )
        expected = img.transpose(Image.ROTATE_180)
        assert list(result.getdata()) == list(expected.getdata())

    def test_rotate_false_leaves_unrotated(self, compositor):
        img = _marked_image()
        result = compositor.compose(
            img, img.width, img.height,
            rotate=False, bgr=False, is_artwork=False,
        )
        assert list(result.getdata()) == list(img.getdata())


class TestBgrOnly:
    def test_bgr_true_swaps_channels(self, compositor):
        img = _marked_image()
        result = compositor.compose(
            img, img.width, img.height,
            rotate=False, bgr=True, is_artwork=False,
        )
        expected = Image.merge("RGB", img.split()[::-1])
        assert list(result.getdata()) == list(expected.getdata())

    def test_bgr_false_leaves_unswapped(self, compositor):
        img = _marked_image()
        result = compositor.compose(
            img, img.width, img.height,
            rotate=False, bgr=False, is_artwork=False,
        )
        assert list(result.getdata()) == list(img.getdata())


class TestRotateAndBgrCombine:
    def test_both_apply_rotate_before_bgr_deterministically(self, compositor):
        img = _marked_image()
        result = compositor.compose(
            img, img.width, img.height,
            rotate=True, bgr=True, is_artwork=False,
        )
        expected = img.transpose(Image.ROTATE_180)
        expected = Image.merge("RGB", expected.split()[::-1])
        assert list(result.getdata()) == list(expected.getdata())

    def test_result_is_deterministic_across_repeated_calls(self, compositor):
        img = _marked_image()
        first = compositor.compose(
            img, img.width, img.height,
            rotate=True, bgr=True, is_artwork=False,
        )
        second = compositor.compose(
            img, img.width, img.height,
            rotate=True, bgr=True, is_artwork=False,
        )
        assert list(first.getdata()) == list(second.getdata())


class TestNeitherIsIdentity:
    def test_already_panel_sized_base_passes_through_unchanged(self, compositor):
        img = _marked_image(size=(160, 128))
        result = compositor.compose(
            img, 160, 128,
            rotate=False, bgr=False, is_artwork=False,
        )
        assert result.size == (160, 128)
        assert list(result.getdata()) == list(img.getdata())


class TestArtworkPath:
    def test_runs_transform_artwork_for_panel_and_fits_panel_size(self, compositor):
        # Source is not panel-sized — the compositor must run it through
        # transform_artwork_for_panel and come out panel-fitted.
        raw = Image.new("RGB", (300, 300), (10, 20, 30))
        result = compositor.compose(
            raw, 160, 128,
            rotate=False, bgr=False, is_artwork=True,
        )
        assert result.size == (160, 128)

    def test_artwork_path_calls_transform_artwork_for_panel(self, compositor):
        """The compositor owns the panel-fit call — the manager hands it the
        raw decoded image and never fits it first."""
        raw = Image.new("RGB", (300, 300))
        sentinel = Image.new("RGB", (7, 7))
        calls = []

        def fake_transform(image, width, height, blur_radius=None):
            calls.append((image, width, height, blur_radius))
            return sentinel

        with patch("dial_display_compositor.transform_artwork_for_panel", fake_transform):
            result = compositor.compose(
                raw, 160, 128,
                rotate=False, bgr=False, is_artwork=True,
            )
        # blur_radius is metrics.blur_radius for a metrics-less call —
        # metrics_for(160, 128).blur_radius, the same number
        # _blur_radius_for(160, 128) has always returned.
        assert calls == [(raw, 160, 128, 10)]
        assert result is sentinel


class TestLogoPath:
    def test_already_sized_base_only_gets_transforms(self, compositor):
        # is_artwork=False means the base (e.g. the logo, already loaded and
        # letterboxed by dial_display_image.load_logo) is passed through
        # untouched apart from rotate/bgr.
        logo = _marked_image(size=(160, 128))
        result = compositor.compose(
            logo, 160, 128,
            rotate=True, bgr=False, is_artwork=False,
        )
        expected = logo.transpose(Image.ROTATE_180)
        assert list(result.getdata()) == list(expected.getdata())

    def test_logo_path_never_calls_transform_artwork_for_panel(self, compositor):
        logo = _marked_image(size=(160, 128))
        calls = []

        def fake_transform(image, width, height):
            calls.append((image, width, height))
            return image

        with patch("dial_display_compositor.transform_artwork_for_panel", fake_transform):
            compositor.compose(
                logo, 160, 128,
                rotate=False, bgr=False, is_artwork=False,
            )
        assert calls == []


class TestStatelessness:
    def test_same_inputs_produce_same_output(self, compositor):
        img = _marked_image()
        first = compositor.compose(
            img, img.width, img.height,
            rotate=True, bgr=False, is_artwork=False,
        )
        second = compositor.compose(
            img, img.width, img.height,
            rotate=True, bgr=False, is_artwork=False,
        )
        assert list(first.getdata()) == list(second.getdata())

    def test_instance_holds_no_attributes_that_change_between_calls(self, compositor):
        before = dict(vars(compositor))
        compositor.compose(
            _marked_image(), 4, 4,
            rotate=True, bgr=True, is_artwork=False,
        )
        compositor.compose(
            Image.new("RGB", (300, 300)), 160, 128,
            rotate=False, bgr=False, is_artwork=True,
        )
        after = dict(vars(compositor))
        assert before == after == {}

    def test_two_instances_behave_identically(self):
        img = _marked_image()
        a = DialDisplayCompositor()
        b = DialDisplayCompositor()
        result_a = a.compose(img, img.width, img.height, rotate=True, bgr=True, is_artwork=False)
        result_b = b.compose(img, img.width, img.height, rotate=True, bgr=True, is_artwork=False)
        assert list(result_a.getdata()) == list(result_b.getdata())

    def test_compose_list_same_inputs_produce_same_output(self, compositor):
        state = ListState(rows=(("CD Player", True), ("Kitchen", False)), has_prev=False, has_next=True)
        first = compositor.compose_list(160, 128, state, rotate=False, bgr=False)
        second = compositor.compose_list(160, 128, state, rotate=False, bgr=False)
        assert list(first.getdata()) == list(second.getdata())

    def test_compose_list_holds_no_attributes_that_change_between_calls(self, compositor):
        before = dict(vars(compositor))
        compositor.compose_list(160, 128, ListState(rows=(("A", False),)), rotate=False, bgr=False)
        after = dict(vars(compositor))
        assert before == after == {}


class TestOverlayInert:
    """overlay=None (or an OverlayState with visible=False) must remain a
    strict no-op — the regression guard for the pre-existing rotate/bgr
    behaviour now that the overlay is activated."""

    def test_overlay_none_is_a_no_op(self, compositor):
        img = _marked_image()
        without = compositor.compose(
            img, img.width, img.height,
            rotate=True, bgr=True, is_artwork=False,
        )
        with_overlay = compositor.compose(
            img, img.width, img.height,
            rotate=True, bgr=True, is_artwork=False,
            overlay=None,
        )
        assert list(without.getdata()) == list(with_overlay.getdata())

    def test_not_visible_overlay_is_a_no_op(self, compositor):
        img = _marked_image()
        without = compositor.compose(
            img, img.width, img.height,
            rotate=True, bgr=True, is_artwork=False,
        )
        with_overlay = compositor.compose(
            img, img.width, img.height,
            rotate=True, bgr=True, is_artwork=False,
            overlay=OverlayState(visible=False),
        )
        assert list(without.getdata()) == list(with_overlay.getdata())

    def test_default_overlay_state_is_not_visible(self):
        assert OverlayState().visible is False

    def test_overlay_accepted_on_artwork_path_too(self, compositor):
        raw = Image.new("RGB", (300, 300))
        result = compositor.compose(
            raw, 160, 128,
            rotate=False, bgr=False, is_artwork=True,
            overlay=OverlayState(visible=False),
        )
        assert result.size == (160, 128)


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
        with patch("dial_display_compositor.ImageFont.truetype", side_effect=OSError("no font")):
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
        with patch("dial_display_compositor.ImageFont.truetype", side_effect=OSError("no font")), \
             patch("dial_display_compositor.ImageFont.load_default", side_effect=OSError("no default")):
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
        assert _scaled_px(_ARTIST_FONT_PX_AT_REFERENCE, width, height, 8) == expected_artist
        assert _scaled_px(_VOLUME_FONT_PX_AT_REFERENCE, width, height, 9) == expected_volume


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
        with patch("dial_display_compositor.ImageFont.truetype", side_effect=OSError("no font")), \
             patch("dial_display_compositor.ImageFont.load_default", side_effect=OSError("no default")):
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
        with patch("dial_display_compositor.ImageFilter.GaussianBlur", side_effect=RuntimeError("boom")):
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
        with patch("dial_display_compositor.ImageFont.truetype", side_effect=OSError("no font")), \
             patch("dial_display_compositor.ImageFont.load_default", side_effect=OSError("no default")):
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
        the LOOP_GLYPH/secondary-text feature."""
        state = ListState(rows=(("CD Player", True), ("Kitchen", False)), has_prev=True, has_next=True)
        result = compositor.compose_list(160, 128, state, rotate=False, bgr=False)
        # Re-run with an explicitly empty secondary on each row: must be
        # pixel-identical to the plain 2-tuple form.
        state_explicit = ListState(
            rows=(("CD Player", True, ""), ("Kitchen", False, "")), has_prev=True, has_next=True,
        )
        result_explicit = compositor.compose_list(160, 128, state_explicit, rotate=False, bgr=False)
        assert list(result.getdata()) == list(result_explicit.getdata())

    def test_loop_glyph_drawn_in_theme_colour(self, compositor):
        layout = list_layout_for(160, 128)
        plain = compositor.compose_list(160, 128, ListState(rows=(("Kitchen", False),)), rotate=False, bgr=False)
        looping = compositor.compose_list(
            160, 128, ListState(rows=(("Kitchen", False, LOOP_GLYPH),)), rotate=False, bgr=False,
        )
        assert list(plain.crop(layout.rows[0]).getdata()) != list(looping.crop(layout.rows[0]).getdata())

    def test_loop_glyph_and_checked_dot_both_drawn(self, compositor):
        """When a row is both the current focus AND replaying, the check
        dot and the loop glyph must both appear (side by side), never one
        silently overwriting the other."""
        layout = list_layout_for(160, 128)
        checked_only = compositor.compose_list(
            160, 128, ListState(rows=(("Kitchen", True),)), rotate=False, bgr=False,
        )
        checked_and_looping = compositor.compose_list(
            160, 128, ListState(rows=(("Kitchen", True, LOOP_GLYPH),)), rotate=False, bgr=False,
        )
        assert list(checked_only.crop(layout.rows[0]).getdata()) != list(
            checked_and_looping.crop(layout.rows[0]).getdata()
        )

    def test_loop_glyph_never_raises_with_no_font(self, compositor):
        with patch("dial_display_compositor.ImageFont.truetype", side_effect=OSError("no font")), \
             patch("dial_display_compositor.ImageFont.load_default", side_effect=OSError("no default")):
            result = compositor.compose_list(
                160, 128, ListState(rows=(("Kitchen", True, LOOP_GLYPH),)), rotate=False, bgr=False,
            )
        assert result.size == (160, 128)


# ---------------------------------------------------------------------------
# format_mmss — pure time formatting helper.
# ---------------------------------------------------------------------------

class TestFormatMmss:
    def test_zero(self):
        assert format_mmss(0) == "0:00"

    def test_under_a_minute(self):
        assert format_mmss(42) == "0:42"

    def test_exact_minute(self):
        assert format_mmss(60) == "1:00"

    def test_rounds_to_nearest_second(self):
        assert format_mmss(59.6) == "1:00"
        assert format_mmss(59.4) == "0:59"

    def test_hours_fold_into_minutes(self):
        assert format_mmss(3723) == "62:03"

    def test_negative_clamps_to_zero(self):
        assert format_mmss(-5) == "0:00"


# ---------------------------------------------------------------------------
# compose_repeat — the repeat screen: enable layout ("Repeat Play" row,
# armed) and the replaying layout (Restart/Stop, position line over the
# current artwork/logo base image). Both layouts share the main screen's
# top band (dots, name, mute/volume readout).
# ---------------------------------------------------------------------------

def _repeat_state(**overrides) -> RepeatViewState:
    base = dict(
        name="Kitchen", layout="enable", armed=False, line="",
        start_enabled=False, stop_enabled=False, stop_pressed=False,
        muted=None, volume=None, pressed=None,
    )
    base.update(overrides)
    return RepeatViewState(**base)


def _repeat_dot_rect(layout, width=160, height=128):
    """The enable layout's "Repeat Play" row dot marker rect — mirrors the
    geometry _body_repeat_row() itself computes."""
    pad = _pad_px(width, height)
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
        with patch("dial_display_compositor.ImageFont.truetype", side_effect=OSError("no font")), \
             patch("dial_display_compositor.ImageFont.load_default", side_effect=OSError("no default")):
            result = compositor.compose_repeat(160, 128, _repeat_state(armed=True), rotate=False, bgr=False)
        assert result.size == (160, 128)


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

    def test_muted_glyph_differs_from_unmuted(self, compositor):
        layout = repeat_layout_for(160, 128)
        unmuted = compositor.compose_repeat(160, 128, _repeat_state(muted=False), rotate=False, bgr=False)
        muted = compositor.compose_repeat(160, 128, _repeat_state(muted=True), rotate=False, bgr=False)
        assert list(unmuted.crop(layout.volume_cluster).getdata()) != list(
            muted.crop(layout.volume_cluster).getdata()
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
        with patch("dial_display_compositor._draw_label_centered") as mock_label_centered:
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
        with patch("dial_display_compositor.ImageFont.truetype", side_effect=OSError("no font")), \
             patch("dial_display_compositor.ImageFont.load_default", side_effect=OSError("no default")):
            result = compositor.compose_repeat(160, 128, self._state(), rotate=False, bgr=False)
        assert result.size == (160, 128)


class TestRepeatMuteWash:
    """Reading the shared zone table gives the repeat screen's pressed-rect
    lookup a MUTE entry it never had before: a tap there has always resolved
    to MUTE and toggled it (repeat_zone_at() already did this), so drawing
    its wash the same way every other tappable zone's wash is drawn is the
    consistent behaviour, not a special case. No manager-produced state
    reaches this today — the repeat screen's own pressed channel is only
    ever populated for the repeat screen's own zones — so this documents the
    input-space difference deliberately rather than leaving it accidental."""

    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    def test_pressed_mute_washes_the_volume_cluster_and_nothing_else(self, compositor):
        layout = repeat_layout_for(160, 128)
        unpressed = compositor.compose_repeat(160, 128, _repeat_state(), rotate=False, bgr=False)
        pressed = compositor.compose_repeat(
            160, 128, _repeat_state(pressed=TouchZone.MUTE), rotate=False, bgr=False,
        )
        assert list(unpressed.crop(layout.volume_cluster).getdata()) != list(
            pressed.crop(layout.volume_cluster).getdata()
        )
        for rect in (layout.dots, layout.name, layout.row, layout.start, layout.stop):
            assert list(unpressed.crop(rect).getdata()) == list(pressed.crop(rect).getdata())


# ---------------------------------------------------------------------------
# _zone_rect — the pressed-rect lookups' shared helper over the zone table.
# ---------------------------------------------------------------------------

class TestZoneRectHelper:
    @pytest.mark.parametrize("geometry", [GEOMETRY_MAIN, GEOMETRY_LIST, GEOMETRY_REPEAT])
    def test_returns_each_table_entrys_own_rect(self, geometry):
        for entry in zone_rects_for(geometry, 160, 128):
            assert _zone_rect(geometry, entry.zone, entry.index, 160, 128) == entry.rect

    def test_stale_list_row_index_returns_none(self):
        assert _zone_rect(GEOMETRY_LIST, TouchZone.LIST_ROW, 99, 160, 128) is None

    def test_none_index_for_list_row_returns_none(self):
        assert _zone_rect(GEOMETRY_LIST, TouchZone.LIST_ROW, None, 160, 128) is None

    def test_zone_from_a_different_geometry_returns_none(self):
        # REPEAT_PLAY only ever appears in the repeat geometry's table.
        assert _zone_rect(GEOMETRY_MAIN, TouchZone.REPEAT_PLAY, None, 160, 128) is None

    def test_none_zone_returns_none(self):
        assert _zone_rect(GEOMETRY_MAIN, None, None, 160, 128) is None


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

    def _logo(self):
        return Image.new("RGB", (160, 128), (32, 32, 32))

    def test_renders_the_base_plainly(self, compositor):
        base = self._logo()
        result = compositor.compose_idle(base, 160, 128, rotate=False, bgr=False)
        assert list(result.getdata()) == list(base.convert("RGB").getdata())

    def test_none_base_returns_none(self, compositor):
        assert compositor.compose_idle(None, 160, 128, rotate=False, bgr=False) is None

    def test_rotate_and_bgr_applied(self, compositor):
        base = self._logo()
        plain = compositor.compose_idle(base, 160, 128, rotate=False, bgr=False)
        rotated = compositor.compose_idle(base, 160, 128, rotate=True, bgr=False)
        assert list(rotated.getdata()) == list(plain.transpose(Image.ROTATE_180).getdata())
        swapped = compositor.compose_idle(base, 160, 128, rotate=False, bgr=True)
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


# ---------------------------------------------------------------------------
# _compose_frame — the shared pipeline every screen frame is built from:
# background, dims, pressed wash, header, body, footer, then rotate/BGR.
# Exercised directly here (rather than only through the four public
# entry points above) so the dispatch tables and the pipeline's own
# invariants are pinned independently of any one screen's adapter.
# ---------------------------------------------------------------------------

class TestComposeFramePipeline:
    def test_every_body_kind_has_a_renderer(self):
        for kind in (BODY_NONE, BODY_NOW_PLAYING, BODY_REPEAT_ROW, BODY_REPEAT_LINE, BODY_LIST_ROWS):
            assert kind in _BODY_RENDERERS

    def test_every_footer_kind_has_a_renderer(self):
        for kind in (FOOTER_NONE, FOOTER_VOLUME, FOOTER_LABELS, FOOTER_LIST_BAR, FOOTER_LIST_RAIL):
            assert kind in _FOOTER_RENDERERS

    def test_default_frame_renders_the_base_unchanged(self):
        size = (160, 128)
        base = Image.new("RGB", size, (12, 34, 56))
        result = _compose_frame(base, *size, Frame(BG_BASE), rotate=False, bgr=False)
        assert list(result.getdata()) == list(base.getdata())

    def test_pressed_rects_wash_exactly_those_rects_and_nothing_else(self):
        size = (160, 128)
        base = Image.new("RGB", size, (200, 150, 100))
        rect_a = (10, 10, 30, 30)
        rect_b = (50, 60, 70, 90)
        unpressed = _compose_frame(base, *size, Frame(BG_BASE), rotate=False, bgr=False)
        pressed = _compose_frame(
            base, *size, Frame(BG_BASE, pressed=(rect_a, rect_b)), rotate=False, bgr=False,
        )
        assert list(unpressed.crop(rect_a).getdata()) != list(pressed.crop(rect_a).getdata())
        assert list(unpressed.crop(rect_b).getdata()) != list(pressed.crop(rect_b).getdata())
        outside = (100, 100, 120, 120)
        assert list(unpressed.crop(outside).getdata()) == list(pressed.crop(outside).getdata())

    def test_rotate_applied_before_bgr(self):
        size = (4, 4)
        base = _marked_image(size)
        result = _compose_frame(base, *size, Frame(BG_BASE), rotate=True, bgr=True)
        expected = base.transpose(Image.ROTATE_180)
        expected = Image.merge("RGB", expected.split()[::-1])
        assert list(result.getdata()) == list(expected.getdata())

    def test_new_frame_does_not_mutate_the_caller_base(self):
        size = (160, 128)
        base = Image.new("RGB", size, (12, 34, 56))
        before = base.tobytes()
        _compose_frame(
            base, *size,
            Frame(BG_BASE, dim_top=True, dim_bottom=True, pressed=((0, 0, 10, 10),)),
            rotate=False, bgr=False,
        )
        assert base.tobytes() == before

    def test_new_frame_returns_a_distinct_object_from_the_base(self):
        size = (160, 128)
        base = Image.new("RGB", size, (1, 2, 3))
        result = _compose_frame(base, *size, Frame(BG_BASE), rotate=False, bgr=False)
        assert result is not base


# ---------------------------------------------------------------------------
# Physical-size metrics: passing a LayoutMetrics (any density, including one
# that resolves to compact or large) must never change a single output byte
# in this stage — tier is reported, never consumed. metrics=None and a
# metrics_for(w, h) built from an unrelated density must render identically.
# ---------------------------------------------------------------------------

class TestMetricsByteEquivalence:
    @pytest.mark.parametrize("size,mm", _METRICS_EQUIVALENCE_CASES)
    def test_compose_main_overlay_unaffected(self, compositor, size, mm):
        width, height = size
        base = _marked_image(size=(width, height))
        overlay = OverlayState(
            visible=True, muted=False, artist="Artist", title="Title", volume=42, name="Kitchen",
        )
        plain = compositor.compose(
            base, width, height, rotate=False, bgr=False, is_artwork=False, overlay=overlay,
        )
        with_metrics = compositor.compose(
            base, width, height, rotate=False, bgr=False, is_artwork=False, overlay=overlay,
            metrics=metrics_for(width, height, mm),
        )
        assert list(plain.getdata()) == list(with_metrics.getdata())

    @pytest.mark.parametrize("size,mm", _METRICS_EQUIVALENCE_CASES)
    def test_compose_list_unaffected(self, compositor, size, mm):
        width, height = size
        state = ListState(rows=(("CD Player", True), ("Kitchen", False)), has_prev=True, has_next=True)
        plain = compositor.compose_list(width, height, state, rotate=False, bgr=False)
        with_metrics = compositor.compose_list(
            width, height, state, rotate=False, bgr=False, metrics=metrics_for(width, height, mm),
        )
        assert list(plain.getdata()) == list(with_metrics.getdata())

    @pytest.mark.parametrize("size,mm", _METRICS_EQUIVALENCE_CASES)
    def test_compose_repeat_enable_layout_unaffected(self, compositor, size, mm):
        width, height = size
        state = RepeatViewState(
            name="Kitchen", layout="enable", armed=True, line="",
            start_enabled=False, stop_enabled=False, stop_pressed=False,
        )
        plain = compositor.compose_repeat(width, height, state, rotate=False, bgr=False)
        with_metrics = compositor.compose_repeat(
            width, height, state, rotate=False, bgr=False, metrics=metrics_for(width, height, mm),
        )
        assert list(plain.getdata()) == list(with_metrics.getdata())

    @pytest.mark.parametrize("size,mm", _METRICS_EQUIVALENCE_CASES)
    def test_compose_repeat_replaying_layout_unaffected(self, compositor, size, mm):
        width, height = size
        base = _marked_image(size=(width, height))
        state = RepeatViewState(
            name="Kitchen", layout="replaying", armed=True, line="0:12 / 3:45",
            start_enabled=True, stop_enabled=True, stop_pressed=False,
        )
        plain = compositor.compose_repeat(width, height, state, rotate=False, bgr=False, base=base)
        with_metrics = compositor.compose_repeat(
            width, height, state, rotate=False, bgr=False, base=base,
            metrics=metrics_for(width, height, mm),
        )
        assert list(plain.getdata()) == list(with_metrics.getdata())

    @pytest.mark.parametrize("size,mm", _METRICS_EQUIVALENCE_CASES)
    def test_compose_idle_unaffected(self, compositor, size, mm):
        width, height = size
        base = _marked_image(size=(width, height))
        plain = compositor.compose_idle(base, width, height, rotate=False, bgr=False)
        with_metrics = compositor.compose_idle(
            base, width, height, rotate=False, bgr=False, metrics=metrics_for(width, height, mm),
        )
        assert list(plain.getdata()) == list(with_metrics.getdata())


class TestShimsEqualMetricsFields:
    """_pad_px and _scaled_px are test-facing shims now delegating to
    dial_touch_layout — check they still agree with the metrics fields they
    stand in for, at every profile size."""

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_pad_px_equals_metrics_pad(self, width, height):
        assert _pad_px(width, height) == metrics_for(width, height).pad

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_scaled_px_equals_metrics_font_body(self, width, height):
        m = metrics_for(width, height)
        assert _scaled_px(_ARTIST_FONT_PX_AT_REFERENCE, width, height, 8) == m.font_body
        assert _scaled_px(_VOLUME_FONT_PX_AT_REFERENCE, width, height, 9) == m.font_readout


# ---------------------------------------------------------------------------
# Glyph-tile and halo-layer caches — both are memoised pure functions (the
# same footing as _load_font), so a cold render (empty cache), a warm render
# (second pass, everything a hit) and a render with the caches bypassed
# entirely (the memoised functions swapped for their own uncached originals)
# must all produce byte-identical frames. Covered over a corpus spanning
# every public compose entry point and a representative set of states, at
# every profile size, under both the normal font and the truetype-
# unavailable fallback face.
# ---------------------------------------------------------------------------

def _repeat_state_for_cache_tests(**overrides) -> RepeatViewState:
    base = dict(
        name="Kitchen", layout="enable", armed=False, line="",
        start_enabled=False, stop_enabled=False, stop_pressed=False,
        muted=None, volume=None, pressed=None,
    )
    base.update(overrides)
    return RepeatViewState(**base)


def _render_cache_corpus(width, height, metrics=None):
    """Every distinct screen/state combination the glyph-tile and halo-layer
    caches can be exercised by: the main overlay (with/without dots, a
    pressed zone, a muted state, empty/short/long text), the appliance-
    selector list (row counts, a secondary-text row, the loop marker, paging
    states, a pressed row and a pressed bar zone), the repeat screen (both
    layouts, a pressed zone, the fade-out Stop wash) and the idle screen.
    Returns a list of
    (name, render(compositor) -> Image) pairs so the same corpus can be run
    cold, warm and with the caches bypassed. *metrics*, when given, is
    threaded through every render call the same way the display manager
    threads its own resolved LayoutMetrics through — None reproduces
    today's density-unaware geometry."""
    base = Image.new("RGB", (width, height), (200, 150, 100))
    logo = Image.new("RGB", (width, height), (32, 32, 32))
    long_text = "A Very Long Name Indeed Of Considerable Length" * 2

    cases = []

    def add_main(name, **overrides):
        state = dict(visible=True, artist="Artist", title="Title", volume=42, name="Kitchen")
        state.update(overrides)
        cases.append((
            f"main/{name}",
            lambda c, state=state: c.compose(
                base, width, height, rotate=False, bgr=False, is_artwork=False,
                overlay=OverlayState(**state), metrics=metrics,
            ),
        ))

    add_main("plain")
    add_main("dots", dots=True)
    add_main("pressed_down", pressed=TouchZone.DOWN)
    add_main("pressed_name", pressed=TouchZone.NAME)
    add_main("muted_true", muted=True)
    add_main("muted_false", muted=False)
    add_main("empty_text", artist="", title="")
    add_main("long_text", artist=long_text, title=long_text)

    def add_list(name, state):
        cases.append((
            f"list/{name}",
            lambda c, state=state: c.compose_list(
                width, height, state, rotate=False, bgr=False, metrics=metrics,
            ),
        ))

    add_list("empty", ListState(rows=()))
    add_list("one_row", ListState(rows=(("CD Player", True),)))
    add_list("three_rows", ListState(rows=(("CD Player", True), ("Kitchen", False), ("Study", False))))
    add_list("secondary_text", ListState(rows=(("Kitchen", False, "42:10"),)))
    add_list("loop_marker", ListState(rows=(("Kitchen", True, LOOP_GLYPH),)))
    add_list("paging_both", ListState(rows=(("A", False),), has_prev=True, has_next=True))
    add_list("paging_none", ListState(rows=(("A", False),), has_prev=False, has_next=False))
    add_list("pressed_row", ListState(
        rows=(("CD Player", True), ("Kitchen", False), ("Study", False)),
        pressed=(TouchZone.LIST_ROW, 1),
    ))
    add_list("pressed_bar", ListState(rows=(("A", False),), pressed=(TouchZone.LIST_BACK, None)))

    def add_repeat(name, state, base_img=None):
        cases.append((
            f"repeat/{name}",
            lambda c, state=state, base_img=base_img: c.compose_repeat(
                width, height, state, rotate=False, bgr=False, base=base_img, metrics=metrics,
            ),
        ))

    add_repeat("enable_unarmed", _repeat_state_for_cache_tests(layout="enable", armed=False))
    add_repeat("enable_armed", _repeat_state_for_cache_tests(layout="enable", armed=True))
    add_repeat("enable_pressed", _repeat_state_for_cache_tests(layout="enable", pressed=TouchZone.REPEAT_PLAY))
    add_repeat("mute_pressed", _repeat_state_for_cache_tests(layout="enable", pressed=TouchZone.MUTE))
    add_repeat(
        "replaying",
        _repeat_state_for_cache_tests(
            layout="replaying", line="1:23 / 4:56", start_enabled=True, stop_enabled=True,
        ),
        base_img=base,
    )
    add_repeat(
        "replaying_stop_pressed",
        _repeat_state_for_cache_tests(
            layout="replaying", line="1:23 / 4:56", start_enabled=True, stop_enabled=True,
            stop_pressed=True,
        ),
        base_img=base,
    )

    cases.append((
        "idle",
        lambda c: c.compose_idle(logo, width, height, rotate=False, bgr=False, metrics=metrics),
    ))

    return cases


class TestRenderCacheEquivalence:
    """Cold (caches cleared before the corpus runs), warm (a second full
    pass, so every tile and layer the corpus can produce is already cached)
    and bypassed (the memoised functions swapped for their own uncached
    `__wrapped__` originals) must render byte-identical output for every
    case — the whole point of memoising a pure function is that using the
    cache never changes what gets drawn."""

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    @pytest.mark.parametrize("no_font", [False, True], ids=["normal_font", "fallback_font"])
    def test_cold_warm_bypassed_are_byte_identical(self, width, height, no_font):
        compositor = DialDisplayCompositor()
        font_cm = (
            patch("dial_display_compositor.ImageFont.truetype", side_effect=OSError("no font"))
            if no_font else contextlib.nullcontext()
        )

        def render_all():
            return [(name, fn(compositor)) for name, fn in _render_cache_corpus(width, height)]

        try:
            with font_cm:
                _reset_font_cache()
                cold = render_all()
                warm = render_all()
                with patch("dial_display_compositor._glyph_tile", _glyph_tile.__wrapped__), \
                     patch("dial_display_compositor._halo_layer", _halo_layer.__wrapped__):
                    bypassed = render_all()
        finally:
            _reset_font_cache()

        for (name, cold_img), (_, warm_img), (_, bypassed_img) in zip(cold, warm, bypassed):
            assert cold_img.tobytes() == warm_img.tobytes(), f"{name}: cold != warm"
            assert cold_img.tobytes() == bypassed_img.tobytes(), f"{name}: cold != bypassed"


# (size, metrics) pairs re-running the same corpus with an explicit,
# resolved LayoutMetrics threaded through every call — the base entries
# prove the metrics-threading seam (4.1) and the supersample pass-through
# changed no base pixel; the rich/large entries prove the same cold/warm/
# bypassed discipline holds for the new right-rail footer and its glyph
# tiles (a different supersample factor on the large tier).
_CONTENT_TIER_CACHE_CASES = [
    ((160, 128), metrics_for(160, 128)),
    ((128, 128), metrics_for(128, 128)),
    ((240, 240), metrics_for(240, 240, 0.0973)),
    ((320, 240), _RICH_METRICS),
    ((640, 480), _LARGE_METRICS),
]


class TestRenderCacheEquivalenceWithMetrics:
    """Same cold/warm/bypassed discipline as TestRenderCacheEquivalence,
    but with an explicit LayoutMetrics threaded through every render call
    instead of relying on the metrics=None default."""

    @pytest.mark.parametrize("size,metrics", _CONTENT_TIER_CACHE_CASES)
    def test_cold_warm_bypassed_are_byte_identical(self, size, metrics):
        width, height = size
        compositor = DialDisplayCompositor()

        def render_all():
            return [(name, fn(compositor)) for name, fn in _render_cache_corpus(width, height, metrics=metrics)]

        try:
            _reset_font_cache()
            cold = render_all()
            warm = render_all()
            with patch("dial_display_compositor._glyph_tile", _glyph_tile.__wrapped__), \
                 patch("dial_display_compositor._halo_layer", _halo_layer.__wrapped__):
                bypassed = render_all()
        finally:
            _reset_font_cache()

        for (name, cold_img), (_, warm_img), (_, bypassed_img) in zip(cold, warm, bypassed):
            assert cold_img.tobytes() == warm_img.tobytes(), f"{name}: cold != warm"
            assert cold_img.tobytes() == bypassed_img.tobytes(), f"{name}: cold != bypassed"


# ---------------------------------------------------------------------------
# The right-rail list on the rich/large tiers: FOOTER_LIST_RAIL's rendering,
# the GLYPH_CROSS tile, pressed-wash-follows-the-table, and the pressed-rect
# lookup resolving against the same (possibly band-capped) metrics the
# renderer drew with.
# ---------------------------------------------------------------------------

class TestCrossGlyph:
    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_render_caches()
        yield
        _reset_render_caches()

    def test_glyph_cross_has_a_registered_painter(self):
        from dial_display_compositor import _GLYPH_PAINTERS
        assert GLYPH_CROSS in _GLYPH_PAINTERS

    def test_tile_has_both_diagonals_and_empty_corners(self):
        w, h = 60, 72
        tile = _glyph_tile(GLYPH_CROSS, (), w, h, 4)
        assert tile.size == (w, h)
        assert tile.mode == "RGBA"
        pixels = tile.load()
        assert pixels[w // 2, h // 2][3] > 0  # the two diagonals cross here
        for corner in ((0, 0), (w - 1, 0), (0, h - 1), (w - 1, h - 1)):
            assert pixels[corner][3] == 0


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
        from dial_display_compositor import _LIST_SEPARATOR_RGB
        layout = list_layout_for(320, 240, metrics=_RICH_METRICS)
        result = compositor.compose_list(
            320, 240, ListState(rows=self._rows()), rotate=False, bgr=False, metrics=_RICH_METRICS,
        )
        assert result.getpixel((layout.rail[0] - 1, 10)) == _LIST_SEPARATOR_RGB

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


class TestPressedRectsFollowRenderedMetrics:
    """The pressed-rect lookup (_zone_rect, via _main_pressed_rects/
    _repeat_pressed_rects) must resolve against the SAME metrics the
    renderer drew with. Proven at a panel/density pair where the 12 mm band
    cap actually moves the header/footer bands away from their base-tier
    position (320x240 at a coarser density than the shipped panel) — if the
    pressed lookup ever fell back to density-free geometry, the wash would
    land on the wrong rect."""

    def test_main_screen_down_press_washes_the_capped_rect(self, compositor):
        width, height = 320, 240
        metrics = metrics_for(width, height, 0.2778)
        base_layout = layout_for(width, height)
        capped_layout = layout_for(width, height, metrics=metrics)
        assert capped_layout.down != base_layout.down  # the cap actually moved it

        base_img = Image.new("RGB", (width, height), (100, 120, 140))
        unpressed = compositor.compose(
            base_img, width, height, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, name="Kitchen"), metrics=metrics,
        )
        pressed = compositor.compose(
            base_img, width, height, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, name="Kitchen", pressed=TouchZone.DOWN), metrics=metrics,
        )
        assert list(unpressed.crop(capped_layout.down).getdata()) != list(pressed.crop(capped_layout.down).getdata())

    def test_repeat_screen_start_press_washes_the_capped_rect(self, compositor):
        width, height = 320, 240
        metrics = metrics_for(width, height, 0.2778)
        capped_layout = repeat_layout_for(width, height, metrics=metrics)
        base_img = Image.new("RGB", (width, height), (100, 120, 140))

        def _state(**overrides):
            state = dict(
                name="Kitchen", layout="replaying", armed=True, line="0:10 / 1:00",
                start_enabled=True, stop_enabled=True, stop_pressed=False,
            )
            state.update(overrides)
            return RepeatViewState(**state)

        unpressed = compositor.compose_repeat(
            width, height, _state(), rotate=False, bgr=False, base=base_img, metrics=metrics,
        )
        pressed = compositor.compose_repeat(
            width, height, _state(pressed=TouchZone.REPEAT_START),
            rotate=False, bgr=False, base=base_img, metrics=metrics,
        )
        assert list(unpressed.crop(capped_layout.start).getdata()) != list(pressed.crop(capped_layout.start).getdata())


class TestGlyphTileCacheAccounting:
    """cache_info() hit/miss accounting for _glyph_tile — pins that a hit
    and a miss happen exactly where expected, not merely that the pixels
    come out right."""

    @pytest.fixture(autouse=True)
    def _reset(self):
        _reset_render_caches()
        yield
        _reset_render_caches()

    def test_main_compose_with_dots_one_miss_then_one_hit(self):
        compositor = DialDisplayCompositor()
        img = Image.new("RGB", (160, 128), (200, 150, 100))
        overlay = OverlayState(visible=True, dots=True)
        compositor.compose(img, 160, 128, rotate=False, bgr=False, is_artwork=False, overlay=overlay)
        info = _glyph_tile.cache_info()
        assert info.misses == 1
        assert info.hits == 0

        compositor.compose(img, 160, 128, rotate=False, bgr=False, is_artwork=False, overlay=overlay)
        info = _glyph_tile.cache_info()
        assert info.misses == 1
        assert info.hits == 1

    def test_a_second_profile_size_adds_a_miss(self):
        # 160x128 and 320x240 round to different dots-glyph pixel sizes, so
        # the second compose's tile key is genuinely new — a same-tier size
        # that happens to round to the identical glyph box would (correctly)
        # hit instead, which is why this picks two sizes confirmed to differ.
        compositor = DialDisplayCompositor()
        overlay = OverlayState(visible=True, dots=True)
        img_a = Image.new("RGB", (160, 128), (200, 150, 100))
        img_b = Image.new("RGB", (320, 240), (200, 150, 100))
        compositor.compose(img_a, 160, 128, rotate=False, bgr=False, is_artwork=False, overlay=overlay)
        assert _glyph_tile.cache_info().misses == 1

        compositor.compose(img_b, 320, 240, rotate=False, bgr=False, is_artwork=False, overlay=overlay)
        assert _glyph_tile.cache_info().misses == 2

    def test_list_compose_chevrons_plus_one_per_distinct_marker(self):
        compositor = DialDisplayCompositor()
        state = ListState(
            rows=(("CD Player", True), ("Kitchen", False, LOOP_GLYPH)),
            has_prev=True, has_next=True,
        )
        compositor.compose_list(160, 128, state, rotate=False, bgr=False)
        info = _glyph_tile.cache_info()
        # 3 chevrons (back/down/up) + 1 selected-dot marker + 1 loop marker.
        assert info.misses == 5
        assert info.hits == 0


class TestHaloLayerCacheAccounting:
    """cache_info() hit/miss accounting for _halo_layer."""

    @pytest.fixture(autouse=True)
    def _reset(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    def _panel(self):
        return Image.new("RGB", (160, 128), (200, 150, 100))

    def test_two_identical_composes_give_two_misses_then_two_hits(self):
        compositor = DialDisplayCompositor()
        img = self._panel()
        overlay = OverlayState(visible=True, artist="Artist", title="Title")
        compositor.compose(img, 160, 128, rotate=False, bgr=False, is_artwork=False, overlay=overlay)
        info = _halo_layer.cache_info()
        assert info.misses == 2
        assert info.hits == 0

        compositor.compose(img, 160, 128, rotate=False, bgr=False, is_artwork=False, overlay=overlay)
        info = _halo_layer.cache_info()
        assert info.misses == 2
        assert info.hits == 2

    def test_changing_the_artist_string_adds_one_miss(self):
        compositor = DialDisplayCompositor()
        img = self._panel()
        compositor.compose(
            img, 160, 128, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, artist="Artist", title="Title"),
        )
        misses_before = _halo_layer.cache_info().misses

        compositor.compose(
            img, 160, 128, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, artist="Someone Else", title="Title"),
        )
        assert _halo_layer.cache_info().misses == misses_before + 1

    def test_font_reset_between_composes_forces_misses(self):
        compositor = DialDisplayCompositor()
        img = self._panel()
        overlay = OverlayState(visible=True, artist="Artist", title="Title")
        compositor.compose(img, 160, 128, rotate=False, bgr=False, is_artwork=False, overlay=overlay)

        _reset_font_cache()
        compositor.compose(img, 160, 128, rotate=False, bgr=False, is_artwork=False, overlay=overlay)
        info = _halo_layer.cache_info()
        assert info.hits == 0
        assert info.misses == 2


class TestRenderCacheTileImmutability:
    """A cached tile or layer must never be mutated by anything downstream
    of the cache — a shared object handed out to many callers has to stay
    byte-identical to itself across all of them."""

    def test_glyph_tile_bytes_unchanged_across_repeated_composes(self):
        _reset_render_caches()
        compositor = DialDisplayCompositor()
        img = Image.new("RGB", (160, 128), (200, 150, 100))
        overlay = OverlayState(visible=True, dots=True)
        layout = layout_for(160, 128)
        w = layout.dots[2] - layout.dots[0]
        h = layout.dots[3] - layout.dots[1]

        compositor.compose(img, 160, 128, rotate=False, bgr=False, is_artwork=False, overlay=overlay)
        tile_before = _glyph_tile(GLYPH_TWO_DOTS, (0,), w, h, _GLYPH_SUPERSAMPLE).tobytes()

        for _ in range(10):
            compositor.compose(img, 160, 128, rotate=False, bgr=False, is_artwork=False, overlay=overlay)

        tile_after = _glyph_tile(GLYPH_TWO_DOTS, (0,), w, h, _GLYPH_SUPERSAMPLE).tobytes()
        assert tile_before == tile_after

    def test_halo_layer_bytes_unchanged_across_repeated_composes(self):
        _reset_font_cache()
        compositor = DialDisplayCompositor()
        img = Image.new("RGB", (160, 128), (200, 150, 100))
        overlay = OverlayState(visible=True, artist="Artist", title="Title")

        compositor.compose(img, 160, 128, rotate=False, bgr=False, is_artwork=False, overlay=overlay)
        info_before = _halo_layer.cache_info()
        assert info_before.currsize >= 1

        for _ in range(10):
            compositor.compose(img, 160, 128, rotate=False, bgr=False, is_artwork=False, overlay=overlay)

        # Ten more identical composes must be ten more hits, not ten more
        # misses — if the cached layer had been mutated in place, the key
        # would still match but a later crop/composite would see different
        # bytes than the first hit did.
        info_after = _halo_layer.cache_info()
        assert info_after.currsize == info_before.currsize
        assert info_after.hits >= 10


class TestRenderCacheLruBound:
    """Both caches are bounded (a 512 MB-class board): after more distinct
    keys than maxsize are produced, currsize must settle at maxsize, never
    grow past it."""

    def test_glyph_tile_currsize_settles_at_maxsize(self):
        _reset_render_caches()
        for w in range(_glyph_tile.cache_info().maxsize + 20):
            _glyph_tile(GLYPH_CHEVRON, ("left", True), 10 + w, 10, 4)
        info = _glyph_tile.cache_info()
        assert info.currsize == info.maxsize == 48

    def test_halo_layer_currsize_settles_at_maxsize(self):
        _reset_font_cache()
        compositor = DialDisplayCompositor()
        img = Image.new("RGB", (160, 128), (200, 150, 100))
        maxsize = _halo_layer.cache_info().maxsize
        for i in range(maxsize + 10):
            compositor.compose(
                img, 160, 128, rotate=False, bgr=False, is_artwork=False,
                overlay=OverlayState(visible=True, artist=f"Artist {i}"),
            )
        info = _halo_layer.cache_info()
        assert info.currsize == info.maxsize == 16
