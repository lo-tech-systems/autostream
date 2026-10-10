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
    DialDisplayCompositor,
    ListState,
    LOOP_GLYPH,
    OverlayState,
    RepeatViewState,
    _pad_px,
    _reset_font_cache,
    _scaled_px,
    _truncate_to_width,
    format_mmss,
)
from dial_touch_layout import (  # noqa: E402
    TouchZone,
    layout_for,
    list_layout_for,
    repeat_layout_for,
    zones_for,
)


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

        def fake_transform(image, width, height):
            calls.append((image, width, height))
            return sentinel

        with patch("dial_display_compositor.transform_artwork_for_panel", fake_transform):
            result = compositor.compose(
                raw, 160, 128,
                rotate=False, bgr=False, is_artwork=True,
            )
        assert calls == [(raw, 160, 128)]
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
    geometry _draw_repeat() itself computes."""
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
