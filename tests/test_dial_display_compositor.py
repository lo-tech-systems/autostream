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
import dataclasses
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
    BG_CHASSIS,
    BODY_COMPACT_CONTROLS,
    BODY_COMPACT_LIST,
    BODY_COMPACT_REPLAY,
    BODY_COMPACT_TOGGLE,
    BODY_CENTRED_LABEL,
    BODY_EQ_BARS,
    BODY_IDLE_BADGE,
    BODY_INFO_VALUE,
    BODY_LIST_ROWS,
    BODY_NONE,
    BODY_NOW_PLAYING,
    BODY_REPEAT_LINE,
    BODY_REPEAT_ROW,
    BODY_TOGGLE_ROW,
    BODY_WARNING,
    EQ_LIMIT_DB,
    Body,
    DialDisplayCompositor,
    EqViewState,
    FOOTER_LABELS,
    FOOTER_LIST_BAR,
    FOOTER_LIST_RAIL,
    FOOTER_NONE,
    FOOTER_VOLUME,
    FOOTER_VOLUME_MUTE,
    Frame,
    GLYPH_CHEVRON,
    GLYPH_CROSS,
    GLYPH_INFO,
    GLYPH_MUTE,
    GLYPH_PAGE_DOTS,
    GLYPH_PLAY,
    GLYPH_RESTART,
    GLYPH_STOP,
    GLYPH_TWO_DOTS,
    GLYPH_WIFI,
    Header,
    InfoValueView,
    ListState,
    NoWifiView,
    OutputViewState,
    PLAY_GLYPH,
    OverlayState,
    RepeatViewState,
    RESTARTING_TEXT,
    SdHealthView,
    STARTING_TEXT,
    WarningView,
    WIFI_GREY,
    WIFI_OFF,
    WIFI_RED,
    WIFI_SIGNAL,
    _BODY_RENDERERS,
    _ALARM_RGB,
    _CARD_FILL_RGB,
    _DIMMED_GLYPH_RGB,
    _FOOTER_RENDERERS,
    _GLYPH_PAINTERS,
    _GLYPH_RGB,
    _GLYPH_SUPERSAMPLE,
    _INFO_GLYPH_FRACTION,
    _INVERTED_GLYPH_RGB,
    _LIST_BG_RGB,
    OVERLAY_DIM_FACTOR,
    _COMPACT_PICKER_TITLE,
    _COMPACT_SMALL_GLYPH_FRACTION,
    _centred_box,
    _compact_controls_frame,
    _compact_glyph_box,
    _compact_list_frame,
    _compact_repeat_frame,
    _compact_small_glyph_box,
    _compose_frame,
    _draw_compact_list_row,
    _draw_speaker_glyph,
    _eq_frame,
    _eq_pressed_rects,
    _fit_value_lines,
    _glyph_tile,
    _halo_layer,
    _load_font,
    _now_playing_frame,
    _pad_px,
    _repeat_frame,
    _reset_font_cache,
    _reset_render_caches,
    _scaled_px,
    _text_size,
    _truncate_to_width,
    _zone_rect,
    format_mmss,
)
from dial_touch_layout import (  # noqa: E402
    CONTENT_BASE,
    CONTENT_COMPACT,
    CONTENT_LARGE,
    FONT_BODY_MAX_PX,
    FONT_READOUT_MAX_PX,
    GEOMETRY_EQ,
    GEOMETRY_INFO,
    GEOMETRY_LIST,
    GEOMETRY_MAIN,
    GEOMETRY_NOWIFI,
    GEOMETRY_REPEAT,
    GEOMETRY_REPEAT_REPLAY,
    GEOMETRY_SDHEALTH,
    COMPACT_PICKER_LEFT_FRACTION,
    CompactLayout,
    CompactPickerLayout,
    TouchZone,
    compact_layout_for,
    compact_picker_layout_for,
    eq_layout_for,
    idle_layout_for,
    info_value_layout_for,
    layout_for,
    list_layout_for,
    metrics_for,
    nowifi_layout_for,
    repeat_layout_for,
    sdhealth_layout_for,
    warning_layout_for,
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

# The two shipped compact panels — 1.3in 240x240 and 1.44in 128x128.
_COMPACT_240 = metrics_for(240, 240, 0.0973)
_COMPACT_128 = metrics_for(128, 128, 0.2021)


def _marked_image(size=(4, 4)):
    """A small asymmetric image so a 180 degree rotation is detectable."""
    image = Image.new("RGB", size, (0, 0, 0))
    image.putpixel((0, 0), (255, 0, 0))
    return image


def _diff_bbox(a: Image.Image, b: Image.Image):
    """Bounding box (left, upper, right, lower) of every pixel where *a* and
    *b* differ, or None when they are identical — a compact way to assert
    both "this drew something" and "it stayed inside its rect"."""
    from PIL import ImageChops

    return ImageChops.difference(a, b).getbbox()


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
        compositor.compose(
            Image.new("RGB", (_RICH_METRICS.width, _RICH_METRICS.height), (80, 80, 80)),
            _RICH_METRICS.width, _RICH_METRICS.height,
            rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, artist="Artist", title="Title", name="Kitchen"),
            metrics=_RICH_METRICS, reveal_progress=0.5,
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

    def test_compose_idle_holds_no_attributes_that_change_between_calls(self, compositor):
        before = dict(vars(compositor))
        base = Image.new("RGB", (160, 128), (32, 32, 32))
        compositor.compose_idle(base, 160, 128, rotate=False, bgr=False)
        after = dict(vars(compositor))
        assert before == after == {}

    def test_compose_list_info_variant_holds_no_attributes_that_change_between_calls(self, compositor):
        # The read-only info variant (title + plain_background set) adds no
        # instance state either.
        before = dict(vars(compositor))
        state = ListState(
            rows=(("Dial name", False, "Kitchen"),), title="Info", plain_background=True,
        )
        compositor.compose_list(160, 128, state, rotate=False, bgr=False)
        after = dict(vars(compositor))
        assert before == after == {}

    def test_compose_info_value_holds_no_attributes_that_change_between_calls(self, compositor):
        before = dict(vars(compositor))
        view = InfoValueView(label="IPv4", value="10.0.0.5")
        compositor.compose_info_value(240, 240, view, rotate=False, bgr=False)
        after = dict(vars(compositor))
        assert before == after == {}

    def test_compose_info_value_same_inputs_produce_same_output(self, compositor):
        view = InfoValueView(label="IPv4", value="10.0.0.5")
        first = compositor.compose_info_value(240, 240, view, rotate=False, bgr=False)
        second = compositor.compose_info_value(240, 240, view, rotate=False, bgr=False)
        assert list(first.getdata()) == list(second.getdata())

    def test_compose_nowifi_holds_no_attributes_that_change_between_calls(self, compositor):
        before = dict(vars(compositor))
        base = Image.new("RGB", (160, 128), (32, 32, 32))
        compositor.compose_nowifi(base, 160, 128, NoWifiView(), rotate=False, bgr=False)
        compositor.compose_nowifi(None, 240, 240, NoWifiView(pressed=TouchZone.NOWIFI_RESTART),
                                  rotate=True, bgr=True, metrics=metrics_for(240, 240, 0.0973))
        compositor.compose_restarting(160, 128, rotate=False, bgr=False)
        compositor.compose_starting(160, 128, rotate=False, bgr=False)
        compositor.compose_idle(base, 160, 128, rotate=False, bgr=False, wifi_bars=2, wifi_style=WIFI_RED)
        compositor.compose_idle(base, 160, 128, rotate=False, bgr=False, wifi_style=WIFI_OFF)
        after = dict(vars(compositor))
        assert before == after == {}

    def test_compose_sdhealth_holds_no_attributes_that_change_between_calls(self, compositor):
        before = dict(vars(compositor))
        base = Image.new("RGB", (160, 128), (32, 32, 32))
        compositor.compose_sdhealth(base, 160, 128, SdHealthView(percent=12), rotate=False, bgr=False)
        compositor.compose_sdhealth(None, 240, 240, SdHealthView(pressed=TouchZone.SDHEALTH_DISMISS),
                                    rotate=True, bgr=True, metrics=metrics_for(240, 240, 0.0973))
        after = dict(vars(compositor))
        assert before == after == {}

    def test_compose_warning_holds_no_attributes_that_change_between_calls(self, compositor):
        before = dict(vars(compositor))
        base = Image.new("RGB", (160, 128), (32, 32, 32))
        compositor.compose_warning(
            base, 160, 128,
            WarningView(title="One", buttons=("Dismiss",), geometry=GEOMETRY_SDHEALTH),
            rotate=False, bgr=False,
        )
        compositor.compose_warning(
            None, 240, 240,
            WarningView(title="Two", buttons=("Dismiss", "Restart"), geometry=GEOMETRY_NOWIFI,
                        pressed=TouchZone.NOWIFI_RESTART),
            rotate=True, bgr=True, metrics=metrics_for(240, 240, 0.0973),
        )
        compositor.compose_warning(
            base, 320, 240,
            WarningView(title="Three", message="detail", buttons=("A", "B", "C"), geometry=GEOMETRY_NOWIFI),
            rotate=False, bgr=False, metrics=metrics_for(320, 240, 0.1778),
        )
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
    from dial_display_compositor import _MARKER_BOX_FRACTION

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
        from dial_display_compositor import GLYPH_PLAY, _draw_glyph as real_draw_glyph

        calls = []

        def spy(img, rect, kind, *params, **kwargs):
            calls.append(kind)
            return real_draw_glyph(img, rect, kind, *params, **kwargs)

        with patch("dial_display_compositor._draw_glyph", side_effect=spy):
            compositor.compose_list(
                width, height, ListState(rows=(("Kitchen", False),)), rotate=False, bgr=False, metrics=metrics,
            )
            compositor.compose_list(
                width, height, ListState(rows=(("Kitchen", False, "42:10"),)),
                rotate=False, bgr=False, metrics=metrics,
            )
        assert GLYPH_PLAY not in calls

    def test_marker_never_raises_with_no_font(self, compositor):
        with patch("dial_display_compositor.ImageFont.truetype", side_effect=OSError("no font")), \
             patch("dial_display_compositor.ImageFont.load_default", side_effect=OSError("no default")):
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

    def test_header_readout_unslashed_regardless_of_muted(self, compositor):
        """The header glyph is never slashed on any screen, the repeat
        screen's display-only readout included -- mute has one home, the
        footer's own glyph and wash (see the main-screen footer tests)."""
        layout = repeat_layout_for(160, 128)
        unmuted = compositor.compose_repeat(160, 128, _repeat_state(muted=False), rotate=False, bgr=False)
        muted = compositor.compose_repeat(160, 128, _repeat_state(muted=True), rotate=False, bgr=False)
        assert list(unmuted.crop(layout.volume_cluster).getdata()) == list(
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
        layout = repeat_layout_for(160, 128)
        unpressed = compositor.compose_repeat(160, 128, _repeat_state(), rotate=False, bgr=False)
        pressed = compositor.compose_repeat(
            160, 128, _repeat_state(pressed=TouchZone.MUTE), rotate=False, bgr=False,
        )
        assert list(unpressed.getdata()) == list(pressed.getdata())


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

    def test_renders_the_base_plus_the_info_badge_only(self, compositor):
        # Every idle frame now carries the "i" badge and the Wi-Fi glyph
        # (both show on the plain logo too, not only the replay-available
        # one), so the only pixels that ever differ from the plain base are
        # the ones inside one of their two boxes.
        base = self._logo()
        result = compositor.compose_idle(base, 160, 128, rotate=False, bgr=False)
        idle = idle_layout_for(160, 128)
        info, wifi = idle.info, idle.wifi
        for y in range(128):
            for x in range(160):
                if info[0] <= x < info[2] and info[1] <= y < info[3]:
                    continue
                if wifi[0] <= x < wifi[2] and wifi[1] <= y < wifi[3]:
                    continue
                assert result.getpixel((x, y)) == base.getpixel((x, y))

    def test_info_badge_drawn_inside_its_own_box(self, compositor):
        base = self._logo()
        result = compositor.compose_idle(base, 160, 128, rotate=False, bgr=False)
        info = idle_layout_for(160, 128).info
        assert list(result.crop(info).getdata()) != list(base.crop(info).getdata())

    def test_wifi_glyph_drawn_inside_its_own_box(self, compositor):
        base = self._logo()
        result = compositor.compose_idle(base, 160, 128, rotate=False, bgr=False)
        wifi = idle_layout_for(160, 128).wifi
        assert list(result.crop(wifi).getdata()) != list(base.crop(wifi).getdata())

    def test_none_base_returns_none(self, compositor):
        assert compositor.compose_idle(None, 160, 128, rotate=False, bgr=False) is None

    def test_never_raises_with_a_failing_painter(self, compositor):
        base = self._logo()
        with patch("dial_display_compositor._glyph_tile", side_effect=RuntimeError("boom")):
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
# GLYPH_WIFI — the idle screen's Wi-Fi status glyph.
# ---------------------------------------------------------------------------

class TestWifiGlyph:
    """GLYPH_WIFI: a dot with three arcs fanning upward; the innermost
    `lit` arcs and the dot in the given colour, the rest dimmed."""

    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_render_caches()
        yield
        _reset_render_caches()

    S = 60

    def _arc_points(self):
        # The vertical centre line crosses each arc at dot_cy - r_i.
        s = self.S
        dot_cy = 0.56 * s
        outer = 0.33 * s
        return [(s // 2, round(dot_cy - outer * f)) for f in (0.42, 0.71, 1.00)], (s // 2, round(dot_cy))

    def test_registered_painter(self):
        assert GLYPH_WIFI in _GLYPH_PAINTERS

    def test_corners_transparent(self):
        tile = _glyph_tile(GLYPH_WIFI, (3, _GLYPH_RGB), self.S, self.S, 4)
        px = tile.load()
        for corner in ((0, 0), (self.S - 1, 0), (0, self.S - 1), (self.S - 1, self.S - 1)):
            assert px[corner][3] == 0

    # The smallest (innermost) arc's own antialiasing softens its sampled
    # centreline pixel a little after the supersample/LANCZOS downsample —
    # comfortably opaque, just short of the outer arcs' own full 255. 150
    # still rules out anything actually transparent.
    _MIN_OPAQUE_ALPHA = 150

    @pytest.mark.parametrize("lit", [0, 1, 2, 3])
    def test_innermost_lit_arcs_are_white_and_the_rest_grey(self, lit):
        tile = _glyph_tile(GLYPH_WIFI, (lit, _GLYPH_RGB), self.S, self.S, 4)
        px = tile.load()
        arcs, dot = self._arc_points()
        for i, (x, y) in enumerate(arcs):
            r, g, b, a = px[x, y]
            assert a > self._MIN_OPAQUE_ALPHA
            if i < lit:
                assert r > 150 and g > 150 and b > 150
            else:
                assert r < 130 and g < 130 and b < 130
        r, g, b, a = px[dot]
        assert a > self._MIN_OPAQUE_ALPHA
        assert (r > 150) == (lit > 0)

    def test_alarm_colour_reaches_every_part(self):
        tile = _glyph_tile(GLYPH_WIFI, (3, _ALARM_RGB), self.S, self.S, 4)
        px = tile.load()
        arcs, dot = self._arc_points()
        for x, y in arcs + [dot]:
            r, g, b, a = px[x, y]
            assert a > self._MIN_OPAQUE_ALPHA and r > 150 and g < 130 and b < 130

    def test_symmetric_about_the_vertical_centre(self):
        # Unlike the "i" badge's plain ellipse/rectangle shapes, Pillow's arc
        # rasterizer is not pixel-exact about a vertical centreline once
        # supersampled and downsampled with LANCZOS: a handful of edge pixels
        # on the arcs' own antialiased boundary land a few alpha levels off
        # their mirror. A generous per-channel tolerance (and skipping pixels
        # where both sides are already near-transparent noise) still catches
        # any genuine left/right asymmetry in the glyph's own geometry.
        s = 61
        tile = _glyph_tile(GLYPH_WIFI, (2, _GLYPH_RGB), s, s, 4)
        px = tile.load()
        for y in range(0, s, 5):
            for dx in range(0, s // 2, 5):
                left, right = px[dx, y], px[s - 1 - dx, y]
                if left[3] < 30 and right[3] < 30:
                    continue
                assert all(abs(left[i] - right[i]) <= 40 for i in range(4)), (dx, y, left, right)

    def test_lit_and_colour_are_distinct_cache_keys(self):
        _glyph_tile.cache_clear()
        _glyph_tile(GLYPH_WIFI, (1, _GLYPH_RGB), 30, 30, 4)
        _glyph_tile(GLYPH_WIFI, (2, _GLYPH_RGB), 30, 30, 4)
        _glyph_tile(GLYPH_WIFI, (2, _ALARM_RGB), 30, 30, 4)
        _glyph_tile(GLYPH_WIFI, (2, _ALARM_RGB), 30, 30, 4)
        info = _glyph_tile.cache_info()
        assert info.misses == 3 and info.hits == 1


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
        # And the rest of the frame (info badge included) is byte-identical.
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
        # Off means the painter is never invoked: only the "i" badge's tile
        # is built (one lru miss), nothing is cached for the wifi corner.
        _reset_render_caches()
        compositor.compose_idle(self._logo(), 160, 128, rotate=False, bgr=False, wifi_style=WIFI_OFF)
        assert _glyph_tile.cache_info().misses == 1

    def test_info_badge_disc_radius_is_a_quarter_of_the_zone(self, compositor):
        # 0.42 * _INFO_GLYPH_FRACTION == 0.25 (to within a pixel at 320x240).
        assert abs(0.42 * _INFO_GLYPH_FRACTION - 0.25) < 0.01
        metrics = metrics_for(320, 240, 0.1778)
        frame = compositor.compose_idle(self._logo((320, 240)), 320, 240, rotate=False, bgr=False, metrics=metrics)
        x0, y0, x1, y1 = idle_layout_for(320, 240, metrics=metrics).info
        cx, cy = (x0 + x1) // 2, (y0 + y1) // 2
        # The disc's own top edge sits ~11 px above the centre on a 45 px
        # zone (box 27 px, disc radius 0.42 * 27 = 11.3): 9 px up is inside
        # the disc and clear of the "i" dot, 14 px up is outside the box.
        assert frame.getpixel((cx, cy - 9))[0] > 200
        assert frame.getpixel((cx, cy - 14)) == (32, 32, 32)


# ---------------------------------------------------------------------------
# compose_nowifi — the No-WiFi page: dimmed base, card off compact,
# crosshair, press wash.
# ---------------------------------------------------------------------------

class TestComposeNoWifi:
    """compose_nowifi(): dimmed base, card off compact, crosshair, press wash."""

    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    def _base(self, size):
        return Image.new("RGB", size, (200, 200, 200))

    def test_rich_card_geometry_is_pinned(self):
        layout = nowifi_layout_for(320, 240, metrics=metrics_for(320, 240, 0.1778))
        assert layout.card == (41, 48, 278, 192)
        assert layout.message == (41, 48, 278, 114)
        assert layout.dismiss == (41, 126, 153, 192)
        assert layout.restart == (166, 126, 278, 192)
        assert (layout.divider_x, layout.divider_y) == (159, 120)

    def test_backdrop_outside_the_card_is_dimmed_base(self, compositor):
        metrics = metrics_for(320, 240, 0.1778)
        frame = compositor.compose_nowifi(self._base((320, 240)), 320, 240, NoWifiView(),
                                          rotate=False, bgr=False, metrics=metrics)
        dimmed = round(200 * OVERLAY_DIM_FACTOR)
        for xy in ((2, 2), (317, 2), (2, 237), (20, 120)):
            assert frame.getpixel(xy) == (dimmed, dimmed, dimmed)

    def test_card_fill_outline_and_shadow(self, compositor):
        metrics = metrics_for(320, 240, 0.1778)
        frame = compositor.compose_nowifi(self._base((320, 240)), 320, 240, NoWifiView(),
                                          rotate=False, bgr=False, metrics=metrics)
        card = nowifi_layout_for(320, 240, metrics=metrics).card
        # An interior point away from text/dividers is the flat fill.
        assert frame.getpixel((card[0] + 6, card[1] + 6)) == _CARD_FILL_RGB
        # The outline is a thin translucent white edge on the card's own
        # border: lighter than the fill in every channel, but not fully
        # white (it is blended, not opaque).
        outline_px = frame.getpixel((card[0], card[1] + 20))
        assert all(outline_px[i] > _CARD_FILL_RGB[i] for i in range(3))
        assert outline_px != (255, 255, 255)
        # The shadow darkens the dimmed backdrop just outside the bottom-right corner.
        dimmed = round(200 * OVERLAY_DIM_FACTOR)
        assert frame.getpixel((card[2] + 1, card[3] - 20))[0] < dimmed

    def test_crosshair_horizontal_full_card_width_vertical_bottom_row_only(self, compositor):
        metrics = metrics_for(320, 240, 0.1778)
        frame = compositor.compose_nowifi(self._base((320, 240)), 320, 240, NoWifiView(),
                                          rotate=False, bgr=False, metrics=metrics)
        l = nowifi_layout_for(320, 240, metrics=metrics)
        for x in (l.card[0] + 1, l.divider_x, l.card[2] - 2):
            assert frame.getpixel((x, l.divider_y)) == (255, 255, 255)
        assert frame.getpixel((l.divider_x, l.dismiss[1] + 5)) == (255, 255, 255)
        assert frame.getpixel((l.divider_x, l.card[3] - 2)) == (255, 255, 255)
        # No vertical line through the message row (just inside the card fill,
        # clear of the text: sample near the row's top-left).
        assert frame.getpixel((l.divider_x, l.message[1] + 4)) == _CARD_FILL_RGB

    def test_pressed_dismiss_washes_only_its_cell(self, compositor):
        metrics = metrics_for(320, 240, 0.1778)
        plain = compositor.compose_nowifi(self._base((320, 240)), 320, 240, NoWifiView(),
                                          rotate=False, bgr=False, metrics=metrics)
        pressed = compositor.compose_nowifi(self._base((320, 240)), 320, 240,
                                            NoWifiView(pressed=TouchZone.NOWIFI_DISMISS),
                                            rotate=False, bgr=False, metrics=metrics)
        l = nowifi_layout_for(320, 240, metrics=metrics)
        p_in = pressed.getpixel((l.dismiss[0] + 3, l.dismiss[1] + 3))
        assert p_in[0] > _CARD_FILL_RGB[0]                 # washed brighter than the fill
        assert plain.getpixel((l.dismiss[0] + 3, l.dismiss[1] + 3)) == _CARD_FILL_RGB
        assert pressed.getpixel((l.restart[0] + 3, l.restart[1] + 3)) == _CARD_FILL_RGB
        assert list(pressed.crop(l.message).getdata()) == list(plain.crop(l.message).getdata())

    def test_stale_zone_washes_nothing(self, compositor):
        a = compositor.compose_nowifi(self._base((160, 128)), 160, 128, NoWifiView(), rotate=False, bgr=False)
        b = compositor.compose_nowifi(self._base((160, 128)), 160, 128, NoWifiView(pressed=TouchZone.MUTE),
                                      rotate=False, bgr=False)
        assert list(a.getdata()) == list(b.getdata())

    def test_none_base_falls_back_to_chassis(self, compositor):
        frame = compositor.compose_nowifi(None, 160, 128, NoWifiView(), rotate=False, bgr=False)
        dimmed = tuple(round(c * OVERLAY_DIM_FACTOR) for c in _LIST_BG_RGB)
        assert frame.getpixel((1, 1)) == dimmed

    def test_compact_is_full_screen_two_by_two_no_card(self, compositor):
        metrics = metrics_for(240, 240, 0.0973)
        frame = compositor.compose_nowifi(self._base((240, 240)), 240, 240, NoWifiView(),
                                          rotate=False, bgr=False, metrics=metrics)
        dimmed = round(200 * OVERLAY_DIM_FACTOR)
        assert frame.getpixel((2, 2)) == (dimmed, dimmed, dimmed)       # no card fill on compact
        l = nowifi_layout_for(240, 240, metrics=metrics)
        assert (l.dismiss, l.restart, l.divider_x, l.divider_y) == ((0, 126, 114, 240), (126, 126, 240, 240), 120, 120)
        assert frame.getpixel((5, 120)) == (255, 255, 255)              # horizontal, full width
        assert frame.getpixel((120, 200)) == (255, 255, 255)            # vertical, bottom row
        assert frame.getpixel((120, 8)) == (dimmed, dimmed, dimmed)     # none in the top row

    def test_compact_pressed_restart_washes_its_cell(self, compositor):
        metrics = metrics_for(240, 240, 0.0973)
        plain = compositor.compose_nowifi(self._base((240, 240)), 240, 240, NoWifiView(),
                                          rotate=False, bgr=False, metrics=metrics)
        pressed = compositor.compose_nowifi(self._base((240, 240)), 240, 240,
                                            NoWifiView(pressed=TouchZone.NOWIFI_RESTART),
                                            rotate=False, bgr=False, metrics=metrics)
        assert pressed.getpixel((130, 130))[0] > plain.getpixel((130, 130))[0]
        assert pressed.getpixel((5, 130)) == plain.getpixel((5, 130))

    def test_rotate_and_bgr_applied(self, compositor):
        base = self._base((160, 128))
        plain = compositor.compose_nowifi(base, 160, 128, NoWifiView(), rotate=False, bgr=False)
        rotated = compositor.compose_nowifi(base, 160, 128, NoWifiView(), rotate=True, bgr=False)
        assert list(rotated.getdata()) == list(plain.transpose(Image.ROTATE_180).getdata())
        swapped = compositor.compose_nowifi(base, 160, 128, NoWifiView(), rotate=False, bgr=True)
        assert list(swapped.getdata()) == list(Image.merge("RGB", plain.split()[::-1]).getdata())

    def test_never_raises_without_a_font(self, compositor):
        with patch("dial_display_compositor._load_font", return_value=None):
            frame = compositor.compose_nowifi(self._base((160, 128)), 160, 128, NoWifiView(),
                                              rotate=False, bgr=False)
        assert frame.size == (160, 128)


# ---------------------------------------------------------------------------
# compose_sdhealth — the SD card warning: the No-WiFi page's own dressing,
# a fixed title/body over one Dismiss cell, no vertical divider.
# ---------------------------------------------------------------------------

class TestComposeSdHealth:
    """compose_sdhealth(): dimmed base, card off compact, one Dismiss cell,
    press wash, no vertical divider (mirrors TestComposeNoWifi)."""

    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    def _base(self, size):
        return Image.new("RGB", size, (200, 200, 200))

    def test_backdrop_outside_the_card_is_dimmed_base(self, compositor):
        metrics = metrics_for(320, 240, 0.1778)
        frame = compositor.compose_sdhealth(self._base((320, 240)), 320, 240, SdHealthView(percent=15),
                                            rotate=False, bgr=False, metrics=metrics)
        dimmed = round(200 * OVERLAY_DIM_FACTOR)
        for xy in ((2, 2), (317, 2), (2, 237), (20, 120)):
            assert frame.getpixel(xy) == (dimmed, dimmed, dimmed)

    def test_card_fill_present_off_compact(self, compositor):
        metrics = metrics_for(320, 240, 0.1778)
        frame = compositor.compose_sdhealth(self._base((320, 240)), 320, 240, SdHealthView(percent=15),
                                            rotate=False, bgr=False, metrics=metrics)
        card = sdhealth_layout_for(320, 240, metrics=metrics).card
        assert frame.getpixel((card[0] + 6, card[1] + 6)) == _CARD_FILL_RGB

    def test_compact_is_full_screen_no_card(self, compositor):
        metrics = metrics_for(240, 240, 0.0973)
        frame = compositor.compose_sdhealth(self._base((240, 240)), 240, 240, SdHealthView(percent=15),
                                            rotate=False, bgr=False, metrics=metrics)
        dimmed = round(200 * OVERLAY_DIM_FACTOR)
        assert frame.getpixel((2, 2)) == (dimmed, dimmed, dimmed)   # no card fill on compact

    def test_no_vertical_divider(self, compositor):
        metrics = metrics_for(320, 240, 0.1778)
        frame = compositor.compose_sdhealth(self._base((320, 240)), 320, 240, SdHealthView(percent=15),
                                            rotate=False, bgr=False, metrics=metrics)
        l = sdhealth_layout_for(320, 240, metrics=metrics)
        # The horizontal divider spans the card; no vertical line exists at
        # any x through the dismiss row (unlike No-WiFi's two-cell split).
        assert frame.getpixel((l.card[0] + 1, l.divider_y)) == (255, 255, 255)
        mid_x = (l.dismiss[0] + l.dismiss[2]) // 2
        assert frame.getpixel((mid_x, l.dismiss[1] + 2)) != (255, 255, 255)

    def test_pressed_dismiss_washes_its_cell(self, compositor):
        metrics = metrics_for(320, 240, 0.1778)
        plain = compositor.compose_sdhealth(self._base((320, 240)), 320, 240, SdHealthView(percent=15),
                                            rotate=False, bgr=False, metrics=metrics)
        pressed = compositor.compose_sdhealth(
            self._base((320, 240)), 320, 240,
            SdHealthView(percent=15, pressed=TouchZone.SDHEALTH_DISMISS),
            rotate=False, bgr=False, metrics=metrics,
        )
        l = sdhealth_layout_for(320, 240, metrics=metrics)
        p_in = pressed.getpixel((l.dismiss[0] + 3, l.dismiss[1] + 3))
        assert p_in[0] > _CARD_FILL_RGB[0]
        assert plain.getpixel((l.dismiss[0] + 3, l.dismiss[1] + 3)) == _CARD_FILL_RGB

    def test_foreign_pressed_zone_washes_nothing(self, compositor):
        a = compositor.compose_sdhealth(self._base((160, 128)), 160, 128, SdHealthView(percent=15),
                                        rotate=False, bgr=False)
        b = compositor.compose_sdhealth(self._base((160, 128)), 160, 128,
                                        SdHealthView(percent=15, pressed=TouchZone.MUTE),
                                        rotate=False, bgr=False)
        assert list(a.getdata()) == list(b.getdata())

    def test_none_base_falls_back_to_chassis(self, compositor):
        frame = compositor.compose_sdhealth(None, 160, 128, SdHealthView(percent=15), rotate=False, bgr=False)
        dimmed = tuple(round(c * OVERLAY_DIM_FACTOR) for c in _LIST_BG_RGB)
        assert frame.getpixel((1, 1)) == dimmed

    def test_rotate_and_bgr_applied_last(self, compositor):
        base = self._base((160, 128))
        plain = compositor.compose_sdhealth(base, 160, 128, SdHealthView(percent=15), rotate=False, bgr=False)
        rotated = compositor.compose_sdhealth(base, 160, 128, SdHealthView(percent=15), rotate=True, bgr=False)
        assert list(rotated.getdata()) == list(plain.transpose(Image.ROTATE_180).getdata())
        swapped = compositor.compose_sdhealth(base, 160, 128, SdHealthView(percent=15), rotate=False, bgr=True)
        assert list(swapped.getdata()) == list(Image.merge("RGB", plain.split()[::-1]).getdata())

    def test_percent_none_uses_the_no_percent_line(self, compositor):
        with patch("dial_display_compositor._draw_label_centered") as mock_draw:
            compositor.compose_sdhealth(self._base((160, 128)), 160, 128, SdHealthView(percent=None),
                                        rotate=False, bgr=False)
        texts = [call.args[2] for call in mock_draw.call_args_list]
        assert "Replace it soon" in texts
        assert not any("% left" in t for t in texts)

    def test_percent_fills_the_body_line(self, compositor):
        with patch("dial_display_compositor._draw_label_centered") as mock_draw:
            compositor.compose_sdhealth(self._base((160, 128)), 160, 128, SdHealthView(percent=12),
                                        rotate=False, bgr=False)
        texts = [call.args[2] for call in mock_draw.call_args_list]
        assert "12% left, replace soon" in texts

    def test_never_raises_without_a_font(self, compositor):
        with patch("dial_display_compositor._load_font", return_value=None):
            frame = compositor.compose_sdhealth(self._base((160, 128)), 160, 128, SdHealthView(percent=15),
                                                rotate=False, bgr=False)
        assert frame.size == (160, 128)


# ---------------------------------------------------------------------------
# compose_warning: the generic warning page compose_nowifi/compose_sdhealth
# are now thin adapters over. Byte-identity of the adapters against the
# generic call is the guard that the generalisation changed no pixel.
# ---------------------------------------------------------------------------

class TestComposeWarning:
    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    def _base(self, size):
        return Image.new("RGB", size, (200, 200, 200))

    @pytest.mark.parametrize("width,height,mm_per_px", [
        (160, 128, None), (320, 240, 0.1778), (240, 240, 0.0973),
    ])
    @pytest.mark.parametrize("pressed", [None, TouchZone.NOWIFI_DISMISS, TouchZone.NOWIFI_RESTART])
    def test_nowifi_adapter_is_byte_identical_to_the_generic_call(self, compositor, width, height, mm_per_px, pressed):
        metrics = metrics_for(width, height, mm_per_px) if mm_per_px is not None else None
        base = self._base((width, height))
        adapter = compositor.compose_nowifi(base, width, height, NoWifiView(pressed=pressed),
                                            rotate=False, bgr=False, metrics=metrics)
        generic = compositor.compose_warning(
            base, width, height,
            WarningView(title="No WiFi", message="", buttons=("Dismiss", "Restart"),
                        geometry=GEOMETRY_NOWIFI, pressed=pressed),
            rotate=False, bgr=False, metrics=metrics,
        )
        assert list(adapter.getdata()) == list(generic.getdata())

    @pytest.mark.parametrize("width,height,mm_per_px", [
        (160, 128, None), (320, 240, 0.1778), (240, 240, 0.0973),
    ])
    @pytest.mark.parametrize("pressed", [None, TouchZone.SDHEALTH_DISMISS])
    def test_sdhealth_adapter_is_byte_identical_to_the_generic_call(self, compositor, width, height, mm_per_px, pressed):
        metrics = metrics_for(width, height, mm_per_px) if mm_per_px is not None else None
        base = self._base((width, height))
        adapter = compositor.compose_sdhealth(base, width, height, SdHealthView(percent=15, pressed=pressed),
                                              rotate=False, bgr=False, metrics=metrics)
        generic = compositor.compose_warning(
            base, width, height,
            WarningView(title="SD card low", message="15% left, replace soon", buttons=("Dismiss",),
                        geometry=GEOMETRY_SDHEALTH, pressed=pressed),
            rotate=False, bgr=False, metrics=metrics,
        )
        assert list(adapter.getdata()) == list(generic.getdata())

    def test_three_buttons_draw_two_vertical_dividers(self, compositor):
        metrics = metrics_for(320, 240, 0.1778)
        frame = compositor.compose_warning(
            self._base((320, 240)), 320, 240,
            WarningView(title="Three", buttons=("A", "B", "C"), geometry=GEOMETRY_NOWIFI),
            rotate=False, bgr=False, metrics=metrics,
        )
        layout = warning_layout_for(320, 240, buttons=3, metrics=metrics)
        for x in layout.divider_xs:
            assert frame.getpixel((x, layout.cells[0][1] + 5)) == (255, 255, 255)
            assert frame.getpixel((x, layout.message[1] + 4)) != (255, 255, 255)

    def test_never_raises_without_a_font(self, compositor):
        with patch("dial_display_compositor._load_font", return_value=None):
            frame = compositor.compose_warning(
                self._base((160, 128)), 160, 128,
                WarningView(title="Hi", buttons=("Dismiss",), geometry=GEOMETRY_SDHEALTH),
                rotate=False, bgr=False,
            )
        assert frame.size == (160, 128)

    def test_body_buttons_default_is_empty_and_frame_unchanged(self):
        assert Body() == Body(buttons=())


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
            assert frame.getpixel(xy) == _LIST_BG_RGB
        row = [frame.getpixel((x, height // 2)) for x in range(width)]
        ink_x = [x for x, p in enumerate(row) if p != _LIST_BG_RGB]
        assert ink_x
        # The ink's own bounding box is centred on the panel — a per-column
        # ink-count comparison would be thrown off by "Restarting..." itself
        # being visually denser at the start (solid letters) than the end
        # (three dots), which is a property of the string, not of centring.
        bbox_mid = (min(ink_x) + max(ink_x)) / 2
        assert abs(bbox_mid - width / 2) <= max(6, width * 0.08)

    def test_font_failure_leaves_the_flat_fill(self, compositor):
        with patch("dial_display_compositor._load_font", return_value=None):
            frame = compositor.compose_restarting(160, 128, rotate=False, bgr=False)
        assert set(frame.getdata()) == {_LIST_BG_RGB}


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
            assert frame.getpixel(xy) == _LIST_BG_RGB
        row = [frame.getpixel((x, height // 2)) for x in range(width)]
        ink_x = [x for x, p in enumerate(row) if p != _LIST_BG_RGB]
        assert ink_x
        bbox_mid = (min(ink_x) + max(ink_x)) / 2
        assert abs(bbox_mid - width / 2) <= max(6, width * 0.08)

    def test_font_failure_leaves_the_flat_fill(self, compositor):
        with patch("dial_display_compositor._load_font", return_value=None):
            frame = compositor.compose_starting(160, 128, rotate=False, bgr=False)
        assert set(frame.getdata()) == {_LIST_BG_RGB}

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

    def test_highlights_wash_before_pressed_and_nowhere_else(self):
        size = (160, 128)
        base = Image.new("RGB", size, (16, 16, 16))
        rect = (10, 10, 30, 30)
        outside = (100, 100, 120, 120)

        highlighted = _compose_frame(base, *size, Frame(BG_BASE, highlights=(rect,)), rotate=False, bgr=False)
        assert highlighted.getpixel((15, 15)) == (36, 36, 36)
        assert highlighted.getpixel(outside[:2]) == (16, 16, 16)

        both = _compose_frame(
            base, *size, Frame(BG_BASE, highlights=(rect,), pressed=(rect,)), rotate=False, bgr=False,
        )
        assert both.getpixel((15, 15)) == (96, 96, 96)

        pressed_only = _compose_frame(base, *size, Frame(BG_BASE, pressed=(rect,)), rotate=False, bgr=False)
        assert pressed_only.getpixel((15, 15)) == (82, 82, 82)


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

    def test_repeat_view_counter_second_defaults_to_none_and_is_not_drawn(self, compositor):
        state = RepeatViewState(
            name="Kitchen", layout="replaying", armed=True, line="0:12 / 3:45",
            start_enabled=True, stop_enabled=True, stop_pressed=False,
        )
        assert state.counter_second is None
        a = compositor.compose_repeat(160, 128, state, rotate=False, bgr=False)
        b = compositor.compose_repeat(
            160, 128, dataclasses.replace(state, counter_second=12), rotate=False, bgr=False,
        )
        assert a.tobytes() == b.tobytes()

    @pytest.mark.parametrize("size,mm", _METRICS_EQUIVALENCE_CASES)
    def test_compose_idle_unaffected_outside_the_info_badge(self, compositor, size, mm):
        # The idle frame's one deliberate density-dependent pixel region is
        # the "i" badge's own box (its side is 8mm by construction wherever
        # density is known — see dial_touch_layout.IdleLayout.info); every
        # other pixel stays exactly as before regardless of density.
        width, height = size
        base = _marked_image(size=(width, height))
        metrics = metrics_for(width, height, mm)
        plain = compositor.compose_idle(base, width, height, rotate=False, bgr=False)
        with_metrics = compositor.compose_idle(
            base, width, height, rotate=False, bgr=False, metrics=metrics,
        )
        idle_a = idle_layout_for(width, height)
        idle_b = idle_layout_for(width, height, metrics=metrics)
        boxes = (idle_a.info, idle_b.info, idle_a.wifi, idle_b.wifi)
        for y in range(height):
            for x in range(width):
                if any(bx0 <= x < bx1 and by0 <= y < by1 for bx0, by0, bx1, by1 in boxes):
                    continue
                assert plain.getpixel((x, y)) == with_metrics.getpixel((x, y))

    @pytest.mark.parametrize("size,mm", _METRICS_EQUIVALENCE_CASES)
    def test_album_ignored_on_the_base_tier(self, compositor, size, mm):
        # A tier with no album rect must render identically whether an
        # album string is set or not — the field is read nowhere the
        # layout has no rect for it.
        width, height = size
        base = _marked_image(size=(width, height))
        with_album = compositor.compose(
            base, width, height, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, artist="Artist", title="Title", album="Album"),
            metrics=metrics_for(width, height, mm),
        )
        without_album = compositor.compose(
            base, width, height, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, artist="Artist", title="Title", album=""),
            metrics=metrics_for(width, height, mm),
        )
        assert list(with_album.getdata()) == list(without_album.getdata())

    def test_album_ignored_on_the_rich_tier(self, compositor):
        width, height = _RICH_METRICS.width, _RICH_METRICS.height
        base = _marked_image(size=(width, height))
        with_album = compositor.compose(
            base, width, height, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, artist="Artist", title="Title", album="Album"),
            metrics=_RICH_METRICS,
        )
        without_album = compositor.compose(
            base, width, height, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, artist="Artist", title="Title", album=""),
            metrics=_RICH_METRICS,
        )
        assert list(with_album.getdata()) == list(without_album.getdata())


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
    add_main("album", album="Album Name")
    add_main("long_album", album=long_text)

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
    add_list("play_marker", ListState(rows=(("Kitchen", True, PLAY_GLYPH),)))
    add_list("play_marker_unchecked", ListState(rows=(("Kitchen", False, PLAY_GLYPH),)))
    add_list("mixed_markers", ListState(rows=(
        ("A", True), ("B", False, PLAY_GLYPH), ("C", True, PLAY_GLYPH),
    )))
    add_list("current_pressed", ListState(
        rows=(("CD Player", True), ("Kitchen", False), ("Study", False)),
        pressed=(TouchZone.LIST_ROW, 0),
    ))
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
    cases.append((
        "idle_down_grey",
        lambda c: c.compose_idle(logo, width, height, rotate=False, bgr=False, metrics=metrics, wifi_bars=0),
    ))
    cases.append((
        "idle_alarm",
        lambda c: c.compose_idle(
            logo, width, height, rotate=False, bgr=False, metrics=metrics, wifi_style=WIFI_RED,
        ),
    ))
    cases.append((
        "idle_bars3",
        lambda c: c.compose_idle(logo, width, height, rotate=False, bgr=False, metrics=metrics, wifi_bars=3),
    ))
    cases.append((
        "idle_off",
        lambda c: c.compose_idle(logo, width, height, rotate=False, bgr=False, metrics=metrics, wifi_style=WIFI_OFF),
    ))
    cases.append((
        "nowifi",
        lambda c: c.compose_nowifi(
            logo, width, height, NoWifiView(), rotate=False, bgr=False, metrics=metrics,
        ),
    ))
    cases.append((
        "nowifi_pressed",
        lambda c: c.compose_nowifi(
            logo, width, height, NoWifiView(pressed=TouchZone.NOWIFI_DISMISS),
            rotate=False, bgr=False, metrics=metrics,
        ),
    ))
    cases.append((
        "sdhealth",
        lambda c: c.compose_sdhealth(
            logo, width, height, SdHealthView(percent=15), rotate=False, bgr=False, metrics=metrics,
        ),
    ))
    cases.append((
        "sdhealth_pressed",
        lambda c: c.compose_sdhealth(
            logo, width, height, SdHealthView(percent=15, pressed=TouchZone.SDHEALTH_DISMISS),
            rotate=False, bgr=False, metrics=metrics,
        ),
    ))
    cases.append((
        "restarting",
        lambda c: c.compose_restarting(width, height, rotate=False, bgr=False, metrics=metrics),
    ))
    cases.append((
        "starting",
        lambda c: c.compose_starting(width, height, rotate=False, bgr=False, metrics=metrics),
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


class TestPlayGlyphTile:
    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_render_caches()
        yield
        _reset_render_caches()

    def test_every_glyph_kind_has_a_registered_painter(self):
        from dial_display_compositor import (
            GLYPH_ARM_DOT,
            GLYPH_MUTE,
            GLYPH_PAGE_DOTS,
            GLYPH_RESTART,
            GLYPH_STOP,
            _GLYPH_PAINTERS,
        )

        assert set(_GLYPH_PAINTERS) == {
            GLYPH_CHEVRON, GLYPH_TWO_DOTS, GLYPH_PAGE_DOTS, GLYPH_ARM_DOT, GLYPH_PLAY, GLYPH_CROSS, GLYPH_MUTE,
            GLYPH_RESTART, GLYPH_STOP, GLYPH_INFO, GLYPH_WIFI,
        }

    def test_tile_has_opaque_pixels_in_the_left_half_and_empty_corners(self):
        tile = _glyph_tile(GLYPH_PLAY, (), 24, 24, 4)
        assert tile.size == (24, 24)
        assert tile.mode == "RGBA"
        pixels = tile.load()
        assert pixels[10, 12][3] > 0  # left half, centre row — inside the triangle's base
        for corner in ((0, 0), (23, 0), (0, 23), (23, 23)):
            assert pixels[corner][3] == 0


class TestInfoGlyph:
    """GLYPH_INFO: a filled white disc with a dark "i" (dot + stem) cut
    from it, symmetric about the vertical centre — the idle screen's own
    information badge."""

    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_render_caches()
        yield
        _reset_render_caches()

    def test_registered_painter(self):
        assert GLYPH_INFO in _GLYPH_PAINTERS

    def test_disc_is_opaque_white_with_transparent_corners(self):
        w, h = 60, 60
        tile = _glyph_tile(GLYPH_INFO, (), w, h, 4)
        assert tile.size == (w, h)
        assert tile.mode == "RGBA"
        pixels = tile.load()
        for corner in ((0, 0), (w - 1, 0), (0, h - 1), (w - 1, h - 1)):
            assert pixels[corner][3] == 0
        # A point on the disc, away from the "i", is opaque white.
        edge_of_disc = pixels[w // 2, 2]
        assert edge_of_disc[3] > 0
        assert edge_of_disc[:3] == (255, 255, 255)

    def test_dot_and_stem_are_dark_inside_the_white_disc(self):
        w, h = 60, 60
        tile = _glyph_tile(GLYPH_INFO, (), w, h, 4)
        pixels = tile.load()
        cx, cy = w // 2, h // 2
        # The dot sits above the centre, the stem below it — both cut in a
        # dark colour, distinct from the disc's own white.
        dot_pixel = pixels[cx, cy - round(h * 0.16)]
        stem_pixel = pixels[cx, cy + round(h * 0.15)]
        assert dot_pixel[:3] != (255, 255, 255)
        assert stem_pixel[:3] != (255, 255, 255)

    def test_symmetric_about_the_vertical_centre(self):
        w, h = 61, 61
        tile = _glyph_tile(GLYPH_INFO, (), w, h, 4)
        pixels = tile.load()
        for y in range(0, h, 5):
            for dx in range(0, w // 2, 5):
                left = pixels[dx, y]
                right = pixels[w - 1 - dx, y]
                assert left == right

    def test_one_tile_per_size_in_the_cache(self):
        _glyph_tile.cache_clear()
        _glyph_tile(GLYPH_INFO, (), 30, 30, 4)
        _glyph_tile(GLYPH_INFO, (), 30, 30, 4)
        info = _glyph_tile.cache_info()
        assert info.hits == 1
        assert info.misses == 1


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
        """Two glyph-tile kinds are drawn on every main compose now: the
        dots (when overlay.dots is True) and the footer's own mute cell
        (drawn unconditionally by FOOTER_VOLUME_MUTE) -- one miss each on a
        cold cache, one hit each once both tiles are memoised."""
        compositor = DialDisplayCompositor()
        img = Image.new("RGB", (160, 128), (200, 150, 100))
        overlay = OverlayState(visible=True, dots=True)
        compositor.compose(img, 160, 128, rotate=False, bgr=False, is_artwork=False, overlay=overlay)
        info = _glyph_tile.cache_info()
        assert info.misses == 2
        assert info.hits == 0

        compositor.compose(img, 160, 128, rotate=False, bgr=False, is_artwork=False, overlay=overlay)
        info = _glyph_tile.cache_info()
        assert info.misses == 2
        assert info.hits == 2

    def test_a_second_profile_size_adds_a_miss(self):
        # 160x128 and 320x240 round to different dots/mute-glyph pixel
        # sizes, so the second compose's tile keys are genuinely new — a
        # same-tier size that happens to round to the identical glyph box
        # would (correctly) hit instead, which is why this picks two sizes
        # confirmed to differ. Two glyph kinds (dots, mute) means two new
        # misses per distinct size — see test_main_compose_with_dots_one_
        # miss_then_one_hit above.
        compositor = DialDisplayCompositor()
        overlay = OverlayState(visible=True, dots=True)
        img_a = Image.new("RGB", (160, 128), (200, 150, 100))
        img_b = Image.new("RGB", (320, 240), (200, 150, 100))
        compositor.compose(img_a, 160, 128, rotate=False, bgr=False, is_artwork=False, overlay=overlay)
        assert _glyph_tile.cache_info().misses == 2

        compositor.compose(img_b, 320, 240, rotate=False, bgr=False, is_artwork=False, overlay=overlay)
        assert _glyph_tile.cache_info().misses == 4

    def test_list_compose_chevrons_plus_one_per_distinct_marker(self):
        compositor = DialDisplayCompositor()
        state = ListState(
            rows=(("A", True), ("B", False, PLAY_GLYPH), ("C", True, PLAY_GLYPH)),
            has_prev=True, has_next=True,
        )
        compositor.compose_list(160, 128, state, rotate=False, bgr=False)
        info = _glyph_tile.cache_info()
        # 3 chevrons (back/down/up) + 1 play tile; row C reuses row B's tile.
        assert info.misses == 4
        assert info.hits == 1

        compositor.compose_list(160, 128, state, rotate=False, bgr=False)
        info = _glyph_tile.cache_info()
        assert info.misses == 4
        assert info.hits == 6

    def test_list_compose_chevrons_plus_one_per_distinct_marker_rail_tier(self):
        compositor = DialDisplayCompositor()
        state = ListState(
            rows=(("A", True), ("B", False, PLAY_GLYPH), ("C", True, PLAY_GLYPH)),
            has_prev=True, has_next=True,
        )
        compositor.compose_list(320, 240, state, rotate=False, bgr=False, metrics=_RICH_METRICS)
        info = _glyph_tile.cache_info()
        # up chevron, cross, down chevron + 1 play tile; row C reuses row B's tile.
        assert info.misses == 4
        assert info.hits == 1

        compositor.compose_list(320, 240, state, rotate=False, bgr=False, metrics=_RICH_METRICS)
        info = _glyph_tile.cache_info()
        assert info.misses == 4
        assert info.hits == 6


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


# ---------------------------------------------------------------------------
# The large content tier's now-playing body: the album line above the title,
# and the fonts/icon/halo caps that keep a large panel legible rather than
# merely bigger. Base and rich unaffected by construction — proved above
# (TestMetricsByteEquivalence's album-ignored pins and TestHaloLayerCache-
# Accounting's unchanged two-miss count at 160x128).
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
        with patch("dial_display_compositor._load_font", wraps=_load_font) as spy:
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
        with patch("dial_touch_layout.FONT_BODY_MAX_PX", 999):
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
        """The header's own readout glyph, drawn directly (not through the
        glyph-tile cache) as the FIRST _draw_speaker_glyph call every main
        compose makes -- the second call is the footer's own mute cell,
        drawn through _glyph_tile() at that cell's (supersampled) size,
        which has nothing to do with this cap."""
        metrics = _LARGE_METRICS
        img = Image.new("RGB", (metrics.width, metrics.height), (200, 150, 100))
        with patch("dial_display_compositor._draw_speaker_glyph", wraps=_draw_speaker_glyph) as spy:
            compositor.compose(
                img, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
                overlay=OverlayState(visible=True, volume=42), metrics=metrics,
            )
        box = spy.call_args_list[0].args[1]
        assert box[2] - box[0] == metrics.icon == FONT_READOUT_MAX_PX


class TestLargeHaloCacheAccounting:
    @pytest.fixture(autouse=True)
    def _reset(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    def _panel(self):
        return Image.new("RGB", (_LARGE_METRICS.width, _LARGE_METRICS.height), (200, 150, 100))

    def test_three_misses_then_three_hits(self, compositor):
        img = self._panel()
        overlay = OverlayState(visible=True, artist="Artist", title="Title", album="Album")
        compositor.compose(
            img, _LARGE_METRICS.width, _LARGE_METRICS.height, rotate=False, bgr=False,
            is_artwork=False, overlay=overlay, metrics=_LARGE_METRICS,
        )
        info = _halo_layer.cache_info()
        assert info.misses == 3
        assert info.hits == 0

        compositor.compose(
            img, _LARGE_METRICS.width, _LARGE_METRICS.height, rotate=False, bgr=False,
            is_artwork=False, overlay=overlay, metrics=_LARGE_METRICS,
        )
        info = _halo_layer.cache_info()
        assert info.misses == 3
        assert info.hits == 3

    def test_changing_only_the_album_adds_one_miss(self, compositor):
        img = self._panel()
        compositor.compose(
            img, _LARGE_METRICS.width, _LARGE_METRICS.height, rotate=False, bgr=False,
            is_artwork=False,
            overlay=OverlayState(visible=True, artist="Artist", title="Title", album="Album"),
            metrics=_LARGE_METRICS,
        )
        misses_before = _halo_layer.cache_info().misses

        compositor.compose(
            img, _LARGE_METRICS.width, _LARGE_METRICS.height, rotate=False, bgr=False,
            is_artwork=False,
            overlay=OverlayState(visible=True, artist="Artist", title="Title", album="Other Album"),
            metrics=_LARGE_METRICS,
        )
        assert _halo_layer.cache_info().misses == misses_before + 1


class TestLargeNeverRaises:
    @pytest.fixture(autouse=True)
    def _reset(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    def test_no_font_available_still_composes_a_full_frame(self, compositor):
        metrics = _LARGE_METRICS
        img = Image.new("RGB", (metrics.width, metrics.height), (200, 150, 100))
        with patch("dial_display_compositor.ImageFont.truetype", side_effect=OSError("no font")), \
             patch("dial_display_compositor.ImageFont.load_default", side_effect=OSError("no default")):
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
        with patch("dial_display_compositor.ImageFilter.GaussianBlur", side_effect=RuntimeError("boom")):
            with_album = compositor.compose(
                img, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
                overlay=OverlayState(visible=True, album="Album"), metrics=metrics,
            )
        baseline_blank = compositor.compose(
            img, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, album=""), metrics=metrics,
        )
        assert list(with_album.crop(layout.album).getdata()) != list(baseline_blank.crop(layout.album).getdata())


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


def _has_near_white_pixel(region) -> bool:
    """True if *region* contains a pixel close to the glyph colour
    (255, 255, 255) — a cheap proxy for "a glyph stroke was drawn here"."""
    return any(min(px) > 200 for px in region.getdata())


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
        from dial_display_compositor import _DIVIDER_RGB
        img = Image.new("RGB", size, (60, 60, 60))
        result = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True), metrics=metrics,
        )
        layout = layout_for(*size, metrics=metrics)
        mid_y = (layout.bottom_band[1] + layout.bottom_band[3]) // 2
        for x in layout.footer_dividers:
            assert result.getpixel((x, mid_y)) == _DIVIDER_RGB

    def test_thirds_sit_between_the_footer_dividers_in_order(self):
        """Owner-chosen order: minus (DOWN) left, plus (UP) middle, mute
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

    def test_wash_clearly_visible_over_a_dimmed_mid_grey_base(self, compositor):
        """Regression: the old row-highlight alpha (21, tuned for the
        undimmed list chassis) added only about 20 levels over a dimmed
        mid-grey band -- all but invisible under the white glyph. The
        dedicated mute-wash alpha must clear that by a wide margin."""
        size = (320, 240)
        img = Image.new("RGB", size, (150, 150, 150))
        layout = layout_for(*size, metrics=_RICH_METRICS)
        corner = (layout.footer_mute[0] + 1, layout.footer_mute[3] - 2)
        unmuted = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, muted=False), metrics=_RICH_METRICS,
        )
        muted = compositor.compose(
            img, *size, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, muted=True), metrics=_RICH_METRICS,
        )
        old_alpha_delta_summed = 3 * 20   # today's near-invisible delta, per the finding above
        delta = sum(muted.getpixel(corner)) - sum(unmuted.getpixel(corner))
        assert delta > old_alpha_delta_summed
        assert delta >= 3 * 60  # at least 60 levels per channel, summed across RGB


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


class TestGlyphMuteTile:
    def test_tile_is_monochrome_with_opaque_pixels(self):
        tile = _glyph_tile(GLYPH_MUTE, (), 32, 32, 4)
        assert tile.size == (32, 32)
        assert tile.mode == "RGBA"
        pixels = tile.load()
        opaque = [pixels[x, y] for x in range(32) for y in range(32) if pixels[x, y][3] > 0]
        assert opaque, "expected at least one opaque pixel"
        # Monochrome: every opaque pixel is the plain glyph colour, no shading.
        assert all(px[:3] == (255, 255, 255) for px in opaque)

    def test_tile_has_a_diagonal_slash_and_a_speaker_body(self):
        """The mute glyph is the muted speaker: a body (opaque pixels in the
        left half) plus a diagonal slash — distinct from the unmuted
        variant's sound-wave arcs, which never form a straight diagonal like
        this. The slash is centred on the speaker body, not on the glyph's
        own box, so it runs shifted left of the box's own diagonal — see
        _draw_speaker_glyph's muted branch."""
        w = h = 40
        tile = _glyph_tile(GLYPH_MUTE, (), w, h, 4)
        pixels = tile.load()
        left_half_opaque = any(pixels[x, 20][3] > 0 for x in range(4, 16))
        assert left_half_opaque

        # The same box/body arithmetic _draw_mute_glyph/_draw_speaker_glyph
        # use, so this scans along the actual (shifted) slash the glyph
        # draws rather than a guessed position.
        side = round(min(w, h) * 0.56)
        cx, cy = w // 2, h // 2
        half = side // 2
        x0, y0, x1, y1 = cx - half, cy - half, cx - half + side, cy - half + side
        cxg, cyg = (x0 + x1) // 2, (y0 + y1) // 2
        r = max(2, min(x1 - x0, y1 - y0) // 2 - 1)
        body_w = max(2, r // 2)
        body_left = cxg - r
        cone_tip_x = body_left + body_w + r // 2
        body_cx = (body_left + cone_tip_x) // 2

        # The slash runs opaque along its own (shifted) diagonal, corner to
        # corner of a box centred on body_cx rather than cxg.
        on_diagonal_opaque = all(
            pixels[body_cx - r + i, cyg - r + i][3] > 200 for i in range(2 * r + 1)
        )
        assert on_diagonal_opaque

        # Its own midpoint sits on the body's centre column, not the box's.
        assert pixels[body_cx, cyg][3] > 200

        # Nothing opaque to the right of the body's own centre plus its
        # radius (a couple of pixels' margin for anti-aliasing at the tip) —
        # the shift moves the whole slash left, it never reaches back out to
        # the old box-centred position.
        for x in range(body_cx + r + 2, w):
            assert all(pixels[x, y][3] < 50 for y in range(h)), f"unexpected opacity at column {x}"


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
        pad = _pad_px(160, 128)
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
        with patch("dial_display_compositor.ImageFont.truetype", side_effect=OSError("no font")), \
             patch("dial_display_compositor.ImageFont.load_default", side_effect=OSError("no default")):
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
        from dial_display_compositor import OVERLAY_DIM_FACTOR, _LIST_BG_RGB, _centred_box
        metrics = metrics_for(160, 128)
        layout = layout_for(160, 128, metrics=metrics)
        box = _centred_box(layout.dots, metrics.icon)
        corner = (layout.dots[0], layout.dots[1])
        assert corner[0] < box[0] and corner[1] < box[1]
        with_back = compositor.compose_output(160, 128, _output_state(), rotate=False, bgr=False)
        # compose_output's own chassis background, dimmed the same way the
        # top band always is — the plain, glyph-free corner colour.
        expected = tuple(round(c * OVERLAY_DIM_FACTOR) for c in _LIST_BG_RGB)
        assert with_back.getpixel(corner) == expected


# ---------------------------------------------------------------------------
# BODY_TOGGLE_ROW / BODY_REPEAT_ROW: the shared renderer, byte-identical
# for the repeat screen.
# ---------------------------------------------------------------------------

class TestBodyToggleRowByteIdentity:
    def test_repeat_row_and_toggle_row_render_identically_for_the_same_label(self):
        img_a = Image.new("RGB", (160, 128), (16, 16, 16))
        img_b = Image.new("RGB", (160, 128), (16, 16, 16))
        metrics = metrics_for(160, 128)
        _BODY_RENDERERS[BODY_REPEAT_ROW](
            img_a, metrics, Body(BODY_REPEAT_ROW, armed=True, label="Repeat Play"),
        )
        _BODY_RENDERERS[BODY_TOGGLE_ROW](
            img_b, metrics, Body(BODY_TOGGLE_ROW, armed=True, label="Repeat Play"),
        )
        assert list(img_a.getdata()) == list(img_b.getdata())

    def test_repeat_screen_still_draws_repeat_play_label(self):
        """Regression guard: _repeat_frame must still pass the literal
        label, not an empty one, now that the renderer reads body.label
        instead of a hardcoded string."""
        from dial_display_compositor import _repeat_frame
        frame = _repeat_frame(_repeat_state(layout="enable", armed=False), 160, 128, metrics_for(160, 128))
        assert frame.body.kind == BODY_REPEAT_ROW
        assert frame.body.label == "Repeat Play"


# ---------------------------------------------------------------------------
# The compact tier: physically tiny panels get a 2x2 grid instead of the
# band+body+footer layouts — a whole-frame dim (Frame.dim_all) behind white
# dividers and white controls, with no name/readout anywhere. Pinned at both
# shipped compact sizes (240x240 at 1.3in, 128x128 at 1.44in).
# ---------------------------------------------------------------------------


class TestCompactStatelessness:
    def test_vars_empty_after_composing_every_compact_screen(self, compositor):
        metrics = _COMPACT_240
        base = Image.new("RGB", (metrics.width, metrics.height), (120, 130, 140))
        compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True, muted=True, dots=True), metrics=metrics,
        )
        compositor.compose_list(
            metrics.width, metrics.height,
            ListState(rows=(("Kitchen", True, "1:23"), ("Lounge", False, "4:56")), has_prev=True, has_next=True),
            rotate=False, bgr=False, metrics=metrics, base=base,
        )
        compositor.compose_repeat(
            metrics.width, metrics.height, _repeat_state(layout="enable", armed=True),
            rotate=False, bgr=False, metrics=metrics,
        )
        compositor.compose_repeat(
            metrics.width, metrics.height,
            _repeat_state(layout="replaying", line="0:10 / 1:00", start_enabled=True, stop_enabled=True),
            rotate=False, bgr=False, base=base, metrics=metrics,
        )
        assert vars(compositor) == {}


class TestCompactDimAll:
    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_whole_panel_dimmed_outside_drawn_content(self, compositor, metrics):
        base_rgb = (200, 150, 100)
        base = Image.new("RGB", (metrics.width, metrics.height), base_rgb)
        result = compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True), metrics=metrics,
        )
        # (2, 2) is inside the tl cell but well clear of the centred dots
        # glyph box (57px/30px, centred) and the divider lines.
        expected = tuple(round(c * OVERLAY_DIM_FACTOR) for c in base_rgb)
        assert result.getpixel((2, 2)) == expected

    def test_playing_screen_never_sets_dim_top_or_dim_bottom(self):
        frame = _compact_controls_frame(OverlayState(visible=True), 240, 240, _COMPACT_240)
        assert frame.dim_all is True
        assert frame.dim_top is False
        assert frame.dim_bottom is False


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
    def test_muted_cell_is_a_solid_white_wash_with_a_black_glyph(self, compositor, metrics):
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
        # The wash: every pixel of tr not part of the glyph itself is solid
        # white on the muted frame.
        x0, y0, x1, y1 = c.tr
        corner = muted.getpixel((x0 + 2, y0 + 2))
        assert corner == (255, 255, 255)
        # The glyph itself is drawn in black over that white wash.
        pixels = list(muted.crop(c.tr).getdata())
        assert any(p == (0, 0, 0) for p in pixels)
        # Unmuted: no wash (the corner stays dimmed background, not white).
        assert unmuted.getpixel((x0 + 2, y0 + 2)) != (255, 255, 255)

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
        from dial_display_compositor import _LIST_BG_RGB
        expected = tuple(round(c * OVERLAY_DIM_FACTOR) for c in _LIST_BG_RGB)
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
    chassis unchanged (see TestComposeList's rich five-row test)."""

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
        from dial_display_compositor import _LIST_BG_RGB
        # Flat chassis, undimmed — not the dimmed base colour a picker frame
        # would show at the same corner (see test_base_is_dimmed_behind_when_given).
        assert result.getpixel((2, 2)) == _LIST_BG_RGB

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
        p = compact_picker_layout_for(metrics.width, metrics.height, metrics=metrics)
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
        from dial_display_compositor import _LIST_BG_RGB
        assert chassis_bg == _LIST_BG_RGB

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
        with patch("dial_display_compositor._load_font", return_value=None):
            result = compositor.compose_list(
                metrics.width, metrics.height, state, rotate=False, bgr=False, metrics=metrics,
            )
        assert result.size == (metrics.width, metrics.height)


class TestFitValueLines:
    """_fit_value_lines: the compact info page's own drill-in fit rule —
    greedy word-wrap at the largest size, a single over-wide token split by
    character, a smaller fallback size, and a final ellipsis — pure, and
    never raising even with no usable font."""

    @pytest.fixture
    def draw(self):
        from PIL import ImageDraw
        return ImageDraw.Draw(Image.new("RGB", (240, 240)))

    def test_single_line_fit(self, draw):
        rect = (8, 32, 232, 240)
        lines, font = _fit_value_lines(draw, "10.0.0.5", (28, 24), rect)
        assert lines == ("10.0.0.5",)
        assert font is not None

    def test_word_wrap_across_multiple_lines(self, draw):
        rect = (8, 32, 232, 240)
        text = "My Really Long Home WiFi Network Name"
        lines, font = _fit_value_lines(draw, text, (28, 24), rect)
        assert len(lines) > 1
        assert " ".join(lines) == text

    def test_character_split_of_one_long_token(self, draw):
        rect = (8, 32, 232, 240)
        token = "x" * 60
        lines, font = _fit_value_lines(draw, token, (28, 24), rect)
        assert len(lines) > 1
        assert "".join(lines) == token

    def test_size_fallback_when_the_larger_size_does_not_fit(self, draw):
        # A short, tight rect that only the smaller of the two sizes' line
        # height can fit at all — the returned font must be the smaller one.
        rect = (0, 0, 200, 20)
        lines, font = _fit_value_lines(draw, "Hello", (40, 10), rect)
        assert font is not None
        assert font.size == 10

    def test_ellipsis_when_nothing_fits(self, draw):
        rect = (0, 0, 60, 20)
        text = "A" * 200
        lines, font = _fit_value_lines(draw, text, (28, 24), rect)
        assert lines
        assert lines[-1].endswith("...")
        for line in lines:
            measured = _text_size(draw, line, font)
            assert measured is not None and measured[0] <= 60

    def test_missing_font_returns_empty(self, draw):
        with patch("dial_display_compositor._load_font", return_value=None):
            lines, font = _fit_value_lines(draw, "anything", (28, 24), (0, 0, 200, 200))
        assert lines == ()
        assert font is None

    def test_is_pure(self, draw):
        rect = (8, 32, 232, 240)
        a = _fit_value_lines(draw, "10.0.0.5", (28, 24), rect)
        b = _fit_value_lines(draw, "10.0.0.5", (28, 24), rect)
        assert a == b


class TestInfoValueView:
    """compose_info_value()/_body_info_value(): the compact info page's own
    drill-in — a flat chassis background, the field name small in the top
    band, the value large and centred below, wrapped or shrunk to fit."""

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_background_is_flat_chassis(self, compositor, metrics):
        from dial_display_compositor import _LIST_BG_RGB
        result = compositor.compose_info_value(
            metrics.width, metrics.height, InfoValueView(label="IPv4", value="10.0.0.5"),
            rotate=False, bgr=False, metrics=metrics,
        )
        assert result.getpixel((1, 1)) == _LIST_BG_RGB

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
        with patch("dial_display_compositor._load_font", return_value=None):
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
        right = _glyph_tile(GLYPH_TWO_DOTS, (1, _GLYPH_RGB), 32, 32, 4)
        left = _glyph_tile(GLYPH_TWO_DOTS, (0, _GLYPH_RGB), 32, 32, 4)
        assert list(right.getdata()) != list(left.getdata())

    @pytest.mark.parametrize("metrics", [_COMPACT_240, _COMPACT_128])
    def test_nothing_drawn_in_the_dead_top_right_cell(self, compositor, metrics):
        from dial_display_compositor import _LIST_BG_RGB
        c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
        armed = compositor.compose_repeat(
            metrics.width, metrics.height, _repeat_state(layout="enable", armed=True),
            rotate=False, bgr=False, metrics=metrics,
        )
        disarmed = compositor.compose_repeat(
            metrics.width, metrics.height, _repeat_state(layout="enable", armed=False),
            rotate=False, bgr=False, metrics=metrics,
        )
        expected = tuple(round(ch * OVERLAY_DIM_FACTOR) for ch in _LIST_BG_RGB)
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
        # compact replaying cell is a quarter of the panel and the owner's
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


class TestCompactGlyphTiles:
    def test_restart_and_stop_tiles_are_non_empty(self):
        restart = _glyph_tile(GLYPH_RESTART, (_GLYPH_RGB,), 32, 32, 4)
        stop = _glyph_tile(GLYPH_STOP, (_GLYPH_RGB,), 32, 32, 4)
        assert any(p[3] > 0 for p in restart.getdata())
        assert any(p[3] > 0 for p in stop.getdata())

    def test_stop_tile_is_a_centred_filled_square(self):
        w = h = 40
        tile = _glyph_tile(GLYPH_STOP, (_GLYPH_RGB,), w, h, 4)
        pixels = tile.load()
        cx, cy = w // 2, h // 2
        assert pixels[cx, cy][3] > 0
        # Roughly symmetric about the centre (a filled square is) — a small
        # tolerance absorbs the supersample/LANCZOS downsample's own
        # antialiasing at the edge, which need not be bit-exact.
        side = round(min(w, h) * 0.56)
        half = side // 2
        assert abs(pixels[cx - half + 1, cy][3] - pixels[cx + half - 1, cy][3]) <= 4

    def test_restart_tile_is_a_bar_then_two_widening_triangles(self):
        # The seek-to-start "|<<" icon, read left to right: a full-height
        # bar, a transparent gap, a triangle narrowing toward the bar
        # (its apex) and widening away from it (its base), a second
        # transparent gap, then a second triangle shaped the same way —
        # checked structurally (per-column opaque extent) rather than at
        # one hand-picked pixel, so it does not depend on exact rounding.
        w = h = 40
        tile = _glyph_tile(GLYPH_RESTART, (_GLYPH_RGB,), w, h, 4)
        pixels = tile.load()

        def col_extent(x):
            ys = [y for y in range(h) if pixels[x, y][3] > 100]
            return (min(ys), max(ys)) if ys else None

        cx = w // 2
        short = min(w, h)
        r = short * 0.28
        left = round(cx - r)
        right = round(cx + r)
        bar_w = max(2, round(short / 8))

        # The bar: constant (full) height across its own width.
        bar_extent = col_extent(left + 1)
        assert bar_extent is not None
        assert col_extent(left + bar_w - 1) == bar_extent

        # A fully transparent gap separates the bar from the first triangle.
        assert col_extent(left + bar_w + 1) is None

        # The remaining span narrows toward the bar (its shared apex side)
        # and widens toward the glyph's own right edge (the triangles'
        # bases) — compare a column near each end.
        near_apex = col_extent(left + bar_w + 3)
        near_base = col_extent(right - 2)
        assert near_apex is not None and near_base is not None
        assert (near_apex[1] - near_apex[0]) < (near_base[1] - near_base[0])

        # Outside the glyph's own box entirely: transparent.
        assert col_extent(1) is None
        assert col_extent(w - 2) is None

    def test_lit_and_dimmed_are_distinct_cache_keys_and_pixels(self):
        _reset_render_caches()
        lit = _glyph_tile(GLYPH_RESTART, (_GLYPH_RGB,), 32, 32, 4)
        dimmed = _glyph_tile(GLYPH_RESTART, (_DIMMED_GLYPH_RGB,), 32, 32, 4)
        assert _glyph_tile.cache_info().misses == 2
        assert list(lit.getdata()) != list(dimmed.getdata())

    def test_existing_glyph_kinds_keep_byte_identical_default_tiles(self):
        # Every existing call site still passes no colour param at all, so
        # the tile key (kind, (), w, h, ss) — and therefore its pixels —
        # must be unaffected by the new trailing colour parameter.
        two_dots_default = _glyph_tile(GLYPH_TWO_DOTS, (0,), 24, 24, 4)
        two_dots_explicit_default_color = _glyph_tile(GLYPH_TWO_DOTS, (0, _GLYPH_RGB), 24, 24, 4)
        assert list(two_dots_default.getdata()) == list(two_dots_explicit_default_color.getdata())

        mute_default = _glyph_tile(GLYPH_MUTE, (), 24, 24, 4)
        mute_explicit_default_color = _glyph_tile(GLYPH_MUTE, (_GLYPH_RGB,), 24, 24, 4)
        assert list(mute_default.getdata()) == list(mute_explicit_default_color.getdata())


class TestCompactNeverRaises:
    @pytest.fixture(autouse=True)
    def _reset(self):
        _reset_font_cache()
        yield
        _reset_font_cache()

    def test_no_font_available_still_composes_every_compact_screen(self, compositor):
        metrics = _COMPACT_240
        base = Image.new("RGB", (metrics.width, metrics.height), (200, 150, 100))
        with patch("dial_display_compositor.ImageFont.truetype", side_effect=OSError("no font")), \
             patch("dial_display_compositor.ImageFont.load_default", side_effect=OSError("no default")):
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


# ---------------------------------------------------------------------------
# Three pager dots (GLYPH_PAGE_DOTS / Header.dots_count) — the EQ page's
# own third page indicator, drawn only when dots_count == 3; every existing
# two-dot tile/key stays untouched.
# ---------------------------------------------------------------------------

class TestPageDotsGlyphTiles:
    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_render_caches()
        yield
        _reset_render_caches()

    def test_three_tiles_are_distinct_and_keyed_separately(self):
        tiles = [_glyph_tile(GLYPH_PAGE_DOTS, (3, k), 40, 16, 4) for k in range(3)]
        for a in range(3):
            for b in range(a + 1, 3):
                assert list(tiles[a].getdata()) != list(tiles[b].getdata())

    def test_right_dot_solid_only_for_k_2(self):
        """The third dot (rightmost) is filled only when filled == 2 — a
        cheap proxy: sample a pixel at the tile's own right edge, which the
        filled dot's own more solid coverage should differ."""
        filled_2 = _glyph_tile(GLYPH_PAGE_DOTS, (3, 2), 40, 16, 4)
        filled_0 = _glyph_tile(GLYPH_PAGE_DOTS, (3, 0), 40, 16, 4)
        assert list(filled_2.getdata()) != list(filled_0.getdata())

    def test_two_dot_tiles_and_keys_untouched(self):
        """GLYPH_TWO_DOTS keeps its own kind string and painter — adding
        GLYPH_PAGE_DOTS must not perturb it."""
        assert GLYPH_TWO_DOTS != GLYPH_PAGE_DOTS
        assert _GLYPH_PAINTERS[GLYPH_TWO_DOTS] is not _GLYPH_PAINTERS[GLYPH_PAGE_DOTS]
        two_dots = _glyph_tile(GLYPH_TWO_DOTS, (0,), 24, 24, 4)
        assert two_dots.size == (24, 24)

    def test_page_dots_registered_in_glyph_painters(self):
        assert GLYPH_PAGE_DOTS in _GLYPH_PAINTERS


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
        layout = layout_for(160, 128)
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
        muted=None, volume=None, pressed=None,
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
        from dial_display_compositor import _LIST_BG_RGB
        result = compositor.compose_eq(320, 240, _eq_state(name=""), rotate=False, bgr=False, metrics=_RICH_METRICS)
        layout = layout_for(320, 240, metrics=_RICH_METRICS)
        corner = (layout.top_band[0], layout.top_band[1])
        expected = tuple(round(c * OVERLAY_DIM_FACTOR) for c in _LIST_BG_RGB)
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
            result.getpixel((x, bar.track_y)) == _GLYPH_RGB
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
        assert positive.getpixel(right_of_centre) == _GLYPH_RGB
        assert negative.getpixel(left_of_centre) == _GLYPH_RGB

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
            320, 240, _eq_state(bass_db=-EQ_LIMIT_DB), rotate=False, bgr=False, metrics=_RICH_METRICS,
        )
        at_max = compositor.compose_eq(
            320, 240, _eq_state(bass_db=EQ_LIMIT_DB), rotate=False, bgr=False, metrics=_RICH_METRICS,
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
        with patch("dial_display_compositor.ImageFont.truetype", side_effect=OSError("no font")), \
             patch("dial_display_compositor.ImageFont.load_default", side_effect=OSError("no default")):
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


# ---------------------------------------------------------------------------
# The artwork-tap reveal: compose(reveal_progress=p) slides the finished
# top/bottom bands off the panel and fades the inter-band text as p runs
# from 0 (bands in place, the ordinary frame) to 1 (bands gone, the
# no-overlay frame). Pinned on both the rich and large tiers, which are the
# only ones the manager ever animates; the compact tier ignores the
# parameter entirely.
# ---------------------------------------------------------------------------


def _reveal_base_image(metrics):
    """A mid-grey-to-white vertical gradient, tall enough for a fade to be
    provable (a flat dark image cannot show a blend changing anything)."""
    grad = Image.linear_gradient("L").resize((metrics.width, metrics.height))
    return grad.convert("RGB")


def _reveal_overlay():
    return OverlayState(
        visible=True, artist="Artist", title="Title", album="Album", name="Kitchen",
        volume=50, dots=True, muted=True,
    )


class TestRevealProgress:
    @pytest.mark.parametrize("metrics", [_RICH_METRICS, _LARGE_METRICS])
    @pytest.mark.parametrize("rotate,bgr", [(False, False), (True, False), (False, True), (True, True)])
    def test_zero_progress_is_byte_identical_to_shown(self, compositor, metrics, rotate, bgr):
        base = _reveal_base_image(metrics)
        overlay = _reveal_overlay()
        shown = compositor.compose(
            base, metrics.width, metrics.height, rotate=rotate, bgr=bgr, is_artwork=False,
            overlay=overlay, metrics=metrics,
        )
        zero = compositor.compose(
            base, metrics.width, metrics.height, rotate=rotate, bgr=bgr, is_artwork=False,
            overlay=overlay, metrics=metrics, reveal_progress=0.0,
        )
        assert list(zero.getdata()) == list(shown.getdata())

    @pytest.mark.parametrize("metrics", [_RICH_METRICS, _LARGE_METRICS])
    @pytest.mark.parametrize("progress", [-0.5, float("nan")])
    def test_negative_and_nan_progress_are_drawn_as_shown(self, compositor, metrics, progress):
        base = _reveal_base_image(metrics)
        overlay = _reveal_overlay()
        shown = compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=overlay, metrics=metrics,
        )
        out = compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=overlay, metrics=metrics, reveal_progress=progress,
        )
        assert list(out.getdata()) == list(shown.getdata())

    @pytest.mark.parametrize("metrics", [_RICH_METRICS, _LARGE_METRICS])
    @pytest.mark.parametrize("rotate,bgr", [(False, False), (True, False), (False, True), (True, True)])
    @pytest.mark.parametrize("progress", [1.0, 1.5])
    def test_full_progress_is_byte_identical_to_hidden(self, compositor, metrics, rotate, bgr, progress):
        base = _reveal_base_image(metrics)
        overlay = _reveal_overlay()
        bare = compositor.compose(
            base, metrics.width, metrics.height, rotate=rotate, bgr=bgr, is_artwork=False,
            overlay=None, metrics=metrics,
        )
        out = compositor.compose(
            base, metrics.width, metrics.height, rotate=rotate, bgr=bgr, is_artwork=False,
            overlay=overlay, metrics=metrics, reveal_progress=progress,
        )
        assert list(out.getdata()) == list(bare.getdata())
        if not rotate and not bgr:
            direct = compositor.compose(
                base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
                overlay=overlay, metrics=metrics, reveal_progress=progress,
            )
            assert direct is base

    @pytest.mark.parametrize("metrics", [_RICH_METRICS, _LARGE_METRICS])
    @pytest.mark.parametrize("p", [0.25, 0.5, 0.8])
    def test_intermediate_progress_slides_bands_and_fades_text(self, compositor, metrics, p):
        w, h = metrics.width, metrics.height
        base = _reveal_base_image(metrics)
        overlay = _reveal_overlay()
        shown = compositor.compose(
            base, w, h, rotate=False, bgr=False, is_artwork=False, overlay=overlay, metrics=metrics,
        )
        bare = compositor.compose(
            base, w, h, rotate=False, bgr=False, is_artwork=False, overlay=None, metrics=metrics,
        )
        out = compositor.compose(
            base, w, h, rotate=False, bgr=False, is_artwork=False,
            overlay=overlay, metrics=metrics, reveal_progress=p,
        )
        layout = layout_for(w, h, metrics=metrics)
        band_h = layout.top_band[3]
        dy = round(p * band_h)

        assert list(out.crop((0, 0, w, band_h - dy)).getdata()) == list(
            shown.crop((0, dy, w, band_h)).getdata()
        )
        assert list(out.crop((0, band_h - dy, w, band_h)).getdata()) == list(
            bare.crop((0, band_h - dy, w, band_h)).getdata()
        )
        assert list(out.crop((0, h - band_h + dy, w, h)).getdata()) == list(
            shown.crop((0, h - band_h, w, h - dy)).getdata()
        )
        assert list(out.crop((0, h - band_h, w, h - band_h + dy)).getdata()) == list(
            bare.crop((0, h - band_h, w, h - band_h + dy)).getdata()
        )
        expected_strip = Image.blend(
            bare.crop(layout.artwork), shown.crop(layout.artwork), 1.0 - p,
        )
        assert list(out.crop(layout.artwork).getdata()) == list(expected_strip.getdata())
        assert _diff_bbox(out.crop(layout.title), shown.crop(layout.title)) is not None
        assert _diff_bbox(out.crop(layout.title), bare.crop(layout.title)) is not None

    def test_progress_is_ignored_on_compact(self, compositor):
        metrics = _COMPACT_240
        base = _reveal_base_image(metrics)
        overlay = _reveal_overlay()
        zero = compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=overlay, metrics=metrics, reveal_progress=0.0,
        )
        half = compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=overlay, metrics=metrics, reveal_progress=0.5,
        )
        assert list(zero.getdata()) == list(half.getdata())

    def test_rotate_and_bgr_apply_after_the_slide(self, compositor):
        metrics = _RICH_METRICS
        base = _reveal_base_image(metrics)
        overlay = _reveal_overlay()
        plain = compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=overlay, metrics=metrics, reveal_progress=0.5,
        )
        transformed = compositor.compose(
            base, metrics.width, metrics.height, rotate=True, bgr=True, is_artwork=False,
            overlay=overlay, metrics=metrics, reveal_progress=0.5,
        )
        expected = plain.transpose(Image.ROTATE_180)
        expected = Image.merge("RGB", expected.split()[::-1])
        assert list(transformed.getdata()) == list(expected.getdata())

    def test_base_image_is_not_mutated(self, compositor):
        metrics = _RICH_METRICS
        base = _reveal_base_image(metrics)
        before = base.tobytes()
        compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=_reveal_overlay(), metrics=metrics, reveal_progress=0.5,
        )
        assert base.tobytes() == before

    def test_same_inputs_same_output(self, compositor):
        metrics = _RICH_METRICS
        base = _reveal_base_image(metrics)
        overlay = _reveal_overlay()
        first = compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=overlay, metrics=metrics, reveal_progress=0.37,
        )
        second = compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=overlay, metrics=metrics, reveal_progress=0.37,
        )
        assert list(first.getdata()) == list(second.getdata())

    def test_statelessness(self, compositor):
        metrics = _RICH_METRICS
        base = _reveal_base_image(metrics)
        before = dict(vars(compositor))
        compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=_reveal_overlay(), metrics=metrics, reveal_progress=0.5,
        )
        after = dict(vars(compositor))
        assert before == after == {}
