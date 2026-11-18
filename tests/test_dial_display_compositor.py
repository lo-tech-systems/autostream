"""Tests for dial_display_compositor.py — stateless frame composition.

Covers rotate/bgr in isolation and combined, identity when neither is set,
the artwork-fit path (transform_artwork_for_panel runs and panel-fits a
non-panel-sized input), the logo path (already-sized base passes through
transforms only), statelessness, the inert overlay parameter, the zone-rect
helper, the frame pipeline, the byte equivalence of renders with and
without metrics, the render caches, and the compact tier's statelessness
and whole-frame dim. The tests of the drawing layers beneath it are in
test_dial_display_views.py, test_dial_display_draw.py,
test_dial_display_render.py, test_dial_display_render_compact.py and
test_dial_display_reveal.py; their shared helpers and fixture are in
dial_compositor_support.py.
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

from dial_display_views import (  # noqa: E402
    BG_BASE,
    BODY_LIST_ROWS,
    BODY_NONE,
    BODY_NOW_PLAYING,
    BODY_REPEAT_LINE,
    BODY_TOGGLE_ROW,
    FOOTER_LABELS,
    FOOTER_LIST_BAR,
    FOOTER_LIST_RAIL,
    FOOTER_NONE,
    FOOTER_VOLUME,
    Frame,
    InfoValueView,
    ListState,
    PLAY_GLYPH,
    OverlayState,
    RepeatViewState,
    WarningView,
    BellBadge,
    WIFI_OFF,
    WIFI_RED,
)
from dial_display_draw import (  # noqa: E402
    _glyph_tile,
    _halo_layer,
)
from dial_display_render import (  # noqa: E402
    _BODY_RENDERERS,
    _FOOTER_RENDERERS,
)
from dial_display_compositor import (  # noqa: E402
    DialDisplayCompositor,
    _compact_controls_frame,
    _compose_frame,
    _reset_font_cache,
    _zone_rect,
)
from dial_display_palette import OVERLAY_DIM_FACTOR  # noqa: E402
from dial_layout_metrics import (  # noqa: E402
    CONTENT_BASE,
    metrics_for,
)
from dial_touch_layout import (  # noqa: E402
    GEOMETRY_LIST,
    GEOMETRY_MAIN,
    GEOMETRY_REPEAT,
    TouchZone,
    idle_layout_for,
    layout_for,
    repeat_layout_for,
    zone_rects_for,
)
from dial_compositor_support import (
    PROFILE_SIZES,
    _COMPACT_128,
    _COMPACT_240,
    _LARGE_METRICS,
    _RICH_METRICS,
    _marked_image,
    _repeat_state,
)
from dial_compositor_support import compositor  # noqa: F401

_CONFIRMED_MM_PER_PX = [0.2231, 0.2021, 0.0973, 0.1778]
# Densities chosen to resolve to base at every panel size — proves the
# metrics-threading seam changed no base pixel. A (size, mm) pair that
# resolves to a richer content tier is a deliberate geometry change instead,
# not a byte-equivalence case.
_OUT_OF_TIER_MM_PER_PX = [0.05, 0.5]
_METRICS_EQUIVALENCE_CASES = [
    (size, mm)
    for size, mm in (
        list(zip(PROFILE_SIZES, _CONFIRMED_MM_PER_PX))
        + [(size, mm) for size in PROFILE_SIZES for mm in _OUT_OF_TIER_MM_PER_PX]
    )
    if metrics_for(size[0], size[1], mm).content_tier == CONTENT_BASE
]


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

    def test_compose_restarting_and_idle_hold_no_attributes_that_change_between_calls(self, compositor):
        before = dict(vars(compositor))
        base = Image.new("RGB", (160, 128), (32, 32, 32))
        compositor.compose_restarting(160, 128, rotate=False, bgr=False)
        compositor.compose_starting(160, 128, rotate=False, bgr=False)
        compositor.compose_idle(base, 160, 128, rotate=False, bgr=False, wifi_bars=2, wifi_style=WIFI_RED)
        compositor.compose_idle(base, 160, 128, rotate=False, bgr=False, wifi_style=WIFI_OFF)
        compositor.compose_idle(base, 160, 128, rotate=False, bgr=False, bell=BellBadge("critical", 3))
        after = dict(vars(compositor))
        assert before == after == {}

    def test_compose_warning_holds_no_attributes_that_change_between_calls(self, compositor):
        before = dict(vars(compositor))
        compositor.compose_warning(
            160, 128,
            WarningView(title="One", buttons=("Close",)),
            rotate=False, bgr=False,
        )
        compositor.compose_warning(
            240, 240,
            WarningView(title="Two", buttons=("Close", "Restart"), pressed=1),
            rotate=True, bgr=True, metrics=metrics_for(240, 240, 0.0973),
        )
        compositor.compose_warning(
            320, 240,
            WarningView(title="Three", message="detail", buttons=("A", "B", "C")),
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
# _compose_frame — the shared pipeline every screen frame is built from:
# background, dims, pressed wash, header, body, footer, then rotate/BGR.
# Exercised directly here (rather than only through the four public
# entry points above) so the dispatch tables and the pipeline's own
# invariants are pinned independently of any one screen's adapter.
# ---------------------------------------------------------------------------

class TestComposeFramePipeline:
    def test_every_body_kind_has_a_renderer(self):
        for kind in (BODY_NONE, BODY_NOW_PLAYING, BODY_TOGGLE_ROW, BODY_REPEAT_LINE, BODY_LIST_ROWS):
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
    def test_compose_idle_unaffected_outside_the_corner_boxes(self, compositor, size, mm):
        # The idle frame's one deliberate density-dependent pixel region is
        # the corner boxes (their side is 8mm by construction wherever
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
        volume=None, pressed=None,
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
        "idle_bell",
        lambda c: c.compose_idle(
            logo, width, height, rotate=False, bgr=False, metrics=metrics, bell=BellBadge("critical", 12),
        ),
    ))
    cases.append((
        "warning_two",
        lambda c: c.compose_warning(
            width, height, WarningView(title="No WiFi", buttons=("Restart", "Close")),
            rotate=False, bgr=False, metrics=metrics,
        ),
    ))
    cases.append((
        "warning_two_pressed",
        lambda c: c.compose_warning(
            width, height, WarningView(title="No WiFi", buttons=("Restart", "Close"), pressed=0),
            rotate=False, bgr=False, metrics=metrics,
        ),
    ))
    cases.append((
        "warning_one",
        lambda c: c.compose_warning(
            width, height,
            WarningView(title="microSD card", message="15% life left, replace soon", buttons=("Close",)),
            rotate=False, bgr=False, metrics=metrics,
        ),
    ))
    cases.append((
        "warning_three_paged",
        lambda c: c.compose_warning(
            width, height,
            WarningView(title="Stylus wear", message="Over 450 hours", buttons=("Close", "Restart", "Next"),
                        source="Turntable \u00b7 1 of 2", pressed=2),
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
            patch("dial_display_draw.ImageFont.truetype", side_effect=OSError("no font"))
            if no_font else contextlib.nullcontext()
        )

        def render_all():
            return [(name, fn(compositor)) for name, fn in _render_cache_corpus(width, height)]

        try:
            with font_cm:
                _reset_font_cache()
                cold = render_all()
                warm = render_all()
                with patch("dial_display_draw._glyph_tile", _glyph_tile.__wrapped__), \
                     patch("dial_display_draw._halo_layer", _halo_layer.__wrapped__):
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
            with patch("dial_display_draw._glyph_tile", _glyph_tile.__wrapped__), \
                 patch("dial_display_draw._halo_layer", _halo_layer.__wrapped__):
                bypassed = render_all()
        finally:
            _reset_font_cache()

        for (name, cold_img), (_, warm_img), (_, bypassed_img) in zip(cold, warm, bypassed):
            assert cold_img.tobytes() == warm_img.tobytes(), f"{name}: cold != warm"
            assert cold_img.tobytes() == bypassed_img.tobytes(), f"{name}: cold != bypassed"


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


# ---------------------------------------------------------------------------
# BODY_TOGGLE_ROW: the repeat screen's row.
# ---------------------------------------------------------------------------

class TestRepeatScreenToggleRow:
    def test_repeat_screen_still_draws_repeat_play_label(self):
        """Regression guard: _repeat_frame must still pass the literal
        label, not an empty one, now that the renderer reads body.label
        instead of a hardcoded string."""
        from dial_display_compositor import _repeat_frame
        frame = _repeat_frame(_repeat_state(layout="enable", armed=False), 160, 128, metrics_for(160, 128))
        assert frame.body.kind == BODY_TOGGLE_ROW
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
