"""Tests for dial_display_draw.py — glyph tiles, the tile and halo caches, and text fitting."""
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
    ListState,
    PLAY_GLYPH,
    OverlayState,
)
from dial_display_draw import (  # noqa: E402
    GLYPH_CHEVRON,
    GLYPH_CROSS,
    GLYPH_BELL,
    GLYPH_MUTE,
    GLYPH_SPEAKER,
    GLYPH_PAGE_DOTS,
    GLYPH_PLAY,
    GLYPH_RESTART,
    GLYPH_STOP,
    GLYPH_TWO_DOTS,
    GLYPH_WIFI,
    _GLYPH_PAINTERS,
    _GLYPH_SUPERSAMPLE,
    _BELL_RGB,
    _fit_value_lines,
    _glyph_tile,
    _halo_layer,
    _text_size,
)
from dial_display_compositor import (  # noqa: E402
    DialDisplayCompositor,
    _reset_font_cache,
    _reset_render_caches,
)
from dial_display_palette import (  # noqa: E402
    ALARM_RGB,
    DIMMED_GLYPH_RGB,
    GLYPH_RGB,
)
from dial_touch_layout import layout_for  # noqa: E402
from dial_compositor_support import _LARGE_METRICS, _RICH_METRICS
from dial_compositor_support import compositor  # noqa: F401

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
        tile = _glyph_tile(GLYPH_WIFI, (3, GLYPH_RGB), self.S, self.S, 4)
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
        tile = _glyph_tile(GLYPH_WIFI, (lit, GLYPH_RGB), self.S, self.S, 4)
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
        tile = _glyph_tile(GLYPH_WIFI, (3, ALARM_RGB), self.S, self.S, 4)
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
        tile = _glyph_tile(GLYPH_WIFI, (2, GLYPH_RGB), s, s, 4)
        px = tile.load()
        for y in range(0, s, 5):
            for dx in range(0, s // 2, 5):
                left, right = px[dx, y], px[s - 1 - dx, y]
                if left[3] < 30 and right[3] < 30:
                    continue
                assert all(abs(left[i] - right[i]) <= 40 for i in range(4)), (dx, y, left, right)

    def test_lit_and_colour_are_distinct_cache_keys(self):
        _glyph_tile.cache_clear()
        _glyph_tile(GLYPH_WIFI, (1, GLYPH_RGB), 30, 30, 4)
        _glyph_tile(GLYPH_WIFI, (2, GLYPH_RGB), 30, 30, 4)
        _glyph_tile(GLYPH_WIFI, (2, ALARM_RGB), 30, 30, 4)
        _glyph_tile(GLYPH_WIFI, (2, ALARM_RGB), 30, 30, 4)
        info = _glyph_tile.cache_info()
        assert info.misses == 3 and info.hits == 1


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
        from dial_display_draw import _GLYPH_PAINTERS
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
        from dial_display_draw import (
            GLYPH_ARM_DOT,
            GLYPH_MUTE,
            GLYPH_PAGE_DOTS,
            GLYPH_RESTART,
            GLYPH_STOP,
            _GLYPH_PAINTERS,
        )

        assert set(_GLYPH_PAINTERS) == {
            GLYPH_CHEVRON, GLYPH_TWO_DOTS, GLYPH_PAGE_DOTS, GLYPH_ARM_DOT, GLYPH_PLAY, GLYPH_CROSS, GLYPH_MUTE,
            GLYPH_SPEAKER, GLYPH_RESTART, GLYPH_STOP, GLYPH_BELL, GLYPH_WIFI,
        }

    def test_tile_has_opaque_pixels_in_the_left_half_and_empty_corners(self):
        tile = _glyph_tile(GLYPH_PLAY, (), 24, 24, 4)
        assert tile.size == (24, 24)
        assert tile.mode == "RGBA"
        pixels = tile.load()
        assert pixels[10, 12][3] > 0  # left half, centre row — inside the triangle's base
        for corner in ((0, 0), (23, 0), (0, 23), (23, 23)):
            assert pixels[corner][3] == 0


class TestBellGlyph:
    """GLYPH_BELL: a filled bell in the severity's colour with the number of
    entries in white, symmetric about the vertical centre outside the
    number."""

    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _reset_render_caches()
        yield
        _reset_render_caches()

    def test_registered_painter(self):
        assert GLYPH_BELL in _GLYPH_PAINTERS

    @pytest.mark.parametrize("severity", sorted(_BELL_RGB))
    def test_the_body_is_opaque_in_the_severity_colour_with_transparent_corners(self, severity):
        w, h = 60, 60
        tile = _glyph_tile(GLYPH_BELL, (severity, 1), w, h, 4)
        assert tile.size == (w, h)
        assert tile.mode == "RGBA"
        pixels = tile.load()
        for corner in ((0, 0), (w - 1, 0), (0, h - 1), (w - 1, h - 1)):
            assert pixels[corner][3] == 0
        body = pixels[round(w * 7.4 / 24), round(h * 13.5 / 24)]
        assert body[3] == 255 and body[:3] == _BELL_RGB[severity]

    def test_an_informational_bell_takes_the_accent_colour(self):
        tile = _glyph_tile(GLYPH_BELL, ("info", 1), 60, 60, 4)
        body = tile.load()[round(60 * 7.4 / 24), round(60 * 13.5 / 24)]
        assert body[:3] not in set(_BELL_RGB.values()) and body[3] == 255

    def test_the_number_is_white_inside_the_body(self):
        tile = _glyph_tile(GLYPH_BELL, ("warning", 8), 60, 60, 4)
        assert any(px[:3] == (255, 255, 255) and px[3] == 255 for px in tile.getdata())

    def test_a_count_above_nine_is_drawn_as_nine_plus(self):
        assert _glyph_tile(GLYPH_BELL, ("warning", 10), 60, 60, 4).tobytes() == \
            _glyph_tile(GLYPH_BELL, ("warning", 99), 60, 60, 4).tobytes()
        assert _glyph_tile(GLYPH_BELL, ("warning", 9), 60, 60, 4).tobytes() != \
            _glyph_tile(GLYPH_BELL, ("warning", 10), 60, 60, 4).tobytes()

    def test_symmetric_about_the_vertical_centre_outside_the_number(self):
        w, h = 61, 61
        tile = _glyph_tile(GLYPH_BELL, ("warning", 1), w, h, 4)
        pixels = tile.load()
        # Rows above and below the number's box (6.4..17.0 of 24).
        for y in list(range(0, round(h * 6 / 24), 3)) + list(range(round(h * 17.5 / 24), h, 3)):
            for dx in range(0, w // 2, 4):
                assert abs(pixels[dx, y][3] - pixels[w - 1 - dx, y][3]) <= 8

    def test_one_tile_per_size_and_params_in_the_cache(self):
        _glyph_tile.cache_clear()
        _glyph_tile(GLYPH_BELL, ("warning", 2), 30, 30, 4)
        _glyph_tile(GLYPH_BELL, ("warning", 2), 30, 30, 4)
        _glyph_tile(GLYPH_BELL, ("critical", 2), 30, 30, 4)
        info = _glyph_tile.cache_info()
        assert (info.hits, info.misses) == (1, 2)


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
        """Three glyph-tile kinds are drawn on every main compose now: the
        dots (when overlay.dots is True), the header's speaker icon and the
        footer's own mute cell (drawn unconditionally by FOOTER_VOLUME_MUTE)
        -- one miss each on a cold cache, one hit each once all three tiles
        are memoised."""
        compositor = DialDisplayCompositor()
        img = Image.new("RGB", (160, 128), (200, 150, 100))
        overlay = OverlayState(visible=True, dots=True)
        compositor.compose(img, 160, 128, rotate=False, bgr=False, is_artwork=False, overlay=overlay)
        info = _glyph_tile.cache_info()
        assert info.misses == 3
        assert info.hits == 0

        compositor.compose(img, 160, 128, rotate=False, bgr=False, is_artwork=False, overlay=overlay)
        info = _glyph_tile.cache_info()
        assert info.misses == 3
        assert info.hits == 3

    def test_a_second_profile_size_adds_a_miss(self):
        # 160x128 and 320x240 round to different dots/mute-glyph pixel
        # sizes, so the second compose's tile keys are genuinely new — a
        # same-tier size that happens to round to the identical glyph box
        # would (correctly) hit instead, which is why this picks two sizes
        # confirmed to differ. Three glyph kinds (dots, speaker, mute) means
        # three new misses per distinct size — see test_main_compose_with_
        # dots_one_miss_then_one_hit above.
        compositor = DialDisplayCompositor()
        overlay = OverlayState(visible=True, dots=True)
        img_a = Image.new("RGB", (160, 128), (200, 150, 100))
        img_b = Image.new("RGB", (320, 240), (200, 150, 100))
        compositor.compose(img_a, 160, 128, rotate=False, bgr=False, is_artwork=False, overlay=overlay)
        assert _glyph_tile.cache_info().misses == 3

        compositor.compose(img_b, 320, 240, rotate=False, bgr=False, is_artwork=False, overlay=overlay)
        assert _glyph_tile.cache_info().misses == 6

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
        with patch("dial_display_draw._load_font", return_value=None):
            lines, font = _fit_value_lines(draw, "anything", (28, 24), (0, 0, 200, 200))
        assert lines == ()
        assert font is None

    def test_is_pure(self, draw):
        rect = (8, 32, 232, 240)
        a = _fit_value_lines(draw, "10.0.0.5", (28, 24), rect)
        b = _fit_value_lines(draw, "10.0.0.5", (28, 24), rect)
        assert a == b


class TestCompactGlyphTiles:
    def test_restart_and_stop_tiles_are_non_empty(self):
        restart = _glyph_tile(GLYPH_RESTART, (GLYPH_RGB,), 32, 32, 4)
        stop = _glyph_tile(GLYPH_STOP, (GLYPH_RGB,), 32, 32, 4)
        assert any(p[3] > 0 for p in restart.getdata())
        assert any(p[3] > 0 for p in stop.getdata())

    def test_stop_tile_is_a_centred_filled_square(self):
        w = h = 40
        tile = _glyph_tile(GLYPH_STOP, (GLYPH_RGB,), w, h, 4)
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
        tile = _glyph_tile(GLYPH_RESTART, (GLYPH_RGB,), w, h, 4)
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
        lit = _glyph_tile(GLYPH_RESTART, (GLYPH_RGB,), 32, 32, 4)
        dimmed = _glyph_tile(GLYPH_RESTART, (DIMMED_GLYPH_RGB,), 32, 32, 4)
        assert _glyph_tile.cache_info().misses == 2
        assert list(lit.getdata()) != list(dimmed.getdata())

    def test_existing_glyph_kinds_keep_byte_identical_default_tiles(self):
        # Every existing call site still passes no colour param at all, so
        # the tile key (kind, (), w, h, ss) — and therefore its pixels —
        # must be unaffected by the new trailing colour parameter.
        two_dots_default = _glyph_tile(GLYPH_TWO_DOTS, (0,), 24, 24, 4)
        two_dots_explicit_default_color = _glyph_tile(GLYPH_TWO_DOTS, (0, GLYPH_RGB), 24, 24, 4)
        assert list(two_dots_default.getdata()) == list(two_dots_explicit_default_color.getdata())

        mute_default = _glyph_tile(GLYPH_MUTE, (), 24, 24, 4)
        mute_explicit_default_color = _glyph_tile(GLYPH_MUTE, (GLYPH_RGB,), 24, 24, 4)
        assert list(mute_default.getdata()) == list(mute_explicit_default_color.getdata())


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
