"""Tests for dial_touch_layout.py — pure touch-zone geometry.

Covers the band layout across all profile sizes in dial_display_profiles.py
(layout_for()'s band/name/artist/cluster/down/up geometry), exact tiling
(zones + dead zones cover the panel with no gap/overlap), the remainder
policy (leftover pixels never land in a control rectangle), zone_at()
hit-testing at zone centres and in dead-zone/artist/middle-band gaps, the
selector surface's list_layout_for()/list_zone_at(), and the pinned 160x128
reference geometry.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
if _DIAL not in sys.path:
    sys.path.insert(0, _DIAL)

from dial_touch_layout import (  # noqa: E402
    BAND_DIVISOR_RICH,
    BAND_MAX_MM,
    COMPACT_MAX_SHORT_SIDE_MM,
    CONTENT_BASE,
    CONTENT_COMPACT,
    CONTENT_LARGE,
    CONTENT_RICH,
    FONT_BODY_MAX_PX,
    FONT_READOUT_MAX_PX,
    GEOMETRIES,
    GEOMETRY_EQ,
    GEOMETRY_IDLE,
    GEOMETRY_INFO,
    GEOMETRY_INFO_VALUE,
    GEOMETRY_LIST,
    GEOMETRY_MAIN,
    GEOMETRY_NONE,
    GEOMETRY_NOWIFI,
    GEOMETRY_OUTPUT,
    GEOMETRY_REPEAT,
    GEOMETRY_REPEAT_REPLAY,
    GEOMETRY_SDHEALTH,
    HALO_MAX_PX,
    LARGE_MIN_SHORT_SIDE_PX,
    RICH_MIN_SHORT_SIDE_PX,
    SUPERSAMPLE_DEFAULT,
    SUPERSAMPLE_LARGE,
    TOUCH_MIN_MM,
    TOUCH_SHORT_BELOW_BAND_MM,
    WARNING_ZONES,
    COMPACT_PICKER_LEFT_FRACTION,
    CompactLayout,
    CompactPickerLayout,
    EqBarLayout,
    EqLayout,
    InfoValueLayout,
    TouchZone,
    WarningLayout,
    ZoneRect,
    _dead_zone_margin,
    compact_layout_for,
    compact_picker_layout_for,
    eq_layout_for,
    hit_test,
    idle_layout_for,
    idle_zone_at,
    info_value_layout_for,
    layout_for,
    list_layout_for,
    list_zone_at,
    metrics_for,
    nowifi_layout_for,
    output_layout_for,
    repeat_layout_for,
    sdhealth_layout_for,
    warning_layout_for,
    repeat_zone_at,
    scale_px,
    zone_at,
    zone_rects_for,
    zones_for,
)

# The distinct profile sizes from dial_display_profiles.DISPLAY_PROFILES.
# Two profiles (st7789_320x240, ili9341_320x240) share 320x240; the layout
# depends only on the size, so it is listed once.
PROFILE_SIZES = [
    (160, 128),  # st7735s_160x128
    (128, 128),  # st7735s_128x128
    (240, 240),  # st7789_240x240
    (320, 240),  # st7789_320x240, ili9341_320x240
]

ALL_ZONES = {
    TouchZone.DOTS, TouchZone.NAME, TouchZone.OUTPUTS,
    TouchZone.MUTE, TouchZone.DOWN, TouchZone.UP, TouchZone.ARTWORK,
}


class TestExactTiling:
    """The union of the three active zones plus the implied dead-zone bands
    must exactly cover the panel: every pixel is in exactly one zone or
    exactly one dead zone, never both, never neither."""

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_zones_do_not_overlap(self, width, height):
        zones = zones_for(width, height)
        covered = [[None] * width for _ in range(height)]
        for zone, (x0, y0, x1, y1) in zones.items():
            for y in range(y0, y1):
                for x in range(x0, x1):
                    assert covered[y][x] is None, (
                        f"pixel ({x},{y}) claimed by both {covered[y][x]} and {zone}"
                    )
                    covered[y][x] = zone

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_every_pixel_is_zone_or_dead_zone(self, width, height):
        # The top band's controls reach below the band, so membership is
        # tested against each entry's touch rect (zones_for gives the drawn
        # rects only).
        touch_rects = [
            entry.touch_rect for entry in zone_rects_for(GEOMETRY_MAIN, width, height)
        ]
        for y in range(height):
            for x in range(width):
                z = zone_at(x, y, width, height)
                in_some_rect = any(
                    x0 <= x < x1 and y0 <= y < y1 for (x0, y0, x1, y1) in touch_rects
                )
                # zone_at agrees with manual rectangle membership: a hit
                # means some touch rectangle contains the point, a miss
                # (dead zone, the relocated artist line, middle band, or
                # out-of-bounds) means none does. The NAME zone now covers
                # what used to be the non-actuating artist area; the
                # relocated artist line (centre-low) is itself non-actuating
                # and stays dead pixels by construction, so this still
                # holds.
                assert (z is not None) == in_some_rect

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_zone_rects_within_panel_bounds(self, width, height):
        for x0, y0, x1, y1 in zones_for(width, height).values():
            assert 0 <= x0 < x1 <= width
            assert 0 <= y0 < y1 <= height


class TestRemainderPolicy:
    """Non-evenly-divisible widths (e.g. 320/2 is even, but the active width
    after the dead-zone gap is subtracted is not always) must not fatten one
    of DOWN/UP relative to the other — the leftover pixel(s) must be
    absorbed into a dead-zone gap."""

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_down_up_widths_equal_within_one_pixel(self, width, height):
        zones = zones_for(width, height)
        dw = zones[TouchZone.DOWN][2] - zones[TouchZone.DOWN][0]
        uw = zones[TouchZone.UP][2] - zones[TouchZone.UP][0]
        assert abs(dw - uw) <= 1


class TestZoneAt:
    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_zone_centres_hit_the_right_zone(self, width, height):
        zones = zones_for(width, height)
        for zone, (x0, y0, x1, y1) in zones.items():
            cx, cy = (x0 + x1) // 2, (y0 + y1) // 2
            assert zone_at(cx, cy, width, height) == zone

    def test_out_of_bounds_returns_none(self):
        assert zone_at(-1, 0, 160, 128) is None
        assert zone_at(0, -1, 160, 128) is None
        assert zone_at(160, 0, 160, 128) is None
        assert zone_at(0, 128, 160, 128) is None
        assert zone_at(1000, 1000, 160, 128) is None

    def test_dead_zone_margin_is_positive_and_scales(self):
        assert _dead_zone_margin(160, 128) == 3
        assert _dead_zone_margin(128, 128) == 3
        assert _dead_zone_margin(240, 240) > 3

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_tap_in_name_area_hits_name_and_middle_hits_artwork(self, width, height):
        layout = layout_for(width, height)

        # The old artist-area rectangle is now the NAME zone.
        nx0, ny0, nx1, ny1 = layout.name
        ncx, ncy = (nx0 + nx1) // 2, (ny0 + ny1) // 2
        assert zone_at(ncx, ncy, width, height) == TouchZone.NAME

        # The relocated (centre-low) artist line is over the ARTWORK zone
        # (the inter-band strip) but is itself still non-actuating in its
        # OWN right — its rect has no TouchZone of its own, so a tap there
        # resolves to whatever zone actually covers that point, which is
        # now ARTWORK rather than a dead zone.
        ax0, ay0, ax1, ay1 = layout.artist
        acx, acy = (ax0 + ax1) // 2, (ay0 + ay1) // 2
        assert zone_at(acx, acy, width, height) == TouchZone.ARTWORK

        mid_y = (layout.top_band[3] + layout.bottom_band[1]) // 2
        assert zone_at(width // 2, mid_y, width, height) == TouchZone.ARTWORK

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_divider_x_sits_in_the_gap(self, width, height):
        """The main screen's own footer dividers (the three-way split) are
        dead zones. layout.divider_x (the two-way split's midpoint, kept for
        the repeat/detail screens) is no longer necessarily one of the main
        screen's dead zones now that the footer is three-way."""
        layout = layout_for(width, height)
        y0, y1 = layout.bottom_band[1], layout.bottom_band[3]
        for divider_x in layout.footer_dividers:
            for y in range(y0, y1):
                assert zone_at(divider_x, y, width, height) is None


class TestZonesForCompleteness:
    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_all_three_zones_present(self, width, height):
        assert set(zones_for(width, height).keys()) == ALL_ZONES

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_zones_for_matches_layout_for(self, width, height):
        zones = zones_for(width, height)
        layout = layout_for(width, height)
        assert zones[TouchZone.DOTS] == layout.dots
        assert zones[TouchZone.NAME] == layout.name
        assert zones[TouchZone.OUTPUTS] == layout.volume_cluster
        assert zones[TouchZone.MUTE] == layout.footer_mute
        assert zones[TouchZone.DOWN] == layout.footer_down
        assert zones[TouchZone.UP] == layout.footer_up


class TestBandLayout:
    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_band_rects_are_a_quarter_of_the_height(self, width, height):
        layout = layout_for(width, height)
        band_h = height // 4
        assert layout.top_band == (0, 0, width, band_h)
        assert layout.bottom_band == (0, height - band_h, width, height)

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_down_and_up_lie_inside_the_bottom_band(self, width, height):
        layout = layout_for(width, height)
        by0, by1 = layout.bottom_band[1], layout.bottom_band[3]
        for rect in (layout.down, layout.up):
            x0, y0, x1, y1 = rect
            assert by0 <= y0 < y1 <= by1
            assert 0 <= x0 < x1 <= width

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_mute_and_name_lie_inside_the_top_band(self, width, height):
        layout = layout_for(width, height)
        ty0, ty1 = layout.top_band[1], layout.top_band[3]
        for rect in (layout.volume_cluster, layout.name):
            x0, y0, x1, y1 = rect
            assert ty0 <= y0 < y1 <= ty1
            assert 0 <= x0 < x1 <= width

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_name_and_mute_are_separated_by_two_margins(self, width, height):
        layout = layout_for(width, height)
        margin = _dead_zone_margin(width, height)
        gap = layout.volume_cluster[0] - layout.name[2]
        assert gap == 2 * margin

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_artist_sits_above_bottom_band_and_never_overlaps_it(self, width, height):
        layout = layout_for(width, height)
        ax0, ay0, ax1, ay1 = layout.artist
        assert ay1 == layout.bottom_band[1]
        assert ay0 < ay1
        assert 0 <= ax0 < ax1 <= width

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_middle_rows_are_entirely_the_artwork_zone(self, width, height):
        # The inter-band strip is the ARTWORK zone (a tap there hides the
        # bands) — it is not a dead zone at all — except where the top
        # band's controls reach down into it: there a tap takes the control
        # whose touch rect covers the point.
        layout = layout_for(width, height)
        reaching = [
            entry for entry in zone_rects_for(GEOMETRY_MAIN, width, height)
            if entry.zone in (TouchZone.DOTS, TouchZone.NAME, TouchZone.OUTPUTS)
        ]
        for y in range(layout.top_band[3], layout.bottom_band[1]):
            for x in range(width):
                expected = TouchZone.ARTWORK
                for entry in reaching:
                    x0, y0, x1, y1 = entry.touch_rect
                    if x0 <= x < x1 and y0 <= y < y1:
                        expected = entry.zone
                        break
                assert zone_at(x, y, width, height) == expected


def test_reference_geometry_exact():
    """Pin the 160x128 numbers so any future
    drift in the band-layout arithmetic is deliberate, not accidental."""
    layout = layout_for(160, 128)
    assert layout.volume_cluster == (99, 0, 160, 29)
    assert layout.dots == (3, 0, 35, 32)
    # DOTS (m=3, band_h=32 wide) plus the 2m gap pushes name's x0 from the
    # earlier value of 3 to 41.
    assert layout.name == (41, 0, 93, 32)
    assert layout.artist == (3, 80, 157, 96)
    assert layout.title == (3, 64, 157, 80)
    assert layout.down == (0, 99, 77, 128)
    assert layout.up == (83, 99, 160, 128)
    assert layout.divider_x == 80
    assert layout.album is None


class TestListLayout:
    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_three_rows_per_page_on_every_profile(self, width, height):
        layout = list_layout_for(width, height)
        assert layout.rows_per_page == 3
        assert len(layout.rows) == 3

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_rows_tile_from_zero_to_bar_with_no_gap_or_overlap(self, width, height):
        layout = list_layout_for(width, height)
        bar_h = height // 4
        expected_top = 0
        for x0, y0, x1, y1 in layout.rows:
            assert (x0, x1) == (0, width)
            assert y0 == expected_top
            assert y1 - y0 == layout.row_h
            expected_top = y1
        assert expected_top == height - bar_h
        assert layout.bar == (0, height - bar_h, width, height)

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_bar_splits_into_three_with_dead_gaps(self, width, height):
        layout = list_layout_for(width, height)
        margin = _dead_zone_margin(width, height)
        # The first gap (back -> down) never absorbs the remainder, so it is
        # always exactly 2*margin; the last gap (down -> up) may be wider by
        # the leftover pixel(s) — see _split's REMAINDER POLICY.
        assert layout.down[0] - layout.back[2] == 2 * margin
        assert layout.up[0] - layout.down[2] >= 2 * margin

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_row_centres_hit_list_row_with_index(self, width, height):
        layout = list_layout_for(width, height)
        for i, (x0, y0, x1, y1) in enumerate(layout.rows):
            cx, cy = (x0 + x1) // 2, (y0 + y1) // 2
            assert list_zone_at(cx, cy, width, height) == (TouchZone.LIST_ROW, i)

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_bar_centres_hit_back_down_up(self, width, height):
        layout = list_layout_for(width, height)
        for zone, rect in (
            (TouchZone.LIST_BACK, layout.back),
            (TouchZone.LIST_DOWN, layout.down),
            (TouchZone.LIST_UP, layout.up),
        ):
            x0, y0, x1, y1 = rect
            cx, cy = (x0 + x1) // 2, (y0 + y1) // 2
            assert list_zone_at(cx, cy, width, height) == (zone, None)

    def test_gaps_between_bar_zones_return_none(self):
        layout = list_layout_for(160, 128)
        gap_x = (layout.back[2] + layout.down[0]) // 2
        gap_y = (layout.bar[1] + layout.bar[3]) // 2
        assert list_zone_at(gap_x, gap_y, 160, 128) is None

    def test_out_of_bounds_returns_none(self):
        assert list_zone_at(-1, 0, 160, 128) is None
        assert list_zone_at(0, -1, 160, 128) is None
        assert list_zone_at(160, 0, 160, 128) is None
        assert list_zone_at(1000, 1000, 160, 128) is None

    def test_reference_geometry_exact(self):
        """Pin the 160x128 numbers so any future drift is deliberate."""
        layout = list_layout_for(160, 128)
        assert layout.row_h == 32
        assert layout.rows == ((0, 0, 160, 32), (0, 32, 160, 64), (0, 64, 160, 96))
        assert layout.bar == (0, 96, 160, 128)


# ---------------------------------------------------------------------------
# DOTS zone.
# ---------------------------------------------------------------------------

class TestDotsZone:
    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_dots_is_square_with_the_band_height(self, width, height):
        layout = layout_for(width, height)
        x0, y0, x1, y1 = layout.dots
        band_h = height // 4
        assert (x1 - x0) == band_h
        assert (y1 - y0) == band_h

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_dots_sits_left_of_name_with_a_two_margin_gap(self, width, height):
        layout = layout_for(width, height)
        margin = _dead_zone_margin(width, height)
        gap = layout.name[0] - layout.dots[2]
        assert gap == 2 * margin

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_dots_starts_at_the_left_margin(self, width, height):
        layout = layout_for(width, height)
        margin = _dead_zone_margin(width, height)
        assert layout.dots[0] == margin

    def test_dots_centre_hits_dots_zone(self):
        layout = layout_for(160, 128)
        x0, y0, x1, y1 = layout.dots
        cx, cy = (x0 + x1) // 2, (y0 + y1) // 2
        assert zone_at(cx, cy, 160, 128) == TouchZone.DOTS

    def test_dots_reference_geometry_exact(self):
        layout = layout_for(160, 128)
        assert layout.dots == (3, 0, 35, 32)


# ---------------------------------------------------------------------------
# The repeat surface: repeat_layout_for()/repeat_zone_at().
# ---------------------------------------------------------------------------

class TestRepeatSurface:
    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_dots_name_and_volume_cluster_match_the_main_surface(self, width, height):
        main = layout_for(width, height)
        repeat = repeat_layout_for(width, height)
        assert repeat.dots == main.dots
        assert repeat.name == main.name
        assert repeat.volume_cluster == main.volume_cluster

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_row_is_a_full_width_strip_of_two_band_heights(self, width, height):
        repeat = repeat_layout_for(width, height)
        x0, y0, x1, y1 = repeat.row
        band_h = height // 4
        margin = _dead_zone_margin(width, height)
        assert (y1 - y0) == 2 * band_h
        assert x0 == margin
        assert x1 == width - margin
        cy = (y0 + y1) // 2
        assert cy == height // 2

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_line_shares_the_rows_geometry(self, width, height):
        repeat = repeat_layout_for(width, height)
        assert repeat.line == repeat.row

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_start_stop_reuse_down_up(self, width, height):
        main = layout_for(width, height)
        repeat = repeat_layout_for(width, height)
        assert repeat.start == main.down
        assert repeat.stop == main.up

    def test_repeat_zone_at_resolves_dots(self):
        layout = repeat_layout_for(160, 128)
        x0, y0, x1, y1 = layout.dots
        cx, cy = (x0 + x1) // 2, (y0 + y1) // 2
        assert repeat_zone_at(cx, cy, 160, 128) == TouchZone.DOTS

    def test_repeat_zone_at_resolves_name(self):
        layout = repeat_layout_for(160, 128)
        x0, y0, x1, y1 = layout.name
        cx, cy = (x0 + x1) // 2, (y0 + y1) // 2
        assert repeat_zone_at(cx, cy, 160, 128) == TouchZone.NAME

    def test_repeat_zone_at_resolves_row(self):
        layout = repeat_layout_for(160, 128)
        x0, y0, x1, y1 = layout.row
        cx, cy = (x0 + x1) // 2, (y0 + y1) // 2
        assert repeat_zone_at(cx, cy, 160, 128) == TouchZone.REPEAT_PLAY

    def test_repeat_artwork_is_hit_only_outside_the_row(self):
        """On the rich tier the row leaves gaps of artwork above and below
        it: a tap in a gap is an artwork tap, a tap in the row is still the
        row."""
        metrics = metrics_for(320, 240, 0.1778)
        layout = repeat_layout_for(320, 240, metrics=metrics)
        # The top band's controls reach below the band; the artwork gap is
        # what is left between that reach and the row.
        reach_bottom = metrics.band_h + metrics.band_h // 3
        assert layout.row[1] > reach_bottom >= layout.top_band[3]
        gap_y = (reach_bottom + layout.row[1]) // 2
        row_y = (layout.row[1] + layout.row[3]) // 2
        hit = hit_test(GEOMETRY_REPEAT, 160, gap_y, 320, 240, metrics=metrics)
        assert hit is not None and hit.zone == TouchZone.ARTWORK
        hit = hit_test(GEOMETRY_REPEAT, 160, row_y, 320, 240, metrics=metrics)
        assert hit is not None and hit.zone == TouchZone.REPEAT_PLAY

    def test_repeat_zone_at_resolves_outputs(self):
        """The top band's volume readout opens the outputs list on the
        repeat screen too (same as the main screen), so a tap there
        resolves to OUTPUTS, not MUTE -- the repeat screen has no mute
        control of its own."""
        layout = repeat_layout_for(160, 128)
        x0, y0, x1, y1 = layout.volume_cluster
        cx, cy = (x0 + x1) // 2, (y0 + y1) // 2
        assert repeat_zone_at(cx, cy, 160, 128) == TouchZone.OUTPUTS

    def test_repeat_zone_at_resolves_start_and_stop(self):
        layout = repeat_layout_for(160, 128)
        sx0, sy0, sx1, sy1 = layout.start
        assert repeat_zone_at((sx0 + sx1) // 2, (sy0 + sy1) // 2, 160, 128) == TouchZone.REPEAT_START
        tx0, ty0, tx1, ty1 = layout.stop
        assert repeat_zone_at((tx0 + tx1) // 2, (ty0 + ty1) // 2, 160, 128) == TouchZone.REPEAT_STOP

    def test_repeat_zone_at_dead_zone_returns_none(self):
        layout = repeat_layout_for(160, 128)
        # The divider between start and stop is a dead zone, same geometry
        # as the main surface's DOWN/UP divider.
        assert repeat_zone_at(layout.divider_x, layout.start[1], 160, 128) is None

    def test_repeat_zone_at_out_of_bounds_returns_none(self):
        assert repeat_zone_at(-1, 0, 160, 128) is None
        assert repeat_zone_at(1000, 1000, 160, 128) is None


# ---------------------------------------------------------------------------
# The idle surface: idle_layout_for()/idle_zone_at().
# ---------------------------------------------------------------------------

class TestIdleSurface:
    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_affordance_is_the_artist_rect(self, width, height):
        main = layout_for(width, height)
        idle = idle_layout_for(width, height)
        assert idle.affordance == main.artist

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_top_band_excluded(self, width, height):
        layout = layout_for(width, height)
        ty0, ty1 = layout.top_band[1], layout.top_band[3]
        for y in range(ty0, ty1):
            assert idle_zone_at(width // 2, y, width, height) is None

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_everything_below_top_band_is_idle_replay(self, width, height):
        layout = layout_for(width, height)
        for y in (layout.top_band[3], height - 1):
            assert idle_zone_at(width // 2, y, width, height) == TouchZone.IDLE_REPLAY

    def test_out_of_bounds_returns_none(self):
        assert idle_zone_at(-1, 50, 160, 128) is None
        assert idle_zone_at(160, 50, 160, 128) is None
        assert idle_zone_at(50, -1, 160, 128) is None
        assert idle_zone_at(50, 128, 160, 128) is None


class TestIdleInfoZone:
    """The "i" affordance's own square: 8mm by construction wherever
    density is known, a band-high square otherwise — pinned at every
    shipped panel/density combination."""

    def test_pinned_at_320x240_rich(self):
        metrics = metrics_for(320, 240, 0.1778)
        assert metrics.touch_min_px == 45
        idle = idle_layout_for(320, 240, metrics=metrics)
        assert idle.info == (269, 6, 314, 51)
        assert idle.wifi == (6, 6, 51, 51)
        assert idle.replay == (0, 48, 320, 240)

    def test_pinned_at_240x240_compact(self):
        metrics = metrics_for(240, 240, 0.0973)
        assert metrics.touch_min_px == 83
        idle = idle_layout_for(240, 240, metrics=metrics)
        assert idle.info == (151, 6, 234, 89)
        assert idle.wifi == (6, 6, 89, 89)
        assert idle.replay == (0, 0, 240, 240)

    def test_pinned_at_128x128_compact(self):
        metrics = metrics_for(128, 128, 0.2021)
        assert metrics.touch_min_px == 40
        idle = idle_layout_for(128, 128, metrics=metrics)
        assert idle.info == (85, 3, 125, 43)
        assert idle.wifi == (3, 3, 43, 43)
        assert idle.replay == (0, 0, 128, 128)

    def test_pinned_at_160x128_base(self):
        metrics = metrics_for(160, 128, 0.2231)
        assert metrics.touch_min_px == 36
        idle = idle_layout_for(160, 128, metrics=metrics)
        assert idle.info == (121, 3, 157, 39)
        assert idle.wifi == (3, 3, 39, 39)
        assert idle.replay == (0, 32, 160, 128)

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_density_unknown_uses_band_high_square(self, width, height):
        # metrics=None (tests, a bare caller): side is band_h, not
        # touch_min_px (which is None with no density).
        metrics = metrics_for(width, height)
        assert metrics.touch_min_px is None
        idle = idle_layout_for(width, height, metrics=metrics)
        m, side = metrics.margin, metrics.band_h
        assert idle.info == (width - m - side, m, width - m, m + side)

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_square_is_at_least_8mm_when_density_known(self, width, height):
        mm_per_px = 0.1778 if min(width, height) >= 200 else 0.2021
        metrics = metrics_for(width, height, mm_per_px)
        idle = idle_layout_for(width, height, metrics=metrics)
        x0, y0, x1, y1 = idle.info
        assert (x1 - x0) * mm_per_px >= TOUCH_MIN_MM - 1e-9
        assert (y1 - y0) * mm_per_px >= TOUCH_MIN_MM - 1e-9
        assert (x1 - x0) == (y1 - y0)


# ---------------------------------------------------------------------------
# The shared zone-rect table: one ordered table per geometry, read by both
# the hit-tests above and the compositor's pressed-zone wash.
# ---------------------------------------------------------------------------

class TestZoneRectsCompleteness:
    """Every TouchZone member must belong to some geometry's table — a new
    enum member that no geometry lists would otherwise silently never be
    reachable by any hit-test."""

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_union_of_geometries_covers_every_zone(self, width, height):
        covered = set()
        for geometry in GEOMETRIES:
            covered.update(entry.zone for entry in zone_rects_for(geometry, width, height))
        assert covered == set(TouchZone)


class TestZoneRectsOrder:
    """The table's order is hit-test order — pinned once per geometry at
    the reference size."""

    def test_main_order(self):
        entries = zone_rects_for(GEOMETRY_MAIN, 160, 128)
        assert [(e.zone, e.index) for e in entries] == [
            (TouchZone.DOTS, None),
            (TouchZone.NAME, None),
            (TouchZone.OUTPUTS, None),
            (TouchZone.MUTE, None),
            (TouchZone.DOWN, None),
            (TouchZone.UP, None),
            (TouchZone.ARTWORK, None),
        ]

    def test_list_order(self):
        entries = zone_rects_for(GEOMETRY_LIST, 160, 128)
        assert [(e.zone, e.index) for e in entries] == [
            (TouchZone.LIST_ROW, 0),
            (TouchZone.LIST_ROW, 1),
            (TouchZone.LIST_ROW, 2),
            (TouchZone.LIST_BACK, None),
            (TouchZone.LIST_DOWN, None),
            (TouchZone.LIST_UP, None),
        ]

    def test_repeat_order(self):
        entries = zone_rects_for(GEOMETRY_REPEAT, 160, 128)
        assert [(e.zone, e.index) for e in entries] == [
            (TouchZone.DOTS, None),
            (TouchZone.NAME, None),
            (TouchZone.OUTPUTS, None),
            (TouchZone.REPEAT_PLAY, None),
            (TouchZone.REPEAT_START, None),
            (TouchZone.REPEAT_STOP, None),
            (TouchZone.ARTWORK, None),
        ]

    def test_idle_order(self):
        entries = zone_rects_for(GEOMETRY_IDLE, 160, 128)
        assert [(e.zone, e.index) for e in entries] == [
            (TouchZone.IDLE_WIFI, None),
            (TouchZone.IDLE_INFO, None),
            (TouchZone.IDLE_REPLAY, None),
        ]

    def test_output_order(self):
        entries = zone_rects_for(GEOMETRY_OUTPUT, 160, 128)
        assert [(e.zone, e.index) for e in entries] == [
            (TouchZone.OUTPUT_BACK, None),
            (TouchZone.NAME, None),
            (TouchZone.OUTPUT_TOGGLE, None),
            (TouchZone.OUTPUT_DOWN, None),
            (TouchZone.OUTPUT_UP, None),
        ]


class TestZoneRectsMatchLayoutFields:
    """The table is a view, not a recomputation: every rect it carries must
    be exactly the corresponding *Layout field."""

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_main_rects_are_layout_fields(self, width, height):
        layout = layout_for(width, height)
        entries = {e.zone: e.rect for e in zone_rects_for(GEOMETRY_MAIN, width, height)}
        assert entries[TouchZone.DOTS] == layout.dots
        assert entries[TouchZone.NAME] == layout.name
        assert entries[TouchZone.OUTPUTS] == layout.volume_cluster
        assert entries[TouchZone.MUTE] == layout.footer_mute
        assert entries[TouchZone.DOWN] == layout.footer_down
        assert entries[TouchZone.UP] == layout.footer_up

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_list_rects_are_layout_fields(self, width, height):
        layout = list_layout_for(width, height)
        entries = list(zone_rects_for(GEOMETRY_LIST, width, height))
        row_entries = [e for e in entries if e.zone == TouchZone.LIST_ROW]
        assert [e.rect for e in row_entries] == list(layout.rows)
        assert [e.index for e in row_entries] == list(range(len(layout.rows)))
        by_zone = {e.zone: e.rect for e in entries if e.zone != TouchZone.LIST_ROW}
        assert by_zone[TouchZone.LIST_BACK] == layout.back
        assert by_zone[TouchZone.LIST_DOWN] == layout.down
        assert by_zone[TouchZone.LIST_UP] == layout.up

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_repeat_rects_are_layout_fields(self, width, height):
        layout = repeat_layout_for(width, height)
        entries = {e.zone: e.rect for e in zone_rects_for(GEOMETRY_REPEAT, width, height)}
        assert entries[TouchZone.DOTS] == layout.dots
        assert entries[TouchZone.NAME] == layout.name
        assert entries[TouchZone.OUTPUTS] == layout.volume_cluster
        assert entries[TouchZone.REPEAT_PLAY] == layout.row
        assert entries[TouchZone.REPEAT_START] == layout.start
        assert entries[TouchZone.REPEAT_STOP] == layout.stop
        assert entries[TouchZone.ARTWORK] == layout.artwork == layout_for(width, height).artwork

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_idle_rect_is_layout_field(self, width, height):
        layout = idle_layout_for(width, height)
        entries = {e.zone: e.rect for e in zone_rects_for(GEOMETRY_IDLE, width, height)}
        assert entries[TouchZone.IDLE_WIFI] == layout.wifi
        assert entries[TouchZone.IDLE_INFO] == layout.info
        assert entries[TouchZone.IDLE_REPLAY] == layout.replay

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_output_rects_are_layout_fields(self, width, height):
        layout = output_layout_for(width, height)
        entries = {e.zone: e.rect for e in zone_rects_for(GEOMETRY_OUTPUT, width, height)}
        assert entries[TouchZone.OUTPUT_BACK] == layout.back
        assert entries[TouchZone.NAME] == layout.name
        assert entries[TouchZone.OUTPUT_TOGGLE] == layout.row
        assert entries[TouchZone.OUTPUT_DOWN] == layout.down
        assert entries[TouchZone.OUTPUT_UP] == layout.up


class TestOutputLayout:
    """OutputLayout is the tiered repeat layout's own geometry, relabelled
    — every field must equal the layout it aliases, at every tier."""

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_fields_equal_the_layouts_they_alias(self, width, height):
        main = layout_for(width, height)
        repeat = repeat_layout_for(width, height)
        output = output_layout_for(width, height)
        assert output.back == main.dots
        assert output.name == main.name
        assert output.volume_cluster == main.volume_cluster
        assert output.row == repeat.row
        assert output.down == main.down
        assert output.up == main.up
        assert output.divider_x == main.divider_x
        assert output.top_band == main.top_band
        assert output.bottom_band == main.bottom_band

    def test_pinned_geometry_at_320x240_rich(self):
        metrics = metrics_for(320, 240, 0.1778)
        output = output_layout_for(320, 240, metrics=metrics)
        assert output.back == (6, 0, 54, 48)
        assert output.name == (66, 0, 186, 48)
        assert output.volume_cluster == (198, 0, 320, 42)
        assert output.row == (6, 72, 314, 168)
        assert output.down == (0, 198, 154, 240)
        assert output.up == (166, 198, 320, 240)
        assert output.divider_x == 160


class TestListZoneAtExhaustive:
    """Every pixel of every profile size against a hand-written reference
    (row containment, then bar containment) — the per-centre tests above
    already pin the happy path; this pins the whole plane, dead zones
    included."""

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_every_pixel_matches_a_hand_written_reference(self, width, height):
        layout = list_layout_for(width, height)

        def reference(x, y):
            for i, (x0, y0, x1, y1) in enumerate(layout.rows):
                if x0 <= x < x1 and y0 <= y < y1:
                    return (TouchZone.LIST_ROW, i)
            for zone, (x0, y0, x1, y1) in (
                (TouchZone.LIST_BACK, layout.back),
                (TouchZone.LIST_DOWN, layout.down),
                (TouchZone.LIST_UP, layout.up),
            ):
                if x0 <= x < x1 and y0 <= y < y1:
                    return (zone, None)
            return None

        for y in range(height):
            for x in range(width):
                assert list_zone_at(x, y, width, height) == reference(x, y)


class TestInfoGeometry:
    """GEOMETRY_INFO: off the compact tier, the list table with every
    LIST_ROW entry removed — the info page's rows are display-only, dead at
    the geometry level there. On the compact tier the rows are tappable
    instead: the table is the list table unchanged (its rows open the
    compact info page's own drill-in — see info_row_tap())."""

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_equals_list_minus_rows_off_compact(self, width, height):
        list_entries = zone_rects_for(GEOMETRY_LIST, width, height)
        info_entries = zone_rects_for(GEOMETRY_INFO, width, height)
        assert info_entries == tuple(e for e in list_entries if e.zone != TouchZone.LIST_ROW)
        assert all(e.zone != TouchZone.LIST_ROW for e in info_entries)

    @pytest.mark.parametrize("metrics", [metrics_for(240, 240, 0.0973), metrics_for(128, 128, 0.2021)])
    def test_equals_list_unchanged_on_compact(self, metrics):
        list_entries = zone_rects_for(GEOMETRY_LIST, metrics.width, metrics.height, metrics=metrics)
        info_entries = zone_rects_for(GEOMETRY_INFO, metrics.width, metrics.height, metrics=metrics)
        assert info_entries == list_entries
        assert any(e.zone == TouchZone.LIST_ROW for e in info_entries)

    @pytest.mark.parametrize("metrics", [None, metrics_for(320, 240, 0.1778)])
    def test_no_pixel_ever_resolves_to_a_row_off_compact(self, metrics):
        width = metrics.width if metrics is not None else 160
        height = metrics.height if metrics is not None else 128
        for y in range(height):
            for x in range(width):
                hit = hit_test(GEOMETRY_INFO, x, y, width, height, metrics=metrics)
                assert hit is None or hit.zone != TouchZone.LIST_ROW

    @pytest.mark.parametrize("metrics", [metrics_for(240, 240, 0.0973), metrics_for(128, 128, 0.2021)])
    def test_rows_resolve_at_the_pinned_picker_rects_on_compact(self, metrics):
        p = compact_picker_layout_for(metrics.width, metrics.height, metrics=metrics)
        for rect, index in ((p.row0, 0), (p.row1, 1)):
            cx, cy = (rect[0] + rect[2]) // 2, (rect[1] + rect[3]) // 2
            hit = hit_test(GEOMETRY_INFO, cx, cy, metrics.width, metrics.height, metrics=metrics)
            assert hit is not None and (hit.zone, hit.index) == (TouchZone.LIST_ROW, index)

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_controls_resolve_exactly_as_on_the_list(self, width, height):
        list_layout = list_layout_for(width, height)
        for zone, rect in (
            (TouchZone.LIST_BACK, list_layout.back),
            (TouchZone.LIST_DOWN, list_layout.down),
            (TouchZone.LIST_UP, list_layout.up),
        ):
            if rect is None:
                continue
            cx, cy = (rect[0] + rect[2]) // 2, (rect[1] + rect[3]) // 2
            list_hit = hit_test(GEOMETRY_LIST, cx, cy, width, height)
            info_hit = hit_test(GEOMETRY_INFO, cx, cy, width, height)
            assert info_hit is not None and (info_hit.zone, info_hit.index) == (list_hit.zone, list_hit.index)
        rail = list_layout.rail_up, list_layout.rail_cancel, list_layout.rail_down
        for rect, zone in zip(rail, (TouchZone.LIST_UP, TouchZone.LIST_BACK, TouchZone.LIST_DOWN)):
            if rect is None:
                continue
            cx, cy = (rect[0] + rect[2]) // 2, (rect[1] + rect[3]) // 2
            info_hit = hit_test(GEOMETRY_INFO, cx, cy, width, height)
            assert info_hit is not None and info_hit.zone == zone

    def test_is_pure(self):
        for width, height in PROFILE_SIZES:
            a = zone_rects_for(GEOMETRY_INFO, width, height)
            b = zone_rects_for(GEOMETRY_INFO, width, height)
            assert a == b
        for metrics in (metrics_for(240, 240, 0.0973), metrics_for(128, 128, 0.2021)):
            a = zone_rects_for(GEOMETRY_INFO, metrics.width, metrics.height, metrics=metrics)
            b = zone_rects_for(GEOMETRY_INFO, metrics.width, metrics.height, metrics=metrics)
            assert a == b


class TestIdleZoneAtExhaustive:
    """Every pixel of every profile size, plus a one-pixel ring outside the
    panel: IDLE_WIFI inside the top-left square, else IDLE_INFO inside the
    "i" square (checked first, so the two corner squares win the corners
    they share with IDLE_REPLAY), else IDLE_REPLAY iff the point is
    on-panel and at or below the top band, else None."""

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_matches_top_band_boundary_at_every_pixel_and_a_ring_outside(self, width, height):
        band_h = height // 4
        idle = idle_layout_for(width, height)
        info = idle.info
        ix0, iy0, ix1, iy1 = info
        wx0, wy0, wx1, wy1 = idle.wifi
        for y in range(-1, height + 1):
            for x in range(-1, width + 1):
                expected = None
                if wx0 <= x < wx1 and wy0 <= y < wy1:
                    expected = TouchZone.IDLE_WIFI
                elif ix0 <= x < ix1 and iy0 <= y < iy1:
                    expected = TouchZone.IDLE_INFO
                elif 0 <= x < width and 0 <= y < height and y >= band_h:
                    expected = TouchZone.IDLE_REPLAY
                assert idle_zone_at(x, y, width, height) == expected


class TestHitTestUnknownGeometry:
    def test_raises_key_error(self):
        with pytest.raises(KeyError):
            hit_test("bogus", 0, 0, 160, 128)


class TestIdleLayoutReplayField:
    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_replay_is_the_panel_below_the_top_band(self, width, height):
        idle = idle_layout_for(width, height)
        assert idle.replay == (0, height // 4, width, height)


class TestIdleWifiZone:
    def test_mirrors_the_info_square(self):
        for metrics in (metrics_for(320, 240, 0.1778), metrics_for(240, 240, 0.0973),
                        metrics_for(128, 128, 0.2021), metrics_for(160, 128, 0.2231), metrics_for(160, 128)):
            idle = idle_layout_for(metrics.width, metrics.height, metrics=metrics)
            m = metrics.margin
            side = idle.info[2] - idle.info[0]
            assert idle.wifi == (m, m, m + side, m + side)
            assert idle.wifi[3] == idle.info[3] and idle.wifi[1] == idle.info[1]

    def test_pinned(self):
        assert idle_layout_for(320, 240, metrics=metrics_for(320, 240, 0.1778)).wifi == (6, 6, 51, 51)
        assert idle_layout_for(240, 240, metrics=metrics_for(240, 240, 0.0973)).wifi == (6, 6, 89, 89)
        assert idle_layout_for(128, 128, metrics=metrics_for(128, 128, 0.2021)).wifi == (3, 3, 43, 43)
        assert idle_layout_for(160, 128, metrics=metrics_for(160, 128, 0.2231)).wifi == (3, 3, 39, 39)
        assert idle_layout_for(160, 128).wifi == (3, 3, 35, 35)

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_wifi_and_info_never_overlap(self, width, height):
        idle = idle_layout_for(width, height)
        assert idle.wifi[2] <= idle.info[0]


class TestNoWifiLayout:
    def test_rich_pinned(self):
        l = nowifi_layout_for(320, 240, metrics=metrics_for(320, 240, 0.1778))
        assert l.card == (41, 48, 278, 192)
        assert l.message == (41, 48, 278, 114)
        assert l.dismiss == (41, 126, 153, 192)
        assert l.restart == (166, 126, 278, 192)
        assert (l.divider_x, l.divider_y) == (159, 120)

    def test_base_pinned(self):
        l = nowifi_layout_for(160, 128)
        assert l.card == (21, 25, 139, 102)
        assert l.message == (21, 25, 139, 60)
        assert l.dismiss == (21, 67, 77, 102)
        assert l.restart == (83, 67, 139, 102)
        assert (l.divider_x, l.divider_y) == (80, 63)

    def test_compact_is_the_two_by_two(self):
        for metrics in (_COMPACT_240x240, _COMPACT_128x128):
            c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
            l = nowifi_layout_for(metrics.width, metrics.height, metrics=metrics)
            assert l.card == (0, 0, metrics.width, metrics.height)
            assert (l.message, l.dismiss, l.restart) == (c.top_row, c.bl, c.br)
            assert (l.divider_x, l.divider_y) == (c.divider_x, c.divider_y)

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_cells_inside_card_with_dead_gaps(self, width, height):
        l = nowifi_layout_for(width, height)
        m = metrics_for(width, height).margin
        for r in (l.message, l.dismiss, l.restart):
            assert l.card[0] <= r[0] < r[2] <= l.card[2] and l.card[1] <= r[1] < r[3] <= l.card[3]
        assert l.dismiss[1] - l.message[3] >= 2 * m
        assert l.restart[0] - l.dismiss[2] >= 2 * m
        assert l.message[3] <= l.divider_y < l.dismiss[1]
        assert l.dismiss[2] <= l.divider_x < l.restart[0]

    def test_nowifi_table_is_dismiss_then_restart(self):
        entries = zone_rects_for(GEOMETRY_NOWIFI, 160, 128)
        l = nowifi_layout_for(160, 128)
        assert entries == (ZoneRect(TouchZone.NOWIFI_DISMISS, l.dismiss), ZoneRect(TouchZone.NOWIFI_RESTART, l.restart))

    def test_none_table_is_empty_everywhere(self):
        for width, height in PROFILE_SIZES:
            assert zone_rects_for(GEOMETRY_NONE, width, height) == ()
            assert hit_test(GEOMETRY_NONE, width // 2, height // 2, width, height) is None

    def test_message_row_is_dead(self):
        l = nowifi_layout_for(160, 128)
        cx, cy = (l.message[0] + l.message[2]) // 2, (l.message[1] + l.message[3]) // 2
        assert hit_test(GEOMETRY_NOWIFI, cx, cy, 160, 128) is None


class TestSdHealthLayout:
    """sdhealth_layout_for(): the No-WiFi card's own rectangle and message
    row, with the bottom row merged into one Dismiss cell."""

    def test_base_matches_nowifi_card_and_message(self):
        n = nowifi_layout_for(160, 128)
        s = sdhealth_layout_for(160, 128)
        assert s.card == n.card
        assert s.message == n.message
        assert s.divider_y == n.divider_y

    def test_base_dismiss_spans_both_nowifi_cells(self):
        n = nowifi_layout_for(160, 128)
        s = sdhealth_layout_for(160, 128)
        assert s.dismiss == (n.dismiss[0], n.dismiss[1], n.restart[2], n.restart[3])

    def test_compact_equals_the_two_by_two_with_bottom_row_merged(self):
        for metrics in (_COMPACT_240x240, _COMPACT_128x128):
            n = nowifi_layout_for(metrics.width, metrics.height, metrics=metrics)
            s = sdhealth_layout_for(metrics.width, metrics.height, metrics=metrics)
            assert s.card == n.card == (0, 0, metrics.width, metrics.height)
            assert s.message == n.message
            assert s.dismiss == (n.dismiss[0], n.dismiss[1], n.restart[2], n.restart[3])

    def test_sdhealth_table_is_one_dismiss_cell(self):
        entries = zone_rects_for(GEOMETRY_SDHEALTH, 160, 128)
        s = sdhealth_layout_for(160, 128)
        assert entries == (ZoneRect(TouchZone.SDHEALTH_DISMISS, s.dismiss),)

    def test_message_row_is_dead(self):
        s = sdhealth_layout_for(160, 128)
        cx, cy = (s.message[0] + s.message[2]) // 2, (s.message[1] + s.message[3]) // 2
        assert hit_test(GEOMETRY_SDHEALTH, cx, cy, 160, 128) is None

    def test_dismiss_cell_hits(self):
        s = sdhealth_layout_for(160, 128)
        cx, cy = (s.dismiss[0] + s.dismiss[2]) // 2, (s.dismiss[1] + s.dismiss[3]) // 2
        entry = hit_test(GEOMETRY_SDHEALTH, cx, cy, 160, 128)
        assert entry is not None and entry.zone == TouchZone.SDHEALTH_DISMISS


class TestWarningLayout:
    """warning_layout_for(): the No-WiFi table for two cells, the SD
    health table for one, an even split of the same row for more."""

    def test_two_buttons_matches_nowifi_exactly(self):
        n = nowifi_layout_for(320, 240, metrics=metrics_for(320, 240, 0.1778))
        w = warning_layout_for(320, 240, buttons=2, metrics=metrics_for(320, 240, 0.1778))
        assert w.card == n.card
        assert w.message == n.message
        assert w.cells == (n.dismiss, n.restart)
        assert w.divider_y == n.divider_y
        assert w.divider_xs == (n.divider_x,)

    def test_one_button_matches_sdhealth_exactly(self):
        s = sdhealth_layout_for(320, 240, metrics=metrics_for(320, 240, 0.1778))
        w = warning_layout_for(320, 240, buttons=1, metrics=metrics_for(320, 240, 0.1778))
        assert w.card == s.card
        assert w.message == s.message
        assert w.cells == (s.dismiss,)
        assert w.divider_xs == ()

    @pytest.mark.parametrize("width,height", [(160, 128), (128, 128), (240, 240), (320, 240)])
    def test_zero_buttons_is_the_whole_card_as_one_message_row(self, width, height):
        n = nowifi_layout_for(width, height)
        w = warning_layout_for(width, height, buttons=0)
        assert w.card == n.card
        assert w.message == n.card
        assert w.cells == ()
        assert w.divider_xs == ()
        assert w.divider_y is None

    def test_negative_buttons_is_treated_as_none(self):
        assert warning_layout_for(160, 128, buttons=-1) == warning_layout_for(160, 128, buttons=0)

    def test_one_and_two_buttons_are_unchanged_by_the_zero_form(self):
        assert warning_layout_for(160, 128, buttons=1).divider_y is not None
        assert warning_layout_for(160, 128, buttons=2).message != warning_layout_for(160, 128, buttons=2).card

    def test_three_buttons_are_ascending_non_overlapping_with_margin_gaps(self):
        metrics = metrics_for(320, 240, 0.1778)
        w = warning_layout_for(320, 240, buttons=3, metrics=metrics)
        assert len(w.cells) == 3
        assert len(w.divider_xs) == 2
        x0, _, x1, _ = w.card
        prev_end = x0
        for cell in w.cells:
            assert cell[0] >= prev_end
            assert cell[0] < cell[2] <= x1
            prev_end = cell[2]
        for i in range(len(w.cells) - 1):
            gap = w.cells[i + 1][0] - w.cells[i][2]
            assert gap == 2 * metrics.margin

    def test_warning_zones_is_the_union_of_both_geometries(self):
        nowifi_zones = {rect.zone for rect in zone_rects_for(GEOMETRY_NOWIFI, 160, 128)}
        sdhealth_zones = {rect.zone for rect in zone_rects_for(GEOMETRY_SDHEALTH, 160, 128)}
        assert WARNING_ZONES == nowifi_zones | sdhealth_zones


# ---------------------------------------------------------------------------
# Physical-size metrics: metrics_for()/LayoutMetrics/scale_px. Regular-tier
# equivalence is the permanent regression guard for this feature — every
# shipped profile must render byte-identically regardless of physical size,
# since nothing consumes `tier` yet.
# ---------------------------------------------------------------------------

# (reference_px, floor) pairs metrics_for() derives its scale fields from —
# see the module's *_PX_AT_REFERENCE tuples.
_METRICS_SCALE_FIELDS = [
    ("margin", 3, 1),
    ("divider_w", 1, 1),
    ("blur_radius", 10, 0),
    ("font_body", 13, 8),
    ("font_readout", 15, 9),
    ("icon", 15, 9),
    ("pad", 4, 2),
    ("icon_gap", 3, 2),
    ("halo_stroke", 2, 1),
    ("halo_blur", 2, 1),
]


class TestMetricsForReferenceEquivalence:
    """metrics_for(w, h) with no mm_per_px must reproduce today's numbers
    exactly — the one-line inline reference expressions here are stable
    enough to keep as a permanent pin (unlike a rendered-bytes reference)."""

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_scale_fields_match_inline_reference_formula(self, width, height):
        m = metrics_for(width, height)
        for field, ref, floor in _METRICS_SCALE_FIELDS:
            expected = max(floor, round(min(width, height) * ref / 128))
            assert getattr(m, field) == expected, field

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_band_row_and_paging_fields(self, width, height):
        m = metrics_for(width, height)
        assert m.band_h == height // 4
        assert m.row_h == m.band_h
        assert m.rows_per_page == 3


# Confirmed mm_per_px per PROFILE_SIZES entry, in order — see the density
# table in the profiles module's design notes. The 320x240 entry (index 3,
# shared by both 320x240 profiles) is confirmed but resolves to the rich
# content tier (the panel's short side clears RICH_MIN_SHORT_SIDE_PX and its
# quarter-height band is physically tall enough to escape the touch_short
# veto) — see TestRichAndLargeGeometry for its pins. Indices 1 and 2 (128x128,
# 240x240) are physically small enough to resolve to the compact tier at
# this density instead — see _COMPACT_RESOLVING_CASES below. Only the first
# entry stays base.
_CONFIRMED_MM_PER_PX = [0.2231, 0.2021, 0.0973, 0.1778]
_BASE_RESOLVING_CASES = list(zip(PROFILE_SIZES, _CONFIRMED_MM_PER_PX))[:1]
_COMPACT_RESOLVING_CASES = list(zip(PROFILE_SIZES, _CONFIRMED_MM_PER_PX))[1:3]

# A density fine enough that a panel is physically tiny by any measure —
# below the compact gate at every shipped pixel size, so this now resolves
# CONTENT_COMPACT everywhere rather than exercising the older rich/large
# touch_short veto: the compact gate (COMPACT_MAX_SHORT_SIDE_MM=27mm) is
# deliberately looser than the veto's own implied screen size
# (BAND_DIVISOR * TOUCH_SHORT_BELOW_BAND_MM = 24mm), so any panel dense
# enough to trip touch_short is always dense enough to be compact too — see
# TestTierReporting's compact-vs-veto tests.
_TOUCH_SHORT_VETO_MM_PER_PX = 0.05


class TestDensityHasNoEffectOnGeometry:
    """Passing a real mm_per_px must never change a single pixel of layout
    or hit-test geometry for a panel that resolves to the base content
    tier — only metrics_for()'s own reported fields (band_mm, content_tier,
    touch_min_px, ...) are density-dependent there. A panel whose pixel size
    and density resolve to a richer tier is a deliberate, pinned geometry
    change instead — see TestRichAndLargeGeometry."""

    @pytest.mark.parametrize("size,mm", _BASE_RESOLVING_CASES)
    def test_layout_for_unaffected(self, size, mm):
        width, height = size
        assert layout_for(width, height) == layout_for(
            width, height, metrics=metrics_for(width, height, mm)
        )

    @pytest.mark.parametrize("size,mm", _BASE_RESOLVING_CASES)
    def test_list_layout_for_unaffected(self, size, mm):
        width, height = size
        assert list_layout_for(width, height) == list_layout_for(
            width, height, metrics=metrics_for(width, height, mm)
        )

    @pytest.mark.parametrize("size,mm", _BASE_RESOLVING_CASES)
    def test_repeat_layout_for_unaffected(self, size, mm):
        width, height = size
        assert repeat_layout_for(width, height) == repeat_layout_for(
            width, height, metrics=metrics_for(width, height, mm)
        )

    @pytest.mark.parametrize("size,mm", _BASE_RESOLVING_CASES)
    def test_idle_layout_for_unaffected(self, size, mm):
        # affordance/replay are unaffected by density at the base tier, same
        # as every other layout here; `info` is a deliberate exception (see
        # TestIdleSurface's own pinned info-square tests) — it is 8mm by
        # construction whenever density is known, which is exactly the
        # feature, not a regression this invariant should guard.
        width, height = size
        base = idle_layout_for(width, height)
        dense = idle_layout_for(width, height, metrics=metrics_for(width, height, mm))
        assert base.affordance == dense.affordance
        assert base.replay == dense.replay

    @pytest.mark.parametrize("size,mm", _BASE_RESOLVING_CASES)
    def test_idle_layout_for_info_square_is_density_dependent(self, size, mm):
        # The one deliberate exception to this class's own invariant: see
        # test_idle_layout_for_unaffected above. wifi mirrors info, so it is
        # density-dependent for the same reason.
        width, height = size
        base = idle_layout_for(width, height)
        dense = idle_layout_for(width, height, metrics=metrics_for(width, height, mm))
        assert base.info != dense.info
        assert base.wifi != dense.wifi

    @pytest.mark.parametrize("size,mm", _BASE_RESOLVING_CASES)
    def test_zone_rects_for_unaffected(self, size, mm):
        # GEOMETRY_IDLE is excluded: its IDLE_INFO rect is the one
        # deliberate density-dependent exception (see
        # test_idle_layout_for_info_square_is_density_dependent above).
        width, height = size
        metrics = metrics_for(width, height, mm)
        for geometry in GEOMETRIES:
            if geometry == GEOMETRY_IDLE:
                continue
            assert zone_rects_for(geometry, width, height) == zone_rects_for(
                geometry, width, height, metrics=metrics
            )

    # -- the same panels at a compact-resolving density: layout_for()/
    # repeat_layout_for() are not tier-aware at all (they read only margin/
    # band_h, which the compact tier keeps at the base formula) so they stay
    # byte-identical; list_layout_for()'s rows_per_page and every compact
    # zone table are a deliberate, pinned difference instead — see
    # TestCompactTier below for their pins. GEOMETRY_OUTPUT is unreachable
    # on compact, so it is the one geometry left wholly untouched.

    @pytest.mark.parametrize("size,mm", _COMPACT_RESOLVING_CASES)
    def test_layout_for_unaffected_even_when_compact_resolving(self, size, mm):
        width, height = size
        assert layout_for(width, height) == layout_for(
            width, height, metrics=metrics_for(width, height, mm)
        )

    @pytest.mark.parametrize("size,mm", _COMPACT_RESOLVING_CASES)
    def test_repeat_layout_for_unaffected_even_when_compact_resolving(self, size, mm):
        width, height = size
        assert repeat_layout_for(width, height) == repeat_layout_for(
            width, height, metrics=metrics_for(width, height, mm)
        )

    @pytest.mark.parametrize("size,mm", _COMPACT_RESOLVING_CASES)
    def test_list_layout_for_rows_per_page_drops_to_two_when_compact_resolving(self, size, mm):
        width, height = size
        base_layout = list_layout_for(width, height)
        compact_layout = list_layout_for(width, height, metrics=metrics_for(width, height, mm))
        assert base_layout.rows_per_page == 3
        assert compact_layout.rows_per_page == 2
        assert len(compact_layout.rows) == 2

    @pytest.mark.parametrize("size,mm", _COMPACT_RESOLVING_CASES)
    def test_output_geometry_unaffected_even_when_compact_resolving(self, size, mm):
        width, height = size
        metrics = metrics_for(width, height, mm)
        assert zone_rects_for(GEOMETRY_OUTPUT, width, height) == zone_rects_for(
            GEOMETRY_OUTPUT, width, height, metrics=metrics
        )

    def test_touch_short_veto_and_compact_gate_agree(self):
        # Any density fine enough to trip the older rich/large touch_short
        # veto is also fine enough to trip the compact gate — the compact
        # threshold (27mm) is deliberately looser than the veto's own
        # implied screen size (BAND_DIVISOR * TOUCH_SHORT_BELOW_BAND_MM =
        # 24mm) — so this now resolves CONTENT_COMPACT at every shipped
        # pixel size rather than exercising the older veto path.
        for width, height in PROFILE_SIZES:
            metrics = metrics_for(width, height, _TOUCH_SHORT_VETO_MM_PER_PX)
            assert metrics.touch_short is True
            assert metrics.content_tier == CONTENT_COMPACT

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_mm_per_px_none_matches_the_bare_call(self, width, height):
        metrics = metrics_for(width, height)
        assert metrics.content_tier == CONTENT_BASE
        assert list_layout_for(width, height, metrics=metrics) == list_layout_for(width, height)


class TestScalePxConsolidation:
    """The three duplicated (reference_px, width, height, floor) scale
    formulas are now all dial_touch_layout.scale_px — check they still
    agree everywhere, not just at the reference size."""

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_scale_px_matches_dead_zone_margin(self, width, height):
        assert scale_px(3, width, height, 1) == _dead_zone_margin(width, height)

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_scale_px_matches_compositor_scaled_px(self, width, height):
        pytest.importorskip("PIL.Image", reason="Pillow not installed")
        from dial_display_compositor import _scaled_px

        for ref, floor in [(13, 8), (15, 9), (4, 2), (3, 2), (2, 1)]:
            assert scale_px(ref, width, height, floor) == _scaled_px(ref, width, height, floor)

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_scale_px_matches_image_blur_radius(self, width, height):
        pytest.importorskip("PIL.Image", reason="Pillow not installed")
        from dial_display_image import _blur_radius_for

        assert scale_px(10, width, height, 0) == _blur_radius_for(width, height)


# (size, mm_per_px, expected content_tier) for five confirmed sizes: the
# four shipped sizes plus one representative large panel. The 320x240 entry
# (both 320x240 profiles) resolves rich (the band cap does not bite at that
# density); the 128x128 and 240x240 entries are physically small enough
# (25.9mm, 23.4mm short side) to resolve to the compact tier ahead of any pixel-tier check.
_CONFIRMED_TIERS = [
    ((160, 128), 0.2231, CONTENT_BASE),
    ((128, 128), 0.2021, CONTENT_COMPACT),
    ((240, 240), 0.0973, CONTENT_COMPACT),
    ((320, 240), 0.1778, CONTENT_RICH),
    ((640, 480), 0.127, CONTENT_LARGE),
]

# (size, mm, tier, band_h, rows_per_page, row_h, touch_min_px, list_rail,
# supersample) — the confirmed-panel table, one row per _CONFIRMED_TIERS
# entry, above. The compact rows keep every base-formula field (band_h,
# row_h, touch_min_px, list_rail, supersample) except rows_per_page, which
# drops to 2 (the compact picker's own two visible rows).
_CONFIRMED_PANEL_TABLE = [
    ((160, 128), 0.2231, CONTENT_BASE, 32, 3, 32, 36, False, SUPERSAMPLE_DEFAULT),
    ((128, 128), 0.2021, CONTENT_COMPACT, 32, 2, 32, 40, False, SUPERSAMPLE_DEFAULT),
    ((240, 240), 0.0973, CONTENT_COMPACT, 60, 2, 60, 83, False, SUPERSAMPLE_DEFAULT),
    ((320, 240), 0.1778, CONTENT_RICH, 48, 5, 48, 45, True, SUPERSAMPLE_DEFAULT),
    ((640, 480), 0.127, CONTENT_LARGE, 95, 5, 96, 63, True, SUPERSAMPLE_LARGE),
]


class TestTierReporting:
    @pytest.mark.parametrize("size,mm,expected_tier", _CONFIRMED_TIERS)
    def test_confirmed_profiles_report_expected_tier(self, size, mm, expected_tier):
        width, height = size
        assert metrics_for(width, height, mm).content_tier == expected_tier

    @pytest.mark.parametrize(
        "size,mm,tier,band_h,rows_per_page,row_h,touch_min_px,list_rail,supersample",
        _CONFIRMED_PANEL_TABLE,
    )
    def test_confirmed_panel_table(
        self, size, mm, tier, band_h, rows_per_page, row_h, touch_min_px, list_rail, supersample,
    ):
        width, height = size
        m = metrics_for(width, height, mm)
        assert m.content_tier == tier
        assert m.band_h == band_h
        assert m.rows_per_page == rows_per_page
        assert m.row_h == row_h
        assert m.touch_min_px == touch_min_px
        assert m.list_rail == list_rail
        assert m.supersample == supersample

    def test_mm_per_px_none_gives_base_at_every_size(self):
        assert metrics_for(160, 128).content_tier == CONTENT_BASE
        assert metrics_for(240, 240).content_tier == CONTENT_BASE
        assert metrics_for(640, 480).content_tier == CONTENT_BASE

    def test_touch_min_px_matches_confirmed_table(self):
        from math import ceil

        for size, mm, _ in _CONFIRMED_TIERS:
            width, height = size
            assert metrics_for(width, height, mm).touch_min_px == ceil(TOUCH_MIN_MM / mm)

    def test_touch_min_px_none_when_density_unknown(self):
        assert metrics_for(160, 128).touch_min_px is None

    # -- pixel-size tier boundaries: short side 199/200/399/400 ------------
    # Densities are chosen well clear of the touch_short veto, so only the
    # pixel-size boundary itself is under test.

    def test_boundary_just_below_rich_threshold_is_base(self):
        side = RICH_MIN_SHORT_SIDE_PX - 1
        assert metrics_for(side, side, 0.2).content_tier == CONTENT_BASE

    def test_boundary_at_rich_threshold_is_rich(self):
        side = RICH_MIN_SHORT_SIDE_PX
        assert metrics_for(side, side, 0.2).content_tier == CONTENT_RICH

    def test_boundary_just_below_large_threshold_is_rich(self):
        side = LARGE_MIN_SHORT_SIDE_PX - 1
        assert metrics_for(side, side, 0.1).content_tier == CONTENT_RICH

    def test_boundary_at_large_threshold_is_large(self):
        side = LARGE_MIN_SHORT_SIDE_PX
        assert metrics_for(side, side, 0.1).content_tier == CONTENT_LARGE

    def test_mm_per_px_none_is_base_regardless_of_pixel_size(self):
        assert metrics_for(200, 200).content_tier == CONTENT_BASE
        assert metrics_for(640, 480).content_tier == CONTENT_BASE

    # -- the touch_short veto ------------------------------------------------

    def test_touch_short_veto_downgrades_an_automatic_size(self):
        # At this density 240x240 is compact (23.4mm short side), decided
        # ahead of the pixel-tier ladder the veto below lives in — so this
        # panel never reaches the veto at all any more; it is caught by the
        # compact gate first. touch_short is still reported, informationally.
        m = metrics_for(240, 240, 0.0973)
        assert m.touch_short is True
        assert m.content_tier == CONTENT_COMPACT

    def test_touch_short_veto_does_not_apply_to_a_chosen_size(self):
        # size_chosen lifts the older rich/large veto, but never lifts
        # compact — compact is a physical tier down, decided from the glass
        # itself, not a pixel tier the veto ever tiers back up to.
        m = metrics_for(240, 240, 0.0973, size_chosen=True)
        assert m.touch_short is True
        assert m.content_tier == CONTENT_COMPACT

    def test_touch_short_is_reported_on_the_compact_tier_too(self):
        # Any density fine enough to trip touch_short is also fine enough to
        # trip the compact gate (COMPACT_MAX_SHORT_SIDE_MM is deliberately
        # looser than the veto's own implied screen size) — touch_short
        # still reports correctly there, alongside the compact tier itself.
        m = metrics_for(128, 128, 0.2021)
        assert m.touch_short is False  # band_mm is 6.47mm here, not short
        m = metrics_for(240, 240, 0.05)
        assert m.touch_short is True
        assert m.content_tier == CONTENT_COMPACT

    def test_touch_short_boundary_is_strict_less_than(self):
        # band_mm exactly at the threshold must NOT read touch_short — the
        # comparison is strict '<'. At this density the panel is also well
        # within the compact gate (24mm short side), so content_tier reads
        # compact rather than the rich tier this boundary predates.
        quarter = 240 // 4
        mm = TOUCH_SHORT_BELOW_BAND_MM / quarter
        m = metrics_for(240, 240, mm)
        assert m.touch_short is False
        assert m.content_tier == CONTENT_COMPACT

    # -- the band cap ----------------------------------------------------------

    def test_band_cap_bites_on_a_large_panel(self):
        from math import ceil

        mm = 0.127
        expected = min(480 // BAND_DIVISOR_RICH, ceil(BAND_MAX_MM / mm))
        assert metrics_for(640, 480, mm).band_h == expected == 95

    def test_band_cap_does_not_bite_at_the_shipped_320x240_density(self):
        assert metrics_for(320, 240, 0.1778).band_h == 48

    def test_band_cap_bites_at_a_coarser_320x240_density(self):
        # Same pixel count, physically bigger pixels (a 3.5 inch panel): the
        # cap now bites where it did not at the shipped density.
        assert metrics_for(320, 240, 0.2778).band_h == 44


# ---------------------------------------------------------------------------
# The right-rail list: geometry, its zone table and its hit-test on the
# rich/large tiers — the counterpart to TestListLayout/TestListZoneAtExhaustive
# above, which stay on the base tier (metrics=None) and are unaffected.
# ---------------------------------------------------------------------------

_RICH_320x240 = metrics_for(320, 240, 0.1778)
_LARGE_640x480 = metrics_for(640, 480, 0.127)


class TestRailListLayout:
    def test_pinned_geometry_at_320x240(self):
        layout = list_layout_for(320, 240, metrics=_RICH_320x240)
        assert layout.rows == (
            (0, 0, 262, 48), (0, 48, 262, 96), (0, 96, 262, 144),
            (0, 144, 262, 192), (0, 192, 262, 240),
        )
        assert layout.rail == (274, 0, 320, 240)
        assert layout.rail_up == (280, 0, 320, 72)
        assert layout.rail_cancel == (280, 84, 320, 156)
        assert layout.rail_down == (280, 168, 320, 240)
        assert layout.bar is None
        assert layout.back is None
        assert layout.down is None
        assert layout.up is None

    def test_pinned_geometry_at_640x480(self):
        layout = list_layout_for(640, 480, metrics=_LARGE_640x480)
        assert layout.row_h == 96
        assert layout.rows_per_page == 5
        assert layout.rows[0] == (0, 0, 544, 96)
        assert layout.rail == (566, 0, 640, 480)
        assert layout.rail_up == (577, 0, 640, 145)
        assert layout.rail_cancel == (577, 167, 640, 312)
        assert layout.rail_down == (577, 335, 640, 480)
        assert layout.bar is None
        assert layout.back is None
        assert layout.down is None
        assert layout.up is None

    def test_base_layout_on_a_rich_capable_size_without_density(self):
        # No mm_per_px means base regardless of pixel size — today's bottom
        # bar and three rows of 60, not the rail.
        layout = list_layout_for(320, 240)
        assert layout.rail is None
        assert layout.rows_per_page == 3
        assert layout.row_h == 60

    @pytest.mark.parametrize("metrics", [_RICH_320x240, _LARGE_640x480])
    def test_touch_floor_is_respected(self, metrics):
        """Every row and every rail button clears the touch floor on its
        own (taller) axis. The rail's WIDTH is a deliberate, narrower,
        owner-accepted exception — see test_rail_width_is_the_owner_set_
        minimum below — so it is not asserted here."""
        layout = list_layout_for(metrics.width, metrics.height, metrics=metrics)
        for rect in layout.rows:
            assert rect[3] - rect[1] >= metrics.touch_min_px
        for rect in (layout.rail_up, layout.rail_cancel, layout.rail_down):
            assert rect[3] - rect[1] >= metrics.touch_min_px

    def test_rail_width_is_the_owner_set_minimum(self):
        # A straight icon-plus-padding formula gives 38px at the shipped
        # rich density — under the 8mm touch floor (TOUCH_MIN_MM). The
        # owner chose a fixed 46px column instead (about 7mm): narrower
        # than the header/footer bands, but not as narrow as the formula
        # alone would produce. The large tier's own icon-plus-padding value
        # already clears 46px, so it is untouched by the floor.
        assert _RICH_320x240.rail_glyph == 22
        assert _RICH_320x240.rail_w == 46
        assert _LARGE_640x480.rail_glyph == 44
        assert _LARGE_640x480.rail_w == 74


class TestRailZoneTable:
    def test_order_is_up_back_down_then_rows(self):
        # The rail controls reach left over the rows, so they come first.
        entries = zone_rects_for(GEOMETRY_LIST, 320, 240, metrics=_RICH_320x240)
        assert [(e.zone, e.index) for e in entries] == [
            (TouchZone.LIST_UP, None),
            (TouchZone.LIST_BACK, None),
            (TouchZone.LIST_DOWN, None),
            (TouchZone.LIST_ROW, 0),
            (TouchZone.LIST_ROW, 1),
            (TouchZone.LIST_ROW, 2),
            (TouchZone.LIST_ROW, 3),
            (TouchZone.LIST_ROW, 4),
        ]

    def test_base_order_is_unaffected(self):
        entries = zone_rects_for(GEOMETRY_LIST, 160, 128)
        assert [(e.zone, e.index) for e in entries] == [
            (TouchZone.LIST_ROW, 0),
            (TouchZone.LIST_ROW, 1),
            (TouchZone.LIST_ROW, 2),
            (TouchZone.LIST_BACK, None),
            (TouchZone.LIST_DOWN, None),
            (TouchZone.LIST_UP, None),
        ]

    def test_every_rect_is_a_layout_field(self):
        layout = list_layout_for(320, 240, metrics=_RICH_320x240)
        entries = list(zone_rects_for(GEOMETRY_LIST, 320, 240, metrics=_RICH_320x240))
        row_entries = [e for e in entries if e.zone == TouchZone.LIST_ROW]
        assert [e.rect for e in row_entries] == list(layout.rows)
        by_zone = {e.zone: e.rect for e in entries if e.zone != TouchZone.LIST_ROW}
        assert by_zone[TouchZone.LIST_UP] == layout.rail_up
        assert by_zone[TouchZone.LIST_BACK] == layout.rail_cancel
        assert by_zone[TouchZone.LIST_DOWN] == layout.rail_down

    def test_union_of_geometries_still_covers_every_zone(self):
        covered = set()
        for geometry in GEOMETRIES:
            covered.update(
                entry.zone for entry in zone_rects_for(geometry, 320, 240, metrics=_RICH_320x240)
            )
        assert covered == set(TouchZone)


class TestRailListHitTestExhaustive:
    def test_every_pixel_matches_a_hand_written_reference(self):
        metrics = _RICH_320x240
        width, height = metrics.width, metrics.height
        layout = list_layout_for(width, height, metrics=metrics)
        left = layout.rail[0] - metrics.band_h // 3

        def reference(x, y):
            # Each rail control reaches left from the drawn rail's left edge
            # by a third of a band, ahead of the rows.
            for zone, (x0, y0, x1, y1) in (
                (TouchZone.LIST_UP, layout.rail_up),
                (TouchZone.LIST_BACK, layout.rail_cancel),
                (TouchZone.LIST_DOWN, layout.rail_down),
            ):
                if left <= x < x1 and y0 <= y < y1:
                    return (zone, None)
            for i, (x0, y0, x1, y1) in enumerate(layout.rows):
                if x0 <= x < x1 and y0 <= y < y1:
                    return (TouchZone.LIST_ROW, i)
            return None

        for y in range(height):
            for x in range(width):
                hit = hit_test(GEOMETRY_LIST, x, y, width, height, metrics=metrics)
                got = (hit.zone, hit.index) if hit is not None else None
                assert got == reference(x, y)

    def test_rail_zone_centres_resolve_correctly(self):
        metrics = _RICH_320x240
        layout = list_layout_for(metrics.width, metrics.height, metrics=metrics)
        for zone, rect in (
            (TouchZone.LIST_UP, layout.rail_up),
            (TouchZone.LIST_BACK, layout.rail_cancel),
            (TouchZone.LIST_DOWN, layout.rail_down),
        ):
            x0, y0, x1, y1 = rect
            cx, cy = (x0 + x1) // 2, (y0 + y1) // 2
            hit = hit_test(GEOMETRY_LIST, cx, cy, metrics.width, metrics.height, metrics=metrics)
            assert (hit.zone, hit.index) == (zone, None)

    def test_gap_between_cross_and_down_chevron_is_dead(self):
        metrics = _RICH_320x240
        layout = list_layout_for(metrics.width, metrics.height, metrics=metrics)
        gap_y = (layout.rail_cancel[3] + layout.rail_down[1]) // 2
        gap_x = (layout.rail_cancel[0] + layout.rail_cancel[2]) // 2
        assert hit_test(GEOMETRY_LIST, gap_x, gap_y, metrics.width, metrics.height, metrics=metrics) is None

    def test_row_right_edge_gap_before_the_rail_is_covered_by_the_rail_reach(self):
        # The gap between a row's right edge and the drawn rail is
        # chassis-coloured, but the rail control at that height reaches over
        # it, so a point there resolves to the rail control rather than to
        # nothing.
        metrics = _RICH_320x240
        layout = list_layout_for(metrics.width, metrics.height, metrics=metrics)
        assert layout.rows[0][2] < layout.rail[0]
        gap_x = (layout.rows[0][2] + layout.rail[0]) // 2
        gap_y = layout.rows[0][1]
        hit = hit_test(GEOMETRY_LIST, gap_x, gap_y, metrics.width, metrics.height, metrics=metrics)
        assert hit is not None and hit.zone == TouchZone.LIST_UP


# ---------------------------------------------------------------------------
# The large content tier's now-playing body: capped fonts/icon/halo, and the
# album line above the title. Base and rich pin their pre-change values
# explicitly, proving the cap/gate never runs off the large tier.
# ---------------------------------------------------------------------------

class TestFontCaps:
    def test_large_native_panel_caps_every_scaled_font(self):
        m = _LARGE_640x480
        assert m.font_body == FONT_BODY_MAX_PX == 36
        assert m.font_readout == FONT_READOUT_MAX_PX == 44
        assert m.icon == FONT_READOUT_MAX_PX == 44
        assert m.halo_stroke == HALO_MAX_PX == 3
        assert m.halo_blur == HALO_MAX_PX == 3
        assert m.has_album_line is True
        # Padding, margin and the divider are proportion, not legibility —
        # they keep scaling past the font/icon/halo caps.
        assert m.pad == 15
        assert m.margin == 11
        assert m.divider_w == 4

    def test_large_preview_on_a_smaller_chosen_panel_caps_the_same_way(self):
        m = metrics_for(640, 480, 0.0889, size_chosen=True)
        assert m.band_h == 96
        assert m.font_body == 36
        assert m.font_readout == 44
        assert m.icon == 44
        assert m.halo_stroke == 3
        assert m.halo_blur == 3
        assert m.has_album_line is True

    def test_rich_tier_sizes_and_has_no_album_line(self):
        # Rich scales its text from the large tier's own reference (see
        # FONT_BODY_PX_AT_LARGE_REFERENCE); its halo is capped the same way
        # the large tier's is, even though its fonts stay well under their
        # own cap at this panel size.
        m = _RICH_320x240
        assert m.font_body == 18
        assert m.font_readout == 22
        assert m.icon == 22
        assert m.halo_stroke == 3
        assert m.halo_blur == 3
        assert m.has_album_line is False

    @pytest.mark.parametrize("width,height", [(160, 128), (128, 128)])
    def test_base_tier_is_uncapped_and_has_no_album_line(self, width, height):
        m = metrics_for(width, height)
        assert m.font_body == 13
        assert m.font_readout == 15
        assert m.icon == 15
        assert m.halo_stroke == 2
        assert m.halo_blur == 2
        assert m.has_album_line is False

    def test_compact_resolving_panel_is_uncapped_and_has_no_album_line(self):
        # This physically tiny panel resolves compact ahead of the pixel-
        # tier ladder the cap lives in (see
        # TestTierReporting.test_touch_short_veto_downgrades_an_automatic_size)
        # despite a pixel size that would otherwise scale past the cap: the
        # gate is the resolved tier, not the raw scaled value. Compact keeps
        # the base tier's own font formula, uncapped.
        m = metrics_for(240, 240, 0.0973)
        assert m.content_tier == CONTENT_COMPACT
        assert m.font_body == round(240 * 13 / 128) == 24
        assert m.font_readout == round(240 * 15 / 128) == 28
        assert m.icon == round(240 * 15 / 128) == 28
        assert m.has_album_line is False

    def test_cap_is_a_minimum_not_a_constant(self):
        # A much bigger large-tier panel scales to a far higher natural
        # value than the native panel, but both land on the same cap — the
        # cap is a min(), not a hardcoded replacement for one specific size.
        big_large = metrics_for(960, 960, 0.05)
        assert big_large.content_tier == CONTENT_LARGE
        assert big_large.font_body == 36        # round(960*36/480) = 72, capped
        assert big_large.font_readout == 44     # round(960*44/480) = 88, capped
        assert _LARGE_640x480.font_body == 36   # round(480*36/480) = 36, already at the cap
        assert _LARGE_640x480.font_readout == 44
        # the uncapped fields still scale between the two sizes
        assert big_large.pad != _LARGE_640x480.pad
        assert big_large.margin != _LARGE_640x480.margin


class TestAlbumLine:
    def test_large_native_panel_album_title_artist_rects(self):
        layout = layout_for(640, 480, metrics=_LARGE_640x480)
        assert layout.album == (11, 244, 629, 291)
        assert layout.title == (11, 291, 629, 338)
        assert layout.artist == (11, 338, 629, 385)

    def test_large_preview_panel_album_rect(self):
        metrics = metrics_for(640, 480, 0.0889, size_chosen=True)
        layout = layout_for(640, 480, metrics=metrics)
        assert layout.album == (11, 240, 629, 288)

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_base_tier_has_no_album_rect(self, width, height):
        assert layout_for(width, height).album is None

    def test_rich_tier_has_no_album_rect_and_title_artist_follow_the_shorter_band(self):
        # The rich tier's own (shorter) band height moves title/artist up
        # from where the base tier's own band would put them — pinned
        # explicitly rather than compared to base, which no longer shares
        # the same band height at this panel size.
        layout = layout_for(320, 240, metrics=_RICH_320x240)
        assert layout.album is None
        assert layout.title == (6, 144, 314, 168)
        assert layout.artist == (6, 168, 314, 192)

    def test_main_zone_table_unaffected_at_large(self):
        # No touch/zone change: the album rect never enters the hit-test
        # table, exactly like the artist and title rects it sits beside.
        entries = zone_rects_for(GEOMETRY_MAIN, 640, 480, metrics=_LARGE_640x480)
        assert [e.zone for e in entries] == [
            TouchZone.DOTS, TouchZone.NAME, TouchZone.OUTPUTS,
            TouchZone.MUTE, TouchZone.DOWN, TouchZone.UP, TouchZone.ARTWORK,
        ]


# ---------------------------------------------------------------------------
# The compact tier: a physically tiny panel's 2x2 grid, replacing the
# band+body+footer layouts entirely. Gated purely on physical size (see
# metrics_for()), never on logical pixel count.
# ---------------------------------------------------------------------------

# Pinned rects at both shipped compact panels — see the module's own
# CompactLayout/compact_layout_for docstrings.
_COMPACT_240x240 = metrics_for(240, 240, 0.0973)
_COMPACT_128x128 = metrics_for(128, 128, 0.2021)


class TestCompactGate:
    def test_shipped_compact_panels_resolve_compact(self):
        assert metrics_for(240, 240, 0.0973).content_tier == CONTENT_COMPACT  # 1.3in
        assert metrics_for(128, 128, 0.2021).content_tier == CONTENT_COMPACT  # 1.44in

    def test_shipped_larger_panels_do_not_resolve_compact(self):
        assert metrics_for(160, 128, 0.2231).content_tier != CONTENT_COMPACT  # 1.8in
        assert metrics_for(320, 240, 0.1778).content_tier != CONTENT_COMPACT  # 2.8in

    def test_boundary_is_at_or_below(self):
        # short * mm_per_px == COMPACT_MAX_SHORT_SIDE_MM resolves compact
        # (<=); one hundredth of a millimetre more does not.
        width = height = 128
        at_boundary = COMPACT_MAX_SHORT_SIDE_MM / width
        just_over = (COMPACT_MAX_SHORT_SIDE_MM + 0.01) / width
        assert metrics_for(width, height, at_boundary).content_tier == CONTENT_COMPACT
        assert metrics_for(width, height, just_over).content_tier != CONTENT_COMPACT

    def test_unknown_density_never_resolves_compact(self):
        assert metrics_for(240, 240).content_tier == CONTENT_BASE
        assert metrics_for(128, 128).content_tier == CONTENT_BASE

    def test_size_chosen_does_not_lift_compact(self):
        # A deliberately chosen logical size lifts the older rich/large
        # touch_short veto, but compact is never reached through that veto
        # in the first place — it is decided purely from the glass, ahead
        # of the pixel-tier ladder, so size_chosen has no effect on it.
        without = metrics_for(240, 240, 0.0973, size_chosen=False)
        with_chosen = metrics_for(240, 240, 0.0973, size_chosen=True)
        assert without.content_tier == CONTENT_COMPACT
        assert with_chosen.content_tier == CONTENT_COMPACT

    def test_compact_metrics_keep_base_formulas_except_rows_per_page(self):
        base = metrics_for(240, 240)
        compact = _COMPACT_240x240
        assert compact.rows_per_page == 2
        assert base.rows_per_page == 3
        for field in (
            "margin", "band_h", "row_h", "divider_w", "font_body", "font_readout",
            "icon", "pad", "icon_gap", "halo_stroke", "halo_blur", "list_rail",
            "rail_w", "rail_glyph", "supersample",
        ):
            assert getattr(compact, field) == getattr(base, field), field

    def test_pinned_metrics_at_both_shipped_sizes(self):
        assert (_COMPACT_240x240.margin, _COMPACT_240x240.divider_w) == (6, 2)
        assert (_COMPACT_240x240.font_body, _COMPACT_240x240.font_readout, _COMPACT_240x240.icon) == (24, 28, 28)
        assert _COMPACT_240x240.pad == 8
        assert (_COMPACT_128x128.margin, _COMPACT_128x128.divider_w) == (3, 1)
        assert (_COMPACT_128x128.font_body, _COMPACT_128x128.font_readout, _COMPACT_128x128.icon) == (13, 15, 15)
        assert _COMPACT_128x128.pad == 4


class TestCompactLayoutFor:
    def test_pinned_cells_at_240x240(self):
        layout = compact_layout_for(240, 240, metrics=_COMPACT_240x240)
        assert layout.tl == (0, 0, 114, 114)
        assert layout.tr == (126, 0, 240, 114)
        assert layout.bl == (0, 126, 114, 240)
        assert layout.br == (126, 126, 240, 240)
        assert layout.top_row == (0, 0, 240, 114)
        assert layout.bottom_row == (0, 126, 240, 240)
        assert (layout.divider_x, layout.divider_y) == (120, 120)

    def test_pinned_cells_at_128x128(self):
        layout = compact_layout_for(128, 128, metrics=_COMPACT_128x128)
        assert layout.tl == (0, 0, 61, 61)
        assert layout.tr == (67, 0, 128, 61)
        assert layout.bl == (0, 67, 61, 128)
        assert layout.br == (67, 67, 128, 128)
        assert layout.top_row == (0, 0, 128, 61)
        assert layout.bottom_row == (0, 67, 128, 128)
        assert (layout.divider_x, layout.divider_y) == (64, 64)

    @pytest.mark.parametrize("metrics", [_COMPACT_240x240, _COMPACT_128x128])
    def test_cells_are_square(self, metrics):
        layout = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
        for rect in (layout.tl, layout.tr, layout.bl, layout.br):
            x0, y0, x1, y1 = rect
            assert x1 - x0 == y1 - y0

    @pytest.mark.parametrize("metrics", [_COMPACT_240x240, _COMPACT_128x128])
    def test_cells_plus_gaps_exactly_tile_the_panel(self, metrics):
        layout = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
        covered = [[False] * metrics.width for _ in range(metrics.height)]
        for rect in (layout.tl, layout.tr, layout.bl, layout.br):
            x0, y0, x1, y1 = rect
            for y in range(y0, y1):
                for x in range(x0, x1):
                    assert not covered[y][x]
                    covered[y][x] = True
        # The only uncovered pixels are the dead-zone gap around each
        # divider — every one of them lies within margin px of divider_x
        # or divider_y.
        m = metrics.margin
        for y in range(metrics.height):
            for x in range(metrics.width):
                if covered[y][x]:
                    continue
                near_v_divider = abs(x - layout.divider_x) <= m
                near_h_divider = abs(y - layout.divider_y) <= m
                assert near_v_divider or near_h_divider, (x, y)

    def test_non_square_panel_splits_each_axis_independently(self):
        # A developer-preview size: 320x240 at a low enough screen-size
        # setting to resolve compact. Not a shipped target, but each axis
        # is still split on its own, so the cells need not be square.
        mm = 1.4 * 25.4 / (320 ** 2 + 240 ** 2) ** 0.5
        metrics = metrics_for(320, 240, mm)
        assert metrics.content_tier == CONTENT_COMPACT
        layout = compact_layout_for(320, 240, metrics=metrics)
        x0, y0, x1, y1 = layout.tl
        assert (x1 - x0) != (y1 - y0)


class TestCompactPickerLayoutFor:
    """Pinned fields for compact_picker_layout_for() at both shipped
    compact sizes, plus the shape rules that must hold everywhere."""

    def test_pinned_fields_at_240x240(self):
        p = compact_picker_layout_for(240, 240, metrics=_COMPACT_240x240)
        assert p.title == (0, 0, 240, 32)
        assert p.title_divider_y == 32
        assert p.cancel == (0, 38, 78, 133)
        assert p.more == (0, 145, 78, 240)
        assert p.row0 == (90, 38, 240, 133)
        assert p.row1 == (90, 145, 240, 240)
        assert (p.divider_x, p.divider_y) == (84, 139)

    def test_pinned_fields_at_128x128(self):
        p = compact_picker_layout_for(128, 128, metrics=_COMPACT_128x128)
        assert p.title == (0, 0, 128, 17)
        assert p.title_divider_y == 17
        assert p.cancel == (0, 20, 42, 71)
        assert p.more == (0, 77, 42, 128)
        assert p.row0 == (48, 20, 128, 71)
        assert p.row1 == (48, 77, 128, 128)
        assert (p.divider_x, p.divider_y) == (45, 74)

    @pytest.mark.parametrize("metrics", [_COMPACT_240x240, _COMPACT_128x128])
    def test_title_height_is_font_body_plus_pad(self, metrics):
        p = compact_picker_layout_for(metrics.width, metrics.height, metrics=metrics)
        assert p.title == (0, 0, metrics.width, metrics.font_body + metrics.pad)
        assert p.title_divider_y == metrics.font_body + metrics.pad

    @pytest.mark.parametrize("metrics", [_COMPACT_240x240, _COMPACT_128x128])
    def test_divider_x_is_the_left_fraction_of_width_rounded(self, metrics):
        p = compact_picker_layout_for(metrics.width, metrics.height, metrics=metrics)
        assert p.divider_x == round(metrics.width * COMPACT_PICKER_LEFT_FRACTION)

    @pytest.mark.parametrize("metrics", [_COMPACT_240x240, _COMPACT_128x128])
    def test_left_column_narrower_than_the_right(self, metrics):
        p = compact_picker_layout_for(metrics.width, metrics.height, metrics=metrics)
        left_w = p.cancel[2] - p.cancel[0]
        right_w = p.row0[2] - p.row0[0]
        assert 0 < left_w < right_w

    @pytest.mark.parametrize("metrics", [_COMPACT_240x240, _COMPACT_128x128])
    def test_row_heights_are_equal_on_both_columns(self, metrics):
        p = compact_picker_layout_for(metrics.width, metrics.height, metrics=metrics)
        assert (p.cancel[3] - p.cancel[1]) == (p.more[3] - p.more[1])
        assert (p.row0[3] - p.row0[1]) == (p.row1[3] - p.row1[1])
        assert (p.cancel[3] - p.cancel[1]) == (p.row0[3] - p.row0[1])

    @pytest.mark.parametrize("metrics", [_COMPACT_240x240, _COMPACT_128x128])
    def test_cells_plus_dead_gaps_exactly_tile_below_the_title(self, metrics):
        p = compact_picker_layout_for(metrics.width, metrics.height, metrics=metrics)
        m = metrics.margin
        grid_y0 = p.title[3] + m
        covered = [[False] * metrics.width for _ in range(metrics.height)]
        for rect in (p.cancel, p.more, p.row0, p.row1):
            x0, y0, x1, y1 = rect
            for y in range(y0, y1):
                for x in range(x0, x1):
                    assert not covered[y][x]
                    covered[y][x] = True
        for y in range(grid_y0, metrics.height):
            for x in range(metrics.width):
                if covered[y][x]:
                    continue
                near_v = abs(x - p.divider_x) <= m
                near_h = abs(y - p.divider_y) <= m
                assert near_v or near_h, (x, y)

    def test_pure(self):
        for metrics in (_COMPACT_240x240, _COMPACT_128x128):
            a = compact_picker_layout_for(metrics.width, metrics.height, metrics=metrics)
            b = compact_picker_layout_for(metrics.width, metrics.height, metrics=metrics)
            assert a == b


class TestCompactZoneTables:
    """Pinned zone tables at both shipped compact sizes, plus an exhaustive
    per-pixel hit-test proving every pixel maps to exactly one entry or a
    dead gap — the same discipline TestListZoneAtExhaustive applies to the
    base tier's own list geometry."""

    @pytest.mark.parametrize("metrics", [_COMPACT_240x240, _COMPACT_128x128])
    def test_main_table(self, metrics):
        entries = zone_rects_for(GEOMETRY_MAIN, metrics.width, metrics.height, metrics=metrics)
        c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
        assert [(e.zone, e.rect) for e in entries] == [
            (TouchZone.DOTS, c.tl), (TouchZone.MUTE, c.tr),
            (TouchZone.DOWN, c.bl), (TouchZone.UP, c.br),
        ]

    @pytest.mark.parametrize("metrics", [_COMPACT_240x240, _COMPACT_128x128])
    def test_list_table(self, metrics):
        entries = zone_rects_for(GEOMETRY_LIST, metrics.width, metrics.height, metrics=metrics)
        p = compact_picker_layout_for(metrics.width, metrics.height, metrics=metrics)
        assert [(e.zone, e.rect, e.index) for e in entries] == [
            (TouchZone.LIST_ROW, p.row0, 0), (TouchZone.LIST_ROW, p.row1, 1),
            (TouchZone.LIST_BACK, p.cancel, None), (TouchZone.LIST_DOWN, p.more, None),
        ]

    @pytest.mark.parametrize("metrics", [_COMPACT_240x240, _COMPACT_128x128])
    def test_repeat_enable_table(self, metrics):
        # Back top-left, "Repeat Play" spanning the full bottom row; the
        # top-right cell carries no entry at all (dead).
        entries = zone_rects_for(GEOMETRY_REPEAT, metrics.width, metrics.height, metrics=metrics)
        c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
        assert [(e.zone, e.rect) for e in entries] == [
            (TouchZone.DOTS, c.tl), (TouchZone.REPEAT_PLAY, c.bottom_row),
        ]

    @pytest.mark.parametrize("metrics", [_COMPACT_240x240, _COMPACT_128x128])
    def test_repeat_replay_table(self, metrics):
        # Back top-left, Restart bottom-left, Stop bottom-right; the
        # top-right time cell is display-only, no entry at all (dead).
        entries = zone_rects_for(GEOMETRY_REPEAT_REPLAY, metrics.width, metrics.height, metrics=metrics)
        c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
        assert [(e.zone, e.rect) for e in entries] == [
            (TouchZone.DOTS, c.tl),
            (TouchZone.REPEAT_START, c.bl), (TouchZone.REPEAT_STOP, c.br),
        ]

    @pytest.mark.parametrize("metrics", [_COMPACT_240x240, _COMPACT_128x128])
    def test_idle_table_is_the_whole_panel(self, metrics):
        entries = zone_rects_for(GEOMETRY_IDLE, metrics.width, metrics.height, metrics=metrics)
        idle = idle_layout_for(metrics.width, metrics.height, metrics=metrics)
        assert entries == (
            ZoneRect(TouchZone.IDLE_WIFI, idle.wifi),
            ZoneRect(TouchZone.IDLE_INFO, idle.info),
            ZoneRect(TouchZone.IDLE_REPLAY, (0, 0, metrics.width, metrics.height)),
        )

    def test_output_table_is_unreachable_and_unaffected(self):
        # GEOMETRY_OUTPUT is unchanged on compact — the per-output detail
        # page is not reachable there at all.
        for metrics in (_COMPACT_240x240, _COMPACT_128x128):
            assert zone_rects_for(GEOMETRY_OUTPUT, metrics.width, metrics.height, metrics=metrics) == (
                zone_rects_for(GEOMETRY_OUTPUT, metrics.width, metrics.height)
            )

    @pytest.mark.parametrize(
        "geometry,metrics", [
            (g, m) for g in (GEOMETRY_MAIN, GEOMETRY_REPEAT, GEOMETRY_REPEAT_REPLAY)
            for m in (_COMPACT_240x240, _COMPACT_128x128)
        ],
    )
    def test_every_pixel_hits_exactly_one_entry_or_a_dead_gap(self, geometry, metrics):
        # Shared by every compact geometry still built straight from the
        # compact grid (MAIN, REPEAT, REPEAT_REPLAY) — GEOMETRY_LIST gets its
        # own picker-shaped version below, since it no longer uses the grid's
        # cells directly, and GEOMETRY_IDLE gets its own version further
        # down (its IDLE_INFO/IDLE_REPLAY entries overlap by design, resolved
        # by hit_test's first-match order rather than by non-overlap).
        w, h = metrics.width, metrics.height
        entries = zone_rects_for(geometry, w, h, metrics=metrics)
        c = compact_layout_for(w, h, metrics=metrics)
        m = metrics.margin
        for y in range(h):
            for x in range(w):
                hits = [
                    (e.zone, e.index) for e in entries
                    if e.rect[0] <= x < e.rect[2] and e.rect[1] <= y < e.rect[3]
                ]
                assert len(hits) <= 1, (geometry, x, y, hits)
                result = hit_test(geometry, x, y, w, h, metrics=metrics)
                if hits:
                    assert result is not None and (result.zone, result.index) == hits[0]
                else:
                    # A dead pixel must sit either in the grid's own margin
                    # gap around one of the two dividers, or (on the REPEAT/
                    # REPEAT_REPLAY enable and replaying tables, which carry
                    # no entry for the top-right cell at all) inside that
                    # cell itself.
                    near_v = abs(x - c.divider_x) <= m
                    near_h = abs(y - c.divider_y) <= m
                    tx0, ty0, tx1, ty1 = c.tr
                    in_tr = tx0 <= x < tx1 and ty0 <= y < ty1
                    assert near_v or near_h or in_tr, (geometry, x, y)
                    assert result is None

    @pytest.mark.parametrize("metrics", [_COMPACT_240x240, _COMPACT_128x128])
    def test_idle_every_pixel_resolves_info_first_then_replay(self, metrics):
        # GEOMETRY_IDLE's own version: IDLE_WIFI/IDLE_INFO and IDLE_REPLAY
        # overlap by design (IDLE_REPLAY is the whole panel on compact), so
        # every pixel inside one of the two corner squares resolves to that
        # square's own zone and every other pixel resolves to IDLE_REPLAY —
        # no dead gap anywhere.
        w, h = metrics.width, metrics.height
        idle = idle_layout_for(w, h, metrics=metrics)
        ix0, iy0, ix1, iy1 = idle.info
        wx0, wy0, wx1, wy1 = idle.wifi
        for y in range(h):
            for x in range(w):
                result = hit_test(GEOMETRY_IDLE, x, y, w, h, metrics=metrics)
                assert result is not None
                if wx0 <= x < wx1 and wy0 <= y < wy1:
                    assert result.zone == TouchZone.IDLE_WIFI
                elif ix0 <= x < ix1 and iy0 <= y < iy1:
                    assert result.zone == TouchZone.IDLE_INFO
                else:
                    assert result.zone == TouchZone.IDLE_REPLAY

    @pytest.mark.parametrize("metrics", [_COMPACT_240x240, _COMPACT_128x128])
    def test_picker_table_every_pixel_hits_exactly_one_entry_or_a_dead_gap(self, metrics):
        # GEOMETRY_LIST's own version of the exhaustive hit-test: the picker
        # layout's cells, not the plain compact grid — a dead pixel is
        # either the title band plus the one-margin gap under its line, or
        # the usual margin gap around one of the picker's own two dividers.
        w, h = metrics.width, metrics.height
        entries = zone_rects_for(GEOMETRY_LIST, w, h, metrics=metrics)
        p = compact_picker_layout_for(w, h, metrics=metrics)
        m = metrics.margin
        grid_y0 = p.title[3] + m
        for y in range(h):
            for x in range(w):
                hits = [
                    (e.zone, e.index) for e in entries
                    if e.rect[0] <= x < e.rect[2] and e.rect[1] <= y < e.rect[3]
                ]
                assert len(hits) <= 1, (x, y, hits)
                result = hit_test(GEOMETRY_LIST, x, y, w, h, metrics=metrics)
                if hits:
                    assert result is not None and (result.zone, result.index) == hits[0]
                else:
                    assert result is None
                    if y < grid_y0:
                        continue  # the title band and the gap under its line
                    near_v = abs(x - p.divider_x) <= m
                    near_h = abs(y - p.divider_y) <= m
                    assert near_v or near_h, (x, y)

    def test_repeat_replay_equals_repeat_off_compact(self):
        for width, height in PROFILE_SIZES:
            assert zone_rects_for(GEOMETRY_REPEAT_REPLAY, width, height) == zone_rects_for(
                GEOMETRY_REPEAT, width, height,
            )

    def test_zone_rects_for_is_pure(self):
        for metrics in (_COMPACT_240x240, _COMPACT_128x128):
            for geometry in GEOMETRIES:
                a = zone_rects_for(geometry, metrics.width, metrics.height, metrics=metrics)
                b = zone_rects_for(geometry, metrics.width, metrics.height, metrics=metrics)
                assert a == b


class TestCompactIdleGeometry:
    @pytest.mark.parametrize("metrics", [_COMPACT_240x240, _COMPACT_128x128])
    def test_idle_layout_replay_is_the_whole_panel(self, metrics):
        idle = idle_layout_for(metrics.width, metrics.height, metrics=metrics)
        assert idle.replay == (0, 0, metrics.width, metrics.height)

    @pytest.mark.parametrize("metrics", [_COMPACT_240x240, _COMPACT_128x128])
    def test_idle_hit_test_covers_every_pixel(self, metrics):
        # idle_zone_at() itself has no metrics parameter (a base-tier-only
        # convenience — see zone_at()/list_zone_at()/repeat_zone_at()); the
        # density-aware hit-test every real caller uses is hit_test() with
        # an explicit metrics, exercised directly here. Every pixel resolves
        # to IDLE_INFO or IDLE_REPLAY — see
        # test_idle_every_pixel_resolves_info_first_then_replay for the
        # exact split.
        for y in range(metrics.height):
            for x in range(metrics.width):
                hit = hit_test(GEOMETRY_IDLE, x, y, metrics.width, metrics.height, metrics=metrics)
                assert hit is not None and hit.zone in (
                    TouchZone.IDLE_WIFI, TouchZone.IDLE_INFO, TouchZone.IDLE_REPLAY,
                )


class TestInfoValueGeometry:
    """InfoValueLayout/info_value_layout_for and GEOMETRY_INFO_VALUE: the
    compact info page's own drill-in — a small label band over a value rect,
    and a single whole-panel LIST_BACK zone (a tap anywhere returns to the
    list)."""

    def test_pinned_at_240x240(self):
        layout = info_value_layout_for(240, 240, metrics=_COMPACT_240x240)
        assert isinstance(layout, InfoValueLayout)
        assert layout.label == (0, 0, 240, 32)
        assert layout.value == (8, 32, 232, 240)

    def test_pinned_at_128x128(self):
        layout = info_value_layout_for(128, 128, metrics=_COMPACT_128x128)
        assert layout.label == (0, 0, 128, 17)
        assert layout.value == (4, 17, 124, 128)

    @pytest.mark.parametrize("metrics", [_COMPACT_240x240, _COMPACT_128x128])
    def test_label_band_height_is_font_body_plus_pad(self, metrics):
        layout = info_value_layout_for(metrics.width, metrics.height, metrics=metrics)
        band_h = metrics.font_body + metrics.pad
        assert layout.label == (0, 0, metrics.width, band_h)
        assert layout.value == (metrics.pad, band_h, metrics.width - metrics.pad, metrics.height)

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_tier_agnostic(self, width, height):
        # A pure function of (width, height, metrics) — only the compact
        # tier ever opens the screen that reads it, but the geometry itself
        # makes no tier check of its own.
        metrics = metrics_for(width, height)
        layout = info_value_layout_for(width, height)
        band_h = metrics.font_body + metrics.pad
        assert layout.label == (0, 0, width, band_h)
        assert layout.value == (metrics.pad, band_h, width - metrics.pad, height)

    def test_geometry_is_one_whole_panel_list_back_entry(self):
        for metrics in (_COMPACT_240x240, _COMPACT_128x128):
            entries = zone_rects_for(GEOMETRY_INFO_VALUE, metrics.width, metrics.height, metrics=metrics)
            assert entries == (ZoneRect(TouchZone.LIST_BACK, (0, 0, metrics.width, metrics.height)),)

    @pytest.mark.parametrize("metrics", [_COMPACT_240x240, _COMPACT_128x128])
    def test_every_pixel_resolves_to_list_back(self, metrics):
        w, h = metrics.width, metrics.height
        for y in range(h):
            for x in range(w):
                hit = hit_test(GEOMETRY_INFO_VALUE, x, y, w, h, metrics=metrics)
                assert hit is not None and hit.zone == TouchZone.LIST_BACK

    def test_is_pure(self):
        for metrics in (_COMPACT_240x240, _COMPACT_128x128):
            a = zone_rects_for(GEOMETRY_INFO_VALUE, metrics.width, metrics.height, metrics=metrics)
            b = zone_rects_for(GEOMETRY_INFO_VALUE, metrics.width, metrics.height, metrics=metrics)
            assert a == b
            la = info_value_layout_for(metrics.width, metrics.height, metrics=metrics)
            lb = info_value_layout_for(metrics.width, metrics.height, metrics=metrics)
            assert la == lb


# ---------------------------------------------------------------------------
# EQ page geometry (GEOMETRY_EQ / eq_layout_for): the shared top band over
# two bar rows, each with a band-high square stepper at each end. Rich/large
# only in practice (see DialDisplay._eq_available), but the function itself
# is a pure geometry computation reachable at any size.
# ---------------------------------------------------------------------------

class TestEqLayout:
    def test_pinned_geometry_at_320x240_rich(self):
        metrics = _RICH_320x240
        layout = eq_layout_for(320, 240, metrics=metrics)
        assert layout.top_band == (0, 0, 320, 48)
        assert layout.dots == (6, 0, 54, 48)
        assert layout.bass.row == (6, 48, 314, 138)
        assert layout.treble.row == (6, 150, 314, 240)
        assert layout.bass.down == (6, 48, 54, 138)
        assert layout.bass.up == (266, 48, 314, 138)
        assert layout.bass.caption == (66, 48, 254, 93)
        assert layout.bass.track == (66, 93, 254, 138)
        assert (layout.bass.track_x0, layout.bass.track_x1) == (74, 246)
        assert layout.bass.track_y == 115
        assert layout.bass.centre_x == 160
        assert layout.treble.down == (6, 150, 54, 240)
        assert layout.treble.up == (266, 150, 314, 240)
        assert layout.treble.caption == (66, 150, 254, 195)
        assert layout.treble.track == (66, 195, 254, 240)
        assert layout.treble.track_y == 217

    def test_pinned_geometry_at_640x480_large(self):
        metrics = _LARGE_640x480
        layout = eq_layout_for(640, 480, metrics=metrics)
        assert layout.top_band == (0, 0, 640, 95)
        assert layout.dots == (11, 0, 106, 95)
        assert layout.bass.row == (11, 95, 629, 276)
        assert layout.treble.row == (11, 299, 629, 480)
        assert layout.bass.down == (11, 95, 106, 276)
        assert layout.bass.up == (534, 95, 629, 276)
        assert layout.bass.caption == (128, 95, 512, 185)
        assert layout.bass.track == (128, 185, 512, 276)
        assert (layout.bass.track_x0, layout.bass.track_x1) == (143, 497)
        assert layout.bass.track_y == 230
        assert layout.bass.centre_x == 320
        assert layout.treble.down == (11, 299, 106, 480)
        assert layout.treble.up == (534, 299, 629, 480)
        assert layout.treble.caption == (128, 299, 512, 389)
        assert layout.treble.track == (128, 389, 512, 480)
        assert layout.treble.track_y == 434

    def test_top_band_fields_equal_layout_for(self):
        for metrics in (_RICH_320x240, _LARGE_640x480):
            main = layout_for(metrics.width, metrics.height, metrics=metrics)
            eq = eq_layout_for(metrics.width, metrics.height, metrics=metrics)
            assert eq.dots == main.dots
            assert eq.name == main.name
            assert eq.volume_cluster == main.volume_cluster
            assert eq.top_band == main.top_band

    def test_control_size_clears_the_touch_floor(self):
        for metrics in (_RICH_320x240, _LARGE_640x480):
            layout = eq_layout_for(metrics.width, metrics.height, metrics=metrics)
            for bar in (layout.bass, layout.treble):
                for rect in (bar.down, bar.up):
                    assert rect[2] - rect[0] >= metrics.touch_min_px
                    assert rect[3] - rect[1] >= metrics.touch_min_px

    def test_is_pure(self):
        for metrics in (_RICH_320x240, _LARGE_640x480):
            a = eq_layout_for(metrics.width, metrics.height, metrics=metrics)
            b = eq_layout_for(metrics.width, metrics.height, metrics=metrics)
            assert a == b

    def test_stays_pure_off_the_tier_it_is_actually_used_on(self):
        """eq_layout_for has no idea what tier it is being used on — it is
        never called off rich/large in the running dial (see
        DialDisplay._eq_available), but the function itself does not raise
        or vary at a smaller size."""
        a = eq_layout_for(240, 240)
        b = eq_layout_for(240, 240)
        assert a == b


class TestEqZoneTable:
    def test_order_is_dots_name_outputs_then_bass_then_treble(self):
        entries = zone_rects_for(GEOMETRY_EQ, 320, 240, metrics=_RICH_320x240)
        assert [e.zone for e in entries] == [
            TouchZone.DOTS, TouchZone.NAME, TouchZone.OUTPUTS,
            TouchZone.EQ_BASS_DOWN, TouchZone.EQ_BASS_UP,
            TouchZone.EQ_TREBLE_DOWN, TouchZone.EQ_TREBLE_UP,
        ]

    def test_every_rect_is_a_layout_field(self):
        layout = eq_layout_for(320, 240, metrics=_RICH_320x240)
        by_zone = {e.zone: e.rect for e in zone_rects_for(GEOMETRY_EQ, 320, 240, metrics=_RICH_320x240)}
        assert by_zone[TouchZone.DOTS] == layout.dots
        assert by_zone[TouchZone.NAME] == layout.name
        assert by_zone[TouchZone.OUTPUTS] == layout.volume_cluster
        assert by_zone[TouchZone.EQ_BASS_DOWN] == layout.bass.down
        assert by_zone[TouchZone.EQ_BASS_UP] == layout.bass.up
        assert by_zone[TouchZone.EQ_TREBLE_DOWN] == layout.treble.down
        assert by_zone[TouchZone.EQ_TREBLE_UP] == layout.treble.up

    def test_union_of_geometries_still_covers_every_eq_zone(self):
        covered = set()
        for geometry in GEOMETRIES:
            covered.update(entry.zone for entry in zone_rects_for(geometry, 320, 240, metrics=_RICH_320x240))
        assert {
            TouchZone.EQ_BASS_DOWN, TouchZone.EQ_BASS_UP,
            TouchZone.EQ_TREBLE_DOWN, TouchZone.EQ_TREBLE_UP,
        } <= covered


class TestEqHitTestExhaustive:
    def test_every_pixel_matches_a_hand_written_reference(self):
        metrics = _RICH_320x240
        width, height = metrics.width, metrics.height
        layout = eq_layout_for(width, height, metrics=metrics)
        reach_bottom = metrics.band_h + metrics.band_h // 3

        def reach(rect):
            return (rect[0], rect[1], rect[2], reach_bottom)

        def reference(x, y):
            # The top band's controls reach down to reach_bottom, ahead of
            # the steppers.
            for zone, (x0, y0, x1, y1) in (
                (TouchZone.DOTS, reach(layout.dots)),
                (TouchZone.NAME, reach(layout.name)),
                (TouchZone.OUTPUTS, reach(layout.volume_cluster)),
                (TouchZone.EQ_BASS_DOWN, layout.bass.down),
                (TouchZone.EQ_BASS_UP, layout.bass.up),
                (TouchZone.EQ_TREBLE_DOWN, layout.treble.down),
                (TouchZone.EQ_TREBLE_UP, layout.treble.up),
            ):
                if x0 <= x < x1 and y0 <= y < y1:
                    return zone
            return None

        for y in range(height):
            for x in range(width):
                hit = hit_test(GEOMETRY_EQ, x, y, width, height, metrics=metrics)
                got = hit.zone if hit is not None else None
                assert got == reference(x, y)

    def test_captions_and_tracks_resolve_to_nothing(self):
        metrics = _RICH_320x240
        layout = eq_layout_for(320, 240, metrics=metrics)
        for bar in (layout.bass, layout.treble):
            for rect in (bar.caption, bar.track):
                cx, cy = (rect[0] + rect[2]) // 2, (rect[1] + rect[3]) // 2
                assert hit_test(GEOMETRY_EQ, cx, cy, 320, 240, metrics=metrics) is None

    def test_dead_gap_between_bass_and_treble_resolves_to_nothing(self):
        metrics = _RICH_320x240
        layout = eq_layout_for(320, 240, metrics=metrics)
        gap_y = (layout.bass.row[3] + layout.treble.row[1]) // 2
        assert hit_test(GEOMETRY_EQ, layout.bass.centre_x, gap_y, 320, 240, metrics=metrics) is None

    def test_pinned_control_centres_at_640x480(self):
        metrics = _LARGE_640x480
        layout = eq_layout_for(640, 480, metrics=metrics)
        for zone, rect in (
            (TouchZone.EQ_BASS_DOWN, layout.bass.down),
            (TouchZone.EQ_BASS_UP, layout.bass.up),
            (TouchZone.EQ_TREBLE_DOWN, layout.treble.down),
            (TouchZone.EQ_TREBLE_UP, layout.treble.up),
        ):
            cx, cy = (rect[0] + rect[2]) // 2, (rect[1] + rect[3]) // 2
            hit = hit_test(GEOMETRY_EQ, cx, cy, 640, 480, metrics=metrics)
            assert hit is not None and hit.zone == zone


# ---------------------------------------------------------------------------
# Purity: this module must import nothing new (no hardware, no Pillow, no
# display coupling) — the same guarantee the module docstring makes.
# ---------------------------------------------------------------------------

class TestPurity:
    def test_module_imports_are_unchanged(self):
        import dial_touch_layout as m
        import types
        module_names = {
            name for name, val in vars(m).items()
            if isinstance(val, types.ModuleType)
        }
        assert module_names == set()


class TestTouchReach:
    """The top band's DOTS/NAME/OUTPUTS reach down below the band and the
    list rail's controls reach left over the rows; the drawn rects do not
    change."""

    def _hit(self, geometry, x, y, **kwargs):
        hit = hit_test(geometry, x, y, 320, 240, metrics=_RICH_320x240, **kwargs)
        return hit.zone if hit is not None else None

    @pytest.mark.parametrize("geometry", [GEOMETRY_MAIN, GEOMETRY_REPEAT, GEOMETRY_EQ])
    def test_a_point_just_below_the_band_takes_the_band_control(self, geometry):
        metrics = _RICH_320x240
        layout = layout_for(320, 240, metrics=metrics)
        y = metrics.band_h + 2
        for zone, rect in (
            (TouchZone.DOTS, layout.dots),
            (TouchZone.NAME, layout.name),
            (TouchZone.OUTPUTS, layout.volume_cluster),
        ):
            assert self._hit(geometry, (rect[0] + rect[2]) // 2, y) == zone

    def test_a_point_past_the_reach_is_what_it_was_before(self):
        metrics = _RICH_320x240
        layout = layout_for(320, 240, metrics=metrics)
        y = metrics.band_h + metrics.band_h // 3
        for rect in (layout.dots, layout.name, layout.volume_cluster):
            assert self._hit(GEOMETRY_MAIN, (rect[0] + rect[2]) // 2, y) == TouchZone.ARTWORK
        eq = eq_layout_for(320, 240, metrics=metrics)
        assert self._hit(GEOMETRY_EQ, (eq.dots[0] + eq.dots[2]) // 2, y) == TouchZone.EQ_BASS_DOWN

    def test_rail_reach_resolves_to_the_rail_control_and_stops_short_of_the_rows(self):
        metrics = _RICH_320x240
        layout = list_layout_for(320, 240, metrics=metrics)
        rail_x = layout.rail[0]
        reach = metrics.band_h // 3
        rail_rects = (
            (TouchZone.LIST_UP, layout.rail_up),
            (TouchZone.LIST_BACK, layout.rail_cancel),
            (TouchZone.LIST_DOWN, layout.rail_down),
        )
        checked = 0
        for row in layout.rows:
            y = (row[1] + row[3]) // 2
            expected = next((zone for zone, rect in rail_rects if rect[1] <= y < rect[3]), None)
            if expected is not None:
                assert self._hit(GEOMETRY_LIST, rail_x - 2, y) == expected
                checked += 1
            assert self._hit(GEOMETRY_LIST, rail_x - reach - 1, y) == TouchZone.LIST_ROW
        assert checked > 0

    def test_skip_passes_over_a_switched_off_zone(self):
        metrics = _RICH_320x240
        layout = layout_for(320, 240, metrics=metrics)
        x = (layout.name[0] + layout.name[2]) // 2
        skip = frozenset({TouchZone.NAME})
        assert self._hit(GEOMETRY_MAIN, x, metrics.band_h + 2, skip=skip) == TouchZone.ARTWORK
        assert self._hit(GEOMETRY_MAIN, x, 2, skip=skip) is None
        assert self._hit(GEOMETRY_MAIN, x, 2) == TouchZone.NAME

    @pytest.mark.parametrize("geometry", [
        GEOMETRY_MAIN, GEOMETRY_REPEAT, GEOMETRY_EQ, GEOMETRY_LIST, GEOMETRY_INFO,
    ])
    def test_reach_always_contains_the_drawn_rect(self, geometry):
        reaching = 0
        for metrics in (_RICH_320x240, _LARGE_640x480):
            for entry in zone_rects_for(geometry, metrics.width, metrics.height, metrics=metrics):
                if entry.reach is None:
                    assert entry.touch_rect == entry.rect
                    continue
                reaching += 1
                assert entry.touch_rect == entry.reach
                rx0, ry0, rx1, ry1 = entry.reach
                x0, y0, x1, y1 = entry.rect
                assert rx0 <= x0 and ry0 <= y0 and x1 <= rx1 and y1 <= ry1
        assert reaching > 0
