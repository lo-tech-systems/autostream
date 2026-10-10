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
    COMPACT_BELOW_BAND_MM,
    GEOMETRIES,
    GEOMETRY_IDLE,
    GEOMETRY_LIST,
    GEOMETRY_MAIN,
    GEOMETRY_REPEAT,
    LARGE_ABOVE_BAND_MM,
    TIER_COMPACT,
    TIER_LARGE,
    TIER_REGULAR,
    TOUCH_MIN_MM,
    TouchZone,
    _dead_zone_margin,
    hit_test,
    idle_layout_for,
    idle_zone_at,
    layout_for,
    list_layout_for,
    list_zone_at,
    metrics_for,
    repeat_layout_for,
    repeat_zone_at,
    scale_px,
    zone_at,
    zone_rects_for,
    zones_for,
)

# The profile sizes from dial_display_profiles.DISPLAY_PROFILES. Two
# profiles (st7789_320x240, ili9341_320x240) share 320x240 — kept as
# separate parametrize entries anyway since the point is "every profile
# size behaves correctly", duplicate value included on purpose.
PROFILE_SIZES = [
    (160, 128),  # st7735s_160x128
    (128, 128),  # st7735s_128x128
    (240, 240),  # st7789_240x240
    (320, 240),  # st7789_320x240
    (320, 240),  # ili9341_320x240 (duplicate size, both must work)
]

ALL_ZONES = {TouchZone.DOTS, TouchZone.NAME, TouchZone.MUTE, TouchZone.DOWN, TouchZone.UP}


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
        zones = zones_for(width, height)
        for y in range(height):
            for x in range(width):
                z = zone_at(x, y, width, height)
                in_some_rect = any(
                    x0 <= x < x1 and y0 <= y < y1 for (x0, y0, x1, y1) in zones.values()
                )
                # zone_at agrees with manual rectangle membership: a hit
                # means exactly one rectangle contains the point, a miss
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
    def test_tap_in_name_area_hits_name_and_middle_returns_none(self, width, height):
        layout = layout_for(width, height)

        # The old artist-area rectangle is now the NAME zone.
        nx0, ny0, nx1, ny1 = layout.name
        ncx, ncy = (nx0 + nx1) // 2, (ny0 + ny1) // 2
        assert zone_at(ncx, ncy, width, height) == TouchZone.NAME

        # The relocated (centre-low) artist line is still non-actuating.
        ax0, ay0, ax1, ay1 = layout.artist
        acx, acy = (ax0 + ax1) // 2, (ay0 + ay1) // 2
        assert zone_at(acx, acy, width, height) is None

        mid_y = (layout.top_band[3] + layout.bottom_band[1]) // 2
        assert zone_at(width // 2, mid_y, width, height) is None

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_divider_x_sits_in_the_gap(self, width, height):
        layout = layout_for(width, height)
        y0, y1 = layout.bottom_band[1], layout.bottom_band[3]
        for y in range(y0, y1):
            assert zone_at(layout.divider_x, y, width, height) is None


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
        assert zones[TouchZone.MUTE] == layout.volume_cluster
        assert zones[TouchZone.DOWN] == layout.down
        assert zones[TouchZone.UP] == layout.up


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
    def test_middle_rows_contain_no_zone_pixel(self, width, height):
        layout = layout_for(width, height)
        for y in range(layout.top_band[3], layout.bottom_band[1]):
            for x in range(width):
                assert zone_at(x, y, width, height) is None


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

    def test_repeat_zone_at_resolves_mute(self):
        """The top band's mute/volume readout toggles mute on the repeat
        screen too (same as the main screen), so a tap there resolves to
        MUTE."""
        layout = repeat_layout_for(160, 128)
        x0, y0, x1, y1 = layout.volume_cluster
        cx, cy = (x0 + x1) // 2, (y0 + y1) // 2
        assert repeat_zone_at(cx, cy, 160, 128) == TouchZone.MUTE

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
            (TouchZone.MUTE, None),
            (TouchZone.DOWN, None),
            (TouchZone.UP, None),
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
            (TouchZone.MUTE, None),
            (TouchZone.REPEAT_PLAY, None),
            (TouchZone.REPEAT_START, None),
            (TouchZone.REPEAT_STOP, None),
        ]

    def test_idle_order(self):
        entries = zone_rects_for(GEOMETRY_IDLE, 160, 128)
        assert [(e.zone, e.index) for e in entries] == [(TouchZone.IDLE_REPLAY, None)]


class TestZoneRectsMatchLayoutFields:
    """The table is a view, not a recomputation: every rect it carries must
    be exactly the corresponding *Layout field."""

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_main_rects_are_layout_fields(self, width, height):
        layout = layout_for(width, height)
        entries = {e.zone: e.rect for e in zone_rects_for(GEOMETRY_MAIN, width, height)}
        assert entries[TouchZone.DOTS] == layout.dots
        assert entries[TouchZone.NAME] == layout.name
        assert entries[TouchZone.MUTE] == layout.volume_cluster
        assert entries[TouchZone.DOWN] == layout.down
        assert entries[TouchZone.UP] == layout.up

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
        assert entries[TouchZone.MUTE] == layout.volume_cluster
        assert entries[TouchZone.REPEAT_PLAY] == layout.row
        assert entries[TouchZone.REPEAT_START] == layout.start
        assert entries[TouchZone.REPEAT_STOP] == layout.stop

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_idle_rect_is_layout_field(self, width, height):
        layout = idle_layout_for(width, height)
        entries = zone_rects_for(GEOMETRY_IDLE, width, height)
        assert entries[0].rect == layout.replay


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


class TestIdleZoneAtExhaustive:
    """Every pixel of every profile size, plus a one-pixel ring outside the
    panel: IDLE_REPLAY iff the point is on-panel and at or below the top
    band, else None."""

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_matches_top_band_boundary_at_every_pixel_and_a_ring_outside(self, width, height):
        band_h = height // 4
        for y in range(-1, height + 1):
            for x in range(-1, width + 1):
                expected = None
                if 0 <= x < width and 0 <= y < height and y >= band_h:
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
# table in the profiles module's design notes.
_CONFIRMED_MM_PER_PX = [0.2231, 0.2021, 0.0973, 0.1778, 0.1778]
# Densities chosen to resolve to compact/large respectively, proving tier is
# reported-only: geometry must stay regular-tier regardless.
_OUT_OF_TIER_MM_PER_PX = [0.05, 0.5]


class TestDensityHasNoEffectOnGeometry:
    """Passing a real mm_per_px must never change a single pixel of layout
    or hit-test geometry in this stage — only metrics_for()'s own reported
    fields (band_mm, tier, touch_min_px) are density-dependent."""

    @pytest.mark.parametrize("size,mm", list(zip(PROFILE_SIZES, _CONFIRMED_MM_PER_PX)))
    def test_layout_for_unaffected(self, size, mm):
        width, height = size
        assert layout_for(width, height) == layout_for(
            width, height, metrics=metrics_for(width, height, mm)
        )

    @pytest.mark.parametrize("size,mm", list(zip(PROFILE_SIZES, _CONFIRMED_MM_PER_PX)))
    def test_list_layout_for_unaffected(self, size, mm):
        width, height = size
        assert list_layout_for(width, height) == list_layout_for(
            width, height, metrics=metrics_for(width, height, mm)
        )

    @pytest.mark.parametrize("size,mm", list(zip(PROFILE_SIZES, _CONFIRMED_MM_PER_PX)))
    def test_repeat_layout_for_unaffected(self, size, mm):
        width, height = size
        assert repeat_layout_for(width, height) == repeat_layout_for(
            width, height, metrics=metrics_for(width, height, mm)
        )

    @pytest.mark.parametrize("size,mm", list(zip(PROFILE_SIZES, _CONFIRMED_MM_PER_PX)))
    def test_idle_layout_for_unaffected(self, size, mm):
        width, height = size
        assert idle_layout_for(width, height) == idle_layout_for(
            width, height, metrics=metrics_for(width, height, mm)
        )

    @pytest.mark.parametrize("size,mm", list(zip(PROFILE_SIZES, _CONFIRMED_MM_PER_PX)))
    def test_zone_rects_for_unaffected(self, size, mm):
        width, height = size
        metrics = metrics_for(width, height, mm)
        for geometry in GEOMETRIES:
            assert zone_rects_for(geometry, width, height) == zone_rects_for(
                geometry, width, height, metrics=metrics
            )

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    @pytest.mark.parametrize("mm", _OUT_OF_TIER_MM_PER_PX)
    def test_out_of_tier_density_still_leaves_geometry_unchanged(self, width, height, mm):
        metrics = metrics_for(width, height, mm)
        assert metrics.tier != TIER_REGULAR
        assert layout_for(width, height, metrics=metrics) == layout_for(width, height)
        assert list_layout_for(width, height, metrics=metrics) == list_layout_for(width, height)
        assert repeat_layout_for(width, height, metrics=metrics) == repeat_layout_for(width, height)
        assert idle_layout_for(width, height, metrics=metrics) == idle_layout_for(width, height)


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


# (size, mm_per_px, expected tier) for the five confirmed profiles, in
# PROFILE_SIZES order — the 1.3 inch 240x240 is the one honestly compact.
_CONFIRMED_TIERS = [
    ((160, 128), 0.2231, TIER_REGULAR),
    ((128, 128), 0.2021, TIER_REGULAR),
    ((240, 240), 0.0973, TIER_COMPACT),
    ((320, 240), 0.1778, TIER_REGULAR),
    ((320, 240), 0.1778, TIER_REGULAR),
]


class TestTierReporting:
    @pytest.mark.parametrize("size,mm,expected_tier", _CONFIRMED_TIERS)
    def test_confirmed_profiles_report_expected_tier(self, size, mm, expected_tier):
        width, height = size
        assert metrics_for(width, height, mm).tier == expected_tier

    def test_mm_per_px_none_gives_regular(self):
        assert metrics_for(160, 128).tier == TIER_REGULAR
        assert metrics_for(240, 240).tier == TIER_REGULAR

    def test_tier_override_is_returned_as_given(self):
        assert metrics_for(160, 128, tier_override=TIER_COMPACT).tier == TIER_COMPACT
        assert metrics_for(160, 128, tier_override=TIER_LARGE).tier == TIER_LARGE
        # An override wins even against a density that would otherwise
        # resolve differently.
        assert metrics_for(160, 128, mm_per_px=0.0973, tier_override=TIER_LARGE).tier == TIER_LARGE

    def test_invalid_tier_override_raises(self):
        with pytest.raises(ValueError):
            metrics_for(160, 128, tier_override="huge")

    def test_touch_min_px_matches_confirmed_table(self):
        from math import ceil

        for size, mm, _ in _CONFIRMED_TIERS:
            width, height = size
            assert metrics_for(width, height, mm).touch_min_px == ceil(TOUCH_MIN_MM / mm)

    def test_touch_min_px_none_when_density_unknown(self):
        assert metrics_for(160, 128).touch_min_px is None

    def test_boundary_at_exactly_compact_threshold_is_regular(self):
        # band_mm == COMPACT_BELOW_BAND_MM exactly must NOT read compact —
        # the comparison is strict '<'.
        band_h = 128 // 4
        mm = COMPACT_BELOW_BAND_MM / band_h
        assert metrics_for(160, 128, mm).tier == TIER_REGULAR

    def test_boundary_at_exactly_large_threshold_is_regular(self):
        # band_mm == LARGE_ABOVE_BAND_MM exactly must NOT read large — the
        # comparison is strict '>'.
        band_h = 128 // 4
        mm = LARGE_ABOVE_BAND_MM / band_h
        assert metrics_for(160, 128, mm).tier == TIER_REGULAR


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
