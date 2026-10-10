"""Tests for dial_touch_layout.py — pure touch-zone geometry.

Covers the band layout across all profile sizes in dial_display_profiles.py
(layout_for()'s band/artist/cluster/down/up geometry), exact tiling (zones +
dead zones cover the panel with no gap/overlap), the remainder policy
(leftover pixels never land in a control rectangle), zone_at() hit-testing
at zone centres and in dead-zone/artist/middle-band gaps, and the pinned
160x128 reference geometry from the low-level design.
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
    TouchZone,
    _dead_zone_margin,
    layout_for,
    zone_at,
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

ALL_ZONES = {TouchZone.MUTE, TouchZone.DOWN, TouchZone.UP}


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
                # (dead zone, artist area, middle band, or out-of-bounds)
                # means none does. The middle half and the artist area are
                # now dead pixels by construction, so this still holds.
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
    def test_tap_in_artist_area_and_middle_returns_none(self, width, height):
        layout = layout_for(width, height)

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
    def test_mute_and_artist_lie_inside_the_top_band(self, width, height):
        layout = layout_for(width, height)
        ty0, ty1 = layout.top_band[1], layout.top_band[3]
        for rect in (layout.volume_cluster, layout.artist):
            x0, y0, x1, y1 = rect
            assert ty0 <= y0 < y1 <= ty1
            assert 0 <= x0 < x1 <= width

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_artist_and_mute_are_separated_by_two_margins(self, width, height):
        layout = layout_for(width, height)
        margin = _dead_zone_margin(width, height)
        gap = layout.volume_cluster[0] - layout.artist[2]
        assert gap == 2 * margin

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_middle_rows_contain_no_zone_pixel(self, width, height):
        layout = layout_for(width, height)
        for y in range(layout.top_band[3], layout.bottom_band[1]):
            for x in range(width):
                assert zone_at(x, y, width, height) is None


def test_reference_geometry_exact():
    """Pin the 160x128 numbers from the low-level design so any future
    drift in the band-layout arithmetic is deliberate, not accidental."""
    layout = layout_for(160, 128)
    assert layout.volume_cluster == (99, 0, 160, 29)
    assert layout.artist == (3, 0, 93, 32)
    assert layout.down == (0, 99, 77, 128)
    assert layout.up == (83, 99, 160, 128)
    assert layout.divider_x == 80
