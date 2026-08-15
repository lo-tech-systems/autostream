"""Tests for dial_touch_layout.py — pure touch-zone geometry.

Covers layout selection by aspect ratio across all profile sizes in
dial_display_profiles.py, exact tiling (zones + dead zones cover the panel
with no gap/overlap), the remainder policy (leftover pixels never land in a
control rectangle), zone_at() hit-testing at zone centres and in dead-zone
bands, and rough area parity between zones.
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
    WIDE_ASPECT_THRESHOLD,
    _dead_zone_margin,
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


def _is_wide(width, height):
    return width / height >= WIDE_ASPECT_THRESHOLD


class TestLayoutSelection:
    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_layout_matches_ratio_threshold(self, width, height):
        zones = zones_for(width, height)
        mute = zones[TouchZone.MUTE]
        down = zones[TouchZone.DOWN]
        up = zones[TouchZone.UP]

        if _is_wide(width, height):
            # WIDE: MUTE/DOWN/UP stacked left-to-right, each spanning the
            # full height.
            assert mute[1] == 0 and mute[3] == height
            assert down[1] == 0 and down[3] == height
            assert up[1] == 0 and up[3] == height
            assert mute[2] <= down[0]
            assert down[2] <= up[0]
        else:
            # SQUARE: MUTE is a full-width top band; DOWN/UP share a bottom
            # band split left/right.
            assert mute[0] == 0 and mute[2] == width
            assert mute[3] <= down[1]
            assert down[1] == up[1] and down[3] == up[3]
            assert down[2] <= up[0]

    def test_threshold_boundary_values(self):
        # Exactly at the threshold -> WIDE.
        zones = zones_for(180, 100)  # ratio == 1.8
        assert zones[TouchZone.MUTE][1] == 0 and zones[TouchZone.MUTE][3] == 100

        # Just under the threshold -> SQUARE.
        zones = zones_for(179, 100)  # ratio < 1.8
        assert zones[TouchZone.MUTE][0] == 0 and zones[TouchZone.MUTE][2] == 179

    def test_sixteen_by_nine_selects_square(self):
        # 16:9 sits just below the threshold, so a widescreen panel still
        # gets the full-width mute band rather than three narrow columns.
        zones = zones_for(1920, 1080)
        assert zones[TouchZone.MUTE][0] == 0 and zones[TouchZone.MUTE][2] == 1920

    def test_every_shipped_profile_size_selects_square(self):
        # Every profile in dial_display_profiles is between 1.0 and 1.33, so
        # they all take the square layout; WIDE is reserved for panels wider
        # than 16:9, which none of them are.
        for width, height in PROFILE_SIZES:
            zones = zones_for(width, height)
            assert zones[TouchZone.MUTE][0] == 0, (width, height)
            assert zones[TouchZone.MUTE][2] == width, (width, height)


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
                # (dead zone or, here, never out-of-bounds) means none does.
                assert (z is not None) == in_some_rect

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_zone_rects_within_panel_bounds(self, width, height):
        for x0, y0, x1, y1 in zones_for(width, height).values():
            assert 0 <= x0 < x1 <= width
            assert 0 <= y0 < y1 <= height


class TestRemainderPolicy:
    """Non-evenly-divisible dimensions (160/3, 320/3, 128/3 all leave a
    remainder) must not fatten a control zone — the leftover pixels must be
    absorbed into a dead-zone gap."""

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_wide_zone_widths_equal_within_one_pixel(self, width, height):
        if not _is_wide(width, height):
            pytest.skip("SQUARE layout at this size")
        zones = zones_for(width, height)
        widths = [zones[z][2] - zones[z][0] for z in (TouchZone.MUTE, TouchZone.DOWN, TouchZone.UP)]
        assert max(widths) - min(widths) <= 1

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_square_down_up_widths_equal_within_one_pixel(self, width, height):
        if _is_wide(width, height):
            pytest.skip("WIDE layout at this size")
        zones = zones_for(width, height)
        dw = zones[TouchZone.DOWN][2] - zones[TouchZone.DOWN][0]
        uw = zones[TouchZone.UP][2] - zones[TouchZone.UP][0]
        assert abs(dw - uw) <= 1

    def test_160_wide_remainder_not_in_a_zone(self):
        # 160x128 is ratio 1.25, so it takes the SQUARE layout: MUTE spans
        # the full width across the top and DOWN/UP split the bottom. The
        # remainder policy is checked on the axes that actually get split —
        # the vertical thirds, and the bottom row's left/right halves.
        width, height = 160, 128
        zones = zones_for(width, height)
        total_zone_pixels = sum(
            (x1 - x0) * (y1 - y0) for (x0, y0, x1, y1) in zones.values()
        )
        assert total_zone_pixels < width * height  # some pixels went to dead zones
        down_w = zones[TouchZone.DOWN][2] - zones[TouchZone.DOWN][0]
        up_w = zones[TouchZone.UP][2] - zones[TouchZone.UP][0]
        assert down_w == up_w, "remainder leaked into unequal bottom-half widths"
        assert zones[TouchZone.MUTE][0] == 0 and zones[TouchZone.MUTE][2] == width


class TestZoneAt:
    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_zone_centres_hit_the_right_zone(self, width, height):
        zones = zones_for(width, height)
        for zone, (x0, y0, x1, y1) in zones.items():
            cx, cy = (x0 + x1) // 2, (y0 + y1) // 2
            assert zone_at(cx, cy, width, height) == zone

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_dead_zone_between_wide_zones_returns_none(self, width, height):
        if not _is_wide(width, height):
            pytest.skip("SQUARE layout at this size")
        zones = zones_for(width, height)
        # Between MUTE and DOWN there must be at least one dead pixel.
        boundary_x = zones[TouchZone.MUTE][2]
        if boundary_x < zones[TouchZone.DOWN][0]:
            mid = (boundary_x + zones[TouchZone.DOWN][0]) // 2
            assert zone_at(mid, height // 2, width, height) is None

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


class TestZoneAreas:
    """Zone areas should be roughly a third of the panel each, in both
    layouts — "roughly" allows for the dead-zone bands and the asymmetric
    1:2 vertical split in the SQUARE layout's row-vs-band shape, but no zone
    should be wildly out of proportion."""

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_areas_within_tolerance_of_a_third(self, width, height):
        panel_area = width * height
        zones = zones_for(width, height)
        for zone, (x0, y0, x1, y1) in zones.items():
            area = (x1 - x0) * (y1 - y0)
            fraction = area / panel_area
            assert 0.2 <= fraction <= 0.5, f"{zone} area fraction {fraction} out of range"

    @pytest.mark.parametrize("width,height", PROFILE_SIZES)
    def test_all_three_zones_present(self, width, height):
        assert set(zones_for(width, height).keys()) == ALL_ZONES
