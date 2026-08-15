"""Tests for dial_display_compositor.py — stateless frame composition.

Covers rotate/bgr in isolation and combined, identity when neither is set,
the artwork-fit path (transform_artwork_for_panel runs and panel-fits a
non-panel-sized input), the logo path (already-sized base passes through
transforms only), statelessness, and the inert overlay parameter.
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

from dial_display_compositor import DialDisplayCompositor, OverlayState  # noqa: E402
from dial_touch_layout import TouchZone, zones_for  # noqa: E402


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

    def test_dim_darkens_mean_brightness(self, compositor):
        img = self._panel_image(color=(200, 200, 200))
        result = compositor.compose(
            img, img.width, img.height,
            rotate=False, bgr=False, is_artwork=False,
            overlay=OverlayState(visible=True),
        )

        def mean_brightness(im):
            data = list(im.getdata())
            total = sum(sum(px) for px in data)
            return total / (len(data) * 3)

        assert mean_brightness(result) < mean_brightness(img)

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
