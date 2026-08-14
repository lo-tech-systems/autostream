"""Tests for dial_display_image.py — Pillow-only decode/transform/logo helpers.

Covers: MAX_IMAGE_PIXELS/DecompressionBombWarning wiring, artwork decode
(format validation, pixel-count and expanded-footprint limits, malformed
image handling, EXIF orientation, RGB conversion), panel transform (ambient
blur backdrop: fit-to-panel foreground centered over a blurred, darkened
cover-fill backdrop, resulting in one 160x128 frame), and logo scale-to-fit
letterboxing.
"""
from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

Image = pytest.importorskip("PIL.Image", reason="Pillow not installed")

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
if _DIAL not in sys.path:
    sys.path.insert(0, _DIAL)

import dial_display_image as ddi
from dial_display_image import (
    BACKDROP_BLUR_RADIUS,
    BACKDROP_DARKEN_PERCENT,
    LOGO_BACKGROUND_RGB,
    PANEL_HEIGHT,
    PANEL_WIDTH,
    decode_artwork,
    load_logo,
    transform_artwork_for_panel,
)
from PIL import ImageEnhance, ImageFilter


def _jpeg_bytes(size=(400, 300), color=(255, 0, 0)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, format="JPEG")
    return buf.getvalue()


def _png_bytes(size=(200, 200), color=(0, 255, 0)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, format="PNG")
    return buf.getvalue()


class TestModuleWideLimits:
    def test_max_image_pixels_set(self):
        assert Image.MAX_IMAGE_PIXELS == ddi.MAX_DECODED_ARTWORK_PIXELS


class TestDecodeArtwork:
    def test_decodes_valid_jpeg(self):
        img = decode_artwork(_jpeg_bytes())
        assert img is not None
        assert img.mode == "RGB"
        assert img.size == (400, 300)

    def test_decodes_valid_png(self):
        img = decode_artwork(_png_bytes())
        assert img is not None
        assert img.size == (200, 200)

    def test_malformed_bytes_return_none(self):
        assert decode_artwork(b"not an image") is None

    def test_truncated_jpeg_returns_none(self):
        data = _jpeg_bytes()
        assert decode_artwork(data[: len(data) // 2]) is None

    def test_oversized_pixel_count_rejected(self):
        # width * height exceeds MAX_DECODED_ARTWORK_PIXELS
        w = 20000
        h = 20000
        buf = io.BytesIO()
        # Use a small actual image but monkeypatch is unnecessary — PIL's
        # own MAX_IMAGE_PIXELS guard raises during Image.open()/load() for
        # a genuinely huge image; build one just over the threshold cheaply
        # using a paletted/RLE-friendly format is impractical here, so
        # validate via the pixel-count branch directly using a real (but
        # still large) generated bitmap.
        img = Image.new("L", (4200, 4000))  # 16,800,000 > 16,777,216
        img.save(buf, format="PNG")
        assert decode_artwork(buf.getvalue()) is None

    def test_unsupported_format_rejected(self):
        buf = io.BytesIO()
        Image.new("RGB", (10, 10)).save(buf, format="BMP")
        assert decode_artwork(buf.getvalue()) is None

    def test_converts_to_rgb(self):
        buf = io.BytesIO()
        Image.new("RGBA", (50, 50), (10, 20, 30, 128)).save(buf, format="PNG")
        img = decode_artwork(buf.getvalue())
        assert img is not None
        assert img.mode == "RGB"


class TestTransformArtworkForPanel:
    def test_output_is_fixed_panel_size(self):
        img = decode_artwork(_jpeg_bytes(size=(500, 500)))
        out = transform_artwork_for_panel(img)
        assert out.size == (PANEL_WIDTH, PANEL_HEIGHT)
        assert out.mode == "RGB"

    def test_wide_panel_ratio_source_fills_edge_to_edge(self):
        # Exactly the panel's 5:4 ratio — the fit-to-panel foreground already
        # covers the whole frame, so this is the no-backdrop fast path.
        img = decode_artwork(_jpeg_bytes(size=(800, 640), color=(10, 20, 30)))
        out = transform_artwork_for_panel(img)
        assert out.size == (PANEL_WIDTH, PANEL_HEIGHT)
        # No blurred/darkened backdrop bands — every pixel is the flat source
        # colour, including the corners.
        assert out.getpixel((0, 0)) == (10, 20, 30)
        assert out.getpixel((PANEL_WIDTH - 1, PANEL_HEIGHT - 1)) == (10, 20, 30)

    def test_narrow_tall_source_gets_backdrop_left_right(self):
        # The "contain" logic applies to any aspect ratio, not just square.
        # A narrow/tall source (200x800) is constrained by height when fit
        # within the panel — it scales to 32x128, full height, leaving
        # blurred backdrop bands left and right rather than above/below.
        img = decode_artwork(_jpeg_bytes(size=(200, 800), color=(200, 40, 40)))
        out = transform_artwork_for_panel(img)
        assert out.size == (PANEL_WIDTH, PANEL_HEIGHT)
        band_pixel = out.getpixel((2, PANEL_HEIGHT // 2))
        foreground_pixel = out.getpixel((PANEL_WIDTH // 2, PANEL_HEIGHT // 2))
        assert band_pixel != foreground_pixel

    def test_small_source_is_upscaled_to_fill_axis(self):
        # thumbnail() never upscales; the contain-scale must. A 64x64 cover
        # becomes a full 128x128 foreground, not a 64x64 stamp in the middle.
        img = decode_artwork(_jpeg_bytes(size=(64, 64), color=(40, 200, 40)))
        out = transform_artwork_for_panel(img)
        assert out.size == (PANEL_WIDTH, PANEL_HEIGHT)

        expected_fg = img.resize((PANEL_HEIGHT, PANEL_HEIGHT), ddi._RESAMPLE)
        x_offset = (PANEL_WIDTH - PANEL_HEIGHT) // 2
        actual_fg = out.crop((x_offset, 0, x_offset + PANEL_HEIGHT, PANEL_HEIGHT))
        assert list(actual_fg.getdata()) == list(expected_fg.getdata())

    def test_square_source_foreground_matches_plain_resize(self):
        # Square album art (the common case) becomes a full 128x128
        # foreground pasted centered over the backdrop.
        img = decode_artwork(_jpeg_bytes(size=(300, 300)))
        out = transform_artwork_for_panel(img)
        assert out.size == (PANEL_WIDTH, PANEL_HEIGHT)

        expected_fg = img.resize((PANEL_HEIGHT, PANEL_HEIGHT), ddi._RESAMPLE)
        x_offset = (PANEL_WIDTH - PANEL_HEIGHT) // 2
        actual_fg = out.crop((x_offset, 0, x_offset + PANEL_HEIGHT, PANEL_HEIGHT))
        assert list(actual_fg.getdata()) == list(expected_fg.getdata())

    def test_square_source_side_bands_are_darkened_blurred_backdrop(self):
        img = decode_artwork(_jpeg_bytes(size=(300, 300), color=(200, 40, 40)))
        out = transform_artwork_for_panel(img)

        x_offset = (PANEL_WIDTH - PANEL_HEIGHT) // 2
        band_pixel = out.getpixel((2, PANEL_HEIGHT // 2))

        # Not black — it carries the source's colour wash, not a letterbox.
        assert band_pixel != (0, 0, 0)

        # Matches the same cover/blur/darken pipeline the implementation
        # uses, exactly.
        expected_backdrop = ddi._cover_panel(img)
        expected_backdrop = expected_backdrop.filter(ImageFilter.GaussianBlur(BACKDROP_BLUR_RADIUS))
        expected_backdrop = ImageEnhance.Brightness(expected_backdrop).enhance(
            1 - BACKDROP_DARKEN_PERCENT / 100
        )
        assert band_pixel == expected_backdrop.getpixel((2, PANEL_HEIGHT // 2))

        # Darkened relative to the un-darkened blurred backdrop, by
        # approximately BACKDROP_DARKEN_PERCENT.
        undarkened = ddi._cover_panel(img).filter(ImageFilter.GaussianBlur(BACKDROP_BLUR_RADIUS))
        undarkened_pixel = undarkened.getpixel((2, PANEL_HEIGHT // 2))
        ratio = sum(band_pixel) / sum(undarkened_pixel)
        assert abs(ratio - (1 - BACKDROP_DARKEN_PERCENT / 100)) < 0.05

        # Sanity-check the offset used above is still outside the pasted
        # foreground region.
        assert 2 < x_offset

    def test_backdrop_darken_percent_pinned(self):
        assert BACKDROP_DARKEN_PERCENT == 35


class TestTransformArtworkForPanelNonDefaultDims:
    """Same pipeline, parameterized panel size — the profile table carries
    non-160x128 entries (e.g. 240x240, 320x240) that must compose correctly
    even though nothing ships on them yet."""

    @pytest.mark.parametrize("width,height", [(240, 240), (320, 240)])
    def test_output_is_requested_panel_size(self, width, height):
        img = decode_artwork(_jpeg_bytes(size=(500, 500)))
        out = transform_artwork_for_panel(img, width, height)
        assert out.size == (width, height)
        assert out.mode == "RGB"

    def test_square_panel_240_panel_ratio_source_fills_edge_to_edge(self):
        # A square source into a square panel is again the panel-ratio fast
        # path — same shape as test_wide_panel_ratio_source_fills_edge_to_edge
        # above, just at a different resolution.
        img = decode_artwork(_jpeg_bytes(size=(300, 300), color=(200, 40, 40)))
        out = transform_artwork_for_panel(img, 240, 240)
        assert out.size == (240, 240)
        assert out.getpixel((0, 0)) == (200, 40, 40)
        assert out.getpixel((239, 239)) == (200, 40, 40)

    def test_landscape_320x240_square_art_centre_intact_with_side_bands(self):
        img = decode_artwork(_jpeg_bytes(size=(300, 300), color=(200, 40, 40)))
        out = transform_artwork_for_panel(img, 320, 240)
        assert out.size == (320, 240)

        # Foreground: 300x300 fit to the 240 height -> a 240x240 square,
        # centered on the 320-wide panel.
        expected_fg = img.resize((240, 240), ddi._RESAMPLE)
        x_offset = (320 - 240) // 2
        actual_fg = out.crop((x_offset, 0, x_offset + 240, 240))
        assert list(actual_fg.getdata()) == list(expected_fg.getdata())

        # Side bands carry the blurred/darkened colour wash, not a letterbox
        # and not the flat foreground colour.
        band_pixel = out.getpixel((2, 120))
        assert band_pixel != (0, 0, 0)
        assert band_pixel != (200, 40, 40)

    def test_explicit_blur_radius_override_is_honoured(self):
        img = decode_artwork(_jpeg_bytes(size=(300, 300), color=(200, 40, 40)))
        out = transform_artwork_for_panel(img, blur_radius=1)

        expected_backdrop = ddi._cover_panel(img)
        expected_backdrop = expected_backdrop.filter(ImageFilter.GaussianBlur(1))
        expected_backdrop = ImageEnhance.Brightness(expected_backdrop).enhance(
            1 - BACKDROP_DARKEN_PERCENT / 100
        )
        band_pixel = out.getpixel((2, PANEL_HEIGHT // 2))
        assert band_pixel == expected_backdrop.getpixel((2, PANEL_HEIGHT // 2))


class TestBlurRadiusFor:
    def test_returns_ten_at_default_panel_size(self):
        assert ddi._blur_radius_for(PANEL_WIDTH, PANEL_HEIGHT) == 10

    def test_matches_backdrop_blur_radius_constant(self):
        assert ddi._blur_radius_for(PANEL_WIDTH, PANEL_HEIGHT) == BACKDROP_BLUR_RADIUS

    def test_scales_up_for_larger_panels(self):
        # min(short side) * 10 / 128, rounded — see the helper's docstring.
        assert ddi._blur_radius_for(240, 240) == 19
        assert ddi._blur_radius_for(320, 240) == 19

    def test_monotonic_with_panel_short_side(self):
        small = ddi._blur_radius_for(160, 128)
        mid = ddi._blur_radius_for(200, 176)
        large = ddi._blur_radius_for(320, 240)
        assert small < mid < large


class TestLoadLogo:
    def _write_logo(self, tmp_path, size=(983, 575)):
        path = tmp_path / "logo.png"
        Image.new("RGB", size, (14, 40, 65)).save(path, format="PNG")
        return str(path)

    def test_missing_file_returns_none(self):
        assert load_logo("/nonexistent/path/logo.png") is None

    def test_valid_logo_returns_panel_sized_image(self, tmp_path):
        path = self._write_logo(tmp_path)
        img = load_logo(path)
        assert img is not None
        assert img.size == (PANEL_WIDTH, PANEL_HEIGHT)

    def test_logo_is_letterboxed_not_cropped(self, tmp_path):
        """A landscape logo scaled to fit must be padded, not cropped — the
        full width of the source content should remain visible after fit."""
        path = self._write_logo(tmp_path, size=(983, 575))
        img = load_logo(path)
        assert img is not None
        # Corner pixels must be the letterbox background (top/bottom padding
        # for a landscape source scaled to fit width).
        assert img.getpixel((0, 0)) == LOGO_BACKGROUND_RGB

    def test_malformed_logo_file_returns_none(self, tmp_path):
        path = tmp_path / "bad.png"
        path.write_bytes(b"not a real png")
        assert load_logo(str(path)) is None

    def test_real_dial_logo_asset_loads(self):
        """The actual shipped asset must decode and produce a panel-sized image."""
        real_path = REPO_ROOT / "images" / "autostream-logo-centred-dark.png"
        img = load_logo(str(real_path))
        assert img is not None
        assert img.size == (PANEL_WIDTH, PANEL_HEIGHT)

    def test_valid_logo_at_non_default_dims_returns_those_dims(self, tmp_path):
        path = self._write_logo(tmp_path)
        img = load_logo(path, 240, 240)
        assert img is not None
        assert img.size == (240, 240)
