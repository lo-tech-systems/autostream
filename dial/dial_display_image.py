"""dial_display_image.py — Pillow-only image policy for the dial display.

Owns logo loading, artwork decode/transform, and the default panel
dimensions (callers pass their own active dimensions; the default profile's
values are used when none are given). Backend hardware code stays in
dial_display_adafruit.py; display policy (selection, fetch, threading) stays
in dial_display.py.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
import warnings

from PIL import Image, ImageEnhance, ImageFilter, ImageOps

from dial_display_profiles import DEFAULT_PROFILE_KEY, get_profile

# MAX_IMAGE_PIXELS is a PIL process-wide global. This is the dial's only PIL
# user, so applying the limit here at import time is safe and also protects
# logo decoding.
MAX_DECODED_ARTWORK_PIXELS = 16_777_216
Image.MAX_IMAGE_PIXELS = MAX_DECODED_ARTWORK_PIXELS
warnings.simplefilter("error", Image.DecompressionBombWarning)

MAX_ARTWORK_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_EXPANDED_ARTWORK_BYTES = 64 * 1024 * 1024

# The ST7735S glass is a 128x160 panel physically mounted in landscape, so the
# usable image is 160 wide x 128 tall. Frames are rendered at this landscape
# size covering the full panel (artwork is cropped to fill; the logo is
# letterboxed onto a full-size background canvas) and the hardware backend
# sends each one unrotated as a single whole-screen write — the controller's
# MADCTL init already scans landscape (see dial_display_adafruit.py). Keeping
# the panel dimensions here means the crop/letterbox policy already targets
# the true visible orientation.
#
# This module stays profile-agnostic (plain ints, no DisplayProfile objects)
# — dial_display.py is the one that knows which profile is active and passes
# its dimensions through. PANEL_WIDTH/PANEL_HEIGHT are sourced from the
# default profile purely so the values live in one place; they remain the
# default (width, height) for every function below so existing callers and
# tests keep working unchanged.
_DEFAULT_PROFILE = get_profile(DEFAULT_PROFILE_KEY)
PANEL_WIDTH = _DEFAULT_PROFILE.width
PANEL_HEIGHT = _DEFAULT_PROFILE.height

# Matches the web UI dark-theme --color-bg and the logo asset's own
# background, so letterbox padding is seamless.
LOGO_BACKGROUND_RGB = (14, 40, 65)

_ARTWORK_FORMATS = ("JPEG", "PNG", "WEBP")

# Ambient-blur backdrop (Apple-TV-style): the source is scaled to cover the
# panel, blurred into a soft colour wash, then darkened so the foreground art
# reads clearly on top.
def _blur_radius_for(width: int, height: int) -> int:
    """Scale the empirically-tuned 160x128 blur radius to other panel sizes.

    Radius 10 only "reads right" (soft wash, no surviving source detail) at
    the resolution it was tuned on; a bigger panel needs a proportionally
    bigger radius to look the same, and a smaller one a smaller radius.
    Scaling by the panel's short side (min(width, height)) rather than area
    or the long side keeps the ratio stable across both the "wide" and
    "tall" profile shapes in the table. Returns exactly 10 at 160x128 —
    min(160, 128) * 10 / 128 == 10 — so today's shipped panel is bit-for-bit
    unchanged.
    """
    return round(min(width, height) * 10 / PANEL_HEIGHT)


# Kept as a module constant for existing callers/tests — equal to
# _blur_radius_for(PANEL_WIDTH, PANEL_HEIGHT) by construction, i.e. 10.
BACKDROP_BLUR_RADIUS = _blur_radius_for(PANEL_WIDTH, PANEL_HEIGHT)

# Percentage by which the blurred backdrop is darkened before compositing —
# 35 means backdrop pixels are multiplied down to 65% of their blurred
# brightness, keeping the foreground art the clear visual focus.
BACKDROP_DARKEN_PERCENT = 35

try:
    _RESAMPLE = Image.Resampling.LANCZOS
except AttributeError:  # Pillow < 9.1
    _RESAMPLE = Image.LANCZOS


def decode_artwork(data: bytes) -> Image.Image | None:
    """Decode, validate, and orient fetched provider artwork bytes.

    Returns None on any decode failure, unsupported format, or oversized
    image — callers must fall back to the logo. Never raises.
    """
    import io

    try:
        img = Image.open(io.BytesIO(data), formats=_ARTWORK_FORMATS)
        img.load()
    except Exception as e:
        logging.debug("dial display: artwork decode failed: %s", e)
        return None

    width, height = img.size
    if width * height > MAX_DECODED_ARTWORK_PIXELS:
        logging.debug("dial display: artwork exceeds pixel limit (%dx%d)", width, height)
        return None
    if width * height * 4 > MAX_EXPANDED_ARTWORK_BYTES:
        logging.debug("dial display: artwork exceeds expanded footprint limit")
        return None

    try:
        img = ImageOps.exif_transpose(img) or img
    except Exception:
        pass

    try:
        img = img.convert("RGB")
    except Exception as e:
        logging.debug("dial display: artwork RGB conversion failed: %s", e)
        return None

    return img


def _cover_panel(img: Image.Image, width: int = PANEL_WIDTH, height: int = PANEL_HEIGHT) -> Image.Image:
    """Center-crop to the panel aspect ratio and resize to (width, height),
    filling the panel with no letterboxing (some source content is cropped
    away)."""
    src_w, src_h = img.size
    target_ratio = width / height

    if src_w / src_h > target_ratio:
        # Source is wider than target — crop width.
        new_w = int(round(src_h * target_ratio))
        left = (src_w - new_w) // 2
        box = (left, 0, left + new_w, src_h)
    else:
        # Source is taller than (or equal to) target — crop height.
        new_h = int(round(src_w / target_ratio))
        top = (src_h - new_h) // 2
        box = (0, top, src_w, top + new_h)

    cropped = img.crop(box)
    return cropped.resize((width, height), _RESAMPLE)


def transform_artwork_for_panel(
    img: Image.Image,
    width: int = PANEL_WIDTH,
    height: int = PANEL_HEIGHT,
    blur_radius: int | None = None,
) -> Image.Image:
    """Compose an Apple-TV-style ambient-blur backdrop, returning one
    (width, height) RGB frame.

    The source is scaled to fit within the panel preserving aspect ratio
    (the common case — square album art — becomes a full height-square
    foreground) and pasted centered over a blurred, darkened backdrop built
    by covering the panel with the same source. This applies to any aspect
    ratio, not just square: art narrower than width:height leaves blurred
    bands left/right, art wider than width:height leaves them above/below.

    blur_radius overrides the resolution-scaled default from
    _blur_radius_for() — the caller's escape hatch for a profile that needs
    a specific radius, since this module deals only in plain ints and never
    reaches into a DisplayProfile itself.
    """
    # Explicit contain-scale rather than Image.thumbnail(): thumbnail never
    # upscales, and provider artwork smaller than the panel must still fill
    # its axis (a 100x100 cover becomes a 128x128 foreground, not a stamp).
    src_w, src_h = img.size
    scale = min(width / src_w, height / src_h)
    fitted = img.resize(
        (max(1, round(src_w * scale)), max(1, round(src_h * scale))),
        _RESAMPLE,
    )

    if fitted.size == (width, height):
        # Source is already exactly panel ratio — the foreground covers the
        # whole frame, so there is no backdrop left to show. Skip the blur
        # work entirely.
        return fitted

    radius = _blur_radius_for(width, height) if blur_radius is None else blur_radius
    backdrop = _cover_panel(img, width, height)
    backdrop = backdrop.filter(ImageFilter.GaussianBlur(radius))
    backdrop = ImageEnhance.Brightness(backdrop).enhance(1 - BACKDROP_DARKEN_PERCENT / 100)

    offset = (
        (width - fitted.width) // 2,
        (height - fitted.height) // 2,
    )
    backdrop.paste(fitted, offset)
    return backdrop


def load_logo(path: str, width: int = PANEL_WIDTH, height: int = PANEL_HEIGHT) -> Image.Image | None:
    """Load the fallback logo, scaled to fit and letterboxed to (width, height).

    The source asset is 983x575 landscape; scale to fit within the panel
    preserving aspect ratio, then pad with the autostream dark-theme
    background colour. Returns None on any failure — callers must leave the
    screen blank rather than crash.
    """
    try:
        img = Image.open(path)
        img.load()
    except Exception as e:
        logging.debug("dial display: logo load failed (%s): %s", path, e)
        return None

    try:
        img = img.convert("RGB")
        fitted = img.copy()
        fitted.thumbnail((width, height), _RESAMPLE)
        canvas = Image.new("RGB", (width, height), LOGO_BACKGROUND_RGB)
        offset = (
            (width - fitted.width) // 2,
            (height - fitted.height) // 2,
        )
        canvas.paste(fitted, offset)
        return canvas
    except Exception as e:
        logging.debug("dial display: logo transform failed: %s", e)
        return None
