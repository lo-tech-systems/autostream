"""dial_display_image.py — Pillow-only image policy for the dial display.

Owns logo loading, artwork decode/transform, and the fixed v1 panel
dimensions. Backend hardware code stays in dial_display_adafruit.py; display
policy (selection, fetch, threading) stays in dial_display.py.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
import warnings

from PIL import Image, ImageEnhance, ImageFilter, ImageOps

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
PANEL_WIDTH = 160
PANEL_HEIGHT = 128

# Matches the web UI dark-theme --color-bg and the logo asset's own
# background, so letterbox padding is seamless.
LOGO_BACKGROUND_RGB = (14, 40, 65)

_ARTWORK_FORMATS = ("JPEG", "PNG", "WEBP")

# Ambient-blur backdrop (Apple-TV-style): the source is scaled to cover the
# panel, blurred into a soft colour wash, then darkened so the foreground art
# reads clearly on top. Radius 10 is chosen empirically for a 160x128 panel —
# low enough that the blur still carries the source's dominant colours,
# high enough that no source detail or hard edges survive into the wash.
BACKDROP_BLUR_RADIUS = 10

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


def _cover_panel(img: Image.Image) -> Image.Image:
    """Center-crop to the panel aspect ratio (5:4 landscape) and resize to
    160x128, filling the panel with no letterboxing (some source content is
    cropped away)."""
    src_w, src_h = img.size
    target_ratio = PANEL_WIDTH / PANEL_HEIGHT

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
    return cropped.resize((PANEL_WIDTH, PANEL_HEIGHT), _RESAMPLE)


def transform_artwork_for_panel(img: Image.Image) -> Image.Image:
    """Compose an Apple-TV-style ambient-blur backdrop, returning one 160x128
    RGB frame.

    The source is scaled to fit within the panel preserving aspect ratio
    (the common case — square album art — becomes a full 128x128 foreground)
    and pasted centered over a blurred, darkened backdrop built by covering
    the panel with the same source. This applies to any aspect ratio, not
    just square: art narrower than 160:128 leaves blurred bands left/right,
    art wider than 160:128 leaves them above/below.
    """
    # Explicit contain-scale rather than Image.thumbnail(): thumbnail never
    # upscales, and provider artwork smaller than the panel must still fill
    # its axis (a 100x100 cover becomes a 128x128 foreground, not a stamp).
    src_w, src_h = img.size
    scale = min(PANEL_WIDTH / src_w, PANEL_HEIGHT / src_h)
    fitted = img.resize(
        (max(1, round(src_w * scale)), max(1, round(src_h * scale))),
        _RESAMPLE,
    )

    if fitted.size == (PANEL_WIDTH, PANEL_HEIGHT):
        # Source is already exactly panel ratio — the foreground covers the
        # whole frame, so there is no backdrop left to show. Skip the blur
        # work entirely.
        return fitted

    backdrop = _cover_panel(img)
    backdrop = backdrop.filter(ImageFilter.GaussianBlur(BACKDROP_BLUR_RADIUS))
    backdrop = ImageEnhance.Brightness(backdrop).enhance(1 - BACKDROP_DARKEN_PERCENT / 100)

    offset = (
        (PANEL_WIDTH - fitted.width) // 2,
        (PANEL_HEIGHT - fitted.height) // 2,
    )
    backdrop.paste(fitted, offset)
    return backdrop


def load_logo(path: str) -> Image.Image | None:
    """Load the fallback logo, scaled to fit and letterboxed to 160x128.

    The source asset is 983x575 landscape; scale to fit within the landscape
    panel preserving aspect ratio, then pad with the autostream dark-theme
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
        fitted.thumbnail((PANEL_WIDTH, PANEL_HEIGHT), _RESAMPLE)
        canvas = Image.new("RGB", (PANEL_WIDTH, PANEL_HEIGHT), LOGO_BACKGROUND_RGB)
        offset = (
            (PANEL_WIDTH - fitted.width) // 2,
            (PANEL_HEIGHT - fitted.height) // 2,
        )
        canvas.paste(fitted, offset)
        return canvas
    except Exception as e:
        logging.debug("dial display: logo transform failed: %s", e)
        return None
