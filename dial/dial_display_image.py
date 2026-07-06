"""dial_display_image.py — Pillow-only image policy for the dial display.

Owns logo loading, artwork decode/transform, and the fixed v1 panel
dimensions. Backend hardware code stays in dial_display_adafruit.py; display
policy (selection, fetch, threading) stays in dial_display.py.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
import warnings

from PIL import Image, ImageOps

# MAX_IMAGE_PIXELS is a PIL process-wide global. This is the dial's only PIL
# user, so applying the limit here at import time is safe and also protects
# logo decoding.
MAX_DECODED_ARTWORK_PIXELS = 16_777_216
Image.MAX_IMAGE_PIXELS = MAX_DECODED_ARTWORK_PIXELS
warnings.simplefilter("error", Image.DecompressionBombWarning)

MAX_ARTWORK_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_EXPANDED_ARTWORK_BYTES = 64 * 1024 * 1024

PANEL_WIDTH = 128
PANEL_HEIGHT = 160

# Matches the web UI dark-theme --color-bg and the logo asset's own
# background, so letterbox padding is seamless.
LOGO_BACKGROUND_RGB = (14, 40, 65)

_ARTWORK_FORMATS = ("JPEG", "PNG", "WEBP")

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


def transform_artwork_for_panel(img: Image.Image) -> Image.Image:
    """Center-crop to the panel aspect ratio (4:5) and resize to 128x160."""
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


def load_logo(path: str) -> Image.Image | None:
    """Load the fallback logo, scaled to fit and letterboxed to 128x160.

    The source asset is 983x575 landscape; center-cropping it to a portrait
    panel would reduce the wordmark to an illegible vertical slice. Instead
    scale to fit within the panel preserving aspect ratio, then pad with the
    autostream dark-theme background colour. Returns None on any failure —
    callers must leave the screen blank rather than crash.
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
