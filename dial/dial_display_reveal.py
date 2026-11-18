"""dial_display_reveal.py -- the artwork-tap reveal frames.

The reveal slides the overlay's chrome off the panel while the artwork stays
put. The chrome is held as RevealLayers (for the top band, the bottom band
and the inter-band strip: the light it adds and how much of the base shows
through), laid over a base image one frame at a time. The normal path does a
frame as arithmetic on numpy arrays; if that fails, the same frame is built
with Pillow. The layers themselves are built by the compositor's memoised
_reveal_layers(), the one step that needs the drawing pipeline.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

import numpy as np
from PIL import Image, ImageChops

from dial_display_draw import _BOX, _new_frame
from dial_display_views import BG_BASE
from dial_touch_layout import Rect

_logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RevealLayers:
    """The overlay's own contribution to one screen's frame, separated from
    the artwork it is drawn over, for the artwork-tap reveal: for each of
    the top band, the bottom band and the inter-band strip, the light the
    chrome adds on its own (`*_add`) and how much of whatever is behind it
    shows through (`*_keep`, per channel, 0..255), so that a band's pixels
    are add + keep * base / 255 wherever the band sits. Built by
    _reveal_layers() from two renders of the same frame descriptor, over
    black and over white; a pure function of that descriptor, so it is
    memoised like the glyph tiles and never depends on the base image."""

    top_band: Rect
    bottom_band: Rect
    strip: Rect
    top_add: Image.Image
    top_keep: Image.Image
    bottom_add: Image.Image
    bottom_keep: Image.Image
    strip_add: Image.Image
    strip_keep: Image.Image
    # The same layers as uint16 arrays for the numpy compositing path, plus
    # the strip rows the chrome actually touches; None when building them
    # failed (the Pillow path is used then). Derived from the images
    # above, so excluded from equality and repr.
    arrays: "_RevealArrays | None" = field(default=None, compare=False, repr=False)


@dataclass(frozen=True)
class _RevealArrays:
    """RevealLayers' layers as (rows, cols, 3) uint16 arrays, so a slide
    frame is pure arithmetic. `strip_runs` lists the half-open row ranges
    (relative to the strip) where the chrome changes anything, that is
    where add is not 0 or keep is not 255 in some column; every other
    strip row passes the base through unchanged and is never touched."""

    top_add: object
    top_keep: object
    bottom_add: object
    bottom_keep: object
    strip_add: object
    strip_keep: object
    strip_runs: tuple


def _active_runs(np, add, keep) -> tuple:
    """Half-open row ranges of a layer where it is not the identity."""
    active = ((add != 0) | (keep != 255)).any(axis=(1, 2))
    padded = np.concatenate(([0], active.astype(np.int8), [0]))
    edges = np.flatnonzero(np.diff(padded))
    return tuple((int(a), int(b)) for a, b in zip(edges[::2], edges[1::2]))


def _build_reveal_arrays(layers: RevealLayers) -> "_RevealArrays | None":
    try:
        def arr(img):
            return np.array(img, dtype=np.uint16)

        strip_add, strip_keep = arr(layers.strip_add), arr(layers.strip_keep)
        return _RevealArrays(
            top_add=arr(layers.top_add), top_keep=arr(layers.top_keep),
            bottom_add=arr(layers.bottom_add), bottom_keep=arr(layers.bottom_keep),
            strip_add=strip_add, strip_keep=strip_keep,
            strip_runs=_active_runs(np, strip_add, strip_keep),
        )
    except Exception:
        _logger.warning("dial display: reveal layer arrays unavailable", exc_info=True)
        return None


def _reveal_output_size(width: int, height: int, output_size) -> "tuple[int, int] | None":
    """The size a reveal slide's frames are built at when it is not the
    compose size: *output_size* when it is strictly smaller on at least one
    axis and no larger on either (a layout size composed bigger than the
    panel), else None. Only a reduction qualifies: the shrink is a box
    average, which is right for that and wrong for growing."""
    if output_size is None:
        return None
    ow, oh = output_size
    if (ow, oh) == (width, height) or ow > width or oh > height or ow < 1 or oh < 1:
        return None
    return ow, oh


def _scale_rect(rect: Rect, sx: float, sy: float) -> Rect:
    return (round(rect[0] * sx), round(rect[1] * sy), round(rect[2] * sx), round(rect[3] * sy))


# The base a resampled reveal slide is drawn over, shrunk once per base
# rather than once per frame: (source image, size, shrunk image). Holding
# the source keeps its identity from being reused while the entry lives.
_shrunk_base_memo: "tuple | None" = None


def _shrunk_base(base, size: tuple[int, int]):
    """*base* box-averaged to *size*, memoised on the base object itself
    for as long as the same base keeps being passed (one slide's frames).
    None stays None, and a base already at *size* is returned as it is."""
    global _shrunk_base_memo
    if base is None or getattr(base, "size", None) == size:
        return base
    memo = _shrunk_base_memo
    if memo is not None and memo[0] is base and memo[1] == size:
        return memo[2]
    shrunk = base.convert("RGB").resize(size, _BOX)
    _shrunk_base_memo = (base, size, shrunk)
    return shrunk


def _reset_shrunk_base() -> None:
    """Forget the memoised shrunk base. Test hook, called by the
    compositor's _reset_render_caches()."""
    global _shrunk_base_memo
    _shrunk_base_memo = None


def _apply_layer(region: Image.Image, add: Image.Image, keep: Image.Image) -> Image.Image:
    """The chrome laid over *region*: add + keep * region / 255, per
    channel. All three images are the same size."""
    return ImageChops.add(ImageChops.multiply(region, keep), add)


def _apply_layer_np(np, region, add, keep):
    """_apply_layer() on arrays, bit-identical to Pillow's multiply (the
    truncated a * b // 255) then saturating add. *region* is uint8, *add*
    and *keep* uint16 of the same shape; returns uint16 in 0..255."""
    t = region.astype(np.uint16)
    t *= keep
    # (t + 1 + (t >> 8)) >> 8 is exactly t // 255 for every t up to 255 * 255.
    t += (t >> 8) + 1
    t >>= 8
    t += add
    np.minimum(t, 255, out=t)
    return t


def _reveal_frame(base, layers: RevealLayers, progress: float) -> Image.Image:
    """One frame of the artwork-tap reveal, in compose space (before
    rotate/BGR). *progress* is strictly between 0 and 1. A fresh copy of
    *base* (never the caller's object) has the inter-band strip's chrome
    laid over it at opacity 1 - progress, so the text fades; then the top
    band's chrome is laid over the top rows shifted round(progress * band
    height) upwards and the bottom band's the same amount downwards, each
    over the artwork already at those rows, so the chrome leaves the
    panel edge while the artwork underneath never moves and shows bare
    where the chrome has gone. Reproduces the ordinary frame at 0 and the
    bare base at 1 to within rounding; the callers short-circuit both
    endpoints to the exact frames anyway.

    The normal path does the whole frame as arithmetic on one array and
    converts back once, touching only the strip rows the chrome changes;
    that keeps the per-frame cost low and, unlike Pillow's chop and blend
    calls, lets other threads run while it works. The bands are
    bit-identical to the Pillow path; the strip fade is exact too, apart
    from possible one-level float rounding differences. If the array path
    fails for any reason, the same frame is built with Pillow instead; this
    never raises for either."""
    arrays = layers.arrays
    if arrays is not None:
        try:
            return _reveal_frame_np(np, base, layers, arrays, progress)
        except Exception:
            _logger.warning("dial display: numpy reveal failed; using Pillow", exc_info=True)
    return _reveal_frame_pillow(base, layers, progress)


def _reveal_frame_np(np, base, layers: RevealLayers, arrays: _RevealArrays, progress: float):
    width, height = layers.strip[2], layers.bottom_band[3]
    src = _new_frame(base, width, height, BG_BASE)
    out = np.array(src, dtype=np.uint8)
    x0, y0, x1, y1 = layers.strip
    if x1 > x0 and y1 > y0 and arrays.strip_runs:
        alpha = np.float32(1.0 - progress)
        for r0, r1 in arrays.strip_runs:
            region = out[y0 + r0:y0 + r1, x0:x1]
            applied = _apply_layer_np(
                np, region, arrays.strip_add[r0:r1], arrays.strip_keep[r0:r1],
            )
            base_f = region.astype(np.float32)
            applied = applied.astype(np.float32)
            applied -= base_f
            applied *= alpha
            applied += base_f
            region[...] = applied.astype(np.uint8)
    x0, y0, x1, y1 = layers.top_band
    band_h = y1 - y0
    dy = round(progress * band_h)
    if dy < band_h:
        region = out[y0:y1 - dy, x0:x1]
        region[...] = _apply_layer_np(
            np, region, arrays.top_add[dy:band_h], arrays.top_keep[dy:band_h],
        )
    x0, y0, x1, y1 = layers.bottom_band
    band_h = y1 - y0
    dy = round(progress * band_h)
    if dy < band_h:
        region = out[y0 + dy:y1, x0:x1]
        region[...] = _apply_layer_np(
            np, region, arrays.bottom_add[:band_h - dy], arrays.bottom_keep[:band_h - dy],
        )
    return Image.fromarray(out, "RGB")


def _reveal_frame_pillow(base, layers: RevealLayers, progress: float) -> Image.Image:
    """_reveal_frame() with Pillow's own chop and blend operations."""
    width, height = layers.strip[2], layers.bottom_band[3]
    out = _new_frame(base, width, height, BG_BASE)
    x0, y0, x1, y1 = layers.strip
    if x1 > x0 and y1 > y0:
        region = out.crop(layers.strip)
        faded = Image.blend(
            region, _apply_layer(region, layers.strip_add, layers.strip_keep), 1.0 - progress,
        )
        out.paste(faded, (x0, y0))
    x0, y0, x1, y1 = layers.top_band
    band_h = y1 - y0
    dy = round(progress * band_h)
    if dy < band_h:
        region = out.crop((x0, y0, x1, y1 - dy))
        chrome = (0, dy, x1 - x0, band_h)
        out.paste(
            _apply_layer(region, layers.top_add.crop(chrome), layers.top_keep.crop(chrome)),
            (x0, y0),
        )
    x0, y0, x1, y1 = layers.bottom_band
    band_h = y1 - y0
    dy = round(progress * band_h)
    if dy < band_h:
        region = out.crop((x0, y0 + dy, x1, y1))
        chrome = (0, 0, x1 - x0, band_h - dy)
        out.paste(
            _apply_layer(region, layers.bottom_add.crop(chrome), layers.bottom_keep.crop(chrome)),
            (x0, y0 + dy),
        )
    return out
