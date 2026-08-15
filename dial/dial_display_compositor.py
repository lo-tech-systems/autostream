"""dial_display_compositor.py — stateless frame composition for the dial
display.

The manager (dial_display.py) owns all I/O: fetching artwork, decoding it,
loading the logo file, deciding what to show and when. This module owns all
pixel work once a base image is in hand — it is the single place a frame is
actually built. It has no threading, no hardware access, no persistent
state, and no lock of its own; every call is independent of every other.

Two kinds of base image reach compose():
  - Artwork: the manager hands over the RAW DECODED image plus the active
    panel (width, height) and sets is_artwork=True. compose() calls
    transform_artwork_for_panel() itself — a "finished frame" is by
    definition already panel-fitted, so that call belongs here rather than
    in the manager.
  - Logo: the manager calls load_logo(...) itself (file I/O, and the
    failure-to-sentinel branch is manager policy) and passes the resulting
    already-panel-sized image with is_artwork=False — compose() then just
    runs it through the transforms below unchanged.

After the base is panel-sized, compose() applies, in order:
  1. overlay — RESERVED for a later change (e.g. a status glyph). The
     parameter exists so callers can start threading it through now, but it
     is INERT this WP: accepted and otherwise ignored, nothing is drawn.
  2. rotate (180 degrees, when configured)
  3. BGR channel swap (when configured)

This is the same rotate-then-BGR logic and ordering that previously lived in
dial_display.py's _apply_frame_transform, moved here unchanged. As before,
this seam is bypassed by the backend-internal clear()/sleep() fills, which
paint directly against the backend rather than going through the manager's
_display_locked()/compose() path. sleep()'s black fill is swap-symmetric so
that is harmless; clear()'s background colour is not — an accepted cosmetic
exception, limited to the fallback background and never artwork.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

from PIL import Image

from dial_display_image import transform_artwork_for_panel


class DialDisplayCompositor:
    """Stateless frame composer — holds no attributes that change between
    calls, so a single instance can safely be shared/reused by the manager.
    """

    def compose(
        self,
        base,
        width: int,
        height: int,
        *,
        rotate: bool,
        bgr: bool,
        is_artwork: bool,
        overlay=None,
    ):
        """Build one display-ready frame from *base*.

        base: either the raw decoded artwork image (is_artwork=True) or an
            already panel-sized base such as the logo or a previously
            fitted/cached artwork frame (is_artwork=False).
        width, height: the active panel dimensions — used to fit artwork;
            ignored when is_artwork=False since the base is assumed already
            sized.
        rotate, bgr: transform toggles applied last, in that order.
        is_artwork: when True, runs transform_artwork_for_panel(base, width,
            height) first so the result is panel-fitted.
        overlay: RESERVED — accepted but never drawn yet; the overlay
            compositing step lands with the touch UI.
        """
        if base is None:
            return base

        image = base
        if is_artwork:
            image = transform_artwork_for_panel(image, width, height)

        # overlay is reserved for a later change; intentionally a no-op here.
        del overlay

        if rotate:
            image = image.transpose(Image.ROTATE_180)
        if bgr:
            image = Image.merge("RGB", image.split()[::-1])
        return image
