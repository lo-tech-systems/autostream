"""The HD page's backdrops: a blurred, darkened copy of the held artwork and
one of the logo, rendered on first request and kept in memory.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
import threading
from pathlib import Path


class BackdropStore:
    """One artwork backdrop, keyed by the artwork's key and replaced when the
    key changes, and one logo backdrop kept for the life of the process. A
    render that fails is remembered as None so the bytes are not decoded
    again. Renders run on the calling thread under the store's own lock, so
    two requests for the same key cost one render and the second waits for
    the first; the lock is never held while anything else is called."""

    def __init__(self, logo_path: Path, *, render_artwork=None, render_logo=None) -> None:
        self._logo_path = logo_path
        self._render_artwork = render_artwork or _render_artwork
        self._render_logo = render_logo or _render_logo
        self._lock = threading.Lock()
        self._artwork: tuple[str, bytes | None] | None = None   # (key, bytes or None)
        self._logo: tuple[bool, bytes | None] = (False, None)    # (rendered, bytes or None)

    def artwork(self, key: str, data: bytes) -> bytes | None:
        """The backdrop for the artwork *data* held under *key*."""
        with self._lock:
            if self._artwork is None or self._artwork[0] != key:
                self._artwork = (key, _guarded(self._render_artwork, data))
            return self._artwork[1]

    def logo(self) -> bytes | None:
        """The backdrop for the logo file."""
        with self._lock:
            if not self._logo[0]:
                self._logo = (True, _guarded(self._render_logo, str(self._logo_path)))
            return self._logo[1]


def _guarded(render, arg) -> bytes | None:
    try:
        return render(arg)
    except Exception:
        logging.debug("hd backdrop: render failed", exc_info=True)
        return None


def _render_artwork(data: bytes) -> bytes | None:
    import dial_display_image
    return dial_display_image.render_artwork_backdrop(data)


def _render_logo(path: str) -> bytes | None:
    import dial_display_image
    return dial_display_image.render_logo_backdrop(path)
