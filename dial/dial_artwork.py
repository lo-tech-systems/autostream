"""dial_artwork.py — the artwork download for the dial's screens.

The core fetches the focused appliance's artwork on a short-lived thread of
its own (dial_core); this module holds what that thread calls: the shared
fetcher at the dial's own size ceiling, its URL rule, and the download into
an `Artwork` without decoding it. Failures are logged through a per-key rate
limiter so a broken provider cannot flood the SD card.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import hashlib
import logging
import os
import sys
import time
from typing import Callable

# autostream_logging and autostream_artwork are deployed flat beside the dial
# package; in the repo they live in core/.
try:
    import autostream_logging as log_setup
except ImportError:
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "core")))
    import autostream_logging as log_setup  # noqa: E402
from dial_core_state import Artwork, artwork_key

ARTWORK_FETCH_TIMEOUT_SECONDS = 2.0
# The largest artwork response the dial will take.
MAX_ARTWORK_RESPONSE_BYTES = 2 * 1024 * 1024


class RateLimitedLogger:
    """Emits at most one record per key each LOG_INTERVAL_SECONDS.

    Every key has its own timer, so a different key is visible immediately,
    per the dial logging policy.
    """

    LOG_INTERVAL_SECONDS = 60.0

    def __init__(self, clock: Callable[[], float] | None = None) -> None:
        self._clock = clock

    def log(self, level: int, key: str, msg: str, *args) -> None:
        now = (self._clock or time.monotonic)()
        if log_setup.log_every((key,), self.LOG_INTERVAL_SECONDS, now=now):
            logging.log(level, msg, *args)


def _artwork_module():
    """The shared artwork fetcher. The dial deployment copies core modules
    alongside the dial package; in the repo they live in core/, which may
    or may not be on sys.path."""
    try:
        import autostream_artwork
    except ImportError:
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "core")))
        import autostream_artwork
    return autostream_artwork


def default_fetch_artwork(url: str, timeout: float) -> tuple[bytes | None, str]:
    """Fetch artwork at the dial's own size ceiling: (bytes_or_None, error_text)."""
    return _artwork_module().fetch_artwork(url, timeout, MAX_ARTWORK_RESPONSE_BYTES)


def default_artwork_eligible(url: str) -> bool:
    """Whether *url* may be fetched at all (the shared fetcher's own rule)."""
    return _artwork_module().artwork_url_eligible(url)


def url_log_key(url: str) -> str:
    """Short, non-reversible identifier for a provider URL, safe at INFO/WARNING."""
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]


def fetch_artwork_bytes(
    url: str, log_limiter, *, fetch: Callable,
    timeout: float = ARTWORK_FETCH_TIMEOUT_SECONDS,
    on_error: Callable[[str], None] | None = None,
    now_fn: Callable[[], float] | None = None,
) -> Artwork | None:
    """Download the artwork at *url* without decoding it. *fetch* is called
    as fetch(url, timeout) and returns (bytes_or_None, error_text). A failed
    fetch is reported through *on_error* ("artwork_fetch_failed") and
    logged at WARNING through the rate limiter, and returns None; the
    caller shows the logo and tries again on a later fold."""
    data, err = fetch(url, timeout)
    if err:
        if on_error is not None:
            on_error("artwork_fetch_failed")
        url_key = url_log_key(url)
        log_limiter.log(
            logging.WARNING, f"artwork_fetch:{url_key}",
            "dial display: artwork fetch failed (%s): %s", url_key, err,
        )
        return None
    now_fn = now_fn or time.monotonic
    return Artwork(
        url=url,
        key=artwork_key(url),
        data=data,
        content_type="",
        fetched_at=now_fn(),
    )
