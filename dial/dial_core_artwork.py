"""dial_core_artwork.py -- the artwork the core follows.

The fold names a URL, and a short-lived thread fetches it when it is new, so
a slow download never holds the core or a request. The URL is never logged,
and the held artwork carries its key, not its URL.

The follower creates no lock. It takes the core's own lock (reached through
a getter, so a replaced lock is seen) only to read or write `url`, and never
holds it across a publish, a spawn, the fetch or a clear. The mutates it
hands to `publish` already run under the core's lock, which is not
reentrant, so they read `url` without taking it.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import dataclasses
import logging
from typing import Callable

import dial_artwork
from dial_core_state import Artwork, artwork_key


class ArtworkFollower:
    def __init__(
        self,
        *,
        lock: Callable[[], object],
        publish: Callable[[Callable], object],
        held: Callable[[], Artwork | None],
        io: Callable[[], object],
        clock: Callable[[], float],
    ) -> None:
        self._lock_of = lock
        self._publish = publish
        self._held = held
        self._io_of = io
        self._clock = clock
        self.url: str | None = None   # the URL whose artwork is held or being fetched

    def follow(self, url: str | None) -> None:
        """Hold the artwork for *url*: a short-lived thread fetches it when it
        is new, so a slow download never holds the core or a request. With no
        URL the held artwork is released."""
        if not url:
            with self._lock_of():
                self.url = None
            self.clear()
            return
        with self._lock_of():
            if self.url == url:
                return
            self.url = url
        held = self._held()
        if held is not None and held.key == artwork_key(url):
            return
        self.clear()
        self._io_of().spawn(self._fetch, url)

    def clear(self, key: str | None = None) -> None:
        """Release the held artwork bytes: always, or only when they are the
        copy named by *key* (so a view dropping an undecodable image cannot
        discard a newer track's). A copy dropped by its key is fetched again
        at the next fold, so a truncated transfer heals."""
        if key is not None:
            with self._lock_of():
                if self.url is not None and artwork_key(self.url) == key:
                    self.url = None

        def mutate(state) -> "bool | None":
            held = state.artwork
            if held is None or (key is not None and held.key != key):
                return False
            state.artwork = None
        self._publish(mutate)

    def _fetch(self, url: str) -> None:
        """Fetch the artwork for *url* and hold it, unless the URL is no
        longer the one followed by then. A failed fetch is asked for again by
        a later fold; a URL that may not be fetched is not."""
        io = self._io_of()
        art = None
        try:
            if not io.artwork_eligible(url):
                logging.debug("dial display: unsupported artwork url candidate")
                return
            art = dial_artwork.fetch_artwork_bytes(
                url, io.log_limiter, fetch=io.fetch_artwork,
                timeout=dial_artwork.ARTWORK_FETCH_TIMEOUT_SECONDS,
                on_error=io.on_artwork_error, now_fn=self._clock,
            )
        except Exception:
            logging.debug("dial core: artwork fetch raised", exc_info=True)
        if art is None:
            with self._lock_of():
                if self.url == url:
                    self.url = None
            return
        art = dataclasses.replace(art, url="")

        def mutate(state) -> "bool | None":
            if self.url != url:
                return False
            state.artwork = art
        self._publish(mutate)
