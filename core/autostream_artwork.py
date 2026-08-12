"""autostream_artwork.py

Fetching provider (Shazam) artwork URLs, and normalising them into the one
in-memory image contract every downstream consumer relies on.

Two consumers:

  * the dial display, which wants the image bytes to draw on the panel;
  * the OwnTone metadata pipe, which carries artwork as bytes embedded
    directly in a NowPlayingMetadata bundle (see autostream_nowplaying.py) --
    no file on disk changes hands between "an image was fetched" and "a
    receiver saw it".

The fetch itself lives here, once, rather than in each consumer. It faces the
open internet with a URL that arrives from a third-party provider response, so
the eligibility rules and the redirect handling below are a security boundary:
https only, no IP literals, no ``.local``, no odd ports, and every redirect hop
revalidated against the same rules. Two copies of that would drift apart.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse


LOGGER = logging.getLogger(__name__)

MAX_ARTWORK_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_ARTWORK_REDIRECTS = 2
ARTWORK_CONTENT_TYPES = ("image/jpeg", "image/png", "image/webp")

ARTWORK_FETCH_TIMEOUT_SECONDS = 5.0


def _is_ip_literal(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False


def artwork_url_eligible(url: str) -> bool:
    """https-only, DNS hostname, no IP literal, no .local, no explicit non-default port."""
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    if parsed.scheme != "https":
        return False
    hostname = parsed.hostname
    if not hostname:
        return False
    if hostname.endswith(".local"):
        return False
    if _is_ip_literal(hostname):
        return False
    if parsed.port is not None and parsed.port != 443:
        return False
    return True


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fetch_artwork(
    url: str,
    timeout: float,
    max_bytes: int = MAX_ARTWORK_RESPONSE_BYTES,
) -> tuple[Optional[bytes], str]:
    """Fetch one provider artwork URL with explicit, revalidated redirects.

    Returns (data, error). error is "" on success. Redirect targets are
    revalidated against the same eligibility rules; a chain longer than two
    hops is treated as a fetch failure.

    max_bytes lets each caller keep its own ceiling: the dial and the metadata
    pipe do not have the same appetite for a large image.
    """
    opener = urllib.request.build_opener(_NoRedirectHandler)
    current_url = url

    for _ in range(MAX_ARTWORK_REDIRECTS + 1):
        if not artwork_url_eligible(current_url):
            return None, "ineligible_url"

        LOGGER.debug("artwork: fetching %s", current_url)
        req = urllib.request.Request(current_url, headers={"User-Agent": "autostream"})
        try:
            resp = opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            # _NoRedirectHandler.redirect_request() returning None does not
            # stop urllib from raising HTTPError for 3xx responses — it still
            # surfaces as an exception here rather than a plain response, so
            # redirects must be handled in this branch too.
            if 300 <= e.code < 400:
                location = e.headers.get("Location") if e.headers else None
                if not location:
                    return None, "redirect_no_location"
                current_url = urllib.parse.urljoin(current_url, location)
                continue
            return None, f"http_{e.code}"
        except Exception as e:
            return None, type(e).__name__

        try:
            status = getattr(resp, "status", None) or resp.getcode()
            if 300 <= status < 400:
                location = resp.headers.get("Location")
                if not location:
                    return None, "redirect_no_location"
                current_url = urllib.parse.urljoin(current_url, location)
                continue

            if status != 200:
                return None, f"http_{status}"

            content_type = resp.headers.get("Content-Type", "")
            ct_base = content_type.split(";")[0].strip().lower()
            if ct_base not in ARTWORK_CONTENT_TYPES:
                return None, "unsupported_content_type"

            data = resp.read(max_bytes + 1)
            if len(data) > max_bytes:
                return None, "oversized"
            return data, ""
        finally:
            resp.close()

    return None, "too_many_redirects"


# Apple TV silently discards a NowPlayingInfo push whose ArtworkData exceeds
# a cap somewhere in the 59-97KB range (observed on-wire: a 58,951-byte cover
# displays, a 97,447-byte cover in an otherwise byte-identical payload is
# ignored without any error). Re-encode anything bigger than this target so
# every receiver gets a cover it will actually show. 48KB leaves margin under
# the worst-case reading of the cap.
ARTWORK_TARGET_BYTES = 48 * 1024
# Covers are displayed small (lock screen / now-playing tiles); 600px is
# indistinguishable there and keeps the re-encode fast on Pi-class CPUs.
ARTWORK_MAX_EDGE_PX = 600

_resample_unavailable_logged = False


@dataclass(frozen=True)
class ArtworkImage:
    """A complete, normalised, immutable image ready to publish.

    Created in exactly two places: normalise_artwork() below, at fetch time,
    and the bundled placeholder loaded once at startup (autostream_nowplaying
    .py). Nothing downstream ever holds a path or re-reads a file for this --
    the bytes travel with the decision that produced them.
    """

    data: bytes
    mime: str  # "image/jpeg", except the placeholder, which stays PNG.
    ident: str  # 16 lowercase hex chars, a stable content hash of `data`.


def _mime_for(data: bytes) -> Optional[str]:
    """Best-effort image mime type from magic bytes; None if unrecognised.

    The URL is no guide — provider artwork URLs carry size templates and
    query strings — so the format has to come from what the bytes actually
    are.
    """
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


def _content_ident(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def _reencode_to_jpeg(img, original: bytes) -> Optional[bytes]:
    """Re-encode an already-open Pillow image as baseline JPEG, stepping
    quality down (and finally the long edge) until it fits under
    ARTWORK_TARGET_BYTES. If nothing fits (pathological image), the smallest
    attempt is returned rather than nothing. On any encode failure the
    original bytes are returned unchanged: some receivers still show an
    oversized/wrong-format cover, which beats no cover at all.
    """
    try:
        img = img.convert("RGB")
        if max(img.size) > ARTWORK_MAX_EDGE_PX:
            img.thumbnail((ARTWORK_MAX_EDGE_PX, ARTWORK_MAX_EDGE_PX))

        best: Optional[bytes] = None
        for edge, quality in (
            (None, 85), (None, 78), (None, 70), (None, 60),
            (400, 70), (400, 55), (300, 55),
        ):
            candidate = img
            if edge is not None and max(candidate.size) > edge:
                candidate = img.copy()
                candidate.thumbnail((edge, edge))
            import io
            buf = io.BytesIO()
            candidate.save(buf, "JPEG", quality=quality, optimize=True)
            out = buf.getvalue()
            if best is None or len(out) < len(best):
                best = out
            if len(out) <= ARTWORK_TARGET_BYTES:
                LOGGER.info(
                    "artwork: resampled %d -> %d bytes (quality=%d, %dx%d)",
                    len(original), len(out), quality, *candidate.size,
                )
                return out

        # Nothing fit (pathological image); send the smallest attempt anyway.
        LOGGER.warning(
            "artwork: could not fit cover under %d bytes (best %d); sending best effort",
            ARTWORK_TARGET_BYTES, len(best) if best else len(original),
        )
        return best if best is not None else original
    except Exception as e:
        LOGGER.warning("artwork: resample failed (%s); using original bytes", e)
        return original


def normalise_artwork(raw: bytes) -> Optional[ArtworkImage]:
    """Normalise provider artwork bytes into the one size contract every
    downstream consumer can rely on: at most ARTWORK_TARGET_BYTES (48 KB),
    longest edge at most ARTWORK_MAX_EDGE_PX (600 px) -- see the comment on
    ARTWORK_TARGET_BYTES above for why those numbers. Output is always a
    JPEG (bar the one exception: the bundled placeholder, constructed
    separately, stays PNG).

    A JPEG already inside both limits passes through byte-identical -- no
    quality loss, no re-encode churn for the common case. Anything else
    (oversized, over-dimension, a different format, or metadata blocks such
    as Exif/Photoshop APP13 that a re-encode strips as a side effect) goes
    through the re-encode ladder in _reencode_to_jpeg().

    Returns None -- never raises -- if Pillow is unavailable and the input
    isn't already a compliant JPEG, or if the input can't be decoded as an
    image at all. Either way the caller falls back to the placeholder.
    """
    if not raw:
        return None

    try:
        from PIL import Image
    except ImportError:
        mime = _mime_for(raw)
        if mime == "image/jpeg" and len(raw) <= ARTWORK_TARGET_BYTES:
            return ArtworkImage(data=raw, mime=mime, ident=_content_ident(raw))
        global _resample_unavailable_logged
        if not _resample_unavailable_logged:
            _resample_unavailable_logged = True
            LOGGER.warning(
                "artwork: Pillow unavailable; only already-compliant JPEG "
                "covers can be published, everything else falls back to the "
                "placeholder",
            )
        return None

    try:
        import io
        img = Image.open(io.BytesIO(raw))
        img.load()
    except Exception as e:
        LOGGER.info("artwork: undecodable image (%s); no cover will be published", e)
        return None

    if (
        img.format == "JPEG"
        and len(raw) <= ARTWORK_TARGET_BYTES
        and max(img.size) <= ARTWORK_MAX_EDGE_PX
    ):
        return ArtworkImage(data=raw, mime="image/jpeg", ident=_content_ident(raw))

    out = _reencode_to_jpeg(img, raw)
    if not out:
        return None
    mime = _mime_for(out) or "image/jpeg"
    return ArtworkImage(data=out, mime=mime, ident=_content_ident(out))


class ArtworkMemoryCache:
    """Fetches and normalises provider artwork, keyed by URL, entirely in
    memory: no filesystem handoff, no file lifetime for a publisher that
    might still be holding the previous track's bytes to race against.

    A tiny LRU (2 entries) is enough -- tracks change far less often than
    they're republished, and holding the current and previous track's
    normalised image is plenty to survive a same-poll-cycle source_changed
    handoff between two AudioMonitors sharing one FIFO.
    """

    MAX_ENTRIES = 2

    def __init__(
        self,
        max_bytes: int = MAX_ARTWORK_RESPONSE_BYTES,
        timeout: float = ARTWORK_FETCH_TIMEOUT_SECONDS,
    ) -> None:
        self.max_bytes = max_bytes
        self.timeout = timeout
        self._lock = threading.Lock()
        self._entries: "OrderedDict[str, ArtworkImage]" = OrderedDict()

    def get(self, url: str) -> Optional[ArtworkImage]:
        """Return the normalised ArtworkImage for *url*, fetching and
        normalising on a cache miss. Never raises: artwork is decoration,
        and a provider having a bad day must not take playback with it. A
        failed fetch or normalisation returns None WITHOUT evicting whatever
        is already cached for other URLs.
        """
        if not url:
            return None

        with self._lock:
            cached = self._entries.get(url)
            if cached is not None:
                self._entries.move_to_end(url)
                return cached

        data, err = fetch_artwork(url, self.timeout, self.max_bytes)
        if not data:
            LOGGER.info("artwork: not fetching %s (%s)", url, err or "no_data")
            return None

        image = normalise_artwork(data)
        if image is None:
            LOGGER.info("artwork: %s could not be normalised, not caching", url)
            return None

        with self._lock:
            self._entries[url] = image
            self._entries.move_to_end(url)
            while len(self._entries) > self.MAX_ENTRIES:
                self._entries.popitem(last=False)

        LOGGER.info("artwork: cached %d bytes (normalised) from %s", len(image.data), url)
        return image
