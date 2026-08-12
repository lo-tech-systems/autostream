"""autostream_artwork.py

Fetching provider (Shazam) artwork URLs, and caching them to local files.

Two consumers:

  * the dial display, which wants the image bytes to draw on the panel;
  * the OwnTone metadata pipe, which needs the image as a file on disk, because
    the Shairport-style metadata format carries artwork as embedded bytes read
    from ``NowPlayingMetadata.artwork_path``.

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
import os
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse


LOGGER = logging.getLogger(__name__)

MAX_ARTWORK_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_ARTWORK_REDIRECTS = 2
ARTWORK_CONTENT_TYPES = ("image/jpeg", "image/png", "image/webp")

ARTWORK_FETCH_TIMEOUT_SECONDS = 5.0

DEFAULT_ARTWORK_CACHE_DIR = "/tmp/autostream-artwork"
ARTWORK_CACHE_DIR_ENV = "AUTOSTREAM_ARTWORK_CACHE_DIR"

_CONTENT_TYPE_SUFFIX = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/webp": ".webp",
}


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


def _resample_artwork(data: bytes) -> bytes:
    """Return artwork bytes no larger than ARTWORK_TARGET_BYTES.

    Bytes already within the target pass through untouched. Oversized images
    are re-encoded as progressive-free baseline JPEG, stepping quality down
    (and finally the long edge) until they fit. On any failure -- Pillow not
    installed, undecodable image -- the original bytes are returned: an
    oversized cover that some receivers still show beats no cover at all.
    """
    global _resample_unavailable_logged

    if len(data) <= ARTWORK_TARGET_BYTES:
        return data

    try:
        import io
        from PIL import Image
    except ImportError:
        if not _resample_unavailable_logged:
            _resample_unavailable_logged = True
            LOGGER.warning(
                "artwork: Pillow unavailable; oversized covers (>%d bytes) "
                "will be published as-is and may not display on Apple TV",
                ARTWORK_TARGET_BYTES,
            )
        return data

    try:
        img = Image.open(io.BytesIO(data))
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
            buf = io.BytesIO()
            candidate.save(buf, "JPEG", quality=quality, optimize=True)
            out = buf.getvalue()
            if best is None or len(out) < len(best):
                best = out
            if len(out) <= ARTWORK_TARGET_BYTES:
                LOGGER.info(
                    "artwork: resampled %d -> %d bytes (quality=%d, %dx%d)",
                    len(data), len(out), quality, *candidate.size,
                )
                return out

        # Nothing fit (pathological image); send the smallest attempt anyway.
        LOGGER.warning(
            "artwork: could not fit cover under %d bytes (best %d); sending best effort",
            ARTWORK_TARGET_BYTES, len(best) if best else len(data),
        )
        return best if best is not None else data
    except Exception as e:
        LOGGER.warning("artwork: resample failed (%s); using original bytes", e)
        return data


def _suffix_for(data: bytes) -> str:
    """Suffix from the image's magic bytes.

    The URL is no guide — provider artwork URLs carry size templates and query
    strings — and OwnTone infers the image format from what it is given, so the
    file we write has to be named for what it actually contains.
    """
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if data.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return ".webp"
    return ""


class ArtworkFileCache:
    """Downloads provider artwork to a local file, keyed by URL.

    The OwnTone metadata pipe publishes artwork as bytes read from a path, so a
    URL has to become a file before it can be published. Tracks change far less
    often than they are republished, so we keep the last image on disk and only
    re-fetch when the URL changes.
    """

    def __init__(
        self,
        cache_dir: Optional[str] = None,
        max_bytes: int = MAX_ARTWORK_RESPONSE_BYTES,
        timeout: float = ARTWORK_FETCH_TIMEOUT_SECONDS,
    ) -> None:
        chosen = (
            cache_dir
            or (os.environ.get(ARTWORK_CACHE_DIR_ENV) or "").strip()
            or DEFAULT_ARTWORK_CACHE_DIR
        )
        self.cache_dir = Path(chosen)
        self.max_bytes = max_bytes
        self.timeout = timeout
        self._lock = threading.Lock()
        self._cached_url: str = ""
        self._cached_path: Optional[str] = None

    def get_path(self, url: str) -> Optional[str]:
        """Return a local path holding the image at url, or None if unavailable.

        Never raises: artwork is decoration, and a provider having a bad day
        must not take playback with it.
        """
        if not url:
            return None

        with self._lock:
            if url == self._cached_url and self._cached_path and Path(self._cached_path).exists():
                return self._cached_path

        data, err = fetch_artwork(url, self.timeout, self.max_bytes)
        if not data:
            LOGGER.info("artwork: not caching %s (%s)", url, err or "no_data")
            return None

        suffix = _suffix_for(data)
        if not suffix:
            LOGGER.info("artwork: %s is not a recognised image, not caching", url)
            return None

        # Re-encode oversized covers before they enter the cache, so every
        # consumer downstream (metadata pipe, MRP push) stays under the
        # receiver's silent artwork cap. Re-derive the suffix afterwards: the
        # resample path always emits JPEG.
        data = _resample_artwork(data)
        suffix = _suffix_for(data) or suffix

        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
            path = self.cache_dir / f"artwork-{digest}{suffix}"

            # Write via a temporary file in the same directory and rename, so a
            # reader never sees a half-written image.
            fd, tmp_name = tempfile.mkstemp(dir=str(self.cache_dir), suffix=suffix)
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                os.replace(tmp_name, path)
            except Exception:
                _unlink_quietly(tmp_name)
                raise
        except Exception as e:
            LOGGER.warning("artwork: could not cache %s: %s", url, e)
            return None

        with self._lock:
            previous = self._cached_path
            self._cached_url = url
            self._cached_path = str(path)

        if previous and previous != str(path):
            _unlink_quietly(previous)

        LOGGER.info("artwork: cached %d bytes from %s to %s", len(data), url, path)
        return str(path)


def _unlink_quietly(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass
