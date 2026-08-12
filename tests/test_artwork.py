"""Tests for core/autostream_artwork.py.

The URL eligibility and fetch tests were moved here from test_dial_display.py
when the fetch was extracted out of the dial to be shared with the OwnTone
metadata publisher. They guard a security boundary — a provider-supplied URL
fetched from the open internet — so they moved with the code rather than being
left behind pointing at a re-export.
"""

from __future__ import annotations

import sys
import urllib.error
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

from autostream_artwork import (
    ARTWORK_MAX_EDGE_PX,
    ARTWORK_TARGET_BYTES,
    MAX_ARTWORK_RESPONSE_BYTES,
    ArtworkImage,
    ArtworkMemoryCache,
    artwork_url_eligible,
    fetch_artwork,
    normalise_artwork,
)

try:
    from PIL import Image
except ImportError:  # pragma: no cover -- exercised only when Pillow is absent
    Image = None


# ---------------------------------------------------------------------------
# Provider artwork URL eligibility
# ---------------------------------------------------------------------------

class TestArtworkUrlEligibility:
    def test_https_dns_hostname_default_port_eligible(self):
        assert artwork_url_eligible("https://provider.example/a.jpg") is True

    def test_http_scheme_rejected(self):
        assert artwork_url_eligible("http://provider.example/a.jpg") is False

    def test_ipv4_literal_rejected(self):
        assert artwork_url_eligible("https://93.184.216.34/a.jpg") is False

    def test_ipv6_literal_rejected(self):
        assert artwork_url_eligible("https://[2001:db8::1]/a.jpg") is False

    def test_dot_local_hostname_rejected(self):
        assert artwork_url_eligible("https://box.local/a.jpg") is False

    def test_explicit_non_default_port_rejected(self):
        assert artwork_url_eligible("https://provider.example:8443/a.jpg") is False

    def test_explicit_default_port_443_accepted(self):
        assert artwork_url_eligible("https://provider.example:443/a.jpg") is True

    def test_malformed_url_rejected(self):
        assert artwork_url_eligible("not a url") is False


# ---------------------------------------------------------------------------
# Artwork fetch (redirect handling, size, content-type)
# ---------------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, status: int, headers: dict | None = None, body: bytes = b""):
        self.status = status
        self.headers = headers or {}
        self._body = body

    def read(self, n=-1):
        return self._body if n is None or n < 0 else self._body[:n]

    def close(self):
        pass

    def getcode(self):
        return self.status


class _FakeOpener:
    def __init__(self, responses):
        self._responses = list(responses)
        self.requested_urls: list[str] = []

    def open(self, req, timeout=None):
        self.requested_urls.append(req.full_url)
        resp = self._responses.pop(0)
        if isinstance(resp, Exception):
            raise resp
        return resp


class TestFetchArtwork:
    def test_success(self):
        resp = _FakeResponse(200, {"Content-Type": "image/jpeg"}, b"data")
        opener = _FakeOpener([resp])
        with patch("autostream_artwork.urllib.request.build_opener", return_value=opener):
            data, err = fetch_artwork("https://provider.example/a.jpg", 2.0)
        assert err == ""
        assert data == b"data"

    def test_ineligible_initial_url_rejected_without_request(self):
        opener = _FakeOpener([])
        with patch("autostream_artwork.urllib.request.build_opener", return_value=opener):
            data, err = fetch_artwork("http://provider.example/a.jpg", 2.0)
        assert data is None
        assert err == "ineligible_url"
        assert opener.requested_urls == []

    def test_follows_one_redirect(self):
        redirect = _FakeResponse(302, {"Location": "https://provider.example/final.jpg"})
        final = _FakeResponse(200, {"Content-Type": "image/png"}, b"final-data")
        opener = _FakeOpener([redirect, final])
        with patch("autostream_artwork.urllib.request.build_opener", return_value=opener):
            data, err = fetch_artwork("https://provider.example/start.jpg", 2.0)
        assert err == ""
        assert data == b"final-data"
        assert len(opener.requested_urls) == 2

    def test_rejects_redirect_to_ineligible_target(self):
        redirect = _FakeResponse(302, {"Location": "http://provider.example/final.jpg"})
        opener = _FakeOpener([redirect])
        with patch("autostream_artwork.urllib.request.build_opener", return_value=opener):
            data, err = fetch_artwork("https://provider.example/start.jpg", 2.0)
        assert data is None
        assert err == "ineligible_url"

    def test_rejects_more_than_two_redirects(self):
        redirects = [
            _FakeResponse(302, {"Location": f"https://provider.example/hop{i}.jpg"})
            for i in range(3)
        ]
        opener = _FakeOpener(redirects)
        with patch("autostream_artwork.urllib.request.build_opener", return_value=opener):
            data, err = fetch_artwork("https://provider.example/start.jpg", 2.0)
        assert data is None
        assert err == "too_many_redirects"

    def test_rejects_oversized_body(self):
        oversized = b"x" * (MAX_ARTWORK_RESPONSE_BYTES + 1)
        resp = _FakeResponse(200, {"Content-Type": "image/jpeg"}, oversized)
        opener = _FakeOpener([resp])
        with patch("autostream_artwork.urllib.request.build_opener", return_value=opener):
            data, err = fetch_artwork("https://provider.example/a.jpg", 2.0)
        assert data is None
        assert err == "oversized"

    def test_rejects_unsupported_content_type(self):
        resp = _FakeResponse(200, {"Content-Type": "text/html"}, b"<html>")
        opener = _FakeOpener([resp])
        with patch("autostream_artwork.urllib.request.build_opener", return_value=opener):
            data, err = fetch_artwork("https://provider.example/a.jpg", 2.0)
        assert data is None
        assert err == "unsupported_content_type"

    def test_content_type_with_params_accepted(self):
        resp = _FakeResponse(200, {"Content-Type": "image/jpeg; charset=binary"}, b"data")
        opener = _FakeOpener([resp])
        with patch("autostream_artwork.urllib.request.build_opener", return_value=opener):
            data, err = fetch_artwork("https://provider.example/a.jpg", 2.0)
        assert err == ""

    def test_http_error_reported(self):
        opener = _FakeOpener([urllib.error.HTTPError("url", 404, "not found", {}, None)])
        with patch("autostream_artwork.urllib.request.build_opener", return_value=opener):
            data, err = fetch_artwork("https://provider.example/a.jpg", 2.0)
        assert data is None
        assert err == "http_404"

    def test_redirect_raised_as_http_error_is_followed(self):
        """Regression: with the no-redirect handler, urllib raises HTTPError
        for 3xx responses rather than returning them — this must still be
        followed as a redirect, not treated as a terminal failure."""
        redirect_exc = urllib.error.HTTPError(
            "https://provider.example/start.jpg", 302, "Found",
            {"Location": "https://provider.example/final.jpg"}, None,
        )
        final = _FakeResponse(200, {"Content-Type": "image/jpeg"}, b"final-data")
        opener = _FakeOpener([redirect_exc, final])
        with patch("autostream_artwork.urllib.request.build_opener", return_value=opener):
            data, err = fetch_artwork("https://provider.example/start.jpg", 2.0)
        assert err == ""
        assert data == b"final-data"
        assert opener.requested_urls == [
            "https://provider.example/start.jpg",
            "https://provider.example/final.jpg",
        ]

    def test_redirect_raised_as_http_error_rejects_ineligible_target(self):
        redirect_exc = urllib.error.HTTPError(
            "https://provider.example/start.jpg", 302, "Found",
            {"Location": "http://provider.example/final.jpg"}, None,
        )
        opener = _FakeOpener([redirect_exc])
        with patch("autostream_artwork.urllib.request.build_opener", return_value=opener):
            data, err = fetch_artwork("https://provider.example/start.jpg", 2.0)
        assert data is None
        assert err == "ineligible_url"

    def test_redirect_raised_as_http_error_without_location_is_failure(self):
        redirect_exc = urllib.error.HTTPError(
            "https://provider.example/start.jpg", 302, "Found", {}, None,
        )
        opener = _FakeOpener([redirect_exc])
        with patch("autostream_artwork.urllib.request.build_opener", return_value=opener):
            data, err = fetch_artwork("https://provider.example/start.jpg", 2.0)
        assert data is None
        assert err == "redirect_no_location"

    def test_redirect_raised_as_http_error_chain_exceeds_max(self):
        def _redirect_exc(n):
            return urllib.error.HTTPError(
                f"https://provider.example/hop{n - 1}.jpg", 302, "Found",
                {"Location": f"https://provider.example/hop{n}.jpg"}, None,
            )

        opener = _FakeOpener([_redirect_exc(i) for i in range(3)])
        with patch("autostream_artwork.urllib.request.build_opener", return_value=opener):
            data, err = fetch_artwork("https://provider.example/start.jpg", 2.0)
        assert data is None
        assert err == "too_many_redirects"

    def test_relative_redirect_location_resolved_against_current_url(self):
        redirect = _FakeResponse(302, {"Location": "/final.jpg"})
        final = _FakeResponse(200, {"Content-Type": "image/jpeg"}, b"data")
        opener = _FakeOpener([redirect, final])
        with patch("autostream_artwork.urllib.request.build_opener", return_value=opener):
            data, err = fetch_artwork("https://provider.example/start.jpg", 2.0)
        assert err == ""
        assert opener.requested_urls[1] == "https://provider.example/final.jpg"


# ---------------------------------------------------------------------------
# Test image fixtures -- generated in-process, never committed as binaries.
# ---------------------------------------------------------------------------

PNG_BYTES = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01"
    b"\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
)
# A minimal but truly undecodable "JPEG": right magic bytes, no valid stream
# after them, so Pillow's Image.open()/.load() rejects it.
UNDECODABLE_JPEG_BYTES = b"\xff\xd8\xff\xe0" + b"not a real jpeg stream"


def _make_jpeg(size=(64, 64), color=(120, 60, 200), quality=85, **save_kwargs) -> bytes:
    """A small, valid, compliant JPEG -- well under both the size and
    dimension contract by construction."""
    import io
    img = Image.new("RGB", size, color)
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=quality, **save_kwargs)
    return buf.getvalue()


def _make_png(size=(64, 64), color=(10, 200, 90)) -> bytes:
    import io
    img = Image.new("RGB", size, color)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def _make_oversized_noisy_jpeg(min_bytes=90 * 1024) -> bytes:
    """A large, high-entropy JPEG that resists compression -- the observed
    real-world failure class (issue: covers over ~90KB the receiver
    silently discards). Random noise, unlike a photo, won't compress down
    on its own, so this reliably exceeds min_bytes at quality=100 without
    needing a giant canvas."""
    import io
    import random
    rng = random.Random(1234)
    size = (900, 900)
    img = Image.new("RGB", size)
    pixels = bytes(rng.getrandbits(8) for _ in range(size[0] * size[1] * 3))
    img.frombytes(pixels)
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=100)
    data = buf.getvalue()
    assert len(data) > min_bytes, f"fixture too small ({len(data)} bytes); adjust canvas size"
    return data


requires_pillow = pytest.mark.skipif(Image is None, reason="Pillow not installed")


# ---------------------------------------------------------------------------
# normalise_artwork() / ArtworkImage -- the size/dimension contract (§A1)
# ---------------------------------------------------------------------------

@requires_pillow
class TestNormaliseArtwork:
    def test_compliant_jpeg_passes_through_byte_identical(self):
        data = _make_jpeg()
        image = normalise_artwork(data)
        assert image is not None
        assert image.data == data
        assert image.mime == "image/jpeg"

    def test_oversized_jpeg_reencoded_under_cap(self):
        data = _make_oversized_noisy_jpeg()
        image = normalise_artwork(data)
        assert image is not None
        assert len(image.data) <= ARTWORK_TARGET_BYTES
        assert image.mime == "image/jpeg"
        out = Image.open(__import__("io").BytesIO(image.data))
        assert max(out.size) <= ARTWORK_MAX_EDGE_PX

    def test_undecodable_image_returns_none(self):
        assert normalise_artwork(UNDECODABLE_JPEG_BYTES) is None

    def test_empty_bytes_returns_none(self):
        assert normalise_artwork(b"") is None

    def test_dimension_cap_enforced_even_when_small_in_bytes(self):
        # A solid-colour JPEG compresses extremely well, so it can be tiny
        # in bytes while still being oversized in pixels -- the byte-size
        # check alone would wrongly pass this through.
        data = _make_jpeg(size=(1200, 1200), color=(80, 80, 80), quality=40)
        assert len(data) <= ARTWORK_TARGET_BYTES  # confirms the fixture's premise
        image = normalise_artwork(data)
        assert image is not None
        out = Image.open(__import__("io").BytesIO(image.data))
        assert max(out.size) <= ARTWORK_MAX_EDGE_PX

    def test_png_input_converted_to_jpeg(self):
        data = _make_png()
        image = normalise_artwork(data)
        assert image is not None
        assert image.mime == "image/jpeg"
        assert image.data[:3] == b"\xff\xd8\xff"

    def test_metadata_blocks_stripped_by_reencode(self):
        # Force a re-encode (oversized) with an embedded Exif block, so the
        # metadata-stripping side effect of re-saving through Pillow (which
        # never carries the original exif/Photoshop APP13 segments forward
        # unless explicitly asked to) is actually exercised.
        import io
        import random
        exif = Image.Exif()
        exif[0x0131] = "some-internal-encoder-string"  # Software tag
        rng = random.Random(99)
        size = (900, 900)
        img = Image.new("RGB", size)
        img.frombytes(bytes(rng.getrandbits(8) for _ in range(size[0] * size[1] * 3)))
        buf = io.BytesIO()
        img.save(buf, "JPEG", quality=100, exif=exif)
        data = buf.getvalue()
        assert len(data) > ARTWORK_TARGET_BYTES  # confirms the fixture forces a re-encode
        assert Image.open(io.BytesIO(data)).getexif()  # confirms exif made it into the source

        image = normalise_artwork(data)
        assert image is not None
        reopened = Image.open(io.BytesIO(image.data))
        assert not reopened.getexif()

    def test_identifier_is_16_lowercase_hex_chars(self):
        image = normalise_artwork(_make_jpeg())
        assert image is not None
        assert len(image.ident) == 16
        assert image.ident == image.ident.lower()
        int(image.ident, 16)  # raises if not hex

    def test_identifier_stable_for_identical_bytes(self):
        data = _make_jpeg()
        first = normalise_artwork(data)
        second = normalise_artwork(data)
        assert first.ident == second.ident

    def test_identifier_differs_for_different_images(self):
        first = normalise_artwork(_make_jpeg(color=(1, 2, 3)))
        second = normalise_artwork(_make_jpeg(color=(250, 240, 230)))
        assert first.ident != second.ident

    def test_pillow_unavailable_passes_through_compliant_jpeg(self):
        data = _make_jpeg()
        with patch.dict("sys.modules", {"PIL": None}):
            image = normalise_artwork(data)
        assert image is not None
        assert image.data == data
        assert image.mime == "image/jpeg"

    def test_pillow_unavailable_returns_none_for_oversized(self):
        data = _make_oversized_noisy_jpeg()
        with patch.dict("sys.modules", {"PIL": None}):
            image = normalise_artwork(data)
        assert image is None


# ---------------------------------------------------------------------------
# ArtworkMemoryCache: fetch + normalise, keyed by URL, in memory only
# ---------------------------------------------------------------------------

@requires_pillow
class TestArtworkMemoryCache:
    def test_returns_normalised_image_on_fetch(self):
        cache = ArtworkMemoryCache()
        data = _make_jpeg()
        with patch("autostream_artwork.fetch_artwork", return_value=(data, "")):
            image = cache.get("https://provider.example/a.jpg")

        assert isinstance(image, ArtworkImage)
        assert image.data == data

    def test_same_url_is_not_refetched(self):
        cache = ArtworkMemoryCache()
        data = _make_jpeg()
        with patch("autostream_artwork.fetch_artwork", return_value=(data, "")) as m:
            first = cache.get("https://provider.example/a.jpg")
            second = cache.get("https://provider.example/a.jpg")

        assert first is second
        assert m.call_count == 1

    def test_failed_fetch_returns_none(self):
        cache = ArtworkMemoryCache()
        with patch("autostream_artwork.fetch_artwork", return_value=(None, "http_404")):
            assert cache.get("https://provider.example/a.jpg") is None

    def test_failed_fetch_does_not_evict_other_cached_entries(self):
        cache = ArtworkMemoryCache()
        data = _make_jpeg()
        with patch("autostream_artwork.fetch_artwork", return_value=(data, "")):
            cache.get("https://provider.example/a.jpg")
        with patch("autostream_artwork.fetch_artwork", return_value=(None, "http_404")):
            assert cache.get("https://provider.example/b.jpg") is None
        with patch("autostream_artwork.fetch_artwork") as m:
            again = cache.get("https://provider.example/a.jpg")
        assert again is not None
        m.assert_not_called()

    def test_undecodable_payload_is_not_cached(self):
        cache = ArtworkMemoryCache()
        with patch("autostream_artwork.fetch_artwork", return_value=(b"<html>nope", "")):
            assert cache.get("https://provider.example/a.jpg") is None

    def test_empty_url_returns_none_without_fetching(self):
        cache = ArtworkMemoryCache()
        with patch("autostream_artwork.fetch_artwork") as m:
            assert cache.get("") is None
        m.assert_not_called()

    def test_lru_evicts_oldest_beyond_two_entries(self):
        cache = ArtworkMemoryCache()
        urls = [f"https://provider.example/{i}.jpg" for i in range(3)]
        images = [_make_jpeg(color=(i * 40, i * 20, i * 10)) for i in range(3)]

        for url, data in zip(urls, images):
            with patch("autostream_artwork.fetch_artwork", return_value=(data, "")):
                cache.get(url)

        # First URL was evicted when the third was added; refetching it
        # must hit the network again.
        with patch("autostream_artwork.fetch_artwork", return_value=(images[0], "")) as m:
            cache.get(urls[0])
        m.assert_called_once()

        # The second and third URLs are still cached (most recently used).
        with patch("autostream_artwork.fetch_artwork") as m:
            cache.get(urls[2])
        m.assert_not_called()

    def test_getting_a_cached_entry_refreshes_its_lru_position(self):
        cache = ArtworkMemoryCache()
        url_a, url_b, url_c = (f"https://provider.example/{c}.jpg" for c in "abc")
        data_a, data_b, data_c = (_make_jpeg(color=(i, i, i)) for i in (10, 20, 30))

        with patch("autostream_artwork.fetch_artwork", return_value=(data_a, "")):
            cache.get(url_a)
        with patch("autostream_artwork.fetch_artwork", return_value=(data_b, "")):
            cache.get(url_b)
        # Touch "a" again so "b" becomes the least-recently-used entry.
        with patch("autostream_artwork.fetch_artwork") as m:
            cache.get(url_a)
        m.assert_not_called()
        with patch("autostream_artwork.fetch_artwork", return_value=(data_c, "")):
            cache.get(url_c)

        # "b" should have been evicted, not "a".
        with patch("autostream_artwork.fetch_artwork") as m:
            cache.get(url_a)
        m.assert_not_called()
        with patch("autostream_artwork.fetch_artwork", return_value=(data_b, "")) as m:
            cache.get(url_b)
        m.assert_called_once()
