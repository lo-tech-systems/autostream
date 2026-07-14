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
    MAX_ARTWORK_RESPONSE_BYTES,
    ArtworkFileCache,
    artwork_url_eligible,
    fetch_artwork,
)


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
# ArtworkFileCache: turning a provider URL into a file OwnTone can read
# ---------------------------------------------------------------------------

PNG_BYTES = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01"
    b"\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
)
JPEG_BYTES = b"\xff\xd8\xff\xe0" + b"padding"


class TestArtworkFileCache:
    def test_writes_fetched_image_to_a_file(self, tmp_path):
        cache = ArtworkFileCache(cache_dir=str(tmp_path))
        with patch("autostream_artwork.fetch_artwork", return_value=(PNG_BYTES, "")):
            path = cache.get_path("https://provider.example/a.png")

        assert path is not None
        assert Path(path).exists()
        assert Path(path).read_bytes() == PNG_BYTES

    def test_suffix_comes_from_magic_bytes_not_the_url(self, tmp_path):
        # Provider URLs carry size templates and query strings, so the URL
        # extension is not trustworthy; OwnTone infers format from the file.
        cache = ArtworkFileCache(cache_dir=str(tmp_path))
        with patch("autostream_artwork.fetch_artwork", return_value=(JPEG_BYTES, "")):
            path = cache.get_path("https://provider.example/art/600x600bb.png?x=1")

        assert path is not None
        assert path.endswith(".jpg")

    def test_same_url_is_not_refetched(self, tmp_path):
        cache = ArtworkFileCache(cache_dir=str(tmp_path))
        with patch("autostream_artwork.fetch_artwork", return_value=(PNG_BYTES, "")) as m:
            first = cache.get_path("https://provider.example/a.png")
            second = cache.get_path("https://provider.example/a.png")

        assert first == second
        assert m.call_count == 1

    def test_new_url_replaces_and_removes_the_old_file(self, tmp_path):
        cache = ArtworkFileCache(cache_dir=str(tmp_path))
        with patch("autostream_artwork.fetch_artwork", return_value=(PNG_BYTES, "")):
            first = cache.get_path("https://provider.example/a.png")
        with patch("autostream_artwork.fetch_artwork", return_value=(JPEG_BYTES, "")):
            second = cache.get_path("https://provider.example/b.jpg")

        assert first != second
        assert Path(second).exists()
        assert not Path(first).exists()

    def test_refetches_if_cached_file_vanished(self, tmp_path):
        cache = ArtworkFileCache(cache_dir=str(tmp_path))
        with patch("autostream_artwork.fetch_artwork", return_value=(PNG_BYTES, "")) as m:
            path = cache.get_path("https://provider.example/a.png")
            Path(path).unlink()
            again = cache.get_path("https://provider.example/a.png")

        assert again == path
        assert Path(again).exists()
        assert m.call_count == 2

    def test_failed_fetch_returns_none(self, tmp_path):
        cache = ArtworkFileCache(cache_dir=str(tmp_path))
        with patch("autostream_artwork.fetch_artwork", return_value=(None, "http_404")):
            assert cache.get_path("https://provider.example/a.png") is None

    def test_non_image_payload_is_not_cached(self, tmp_path):
        cache = ArtworkFileCache(cache_dir=str(tmp_path))
        with patch("autostream_artwork.fetch_artwork", return_value=(b"<html>nope", "")):
            assert cache.get_path("https://provider.example/a.png") is None

    def test_empty_url_returns_none_without_fetching(self, tmp_path):
        cache = ArtworkFileCache(cache_dir=str(tmp_path))
        with patch("autostream_artwork.fetch_artwork") as m:
            assert cache.get_path("") is None
        m.assert_not_called()

    def test_unwritable_cache_dir_returns_none_rather_than_raising(self, tmp_path):
        # Artwork is decoration; a broken cache must never take playback down.
        cache = ArtworkFileCache(cache_dir=str(tmp_path / "sub"))
        with patch("autostream_artwork.fetch_artwork", return_value=(PNG_BYTES, "")), \
             patch("autostream_artwork.tempfile.mkstemp", side_effect=OSError("nope")):
            assert cache.get_path("https://provider.example/a.png") is None
