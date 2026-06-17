"""Tests for track_id.acoustid_musicbrainz — AcoustID/MusicBrainz provider.

All network and fingerprinting calls are mocked. No external services are called.
"""
from __future__ import annotations

import io
import json
import logging
import sys
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import track_id.acoustid_musicbrainz as amz
from track_id.acoustid_musicbrainz import (
    AcoustIDMusicBrainzProvider,
    _compute_duration,
    _fingerprint_raw_pcm,
    _pcm_to_wav,
    _acoustid_lookup,
    _best_recording,
    _enrich_from_musicbrainz,
    _extract_recording_info,
    _resolve_artwork,
    _caa_thumbnail_url,
    PROVIDER_ID,
)
from track_id.models import TrackIdentificationResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SAMPLE_RATE = 22050
_SAMPLE_PCM = b"\x00\x01" * (_SAMPLE_RATE * 10)  # 10 seconds of silent PCM


def _make_provider(api_key: str = "testkey") -> AcoustIDMusicBrainzProvider:
    return AcoustIDMusicBrainzProvider({"api_key": api_key})


def _mock_acoustid(fp_result=("fp_abc",), lookup_results=None):
    """Return a mock acoustid module."""
    mod = MagicMock()
    mod.fingerprint.return_value = fp_result
    mod.fingerprint_file.return_value = fp_result
    if lookup_results is not None:
        mod.lookup.return_value = lookup_results
    return mod


def _acoustid_response(results: list) -> dict:
    return {"status": "ok", "results": results}


def _recording_entry(
    score=0.9,
    rec_id="rec-1",
    title="Song Title",
    artists=None,
    releases=None,
) -> dict:
    return {
        "score": score,
        "recordings": [{
            "id": rec_id,
            "title": title,
            "artists": artists or [{"name": "Artist Name"}],
            "releases": releases or [{
                "id": "rel-1",
                "title": "Album Title",
                "releasegroups": [{"id": "rg-1"}],
            }],
        }],
    }


# ---------------------------------------------------------------------------
# Duration calculation
# ---------------------------------------------------------------------------

class TestComputeDuration:

    def test_10_seconds(self):
        pcm = b"\x00" * (22050 * 10 * 2)
        assert abs(_compute_duration(pcm, 22050) - 10.0) < 0.01

    def test_empty_pcm(self):
        assert _compute_duration(b"", 22050) == 0.0


# ---------------------------------------------------------------------------
# WAV wrapping
# ---------------------------------------------------------------------------

class TestPcmToWav:

    def test_wav_header_magic(self):
        wav = _pcm_to_wav(b"\x00" * 100, 22050)
        assert wav[:4] == b"RIFF"
        assert wav[8:12] == b"WAVE"
        assert wav[12:16] == b"fmt "

    def test_wav_length_correct(self):
        pcm = b"\x00" * 1000
        wav = _pcm_to_wav(pcm, 22050)
        assert len(wav) == 44 + 1000


# ---------------------------------------------------------------------------
# Missing API key
# ---------------------------------------------------------------------------

class TestMissingApiKey:

    def test_no_key_returns_not_found_without_fingerprinting(self):
        provider = _make_provider(api_key="")
        with patch.object(amz, "_fingerprint_raw_pcm") as mock_fp:
            result = provider.identify(_SAMPLE_PCM, _SAMPLE_RATE)
        assert result.matched is False
        assert result.source_detail == "no_api_key"
        mock_fp.assert_not_called()

    def test_no_key_logs_warning(self, caplog):
        provider = _make_provider(api_key="")
        with caplog.at_level(logging.WARNING):
            provider.identify(_SAMPLE_PCM, _SAMPLE_RATE)
        assert any("api key" in r.message.lower() or "key" in r.message.lower()
                   for r in caplog.records)


# ---------------------------------------------------------------------------
# Fingerprinting
# ---------------------------------------------------------------------------

class TestFingerprintRawPcm:

    def test_fingerprint_called_with_correct_params(self):
        # 2-tuple (duration, fingerprint) is the common pyacoustid return shape.
        mock_mod = _mock_acoustid(fp_result=(10.0, "fingerprint_data"))
        with patch.dict("sys.modules", {"acoustid": mock_mod}):
            dur, fp = _fingerprint_raw_pcm(_SAMPLE_PCM, _SAMPLE_RATE)
        mock_mod.fingerprint.assert_called_once_with(_SAMPLE_RATE, 1, [_SAMPLE_PCM])
        assert fp == "fingerprint_data"

    def test_tuple_result_unpacked(self):
        mock_mod = _mock_acoustid(fp_result=(10.0, "fp_string"))
        with patch.dict("sys.modules", {"acoustid": mock_mod}):
            dur, fp = _fingerprint_raw_pcm(_SAMPLE_PCM, _SAMPLE_RATE)
        assert fp == "fp_string"
        assert dur == 10.0

    def test_raw_failure_falls_back_to_wav(self):
        mock_mod = MagicMock()
        mock_mod.fingerprint.side_effect = RuntimeError("raw failed")
        mock_mod.fingerprint_file.return_value = (10.0, "fp_via_wav")
        with patch.dict("sys.modules", {"acoustid": mock_mod}):
            dur, fp = _fingerprint_raw_pcm(_SAMPLE_PCM, _SAMPLE_RATE)
        assert fp == "fp_via_wav"


# ---------------------------------------------------------------------------
# AcoustID lookup
# ---------------------------------------------------------------------------

class TestAcoustIDLookup:

    def _run(self, response: dict, timeout: float = 10.0):
        body = json.dumps(response).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = body
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("track_id.acoustid_musicbrainz.urllib.request.urlopen",
                   return_value=mock_resp):
            return _acoustid_lookup("fp_abc", 10.0, "testkey", timeout)

    def test_no_results_returns_empty(self):
        result = self._run({"status": "ok", "results": []})
        assert result == []

    def test_results_returned(self):
        result = self._run(_acoustid_response([_recording_entry()]))
        assert len(result) == 1

    def test_api_key_not_in_url_logged(self, caplog):
        body = json.dumps({"status": "ok", "results": []}).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = body
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        with caplog.at_level(logging.DEBUG):
            with patch("track_id.acoustid_musicbrainz.urllib.request.urlopen",
                       return_value=mock_resp):
                _acoustid_lookup("fp_abc", 10.0, "MY_SECRET_KEY", 10.0)
        assert "MY_SECRET_KEY" not in caplog.text

    def test_error_status_raises(self):
        with pytest.raises(RuntimeError):
            self._run({"status": "error", "error": {"message": "bad request"}})

    def test_http_error_raises(self):
        with patch("track_id.acoustid_musicbrainz.urllib.request.urlopen",
                   side_effect=urllib.error.HTTPError(None, 500, "err", {}, None)):
            with pytest.raises(RuntimeError, match="500"):
                _acoustid_lookup("fp", 10.0, "key", 10.0)


# ---------------------------------------------------------------------------
# Best recording selection
# ---------------------------------------------------------------------------

class TestBestRecording:

    def test_none_for_empty(self):
        assert _best_recording([]) is None

    def test_highest_score_wins(self):
        results = [
            {"score": 0.5, "recordings": [{"id": "low"}]},
            {"score": 0.9, "recordings": [{"id": "high"}]},
        ]
        rec = _best_recording(results)
        assert rec["id"] == "high"
        assert rec["_acoustid_score"] == 0.9

    def test_entry_without_recordings_skipped(self):
        results = [
            {"score": 0.9, "recordings": []},
            {"score": 0.5, "recordings": [{"id": "only"}]},
        ]
        rec = _best_recording(results)
        assert rec["id"] == "only"


# ---------------------------------------------------------------------------
# Extract recording info
# ---------------------------------------------------------------------------

class TestExtractRecordingInfo:

    def test_basic_extraction(self):
        entry = {
            "id": "rec-1",
            "title": "Song",
            "artists": [{"name": "Artist"}],
            "releases": [{"id": "rel-1", "title": "Album", "releasegroups": [{"id": "rg-1"}]}],
        }
        info = _extract_recording_info(entry)
        assert info["title"] == "Song"
        assert info["artist"] == "Artist"
        assert info["album"] == "Album"
        assert info["release_id"] == "rel-1"
        assert info["release_group_id"] == "rg-1"

    def test_missing_fields_return_empty_string(self):
        entry = {"id": "rec-1"}
        info = _extract_recording_info(entry)
        assert info["title"] == ""
        assert info["artist"] == ""
        assert info["release_id"] == ""


# ---------------------------------------------------------------------------
# MusicBrainz enrichment (mocked)
# ---------------------------------------------------------------------------

class TestMusicBrainzEnrichment:

    def _mb_response(self) -> dict:
        return {
            "title": "MB Song",
            "artist-credit": [{"name": "MB Artist", "joinphrase": ""}],
            "releases": [{
                "id": "mb-rel-1",
                "title": "MB Album",
                "release-group": {"id": "mb-rg-1"},
            }],
        }

    def test_enrichment_fills_title_artist(self):
        body = json.dumps(self._mb_response()).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = body
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("track_id.acoustid_musicbrainz.urllib.request.urlopen",
                   return_value=mock_resp):
            info = _enrich_from_musicbrainz("rec-1", 10.0)
        assert info["title"] == "MB Song"
        assert info["artist"] == "MB Artist"
        assert info["release_id"] == "mb-rel-1"


# ---------------------------------------------------------------------------
# Cover Art Archive (mocked)
# ---------------------------------------------------------------------------

class TestCoverArtArchive:

    def _mock_head_ok(self, final_url: str):
        mock_resp = MagicMock()
        mock_resp.url = final_url
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        return mock_resp

    def test_release_front_thumbnail_returned(self):
        with patch("track_id.acoustid_musicbrainz.urllib.request.urlopen",
                   return_value=self._mock_head_ok("https://caa.example.com/img.jpg")):
            url = _caa_thumbnail_url("rel-1", "rg-1", 10.0)
        assert url == "https://caa.example.com/img.jpg"

    def test_404_on_release_tries_release_group(self):
        responses = [
            urllib.error.HTTPError(None, 404, "not found", {}, None),
            self._mock_head_ok("https://caa.example.com/rg.jpg"),
        ]
        with patch("track_id.acoustid_musicbrainz.urllib.request.urlopen",
                   side_effect=responses):
            url = _caa_thumbnail_url("rel-1", "rg-1", 10.0)
        assert url == "https://caa.example.com/rg.jpg"

    def test_both_404_returns_empty(self):
        with patch("track_id.acoustid_musicbrainz.urllib.request.urlopen",
                   side_effect=urllib.error.HTTPError(None, 404, "nf", {}, None)):
            url = _caa_thumbnail_url("rel-1", "rg-1", 10.0)
        assert url == ""

    def test_no_ids_returns_empty(self):
        url = _caa_thumbnail_url("", "", 10.0)
        assert url == ""


# ---------------------------------------------------------------------------
# Full provider end-to-end (mocked)
# ---------------------------------------------------------------------------

class TestAcoustIDMusicBrainzProviderEndToEnd:

    _SENTINEL = object()

    def _run_with_mocks(
        self,
        *,
        fingerprint_result=(10.0, "fp_str"),
        acoustid_results=_SENTINEL,
        mb_response=None,
        caa_url="",
    ) -> TrackIdentificationResult:
        provider = _make_provider()
        mock_acoustid = MagicMock()
        mock_acoustid.fingerprint.return_value = fingerprint_result

        if acoustid_results is self._SENTINEL:
            acoustid_results = [_recording_entry()]

        def fake_urlopen(req, timeout=None):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            if "acoustid" in url:
                body = json.dumps(_acoustid_response(acoustid_results)).encode()
            elif "musicbrainz" in url:
                body = json.dumps(mb_response or {}).encode()
            elif "coverartarchive" in url:
                if caa_url:
                    mock_resp = MagicMock()
                    mock_resp.url = caa_url
                    mock_resp.__enter__ = lambda s: s
                    mock_resp.__exit__ = MagicMock(return_value=False)
                    return mock_resp
                raise urllib.error.HTTPError(None, 404, "nf", {}, None)
            else:
                body = b"{}"
            mock_resp = MagicMock()
            mock_resp.read.return_value = body
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            return mock_resp

        with (
            patch.dict("sys.modules", {"acoustid": mock_acoustid}),
            patch("track_id.acoustid_musicbrainz.urllib.request.urlopen", side_effect=fake_urlopen),
        ):
            return provider.identify(_SAMPLE_PCM, _SAMPLE_RATE)

    def test_full_match_returns_identified(self):
        result = self._run_with_mocks()
        assert result.matched is True
        assert result.title == "Song Title"
        assert result.artist == "Artist Name"
        assert result.provider == PROVIDER_ID

    def test_no_acoustid_results_returns_not_found(self):
        result = self._run_with_mocks(acoustid_results=[])
        assert result.matched is False

    def test_artwork_url_populated_when_caa_returns(self):
        result = self._run_with_mocks(caa_url="https://caa.example.com/art.jpg")
        assert result.artwork is not None
        assert result.artwork.url == "https://caa.example.com/art.jpg"

    def test_no_artwork_when_caa_404(self):
        result = self._run_with_mocks(caa_url="")
        assert result.artwork is None

    def test_confidence_from_score(self):
        result = self._run_with_mocks()
        assert result.confidence == pytest.approx(0.9)

    def test_musicbrainz_external_id_included(self):
        result = self._run_with_mocks()
        assert "musicbrainz_recording" in result.external_ids

    def test_api_key_not_in_logs(self, caplog):
        provider = _make_provider(api_key="VERYSECRETKEY")
        mock_acoustid = MagicMock()
        mock_acoustid.fingerprint.return_value = ("fp",)

        def fake_urlopen(req, timeout=None):
            body = json.dumps({"status": "ok", "results": []}).encode()
            m = MagicMock()
            m.read.return_value = body
            m.__enter__ = lambda s: s
            m.__exit__ = MagicMock(return_value=False)
            return m

        with caplog.at_level(logging.DEBUG):
            with (
                patch.dict("sys.modules", {"acoustid": mock_acoustid}),
                patch("track_id.acoustid_musicbrainz.urllib.request.urlopen",
                      side_effect=fake_urlopen),
            ):
                provider.identify(_SAMPLE_PCM, _SAMPLE_RATE)

        assert "VERYSECRETKEY" not in caplog.text

    def test_fingerprint_not_logged(self, caplog):
        provider = _make_provider()
        mock_acoustid = MagicMock()
        long_fp = "A" * 200  # simulate a real fingerprint
        mock_acoustid.fingerprint.return_value = (long_fp,)

        def fake_urlopen(req, timeout=None):
            body = json.dumps({"status": "ok", "results": []}).encode()
            m = MagicMock()
            m.read.return_value = body
            m.__enter__ = lambda s: s
            m.__exit__ = MagicMock(return_value=False)
            return m

        with caplog.at_level(logging.DEBUG):
            with (
                patch.dict("sys.modules", {"acoustid": mock_acoustid}),
                patch("track_id.acoustid_musicbrainz.urllib.request.urlopen",
                      side_effect=fake_urlopen),
            ):
                provider.identify(_SAMPLE_PCM, _SAMPLE_RATE)

        # Full fingerprint (100+ char string of same char) must not appear in logs.
        assert long_fp not in caplog.text

    def test_network_timeout_propagates(self):
        provider = _make_provider()
        mock_acoustid = MagicMock()
        mock_acoustid.fingerprint.return_value = ("fp",)
        import socket
        with (
            patch.dict("sys.modules", {"acoustid": mock_acoustid}),
            patch("track_id.acoustid_musicbrainz.urllib.request.urlopen",
                  side_effect=urllib.error.URLError("timed out")),
            pytest.raises(RuntimeError, match="network error"),
        ):
            provider.identify(_SAMPLE_PCM, _SAMPLE_RATE, timeout=1.0)

    def test_short_pcm_returns_not_found(self):
        provider = _make_provider()
        short_pcm = b"\x00" * (22050 * 2)  # only 1 second
        result = provider.identify(short_pcm, _SAMPLE_RATE)
        assert result.matched is False

    def test_dependency_import_error_propagates(self):
        provider = _make_provider()
        with patch.dict("sys.modules", {"acoustid": None}):
            with pytest.raises(ImportError):
                provider.identify(_SAMPLE_PCM, _SAMPLE_RATE)
