"""Tests for track_id.service — TrackIdentificationService."""
from __future__ import annotations

import logging
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

from track_id.models import TrackIdentificationResult
from track_id.service import MIN_PCM_DURATION_SECONDS, TrackIdentificationService, _ResultCache

# Enough PCM to pass the minimum-duration guard (6 s at 22050 Hz, 16-bit mono).
_LONG_PCM = b"\x00" * int(22050 * 2 * 6)


def _make_provider(matched: bool = True, raise_exc: Exception | None = None):
    provider = MagicMock()
    provider.provider_id = "test_provider"
    _result = TrackIdentificationResult(
        matched=matched,
        title="T" if matched else "",
        artist="A" if matched else "",
        provider="test_provider",
    )
    if raise_exc is not None:
        provider.identify.side_effect = raise_exc
        provider.identify_from_fingerprint.side_effect = raise_exc
    else:
        provider.identify.return_value = _result
        provider.identify_from_fingerprint.return_value = _result
    return provider


def _make_service(matched: bool = True, raise_exc=None, interval: int = 15):
    provider = _make_provider(matched, raise_exc)
    return TrackIdentificationService(provider, "test_provider", interval), provider


class TestTrackIdentificationService:

    def test_identify_matched_returns_result(self):
        svc, _ = _make_service(matched=True)
        result = svc.identify(_LONG_PCM, 22050, input_index=1)
        assert result.matched is True
        assert result.title == "T"

    def test_identify_not_found_returns_result(self):
        svc, _ = _make_service(matched=False)
        result = svc.identify(_LONG_PCM, 22050, input_index=1)
        assert result.matched is False

    def test_provider_exception_returns_not_found_not_raises(self):
        svc, _ = _make_service(raise_exc=RuntimeError("network error"))
        result = svc.identify(_LONG_PCM, 22050, input_index=1)
        assert result.matched is False
        assert result.source_detail == "provider_error"

    def test_provider_exception_not_logged_with_secret(self, caplog):
        # The service must not log any exception message containing a key.
        provider = _make_provider(raise_exc=Exception("api_key=abc123 failed"))
        svc = TrackIdentificationService(provider, "test_provider", 15)
        with caplog.at_level(logging.DEBUG):
            svc.identify(_LONG_PCM, 22050, input_index=1)
        # We never log the exception message, only the exception type name.
        assert "abc123" not in caplog.text

    def test_identify_logs_info_on_match(self, caplog):
        svc, _ = _make_service(matched=True)
        with caplog.at_level(logging.INFO):
            svc.identify(_LONG_PCM, 22050, input_index=1)
        assert any("match" in r.message.lower() for r in caplog.records)

    def test_identify_with_cache_uses_cache_on_second_call(self):
        svc, provider = _make_service(matched=True)
        pcm = _LONG_PCM
        fp = "fp_abc"
        r1, hit1 = svc.identify_with_cache(fp, pcm, 22050, input_index=1)
        r2, hit2 = svc.identify_with_cache(fp, pcm, 22050, input_index=1)
        assert hit1 is False
        assert hit2 is True
        assert provider.identify.call_count == 1  # second call served from cache

    def test_identify_with_cache_different_fingerprints_both_call_provider(self):
        svc, provider = _make_service(matched=True)
        pcm = _LONG_PCM
        svc.identify_with_cache("fp1", pcm, 22050, input_index=1)
        svc.identify_with_cache("fp2", pcm, 22050, input_index=1)
        assert provider.identify.call_count == 2

    def test_interval_seconds_accessible(self):
        svc, _ = _make_service(interval=30)
        assert svc.interval_seconds == 30

    def test_identify_uses_cache_when_provider_returns_fingerprint(self):
        provider = _make_provider(matched=True)
        provider.fingerprint_pcm.return_value = "stable_fp"
        svc = TrackIdentificationService(provider, "test_provider", 15)
        pcm = _LONG_PCM
        # First call: cache miss → provider.identify_from_fingerprint called (not identify).
        r1 = svc.identify(pcm, 22050, input_index=1)
        # Second call with same fingerprint: cache hit → neither called again.
        r2 = svc.identify(pcm, 22050, input_index=1)
        assert provider.identify_from_fingerprint.call_count == 1
        assert provider.identify.call_count == 0
        assert r1.matched is True
        assert r2.matched is True

    def test_identify_returns_too_short_for_short_pcm(self):
        svc, provider = _make_service(matched=True)
        short_pcm = b"\x00" * 100  # << MIN_PCM_DURATION_SECONDS
        result = svc.identify(short_pcm, 22050, input_index=1)
        assert result.matched is False
        assert result.source_detail == "too_short"
        provider.identify.assert_not_called()
        provider.fingerprint_pcm.assert_not_called()

    def test_identify_does_not_cache_too_short(self):
        svc, provider = _make_service(matched=True)
        short_pcm = b"\x00" * 100
        svc.identify(short_pcm, 22050, input_index=1)
        svc.identify(short_pcm, 22050, input_index=1)
        provider.identify.assert_not_called()  # never reached, not cached

    def test_identify_skips_cache_when_fingerprint_pcm_raises(self):
        provider = _make_provider(matched=True)
        provider.fingerprint_pcm.side_effect = RuntimeError("acoustid not installed")
        svc = TrackIdentificationService(provider, "test_provider", 15)
        pcm = _LONG_PCM
        r1 = svc.identify(pcm, 22050, input_index=1)
        r2 = svc.identify(pcm, 22050, input_index=1)
        # No caching fallback → provider called both times.
        assert provider.identify.call_count == 2
        assert r1.matched is True


class TestNoDoubleFingerprint:
    """On a cache miss the service must not fingerprint twice."""

    def test_identify_from_fingerprint_called_instead_of_identify_on_cache_miss(self):
        """When provider has identify_from_fingerprint, identify() must not be called."""
        provider = MagicMock()
        provider.provider_id = "test_provider"
        provider.fingerprint_pcm.return_value = "fp_xyz"
        provider.identify_from_fingerprint.return_value = TrackIdentificationResult(
            matched=True, title="T", artist="A", provider="test_provider"
        )
        svc = TrackIdentificationService(provider, "test_provider", 15)

        result = svc.identify(_LONG_PCM, 22050, input_index=1)

        assert result.matched is True
        provider.fingerprint_pcm.assert_called_once()
        provider.identify_from_fingerprint.assert_called_once()
        provider.identify.assert_not_called()

    def test_cache_hit_calls_neither_identify_nor_identify_from_fingerprint(self):
        """A cache hit must bypass the provider entirely."""
        provider = MagicMock()
        provider.provider_id = "test_provider"
        provider.fingerprint_pcm.return_value = "fp_xyz"
        provider.identify_from_fingerprint.return_value = TrackIdentificationResult(
            matched=True, title="T", artist="A", provider="test_provider"
        )
        svc = TrackIdentificationService(provider, "test_provider", 15)

        svc.identify(_LONG_PCM, 22050, input_index=1)   # populates cache
        provider.reset_mock()
        provider.fingerprint_pcm.return_value = "fp_xyz"

        svc.identify(_LONG_PCM, 22050, input_index=1)   # cache hit

        provider.identify_from_fingerprint.assert_not_called()
        provider.identify.assert_not_called()

    def test_falls_back_to_identify_when_identify_from_fingerprint_absent(self):
        """Providers without identify_from_fingerprint must still work."""
        provider = MagicMock(spec=["identify", "fingerprint_pcm", "provider_id"])
        provider.provider_id = "test_provider"
        provider.fingerprint_pcm.return_value = "fp_xyz"
        provider.identify.return_value = TrackIdentificationResult(
            matched=True, title="T", artist="A", provider="test_provider"
        )
        svc = TrackIdentificationService(provider, "test_provider", 15)

        result = svc.identify(_LONG_PCM, 22050, input_index=1)

        assert result.matched is True
        provider.identify.assert_called_once()

    def test_falls_back_to_identify_when_fingerprint_pcm_returns_none(self):
        """Providers whose fingerprint_pcm returns None must fall back to identify()."""
        provider = MagicMock()
        provider.provider_id = "test_provider"
        provider.fingerprint_pcm.return_value = None
        provider.identify.return_value = TrackIdentificationResult(
            matched=False, provider="test_provider"
        )
        svc = TrackIdentificationService(provider, "test_provider", 15)

        svc.identify(_LONG_PCM, 22050, input_index=1)

        provider.identify.assert_called_once()
        provider.identify_from_fingerprint.assert_not_called()


class TestSnapshotClampAndCapacity:
    """Buffer and clamp constants must support 45-second snapshots."""

    def test_id_buf_frames_holds_45_seconds(self):
        """ID_BUF_FRAMES must be large enough for 45 s at 22050 Hz."""
        ID_BUF_RATE = 22050
        ID_BUF_FRAMES = 1 << 20  # must match autostream_monitor.h
        capacity_seconds = ID_BUF_FRAMES / ID_BUF_RATE
        assert capacity_seconds >= 45.0

    def test_track_id_max_interval_aligned_to_buffer(self):
        """TRACK_ID_MAX_INTERVAL must not exceed the buffer capacity."""
        import sys
        from pathlib import Path
        core_path = str(Path(__file__).parent.parent / "core")
        if core_path not in sys.path:
            sys.path.insert(0, core_path)
        from autostream_config import TRACK_ID_MAX_INTERVAL
        ID_BUF_RATE = 22050
        ID_BUF_FRAMES = 1 << 20
        capacity_seconds = ID_BUF_FRAMES / ID_BUF_RATE
        assert TRACK_ID_MAX_INTERVAL <= capacity_seconds

    def test_track_id_max_interval_is_45(self):
        import sys
        from pathlib import Path
        core_path = str(Path(__file__).parent.parent / "core")
        if core_path not in sys.path:
            sys.path.insert(0, core_path)
        from autostream_config import TRACK_ID_MAX_INTERVAL
        assert TRACK_ID_MAX_INTERVAL == 45
