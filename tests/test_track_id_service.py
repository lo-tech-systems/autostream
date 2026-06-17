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
from track_id.service import TrackIdentificationService, _ResultCache


def _make_provider(matched: bool = True, raise_exc: Exception | None = None):
    provider = MagicMock()
    provider.provider_id = "test_provider"
    if raise_exc is not None:
        provider.identify.side_effect = raise_exc
    else:
        provider.identify.return_value = TrackIdentificationResult(
            matched=matched,
            title="T" if matched else "",
            artist="A" if matched else "",
            provider="test_provider",
        )
    return provider


def _make_service(matched: bool = True, raise_exc=None, interval: int = 15):
    provider = _make_provider(matched, raise_exc)
    return TrackIdentificationService(provider, "test_provider", interval), provider


class TestTrackIdentificationService:

    def test_identify_matched_returns_result(self):
        svc, _ = _make_service(matched=True)
        result = svc.identify(b"\x00" * 44100, 22050, input_index=1)
        assert result.matched is True
        assert result.title == "T"

    def test_identify_not_found_returns_result(self):
        svc, _ = _make_service(matched=False)
        result = svc.identify(b"\x00" * 44100, 22050, input_index=1)
        assert result.matched is False

    def test_provider_exception_returns_not_found_not_raises(self):
        svc, _ = _make_service(raise_exc=RuntimeError("network error"))
        result = svc.identify(b"\x00" * 44100, 22050, input_index=1)
        assert result.matched is False
        assert result.source_detail == "provider_error"

    def test_provider_exception_not_logged_with_secret(self, caplog):
        # The service must not log any exception message containing a key.
        provider = _make_provider(raise_exc=Exception("api_key=abc123 failed"))
        svc = TrackIdentificationService(provider, "test_provider", 15)
        with caplog.at_level(logging.DEBUG):
            svc.identify(b"\x00" * 100, 22050, input_index=1)
        # We never log the exception message, only the exception type name.
        assert "abc123" not in caplog.text

    def test_identify_logs_info_on_match(self, caplog):
        svc, _ = _make_service(matched=True)
        with caplog.at_level(logging.INFO):
            svc.identify(b"\x00" * 44100, 22050, input_index=1)
        assert any("match" in r.message.lower() for r in caplog.records)

    def test_identify_with_cache_uses_cache_on_second_call(self):
        svc, provider = _make_service(matched=True)
        pcm = b"\x00" * 44100
        fp = "fp_abc"
        r1, hit1 = svc.identify_with_cache(fp, pcm, 22050, input_index=1)
        r2, hit2 = svc.identify_with_cache(fp, pcm, 22050, input_index=1)
        assert hit1 is False
        assert hit2 is True
        assert provider.identify.call_count == 1  # second call served from cache

    def test_identify_with_cache_different_fingerprints_both_call_provider(self):
        svc, provider = _make_service(matched=True)
        pcm = b"\x00" * 44100
        svc.identify_with_cache("fp1", pcm, 22050, input_index=1)
        svc.identify_with_cache("fp2", pcm, 22050, input_index=1)
        assert provider.identify.call_count == 2

    def test_interval_seconds_accessible(self):
        svc, _ = _make_service(interval=30)
        assert svc.interval_seconds == 30
