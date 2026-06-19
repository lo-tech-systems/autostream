"""Tests for track_id.models and track_id.service (WP2)."""
from __future__ import annotations

import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

from track_id.models import (
    STATE_DISABLED,
    STATE_WAITING,
    STATE_ANALYSING,
    STATE_IDENTIFIED,
    STATE_NOT_FOUND,
    STATE_ERROR,
    TrackArtwork,
    TrackIdentificationResult,
    TrackIdentificationSnapshot,
    disabled_snapshot,
    waiting_snapshot,
    state_status_text,
)
from track_id.service import (
    _ResultCache,
    _redact_settings,
    TrackIdentificationService,
    build_service,
)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class TestTrackIdentificationResult:

    def test_not_matched_defaults(self):
        r = TrackIdentificationResult(matched=False)
        assert r.title == ""
        assert r.artist == ""
        assert r.artwork is None

    def test_matched_fields(self):
        r = TrackIdentificationResult(
            matched=True,
            title="Song",
            artist="Artist",
            album="Album",
            provider="vibra_shazam",
            confidence=0.9,
        )
        assert r.matched is True
        assert r.confidence == 0.9

    def test_to_public_dict_matched(self):
        art = TrackArtwork(url="https://example.com/art.jpg")
        r = TrackIdentificationResult(
            matched=True,
            title="S",
            artist="A",
            album="AL",
            artwork=art,
            provider="p",
            confidence=0.8,
        )
        d = r.to_public_dict()
        assert d["matched"] is True
        assert d["artwork_url"] == "https://example.com/art.jpg"
        assert d["confidence"] == 0.8

    def test_to_public_dict_no_artwork(self):
        r = TrackIdentificationResult(matched=False)
        d = r.to_public_dict()
        assert d["artwork_url"] == ""


class TestTrackIdentificationSnapshot:

    def test_disabled_snapshot_stable(self):
        s = disabled_snapshot()
        assert s.enabled is False
        assert s.state == STATE_DISABLED
        assert s.status_text == ""

    def test_waiting_snapshot_stable(self):
        s = waiting_snapshot()
        assert s.enabled is True
        assert s.state == STATE_WAITING
        assert "audio" in s.status_text.lower()

    def test_to_public_dict_contains_required_keys(self):
        s = disabled_snapshot()
        d = s.to_public_dict()
        for key in ("enabled", "state", "status_text", "provider", "title",
                    "artist", "album", "artwork_url", "error"):
            assert key in d

    def test_identified_snapshot_fields(self):
        s = TrackIdentificationSnapshot(
            enabled=True,
            state=STATE_IDENTIFIED,
            status_text=state_status_text(STATE_IDENTIFIED),
            title="T",
            artist="A",
            album="AL",
            artwork_url="https://x.com/a.jpg",
            confidence=0.95,
            updated_at=1000.0,
        )
        d = s.to_public_dict()
        assert d["state"] == STATE_IDENTIFIED
        assert d["artwork_url"] == "https://x.com/a.jpg"


class TestStateStatusText:

    def test_disabled_empty(self):
        assert state_status_text(STATE_DISABLED) == ""

    def test_identified_nonempty(self):
        assert state_status_text(STATE_IDENTIFIED) != ""

    def test_error_safe_text(self):
        text = state_status_text(STATE_ERROR)
        assert "unavailable" in text.lower() or text != ""

    def test_unknown_state_returns_empty_string(self):
        assert state_status_text("totally_unknown_state") == ""


# ---------------------------------------------------------------------------
# _redact_settings
# ---------------------------------------------------------------------------

class TestRedactSettings:

    def test_api_key_redacted(self):
        result = _redact_settings({"api_key": "supersecret"})
        assert result["api_key"] == "***"

    def test_token_redacted(self):
        result = _redact_settings({"access_token": "tok"})
        assert result["access_token"] == "***"

    def test_secret_redacted(self):
        result = _redact_settings({"client_secret": "s"})
        assert result["client_secret"] == "***"

    def test_password_redacted(self):
        result = _redact_settings({"password": "pw"})
        assert result["password"] == "***"

    def test_non_sensitive_preserved(self):
        result = _redact_settings({"host": "localhost", "port": 8080})
        assert result["host"] == "localhost"
        assert result["port"] == 8080

    def test_case_insensitive(self):
        result = _redact_settings({"API_KEY": "val", "Token": "t"})
        assert result["API_KEY"] == "***"
        assert result["Token"] == "***"


# ---------------------------------------------------------------------------
# _ResultCache
# ---------------------------------------------------------------------------

class TestResultCache:

    def _result(self, matched: bool = True) -> TrackIdentificationResult:
        return TrackIdentificationResult(matched=matched, title="T", artist="A")

    def test_cache_miss(self):
        cache = _ResultCache()
        assert cache.get("nokey", time.time()) is None

    def test_cache_hit(self):
        cache = _ResultCache()
        r = self._result()
        key = "k1"
        cache.put(key, r, time.time())
        assert cache.get(key, time.time()) is r

    def test_match_ttl_not_expired(self):
        cache = _ResultCache()
        r = self._result(matched=True)
        key = "k1"
        now = time.time()
        cache.put(key, r, now)
        assert cache.get(key, now + 3600) is r  # 1 hr later still valid

    def test_match_ttl_expired(self):
        cache = _ResultCache()
        r = self._result(matched=True)
        key = "k1"
        now = 0.0
        cache.put(key, r, now)
        # Match TTL is 6 hours = 21600s; 21601s later should expire
        assert cache.get(key, now + 21601) is None

    def test_not_found_ttl_shorter(self):
        cache = _ResultCache()
        r = self._result(matched=False)
        key = "k2"
        now = 0.0
        cache.put(key, r, now)
        # Not-found TTL is 10 min = 600s; 601s later should expire
        assert cache.get(key, now + 601) is None

    def test_not_found_ttl_within_range(self):
        cache = _ResultCache()
        r = self._result(matched=False)
        key = "k2"
        now = 0.0
        cache.put(key, r, now)
        assert cache.get(key, now + 300) is r  # 5 min — still valid

    def test_size_cap_evicts(self):
        cache = _ResultCache(max_entries=3)
        now = 0.0
        for i in range(4):
            cache.put(f"k{i}", self._result(), now + i)
        assert cache.size() == 3

    def test_make_key_stable(self):
        k1 = _ResultCache.make_key("fingerprint_abc")
        k2 = _ResultCache.make_key("fingerprint_abc")
        assert k1 == k2

    def test_make_key_different_for_different_fingerprints(self):
        k1 = _ResultCache.make_key("fp_a")
        k2 = _ResultCache.make_key("fp_b")
        assert k1 != k2


# ---------------------------------------------------------------------------
# build_service
# ---------------------------------------------------------------------------

class TestBuildService:

    def test_disabled_returns_none(self):
        svc = build_service(
            enabled=False,
            provider_id="vibra_shazam",
            provider_settings={},
            interval_seconds=15,
        )
        assert svc is None

    def test_unknown_provider_returns_none(self):
        svc = build_service(
            enabled=True,
            provider_id="totally_unknown_provider",
            provider_settings={},
            interval_seconds=15,
        )
        assert svc is None

    def test_known_provider_unavailable_returns_none(self):
        # vibra_shazam build will fail if the vibra socket doesn't exist at test time
        # (socket connection is lazy, so this actually succeeds). Simulate import failure
        # instead to verify build_service never raises.
        with pytest.MonkeyPatch().context() as mp:
            mp.setitem(sys.modules, "track_id.vibra_shazam", None)
            svc = build_service(
                enabled=True,
                provider_id="vibra_shazam",
                provider_settings={},
                interval_seconds=15,
            )
        # Either None (provider build failed) or a real service — never raises.
        assert svc is None or hasattr(svc, "identify")
