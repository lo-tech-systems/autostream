"""track_id.service — TrackIdentificationService used by autostream_core."""
from __future__ import annotations

import hashlib
import logging
import time
import threading
from typing import Optional

from track_id.models import (
    STATE_ERROR,
    STATE_NOT_FOUND,
    TrackIdentificationResult,
    TrackIdentificationSnapshot,
    disabled_snapshot,
    state_status_text,
    waiting_snapshot,
)
from track_id.provider import TrackIdentifier

_log = logging.getLogger(__name__)

# Default snapshot durations.
DEFAULT_SNAPSHOT_MAX_SECONDS = 15
MIN_PCM_DURATION_SECONDS = 5.0

# Cache TTLs.
_CACHE_TTL_MATCH = 6 * 3600      # 6 hours for successful matches
_CACHE_TTL_NO_MATCH = 10 * 60    # 10 minutes for not-found / errors
_CACHE_MAX_ENTRIES = 128


def _redact_settings(settings: dict) -> dict:
    """Return a copy of settings with sensitive values replaced by '***'.

    Keys whose names contain 'key', 'token', 'secret', or 'password'
    (case-insensitive) have their values redacted.
    """
    _SENSITIVE = ("key", "token", "secret", "password")
    result = {}
    for k, v in settings.items():
        k_lower = str(k).lower()
        if any(s in k_lower for s in _SENSITIVE):
            result[k] = "***"
        else:
            result[k] = v
    return result


class _ResultCache:
    """LRU-style in-memory result cache with per-entry TTL.

    Keyed by a short hash of the fingerprint string.  Thread-safe.
    """

    def __init__(self, max_entries: int = _CACHE_MAX_ENTRIES) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, tuple[float, TrackIdentificationResult]] = {}
        self._max = max_entries

    @staticmethod
    def make_key(fingerprint: str) -> str:
        """Return a short hex digest of the fingerprint for use as cache key."""
        return hashlib.sha256(fingerprint.encode()).hexdigest()[:16]

    def get(self, key: str, now: float) -> Optional[TrackIdentificationResult]:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            expires_at, result = entry
            if now >= expires_at:
                del self._entries[key]
                return None
            return result

    def put(self, key: str, result: TrackIdentificationResult, now: float) -> None:
        ttl = _CACHE_TTL_MATCH if result.matched else _CACHE_TTL_NO_MATCH
        expires_at = now + ttl
        with self._lock:
            if key in self._entries:
                self._entries[key] = (expires_at, result)
                return
            if len(self._entries) >= self._max:
                # Evict the entry that expires soonest.
                oldest_key = min(self._entries, key=lambda k: self._entries[k][0])
                del self._entries[oldest_key]
            self._entries[key] = (expires_at, result)

    def size(self) -> int:
        with self._lock:
            return len(self._entries)


class TrackIdentificationService:
    """Wraps a provider and provides logging, caching, and error conversion.

    This is the object held by AudioMonitor.  One instance per process is
    acceptable because the cache is shared across monitor instances which is
    desirable — same track heard on two inputs shares cached results.
    """

    def __init__(
        self,
        provider: TrackIdentifier,
        provider_id: str,
        interval_seconds: int,
    ) -> None:
        self._provider = provider
        self._provider_id = provider_id
        self.interval_seconds = interval_seconds
        self._cache = _ResultCache()

    @property
    def provider_id(self) -> str:
        return self._provider_id

    def identify(
        self,
        pcm16_mono: bytes,
        sample_rate: int,
        *,
        input_index: int,
        timeout: Optional[float] = None,
    ) -> TrackIdentificationResult:
        """Identify a track, using the cache when the provider supports fingerprinting.

        Logs attempt stages at DEBUG and result at INFO.  Converts all
        provider exceptions to a not-found result with a sanitized error
        detail.  API keys are never logged.
        """
        from track_id.models import TrackIdentificationResult as R
        duration = len(pcm16_mono) / (sample_rate * 2) if sample_rate else 0.0
        _log.debug(
            "track_id[%d]: starting identification (%.1f s, provider=%s)",
            input_index, duration, self._provider_id,
        )

        if duration < MIN_PCM_DURATION_SECONDS:
            _log.debug(
                "track_id[%d]: audio too short (%.1f s < %.1f s); skipping.",
                input_index, duration, MIN_PCM_DURATION_SECONDS,
            )
            return R(matched=False, provider=self._provider_id, source_detail="too_short")

        now = time.time()

        # Attempt to get a fingerprint for cache lookup before calling the
        # provider.  fingerprint_pcm() is optional on the Protocol; providers
        # that do not implement it return None and skip the cache.
        fp_key: Optional[str] = None
        try:
            fp_str = self._provider.fingerprint_pcm(pcm16_mono, sample_rate)
            if isinstance(fp_str, str) and fp_str:
                fp_key = _ResultCache.make_key(fp_str)
                cached = self._cache.get(fp_key, now)
                if cached is not None:
                    _log.debug("track_id[%d]: cache hit", input_index)
                    return cached
        except Exception:
            fp_key = None

        try:
            result = self._provider.identify(
                pcm16_mono,
                sample_rate,
                timeout=timeout,
            )
        except Exception as exc:
            _log.warning(
                "track_id[%d]: provider '%s' error: %s",
                input_index,
                self._provider_id,
                type(exc).__name__,
            )
            return R(matched=False, provider=self._provider_id, source_detail="provider_error")

        if fp_key is not None:
            self._cache.put(fp_key, result, now)

        if result.matched:
            _log.info(
                "track_id[%d]: match found — artist=%r title=%r provider=%s score=%s",
                input_index,
                result.artist,
                result.title,
                result.provider or self._provider_id,
                f"{result.confidence:.2f}" if result.confidence is not None else "n/a",
            )
        else:
            _log.info("track_id[%d]: no match found (provider=%s)", input_index, self._provider_id)

        return result

    def identify_with_cache(
        self,
        fingerprint: str,
        pcm16_mono: bytes,
        sample_rate: int,
        *,
        input_index: int,
        timeout: Optional[float] = None,
    ) -> tuple[TrackIdentificationResult, bool]:
        """Identify using the cache.  Returns (result, cache_hit)."""
        key = _ResultCache.make_key(fingerprint)
        now = time.time()
        cached = self._cache.get(key, now)
        if cached is not None:
            _log.debug(
                "track_id[%d]: cache hit (key=%s matched=%s)",
                input_index, key, cached.matched,
            )
            return cached, True

        _log.debug("track_id[%d]: cache miss (key=%s)", input_index, key)
        result = self.identify(
            pcm16_mono, sample_rate, input_index=input_index, timeout=timeout
        )
        self._cache.put(key, result, now)
        return result, False


class _DisabledService:
    """No-op service used when track identification is disabled or misconfigured."""

    provider_id = ""
    interval_seconds = 15

    def identify(self, *args, **kwargs) -> None:
        return None

    def identify_with_cache(self, *args, **kwargs):
        return None, False


def build_service(
    enabled: bool,
    provider_id: str,
    provider_settings: dict,
    interval_seconds: int,
) -> Optional[TrackIdentificationService]:
    """Build and return a service, or None when disabled / provider unavailable.

    Logs provider selection at INFO.  Returns None if not enabled or if the
    provider cannot be instantiated (already logged by registry).
    """
    if not enabled:
        _log.info("track_id: identification disabled.")
        return None

    from track_id.registry import build_provider
    provider = build_provider(provider_id, provider_settings)
    if provider is None:
        _log.warning("track_id: provider '%s' unavailable; identification disabled.", provider_id)
        return None

    _log.info("track_id: enabled with provider '%s' at %ds interval.", provider_id, interval_seconds)
    return TrackIdentificationService(provider, provider_id, interval_seconds)
