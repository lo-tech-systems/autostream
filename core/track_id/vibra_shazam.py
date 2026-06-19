"""track_id.vibra_shazam — Shazam provider backed by the autostream-vibra daemon."""
from __future__ import annotations

import logging
from typing import Optional

from track_id.models import (
    TrackArtwork,
    TrackIDRateLimitedError,
    TrackIdentificationResult,
)
from track_id.vibra_client import VibraClient

_log = logging.getLogger(__name__)

PROVIDER_ID = "vibra_shazam"

# Process-wide singleton VibraClient shared by all VibraShazamProvider instances.
# The client's internal lock serialises concurrent recognize() calls so the
# daemon (which handles one client at a time) is never sent interleaved requests.
_shared_client: Optional[VibraClient] = None


def _get_shared_client() -> VibraClient:
    global _shared_client
    if _shared_client is None:
        _shared_client = VibraClient()
    return _shared_client


class VibraRecognitionError(Exception):
    """Raised when the Vibra daemon returns ok:false for any reason other than rate limiting."""


class VibraRateLimitedError(TrackIDRateLimitedError):
    """Raised when the Vibra daemon returns ok:false, error:'rate_limited'."""


class VibraShazamProvider:
    """Track identification provider backed by the autostream-vibra Shazam daemon."""

    provider_id = PROVIDER_ID

    def __init__(
        self,
        settings: dict,
        client: Optional[VibraClient] = None,
    ) -> None:
        # Injectable client for tests; production uses the process-wide singleton.
        self._client = client if client is not None else _get_shared_client()

    def fingerprint_pcm(
        self,
        pcm16_mono: bytes,
        sample_rate: int,
    ) -> None:
        """Vibra handles fingerprinting internally; return None to skip service cache."""
        return None

    def identify(
        self,
        pcm16_mono: bytes,
        sample_rate: int,
        *,
        timeout: Optional[float] = None,
    ) -> TrackIdentificationResult:
        """Identify a track by sending PCM to the Vibra daemon.

        Raises:
            VibraRateLimitedError: Daemon returned error:'rate_limited'.
            VibraRecognitionError: Daemon returned any other ok:false error.
            OSError: Socket failure after the client's reconnect retry.
        """
        resp = self._client.recognize(pcm16_mono, sample_rate)

        if not resp.get("ok"):
            error_code = resp.get("error", "unknown")
            if error_code == "rate_limited":
                raise VibraRateLimitedError(error_code)
            raise VibraRecognitionError(error_code)

        if not resp.get("matched"):
            return TrackIdentificationResult(matched=False, provider=PROVIDER_ID)

        artwork_url = resp.get("artwork_url", "")
        artwork = TrackArtwork(url=artwork_url) if artwork_url else None
        return TrackIdentificationResult(
            matched=True,
            title=resp.get("title", ""),
            artist=resp.get("artist", ""),
            artwork=artwork,
            provider=PROVIDER_ID,
        )
