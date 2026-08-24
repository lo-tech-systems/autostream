"""track_id.vibra_shazam — Shazam provider backed by the vibra-mini daemon."""
from __future__ import annotations

import logging
from typing import Optional

from track_id.models import (
    TrackArtwork,
    TrackIDProviderUnreachableError,
    TrackIDRateLimitedError,
    TrackIDUpstreamRejectionError,
    TrackIdentificationResult,
)
from track_id.vibra_client import VibraClient, VibraRuntimeInfo

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


def get_vibra_runtime_info() -> VibraRuntimeInfo:
    """Return the shared client's in-memory runtime metadata without socket I/O."""
    return _get_shared_client().get_runtime_info()


def refresh_vibra_runtime_info(timeout: float = 1.0) -> None:
    """Best-effort shared-client connect/handshake; never raises."""
    try:
        _get_shared_client().refresh_runtime_info(timeout)
    except Exception:
        pass


class VibraRecognitionError(Exception):
    """Raised when the Vibra daemon returns ok:false for any reason other than rate limiting or rejection."""


class VibraRateLimitedError(TrackIDRateLimitedError):
    """Raised when the Vibra daemon returns ok:false, error:'rate_limited'."""


class VibraUpstreamRejectionError(TrackIDUpstreamRejectionError):
    """Raised when the Vibra daemon reports HTTP 403 or 406 from Shazam."""


class VibraProviderUnreachableError(TrackIDProviderUnreachableError):
    """Raised when the vibra-mini daemon itself could not be reached (a
    socket-level OSError from VibraClient.recognize()) or when it reports it
    could not reach Shazam's upstream (error:'network_error' or
    error:'network_timeout') -- both fall under a "provider unreachable"
    classification, grouped with rate-limit backoff rather than the
    generic config-error one."""


# error codes the vibra-mini daemon reports when its own Shazam HTTP call
# fails to connect/times out (daemon/shazam_client.cpp's ShazamLookupError
# codes), as distinct from an HTTP response it did receive (rate_limited,
# http_error).
_NETWORK_ERROR_CODES = frozenset({"network_error", "network_timeout"})


class VibraShazamProvider:
    """Track identification provider backed by the vibra-mini Shazam daemon."""

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
            VibraProviderUnreachableError: The vibra-mini socket itself
                could not be reached (wraps the client's OSError), or the
                daemon reports it could not reach Shazam's own upstream
                (error:'network_error'/'network_timeout').
            VibraRecognitionError: Daemon returned any other ok:false error.
        """
        try:
            resp = self._client.recognize(pcm16_mono, sample_rate)
        except OSError as exc:
            # Local socket to the vibra-mini daemon itself failed (daemon
            # down, connect refused, etc.) -- a "provider unreachable"
            # classification, distinct from a response the daemon returned
            # and we understood.
            raise VibraProviderUnreachableError(str(exc)) from exc

        if not resp.get("ok"):
            error_code = resp.get("error", "unknown")
            http_status = resp.get("http_status", 0)
            if error_code == "rate_limited":
                # retry_after_seconds: not emitted by the vibra-mini daemon
                # today (grepped daemon/shazam_client.cpp -- no Retry-After
                # capture), so this is always None in practice; read
                # opportunistically so a future daemon version that adds it
                # is honored without another Python-side change.
                retry_after = resp.get("retry_after_seconds")
                raise VibraRateLimitedError(error_code, retry_after_seconds=retry_after)
            if http_status in (403, 406):
                raise VibraUpstreamRejectionError(http_status)
            if error_code in _NETWORK_ERROR_CODES:
                raise VibraProviderUnreachableError(error_code)
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
