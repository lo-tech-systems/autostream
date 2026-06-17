"""track_id.provider — TrackIdentifier protocol definition."""
from __future__ import annotations

from typing import Optional, Protocol, runtime_checkable

from track_id.models import TrackIdentificationResult


@runtime_checkable
class TrackIdentifier(Protocol):
    """Protocol all track-identification providers must satisfy."""

    provider_id: str

    def identify(
        self,
        pcm16_mono: bytes,
        sample_rate: int,
        *,
        timeout: Optional[float] = None,
    ) -> TrackIdentificationResult:
        """Identify a track from raw s16le mono PCM.

        Args:
            pcm16_mono: Raw s16le mono PCM bytes.
            sample_rate: Sample rate in Hz (typically 22050).
            timeout: Optional network timeout in seconds.

        Returns:
            TrackIdentificationResult with matched=True on success or
            matched=False when no match was found.

        Raises:
            Any exception on dependency/network/config failure.  The service
            layer converts exceptions to state="error" at the core boundary.
        """
        ...

    def fingerprint_pcm(
        self,
        pcm16_mono: bytes,
        sample_rate: int,
    ) -> Optional[str]:
        """Return the Chromaprint fingerprint string for the given PCM, or None.

        Used by the service layer to key the result cache without re-fingerprinting
        on cache hit.  Providers that do not support separate fingerprinting should
        return None; the service will fall back to calling identify() directly.

        Raises:
            Any exception on dependency failure.  The service catches these and
            falls back to uncached identify().
        """
        ...
