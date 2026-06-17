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
