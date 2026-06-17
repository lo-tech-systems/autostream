"""track_id.models — normalized dataclasses for track identification."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# Public state strings.
STATE_DISABLED = "disabled"
STATE_WAITING = "waiting_for_audio"
STATE_ANALYSING = "analysing"
STATE_IDENTIFIED = "identified"
STATE_NOT_FOUND = "not_found"
STATE_ERROR = "error"

_VALID_STATES = frozenset({
    STATE_DISABLED, STATE_WAITING, STATE_ANALYSING,
    STATE_IDENTIFIED, STATE_NOT_FOUND, STATE_ERROR,
})

_STATE_TEXT = {
    STATE_DISABLED: "",
    STATE_WAITING: "Waiting for audio",
    STATE_ANALYSING: "Analysing",
    STATE_IDENTIFIED: "Track identified",
    STATE_NOT_FOUND: "Listening",
    STATE_ERROR: "Identification unavailable",
}


def state_status_text(state: str) -> str:
    """Return default UI status text for a state string."""
    return _STATE_TEXT.get(state, "")


@dataclass(frozen=True)
class TrackArtwork:
    url: str = ""
    source: str = ""
    width: Optional[int] = None
    height: Optional[int] = None


@dataclass(frozen=True)
class TrackIdentificationResult:
    """Normalized result returned by a provider's identify() call."""
    matched: bool
    title: str = ""
    artist: str = ""
    album: str = ""
    artwork: Optional[TrackArtwork] = None
    provider: str = ""
    confidence: Optional[float] = None
    external_ids: dict = field(default_factory=dict)
    source_detail: str = ""
    is_configuration_error: bool = False

    def to_public_dict(self) -> dict:
        return {
            "matched": self.matched,
            "title": self.title,
            "artist": self.artist,
            "album": self.album,
            "artwork_url": (self.artwork.url if self.artwork else ""),
            "provider": self.provider,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class TrackIdentificationSnapshot:
    """Thread-safe immutable snapshot of the current identification state.

    Used by build_home_state() and the Web UI. Never contains raw provider
    payloads, full fingerprints, or API keys.
    """
    enabled: bool
    state: str
    status_text: str
    input_index: Optional[int] = None
    provider: str = ""
    title: str = ""
    artist: str = ""
    album: str = ""
    artwork_url: str = ""
    confidence: Optional[float] = None
    updated_at: Optional[float] = None
    last_attempt_at: Optional[float] = None
    error: str = ""

    def to_public_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "state": self.state,
            "status_text": self.status_text,
            "input_index": self.input_index,
            "provider": self.provider,
            "title": self.title,
            "artist": self.artist,
            "album": self.album,
            "artwork_url": self.artwork_url,
            "confidence": self.confidence,
            "updated_at": self.updated_at,
            "last_attempt_at": self.last_attempt_at,
            "error": self.error,
        }


def disabled_snapshot() -> TrackIdentificationSnapshot:
    return TrackIdentificationSnapshot(
        enabled=False,
        state=STATE_DISABLED,
        status_text=state_status_text(STATE_DISABLED),
    )


def waiting_snapshot(*, input_index: Optional[int] = None) -> TrackIdentificationSnapshot:
    return TrackIdentificationSnapshot(
        enabled=True,
        state=STATE_WAITING,
        status_text=state_status_text(STATE_WAITING),
        input_index=input_index,
    )
