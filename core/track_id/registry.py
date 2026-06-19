"""track_id.registry — provider factory registry."""
from __future__ import annotations

import logging
from typing import Optional

from track_id.provider import TrackIdentifier

_log = logging.getLogger(__name__)

# Registered provider ids.
PROVIDER_ACOUSTID_MUSICBRAINZ = "acoustid_musicbrainz"
PROVIDER_VIBRA_SHAZAM = "vibra_shazam"


def build_provider(
    provider_id: str,
    provider_settings: dict,
) -> Optional[TrackIdentifier]:
    """Build and return a provider instance, or None if unavailable.

    Returns None rather than raising so the caller can fall back to a disabled
    service without crashing.  Unknown provider ids are logged at WARNING.
    """
    if provider_id == PROVIDER_ACOUSTID_MUSICBRAINZ:
        try:
            from track_id.acoustid_musicbrainz import AcoustIDMusicBrainzProvider
            return AcoustIDMusicBrainzProvider(provider_settings)
        except Exception as exc:
            _log.warning(
                "track_id: failed to build provider '%s': %s",
                provider_id,
                exc,
            )
            return None

    if provider_id == PROVIDER_VIBRA_SHAZAM:
        try:
            from track_id.vibra_shazam import VibraShazamProvider
            return VibraShazamProvider(provider_settings)
        except Exception as exc:
            _log.warning(
                "track_id: failed to build provider '%s': %s",
                provider_id,
                exc,
            )
            return None

    _log.warning("track_id: unknown provider id '%s'; identification disabled.", provider_id)
    return None
