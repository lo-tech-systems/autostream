"""track_id.acoustid_musicbrainz — AcoustID + MusicBrainz + Cover Art Archive provider.

PCM pipeline:
  raw s16le mono PCM @ 22050 Hz
  → acoustid.fingerprint() / fpcalc fallback
  → AcoustID web lookup (api_key required)
  → best recording by score
  → MusicBrainz recording metadata if needed
  → Cover Art Archive thumbnail URL

All network calls are isolated in this module.  The service boundary
(service.py) converts exceptions to state="error" so the coordinator
loop is never affected.

Security:
  - API key is never logged.
  - Full fingerprints are never logged.
  - Raw provider payloads are never passed to callers.
"""
from __future__ import annotations

import io
import logging
import struct
import time
import urllib.request
import urllib.error
from typing import Optional

from track_id.models import TrackArtwork, TrackIdentificationResult

_log = logging.getLogger(__name__)

# Provider metadata.
PROVIDER_ID = "acoustid_musicbrainz"

# AcoustID constants.
_ACOUSTID_LOOKUP_URL = "https://api.acoustid.org/v2/lookup"
_ACOUSTID_META = "recordings+releases+releasegroups+compress"

# MusicBrainz constants.
_MB_API_BASE = "https://musicbrainz.org/ws/2"
_MB_RATE_LIMIT_DELAY = 1.1  # seconds between MB calls (1 req/s limit)
_mb_last_call: float = 0.0

# Cover Art Archive.
_CAA_BASE = "https://coverartarchive.org"

# User-Agent for HTTP calls (MusicBrainz requires a meaningful UA).
_USER_AGENT = "autostream/1 (https://github.com/lo-tech/autostream)"

# Minimum PCM duration to attempt fingerprinting.
_MIN_DURATION_S = 5.0

# Default timeout for all network calls (seconds).
_DEFAULT_TIMEOUT = 10.0


# ---------------------------------------------------------------------------
# PCM fingerprinting
# ---------------------------------------------------------------------------

def _compute_duration(pcm16_mono: bytes, sample_rate: int) -> float:
    return len(pcm16_mono) / (sample_rate * 2)


def _fingerprint_raw_pcm(
    pcm16_mono: bytes,
    sample_rate: int,
) -> tuple[float, str]:
    """Return (duration_s, fingerprint_string) from raw s16le mono PCM.

    Uses acoustid.fingerprint() (from python3-acoustid / pyacoustid) which
    accepts raw PCM bytes directly.  Falls back to a WAV-wrapping fpcalc path
    if the raw API fails.

    Raises ImportError if acoustid is not installed.
    Raises RuntimeError if fingerprinting fails.
    """
    import acoustid  # type: ignore[import]

    duration = _compute_duration(pcm16_mono, sample_rate)
    _log.debug("track_id: fingerprinting %.1f s of PCM", duration)

    try:
        result = acoustid.fingerprint(sample_rate, 1, [pcm16_mono])
        # Some pyacoustid versions return (duration, fingerprint); others just fingerprint.
        if isinstance(result, tuple) and len(result) == 2:
            _dur, fp = result
            duration = float(_dur) if _dur else duration
        else:
            fp = result
        if not fp:
            raise RuntimeError("empty fingerprint returned")
        # pyacoustid may return bytes on some platforms; decode to ASCII string.
        if isinstance(fp, bytes):
            fp = fp.decode("latin-1")
        else:
            fp = str(fp)
        _log.debug("track_id: fingerprint generated (len=%d)", len(fp))
        return duration, fp
    except Exception as raw_exc:
        _log.debug("track_id: raw PCM fingerprint failed (%s); trying fpcalc WAV path", raw_exc)
        return _fingerprint_via_wav(pcm16_mono, sample_rate, duration)


def _fingerprint_via_wav(
    pcm16_mono: bytes,
    sample_rate: int,
    duration: float,
) -> tuple[float, str]:
    """Fallback: wrap PCM in a minimal WAV file and run fpcalc on it."""
    import acoustid  # type: ignore[import]
    import os
    import tempfile

    wav_bytes = _pcm_to_wav(pcm16_mono, sample_rate)
    tmp = tempfile.NamedTemporaryFile(suffix=".wav", delete=False)
    try:
        tmp.write(wav_bytes)
        tmp.close()
        result = acoustid.fingerprint_file(tmp.name, force_fpcalc=True)
        if isinstance(result, tuple) and len(result) == 2:
            _dur, fp = result
            duration = float(_dur) if _dur else duration
        else:
            fp = result
        if not fp:
            raise RuntimeError("fpcalc returned empty fingerprint")
        if isinstance(fp, bytes):
            fp = fp.decode("latin-1")
        else:
            fp = str(fp)
        _log.debug("track_id: fpcalc fingerprint generated (len=%d)", len(fp))
        return duration, fp
    except Exception as exc:
        raise RuntimeError(f"fingerprinting failed (raw and fpcalc): {exc}") from exc
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


def _pcm_to_wav(pcm16_mono: bytes, sample_rate: int) -> bytes:
    """Wrap raw s16le mono PCM in a minimal RIFF WAV header."""
    n_channels = 1
    bits_per_sample = 16
    byte_rate = sample_rate * n_channels * bits_per_sample // 8
    block_align = n_channels * bits_per_sample // 8
    data_size = len(pcm16_mono)
    chunk_size = 36 + data_size

    header = struct.pack(
        "<4sI4s4sIHHIIHH4sI",
        b"RIFF",
        chunk_size,
        b"WAVE",
        b"fmt ",
        16,               # subchunk1 size
        1,                # PCM audio format
        n_channels,
        sample_rate,
        byte_rate,
        block_align,
        bits_per_sample,
        b"data",
        data_size,
    )
    return header + pcm16_mono


# ---------------------------------------------------------------------------
# AcoustID lookup
# ---------------------------------------------------------------------------

def _acoustid_lookup(
    fingerprint: str,
    duration: float,
    api_key: str,
    timeout: float,
) -> list[dict]:
    """Query AcoustID and return the raw results list.

    Returns [] on no results.  Raises on network/HTTP error or JSON parse error.
    API key is never included in log output.
    """
    import json
    import urllib.parse

    params = urllib.parse.urlencode({
        "client": api_key,
        "duration": str(int(duration)),
        "fingerprint": fingerprint,
        "meta": _ACOUSTID_META,
    })
    url = f"{_ACOUSTID_LOOKUP_URL}?{params}"
    _log.debug("track_id: AcoustID lookup started")

    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"AcoustID HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"AcoustID network error: {exc.reason}") from exc

    status = body.get("status")
    if status != "ok":
        error = body.get("error", {})
        raise RuntimeError(f"AcoustID error: {error.get('message', status)}")

    results = body.get("results") or []
    _log.debug("track_id: AcoustID returned %d result(s)", len(results))
    return results


def _best_recording(results: list[dict]) -> Optional[dict]:
    """Return the recording with the highest AcoustID score, or None."""
    best_score = -1.0
    best_rec = None
    for entry in results:
        score = float(entry.get("score", 0.0))
        recordings = entry.get("recordings") or []
        for rec in recordings:
            if score > best_score:
                best_score = score
                best_rec = dict(rec)
                best_rec["_acoustid_score"] = score
    return best_rec


# ---------------------------------------------------------------------------
# MusicBrainz metadata enrichment
# ---------------------------------------------------------------------------

def _mb_api_get(path: str, timeout: float) -> dict:
    """Fetch a MusicBrainz API resource and return the parsed JSON dict."""
    global _mb_last_call
    import json

    elapsed = time.monotonic() - _mb_last_call
    if elapsed < _MB_RATE_LIMIT_DELAY:
        time.sleep(_MB_RATE_LIMIT_DELAY - elapsed)

    url = f"{_MB_API_BASE}/{path}"
    _log.debug("track_id: MusicBrainz lookup: %s", path.split("?")[0])
    req = urllib.request.Request(
        url,
        headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
    )
    _mb_last_call = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"MusicBrainz HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"MusicBrainz network error: {exc.reason}") from exc


def _enrich_from_musicbrainz(
    recording_id: str,
    timeout: float,
) -> dict:
    """Return normalized metadata dict from MusicBrainz for a recording ID."""
    path = (
        f"recording/{recording_id}"
        "?inc=artists+releases+release-groups&fmt=json"
    )
    data = _mb_api_get(path, timeout)

    title = str(data.get("title") or "").strip()
    artist = ""
    artist_credit = data.get("artist-credit") or []
    if artist_credit:
        artist = "".join(
            str(a.get("name") or a.get("artist", {}).get("name", ""))
            + str(a.get("joinphrase") or "")
            for a in artist_credit
        ).strip()

    # Pick the first release for release-level artwork and album name.
    releases = data.get("releases") or []
    release_id = ""
    release_group_id = ""
    album = ""
    if releases:
        r = releases[0]
        release_id = str(r.get("id") or "")
        album = str(r.get("title") or "").strip()
        rg = r.get("release-group") or {}
        release_group_id = str(rg.get("id") or "")

    return {
        "title": title,
        "artist": artist,
        "album": album,
        "release_id": release_id,
        "release_group_id": release_group_id,
    }


def _extract_recording_info(recording: dict) -> dict:
    """Extract title/artist/album/release info from an AcoustID recording entry."""
    title = str(recording.get("title") or "").strip()

    artists = recording.get("artists") or []
    artist = " & ".join(
        str(a.get("name") or "") for a in artists if a.get("name")
    ).strip()

    releases = recording.get("releases") or []
    release_id = ""
    release_group_id = ""
    album = ""
    if releases:
        r = releases[0]
        release_id = str(r.get("id") or "")
        album = str(r.get("title") or "").strip()
        # release-group ID may be nested inside the release entry.
        rg = r.get("releasegroups") or r.get("release-group") or {}
        if isinstance(rg, list) and rg:
            rg = rg[0]
        release_group_id = str(rg.get("id") if isinstance(rg, dict) else "")

    # AcoustID also returns a top-level releasegroups list on the recording when
    # the "releasegroups" meta flag is requested.  Use it as a fallback for the
    # release-group ID (needed for Cover Art Archive lookups).
    if not release_group_id:
        rec_rgs = recording.get("releasegroups") or []
        if rec_rgs:
            release_group_id = str(rec_rgs[0].get("id") or "")

    return {
        "title": title,
        "artist": artist,
        "album": album,
        "release_id": release_id,
        "release_group_id": release_group_id,
    }


# ---------------------------------------------------------------------------
# Cover Art Archive
# ---------------------------------------------------------------------------

def _resolve_artwork(
    release_id: str,
    release_group_id: str,
    timeout: float,
) -> Optional[TrackArtwork]:
    """Try release front art, then release-group front art, then give up."""
    url = _caa_thumbnail_url(release_id, release_group_id, timeout)
    if url:
        return TrackArtwork(url=url, source="cover_art_archive")
    return None


def _caa_thumbnail_url(
    release_id: str,
    release_group_id: str,
    timeout: float,
) -> str:
    """Return the 250px front thumbnail URL, or '' if none found."""
    for kind, rid in (("release", release_id), ("release-group", release_group_id)):
        if not rid:
            continue
        url = f"{_CAA_BASE}/{kind}/{rid}/front-250"
        _log.debug("track_id: Cover Art Archive %s %s", kind, rid)
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": _USER_AGENT},
                method="HEAD",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                final_url = resp.url or url
                return str(final_url)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                _log.debug("track_id: CAA %s %s → 404", kind, rid)
                continue
            _log.warning("track_id: CAA HTTP %s for %s %s", exc.code, kind, rid)
            continue
        except Exception as exc:
            _log.warning("track_id: CAA lookup failed: %s", exc)
            continue
    return ""


# ---------------------------------------------------------------------------
# Provider class
# ---------------------------------------------------------------------------

class AcoustIDMusicBrainzProvider:
    """Track identification provider using AcoustID + MusicBrainz + Cover Art Archive."""

    provider_id = PROVIDER_ID

    def __init__(self, settings: dict) -> None:
        self._api_key = str((settings or {}).get("api_key", "") or "").strip()

    def fingerprint_pcm(self, pcm16_mono: bytes, sample_rate: int) -> Optional[str]:
        """Return the Chromaprint fingerprint string, or None on failure."""
        try:
            _, fp = _fingerprint_raw_pcm(pcm16_mono, sample_rate)
            return fp
        except Exception:
            return None

    def identify(
        self,
        pcm16_mono: bytes,
        sample_rate: int,
        *,
        timeout: Optional[float] = None,
    ) -> TrackIdentificationResult:
        if not self._api_key:
            _log.warning(
                "track_id: AcoustID API key not configured; identification skipped."
            )
            return TrackIdentificationResult(
                matched=False,
                provider=PROVIDER_ID,
                source_detail="no_api_key",
                is_configuration_error=True,
            )

        _timeout = float(timeout) if timeout is not None else _DEFAULT_TIMEOUT

        duration = _compute_duration(pcm16_mono, sample_rate)
        if duration < _MIN_DURATION_S:
            _log.debug(
                "track_id: PCM too short (%.1f s < %.1f s); skipping.", duration, _MIN_DURATION_S
            )
            return TrackIdentificationResult(matched=False, provider=PROVIDER_ID)

        # 1. Fingerprint.
        try:
            duration, fingerprint = _fingerprint_raw_pcm(pcm16_mono, sample_rate)
        except ImportError:
            _log.warning(
                "track_id: acoustid library not available. "
                "Install python3-acoustid and libchromaprint-tools."
            )
            raise
        except Exception as exc:
            _log.warning("track_id: fingerprinting failed: %s", exc)
            raise

        # 2. AcoustID lookup.
        results = _acoustid_lookup(fingerprint, duration, self._api_key, _timeout)
        if not results:
            return TrackIdentificationResult(matched=False, provider=PROVIDER_ID)

        recording = _best_recording(results)
        if recording is None:
            return TrackIdentificationResult(matched=False, provider=PROVIDER_ID)

        score = float(recording.get("_acoustid_score", 0.0))
        recording_id = str(recording.get("id") or "")

        # 3. Extract or enrich metadata.
        info = _extract_recording_info(recording)
        # Enrich from MusicBrainz when title/artist are missing OR when we lack
        # release IDs (needed for Cover Art Archive lookups).
        if recording_id and (
            not info["title"]
            or not info["artist"]
            or not info["release_id"]
        ):
            try:
                mb_info = _enrich_from_musicbrainz(recording_id, _timeout)
                for key in ("title", "artist", "album", "release_id", "release_group_id"):
                    if not info[key] and mb_info.get(key):
                        info[key] = mb_info[key]
            except Exception as exc:
                _log.warning("track_id: MusicBrainz enrichment failed: %s", exc)

        # 4. Resolve artwork.
        artwork: Optional[TrackArtwork] = None
        if info.get("release_id") or info.get("release_group_id"):
            try:
                artwork = _resolve_artwork(
                    info.get("release_id", ""),
                    info.get("release_group_id", ""),
                    _timeout,
                )
            except Exception as exc:
                _log.warning("track_id: artwork lookup failed: %s", exc)

        external_ids: dict[str, str] = {}
        if recording_id:
            external_ids["musicbrainz_recording"] = recording_id
        if info.get("release_id"):
            external_ids["musicbrainz_release"] = info["release_id"]

        _log.debug(
            "track_id: result — title=%r artist=%r album=%r artwork=%s score=%.2f",
            info["title"], info["artist"], info["album"],
            artwork.url if artwork else "none",
            score,
        )

        return TrackIdentificationResult(
            matched=True,
            title=info["title"],
            artist=info["artist"],
            album=info["album"],
            artwork=artwork,
            provider=PROVIDER_ID,
            confidence=score,
            external_ids=external_ids,
        )
