#!/usr/bin/env python3
"""High-level player service built on top of autostream_players."""

from __future__ import annotations

from dataclasses import dataclass
import logging
import threading
import time
from typing import Optional, Any

from autostream_players import (
    ActionResult,
    BACKEND_OWNTONE,
    BackendCapabilities,
    BackendStatus,
    GetOutputResult,
    ListOutputsResult,
    OUTPUT_MODE_AIRPLAY1,
    OUTPUT_MODE_AIRPLAY2,
    OUTPUT_MODE_AUTO,
    OutputInfo,
    PlaybackMetadata,
    SaveSettingResult,
    SETTING_LOG_LEVEL,
    SettingDescriptor,
    SettingValueResult,
    create_backend,
    detect_backend,
)


_CACHE_LOCK = threading.Lock()
_DETECTION_CACHE_SECONDS = 5.0
_DETECTION_CACHE_MAX_ENTRIES = 16
_DETECTION_CACHE: dict[str, tuple[float, str]] = {}
LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class ResolvedBackend:
    backend_id: str
    backend: Any


def _normalize_base_url(base_url: str) -> str:
    return (str(base_url or "").strip() or "http://localhost:3689").rstrip("/")


def resolve_backend(base_url: str, *, timeout: float = 3.0) -> ResolvedBackend:
    normalized_base_url = _normalize_base_url(base_url)

    with _CACHE_LOCK:
        cached = _DETECTION_CACHE.get(normalized_base_url)
        if cached and (time.monotonic() - cached[0]) <= _DETECTION_CACHE_SECONDS:
            backend_id = cached[1]
            LOG.debug(
                "Playback backend cache hit for %s: backend=%s age=%.2fs",
                normalized_base_url,
                backend_id,
                time.monotonic() - cached[0],
            )
            return ResolvedBackend(
                backend_id=backend_id,
                backend=create_backend(backend_id, base_url=normalized_base_url, timeout=timeout),
            )

    LOG.info(
        "Resolving playback backend for %s (timeout=%.1fs)",
        normalized_base_url,
        timeout,
    )
    backend, detections = detect_backend(normalized_base_url, timeout=timeout)
    for detection in detections:
        level = logging.INFO if detection.matched else logging.DEBUG
        LOG.log(
            level,
            "Playback backend probe for %s: candidate=%s matched=%s detail=%s",
            normalized_base_url,
            detection.backend_id,
            detection.matched,
            detection.detail or "-",
        )
    if backend is None:
        LOG.info(
            "No playback backend probe matched for %s; falling back to backend=%s",
            normalized_base_url,
            BACKEND_OWNTONE,
        )
        backend = create_backend(BACKEND_OWNTONE, base_url=normalized_base_url, timeout=timeout)
    backend_id = backend.backend_id
    LOG.info(
        "Playback backend selected for %s: backend=%s",
        normalized_base_url,
        backend_id,
    )

    with _CACHE_LOCK:
        if len(_DETECTION_CACHE) >= _DETECTION_CACHE_MAX_ENTRIES:
            # Evict the oldest entry to keep the dict bounded.
            oldest_key = min(_DETECTION_CACHE, key=lambda k: _DETECTION_CACHE[k][0])
            LOG.debug(
                "Evicting playback backend cache entry for %s to keep cache bounded",
                oldest_key,
            )
            del _DETECTION_CACHE[oldest_key]
        _DETECTION_CACHE[normalized_base_url] = (time.monotonic(), backend_id)
        LOG.debug(
            "Cached playback backend selection for %s: backend=%s ttl=%.1fs",
            normalized_base_url,
            backend_id,
            _DETECTION_CACHE_SECONDS,
        )

    return ResolvedBackend(backend_id=backend_id, backend=backend)


def list_outputs(base_url: str, *, timeout: float = 3.0) -> ListOutputsResult:
    return resolve_backend(base_url, timeout=timeout).backend.list_outputs()


def get_output(base_url: str, output_id: str, *, timeout: float = 3.0) -> GetOutputResult:
    return resolve_backend(base_url, timeout=timeout).backend.get_output(output_id)


def get_output_by_name(base_url: str, output_name: str, *, timeout: float = 3.0) -> Optional[OutputInfo]:
    wanted = str(output_name or "").strip()
    if not wanted:
        return None
    result = list_outputs(base_url, timeout=timeout)
    if not result.ok:
        return None
    for output in result.outputs:
        if str(output.name or "").strip() == wanted:
            return output
    return None


def set_output_enabled(base_url: str, output_id: str, enabled: bool, *, timeout: float = 3.0) -> ActionResult:
    return resolve_backend(base_url, timeout=timeout).backend.set_output_enabled(output_id, enabled)


def set_selected_outputs(base_url: str, output_ids: list[str], *, timeout: float = 3.0) -> ActionResult:
    return resolve_backend(base_url, timeout=timeout).backend.set_selected_outputs(output_ids)


def set_output_volume(base_url: str, output_id: str, volume_percent: int, *, timeout: float = 3.0) -> ActionResult:
    return resolve_backend(base_url, timeout=timeout).backend.set_output_volume(output_id, volume_percent)


def set_output_offset(base_url: str, output_id: str, offset_ms: int, *, timeout: float = 3.0) -> ActionResult:
    return resolve_backend(base_url, timeout=timeout).backend.set_output_offset(output_id, offset_ms)


def submit_output_pin(base_url: str, output_id: str, pin: str, *, timeout: float = 3.0) -> ActionResult:
    return resolve_backend(base_url, timeout=timeout).backend.submit_output_pin(output_id, pin)


def set_output_mode(base_url: str, output_id: str, mode: str, *, timeout: float = 3.0) -> ActionResult:
    return resolve_backend(base_url, timeout=timeout).backend.set_output_mode(output_id, mode)


def play(base_url: str, *, timeout: float = 3.0) -> ActionResult:
    return resolve_backend(base_url, timeout=timeout).backend.play()


def stop(base_url: str, *, timeout: float = 3.0) -> ActionResult:
    return resolve_backend(base_url, timeout=timeout).backend.stop()


def stop_and_disable_all(base_url: str, *, timeout: float = 3.0) -> ActionResult:
    stop_result = stop(base_url, timeout=timeout)
    disable_result = set_selected_outputs(base_url, [], timeout=timeout)
    if stop_result.ok and disable_result.ok:
        return ActionResult(ok=True)
    errors = [r.error for r in (stop_result, disable_result) if not r.ok and r.error]
    codes = [r.error_code for r in (stop_result, disable_result) if not r.ok and r.error_code]
    return ActionResult(
        ok=False,
        error="; ".join(errors) or "Failed to stop playback and disable outputs",
        error_code=codes[0] if codes else "compound_error",
        detail="; ".join(
            f"{label}: {r.detail}"
            for label, r in (("stop", stop_result), ("disable", disable_result))
            if not r.ok and r.detail
        ),
    )


def ensure_pipe_source_ready(base_url: str, *, timeout: float = 3.0) -> ActionResult:
    return resolve_backend(base_url, timeout=timeout).backend.ensure_pipe_source_ready()


def refresh_runtime_state(base_url: str, *, timeout: float = 3.0) -> ActionResult:
    return resolve_backend(base_url, timeout=timeout).backend.refresh_runtime_state()


def get_status(base_url: str, *, timeout: float = 3.0) -> BackendStatus:
    return resolve_backend(base_url, timeout=timeout).backend.get_status()


def get_capabilities(base_url: str, *, timeout: float = 3.0) -> BackendCapabilities:
    return resolve_backend(base_url, timeout=timeout).backend.get_capabilities()


def get_setting(base_url: str, key: str, *, timeout: float = 3.0) -> SettingValueResult:
    return resolve_backend(base_url, timeout=timeout).backend.get_setting(key)


def save_setting(base_url: str, key: str, value: Any, *, timeout: float = 3.0) -> SaveSettingResult:
    return resolve_backend(base_url, timeout=timeout).backend.save_setting(key, value)


def list_supported_settings(base_url: str, *, timeout: float = 3.0) -> list[SettingDescriptor]:
    return resolve_backend(base_url, timeout=timeout).backend.list_supported_settings()


def push_metadata(base_url: str, *, title: str = "", artist: str = "", album: str = "", artwork_url: str = "", timeout: float = 3.0) -> ActionResult:
    metadata = PlaybackMetadata(
        title=str(title or ""),
        artist=str(artist or ""),
        album=str(album or ""),
        artwork_url=str(artwork_url or ""),
    )
    return resolve_backend(base_url, timeout=timeout).backend.push_metadata(metadata)


def save_log_level(base_url: str, level_name: str, *, timeout: float = 3.0):
    return save_setting(base_url, SETTING_LOG_LEVEL, level_name, timeout=timeout)


def config_airplay_mode_to_backend(mode: object) -> str:
    text = str(mode or "").strip().lower()
    if text == "raop":
        return OUTPUT_MODE_AIRPLAY1
    if text == "airplay2":
        return OUTPUT_MODE_AIRPLAY2
    return OUTPUT_MODE_AUTO


def backend_output_mode_to_config(mode: object) -> str:
    text = str(mode or "").strip().lower()
    if text == OUTPUT_MODE_AIRPLAY1:
        return "raop"
    if text == OUTPUT_MODE_AIRPLAY2:
        return "airplay2"
    return "default"


def output_supported_config_modes(output: OutputInfo) -> tuple[str, ...]:
    config_modes: list[str] = []
    for mode in output.supported_modes or (OUTPUT_MODE_AUTO,):
        mapped = backend_output_mode_to_config(mode)
        if mapped not in config_modes:
            config_modes.append(mapped)
    return tuple(config_modes)
