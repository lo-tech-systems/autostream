#!/usr/bin/env python3
"""High-level player service built on top of autostream_players."""

from __future__ import annotations

from dataclasses import dataclass
import logging
import os
import stat
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
    SETTING_PIPE_PATH,
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


@dataclass(frozen=True)
class FifoEnsureResult:
    ok: bool
    created_dir: bool = False
    created_fifo: bool = False
    error: str = ""
    error_code: str = ""


@dataclass(frozen=True)
class FifoReconcileResult:
    ok: bool
    created_dir: bool = False
    created_fifo: bool = False
    backend_setting_checked: bool = False
    backend_setting_supported: bool = False
    backend_setting_changed: bool = False
    refresh_attempted: bool = False
    refresh_succeeded: bool = False
    error: str = ""
    error_code: str = ""
    detail: str = ""


def _normalize_base_url(base_url: str) -> str:
    return (str(base_url or "").strip() or "http://localhost:3689").rstrip("/")


def ensure_audio_fifo(path: str) -> FifoEnsureResult:
    """Ensure the configured backend audio FIFO exists and is a named pipe."""
    try:
        if not path or not os.path.isabs(path):
            return FifoEnsureResult(
                ok=False,
                error=f"Configured fifo_path must be an absolute path: {path!r}",
                error_code="invalid_path",
            )

        created_dir = False
        fifo_dir = os.path.dirname(path)
        if fifo_dir:
            created_dir = not os.path.isdir(fifo_dir)
            os.makedirs(fifo_dir, mode=0o777, exist_ok=True)

        if os.path.exists(path):
            st = os.stat(path)
            if not stat.S_ISFIFO(st.st_mode):
                return FifoEnsureResult(
                    ok=False,
                    created_dir=created_dir,
                    error=f"Configured fifo_path exists but is not a FIFO: {path!r}",
                    error_code="not_fifo",
                )
            return FifoEnsureResult(ok=True, created_dir=created_dir)

        os.mkfifo(path, 0o666)
        return FifoEnsureResult(ok=True, created_dir=created_dir, created_fifo=True)
    except Exception as exc:
        return FifoEnsureResult(
            ok=False,
            error=f"Could not create audio FIFO {path!r}: {exc}",
            error_code="create_failed",
        )


def _request_library_update_with_retry(
    backend: Any,
    base_url: str,
    *,
    timeout_s: float = 30.0,
    interval_s: float = 5.0,
) -> ActionResult:
    """Request a backend update, retrying briefly during cold start."""
    deadline = time.monotonic() + max(0.0, float(timeout_s))
    attempt = 0

    while True:
        attempt += 1
        result = backend.request_library_update()
        if result.ok:
            LOG.info(
                "Playback backend update accepted for %s after %d attempt(s).",
                base_url,
                attempt,
            )
            return result

        if result.error_code == "unsupported":
            LOG.info(
                "Playback backend %s does not support update requests for %s.",
                getattr(backend, "backend_id", "unknown"),
                base_url,
            )
            return result

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return result

        LOG.info(
            "Playback backend update for %s not ready yet; retrying in %.1f s (%s).",
            base_url,
            interval_s,
            result.error or result.detail or result.error_code or "request failed",
        )
        time.sleep(min(float(interval_s), max(0.0, remaining)))


def reconcile_fifo_with_backend(
    base_url: str,
    fifo_path: str,
    *,
    timeout: float = 3.0,
    update_timeout_s: float = 30.0,
    update_interval_s: float = 5.0,
) -> FifoReconcileResult:
    """Ensure the local FIFO exists and align backend pipe-path state if possible."""
    fifo_result = ensure_audio_fifo(fifo_path)
    if not fifo_result.ok:
        return FifoReconcileResult(
            ok=False,
            created_dir=fifo_result.created_dir,
            created_fifo=fifo_result.created_fifo,
            error=fifo_result.error,
            error_code=fifo_result.error_code,
        )

    if fifo_result.created_dir:
        LOG.info("Created audio FIFO directory at %s", os.path.dirname(fifo_path))
    if fifo_result.created_fifo:
        LOG.info("Created audio FIFO at %s", fifo_path)

    base_url_text = str(base_url or "").strip()
    if not base_url_text:
        return FifoReconcileResult(
            ok=True,
            created_dir=fifo_result.created_dir,
            created_fifo=fifo_result.created_fifo,
        )

    resolved = resolve_backend(base_url_text, timeout=timeout)
    backend = resolved.backend
    setting_changed = False
    setting_checked = False
    setting_supported = False
    warning_error = ""
    warning_error_code = ""
    warning_detail = ""

    setting_result = backend.get_setting(SETTING_PIPE_PATH)
    if setting_result.unsupported or setting_result.error_code == "unsupported":
        setting_checked = True
        LOG.debug(
            "Playback backend %s does not expose pipe-path inspection at %s; continuing.",
            resolved.backend_id,
            base_url_text,
        )
    elif setting_result.ok:
        setting_checked = True
        setting_supported = True
        backend_fifo_path = str(setting_result.value or "").strip()
        wanted_fifo_path = str(fifo_path or "").strip()
        if backend_fifo_path == wanted_fifo_path:
            LOG.debug(
                "Playback backend %s pipe path already matches configured FIFO at %s.",
                resolved.backend_id,
                base_url_text,
            )
        else:
            save_result = backend.save_setting(SETTING_PIPE_PATH, wanted_fifo_path)
            if not save_result.ok:
                LOG.warning(
                    "Could not update playback backend %s pipe path at %s: %s",
                    resolved.backend_id,
                    base_url_text,
                    save_result.error or save_result.error_code or "save failed",
                )
                warning_error = save_result.error or "Failed to save backend FIFO path"
                warning_error_code = save_result.error_code or "save_failed"
                warning_detail = save_result.detail
            else:
                setting_changed = True
                LOG.info(
                    "Updated playback backend %s pipe path from %r to %r at %s.",
                    resolved.backend_id,
                    backend_fifo_path,
                    wanted_fifo_path,
                    base_url_text,
                )
                if save_result.restart_required:
                    LOG.warning(
                        "Playback backend %s still reported restart_required after pipe-path update at %s.",
                        resolved.backend_id,
                        base_url_text,
                    )
    else:
        LOG.warning(
            "Could not read playback backend %s pipe path at %s: %s",
            resolved.backend_id,
            base_url_text,
            setting_result.error or setting_result.error_code or "read failed",
        )
        warning_error = setting_result.error or "Failed to read backend FIFO path"
        warning_error_code = setting_result.error_code or "read_failed"

    should_refresh = bool(fifo_result.created_fifo or setting_changed)
    if not should_refresh:
        return FifoReconcileResult(
            ok=True,
            created_dir=fifo_result.created_dir,
            created_fifo=fifo_result.created_fifo,
            backend_setting_checked=setting_checked,
            backend_setting_supported=setting_supported,
            backend_setting_changed=setting_changed,
            error=warning_error,
            error_code=warning_error_code,
            detail=warning_detail,
        )

    update_result = _request_library_update_with_retry(
        backend,
        base_url_text,
        timeout_s=update_timeout_s,
        interval_s=update_interval_s,
    )
    if not update_result.ok and update_result.error_code != "unsupported":
        LOG.warning(
            "Could not request playback backend update for %s: %s",
            base_url_text,
            update_result.error or update_result.detail or update_result.error_code or "update failed",
        )
        return FifoReconcileResult(
            ok=True,
            created_dir=fifo_result.created_dir,
            created_fifo=fifo_result.created_fifo,
            backend_setting_checked=setting_checked,
            backend_setting_supported=setting_supported,
            backend_setting_changed=setting_changed,
            refresh_attempted=True,
            refresh_succeeded=False,
            error=update_result.error or warning_error or "Failed to request backend update",
            error_code=update_result.error_code or warning_error_code or "update_failed",
            detail=update_result.detail or warning_detail,
        )

    return FifoReconcileResult(
        ok=True,
        created_dir=fifo_result.created_dir,
        created_fifo=fifo_result.created_fifo,
        backend_setting_checked=setting_checked,
        backend_setting_supported=setting_supported,
        backend_setting_changed=setting_changed,
        refresh_attempted=True,
        refresh_succeeded=update_result.ok,
        error=warning_error,
        error_code=warning_error_code,
        detail=update_result.detail or warning_detail,
    )


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

    LOG.debug(
        "Resolving playback backend for %s (timeout=%.1fs)",
        normalized_base_url,
        timeout,
    )
    backend, detections = detect_backend(normalized_base_url, timeout=timeout)
    for detection in detections:
        LOG.debug(
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
    LOG.debug(
        "Playback backend selected for %s: backend=%s",
        normalized_base_url,
        backend_id,
    )

    with _CACHE_LOCK:
        if len(_DETECTION_CACHE) >= _DETECTION_CACHE_MAX_ENTRIES:
            # Evict the oldest entry to keep the dict bounded.
            # Dict insertion order is guaranteed (Python 3.7+), so the first key is oldest.
            oldest_key = next(iter(_DETECTION_CACHE))
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


def update_output(
    base_url: str,
    output_id: str,
    *,
    enabled: bool | None = None,
    volume_percent: int | None = None,
    offset_ms: int | None = None,
    mode: str | None = None,
    timeout: float = 3.0,
) -> ActionResult:
    return resolve_backend(base_url, timeout=timeout).backend.update_output(
        output_id,
        enabled=enabled,
        volume_percent=volume_percent,
        offset_ms=offset_ms,
        mode=mode,
    )


def submit_output_pin(base_url: str, output_id: str, pin: str, *, timeout: float = 3.0) -> ActionResult:
    return resolve_backend(base_url, timeout=timeout).backend.submit_output_pin(output_id, pin)


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


def request_library_update(base_url: str, *, timeout: float = 3.0) -> ActionResult:
    return resolve_backend(base_url, timeout=timeout).backend.request_library_update()


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
