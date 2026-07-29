#!/usr/bin/env python3
"""autostream_players.py

Backend-neutral player interface for autostream.

This module defines the small surface area that autostream should depend on
when talking to a playback/output backend. Concrete implementations can then
adapt different players, API variants, or config-file-backed fallbacks behind
this interface.

Initial backend identifiers:
  - owntone
  - owntone-mini
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import logging
from typing import Any, Optional

import requests

# Single seam for HTTP calls to the playback backend (owntone / owntone-mini):
# tests patch _session.get/_session.put at this one point. Deliberately the
# plain requests module (a fresh connection per call) rather than a pooled
# requests.Session -- owntone restarts are routine here (format reconciles
# trigger them), and a pooled keep-alive socket would turn each restart into a
# stale-connection error on the next call. The urllib3 connection-setup log
# lines this would have avoided are already pinned to WARNING in setup_logging.
_session = requests


BACKEND_OWNTONE = "owntone"
BACKEND_OWNTONE_MINI = "owntone-mini"

KNOWN_BACKEND_IDS = (
    BACKEND_OWNTONE,
    BACKEND_OWNTONE_MINI,
)

PREFERRED_DETECTION_ORDER = (
    BACKEND_OWNTONE_MINI,
    BACKEND_OWNTONE,
)


# Normalized autostream-facing setting keys. Implementations are responsible
# for mapping these onto backend-specific API endpoints or config storage.
SETTING_LOG_LEVEL = "log_level"
SETTING_PIPE_AUTOSTART = "pipe_autostart"
SETTING_PIPE_PATH = "pipe_path"
SETTING_START_BUFFER_MS = "start_buffer_ms"
SETTING_UNCOMPRESSED_ALAC = "uncompressed_alac"
SETTING_BUFFERED_AUDIO_ENABLED = "buffered_audio_enabled"
SETTING_IPV6 = "ipv6"
SETTING_DEVICE_REMOVAL_GRACE_PERIOD = "device_removal_grace_period"
# Restart-required pipe-format keys: mirror owntone_config.c's flat
# "pipe_sample_rate" / "pipe_bits_per_sample" keys exactly so the reconcile in
# autostream_player_service.py can push the monitor's reported output format
# straight through without a name translation layer.
SETTING_PIPE_SAMPLE_RATE = "pipe_sample_rate"
SETTING_PIPE_BITS_PER_SAMPLE = "pipe_bits_per_sample"
# Output-resampler quality knob, an owntone-mini extension (no restart
# required -- read at filtergraph creation, so a change takes effect on the
# next playback session). Full/stock OwnTone has no normalized-settings
# surface at all (see OwnToneBackend.get_setting/save_setting), so a push
# against it is naturally absorbed as "unsupported" by the same mechanism
# that already covers every other setting key on that backend.
SETTING_RESAMPLE_QUALITY = "resample_quality"
SETTING_RESAMPLE_QUALITY_ALLOWED = ("high", "standard")

# Valid range and UI step for SETTING_START_BUFFER_MS.
SETTING_START_BUFFER_MS_MIN = 300
SETTING_START_BUFFER_MS_MAX = 3500
SETTING_START_BUFFER_MS_STEP = 50
SETTING_START_BUFFER_MS_DEFAULT = 2250

# Allowed value sets for the pipe-format settings, mirroring the validation
# owntone-mini enforces at owntone_config.c ~730-738 (which itself mirrors
# pipe.c's accepted sets at init) -- kept here so callers can pre-validate
# without a round trip, though owntone-mini remains the source of truth.
SETTING_PIPE_SAMPLE_RATE_ALLOWED = (44100, 48000, 88200, 96000)
SETTING_PIPE_BITS_PER_SAMPLE_ALLOWED = (16, 32)

# Valid range (in minutes) for SETTING_DEVICE_REMOVAL_GRACE_PERIOD UI control.
# The API stores and accepts values in seconds; the UI presents minutes.
SETTING_DEVICE_REMOVAL_GRACE_PERIOD_MIN_MINUTES = 1
SETTING_DEVICE_REMOVAL_GRACE_PERIOD_MAX_MINUTES = 15
SETTING_DEVICE_REMOVAL_GRACE_PERIOD_DEFAULT_MINUTES = 2


# Normalized output mode names used by autostream.
OUTPUT_MODE_AUTO = "auto"
OUTPUT_MODE_AIRPLAY1 = "airplay1"
OUTPUT_MODE_AIRPLAY2 = "airplay2"
OUTPUT_MODE_AIRPLAY2_BUFFERED = "airplay2_buffered"
OUTPUT_MODE_AIRPLAY2_SURROUND_STEREO = "airplay2_surround_stereo"
OUTPUT_MODE_AIRPLAY2_SURROUND_UPMIX = "airplay2_surround_upmix"


@dataclass(frozen=True)
class DetectionResult:
    """Result of probing whether a backend matches the current target."""

    matched: bool
    backend_id: str
    detail: str = ""
    version: str = ""


@dataclass(frozen=True)
class ActionResult:
    """Result for a generic backend action."""

    ok: bool
    error: str = ""
    error_code: str = ""
    restart_required: bool = False
    detail: str = ""

    @property
    def message(self) -> str:
        return self.error or self.detail or self.error_code


@dataclass(frozen=True)
class SettingValueResult:
    """Read result for a normalized backend setting."""

    ok: bool
    value: Optional[Any] = None
    unsupported: bool = False
    error: str = ""
    error_code: str = ""

    @property
    def message(self) -> str:
        return self.error or self.error_code


@dataclass(frozen=True)
class SaveSettingResult:
    """Write result for a normalized backend setting."""

    ok: bool
    applied_live: bool = False
    saved_persistently: bool = False
    restart_required: bool = False
    unsupported: bool = False
    error: str = ""
    error_code: str = ""

    @property
    def message(self) -> str:
        return self.error or self.error_code


@dataclass(frozen=True)
class SettingDescriptor:
    """Describes a normalized setting supported by a backend."""

    key: str
    value_type: str
    label: str = ""
    writable: bool = True
    requires_restart_on_change: bool = False
    min_value: Optional[int] = None
    max_value: Optional[int] = None
    allowed_values: tuple[str, ...] = ()


@dataclass(frozen=True)
class BackendCapabilities:
    """Feature flags exposed by a backend implementation."""

    can_list_outputs: bool = False
    can_get_output: bool = False
    can_set_output_enabled: bool = False
    can_set_selected_outputs: bool = False
    can_set_output_volume: bool = False
    can_set_output_offset: bool = False
    can_submit_output_pin: bool = False
    can_set_output_mode: bool = False
    can_play: bool = False
    can_stop: bool = False
    can_ensure_pipe_source_ready: bool = False
    can_refresh_runtime_state: bool = False
    can_push_metadata: bool = False
    can_restart: bool = False
    can_request_library_update: bool = False
    supports_runtime_settings: bool = False
    supports_restart_required_reporting: bool = False
    supported_setting_keys: tuple[str, ...] = ()


@dataclass(frozen=True)
class OutputInfo:
    """Normalized output model used by autostream."""

    id: str
    name: str
    type: str = ""
    selected: bool = False
    volume_percent: int = 0
    offset_ms: Optional[int] = None
    has_password: bool = False
    requires_auth: bool = False
    needs_auth_key: bool = False
    available: bool = True
    current_mode: str = OUTPUT_MODE_AUTO
    supported_modes: tuple[str, ...] = ()
    extra: tuple[tuple[str, Any], ...] = ()

    def extra_dict(self) -> dict[str, Any]:
        """Return extra metadata as a plain dict when needed."""
        return dict(self.extra)


@dataclass(frozen=True)
class ListOutputsResult:
    """Result of enumerating backend outputs."""

    ok: bool
    outputs: tuple[OutputInfo, ...] = ()
    error: str = ""
    error_code: str = ""


@dataclass(frozen=True)
class GetOutputResult:
    """Result of fetching a single backend output."""

    ok: bool
    output: Optional[OutputInfo] = None
    error: str = ""
    error_code: str = ""


@dataclass(frozen=True)
class BackendStatus:
    """Coarse status for a playback backend."""

    ok: bool
    reachable: bool = True
    ready: bool = True
    restart_required: bool = False
    detail: str = ""


@dataclass(frozen=True)
class PlaybackMetadata:
    """Track metadata that may be pushed to outputs."""

    title: str = ""
    artist: str = ""
    album: str = ""
    artwork_url: str = ""


class PlayerBackend(ABC):
    """Abstract player backend interface for autostream."""

    @classmethod
    @abstractmethod
    def backend_id_cls(cls) -> str:
        """Return a stable backend identifier, e.g. 'owntone'."""

    @property
    def backend_id(self) -> str:
        return self.backend_id_cls()

    @abstractmethod
    def detect(self) -> DetectionResult:
        """Probe whether this backend matches the configured target."""

    @abstractmethod
    def get_capabilities(self) -> BackendCapabilities:
        """Return the feature set supported by this backend."""

    @abstractmethod
    def get_status(self) -> BackendStatus:
        """Return coarse backend health/readiness information."""

    @abstractmethod
    def restart(self) -> ActionResult:
        """Request a backend restart, if supported."""

    @abstractmethod
    def list_outputs(self) -> ListOutputsResult:
        """Return the currently known outputs."""

    @abstractmethod
    def get_output(self, output_id: str) -> GetOutputResult:
        """Return one output by id, or None if not found."""

    @abstractmethod
    def set_output_enabled(self, output_id: str, enabled: bool) -> ActionResult:
        """Enable or disable a single output."""

    @abstractmethod
    def set_selected_outputs(self, output_ids: list[str]) -> ActionResult:
        """Replace the selected output set."""

    @abstractmethod
    def set_output_volume(self, output_id: str, volume_percent: int) -> ActionResult:
        """Set one output's volume."""

    @abstractmethod
    def set_output_offset(self, output_id: str, offset_ms: int) -> ActionResult:
        """Set one output's timing offset."""

    @abstractmethod
    def update_output(
        self,
        output_id: str,
        *,
        enabled: Optional[bool] = None,
        volume_percent: Optional[int] = None,
        offset_ms: Optional[int] = None,
        mode: Optional[str] = None,
    ) -> ActionResult:
        """Update multiple fields on one output in a single backend request.

        mode should be a normalized backend mode string (e.g. OUTPUT_MODE_AUTO,
        OUTPUT_MODE_AIRPLAY1, OUTPUT_MODE_AIRPLAY2).  Backends that do not
        support mode must absorb an unsupported-mode condition internally:
        log at INFO and return ok=True rather than propagating a failure.
        """

    @abstractmethod
    def submit_output_pin(self, output_id: str, pin: str) -> ActionResult:
        """Submit an authorization PIN for an output."""

    @abstractmethod
    def play(self) -> ActionResult:
        """Start or resume playback if the backend supports it."""

    @abstractmethod
    def stop(self) -> ActionResult:
        """Stop playback."""

    @abstractmethod
    def ensure_pipe_source_ready(self) -> ActionResult:
        """Ensure the backend's pipe/FIFO source is available and usable."""

    @abstractmethod
    def refresh_runtime_state(self) -> ActionResult:
        """Re-apply selected runtime state after reconnect or restart."""

    @abstractmethod
    def request_library_update(self) -> ActionResult:
        """Request the backend to rescan or refresh its library state."""

    @abstractmethod
    def push_metadata(self, metadata: PlaybackMetadata) -> ActionResult:
        """Push metadata to active outputs if supported."""

    @abstractmethod
    def get_setting(self, key: str) -> SettingValueResult:
        """Read a normalized backend setting."""

    @abstractmethod
    def save_setting(self, key: str, value: Any) -> SaveSettingResult:
        """Save a normalized backend setting."""

    @abstractmethod
    def list_supported_settings(self) -> list[SettingDescriptor]:
        """Return normalized settings that this backend supports."""

    def required_monitor_format(self) -> Optional[str]:
        """Return the monitor pipe-input format this backend expects.

        One of:
          - ``"native"``     -- 48000 Hz / 32-bit / 2ch (autostream_monitor's
            default, no ``--compatible`` flag).
          - ``"compatible"`` -- 44100 Hz / 16-bit / 2ch (monitor started with
            ``--compatible``).
          - ``None``         -- unknown right now (e.g. the backend is
            unreachable). Callers MUST treat ``None`` as "take no
            enforcement action this pass", never as either concrete format.

        This is a concrete (non-abstract) method with a deliberate default
        of ``"compatible"``, not ``"native"``. That default is the safe
        answer for any backend that does not override it -- including
        third-party backends added after this contract existed (see
        docs/ADDING-AUDIO-BACKEND.md) and any adapter that has not been
        taught the native/compatible distinction. A compatible-mode
        monitor's 44.1kHz/16-bit wire format is what a fixed, un-configurable
        pipe input already expects (that is exactly the official OwnTone
        adapter's situation below), so it is universally consumable;
        defaulting to "native" instead would silently start feeding a
        48kHz/32-bit stream to a backend that never declared it could
        accept one. Backends that actually support/require the native
        format (e.g. a probed owntone-mini build with settable pipe-format
        keys) must override this method to say so.
        """
        return "compatible"


class PlayerBackendRegistry:
    """Simple registry for backend implementations."""

    def __init__(self) -> None:
        self._backend_classes: dict[str, type[PlayerBackend]] = {}

    def register(self, backend_cls: type[PlayerBackend]) -> None:
        backend_id = backend_cls.backend_id_cls()
        if not backend_id:
            raise ValueError("Backend class must implement backend_id_cls()")
        self._backend_classes[str(backend_id)] = backend_cls

    def backend_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._backend_classes.keys()))

    def create(self, backend_id: str, *args, **kwargs) -> PlayerBackend:
        try:
            backend_cls = self._backend_classes[backend_id]
        except KeyError as exc:
            raise KeyError(f"Unknown backend id: {backend_id}") from exc
        return backend_cls(*args, **kwargs)


REGISTRY = PlayerBackendRegistry()


def ensure_builtin_backends_registered() -> None:
    """Import built-in backend modules so they can self-register."""
    registered = set(REGISTRY.backend_ids())
    if BACKEND_OWNTONE in registered and BACKEND_OWNTONE_MINI in registered:
        return

    # Imported lazily to avoid circular imports during module initialization.
    try:
        import autostream_owntone  # noqa: F401
        import autostream_owntone_mini  # noqa: F401
    except ImportError:
        logging.exception("Failed to import built-in backend modules")


def create_backend(backend_id: str, *args, **kwargs) -> PlayerBackend:
    """Create one registered backend instance by id."""
    ensure_builtin_backends_registered()
    return REGISTRY.create(backend_id, *args, **kwargs)


def detect_backend(
    base_url: str = "http://localhost:3689",
    *,
    timeout: float = 3.0,
    preferred_backend_ids: Optional[tuple[str, ...]] = None,
) -> tuple[Optional[PlayerBackend], tuple[DetectionResult, ...]]:
    """Detect the first registered backend that matches the current target.

    Probes backends in preferred_backend_ids order (defaulting to
    PREFERRED_DETECTION_ORDER), then any remaining registered backends not
    already in that list.
    """
    ensure_builtin_backends_registered()

    ordered_ids: list[str] = []
    seen: set[str] = set()
    for backend_id in preferred_backend_ids or PREFERRED_DETECTION_ORDER:
        if backend_id and backend_id not in seen:
            ordered_ids.append(backend_id)
            seen.add(backend_id)
    for backend_id in REGISTRY.backend_ids():
        if backend_id not in seen:
            ordered_ids.append(backend_id)
            seen.add(backend_id)

    logging.debug(
        "Playback backend detection start for %s: probe_order=%s timeout=%.1fs",
        base_url,
        ",".join(ordered_ids) or "-",
        timeout,
    )

    detections: list[DetectionResult] = []
    for backend_id in ordered_ids:
        logging.debug(
            "Playback backend detection probing %s for %s",
            backend_id,
            base_url,
        )
        backend = REGISTRY.create(backend_id, base_url=base_url, timeout=timeout)
        detection = backend.detect()
        detections.append(detection)
        logging.debug(
            "Playback backend detection result for %s on %s: matched=%s detail=%s",
            backend_id,
            base_url,
            detection.matched,
            detection.detail or "-",
        )
        if detection.matched:
            logging.debug(
                "Playback backend detection matched %s for %s",
                backend_id,
                base_url,
            )
            return backend, tuple(detections)

    logging.info("Playback backend detection found no match for %s", base_url)
    return None, tuple(detections)


class OwnToneHttpBackendBase(PlayerBackend, ABC):
    """Shared HTTP helpers for OwnTone-flavoured backends."""

    def __init__(self, base_url: str = "http://localhost:3689", *, timeout: float = 3.0) -> None:
        self._base_url = (base_url or "http://localhost:3689").rstrip("/")
        self._timeout = float(timeout)
        self._log = logging.getLogger(type(self).__name__)

    def _unsupported_action(self, action: str) -> ActionResult:
        return ActionResult(
            ok=False,
            error=f"{action} is not supported by the {self.backend_id} backend",
            error_code="unsupported",
        )

    def _normalize_output_info(self, output: dict[str, Any]) -> OutputInfo:
        out_id = str(output.get("id") or "").strip()
        name = str(output.get("name") or out_id or "Unknown Output").strip()
        try:
            volume = int(output.get("volume", 0))
        except Exception:
            volume = 0
        volume = max(0, min(100, volume))

        offset_ms: Optional[int]
        if "offset_ms" in output:
            try:
                offset_ms = int(output.get("offset_ms"))
            except Exception:
                offset_ms = None
        else:
            offset_ms = None

        extra_items: list[tuple[str, Any]] = []
        if "format" in output:
            extra_items.append(("format", output.get("format")))
        if "supported_formats" in output and isinstance(output.get("supported_formats"), list):
            extra_items.append(("supported_formats", tuple(output.get("supported_formats") or ())))

        return OutputInfo(
            id=out_id,
            name=name,
            type=str(output.get("type") or "").strip(),
            selected=bool(output.get("selected")),
            volume_percent=volume,
            offset_ms=offset_ms,
            has_password=bool(output.get("has_password")),
            requires_auth=bool(output.get("requires_auth")),
            needs_auth_key=bool(output.get("needs_auth_key")),
            available=True,
            current_mode=OUTPUT_MODE_AUTO,
            supported_modes=(OUTPUT_MODE_AUTO,),
            extra=tuple(extra_items),
        )

    def _url(self, path: str) -> str:
        return self._base_url + path

    def _get_json(
        self,
        path: str,
    ) -> tuple[Optional[dict[str, Any]], Optional[requests.Response], str]:
        try:
            resp = _session.get(self._url(path), timeout=self._timeout)
        except requests.RequestException as exc:
            return None, None, str(exc)
        if not resp.content:
            return {}, resp, ""
        try:
            payload = resp.json()
        except ValueError:
            return None, resp, "Invalid JSON response"
        if isinstance(payload, dict):
            return payload, resp, ""
        return None, resp, "Unexpected JSON payload shape"

    def _put_json(
        self,
        path: str,
        payload: Optional[dict[str, Any]],
        *,
        success_statuses: tuple[int, ...],
    ) -> ActionResult:
        _payload, resp, err = self._put_json_for_response(path, payload, success_statuses=success_statuses)
        if resp is not None and resp.status_code not in success_statuses:
            return ActionResult(
                ok=False,
                error=f"Backend returned HTTP {resp.status_code}",
                error_code="http_error",
                detail=(resp.text or "").strip() or err,
            )
        if err:
            return ActionResult(ok=False, error="Backend request failed", error_code="request_failed", detail=err)
        return ActionResult(ok=True)

    def _put_json_for_response(
        self,
        path: str,
        payload: Optional[dict[str, Any]],
        *,
        success_statuses: tuple[int, ...],
    ) -> tuple[Optional[dict[str, Any]], Optional[requests.Response], str]:
        try:
            if payload is None:
                resp = _session.put(self._url(path), timeout=self._timeout)
            else:
                resp = _session.put(self._url(path), json=payload, timeout=self._timeout)
        except requests.RequestException as exc:
            return None, None, str(exc)

        if not resp.content:
            if resp.status_code in success_statuses:
                return {}, resp, ""
            return None, resp, f"Unexpected HTTP {resp.status_code} with empty response body"

        try:
            result_payload = resp.json()
        except ValueError:
            if resp.status_code in success_statuses:
                return None, resp, "Invalid JSON response"
            return None, resp, ""
        if isinstance(result_payload, dict):
            return result_payload, resp, ""
        if resp.status_code in success_statuses:
            return None, resp, "Unexpected JSON payload shape"
        return None, resp, ""

    def _put_output_fields(
        self,
        output_id: str,
        payload: dict[str, Any],
        *,
        allow_pin_invalid: bool = False,
        allow_pin_required: bool = False,
    ) -> ActionResult:
        if allow_pin_invalid and allow_pin_required:
            raise ValueError("allow_pin_invalid and allow_pin_required cannot both be True")

        out_id = str(output_id or "").strip()
        if not out_id:
            return ActionResult(ok=False, error="Missing output id", error_code="missing_output_id")

        _response_payload, resp, err = self._put_json_for_response(
            f"/api/outputs/{out_id}",
            payload,
            success_statuses=(204,),
        )
        if resp is not None and resp.status_code == 400:
            if allow_pin_invalid:
                return ActionResult(
                    ok=False,
                    error="PIN was rejected",
                    error_code="pin_invalid",
                    detail=(resp.text or "").strip(),
                )
            if allow_pin_required:
                return ActionResult(
                    ok=False,
                    error="Output requires PIN authorization",
                    error_code="pin_required",
                    detail=(resp.text or "").strip(),
                )
        if resp is not None and resp.status_code == 503 and "encoder_capacity" in ((resp.text or "")):
            return ActionResult(
                ok=False,
                error="Output declined: appliance CPU cannot encode another stream",
                error_code="encoder_capacity",
                detail=(resp.text or "").strip(),
            )
        if resp is not None and resp.status_code != 204:
            return ActionResult(
                ok=False,
                error=f"Backend returned HTTP {resp.status_code}",
                error_code="http_error",
                detail=(resp.text or "").strip() or err,
            )
        if err:
            return ActionResult(ok=False, error="Backend request failed", error_code="request_failed", detail=err)
        if resp is None:
            return ActionResult(ok=False, error="No backend response", error_code="no_response")
        return ActionResult(ok=True)
