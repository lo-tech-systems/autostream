#!/usr/bin/env python3
"""autostream_owntone_mini.py

Player backend implementation for the cut-down OwnTone HTTP API.
"""

from __future__ import annotations

from dataclasses import dataclass
import logging
import time
from typing import Any, Optional

from autostream_config import normalize_log_level, owntone_log_level_value
from autostream_players import (
    ActionResult,
    BACKEND_OWNTONE_MINI,
    BackendCapabilities,
    BackendStatus,
    DetectionResult,
    GetOutputResult,
    ListOutputsResult,
    PlaybackMetadata,
    OwnToneHttpBackendBase,
    REGISTRY,
    SaveSettingResult,
    SettingDescriptor,
    SettingValueResult,
    SETTING_IPV6,
    SETTING_LOG_LEVEL,
    SETTING_PIPE_AUTOSTART,
    SETTING_PIPE_PATH,
    SETTING_START_BUFFER_MS,
    SETTING_UNCOMPRESSED_ALAC,
)


LOG = logging.getLogger(__name__)


_LOG_LEVEL_BY_VALUE = {
    0: "fatal",
    1: "log",
    2: "warning",
    3: "info",
    4: "debug",
    5: "spam",
}


@dataclass(frozen=True)
class _MiniSettingSpec:
    category: str
    option: str
    value_type: str
    requires_restart_on_change: bool = False
    min_value: Optional[int] = None
    max_value: Optional[int] = None


_SETTING_SPECS: dict[str, _MiniSettingSpec] = {
    SETTING_LOG_LEVEL: _MiniSettingSpec(
        category="misc",
        option="loglevel",
        value_type="string",
        requires_restart_on_change=False,
    ),
    SETTING_PIPE_PATH: _MiniSettingSpec(
        category="misc",
        option="pipe_path",
        value_type="string",
        requires_restart_on_change=False,
    ),
    SETTING_PIPE_AUTOSTART: _MiniSettingSpec(
        category="misc",
        option="pipe_autostart",
        value_type="bool",
        requires_restart_on_change=False,
    ),
    SETTING_IPV6: _MiniSettingSpec(
        category="misc",
        option="ipv6",
        value_type="bool",
        requires_restart_on_change=True,
    ),
    SETTING_START_BUFFER_MS: _MiniSettingSpec(
        category="player",
        option="start_buffer_ms",
        value_type="int",
        requires_restart_on_change=True,
        min_value=300,
        max_value=3500,
    ),
    SETTING_UNCOMPRESSED_ALAC: _MiniSettingSpec(
        category="player",
        option="uncompressed_alac",
        value_type="bool",
        requires_restart_on_change=True,
    ),
}


class OwnToneMiniBackend(OwnToneHttpBackendBase):
    """Backend adapter for the pared-down OwnTone API.

    Probe order note: this backend should be probed before the official
    OwnTone backend because it identifies itself via /api/config
    product_name.
    """

    BACKEND_ID = BACKEND_OWNTONE_MINI

    @classmethod
    def backend_id_cls(cls) -> str:
        return cls.BACKEND_ID

    def detect(self) -> DetectionResult:
        config_payload, config_resp, config_err = self._get_json("/api/config")
        if config_err or config_resp is None or not config_resp.ok:
            return DetectionResult(
                matched=False,
                backend_id=self.backend_id,
                detail=config_err or f"GET /api/config failed with status {getattr(config_resp, 'status_code', '?')}",
            )

        version = ""
        product_name = ""
        if isinstance(config_payload, dict):
            version = str(config_payload.get("version") or "").strip()
            product_name = str(config_payload.get("product_name") or "").strip().casefold()

        if product_name == "owntone-mini":
            detail = f"OwnTone mini API detected via /api/config product_name (version={version or 'unknown'})"
            return DetectionResult(matched=True, backend_id=self.backend_id, detail=detail)

        return DetectionResult(
            matched=False,
            backend_id=self.backend_id,
            detail=(
                "OwnTone mini product_name not reported by /api/config "
                f"(got {product_name or 'empty'}, version={version or 'unknown'})"
            ),
        )

    def get_capabilities(self) -> BackendCapabilities:
        return BackendCapabilities(
            can_list_outputs=True,
            can_get_output=True,
            can_set_output_enabled=True,
            can_set_selected_outputs=True,
            can_set_output_volume=True,
            can_set_output_offset=True,
            can_submit_output_pin=True,
            can_set_output_mode=False,
            can_play=True,
            can_stop=True,
            can_ensure_pipe_source_ready=True,
            can_refresh_runtime_state=True,
            can_push_metadata=True,
            can_restart=False,
            can_request_library_update=True,
            supports_runtime_settings=True,
            supports_restart_required_reporting=True,
            supported_setting_keys=tuple(_SETTING_SPECS.keys()),
        )

    def get_status(self) -> BackendStatus:
        config_payload, config_resp, config_err = self._get_json("/api/config")
        if config_err:
            return BackendStatus(ok=False, reachable=False, ready=False, detail=config_err)
        if config_resp is None or not config_resp.ok:
            return BackendStatus(
                ok=False,
                reachable=True,
                ready=False,
                detail=f"GET /api/config failed with status {getattr(config_resp, 'status_code', '?')}",
            )

        library_payload, library_resp, library_err = self._get_json("/api/library")
        if library_err:
            restart_required = bool(config_payload.get("restart_required")) if isinstance(config_payload, dict) else False
            return BackendStatus(
                ok=False,
                reachable=True,
                ready=False,
                restart_required=restart_required,
                detail=library_err,
            )
        if library_resp is None or not library_resp.ok:
            return BackendStatus(
                ok=False,
                reachable=True,
                ready=False,
                restart_required=bool(config_payload.get("restart_required")) if isinstance(config_payload, dict) else False,
                detail=f"GET /api/library failed with status {getattr(library_resp, 'status_code', '?')}",
            )

        restart_required = False
        detail = ""
        if isinstance(config_payload, dict):
            restart_required = bool(config_payload.get("restart_required"))
        if isinstance(library_payload, dict):
            restart_required = restart_required or bool(library_payload.get("restart_required"))
            healthy_value = library_payload.get("Healthy")
            if healthy_value is False:
                detail = "Library health reported unhealthy"
                return BackendStatus(
                    ok=False,
                    reachable=True,
                    ready=False,
                    restart_required=restart_required,
                    detail=detail,
                )
        return BackendStatus(
            ok=True,
            reachable=True,
            ready=True,
            restart_required=restart_required,
            detail="",
        )

    def restart(self) -> ActionResult:
        return self._unsupported_action("restart")

    def list_outputs(self) -> ListOutputsResult:
        payload, resp, err = self._get_json("/api/outputs")
        if err or resp is None or not resp.ok or not isinstance(payload, dict):
            return ListOutputsResult(
                ok=False,
                error="Failed to list outputs",
                error_code="request_failed" if err else "http_error",
            )
        outputs = payload.get("outputs", [])
        if not isinstance(outputs, list):
            return ListOutputsResult(ok=False, error="Invalid outputs payload", error_code="invalid_payload")
        return ListOutputsResult(
            ok=True,
            outputs=tuple(
                self._normalize_output_info(output)
                for output in outputs
                if isinstance(output, dict)
            ),
        )

    def get_output(self, output_id: str) -> GetOutputResult:
        out_id = str(output_id or "").strip()
        if not out_id:
            return GetOutputResult(ok=False, error="Missing output id", error_code="missing_output_id")
        payload, resp, err = self._get_json(f"/api/outputs/{out_id}")
        if err:
            return GetOutputResult(ok=False, error="Failed to get output", error_code="request_failed")
        if resp is None:
            return GetOutputResult(ok=False, error="No backend response", error_code="no_response")
        if resp.status_code == 404:
            return GetOutputResult(ok=False, error="Output not found", error_code="not_found")
        if not resp.ok:
            return GetOutputResult(ok=False, error=f"Backend returned HTTP {resp.status_code}", error_code="http_error")
        if not isinstance(payload, dict):
            return GetOutputResult(ok=False, error="Invalid output payload", error_code="invalid_payload")
        return GetOutputResult(ok=True, output=self._normalize_output_info(payload))

    def set_output_enabled(self, output_id: str, enabled: bool) -> ActionResult:
        return self._put_output_fields(
            output_id,
            {"selected": bool(enabled)},
            allow_pin_required=bool(enabled),
        )

    def set_selected_outputs(self, output_ids: list[str]) -> ActionResult:
        ids = [str(output_id).strip() for output_id in (output_ids or []) if str(output_id).strip()]
        return self._put_json("/api/outputs/set", {"outputs": ids}, success_statuses=(204,))

    def set_output_volume(self, output_id: str, volume_percent: int) -> ActionResult:
        try:
            volume = int(volume_percent)
        except Exception:
            volume = 0
        volume = max(0, min(100, volume))
        return self._put_output_fields(output_id, {"volume": volume})

    def set_output_offset(self, output_id: str, offset_ms: int) -> ActionResult:
        try:
            offset = int(offset_ms)
        except Exception:
            offset = 0
        offset = max(-2000, min(2000, offset))
        return self._put_output_fields(output_id, {"offset_ms": offset})

    def submit_output_pin(self, output_id: str, pin: str) -> ActionResult:
        pin_text = str(pin or "").strip()
        if not pin_text:
            return ActionResult(ok=False, error="Missing PIN", error_code="missing_pin")
        return self._put_output_fields(output_id, {"pin": pin_text}, allow_pin_invalid=True)

    def set_output_mode(self, output_id: str, mode: str) -> ActionResult:
        return self._unsupported_action("set_output_mode")

    def play(self) -> ActionResult:
        return self._put_json("/api/player/play", None, success_statuses=(204,))

    def stop(self) -> ActionResult:
        return self._put_json("/api/player/stop", None, success_statuses=(204,))

    def ensure_pipe_source_ready(self) -> ActionResult:
        """Block for up to 15 seconds while waiting for the pipe source to appear."""
        deadline = time.monotonic() + 15.0
        next_update = time.monotonic()

        while time.monotonic() < deadline:
            payload, resp, err = self._get_json("/api/library")
            if err:
                return ActionResult(ok=False, error="Failed to query backend library status", error_code="library_unreachable", detail=err)
            if resp is not None and resp.ok and isinstance(payload, dict):
                songs = payload.get("songs")
                restart_required = bool(payload.get("restart_required"))
                try:
                    if int(songs) > 0:
                        return ActionResult(ok=True, restart_required=restart_required)
                except Exception:
                    pass

            now = time.monotonic()
            if now >= next_update:
                update_result = self._put_json("/api/update", None, success_statuses=(204,))
                if not update_result.ok:
                    return update_result
                next_update = now + 2.0
            time.sleep(0.5)

        return ActionResult(
            ok=False,
            error="Pipe source was not ready before timeout",
            error_code="not_ready",
        )

    def refresh_runtime_state(self) -> ActionResult:
        return self._put_json("/api/update", None, success_statuses=(204,))

    def request_library_update(self) -> ActionResult:
        return self._put_json("/api/update", None, success_statuses=(204,))

    def push_metadata(self, metadata: PlaybackMetadata) -> ActionResult:
        if not any((metadata.title, metadata.artist, metadata.album, metadata.artwork_url)):
            return ActionResult(ok=True)
        payload: dict[str, str] = {}
        if metadata.title:
            payload["title"] = str(metadata.title)
        if metadata.artist:
            payload["artist"] = str(metadata.artist)
        if metadata.album:
            payload["album"] = str(metadata.album)
        if metadata.artwork_url:
            payload["artwork_url"] = str(metadata.artwork_url)
        return self._put_json("/api/metadata", payload, success_statuses=(204,))

    def get_setting(self, key: str) -> SettingValueResult:
        spec = _SETTING_SPECS.get(str(key))
        if spec is None:
            return SettingValueResult(ok=False, unsupported=True, error="Unsupported setting", error_code="unsupported")

        payload, resp, err = self._get_json(self._setting_path(spec))
        if err:
            return SettingValueResult(ok=False, error="Failed to read backend setting", error_code="request_failed", value=None)
        if resp is None:
            return SettingValueResult(ok=False, error="No response while reading backend setting", error_code="no_response")
        if resp.status_code == 404:
            return SettingValueResult(ok=False, unsupported=True, error="Setting is not supported by owntone-mini", error_code="unsupported")
        if not resp.ok:
            return SettingValueResult(
                ok=False,
                error=f"Backend returned HTTP {resp.status_code}",
                error_code="http_error",
            )
        if not isinstance(payload, dict):
            return SettingValueResult(ok=False, error="Invalid setting response payload", error_code="invalid_payload")

        value = self._normalize_setting_value_from_backend(spec, payload.get("value"))
        return SettingValueResult(ok=True, value=value)

    def save_setting(self, key: str, value: Any) -> SaveSettingResult:
        spec = _SETTING_SPECS.get(str(key))
        if spec is None:
            return SaveSettingResult(ok=False, unsupported=True, error="Unsupported setting", error_code="unsupported")

        backend_value = self._normalize_setting_value_for_backend(spec, value)
        result_payload, resp, err = self._put_json_for_response(
            self._setting_path(spec),
            {"value": backend_value},
            success_statuses=(200,),
        )

        if err:
            return SaveSettingResult(ok=False, error="Failed to save backend setting", error_code="request_failed")
        if resp is None:
            return SaveSettingResult(ok=False, error="No response while saving backend setting", error_code="no_response")
        if resp.status_code == 404:
            return SaveSettingResult(ok=False, unsupported=True, error="Setting is not supported by owntone-mini", error_code="unsupported")
        if not resp.ok:
            return SaveSettingResult(
                ok=False,
                error=f"Backend returned HTTP {resp.status_code}",
                error_code="http_error",
            )

        restart_required = False
        if isinstance(result_payload, dict):
            restart_required = bool(result_payload.get("restart_required"))

        requires_restart = spec.requires_restart_on_change
        return SaveSettingResult(
            ok=True,
            applied_live=not requires_restart,
            saved_persistently=True,
            restart_required=restart_required or requires_restart,
        )

    def list_supported_settings(self) -> list[SettingDescriptor]:
        return [
            SettingDescriptor(
                key=key,
                value_type=spec.value_type,
                label=self._setting_label(key),
                writable=True,
                requires_restart_on_change=spec.requires_restart_on_change,
                min_value=spec.min_value,
                max_value=spec.max_value,
                allowed_values=self._setting_allowed_values(key),
            )
            for key, spec in _SETTING_SPECS.items()
        ]

    def _normalize_setting_value_from_backend(self, spec: _MiniSettingSpec, value: Any) -> Any:
        if spec.option == "loglevel":
            try:
                return _LOG_LEVEL_BY_VALUE[int(value)]
            except Exception:
                return normalize_log_level(value)
        if spec.value_type == "bool":
            return bool(value)
        if spec.value_type == "int":
            try:
                num = int(value)
            except Exception:
                return value
            return num
        if spec.value_type == "string":
            return str(value or "")
        return value

    def _normalize_setting_value_for_backend(self, spec: _MiniSettingSpec, value: Any) -> Any:
        if spec.option == "loglevel":
            return owntone_log_level_value(normalize_log_level(value))
        if spec.value_type == "bool":
            return bool(value)
        if spec.value_type == "int":
            try:
                num = int(value)
            except Exception:
                num = 0
            if spec.min_value is not None:
                num = max(spec.min_value, num)
            if spec.max_value is not None:
                num = min(spec.max_value, num)
            return num
        if spec.value_type == "string":
            return str(value or "")
        return value

    def _setting_path(self, spec: _MiniSettingSpec) -> str:
        return f"/api/settings/{spec.category}/{spec.option}"

    def _setting_label(self, key: str) -> str:
        labels = {
            SETTING_LOG_LEVEL: "Log Level",
            SETTING_PIPE_AUTOSTART: "Pipe Autostart",
            SETTING_PIPE_PATH: "Pipe Path",
            SETTING_START_BUFFER_MS: "Start Buffer",
            SETTING_UNCOMPRESSED_ALAC: "Uncompressed ALAC",
            SETTING_IPV6: "IPv6",
        }
        return labels.get(key, key)

    def _setting_allowed_values(self, key: str) -> tuple[str, ...]:
        if key == SETTING_LOG_LEVEL:
            return ("fatal", "log", "warning", "info", "debug", "spam")
        return ()

REGISTRY.register(OwnToneMiniBackend)
