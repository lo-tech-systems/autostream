#!/usr/bin/env python3
"""autostream_owntone.py

Player backend implementation for the official OwnTone JSON API.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from autostream_players import (
    ActionResult,
    BACKEND_OWNTONE,
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
)


LOG = logging.getLogger(__name__)


class OwnToneBackend(OwnToneHttpBackendBase):
    """Backend adapter for the official OwnTone JSON API.

    Probe order note: owntone-mini should be probed before this backend because
    this backend's detection relies on generic `/api/settings` support.
    """

    BACKEND_ID = BACKEND_OWNTONE

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

        settings_payload, settings_resp, settings_err = self._get_json("/api/settings")
        if settings_err or settings_resp is None or not settings_resp.ok:
            return DetectionResult(
                matched=False,
                backend_id=self.backend_id,
                detail=settings_err or "official settings endpoint /api/settings not available",
            )

        if not isinstance(settings_payload, dict) or not isinstance(settings_payload.get("categories"), list):
            return DetectionResult(
                matched=False,
                backend_id=self.backend_id,
                detail="official settings endpoint did not return category data",
            )

        version = ""
        if isinstance(config_payload, dict):
            version = str(config_payload.get("version") or "").strip()
        detail = f"OwnTone official API detected (version={version or 'unknown'})"
        return DetectionResult(matched=True, backend_id=self.backend_id, detail=detail)

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
            can_ensure_pipe_source_ready=False,
            can_refresh_runtime_state=False,
            can_push_metadata=False,
            can_restart=False,
            can_request_library_update=True,
            supports_runtime_settings=False,
            supports_restart_required_reporting=False,
            supported_setting_keys=(),
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

        player_payload, player_resp, player_err = self._get_json("/api/player")
        if player_err:
            return BackendStatus(ok=False, reachable=True, ready=False, detail=player_err)
        if player_resp is None or not player_resp.ok:
            return BackendStatus(
                ok=False,
                reachable=True,
                ready=False,
                detail=f"GET /api/player failed with status {getattr(player_resp, 'status_code', '?')}",
            )

        detail = ""
        if isinstance(player_payload, dict):
            state = str(player_payload.get("state") or "").strip()
            if state:
                detail = f"player_state={state}"

        return BackendStatus(
            ok=True,
            reachable=True,
            ready=True,
            restart_required=False,
            detail=detail,
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

    def update_output(
        self,
        output_id: str,
        *,
        enabled: Optional[bool] = None,
        volume_percent: Optional[int] = None,
        offset_ms: Optional[int] = None,
    ) -> ActionResult:
        payload: dict[str, Any] = {}
        if enabled is not None:
            payload["selected"] = bool(enabled)
        if volume_percent is not None:
            try:
                volume = int(volume_percent)
            except Exception:
                volume = 0
            payload["volume"] = max(0, min(100, volume))
        if offset_ms is not None:
            try:
                offset = int(offset_ms)
            except Exception:
                offset = 0
            payload["offset_ms"] = max(-2000, min(2000, offset))
        if not payload:
            return ActionResult(ok=False, error="No output fields provided", error_code="missing_fields")
        return self._put_output_fields(
            output_id,
            payload,
            allow_pin_required=bool(enabled),
        )

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
        return self._unsupported_action("ensure_pipe_source_ready")

    def refresh_runtime_state(self) -> ActionResult:
        return self._unsupported_action("refresh_runtime_state")

    def request_library_update(self) -> ActionResult:
        return self._put_json("/api/update", None, success_statuses=(204,))

    def push_metadata(self, metadata: PlaybackMetadata) -> ActionResult:
        return self._unsupported_action("push_metadata")

    def get_setting(self, key: str) -> SettingValueResult:
        return SettingValueResult(
            ok=False,
            unsupported=True,
            error="Normalized backend settings are not supported by the official OwnTone API",
            error_code="unsupported",
        )

    def save_setting(self, key: str, value: Any) -> SaveSettingResult:
        return SaveSettingResult(
            ok=False,
            unsupported=True,
            error="Normalized backend settings are not supported by the official OwnTone API",
            error_code="unsupported",
        )

    def list_supported_settings(self) -> list[SettingDescriptor]:
        return []

REGISTRY.register(OwnToneBackend)
