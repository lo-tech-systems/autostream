"""autostream_identification -- the track identification service: built from
the configuration, and rebuilt live and handed to every monitor when its
settings change.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
from typing import Optional

import autostream_audio_monitor as audio_monitor
import autostream_runtime as runtime
from autostream_config import load_and_parse


def build_track_id_service(cfg) -> Optional[object]:
    """Build and return a TrackIdentificationService from config, or None."""
    try:
        from track_id.service import build_service
        ti = cfg.track_identification
        settings = dict(ti.providers.get(ti.provider, {}))
        return build_service(
            enabled=ti.enabled,
            provider_id=ti.provider,
            provider_settings=settings,
            analysis_lead_in_seconds=ti.analysis_lead_in_seconds,
            snapshot_seconds=ti.snapshot_seconds,
            retry_seconds=ti.retry_seconds,
            refresh_seconds=ti.refresh_seconds,
            track_change_silence_seconds=ti.track_change_silence_seconds,
        )
    except Exception:
        logging.warning("track_id: failed to build service", exc_info=True)
        return None


def apply_track_id_config_live(config_path: str) -> None:
    """Rebuild the track identification service and push it to all monitors.

    Called by the web UI when track identification settings change.  Avoids
    tearing down the audio coordinator or stopping OwnTone -- only the service
    singleton and each monitor's per-instance reference are replaced.
    """
    try:
        from autostream_config import CONFIG_IO_LOCK
        with CONFIG_IO_LOCK:
            cfg = load_and_parse(config_path)
    except Exception:
        logging.warning("track_id: live reload: cannot read config", exc_info=True)
        return
    runtime._track_id_service = build_track_id_service(cfg)
    audio_monitor.publish_track_service(runtime._track_id_service is not None)
    with runtime._monitors_lock:
        monitors = list(runtime.all_monitors)
    for m in monitors:
        m._apply_track_id_service(runtime._track_id_service)
    logging.info(
        "track_id: service rebuilt live (enabled=%s)",
        runtime._track_id_service is not None,
    )


def apply_track_id_config_live_from_parsed(cfg) -> None:
    """Rebuild the track identification service from an already-parsed config.

    Preferred over apply_track_id_config_live when the caller holds a fresh
    in-memory snapshot (e.g. from SettingsStore) and disk may not yet reflect
    the latest accepted settings.
    """
    runtime._track_id_service = build_track_id_service(cfg)
    audio_monitor.publish_track_service(runtime._track_id_service is not None)
    with runtime._monitors_lock:
        monitors = list(runtime.all_monitors)
    for m in monitors:
        m._apply_track_id_service(runtime._track_id_service)
    logging.info(
        "track_id: service rebuilt live from snapshot (enabled=%s)",
        runtime._track_id_service is not None,
    )
