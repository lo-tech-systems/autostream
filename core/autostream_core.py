#!/usr/bin/env python3
"""autostream_core.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Engine behind autostream.  Connects to autostream_monitor (the C++ daemon)
via a Unix domain socket to manage audio capture, resampling, silence
detection, and FIFO writing.  Python retains responsibility for OwnTone
HTTP control, now-playing metadata, and optional track recognition.

The daemon is expected to be running as a systemd service before this
script starts.  The socket path defaults to /tmp/autostream_monitor.sock
and can be overridden with the AUTOSTREAM_MONITOR_SOCKET environment
variable.
"""

import contextlib
import os
import json
import logging
import random
import socket
import sys
import time
import signal
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from autostream_config import (
    DEFAULT_LOG_LEVEL,
    OutputEqConfig,
    load_and_parse,
    normalize_airplay_mode,
    normalize_log_level,
    python_log_level_value,
    unconfigured,
)
from autostream_artwork import ArtworkFileCache
from autostream_nowplaying import (
    MAX_PICTURE_BYTES,
    NowPlayingMetadata,
    OwntoneMetadataPipePublisher,
    PersistentNowPlayingCache,
    get_shared_metadata_publisher,
    release_shared_metadata_publisher,
)
from autostream_player_service import (
    config_airplay_mode_to_backend,
    ensure_pipe_source_ready,
    list_outputs,
    reconcile_fifo_with_backend,
    refresh_runtime_state,
    set_selected_outputs,
    stop_and_disable_all,
    update_output,
)
from autostream_playback_stats import (
    DEFAULT_STYLUS_LIFE_HOURS,
    InputPlaybackSnapshot,
    MaintenanceResetResult,
    PlaybackInputConfig,
    PlaybackSnapshot,
    PlaybackTracker,
    input_label,
    make_fallback_input_snapshot,
)
from autostream_sysutils import (
    audit_static_system_facts,
    get_install_state,
    run_admin_cmd,
    write_avahi_playing_service,
    remove_avahi_playing_service,
)


# --------------------------------------------------------------------------- #
# Process termination                                                          #
# --------------------------------------------------------------------------- #

stop_flag = threading.Event()
reload_flag = threading.Event()


def request_config_reload() -> None:
    """Signal the coordinator loop to tear down and re-initialise all monitors.

    Called by the Web UI after a successful settings save.  The coordinator
    picks this up within one poll interval and re-reads the INI without
    restarting the process.
    """
    reload_flag.set()


# Track all AudioMonitor instances so coordination logic can inspect them.
# _monitors_lock must be held when reading or mutating all_monitors or when
# taking a snapshot of its elements for use on a different thread (Web UI).
all_monitors: list["AudioMonitor"] = []
_monitors_lock = threading.Lock()
_playback_tracker: Optional[PlaybackTracker] = None

# Track identification service singleton (replaced on each config reload).
# Written only from the coordinator thread; read from worker threads under GIL.
_track_id_service = None  # Optional[TrackIdentificationService]

# Process-wide identification admission gate.  A non-blocking acquire is attempted
# before every worker dispatch; at most one identification request runs globally.
_track_id_request_gate = threading.Lock()

def _build_track_id_service(cfg) -> Optional[object]:
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
    tearing down the audio coordinator or stopping OwnTone — only the service
    singleton and each monitor's per-instance reference are replaced.
    """
    global _track_id_service
    try:
        from autostream_config import CONFIG_IO_LOCK
        with CONFIG_IO_LOCK:
            cfg = load_and_parse(config_path)
    except Exception:
        logging.warning("track_id: live reload: cannot read config", exc_info=True)
        return
    _track_id_service = _build_track_id_service(cfg)
    with _monitors_lock:
        monitors = list(all_monitors)
    for m in monitors:
        m._apply_track_id_service(_track_id_service)
    logging.info(
        "track_id: service rebuilt live (enabled=%s)",
        _track_id_service is not None,
    )


def apply_track_id_config_live_from_parsed(cfg) -> None:
    """Rebuild the track identification service from an already-parsed config.

    Preferred over apply_track_id_config_live when the caller holds a fresh
    in-memory snapshot (e.g. from SettingsStore) and disk may not yet reflect
    the latest accepted settings.
    """
    global _track_id_service
    _track_id_service = _build_track_id_service(cfg)
    with _monitors_lock:
        monitors = list(all_monitors)
    for m in monitors:
        m._apply_track_id_service(_track_id_service)
    logging.info(
        "track_id: service rebuilt live from snapshot (enabled=%s)",
        _track_id_service is not None,
    )


def get_track_identification_snapshot(input_index: int):
    """Return the latest TrackIdentificationSnapshot for an input channel."""
    with _monitors_lock:
        monitors = list(all_monitors)
    for m in monitors:
        if m.input_index == input_index:
            return m._ti_snapshot  # atomic under GIL
    from track_id.models import disabled_snapshot
    return disabled_snapshot()


def get_active_track_identification_snapshot():
    """Return track identification state for the monitor actively sourcing audio.

    "Actively sourcing" means capturing, OR being the replay-origin
    input of a currently replaying recording -- the same actively-sourcing
    definition used by _ingest_status()/maybe_trigger_track_identification()
    (see monitor._replay_origin, refreshed each poll cycle from the
    coordinator's _replay_origin_input()). Without the replay-origin check,
    /api/status.track_identification would fall back to waiting_snapshot()
    during replay even though the origin monitor's _ti_snapshot already holds
    a live match -- the daemon confirms vibra keeps matching tracks during
    replay, only the surfaced snapshot was wrong. Capturing is checked first
    so a live capture on another input always takes priority over a
    concurrently-replaying recording. Returns a waiting snapshot when the
    service is configured but nothing is actively sourcing, or a disabled
    snapshot when the service itself is off. Never blocks.
    """
    with _monitors_lock:
        monitors = list(all_monitors)
    for m in monitors:
        if m.is_capturing:
            return m._ti_snapshot  # atomic under GIL
    for m in monitors:
        if m._replay_origin:
            return m._ti_snapshot  # atomic under GIL
    from track_id.models import disabled_snapshot, waiting_snapshot
    if _track_id_service is not None:
        return waiting_snapshot()
    return disabled_snapshot()


# ---------------------------------------------------------------------------
# mDNS playing-state lifecycle
# ---------------------------------------------------------------------------

_AVAHI_PLAYING_PATH = Path("/etc/avahi/services/autostream-playing.service")
_playing_lock = threading.Lock()
_playing_announced: bool = False
_reconcile_started: bool = False


def _sync_playing_announcement(monitors: list, version: str) -> None:
    """Idempotently sync the _autostream-playing._tcp mDNS announcement.

    Writes the avahi service file when any monitor is capturing and the
    service is not yet announced; removes it when no monitor is capturing
    and the service is currently announced.  Updates _playing_announced only
    after a successful admin call.  Thread-safe; never raises.
    """
    global _playing_announced
    is_any = any(m.is_capturing for m in monitors)
    with _playing_lock:
        if is_any and not _playing_announced:
            if write_avahi_playing_service(version):
                _playing_announced = True
        elif not is_any and _playing_announced:
            if remove_avahi_playing_service():
                _playing_announced = False


def _start_playing_reconciliation(get_monitors_fn, version: str) -> None:
    """Start a daemon thread that periodically re-syncs the playing announcement.

    Recovers from transient admin failures and reflects config reloads that
    rebuild the monitor list.  get_monitors_fn() is called fresh each tick.
    """
    def _reconcile() -> None:
        while True:
            time.sleep(60)
            _sync_playing_announcement(get_monitors_fn(), version)

    threading.Thread(target=_reconcile, daemon=True, name="playing-reconcile").start()


@dataclass(frozen=True)
class MonitorRuntimeInfo:
    """Latest top-level runtime metadata reported by autostream_monitor."""

    monitor_build: str
    log_level: str
    connected: bool
    last_seen_at: float


_monitor_runtime_info_lock = threading.Lock()
_monitor_runtime_info = MonitorRuntimeInfo(
    monitor_build="unknown",
    log_level="unknown",
    connected=False,
    last_seen_at=0.0,
)


def _set_monitor_runtime_info(
    *,
    monitor_build: Optional[str] = None,
    log_level: Optional[str] = None,
    connected: Optional[bool] = None,
    last_seen_at: Optional[float] = None,
) -> None:
    """Update the cached autostream_monitor runtime metadata."""
    global _monitor_runtime_info
    with _monitor_runtime_info_lock:
        cur = _monitor_runtime_info
        _monitor_runtime_info = MonitorRuntimeInfo(
            monitor_build=(
                str(monitor_build).strip()
                if monitor_build is not None
                else cur.monitor_build
            ) or "unknown",
            log_level=(
                str(log_level).strip()
                if log_level is not None
                else cur.log_level
            ) or "unknown",
            connected=bool(cur.connected if connected is None else connected),
            last_seen_at=(
                cur.last_seen_at
                if last_seen_at is None
                else float(last_seen_at)
            ),
        )


def get_monitor_runtime_info() -> MonitorRuntimeInfo:
    """Return the latest cached top-level runtime metadata from the monitor."""
    with _monitor_runtime_info_lock:
        return _monitor_runtime_info


# ── Repeat status cache ───────────────────────────────────────────
# Cached verbatim from the most recent get_status() poll's top-level "repeat"
# block, so /api/status can pass it through without a second daemon round trip.
# None means either the feature has never reported (old binary / not yet
# polled) -- Python treats an absent block as feature-unsupported.

_repeat_status_lock = threading.Lock()
_repeat_status: Optional[dict] = None


def _set_repeat_status(status: Optional[dict]) -> None:
    global _repeat_status
    with _repeat_status_lock:
        _repeat_status = status if isinstance(status, dict) else None


def get_repeat_status() -> Optional[dict]:
    """Return the most recently polled daemon "repeat" status block, or None."""
    with _repeat_status_lock:
        return _repeat_status


# ── Unified playback-session state cache ─────────────────────────────────────
# Cached each poll cycle by the coordinator's single _SessionTracker call site
# so /api/status can expose "session" alongside the existing "repeat"
# passthrough, without a second daemon round trip. Same cache pattern as
# _repeat_status above.

_session_state_lock = threading.Lock()
_session_state: dict = {"active": False, "source": None}


def _set_session_state(active: bool, source: Optional[str]) -> None:
    global _session_state
    with _session_state_lock:
        _session_state = {"active": bool(active), "source": source}


def get_session_state() -> dict:
    """Return the most recently computed {"active", "source"} session state."""
    with _session_state_lock:
        return dict(_session_state)


# ── User-initiated output action marker ──────────────────────────────────────
# The Web UI's POST /api/output handler (autostream_webui_post_handlers.py)
# calls note_user_output_action() whenever the user toggles an output,
# independently of the coordinator thread. _OwntoneReconcileTracker consults
# this timestamp so a user manually deselecting every output mid-session is
# not mistaken for OwnTone restarting and forgetting everything: recent user
# activity suppresses an auto-reconcile that would otherwise fight the
# user's own action.

_last_user_output_action_lock = threading.Lock()
_last_user_output_action_at: float = 0.0


def note_user_output_action(now: Optional[float] = None) -> None:
    """Record that a user-initiated output change (POST /api/output) occurred."""
    global _last_user_output_action_at
    with _last_user_output_action_lock:
        _last_user_output_action_at = float(now) if now is not None else time.time()


def _get_last_user_output_action_at() -> float:
    with _last_user_output_action_lock:
        return _last_user_output_action_at


# ── OwnTone-restart reconcile + hang-watchdog status cache ──────────────────
# Exposed via /api/status (autostream_webui_api.py) for observability; never
# authoritative for coordinator decisions (that state lives on the tracker
# instances themselves, which are coordinator-thread-only).

_owntone_selfheal_state_lock = threading.Lock()
_owntone_selfheal_state: dict = {
    "reconcile_fired_count": 0,
    "reconcile_last_fired_at": 0.0,
    "watchdog_armed": False,
    "watchdog_restart_count": 0,
    "watchdog_last_restart_at": 0.0,
}


def _set_owntone_selfheal_state(**fields) -> None:
    global _owntone_selfheal_state
    with _owntone_selfheal_state_lock:
        _owntone_selfheal_state = {**_owntone_selfheal_state, **fields}


def get_owntone_selfheal_state() -> dict:
    """Return the latest reconcile/watchdog counters for /api/status passthrough."""
    with _owntone_selfheal_state_lock:
        return dict(_owntone_selfheal_state)


def _replay_origin_input(repeat_status: Optional[dict]) -> Optional[int]:
    """Return the input index replay is attributed to, or None if not replaying.

    Replay is only a "source" while repeat.replay.active is
    true, and it is attributed to repeat.recording.origin_input (the daemon
    guarantees capture-stop -> replay-start is atomic within one snapshot, so
    there is never a poll where an input is still "capturing" for the same
    recording that is also replaying).
    """
    if not isinstance(repeat_status, dict):
        return None
    replay = repeat_status.get("replay")
    if not (isinstance(replay, dict) and bool(replay.get("active"))):
        return None
    recording = repeat_status.get("recording")
    if not isinstance(recording, dict):
        return None
    origin = recording.get("origin_input")
    return origin if isinstance(origin, int) else None


def _empty_playback_snapshot() -> PlaybackSnapshot:
    return PlaybackSnapshot(
        inputs={},
        stylus_warning_indices=(),
        stylus_overdue_indices=(),
        stylus_banner_text=None,
        belt_warning_indices=(),
        belt_overdue_indices=(),
        belt_banner_text=None,
        bearing_warning_indices=(),
        bearing_overdue_indices=(),
        bearing_banner_text=None,
    )


def _playback_input_configs_from_config(cfg) -> dict[int, PlaybackInputConfig]:
    return {
        1: PlaybackInputConfig.normalized(
            enabled=True,
            is_turntable=cfg.audio1.is_turntable,
            stylus_life_hours=cfg.audio1.stylus_life_hours,
            belt_life_hours=cfg.audio1.belt_life_hours,
            belt_life_years=cfg.audio1.belt_life_years,
            bearing_life_hours=cfg.audio1.bearing_life_hours,
            bearing_life_years=cfg.audio1.bearing_life_years,
        ),
        2: PlaybackInputConfig.normalized(
            enabled=cfg.audio2_enabled,
            is_turntable=cfg.audio2.is_turntable,
            stylus_life_hours=cfg.audio2.stylus_life_hours,
            belt_life_hours=cfg.audio2.belt_life_hours,
            belt_life_years=cfg.audio2.belt_life_years,
            bearing_life_hours=cfg.audio2.bearing_life_hours,
            bearing_life_years=cfg.audio2.bearing_life_years,
        ),
    }


def _ensure_playback_tracker(cfg) -> Optional[PlaybackTracker]:
    global _playback_tracker

    try:
        if _playback_tracker is None:
            _playback_tracker = PlaybackTracker()
        _playback_tracker.replace_input_configs(_playback_input_configs_from_config(cfg))
    except Exception as e:
        logging.warning("Playback tracker unavailable: %s", e)
        _playback_tracker = None

    return _playback_tracker


def get_playback_snapshot() -> PlaybackSnapshot:
    tracker = _playback_tracker
    if tracker is None:
        return _empty_playback_snapshot()
    try:
        return tracker.snapshot()
    except Exception as e:
        logging.warning("Could not read playback snapshot: %s", e)
        return _empty_playback_snapshot()


def get_input_playback_snapshot(input_index: int) -> InputPlaybackSnapshot:
    idx = int(input_index)
    snap = get_playback_snapshot().inputs.get(idx)
    if snap is not None:
        return snap

    return make_fallback_input_snapshot(idx, input_label(idx))


def _reset_input(input_index: int, method_name: str, item_name: str) -> MaintenanceResetResult:
    tracker = _playback_tracker
    if tracker is None:
        return MaintenanceResetResult(applied=False, persisted=False)
    try:
        return getattr(tracker, method_name)(int(input_index))
    except Exception as e:
        logging.warning("Could not reset %s for input %s: %s", item_name, input_index, e)
        return MaintenanceResetResult(applied=False, persisted=False)


def reset_input_stylus(input_index: int) -> MaintenanceResetResult:
    return _reset_input(input_index, "reset_stylus", "stylus")


def reset_input_belt(input_index: int) -> MaintenanceResetResult:
    return _reset_input(input_index, "reset_belt", "belt")


def reset_input_bearing(input_index: int) -> MaintenanceResetResult:
    return _reset_input(input_index, "reset_bearing", "bearing")


def update_playback_input_config(
    input_index: int,
    *,
    enabled: bool,
    is_turntable: bool,
    stylus_life_hours: int,
    belt_life_hours: int = 0,
    belt_life_years: int = 0,
    bearing_life_hours: int = 0,
    bearing_life_years: int = 0,
) -> bool:
    tracker = _playback_tracker
    if tracker is None:
        return False
    try:
        tracker.update_input_config(
            int(input_index),
            enabled=enabled,
            is_turntable=is_turntable,
            stylus_life_hours=stylus_life_hours,
            belt_life_hours=belt_life_hours,
            belt_life_years=belt_life_years,
            bearing_life_hours=bearing_life_hours,
            bearing_life_years=bearing_life_years,
        )
        return True
    except Exception as e:
        logging.warning(
            "Could not update playback config for input %s: %s",
            input_index,
            e,
        )
        return False


def _normalize_owntone_output_offsets(
    output_offsets_ms: Optional[dict[str, object]] = None,
) -> dict[str, int]:
    normalized: dict[str, int] = {}
    for raw_key, raw_val in (output_offsets_ms or {}).items():
        key = str(raw_key).strip()
        if not key:
            continue
        try:
            off = int(raw_val)
        except Exception:
            off = 0
        normalized[key] = max(-2000, min(2000, off))
    return normalized


def _normalize_owntone_output_airplay_modes(
    output_airplay_modes: Optional[dict[str, object]] = None,
) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for raw_key, raw_val in (output_airplay_modes or {}).items():
        key = str(raw_key).strip()
        if not key:
            continue
        normalized[key] = normalize_airplay_mode(raw_val)
    return normalized


def update_live_owntone_runtime(
    *,
    output_name: str,
    volume_percent: object,
    output_offsets_ms: Optional[dict[str, object]] = None,
    output_airplay_modes: Optional[dict[str, object]] = None,
) -> bool:
    try:
        live_output_name = str(output_name or "").strip()
        try:
            live_volume_percent = int(str(volume_percent).strip())
        except Exception:
            live_volume_percent = 20
        live_volume_percent = max(0, min(100, live_volume_percent))
        live_output_offsets_ms = _normalize_owntone_output_offsets(output_offsets_ms)
        live_output_airplay_modes = _normalize_owntone_output_airplay_modes(
            output_airplay_modes
        )

        with _monitors_lock:
            for monitor in all_monitors:
                monitor.owntone_output_name = live_output_name
                monitor.owntone_volume_percent = live_volume_percent
                monitor.owntone_output_offsets_ms = dict(live_output_offsets_ms)
                monitor.owntone_output_airplay_modes = dict(live_output_airplay_modes)
        return True
    except Exception as e:
        logging.warning("Could not update live OwnTone runtime settings: %s", e)
        return False


def update_live_silence_seconds(
    silence_seconds: int,
    *,
    socket_path: Optional[str] = None,
) -> bool:
    """Apply a live silence timeout update to all configured running monitors.

    The monitor daemon supports live updates of silence_seconds via
    configure_input(), so this avoids a full coordinator reload for that single
    setting. Returns True on success, False if the live update could not be
    applied and the caller should fall back to a config reload.
    """
    try:
        live_silence_seconds = max(1, min(3600, int(silence_seconds)))
    except Exception:
        logging.warning(
            "Could not update live silence timeout: invalid value %r",
            silence_seconds,
        )
        return False

    with _monitors_lock:
        snapshot = list(all_monitors)

    if not snapshot:
        return True

    try:
        with _connected_monitor(socket_path) as client:
            if client is None:
                logging.warning(
                    "Could not connect to monitor daemon for live silence timeout update.",
                )
                return False

            for monitor in snapshot:
                if not client.configure_input(
                    monitor.input_index,
                    monitor.input_device,
                    monitor.silence_threshold_dbfs,
                    live_silence_seconds,
                    monitor.track_change_silence_seconds,
                ):
                    logging.warning(
                        "Live silence timeout update failed for input %d.",
                        monitor.input_index,
                    )
                    return False

            with _monitors_lock:
                for monitor in all_monitors:
                    monitor.silence_seconds = live_silence_seconds
            return True
    except Exception as e:
        logging.warning("Could not update live silence timeout: %s", e)
        return False


def any_monitor_capturing() -> bool:
    """Return True if any AudioMonitor currently has an active capture."""
    with _monitors_lock:
        return any(m.is_capturing for m in all_monitors)


def _stop_and_disable_owntone(base_url: str, reason: str) -> None:
    """Best-effort stop of OwnTone playback and deselection of all outputs."""
    if not base_url:
        return
    result = stop_and_disable_all(base_url, timeout=3)
    if result.ok:
        logging.info("OwnTone player stopped and outputs cleared (%s).", reason)
        return
    logging.warning(
        "OwnTone stop/disable request failed (%s): %s",
        reason,
        result.message or "unknown error",
    )


# ── Unified playback-session tracker ─────────────────────────────────────────
#
# A single source-vector session model drives idle-stop gating and
# replay-end/OwnTone-stop handling uniformly: each poll cycle,
# the coordinator derives which of {input1, input2, replay} is the audible
# source from the SAME status snapshot already ingested, and diffs it
# against the previous cycle's source. Exactly one of three events results:
#
#   session_started  (no source -> a source)       -- new-session output path
#   session_ended     (a source -> no source)       -- stop-and-disable path
#   source_changed    (a source -> a *different*     -- no output/volume
#                      source)                          action whatsoever
#
# source_changed covers live-interrupt-of-replay, capture-end -> replay
# handoff, and input1 <-> input2 handoff: in each case OwnTone's selected
# outputs/volume are already correct for the still-active session and must
# be left alone.
#
# Coordinator-thread only: one _SessionTracker instance per run_autostream()
# invocation (recreated on each reload), one update() call per poll cycle.
# No new threads or locks are introduced by the tracker itself.

def _current_source_monitor(monitors, source: Optional[str], origin_input: Optional[int]):
    """Resolve a vector key ("input1"/"input2"/"replay") to its AudioMonitor.

    *origin_input* is the already-computed _replay_origin_input() for the
    SAME snapshot the vector was built from -- resolving "replay" any other
    way would risk reading a later, possibly-stale repeat_status.
    """
    if source is None:
        return None
    if source == "replay":
        idx = origin_input
    else:
        try:
            idx = int(source[len("input"):])
        except (ValueError, IndexError):
            return None
    return next((m for m in monitors if m.input_index == idx), None)


class _SessionTracker:
    """Diffs the {input1, input2, replay} source vector between poll cycles.

    See module comment above for the event semantics. Resolves the AudioMonitor
    for both the previous and new source at update() time (while the snapshot
    driving them is fresh) rather than re-deriving it later from status that
    may have moved on by the time the caller acts on the event.
    """

    def __init__(self) -> None:
        self._source: Optional[str] = None
        self._source_monitor = None  # AudioMonitor or None

    def reset(self) -> None:
        """Clear tracked state so the next update() cannot manufacture a
        spurious event by diffing against stale pre-reset state.

        Called on coordinator reconnect/resync:
        if a session is genuinely still active across the resync, the next
        cycle reports it as a fresh session_started, which is intentional --
        reconnect already forces a full OwnTone output re-validation for
        every monitor (existing _owntone_enabled_ok reset), so re-running the
        new-session output path is consistent with that, not spurious. If
        nothing was active, both sides of the next diff are None and no
        event fires.
        """
        self._source = None
        self._source_monitor = None

    @property
    def active_source(self) -> Optional[str]:
        return self._source

    def update(self, monitors, repeat_status: Optional[dict]):
        """Advance one poll cycle.

        Returns (event, prev_monitor, new_monitor, new_source) where event is
        one of "session_started" / "session_ended" / "source_changed" / None.
        """
        origin_input = _replay_origin_input(repeat_status)
        vector = {f"input{m.input_index}": bool(m.is_capturing) for m in monitors}
        vector["replay"] = origin_input is not None

        # Mutual exclusion between a capturing input and replay for the same
        # recording is a daemon invariant (see _replay_origin_input); prefer
        # "replay" if it's ever violated since it is the rarer, more specific
        # state to surface.
        active = [k for k, v in vector.items() if v]
        new_source = "replay" if vector["replay"] else (active[0] if active else None)
        new_monitor = _current_source_monitor(monitors, new_source, origin_input)

        prev_source = self._source
        prev_monitor = self._source_monitor

        if prev_source is None and new_source is not None:
            event = "session_started"
        elif prev_source is not None and new_source is None:
            event = "session_ended"
        elif prev_source is not None and new_source is not None and prev_source != new_source:
            event = "source_changed"
        else:
            event = None

        self._source = new_source
        self._source_monitor = new_monitor
        return event, prev_monitor, new_monitor, new_source


def _start_session_owntone(monitor: "AudioMonitor") -> None:
    """New-session OwnTone output-enable path (session_started event).

    Equivalent to a capture-start-from-idle output-enable, but
    driven through whichever AudioMonitor is the session's source -- for a
    replay-sourced start that is the origin input's AudioMonitor, not the one
    (if any) that happens to be capturing, so replay start-from-idle reuses
    the existing _owntone_enabled_ok / _maybe_retry_owntone machinery instead
    of duplicating it (this is the fix for the "replay start never enables
    outputs" symptom).
    """
    monitor._owntone_enabled_ok = False
    monitor._owntone_last_attempt = 0.0
    if monitor.owntone_base_url:
        _stop_and_disable_owntone(monitor.owntone_base_url, "session start")
    # replay_origin=True unconditionally: harmless for an input-sourced start
    # (is_capturing already satisfies the guard) and required for a
    # replay-sourced start (the origin input's is_capturing is False).
    monitor._maybe_retry_owntone(time.time(), replay_origin=True)


def _session_nowplaying_start(monitor: Optional["AudioMonitor"]) -> None:
    if monitor is None:
        return
    monitor._nowplaying_publisher.publish_start(monitor._current_nowplaying)


def _session_nowplaying_end(monitor: Optional["AudioMonitor"]) -> None:
    if monitor is None:
        return
    try:
        monitor._nowplaying_publisher.publish_end()
    except Exception as e:
        # Must be logged, not swallowed silently -- same as the publisher's own
        # start/refresh/end write-failure path (_run()'s except).
        logging.debug(
            "now-playing publish_end failed for input %d: %s",
            monitor.input_index, e,
        )


def _dispatch_session_event(
    event: Optional[str],
    prev_monitor: Optional["AudioMonitor"],
    new_monitor: Optional["AudioMonitor"],
    owntone_base_url: str,
    new_source: Optional[str] = None,
) -> None:
    """Apply the session-level side effects for one _SessionTracker event.

    - session_started: OwnTone new-session output-enable path (via
      new_monitor, see _start_session_owntone) + now-playing publish_start.
    - session_ended: OwnTone stop-and-disable (the existing
      _stop_and_disable_owntone path) + now-playing publish_end.
    - source_changed: now-playing publish_end(prev) + publish_start(new)
      only -- NO output/volume action whatsoever. Applies to
      live-interrupt-of-replay, capture-end -> replay handoff, and
      input1 <-> input2 handoff: OwnTone's selected outputs/volume are
      already correct for the still-active session.
    - None: no event this cycle, nothing to do.

    *new_source* is the same _SessionTracker.update() call's vector key
    ("input1"/"input2"/"replay"/None) for new_monitor. When a
    session_started or source_changed event lands on "replay",
    this also arms new_monitor's identification cycle: is_capturing never
    transitions to True for the replay origin input, so _on_capture_started
    -- the only other place that arms it -- would otherwise never fire for a
    replay-sourced session. See _arm_track_identification_for_replay().
    """
    if event == "session_started":
        _session_nowplaying_start(new_monitor)
        if new_monitor is not None:
            _start_session_owntone(new_monitor)
    elif event == "session_ended":
        _session_nowplaying_end(prev_monitor)
        if owntone_base_url:
            _stop_and_disable_owntone(owntone_base_url, "session ended")
    elif event == "source_changed":
        _session_nowplaying_end(prev_monitor)
        _session_nowplaying_start(new_monitor)

    if (
        event in ("session_started", "source_changed")
        and new_source == "replay"
        and new_monitor is not None
    ):
        new_monitor._arm_track_identification_for_replay()


# ── OwnTone-restart reconcile (mechanism 1) ─────────────────────────────────
#
# OwnTone can restart mid-session (forced by the hang watchdog below, or by
# anything else -- a manual `systemctl restart owntone@...`, an OOM kill,
# etc.) and come back with ALL outputs deselected. session_started is
# one-shot (it only fires on the {input, replay} source *vector*
# transitioning from idle to active -- see _SessionTracker above), so a
# still-active session that loses its outputs mid-flight never re-triggers
# the new-session output-enable path and nothing else is watching for it.
#
# Detection: alternatives considered were (a) an OwnTone uptime/start-time
# field -- not exposed by either backend's API surface
# (autostream_owntone.py / autostream_owntone_mini.py have no such field) --
# and (b) diffing the coordinator's own last-applied output set against
# OwnTone's current one. (b) is what this implements: every poll cycle, while
# a session is active, fetch OwnTone's currently-selected outputs and count
# them. Zero selected outputs sustained for _OwntoneReconcileTracker.
# ZERO_POLL_THRESHOLD consecutive checks (~3, i.e. a small multiple of
# POLL_INTERVAL -- long enough to not fire on a single transient empty
# response, short enough to recover quickly) re-arms the existing
# _maybe_retry_owntone rate-limited retry machinery (by resetting
# _owntone_enabled_ok/_owntone_last_attempt on the session's monitor), rather
# than duplicating its enable-default/apply-selection logic.
#
# User-deselect edge: autostream_webui_post_handlers.py's
# handle_output_update (POST /api/output) applies per-output toggles with no
# guard against reaching zero selected outputs mid-playback -- i.e. the UI
# *does* allow a user to manually deselect every output during an active
# session, so "zero selected" alone cannot distinguish "OwnTone forgot
# everything" from "the user turned everything off on purpose". This tracker
# resolves the ambiguity by suppressing a would-be fire for
# USER_ACTION_GRACE_SECONDS after the most recent note_user_output_action()
# call (see that function's docstring): a fresh user action means the zero
# state is presumed intentional and is left alone. This is a heuristic, not a
# proof of intent -- if a user deselects everything and leaves a session
# "playing" with no outputs for longer than the grace window, the next
# reconcile will re-enable the default output, overriding them. This is a
# deliberate tradeoff (documented rather than solved with a full
# per-output-id provenance ledger, which would require instrumenting the Web
# UI POST path more invasively than this single marker call).
class _OwntoneReconcileTracker:
    """Detects "OwnTone restarted/lost state mid-session" and re-arms retry.

    Coordinator-thread only, one instance per run_autostream() invocation
    (recreated on reload, .reset() on reconnect/resync -- same lifecycle as
    _SessionTracker). update() is pure (no I/O, no logging) so it can be
    exercised directly in unit tests with synthetic (selected_count, now,
    last_user_action_at) sequences; the poll loop is responsible for the
    actual outputs fetch and for applying the effect when update() returns
    True (see _reconcile_owntone_outputs_if_wiped()).
    """

    ZERO_POLL_THRESHOLD = 3
    USER_ACTION_GRACE_SECONDS = 30.0

    def __init__(self) -> None:
        self._consecutive_zero = 0
        self._armed = True  # may fire again once a fresh zero-streak starts

    def reset(self) -> None:
        self._consecutive_zero = 0
        self._armed = True

    def update(
        self,
        *,
        session_active: bool,
        selected_count: Optional[int],
        now: float,
        last_user_action_at: float,
    ) -> bool:
        """Advance one check. Returns True iff reconcile should fire now.

        *selected_count* is None when the outputs API could not be reached
        this cycle (owntone unreachable/erroring) -- treated the same as "no
        session" for counting purposes: it must never itself count toward
        the zero streak, since an unreachable API is not evidence of a
        wiped-outputs restart (and is already handled by the existing
        owntone-down retry machinery elsewhere).
        """
        if not session_active or selected_count is None:
            self._consecutive_zero = 0
            self._armed = True
            return False

        if selected_count > 0:
            self._consecutive_zero = 0
            self._armed = True
            return False

        # selected_count == 0 while a session is active.
        self._consecutive_zero += 1
        if self._consecutive_zero < self.ZERO_POLL_THRESHOLD:
            return False
        if not self._armed:
            # Already fired for this zero-streak; wait for a nonzero
            # observation (handled above) before it can fire again.
            return False
        if (now - last_user_action_at) < self.USER_ACTION_GRACE_SECONDS:
            # Recent user output action: presume the zero state is
            # intentional and do not fire, but keep counting/re-checking so
            # a genuine restart-wipe that happens to follow closely on a
            # user toggle is still caught once the grace window elapses.
            return False

        self._armed = False
        return True


def _reconcile_owntone_outputs_if_wiped(
    tracker: "_OwntoneReconcileTracker",
    monitor: Optional["AudioMonitor"],
    session_active: bool,
    now: float,
) -> None:
    """Poll-loop wiring for _OwntoneReconcileTracker: fetch outputs, decide,
    act.

    Called once per poll cycle regardless of session state so the tracker's
    internal counters reset cleanly when a session ends, matching
    _SessionTracker.reset()'s discipline. No-ops (fetches nothing) when there
    is no active session or no monitor/base_url to check.
    """
    selected_count: Optional[int] = None
    if session_active and monitor is not None and monitor.owntone_base_url:
        outputs = monitor._get_owntone_outputs()
        if outputs is not None:
            selected_count = sum(1 for o in outputs if o.selected)

    should_fire = tracker.update(
        session_active=session_active,
        selected_count=selected_count,
        now=now,
        last_user_action_at=_get_last_user_output_action_at(),
    )
    if not should_fire:
        return

    logging.warning(
        "OwnTone-restart reconcile: session active with zero selected outputs "
        "for %d consecutive checks; re-arming output-enable retry for input %s.",
        tracker.ZERO_POLL_THRESHOLD,
        monitor.input_index if monitor is not None else "?",
    )
    state = get_owntone_selfheal_state()
    _set_owntone_selfheal_state(
        reconcile_fired_count=int(state.get("reconcile_fired_count", 0)) + 1,
        reconcile_last_fired_at=now,
    )
    if monitor is not None:
        monitor._owntone_enabled_ok = False
        monitor._owntone_last_attempt = 0.0


# ── OwnTone-hang watchdog (mechanism 2) ─────────────────────────────────────
#
# When the monitor daemon is deadlocked, the coordinator never enables
# outputs, OwnTone's buffer fills and it stops draining, and the FIFO writer
# keeps writing into a full pipe indefinitely (no data edge -- the writer
# never closes the FIFO), so OwnTone never notices anything is wrong and
# needs a manual restart. The daemon reports a top-level "fifo":
# {"stalled_seconds": float} block in get_status(): continuous FIFO
# write-failure seconds while a source wants to write, 0.0 when healthy. This
# watchdog requests an OwnTone restart via the supervisor (autostream_admin
# restart-owntone, the same path the Web UI's owntone-setup restart button
# uses -- see autostream_webui_page_owntone.py's _restart_owntone_worker) when
# the pipe is stuck long enough that OwnTone itself is very unlikely to
# recover unaided.
#
# owntone_reachable is deliberately part of the gate: a stalled FIFO write
# with OwnTone *unreachable* means OwnTone is down, which existing machinery
# (fifo_result.ok gating in _maybe_retry_owntone, reconcile_fifo_with_backend)
# already retries; this watchdog exists specifically for OwnTone being up but
# wedged on a stuck pipe consumer, so firing it when OwnTone cannot even be
# reached would be at best redundant and at worst issue a restart command to
# a backend that a moment later comes back on its own.
#
# The "fifo" block being absent entirely (old daemon binary, or a daemon that
# doesn't yet know about the field) disarms the watchdog silently -- no
# warnings, no restart -- for backward compatibility with older monitor
# binaries.
class _OwntoneHangWatchdog:
    """Decides when a stuck OwnTone pipe consumer warrants a forced restart.

    Coordinator-thread only, pure decision logic (no I/O, no subprocess
    calls) so it is unit-testable with synthetic status sequences. The poll
    loop supplies an owntone_reachable_fn so the (cheap but non-zero cost)
    reachability probe is only ever made when the stall threshold has
    already been exceeded, not on every poll.
    """

    STALL_THRESHOLD_SECONDS = 20.0
    RESTART_RATE_LIMIT_SECONDS = 600.0  # once per 10 minutes, hard

    def __init__(self) -> None:
        self._last_restart_at = float("-inf")  # never restarted yet: rate limit vacuously satisfied
        self.restart_count = 0

    def reset(self) -> None:
        self._last_restart_at = float("-inf")  # never restarted yet: rate limit vacuously satisfied
        self.restart_count = 0

    def maybe_fire(
        self,
        *,
        session_active: bool,
        fifo_status,
        now: float,
        owntone_reachable_fn,
    ) -> bool:
        """Returns True iff a restart should be requested now (and records
        the rate-limit bookkeeping for that decision -- callers must not
        call this speculatively without acting on a True result)."""
        if not session_active:
            return False
        if not isinstance(fifo_status, dict):
            return False  # absent block: old daemon binary, disarmed silently
        try:
            stalled_seconds = float(fifo_status.get("stalled_seconds", 0.0) or 0.0)
        except (TypeError, ValueError):
            return False
        if stalled_seconds <= self.STALL_THRESHOLD_SECONDS:
            return False
        if (now - self._last_restart_at) < self.RESTART_RATE_LIMIT_SECONDS:
            return False
        if not owntone_reachable_fn():
            # OwnTone is down, not hung -- existing owntone-down machinery
            # already handles recovery; this watchdog stands down.
            return False

        self._last_restart_at = now
        self.restart_count += 1
        return True


def _fire_owntone_hang_restart(base_url: str, stalled_seconds: float) -> None:
    """Background (non-blocking) autostream_admin restart-owntone request.

    Runs run_admin_cmd() in a daemon thread -- the same "sudo -n
    autostream_admin restart-owntone" invocation the Web UI's owntone-setup
    restart button uses (autostream_webui_page_owntone.py's
    _restart_owntone_worker) -- so the coordinator poll loop (0.5 s cadence)
    is never blocked on the up-to-20 s subprocess call. Mechanism 1
    (_reconcile_owntone_outputs_if_wiped) picks up the resulting
    zero-selected-outputs state on a later poll and re-enables outputs; this
    function does not attempt to re-enable anything itself.
    """
    logging.warning(
        "OwnTone-hang watchdog: FIFO stalled for %.1fs with OwnTone reachable; "
        "requesting a supervised restart.",
        stalled_seconds,
    )

    def _worker() -> None:
        try:
            p = run_admin_cmd(["restart-owntone"], timeout=20.0)
            if p.returncode != 0:
                logging.error(
                    "OwnTone-hang watchdog: restart-owntone failed (rc=%s): %s",
                    p.returncode, (p.stderr or "").strip(),
                )
            else:
                logging.warning("OwnTone-hang watchdog: restart-owntone requested.")
        except Exception:
            logging.exception("OwnTone-hang watchdog: restart-owntone raised")

    threading.Thread(target=_worker, name="owntone-hang-watchdog-restart", daemon=True).start()


def _maybe_run_owntone_hang_watchdog(
    watchdog: "_OwntoneHangWatchdog",
    status: dict,
    session_active: bool,
    owntone_base_url: str,
    now: float,
) -> None:
    """Poll-loop wiring for _OwntoneHangWatchdog: check, and act if it fires."""
    fifo_status = status.get("fifo") if isinstance(status, dict) else None

    def _reachable() -> bool:
        if not owntone_base_url:
            return False
        return bool(list_outputs(owntone_base_url, timeout=2).ok)

    should_fire = watchdog.maybe_fire(
        session_active=session_active,
        fifo_status=fifo_status,
        now=now,
        owntone_reachable_fn=_reachable,
    )
    _set_owntone_selfheal_state(
        watchdog_armed=isinstance(fifo_status, dict),
        watchdog_restart_count=watchdog.restart_count,
        watchdog_last_restart_at=watchdog._last_restart_at,
    )
    if not should_fire:
        return
    stalled_seconds = 0.0
    if isinstance(fifo_status, dict):
        try:
            stalled_seconds = float(fifo_status.get("stalled_seconds", 0.0) or 0.0)
        except (TypeError, ValueError):
            stalled_seconds = 0.0
    _fire_owntone_hang_restart(owntone_base_url, stalled_seconds)


def handle_signal(signum, frame):
    stop_flag.set()


def _cleanup_discovery() -> None:
    """Best-effort shutdown of all process-lifetime mDNS discovery services.

    Called once after the coordinator outer loop exits (including on SIGINT,
    SIGTERM, and unexpected exceptions).  Never called during a configuration
    reload.  All operations are idempotent.
    """
    try:
        import autostream_output_usage as _ou
        _ou.stop()
    except Exception:
        logging.debug("_cleanup_discovery: output_usage.stop() raised", exc_info=True)
    try:
        import autostream_dials as _dials
        _dials.stop_dial_scanner()
    except Exception:
        logging.debug("_cleanup_discovery: stop_dial_scanner() raised", exc_info=True)
    try:
        import autostream_appliances as _appliances
        _appliances.stop_appliance_scanner()
    except Exception:
        logging.debug("_cleanup_discovery: stop_appliance_scanner() raised", exc_info=True)


def _start_output_usage_poller(cfg) -> None:
    """Best-effort start/update of the cross-appliance output usage poller."""
    try:
        import autostream_output_usage as _ou
        _ou.configure(cfg.webui.output_usage_poll_interval_seconds)
        _ou.start(shutdown_event=stop_flag)
    except Exception:
        logging.warning("output-usage: failed to start poller", exc_info=True)


def _install_signal_handlers() -> None:
    """Register SIGINT/SIGTERM handlers. Call once from the process entry point."""
    signal.signal(signal.SIGINT,  handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)


_live_platform_log_level = normalize_log_level(DEFAULT_LOG_LEVEL)


def setup_logging(log_file: str, log_level: str) -> None:
    global _live_platform_log_level
    normalized = normalize_log_level(log_level)
    log_dir = os.path.dirname(log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    # Route all records through a QueueHandler so no caller thread ever
    # performs file I/O under the logging handler lock. A slow SD write
    # (e.g. during logrotate's compression pass) would otherwise block
    # whichever thread was logging while every other logging thread queued
    # on the shared handler lock -- the same structural wedge the C++
    # daemon's logger avoids. The QueueListener's single background thread
    # owns the blocking writes instead.
    import queue as _queue
    from logging.handlers import QueueHandler, QueueListener

    sink_handlers = [
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout),
    ]
    log_queue: _queue.Queue = _queue.Queue(maxsize=1000)
    logging.basicConfig(
        level=python_log_level_value(normalized),
        format="%(asctime)s: %(message)s",
        datefmt="%d-%b-%y %H:%M:%S",
        handlers=[QueueHandler(log_queue)],
    )
    listener = QueueListener(log_queue, *sink_handlers, respect_handler_level=False)
    listener.daemon = True
    listener.start()
    # Flush queued records on interpreter exit (best-effort; daemon thread
    # otherwise dies with the process mid-write).
    import atexit
    atexit.register(listener.stop)
    _live_platform_log_level = normalized


def update_live_log_level(log_level: str) -> str:
    """Apply the platform log level to the running Python process."""
    global _live_platform_log_level
    normalized = normalize_log_level(log_level)
    target_level = python_log_level_value(normalized)
    root_logger = logging.getLogger()
    root_logger.setLevel(target_level)
    for handler in root_logger.handlers:
        try:
            handler.setLevel(target_level)
        except Exception:
            pass
    _live_platform_log_level = normalized
    return normalized


def get_live_platform_log_level() -> str:
    """Return the current runtime platform log-level name."""
    return _live_platform_log_level


def set_live_monitor_log_level(
    log_level: str,
    socket_path: Optional[str] = None,
) -> bool:
    """Apply the platform log level immediately to the running monitor daemon."""
    normalized = normalize_log_level(log_level)
    with _connected_monitor(socket_path) as client:
        if client is None:
            return False
        return client.set_log_level(normalized)


def update_live_platform_log_level(
    log_level: str,
    socket_path: Optional[str] = None,
) -> tuple[str, bool]:
    """Apply the platform log level to Python and the monitor daemon."""
    normalized = update_live_log_level(log_level)
    monitor_ok = set_live_monitor_log_level(normalized, socket_path=socket_path)
    return normalized, monitor_ok


def get_monitor_levels_dbfs() -> list[dict]:
    """Return current level data for each active monitor for the Web UI.

    Data is sourced from the most recent get_status() poll cached in each
    AudioMonitor instance, so it is at most one poll interval stale.
    """
    levels: list[dict] = []
    with _monitors_lock:
        snapshot = list(all_monitors)
    for idx, mon in enumerate(snapshot, start=1):
        levels.append({
            "label": f"Input {idx}",
            "dbfs": round(mon.poll_peak_dbfs, 1),
            "detected_hz": round(mon.detected_hz, 1),
            "is_above_threshold": not mon.is_silent,
            "vu_history": mon.vu_history,
        })
    return levels


def get_monitor_socket_path() -> str:
    """Return the configured autostream_monitor socket path."""
    return (
        os.environ.get("AUTOSTREAM_MONITOR_SOCKET", "").strip()
        or MonitorClient.DEFAULT_SOCKET_PATH
    )


@contextlib.contextmanager
def _connected_monitor(socket_path: Optional[str] = None):
    """Context manager yielding a connected MonitorClient, or None if unavailable."""
    client = MonitorClient(socket_path or get_monitor_socket_path())
    try:
        yield client if client.connect() else None
    finally:
        client.close()


def normalize_monitor_devices(devices: Optional[list[dict]]) -> list[dict]:
    """Normalize list_devices() results into a stable Web UI-friendly shape.

    Each returned dict contains:
      - hw: ALSA hardware identifier such as "hw:1,0"
      - card: ALSA card description (may be empty)
      - name: ALSA device description (may be empty)
      - label: user-facing text combining card/device/hw
    """
    normalized: list[dict] = []

    for dev in devices or []:
        hw = str(dev.get("hw") or "").strip()
        if not hw:
            continue

        card = str(dev.get("card") or "").strip()
        name = str(dev.get("name") or "").strip()

        label_parts = [part for part in (card, name) if part]
        label = " - ".join(label_parts) if label_parts else hw
        if hw not in label:
            label = f"{label} ({hw})"

        normalized.append({
            "hw": hw,
            "card": card,
            "name": name,
            "label": label,
        })

    normalized.sort(key=lambda d: (d["label"].casefold(), d["hw"].casefold()))
    return normalized


def get_available_monitor_devices(
    socket_path: Optional[str] = None,
) -> list[dict]:
    """Return currently visible monitor devices from autostream_monitor.

    Uses a short-lived MonitorClient connection so callers outside the main
    coordinator loop can safely query available ALSA capture devices.
    Returns an empty list if the daemon is unavailable or the command fails.
    """
    try:
        with _connected_monitor(socket_path) as client:
            if client is None:
                return []
            return normalize_monitor_devices(client.list_devices())
    except Exception as e:
        logging.warning("Could not query autostream_monitor devices: %s", e)
        return []


# Fixed output PEQ band definitions.  The stored field names (peq1_db … peq6_db)
# are generic so the storage model can survive a future move to user-configurable
# parametrics.  This table is the single source of truth for both the band
# parameters sent to autostream_monitor and the labels shown on the Equaliser page.
OUTPUT_PEQ_BANDS: list[dict] = [
    {"key": "peq1_db", "label": "40Hz",   "type": "low_shelf",  "freq_hz":    40.0, "q": 0.5},
    {"key": "peq2_db", "label": "100Hz",  "type": "peak",       "freq_hz":   100.0, "q": 0.707},
    {"key": "peq3_db", "label": "300Hz",  "type": "peak",       "freq_hz":   300.0, "q": 0.707},
    {"key": "peq4_db", "label": "1kHz",   "type": "peak",       "freq_hz":  1000.0, "q": 0.707},
    {"key": "peq5_db", "label": "4kHz",   "type": "peak",       "freq_hz":  4000.0, "q": 0.707},
    {"key": "peq6_db", "label": "10kHz",  "type": "high_shelf", "freq_hz": 10000.0, "q": 0.5},
]


def build_monitor_eq_bands(
    eq_40hz_db: float,
    eq_100hz_db: float,
    eq_8khz_db: float,
) -> list[dict]:
    """Return the fixed three-band EQ definition expected by autostream_monitor.

    For shelf filters, the monitor currently uses the RBJ cookbook shelf
    formula wired through the generic ``q`` field. A value of ``q=0.707`` is
    equivalent to a shelf slope of ``S=1.0``.
    """
    return [
        {"type": "peak", "freq_hz": 40.0, "gain_db": float(eq_40hz_db), "q": 0.707},
        {"type": "low_shelf", "freq_hz": 100.0, "gain_db": float(eq_100hz_db), "q": 0.5},
        {"type": "high_shelf", "freq_hz": 8000.0, "gain_db": float(eq_8khz_db), "q": 0.5},
    ]


def apply_input_eq(
    client: "MonitorClient",
    input_index: int,
    eq_40hz_db: float,
    eq_100hz_db: float,
    eq_8khz_db: float,
) -> bool:
    """Push one input's EQ settings to autostream_monitor."""
    return client.set_eq(
        input_index,
        build_monitor_eq_bands(eq_40hz_db, eq_100hz_db, eq_8khz_db),
    )


def apply_input_gain(
    client: "MonitorClient",
    input_index: int,
    gain_db: float,
) -> bool:
    """Push one input's gain setting to autostream_monitor."""
    return client.set_gain(input_index, float(gain_db))


def set_live_input_eq(
    input_index: int,
    eq_40hz_db: float,
    eq_100hz_db: float,
    eq_8khz_db: float,
    socket_path: Optional[str] = None,
) -> bool:
    """Apply one input's EQ immediately to the running autostream_monitor.

    Uses a short-lived monitor connection so the Web UI can update EQ live
    without depending on the coordinator loop's persistent client.
    Also updates any matching in-process AudioMonitor cache so reconnect replay
    continues to use the most recent live values until the INI is saved.
    """
    with _connected_monitor(socket_path) as client:
        if client is None:
            return False
        ok = apply_input_eq(client, input_index, eq_40hz_db, eq_100hz_db, eq_8khz_db)
        if ok:
            with _monitors_lock:
                for mon in all_monitors:
                    if mon.input_index == input_index:
                        mon.eq_40hz_db = float(eq_40hz_db)
                        mon.eq_100hz_db = float(eq_100hz_db)
                        mon.eq_8khz_db = float(eq_8khz_db)
        return ok


def set_live_input_gain(
    input_index: int,
    gain_db: float,
    socket_path: Optional[str] = None,
) -> bool:
    """Apply one input's gain immediately to the running autostream_monitor."""
    with _connected_monitor(socket_path) as client:
        if client is None:
            return False
        ok = apply_input_gain(client, input_index, gain_db)
        if ok:
            with _monitors_lock:
                for mon in all_monitors:
                    if mon.input_index == input_index:
                        mon.gain_db = float(gain_db)
        return ok


def set_live_repeat_enabled(
    enabled: bool,
    codec: str,
    socket_path: Optional[str] = None,
) -> bool:
    """Push the global repeat enable/codec policy immediately to autostream_monitor.

    Live setter -- must NOT trigger a coordinator reload; this
    persists no state of its own and is safe to call at any time.
    """
    with _connected_monitor(socket_path) as client:
        if client is None:
            return False
        return client.set_repeat_enabled(bool(enabled), str(codec))


def set_live_repeat_armed(
    armed: bool,
    socket_path: Optional[str] = None,
) -> bool:
    """Arm/disarm repeat replay immediately on autostream_monitor.

    Session arm is runtime-only: no settings write accompanies
    this call. Disarming during replay triggers the daemon's fade-out.
    """
    with _connected_monitor(socket_path) as client:
        if client is None:
            return False
        return client.set_repeat_armed(bool(armed))


def build_output_eq_bands(
    peq1_db: float,
    peq2_db: float,
    peq3_db: float,
    peq4_db: float,
    peq5_db: float,
    peq6_db: float,
) -> list[dict]:
    """Return the six-band output EQ definition expected by autostream_monitor."""
    values = [peq1_db, peq2_db, peq3_db, peq4_db, peq5_db, peq6_db]
    return [
        {"type": b["type"], "freq_hz": b["freq_hz"], "gain_db": float(db), "q": b["q"]}
        for b, db in zip(OUTPUT_PEQ_BANDS, values)
    ]


def apply_output_eq(
    client: "MonitorClient",
    peq1_db: float,
    peq2_db: float,
    peq3_db: float,
    peq4_db: float,
    peq5_db: float,
    peq6_db: float,
) -> bool:
    """Push shared output EQ bands to autostream_monitor."""
    return client.set_output_eq(
        build_output_eq_bands(peq1_db, peq2_db, peq3_db, peq4_db, peq5_db, peq6_db)
    )


def apply_output_gain(client: "MonitorClient", gain_db: float) -> bool:
    """Push shared output gain to autostream_monitor."""
    return client.set_output_gain(float(gain_db))


def apply_output_auto_trim(client: "MonitorClient", enabled: bool) -> bool:
    """Push shared output auto-trim enable state to autostream_monitor."""
    return client.set_output_auto_trim(bool(enabled))


def _apply_output_eq_config(
    client: "MonitorClient",
    output_eq: OutputEqConfig,
) -> bool:
    """Push all persisted [output_eq] settings to the running monitor daemon.

    Applies gain, EQ bands, and auto-trim in one call.  Used during both
    initial startup and reconnect resync so the daemon always reflects the INI.
    """
    if not apply_output_gain(client, output_eq.gain_db):
        return False
    if not apply_output_eq(
        client,
        output_eq.peq1_db,
        output_eq.peq2_db,
        output_eq.peq3_db,
        output_eq.peq4_db,
        output_eq.peq5_db,
        output_eq.peq6_db,
    ):
        return False
    if not apply_output_auto_trim(client, output_eq.auto_trim_enabled):
        return False
    return True


def set_live_output_eq(
    peq1_db: float,
    peq2_db: float,
    peq3_db: float,
    peq4_db: float,
    peq5_db: float,
    peq6_db: float,
    socket_path: Optional[str] = None,
) -> bool:
    """Apply shared output EQ immediately to the running autostream_monitor."""
    with _connected_monitor(socket_path) as client:
        if client is None:
            return False
        return apply_output_eq(client, peq1_db, peq2_db, peq3_db, peq4_db, peq5_db, peq6_db)


def set_live_output_gain(
    gain_db: float,
    socket_path: Optional[str] = None,
) -> bool:
    """Apply shared output gain immediately to the running autostream_monitor."""
    with _connected_monitor(socket_path) as client:
        if client is None:
            return False
        return apply_output_gain(client, gain_db)


def set_live_output_auto_trim(
    enabled: bool,
    socket_path: Optional[str] = None,
) -> bool:
    """Apply shared output auto-trim enable state immediately to the running monitor."""
    with _connected_monitor(socket_path) as client:
        if client is None:
            return False
        return apply_output_auto_trim(client, enabled)


def get_live_output_eq_status(
    socket_path: Optional[str] = None,
) -> Optional[dict]:
    """Return current output EQ status from autostream_monitor, or None if unavailable.

    Returned dict contains:
      output_auto_trim_enabled  bool
      output_auto_trim_db       float  (current accumulated trim; 0.0 or negative)
      effective_output_gain_db  float
    """
    try:
        with _connected_monitor(socket_path) as client:
            if client is None:
                return None
            status = client.get_status()
            if not status:
                return None
            return {
                "output_auto_trim_enabled": bool(status.get("output_auto_trim_enabled", False)),
                "output_auto_trim_db": float(status.get("output_auto_trim_db", 0.0)),
                "effective_output_gain_db": float(status.get("effective_output_gain_db", 0.0)),
            }
    except Exception as e:
        logging.warning("Could not get live output EQ status: %s", e)
        return None


# --------------------------------------------------------------------------- #
# MonitorClient                                                                #
# --------------------------------------------------------------------------- #

class MonitorClient:
    """Thin wrapper around the autostream_monitor Unix domain socket.

    All commands are synchronous and serialised by _lock so that callers
    on different threads (e.g. the coordinator loop and a background
    recognition thread) do not interleave their JSON lines.

    The client holds a persistent connection.  If the socket is lost,
    is_connected() returns False and the caller is responsible for calling
    connect() again (the coordinator loop does this automatically).
    """

    DEFAULT_SOCKET_PATH = "/tmp/autostream_monitor.sock"
    CONNECT_TIMEOUT = 5.0    # seconds
    COMMAND_TIMEOUT = 15.0   # seconds; covers get_id_snapshot binary transfer

    def __init__(self, socket_path: str = DEFAULT_SOCKET_PATH) -> None:
        self._socket_path = socket_path
        self._sock: Optional[socket.socket] = None
        self._lock = threading.Lock()
        self._recv_buf = b""

    # ── Connection ───────────────────────────────────────────────────────────

    def connect(self) -> bool:
        """Open the socket; return True on success."""
        self.close()
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(self.CONNECT_TIMEOUT)
            s.connect(self._socket_path)
            s.settimeout(self.COMMAND_TIMEOUT)
            self._sock = s
            self._recv_buf = b""
            logging.info("MonitorClient: connected to %s", self._socket_path)
            return True
        except OSError as e:
            logging.error("MonitorClient: connect failed: %s", e)
            return False

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        self._recv_buf = b""

    def is_connected(self) -> bool:
        return self._sock is not None

    # ── Low-level I/O ────────────────────────────────────────────────────────

    def _readline(self) -> Optional[bytes]:
        """Read bytes from the socket up to and including the next newline."""
        while b"\n" not in self._recv_buf:
            try:
                chunk = self._sock.recv(4096)
            except OSError:
                self.close()
                return None
            if not chunk:
                self.close()
                return None
            self._recv_buf += chunk
        idx = self._recv_buf.index(b"\n")
        line = self._recv_buf[:idx]
        self._recv_buf = self._recv_buf[idx + 1:]
        return line

    def _readbytes(self, n: int) -> Optional[bytes]:
        """Read exactly n bytes from the socket (used for binary payloads)."""
        while len(self._recv_buf) < n:
            try:
                chunk = self._sock.recv(65536)
            except OSError:
                self.close()
                return None
            if not chunk:
                self.close()
                return None
            self._recv_buf += chunk
        data = self._recv_buf[:n]
        self._recv_buf = self._recv_buf[n:]
        return data

    def _command(self, cmd: dict) -> Optional[dict]:
        """Send one JSON command and return the parsed response dict."""
        if not self._sock:
            return None
        try:
            self._sock.sendall((json.dumps(cmd) + "\n").encode())
            line = self._readline()
            if line is None:
                return None
            parsed = json.loads(line)
            if not isinstance(parsed, dict):
                logging.warning(
                    "MonitorClient: command %r returned non-object response",
                    cmd.get("type"),
                )
                self.close()
                return None
            return parsed
        except (OSError, json.JSONDecodeError, ValueError) as e:
            logging.warning("MonitorClient: command %r failed: %s", cmd.get("type"), e)
            self.close()
            return None

    # ── Commands ─────────────────────────────────────────────────────────────

    def list_devices(self) -> Optional[list[dict]]:
        with self._lock:
            resp = self._command({"type": "list_devices"})
            return resp.get("devices") if resp and resp.get("ok") else None

    def configure_input(
        self,
        index: int,
        device: str,
        silence_threshold_dbfs: float,
        silence_seconds: int,
        track_change_silence_seconds: float = 1.25,
    ) -> bool:
        with self._lock:
            resp = self._command({
                "type": "configure_input",
                "input": index,
                "device": device,
                "silence_threshold_dbfs": silence_threshold_dbfs,
                "silence_seconds": silence_seconds,
                "track_change_silence_seconds": track_change_silence_seconds,
            })
            ok = bool(resp and resp.get("ok"))
            if not ok:
                logging.error(
                    "MonitorClient: configure_input(%d, %r) failed: %s",
                    index, device, (resp or {}).get("error", "no response"),
                )
            return ok

    def set_fifo(self, path: str) -> bool:
        with self._lock:
            resp = self._command({"type": "set_fifo", "path": path})
            ok = bool(resp and resp.get("ok"))
            if not ok:
                logging.error(
                    "MonitorClient: set_fifo(%r) failed: %s",
                    path, (resp or {}).get("error", "no response"),
                )
            return ok

    def start_input(self, index: int) -> bool:
        with self._lock:
            resp = self._command({"type": "start_input", "input": index})
            ok = bool(resp and resp.get("ok"))
            if not ok:
                logging.error(
                    "MonitorClient: start_input(%d) failed: %s",
                    index, (resp or {}).get("error", "no response"),
                )
            return ok

    def stop_input(self, index: int) -> bool:
        with self._lock:
            resp = self._command({"type": "stop_input", "input": index})
            return bool(resp and resp.get("ok"))

    def set_allow_capture(self, index: int, allow: bool) -> bool:
        with self._lock:
            resp = self._command({
                "type": "set_allow_capture",
                "input": index,
                "allow": allow,
            })
            return bool(resp and resp.get("ok"))

    def set_eq(self, index: int, bands: list[dict]) -> bool:
        with self._lock:
            resp = self._command({"type": "set_eq", "input": index, "bands": bands})
            return bool(resp and resp.get("ok"))

    def set_gain(self, index: int, gain_db: float) -> bool:
        with self._lock:
            resp = self._command({"type": "set_gain", "input": index, "gain_db": gain_db})
            return bool(resp and resp.get("ok"))

    def set_output_eq(self, bands: list[dict]) -> bool:
        with self._lock:
            resp = self._command({"type": "set_output_eq", "bands": bands})
            return bool(resp and resp.get("ok"))

    def set_output_gain(self, gain_db: float) -> bool:
        with self._lock:
            resp = self._command({"type": "set_output_gain", "gain_db": gain_db})
            return bool(resp and resp.get("ok"))

    def set_output_auto_trim(self, enabled: bool) -> bool:
        with self._lock:
            resp = self._command({"type": "set_output_auto_trim", "enabled": enabled})
            return bool(resp and resp.get("ok"))

    def set_repeat_enabled(self, enabled: bool, codec: str) -> bool:
        """Push the global repeat-recording enable/codec policy.

        Tolerated to fail silently (returns False, no exception) against an
        old binary that does not recognise the command -- callers must not
        let this break startup/resync/reload.
        """
        with self._lock:
            resp = self._command({
                "type": "set_repeat_enabled",
                "enabled": bool(enabled),
                "codec": str(codec),
            })
            return bool(resp and resp.get("ok"))

    def set_repeat_armed(self, armed: bool) -> bool:
        """Arm/disarm session replay. See set_repeat_enabled re: old binaries."""
        with self._lock:
            resp = self._command({"type": "set_repeat_armed", "armed": bool(armed)})
            return bool(resp and resp.get("ok"))

    def set_log_level(self, log_level: str) -> bool:
        with self._lock:
            normalized = normalize_log_level(log_level)
            resp = self._command({"type": "set_log_level", "level": normalized})
            ok = bool(resp and resp.get("ok"))
            if not ok:
                logging.error(
                    "MonitorClient: set_log_level(%r) failed: %s",
                    normalized, (resp or {}).get("error", "no response"),
                )
            return ok

    def start_output_dump(self, path: str, overwrite: bool = False) -> bool:
        """Begin recording output PCM to a WAV file at *path*.

        Returns True if the daemon accepted the request.  The C++ dispatcher
        rejects the call if a dump is already active; call stop_output_dump()
        first.
        """
        with self._lock:
            resp = self._command({
                "type": "start_output_dump",
                "path": path,
                "overwrite": overwrite,
            })
            ok = bool(resp and resp.get("ok"))
            if not ok:
                logging.error(
                    "MonitorClient: start_output_dump(%r) failed: %s",
                    path, (resp or {}).get("error", "no response"),
                )
            return ok

    def stop_output_dump(self) -> Optional[dict]:
        """Stop an active output dump and return the result dict.

        The result always has ok=True and includes was_active, frames_written,
        and frames_dropped.  Returns None only if the socket fails.
        """
        with self._lock:
            return self._command({"type": "stop_output_dump"})

    def get_status(self) -> Optional[dict]:
        """Return the parsed status dict, or None on failure."""
        with self._lock:
            return self._command({"type": "get_status"})

    def get_id_snapshot(
        self, index: int, max_seconds: int = 20
    ) -> "Optional[tuple[bytes, int]]":
        """Return (pcm_bytes, rate_hz) from the monitor's ID snapshot buffer.

        pcm_bytes is raw s16le mono PCM at rate_hz Hz.  Returns (b"", rate)
        when no frames are available yet.  Returns None on any protocol or
        socket failure.  The rate is read from the monitor ack so callers
        are not hardcoded to any particular sample rate.
        """
        with self._lock:
            resp = self._command({
                "type": "get_id_snapshot",
                "input": index,
                "max_seconds": max_seconds,
            })
            if not resp or not resp.get("ok"):
                return None
            frames = resp.get("frames", 0)
            rate = resp.get("rate")
            if not isinstance(frames, int) or isinstance(frames, bool):
                self.close()
                return None
            if frames < 0:
                self.close()
                return None
            if not isinstance(rate, int) or isinstance(rate, bool) or rate <= 0:
                self.close()
                return None
            if frames == 0:
                return (b"", rate)
            max_frames = max_seconds * rate
            if frames > max_frames:
                self.close()
                return None
            pcm = self._readbytes(frames * 2)
            if pcm is None:
                return None
            return (pcm, rate)


# --------------------------------------------------------------------------- #
# AudioMonitor                                                                 #
# --------------------------------------------------------------------------- #

class AudioMonitor:
    """Manages OwnTone control, now-playing metadata, and track recognition
    for one input channel.

    This class no longer performs audio capture or FIFO writing; those are
    handled by the C++ autostream_monitor daemon.  The coordinator loop
    ingests each get_status() poll via _ingest_status() and then fires
    OwnTone or recognition side-effects in a second pass once all monitor
    states have been updated.

    The allow_capture property is set by the coordinator to choose which
    input owns the FIFO at any moment; apply_allow_capture() sends the
    corresponding set_allow_capture command to the daemon when the value
    changes.
    """

    OWNTONE_RETRY_SECONDS = 10.0
    OWNTONE_LOG_THROTTLE_SECONDS = 60.0

    def __init__(
        self,
        input_index: int,
        input_device: str,
        silence_threshold_dbfs: float,
        silence_seconds: int,
        fifo_path: str,
        owntone_base_url: str,
        owntone_output_name: str,
        owntone_volume_percent: int,
        track_change_silence_seconds: float = 1.25,
        owntone_output_offsets_ms: Optional[dict[str, int]] = None,
        owntone_output_airplay_modes: Optional[dict[str, str]] = None,
        gain_db: float = 0.0,
        eq_40hz_db: float = 0.0,
        eq_100hz_db: float = 0.0,
        eq_8khz_db: float = 0.0,
    ) -> None:
        self.input_index = input_index
        self.input_device = input_device
        self.silence_threshold_dbfs = silence_threshold_dbfs
        self.silence_seconds = silence_seconds
        self.track_change_silence_seconds = track_change_silence_seconds
        self.fifo_path = fifo_path
        self.owntone_base_url = owntone_base_url
        self.owntone_output_name = owntone_output_name
        self.owntone_volume_percent = owntone_volume_percent
        self.owntone_output_offsets_ms = owntone_output_offsets_ms or {}
        self.owntone_output_airplay_modes = owntone_output_airplay_modes or {}
        self.gain_db = gain_db
        self.eq_40hz_db = eq_40hz_db
        self.eq_100hz_db = eq_100hz_db
        self.eq_8khz_db = eq_8khz_db

        # --- Now-playing metadata helpers ---
        self._nowplaying_cache = PersistentNowPlayingCache()
        # Shared per fifo_path: two AudioMonitors pointing at
        # the same physical FIFO (e.g. input1/input2 on one OwnTone pipe
        # input) must publish through one queue+thread, or their bundles can
        # interleave mid-stream during a cross-monitor source_changed
        # dispatch. Paired with release_shared_metadata_publisher() in stop().
        self._nowplaying_publisher = get_shared_metadata_publisher(fifo_path)
        # Track ID gives us an artwork URL, but the metadata pipe publishes
        # artwork as bytes read from a file, so the URL has to be fetched to
        # disk before OwnTone can carry it to the speakers. Cap the download at
        # what the pipe can actually carry; a larger image would be fetched
        # only to be dropped at publish time.
        self._artwork_cache = ArtworkFileCache(max_bytes=MAX_PICTURE_BYTES)
        self._current_nowplaying = (
            self._nowplaying_cache.get_manual_hint(input_device)
            or NowPlayingMetadata(
                title=f"Autostream ({input_device})",
                artist="Vinyl",
                album="Unknown Album",
            )
        )

        # --- Track identification scheduling ---
        from track_id.models import disabled_snapshot as _ds
        self._ti_state_lock = threading.Lock()  # guards dispatch setup and _apply_track_id_service
        self._ti_generation: int = 0           # incremented on service swap or capture start
        self._ti_inflight: bool = False
        self._ti_inflight_token: Optional[object] = None  # unique per worker
        self._ti_next_attempt: float = 0.0
        self._ti_next_attempt_reason: str = ""
        self._ti_last_attempt: float = 0.0
        self._ti_last_identified_at: float = 0.0
        self._ti_snapshot = _ds()              # replaced atomically under GIL

        # --- Status (updated by coordinator via _ingest_status) ---
        self.level_dbfs: float = -90.0
        self.poll_peak_dbfs: float = -90.0
        self.detected_hz: float = 0.0
        self.is_silent: bool = True
        self.is_capturing: bool = False
        # Set each poll cycle from the coordinator's _replay_origin_input():
        # True while this input is the origin of a currently
        # replaying recording, i.e. it is the session's audible source even
        # though it is not itself "capturing". See _ingest_status() and
        # maybe_trigger_track_identification()'s actively-sourcing gate.
        self._replay_origin: bool = False
        self._last_active_time: Optional[float] = None
        self._tracker_playback_active: bool = False
        self.track_change_seq: int = 0           # last seq from daemon; monotonically increasing
        self._track_change_seq_baseline: int = 0  # seq at capture session start (baselined on "started" transition)
        # Latest VU history block from the daemon (passed through as-is).
        # Replaced atomically on each status poll; Flask thread reads under GIL.
        self.vu_history: dict = {}

        # --- allow_capture: set by coordinator; synced to daemon lazily ---
        self._allow_capture: bool = True
        self._allow_capture_sent: Optional[bool] = None  # last value sent to daemon

        # --- OwnTone retry state ---
        self._owntone_last_attempt: float = 0.0
        self._owntone_last_log: float = 0.0
        self._owntone_enabled_ok: bool = False
        self._capture_start_no_output_retry_at: float = 0.0
        self._capture_start_no_output_log_at: float = 0.0

        with _monitors_lock:
            all_monitors.append(self)

    # ── Public interface ─────────────────────────────────────────────────────

    @property
    def allow_capture(self) -> bool:
        return self._allow_capture

    @allow_capture.setter
    def allow_capture(self, value: bool) -> None:
        self._allow_capture = value
        # Actual socket send is deferred to apply_allow_capture().

    @property
    def seconds_since_last_activity(self) -> float:
        """Seconds since audio last exceeded the silence threshold.

        Returns float('inf') if activity has never been observed.
        """
        if self._last_active_time is None:
            return float("inf")
        return time.time() - self._last_active_time

    def _ingest_status(self, status_entry: dict, replay_origin: bool = False) -> str:
        """Update fields from a get_status() entry without firing callbacks.

        Returns 'started', 'stopped', or '' to indicate the capturing
        transition so the coordinator can fire callbacks in a second pass,
        after all monitors have been updated.

        *replay_origin* is this same poll cycle's _replay_origin_input()
        result compared against self.input_index: True while
        this input is the origin of a currently-replaying recording, so it
        is "actively sourcing" the session even though is_capturing is False.
        track_change_seq advances are daemon-routed under origin_input during
        replay, so the steady-state seq check below must key off
        actively-sourcing, not is_capturing alone, or replay-driven track
        changes are silently dropped. The transition into/out of
        replay-sourcing itself is NOT handled here -- since is_capturing does
        not change when replay starts/stops, there is no "started"/"stopped"
        edge to return; the seq baseline + identification-cycle arming for
        that transition is handled by _dispatch_session_event() ->
        _arm_track_identification_for_replay(), which runs after this method
        for the whole monitor set (mirrors _on_capture_started, which arms
        the same cycle for a real capturing transition).
        """
        was_capturing = self.is_capturing
        was_actively_sourcing = was_capturing or self._replay_origin

        self.level_dbfs      = float(status_entry.get("level_dbfs", -90.0))
        self.poll_peak_dbfs  = float(status_entry.get("poll_peak_dbfs", -90.0))
        self.detected_hz     = float(status_entry.get("detected_hz", 0.0))
        self.is_silent       = bool(status_entry.get("silent", True))
        self.is_capturing    = bool(status_entry.get("capturing", False))
        self._replay_origin  = bool(replay_origin)
        raw_tcs = status_entry.get("track_change_seq")
        if isinstance(raw_tcs, int) and raw_tcs >= 0:
            self.track_change_seq = raw_tcs
        # Cache the whole vu_history block; Flask thread reads it as-is.
        raw_vu = status_entry.get("vu_history")
        self.vu_history = raw_vu if isinstance(raw_vu, dict) else {}

        if not self.is_silent:
            self._last_active_time = time.time()

        is_actively_sourcing = self.is_capturing or self._replay_origin

        if self.is_capturing and not was_capturing:
            self._track_change_seq_baseline = self.track_change_seq
            return "started"
        if not self.is_capturing and was_capturing:
            return "stopped"

        # No capturing transition this cycle: check for track-change events
        # whenever actively-sourcing on both sides of this ingest (a fresh
        # transition into replay-sourcing is armed by _dispatch_session_event
        # instead, after this same poll cycle's baseline would otherwise be
        # stale/unset).
        if was_actively_sourcing and is_actively_sourcing:
            if self.track_change_seq != self._track_change_seq_baseline:
                self._on_possible_track_change(self.track_change_seq)

        return ""

    def _on_possible_track_change(self, new_seq: int) -> None:
        """Handle a track_change_seq advance while capturing."""
        self._track_change_seq_baseline = new_seq
        svc = _track_id_service
        if svc is None:
            return
        self._ti_generation += 1  # invalidate stale in-flight worker results
        from track_id.models import waiting_snapshot
        self._ti_snapshot = waiting_snapshot(input_index=self.input_index)
        delay = svc.analysis_lead_in_seconds + svc.snapshot_seconds
        now = time.time()
        logging.info(
            "track_id[%d]: possible track change seq=%d; analysis scheduled in %ds"
            " (lead-in=%ds window=%ds)",
            self.input_index, new_seq, delay,
            svc.analysis_lead_in_seconds, svc.snapshot_seconds,
        )
        self._schedule_track_id_after(now, delay, "track_change")

    def apply_allow_capture(self, client: "MonitorClient") -> None:
        """Send set_allow_capture to the daemon if the value has changed."""
        if self._allow_capture != self._allow_capture_sent:
            if client.set_allow_capture(self.input_index, self._allow_capture):
                self._allow_capture_sent = self._allow_capture

    def stop(self) -> None:
        """Release resources (call at shutdown)."""
        self._tracker_playback_active = False
        try:
            # Release this monitor's reference to the shared publisher
            # rather than closing it directly: another
            # AudioMonitor on the same fifo_path may still be using it. The
            # registry only actually closes the underlying thread once the
            # last referencing monitor has released it.
            release_shared_metadata_publisher(self.fifo_path)
        except Exception:
            pass

    def _sync_playback_tracker_state(self, repeat_status: Optional[dict] = None) -> None:
        """Keep playback-hour tracking aligned to audible activity.

        *repeat_status* is the same-poll top-level "repeat" block:
        while repeat.replay.active, the origin input's recording is audibly
        playing even though that input itself is not capturing, so hours must
        keep accruing against repeat.recording.origin_input. Track-ID/now-
        playing metadata are unaffected here -- they keep flowing from the
        daemon's replay-path track-change events independently.
        """
        tracker = _playback_tracker
        if tracker is None:
            self._tracker_playback_active = False
            return

        replaying_this_input = False
        if isinstance(repeat_status, dict):
            replay = repeat_status.get("replay")
            if isinstance(replay, dict) and bool(replay.get("active")):
                recording = repeat_status.get("recording")
                origin_input = recording.get("origin_input") if isinstance(recording, dict) else None
                replaying_this_input = origin_input == self.input_index

        playback_active = (self.is_capturing and not self.is_silent) or replaying_this_input
        if playback_active == self._tracker_playback_active:
            return

        if playback_active:
            tracker.on_playback_started(self.input_index)
        else:
            tracker.on_playback_stopped(self.input_index)
        self._tracker_playback_active = playback_active

    # ── Capture transitions ──────────────────────────────────────────────────

    def _on_capture_started(self) -> None:
        """Called when the daemon transitions this channel to capturing.

        Per-input duties only: track-ID scheduling and logging.
        Session-level duties -- OwnTone output-enable/default-volume and
        now-playing publish_start -- are not fired unconditionally on
        every capture-start transition, since a replay-sourced session start
        never transitions any input to capturing at all. They run from the
        coordinator's _SessionTracker session_started event via
        _start_session_owntone() / _session_nowplaying_start(), see the poll
        loop in run_autostream().
        """
        self._ti_generation += 1  # invalidate any worker queued before capture started
        self._ti_inflight = False
        self._ti_inflight_token = None
        self._ti_next_attempt = 0.0
        self._ti_next_attempt_reason = ""
        self._ti_last_identified_at = 0.0
        if _track_id_service is not None:
            svc = _track_id_service
            delay = svc.analysis_lead_in_seconds + svc.snapshot_seconds
            self._schedule_track_id_after(time.time(), delay, "initial")
            logging.debug(
                "track_id[%d]: initial attempt scheduled in %.0fs (lead-in=%.0fs window=%.0fs).",
                self.input_index, delay, svc.analysis_lead_in_seconds, svc.snapshot_seconds,
            )
            from track_id.models import waiting_snapshot
            self._ti_snapshot = waiting_snapshot()
        else:
            from track_id.models import disabled_snapshot
            self._ti_snapshot = disabled_snapshot()

        logging.info(
            "Input %d (%s): capture started.",
            self.input_index, self.input_device,
        )

    def _arm_track_identification_for_replay(self) -> None:
        """Arm the identification cycle for a replay-sourced session.

        Mirrors _on_capture_started()'s track-ID setup (reset generation,
        invalidate in-flight state, schedule the initial attempt), but is
        invoked directly by _dispatch_session_event() for a session_started
        or source_changed event landing on the "replay" source. is_capturing
        never transitions to True in that case (the origin input isn't
        capturing while its recording replays), so _on_capture_started would
        otherwise never fire and this input's identification cycle would stay
        parked at whatever state it was in before replay began: the daemon
        serves replay-tap snapshots under origin_input, so the Python side
        only needs to schedule attempts, not gate on is_capturing.

        Also baselines track_change_seq here, since _ingest_status()'s
        steady-state seq check requires actively-sourcing on BOTH sides of
        an ingest and so deliberately does not fire (and does not baseline)
        on the same cycle this transition is first observed.
        """
        self._track_change_seq_baseline = self.track_change_seq
        self._ti_generation += 1  # invalidate any worker queued before replay sourcing began
        self._ti_inflight = False
        self._ti_inflight_token = None
        self._ti_next_attempt = 0.0
        self._ti_next_attempt_reason = ""
        self._ti_last_identified_at = 0.0
        if _track_id_service is not None:
            svc = _track_id_service
            delay = svc.analysis_lead_in_seconds + svc.snapshot_seconds
            self._schedule_track_id_after(time.time(), delay, "initial")
            logging.debug(
                "track_id[%d]: initial attempt scheduled in %.0fs (replay-sourced session; "
                "lead-in=%.0fs window=%.0fs).",
                self.input_index, delay, svc.analysis_lead_in_seconds, svc.snapshot_seconds,
            )
            from track_id.models import waiting_snapshot
            self._ti_snapshot = waiting_snapshot()
        else:
            from track_id.models import disabled_snapshot
            self._ti_snapshot = disabled_snapshot()

        logging.info(
            "Input %d (%s): identification armed for replay-sourced session.",
            self.input_index, self.input_device,
        )

    def _on_capture_stopped(
        self,
        client: "MonitorClient",
    ) -> None:
        """Called when the daemon transitions this channel out of capturing.

        Per-input duties only: track-ID state invalidation and
        logging. Session-level duties -- the OwnTone idle-stop and
        now-playing publish_end -- are not fired here: the coordinator's
        _SessionTracker source vector treats a capture-stop immediately
        followed by a replay-start as a source_changed event with no
        OwnTone-level capture-stop in between, so per-input teardown must
        stay silent on the session-level effects. The session-level stop
        runs from the tracker's session_ended event, see the poll loop in
        run_autostream().
        """
        # Invalidate any running worker and clear scheduled deadlines so a
        # worker that completes after capture stops cannot overwrite the
        # waiting/disabled snapshot below or leave a stale _ti_next_attempt.
        self._ti_generation += 1
        self._ti_next_attempt = 0.0
        self._ti_next_attempt_reason = ""
        self._track_change_seq_baseline = 0

        if _track_id_service is not None:
            from track_id.models import waiting_snapshot
            self._ti_snapshot = waiting_snapshot()
        else:
            from track_id.models import disabled_snapshot
            self._ti_snapshot = disabled_snapshot()

        logging.info(
            "Input %d (%s): capture stopped.",
            self.input_index, self.input_device,
        )

    # ── Track identification ──────────────────────────────────────────────────

    def _apply_track_id_service(self, service) -> None:
        """Set the initial snapshot based on whether the service is available."""
        with self._ti_state_lock:
            self._ti_generation += 1  # invalidate any in-flight worker for the old service
            if service is not None:
                from track_id.models import waiting_snapshot
                self._ti_snapshot = waiting_snapshot()
                # Schedule first attempt if currently capturing; otherwise wait for capture-start.
                if self.is_capturing:
                    delay = service.analysis_lead_in_seconds + service.snapshot_seconds
                    self._schedule_track_id_after(time.time(), delay, "initial")
                else:
                    self._ti_next_attempt = 0.0
                    self._ti_next_attempt_reason = ""
            else:
                from track_id.models import disabled_snapshot
                self._ti_snapshot = disabled_snapshot()
                self._ti_next_attempt = 0.0
                self._ti_next_attempt_reason = ""
            self._ti_inflight = False
            self._ti_inflight_token = None
            self._ti_last_identified_at = 0.0

    def _schedule_track_id_attempt(self, when: float, reason: str) -> None:
        """Set the next attempt deadline to `when`, preserving any later protected deadline."""
        from autostream_config import (
            TRACK_ID_RATE_LIMIT_BACKOFF_SECONDS,
            TRACK_ID_UPSTREAM_REJECTION_BACKOFF_SECONDS,
        )
        protected_reasons = {"rate_limit", "upstream_rejection"}
        if (self._ti_next_attempt_reason in protected_reasons
                and self._ti_next_attempt > when):
            return
        self._ti_next_attempt = max(when, time.time() + 1.0)
        self._ti_next_attempt_reason = reason

    def _schedule_track_id_after(self, now: float, delay: float, reason: str) -> None:
        """Set the next attempt deadline to `now + delay`."""
        self._schedule_track_id_attempt(now + delay, reason)

    def maybe_trigger_track_identification(
        self, client: "MonitorClient", now: float, replay_origin: bool = False,
    ) -> None:
        """Dispatch an identification worker if the deadline has elapsed and conditions allow.

        *replay_origin* is this poll cycle's _replay_origin_input() result
        compared against self.input_index: an input replaying
        its own recording is "actively sourcing" the session even though
        is_capturing is False, and the daemon already serves replay-tap
        snapshots for it under origin_input, so
        identification must run for it too. The is_silent check only applies
        to live capture -- a replay-sourced input is silent by definition
        (it isn't capturing anything), so gating on it here would make
        replay-sourced identification permanently dead.
        """
        svc = _track_id_service
        if svc is None:
            return
        actively_sourcing = self.is_capturing or replay_origin
        if not actively_sourcing:
            return
        if self.is_capturing and self.is_silent:
            return
        if self._ti_inflight:
            return
        if self._ti_next_attempt == 0.0 or now < self._ti_next_attempt:
            return

        # Attempt non-blocking acquisition of the process-wide admission gate.
        if not _track_id_request_gate.acquire(blocking=False):
            # Another input is active; retry after 1 s without disturbing the reason.
            self._ti_next_attempt = now + 1.0
            return

        # Gate acquired.  Recheck critical preconditions after acquiring.
        if not actively_sourcing or _track_id_service is not svc:
            _track_id_request_gate.release()
            return

        # Capture generation before the blocking snapshot call so any live
        # reconfiguration that bumps the generation during get_id_snapshot() is
        # detected by the recheck below.
        dispatch_gen = self._ti_generation

        snapshot = client.get_id_snapshot(self.input_index, max_seconds=svc.snapshot_seconds)

        # _ti_state_lock makes the post-snapshot recheck and all state mutations
        # atomic with respect to _apply_track_id_service(), which also holds this
        # lock.  Without it a concurrent live reconfiguration could publish a
        # disabled snapshot between our validation and our STATE_ANALYSING write,
        # leaving the UI stuck in analysing with no future attempt to clear it.
        with self._ti_state_lock:
            # Recheck generation and service immediately after the blocking
            # snapshot call, before interpreting its result.
            if self._ti_generation != dispatch_gen or _track_id_service is not svc:
                logging.debug(
                    "track_id[%d]: generation or service changed during snapshot; aborting dispatch.",
                    self.input_index,
                )
                _track_id_request_gate.release()
                return

            if snapshot is None or not snapshot[0]:
                logging.debug(
                    "track_id[%d]: get_id_snapshot returned no audio; retry in %.0fs.",
                    self.input_index, svc.retry_seconds,
                )
                _track_id_request_gate.release()
                self._schedule_track_id_after(now, svc.retry_seconds, "no_match")
                return
            pcm_bytes, rate = snapshot

            duration_s = len(pcm_bytes) / (rate * 2)
            logging.debug(
                "track_id[%d]: snapshot returned %d bytes (%.1f s, requested=%d s).",
                self.input_index, len(pcm_bytes), duration_s, svc.snapshot_seconds,
            )
            from track_id.service import MIN_PCM_DURATION_SECONDS
            if duration_s < MIN_PCM_DURATION_SECONDS:
                logging.debug(
                    "track_id[%d]: snapshot too short (%.1f s); retry in %.0fs.",
                    self.input_index, duration_s, svc.retry_seconds,
                )
                _track_id_request_gate.release()
                self._schedule_track_id_after(now, svc.retry_seconds, "no_match")
                return

            logging.info(
                "track_id[%d]: queuing identification (%.1f s of audio, reason=%s).",
                self.input_index, duration_s, self._ti_next_attempt_reason,
            )

            from track_id.models import STATE_ANALYSING, state_status_text, TrackIdentificationSnapshot
            self._ti_snapshot = TrackIdentificationSnapshot(
                enabled=True,
                state=STATE_ANALYSING,
                status_text=state_status_text(STATE_ANALYSING),
                input_index=self.input_index,
                provider=svc.provider_id,
                updated_at=now,
                last_attempt_at=now,
            )
            worker_token = object()
            self._ti_inflight = True
            self._ti_inflight_token = worker_token
            self._ti_last_attempt = now

            try:
                threading.Thread(
                    target=self._ti_worker,
                    args=(bytes(pcm_bytes), rate, worker_token, dispatch_gen),
                    daemon=True,
                    name=f"track-id-{self.input_index}",
                ).start()
            except Exception:
                logging.warning(
                    "track_id[%d]: Thread.start() failed; releasing gate.",
                    self.input_index, exc_info=True,
                )
                _track_id_request_gate.release()
                if self._ti_inflight_token is worker_token:
                    self._ti_inflight = False
                    self._ti_inflight_token = None

    def _ti_worker(self, pcm16_mono: bytes, sample_rate: int, worker_token: object, dispatch_gen: int) -> None:
        """Run identification in the background and schedule the next attempt."""
        from track_id.models import (
            TrackIDRateLimitedError,
            TrackIDUpstreamRejectionError,
            STATE_ERROR, STATE_IDENTIFIED, STATE_NOT_FOUND,
            state_status_text,
            TrackIdentificationSnapshot,
        )
        from autostream_config import (
            TRACK_ID_ERROR_RETRY_SECONDS,
            TRACK_ID_RATE_LIMIT_BACKOFF_SECONDS,
            TRACK_ID_REFRESH_JITTER_SECONDS,
            TRACK_ID_UPSTREAM_REJECTION_BACKOFF_SECONDS,
        )
        my_gen = dispatch_gen
        try:
            svc = _track_id_service
            if svc is None:
                return

            result = svc.identify(pcm16_mono, sample_rate, input_index=self.input_index)
            now = time.time()

            if self._ti_generation != my_gen or self._ti_inflight_token is not worker_token:
                return  # stale: service replaced or capture restarted while we ran

            if result.matched:
                jitter = random.uniform(-TRACK_ID_REFRESH_JITTER_SECONDS, TRACK_ID_REFRESH_JITTER_SECONDS)
                delay = max(1.0, svc.refresh_seconds + jitter)
                self._schedule_track_id_after(now, delay, "match")
                logging.debug(
                    "track_id[%d]: identified; refresh scheduled in %.0fs (base=%.0fs jitter=%+.0fs).",
                    self.input_index, delay, svc.refresh_seconds, jitter,
                )
                self._ti_last_identified_at = now
                if result.title or result.artist:
                    # Fall back to the previous artwork rather than the hint's
                    # badge: an identified track with the wrong cover is worse
                    # than an identified track with the cover we already had.
                    artwork_url = result.artwork.url if result.artwork else ""
                    artwork_path = (
                        self._artwork_cache.get_path(artwork_url)
                        or self._current_nowplaying.artwork_path
                    )
                    new_meta = NowPlayingMetadata(
                        title=result.title or self._current_nowplaying.title,
                        artist=result.artist or self._current_nowplaying.artist,
                        album=result.album or self._current_nowplaying.album,
                        artwork_path=artwork_path,
                    )
                    if new_meta != self._current_nowplaying:
                        self._current_nowplaying = new_meta
                        # publish_refresh(), not publish_start(): this fires
                        # mid-session (track-ID match landing after the
                        # session's pbeg already went out), so it must not
                        # emit a second pbeg.
                        self._nowplaying_publisher.publish_refresh(new_meta)
                self._ti_snapshot = TrackIdentificationSnapshot(
                    enabled=True,
                    state=STATE_IDENTIFIED,
                    status_text=state_status_text(STATE_IDENTIFIED),
                    input_index=self.input_index,
                    provider=result.provider or svc.provider_id,
                    title=result.title,
                    artist=result.artist,
                    album=result.album,
                    artwork_url=(result.artwork.url if result.artwork else ""),
                    confidence=result.confidence,
                    updated_at=now,
                    last_attempt_at=now,
                )
            elif result.is_configuration_error:
                self._schedule_track_id_after(now, TRACK_ID_ERROR_RETRY_SECONDS, "error")
                logging.debug(
                    "track_id[%d]: configuration error; retry scheduled in %.0fs.",
                    self.input_index, TRACK_ID_ERROR_RETRY_SECONDS,
                )
                self._ti_snapshot = TrackIdentificationSnapshot(
                    enabled=True,
                    state=STATE_ERROR,
                    status_text=state_status_text(STATE_ERROR),
                    input_index=self.input_index,
                    provider=svc.provider_id,
                    updated_at=now,
                    last_attempt_at=now,
                )
            else:
                self._schedule_track_id_after(now, svc.retry_seconds, "no_match")
                logging.debug(
                    "track_id[%d]: no match; retry scheduled in %.0fs.",
                    self.input_index, svc.retry_seconds,
                )
                self._ti_snapshot = TrackIdentificationSnapshot(
                    enabled=True,
                    state=STATE_NOT_FOUND,
                    status_text=state_status_text(STATE_NOT_FOUND),
                    input_index=self.input_index,
                    provider=svc.provider_id,
                    updated_at=now,
                    last_attempt_at=now,
                )

        except Exception as exc:
            now = time.time()
            if self._ti_generation != my_gen or self._ti_inflight_token is not worker_token:
                return  # stale
            if isinstance(exc, TrackIDUpstreamRejectionError):
                logging.warning(
                    "track_id[%d]: upstream rejected request (http_status=%d); backing off %ds",
                    self.input_index, exc.http_status, TRACK_ID_UPSTREAM_REJECTION_BACKOFF_SECONDS,
                )
                self._schedule_track_id_after(now, TRACK_ID_UPSTREAM_REJECTION_BACKOFF_SECONDS, "upstream_rejection")
            elif isinstance(exc, TrackIDRateLimitedError):
                logging.warning(
                    "track_id[%d]: rate limited; backing off %ds",
                    self.input_index, TRACK_ID_RATE_LIMIT_BACKOFF_SECONDS,
                )
                self._schedule_track_id_after(now, TRACK_ID_RATE_LIMIT_BACKOFF_SECONDS, "rate_limit")
            else:
                logging.warning(
                    "track_id[%d]: worker error: %s; retry in %.0fs.",
                    self.input_index, type(exc).__name__, TRACK_ID_ERROR_RETRY_SECONDS,
                )
                self._schedule_track_id_after(now, TRACK_ID_ERROR_RETRY_SECONDS, "error")
            self._ti_snapshot = TrackIdentificationSnapshot(
                enabled=True,
                state=STATE_ERROR,
                status_text=state_status_text(STATE_ERROR),
                input_index=self.input_index,
                provider=(_track_id_service.provider_id if _track_id_service else ""),
                updated_at=now,
                last_attempt_at=now,
                error=type(exc).__name__,
            )

        finally:
            _track_id_request_gate.release()
            if self._ti_inflight_token is worker_token:
                self._ti_inflight = False
                self._ti_inflight_token = None

    # ── OwnTone helpers ──────────────────────────────────────────────────────

    def _maybe_retry_owntone(self, now: float, replay_origin: bool = False) -> None:
        """Periodically retry refreshing currently selected OwnTone outputs.

        *replay_origin* is True when this monitor's input is the current
        replay's origin_input: this input isn't "capturing" while
        replay plays its buffer, but it is still the session's audible
        source, so the retry must not bail out as if idle. Defaults to False
        so existing capture-driven call sites are unaffected.
        """
        if not self.is_capturing and not replay_origin:
            return
        if not self.owntone_base_url:
            return
        if self._owntone_enabled_ok:
            return
        if (now - self._owntone_last_attempt) < self.OWNTONE_RETRY_SECONDS:
            return
        self._owntone_last_attempt = now

        fifo_result = reconcile_fifo_with_backend(
            self.owntone_base_url,
            self.fifo_path,
            timeout=3.0,
            update_timeout_s=5.0,
            update_interval_s=2.0,
        )
        if not fifo_result.ok:
            self._throttled_owntone_log(
                now,
                logging.WARNING,
                "Skipping OwnTone recovery while FIFO/backend reconciliation failed: %s",
                fifo_result.message or "reconcile failed",
            )
            return

        outputs = self._get_owntone_outputs()
        if outputs is None:
            self._throttled_owntone_log(
                now,
                logging.WARNING,
                "Skipping OwnTone selected-output refresh: outputs API unavailable.",
            )
            return

        if not self._has_any_selected_outputs(outputs):
            if not self._auto_select_default_output(now, outputs, reason="retry"):
                self._throttled_owntone_log(
                    now,
                    logging.INFO,
                    "No outputs selected during capture; default fallback not available yet.",
                )
                return
            outputs = self._get_owntone_outputs()
            if outputs is None or not self._has_any_selected_outputs(outputs):
                return

        if self._refresh_selected_outputs(outputs):
            self._owntone_enabled_ok = True
            return

        self._throttled_owntone_log(
            now,
            logging.WARNING,
            "OwnTone selected-output refresh failed during capture; will retry.",
        )

    def _throttled_owntone_log(self, now: float, level: int, msg: str, *args) -> None:
        """Log OwnTone-related failures with a long throttle to avoid SD churn."""
        if (now - self._owntone_last_log) < self.OWNTONE_LOG_THROTTLE_SECONDS:
            return
        self._owntone_last_log = now
        logging.log(level, msg, *args)

    def _get_owntone_outputs(self):
        """Return OwnTone outputs list, or None if API is unavailable."""
        if not self.owntone_base_url:
            return None
        result = list_outputs(self.owntone_base_url, timeout=3)
        if not result.ok:
            return None
        return list(result.outputs)

    @staticmethod
    def _selected_output_ids(outputs) -> list[str]:
        return [
            str(output.id)
            for output in outputs
            if output.selected and output.id
        ]

    def _has_any_selected_outputs(self, outputs=None) -> bool:
        """Return True if OwnTone currently has at least one selected output."""
        if outputs is None:
            outputs = self._get_owntone_outputs()
            if outputs is None:
                return False
        return any(bool(output.selected) for output in outputs)

    def _auto_select_default_output(
        self,
        now: float,
        outputs=None,
        reason: str = "auto-select",
    ) -> bool:
        """If nothing is selected, auto-enable the configured default output."""
        if not self.owntone_base_url:
            return False

        if outputs is None:
            outputs = self._get_owntone_outputs()
        if outputs is None:
            self._throttled_owntone_log(
                now, logging.WARNING,
                "Could not fetch OwnTone outputs for default fallback (%s).", reason,
            )
            return False
        if self._has_any_selected_outputs(outputs):
            return True

        default_name = (self.owntone_output_name or "").strip()
        if not default_name:
            self._throttled_owntone_log(
                now, logging.WARNING,
                "No default output configured; cannot apply zero-target fallback (%s).",
                reason,
            )
            return False

        default_out = next(
            (output for output in outputs if str(output.name or "") == default_name),
            None,
        )
        if not default_out or not default_out.id:
            self._throttled_owntone_log(
                now, logging.WARNING,
                "Default output '%s' not found in OwnTone; cannot apply fallback (%s).",
                default_name, reason,
            )
            return False

        try:
            import autostream_output_usage as _ou
            _ou.refresh_now("default-output-auto-select", timeout=1.5)
            _usage = _ou.usage_for_output(default_name)
            if _usage is not None:
                logging.info(
                    "Default output '%s' is in use by %s; skipping auto-select (%s).",
                    default_name, _usage.owner_name, reason,
                )
                return False
        except Exception:
            logging.debug("_auto_select_default_output: usage check failed", exc_info=True)

        out_id = str(default_out.id)
        try:
            out_volume = int(self.owntone_volume_percent)
        except Exception:
            out_volume = 20
        out_volume = max(0, min(100, out_volume))
        offset_ms = self.owntone_output_offsets_ms.get(out_id)
        update_result = update_output(
            self.owntone_base_url,
            out_id,
            enabled=True,
            volume_percent=out_volume,
            offset_ms=int(offset_ms) if offset_ms is not None else None,
            mode=config_airplay_mode_to_backend(self.owntone_output_airplay_modes.get(out_id)),
            timeout=3,
        )
        if not update_result.ok:
            self._throttled_owntone_log(
                now,
                logging.WARNING,
                "Failed to apply default output settings for '%s' (%s): %s",
                default_name,
                reason,
                update_result.message,
            )
            return False

        logging.info(
            "No outputs selected; auto-enabled default output '%s' (%s).",
            default_name, reason,
        )
        return True

    def _refresh_selected_outputs(self, outputs=None) -> bool:
        """Re-apply current selected output IDs to nudge OwnTone playback state."""
        if not self.owntone_base_url:
            return False
        try:
            if outputs is None:
                outputs = self._get_owntone_outputs()
            if outputs is None:
                return False
            selected_ids = self._selected_output_ids(outputs)
            if not selected_ids:
                return False
            set_result = set_selected_outputs(self.owntone_base_url, selected_ids, timeout=3)
            if not set_result.ok:
                logging.warning(
                    "Failed to refresh selected OwnTone outputs: %s",
                    set_result.message,
                )
                return False
            refresh_result = refresh_runtime_state(self.owntone_base_url, timeout=3)
            if not refresh_result.ok and refresh_result.error_code != "unsupported":
                logging.warning(
                    "Failed to refresh OwnTone runtime state: %s",
                    refresh_result.message,
                )
                return False
            outputs_by_id = {str(output.id): output for output in outputs if output.id}
            try:
                recovery_volume = int(self.owntone_volume_percent)
            except Exception:
                recovery_volume = 20
            recovery_volume = max(0, min(100, recovery_volume))
            for out_id in selected_ids:
                out_key = str(out_id)
                output = outputs_by_id.get(out_key)
                if output is None:
                    continue
                offset_ms = self.owntone_output_offsets_ms.get(out_key)
                update_result = update_output(
                    self.owntone_base_url,
                    out_key,
                    volume_percent=recovery_volume,
                    offset_ms=int(offset_ms) if offset_ms is not None else None,
                    mode=config_airplay_mode_to_backend(self.owntone_output_airplay_modes.get(out_key)),
                    timeout=3,
                )
                if not update_result.ok:
                    logging.warning(
                        "Failed to refresh OwnTone output %s settings: %s",
                        out_id,
                        update_result.message,
                    )
                    return False
            logging.info("Refreshed selected OwnTone outputs: %s", selected_ids)
            return True
        except Exception as e:
            logging.warning("Error refreshing selected OwnTone outputs: %s", e)
            return False


# --------------------------------------------------------------------------- #
# Top-level entry points                                                       #
# --------------------------------------------------------------------------- #

def _push_repeat_policy(
    client: MonitorClient,
    enabled: bool,
    codec: str,
    context: str,
) -> None:
    """Push the persisted repeat enabled/codec policy to the daemon.

    Tolerant of rejection (F-C): an older monitor binary that does not
    recognise set_repeat_enabled, or a transient failure, must never fail the
    caller (startup / reconnect resync) -- it is only logged, and repeat state
    simply re-syncs on the next successful reconnect or settings change.
    `context` names the call site for the log line, e.g. "after reconnect" or
    "during startup".
    """
    if not client.set_repeat_enabled(enabled, codec):
        logging.info(
            "set_repeat_enabled(%r, %r) not accepted %s "
            "(older monitor binary, or a transient failure).",
            enabled, codec, context,
        )


def _resync_monitor_daemon(
    client: MonitorClient,
    monitors: list["AudioMonitor"],
    fifo_path: str,
    owntone_base_url: str,
    output_eq: OutputEqConfig,
    repeat_enabled: bool = False,
    repeat_codec: str = "auto",
) -> bool:
    """Re-send the full daemon state after reconnect.

    This is transactional from Python's point of view: if any required step
    fails for any configured monitor, the whole resync is treated as failed so
    the coordinator does not continue with Python-side monitor objects that do
    not exist in the daemon.

    set_repeat_enabled is the one exception: an old binary that does not
    recognise the command must not fail the whole resync, so its result is
    logged but not treated as fatal.
    """
    fifo_result = reconcile_fifo_with_backend(
        owntone_base_url,
        fifo_path,
        timeout=3.0,
        update_timeout_s=5.0,
        update_interval_s=2.0,
    )
    if not fifo_result.ok:
        logging.error(
            "Could not reconcile audio FIFO/backend during monitor-daemon reconnect: %s",
            fifo_result.message or "reconcile failed",
        )
        client.close()
        return False

    if not client.set_fifo(fifo_path):
        logging.warning("set_fifo failed after reconnect; will retry.")
        client.close()
        return False

    live_log_level = get_live_platform_log_level()
    if not client.set_log_level(live_log_level):
        logging.warning("set_log_level(%r) failed after reconnect; will retry.", live_log_level)
        client.close()
        return False

    for m in monitors:
        m._allow_capture_sent = None

    # Stop all inputs before reconfiguring.  The daemon may not have restarted
    # (the connection could have dropped due to a transient timeout while the
    # coordinator was blocked in OwnTone callbacks), in which case the inputs
    # are still running and configure_input / start_input would fail.
    # api_stop_input is idempotent — it is a safe no-op if the input is not
    # currently started.
    for m in monitors:
        client.stop_input(m.input_index)

    for m in monitors:
        if not client.configure_input(
            m.input_index,
            m.input_device,
            m.silence_threshold_dbfs,
            m.silence_seconds,
            m.track_change_silence_seconds,
        ):
            logging.warning(
                "configure_input(%d, %r) failed after reconnect; will retry full resync.",
                m.input_index,
                m.input_device,
            )
            client.close()
            return False

    for m in monitors:
        if not client.start_input(m.input_index):
            logging.warning(
                "start_input(%d) failed after reconnect; will retry full resync.",
                m.input_index,
            )
            client.close()
            return False

    for m in monitors:
        if not apply_input_gain(client, m.input_index, m.gain_db):
            logging.warning(
                "set_gain(%d, %.1f) failed after reconnect; will retry full resync.",
                m.input_index,
                m.gain_db,
            )
            client.close()
            return False

    for m in monitors:
        if not apply_input_eq(
            client,
            m.input_index,
            m.eq_40hz_db,
            m.eq_100hz_db,
            m.eq_8khz_db,
        ):
            logging.warning(
                "set_eq(%d) failed after reconnect; will retry full resync.",
                m.input_index,
            )
            client.close()
            return False

    for m in monitors:
        if not client.set_allow_capture(m.input_index, m._allow_capture):
            logging.warning(
                "set_allow_capture(%d, %r) failed after reconnect; will retry full resync.",
                m.input_index,
                m._allow_capture,
            )
            client.close()
            return False
        m._allow_capture_sent = m._allow_capture

    if not _apply_output_eq_config(client, output_eq):
        logging.warning("Output EQ config failed after reconnect; will retry full resync.")
        client.close()
        return False

    _push_repeat_policy(client, repeat_enabled, repeat_codec, "after reconnect")

    return True


def _configure_startup_monitors(
    client: MonitorClient,
    cfg,
    fifo_path: str,
) -> Optional[list["AudioMonitor"]]:
    """Configure daemon inputs for initial startup and return monitor objects."""
    if not client.set_log_level(cfg.general.log_level):
        logging.warning("set_log_level(%r) failed during startup; will retry.",
                        cfg.general.log_level)
        return None

    # Defensively stop both inputs before configuring.  If a previous reload
    # left the daemon with inputs still running (e.g. stop_input in the finally
    # block failed silently due to a lost connection), configure_input and
    # start_input would otherwise fail.  api_stop_input is idempotent.
    client.stop_input(1)
    client.stop_input(2)

    if not client.configure_input(
        1,
        cfg.audio1.capture_device,
        cfg.audio1.silence_threshold_dbfs,
        cfg.general.silence_seconds,
        cfg.track_identification.track_change_silence_seconds,
    ):
        logging.warning(
            "configure_input(1, %r) failed during startup; will retry.",
            cfg.audio1.capture_device,
        )
        return None

    if not client.start_input(1):
        logging.warning("start_input(1) failed during startup; will retry.")
        return None

    if not apply_input_gain(client, 1, cfg.audio1.gain_db):
        logging.warning("set_gain(1) failed during startup; will retry.")
        return None

    if not apply_input_eq(
        client,
        1,
        cfg.audio1.eq_40hz_db,
        cfg.audio1.eq_100hz_db,
        cfg.audio1.eq_8khz_db,
    ):
        logging.warning("set_eq(1) failed during startup; will retry.")
        return None

    monitors: list[AudioMonitor] = [AudioMonitor(
        input_index=1,
        input_device=cfg.audio1.capture_device,
        silence_threshold_dbfs=cfg.audio1.silence_threshold_dbfs,
        silence_seconds=cfg.general.silence_seconds,
        fifo_path=fifo_path,
        owntone_base_url=cfg.owntone.base_url,
        owntone_output_name=cfg.owntone.output_name,
        owntone_volume_percent=cfg.owntone.volume_percent,
        track_change_silence_seconds=cfg.track_identification.track_change_silence_seconds,
        owntone_output_offsets_ms=cfg.owntone.output_offsets_ms,
        owntone_output_airplay_modes=cfg.owntone.output_airplay_modes,
        gain_db=cfg.audio1.gain_db,
        eq_40hz_db=cfg.audio1.eq_40hz_db,
        eq_100hz_db=cfg.audio1.eq_100hz_db,
        eq_8khz_db=cfg.audio1.eq_8khz_db,
    )]

    if (
        cfg.audio2_enabled
        and cfg.audio2.capture_device
        and cfg.audio2.capture_device != cfg.audio1.capture_device
    ):
        audio2_ok = True

        if not client.configure_input(
            2,
            cfg.audio2.capture_device,
            cfg.audio2.silence_threshold_dbfs,
            cfg.general.silence_seconds,
            cfg.track_identification.track_change_silence_seconds,
        ):
            logging.error(
                "configure_input(2, %r) failed; skipping second input.",
                cfg.audio2.capture_device,
            )
            audio2_ok = False

        if audio2_ok and not client.start_input(2):
            logging.error("start_input(2) failed; skipping second input.")
            audio2_ok = False

        if audio2_ok and not apply_input_gain(client, 2, cfg.audio2.gain_db):
            logging.error("set_gain(2) failed; skipping second input.")
            audio2_ok = False

        if audio2_ok and not apply_input_eq(
            client,
            2,
            cfg.audio2.eq_40hz_db,
            cfg.audio2.eq_100hz_db,
            cfg.audio2.eq_8khz_db,
        ):
            logging.error("set_eq(2) failed; skipping second input.")
            audio2_ok = False

        if audio2_ok:
            monitors.append(AudioMonitor(
                input_index=2,
                input_device=cfg.audio2.capture_device,
                silence_threshold_dbfs=cfg.audio2.silence_threshold_dbfs,
                silence_seconds=cfg.general.silence_seconds,
                fifo_path=fifo_path,
                owntone_base_url=cfg.owntone.base_url,
                owntone_output_name=cfg.owntone.output_name,
                owntone_volume_percent=cfg.owntone.volume_percent,
                track_change_silence_seconds=cfg.track_identification.track_change_silence_seconds,
                owntone_output_offsets_ms=cfg.owntone.output_offsets_ms,
                owntone_output_airplay_modes=cfg.owntone.output_airplay_modes,
                gain_db=cfg.audio2.gain_db,
                eq_40hz_db=cfg.audio2.eq_40hz_db,
                eq_100hz_db=cfg.audio2.eq_100hz_db,
                eq_8khz_db=cfg.audio2.eq_8khz_db,
            ))

    if len(monitors) > 1:
        for m in monitors:
            m.allow_capture = False

    for m in monitors:
        m.apply_allow_capture(client)

    if not _apply_output_eq_config(client, cfg.output_eq):
        logging.warning("Output EQ config failed during startup; will retry.")
        return None

    # Push the persisted repeat policy so a freshly (re)started daemon
    # reflects it immediately, not only after the next settings change or
    # reconnect resync. Tolerated to fail against an older monitor binary --
    # this must never block startup.
    _push_repeat_policy(client, cfg.repeat.enabled, cfg.repeat.codec, "during startup")

    return monitors

def _check_webui_thread(thread) -> None:
    """Raise RuntimeError if the Web UI thread has exited unexpectedly.

    Called periodically from the coordinator loops so that a dead Web UI is
    detected within one poll interval and causes a process exit that allows
    systemd to restart the service.
    """
    if thread is not None and not thread.is_alive():
        raise RuntimeError("Web UI thread has exited unexpectedly; shutting down")


def run_autostream(config_path: str, start_webui=None, settings=None) -> None:
    """Run autostream using the given config file path.

    Connects to the autostream_monitor daemon, configures inputs, and runs
    the coordinator loop until a stop signal is received.

    If start_webui is provided it is called with (config_path, settings=settings)
    to start the optional web UI in a background thread.

    If settings is None a SettingsStore is created internally and closed when
    the coordinator exits.  Pass an externally-owned store to share the same
    in-memory config between the coordinator and the Web UI.
    """
    from autostream_settings import SettingsStore as _SettingsStore
    _own_settings = settings is None
    if settings is None:
        settings = _SettingsStore(config_path)

    global _playing_announced, _reconcile_started
    _install_signal_handlers()
    cfg = settings.snapshot()
    setup_logging(cfg.general.log_file, cfg.general.log_level)
    try:
        from autostream_log_policy import apply_startup_log_level as _apply_startup_log_level
        _apply_startup_log_level(config_path)
    except Exception:
        logging.warning("apply_startup_log_level: import or apply failed; continuing")
    try:
        from autostream_webui_api import forward_log_level_to_watcher as _forward_log_level_to_watcher
        if not _forward_log_level_to_watcher(cfg.general.log_level):
            logging.debug("forward_log_level_to_watcher: startup forward not accepted")
    except Exception:
        logging.debug("forward_log_level_to_watcher: startup import or forward failed; continuing")
    audit_static_system_facts()
    _ensure_playback_tracker(cfg)
    _install_state = get_install_state(Path("/var/lib/autostream/install-state.env"))
    version = _install_state.get("AUTOSTREAM_RELEASE_TAG", "")

    # Optionally start the web UI.  Let any startup failure propagate so the
    # process exits nonzero and systemd can restart it.
    webui_thread = None
    if start_webui is not None:
        webui_thread = start_webui(config_path, settings=settings)

    socket_path = get_monitor_socket_path()
    POLL_INTERVAL = 0.5          # seconds between get_status() polls
    SWITCH_SILENCE_SECONDS = 5.0 # how long current input must be silent before switching

    # Remove any stale playing announcement from a previous crash, then
    # sync _playing_announced to filesystem truth so _sync_playing_announcement
    # does not attempt a redundant remove on the first poll.
    remove_avahi_playing_service()
    _playing_announced = _AVAHI_PLAYING_PATH.exists()
    _start_output_usage_poller(cfg)

    # Outer loop: runs once normally; repeats after a config reload.
    while not stop_flag.is_set():
        client = MonitorClient(socket_path)
        monitors: Optional[list[AudioMonitor]] = None

        # ── Startup / configuration phase ────────────────────────────────────
        while not stop_flag.is_set():
            if unconfigured(config_path):
                if start_webui is None:
                    logging.error("Configuration is incomplete; cannot start without a valid INI.")
                    return
                logging.info(
                    "Configuration is incomplete or has an invalid device format; "
                    "starting in setup mode and waiting for Web UI changes.",
                )
                while not stop_flag.is_set() and unconfigured(config_path):
                    _check_webui_thread(webui_thread)
                    time.sleep(1.0)
                if stop_flag.is_set():
                    return
                cfg = settings.snapshot()
                continue

            cfg = settings.snapshot()
            fifo_path = cfg.general.fifo_path
            _ensure_playback_tracker(cfg)

            if not client.connect():
                logging.warning(
                    "Cannot connect to autostream_monitor at %s; retrying in 5 s.",
                    socket_path,
                )
                _check_webui_thread(webui_thread)
                time.sleep(5.0)
                continue

            fifo_result = reconcile_fifo_with_backend(cfg.owntone.base_url, fifo_path, timeout=3.0)
            if not fifo_result.ok:
                logging.error(
                    "Could not reconcile audio FIFO/backend during startup: %s",
                    fifo_result.message or "reconcile failed",
                )
                client.close()
                _check_webui_thread(webui_thread)
                time.sleep(5.0)
                continue

            if not client.set_fifo(fifo_path):
                logging.warning("set_fifo(%r) failed during startup; retrying in 5 s.", fifo_path)
                client.close()
                _check_webui_thread(webui_thread)
                time.sleep(5.0)
                continue

            if cfg.owntone.base_url:
                pipe_ready_result = ensure_pipe_source_ready(cfg.owntone.base_url, timeout=3)
                if pipe_ready_result.ok:
                    logging.info("OwnTone pipe source is indexed and ready.")
                else:
                    logging.warning(
                        "OwnTone pipe source is not indexed yet; "
                        "playback start may fail until backend refresh succeeds (%s).",
                        pipe_ready_result.message or "not ready",
                    )

            monitors = _configure_startup_monitors(client, cfg, fifo_path)
            if monitors is not None:
                break

            client.close()
            _check_webui_thread(webui_thread)
            time.sleep(5.0)

        if stop_flag.is_set() or monitors is None:
            client.close()
            break

        global _track_id_service
        _track_id_service = _build_track_id_service(cfg)
        for m in monitors:
            m._apply_track_id_service(_track_id_service)

        logging.info(
            "autostream_core is now running with %d input(s). Press Ctrl+C to exit.",
            len(monitors),
        )

        if not _reconcile_started:
            def _get_current_monitors() -> list:
                with _monitors_lock:
                    return list(all_monitors)
            _start_playing_reconciliation(_get_current_monitors, version)
            _reconcile_started = True

        _start_output_usage_poller(cfg)

        current: Optional[AudioMonitor] = None
        reconnect_at: float = 0.0
        _reloading = False
        # Unified playback-session tracker: fresh instance
        # each time this point is reached (startup and every config reload),
        # and explicitly .reset() on reconnect/resync below, so a stale
        # pre-reload/pre-reconnect source can never manufacture a spurious
        # event once polling resumes.
        session_tracker = _SessionTracker()
        # OwnTone-restart reconcile + hang watchdog: same fresh-per-(re)start
        # / .reset()-on-reconnect lifecycle as session_tracker above -- a
        # stale pre-reload/pre-reconnect streak or rate-limit window must
        # never carry across a resync.
        owntone_reconcile_tracker = _OwntoneReconcileTracker()
        owntone_hang_watchdog = _OwntoneHangWatchdog()

        try:
            while not stop_flag.is_set():

                # ── Web UI health check ───────────────────────────────────────
                _check_webui_thread(webui_thread)

                # ── Config reload requested by Web UI ────────────────────────
                if reload_flag.is_set():
                    reload_flag.clear()
                    _reloading = True
                    logging.info("Config reload requested; tearing down monitors.")
                    break

                # ── Reconnect if the socket was lost ─────────────────────────
                if not client.is_connected():
                    now = time.time()
                    if now < reconnect_at:
                        time.sleep(min(1.0, reconnect_at - now))
                        continue

                    if not client.connect():
                        _set_monitor_runtime_info(connected=False)
                        logging.warning(
                            "autostream_monitor unavailable; retrying in 5 s.",
                        )
                        reconnect_at = time.time() + 5.0
                        continue

                    # Reconnected: re-send the full configuration because the
                    # daemon may have restarted and lost its state.
                    if not _resync_monitor_daemon(
                        client,
                        monitors,
                        fifo_path,
                        cfg.owntone.base_url,
                        cfg.output_eq,
                        cfg.repeat.enabled,
                        cfg.repeat.codec,
                    ):
                        _set_monitor_runtime_info(connected=False)
                        reconnect_at = time.time() + 5.0
                        current = None
                        continue

                # ── Poll status ───────────────────────────────────────────────
                    if cfg.owntone.base_url:
                        pipe_ready_result = ensure_pipe_source_ready(cfg.owntone.base_url, timeout=3)
                        if pipe_ready_result.ok:
                            logging.info("OwnTone pipe source is indexed and ready after reconnect.")
                        else:
                            logging.warning(
                                "OwnTone pipe source is not indexed yet after reconnect; "
                                "playback recovery may lag until backend refresh succeeds (%s).",
                                pipe_ready_result.message or "not ready",
                            )

                    for m in monitors:
                        m._owntone_enabled_ok = False
                        m._owntone_last_attempt = 0.0
                    session_tracker.reset()
                    # Reconcile's zero-selected-outputs streak is meaningless
                    # across a resync (session state itself just got reset
                    # above); the hang watchdog's 10-minute restart rate limit
                    # is intentionally NOT reset here -- it is a hard global
                    # safety limit that must survive a flapping daemon
                    # connection, not something a reconnect should clear.
                    owntone_reconcile_tracker.reset()

                status = client.get_status()
                if status is None:
                    _set_monitor_runtime_info(connected=False)
                    logging.warning("get_status() failed; will reconnect.")
                    reconnect_at = time.time() + 2.0
                    continue

                _set_monitor_runtime_info(
                    monitor_build=str(status.get("monitor_build") or "").strip() or "unknown",
                    log_level=str(status.get("log_level") or "").strip() or "unknown",
                    connected=True,
                    last_seen_at=time.time(),
                )

                status_by_index = {
                    e["index"]: e for e in status.get("inputs", [])
                }

                # Cache the top-level "repeat" block from this same snapshot
                # for /api/status passthrough and take a local copy
                # so the transition/gating/tracker logic below all reason
                # about the one poll cycle's view, not a value that could be
                # overwritten by a later poll before this cycle finishes.
                repeat_status = status.get("repeat")
                repeat_status = repeat_status if isinstance(repeat_status, dict) else None
                _set_repeat_status(repeat_status)

                # Computed once per poll cycle from this same snapshot
                # and reused below for _ingest_status()'s
                # actively-sourcing seq check, the OwnTone retry replay_origin
                # gate, and the track-ID actively-sourcing gate -- all must
                # agree on which input (if any) is the replay origin for THIS
                # cycle, not a later, possibly-stale repeat_status.
                replay_origin_idx = _replay_origin_input(repeat_status)

                # Two-pass update so that callbacks see the final state of ALL
                # monitors, not a partially-updated snapshot.  This prevents
                # spurious OwnTone stop/disable when one input hands off to
                # another in the same poll cycle.
                started: list[AudioMonitor] = []
                stopped: list[AudioMonitor] = []

                for m in monitors:
                    if m.input_index in status_by_index:
                        transition = m._ingest_status(
                            status_by_index[m.input_index],
                            replay_origin=(m.input_index == replay_origin_idx),
                        )
                        if transition == "started":
                            started.append(m)
                        elif transition == "stopped":
                            stopped.append(m)

                # Keep playback-hours tracking aligned to actual audible
                # activity, rather than the broader capture window that
                # includes the silence timeout used to detect playback end.
                for m in monitors:
                    m._sync_playback_tracker_state(repeat_status)

                # Per-input duties only (track-ID scheduling + logging); see
                # _on_capture_started/_on_capture_stopped docstrings. Fire
                # stopped callbacks first so any_monitor_capturing() is
                # already correct when started callbacks check it.
                for m in stopped:
                    m._on_capture_stopped(client)
                for m in started:
                    m._on_capture_started()

                if started or stopped:
                    _sync_playing_announcement(monitors, version)

                # ── Unified playback-session tracker ───────────────────────────
                # Single call site: derives the {input1, input2, replay}
                # source vector from this SAME snapshot and fires exactly one
                # of session_started / session_ended / source_changed / None,
                # dispatched by _dispatch_session_event(). This is the sole
                # place session-level OwnTone output-enable/stop and
                # now-playing publish_start/publish_end run -- see
                # _SessionTracker's module comment for the full event
                # semantics.
                session_event, session_prev_monitor, session_new_monitor, session_source = (
                    session_tracker.update(monitors, repeat_status)
                )
                _dispatch_session_event(
                    session_event, session_prev_monitor, session_new_monitor,
                    cfg.owntone.base_url, new_source=session_source,
                )
                _set_session_state(session_source is not None, session_source)

                # ── OwnTone-restart reconcile + hang watchdog ──────────────────
                # Both run every cycle (not gated on started/stopped/session
                # events above) so a mid-session state loss on an otherwise
                # steady-state "still playing" cycle is still caught.
                _reconcile_owntone_outputs_if_wiped(
                    owntone_reconcile_tracker,
                    session_new_monitor,
                    session_source is not None,
                    time.time(),
                )
                _maybe_run_owntone_hang_watchdog(
                    owntone_hang_watchdog,
                    status,
                    session_source is not None,
                    cfg.owntone.base_url,
                    time.time(),
                )

                # ── Multi-input coordination ──────────────────────────────────
                if len(monitors) == 1:
                    monitors[0].allow_capture = True
                    current = monitors[0]
                else:
                    # Rank inputs that are currently above their silence threshold
                    # by level, highest first.
                    loud = sorted(
                        [m for m in monitors if not m.is_silent],
                        key=lambda m: m.level_dbfs,
                        reverse=True,
                    )
                    candidate = loud[0] if loud else None
                    new_current = current

                    if current is None or not current.is_capturing:
                        # Nothing playing: pick any loud candidate.
                        if candidate is not None:
                            new_current = candidate
                    else:
                        silent_for = current.seconds_since_last_activity
                        if (
                            candidate is not None
                            and candidate is not current
                            and SWITCH_SILENCE_SECONDS <= silent_for < current.silence_seconds
                        ):
                            # Current has been silent long enough but not timed
                            # out yet; hand off to the louder candidate.
                            new_current = candidate

                    if new_current is not current:
                        for m in monitors:
                            m.allow_capture = m is new_current
                        current = new_current
                        if current is not None:
                            logging.info(
                                "Switched active input to %s.", current.input_device,
                            )
                        else:
                            logging.info("No active input selected.")

                # ── Flush pending allow_capture changes and OwnTone retries ───
                # replay_origin_idx was already computed above from this same
                # snapshot, before the ingest loop.
                now = time.time()
                for m in monitors:
                    m.apply_allow_capture(client)
                    m._maybe_retry_owntone(now, replay_origin=(m.input_index == replay_origin_idx))
                    m.maybe_trigger_track_identification(
                        client, now, replay_origin=(m.input_index == replay_origin_idx),
                    )

                tracker = _playback_tracker
                if tracker is not None:
                    tracker.maybe_flush()

                time.sleep(POLL_INTERVAL)

        except Exception:
            logging.exception("Unexpected coordinator error; running cleanup before exit")
            raise

        finally:
            tracker = _playback_tracker
            teardown_was_capturing = any(m.is_capturing for m in monitors)
            teardown_owntone_base_url = next(
                (m.owntone_base_url for m in monitors if m.owntone_base_url),
                "",
            )
            if teardown_was_capturing and teardown_owntone_base_url:
                _stop_and_disable_owntone(
                    teardown_owntone_base_url,
                    "coordinator teardown",
                )
            # Disarm repeat before stop_input below: the
            # daemon also discards the buffer on stop_input of the origin
            # input, so this is belt-and-braces, and its failure (old binary,
            # or the socket already being gone) must never break teardown.
            try:
                client.set_repeat_armed(False)
            except Exception:
                logging.debug("set_repeat_armed(False) during teardown failed", exc_info=True)
            for m in monitors:
                if tracker is not None:
                    tracker.on_playback_stopped(m.input_index)
                client.stop_input(m.input_index)
                m.stop()
            if tracker is not None:
                tracker.save()
            with _monitors_lock:
                all_monitors.clear()
            _sync_playing_announcement([], version)
            client.close()
            if not _reloading:
                logging.info("Stopped cleanly.")
                _cleanup_discovery()

        if not _reloading:
            break
        # _reloading: continue outer loop → startup phase runs again with fresh config

    # Final flush: persist any pending in-memory changes before process exit.
    # Also covers the case where the coordinator loop was never entered (stop_flag
    # set during the startup phase before _cleanup_discovery ran in the finally).
    _cleanup_discovery()
    try:
        settings.save_now()
    except Exception:
        logging.warning("Settings: final save failed", exc_info=True)
    if _own_settings:
        settings.close(save=False)  # save already attempted above


def main() -> None:
    """CLI entry point for running autostream without the web UI."""
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} PATH_TO_CONFIG.json")
        sys.exit(1)

    run_autostream(sys.argv[1])


if __name__ == "__main__":
    main()
