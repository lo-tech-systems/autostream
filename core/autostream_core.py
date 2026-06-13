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
from autostream_nowplaying import (
    NowPlayingMetadata,
    OwntoneMetadataPipePublisher,
    PersistentNowPlayingCache,
)
try:
    from autostream_nowplaying import VinylRecognizer
except ImportError:  # Optional recognizer; core should run without it.
    VinylRecognizer = None  # type: ignore[assignment]

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
    get_install_state,
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


def handle_signal(signum, frame):
    stop_flag.set()


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
    logging.basicConfig(
        level=python_log_level_value(normalized),
        format="%(asctime)s: %(message)s",
        datefmt="%d-%b-%y %H:%M:%S",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout),
        ],
    )
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
    ) -> bool:
        with self._lock:
            resp = self._command({
                "type": "configure_input",
                "input": index,
                "device": device,
                "silence_threshold_dbfs": silence_threshold_dbfs,
                "silence_seconds": silence_seconds,
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

    def get_status(self) -> Optional[dict]:
        """Return the parsed status dict, or None on failure."""
        with self._lock:
            return self._command({"type": "get_status"})

    def get_id_snapshot(self, index: int, max_seconds: int = 20) -> Optional[bytes]:
        """Return raw s16le mono 22050 Hz PCM bytes, or None on failure.

        Reads the JSON ack line, then reads the binary payload of exactly
        frames * 2 bytes as declared in the ack.  Returns an empty bytes
        object if the monitor reports zero frames available.
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
            if not isinstance(frames, int) or isinstance(frames, bool):
                self.close()
                return None
            if frames < 0:
                self.close()
                return None
            if frames == 0:
                return b""
            max_frames = max_seconds * 22050
            if frames > max_frames:
                self.close()
                return None
            return self._readbytes(frames * 2)


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
        self._nowplaying_publisher = OwntoneMetadataPipePublisher(fifo_path)
        self._vinyl_recognizer = (
            VinylRecognizer(self._nowplaying_cache, input_device)
            if VinylRecognizer else None
        )
        if self._vinyl_recognizer is None:
            logging.info("Input %d: vinyl recognizer unavailable.", input_index)
        self._current_nowplaying = (
            self._nowplaying_cache.get_manual_hint(input_device)
            or NowPlayingMetadata(
                title=f"Autostream ({input_device})",
                artist="Vinyl",
                album="Unknown Album",
            )
        )

        # --- Recognition state ---
        self._recognition_inflight = False
        self._recognition_attempt_count = 0

        # --- Status (updated by coordinator via _ingest_status) ---
        self.level_dbfs: float = -90.0
        self.poll_peak_dbfs: float = -90.0
        self.detected_hz: float = 0.0
        self.is_silent: bool = True
        self.is_capturing: bool = False
        self._last_active_time: Optional[float] = None
        self._tracker_playback_active: bool = False
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

    def _ingest_status(self, status_entry: dict) -> str:
        """Update fields from a get_status() entry without firing callbacks.

        Returns 'started', 'stopped', or '' to indicate the capturing
        transition so the coordinator can fire callbacks in a second pass,
        after all monitors have been updated.
        """
        was_capturing = self.is_capturing

        self.level_dbfs      = float(status_entry.get("level_dbfs", -90.0))
        self.poll_peak_dbfs  = float(status_entry.get("poll_peak_dbfs", -90.0))
        self.detected_hz     = float(status_entry.get("detected_hz", 0.0))
        self.is_silent       = bool(status_entry.get("silent", True))
        self.is_capturing    = bool(status_entry.get("capturing", False))
        # Cache the whole vu_history block; Flask thread reads it as-is.
        raw_vu = status_entry.get("vu_history")
        self.vu_history = raw_vu if isinstance(raw_vu, dict) else {}

        if not self.is_silent:
            self._last_active_time = time.time()

        if self.is_capturing and not was_capturing:
            return "started"
        if not self.is_capturing and was_capturing:
            return "stopped"
        return ""

    def apply_allow_capture(self, client: "MonitorClient") -> None:
        """Send set_allow_capture to the daemon if the value has changed."""
        if self._allow_capture != self._allow_capture_sent:
            if client.set_allow_capture(self.input_index, self._allow_capture):
                self._allow_capture_sent = self._allow_capture

    def stop(self) -> None:
        """Release resources (call at shutdown)."""
        self._tracker_playback_active = False
        try:
            self._nowplaying_publisher.close()
        except Exception:
            pass

    def _sync_playback_tracker_state(self) -> None:
        """Keep playback-hour tracking aligned to audible activity."""
        tracker = _playback_tracker
        if tracker is None:
            self._tracker_playback_active = False
            return

        playback_active = self.is_capturing and not self.is_silent
        if playback_active == self._tracker_playback_active:
            return

        if playback_active:
            tracker.on_playback_started(self.input_index)
        else:
            tracker.on_playback_stopped(self.input_index)
        self._tracker_playback_active = playback_active

    # ── Capture transitions ──────────────────────────────────────────────────

    def _on_capture_started(self, was_idle: bool) -> None:
        """Called when the daemon transitions this channel to capturing."""
        self._owntone_enabled_ok = False
        self._owntone_last_attempt = 0.0   # force immediate attempt

        # If transitioning from fully idle, clear previous output selection
        # so we start from a known state.
        if self.owntone_base_url and was_idle:
            _stop_and_disable_owntone(self.owntone_base_url, "capture start")

        self._maybe_retry_owntone(time.time())

        self._recognition_inflight = False
        self._recognition_attempt_count = 0

        self._nowplaying_publisher.publish_start(self._current_nowplaying)

        logging.info(
            "Input %d (%s): capture started.",
            self.input_index, self.input_device,
        )

    def _on_capture_stopped(self, client: "MonitorClient") -> None:
        """Called when the daemon transitions this channel out of capturing."""
        self._owntone_enabled_ok = False

        # Request a PCM snapshot for track recognition before signalling stop.
        self._trigger_recognition(client)

        try:
            self._nowplaying_publisher.publish_end()
        except Exception:
            pass

        if self.owntone_base_url and not any_monitor_capturing():
            self._request_owntone_stop("capture stop")

        logging.info(
            "Input %d (%s): capture stopped.",
            self.input_index, self.input_device,
        )

    # ── Track recognition ────────────────────────────────────────────────────

    def _trigger_recognition(self, client: "MonitorClient") -> None:
        """Fetch an ID snapshot from the daemon and queue recognition."""
        if self._vinyl_recognizer is None:
            return
        if self._recognition_inflight:
            logging.info(
                "Input %d: skipping recognition (prior attempt still running).",
                self.input_index,
            )
            return

        pcm_bytes = client.get_id_snapshot(self.input_index, max_seconds=20)
        if not pcm_bytes:
            logging.info(
                "Input %d: get_id_snapshot returned no audio; skipping recognition.",
                self.input_index,
            )
            return

        self._recognition_attempt_count += 1
        attempt_no = self._recognition_attempt_count
        self._recognition_inflight = True

        duration_s = len(pcm_bytes) / (22050 * 2)
        logging.info(
            "Input %d: recognition attempt %d queued (%.1f s of audio).",
            self.input_index, attempt_no, duration_s,
        )

        threading.Thread(
            target=self._recognize_nowplaying_worker,
            args=(bytes(pcm_bytes), 22050, attempt_no),
            daemon=True,
        ).start()

    def _recognize_nowplaying_worker(
        self,
        pcm16_mono: bytes,
        samplerate: int,
        attempt_no: int,
    ) -> None:
        """Resolve metadata in the background and publish updates if found."""
        try:
            if self._vinyl_recognizer is None:
                return
            meta, source = self._vinyl_recognizer.resolve_with_source(pcm16_mono, samplerate)
            if not meta:
                logging.info(
                    "Input %d: recognition attempt %d found no metadata.",
                    self.input_index, attempt_no,
                )
                return

            changed = meta != self._current_nowplaying
            self._current_nowplaying = meta
            if changed:
                self._nowplaying_publisher.publish_start(meta)
                logging.info(
                    "Input %d: now-playing updated (%s): artist=%s album=%s title=%s",
                    self.input_index, source,
                    meta.artist, meta.album, meta.title,
                )
            else:
                logging.info(
                    "Input %d: recognition attempt %d matched existing metadata (%s).",
                    self.input_index, attempt_no, source,
                )
        except Exception as e:
            logging.info("Input %d: recognition failed: %s", self.input_index, e)
        finally:
            self._recognition_inflight = False

    # ── OwnTone helpers ──────────────────────────────────────────────────────

    def _request_owntone_stop(self, reason: str) -> None:
        """Send a player stop command to OwnTone."""
        _stop_and_disable_owntone(self.owntone_base_url, reason)

    def _maybe_retry_owntone(self, now: float) -> None:
        """Periodically retry refreshing currently selected OwnTone outputs."""
        if not self.is_capturing:
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

def _resync_monitor_daemon(
    client: MonitorClient,
    monitors: list["AudioMonitor"],
    fifo_path: str,
    owntone_base_url: str,
    output_eq: OutputEqConfig,
) -> bool:
    """Re-send the full daemon state after reconnect.

    This is transactional from Python's point of view: if any required step
    fails for any configured monitor, the whole resync is treated as failed so
    the coordinator does not continue with Python-side monitor objects that do
    not exist in the daemon.
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

    return monitors

def run_autostream(config_path: str, start_webui=None) -> None:
    """Run autostream using the given config file path.

    Connects to the autostream_monitor daemon, configures inputs, and runs
    the coordinator loop until a stop signal is received.

    If start_webui is provided it is called with config_path to start the
    optional web UI in a background thread.
    """
    global _playing_announced, _reconcile_started
    _install_signal_handlers()
    cfg = load_and_parse(config_path)
    setup_logging(cfg.general.log_file, cfg.general.log_level)
    _ensure_playback_tracker(cfg)
    _install_state = get_install_state(Path("/var/lib/autostream/install-state.env"))
    version = _install_state.get("AUTOSTREAM_RELEASE_TAG", "")

    # Optionally start the web UI.
    if start_webui is not None:
        try:
            start_webui(config_path)
        except Exception as e:
            logging.error("Failed to start web UI: %s", e)

    socket_path = get_monitor_socket_path()
    POLL_INTERVAL = 0.5          # seconds between get_status() polls
    SWITCH_SILENCE_SECONDS = 5.0 # how long current input must be silent before switching

    # Remove any stale playing announcement from a previous crash, then
    # sync _playing_announced to filesystem truth so _sync_playing_announcement
    # does not attempt a redundant remove on the first poll.
    remove_avahi_playing_service()
    _playing_announced = _AVAHI_PLAYING_PATH.exists()

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
                    time.sleep(1.0)
                if stop_flag.is_set():
                    return
                cfg = load_and_parse(config_path)
                continue

            cfg = load_and_parse(config_path)
            fifo_path = cfg.general.fifo_path
            _ensure_playback_tracker(cfg)

            if not client.connect():
                logging.warning(
                    "Cannot connect to autostream_monitor at %s; retrying in 5 s.",
                    socket_path,
                )
                time.sleep(5.0)
                continue

            fifo_result = reconcile_fifo_with_backend(cfg.owntone.base_url, fifo_path, timeout=3.0)
            if not fifo_result.ok:
                logging.error(
                    "Could not reconcile audio FIFO/backend during startup: %s",
                    fifo_result.message or "reconcile failed",
                )
                client.close()
                time.sleep(5.0)
                continue

            if not client.set_fifo(fifo_path):
                logging.warning("set_fifo(%r) failed during startup; retrying in 5 s.", fifo_path)
                client.close()
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
            time.sleep(5.0)

        if stop_flag.is_set() or monitors is None:
            client.close()
            return

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

        current: Optional[AudioMonitor] = None
        reconnect_at: float = 0.0
        _reloading = False

        try:
            while not stop_flag.is_set():

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

                # Two-pass update so that callbacks see the final state of ALL
                # monitors, not a partially-updated snapshot.  This prevents
                # spurious OwnTone stop/disable when one input hands off to
                # another in the same poll cycle.
                was_any_capturing = any_monitor_capturing()
                started: list[AudioMonitor] = []
                stopped: list[AudioMonitor] = []

                for m in monitors:
                    if m.input_index in status_by_index:
                        transition = m._ingest_status(status_by_index[m.input_index])
                        if transition == "started":
                            started.append(m)
                        elif transition == "stopped":
                            stopped.append(m)

                # Keep playback-hours tracking aligned to actual audible
                # activity, rather than the broader capture window that
                # includes the silence timeout used to detect playback end.
                for m in monitors:
                    m._sync_playback_tracker_state()

                # Fire stopped callbacks first so any_monitor_capturing() is
                # already correct when started callbacks check it.
                for m in stopped:
                    m._on_capture_stopped(client)
                was_idle = not was_any_capturing
                for m in started:
                    m._on_capture_started(was_idle)

                if started or stopped:
                    _sync_playing_announcement(monitors, version)

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
                for m in monitors:
                    m.apply_allow_capture(client)
                    m._maybe_retry_owntone(time.time())

                tracker = _playback_tracker
                if tracker is not None:
                    tracker.maybe_flush()

                time.sleep(POLL_INTERVAL)

        except Exception as e:
            logging.error("Unexpected error: %s", e)

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

        if not _reloading:
            break
        # _reloading: continue outer loop → startup phase runs again with fresh config


def main() -> None:
    """CLI entry point for running autostream without the web UI."""
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} PATH_TO_CONFIG.json")
        sys.exit(1)

    run_autostream(sys.argv[1])


if __name__ == "__main__":
    main()
