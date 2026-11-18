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
import importlib
import os
import json
import logging
import random
import sys
import time
import signal
import threading
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable, Optional

import autostream_announce as announce
import autostream_input_status as input_status
import autostream_logging as log_setup
import autostream_monitor_client as monitor_client
import autostream_monitor_control as monitor_control
import autostream_playback_tracking as playback_tracking
import autostream_repeat
import autostream_runtime as runtime
import autostream_selfheal as selfheal
import autostream_session
import autostream_state
import autostream_intents as intents
from autostream_intents import Intent
from autostream_state import Origin
from autostream_state.outputs import WRITE_TIMEOUT_S, PlayerServiceBackend, get_authority
from autostream_config import (
    AUDIO_PATH_DEFAULT,
    INPUT_TYPE_DEFAULT,
    OutputEqConfig,
    input_type_label,
    load_and_parse,
    normalize_audio_path,
    normalize_input_type,
    unconfigured,
)
from autostream_artwork import ArtworkMemoryCache
import autostream_dial_push
from autostream_bluetooth_client import (
    BluetoothClient,
    bluetooth_capture_label,
    bluetooth_installed,
    classify_loopback_hw,
)
from autostream_nowplaying import (
    NowPlayingMetadata,
    OwntoneMetadataPipePublisher,
    PersistentNowPlayingCache,
    get_shared_metadata_publisher,
    release_shared_metadata_publisher,
    _load_placeholder_artwork,
)
from autostream_player_service import (
    ensure_pipe_source_ready,
    push_resample_quality,
    reconcile_fifo_with_backend,
    reconcile_monitor_format,
    reconcile_pipe_format_with_backend,
    sync_monitor_args_for_audio_path,
)
from autostream_rpi import is_high_performance_pi
from autostream_playback_stats import DEFAULT_FLUSH_INTERVAL_SECONDS
from autostream_sysutils import (
    audit_static_system_facts,
    get_install_state,
    log_lifecycle,
)


# --------------------------------------------------------------------------- #
# Module-level locks/events, grouped by conceptual store (documentation only  #
# -- the grouping below is descriptive; the locks/events themselves are not   #
# consolidated into a single object).                                        #
# --------------------------------------------------------------------------- #
#
# Process-wide signals (not tied to any store):
#   stop_flag, reload_flag                    -- in autostream_runtime
#   (log_queue -- async log fan-out, bounded 1000 -- is function-local to
#    the logging-setup call today, not a module-level global; listed here
#    only because an earlier gap-analysis pass described it as module-level)
#
# Independent, single-purpose locks (each guards something distinct enough
# that folding it into a group below would blur its meaning):
#   (_monitors_lock and _track_id_request_gate are in autostream_runtime;
#    the Avahi "playing" announcement lock is in autostream_announce)
#   (the now-playing republish-request lock is in autostream_runtime)
#   (the repeat-block overlay lock is in autostream_repeat)
#
# Class-level (not module-level, listed here for completeness):
#   MonitorClient._lock                       -- serializes daemon-socket
#                                                 commands across coordinator
#                                                 + track-ID worker threads
#   AudioMonitor._ti_state_lock                -- identification dispatch
#                                                 state vs. _apply_track_id_service


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
    runtime._track_id_service = _build_track_id_service(cfg)
    _publish_track_service(runtime._track_id_service is not None)
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
    runtime._track_id_service = _build_track_id_service(cfg)
    _publish_track_service(runtime._track_id_service is not None)
    with runtime._monitors_lock:
        monitors = list(runtime.all_monitors)
    for m in monitors:
        m._apply_track_id_service(runtime._track_id_service)
    logging.info(
        "track_id: service rebuilt live from snapshot (enabled=%s)",
        runtime._track_id_service is not None,
    )


_track_writer = autostream_state.store().claim("track", "autostream_core")


def _publish_track_service(enabled: bool) -> None:
    """Record whether a track identification service exists: with none, an
    input with nothing playing reads as disabled rather than waiting."""
    _track_writer.update(lambda cur: replace(cur, service_enabled=bool(enabled))).notify()


_monitor_writer = autostream_state.store().claim("monitor", "autostream_core")


def _set_monitor_runtime_info(
    *,
    monitor_build: Optional[str] = None,
    log_level: Optional[str] = None,
    connected: Optional[bool] = None,
    last_seen_at: Optional[float] = None,
) -> None:
    """Update the published autostream_monitor runtime metadata. Called from
    the coordinator thread only."""
    cur = autostream_state.store().snapshot().monitor
    pending = _monitor_writer.publish(autostream_state.MonitorRuntimeInfo(
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
    ))
    pending.notify()
    if autostream_state.store().snapshot().monitor.connected != cur.connected:
        # The Setup readout shows "not running" while the daemon is away.
        input_status.publish_inputs()


# Every module that binds intent rows when it is imported.
_HANDLER_MODULES = (
    "autostream_live_config",
    "autostream_log_policy",
    "autostream_monitor_control",
    "autostream_output_intents",
    "autostream_output_policy",
    "autostream_playback_tracking",
)


def _bind_intent_handlers() -> None:
    """Import the modules that handle intents; each binds its rows when
    imported."""
    for name in _HANDLER_MODULES:
        importlib.import_module(name)

    import autostream_live_config
    # Each hook finds the coordinator's function when it is called.
    autostream_live_config.bind_coordinator(autostream_live_config.CoordinatorHooks(
        apply_track_id_config_live=lambda config_path: apply_track_id_config_live(config_path),
        apply_track_id_config_live_from_parsed=lambda cfg: apply_track_id_config_live_from_parsed(cfg),
    ))


_bind_intent_handlers()


_settings_writer = autostream_state.store().claim("settings", "autostream_core")


def _publish_settings_generation(generation: int) -> None:
    """Commit hook for the settings store: record the newest generation,
    never letting a late hook move it backwards."""
    _settings_writer.update(
        lambda cur: autostream_state.SettingsPart(max(cur.generation, generation))
    ).notify()


def any_monitor_capturing() -> bool:
    """Return True if any AudioMonitor currently has an active capture."""
    with runtime._monitors_lock:
        return any(m.is_capturing for m in runtime.all_monitors)


def handle_signal(signum, frame):
    runtime.stop_flag.set()


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
        _ou.start(shutdown_event=runtime.stop_flag)
    except Exception:
        logging.warning("output-usage: failed to start poller", exc_info=True)


def _install_signal_handlers() -> None:
    """Register SIGINT/SIGTERM handlers. Call once from the process entry point."""
    signal.signal(signal.SIGINT,  handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)


def normalize_monitor_devices(
    devices: Optional[list[dict]],
    bluetooth_status: Optional[dict] = None,
    *,
    bluetooth_enabled: Optional[bool] = None,
) -> list[dict]:
    """Normalize list_devices() results into a stable Web UI-friendly shape.

    Each returned dict contains:
      - hw: ALSA hardware identifier such as "hw:1,0"
      - card: ALSA card description (may be empty)
      - name: ALSA device description (may be empty)
      - label: user-facing text combining card/device/hw

    Bluetooth relabel hook, active only when the Bluetooth-input subsystem
    is installed on this appliance: the loopback
    playback side (``CARD=ASBT,DEV=0``) is dropped entirely (it is not a
    selectable input), and the capture side (``CARD=ASBT,DEV=1``) is
    relabelled to "Bluetooth: <name>" / "Bluetooth (not paired)" /
    "Bluetooth (service unavailable)" using ``bluetooth_status`` (the
    cached-or-live daemon status; None is treated as "service
    unavailable").  ``bluetooth_enabled`` lets callers (tests) force the
    on/off branch explicitly; when omitted it is resolved from whether the
    Bluetooth-input subsystem is installed via ``bluetooth_installed()``
    (the relabel applies whenever the loopback card can exist, regardless
    of whether the service is currently enabled/running).  When the
    subsystem isn't installed, behaviour is byte-identical to before this
    hook existed -- the ASBT card cannot exist on such an appliance in any
    case.
    """
    bt_on = bluetooth_enabled if bluetooth_enabled is not None else bluetooth_installed()

    normalized: list[dict] = []

    for dev in devices or []:
        hw = str(dev.get("hw") or "").strip()
        if not hw:
            continue

        loopback_kind = classify_loopback_hw(hw) if bt_on else None
        if loopback_kind == "playback":
            continue

        card = str(dev.get("card") or "").strip()
        name = str(dev.get("name") or "").strip()

        label_parts = [part for part in (card, name) if part]
        label = " - ".join(label_parts) if label_parts else hw
        if hw not in label:
            label = f"{label} ({hw})"

        if loopback_kind == "capture":
            label = bluetooth_capture_label(bluetooth_status)

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
    bluetooth_status: Optional[dict] = None,
) -> list[dict]:
    """Return currently visible monitor devices from autostream_monitor.

    Uses a short-lived MonitorClient connection so callers outside the main
    coordinator loop can safely query available ALSA capture devices.
    Returns an empty list if the daemon is unavailable or the command fails.
    ``bluetooth_status`` is threaded through to ``normalize_monitor_devices()``
    for the Bluetooth relabel hook (see there); callers that don't pass it
    get the "service unavailable" label whenever Bluetooth mode is on.
    """
    try:
        with monitor_client._connected_monitor(socket_path) as client:
            if client is None:
                return []
            return normalize_monitor_devices(client.list_devices(), bluetooth_status)
    except Exception as e:
        logging.warning("Could not query autostream_monitor devices: %s", e)
        return []


def _default_nowplaying_title(input_type: str) -> str:
    """The receiver-facing default title for an input with no manual hint
    and no identified track: the input type's label ("Turntable", "CD",
    "Line"), never the raw ALSA device string."""
    return input_type_label(input_type)


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
    # The mismatch WARNING has its own timer so no other message can
    # silence it; the value matches the monitor's own mismatch log interval.
    RATE_MISMATCH_LOG_THROTTLE_SECONDS = 60.0

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
        minimum_playback_seconds: int = 30,
        owntone_output_offsets_ms: Optional[dict[str, int]] = None,
        owntone_output_airplay_modes: Optional[dict[str, str]] = None,
        gain_db: float = 0.0,
        eq_40hz_db: float = 0.0,
        eq_100hz_db: float = 0.0,
        eq_8khz_db: float = 0.0,
        is_turntable: bool = False,
        input_type: str = INPUT_TYPE_DEFAULT,
        dynamic_rate_matching: bool = True,
    ) -> None:
        self.input_index = input_index
        self.input_device = input_device
        self.is_turntable = is_turntable
        self.input_type = normalize_input_type(input_type)
        self.dynamic_rate_matching = bool(dynamic_rate_matching)
        self.silence_threshold_dbfs = silence_threshold_dbfs
        self.silence_seconds = silence_seconds
        self.track_change_silence_seconds = track_change_silence_seconds
        self.minimum_playback_seconds = minimum_playback_seconds
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
        # Track ID gives us an artwork URL; the cache fetches and normalises
        # it into an ArtworkImage entirely in memory (no file handoff -- see
        # autostream_artwork.ArtworkMemoryCache). The fetch cap is
        # deliberately generous (the module default): normalise_artwork()
        # re-encodes an oversized cover down to the publish-ready 48KB
        # regardless of how large the source was, so there is no reason to
        # reject a large source before that resampling gets a chance to run.
        self._artwork_cache = ArtworkMemoryCache()
        self._current_nowplaying = self._default_nowplaying_metadata()

        # --- Track identification scheduling ---
        from track_id.models import disabled_snapshot as _ds
        self._ti_state_lock = threading.Lock()  # guards dispatch setup and _apply_track_id_service
        # Held through _ti_locked(): the thread that holds the lock, and the
        # track-part changes made under it, delivered once it is released.
        self._ti_lock_owner: Optional[int] = None
        self._ti_pending: list = []
        self._ti_generation: int = 0           # incremented on service swap or capture start
        self._ti_inflight: bool = False
        self._ti_inflight_token: Optional[object] = None  # unique per worker
        self._ti_next_attempt: float = 0.0
        self._ti_next_attempt_reason: str = ""
        self._ti_last_attempt: float = 0.0
        self._ti_last_identified_at: float = 0.0
        with self._ti_locked():
            self._set_ti_snapshot(_ds())

        # --- Status (updated by coordinator via _ingest_status) ---
        self.level_dbfs: float = -90.0
        self.poll_peak_dbfs: float = -90.0
        self.detected_hz: float = 0.0
        self.negotiated_hz: int = 0
        self.rate_lock: str = "locked"
        self.relock_count: int = 0
        self.rate_mismatch_hz: int = 0
        # None until a status poll says: an older monitor never reports the
        # key, which is how the Setup card knows the setting cannot take effect.
        self.monitor_dynamic_rate_matching: Optional[bool] = None
        self._rate_mismatch_last_warning: float = 0.0
        self.is_silent: bool = True
        self.is_capturing: bool = False
        # Set each poll cycle from the coordinator's replay_origin_input():
        # True while this input is the origin of a currently
        # replaying recording, i.e. it is the session's audible source even
        # though it is not itself "capturing". See _ingest_status() and
        # maybe_trigger_track_identification()'s actively-sourcing gate.
        self._replay_origin: bool = False
        self._last_active_time: Optional[float] = None
        self._tracker_playback_active: bool = False
        self._tracker_wear_active: bool = False
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
        self._owntone_enabled_ok: bool = False
        # The output authority's player-restart marker when the selection was
        # last applied; a different one later means the player restarted.
        self._outputs_boot_seen: Optional[str] = None
        self._owntone_recovery_log = runtime.RecoveryLog("OwnTone output-enable")
        self._capture_start_no_output_retry_at: float = 0.0
        self._capture_start_no_output_log_at: float = 0.0

        with runtime._monitors_lock:
            runtime.all_monitors.append(self)

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

    def _ingest_rate_status(self, status_entry: dict) -> None:
        """Take the sample-rate fields from a get_status() entry.

        An older monitor reports none of them, so each falls back to a
        value that leaves the Home page as it was: locked, no mismatch, and
        no sign that the monitor supports Dynamic Rate Matching. An input that
        is not started has no rate lock to report, so a monitor that reports
        one for it is read as reporting none (an empty string). A mismatch
        counts only while the input is started and the rate is non-zero;
        the rate, not the lock string, is what the banner and the log follow.
        """
        started = bool(status_entry.get("started", True))
        self.negotiated_hz = int(status_entry.get("negotiated_hz", 0) or 0)
        if "rate_lock" in status_entry and not started:
            self.rate_lock = ""
        else:
            self.rate_lock = str(status_entry.get("rate_lock", "locked") or "locked")
        raw_supported = status_entry.get("dynamic_rate_matching")
        self.monitor_dynamic_rate_matching = (
            raw_supported if isinstance(raw_supported, bool) else None
        )

        new_mismatch = int(status_entry.get("rate_mismatch_hz", 0) or 0) if started else 0
        if new_mismatch != self.rate_mismatch_hz:
            if new_mismatch:
                # The WARNING is limited to one a minute per input by its own
                # timer; a transition inside that period logs at INFO.
                now = time.time()
                level = (
                    logging.WARNING
                    if now - self._rate_mismatch_last_warning
                    >= self.RATE_MISMATCH_LOG_THROTTLE_SECONDS
                    else logging.INFO
                )
                if level == logging.WARNING:
                    self._rate_mismatch_last_warning = now
                logging.log(
                    level,
                    "Input %d is delivering %d Hz but was opened at %d Hz; "
                    "Dynamic Rate Matching is off for this input.",
                    self.input_index, new_mismatch, self.negotiated_hz,
                )
            else:
                logging.info("Input %d sample rate mismatch cleared.", self.input_index)
            self.rate_mismatch_hz = new_mismatch

        new_relocks = int(status_entry.get("relock_count", 0) or 0)
        if new_relocks != self.relock_count:
            if new_relocks:
                logging.info(
                    "Input %d capture rate step #%d: now %.1f Hz (negotiated %d Hz)",
                    self.input_index, new_relocks, self.detected_hz, self.negotiated_hz,
                )
            self.relock_count = new_relocks

    def _ingest_status(self, status_entry: dict, replay_origin: bool = False) -> str:
        """Update fields from a get_status() entry without firing callbacks.

        Returns 'started', 'stopped', or '' to indicate the capturing
        transition so the coordinator can fire callbacks in a second pass,
        after all monitors have been updated.

        *replay_origin* is this same poll cycle's replay_origin_input()
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
        that transition is handled by autostream_session.dispatch_session_event() ->
        _arm_track_identification_for_session(), which runs after this method
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
        self._ingest_rate_status(status_entry)
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
        # transition into replay-sourcing is armed by autostream_session.dispatch_session_event
        # instead, after this same poll cycle's baseline would otherwise be
        # stale/unset).
        if was_actively_sourcing and is_actively_sourcing:
            if self.track_change_seq != self._track_change_seq_baseline:
                self._on_possible_track_change(self.track_change_seq)

        return ""

    def _on_possible_track_change(self, new_seq: int) -> None:
        """Handle a track_change_seq advance while capturing."""
        self._track_change_seq_baseline = new_seq
        svc = runtime._track_id_service
        if svc is None:
            return
        from track_id.models import waiting_snapshot
        delay = svc.analysis_lead_in_seconds + svc.snapshot_seconds
        now = time.time()
        # Under the state lock so a worker keeping a held track after a failed
        # re-check (which re-checks the generation under the same lock) cannot
        # publish it over this reset.
        with self._ti_locked():
            self._ti_generation += 1  # invalidate stale in-flight worker results
            self._set_ti_snapshot(waiting_snapshot(input_index=self.input_index))
            self._schedule_track_id_after(now, delay, "track_change")
        logging.info(
            "track_id[%d]: possible track change seq=%d; analysis scheduled in %ds"
            " (lead-in=%ds window=%ds)",
            self.input_index, new_seq, delay,
            svc.analysis_lead_in_seconds, svc.snapshot_seconds,
        )
        self._publish_interstitial_nowplaying()

    def _publish_interstitial_nowplaying(self) -> None:
        """Reset the now-playing metadata to the input-label default and publish it.

        DETECTING-INTERSTITIAL policy: a detected track boundary (or a seek
        within a replay) is a visible moment for the receiver, not just a
        status change. Reset _current_nowplaying to the input-label default
        (with the bundled placeholder logo as its artwork, decided
        explicitly rather than left as None) and publish it immediately, so
        the receiver drops the just-finished track's title/cover and shows
        "<input label> / autostream" + the autostream logo while
        re-identification runs -- the same look a session start gets from
        _reset_nowplaying_for_new_session() / autostream_session._session_nowplaying_start().
        When the pending identification lands, _ti_worker() compares its
        result against this now-reset _current_nowplaying: for a *different*
        track the comparison obviously differs; for the *same* track it
        still differs (this interstitial's placeholder artwork vs. the
        identified cover), so either way _ti_worker() publishes real
        metadata and the receiver's display "restores" on its own -- no
        special-casing needed for the same-track case. Callers are a
        monitor-reported gap event (track_change_seq advancing) and an
        accepted seek within a running replay; the periodic
        re-identification timer (_ti_worker() scheduling itself via
        _schedule_track_id_after()) never calls this, so a routine refresh
        of an already-identified track does not re-trigger the interstitial.
        """
        self._current_nowplaying = self._default_nowplaying_metadata()
        self._current_nowplaying = replace(
            self._current_nowplaying, artwork=_load_placeholder_artwork()
        )
        self._nowplaying_publisher.publish_refresh(self._current_nowplaying)

    def _default_nowplaying_metadata(self) -> "NowPlayingMetadata":
        """The now-playing metadata for this input with no identified track:
        a manual hint from nowplaying_hints.json if one applies, otherwise a
        receiver-friendly input label (Turntable / CD / Line) as the
        title -- the prominent line on the receiver -- with the constant
        "autostream" as the artist beneath it, rather than leaking the raw
        ALSA device string. Re-read each call (not cached) so a manual-hints
        file edit is picked up at the next session start."""
        return self._nowplaying_cache.get_manual_hint(self.input_device) or NowPlayingMetadata(
            title=_default_nowplaying_title(self.input_type),
            artist="autostream",
            album="Unknown Album",
        )

    def _reset_nowplaying_for_new_session(self) -> None:
        """Called at the start of each new play session (session_started /
        source_changed dispatch, via autostream_session._session_nowplaying_start()) to drop
        any title/artist/artwork carried over from a previous session --
        otherwise a stale cover from whatever was last playing could flash
        up before this session's own track ID (if any) lands. Within a
        session, a detected track boundary resets metadata the same way
        (see _on_possible_track_change() above, and _ti_worker() below for
        where a completed identification then replaces it)."""
        self._current_nowplaying = self._default_nowplaying_metadata()

    def apply_allow_capture(self, client: "monitor_client.MonitorClient") -> None:
        """Send set_allow_capture to the daemon if the value has changed."""
        if self._allow_capture != self._allow_capture_sent:
            if client.set_allow_capture(self.input_index, self._allow_capture):
                self._allow_capture_sent = self._allow_capture

    def stop(self) -> None:
        """Release resources (call at shutdown)."""
        self._tracker_playback_active = False
        self._tracker_wear_active = False
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
        """Keep playback-hour tracking aligned to activity, split by purpose.

        total_playback_seconds accrues for all audible playback, including
        repeat-buffer replay: *repeat_status* is the same-poll top-level
        "repeat" block, and while repeat.replay.active, the origin input's
        recording is audibly playing even though that input itself is not
        capturing, so total hours keep accruing against
        repeat.recording.origin_input. Stylus/belt/bearing wear counters
        accrue only for real input capture -- capturing and not silent --
        since replay is buffered audio with no corresponding physical wear
        on the source turntable. Track-ID/now-playing metadata are
        unaffected here -- they keep flowing from the daemon's replay-path
        track-change events independently.
        """
        tracker = runtime._playback_tracker
        if tracker is None:
            self._tracker_playback_active = False
            self._tracker_wear_active = False
            return

        replaying_this_input = False
        if isinstance(repeat_status, dict):
            replay = repeat_status.get("replay")
            if isinstance(replay, dict) and bool(replay.get("active")):
                recording = repeat_status.get("recording")
                origin_input = recording.get("origin_input") if isinstance(recording, dict) else None
                replaying_this_input = origin_input == self.input_index

        wear_active = self.is_capturing and not self.is_silent
        playback_active = wear_active or replaying_this_input

        if playback_active != self._tracker_playback_active:
            if playback_active:
                tracker.on_playback_started(self.input_index)
            else:
                tracker.on_playback_stopped(self.input_index)
            self._tracker_playback_active = playback_active

        if wear_active != self._tracker_wear_active:
            if wear_active:
                tracker.on_wear_started(self.input_index)
            else:
                tracker.on_wear_stopped(self.input_index)
            self._tracker_wear_active = wear_active

    # ── Capture transitions ──────────────────────────────────────────────────

    def _on_capture_started(self) -> None:
        """Called when the daemon transitions this channel to capturing.

        Per-input duties only: track-ID scheduling and logging.
        Session-level duties -- OwnTone output-enable/default-volume and
        now-playing publish_start -- are not fired unconditionally on
        every capture-start transition, since a replay-sourced session start
        never transitions any input to capturing at all. They run from the
        coordinator's autostream_session.SessionTracker session_started event via
        autostream_session._start_session_owntone() / autostream_session._session_nowplaying_start(), see the poll
        loop in run_autostream().

        A settling-noise transient on the replay-origin input can flip
        capturing true then false during its own replay (allowed since the
        monitor probation commit). self._replay_origin is refreshed for
        this same tick by _ingest_status() before this callback runs, so
        when it is true this is that transient, not a real capture start:
        the replay identification cycle (already armed by
        _arm_track_identification_for_session()) must be left alone rather
        than reset out from under it. Mirrors _on_capture_stopped()'s guard.
        """
        if self._replay_origin:
            logging.debug(
                "Input %d (%s): own recording is replaying; capture-start "
                "transient ignored, identification preserved.",
                self.input_index, self.input_device,
            )
            return

        with self._ti_locked():
            self._ti_generation += 1  # invalidate any worker queued before capture started
            self._ti_inflight = False
            self._ti_inflight_token = None
            self._ti_next_attempt = 0.0
            self._ti_next_attempt_reason = ""
            self._ti_last_identified_at = 0.0
            if runtime._track_id_service is not None:
                svc = runtime._track_id_service
                delay = svc.analysis_lead_in_seconds + svc.snapshot_seconds
                self._schedule_track_id_after(time.time(), delay, "initial")
                logging.debug(
                    "track_id[%d]: initial attempt scheduled in %.0fs (lead-in=%.0fs window=%.0fs).",
                    self.input_index, delay, svc.analysis_lead_in_seconds, svc.snapshot_seconds,
                )
                from track_id.models import waiting_snapshot
                self._set_ti_snapshot(waiting_snapshot(
                    next_attempt_at=self._ti_next_attempt,
                    next_attempt_reason=self._ti_next_attempt_reason,
                ))
            else:
                from track_id.models import disabled_snapshot
                self._set_ti_snapshot(disabled_snapshot())

        logging.info(
            "Input %d (%s): capture started.",
            self.input_index, self.input_device,
        )

    def _arm_track_identification_for_session(self) -> None:
        """Arm the identification cycle for this monitor's new session source.

        Mirrors _on_capture_started()'s track-ID setup (reset generation,
        invalidate in-flight state, schedule the initial attempt), but is
        invoked directly by autostream_session.dispatch_session_event() for a session_started
        or source_changed event landing on this monitor -- for a
        replay-sourced source ("replay") as well as a live one
        ("input1"/"input2"). Generalized from a replay-only arm (see history)
        because a live source can also reach a session_started/source_changed
        event without a fresh is_capturing 0->1 edge to arm from:

        - Replay case: is_capturing never transitions to True for the replay
          origin input (the origin input isn't capturing while its recording
          replays), so _on_capture_started would otherwise never fire and
          this input's identification cycle would stay parked at whatever
          state it was in before replay began: the daemon serves replay-tap
          snapshots under origin_input, so the Python side only needs to
          schedule attempts, not gate on is_capturing.

        - Live case (confirmed-live-interrupt of a replay): a probation
          transient can flip this input's is_capturing true while it is
          still the replay origin; _on_capture_started()'s replay-origin
          guard deliberately leaves the identification cycle alone for that
          edge (see its docstring) so the in-flight replay identification
          survives. If the transient turns into a genuine live takeover,
          the session source changes to this input with no further
          is_capturing edge to arm from (it was already True), so this
          session-arm call is the only place left to do it.

        Also baselines track_change_seq here, since _ingest_status()'s
        steady-state seq check requires actively-sourcing on BOTH sides of
        an ingest and so deliberately does not fire (and does not baseline)
        on the same cycle this transition is first observed.

        Takes _ti_state_lock, because the arm can also run on the API thread
        (on_replay_seek_accepted) and must not interleave with the
        coordinator's dispatch section.
        """
        with self._ti_locked():
            self._arm_identification_cycle_locked("initial")

        logging.info(
            "Input %d (%s): identification armed for session source.",
            self.input_index, self.input_device,
        )

    @contextlib.contextmanager
    def _ti_locked(self):
        """Hold _ti_state_lock. Changes made to the identification snapshot
        meanwhile are published to the track part under the lock, in order,
        and delivered to subscribers after it is released."""
        pending: list = []
        self._ti_state_lock.acquire()
        try:
            self._ti_lock_owner = threading.get_ident()
            try:
                yield
            finally:
                pending, self._ti_pending = self._ti_pending, []
                self._ti_lock_owner = None
        finally:
            self._ti_state_lock.release()
            for change in pending:
                change.notify()

    def _set_ti_snapshot(self, value) -> None:
        """Replace this input's identification snapshot and publish it as its
        entry in the track part. The caller holds _ti_state_lock through
        _ti_locked()."""
        assert self._ti_lock_owner == threading.get_ident(), (
            "_set_ti_snapshot outside _ti_locked()")
        self._ti_snapshot = value
        index = self.input_index
        self._ti_pending.append(_track_writer.update(lambda cur: replace(
            cur, entries=autostream_state.FrozenDict({**cur.entries, index: value}))))

    def _arm_identification_cycle_locked(self, reason: str) -> None:
        """Restart this monitor's identification cycle; caller holds _ti_state_lock.

        Baselines track_change_seq, bumps _ti_generation (a worker still in
        flight discards its result on the generation check), clears the
        in-flight state, schedules the first attempt one lead-in plus one
        snapshot window away and publishes a waiting (or disabled) snapshot.
        *reason* labels the scheduled attempt. Only a "seek" arm keeps a
        rate-limit or upstream-rejection deadline that lies further out than
        the new attempt: a provider backoff outranks a seek, whereas a new
        session source starts from a clean schedule.
        """
        self._track_change_seq_baseline = self.track_change_seq
        self._ti_generation += 1  # invalidate any worker queued before this cycle began
        self._ti_inflight = False
        self._ti_inflight_token = None
        if reason != "seek":
            self._ti_next_attempt = 0.0
            self._ti_next_attempt_reason = ""
        self._ti_last_identified_at = 0.0
        if runtime._track_id_service is not None:
            svc = runtime._track_id_service
            delay = svc.analysis_lead_in_seconds + svc.snapshot_seconds
            self._schedule_track_id_after(time.time(), delay, reason)
            logging.debug(
                "track_id[%d]: %s attempt scheduled in %.0fs (lead-in=%.0fs "
                "window=%.0fs).",
                self.input_index, reason, delay,
                svc.analysis_lead_in_seconds, svc.snapshot_seconds,
            )
            from track_id.models import waiting_snapshot
            self._set_ti_snapshot(waiting_snapshot(
                next_attempt_at=self._ti_next_attempt,
                next_attempt_reason=self._ti_next_attempt_reason,
            ))
        else:
            from track_id.models import disabled_snapshot
            self._ti_next_attempt = 0.0
            self._ti_next_attempt_reason = ""
            self._set_ti_snapshot(disabled_snapshot())

    def on_replay_seek_accepted(self, in_session: bool) -> None:
        """Re-arm identification after an accepted replay start or seek.

        Called on the API thread from apply_repeat_ack (autostream_repeat) for the replay origin
        monitor. A seek resets the daemon's reader and decoder but not its
        track_change_seq, so no gap event would ever tell the coordinator
        that the audio moved. *in_session* is True for a seek within a
        running replay: the receiver still shows the pre-seek track, so the
        interstitial is published now. It is False for a start from Hold:
        the coordinator's session_started publishes the session's now-playing
        on its next poll, and a refresh ahead of that session's start would be
        out of order. The later session_started arm repeats this one
        harmlessly (nothing can be in flight yet).
        """
        with self._ti_locked():
            self._arm_identification_cycle_locked("seek")
        if in_session:
            self._publish_interstitial_nowplaying()
        logging.info(
            "Input %d (%s): identification re-armed for a replay seek.",
            self.input_index, self.input_device,
        )

    def _on_capture_stopped(
        self,
        client: "monitor_client.MonitorClient",
    ) -> None:
        """Called when the daemon transitions this channel out of capturing.

        Per-input duties only: track-ID state invalidation and
        logging. Session-level duties -- the OwnTone idle-stop and
        now-playing publish_end -- are not fired here: the coordinator's
        autostream_session.SessionTracker source vector treats a capture-stop immediately
        followed by a replay-start as a source_changed event with no
        OwnTone-level capture-stop in between, so per-input teardown must
        stay silent on the session-level effects. The session-level stop
        runs from the tracker's session_ended event, see the poll loop in
        run_autostream().

        self._replay_origin is refreshed for this same tick by
        _ingest_status() before this callback runs, so when it is true this
        stop edge is one of two things, and either way the identification
        schedule must be left alone:

        - A settling-noise transient on the replay-origin input flipping
          capturing true then false during its own replay (allowed since
          the monitor probation commit): zeroing the identification
          schedule here would kill identification until the replay's own
          gap detector emits its next internal track boundary.

        - The ordinary armed-repeat handoff: repeat starts replay inside
          the same capture-stop tick, so an ordinary capture-end on the
          input that is about to become the replay origin also lands here
          with self._replay_origin already true. The session arm
          (_arm_track_identification_for_session(), via
          autostream_session.dispatch_session_event()) re-arms this input's identification
          cycle for the new replay source later in this same tick, so
          tearing it down here would just be redone -- and would race the
          re-arm if worker teardown timing ever shifted.

        Mirrors _on_capture_started()'s guard. The usual INFO capture-stopped
        line below is still emitted in both cases: OwnTone capture did stop,
        which is worth logging regardless of what happens to identification.
        """
        logging.info(
            "Input %d (%s): capture stopped.",
            self.input_index, self.input_device,
        )

        if self._replay_origin:
            logging.debug(
                "Input %d (%s): own recording is replaying; leaving "
                "identification to the session arm.",
                self.input_index, self.input_device,
            )
            return

        # Invalidate any running worker and clear scheduled deadlines so a
        # worker that completes after capture stops cannot overwrite the
        # waiting/disabled snapshot below or leave a stale _ti_next_attempt.
        # Under the state lock so a worker keeping a held track after a failed
        # re-check cannot publish it over this reset.
        with self._ti_locked():
            self._ti_generation += 1
            self._ti_next_attempt = 0.0
            self._ti_next_attempt_reason = ""
            self._track_change_seq_baseline = 0

            if runtime._track_id_service is not None:
                from track_id.models import waiting_snapshot
                self._set_ti_snapshot(waiting_snapshot())
            else:
                from track_id.models import disabled_snapshot
                self._set_ti_snapshot(disabled_snapshot())

    def _teardown_identification_after_replay(self) -> None:
        """Drop this monitor's identification state once its replay has ended.

        Called on the coordinator thread from
        autostream_session.teardown_identification_after_replay_end() when the session's
        previous source was "replay" and that source has gone
        (session_ended) or moved to a different monitor (source_changed).
        A replay end produces no capturing edge, so _on_capture_stopped()
        never runs for it; without this the origin monitor would carry its
        last identified snapshot through Hold and let a worker that finishes
        after the end land a match on an idle input.

        Same effect as _on_capture_stopped()'s live teardown (generation
        bump so a late worker result is discarded, deadlines and baseline
        zeroed, waiting/disabled snapshot), plus clearing the in-flight
        fields so the next arm starts clean. A rate-limit or
        upstream-rejection deadline is dropped with the rest, as on a live
        capture stop; the next session arm starts from a clean schedule
        either way. Takes _ti_state_lock. Idempotent: a second call only
        bumps the generation again.
        """
        with self._ti_locked():
            self._ti_generation += 1
            self._ti_inflight = False
            self._ti_inflight_token = None
            self._ti_next_attempt = 0.0
            self._ti_next_attempt_reason = ""
            self._ti_last_identified_at = 0.0
            self._track_change_seq_baseline = 0
            if runtime._track_id_service is not None:
                from track_id.models import waiting_snapshot
                self._set_ti_snapshot(waiting_snapshot())
            else:
                from track_id.models import disabled_snapshot
                self._set_ti_snapshot(disabled_snapshot())

        logging.debug(
            "Input %d (%s): identification torn down after replay.",
            self.input_index, self.input_device,
        )

    # ── Track identification ──────────────────────────────────────────────────

    def _apply_track_id_service(self, service) -> None:
        """Set the initial snapshot based on whether the service is available."""
        with self._ti_locked():
            self._ti_generation += 1  # invalidate any in-flight worker for the old service
            if service is not None:
                from track_id.models import waiting_snapshot
                # Schedule first attempt if actively sourcing (capturing, or
                # the replay-origin input of a currently replaying
                # recording); otherwise wait for capture-start / session-arm.
                # Without the replay-origin half of this check, changing the
                # track-ID setting mid-replay would park the schedule at 0.0
                # with nothing left to un-park it until replay ends.
                if self.is_capturing or self._replay_origin:
                    delay = service.analysis_lead_in_seconds + service.snapshot_seconds
                    self._schedule_track_id_after(time.time(), delay, "initial")
                else:
                    self._ti_next_attempt = 0.0
                    self._ti_next_attempt_reason = ""
                self._set_ti_snapshot(waiting_snapshot(
                    next_attempt_at=(self._ti_next_attempt or None),
                    next_attempt_reason=self._ti_next_attempt_reason,
                ))
            else:
                from track_id.models import disabled_snapshot
                self._set_ti_snapshot(disabled_snapshot())
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
        self, client: "monitor_client.MonitorClient", now: float, replay_origin: bool = False,
    ) -> None:
        """Dispatch an identification worker if the deadline has elapsed and conditions allow.

        *replay_origin* is this poll cycle's replay_origin_input() result
        compared against self.input_index: an input replaying
        its own recording is "actively sourcing" the session even though
        is_capturing is False, and the daemon already serves replay-tap
        snapshots for it under origin_input, so
        identification must run for it too. The is_silent check only applies
        to live capture -- a replay-sourced input is silent by definition
        (it isn't capturing anything), so gating on it here would make
        replay-sourced identification permanently dead.

        Self-heal: if this input is actively sourcing with the service
        enabled and nothing in flight, but _ti_next_attempt is still the
        0.0 sentinel (never armed, or a prior arming path was missed or
        raced), schedule an initial attempt here rather than staying
        parked forever. This bounds any such stall to one poll cycle plus
        the normal initial-attempt delay.
        """
        svc = runtime._track_id_service
        if svc is None:
            return
        actively_sourcing = self.is_capturing or replay_origin
        if not actively_sourcing:
            return
        if self.is_capturing and self.is_silent:
            return
        if self._ti_inflight:
            return
        if self._ti_next_attempt == 0.0:
            delay = svc.analysis_lead_in_seconds + svc.snapshot_seconds
            self._schedule_track_id_after(now, delay, "initial")
            logging.debug(
                "track_id[%d]: self-heal: schedule was parked at 0.0 while "
                "actively sourcing; initial attempt scheduled in %.0fs.",
                self.input_index, delay,
            )
            return
        if now < self._ti_next_attempt:
            return

        # Attempt non-blocking acquisition of the process-wide admission gate.
        if not runtime._track_id_request_gate.acquire(blocking=False):
            # Another input is active; retry after 1 s without disturbing the reason.
            self._ti_next_attempt = now + 1.0
            return

        # Gate acquired.  Recheck critical preconditions after acquiring.
        if not actively_sourcing or runtime._track_id_service is not svc:
            runtime._track_id_request_gate.release()
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
        with self._ti_locked():
            # Recheck generation and service immediately after the blocking
            # snapshot call, before interpreting its result.
            if self._ti_generation != dispatch_gen or runtime._track_id_service is not svc:
                logging.debug(
                    "track_id[%d]: generation or service changed during snapshot; aborting dispatch.",
                    self.input_index,
                )
                runtime._track_id_request_gate.release()
                return

            if snapshot is None or not snapshot[0]:
                logging.debug(
                    "track_id[%d]: get_id_snapshot returned no audio; retry in %.0fs.",
                    self.input_index, svc.retry_seconds,
                )
                runtime._track_id_request_gate.release()
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
                runtime._track_id_request_gate.release()
                self._schedule_track_id_after(now, svc.retry_seconds, "no_match")
                return

            logging.info(
                "track_id[%d]: queuing identification (%.1f s of audio, reason=%s).",
                self.input_index, duration_s, self._ti_next_attempt_reason,
            )

            from track_id.models import (
                STATE_ANALYSING, STATE_IDENTIFIED, state_status_text,
                TrackIdentificationSnapshot,
            )
            # A snapshot still identified here means this is the periodic
            # re-check of a track that is playing: a track change, a new
            # session and a seek all replace the snapshot with a waiting one
            # first. Keep publishing the identified track while the attempt
            # runs (the in-flight flag stops a second attempt), so a dial, the
            # Home page or a receiver reading it never loses the title and
            # cover; the worker publishes the outcome. Any other attempt
            # shows the analysing state.
            held = self._ti_snapshot if self._ti_snapshot.state == STATE_IDENTIFIED else None
            if held is not None:
                # No attempt is scheduled while one is in flight.
                self._set_ti_snapshot(replace(
                    held, next_attempt_at=None, next_attempt_reason="",
                ))
            else:
                self._set_ti_snapshot(TrackIdentificationSnapshot(
                    enabled=True,
                    state=STATE_ANALYSING,
                    status_text=state_status_text(STATE_ANALYSING),
                    input_index=self.input_index,
                    provider=svc.provider_id,
                    updated_at=now,
                    last_attempt_at=now,
                ))
            worker_token = object()
            self._ti_inflight = True
            self._ti_inflight_token = worker_token
            self._ti_last_attempt = now

            # Scheduled on the process-wide task pool under a per-input
            # single-flight key -- same worker function, same args, just
            # scheduled via runtime._task_pool.submit() instead of a raw
            # threading.Thread(...).start(). The
            # process-wide runtime._track_id_request_gate above is still the true
            # admission control (at most one identification in flight across
            # all inputs); this per-input key is a second, redundant guard
            # that should never actually reject a submission in practice.
            # _ti_worker's own completion contract (release the gate, clear
            # _ti_inflight/_ti_inflight_token in its `finally`) is untouched.
            submitted = False
            try:
                submitted = runtime._task_pool.submit(
                    f"track-id-{self.input_index}",
                    self._ti_worker,
                    bytes(pcm_bytes), rate, worker_token, dispatch_gen, held,
                )
            except Exception:
                logging.warning(
                    "track_id[%d]: task pool submit() raised; releasing gate.",
                    self.input_index, exc_info=True,
                )
            else:
                if not submitted:
                    logging.warning(
                        "track_id[%d]: task pool submit() rejected (already in "
                        "flight for this input); releasing gate.",
                        self.input_index,
                    )
            if not submitted:
                runtime._track_id_request_gate.release()
                if self._ti_inflight_token is worker_token:
                    self._ti_inflight = False
                    self._ti_inflight_token = None

    def _keep_held_track(
        self, held, my_gen: int, worker_token: object, now: float,
    ) -> None:
        """Publish the held identified track again after a re-check that found
        nothing or failed, pointing its attempt fields at the retry just
        scheduled. The generation and token are checked again under the state
        lock, which a track change, a new session and a reconfiguration also
        take, so a superseded attempt never puts the old track back over the
        newer snapshot."""
        with self._ti_locked():
            if self._ti_generation != my_gen or self._ti_inflight_token is not worker_token:
                return
            self._set_ti_snapshot(replace(
                held,
                last_attempt_at=now,
                next_attempt_at=self._ti_next_attempt,
                next_attempt_reason=self._ti_next_attempt_reason,
            ))

    def _ti_worker(
        self, pcm16_mono: bytes, sample_rate: int, worker_token: object, dispatch_gen: int,
        held=None,
    ) -> None:
        """Run identification in the background and schedule the next attempt.

        *held* is the identified snapshot that was being published when this
        attempt was dispatched (a periodic re-check of a playing track), or
        None. A failed or empty attempt keeps publishing it rather than
        replacing it with a not-found or error state; a matching result
        replaces it as usual.
        """
        from track_id.models import (
            TrackIDProviderUnreachableError,
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
            svc = runtime._track_id_service
            if svc is None:
                return

            result = svc.identify(pcm16_mono, sample_rate, input_index=self.input_index)
            now = time.time()

            if self._ti_generation != my_gen or self._ti_inflight_token is not worker_token:
                logging.info(
                    "track_id[%d]: match discarded: stale generation/service.",
                    self.input_index,
                )
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
                    # If there is no previous artwork either, the publisher's
                    # own HOLD-UNTIL-NEW fallback (see
                    # OwntoneMetadataPipePublisher._resolve_refresh_artwork())
                    # re-emits whatever it last sent for this session
                    # (placeholder or real), so the receiver never sees a
                    # bundle with no picture at all.
                    artwork_url = result.artwork.url if result.artwork else ""
                    artwork = (
                        self._artwork_cache.get(artwork_url)
                        or self._current_nowplaying.artwork
                    )
                    new_meta = NowPlayingMetadata(
                        title=result.title or self._current_nowplaying.title,
                        artist=result.artist or self._current_nowplaying.artist,
                        album=result.album or self._current_nowplaying.album,
                        artwork=artwork,
                    )
                    if new_meta != self._current_nowplaying:
                        self._current_nowplaying = new_meta
                        # publish_refresh(), not publish_start(): this fires
                        # mid-session (track-ID match landing after the
                        # session's pbeg already went out), so it must not
                        # emit a second pbeg.
                        self._nowplaying_publisher.publish_refresh(new_meta)
                with self._ti_locked():
                    self._set_ti_snapshot(TrackIdentificationSnapshot(
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
                        next_attempt_at=self._ti_next_attempt,
                        next_attempt_reason=self._ti_next_attempt_reason,
                    ))
            elif result.is_configuration_error:
                self._schedule_track_id_after(now, TRACK_ID_ERROR_RETRY_SECONDS, "error")
                logging.debug(
                    "track_id[%d]: configuration error; retry scheduled in %.0fs.",
                    self.input_index, TRACK_ID_ERROR_RETRY_SECONDS,
                )
                if held is not None:
                    self._keep_held_track(held, my_gen, worker_token, now)
                else:
                    with self._ti_locked():
                        self._set_ti_snapshot(TrackIdentificationSnapshot(
                            enabled=True,
                            state=STATE_ERROR,
                            status_text=state_status_text(STATE_ERROR),
                            input_index=self.input_index,
                            provider=svc.provider_id,
                            updated_at=now,
                            last_attempt_at=now,
                            next_attempt_at=self._ti_next_attempt,
                            next_attempt_reason=self._ti_next_attempt_reason,
                        ))
            else:
                self._schedule_track_id_after(now, svc.retry_seconds, "no_match")
                logging.debug(
                    "track_id[%d]: no match; retry scheduled in %.0fs.",
                    self.input_index, svc.retry_seconds,
                )
                if held is not None:
                    self._keep_held_track(held, my_gen, worker_token, now)
                else:
                    with self._ti_locked():
                        self._set_ti_snapshot(TrackIdentificationSnapshot(
                            enabled=True,
                            state=STATE_NOT_FOUND,
                            status_text=state_status_text(STATE_NOT_FOUND),
                            input_index=self.input_index,
                            provider=svc.provider_id,
                            updated_at=now,
                            last_attempt_at=now,
                            next_attempt_at=self._ti_next_attempt,
                            next_attempt_reason=self._ti_next_attempt_reason,
                        ))

        except Exception as exc:
            now = time.time()
            if self._ti_generation != my_gen or self._ti_inflight_token is not worker_token:
                logging.info(
                    "track_id[%d]: match discarded: stale generation/service.",
                    self.input_index,
                )
                return  # stale
            if isinstance(exc, TrackIDUpstreamRejectionError):
                logging.warning(
                    "track_id[%d]: upstream rejected request (http_status=%d); backing off %ds",
                    self.input_index, exc.http_status, TRACK_ID_UPSTREAM_REJECTION_BACKOFF_SECONDS,
                )
                self._schedule_track_id_after(now, TRACK_ID_UPSTREAM_REJECTION_BACKOFF_SECONDS, "upstream_rejection")
            elif isinstance(exc, TrackIDRateLimitedError):
                # Honor a provider-supplied Retry-After-equivalent value
                # when present and positive; otherwise fall back to the
                # fixed constant.
                retry_after = getattr(exc, "retry_after_seconds", None)
                if isinstance(retry_after, (int, float)) and retry_after > 0:
                    backoff = float(retry_after)
                    logging.warning(
                        "track_id[%d]: rate limited; backing off %.0fs (provider Retry-After)",
                        self.input_index, backoff,
                    )
                else:
                    backoff = TRACK_ID_RATE_LIMIT_BACKOFF_SECONDS
                    logging.warning(
                        "track_id[%d]: rate limited; backing off %ds",
                        self.input_index, backoff,
                    )
                self._schedule_track_id_after(now, backoff, "rate_limit")
            elif isinstance(exc, TrackIDProviderUnreachableError):
                # "Provider unreachable" (network/DNS/timeout) shares the
                # rate-limit backoff bucket rather than the generic
                # config-error one: a flaky network should not be retried
                # more aggressively than an explicit rate limit.
                logging.warning(
                    "track_id[%d]: provider unreachable; backing off %ds",
                    self.input_index, TRACK_ID_RATE_LIMIT_BACKOFF_SECONDS,
                )
                self._schedule_track_id_after(now, TRACK_ID_RATE_LIMIT_BACKOFF_SECONDS, "provider_unreachable")
            else:
                logging.warning(
                    "track_id[%d]: worker error: %s; retry in %.0fs.",
                    self.input_index, type(exc).__name__, TRACK_ID_ERROR_RETRY_SECONDS,
                )
                self._schedule_track_id_after(now, TRACK_ID_ERROR_RETRY_SECONDS, "error")
            if held is not None:
                self._keep_held_track(held, my_gen, worker_token, now)
            else:
                with self._ti_locked():
                    self._set_ti_snapshot(TrackIdentificationSnapshot(
                        enabled=True,
                        state=STATE_ERROR,
                        status_text=state_status_text(STATE_ERROR),
                        input_index=self.input_index,
                        provider=(runtime._track_id_service.provider_id if runtime._track_id_service else ""),
                        updated_at=now,
                        last_attempt_at=now,
                        error=type(exc).__name__,
                        next_attempt_at=self._ti_next_attempt,
                        next_attempt_reason=self._ti_next_attempt_reason,
                    ))

        finally:
            runtime._track_id_request_gate.release()
            if self._ti_inflight_token is worker_token:
                self._ti_inflight = False
                self._ti_inflight_token = None

    # ── OwnTone helpers ──────────────────────────────────────────────────────

    def _maybe_retry_owntone(
        self, now: float, replay_origin: bool = False, monitor_status: Optional[dict] = None,
    ) -> None:
        """Periodically retry refreshing currently selected OwnTone outputs.

        Thin delegate onto selfheal.SelfHeal.maybe_retry_owntone(): the substantive
        logic lives there, grouped with the other two self-heal mechanisms.
        Kept as a bound method under its original
        name so every existing call site (m._maybe_retry_owntone(...),
        patch.object(mon, "_maybe_retry_owntone")) keeps working unchanged.
        See selfheal.SelfHeal.maybe_retry_owntone()'s docstring for the full
        *replay_origin* / *monitor_status* contract.
        """
        selfheal.SelfHeal.maybe_retry_owntone(
            self, now, replay_origin=replay_origin, monitor_status=monitor_status,
        )

    def _throttled_owntone_log(self, now: float, level: int, msg: str, *args) -> None:
        """Log OwnTone-related failures with a long throttle to avoid SD churn.

        Each message has its own timer per input, so one failure repeating
        does not hide a different one."""
        if log_setup.log_every(
            ("owntone", self.input_index, msg),
            self.OWNTONE_LOG_THROTTLE_SECONDS,
            now=now,
        ):
            logging.log(level, msg, *args)

    def _log_default_output_refusal(self, now: float, default_name: str, reply) -> None:
        """The throttled line for a default-output select that was not made."""
        error = reply.error
        if error == "no_default":
            self._throttled_owntone_log(
                now, logging.WARNING,
                "No default output configured; cannot apply zero-target fallback.",
            )
        elif error == "not_found":
            self._throttled_owntone_log(
                now, logging.WARNING,
                "Default output '%s' not found in OwnTone; cannot apply fallback.", default_name,
            )
        elif error == "pin_pending":
            self._throttled_owntone_log(
                now, logging.INFO,
                "Default output '%s' is waiting for a PIN; not auto-enabling it.", default_name,
            )
        elif error == "in_use":
            self._throttled_owntone_log(
                now, logging.INFO,
                "Default output '%s' is in use by %s; skipping auto-select.",
                default_name, (reply.result or {}).get("owner", "another appliance"),
            )
        elif error == "pin_required":
            self._throttled_owntone_log(
                now, logging.INFO,
                "Default output '%s' requires a PIN; enable it via the web interface.", default_name,
            )
        else:
            self._throttled_owntone_log(
                now, logging.WARNING,
                "Failed to apply default output settings for '%s': %s",
                default_name, (reply.result or {}).get("message") or error,
            )


# --------------------------------------------------------------------------- #
# Top-level entry points                                                       #
# --------------------------------------------------------------------------- #

def _reconcile_audio_path_startup(settings) -> None:
    """One-time (per stored-value transition) audio_path write-back.

    Runs at every pass through the startup phase, sequenced before the
    first monitor-format reconcile call site below -- cheap and idempotent,
    so repeated passes (connection retries, config reloads) after the first
    successful write are no-ops. Two independent corrections share this one
    slot and mechanism (SettingsStore.save_now(), standard logging):

      - FILL-MISSING: the key is entirely absent (upgraded install whose
        settings predate this feature) -- write the hardware-mapped default
        (max on Pi 4/5-class hardware, else balanced) once, at INFO.
      - DEMOTE-ONLY: the key is present but normalizes to something lower
        (an SD card carrying "max" moved from a Pi 5 to a Zero 2 W) --
        persist the demotion once, at WARN. A present "balanced" on
        high-perf hardware normalizes to itself and is therefore never
        touched -- this can only ever lower a stored value, never raise one.
    """
    high_perf = is_high_performance_pi()
    raw = settings.raw_snapshot()
    general_raw = raw.get("general") or {}

    if "audio_path" not in general_raw:
        hardware_default = "max" if high_perf else AUDIO_PATH_DEFAULT
        settings.update(
            lambda r: r.setdefault("general", {}).update({"audio_path": hardware_default})
        )
        settings.save_now()
        logging.info(
            "audio_path setting was absent; writing hardware default %r.",
            hardware_default,
        )
        return

    stored = general_raw.get("audio_path")
    normalized = normalize_audio_path(stored, high_perf=high_perf)
    if str(stored).strip().lower() == normalized:
        return

    settings.update(
        lambda r: r.setdefault("general", {}).update({"audio_path": normalized})
    )
    settings.save_now()
    logging.warning(
        "audio_path %r is not valid for this hardware; demoted to %r.",
        stored, normalized,
    )


def _fresh_audio_path(settings) -> Optional[str]:
    """Return general.audio_path from a fresh snapshot of the canonical
    in-memory settings store.

    Returns None if the store is unavailable or the snapshot cannot be
    taken -- callers must treat None as "unknown, skip audio-path
    enforcement this pass", never fall back to a cached cfg snapshot (a
    stale snapshot acting where fresh data was unavailable is exactly the
    failure mode this exists to prevent). Deliberately not a disk read:
    json persistence lags the in-memory store by up to the dirty-save
    interval, and a successful read of pre-change bytes is
    indistinguishable from fresh data.
    """
    if settings is None:
        return None
    try:
        return settings.snapshot().general.audio_path
    except Exception:
        logging.debug("settings.snapshot() raised while reading audio_path", exc_info=True)
        return None


def _sync_audio_path_backend(base_url: str, audio_path: str) -> None:
    """Push the resample_quality knob and recompose/restart monitor args for
    *audio_path*, tolerating any backend/transport failure (both callees
    already log and self-limit; neither ever raises).

    Called from the same startup/reconnect call sites as
    reconcile_pipe_format_with_backend()/reconcile_monitor_format() above so
    a boot-time audio_path correction (see _reconcile_audio_path_startup())
    or an out-of-band config edit converges without requiring a Web UI visit.
    """
    if not base_url:
        return
    try:
        push_resample_quality(base_url, audio_path, timeout=3.0)
    except Exception:
        logging.debug("resample_quality push raised", exc_info=True)
    try:
        sync_monitor_args_for_audio_path(base_url, audio_path, timeout=3.0)
    except Exception:
        logging.debug("sync_monitor_args_for_audio_path raised", exc_info=True)


def _push_repeat_policy(
    client: monitor_client.MonitorClient,
    enabled: bool,
    codec: str,
    context: str,
    target_minutes: Optional[int] = None,
) -> None:
    """Push the persisted repeat enabled/codec/target-duration policy to the daemon.

    target_minutes is the target-duration goal; pass the persisted
    `repeat.target_minutes` setting so a freshly (re)started daemon or a
    resync always reflects it, same as enabled/codec.

    Tolerant of rejection: an older monitor binary that does not recognise
    set_repeat_enabled, or a transient failure, must never fail the caller
    (startup / reconnect resync) -- it is only logged, and repeat state
    simply re-syncs on the next successful reconnect or settings change.
    `context` names the call site for the log line, e.g. "after reconnect" or
    "during startup".
    """
    if not client.set_repeat_enabled(enabled, codec, target_minutes):
        logging.info(
            "set_repeat_enabled(%r, %r, target_minutes=%r) not accepted %s "
            "(older monitor binary, or a transient failure).",
            enabled, codec, target_minutes, context,
        )


def _resync_monitor_daemon(
    client: monitor_client.MonitorClient,
    monitors: list["AudioMonitor"],
    fifo_path: str,
    owntone_base_url: str,
    output_eq: OutputEqConfig,
    repeat_enabled: bool = False,
    repeat_codec: str = "auto",
    repeat_target_minutes: Optional[int] = None,
    audio_path: Optional[str] = None,
) -> bool:
    """Re-send the full daemon state after reconnect.

    This is transactional from Python's point of view: if any required step
    fails for any configured monitor, the whole resync is treated as failed so
    the coordinator does not continue with Python-side monitor objects that do
    not exist in the daemon.

    set_repeat_enabled is the one exception: an old binary that does not
    recognise the command must not fail the whole resync, so its result is
    logged but not treated as fatal.

    audio_path is None when the caller could not obtain a fresh value (e.g.
    the settings store was unavailable at resync time): format enforcement
    below still runs since it is snapshot-free by design, but the
    audio_path-derived backend sync leg is skipped for this pass rather than
    guessing from stale data.
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

    # Monitor-format reconcile: sequenced BEFORE the pipe-format
    # (owntone-mini-side) reconcile below, deliberately. If the active
    # backend's required_monitor_format() disagrees with what the monitor is
    # currently running as, this rewrites the monitor's env-file arg and
    # requests a monitor restart -- which tears down this very connection and
    # re-enters this function via the reconnect path, so the pipe-format
    # reconcile immediately below would otherwise chase a monitor report that
    # is about to change out from under it. Running monitor-format first
    # means: on the pass where a restart is requested, the pipe-format
    # reconcile below still runs against the (about-to-be-stale) pre-restart
    # report -- harmless, since it is idempotent and simply gets superseded
    # by the reconcile that naturally happens once the daemon reconnects
    # post-restart -- but on every subsequent pass (once the monitor is
    # already running the format the backend wants), it is a same-order
    # no-op ahead of a real pipe-format sync. Never fails the caller (see
    # docstring above).
    format_status = client.get_status()
    monitor_format_result = reconcile_monitor_format(
        owntone_base_url, format_status, timeout=3.0, audio_path=audio_path,
    )
    if monitor_format_result.error or monitor_format_result.error_code:
        logging.debug(
            "Monitor-format reconcile during monitor-daemon reconnect: %s",
            monitor_format_result.message,
        )

    # Format reconcile: sequenced
    # after the FIFO-path reconcile above, not before, because a monitor
    # reconnect is exactly the moment the daemon's (compile-time) output
    # format could have changed -- e.g. an upgraded monitor binary. Safe to
    # run unconditionally: reconcile_pipe_format_with_backend() is a no-op
    # whenever the monitor doesn't report output_rate/output_bits (older
    # daemon build) and never fails the caller, matching set_repeat_enabled's
    # "must not fail the whole resync" treatment above. No double-restart risk
    # with fifo_result: reconcile_fifo_with_backend's own restart-coupled
    # action (_request_library_update_with_retry) is a synchronous /api/update
    # HTTP call, already complete by the time we get here -- it never invokes
    # restart-owntone, so there is nothing in flight for the format reconcile's
    # (possible) real process restart to race with.
    format_result = reconcile_pipe_format_with_backend(
        owntone_base_url, format_status, timeout=3.0,
    )
    if format_result.error or format_result.error_code:
        logging.debug(
            "Pipe-format reconcile during monitor-daemon reconnect: %s",
            format_result.message,
        )

    # audio_path backend sync: same tolerant, never-fails-the-caller
    # treatment as the reconciles above -- see _sync_audio_path_backend().
    # Gated on format_status like reconcile_monitor_format()'s own no-op
    # path above: a monitor that cannot report status right now must not be
    # used as a reason to contact the playback backend at all. Also gated on
    # audio_path itself: None means the caller could not obtain a fresh
    # value, and pushing a derived resample_quality/tier from an unknown
    # source value would be a guess. The next startup lap, reconnect, or
    # settings change re-attempts with fresh data.
    if format_status and audio_path is not None:
        _sync_audio_path_backend(owntone_base_url, audio_path)
    elif format_status:
        logging.warning(
            "audio_path unavailable from the settings store; skipping "
            "audio-path enforcement for this reconnect pass."
        )

    if not client.set_fifo(fifo_path):
        logging.warning("set_fifo failed after reconnect; will retry.")
        client.close()
        return False

    live_log_level = log_setup.get_live_platform_log_level()
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
            m.minimum_playback_seconds,
            input_type=m.input_type,
            dynamic_rate_matching=m.dynamic_rate_matching,
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
        if not monitor_control.apply_input_gain(client, m.input_index, m.gain_db):
            logging.warning(
                "set_gain(%d, %.1f) failed after reconnect; will retry full resync.",
                m.input_index,
                m.gain_db,
            )
            client.close()
            return False

    for m in monitors:
        if not monitor_control.apply_input_eq(
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

    if not monitor_control._apply_output_eq_config(client, output_eq):
        logging.warning("Output EQ config failed after reconnect; will retry full resync.")
        client.close()
        return False

    _push_repeat_policy(client, repeat_enabled, repeat_codec, "after reconnect", repeat_target_minutes)

    return True


# How long the coordinator will wait for the Bluetooth pump to hold the
# loopback before starting a monitor input on that device, and the poll
# interval while waiting. The pump normally holds the loopback within a
# couple of seconds of the Bluetooth service starting; the ceiling only
# matters when that service is broken, where starting the input anyway (at
# whatever the unheld loopback negotiates) beats never starting it.
BLUETOOTH_LOOPBACK_WAIT_SECONDS = 10.0
BLUETOOTH_LOOPBACK_POLL_SECONDS = 0.5


def _wait_for_bluetooth_loopback(capture_device: str) -> None:
    """Hold off opening a monitor capture on the Bluetooth loopback until the
    pump reports it holds the playback end.

    The shared snd-aloop cable takes its rate/format from whichever end
    opens first. The pump's end carries the source's real parameters, so the
    monitor's capture open must come second -- it then auto-negotiates to
    match, exactly as it would against a hardware device with those native
    parameters. Opening first would instead pin the cable at the monitor's
    own negotiation ceiling and force the pump into its paused/retrying
    state (no audio).

    Best-effort by design: not the Bluetooth device, Bluetooth not
    installed, or a status surface without the field all fall through
    immediately; a pump that never reports readiness falls through after
    BLUETOOTH_LOOPBACK_WAIT_SECONDS with a warning.
    """
    if classify_loopback_hw(capture_device) != "capture":
        return
    if not bluetooth_installed():
        return

    bt_client = BluetoothClient()
    deadline = time.monotonic() + BLUETOOTH_LOOPBACK_WAIT_SECONDS
    while time.monotonic() < deadline and not runtime.stop_flag.is_set():
        status = bt_client.status()
        if status is not None and "loopback_held" not in status:
            return   # older bluetooth service without the field; nothing to wait on
        if status is not None and status.get("loopback_held"):
            return
        if runtime.stop_flag.wait(BLUETOOTH_LOOPBACK_POLL_SECONDS):
            return   # shutting down; the caller's own stop_flag checks take over
    logging.warning(
        "Bluetooth pump did not report holding the loopback within %.0fs; "
        "starting input on %r anyway.",
        BLUETOOTH_LOOPBACK_WAIT_SECONDS, capture_device,
    )


def _configure_startup_monitors(
    client: monitor_client.MonitorClient,
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

    monitors: list[AudioMonitor] = []

    if cfg.audio1_enabled:
        if not client.configure_input(
            1,
            cfg.audio1.capture_device,
            cfg.audio1.silence_threshold_dbfs,
            cfg.general.silence_seconds,
            cfg.track_identification.track_change_silence_seconds,
            cfg.general.minimum_playback_seconds,
            input_type=cfg.audio1.input_type,
            dynamic_rate_matching=cfg.audio1.dynamic_rate_matching,
        ):
            logging.warning(
                "configure_input(1, %r) failed during startup; will retry.",
                cfg.audio1.capture_device,
            )
            return None

        _wait_for_bluetooth_loopback(cfg.audio1.capture_device)
        if not client.start_input(1):
            logging.warning("start_input(1) failed during startup; will retry.")
            return None

        if not monitor_control.apply_input_gain(client, 1, cfg.audio1.gain_db):
            logging.warning("set_gain(1) failed during startup; will retry.")
            return None

        if not monitor_control.apply_input_eq(
            client,
            1,
            cfg.audio1.eq_40hz_db,
            cfg.audio1.eq_100hz_db,
            cfg.audio1.eq_8khz_db,
        ):
            logging.warning("set_eq(1) failed during startup; will retry.")
            return None

        monitors.append(AudioMonitor(
            input_index=1,
            input_device=cfg.audio1.capture_device,
            silence_threshold_dbfs=cfg.audio1.silence_threshold_dbfs,
            silence_seconds=cfg.general.silence_seconds,
            fifo_path=fifo_path,
            owntone_base_url=cfg.owntone.base_url,
            owntone_output_name=cfg.owntone.output_name,
            owntone_volume_percent=cfg.owntone.volume_percent,
            track_change_silence_seconds=cfg.track_identification.track_change_silence_seconds,
            minimum_playback_seconds=cfg.general.minimum_playback_seconds,
            owntone_output_offsets_ms=cfg.owntone.output_offsets_ms,
            owntone_output_airplay_modes=cfg.owntone.output_airplay_modes,
            gain_db=cfg.audio1.gain_db,
            eq_40hz_db=cfg.audio1.eq_40hz_db,
            eq_100hz_db=cfg.audio1.eq_100hz_db,
            eq_8khz_db=cfg.audio1.eq_8khz_db,
            is_turntable=cfg.audio1.is_turntable,
            input_type=cfg.audio1.input_type,
            dynamic_rate_matching=cfg.audio1.dynamic_rate_matching,
        ))

    if (
        cfg.audio2_enabled
        and cfg.audio2.capture_device
        and (not cfg.audio1_enabled or cfg.audio2.capture_device != cfg.audio1.capture_device)
    ):
        audio2_ok = True

        if not client.configure_input(
            2,
            cfg.audio2.capture_device,
            cfg.audio2.silence_threshold_dbfs,
            cfg.general.silence_seconds,
            cfg.track_identification.track_change_silence_seconds,
            cfg.general.minimum_playback_seconds,
            input_type=cfg.audio2.input_type,
            dynamic_rate_matching=cfg.audio2.dynamic_rate_matching,
        ):
            logging.error(
                "configure_input(2, %r) failed; skipping second input.",
                cfg.audio2.capture_device,
            )
            audio2_ok = False

        if audio2_ok:
            _wait_for_bluetooth_loopback(cfg.audio2.capture_device)
        if audio2_ok and not client.start_input(2):
            logging.error("start_input(2) failed; skipping second input.")
            audio2_ok = False

        if audio2_ok and not monitor_control.apply_input_gain(client, 2, cfg.audio2.gain_db):
            logging.error("set_gain(2) failed; skipping second input.")
            audio2_ok = False

        if audio2_ok and not monitor_control.apply_input_eq(
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
                minimum_playback_seconds=cfg.general.minimum_playback_seconds,
                owntone_output_offsets_ms=cfg.owntone.output_offsets_ms,
                owntone_output_airplay_modes=cfg.owntone.output_airplay_modes,
                gain_db=cfg.audio2.gain_db,
                eq_40hz_db=cfg.audio2.eq_40hz_db,
                eq_100hz_db=cfg.audio2.eq_100hz_db,
                eq_8khz_db=cfg.audio2.eq_8khz_db,
                is_turntable=cfg.audio2.is_turntable,
                input_type=cfg.audio2.input_type,
                dynamic_rate_matching=cfg.audio2.dynamic_rate_matching,
            ))

    if len(monitors) > 1:
        for m in monitors:
            m.allow_capture = False

    for m in monitors:
        m.apply_allow_capture(client)

    if not monitor_control._apply_output_eq_config(client, cfg.output_eq):
        logging.warning("Output EQ config failed during startup; will retry.")
        return None

    # Push the persisted repeat policy so a freshly (re)started daemon
    # reflects it immediately, not only after the next settings change or
    # reconnect resync. Tolerated to fail against an older monitor binary --
    # this must never block startup.
    _push_repeat_policy(client, cfg.repeat.enabled, cfg.repeat.codec, "during startup", cfg.repeat.target_minutes)

    return monitors

def _check_webui_thread(thread) -> None:
    """Raise RuntimeError if the Web UI thread has exited unexpectedly.

    Called periodically from the coordinator loops so that a dead Web UI is
    detected within one poll interval and causes a process exit that allows
    systemd to restart the service.
    """
    if thread is not None and not thread.is_alive():
        raise RuntimeError("Web UI thread has exited unexpectedly; shutting down")


# --------------------------------------------------------------------------- #
# Named-interval table                                                        #
# --------------------------------------------------------------------------- #
# One small table of (name, period, callback) rows, consulted once per        #
# coordinator-loop tick, immediately before time.sleep(). This is the "one    #
# way to run a periodic task" convention for anything slower than the loop's  #
# own 500ms cadence. Adding a new periodic task means adding one row here,    #
# not spawning a thread or hand-rolling a counter.                           #
#
# Tick-frequency checks that already carry their own internal rate limit
# (the OwnTone zero-output reconcile and hang watchdog) are intentionally
# not put on this table -- they are cheap enough, and already self-limiting
# enough, that a dedicated table row would add indirection without benefit.
@dataclass
class _NamedInterval:
    """One row in the named-interval table.

    `callback` runs at most once every `period_s`, driven synchronously from
    the coordinator loop's own tick -- no dedicated thread or timer.
    """

    name: str
    period_s: float
    callback: Callable[[], None]
    last_run: float = 0.0


class _IntervalTable:
    """A tiny in-process scheduler: a list of `_NamedInterval` rows, checked
    once per coordinator-loop tick via `tick()`.

    Not a thread of its own -- `tick()` must be called synchronously from the
    existing loop body, immediately before the loop's own sleep.
    """

    def __init__(self) -> None:
        self._intervals: list[_NamedInterval] = []

    def register(self, name: str, period_s: float, callback: Callable[[], None]) -> None:
        self._intervals.append(_NamedInterval(name=name, period_s=period_s, callback=callback))

    def tick(self, now: Optional[float] = None) -> None:
        """Run any row whose period has elapsed since it last ran.

        A freshly-registered row (never run, `last_run == 0.0`) fires on the
        first tick it's eligible for, matching the cadence a plain
        `if <condition>: callback()` check would have had at startup.
        """
        now = time.time() if now is None else now
        for interval in self._intervals:
            if now - interval.last_run >= interval.period_s:
                interval.last_run = now
                interval.callback()


@dataclass(frozen=True)
class _TickSnapshot:
    """Read-only per-tick snapshot of one poll cycle's status/repeat/
    replay-origin state, built once immediately after those values are
    read from get_status() and consulted by the ingest call sites below
    instead of each one re-deriving them from three loose locals.

    Populated from exactly the same source reads, at exactly the same
    point in the coordinator loop, that fed those calls before this
    snapshot existed -- a mechanical wrapper, not a logic change.
    TIMING-SENSITIVE: constructed once per 500ms tick.
    """

    status_by_index: dict
    repeat_status: Optional[dict]
    replay_origin_idx: Optional[int]

    def status_for(self, input_index: int) -> Optional[dict]:
        return self.status_by_index.get(input_index)

    def is_replay_origin(self, input_index: int) -> bool:
        return input_index == self.replay_origin_idx


@dataclass
class _BootstrapResult:
    """Everything run_autostream()'s startup-retry and coordinator-loop
    phases need out of one-time process bootstrap. See _bootstrap()."""

    settings: object
    own_settings: bool
    cfg: object
    webui_thread: object
    socket_path: str
    version: str
    poll_interval: float
    switch_silence_seconds: float


def _start_output_authority(cfg, settings) -> None:
    """Start the output authority on the player named in the configuration.
    Only starts its threads: the first read and the choice of event source
    are the authority's own, so the web server is never held up by the player."""
    import autostream_live_config
    autostream_live_config.bind_settings_store(settings)
    import autostream_output_policy
    policy = autostream_output_policy.get_policy()
    policy.bind_settings(autostream_live_config.output_policy_settings)
    get_authority().set_policy(policy)
    get_authority().set_include_tv_reader(autostream_live_config.include_tv_for)
    get_authority().start(PlayerServiceBackend(cfg.owntone.base_url))


def _bootstrap(config_path: str, start_webui, settings) -> _BootstrapResult:
    """Run-once process bootstrap: settings store, signal handlers, logging,
    startup log-level policy, static-facts audit, playback-tracker init,
    install-state read, optional Web UI thread start, poll-cadence
    constants, stale-Avahi cleanup, output-usage poller start.

    Split out of run_autostream() -- every line here runs exactly once and
    has no loop-carried state dependency on the startup-retry or
    coordinator-loop phases.
    """
    from autostream_settings import SettingsStore as _SettingsStore
    own_settings = settings is None
    if settings is None:
        settings = _SettingsStore(config_path)
    settings.add_commit_hook(_publish_settings_generation)

    _install_signal_handlers()
    cfg = settings.snapshot()
    log_setup.setup_logging(cfg.general.log_file, cfg.general.log_level)
    try:
        # apply_startup_log_level drives set_log_level(_startup=True), whose
        # fan-out already forwards the level to the Wi-Fi watcher -- no
        # separate startup forward call is needed here.
        from autostream_log_policy import apply_startup_log_level as _apply_startup_log_level
        _apply_startup_log_level(config_path, settings=settings)
    except Exception:
        logging.warning("apply_startup_log_level: import or apply failed; continuing")
    audit_static_system_facts()
    playback_tracking.ensure_playback_tracker(cfg)
    _install_state = get_install_state(Path("/var/lib/autostream/install-state.env"))
    version = _install_state.get("AUTOSTREAM_RELEASE_TAG", "")
    # Always logged, whatever the level (see log_lifecycle()): a log bundle
    # must say which release was running and when it started.
    log_lifecycle(
        "autostream starting (release %s, python %s, log level %s)",
        version or "unknown", sys.version.split()[0],
        log_setup.get_live_platform_log_level(),
    )

    autostream_dial_push.install_state_hints(autostream_state.store())
    _bind_intent_handlers()
    _start_output_authority(cfg, settings)

    # Optionally start the web UI.  Let any startup failure propagate so the
    # process exits nonzero and systemd can restart it.
    webui_thread = None
    if start_webui is not None:
        webui_thread = start_webui(config_path, settings=settings)

    socket_path = monitor_client.get_monitor_socket_path()
    poll_interval = 0.5          # seconds between get_status() polls
    switch_silence_seconds = 5.0 # how long current input must be silent before switching

    # Remove any stale playing announcement from a previous crash, then
    # sync the announced flag to filesystem truth so sync_playing_announcement
    # does not attempt a redundant remove on the first poll.
    announce.reset_at_startup()
    _start_output_usage_poller(cfg)

    return _BootstrapResult(
        settings=settings,
        own_settings=own_settings,
        cfg=cfg,
        webui_thread=webui_thread,
        socket_path=socket_path,
        version=version,
        poll_interval=poll_interval,
        switch_silence_seconds=switch_silence_seconds,
    )


@dataclass
class _StartupResult:
    """Outcome of run_autostream()'s startup-retry phase. See
    _await_startup().

    `abort=True` means the caller must `return` from run_autostream
    immediately, without teardown or the final settings flush -- this
    reproduces the original inline `return` statements' behavior exactly
    (the unconfigured-and-no-webui and stop-flag-while-waiting-for-config
    cases). Otherwise the caller inspects `monitors`: None means stop_flag
    was set (or the retry loop otherwise exited without success) and the
    outer reload loop should `break`; a list means startup succeeded.
    """

    monitors: Optional[list["AudioMonitor"]]
    cfg: object
    fifo_path: Optional[str]
    abort: bool = False


def _await_startup(
    config_path: str,
    settings,
    client: "monitor_client.MonitorClient",
    webui_thread,
    cfg,
    start_webui,
    socket_path: str,
) -> _StartupResult:
    """Startup-retry phase: wait out an unconfigured device, connect to the
    monitor daemon, and reconcile FIFO/pipe-format/monitor-format, retrying
    on any transient failure until stop_flag is set or startup succeeds.

    Split out of run_autostream() -- same body, same retry/continue/break
    structure, just callable in isolation. See _StartupResult for the
    return contract.
    """
    fifo_path: Optional[str] = None
    monitors: Optional[list["AudioMonitor"]] = None

    while not runtime.stop_flag.is_set():
        if unconfigured(config_path):
            if start_webui is None:
                logging.error("Configuration is incomplete; cannot start without a valid INI.")
                return _StartupResult(monitors=None, cfg=cfg, fifo_path=fifo_path, abort=True)
            logging.info(
                "Configuration is incomplete or has an invalid device format; "
                "starting in setup mode and waiting for Web UI changes.",
            )
            while not runtime.stop_flag.is_set() and unconfigured(config_path):
                _check_webui_thread(webui_thread)
                time.sleep(1.0)
            if runtime.stop_flag.is_set():
                return _StartupResult(monitors=None, cfg=cfg, fifo_path=fifo_path, abort=True)
            cfg = settings.snapshot()
            continue

        # SD-swap / fill-missing audio_path write-back, sequenced before
        # the first monitor-format reconcile call site below. Idempotent
        # (see _reconcile_audio_path_startup()'s docstring), so re-running
        # it on every lap of this loop -- including connect-retry laps --
        # settles to a no-op after the first successful correction.
        _reconcile_audio_path_startup(settings)

        cfg = settings.snapshot()
        fifo_path = cfg.general.fifo_path
        playback_tracking.ensure_playback_tracker(cfg)

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

        # Monitor-format reconcile, same placement logic as the reconnect
        # path in _resync_monitor_daemon: sequenced BEFORE the
        # pipe-format (owntone-mini-side) reconcile below, since a
        # monitor restart requested here re-enters this startup loop via
        # the `client.connect()` retry above and the pipe-format
        # reconcile naturally re-runs against the post-restart report on
        # that next lap. Unconditionally non-fatal to startup.
        format_status = client.get_status()
        monitor_format_result = reconcile_monitor_format(
            cfg.owntone.base_url, format_status, timeout=3.0,
            audio_path=cfg.general.audio_path,
        )
        if monitor_format_result.error or monitor_format_result.error_code:
            logging.debug(
                "Monitor-format reconcile during startup: %s",
                monitor_format_result.message,
            )

        # Format reconcile, same
        # placement logic as the reconnect path in _resync_monitor_daemon:
        # sequenced after the FIFO-path reconcile (whose own restart-
        # coupled action is a synchronous /api/update call, already
        # finished by now -- nothing for a real process restart to race
        # with), and unconditionally non-fatal to startup, mirroring
        # fifo_result's own soft-failure-tolerant siblings below.
        format_result = reconcile_pipe_format_with_backend(
            cfg.owntone.base_url, format_status, timeout=3.0,
        )
        if format_result.error or format_result.error_code:
            logging.debug(
                "Pipe-format reconcile during startup: %s",
                format_result.message,
            )

        # audio_path backend sync: same tolerant, never-fails-startup
        # treatment as the reconciles above -- see _sync_audio_path_backend().
        # Gated on format_status like reconcile_monitor_format()'s own
        # no-op path above: a monitor that cannot report status right
        # now must not be used as a reason to contact the playback
        # backend at all.
        if format_status:
            _sync_audio_path_backend(cfg.owntone.base_url, cfg.general.audio_path)

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
            input_status.publish_inputs()
            break

        client.close()
        _check_webui_thread(webui_thread)
        time.sleep(5.0)

    return _StartupResult(monitors=monitors, cfg=cfg, fifo_path=fifo_path, abort=False)


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
    bootstrap = _bootstrap(config_path, start_webui, settings)
    settings = bootstrap.settings
    _own_settings = bootstrap.own_settings
    cfg = bootstrap.cfg
    webui_thread = bootstrap.webui_thread
    socket_path = bootstrap.socket_path
    version = bootstrap.version
    announce.set_version(version)
    POLL_INTERVAL = bootstrap.poll_interval
    SWITCH_SILENCE_SECONDS = bootstrap.switch_silence_seconds

    # Fresh at process start; carried forward (not reconstructed) across
    # every outer-loop pass below so its restart rate limit survives both
    # reconnects and reloads -- see selfheal.carry_forward_hang_watchdog.
    owntone_hang_watchdog = selfheal.OwntoneHangWatchdog()

    # Outer loop: runs once normally; repeats after a config reload.
    while not runtime.stop_flag.is_set():
        client = monitor_client.MonitorClient(socket_path)

        # ── Startup / configuration phase ────────────────────────────────────
        startup = _await_startup(config_path, settings, client, webui_thread, cfg, start_webui, socket_path)
        cfg = startup.cfg
        fifo_path = startup.fifo_path
        monitors = startup.monitors
        if startup.abort:
            return
        if cfg.owntone.base_url != get_authority().base_url:
            get_authority().set_backend(PlayerServiceBackend(cfg.owntone.base_url))

        if runtime.stop_flag.is_set() or monitors is None:
            client.close()
            break

        runtime._track_id_service = _build_track_id_service(cfg)
        _publish_track_service(runtime._track_id_service is not None)
        for m in monitors:
            m._apply_track_id_service(runtime._track_id_service)

        logging.info(
            "autostream_core is now running with %d input(s). Press Ctrl+C to exit.",
            len(monitors),
        )

        announce.start_reconciliation_once(version)

        _start_output_usage_poller(cfg)

        current: Optional[AudioMonitor] = None
        reconnect_at: float = 0.0
        _reloading = False
        # Unified playback-session tracker: fresh instance
        # each time this point is reached (startup and every config reload),
        # and explicitly .reset() on reconnect/resync below, so a stale
        # pre-reload/pre-reconnect source can never manufacture a spurious
        # event once polling resumes.
        session_tracker = autostream_session.SessionTracker()
        # Same "log the recovery, not just the failure" rationale as
        # _owntone_recovery_log above, applied to the monitor daemon socket
        # connection: covers both the connect() retry and the get_status()
        # failure path below, since either one leaving the loop unable to
        # reach the daemon is the same observable outage to an operator.
        monitor_daemon_recovery_log = runtime.RecoveryLog("autostream_monitor connection")
        # Hang watchdog is the deliberate exception: its restart rate limit
        # carries forward across both reload and reconnect (see
        # selfheal.carry_forward_hang_watchdog and the reconnect branch below).
        owntone_hang_watchdog = selfheal.carry_forward_hang_watchdog(owntone_hang_watchdog)

        # Named-interval table: lower-frequency work registers a row here
        # instead of being interleaved ad hoc in the loop body below. Fresh
        # per (re)start, matching session_tracker/owntone_*_tracker above --
        # a row's last-run time must not carry across a reload/reconnect.
        def _flush_stats() -> None:
            t = runtime._playback_tracker
            if t is not None:
                t.maybe_flush()

        interval_table = _IntervalTable()
        interval_table.register("stats_flush", DEFAULT_FLUSH_INTERVAL_SECONDS, _flush_stats)

        # One change per poll cycle: opened after the daemon answers, closed
        # once the cycle's state is published, and closed first thing in the
        # finally below if the cycle raises before that.
        tick_batch = None
        try:
            while not runtime.stop_flag.is_set():

                # ── Web UI health check ───────────────────────────────────────
                _check_webui_thread(webui_thread)

                # ── Config reload requested by Web UI ────────────────────────
                if runtime.reload_flag.is_set():
                    runtime.reload_flag.clear()
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
                        monitor_daemon_recovery_log.fail(now)
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
                        cfg.repeat.target_minutes,
                        _fresh_audio_path(settings),
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
                        m._outputs_boot_seen = None
                    session_tracker.reset()
                    # The hang watchdog's 10-minute restart rate limit is
                    # intentionally NOT reset here -- it is a hard global
                    # safety limit that must survive a flapping daemon
                    # connection, not something a reconnect should clear.

                status = client.get_status()
                if status is None:
                    _set_monitor_runtime_info(connected=False)
                    monitor_daemon_recovery_log.fail(time.time())
                    logging.warning("get_status() failed; will reconnect.")
                    reconnect_at = time.time() + 2.0
                    continue

                monitor_daemon_recovery_log.ok(time.time())
                tick_batch = autostream_state.store().batch()
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
                autostream_repeat.publish_from_daemon(repeat_status)

                # Computed once per poll cycle from this same snapshot
                # and reused below for _ingest_status()'s
                # actively-sourcing seq check, the OwnTone retry replay_origin
                # gate, and the track-ID actively-sourcing gate -- all must
                # agree on which input (if any) is the replay origin for THIS
                # cycle, not a later, possibly-stale repeat_status.
                replay_origin_idx = autostream_state.replay_origin_input(repeat_status)

                # Read-only per-tick snapshot bundling the three values just
                # computed above, so the ingest call sites below (and the
                # OwnTone-retry / track-ID-trigger calls further down) read
                # from one object instead of re-deriving from three loose
                # locals. See _TickSnapshot.
                tick_snapshot = _TickSnapshot(
                    status_by_index=status_by_index,
                    repeat_status=repeat_status,
                    replay_origin_idx=replay_origin_idx,
                )

                # Two-pass update so that callbacks see the final state of ALL
                # monitors, not a partially-updated snapshot.  This prevents
                # spurious OwnTone stop/disable when one input hands off to
                # another in the same poll cycle.
                started: list[AudioMonitor] = []
                stopped: list[AudioMonitor] = []

                for m in monitors:
                    status_entry = tick_snapshot.status_for(m.input_index)
                    if status_entry is not None:
                        transition = m._ingest_status(
                            status_entry,
                            replay_origin=tick_snapshot.is_replay_origin(m.input_index),
                        )
                        if transition == "started":
                            started.append(m)
                        elif transition == "stopped":
                            stopped.append(m)

                # Keep playback-hours tracking aligned to actual audible
                # activity, rather than the broader capture window that
                # includes the silence timeout used to detect playback end.
                for m in monitors:
                    m._sync_playback_tracker_state(tick_snapshot.repeat_status)
                playback_tracking.publish_playback()

                # Per-input duties only (track-ID scheduling + logging); see
                # _on_capture_started/_on_capture_stopped docstrings. Fire
                # stopped callbacks first so any_monitor_capturing() is
                # already correct when started callbacks check it.
                for m in stopped:
                    m._on_capture_stopped(client)
                for m in started:
                    m._on_capture_started()
                input_status.publish_inputs()

                # ── Unified playback-session tracker ───────────────────────────
                # Single call site: derives the {input1, input2, replay}
                # source vector from this SAME snapshot and fires exactly one
                # of session_started / session_ended / source_changed / None,
                # dispatched by autostream_session.dispatch_session_event(). This is the sole
                # place session-level OwnTone output-enable/stop and
                # now-playing publish_start/publish_end run -- see
                # autostream_session.SessionTracker's module comment for the full event
                # semantics.
                session_prev_source = session_tracker.active_source
                session_event, session_prev_monitor, session_new_monitor, session_source = (
                    session_tracker.update(monitors, repeat_status)
                )
                autostream_session.dispatch_session_event(
                    session_event, session_prev_monitor, session_new_monitor,
                    cfg.owntone.base_url, new_source=session_source,
                )
                autostream_session.publish(
                    session_source is not None, session_source,
                    edge=session_event is not None)

                # The LAN "playing" announcement is a consumer of the session
                # state (so repeat replay counts, not just live capture); the
                # sync is idempotent and only touches avahi on a transition.
                announce.sync_playing_announcement(session_source is not None, version)

                tick_batch.close()

                # Reset the replay origin's identification only now that the
                # session is marked inactive and the announcement withdrawn:
                # a client polling status must never see "advertised as
                # playing" together with an already-reset identification.
                autostream_session.teardown_identification_after_replay_end(
                    session_event, session_prev_source,
                    session_prev_monitor, session_new_monitor,
                )

                # ── Output restart check + hang watchdog ───────────────────────
                # Both run every cycle (not gated on started/stopped/session
                # events above) so a mid-session state loss on an otherwise
                # steady-state "still playing" cycle is still caught.
                selfheal.SelfHeal.note_outputs(
                    session_new_monitor,
                    session_source is not None,
                    time.time(),
                )
                # A newly enabled output or a just-recovered backend has
                # requested the current now-playing bundle be re-sent (see
                # runtime.request_nowplaying_republish()); consume
                # at most one request per cycle.
                if runtime.consume_nowplaying_republish():
                    autostream_session.republish_current_nowplaying(
                        session_new_monitor, session_source is not None,
                    )
                selfheal.maybe_run_owntone_hang_watchdog(
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
                # tick_snapshot was already built above from this same poll
                # cycle's status/replay-origin read, before the ingest loop.
                now = time.time()
                for m in monitors:
                    m.apply_allow_capture(client)
                    m._maybe_retry_owntone(
                        now,
                        replay_origin=tick_snapshot.is_replay_origin(m.input_index),
                        monitor_status=status,
                    )
                    m.maybe_trigger_track_identification(
                        client, now, replay_origin=tick_snapshot.is_replay_origin(m.input_index),
                    )

                # ── Named-interval table ───────────────────────────────────────
                # Lower-frequency work (currently: stats flush) runs from here,
                # immediately before the tick sleep. See _IntervalTable above.
                interval_table.tick()

                time.sleep(POLL_INTERVAL)

        except Exception:
            logging.exception("Unexpected coordinator error; running cleanup before exit")
            raise

        finally:
            if tick_batch is not None:
                tick_batch.close()
            tracker = runtime._playback_tracker
            teardown_was_capturing = any(m.is_capturing for m in monitors)
            teardown_owntone_base_url = next(
                (m.owntone_base_url for m in monitors if m.owntone_base_url),
                "",
            )
            if teardown_was_capturing and teardown_owntone_base_url:
                # stop_and_disable_all is a stop and then a deselect of
                # everything, each bounded by its own write timeout.
                intents.submit(
                    Intent("outputs.deselect_all", {}, Origin.SESSION, "coordinator"),
                    wait=2 * WRITE_TIMEOUT_S,
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
                    tracker.on_wear_stopped(m.input_index)
                client.stop_input(m.input_index)
                m.stop()
            if tracker is not None:
                tracker.save()
            playback_tracking.publish_playback()
            with runtime._monitors_lock:
                runtime.all_monitors.clear()
            input_status.publish_inputs()
            announce.sync_playing_announcement(False, version)
            client.close()
            if not _reloading:
                log_lifecycle("autostream stopped cleanly")
                _cleanup_discovery()

        if not _reloading:
            break
        # _reloading: continue outer loop → startup phase runs again with fresh config

    get_authority().stop()

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
