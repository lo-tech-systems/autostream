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

import importlib
import os
import json
import logging
import sys
import time
import signal
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

import autostream_announce as announce
import autostream_audio_monitor as audio_monitor
import autostream_identification as identification
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
    OutputEqConfig,
    normalize_audio_path,
    unconfigured,
)
import autostream_dial_push
from autostream_bluetooth_client import (
    BluetoothClient,
    bluetooth_capture_label,
    bluetooth_installed,
    classify_loopback_hw,
)
from autostream_nowplaying import OwntoneMetadataPipePublisher
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
#   audio_monitor.AudioMonitor._ti_state_lock                -- identification dispatch
#                                                 state vs. _apply_track_id_service


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


_bind_intent_handlers()


_settings_writer = autostream_state.store().claim("settings", "autostream_core")


def _publish_settings_generation(generation: int) -> None:
    """Commit hook for the settings store: record the newest generation,
    never letting a late hook move it backwards."""
    _settings_writer.update(
        lambda cur: autostream_state.SettingsPart(max(cur.generation, generation))
    ).notify()


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
    monitors: list["audio_monitor.AudioMonitor"],
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
) -> Optional[list["audio_monitor.AudioMonitor"]]:
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

    monitors: list[audio_monitor.AudioMonitor] = []

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

        monitors.append(audio_monitor.AudioMonitor(
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
            monitors.append(audio_monitor.AudioMonitor(
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

    monitors: Optional[list["audio_monitor.AudioMonitor"]]
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
    monitors: Optional[list["audio_monitor.AudioMonitor"]] = None

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

        runtime._track_id_service = identification.build_track_id_service(cfg)
        audio_monitor.publish_track_service(runtime._track_id_service is not None)
        for m in monitors:
            m._apply_track_id_service(runtime._track_id_service)

        logging.info(
            "autostream_core is now running with %d input(s). Press Ctrl+C to exit.",
            len(monitors),
        )

        announce.start_reconciliation_once(version)

        _start_output_usage_poller(cfg)

        current: Optional[audio_monitor.AudioMonitor] = None
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
                started: list[audio_monitor.AudioMonitor] = []
                stopped: list[audio_monitor.AudioMonitor] = []

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
                # stopped callbacks first so the capture state is
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
