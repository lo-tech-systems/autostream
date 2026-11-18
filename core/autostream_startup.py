"""autostream_startup -- bringing the monitor daemon up to the configuration:
the start-up retry, the per-input start, the resync after a reconnect, the
audio-path write-back, and the process's signal handlers.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
import signal
import time
from dataclasses import dataclass
from typing import Optional

import autostream_audio_monitor as audio_monitor
import autostream_input_status as input_status
import autostream_logging as log_setup
import autostream_monitor_client as monitor_client
import autostream_monitor_control as monitor_control
import autostream_playback_tracking as playback_tracking
import autostream_runtime as runtime
from autostream_bluetooth_client import BluetoothClient, bluetooth_installed, classify_loopback_hw
from autostream_config import (
    AUDIO_PATH_DEFAULT,
    OutputEqConfig,
    normalize_audio_path,
    unconfigured,
)
from autostream_player_service import (
    ensure_pipe_source_ready,
    push_resample_quality,
    reconcile_fifo_with_backend,
    reconcile_monitor_format,
    reconcile_pipe_format_with_backend,
    sync_monitor_args_for_audio_path,
)
from autostream_system_stats import is_high_performance_pi


def handle_signal(signum, frame):
    runtime.stop_flag.set()


def install_signal_handlers() -> None:
    """Register SIGINT/SIGTERM handlers. Call once from the process entry point."""
    signal.signal(signal.SIGINT,  handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)


def reconcile_audio_path_startup(settings) -> None:
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


def fresh_audio_path(settings) -> Optional[str]:
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


def sync_audio_path_backend(base_url: str, audio_path: str) -> None:
    """Push the resample_quality knob and recompose/restart monitor args for
    *audio_path*, tolerating any backend/transport failure (both callees
    already log and self-limit; neither ever raises).

    Called from the same startup/reconnect call sites as
    reconcile_pipe_format_with_backend()/reconcile_monitor_format() above so
    a boot-time audio_path correction (see reconcile_audio_path_startup())
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


def resync_monitor_daemon(
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
    # treatment as the reconciles above -- see sync_audio_path_backend().
    # Gated on format_status like reconcile_monitor_format()'s own no-op
    # path above: a monitor that cannot report status right now must not be
    # used as a reason to contact the playback backend at all. Also gated on
    # audio_path itself: None means the caller could not obtain a fresh
    # value, and pushing a derived resample_quality/tier from an unknown
    # source value would be a guess. The next startup lap, reconnect, or
    # settings change re-attempts with fresh data.
    if format_status and audio_path is not None:
        sync_audio_path_backend(owntone_base_url, audio_path)
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
            start_after_ms=m.start_after_ms,
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


def configure_startup_monitors(
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
            start_after_ms=cfg.audio1.start_after_ms,
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
            start_after_ms=cfg.audio1.start_after_ms,
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
            start_after_ms=cfg.audio2.start_after_ms,
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
                start_after_ms=cfg.audio2.start_after_ms,
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


def check_webui_thread(thread) -> None:
    """Raise RuntimeError if the Web UI thread has exited unexpectedly.

    Called periodically from the coordinator loops so that a dead Web UI is
    detected within one poll interval and causes a process exit that allows
    systemd to restart the service.
    """
    if thread is not None and not thread.is_alive():
        raise RuntimeError("Web UI thread has exited unexpectedly; shutting down")


def log_pipe_source_ready(base_url: str, *, after_reconnect: bool = False) -> None:
    """Check that the player has indexed the pipe source and log the result.
    A missing base URL (no player configured) is skipped."""
    if not base_url:
        return
    suffix = " after reconnect" if after_reconnect else ""
    pipe_ready_result = ensure_pipe_source_ready(base_url, timeout=3)
    if pipe_ready_result.ok:
        logging.info("OwnTone pipe source is indexed and ready%s.", suffix)
    elif pipe_ready_result.error_code == "unsupported":
        # A player that cannot inspect its pipe source has nothing to wait for.
        logging.debug("The playback backend does not report whether its pipe source is indexed%s.", suffix)
    elif after_reconnect:
        logging.warning(
            "OwnTone pipe source is not indexed yet after reconnect; "
            "playback recovery may lag until backend refresh succeeds (%s).",
            pipe_ready_result.message or "not ready",
        )
    else:
        logging.warning(
            "OwnTone pipe source is not indexed yet; "
            "playback start may fail until backend refresh succeeds (%s).",
            pipe_ready_result.message or "not ready",
        )


@dataclass
class StartupResult:
    """Outcome of run_autostream()'s startup-retry phase. See
    await_startup().

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


def await_startup(
    config_path: str,
    settings,
    client: "monitor_client.MonitorClient",
    webui_thread,
    cfg,
    start_webui,
    socket_path: str,
) -> StartupResult:
    """Startup-retry phase: wait out an unconfigured device, connect to the
    monitor daemon, and reconcile FIFO/pipe-format/monitor-format, retrying
    on any transient failure until stop_flag is set or startup succeeds.

    Split out of run_autostream() -- same body, same retry/continue/break
    structure, just callable in isolation. See StartupResult for the
    return contract.
    """
    fifo_path: Optional[str] = None
    monitors: Optional[list["audio_monitor.AudioMonitor"]] = None

    while not runtime.stop_flag.is_set():
        if unconfigured(config_path):
            if start_webui is None:
                logging.error("Configuration is incomplete; cannot start without a valid INI.")
                return StartupResult(monitors=None, cfg=cfg, fifo_path=fifo_path, abort=True)
            logging.info(
                "Configuration is incomplete or has an invalid device format; "
                "starting in setup mode and waiting for Web UI changes.",
            )
            while not runtime.stop_flag.is_set() and unconfigured(config_path):
                check_webui_thread(webui_thread)
                time.sleep(1.0)
            if runtime.stop_flag.is_set():
                return StartupResult(monitors=None, cfg=cfg, fifo_path=fifo_path, abort=True)
            cfg = settings.snapshot()
            continue

        # SD-swap / fill-missing audio_path write-back, sequenced before
        # the first monitor-format reconcile call site below. Idempotent
        # (see reconcile_audio_path_startup()'s docstring), so re-running
        # it on every lap of this loop -- including connect-retry laps --
        # settles to a no-op after the first successful correction.
        reconcile_audio_path_startup(settings)

        cfg = settings.snapshot()
        fifo_path = cfg.general.fifo_path
        playback_tracking.ensure_playback_tracker(cfg)

        if not client.connect():
            logging.warning(
                "Cannot connect to autostream_monitor at %s; retrying in 5 s.",
                socket_path,
            )
            check_webui_thread(webui_thread)
            time.sleep(5.0)
            continue

        fifo_result = reconcile_fifo_with_backend(cfg.owntone.base_url, fifo_path, timeout=3.0)
        if not fifo_result.ok:
            logging.error(
                "Could not reconcile audio FIFO/backend during startup: %s",
                fifo_result.message or "reconcile failed",
            )
            client.close()
            check_webui_thread(webui_thread)
            time.sleep(5.0)
            continue

        # Monitor-format reconcile, same placement logic as the reconnect
        # path in resync_monitor_daemon: sequenced BEFORE the
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
        # placement logic as the reconnect path in resync_monitor_daemon:
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
        # treatment as the reconciles above -- see sync_audio_path_backend().
        # Gated on format_status like reconcile_monitor_format()'s own
        # no-op path above: a monitor that cannot report status right
        # now must not be used as a reason to contact the playback
        # backend at all.
        if format_status:
            sync_audio_path_backend(cfg.owntone.base_url, cfg.general.audio_path)

        if not client.set_fifo(fifo_path):
            logging.warning("set_fifo(%r) failed during startup; retrying in 5 s.", fifo_path)
            client.close()
            check_webui_thread(webui_thread)
            time.sleep(5.0)
            continue

        log_pipe_source_ready(cfg.owntone.base_url)

        monitors = configure_startup_monitors(client, cfg, fifo_path)
        if monitors is not None:
            input_status.publish_inputs()
            break

        client.close()
        check_webui_thread(webui_thread)
        time.sleep(5.0)

    return StartupResult(monitors=monitors, cfg=cfg, fifo_path=fifo_path, abort=False)
