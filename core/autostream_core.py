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

This module is the process bootstrap and the coordinator loop: it sets up the
settings store, logging and the output authority, starts the background
services and the web UI, then polls the daemon twice a second and hands each
cycle's changes to the modules that act on them (the session tracker, the
per-input monitors, the self-heal and the published parts).  Monitor start-up
and resync, the per-input state, track identification, the background
services and the dial push client are in their own modules.
"""

import importlib
import logging
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

import autostream_announce as announce
import autostream_audio_monitor as audio_monitor
import autostream_identification as identification
import autostream_input_status as input_status
import autostream_logging as log_setup
import autostream_monitor_client as monitor_client
import autostream_playback_tracking as playback_tracking
import autostream_repeat
import autostream_runtime as runtime
import autostream_selfheal as selfheal
import autostream_services as services
import autostream_session
import autostream_startup as startup
import autostream_state
import autostream_intents as intents
from autostream_intents import Intent
from autostream_state import Origin
from autostream_state.outputs import WRITE_TIMEOUT_S, PlayerServiceBackend, get_authority
import autostream_dial_push
from autostream_playback_stats import DEFAULT_FLUSH_INTERVAL_SECONDS
from autostream_sysutils import (
    audit_static_system_facts,
    get_install_state,
    log_lifecycle,
)


# --------------------------------------------------------------------------- #
# Where the locks and events live. The coordinator holds none of its own; each #
# belongs to the module that guards the state it protects.                    #
# --------------------------------------------------------------------------- #
#
# Process-wide signals (not tied to any store):
#   stop_flag, reload_flag                    -- in autostream_runtime
#
# Domain locks held across read, build and publish of one part:
#   input_status._inputs_publish_lock         -- the inputs part
#   playback_tracking._playback_publish_lock  -- the playback part
#
# Independent, single-purpose locks:
#   (_monitors_lock and _track_id_request_gate are in autostream_runtime;
#    the Avahi "playing" announcement lock is in autostream_announce)
#   (the now-playing republish-request lock is in autostream_runtime)
#   (the repeat-block overlay lock is in autostream_repeat)
#
# Class-level:
#   MonitorClient._lock                       -- serializes daemon-socket
#                                                 commands across coordinator
#                                                 + track-ID worker threads
#   audio_monitor.AudioMonitor._ti_state_lock -- identification dispatch
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
    "autostream_align",
    "autostream_dial_push",
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


# --------------------------------------------------------------------------- #
# Top-level entry points                                                       #
# --------------------------------------------------------------------------- #

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

    startup.install_signal_handlers()
    cfg = settings.snapshot()
    log_setup.setup_logging(cfg.general.log_file, cfg.general.log_level)
    try:
        # apply_startup_log_level drives set_log_level(_startup=True), whose
        # fan-out already forwards the level to the Wi-Fi watcher -- no
        # separate startup forward call is needed here.
        import autostream_log_policy
        autostream_log_policy.apply_startup_log_level(config_path, settings=settings)
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
        import webui.peer.gateway as webui_gateway
        import webui.system.updates as webui_updates
        services.start(runtime.lifecycle(), settings,
                       app_version=webui_updates.get_app_version,
                       sweeps=(webui_gateway.sweep_token_cache,),
                       on_peer_removed=(webui_gateway.evict_gateway_token,))
        webui_thread = start_webui(config_path, settings=settings)

    socket_path = monitor_client.get_monitor_socket_path()
    poll_interval = 0.5          # seconds between get_status() polls
    switch_silence_seconds = 5.0 # how long current input must be silent before switching

    # Remove any stale playing announcement from a previous crash, then
    # sync the announced flag to filesystem truth so sync_playing_announcement
    # does not attempt a redundant remove on the first poll.
    announce.reset_at_startup()
    services.start_output_usage_poller(cfg, runtime.lifecycle())

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
        startup_result = startup.await_startup(config_path, settings, client, webui_thread, cfg, start_webui, socket_path)
        cfg = startup_result.cfg
        fifo_path = startup_result.fifo_path
        monitors = startup_result.monitors
        if startup_result.abort:
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

        services.start_output_usage_poller(cfg, runtime.lifecycle())

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
                startup.check_webui_thread(webui_thread)

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
                    if not startup.resync_monitor_daemon(
                        client,
                        monitors,
                        fifo_path,
                        cfg.owntone.base_url,
                        cfg.output_eq,
                        cfg.repeat.enabled,
                        cfg.repeat.codec,
                        cfg.repeat.target_minutes,
                        startup.fresh_audio_path(settings),
                    ):
                        _set_monitor_runtime_info(connected=False)
                        reconnect_at = time.time() + 5.0
                        current = None
                        continue

                # ── Poll status ───────────────────────────────────────────────
                    startup.log_pipe_source_ready(cfg.owntone.base_url, after_reconnect=True)

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
                services.stop_discovery()

        if not _reloading:
            break
        # _reloading: continue outer loop → startup phase runs again with fresh config

    get_authority().stop()

    # Final flush: persist any pending in-memory changes before process exit.
    # Also covers the case where the coordinator loop was never entered (stop_flag
    # set during the startup phase before stop_discovery ran in the finally).
    services.stop_discovery()
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
