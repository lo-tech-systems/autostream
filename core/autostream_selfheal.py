"""autostream_selfheal -- what self-heals the coordinator: the OwnTone hang
watchdog (a supervised restart when the pipe to the player is stuck) and the
output retry (the default speaker and the selection re-applied after a player
restart), published as the health part.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
from dataclasses import replace
from typing import Optional

import autostream_intents as intents
import autostream_runtime as runtime
import autostream_state
from autostream_intents import Intent
from autostream_player_service import (
    config_airplay_mode_to_backend,
    list_outputs,
    reconcile_fifo_with_backend,
    retry_pending_format_reconcile,
)
from autostream_state import Origin
from autostream_sysutils import run_admin_cmd


# ── Self-heal status cache ───────────────────────────────────────────────────
# Exposed via /api/status (webui/browser/home_api.py) for observability; never
# authoritative for coordinator decisions (the hang watchdog's state lives on
# its own instance, which is coordinator-thread-only).

_health_writer = autostream_state.store().claim("health", "autostream_selfheal")


def _set_owntone_selfheal_state(**fields) -> None:
    _health_writer.update(lambda cur: replace(cur, **fields)).notify()


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
# uses -- see webui/browser/owntone.py's _restart_owntone_worker) when
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
class OwntoneHangWatchdog:
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


def carry_forward_hang_watchdog(previous: "OwntoneHangWatchdog") -> "OwntoneHangWatchdog":
    """Build the hang watchdog for a new outer-loop pass, preserving the
    prior instance's restart-rate-limit state.

    A config reload re-enters the same startup code path as first process
    launch, which would otherwise hand back a brand-new watchdog with its
    10-minute restart rate limit vacuously satisfied -- permitting an
    immediate second forced OwnTone restart right after a reload, even if
    one had just fired moments before. That limit is a hard ceiling meant to
    survive a reload exactly as it already survives a monitor-daemon
    reconnect (which deliberately leaves this watchdog untouched); only the
    restart bookkeeping carries forward here, nothing else.
    """
    watchdog = OwntoneHangWatchdog()
    watchdog._last_restart_at = previous._last_restart_at
    watchdog.restart_count = previous.restart_count
    return watchdog


def _fire_owntone_hang_restart(base_url: str, stalled_seconds: float) -> None:
    """Background (non-blocking) autostream_admin restart-owntone request.

    Runs run_admin_cmd() via the process-wide task pool under the
    single-flight key "owntone-restart" -- the same "sudo -n
    autostream_admin restart-owntone" invocation the Web UI's owntone-setup
    restart button uses (webui/browser/owntone.py's
    _restart_owntone_worker) -- so the coordinator poll loop (0.5 s cadence)
    is never blocked on the up-to-20 s subprocess call. The output authority
    notices the restart on a later read and selects the speakers again; this
    function does not attempt to re-enable anything itself.

    This is a low-risk fit for the task pool:
    OwntoneHangWatchdog.maybe_fire() already rate-limits calls
    into this function to at most once per RESTART_RATE_LIMIT_SECONDS
    (600s), and this is the function's only call site, so the pool's
    single-flight guard is a defensive no-op in practice, never expected to
    actually reject a submission -- no code path today needs two concurrent
    restart-owntone calls in flight.
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

    if not runtime._task_pool.submit("owntone-restart", _worker):
        logging.debug(
            "OwnTone-hang watchdog: restart-owntone already in flight; "
            "skipping duplicate request."
        )


def maybe_run_owntone_hang_watchdog(
    watchdog: "OwntoneHangWatchdog",
    status: dict,
    session_active: bool,
    owntone_base_url: str,
    now: float,
) -> None:
    """Poll-loop wiring for OwntoneHangWatchdog: check, and act if it fires."""
    fifo_status = status.get("fifo") if isinstance(status, dict) else None

    def _reachable() -> bool:
        if not owntone_base_url:
            return False
        if not autostream_state.store().snapshot().outputs.connected:
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


# --------------------------------------------------------------------------- #
# Self-heal grouping                                                          #
# --------------------------------------------------------------------------- #
#
# OwntoneHangWatchdog / maybe_run_owntone_hang_watchdog / _fire_owntone_
# hang_restart (all defined immediately above) are free functions/classes,
# not AudioMonitor methods. SelfHeal gathers the self-heal mechanisms that
# the coordinator drives under one namespace so a reader has one place to look
# for "what self-heals this process": the hang watchdog and the output retry
# (the output authority itself re-selects speakers after a player restart).
# AudioMonitor._maybe_retry_owntone's substantive logic lives here as
# SelfHeal.maybe_retry_owntone() (self -> monitor); AudioMonitor keeps a
# thin one-line delegate under its original name so every existing call site
# (m._maybe_retry_owntone(...), patch.object(mon, "_maybe_retry_owntone"))
# keeps working exactly as before.
class SelfHeal:
    """Namespace grouping the coordinator's self-heal mechanisms: the hang
    watchdog and the OwnTone output retry. See module comment above."""

    HangWatchdog = OwntoneHangWatchdog

    maybe_run_hang_watchdog = staticmethod(maybe_run_owntone_hang_watchdog)

    @staticmethod
    def maybe_retry_owntone(
        monitor: "AudioMonitor",
        now: float,
        replay_origin: bool = False,
        monitor_status: Optional[dict] = None,
    ) -> None:
        """Periodically retry refreshing currently selected OwnTone outputs
        for one AudioMonitor. Same body as AudioMonitor._maybe_retry_owntone(),
        with `self` renamed to `monitor`, no logic change.

        *replay_origin* is True when this monitor's input is the current
        replay's origin_input: this input isn't "capturing" while
        replay plays its buffer, but it is still the session's audible
        source, so the retry must not bail out as if idle. Defaults to False
        so existing capture-driven call sites are unaffected.

        *monitor_status* is the poll loop's most recent client.get_status()
        result, if the caller has one in hand -- passed through to
        retry_pending_format_reconcile() below. Callers
        without a fresh status handy (e.g. the replay-session-start path)
        may omit it: a pending format retry just waits for the next call
        that does have one, which for the main poll-loop call site is at
        most one poll interval away.
        """
        if not monitor.is_capturing and not replay_origin:
            return
        if not monitor.owntone_base_url:
            return
        if monitor._owntone_enabled_ok:
            return
        if (now - monitor._owntone_last_attempt) < monitor.OWNTONE_RETRY_SECONDS:
            return
        monitor._owntone_last_attempt = now

        fifo_result = reconcile_fifo_with_backend(
            monitor.owntone_base_url,
            monitor.fifo_path,
            timeout=3.0,
            update_timeout_s=5.0,
            update_interval_s=2.0,
        )
        if not fifo_result.ok:
            monitor._owntone_recovery_log.fail(now)
            monitor._throttled_owntone_log(
                now,
                logging.WARNING,
                "Skipping OwnTone recovery while FIFO/backend reconciliation failed: %s",
                fifo_result.message or "reconcile failed",
            )
            return

        snap = autostream_state.store().snapshot().outputs
        if not snap.connected:
            monitor._owntone_recovery_log.fail(now)
            monitor._throttled_owntone_log(
                now,
                logging.WARNING,
                "Skipping OwnTone selected-output refresh: outputs API unavailable.",
            )
            return

        # The authority just confirmed owntone-mini is reachable -- exactly
        # the moment to retry a still-pending pipe-format reconcile, in case a
        # startup/reconnect-time partial save is still waiting for the
        # backend to come back. Cheap no-op (zero HTTP traffic) whenever
        # nothing is pending, so this costs nothing in the steady state.
        retry_pending_format_reconcile(monitor.owntone_base_url, monitor_status)

        if snap.unit_by_name((monitor.owntone_output_name or "").strip()) is not None:
            monitor.note_default_output_found(now, monitor.owntone_output_name)
        volume = _clamped_output_volume(monitor.owntone_volume_percent)
        if not snap.selected_units():
            if snap.silence_chosen:
                # The user chose silence this session (switched the last
                # speaker off, or a device did); the default speaker is not
                # switched back on. The FIFO/format reconcile work above
                # still ran this cycle.
                return
            if any(u.availability == "password" for u in snap.units):
                monitor._throttled_owntone_log(
                    now,
                    logging.INFO,
                    "An output is waiting for a PIN; not auto-enabling the default output.",
                )
                return
            default_name = (monitor.owntone_output_name or "").strip()
            default_unit = snap.unit_by_name(default_name) if default_name else None
            args = {"name": monitor.owntone_output_name or "", "volume": volume}
            if default_unit is not None:
                offset_ms = monitor.owntone_output_offsets_ms.get(default_unit.id)
                if offset_ms is not None:
                    args["offset_ms"] = int(offset_ms)
                mode = config_airplay_mode_to_backend(
                    monitor.owntone_output_airplay_modes.get(default_unit.id))
                if mode:
                    args["mode"] = mode
            reply = intents.submit(Intent("outputs.select_default", args, Origin.SESSION, "coordinator"))
            if not reply.ok:
                monitor._log_default_output_refusal(now, default_name, reply)
                monitor._throttled_owntone_log(
                    now,
                    logging.INFO,
                    "No outputs selected during capture; default fallback not available yet.",
                )
                return
        monitor._owntone_recovery_log.ok(now)
        monitor._owntone_enabled_ok = True

    @staticmethod
    def note_outputs(monitor: Optional["AudioMonitor"], session_active: bool, now: float) -> None:
        """Called every coordinator cycle. When a session is active and the
        output authority has seen the player restart, re-arm the output retry
        (which re-runs the FIFO and format reconcile) and count it (the
        figures the status reply shows). The authority itself restores the
        selection."""
        if not session_active or monitor is None:
            return
        current = autostream_state.store().snapshot().outputs.backend_restarts
        seen = monitor._outputs_restarts_seen
        monitor._outputs_restarts_seen = current
        if seen is None or seen == current or not monitor._owntone_enabled_ok:
            return
        monitor._owntone_enabled_ok = False
        monitor._owntone_last_attempt = 0.0
        cur = autostream_state.store().snapshot().health
        _set_owntone_selfheal_state(
            reconcile_fired_count=cur.reconcile_fired_count + 1,
            reconcile_last_fired_at=now,
        )
        logging.warning("OwnTone restarted mid-session; its outputs are restored by the output reconcile.")


def _clamped_output_volume(value) -> int:
    try:
        return max(0, min(100, int(value)))
    except Exception:
        return 20
