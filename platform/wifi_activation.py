#!/usr/bin/python3
"""wifi_activation.py

Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

Off-thread Wi-Fi activation for the Autostream Wi-Fi watcher: the worker half
of the activation engine.

Every effectful join (committed-profile reconnect, candidate-profile
activation, credential apply) runs off-thread so the monitor loop is never
blocked on a slow nmcli call.  This module owns the worker half: the shared
activation core (``_activate_profile_on`` / ``_validate_activation``), the
job/result types, the single-slot job queue and the worker thread body
(``_run_activation_job`` / ``_activation_worker_loop``).  The loop-thread tail
that applies a completed job's connectivity/session effects
(``apply_activation_result``) stays a separate concern; this module only
produces the result and hands it off.

Every function takes an :class:`ActivationContext` as its first argument — a
narrow view of the watcher exposing only the STATE, constants and callables
the worker needs.  The watcher constructs the context once and passes it
where the whole module used to go.  ``autostream_wifi_network`` is imported
directly because it is a shared module object (patching it affects both
modules).
"""
from __future__ import annotations

import logging
import queue
import threading
from dataclasses import dataclass
from typing import Callable, Optional

import autostream_wifi_network as wifi_net


@dataclass
class ActivationContext:
    """Narrow view of the watcher that the activation worker depends on.

    Constructed once by the watcher and passed to every function here.  It
    carries the shared STATE object and its lock, the NM client singleton, the
    hotspot controller, the timeout constants, and the small set of watcher
    callables the worker invokes — nothing else of the watcher is reachable
    from this module.
    """

    STATE: object
    state_lock: object
    nm: object
    hotspot_controller: object
    logger: logging.Logger
    WAIT_FOR_CONNECTION_TIMEOUT: float
    WAIT_FOR_CONNECTION_INTERVAL: float
    configure_wifi_with_nmcli: Callable
    stop_ap_mode: Callable
    get_configured_network_state: Callable
    is_wifi_client_healthy: Callable
    wait_for_connection: Callable
    _resolve_committed_uuid: Callable
    _activate_committed_on: Callable


def _activation_network_absent(result) -> bool:
    """True when nmcli reported the target SSID is not currently visible.

    A hard "network could not be found" activation failure means waiting the full
    WAIT_FOR_CONNECTION_TIMEOUT for an IPv4 lease is pointless — the join never
    started — so the recovery ladder should fail this rung immediately and climb
    to the next one (e.g. the onboard) far sooner.
    """
    if result is None or getattr(result, "returncode", 0) == 0:
        return False
    stderr = (getattr(result, "stderr", "") or "").lower()
    return "could not be found" in stderr or "no network with ssid" in stderr


def _activate_profile_on(ctx: ActivationContext, ifname: str, state: "wifi_net.NetworkState",
                         *, wait_for_validation: bool = True) -> bool:
    """Shared activation core: resolve UUID, clear restrictions, activate, validate.

    Clears cross-adapter NM restrictions (interface-name, MAC, BSSID, band,
    channel) BEFORE activating so a legacy profile bound to one adapter can be
    moved to another.  A "network could not be found" activation short-circuits
    the IPv4 wait (the join never started).  With ``wait_for_validation`` the
    interface must become a healthy, non-AP client to return True; without it
    the call is fire-and-forget and returns True as soon as the activation
    command succeeds (the monitor loop validates on a later pass).
    """
    if not state.is_configured:
        return False
    uuid = ctx._resolve_committed_uuid(state)
    if uuid:
        ctx.nm.clear_restrictions(uuid, wifi_net.CROSS_ADAPTER_RESTRICTIONS)
    r_up = ctx.nm.activate(uuid, state.connection_name, ifname)
    return _validate_activation(ctx, ifname, r_up, wait_for_validation=wait_for_validation)


def _validate_activation(ctx: ActivationContext, ifname: str, activation_result,
                         *, wait_for_validation: bool = True) -> bool:
    """Shared post-activation validation tail (net-absent -> IPv4 -> gateway).

    Used by every join path (committed-profile core and the candidate-profile
    builder) so the "network could not be found" short-circuit and the
    IPv4-then-gateway health check are defined once.  Returns True only when the
    interface becomes a healthy, non-AP client; when ``wait_for_validation`` is
    False it is fire-and-forget (True iff the activation command succeeded).
    """
    # Probe-patience: a "network not found" activation cannot yield an IP, so
    # skip the IPv4 wait and fail fast (frees the ladder to climb sooner).
    if _activation_network_absent(activation_result):
        ctx.logger.info("Network not visible on %s; skipping IPv4 wait", ifname)
        return False
    if not wait_for_validation:
        return getattr(activation_result, "returncode", 1) == 0
    return (ctx.wait_for_connection(ifname, timeout=ctx.WAIT_FOR_CONNECTION_TIMEOUT,
                                    interval=ctx.WAIT_FOR_CONNECTION_INTERVAL)
            and ctx.is_wifi_client_healthy(ifname))


# ---- Off-thread activation worker — job/result types + the worker half ----
#
# Activation is split into a worker half (_run_activation_job: slow, bounded
# effects — AP drop for the attempt, the nmcli core, and symmetric AP rebuild on
# its own failure) and a loop half (apply_activation_result: the success/failure
# connectivity tail).  Every effectful join goes off-thread: loop-initiated call
# sites submit the worker half and the loop applies the tail at the next pass top.
# The only remaining synchronous join core is _activate_committed_on, used by
# wifi_recovery's two transitioning-gated dead-PHY rungs.


@dataclass(frozen=True)
class ActivationJob:
    """One activation request (worker input).  Carries the tail-selection flags the
    loop half (apply_activation_result) reads to reproduce the per-site tail."""
    epoch: int
    kind: str                          # "activate_committed" | "activate_profile" | "apply_credentials"
    ifname: str
    profile: "Optional[wifi_net.NetworkState]" = None
    ssid: str = ""                     # apply_credentials only
    password: str = ""                 # apply_credentials only (never logged)
    drop_hotspot: bool = False
    on_success_leaves_setup: bool = False
    leave_reason: str = ""
    records_noip: bool = False
    noip_at: "Optional[float]" = None
    records_onboard_failure: bool = False   # count onboard failures toward the hotspot bound
    sets_builtin_fallback: "Optional[bool]" = None
    clears_down_timers: bool = False
    # Runtime-adoption transactional handover: disconnect this previously-active
    # client on the success tail (only after the worker validated the new one).
    disconnects_previous_ifname: str = ""
    clears_pending_adoption: bool = False   # clear STATE.pending_usb_adoption on done
    stable_id: "Optional[str]" = None
    wait_for_validation: bool = True


@dataclass(frozen=True)
class ActivationResult:
    """One activation outcome (worker output); the loop applies the tail."""
    epoch: int
    ok: bool
    ifname: str
    job: "ActivationJob"
    error: str = ""


_activation_epoch_counter: int = 0


def _next_activation_epoch(ctx: ActivationContext) -> int:
    """Monotonic epoch so a stale worker result can be recognised and discarded."""
    global _activation_epoch_counter
    with ctx.state_lock:
        _activation_epoch_counter += 1
        return _activation_epoch_counter


def _run_activation_job(ctx: ActivationContext, job: "ActivationJob") -> "ActivationResult":
    """Worker half: the slow, bounded effects only (no connectivity/session tail).

    Optional AP drop for the attempt, the shared activation core, and — symmetric
    self-undo — rebuild the AP if this attempt dropped it and then failed.  Takes
    ``state_lock`` only for the brief flag reads/writes, never across the blocking
    nmcli/wait calls.  Returns the outcome; the loop applies the tail.
    """
    if job.kind == "apply_credentials":
        # The credential-apply transaction runs the rollback-safe candidate
        # sequence itself (scan -> ordered targets -> commit-on-success); the loop
        # applies the wait-page status tail AND the session success tail.
        # configure_wifi_with_nmcli returns the adapter it came up on; carry that
        # ifname on the result so apply_activation_result can set the active
        # client and leave setup on the loop thread.
        ctx.logger.info("Async apply starting for SSID '%s'", job.ssid)
        target = ctx.configure_wifi_with_nmcli(job.ssid, job.password)
        ok = target is not None
        ifname = target.ifname if target is not None else ""
        return ActivationResult(job.epoch, ok, ifname, job, error="" if ok else "nmcli-failed")

    if not job.ifname:
        return ActivationResult(job.epoch, False, "", job, error="no_ifname")

    dropped_ap = False
    if job.drop_hotspot:
        with ctx.state_lock:
            in_setup = ctx.STATE.setup_mode
        if in_setup:
            ctx.stop_ap_mode()
            dropped_ap = True

    if job.profile is None and job.wait_for_validation:
        # Common case: route through the named _activate_committed_on seam so
        # existing per-caller test patches continue to intercept the core.
        ok = ctx._activate_committed_on(job.ifname)
    else:
        state = job.profile if job.profile is not None else ctx.get_configured_network_state()
        ok = _activate_profile_on(ctx, job.ifname, state, wait_for_validation=job.wait_for_validation)

    # Worker self-undo: rebuild the AP it tore down so the portal stays up.  On
    # success the AP teardown (leave_setup_mode) is a loop-applied tail instead.
    if not ok and dropped_ap:
        ctx.hotspot_controller.rebuild()

    return ActivationResult(job.epoch, ok, job.ifname, job,
                            error="" if ok else "activation_failed")


# ---- Worker thread: single-slot job queue + result slot ----
#
# There is never more than one in-flight activation — the STATE.transitioning gate
# enforces it — so the queue and result slot are single-slot.  The loop submits a
# job (setting transitioning) and keeps ticking; the worker runs the one slow job
# and posts a result; step_apply_activation_result drains and applies it at pass
# top and clears transitioning.

_activation_job_queue: "queue.Queue" = queue.Queue(maxsize=1)
_activation_result_slot: "Optional[ActivationResult]" = None
_activation_result_lock = threading.Lock()
activation_result_event = threading.Event()
_inflight_activation_epoch: "Optional[int]" = None


def submit_activation_job(ctx: ActivationContext, job: "ActivationJob") -> bool:
    """Submit at most one in-flight activation job; set the transitioning gate.

    Returns False without enqueuing when a job is already in flight (the caller
    must have honoured the transitioning gate; this is the belt-and-braces guard).
    """
    global _inflight_activation_epoch
    with ctx.state_lock:
        if ctx.STATE.transitioning:
            return False
        ctx.STATE.transitioning = True
        _inflight_activation_epoch = job.epoch
    _activation_job_queue.put(job)
    return True


def _post_activation_result(result: "ActivationResult") -> None:
    """Worker -> loop hand-off: store the result and signal the loop."""
    global _activation_result_slot
    with _activation_result_lock:
        _activation_result_slot = result
    activation_result_event.set()


def drain_activation_result() -> "Optional[ActivationResult]":
    """Loop-side: take the pending worker result (if any) and clear the signal."""
    global _activation_result_slot
    with _activation_result_lock:
        result = _activation_result_slot
        _activation_result_slot = None
    activation_result_event.clear()
    return result


def get_inflight_activation_epoch() -> "Optional[int]":
    """Loop-side: the epoch of the activation currently in flight (if any)."""
    return _inflight_activation_epoch


def clear_inflight_activation_epoch() -> None:
    """Loop-side: clear the in-flight epoch once its result has been applied."""
    global _inflight_activation_epoch
    _inflight_activation_epoch = None


def _activation_worker_loop(ctx: ActivationContext) -> None:
    """Worker thread body: run one job at a time, posting each result.

    A ``None`` job is the stop sentinel (used by tests).  The worker never applies
    session/connectivity success tails; its only sanctioned session-state writes
    are the AP drop/rebuild flags around its own attempt.  It runs
    _run_activation_job (slow bounded effects) and posts the outcome for the loop
    to apply.
    """
    while True:
        job = _activation_job_queue.get()
        if job is None:
            return
        try:
            result = _run_activation_job(ctx, job)
        except Exception as e:  # never let the worker thread die silently
            ctx.logger.exception("activation worker: job failed")
            result = ActivationResult(job.epoch, False, job.ifname, job,
                                      error=f"worker_exception: {e}")
        _post_activation_result(result)


def start_activation_worker(ctx: ActivationContext) -> "threading.Thread":
    """Start the daemon worker thread (idle until a job is submitted)."""
    t = threading.Thread(target=_activation_worker_loop, args=(ctx,), daemon=True,
                         name="activation-worker")
    t.start()
    return t
