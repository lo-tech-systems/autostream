#!/usr/bin/python3
"""wifi_activation.py

Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

Off-thread Wi-Fi activation for the Autostream Wi-Fi watcher: the worker half
of the activation engine.

Every effectful join (committed-profile reconnect, candidate-profile
activation, credential apply) runs off-thread so the monitor loop is never
blocked on a slow nmcli call.  This module owns both halves of the engine:
the worker half — the shared activation core (``_activate_profile_on`` /
``_validate_activation``), the job/result types, the single-slot job queue
and the worker thread body (``_run_activation_job`` / ``_activation_worker_loop``)
— and the loop-thread tail that applies a completed job's connectivity/session
effects (``apply_activation_result`` / ``client_up_tail``), drained and applied
at pass top by ``step_apply_activation_result``.

Every function takes an :class:`ActivationContext` as its first argument — a
narrow view of the watcher exposing only the STATE, constants and callables
the worker needs.  The watcher constructs the context once and passes it in.
``autostream_wifi_network`` is imported directly because it is a shared
module object (patching it affects both modules).
"""
from __future__ import annotations

import logging
import queue
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

import autostream_wifi_network as wifi_net
import wifi_policy
import wifi_recovery

PIN_IMPLICATE_SIGNAL = 50  # scan signal at/above which a failed pinned activation implicates the adapter


@dataclass
class ActivationContext:
    """Narrow view of the watcher that the activation engine depends on.

    Constructed once by the watcher and passed to every function here.  It
    carries the shared STATE object and its lock, the AdoptionState fragment
    (BSSID pin/table and roam-holdoff bookkeeping), the NM client singleton,
    the hotspot controller, the timeout constants, and the small set of
    watcher callables the worker and the loop-thread tail invoke — nothing
    else of the watcher is reachable from this module.
    """

    STATE: object
    APPLY_STATE: object
    ADOPTION_STATE: object
    state_lock: object
    RECOVERY_STATE: object
    RECOVERY_CTX: object
    nm: object
    hotspot_controller: object
    logger: logging.Logger
    HotspotPurpose: object
    Verdict: object
    WAIT_FOR_CONNECTION_TIMEOUT: float
    WAIT_FOR_CONNECTION_INTERVAL: float
    configure_wifi_with_nmcli: Callable
    stop_ap_mode: Callable
    get_configured_network_state: Callable
    is_wifi_client_healthy: Callable
    wait_for_connection: Callable
    _resolve_committed_uuid: Callable
    enter_setup_mode: Callable
    leave_setup_mode: Callable
    verify_avahi_after_handover: Callable
    clear_noip_failures: Callable
    clear_dead_adapter_state: Callable
    record_noip_failure: Callable
    clear_pending_adoption: Callable
    advance_reconnect_episode: Callable


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


def _pin_usb_bssid(ctx: ActivationContext, ifname: str, uuid: str, exclude: str = "") -> str:
    """Pin the best BSSID for a USB target before activation; "" leaves it unpinned.

    Non-USB targets, and USB targets whose scan fails or yields no selectable
    candidate, are explicitly unpinned (the scan must never become a new way
    for activation to fail).  Records the pin (or its absence) on
    ``ADOPTION_STATE.last_bssid_pin`` for the reset/retry gate.  ``exclude``
    skips a BSSID (the one a just-failed pinned attempt used) so a retry
    selects a different candidate.
    """
    if wifi_net.usb_sysfs_paths(ifname) is None:
        ctx.nm.set_bssid(uuid, "")
        with ctx.state_lock:
            ctx.ADOPTION_STATE.last_bssid_pin = {}
        return ""

    rows = ctx.nm.wifi_bssid_scan(ifname, rescan=True)
    ssid = wifi_net.get_connection_ssid(uuid) if rows is not None else ""
    ctx.logger.debug(wifi_policy.format_bssid_scan_debug(ifname, True, "pin", rows, ssid))
    bssid, signal = "", 0
    if rows is not None:
        now = time.monotonic()
        with ctx.state_lock:
            table = wifi_policy.bssid_table_for_interface(ctx.ADOPTION_STATE.bssid_tables, ifname)
            wifi_policy.update_bssid_table(table, rows, ssid, now)
            bssid = wifi_policy.select_bssid(table, now, exclude=exclude)
            if bssid:
                signal = table[bssid]["signal"]

    if not bssid:
        ctx.nm.set_bssid(uuid, "")
        with ctx.state_lock:
            ctx.ADOPTION_STATE.last_bssid_pin = {}
        return ""

    ctx.nm.set_bssid(uuid, bssid)
    with ctx.state_lock:
        ctx.ADOPTION_STATE.last_bssid_pin = {
            "ifname": ifname, "bssid": bssid, "signal": signal, "at": time.monotonic(),
        }
    return bssid


def _activate_profile_on(ctx: ActivationContext, ifname: str, state: "wifi_net.NetworkState",
                         *, wait_for_validation: bool = True, exclude_bssid: str = "") -> bool:
    """Shared activation core: resolve UUID, clear restrictions, pin, activate, validate.

    Clears cross-adapter NM restrictions (interface-name, MAC, band, channel)
    BEFORE activating so a legacy profile bound to one adapter can be moved to
    another.  A USB target additionally gets its BSSID pinned (or explicitly
    cleared) by ``_pin_usb_bssid`` (``exclude_bssid`` skips a just-failed
    candidate on a retry), with per-BSSID success/failure accounting after the
    activation verdict.  A "network could not be found" activation
    short-circuits the IPv4 wait (the join never started).  With
    ``wait_for_validation`` the interface must become a healthy, non-AP client
    to return True; without it the call is fire-and-forget and returns True as
    soon as the activation command succeeds (the monitor loop validates on a
    later pass).
    """
    if not state.is_configured:
        return False
    uuid = ctx._resolve_committed_uuid(state)
    if uuid:
        ctx.nm.clear_restrictions(uuid, wifi_net.CROSS_ADAPTER_RESTRICTIONS)
    pinned_bssid = _pin_usb_bssid(ctx, ifname, uuid, exclude=exclude_bssid) if uuid else ""
    r_up = ctx.nm.activate(uuid, state.connection_name, ifname)
    ok = _validate_activation(ctx, ifname, r_up, wait_for_validation=wait_for_validation)
    if pinned_bssid:
        with ctx.state_lock:
            table = wifi_policy.bssid_table_for_interface(ctx.ADOPTION_STATE.bssid_tables, ifname)
            if ok:
                wifi_policy.record_bssid_success(table, pinned_bssid, time.monotonic())
            else:
                wifi_policy.record_bssid_failure(table, pinned_bssid)
    return ok


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
    clears_pending_adoption: bool = False   # clear ADOPTION_STATE.pending_usb_adoption on done
    stable_id: "Optional[str]" = None
    wait_for_validation: bool = True
    # RESET_USB rung: one budgeted hardware reset + interface reappear before the
    # activation core runs (on the resolved, possibly-renamed ifname).
    reset_before: bool = False


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


def _pin_implicates_adapter(ctx: ActivationContext, ifname: str) -> bool:
    """True when the last BSSID pin on *ifname* saw a joinable AP.

    An absent/weak network never implicates the adapter — only a failed
    activation whose scan found a strong candidate does.
    """
    with ctx.state_lock:
        pin = dict(ctx.ADOPTION_STATE.last_bssid_pin)
    return (pin.get("ifname") == ifname and bool(pin.get("bssid"))
            and pin.get("signal", 0) >= PIN_IMPLICATE_SIGNAL)


def _reset_usb_and_wait_reappear(ctx: ActivationContext, target: "wifi_recovery.TargetAdapter") -> str:
    """Record one budgeted USB reset, rebind, and wait for the interface to
    reappear (possibly renamed).  Returns the resolved ifname, or "" if it
    never reappears.  Shared by the in-job implicated-failure retry and the
    reset-before-failover job prefix — each call site logs its own reason for
    triggering the reset.
    """
    wifi_recovery.record_adapter_reset(ctx.RECOVERY_CTX, target, time.monotonic())
    wifi_net.reset_usb_adapter_rebind(target.ifname)
    return wifi_recovery.wait_for_interface_reappears(ctx.RECOVERY_CTX, target)


def _retry_after_implicated_failure(ctx: ActivationContext, job: "ActivationJob"):
    """One budgeted USB reset + a single retry, excluding the failed BSSID.

    Returns ``(ok, ifname)`` for the retried attempt, or ``None`` when the
    retry does not apply (not implicated, or the reset budget is spent) — the
    caller keeps the original failed outcome in that case.
    """
    if not _pin_implicates_adapter(ctx, job.ifname):
        return None

    with ctx.state_lock:
        failed_bssid = ctx.ADOPTION_STATE.last_bssid_pin.get("bssid", "")

    adapters = wifi_net.discover_adapters()
    target = wifi_recovery.build_target_adapter(ctx.RECOVERY_CTX, job.ifname, adapters)
    if not target.resettable_usb:
        return None
    now = time.monotonic()
    if wifi_recovery.adapter_reset_budget_exhausted(ctx.RECOVERY_CTX, target, now):
        return None

    ctx.logger.info(
        "Pinned activation on %s failed with a joinable scan (implicated adapter); "
        "spending one budgeted USB reset and retrying", job.ifname)
    new_ifname = _reset_usb_and_wait_reappear(ctx, target)
    if not new_ifname:
        ctx.logger.warning("USB reset: %s did not reappear; retry failed", job.ifname)
        return (False, job.ifname)

    state = job.profile if job.profile is not None else ctx.get_configured_network_state()
    ok = _activate_profile_on(ctx, new_ifname, state,
                              wait_for_validation=job.wait_for_validation,
                              exclude_bssid=failed_bssid)
    return (ok, new_ifname)


def _run_activation_job(ctx: ActivationContext, job: "ActivationJob") -> "ActivationResult":
    """Worker half: the slow, bounded effects only (no connectivity/session tail).

    Optional AP drop for the attempt, the shared activation core, and — symmetric
    self-undo — rebuild the AP it dropped if this attempt then failed.  A
    ``reset_before`` job (the RESET_USB rung) spends its one budgeted reset first
    and runs the activation core on the resolved (possibly-renamed) interface; if
    the interface never reappears the job fails cleanly with no activation
    attempt.  A failed activate_committed/activate_profile on an implicated USB
    target otherwise gets exactly one budgeted reset + retry (see
    ``_retry_after_implicated_failure``) before the outcome is final — never
    stacked on top of a ``reset_before`` job's own reset (one reset per job,
    ever).  Takes ``state_lock`` only for the brief flag reads/writes, never
    across the blocking nmcli/wait calls.  Returns the outcome; the loop applies
    the tail.
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

    target_ifname = job.ifname
    already_reset = False
    if job.reset_before:
        already_reset = True
        adapters = wifi_net.discover_adapters()
        reset_target = wifi_recovery.build_target_adapter(ctx.RECOVERY_CTX, job.ifname, adapters)
        snapshot = wifi_recovery.adapter_reset_ledger_snapshot(
            ctx.RECOVERY_CTX, reset_target, time.monotonic())
        ctx.logger.info(
            "resetting active USB %s before onboard failover (reset %d of %d in window)",
            job.ifname, len(snapshot.get("recent_resets", [])) + 1,
            ctx.RECOVERY_CTX.USB_MAX_RESETS_PER_WINDOW,
        )
        target_ifname = _reset_usb_and_wait_reappear(ctx, reset_target)
        if not target_ifname:
            ctx.logger.warning(
                "USB reset before failover: %s did not reappear", job.ifname)
            return ActivationResult(job.epoch, False, job.ifname, job, error="reset_no_reappear")

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
        ok = _activate_committed_on(ctx, target_ifname)
    else:
        state = job.profile if job.profile is not None else ctx.get_configured_network_state()
        ok = _activate_profile_on(ctx, target_ifname, state, wait_for_validation=job.wait_for_validation)

    result_ifname = target_ifname
    if not ok and job.kind in ("activate_committed", "activate_profile") and not already_reset:
        retried = _retry_after_implicated_failure(ctx, job)
        if retried is not None:
            ok, result_ifname = retried

    # Worker self-undo: rebuild the AP it tore down so the portal stays up.  On
    # success the AP teardown (leave_setup_mode) is a loop-applied tail instead.
    if not ok and dropped_ap:
        ctx.hotspot_controller.rebuild()

    return ActivationResult(job.epoch, ok, result_ifname, job,
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


def _activate_committed_on(ctx: ActivationContext, ifname: str) -> bool:
    """Activate the configured committed profile on *ifname* and validate health.

    Thin wrapper over ``_activate_profile_on`` for the common case (the
    committed profile from network.json, blocking validation).  Kept as a named
    seam because several recovery sites and their tests reference it directly.
    """
    return _activate_profile_on(ctx, ifname, ctx.get_configured_network_state())


# ---- Loop-thread tail: apply a completed job's connectivity/session effects ----
#
# The worker never applies session/connectivity success tails; its only
# sanctioned session-state writes are the AP drop/rebuild flags around its own
# attempt.  apply_activation_result (and the client_up_tail choreography it
# calls on success) run on the loop thread only, once step_apply_activation_result
# drains the worker's result at pass top.


def _set_active_client(ctx: ActivationContext, adapter) -> None:
    with ctx.state_lock:
        if adapter is None and ctx.STATE.conn_unhealthy_checks > 0:
            # Soft debounce in progress (the single connectivity hysteresis
            # counter): clear ifname so the loop knows there is no
            # active client, but keep active_client_mac so the next pass can still
            # match the recorded USB adapter (NM-disconnected-but-present case).
            ctx.STATE.active_client_ifname = ""
            return
        changed = ctx.STATE.active_client_ifname != (adapter.ifname if adapter else "")
        ctx.STATE.active_client_ifname = adapter.ifname if adapter else ""
        ctx.STATE.active_client_mac = adapter.permanent_mac if adapter else ""
        # This adapter is now the healthy active client: end its no-IP hold-back
        # episode so a future hold-back may spend a fresh reset.
        if adapter is not None:
            sid = getattr(adapter, "stable_id", "")
            if sid:
                ctx.RECOVERY_STATE.noip_holdback_reset_done.discard(sid)
    if changed and adapter:
        ctx.logger.info("Active client adapter changed -> %s (%s)", adapter.ifname, adapter.kind)


def activation_success_tail(*, set_builtin_fallback=None, clear_noip_stable_id=None,
                            disconnect_builtin_ifname="", leave_setup_reason=None,
                            clear_down_timers=False, clear_pending_adoption=False) -> "wifi_recovery.TailSpec":
    """Tail for a client the activation worker just brought up successfully
    (bring-up, adoption, reconnect episode, or credential apply) — every job
    kind that runs through ``apply_activation_result`` funnels here.  Always
    resets the onboard-failure bound; never touches dead-PHY recovery state
    (that ladder has its own tail variants)."""
    return wifi_recovery.TailSpec(
        set_builtin_fallback=set_builtin_fallback,
        clear_noip_stable_id=clear_noip_stable_id,
        disconnect_builtin_ifname=disconnect_builtin_ifname,
        leave_setup_reason=leave_setup_reason,
        clear_down_timers=clear_down_timers,
        reset_onboard_bound=True,
        clear_pending_adoption=clear_pending_adoption,
    )


def client_up_tail(ctx: ActivationContext, adapter,
                   spec: "wifi_recovery.TailSpec" = wifi_recovery.TailSpec()) -> None:
    """The shared "a client came up" choreography (loop thread only).

    One place applies the standardised handover effects; each caller passes a
    :class:`wifi_recovery.TailSpec` describing only the deltas it needs and
    does its own adapter discovery/logging first.  The individual effects
    touch disjoint STATE/ADOPTION_STATE fields (or independent nmcli/ledger
    calls), so their order is not load-bearing.

    ``adapter`` is the resolved client adapter to record active (None = skip).

    Every call here is a successful client activation, so this is also the
    other half of the BSSID roam holdoff (the roam submission stamps the same
    field): it stops the survey step from roaming again right after we just
    fought to get connected.
    """
    if adapter is not None:
        _set_active_client(ctx, adapter)
    if spec.disconnect_builtin_ifname:
        ctx.logger.info("Disconnecting built-in client on %s", spec.disconnect_builtin_ifname)
        ctx.nm.disconnect_device(spec.disconnect_builtin_ifname)
    if spec.clear_noip_stable_id:
        ctx.clear_noip_failures(spec.clear_noip_stable_id)
    with ctx.state_lock:
        ctx.ADOPTION_STATE.last_roam_or_activation = time.monotonic()
        if spec.set_builtin_fallback is not None:
            ctx.ADOPTION_STATE.using_builtin_fallback = spec.set_builtin_fallback
        if spec.clear_down_timers:
            ctx.STATE.conn_down_start = None
            ctx.STATE.last_reconnect_attempt = None
        if spec.reset_onboard_bound:
            ctx.STATE.onboard_activation_failures = 0
    if spec.clear_pending_adoption:
        ctx.clear_pending_adoption()
    if spec.clear_dead_adapter:
        ctx.clear_dead_adapter_state()
        # The dead-PHY recovery episode this adapter was tracked under is over
        # (recovered or handed to another radio): clear the RESET_USB spend so
        # a fresh wedge gets its one budgeted reset again.
        with ctx.state_lock:
            ctx.RECOVERY_STATE.failover_reset_done.clear()
    if spec.leave_setup_reason is not None:
        ctx.leave_setup_mode(spec.leave_setup_reason)
    ctx.verify_avahi_after_handover()


def apply_activation_result(ctx: ActivationContext, result: "ActivationResult",
                            adapter: "Optional[object]" = None) -> bool:
    """Loop half: apply the success/failure connectivity tail (loop thread only).

    The loop re-resolves the adapter by ``result.ifname`` from a fresh discover
    (the worker result carries only the ifname); ``adapter`` optionally supplies an
    already-resolved object.
    """
    job = result.job

    if job.kind == "apply_credentials":
        # The wait-page status tail (applying -> ok/failed), clearing
        # apply_in_progress and, on failure, returning to setup mode.
        if not result.ok:
            with ctx.state_lock:
                ctx.APPLY_STATE.last_apply_result = "failed"
                ctx.APPLY_STATE.last_apply_error = "nmcli-failed"
                ctx.APPLY_STATE.apply_in_progress = False
                # Re-enter with whatever purpose the interrupted session held
                # (configure_wifi_with_nmcli keeps setup_mode set on failure, so
                # this is normally a no-op); fall back to FIRST_RUN.
                purpose = ctx.STATE.hotspot.purpose if ctx.STATE.hotspot else ctx.HotspotPurpose.FIRST_RUN
            ctx.logger.warning("WiFi configuration failed; returning to SetupMode")
            ctx.enter_setup_mode(purpose, reason="nmcli failed to configure WiFi")
            return False
        with ctx.state_lock:
            ctx.APPLY_STATE.last_apply_result = "ok"
            ctx.APPLY_STATE.last_apply_error = ""
            ctx.APPLY_STATE.apply_in_progress = False
        ctx.logger.info("WiFi configuration and connectivity verified")
        # Fall through to the shared success tail below (set active client by
        # result.ifname, leave setup, verify avahi) — the same tail the other job
        # kinds use — so the credential apply's session tail runs on the loop
        # thread rather than on the worker.

    if result.ok and not job.wait_for_validation:
        # Fire-and-forget: activation issued, loop validates on a later pass.
        return True

    if result.ok:
        resolved = adapter
        if resolved is None:
            resolved = wifi_net.find_adapter_by_ifname(
                wifi_net.discover_adapters(), result.ifname)
        # Disconnect a previously-active client whose ifname the job carries (the
        # runtime-adoption transactional handover: the USB validated by the worker
        # replaces the healthy built-in only now, on the success tail).
        disconnect_ifname = job.disconnects_previous_ifname
        if disconnect_ifname == result.ifname:
            disconnect_ifname = ""
        clear_id = job.stable_id if job.stable_id is not None else (
            resolved.stable_id if resolved is not None else "")
        # A client came up: apply the shared handover tail (set active, optional
        # previous-client disconnect, clear the no-IP ledger, fallback/timer flags,
        # reset the onboard-failure bound, leave setup, clear pending adoption,
        # verify avahi).
        client_up_tail(ctx, resolved, activation_success_tail(
            set_builtin_fallback=job.sets_builtin_fallback,
            clear_noip_stable_id=(clear_id or None),
            disconnect_builtin_ifname=disconnect_ifname,
            leave_setup_reason=(job.leave_reason if job.on_success_leaves_setup else None),
            clear_down_timers=job.clears_down_timers,
            clear_pending_adoption=job.clears_pending_adoption,
        ))
        return True

    # Failure tail (the worker already rebuilt any AP it dropped).
    if job.clears_pending_adoption:
        ctx.clear_pending_adoption()
    if job.records_onboard_failure:
        # Count this onboard failure toward the recovery-hotspot bound so a
        # present-but-failing onboard eventually yields to the hotspot.
        with ctx.state_lock:
            ctx.STATE.onboard_activation_failures += 1
    if job.records_noip:
        record_id = job.stable_id
        if record_id is None:
            record_id = adapter.stable_id if adapter is not None else None
        if record_id is None:
            found = wifi_net.find_adapter_by_ifname(wifi_net.discover_adapters(), result.ifname)
            record_id = found.stable_id if found is not None else result.ifname
        ctx.record_noip_failure(
            record_id, job.noip_at if job.noip_at is not None else time.monotonic())
    return False


def step_apply_activation_result(ctx: ActivationContext, pre: "PreFactsContext") -> "Verdict":
    """Phase A: drain a completed worker result at pass top, apply its tail, and
    clear the transitioning gate.

    A result whose epoch is not the in-flight one is discarded (defensive — the
    single-slot gate makes it unreachable in normal operation) but still clears the
    gate so the loop can never wedge.  Never owns the pass.
    """
    result = drain_activation_result()
    if result is None:
        return ctx.Verdict.CONTINUE
    inflight_epoch = get_inflight_activation_epoch()
    stale = result.epoch != inflight_epoch
    try:
        if stale:
            ctx.logger.warning("activation result epoch %s != in-flight %s; discarding",
                               result.epoch, inflight_epoch)
        else:
            apply_activation_result(ctx, result)
            # Advance any reconnect-saved episode this job belonged to (success
            # ends it; failure moves to the next target on a later pass).
            ctx.advance_reconnect_episode(result)
    finally:
        clear_inflight_activation_epoch()
        with ctx.state_lock:
            ctx.STATE.transitioning = False
    return ctx.Verdict.CONTINUE
