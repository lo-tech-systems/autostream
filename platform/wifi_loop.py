#!/usr/bin/python3
"""wifi_loop.py

Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

The ordered monitor-loop handlers for the Autostream Wi-Fi watcher.

The loop itself (``network_monitor_loop``) stays in the hub as the supervisor
skeleton; this module owns the ordered per-pass handlers it drives (the
``step_*`` ``Verdict`` functions), the per-pass context types
(``PreFactsContext`` / ``FactsContext`` / ``HealthContext`` / ``LoopState``),
and the fact/health derivation (``finalize_active_client_and_health``,
``_debounced_connectivity``, ``_connectivity_failure_is_hard``) that bridges
Phase B-early and Phase B-late.

Every handler takes a :class:`LoopContext` as its first argument — a narrow
view of the watcher exposing only the STATE, constants and callables these
handlers use — followed by the per-pass
phase context (``pre`` / ``fctx`` / ``hctx``) that ``run_steps`` threads
through unchanged.  The watcher builds one ``LOOP_CTX`` and binds each handler
to it with ``functools.partial`` when building the ordered phase lists, so
``run_steps`` keeps a single uniform ``step(phase_ctx) -> Verdict`` calling
convention.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, Optional

import autostream_wifi_network as wifi_net


@dataclass
class LoopContext:
    """Narrow view of the watcher that the monitor-loop handlers depend on.

    Constructed once by the watcher and passed (via ``functools.partial``) to
    every handler here.  It carries the shared STATE object and its lock, the
    loop-timing constants, and the small set of watcher callables the handlers
    invoke — nothing else of the watcher is reachable from this module.
    """

    STATE: object
    APPLY_STATE: object
    CONTROL_STATE: object
    RECOVERY_STATE: object
    state_lock: object
    logger: logging.Logger
    Verdict: object
    HotspotPurpose: object
    _NON_DISRUPTIVE_ACTIONS: set
    control_action_event: object
    nm: object
    # Constants
    AVAHI_CHECK_INTERVAL: float
    AP_MAX_DURATION: float
    BOOT_AP_GRACE: float
    BOOT_AP_CUTOFF: float
    GW_DOWN_REBOOT_AFTER: float
    GW_DOWN_RECONNECT_AFTER: float
    RECONNECT_ATTEMPT_INTERVAL: float
    NO_ACTIVE_PATH_REBOOT_AFTER: float
    CONNECTIVITY_DOWN_DEBOUNCE: int
    HANDOVER_SETTLE_SECONDS: float
    AP_IFNAME: str
    # Callables
    check_and_repair_avahi_hostname: Callable
    maybe_reannounce_mdns: Callable
    revert_expired_log_level: Callable
    process_control_action: Callable
    handle_reconfigure_timeout: Callable
    log_on_change: Callable
    update_known_adapters: Callable
    gather_recovery_facts: Callable
    submit_client_activation: Callable
    handle_usb_failure_fallback: Callable
    handle_runtime_usb_adoption: Callable
    bssid_survey_and_roam: Callable
    maybe_reset_noip_held_usb: Callable
    escalate_dead_adapter_recovery: Callable
    publish_network_status: Callable
    hotspot_blocks_eth: Callable
    leave_setup_mode: Callable
    enter_setup_mode: Callable
    set_active_client: Callable
    connect_to_configured_wifi: Callable
    request_network_down_reboot: Callable
    attempt_recovery_reconnect: Callable
    next_mode: Callable
    next_recovery_action: Callable
    RecoveryKind: object
    PURPOSE_TABLE: dict


@dataclass(frozen=True)
class PreFactsContext:
    """Phase A context (event/timer), before gather_facts().

    ``avahi_ok`` (``not setup_mode and not apply_in_progress``) is read in the same
    top-of-pass state_lock block as ``boot_time`` so the avahi/mDNS handlers gate on
    it without re-reading STATE (which would change the lock/read timing).
    """
    now: float
    boot_time: float
    avahi_ok: bool


@dataclass(frozen=True)
class FactsContext:
    """Phase B-early context: PreFactsContext + the per-pass Facts and playback memo.

    Carries no health fields, so a handler that must run before
    _set_active_client() (step_usb_failure_fallback) structurally cannot read them.
    """
    pre: PreFactsContext
    facts: "Facts"
    playing: object            # per-pass memoised playback resolver (callable)

    @property
    def now(self) -> float: return self.pre.now
    @property
    def boot_time(self) -> float: return self.pre.boot_time
    @property
    def avahi_ok(self) -> bool: return self.pre.avahi_ok


@dataclass(frozen=True)
class HealthContext:
    """Phase B-late context: FactsContext + the health fields.

    Produced by finalize_active_client_and_health().  ``prev_active_mac`` /
    ``prev_active_ifname`` carry the active-client identity recorded *before* this
    pass's _set_active_client, so the Phase B-late USB-failure handler can still
    attribute a just-vanished adapter.
    """
    fctx: FactsContext
    health_ifname: str
    wifi_connected: bool
    client_ok: bool
    conn_ok: bool
    active_path_ok: bool
    prev_active_mac: str = ""
    prev_active_ifname: str = ""

    @property
    def now(self) -> float: return self.fctx.now
    @property
    def boot_time(self) -> float: return self.fctx.boot_time
    @property
    def avahi_ok(self) -> bool: return self.fctx.avahi_ok
    @property
    def facts(self) -> "Facts": return self.fctx.facts
    @property
    def playing(self) -> object: return self.fctx.playing


@dataclass
class LoopState:
    """Driver-owned state that persists across passes (not per-pass context).

    Home for cross-pass loop-locals so handlers never smuggle persistent state
    through a per-pass context.  Currently just the avahi hostname-check rate limit.
    """
    last_avahi_check: float = 0.0


def finalize_active_client_and_health(ctx: LoopContext, fctx: "FactsContext") -> "HealthContext":
    """Named phase boundary (not a Verdict handler): set the active client and
    compute the five health fields, returning the HealthContext for Phase B-late.

    Wraps _set_active_client() plus the health computation; it may mutate
    STATE.active_client_* but never owns the pass.
    """
    facts = fctx.facts
    active_client = facts.active_client
    wifi_cfg = facts.wifi_configured

    # Capture the identity recorded *before* this pass's _set_active_client so the
    # Phase B-late USB-failure handler can attribute a just-vanished adapter, and
    # so the soft-fail hysteresis can recognise an NM-disconnected-but-present USB.
    with ctx.state_lock:
        prev_active_mac = ctx.STATE.active_client_mac
        prev_active_ifname = ctx.STATE.active_client_ifname

    # Health is scoped to the *active client* adapter; fall back to the built-in
    # interface name for an unconfigured/idle device.
    health_ifname = active_client.ifname if active_client else ctx.AP_IFNAME
    wifi_connected = wifi_net.is_wifi_connected(health_ifname) if wifi_cfg else False
    client_ok = (
        facts.health_memo(health_ifname, wifi_connected=wifi_connected)
        if wifi_cfg
        else False
    )
    # Apply source-level hysteresis: one stable connectivity verdict that
    # every downstream consumer (next_mode, boot-entry, reconnect, the USB-failure
    # overlay) reads, so a single soft blip on the active path no longer flips
    # Mode or triggers a failover.  active_path_ok tracks the same debounced
    # verdict.  Computed before _set_active_client so the incremented debounce
    # counter is visible to _set_active_client's MAC-preservation.
    conn_ok = _debounced_connectivity(ctx, facts, active_client, client_ok, prev_active_mac)
    active_path_ok = conn_ok
    ctx.set_active_client(active_client)
    return HealthContext(
        fctx, health_ifname=health_ifname, wifi_connected=wifi_connected,
        client_ok=client_ok, conn_ok=conn_ok, active_path_ok=active_path_ok,
        prev_active_mac=prev_active_mac, prev_active_ifname=prev_active_ifname,
    )


def _connectivity_failure_is_hard(ctx: LoopContext, facts: "Facts", active_client, prev_mac: str) -> bool:
    """True when this pass's connectivity failure is a HARD signal (no debounce).

    Hard: nothing configured; the active client reports NO-CARRIER (link down); or
    there is no client this pass and no recorded USB left to reconnect to.  Soft
    (debounced): the client is connected with carrier up but gateway/IPv4 is not
    ready (the transient-prone case), OR there is no active client this pass but
    the recorded USB is still physically present (NM merely disconnected it, may
    reassociate) — softening the NM-disconnected case gives it the same 2-pass
    debounce.

    Within HANDOVER_SETTLE_SECONDS of the last active-client identity change, a
    HARD signal is demoted to soft (returns False here) instead of condemning on
    a single pass: races settling right after a handover still condemn, but only
    after the normal debounce.  No grace when no identity change has ever been
    recorded (STATE.active_client_changed_at is None).
    """
    if not facts.wifi_configured:
        return True
    if active_client is not None:
        hard = wifi_net.read_link_down(active_client.ifname) is True
    else:
        # No active client: soft only if the recorded USB is still present (a
        # disconnect that may recover); otherwise the path is genuinely down.
        recorded_usb_present = bool(prev_mac) and any(
            a.is_usb and a.permanent_mac == prev_mac for a in facts.adapters
        )
        hard = not recorded_usb_present
    if not hard:
        return False
    with ctx.state_lock:
        changed_at = ctx.STATE.active_client_changed_at
    if changed_at is not None and (facts.taken_at - changed_at) < ctx.HANDOVER_SETTLE_SECONDS:
        return False
    return True


def _debounced_connectivity(ctx: LoopContext, facts: "Facts", active_client, client_ok: bool,
                            prev_mac: str = "") -> bool:
    """Stable connectivity_ok with soft-fail hysteresis.

    Healthy (wired or client) -> True immediately and the counter resets.  A hard
    unhealthy signal condemns the path at once.  A soft unhealthy signal only
    condemns after CONNECTIVITY_DOWN_DEBOUNCE consecutive passes; until then the
    prior verdict is held (slow to condemn, quick to forgive).  ``prev_mac`` is the
    pre-_set_active_client recorded MAC, used to keep an NM-disconnected-but-
    present USB in the soft (debounced) class.
    """
    if facts.wired_ok or client_ok:
        with ctx.state_lock:
            ctx.STATE.conn_unhealthy_checks = 0
        return True
    if _connectivity_failure_is_hard(ctx, facts, active_client, prev_mac):
        with ctx.state_lock:
            ctx.STATE.conn_unhealthy_checks = 0
        return False
    with ctx.state_lock:
        ctx.STATE.conn_unhealthy_checks += 1
        condemned = ctx.STATE.conn_unhealthy_checks >= ctx.CONNECTIVITY_DOWN_DEBOUNCE
        prior = ctx.STATE.connectivity_ok
    return False if condemned else prior


# ---- Phase A handlers (event/timer, PreFactsContext, before gather_facts) ----


def step_avahi_hostname(ctx: LoopContext, pre: "PreFactsContext", loop_state: "LoopState") -> "Verdict":
    """Avahi mDNS hostname check (rate-limited; skipped during setup/apply)."""
    if pre.avahi_ok and (pre.now - loop_state.last_avahi_check) >= ctx.AVAHI_CHECK_INTERVAL:
        loop_state.last_avahi_check = pre.now
        ctx.check_and_repair_avahi_hostname()
    return ctx.Verdict.CONTINUE


def step_mdns_reannounce(ctx: LoopContext, pre: "PreFactsContext") -> "Verdict":
    """Debounced mDNS host-record re-announce (skipped during setup/apply)."""
    if pre.avahi_ok:
        ctx.maybe_reannounce_mdns(pre.now)
    return ctx.Verdict.CONTINUE


def step_revert_log_level(ctx: LoopContext, pre: "PreFactsContext") -> "Verdict":
    """Revert a temporary runtime log level once its TTL expires."""
    ctx.revert_expired_log_level(pre.now)
    return ctx.Verdict.CONTINUE


def step_control_action(ctx: LoopContext, pre: "PreFactsContext") -> "Verdict":
    """Consume a queued local-control action (peek-then-consume).

    Disruptive actions own the pass; the non-disruptive set_log_level is applied
    and the pass continues normally.  While a worker activation is in flight
    (STATE.transitioning) OR a reconnect-saved episode is still running
    (STATE.reconnect_episode), a *disruptive* action (start_setup /
    reconnect_saved) is peeked but NOT consumed — it is left queued and applied on
    the first pass after the transition/episode completes, so it is deferred,
    never dropped.  A non-disruptive set_log_level is always consumed and applied
    immediately (it touches no connectivity/AP state).
    """
    if not ctx.control_action_event.is_set():
        return ctx.Verdict.CONTINUE
    with ctx.state_lock:
        action = ctx.CONTROL_STATE.pending_control_action
        params = dict(ctx.CONTROL_STATE.pending_control_params)
        # Non-disruptive actions touch no connectivity/AP state, so they are never
        # deferred and never own the pass: log-level and the manual adapter
        # enable/disable/clear-fault actions.
        disruptive = bool(action) and action not in ctx._NON_DISRUPTIVE_ACTIONS
        defer = disruptive and (ctx.STATE.transitioning or ctx.STATE.reconnect_episode is not None)
        if not defer:
            ctx.CONTROL_STATE.pending_control_action = ""
            ctx.CONTROL_STATE.pending_control_params = {}
            ctx.control_action_event.clear()
    if defer:
        # Leave the disruptive action queued (event stays set) for a later pass.
        return ctx.Verdict.CONTINUE
    if action:
        ctx.process_control_action(action, params)
        if disruptive:
            return ctx.Verdict.OWN_PASS
    return ctx.Verdict.CONTINUE


def step_reconfigure_timeout(ctx: LoopContext, pre: "PreFactsContext") -> "Verdict":
    """Enforce the explicit-reconfiguration 30-minute timeout.

    Starts the rollback episode once; while that episode is still running the
    guard below keeps it from being restarted every pass.
    """
    with ctx.state_lock:
        session = ctx.STATE.hotspot
        episode_active = ctx.STATE.reconnect_episode is not None
    if (session is not None
            and not episode_active
            and session.purpose == ctx.HotspotPurpose.EXPLICIT_RECONFIGURE
            and (pre.now - session.entered_at) >= ctx.AP_MAX_DURATION):
        ctx.handle_reconfigure_timeout()
        return ctx.Verdict.OWN_PASS
    return ctx.Verdict.CONTINUE


# ---- Phase B-early handlers (facts only, FactsContext, before health) ----


def step_update_known_adapters(ctx: LoopContext, fctx: "FactsContext") -> "Verdict":
    """Track USB MACs and log adapter-set changes (multi-adapter discovery)."""
    ctx.update_known_adapters(fctx.facts.adapters)
    return ctx.Verdict.CONTINUE


def step_boot_client_bringup(ctx: LoopContext, fctx: "FactsContext") -> "Verdict":
    """BOOT-window client bring-up via the recovery ladder.

    While BOOT_AP_GRACE is open and the device is offline, run the single recovery
    ladder each pass to bring up a client (preferred USB first, else onboard).
    The ladder ranks the same USB-before-onboard priority, so a
    USB adapter that finishes enumerating after boot is engaged on the pass it
    appears; a healthy client makes the ladder HOLD (no thrash).  A wedged
    resettable USB gets its one budgeted reset (RESET_USB) before onboard is
    tried, same as at runtime.  Only ACTIVATE_*/RESET_USB act here — hotspot
    entry stays with step_boot_ap_entry after the grace window.
    """
    facts = fctx.facts
    boot_age_now = fctx.now - fctx.boot_time
    with ctx.state_lock:
        transitioning = ctx.STATE.transitioning
        in_setup = ctx.STATE.setup_mode
    if not (boot_age_now < ctx.BOOT_AP_GRACE
            and facts.wifi_configured
            and not facts.wired_ok
            and not in_setup
            and not transitioning):        # hold off while a job is in flight
        return ctx.Verdict.CONTINUE
    raction = ctx.next_recovery_action(ctx.STATE, ctx.gather_recovery_facts(facts))
    if raction.kind in (ctx.RecoveryKind.ACTIVATE_USB, ctx.RecoveryKind.RESET_USB,
                        ctx.RecoveryKind.ACTIVATE_ONBOARD) \
            and ctx.submit_client_activation(raction, facts):
        return ctx.Verdict.OWN_PASS
    return ctx.Verdict.CONTINUE


def step_usb_failure_fallback(ctx: LoopContext, hctx: "HealthContext") -> "Verdict":
    """Active-USB failure fallback — over the debounced verdict, never playback-gated.

    Runs at the front of Phase B-late so it can read the finalized connectivity
    hysteresis verdict (hctx.conn_ok); the overlay keeps no debounce of its own.
    The pre-_set_active_client identity it needs
    to attribute a vanished adapter is carried on the HealthContext
    (prev_active_mac / prev_active_ifname).
    """
    facts = hctx.facts
    with ctx.state_lock:
        transitioning = ctx.STATE.transitioning
        in_setup = ctx.STATE.setup_mode
    # Defer the failure fallback while an activation is in flight.
    if transitioning:
        return ctx.Verdict.CONTINUE
    if facts.wifi_configured and not facts.wired_ok and not in_setup:
        if ctx.handle_usb_failure_fallback(hctx):
            return ctx.Verdict.OWN_PASS
    return ctx.Verdict.CONTINUE


# ---- Phase B-late handlers (health/state, HealthContext) ----


def step_runtime_usb_adoption(ctx: LoopContext, hctx: "HealthContext") -> "Verdict":
    """Optional idle-time adoption of a newly available USB adapter.

    This transactional idle-time optimisation stays synchronous (it validates the
    USB before dropping the healthy built-in), but is deferred while an activation
    is in flight so it never overlaps a worker transition.
    """
    facts = hctx.facts
    with ctx.state_lock:
        transitioning = ctx.STATE.transitioning
        in_setup = ctx.STATE.setup_mode
    if transitioning:
        return ctx.Verdict.CONTINUE
    if facts.wifi_configured and hctx.conn_ok and not in_setup:
        if ctx.handle_runtime_usb_adoption(facts.adapters, facts.wired_ok, playing_fn=hctx.playing):
            return ctx.Verdict.OWN_PASS
    return ctx.Verdict.CONTINUE


def step_noip_holdback_reset(ctx: LoopContext, hctx: "HealthContext") -> "Verdict":
    """Spend one budgeted USB reset on an idle no-IP-held spare before its
    hold-back is final.

    Gated on a healthy device (conn_ok) so only idle spares — never the active
    path — are reset here, and deferred while an activation is in flight (the
    reset is a synchronous blocking effect, like the dead-PHY reset).
    """
    facts = hctx.facts
    with ctx.state_lock:
        transitioning = ctx.STATE.transitioning
        in_setup = ctx.STATE.setup_mode
    if transitioning:
        return ctx.Verdict.CONTINUE
    if facts.wifi_configured and hctx.conn_ok and not in_setup:
        if ctx.maybe_reset_noip_held_usb(facts.adapters, facts.taken_at):
            return ctx.Verdict.OWN_PASS
    return ctx.Verdict.CONTINUE


def step_dead_phy_recovery(ctx: LoopContext, hctx: "HealthContext") -> "Verdict":
    """Detect a wedged-but-present client adapter and run the reset ladder.

    Runs before the ethernet-wins short-circuit so a genuinely dead Wi-Fi PHY is
    reset even while ethernet is attached.  But when wired Ethernet wins and the
    Wi-Fi client has already been dropped (wired-wins), the idle radio is
    administratively down by design — leave it down rather than spending reset
    budget on it.
    """
    facts = hctx.facts
    with ctx.state_lock:
        transitioning = ctx.STATE.transitioning
    # The dead-PHY reset is a second blocking effect; defer it while an activation
    # is in flight so at most one effectful transition runs.
    if transitioning:
        return ctx.Verdict.CONTINUE
    if facts.wifi_configured and not (facts.wired_ok and facts.active_client is None):
        if ctx.escalate_dead_adapter_recovery(facts.adapters, facts.wired_ok):
            return ctx.Verdict.OWN_PASS
    return ctx.Verdict.CONTINUE


def step_publish_state(ctx: LoopContext, hctx: "HealthContext") -> "Verdict":
    """Apply the pure mode classifier, log on change, and publish the snapshot."""
    facts = hctx.facts
    with ctx.state_lock:
        ctx.STATE.wifistate = "configured" if facts.wifi_configured else "unconfigured"
        ctx.STATE.wiredstate = "connected" if facts.wired_connected else "disconnected"
        ctx.STATE.connectivity_ok = hctx.conn_ok
        if hctx.conn_ok:
            ctx.STATE.been_online_this_boot = True
            # A healthy pass ends the offline episode: reset the onboard-failure
            # bound so a later failure gets a fresh set of attempts, and clear
            # the RESET_USB per-episode spend so a later wedge gets its one
            # budgeted reset again.
            ctx.STATE.onboard_activation_failures = 0
            ctx.RECOVERY_STATE.failover_reset_done.clear()
        if hctx.active_path_ok and not ctx.STATE.setup_mode:
            ctx.STATE.last_active_path_seen = hctx.now
            ctx.STATE.conn_reboot_retry_after = 0.0
        # setup_mode migration canary: setup_mode must equal (hotspot is not None)
        # now that every write goes through enter/leave/controller.  Log (not
        # crash the supervisor) on any mismatch for one release before setup_mode
        # is converted to a read-only property derived from hotspot.
        if ctx.STATE.setup_mode != (ctx.STATE.hotspot is not None):
            ctx.log_on_change(
                "setup_mode_hotspot_mismatch", True,
                f"setup_mode/hotspot invariant broken: setup_mode={ctx.STATE.setup_mode}, "
                f"hotspot={'set' if ctx.STATE.hotspot else 'None'}",
                logging.WARNING)
        else:
            ctx.log_on_change("setup_mode_hotspot_mismatch", False, "")
        # Apply the pure forward classifier: STATE.mode is authoritative.
        ctx.STATE.mode = ctx.next_mode(ctx.STATE, facts)
        ctx.log_on_change("device_mode", ctx.STATE.mode, f"Mode changed -> {ctx.STATE.mode.value}")
        ctx.log_on_change("wifistate", ctx.STATE.wifistate, f"WiFi state changed -> {ctx.STATE.wifistate}")
        ctx.log_on_change("wiredstate", ctx.STATE.wiredstate, f"Wired state changed -> {ctx.STATE.wiredstate}")
        ctx.log_on_change("gateway_reachable", ctx.STATE.connectivity_ok,
                          f"Connectivity changed -> {ctx.STATE.connectivity_ok}")

    # Publish the runtime status snapshot served by /network_status.  Pass the
    # per-tick addresses so the status builder does not re-enumerate.
    ctx.publish_network_status(facts.adapters, facts.wired_connected, facts.wired_ok,
                               facts.addresses, facts.health_memo)
    return ctx.Verdict.CONTINUE


def step_bssid_survey(ctx: LoopContext, hctx: "HealthContext") -> "Verdict":
    """Periodic USB BSSID survey and gated roam (USB client adapters only).

    Skips entirely outside the narrow window where a survey is meaningful:
    setup mode and an in-flight activation both defer to their own ladders, and
    an onboard or unhealthy active client is out of scope (the recovery ladder
    owns an unhealthy client, never this survey).
    """
    facts = hctx.facts
    active = facts.active_client
    with ctx.state_lock:
        in_setup = ctx.STATE.setup_mode
        transitioning = ctx.STATE.transitioning
    if in_setup or transitioning:
        return ctx.Verdict.CONTINUE
    if active is None or not active.is_usb or not hctx.client_ok:
        return ctx.Verdict.CONTINUE
    if ctx.bssid_survey_and_roam(hctx):
        return ctx.Verdict.OWN_PASS
    return ctx.Verdict.CONTINUE


def step_ethernet_wins(ctx: LoopContext, hctx: "HealthContext") -> "Verdict":
    """Usable wired Ethernet wins regardless of subnet.

    Owns the pass whenever the ``ethernet_wins`` predicate holds — independent of
    whether it actually leaves AP mode or disconnects Wi-Fi (matching the current
    short-circuit).  The single disconnect gate is playback.  When ethernet is
    usable but held off by a user-initiated hotspot, the conn timers are cleared
    and the pass continues.
    """
    facts = hctx.facts
    with ctx.state_lock:
        # Ethernet suppresses an automatic-purpose hotspot, but a user-initiated
        # one (MANUAL / EXPLICIT_RECONFIGURE) is left up.
        ethernet_wins = facts.wired_ok and not ctx.hotspot_blocks_eth(ctx.STATE.hotspot)
        in_ap_for_eth = ctx.STATE.setup_mode
        transitioning = ctx.STATE.transitioning
        if ethernet_wins:
            ctx.STATE.conn_down_start = None
            ctx.STATE.last_reconnect_attempt = None

    if ethernet_wins and transitioning:
        # Ethernet is observed (timers cleared above, snapshot
        # already published) but its *enforcement* — the AP leave / Wi-Fi client
        # drop — is deferred until the in-flight transition completes, so at most
        # one effectful transition is ever in flight.  Fires on the next pass.
        ctx.log_on_change("eth_wins_deferred", True,
                          "Usable wired Ethernet present but an activation is in flight; "
                          "deferring the Wi-Fi client drop until it completes")
        return ctx.Verdict.OWN_PASS

    if ethernet_wins:
        # leave_setup_mode is called outside the lock (it re-acquires state_lock,
        # which is not re-entrant).
        if in_ap_for_eth:
            ctx.leave_setup_mode("Wired ethernet is up; suppressing AP mode")
        with ctx.state_lock:
            active_wifi_ifname = ctx.STATE.active_client_ifname
            skip_disconnect = (
                ctx.APPLY_STATE.apply_in_progress or ctx.STATE.setup_mode or in_ap_for_eth
            )
        # Drop the redundant Wi-Fi client so there is one deterministic path and
        # one mDNS address.  Deferred while streaming or while playback is
        # uncertain (switching the active interface would break an in-flight
        # AirPlay/OwnTone stream).
        if active_wifi_ifname and not skip_disconnect:
            if hctx.playing() is False:
                ctx.logger.info(
                    "Usable wired Ethernet present; disconnecting idle WiFi client %s",
                    active_wifi_ifname,
                )
                ctx.nm.disconnect_device(active_wifi_ifname)
                ctx.set_active_client(None)
        return ctx.Verdict.OWN_PASS

    with ctx.state_lock:
        if facts.wired_ok and ctx.hotspot_blocks_eth(ctx.STATE.hotspot):
            # A user-initiated hotspot (MANUAL / EXPLICIT) is held up even though
            # ethernet is usable; do not let conn timers fire.
            ctx.STATE.conn_down_start = None
            ctx.STATE.last_reconnect_attempt = None
    return ctx.Verdict.CONTINUE


def step_hotspot_policy(ctx: LoopContext, hctx: "HealthContext") -> "Verdict":
    """Enforce the active hotspot's purpose-driven policy from PURPOSE_TABLE.

    While an activation is in flight the deadline is still
    *observed* (measured, published) but its *enforcement* (the probe that could
    start a rejoin, and the deadline leave_setup_mode) is deferred to the pass
    after the job completes, so at most one effectful transition is in flight.
    """
    facts = hctx.facts
    with ctx.state_lock:
        in_setup = ctx.STATE.setup_mode
        session = ctx.STATE.hotspot
        transitioning = ctx.STATE.transitioning

    if in_setup and session is not None:
        policy = ctx.PURPOSE_TABLE[session.purpose]
        ap_age = hctx.now - session.entered_at
        deadline_expired = policy.deadline_s is not None and ap_age >= policy.deadline_s
        if transitioning:
            # Observe only: a deferred deadline is logged so the operator still
            # sees it; the leave/probe fire once the in-flight transition ends.
            if deadline_expired:
                ctx.log_on_change("hotspot_deadline_deferred", session.purpose,
                                  f"Hotspot deadline reached ({session.purpose.value}) but an "
                                  f"activation is in flight; enforcing after it completes")
            return ctx.Verdict.OWN_PASS
        # Recovery purposes probe for the saved network's return; user-initiated
        # hotspots wait policy.probe_grace_s after entry before probing so the
        # watcher does not rejoin the network the user opened the portal to change.
        if policy.probes_return and facts.wifi_configured and ap_age >= policy.probe_grace_s:
            ctx.attempt_recovery_reconnect(facts)
        # FIRST_RUN (deadline None) stays up indefinitely; every other purpose
        # closes after its deadline.
        if deadline_expired:
            ctx.leave_setup_mode(
                f"Hotspot lifetime expired after {ap_age:.0f}s ({session.purpose.value})")
        return ctx.Verdict.OWN_PASS
    return ctx.Verdict.CONTINUE


def step_boot_ap_entry(ctx: LoopContext, hctx: "HealthContext") -> "Verdict":
    """Enter a recovery hotspot during the boot window — client path tried first.

    No once-per-boot budget; the boot window only gates this initial auto-entry so
    NM/firmware get a chance to come up first.  Before committing a radio to a
    hotspot, the recovery ladder tries the highest-priority client path (preferred
    USB, else onboard); only an ACTIVATE_* that comes up healthy short-circuits the
    hotspot.
    """
    facts = hctx.facts
    with ctx.state_lock:
        in_setup = ctx.STATE.setup_mode
        transitioning = ctx.STATE.transitioning
    if in_setup:
        return ctx.Verdict.CONTINUE
    # An activation is in flight — hold off starting a conflicting AP transition;
    # the result is applied at the next pass top.
    if transitioning:
        return ctx.Verdict.CONTINUE

    boot_age = hctx.now - hctx.boot_time
    # Consume the *debounced* connectivity verdict: a single soft blur on the
    # active path in the boot window must not trip boot-entry into a failover.
    # wifi_connected stays as a fast hard-disconnect signal; conn_ok replaces the
    # raw per-pass client_ok.
    offline = (not facts.wifi_configured) or (not hctx.wifi_connected) or (not hctx.conn_ok)
    should_enter_ap = (
        boot_age >= ctx.BOOT_AP_GRACE
        and boot_age <= ctx.BOOT_AP_CUTOFF
        and offline
    )

    if boot_age <= ctx.BOOT_AP_CUTOFF:
        ctx.logger.debug(
            "Boot window: age=%.0fs/%.0fs, wifi_cfg=%s, connected=%s, client_ok=%s",
            boot_age, ctx.BOOT_AP_CUTOFF, facts.wifi_configured, hctx.wifi_connected, hctx.client_ok,
        )
    if offline and boot_age > ctx.BOOT_AP_CUTOFF:
        ctx.log_on_change(
            "boot_ap_window_expired", True,
            f"Boot AP window expired (boot_age={boot_age:.0f}s); "
            f"device offline but automatic boot-window AP entry has passed",
            logging.WARNING,
        )

    if should_enter_ap:
        # Once the device has been ONLINE this boot, a runtime loss must not
        # re-enter the boot-recovery rung; the debounced runtime paths
        # (reconnect, USB-failure fallback, dead-PHY) own it.  The unconfigured
        # first-run path is unaffected (it can never have been online on Wi-Fi).
        with ctx.state_lock:
            been_online = ctx.STATE.been_online_this_boot
        if facts.wifi_configured and been_online:
            return ctx.Verdict.CONTINUE
        raction = ctx.next_recovery_action(ctx.STATE, ctx.gather_recovery_facts(facts))
        if raction.kind in (ctx.RecoveryKind.ACTIVATE_USB,
                            ctx.RecoveryKind.ACTIVATE_ONBOARD) \
                and ctx.submit_client_activation(raction, facts):
            return ctx.Verdict.OWN_PASS
        # No client path this pass (ladder held / ENTER_HOTSPOT / onboard budget
        # spent).  Configured-but-offline enters BOOT_RECOVERY (probes for return);
        # unconfigured enters FIRST_RUN (nothing saved to probe).
        purpose = (ctx.HotspotPurpose.BOOT_RECOVERY if facts.wifi_configured
                   else ctx.HotspotPurpose.FIRST_RUN)
        ctx.enter_setup_mode(
            purpose,
            reason=(f"boot_age={boot_age:.0f}s, wifi_cfg={facts.wifi_configured}, "
                    f"wifi_connected={hctx.wifi_connected}, client_ok={hctx.client_ok}"),
        )
        return ctx.Verdict.OWN_PASS
    return ctx.Verdict.CONTINUE


def step_connection_reliability(ctx: LoopContext, hctx: "HealthContext") -> "Verdict":
    """WiFi configured, ethernet down: prompt/periodic reconnect + gateway-down reboot.

    Always CONTINUE — reconnect/reboot never own the pass, so the 12-hour
    catch-all still runs afterward in the same pass.
    """
    facts = hctx.facts
    if not (facts.wifi_configured and not facts.wired_ok):
        return ctx.Verdict.CONTINUE

    now = hctx.now
    with ctx.state_lock:
        down_start = ctx.STATE.conn_down_start
        last_attempt = ctx.STATE.last_reconnect_attempt

    if not hctx.conn_ok:
        first_entry = down_start is None
        if first_entry:
            # Entering OFFLINE_RECONNECTING: one prompt reconnect
            # immediately rather than waiting for the 5-minute threshold.
            with ctx.state_lock:
                ctx.STATE.conn_down_start = now
                ctx.STATE.last_reconnect_attempt = now
            down_start = now
            ctx.logger.info("Connectivity lost; attempting prompt reconnect on entry")
            ctx.connect_to_configured_wifi()

        down_for = now - down_start

        # Generic gateway-down 30-minute reboot: a configured client connected but
        # with no usable gateway (NOT a wedged/NO-CARRIER adapter — that is the
        # dead-PHY ladder's domain).
        if down_for >= ctx.GW_DOWN_REBOOT_AFTER:
            ctx.request_network_down_reboot(
                now,
                "Connectivity unhealthy for %.0fs (threshold %ss)"
                % (down_for, ctx.GW_DOWN_REBOOT_AFTER),
            )

        if (not first_entry) and down_for >= ctx.GW_DOWN_RECONNECT_AFTER:
            if (last_attempt is None) or (now - last_attempt >= ctx.RECONNECT_ATTEMPT_INTERVAL):
                with ctx.state_lock:
                    ctx.STATE.last_reconnect_attempt = now
                ctx.logger.info("Connectivity unhealthy for %.0fs; attempting reconnect", down_for)
                ctx.connect_to_configured_wifi()
    else:
        with ctx.state_lock:
            ctx.STATE.conn_down_start = None
            ctx.STATE.last_reconnect_attempt = None
            ctx.STATE.conn_reboot_retry_after = 0.0
    return ctx.Verdict.CONTINUE


def step_catchall_reboot(ctx: LoopContext, hctx: "HealthContext") -> "Verdict":
    """12-hour no-active-path catch-all reboot (suspended during setup/AP mode)."""
    with ctx.state_lock:
        in_setup = ctx.STATE.setup_mode
        last_active_path_seen = ctx.STATE.last_active_path_seen

    if not in_setup and last_active_path_seen is not None:
        no_active_for = hctx.now - last_active_path_seen
        if no_active_for >= ctx.NO_ACTIVE_PATH_REBOOT_AFTER:
            ctx.request_network_down_reboot(
                hctx.now,
                "No usable network path for %.0fs (threshold %ss)"
                % (no_active_for, ctx.NO_ACTIVE_PATH_REBOOT_AFTER),
            )
    return ctx.Verdict.CONTINUE
