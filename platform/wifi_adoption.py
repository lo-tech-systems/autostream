#!/usr/bin/python3
"""wifi_adoption.py

Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

Multi-adapter client-path fallback and runtime USB adoption for the Autostream
Wi-Fi watcher.

This module owns "which adapter carries the client, and how we hand over"
policy — distinct from the activation *mechanism* (wifi_activation) and the
dead-PHY *reset* ladder (wifi_recovery):

  * the adapter-remediation overlay's ClientFailed handling, which engages the
    single recovery ladder (``wifi_policy.next_recovery_action``) to pick a
    replacement client path;
  * idle-time runtime USB adoption (adopting a newly-available USB dongle
    without disrupting a healthy built-in client);
  * the recovery-hotspot exit edge (probing the saved network's return and
    rejoining without dropping an associated setup-portal station); and
  * the reconnect-saved episode machinery that restores a saved/rollback
    profile one target per pass so monitoring never blacks out.

Every function takes an :class:`AdoptionContext` as its first argument — a
narrow view of the watcher exposing only the STATE, constants and callables
this module uses.  The watcher constructs the context once and passes it in;
internal cross-calls within this module take the same ``ctx``.  ``autostream_wifi_network``,
``wifi_policy``, ``wifi_recovery`` and ``wifi_activation`` are imported directly
because they are shared module objects (patching them affects every module
that imports them).
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Optional

import autostream_wifi_network as wifi_net
import wifi_activation
import wifi_policy
import wifi_recovery


@dataclass
class ReconnectEpisode:
    """A reconnect-saved episode: restore a saved/rollback profile across passes.

    Instead of one synchronous multi-target join, the watcher submits one
    single-target activation job per pass and advances this episode on the result,
    so monitoring never blacks out.  ``target_ifnames`` is the ordered list of
    interfaces to try; ``index`` is the next one; the profile to activate is
    ``profile_name``/``profile_uuid`` (the committed profile, or the rollback
    profile for EXPLICIT_RECONFIGURE).  ``hotspot_ifname`` selects which target
    needs the job's drop-hotspot mechanics.  ``failure_tail`` picks what runs when
    every target fails: "retain_hotspot" (the reconnect_saved caller) or
    "reconfigure_timeout" (convert the session to USB_LOSS_RECOVERY).
    ``inflight_epoch`` is the epoch of the currently submitted job, else None.
    """
    target_ifnames: list
    profile_name: str
    profile_uuid: str
    hotspot_ifname: str
    failure_tail: str
    index: int = 0
    inflight_epoch: Optional[int] = None


@dataclass
class AdoptionContext:
    """Narrow view of the watcher that the adoption/fallback helpers depend on.

    Constructed once by the watcher and passed to every function here.  It
    carries the shared STATE object and its lock, the AdoptionState fragment
    (fallback/adoption tracking, BSSID roaming and the known-USB-MAC set the
    recovery module reads), the recovery context (for the dead-PHY module's
    reset ledgers), a callable to reset one log-dedup key, the
    adoption/reconnect constants, and the small set of watcher callables these
    helpers invoke — nothing else of the watcher is reachable from this
    module.
    """

    STATE: object
    ADOPTION_STATE: object
    state_lock: object
    logger: object
    RECOVERY_CTX: object
    nm: object
    HotspotPurpose: object
    Verdict: object
    reset_log_key: Callable
    # Constants
    RECOVERY_SCAN_INTERVAL: float
    RECONNECT_ATTEMPT_INTERVAL: float
    ADOPTION_SCAN_INTERVAL: float
    USB_ADOPTION_STABLE_PASSES: int
    EMPTY_SCAN_RESET_STREAK: int
    BSSID_SURVEY_INTERVAL: float
    # Callables
    get_configured_network_state: Callable
    is_wifi_client_healthy: Callable
    resolve_hotspot_adapter: Callable
    hotspot_station_count: Callable
    query_playing_status: Callable
    log_on_change: Callable
    gather_recovery_facts: Callable
    enter_setup_mode: Callable
    submit_activation_job: Callable
    next_activation_epoch: Callable


def resolve_active_client(adapters: list) -> Optional[object]:
    """Return the adapter currently carrying a non-AP Wi-Fi client connection."""
    for a in adapters:
        if wifi_net.is_wifi_connected(a.ifname):
            return a
    return None


def handle_usb_failure_fallback(ctx: AdoptionContext, hctx: "HealthContext") -> bool:
    """Active-USB failure handling via the adapter-remediation overlay.

    The overlay (wifi_recovery.diagnose_client_failure) classifies the condemned
    active path over the debounced verdict and returns a ClientFailed
    event; this loop site applies the connectivity transition.  Returns True when
    a transition was performed on this pass; the caller then skips its ordinary
    reconnect/reboot logic for this pass.  Never gated by playback.
    """
    facts = hctx.facts
    event = wifi_recovery.diagnose_client_failure(
        ctx.RECOVERY_CTX, facts.adapters, facts.active_client,
        hctx.conn_ok, hctx.prev_active_mac, hctx.prev_active_ifname)
    if event is None:
        return False
    return apply_client_failed(ctx, event, facts)


def apply_client_failed(ctx: AdoptionContext, event, facts: "Facts") -> bool:
    """Apply an overlay ClientFailed event through the single recovery decider.

    The USB-failure fallback ranks client paths via next_recovery_action (the one
    priority ladder) and engages one via a submitted activation job.  A
    quarantined / no-IP-suppressed onboard is not blindly engaged — the ladder /
    gather_recovery_facts gate onboard usability, so a demoted onboard is skipped
    and we go to the recovery hotspot instead.

    A condemned active USB is retried in place before any demotion.  The ladder
    returns HOLD("usb_active_no_ip") for an active preferred USB that still has
    carrier but no usable IP; this handler answers it by submitting an
    ifname-pinned re-activation of that same USB ("usb_active_reactivate"), not
    the onboard fallback.  A transient blip re-activates and the client keeps
    its identity; a genuine failure records a no-IP ledger entry (the job's
    records_noip tail), whose escalating retry_after backoff excludes the
    adapter from preferred_usb, so the next ClientFailed reaches the ladder's
    onboard rung and demotes naturally — after NOIP_STOP_AFTER failures the
    exclusion is indefinite.  HOLD("usb_link_down_debouncing") means the
    dead-PHY debounce owns the adapter: no action this pass (a sustained
    link-down accrues the wedged verdict and proceeds to the budgeted reset /
    onboard rungs).  HOLDs with any other reason, and the ladder offering no
    client path, still try a *usable* onboard (one the gate did not exclude)
    before the USB_LOSS_RECOVERY hotspot; the ladder may also pick ACTIVATE_USB
    (re-activate) itself for an NM-dropped-but-present USB.

    The chosen activation is *submitted* to the worker (non-blocking) and owns the
    pass; its result is applied at the next pass top, and the ladder
    re-evaluates.  A failing USB is no-IP-suppressed after its budget, and a
    failing onboard is bounded (ONBOARD_ACTIVATION_MAX_FAILURES) so onboard stops
    being offered and this handler falls to the hotspot instead of retrying forever.
    """
    ctx.logger.info(
        "Overlay ClientFailed(%s) on %s; applying via recovery ladder",
        event.reason, event.ifname or event.mac or "?",
    )
    rf = ctx.gather_recovery_facts(facts)
    raction = wifi_policy.next_recovery_action(ctx.STATE, rf)
    if raction.kind in (wifi_policy.RecoveryKind.ACTIVATE_USB, wifi_policy.RecoveryKind.RESET_USB,
                        wifi_policy.RecoveryKind.ACTIVATE_ONBOARD):
        if _submit_client_activation(ctx, raction, facts):
            return True
    # The active preferred USB has carrier but no usable IP: retry the same
    # adapter in place instead of demoting to onboard.  The re-activation job
    # records a no-IP failure on failure, so a genuinely broken USB backs off
    # out of preferred_usb and the next ClientFailed demotes via the ladder.
    elif (raction.kind == wifi_policy.RecoveryKind.HOLD
          and raction.reason == "usb_active_no_ip"):
        retry = wifi_policy.RecoveryAction(
            wifi_policy.RecoveryKind.ACTIVATE_USB, ifname=rf.preferred_usb_ifname,
            drop_hotspot=(rf.preferred_usb_ifname == rf.hotspot_ifname),
            reason="usb_active_reactivate",
        )
        return _submit_client_activation(ctx, retry, facts)
    # The active USB reads link-down but the dead-PHY debounce has not declared
    # it wedged: take no action this pass.  A sustained link-down accrues the
    # wedged verdict and proceeds to the reset/onboard rungs on a later pass.
    elif (raction.kind == wifi_policy.RecoveryKind.HOLD
          and raction.reason == "usb_link_down_debouncing"):
        ctx.log_on_change(
            "client_failed_overlay_held", raction.reason,
            f"ClientFailed overlay held ({raction.reason}); "
            f"deferring to the dead-PHY debounce",
        )
        return False
    # Ladder held for another reason, or offered no client path: try a usable
    # onboard before the hotspot (not the adapter the ladder targeted, and not a
    # gated-out quarantined/suppressed/budget-spent onboard — rf.onboard_ifname is
    # "" once the onboard failure bound is reached).
    elif rf.onboard_ifname and rf.onboard_ifname != raction.ifname:
        onboard_action = wifi_policy.RecoveryAction(
            wifi_policy.RecoveryKind.ACTIVATE_ONBOARD, ifname=rf.onboard_ifname,
            drop_hotspot=(rf.onboard_ifname == rf.hotspot_ifname),
            reason="usb_failure_onboard_fallback",
        )
        if _submit_client_activation(ctx, onboard_action, facts):
            return True
    ctx.logger.warning("No usable client path on USB failure (%s); entering recovery hotspot",
                       event.reason)
    ctx.enter_setup_mode(ctx.HotspotPurpose.USB_LOSS_RECOVERY,
                         reason=f"usb_loss_recovery: {event.reason}")
    return True


def _submit_client_activation(ctx: AdoptionContext, action: "RecoveryAction", facts: "Facts") -> bool:
    """Submit an ACTIVATE_USB / RESET_USB / ACTIVATE_ONBOARD recovery action to
    the worker.

    Builds an ActivationJob with the tail flags the activation needs and submits it
    (non-blocking).  Returns True when the job was accepted (the loop owns the pass
    and apply_activation_result runs the tail at the next pass top); False if a job
    is already in flight (transitioning) or the action has no target.

    Cross-pass progression: on failure the ladder re-evaluates each pass — a USB
    failure is no-IP-recorded (suppressed after its budget), and an onboard failure
    is counted toward ONBOARD_ACTIVATION_MAX_FAILURES so the onboard eventually
    stops being offered and the ladder falls to the recovery hotspot.  RESET_USB is
    the same USB recovery job with a reset prefix (``reset_before``); its episode
    spend is marked here, on submission, so a failed job cannot loop the rung.
    """
    ifname = action.ifname
    if not ifname:
        return False

    is_reset_usb = action.kind == wifi_policy.RecoveryKind.RESET_USB
    # Onboard counts as a fallback only when a USB path also exists (a broken
    # configured USB); a lone onboard client is not "degraded".
    usb_present = any(a.is_usb for a in facts.adapters)
    sets_fallback = action.kind == wifi_policy.RecoveryKind.ACTIVATE_ONBOARD and usb_present
    # Record a no-IP failure only for USB targets (the ladder promotes the onboard
    # once the USB budget is spent); onboard failures instead count toward the
    # hotspot bound.
    records_usb_noip = action.kind in (wifi_policy.RecoveryKind.ACTIVATE_USB,
                                       wifi_policy.RecoveryKind.RESET_USB)
    records_onboard = action.kind == wifi_policy.RecoveryKind.ACTIVATE_ONBOARD
    stable_id = None
    if records_usb_noip:
        adapter = wifi_net.find_adapter_by_ifname(facts.adapters, ifname)
        stable_id = adapter.stable_id if adapter is not None else ifname

    job = wifi_activation.ActivationJob(
        epoch=ctx.next_activation_epoch(), kind="activate_committed", ifname=ifname,
        drop_hotspot=action.drop_hotspot, on_success_leaves_setup=True,
        leave_reason=f"recovery: client up on {ifname} ({action.reason})",
        reset_before=is_reset_usb,
        records_noip=records_usb_noip, noip_at=facts.taken_at,
        records_onboard_failure=records_onboard,
        sets_builtin_fallback=sets_fallback, clears_down_timers=True, stable_id=stable_id,
    )
    submitted = ctx.submit_activation_job(job)
    if submitted:
        ctx.logger.info("Recovery: submitted client activation on %s (%s)", ifname, action.reason)
        if is_reset_usb and stable_id:
            # Mark the episode spend on submission (not success): a failed reset
            # job must not loop the rung — match noip_holdback_reset_done's
            # locking exactly.
            with ctx.RECOVERY_CTX.state_lock:
                ctx.RECOVERY_CTX.RECOVERY_STATE.failover_reset_done.add(stable_id)
    return submitted


def _saved_network_ssid(ctx: AdoptionContext) -> str:
    """Return the SSID of the committed network profile, or "" if unknown."""
    state = ctx.get_configured_network_state()
    name = state.connection_uuid or state.connection_name
    return wifi_net.get_connection_ssid(name) if name else ""


# Three-way classification of a saved-SSID scan attempt, distinguishing a
# failed scan command from a scan that succeeded with zero rows (a wedged
# radio) from one that succeeded but did not include the saved SSID.
SCAN_FAILED = "failed"
SCAN_EMPTY = "empty"
SCAN_SSID_ABSENT = "absent"
SCAN_SSID_VISIBLE = "visible"


def _saved_ssid_scan_outcome(ctx: AdoptionContext, adapter) -> str:
    """Classify one saved-SSID scan on *adapter*.

    Returns SCAN_FAILED when no saved SSID is configured or the scan command
    itself failed (`scan_adapter` returned None) — both are "no information"
    outcomes.  Returns SCAN_EMPTY when the scan succeeded but returned zero
    rows (the radio is wedged: a working scan always sees *some* network).
    Returns SCAN_SSID_ABSENT when the scan returned rows but not the saved
    SSID, and SCAN_SSID_VISIBLE when it did.
    """
    ssid = _saved_network_ssid(ctx)
    if not ssid:
        return SCAN_FAILED
    scan = wifi_net.scan_adapter(adapter)
    if scan is None:
        return SCAN_FAILED
    if not scan:
        return SCAN_EMPTY
    return SCAN_SSID_VISIBLE if ssid in scan else SCAN_SSID_ABSENT


def _saved_ssid_visible(ctx: AdoptionContext, hotspot_adapter) -> bool:
    """True when the saved SSID is visible in a scan on the hotspot radio.

    Scanning works in AP mode on the onboard radio without dropping the AP, so a
    single-radio recovery hotspot can cheaply check for the network's return
    before committing to the expensive tear-down->join.  A failed scan or an
    empty scan are both "not visible" here — callers needing to distinguish
    them use `_saved_ssid_scan_outcome` directly.
    """
    return _saved_ssid_scan_outcome(ctx, hotspot_adapter) == SCAN_SSID_VISIBLE


def _scan_due_and_stamp(ctx: AdoptionContext, state_obj: object, last_scan_attr: str,
                        interval: float, now: float) -> bool:
    """Rate-gate mechanics shared by every idle-time saved-SSID scan site.

    *state_obj* is the state fragment carrying the timestamp; *last_scan_attr*
    names its field.  Returns False (nothing else to do) when a scan is not
    yet due; otherwise stamps the timestamp under `state_lock` and returns
    True.
    """
    with ctx.state_lock:
        last = getattr(state_obj, last_scan_attr)
    if last is not None and now - last < interval:
        return False
    with ctx.state_lock:
        setattr(state_obj, last_scan_attr, now)
    return True


def _rate_gated_saved_ssid_scan(ctx: AdoptionContext, adapter, state_obj: object,
                                last_scan_attr: str, interval: float, now: float) -> Optional[bool]:
    """Rate-bounded "is the committed SSID visible on *adapter*" probe.

    Used by the recovery hotspot exit edge, which only needs the collapsed
    boolean.  Returns None when a scan is not yet due — the caller must treat
    this as "no information, do nothing".  It calls `_saved_ssid_visible` by
    module-global name so test patches still intercept.
    """
    if not _scan_due_and_stamp(ctx, state_obj, last_scan_attr, interval, now):
        return None
    return _saved_ssid_visible(ctx, adapter)


def _rate_gated_saved_ssid_outcome(ctx: AdoptionContext, adapter, state_obj: object,
                                   last_scan_attr: str, interval: float, now: float) -> Optional[str]:
    """Rate-bounded saved-SSID scan outcome (SCAN_FAILED/EMPTY/SSID_ABSENT/SSID_VISIBLE).

    Used by runtime USB adoption, which needs to distinguish a wedged radio
    (SCAN_EMPTY) from a working scan that simply doesn't see the saved network
    (SCAN_SSID_ABSENT) or a failed scan command (SCAN_FAILED).  Returns None
    when a scan is not yet due.  It calls `_saved_ssid_scan_outcome` by
    module-global name so test patches still intercept.
    """
    if not _scan_due_and_stamp(ctx, state_obj, last_scan_attr, interval, now):
        return None
    return _saved_ssid_scan_outcome(ctx, adapter)


def _attempt_recovery_reconnect(ctx: AdoptionContext, facts: "Facts") -> None:
    """Scan-gated recovery reconnect from within a recovery hotspot.

    Routes the client-path-vs-hotspot choice through the single recovery ladder:
    next_recovery_action ranks the usable radios exactly as it does at
    boot-entry and on USB failure, so the in-hotspot probe can no longer diverge
    from those sites.  A second (non-hotspot) radio the ladder still rates usable
    is (re)activated without dropping the AP; when the only client path is the
    AP-hosting radio itself the ladder returns ACTIVATE_ONBOARD with
    drop_hotspot=True — the single-radio exit edge.

    This function keeps only the *apply-layer mechanics* the ladder does not own:
    the RECONNECT_ATTEMPT_INTERVAL bound on the (expensive) join, and — before a
    drop-AP rejoin — the RECOVERY_SCAN_INTERVAL-gated _saved_ssid_visible scan
    that cheaply confirms the saved network is back before tearing the AP down.
    """
    now = facts.taken_at

    # The user chose "keep reconfiguring" this session: stop probing/offering the
    # rejoin entirely until the session ends.
    with ctx.state_lock:
        if ctx.STATE.rejoin_dismissed:
            return

    raction = wifi_policy.next_recovery_action(ctx.STATE, ctx.gather_recovery_facts(facts))
    if raction.kind not in (wifi_policy.RecoveryKind.ACTIVATE_USB, wifi_policy.RecoveryKind.RESET_USB,
                            wifi_policy.RecoveryKind.ACTIVATE_ONBOARD):
        # HOLD / ENTER_HOTSPOT: the active path is fine, Ethernet is up, or a
        # wedged-USB-only case the dead-PHY ladder owns — retain the hotspot.
        return

    with ctx.state_lock:
        last_reconnect = ctx.STATE.last_reconnect_attempt
    join_due = (last_reconnect is None
                or (now - last_reconnect) >= ctx.RECONNECT_ATTEMPT_INTERVAL)

    # A drop-AP rejoin on the AP-hosting radio is expensive and tears the hotspot
    # down; gate it behind the cheap saved-SSID scan (single-radio exit edge) so
    # the AP is dropped only once the network is actually visible again.
    if raction.drop_hotspot:
        hotspot = ctx.resolve_hotspot_adapter(facts.adapters)
        if hotspot is None:
            return
        visible = _rate_gated_saved_ssid_scan(
            ctx, hotspot, ctx.STATE, "last_recovery_scan", ctx.RECOVERY_SCAN_INTERVAL, now)
        if not visible:
            # None (scan not due) or False (not visible / scan failed): keep the AP.
            if visible is False:
                ctx.logger.debug("Recovery scan: saved SSID not visible on %s; AP retained",
                                 hotspot.ifname)
            return
        # Saved SSID is back.  Dropping the AP would disconnect anyone using the
        # portal, so when a station is associated (or the count is unknown) do not
        # rejoin automatically — surface the choice on the setup page instead.
        # With zero stations nobody is on the portal, so proceed as before.
        stations = ctx.hotspot_station_count(hotspot.ifname)
        if stations is None or stations > 0:
            with ctx.state_lock:
                ctx.STATE.saved_ssid_visible = True
                ctx.STATE.saved_ssid_name = _saved_network_ssid(ctx)
            ctx.log_on_change("saved_ssid_visible_prompt", True,
                              "Saved network visible with a client on the setup AP; "
                              "offering rejoin instead of yanking the hotspot")
            return
        with ctx.state_lock:
            ctx.STATE.saved_ssid_visible = False

    if not join_due:
        return
    with ctx.state_lock:
        ctx.STATE.last_reconnect_attempt = now
    _submit_client_activation(ctx, raction, facts)


def handle_runtime_usb_adoption(ctx: AdoptionContext, adapters: list, wired_connected: bool,
                                playing_fn=None) -> bool:
    """Optional idle-time adoption of a newly available USB adapter.

    Adopts USB only when: Ethernet is not active; built-in carries a healthy
    Wi-Fi client (or built-in fallback is active); no USB is already the active
    client; the same deterministic USB candidate has been present for two passes;
    and (main appliance) playback is confirmed idle.  Returns True if a handover
    was performed.  *playing_fn* is the per-pass memoised playback resolver; it
    defaults to query_playing_status for direct callers/tests.
    """
    if playing_fn is None:
        playing_fn = ctx.query_playing_status
    now = time.monotonic()
    with ctx.state_lock:
        in_setup = ctx.STATE.setup_mode
    if in_setup or wired_connected:
        _clear_pending_adoption(ctx)
        return False

    usb = wifi_net.usb_candidates(adapters)
    if not usb:
        _clear_pending_adoption(ctx)
        _prune_empty_scan_streaks(ctx, None)
        return False
    candidate = usb[0]
    # A candidate change drops any other stable_id's empty-scan streak; the
    # entry survives only while its adapter remains the current candidate.
    _prune_empty_scan_streaks(ctx, candidate.stable_id)

    # An operator-disabled adapter is never adopted.
    if wifi_recovery.adapter_disabled(ctx.RECOVERY_CTX, candidate.stable_id):
        _clear_pending_adoption(ctx)
        return False

    # A quarantined adapter (reset budget exhausted after repeated failures,
    # whatever the failure mode) is neither scanned nor adopted until the
    # quarantine expires.
    target = wifi_recovery.build_target_adapter(ctx.RECOVERY_CTX, candidate.ifname, adapters)
    if wifi_recovery.adapter_quarantined_until(ctx.RECOVERY_CTX, target, now) is not None:
        _clear_pending_adoption(ctx)
        return False

    # Escalating no-IP back-off: a dongle that repeatedly associates but
    # cannot get an IP is held back (and eventually stopped) instead of thrashing
    # adoption every cycle.
    if wifi_recovery.noip_retry_suppressed(ctx.RECOVERY_CTX, candidate.stable_id, now):
        return False

    active_client = resolve_active_client(adapters)
    # Do not switch from a healthy USB client to another USB adapter.
    if active_client is not None and active_client.is_usb:
        _clear_pending_adoption(ctx)
        return False
    # Built-in must currently carry a healthy client (direct or fallback).
    builtin = wifi_net.resolve_builtin(adapters)
    if builtin is None or not ctx.is_wifi_client_healthy(builtin.ifname):
        _clear_pending_adoption(ctx)
        return False

    # Two-pass stability on the same deterministic candidate.
    with ctx.state_lock:
        if ctx.ADOPTION_STATE.pending_usb_adoption_mac == candidate.permanent_mac:
            ctx.ADOPTION_STATE.pending_usb_adoption_checks += 1
        else:
            ctx.ADOPTION_STATE.pending_usb_adoption_mac = candidate.permanent_mac
            ctx.ADOPTION_STATE.pending_usb_adoption_checks = 1
        checks = ctx.ADOPTION_STATE.pending_usb_adoption_checks
    if checks < ctx.USB_ADOPTION_STABLE_PASSES:
        return False

    # Playback gating (main appliance only).
    playing = playing_fn()
    if playing is None:
        ctx.logger.debug("USB adoption deferred: playback status uncertain")
        return False
    if playing:
        ctx.log_on_change("usb_adopt_deferred_playing", True,
                          "USB adoption deferred because playback is active")
        return False

    # Scan-gate the handover: the committed profile is usually active on the
    # built-in too, and `nmcli connection up ... ifname <usb>` *moves* an
    # already-active connection — it deactivates the built-in as part of trying
    # the USB.  A USB that cannot even see the SSID would fail that move and take
    # the whole device offline, so proceed only once the candidate's own scan
    # shows the committed SSID.  The scan outcome is classified three ways: a
    # not-due (None) or failed (command error / no saved SSID) scan is a
    # non-destructive skip identical to before — the candidate stays pending
    # and the no-IP ledger is untouched (the dongle never got the chance to
    # fail DHCP).  A scan that succeeds with zero rows means the radio itself
    # is wedged (a working scan always sees *some* network) and counts toward
    # the empty-scan streak; any other outcome resets that streak.
    outcome = _rate_gated_saved_ssid_outcome(
        ctx, candidate, ctx.ADOPTION_STATE, "last_adoption_scan", ctx.ADOPTION_SCAN_INTERVAL, now)
    if outcome is None or outcome == SCAN_FAILED:
        return False
    if outcome == SCAN_EMPTY:
        _handle_empty_adoption_scan(ctx, candidate, adapters, now)
        return False
    _clear_empty_scan_streak(ctx, candidate.stable_id)
    if outcome == SCAN_SSID_ABSENT:
        ctx.log_on_change("usb_adopt_skipped_ssid_not_visible", True,
                          "USB adoption skipped: committed SSID not visible on %s"
                          % candidate.ifname)
        return False
    # Attempted (visible) pass: reset the skip key so a future not-visible
    # episode logs again, without emitting a spurious transition line.
    ctx.reset_log_key("usb_adopt_skipped_ssid_not_visible")

    # Transactional handover, off-thread: submit a worker job that validates the
    # USB (activate committed + IPv4/health wait); only the loop-half success tail
    # then disconnects the healthy built-in, clears the fallback flag / no-IP
    # ledger / pending adoption, sets the active client, and re-announces mDNS —
    # so the built-in is dropped one pass later, after the USB is validated.  On
    # failure the tail records the no-IP failure and clears the pending adoption.
    ctx.logger.info("Runtime USB adoption starting on %s", candidate.ifname)
    job = wifi_activation.ActivationJob(
        epoch=ctx.next_activation_epoch(), kind="activate_committed", ifname=candidate.ifname,
        disconnects_previous_ifname=builtin.ifname,
        sets_builtin_fallback=False,
        clears_pending_adoption=True,
        records_noip=True, noip_at=now, stable_id=candidate.stable_id,
    )
    return ctx.submit_activation_job(job)


def _clear_pending_adoption(ctx: AdoptionContext) -> None:
    with ctx.state_lock:
        ctx.ADOPTION_STATE.pending_usb_adoption_mac = None
        ctx.ADOPTION_STATE.pending_usb_adoption_checks = 0


def _prune_empty_scan_streaks(ctx: AdoptionContext, keep_stable_id: Optional[str]) -> None:
    """Drop empty-scan streak entries for every stable_id but the current
    candidate (or all of them when there is no current candidate)."""
    with ctx.state_lock:
        streaks = ctx.ADOPTION_STATE.empty_scan_streaks
        for stale in [sid for sid in streaks if sid != keep_stable_id]:
            del streaks[stale]


def _clear_empty_scan_streak(ctx: AdoptionContext, stable_id: str) -> None:
    with ctx.state_lock:
        ctx.ADOPTION_STATE.empty_scan_streaks.pop(stable_id, None)


def _bump_empty_scan_streak(ctx: AdoptionContext, stable_id: str) -> int:
    with ctx.state_lock:
        streaks = ctx.ADOPTION_STATE.empty_scan_streaks
        streak = streaks.get(stable_id, 0) + 1
        streaks[stable_id] = streak
        return streak


def _handle_empty_adoption_scan(ctx: AdoptionContext, candidate, adapters: list, now: float) -> None:
    """Count one empty adoption scan against *candidate* and remediate once the
    streak reaches EMPTY_SCAN_RESET_STREAK.

    A present idle USB candidate whose scan repeatedly returns zero rows is a
    wedged radio, not an absent network — routed through the shared
    remediate_unusable_usb primitive (reason="empty_scan") the same way every
    other unusable-USB detector is.  On a "reset" outcome the adoption
    scan rate-gate is cleared so the next pass re-scans promptly instead of
    waiting out ADOPTION_SCAN_INTERVAL; a recovered radio then fails back
    through the ordinary adoption path above, untouched.  On "quarantined"
    the rate gate is left alone (the new candidate gate above now skips this
    adapter regardless).
    """
    streak = _bump_empty_scan_streak(ctx, candidate.stable_id)
    ctx.log_on_change(
        "usb_adopt_empty_scan_streak_%s" % candidate.stable_id, streak,
        "USB adoption candidate %s scan returned zero rows (streak %d/%d)"
        % (candidate.ifname, streak, ctx.EMPTY_SCAN_RESET_STREAK))
    if streak < ctx.EMPTY_SCAN_RESET_STREAK:
        return
    target = wifi_recovery.build_target_adapter(ctx.RECOVERY_CTX, candidate.ifname, adapters)
    outcome = wifi_recovery.remediate_unusable_usb(ctx.RECOVERY_CTX, target, now, reason="empty_scan")
    _clear_empty_scan_streak(ctx, candidate.stable_id)
    if outcome == "reset":
        with ctx.state_lock:
            ctx.ADOPTION_STATE.last_adoption_scan = None


def update_known_adapters(ctx: AdoptionContext, adapters: list) -> None:
    """Track USB MACs and log adapter-set changes at INFO on transition."""
    macs = frozenset(a.permanent_mac for a in adapters if a.permanent_mac)
    for a in adapters:
        if a.is_usb and a.permanent_mac:
            ctx.ADOPTION_STATE.known_usb_macs.add(a.permanent_mac)
    with ctx.state_lock:
        prev = ctx.ADOPTION_STATE.last_detected_adapter_macs
        ctx.ADOPTION_STATE.last_detected_adapter_macs = macs
    if prev is not None and prev != macs:
        ctx.logger.info("Detected Wi-Fi adapter set changed: %s", sorted(macs))
    # Drop no-IP ledgers for adapters that are no longer present so a replaced
    # or removed dongle starts fresh (the back-off ceiling releases).  The
    # ledger is keyed by stable_id (permanent MAC, else ifname), so prune by the
    # present stable_ids — not just permanent MACs — or a MAC-less adapter's
    # ledger would be dropped every pass.
    present_stable_ids = {a.stable_id for a in adapters if a.stable_id}
    wifi_recovery.prune_noip_ledgers(ctx.RECOVERY_CTX, present_stable_ids)


# ---- USB BSSID survey + gated roam ----
#
# Keeps the BSSID table fresh for the active USB client (so a pinned reconnect
# always has recent candidates) and, only when playback is idle, considers a
# deliberate roam to a clearly-better AP.  Scans here run inline on the loop
# thread bounded by NMCLI_BSSID_SCAN_TIMEOUT — the same precedent as the loop's
# other bounded blocking effects (recovery/adoption scans above).


def _survey_due(ctx: AdoptionContext, attr: str, interval: float, now: float) -> bool:
    """Rate gate: True (and stamps *attr* on ADOPTION_STATE) once *interval* has elapsed."""
    with ctx.state_lock:
        last = getattr(ctx.ADOPTION_STATE, attr)
        if last is not None and now - last < interval:
            return False
        setattr(ctx.ADOPTION_STATE, attr, now)
        return True


def _idle_onboard_for_survey(ctx: AdoptionContext, facts: "Facts", usb_ifname: str):
    """The onboard radio eligible for an opportunistic survey scan, else None.

    Idle: managed, not the hotspot, not the active (USB) client, and not
    manually disabled or reset-quarantined.
    """
    onboard = wifi_net.resolve_builtin(facts.adapters)
    if onboard is None or onboard.ifname == usb_ifname or not onboard.managed:
        return None
    hotspot = ctx.resolve_hotspot_adapter(facts.adapters)
    if hotspot is not None and hotspot.ifname == onboard.ifname:
        return None
    if wifi_recovery.adapter_disabled(ctx.RECOVERY_CTX, onboard.stable_id):
        return None
    target = wifi_recovery.build_target_adapter(ctx.RECOVERY_CTX, onboard.ifname, facts.adapters)
    if wifi_recovery.adapter_quarantined_until(ctx.RECOVERY_CTX, target, time.monotonic()) is not None:
        return None
    return onboard


def bssid_survey_and_roam(ctx: AdoptionContext, hctx: "HealthContext") -> bool:
    """Periodic BSSID survey for the active USB client, plus a gated roam.

    Single cadence gate: every BSSID_SURVEY_INTERVAL the USB self-scan runs
    alongside an opportunistic idle-onboard scan (the latter always
    rescan=True, written only to its own interface's table — it never
    influences a USB roam decision).  The USB scan is a full rescan
    (rescan=True) — "eligible" evidence for the roam-candidate streak — only
    while playback is exactly False; while playback is True/None it is a
    cheap rescan=False read that keeps the table fresh but never advances or
    resets the streak.

    On an eligible scan, a candidate that clears wifi_policy.next_roam_target
    advances ADOPTION_STATE.bssid_roam_candidate (wifi_policy.update_roam_streak);
    a candidate that fails policy, or no eligible scan at all, resets/leaves the
    streak per update_roam_streak's rules.  Only once the streak reaches
    BSSID_ROAM_REQUIRED_SCANS does a fresh confirmation scan run; the roam is
    submitted only when the confirmation scan still names the same candidate and
    it still clears policy — the world may have moved since the scan that built
    the streak.  Returns True when a roam job was submitted (the caller owns
    the pass).
    """
    facts = hctx.facts
    usb = facts.active_client
    usb_ifname = usb.ifname
    now = hctx.now
    playing = hctx.playing()

    ssid = _saved_network_ssid(ctx)
    if not ssid:
        return False

    if not _survey_due(ctx, "last_bssid_survey_at", ctx.BSSID_SURVEY_INTERVAL, now):
        return False

    eligible = playing is False
    rows = ctx.nm.wifi_bssid_scan(usb_ifname, rescan=eligible)
    ctx.logger.debug(wifi_policy.format_bssid_scan_debug(usb_ifname, eligible, "survey", rows, ssid))
    current_bssid, current_signal = "", 0
    if rows is not None:
        with ctx.state_lock:
            usb_table = wifi_policy.bssid_table_for_interface(
                ctx.ADOPTION_STATE.bssid_tables, usb_ifname)
            current_bssid, current_signal = wifi_policy.update_bssid_table(
                usb_table, rows, ssid, now)

    onboard = _idle_onboard_for_survey(ctx, facts, usb_ifname)
    if onboard is not None:
        onboard_rows = ctx.nm.wifi_bssid_scan(onboard.ifname, rescan=True)
        ctx.logger.debug(wifi_policy.format_bssid_scan_debug(onboard.ifname, True, "onboard", onboard_rows, ssid))
        if onboard_rows is not None:
            with ctx.state_lock:
                onboard_table = wifi_policy.bssid_table_for_interface(
                    ctx.ADOPTION_STATE.bssid_tables, onboard.ifname)
                wifi_policy.update_bssid_table(onboard_table, onboard_rows, ssid, now)

    # A non-eligible (cheap) scan, a failed scan, or an eligible scan with no
    # in-use row (nothing to compare a candidate against) leaves the streak
    # untouched: there is no fresh evidence this pass.
    if not eligible or rows is None or not current_bssid:
        return False

    with ctx.state_lock:
        usb_table = wifi_policy.bssid_table_for_interface(ctx.ADOPTION_STATE.bssid_tables, usb_ifname)
        last_roam = ctx.ADOPTION_STATE.last_roam_or_activation
        target = wifi_policy.next_roam_target(usb_table, current_bssid, now, playing, last_roam)
        streak = wifi_policy.update_roam_streak(
            ctx.ADOPTION_STATE.bssid_roam_candidate, usb_ifname, target, now)
        ctx.ADOPTION_STATE.bssid_roam_candidate = streak
        target_signal = usb_table.get(target, {}).get("signal", 0) if target else 0

    if not target:
        return False

    if streak["count"] == 1:
        ctx.logger.info(
            "BSSID roam candidate streak started on %s: %s (%d) -> %s (%d)",
            usb_ifname, current_bssid, current_signal, target, target_signal)
    else:
        ctx.logger.debug(
            "BSSID roam candidate on %s: %s (%d) -> %s (%d) [%d/%d]",
            usb_ifname, current_bssid, current_signal, target, target_signal,
            streak["count"], wifi_policy.BSSID_ROAM_REQUIRED_SCANS)

    if streak["count"] < wifi_policy.BSSID_ROAM_REQUIRED_SCANS:
        return False

    # Confirm with one fresh scan before committing — the world may have moved
    # since the survey scan that built the streak.
    confirm_rows = ctx.nm.wifi_bssid_scan(usb_ifname, rescan=True)
    if confirm_rows is None:
        return False
    with ctx.state_lock:
        usb_table = wifi_policy.bssid_table_for_interface(ctx.ADOPTION_STATE.bssid_tables, usb_ifname)
        confirm_bssid, confirm_signal = wifi_policy.update_bssid_table(
            usb_table, confirm_rows, ssid, now)
        last_roam = ctx.ADOPTION_STATE.last_roam_or_activation
        confirmed_target = wifi_policy.next_roam_target(
            usb_table, confirm_bssid or current_bssid, now, playing, last_roam)
        if confirmed_target != target:
            return False
        confirmed_signal = usb_table.get(confirmed_target, {}).get("signal", 0)
        ctx.ADOPTION_STATE.last_roam_or_activation = now
        ctx.ADOPTION_STATE.bssid_roam_candidate = {}

    ctx.logger.info(
        "BSSID roam: SSID '%s' %s %s (signal %d) -> %s (signal %d) after %d scans",
        ssid, usb_ifname, confirm_bssid or current_bssid, confirm_signal,
        confirmed_target, confirmed_signal, wifi_policy.BSSID_ROAM_REQUIRED_SCANS)

    job = wifi_activation.ActivationJob(
        epoch=ctx.next_activation_epoch(), kind="activate_committed", ifname=usb_ifname)
    return ctx.submit_activation_job(job)


# ---- Reconnect-saved episode machinery ----
#
# Restores a saved/rollback profile across passes: one single-target activation
# job per pass, advanced on the result, so monitoring never blacks out.


def start_reconnect_saved_episode(ctx: AdoptionContext, failure_tail: str = "retain_hotspot") -> bool:
    """Begin a reconnect-saved episode and submit its first target's job.

    Builds the same target list and profile the old synchronous
    reconnect_saved_network built (for EXPLICIT_RECONFIGURE the rollback adapter
    first, then ``client_candidate_order``, restoring the rollback profile;
    otherwise ``client_candidate_order`` restoring the committed profile), records
    the episode on STATE, and submits the first single-target activation job.
    Returns True when an episode was started (a job was submitted or targets
    remain to try); False when there is nothing configured to restore.  The
    episode is then advanced one target per pass by step_reconnect_episode /
    step_apply_activation_result.  ``failure_tail`` selects the exhaustion tail:
    "retain_hotspot" (reconnect_saved) or "reconfigure_timeout".
    """
    with ctx.state_lock:
        session = ctx.STATE.hotspot
    purpose = session.purpose if session else None
    rollback = session.rollback if session else None
    rb_name = rollback.connection_name if rollback else ""
    rb_uuid = rollback.connection_uuid if rollback else ""
    rb_mac = rollback.adapter_mac if rollback else ""
    adapters = wifi_net.discover_adapters()

    targets: list = []
    if purpose == ctx.HotspotPurpose.EXPLICIT_RECONFIGURE and rb_name:
        prev = wifi_net.find_adapter_by_mac(adapters, rb_mac)
        if prev is not None:
            targets.append(prev)
        # Then fall back to USB-first, then built-in.
        for a in wifi_net.client_candidate_order(adapters):
            if a not in targets:
                targets.append(a)
        committed = wifi_net.NetworkState(connection_name=rb_name, connection_uuid=rb_uuid)
    else:
        targets = wifi_net.client_candidate_order(adapters)
        committed = ctx.get_configured_network_state()

    if not committed.is_configured:
        return False

    hotspot = ctx.resolve_hotspot_adapter(adapters)
    episode = ReconnectEpisode(
        target_ifnames=[t.ifname for t in targets],
        profile_name=committed.connection_name,
        profile_uuid=committed.connection_uuid,
        hotspot_ifname=hotspot.ifname if hotspot is not None else "",
        failure_tail=failure_tail,
    )
    with ctx.state_lock:
        ctx.STATE.reconnect_episode = episode
    _submit_next_reconnect_target(ctx)
    return True


def _submit_next_reconnect_target(ctx: AdoptionContext) -> bool:
    """Submit the episode's next single-target job, or run its failure tail when
    the targets are exhausted.  Returns True when a job was submitted."""
    with ctx.state_lock:
        ep = ctx.STATE.reconnect_episode
    if ep is None:
        return False
    if ep.index >= len(ep.target_ifnames):
        _finish_reconnect_episode_failure(ctx)
        return False
    ifname = ep.target_ifnames[ep.index]
    # Activate the episode's saved/rollback profile on this target; drop the AP
    # first (worker-half) only when the target is the AP-hosting radio.
    profile = wifi_net.NetworkState(connection_name=ep.profile_name,
                                    connection_uuid=ep.profile_uuid)
    job = wifi_activation.ActivationJob(
        epoch=ctx.next_activation_epoch(), kind="activate_profile", ifname=ifname,
        profile=profile, drop_hotspot=(ifname == ep.hotspot_ifname),
        on_success_leaves_setup=True, leave_reason="WiFi client connection succeeded",
        wait_for_validation=True,
    )
    if not ctx.submit_activation_job(job):
        return False   # busy; retried on a later pass
    with ctx.state_lock:
        ep.inflight_epoch = job.epoch
    ctx.logger.info("Reconnect episode: submitted restore on %s (target %d/%d)",
                    ifname, ep.index + 1, len(ep.target_ifnames))
    return True


def _advance_reconnect_episode(ctx: AdoptionContext, result: "ActivationResult") -> None:
    """Advance the episode from an applied activation result (loop thread).

    On success the loop-half tail already left setup, so the episode ends; on
    failure the index advances so step_reconnect_episode submits the next target
    on a later pass.  Ignores results that do not belong to the episode's
    in-flight job.
    """
    with ctx.state_lock:
        ep = ctx.STATE.reconnect_episode
        if ep is None or result.epoch != ep.inflight_epoch:
            return
        if result.ok:
            ctx.STATE.reconnect_episode = None
            return
        ep.index += 1
        ep.inflight_epoch = None


def _finish_reconnect_episode_failure(ctx: AdoptionContext) -> None:
    """Run the episode's exhaustion tail and clear it."""
    with ctx.state_lock:
        ep = ctx.STATE.reconnect_episode
        ctx.STATE.reconnect_episode = None
    if ep is None:
        return
    if ep.failure_tail == "reconfigure_timeout":
        # Restoration failed: retain the hotspot but convert it to an automatic
        # USB-loss recovery session (probes for return, eth-suppressible, no
        # rollback).
        with ctx.state_lock:
            if ctx.STATE.hotspot is not None:
                ctx.STATE.hotspot.purpose = ctx.HotspotPurpose.USB_LOSS_RECOVERY
                ctx.STATE.hotspot.rollback = None
        ctx.logger.warning("Timeout restore failed; remaining in recovery hotspot")
    else:
        ctx.logger.warning("Reconnect to saved network failed; retaining hotspot")


def step_reconnect_episode(ctx: AdoptionContext, pre: "PreFactsContext") -> "Verdict":
    """Drive a reconnect-saved episode: submit its next target when none is in
    flight and no other transition is running.  Placed before
    step_apply_activation_result so the result of one target is applied (and the
    index advanced) before the next target is submitted on a subsequent pass."""
    with ctx.state_lock:
        ep = ctx.STATE.reconnect_episode
        transitioning = ctx.STATE.transitioning
    if ep is None:
        return ctx.Verdict.CONTINUE
    if ep.inflight_epoch is not None or transitioning:
        # A job is still in flight (this episode's, or another transition): wait.
        return ctx.Verdict.CONTINUE
    if _submit_next_reconnect_target(ctx):
        return ctx.Verdict.OWN_PASS
    return ctx.Verdict.CONTINUE
