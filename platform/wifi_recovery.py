#!/usr/bin/python3
"""wifi_recovery.py

Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

Dead-PHY recovery policy for the Autostream Wi-Fi watcher.

This module owns adapter health classification for the dead-PHY case, the reset
budget / quarantine ledger, the persistent cross-boot reboot guard, and the
recovery-action ladder.  The bounded sysfs primitives live in
``core/autostream_wifi_network``.

To keep the extraction mechanical and behaviour-preserving, every public/helper
function takes the watcher module ``w`` as its first argument and reads its
STATE, constants, and policy helpers through it; this avoids a circular import
while preserving the single source of mutable state.  ``autostream_wifi_network``
is imported directly (shared module object, so patching it affects both).
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional

import autostream_wifi_network as wifi_net

INTERFACE_REAPPEAR_TIMEOUT = 15  # seconds to wait for a netdev after a USB reset


# ---- Adapter-remediation overlay event contract ----
#
# The overlay *diagnoses* the active client adapter and emits events; the
# connectivity loop *consumes* them and applies the transition (pure classify,
# watcher applies; no generic Action engine).  ClientFailed is produced here by
# diagnose_client_failure (the USB-failure path); NeedReboot is the dead-PHY
# ladder's offline-too-long escalation (the LINK_DOWN branch below, which both
# diagnoses and applies its own reboot in-module).


class OverlayEvent(Enum):
    CLIENT_FAILED = "client_failed"
    NEED_REBOOT = "need_reboot"


@dataclass(frozen=True)
class ClientFailed:
    """OverlayEvent.CLIENT_FAILED — the active client adapter is no longer usable."""
    ifname: str
    mac: str
    reason: str              # "no_ip" | "absent" | "dead_phy_quarantined"
    has_alt_path: bool       # a built-in fallback adapter is available


@dataclass(frozen=True)
class NeedReboot:
    """OverlayEvent.NEED_REBOOT — only path dead and offline past the threshold."""
    ifname: str
    reason: str              # e.g. "dead_phy_only_path_offline_30min"


# ---- "Associated but no IP" / adoption-failure ledger ----
#
# Separate from the dead-PHY reset ledger: this counts how many times a managed
# adapter associated (or was adopted/reconnected) but failed to obtain a usable
# IP/gateway.  It both drives the escalating adoption back-off (so a dongle that
# cannot get a DHCP lease stops thrashing every 90s) and feeds the DEGRADED_NO_IP
# status taxonomy.

NOIP_STOP_AFTER = 5            # failures before retries are suppressed until the MAC changes


def _noip_ledger_locked(w, stable_id: str, create: bool = True) -> Optional[dict]:
    if not stable_id:
        return None
    led = w.STATE.adapter_noip_ledgers.get(stable_id)
    if led is None and create:
        led = {"count": 0, "retry_after": 0.0}
        w.STATE.adapter_noip_ledgers[stable_id] = led
    return led


def record_noip_failure(w, stable_id: str, now: float) -> int:
    """Record one associate-but-no-IP failure for *stable_id*; return the new count.

    The retry back-off escalates from RECONNECT_ATTEMPT_INTERVAL up to
    USB_EMERGENCY_BACKOFF; after NOIP_STOP_AFTER failures retries are suppressed
    indefinitely (retry_after = inf) until the ledger is cleared (the MAC changes
    or disappears).
    """
    if not stable_id:
        return 0
    with w.state_lock:
        led = _noip_ledger_locked(w, stable_id)
        led["count"] += 1
        n = led["count"]
        if n >= NOIP_STOP_AFTER:
            led["retry_after"] = float("inf")
        else:
            interval = min(
                w.RECONNECT_ATTEMPT_INTERVAL * (2 ** (n - 1)), w.USB_EMERGENCY_BACKOFF
            )
            led["retry_after"] = now + interval
    w.logger.info(
        "No-IP failure #%d recorded for adapter %s; backing off adoption", n, stable_id
    )
    persist_adapter_fault_state(w)
    return n


def noip_failure_count(w, stable_id: str) -> int:
    if not stable_id:
        return 0
    with w.state_lock:
        led = _noip_ledger_locked(w, stable_id, create=False)
        return int(led["count"]) if led else 0


def noip_retry_suppressed(w, stable_id: str, now: float) -> bool:
    """True when adoption of *stable_id* should be skipped this pass (back-off)."""
    if not stable_id:
        return False
    with w.state_lock:
        led = _noip_ledger_locked(w, stable_id, create=False)
        retry_after = led["retry_after"] if led else 0.0
    return now < retry_after


def clear_noip_failures(w, stable_id: str) -> None:
    """Clear the no-IP ledger for *stable_id* (success, or the MAC disappeared)."""
    if not stable_id:
        return
    with w.state_lock:
        existed = w.STATE.adapter_noip_ledgers.pop(stable_id, None) is not None
    if existed:
        persist_adapter_fault_state(w)


def prune_noip_ledgers(w, present_stable_ids: set) -> None:
    """Drop ledgers for adapters that are no longer present (MAC disappeared)."""
    with w.state_lock:
        for sid in list(w.STATE.adapter_noip_ledgers):
            if sid not in present_stable_ids:
                w.STATE.adapter_noip_ledgers.pop(sid, None)
        # A removed adapter starts a fresh hold-back episode if it returns.
        for sid in list(w.STATE.noip_holdback_reset_done):
            if sid not in present_stable_ids:
                w.STATE.noip_holdback_reset_done.discard(sid)


# ---- Manual adapter enable/disable + fault clearing (control API) ----

def adapter_disabled(w, stable_id: str) -> bool:
    """True when *stable_id* has been manually disabled by an operator."""
    if not stable_id:
        return False
    return stable_id in w.STATE.disabled_adapters


def disable_adapter(w, stable_id: str) -> None:
    """Manually disable an adapter until re-enabled (persists across restarts)."""
    if not stable_id:
        return
    with w.state_lock:
        added = stable_id not in w.STATE.disabled_adapters
        w.STATE.disabled_adapters.add(stable_id)
    if added:
        w.logger.info("Adapter %s manually disabled", stable_id)
        persist_adapter_fault_state(w)


def enable_adapter(w, stable_id: str) -> None:
    """Re-enable a previously disabled adapter."""
    if not stable_id:
        return
    with w.state_lock:
        removed = stable_id in w.STATE.disabled_adapters
        w.STATE.disabled_adapters.discard(stable_id)
    if removed:
        w.logger.info("Adapter %s manually re-enabled", stable_id)
        persist_adapter_fault_state(w)


def clear_adapter_fault_state(w, stable_id: str) -> None:
    """Clear an adapter's quarantine / reset / no-IP ledgers (after replacement or
    troubleshooting) so it starts fresh; does not change its enabled state."""
    if not stable_id:
        return
    with w.state_lock:
        had = (w.STATE.adapter_noip_ledgers.pop(stable_id, None) is not None)
        had = (w.STATE.adapter_reset_ledgers.pop(stable_id, None) is not None) or had
    if had:
        w.logger.info("Cleared fault ledgers for adapter %s", stable_id)
    persist_adapter_fault_state(w)


def is_degraded_no_ip(w, *, managed: bool, carrier: bool, healthy: bool,
                      stable_id: str) -> bool:
    """Overlay verdict: managed + carrier-up + not healthy + repeated no-IP failure.

    This is the DEGRADED_NO_IP determination — distinct
    from the transient ``connecting`` that wifi_status reports for a freshly
    associating adapter.  It requires an accumulated no-IP failure count so a
    single in-flight DHCP attempt is not misreported.
    """
    return bool(managed and carrier and not healthy and noip_failure_count(w, stable_id) > 0)


def diagnose_client_failure(w, adapters: list, active_client, conn_ok: bool,
                            prev_mac: str, prev_ifname: str) -> Optional[ClientFailed]:
    """Classify an active-USB client failure over the debounced verdict; event/None.

    A *pure classifier* over the loop's single connectivity hysteresis: it fires
    only once the debounced verdict has already condemned the active path
    (``conn_ok is False``), and only when that condemnation is attributable to the
    recorded USB client.  The hysteresis provides the debounce (NM-disconnected and
    carrier-up-no-IP are both *soft* — condemned after CONNECTIVITY_DOWN_DEBOUNCE
    passes; a vanished adapter is *hard* — condemned at once).
    ``prev_mac``/``prev_ifname`` are the identity recorded *before* this
    pass's _set_active_client (captured by finalize), so an adapter that has just
    disappeared is still attributable.  No STATE mutation, no effects — the loop
    applies the transition.
    """
    # The active path is fine (or held True through a transient blip): nothing to do.
    if conn_ok:
        return None

    recorded_usb = bool(prev_mac) and prev_mac in w._known_usb_macs
    if not recorded_usb:
        # The condemned path is not a recorded USB client (built-in / unconfigured
        # / genuinely nothing); reconnect and the dead-PHY ladder own those.
        return None

    recorded_usb_present = any(
        a.is_usb and a.permanent_mac == prev_mac for a in adapters
    )
    has_alt_path = wifi_net.resolve_builtin(adapters) is not None
    reason = "no_ip" if recorded_usb_present else "absent"
    ifname = active_client.ifname if active_client else prev_ifname
    w.logger.info("Recorded USB client %s condemned (%s); overlay ClientFailed(%s)",
                  prev_mac, "present" if recorded_usb_present else "absent", reason)
    return ClientFailed(ifname=ifname, mac=prev_mac,
                        reason=reason, has_alt_path=has_alt_path)


@dataclass(frozen=True)
class TargetAdapter:
    """The client adapter the dead-PHY ladder operates on this pass."""
    ifname: str
    stable_id: str             # active_client_mac/MAC when known, else sysfs/ifname fallback
    kind: str                  # "usb_wifi" | "builtin_wifi"
    is_usb: bool
    is_builtin: bool
    present_in_nm: bool
    present_in_sysfs: bool
    resettable_usb: bool


def build_target_adapter(w, ifname: str, adapters: list) -> TargetAdapter:
    """Resolve the per-pass facts for *ifname* into a TargetAdapter record."""
    nm = wifi_net.find_adapter_by_ifname(adapters, ifname)
    present_in_nm = nm is not None
    present_in_sysfs = ifname in wifi_net.list_sysfs_netdevs()
    usb_paths = wifi_net.usb_sysfs_paths(ifname) if present_in_sysfs else None
    resettable_usb = usb_paths is not None

    if nm is not None:
        is_usb = bool(nm.is_usb) or resettable_usb
        is_builtin = bool(nm.is_builtin) and not resettable_usb
        stable_id = nm.permanent_mac or wifi_net._sys_read_mac(ifname) or ifname
    else:
        is_usb = resettable_usb
        is_builtin = False
        stable_id = wifi_net._sys_read_mac(ifname) or ifname

    kind = "usb_wifi" if is_usb else "builtin_wifi"
    return TargetAdapter(
        ifname=ifname,
        stable_id=stable_id,
        kind=kind,
        is_usb=is_usb,
        is_builtin=is_builtin,
        present_in_nm=present_in_nm,
        present_in_sysfs=present_in_sysfs,
        resettable_usb=resettable_usb,
    )


def resolve_target_client(w, adapters: list) -> Optional[TargetAdapter]:
    """Resolve the dead-PHY target client adapter for this pass.

    Resolution order, most-specific first:
      1. STATE.active_client_mac mapped to a current NM device or sysfs netdev.
      2. STATE.active_client_ifname when present in discovery.
      3. the deterministic startup target: sole USB candidate, else built-in.
      4. AP_IFNAME ("wlan0") as a last-resort literal.
    """
    with w.state_lock:
        rec_mac = w.STATE.active_client_mac
        rec_ifname = w.STATE.active_client_ifname

    # 1. recorded MAC -> current interface (NM first, then sysfs-only).
    if rec_mac:
        adapter = wifi_net.find_adapter_by_mac(adapters, rec_mac)
        if adapter is not None:
            return build_target_adapter(w, adapter.ifname, adapters)
        sysfs_if = wifi_net.find_sysfs_netdev_by_mac(rec_mac)
        if sysfs_if:
            return build_target_adapter(w, sysfs_if, adapters)

    # 2. recorded ifname present in discovery.
    if rec_ifname and wifi_net.find_adapter_by_ifname(adapters, rec_ifname) is not None:
        return build_target_adapter(w, rec_ifname, adapters)

    # 3. deterministic startup target.
    usb = wifi_net.usb_candidates(adapters)
    if len(usb) == 1:
        return build_target_adapter(w, usb[0].ifname, adapters)
    builtin = wifi_net.resolve_builtin(adapters)
    if builtin is not None:
        return build_target_adapter(w, builtin.ifname, adapters)

    # 4. last-resort literal.
    return build_target_adapter(w, w.AP_IFNAME, adapters)


def _clear_dead_adapter_state_locked(w) -> None:
    """Clear the *active* dead/debounce/reset fields (assumes state_lock held)."""
    w.STATE.dead_adapter_ifname = ""
    w.STATE.dead_adapter_checks = 0
    w.STATE.dead_adapter_since = None
    w.STATE.last_reset_attempt = None
    w.STATE.last_reset_method = ""


def clear_dead_adapter_state(w) -> None:
    """Clear the active dead/debounce/reset fields (does not erase the ledger)."""
    with w.state_lock:
        _clear_dead_adapter_state_locked(w)


def _clear_active_dead_tracking_locked(w) -> None:
    """Clear active dead-PHY tracking state without touching accounting ledgers."""
    _clear_dead_adapter_state_locked(w)
    w.STATE.dead_adapter_first_failure = None
    w.STATE.dead_adapter_healthy_since = None


def _new_adapter_ledger() -> dict:
    return {"recent_resets": [], "total_resets": 0, "quarantined_until": None}


def _adapter_ledger_locked(w, target: Optional[TargetAdapter], create: bool = True) -> Optional[dict]:
    """Return the reset-accounting ledger for *target* (assumes state_lock held)."""
    if target is None or not target.stable_id:
        return None
    ledgers = w.STATE.adapter_reset_ledgers
    ledger = ledgers.get(target.stable_id)
    if ledger is None and create:
        ledger = _new_adapter_ledger()
        ledgers[target.stable_id] = ledger
    return ledger


def _prune_adapter_ledgers_locked(w, now: float) -> None:
    """Prune rolling reset windows and expired quarantine deadlines."""
    cutoff = now - w.USB_RESET_WINDOW
    expired = []
    for stable_id, ledger in list(w.STATE.adapter_reset_ledgers.items()):
        recent = ledger.get("recent_resets")
        if not isinstance(recent, list):
            recent = []
        ledger["recent_resets"] = [
            t for t in recent
            if isinstance(t, (int, float)) and not isinstance(t, bool) and t >= cutoff
        ]
        quarantined_until = ledger.get("quarantined_until")
        if (
            isinstance(quarantined_until, (int, float))
            and not isinstance(quarantined_until, bool)
            and now >= quarantined_until
        ):
            ledger["quarantined_until"] = None
        elif not isinstance(quarantined_until, (int, float)) or isinstance(quarantined_until, bool):
            ledger["quarantined_until"] = None
        total = int(ledger.get("total_resets", 0) or 0)
        if not ledger["recent_resets"] and ledger.get("quarantined_until") is None and total == 0:
            expired.append(stable_id)
    for stable_id in expired:
        w.STATE.adapter_reset_ledgers.pop(stable_id, None)


def adapter_reset_ledger_snapshot(w, target: Optional[TargetAdapter], now: float) -> dict:
    """Return a copy of the target ledger after pruning expired state."""
    with w.state_lock:
        _prune_adapter_ledgers_locked(w, now)
        ledger = _adapter_ledger_locked(w, target, create=False)
        if ledger is None:
            return _new_adapter_ledger()
        return {
            "recent_resets": list(ledger.get("recent_resets", [])),
            "total_resets": int(ledger.get("total_resets", 0) or 0),
            "quarantined_until": ledger.get("quarantined_until"),
        }


def adapter_quarantined_until(w, target: Optional[TargetAdapter], now: float) -> Optional[float]:
    """Return the active quarantine deadline for target, or None if expired/absent."""
    with w.state_lock:
        _prune_adapter_ledgers_locked(w, now)
        ledger = _adapter_ledger_locked(w, target, create=False)
        if ledger is None:
            return None
        quarantined_until = ledger.get("quarantined_until")
        if isinstance(quarantined_until, (int, float)) and not isinstance(quarantined_until, bool):
            return quarantined_until if now < quarantined_until else None
        return None


def update_dead_adapter_detection(w, adapters: list, target: Optional[TargetAdapter]) -> bool:
    """Advance/clear the debounce; return True when the adapter is classed dead.

    A target that is present (in sysfs or NM), link-down, and not a healthy
    client increments the debounce; reaching DEAD_ADAPTER_DEBOUNCE declares the
    adapter dead.  A sustained-healthy pass clears the active fields.  A change
    of stable identity resets active debounce/timing state but leaves adapter
    accounting ledgers isolated by stable_id.
    """
    now = time.monotonic()
    if target is None:
        clear_dead_adapter_state(w)
        return False

    link_down = wifi_net.read_link_down(target.ifname)
    present = target.present_in_sysfs or target.present_in_nm
    healthy = (
        w.is_wifi_client_healthy(target.ifname) if target.present_in_nm else False
    )
    down_unhealthy = bool(present and link_down is True and not healthy)

    declared_now = False
    checks = 0
    with w.state_lock:
        prev_id = w.STATE.dead_adapter_stable_id
        if prev_id and prev_id != target.stable_id:
            w.logger.debug(
                "Dead-PHY target identity changed (%s -> %s); resetting active state",
                prev_id, target.stable_id,
            )
            _clear_active_dead_tracking_locked(w)
        w.STATE.dead_adapter_stable_id = target.stable_id

        if not down_unhealthy:
            _clear_dead_adapter_state_locked(w)
            if healthy:
                if w.STATE.dead_adapter_healthy_since is None:
                    w.STATE.dead_adapter_healthy_since = now
                elif (now - w.STATE.dead_adapter_healthy_since) >= w.DEAD_ADAPTER_HEALTHY_DECAY:
                    _clear_active_dead_tracking_locked(w)
            else:
                w.STATE.dead_adapter_healthy_since = None
            return False

        w.STATE.dead_adapter_healthy_since = None
        if w.STATE.dead_adapter_first_failure is None:
            w.STATE.dead_adapter_first_failure = now
        w.STATE.dead_adapter_checks += 1
        checks = w.STATE.dead_adapter_checks
        if checks >= w.DEAD_ADAPTER_DEBOUNCE:
            if not w.STATE.dead_adapter_ifname:
                declared_now = True
            w.STATE.dead_adapter_ifname = target.ifname
            if w.STATE.dead_adapter_since is None:
                w.STATE.dead_adapter_since = now
            result = True
        else:
            result = False

    if declared_now:
        w.logger.info(
            "Wi-Fi adapter %s wedged (link-down x%d); attempting USB reset",
            target.ifname, checks,
        )
    else:
        w.logger.debug(
            "Dead-PHY debounce on %s: %d/%d", target.ifname, checks, w.DEAD_ADAPTER_DEBOUNCE,
        )
    return result


def adapter_reset_budget_exhausted(w, target: Optional[TargetAdapter], now: float) -> bool:
    """True when the adapter has hit either the per-window or total reset budget.

    The *policy* decision (quarantine vs. emergency-only retry) lives in the
    ladder; this reports only whether the budget is spent.
    """
    with w.state_lock:
        _prune_adapter_ledgers_locked(w, now)
        ledger = _adapter_ledger_locked(w, target)
        recent = len(ledger["recent_resets"]) if ledger else 0
        total = int(ledger.get("total_resets", 0) or 0) if ledger else 0
    exhausted = recent >= w.USB_MAX_RESETS_PER_WINDOW or total >= w.USB_MAX_RESETS_TOTAL
    if exhausted:
        w.logger.debug(
            "Reset budget exhausted for %s: recent=%d/%d total=%d/%d",
            target.ifname if target else "?", recent, w.USB_MAX_RESETS_PER_WINDOW,
            total, w.USB_MAX_RESETS_TOTAL,
        )
    return exhausted


def record_adapter_reset(w, target: Optional[TargetAdapter], now: float) -> None:
    """Record one reset attempt against the rolling/total budgets."""
    with w.state_lock:
        _prune_adapter_ledgers_locked(w, now)
        ledger = _adapter_ledger_locked(w, target)
        if ledger is None:
            return
        ledger["recent_resets"].append(now)
        ledger["total_resets"] = int(ledger.get("total_resets", 0) or 0) + 1
        recent = len(ledger["recent_resets"])
        total = ledger["total_resets"]
    w.logger.debug(
        "Recorded USB reset for %s: recent=%d total=%d",
        target.ifname if target else "?", recent, total,
    )
    persist_adapter_fault_state(w)


def maybe_reset_noip_held_usb(w, adapters: list, now: float) -> bool:
    """Spend one budgeted USB reset on an idle no-IP-held spare before the
    hold-back becomes final.

    The dead-PHY reset ladder only ever targets the *active* client, so an idle
    USB spare that repeatedly associates but cannot get an IP is held back by the
    no-IP ledger without the watcher ever attempting the one cheap hardware
    remediation it has (the field unit showed "held back … Reset attempts: 0").
    When such a spare is at the final hold-back (no-IP count >= NOIP_STOP_AFTER),
    resettable, still has reset budget, and has not already spent its one
    hold-back reset this episode, perform one reset (accounted against the normal
    reset budget/quarantine ledger) and clear its no-IP suppression so the normal
    adoption path gets a fresh attempt.  If the reset does not bring it to a
    joinable state it re-accumulates and the hold-back proceeds — the
    holdback-reset-done flag prevents a second reset.  Returns True when a reset
    was spent (the caller owns the pass; this is a blocking effect like the
    dead-PHY reset).  The caller must gate on a healthy device (conn_ok) so only
    idle spares — never the active path — are reset here.
    """
    for a in adapters:
        if not getattr(a, "is_usb", False) or not a.stable_id:
            continue
        if adapter_disabled(w, a.stable_id):
            continue
        if noip_failure_count(w, a.stable_id) < NOIP_STOP_AFTER:
            continue
        with w.state_lock:
            already = a.stable_id in w.STATE.noip_holdback_reset_done
        if already:
            continue
        target = build_target_adapter(w, a.ifname, adapters)
        if not target.resettable_usb:
            continue
        if adapter_reset_budget_exhausted(w, target, now):
            continue
        w.logger.info(
            "No-IP hold-back on idle USB %s: spending one budgeted reset before "
            "finalising the hold-back", a.ifname)
        record_adapter_reset(w, target, now)
        wifi_net.reset_usb_adapter_rebind(a.ifname)
        with w.state_lock:
            w.STATE.noip_holdback_reset_done.add(a.stable_id)
        # Fresh adoption chance: clear the no-IP suppression (the reset may have
        # fixed the hardware).  A renewed failure re-accumulates and re-suppresses,
        # but the holdback-reset-done flag blocks a second reset this episode.
        clear_noip_failures(w, a.stable_id)
        return True
    return False


# ---- Shared per-adapter recovery facts (recovery-ladder unification) ----
#
# One place that derives the per-adapter health/budget/quarantine/no-IP facts the
# recovery ladder and the status snapshot both need.  Consumed by
# wifi_status.build_network_status_snapshot (presentation) and by the watcher's
# per-pass recovery-facts gatherer that feeds the pure next_recovery_action
# classifier — keeping a single source of truth for "is this adapter usable".


@dataclass(frozen=True)
class AdapterRecoveryFacts:
    """Per-adapter facts the recovery ladder reasons over (pure data)."""
    ifname: str
    stable_id: str
    kind: str                 # "usb_wifi" | "builtin_wifi" | passthrough
    is_usb: bool
    is_builtin: bool
    managed: bool
    healthy: bool
    link_down: Optional[bool]
    carrier: bool
    quarantined_until: Optional[float]
    quarantined: bool
    recent_reset_count: int
    total_reset_count: int
    budget_exhausted: bool
    noip_count: int
    noip_suppressed: bool
    is_no_ip: bool
    disabled: bool


def adapter_recovery_facts(w, a, now_monotonic: float, health_fn=None) -> AdapterRecoveryFacts:
    """Derive the shared recovery facts for one discovered adapter *a*.

    Reuses the reset/quarantine/no-IP ledgers so the recovery classifier and the
    status snapshot agree exactly.  Pure w.r.t. STATE (reads ledgers, does not
    mutate); performs the same fact reads (health, link state) the snapshot did.

    ``health_fn`` is the optional per-pass health memo: when supplied it
    samples ``is_wifi_client_healthy`` at most once per (pass, ifname), so the
    recovery classifier and the status snapshot see the *same* health verdict in
    a pass.  When absent (ad-hoc calls) it falls back to a fresh sample.
    """
    health = health_fn or w.is_wifi_client_healthy
    healthy = bool(a.managed and health(a.ifname))
    link_down = wifi_net.read_link_down(a.ifname)
    carrier = (link_down is False)
    kind = a.kind + ("_wifi" if a.kind in ("usb", "builtin") else "")
    target = TargetAdapter(
        ifname=a.ifname,
        stable_id=a.stable_id,
        kind=kind,
        is_usb=bool(a.is_usb),
        is_builtin=bool(a.is_builtin),
        present_in_nm=True,
        present_in_sysfs=True,
        resettable_usb=bool(a.is_usb),
    )
    ledger = adapter_reset_ledger_snapshot(w, target, now_monotonic)
    quarantined_until = adapter_quarantined_until(w, target, now_monotonic)
    recent = len(ledger.get("recent_resets", []))
    total = int(ledger.get("total_resets", 0) or 0)
    budget_exhausted = (
        recent >= w.USB_MAX_RESETS_PER_WINDOW or total >= w.USB_MAX_RESETS_TOTAL
    )
    return AdapterRecoveryFacts(
        ifname=a.ifname,
        stable_id=a.stable_id,
        kind=kind,
        is_usb=bool(a.is_usb),
        is_builtin=bool(a.is_builtin),
        managed=bool(a.managed),
        healthy=healthy,
        link_down=link_down,
        carrier=carrier,
        quarantined_until=quarantined_until,
        quarantined=quarantined_until is not None,
        recent_reset_count=recent,
        total_reset_count=total,
        budget_exhausted=budget_exhausted,
        noip_count=noip_failure_count(w, a.stable_id),
        noip_suppressed=noip_retry_suppressed(w, a.stable_id, now_monotonic),
        is_no_ip=is_degraded_no_ip(
            w, managed=a.managed, carrier=carrier, healthy=healthy,
            stable_id=a.stable_id,
        ),
        disabled=adapter_disabled(w, a.stable_id),
    )


# ---- Persistent dead-PHY reboot guard (cross-boot loop prevention) ----

def _empty_reboot_guard(now_wall: float) -> dict:
    return {"schema_version": 1, "window_started_at": now_wall, "requests": []}


def read_dead_phy_reboot_guard(w, now_wall: float) -> dict:
    """Read and prune the persistent reboot-guard file (wall-clock).

    Requests older than DEAD_ADAPTER_REBOOT_WINDOW are discarded; if none
    remain a fresh window is started.  Corrupt/unreadable files are treated as
    empty but logged at WARNING.
    """
    try:
        with open(w.DEAD_ADAPTER_REBOOT_STAMP, "r", encoding="utf-8") as f:
            obj = json.load(f)
    except FileNotFoundError:
        return _empty_reboot_guard(now_wall)
    except (OSError, ValueError) as e:
        w.logger.warning("Dead-PHY reboot guard unreadable (%s); treating as empty", e)
        return _empty_reboot_guard(now_wall)

    if not isinstance(obj, dict) or obj.get("schema_version") != 1:
        w.logger.warning("Dead-PHY reboot guard has unexpected schema; treating as empty")
        return _empty_reboot_guard(now_wall)

    reqs = obj.get("requests")
    if not isinstance(reqs, list):
        reqs = []
    cutoff = now_wall - w.DEAD_ADAPTER_REBOOT_WINDOW
    retained = [
        r for r in reqs
        if isinstance(r, dict)
        and isinstance(r.get("requested_at"), (int, float))
        and not isinstance(r.get("requested_at"), bool)
        and r["requested_at"] >= cutoff
    ]
    started = obj.get("window_started_at")
    if not retained or not isinstance(started, (int, float)) or isinstance(started, bool):
        started = now_wall
    return {"schema_version": 1, "window_started_at": started, "requests": retained}


def dead_phy_reboot_guard_permits(w, now_wall: float) -> bool:
    """True when fewer than the cross-boot cap of retained requests exist."""
    guard = read_dead_phy_reboot_guard(w, now_wall)
    count = len(guard["requests"])
    permitted = count < w.DEAD_ADAPTER_MAX_REBOOTS_PER_WINDOW
    if not permitted:
        w.logger.debug(
            "Dead-PHY reboot guard: %d requests in window (cap %d); suppressing",
            count, w.DEAD_ADAPTER_MAX_REBOOTS_PER_WINDOW,
        )
    return permitted


def record_dead_phy_reboot_request(w, now_wall: float, target: Optional[TargetAdapter]) -> None:
    """Append a reboot request and atomically persist the guard file."""
    guard = read_dead_phy_reboot_guard(w, now_wall)
    guard["requests"].append({
        "requested_at": now_wall,
        "ifname": target.ifname if target else "",
        "stable_id": target.stable_id if target else "",
    })
    try:
        directory = os.path.dirname(w.DEAD_ADAPTER_REBOOT_STAMP) or "."
        os.makedirs(directory, exist_ok=True)
        wifi_net._atomic_write(
            w.DEAD_ADAPTER_REBOOT_STAMP, json.dumps(guard, indent=2) + "\n", mode=0o644,
        )
    except OSError as e:
        w.logger.warning("Could not persist dead-PHY reboot guard: %s", e)


# ---- Persistent per-stable-id fault state (no-IP + reset/quarantine ledgers) ----
#
# The two in-memory ledgers use *monotonic* deadlines, which reset on reboot; to
# persist them across a restart we store each timestamp as wall-clock and, on
# load, translate it back onto the current monotonic clock accounting for real
# elapsed time (including downtime), then prune by the same rolling windows.
# Tolerant parsing throughout: any malformed/absent file loads as "no state".

ADAPTER_FAULT_STATE_SCHEMA = 1
_INF_SENTINEL = "inf"


def _mono_to_wall(t, now_mono: float, now_wall: float):
    """Translate a monotonic timestamp to wall-clock (None / inf pass through)."""
    if t is None:
        return None
    if t == float("inf"):
        return _INF_SENTINEL
    if not isinstance(t, (int, float)) or isinstance(t, bool):
        return None
    return now_wall - (now_mono - t)


def _wall_to_mono(w_ts, now_mono: float, now_wall: float):
    """Translate a persisted wall-clock timestamp back onto the monotonic clock."""
    if w_ts is None:
        return None
    if w_ts == _INF_SENTINEL:
        return float("inf")
    try:
        return now_mono - (now_wall - float(w_ts))
    except (TypeError, ValueError):
        return None


def persist_adapter_fault_state(w) -> None:
    """Atomically write the no-IP + reset ledgers with wall-clock timestamps."""
    now_mono = time.monotonic()
    now_wall = time.time()
    with w.state_lock:
        noip = {
            sid: {
                "count": int(led.get("count", 0) or 0),
                "retry_after": _mono_to_wall(led.get("retry_after"), now_mono, now_wall),
            }
            for sid, led in w.STATE.adapter_noip_ledgers.items()
        }
        reset = {}
        for sid, led in w.STATE.adapter_reset_ledgers.items():
            reset[sid] = {
                "recent_resets": [
                    _mono_to_wall(t, now_mono, now_wall)
                    for t in led.get("recent_resets", []) or []
                ],
                "total_resets": int(led.get("total_resets", 0) or 0),
                "quarantined_until": _mono_to_wall(led.get("quarantined_until"), now_mono, now_wall),
            }
    with w.state_lock:
        disabled = sorted(str(s) for s in w.STATE.disabled_adapters)
    data = {
        "schema_version": ADAPTER_FAULT_STATE_SCHEMA,
        "saved_at": now_wall,
        "noip_ledgers": noip,
        "reset_ledgers": reset,
        "disabled_adapters": disabled,
    }
    try:
        directory = os.path.dirname(w.ADAPTER_FAULT_STATE_PATH) or "."
        os.makedirs(directory, exist_ok=True)
        wifi_net._atomic_write(
            w.ADAPTER_FAULT_STATE_PATH, json.dumps(data, indent=2) + "\n", mode=0o644)
    except OSError as e:
        w.logger.warning("Could not persist adapter fault state: %s", e)


def load_adapter_fault_state(w) -> None:
    """Load the persisted ledgers, translating wall-clock -> monotonic and pruning
    by the rolling windows.  Any malformed/absent file is a no-op."""
    try:
        with open(w.ADAPTER_FAULT_STATE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return
    if not isinstance(data, dict) or data.get("schema_version") != ADAPTER_FAULT_STATE_SCHEMA:
        return
    now_mono = time.monotonic()
    now_wall = time.time()

    noip_out: dict = {}
    noip_in = data.get("noip_ledgers")
    if isinstance(noip_in, dict):
        for sid, led in noip_in.items():
            if not isinstance(led, dict):
                continue
            count = int(led.get("count", 0) or 0)
            if count <= 0:
                continue
            # retry_after is derivable from count for the suppressed case; a
            # finite deadline that already elapsed during downtime is not carried.
            if count >= NOIP_STOP_AFTER:
                retry_after = float("inf")
            else:
                m = _wall_to_mono(led.get("retry_after"), now_mono, now_wall)
                retry_after = m if (isinstance(m, float) and m > now_mono) else 0.0
            noip_out[sid] = {"count": count, "retry_after": retry_after}

    reset_out: dict = {}
    reset_in = data.get("reset_ledgers")
    if isinstance(reset_in, dict):
        for sid, led in reset_in.items():
            if not isinstance(led, dict):
                continue
            recent = []
            for wt in led.get("recent_resets", []) or []:
                m = _wall_to_mono(wt, now_mono, now_wall)
                if m is not None and m != float("inf") and (now_mono - m) <= w.USB_RESET_WINDOW:
                    recent.append(m)
            total = int(led.get("total_resets", 0) or 0)
            q = _wall_to_mono(led.get("quarantined_until"), now_mono, now_wall)
            if q is not None and q != float("inf") and now_mono >= q:
                q = None
            if recent or total or q is not None:
                reset_out[sid] = {
                    "recent_resets": recent,
                    "total_resets": total,
                    "quarantined_until": q,
                }

    disabled_in = data.get("disabled_adapters")
    disabled_out = set(str(s) for s in disabled_in) if isinstance(disabled_in, list) else set()

    with w.state_lock:
        w.STATE.adapter_noip_ledgers = noip_out
        w.STATE.adapter_reset_ledgers = reset_out
        w.STATE.disabled_adapters = disabled_out
    w.logger.info(
        "Loaded persisted adapter fault state: %d no-IP, %d reset ledger(s), %d disabled",
        len(noip_out), len(reset_out), len(disabled_out))


# ---- Dead-PHY recovery ladder ----

def wait_for_interface_reappears(w, target: TargetAdapter,
                                 timeout: float = INTERFACE_REAPPEAR_TIMEOUT) -> str:
    """Poll sysfs + NM discovery for the target to reappear after a reset.

    Rediscovers by stable identity/MAC (NetworkManager), then by ifname in NM,
    then by sysfs MAC, then by sysfs ifname — in that order.  Returns the
    resolved ifname (which may differ from the original) or "".  Does NOT wait
    for ``operstate up``; after a reset the interface can remain down/dormant
    until activation starts (~4-6s to firmware reload/association on the field
    unit).
    """
    deadline = time.monotonic() + timeout
    stable = target.stable_id
    while True:
        adapters = wifi_net.discover_adapters()
        by_mac = wifi_net.find_adapter_by_mac(adapters, stable)
        if by_mac is not None:
            return by_mac.ifname
        by_if = wifi_net.find_adapter_by_ifname(adapters, target.ifname)
        if by_if is not None:
            return by_if.ifname
        sysfs_if = wifi_net.find_sysfs_netdev_by_mac(stable)
        if sysfs_if:
            return sysfs_if
        if target.ifname in wifi_net.list_sysfs_netdevs():
            return target.ifname
        if time.monotonic() >= deadline:
            return ""
        time.sleep(1.0)


def _other_network_path_available(w, adapters: list, target: TargetAdapter,
                                  wired_connected: bool) -> bool:
    """True when a usable network path other than *target* exists."""
    if wired_connected:
        return True
    for a in adapters:
        if a.ifname == target.ifname:
            continue
        if a.managed and w.is_wifi_client_healthy(a.ifname):
            return True
    return False


def _perform_reset_step(w, target: TargetAdapter, now: float) -> bool:
    """Run one USB reset step (cycling A->B->A), then rediscover and reconnect.

    Always returns True: the reset attempt owns the monitor pass regardless of
    outcome.

    This dead-PHY USB rebind/re-enumerate plus wait_for_interface_reappears (up to
    INTERFACE_REAPPEAR_TIMEOUT ~15 s) is a *second* thing that blocks the monitor
    loop, distinct from the worker activation join.  It is
    deliberately left synchronous: it is a different effect family (USB
    rebind/reenumerate) with its own budget/quarantine/reboot ladder, and folding
    it onto the worker widens the blast radius for little gain (a wedged reset is
    already backstopped by the loop's guarded reboot ladder, which keeps running
    because the loop never blocks on the worker).  step_dead_phy_recovery is gated
    on STATE.transitioning, so a reset never overlaps a worker activation — only
    one blocking effect runs at a time.
    """
    with w.state_lock:
        method = "B" if w.STATE.last_reset_method == "A" else "A"

    w.logger.info("USB reset (method %s) attempted on %s", method, target.ifname)
    if method == "A":
        ok = wifi_net.reset_usb_adapter_rebind(target.ifname)
    else:
        # Method B is the defensive fallback re-enumeration.
        ok = wifi_net.reset_usb_adapter_reenumerate(target.ifname)

    record_adapter_reset(w, target, now)
    with w.state_lock:
        w.STATE.last_reset_attempt = now
        w.STATE.last_reset_method = method

    if not ok:
        w.logger.warning("USB reset (method %s) failed on %s; escalating", method, target.ifname)
        return True

    new_ifname = w.wait_for_interface_reappears(target)
    if not new_ifname:
        w.logger.warning("USB reset (method %s): %s did not reappear", method, target.ifname)
        return True

    if w._activate_committed_on(new_ifname):
        w.logger.info("USB reset (method %s) recovered %s", method, new_ifname)
        adapters = wifi_net.discover_adapters()
        recovered = wifi_net.find_adapter_by_ifname(adapters, new_ifname)
        # Shared handover tail: set the recovered adapter active, clear the
        # builtin-fallback flag and dead-PHY recovery state, leave setup if it was
        # up (leave_setup_mode no-ops otherwise), and re-announce mDNS.
        w.client_up_tail(
            recovered,
            set_builtin_fallback=False,
            clear_dead_adapter=True,
            leave_setup_reason="dead-PHY recovered via USB reset",
        )
    return True


def _maybe_request_dead_phy_reboot(w, target: TargetAdapter, now: float) -> bool:
    """Request a guarded NetworkDown reboot when offline and dead >= threshold.

    Returns True only when a reboot was accepted (owns the pass).  When the
    persistent guard or in-process rate limit suppresses the reboot, returns
    False so the monitor loop's no-active-path catch-all can still apply.  The
    guard/throttle/stamp mechanics live in the shared request_guarded_reboot;
    this function owns only the dead-for threshold and the target.
    """
    with w.state_lock:
        first_failure = w.STATE.dead_adapter_first_failure
    base = first_failure if first_failure is not None else now
    dead_for = now - base
    if dead_for < w.DEAD_ADAPTER_REBOOT_AFTER:
        return False

    reason = ("Dead Wi-Fi adapter %s offline > %ds"
              % (target.ifname, w.DEAD_ADAPTER_REBOOT_AFTER))
    return w.request_guarded_reboot(now, reason, domain="dead_phy", target=target)


def escalate_dead_adapter_recovery(w, adapters: list, wired_connected: bool) -> bool:
    """Run one step of the dead-PHY recovery ladder.

    Resolves the target client, advances dead detection, and — when the adapter
    is dead — steps the ladder: built-in fallback -> USB reset (Method A/B) ->
    quarantine/backoff -> guarded reboot (offline only).  Returns True when an
    action owned this pass (the caller should sleep and ``continue``).
    """
    now = time.monotonic()
    target = resolve_target_client(w, adapters)
    dead = update_dead_adapter_detection(w, adapters, target)
    if not dead or target is None:
        return False

    # An operator-disabled adapter is never reset — leave it down until re-enabled.
    if adapter_disabled(w, target.stable_id):
        w.logger.debug("Dead-PHY: %s is manually disabled; skipping reset ladder",
                       target.ifname)
        return False

    # (1) Setup-mode: defer only to a working AP on a *different* adapter.  On
    # single-radio hardware whose sole radio is the dead target, do NOT suppress
    # recovery forever — reset it instead of leaving a dead hotspot.
    with w.state_lock:
        in_setup = w.STATE.setup_mode
    if in_setup:
        hotspot = w.resolve_hotspot_adapter(adapters)
        if hotspot is not None and hotspot.ifname != target.ifname:
            w.logger.debug(
                "Dead-PHY: AP active on %s; deferring recovery of %s",
                hotspot.ifname, target.ifname,
            )
            return False
        w.logger.warning(
            "Single-radio hotspot cannot start because the only radio %s appears "
            "dead; using USB reset ladder instead", target.ifname,
        )

    # (2) Built-in client fallback when a *separate* built-in radio is present.
    builtin = wifi_net.resolve_builtin(adapters)
    if builtin is not None and builtin.ifname != target.ifname:
        if w._activate_committed_on(builtin.ifname):
            w.logger.info("Dead-PHY: built-in fallback selected and connected on %s",
                          builtin.ifname)
            # Shared handover tail: set the built-in active, mark the
            # builtin-fallback flag, clear dead-PHY recovery state, verify avahi.
            w.client_up_tail(
                builtin,
                set_builtin_fallback=True,
                clear_dead_adapter=True,
            )
            return True

    other_path = _other_network_path_available(w, adapters, target, wired_connected)

    # (3)/(4)/(5) USB reset rungs — only a resettable USB target can be reset.
    if target.resettable_usb:
        budget_spent = adapter_reset_budget_exhausted(w, target, now)
        if budget_spent and other_path:
            # (3) Quarantine for preferred client use; keep publishing degraded
            # status and let the normal loop logic run.
            with w.state_lock:
                _prune_adapter_ledgers_locked(w, now)
                ledger = _adapter_ledger_locked(w, target)
                current = ledger.get("quarantined_until") if ledger else None
                newly = not (
                    isinstance(current, (int, float))
                    and not isinstance(current, bool)
                    and now < current
                )
                if ledger is not None:
                    ledger["quarantined_until"] = now + w.USB_RESET_WINDOW
            if newly:
                w.logger.info(
                    "USB adapter %s quarantined for preferred client use "
                    "(reset budget exhausted; alternate path available)", target.ifname,
                )
            return False

        # (4) Emergency-only slow backoff when this USB is the only path;
        # (5) otherwise the normal reset cadence.
        interval = w.USB_EMERGENCY_BACKOFF if budget_spent else w.RESET_ATTEMPT_INTERVAL
        with w.state_lock:
            last = w.STATE.last_reset_attempt
        due = last is None or (now - last) >= interval
        if due:
            if budget_spent:
                w.logger.info(
                    "USB adapter %s reset budget exhausted but no other path; "
                    "slow emergency reset attempt", target.ifname,
                )
            return _perform_reset_step(w, target, now)

    # (6) Reboot escalation — only when genuinely offline.
    if not wired_connected and _maybe_request_dead_phy_reboot(w, target, now):
        return True

    return False
