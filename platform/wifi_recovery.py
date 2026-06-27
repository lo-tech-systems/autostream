#!/usr/bin/python3
"""wifi_recovery.py

Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

Dead-PHY recovery policy for the Autostream Wi-Fi watcher (dead-PHY recovery
plan, WP8 split of platform/wifi_watcher).

This module owns adapter health classification for the dead-PHY case, the reset
budget / quarantine ledger, the persistent cross-boot reboot guard, and the
recovery-action ladder.  The bounded sysfs primitives live in
``core/autostream_wifi_network`` (WP1).

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
from typing import Optional

import autostream_wifi_network as wifi_net

INTERFACE_REAPPEAR_TIMEOUT = 15  # seconds to wait for a netdev after a USB reset


@dataclass(frozen=True)
class TargetAdapter:
    """The client adapter the dead-PHY ladder operates on this pass (Section 5.1)."""
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
    """Resolve the dead-PHY target client adapter for this pass (Section 5.1).

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


# ---- Persistent dead-PHY reboot guard (cross-boot loop prevention, Section 4) ----

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
        if recovered is not None:
            w._set_active_client(recovered)
        with w.state_lock:
            w.STATE.using_builtin_fallback = False
            in_setup = w.STATE.setup_mode
        clear_dead_adapter_state(w)
        if in_setup:
            w.leave_setup_mode("dead-PHY recovered via USB reset")
        w.verify_avahi_after_handover()
    return True


def _maybe_request_dead_phy_reboot(w, target: TargetAdapter, now: float) -> bool:
    """Request a guarded NetworkDown reboot when offline and dead >= threshold.

    Returns True only when a reboot was accepted (owns the pass).  When the
    persistent guard or in-process rate limit suppresses the reboot, returns
    False so the monitor loop's no-active-path catch-all can still apply.
    """
    with w.state_lock:
        first_failure = w.STATE.dead_adapter_first_failure
        retry_after = w.STATE.conn_reboot_retry_after
    base = first_failure if first_failure is not None else now
    dead_for = now - base
    if dead_for < w.DEAD_ADAPTER_REBOOT_AFTER:
        return False

    now_wall = time.time()
    if not dead_phy_reboot_guard_permits(w, now_wall):
        w.logger.warning(
            "Persistent dead-PHY reboot guard suppresses reboot for %s; "
            "leaving no-active-path catch-all in effect", target.ifname,
        )
        return False

    if now < retry_after:
        if retry_after == float('inf'):
            w.logger.debug("Dead-PHY NetworkDown reboot accepted; awaiting reboot")
        else:
            w.logger.debug("Dead-PHY reboot suppressed (in-process); retry in %.0fs",
                           retry_after - now)
        return False

    w.logger.warning(
        "Dead Wi-Fi adapter %s offline > %ds; requesting reboot",
        target.ifname, w.DEAD_ADAPTER_REBOOT_AFTER,
    )
    accepted = w.reboot_system("NetworkDown")
    with w.state_lock:
        w.STATE.conn_reboot_retry_after = (
            float('inf') if accepted else now + w.REBOOT_RATE_LIMIT_RETRY
        )
    if accepted:
        record_dead_phy_reboot_request(w, now_wall, target)
        return True
    return False


def escalate_dead_adapter_recovery(w, adapters: list, wired_connected: bool) -> bool:
    """Run one step of the dead-PHY recovery ladder (Section 3).

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
            with w.state_lock:
                w.STATE.using_builtin_fallback = True
            w._set_active_client(builtin)
            clear_dead_adapter_state(w)
            w.verify_avahi_after_handover()
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
