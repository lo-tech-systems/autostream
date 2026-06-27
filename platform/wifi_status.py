#!/usr/bin/python3
"""wifi_status.py

Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

Runtime network-status snapshot construction for the Autostream Wi-Fi watcher
(dead-PHY recovery plan, WP8 split of platform/wifi_watcher).

This module builds the nested ``schema_version: 1`` snapshot from facts plus the
watcher's recovery state and publishes it atomically.  All derived meaning
(device.state, health.state, policy.action, primary-adapter selection,
stale/unknown interpretation) is platform policy and lives here — never in
``core/autostream_wifi_network.py``.

To keep the extraction mechanical and behaviour-preserving, the public builders
take the watcher module ``w`` as their first argument and read its STATE,
constants, and fact helpers through it.  ``autostream_wifi_network`` is imported
directly because it is a shared module object (patching it affects both modules).
"""
from __future__ import annotations

import logging
import time
from typing import Optional

import autostream_wifi_network as wifi_net

logger = logging.getLogger(__name__)

# Module-level latch so the schema-initialised line is logged once.
_status_schema_logged = False


def _effective_log_level_name(w) -> str:
    """Return the effective runtime log level name (warning/info/debug)."""
    with w.state_lock:
        temp = w.STATE.temporary_log_level
        default = w.STATE.default_log_level_name
    if temp:
        return temp
    return default or "info"


def _primary_addresses(addresses: dict, ifname: str) -> tuple[str, str]:
    """Return (primary_ipv4, primary_ipv6) preferring global over link-local."""
    ipv4 = ""
    ipv6 = ""
    for a in addresses.get(ifname, []):
        if a["family"] == "ipv4":
            if a.get("scope") == "global" and not ipv4:
                ipv4 = a["address"]
        elif a["family"] == "ipv6":
            if a.get("scope") == "global" and not ipv6:
                ipv6 = a["address"]
    return ipv4, ipv6


def _adapter_ip_lists(addresses: dict, ifname: str) -> tuple[list, list]:
    v4 = [a for a in addresses.get(ifname, []) if a["family"] == "ipv4"]
    v6 = [a for a in addresses.get(ifname, []) if a["family"] == "ipv6"]
    return v4, v6


def _classify_adapter_health(*, present, managed, carrier, healthy, nm_state,
                             is_dead, is_link_down, quarantined, is_hotspot):
    """Map facts + recovery flags to a defined adapter health state/severity."""
    if not present:
        state = "absent"
    elif is_hotspot:
        state = "hotspot_active"
    elif not managed:
        state = "unmanaged"
    elif quarantined:
        state = "quarantined"
    elif is_dead:
        state = "dead_phy"
    elif healthy:
        state = "healthy"
    elif is_link_down:
        state = "link_down"
    elif nm_state in ("connecting", "config", "ip-config", "prepare", "need-auth"):
        state = "connecting"
    elif nm_state in ("connected", "activated"):
        # NM-connected but not a usable client (no gateway yet).
        state = "degraded"
    else:
        state = "idle"

    ok_states = {"healthy", "idle", "connecting", "hotspot_active"}
    severity = "ok" if state in ok_states else "degraded"
    return state, severity


def build_network_status_snapshot(w, adapters: Optional[list] = None,
                                  wired_connected: Optional[bool] = None) -> dict:
    """Build the schema_version:1 runtime network-status snapshot.

    Uses the watcher's facts and the dead-PHY recovery ledger.  All derived
    meaning is computed here (platform policy); core only supplies facts.
    """
    if adapters is None:
        try:
            adapters = wifi_net.discover_adapters()
        except Exception:
            adapters = []
    if wired_connected is None:
        wired_connected = w.is_wired_connected()

    addresses = wifi_net.list_interface_addresses()
    now_wall = time.time()

    with w.state_lock:
        active_ifname = w.STATE.active_client_ifname
        active_mac = w.STATE.active_client_mac
        using_fallback = w.STATE.using_builtin_fallback
        in_setup = w.STATE.setup_mode
        dead_ifname = w.STATE.dead_adapter_ifname
        dead_since = w.STATE.dead_adapter_since
        dead_checks = w.STATE.dead_adapter_checks
        quarantined_until = w.STATE.dead_adapter_quarantined_until
        last_reset_method = w.STATE.last_reset_method
        last_reset_attempt = w.STATE.last_reset_attempt
        recent_resets = list(w.STATE.dead_adapter_recent_resets)
        reboot_retry_after = w.STATE.conn_reboot_retry_after
        temp_expires = w.STATE.temporary_log_level_until
        default_level = w.STATE.default_log_level_name

    hotspot_adapter = w.resolve_hotspot_adapter(adapters)
    hotspot_ifname = hotspot_adapter.ifname if (in_setup and hotspot_adapter) else ""

    adapter_records = []
    any_healthy = False
    any_unhealthy = False
    for a in adapters:
        healthy = a.managed and w.is_wifi_client_healthy(a.ifname)
        link_down = wifi_net.read_link_down(a.ifname)
        operstate = wifi_net.read_operstate(a.ifname)
        carrier = (link_down is False)
        is_dead = (a.ifname == dead_ifname)
        is_hotspot = (a.ifname == hotspot_ifname)
        quarantined = bool(quarantined_until) and is_dead
        v4, v6 = _adapter_ip_lists(addresses, a.ifname)

        if healthy:
            any_healthy = True
        elif a.managed and not is_hotspot:
            any_unhealthy = True

        gw_ipv4 = wifi_net.default_gateway_ipv4(a.ifname)
        gw_reachable = w.is_gateway_reachable(a.ifname) if gw_ipv4 else False

        state, severity = _classify_adapter_health(
            present=True, managed=a.managed, carrier=carrier, healthy=healthy,
            nm_state=a.state, is_dead=is_dead, is_link_down=(link_down is True),
            quarantined=quarantined, is_hotspot=is_hotspot,
        )

        if is_hotspot:
            role = "hotspot"
        elif a.ifname == active_ifname or (active_mac and a.permanent_mac == active_mac):
            role = "client"
        else:
            role = "idle"

        if quarantined:
            action = "quarantined"
            next_after = quarantined_until
        elif is_dead:
            action = "reset_backoff"
            base = last_reset_attempt if last_reset_attempt is not None else None
            next_after = (base + w.RESET_ATTEMPT_INTERVAL) if base is not None else None
        else:
            action = "none"
            next_after = None
        last_action = (
            f"usb_reset_method_{last_reset_method.lower()}"
            if (is_dead and last_reset_method) else ""
        )

        adapter_records.append({
            "ifname": a.ifname,
            "stable_id": a.stable_id,
            "kind": a.kind + ("_wifi" if a.kind in ("usb", "builtin") else ""),
            "role": role,
            "facts": {
                "present": True,
                "managed": a.managed,
                "carrier": carrier,
                "operstate": operstate,
                "nm_state": a.state,
                "ipv4": v4,
                "ipv6": v6,
                "gateway": {
                    "ipv4": gw_ipv4,
                    "ipv4_reachable": gw_reachable,
                    "ipv6": "",
                    "ipv6_reachable": None,
                    "last_checked_at": now_wall,
                },
            },
            "health": {
                "state": state,
                "severity": severity,
                "since": dead_since if is_dead else None,
                "checks": dead_checks if is_dead else 0,
                "reason": "link_down_unhealthy" if is_dead else "",
            },
            "policy": {
                "eligible": a.managed,
                "preferred": (role == "client" and not quarantined),
                "quarantined": quarantined,
                "action": action,
                "last_action": last_action,
                "next_action_after": next_after,
                "resets_24h": len(recent_resets) if is_dead else 0,
                "reset_budget_24h": w.USB_MAX_RESETS_PER_WINDOW,
            },
        })

    online_path = wired_connected or any_healthy

    primary_ifname = ""
    primary_kind = ""
    if active_ifname and any(
        r["ifname"] == active_ifname and r["health"]["state"] == "healthy"
        for r in adapter_records
    ):
        primary_ifname = active_ifname
        primary_kind = next(r["kind"] for r in adapter_records if r["ifname"] == active_ifname)
    elif wired_connected:
        for name in addresses:
            if name.startswith(("eth", "en")):
                primary_ifname = name
                primary_kind = "ethernet"
                break

    primary_ipv4, primary_ipv6 = (
        _primary_addresses(addresses, primary_ifname) if primary_ifname else ("", "")
    )

    if in_setup:
        device_state = "setup_mode"
    elif reboot_retry_after == float("inf"):
        device_state = "reboot_pending"
    elif online_path:
        device_state = "degraded" if (using_fallback or any_unhealthy) else "online"
    elif dead_ifname:
        device_state = "recovering"
    else:
        device_state = "offline"

    hotspot_reason = ""
    if in_setup:
        with w.state_lock:
            hotspot_reason = w.STATE.setup_purpose

    return {
        "schema_version": wifi_net.NETWORK_STATUS_SCHEMA_VERSION,
        "updated_at": now_wall,
        "device": {
            "state": device_state,
            "primary_ifname": primary_ifname,
            "primary_kind": primary_kind,
            "primary_ipv4": primary_ipv4,
            "primary_ipv6": primary_ipv6,
        },
        "hotspot": {
            "active": bool(hotspot_ifname),
            "ifname": hotspot_ifname,
            "reason": hotspot_reason,
        },
        "logging": {
            "effective_level": _effective_log_level_name(w),
            "default_level": default_level or "info",
            "temporary_level_expires_at": temp_expires,
        },
        "adapters": adapter_records,
    }


def publish_network_status(w, adapters: Optional[list] = None,
                           wired_connected: Optional[bool] = None) -> None:
    """Build and publish the latest runtime status snapshot in memory."""
    global _status_schema_logged
    try:
        snapshot = build_network_status_snapshot(w, adapters, wired_connected)
        snapshot["ok"] = True
        with w.state_lock:
            w.STATE.network_status_snapshot = snapshot
            w.STATE.network_status_updated_at = snapshot.get("updated_at")
        if not _status_schema_logged:
            _status_schema_logged = True
            logger.info("Network status snapshot schema v%d initialised in memory",
                        wifi_net.NETWORK_STATUS_SCHEMA_VERSION)
        else:
            logger.debug("Published network status snapshot")
    except Exception as e:
        logger.warning("Network status snapshot publish failed: %s", e)
