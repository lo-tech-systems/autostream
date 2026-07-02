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
import ipaddress
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


def _primary_ipv4_info(addresses: dict, ifname: str, gateway: str) -> dict:
    """Return active-path IPv4 details for the selected primary interface."""
    for a in addresses.get(ifname, []):
        if a.get("family") != "ipv4":
            continue
        address = a.get("address", "")
        if a.get("scope") != "global" or not address:
            continue
        prefixlen = a.get("prefixlen")
        netmask = ""
        if isinstance(prefixlen, int) and not isinstance(prefixlen, bool):
            try:
                netmask = str(ipaddress.IPv4Network(f"0.0.0.0/{prefixlen}").netmask)
            except ValueError:
                pass
        return {
            "address": address,
            "prefixlen": prefixlen if isinstance(prefixlen, int) else None,
            "netmask": netmask,
            "gateway": gateway,
        }
    return {"address": "", "prefixlen": None, "netmask": "", "gateway": ""}


def _adapter_ip_lists(addresses: dict, ifname: str) -> tuple[list, list]:
    v4 = [a for a in addresses.get(ifname, []) if a["family"] == "ipv4"]
    v6 = [a for a in addresses.get(ifname, []) if a["family"] == "ipv6"]
    return v4, v6


def _has_usable_ipv4(addresses: dict, ifname: str) -> bool:
    for a in addresses.get(ifname, []):
        if a.get("family") == "ipv4" and wifi_net.is_usable_unicast_ipv4(a.get("address", "")):
            return True
    return False


def _primary_wired_ifname(addresses: dict) -> str:
    for name in addresses:
        if name.startswith(("eth", "en")) and _has_usable_ipv4(addresses, name):
            return name
    return ""


def _classify_adapter_health(*, present, managed, carrier, healthy, nm_state,
                             is_dead, is_link_down, quarantined, is_hotspot,
                             is_no_ip=False):
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
    elif is_no_ip:
        # Overlay verdict: associated/carrier-up but repeatedly could not get a
        # usable IP/gateway (defect 3) — distinct from a transient `connecting`.
        state = "degraded_no_ip"
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
                                  wired_connected: Optional[bool] = None,
                                  wired_ok: Optional[bool] = None,
                                  addresses: Optional[dict] = None,
                                  health_fn=None) -> dict:
    """Build the schema_version:1 runtime network-status snapshot.

    Uses the watcher's facts and the dead-PHY recovery ledger.  All derived
    meaning is computed here (platform policy); core only supplies facts.  When
    *addresses* is supplied (the per-tick Facts snapshot, WP1) it is reused
    rather than re-enumerated via ``ip``.
    """
    if adapters is None:
        try:
            adapters = wifi_net.discover_adapters()
        except Exception:
            adapters = []
    if wired_connected is None:
        wired_connected = w.is_wired_connected()
    if wired_ok is None:
        wired_ok = w.any_wired_path_healthy()

    if addresses is None:
        addresses = wifi_net.list_interface_addresses()
    now_wall = time.time()
    now_monotonic = time.monotonic()

    with w.state_lock:
        active_ifname = w.STATE.active_client_ifname
        active_mac = w.STATE.active_client_mac
        using_fallback = w.STATE.using_builtin_fallback
        in_setup = w.STATE.setup_mode
        dead_ifname = w.STATE.dead_adapter_ifname
        dead_since = w.STATE.dead_adapter_since
        dead_checks = w.STATE.dead_adapter_checks
        last_reset_method = w.STATE.last_reset_method
        last_reset_attempt = w.STATE.last_reset_attempt
        reboot_retry_after = w.STATE.conn_reboot_retry_after
        temp_expires = w.STATE.temporary_log_level_until
        default_level = w.STATE.default_log_level_name
        last_active_path_seen = w.STATE.last_active_path_seen

    hotspot_adapter = w.resolve_hotspot_adapter(adapters)
    hotspot_ifname = hotspot_adapter.ifname if (in_setup and hotspot_adapter) else ""

    adapter_records = []
    adapter_default_gateways = {}
    any_healthy = False
    any_unhealthy = False
    for a in adapters:
        # Shared per-adapter recovery facts (single source of truth with the
        # recovery-ladder classifier); presentation-only fields stay here.
        rf = w._adapter_recovery_facts(a, now_monotonic, health_fn)
        healthy = rf.healthy
        link_down = rf.link_down
        operstate = wifi_net.read_operstate(a.ifname)
        carrier = rf.carrier
        is_dead = (a.ifname == dead_ifname)
        is_hotspot = (a.ifname == hotspot_ifname)
        quarantined_until = rf.quarantined_until
        quarantined = rf.quarantined
        recent_reset_count = rf.recent_reset_count
        total_reset_count = rf.total_reset_count
        budget_exhausted = rf.budget_exhausted
        v4, v6 = _adapter_ip_lists(addresses, a.ifname)

        # Overlay no-IP verdict (defect 3): managed + carrier-up + not healthy +
        # repeated no-IP failures recorded in the overlay ledger.
        noip_count = rf.noip_count
        is_no_ip = rf.is_no_ip

        if is_hotspot:
            role = "hotspot"
        elif a.ifname == active_ifname or (active_mac and a.permanent_mac == active_mac):
            role = "client"
        else:
            role = "idle"

        if healthy:
            any_healthy = True
        elif a.managed and not is_hotspot and (
            role == "client" or is_no_ip or is_dead or quarantined
        ):
            # Only an *attributed* problem degrades whole-device state: the active
            # client, a no-IP adapter, a dead-PHY adapter, or a quarantined one.
            # An idle unusable spare (merely unhealthy, no attribution) does not
            # silently flip device.state to degraded (defect 3 tightening).
            any_unhealthy = True

        gw_ipv4 = wifi_net.default_gateway_ipv4(a.ifname)
        adapter_default_gateways[a.ifname] = gw_ipv4
        gw_reachable = w.is_gateway_reachable(a.ifname) if gw_ipv4 else False

        state, severity = _classify_adapter_health(
            present=True, managed=a.managed, carrier=carrier, healthy=healthy,
            nm_state=a.state, is_dead=is_dead, is_link_down=(link_down is True),
            quarantined=quarantined, is_hotspot=is_hotspot, is_no_ip=is_no_ip,
        )

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
        if quarantined:
            warning = "quarantined"
        elif is_dead:
            warning = "resetting"
        elif budget_exhausted:
            warning = "reset_budget_exhausted"
        elif is_no_ip:
            warning = "no_ip_address"
        elif recent_reset_count:
            warning = "recent_resets"
        else:
            warning = ""

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
                "checks": dead_checks if is_dead else (noip_count if is_no_ip else 0),
                "reason": ("link_down_unhealthy" if is_dead
                           else ("associated_no_ip" if is_no_ip else "")),
            },
            "policy": {
                "eligible": a.managed,
                "preferred": (role == "client" and not quarantined),
                "quarantined": quarantined,
                "action": action,
                "last_action": last_action,
                "next_action_after": next_after,
                "resets_24h": recent_reset_count,
                "reset_budget_24h": w.USB_MAX_RESETS_PER_WINDOW,
                "warning": warning,
            },
        })

    client_ok = any_healthy
    active_path_ok = bool((wired_ok or client_ok) and not in_setup)
    online_path = active_path_ok

    primary_ifname = ""
    primary_kind = ""
    wifi_primary_ifname = ""
    wifi_primary_kind = ""
    if active_ifname and any(
        r["ifname"] == active_ifname and r["health"]["state"] == "healthy"
        for r in adapter_records
    ):
        wifi_primary_ifname = active_ifname
        wifi_primary_kind = next(r["kind"] for r in adapter_records if r["ifname"] == active_ifname)

    wired_primary_ifname = _primary_wired_ifname(addresses) if wired_ok else ""

    if wifi_primary_ifname and wired_primary_ifname:
        wifi_has_default = bool(adapter_default_gateways.get(wifi_primary_ifname))
        wired_has_default = bool(wifi_net.default_gateway_ipv4(wired_primary_ifname))
        if wifi_has_default and not wired_has_default:
            primary_ifname = wifi_primary_ifname
            primary_kind = wifi_primary_kind
        else:
            primary_ifname = wired_primary_ifname
            primary_kind = "ethernet"
    elif wifi_primary_ifname:
        primary_ifname = wifi_primary_ifname
        primary_kind = wifi_primary_kind
    elif wired_primary_ifname:
        primary_ifname = wired_primary_ifname
        primary_kind = "ethernet"

    primary_ipv4, primary_ipv6 = (
        _primary_addresses(addresses, primary_ifname) if primary_ifname else ("", "")
    )
    primary_gateway = wifi_net.default_gateway_ipv4(primary_ifname) if primary_ifname else ""
    primary_ipv4_info = (
        _primary_ipv4_info(addresses, primary_ifname, primary_gateway)
        if primary_ifname else {"address": "", "prefixlen": None, "netmask": "", "gateway": ""}
    )
    primary_ssid = ""
    if primary_kind in ("builtin_wifi", "usb_wifi"):
        primary_ssid = wifi_net.get_active_wifi_ssid(primary_ifname) or ""

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
            session = w.STATE.hotspot
        hotspot_reason = session.purpose.value if session else ""

    if in_setup or last_active_path_seen is None:
        no_active_age = None
        no_active_remaining = None
    else:
        no_active_age = max(0.0, now_monotonic - last_active_path_seen)
        no_active_remaining = max(0.0, w.NO_ACTIVE_PATH_REBOOT_AFTER - no_active_age)

    # Publish the authoritative STATE.mode the loop applies from the pure
    # next_mode() classifier each pass (set just before publish).  Standalone
    # diagnostic/test builds reflect the current STATE.mode.
    with w.state_lock:
        mode_value = w.STATE.mode.value

    return {
        "schema_version": wifi_net.NETWORK_STATUS_SCHEMA_VERSION,
        "updated_at": now_wall,
        "device": {
            "state": device_state,
            "mode": mode_value,
            "primary_ifname": primary_ifname,
            "primary_kind": primary_kind,
            "primary_ssid": primary_ssid,
            "primary_ipv4": primary_ipv4,
            "primary_ipv4_info": primary_ipv4_info,
            "primary_ipv6": primary_ipv6,
        },
        "hotspot": {
            "active": bool(hotspot_ifname),
            "ifname": hotspot_ifname,
            "reason": hotspot_reason,
        },
        "connectivity": {
            "active_path_ok": active_path_ok,
            "client_ok": client_ok,
            "wired_carrier": bool(wired_connected),
            "wired_ok": bool(wired_ok),
            "last_active_path_seen_monotonic": last_active_path_seen,
            "no_active_path_age_seconds": no_active_age,
            "no_active_path_reboot_after_seconds": w.NO_ACTIVE_PATH_REBOOT_AFTER,
            "no_active_path_reboot_remaining_seconds": no_active_remaining,
        },
        "logging": {
            "effective_level": _effective_log_level_name(w),
            "default_level": default_level or "info",
            "temporary_level_expires_at": temp_expires,
        },
        "adapters": adapter_records,
    }


def publish_network_status(w, adapters: Optional[list] = None,
                           wired_connected: Optional[bool] = None,
                           wired_ok: Optional[bool] = None,
                           addresses: Optional[dict] = None,
                           health_fn=None) -> None:
    """Build and publish the latest runtime status snapshot in memory."""
    global _status_schema_logged
    try:
        snapshot = build_network_status_snapshot(
            w, adapters, wired_connected, wired_ok, addresses, health_fn)
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
