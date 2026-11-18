#!/usr/bin/env python3
"""webui/system/network.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Network status and set-up: a bounded proxy to the root watcher.

Contents:
  - send_network_status_json           -- GET /api/network/status
  - send_network_setup_json            -- POST /api/network/setup
  - send_network_roaming_json          -- POST /api/network/roaming
"""

from __future__ import annotations

from __future__ import annotations

import time

from typing import Optional

import autostream_watcher_client as watcher_client

from webui import common

# ---------------------------------------------------------------------------
# Network status / setup — bounded proxy to the root watcher
# ---------------------------------------------------------------------------


def _network_ip_detail(device: dict) -> str:
    info = device.get("primary_ipv4_info") if isinstance(device.get("primary_ipv4_info"), dict) else {}
    address = str(info.get("address") or "").strip()
    prefixlen = info.get("prefixlen")
    netmask = str(info.get("netmask") or "").strip()
    gateway = str(info.get("gateway") or "").strip()

    if address:
        if prefixlen is not None:
            ip_text = f"{address}/{prefixlen}"
        elif netmask:
            ip_text = f"{address}/{netmask}"
        else:
            ip_text = address
    else:
        ip_text = "Not assigned"

    return f"IP: {ip_text} | Gateway: {gateway or 'Not available'}"


def _network_ipv4_text(info: dict) -> str:
    address = str(info.get("address") or "").strip()
    if not address:
        return ""
    prefixlen = info.get("prefixlen")
    if prefixlen is not None:
        return f"{address}/{prefixlen}"
    netmask = str(info.get("netmask") or "").strip()
    if netmask:
        return f"{address}/{netmask}"
    return address


def _network_adapter_ipv4_text(adapter: dict, device: dict) -> str:
    facts = adapter.get("facts") if isinstance(adapter.get("facts"), dict) else {}
    ipv4 = facts.get("ipv4") if isinstance(facts.get("ipv4"), list) else []
    selected = None
    for addr in ipv4:
        if not isinstance(addr, dict):
            continue
        if addr.get("family") == "ipv4" and str(addr.get("scope") or "") == "global":
            selected = addr
            break
        if selected is None and addr.get("family") == "ipv4":
            selected = addr
    if isinstance(selected, dict):
        text = _network_ipv4_text(selected)
        if text:
            return text

    if str(adapter.get("ifname") or "").strip() == str(device.get("primary_ifname") or "").strip():
        info = device.get("primary_ipv4_info") if isinstance(device.get("primary_ipv4_info"), dict) else {}
        return _network_ipv4_text(info)
    return ""


def _network_adapter_label(adapter: dict) -> str:
    kind = str(adapter.get("kind") or "").strip()
    if kind == "builtin_wifi":
        return "On-board WiFi"
    if kind == "usb_wifi":
        return "USB WiFi"
    return ""


def _network_quarantine_retry_label(next_action_after) -> str:
    """Render the quarantine retry label from the watcher's monotonic deadline.

    The webui and watcher run on the same host, so their CLOCK_MONOTONIC
    values are directly comparable without any timestamp translation.
    """
    remaining_seconds = 0.0
    if isinstance(next_action_after, (int, float)) and not isinstance(next_action_after, bool):
        remaining_seconds = max(0.0, next_action_after - time.monotonic())
    hours = max(1, round(remaining_seconds / 3600))
    return f"Quarantined (auto-retry in {hours}h)"


def _network_activation_failure_label(last_activation_failure: dict) -> Optional[str]:
    """Render the association-failure label, or None when the record is stale."""
    age_seconds = last_activation_failure.get("age_seconds")
    if not isinstance(age_seconds, (int, float)) or isinstance(age_seconds, bool):
        return None
    if age_seconds >= 900:
        return None
    minutes = int(age_seconds // 60)
    reason = str(last_activation_failure.get("reason") or "").strip()
    if reason == "network_not_visible":
        return f"Association failed — network not visible ({minutes}m ago)"
    return f"Association failed ({minutes}m ago)"


def _network_no_ip_status_label(adapter: dict) -> str:
    """Map an adapter with no IP to a truthful status label from health/policy.

    Checked in order of specificity (first match wins): quarantined, reset
    pending, radio-check recovery, a recent association failure, held back,
    reconnect backoff, actively connecting, else disconnected.
    """
    health = adapter.get("health") if isinstance(adapter.get("health"), dict) else {}
    policy = adapter.get("policy") if isinstance(adapter.get("policy"), dict) else {}
    state = str(health.get("state") or "").strip()
    warning = str(policy.get("warning") or "").strip()

    if policy.get("quarantined") is True:
        return _network_quarantine_retry_label(policy.get("next_action_after"))

    if warning == "resetting" or state == "dead_phy":
        return "Recovering (reset pending)"

    empty_scan_streak = policy.get("empty_scan_streak")
    empty_scan_count = empty_scan_streak.get("count") if isinstance(empty_scan_streak, dict) else 0
    if isinstance(empty_scan_count, (int, float)) and not isinstance(empty_scan_count, bool) and empty_scan_count > 0:
        return "Recovering — radio check in progress"

    last_activation_failure = adapter.get("last_activation_failure")
    if isinstance(last_activation_failure, dict):
        failure_label = _network_activation_failure_label(last_activation_failure)
        if failure_label is not None:
            return failure_label

    if state == "no_ip_held_back" or policy.get("held_back") is True:
        return "Held back after repeated failures"

    noip_failures = policy.get("noip_failures")
    has_noip_failures = isinstance(noip_failures, (int, float)) and not isinstance(noip_failures, bool) and noip_failures > 0
    if state == "degraded_no_ip" or has_noip_failures:
        return f"Reconnect backoff (attempt {int(noip_failures or 0)})"

    if state == "connecting":
        return "Connecting…"

    return "Disconnected"


def _network_interface_lines(status: dict) -> list[str]:
    device = status.get("device") if isinstance(status.get("device"), dict) else {}
    lines: list[str] = []

    if str(device.get("primary_kind") or "").strip() == "ethernet":
        eth_text = _network_ipv4_text(
            device.get("primary_ipv4_info") if isinstance(device.get("primary_ipv4_info"), dict) else {}
        )
        if eth_text:
            lines.append(f"Ethernet: {eth_text}")

    adapters = status.get("adapters") if isinstance(status.get("adapters"), list) else []
    wifi_rows = []
    for idx, adapter in enumerate(adapters):
        if not isinstance(adapter, dict):
            continue
        label = _network_adapter_label(adapter)
        if not label:
            continue
        ifname = str(adapter.get("ifname") or "").strip()
        sort_kind = 0 if label == "On-board WiFi" else 1
        wifi_rows.append((sort_kind, ifname, idx, label, adapter))

    for _sort_kind, _ifname, _idx, label, adapter in sorted(wifi_rows):
        ip_text = _network_adapter_ipv4_text(adapter, device)
        if not ip_text:
            lines.append(f"{label}: {_network_no_ip_status_label(adapter)}")
            continue

        ssid_text = ""
        if str(adapter.get("ifname") or "").strip() == str(device.get("primary_ifname") or "").strip():
            ssid_text = str(device.get("primary_ssid") or "").strip()

        if ssid_text:
            lines.append(f"{label}: {ssid_text} - {ip_text}")
        else:
            lines.append(f"{label}: {ip_text}")
    return lines


def _network_warning_rank(adapter: dict) -> int | None:
    policy = adapter.get("policy") if isinstance(adapter.get("policy"), dict) else {}
    warning = str(policy.get("warning") or "").strip()
    if policy.get("quarantined") is True or warning == "quarantined":
        return 0
    # A no-IP-suppressed / demoted adapter is as serious as a reset budget spend
    # (held back out of service) — rank it just below quarantined.
    if warning == "no_ip_held_back" or policy.get("held_back") is True:
        return 1
    if warning == "reset_budget_exhausted":
        return 2
    if warning == "no_ip_address":
        return 3
    if warning == "resetting":
        return 4
    if warning == "recent_resets":
        return 5
    return None


def _network_warning_fields(adapter: dict) -> dict:
    policy = adapter.get("policy") if isinstance(adapter.get("policy"), dict) else {}
    rank = _network_warning_rank(adapter)
    resets = int(policy.get("resets_24h") or 0)
    budget = int(policy.get("reset_budget_24h") or 0)
    # IF-7b: the no-IP failure count published by the watcher (never recomputed
    # here) — the meaningful number for the held-back / no-IP ranks, which the
    # dead-PHY reset ledger ("resets_24h") never ticks.
    noip = int(policy.get("noip_failures") or 0)
    ifname = str(adapter.get("ifname") or "").strip() or "Unknown"

    role = str(adapter.get("role") or "").strip()
    label = _network_adapter_label(adapter) or "WiFi"

    if rank == 0:
        if role == "client":
            warning = f"Warning: the {label} adapter has needed repeated resets and may be faulty."
        else:
            warning = f"{label} adapter held back after repeated failures. Replace the adapter if this keeps happening."
        severity = "danger"
    elif rank == 1:
        # No-IP-suppressed / demoted spare — the "held back" copy now
        # covers no-IP suppression (previously wired only to quarantine), and
        # notes the device fell back to the on-board radio. That fallback
        # framing only fits a non-onboard adapter being held back.
        if label == "On-board WiFi":
            warning = f"{label} adapter held back after repeated failures. Replace the adapter if this keeps happening."
        else:
            warning = (f"{label} adapter held back after repeated failures — running on on-board WiFi. "
                       "Replace the adapter if this keeps happening.")
        severity = "danger"
    elif rank == 2:
        warning = f"Warning: the {label} adapter has needed repeated resets and may be faulty."
        severity = "danger"
    elif rank == 3:
        warning = (f"{label} adapter detected but could not get a network address — "
                   "check the network's DHCP, the adapter's band, or the dongle.")
        severity = "warning"
    elif rank == 4:
        warning = f"{label} adapter is being reset. Network connection may be unstable for a minute."
        severity = "warning"
    elif rank == 5:
        reset_text = "1 reset" if resets == 1 else f"{resets} resets"
        warning = f"Warning: the {label} adapter has needed {reset_text} in the last 24 hours."
        severity = "warning"
    else:
        return {}

    # The no-IP family (rank 1 held-back, rank 3 no-IP) is tracked by the no-IP
    # ledger, not the reset ledger, so show the failed-connection count; the
    # reset-family ranks (0, 2, 4, 5) keep the reset-attempt line (IF-7b).
    if rank in (1, 3):
        support_detail = f"Adapter: {ifname} | Failed connection attempts: {noip}"
    else:
        support_detail = (
            f"Adapter: {ifname} | Reset attempts: {resets} in 24h "
            f"(normal budget: {budget})"
        )

    return {
        "warning": warning,
        "warning_severity": severity,
        "support_detail": support_detail,
    }


def build_network_card_presentation(status: dict) -> dict:
    """Return Network-card presentation fields derived from watcher schema v1."""
    device = status.get("device") if isinstance(status.get("device"), dict) else {}
    primary_kind = str(device.get("primary_kind") or "").strip()
    primary_ifname = str(device.get("primary_ifname") or "").strip()
    primary_ssid = str(device.get("primary_ssid") or "").strip()

    if primary_kind == "ethernet":
        display = "Connected via Ethernet"
    elif primary_kind == "usb_wifi":
        display = "Connected via USB WiFi adapter"
        if primary_ssid:
            display += f" to {primary_ssid}"
    elif primary_kind == "builtin_wifi":
        display = "Connected via on-board WiFi"
        if primary_ssid:
            display += f" to {primary_ssid}"
    else:
        display = "No active network connection"

    result = {
        "title": "Network",
        "display": display,
        "detail": _network_ip_detail(device) if primary_kind else "",
        "interface_lines": _network_interface_lines(status),
        "warning": "",
        "warning_severity": "",
        "support_detail": "",
    }

    adapters = status.get("adapters") if isinstance(status.get("adapters"), list) else []
    wifi_adapters = [
        a for a in adapters
        if isinstance(a, dict) and str(a.get("kind") or "").strip() in ("usb_wifi", "builtin_wifi")
    ]
    active_wifi = [
        a for a in wifi_adapters
        if str(a.get("ifname") or "").strip() == primary_ifname or str(a.get("role") or "").strip() == "client"
    ]
    for adapter in active_wifi:
        if _network_warning_rank(adapter) is not None:
            result.update(_network_warning_fields(adapter))
            return result

    ranked = [
        (rank, adapter) for adapter in wifi_adapters
        for rank in [_network_warning_rank(adapter)]
        if rank is not None
    ]
    if ranked:
        ranked.sort(key=lambda item: item[0])
        result.update(_network_warning_fields(ranked[0][1]))
    return result


def send_network_status_json(handler) -> None:
    """GET /api/network/status — proxy the watcher's non-secret network status."""
    try:
        status, data = watcher_client.watcher_request("GET", "/network_status")
    except Exception:
        common.send_browser_api_error(handler, 503, "Network service unavailable")
        return
    if status != 200 or not isinstance(data, dict) or not data.get("ok"):
        common.send_browser_api_error(handler, 503, "Network service unavailable")
        return
    data.update(build_network_card_presentation(data))
    common.send_json(handler, 200, data)


_NETWORK_SETUP_ALLOWED_ACTIONS = frozenset({"start_setup", "reconnect_saved"})


def send_network_setup_json(handler, json_obj: dict) -> None:
    """POST /api/network/setup — proxy a bounded setup action to the watcher."""
    if not isinstance(json_obj, dict):
        common.send_browser_api_error(handler, 400, "JSON object required")
        return
    action = json_obj.get("action")
    extra = set(json_obj.keys()) - {"action", "csrf_token"}
    if action not in _NETWORK_SETUP_ALLOWED_ACTIONS or extra:
        common.send_browser_api_error(handler, 400, "Invalid action")
        return
    try:
        status, data = watcher_client.watcher_request("POST", "/network_control", {"action": action})
    except Exception:
        common.send_browser_api_error(handler, 503, "Network service unavailable")
        return
    if status == 200 and isinstance(data, dict) and data.get("ok"):
        common.send_json(handler, 200, {"ok": True, "queued": True, "action": action})
        return
    # Surface watcher conflict (busy) without breaking the Setup page.
    if status == 409:
        common.send_browser_api_error(handler, 409, "A network change is already in progress")
        return
    common.send_browser_api_error(handler, 503, "Network service unavailable")


def send_network_roaming_json(handler, json_obj: dict) -> None:
    """POST /api/network/roaming — proxy the USB roaming-management preference to the watcher."""
    if not isinstance(json_obj, dict):
        common.send_browser_api_error(handler, 400, "JSON object required")
        return
    managed = json_obj.get("managed")
    extra = set(json_obj.keys()) - {"managed", "csrf_token"}
    if not isinstance(managed, bool) or extra:
        common.send_browser_api_error(handler, 400, "Invalid request")
        return
    try:
        status, data = watcher_client.watcher_request(
            "POST", "/network_control", {"action": "set_roaming_management", "managed": managed}
        )
    except Exception:
        common.send_browser_api_error(handler, 503, "Network service unavailable")
        return
    if status == 200 and isinstance(data, dict) and data.get("ok"):
        common.send_json(handler, 200, {"ok": True, "managed": managed})
        return
    common.send_browser_api_error(handler, 503, "Network service unavailable")

# -----------------------------------------------------------------------------
# Route-table adapters
# -----------------------------------------------------------------------------


def _route_get_network_status(handler, state):
    send_network_status_json(handler)


def _route_post_network_setup(handler, state, body_str):
    send_network_setup_json(handler, common._route_post_json_obj(handler))


def _route_post_network_roaming(handler, state, body_str):
    send_network_roaming_json(handler, common._route_post_json_obj(handler))
