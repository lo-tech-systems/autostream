#!/usr/bin/env python3
"""autostream_webui_api.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Lightweight JSON API endpoints.

Contents:
  - run_updater                  -- invoke the updater script via sudo
  - send_update_check_json       -- GET /api/update/check
  - send_update_status_json      -- GET /api/update/status
  - send_dial_volume_post_json   -- POST /api/dial/volume
  - send_dial_status_post_json   -- POST /api/dial/status
  - send_dial_mute_post_json     -- POST /api/dial/mute
  - send_dial_outputs_post_json  -- POST /api/dial/outputs
  - send_dial_outputs_set_post_json -- POST /api/dial/outputs/set
  - send_dial_eq_post_json       -- POST /api/dial/eq
  - send_dial_eq_set_post_json   -- POST /api/dial/eq/set
  - send_dial_warnings_post_json -- POST /api/dial/warnings
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import time

from typing import Optional

import autostream_watcher_client as watcher_client

from autostream_bluetooth_client import (
    BLUETOOTH_CAPTURE_DEVICE,
    BluetoothClient,
    bluetooth_capture_label,
    bluetooth_card_summary,
    bluetooth_input_fragment_text,
    bluetooth_installed,
    bluetooth_onboard_enabled,
    bluetooth_paired_row_text,
    bluetooth_services_enabled,
    classify_loopback_hw,
)
from autostream_config import DEFAULT_AIRPLAY_MODE, is_valid_monitor_device_id
from autostream_intents import Intent, submit
from autostream_settings import SettingsView
from autostream_state import Origin, store
from autostream_state.live import get_live_output_eq_status
from autostream_pin_pairing import REQUESTER_WEBUI
from webui.browser import home_model
from webui.browser.home_model import build_equaliser_state, build_home_state, sanitize_output_body
from autostream_sysutils import (
    bt_onboard_set,
    bt_services_disable,
    bt_services_enable,
    run_admin_cmd,
    SDCARD_HEALTH_METHODS,
    sdcard_health_check,
    sdcard_health_disable,
    sdcard_health_enable,
    sdcard_health_state,
)
from webui.common import render_license_md
from webui.session_state import WebUIState
from webui import common, repeat
from webui.browser import api_settings




# -----------------------------------------------------------------------------
# Updater subprocess helper
# -----------------------------------------------------------------------------

def run_updater(args: list[str], timeout: int = 30) -> tuple[int, str, str]:
    cmd = ["/usr/bin/sudo", "-n", "/usr/local/libexec/autostream/autostream_updater", *args]
    p = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )
    return p.returncode, p.stdout, p.stderr


def send_update_check_json(handler, state=None) -> None:
    # The updater subprocess reads the update channel from the config file on
    # disk, while settings changes (e.g. the pre-release channel toggle) are
    # flushed to disk on a debounced interval -- force the flush first so a
    # check issued right after a toggle cannot run against the old channel.
    if getattr(state, "settings", None) is not None:
        try:
            submit(Intent("settings.save", {"timeout": 5.0}, Origin.USER, "webui", context=state))
        except Exception:
            pass  # best effort; the check still runs against current disk state
    rc, out, err = run_updater(["check"], timeout=60)
    if rc != 0:
        common.send_json(handler, 200, {"ok": False, "error": "check failed"})
        return
    try:
        payload = json.loads(out)
    except Exception:
        common.send_json(handler, 200, {"ok": False})
        return
    if isinstance(payload, dict):
        notes = payload.get("release_notes")
        if isinstance(notes, str) and notes:
            payload = {**payload, "release_notes_html": render_license_md(notes)}
    common.send_json(handler, 200, payload)


def send_update_status_json(handler) -> None:
    """Return the persisted update status from update-result.env via autostream_admin.

    The response shape matches what autostream_admin update-status emits:
      {ok, status, message, percent, last_run_at}
    where status is one of: in_progress | success | failure | error | unknown
    """
    p = run_admin_cmd(["update-status"], timeout=10.0)
    if p.returncode != 0:
        common.send_json(handler, 200, {
            "ok": False,
            "status": "error",
            "message": "Could not read update status",
            "percent": 0,
            "last_run_at": "",
        })
        return
    try:
        common.send_json(handler, 200, json.loads(p.stdout or "{}"))
    except Exception:
        common.send_json(handler, 200, {
            "ok": False,
            "status": "error",
            "message": "Malformed update status response",
            "percent": 0,
            "last_run_at": "",
        })


# ---------------------------------------------------------------------------
# Federation target API handlers (called by autostream_webui._dispatch_federation)
# ---------------------------------------------------------------------------

def send_federation_session_json(handler, source_ip: str) -> None:
    """POST /api/federation/v1/session -- issue a short-lived bearer token.

    Rate-limited to 5 successful issuances per source IP per 60-second window.
    A rejected request does not consume an issuance slot.
    The token is never logged.
    """
    import autostream_federation
    token, value = autostream_federation.create_session(source_ip)
    if token is None:
        retry_after = value
        handler.send_response(429)
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        handler.send_header("Retry-After", str(retry_after))
        body = json.dumps({
            "ok": False,
            "error": "rate_limited",
            "retryable": True,
            "retry_after": retry_after,
        }).encode("utf-8")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)
        return
    common.send_json(handler, 200, {
        "ok": True,
        "token": token,
        "token_type": "Bearer",
        "expires_in": autostream_federation.EXPIRY_SECONDS,
        "federation_version": autostream_federation.FEDERATION_VERSION,
    })


def send_federation_home_json(handler, state: WebUIState) -> None:
    """GET /api/federation/v1/home — return aggregate Home state."""
    try:
        parsed = common._config_snapshot(state)
    except Exception as e:
        logging.warning("federation home: settings unavailable: %s", e)
        common.send_json(handler, 500, {"ok": False, "error": str(e)})
        return
    common.send_json(handler, 200, build_home_state(store().snapshot(), parsed))


def send_federation_output_json(handler, state: WebUIState, body_str: str) -> None:
    """POST /api/federation/v1/output — toggle or PIN-submit an AirPlay output."""
    try:
        body = json.loads(body_str)
    except (json.JSONDecodeError, ValueError):
        common.send_json(handler, 400, {"ok": False, "error": "invalid_json"})
        return
    if not isinstance(body, dict):
        common.send_json(handler, 400, {"ok": False, "error": "invalid_request_body"})
        return

    out_id = str(body.get("id") or "").strip()
    if not out_id:
        common.send_json(handler, 400, {"ok": False, "error": "missing_output_id"})
        return

    try:
        parsed = common._config_snapshot(state)
        from autostream_player_service import config_airplay_mode_to_backend
        from autostream_config import DEFAULT_AIRPLAY_MODE
        offset_ms_raw = parsed.owntone.output_offsets_ms.get(out_id)
        offset_ms = int(offset_ms_raw) if offset_ms_raw is not None else None
        mode_text = parsed.owntone.output_airplay_modes.get(out_id, DEFAULT_AIRPLAY_MODE)
        mode = config_airplay_mode_to_backend(mode_text)
    except Exception as e:
        logging.error("federation output: config error: %s", e)
        common.send_json(handler, 500, {"ok": False, "error": "internal_error"})
        return

    # Same preserved error-priority ordering as before this extraction: the
    # out_id/config checks above run first, then the shared sanitiser
    # validates the op/pin/selected/volume shape.
    sanitized, sanitize_error = sanitize_output_body(body)
    if sanitize_error is not None:
        common.send_json(handler, 400, {"ok": False, "error": sanitize_error})
        return

    result = home_model.submit_output_change(
        sanitized, requester="peer", pin_requester=REQUESTER_WEBUI,
        offset_ms=offset_ms, mode=mode,
    )
    common.send_json(handler, 200, result)


def send_federation_equaliser_json(handler, state: WebUIState) -> None:
    """GET /api/federation/v1/equaliser — return aggregate Equaliser state."""
    try:
        parsed = common._config_snapshot(state)
    except Exception as e:
        logging.warning("federation equaliser: settings unavailable: %s", e)
        common.send_json(handler, 500, {"ok": False, "error": str(e)})
        return
    common.send_json(handler, 200, build_equaliser_state(parsed))


def send_federation_eq_config_json(handler, state: WebUIState, body_str: str) -> None:
    """POST /api/federation/v1/equaliser/config — apply one EQ field."""
    try:
        payload = json.loads(body_str)
    except (json.JSONDecodeError, ValueError):
        common.send_json(handler, 400, {"ok": False, "error": "invalid_json"})
        return
    if not isinstance(payload, dict):
        common.send_json(handler, 400, {"ok": False, "error": "invalid_request_body"})
        return
    field = str(payload.get("field", "")).strip()
    value_raw = str(payload.get("value", "")).strip()
    reply = submit(Intent(
        "output.eq.set", {"fields": ((field, value_raw),)}, Origin.USER, "peer", context=state))
    if "invalid" in reply.result:
        common.send_json(handler, 400, {"ok": False, "error": reply.result["invalid"]})
        return
    if not reply.ok:
        common.send_json(handler, 500, {"ok": False, "error": reply.result.get("error", reply.error) or "internal_error"})
        return
    common.send_json(handler, 200, {"ok": True, "field": field, "value": reply.result.get("value", "")})


def send_federation_eq_reset_json(handler, state: WebUIState) -> None:
    """POST /api/federation/v1/equaliser/reset — zero all EQ bands; does not change output gain or auto-trim."""
    reply = submit(Intent("output.eq.reset", {}, Origin.USER, "peer", context=state))
    if not reply.ok:
        common.send_json(handler, 500, {"ok": False, "error": reply.result.get("error", reply.error) or "internal_error"})
        return
    common.send_json(handler, 200, {"ok": True})


def send_federation_eq_status_json(handler, state: WebUIState) -> None:  # noqa: ARG001
    """GET /api/federation/v1/equaliser/status — return live trim state."""
    status = get_live_output_eq_status()
    if status is None:
        common.send_json(handler, 200, {"ok": False, "error": "monitor_unavailable"})
        return
    common.send_json(handler, 200, {"ok": True, **status})


def send_federation_repeat_json(handler, state: WebUIState, body_str: str) -> None:  # noqa: ARG001
    """POST /api/federation/v1/repeat -- arm/disarm repeat replay on the local
    appliance.  Same request/response contract as POST /api/repeat -- see
    apply_repeat_arm_request().
    """
    status, resp = repeat.apply_repeat_arm_request(body_str, requester="peer")
    common.send_json(handler, status, resp)


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
# Bluetooth input — thin translations onto BluetoothClient plus the
# sysutils enable/disable/onboard wrappers.  The pairing/scan/forget
# handlers below return {"ok": false, "error": "bluetooth_unavailable"}
# (tunneled through send_browser_api_error as a semantic 503, following the
# same pattern as send_network_status_json) when the subsystem isn't
# installed, the daemon socket is absent, or the daemon reply is malformed
# -- callers never see a bare exception.
# -----------------------------------------------------------------------------

_BLUETOOTH_SCAN_ALLOWED_ACTIONS = frozenset({"start", "stop"})
_BLUETOOTH_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
_BLUETOOTH_SERVICES_ALLOWED_ACTIONS = frozenset({"enable", "disable"})
_BLUETOOTH_BUFFER_MS_MIN = 100
_BLUETOOTH_BUFFER_MS_MAX = 500


def send_bluetooth_status_json(handler, state) -> None:
    """GET /api/bluetooth/status -- install/enable/onboard flags + daemon status.

    Always returns HTTP 200 with ``ok: true`` -- the daemon being down
    (expected whenever services are disabled) is reported as ``daemon:
    null``, not as a request failure, so the Bluetooth card can render its
    disabled state from a single successful poll rather than special-casing
    an error response.

    When installed, attempts a live daemon query first (freshest); falls
    back to the cache populated by the webui's background scan loop
    (``WebUIState.get_bluetooth_status``) if the live query fails.

    Also returns a ``ui`` object -- ``card_summary``, ``paired_text``,
    ``bt_input_text`` -- computed from the same ``services_enabled``/
    ``daemon`` data by the single shared presentation-string implementation
    also used by the Setup page's server render, so the card's summary line
    can never disagree between the initial render and this poll.
    """
    installed = bluetooth_installed()
    services_enabled = bluetooth_services_enabled() if installed else False
    onboard_enabled = bluetooth_onboard_enabled() if installed else False

    daemon = None
    if installed:
        try:
            daemon = BluetoothClient().status()
        except Exception:
            daemon = None
        if not isinstance(daemon, dict) or daemon.get("ok") is not True:
            cached = state.get_bluetooth_status() if state is not None else None
            daemon = cached if isinstance(cached, dict) and cached.get("ok") is True else None

    common.send_json(handler, 200, {
        "ok": True,
        "installed": installed,
        "services_enabled": services_enabled,
        "onboard_enabled": onboard_enabled,
        "daemon": daemon,
        "ui": {
            "card_summary": bluetooth_card_summary(services_enabled, daemon),
            "paired_text": bluetooth_paired_row_text(daemon),
            "bt_input_text": bluetooth_input_fragment_text(daemon),
            # Label for the loopback entry in the capture-device dropdowns,
            # so the poll can relabel it live ("Bluetooth: <name>" after a
            # pair, back to unpaired after a forget) without a page reload.
            "capture_label": bluetooth_capture_label(daemon),
        },
    })


def send_bluetooth_scan_results_json(handler) -> None:
    """GET /api/bluetooth/scan_results — live device list from the daemon."""
    if not bluetooth_installed():
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    result = BluetoothClient().scan_results()
    if not isinstance(result, dict) or result.get("ok") is not True:
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    common.send_json(handler, 200, result)


def send_bluetooth_pair_status_json(handler, state=None) -> None:
    """GET /api/bluetooth/pair_status -- live pairing-attempt state from the daemon.

    A ``pair`` POST reply only means pairing *started*; the daemon's own
    reported outcome ("done" vs "failed") is only known here, via the
    polled status. So this is the hook point for the post-pairing input
    auto-enable rules (see ``_bt_pair_auto_configure``), not the POST
    handler: once the daemon reports ``state == "done"``, apply the rules
    and surface the outcome under ``input_auto_configure`` so the pairing
    UI (which polls this endpoint) can show the user what changed. Never
    fires on "failed" or "in_progress".

    The UI keeps polling this endpoint every couple of seconds until it
    observes "done" or "failed" and may therefore see "done" more than
    once (e.g. a slow client tick); that's safe to re-run here because the
    rules themselves are idempotent -- an input already on the loopback
    device short-circuits to ``already_configured`` with no further
    change.
    """
    if not bluetooth_installed():
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    result = BluetoothClient().pair_status()
    if not isinstance(result, dict) or result.get("ok") is not True:
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    if result.get("state") == "done":
        try:
            auto = _bt_pair_auto_configure(state)
        except Exception:
            logging.exception("send_bluetooth_pair_status_json: auto-configure step failed")
            auto = None
        if auto is not None:
            result["input_auto_configure"] = auto
    common.send_json(handler, 200, result)


def send_bluetooth_scan_post_json(handler, json_obj) -> None:
    """POST /api/bluetooth/scan {"action": "start"|"stop"} -- closed action set.

    Mirrors ``send_network_setup_json``'s ``_NETWORK_SETUP_ALLOWED_ACTIONS``
    rejection style: unknown actions or extra keys are rejected before ever
    touching the daemon.  A daemon reply of ``{"ok": false, "error":
    "scan_in_progress"}`` (another scan already active) is surfaced as a 409,
    mirroring ``send_network_setup_json``'s watcher-busy 409; any other
    non-ok reply stays a 503 ``bluetooth_unavailable``.
    """
    if not bluetooth_installed():
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    if not isinstance(json_obj, dict):
        common.send_browser_api_error(handler, 400, "JSON object required")
        return
    action = json_obj.get("action")
    extra = set(json_obj.keys()) - {"action", "csrf_token"}
    if action not in _BLUETOOTH_SCAN_ALLOWED_ACTIONS or extra:
        common.send_browser_api_error(handler, 400, "Invalid action")
        return

    client = BluetoothClient()
    result = client.scan_start() if action == "start" else client.scan_stop()
    if not isinstance(result, dict) or result.get("ok") is not True:
        if isinstance(result, dict) and result.get("error") == "scan_in_progress":
            common.send_browser_api_error(handler, 409, "scan_in_progress")
            return
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    common.send_json(handler, 200, {"ok": True, "action": action})


def _bt_pairing_set_field(state, settings, field: str, value) -> tuple[bool, Optional[str]]:
    """Write one settings field through the same validator/mutator/live-effect
    machinery as ``POST /api/settings`` (see ``send_settings_post_json`` and
    ``_SETTINGS_FIELDS``), so this non-browser-initiated caller still goes
    through the coordinator-reload debounce and the cross-input exclusivity
    guard exactly like a user editing the Setup page would. Returns ``(ok,
    error_or_None)``; never raises.
    """
    validator = api_settings._SETTINGS_FIELDS[field][2]
    try:
        normalized = validator(value)
    except ValueError as e:
        return False, str(e)

    # Enabling input 1 requires a valid capture device already on record
    # (mirrors the completeness gates and send_settings_post_json's own
    # guard) -- relevant here only as a defensive backstop, since the
    # caller below always writes the capture device before the enable flag.
    if field == "audio1.enabled" and normalized:
        try:
            current_device = str(settings.snapshot().audio1.capture_device or "").strip()
        except Exception:
            current_device = ""
        if not is_valid_monitor_device_id(current_device):
            return False, "input 1 has no valid capture device on record"

    # Cross-input exclusivity guard: the same capture device must never be
    # assigned to both inputs at once. Fast-path check against the live
    # snapshot; the authoritative, race-proof check is repeated inside the
    # mutator below, under the store lock.
    if field in ("audio1.capture_device", "audio2.capture_device") and normalized:
        other_section = "audio2" if field == "audio1.capture_device" else "audio1"
        try:
            other_value = str(getattr(settings.snapshot(), other_section).capture_device or "").strip()
        except Exception:
            other_value = ""
        if other_value == normalized:
            return False, "that device is already assigned to the other input"

    # The schema row's own cross-validation repeats the duplicate-device check
    # under the store lock, and its live effect runs with the commit.
    reply = submit(Intent(
        "settings.apply", {"changes": ((field, normalized),)}, Origin.USER, "webui",
        context=state))
    if not reply.ok:
        if "invalid" in reply.result:
            return False, reply.result["invalid"]
        return False, "internal error"

    return True, None


_BT_PAIR_NOTICE = "Bluetooth paired — assign the Bluetooth input on the Setup page."


def _bt_pair_auto_configure(state) -> Optional[dict]:
    """Apply the post-pairing input auto-enable rules, once the daemon has
    confirmed a successful pair. Never auto-disables anything.

    Rules, evaluated against the settings snapshot at the moment pairing
    completes:
      a. Input 1 disabled -> point it at the loopback capture device and
         enable it (overwrites any stale device value already on record).
      b. Input 1 enabled on a non-loopback device, and input 2 is unmapped
         (disabled, or has no capture device on record) -> map input 2 to
         the loopback and enable it.
      c. Either input already on the loopback -> already wired; no change,
         no notice.
      d. Otherwise (both inputs occupied by real devices, or a weird
         pre-existing state rules a/b can't safely resolve) -> change
         nothing; the result carries a notice for the caller to surface.

    Returns a dict describing the outcome (for embedding in the pairing
    API response), or ``None`` when there is no settings store to act on
    (nothing could be determined or changed).
    """
    settings = getattr(state, "settings", None)
    if not isinstance(settings, SettingsView):
        return None

    try:
        snap = settings.snapshot()
        a1_enabled = bool(snap.audio1_enabled)
        a1_device = str(snap.audio1.capture_device or "").strip()
        a2_enabled = bool(snap.audio2_enabled)
        a2_device = str(snap.audio2.capture_device or "").strip()
    except Exception:
        logging.exception("_bt_pair_auto_configure: could not read settings snapshot")
        return None

    a1_on_loopback = classify_loopback_hw(a1_device) == "capture"
    a2_on_loopback = classify_loopback_hw(a2_device) == "capture"

    # Rule c takes priority over a/b unconditionally: if either input is
    # already wired to the loopback, nothing further can be done without
    # risking both inputs ending up on the loopback at once (the one
    # invariant that must never happen), so a weird pre-existing state
    # (e.g. input 1 disabled while input 2 already holds the loopback)
    # bails here rather than letting rule a fire underneath it.
    if a1_on_loopback or a2_on_loopback:
        return {"action": "already_configured"}

    if not a1_enabled:
        target_input, device_field, enabled_field = "audio1", "audio1.capture_device", "audio1.enabled"
    elif a1_device and (not a2_enabled or not a2_device):
        target_input, device_field, enabled_field = "audio2", "audio2.capture_device", "audio2.enabled"
    else:
        return {"action": "notice", "notice": _BT_PAIR_NOTICE}

    device_ok, device_err = _bt_pairing_set_field(state, settings, device_field, BLUETOOTH_CAPTURE_DEVICE)
    if not device_ok:
        logging.warning(
            "_bt_pair_auto_configure: could not set %s to the loopback device: %s",
            device_field, device_err,
        )
        return {"action": "notice", "notice": _BT_PAIR_NOTICE}

    enabled_ok, enabled_err = _bt_pairing_set_field(state, settings, enabled_field, True)
    if not enabled_ok:
        # The device is now on record but the input stays disabled -- a
        # legal state (capture_device may be set while disabled) -- rather
        # than leaving a half-applied change or raising out of a pairing
        # response.
        logging.warning(
            "_bt_pair_auto_configure: set %s but could not enable %s: %s",
            device_field, enabled_field, enabled_err,
        )
        return {"action": "device_set_only", "input": target_input}

    return {"action": "enabled", "input": target_input}


def send_bluetooth_pair_post_json(handler, json_obj) -> None:
    """POST /api/bluetooth/pair {"address": <mac>} -- server-side MAC validation.

    A daemon reply of ``{"ok": false, "error": "pair_in_progress"}`` (a
    pairing attempt already active) is surfaced as a 409, mirroring
    ``send_network_setup_json``'s watcher-busy 409; any other non-ok reply
    stays a 503 ``bluetooth_unavailable``.

    This only means the daemon has *started* pairing, not that it
    succeeded -- the real outcome is only known once the client polls
    ``GET /api/bluetooth/pair_status`` and sees ``state == "done"``. It no
    longer applies the input auto-enable rules for that reason (see
    ``send_bluetooth_pair_status_json``, which does); this handler's
    response stays the plain ``{"ok": True}`` shape.
    """
    if not bluetooth_installed():
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    if not isinstance(json_obj, dict):
        common.send_browser_api_error(handler, 400, "JSON object required")
        return
    address = json_obj.get("address")
    extra = set(json_obj.keys()) - {"address", "csrf_token"}
    if not isinstance(address, str) or not _BLUETOOTH_MAC_RE.match(address) or extra:
        common.send_browser_api_error(handler, 400, "Invalid address")
        return

    result = BluetoothClient().pair(address)
    if not isinstance(result, dict) or result.get("ok") is not True:
        if isinstance(result, dict) and result.get("error") == "pair_in_progress":
            common.send_browser_api_error(handler, 409, "pair_in_progress")
            return
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return

    common.send_json(handler, 200, {"ok": True})


def send_bluetooth_forget_post_json(handler) -> None:
    """POST /api/bluetooth/forget — RemoveDevice + clear daemon state."""
    if not bluetooth_installed():
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    result = BluetoothClient().forget()
    if not isinstance(result, dict) or result.get("ok") is not True:
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    common.send_json(handler, 200, {"ok": True})


def send_bluetooth_services_post_json(handler, json_obj) -> None:
    """POST /api/bluetooth/services {"action": "enable"|"disable"}.

    Thin wrapper over the ``autostream_sysutils`` privileged-path
    functions, which each return ``(ok, message)``. Disabling implicitly
    stops any active stream -- that is handled inside the systemd unit
    stop, not here. Closed action set, extra keys rejected.
    """
    if not bluetooth_installed():
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    if not isinstance(json_obj, dict):
        common.send_browser_api_error(handler, 400, "JSON object required")
        return
    action = json_obj.get("action")
    extra = set(json_obj.keys()) - {"action", "csrf_token"}
    if action not in _BLUETOOTH_SERVICES_ALLOWED_ACTIONS or extra:
        common.send_browser_api_error(handler, 400, "Invalid action")
        return

    try:
        ok, message = bt_services_enable() if action == "enable" else bt_services_disable()
    except Exception as e:
        logging.exception("send_bluetooth_services_post_json: %s failed", action)
        common.send_json(handler, 200, {"ok": False, "message": str(e)})
        return
    common.send_json(handler, 200, {"ok": bool(ok), "message": str(message)})


def send_bluetooth_onboard_post_json(handler, json_obj) -> None:
    """POST /api/bluetooth/onboard {"enabled": bool}.

    Edits ``dtoverlay=disable-bt`` in config.txt via ``bt_onboard_set()``.
    On success, ``reboot_required: true`` tells the frontend to drive the
    existing reboot holding-page flow -- this handler does not reboot.
    """
    if not bluetooth_installed():
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    if not isinstance(json_obj, dict):
        common.send_browser_api_error(handler, 400, "JSON object required")
        return
    enabled = json_obj.get("enabled")
    extra = set(json_obj.keys()) - {"enabled", "csrf_token"}
    if not isinstance(enabled, bool) or extra:
        common.send_browser_api_error(handler, 400, "Invalid enabled value")
        return

    try:
        ok, message = bt_onboard_set(enabled)
    except Exception as e:
        logging.exception("send_bluetooth_onboard_post_json: bt_onboard_set failed")
        common.send_json(handler, 200, {"ok": False, "message": str(e)})
        return
    resp: dict = {"ok": bool(ok), "message": str(message)}
    if ok:
        resp["reboot_required"] = True
    common.send_json(handler, 200, resp)


def send_bluetooth_buffer_post_json(handler, json_obj) -> None:
    """POST /api/bluetooth/buffer {"buffer_ms": int} -- daemon configure passthrough.

    Server-side range validation (100-500 ms, matching the card's slider)
    happens before ever touching the daemon; the daemon's own
    ``invalid_buffer_ms`` rejection (defence in depth) is surfaced as 400
    too. An unreachable daemon is a 503 ``bluetooth_unavailable``.
    """
    if not bluetooth_installed():
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    if not isinstance(json_obj, dict):
        common.send_browser_api_error(handler, 400, "JSON object required")
        return
    buffer_ms = json_obj.get("buffer_ms")
    extra = set(json_obj.keys()) - {"buffer_ms", "csrf_token"}
    if (
        isinstance(buffer_ms, bool)
        or not isinstance(buffer_ms, int)
        or not (_BLUETOOTH_BUFFER_MS_MIN <= buffer_ms <= _BLUETOOTH_BUFFER_MS_MAX)
        or extra
    ):
        common.send_browser_api_error(handler, 400, "invalid_buffer_ms")
        return

    result = BluetoothClient().configure(buffer_ms)
    if not isinstance(result, dict):
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    if result.get("ok") is not True:
        if result.get("error") == "invalid_buffer_ms":
            common.send_browser_api_error(handler, 400, "invalid_buffer_ms")
            return
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    common.send_json(handler, 200, {"ok": True, "buffer_ms": buffer_ms})


# -----------------------------------------------------------------------------
# SD card health monitoring
# -----------------------------------------------------------------------------

def send_sdcard_health_get_json(handler) -> None:
    """GET /api/sdcard-health — read-only, no CSRF; current monitoring state."""
    common.send_json(handler, 200, sdcard_health_state())


def send_sdcard_health_enable_post_json(handler, json_obj) -> None:
    """POST /api/sdcard-health/enable {"method": str, "csrf_token": str}.

    Runs the guarded probe for *method* first (the wrapper's `check` verb,
    which never enables anything) and only enables scheduled monitoring on
    a passing result -- an unsupported or hung card is refused with 409
    and the timer is left untouched. Wrapper exit codes: 0 passed, 3 failed,
    4 hung marker found, 2 tool missing.
    """
    if not isinstance(json_obj, dict):
        common.send_browser_api_error(handler, 400, "JSON object required")
        return
    method = json_obj.get("method")
    extra = set(json_obj.keys()) - {"method", "csrf_token"}
    if not isinstance(method, str) or method not in SDCARD_HEALTH_METHODS or extra:
        common.send_browser_api_error(handler, 400, "Invalid method")
        return

    ok, code, payload = sdcard_health_check(method)
    if not ok:
        if code == 3:
            common.send_browser_api_error(handler, 409, "unsupported", extra={"reason": payload.get("reason", "")})
            return
        if code == 4:
            common.send_browser_api_error(handler, 409, "hung")
            return
        if code == 2:
            common.send_browser_api_error(handler, 503, "tool_missing")
            return
        common.send_browser_api_error(handler, 500, "check_failed", extra={"output": payload.get("output", "")})
        return

    ok, code, payload = sdcard_health_enable(method)
    if not ok:
        common.send_browser_api_error(handler, 500, "enable_failed", extra={"output": payload.get("output", "")})
        return
    common.send_json(handler, 200, {"ok": True, "state": sdcard_health_state()})


def send_sdcard_health_disable_post_json(handler, json_obj) -> None:
    """POST /api/sdcard-health/disable {"csrf_token": str}."""
    if not isinstance(json_obj, dict):
        common.send_browser_api_error(handler, 400, "JSON object required")
        return
    extra = set(json_obj.keys()) - {"csrf_token"}
    if extra:
        common.send_browser_api_error(handler, 400, "Invalid request")
        return

    ok, code, payload = sdcard_health_disable()
    if not ok:
        common.send_browser_api_error(handler, 500, "disable_failed", extra={"output": payload.get("output", "")})
        return
    common.send_json(handler, 200, {"ok": True, "state": sdcard_health_state()})
