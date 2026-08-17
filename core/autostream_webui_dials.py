"""autostream_webui_dials.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

HTTP handler functions for all dial management endpoints.

All host-side proxy handlers normalize responses for the main autostream NGINX
boundary (see docs/API-ERROR-CONTRACT.md). Statuses 404/502/503/504 cannot be
used as browser transport status because NGINX intercepts them; they are tunneled
through HTTP 200 with error_status carrying the semantic code.

Host error contract:
  - dial UUID absent from live registry → transport 200, error: dial_offline, error_status: 404
  - connection refused / network failure / socket timeout → transport 200, error: dial_unreachable, error_status: 502
  - target body not valid JSON / non-object JSON / oversized body → transport 200, error: dial_bad_response, error_status: 502
  - target 3xx → rejected before JSON pass-through as dial_bad_response (error_status: 502)
  - target 404/502/503/504 → tunneled through transport 200 with error_status
  - target 400/403/429/500 → passed through natively (not intercepted by NGINX)
"""
from __future__ import annotations

import http.client
import json as _json
import logging

from autostream_dials import (
    get_dial_sighting,
    remove_dial_entry,
    validate_dial_name,
    write_dial_entry,
)
from autostream_webui_api import send_json, send_browser_api_error, _NGINX_INTERCEPTED_STATUSES

_PROXY_TIMEOUT = 4  # seconds — short; dial is on the same LAN

# Maximum target-response body size. A body of exactly 65,536 bytes is accepted;
# 65,537 bytes is rejected as dial_bad_response before JSON parsing.
_MAX_PROXY_RESPONSE_BYTES = 64 * 1024  # 65,536

# Default error identifiers for tunneled target statuses.
_TARGET_STATUS_ERRORS: dict[int, str] = {
    404: "not_found",
    502: "dial_bad_response",
    503: "dial_unavailable",
    504: "dial_timeout",
}


class _BadTargetResponse(Exception):
    """Raised inside _proxy_call when the target body must be rejected."""


# ---------------------------------------------------------------------------
# Proxy helper
# ---------------------------------------------------------------------------

def _proxy_call(method: str, ip: str, port: int, path: str,
                body: bytes | None = None) -> tuple[int, dict]:
    """Send HTTP request to a dial and return (target_status, parsed_json_object).

    Raises:
      ConnectionError (or subclass) on network failure.
      _BadTargetResponse if the body is oversized, is a redirect (3xx), is not
        valid JSON, or the JSON root is not an object.
    """
    conn = http.client.HTTPConnection(ip, port, timeout=_PROXY_TIMEOUT)
    headers = {"Content-Type": "application/json"} if body else {}
    try:
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        target_status = resp.status

        # Read with an overflow sentinel byte so we can detect 65,537 bytes
        # without buffering the entire oversized body.
        raw = resp.read(_MAX_PROXY_RESPONSE_BYTES + 1)

        if len(raw) > _MAX_PROXY_RESPONSE_BYTES:
            raise _BadTargetResponse("target response exceeded size limit")

        # Reject redirects before JSON parsing — no dial endpoint legitimately
        # redirects, and a redirect body that happens to be valid JSON must not
        # be passed through to the browser.
        if 300 <= target_status <= 399:
            raise _BadTargetResponse(f"target returned redirect {target_status}")

        try:
            parsed = _json.loads(raw)
        except Exception:
            raise _BadTargetResponse("target body is not valid JSON")

        if not isinstance(parsed, dict):
            raise _BadTargetResponse("target body JSON root is not an object")

        return target_status, parsed
    finally:
        conn.close()


def _get_sighting_or_error(handler, uuid: str):
    """Return DialSighting for uuid, or send a tunneled 404 and return None."""
    sighting = get_dial_sighting(uuid)
    if sighting is None:
        send_browser_api_error(handler, 404, "dial_offline", retryable=True)
    return sighting


def _normalize_target_response(
    handler,
    target_status: int,
    data: dict,
) -> None:
    """Send the final browser-facing response after a successful _proxy_call().

    Non-intercepted target statuses (400/403/429/500) pass through natively.
    Intercepted statuses (404/502/503/504) are tunneled through HTTP 200 with
    error_status; safe object fields from the target body are preserved.
    """
    if target_status not in _NGINX_INTERCEPTED_STATUSES:
        # Native pass-through — NGINX will not intercept this status.
        send_json(handler, target_status, data)
        return

    # Tunnel the intercepted status.  Use the target's stable error identifier
    # if it provided one; otherwise fall back to a safe default for this status.
    error_id = data.get("error") if isinstance(data.get("error"), str) and data["error"] else None
    if not error_id:
        error_id = _TARGET_STATUS_ERRORS.get(target_status, "dial_bad_response")

    # Build normalized body, then merge safe endpoint-specific fields.
    # The caller cannot override ok, error, or error_status via the target body.
    retryable_field: dict = {}
    if target_status in (502, 503, 504):
        retryable_field = {"retryable": True}
    elif target_status == 404:
        # For 404, preserve a target-provided retryable if present.
        if "retryable" in data:
            retryable_field = {"retryable": data["retryable"]}

    payload: dict = {"ok": False, "error": error_id, "error_status": target_status}
    payload.update(retryable_field)

    # Merge safe target fields (anything that is not a reserved key).
    reserved = {"ok", "error", "error_status", "retryable"}
    for k, v in data.items():
        if k not in reserved:
            payload[k] = v

    send_json(handler, 200, payload)


def _proxy_get(handler, uuid: str, dial_path: str) -> None:
    sighting = _get_sighting_or_error(handler, uuid)
    if sighting is None:
        return
    try:
        target_status, data = _proxy_call("GET", sighting.ip, sighting.port, dial_path)
    except OSError as e:
        logging.debug("dial proxy GET %s: %s", dial_path, e)
        send_browser_api_error(handler, 502, "dial_unreachable", retryable=True)
        return
    except _BadTargetResponse as e:
        logging.debug("dial proxy GET %s bad response: %s", dial_path, e)
        send_browser_api_error(handler, 502, "dial_bad_response", retryable=True)
        return
    _normalize_target_response(handler, target_status, data)


def _proxy_post(handler, uuid: str, dial_path: str, body_dict) -> None:
    sighting = _get_sighting_or_error(handler, uuid)
    if sighting is None:
        return
    body_bytes = _json.dumps(body_dict).encode() if body_dict is not None else None
    try:
        target_status, data = _proxy_call("POST", sighting.ip, sighting.port,
                                          dial_path, body=body_bytes)
    except OSError as e:
        logging.debug("dial proxy POST %s: %s", dial_path, e)
        send_browser_api_error(handler, 502, "dial_unreachable", retryable=True)
        return
    except _BadTargetResponse as e:
        logging.debug("dial proxy POST %s bad response: %s", dial_path, e)
        send_browser_api_error(handler, 502, "dial_bad_response", retryable=True)
        return
    _normalize_target_response(handler, target_status, data)


# ---------------------------------------------------------------------------
# Management dispatcher (session + CSRF required)
# ---------------------------------------------------------------------------

def dispatch_dial_management_post(handler, path: str, json_obj) -> None:
    body = json_obj if isinstance(json_obj, dict) else {}
    if path == "/api/dial/authorize":
        handle_dial_authorize_post(handler, body)
    elif path == "/api/dial/revoke":
        handle_dial_revoke_post(handler, body)
    elif path == "/api/dial/configure":
        handle_dial_configure_post(handler, body)
    elif path == "/api/dial/pin_recovery/complete":
        handle_dial_pin_recovery_complete_post(handler, body)
    elif path == "/api/dial/recovery/arm":
        handle_dial_recovery_arm_post(handler, body)
    elif path == "/api/dial/recovery/disarm":
        handle_dial_recovery_disarm_post(handler, body)
    else:
        # Known dispatcher, unknown management path — tunnel the semantic 404
        # so it survives NGINX interception on the browser boundary.
        send_browser_api_error(handler, 404, "not_found")


# ---------------------------------------------------------------------------
# Authorize / revoke
# ---------------------------------------------------------------------------

def handle_dial_authorize_post(handler, json_obj: dict) -> None:
    uuid = json_obj.get("uuid", "")
    name = json_obj.get("name", "")
    if not isinstance(uuid, str) or not uuid:
        send_json(handler, 400, {"ok": False, "error": "missing_uuid"})
        return
    if not isinstance(name, str) or not name:
        send_json(handler, 400, {"ok": False, "error": "missing_name"})
        return
    if not validate_dial_name(name):
        send_json(handler, 400, {"ok": False, "error": "invalid_name"})
        return
    write_dial_entry(uuid, name)
    send_json(handler, 200, {"ok": True})


def handle_dial_revoke_post(handler, json_obj: dict) -> None:
    uuid = json_obj.get("uuid", "")
    if not isinstance(uuid, str) or not uuid:
        send_json(handler, 400, {"ok": False, "error": "missing_uuid"})
        return
    remove_dial_entry(uuid)
    send_json(handler, 200, {"ok": True})


# ---------------------------------------------------------------------------
# Configure (proxy to dial's /configure endpoint)
# ---------------------------------------------------------------------------

def handle_dial_configure_post(handler, json_obj: dict) -> None:
    uuid = json_obj.get("uuid", "")
    if not isinstance(uuid, str) or not uuid:
        send_json(handler, 400, {"ok": False, "error": "missing_uuid"})
        return
    body = {k: v for k, v in json_obj.items() if k != "uuid"}
    _proxy_post(handler, uuid, "/configure", body)


def handle_dial_pin_recovery_complete_post(handler, json_obj: dict) -> None:
    uuid = json_obj.get("uuid", "")
    if not isinstance(uuid, str) or not uuid:
        send_json(handler, 400, {"ok": False, "error": "missing_uuid"})
        return
    body = {k: v for k, v in json_obj.items() if k != "uuid"}
    _proxy_post(handler, uuid, "/configure", body)


def handle_dial_recovery_arm_post(handler, json_obj: dict) -> None:
    uuid = json_obj.get("uuid", "")
    if not isinstance(uuid, str) or not uuid:
        send_json(handler, 400, {"ok": False, "error": "missing_uuid"})
        return
    _proxy_post(handler, uuid, "/recovery/arm", None)


def handle_dial_recovery_disarm_post(handler, json_obj: dict) -> None:
    uuid = json_obj.get("uuid", "")
    if not isinstance(uuid, str) or not uuid:
        send_json(handler, 400, {"ok": False, "error": "missing_uuid"})
        return
    _proxy_post(handler, uuid, "/recovery/disarm", None)


def handle_dial_configure_get(handler, uuid: str) -> None:
    _proxy_get(handler, uuid, "/configure")


def handle_dial_pin_recovery_status(handler, uuid: str) -> None:
    _proxy_get(handler, uuid, "/recovery_status")


# ---------------------------------------------------------------------------
# Update (proxy to dial's /update endpoint)
# ---------------------------------------------------------------------------

def handle_dial_update_post(handler, uuid: str) -> None:
    _proxy_post(handler, uuid, "/update", None)


def handle_dial_update_status(handler, uuid: str) -> None:
    _proxy_get(handler, uuid, "/update/status")


# ---------------------------------------------------------------------------
# Screen settings (proxy to dial's /screen/settings endpoint)
# ---------------------------------------------------------------------------

def handle_dial_screen_settings_get(handler, uuid: str) -> None:
    _proxy_get(handler, uuid, "/screen/settings")


def handle_dial_screen_settings_post(handler, json_obj: dict) -> None:
    uuid = json_obj.get("uuid", "")
    if not isinstance(uuid, str) or not uuid:
        send_json(handler, 400, {"ok": False, "error": "missing_uuid"})
        return
    body = {k: v for k, v in json_obj.items() if k != "uuid"}
    _proxy_post(handler, uuid, "/screen/settings", body)
