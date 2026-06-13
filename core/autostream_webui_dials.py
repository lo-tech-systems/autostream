"""autostream_webui_dials.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

HTTP handler functions for all dial management endpoints.  All proxy
handlers follow the same offline/failure contract:
  - dial not in mDNS registry → 404  {"ok": false, "error": "dial_offline"}
  - network error (OSError/timeout) → 502  {"ok": false, "error": "dial_unreachable"}
  - non-JSON response from dial → 502  {"ok": false, "error": "dial_bad_response"}
  - dial returns non-200 status → pass through verbatim
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
from autostream_webui_api import send_json

_PROXY_TIMEOUT = 4  # seconds — short; dial is on the same LAN


# ---------------------------------------------------------------------------
# Proxy helper
# ---------------------------------------------------------------------------

def _proxy_call(method: str, ip: str, port: int, path: str,
                body: bytes | None = None) -> tuple[int, dict]:
    """Send HTTP request to a dial and return (status_code, parsed_json).

    Raises ConnectionError (or subclass) on network failure so callers can
    map to 502.  Raises ValueError if the response body is not valid JSON.
    """
    conn = http.client.HTTPConnection(ip, port, timeout=_PROXY_TIMEOUT)
    headers = {"Content-Type": "application/json"} if body else {}
    try:
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        return resp.status, _json.loads(raw)
    finally:
        conn.close()


def _get_sighting_or_404(handler, uuid: str):
    """Return DialSighting for uuid, or send 404 and return None."""
    sighting = get_dial_sighting(uuid)
    if sighting is None:
        send_json(handler, 404, {"ok": False, "error": "dial_offline"})
    return sighting


def _proxy_get(handler, uuid: str, dial_path: str) -> None:
    sighting = _get_sighting_or_404(handler, uuid)
    if sighting is None:
        return
    try:
        status, data = _proxy_call("GET", sighting.ip, sighting.port, dial_path)
    except OSError as e:
        logging.debug("dial proxy GET %s: %s", dial_path, e)
        send_json(handler, 502, {"ok": False, "error": "dial_unreachable"})
        return
    except ValueError:
        send_json(handler, 502, {"ok": False, "error": "dial_bad_response"})
        return
    send_json(handler, status, data)


def _proxy_post(handler, uuid: str, dial_path: str, body_dict) -> None:
    sighting = _get_sighting_or_404(handler, uuid)
    if sighting is None:
        return
    body_bytes = _json.dumps(body_dict).encode() if body_dict is not None else None
    try:
        status, data = _proxy_call("POST", sighting.ip, sighting.port,
                                   dial_path, body=body_bytes)
    except OSError as e:
        logging.debug("dial proxy POST %s: %s", dial_path, e)
        send_json(handler, 502, {"ok": False, "error": "dial_unreachable"})
        return
    except ValueError:
        send_json(handler, 502, {"ok": False, "error": "dial_bad_response"})
        return
    send_json(handler, status, data)


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
    else:
        send_json(handler, 404, {"ok": False, "error": "not_found"})


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
