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
import queue
import threading
import time
from dataclasses import dataclass

from autostream_dials import (
    dial_proto_generation,
    get_dial_sighting,
    parse_dial_entries,
    remove_dial_entry,
    validate_dial_name,
    write_dial_entry,
)
from autostream_rpi import get_appliance_id
from autostream_webui_api import send_json, send_browser_api_error, _NGINX_INTERCEPTED_STATUSES
from autostream_webui_common import send_bytes

_PROXY_TIMEOUT = 4  # seconds — short; dial is on the same LAN

# Maximum target-response body size. A body of exactly 65,536 bytes is accepted;
# 65,537 bytes is rejected as dial_bad_response before JSON parsing.
_MAX_PROXY_RESPONSE_BYTES = 64 * 1024  # 65,536

# Maximum size for a binary proxy response (e.g. a screenshot) — a
# 640x480 PNG of the panel is well under this.
_MAX_PROXY_IMAGE_BYTES = 2 * 1024 * 1024

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


def _proxy_get_bytes(handler, uuid: str, dial_path: str, *, accept_type: str) -> None:
    """Proxy a binary GET to the dial: the body is streamed back with the
    dial's content type when it is *accept_type*; the dial's JSON error
    replies (and every transport failure) are normalized exactly as
    _proxy_get() normalizes them, so the browser sees the same error
    contract for an image as for a settings call."""
    sighting = _get_sighting_or_error(handler, uuid)
    if sighting is None:
        return
    conn = http.client.HTTPConnection(sighting.ip, sighting.port, timeout=_PROXY_TIMEOUT)
    try:
        conn.request("GET", dial_path)
        resp = conn.getresponse()
        status = resp.status
        content_type = (resp.getheader("Content-Type") or "").split(";", 1)[0].strip().lower()
        raw = resp.read(_MAX_PROXY_IMAGE_BYTES + 1)
    except OSError as e:
        logging.debug("dial proxy GET %s: %s", dial_path, e)
        send_browser_api_error(handler, 502, "dial_unreachable", retryable=True)
        return
    finally:
        conn.close()
    if len(raw) > _MAX_PROXY_IMAGE_BYTES or 300 <= status <= 399:
        send_browser_api_error(handler, 502, "dial_bad_response", retryable=True)
        return
    if status == 200 and content_type == accept_type:
        send_bytes(handler, 200, accept_type, raw, extra_headers={"Cache-Control": "no-store"})
        return
    if content_type == "application/json":
        try:
            data = _json.loads(raw)
        except Exception:
            data = None
        if isinstance(data, dict):
            _normalize_target_response(handler, status, data)
            return
    send_browser_api_error(handler, 502, "dial_bad_response", retryable=True)


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
# Dial pushes
# ---------------------------------------------------------------------------
# Best-effort notifications to a dial: "authorization may have changed"
# (/auth-changed) and "warnings may have changed" (/warnings-changed). Each
# only causes the dial to fetch or poll now instead of waiting for its next
# scheduled tick, and grants nothing by itself, so a lost or failed push is
# harmless: the dial's own poll and reconcile are the source of truth.
#
# Every push goes through one worker thread fed by a queue, so a burst of
# changes costs one thread however many pushes it holds; a slow dial delays
# the pushes behind it by at most the timeout and one retry.
#
# A job naming one dial is tried, then retried once. A job naming no dial is a
# fan-out: the worker resolves the eligible dials when it runs it and sends to
# each once with no retry. A dial that did not answer is skipped for a few
# seconds and tried last afterwards, so an unreachable dial does not hold up
# the others.

_PUSH_TIMEOUT_S = 1.0
_PUSH_RETRY_DELAY_S = 2.0
_AUTH_CHANGED_PATH = "/auth-changed"

# After a failed fan-out send a dial is skipped for this long and sent to last
# thereafter.
STATE_FANOUT_BACKOFF_S = 5.0
# A failure mark older than this is forgotten, which bounds the table.
_PUSH_ENTRY_MAX_AGE_S = 60.0


@dataclass(frozen=True)
class _PushJob:
    path: str
    uuid: str | None          # None: every eligible dial, resolved when the job runs
    body: dict
    min_generation: int = 0
    exclude: frozenset = frozenset()


_push_queue: "queue.SimpleQueue[_PushJob]" = queue.SimpleQueue()
_push_worker_lock = threading.Lock()
_push_worker_thread: threading.Thread | None = None
# uuid -> monotonic time of its last failed fan-out send. Worker thread only.
_fanout_failed_at: dict[str, float] = {}


def _post_push_body(ip: str, port: int, path: str, body: dict, timeout: float) -> bool:
    """One POST of the JSON object *body* to *path* on the dial's own server.
    Never raises.

    Returns True on any 2xx response. Plain http.client, no redirects
    followed and no interest in the response body -- the push is advisory.
    """
    conn = None
    try:
        conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        conn.request("POST", path, body=_json.dumps(body).encode(),
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        resp.read()
        return 200 <= resp.status < 300
    except Exception as e:
        logging.debug("dial push: POST %s:%s%s failed: %s", ip, port, path, e)
        return False
    finally:
        if conn is not None:
            conn.close()


def _post_push(ip: str, port: int, path: str, appliance_id: str, timeout: float) -> bool:
    """One POST of {"appliance_id": ...} to *path*; see _post_push_body."""
    return _post_push_body(ip, port, path, {"appliance_id": appliance_id}, timeout)


def _push_once(path: str, uuid: str, appliance_id: str) -> None:
    """One push job: one attempt, one retry after a short delay."""
    sighting = get_dial_sighting(uuid)
    if sighting is None:
        logging.debug("dial push: %s not sighted, skipping", uuid)
        return
    if _post_push(sighting.ip, sighting.port, path, appliance_id, _PUSH_TIMEOUT_S):
        return
    time.sleep(_PUSH_RETRY_DELAY_S)
    _post_push(sighting.ip, sighting.port, path, appliance_id, _PUSH_TIMEOUT_S)


def eligible_dial_uuids(min_generation: int, *, exclude=()) -> list[str]:
    """The authorised dials that are sighted now and speak at least
    *min_generation*, in the authorised list's order, less *exclude*. Reads
    the dials file: not for a request thread or the coordinator loop."""
    out = []
    for entry in parse_dial_entries():
        if entry.uuid in exclude:
            continue
        sighting = get_dial_sighting(entry.uuid)
        if sighting is None or dial_proto_generation(sighting.dial_proto) < min_generation:
            continue
        out.append(entry.uuid)
    return out


def _fanout(job: _PushJob) -> None:
    """One fan-out job: *job.body* plus the appliance id, sent once to each
    eligible dial. No retry and no sleep. Dials that have not failed lately go
    first; one that failed is skipped for STATE_FANOUT_BACKOFF_S and goes last
    after that. Runs on the worker thread, which owns _fanout_failed_at."""
    appliance_id = get_appliance_id()
    if not appliance_id:
        return
    body = dict(job.body)
    body["appliance_id"] = appliance_id
    now = time.monotonic()
    for uuid in [u for u, t in _fanout_failed_at.items() if now - t > _PUSH_ENTRY_MAX_AGE_S]:
        del _fanout_failed_at[uuid]
    uuids = eligible_dial_uuids(job.min_generation, exclude=job.exclude)
    for uuid in sorted(uuids, key=lambda u: _fanout_failed_at.get(u, 0.0)):
        failed_at = _fanout_failed_at.get(uuid)
        if failed_at is not None and now - failed_at < STATE_FANOUT_BACKOFF_S:
            continue
        sighting = get_dial_sighting(uuid)
        if sighting is None:
            continue
        if _post_push_body(sighting.ip, sighting.port, job.path, body, _PUSH_TIMEOUT_S):
            _fanout_failed_at.pop(uuid, None)
        else:
            _fanout_failed_at[uuid] = time.monotonic()
            logging.debug("dial push: %s did not take %s, skipping it for %.0f s",
                          uuid, job.path, STATE_FANOUT_BACKOFF_S)


def _run_job(job: _PushJob) -> None:
    if job.uuid is not None:
        _push_once(job.path, job.uuid, job.body["appliance_id"])
    else:
        _fanout(job)


def _push_worker_loop(jobs: "queue.SimpleQueue[_PushJob]") -> None:
    while True:
        job = jobs.get()
        try:
            _run_job(job)
        except Exception:
            logging.debug("dial push: job failed", exc_info=True)


def _enqueue(job: _PushJob) -> None:
    """Queue *job*, starting the worker thread on first use. Never blocks on
    the network."""
    global _push_worker_thread
    with _push_worker_lock:
        if _push_worker_thread is None or not _push_worker_thread.is_alive():
            _push_worker_thread = threading.Thread(
                target=_push_worker_loop, args=(_push_queue,),
                daemon=True, name="dial-push")
            _push_worker_thread.start()
    _push_queue.put(job)


def enqueue_push(path: str, uuid: str, appliance_id: str) -> None:
    """Queue one push of *path* to the dial *uuid*, starting the worker
    thread on first use. Never blocks on the network."""
    _enqueue(_PushJob(path, uuid, {"appliance_id": appliance_id}))


def enqueue_fanout(path: str, body: dict, *, min_generation: int,
                   exclude: frozenset = frozenset()) -> None:
    """Queue one push of *path* to every eligible dial, resolved when the
    worker runs it, with no retry. The appliance id is added then."""
    _enqueue(_PushJob(path, None, dict(body),
                      min_generation=min_generation, exclude=frozenset(exclude)))


def notify_dial_auth_changed(uuid: str) -> None:
    """Best-effort, fire-and-forget. Called by the authorize and revoke
    handlers AFTER their response is sent. No-op when this appliance has no
    identity (there is nothing to correlate on the dial). Goes to the one dial
    named, whether or not it is (still) authorised.
    """
    appliance_id = get_appliance_id()
    if not appliance_id:
        return
    enqueue_push(_AUTH_CHANGED_PATH, uuid, appliance_id)


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
    try:
        notify_dial_auth_changed(uuid)
    except Exception as e:
        logging.debug("dial auth push: enqueue failed after authorize: %s", e)


def handle_dial_revoke_post(handler, json_obj: dict) -> None:
    uuid = json_obj.get("uuid", "")
    if not isinstance(uuid, str) or not uuid:
        send_json(handler, 400, {"ok": False, "error": "missing_uuid"})
        return
    remove_dial_entry(uuid)
    send_json(handler, 200, {"ok": True})
    try:
        notify_dial_auth_changed(uuid)
    except Exception as e:
        logging.debug("dial auth push: enqueue failed after revoke: %s", e)


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


# ---------------------------------------------------------------------------
# Screen image (proxy to dial's /screen/image endpoint)
# ---------------------------------------------------------------------------

def handle_dial_screen_image_get(handler, uuid: str) -> None:
    _proxy_get_bytes(handler, uuid, "/screen/image", accept_type="image/png")


# ---------------------------------------------------------------------------
# SD card health (proxy to the dial's /sdcard-health endpoint)
# ---------------------------------------------------------------------------

def handle_dial_sdcard_health_get(handler, uuid: str) -> None:
    _proxy_get(handler, uuid, "/sdcard-health")


def handle_dial_sdcard_health_post(handler, json_obj: dict) -> None:
    uuid = json_obj.get("uuid", "")
    if not isinstance(uuid, str) or not uuid:
        send_json(handler, 400, {"ok": False, "error": "missing_uuid"})
        return
    body = {k: v for k, v in json_obj.items() if k != "uuid"}
    _proxy_post(handler, uuid, "/sdcard-health", body)
