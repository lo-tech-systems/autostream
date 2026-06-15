"""autostream_appliance_gateway.py — bound-appliance gateway for remote appliances.

Provides:
  - /api/appliances (appliance list with bound-first ordering)
  - /api/appliances/<id>/{home, equaliser, equaliser/status, output,
                          equaliser/config, equaliser/reset}

Remote dispatch uses the live mDNS registry only; no browser-supplied
addresses are ever accepted.  Token caching, per-target exponential
backoff, one-second successful-read caching and per-target request
coalescing are all in-memory and process-scoped.

Backoff discipline: _remote_request() is a pure transport helper with no
side-effects on backoff state.  Callers (_coalesced_remote_get and each
POST handler) are responsible for calling _update_backoff() after every
completed request so that success clears the counter and failure advances
it exactly once.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import http.client
import json
import logging
import re
import socket
import threading
import time
from typing import Optional

from autostream_appliance_models import (
    apply_eq_field,
    apply_eq_reset,
    apply_output_mutation,
    build_equaliser_state,
    build_home_state,
)
from autostream_appliances import (
    ApplianceSighting,
    get_all_appliances,
    get_appliance_sighting,
    get_conflict_ids,
    grace_remaining_ms,
    scanner_ready,
)
from autostream_config import DEFAULT_AIRPLAY_MODE, parse_config
from autostream_core import get_live_output_eq_status
from autostream_player_service import config_airplay_mode_to_backend
from autostream_rpi import get_appliance_id
from autostream_webui_api import send_browser_api_error, send_json
from autostream_webui_common import locked_load_config

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_APPLIANCE_ID_RE = re.compile(r'^[0-9a-f]{20}$')
_TOKEN_RENEW_MARGIN = 120          # seconds — renew token when < 2 min remain
_BACKOFF_STEPS = (1, 2, 4, 8, 15)  # per-target exponential backoff in seconds
_REMOTE_RESPONSE_MAX = 256 * 1024  # 256 KiB response body cap
_CONNECT_TIMEOUT = 1.0             # seconds
_READ_TIMEOUT = 2.0                # seconds
_READ_CACHE_TTL = 1.0              # seconds for successful-read cache
_FED_VERSION_HEADER = "1"


# ---------------------------------------------------------------------------
# Module-level state (all under _state_lock)
# ---------------------------------------------------------------------------

_state_lock = threading.Lock()

# token cache: appliance_id → (token, expires_monotonic)
_token_cache: dict[str, tuple[str, float]] = {}

# backoff state: appliance_id → (backoff_until_monotonic, step_index)
_backoff_state: dict[str, tuple[float, int]] = {}

# successful-read cache: (appliance_id, fed_path) → (data_dict, cache_until_monotonic)
_read_cache: dict[tuple[str, str], tuple[dict, float]] = {}

# in-flight coalescing: (appliance_id, fed_path) → (Event, result_list)
_in_flight: dict[tuple[str, str], tuple[threading.Event, list]] = {}


# ---------------------------------------------------------------------------
# ID resolution
# ---------------------------------------------------------------------------

def resolve_appliance(appliance_id: str) -> tuple[str, Optional[ApplianceSighting]]:
    """Resolve *appliance_id* using one thread-safe registry snapshot.

    Returns (resolution, sighting) where resolution is one of:
      'invalid'   — not exactly 20 lowercase hex characters
      'bound'     — equals the local appliance ID
      'conflict'  — in the registry conflict set
      'remote'    — has a live, eligible registry entry
      'offline'   — syntactically valid but not in the live registry
    """
    if not _APPLIANCE_ID_RE.match(appliance_id):
        return "invalid", None
    local_id = get_appliance_id()
    if local_id and appliance_id == local_id:
        return "bound", None
    conflicts = get_conflict_ids()
    if appliance_id in conflicts:
        return "conflict", None
    sighting = get_appliance_sighting(appliance_id)
    if sighting is not None:
        return "remote", sighting
    return "offline", None


# ---------------------------------------------------------------------------
# Backoff management (must be called with _state_lock held)
# ---------------------------------------------------------------------------

def _check_backoff_locked(appliance_id: str) -> tuple[bool, int]:
    """Return (in_backoff, retry_after_seconds). Lock must be held."""
    bs = _backoff_state.get(appliance_id)
    if bs is None:
        return False, 0
    until, _ = bs
    now = time.monotonic()
    if now >= until:
        return False, 0
    return True, max(1, int(until - now) + 1)


def _record_failure_locked(appliance_id: str) -> None:
    """Advance per-target backoff. Lock must be held."""
    bs = _backoff_state.get(appliance_id)
    if bs is None:
        step_idx = 0
    else:
        _, step_idx = bs
        step_idx = min(step_idx + 1, len(_BACKOFF_STEPS) - 1)
    delay = _BACKOFF_STEPS[step_idx]
    _backoff_state[appliance_id] = (time.monotonic() + delay, step_idx)


def _record_success_locked(appliance_id: str) -> None:
    """Reset per-target backoff. Lock must be held."""
    _backoff_state.pop(appliance_id, None)


# ---------------------------------------------------------------------------
# Token management
# ---------------------------------------------------------------------------

def _get_token_from_cache_locked(appliance_id: str) -> Optional[str]:
    """Return cached token if still valid with renew margin. Lock must be held."""
    entry = _token_cache.get(appliance_id)
    if entry is None:
        return None
    token, expires = entry
    if time.monotonic() < expires - _TOKEN_RENEW_MARGIN:
        return token
    return None


def _acquire_token(appliance_id: str, sighting: ApplianceSighting) -> tuple[Optional[str], str]:
    """Acquire a new federation token from the target. Returns (token, error_code)."""
    status, data = _remote_federation_request(
        "POST", sighting, "/api/federation/v1/session",
        token="",  # no token needed for session creation
        body={},
    )
    if status == 0:
        error_code = data.get("error", "remote_timeout")
        return None, error_code

    if status != 200 or not data.get("ok"):
        error_code = data.get("error", "remote_bad_response")
        if error_code not in ("appliance_unconfigured", "appliance_identity_unavailable",
                               "rate_limited"):
            error_code = "remote_bad_response"
        return None, error_code

    # Validate exact v1 session schema
    token = data.get("token")
    token_type = data.get("token_type")
    expires_in = data.get("expires_in")
    fed_version = data.get("federation_version")
    if (
        not isinstance(token, str) or not token
        or token_type != "Bearer"
        or not isinstance(expires_in, int) or isinstance(expires_in, bool) or expires_in <= 0
        or not isinstance(fed_version, int) or isinstance(fed_version, bool)
    ):
        logging.warning("gateway: target %s returned malformed session schema", appliance_id)
        return None, "remote_bad_response"

    received_at = time.monotonic()
    expires = received_at + expires_in
    with _state_lock:
        _token_cache[appliance_id] = (token, expires)
    return token, ""


def _get_or_renew_token(appliance_id: str, sighting: ApplianceSighting) -> tuple[Optional[str], str]:
    """Return a valid bearer token for *appliance_id*, acquiring one if needed."""
    with _state_lock:
        token = _get_token_from_cache_locked(appliance_id)
    if token:
        return token, ""
    return _acquire_token(appliance_id, sighting)


def evict_gateway_token(appliance_id: str) -> None:
    """Evict the cached token for *appliance_id* (call on final peer removal)."""
    with _state_lock:
        _token_cache.pop(appliance_id, None)


# ---------------------------------------------------------------------------
# HTTP transport
# ---------------------------------------------------------------------------

def _remote_federation_request(
    method: str,
    sighting: ApplianceSighting,
    fed_path: str,
    token: str,
    body: Optional[dict] = None,
) -> tuple[int, dict]:
    """Issue one federation HTTP request to *sighting*. Returns (status, data).

    Status 0 means a transport failure (timeout or connection error).  The
    caller must never interpret the body on status 0.  The token is never
    logged.
    """
    headers: dict[str, str] = {
        "Accept": "application/json",
        "X-Autostream-Federation-Version": _FED_VERSION_HEADER,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    encoded_body: Optional[bytes] = None
    if body is not None:
        encoded_body = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(encoded_body))

    conn: Optional[http.client.HTTPConnection] = None
    try:
        conn = http.client.HTTPConnection(
            sighting.ip, sighting.port,
            timeout=_CONNECT_TIMEOUT,
        )
        conn.request(method, fed_path, body=encoded_body, headers=headers)
        if conn.sock:
            conn.sock.settimeout(_READ_TIMEOUT)
        resp = conn.getresponse()
        status = resp.status

        ct = (resp.getheader("Content-Type") or "").split(";", 1)[0].strip()
        if ct != "application/json":
            resp.read(_REMOTE_RESPONSE_MAX + 1)
            return 0, {"ok": False, "error": "remote_bad_response"}

        raw = resp.read(_REMOTE_RESPONSE_MAX + 1)
        if len(raw) > _REMOTE_RESPONSE_MAX:
            return 0, {"ok": False, "error": "remote_bad_response"}

        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return 0, {"ok": False, "error": "remote_bad_response"}

        if not isinstance(data, dict):
            return 0, {"ok": False, "error": "remote_bad_response"}

        return status, data

    except socket.timeout:
        return 0, {"ok": False, "error": "remote_timeout"}
    except OSError:
        return 0, {"ok": False, "error": "remote_timeout"}
    except Exception as exc:
        logging.debug("federation transport error: %s", type(exc).__name__)
        return 0, {"ok": False, "error": "remote_timeout"}
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Remote request dispatch (with token, backoff, retry-once on 401)
# ---------------------------------------------------------------------------

def _remote_request(
    appliance_id: str,
    sighting: ApplianceSighting,
    method: str,
    fed_path: str,
    body: Optional[dict] = None,
) -> tuple[int, dict]:
    """Full remote request cycle: token acquisition and retry-once on 401.

    Pure transport helper — does NOT update backoff state.  Callers must
    call _update_backoff() after every completed request.
    Returns (http_status, data_dict). Status 0 means transport failure.
    """
    token, err = _get_or_renew_token(appliance_id, sighting)
    if token is None:
        return 0, {"ok": False, "error": err or "remote_timeout"}

    status, data = _remote_federation_request(method, sighting, fed_path, token, body)

    if status == 401:
        # Token may have expired: evict and retry once with a fresh token
        with _state_lock:
            _token_cache.pop(appliance_id, None)
        token2, err2 = _acquire_token(appliance_id, sighting)
        if token2 is None:
            return 0, {"ok": False, "error": err2 or "remote_timeout"}
        status, data = _remote_federation_request(method, sighting, fed_path, token2, body)

    return status, data


def _update_backoff(appliance_id: str, status: int, data: dict) -> None:
    """Record backoff outcome after a completed _remote_request() call."""
    with _state_lock:
        if status == 200 and isinstance(data, dict) and data.get("ok"):
            _record_success_locked(appliance_id)
        else:
            _record_failure_locked(appliance_id)


# ---------------------------------------------------------------------------
# Coalesced remote GET (cache + coalescing + backoff)
# ---------------------------------------------------------------------------

def _coalesced_remote_get(
    appliance_id: str,
    sighting: ApplianceSighting,
    fed_path: str,
) -> tuple[int, dict]:
    """GET with one-second cache, per-target coalescing and backoff guard."""
    cache_key = (appliance_id, fed_path)
    event_to_wait: Optional[threading.Event] = None
    result_holder: Optional[list] = None
    am_owner = False

    with _state_lock:
        # Cache hit?
        cached = _read_cache.get(cache_key)
        if cached is not None:
            data, expires = cached
            if time.monotonic() < expires:
                return 200, data

        # Backoff guard
        in_backoff, retry_after = _check_backoff_locked(appliance_id)
        if in_backoff:
            return 0, {"ok": False, "error": "remote_backoff", "retry_after": retry_after}

        # Coalescing: join an in-flight request or become the owner
        flight = _in_flight.get(cache_key)
        if flight is not None:
            event_to_wait, result_holder = flight
        else:
            ev = threading.Event()
            rl: list = []
            _in_flight[cache_key] = (ev, rl)
            event_to_wait = ev
            result_holder = rl
            am_owner = True

    if not am_owner:
        # Wait for the owning request to complete
        event_to_wait.wait(timeout=_READ_TIMEOUT + 0.5)
        if result_holder:
            return result_holder[0]
        return 0, {"ok": False, "error": "remote_timeout"}

    # We are the owner: make the actual request
    try:
        status, data = _remote_request(appliance_id, sighting, "GET", fed_path)
    except Exception:
        logging.exception("_coalesced_remote_get: unexpected error")
        status, data = 0, {"ok": False, "error": "remote_timeout"}

    with _state_lock:
        result_holder.append((status, data))
        if status == 200 and isinstance(data, dict) and data.get("ok"):
            _read_cache[cache_key] = (data, time.monotonic() + _READ_CACHE_TTL)
            _record_success_locked(appliance_id)
        else:
            _record_failure_locked(appliance_id)
        del _in_flight[cache_key]
    event_to_wait.set()

    return status, data


# ---------------------------------------------------------------------------
# Browser response emission
# ---------------------------------------------------------------------------

def _gateway_error_to_browser(handler, resolution: str) -> None:
    """Emit the standard browser error for a pre-flight ID resolution failure."""
    if resolution == "invalid":
        send_browser_api_error(handler, 404, "not_found")
    elif resolution == "conflict":
        send_json(handler, 409, {"ok": False, "error": "appliance_conflicted"})
    elif resolution == "offline":
        send_browser_api_error(handler, 503, "appliance_offline", retryable=True)


def _check_and_emit_backoff(handler, appliance_id: str) -> bool:
    """Return True (and emit response) if target is currently in backoff."""
    with _state_lock:
        in_backoff, retry_after = _check_backoff_locked(appliance_id)
    if in_backoff:
        send_browser_api_error(handler, 429, "remote_backoff", retryable=True,
                               extra={"retry_after": retry_after})
    return in_backoff


def _handle_remote_response(handler, appliance_id: str, status: int, data: dict) -> None:  # noqa: ARG001
    """Emit the browser response for a completed remote request."""
    if status == 200 and isinstance(data, dict) and data.get("ok"):
        send_json(handler, 200, data)
        return

    err = data.get("error", "remote_timeout") if isinstance(data, dict) else "remote_timeout"

    if err == "remote_backoff":
        retry = data.get("retry_after", 1) if isinstance(data, dict) else 1
        send_browser_api_error(handler, 429, "remote_backoff", retryable=True,
                               extra={"retry_after": int(retry)})
    elif err in ("appliance_unconfigured", "appliance_identity_unavailable"):
        send_json(handler, 409, {"ok": False, "error": err})
    elif status == 200:
        # Target returned HTTP 200 but ok=False — application-level error on remote
        send_json(handler, 500, {"ok": False, "error": "target_error"})
    elif err == "remote_timeout":
        send_browser_api_error(handler, 504, err, retryable=True)
    elif err == "remote_bad_response":
        send_browser_api_error(handler, 502, err, retryable=True)
    elif err == "appliance_offline":
        send_browser_api_error(handler, 503, err, retryable=True)
    else:
        send_browser_api_error(handler, 502, err, retryable=True)


# ---------------------------------------------------------------------------
# Public: appliance list
# ---------------------------------------------------------------------------

def send_appliances_json(handler, state) -> None:  # noqa: ARG001
    """GET /api/appliances — bound-first appliance list."""
    local_id = get_appliance_id()
    if not local_id:
        send_json(handler, 500, {
            "ok": False,
            "error": "appliance_identity_unavailable",
            "retryable": False,
        })
        return

    ready = scanner_ready()
    grace_ms = grace_remaining_ms()

    peers = get_all_appliances()
    appliances = [
        {
            "id": local_id,
            "hostname": _local_hostname(),
            "version": _local_version(),
            "is_bound": True,
            "home_path": "/",
            "equaliser_path": "/equaliser",
        }
    ]
    for s in peers:
        if s.id == local_id:
            continue
        appliances.append({
            "id": s.id,
            "hostname": _format_hostname(s.hostname),
            "version": s.version,
            "is_bound": False,
            "home_path": f"/a/{s.id}/",
            "equaliser_path": f"/a/{s.id}/equaliser",
        })

    send_json(handler, 200, {
        "ok": True,
        "bound_appliance_id": local_id,
        "scanner": {
            "ready": ready,
            "grace_remaining_ms": grace_ms,
        },
        "appliances": appliances,
    })


def _local_hostname() -> str:
    from autostream_sysutils import get_system_hostname
    hostname = str(get_system_hostname() or "").strip()
    if hostname.lower().endswith(".local"):
        hostname = hostname[:-6]
    return hostname.strip() or "autostream"


def _local_version() -> str:
    from autostream_webui_common import get_app_version
    return get_app_version()


def _format_hostname(raw: str) -> str:
    hostname = str(raw or "").strip()
    if hostname.lower().endswith(".local"):
        hostname = hostname[:-6]
    return hostname.strip() or "autostream"


# ---------------------------------------------------------------------------
# Public: gateway Home
# ---------------------------------------------------------------------------

def send_gateway_home_json(handler, state, appliance_id: str) -> None:
    """GET /api/appliances/<id>/home"""
    resolution, sighting = resolve_appliance(appliance_id)
    if resolution not in ("bound", "remote"):
        _gateway_error_to_browser(handler, resolution)
        return

    if resolution == "bound":
        home = build_home_state(state.config_path, deadline=time.monotonic() + 1.5)
        if not home.get("ok"):
            send_json(handler, 500, {"ok": False, "error": "internal_error"})
            return
        send_json(handler, 200, home)
        return

    if _check_and_emit_backoff(handler, appliance_id):
        return
    status, data = _coalesced_remote_get(appliance_id, sighting, "/api/federation/v1/home")
    _handle_remote_response(handler, appliance_id, status, data)


# ---------------------------------------------------------------------------
# Public: gateway output mutation
# ---------------------------------------------------------------------------

def send_gateway_output_json(handler, state, appliance_id: str, body_str: str) -> None:
    """POST /api/appliances/<id>/output (browser CSRF already validated by caller)."""
    try:
        body = json.loads(body_str) if body_str else {}
    except (json.JSONDecodeError, ValueError):
        send_json(handler, 400, {"ok": False, "error": "invalid_json"})
        return
    if not isinstance(body, dict):
        send_json(handler, 400, {"ok": False, "error": "invalid_request_body"})
        return

    out_id = str(body.get("id") or "").strip()
    if not out_id:
        send_json(handler, 400, {"ok": False, "error": "missing_output_id"})
        return

    resolution, sighting = resolve_appliance(appliance_id)
    if resolution not in ("bound", "remote"):
        _gateway_error_to_browser(handler, resolution)
        return

    # Sanitize body — strip browser-only fields before forwarding
    sanitized: dict = {"id": out_id}
    op = str(body.get("op") or "").strip().lower()
    if op == "pin":
        sanitized["op"] = "pin"
        sanitized["pin"] = str(body.get("pin") or "")
    else:
        sanitized["selected"] = bool(body.get("selected", False))
        raw_vol = body.get("volume")
        try:
            sanitized["volume"] = max(0, min(100, int(raw_vol))) if raw_vol is not None else 50
        except (ValueError, TypeError):
            sanitized["volume"] = 50

    if resolution == "bound":
        try:
            cfg = locked_load_config(state.config_path)
            parsed = parse_config(cfg)
            base_url = parsed.owntone.base_url.rstrip("/")
            offset_ms_raw = parsed.owntone.output_offsets_ms.get(out_id)
            offset_ms = int(offset_ms_raw) if offset_ms_raw is not None else None
            mode_text = parsed.owntone.output_airplay_modes.get(out_id, DEFAULT_AIRPLAY_MODE)
            mode = config_airplay_mode_to_backend(mode_text)
        except Exception as e:
            logging.error("gateway output (bound): config error: %s", e)
            send_json(handler, 500, {"ok": False, "error": "internal_error"})
            return
        result = apply_output_mutation(base_url, out_id, sanitized, offset_ms=offset_ms, mode=mode)
        send_json(handler, 200, result)
        return

    if _check_and_emit_backoff(handler, appliance_id):
        return
    status, data = _remote_request(
        appliance_id, sighting, "POST", "/api/federation/v1/output", body=sanitized,
    )
    _update_backoff(appliance_id, status, data)
    _handle_remote_response(handler, appliance_id, status, data)


# ---------------------------------------------------------------------------
# Public: gateway Equaliser
# ---------------------------------------------------------------------------

def send_gateway_equaliser_json(handler, state, appliance_id: str) -> None:
    """GET /api/appliances/<id>/equaliser"""
    resolution, sighting = resolve_appliance(appliance_id)
    if resolution not in ("bound", "remote"):
        _gateway_error_to_browser(handler, resolution)
        return

    if resolution == "bound":
        eq = build_equaliser_state(state.config_path)
        if not eq.get("ok"):
            send_json(handler, 500, {"ok": False, "error": "internal_error"})
            return
        send_json(handler, 200, eq)
        return

    if _check_and_emit_backoff(handler, appliance_id):
        return
    status, data = _coalesced_remote_get(appliance_id, sighting, "/api/federation/v1/equaliser")
    _handle_remote_response(handler, appliance_id, status, data)


def send_gateway_eq_status_json(handler, state, appliance_id: str) -> None:
    """GET /api/appliances/<id>/equaliser/status"""
    resolution, sighting = resolve_appliance(appliance_id)
    if resolution not in ("bound", "remote"):
        _gateway_error_to_browser(handler, resolution)
        return

    if resolution == "bound":
        live = get_live_output_eq_status()
        if live is None:
            send_json(handler, 200, {"ok": False, "error": "monitor_unavailable"})
            return
        send_json(handler, 200, {"ok": True, **live})
        return

    if _check_and_emit_backoff(handler, appliance_id):
        return
    status, data = _remote_request(
        appliance_id, sighting, "GET", "/api/federation/v1/equaliser/status",
    )
    _update_backoff(appliance_id, status, data)
    _handle_remote_response(handler, appliance_id, status, data)


def send_gateway_eq_config_json(handler, state, appliance_id: str, body_str: str) -> None:
    """POST /api/appliances/<id>/equaliser/config"""
    try:
        body = json.loads(body_str) if body_str else {}
    except (json.JSONDecodeError, ValueError):
        send_json(handler, 400, {"ok": False, "error": "invalid_json"})
        return
    if not isinstance(body, dict):
        send_json(handler, 400, {"ok": False, "error": "invalid_request_body"})
        return

    field = str(body.get("field", "")).strip()
    value_raw = str(body.get("value", "")).strip()

    resolution, sighting = resolve_appliance(appliance_id)
    if resolution not in ("bound", "remote"):
        _gateway_error_to_browser(handler, resolution)
        return

    if resolution == "bound":
        try:
            ok, norm, err = apply_eq_field(state.config_path, field, value_raw)
        except ValueError as e:
            send_json(handler, 400, {"ok": False, "error": str(e)})
            return
        if not ok:
            send_json(handler, 500, {"ok": False, "error": err or "internal_error"})
            return
        send_json(handler, 200, {"ok": True, "field": field, "value": norm})
        return

    if _check_and_emit_backoff(handler, appliance_id):
        return
    sanitized = {"field": field, "value": value_raw}
    status, data = _remote_request(
        appliance_id, sighting, "POST", "/api/federation/v1/equaliser/config", body=sanitized,
    )
    _update_backoff(appliance_id, status, data)
    _handle_remote_response(handler, appliance_id, status, data)


def send_gateway_eq_reset_json(handler, state, appliance_id: str) -> None:
    """POST /api/appliances/<id>/equaliser/reset"""
    resolution, sighting = resolve_appliance(appliance_id)
    if resolution not in ("bound", "remote"):
        _gateway_error_to_browser(handler, resolution)
        return

    if resolution == "bound":
        ok, err = apply_eq_reset(state.config_path)
        if not ok:
            send_json(handler, 500, {"ok": False, "error": err or "internal_error"})
            return
        send_json(handler, 200, {"ok": True})
        return

    if _check_and_emit_backoff(handler, appliance_id):
        return
    status, data = _remote_request(
        appliance_id, sighting, "POST", "/api/federation/v1/equaliser/reset", body={},
    )
    _update_backoff(appliance_id, status, data)
    _handle_remote_response(handler, appliance_id, status, data)
