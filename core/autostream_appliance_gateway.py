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

Stale fallback: _coalesced_remote_get retains successful GET data for
_STALE_READ_CACHE_TTL seconds. If a subsequent request hits backoff or a
transport failure, the cached data is returned with stale=True metadata
rather than an error, so the browser can render the last-known state while
retrying in the background. Stale fallback never clears backoff state — only
a real successful remote response does that.

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
    register_peer_removal_callback,
    scanner_ready,
)
from autostream_federation import EXPIRY_SECONDS as _FED_EXPIRY_SECONDS, FEDERATION_VERSION as _FED_VERSION
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
_READ_CACHE_TTL = 1.0              # seconds — fresh window for successful-read cache
_STALE_READ_CACHE_TTL = 15.0       # seconds — stale fallback window after fresh_until
_FED_VERSION_HEADER = "1"


# ---------------------------------------------------------------------------
# Module-level state (all under _state_lock)
# ---------------------------------------------------------------------------

_state_lock = threading.Lock()

# token cache: appliance_id → (token, expires_monotonic)
_token_cache: dict[str, tuple[str, float]] = {}

# backoff state: appliance_id → (backoff_until_monotonic, step_index)
_backoff_state: dict[str, tuple[float, int]] = {}

# successful-read cache: (appliance_id, fed_path) → cache entry dict
# shape: {"data": dict, "cached_at": float, "fresh_until": float, "stale_until": float}
_read_cache: dict[tuple[str, str], dict] = {}

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
    logging.debug("gateway: backoff set for %s: %ds (step %d)", appliance_id, delay, step_idx)


def _record_success_locked(appliance_id: str) -> None:
    """Reset per-target backoff. Lock must be held."""
    if appliance_id in _backoff_state:
        logging.debug("gateway: backoff cleared for %s", appliance_id)
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


_V1_SESSION_KEYS = frozenset({"ok", "token", "token_type", "expires_in", "federation_version"})


def _acquire_token(appliance_id: str, sighting: ApplianceSighting) -> tuple[Optional[str], str, int]:
    """Acquire a new federation token from the target.

    Returns (token, error_code, retry_after_seconds).  On success: (token, "", 0).
    On rate_limited: (None, "rate_limited", retry_after).  Other errors: (None, code, 0).
    """
    logging.debug("gateway: acquiring token for %s at %s:%d", appliance_id, sighting.ip, sighting.port)
    status, data = _remote_federation_request(
        "POST", sighting, "/api/federation/v1/session",
        token="",  # no token needed for session creation
        body={},
    )
    if status == 0:
        error_code = data.get("error", "remote_timeout")
        logging.debug("gateway: token acquisition transport failure for %s: %s", appliance_id, error_code)
        return None, error_code, 0

    if status != 200 or not data.get("ok"):
        error_code = data.get("error", "remote_bad_response")
        if error_code == "rate_limited":
            retry_after = int(data.get("retry_after", 60)) if isinstance(data, dict) else 60
            logging.debug(
                "gateway: token acquisition rate-limited for %s (retry_after=%ds)",
                appliance_id, retry_after,
            )
            return None, "rate_limited", retry_after
        if error_code not in ("appliance_unconfigured", "appliance_identity_unavailable"):
            error_code = "remote_bad_response"
        logging.debug(
            "gateway: token acquisition rejected for %s: %s (HTTP %d)",
            appliance_id, error_code, status,
        )
        return None, error_code, 0

    # Reject responses with unexpected fields — plan requires the exact v1 schema
    if set(data.keys()) != _V1_SESSION_KEYS:
        logging.warning("gateway: target %s returned non-exact session schema", appliance_id)
        return None, "remote_bad_response", 0

    # Validate exact v1 session schema values
    token = data.get("token")
    token_type = data.get("token_type")
    expires_in = data.get("expires_in")
    fed_version = data.get("federation_version")
    if (
        not isinstance(token, str) or len(token) < 40
        or token_type != "Bearer"
        or isinstance(expires_in, bool) or expires_in != _FED_EXPIRY_SECONDS
        or isinstance(fed_version, bool) or fed_version != _FED_VERSION
    ):
        logging.warning("gateway: target %s returned malformed session schema", appliance_id)
        return None, "remote_bad_response", 0

    received_at = time.monotonic()
    expires = received_at + expires_in
    with _state_lock:
        _token_cache[appliance_id] = (token, expires)
    logging.debug("gateway: token acquired for %s (expires in %ds)", appliance_id, expires_in)
    return token, "", 0


def _get_or_renew_token(appliance_id: str, sighting: ApplianceSighting) -> tuple[Optional[str], str, int]:
    """Return a valid bearer token for *appliance_id*, acquiring one if needed."""
    with _state_lock:
        token = _get_token_from_cache_locked(appliance_id)
    if token:
        return token, "", 0
    return _acquire_token(appliance_id, sighting)


def evict_gateway_token(appliance_id: str) -> None:
    """Evict the cached token for *appliance_id* (call on final peer removal)."""
    with _state_lock:
        _token_cache.pop(appliance_id, None)


def sweep_token_cache() -> None:
    """Evict expired entries from the gateway token cache."""
    now = time.monotonic()
    with _state_lock:
        expired = [aid for aid, (_, exp) in _token_cache.items() if exp <= now]
        for aid in expired:
            _token_cache.pop(aid, None)


register_peer_removal_callback(evict_gateway_token)


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

        logging.debug(
            "gateway: fed response %s %s %s:%d → HTTP %d",
            method, fed_path, sighting.ip, sighting.port, status,
        )
        return status, data

    except socket.timeout:
        logging.debug(
            "gateway: socket timeout %s %s %s:%d",
            method, fed_path, sighting.ip, sighting.port,
        )
        return 0, {"ok": False, "error": "remote_timeout"}
    except OSError as exc:
        logging.debug(
            "gateway: connection error %s %s %s:%d: %s",
            method, fed_path, sighting.ip, sighting.port, type(exc).__name__,
        )
        return 0, {"ok": False, "error": "remote_timeout"}
    except Exception as exc:
        logging.debug(
            "gateway: unexpected transport error %s %s %s:%d: %s",
            method, fed_path, sighting.ip, sighting.port, type(exc).__name__,
        )
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
    token, err, retry_after = _get_or_renew_token(appliance_id, sighting)
    if token is None:
        if err == "rate_limited":
            return 429, {"ok": False, "error": "rate_limited", "retry_after": retry_after or 60}
        return 0, {"ok": False, "error": err or "remote_timeout"}

    status, data = _remote_federation_request(method, sighting, fed_path, token, body)

    if status == 401:
        # Token may have expired: evict and retry once with a fresh token
        with _state_lock:
            _token_cache.pop(appliance_id, None)
        token2, err2, retry2 = _acquire_token(appliance_id, sighting)
        if token2 is None:
            if err2 == "rate_limited":
                return 429, {"ok": False, "error": "rate_limited", "retry_after": retry2 or 60}
            return 0, {"ok": False, "error": err2 or "remote_timeout"}
        status, data = _remote_federation_request(method, sighting, fed_path, token2, body)

    return status, data


def _update_backoff(appliance_id: str, status: int, data: dict) -> None:
    """Record backoff outcome after a completed _remote_request() call.

    Only transport failures (status 0 or error codes remote_timeout /
    remote_bad_response) advance the failure counter.  Application-level
    errors from a reachable target (4xx, 5xx, ok=False with other codes)
    count as success to avoid triggering backoff against a reachable peer.
    """
    err = data.get("error", "") if isinstance(data, dict) else ""
    is_transport = status == 0 or err in ("remote_timeout", "remote_bad_response")
    with _state_lock:
        if is_transport:
            _record_failure_locked(appliance_id)
        else:
            _record_success_locked(appliance_id)


# ---------------------------------------------------------------------------
# Stale-response helper
# ---------------------------------------------------------------------------

def _stale_response(entry: dict, reason: str, retry_after: int = 0) -> dict:
    """Return a copy of cached data with stale metadata merged in.

    Never mutates the cached entry — always produces a new dict.
    """
    age_ms = int((time.monotonic() - entry["cached_at"]) * 1000)
    result = dict(entry["data"])
    result["stale"] = True
    result["stale_reason"] = reason
    result["stale_age_ms"] = age_ms
    if retry_after:
        result["retry_after"] = retry_after
    return result


# ---------------------------------------------------------------------------
# Coalesced remote GET (cache + coalescing + backoff + stale fallback)
# ---------------------------------------------------------------------------

def _coalesced_remote_get(
    appliance_id: str,
    sighting: ApplianceSighting,
    fed_path: str,
) -> tuple[int, dict]:
    """GET with cache, per-target coalescing, backoff guard, and stale fallback.

    Returns fresh cached data immediately if within _READ_CACHE_TTL.
    On backoff or transport failure, returns stale cached data (within
    _STALE_READ_CACHE_TTL) with stale=True metadata rather than an error.
    Only a real successful remote response clears backoff state.
    """
    cache_key = (appliance_id, fed_path)
    event_to_wait: Optional[threading.Event] = None
    result_holder: Optional[list] = None
    am_owner = False

    with _state_lock:
        # Fresh cache hit?
        entry = _read_cache.get(cache_key)
        if entry is not None and time.monotonic() < entry["fresh_until"]:
            return 200, entry["data"]

        # Backoff guard — return stale data if available, otherwise backoff error
        in_backoff, retry_after = _check_backoff_locked(appliance_id)
        if in_backoff:
            if entry is not None and time.monotonic() < entry["stale_until"]:
                return 200, _stale_response(entry, "remote_backoff", retry_after)
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
            owner_status, owner_data = result_holder[0]
            if owner_status == 200 and isinstance(owner_data, dict) and owner_data.get("ok"):
                return owner_status, owner_data
        # Owner failed — fall back to stale if available
        with _state_lock:
            stale = _read_cache.get(cache_key)
        if stale is not None and time.monotonic() < stale["stale_until"]:
            return 200, _stale_response(stale, "remote_timeout")
        return 0, {"ok": False, "error": "remote_timeout"}

    # We are the owner: make the actual request
    try:
        status, data = _remote_request(appliance_id, sighting, "GET", fed_path)
    except Exception:
        logging.exception("_coalesced_remote_get: unexpected error")
        status, data = 0, {"ok": False, "error": "remote_timeout"}

    with _state_lock:
        result_holder.append((status, data))
        now = time.monotonic()
        if status == 200 and isinstance(data, dict) and data.get("ok"):
            _read_cache[cache_key] = {
                "data": data,
                "cached_at": now,
                "fresh_until": now + _READ_CACHE_TTL,
                "stale_until": now + _STALE_READ_CACHE_TTL,
            }
            _record_success_locked(appliance_id)
        else:
            err_str = data.get("error", "") if isinstance(data, dict) else ""
            if status == 0 or err_str in ("remote_timeout", "remote_bad_response"):
                _record_failure_locked(appliance_id)
            else:
                _record_success_locked(appliance_id)
        del _in_flight[cache_key]
    event_to_wait.set()

    # On transport failure, return stale data if available rather than the error
    if not (status == 200 and isinstance(data, dict) and data.get("ok")):
        with _state_lock:
            stale = _read_cache.get(cache_key)
        if stale is not None and time.monotonic() < stale["stale_until"]:
            err_str = data.get("error", "") if isinstance(data, dict) else "remote_timeout"
            return 200, _stale_response(stale, err_str)

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
        logging.debug(
            "gateway: serving backoff for %s (retry_after=%ds)", appliance_id, retry_after,
        )
        send_browser_api_error(handler, 429, "remote_backoff", retryable=True,
                               extra={"retry_after": retry_after})
    return in_backoff


def _handle_remote_response(handler, appliance_id: str, status: int, data: dict) -> None:
    """Emit the browser response for a completed remote request."""
    if status == 200 and isinstance(data, dict) and data.get("ok"):
        send_json(handler, 200, data)
        return

    err = data.get("error", "remote_timeout") if isinstance(data, dict) else "remote_timeout"
    logging.debug("gateway: error response for %s: %s (HTTP %d)", appliance_id, err, status)

    if err == "remote_backoff":
        retry = data.get("retry_after", 1) if isinstance(data, dict) else 1
        send_browser_api_error(handler, 429, "remote_backoff", retryable=True,
                               extra={"retry_after": int(retry)})
    elif err == "rate_limited":
        retry = data.get("retry_after", 1) if isinstance(data, dict) else 1
        send_browser_api_error(handler, 429, "rate_limited", retryable=True,
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
        send_json(handler, 500, {"ok": False, "error": "target_error"})


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

    # Sanitize body — only the two documented schemas are accepted.
    sanitized: dict = {"id": out_id}
    op = str(body.get("op") or "").strip().lower()
    if op == "pin":
        pin_val = str(body.get("pin") or "")
        if not pin_val:
            send_json(handler, 400, {"ok": False, "error": "invalid_request_body"})
            return
        sanitized["op"] = "pin"
        sanitized["pin"] = pin_val
    elif op == "":
        selected_raw = body.get("selected")
        if not isinstance(selected_raw, bool):
            send_json(handler, 400, {"ok": False, "error": "invalid_request_body"})
            return
        sanitized["selected"] = selected_raw
        raw_vol = body.get("volume")
        try:
            sanitized["volume"] = max(0, min(100, int(raw_vol))) if raw_vol is not None else 50
        except (ValueError, TypeError):
            sanitized["volume"] = 50
    else:
        send_json(handler, 400, {"ok": False, "error": "invalid_request_body"})
        return

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
