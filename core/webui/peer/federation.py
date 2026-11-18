#!/usr/bin/env python3
"""webui/peer/federation.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

The federation endpoints other appliances call, and their dispatcher.

Contents:
  - dispatch                     -- checks and routes /api/federation/v1/*
  - send_federation_*_json       -- the endpoint handlers
"""

from __future__ import annotations

import json
import logging

import autostream_rpi as rpi
from autostream_intents import Intent, submit
from autostream_state import Origin, store
from autostream_state.live import get_live_output_eq_status
from autostream_pin_pairing import REQUESTER_WEBUI
from webui.browser import home_model
from webui.browser.home_model import build_equaliser_state, build_home_state, sanitize_output_body
from webui.session_state import WebUIState
from webui import common, repeat
import autostream_commissioning as commissioning
import autostream_federation
from webui import session_state

_FEDERATION_PREFIX = "/api/federation/v1"
_FEDERATION_BODY_MAX = 4096  # bytes


# ---------------------------------------------------------------------------
# Federation target API handlers (called by dispatch)
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
    appliance.  See apply_repeat_arm_request() for the request/response contract.
    """
    status, resp = repeat.apply_repeat_arm_request(body_str, requester="peer")
    common.send_json(handler, status, resp)


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


def dispatch(handler, method: str, path: str, body_str: str = "") -> None:
    """Dispatch a federation API request before browser auth/CSRF.

    Never redirects to /auth, never reads or sets browser cookies, and
    never creates a browser UI session.  Source-IP-bound bearer tokens
    are the only acceptable credential on all routes except POST /session.
    """
    source_ip = handler._get_client_ip()

    # Unavailable during commissioning or when identity is missing.
    # 404 per the documented federation wire contract (peers key off the
    # "error" body field, never the status code).
    if commissioning.is_commissioning_required(session_state.STATE.config_path, session_state.STATE.state_path):
        common.send_json(handler, 404, {"ok": False, "error": "appliance_unconfigured"})
        return
    if not rpi.get_appliance_id():
        common.send_json(handler, 404, {"ok": False, "error": "appliance_unconfigured"})
        return

    # Fail closed: refuse every federation route (including /session, so
    # no bearer token is ever issued) when the local peer-control setting
    # is off. Unlike _effective_control_other_appliances (which fails
    # open for the local UI), an unreadable setting here must not leave
    # the security gap open.
    try:
        if not common._config_snapshot(session_state.STATE).webui.advertise_appliance:
            common.send_json(handler, 403, {"ok": False, "error": "control_disabled"})
            return
    except Exception:
        logging.debug("federation: control setting unreadable; refusing", exc_info=True)
        common.send_json(handler, 403, {"ok": False, "error": "control_disabled"})
        return

    # POST /session: no bearer token required
    if path == f"{_FEDERATION_PREFIX}/session":
        if method != "POST":
            common.send_json(handler, 405, {"ok": False, "error": "method_not_allowed"})
            return
        if body_str:
            if len(body_str) > _FEDERATION_BODY_MAX:
                common.send_json(handler, 400, {"ok": False, "error": "body_too_large"})
                return
            try:
                obj = json.loads(body_str)
            except json.JSONDecodeError:
                common.send_json(handler, 400, {"ok": False, "error": "invalid_json"})
                return
            if not isinstance(obj, dict) or obj:
                common.send_json(handler, 400, {"ok": False, "error": "invalid_request_body"})
                return
        send_federation_session_json(handler, source_ip)
        return

    # All other federation endpoints require a valid bearer token
    auth_header = handler.headers.get("Authorization") or ""
    token = auth_header[7:].strip() if auth_header.startswith("Bearer ") else ""
    if not autostream_federation.validate_session(token, source_ip):
        common.send_json(handler, 401, {"ok": False, "error": "unauthorized"})
        return

    if method == "GET":
        if path == f"{_FEDERATION_PREFIX}/home":
            send_federation_home_json(handler, session_state.STATE)
        elif path == f"{_FEDERATION_PREFIX}/equaliser":
            send_federation_equaliser_json(handler, session_state.STATE)
        elif path == f"{_FEDERATION_PREFIX}/equaliser/status":
            send_federation_eq_status_json(handler, session_state.STATE)
        else:
            common.send_json(handler, 400, {"ok": False, "error": "invalid_endpoint"})
        return

    if method == "POST":
        if len(body_str) > _FEDERATION_BODY_MAX:
            common.send_json(handler, 400, {"ok": False, "error": "body_too_large"})
            return
        if path == f"{_FEDERATION_PREFIX}/output":
            if not body_str:
                common.send_json(handler, 400, {"ok": False, "error": "missing_body"})
                return
            send_federation_output_json(handler, session_state.STATE, body_str)
        elif path == f"{_FEDERATION_PREFIX}/equaliser/config":
            if not body_str:
                common.send_json(handler, 400, {"ok": False, "error": "missing_body"})
                return
            send_federation_eq_config_json(handler, session_state.STATE, body_str)
        elif path == f"{_FEDERATION_PREFIX}/equaliser/reset":
            send_federation_eq_reset_json(handler, session_state.STATE)
        elif path == f"{_FEDERATION_PREFIX}/repeat":
            if not body_str:
                common.send_json(handler, 400, {"ok": False, "error": "missing_body"})
                return
            send_federation_repeat_json(handler, session_state.STATE, body_str)
        else:
            common.send_json(handler, 400, {"ok": False, "error": "invalid_endpoint"})
        return

    common.send_json(handler, 405, {"ok": False, "error": "method_not_allowed"})


# ---------------------------------------------------------------------------
# Route-table adapters
# ---------------------------------------------------------------------------


def _route_get_federation(handler, state):
    handler._dispatch_federation("GET", handler._normalized_path())


def _route_post_federation(handler, state):
    # Reproduces do_POST's former universal body-read (steps 2-3) up to and
    # including the "Invalid JSON" check -- but NOT the later "JSON object
    # required" non-dict-body check (do_POST's own former federation branch
    # returned before ever reaching that check, so a federation POST never
    # saw it either). _dispatch_federation only consumes body_str; any
    # further JSON validation (e.g. POST /session's own isinstance check)
    # stays inside it, unchanged.
    body_bytes = handler._read_post_body_bytes()
    if body_bytes is None:
        return  # error already sent
    try:
        body_str = body_bytes.decode("utf-8")
    except UnicodeDecodeError:
        handler.send_error(400, "Request body is not valid UTF-8")
        return
    content_type = (handler.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
    if body_str and content_type == "application/json":
        try:
            json.loads(body_str)
        except json.JSONDecodeError:
            handler.send_error(400, "Invalid JSON")
            return
    handler._dispatch_federation("POST", handler._normalized_path(), body_str)
