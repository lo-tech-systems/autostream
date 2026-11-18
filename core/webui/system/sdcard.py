#!/usr/bin/env python3
"""webui/system/sdcard.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

SD card health monitoring endpoints.

Contents:
  - send_sdcard_health_get_json        -- GET /api/sdcard-health
  - send_sdcard_health_enable_post_json -- POST enable
  - send_sdcard_health_disable_post_json -- POST disable
"""

from __future__ import annotations

from __future__ import annotations




from autostream_sysutils import (
    SDCARD_HEALTH_METHODS,
    sdcard_health_check,
    sdcard_health_disable,
    sdcard_health_enable,
    sdcard_health_state,
)
from webui import common

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

# -----------------------------------------------------------------------------
# Route-table adapters
# -----------------------------------------------------------------------------


def _route_get_sdcard_health(handler, state):
    send_sdcard_health_get_json(handler)


def _route_post_sdcard_health_enable(handler, state, body_str):
    send_sdcard_health_enable_post_json(handler, common._route_post_json_obj(handler))


def _route_post_sdcard_health_disable(handler, state, body_str):
    send_sdcard_health_disable_post_json(handler, common._route_post_json_obj(handler))
