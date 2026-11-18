#!/usr/bin/env python3
"""webui/repeat.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

The repeat-arm request shared by the Home page, the dial and the peer routes.

Contents:
  - apply_repeat_arm_request         -- the arm request itself
  - send_repeat_post_json            -- POST /api/repeat
"""

from __future__ import annotations

import json
from autostream_intents import Intent, submit
from autostream_state import Origin
from autostream_pin_pairing import REQUESTER_WEBUI
from webui import common


def apply_repeat_arm_request(body: str, *, requester: str = REQUESTER_WEBUI) -> tuple[int, dict]:
    """Validate and apply an {"armed": bool} repeat arm/disarm request.

    Shared core logic for POST /api/repeat (below), POST
    /api/federation/v1/repeat (send_federation_repeat_json), and the
    bound-appliance path of POST /api/appliances/<id>/repeat
    (autostream_appliance_gateway.send_gateway_repeat_json) -- all three
    apply to this same appliance's daemon, so the validation and
    response-shape contract lives in one place rather than three.

    Session arm is runtime-only: no settings write accompanies
    this call, and current armed/replay state is read back from /api/status
    (the daemon is the single source of truth -- no WebUIState mirror).

    Returns (http_status, response_dict):
      Success (200):            {"ok": true, "armed": <bool>}
      Validation failure (400): {"ok": false, "error": "..."}
      Live-apply failure (200, ok:false): daemon rejected/unreachable
        (e.g. an older monitor binary that does not support the command).
    """
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        return 400, {"ok": False, "error": "Invalid JSON"}

    if not isinstance(payload, dict):
        return 400, {"ok": False, "error": "JSON object required"}

    if "armed" not in payload:
        return 400, {"ok": False, "error": "armed is required"}

    armed = payload["armed"]
    if not isinstance(armed, bool):
        return 400, {"ok": False, "error": "armed must be true or false"}

    reply = submit(Intent("repeat.arm", {"armed": armed}, Origin.USER, requester))
    ack = reply.result.get("ack")
    ok = bool(ack and ack.get("ok"))
    if not ok:
        return 200, {"ok": False, "armed": armed, "error": "Could not update repeat arm state"}

    return 200, {"ok": True, "armed": armed}


def send_repeat_post_json(handler, state, body: str) -> None:
    """POST /api/repeat -- arm/disarm repeat-recording replay.

    Request: {"armed": bool}

    See apply_repeat_arm_request() for the full validation/response contract.
    """
    status, resp = apply_repeat_arm_request(body)
    common.send_json(handler, status, resp)
