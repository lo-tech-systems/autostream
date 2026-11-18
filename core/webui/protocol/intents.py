#!/usr/bin/env python3
"""webui/protocol/intents.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Intents over HTTP (POST /api/v1/intents/<name>). The body is a JSON object
with ``args`` and, for a dial or another appliance, ``client`` and
``protocol``. The reply is always HTTP 200 with ok, error, version, boot and
the intent's result, except where the request itself is refused (no JSON, too
large, cross-origin, a stale CSRF token, a malformed client).

Only the rows marked exposed in the intent table are served. For the speaker
rows the route fills in what a caller must not choose: the PIN claimant, the
speaker's configured offset and AirPlay mode, and the level a volume change
falls back to.

Contents:
  - post_intent  -- POST /api/v1/intents/<name>
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from typing import Optional
from urllib.parse import urlsplit

import autostream_commissioning as commissioning
from autostream_intents import ROWS, Intent, Origin, Role, submit
from autostream_protocol import PROTOCOL, parse_client
from autostream_state import store
from webui import common
from webui.protocol import caller as caller_module
from webui.protocol.stream import _same_origin

_PREFIX = "/api/v1/intents/"
_NAME_RE = re.compile(r"[a-z0-9_.]{1,64}")
_OUTPUT_ROWS = frozenset({"outputs.set", "output.pin.submit"})
_LEVEL_ROWS = frozenset({"volume.step", "volume.set", "mute.set"})
_CONFIGURED_TTL_S = 1.0

_configured_lock = threading.Lock()
_configured_memo: Optional[tuple] = None        # ((config_path, state_path), at, configured)


def _reply(handler, error: Optional[str], ok: bool = False, result=None, **extra) -> None:
    snap = store().snapshot()
    body = {"ok": ok, "error": error, "version": snap.version, "boot": snap.boot,
            "result": dict(result or {})}
    body.update(extra)
    common.send_json(handler, 200, body)


def _read_json(handler) -> Optional[dict]:
    """The request's JSON object, or None after sending the refusal."""
    try:
        length = int(handler.headers.get("Content-Length", 0))
    except (TypeError, ValueError):
        common.send_browser_api_error(handler, 400, "invalid_json")
        return None
    if not 0 <= length <= handler.MAX_POST_SIZE:
        common.send_browser_api_error(handler, 413, "body_too_large")
        return None
    raw = handler._read_post_body_bytes()
    if raw is None:
        return None
    content_type = (handler.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        body = None
    if content_type != "application/json" or not isinstance(body, dict):
        common.send_browser_api_error(handler, 400, "invalid_json")
        return None
    return body


def _configured(state) -> bool:
    """Whether the appliance is set up, read live and remembered for a second
    (a dial's knob sends several intents a second)."""
    global _configured_memo
    key = (state.config_path, state.state_path)
    now = time.monotonic()
    with _configured_lock:
        memo = _configured_memo
        if memo is not None and memo[0] == key and now - memo[1] < _CONFIGURED_TTL_S:
            return memo[2]
    try:
        value = not commissioning.is_commissioning_required(*key)
    except Exception:
        logging.warning("intents: commissioning state unreadable; treating as unconfigured", exc_info=True)
        return False
    with _configured_lock:
        _configured_memo = (key, now, value)
    return value


def _fill(name: str, args: dict, state) -> Optional[str]:
    """Add what the configuration decides to *args*; the error name when the
    caller sent a field that is not theirs to choose."""
    if name in _OUTPUT_ROWS:
        if "offset_ms" in args or "mode" in args:
            return "invalid_args"
        out_id = args.get("id")
        if isinstance(out_id, str) and out_id.strip():
            start = common.output_start_args(state, out_id.strip())
            for key in ("offset_ms", "mode"):
                if start.get(key) is not None:
                    args[key] = start[key]
    elif name in _LEVEL_ROWS:
        if "default_level" in args:
            return "invalid_args"
        args["default_level"] = common.output_start_args(state)["default_level"]
    return None


def post_intent(handler, state) -> None:
    """POST /api/v1/intents/<name>."""
    body = _read_json(handler)
    if body is None:
        return
    if not _same_origin(handler.headers):
        common.send_browser_api_error(handler, 403, "cross_origin")
        return
    named = body.get("client") is not None
    if named and (not isinstance(body["client"], str) or parse_client(body["client"]) is None):
        common.send_browser_api_error(handler, 400, "invalid_client")
        return
    if named or "protocol" in body:
        if body.get("protocol") != PROTOCOL:
            common.send_json(handler, 200, {"ok": False, "error": "protocol_mismatch", "protocol": PROTOCOL})
            return
    configured = _configured(state)
    if not configured:
        _reply(handler, "unconfigured")
        return
    who = caller_module.identify(handler, body, write=True, configured=configured)
    if isinstance(who, caller_module.Refusal):
        common.send_browser_api_error(handler, who.status, who.error, extra=who.extra)
        return
    if who.role is Role.NONE:
        _reply(handler, who.reason or "not_allowed")
        return

    name = urlsplit(handler.path).path[len(_PREFIX):]
    row = ROWS.get(name) if _NAME_RE.fullmatch(name) else None
    if row is None or not row.exposed:
        _reply(handler, "unknown_intent")
        return
    args = body.get("args", {})
    if not isinstance(args, dict):
        _reply(handler, "invalid_args")
        return
    args = dict(args)
    try:
        error = _fill(name, args, state)
    except Exception:
        logging.warning("intents: configuration unreadable for %s", name, exc_info=True)
        _reply(handler, "config_error")
        return
    if error is not None:
        _reply(handler, error)
        return

    context = who.pin_claimant if name in _OUTPUT_ROWS else None
    try:
        reply = submit(Intent(name, args, Origin.USER, who.requester, context=context, role=who.role))
    except Exception:
        logging.exception("intents: %s failed", name)
        _reply(handler, "internal_error")
        return
    extra = {}
    if reply.error == "rate_limited" and "retry_after_s" in reply.result:
        extra["retry_after_s"] = reply.result["retry_after_s"]
    _reply(handler, reply.error, ok=reply.ok, result=reply.result, **extra)
