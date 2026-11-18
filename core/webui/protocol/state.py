#!/usr/bin/env python3
"""webui/protocol/state.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

The state snapshot (GET /api/v1/state). The body is unstable: its shape may
change.

Contents:
  - send_state_json  -- GET /api/v1/state
  - state_json       -- the snapshot as plain JSON types
"""

from __future__ import annotations

import dataclasses
import enum
import json
import math
import time
from typing import Optional
from urllib.parse import parse_qs, urlsplit

from autostream_protocol import PROTOCOL
from autostream_state import PART_NAMES, OutputUnitView
from webui import common
from webui.protocol import hub as hub_module


def _jsonable(value):
    """*value* as plain JSON types: dataclasses by field (an output unit also
    carries its offline property), mappings with string
    keys, sequences and sets as lists, enums by value, non-finite floats as
    None."""
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, enum.Enum):
        return _jsonable(value.value)
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        fields = {f.name: _jsonable(getattr(value, f.name)) for f in dataclasses.fields(value)}
        if isinstance(value, OutputUnitView):
            fields["offline"] = value.offline
        return fields
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (frozenset, set)):
        return sorted((_jsonable(v) for v in value), key=str)
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def part_json(snap, name: str) -> bytes:
    """The JSON of part *name* in *snap*, as it appears in the state body and
    in an event."""
    return json.dumps(_jsonable(getattr(snap, name)), allow_nan=False,
                      separators=(",", ":")).encode("ascii")


def state_json(snap, *, clients: int, parts=None) -> dict:
    """The snapshot's parts as they are, with the boot id, the version, the
    protocol number, the server's wall clock in seconds, the version at which each
    part last moved, and the number of stream clients. *parts* names the parts
    to include; None is all, and none
    at all gives the appliance part alone, since it says who is asking and
    whether it is set up."""
    names = PART_NAMES if parts is None else (parts or ("appliance",))
    return {
        "boot": snap.boot,
        "version": snap.version,
        "protocol": PROTOCOL,
        "time": time.time(),
        "clients": clients,
        "part_versions": {str(k): v for k, v in snap.part_versions.items()},
        "parts": {name: _jsonable(getattr(snap, name)) for name in names},
    }


def _requested_parts(path: str) -> Optional[tuple]:
    """The parts the ``parts`` query parameter names, in PART_NAMES order: None
    when it is absent, () when it is empty. ValueError when it names a part
    that does not exist."""
    values = parse_qs(urlsplit(path).query, keep_blank_values=True).get("parts")
    if not values:
        return None
    names = values[0].split(",") if values[0] else []
    if any(n not in PART_NAMES for n in names):
        raise ValueError("unknown part")
    return tuple(n for n in PART_NAMES if n in names)


def send_state_json(handler, state) -> None:
    """GET /api/v1/state, with ``?parts=a,b`` for only those parts."""
    hub = hub_module.current()
    if hub is None:
        common.send_browser_api_error(handler, 404, "not_found")
        return
    try:
        parts = _requested_parts(handler.path)
    except ValueError:
        common.send_browser_api_error(handler, 400, "unknown_part")
        return
    body = hub.state_body(parts)
    try:
        handler.send_response(200)
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)
    except (BrokenPipeError, ConnectionResetError):
        return
