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
import math

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


def state_json(snap, *, clients: int) -> dict:
    """The snapshot's parts as they are, with the boot id, the version, the
    version at which each part last moved, and the number of stream clients."""
    return {
        "boot": snap.boot,
        "version": snap.version,
        "clients": clients,
        "part_versions": {str(k): v for k, v in snap.part_versions.items()},
        "parts": {name: _jsonable(getattr(snap, name)) for name in PART_NAMES},
    }


def send_state_json(handler, state) -> None:
    """GET /api/v1/state."""
    hub = hub_module.current()
    if hub is None:
        common.send_browser_api_error(handler, 404, "not_found")
        return
    body = hub.state_body()
    try:
        handler.send_response(200)
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)
    except (BrokenPipeError, ConnectionResetError):
        return
