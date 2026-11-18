"""dial_http_common.py: the request mechanics the dial's two servers share.

Each server keeps its own response methods and error vocabulary: the
appliance web UI proxies the management API and its tests assert those
names, and the HD server answers its own page.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import json

# The most bytes of request body either server reads (bytes), so an oversized
# body is refused before it is parsed.
MAX_BODY = 4096

# The body of the 429 both servers send once a client is backed off.
TOO_MANY_ATTEMPTS = {"ok": False, "error": "too_many_attempts"}


def content_length(headers) -> int | None:
    """The request's Content-Length, or None when absent. A malformed value
    raises ValueError, and a negative one is returned as it is."""
    value = headers.get("Content-Length")
    return None if value is None else int(value)


def json_bytes(obj, *, compact: bool = False) -> bytes:
    """obj as UTF-8 JSON; compact drops the spaces after separators."""
    return json.dumps(obj, separators=(",", ":") if compact else None).encode("utf-8")
