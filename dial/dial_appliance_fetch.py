"""dial_appliance_fetch.py — reads of an appliance's own descriptive endpoints,
own thread.

Fetches what an appliance says about itself (its capabilities and its warnings) from one
appliance at a time over a worker thread, queue and HTTP client of its own,
entirely separate from dial_eq.py's, dial_outputs.py's, dial_volume.py's and
dial_repeat.py's workers. A slow or unreachable appliance holds up only this
queue: a volume detent, an outputs or EQ request and a repeat transport send
are never delayed by it, nor is the poll.

Touch- and core-thread entry points (enqueue) do no I/O and take no lock
other than a small pending set guarded by its own lock — the same discipline
dial_eq.enqueue_fetch() follows. The worker thread never touches a display
lock; its result callback (on_result, wired to the core by dial_main.py) is
called with no lock held here either.

A request already queued for the same appliance and kind is not duplicated,
so a caller that asks again every second while a slow reply is awaited queues
one request.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import http.client
import json
import logging
import queue
import threading
from dataclasses import dataclass

# Own thread, so a slow read here delays nothing else; the same budget the
# other workers' sends use.
FETCH_TIMEOUT_S = 2.0

# The replies are small; the cap exists only to stop a misbehaving or
# malicious responder from tying up the worker reading an unbounded body.
# The validators apply their own, tighter caps.
_MAX_RESPONSE_BYTES = 64 * 1024

# kind: (method, path, body builder given the dial's own id)
_KINDS = {
    "capabilities": ("GET", "/api/dial/capabilities", lambda dial_id: None),
    "warnings": ("POST", "/api/dial/warnings", lambda dial_id: {"dial_id": dial_id}),
}


@dataclass(frozen=True)
class _FetchTarget:
    appliance_id: str
    ip: str
    port: int
    version: str = ""    # the advertised version the read is made for, echoed to on_result


_queue: "queue.SimpleQueue" = queue.SimpleQueue()

# The (kind, appliance id) pairs with an item sitting in _queue, not yet
# picked up by the worker.
_pending_lock = threading.Lock()
_pending: set = set()

_cfg = None
_on_result = None


def start_appliance_fetch_worker(cfg, *, on_result=None) -> None:
    """Store shared state and start the background worker thread.

    on_result, when supplied, is called as
    on_result(kind, appliance_id, version, http_status, body) after every
    read completes — wired to the core by dial_main.py. A raising callback is
    swallowed by the worker loop, never allowed to kill the thread.
    """
    global _cfg, _on_result
    _cfg = cfg
    _on_result = on_result
    threading.Thread(target=_worker, daemon=True, name="appliance-fetch-worker").start()


def enqueue(kind: str, target: "_FetchTarget") -> bool:
    """Enqueue a read of *kind* from *target*. Returns immediately — no I/O,
    no lock beyond the small pending set. False when *kind* is unknown or the
    same read for this appliance is already queued."""
    if kind not in _KINDS:
        return False
    key = (kind, target.appliance_id)
    with _pending_lock:
        if key in _pending:
            return False
        _pending.add(key)
    _queue.put((kind, target))
    return True


def _send_one(kind: str, target: "_FetchTarget") -> "tuple[int | None, dict | None]":
    """Make the *kind* request of *target*.

    Never raises: any connection, timeout or parse failure returns
    (None, None). Never follows a redirect — http.client does not chase one
    on its own. Reads at most _MAX_RESPONSE_BYTES and parses the body
    leniently — a non-JSON or non-object body is reported as (status, None).
    """
    method, path, build = _KINDS[kind]
    try:
        conn = http.client.HTTPConnection(target.ip, target.port, timeout=FETCH_TIMEOUT_S)
        try:
            payload = build(_cfg.uuid if _cfg is not None else "")
            if payload is None:
                conn.request(method, path)
            else:
                conn.request(
                    method, path, body=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                )
            resp = conn.getresponse()
            status = resp.status
            raw = resp.read(_MAX_RESPONSE_BYTES)
        finally:
            conn.close()
    except Exception:
        return None, None

    try:
        parsed = json.loads(raw.decode("utf-8"))
    except Exception:
        parsed = None
    if not isinstance(parsed, dict):
        parsed = None
    return status, parsed


def _worker() -> None:
    while True:
        kind, target = _queue.get()
        with _pending_lock:
            _pending.discard((kind, target.appliance_id))
        status, body = _send_one(kind, target)
        if _on_result is not None:
            try:
                _on_result(kind, target.appliance_id, target.version, status, body)
            except Exception:
                logging.debug("dial appliance fetch: on_result callback raised", exc_info=True)
