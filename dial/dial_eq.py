"""dial_eq.py — bass/treble EQ sender for the EQ page, own thread.

Sends the two EQ-page requests a touch can trigger — a read (bass/treble
readback) and an absolute bass/treble set — to a single appliance over its
own worker thread, queue and HTTP client, entirely separate from
dial_outputs.py's worker (and from dial_volume.py's fan-out worker and
dial_repeat.py's transport worker). A slow fetch or set here must never
delay a volume detent, an outputs mutation or a repeat transport send, so
it never shares their queues or threads.

Touch-thread entry points (enqueue_fetch/enqueue_set) do no I/O and take
no lock other than a small pending-fetch set guarded by its own lock — the
same discipline dial_outputs.enqueue_fetch()/enqueue_set() follows. The
worker thread never touches dial_display.DialDisplay._lock; its result
callback (on_result, wired to DialDisplay.on_eq_result by dial_main.py) is
called with no lock held here either.

Every set is followed by an automatic fetch for the same target, so the
page always ends up showing the appliance's own truth rather than trusting
the set's optimistic outcome — the same dial_outputs.py rule.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import http.client
import json
import logging
import queue
import threading
from dataclasses import dataclass

# Own thread, so a slow send here never delays a volume detent, an outputs
# mutation or a repeat transport send — the same budget dial_outputs.py's
# OUTPUTS_SEND_TIMEOUT_S uses for the identical reason.
EQ_SEND_TIMEOUT_S = 2.0

# The response bodies this protocol returns are a handful of fields; the cap
# exists only to stop a misbehaving or malicious responder from tying up the
# worker thread reading an unbounded body — same rationale and value as
# dial_outputs._MAX_RESPONSE_BYTES.
_MAX_RESPONSE_BYTES = 64 * 1024

_FETCH_PATH = "/api/dial/eq"
_SET_PATH = "/api/dial/eq/set"


@dataclass(frozen=True)
class _EqTarget:
    appliance_id: str
    ip: str
    port: int


# One queue, one worker thread, for both kinds of send — "fetch" (the
# bass/treble readback) and "set" (an absolute bass and/or treble value).
# Each item is (kind, target, payload), where payload is the JSON body to
# send before the dial's own id is added ({} for a fetch).
_queue: "queue.SimpleQueue" = queue.SimpleQueue()

# Fetch coalescing: the appliance ids with a "fetch" item currently sitting
# in _queue, not yet picked up by the worker — see dial_outputs.py's own
# _pending_fetch_ids for the identical discipline.
_pending_fetch_lock = threading.Lock()
_pending_fetch_ids: set = set()

_cfg = None
_on_result = None


def start_eq_worker(cfg, *, on_result=None) -> None:
    """Store shared state and start the background worker thread.

    on_result, when supplied, is called as
    on_result(kind, appliance_id, http_status, body, request_body) after
    every send completes — wired to DialDisplay.on_eq_result by
    dial_main.py. A raising callback is swallowed by the worker loop, never
    allowed to kill the thread.
    """
    global _cfg, _on_result
    _cfg = cfg
    _on_result = on_result
    threading.Thread(target=_worker, daemon=True, name="eq-worker").start()


def enqueue_fetch(target: "_EqTarget") -> None:
    """Enqueue a bass/treble readback for *target*. Returns immediately —
    no I/O, no lock beyond the small pending-fetch set. Called from the
    touch thread (opening the page, cycling to it) and from a set's own
    automatic follow-up. A fetch already queued for this appliance is not
    duplicated."""
    with _pending_fetch_lock:
        if target.appliance_id in _pending_fetch_ids:
            return
        _pending_fetch_ids.add(target.appliance_id)
    _queue.put(("fetch", target, {}))


def enqueue_set(target: "_EqTarget", *, bass_db: "int | None" = None, treble_db: "int | None" = None) -> None:
    """Enqueue an absolute bass and/or treble value for *target*. Returns
    immediately — same discipline as enqueue_fetch(). Called from the touch
    thread. Only the given key is sent (an EQ_BASS_* tap sends bass_db
    alone, an EQ_TREBLE_* tap sends treble_db alone) — the appliance leaves
    an absent field's own band(s) untouched."""
    body: dict = {}
    if bass_db is not None:
        body["bass_db"] = int(bass_db)
    if treble_db is not None:
        body["treble_db"] = int(treble_db)
    _queue.put(("set", target, body))


def _send_one(path: str, target: "_EqTarget", body: dict) -> "tuple[int | None, dict | None]":
    """POST *body* (plus this dial's id) to *target* at *path*.

    Never raises: any connection, timeout or parse failure returns
    (None, None). Never follows a redirect — http.client does not chase
    one on its own. Reads at most _MAX_RESPONSE_BYTES and parses the body
    leniently — a non-JSON or non-object body is reported as (status, None)
    rather than raising.
    """
    try:
        conn = http.client.HTTPConnection(target.ip, target.port, timeout=EQ_SEND_TIMEOUT_S)
        try:
            payload = dict(body)
            payload["dial_id"] = _cfg.uuid if _cfg is not None else ""
            data = json.dumps(payload).encode("utf-8")
            conn.request(
                "POST", path, body=data,
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
        kind, target, payload = _queue.get()
        if kind == "fetch":
            with _pending_fetch_lock:
                _pending_fetch_ids.discard(target.appliance_id)
            path = _FETCH_PATH
        else:
            path = _SET_PATH
        status, body = _send_one(path, target, payload)
        if _on_result is not None:
            try:
                _on_result(kind, target.appliance_id, status, body, payload)
            except Exception:
                logging.debug("dial eq: on_result callback raised", exc_info=True)
        if kind == "set":
            # The page reconciles from the appliance's own truth rather
            # than trusting this set's outcome, whatever it was.
            enqueue_fetch(target)
