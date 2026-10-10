"""dial_outputs.py — per-output list/enable/volume sender, own thread.

Sends the two outputs-screen requests a touch can trigger — a list refresh
and an enable/disable/volume change for one output — to a single appliance
over its own worker thread, queue and HTTP client, entirely separate from
dial_volume.py's fan-out worker and dial_repeat.py's transport worker. A
slow fetch or mutation here must never delay a volume detent or a repeat
transport send, so it never shares their queues or threads.

Touch-thread entry points (enqueue_fetch/enqueue_set) do no I/O and take
no lock other than a small pending-fetch set guarded by its own lock — the
same discipline dial_volume.enqueue_delta()/enqueue_mute() and
dial_repeat.enqueue_transport()/enqueue_arm() follow. The worker thread
never touches dial_display.DialDisplay._lock; its result callback
(on_result, wired to DialCore.on_outputs_result by dial_main.py) is
called with no lock held here either.

Every mutation is followed by an automatic list refetch for the same
target, so the screen always ends up showing the appliance's own truth
rather than trusting the mutation's optimistic outcome. Repeated fetch
requests for a target that is already queued (a periodic refresh landing
at the same moment as a post-mutation refetch, for example) collapse to
one queued item rather than stacking.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import http.client
import json
import logging
import queue
import threading
from dataclasses import dataclass

# Never blocks the worker beyond this — matches dial_repeat's own budget for
# the same reason: this is its own thread, so a slow send here never delays
# a volume detent or a repeat transport send.
OUTPUTS_SEND_TIMEOUT_S = 2.0

# A set waits on the appliance, which waits on the player: an enable up to
# three seconds, a PIN followed by an enable twice that, plus the check that
# the output is free. The fetches keep the short budget above.
OUTPUTS_SET_TIMEOUT_S = 10.0

# A generous but bounded read — the response bodies this protocol returns
# are a handful of fields plus a short output list, never anything
# approaching this size; the cap exists only to stop a misbehaving or
# malicious responder from tying up the worker thread reading an unbounded
# body.
_MAX_RESPONSE_BYTES = 64 * 1024

_FETCH_PATH = "/api/dial/outputs"
_SET_PATH = "/api/dial/outputs/set"


@dataclass(frozen=True)
class _OutputsTarget:
    appliance_id: str
    ip: str
    port: int


# One queue, one worker thread, for both kinds of send — "fetch" (the list)
# and "set" (enable/disable/volume for one output). Each item is
# (kind, target, payload), where payload is the JSON body to send before
# the dial's own id is added ({} for a fetch).
_queue: "queue.SimpleQueue" = queue.SimpleQueue()

# Fetch coalescing: the appliance ids with a "fetch" item currently sitting
# in _queue, not yet picked up by the worker. enqueue_fetch() skips putting
# a second one while the first is still queued; the worker clears the flag
# the moment it dequeues the item (not when the send completes), so a fetch
# requested while the send is in flight still queues promptly.
_pending_fetch_lock = threading.Lock()
_pending_fetch_ids: set = set()

_cfg = None
_on_result = None


def start_outputs_worker(cfg, *, on_result=None) -> None:
    """Store shared state and start the background worker thread.

    on_result, when supplied, is called as
    on_result(kind, appliance_id, http_status, body, request_body) after
    every send completes — wired to DialCore.on_outputs_result by
    dial_main.py. A raising callback is swallowed by the worker loop, never
    allowed to kill the thread.
    """
    global _cfg, _on_result
    _cfg = cfg
    _on_result = on_result
    threading.Thread(target=_worker, daemon=True, name="outputs-worker").start()


def enqueue_fetch(target: "_OutputsTarget") -> None:
    """Enqueue an outputs-list refresh for *target*. Returns immediately —
    no I/O, no lock beyond the small pending-fetch set. Called from the
    touch thread and from the repaint thread's quiet-second refresh tick.
    A fetch already queued for this appliance is not duplicated."""
    with _pending_fetch_lock:
        if target.appliance_id in _pending_fetch_ids:
            return
        _pending_fetch_ids.add(target.appliance_id)
    _queue.put(("fetch", target, {}))


def enqueue_set(
    target: "_OutputsTarget", output_id: str, *, selected: bool, volume: "int | None",
    pin: "str | None" = None, pin_capable: bool = False,
) -> None:
    """Enqueue an enable/disable/volume change for *output_id* on *target*.
    Returns immediately — same discipline as enqueue_fetch(). Called from
    the touch thread. *volume* is omitted from the body when None (a plain
    enable/disable with no explicit level), letting the appliance apply its
    own configured default on an enable. A *pin* makes it a PIN submission
    (the appliance pairs the speaker and, with selected true, enables it);
    *pin_capable* tells the appliance this sender can answer a request for
    a PIN. The body is never logged."""
    body: dict = {"id": output_id, "selected": bool(selected)}
    if volume is not None:
        body["volume"] = int(volume)
    if pin is not None:
        body["op"] = "pin"
        body["pin"] = pin
    if pin_capable:
        body["pin_capable"] = True
    _queue.put(("set", target, body))


def _send_one(
    path: str, target: "_OutputsTarget", body: dict, timeout: float = OUTPUTS_SEND_TIMEOUT_S,
) -> "tuple[int | None, dict | None]":
    """POST *body* (plus this dial's id) to *target* at *path*.

    Never raises: any connection, timeout or parse failure returns
    (None, None). Never follows a redirect — http.client does not chase
    one on its own. Reads at most _MAX_RESPONSE_BYTES and parses the body
    leniently — a non-JSON or non-object body is reported as (status, None)
    rather than raising.
    """
    try:
        conn = http.client.HTTPConnection(target.ip, target.port, timeout=timeout)
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
            path, timeout = _FETCH_PATH, OUTPUTS_SEND_TIMEOUT_S
        else:
            path, timeout = _SET_PATH, OUTPUTS_SET_TIMEOUT_S
        status, body = _send_one(path, target, payload, timeout)
        # The callback is told what was asked, never the PIN.
        request = {k: v for k, v in payload.items() if k != "pin"}
        if _on_result is not None:
            try:
                _on_result(kind, target.appliance_id, status, body, request)
            except Exception:
                logging.debug("dial outputs: on_result callback raised", exc_info=True)
        if kind == "set":
            # The screen reconciles from the appliance's own truth rather
            # than trusting this mutation's outcome, whatever it was.
            enqueue_fetch(target)
