"""dial_repeat.py — repeat/replay transport and arm sender, own thread.

Sends the two repeat-screen actions a touch can trigger — the arm toggle
and the Start/Stop transport — to a single appliance over its own worker
thread, queue and HTTP client, entirely separate from dial_volume.py's
fan-out worker. A 2-second send here (the arm/transport round trip can
start a whole replay session on the appliance) would otherwise sit in
front of dial_volume's 0.6-second fan-out join and delay every volume
detent behind it; keeping the two workers apart means a slow repeat send
can never do that.

Touch-thread entry points (enqueue_transport/enqueue_arm) do no I/O and
take no lock other than the queue's own — the same discipline
dial_volume.enqueue_delta()/enqueue_mute() follow. The worker thread never
touches dial_display.DialDisplay._lock; its result callback
(on_result, wired to DialCore.on_repeat_result by dial_main.py) is
called with no lock held here either.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import http.client
import json
import logging
import queue
import threading
from dataclasses import dataclass

# Never blocks the worker beyond this — long enough for a transport send to
# start a replay session on the appliance, short enough that a genuinely
# unreachable appliance is discovered quickly (see the module docstring:
# this is its own thread, so a slow send here never delays a volume detent).
REPEAT_SEND_TIMEOUT_S = 2.0

# A generous but bounded read — the ack bodies this protocol returns are a
# handful of fields, never anything approaching this size; the cap exists
# only to stop a misbehaving or malicious responder from tying up the
# worker thread reading an unbounded body.
_MAX_RESPONSE_BYTES = 64 * 1024

# Keys a queued body carries for the dial's own use and never sends.
_NOT_SENT = ("token",)

_TRANSPORT_PATH = "/api/dial/repeat"
_ARM_PATH = "/api/dial/repeat/arm"


@dataclass(frozen=True)
class _RepeatTarget:
    appliance_id: str
    ip: str
    port: int


# One queue, one worker thread, for both kinds of send — "transport" (Start/
# Stop) and "arm" (the ring toggle). Each item is (kind, target, payload),
# where payload is the JSON body to send before the dial's own id is added.
_queue: "queue.SimpleQueue" = queue.SimpleQueue()

_cfg = None
_on_result = None


def start_repeat_worker(cfg, *, on_result=None) -> None:
    """Store shared state and start the background worker thread.

    on_result, when supplied, is called as on_result(kind, appliance_id,
    http_status, body, request_body) after every send completes — wired to
    DialCore.on_repeat_result by dial_main.py. A raising callback is
    swallowed by the worker loop, never allowed to kill the thread.
    """
    global _cfg, _on_result
    _cfg = cfg
    _on_result = on_result
    threading.Thread(target=_worker, daemon=True, name="repeat-worker").start()


def enqueue_transport(
    target: "_RepeatTarget", action: str, position_seconds: float, token: float,
) -> None:
    """Enqueue a Start ("seek", 0.0) or Stop ("stop") transport request for
    *target*. Returns immediately — no I/O, no lock beyond the queue's
    own. Called from the touch thread. The *token* names this request: it
    is kept with the queued body and handed back with the result, never
    sent."""
    _queue.put(("transport", target, {
        "action": action, "position_seconds": float(position_seconds), "token": token,
    }))


def enqueue_arm(target: "_RepeatTarget", armed: bool, token: float) -> None:
    """Enqueue an arm/disarm request for *target*. Returns immediately —
    same discipline as enqueue_transport(). Called from the touch thread."""
    _queue.put(("arm", target, {"armed": bool(armed), "token": token}))


def _send_one(path: str, target: "_RepeatTarget", body: dict) -> "tuple[int | None, dict | None]":
    """POST *body* (plus this dial's id) to *target* at *path*.

    Never raises: any connection, timeout or parse failure returns
    (None, None). Never follows a redirect — http.client does not chase
    one on its own, so an old appliance's nginx redirecting to an offline
    page is reported as its real status code, not silently read as a 200.
    Reads at most _MAX_RESPONSE_BYTES and parses the body leniently — a
    non-JSON or non-object body is reported as (status, None) rather than
    raising.
    """
    try:
        conn = http.client.HTTPConnection(target.ip, target.port, timeout=REPEAT_SEND_TIMEOUT_S)
        try:
            payload = {k: v for k, v in body.items() if k not in _NOT_SENT}
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
        path = _TRANSPORT_PATH if kind == "transport" else _ARM_PATH
        status, body = _send_one(path, target, payload)
        if _on_result is not None:
            try:
                _on_result(kind, target.appliance_id, status, body, payload)
            except Exception:
                logging.debug("dial repeat: on_result callback raised", exc_info=True)
