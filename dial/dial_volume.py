"""dial_volume.py — Async volume fan-out worker.

All network I/O runs in a single background worker thread.  Encoder callbacks
call enqueue_delta() and return immediately (DR-2 — GPIO callbacks must never
block).  Rapid encoder events are coalesced: the worker drains the queue in one
pass before dispatching, so a burst of detents produces one HTTP round-trip.

Fan-out is concurrent: one thread per target with a 400 ms network timeout and
a 600 ms join timeout (200 ms headroom ensures threads finish before clamped
is evaluated).  Targets are pre-deduplicated by mDNS service name via
get_playing_targets() so no IP-based dedup is needed here.

Failure logging is rate-limited: WARNING on the 1st failure and every 10th
thereafter per target IP; DEBUG for all intermediate failures.  403 responses
(unauthorized UUID) are DEBUG-only — expected on mixed-network LAN.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import json
import logging
import queue
import threading
import urllib.error
import urllib.request

_queue: queue.SimpleQueue[int] = queue.SimpleQueue()

_cfg        = None
_targets_fn = None
_led_ref    = None

_fail_counts: dict[str, int] = {}   # key: target IP; tracks consecutive failures


def start_volume_worker(cfg, targets_fn, led) -> None:
    """Store shared state and start the background worker thread."""
    global _cfg, _targets_fn, _led_ref
    _cfg, _targets_fn, _led_ref = cfg, targets_fn, led
    threading.Thread(target=_worker, daemon=True, name='volume-worker').start()


def enqueue_delta(delta: int) -> None:
    """Enqueue a volume delta for delivery. Returns immediately."""
    _queue.put(delta)


def _worker() -> None:
    while True:
        # Block until at least one delta is available
        delta = _queue.get()
        # Coalesce any additional queued deltas (rapid encoder events)
        while True:
            try:
                delta += _queue.get_nowait()
            except queue.Empty:
                break
        targets = _targets_fn()
        if not targets:
            continue
        clamped = _fan_out(targets, _cfg.uuid, delta)
        if clamped and _led_ref:
            _led_ref.flash_clamped()


def _fan_out(targets: list, uuid: str, delta: int) -> bool:
    """Send volume delta to all targets concurrently.

    Returns True if any target reported a boundary volume (0 or 100).
    Targets are already deduplicated by mDNS service name.
    """
    clamped: list[bool] = []
    threads = [
        threading.Thread(target=_send_one, args=(t, uuid, delta, clamped))
        for t in targets
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=0.6)
    return bool(clamped)


def _send_one(target, uuid: str, delta: int, clamped: list) -> None:
    url  = f"http://{target.ip}:{target.port}/api/dial/volume"
    body = json.dumps({"dial_id": uuid, "delta": delta}).encode()
    req  = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=0.4) as resp:
            data = json.loads(resp.read())
        if not data.get("ok"):
            # HTTP 200 but application-level failure (e.g. backend_unavailable)
            _log_volume_failure(target.ip, "ok=false error=%s", data.get("error", "unknown"))
            return
        vol = data.get("volume", -1)
        if (delta > 0 and vol == 100) or (delta < 0 and vol == 0):
            clamped.append(True)
        _fail_counts.pop(target.ip, None)   # clear only on confirmed application success
    except urllib.error.HTTPError as e:
        if e.code == 403:
            logging.debug("volume POST %s: 403 unauthorized", target.ip)
        else:
            _log_volume_failure(target.ip, "HTTP %d", e.code)
    except Exception as e:
        _log_volume_failure(target.ip, "%s", e)


def _log_volume_failure(ip: str, fmt: str, *args) -> None:
    n = _fail_counts.get(ip, 0) + 1
    _fail_counts[ip] = n
    if n == 1 or n % 10 == 0:
        logging.warning("volume POST %s: " + fmt + " (failure #%d)", ip, *args, n)
    else:
        logging.debug("volume POST %s: " + fmt, ip, *args)
