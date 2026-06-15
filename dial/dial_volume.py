"""dial_volume.py — Async volume and mute fan-out worker.

All network I/O runs in a single background worker thread.  Encoder callbacks
call enqueue_delta() and button press callbacks call enqueue_mute_toggle();
both return immediately so GPIO interrupt callbacks are never blocked by network I/O.

Rapid encoder events are coalesced: adjacent delta events in the queue are
summed before dispatch so a burst of detents produces one HTTP round-trip.
Mute events are preserved in order: deltas before and after a mute event are
coalesced independently, so the sequence delta+delta+mute+delta dispatches as
combined-delta, mute-toggle, final-delta.

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
from typing import Tuple, Union

# Each queue item is either ("delta", int) or ("mute",)
_Event = Union[Tuple[str, int], Tuple[str]]
_queue: queue.SimpleQueue[_Event] = queue.SimpleQueue()

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
    _queue.put(("delta", delta))


def enqueue_mute_toggle() -> None:
    """Enqueue a mute-toggle event for delivery. Returns immediately."""
    _queue.put(("mute",))


def _coalesce(first: _Event) -> list[_Event]:
    """Drain the queue into an ordered batch, coalescing adjacent delta events."""
    batch: list[_Event] = []

    def _append(ev: _Event) -> None:
        if ev[0] == "delta" and batch and batch[-1][0] == "delta":
            batch[-1] = ("delta", batch[-1][1] + ev[1])  # type: ignore[index]
        else:
            batch.append(ev)

    _append(first)
    while True:
        try:
            _append(_queue.get_nowait())
        except queue.Empty:
            break
    return batch


def _worker() -> None:
    while True:
        first = _queue.get()
        batch = _coalesce(first)
        targets = _targets_fn()
        if not targets:
            continue
        for event in batch:
            if event[0] == "delta":
                clamped = _fan_out(targets, _cfg.uuid, event[1])  # type: ignore[arg-type]
                if clamped and _led_ref:
                    _led_ref.flash_clamped()
            else:  # "mute"
                _fan_out_mute(targets, _cfg.uuid)


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


def _fan_out_mute(targets: list, uuid: str) -> None:
    """Send mute-toggle to all targets concurrently."""
    threads = [
        threading.Thread(target=_send_one_mute, args=(t, uuid))
        for t in targets
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=0.6)


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


def _send_one_mute(target, uuid: str) -> None:
    url  = f"http://{target.ip}:{target.port}/api/dial/mute"
    body = json.dumps({"dial_id": uuid}).encode()
    req  = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=0.4) as resp:
            data = json.loads(resp.read())
        if not data.get("ok"):
            _log_mute_failure(target.ip, "ok=false error=%s", data.get("error", "unknown"))
            return
        _fail_counts.pop(target.ip, None)
    except urllib.error.HTTPError as e:
        if e.code == 403:
            logging.debug("mute POST %s: 403 unauthorized", target.ip)
        else:
            _log_mute_failure(target.ip, "HTTP %d", e.code)
    except Exception as e:
        _log_mute_failure(target.ip, "%s", e)


def _log_volume_failure(ip: str, fmt: str, *args) -> None:
    n = _fail_counts.get(ip, 0) + 1
    _fail_counts[ip] = n
    if n == 1 or n % 10 == 0:
        logging.warning("volume POST %s: " + fmt + " (failure #%d)", ip, *args, n)
    else:
        logging.debug("volume POST %s: " + fmt, ip, *args)


def _log_mute_failure(ip: str, fmt: str, *args) -> None:
    n = _fail_counts.get(ip, 0) + 1
    _fail_counts[ip] = n
    if n == 1 or n % 10 == 0:
        logging.warning("mute POST %s: " + fmt + " (failure #%d)", ip, *args, n)
    else:
        logging.debug("mute POST %s: " + fmt, ip, *args)
