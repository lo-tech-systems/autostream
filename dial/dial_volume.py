"""dial_volume.py — Async volume and mute fan-out worker.

All network I/O runs in a single background worker thread. Encoder callbacks
call enqueue_delta() and button/touch press callbacks call enqueue_mute();
both return immediately so GPIO interrupt callbacks and the touch thread are
never blocked by network I/O.

Mute is deterministic, not toggled independently by each appliance: this
module holds a single `muted` belief (module-level, default False —
optimistic-unmuted: a press happens because something is audible). A press
flips the belief locally and enqueues the resulting ABSOLUTE action ("mute"
or "restore") for every target to obey identically. This is what keeps a
mixed-volume fleet from oscillating out of phase forever: when each appliance
inferred its own action from its own volume, appliances at different levels
disagreed about what a press meant and never converged.

The belief self-corrects from traffic that already happens, at no extra
network cost:
  - Mute responses are authoritative — every target replies to the same
    absolute instruction — and are folded in by _send_one_mute regardless of
    which way they point (see _reconcile_muted()).
  - A master_volume > 0 observed anywhere (a volume fan-out response, a
    status poll, ...) is definitive proof the fleet is audible and sets the
    belief to unmuted via note_master_volume_positive(). CRITICAL ASYMMETRY:
    master_volume == 0 from a single appliance proves nothing about the rest
    of the fleet and must NEVER set the belief to muted — only the
    volume-positive inference is safe from one observation.

Rapid encoder events are coalesced: adjacent delta events in the queue are
summed before dispatch so a burst of detents produces one HTTP round-trip.
Mute events are preserved in order relative to deltas: deltas before and
after a mute event are coalesced independently, so the sequence
delta+delta+mute+delta dispatches as combined-delta, mute-action,
final-delta. Adjacent mute events collapse to the LAST one instead of
cancelling in pairs: actions are absolute now, so re-asserting only the final
state is idempotent and free to replay, and it corrects any drift the belief
picked up in between; cancelling a pair would be consistent too but throws
away that free correction for no benefit.

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

# Each queue item is either ("delta", int) or ("mute", bool) — the bool is
# the resulting absolute belief (True = muted) at the moment it was enqueued.
_Event = Union[Tuple[str, int], Tuple[str, bool]]
_queue: queue.SimpleQueue[_Event] = queue.SimpleQueue()

_cfg        = None
_targets_fn = None
_led_ref    = None

_fail_counts: dict[str, int] = {}   # key: target IP; tracks consecutive failures

# ---------------------------------------------------------------------------
# Mute belief — single module-level flag, guarded by a small leaf lock.
#
# _muted_lock is NEVER held across network I/O and is never nested with
# DialDisplay._lock in either direction — it is only ever taken standalone,
# for the duration of a plain attribute read/write. This is what makes
# enqueue_mute()/is_muted() safe to call from the touch thread and the
# button thread, mirroring the discipline dial_display.DialDisplay documents
# for notify_touch_activity()/set_overlay() and its own overlay leaf lock.
# ---------------------------------------------------------------------------

_muted_lock = threading.Lock()
_muted = False  # optimistic default: something is playing, unmuted


def start_volume_worker(cfg, targets_fn, led) -> None:
    """Store shared state and start the background worker thread."""
    global _cfg, _targets_fn, _led_ref
    _cfg, _targets_fn, _led_ref = cfg, targets_fn, led
    threading.Thread(target=_worker, daemon=True, name='volume-worker').start()


def enqueue_delta(delta: int) -> None:
    """Enqueue a volume delta for delivery. Returns immediately."""
    _queue.put(("delta", delta))


def enqueue_mute() -> bool:
    """Flip the mute belief and enqueue the resulting absolute action.

    Called from the touch thread and the button thread. Does no network
    I/O and never takes DialDisplay._lock — only the small dedicated
    _muted_lock, held for a plain read-modify-write. Returns the new belief
    immediately so the caller can repaint the touch glyph on the same frame
    as the press; the worker thread later fans out the absolute
    "mute"/"restore" action this belief implies.
    """
    global _muted
    with _muted_lock:
        _muted = not _muted
        new_belief = _muted
    _queue.put(("mute", new_belief))
    return new_belief


def is_muted() -> bool:
    """Current mute belief. A cheap, lock-guarded read — safe to call from
    any thread, including the touch thread (see enqueue_mute())."""
    with _muted_lock:
        return _muted


def note_master_volume_positive() -> None:
    """Record a master_volume > 0 observation seen anywhere (a volume
    fan-out response, a status poll, ...) — definitive proof the fleet is
    audible, so the belief becomes unmuted.

    Never call this for master_volume == 0: a single appliance reporting 0
    proves nothing about the rest of the fleet under the fleet mute rule —
    see the module docstring's CRITICAL ASYMMETRY note.
    """
    global _muted
    with _muted_lock:
        _muted = False


def _reconcile_muted(value) -> None:
    """Fold an authoritative `muted` field from a mute response into the
    belief.

    Mute responses come from every target obeying the same absolute
    instruction, so — unlike a bare volume observation — they may set the
    belief either way. Silently ignored if the field is missing or not a
    bool (defensive against a malformed/partial response).
    """
    global _muted
    if not isinstance(value, bool):
        return
    with _muted_lock:
        _muted = value


def _coalesce(first: _Event) -> list[_Event]:
    """Drain the queue into an ordered batch, coalescing adjacent delta
    events (summed) and adjacent mute events (collapsed to the last one)."""
    batch: list[_Event] = []

    def _append(ev: _Event) -> None:
        if ev[0] == "delta" and batch and batch[-1][0] == "delta":
            batch[-1] = ("delta", batch[-1][1] + ev[1])  # type: ignore[index]
        elif ev[0] == "mute" and batch and batch[-1][0] == "mute":
            batch[-1] = ev  # collapse a run of mutes to the last resulting action
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
                _fan_out_mute(targets, _cfg.uuid, event[1])  # type: ignore[arg-type]


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


def _fan_out_mute(targets: list, uuid: str, muted: bool) -> None:
    """Send the absolute mute/restore action to all targets concurrently."""
    threads = [
        threading.Thread(target=_send_one_mute, args=(t, uuid, muted))
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
        # Free reconciliation: this target just confirmed an audible master
        # volume, which proves the fleet is not muted. Without this, turning
        # the volume up while the belief is stale-muted would leave the next
        # mute press sending a restore that no-ops, so the press looks dead.
        if isinstance(vol, int) and not isinstance(vol, bool) and vol > 0:
            note_master_volume_positive()
        _fail_counts.pop(target.ip, None)   # clear only on confirmed application success
    except urllib.error.HTTPError as e:
        if e.code == 403:
            logging.debug("volume POST %s: 403 unauthorized", target.ip)
        else:
            _log_volume_failure(target.ip, "HTTP %d", e.code)
    except Exception as e:
        _log_volume_failure(target.ip, "%s", e)


def _send_one_mute(target, uuid: str, muted: bool) -> None:
    url    = f"http://{target.ip}:{target.port}/api/dial/mute"
    action = "mute" if muted else "restore"
    body   = json.dumps({"dial_id": uuid, "action": action}).encode()
    req    = urllib.request.Request(
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
        # Free reconciliation: fold the authoritative belief this target
        # reports back rather than discarding it — see _reconcile_muted().
        _reconcile_muted(data.get("muted"))
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
