"""dial_volume.py — Async volume and mute fan-out worker.

All network I/O runs in a single background worker thread. Encoder callbacks
call enqueue_delta() and button/touch press callbacks call enqueue_mute();
both return immediately so GPIO interrupt callbacks and the touch thread are
never blocked by network I/O.

Mute is appliance state, not a dial belief: the appliance a press addresses
owns whether it is muted and what its outputs return to on restore (process
memory only — no persistence). This module keeps no belief of its own about
mute; enqueue_mute() takes the caller's best knowledge of the CURRENT state
(read from the observation store below, itself fed only by what an
appliance actually reported) and enqueues the absolute action that flips it.
This is what keeps a mixed-volume fleet from oscillating out of phase
forever: every target obeys the same absolute instruction rather than each
inferring its own action from its own volume.

The observation store is exactly the same shape as the optimistic volume
readout just below it, and for the same reason: a value the dial can show
immediately (an optimistic echo of the just-enqueued action) that the
appliance's own response, or the next status poll, always overwrites. Unlike
the volume readout there is no "positive value proves it" shortcut here —
this module never infers mute from a volume; it only ever repeats back what
an appliance's status/mute/volume response explicitly said.

Volume and mute address a single "reporting-from" target by default — the
display's chosen artwork source when it has one, else the oldest playing
target (see select_volume_target()). Mute alone can be widened back to
fleet-wide via the "mute all playing devices" setting (mute_targets_fn on
start_volume_worker); volume is never fanned out to more than one target.
Callers resolve targets fresh per dispatched event via targets_fn()/
mute_targets_fn() rather than once per batch, so the two callables — and the
config they read live (mute_all_playing) — are always current at send time.

The overlay's volume readout is optimistic: enqueue_delta() nudges a pending
offset immediately so the number reacts to a press before any network round
-trip completes, and observe_master_volume()/shown_volume() reconcile it
against whatever the fast (per-request) or slow (status poll) source of
truth reports next. See the "Optimistic volume readout" section below.

Rapid encoder events are coalesced: adjacent delta events in the queue are
summed before dispatch so a burst of detents produces one HTTP round-trip.
Mute events are preserved in order relative to deltas: deltas before and
after a mute event are coalesced independently, so the sequence
delta+delta+mute+delta dispatches as combined-delta, mute-action,
final-delta. Adjacent mute events collapse to the LAST one instead of
cancelling in pairs: actions are absolute, so re-asserting only the final
state is idempotent and free to replay, and it corrects any drift the
appliance's actual state picked up in between; cancelling a pair would be
consistent too but throws away that free correction for no benefit.

Fan-out is concurrent: one thread per target with a 400 ms network timeout and
a 600 ms join timeout (200 ms headroom ensures threads finish before clamped
is evaluated). The fan-out helpers (_fan_out/_fan_out_mute) are unchanged in
shape by single-targeting above — they still accept a list — but the lists
they are normally handed now hold exactly one target; "fan-out" survives
mainly as the mute-all-playing path. Targets are pre-deduplicated by mDNS
service name via get_playing_targets() so no IP-based dedup is needed here.

Failure logging is rate-limited: WARNING on the 1st failure and every 10th
thereafter per target IP; DEBUG for all intermediate failures.  403 and 412
responses (unauthorized UUID) are DEBUG-only — expected on mixed-network LAN.

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
# the resulting absolute action (True = mute) at the moment it was enqueued.
_Event = Union[Tuple[str, int], Tuple[str, bool]]
_queue: queue.SimpleQueue[_Event] = queue.SimpleQueue()

_cfg        = None
_targets_fn = None
_led_ref    = None
# Resolvers for mute and the readout-changed callback — both optional (None
# is a legitimate, fully-supported value; see start_volume_worker()).
_mute_targets_fn = None
_on_readout_changed = None

_fail_counts: dict[str, int] = {}   # key: target IP; tracks consecutive failures

# ---------------------------------------------------------------------------
# Optimistic volume readout AND mute observation store — module-level state
# guarded by one small leaf lock.
#
# _readout_lock is NEVER held across network I/O and is never nested with
# DialDisplay._lock in either direction — it is only ever taken standalone,
# for the duration of a plain attribute read/write. This is what makes
# enqueue_mute()/shown_muted() safe to call from the touch thread and the
# button thread, mirroring the discipline dial_display.DialDisplay documents
# for notify_touch_activity()/set_overlay() and its own overlay leaf lock.
#
# The overlay needs a volume number that reacts to every source of a delta
# (touch, encoder, control socket) on the same frame as the press, is
# corrected by the fast source of truth (the `volume` field in each
# /api/dial/volume response, about 0.4s after a press — see _send_one()) and
# by the slow one (dial_display's 6s status poll — see
# observe_master_volume()), and is readable by the display without the
# display owning it. _readout_base is the last observed master_volume for
# _readout_service; _readout_pending is the sum of deltas enqueued since
# that observation. shown_volume() is base plus pending, clamped to 0..100.
# Nothing in the wire protocol changes: deltas stay stateless — this is
# purely a local display hint.
#
# Known and accepted imprecision: a poll observation landing between a press
# and its response resets pending, so the number can briefly show the
# pre-press value until the response arrives (under 0.5s). The response then
# wins. No time-stamping is added for this — the next observation always
# reconciles it.
#
# The mute observation store follows the identical shape, keyed separately
# (_readout_muted_service/_readout_muted) so a wide mute-all-playing fan-out
# touching several targets at once can never clobber the volume readout's
# own reporting-from target. There is no "positive proves it" shortcut for
# mute the way there is for volume: nothing here infers a mute state, it
# only ever repeats back what an appliance's own response said.
# ---------------------------------------------------------------------------

_readout_lock = threading.Lock()     # leaf lock, never held across I/O
_readout_service: str | None = None  # target the base was observed on
_readout_base: int | None = None     # last observed master_volume
_readout_pending = 0                 # deltas enqueued since the base

_readout_muted_service: str | None = None  # target the mute flag was observed on
_readout_muted: bool | None = None         # last reported mute state for that target


def observe_master_volume(service_name: str | None, volume: int | None) -> None:
    """Record an observed master_volume for *service_name* (a status poll
    or a volume response). Resets the pending optimistic offset: the
    observation supersedes any delta enqueued before it. volume None
    means the target has no selected outputs; service_name None clears
    the readout entirely."""
    global _readout_service, _readout_base, _readout_pending
    with _readout_lock:
        _readout_service = service_name
        _readout_base = volume
        _readout_pending = 0


def shown_volume(service_name: str | None) -> int | None:
    """The number the overlay should show for *service_name*: base plus
    pending, clamped to 0..100. None when nothing has been observed, or
    when the observation was for a different target (a stale number
    from another appliance must not be shown)."""
    with _readout_lock:
        if service_name is None or service_name != _readout_service or _readout_base is None:
            return None
        return max(0, min(100, _readout_base + _readout_pending))


def observe_mute_state(service_name: str | None, muted) -> None:
    """Record the mute flag an appliance reported (a status poll, a mute
    response or a volume response) for *service_name*. None clears (an
    appliance switch, or an old appliance's response carrying no field);
    anything that is not a plain bool is treated the same as None, exactly
    like dial_target_status's own parsing of the field."""
    global _readout_muted_service, _readout_muted
    with _readout_lock:
        _readout_muted_service = service_name
        _readout_muted = muted if isinstance(muted, bool) else None


def shown_muted(service_name: str | None) -> bool:
    """The last reported mute state for *service_name*; False when unknown
    or when the last observation was for a different target (a stale flag
    from another appliance must never be shown)."""
    with _readout_lock:
        if service_name is None or service_name != _readout_muted_service:
            return False
        return bool(_readout_muted)


# ---------------------------------------------------------------------------
# Single-target selection (see the module docstring's "reporting-from
# target" paragraph). Pure and lock-free: no I/O, no module state touched —
# dial_display's poll and the volume worker's resolvers both call this so
# they can never disagree about who the reporting-from target is.
# ---------------------------------------------------------------------------

def select_volume_target(targets: list, preferred_service_name: str | None):
    """Pick the single target volume/mute should address.

    targets is the display-ordered list (oldest playing first). Returns
    the entry whose service_name equals preferred_service_name when
    present, else targets[0], else None. Pure and lock-free so the
    display poll and the worker's resolver call the same function and
    cannot disagree about who the reporting-from target is."""
    if preferred_service_name is not None:
        for t in targets:
            if t.service_name == preferred_service_name:
                return t
    return targets[0] if targets else None


def start_volume_worker(cfg, targets_fn, led, *, mute_targets_fn=None, on_readout_changed=None) -> None:
    """Store shared state and start the background worker thread.

    targets_fn resolves the volume-delta target(s), called fresh per
    dispatched delta event. mute_targets_fn resolves the mute target(s),
    called fresh per dispatched mute event — defaults to targets_fn itself
    when not supplied (single-target mute, the pre-mute_all_playing
    behaviour). on_readout_changed, when supplied, is called (best-effort)
    after a volume response updates the optimistic readout, so the display
    can repaint the overlay's number — see _send_one().
    """
    global _cfg, _targets_fn, _led_ref, _mute_targets_fn, _on_readout_changed
    _cfg, _targets_fn, _led_ref = cfg, targets_fn, led
    _mute_targets_fn = mute_targets_fn
    _on_readout_changed = on_readout_changed
    threading.Thread(target=_worker, daemon=True, name='volume-worker').start()


def enqueue_delta(delta: int) -> None:
    """Enqueue a volume delta for delivery. Returns immediately.

    Also nudges the optimistic readout's pending offset (see the
    "Optimistic volume readout" section above) under _readout_lock, before
    the event reaches the queue — this is a plain integer add, so the
    encoder/touch/control-socket callers stay lock-free in the sense that
    matters (no I/O, no DialDisplay lock).
    """
    global _readout_pending
    with _readout_lock:
        _readout_pending += delta
    _queue.put(("delta", delta))


def enqueue_mute(currently_muted: bool) -> bool:
    """Enqueue the absolute action that flips *currently_muted* -- the
    reporting appliance's last-known mute state, read by the caller from
    shown_muted() before calling this.

    Called from the touch thread and the button thread. Does no network
    I/O and never takes DialDisplay._lock — only the small dedicated
    _readout_lock, held for a plain write. Echoes the resulting state into
    the observation store immediately, so the glyph updates on the same
    frame as the press even before the appliance's response (about 0.4s
    later) or the next status poll confirms it — either of those overwrites
    this echo. Returns the requested state (the caller may use it, but
    nothing here depends on that).
    """
    global _readout_muted
    new_state = not currently_muted
    with _readout_lock:
        _readout_muted = new_state
    _queue.put(("mute", new_state))
    return new_state


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
        # Targets are resolved fresh PER EVENT, not once per batch: a delta
        # and a mute event coalesced into the same wake can legitimately
        # address different targets (the volume resolver and the mute
        # resolver read different live state — see _build_volume_targets_fn/
        # _build_mute_targets_fn in dial_main.py), and even two delta events
        # could straddle a source switch mid-batch. An empty resolver result
        # skips only that one event, not the rest of the batch.
        for event in batch:
            if event[0] == "delta":
                targets = _targets_fn()
                if not targets:
                    continue
                clamped = _fan_out(targets, _cfg.uuid, event[1])  # type: ignore[arg-type]
                if clamped and _led_ref:
                    _led_ref.flash_clamped()
            else:  # "mute"
                resolver = _mute_targets_fn or _targets_fn
                targets = resolver()
                if not targets:
                    continue
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
        # The appliance's own mute state, reported alongside this response --
        # a new appliance answers False after an unmute-by-volume-up and True
        # after an ignored volume-down. An old appliance carries no field at
        # all: guarded so that case leaves the store as it was, rather than
        # overwriting a real observation (e.g. from the last status poll)
        # with an absent one.
        muted_field = data.get("muted")
        if isinstance(muted_field, bool):
            observe_mute_state(target.service_name, muted_field)
        if isinstance(vol, int) and not isinstance(vol, bool):
            # Fast-path reconciliation of the optimistic readout (see the
            # "Optimistic volume readout" section above) — this response is
            # the authoritative master_volume for the target this delta was
            # actually applied to, about 0.4s after the press.
            observe_master_volume(target.service_name, vol)
            if _on_readout_changed is not None:
                # A repaint request must never break a volume send — this
                # runs on the fan-out thread, not the touch thread, but the
                # same "display failure never affects volume" invariant
                # applies here too.
                try:
                    _on_readout_changed()
                except Exception:
                    pass
        _fail_counts.pop(target.ip, None)   # clear only on confirmed application success
    except urllib.error.HTTPError as e:
        if e.code in (403, 412):
            logging.debug("volume POST %s: %d unauthorized", target.ip, e.code)
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
        # The appliance's own authoritative mute state, reported back for the
        # target this action was actually sent to. Guarded the same way as
        # _send_one() above: an absent or malformed field leaves the store
        # as it was rather than clearing a real observation to unknown.
        muted_field = data.get("muted")
        if isinstance(muted_field, bool):
            observe_mute_state(target.service_name, muted_field)
    except urllib.error.HTTPError as e:
        if e.code in (403, 412):
            logging.debug("mute POST %s: %d unauthorized", target.ip, e.code)
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
