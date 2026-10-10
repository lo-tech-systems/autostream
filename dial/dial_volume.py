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

Volume and mute each address either a single "reporting-from" target — the
display's chosen artwork source when it has one, else the oldest playing
target (see select_volume_target()) — or, under broadcast scope "all", every
playing appliance at once: a dial with no screen (or too small a one to
select an appliance) cannot choose which appliance a twist or a push
addresses, so it addresses all of them. Volume's "all" fans the same delta
out to every target via the ordinary _fan_out(); mute's "all" is decided
fresh at dispatch time by the worker, from what the fleet reports at that
moment — see enqueue_mute_all()/_dispatch_mute_all() below, not a belief
carried in the queue like a "current"-scope mute is. Callers resolve targets
fresh per dispatched event via targets_fn()/mute_targets_fn() rather than
once per batch, so the two callables — and the scope they read live — are
always current at send time.

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
is evaluated). The fan-out helpers (_fan_out/_fan_out_mute/_fan_out_status)
accept a list of any length: exactly one target for "current" scope, every
playing target for "all". Targets are pre-deduplicated by mDNS service name
via get_playing_targets() so no IP-based dedup is needed here.

Failure logging is rate-limited: WARNING on the 1st failure and every 10th
thereafter per target IP; DEBUG for all intermediate failures.  403 and 412
responses (unauthorized UUID) are DEBUG-only — expected on mixed-network LAN
— but also recorded in the auth map exactly as a status poll's refusal is, so
a dial refused on volume or mute learns it without waiting for a poll (see
_note_refusal()).

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import json
import logging
import queue
import threading
import time
import urllib.error
import urllib.request
from typing import Tuple, Union

from dial_auth import AUTH_UNAUTHORIZED, OUTCOME_UNAUTHORIZED, auth_map
from dial_target_status import (
    _is_untyped_refusal,
    _lenient_json_object,
    _parse_appliance_id,
    fetch_target_status,
)

# Each queue item is ("delta", int), ("mute", bool) or ("mute_all", int) —
# for "delta" the int is the delta itself; for "mute" the bool is the
# resulting absolute action (True = mute) at the moment it was enqueued; for
# "mute_all" the int is always 1 and only ever matters for _coalesce()'s
# parity count (see enqueue_mute_all()/_dispatch_mute_all() below) — the
# action itself is decided fresh at dispatch, not at enqueue time.
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
# The mute observation store is per-service (_observed_muted), unlike the
# single-slot volume readout above: a screened dial set to broadcast scope
# "all" fans a push out to every playing appliance, and the poll itself now
# records the flag of every target it walks (not only the reporting one —
# see dial_display.py), so several services can legitimately be tracked at
# once. Keying by service means a response or observation for one target can
# never clobber another's entry — in particular the bound/reporting
# appliance's own glyph, which always reads back its own entry via
# shown_muted(name) regardless of what a fan-out to OTHER targets last
# reported. (This is a fix over the single-slot store this replaces: there,
# every observation shared one slot, so a wide fan-out's last responder to
# arrive could blank a different appliance's glyph until the next poll.)
# There is no "positive proves it" shortcut for mute the way there is for
# volume: nothing here infers a mute state, it only ever repeats back what an
# appliance's own response said.
#
# _last_observed_mute_service additionally tracks whichever service the most
# recent observe_mute_state() call named — purely so enqueue_mute()'s
# same-frame echo (below) can re-target the one entry a "current"-scope press
# just read via shown_muted(), with no service parameter of its own. Reading
# and enqueuing happen back-to-back on the same thread with no I/O in
# between, so this can only go stale if an unrelated observation (another
# thread's poll tick or fan-out response) lands in that brief window — the
# same narrow, accepted race the single-slot store always had.
#
# A poll must never overwrite a state a mute reply or press has already
# established, so poll observations are filtered (see observe_mute_state()).
# Each poll observation carries requested_at, the monotonic time its status
# request was SENT; replies and echoes carry none and always apply. Per
# service the store keeps:
#   _mute_settled_at  the time from which poll observations are trusted. A
#                     mute or volume reply carrying a bool sets it to the
#                     RECEIVE time (the reply reflects state established
#                     before the appliance answered, so any status request
#                     sent after the receive must agree); enqueue_mute()'s
#                     echo sets it to the press time. A poll observation
#                     requested earlier is ignored.
#   _mute_inflight    when a mute request for the service was pressed or
#                     dispatched, until its reply is recorded or its send
#                     fails. While fresh, poll observations are ignored. It
#                     expires after MUTE_INFLIGHT_EXPIRY_SECONDS (above the
#                     worker's send timeout), so a lost request can never
#                     freeze the state.
# For an appliance whose status reports mute, a poll's unknown (non-bool)
# value never overwrites a known bool, so a failed or timed-out status fetch
# cannot flip a confirmed mute to unmuted. An appliance whose status never
# carries the flag (an earlier release) can only ever give unknown, so there
# that rule would latch a reply's mute state on until some other event
# replaced it; for those a poll that passes the in-flight and settled-time
# checks may clear the stored state, so the highlight follows a mute made
# elsewhere within a poll. The in-flight and settled-time checks still
# protect the press itself.
# ---------------------------------------------------------------------------

_readout_lock = threading.Lock()     # leaf lock, never held across I/O
_readout_service: str | None = None  # target the base was observed on
_readout_base: int | None = None     # last observed master_volume
_readout_pending = 0                 # deltas enqueued since the base

_observed_muted: dict[str, bool | None] = {}     # per-service last-reported mute flag
_last_observed_mute_service: str | None = None   # most recently observed service
_mute_settled_at: dict[str, float] = {}          # per-service: poll observations trusted from here
_mute_inflight: dict[str, float] = {}            # per-service: monotonic time a mute request began

MUTE_INFLIGHT_EXPIRY_SECONDS = 3.0   # above the 0.4s send timeout and the 0.6s join


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


def observe_master_volume_if_tracked(service_name: str | None, volume: int | None) -> None:
    """Like observe_master_volume(), but only when *service_name* is the one
    currently tracked (or nothing is tracked yet). Used by a fan-out response
    (see _send_one()) so that with several targets in flight at once, the
    LAST one to respond cannot re-key the single volume readout away from
    the bound appliance's own number — a screenless dial broadcasting volume
    has no readout to lose by this; a screened dial's number stays the bound
    appliance's."""
    global _readout_service, _readout_base, _readout_pending
    with _readout_lock:
        if _readout_service is not None and service_name != _readout_service:
            return
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


def observe_mute_state(
    service_name: str | None, muted, requested_at: float | None = None,
    *, status_reports_mute: bool = True,
) -> None:
    """Record the mute flag an appliance reported (a status poll, a mute
    response or a volume response) for *service_name*, in that service's own
    entry. service_name None clears every entry (nothing is playing any
    more — the dial-wide reset, not a per-target one). Anything that is not
    a plain bool is treated the same as unknown (None), exactly like
    dial_target_status's own parsing of the field.

    requested_at is the monotonic time a status poll's request was sent; it
    marks the call as a poll observation, which is ignored while a mute
    request for the service is in flight, when it was requested before the
    service's settled time, or when it is unknown and a bool is already
    known. A call without requested_at is a reply and always applies; a
    bool reply also settles the service at its receive time.

    status_reports_mute says whether the service's status carries the mute
    flag at all. When it does not, the unknown-never-overwrites-known rule
    is skipped for its poll observations (see the store's comment block)."""
    global _last_observed_mute_service
    now = time.monotonic()
    with _readout_lock:
        if service_name is None:
            _observed_muted.clear()
            _mute_settled_at.clear()
            _mute_inflight.clear()
            _last_observed_mute_service = None
            return
        is_bool = isinstance(muted, bool)
        if requested_at is not None:
            began = _mute_inflight.get(service_name)
            if began is not None:
                if now - began < MUTE_INFLIGHT_EXPIRY_SECONDS:
                    return
                del _mute_inflight[service_name]
            settled = _mute_settled_at.get(service_name)
            if settled is not None and requested_at < settled:
                return
            if (
                status_reports_mute
                and not is_bool
                and isinstance(_observed_muted.get(service_name), bool)
            ):
                return
        elif is_bool:
            _mute_settled_at[service_name] = now
        _observed_muted[service_name] = muted if is_bool else None
        _last_observed_mute_service = service_name


def _mark_mute_inflight(service_name: str) -> None:
    """Note that a mute request for *service_name* is now outstanding."""
    with _readout_lock:
        _mute_inflight[service_name] = time.monotonic()


def _clear_mute_inflight(service_name: str) -> None:
    """The mute request for *service_name* has been answered or has failed."""
    with _readout_lock:
        _mute_inflight.pop(service_name, None)


def shown_muted(service_name: str | None) -> bool:
    """The last reported mute state for *service_name*; False when unknown
    or when nothing has been observed for it — each service has its own
    entry, so a fan-out response or a poll observation for a DIFFERENT
    target can never leak into this one."""
    with _readout_lock:
        if service_name is None:
            return False
        return bool(_observed_muted.get(service_name))


def forget_mute_states_except(service_names) -> None:
    """Drop every observed mute entry whose service is not in *service_names*
    (an iterable, consumed once into a set). Called by the display poll after
    each tick so a target that stopped playing does not accumulate a stale
    entry forever. Pure hygiene — never touches the entries it keeps."""
    keep = set(service_names)
    with _readout_lock:
        for name in list(_observed_muted.keys()):
            if name not in keep:
                del _observed_muted[name]
        for store in (_mute_settled_at, _mute_inflight):
            for name in list(store.keys()):
                if name not in keep:
                    del store[name]


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
    when not supplied (single-target mute, scope "current"). on_readout_changed,
    when supplied, is called (best-effort)
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
    shown_muted() before calling this. Used for scope "current" only; a
    scope "all" push uses enqueue_mute_all() instead (see below), which
    decides its action at dispatch rather than echoing one here.

    Called from the touch thread and the button thread. Does no network
    I/O and never takes DialDisplay._lock — only the small dedicated
    _readout_lock, held for a plain write. Echoes the resulting state into
    the observation store immediately, so the glyph updates on the same
    frame as the press even before the appliance's response (about 0.4s
    later) or the next status poll confirms it — either of those overwrites
    this echo. The echo targets whichever service was most recently
    observed (_last_observed_mute_service) — the same service the caller
    just read via shown_muted() moments before, with no I/O in between to
    let that go stale. Returns the requested state (the caller may use it,
    but nothing here depends on that).
    """
    new_state = not currently_muted
    now = time.monotonic()
    with _readout_lock:
        name = _last_observed_mute_service
        if name is not None:
            _observed_muted[name] = new_state
            _mute_settled_at[name] = now
            _mute_inflight[name] = now
    _queue.put(("mute", new_state))
    return new_state


def enqueue_mute_all() -> None:
    """Enqueue one fleet-wide mute toggle for delivery. Returns immediately.

    Plain queue put; no lock, no I/O — unlike enqueue_mute(), nothing is
    echoed into the observation store here, because the action itself is not
    yet known: a screenless (or scope "all") push cannot be decided from
    what this dial's touch/button thread already believes, since the
    observation store is not a complete picture of the fleet (see
    _dispatch_mute_all()'s docstring). The decision, and the store's
    optimistic echo, happen together on the volume worker thread once it
    dispatches this event — roughly 0.4-1s later, not on the same frame as
    the press. Used for scope "all" only; enqueue_mute() is scope "current"'s
    equivalent.
    """
    _queue.put(("mute_all", 1))


def _coalesce(first: _Event) -> list[_Event]:
    """Drain the queue into an ordered batch, coalescing adjacent delta
    events (summed), adjacent mute events (collapsed to the last one), and
    adjacent mute_all events (collapsed by PARITY: an even-count run cancels
    out entirely, an odd-count run sends one). Mute_all is absolute-per-
    dispatch rather than absolute-per-enqueue like "mute", so a run cannot be
    collapsed "to the last one" the way plain mute is — the worker only
    learns what action a mute_all event means once it dispatches it, so two
    queued pushes mean "toggle, then undo" (parity), not "whatever the last
    one decides"."""
    batch: list[_Event] = []

    def _append(ev: _Event) -> None:
        if ev[0] == "delta" and batch and batch[-1][0] == "delta":
            batch[-1] = ("delta", batch[-1][1] + ev[1])  # type: ignore[index]
        elif ev[0] == "mute" and batch and batch[-1][0] == "mute":
            batch[-1] = ev  # collapse a run of mutes to the last resulting action
        elif ev[0] == "mute_all" and batch and batch[-1][0] == "mute_all":
            batch[-1] = ("mute_all", batch[-1][1] + ev[1])  # type: ignore[index]
        else:
            batch.append(ev)

    _append(first)
    while True:
        try:
            _append(_queue.get_nowait())
        except queue.Empty:
            break
    return [
        ("mute_all", 1) if ev[0] == "mute_all" else ev
        for ev in batch
        if not (ev[0] == "mute_all" and ev[1] % 2 == 0)
    ]


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
            elif event[0] == "mute_all":
                resolver = _mute_targets_fn or _targets_fn
                targets = resolver()
                if not targets:
                    continue
                _dispatch_mute_all(targets, _cfg.uuid)  # type: ignore[arg-type]
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


def _fan_out_status(targets: list, uuid: str) -> list:
    """One fetch_target_status() per target concurrently — mirrors
    _fan_out_mute's shape (thread per target, 0.4s request timeout, 0.6s
    join). Each slot of the returned list is the `muted` flag that target
    reported, or None when it did not answer in time or its response carried
    no flag at all. Never raises: fetch_target_status() itself never raises."""
    results: list = [None] * len(targets)

    def _one(i: int, target) -> None:
        record = fetch_target_status(target, uuid, timeout_seconds=0.4)
        muted = record.get("muted")
        results[i] = muted if isinstance(muted, bool) else None

    threads = [
        threading.Thread(target=_one, args=(i, t))
        for i, t in enumerate(targets)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=0.6)
    return results


def _dispatch_mute_all(targets: list, uuid: str) -> None:
    """Decide and send one fleet-wide mute/restore action, from a fresh
    status sweep taken at this moment.

    The observation store is not a complete-enough picture to decide this
    from: a screenless dial runs no status poll at all, and a screened
    dial's poll only walks targets up to the first identified one (see
    dial_display.py) — so this reads every playing appliance itself, on the
    worker thread, never on the touch or button thread.

    An unknown flag (a timeout, no dial_status support, or a response with
    no `muted` field at all) counts as unmuted, so any appliance this dial
    cannot fully read makes the fleet action "mute" — the safe direction: a
    push on a fleet the dial cannot fully confirm silences it. Only a fleet
    where every target confirms `muted: true` gets a "restore".
    """
    if not targets:
        return
    flags = _fan_out_status(targets, uuid)
    muted = any(flag is not True for flag in flags)
    for t in targets:
        # Optimistic echo, same as enqueue_mute()'s — overwritten by each
        # target's own response in _fan_out_mute() just below. Marked in
        # flight first so a poll cannot slip in between and undo it.
        _mark_mute_inflight(t.service_name)
        observe_mute_state(t.service_name, muted)
    _fan_out_mute(targets, uuid, muted)


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
            # actually applied to, about 0.4s after the press. Scope "all"
            # can fan a delta out to several targets at once; observing only
            # when tracked (or nothing is tracked yet) stops the LAST
            # response to arrive from re-keying the readout away from
            # whichever appliance it actually belongs to.
            observe_master_volume_if_tracked(target.service_name, vol)
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
            _note_refusal(target, e)
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
            _note_refusal(target, e)
        else:
            _log_mute_failure(target.ip, "HTTP %d", e.code)
    except Exception as e:
        _log_mute_failure(target.ip, "%s", e)
    finally:
        # Answered or failed, the request is no longer outstanding: the
        # reply (if any) has been recorded above, so polls resume.
        _clear_mute_inflight(target.service_name)


class _ErrorResponse:
    """The one method of a response object the status helpers read."""

    def __init__(self, err: urllib.error.HTTPError) -> None:
        self._err = err

    def getheader(self, name: str):
        headers = self._err.headers
        return headers.get(name) if headers is not None else None


def _note_refusal(target, err: urllib.error.HTTPError) -> None:
    """Feed a volume or mute refusal into the auth map the way a status
    poll's refusal is fed: a typed 412 whose body id matches the target's
    own, or, for an appliance without typed refusals, a 403 whose body is
    exactly an empty JSON object (correlated with the id the target was
    resolved to). Anything else is ignored. Never raises: a failed refusal
    note must not affect the send."""
    try:
        raw = err.read(4096)
        if err.code == 412:
            data = _lenient_json_object(raw)
            if data is None or data.get("error") != "dial_not_authorized":
                return
            body_id = _parse_appliance_id(data)
        elif err.code == 403:
            if target.typed_refusals or not _is_untyped_refusal(_ErrorResponse(err), raw):
                return
            body_id = target.appliance_id
        else:
            return
        auth_map.apply(target.appliance_id, OUTCOME_UNAUTHORIZED, body_id, time.monotonic())
        if (
            auth_map.state(target.appliance_id) == AUTH_UNAUTHORIZED
            and auth_map.record_refusal(target.appliance_id)
        ):
            logging.warning(
                "dial volume: appliance %s refused this dial; allow it in "
                "that appliance's web UI",
                target.name,
            )
    except Exception:
        logging.debug("volume refusal note failed", exc_info=True)


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
