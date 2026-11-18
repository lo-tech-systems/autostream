"""autostream_dial_push.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Tells dials that something they show has changed. notify_state_changed() is
the single entry point: it is called once a change is committed, from any
thread, and returns at once. A dial that is told asks the appliance for its
state itself, so the hint carries only which kinds of thing changed and a
hint that is lost, late or repeated can never leave a dial wrong.

A change is sent at once; further changes inside a short window are sent
together when it ends (StateChangeCoalescer). The send is one fan-out job on
the push worker in this module, which also sends the authorisation and
warnings pushes. Dial authorisation is written and pushed here too: the
authorise and revoke rows are bound by this module.

Some state is changed only by the coordinator (the daemon's repeat block, the
identified track, a session starting or ending). StateHints, a subscriber to
the state store, notices those once per coordinator cycle. A change to the
outputs part is hinted as what moved in it: the speaker list, the volumes, the
mutes.
"""
from __future__ import annotations

import http.client
import json as _json
import logging
import queue
import threading
import time
from dataclasses import dataclass

from autostream_dials import (
    dial_proto_generation,
    get_dial_sighting,
    parse_dial_entries,
    remove_dial_entry,
    validate_dial_name,
    write_dial_entry,
)
from autostream_intents.table import Intent, Outcome, bind
import autostream_rpi as rpi
from autostream_state import (
    active_track,
    eq_band_digest,
    outputs_list_digest,
    outputs_mute_digest,
    outputs_volume_digest,
    repeat_digest,
    store as _state_store,
    track_digest,
)


STATE_PUSH_PATH = "/state-changed"
# A change is pushed at once; further changes inside this window are pushed
# once, together, when the window ends.
STATE_PUSH_MIN_INTERVAL_S = 0.3
# Oldest dial protocol generation the hint is sent to.
STATE_PUSH_MIN_GENERATION = 3

# What a hint may say changed. A dial treats the list as advisory and an
# unknown token as "something"; the table keeps the senders honest.
CHANGE_KINDS = frozenset({
    "session", "outputs", "volume", "mute", "repeat", "track", "eq", "input",
})


def _timer(delay: float, fn) -> None:
    t = threading.Timer(delay, fn)
    t.daemon = True
    t.start()


class StateChangeCoalescer:
    """A change is emitted at once when none was emitted inside the last
    min_interval_s; otherwise it waits for that window to end and is emitted
    then, together with everything recorded meanwhile. A dial is left out of
    an emitted hint only when every change it merges named that dial.

    The lock covers plain reads and writes only. emit is always called after
    it is released, on the thread of the notify() or flush() that took the
    pending changes."""

    def __init__(self, emit, *, clock=time.monotonic, schedule=None,
                 min_interval_s=STATE_PUSH_MIN_INTERVAL_S) -> None:
        # emit(kinds: frozenset, except_dials: frozenset)
        self._emit = emit
        self._clock = clock
        # schedule(delay_s, fn) runs fn once after delay_s, on another thread
        self._schedule = schedule if schedule is not None else _timer
        self._min_interval_s = min_interval_s
        self._lock = threading.Lock()
        self._last_emit_at: float | None = None
        self._pending_kinds: set = set()
        self._pending_except: set | None = None   # None: nothing pending
        self._scheduled = False

    def notify(self, kinds, except_dial=None) -> None:
        now = self._clock()
        emit = None
        delay = None
        with self._lock:
            self._pending_kinds.update(kinds)
            names = {except_dial} if except_dial else set()
            if self._pending_except is None:
                self._pending_except = names
            else:
                self._pending_except &= names
            inside = (self._last_emit_at is not None
                      and now - self._last_emit_at < self._min_interval_s)
            if not inside:
                emit = self._take_locked(now)
            elif not self._scheduled:
                self._scheduled = True
                delay = self._last_emit_at + self._min_interval_s - now
        if emit is not None:
            self._emit(*emit)
        elif delay is not None:
            try:
                self._schedule(max(0.0, delay), self.flush)
            except Exception:
                # Nothing will flush this window; let the next change
                # schedule again rather than wait for one that never comes.
                with self._lock:
                    self._scheduled = False
                raise

    def flush(self) -> None:
        """Emit what is pending: the end of a window."""
        emit = None
        with self._lock:
            self._scheduled = False
            if self._pending_except is not None:
                emit = self._take_locked(self._clock())
        if emit is not None:
            self._emit(*emit)

    def _take_locked(self, now):
        kinds = frozenset(self._pending_kinds)
        names = frozenset(self._pending_except or ())
        self._pending_kinds.clear()
        self._pending_except = None
        self._last_emit_at = now
        return kinds, names


# ---------------------------------------------------------------------------
# Dial pushes
# ---------------------------------------------------------------------------
# Best-effort notifications to a dial: "authorization may have changed"
# (/auth-changed) and "warnings may have changed" (/warnings-changed). Each
# only causes the dial to fetch or poll now instead of waiting for its next
# scheduled tick, and grants nothing by itself, so a lost or failed push is
# harmless: the dial's own poll and reconcile are the source of truth.
#
# Every push goes through one worker thread fed by a queue, so a burst of
# changes costs one thread however many pushes it holds; a slow dial delays
# the pushes behind it by at most the timeout and one retry.
#
# A job naming one dial is tried, then retried once. A job naming no dial is a
# fan-out: the worker resolves the eligible dials when it runs it and sends to
# each once with no retry. A dial that did not answer is skipped for a few
# seconds and tried last afterwards, so an unreachable dial does not hold up
# the others.

_PUSH_TIMEOUT_S = 1.0
_PUSH_RETRY_DELAY_S = 2.0
_AUTH_CHANGED_PATH = "/auth-changed"

# After a failed fan-out send a dial is skipped for this long and sent to last
# thereafter.
STATE_FANOUT_BACKOFF_S = 5.0
# A failure mark older than this is forgotten, which bounds the table.
_PUSH_ENTRY_MAX_AGE_S = 60.0


@dataclass(frozen=True)
class _PushJob:
    path: str
    uuid: str | None          # None: every eligible dial, resolved when the job runs
    body: dict
    min_generation: int = 0
    exclude: frozenset = frozenset()


_push_queue: "queue.SimpleQueue[_PushJob]" = queue.SimpleQueue()
_push_worker_lock = threading.Lock()
_push_worker_thread: threading.Thread | None = None
# uuid -> monotonic time of its last failed fan-out send. Worker thread only.
_fanout_failed_at: dict[str, float] = {}


def _post_push_body(ip: str, port: int, path: str, body: dict, timeout: float) -> bool:
    """One POST of the JSON object *body* to *path* on the dial's own server.
    Never raises.

    Returns True on any 2xx response. Plain http.client, no redirects
    followed and no interest in the response body -- the push is advisory.
    """
    conn = None
    try:
        conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        conn.request("POST", path, body=_json.dumps(body).encode(),
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        resp.read()
        return 200 <= resp.status < 300
    except Exception as e:
        logging.debug("dial push: POST %s:%s%s failed: %s", ip, port, path, e)
        return False
    finally:
        if conn is not None:
            conn.close()


def _post_push(ip: str, port: int, path: str, appliance_id: str, timeout: float) -> bool:
    """One POST of {"appliance_id": ...} to *path*; see _post_push_body."""
    return _post_push_body(ip, port, path, {"appliance_id": appliance_id}, timeout)


def _push_once(path: str, uuid: str, appliance_id: str) -> None:
    """One push job: one attempt, one retry after a short delay."""
    sighting = get_dial_sighting(uuid)
    if sighting is None:
        logging.debug("dial push: %s not sighted, skipping", uuid)
        return
    if _post_push(sighting.ip, sighting.port, path, appliance_id, _PUSH_TIMEOUT_S):
        return
    time.sleep(_PUSH_RETRY_DELAY_S)
    _post_push(sighting.ip, sighting.port, path, appliance_id, _PUSH_TIMEOUT_S)


def eligible_dial_uuids(min_generation: int, *, exclude=()) -> list[str]:
    """The authorised dials that are sighted now and speak at least
    *min_generation*, in the authorised list's order, less *exclude*. Reads
    the dials file: not for a request thread or the coordinator loop."""
    out = []
    for entry in parse_dial_entries():
        if entry.uuid in exclude:
            continue
        sighting = get_dial_sighting(entry.uuid)
        if sighting is None or dial_proto_generation(sighting.dial_proto) < min_generation:
            continue
        out.append(entry.uuid)
    return out


def _fanout(job: _PushJob) -> None:
    """One fan-out job: *job.body* plus the appliance id, sent once to each
    eligible dial. No retry and no sleep. Dials that have not failed lately go
    first; one that failed is skipped for STATE_FANOUT_BACKOFF_S and goes last
    after that. Runs on the worker thread, which owns _fanout_failed_at."""
    appliance_id = rpi.get_appliance_id()
    if not appliance_id:
        return
    body = dict(job.body)
    body["appliance_id"] = appliance_id
    now = time.monotonic()
    for uuid in [u for u, t in _fanout_failed_at.items() if now - t > _PUSH_ENTRY_MAX_AGE_S]:
        del _fanout_failed_at[uuid]
    uuids = eligible_dial_uuids(job.min_generation, exclude=job.exclude)
    for uuid in sorted(uuids, key=lambda u: _fanout_failed_at.get(u, 0.0)):
        failed_at = _fanout_failed_at.get(uuid)
        if failed_at is not None and now - failed_at < STATE_FANOUT_BACKOFF_S:
            continue
        sighting = get_dial_sighting(uuid)
        if sighting is None:
            continue
        if _post_push_body(sighting.ip, sighting.port, job.path, body, _PUSH_TIMEOUT_S):
            _fanout_failed_at.pop(uuid, None)
        else:
            _fanout_failed_at[uuid] = time.monotonic()
            logging.debug("dial push: %s did not take %s, skipping it for %.0f s",
                          uuid, job.path, STATE_FANOUT_BACKOFF_S)


def _run_job(job: _PushJob) -> None:
    if job.uuid is not None:
        _push_once(job.path, job.uuid, job.body["appliance_id"])
    else:
        _fanout(job)


def _push_worker_loop(jobs: "queue.SimpleQueue[_PushJob]") -> None:
    while True:
        job = jobs.get()
        try:
            _run_job(job)
        except Exception:
            logging.debug("dial push: job failed", exc_info=True)


def _enqueue(job: _PushJob) -> None:
    """Queue *job*, starting the worker thread on first use. Never blocks on
    the network."""
    global _push_worker_thread
    with _push_worker_lock:
        if _push_worker_thread is None or not _push_worker_thread.is_alive():
            _push_worker_thread = threading.Thread(
                target=_push_worker_loop, args=(_push_queue,),
                daemon=True, name="dial-push")
            _push_worker_thread.start()
    _push_queue.put(job)


def enqueue_push(path: str, uuid: str, appliance_id: str) -> None:
    """Queue one push of *path* to the dial *uuid*, starting the worker
    thread on first use. Never blocks on the network."""
    _enqueue(_PushJob(path, uuid, {"appliance_id": appliance_id}))


def enqueue_fanout(path: str, body: dict, *, min_generation: int,
                   exclude: frozenset = frozenset()) -> None:
    """Queue one push of *path* to every eligible dial, resolved when the
    worker runs it, with no retry. The appliance id is added then."""
    _enqueue(_PushJob(path, None, dict(body),
                      min_generation=min_generation, exclude=frozenset(exclude)))


def notify_dial_auth_changed(uuid: str) -> None:
    """Best-effort, fire-and-forget. Called by the authorize and revoke
    handlers once the dial entry is written. No-op when this appliance has no
    identity (there is nothing to correlate on the dial). Goes to the one dial
    named, whether or not it is (still) authorised.
    """
    appliance_id = rpi.get_appliance_id()
    if not appliance_id:
        return
    enqueue_push(_AUTH_CHANGED_PATH, uuid, appliance_id)


# ---------------------------------------------------------------------------
# Authorize / revoke
# ---------------------------------------------------------------------------

def _authorize(intent: Intent, wait: float) -> Outcome:
    uuid, name = intent.args["uuid"], intent.args["name"]
    if not validate_dial_name(name):
        return Outcome(ok=False, error="invalid_name")
    write_dial_entry(uuid, name)
    _notify_after_write(uuid, "authorize")
    return Outcome(ok=True)


def _revoke(intent: Intent, wait: float) -> Outcome:
    uuid = intent.args["uuid"]
    remove_dial_entry(uuid)
    _notify_after_write(uuid, "revoke")
    return Outcome(ok=True)


def _notify_after_write(uuid: str, verb: str) -> None:
    try:
        notify_dial_auth_changed(uuid)
    except Exception as e:
        logging.debug("dial auth push: enqueue failed after %s: %s", verb, e)


bind("dials.authorize", _authorize, owner="autostream_dial_push")
bind("dials.revoke", _revoke, owner="autostream_dial_push")


def _emit_hint(kinds: frozenset, except_dials: frozenset) -> None:
    try:
        enqueue_fanout(
            STATE_PUSH_PATH, {"changed": sorted(kinds)},
            min_generation=STATE_PUSH_MIN_GENERATION, exclude=except_dials,
        )
        logging.debug("dial push: state changed (%s)", ",".join(sorted(kinds)))
    except Exception:
        # Also reached from the timer thread, which has no caller to tell.
        logging.debug("dial push: could not queue the state hint", exc_info=True)


_coalescer = StateChangeCoalescer(_emit_hint)


def notify_state_changed(*kinds: str, except_dial: str | None = None) -> None:
    """Say that something a dial shows has changed. Call once the change is
    committed, with no lock held. Never blocks on the network, never raises.
    *kinds* name what changed (CHANGE_KINDS); *except_dial* is the uuid of
    the dial whose own request made the change, which already has the
    result in its reply and is left out of the hint."""
    try:
        if not kinds or any(k not in CHANGE_KINDS for k in kinds):
            logging.debug("dial push: ignoring state change %r", kinds)
            return
        _coalescer.notify(
            kinds, except_dial if isinstance(except_dial, str) and except_dial else None,
        )
    except Exception:
        logging.debug("dial push: notify failed", exc_info=True)


class StateHints:
    """Turns state changes into dial hints. Session edges come as the
    "session" tag. Repeat and track are compared only on a Change with
    batch=True (the close of a coordinator cycle): the repeat block and the
    active track are compared with their values at the previous close, the
    first close being the baseline and an analysing track keeping the previous
    value. Immediate (non-batch) repeat and track Changes, from the ack path
    and the identification workers, are not compared here: the ack path
    carries the "repeat" tag, which is sent as it is, and comparing them too
    would hint a seek twice. Kinds are
    sent one call each, session first, then repeat, then track, as the
    coordinator did.

    A Change that moved the outputs part, batch or not, is compared in three
    pieces (the speaker list, the volumes, the mutes) with their values at the
    previous comparison, the first being the baseline; each that moved is sent
    as "outputs", "volume" or "mute", in that order, after the session and
    tags and before the repeat and track. A new failed speaker start sends
    "outputs" to every dial, the one that asked included, even when the speaker
    list did not change. A Change that touched the equaliser
    part sends "eq" when the output bands moved, compared the same way; the
    gains, the auto-trim and the input equalisers are not shown on a dial."""

    def __init__(self, notify=None) -> None:
        # None means notify_state_changed, looked up when a hint is sent.
        self._notify = notify
        self._last: dict[str, object] = {}

    def __call__(self, change) -> None:
        try:
            self._hint(change)
        except Exception:
            logging.debug("dial push: state hints failed", exc_info=True)

    def _hint(self, change) -> None:
        except_dial = _dial_of(change.requester)
        if "session" in change.tags:
            self._send("session", except_dial)
        for tag in sorted(change.tags - {"session"}):
            if tag in CHANGE_KINDS:
                self._send(tag, except_dial)
        if "outputs" in change.parts:
            outputs = _state_store().snapshot().outputs
            failure = outputs.start_failure.seq if outputs.start_failure is not None else 0
            failed = self._moved("start_failure", lambda: failure)
            listed = self._moved("outputs", lambda: outputs_list_digest(outputs))
            if listed or failed:
                # A failed start is news to the dial that asked, too.
                self._send("outputs", None if failed else except_dial)
            for kind, digest in (
                ("volume", outputs_volume_digest),
                ("mute", outputs_mute_digest),
            ):
                if self._moved(kind, lambda digest=digest: digest(outputs)):
                    self._send(kind, except_dial)
        if "eq" in change.parts:
            eq = _state_store().snapshot().eq
            if self._moved("eq", lambda: eq_band_digest(eq)):
                self._send("eq", except_dial)
        if not change.batch:
            return
        snap = _state_store().snapshot()
        if self._moved("repeat", lambda: repeat_digest(snap.repeat.block)):
            self._send("repeat", except_dial)
        if self._moved("track", lambda: track_digest(active_track(snap))):
            self._send("track", except_dial)

    def _send(self, kind: str, except_dial) -> None:
        (self._notify or notify_state_changed)(kind, except_dial=except_dial)

    def _moved(self, kind: str, digest) -> bool:
        """True when *kind*'s digest differs from the previous reading. The
        first reading is the baseline: a dial fetches the state itself when it
        first meets the appliance. No reading (an attempt is in flight) keeps
        what was there."""
        try:
            value = digest()
        except Exception:
            logging.debug("dial push: %s digest failed", kind, exc_info=True)
            return False
        if value is None:
            return False
        if kind not in self._last:
            self._last[kind] = value
            return False
        if value == self._last[kind]:
            return False
        self._last[kind] = value
        return True


def _dial_of(requester) -> str | None:
    """The uuid in a requester of the form "dial:<uuid>", else None."""
    if isinstance(requester, str) and requester.startswith("dial:") and len(requester) > 5:
        return requester[5:]
    return None


def install_state_hints(store) -> int:
    """Subscribe a StateHints to *store*; returns the subscription handle."""
    return store.subscribe(StateHints())
