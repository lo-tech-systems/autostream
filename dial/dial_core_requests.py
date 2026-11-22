"""dial_core_requests.py -- what the dial asks of an appliance, and how it hears back.

Four parts, none of which touches the core's state:

  * the intents the dial's controls send (a name, its arguments and the extra
    request body), one builder per kind of request;
  * folding an appliance's reply into the request record the screens read
    (TransportRequest), and the rule that says when an accepted request has
    been overtaken by the appliance's own state, so its shown value can go;
  * RequestLane, one thread that sends the screens' requests, and the reads
    that refresh a replay position, one at a time;
  * the checks a request must pass, as pure functions over the values the
    caller passes, shared by the controls and the HD page's intents. Each
    path passes the source it reads (the controls the roster outside the lock
    and the published outputs; the intents the state's, under the lock).

The lane carries no HD page intent and no artwork: those never wait behind
a slow request.

A refusal is returned as `ActionResult(False, "<reason>")`, so that the
refusal-sentence scan finds every reason.

The two paths keep these differences on purpose:
  * the controls refuse with the dial's own reasons; the page is sent the
    appliance's or the library's name where one says the same;
  * the controls address the focused appliance without checking it (outputs
    and EQ are held only for that one); every page intent must name it;
  * the controls refuse a speaker set that changes nothing; the page's
    intents forward it and the appliance answers;
  * the controls normalise what they send (`bool`, `int`, a zero position);
    the page's arguments are forwarded as given;
  * a page `repeat.transport` records a stop whatever its action says;
  * the controls' EQ step checks its band and the held EQ, clamps, and shows
    the value at once; the page's EQ intents record nothing;
  * the controls return an `ActionResult` with a token, the page's intents
    the appliance's reply.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import dataclasses
import logging
import math
import queue
import threading
from dataclasses import dataclass
from typing import Callable, Mapping

from autostream_peer_client import PeerReply

from dial_core_state import (
    AUTH_UNAUTHORIZED, OUTPUT_KINDS, PIN_RE, ActionResult, TransportRequest, roster_entry, six_band,
)
from dial_eq_model import DERIVED_EQ_IDS, eq_fields
from dial_values import is_int

# The longest wait a rate-limited reply may ask for, in seconds.
RETRY_AFTER_MAX_S = 3600


# ---- intents ------------------------------------------------------------------


@dataclass(frozen=True)
class Intent:
    kind: str                         # the TransportRequest kind this records
    name: str                         # the appliance's intent name
    args: Mapping
    extra_body: Mapping | None = None


def output_set(output_id: str, *, selected: bool, volume: int | None = None) -> Intent:
    """Enable or disable a speaker, or set its level."""
    args: dict = {"id": output_id, "selected": bool(selected)}
    if volume is not None:
        args["volume"] = int(volume)
    return Intent("output_set", "outputs.set", args)


def output_resume(output_id: str) -> Intent:
    """Play again a speaker that paused itself."""
    return Intent("output_resume", "outputs.resume", {"id": output_id})


def eq_set(gains: Mapping[str, float]) -> Intent:
    return Intent("eq_set", "output.eq.set", {"fields": [[name, value] for name, value in eq_fields(gains)]})


def replay_seek() -> Intent:
    """Start the held recording, or restart a running replay, from the beginning."""
    return Intent("seek", "repeat.seek", {"position": 0})


def replay_stop() -> Intent:
    return Intent("stop", "repeat.transport", {"action": "stop"})


def repeat_arm(armed: bool) -> Intent:
    return Intent("arm", "repeat.arm", {"armed": bool(armed)})


# ---- checks -------------------------------------------------------------------

# The repeat states each kind of request acts from.
REPEAT_STATES = {
    "seek": ("replaying", "hold"),
    "stop": ("replaying",),
    "arm": ("recording", "pending", "idle"),
}


def appliance_refusal(roster, appliance_id: str, capability: str) -> ActionResult | None:
    """Why a request needing *capability* cannot go to *appliance_id*, or
    None. The capability is the appliance's own state, which has every
    capability or none (one protocol)."""
    entry = roster_entry(roster, appliance_id)
    if entry is None:
        return ActionResult(False, "unknown_appliance")
    if not getattr(entry, capability, False):
        return ActionResult(False, "no_capability")
    if entry.auth == AUTH_UNAUTHORIZED:
        return ActionResult(False, "unauthorized")
    return None


def repeat_refusal(roster, appliance_id: str, kind: str) -> ActionResult | None:
    """Why a replay or repeat request of *kind* ("seek", "stop" or "arm")
    cannot go to *appliance_id*, or None when it can: the appliance must be
    known, repeat-capable and not have refused this dial, hold a usable
    record, and have that record in a state the kind acts from."""
    refusal = appliance_refusal(roster, appliance_id, "repeat_capable")
    if refusal is not None:
        return refusal
    record = getattr(roster_entry(roster, appliance_id), "repeat", None)
    if record is None or not record.available:
        return ActionResult(False, "no_record")
    if record.state not in REPEAT_STATES[kind]:
        return ActionResult(False, "wrong_state")
    return None


def output_row(outputs, appliance_id: str, output_id):
    """The row for *output_id* among *outputs*, or None unless the outputs
    held are this appliance's."""
    if outputs is None or outputs.appliance_id != appliance_id:
        return None
    return next((r for r in outputs.rows if r.id == output_id), None)


def row_refusal(row) -> ActionResult | None:
    """A speaker row that is not held, or that another appliance has taken,
    cannot be set."""
    if row is None or row.remote_in_use:
        return ActionResult(False, "wrong_state")
    return None


def pin_refusal(pin) -> ActionResult | None:
    """A PIN is four to eight digits."""
    if not (isinstance(pin, str) and PIN_RE.match(pin)):
        return ActionResult(False, "wrong_state")
    return None


def output_shown(row, selected, volume, *, pin: bool) -> tuple[bool, int | None]:
    """What a speaker request shows until the appliance's state catches up:
    on for a PIN, else the *selected* given (a bool) or the row's; and the
    *volume* given (an int, not a bool), else the row's. A speaker switched on
    without a level shows none: the appliance starts it at its configured
    start level, which the row's old level is not."""
    shown_selected = True if pin else (selected if isinstance(selected, bool) else row.selected)
    if is_int(volume):
        return shown_selected, volume
    if shown_selected and not row.selected:
        return shown_selected, None
    return shown_selected, row.volume


# The intents the HD page may send, each with what it needs of the appliance
# and the kind of request it records (None: it records nothing).
INTENTS = {
    "outputs.set": ("dial_outputs", "output_set"),
    "output.pin.submit": ("dial_outputs", "output_pin"),
    "outputs.save_default": ("dial_outputs", None),
    "outputs.resume": ("dial_outputs", None),
    "output.eq.set": ("dial_eq", None),
    "output.eq.reset": ("dial_eq", None),
    "repeat.arm": ("repeat_capable", "arm"),
    "repeat.seek": ("repeat_capable", "seek"),
    "repeat.transport": ("repeat_capable", "stop"),
}
# The intents `submit_intent` forwards; any other name is refused without a request.
SUBMIT_INTENTS = frozenset(INTENTS)
# The page is sent the appliance's or the library's name where one says the
# same as the dial's own reason.
REFUSAL_NAMES = {"unauthorized": "dial_not_authorized", "no_capability": "protocol_mismatch"}


def intent_refusal(roster, outputs, focused_id, appliance_id: str, name: str, args: dict) -> ActionResult | None:
    """Why the HD page's intent *name* cannot go to *appliance_id*, or None:
    the appliance and its capability, then that it is the focused appliance,
    then the repeat record (a repeat intent) or the speaker row and, for a
    PIN, its shape. The caller holds the lock the values were read under."""
    capability, kind = INTENTS[name]
    refusal = appliance_refusal(roster, appliance_id, capability)
    if refusal is not None:
        return refusal
    if appliance_id != focused_id:
        return ActionResult(False, "wrong_state")
    if kind in REPEAT_STATES:
        return repeat_refusal(roster, appliance_id, kind)
    if kind in OUTPUT_KINDS:
        refusal = row_refusal(output_row(outputs, appliance_id, args.get("id")))
        if refusal is not None:
            return refusal
        if kind == "output_pin":
            return pin_refusal(args.get("pin"))
    return None


def intent_record(outputs, appliance_id: str, name: str, args: dict):
    """(lane, kind, output_id, shown) recording the intent *name*, or None for
    an intent with no request record. The checks have passed."""
    kind = INTENTS[name][1]
    if kind is None:
        return None
    if kind in REPEAT_STATES:
        return "transport", kind, None, None
    row = output_row(outputs, appliance_id, args.get("id"))
    if kind == "output_pin":
        shown = output_shown(row, None, None, pin=True)
    else:
        shown = output_shown(row, args.get("selected"), args.get("volume"), pin=False)
    return "outputs_request", kind, row.id, shown


def eq_band_ids(held) -> tuple:
    """The band ids a set may name given the EQ state held: bass and treble
    always, and the appliance's own bands once a six-band reading has
    landed."""
    if held is None or not six_band(held.capability_version):
        return DERIVED_EQ_IDS
    return DERIVED_EQ_IDS + tuple(b.id for b in held.bands if b.id not in DERIVED_EQ_IDS)


# ---- replies ------------------------------------------------------------------


def retry_after(reply) -> int:
    """The whole seconds a reply asks the sender to wait: a non-negative
    count held to RETRY_AFTER_MAX_S, 0 when there is none."""
    value = getattr(reply, "retry_after_s", None)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        return 0
    return min(RETRY_AFTER_MAX_S, math.ceil(value))


def fold_reply(request: TransportRequest, reply, now: float) -> TransportRequest:
    """*request* as its reply leaves it. An ok reply makes it accepted and
    keeps its shown value (see Waiting). Anything else makes it rejected with
    the appliance's own error name, or the library's for a transport outcome
    (unreachable, timeout, bad_reply, backoff, protocol_mismatch), and drops
    the shown value so the screen goes back at once. A rate limit also
    carries the seconds it asks for. A wrong PIN after which the speaker
    shows a new one (the reply says new_pin) is rejected as pin_invalid_new."""
    if reply.ok:
        return dataclasses.replace(request, state="accepted", changed_at=now, error=None, retry_after_s=0)
    error = reply.error or "bad_reply"
    result = getattr(reply, "result", None)
    if isinstance(result, Mapping) and result.get("pin_invalid") is True and result.get("new_pin") is True:
        # A wrong PIN sent with its switch-on: the speaker now shows a new PIN
        error = "pin_invalid_new"
    return dataclasses.replace(
        request, state="rejected", changed_at=now, error=error, shown=None,
        retry_after_s=retry_after(reply) if error == "rate_limited" else 0,
    )


# ---- settling -------------------------------------------------------------------


@dataclass(frozen=True)
class Waiting:
    """An accepted request whose shown value is kept until the appliance's own
    state has caught up with it."""
    appliance_id: str
    token: float                      # the request's token
    boot: str | None                  # the appliance's boot the reply came from
    version: int                      # the store version the reply was made at
    unit_id: str | None = None        # the speaker an output request was for
    failure_seq: int = 0              # the latest start failure's number when the reply came


def _outputs(snapshot) -> Mapping:
    outputs = snapshot.parts.get("outputs") if snapshot is not None else None
    return outputs if isinstance(outputs, Mapping) else {}


def _failure_seq(snapshot) -> int:
    failure = _outputs(snapshot).get("start_failure")
    seq = failure.get("seq") if isinstance(failure, Mapping) else 0
    return seq if is_int(seq) else 0


def wait_for(request: TransportRequest, reply, snapshot) -> Waiting | None:
    """What an accepted request waits for, or None when there is nothing to
    wait for: it shows no value, or the reply carries no version."""
    if request.shown is None or not isinstance(getattr(reply, "version", None), int):
        return None
    unit = request.output_id if request.kind in ("output_set", "output_pin") else None
    return Waiting(request.appliance_id, request.requested_at, reply.boot, reply.version,
                   unit, _failure_seq(snapshot))


def settled(waiting: Waiting, snapshot) -> bool:
    """Whether the appliance's own state has overtaken the request. True when
    the appliance has a new boot, or the snapshot has reached the reply's
    version, except that a speaker still starting holds the value until its
    availability moves on or a start failure for it arrives (a start can take
    longer than the appliance waits for it, so its reply comes before the
    speaker's change)."""
    if snapshot is None:
        return False
    if waiting.boot is not None and snapshot.boot is not None and snapshot.boot != waiting.boot:
        return True
    if snapshot.version < waiting.version:
        return False
    if waiting.unit_id is None:
        return True
    failure = _outputs(snapshot).get("start_failure")
    if (isinstance(failure, Mapping) and failure.get("unit_id") == waiting.unit_id
            and _failure_seq(snapshot) > waiting.failure_seq):
        return True
    for u in _outputs(snapshot).get("units") or ():
        if isinstance(u, Mapping) and u.get("id") == waiting.unit_id:
            return u.get("availability") != "starting"
    return True


# ---- the lane --------------------------------------------------------------------


@dataclass(frozen=True)
class LaneItem:
    appliance_id: str
    kind: str                         # the request kind, or "fetch"
    name: str = ""                    # the intent to send; unused for a fetch
    args: Mapping | None = None
    extra_body: Mapping | None = None
    token: float = 0.0
    parts: tuple = ()                 # the parts a fetch reads


_STOP = object()


class RequestLane:
    """One thread, one queue. An item is sent through the appliance's client
    and the outcome handed to *on_done*: a PeerReply for a request, the
    merged parts (or None) for a fetch. *get_client* maps an appliance id to
    its client, or None when it has none; *on_done* is called with no lock of
    the lane held, and may raise without ending the thread."""

    def __init__(self, get_client: Callable[[str], object | None],
                 on_done: Callable[[LaneItem, object], None], *, name: str = "requests") -> None:
        self._get_client = get_client
        self._on_done = on_done
        self._name = name
        self._queue: queue.SimpleQueue = queue.SimpleQueue()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, daemon=True, name=self._name)
        self._thread.start()

    def stop(self) -> None:
        self._queue.put(_STOP)
        thread, self._thread = self._thread, None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=5.0)

    def enqueue(self, item: LaneItem) -> None:
        """Queue *item*. Returns at once."""
        self._queue.put(item)

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            if item is _STOP:
                return
            try:
                result = self._send(item)
            except Exception:
                logging.warning("dial requests: a send raised", exc_info=True)
                continue
            try:
                self._on_done(item, result)
            except Exception:
                logging.warning("dial requests: a result handler raised", exc_info=True)

    def _send(self, item: LaneItem):
        client = self._get_client(item.appliance_id)
        if item.kind == "fetch":
            return client.fetch(list(item.parts), merge=True) if client is not None else None
        if client is None:
            return PeerReply(False, "unreachable", None, None, {}, None)
        return client.submit(item.name, dict(item.args or {}), extra_body=item.extra_body)
