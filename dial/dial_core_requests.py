"""dial_core_requests.py -- what the dial asks of an appliance, and how it hears back.

Three parts, none of which touches the core's state:

  * the intents the dial's controls send (a name, its arguments and the extra
    request body), one builder per kind of request;
  * folding an appliance's reply into the request record the screens read
    (TransportRequest), and the rule that says when an accepted request has
    been overtaken by the appliance's own state, so its shown value can go;
  * RequestLane, one thread that sends the screens' requests, and the reads
    that refresh a replay position, one at a time.

The lane carries no HD page intent and no artwork: those never wait behind
a slow request.

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

from dial_core_state import TransportRequest
from dial_eq_model import eq_fields
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


def output_set(output_id: str, *, selected: bool, volume: int | None = None, pin_entry: bool = False) -> Intent:
    """Enable or disable a speaker, or set its level. *pin_entry* says the
    caller can show a keypad, so the appliance may ask this dial for a PIN."""
    args: dict = {"id": output_id, "selected": bool(selected)}
    if volume is not None:
        args["volume"] = int(volume)
    return Intent("output_set", "outputs.set", args, {"pin_capable": True} if pin_entry else None)


def output_pin(output_id: str, pin: str) -> Intent:
    """A PIN for a speaker. It is always sent as one this dial can answer."""
    return Intent("output_pin", "output.pin.submit", {"id": output_id, "pin": pin}, {"pin_capable": True})


def eq_set(gains: Mapping[str, float]) -> Intent:
    return Intent("eq_set", "output.eq.set", {"fields": [[name, value] for name, value in eq_fields(gains)]})


def replay_seek() -> Intent:
    """Start the held recording, or restart a running replay, from the beginning."""
    return Intent("seek", "repeat.seek", {"position": 0})


def replay_stop() -> Intent:
    return Intent("stop", "repeat.transport", {"action": "stop"})


def repeat_arm(armed: bool) -> Intent:
    return Intent("arm", "repeat.arm", {"armed": bool(armed)})


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
    carries the seconds it asks for."""
    if reply.ok:
        return dataclasses.replace(request, state="accepted", changed_at=now, error=None, retry_after_s=0)
    error = reply.error or "bad_reply"
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
