"""autostream_state.outputs -- the output authority.

One object owns what the speakers should be doing (desired) and what the
player says they are doing (reported), publishes both as the "outputs" part of
the state snapshot, and is the only writer of speaker selection and volume
once its callers move to it.

Threads (started mode, which production uses):

  outputs-authority  the worker: takes queued events, reads the player's
                     output list when something changed (or every minute,
                     whatever is said), merges what it reads, runs timers.
  outputs-apply      the only thread that writes to the player. Writes are
                     built from the desired state at the moment they are
                     taken, so a stalled player never receives a stale level.
  outputs-events     the event source (owned and described in
                     autostream_backend_events); it only enqueues.

A speaker's mute (the level it returns to) is part of the desired state and
lives in the memory of the process only; the end of a session clears every
mute.

Without threads (tests, and before start()), an intent runs its write on the
calling thread once the desired change has been published, and reads happen
when step() or merge_for_tests() is called.

Lock order (outermost first):

  _apply_lock  ->  _lock  ->  the state store's lock (a leaf)

_lock guards desired state, the units and the snapshot rebuild; it is never
held across a call to the player, a subscriber, the settings store or a log
call. _apply_lock is taken by the apply thread (or by the caller in
unstarted mode) and never while _lock is held. Subscribers are told after
every lock is released.
"""
from __future__ import annotations

import concurrent.futures
import logging
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol, Sequence

import autostream_player_service as player_service
import autostream_runtime as runtime
from autostream_backend_events import (
    DEGRADED,
    ConnectInfo,
    DeviceEvent,
    EventSource,
    PollEventSource,
    create_event_source,
)
from autostream_players import (
    ActionResult,
    BackendCapabilities,
    EventChannelInfo,
    ListOutputsResult,
    OutputInfo,
)

from .origin import Origin
from .parts import OutputsPart, OutputUnitView, StartFailure
from .store import store

LOG = logging.getLogger("autostream.outputs")

READ_TIMEOUT_S = 10.0
WRITE_TIMEOUT_S = 3.0
SAFETY_READ_S = 60.0
START_PENDING_S = 120.0
DEBOUNCE_S = 2.0
DEVICE_VOLUME_MARK_S = 2.0
ABSENT_KEEP_S = 60.0
PROBE_INTERVAL_S = 60.0
RETRY_MIN_S = 10.0
RETRY_MAX_S = 60.0
_READ_BACKOFF_S = (0.5, 1.0, 2.0, 5.0)
_FAILED_READS_BEFORE_DOWN = 3

# Threads start only when this is true; the test configuration turns it off
# once, so that a test which runs the process bootstrap gets an authority
# without threads.
_threads_allowed = True

# A write that has nothing to send yet and waits for a later read.
_HOLD = object()

# Called as fn(unit_id, claimant) when a speaker asks for a PIN after the
# request that switched it on has stopped waiting. The module that owns PIN
# pairing installs it; the authority only knows there may be one.
_pin_claim_handler: Optional[Callable[[str, str], None]] = None


def set_pin_claim_handler(fn: Optional[Callable[[str, str], None]]) -> None:
    global _pin_claim_handler
    _pin_claim_handler = fn


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class WriteOutcome:
    ok: bool
    error_code: str = ""              # the player's ActionResult.error_code ("timeout" for a request timeout)
    error: str = ""                   # the player's message
    pending: bool = False             # the start timed out, or the caller's wait expired first


@dataclass(frozen=True)
class Applied:
    version: int                                       # store version with the desired change
    outcome: Optional["concurrent.futures.Future"]     # one WriteOutcome per write; None: no write
    refused: Optional[str] = None                      # "unknown_output", "not_connected", "no_active_outputs"
    master: Optional[int] = None                       # volume and mute intents: the master level the request leaves
    muted: Optional[bool] = None                       # volume and mute intents: whether the selection is muted after it
    restored: bool = False                             # a volume step that was a restore from mute


def wait_outcome(applied: Applied, wait: float) -> tuple:
    """The outcomes of an intent's writes within *wait* seconds. When the
    future is not done by then (the apply thread is still on earlier writes,
    each bounded by WRITE_TIMEOUT_S, behind the player's one HTTP worker),
    returns one WriteOutcome(ok=True, pending=True) per expected write; the
    future stays alive and the apply thread records the real outcome when it
    comes. A caller replies to pending exactly as to a pending start."""
    future = applied.outcome
    if future is None:
        return ()
    try:
        return future.result(timeout=max(0.0, wait))
    except concurrent.futures.TimeoutError:
        abandon = getattr(future, "abandon", None)
        if abandon is not None and not abandon():
            # The outcome landed between the timeout and now.
            return future.result(timeout=0)
        expected = getattr(future, "expected", 1)
        LOG.debug("Output write still pending after %.1fs; replying as pending", wait)
        return tuple(WriteOutcome(ok=True, pending=True) for _ in range(expected))


# ---------------------------------------------------------------------------
# The backend the authority talks to
# ---------------------------------------------------------------------------

class OutputBackend(Protocol):
    base_url: str

    def list_outputs(self, timeout: float) -> ListOutputsResult: ...

    def update_output(self, output_id: str, **fields) -> ActionResult: ...

    def set_selected_outputs(self, ids: list, timeout: float) -> ActionResult: ...

    def stop_and_disable_all(self, timeout: float) -> ActionResult: ...

    def submit_output_pin(self, output_id: str, pin: str, timeout: float) -> ActionResult: ...

    def refresh_runtime_state(self, timeout: float) -> ActionResult: ...

    def capabilities(self) -> BackendCapabilities: ...

    def event_channel_info(self) -> EventChannelInfo: ...


class PlayerServiceBackend:
    """The production backend: every method calls the player service function
    of the same name, looked up on the module at call time."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url

    def list_outputs(self, timeout: float) -> ListOutputsResult:
        return player_service.list_outputs(self.base_url, timeout=timeout)

    def update_output(self, output_id: str, **fields) -> ActionResult:
        return player_service.update_output(self.base_url, output_id, **fields)

    def set_selected_outputs(self, ids: list, timeout: float) -> ActionResult:
        return player_service.set_selected_outputs(self.base_url, ids, timeout=timeout)

    def stop_and_disable_all(self, timeout: float) -> ActionResult:
        return player_service.stop_and_disable_all(self.base_url, timeout=timeout)

    def submit_output_pin(self, output_id: str, pin: str, timeout: float) -> ActionResult:
        return player_service.submit_output_pin(self.base_url, output_id, pin, timeout=timeout)

    def refresh_runtime_state(self, timeout: float) -> ActionResult:
        return player_service.refresh_runtime_state(self.base_url, timeout=timeout)

    def capabilities(self) -> BackendCapabilities:
        return player_service.get_capabilities(self.base_url)

    def event_channel_info(self) -> EventChannelInfo:
        return player_service.event_channel_info(self.base_url)


# ---------------------------------------------------------------------------
# Internal state
# ---------------------------------------------------------------------------

@dataclass
class UnitDesired:
    selected: bool
    volume: int                       # the level at the speaker: 0 while muted
    muted: bool
    remembered_level: Optional[int]   # the level a muted speaker returns to; None: the default
    cause: Origin
    changed_at: float


@dataclass
class UnitState:
    id: str
    name: str
    desired: UnitDesired
    reported: Optional[OutputInfo]
    seen_at: float
    availability: str = "ok"
    retry_at: Optional[float] = None
    retry_backoff: float = RETRY_MIN_S
    device_volume_at: float = 0.0
    own_write_at: float = 0.0
    was_streaming: bool = False
    absent_since: Optional[float] = None
    start_pending_until: float = 0.0
    desired_seq: int = 0
    retry_allowed: bool = False
    failure_reported: bool = False
    attempt: bool = False             # a start made by the authority has not yet shown its result
    after_boot: bool = False          # the player restarted since this unit last matched
    diff_since: dict = field(default_factory=dict)
    requester: Optional[str] = None   # who asked for the current attempt


class _OwnedLock:
    """A lock that knows its holder, so that a test (and the rule that no
    player call is made under the authority lock) can ask."""

    __slots__ = ("_lock", "_owner")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._owner: Optional[int] = None

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        ok = self._lock.acquire(blocking, timeout)
        if ok:
            self._owner = threading.get_ident()
        return ok

    def release(self) -> None:
        self._owner = None
        self._lock.release()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc) -> None:
        self.release()

    def locked(self) -> bool:
        return self._lock.locked()

    def held_by_current_thread(self) -> bool:
        return self._owner == threading.get_ident()


class _Batch:
    """Collects the outcome of each write of one intent and completes a
    Future with all of them, in the order the writes were made."""

    def __init__(self, count: int) -> None:
        self.future: "concurrent.futures.Future" = concurrent.futures.Future()
        self.future.expected = count  # type: ignore[attr-defined]
        self._results: list = [None] * count
        self._left = count
        self._abandoned = False
        self._lock = threading.Lock()  # a leaf
        self.future.abandon = self.abandon  # type: ignore[attr-defined]

    def abandon(self) -> bool:
        """The caller stops waiting. False when every outcome is already in."""
        with self._lock:
            if self._left == 0:
                return False
            self._abandoned = True
            return True

    def done(self, index: int, outcome: WriteOutcome) -> bool:
        """Record one outcome. True when the caller had already stopped
        waiting for this batch."""
        with self._lock:
            if self._results[index] is not None:
                return False
            self._results[index] = outcome
            self._left -= 1
            finished = self._left == 0
            gone = self._abandoned
        if finished:
            self.future.set_result(tuple(self._results))
        return gone


@dataclass
class _Write:
    kind: str                         # select | deselect | volume | deselect_all | pin | reapply
    unit_id: Optional[str]
    seq: int                          # the unit's desired_seq when the write was queued
    params: dict
    sinks: list                       # (batch, index) pairs waiting for the outcome
    requester: Optional[str] = None   # who asked, as the intent named them
    claimant: Optional[str] = None    # the identity that can enter a PIN for the speaker


class _Effects:
    """What a locked block wants done once the locks are released: log
    lines (nothing logs under a lock) and the now-playing republish request."""

    __slots__ = ("logs", "republish")

    def __init__(self) -> None:
        self.logs: list = []
        self.republish = False

    def log(self, level: int, text: str, *args) -> None:
        self.logs.append((level, text, args))

    def run(self) -> None:
        for level, text, args in self.logs:
            LOG.log(level, text, *args)
        if self.republish:
            runtime.request_nowplaying_republish()


def _clamp(value, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, int(value)))


# ---------------------------------------------------------------------------
# The authority
# ---------------------------------------------------------------------------

class OutputAuthority:
    def __init__(self, *, clock: Callable[[], float] = time.monotonic,
                 wall: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._wall = wall
        self._writer = store().claim("outputs", "autostream_state.outputs")
        self._wq_lock = threading.Lock()  # a leaf: guards the write queue
        self._wq_cond = threading.Condition(self._wq_lock)
        self._init_fields()

    def _init_fields(self) -> None:
        self._lock = _OwnedLock()
        self._apply_lock = _OwnedLock()
        self._backend: OutputBackend = PlayerServiceBackend("http://localhost:3689")
        self._units: dict = {}
        self._row_order: list = []
        self._connected = False
        self._backend_boot = ""
        self._event_kind = "poll"
        self._mute_held = False
        self._silence_chosen = False
        self._start_failure: Optional[StartFailure] = None
        self._failure_seq = 0
        self._session_active = False
        self._rows_carry_session = False
        self._include_tv_supported = False
        self._delivers_device_events = False
        self._inflight = 0
        self._exempt_off = False
        self._policy = None
        self._include_tv_reader: Callable[[str], Optional[bool]] = lambda unit_id: None
        # Worker-side bookkeeping.
        self._items: "queue.Queue" = queue.Queue()
        with self._wq_cond:
            self._wq: list = []
            self._stopping = False
        self._dirty = False
        self._retry_n = 0
        self._fail_count = 0
        self._read_retry_at = 0.0
        self._next_safety_read: Optional[float] = None
        self._boot_id: Optional[str] = None
        self._boot_changed = False
        self._epoch = 0
        self._ever_connected = False
        self._source: Optional[EventSource] = None
        self._source_factory = create_event_source
        self._last_probe: Optional[float] = None
        self._force_probe = False
        self._events_enabled = False
        self._started = False
        self._threads: list = []
        self._touched = False

    # -- lifecycle -----------------------------------------------------------

    def start(self, backend: OutputBackend) -> None:
        """Begin serving. Starts the worker and apply threads when threads are
        allowed; makes no call to the player (the first read, and the choice of
        event source, are the worker's)."""
        self._touched = True
        self._backend = backend
        self._dirty = True
        if not _threads_allowed or self._started:
            return
        with self._wq_cond:
            self._stopping = False
        self._started = True
        self._events_enabled = True
        for name, target in (("outputs-authority", self._worker_loop), ("outputs-apply", self._apply_loop)):
            t = threading.Thread(target=target, name=name, daemon=True)
            self._threads.append(t)
            t.start()

    def set_backend(self, backend: OutputBackend) -> None:
        """The player's address changed (a configuration reload): read again,
        and choose the event source again."""
        self._touched = True
        self._backend = backend
        self._dirty = True
        self._force_probe = True

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the threads, giving them *timeout* seconds in all. A write in
        flight is not interrupted; writes still queued are dropped."""
        self._touched = True
        deadline = time.monotonic() + max(0.0, timeout)
        with self._wq_cond:
            self._stopping = True
            dropped = self._wq
            self._wq = []
            self._wq_cond.notify_all()
        for w in dropped:
            self._complete(w, WriteOutcome(ok=False, error_code="stopped", error="stopping"))
        self._items.put(("stop", None))
        source = self._source
        self._source = None
        if source is not None:
            try:
                source.stop(timeout=min(2.0, max(0.1, deadline - time.monotonic())))
            except Exception:
                LOG.debug("Event source stop failed", exc_info=True)
        for t in self._threads:
            if t is not threading.current_thread():
                t.join(max(0.0, deadline - time.monotonic()))
        self._threads = [t for t in self._threads if t.is_alive()]
        self._started = bool(self._threads)

    @property
    def base_url(self) -> str:
        """The address of the player the authority is serving."""
        return self._backend.base_url

    def set_policy(self, policy) -> None:
        self._touched = True
        self._policy = policy

    def set_include_tv_reader(self, fn: Callable[[str], Optional[bool]]) -> None:
        self._touched = True
        self._include_tv_reader = fn

    # -- tests ---------------------------------------------------------------

    def install_locks_for_tests(self, *, apply_lock, lock) -> None:
        self._touched = True
        self._apply_lock = apply_lock
        self._lock = lock

    def _lock_held_by_current_thread(self) -> bool:
        probe = getattr(self._lock, "held_by_current_thread", None)
        return bool(probe and probe())

    def reset_for_tests(self) -> None:
        """Back to the state of a process that has not started. A few clears;
        returns at once when nothing touched the authority."""
        if not self._touched:
            return
        self.stop(timeout=2.0)
        self._init_fields()

    def merge_for_tests(self, rows: Sequence[OutputInfo], *, connected: bool = True,
                        boot: Optional[str] = None, now: Optional[float] = None) -> None:
        """A successful read of *rows*, through the same merge the worker uses."""
        self._touched = True
        if now is None:
            now = self._clock()
        if boot is not None:
            self._note_boot(boot)
        self._on_read_ok(list(rows), now)
        if not connected:
            self.mark_unreachable_for_tests()

    def mark_unreachable_for_tests(self) -> None:
        """Three failed reads."""
        self._touched = True
        now = self._clock()
        for _ in range(_FAILED_READS_BEFORE_DOWN):
            self._on_read_failed(ListOutputsResult(ok=False, error="unreachable", error_code="request_failed"), now)
        with self._lock:
            pending = self._publish_locked(Origin.BACKEND, None)
        pending.notify()

    # -- reading the state ---------------------------------------------------

    def _ordered_units_locked(self) -> list:
        seen = set()
        out = []
        for uid in self._row_order:
            u = self._units.get(uid)
            if u is not None and uid not in seen:
                seen.add(uid)
                out.append(u)
        for uid, u in self._units.items():
            if uid not in seen:
                out.append(u)
        return out

    def _selected_locked(self) -> list:
        return [u for u in self._ordered_units_locked() if u.desired.selected]

    def _muted_all_locked(self) -> bool:
        selected = [u for u in self._units.values() if u.desired.selected]
        if selected:
            return all(u.desired.muted for u in selected)
        return self._mute_held

    def _master_locked(self) -> Optional[int]:
        """The level the selected speakers stand at, as a dial shows it: the
        mean of their intended levels, rounded up."""
        levels = [
            _clamp(u.desired.remembered_level if u.desired.muted and u.desired.remembered_level is not None
                   else u.desired.volume)
            for u in self._selected_locked()
        ]
        if not levels:
            return None
        return -(-sum(levels) // len(levels))

    def _build_part_locked(self) -> OutputsPart:
        views = []
        for u in self._ordered_units_locked():
            d = u.desired
            level = d.remembered_level if d.muted and d.remembered_level is not None else d.volume
            name = u.reported.name if u.reported is not None else u.name
            views.append(OutputUnitView(
                id=u.id, name=name, selected=d.selected, volume=level, muted=d.muted,
                availability=u.availability, cause=d.cause, reported=u.reported,
            ))
        return OutputsPart(
            units=tuple(views), connected=self._connected, backend_boot=self._backend_boot,
            event_source=self._event_kind, muted_all=self._muted_all_locked(),
            silence_chosen=self._silence_chosen, start_failure=self._start_failure,
        )

    def _publish_locked(self, origin: Optional[Origin], requester: Optional[str]):
        """Phase one of a publish, under _lock. The caller notifies once every
        lock is released."""
        return self._writer.publish(self._build_part_locked(), origin=origin, requester=requester)

    def _refused(self, reason: str) -> Applied:
        return Applied(version=store().snapshot().version, outcome=None, refused=reason)

    def unit_for_device(self, device_id: str) -> Optional[str]:
        """The unit a device id belongs to: the unit's own id. The player
        reports an event under the id of the row that plays the device."""
        with self._lock:
            return self._unit_for_device_locked(device_id)

    def _unit_for_device_locked(self, device_id: str) -> Optional[str]:
        return device_id if device_id in self._units else None

    # -- intents -------------------------------------------------------------

    def _stamp(self, u: UnitState, cause: Origin, now: float) -> None:
        u.desired.cause = cause
        u.desired.changed_at = now
        u.desired_seq += 1

    def _enqueue(self, w: _Write) -> None:
        with self._wq_cond:
            if w.kind == "volume":
                for queued in self._wq:
                    if queued.kind == "volume" and queued.unit_id == w.unit_id:
                        queued.sinks.extend(w.sinks)
                        queued.seq = w.seq
                        self._wq_cond.notify()
                        return
            self._wq.append(w)
            self._wq_cond.notify()

    def _finish_intent(self, pending, future, **extra) -> Applied:
        pending.notify()
        self._after_intent()
        return Applied(version=pending.version, outcome=future, **extra)

    def _after_intent(self) -> None:
        """Without threads, run the queued writes here, with no lock held."""
        if not self._started:
            self._drain_inline()

    def select(self, unit_id: str, cause: Origin, *, volume: Optional[int] = None,
               offset_ms: Optional[int] = None, mode: Optional[str] = None,
               requester: Optional[str] = None, claimant: Optional[str] = None) -> Applied:
        self._touched = True
        now = self._clock()
        vol = None if volume is None else _clamp(volume)
        with self._lock:
            u = self._units.get(unit_id)
            if u is None:
                return self._refused("unknown_output")
            d = u.desired
            if self._muted_all_locked():
                # Joining a muted session: silent, and the level asked for is
                # what a later restore brings it to.
                d.remembered_level = (vol or d.volume) or None
                d.muted = True
                d.volume = 0
            elif vol is not None:
                d.volume = vol
            d.selected = True
            u.retry_allowed = cause != Origin.USER
            u.attempt = True
            u.failure_reported = False
            u.start_pending_until = 0.0
            u.retry_at = None
            u.retry_backoff = RETRY_MIN_S
            u.diff_since.clear()
            u.requester = requester
            self._stamp(u, cause, now)
            batch = _Batch(1)
            self._enqueue(_Write(
                "select", unit_id, u.desired_seq,
                {"volume": vol, "offset_ms": offset_ms, "mode": mode, "cause": cause},
                [(batch, 0)], requester=requester, claimant=claimant,
            ))
            pending = self._publish_locked(cause, requester)
        return self._finish_intent(pending, batch.future)

    def _deselect_locked(self, u: UnitState, cause: Origin, now: float) -> None:
        d = u.desired
        d.selected = False
        d.muted = False
        d.remembered_level = None
        u.attempt = False
        u.retry_at = None
        u.start_pending_until = 0.0
        u.failure_reported = False
        u.diff_since.clear()
        self._stamp(u, cause, now)

    def deselect(self, unit_id: str, cause: Origin, *, requester: Optional[str] = None) -> Applied:
        self._touched = True
        now = self._clock()
        with self._lock:
            u = self._units.get(unit_id)
            if u is None:
                return self._refused("unknown_output")
            self._deselect_locked(u, cause, now)
            if cause in (Origin.USER, Origin.POLICY, Origin.DEVICE) and not self._selected_locked():
                self._silence_chosen = True
            batch = _Batch(1)
            self._enqueue(_Write("deselect", unit_id, u.desired_seq, {}, [(batch, 0)]))
            pending = self._publish_locked(cause, requester)
        return self._finish_intent(pending, batch.future)

    def deselect_all(self, cause: Origin, *, requester: Optional[str] = None) -> Applied:
        self._touched = True
        now = self._clock()
        with self._lock:
            for u in self._units.values():
                if u.desired.selected or u.desired.muted:
                    self._deselect_locked(u, cause, now)
            if cause in (Origin.USER, Origin.POLICY, Origin.DEVICE):
                self._silence_chosen = True
            if cause == Origin.SESSION:
                self._mute_held = False
            batch = _Batch(1)
            self._enqueue(_Write(
                "deselect_all", None, 0, {"session": cause == Origin.SESSION}, [(batch, 0)],
            ))
            pending = self._publish_locked(cause, requester)
        return self._finish_intent(pending, batch.future)

    def set_volume(self, unit_id: str, volume: int, cause: Origin, *,
                   requester: Optional[str] = None) -> Applied:
        self._touched = True
        now = self._clock()
        vol = _clamp(volume)
        with self._lock:
            u = self._units.get(unit_id)
            if u is None:
                return self._refused("unknown_output")
            d = u.desired
            write = True
            if d.muted:
                if cause == Origin.USER:
                    # A deliberate level change on a muted speaker is its unmute.
                    d.muted = False
                    d.remembered_level = None
                    d.volume = vol
                    self._mute_held = False
                else:
                    d.remembered_level = vol
                    write = False
            else:
                d.volume = vol
            self._stamp(u, cause, now)
            batch = None
            if write:
                batch = _Batch(1)
                self._enqueue(_Write("volume", unit_id, u.desired_seq, {}, [(batch, 0)]))
            pending = self._publish_locked(cause, requester)
        return self._finish_intent(pending, batch.future if batch is not None else None)

    def _queue_volume_writes_locked(self, units: list, cause_seq_units: bool = True):
        """One volume write per unit, as one batch. Returns the batch's future,
        or None when there is nothing to write."""
        if not units:
            return None
        batch = _Batch(len(units))
        for index, u in enumerate(units):
            self._enqueue(_Write("volume", u.id, u.desired_seq, {}, [(batch, index)]))
        return batch.future

    def _unmute_all_locked(self, cause: Origin, default_level: int, now: float) -> list:
        """The restore half of mute and of a volume step while muted; returns
        the units whose level moves."""
        changed = []
        level = _clamp(default_level)
        for u in self._selected_locked():
            d = u.desired
            if d.muted:
                d.muted = False
                d.volume = d.remembered_level if d.remembered_level is not None else level
                d.remembered_level = None
            elif d.volume == 0:
                d.volume = level
            else:
                continue
            self._stamp(u, cause, now)
            changed.append(u)
        self._mute_held = False
        return changed

    def step_volume(self, delta: int, cause: Origin, *, default_level: int,
                    requester: Optional[str] = None) -> Applied:
        self._touched = True
        now = self._clock()
        with self._lock:
            if not self._connected:
                return self._refused("not_connected")
            selected = self._selected_locked()
            if not selected:
                return self._refused("no_active_outputs")
            restored = False
            if self._muted_all_locked():
                if delta <= 0:
                    # Nothing is lower than silent; stay muted.
                    return Applied(
                        version=store().snapshot().version, outcome=None,
                        master=self._master_locked(), muted=True,
                    )
                changed = self._unmute_all_locked(cause, default_level, now)
                restored = True
                master = self._master_locked()
            else:
                audible = [u for u in selected if not u.desired.muted]
                current = round(sum(u.desired.volume for u in audible) / len(audible))
                new_master = _clamp(current + int(delta))
                master = new_master
                changed = []
                for u in audible:
                    d = u.desired
                    new = new_master if current == 0 else _clamp(round(d.volume * new_master / current))
                    if new != d.volume:
                        d.volume = new
                        self._stamp(u, cause, now)
                        changed.append(u)
            future = self._queue_volume_writes_locked(changed)
            pending = self._publish_locked(cause, requester)
        return self._finish_intent(pending, future, master=master, muted=False, restored=restored)

    def mute_all(self, cause: Origin, *, requester: Optional[str] = None) -> Applied:
        self._touched = True
        now = self._clock()
        with self._lock:
            if not self._connected:
                return self._refused("not_connected")
            selected = self._selected_locked()
            if not selected:
                return self._refused("no_active_outputs")
            changed = []
            for u in selected:
                d = u.desired
                if d.muted:
                    continue
                d.remembered_level = d.volume if d.volume > 0 else None
                d.muted = True
                self._stamp(u, cause, now)
                if d.volume > 0:
                    d.volume = 0
                    changed.append(u)
            self._mute_held = True
            future = self._queue_volume_writes_locked(changed)
            master = self._master_locked()
            pending = self._publish_locked(cause, requester)
        return self._finish_intent(pending, future, master=master, muted=True)

    def unmute_all(self, cause: Origin, *, default_level: int,
                   requester: Optional[str] = None) -> Applied:
        self._touched = True
        now = self._clock()
        with self._lock:
            if not self._connected:
                return self._refused("not_connected")
            if not self._selected_locked():
                return self._refused("no_active_outputs")
            changed = self._unmute_all_locked(cause, default_level, now)
            future = self._queue_volume_writes_locked(changed)
            master = self._master_locked()
            pending = self._publish_locked(cause, requester)
        return self._finish_intent(pending, future, master=master, muted=False)

    def mute(self, unit_id: str, cause: Origin, *, requester: Optional[str] = None) -> Applied:
        self._touched = True
        now = self._clock()
        with self._lock:
            u = self._units.get(unit_id)
            if u is None:
                return self._refused("unknown_output")
            d = u.desired
            changed = []
            if d.selected and not d.muted:
                d.remembered_level = d.volume if d.volume > 0 else None
                d.muted = True
                self._stamp(u, cause, now)
                if d.volume > 0:
                    d.volume = 0
                    changed.append(u)
            future = self._queue_volume_writes_locked(changed)
            pending = self._publish_locked(cause, requester)
        return self._finish_intent(pending, future)

    def unmute(self, unit_id: str, cause: Origin, *, default_level: int,
               requester: Optional[str] = None) -> Applied:
        self._touched = True
        now = self._clock()
        with self._lock:
            u = self._units.get(unit_id)
            if u is None:
                return self._refused("unknown_output")
            d = u.desired
            changed = []
            if d.muted:
                d.muted = False
                d.volume = d.remembered_level if d.remembered_level is not None else _clamp(default_level)
                d.remembered_level = None
                self._stamp(u, cause, now)
                changed.append(u)
            future = self._queue_volume_writes_locked(changed)
            pending = self._publish_locked(cause, requester)
        return self._finish_intent(pending, future)

    def submit_pin(self, unit_id: str, pin: str, *, requester: Optional[str] = None) -> Applied:
        """A write only: the PIN goes to the player, desired state is untouched."""
        self._touched = True
        batch = _Batch(1)
        self._enqueue(_Write("pin", unit_id, 0, {"pin": pin}, [(batch, 0)]))
        self._after_intent()
        return Applied(version=store().snapshot().version, outcome=batch.future)

    def reapply_selected(self, *, recovery_volume: int) -> Applied:
        """Send the desired selection again after the player restarted, and
        lift any selected speaker the restart left silent."""
        self._touched = True
        batch = _Batch(1)
        self._enqueue(_Write(
            "reapply", None, 0, {"recovery": _clamp(recovery_volume)}, [(batch, 0)],
        ))
        self._after_intent()
        return Applied(version=store().snapshot().version, outcome=batch.future)

    def note_session(self, active: bool) -> None:
        """Session edges. A session end clears the user's "silence" choice and
        the retry back-offs of speakers that failed to start."""
        self._touched = True
        with self._lock:
            self._session_active = bool(active)
            if active:
                return
            self._silence_chosen = False
            for u in self._units.values():
                u.retry_backoff = RETRY_MIN_S
                u.retry_at = None
            pending = self._publish_locked(Origin.SESSION, None)
        pending.notify()

    def device_volume_seen(self, unit_id: str) -> None:
        """A volume was set on the speaker itself: a mute on it ends at once
        (its level is whatever the speaker now reports) and the re-apply of a
        muted level is suppressed for a moment."""
        self._touched = True
        now = self._clock()
        with self._lock:
            u = self._units.get(unit_id)
            if u is None:
                return
            u.device_volume_at = now
            d = u.desired
            if not d.muted:
                return
            d.muted = False
            d.remembered_level = None
            self._mute_held = False
            if u.reported is not None:
                d.volume = u.reported.volume_percent
            self._stamp(u, Origin.DEVICE, now)
            pending = self._publish_locked(Origin.DEVICE, None)
        pending.notify()

    # -- the event sink (the event source thread; each only enqueues) ----------

    def on_connected(self, info: ConnectInfo) -> None:
        self._touched = True
        self._items.put(("connected", info))

    def on_disconnected(self, reason: str) -> None:
        self._touched = True
        self._items.put(("disconnected", reason))

    def on_outputs_changed(self) -> None:
        self._touched = True
        self._items.put(("read", None))

    def on_device_event(self, ev: DeviceEvent) -> None:
        self._touched = True
        self._items.put(("event", ev))

    # -- the worker ----------------------------------------------------------

    def _worker_loop(self) -> None:
        while True:
            try:
                if self.step(block=self._next_wait(self._clock())):
                    return
            except Exception:
                LOG.exception("Output authority iteration failed")
                time.sleep(1.0)
            with self._wq_cond:
                if self._stopping:
                    return

    def _next_wait(self, now: float) -> float:
        wait = 1.0
        if self._dirty:
            wait = min(wait, max(0.0, self._read_retry_at - now))
        if self._next_safety_read is not None:
            wait = min(wait, max(0.0, self._next_safety_read - now))
        return max(0.05, wait)

    def step(self, now: Optional[float] = None, *, block: float = 0.0) -> bool:
        """One worker iteration: take queued items, read if something changed
        or a read is due, run timers. The thread loops on it; tests call it
        directly. True when a stop was requested."""
        self._touched = True
        if now is None:
            now = self._clock()
        if self._take_items(block, now):
            return True
        self._maintain_source(now)
        read_due = (self._dirty and now >= self._read_retry_at) or (
            self._next_safety_read is not None and now >= self._next_safety_read
        )
        if read_due:
            self._read_once(now)
        self._run_timers(now)
        return False

    def _take_items(self, block: float, now: float) -> bool:
        items = []
        try:
            if block > 0:
                items.append(self._items.get(timeout=block))
            else:
                items.append(self._items.get_nowait())
            while True:
                items.append(self._items.get_nowait())
        except queue.Empty:
            pass
        stop = False
        for kind, payload in items:
            if kind == "stop":
                stop = True
            elif kind == "read":
                self._dirty = True
            elif kind == "connected":
                self._handle_connected(payload)
            elif kind == "disconnected":
                self._handle_disconnected(payload, now)
            elif kind == "event":
                self._handle_event(payload, now)
        return stop

    def _note_boot(self, boot: str) -> None:
        if self._boot_id is not None and boot != self._boot_id:
            self._boot_changed = True
        self._boot_id = boot

    def _handle_connected(self, info: ConnectInfo) -> None:
        if info.boot is not None:
            self._note_boot(info.boot)
        else:
            self._boot_id = None
        self._delivers_device_events = {"device_volume", "receiver_command"} <= set(info.capabilities)
        self._dirty = True

    def _handle_disconnected(self, reason: str, now: float) -> None:
        if reason == DEGRADED:
            LOG.info("Event channel degraded; polling the player instead")
            self._swap_source(PollEventSource(self._poll_interval), now)
            return
        with self._lock:
            for u in self._units.values():
                u.start_pending_until = 0.0
            self._exempt_off = True
        self._dirty = True

    def _poll_interval(self) -> float:
        return 2.0 if self._session_active else 5.0

    def _same_source(self, a: EventSource, b: EventSource) -> bool:
        return (
            a.kind == b.kind
            and getattr(a, "_path", None) == getattr(b, "_path", None)
            and getattr(a, "_url", None) == getattr(b, "_url", None)
        )

    def _maintain_source(self, now: float) -> None:
        """Choose the event source: on the first iteration, and again every
        minute unless a unix socket is connected. Worker thread only."""
        if not self._events_enabled:
            return
        src = self._source
        on_good_socket = src is not None and src.kind == "unix_socket" and src.connected
        due = (
            self._last_probe is None or self._force_probe
            or (now - self._last_probe >= PROBE_INTERVAL_S and not on_good_socket)
        )
        if not due:
            return
        self._last_probe = now
        self._force_probe = False
        backend = self._backend
        try:
            info = backend.event_channel_info()
        except Exception:
            LOG.debug("Event channel probe failed", exc_info=True)
            info = EventChannelInfo(kind="poll")
        new = self._source_factory(info, backend.base_url, poll_interval=self._poll_interval)
        if src is not None and self._same_source(src, new):
            return
        self._swap_source(new, now)

    def _swap_source(self, new: EventSource, now: float) -> None:
        old = self._source
        self._source = new
        with self._lock:
            self._event_kind = new.kind
            pending = self._publish_locked(Origin.BACKEND, None)
        pending.notify()
        if old is not None:
            try:
                old.stop()
            except Exception:
                LOG.debug("Event source stop failed", exc_info=True)
        try:
            new.start(self)
        except Exception:
            LOG.exception("Event source start failed")

    # -- reads and the merge -------------------------------------------------

    def _read_once(self, now: float) -> None:
        backend = self._backend
        try:
            result = backend.list_outputs(READ_TIMEOUT_S)
        except Exception as exc:
            LOG.debug("Output read raised", exc_info=True)
            result = ListOutputsResult(ok=False, error=str(exc), error_code="request_failed")
        if result.ok:
            self._on_read_ok(list(result.outputs), now)
        else:
            self._on_read_failed(result, now)

    def _on_read_failed(self, result: ListOutputsResult, now: float) -> None:
        pending = None
        with self._lock:
            exempt = (
                (self._inflight > 0 and not self._exempt_off)
                or any(u.start_pending_until > now for u in self._units.values())
            )
            if not (result.error_code == "timeout" and exempt):
                self._fail_count += 1
            self._retry_n += 1
            self._read_retry_at = now + _READ_BACKOFF_S[min(self._retry_n - 1, len(_READ_BACKOFF_S) - 1)]
            self._dirty = True
            if self._fail_count >= _FAILED_READS_BEFORE_DOWN and self._connected:
                self._connected = False
                pending = self._publish_locked(Origin.BACKEND, None)
        if pending is not None:
            pending.notify()

    def _on_read_ok(self, rows: list, now: float) -> None:
        fx = _Effects()
        with self._lock:
            self._fail_count = 0
            self._retry_n = 0
            self._dirty = False
            self._exempt_off = False
            self._read_retry_at = 0.0
            self._next_safety_read = now + SAFETY_READ_S
            self._merge_locked(rows, now, fx)
            pending = self._publish_locked(Origin.BACKEND, None)
        pending.notify()
        fx.run()
        self._after_intent()

    def _availability_locked(self, row: OutputInfo, selected: bool) -> str:
        if not self._rows_carry_session:
            return "password" if (row.needs_auth_key or row.pin_pending) else "ok"
        state = row.session_state
        if state in ("streaming", "connected"):
            avail = "ok"
        elif state == "startup":
            avail = "starting"
        elif state == "failed":
            avail = "failed"
        elif state == "password":
            avail = "password"
        else:
            avail = "starting" if selected else "ok"
        return avail

    def _start_failure_locked(self, u: UnitState, reason: str, requester: Optional[str] = None) -> None:
        self._failure_seq += 1
        name = u.reported.name if u.reported is not None else u.name
        self._start_failure = StartFailure(
            seq=self._failure_seq, unit_id=u.id, name=name, reason=reason, at=self._wall(),
            requester=requester if requester is not None else u.requester,
        )

    def _revert_locked(self, u: UnitState, now: float) -> None:
        d = u.desired
        d.selected = False
        d.muted = False
        d.remembered_level = None
        u.attempt = False
        u.retry_at = None
        u.start_pending_until = 0.0
        u.desired_seq += 1
        d.changed_at = now

    def _failed_treatment_locked(self, u: UnitState, now: float) -> None:
        """A start failed on a speaker the user did not just ask for (or one
        that timed out): keep it wanted and retry on a back-off while a
        session plays, on a player that can say why. Otherwise it is turned
        back off at once."""
        if u.retry_allowed and self._rows_carry_session and self._session_active:
            u.availability = "failed"
            if u.retry_at is None:
                u.retry_at = now + u.retry_backoff
                u.retry_backoff = min(u.retry_backoff * 2, RETRY_MAX_S)
        else:
            self._revert_locked(u, now)

    def _merge_locked(self, rows: list, now: float, fx: _Effects) -> None:
        if any(row.session_state != "" for row in rows):
            self._rows_carry_session = True
        if any(row.has_homepods is not None for row in rows):
            self._include_tv_supported = True
        boot_changed = self._boot_changed
        self._boot_changed = False
        if not self._connected:
            if self._boot_id is None:
                if self._ever_connected:
                    boot_changed = True
                self._epoch += 1
            self._connected = True
            self._ever_connected = True
        self._backend_boot = self._boot_id if self._boot_id is not None else f"epoch:{self._epoch}"
        if boot_changed:
            for u in self._units.values():
                u.after_boot = True

        seen = set()
        order = []
        for row in rows:
            uid = row.id
            if uid in seen:
                continue
            seen.add(uid)
            order.append(uid)
            u = self._units.get(uid)
            if u is None:
                u = UnitState(
                    id=uid, name=row.name,
                    desired=UnitDesired(
                        selected=row.selected, volume=row.volume_percent, muted=False,
                        remembered_level=None, cause=Origin.ADOPTED, changed_at=now,
                    ),
                    reported=row, seen_at=now,
                )
                self._units[uid] = u
            else:
                u.reported = row
                u.name = row.name
                u.seen_at = now
                u.absent_since = None
            self._update_unit_locked(u, row, now, fx)
        self._row_order = order

        for uid in list(self._units):
            if uid in seen:
                continue
            u = self._units[uid]
            if u.absent_since is None:
                if boot_changed or u.was_streaming:
                    u.absent_since = now
                    u.reported = None
                    u.availability = "gone"
                else:
                    del self._units[uid]
            elif now - u.absent_since >= ABSENT_KEEP_S:
                del self._units[uid]

    def _update_unit_locked(self, u: UnitState, row: OutputInfo, now: float, fx: _Effects) -> None:
        d = u.desired
        sel = d.selected
        avail = self._availability_locked(row, sel)
        if self._rows_carry_session:
            u.was_streaming = row.session_state in ("streaming", "connected")
            result_shown = row.session_state in ("streaming", "connected", "failed", "password")
        else:
            u.was_streaming = row.selected
            result_shown = row.selected or avail == "password"
        if u.start_pending_until > 0.0:
            if result_shown:
                u.start_pending_until = 0.0
            elif now < u.start_pending_until:
                avail = "starting"
        previous = u.availability
        u.availability = avail
        if row.selected == sel:
            u.after_boot = False
        if sel and avail == "ok" and result_shown and u.attempt:
            # The start the authority made has shown its result.
            u.attempt = False
            u.failure_reported = False
            u.retry_at = None
            u.retry_backoff = RETRY_MIN_S
        if sel and previous == "starting" and avail == "ok":
            fx.republish = True
        if sel and u.attempt and avail == "failed":
            if not u.failure_reported:
                u.failure_reported = True
                self._start_failure_locked(u, "failed")
            if not u.retry_allowed:
                self._revert_locked(u, now)
            else:
                self._failed_treatment_locked(u, now)

    def _adopt_volume_locked(self, u: UnitState, r: OutputInfo, now: float) -> None:
        d = u.desired
        if self._inflight > 0 or now - u.own_write_at < DEBOUNCE_S:
            return
        if r.volume_percent == d.volume:
            return
        if d.muted:
            # A level above silence on a muted speaker is a change made on the
            # speaker; without device events nothing else can be told apart.
            d.muted = False
            d.remembered_level = None
            self._mute_held = False
        d.volume = r.volume_percent
        d.cause = Origin.DEVICE if now - u.device_volume_at < DEVICE_VOLUME_MARK_S else Origin.BACKEND
        d.changed_at = now
        u.desired_seq += 1

    # -- timers and reconcile ------------------------------------------------

    def _run_timers(self, now: float) -> None:
        fx = _Effects()
        pending = None
        with self._lock:
            changed = False
            for u in list(self._units.values()):
                if u.start_pending_until > 0.0 and now >= u.start_pending_until:
                    u.start_pending_until = 0.0
                    self._start_failure_locked(u, "timed_out")
                    u.failure_reported = True
                    self._failed_treatment_locked(u, now)
                    changed = True
                if u.absent_since is not None and now - u.absent_since >= ABSENT_KEEP_S:
                    del self._units[u.id]
                    changed = True
            if self._connected:
                changed = self._reconcile_locked(now, fx) or changed
            if changed:
                pending = self._publish_locked(Origin.BACKEND, None)
        if pending is not None:
            pending.notify()
        fx.run()
        self._after_intent()

    def _queue_reapply_select_locked(self, u: UnitState) -> None:
        u.attempt = True
        u.retry_allowed = True
        u.requester = None
        batch = _Batch(1)
        self._enqueue(_Write(
            "select", u.id, u.desired_seq,
            {"volume": u.desired.volume, "offset_ms": None, "mode": None, "cause": u.desired.cause},
            [(batch, 0)],
        ))

    def _due(self, u: UnitState, key: str, now: float) -> bool:
        """True once a difference of kind *key* has lasted DEBOUNCE_S."""
        since = u.diff_since.setdefault(key, now)
        return now - since >= DEBOUNCE_S

    def _reconcile_locked(self, now: float, fx: _Effects) -> bool:
        """Compare reported with desired and queue what repairs a difference.
        True when a unit changed. Runs on the worker, under _lock; it only
        queues writes."""
        changed = False
        restored = 0
        busy = self._inflight > 0 or bool(self._wq)
        for u in self._ordered_units_locked():
            r = u.reported
            if r is None:
                continue
            d = u.desired
            if d.selected != r.selected and (busy or now - u.own_write_at < DEBOUNCE_S):
                # A write of ours is queued, running or has just finished, so
                # the row read may predate it; judge the next read.
                u.diff_since.pop("select", None)
                u.diff_since.pop("deselect", None)
                continue
            if d.selected and not r.selected:
                u.diff_since.pop("deselect", None)
                if u.availability == "password" or r.session_state in ("startup", "connected") \
                        or u.start_pending_until > now:
                    u.diff_since.pop("select", None)
                elif u.availability == "failed":
                    if u.retry_at is not None and now >= u.retry_at and self._session_active:
                        u.retry_at = None
                        self._queue_reapply_select_locked(u)
                elif self._rows_carry_session:
                    if self._due(u, "select", now):
                        u.diff_since.pop("select", None)
                        restored += 1 if u.after_boot else 0
                        self._queue_reapply_select_locked(u)
                elif u.after_boot:
                    if self._due(u, "select", now):
                        u.diff_since.pop("select", None)
                        restored += 1
                        self._queue_reapply_select_locked(u)
                else:
                    # A player without session reports deselected itself (a
                    # device pause, a failed start): follow it.
                    d.selected = False
                    d.muted = False
                    d.remembered_level = None
                    d.cause = Origin.BACKEND
                    u.attempt = False
                    u.desired_seq += 1
                    changed = True
                continue
            u.diff_since.pop("select", None)
            if not d.selected and r.selected:
                if self._due(u, "deselect", now):
                    u.diff_since.pop("deselect", None)
                    batch = _Batch(1)
                    self._enqueue(_Write("deselect", u.id, u.desired_seq, {}, [(batch, 0)]))
                continue
            u.diff_since.pop("deselect", None)
            if d.muted and r.volume_percent > 0 and d.selected:
                recent = now - u.device_volume_at < DEVICE_VOLUME_MARK_S
                if recent or busy:
                    continue
                if self._delivers_device_events:
                    if self._due(u, "mute", now):
                        u.diff_since.pop("mute", None)
                        batch = _Batch(1)
                        self._enqueue(_Write("volume", u.id, u.desired_seq, {}, [(batch, 0)]))
                else:
                    self._adopt_volume_locked(u, r, now)
                    changed = True
                continue
            u.diff_since.pop("mute", None)
            if not d.muted and not busy:
                # With a write queued the row read may predate it, as above.
                before = d.volume
                self._adopt_volume_locked(u, r, now)
                changed = changed or d.volume != before
        if restored:
            fx.log(logging.WARNING, "Output selection restored after the player restarted: %d output(s)", restored)
        return changed

    # -- device events -------------------------------------------------------

    def _handle_event(self, ev: DeviceEvent, now: float) -> None:
        if ev.kind == "device_volume":
            with self._lock:
                if ev.speaker_id == "0":
                    targets = [u.id for u in self._selected_locked()]
                else:
                    uid = self._unit_for_device_locked(ev.speaker_id)
                    targets = [uid] if uid is not None else []
            if not targets:
                LOG.info("device volume from %s maps to no speaker; dropped", ev.speaker_name or ev.speaker_id)
            for uid in targets:
                self.device_volume_seen(uid)
        elif ev.kind == "receiver_command":
            if self._policy is None:
                LOG.info(
                    "receiver command %s from %s: no policy, ignored",
                    ev.verb, ev.speaker_name or ev.speaker_id,
                )
        policy = self._policy
        if policy is not None:
            try:
                policy.on_device_event(ev, store().snapshot().outputs)
            except Exception:
                LOG.exception("Output policy failed on a device event")

    # -- the apply side ------------------------------------------------------

    def _apply_loop(self) -> None:
        while True:
            with self._wq_cond:
                while not self._wq and not self._stopping:
                    self._wq_cond.wait()
                if self._stopping:
                    return
                w = self._wq.pop(0)
            self._run_write(w)

    def _drain_inline(self) -> None:
        while True:
            with self._wq_cond:
                if not self._wq:
                    return
                w = self._wq.pop(0)
            self._run_write(w)

    def _run_write(self, w: _Write) -> None:
        with self._apply_lock:
            pendings, finish = self._apply_one(w)
        # Subscribers and waiters are told with no lock held.
        for p in pendings:
            p.notify()
        finish()

    def _complete(self, w: _Write, outcome: WriteOutcome) -> None:
        gone = False
        for batch, index in w.sinks:
            gone = batch.done(index, outcome) or gone
        if gone and w.kind == "select" and outcome.error_code == "pin_required":
            self._late_pin(w)

    def _late_pin(self, w: _Write) -> None:
        """The speaker asked for a PIN after the request that switched it on
        stopped waiting, so that request's reply could not carry the prompt:
        give the pairing to whoever can enter the PIN. The speaker deselects
        itself while it waits for one, so nothing is sent to it."""
        handler = _pin_claim_handler
        if handler is None or not w.claimant or w.unit_id is None:
            return
        try:
            handler(w.unit_id, w.claimant)
        except Exception:
            LOG.exception("PIN claim for %s failed", w.unit_id)

    def _apply_one(self, w: _Write):
        now = self._clock()
        include = None
        if w.kind == "select" and w.unit_id is not None:
            try:
                include = self._include_tv_reader(w.unit_id)
            except Exception:
                include = None
        with self._lock:
            runner = self._build_locked(w, include)
            if runner is None or runner is _HOLD:
                fx = _Effects()
                outcome = WriteOutcome(ok=True, pending=runner is _HOLD)
                pending = self._publish_locked(Origin.BACKEND, None) if runner is _HOLD else None
                return ([pending] if pending is not None else []), (lambda: (fx.run(), self._complete(w, outcome)))
            self._inflight += 1
        backend = self._backend
        try:
            results = runner(backend)
        except Exception as exc:
            LOG.exception("Output write %s raised", w.kind)
            results = [ActionResult(ok=False, error=str(exc), error_code="exception")]
        fx = _Effects()
        with self._lock:
            self._inflight -= 1
            outcome = self._record_locked(w, results, self._clock(), fx)
            pending = self._publish_locked(Origin.BACKEND, None)
        return [pending], (lambda: (fx.run(), self._complete(w, outcome)))

    def _build_locked(self, w: _Write, include: Optional[bool]):
        """The player calls for a write, built from desired state as it is
        now. None: nothing to send. _HOLD: not yet. Otherwise a function of
        the backend that returns the ActionResults."""
        kind = w.kind
        uid = w.unit_id
        u = self._units.get(uid) if uid is not None else None
        if kind == "select":
            if u is None:
                return None
            d = u.desired
            kwargs = dict(
                enabled=True, volume_percent=0 if d.muted else w.params.get("volume"),
                offset_ms=w.params.get("offset_ms"), mode=w.params.get("mode"),
                timeout=WRITE_TIMEOUT_S,
            )
            if include is not None and self._include_tv_supported:
                if u.reported is not None and u.reported.has_homepods:
                    kwargs["include_tv"] = include
                elif include is False:
                    # The Apple TV is never selected alone: wait for its group.
                    u.availability = "starting"
                    return _HOLD
            return lambda b: [b.update_output(uid, **kwargs)]
        if kind == "deselect":
            if u is None:
                return None
            return lambda b: [b.update_output(uid, enabled=False, timeout=WRITE_TIMEOUT_S)]
        if kind == "volume":
            if u is None or not u.desired.selected:
                return None
            level = 0 if u.desired.muted else u.desired.volume
            return lambda b: [b.update_output(uid, volume_percent=level, timeout=WRITE_TIMEOUT_S)]
        if kind == "deselect_all":
            if w.params.get("session"):
                return lambda b: [b.stop_and_disable_all(timeout=WRITE_TIMEOUT_S)]
            return lambda b: [b.set_selected_outputs([], timeout=WRITE_TIMEOUT_S)]
        if kind == "pin":
            pin = w.params.get("pin", "")
            return lambda b: [b.submit_output_pin(uid, pin, timeout=WRITE_TIMEOUT_S)]
        if kind == "reapply":
            ids = [x.id for x in self._selected_locked()]
            recover = [
                x.id for x in self._selected_locked()
                if not x.desired.muted and x.reported is not None and x.reported.volume_percent == 0
            ]
            level = w.params.get("recovery", 0)
            if not ids:
                return None

            def run(b):
                first = b.set_selected_outputs(ids, timeout=WRITE_TIMEOUT_S)
                results = [first]
                if not first.ok:
                    return results
                refresh = b.refresh_runtime_state(timeout=WRITE_TIMEOUT_S)
                if not refresh.ok and refresh.error_code != "unsupported":
                    LOG.debug("Player state refresh after reselect: %s", refresh.message)
                for rid in recover:
                    r = b.update_output(rid, volume_percent=level, timeout=WRITE_TIMEOUT_S)
                    if not r.ok:
                        LOG.debug("Recovery volume for %s not applied: %s", rid, r.message)
                return results
            return run
        return None

    def _record_locked(self, w: _Write, results: list, now: float, fx: _Effects) -> WriteOutcome:
        r = results[0] if results else ActionResult(ok=True)
        u = self._units.get(w.unit_id) if w.unit_id is not None else None
        if w.kind == "select":
            return self._record_select_locked(w, r, u, now, fx)
        if r.ok:
            if u is not None:
                u.own_write_at = now
            return WriteOutcome(ok=True)
        return WriteOutcome(ok=False, error_code=r.error_code, error=r.message)

    def _record_select_locked(self, w: _Write, r: ActionResult, u: Optional[UnitState],
                              now: float, fx: _Effects) -> WriteOutcome:
        stale = u is None or u.desired_seq != w.seq
        code = r.error_code
        if r.ok:
            if u is not None:
                u.own_write_at = now
                if u.desired.selected and u.availability != "password":
                    u.availability = "starting"
            if w.params.get("cause") == Origin.USER:
                self._silence_chosen = False
            # A speaker that joins late gets the bundle once it exists.
            fx.republish = True
            return WriteOutcome(ok=True)
        if code in ("pin_required", "pin_invalid", "encoder_capacity"):
            reason = {"pin_required": "pin_required", "pin_invalid": "refused",
                      "encoder_capacity": "encoder_capacity"}[code]
            if u is not None:
                if code == "pin_required":
                    u.availability = "password"
                if not stale:
                    self._revert_locked(u, now)
                self._start_failure_locked(u, reason, w.requester)
            return WriteOutcome(ok=False, error_code=code, error=r.message)
        if code == "timeout":
            # The player is still starting it: its command queue is busy, not down.
            if u is not None and not stale:
                u.availability = "starting"
                u.start_pending_until = now + START_PENDING_S
                u.retry_allowed = True
            return WriteOutcome(ok=True, error_code="timeout", pending=True)
        if code == "reselect_required":
            fx.log(logging.WARNING, "include_tv change refused on a selected output (%s)", w.unit_id)
            return WriteOutcome(ok=False, error_code=code, error=r.message)
        if code == "group_not_present":
            if u is not None and not stale:
                u.availability = "starting"
            return WriteOutcome(ok=True, error_code=code, pending=True)
        if u is not None and not stale:
            if not u.retry_allowed:
                self._revert_locked(u, now)
                self._start_failure_locked(u, "refused", w.requester)
            elif self._rows_carry_session and self._session_active:
                if not u.failure_reported:
                    u.failure_reported = True
                    self._start_failure_locked(u, "failed")
                self._failed_treatment_locked(u, now)
            else:
                self._revert_locked(u, now)
        return WriteOutcome(ok=False, error_code=code, error=r.message)


_AUTHORITY = OutputAuthority()


def get_authority() -> OutputAuthority:
    """The process's output authority; the single seam a test patches."""
    return _AUTHORITY
