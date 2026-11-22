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

A speaker's mute is part of the desired state: the player silences the
speaker and keeps its level. It lives in the memory of the process only; the
end of a session clears every mute.

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
import dataclasses
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
    session_failure_for,
)

from . import live, spread
from .player_model import PendingStart, PlayerModel
from .origin import Origin
from .parts import DefaultMemberView, OutputsPart, OutputUnitView, StartFailure
from .store import store

LOG = logging.getLogger("autostream.outputs")

READ_TIMEOUT_S = 10.0
WRITE_TIMEOUT_S = 3.0
SAFETY_READ_S = 60.0
# A start the player accepted but never reports on ends after this long, above
# owntone-mini's slowest give-up: three attempts that each end on a 15 s
# stream-setup timeout, plus a PIN pairing, take about 75 s
START_PENDING_S = 90.0
DEBOUNCE_S = 2.0
DEVICE_VOLUME_MARK_S = 2.0
ABSENT_KEEP_S = 60.0
PROBE_INTERVAL_S = 60.0
# How long a websocket that degraded is not tried again.
WS_DEGRADED_HOLD_S = 3600.0
RETRY_MIN_S = 10.0
RETRY_MAX_S = 60.0
# The gaps between a coordinator start's retries: 10 s, then 20 s, then 30 s,
# then every 30 s while live input lasts.
RETRY_GAPS_S = (10.0, 20.0, 30.0)
RETRY_STEADY_S = 30.0


def _retry_gap(n: int) -> float:
    """The wait before retry *n* (from 0): 10 s, 20 s, 30 s, then every 30 s."""
    return RETRY_GAPS_S[n] if n < len(RETRY_GAPS_S) else RETRY_STEADY_S
# A speaker that fails while it plays is retried this many times (10 s and
# 30 s after the failure, the first two gaps), then switched off
MIDSESSION_RETRIES = 2
_READ_BACKOFF_S = (0.5, 1.0, 2.0, 5.0)
_FAILED_READS_BEFORE_DOWN = 3
# With events, a burst of output changes is read at most once a second
CHANGED_READ_MIN_S = 1.0
# owntone-mini's own bounds on a PIN pairing: the pair-setup computation is
# given up after 10 s, its time in the queue included, and each request to
# the speaker waits up to 15 s for its answer
PAIR_COMPUTE_BOUND_S = 10.0
PAIR_ANSWER_BOUND_S = 15.0
# A PIN sent with its select waits this long for the player's verdict: a
# pairing whose computation and one slow answer both run to their bounds,
# and a margin for the event that reports it
PIN_OUTCOME_S = PAIR_COMPUTE_BOUND_S + PAIR_ANSWER_BOUND_S + 5.0

# The speaker states an output_state event may carry; any other makes the
# authority read the list
_EVENT_STATES = frozenset(
    ("connecting", "connected", "streaming", "stopping", "stopped", "failed", "password"))

# An event's reason as (outcome code, notice); (None, None): no outcome from
# the event. A reason not listed takes the default of its state.
_EVENT_OUTCOMES = {
    "pin_required": ("pin_required", "pin_required"),
    "pin_invalid": ("pin_invalid", "pin_invalid"),
    "capacity": ("encoder_capacity", "encoder_capacity"),
    "no_clock": ("no_clock", "no_clock"),
    "refused": ("failed", "refused"),
    "unreachable": ("failed", "unreachable"),
    "timeout": ("failed", "timed_out"),
    "cancelled": (None, None),
    "lost": (None, None),
}

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
    mute_tokens: tuple = ()                            # ((unit id, token), ...) for every unit a mute call muted or re-stamped
    token_at: int = 0                                  # the mute token counter after a mute call


@dataclass(frozen=True)
class UnitMarks:
    """What a policy needs to know about one unit's history without reading
    the authority's internals."""
    select_seq: int       # +1 each time the desired selection goes from off to on
    mute_token: int       # the token of the unit's current mute; 0 when not muted
    mute_joined: bool     # the current mute came from joining a muted selection


class PolicyHook(Protocol):
    """What set_policy() takes. Every method is called on the worker thread
    with no authority lock held."""

    def on_device_event(self, ev: DeviceEvent, outputs: OutputsPart, now: float) -> None: ...

    def on_timer(self, now: float, outputs: OutputsPart) -> None: ...

    def next_deadline(self) -> Optional[float]: ...

    def on_session(self, active: bool) -> None: ...


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

    def submit_output_pin(self, output_id: str, pin: str, timeout: float, *, select: bool = False,
                          volume_percent: Optional[int] = None, muted: Optional[bool] = None) -> ActionResult: ...

    def set_output_hold(self, output_id: str, held: bool, timeout: float) -> ActionResult: ...

    def set_output_muted(self, output_id: str, muted: bool, timeout: float) -> ActionResult: ...

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

    def submit_output_pin(self, output_id: str, pin: str, timeout: float, *, select: bool = False,
                          volume_percent: Optional[int] = None, muted: Optional[bool] = None) -> ActionResult:
        if not select:
            return player_service.submit_output_pin(self.base_url, output_id, pin, timeout=timeout)
        return player_service.submit_output_pin(self.base_url, output_id, pin, timeout=timeout, select=True,
                                                volume_percent=volume_percent, muted=muted)

    def set_output_hold(self, output_id: str, held: bool, timeout: float) -> ActionResult:
        return player_service.set_output_hold(self.base_url, output_id, held, timeout=timeout)

    def set_output_muted(self, output_id: str, muted: bool, timeout: float) -> ActionResult:
        return player_service.set_output_muted(self.base_url, output_id, muted, timeout=timeout)

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
    volume: int                       # the speaker's own level: what it plays at, or returns to while muted or held
    muted: bool
    cause: Origin
    changed_at: float
    mute_token: int = 0               # the token of the current mute; 0 when not muted
    mute_joined: bool = False         # the current mute came from joining a muted selection
    held: bool = False                # the speaker paused itself and the player holds it


@dataclass
class _Member:
    """One speaker of the Auto-Start set."""
    key: str
    id: str                           # "" for a member saved before its id was known
    name: str
    volume: int


@dataclass
class UnitState:
    id: str
    name: str
    desired: UnitDesired
    reported: Optional[OutputInfo]
    seen_at: float
    availability: str = "ok"
    retry_at: Optional[float] = None
    retry_n: int = 0                  # retries scheduled since the last start that showed a result
    group_hold_backoff: float = RETRY_MIN_S   # the wait for an Apple TV's group, which doubles
    device_volume_at: float = 0.0
    own_write_at: float = 0.0
    report_at: float = 0.0            # last per-speaker volume report that may spread
    report_used_at: float = 0.0       # report_at of the last report a spread considered
    ok_since: float = 0.0             # when the unit last started playing
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
    select_seq: int = 0               # +1 each time the desired selection goes from off to on
    held_until: float = 0.0           # a select the player cannot take yet is not tried again before this
    reselect_retry: bool = False      # a restart's select was refused: send it once more when the unit reads off
    hold_write_at: float = 0.0        # when a hold or its end was last asked of the player
    retry_limit: Optional[int] = None  # retries left to a speaker that failed while playing: none counts
    outcome_applied: bool = False     # the current attempt's failure has been applied (event or reply)
    claimant: Optional[str] = None    # who can enter a PIN for the current attempt
    fail_notice: str = "failed"       # the notice a later give-up of this attempt reports
    pin_sinks: list = field(default_factory=list)   # a PIN-with-select write waiting for the authorise outcome
    pin_deadline: float = 0.0         # when parked PIN sinks are answered "pending"


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
    kind: str                         # select | deselect | volume | mute | deselect_all | pin | hold
    unit_id: Optional[str]
    seq: int                          # the unit's desired_seq when the write was queued
    params: dict
    sinks: list                       # (batch, index) pairs waiting for the outcome
    requester: Optional[str] = None   # who asked, as the intent named them
    claimant: Optional[str] = None    # the identity that can enter a PIN for the speaker


class _Effects:
    """What a locked block wants done once the locks are released: log
    lines (nothing logs under a lock), the now-playing republish request,
    PIN claims to hand to whoever can enter the PIN, and write outcomes to
    give their waiters."""

    __slots__ = ("logs", "republish", "publish_as", "claims", "completions")

    def __init__(self) -> None:
        self.logs: list = []
        self.republish = False
        self.publish_as: Optional[tuple] = None   # an (Origin, requester) pair
        self.claims: list = []                    # (unit id, claimant)
        self.completions: list = []               # (sinks, WriteOutcome)

    def log(self, level: int, text: str, *args) -> None:
        self.logs.append((level, text, args))

    def run(self) -> None:
        for level, text, args in self.logs:
            LOG.log(level, text, *args)
        if self.republish:
            runtime.request_nowplaying_republish()
        handler = _pin_claim_handler
        for unit_id, claimant in self.claims:
            if handler is None:
                break
            try:
                handler(unit_id, claimant)
            except Exception:
                LOG.exception("PIN claim for %s failed", unit_id)
        for sinks, outcome in self.completions:
            for batch, index in sinks:
                batch.done(index, outcome)


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
        self._mute_counter = 0
        self._silence_chosen = False
        self._members: tuple[_Member, ...] = ()
        self._start_volume = 20
        self._pending: set[str] = set()   # member keys still to add this session
        self._hidden: frozenset[str] = frozenset()      # casefolded names the user hides
        self._remote_usage: dict[str, tuple[str, str]] = {}   # casefolded name -> (id, hostname) of the other appliance playing it
        self._claims_published: dict[str, str] = {}     # unit id -> the PIN claim the part last carried
        self._start_failure: Optional[StartFailure] = None
        self._failure_seq = 0
        self._session_active = False
        self._include_tv_supported = False
        self._delivers_device_events = False
        self._inflight = 0
        self._exempt_off = False
        self._policy = None
        self._include_tv_reader: Callable[[str], Optional[bool]] = lambda unit_id: None
        self._spread_reader: Callable[[], bool] = lambda: False
        self._spread_burst: Optional[spread.Burst] = None
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
        # Restarts of the player seen so far, for the self-heal's re-arm.
        self._backend_restarts = 0
        # A socket closed and the player may have restarted before it came
        # back; the next good read counts it like an unreachable spell.
        self._maybe_restarted = False
        # Until when a websocket that gave up is not built again.
        self._ws_degraded_until = 0.0
        # Whether the player starts a speaker at the level it is enabled with,
        # as its hello last said. Kept through the polling between two sockets
        # of one boot; forgotten when a restart is seen without a hello.
        self._start_volume_cap = False
        # What the player's rows can be taken to say: whether they carry a
        # session (seen in a read, and kept), and whether the player reports
        # each speaker's transitions as events and answers a speaker request
        # without waiting for the speaker (as its hello last said; kept and
        # forgotten as the start-volume flag is). Replaced whole, never edited
        self._model = PlayerModel()
        # With events, the earliest time a "changed" read is made (worker only)
        self._next_changed_read = 0.0
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

    def set_spread_reader(self, fn: Callable[[], bool]) -> None:
        """Whether a volume change made at a speaker applies to the other
        playing speakers. Called on the worker with no authority lock held."""
        self._touched = True
        self._spread_reader = fn

    def _read_spread_setting(self) -> bool:
        try:
            return bool(self._spread_reader())
        except Exception:
            LOG.debug("Speaker volume setting could not be read", exc_info=True)
            return False

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

    def assume_start_volume_for_tests(self, supported: bool = True) -> None:
        """The player's hello is taken to have advertised (or not) that it
        starts a speaker at the level it is enabled with."""
        with self._lock:
            self._start_volume_cap = bool(supported)

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

    def record_start_failure_for_tests(self, unit_id: str, reason: str, requester: Optional[str] = None,
                                       at: Optional[float] = None) -> None:
        """Publish a failed start of *unit_id*, as the apply thread would."""
        with self._lock:
            u = self._units[unit_id]
            self._start_failure_locked(u, reason, requester)
            if at is not None:
                self._start_failure = dataclasses.replace(self._start_failure, at=at)
            pending = self._publish_locked(Origin.BACKEND, None)
        pending.notify()

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

    def _selected_locked(self, online_only: bool = False) -> list:
        """The units desired selected; with *online_only*, only those the
        player has a row for."""
        return [
            u for u in self._ordered_units_locked()
            if u.desired.selected and not (online_only and u.reported is None)
        ]

    def _muted_all_locked(self) -> bool:
        selected = [u for u in self._units.values() if u.desired.selected]
        if selected:
            return all(u.desired.muted for u in selected)
        return self._mute_held

    def _master_locked(self, online_only: bool = False) -> Optional[int]:
        """The level the selected speakers stand at, as a dial shows it: the
        mean of their intended levels, rounded up. With *online_only*, the
        speakers the player has not lost."""
        levels = [_clamp(u.desired.volume) for u in self._selected_locked(online_only)]
        if not levels:
            return None
        return -(-sum(levels) // len(levels))

    def set_default_members(self, members: Sequence[tuple[str, str, int]], start_volume: int) -> None:
        """The Auto-Start set, (id, name, volume) in order, and the level a
        speaker outside it starts at. Each member's card is always listed:
        when the player has no row for it, a placeholder view stands in until
        the row appears. A member removed mid-session stops being added; one
        added is not, the user's speakers stand."""
        self._touched = True
        built: list[_Member] = []
        seen: set[str] = set()
        for uid, name, volume in members:
            uid = str(uid or "").strip()
            name = str(name or "").strip()
            if not name:
                continue
            key = uid or "name:" + name
            if key in seen:
                continue
            seen.add(key)
            built.append(_Member(key=key, id=uid, name=name, volume=_clamp(volume)))
        with self._lock:
            self._members = tuple(built)
            self._start_volume = _clamp(start_volume)
            self._pending &= seen
            pending = self._publish_locked(Origin.SYSTEM, None)
        pending.notify()

    def set_hidden_outputs(self, names: Sequence[str]) -> None:
        """The speaker names the user hides from the lists, compared casefolded."""
        self._touched = True
        hidden = frozenset(str(n).strip().casefold() for n in names or () if str(n).strip())
        with self._lock:
            if hidden == self._hidden:
                return
            self._hidden = hidden
            pending = self._publish_locked(Origin.SYSTEM, None)
        pending.notify()

    def set_remote_usage(self, usage: dict) -> None:
        """The speakers other appliances are playing: casefolded name -> that
        appliance's (id, hostname). A speaker selected here is never shown as
        in use elsewhere."""
        self._touched = True
        usage = {str(k): (str(v[0]), str(v[1])) for k, v in (usage or {}).items()}
        with self._lock:
            if usage == self._remote_usage:
                return
            self._remote_usage = usage
            pending = self._publish_locked(Origin.SYSTEM, None)
        pending.notify()

    def republish(self) -> None:
        """Publish the part again, for what it reads outside the authority (a
        PIN claim made or released)."""
        self._touched = True
        with self._lock:
            pending = self._publish_locked(Origin.SYSTEM, None)
        pending.notify()

    def start_volume(self) -> int:
        """The level a speaker starts at when nothing else is asked: the
        configured start volume."""
        with self._lock:
            return self._start_volume

    def starts_are_async(self) -> bool:
        """Whether the player answers a speaker request at once and reports
        how the start went as events (its hello lists output_state)."""
        with self._lock:
            return self._model.outcome_events

    def _member_unit_locked(self, m: _Member) -> Optional[UnitState]:
        """The unit a member stands for: by id, else by exact name."""
        if m.id and m.id in self._units:
            return self._units[m.id]
        for u in self._units.values():
            if u.name == m.name:
                return u
        return None

    def _placeholder_pending_locked(self) -> bool:
        return any(
            m.key in self._pending and self._member_unit_locked(m) is None
            for m in self._members
        )

    def want_default(self, wanted: bool, key: str) -> Applied:
        """The user switched a default speaker's card on or off while the
        player has no row for it. Nothing is sent: the choice is the member's
        pending flag and the session's silence flag, which the self-heal
        reads, and the speaker starts once its row appears. Another member's
        pending flag is not touched."""
        self._touched = True
        with self._lock:
            if wanted:
                if any(m.key == key for m in self._members):
                    self._pending.add(key)
                self._silence_chosen = False
            else:
                self._pending.discard(key)
                if not self._selected_locked() and not self._placeholder_pending_locked():
                    self._silence_chosen = True
            pending = self._publish_locked(Origin.USER, None)
        pending.notify()
        return Applied(version=store().snapshot().version, outcome=None)

    def _placeholders_locked(self) -> list:
        """A card for each member the player has no unit for."""
        if not self._connected:
            return []
        out = []
        for m in self._members:
            if self._member_unit_locked(m) is not None:
                continue
            out.append(OutputUnitView(
                id=m.id or "default:" + m.name, name=m.name,
                selected=self._session_active and m.key in self._pending,
                volume=m.volume, muted=False, availability="gone",
                cause=Origin.SESSION, reported=None, auto_start=True,
            ))
        return out

    def _member_views_locked(self, views: list) -> tuple:
        by_id = {v.id: v for v in views}
        out = []
        for m in self._members:
            mu = self._member_unit_locked(m)
            if mu is not None:
                out.append(DefaultMemberView(
                    key=m.key, id=m.id, name=by_id[mu.id].name, volume=m.volume,
                    unit_id=mu.id, placeholder=False, pending=m.key in self._pending,
                ))
            else:
                out.append(DefaultMemberView(
                    key=m.key, id=m.id, name=m.name, volume=m.volume,
                    unit_id=m.id or "default:" + m.name, placeholder=True,
                    pending=m.key in self._pending,
                ))
        return tuple(out)

    def _default_matches_locked(self, views: list) -> bool:
        """The selection is exactly the set, each member at its saved level."""
        if not self._members:
            return False
        by_id = {v.id: v for v in views}
        member_units = set()
        for m in self._members:
            mu = self._member_unit_locked(m)
            if mu is None:
                return False
            v = by_id[mu.id]
            if v.offline or not v.shown_selected:
                return False
            if m.volume != (v.volume or self._start_volume):
                return False
            member_units.add(mu.id)
        return not any(
            v.shown_selected and not v.offline and v.id not in member_units for v in views
        )

    def _connecting_locked(self, u: UnitState) -> bool:
        """Wanted during a session, the player has the speaker, and it is not
        yet playing: still starting, between retries, or switched off on the
        player. A speaker waiting for a PIN is not connecting."""
        r = u.reported
        if not (u.desired.selected and self._session_active) or r is None or u.availability == "password":
            return False
        if u.desired.held:
            return False
        return self._model.connecting(r)

    @staticmethod
    def _stopping_locked(u: UnitState) -> bool:
        """Switched off here while the player is still ending its session."""
        return not u.desired.selected and u.reported is not None and u.reported.session_state == "stopping"

    def _with_outside_fields_locked(self, view: OutputUnitView, claims: dict) -> OutputUnitView:
        """*view* with the fields the authority does not own: whether the user
        hides the speaker, who is entering its PIN, and which other appliance is
        playing it. Records a live claim in *claims*."""
        key = view.name.casefold()
        claim = live.pin_claim(view.id)
        if claim:
            claims[view.id] = claim
        in_use_id, in_use_by = ("", "") if view.shown_selected else self._remote_usage.get(key, ("", ""))
        return dataclasses.replace(
            view, hidden=key in self._hidden, pin_claim=claim,
            in_use_by=in_use_by, in_use_id=in_use_id,
        )

    def _build_part_locked(self) -> OutputsPart:
        views = []
        matched: dict[str, _Member] = {}
        for m in self._members:
            mu = self._member_unit_locked(m)
            if mu is not None and mu.id not in matched:
                matched[mu.id] = m
                if mu.desired.selected:
                    self._pending.discard(m.key)
        claims: dict[str, str] = {}
        for u in self._ordered_units_locked():
            d = u.desired
            name = u.reported.name if u.reported is not None else u.name
            view = OutputUnitView(
                id=u.id, name=name, selected=d.selected, volume=d.volume, muted=d.muted,
                availability=u.availability, cause=d.cause, reported=u.reported,
                connecting=self._connecting_locked(u), stopping=self._stopping_locked(u),
                auto_start=u.id in matched, held=d.held,
            )
            views.append(self._with_outside_fields_locked(view, claims))
        views.extend(self._with_outside_fields_locked(v, claims) for v in self._placeholders_locked())
        self._claims_published = claims
        return OutputsPart(
            default_members=self._member_views_locked(views),
            default_matches=self._default_matches_locked(views),
            units=tuple(views), connected=self._connected, backend_boot=self._backend_boot,
            backend_restarts=self._backend_restarts,
            event_source=self._event_kind, muted_all=self._muted_all_locked(),
            silence_chosen=self._silence_chosen, start_failure=self._start_failure,
            device_events=self._delivers_device_events, include_tv_supported=self._include_tv_supported,
            master_volume=self._master_locked(online_only=True),
            selected_count=len(self._selected_locked(online_only=True)),
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

    def unit_marks(self, unit_id: str) -> Optional[UnitMarks]:
        with self._lock:
            u = self._units.get(unit_id)
            if u is None:
                return None
            return UnitMarks(u.select_seq, u.desired.mute_token, u.desired.mute_joined)

    # -- intents -------------------------------------------------------------

    def _next_token_locked(self) -> int:
        self._mute_counter += 1
        return self._mute_counter

    @staticmethod
    def _clear_mute_locked(d: UnitDesired) -> None:
        d.muted = False
        d.mute_token = 0
        d.mute_joined = False

    def _stamp(self, u: UnitState, cause: Origin, now: float) -> None:
        u.desired.cause = cause
        u.desired.changed_at = now
        u.desired_seq += 1

    def _enqueue(self, w: _Write) -> None:
        with self._wq_cond:
            if w.kind in ("volume", "mute"):
                # A write is built from desired state when it runs, so a queued
                # one of the same kind takes this one's place and ends in the
                # same state
                for queued in self._wq:
                    if queued.kind == w.kind and queued.unit_id == w.unit_id:
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
            self._begin_select_locked(u, cause, vol, requester, claimant, now)
            batch = _Batch(1)
            self._enqueue(_Write(
                "select", unit_id, u.desired_seq,
                {"volume": vol, "offset_ms": offset_ms, "mode": mode, "cause": cause},
                [(batch, 0)], requester=requester, claimant=claimant,
            ))
            pending = self._publish_locked(cause, requester)
        return self._finish_intent(pending, batch.future)

    def _begin_select_locked(self, u: UnitState, cause: Origin, vol: Optional[int],
                             requester: Optional[str], claimant: Optional[str], now: float) -> None:
        """The desired state of a speaker switched on by *cause*: selected, at
        *vol* when given, muted when it joins a muted selection, and a fresh
        start whose result is still to show."""
        if cause in (Origin.USER, Origin.POLICY, Origin.DEVICE):
            self._pending.clear()
        d = u.desired
        if self._muted_all_locked():
            # Joining a muted session: the speaker starts silent, keeping
            # its level for a later restore.
            if not d.muted:
                d.mute_token = self._next_token_locked()
                d.mute_joined = True
            d.muted = True
        if vol is not None:
            d.volume = vol
        if not d.selected:
            u.select_seq += 1
            d.held = False
        d.selected = True
        u.retry_allowed = cause != Origin.USER
        self._new_attempt_locked(u)
        u.claimant = claimant
        u.failure_reported = False
        u.start_pending_until = 0.0
        u.retry_at = None
        u.retry_n = 0
        u.retry_limit = None
        u.group_hold_backoff = RETRY_MIN_S
        u.held_until = 0.0
        u.reselect_retry = False
        u.diff_since.clear()
        u.requester = requester
        self._stamp(u, cause, now)

    @staticmethod
    def _new_attempt_locked(u: UnitState) -> None:
        """A start the authority makes now: its result is still to show."""
        u.attempt = True
        u.outcome_applied = False
        u.fail_notice = "failed"

    def _deselect_locked(self, u: UnitState, cause: Origin, now: float) -> None:
        d = u.desired
        d.selected = False
        d.held = False
        self._clear_mute_locked(d)
        u.attempt = False
        u.retry_at = None
        u.retry_limit = None
        u.start_pending_until = 0.0
        u.failure_reported = False
        u.held_until = 0.0
        u.reselect_retry = False
        u.diff_since.clear()
        self._stamp(u, cause, now)

    def reselect(self, unit_id: str, cause: Origin, *, requester: Optional[str] = None) -> Applied:
        """Restart a selected output: switch it off and on again with the
        current include-Apple-TV choice. What the user wants is not changed
        (selection, level, mute), and a restart is not a choice to be silent
        or to play, so the mute and the silence choice are left alone."""
        self._touched = True
        now = self._clock()
        with self._lock:
            u = self._units.get(unit_id)
            if u is None:
                return self._refused("unknown_output")
            if not u.desired.selected:
                return self._refused("not_selected")
            u.desired.held = False
            self._new_attempt_locked(u)
            u.failure_reported = False
            u.start_pending_until = 0.0
            u.held_until = 0.0
            u.reselect_retry = False
            u.diff_since.clear()
            u.requester = requester
            self._stamp(u, cause, now)
            batch = _Batch(2)
            self._enqueue(_Write("deselect", unit_id, u.desired_seq, {}, [(batch, 0)]))
            self._enqueue(_Write(
                "select", unit_id, u.desired_seq,
                {"volume": None, "offset_ms": None, "mode": None, "cause": None, "reselect": True},
                [(batch, 1)], requester=requester,
            ))
            pending = self._publish_locked(cause, requester)
        return self._finish_intent(pending, batch.future)

    def deselect(self, unit_id: str, cause: Origin, *, requester: Optional[str] = None) -> Applied:
        self._touched = True
        now = self._clock()
        with self._lock:
            u = self._units.get(unit_id)
            if u is None:
                return self._refused("unknown_output")
            self._deselect_locked(u, cause, now)
            if cause in (Origin.USER, Origin.POLICY, Origin.DEVICE):
                self._pending.clear()
                if not self._selected_locked():
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
                self._pending.clear()
            if cause == Origin.SESSION:
                self._mute_held = False
            batch = _Batch(1)
            self._enqueue(_Write(
                "deselect_all", None, 0, {"session": cause == Origin.SESSION}, [(batch, 0)],
            ))
            pending = self._publish_locked(cause, requester)
        return self._finish_intent(pending, batch.future)

    def hold(self, unit_id: str, cause: Origin, *, requester: Optional[str] = None) -> Applied:
        """The speaker paused itself: ask the player to hold it, so it is sent
        no audio until its hold ends. Refused as not_holdable when the
        player's row says it cannot be held; holding a held speaker changes
        nothing."""
        return self._set_hold(unit_id, True, cause, requester)

    def resume(self, unit_id: str, cause: Origin, *, requester: Optional[str] = None) -> Applied:
        """End a speaker's hold: the player restarts it at the live position.
        Resume means sound, so a mute on the speaker ends too: the outcomes
        are the hold's first, then the mute's when there was one."""
        return self._set_hold(unit_id, False, cause, requester)

    def _set_hold(self, unit_id: str, held: bool, cause: Origin, requester: Optional[str]) -> Applied:
        self._touched = True
        now = self._clock()
        with self._lock:
            u = self._units.get(unit_id)
            if u is None:
                return self._refused("unknown_output")
            d = u.desired
            if not d.selected:
                return self._refused("not_selected")
            if d.held == held:
                return Applied(version=store().snapshot().version, outcome=None)
            if held and (u.reported is None or not u.reported.session_holdable):
                return self._refused("not_holdable")
            d.held = held
            u.hold_write_at = now
            writes = [("hold", u)]
            if not held and d.muted:
                # Resume means sound: ending a speaker's Pause also ends a
                # mute on it; what the Pause muted elsewhere is the policy's
                self._clear_mute_locked(d)
                self._release_mute_hold_locked()
                self._stamp(u, cause, now)
                writes.append(("mute", u))
            future = self._queue_writes_locked(writes, requester)
            pending = self._publish_locked(cause, requester)
        return self._finish_intent(pending, future)

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
            writes = [("volume", u)]
            d.volume = vol
            if d.muted and cause == Origin.USER:
                # A deliberate level change on a muted speaker is its unmute.
                self._clear_mute_locked(d)
                self._mute_held = False
                writes.append(("mute", u))
            # Any other cause moves the level a muted speaker returns to; the
            # player keeps it silent meanwhile.
            self._stamp(u, cause, now)
            future = self._queue_writes_locked(writes, requester)
            pending = self._publish_locked(cause, requester)
        return self._finish_intent(pending, future)

    def _queue_writes_locked(self, writes: list, requester: Optional[str] = None):
        """One write per (kind, unit) pair, as one batch, in order, each
        carrying *requester*. Returns the batch's future, or None when there
        is nothing to write."""
        if not writes:
            return None
        batch = _Batch(len(writes))
        for index, (kind, u) in enumerate(writes):
            self._enqueue(_Write(kind, u.id, u.desired_seq, {}, [(batch, index)], requester=requester))
        return batch.future

    def _queue_volume_writes_locked(self, units: list):
        return self._queue_writes_locked([("volume", u) for u in units])

    def _unmute_all_locked(self, cause: Origin, default_level: int, now: float) -> tuple:
        """The restore half of mute and of a volume step while muted. Returns
        (unmuted, lifted): the units whose mute ended, and those (muted or
        not) lifted from 0 to *default_level* when that is above 0."""
        unmuted, lifted = [], []
        level = _clamp(default_level)
        for u in self._selected_locked():
            d = u.desired
            touched = False
            if d.muted:
                self._clear_mute_locked(d)
                unmuted.append(u)
                touched = True
            if d.volume == 0 and level > 0:
                d.volume = level
                lifted.append(u)
                touched = True
            if touched:
                self._stamp(u, cause, now)
        self._mute_held = False
        return unmuted, lifted

    @staticmethod
    def _restore_writes(unmuted: list, lifted: list) -> list:
        return [("mute", u) for u in unmuted] + [("volume", u) for u in lifted]

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
                writes = self._restore_writes(*self._unmute_all_locked(cause, default_level, now))
                restored = True
                master = self._master_locked()
            else:
                # Every selected speaker moves, a muted one too: its kept
                # level follows and it stays muted
                current = round(sum(u.desired.volume for u in selected) / len(selected))
                new_master = _clamp(current + int(delta))
                master = new_master
                writes = [("volume", u) for u in self._scale_locked(selected, new_master, current, cause, now)]
            future = self._queue_writes_locked(writes)
            pending = self._publish_locked(cause, requester)
        return self._finish_intent(pending, future, master=master, muted=False, restored=restored)

    def _scale_locked(self, units: list, level: int, base, cause: Origin, now: float) -> list:
        """Move *units* so a group standing at *base* stands at *level*, each
        unit keeping its proportion. A zero base puts every unit at *level*.
        Returns the units whose level moved."""
        changed = []
        for u in units:
            d = u.desired
            new = level if base == 0 else _clamp(round(d.volume * level / base))
            if new != d.volume:
                d.volume = new
                self._stamp(u, cause, now)
                changed.append(u)
        return changed

    def set_master(self, level: int, cause: Origin, *, default_level: int,
                   requester: Optional[str] = None) -> Applied:
        """Bring the selected speakers the player has to *level* together,
        keeping their proportions. A muted selection is restored first, unless
        the level is 0, which leaves it muted."""
        self._touched = True
        now = self._clock()
        level = _clamp(level)
        with self._lock:
            if not self._connected:
                return self._refused("not_connected")
            selected = self._selected_locked(online_only=True)
            if not selected:
                return self._refused("no_active_outputs")
            restored = False
            unmuted, lifted = [], []
            if self._muted_all_locked():
                if level == 0:
                    return Applied(
                        version=store().snapshot().version, outcome=None,
                        master=self._master_locked(online_only=True), muted=True,
                    )
                unmuted, lifted = self._unmute_all_locked(cause, default_level, now)
                restored = True
            # Every selected speaker the player has moves, a muted one too: its
            # kept level follows and it stays muted
            base = sum(u.desired.volume for u in selected) / len(selected)
            moved = self._scale_locked(selected, level, base, cause, now)
            levels = lifted + [u for u in moved if u not in lifted]
            future = self._queue_writes_locked(self._restore_writes(unmuted, levels))
            master = self._master_locked(online_only=True)
            pending = self._publish_locked(cause, requester)
        return self._finish_intent(pending, future, master=master, muted=False, restored=restored)

    def mute_all(self, cause: Origin, *, requester: Optional[str] = None,
                 except_id: Optional[str] = None) -> Applied:
        """Mute every selected speaker. With *except_id*, every one but that
        speaker (a Pause holds it instead), and the mute is not carried over
        to speakers switched on later."""
        self._touched = True
        now = self._clock()
        with self._lock:
            if not self._connected:
                return self._refused("not_connected")
            selected = [u for u in self._selected_locked() if u.id != except_id]
            if not selected:
                return self._refused("no_active_outputs")
            writes = []
            tokens = []
            for u in selected:
                d = u.desired
                if d.muted:
                    if cause == Origin.USER:
                        # The user's Mute owns a mute a device Pause made.
                        d.mute_token = self._next_token_locked()
                        d.mute_joined = False
                        tokens.append((u.id, d.mute_token))
                    continue
                d.muted = True
                d.mute_token = self._next_token_locked()
                d.mute_joined = False
                tokens.append((u.id, d.mute_token))
                self._stamp(u, cause, now)
                writes.append(("mute", u))
            if except_id is None:
                self._mute_held = True
            future = self._queue_writes_locked(writes)
            master = self._master_locked()
            token_at = self._mute_counter
            pending = self._publish_locked(cause, requester)
        return self._finish_intent(
            pending, future, master=master, muted=True,
            mute_tokens=tuple(tokens), token_at=token_at,
        )

    def unmute_all(self, cause: Origin, *, default_level: int,
                   requester: Optional[str] = None) -> Applied:
        self._touched = True
        now = self._clock()
        with self._lock:
            if not self._connected:
                return self._refused("not_connected")
            if not self._selected_locked():
                return self._refused("no_active_outputs")
            writes = self._restore_writes(*self._unmute_all_locked(cause, default_level, now))
            future = self._queue_writes_locked(writes)
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
            writes = []
            tokens = []
            if d.selected and not d.muted:
                d.muted = True
                d.mute_token = self._next_token_locked()
                d.mute_joined = False
                tokens.append((u.id, d.mute_token))
                self._stamp(u, cause, now)
                writes.append(("mute", u))
            elif d.selected and cause == Origin.USER:
                # The user's Mute owns a mute a device Pause made.
                d.mute_token = self._next_token_locked()
                d.mute_joined = False
                tokens.append((u.id, d.mute_token))
            future = self._queue_writes_locked(writes)
            token_at = self._mute_counter
            pending = self._publish_locked(cause, requester)
        return self._finish_intent(pending, future, mute_tokens=tuple(tokens), token_at=token_at)

    def _restore_locked(self, u: UnitState, cause: Origin, default_level: int, now: float) -> bool:
        """End a unit's mute. A unit kept at 0 is lifted to *default_level*
        when that is above 0; True when it was, so a level write is due too."""
        d = u.desired
        self._clear_mute_locked(d)
        lifted = d.volume == 0 and default_level > 0
        if lifted:
            d.volume = _clamp(default_level)
        self._stamp(u, cause, now)
        return lifted

    def _restore_writes_one_locked(self, u: UnitState, cause: Origin, default_level: int, now: float) -> list:
        """The writes that end a unit's mute: the mute, and its level when
        it was lifted from 0."""
        lifted = self._restore_locked(u, cause, default_level, now)
        return [("mute", u)] + ([("volume", u)] if lifted else [])

    def _release_mute_hold_locked(self) -> None:
        if not any(u.desired.muted for u in self._selected_locked()):
            self._mute_held = False

    def unmute(self, unit_id: str, cause: Origin, *, default_level: int,
               requester: Optional[str] = None, only_token: Optional[int] = None) -> Applied:
        """End one unit's mute. With *only_token*, only while the unit's
        current mute is the one that token names, checked and changed under
        one hold of the lock. A call that changes nothing makes no write and
        publishes nothing."""
        self._touched = True
        now = self._clock()
        with self._lock:
            u = self._units.get(unit_id)
            if u is None:
                return self._refused("unknown_output")
            d = u.desired
            if not d.muted or (only_token is not None and d.mute_token != only_token):
                return Applied(version=store().snapshot().version, outcome=None)
            writes = self._restore_writes_one_locked(u, cause, default_level, now)
            self._release_mute_hold_locked()
            future = self._queue_writes_locked(writes)
            pending = self._publish_locked(cause, requester)
        return self._finish_intent(pending, future)

    def unmute_joined(self, since_token: int, cause: Origin, *, default_level: int,
                      requester: Optional[str] = None) -> Applied:
        """End the mute of every selected unit whose mute came from joining a
        muted selection after *since_token*. Changes nothing, writes nothing
        and publishes nothing when there is none."""
        self._touched = True
        now = self._clock()
        with self._lock:
            ended = [
                u for u in self._selected_locked()
                if u.desired.muted and u.desired.mute_joined and u.desired.mute_token > since_token
            ]
            if not ended:
                return Applied(version=store().snapshot().version, outcome=None)
            writes = [w for u in ended for w in self._restore_writes_one_locked(u, cause, default_level, now)]
            self._release_mute_hold_locked()
            future = self._queue_writes_locked(writes)
            pending = self._publish_locked(cause, requester)
        return self._finish_intent(pending, future)

    def submit_pin(self, unit_id: str, pin: str, *, requester: Optional[str] = None, select: bool = False,
                   volume: Optional[int] = None, claimant: Optional[str] = None) -> Applied:
        """Without *select*, a write only: the PIN goes to the player and the
        desired state is untouched. With *select* (a player that answers at
        once), the speaker is wanted on as the user's select would make it,
        and the PIN and that start go in one request, whose outcome waits for
        the player's verdict on the PIN."""
        self._touched = True
        if not select:
            batch = _Batch(1)
            self._enqueue(_Write("pin", unit_id, 0, {"pin": pin}, [(batch, 0)]))
            self._after_intent()
            return Applied(version=store().snapshot().version, outcome=batch.future)
        now = self._clock()
        vol = None if volume is None else _clamp(volume)
        with self._lock:
            u = self._units.get(unit_id)
            if u is None:
                return self._refused("unknown_output")
            was_on = u.desired.selected
            self._begin_select_locked(u, Origin.USER, vol, requester, claimant, now)
            batch = _Batch(1)
            params = {"pin": pin, "select": True, "volume": vol, "cause": Origin.USER, "was_on": was_on}
            self._enqueue(_Write("pin", unit_id, u.desired_seq, params, [(batch, 0)],
                                 requester=requester, claimant=claimant))
            pending = self._publish_locked(Origin.USER, requester)
        return self._finish_intent(pending, batch.future)

    def note_session(self, active: bool) -> None:
        """Session edges. A session end clears the user's "silence" choice,
        the retry back-offs of speakers that failed to start, and every hold."""
        self._touched = True
        with self._lock:
            self._session_active = bool(active)
            self._items.put(("session", bool(active)))
            self._pending = {m.key for m in self._members} if active else set()
            if not active:
                self._silence_chosen = False
                for u in self._units.values():
                    u.group_hold_backoff = RETRY_MIN_S
                    u.retry_n = 0
                    u.retry_at = None
                    u.retry_limit = None
                    if u.desired.held:
                        # The player is told too, or it would hold the
                        # speaker into the next session
                        u.desired.held = False
                        u.hold_write_at = self._clock()
                        self._enqueue(_Write("hold", u.id, u.desired_seq, {}, []))
            pending = self._publish_locked(Origin.SESSION, None)
        pending.notify()
        self._after_intent()

    def device_volume_seen(self, unit_id: str, *, single: bool = True) -> None:
        """A volume was set on the speaker itself: stamped for the cause of
        the adoption that follows, and armed to apply to the other speakers
        when made at one speaker (*single*) on a unit neither muted nor held
        that autostream did not just write. It never ends a mute: the player
        does not report the level of a muted speaker; a turn of its knob
        arrives as a wake. A stray one on a held or muted unit is ignored."""
        self._touched = True
        now = self._clock()
        with self._lock:
            u = self._units.get(unit_id)
            if u is None:
                return
            u.device_volume_at = now
            d = u.desired
            if single and not d.muted and not d.held and not self._spread_held(u, now):
                u.report_at = now

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
            wait = min(wait, max(0.0, self._dirty_read_at() - now))
        if self._next_safety_read is not None:
            wait = min(wait, max(0.0, self._next_safety_read - now))
        lapse = live.pin_claim_lapse_in()
        if lapse is not None:
            wait = min(wait, lapse)
        policy = self._policy
        if policy is not None:
            try:
                deadline = policy.next_deadline()
            except Exception:
                LOG.exception("Output policy failed to give its next deadline")
                deadline = None
            if deadline is not None:
                wait = min(wait, max(0.0, deadline - now))
        return max(0.05, wait)

    def step(self, now: Optional[float] = None, *, block: float = 0.0) -> bool:
        """One worker iteration: take queued items, read if something changed
        or a read is due, run timers. The thread loops on it; tests call it
        directly. True when a stop was requested."""
        self._touched = True
        clock = None
        if now is None:
            now = self._clock()
            clock = self._clock
        if self._take_items(block, now, clock):
            return True
        if clock is not None:
            # The wait for the first item may have taken a while.
            now = clock()
        self._maintain_source(now)
        read_due = (self._dirty and now >= self._dirty_read_at()) or (
            self._next_safety_read is not None and now >= self._next_safety_read
        )
        if read_due:
            self._read_once(now)
        self._run_timers(now)
        policy = self._policy
        if policy is not None:
            try:
                policy.on_timer(now, store().snapshot().outputs)
            except Exception:
                LOG.exception("Output policy failed on a timer")
        return False

    def _dirty_read_at(self) -> float:
        """When a read asked for by a change may be made: after a failed
        read's back-off, and with events no sooner than a second after the
        last read, so a burst of transitions is read once."""
        return max(self._read_retry_at, self._next_changed_read)

    def _take_items(self, block: float, now: float,
                    clock: Optional[Callable[[], float]] = None) -> bool:
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
        if clock is not None and block > 0:
            now = clock()
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
            elif kind == "session":
                self._handle_session(payload)
        return stop

    def _handle_session(self, active: bool) -> None:
        policy = self._policy
        if policy is None:
            return
        try:
            policy.on_session(active)
        except Exception:
            LOG.exception("Output policy failed on a session edge")

    def _note_boot(self, boot: str) -> None:
        if self._boot_id is not None and boot != self._boot_id:
            self._boot_changed = True
        self._boot_id = boot

    def _handle_connected(self, info: ConnectInfo) -> None:
        if info.boot is not None:
            self._note_boot(info.boot)
        elif self._source is None or self._source.kind == "unix_socket":
            self._boot_id = None
        # Otherwise a boot id the socket gave stays through the polling
        # between two sockets of one boot; the next hello compares it.
        delivers = {"device_volume", "receiver_command"} <= set(info.capabilities)
        async_changed = None
        with self._lock:
            if info.boot is not None or info.capabilities:
                # Only the event channel's hello says what the player can do.
                self._start_volume_cap = "start_volume" in info.capabilities
                async_cap = "output_state" in info.capabilities
                if async_cap != self._model.outcome_events:
                    async_changed = async_cap
                self._model = dataclasses.replace(self._model, outcome_events=async_cap)
            changed = delivers != self._delivers_device_events
            self._delivers_device_events = delivers
            pending = self._publish_locked(Origin.BACKEND, None) if changed else None
        if pending is not None:
            pending.notify()
        if async_changed is not None:
            LOG.info("The player %s speaker transitions as events",
                     "reports" if async_changed else "no longer reports")
        self._dirty = True

    def _handle_disconnected(self, reason: str, now: float) -> None:
        if reason == DEGRADED:
            LOG.info("Event channel degraded; polling the player instead")
            self._ws_degraded_until = now + WS_DEGRADED_HOLD_S
            self._swap_source(PollEventSource(self._poll_interval), now)
            return
        self._maybe_restarted = True
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
            info = None
        if info is None or not info.reachable:
            # No answer says nothing about the channel: a source already
            # running (a socket reconnects by itself) is kept, and the next
            # probe is the regular one.
            if src is not None:
                return
            info = EventChannelInfo(kind="poll")
        elif info.kind == "websocket" and now < self._ws_degraded_until:
            info = EventChannelInfo(kind="poll", reachable=True)
        new = self._source_factory(info, backend.base_url, poll_interval=self._poll_interval)
        if src is not None and self._same_source(src, new):
            return
        self._swap_source(new, now)

    def _swap_source(self, new: EventSource, now: float) -> None:
        old = self._source
        self._source = new
        with self._lock:
            self._event_kind = new.kind
            if new.kind != "unix_socket":
                self._delivers_device_events = False
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
        # Events carry each transition, so the reads they ask for are spaced out
        self._next_changed_read = now + CHANGED_READ_MIN_S if self._model.outcome_events else 0.0
        if result.ok:
            self._on_read_ok(list(result.outputs), now)
        else:
            self._on_read_failed(result, now)

    def _on_read_failed(self, result: ListOutputsResult, now: float) -> None:
        pending = None
        with self._lock:
            # A player that waits for its speakers may be too busy to answer a
            # read; one that answers at once and reports by events is not
            exempt = not self._model.outcome_events and (
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
            if not self._connected and self._ever_connected:
                # Back after an unreachable spell: look at the channel again.
                self._force_probe = True
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
        return self._model.availability(row, selected)

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
        d.held = False
        self._clear_mute_locked(d)
        u.attempt = False
        u.retry_at = None
        u.retry_limit = None
        u.start_pending_until = 0.0
        u.held_until = 0.0
        u.reselect_retry = False
        u.desired_seq += 1
        d.changed_at = now

    def _failed_treatment_locked(self, u: UnitState, now: float) -> None:
        """A start failed on a speaker the user did not just ask for (or one
        that timed out): keep it wanted and retry it while a session plays, at
        gaps of 10 s, 20 s and 30 s and then every 30 s. Otherwise it is
        turned back off at once. A speaker that failed while it played gets
        MIDSESSION_RETRIES retries; when they are spent it is switched off
        and the failure reported."""
        if u.retry_limit is not None and u.retry_n >= u.retry_limit:
            self._revert_locked(u, now)
            if not u.failure_reported:
                u.failure_reported = True
                self._start_failure_locked(u, u.fail_notice)
            return
        if u.retry_allowed and self._session_active:
            u.availability = "failed"
            if u.retry_at is None:
                u.retry_at = now + _retry_gap(u.retry_n)
                u.retry_n += 1
        else:
            self._revert_locked(u, now)

    def _is_default_unit_locked(self, u: UnitState) -> bool:
        """Whether the unit is one of the session's default speakers."""
        return self._session_active and any(
            mu is not None and mu.id == u.id for mu in (self._member_unit_locked(m) for m in self._members))

    def _merge_locked(self, rows: list, now: float, fx: _Effects) -> None:
        if not self._model.session_rows and any(row.session_state != "" for row in rows):
            self._model = dataclasses.replace(self._model, session_rows=True)
        if any(row.has_homepods is not None for row in rows):
            self._include_tv_supported = True
        boot_changed = self._boot_changed
        self._boot_changed = False
        maybe_restarted = self._maybe_restarted
        self._maybe_restarted = False
        if not self._connected or maybe_restarted:
            if self._boot_id is None:
                if self._ever_connected:
                    boot_changed = True
                    self._start_volume_cap = False
                    if self._model.outcome_events:
                        fx.log(logging.INFO, "The player no longer reports speaker transitions as events")
                    self._model = dataclasses.replace(self._model, outcome_events=False)
                self._epoch += 1
            self._connected = True
            self._ever_connected = True
        self._backend_boot = self._boot_id if self._boot_id is not None else f"epoch:{self._epoch}"
        if boot_changed:
            self._backend_restarts += 1
            for u in self._units.values():
                u.desired.held = False
            self._ws_degraded_until = 0.0
            for u in self._units.values():
                u.after_boot = True
            if self._spread_burst is not None:
                self._end_burst_locked(fx)

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
                        selected=row.selected, volume=row.volume_percent,
                        muted=row.selected and row.muted,
                        cause=Origin.ADOPTED, changed_at=now,
                    ),
                    reported=row, seen_at=now,
                    select_seq=1 if row.selected else 0,
                )
                if u.desired.muted:
                    # autostream restarted while the speaker was muted: it
                    # shows muted at its level, as a held row is adopted held
                    u.desired.mute_token = self._next_token_locked()
                self._units[uid] = u
            else:
                if row.has_homepods and u.held_until > 0.0 and not (u.reported is not None and u.reported.has_homepods):
                    # The HomePods the select was waiting for have appeared.
                    u.held_until = 0.0
                    u.group_hold_backoff = RETRY_MIN_S
                    if u.desired.selected and not row.selected:
                        self._queue_reapply_select_locked(u)
                u.reported = row
                u.name = row.name
                u.seen_at = now
                u.absent_since = None
            self._update_unit_locked(u, row, now, fx)
        self._row_order = order

        default_units = {
            mu.id for mu in (self._member_unit_locked(m) for m in self._members) if mu is not None
        }
        for uid in list(self._units):
            if uid in seen:
                continue
            u = self._units[uid]
            # A set member's card is never dropped: it reads offline until the
            # player has a row for it again.
            is_default = uid in default_units
            if u.absent_since is None:
                if boot_changed or u.was_streaming or is_default:
                    u.absent_since = now
                    u.reported = None
                    u.availability = "gone"
                else:
                    del self._units[uid]
            elif now - u.absent_since >= ABSENT_KEEP_S and not is_default:
                del self._units[uid]

    def _follow_hold_locked(self, u: UnitState, row: OutputInfo, now: float) -> None:
        """Take the player's word on a hold once no hold write of ours is
        queued, running or just done: a held row is adopted (autostream
        restarted while the speaker was held), and a hold the player no
        longer has is over (its session ended or was restarted)."""
        d = u.desired
        if not (self._model.follows_hold and d.selected):
            return
        if self._inflight > 0 or any(w.kind == "hold" and w.unit_id == u.id for w in self._wq):
            return
        if now - u.hold_write_at < DEBOUNCE_S:
            return
        if row.session_held != d.held:
            d.held = row.session_held

    def _update_unit_locked(self, u: UnitState, row: OutputInfo, now: float, fx: _Effects,
                            outcome_handled: bool = False) -> None:
        """Take a row (read, or an event's merged row) as the unit's. With
        *outcome_handled* the event that brought it has already applied its
        failed start, so the failure is not applied again here."""
        was = u.was_streaming
        d = u.desired
        sel = d.selected
        self._follow_hold_locked(u, row, now)
        avail = self._availability_locked(row, sel)
        model = self._model
        u.was_streaming = model.streaming(row)
        result_shown = model.result_shown(row, avail)
        if u.was_streaming and not was:
            u.ok_since = now
        if u.start_pending_until > 0.0:
            pending = PendingStart.WAIT if result_shown else model.pending_start(row)
            if result_shown or pending is PendingStart.NO_WAIT:
                # Shown; or the player took the speaker while nothing plays
                # and starts it with the playback, so there is nothing to wait for
                u.start_pending_until = 0.0
            elif pending is PendingStart.FAILED:
                u.start_pending_until = 0.0
                avail = "failed"
            elif now < u.start_pending_until:
                avail = "starting"
        elif (model.off_means_between_retries and sel and not row.selected and u.attempt
              and u.retry_at is not None and avail != "password"):
            # A player that cannot report a failed start: the speaker is
            # wanted, its start has ended and it is off, so it is between retries.
            avail = "failed"
        previous = u.availability
        u.availability = avail
        if row.selected == sel:
            u.after_boot = False
        if u.reselect_retry and sel and not row.selected:
            # A restart's select was refused while the unit was still on; it
            # reads off now, which is the state that select needed.
            u.reselect_retry = False
            self._queue_select_again_locked(u, None, None)
        if sel and avail == "ok" and result_shown and u.attempt:
            # The start the authority made has shown its result. A group still
            # missing a speaker keeps its place in the retry schedule.
            u.attempt = False
            u.failure_reported = False
            u.retry_at = None
            if row.members_missing == 0:
                u.retry_n = 0
            u.retry_limit = None
            u.group_hold_backoff = RETRY_MIN_S
        if (not outcome_handled and sel and model.authority_retries_loss and avail == "failed" and was
                and not u.attempt and self._session_active and u.retry_at is None):
            # It failed while it played (it went away, or closed its session):
            # tried again a few times before it is given up, with no notice
            # until then. A player that reports events retries it itself, and
            # its give-up is handled with the event (_handle_output_state).
            u.retry_allowed = True
            u.retry_n = 0
            u.retry_limit = MIDSESSION_RETRIES
            u.failure_reported = False
            self._failed_treatment_locked(u, now)
        if sel and previous == "starting" and avail == "ok":
            fx.republish = True
        if not outcome_handled and sel and u.attempt and avail == "failed":
            # Only a start the user asked for is reported; the ones the
            # appliance keeps retrying are not.
            if not u.retry_allowed:
                if not u.failure_reported:
                    u.failure_reported = True
                    self._start_failure_locked(u, "failed")
                self._revert_locked(u, now)
            else:
                self._failed_treatment_locked(u, now)

    def _adopt_volume_locked(self, u: UnitState, r: OutputInfo, now: float) -> Optional[bool]:
        """Take the level the row reports. None when deferred (a write is in
        flight or has just finished), False when it already matches, True
        when it was adopted."""
        d = u.desired
        if self._inflight > 0 or now - u.own_write_at < DEBOUNCE_S:
            return None
        if r.volume_percent == d.volume:
            return False
        # A row's level is the speaker's own level, muted or not
        d.volume = r.volume_percent
        d.cause = Origin.DEVICE if now - u.device_volume_at < DEVICE_VOLUME_MARK_S else Origin.BACKEND
        d.changed_at = now
        u.desired_seq += 1
        return True

    # -- timers and reconcile ------------------------------------------------

    def _run_timers(self, now: float) -> None:
        fx = _Effects()
        pending = None
        follow = self._read_spread_setting()
        with self._lock:
            changed = False
            for u in list(self._units.values()):
                if u.start_pending_until > 0.0 and now >= u.start_pending_until:
                    u.start_pending_until = 0.0
                    if not u.retry_allowed:
                        self._start_failure_locked(u, "timed_out")
                        u.failure_reported = True
                    self._failed_treatment_locked(u, now)
                    changed = True
                if u.pin_sinks and now >= u.pin_deadline:
                    # No verdict on the PIN yet: its request is answered as
                    # pending, and the speaker's row says the rest
                    fx.completions.append((u.pin_sinks, WriteOutcome(ok=True, pending=True)))
                    u.pin_sinks = []
                if u.absent_since is not None and now - u.absent_since >= ABSENT_KEEP_S:
                    del self._units[u.id]
                    changed = True
            if any(live.pin_claim(uid) != who for uid, who in self._claims_published.items()):
                changed = True      # a PIN claim has lapsed
            if self._connected:
                changed = self._reconcile_locked(now, fx, follow) or changed
            b = self._spread_burst
            if b is not None and (not follow or not self._session_active or b.expired(now)):
                self._end_burst_locked(fx)
            if changed:
                origin, requester = fx.publish_as or (Origin.BACKEND, None)
                pending = self._publish_locked(origin, requester)
        if pending is not None:
            pending.notify()
        fx.run()
        self._after_intent()

    def _queue_reapply_select_locked(self, u: UnitState) -> None:
        self._new_attempt_locked(u)
        u.retry_allowed = True
        u.requester = None
        u.claimant = None
        self._queue_select_again_locked(u, u.desired.volume, u.desired.cause)

    def _queue_restart_locked(self, u: UnitState) -> None:
        """Switch a selected speaker off and on again, as a retry the
        authority makes."""
        self._new_attempt_locked(u)
        u.retry_allowed = True
        u.requester = None
        u.claimant = None
        self._enqueue(_Write("deselect", u.id, u.desired_seq, {}, []))
        self._enqueue(_Write(
            "select", u.id, u.desired_seq,
            {"volume": None, "offset_ms": None, "mode": None, "cause": None, "reselect": True}, [],
        ))

    def _queue_select_again_locked(self, u: UnitState, volume: Optional[int], cause: Optional[Origin]) -> None:
        batch = _Batch(1)
        self._enqueue(_Write(
            "select", u.id, u.desired_seq,
            {"volume": volume, "offset_ms": None, "mode": None, "cause": cause},
            [(batch, 0)], requester=u.requester,
        ))

    def _due(self, u: UnitState, key: str, now: float) -> bool:
        """True once a difference of kind *key* has lasted DEBOUNCE_S."""
        since = u.diff_since.setdefault(key, now)
        return now - since >= DEBOUNCE_S

    def _spread_held(self, u: UnitState, now: float) -> bool:
        """Written by autostream, or started playing, too recently to be a reporter."""
        return now - max(u.own_write_at, u.ok_since) < spread.SPREAD_HOLD_S

    def _reconcile_locked(self, now: float, fx: _Effects, follow: bool = False) -> bool:
        """Compare reported with desired and queue what repairs a difference.
        True when a unit changed. Runs on the worker, under _lock; it only
        queues writes. *follow* is whether a volume change made at a speaker
        applies to the other playing speakers."""
        changed = False
        restored = 0
        busy = self._inflight > 0 or bool(self._wq)
        for u in self._ordered_units_locked():
            r = u.reported
            if r is None:
                continue
            d = u.desired
            if self._default_short_locked(u, r):
                # A default speaker the player gave up on, or a group of one
                # still missing a speaker: selected again on the retry
                # schedule while the session plays. The select starts only
                # what is not playing.
                if u.retry_at is None:
                    u.retry_at = now + _retry_gap(u.retry_n)
                    u.retry_n += 1
                elif now >= u.retry_at and not busy:
                    u.retry_at = None
                    self._queue_reapply_select_locked(u)
                    busy = True
                    changed = True
                    continue
            elif (self._model.outcome_events and u.availability == "ok" and r.members_missing == 0
                    and not u.attempt and u.retry_at is not None):
                # Whole again on its own: the schedule starts afresh next time
                u.retry_at = None
                u.retry_n = 0
            if (d.selected and r.selected and u.availability == "failed" and u.retry_at is not None
                    and now >= u.retry_at and self._session_active and not busy):
                # A speaker that failed while it played stays selected on the
                # player with its session failed: restart it.
                u.retry_at = None
                self._queue_restart_locked(u)
                busy = True
                continue
            if d.selected != r.selected and (busy or now - u.own_write_at < DEBOUNCE_S):
                # A write of ours is queued, running or has just finished, so
                # the row read may predate it; judge the next read.
                u.diff_since.pop("select", None)
                u.diff_since.pop("deselect", None)
                continue
            if d.selected and not r.selected:
                u.diff_since.pop("deselect", None)
                if u.availability == "password" \
                        or r.session_state in ("startup", "connecting", "connected", "stopping") \
                        or u.start_pending_until > now:
                    u.diff_since.pop("select", None)
                elif u.availability == "failed":
                    if u.retry_at is not None and now >= u.retry_at and self._session_active:
                        u.retry_at = None
                        self._queue_reapply_select_locked(u)
                elif now < u.held_until:
                    # The player cannot take this select yet; it is tried
                    # again when the hold ends or its HomePods appear.
                    u.diff_since.setdefault("select", now)
                elif self._model.reselects_an_off_row:
                    if self._due(u, "select", now):
                        u.diff_since.pop("select", None)
                        restored += 1 if u.after_boot else 0
                        self._queue_reapply_select_locked(u)
                elif u.after_boot:
                    if self._due(u, "select", now):
                        u.diff_since.pop("select", None)
                        restored += 1
                        self._queue_reapply_select_locked(u)
                elif u.attempt and u.retry_allowed and self._session_active                         and now - u.own_write_at < START_PENDING_S:
                    # A start the authority made or will retry: not a pause on
                    # the speaker.
                    u.diff_since.pop("select", None)
                else:
                    # A player without session reports deselected itself (a
                    # device pause, a failed start): follow it.
                    d.selected = False
                    self._clear_mute_locked(d)
                    d.cause = Origin.BACKEND
                    u.attempt = False
                    u.desired_seq += 1
                    changed = True
                continue
            u.diff_since.pop("select", None)
            if not d.selected and r.selected:
                if live.pin_claim(u.id):
                    # A PIN is being entered for it: the player starts it
                    # again for the next PIN itself
                    u.diff_since.pop("deselect", None)
                    continue
                if self._due(u, "deselect", now):
                    u.diff_since.pop("deselect", None)
                    batch = _Batch(1)
                    self._enqueue(_Write("deselect", u.id, u.desired_seq, {}, [(batch, 0)]))
                continue
            u.diff_since.pop("deselect", None)
            if d.selected and r.selected and r.muted != d.muted:
                # The row may predate a write of ours that is queued, running
                # or just made: judge a later read, keeping the time the
                # difference was first seen
                due = self._due(u, "mute", now)
                if due and not (busy or now - u.own_write_at < DEBOUNCE_S):
                    u.diff_since.pop("mute", None)
                    self._enqueue(_Write("mute", u.id, u.desired_seq, {}, []))
                    fx.log(logging.INFO, "Mute of %s repaired: the player reads it %s",
                           self._unit_name_locked(u.id), "muted" if r.muted else "unmuted")
                    busy = True
            else:
                u.diff_since.pop("mute", None)
            if not busy:
                # With a write queued the row read may predate it, as above.
                before = d.volume
                adopted = self._adopt_volume_locked(u, r, now)
                if adopted:
                    changed = True
                if adopted is not None and self._spread_locked(u, before, adopted, follow, now, fx):
                    # The targets' rows predate the writes just queued.
                    busy = True
        if restored:
            fx.log(logging.WARNING, "Output selection restored after the player restarted: %d output(s)", restored)
        return changed

    def _spread_locked(self, u: UnitState, before: int, adopted: bool, follow: bool,
                       now: float, fx: _Effects) -> bool:
        """u's row was just compared with its desired level (not deferred); it
        moved from *before* when *adopted*. Consume u's arm when the row is
        newer than it, and when that was a report made at the speaker, apply
        it to the other playing speakers. True when a write was queued."""
        if u.seen_at < u.report_at:
            # The row predates the event; keep the arm for the read that follows.
            return False
        armed = u.report_at > u.report_used_at and now - u.report_at < spread.SPREAD_REPORT_S
        u.report_used_at = u.report_at
        if not (follow and armed and adopted):
            return False
        if not (self._session_active and self._delivers_device_events):
            return False
        d = u.desired
        # A silent speaker (held or muted) is never the one that moves the others
        if not (d.selected and not d.muted and not d.held and u.reported is not None
                and u.availability == "ok"):
            return False
        if self._spread_held(u, now):
            return False
        d.cause = Origin.DEVICE
        fx.publish_as = (Origin.DEVICE, f"device:{u.id}")
        # Every other playing speaker follows, a silent one too: its kept
        # level moves and it stays silent
        targets = [t for t in self._selected_locked(online_only=True) if t.id != u.id]
        b = self._spread_burst
        if b is not None and (b.reporter != u.id or b.expired(now) or self._foreign_locked(b)):
            self._end_burst_locked(fx)
            b = None
        if b is None:
            if not targets:
                return False
            b = spread.Burst(
                reporter=u.id, reporter_old=before,
                base={t.id: t.desired.volume for t in targets},
                seqs={t.id: t.desired_seq for t in targets},
                last_at=now,
            )
            self._spread_burst = b
        levels = spread.spread_levels(b.base, b.reporter_old, d.volume)
        moved = []
        for t in targets:
            if t.id in levels and levels[t.id] != t.desired.volume:
                t.desired.volume = levels[t.id]
                self._stamp(t, Origin.DEVICE, now)
                moved.append(t)
        b.note_spread(now, d.volume, {t.id: (t.desired_seq, t.desired.volume)
                                      for t in targets if t.id in levels})
        self._queue_volume_writes_locked(moved)
        return bool(moved)

    def _foreign_locked(self, b: spread.Burst) -> bool:
        """True when a unit of the burst changed in a way the burst did not make."""
        return any(uid in self._units and self._units[uid].desired_seq != seq
                   for uid, seq in b.seqs.items())

    def _unit_name_locked(self, uid: str) -> str:
        u = self._units.get(uid)
        if u is None:
            return uid
        return u.reported.name if u.reported is not None else (u.name or uid)

    def _end_burst_locked(self, fx: _Effects) -> None:
        """Forget the open burst; log it once when it moved anything."""
        b = self._spread_burst
        self._spread_burst = None
        if b is None:
            return
        moved = b.moved()
        if not moved:
            return
        text = ", ".join(
            "%s %d -> %d" % (self._unit_name_locked(uid), b.base[uid], b.after[uid]) for uid in moved
        )
        fx.log(logging.INFO, "Speaker volume applied to all: %s %d -> %d; moved %s",
               self._unit_name_locked(b.reporter), b.reporter_old, b.reporter_new, text)

    # -- device events -------------------------------------------------------

    def _handle_event(self, ev: DeviceEvent, now: float) -> None:
        if ev.kind == "output_state":
            # A speaker's transition is the authority's alone; the policy has
            # nothing to do with it
            self._handle_output_state(ev, now)
            return
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
                self.device_volume_seen(uid, single=ev.speaker_id != "0")
        elif ev.kind == "receiver_command":
            if self._policy is None:
                LOG.info(
                    "receiver command %s from %s: no policy, ignored",
                    ev.verb, ev.speaker_name or ev.speaker_id,
                )
        policy = self._policy
        if policy is not None:
            try:
                policy.on_device_event(ev, store().snapshot().outputs, now)
            except Exception:
                LOG.exception("Output policy failed on a device event")

    def _handle_output_state(self, ev: DeviceEvent, now: float) -> None:
        """A speaker moved: apply a failed start's reason once, then take the
        event's row values as the unit's row, as a read would."""
        fx = _Effects()
        pending = None
        with self._lock:
            uid = self._unit_for_device_locked(ev.speaker_id)
            u = self._units.get(uid) if uid is not None else None
            if u is None or u.reported is None or ev.state not in _EVENT_STATES:
                # Unknown to us, or a state this version does not know: the list says
                self._dirty = True
                fx.log(logging.DEBUG, "Output state %s for %s: reading the outputs", ev.state, ev.speaker_id)
            else:
                fx.log(logging.DEBUG, "Output state %s (%s; member %s %s) for %s", ev.state, ev.reason or "none",
                       ev.member_id or ev.speaker_id, ev.member_state or "-", self._unit_name_locked(u.id))
                handled = False
                failure = ev.state in ("failed", "password")
                stale = self._outcome_stale_locked(u) if failure else True
                if failure and not stale:
                    default = ("pin_required", "pin_required") if ev.state == "password" else ("failed", "failed")
                    code, notice = _EVENT_OUTCOMES.get(ev.reason, default)
                    if code is not None:
                        self._select_outcome_locked(u, code, notice, u.requester, u.claimant, False, now, fx)
                        handled = True
                if not handled and self._player_gave_up_locked(u, ev):
                    # The player has made its quick retry and given up: a speaker
                    # that is not a default is switched off, and the failure
                    # reported. A default one is retried by the reconcile.
                    self._revert_locked(u, now)
                    self._start_failure_locked(u, session_failure_for("failed", ev.reason))
                    handled = True
                self._settle_pin_locked(u, ev, fx)
                u.reported = self._merged_row(u.reported, ev)
                # A failure that belongs to an older attempt, or was applied
                # already, is merged but not applied (again) by the row either
                self._update_unit_locked(u, u.reported, now, fx,
                                         outcome_handled=handled or (failure and stale and u.attempt))
                pending = self._publish_locked(Origin.BACKEND, None)
        if pending is not None:
            pending.notify()
        fx.run()
        self._after_intent()

    def _default_short_locked(self, u: UnitState, r: OutputInfo) -> bool:
        """Whether a default speaker, with a player that reports events, is
        wanted but not fully playing: the player gave up on it (it reads
        failed), or its group is missing a speaker. No start of ours is
        waiting for its result."""
        return (self._model.outcome_events and u.desired.selected and self._session_active and not u.attempt
                and (u.availability == "failed" or r.members_missing > 0)
                and self._is_default_unit_locked(u))

    def _player_gave_up_locked(self, u: UnitState, ev: DeviceEvent) -> bool:
        """Whether *ev* is a player that reports events giving up on a wanted
        speaker that is not a default: its row reads failed (a speaker the
        player still retries reads connecting), whatever its selection says,
        and no start of ours is waiting for its result."""
        return (self._model.outcome_events and ev.state == "failed" and u.desired.selected
                and self._session_active and (not u.attempt or u.outcome_applied)
                and not self._is_default_unit_locked(u))

    @staticmethod
    def _merged_row(row: OutputInfo, ev: DeviceEvent) -> OutputInfo:
        """*row* with what the event says about it; a field the event leaves
        out keeps the row's value. The time the row was read is not moved."""
        fields = dict(session_state=ev.state, session_failure=session_failure_for(ev.state, ev.reason))
        for name, value in (("selected", ev.selected), ("session_held", ev.held),
                            ("session_holdable", ev.holdable), ("muted", ev.muted),
                            ("volume_percent", ev.volume), ("pin_pending", ev.pin_pending),
                            ("members_missing", ev.members_missing)):
            if value is not None:
                fields[name] = value
        return dataclasses.replace(row, **fields)

    def _outcome_stale_locked(self, u: UnitState) -> bool:
        """Whether an event's failure is not this unit's current start to
        report: the unit is not wanted, no start of ours is waiting for its
        result, that result was applied already, or a newer start is still
        queued (the event is about the one before)."""
        return (not u.desired.selected or not u.attempt or u.outcome_applied
                or self._start_queued_locked(u.id))

    def _start_queued_locked(self, uid: str) -> bool:
        # _lock, then the write queue's leaf lock: the order _enqueue takes
        with self._wq_cond:
            return any(w.unit_id == uid and (w.kind == "select" or (w.kind == "pin" and w.params.get("select")))
                       for w in self._wq)

    def _settle_pin_locked(self, u: UnitState, ev: DeviceEvent, fx: _Effects) -> None:
        """A PIN sent with its select is answered by the event that ends the
        authorise: a refusal or a new prompt; the speaker paired (stopped
        with pin_pending false, or connected or streaming when that event
        came before the answer was parked); or the pairing cancelled by a
        switch-off. The authorise's own connecting, which may read
        pin_pending false when the speaker was not waiting for a PIN, says
        nothing yet, and while the authorise runs the waiters keep waiting."""
        if not u.pin_sinks:
            return
        if ev.state in ("failed", "password"):
            # A pairing that ran out of time is named as a notice names it, so
            # it is not taken for a request that went unanswered
            code = {"timeout": "timed_out", "": "failed", "none": "failed"}.get(ev.reason, ev.reason)
            outcome = WriteOutcome(ok=False, error_code=code, error=code)
        elif ev.state == "stopped" and ev.reason == "cancelled":
            outcome = WriteOutcome(ok=False, error_code="cancelled", error="cancelled")
        elif ev.state in ("stopped", "connected", "streaming") and ev.pin_pending is False:
            outcome = WriteOutcome(ok=True)
        else:
            return
        fx.completions.append((u.pin_sinks, outcome))
        u.pin_sinks = []
        u.pin_deadline = 0.0

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
            held_unit = self._units.get(w.unit_id) if w.unit_id is not None else None
            availability_before = held_unit.availability if held_unit is not None else None
            runner = self._build_locked(w, include)
            if runner is None or runner is _HOLD:
                fx = _Effects()
                outcome = WriteOutcome(ok=True, pending=runner is _HOLD)
                # A held select changes nothing a page shows after the first
                # time, so it publishes only when the unit's availability moved.
                moved = held_unit is not None and held_unit.availability != availability_before
                pending = self._publish_locked(Origin.BACKEND, None) if runner is _HOLD and moved else None
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
        if outcome is None:
            # Parked on the unit: an event or the timer completes the waiters
            return [pending], fx.run
        return [pending], (lambda: (fx.run(), self._complete(w, outcome)))

    def _build_locked(self, w: _Write, include: Optional[bool]):
        """The player calls for a write, built from desired state as it is
        now. None: nothing to send. _HOLD: not yet. Otherwise a function of
        the backend that returns the ActionResults."""
        kind = w.kind
        uid = w.unit_id
        u = self._units.get(uid) if uid is not None else None
        # A speaker the player has no row for takes no select or deselect; the
        # reconcile applies the desired state when its row returns.
        if kind == "select":
            if u is None or u.reported is None:
                return None
            d = u.desired
            # Every select carries the speaker's own level and its mute, so a
            # muted speaker starts silent and keeps that level.
            asked = w.params.get("volume")
            level = _clamp(d.volume if asked is None else asked)
            muted = d.muted
            kwargs = dict(
                enabled=True, volume_percent=level, muted=muted,
                offset_ms=w.params.get("offset_ms"), mode=w.params.get("mode"),
                timeout=WRITE_TIMEOUT_S,
            )
            if include is not None and self._include_tv_supported:
                if u.reported is not None and u.reported.has_homepods:
                    kwargs["include_tv"] = include
                elif include is False:
                    # The Apple TV is never selected alone: wait for its group.
                    u.availability = "starting"
                    u.held_until = self._clock() + u.group_hold_backoff
                    u.group_hold_backoff = min(u.group_hold_backoff * 2, RETRY_MAX_S)
                    return _HOLD
            if self._start_volume_cap:
                return lambda b: [b.update_output(uid, **kwargs)]

            def select_after_level(b):
                # A player that does not start a speaker at the level it is
                # enabled with is given the level first, so the start uses it.
                first = b.update_output(uid, volume_percent=level, muted=muted, timeout=WRITE_TIMEOUT_S)
                if not first.ok:
                    LOG.debug("Start level for %s not applied: %s", uid, first.message)
                return [b.update_output(uid, **kwargs)]
            return select_after_level
        if kind == "deselect":
            if u is None or u.reported is None:
                return None
            return lambda b: [b.update_output(uid, enabled=False, timeout=WRITE_TIMEOUT_S)]
        if kind == "volume":
            if u is None or not u.desired.selected:
                return None
            level = u.desired.volume
            return lambda b: [b.update_output(uid, volume_percent=level, timeout=WRITE_TIMEOUT_S)]
        if kind == "mute":
            # The mute as it is wanted now, as for a hold
            if u is None or u.reported is None or not u.desired.selected:
                return None
            muted = u.desired.muted
            return lambda b: [b.set_output_muted(uid, muted, timeout=WRITE_TIMEOUT_S)]
        if kind == "deselect_all":
            if w.params.get("session"):
                return lambda b: [b.stop_and_disable_all(timeout=WRITE_TIMEOUT_S)]
            return lambda b: [b.set_selected_outputs([], timeout=WRITE_TIMEOUT_S)]
        if kind == "pin":
            pin = w.params.get("pin", "")
            if not w.params.get("select"):
                return lambda b: [b.submit_output_pin(uid, pin, timeout=WRITE_TIMEOUT_S)]
            if u is None or u.reported is None:
                return None
            # The start the PIN unlocks carries the level and mute a select would
            asked = w.params.get("volume")
            level = _clamp(u.desired.volume if asked is None else asked)
            muted = u.desired.muted
            return lambda b: [b.submit_output_pin(uid, pin, select=True, volume_percent=level, muted=muted,
                                                  timeout=WRITE_TIMEOUT_S)]
        if kind == "hold":
            # The hold as it is wanted now: a hold and its end queued close
            # together send the latest twice, which the player takes as one.
            if u is None or u.reported is None or not u.desired.selected:
                return None
            held = u.desired.held
            return lambda b: [b.set_output_hold(uid, held, timeout=WRITE_TIMEOUT_S)]
        return None

    def _record_locked(self, w: _Write, results: list, now: float, fx: _Effects) -> Optional[WriteOutcome]:
        """The outcome of a write the player answered, recorded in the unit;
        None when its outcome waits for a later event (a PIN sent with its
        select to a player that answers at once)."""
        r = results[0] if results else ActionResult(ok=True)
        u = self._units.get(w.unit_id) if w.unit_id is not None else None
        if w.kind == "select":
            return self._record_select_locked(w, r, u, now, fx)
        if w.kind == "pin" and w.params.get("select"):
            return self._record_pin_select_locked(w, r, u, now, fx)
        if w.kind == "hold" and not r.ok and u is not None and u.desired.held:
            # The player could not hold it after all (its session changed
            # since its row was read): it plays on, and so it reads.
            u.desired.held = False
            fx.log(logging.INFO, "Hold of %s refused by the player (%s)", w.unit_id, r.error_code)
        if w.kind == "mute" and not r.ok:
            # The desired mute stands; the reconcile asks again once the row
            # still disagrees
            fx.log(logging.INFO, "Mute of %s refused by the player (%s)", w.unit_id, r.error_code)
        if r.ok or (w.kind == "volume" and r.error_code == "timeout"):
            if u is not None:
                u.own_write_at = now
        if r.ok:
            return WriteOutcome(ok=True)
        return WriteOutcome(ok=False, error_code=r.error_code, error=r.message)

    def _record_select_locked(self, w: _Write, r: ActionResult, u: Optional[UnitState],
                              now: float, fx: _Effects) -> WriteOutcome:
        stale = u is None or u.desired_seq != w.seq
        code = r.error_code
        if r.ok:
            # A failure event can arrive before the answer is recorded; it
            # stands, and the answer only says the request was accepted
            if u is not None:
                u.own_write_at = now
                if u.desired.selected and u.availability != "password" and not u.outcome_applied:
                    u.availability = "starting"
                    if self._model.outcome_events and not stale:
                        # Accepted, not started: the outcome comes as an
                        # event, and this guard ends a start that never says
                        u.start_pending_until = now + START_PENDING_S
            if w.params.get("cause") == Origin.USER:
                self._silence_chosen = False
            # A speaker that joins late gets the bundle once it exists.
            fx.republish = True
            return WriteOutcome(ok=True)
        if code in ("pin_required", "pin_invalid", "encoder_capacity"):
            if u is not None:
                self._select_outcome_locked(u, code, code, w.requester, None, stale, now, fx)
            return WriteOutcome(ok=False, error_code=code, error=r.message)
        if code == "timeout":
            # The player is still starting it: its command queue is busy, not down.
            # Whether it started is for the row to say; a read just after this
            # is not taken as the player's own change.
            if u is not None and not stale and not u.outcome_applied:
                u.own_write_at = now
                u.availability = "starting"
                u.start_pending_until = now + START_PENDING_S
            if self._model.outcome_events:
                fx.log(logging.WARNING, "Start of %s not answered in %.0f s by a player that answers at once",
                       self._unit_name_locked(w.unit_id), WRITE_TIMEOUT_S)
            return WriteOutcome(ok=True, error_code="timeout", pending=True)
        if code == "reselect_required":
            if w.params.get("reselect") and u is not None and not stale:
                # The switch-off did not take, so the unit was still on when
                # this select arrived; send it again once the unit reads off.
                u.reselect_retry = True
                return WriteOutcome(ok=False, error_code=code, error=r.message)
            fx.log(logging.WARNING, "include_tv change refused on a selected output (%s)", w.unit_id)
            return WriteOutcome(ok=False, error_code=code, error=r.message)
        if code == "group_not_present":
            if u is not None and not stale:
                u.availability = "starting"
            return WriteOutcome(ok=True, error_code=code, pending=True)
        if u is not None:
            self._select_outcome_locked(u, "failed", "refused", w.requester, None, stale, now, fx)
        return WriteOutcome(ok=False, error_code=code, error=r.message)

    def _record_pin_select_locked(self, w: _Write, r: ActionResult, u: Optional[UnitState],
                                  now: float, fx: _Effects) -> Optional[WriteOutcome]:
        """A PIN sent with its select. The player accepted it: the pairing
        runs, and the event that ends it answers the request (parked here
        until then, or until PIN_OUTCOME_S passes). A refusal is a failed
        start, as a select's would be; any 400 to a PIN reads as a wrong PIN.

        The request is parked even when the unit's desired state moved
        while it was queued (a level change while the PIN was typed): the
        pairing runs on the player all the same, so its outcome, not the
        answer, says whether the PIN was right, and the claim stays until it
        does."""
        stale = u is None or u.desired_seq != w.seq
        if r.ok and u is not None and self._model.outcome_events:
            r_now = u.reported
            if stale and u.outcome_applied and r_now is not None and r_now.session_state in ("failed", "password"):
                # The verdict came as an event before this answer
                code = {"timeout": "timed_out", "none": "failed"}.get(r_now.session_failure, r_now.session_failure)
                return WriteOutcome(ok=False, error_code=code, error=code)
            u.own_write_at = now
            if not stale or (u.desired.selected and not u.outcome_applied):
                u.start_pending_until = now + START_PENDING_S
            u.pin_sinks.extend(w.sinks)
            u.pin_deadline = now + PIN_OUTCOME_S
            fx.republish = True
            return None
        if r.error_code == "busy":
            # The player was still busy with the speaker and took neither the
            # PIN nor its start: the speaker goes back to how it was, with no
            # notice, and the PIN may be sent again in a moment
            if u is not None and u.desired.selected and not w.params.get("was_on"):
                self._revert_locked(u, now)
            fx.log(logging.INFO, "PIN for %s not taken: the player is busy with it", self._unit_name_locked(w.unit_id))
            fx.republish = True
            return WriteOutcome(ok=False, error_code="busy", error="busy")
        return self._record_select_locked(w, r, u, now, fx)

    def _select_outcome_locked(self, u: UnitState, code: str, notice: str, requester: Optional[str],
                               claimant: Optional[str], stale: bool, now: float, fx: _Effects) -> None:
        """The one place a failed start is applied, whether the verdict came
        in a request's answer or in an output_state event. *code* is
        pin_required, pin_invalid, encoder_capacity, no_clock or failed;
        *notice* is the reason a notice gives. A start the user asked for is
        turned back off with a notice; one the appliance made is retried
        while a session plays. *stale* (an answer to an older request) keeps
        the desired state as it is. *claimant*, given on the event path, is
        handed the PIN the speaker now shows."""
        if not stale:
            u.outcome_applied = True
        user = not u.retry_allowed
        if code in ("pin_required", "pin_invalid", "encoder_capacity"):
            # The speaker refused this start whoever asked; never retried
            if code == "pin_required":
                u.availability = "password"
            if not stale:
                self._revert_locked(u, now)
            self._start_failure_locked(u, notice, requester)
            if code == "pin_required" and claimant and not stale:
                fx.claims.append((u.id, claimant))
            return
        if stale:
            return
        if user or not self._session_active:
            self._revert_locked(u, now)
            if user:
                self._start_failure_locked(u, notice, requester)
            return
        if code == "no_clock" and u.retry_limit is None:
            # The speaker is not following the clock: a couple of tries, then the notice
            u.retry_limit = MIDSESSION_RETRIES
        u.fail_notice = notice
        self._failed_treatment_locked(u, now)


_AUTHORITY = OutputAuthority()


def get_authority() -> OutputAuthority:
    """The process's output authority; the single seam a test patches."""
    return _AUTHORITY
