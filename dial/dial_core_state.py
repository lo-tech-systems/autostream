"""dial_core_state.py — the dial's appliance state as plain data, plus the
pure decisions made over it.

Frozen snapshot dataclasses (collections as tuples, no side-effecting
methods) and reducers that take everything they need as arguments: no I/O,
no threads, no locks, no clock reads (the time is always passed in), and no
import of the display. Whoever owns the state (the core's fold) does the
reading and the writing, and calls these to decide.

Focus resolution and the walk live in dial_core_focus; appliance-supplied
warnings in dial_appliance_warnings.

Field order in every dataclass is append-only, so positional construction
stays valid as fields are added at the end.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from typing import Callable, Iterable

from dial_appliance_warnings import clean_text
from dial_mdns import appliance_display_name
from dial_network import NetworkView
from dial_repeat_store import RepeatRecord
from dial_sdhealth import SdHealthView
from dial_update_watch import UpdateView
from dial_values import is_int

# What this dial believes about its authorisation on one appliance.
AUTH_UNKNOWN = "unknown"
AUTH_AUTHORIZED = "authorized"
AUTH_UNAUTHORIZED = "unauthorized"

# How long an EQ tap's value is shown ahead of the appliance's own reading.
EQ_OPTIMISTIC_WINDOW_S = 2.0

SIX_BAND_EQ_VERSION = 2


def six_band(version: int) -> bool:
    """Whether an EQ capability version lists six bands of its own."""
    return version >= SIX_BAND_EQ_VERSION


# How long a replay the appliance has just accepted may be shown as playing
# before the appliance's own session state reaches the dial (normally a few
# seconds).
ACCEPTED_REPLAY_GRACE_S = 20.0

# How many consecutive "down" polls (15 s apart) open the No-WiFi page on
# their own: three, so a brief drop that recovers within about 45 s only
# ever flashes the icon. A tap on the flashing icon opens the page at once.
NOWIFI_PROMPT_STREAK = 3


# ---- row and now-playing types -------------------------------------------


@dataclass(frozen=True)
class NowPlaying:
    """Now-playing state for the overlay, as last folded by the core thread.
    Immutable — a changed state produces a new instance rather than mutating
    this one, which is what makes the `!=` comparison in the core's fold a
    reliable "did anything worth repainting change" check.
    """
    service_name: str
    artist: str
    title: str          # track title, drawn on the title line above the artist
    master_volume: int | None
    album: str = ""     # album name, drawn above the title where the layout has room
    # False for an idle or pending focus (an appliance is shown but nothing
    # is actually playing under it) — see the rich/large artist-row fallback
    # in _effective_overlay_locked. True (the default) for a real playback
    # walk result; also feeds the `!=` change check above, so a focused
    # appliance starting or stopping always triggers a repaint.
    playing: bool = True
    artwork_url: str = ""   # the selected track's artwork URL ("" = none)
    input_label: str = ""   # the appliance's name for the input ("CD"); "" when it sent none


# What stands in for a track the appliance has not named yet, on every view:
# a playing appliance with no title reads as playing rather than blank.
PLAYING_TEXT = "Playing"


def awaiting_title(now_playing: "NowPlaying | None") -> bool:
    """Whether the appliance is playing but has not named the track yet (a
    track change just detected, or the first moments of playback)."""
    return now_playing is not None and now_playing.playing and not now_playing.title


def title_fallback(now_playing: "NowPlaying | None") -> str:
    """What stands in for the title while the appliance plays an unnamed
    track: the input's label when the appliance sent one, else the fixed
    word. Empty when nothing is awaited."""
    if not awaiting_title(now_playing):
        return ""
    return now_playing.input_label or PLAYING_TEXT


@dataclass(frozen=True)
class SelectorRow:
    """One row of the appliance-selector screen — see ListScreenState."""
    appliance_id: str
    label: str        # appliance_display_name(service_name)
    current: bool     # this row is the focus (manual, else the reporting-from target)
    playing: bool = False  # the appliance is playing now, live or replay
    # False for an appliance confirmed to have refused this dial: listed but
    # marked, never focused or controlled (see selector_pick).
    authorized: bool = True
    # True for an appliance on another protocol than this dial's: listed but
    # marked, never focused or controlled.
    needs_update: bool = False


@dataclass(frozen=True)
class PickerRow:
    """One row of the replay picker — see ListScreenState."""
    appliance_id: str
    service_name: str
    ip: str
    port: int
    label: str        # appliance_display_name(service_name)
    seconds: float     # recording_seconds — the held buffer's length


@dataclass(frozen=True)
class OutputRow:
    """One row of the outputs list, or the output shown on the detail page."""
    id: str
    name: str
    selected: bool
    volume: int          # 0..100, meaningful when selected
    remote_in_use: bool = False      # owned by another appliance
    remote_owner: str | None = None  # that appliance's name once known; None until then
    is_default: bool = False         # the appliance's configured default output
    needs_auth_key: bool = False     # a speaker that has never been paired (its first PIN is still to be entered)
    paused: bool = False             # on, and held because it paused itself


# ---- appliance snapshot types --------------------------------------------


@dataclass(frozen=True)
class ApplianceState:
    appliance_id: str
    service_name: str
    name: str                 # appliance_display_name(service_name)
    ip: str
    port: int
    playing: bool             # in this tick's playing set (incl. the accepted-replay bridge)
    playing_since: float      # 0.0 when idle
    auth: str                 # AUTH_* above
    dial_status: bool
    dial_outputs: bool
    dial_eq: bool
    repeat_capable: bool
    dial_proto_version: int
    dial_outputs_version: int  # 0 = none, 1 = the first outputs capability
    status_error: str | None  # last fetch outcome this tick; None = ok or not fetched
    master_volume: int | None  # last good record's master_volume, else None
    muted: bool | None        # the observed mute flag, None = unknown
    repeat: RepeatRecord | None  # the repeat record at publish time
    webui_scheme: str = "http"   # where this appliance's web UI is reached:
    webui_host: str = ""         # its roster address, and the port it
    webui_port: int = 0          # serves the web UI and the dial API on
    warnings: tuple = ()             # its validated warnings, ApplianceWarning each


@dataclass(frozen=True)
class FocusState:
    manual_id: str | None
    bound_id: str | None
    pending: tuple[str, str, float] | None   # (appliance_id, service_name, expires_at)
    reporting_id: str | None
    source_service_name: str | None
    accepted_replay: tuple[str, float] | None  # (appliance_id, until)
    idle_focus: bool          # the reporting appliance is a focus with nothing playing under it


def artwork_key(url: str) -> str:
    """A stable, non-reversible local handle for an artwork URL: what the
    core and the views compare, cache and serve by, so the URL itself is
    never kept or logged."""
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class Artwork:
    url: str                  # the fetch handle, never logged; "" once the core holds it
    key: str                  # sha256(url)[:16]: a stable local handle to serve or cache by
    data: bytes               # the bytes as fetched (undecoded), bounded by the fetch limit
    content_type: str         # from the fetch, "" if unknown
    fetched_at: float


@dataclass(frozen=True)
class OutputsState:
    appliance_id: str
    rows: tuple[OutputRow, ...]          # as fetched, INCLUDING remote_in_use rows
    loaded: bool
    fetched_at: float


@dataclass(frozen=True)
class EqBand:
    id: str                   # "bass" | "treble" on capability 1; "peq1".."peq6" on capability 2
    frequency_hz: int | None  # None for the two derived controls of capability 1
    gain_db: int
    min_db: int
    max_db: int


@dataclass(frozen=True)
class EqState:
    appliance_id: str
    capability_version: int   # 1 = bass/treble, 2 = six bands
    bands: tuple[EqBand, ...]  # as fetched; () until the first fetch lands
    loaded: bool
    optimistic: tuple[tuple[str, int], ...]   # (band_id, gain) overrides, see expires_at
    optimistic_expires_at: float              # 0.0 when none


@dataclass(frozen=True)
class WarningState:
    id: str
    active: bool
    reading: object                # what the source reported; the descriptor reads it
    active_since: float | None     # wall clock; a change means a new incident


@dataclass(frozen=True)
class TransportRequest:
    appliance_id: str
    kind: str                 # "seek" | "stop" | "arm" | "output_set" | "output_pin"
    requested_at: float
    state: str                # "pending" | "accepted" | "rejected"
    changed_at: float
    error: str | None         # the error name of a rejection, else None
    output_id: str | None = None   # the output an output request was for
    retry_after_s: int = 0         # seconds a rate-limited reply asked the sender to wait
    shown: tuple[bool, int | None] | None = None   # (selected, volume) an output request shows for its output until a later reading or a rejection


@dataclass(frozen=True)
class PowerState:
    state: str          # "idle" | "requested" | "failed"
    changed_at: float   # the core's clock when it reached this state


POWER_IDLE = PowerState("idle", 0.0)


# The rule an appliance applies to a speaker PIN; the dial refuses anything
# else before sending it.
PIN_RE = re.compile(r"^[0-9]{4,8}\Z")
# How long after a pairing outcome the screen may still be answering it.
PIN_WINDOW_S = 90.0
# Reply ids that mean the speaker is asking for a PIN; pin_invalid_new is a
# wrong PIN after which the speaker shows a new one.
PIN_ERRORS = frozenset({"pin_required", "pin_invalid", "pin_invalid_new"})
# The kinds of request the outputs lane carries.
OUTPUT_KINDS = frozenset({"output_set", "output_pin"})


def pin_wanted(request) -> bool:
    """Whether *request* wants a PIN on the screen while its window is open:
    a PIN is on its way (a pending output_pin), or the request ended asking
    for one, or a PIN attempt ended any other way (rate limited, lost) and
    is owed an answer."""
    if request is None or request.kind not in OUTPUT_KINDS:
        return False
    if request.state == "pending":
        return request.kind == "output_pin"
    if request.state != "rejected":
        return False
    return request.error in PIN_ERRORS or request.kind == "output_pin"


def pin_window_end(request) -> float | None:
    """The core-clock time after which an outcome of *request* is no longer
    answered on the screen; None for a request not on the outputs lane."""
    if request is None or request.kind not in OUTPUT_KINDS:
        return None
    return request.changed_at + PIN_WINDOW_S


def awaiting_pin(request, now: float) -> bool:
    """Whether a PIN may be entered for *request*: a pending request waits
    for its reply, any other until PIN_WINDOW_S after it ended."""
    return pin_wanted(request) and (request.state == "pending" or now < pin_window_end(request))


def outputs_tap(snapshot) -> tuple | None:
    """What the latest output request shows meanwhile, (output_id, selected,
    volume, requested_at), or None: nothing is shown once a later reading or a
    rejection has taken it, or when the outputs held are another appliance's."""
    request, held = snapshot.outputs_request, snapshot.outputs
    if request is None or request.shown is None or held is None or request.appliance_id != held.appliance_id:
        return None
    return (request.output_id, request.shown[0], request.shown[1], request.requested_at)


# ---- a speaker that could not start ---------------------------------------

# A failed start older than this when the dial first reads it is not news.
START_FAILURE_MAX_AGE_S = 30
# How long a raised notice stays on the snapshot for a view that has not answered it.
START_FAILURE_HOLD_S = 60.0
START_FAILURE_NAME_MAX = 40
_START_FAILURE_REASON_RE = re.compile(r"[a-z_]{1,32}")
_START_FAILURE_TOKEN_RE = re.compile(r"[A-Za-z0-9_.:-]{1,64}")   # boot and unit id


@dataclass(frozen=True)
class StartFailureReport:
    """One status reply's start_failure, validated."""
    boot: str
    seq: int
    unit_id: str         # the speaker row id the dial sent as output_id
    name: str            # cleaned, at most START_FAILURE_NAME_MAX characters
    reason: str
    mine: bool           # this dial asked for the start
    age_s: int


@dataclass(frozen=True)
class StartFailureNotice:
    """A failure the screens show: "Could not start <name>"."""
    appliance_id: str
    key: str             # "<appliance_id>:<boot>:<seq>", what a view dismisses it by
    unit_id: str
    name: str
    reason: str
    raised_at: float     # the core's clock


def _whole_number(value, minimum: int) -> int | None:
    """*value* when it is an int (not a bool) of at least *minimum*, else None."""
    if not is_int(value) or value < minimum:
        return None
    return value


def parse_start_failure(raw) -> StartFailureReport | None:
    """The status reply's start_failure object, or None when it is absent or
    not well formed: seq a positive int, age_s a non-negative int (bools
    refused), boot and unit_id short tokens, reason a short lower-case id,
    mine a bool (absent reads as False), name a string. Never raises."""
    try:
        if not isinstance(raw, dict):
            return None
        seq = _whole_number(raw.get("seq"), 1)
        age_s = _whole_number(raw.get("age_s"), 0)
        boot, unit_id = raw.get("boot"), raw.get("unit_id")
        reason, name = raw.get("reason"), raw.get("name")
        mine = raw.get("mine", False)
        if seq is None or age_s is None or not isinstance(mine, bool):
            return None
        if not (isinstance(boot, str) and _START_FAILURE_TOKEN_RE.fullmatch(boot)):
            return None
        if not (isinstance(unit_id, str) and _START_FAILURE_TOKEN_RE.fullmatch(unit_id)):
            return None
        if not (isinstance(reason, str) and _START_FAILURE_REASON_RE.fullmatch(reason)):
            return None
        if not isinstance(name, str):
            return None
        return StartFailureReport(
            boot, seq, unit_id, clean_text(name, START_FAILURE_NAME_MAX), reason, mine, age_s,
        )
    except Exception:
        return None


# What a failure means for this dial (start_failure_action's answers).
FAILURE_SEEN = "seen"        # already handled: nothing
FAILURE_MARK = "mark"        # remember it, show nothing
FAILURE_DEFER = "defer"      # look again at the next reading, remember nothing
FAILURE_NOTICE = "notice"    # remember it and raise the notice
FAILURE_PIN = "pin"          # remember it and reopen the output request for a PIN


def start_failure_action(
    report: StartFailureReport | None, seen: tuple[str, int] | None, *,
    appliance_id: str, request: TransportRequest | None,
) -> str:
    """The first rule that applies:
    1. no report, or seen holds the same boot and a seq at or above it: SEEN;
    2. not report.mine: MARK;
    3. reason "pin_required": if request is not None and
       request.appliance_id == appliance_id and request.kind == "output_set"
       and request.output_id == report.unit_id, then
         state "pending": DEFER (its own reply is on the way);
         state "accepted": PIN;
         state "rejected": MARK (the reply already asked);
       otherwise MARK. No age or focus rule applies here;
    4. reason "pin_invalid": PIN when request is this dial's "output_pin"
       for that unit on that appliance and was accepted (its reply said the
       verdict was still to come), else MARK (the keypad re-asks from the
       PIN reply);
    5. report.age_s > START_FAILURE_MAX_AGE_S: MARK;
    6. otherwise: NOTICE."""
    if report is None or (seen is not None and seen[0] == report.boot and seen[1] >= report.seq):
        return FAILURE_SEEN
    if not report.mine:
        return FAILURE_MARK
    if report.reason == "pin_required":
        if (request is None or request.appliance_id != appliance_id
                or request.kind != "output_set" or request.output_id != report.unit_id):
            return FAILURE_MARK
        if request.state == "pending":
            return FAILURE_DEFER
        return FAILURE_PIN if request.state == "accepted" else FAILURE_MARK
    if report.reason == "pin_invalid":
        if (request is not None and request.appliance_id == appliance_id and request.kind == "output_pin"
                and request.output_id == report.unit_id and request.state == "accepted"):
            return FAILURE_PIN
        return FAILURE_MARK
    if report.age_s > START_FAILURE_MAX_AGE_S:
        return FAILURE_MARK
    return FAILURE_NOTICE


def reopen_for_pin(request: TransportRequest, now: float, error: str = "pin_required") -> TransportRequest:
    """The accepted output request as one that ended asking for a PIN now:
    state "rejected", *error* ("pin_required", or "pin_invalid_new" for a
    PIN refused after its reply, when the speaker shows a new one),
    changed_at now (so the PIN window runs from now), shown None.
    Everything else kept, the token (requested_at) and output_id included."""
    return replace(
        request, state="rejected", error=error, changed_at=now, shown=None,
    )


@dataclass(frozen=True)
class ActionResult:
    """The outcome of a request made of the core: accepted means the request
    was taken (a state change made or a send enqueued), not that the
    appliance agreed. A refusal carries one of a closed set of reasons. A
    request that was queued for a worker also carries its token, which the
    worker hands back with the reply so the reply resolves that request."""
    accepted: bool
    reason: str | None = None
    token: float | None = None


@dataclass(frozen=True)
class DialInfo:               # this dial, for any surface
    name: str
    version: str
    uuid: str
    ip: str                   # "" until known
    port: int
    inputs: tuple[str, ...]   # what is running: "encoder", "button", "touch:<type>", ...
    volume_scope: str         # the EFFECTIVE scope ("current" | "all")
    mute_scope: str


@dataclass(frozen=True)
class TickContext:
    """What a fold started from, carried on the snapshot that ends it,
    so a view can tell what that tick changed: the reporting appliance, the
    now-playing line and the idle-screen affordance as they were before it,
    whether it cleared the manual focus, and whether it found a focus
    resting on an idle appliance."""
    previous_reporting_id: str | None
    previous_now_playing: NowPlaying | None
    previous_idle_affordance: bool
    focus_cleared: bool
    idle_focus: bool


@dataclass(frozen=True)
class CoreSnapshot:
    seq: int
    at: float                           # monotonic publish time
    polling: bool                       # the fitted gate
    appliances: tuple[ApplianceState, ...]   # display order (see display_order)
    focus: FocusState
    now_playing: NowPlaying | None
    artwork: Artwork | None             # bytes for now_playing.artwork_url, or None
    idle_affordance: bool               # a held, authorised, repeat-capable appliance exists
    outputs: OutputsState | None        # for the focused/reporting appliance, while watched
    eq: EqState | None
    outputs_available: bool             # focused/reporting appliance advertises dial_outputs and is not refused
    eq_available: bool                  # same for dial_eq (the compact-tier veto is the view's)
    warnings: tuple[WarningState, ...]  # registry order
    due_status_id: str | None           # the warning manager's due_status() at publish time
    network: NetworkView | None
    wifi_ever_connected: bool
    sd_health: SdHealthView | None
    update: UpdateView | None
    transport: TransportRequest | None  # the latest replay/arm request and its outcome
    dial: DialInfo                      # this dial: name, version, address, inputs present
    dots_active: bool = False           # the page dots are tappable for the focused/reporting appliance
    visible_playing: tuple[str, ...] = ()   # ids of the playing appliances this dial may use (not refused, identified)
    ticks: int = 0                      # folds completed; a snapshot with a new count ends a tick
    tick: TickContext | None = None     # what the tick that ended in this snapshot started from
    auth_promotions: int = 0            # appliances a pushed auth change has confirmed as newly authorised
    outputs_request: TransportRequest | None = None  # the latest output request and its outcome
    power: PowerState = POWER_IDLE      # whether a requested power-off is in hand or did not happen
    start_failure: "StartFailureNotice | None" = None   # the raised "could not start" notice, until answered or held out
    focused_peer: object | None = None  # the focused appliance's PeerSnapshot exactly as folded into this snapshot

    def appliance(self, appliance_id: str | None) -> ApplianceState | None:
        if appliance_id is None:
            return None
        return next((a for a in self.appliances if a.appliance_id == appliance_id), None)

    def reporting(self) -> ApplianceState | None:
        return self.appliance(self.focus.reporting_id)

    def focused_id(self) -> str | None:
        return self.focus.manual_id or self.focus.reporting_id

    def selector_rows(self) -> tuple:
        """The appliance selector's rows for this snapshot."""
        return selector_rows(self.appliances, self.focus.manual_id, self.focus.reporting_id)

    def picker_rows(self) -> tuple:
        """The replay picker's rows for this snapshot, from each appliance's
        repeat record as of the last publish."""
        records = {a.appliance_id: a.repeat for a in self.appliances}
        return picker_rows(self.appliances, lambda appliance_id, now: records.get(appliance_id), 0.0)


# ---- rows and availability -----------------------------------------------


def selector_rows(roster: Iterable, manual_id: str | None, reporting_id: str | None) -> tuple:
    """The appliance selector's rows: every roster entry with an identity
    whose auth is AUTHORIZED (an unknown appliance is controllable but not
    yet confirmed, so it stays off the list until a probe confirms it) or
    UNAUTHORIZED (listed, marked, never current or playing). An appliance on
    another protocol than this dial's is listed whatever its auth, marked as
    needing an update, never current or playing. *current* marks the manual
    focus when one is set, else the reporting-from appliance."""
    current_id = manual_id if manual_id is not None else reporting_id
    rows = []
    for r in roster:
        needs_update = getattr(r, "status_error", None) == "protocol"
        if not r.appliance_id or not (needs_update or r.auth in (AUTH_AUTHORIZED, AUTH_UNAUTHORIZED)):
            continue
        usable = r.auth == AUTH_AUTHORIZED and not needs_update
        rows.append(SelectorRow(
            appliance_id=r.appliance_id,
            label=appliance_display_name(r.service_name),
            current=(usable and r.appliance_id == current_id),
            playing=(usable and r.playing),
            authorized=(r.auth == AUTH_AUTHORIZED),
            needs_update=needs_update,
        ))
    return tuple(rows)


def picker_rows(roster: Iterable, repeat_lookup: Callable, now: float) -> tuple:
    """The replay picker's rows: every rostered, authorized, repeat-capable
    appliance currently in Hold — the only daemon state a replay can start
    from. *repeat_lookup(appliance_id, now)* returns its repeat record."""
    return tuple(
        PickerRow(
            appliance_id=r.appliance_id, service_name=r.service_name,
            ip=r.ip, port=r.port,
            label=appliance_display_name(r.service_name),
            seconds=rec.recording_seconds,
        )
        for r in roster
        for rec in [repeat_lookup(r.appliance_id, now)]
        if rec is not None and rec.state == "hold"
        and r.auth == AUTH_AUTHORIZED and r.repeat_capable
    )


def webui_address(ip: str, port: int) -> tuple[str, str, int]:
    """(scheme, host, port) of an appliance's web UI, from its roster
    address. The appliance serves its web UI and the dial API on the one
    advertised port, over plain HTTP."""
    return "http", ip, port


# Where each authorisation state sits in the appliance list: authorised
# first, then not yet known, then refused. Anything else ranks as unknown.
_AUTH_LIST_RANK = {AUTH_AUTHORIZED: 0, AUTH_UNKNOWN: 1, AUTH_UNAUTHORIZED: 2}


def display_order(entries: Iterable) -> list:
    """*entries* (roster entries or appliance states) in the order every
    appliance list is shown: authorisation first (authorised, then unknown,
    then refused), then playing before idle, then by display name, then by
    id. A total order on stable fields, so a list moves only when an
    appliance's own state changes. The roster's own order is the walk
    order and is left alone; lists built for display come through here."""
    def key(r):
        service_name = getattr(r, "service_name", "") or ""
        return (
            _AUTH_LIST_RANK.get(getattr(r, "auth", ""), _AUTH_LIST_RANK[AUTH_UNKNOWN]),
            not getattr(r, "playing", False),
            appliance_display_name(service_name).lower() if isinstance(service_name, str) else "",
            getattr(r, "appliance_id", "") or "",
        )
    return sorted(entries, key=key)


def eq_gain(bands: Iterable, band_id: str) -> int | None:
    """The gain of the band named *band_id*, or None when there is none."""
    return next((b.gain_db for b in bands if b.id == band_id), None)


def roster_entry(roster: Iterable, appliance_id: str | None):
    if not appliance_id:
        return None
    return next((r for r in roster if r.appliance_id == appliance_id), None)


def dots_active(rec: RepeatRecord | None, eq_is_available: bool) -> bool:
    """The page dots are tappable when the focused appliance has a fresh,
    available repeat record, or the EQ page is available for it."""
    return (rec is not None and rec.available) or eq_is_available


