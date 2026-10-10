"""dial_core_state.py — the dial's appliance state as plain data, plus the
pure decisions made over it.

Frozen snapshot dataclasses (collections as tuples, no side-effecting
methods) and reducers that take everything they need as arguments: no I/O,
no threads, no locks, no clock reads (the time is always passed in), and no
import of the display. Whoever owns the state (the core's poll tick) does
the fetching and the writing, and calls these to decide.

Field order in every dataclass is append-only, so positional construction
stays valid as fields are added at the end.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, replace
from typing import Callable, Iterable

from dial_auth import AUTH_AUTHORIZED, AUTH_UNAUTHORIZED
from dial_capabilities import appliance_capabilities, txt_capabilities
from dial_mdns import PlayingTarget, appliance_display_name
from dial_network import NetworkView
from dial_repeat_store import RepeatRecord
from dial_sdhealth import SdHealthView
from dial_update_watch import UpdateView
from dial_volume import select_volume_target

# How often the outputs list is refetched while someone is watching it.
OUTPUTS_REFRESH_S = 2.0

# The EQ bass/treble range: both ends (the core's step and the appliance's
# own apply_eq_fields) independently clamp to it.
EQ_LIMIT_DB = 6

# How long an EQ tap's value is shown ahead of the appliance's own reading.
EQ_OPTIMISTIC_WINDOW_S = 2.0

# The two controls every EQ capability exposes; a six-band appliance lists its
# own bands before them.
DERIVED_EQ_IDS = ("bass", "treble")
SIX_BAND_EQ_VERSION = 2
PIN_OUTPUTS_VERSION = 2


def six_band(version: int) -> bool:
    """Whether an EQ capability version lists six bands of its own."""
    return version >= SIX_BAND_EQ_VERSION


def pin_capable_outputs(version: int) -> bool:
    """Whether an outputs capability version accepts a PIN from a dial."""
    return version >= PIN_OUTPUTS_VERSION


# How long a replay the appliance has just accepted may be shown as playing
# before its own playing advertisement reaches the dial (normally a few
# seconds).
ACCEPTED_REPLAY_GRACE_S = 20.0

# How many consecutive "down" polls (15 s apart) open the No-WiFi page on
# their own: three, so a brief drop that recovers within about 45 s only
# ever flashes the icon. A tap on the flashing icon opens the page at once.
NOWIFI_PROMPT_STREAK = 3


# ---- row and now-playing types -------------------------------------------


@dataclass(frozen=True)
class NowPlaying:
    """Now-playing state for the overlay, as last observed by the poll
    thread. Immutable — a changed poll result produces a new instance rather
    than mutating this one, which is what makes the `!=` comparison in
    _poll_once() a reliable "did anything worth repainting change" check.
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


# What stands in for a track the appliance has not named yet, on every view:
# a playing appliance with no title reads as playing rather than blank.
PLAYING_TEXT = "Playing"


def awaiting_title(now_playing: "NowPlaying | None") -> bool:
    """Whether the appliance is playing but has not named the track yet (a
    track change just detected, or the first moments of playback)."""
    return now_playing is not None and now_playing.playing and not now_playing.title


@dataclass(frozen=True)
class SelectorRow:
    """One row of the appliance-selector screen — see SelectorState."""
    appliance_id: str
    label: str        # appliance_display_name(service_name)
    current: bool     # this row is the focus (manual, else the reporting-from target)
    playing: bool = False  # the appliance is playing now, live or replay
    # False for an appliance confirmed to have refused this dial: listed but
    # marked, never focused or controlled (see selector_pick).
    authorized: bool = True


@dataclass(frozen=True)
class PickerRow:
    """One row of the replay picker — see PickerState."""
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
    auth: str                 # dial_auth AUTH_*
    dial_status: bool
    dial_outputs: bool
    dial_eq: bool
    repeat_capable: bool
    dial_proto_version: int
    dial_eq_version: int      # 0 = none, 1 = bass/treble, 2 = six bands
    dial_outputs_version: int  # 0 = none, 1 = the first outputs capability
    status_error: str | None  # last fetch outcome this tick; None = ok or not fetched
    master_volume: int | None  # last good record's master_volume, else None
    muted: bool | None        # the observed mute flag, None = unknown
    repeat: RepeatRecord | None  # the repeat record at publish time
    webui_scheme: str = "http"   # where this appliance's web UI is reached:
    webui_host: str = ""         # its roster address, and the port it
    webui_port: int = 0          # serves the web UI and the dial API on
    supplies_warnings: bool = False  # advertises the appliance-warnings capability
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
    optimistic: tuple[str, bool, int | None, float] | None  # (output_id, selected, volume, stamped_at)


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
    severity: object
    active_since: float | None     # wall clock; a change means a new incident
    snoozed_until: float | None    # wall clock; inf until the source clears it


@dataclass(frozen=True)
class TransportRequest:
    appliance_id: str
    kind: str                 # "seek" | "stop" | "arm" | "output_set" | "output_pin"
    requested_at: float
    state: str                # "pending" | "accepted" | "rejected"
    changed_at: float
    error: str | None         # the daemon's error string on rejection, or a reply id (see dial_core_poll.reply_error_id), else None
    output_id: str | None = None   # the output an output request was for
    retry_after_s: int = 0         # seconds a rate-limited reply asked the sender to wait


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
# Reply ids that mean the speaker is asking for a PIN.
PIN_ERRORS = frozenset({"pin_required", "pin_invalid"})
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
    """What a poll tick started from, carried on the snapshot that ends it,
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
    appliances: tuple[ApplianceState, ...]   # roster order (playing first, then by name)
    focus: FocusState
    now_playing: NowPlaying | None
    artwork: Artwork | None             # bytes for now_playing.artwork_url, or None
    idle_affordance: bool               # a held, authorised, repeat-capable appliance exists
    outputs: OutputsState | None        # for the focused/reporting appliance, while watched
    eq: EqState | None
    outputs_available: bool             # focused/reporting appliance advertises dial_outputs and is not refused
    eq_available: bool                  # same for dial_eq (the compact-tier veto is the view's)
    warnings: tuple[WarningState, ...]  # registry order
    due_warning_id: str | None          # the warning manager's due() at publish time
    network: NetworkView | None
    wifi_ever_connected: bool
    sd_health: SdHealthView | None
    update: UpdateView | None
    transport: TransportRequest | None  # the latest replay/arm request and its outcome
    volume_readout: tuple[str | None, int | None]  # (service_name, shown_volume)
    dial: DialInfo                      # this dial: name, version, address, inputs present
    dots_active: bool = False           # the page dots are tappable for the focused/reporting appliance
    visible_playing: tuple[str, ...] = ()   # ids of the playing appliances this dial may use (not refused, identified)
    ticks: int = 0                      # poll ticks completed; a snapshot with a new count ends a tick
    tick: TickContext | None = None     # what the tick that ended in this snapshot started from
    auth_promotions: int = 0            # appliances a pushed auth change has confirmed as newly authorised
    outputs_request: TransportRequest | None = None  # the latest output request and its outcome
    power: PowerState = POWER_IDLE      # whether a requested power-off is in hand or did not happen

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


# ---- appliance-supplied warnings ------------------------------------------
#
# The protocol is plain HTTP, so any host on the LAN can answer in an
# appliance's place: everything in a warnings reply is untrusted text. The
# validator below is the one entry point. It only ever returns data (strings
# drawn from closed sets, or stripped and length-capped text); nothing it
# returns is a format template, a path, a command or a link.

# A reply larger than this is not parsed at all.
APPLIANCE_WARNINGS_MAX_BODY_BYTES = 8192
# At most this many warnings are kept per appliance; the rest are dropped.
APPLIANCE_WARNINGS_MAX = 8
# Entries examined before giving up on a list padded with unusable ones.
APPLIANCE_WARNINGS_MAX_SCAN = 4 * APPLIANCE_WARNINGS_MAX
# Longest title and message kept, in characters; longer ones are truncated.
APPLIANCE_WARNING_TITLE_MAX = 40
APPLIANCE_WARNING_MESSAGE_MAX = 120
# A warning id is short and plain, so it can key a snooze safely.
APPLIANCE_WARNING_ID_RE = re.compile(r"[a-z0-9_-]{1,32}")

SEVERITY_INFO = "info"
SEVERITY_WARNING = "warning"
SEVERITY_CRITICAL = "critical"
APPLIANCE_WARNING_SEVERITIES = (SEVERITY_INFO, SEVERITY_WARNING, SEVERITY_CRITICAL)
# An unknown or missing severity reads as the mildest.
APPLIANCE_WARNING_DEFAULT_SEVERITY = SEVERITY_INFO

# How the appliance suggests a Dismiss should hold: a day, a week, or not at
# all (a notice with no Dismiss). Anything else reads as a day.
DISMISS_DAY = "day"
DISMISS_WEEK = "week"
DISMISS_NONE = "none"
APPLIANCE_WARNING_DISMISSALS = (DISMISS_DAY, DISMISS_WEEK, DISMISS_NONE)
APPLIANCE_WARNING_DEFAULT_DISMISSAL = DISMISS_DAY


@dataclass(frozen=True)
class ApplianceWarning:
    """One warning an appliance supplies, after validation. The dial sets
    everything about how it behaves (priority, no interruption, no wake);
    the appliance supplies only these fields."""
    id: str                 # [a-z0-9_-]{1,32}, unique within its appliance
    severity: str           # one of APPLIANCE_WARNING_SEVERITIES
    title: str              # non-empty, at most APPLIANCE_WARNING_TITLE_MAX characters
    message: str            # at most APPLIANCE_WARNING_MESSAGE_MAX characters
    dismissal: str          # one of APPLIANCE_WARNING_DISMISSALS
    appliance_name: str = ""  # the roster's display name, set by the core


def _clean_text(value, limit: int) -> str:
    """*value* as plain display text of at most *limit* characters, or ""
    for anything that is not a string. Control, format (which includes the
    bidirectional overrides and isolates), surrogate, private-use and
    unassigned characters are removed, except that white-space controls and
    line separators become a space; runs of spaces collapse, the ends are
    trimmed, and the result is Unicode NFC."""
    if not isinstance(value, str):
        return ""
    value = value[:limit * 4]
    out = []
    for ch in value:
        category = unicodedata.category(ch)
        if category in ("Zl", "Zp") or (category == "Cc" and ch.isspace()):
            out.append(" ")
        elif category in ("Cc", "Cf", "Cs", "Co", "Cn"):
            continue
        else:
            out.append(ch)
    text = unicodedata.normalize("NFC", "".join(out))
    text = re.sub(r" {2,}", " ", text).strip()
    return text[:limit].rstrip()


def _enum_or_default(value, allowed: tuple, default: str) -> str:
    if isinstance(value, str):
        value = value.strip().lower()
        if value in allowed:
            return value
    return default


def validate_appliance_warnings(body, appliance_id: str) -> tuple[ApplianceWarning, ...]:
    """The validated warnings of an appliance's reply, or () when there is
    nothing usable. *body* is the reply as received (bytes or text, parsed
    here under a size cap) or an already parsed object; *appliance_id* is
    the appliance the request was made of.

    The expected shape is {"appliance_id": "<id>", "warnings": [{"id":
    "<id>", "severity": "<name>", "title": "<text>", "message": "<text>",
    "dismissal": "<hint>"}, ...]}. The reply is refused (()) when it is too
    large, is not JSON, is not an object, names a different appliance than
    *appliance_id* or has no list of warnings. Within a list: an entry that
    is not an object, has an invalid or repeated id, or has no title once
    cleaned is dropped; over-long text and a long list are truncated, not
    refused; severity and dismissal fall back to their defaults. Never
    raises."""
    try:
        if not isinstance(appliance_id, str) or not appliance_id:
            return ()
        if isinstance(body, (bytes, bytearray, str)):
            if len(body) > APPLIANCE_WARNINGS_MAX_BODY_BYTES:
                return ()
            body = json.loads(body)
        if not isinstance(body, dict) or body.get("appliance_id") != appliance_id:
            return ()
        entries = body.get("warnings")
        if not isinstance(entries, list):
            return ()
        out: list[ApplianceWarning] = []
        seen: set[str] = set()
        for entry in entries[:APPLIANCE_WARNINGS_MAX_SCAN]:
            if len(out) >= APPLIANCE_WARNINGS_MAX:
                break
            if not isinstance(entry, dict):
                continue
            warning_id = entry.get("id")
            if (
                not isinstance(warning_id, str)
                or APPLIANCE_WARNING_ID_RE.fullmatch(warning_id) is None
                or warning_id in seen
            ):
                continue
            title = _clean_text(entry.get("title"), APPLIANCE_WARNING_TITLE_MAX)
            if not title:
                continue
            seen.add(warning_id)
            out.append(ApplianceWarning(
                id=warning_id,
                severity=_enum_or_default(
                    entry.get("severity"), APPLIANCE_WARNING_SEVERITIES,
                    APPLIANCE_WARNING_DEFAULT_SEVERITY,
                ),
                title=title,
                message=_clean_text(entry.get("message"), APPLIANCE_WARNING_MESSAGE_MAX),
                dismissal=_enum_or_default(
                    entry.get("dismissal"), APPLIANCE_WARNING_DISMISSALS,
                    APPLIANCE_WARNING_DEFAULT_DISMISSAL,
                ),
            ))
        return tuple(out)
    except Exception:
        return ()


def attribute_appliance_warnings(warnings, name: str) -> tuple[ApplianceWarning, ...]:
    """*warnings* carrying *name* (the roster's display name) as their
    source, whatever the appliance said about itself."""
    return tuple(replace(w, appliance_name=name) for w in warnings)


# ---- poll decisions ------------------------------------------------------


def visible_targets(targets: Iterable) -> list:
    """The targets this dial may act on: not confirmed unauthorized, and
    carrying an identity (an unresolved legacy or identity-less appliance
    cannot be addressed or tracked)."""
    return [t for t in targets if t.auth != AUTH_UNAUTHORIZED and t.appliance_id]


def started_refused(targets: Iterable, prev_playing_ids: Iterable[str]) -> list[str]:
    """Ids of refused appliances that have just started playing: in the
    playing set now, not last tick, and confirmed unauthorized."""
    prev = prev_playing_ids if isinstance(prev_playing_ids, (set, frozenset)) else set(prev_playing_ids)
    return [
        t.appliance_id for t in targets
        if t.appliance_id not in prev and t.auth == AUTH_UNAUTHORIZED
    ]


@dataclass(frozen=True)
class FocusResolution:
    manual_id: str | None       # the manual focus after this tick's resolution
    pending: tuple[str, str, float] | None
    focus_entry: object | None  # the roster entry, playing or idle
    focus_target: object | None  # the playing-set entry, when playing
    idle_focus: object | None   # a rostered focus with nothing playing under it
    clear_reason: str | None    # set when the focus must be cleared (the caller applies it)


def resolve_focus(
    prev_manual: str | None,
    prev_pending: tuple[str, str, float] | None,
    roster: list,
    visible: list,
    stopped_ids: Iterable[str],
    now: float,
    auth_state: Callable[[str], str],
) -> FocusResolution:
    """Resolve the manual focus for this tick. A focus is cleared when the
    appliance is no longer rostered at all (or is confirmed unauthorized),
    or when it was playing last tick and has just stopped. A focus resting
    on an idle appliance is otherwise kept even while something else plays.
    A pending (picker-started replay) grace keeps a not-yet-rostered focus
    until it expires or the appliance is sighted. *auth_state* maps an
    appliance id to its dial_auth state; it is read only for the grace
    check."""
    focus_id = prev_manual
    pending = prev_pending
    if pending is not None and (pending[0] != focus_id or now >= pending[2]):
        pending = None
    focus_entry = None
    focus_target = None
    clear_reason = None
    if focus_id is not None:
        focus_entry = next(
            (r for r in roster if r.appliance_id == focus_id and r.auth != AUTH_UNAUTHORIZED),
            None,
        )
        focus_target = next(
            (t for t in visible if t.appliance_id == focus_id),
            None,
        )
        if focus_entry is None:
            if pending is not None and auth_state(focus_id) != AUTH_UNAUTHORIZED:
                pass  # grace: keep the focus, appliance not rostered yet
            else:
                clear_reason = "appliance gone or unauthorized"
                focus_entry = focus_target = None
        elif focus_target is None and focus_id in stopped_ids:
            clear_reason = "appliance stopped playing"
            focus_entry = None
        elif focus_target is not None and pending is not None:
            pending = None  # sighted: converts to a normal focus
    if clear_reason is not None:
        focus_id = None
        pending = None
    idle_focus = focus_entry if (focus_entry is not None and focus_target is None) else None
    return FocusResolution(focus_id, pending, focus_entry, focus_target, idle_focus, clear_reason)


def choose_pin(focus_target, bound_id: str | None, visible: list):
    """(pin_target, bound_id) for the walk. With a focus target, it is the
    pin. Without, the appliance the screen was already bound to is pinned
    while it is still in the visible playing set; a binding whose
    appliance has gone is released (the returned bound_id is None). A
    caller with a manual focus set but no focus target passes bound_id
    None, so nothing is looked up and nothing is released."""
    bound_target = None
    if bound_id is not None:
        bound_target = next((t for t in visible if t.appliance_id == bound_id), None)
        if bound_target is None:
            bound_id = None
    pin_target = focus_target if focus_target is not None else bound_target
    return pin_target, bound_id


def walk_order(pin_target, visible: list) -> list:
    """The order the status walk visits targets: the pin first, then the
    rest in their own order; unchanged when nothing is pinned."""
    if pin_target is None:
        return visible
    return [pin_target] + [t for t in visible if t is not pin_target]


@dataclass(frozen=True)
class Selection:
    """What the walk selected: the artwork URL (None = none), the source
    service, and the track's artist, title and album."""
    url: str | None = None
    service: str | None = None
    artist: str = ""
    title: str = ""
    album: str = ""


def _identified(track_id) -> bool:
    return bool(track_id) and track_id.get("state") == "identified"


def walk_step(target, record: dict | None, is_pin: bool, fallback):
    """One target's contribution to the walk, given its fetched *record*
    (None for a status error or a target not fetched). Returns
    (selection, fallback): a Selection when the walk stops at this target,
    else None; *fallback* carries the first target identified without
    artwork, (service_name, track_id) or None, and is returned updated.

    A pinned target always ends the walk and is shown whether or not its
    status could be read (an errored one keeps its service name), with its
    identified track's text even when it has no artwork. An unpinned target
    ends the walk only with identified artwork; a status error skips it."""
    if is_pin:
        if record is None:
            return Selection(service=target.service_name), fallback
        track_id = record.get("track_id")
        if _identified(track_id):
            return Selection(
                url=track_id.get("artwork_url") or None,
                service=target.service_name,
                artist=track_id.get("artist", ""),
                title=track_id.get("title", ""),
                album=track_id.get("album", ""),
            ), fallback
        return Selection(service=target.service_name), fallback
    if record is None:
        return None, fallback
    track_id = record.get("track_id")
    if _identified(track_id) and track_id.get("artwork_url"):
        return Selection(
            url=track_id["artwork_url"],
            service=target.service_name,
            artist=track_id.get("artist", ""),
            title=track_id.get("title", ""),
            album=track_id.get("album", ""),
        ), fallback
    if _identified(track_id) and fallback is None:
        fallback = (target.service_name, track_id)
    return None, fallback


def walk_fallback(fallback) -> Selection:
    """The selection when the walk ran out of targets without a stop: the
    first target identified without artwork (title and artist over the
    logo), else nothing."""
    if fallback is None:
        return Selection()
    service, track_id = fallback
    return Selection(
        service=service,
        artist=track_id.get("artist", ""),
        title=track_id.get("title", ""),
        album=track_id.get("album", ""),
    )


def select_from_records(ordered: list, records: dict, pin_target) -> Selection:
    """The whole walk's decision over already-fetched *records* (service
    name -> status record, absent for an errored or unfetched target).
    Unauthorized targets are skipped; a pinned target without status
    support is selected by name alone. The same steps the poll takes one
    fetch at a time."""
    fallback = None
    for target in ordered:
        is_pin = pin_target is not None and target is pin_target
        if target.auth == AUTH_UNAUTHORIZED:
            continue
        if not target.dial_status:
            if is_pin:
                return Selection(service=target.service_name)
            continue
        selection, fallback = walk_step(target, records.get(target.service_name), is_pin, fallback)
        if selection is not None:
            return selection
    return walk_fallback(fallback)


def reporting_for(idle_focus, visible: list, selected_service: str | None):
    """The reporting-from target: the idle focus when one is pinned; else
    the identified (or focused) source, else the oldest playing
    controllable target. Only visible targets are offered, matching the
    volume resolver's own filter."""
    if idle_focus is not None:
        return idle_focus
    return select_volume_target(visible, selected_service)


def with_accepted_replay(
    accepted: tuple[str, float] | None,
    targets: list,
    roster: list,
    manual_id: str | None,
    rec: RepeatRecord | None,
    now: float,
) -> tuple[list, tuple[str, float] | None]:
    """*targets* (the mDNS playing set), plus the appliance whose replay the
    dial has just had accepted, until its own playing advertisement
    arrives. Returns (targets, accepted): *accepted* comes back None once
    the window is over. The window ends as soon as the advertisement is
    seen, when the dial stops following the appliance, when its repeat
    record *rec* no longer says a replay is running, or at its deadline.
    The roster is the one published by the previous poll."""
    if accepted is None:
        return targets, None
    appliance_id, until = accepted
    if (
        now >= until
        or manual_id != appliance_id
        or any(t.appliance_id == appliance_id for t in targets)
        or rec is None or not rec.available or rec.state not in ("replaying", "fading_out")
    ):
        return targets, None
    entry = next(
        (r for r in roster if r.appliance_id == appliance_id and r.auth != AUTH_UNAUTHORIZED),
        None,
    )
    if entry is None:
        return targets, accepted
    return [*targets, PlayingTarget(
        ip=entry.ip, port=entry.port, name=entry.name, dial_api=entry.dial_api,
        audio_status=entry.audio_status, dial_status=entry.dial_status,
        dial_outputs=entry.dial_outputs, dial_eq=entry.dial_eq,
        service_name=entry.service_name, playing_since=now,
        appliance_id=entry.appliance_id, auth=entry.auth,
        dial_eq_version=getattr(entry, "dial_eq_version", 0),
    )], accepted


# ---- rows and availability -----------------------------------------------


def selector_rows(roster: Iterable, manual_id: str | None, reporting_id: str | None) -> tuple:
    """The appliance selector's rows: every roster entry with an identity
    whose auth is AUTHORIZED (an unknown appliance is controllable but not
    yet confirmed, so it stays off the list until a probe confirms it) or
    UNAUTHORIZED (listed, marked, never current or playing). *current* marks
    the manual focus when one is set, else the reporting-from appliance."""
    current_id = manual_id if manual_id is not None else reporting_id
    return tuple(
        SelectorRow(
            appliance_id=r.appliance_id,
            label=appliance_display_name(r.service_name),
            current=(r.auth == AUTH_AUTHORIZED and r.appliance_id == current_id),
            playing=(r.auth == AUTH_AUTHORIZED and r.playing),
            authorized=(r.auth == AUTH_AUTHORIZED),
        )
        for r in roster
        if r.appliance_id and r.auth in (AUTH_AUTHORIZED, AUTH_UNAUTHORIZED)
    )


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


def appliance_states(
    roster: Iterable, repeats: dict | None = None, appliance_warnings: dict | None = None,
    capabilities: dict | None = None, statuses: dict | None = None,
) -> tuple:
    """One ApplianceState per roster entry, in roster order. *repeats* maps
    an appliance id to its repeat record, *appliance_warnings* to its
    validated warnings, *statuses* to the (status_error, master_volume,
    muted) the last poll tick read from it. *capabilities* maps an appliance id to its
    Capabilities as already read through the switch point, for a caller that
    holds a lock the registry's must not be taken under (an id missing from
    it reads from the entry's mDNS flags); without it each entry is read
    through the switch point here. Entries are read defensively:
    anything an entry does not carry takes its neutral value. An appliance
    the last tick did not ask has no entry in *statuses*, and its error,
    volume and mute stay None."""
    repeats = repeats or {}
    statuses = statuses or {}
    appliance_warnings = appliance_warnings or {}
    out = []
    for r in roster:
        appliance_id = getattr(r, "appliance_id", "") or ""
        service_name = getattr(r, "service_name", "") or ""
        ip = getattr(r, "ip", "") or ""
        port = getattr(r, "port", 0) or 0
        if capabilities is None:
            caps = appliance_capabilities(r)
        else:
            caps = capabilities.get(appliance_id) or txt_capabilities(r)
        scheme, host, web_port = webui_address(ip, port)
        status_error, master_volume, muted = statuses.get(appliance_id, (None, None, None))
        out.append(ApplianceState(
            appliance_id=appliance_id,
            service_name=service_name,
            name=appliance_display_name(service_name) if isinstance(service_name, str) else "",
            ip=ip,
            port=port,
            playing=bool(getattr(r, "playing", False)),
            playing_since=0.0,
            auth=getattr(r, "auth", ""),
            dial_status=bool(getattr(r, "dial_status", False)),
            dial_outputs=caps.outputs,
            dial_eq=caps.eq,
            repeat_capable=caps.repeat,
            dial_proto_version=getattr(r, "dial_proto_version", 0),
            dial_eq_version=caps.eq_version,
            dial_outputs_version=caps.outputs_version,
            status_error=status_error,
            master_volume=master_volume,
            muted=muted,
            repeat=repeats.get(appliance_id),
            webui_scheme=scheme,
            webui_host=host,
            webui_port=web_port,
            supplies_warnings=caps.warnings,
            warnings=appliance_warnings.get(appliance_id, ()),
        ))
    return tuple(out)


def eq_gain(bands: Iterable, band_id: str) -> int | None:
    """The gain of the band named *band_id*, or None when there is none."""
    return next((b.gain_db for b in bands if b.id == band_id), None)


def idle_affordance(roster: Iterable, held_ids) -> bool:
    """True when at least one rostered, authorized, repeat-capable appliance
    is currently held (a retained recording with nothing else to show)."""
    return any(
        r.appliance_id in held_ids and r.auth == AUTH_AUTHORIZED and r.repeat_capable
        for r in roster
    )


def _roster_entry(roster: Iterable, appliance_id: str | None):
    if not appliance_id:
        return None
    return next((r for r in roster if r.appliance_id == appliance_id), None)


def outputs_available(roster: Iterable, focused_id: str | None) -> bool:
    entry = _roster_entry(roster, focused_id)
    return (
        entry is not None and appliance_capabilities(entry).outputs
        and entry.auth != AUTH_UNAUTHORIZED
    )


def eq_available(
    roster: Iterable, focused_id: str | None, compact: "bool | Callable[[], bool]",
) -> bool:
    """The EQ page is available for the focused appliance when it advertises
    dial_eq and is not refused, with an extra veto on the compact tier.
    *compact* may be a callable, read only when the other conditions hold."""
    entry = _roster_entry(roster, focused_id)
    return (
        entry is not None and appliance_capabilities(entry).eq
        and entry.auth != AUTH_UNAUTHORIZED
        and not (compact() if callable(compact) else compact)
    )


def dots_active(rec: RepeatRecord | None, eq_is_available: bool) -> bool:
    """The page dots are tappable when the focused appliance has a fresh,
    available repeat record, or the EQ page is available for it."""
    return (rec is not None and rec.available) or eq_is_available


def availability(
    roster: Iterable, focused_id: str | None, compact: "bool | Callable[[], bool]",
    rec: RepeatRecord | None,
) -> tuple[bool, bool, bool]:
    """(dots, outputs, eq) for the focused/reporting appliance. *rec* is its
    repeat record, read from the store by the caller."""
    eq = eq_available(roster, focused_id, compact)
    return dots_active(rec, eq), outputs_available(roster, focused_id), eq
