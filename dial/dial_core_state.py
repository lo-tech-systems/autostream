"""dial_core_state.py — the dial's appliance state as plain data, plus the
pure decisions made over it.

Frozen snapshot dataclasses (collections as tuples, no side-effecting
methods) and reducers that take everything they need as arguments: no I/O,
no threads, no locks, no clock reads (the time is always passed in), and no
import of the display. Whoever owns the state (today the display's poll
tick) does the fetching and the writing, and calls these to decide.

Field order in every dataclass is append-only, so positional construction
stays valid as fields are added at the end.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

from dial_auth import AUTH_AUTHORIZED, AUTH_UNAUTHORIZED
from dial_mdns import PlayingTarget, appliance_display_name
from dial_network import NetworkView
from dial_repeat_store import RepeatRecord
from dial_sdhealth import SdHealthView
from dial_update_watch import UpdateView
from dial_volume import select_volume_target


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


@dataclass(frozen=True)
class FocusState:
    manual_id: str | None
    bound_id: str | None
    pending: tuple[str, str, float] | None   # (appliance_id, service_name, expires_at)
    reporting_id: str | None
    source_service_name: str | None
    accepted_replay: tuple[str, float] | None  # (appliance_id, until)
    idle_focus: bool          # the reporting appliance is a focus with nothing playing under it


@dataclass(frozen=True)
class Artwork:
    url: str                  # never logged; consumers use `key`
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
    snoozed_until: float | None


@dataclass(frozen=True)
class TransportRequest:
    appliance_id: str
    kind: str                 # "seek" | "stop" | "arm"
    requested_at: float
    state: str                # "pending" | "accepted" | "rejected"
    changed_at: float
    error: str | None         # daemon error string on rejection, else None


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

    def appliance(self, appliance_id: str | None) -> ApplianceState | None:
        if appliance_id is None:
            return None
        return next((a for a in self.appliances if a.appliance_id == appliance_id), None)

    def reporting(self) -> ApplianceState | None:
        return self.appliance(self.focus.reporting_id)

    def focused_id(self) -> str | None:
        return self.focus.manual_id or self.focus.reporting_id


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
    return entry is not None and entry.dial_outputs and entry.auth != AUTH_UNAUTHORIZED


def eq_available(
    roster: Iterable, focused_id: str | None, compact: "bool | Callable[[], bool]",
) -> bool:
    """The EQ page is available for the focused appliance when it advertises
    dial_eq and is not refused, with an extra veto on the compact tier.
    *compact* may be a callable, read only when the other conditions hold."""
    entry = _roster_entry(roster, focused_id)
    return (
        entry is not None and entry.dial_eq and entry.auth != AUTH_UNAUTHORIZED
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
