"""dial_core_focus.py -- which appliance the dial follows, decided from state.

Pure functions, no I/O and no clock reads. choose_focus works out, from the
appliances' own state, who is shown: the focus the person picked, else the
appliance the screen was already bound to, else the playing appliance whose
track is identified, else the one that started playing first. The pending
focus (a replay started from the picker) and the accepted-replay bridge are
small transformations of FocusState kept here beside it.

The rule is the one the dial has always used. The helpers it is built from
(resolve_focus, choose_pin, walk_order, select_from_records, reporting_for)
sit in this module too; choose_focus only feeds them from the appliances' held
state.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Callable, Iterable, Mapping

from dial_core_state import AUTH_UNAUTHORIZED, AUTH_UNKNOWN, FocusState

# How long a picker-started replay's focus is held while its appliance has not
# yet shown the session.
FOCUS_PENDING_GRACE_S = 3.0


# ---- focus resolution and the walk ---------------------------------------------


def visible_targets(targets: Iterable) -> list:
    """The targets this dial may act on: not confirmed unauthorized, and
    carrying an identity (an unresolved legacy or identity-less appliance
    cannot be addressed or tracked)."""
    return [t for t in targets if t.auth != AUTH_UNAUTHORIZED and t.appliance_id]


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
    appliance id to its authorisation state; it is read only for the grace
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
    support is selected by name alone."""
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


# ---------------------------------------------------------------------------
# Single-target selection (see the module docstring's "reporting-from
# target" paragraph). Pure and lock-free: no I/O, no module state touched —
# the focus rule's reporting_for and dial_main's volume-target resolver both
# call this so they can never disagree about who the reporting-from target is.
# ---------------------------------------------------------------------------

def select_volume_target(targets: list, preferred_service_name: str | None):
    """Pick the single target volume/mute should address.

    targets is the display-ordered list (oldest playing first). Returns
    the entry whose service_name equals preferred_service_name when
    present, else targets[0], else None. Pure and lock-free so the
    display and the worker's resolver call the same function and
    cannot disagree about who the reporting-from target is."""
    if preferred_service_name is not None:
        for t in targets:
            if t.service_name == preferred_service_name:
                return t
    return targets[0] if targets else None


@dataclass(frozen=True)
class FocusChoice:
    manual_id: str | None
    pending: tuple[str, str, float] | None
    bound_id: str | None
    reporting_id: str | None
    reporting: object | None          # the entry shown, None when there is none
    idle_focus: object | None         # a focus with nothing playing under it
    selection: Selection              # the selected track's source, text and artwork
    source_service_name: str | None
    accepted_replay: tuple[str, float] | None
    visible: tuple                    # the playing entries this dial may act on, oldest first
    clear_reason: str | None          # set when the manual focus was cleared

    def apply(self, focus: FocusState) -> FocusState:
        """*focus* with everything this choice decided."""
        return dataclasses.replace(
            focus, manual_id=self.manual_id, bound_id=self.bound_id, pending=self.pending,
            reporting_id=self.reporting_id, source_service_name=self.source_service_name,
            accepted_replay=self.accepted_replay, idle_focus=self.idle_focus is not None,
        )


def playing_order(roster: Iterable) -> list:
    """The playing entries, oldest first (then by name, address and port)."""
    return sorted(
        (e for e in roster if e.playing),
        key=lambda e: (e.playing_since, e.name, e.ip, e.port),
    )


def bridge_accepted_replay(
    accepted: tuple[str, float] | None, targets: list, roster: Iterable,
    manual_id: str | None, now: float,
) -> tuple[list, tuple[str, float] | None]:
    """*targets* (the playing entries), plus the appliance whose replay the
    dial has just had accepted until the appliance shows the session itself.
    Returns (targets, accepted); *accepted* comes back None once the window is
    over. The window ends as soon as the appliance is playing, when the dial
    stops following it, when its repeat record no longer says a replay is
    running, or at its deadline."""
    if accepted is None:
        return targets, None
    appliance_id, until = accepted
    entry = next((e for e in roster if e.appliance_id == appliance_id), None)
    rec = entry.repeat if entry is not None else None
    if (
        now >= until
        or manual_id != appliance_id
        or any(t.appliance_id == appliance_id for t in targets)
        or rec is None or not rec.available or rec.state not in ("replaying", "fading_out")
    ):
        return targets, None
    if entry.auth == AUTH_UNAUTHORIZED:
        return targets, accepted
    return [*targets, dataclasses.replace(entry, playing=True, playing_since=now)], accepted


def choose_focus(
    roster: Iterable, focus: FocusState, now: float, *,
    tracks: Mapping[str, Mapping | None], prev_playing_ids: Iterable[str] = (),
) -> FocusChoice:
    """Who the dial shows.

    *roster* is every appliance sighted, as ApplianceState. *tracks* maps an
    appliance id to the identification entry of its active input (None, or
    absent, when it cannot be read). *prev_playing_ids* are the appliances
    that were playing at the last decision, so a focus on one that has just
    stopped is cleared.

    Order of the rule:
      1. a focus on an appliance with nothing playing (an idle focus) is
         shown;
      2. else the first playing appliance, oldest first with the manual focus
         or the current binding first, whose track is identified with
         artwork; failing that the first identified without artwork;
      3. else the oldest playing appliance this dial may control.
    A manual focus is kept while its appliance is rostered, cleared when it
    has gone, refused this dial, or has just stopped playing. With nothing
    playing, a pending focus is reported by name."""
    roster = list(roster)
    accepted = focus.accepted_replay
    targets, accepted = bridge_accepted_replay(
        accepted, playing_order(roster), roster, focus.manual_id, now)
    visible = visible_targets(targets)
    playing_ids = {t.appliance_id for t in targets if t.appliance_id}
    stopped = set(prev_playing_ids) - playing_ids
    auth_by_id = {e.appliance_id: e.auth for e in roster}
    resolution = resolve_focus(
        focus.manual_id, focus.pending, roster, visible, stopped, now,
        lambda appliance_id: auth_by_id.get(appliance_id, AUTH_UNKNOWN),
    )
    manual_id = resolution.manual_id
    previous_manual = focus.manual_id      # the binding follows the focus as it stood before this decision
    pending = resolution.pending
    idle_focus = resolution.idle_focus

    if not visible:
        if idle_focus is not None:
            reporting = idle_focus
            reporting_id, source = idle_focus.appliance_id, idle_focus.service_name
        else:
            reporting = None
            reporting_id = pending[0] if pending is not None else None
            source = None
        return FocusChoice(
            manual_id=manual_id, pending=pending,
            bound_id=previous_manual if previous_manual is not None else reporting_id,
            reporting_id=reporting_id, reporting=reporting, idle_focus=idle_focus,
            selection=Selection(), source_service_name=source, accepted_replay=accepted,
            visible=(), clear_reason=resolution.clear_reason,
        )

    if idle_focus is not None:
        selection = Selection(service=idle_focus.service_name)
    else:
        pin, _ = choose_pin(
            resolution.focus_target, focus.bound_id if previous_manual is None else None, visible)
        records = {
            e.service_name: {"track_id": tracks[e.appliance_id]}
            for e in visible if tracks.get(e.appliance_id) is not None
        }
        selection = select_from_records(walk_order(pin, visible), records, pin)
    reporting = reporting_for(idle_focus, visible, selection.service)
    reporting_id = reporting.appliance_id if reporting is not None else None
    return FocusChoice(
        manual_id=manual_id, pending=pending,
        bound_id=previous_manual if previous_manual is not None else reporting_id,
        reporting_id=reporting_id, reporting=reporting, idle_focus=idle_focus,
        selection=selection, source_service_name=selection.service, accepted_replay=accepted,
        visible=tuple(visible), clear_reason=resolution.clear_reason,
    )


# ---- the focus the person sets -------------------------------------------------


def with_pending(focus: FocusState, appliance_id: str, service_name: str, expires_at: float) -> FocusState:
    """Pin the focus to *appliance_id* and mark it pending until *expires_at*:
    a replay started from the picker has not yet shown the session, so the
    ordinary clear for an appliance that is not rostered must not fire first."""
    return dataclasses.replace(
        focus, manual_id=appliance_id, pending=(appliance_id, service_name, expires_at))


def cleared(focus: FocusState) -> FocusState:
    """The focus with no manual pin and no pending grace."""
    return dataclasses.replace(focus, manual_id=None, pending=None)


def dropped_pending(focus: FocusState, appliance_id: str) -> FocusState | None:
    """The focus with the manual pin and the grace cleared, when the pending
    focus is for *appliance_id* (its replay did not start); None otherwise."""
    if focus.pending is None or focus.pending[0] != appliance_id:
        return None
    return cleared(focus)


def with_accepted(focus: FocusState, appliance_id: str, until: float) -> FocusState | None:
    """The focus with the accepted-replay window open until *until*, when the
    dial is following *appliance_id*; None otherwise."""
    if focus.manual_id != appliance_id:
        return None
    return dataclasses.replace(focus, accepted_replay=(appliance_id, until))
