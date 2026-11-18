"""dial_core_focus.py -- which appliance the dial follows, decided from state.

Pure functions, no I/O and no clock reads. choose_focus works out, from the
appliances' own state, who is shown: the focus the person picked, else the
appliance the screen was already bound to, else the playing appliance whose
track is identified, else the one that started playing first. The pending
focus (a replay started from the picker) and the accepted-replay bridge are
small transformations of FocusState kept here beside it.

The rule is the one the dial has always used. It is built from the pure
helpers in dial_core_state (resolve_focus, choose_pin, walk_order,
select_from_records, reporting_for); this module only feeds them from the
appliances' held state.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Iterable, Mapping

from dial_core_state import (
    AUTH_UNAUTHORIZED, AUTH_UNKNOWN, FocusState, Selection, choose_pin, reporting_for,
    resolve_focus, select_from_records, visible_targets, walk_order,
)

# How long a picker-started replay's focus is held while its appliance has not
# yet shown the session.
FOCUS_PENDING_GRACE_S = 3.0


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
