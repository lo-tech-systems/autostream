"""dial_core_effects.py -- what a source, a reply or the fold meant, queued
for the one view through `DialCore.take_effects`.

All are frozen values. An effect type is never published on the snapshot.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RepeatOutcome:
    """What a repeat transport result meant, for the caller's own reactions
    (a fold, screen changes); the state it implies is already folded."""
    ok: bool                # an ok:true ack
    replay_accepted: bool   # an ack for a replay of the appliance the dial follows
    stop_acked: bool        # an ok ack for the Stop this dial sent


@dataclass(frozen=True)
class WarningChange:
    """What a source did to one warning, for a caller that turns warnings
    into screens: reported present (`active`, and `began` when that started
    a new incident rather than refreshing one) or cleared."""
    warning_id: str
    active: bool
    began: bool = False


@dataclass(frozen=True)
class SourceEffects:
    """The outcome of folding a source's reading: the warning changes in the
    order they were made, whether the update run reached its reboot phase
    (the caller shows its restarting screen), and whether the caller should
    repaint."""
    changes: tuple = ()
    restarting: bool = False
    signal: bool = True


@dataclass(frozen=True)
class RepeatEffect:
    """A repeat transport result as queued for a view: the appliance it was
    for, what it meant (see `RepeatOutcome`) and the token of the request it
    answered (0.0 when the reply carried none)."""
    appliance_id: str
    outcome: RepeatOutcome
    token: float = 0.0


@dataclass(frozen=True)
class OutputsEffect:
    """An output request's outcome as queued for a view: the appliance and
    output it was for, its kind ("output_set" or "output_pin"), whether it was
    "accepted" or "rejected" and, when rejected, the error name of the reply
    and the token of the request it resolved."""
    appliance_id: str
    output_id: str
    kind: str
    outcome: str
    error: str | None
    token: float = 0.0
    late: bool = False   # a PIN request that arrived after the switch's reply


@dataclass(frozen=True)
class StartFailureEffect:
    """A raised notice, queued for a view: the appliance, the notice's key,
    the speaker's name and the reason."""
    appliance_id: str
    key: str
    name: str
    reason: str
