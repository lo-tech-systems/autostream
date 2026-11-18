"""dial_warning_bell.py: what a warning bell holds.

A bell lists the warnings behind one tap: the dial's own, one appliance's, or
(on the small screen) the dial's and every appliance the dial shows. The
three functions here are pure functions of a core snapshot and the warning
descriptors, shared by both dials so the small screen and the HD page cannot
disagree about what a bell holds, how many, or in what order.

Order is the worst severity first; within a severity the dial's own come
before the appliances', and each source keeps its own order (the registry's
for the dial, the order the appliance reported for an appliance).

Only warnings are listed. A status (an update running or finished) is shown
by itself and never sits in a bell.

No drawing, no I/O, no clock.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from dial_core_state import (
    AUTH_AUTHORIZED, AUTH_UNAUTHORIZED, SEVERITY_CRITICAL, SEVERITY_INFO, SEVERITY_WARNING,
)
from dial_warning_text import appliance_warning_key
from dial_warnings import ACTION_CLOSE, APPLIANCE_WARNING_PREFIX, KIND_WARNING

# Who a dial-own entry is attributed to.
DIAL_SOURCE = "This dial"

# Worst last, so a larger rank is a worse severity.
_RANK = {SEVERITY_INFO: 0, SEVERITY_WARNING: 1, SEVERITY_CRITICAL: 2}


@dataclass(frozen=True)
class BellEntry:
    """One warning in a bell."""
    key: str            # the registry key: "sdhealth", "appliance:<aid>:<wid>"
    source: str         # DIAL_SOURCE, or the appliance's name
    severity: str       # SEVERITY_INFO, SEVERITY_WARNING or SEVERITY_CRITICAL
    title: str
    message: str
    actions: tuple      # actions beside Close, e.g. (ACTION_RESTART,)


@dataclass(frozen=True)
class Bell:
    entries: tuple      # BellEntry, worst severity first

    @property
    def count(self) -> int:
        return len(self.entries)

    @property
    def severity(self) -> "str | None":
        """The worst severity among the entries, None when there are none."""
        if not self.entries:
            return None
        return max((e.severity for e in self.entries), key=_RANK.__getitem__)


def _worst_first(entries: Iterable[BellEntry]) -> tuple:
    return tuple(sorted(entries, key=lambda e: -_RANK[e.severity]))


def descriptor_map(descriptors: "Mapping | Iterable | None") -> dict:
    """The descriptors by id, from a mapping, an iterable or None."""
    if descriptors is None:
        return {}
    if isinstance(descriptors, Mapping):
        return dict(descriptors)
    return {d.id: d for d in descriptors}


def dial_bell(snapshot, descriptors) -> Bell:
    """The dial's own active warnings: every active KIND_WARNING descriptor
    that is not an appliance's, in registry order."""
    by_id = descriptor_map(descriptors)
    entries = []
    for state in snapshot.warnings:
        desc = by_id.get(state.id)
        if not state.active or desc is None or desc.kind != KIND_WARNING:
            continue
        if state.id.startswith(APPLIANCE_WARNING_PREFIX):
            continue
        entries.append(BellEntry(
            key=state.id,
            source=DIAL_SOURCE,
            severity=desc.severity(state.reading),
            title=desc.title_text(state.reading),
            message=desc.message_text(state.reading),
            actions=tuple(b.action for b in desc.buttons if b.action != ACTION_CLOSE),
        ))
    return Bell(_worst_first(entries))


def appliance_bell(appliance) -> Bell:
    """One appliance's warnings, as it reported them (the dial's "Update
    <appliance>" for an older appliance among them), each attributed to the
    appliance by name."""
    return Bell(_worst_first(
        BellEntry(
            key=appliance_warning_key(appliance.appliance_id, w.id),
            source=appliance.name,
            severity=w.severity,
            title=w.title,
            message=w.message,
            actions=(),
        )
        for w in appliance.warnings
    ))


def rostered(snapshot) -> tuple:
    """The appliances the dial shows in its list: those it is authorised on
    and those it is not, so a bell never counts one the person cannot see."""
    return tuple(
        a for a in snapshot.appliances
        if a.appliance_id and a.auth in (AUTH_AUTHORIZED, AUTH_UNAUTHORIZED)
    )


def whole_bell(snapshot, descriptors) -> Bell:
    """The dial's own warnings and those of every rostered appliance."""
    entries = list(dial_bell(snapshot, descriptors).entries)
    for appliance in rostered(snapshot):
        entries.extend(appliance_bell(appliance).entries)
    return Bell(_worst_first(entries))
