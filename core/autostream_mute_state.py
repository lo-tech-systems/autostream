#!/usr/bin/env python3
"""autostream_mute_state.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Appliance-side mute state: process memory only, no persistence.

The appliance is the single source of truth for whether it is muted. It
accepts an explicit mute/restore action (from the dial's pushbutton, from
the WebUI's master-volume icon, or from a fleet-wide fan-out), keeps the
level each affected output should return to, and reports both the flag and
the intended level on every status/volume response so that any client --
dial or browser -- shows the same thing without keeping any belief of its
own.

There is deliberately no file, no load-at-start and no persistence here: a
restarted appliance comes back unmuted, with OwnTone's own output volumes
exactly as OwnTone left them. This module is a pure, tiny piece of shared
memory -- callers own all I/O and all OwnTone round trips; this module never
performs any.

Thread safety: `_lock` is a leaf lock. It is only ever held for a plain
dict/bool read-modify-write and is never held across an OwnTone (or any
other) network call. Callers that also hold their own coarser lock (e.g.
the appliance's OwnTone-round-trip serialisation lock) may safely nest this
one inside it; this module never takes any other lock, so the reverse
nesting can never happen.
"""
from __future__ import annotations

import threading

_lock = threading.Lock()
_muted: bool = False
_remembered: dict[str, int] = {}  # output_id -> level to return to on restore


def is_muted() -> bool:
    """Whether the appliance currently holds a mute."""
    with _lock:
        return _muted


def intended_level(output_id: str, actual: int) -> int:
    """The level *output_id* should be reported at.

    While muted, the remembered level for this output (the level it will
    return to on restore); *actual* for an output the mute never touched
    (never selected/audible at mute time, or added afterwards and never
    adjusted). Equal to *actual* whenever the appliance is not muted.
    """
    with _lock:
        if not _muted:
            return actual
        return _remembered.get(output_id, actual)


def begin_mute(levels: dict[str, int]) -> None:
    """Enter (or stay in) the muted state.

    Remembers *levels* for any id not already remembered -- so a second
    mute press while already muted never overwrites a level a previous
    press already captured -- and sets the flag, even when *levels* is
    empty (an already-silent selection still reports muted on the next
    press).
    """
    global _muted
    with _lock:
        for output_id, level in levels.items():
            _remembered.setdefault(output_id, level)
        _muted = True


def end_mute() -> dict[str, int]:
    """Leave the muted state, returning what was remembered.

    Clears the flag and forgets every remembered level unconditionally --
    this module keeps no history beyond "currently muted, and what to
    restore to"; a caller that could not apply a given output's restore
    (a failed write) does not get another chance to recover that exact
    level from here.
    """
    global _muted
    with _lock:
        levels = dict(_remembered)
        _remembered.clear()
        _muted = False
        return levels


def remember_level(output_id: str, level: int) -> bool:
    """Record a live level for *output_id* while muted, on the caller's
    behalf, without unmuting anything.

    Used when a client moves a slider or enables an output while the
    appliance is muted: the requested level becomes what that output
    returns to on restore, but the output itself must stay silent. Returns
    True (the caller must keep the output silent -- skip or override the
    write it was about to make) when muted; False when not muted, meaning
    the caller should just apply the level normally.
    """
    with _lock:
        if not _muted:
            return False
        _remembered[output_id] = level
        return True


def forget_output(output_id: str) -> None:
    """Drop any remembered level for an output that was disabled -- it has
    nothing to restore to any more."""
    with _lock:
        _remembered.pop(output_id, None)


def reset_for_tests() -> None:
    """Restore the module to its just-imported state. Test-only."""
    global _muted
    with _lock:
        _remembered.clear()
        _muted = False
