"""dial_hd_actions.py: the HD page's actions, as one table onto core methods.

Each entry names its arguments and the call. A request body is checked
against the argument spec before anything is called: the body must hold only
the named fields, each of its type and range, and a failure names the field.
Nothing here touches a socket or a lock; the caller maps the outcome to HTTP.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from dial_core_state import PIN_RE, ActionResult
from dial_warnings import ACTION_RESTART

ACTION_NAME_RE = re.compile(r"^[a-z_]{1,32}$")
ID_MAX = 128
GAINS_MAX_BANDS = 16
BAND_ID_RE = re.compile(r"^[a-z0-9_]{1,16}$")


class InvalidArgument(Exception):
    """A request field failed its check; *field* names it."""

    def __init__(self, field: str) -> None:
        super().__init__(field)
        self.field = field


# ---- argument checks ---------------------------------------------------------
# Each check takes the value (None when the field is absent) and returns the
# value to use, or raises ValueError.

def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def text(value):
    if not isinstance(value, str) or not 0 < len(value) <= ID_MAX or not value.isprintable():
        raise ValueError
    return value


def opt_text(value):
    return None if value is None else text(value)


def boolean(value):
    if not isinstance(value, bool):
        raise ValueError
    return value


def opt_boolean(value):
    return None if value is None else boolean(value)


def pin_text(value):
    """A speaker PIN: absent, or four to eight ASCII digits. The text is never
    echoed back, so a refusal names only the field."""
    if value is None:
        return None
    if not isinstance(value, str) or not PIN_RE.match(value):
        raise ValueError
    return value


def integer(low: int, high: int):
    def check(value):
        if not _is_int(value) or not low <= value <= high:
            raise ValueError
        return value
    return check


def opt_integer(low: int, high: int):
    check = integer(low, high)

    def opt(value):
        return None if value is None else check(value)
    return opt


def gain_map(low: int, high: int):
    check = integer(low, high)

    def gains(value):
        if not isinstance(value, dict) or not 0 < len(value) <= GAINS_MAX_BANDS:
            raise ValueError
        out = {}
        for band_id, gain in value.items():
            if not isinstance(band_id, str) or not BAND_ID_RE.match(band_id):
                raise ValueError
            out[band_id] = check(gain)
        return out
    return gains


# ---- the table ---------------------------------------------------------------

@dataclass(frozen=True)
class Context:
    """What an action's call reaches: the core and the management server."""
    core: object
    http_server: object = None


def _dial_restart(ctx: Context, args: dict) -> ActionResult:
    """The No-WiFi card's Restart: taken only while the warning that shows
    a Restart button is the one due."""
    due = ctx.core.warnings.due()
    if due is None or not any(b.action == ACTION_RESTART for b in due.buttons):
        return ActionResult(False, "wrong_state")
    if not ctx.core.request_dial_reboot():
        return ActionResult(False, "wrong_state")
    return ActionResult(True)


def _presence(ctx: Context, args: dict) -> ActionResult:
    """Confirm a person is at the dial (the recovery window ignores it unless
    one is open and unconfirmed)."""
    if ctx.http_server is None:
        return ActionResult(False, "wrong_state")
    ctx.http_server.confirm_volume()
    return ActionResult(True)


ACTIONS: "dict[str, tuple[dict, Callable[[Context, dict], ActionResult]]]" = {
    "focus": (
        {"appliance_id": opt_text},
        lambda c, a: c.core.set_focus(a["appliance_id"]),
    ),
    "output": (
        {"appliance_id": text, "output_id": text,
         "selected": opt_boolean, "volume": opt_integer(0, 100), "pin": pin_text},
        # The page can always show a keypad, so a PIN request may be raised.
        lambda c, a: c.core.set_output(
            a["appliance_id"], a["output_id"], selected=a["selected"], volume=a["volume"],
            pin=a["pin"], pin_entry=True),
    ),
    "eq": (
        {"appliance_id": text, "gains": gain_map(-24, 24)},
        lambda c, a: c.core.set_eq(a["appliance_id"], a["gains"]),
    ),
    "eq_reset": (
        {"appliance_id": text},
        lambda c, a: c.core.reset_eq(a["appliance_id"]),
    ),
    "replay_start": (
        {"appliance_id": text},
        lambda c, a: c.core.start_replay(a["appliance_id"]),
    ),
    "replay_restart": (
        {"appliance_id": text},
        lambda c, a: c.core.restart_replay(a["appliance_id"]),
    ),
    "replay_stop": (
        {"appliance_id": text},
        lambda c, a: c.core.stop_replay(a["appliance_id"]),
    ),
    "repeat_arm": (
        {"appliance_id": text, "armed": boolean},
        lambda c, a: c.core.set_repeat_armed(a["appliance_id"], a["armed"]),
    ),
    "volume_set": (
        {"appliance_id": text, "level": integer(0, 100)},
        lambda c, a: c.core.volume_set(a["level"], a["appliance_id"]),
    ),
    "volume_step": (
        {"appliance_id": text, "delta": integer(-100, 100)},
        lambda c, a: c.core.volume_step(a["delta"], a["appliance_id"]),
    ),
    "mute_toggle": (
        {"appliance_id": text},
        lambda c, a: c.core.mute_toggle(a["appliance_id"]),
    ),
    "warning_dismiss": (
        {"warning_id": text},
        lambda c, a: c.core.dismiss_warning(a["warning_id"]),
    ),
    "dial_restart": ({}, _dial_restart),
    "presence": ({}, _presence),
}


def prepare(name: str, body: dict):
    """(call, arguments) for the action *name* with *body*, the arguments
    checked and completed (an absent optional field is None). Raises KeyError
    for an unknown action and InvalidArgument for a bad field."""
    spec, call = ACTIONS[name]
    for key in body:
        if key not in spec:
            raise InvalidArgument("field")
    args = {}
    for field, check in spec.items():
        try:
            args[field] = check(body.get(field))
        except ValueError:
            raise InvalidArgument(field) from None
    return call, args
