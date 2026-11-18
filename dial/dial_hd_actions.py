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

from dial_core_state import ActionResult
from dial_warning_text import NOWIFI_WARNING_ID

ACTION_NAME_RE = re.compile(r"^[a-z_]{1,32}$")
ID_MAX = 128

# The appliance intents the loopback forwards, a subset of the protocol's
# exposed intents. Volume and mute stay on the dial's own actions, so the core's
# scope policy and volume lane are the only path for them.
HD_INTENTS = (
    "outputs.set", "output.pin.submit", "output.eq.set", "output.eq.reset",
    "repeat.arm", "repeat.seek", "repeat.transport", "outputs.save_default",
)


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


def integer(low: int, high: int):
    def check(value):
        if not _is_int(value) or not low <= value <= high:
            raise ValueError
        return value
    return check


# ---- the table ---------------------------------------------------------------

@dataclass(frozen=True)
class Context:
    """What an action's call reaches: the core and the management server."""
    core: object
    http_server: object = None


def _dial_restart(ctx: Context, args: dict) -> ActionResult:
    """The No-WiFi card's Restart: taken only while the No-WiFi warning is
    active."""
    if not ctx.core.warnings.is_active(NOWIFI_WARNING_ID):
        return ActionResult(False, "wrong_state")
    if not ctx.core.request_dial_reboot():
        return ActionResult(False, "wrong_state")
    return ActionResult(True)


def _dial_shutdown(ctx: Context, args: dict) -> ActionResult:
    """The pull-down's Shut down: a graceful power-off of the dial. The page
    asks for confirmation first, and the server takes this only from the
    dial's own screen."""
    if not ctx.core.request_dial_shutdown():
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
    "start_failure_dismiss": (
        {"key": text},
        lambda c, a: c.core.dismiss_start_failure(a["key"]),
    ),
    "status_close": (
        {"status_id": text},
        lambda c, a: c.core.close_status(a["status_id"]),
    ),
    "dial_restart": ({}, _dial_restart),
    "dial_shutdown": ({}, _dial_shutdown),
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
