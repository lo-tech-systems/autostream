"""autostream_monitor_control -- live commands to the audio monitor daemon.

Each function here opens a short-lived connection to autostream_monitor, sends
one command and returns the daemon's answer, so a request thread never
depends on the coordinator's own persistent connection. The repeat commands
(arm, stop, seek) are also rows of the intent table, bound at import: a
browser, a dial or a peer submits the intent and the handler here sends the
command, folds the daemon's ack into the published repeat block and tells
subscribers who asked.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

from typing import Optional

import autostream_monitor_client as monitor_client
import autostream_repeat
from autostream_intents.table import Intent, Outcome, bind

_OWNER = "autostream_monitor_control"


def set_live_repeat_enabled(
    enabled: bool,
    codec: str,
    target_minutes: Optional[int] = None,
    socket_path: Optional[str] = None,
) -> bool:
    """Push the global repeat enable/codec/target-duration policy immediately
    to autostream_monitor.

    Live setter -- must NOT trigger a coordinator reload; this
    persists no state of its own and is safe to call at any time.
    target_minutes is the target-duration goal; None means "leave whatever
    the daemon already has" (MonitorClient.set_repeat_enabled's own default
    sentinel).
    """
    with monitor_client._connected_monitor(socket_path) as client:
        if client is None:
            return False
        return client.set_repeat_enabled(bool(enabled), str(codec), target_minutes)


def set_live_repeat_armed_ack(
    armed: bool,
    socket_path: Optional[str] = None,
    *,
    requester: Optional[str] = None,
) -> Optional[dict]:
    """Arm/disarm repeat replay immediately on autostream_monitor and return
    the parsed daemon ack (None when the daemon is unreachable).

    Session arm is runtime-only: no settings write accompanies
    this call. Disarming during replay triggers the daemon's fade-out.
    *requester* names who asked, for the change this publishes.
    """
    with monitor_client._connected_monitor(socket_path) as client:
        if client is None:
            return None
        ack = client.set_repeat_armed_ack(bool(armed))
    return autostream_repeat.apply_repeat_ack(ack, requester=requester)


def set_live_repeat_armed(
    armed: bool,
    socket_path: Optional[str] = None,
) -> bool:
    """Arm/disarm repeat replay immediately on autostream_monitor.

    Session arm is runtime-only: no settings write accompanies
    this call. Disarming during replay triggers the daemon's fade-out.
    """
    ack = set_live_repeat_armed_ack(armed, socket_path)
    return bool(ack and ack.get("ok"))


def send_live_repeat_transport(
    action: str,
    position_seconds: float = 0.0,
    socket_path: Optional[str] = None,
    *,
    requester: Optional[str] = None,
) -> Optional[dict]:
    """Send a repeat-replay transport command ("stop" or "seek") to
    autostream_monitor and return the parsed daemon ack (None when the
    daemon is unreachable). *requester* names who asked, for the change this
    publishes."""
    with monitor_client._connected_monitor(socket_path) as client:
        if client is None:
            return None
        if action == "stop":
            ack = client.repeat_stop()
        else:
            ack = client.repeat_seek(position_seconds)
    return autostream_repeat.apply_repeat_ack(ack, requester=requester)


# ---------------------------------------------------------------------------
# Intent handlers
# ---------------------------------------------------------------------------

def _ack_outcome(ack: Optional[dict]) -> Outcome:
    """The outcome of a command: ok when the daemon accepted it. The ack
    itself (None when the daemon could not be reached) is in the result for
    the route to map to its reply."""
    accepted = isinstance(ack, dict) and bool(ack.get("ok"))
    error = None
    if not accepted:
        error = ack.get("error") if isinstance(ack, dict) else None
        if not isinstance(error, str) or not error:
            error = "backend_unavailable"
    return Outcome(ok=accepted, error=error, result={"ack": ack})


def _repeat_arm(intent: Intent, wait: float) -> Outcome:
    ack = set_live_repeat_armed_ack(intent.args["armed"], requester=intent.requester)
    return _ack_outcome(ack)


def _repeat_stop(intent: Intent, wait: float) -> Outcome:
    ack = send_live_repeat_transport("stop", requester=intent.requester)
    return _ack_outcome(ack)


def _repeat_seek(intent: Intent, wait: float) -> Outcome:
    ack = send_live_repeat_transport(
        "seek", float(intent.args["position"]), requester=intent.requester)
    return _ack_outcome(ack)


bind("repeat.arm", _repeat_arm, owner=_OWNER)
bind("repeat.transport", _repeat_stop, owner=_OWNER)
bind("repeat.seek", _repeat_seek, owner=_OWNER)
